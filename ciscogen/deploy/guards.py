"""Guardrails, backups, diffs and reports for deployment workflows."""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from ..models import SECTION_LABELS
from . import DEPLOYMENT_WARNING, POSTCHECK_ITEMS, PRECHECK_COMMANDS, redact_secrets
from .profiles import SSHProfile

DEPLOY_ERROR_PATTERNS = (
    "% Invalid input",
    "% Incomplete command",
    "% Ambiguous command",
    "% Unknown command",
    "Error:",
    "Traceback",
)

SECTION_COMMENT_LABELS = {
    "system": ["Base System", "Global services", "Identity & security basics",
               "AAA & local users", "Console & VTY lines",
               "Logging, NTP & SNMP"],
    "interfaces": ["Interfaces"],
    "vlans": ["VLANs & Layer 2", "VLANs",
              "Spanning tree & Layer 2 security"],
    "layer3": ["Static Routing & PBR", "Static routes"],
    "routing": ["Routing Protocols", "Routing protocols"],
    "acls": ["Access Lists", "Access lists"],
    "nat": ["NAT / PAT", "NAT / PAT"],
    "tunnels": ["IP Tunnels & VPN", "IKE / IPsec"],
    "dmvpn": ["DMVPN & IPsec (legacy)", "IKE / IPsec"],
    "ipsla": ["IP SLA & Tracking", "IP SLA and object tracking"],
    "qos": ["QoS"],
    "zbf": ["Zone Firewall", "Zone-Based Firewall"],
    "custom_cli": ["Custom CLI", "Custom global CLI",
                   "Custom pre-interface CLI", "Custom post-routing CLI",
                   "Custom end-of-config CLI"],
}


@dataclass
class DeploymentSelection:
    mode: str = "dry-run"       # dry-run | selected-lines | selected-section | full
    selected_text: str = ""
    section_key: str = ""


@dataclass
class DeploymentAssessment:
    dry_run: bool = True
    allowed: bool = False
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)


@dataclass
class DeploymentReport:
    timestamp: str
    ssh_profile_name: str
    target: str
    detected_hostname: str = ""
    selected_project_device: str = ""
    selected_capability_profile: str = "device-profile"
    detected_platform: str = ""
    detected_version: str = ""
    validation_status: str = ""
    precheck_summary: dict = field(default_factory=dict)
    backup_path: str = ""
    diff_summary: str = ""
    deployment_mode: str = "dry-run"
    commands_sent: list[str] = field(default_factory=list)
    errors_detected: list[str] = field(default_factory=list)
    postcheck_summary: dict = field(default_factory=dict)
    save_running_config_status: str = "not requested"
    rollback_notes: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["commands_sent"] = [redact_secrets(cmd) for cmd in self.commands_sent]
        data["errors_detected"] = [redact_secrets(err) for err in self.errors_detected]
        return data


def default_backup_dir() -> Path:
    return Path.cwd() / "backups"


def selected_config_text(project, live_config: str, final_config: str) -> str:
    return final_config if (final_config or "").strip() else live_config


def prepare_deployment_commands(candidate_config: str,
                                selection: DeploymentSelection) -> list[str]:
    if selection.mode == "selected-lines":
        source = selection.selected_text
    elif selection.mode == "selected-section":
        source = _extract_section(candidate_config, selection.section_key)
    elif selection.mode == "full":
        source = candidate_config
    else:
        return []
    return _clean_config_commands(source)


def _extract_section(config: str, section_key: str) -> str:
    if not section_key:
        return ""
    labels = SECTION_COMMENT_LABELS.get(
        section_key, [SECTION_LABELS.get(section_key, section_key)])
    starts = {f"! --- {label} ---" for label in labels}
    lines = (config or "").splitlines()
    collecting = False
    collected: list[str] = []
    for line in lines:
        if line.strip() in starts:
            collecting = True
            continue
        if collecting and line.startswith("! --- "):
            break
        if collecting:
            collected.append(line)
    return "\n".join(collected)


def _clean_config_commands(text: str) -> list[str]:
    commands = []
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line or line.strip() == "!" or line.strip() == "end":
            continue
        if line.lstrip().startswith("!"):
            continue
        commands.append(line)
    return commands


def critical_validation_messages(issues) -> list[str]:
    messages = []
    for issue in issues or []:
        severity = getattr(issue, "severity", "")
        message = getattr(issue, "message", str(issue))
        if severity in ("critical", "error"):
            messages.append(message)
    return messages


def assess_deployment(selection: DeploymentSelection, candidate_config: str,
                      validation_issues=None, backup_path: str = "",
                      confirmation: bool = False) -> DeploymentAssessment:
    commands = prepare_deployment_commands(candidate_config, selection)
    dry_run = selection.mode == "dry-run"
    blockers: list[str] = []
    warnings: list[str] = []
    if not dry_run and not commands:
        blockers.append("No candidate commands were selected for deployment.")
    if not dry_run and not backup_path:
        blockers.append("Back up running-config before deploying.")
    critical = critical_validation_messages(validation_issues)
    if critical:
        blockers.append("Critical validation errors must be resolved before deployment.")
    if not dry_run and not confirmation:
        blockers.append("Deployment requires explicit confirmation.")
    if dry_run:
        warnings.append("Dry-run only: no commands will be sent.")
    return DeploymentAssessment(
        dry_run=dry_run,
        allowed=not blockers and not dry_run,
        blockers=blockers,
        warnings=warnings,
        commands=commands,
    )


def precheck_commands(project, profile=None) -> list[str]:
    commands = list(PRECHECK_COMMANDS)
    enabled = getattr(project, "sections_enabled", {})
    if enabled.get("tunnels") or enabled.get("dmvpn"):
        commands.extend(["show interfaces tunnel", "show ip interface brief",
                         "show dmvpn", "show ip nhrp",
                         "show crypto ikev2 sa", "show crypto ipsec sa"])
    if enabled.get("routing"):
        commands.extend([
            "show ip ospf neighbor",
            "show ip eigrp neighbors",
            "show ip bgp summary",
        ])
    if enabled.get("ipsla"):
        commands.extend(["show ip sla summary", "show track"])
    if enabled.get("nat"):
        commands.extend(["show ip nat translations", "show ip nat statistics"])
    if enabled.get("vlans") or enabled.get("interfaces"):
        commands.extend(["show inventory", "show platform"])
    return _dedupe(commands)


def postcheck_commands(project, profile=None) -> list[str]:
    enabled = getattr(project, "sections_enabled", {})
    commands = ["show ip interface brief", "show ip route"]
    if enabled.get("vlans"):
        commands.append("show vlan brief")
    if enabled.get("acls"):
        commands.append("show access-lists")
    if enabled.get("nat"):
        commands.extend(["show ip nat translations", "show ip nat statistics"])
    if enabled.get("routing"):
        commands.extend([
            "show ip ospf neighbor",
            "show ip eigrp neighbors",
            "show ip bgp summary",
        ])
    if enabled.get("tunnels") or enabled.get("dmvpn"):
        commands.extend([
            "show interfaces tunnel",
            "show dmvpn",
            "show ip nhrp",
            "show crypto isakmp sa",
            "show crypto ikev2 sa",
            "show crypto ipsec sa",
        ])
    if enabled.get("ipsla"):
        commands.extend(["show ip sla summary", "show track"])
    return _dedupe(commands)


def _dedupe(commands: list[str]) -> list[str]:
    return list(dict.fromkeys(command for command in commands if command))


def backup_running_config(running_config: str, profile_name: str = "device",
                          backup_dir: str | Path | None = None) -> Path:
    directory = Path(backup_dir) if backup_dir else default_backup_dir()
    directory.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", profile_name or "device").strip("_")
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = directory / f"{safe_name}-{timestamp}-running.cfg"
    path.write_text(running_config or "", encoding="utf-8", newline="\n")
    return path


def config_diff(left: str, right: str, left_name: str = "candidate",
                right_name: str = "running-config") -> str:
    return "\n".join(difflib.unified_diff(
        redact_secrets(left or "").splitlines(),
        redact_secrets(right or "").splitlines(),
        fromfile=left_name,
        tofile=right_name,
        lineterm="",
    ))


def summarize_diff(diff_text: str) -> str:
    adds = deletes = 0
    for line in (diff_text or "").splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            adds += 1
        elif line.startswith("-") and not line.startswith("---"):
            deletes += 1
    return f"{adds} additions, {deletes} removals"


def detect_cli_errors(output: str) -> list[str]:
    errors = []
    for line in (output or "").splitlines():
        if any(pattern.lower() in line.lower() for pattern in DEPLOY_ERROR_PATTERNS):
            errors.append(redact_secrets(line))
    return errors


def parse_device_facts(show_version_output: str) -> dict:
    """Best-effort extraction of hostname/model/version from
    'show version' text so identity mismatches can be flagged."""
    facts: dict[str, str] = {}
    text = show_version_output or ""
    hostname = re.search(r"^(\S+)\s+uptime is", text, flags=re.MULTILINE)
    if hostname:
        facts["hostname"] = hostname.group(1)
    version = re.search(r"(?:IOS[ -]XE Software.*?Version|Cisco IOS Software.*?"
                        r"Version|Version)\s+([0-9][0-9A-Za-z().]+)", text)
    if version:
        facts["version"] = version.group(1).rstrip(",")
    model = re.search(r"cisco\s+(\S+)\s+\(", text)
    if model:
        facts["model"] = model.group(1)
    return facts


def identity_warnings(project, detected: dict) -> list[str]:
    warnings = []
    expected_hostname = (getattr(project, "data", {})
                         .get("system", {}).get("hostname", "")).strip()
    detected_hostname = (detected.get("hostname") or "").strip()
    if expected_hostname and detected_hostname \
            and expected_hostname.lower() != detected_hostname.lower():
        warnings.append(
            f"Connected hostname '{detected_hostname}' does not match project "
            f"hostname '{expected_hostname}'.")
    expected_model = getattr(project, "device_model", "")
    detected_model = detected.get("model", "")
    if expected_model and detected_model \
            and expected_model.lower() not in detected_model.lower():
        warnings.append(
            f"Detected platform '{detected_model}' does not match selected "
            f"profile '{expected_model}'.")
    expected_version = getattr(project, "os_version", "")
    detected_version = detected.get("version", "")
    if expected_version and detected_version and expected_version not in detected_version:
        warnings.append(
            f"Detected OS version '{detected_version}' differs from selected "
            f"version '{expected_version}'.")
    return warnings


def rollback_notes(backup_path: str = "") -> str:
    backup = backup_path or "the timestamped running-config backup"
    return (
        "Keep console or out-of-band access available. If rollback is needed, "
        f"compare the current running-config to {backup}, then manually paste "
        "the known-good commands or restore in a lab-tested procedure. Do not "
        "use config replace unless the platform behavior is understood and "
        "explicitly approved."
    )


def deployment_report_markdown(report: DeploymentReport) -> str:
    data = report.to_dict()
    lines = [
        "# Deployment Report",
        "",
        DEPLOYMENT_WARNING,
        "",
        f"- Timestamp: {data['timestamp']}",
        f"- SSH profile: {data['ssh_profile_name']}",
        f"- Target: {data['target']}",
        f"- Detected hostname: {data['detected_hostname'] or 'unknown'}",
        f"- Selected project device: {data['selected_project_device'] or 'unknown'}",
        f"- Capability profile: {data['selected_capability_profile'] or 'device-profile'}",
        f"- Detected platform/version: "
        f"{data['detected_platform'] or 'unknown'} / {data['detected_version'] or 'unknown'}",
        f"- Validation status: {data['validation_status'] or 'unknown'}",
        f"- Backup path: {data['backup_path'] or 'not created'}",
        f"- Diff summary: {data['diff_summary'] or 'not generated'}",
        f"- Deployment mode: {data['deployment_mode']}",
        f"- Save running-config: {data['save_running_config_status']}",
        "",
        "## Commands Sent",
    ]
    lines.extend(f"- `{command}`" for command in data["commands_sent"] or ["none"])
    lines.extend(["", "## Errors Detected"])
    lines.extend(f"- {err}" for err in data["errors_detected"] or ["none"])
    lines.extend(["", "## Pre-Checks"])
    for command, status in data["precheck_summary"].items():
        lines.append(f"- `{command}`: {status}")
    lines.extend(["", "## Post-Checks"])
    for command, status in data["postcheck_summary"].items():
        lines.append(f"- `{command}`: {status}")
    lines.extend(["", "## Warnings"])
    lines.extend(f"- {warning}" for warning in data["warnings"] or ["none"])
    lines.extend(["", "## Rollback Notes", data["rollback_notes"] or rollback_notes()])
    return "\n".join(lines) + "\n"


def deployment_report_text(report: DeploymentReport) -> str:
    return deployment_report_markdown(report).replace("#", "").replace("`", "")


def deployment_report_json(report: DeploymentReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def new_report(profile: SSHProfile | None, project, **kwargs) -> DeploymentReport:
    target = ""
    profile_name = ""
    if profile is not None:
        target = f"{profile.host}:{profile.port}"
        profile_name = profile.name
    return DeploymentReport(
        timestamp=datetime.now().isoformat(timespec="seconds"),
        ssh_profile_name=profile_name,
        target=target,
        selected_project_device=getattr(project, "device_model", ""),
        selected_capability_profile=(
            profile.capability_profile if profile is not None else "device-profile"),
        **kwargs,
    )
