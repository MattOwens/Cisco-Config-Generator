"""Report, checklist and deployment bundle exporters."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from .lint import lint_config, report_markdown
from .profiles.capabilities import (
    capability_summary,
    resolve_capabilities,
    resolve_feature_lock_state,
)


PRECHECK_COMMANDS = [
    "show version",
    "show running-config",
    "show startup-config",
    "show ip interface brief",
    "show interfaces status",
    "show vlan brief",
    "show ip route",
    "show cdp neighbors",
    "show lldp neighbors",
    "show spanning-tree summary",
    "show etherchannel summary",
    "show access-lists",
    "show license",
    "show license all",
    "show inventory",
    "show platform",
    "show crypto isakmp sa",
    "show crypto ikev2 sa",
    "show crypto ipsec sa",
    "show interfaces tunnel",
    "show dmvpn",
    "show ip nhrp",
    "show ip ospf neighbor",
    "show ip eigrp neighbors",
    "show ip bgp summary",
    "show ip sla summary",
    "show track",
]

POSTCHECK_ITEMS = [
    "No configuration mode errors were returned.",
    "Critical interfaces remain up/up.",
    "Routing neighbors are established.",
    "DMVPN tunnels and NHRP registrations are healthy when configured.",
    "IPsec SAs are present when encrypted tunnels are configured.",
    "IP SLA operations and track objects are up.",
    "Default route and management reachability are retained.",
    "No unexpected reload is scheduled.",
]


def validation_report_markdown(project, profile, config: str) -> str:
    issues = lint_config(config, project, profile)
    return report_markdown(issues)


def deployment_checklist_markdown(project, profile, config: str) -> str:
    lock_state = resolve_feature_lock_state(project, profile)
    enabled = [key for key, value in project.sections_enabled.items() if value]
    caps = sorted(resolve_capabilities(project, profile))
    lines = [
        "# Deployment Checklist",
        "",
        "Only connect to devices you own or are authorized to administer. "
        "Always test generated configs in a lab first.",
        "",
        f"- Device model: {project.device_model}",
        f"- OS: {project.os_type} {project.os_version}",
        f"- Feature summary: {capability_summary(project, profile, limit=20)}",
        f"- Enabled sections: {', '.join(enabled)}",
        f"- Device-profile capabilities: {', '.join(caps) if caps else 'unknown'}",
    ]
    availability = [
        f"- {state['label']}: {state['state']} - {state['reason']}"
        for key, state in lock_state.items()
        if key in enabled and state["state"] != "supported"
    ]
    if availability:
        lines.extend(["", "## Feature Availability"])
        lines.extend(availability)
    lines.extend(["", "## Pre-Deployment Checks"])
    lines.extend(f"- `{command}`" for command in PRECHECK_COMMANDS)
    lines.extend([
        "",
        "## Backup",
        "- Save `show running-config` and `show startup-config` before changes.",
        "- Export this project JSON and the generated candidate config.",
        "",
        "## Deployment Method",
        "- Review validation and lint reports.",
        "- Prefer a maintenance window and console/OOB access.",
        "- Dry-run/diff first; live deployment must be explicitly confirmed.",
        "",
        "## Post-Deployment Validation",
    ])
    lines.extend(f"- {item}" for item in POSTCHECK_ITEMS)
    if project.warnings:
        lines.extend(["", "## Validation Warnings"])
        for issue in project.warnings:
            lines.append(f"- [{issue.get('severity')}] {issue.get('section')}: {issue.get('message')}")
    return "\n".join(lines) + "\n"


def rollback_checklist_markdown(project, profile, config: str) -> str:
    hostname = project.data.get("system", {}).get("hostname") or project.device_model
    return (
        "# Rollback Checklist\n\n"
        f"- Target device: {hostname}\n"
        "- Confirm out-of-band access before rollback.\n"
        "- Keep the timestamped pre-change running-config backup available.\n"
        "- If only a few commands changed, prefer precise inverse commands.\n"
        "- If full restore is required, paste the saved running-config in a lab-tested procedure.\n"
        "- Do not use config replace on production equipment unless the platform behavior is known and approved.\n"
        "- Re-run post-checks after rollback and save the restored running-config only after confirmation.\n"
    )


def export_deployment_bundle(project, profile, config: str, destination: str | Path) -> Path:
    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    hostname = project.data.get("system", {}).get("hostname") or "config"
    files = {
        f"{hostname}.cfg": config,
        "project.json": json.dumps(project.to_dict(), indent=2),
        "validation_lint_report.md": validation_report_markdown(project, profile, config),
        "deployment_checklist.md": deployment_checklist_markdown(project, profile, config),
        "rollback_checklist.md": rollback_checklist_markdown(project, profile, config),
    }
    for name, text in files.items():
        (dest / name).write_text(text, encoding="utf-8", newline="\n")
    zip_path = dest / "deployment_bundle.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name in files:
            bundle.write(dest / name, arcname=name)
    return zip_path
