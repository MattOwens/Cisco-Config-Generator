"""Generated configuration lint/compliance checks."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass


@dataclass
class LintIssue:
    severity: str
    category: str
    message: str
    suggested_fix: str
    section: str = ""
    capability: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _issue(severity: str, category: str, message: str, fix: str,
           section: str = "", capability: str = "") -> LintIssue:
    return LintIssue(severity, category, message, fix, section, capability)


def lint_config(config: str, project=None, profile=None) -> list[LintIssue]:
    text = config or ""
    lower = text.lower()
    issues: list[LintIssue] = []
    if "\nhostname " not in lower and not lower.startswith("hostname "):
        issues.append(_issue("error", "identity", "Missing hostname.",
                             "Set a hostname in Base System.", "system"))
    if "enable secret " not in lower:
        issues.append(_issue("warning", "identity", "Missing enable secret.",
                             "Set a strong enable secret.", "system"))
    for weak in ("username admin password cisco", "username cisco", " password cisco"):
        if weak in lower:
            issues.append(_issue("critical", "credentials", "Weak local credentials detected.",
                                 "Replace default credentials with unique secrets.", "system"))
            break
    if "transport input telnet" in lower or "transport input ssh telnet" in lower:
        issues.append(_issue("warning", "management", "Telnet is enabled on VTY lines.",
                             "Use SSH-only management access.", "system"))
    if "\nip http server" in lower:
        issues.append(_issue("warning", "management", "HTTP server is enabled.",
                             "Disable HTTP or restrict it with an ACL.", "security"))
    if "ip ssh version" in lower and "ip domain-name" not in lower:
        issues.append(_issue("error", "management", "SSH is enabled without a domain name.",
                             "Set ip domain-name before RSA key generation.", "system"))
    if "line vty" in lower and "access-class" not in lower:
        issues.append(_issue("warning", "management", "VTY lines have no access-class.",
                             "Apply a management ACL to VTY lines.", "acls"))
    if "snmp-server community public" in lower or "snmp-server community private" in lower:
        issues.append(_issue("warning", "monitoring", "Default SNMP community detected.",
                             "Use SNMPv3 or a unique community restricted by ACL.", "system", "snmpv3"))
    if "permit ip any any" in lower:
        issues.append(_issue("warning", "acls", "ACL permits all IP traffic.",
                             "Narrow the ACL source, destination or protocol.", "acls"))
    if "switchport trunk native vlan 1" in lower:
        issues.append(_issue("info", "layer2", "Native VLAN 1 is configured.",
                             "Use an unused dedicated native VLAN.", "interfaces"))
    if "switchport access vlan 1" in lower:
        issues.append(_issue("info", "layer2", "Access VLAN 1 is configured.",
                             "Move user ports to a non-default VLAN.", "interfaces"))
    if "switchport mode trunk" in lower and "switchport trunk allowed vlan" not in lower:
        issues.append(_issue("warning", "layer2", "A trunk may allow all VLANs.",
                             "Prune trunks with switchport trunk allowed vlan.", "interfaces"))
    if "vlan " in lower and "switchport access vlan" not in lower and "interface vlan" not in lower:
        issues.append(_issue("info", "layer2", "Configured VLANs may be unused.",
                             "Confirm VLANs are assigned to ports or SVIs.", "vlans"))
    if "description uplink" in lower and "\n shutdown" in lower:
        issues.append(_issue("warning", "interfaces", "A described uplink may be shut down.",
                             "Verify intended shutdown state.", "interfaces"))
    if "ip route 0.0.0.0 0.0.0.0" not in lower and "ip default-gateway" not in lower:
        issues.append(_issue("info", "routing", "No default route/default gateway found.",
                             "Add default reachability if the device needs off-subnet access.", "layer3"))
    if "ntp server" not in lower:
        issues.append(_issue("info", "management", "No NTP servers configured.",
                             "Add redundant NTP servers.", "system"))
    if "logging host" not in lower:
        issues.append(_issue("info", "management", "No remote syslog destination configured.",
                             "Add logging hosts for auditability.", "system"))
    if "ip nat inside source" in lower and ("ip nat inside" not in lower or "ip nat outside" not in lower):
        issues.append(_issue("error", "nat", "NAT rules exist without inside/outside markings.",
                             "Mark inside and outside interfaces.", "nat", "nat"))
    if "interface tunnel" in lower and ("ip nhrp network-id" not in lower or "tunnel source" not in lower):
        issues.append(_issue("warning", "dmvpn", "DMVPN tunnel appears incomplete.",
                             "Add tunnel source and NHRP network-id.", "dmvpn", "dmvpn"))
    if "crypto ipsec profile" in lower and "tunnel protection ipsec profile" not in lower:
        issues.append(_issue("warning", "crypto", "IPsec profile is configured but not applied to a tunnel.",
                             "Apply tunnel protection ipsec profile under the tunnel.", "dmvpn", "ipsec"))
    referenced_tracks = set(re.findall(r"^ip route .* track (\d+)", text,
                                       flags=re.MULTILINE))
    defined_tracks = set(re.findall(r"^track (\d+) ", text, flags=re.MULTILINE))
    for track_id in sorted(referenced_tracks - defined_tracks):
        issues.append(_issue("warning", "ipsla",
                             f"A static route references track {track_id} but no "
                             "track object with that ID was found.",
                             "Create the track object tied to IP SLA.",
                             "ipsla", "object_tracking"))
    if project is not None and any(
            w.get("section") == "platform"
            and "not listed for this device profile" in w.get("message", "").lower()
            for w in getattr(project, "warnings", [])):
        issues.append(_issue("warning", "platform", "Generated config uses a feature "
                             "the selected device profile does not list.",
                             "Change the selected device profile or remove the feature.", "platform"))
    return issues


def report_markdown(issues: list[LintIssue], title: str = "Validation and Lint Report") -> str:
    lines = [f"# {title}", ""]
    if not issues:
        lines.append("No lint issues detected.")
        return "\n".join(lines) + "\n"
    lines.append("| Severity | Category | Section | Message | Suggested fix |")
    lines.append("|---|---|---|---|---|")
    for issue in issues:
        lines.append(f"| {issue.severity} | {issue.category} | {issue.section} | "
                     f"{issue.message} | {issue.suggested_fix} |")
    return "\n".join(lines) + "\n"


def report_text(issues: list[LintIssue], title: str = "Validation and Lint Report") -> str:
    lines = [title, "=" * len(title), ""]
    if not issues:
        lines.append("No lint issues detected.")
        return "\n".join(lines) + "\n"
    for issue in issues:
        lines.append(f"[{issue.severity.upper()}] {issue.category} / {issue.section}")
        lines.append(issue.message)
        lines.append(f"Suggested fix: {issue.suggested_fix}")
        if issue.capability:
            lines.append(f"Capability: {issue.capability}")
        lines.append("")
    return "\n".join(lines)
