"""Validation framework: every check returns a list of Issue objects."""

from __future__ import annotations

from dataclasses import dataclass, asdict

ERROR = "error"
WARNING = "warning"
INFO = "info"


@dataclass
class Issue:
    severity: str   # error | warning | info
    section: str    # section key or "platform"
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


def error(section: str, message: str) -> Issue:
    return Issue(ERROR, section, message)


def warning(section: str, message: str) -> Issue:
    return Issue(WARNING, section, message)


def info(section: str, message: str) -> Issue:
    return Issue(INFO, section, message)


def validate_project(project, profile) -> list[Issue]:
    """Run every applicable validator for the enabled sections."""
    from . import sections, platform as platform_checks

    issues: list[Issue] = []
    enabled = project.sections_enabled
    data = project.data

    if enabled.get("system"):
        issues += sections.validate_system(
            data["system"], profile,
            acl_data=data["acls"] if enabled.get("acls") else None)
    if enabled.get("interfaces"):
        issues += sections.validate_interfaces(data["interfaces"], profile)
    if enabled.get("vlans"):
        issues += sections.validate_vlans(data["vlans"], profile)
    if enabled.get("layer3"):
        issues += sections.validate_layer3(data["layer3"], profile)
    if enabled.get("vrf"):
        issues += sections.validate_vrf(data["vrf"], data["interfaces"], profile)
    if enabled.get("ipv6"):
        issues += sections.validate_ipv6(data["ipv6"], profile)
    if enabled.get("dhcp"):
        issues += sections.validate_dhcp(data["dhcp"], profile)
    if enabled.get("nat"):
        issues += sections.validate_nat(data["nat"], data["interfaces"], profile)
    if enabled.get("acls"):
        issues += sections.validate_acls(data["acls"], data["interfaces"], profile)
    if enabled.get("routing"):
        issues += sections.validate_routing(data["routing"], profile)
    if enabled.get("tunnels"):
        from ..profiles.capabilities import resolve_capabilities
        issues += sections.validate_tunnels(
            data["tunnels"], profile, resolve_capabilities(project, profile))
    if enabled.get("dmvpn"):
        issues += sections.validate_dmvpn(data["dmvpn"], profile)
    if enabled.get("ipsla"):
        issues += sections.validate_ipsla(data["ipsla"], profile)
    if enabled.get("zbf"):
        issues += sections.validate_zbf(
            data["zbf"], profile,
            if_data=data["interfaces"] if enabled.get("interfaces") else None,
            dmvpn_data=data["dmvpn"] if enabled.get("dmvpn") else None,
            tunnels_data=data["tunnels"] if enabled.get("tunnels") else None)
    if enabled.get("qos"):
        issues += sections.validate_qos(data["qos"], data["interfaces"], profile)
    if enabled.get("ha"):
        issues += sections.validate_ha(data["ha"], data.get("ipsla", {}), profile)
    if enabled.get("security"):
        issues += sections.validate_security(data["security"], data["system"], profile)
    if enabled.get("custom_cli"):
        issues += sections.validate_custom_cli(data["custom_cli"], profile)

    issues += sections.validate_duplicate_ips(data, enabled)
    issues += platform_checks.validate_platform(project, profile)

    order = {ERROR: 0, WARNING: 1, INFO: 2}
    issues.sort(key=lambda i: order.get(i.severity, 3))
    return issues
