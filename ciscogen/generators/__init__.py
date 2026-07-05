"""Config generation orchestrator.

Each feature module contributes lines to named segments; this module
assembles the segments in Cisco-conventional order, removes duplicate
global commands and renders the final text.

Segment order (per the application spec):
    1. services          global/service commands
    2. identity          hostname/domain/security basics
    3. aaa_users         AAA & local users
    4. custom_global     user global CLI
    5. vrfs              VRF definitions
    6. vlans             VLAN definitions
    7. l2_security       STP / DHCP snooping / DAI / VTP
    8. crypto            IKE/IPsec definitions
    9. zbf               zone firewall definitions
    10. qos              QoS definitions
    11. custom_pre_interface user CLI before interface blocks
    12. interfaces       physical, logical and tunnel interfaces
    13. dhcp             DHCP pools
    14. acls             access lists / route maps
    15. nat              NAT/PAT
    16. routing          dynamic routing protocols
    17. ipsla            IP SLA / track / EEM
    18. static_routes    static/default routes
    19. custom_post_routing user CLI after routing
    20. lines            console & VTY
    21. management       logging / NTP / SNMP
    22. archive          archive configuration
    23. custom_end       end-of-config user CLI
"""

from __future__ import annotations

from ..utils import truthy
from . import (
    acl, base, custom_cli, dhcp, dmvpn, ha, interfaces, ipsla, ipv6, layer3,
    misc, nat, qos, routing, security, tunnels, vlans, vrf, zbf,
)

SEGMENT_ORDER = [
    "services", "identity", "aaa_users", "custom_global", "vrfs", "vlans",
    "l2_security", "crypto", "zbf", "qos", "custom_pre_interface",
    "interfaces", "dhcp", "acls", "nat", "routing", "ipsla",
    "static_routes", "custom_post_routing", "lines", "management", "archive",
    "custom_end",
]

SEGMENT_LABELS = {
    "services": "Global services",
    "identity": "Identity & security basics",
    "aaa_users": "AAA & local users",
    "custom_global": "Custom global CLI",
    "vrfs": "VRF definitions",
    "vlans": "VLANs",
    "l2_security": "Spanning tree & Layer 2 security",
    "crypto": "IKE / IPsec",
    "zbf": "Zone-Based Firewall",
    "qos": "QoS",
    "custom_pre_interface": "Custom pre-interface CLI",
    "interfaces": "Interfaces",
    "dhcp": "DHCP",
    "acls": "Access lists",
    "nat": "NAT / PAT",
    "routing": "Routing protocols",
    "ipsla": "IP SLA and object tracking",
    "static_routes": "Static routes",
    "custom_post_routing": "Custom post-routing CLI",
    "lines": "Console & VTY lines",
    "management": "Logging, NTP & SNMP",
    "archive": "Configuration archive",
    "custom_end": "Custom end-of-config CLI",
}


def _merge(target: dict, contribution: dict) -> None:
    for segment, lines in contribution.items():
        if lines:
            target.setdefault(segment, []).extend(lines)


def _dedupe_globals(lines: list[str]) -> list[str]:
    """Drop repeated global-level commands (never indented lines, separators,
    interface headers or banner bodies)."""
    seen: set[str] = set()
    out: list[str] = []
    in_banner = False
    banner_delim = ""
    for line in lines:
        if in_banner:
            out.append(line)
            if line.strip() == banner_delim or line.strip().endswith(banner_delim):
                in_banner = False
            continue
        stripped = line.strip()
        if stripped.startswith("banner "):
            # Our banners are always "banner motd ^" + body + "^"; skip
            # dedupe until the closing delimiter so body text is untouched.
            out.append(line)
            banner_delim = stripped.split()[-1]
            in_banner = True
            continue
        if line.startswith(" ") or line == "!" or line.startswith("!"):
            out.append(line)
            continue
        if line.startswith("interface "):
            out.append(line)
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def _collapse_separators(lines: list[str]) -> list[str]:
    out: list[str] = []
    for line in lines:
        if line == "!" and (not out or out[-1] == "!"):
            continue
        out.append(line)
    return out


def generate_config(project, profile) -> str:
    """Render the full configuration for the project/profile pair."""
    data = project.data
    enabled = project.sections_enabled
    segments: dict[str, list[str]] = {}

    # Interface-level lines contributed by other sections (NAT inside/outside,
    # snooping/DAI trust, ACL bindings, PBR).  The interfaces generator merges
    # them into blocks it renders; leftovers become standalone blocks.
    extras: dict[str, list[str]] = {}
    if enabled.get("system"):
        base.collect_interface_extras(data["system"], extras)
    if enabled.get("vlans"):
        vlans.collect_interface_extras(data["vlans"], extras)
    if enabled.get("vrf"):
        vrf.collect_interface_extras(data["vrf"], extras)
    if enabled.get("ipv6"):
        ipv6.collect_interface_extras(data["ipv6"], extras)
    if enabled.get("nat"):
        nat.collect_interface_extras(data["nat"], extras)
    if enabled.get("acls"):
        acl.collect_interface_extras(data["acls"], extras)
    if enabled.get("layer3"):
        layer3.collect_interface_extras(data["layer3"], extras)
    if enabled.get("zbf"):
        zbf.collect_interface_extras(data["zbf"], extras)
    if enabled.get("qos"):
        qos.collect_interface_extras(data["qos"], extras, profile)
    if enabled.get("ha"):
        ha.collect_interface_extras(data["ha"], extras)
    if enabled.get("custom_cli"):
        custom_cli.collect_interface_extras(data["custom_cli"], extras)

    if enabled.get("system"):
        _merge(segments, base.generate(data["system"], profile))
    if enabled.get("security"):
        _merge(segments, security.generate(data["security"], profile))
    if enabled.get("misc"):
        _merge(segments, misc.generate(data["misc"], profile))
    if enabled.get("custom_cli"):
        _merge(segments, custom_cli.generate(data["custom_cli"], profile))
    if enabled.get("vrf"):
        _merge(segments, vrf.generate(data["vrf"], profile))
    if enabled.get("vlans"):
        _merge(segments, vlans.generate(data["vlans"], profile))
    if enabled.get("layer3"):
        _merge(segments, layer3.generate(data["layer3"], profile))
    if enabled.get("ipv6"):
        _merge(segments, ipv6.generate(data["ipv6"], profile))
    if enabled.get("tunnels"):
        _merge(segments, tunnels.generate(data["tunnels"], profile))
    if enabled.get("dmvpn"):     # legacy single-DMVPN (pre-migration projects)
        _merge(segments, dmvpn.generate(data["dmvpn"], profile))
    if enabled.get("zbf"):
        _merge(segments, zbf.generate(data["zbf"], profile))
    if enabled.get("qos"):
        _merge(segments, qos.generate(data["qos"], profile))
    if enabled.get("interfaces") or extras:
        _merge(segments, interfaces.generate(
            data["interfaces"] if enabled.get("interfaces")
            else {"physical": [], "port_channels": [], "subinterfaces": [], "svis": []},
            profile, extras))
    if enabled.get("dhcp"):
        _merge(segments, dhcp.generate(data["dhcp"], profile))
    if enabled.get("acls"):
        _merge(segments, acl.generate(data["acls"], profile))
    if enabled.get("nat"):
        _merge(segments, nat.generate(data["nat"], profile))
    if enabled.get("routing"):
        _merge(segments, routing.generate(data["routing"], profile))
    if enabled.get("ipsla"):
        _merge(segments, ipsla.generate(data["ipsla"], profile))
    if enabled.get("system"):
        force_ssh = enabled.get("security") and truthy(
            data["security"].get("ssh_only"))
        vty_acl = data["acls"].get("vty_acl", "") if enabled.get("acls") else ""
        _merge(segments, base.generate_lines(data["system"], profile,
                                             vty_acl=vty_acl,
                                             force_ssh=bool(force_ssh)))
        mgmt_acl = data["acls"].get("management_plane_acl", "") \
            if enabled.get("acls") else ""
        _merge(segments, base.generate_management(data["system"], profile,
                                                  mgmt_acl=mgmt_acl))

    include_comments = truthy(project.options.get("include_comments"))
    lines: list[str] = ["!"]
    for segment in SEGMENT_ORDER:
        seg_lines = segments.get(segment)
        if not seg_lines:
            continue
        if include_comments:
            lines.append(f"! --- {SEGMENT_LABELS[segment]} ---")
        lines.extend(seg_lines)
        lines.append("!")
    lines.append("end")

    lines = _dedupe_globals(lines)
    lines = _collapse_separators(lines)
    return "\n".join(lines) + "\n"
