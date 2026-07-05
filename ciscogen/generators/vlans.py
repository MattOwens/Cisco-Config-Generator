"""VLAN definitions and Layer 2 security (STP, DHCP snooping, DAI, VTP)."""

from __future__ import annotations

from ..utils import normalize_interface_name, parse_list, s, safe_int, truthy


def collect_interface_extras(vlan_data: dict, extras: dict[str, list[str]]) -> None:
    """Trusted-interface commands merged into interface blocks."""
    snooping = vlan_data.get("dhcp_snooping", {})
    if truthy(snooping.get("enabled")):
        for name in parse_list(snooping.get("trusted_interfaces")):
            extras.setdefault(normalize_interface_name(name), []).append(
                " ip dhcp snooping trust")
    dai = vlan_data.get("dai", {})
    if truthy(dai.get("enabled")):
        for name in parse_list(dai.get("trusted_interfaces")):
            extras.setdefault(normalize_interface_name(name), []).append(
                " ip arp inspection trust")


def generate(vlan_data: dict, profile) -> dict[str, list[str]]:
    return {
        "vlans": _vlan_definitions(vlan_data),
        "l2_security": _l2_security(vlan_data, profile),
    }


def _vlan_definitions(vlan_data: dict) -> list[str]:
    lines: list[str] = []
    seen: set[int] = set()
    for vlan in vlan_data.get("vlans", []):
        vid = safe_int(vlan.get("id"))
        if vid is None or vid in seen:
            continue
        seen.add(vid)
        lines.append(f"vlan {vid}")
        name = s(vlan.get("name"))
        if name:
            lines.append(f" name {name.replace(' ', '_')}")
    blackhole = safe_int(vlan_data.get("blackhole_vlan"))
    if blackhole and blackhole not in seen:
        lines.append(f"vlan {blackhole}")
        lines.append(" name BLACKHOLE-UNUSED")
    return lines


def _l2_security(vlan_data: dict, profile) -> list[str]:
    lines: list[str] = []
    stp = vlan_data.get("stp", {})
    mode = s(stp.get("mode"))
    if mode:
        lines.append(f"spanning-tree mode {mode}")
    if truthy(stp.get("portfast_default")):
        lines.append("spanning-tree portfast default")
    if truthy(stp.get("bpduguard_default")):
        lines.append("spanning-tree portfast bpduguard default")
    root_primary = s(stp.get("root_primary"))
    if root_primary:
        lines.append(f"spanning-tree vlan {root_primary.replace(' ', '')} root primary")
    root_secondary = s(stp.get("root_secondary"))
    if root_secondary:
        lines.append(f"spanning-tree vlan {root_secondary.replace(' ', '')} root secondary")
    priority_vlans = s(stp.get("priority_vlans"))
    priority_value = s(stp.get("priority_value"))
    if priority_vlans and priority_value:
        lines.append(f"spanning-tree vlan {priority_vlans.replace(' ', '')} "
                     f"priority {priority_value}")

    snooping = vlan_data.get("dhcp_snooping", {})
    if truthy(snooping.get("enabled")):
        lines.append("ip dhcp snooping")
        vlans = s(snooping.get("vlans"))
        if vlans:
            lines.append(f"ip dhcp snooping vlan {vlans.replace(' ', '')}")

    dai = vlan_data.get("dai", {})
    if truthy(dai.get("enabled")):
        vlans = s(dai.get("vlans"))
        if vlans:
            lines.append(f"ip arp inspection vlan {vlans.replace(' ', '')}")

    vtp = vlan_data.get("vtp", {})
    if truthy(vtp.get("enabled")):
        domain = s(vtp.get("domain"))
        if domain:
            lines.append(f"vtp domain {domain}")
        lines.append(f"vtp mode {s(vtp.get('mode', 'transparent')) or 'transparent'}")
        password = s(vtp.get("password"))
        if password:
            lines.append(f"vtp password {password}")
    errdisable = vlan_data.get("errdisable_recovery", {})
    if truthy(errdisable.get("enabled")):
        for cause in parse_list(errdisable.get("causes")):
            lines.append(f"errdisable recovery cause {cause}")
        interval = s(errdisable.get("interval"))
        if interval:
            lines.append(f"errdisable recovery interval {interval}")
    for pvlan in vlan_data.get("private_vlans", []):
        primary = safe_int(pvlan.get("primary"))
        secondary = safe_int(pvlan.get("secondary"))
        pvlan_type = s(pvlan.get("type", "isolated")) or "isolated"
        if primary and secondary:
            lines.append(f"vlan {secondary}")
            lines.append(f" private-vlan {pvlan_type}")
            lines.append(f"vlan {primary}")
            lines.append(" private-vlan primary")
            lines.append(f" private-vlan association {secondary}")
    for span in vlan_data.get("span_sessions", []):
        session = s(span.get("session"))
        source = s(span.get("source"))
        destination = s(span.get("destination"))
        if session and source:
            direction = s(span.get("direction", "both")) or "both"
            lines.append(f"monitor session {session} source interface "
                         f"{normalize_interface_name(source)} {direction}")
        if session and destination:
            lines.append(f"monitor session {session} destination interface "
                         f"{normalize_interface_name(destination)}")
    stack = vlan_data.get("stackwise", {})
    if truthy(stack.get("enabled")) and s(stack.get("switch_number")):
        number = s(stack.get("switch_number"))
        if s(stack.get("priority")):
            lines.append(f"switch {number} priority {s(stack.get('priority'))}")
    return lines
