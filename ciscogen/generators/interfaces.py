"""Interface generator: physical ports, port-channels, subinterfaces, SVIs.

Other sections (NAT, ACLs, DHCP snooping trust, PBR) contribute per-interface
lines through the ``extras`` mapping.  Lines for interfaces defined here are
merged into their blocks; anything left over is rendered as standalone
interface blocks at the end so no configuration is silently dropped.
"""

from __future__ import annotations

from ..utils import normalize_interface_name, parse_list, s, safe_int, truthy


def generate(if_data: dict, profile, extras: dict[str, list[str]] | None = None
             ) -> dict[str, list[str]]:
    extras = dict(extras or {})
    lines: list[str] = []

    for item in if_data.get("physical", []):
        lines.extend(_physical_block(item, profile, extras))
    for pc in if_data.get("port_channels", []):
        lines.extend(_port_channel_block(pc, profile, extras))
    for sub in if_data.get("subinterfaces", []):
        lines.extend(_subinterface_block(sub, extras))
    for svi in if_data.get("svis", []):
        lines.extend(_svi_block(svi, extras))

    # Standalone blocks for interfaces referenced only by other sections.
    for name, extra_lines in extras.items():
        if not name or not extra_lines:
            continue
        lines.append(f"interface {name}")
        lines.extend(extra_lines)
    return {"interfaces": lines}


def _take_extras(extras: dict, name: str) -> list[str]:
    return extras.pop(name, [])


def _take_early_extras(extras: dict, name: str) -> list[str]:
    lines = extras.get(name, [])
    early = [line for line in lines
             if line.startswith((" vrf forwarding", " ip vrf forwarding"))]
    if not early:
        return []
    remaining = [line for line in lines if line not in early]
    if remaining:
        extras[name] = remaining
    else:
        extras.pop(name, None)
    return early


def _physical_block(item: dict, profile, extras: dict) -> list[str]:
    name = normalize_interface_name(s(item.get("name")))
    if not name:
        return []
    lines = [f"interface {name}"]
    description = s(item.get("description"))
    if description:
        lines.append(f" description {description}")
    lines.extend(_take_early_extras(extras, name))

    mode = s(item.get("mode", "access"))
    is_switch = profile.supports("layer2")

    if mode == "routed" and is_switch:
        lines.append(" no switchport")
    if mode == "access" and is_switch:
        lines.append(" switchport mode access")
        access_vlan = s(item.get("access_vlan"))
        if access_vlan:
            lines.append(f" switchport access vlan {access_vlan}")
        voice_vlan = s(item.get("voice_vlan"))
        if voice_vlan:
            lines.append(f" switchport voice vlan {voice_vlan}")
    elif mode == "trunk" and is_switch:
        if profile.supports("requires_trunk_encap"):
            lines.append(" switchport trunk encapsulation dot1q")
        lines.append(" switchport mode trunk")
        native = s(item.get("native_vlan"))
        if native:
            lines.append(f" switchport trunk native vlan {native}")
        allowed = s(item.get("allowed_vlans"))
        if allowed:
            lines.append(f" switchport trunk allowed vlan {allowed.replace(' ', '')}")
        if truthy(item.get("nonegotiate")):
            lines.append(" switchport nonegotiate")
    elif mode == "routed":
        ip, mask = s(item.get("ip")), s(item.get("mask"))
        if ip and mask:
            lines.append(f" ip address {ip} {mask}")
        for helper in parse_list(item.get("helper")):
            lines.append(f" ip helper-address {helper}")

    if mode == "access":
        if truthy(item.get("portfast")):
            lines.append(" spanning-tree portfast")
        if truthy(item.get("bpduguard")):
            lines.append(" spanning-tree bpduguard enable")
    if truthy(item.get("rootguard")):
        lines.append(" spanning-tree guard root")
    if truthy(item.get("loopguard")):
        lines.append(" spanning-tree guard loop")
    if truthy(item.get("udld")):
        udld_mode = s(item.get("udld_mode", "port aggressive")) or "port aggressive"
        lines.append(f" udld {udld_mode}")

    storm_bc = s(item.get("storm_bc"))
    if storm_bc:
        lines.append(f" storm-control broadcast level {storm_bc}")
    storm_mc = s(item.get("storm_mc"))
    if storm_mc:
        lines.append(f" storm-control multicast level {storm_mc}")
    storm_uc = s(item.get("storm_uc"))
    if storm_uc:
        lines.append(f" storm-control unicast level {storm_uc}")

    if truthy(item.get("ps_enabled")) and mode == "access":
        lines.append(" switchport port-security")
        ps_max = s(item.get("ps_max"))
        if ps_max:
            lines.append(f" switchport port-security maximum {ps_max}")
        violation = s(item.get("ps_violation"))
        if violation and violation != "shutdown":
            lines.append(f" switchport port-security violation {violation}")
        if truthy(item.get("ps_sticky")):
            lines.append(" switchport port-security mac-address sticky")

    if truthy(item.get("ip_source_guard")):
        lines.append(" ip verify source")

    group = safe_int(item.get("channel_group"))
    if group is not None:
        channel_mode = s(item.get("channel_mode", "active")) or "active"
        lines.append(f" channel-group {group} mode {channel_mode}")

    speed = s(item.get("speed"))
    if speed and speed != "auto":
        lines.append(f" speed {speed}")
    duplex = s(item.get("duplex"))
    if duplex and duplex != "auto":
        lines.append(f" duplex {duplex}")
    mtu = s(item.get("mtu"))
    if mtu:
        lines.append(f" mtu {mtu}")

    if truthy(item.get("cdp_disabled")):
        lines.append(" no cdp enable")
    if truthy(item.get("lldp_disabled")):
        lines.append(" no lldp transmit")
        lines.append(" no lldp receive")

    lines.extend(_take_extras(extras, name))
    lines.append(" no shutdown" if truthy(item.get("enabled", True)) else " shutdown")
    return lines


def _port_channel_block(pc: dict, profile, extras: dict) -> list[str]:
    pc_id = s(pc.get("id"))
    if not pc_id:
        return []
    name = f"Port-channel{pc_id}"
    lines = [f"interface {name}"]
    description = s(pc.get("description"))
    if description:
        lines.append(f" description {description}")
    lines.extend(_take_early_extras(extras, name))
    mode = s(pc.get("mode", "trunk"))
    is_switch = profile.supports("layer2")
    if mode == "routed":
        if is_switch:
            lines.append(" no switchport")
        ip, mask = s(pc.get("ip")), s(pc.get("mask"))
        if ip and mask:
            lines.append(f" ip address {ip} {mask}")
    elif mode == "access" and is_switch:
        lines.append(" switchport mode access")
        access_vlan = s(pc.get("access_vlan"))
        if access_vlan:
            lines.append(f" switchport access vlan {access_vlan}")
    elif mode == "trunk" and is_switch:
        if profile.supports("requires_trunk_encap"):
            lines.append(" switchport trunk encapsulation dot1q")
        lines.append(" switchport mode trunk")
        native = s(pc.get("native_vlan"))
        if native:
            lines.append(f" switchport trunk native vlan {native}")
        allowed = s(pc.get("allowed_vlans"))
        if allowed:
            lines.append(f" switchport trunk allowed vlan {allowed.replace(' ', '')}")
    lines.extend(_take_extras(extras, name))
    return lines


def _subinterface_block(sub: dict, extras: dict) -> list[str]:
    parent = normalize_interface_name(s(sub.get("parent")))
    vlan = s(sub.get("vlan"))
    if not parent or not vlan:
        return []
    name = f"{parent}.{vlan}"
    lines = [f"interface {name}"]
    description = s(sub.get("description"))
    if description:
        lines.append(f" description {description}")
    lines.extend(_take_early_extras(extras, name))
    native = " native" if truthy(sub.get("native")) else ""
    lines.append(f" encapsulation dot1Q {vlan}{native}")
    ip, mask = s(sub.get("ip")), s(sub.get("mask"))
    if ip and mask:
        lines.append(f" ip address {ip} {mask}")
    for helper in parse_list(sub.get("helper")):
        lines.append(f" ip helper-address {helper}")
    lines.extend(_take_extras(extras, name))
    return lines


def _svi_block(svi: dict, extras: dict) -> list[str]:
    vlan = s(svi.get("vlan"))
    if not vlan:
        return []
    name = f"Vlan{vlan}"
    lines = [f"interface {name}"]
    description = s(svi.get("description"))
    if description:
        lines.append(f" description {description}")
    lines.extend(_take_early_extras(extras, name))
    ip, mask = s(svi.get("ip")), s(svi.get("mask"))
    if ip and mask:
        lines.append(f" ip address {ip} {mask}")
    for helper in parse_list(svi.get("helper")):
        lines.append(f" ip helper-address {helper}")
    lines.extend(_take_extras(extras, name))
    lines.append(" no shutdown" if truthy(svi.get("enabled", True)) else " shutdown")
    return lines
