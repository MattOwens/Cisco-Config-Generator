"""Gateway redundancy generator for HSRP, VRRP and GLBP."""

from __future__ import annotations

from ..utils import normalize_interface_name, s, truthy


def collect_interface_extras(ha_data: dict, extras: dict[str, list[str]]) -> None:
    for group in ha_data.get("groups", []):
        interface = normalize_interface_name(s(group.get("interface")))
        protocol = s(group.get("protocol", "hsrp")).lower() or "hsrp"
        group_id = s(group.get("group", "1")) or "1"
        vip = s(group.get("virtual_ip"))
        if not interface or not vip:
            continue
        lines: list[str] = []
        if protocol == "vrrp":
            lines.append(f" vrrp {group_id} ip {vip}")
            if s(group.get("priority")):
                lines.append(f" vrrp {group_id} priority {s(group.get('priority'))}")
            if truthy(group.get("preempt")):
                lines.append(f" vrrp {group_id} preempt")
            if s(group.get("auth")):
                lines.append(f" vrrp {group_id} authentication text {s(group.get('auth'))}")
        elif protocol == "glbp":
            lines.append(f" glbp {group_id} ip {vip}")
            if s(group.get("priority")):
                lines.append(f" glbp {group_id} priority {s(group.get('priority'))}")
            if truthy(group.get("preempt")):
                lines.append(f" glbp {group_id} preempt")
            if s(group.get("auth")):
                lines.append(f" glbp {group_id} authentication text {s(group.get('auth'))}")
        else:
            lines.append(f" standby {group_id} ip {vip}")
            if s(group.get("priority")):
                lines.append(f" standby {group_id} priority {s(group.get('priority'))}")
            if truthy(group.get("preempt")):
                lines.append(f" standby {group_id} preempt")
            if s(group.get("auth")):
                lines.append(f" standby {group_id} authentication {s(group.get('auth'))}")
        track_id = s(group.get("track_id"))
        decrement = s(group.get("decrement", "10")) or "10"
        if track_id:
            keyword = {"vrrp": "vrrp", "glbp": "glbp"}.get(protocol, "standby")
            lines.append(f" {keyword} {group_id} track {track_id} decrement {decrement}")
        extras.setdefault(interface, []).extend(lines)
