"""IP SLA, object tracking, tracked routes and simple EEM actions."""

from __future__ import annotations

from ..utils import normalize_interface_name, s


def generate(ipsla: dict, profile) -> dict[str, list[str]]:
    return {
        "ipsla": _operations(ipsla) + _tracks(ipsla) + _eem(ipsla),
        "static_routes": _routes(ipsla),
    }


def _operations(ipsla: dict) -> list[str]:
    lines: list[str] = []
    for op in ipsla.get("operations", []):
        op_id = s(op.get("id"))
        target = s(op.get("target"))
        if not op_id or not target:
            continue
        op_type = s(op.get("type", "icmp-echo")) or "icmp-echo"
        source = s(op.get("source_interface"))
        port = s(op.get("port"))
        lines.append(f"ip sla {op_id}")
        if op_type == "tcp-connect":
            suffix = f" {port}" if port else ""
            line = f" tcp-connect {target}{suffix}"
        elif op_type == "udp-jitter":
            suffix = f" {port}" if port else ""
            line = f" udp-jitter {target}{suffix}"
        else:
            line = f" icmp-echo {target}"
        if source:
            line += f" source-interface {normalize_interface_name(source)}"
        lines.append(line)
        for key, command in (("frequency", "frequency"),
                             ("timeout", "timeout"),
                             ("threshold", "threshold")):
            value = s(op.get(key))
            if value:
                lines.append(f" {command} {value}")
        schedule = s(op.get("schedule", "life forever start-time now")) \
            or "life forever start-time now"
        lines.append(f"ip sla schedule {op_id} {schedule}")
    return lines


def _tracks(ipsla: dict) -> list[str]:
    lines: list[str] = []
    for track in ipsla.get("tracks", []):
        track_id = s(track.get("id"))
        sla_id = s(track.get("sla_id"))
        if not track_id or not sla_id:
            continue
        track_type = s(track.get("type", "reachability")) or "reachability"
        lines.append(f"track {track_id} ip sla {sla_id} {track_type}")
        delay_up = s(track.get("delay_up"))
        delay_down = s(track.get("delay_down"))
        if delay_up or delay_down:
            parts = [" delay"]
            if delay_up:
                parts.append(f"up {delay_up}")
            if delay_down:
                parts.append(f"down {delay_down}")
            lines.append(" ".join(parts))
    return lines


def _routes(ipsla: dict) -> list[str]:
    lines: list[str] = []
    for route in ipsla.get("tracked_routes", []):
        prefix, mask, next_hop = s(route.get("prefix")), s(route.get("mask")), s(route.get("next_hop"))
        track_id = s(route.get("track_id"))
        if not prefix or not mask or not next_hop:
            continue
        parts = [f"ip route {prefix} {mask} {next_hop}"]
        distance = s(route.get("distance"))
        if distance:
            parts.append(distance)
        # IOS grammar: 'name' precedes the 'track'/'permanent' keyword.
        name = s(route.get("name"))
        if name:
            parts.append(f"name {name.replace(' ', '_')}")
        if track_id:
            parts.append(f"track {track_id}")
        lines.append(" ".join(parts))
    for route in ipsla.get("floating_routes", []):
        prefix, mask, next_hop = s(route.get("prefix")), s(route.get("mask")), s(route.get("next_hop"))
        if not prefix or not mask or not next_hop:
            continue
        distance = s(route.get("distance", "250")) or "250"
        parts = [f"ip route {prefix} {mask} {next_hop} {distance}"]
        name = s(route.get("name"))
        if name:
            parts.append(f"name {name.replace(' ', '_')}")
        lines.append(" ".join(parts))
    return lines


def _eem(ipsla: dict) -> list[str]:
    lines: list[str] = []
    for applet in ipsla.get("eem", []):
        name = s(applet.get("name"))
        track_id = s(applet.get("track_id"))
        action_cli = s(applet.get("action_cli"))
        if not name or not track_id or not action_cli:
            continue
        state = s(applet.get("state", "down")) or "down"
        lines.append(f"event manager applet {name}")
        lines.append(f" event track {track_id} state {state}")
        lines.append(f" action 1.0 cli command \"{action_cli}\"")
    return lines
