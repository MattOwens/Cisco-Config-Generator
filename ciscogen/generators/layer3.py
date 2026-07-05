"""Layer 3 generator: ip routing, static routes, prefix lists, route maps, PBR."""

from __future__ import annotations

from ..utils import normalize_interface_name, s, truthy


def collect_interface_extras(l3_data: dict, extras: dict[str, list[str]]) -> None:
    for apply_entry in l3_data.get("pbr_apply", []):
        interface = normalize_interface_name(s(apply_entry.get("interface")))
        route_map = s(apply_entry.get("route_map"))
        if interface and route_map:
            extras.setdefault(interface, []).append(
                f" ip policy route-map {route_map}")


def generate(l3_data: dict, profile) -> dict[str, list[str]]:
    segments: dict[str, list[str]] = {}

    if profile.is_switch and (
            profile.supports("layer3") or profile.supports("static_routing")) \
            and truthy(l3_data.get("ip_routing", True)):
        segments["services"] = ["ip routing"]

    routes: list[str] = []
    for route in l3_data.get("static_routes", []):
        prefix, mask = s(route.get("prefix")), s(route.get("mask"))
        if not prefix or not mask:
            continue
        parts = [f"ip route {prefix} {mask}"]
        exit_if = s(route.get("exit_interface"))
        if exit_if:
            parts.append(normalize_interface_name(exit_if))
        next_hop = s(route.get("next_hop"))
        if next_hop:
            parts.append(next_hop)
        distance = s(route.get("distance"))
        if distance:
            parts.append(distance)
        name = s(route.get("name"))
        if name:
            parts.append(f"name {name.replace(' ', '_')}")
        if truthy(route.get("permanent")):
            parts.append("permanent")
        routes.append(" ".join(parts))
    segments["static_routes"] = routes

    pbr: list[str] = []
    for pl in l3_data.get("prefix_lists", []):
        name, prefix = s(pl.get("name")), s(pl.get("prefix"))
        if not name or not prefix:
            continue
        seq = s(pl.get("seq"))
        seq_part = f" seq {seq}" if seq else ""
        action = s(pl.get("action", "permit")) or "permit"
        line = f"ip prefix-list {name}{seq_part} {action} {prefix}"
        ge, le = s(pl.get("ge")), s(pl.get("le"))
        if ge:
            line += f" ge {ge}"
        if le:
            line += f" le {le}"
        pbr.append(line)
    for rm in l3_data.get("route_maps", []):
        name = s(rm.get("name"))
        if not name:
            continue
        action = s(rm.get("action", "permit")) or "permit"
        seq = s(rm.get("seq", "10")) or "10"
        pbr.append(f"route-map {name} {action} {seq}")
        match_acl = s(rm.get("match_acl"))
        if match_acl:
            pbr.append(f" match ip address {match_acl}")
        match_pl = s(rm.get("match_prefix_list"))
        if match_pl:
            pbr.append(f" match ip address prefix-list {match_pl}")
        next_hop = s(rm.get("set_next_hop"))
        if next_hop:
            pbr.append(f" set ip next-hop {next_hop}")
    if pbr:
        # Route maps and prefix lists precede the routing protocols that
        # reference them; reuse the acls segment position (before nat/routing).
        segments["acls"] = pbr
    return segments
