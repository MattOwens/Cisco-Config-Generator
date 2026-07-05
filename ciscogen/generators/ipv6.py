"""IPv6 generator: interface addresses, ACLs, static routes and OSPFv3."""

from __future__ import annotations

from ..utils import normalize_interface_name, s, truthy


def collect_interface_extras(ipv6_data: dict, extras: dict[str, list[str]]) -> None:
    for item in ipv6_data.get("interface_addresses", []):
        interface = normalize_interface_name(s(item.get("interface")))
        address = s(item.get("address"))
        if not interface or not address:
            continue
        suffix = " eui-64" if truthy(item.get("eui64")) else ""
        extras.setdefault(interface, []).append(f" ipv6 address {address}{suffix}")
        if truthy(item.get("suppress_ra")):
            extras.setdefault(interface, []).append(" ipv6 nd ra suppress")
    for relay in ipv6_data.get("dhcp_relays", []):
        interface = normalize_interface_name(s(relay.get("interface")))
        destination = s(relay.get("destination"))
        if interface and destination:
            extras.setdefault(interface, []).append(f" ipv6 dhcp relay destination {destination}")
    for ospf in ipv6_data.get("ospfv3", {}).get("interfaces", []):
        interface = normalize_interface_name(s(ospf.get("interface")))
        area = s(ospf.get("area", "0")) or "0"
        process_id = s(ipv6_data.get("ospfv3", {}).get("process_id", "1")) or "1"
        if interface:
            extras.setdefault(interface, []).append(f" ipv6 ospf {process_id} area {area}")
            network_type = s(ospf.get("network_type"))
            if network_type:
                extras.setdefault(interface, []).append(f" ipv6 ospf network {network_type}")
            cost = s(ospf.get("cost"))
            if cost:
                extras.setdefault(interface, []).append(f" ipv6 ospf cost {cost}")


def generate(ipv6_data: dict, profile) -> dict[str, list[str]]:
    segments: dict[str, list[str]] = {}
    if truthy(ipv6_data.get("unicast_routing")):
        segments["services"] = ["ipv6 unicast-routing"]

    acls: list[str] = []
    for acl in ipv6_data.get("acls", []):
        name = s(acl.get("name"))
        if not name:
            continue
        acls.append(f"ipv6 access-list {name}")
        for rule in acl.get("rules", []):
            action = s(rule.get("action", "permit")) or "permit"
            protocol = s(rule.get("protocol", "ipv6")) or "ipv6"
            src = s(rule.get("src", "any")) or "any"
            dst = s(rule.get("dst", "any")) or "any"
            if action == "remark":
                remark = s(rule.get("remark"))
                if remark:
                    acls.append(f" remark {remark}")
            else:
                acls.append(f" {action} {protocol} {src} {dst}")
    segments["acls"] = acls

    routes: list[str] = []
    for route in ipv6_data.get("static_routes", []):
        prefix = s(route.get("prefix"))
        if not prefix:
            continue
        vrf = s(route.get("vrf"))
        parts = ["ipv6 route"]
        if vrf:
            parts.extend(["vrf", vrf])
        parts.append(prefix)
        exit_if = s(route.get("exit_interface"))
        if exit_if:
            parts.append(normalize_interface_name(exit_if))
        next_hop = s(route.get("next_hop"))
        if next_hop:
            parts.append(next_hop)
        distance = s(route.get("distance"))
        if distance:
            parts.append(distance)
        routes.append(" ".join(parts))
    segments["static_routes"] = routes

    ospfv3 = ipv6_data.get("ospfv3", {})
    if truthy(ospfv3.get("enabled")):
        process_id = s(ospfv3.get("process_id", "1")) or "1"
        routing = [f"ipv6 router ospf {process_id}"]
        router_id = s(ospfv3.get("router_id"))
        if router_id:
            routing.append(f" router-id {router_id}")
        segments["routing"] = routing
    return segments
