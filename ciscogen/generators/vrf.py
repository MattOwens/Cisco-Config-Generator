"""VRF-Lite generator."""

from __future__ import annotations

from ..utils import normalize_interface_name, s, truthy


def collect_interface_extras(vrf_data: dict, extras: dict[str, list[str]]) -> None:
    for item in vrf_data.get("interface_assignments", []):
        interface = normalize_interface_name(s(item.get("interface")))
        name = s(item.get("vrf"))
        if interface and name:
            # 'vrf definition' blocks pair with 'vrf forwarding' on the
            # interface; the legacy 'ip vrf forwarding' form is rejected.
            extras.setdefault(interface, []).append(f" vrf forwarding {name}")
    for relay in vrf_data.get("dhcp_relays", []):
        interface = normalize_interface_name(s(relay.get("interface")))
        helper = s(relay.get("helper"))
        name = s(relay.get("vrf"))
        if interface and helper:
            suffix = f" vrf {name}" if name else ""
            extras.setdefault(interface, []).append(f" ip helper-address{suffix} {helper}")


def generate(vrf_data: dict, profile) -> dict[str, list[str]]:
    segments: dict[str, list[str]] = {}
    vrfs: list[str] = []
    for item in vrf_data.get("vrfs", []):
        name = s(item.get("name"))
        if not name:
            continue
        vrfs.append(f"vrf definition {name}")
        description = s(item.get("description"))
        if description:
            vrfs.append(f" description {description}")
        rd = s(item.get("rd"))
        if rd:
            vrfs.append(f" rd {rd}")
        if truthy(item.get("address_family_ipv4", True)):
            vrfs.append(" address-family ipv4")
            vrfs.append(" exit-address-family")
    segments["vrfs"] = vrfs

    routes: list[str] = []
    for route in vrf_data.get("static_routes", []):
        name, prefix, mask = s(route.get("vrf")), s(route.get("prefix")), s(route.get("mask"))
        if not name or not prefix or not mask:
            continue
        parts = [f"ip route vrf {name} {prefix} {mask}"]
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

    routing: list[str] = []
    for ospf in vrf_data.get("ospf", []):
        name = s(ospf.get("vrf"))
        process_id = s(ospf.get("process_id", "1")) or "1"
        if not name:
            continue
        routing.append(f"router ospf {process_id} vrf {name}")
        router_id = s(ospf.get("router_id"))
        if router_id:
            routing.append(f" router-id {router_id}")
        for network in ospf.get("networks", []):
            net, wildcard, area = s(network.get("network")), s(network.get("wildcard")), s(network.get("area"))
            if net and wildcard and area:
                routing.append(f" network {net} {wildcard} area {area}")
    for bgp in vrf_data.get("bgp", []):
        name, asn = s(bgp.get("vrf")), s(bgp.get("asn"))
        if not name or not asn:
            continue
        routing.append(f"router bgp {asn}")
        routing.append(f" address-family ipv4 vrf {name}")
        for neighbor in bgp.get("neighbors", []):
            ip, remote_as = s(neighbor.get("ip")), s(neighbor.get("remote_as"))
            if ip and remote_as:
                routing.append(f"  neighbor {ip} remote-as {remote_as}")
        for network in bgp.get("networks", []):
            net, mask = s(network.get("network")), s(network.get("mask"))
            if net and mask:
                routing.append(f"  network {net} mask {mask}")
        routing.append(" exit-address-family")
    segments["routing"] = routing
    return segments
