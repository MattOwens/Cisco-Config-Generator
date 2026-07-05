"""Dynamic routing protocol generator: OSPF, EIGRP, BGP, RIP."""

from __future__ import annotations

from ..utils import normalize_interface_name, parse_list, s, truthy


def generate(routing: dict, profile) -> dict[str, list[str]]:
    lines: list[str] = []
    lines += _ospf(routing.get("ospf", {}))
    lines += _eigrp(routing.get("eigrp", {}))
    lines += _bgp(routing.get("bgp", {}))
    lines += _rip(routing.get("rip", {}))
    return {"routing": lines}


def _ospf(ospf: dict) -> list[str]:
    if not truthy(ospf.get("enabled")):
        return []
    process_id = s(ospf.get("process_id", "1")) or "1"
    lines = [f"router ospf {process_id}"]
    router_id = s(ospf.get("router_id"))
    if router_id:
        lines.append(f" router-id {router_id}")
    if truthy(ospf.get("passive_default")):
        lines.append(" passive-interface default")
        keyword = "no passive-interface"
    else:
        keyword = "passive-interface"
    for name in parse_list(ospf.get("passive_interfaces")):
        lines.append(f" {keyword} {normalize_interface_name(name)}")
    for net in ospf.get("networks", []):
        network, wildcard = s(net.get("network")), s(net.get("wildcard"))
        area = s(net.get("area"))
        if network and wildcard and area:
            lines.append(f" network {network} {wildcard} area {area}")
    area_auth = s(ospf.get("area_auth_area"))
    if area_auth:
        suffix = " message-digest" if truthy(ospf.get("area_auth_md5", True)) else ""
        lines.append(f" area {area_auth} authentication{suffix}")
    if truthy(ospf.get("redistribute_connected")):
        lines.append(" redistribute connected subnets")
    if truthy(ospf.get("redistribute_static")):
        lines.append(" redistribute static subnets")
    if truthy(ospf.get("default_originate")):
        always = " always" if truthy(ospf.get("default_originate_always")) else ""
        lines.append(f" default-information originate{always}")
    return lines


def _eigrp(eigrp: dict) -> list[str]:
    if not truthy(eigrp.get("enabled")):
        return []
    asn = s(eigrp.get("asn"))
    if not asn:
        return []
    lines = [f"router eigrp {asn}"]
    router_id = s(eigrp.get("router_id"))
    if router_id:
        lines.append(f" eigrp router-id {router_id}")
    for name in parse_list(eigrp.get("passive_interfaces")):
        lines.append(f" passive-interface {normalize_interface_name(name)}")
    for net in eigrp.get("networks", []):
        network, wildcard = s(net.get("network")), s(net.get("wildcard"))
        if not network:
            continue
        lines.append(f" network {network} {wildcard}".rstrip())
    if truthy(eigrp.get("no_auto_summary", True)):
        lines.append(" no auto-summary")
    if truthy(eigrp.get("redistribute_static")):
        lines.append(" redistribute static")
    return lines


def _bgp(bgp: dict) -> list[str]:
    if not truthy(bgp.get("enabled")):
        return []
    asn = s(bgp.get("asn"))
    if not asn:
        return []
    lines = [f"router bgp {asn}"]
    router_id = s(bgp.get("router_id"))
    if router_id:
        lines.append(f" bgp router-id {router_id}")
    for neighbor in bgp.get("neighbors", []):
        ip = s(neighbor.get("ip"))
        remote_as = s(neighbor.get("remote_as"))
        if not ip or not remote_as:
            continue
        lines.append(f" neighbor {ip} remote-as {remote_as}")
        description = s(neighbor.get("description"))
        if description:
            lines.append(f" neighbor {ip} description {description}")
        update_source = s(neighbor.get("update_source"))
        if update_source:
            lines.append(f" neighbor {ip} update-source "
                         f"{normalize_interface_name(update_source)}")
        multihop = s(neighbor.get("ebgp_multihop"))
        if multihop:
            lines.append(f" neighbor {ip} ebgp-multihop {multihop}")
    for net in bgp.get("networks", []):
        network, mask = s(net.get("network")), s(net.get("mask"))
        if not network:
            continue
        if mask:
            lines.append(f" network {network} mask {mask}")
        else:
            lines.append(f" network {network}")
    return lines


def _rip(rip: dict) -> list[str]:
    if not truthy(rip.get("enabled")):
        return []
    lines = ["router rip"]
    if truthy(rip.get("version2", True)):
        lines.append(" version 2")
    if truthy(rip.get("no_auto_summary", True)):
        lines.append(" no auto-summary")
    for network in parse_list(rip.get("networks")):
        lines.append(f" network {network}")
    for name in parse_list(rip.get("passive_interfaces")):
        lines.append(f" passive-interface {normalize_interface_name(name)}")
    return lines
