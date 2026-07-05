"""NAT/PAT generator: static NAT, dynamic NAT with pool, interface PAT."""

from __future__ import annotations

from ..utils import normalize_interface_name, parse_list, s, truthy


def collect_interface_extras(nat_data: dict, extras: dict[str, list[str]]) -> None:
    for name in parse_list(nat_data.get("inside_interfaces")):
        extras.setdefault(normalize_interface_name(name), []).append(" ip nat inside")
    for name in parse_list(nat_data.get("outside_interfaces")):
        extras.setdefault(normalize_interface_name(name), []).append(" ip nat outside")


def generate(nat_data: dict, profile) -> dict[str, list[str]]:
    lines: list[str] = []
    for rule in nat_data.get("static_rules", []):
        local, global_ = s(rule.get("inside_local")), s(rule.get("inside_global"))
        if not local or not global_:
            continue
        protocol = s(rule.get("protocol"))
        local_port, global_port = s(rule.get("local_port")), s(rule.get("global_port"))
        if protocol in ("tcp", "udp") and local_port and global_port:
            lines.append(f"ip nat inside source static {protocol} "
                         f"{local} {local_port} {global_} {global_port}")
        else:
            lines.append(f"ip nat inside source static {local} {global_}")
    if truthy(nat_data.get("dynamic_enabled")):
        acl_ref = s(nat_data.get("dynamic_acl"))
        if truthy(nat_data.get("use_pool")):
            pool = s(nat_data.get("pool_name"))
            start, end = s(nat_data.get("pool_start")), s(nat_data.get("pool_end"))
            mask = s(nat_data.get("pool_mask"))
            if pool and start and end and mask:
                lines.append(f"ip nat pool {pool} {start} {end} netmask {mask}")
            if acl_ref and pool:
                overload = " overload" if truthy(nat_data.get("overload")) else ""
                lines.append(f"ip nat inside source list {acl_ref} pool {pool}"
                             f"{overload}")
        else:
            outside = normalize_interface_name(s(nat_data.get("overload_interface")))
            if acl_ref and outside:
                lines.append(f"ip nat inside source list {acl_ref} "
                             f"interface {outside} overload")
    return {"nat": lines}
