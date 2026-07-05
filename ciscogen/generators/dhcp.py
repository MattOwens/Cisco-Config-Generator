"""DHCP server generator: excluded addresses and pools."""

from __future__ import annotations

from ..utils import parse_list, s, safe_int


def generate(dhcp_data: dict, profile) -> dict[str, list[str]]:
    lines: list[str] = []
    for rng in dhcp_data.get("excluded", []):
        start = s(rng.get("start"))
        if not start:
            continue
        end = s(rng.get("end"))
        if end and end != start:
            lines.append(f"ip dhcp excluded-address {start} {end}")
        else:
            lines.append(f"ip dhcp excluded-address {start}")
    for pool in dhcp_data.get("pools", []):
        name = s(pool.get("name"))
        if not name:
            continue
        lines.append(f"ip dhcp pool {name.replace(' ', '_')}")
        network, mask = s(pool.get("network")), s(pool.get("mask"))
        if network and mask:
            lines.append(f" network {network} {mask}")
        router = s(pool.get("default_router"))
        if router:
            lines.append(f" default-router {router}")
        dns = parse_list(pool.get("dns"))
        if dns:
            lines.append(f" dns-server {' '.join(dns[:8])}")
        domain = s(pool.get("domain"))
        if domain:
            lines.append(f" domain-name {domain}")
        lease = safe_int(pool.get("lease_days"))
        if lease is not None:
            lines.append(f" lease {lease}")
        option150 = s(pool.get("option150"))
        if option150:
            lines.append(f" option 150 ip {option150}")
    for binding in dhcp_data.get("static_bindings", []):
        name = s(binding.get("name"))
        host_ip = s(binding.get("host_ip"))
        if not name or not host_ip:
            continue
        lines.append(f"ip dhcp pool {name.replace(' ', '_')}")
        mask = s(binding.get("mask")) or "255.255.255.255"
        lines.append(f" host {host_ip} {mask}")
        client_id = s(binding.get("client_id"))
        mac = s(binding.get("mac"))
        if client_id:
            lines.append(f" client-identifier {client_id}")
        elif mac:
            lines.append(f" hardware-address {mac}")
        router = s(binding.get("default_router"))
        if router:
            lines.append(f" default-router {router}")
    return {"dhcp": lines}
