"""IPv4 primitives: address, mask, wildcard and overlap checks."""

from __future__ import annotations

import ipaddress


def parse_ipv4(value: str) -> int | None:
    """Return the address as an int, or None if invalid."""
    value = (value or "").strip()
    parts = value.split(".")
    if len(parts) != 4:
        return None
    result = 0
    for part in parts:
        if not part.isdigit():
            return None
        octet = int(part)
        if octet > 255:
            return None
        result = (result << 8) | octet
    return result


def is_valid_ipv4(value: str) -> bool:
    return parse_ipv4(value) is not None


def is_valid_mask(value: str) -> bool:
    """Contiguous subnet mask, e.g. 255.255.255.0."""
    n = parse_ipv4(value)
    if n is None:
        return False
    # A valid mask is 1-bits followed by 0-bits: inverting gives 2^k - 1.
    inverted = ~n & 0xFFFFFFFF
    return (inverted & (inverted + 1)) == 0


def is_valid_wildcard(value: str) -> bool:
    """Contiguous wildcard mask, e.g. 0.0.0.255 (inverse of a subnet mask)."""
    n = parse_ipv4(value)
    if n is None:
        return False
    return (n & (n + 1)) == 0


def is_valid_cidr(value) -> bool:
    try:
        prefix = int(str(value).strip().lstrip("/"))
    except (TypeError, ValueError):
        return False
    return 0 <= prefix <= 32


def mask_to_prefix(mask: str) -> int | None:
    if not is_valid_mask(mask):
        return None
    return bin(parse_ipv4(mask)).count("1")


def prefix_to_mask(prefix: int) -> str:
    n = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
    return ".".join(str((n >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def network_of(ip: str, mask: str) -> int | None:
    ip_n, mask_n = parse_ipv4(ip), parse_ipv4(mask)
    if ip_n is None or mask_n is None or not is_valid_mask(mask):
        return None
    return ip_n & mask_n


def same_network(ip_a: str, ip_b: str, mask: str) -> bool:
    a, b = network_of(ip_a, mask), network_of(ip_b, mask)
    return a is not None and a == b


def networks_overlap(net_a: str, mask_a: str, net_b: str, mask_b: str) -> bool:
    """True when the two IPv4 networks share any addresses."""
    a, b = network_of(net_a, mask_a), network_of(net_b, mask_b)
    ma, mb = parse_ipv4(mask_a), parse_ipv4(mask_b)
    if a is None or b is None:
        return False
    common = ma & mb  # the shorter (less specific) of the two masks
    return (a & common) == (b & common)


def ip_in_network(ip: str, network: str, mask: str) -> bool:
    ip_n = parse_ipv4(ip)
    net = network_of(network, mask)
    mask_n = parse_ipv4(mask)
    if ip_n is None or net is None:
        return False
    return (ip_n & mask_n) == net


def ranges_overlap(a_start: str, a_end: str, b_start: str, b_end: str) -> bool:
    """True when two inclusive address ranges intersect."""
    a1, a2 = parse_ipv4(a_start), parse_ipv4(a_end)
    b1, b2 = parse_ipv4(b_start), parse_ipv4(b_end)
    if None in (a1, a2, b1, b2):
        return False
    return max(a1, b1) <= min(a2, b2)


def is_valid_vlan(value) -> bool:
    try:
        vlan = int(str(value).strip())
    except (TypeError, ValueError):
        return False
    return 1 <= vlan <= 4094


RESERVED_VLANS = {1002, 1003, 1004, 1005}


def is_valid_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(str(value).strip())
    except ValueError:
        return False
    return True


def is_valid_ipv6_interface(value: str) -> bool:
    try:
        ipaddress.IPv6Interface(str(value).strip())
    except ValueError:
        return False
    return True


def is_valid_ipv6_network(value: str) -> bool:
    try:
        ipaddress.IPv6Network(str(value).strip(), strict=False)
    except ValueError:
        return False
    return True
