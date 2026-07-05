"""IP Tunnels and VPN generator.

Supersedes the single-DMVPN generator with a list of tunnels, each of a
selectable type.  DMVPN tunnels reuse the proven helpers in ``dmvpn.py``;
GRE point-to-point and static VTI tunnels are handled here.  The section is
designed to grow (crypto-map site-to-site, FlexVPN, GETVPN, L2TPv3, IPv6
transition tunnels) without changing the per-tunnel contract.
"""

from __future__ import annotations

from ..utils import normalize_interface_name, s, truthy
from . import dmvpn as _dmvpn

# Tunnel type labels (also used by the UI and validators).
GRE_P2P = "GRE point-to-point"
GRE_MULTIPOINT = "GRE multipoint (DMVPN)"
STATIC_VTI = "Static VTI"
IPIP = "IP-in-IP"
TUNNEL_TYPES = [GRE_P2P, GRE_MULTIPOINT, STATIC_VTI, IPIP]

# Capability tag required for each tunnel type.
TYPE_CAPABILITY = {
    GRE_P2P: "gre",
    GRE_MULTIPOINT: "dmvpn",
    STATIC_VTI: "vti",
    IPIP: "gre",
}


def is_dmvpn(tunnel: dict) -> bool:
    return s(tunnel.get("type", GRE_MULTIPOINT)) == GRE_MULTIPOINT


def _merge(target: dict, contribution: dict) -> None:
    for segment, lines in contribution.items():
        if lines:
            target.setdefault(segment, []).extend(lines)


def generate(tunnels_data: dict, profile) -> dict[str, list[str]]:
    segments: dict[str, list[str]] = {}
    for tunnel in tunnels_data.get("tunnels", []):
        if not truthy(tunnel.get("enabled", True)):
            continue
        _merge(segments, generate_tunnel(tunnel, profile))
    return segments


_DEFAULT_CRYPTO_NAMES = {
    "ikev1_transform_set": "TUNNEL-TS",
    "ikev2_proposal": "TUNNEL-IKEV2-PROP",
    "ikev2_policy": "TUNNEL-IKEV2-POLICY",
    "ikev2_keyring": "TUNNEL-KEYRING",
    "ikev2_profile": "TUNNEL-IKEV2-PROFILE",
    "ipsec_profile": "TUNNEL-IPSEC-PROFILE",
    "tunnel_protection_profile": "TUNNEL-IPSEC-PROFILE",
}


def _unique_crypto_working_copy(tunnel: dict) -> dict:
    """Copy the tunnel and, where crypto object names are still the generic
    defaults, suffix them with the tunnel number so multiple encrypted
    tunnels on one router do not collide into one garbled crypto block."""
    working = dict(tunnel)
    working["enabled"] = True
    if not truthy(tunnel.get("ipsec_enabled")):
        return working
    number = s(tunnel.get("tunnel_number", "0")) or "0"
    for field, default in _DEFAULT_CRYPTO_NAMES.items():
        if s(tunnel.get(field)) in ("", default):
            working[field] = f"{default}-{number}"
    # Keep tunnel protection pointing at the (renamed) IPsec profile.
    if s(tunnel.get("tunnel_protection_profile")) in (
            "", "TUNNEL-IPSEC-PROFILE", s(tunnel.get("ipsec_profile"))):
        working["tunnel_protection_profile"] = working["ipsec_profile"]
    return working


def generate_tunnel(tunnel: dict, profile) -> dict[str, list[str]]:
    working = _unique_crypto_working_copy(tunnel)
    if is_dmvpn(tunnel):
        # Reuse the DMVPN generator wholesale (mode gre multipoint + NHRP).
        return {
            "crypto": _dmvpn._crypto(working),
            "interfaces": _dmvpn._tunnel_interface(working),
            "routing": _dmvpn._routing(working),
            "static_routes": _dmvpn._static_routes(working),
        }
    return {
        "crypto": _dmvpn._crypto(working) if truthy(working.get("ipsec_enabled")) else [],
        "interfaces": _point_to_point_interface(working),
        "routing": _dmvpn._routing(working),
        "static_routes": _dmvpn._static_routes(working),
    }


def _tunnel_name(tunnel: dict) -> str:
    return f"Tunnel{s(tunnel.get('tunnel_number', '0')) or '0'}"


def _point_to_point_interface(tunnel: dict) -> list[str]:
    """GRE point-to-point, static VTI or IP-in-IP tunnel block."""
    ttype = s(tunnel.get("type", GRE_P2P))
    lines = [f"interface {_tunnel_name(tunnel)}"]
    description = s(tunnel.get("description"))
    if description:
        lines.append(f" description {description}")
    vrf = s(tunnel.get("vrf"))
    if vrf:
        lines.append(f" vrf forwarding {vrf}")
    ip, mask = s(tunnel.get("tunnel_ip")), s(tunnel.get("tunnel_mask"))
    if ip and mask:
        lines.append(f" ip address {ip} {mask}")
    ipv6 = s(tunnel.get("ipv6_address"))
    if ipv6:
        lines.append(f" ipv6 address {ipv6}")
    mtu = s(tunnel.get("ip_mtu"))
    if mtu:
        lines.append(f" ip mtu {mtu}")
    mss = s(tunnel.get("tcp_mss"))
    if mss:
        lines.append(f" ip tcp adjust-mss {mss}")
    bandwidth = s(tunnel.get("bandwidth"))
    if bandwidth:
        lines.append(f" bandwidth {bandwidth}")
    delay = s(tunnel.get("delay"))
    if delay:
        lines.append(f" delay {delay}")
    keepalive = s(tunnel.get("keepalive"))
    if keepalive and ttype in (GRE_P2P, IPIP):
        lines.append(f" keepalive {keepalive}")

    # Routing that lives under the interface (ip ospf / eigrp knobs).
    _dmvpn._routing_interface_lines(tunnel, lines)

    source_if = s(tunnel.get("tunnel_source_interface"))
    source_ip = s(tunnel.get("tunnel_source_ip"))
    if source_if:
        lines.append(f" tunnel source {normalize_interface_name(source_if)}")
    elif source_ip:
        lines.append(f" tunnel source {source_ip}")
    destination = s(tunnel.get("tunnel_destination"))
    if destination:
        lines.append(f" tunnel destination {destination}")

    if ttype == STATIC_VTI:
        family = "ipv6" if ipv6 and not ip else "ipv4"
        lines.append(f" tunnel mode ipsec {family}")
    elif ttype == IPIP:
        lines.append(" tunnel mode ipip")
    elif ipv6 and not ip:
        lines.append(" tunnel mode gre ipv6")
    # GRE/IP point-to-point uses the default tunnel mode; no command needed.

    tunnel_key = s(tunnel.get("tunnel_key"))
    if tunnel_key and ttype in (GRE_P2P, GRE_MULTIPOINT):
        lines.append(f" tunnel key {tunnel_key}")
    if truthy(tunnel.get("ipsec_enabled")):
        profile_name = s(tunnel.get("tunnel_protection_profile")) \
            or s(tunnel.get("ipsec_profile")) or "TUNNEL-IPSEC-PROFILE"
        lines.append(f" tunnel protection ipsec profile {profile_name}")
    lines.append(" shutdown" if not truthy(tunnel.get("enabled", True))
                 else " no shutdown")
    return lines
