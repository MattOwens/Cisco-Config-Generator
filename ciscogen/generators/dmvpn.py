"""DMVPN and IPsec generator."""

from __future__ import annotations

from ..utils import normalize_interface_name, s, truthy


def generate(dmvpn: dict, profile) -> dict[str, list[str]]:
    if not truthy(dmvpn.get("enabled")):
        return {}
    return {
        "crypto": _crypto(dmvpn),
        "interfaces": _tunnel_interface(dmvpn),
        "routing": _routing(dmvpn),
        "static_routes": _static_routes(dmvpn),
    }


def _tunnel_name(dmvpn: dict) -> str:
    return f"Tunnel{s(dmvpn.get('tunnel_number', '0')) or '0'}"


def _crypto(dmvpn: dict) -> list[str]:
    if not truthy(dmvpn.get("ipsec_enabled")):
        return []
    psk = s(dmvpn.get("pre_shared_key"))
    if s(dmvpn.get("ike_version", "IKEv2")) == "IKEv1":
        policy = dmvpn.get("ikev1_policy", {})
        number = s(policy.get("number", "10")) or "10"
        transform = s(dmvpn.get("ikev1_transform_set")) or "DMVPN-TS"
        profile = s(dmvpn.get("ipsec_profile")) or "DMVPN-IPSEC-PROFILE"
        lines = [f"crypto isakmp policy {number}"]
        for field, command in (
                ("encryption", "encr"),
                ("hash", "hash"),
                ("authentication", "authentication"),
                ("group", "group"),
                ("lifetime", "lifetime")):
            value = s(policy.get(field))
            if value:
                lines.append(f" {command} {value}")
        if psk:
            lines.append(f"crypto isakmp key {psk} address 0.0.0.0 0.0.0.0")
        lines.append(f"crypto ipsec transform-set {transform} esp-aes 256 esp-sha-hmac")
        lines.append(" mode transport")
        lines.append(f"crypto ipsec profile {profile}")
        lines.append(f" set transform-set {transform}")
        return lines

    proposal = s(dmvpn.get("ikev2_proposal")) or "DMVPN-IKEV2-PROP"
    policy = s(dmvpn.get("ikev2_policy")) or "DMVPN-IKEV2-POLICY"
    keyring = s(dmvpn.get("ikev2_keyring")) or "DMVPN-KEYRING"
    ike_profile = s(dmvpn.get("ikev2_profile")) or "DMVPN-IKEV2-PROFILE"
    ipsec_profile = s(dmvpn.get("ipsec_profile")) or "DMVPN-IPSEC-PROFILE"
    lines = [
        f"crypto ikev2 proposal {proposal}",
        " encryption aes-cbc-256",
        " integrity sha256",
        " group 14",
        f"crypto ikev2 policy {policy}",
        f" proposal {proposal}",
        f"crypto ikev2 keyring {keyring}",
        " peer DMVPN-PEERS",
        "  address 0.0.0.0 0.0.0.0",
    ]
    if psk:
        lines.append(f"  pre-shared-key {psk}")
    lines.extend([
        f"crypto ikev2 profile {ike_profile}",
        " match identity remote address 0.0.0.0 0.0.0.0",
        " authentication remote pre-share",
        " authentication local pre-share",
        f" keyring local {keyring}",
        f"crypto ipsec profile {ipsec_profile}",
        f" set ikev2-profile {ike_profile}",
    ])
    return lines


def _tunnel_interface(dmvpn: dict) -> list[str]:
    name = _tunnel_name(dmvpn)
    lines = [f"interface {name}"]
    description = s(dmvpn.get("description"))
    if description:
        lines.append(f" description {description}")
    vrf = s(dmvpn.get("vrf"))
    if vrf:
        lines.append(f" vrf forwarding {vrf}")
    ip, mask = s(dmvpn.get("tunnel_ip")), s(dmvpn.get("tunnel_mask"))
    if ip and mask:
        lines.append(f" ip address {ip} {mask}")
    mtu = s(dmvpn.get("ip_mtu"))
    if mtu:
        lines.append(f" ip mtu {mtu}")
    mss = s(dmvpn.get("tcp_mss"))
    if mss:
        lines.append(f" ip tcp adjust-mss {mss}")
    bandwidth = s(dmvpn.get("bandwidth"))
    if bandwidth:
        lines.append(f" bandwidth {bandwidth}")
    delay = s(dmvpn.get("delay"))
    if delay:
        lines.append(f" delay {delay}")
    auth = s(dmvpn.get("nhrp_authentication"))
    if auth:
        lines.append(f" ip nhrp authentication {auth}")
    network_id = s(dmvpn.get("nhrp_network_id"))
    if network_id:
        lines.append(f" ip nhrp network-id {network_id}")
    holdtime = s(dmvpn.get("nhrp_holdtime"))
    if holdtime:
        lines.append(f" ip nhrp holdtime {holdtime}")
    _nhrp_role_lines(dmvpn, lines)
    _routing_interface_lines(dmvpn, lines)
    source_if = s(dmvpn.get("tunnel_source_interface"))
    source_ip = s(dmvpn.get("tunnel_source_ip"))
    if source_if:
        lines.append(f" tunnel source {normalize_interface_name(source_if)}")
    elif source_ip:
        lines.append(f" tunnel source {source_ip}")
    mode = s(dmvpn.get("tunnel_mode", "gre multipoint")) or "gre multipoint"
    lines.append(f" tunnel mode {mode}")
    tunnel_key = s(dmvpn.get("tunnel_key"))
    if tunnel_key:
        lines.append(f" tunnel key {tunnel_key}")
    if truthy(dmvpn.get("ipsec_enabled")):
        profile = s(dmvpn.get("tunnel_protection_profile")) \
            or s(dmvpn.get("ipsec_profile")) or "DMVPN-IPSEC-PROFILE"
        lines.append(f" tunnel protection ipsec profile {profile}")
    lines.append(" no shutdown")
    return lines


def _nhrp_role_lines(dmvpn: dict, lines: list[str]) -> None:
    role = s(dmvpn.get("role", "Hub")).lower()
    phase = s(dmvpn.get("phase", "Phase 3")).lower()
    if "hub" in role and "spoke" not in role:
        multicast = s(dmvpn.get("nhrp_map_multicast", "dynamic")) or "dynamic"
        lines.append(f" ip nhrp map multicast {multicast}")
        if "3" in phase and truthy(dmvpn.get("nhrp_redirect", True)):
            lines.append(" ip nhrp redirect")
        return
    for nhs in dmvpn.get("nhrp_nhs", []):
        address = s(nhs.get("address"))
        nbma = s(nhs.get("nbma"))
        if address:
            lines.append(f" ip nhrp nhs {address}")
        if address and nbma:
            lines.append(f" ip nhrp map {address} {nbma}")
            lines.append(f" ip nhrp map multicast {nbma}")
    for entry in dmvpn.get("nhrp_static_maps", []):
        tunnel_ip, nbma = s(entry.get("tunnel_ip")), s(entry.get("nbma"))
        if tunnel_ip and nbma:
            lines.append(f" ip nhrp map {tunnel_ip} {nbma}")
            if truthy(entry.get("multicast")):
                lines.append(f" ip nhrp map multicast {nbma}")
    if "3" in phase and truthy(dmvpn.get("nhrp_shortcut", True)):
        lines.append(" ip nhrp shortcut")


def _routing_interface_lines(dmvpn: dict, lines: list[str]) -> None:
    routing = dmvpn.get("routing", {})
    ospf = routing.get("ospf", {})
    if truthy(ospf.get("enabled")):
        process_id = s(ospf.get("process_id", "1")) or "1"
        area = s(ospf.get("area", "0")) or "0"
        lines.append(f" ip ospf {process_id} area {area}")
        network_type = s(ospf.get("network_type"))
        if network_type:
            lines.append(f" ip ospf network {network_type}")
        cost = s(ospf.get("cost"))
        if cost:
            lines.append(f" ip ospf cost {cost}")
        if s(ospf.get("authentication")):
            lines.append(f" ip ospf authentication {s(ospf.get('authentication'))}")
    eigrp = routing.get("eigrp", {})
    role = s(dmvpn.get("role", "Hub")).lower()
    phase = s(dmvpn.get("phase", "Phase 3")).lower()
    if truthy(eigrp.get("enabled")) and "hub" in role:
        asn = s(eigrp.get("asn"))
        if asn and truthy(eigrp.get("hub_disable_split_horizon", True)):
            lines.append(f" no ip split-horizon eigrp {asn}")
        if asn and "1" not in phase and truthy(eigrp.get("hub_disable_next_hop_self", True)):
            lines.append(f" no ip next-hop-self eigrp {asn}")
    # BGP neighbor statements (with update-source set to the tunnel) are
    # emitted in the routing segment by _routing(); nothing interface-level
    # is required here.


def _routing(dmvpn: dict) -> list[str]:
    lines: list[str] = []
    routing = dmvpn.get("routing", {})
    eigrp = routing.get("eigrp", {})
    if truthy(eigrp.get("enabled")) and s(eigrp.get("asn")):
        lines.append(f"router eigrp {s(eigrp.get('asn'))}")
        for network in eigrp.get("networks", []):
            net, wildcard = s(network.get("network")), s(network.get("wildcard"))
            if net:
                lines.append(f" network {net} {wildcard}".rstrip())
    bgp = routing.get("bgp", {})
    if truthy(bgp.get("enabled")) and s(bgp.get("local_as")):
        tunnel = _tunnel_name(dmvpn)
        lines.append(f"router bgp {s(bgp.get('local_as'))}")
        for neighbor in bgp.get("neighbors", []):
            ip, remote_as = s(neighbor.get("ip")), s(neighbor.get("remote_as"))
            if not ip or not remote_as:
                continue
            lines.append(f" neighbor {ip} remote-as {remote_as}")
            description = s(neighbor.get("description"))
            if description:
                lines.append(f" neighbor {ip} description {description}")
            lines.append(f" neighbor {ip} update-source {tunnel}")
            if truthy(bgp.get("route_reflector")):
                lines.append(f" neighbor {ip} route-reflector-client")
            if truthy(bgp.get("next_hop_self", True)):
                lines.append(f" neighbor {ip} next-hop-self")
        for network in bgp.get("networks", []):
            net, mask = s(network.get("network")), s(network.get("mask"))
            if net and mask:
                lines.append(f" network {net} mask {mask}")
    return lines


def _static_routes(dmvpn: dict) -> list[str]:
    lines: list[str] = []
    for route in dmvpn.get("routing", {}).get("static_routes", []):
        prefix, mask = s(route.get("prefix")), s(route.get("mask"))
        if not prefix or not mask:
            continue
        next_hop = s(route.get("next_hop"))
        if next_hop:
            lines.append(f"ip route {prefix} {mask} {next_hop}")
        else:
            lines.append(f"ip route {prefix} {mask} {_tunnel_name(dmvpn)}")
    return lines
