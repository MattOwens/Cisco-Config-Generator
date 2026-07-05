"""Device-profile capability resolver.

Device JSON files keep compact capability flags. This module maps those flags
into richer Cisco feature tags used by the UI, validators and reports. Older
saved project planning fields are intentionally ignored for feature gating.
"""

from __future__ import annotations

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "capability_data"

CAPABILITY_TAGS = [
    "basic_l2", "basic_l3", "svi", "routed_ports", "static_routing",
    "dhcp_server", "dhcp_relay", "ospf", "ospfv3", "eigrp", "bgp", "rip",
    "ipv6", "vrf_lite", "pbr", "nat", "zone_based_firewall", "ipsec",
    "ikev1", "ikev2", "tunnel", "gre", "multipoint_gre", "nhrp", "dmvpn",
    "vti", "flexvpn", "crypto_maps", "tunnel_protection", "ip_sla",
    "object_tracking", "eem", "qos", "netflow", "snmpv3", "aaa_tacacs",
    "aaa_radius", "dhcp_snooping", "dai", "ip_source_guard", "port_security",
    "private_vlan", "hsrp", "vrrp", "glbp", "macsec", "stackwise",
    "wireless_controller", "restconf", "netconf", "telemetry",
]

CAPABILITY_LABELS = {
    "basic_l2": "Layer 2 switching",
    "basic_l3": "Layer 3 routing",
    "svi": "SVI interfaces",
    "routed_ports": "routed ports",
    "static_routing": "static routing",
    "dhcp_server": "DHCP server",
    "dhcp_relay": "DHCP relay",
    "ospf": "OSPF",
    "ospfv3": "OSPFv3",
    "eigrp": "EIGRP",
    "bgp": "BGP",
    "rip": "RIP",
    "ipv6": "IPv6",
    "vrf_lite": "VRF-Lite",
    "pbr": "policy-based routing",
    "nat": "NAT/PAT",
    "zone_based_firewall": "Zone-Based Firewall",
    "ipsec": "IPsec",
    "ikev1": "IKEv1",
    "ikev2": "IKEv2",
    "tunnel": "IP tunnels",
    "gre": "GRE tunnels",
    "multipoint_gre": "multipoint GRE",
    "nhrp": "NHRP",
    "dmvpn": "DMVPN",
    "vti": "IPsec VTI",
    "flexvpn": "FlexVPN",
    "crypto_maps": "crypto maps",
    "tunnel_protection": "IPsec tunnel protection",
    "ip_sla": "IP SLA",
    "object_tracking": "object tracking",
    "eem": "EEM",
    "qos": "QoS",
    "netflow": "NetFlow",
    "snmpv3": "SNMPv3",
    "aaa_tacacs": "TACACS+ AAA",
    "aaa_radius": "RADIUS AAA",
    "dhcp_snooping": "DHCP snooping",
    "dai": "Dynamic ARP Inspection",
    "ip_source_guard": "IP Source Guard",
    "port_security": "port security",
    "private_vlan": "private VLANs",
    "hsrp": "HSRP",
    "vrrp": "VRRP",
    "glbp": "GLBP",
    "macsec": "MACsec",
    "stackwise": "StackWise",
    "wireless_controller": "wireless controller",
    "restconf": "RESTCONF",
    "netconf": "NETCONF",
    "telemetry": "streaming telemetry",
}

LEGACY_PROFILE_MAP = {
    "layer2": "basic_l2",
    "layer3": "basic_l3",
    "static_routing": "static_routing",
    "svi": "svi",
    "routed_ports": "routed_ports",
    "dhcp_server": "dhcp_server",
    "dhcp_snooping": "dhcp_snooping",
    "dai": "dai",
    "ip_source_guard": "ip_source_guard",
    "nat": "nat",
    "ospf": "ospf",
    "eigrp": "eigrp",
    "bgp": "bgp",
    "rip": "rip",
    "ipv6": "ipv6",
    "vrf_lite": "vrf_lite",
    "pbr": "pbr",
    "qos": "qos",
    "hsrp": "hsrp",
    "vrrp": "vrrp",
    "glbp": "glbp",
    "port_security": "port_security",
    "voice_vlan": "qos",
}

COMMON_SHOW_COMMANDS = [
    "show version",
    "show running-config",
    "show ip route",
]


def _load_json(name: str) -> dict:
    path = DATA_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


def load_feature_capabilities() -> dict[str, dict]:
    return _load_json("feature_capabilities.json")


# Router families with full crypto/VPN feature sets on IOS-XE.  Crypto on
# these platforms is still license-gated (securityk9 / DNA tiers); the
# platform validator surfaces that via profile feature_warnings.
XE_CRYPTO_ROUTER_FAMILIES = {
    "ISR 4000", "CSR 1000v", "Catalyst 8000v",
    "Catalyst 8200", "Catalyst 8300", "Catalyst 8500",
}

# Classic-IOS router families: crypto exists but requires the securityk9 /
# advanced-security feature set; no model-driven programmability.
IOS_CRYPTO_ROUTER_FAMILIES = {"ISR G1", "ISR G2"}

CBS_OS_TYPE = "IOS-like (CBS)"

# CBS/Business models with documented VRRP support (350 series only).
CBS_VRRP_MODELS = {"Cisco Business 350", "Cisco CBS350"}

# Catalyst 9000 models that stack with StackWise (stack member priority
# commands); 9400/9500/9600 use StackWise Virtual instead.
STACKWISE_FAMILIES = {"Catalyst 9200", "Catalyst 9300"}

# Catalyst 9000 models with documented GRE tunnel support (Network
# Advantage; per the per-release IP Addressing Services guides).  The 9200
# has no tunneling support.
GRE_SWITCH_FAMILIES = {"Catalyst 9300", "Catalyst 9400", "Catalyst 9500",
                       "Catalyst 9600"}


def _profile_capabilities(profile) -> set[str]:
    caps: set[str] = set()
    for old_key, tag in LEGACY_PROFILE_MAP.items():
        if profile.supports(old_key):
            caps.add(tag)
    is_cbs = profile.os_type == CBS_OS_TYPE

    if profile.is_router:
        caps.update({"basic_l3", "static_routing", "dhcp_relay", "pbr",
                     "ip_sla", "object_tracking", "eem", "snmpv3",
                     "aaa_tacacs", "aaa_radius", "qos"})
    if profile.is_switch:
        caps.add("basic_l2")
        if profile.supports("layer3") and not is_cbs:
            caps.update({"basic_l3", "static_routing", "dhcp_relay", "pbr",
                         "ip_sla", "object_tracking", "qos", "hsrp", "vrrp",
                         "snmpv3", "aaa_tacacs", "aaa_radius"})
        if is_cbs:
            # CBS/Business switches: SNMPv3/RADIUS/TACACS management is
            # documented; HSRP, IP SLA, PBR and object tracking are not.
            caps.update({"snmpv3", "aaa_radius", "aaa_tacacs"})
            if profile.supports("layer3"):
                caps.update({"basic_l3", "static_routing", "dhcp_relay"})
            if profile.model in CBS_VRRP_MODELS:
                caps.add("vrrp")
        if profile.family.startswith("Catalyst 9"):
            caps.update({"ipv6", "ospfv3", "vrf_lite", "private_vlan",
                         "netflow"})
            if profile.family in STACKWISE_FAMILIES:
                caps.add("stackwise")
            if profile.family in GRE_SWITCH_FAMILIES:
                caps.update({"tunnel", "gre"})

    if profile.family in XE_CRYPTO_ROUTER_FAMILIES:
        caps.update({"ipv6", "ospfv3", "vrf_lite", "tunnel", "gre",
                     "multipoint_gre", "nhrp", "dmvpn", "vti", "ipsec",
                     "ikev1", "ikev2", "flexvpn", "crypto_maps",
                     "tunnel_protection", "zone_based_firewall", "netflow",
                     "hsrp", "vrrp", "glbp"})
    elif profile.family in IOS_CRYPTO_ROUTER_FAMILIES:
        # License-dependent (securityk9); IKEv2 additionally requires
        # IOS 15.1(1)T+ - the platform validator warns on 12.x versions.
        caps.update({"ipv6", "ospfv3", "vrf_lite", "tunnel", "gre",
                     "multipoint_gre", "nhrp", "dmvpn", "vti", "ipsec",
                     "ikev1", "ikev2", "crypto_maps",
                     "tunnel_protection", "zone_based_firewall",
                     "hsrp", "vrrp", "glbp"})
        if profile.family == "ISR G2":
            caps.add("netflow")  # Flexible NetFlow exists on 15.x M trains

    # Model-driven programmability only exists on IOS-XE.
    if profile.os_type == "IOS-XE":
        caps.update({"restconf", "netconf", "telemetry"})
    else:
        caps -= {"restconf", "netconf", "telemetry"}
    return caps & set(CAPABILITY_TAGS)


def resolve_capabilities(project, profile) -> set[str]:
    resolved = _profile_capabilities(profile)
    return resolved & set(CAPABILITY_TAGS)


def missing_capabilities(project, profile, required: list[str]) -> list[str]:
    resolved = resolve_capabilities(project, profile)
    return [cap for cap in required if cap not in resolved]


def capability_label(capability: str) -> str:
    return CAPABILITY_LABELS.get(capability, capability.replace("_", " "))


def capability_labels(capabilities: list[str] | set[str]) -> list[str]:
    return [capability_label(cap) for cap in capabilities]


def feature_lock_state(project, profile, feature_key: str) -> dict:
    features = load_feature_capabilities()
    raw = features.get(feature_key, {})
    required = list(raw.get("required", []))
    missing = missing_capabilities(project, profile, required)
    commands = list(dict.fromkeys(COMMON_SHOW_COMMANDS
                                  + raw.get("verification_commands", [])))
    if missing:
        state = "locked"
        reason = f"{profile.model} does not include " + \
            ", ".join(capability_labels(missing))
    else:
        state = "supported"
        reason = "Required capabilities are available in the device profile."
    return {
        "feature": feature_key,
        "label": raw.get("label", feature_key),
        "state": state,
        "required": required,
        "missing": missing,
        "required_labels": capability_labels(required),
        "missing_labels": capability_labels(missing),
        "optional": list(raw.get("optional", [])),
        "reason": reason,
        "verification_commands": commands,
    }


def resolve_feature_lock_state(project, profile) -> dict[str, dict]:
    return {
        feature: feature_lock_state(project, profile, feature)
        for feature in load_feature_capabilities()
    }


def capability_summary(project, profile, limit: int = 12) -> str:
    caps = sorted(resolve_capabilities(project, profile))
    if not caps:
        return "Device profile: no capabilities detected yet."
    return f"Device profile: {len(caps)} capabilities detected"
