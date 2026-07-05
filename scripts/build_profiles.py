"""Regenerate the JSON device profiles under ciscogen/profiles/data/.

Run from the repository root:

    python scripts/build_profiles.py

Profiles are plain JSON so they can also be hand-edited or added
individually without touching this script.  This script exists so the
whole catalogue can be rebuilt consistently from family templates.
"""

from __future__ import annotations

import json
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "ciscogen" / "profiles" / "data"


def ifrange(prefix: str, start: int, end: int, slot: str = "") -> list[str]:
    return [f"{prefix}{slot}{i}" for i in range(start, end + 1)]


def caps(**overrides) -> dict:
    """Full capability dict with explicit defaults; overrides applied on top."""
    base = {
        "layer2": False,
        "layer3": False,
        "static_routing": False,
        "svi": False,
        "routed_ports": False,
        "subinterfaces": False,
        "etherchannel": False,
        "pagp": False,
        "dhcp_server": False,
        "dhcp_snooping": False,
        "dai": False,
        "ip_source_guard": False,
        "nat": False,
        "acl": True,
        "ospf": False,
        "eigrp": False,
        "bgp": False,
        "rip": False,
        "stp": False,
        "vtp": False,
        "port_security": False,
        "storm_control": False,
        "voice_vlan": False,
        "interface_mtu": False,
        "requires_trunk_encap": False,
    }
    base.update(overrides)
    return base


PROFILES: list[dict] = []


def add(profile: dict) -> None:
    PROFILES.append(profile)


# --------------------------------------------------------------------------
# Layer 2 access switches - Catalyst 2960 family (classic IOS)
# --------------------------------------------------------------------------
L2_SWITCH_CAPS = dict(
    layer2=True, svi=True, etherchannel=True, pagp=True, dhcp_server=True,
    dhcp_snooping=True, ip_source_guard=True, stp=True, vtp=True,
    port_security=True, storm_control=True, voice_vlan=True,
)

for model, versions, interfaces in [
    ("Catalyst 2960", ["12.2", "15.0", "15.2"],
     ifrange("FastEthernet", 1, 24, "0/") + ifrange("GigabitEthernet", 1, 2, "0/")),
    ("Catalyst 2960-C", ["15.0", "15.2"],
     ifrange("FastEthernet", 1, 8, "0/") + ifrange("GigabitEthernet", 1, 2, "0/")),
    ("Catalyst 2960-L", ["15.2"],
     ifrange("GigabitEthernet", 1, 28, "0/")),
]:
    profile = {
        "model": model,
        "family": "Catalyst 2960",
        "device_class": "switch",
        "os_type": "IOS",
        "supported_os_versions": versions,
        "interface_naming": "TypeX/Y (e.g. GigabitEthernet0/1)",
        "interfaces": interfaces,
        "interface_count": len(interfaces),
        "capabilities": caps(**L2_SWITCH_CAPS),
        "syntax_notes": [
            "Classic IOS syntax. Trunks are dot1q-only; no 'switchport trunk encapsulation' command.",
            "Per-interface MTU is not configurable; use 'system mtu jumbo' globally instead.",
        ],
        "platform_warnings": [
            "Layer 2 only platform: SVIs are for management; inter-VLAN routing is not supported.",
        ],
        "feature_warnings": {
            "dhcp_server": "DHCP server requires the LAN Base image (15.0(2) or later).",
            "dai": "Dynamic ARP Inspection is not supported on the classic 2960; use DHCP snooping alone.",
            "interface_mtu": "Per-interface MTU is not supported; configure 'system mtu jumbo' globally.",
        },
    }
    if model == "Catalyst 2960-L":
        profile["capabilities"]["static_routing"] = True
        profile["platform_warnings"] = []
        profile["feature_warnings"]["static_routing"] = (
            "Cisco's public 2960-L data sheet describes the platform as "
            "enhanced IOS LAN Lite with advanced Layer 2 features. Verify "
            "exact static-route support against the installed IOS image "
            "before using it for transit routing."
        )
    add(profile)

# --------------------------------------------------------------------------
# Layer 3 switches - Catalyst 3560/3750 (classic IOS)
# --------------------------------------------------------------------------
L3_IOS_SWITCH_CAPS = dict(
    layer2=True, layer3=True, svi=True, routed_ports=True, etherchannel=True,
    pagp=True, dhcp_server=True, dhcp_snooping=True, dai=True,
    ip_source_guard=True, ospf=True, eigrp=True, bgp=True, rip=True,
    stp=True, vtp=True, port_security=True, storm_control=True,
    voice_vlan=True, requires_trunk_encap=True,
)

for model, interfaces in [
    ("Catalyst 3560",
     ifrange("FastEthernet", 1, 24, "0/") + ifrange("GigabitEthernet", 1, 2, "0/")),
    ("Catalyst 3750",
     ifrange("GigabitEthernet", 1, 28, "1/0/")),
]:
    add({
        "model": model,
        "family": model,
        "device_class": "switch",
        "os_type": "IOS",
        "supported_os_versions": ["12.2", "15.0"],
        "interface_naming": ("TypeX/Y (e.g. FastEthernet0/1)" if model == "Catalyst 3560"
                             else "TypeX/Y/Z (e.g. GigabitEthernet1/0/1)"),
        "interfaces": interfaces,
        "interface_count": len(interfaces),
        "capabilities": caps(**L3_IOS_SWITCH_CAPS),
        "syntax_notes": [
            "Classic IOS syntax. Trunk ports require 'switchport trunk encapsulation dot1q' before 'switchport mode trunk'.",
            "Enable 'ip routing' globally before configuring SVI-based routing or routed ports.",
            "Per-interface MTU is limited; 'system mtu' / 'system mtu jumbo' control frame size globally.",
        ],
        "platform_warnings": [
            "End-of-life platform; verify the IOS feature set (IP Base vs IP Services) matches the features you enable.",
        ],
        "feature_warnings": {
            "bgp": "BGP requires the IP Services image and has limited scale on this platform.",
            "nat": "NAT is not supported on this platform.",
        },
    })

# --------------------------------------------------------------------------
# Layer 3 switches - Catalyst 3650/3850 (IOS-XE 3.x/16.x)
# --------------------------------------------------------------------------
L3_XE_SWITCH_CAPS = dict(
    layer2=True, layer3=True, svi=True, routed_ports=True, etherchannel=True,
    pagp=True, dhcp_server=True, dhcp_snooping=True, dai=True,
    ip_source_guard=True, ospf=True, eigrp=True, bgp=True, rip=True,
    stp=True, vtp=True, port_security=True, storm_control=True,
    voice_vlan=True, interface_mtu=True,
)

for model in ["Catalyst 3650", "Catalyst 3850"]:
    interfaces = ifrange("GigabitEthernet", 1, 48, "1/0/") + ifrange("TenGigabitEthernet", 1, 4, "1/1/")
    add({
        "model": model,
        "family": model,
        "device_class": "switch",
        "os_type": "IOS-XE",
        "supported_os_versions": ["3.6", "3.7", "16.3", "16.6", "16.9", "16.12"],
        "interface_naming": "TypeX/Y/Z (e.g. GigabitEthernet1/0/1)",
        "interfaces": interfaces,
        "interface_count": len(interfaces),
        "capabilities": caps(**L3_XE_SWITCH_CAPS),
        "syntax_notes": [
            "IOS-XE syntax; configuration commands largely match classic IOS.",
            "Enable 'ip routing' globally before configuring SVI-based routing or routed ports.",
        ],
        "platform_warnings": [
            "Feature availability varies by SKU, IOS-XE image and release. Verify on the target device before deployment.",
        ],
        "feature_warnings": {
            "bgp": "BGP may require the IP Services feature set.",
            "nat": "NAT is not supported on this platform.",
        },
    })

# --------------------------------------------------------------------------
# Catalyst 9000 series (IOS-XE 16.x/17.x)
# --------------------------------------------------------------------------
CAT9K_CAPS = dict(
    layer2=True, layer3=True, svi=True, routed_ports=True, etherchannel=True,
    pagp=True, dhcp_server=True, dhcp_snooping=True, dai=True,
    ip_source_guard=True, ospf=True, eigrp=True, bgp=True, rip=True,
    stp=True, vtp=True, port_security=True, storm_control=True,
    voice_vlan=True, interface_mtu=True,
)

CAT9K = [
    ("Catalyst 9200", ["16.9", "16.12", "17.3", "17.6", "17.9"],
     ifrange("GigabitEthernet", 1, 24, "1/0/") + ifrange("TenGigabitEthernet", 1, 4, "1/1/"),
     dict(bgp=False, nat=False),
     {"bgp": "BGP is not supported on the Catalyst 9200 (Network Essentials only).",
      "nat": "NAT is not supported on the Catalyst 9200."}),
    ("Catalyst 9300", ["16.6", "16.9", "16.12", "17.3", "17.6", "17.9", "17.12"],
     ifrange("GigabitEthernet", 1, 48, "1/0/") + ifrange("TenGigabitEthernet", 1, 8, "1/1/"),
     dict(nat=True),
     {"nat": "NAT on Catalyst 9300 requires Network Advantage and IOS-XE 17.1 or later.",
      "bgp": "Full BGP may require Network Advantage."}),
    ("Catalyst 9400", ["16.6", "16.9", "16.12", "17.3", "17.6", "17.9", "17.12"],
     ifrange("GigabitEthernet", 1, 48, "1/0/"),
     dict(nat=True),
     {"nat": "NAT on Catalyst 9400 requires Network Advantage and a recent IOS-XE release.",
      "bgp": "Full BGP may require Network Advantage."}),
    ("Catalyst 9500", ["16.6", "16.9", "16.12", "17.3", "17.6", "17.9", "17.12"],
     ifrange("TenGigabitEthernet", 1, 24, "1/0/") + ifrange("FortyGigabitEthernet", 1, 4, "1/1/"),
     dict(nat=True, port_security=True),
     {"nat": "NAT on Catalyst 9500 requires Network Advantage and a recent IOS-XE release."}),
    ("Catalyst 9600", ["16.12", "17.3", "17.6", "17.9", "17.12"],
     ifrange("TenGigabitEthernet", 1, 48, "1/0/"),
     dict(nat=True),
     {"nat": "NAT on Catalyst 9600 requires Network Advantage and a recent IOS-XE release."}),
]

for model, versions, interfaces, cap_over, feat_warn in CAT9K:
    c = dict(CAT9K_CAPS)
    c.update(cap_over)
    add({
        "model": model,
        "family": model,
        "device_class": "switch",
        "os_type": "IOS-XE",
        "supported_os_versions": versions,
        "interface_naming": "TypeX/Y/Z (e.g. GigabitEthernet1/0/1)",
        "interfaces": interfaces,
        "interface_count": len(interfaces),
        "capabilities": caps(**c),
        "syntax_notes": [
            "IOS-XE 16.x/17.x syntax.",
            "Enable 'ip routing' globally before configuring SVI-based routing or routed ports.",
            "On recent releases 'spanning-tree portfast' may be shown as 'spanning-tree portfast edge'; both are accepted.",
        ],
        "platform_warnings": [
            "Feature availability varies by SKU, IOS-XE image and release. Verify on the target device before deployment.",
        ],
        "feature_warnings": feat_warn,
    })

# --------------------------------------------------------------------------
# Cisco Business / CBS switches (IOS-like CLI, not classic IOS)
# --------------------------------------------------------------------------
CBS_WARNING = (
    "CBS/Cisco Business switches run an IOS-like CLI that is NOT classic IOS. "
    "Many commands differ (flat port naming such as GigabitEthernet1, no 'ip routing' "
    "command, different management commands). Review every generated line before use."
)

CBS = [
    ("Cisco Business 220", ["2.0"], False, False, False,
     "Smart switch: Layer 2 only with basic management."),
    ("Cisco Business 250", ["3.1", "3.2", "3.3"], True, False, True,
     "Smart switch: static routing between SVIs only."),
    ("Cisco Business 350", ["3.1", "3.2", "3.3"], True, True, True,
     "Managed switch: static routing; RIPv2 available on 350 series firmware 3.1+."),
    ("Cisco CBS250", ["3.0", "3.1", "3.2", "3.3"], True, False, True,
     "Smart switch: static routing between SVIs only."),
    ("Cisco CBS350", ["3.0", "3.1", "3.2", "3.3"], True, True, True,
     "Managed switch: static routing; RIPv2 available on firmware 3.1+."),
]

for model, versions, l3, dai_ok, dhcp_srv, note in CBS:
    interfaces = ifrange("GigabitEthernet", 1, 28)
    add({
        "model": model,
        "family": "Cisco Business / CBS",
        "device_class": "switch",
        "os_type": "IOS-like (CBS)",
        "supported_os_versions": versions,
        "interface_naming": "TypeN flat numbering (e.g. GigabitEthernet1)",
        "interfaces": interfaces,
        "interface_count": len(interfaces),
        "capabilities": caps(
            layer2=True, layer3=l3, svi=True, etherchannel=True,
            dhcp_server=dhcp_srv, dhcp_snooping=True, dai=dai_ok,
            ip_source_guard=dai_ok, rip=(model in ("Cisco Business 350", "Cisco CBS350")),
            stp=True, port_security=True, storm_control=True, voice_vlan=True,
        ),
        "syntax_notes": [
            "IOS-like CLI with flat interface numbering (GigabitEthernet1..N).",
            "No 'ip routing' global command; L3 behaviour is controlled per firmware defaults.",
            note,
        ],
        "platform_warnings": [CBS_WARNING],
        "feature_warnings": {
            "ospf": "OSPF is not supported on this platform.",
            "eigrp": "EIGRP is not supported on this platform.",
            "bgp": "BGP is not supported on this platform.",
            "nat": "NAT is not supported on this platform.",
            "subinterfaces": "Router subinterfaces are not supported on this platform.",
            "pagp": "Only LACP is supported for link aggregation; PAgP is unavailable.",
        },
    })

# --------------------------------------------------------------------------
# ISR G1/G2 routers (classic IOS)
# --------------------------------------------------------------------------
ROUTER_IOS_CAPS = dict(
    layer3=True, routed_ports=True, subinterfaces=True, dhcp_server=True,
    nat=True, ospf=True, eigrp=True, bgp=True, rip=True,
)

ISR_G = [
    ("Cisco 1841", ["12.4", "15.1"], ifrange("FastEthernet", 0, 1, "0/")),
    ("Cisco 1941", ["15.0", "15.1", "15.2", "15.4", "15.7"], ifrange("GigabitEthernet", 0, 1, "0/")),
    ("Cisco 2901", ["15.0", "15.1", "15.2", "15.4", "15.7"], ifrange("GigabitEthernet", 0, 1, "0/")),
    ("Cisco 2911", ["15.0", "15.1", "15.2", "15.4", "15.7"], ifrange("GigabitEthernet", 0, 2, "0/")),
    ("Cisco 2921", ["15.0", "15.1", "15.2", "15.4", "15.7"], ifrange("GigabitEthernet", 0, 2, "0/")),
    ("Cisco 2951", ["15.0", "15.1", "15.2", "15.4", "15.7"], ifrange("GigabitEthernet", 0, 2, "0/")),
    ("Cisco 3925", ["15.0", "15.1", "15.2", "15.4", "15.7"], ifrange("GigabitEthernet", 0, 3, "0/")),
    ("Cisco 3945", ["15.0", "15.1", "15.2", "15.4", "15.7"], ifrange("GigabitEthernet", 0, 3, "0/")),
]

for model, versions, interfaces in ISR_G:
    family = "ISR G1" if model == "Cisco 1841" else "ISR G2"
    add({
        "model": model,
        "family": family,
        "device_class": "router",
        "os_type": "IOS",
        "supported_os_versions": versions,
        "interface_naming": "TypeX/Y (e.g. GigabitEthernet0/0)",
        "interfaces": interfaces,
        "interface_count": len(interfaces),
        "capabilities": caps(**ROUTER_IOS_CAPS),
        "syntax_notes": [
            "Classic IOS router syntax.",
            "Subinterfaces use 'encapsulation dot1Q <vlan>' for router-on-a-stick.",
        ],
        "platform_warnings": [
            "End-of-life platform; verify IOS image feature set (e.g. securityk9, datak9) for advanced features.",
        ],
        "feature_warnings": {
            "etherchannel": "EtherChannel is not typically available on onboard router ports of this platform.",
            "layer2": "Switchport commands require an EtherSwitch service module; onboard ports are routed only.",
            "svi": "SVIs require an EtherSwitch service module.",
        },
    })

# --------------------------------------------------------------------------
# ISR 4000 series and Catalyst 8000 routers (IOS-XE)
# --------------------------------------------------------------------------
ROUTER_XE_CAPS = dict(
    layer3=True, routed_ports=True, subinterfaces=True, dhcp_server=True,
    nat=True, ospf=True, eigrp=True, bgp=True, rip=True, interface_mtu=True,
)

XE_ROUTERS = [
    ("Cisco ISR 4221", "ISR 4000", ["16.6", "16.9", "16.12", "17.3", "17.6"],
     ifrange("GigabitEthernet", 0, 1, "0/0/")),
    ("Cisco ISR 4321", "ISR 4000", ["3.16", "16.6", "16.9", "16.12", "17.3", "17.6"],
     ifrange("GigabitEthernet", 0, 1, "0/0/")),
    ("Cisco ISR 4331", "ISR 4000", ["3.16", "16.6", "16.9", "16.12", "17.3", "17.6"],
     ifrange("GigabitEthernet", 0, 2, "0/0/")),
    ("Cisco ISR 4351", "ISR 4000", ["3.16", "16.6", "16.9", "16.12", "17.3", "17.6"],
     ifrange("GigabitEthernet", 0, 2, "0/0/")),
    ("Cisco ISR 4431", "ISR 4000", ["3.16", "16.6", "16.9", "16.12", "17.3", "17.6"],
     ifrange("GigabitEthernet", 0, 3, "0/0/")),
    ("Cisco ISR 4451", "ISR 4000", ["3.16", "16.6", "16.9", "16.12", "17.3", "17.6"],
     ifrange("GigabitEthernet", 0, 3, "0/0/")),
    ("Cisco CSR1000v", "CSR 1000v", ["16.6", "16.9", "16.12", "17.1", "17.3"],
     ifrange("GigabitEthernet", 1, 4)),
    ("Cisco Catalyst 8000v", "Catalyst 8000v", ["17.4", "17.6", "17.9", "17.12"],
     ifrange("GigabitEthernet", 1, 4)),
    ("Cisco Catalyst 8200", "Catalyst 8200", ["17.3", "17.6", "17.9", "17.12"],
     ifrange("GigabitEthernet", 0, 3, "0/0/")),
    ("Cisco Catalyst 8300", "Catalyst 8300", ["17.3", "17.6", "17.9", "17.12"],
     ifrange("GigabitEthernet", 0, 5, "0/0/")),
    ("Cisco Catalyst 8500", "Catalyst 8500", ["17.3", "17.6", "17.9", "17.12"],
     ifrange("TenGigabitEthernet", 0, 7, "0/0/")),
]

for model, family, versions, interfaces in XE_ROUTERS:
    flat = model in ("Cisco CSR1000v", "Cisco Catalyst 8000v")
    add({
        "model": model,
        "family": family,
        "device_class": "router",
        "os_type": "IOS-XE",
        "supported_os_versions": versions,
        "interface_naming": ("TypeN flat numbering (e.g. GigabitEthernet1)" if flat
                             else "TypeX/Y/Z (e.g. GigabitEthernet0/0/0)"),
        "interfaces": interfaces,
        "interface_count": len(interfaces),
        "capabilities": caps(**ROUTER_XE_CAPS),
        "syntax_notes": [
            "IOS-XE router syntax; configuration commands largely match classic IOS.",
            "Subinterfaces use 'encapsulation dot1Q <vlan>' for router-on-a-stick.",
        ],
        "platform_warnings": (
            ["Virtual platform: interface names depend on the hypervisor NIC mapping."] if flat else
            ["Throughput and some features vary by platform entitlement, IOS-XE image and release."]
        ),
        "feature_warnings": {
            "etherchannel": "Port-channels are supported only in specific designs; verify before use.",
            "layer2": "Switchport commands require an NIM/SM switch module; onboard ports are routed only.",
            "svi": "SVIs require a switch module or virtual platform support.",
        },
    })


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for profile in PROFILES:
        slug = (profile["model"].lower()
                .replace(" ", "_").replace("/", "_").replace("-", "_"))
        path = OUT_DIR / f"{slug}.json"
        path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(PROFILES)} profiles to {OUT_DIR}")


if __name__ == "__main__":
    main()
