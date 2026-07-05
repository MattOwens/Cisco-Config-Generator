"""Platform capability checks: warn when the project uses features the
selected device profile does not (or may not) support."""

from __future__ import annotations

from ..profiles.capabilities import (
    feature_lock_state,
    resolve_capabilities,
)
from ..utils import s, truthy
from . import Issue, error, warning, info


def _issue_for(profile, feature: str, used_by: str) -> Issue:
    note = profile.warning_for(feature)
    if note:
        return warning("platform", f"{used_by}: {note}")
    return warning("platform", f"{used_by} may not be supported on "
                               f"{profile.model}.")


def validate_platform(project, profile) -> list[Issue]:
    issues: list[Issue] = []
    data = project.data
    enabled = project.sections_enabled
    resolved_caps = resolve_capabilities(project, profile)

    for note in profile.platform_warnings:
        issues.append(info("platform", note))

    if project.os_version and project.os_version not in profile.supported_os_versions:
        issues.append(warning("platform", f"OS version '{project.os_version}' is not "
                                          f"in the known list for {profile.model} "
                                          f"({', '.join(profile.supported_os_versions)})."))

    if enabled.get("interfaces"):
        if_data = data.get("interfaces", {})
        modes = {s(item.get("mode")) for item in if_data.get("physical", [])}
        if ("access" in modes or "trunk" in modes) and not profile.supports("layer2"):
            issues.append(_issue_for(profile, "layer2",
                                     "Switchport (access/trunk) configuration"))
        if "routed" in modes and not profile.supports("routed_ports"):
            issues.append(error("platform", f"Routed ports are not supported on "
                                            f"{profile.model}."))
        if if_data.get("svis") and not profile.supports("svi"):
            issues.append(_issue_for(profile, "svi", "SVI configuration"))
        if if_data.get("subinterfaces") and not profile.supports("subinterfaces"):
            issues.append(error("platform", f"Router subinterfaces are not supported "
                                            f"on {profile.model}."))
        if (if_data.get("port_channels")
                or any(s(i.get("channel_group")) for i in if_data.get("physical", []))) \
                and not profile.supports("etherchannel"):
            issues.append(_issue_for(profile, "etherchannel", "EtherChannel"))
        pagp_modes = {"desirable", "auto"}
        if any(s(i.get("channel_mode")) in pagp_modes
               for i in if_data.get("physical", [])) and not profile.supports("pagp"):
            issues.append(_issue_for(profile, "pagp", "PAgP channel mode"))
        if any(truthy(i.get("ps_enabled")) for i in if_data.get("physical", [])) \
                and not profile.supports("port_security"):
            issues.append(_issue_for(profile, "port_security", "Port security"))
        if any(s(i.get("voice_vlan")) for i in if_data.get("physical", [])) \
                and not profile.supports("voice_vlan"):
            issues.append(_issue_for(profile, "voice_vlan", "Voice VLAN"))
        if any(truthy(i.get("ip_source_guard")) for i in if_data.get("physical", [])) \
                and not profile.supports("ip_source_guard"):
            issues.append(_issue_for(profile, "ip_source_guard", "IP Source Guard"))
        if any(s(i.get("ipv6")) for i in if_data.get("physical", [])) \
                and "ipv6" not in resolved_caps:
            issues.append(warning("platform", "IPv6 interface addressing is configured "
                                             "but the resolved capability set lacks ipv6."))

    if enabled.get("vlans"):
        vlan_data = data.get("vlans", {})
        if vlan_data.get("vlans") and not profile.supports("layer2"):
            issues.append(info("platform", "VLAN IDs are included for planning. "
                                           "On routed-only platforms, create "
                                           "router-on-a-stick VLAN handling with "
                                           "subinterfaces instead of switchport VLANs."))
        if truthy(vlan_data.get("dhcp_snooping", {}).get("enabled")) \
                and not profile.supports("dhcp_snooping"):
            issues.append(_issue_for(profile, "dhcp_snooping", "DHCP snooping"))
        if truthy(vlan_data.get("dai", {}).get("enabled")):
            if not profile.supports("dai"):
                issues.append(_issue_for(profile, "dai",
                                         "Dynamic ARP Inspection"))
            elif profile.warning_for("dai"):
                # Supported, but image/feature-set dependent (e.g. 2960
                # LAN Base vs LAN Lite).
                issues.append(info("platform",
                                   f"Dynamic ARP Inspection: "
                                   f"{profile.warning_for('dai')}"))
        if truthy(vlan_data.get("vtp", {}).get("enabled")) \
                and not profile.supports("vtp"):
            issues.append(_issue_for(profile, "vtp", "VTP"))

    if enabled.get("dhcp") and data.get("dhcp", {}).get("pools") \
            and not profile.supports("dhcp_server"):
        issues.append(_issue_for(profile, "dhcp_server", "DHCP server"))

    if enabled.get("nat"):
        nat = data.get("nat", {})
        nat_used = nat.get("static_rules") or truthy(nat.get("dynamic_enabled"))
        if nat_used and not profile.supports("nat"):
            note = profile.warning_for("nat")
            issues.append(error("platform", note or f"NAT is not supported on "
                                                    f"{profile.model}."))

    if enabled.get("routing"):
        routing = data.get("routing", {})
        for proto in ("ospf", "eigrp", "bgp", "rip"):
            if truthy(routing.get(proto, {}).get("enabled")) \
                    and not profile.supports(proto):
                note = profile.warning_for(proto)
                issues.append(error("platform", note or
                                    f"{proto.upper()} is not supported on "
                                    f"{profile.model}."))

    if enabled.get("layer3"):
        l3 = data.get("layer3", {})
        if (l3.get("static_routes") or l3.get("route_maps")) \
                and not profile.is_l3 and not profile.is_router \
                and "static_routing" not in resolved_caps:
            issues.append(warning("platform", f"{profile.model} is a Layer 2 platform; "
                                              "static routes beyond the default "
                                              "gateway are not supported."))
        if l3.get("route_maps") and "pbr" not in resolved_caps:
            issues.append(warning("platform", "Policy-based routing is configured "
                                             "but this device profile does not "
                                             "include policy-based routing."))

    for section in ("vrf", "ipv6", "tunnels", "dmvpn", "ipsla", "zbf", "qos", "ha"):
        if enabled.get(section) and _advanced_section_used(section, data.get(section, {})):
            state = feature_lock_state(project, profile, section)
            if state["state"] == "locked":
                issues.append(warning(
                    "platform",
                    f"{state['label']} is not listed for this device profile: "
                    f"{state['reason']}. Verify with "
                    f"{', '.join(state['verification_commands'][:4])}."))
            else:
                # Supported but license/image-gated on this platform.
                note = profile.warning_for(section)
                if note:
                    issues.append(warning("platform",
                                          f"{state['label']}: {note}"))

    if enabled.get("dmvpn") and truthy(data.get("dmvpn", {}).get("enabled")):
        dmvpn = data["dmvpn"]
        if truthy(dmvpn.get("ipsec_enabled")):
            note = profile.warning_for("ipsec")
            if note and not profile.warning_for("dmvpn"):
                issues.append(warning("platform", f"IPsec: {note}"))
            if s(dmvpn.get("ike_version", "IKEv2")) == "IKEv2":
                ikev2_note = profile.warning_for("ikev2")
                if profile.os_type == "IOS" and \
                        s(project.os_version).startswith("12"):
                    issues.append(error(
                        "platform",
                        "IKEv2 is selected but IOS "
                        f"{project.os_version} predates IKEv2 support "
                        "(introduced in 15.1(1)T). Use IKEv1 or a 15.x "
                        "image."))
                elif ikev2_note:
                    issues.append(info("platform", ikev2_note))

    if enabled.get("tunnels"):
        encrypted = [t for t in data.get("tunnels", {}).get("tunnels", [])
                     if truthy(t.get("enabled", True))
                     and truthy(t.get("ipsec_enabled"))]
        if encrypted:
            note = profile.warning_for("ipsec") or profile.warning_for("dmvpn")
            if note:
                issues.append(warning("platform", f"Encrypted tunnels: {note}"))
            for tunnel in encrypted:
                if s(tunnel.get("ike_version", "IKEv2")) == "IKEv2" \
                        and profile.os_type == "IOS" \
                        and s(project.os_version).startswith("12"):
                    name = s(tunnel.get("name")) or \
                        f"Tunnel{s(tunnel.get('tunnel_number'))}"
                    issues.append(error(
                        "platform",
                        f"{name}: IKEv2 is selected but IOS "
                        f"{project.os_version} predates IKEv2 (15.1(1)T+). "
                        "Use IKEv1 or a 15.x image."))
                    break
    return issues


def _advanced_section_used(section: str, section_data: dict) -> bool:
    if section == "dmvpn":
        return truthy(section_data.get("enabled"))
    if section == "tunnels":
        return any(truthy(t.get("enabled", True))
                   for t in section_data.get("tunnels", []))
    if section == "ipsla":
        return bool(section_data.get("operations")
                    or section_data.get("tracks")
                    or section_data.get("tracked_routes")
                    or section_data.get("floating_routes"))
    if section == "vrf":
        return bool(section_data.get("vrfs")
                    or section_data.get("interface_assignments")
                    or section_data.get("static_routes"))
    if section == "zbf":
        return bool(section_data.get("zones")
                    or section_data.get("class_maps")
                    or section_data.get("policy_maps")
                    or section_data.get("zone_pairs"))
    if section == "ipv6":
        return bool(truthy(section_data.get("unicast_routing"))
                    or section_data.get("interface_addresses")
                    or section_data.get("static_routes")
                    or section_data.get("acls")
                    or truthy(section_data.get("ospfv3", {}).get("enabled")))
    if section == "qos":
        return bool(section_data.get("trust")
                    or section_data.get("autoqos")
                    or section_data.get("class_maps")
                    or section_data.get("policy_maps")
                    or section_data.get("service_policies"))
    if section == "ha":
        return bool(section_data.get("groups"))
    return bool(section_data)
