"""Regression tests for the validation-audit fixes."""

from conftest import gen

from ciscogen.deploy import redact_secrets
from ciscogen.lint import lint_config
from ciscogen.models import Project
from ciscogen.profiles.capabilities import resolve_capabilities
from ciscogen.validators import validate_project


def messages(issues):
    return " | ".join(f"{i.severity}:{i.message}" for i in issues).lower()


# ------------------------------------------------- critical: UDLD shadowing
def test_udld_does_not_drop_port_security(project, profiles):
    project.data["interfaces"]["physical"] = [{
        "name": "Gi1/0/1", "mode": "access", "access_vlan": "10",
        "udld": True, "ps_enabled": True, "ps_max": "2", "ps_sticky": True,
    }]
    config = gen(project, profiles)
    assert " udld port aggressive" in config
    assert " switchport port-security\n" in config
    assert " switchport port-security maximum 2" in config
    assert " switchport port-security mac-address sticky" in config


# ------------------------------------------------- critical: redaction
def test_redaction_covers_secret_values():
    text = "\n".join([
        "enable secret MySecret123",
        "crypto isakmp key MyPSK123 address 0.0.0.0 0.0.0.0",
        "  pre-shared-key MyIkev2Psk",
        "snmp-server community mycommunity RO",
        "ntp authentication-key 5 md5 NtpKey99",
        "interface GigabitEthernet0/0",
    ])
    redacted = redact_secrets(text)
    for secret in ("MySecret123", "MyPSK123", "MyIkev2Psk", "mycommunity",
                   "NtpKey99"):
        assert secret not in redacted
    assert "address 0.0.0.0 0.0.0.0" in redacted   # non-secret tokens kept
    assert "interface GigabitEthernet0/0" in redacted
    assert redacted.splitlines()[2].startswith("  ")  # indentation kept


# ------------------------------------------------- high: AAA group keyword
def test_aaa_login_uses_group_keyword(project, profiles):
    project.data["system"]["aaa_new_model"] = True
    project.data["system"]["aaa_methods"]["login"] = "tacacs+ local"
    config = gen(project, profiles)
    assert "aaa authentication login default group tacacs+ local" in config

    project.data["system"]["aaa_methods"]["login"] = "radius local"
    config = gen(project, profiles)
    assert "aaa authentication login default group radius local" in config


# ------------------------------------------------- high: platform QoS
def qos_trust_project(model):
    project = Project()
    project.device_model = model
    project.sections_enabled["qos"] = True
    project.data["qos"]["trust"] = [{"interface": "Gi1/0/1", "mode": "dscp"}]
    project.data["qos"]["class_maps"] = [{"name": "CM", "dscp": "ef"}]
    return project


def test_mls_qos_only_on_classic_ios_switches(profiles):
    classic = qos_trust_project("Catalyst 2960")
    config = gen(classic, profiles)
    assert "mls qos\n" in config
    assert " mls qos trust dscp" in config

    xe_switch = qos_trust_project("Catalyst 9300")
    config = gen(xe_switch, profiles)
    assert "mls qos" not in config

    router = qos_trust_project("Cisco ISR 4331")
    config = gen(router, profiles)
    assert "mls qos" not in config
    issues = validate_project(xe_switch, profiles["Catalyst 9300"])
    assert "mls qos trust" in messages(issues)


# ------------------------------------------------- high: VRF syntax
def test_vrf_forwarding_modern_syntax(project, profiles):
    project.sections_enabled.update({"vrf": True})
    project.data["vrf"]["vrfs"] = [{"name": "T1", "rd": "65000:1"}]
    project.data["vrf"]["interface_assignments"] = [
        {"interface": "Vlan10", "vrf": "T1"}]
    project.data["interfaces"]["svis"] = [
        {"vlan": "10", "ip": "10.0.0.1", "mask": "255.255.255.0"}]
    config = gen(project, profiles)
    assert " vrf forwarding T1" in config
    assert " ip vrf forwarding" not in config


def test_dmvpn_tunnel_vrf_syntax(profiles):
    project = Project()
    project.device_model = "Cisco ISR 4331"
    project.sections_enabled["dmvpn"] = True
    project.data["dmvpn"].update(enabled=True, vrf="WAN",
                                 tunnel_ip="10.255.0.1",
                                 tunnel_mask="255.255.255.0")
    config = gen(project, profiles)
    assert " vrf forwarding WAN" in config


# ------------------------------------------------- high: capability resolver
def test_catalyst_8300_gets_crypto_capabilities(profiles):
    for model in ("Cisco Catalyst 8200", "Cisco Catalyst 8300",
                  "Cisco Catalyst 8500"):
        project = Project()
        project.device_model = model
        caps = resolve_capabilities(project, profiles[model])
        assert {"dmvpn", "ipsec", "ikev2", "zone_based_firewall",
                "vrf_lite", "ipv6"} <= caps, model


def test_classic_ios_has_no_programmability(profiles):
    for model in ("Cisco 1841", "Cisco 1941", "Cisco 3945",
                  "Catalyst 2960", "Catalyst 3560"):
        project = Project()
        project.device_model = model
        caps = resolve_capabilities(project, profiles[model])
        assert not caps & {"restconf", "netconf", "telemetry"}, model


def test_cbs_capabilities_are_narrow(profiles):
    project = Project()
    project.device_model = "Cisco CBS250"
    caps = resolve_capabilities(project, profiles["Cisco CBS250"])
    assert not caps & {"hsrp", "vrrp", "ip_sla", "object_tracking", "pbr"}
    assert "static_routing" in caps

    project.device_model = "Cisco CBS350"
    caps = resolve_capabilities(project, profiles["Cisco CBS350"])
    assert "vrrp" in caps          # documented on the 350 series
    assert "hsrp" not in caps      # Cisco IOS-only protocol


def test_stackwise_only_on_stacking_models(profiles):
    for model, expected in (("Catalyst 9300", True), ("Catalyst 9200", True),
                            ("Catalyst 9400", False),
                            ("Catalyst 9600", False)):
        project = Project()
        project.device_model = model
        caps = resolve_capabilities(project, profiles[model])
        assert ("stackwise" in caps) is expected, model


# ------------------------------------------------- high: license warnings
def test_isr_g2_dmvpn_warns_securityk9(profiles):
    project = Project()
    project.device_model = "Cisco 1941"
    project.os_type = "IOS"
    project.os_version = "15.4"
    project.sections_enabled["dmvpn"] = True
    project.data["dmvpn"].update(enabled=True, tunnel_ip="10.255.0.1",
                                 tunnel_mask="255.255.255.0",
                                 tunnel_source_interface="Gi0/0",
                                 nhrp_network_id="1")
    issues = validate_project(project, profiles["Cisco 1941"])
    assert "securityk9" in messages(issues)


def test_ikev2_on_ios12_is_error(profiles):
    project = Project()
    project.device_model = "Cisco 1841"
    project.os_type = "IOS"
    project.os_version = "12.4"
    project.sections_enabled["dmvpn"] = True
    project.data["dmvpn"].update(enabled=True, ipsec_enabled=True,
                                 ike_version="IKEv2",
                                 pre_shared_key="Str0ngKey!x",
                                 tunnel_ip="10.255.0.1",
                                 tunnel_mask="255.255.255.0",
                                 tunnel_source_interface="Fa0/0",
                                 nhrp_network_id="1")
    issues = validate_project(project, profiles["Cisco 1841"])
    text = messages(issues)
    assert "error:ikev2 is selected but ios 12.4" in text


# ------------------------------------------------- medium: syntax details
def test_ikev2_match_identity_has_mask(profiles):
    project = Project()
    project.device_model = "Cisco ISR 4331"
    project.sections_enabled["dmvpn"] = True
    project.data["dmvpn"].update(enabled=True, ipsec_enabled=True,
                                 ike_version="IKEv2",
                                 pre_shared_key="Str0ngKey!x",
                                 tunnel_ip="10.255.0.1",
                                 tunnel_mask="255.255.255.0")
    config = gen(project, profiles)
    assert " match identity remote address 0.0.0.0 0.0.0.0" in config
    assert "! BGP update-source" not in config


def test_private_vlan_primary_keyword(project, profiles):
    project.sections_enabled["vlans"] = True
    project.data["vlans"]["private_vlans"] = [
        {"primary": "100", "secondary": "101", "type": "isolated"}]
    config = gen(project, profiles)
    block = config[config.index("vlan 101"):]
    assert " private-vlan isolated" in block
    assert "vlan 100\n private-vlan primary\n private-vlan association 101" \
        in config


def test_netflow_generates_record_monitor_and_binding(project, profiles):
    project.data["system"]["netflow"].update(
        enabled=True, exporter="NF-EXPORT", destination="10.0.0.50",
        source_interface="Vlan99", transport_port="2055",
        interfaces="Gi1/0/1")
    project.data["interfaces"]["physical"] = [
        {"name": "Gi1/0/1", "mode": "access", "access_vlan": "10"}]
    config = gen(project, profiles)
    assert "flow record CISCOGEN-RECORD" in config
    assert " match ipv4 source address" in config
    assert "flow exporter NF-EXPORT" in config
    assert "flow monitor CISCOGEN-MONITOR" in config
    assert " record CISCOGEN-RECORD" in config
    assert " ip flow monitor CISCOGEN-MONITOR input" in config
    # definitions must precede the interface that references the monitor
    assert config.index("flow monitor CISCOGEN-MONITOR") < \
        config.index("interface GigabitEthernet1/0/1")


def test_snmp_management_acl_applied_and_validated(project, profiles):
    project.sections_enabled["acls"] = True
    project.data["system"]["snmp"]["communities"] = [
        {"community": "corp-ro", "mode": "RO"}]
    project.data["acls"]["acls"] = [{"type": "standard", "id": "MGMT",
                                     "rules": [{"action": "permit",
                                                "src": "10.99.0.0",
                                                "src_wildcard": "0.0.0.255"}]}]
    project.data["acls"]["management_plane_acl"] = "MGMT"
    config = gen(project, profiles)
    assert "snmp-server community corp-ro RO MGMT" in config
    issues = validate_project(project, profiles[project.device_model])
    assert "restrict management access by setting" not in messages(issues)

    project.data["acls"]["management_plane_acl"] = ""
    issues = validate_project(project, profiles[project.device_model])
    assert "restrict management access by setting" in messages(issues)


def test_restconf_https_conflict_warns(project, profiles):
    project.sections_enabled["security"] = True
    project.data["system"]["restconf_enabled"] = True
    project.data["security"]["disable_https"] = True
    issues = validate_project(project, profiles[project.device_model])
    assert "restconf requires the https server" in messages(issues)


def test_zbf_unzoned_interface_warns(profiles):
    project = Project()
    project.device_model = "Cisco ISR 4331"
    project.sections_enabled.update({"zbf": True, "interfaces": True})
    project.data["zbf"]["zones"] = [{"name": "OUT"}]
    project.data["zbf"]["interface_memberships"] = [
        {"interface": "Gi0/0/0", "zone": "OUT"}]
    project.data["interfaces"]["physical"] = [
        {"name": "Gi0/0/0", "mode": "routed", "ip": "198.51.100.1",
         "mask": "255.255.255.252"},
        {"name": "Gi0/0/1", "mode": "routed", "ip": "10.0.0.1",
         "mask": "255.255.255.0"},
    ]
    issues = validate_project(project, profiles["Cisco ISR 4331"])
    assert "in no security zone" in messages(issues)
    assert "gigabitethernet0/0/1" in messages(issues)


def test_ipsla_route_name_precedes_track(project, profiles):
    project.sections_enabled["ipsla"] = True
    project.data["ipsla"]["operations"] = [
        {"id": "1", "type": "icmp-echo", "target": "8.8.8.8"}]
    project.data["ipsla"]["tracks"] = [{"id": "1", "sla_id": "1"}]
    project.data["ipsla"]["tracked_routes"] = [{
        "prefix": "0.0.0.0", "mask": "0.0.0.0", "next_hop": "10.0.0.1",
        "track_id": "1", "name": "WAN"}]
    config = gen(project, profiles)
    assert "ip route 0.0.0.0 0.0.0.0 10.0.0.1 name WAN track 1" in config


def test_ipsla_same_ad_warning_only_when_real(project, profiles):
    project.sections_enabled["ipsla"] = True
    project.data["ipsla"]["operations"] = [
        {"id": "1", "type": "icmp-echo", "target": "8.8.8.8"}]
    project.data["ipsla"]["tracks"] = [{"id": "1", "sla_id": "1"}]
    project.data["ipsla"]["tracked_routes"] = [{
        "prefix": "0.0.0.0", "mask": "0.0.0.0", "next_hop": "10.0.0.1",
        "track_id": "1"}]
    issues = validate_project(project, profiles[project.device_model])
    assert "administrative distance" not in messages(issues)

    project.data["ipsla"]["floating_routes"] = [{
        "prefix": "0.0.0.0", "mask": "0.0.0.0", "next_hop": "10.0.0.2",
        "distance": "1"}]
    issues = validate_project(project, profiles[project.device_model])
    assert "same administrative distance" in messages(issues)


def test_2960_dai_generates_with_image_note(profiles):
    project = Project()
    project.device_model = "Catalyst 2960"
    project.sections_enabled["vlans"] = True
    project.data["vlans"]["dai"].update(enabled=True, vlans="10",
                                        trusted_interfaces="Gi0/1")
    project.data["vlans"]["dhcp_snooping"].update(enabled=True, vlans="10",
                                                  trusted_interfaces="Gi0/1")
    config = gen(project, profiles)
    issues = validate_project(project, profiles["Catalyst 2960"])
    assert "ip arp inspection vlan 10" in config
    text = messages(issues)
    assert "dynamic arp inspection is not supported" not in text
    assert "lan base" in text


def test_lint_track_reference_rule(project, profiles):
    config = "ip route 0.0.0.0 0.0.0.0 10.0.0.1 track 7\n"
    issues = lint_config(config, project, profiles[project.device_model])
    assert any("track 7" in issue.message for issue in issues)

    config += "track 7 ip sla 1 reachability\n"
    issues = lint_config(config, project, profiles[project.device_model])
    assert not any("track 7" in issue.message for issue in issues)


def test_2960l_dai_supported(profiles):
    # Cisco 2960-L 15.2(5)E config guide documents DAI (needs DHCP snooping).
    assert profiles["Catalyst 2960-L"].supports("dai")


def test_cat9k_gre_tunnels_capability(profiles):
    from ciscogen.profiles.capabilities import resolve_capabilities
    for model in ("Catalyst 9300", "Catalyst 9400", "Catalyst 9500",
                  "Catalyst 9600"):
        p = Project(); p.device_model = model
        caps = resolve_capabilities(p, profiles[model])
        assert "gre" in caps and "tunnel" in caps, model
        # DMVPN/VTI stay switch-unsupported on Catalyst 9000.
        assert "dmvpn" not in caps and "vti" not in caps, model


def test_cat9200_has_no_tunnels(profiles):
    from ciscogen.profiles.capabilities import resolve_capabilities
    p = Project(); p.device_model = "Catalyst 9200"
    caps = resolve_capabilities(p, profiles["Catalyst 9200"])
    assert "gre" not in caps and "tunnel" not in caps


def test_restconf_not_generated_on_classic_ios(profiles):
    p = Project(); p.device_model = "Cisco 2911"
    p.os_type = "IOS"; p.os_version = "15.4"
    p.data["system"]["restconf_enabled"] = True
    p.data["system"]["netconf_enabled"] = True
    from conftest import gen
    config = gen(p, profiles)
    assert "restconf" not in config
    assert "netconf-yang" not in config
    issues = validate_project(p, profiles[p.device_model])
    assert "ios-xe features and will not be generated" in messages(issues)


def test_restconf_generated_on_iosxe(project, profiles):
    project.data["system"]["restconf_enabled"] = True
    from conftest import gen
    config = gen(project, profiles)          # Catalyst 9300 is IOS-XE
    assert "restconf" in config


def test_project_drops_legacy_license_fields():
    project = Project.from_dict({
        "device": {"model": "Catalyst 9300"},
        "license_profile": "security",
        "capability_overrides": {"dmvpn": True},
    })
    dumped = project.to_dict()
    assert "license_profile" not in dumped
    assert "capability_overrides" not in dumped
