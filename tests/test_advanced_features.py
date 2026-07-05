from pathlib import Path

from conftest import gen

from ciscogen.deploy import optional_dependency_status
from ciscogen.exporting import deployment_checklist_markdown
from ciscogen.lint import lint_config
from ciscogen.models import Project, SCHEMA_VERSION
from ciscogen.profiles.capabilities import resolve_capabilities
from ciscogen.templates import apply_template, load_template
from ciscogen.validators import validate_project
from ciscogen.validators.network import is_valid_ipv6_interface


def messages(issues):
    return " | ".join(i.message for i in issues).lower()


def test_schema_v1_migrates_to_v2_defaults():
    loaded = Project.from_dict({
        "schema_version": 1,
        "device": {"model": "Catalyst 9300", "os_type": "IOS-XE"},
        "data": {"system": {"hostname": "OLD"}},
    })
    assert SCHEMA_VERSION == 2
    assert loaded.data["system"]["hostname"] == "OLD"
    assert loaded.data["dmvpn"]["enabled"] is False
    assert loaded.data["custom_cli"]["global"] == ""
    assert "license_profile" not in loaded.to_dict()


def test_profile_capability_resolution_ignores_saved_license(project, profiles):
    project.license_profile = "network_essentials"
    caps = resolve_capabilities(project, profiles[project.device_model])
    assert "basic_l3" in caps
    assert "vrf_lite" in caps
    project.license_profile = "security"
    assert "vrf_lite" in resolve_capabilities(project, profiles[project.device_model])


def test_2960_l_static_routing_profile_is_narrow(profiles):
    project = Project()
    project.device_model = "Catalyst 2960-L"
    caps = resolve_capabilities(project, profiles[project.device_model])
    assert "static_routing" in caps
    assert "pbr" not in caps


def test_router_vlan_ids_generate_without_lock_warning(profiles):
    project = Project()
    project.device_model = "Cisco ISR 4331"
    project.os_type = "IOS-XE"
    project.os_version = "17.6"
    project.sections_enabled["vlans"] = True
    project.data["vlans"]["vlans"] = [{"id": "10", "name": "USERS"}]
    config = gen(project, profiles)
    issues = validate_project(project, profiles[project.device_model])
    assert "vlan 10" in config
    assert "name USERS" in config
    assert "vlan and layer 2 security is locked" not in messages(issues)


def test_2960_l_static_routes_generate(profiles):
    project = Project()
    project.device_model = "Catalyst 2960-L"
    project.os_type = "IOS"
    project.os_version = "15.2"
    project.sections_enabled["layer3"] = True
    project.data["layer3"]["static_routes"] = [{
        "prefix": "0.0.0.0", "mask": "0.0.0.0", "next_hop": "10.0.0.1",
    }]
    config = gen(project, profiles)
    issues = validate_project(project, profiles[project.device_model])
    assert "ip routing" in config
    assert "ip route 0.0.0.0 0.0.0.0 10.0.0.1" in config
    assert "layer 2 platform" not in messages(issues)


def dmvpn_project():
    p = Project()
    p.device_model = "Cisco ISR 4331"
    p.os_type = "IOS-XE"
    p.os_version = "17.6"
    p.sections_enabled["dmvpn"] = True
    p.data["dmvpn"].update({
        "enabled": True,
        "role": "Hub",
        "phase": "Phase 3",
        "tunnel_number": "100",
        "tunnel_ip": "10.255.0.1",
        "tunnel_mask": "255.255.255.0",
        "tunnel_source_interface": "Gi0/0/0",
        "nhrp_network_id": "100",
        "ipsec_enabled": True,
        "pre_shared_key": "VeryStrongSharedKey123",
    })
    return p


def test_dmvpn_hub_phase3_ikev2_generation(profiles):
    project = dmvpn_project()
    config = gen(project, profiles)
    assert "crypto ikev2 proposal DMVPN-IKEV2-PROP" in config
    assert "interface Tunnel100" in config
    assert " ip nhrp redirect" in config
    assert " tunnel protection ipsec profile DMVPN-IPSEC-PROFILE" in config


def test_dmvpn_spoke_generation(profiles):
    project = dmvpn_project()
    project.data["dmvpn"].update({"role": "Spoke", "tunnel_ip": "10.255.0.11"})
    project.data["dmvpn"]["nhrp_nhs"] = [{"address": "10.255.0.1", "nbma": "203.0.113.10"}]
    config = gen(project, profiles)
    assert " ip nhrp nhs 10.255.0.1" in config
    assert " ip nhrp map 10.255.0.1 203.0.113.10" in config
    assert " ip nhrp shortcut" in config


def test_ikev1_dmvpn_generation(profiles):
    project = dmvpn_project()
    project.data["dmvpn"]["ike_version"] = "IKEv1"
    config = gen(project, profiles)
    assert "crypto isakmp policy 10" in config
    assert "crypto ipsec transform-set DMVPN-TS" in config


def test_dmvpn_validation_warns_for_incomplete(profiles):
    project = dmvpn_project()
    project.data["dmvpn"]["tunnel_source_interface"] = ""
    project.data["dmvpn"]["pre_shared_key"] = "cisco"
    issues = validate_project(project, profiles[project.device_model])
    text = messages(issues)
    assert "tunnel source" in text
    assert "pre-shared key looks weak" in text


def test_ipsla_track_and_route_generation(project, profiles):
    project.sections_enabled["ipsla"] = True
    project.data["ipsla"]["operations"] = [{
        "id": "1", "type": "icmp-echo", "target": "8.8.8.8",
        "source_interface": "Gi1/0/1", "frequency": "5",
    }]
    project.data["ipsla"]["tracks"] = [{"id": "1", "sla_id": "1", "type": "reachability"}]
    project.data["ipsla"]["tracked_routes"] = [{
        "prefix": "0.0.0.0", "mask": "0.0.0.0",
        "next_hop": "10.0.0.1", "track_id": "1",
    }]
    project.data["ipsla"]["floating_routes"] = [{
        "prefix": "0.0.0.0", "mask": "0.0.0.0",
        "next_hop": "10.0.0.2", "distance": "250",
    }]
    config = gen(project, profiles)
    assert "ip sla 1" in config
    assert "icmp-echo 8.8.8.8 source-interface GigabitEthernet1/0/1" in config
    assert "track 1 ip sla 1 reachability" in config
    assert "ip route 0.0.0.0 0.0.0.0 10.0.0.1 track 1" in config


def test_acl_vty_binding_generation(project, profiles):
    project.sections_enabled["acls"] = True
    project.data["acls"]["acls"] = [{"type": "standard", "id": "MGMT", "rules": [{"action": "permit", "src": "10.0.0.0", "src_wildcard": "0.0.0.255"}]}]
    project.data["acls"]["vty_bindings"] = [{"acl": "MGMT", "lines": "0 4", "direction": "in"}]
    config = gen(project, profiles)
    assert "line vty 0 4" in config
    assert " access-class MGMT in" in config


def test_vrf_generation_order(project, profiles):
    project.sections_enabled.update({"vrf": True, "interfaces": True})
    project.data["vrf"]["vrfs"] = [{"name": "TENANT-A", "rd": "65000:1"}]
    project.data["vrf"]["interface_assignments"] = [{"interface": "Vlan10", "vrf": "TENANT-A"}]
    project.data["interfaces"]["svis"] = [{"vlan": "10", "ip": "10.10.0.1", "mask": "255.255.255.0"}]
    config = gen(project, profiles)
    assert config.index("vrf definition TENANT-A") < config.index("interface Vlan10")
    block = config[config.index("interface Vlan10"):].split("!")[0]
    # Modern syntax: 'vrf definition' pairs with 'vrf forwarding' (never
    # the legacy 'ip vrf forwarding'), placed before the IP address.
    assert " ip vrf forwarding" not in block
    assert block.index(" vrf forwarding TENANT-A") < block.index(" ip address")


def test_zbf_ipv6_qos_ha_generation(project, profiles):
    project.sections_enabled.update({"zbf": True, "ipv6": True, "qos": True, "ha": True})
    project.data["zbf"]["zones"] = [{"name": "INSIDE"}, {"name": "OUTSIDE"}]
    project.data["zbf"]["class_maps"] = [{"name": "CM-WEB", "protocols": "http, https"}]
    project.data["zbf"]["policy_maps"] = [{"name": "PM-IN-OUT", "classes": "CM-WEB", "class_default_action": "drop"}]
    project.data["zbf"]["zone_pairs"] = [{"name": "ZP", "source": "INSIDE", "destination": "OUTSIDE", "policy": "PM-IN-OUT"}]
    project.data["ipv6"]["unicast_routing"] = True
    project.data["ipv6"]["interface_addresses"] = [{"interface": "Vlan10", "address": "2001:db8:10::1/64"}]
    project.data["ipv6"]["static_routes"] = [{"prefix": "2001:db8:ffff::/64", "next_hop": "2001:db8:10::2"}]
    project.data["qos"]["class_maps"] = [{"name": "VOICE", "dscp": "ef"}]
    project.data["qos"]["policy_maps"] = [{"name": "WAN-QOS", "classes": [{"class_name": "VOICE", "bandwidth_percent": "30"}]}]
    project.data["qos"]["service_policies"] = [{"interface": "Vlan10", "direction": "output", "policy": "WAN-QOS"}]
    project.data["ha"]["groups"] = [{"protocol": "hsrp", "interface": "Vlan10", "group": "10", "virtual_ip": "10.10.0.254", "priority": "110", "preempt": True}]
    config = gen(project, profiles)
    assert "zone security INSIDE" in config
    assert "ipv6 unicast-routing" in config
    assert "ipv6 route 2001:db8:ffff::/64 2001:db8:10::2" in config
    assert "policy-map WAN-QOS" in config
    assert " standby 10 ip 10.10.0.254" in config
    assert is_valid_ipv6_interface("2001:db8:10::1/64")


def test_snmpv3_tacacs_radius_generation(project, profiles):
    project.data["system"]["aaa_new_model"] = True
    project.data["system"]["aaa_methods"]["login"] = "tacacs+ local"
    project.data["system"]["tacacs"]["servers"] = [{"name": "TAC1", "address": "10.0.0.10", "key": "abc"}]
    project.data["system"]["radius"]["servers"] = [{"name": "RAD1", "address": "10.0.0.11", "key": "abc"}]
    project.data["system"]["snmp"]["views"] = [{"name": "ROVIEW", "oid": "iso", "action": "included"}]
    project.data["system"]["snmp"]["groups"] = [{"name": "ROGROUP", "version": "v3 priv", "view": "ROVIEW"}]
    project.data["system"]["snmp"]["users"] = [{"username": "snmpadmin", "group": "ROGROUP", "auth_protocol": "sha", "auth_key": "authpass123", "priv_protocol": "aes 128", "priv_key": "privpass123"}]
    config = gen(project, profiles)
    assert "tacacs server TAC1" in config
    assert "radius server RAD1" in config
    assert "snmp-server group ROGROUP v3 priv read ROVIEW" in config
    assert "snmp-server user snmpadmin ROGROUP v3 auth sha authpass123 priv aes 128 privpass123" in config


def test_lint_template_deployment_and_custom_cli(project, profiles):
    config = "line vty 0 4\n transport input telnet\npermit ip any any\n"
    lint = lint_config(config, project, profiles[project.device_model])
    assert any(issue.category == "management" for issue in lint)
    template = load_template(Path("samples/templates/dmvpn_hub.json"))
    touched = apply_template(project, template)
    assert "tunnels" in touched
    report = deployment_checklist_markdown(project, profiles[project.device_model], gen(project, profiles))
    assert "Deployment Checklist" in report
    project.sections_enabled["custom_cli"] = True
    project.data["custom_cli"]["global"] = "service sequence-numbers"
    project.data["custom_cli"]["post_routing"] = "event manager environment CHECK yes"
    cfg = gen(project, profiles)
    assert cfg.index("service sequence-numbers") < cfg.index("interface Tunnel100")
    assert cfg.index("event manager environment CHECK yes") > cfg.index("interface Tunnel100")
    assert isinstance(optional_dependency_status(), dict)
