"""Validator tests: network primitives, section validators, platform checks."""

from ciscogen.validators import validate_project
from ciscogen.validators.network import (
    is_valid_cidr, is_valid_ipv4, is_valid_mask, is_valid_vlan,
    is_valid_wildcard, networks_overlap, ranges_overlap,
)


def issues_of(project, profiles, severity=None, section=None):
    issues = validate_project(project, profiles[project.device_model])
    if severity:
        issues = [i for i in issues if i.severity == severity]
    if section:
        issues = [i for i in issues if i.section == section]
    return issues


def has_message(issues, fragment):
    return any(fragment.lower() in i.message.lower() for i in issues)


# ----------------------------------------------------------- primitives --
def test_ipv4_validation():
    assert is_valid_ipv4("192.168.1.1")
    assert is_valid_ipv4("0.0.0.0")
    assert is_valid_ipv4("255.255.255.255")
    assert not is_valid_ipv4("256.1.1.1")
    assert not is_valid_ipv4("10.0.0")
    assert not is_valid_ipv4("10.0.0.0.1")
    assert not is_valid_ipv4("a.b.c.d")
    assert not is_valid_ipv4("")


def test_mask_validation():
    assert is_valid_mask("255.255.255.0")
    assert is_valid_mask("255.255.255.252")
    assert is_valid_mask("0.0.0.0")
    assert is_valid_mask("255.255.255.255")
    assert not is_valid_mask("255.0.255.0")     # non-contiguous
    assert not is_valid_mask("255.255.255.3")
    assert not is_valid_mask("hello")


def test_wildcard_validation():
    assert is_valid_wildcard("0.0.0.255")
    assert is_valid_wildcard("0.0.255.255")
    assert is_valid_wildcard("0.0.0.0")
    assert is_valid_wildcard("255.255.255.255")
    assert not is_valid_wildcard("0.255.0.255")  # non-contiguous
    assert not is_valid_wildcard("255.255.255.0")


def test_cidr_and_vlan():
    assert is_valid_cidr("24") and is_valid_cidr("/32") and is_valid_cidr(0)
    assert not is_valid_cidr("33") and not is_valid_cidr("x")
    assert is_valid_vlan(1) and is_valid_vlan("4094")
    assert not is_valid_vlan(0) and not is_valid_vlan("4095")
    assert not is_valid_vlan("abc")


def test_overlap_helpers():
    assert networks_overlap("10.0.0.0", "255.255.0.0",
                            "10.0.5.0", "255.255.255.0")
    assert not networks_overlap("10.0.0.0", "255.255.255.0",
                                "10.0.1.0", "255.255.255.0")
    assert ranges_overlap("10.0.0.1", "10.0.0.10", "10.0.0.5", "10.0.0.20")
    assert not ranges_overlap("10.0.0.1", "10.0.0.4", "10.0.0.5", "10.0.0.9")


# --------------------------------------------------------------- system --
def test_missing_hostname_and_secret(project, profiles):
    errors = issues_of(project, profiles, severity="error", section="system")
    assert has_message(errors, "hostname")
    warnings = issues_of(project, profiles, severity="warning",
                         section="system")
    assert has_message(warnings, "enable secret")


def test_ssh_without_domain_is_error(project, profiles):
    project.data["system"]["hostname"] = "R1"
    project.data["system"]["ssh_enabled"] = True
    project.data["system"]["domain_name"] = ""
    errors = issues_of(project, profiles, severity="error", section="system")
    assert has_message(errors, "domain name")


def test_empty_user_password(project, profiles):
    project.data["system"]["users"].append(
        {"username": "bob", "password": "", "privilege": "15"})
    errors = issues_of(project, profiles, severity="error", section="system")
    assert has_message(errors, "empty password")


def test_weak_credentials_warn(project, profiles):
    project.data["system"]["enable_secret"] = "cisco"
    warnings = issues_of(project, profiles, severity="warning",
                         section="system")
    assert has_message(warnings, "weak")


def test_default_snmp_community_warns(project, profiles):
    project.data["system"]["snmp"]["communities"].append(
        {"community": "public", "mode": "RO"})
    warnings = issues_of(project, profiles, severity="warning",
                         section="system")
    assert has_message(warnings, "well-known")


# ---------------------------------------------------------------- vlans --
def test_vlan_validator(project, profiles):
    project.sections_enabled["vlans"] = True
    project.data["vlans"]["vlans"] = [
        {"id": "10", "name": "A"},
        {"id": "10", "name": "B"},        # duplicate
        {"id": "5000", "name": "C"},      # out of range
        {"id": "1002", "name": "D"},      # reserved
    ]
    issues = issues_of(project, profiles, section="vlans")
    assert has_message(issues, "more than once")
    assert has_message(issues, "1-4094")
    assert has_message(issues, "reserved")


# ----------------------------------------------------------- interfaces --
def test_interface_validators(project, profiles):
    project.data["interfaces"]["physical"] = [
        {"name": "Gi1/0/1", "mode": "access"},              # no VLAN -> warn
        {"name": "Gi1/0/1", "mode": "access"},              # duplicate
        {"name": "Gi1/0/2", "mode": "trunk"},               # no native/allowed
        {"name": "Gi1/0/3", "mode": "routed", "ip": "10.0.0.1",
         "mask": "255.0.255.0"},                            # bad mask
        {"name": "Ethernet99/1", "mode": "access",
         "access_vlan": "10"},                              # unknown name
    ]
    issues = issues_of(project, profiles, section="interfaces")
    assert has_message(issues, "no access vlan")
    assert has_message(issues, "defined more than once")
    assert has_message(issues, "native")
    assert has_message(issues, "allows all vlans")
    assert has_message(issues, "valid subnet mask")
    assert has_message(issues, "port layout")


def test_duplicate_ip_detection(project, profiles):
    project.data["interfaces"]["physical"] = [
        {"name": "Gi1/0/1", "mode": "routed", "ip": "10.0.0.1",
         "mask": "255.255.255.0"},
    ]
    project.data["interfaces"]["svis"] = [
        {"vlan": "10", "ip": "10.0.0.1", "mask": "255.255.255.0"},
    ]
    errors = issues_of(project, profiles, severity="error",
                       section="interfaces")
    assert has_message(errors, "assigned to both")


# ----------------------------------------------------------------- routes --
def test_route_validator(project, profiles):
    project.sections_enabled["layer3"] = True
    project.data["layer3"]["static_routes"] = [
        {"prefix": "10.0.0.0", "mask": "255.255.255.0",
         "next_hop": "", "exit_interface": ""},                  # no NH
        {"prefix": "10.1.0.0", "mask": "255.255.0.0",
         "next_hop": "10.0.0.300"},                              # bad NH
        {"prefix": "10.2.0.0", "mask": "255.255.0.0",
         "next_hop": "10.0.0.2", "distance": "900"},             # bad AD
    ]
    errors = issues_of(project, profiles, severity="error", section="layer3")
    assert has_message(errors, "next hop or an exit interface")
    assert has_message(errors, "'10.0.0.300' is invalid")
    assert has_message(errors, "1-255")


# ------------------------------------------------------------------ dhcp --
def test_dhcp_pool_overlap(project, profiles):
    project.sections_enabled["dhcp"] = True
    project.data["dhcp"]["pools"] = [
        {"name": "A", "network": "10.0.0.0", "mask": "255.255.0.0",
         "default_router": "10.0.0.1"},
        {"name": "B", "network": "10.0.5.0", "mask": "255.255.255.0",
         "default_router": "10.0.5.1"},
    ]
    errors = issues_of(project, profiles, severity="error", section="dhcp")
    assert has_message(errors, "overlapping networks")


def test_dhcp_missing_router_and_excluded_overlap(project, profiles):
    project.sections_enabled["dhcp"] = True
    project.data["dhcp"]["pools"] = [
        {"name": "A", "network": "10.0.0.0", "mask": "255.255.255.0",
         "default_router": ""},
    ]
    project.data["dhcp"]["excluded"] = [
        {"start": "10.0.0.1", "end": "10.0.0.30"},
        {"start": "10.0.0.20", "end": "10.0.0.40"},
    ]
    issues = issues_of(project, profiles, section="dhcp")
    assert has_message(issues, "no default router")
    assert has_message(issues, "overlap")


# ------------------------------------------------------------------ acls --
def test_acl_dangerous_rule(project, profiles):
    project.sections_enabled["acls"] = True
    project.data["acls"]["acls"] = [{
        "type": "extended", "id": "100",
        "rules": [
            {"action": "permit", "protocol": "ip", "src": "any",
             "dst": "any"},
            {"action": "deny", "protocol": "tcp", "src": "any",
             "dst": "10.0.0.5", "dst_port_op": "eq", "dst_port": "23"},
        ],
    }]
    warnings = issues_of(project, profiles, severity="warning",
                         section="acls")
    assert has_message(warnings, "permit ip any any")
    assert has_message(warnings, "later rules are unreachable")


def test_acl_unknown_reference(project, profiles):
    project.sections_enabled["acls"] = True
    project.data["acls"]["vty_acl"] = "NOPE"
    warnings = issues_of(project, profiles, severity="warning",
                         section="acls")
    assert has_message(warnings, "not defined")


# ------------------------------------------------------------------- nat --
def test_nat_missing_inside_outside(profiles):
    from ciscogen.models import Project
    project = Project()
    project.device_model = "Cisco ISR 4331"
    project.sections_enabled["nat"] = True
    project.data["nat"]["static_rules"] = [
        {"inside_local": "10.0.0.5", "inside_global": "203.0.113.5"}]
    errors = issues_of(project, profiles, severity="error", section="nat")
    assert has_message(errors, "ip nat inside")
    assert has_message(errors, "ip nat outside")


# ----------------------------------------------------------------- ospf --
def test_ospf_network_missing_wildcard_or_area(project, profiles):
    project.sections_enabled["routing"] = True
    project.data["routing"]["ospf"].update({"enabled": True})
    project.data["routing"]["ospf"]["networks"] = [
        {"network": "10.0.0.0", "wildcard": "", "area": "0"},
        {"network": "10.1.0.0", "wildcard": "0.0.0.255", "area": ""},
    ]
    errors = issues_of(project, profiles, severity="error", section="routing")
    assert has_message(errors, "wildcard mask is missing")
    assert has_message(errors, "area is missing")


# -------------------------------------------------------------- platform --
def test_unsupported_features_flagged(profiles):
    from ciscogen.models import Project
    project = Project()
    project.device_model = "Catalyst 2960"
    project.sections_enabled.update({"nat": True, "routing": True,
                                     "vlans": True})
    project.data["nat"]["dynamic_enabled"] = True
    project.data["nat"]["dynamic_acl"] = "10"
    project.data["routing"]["ospf"]["enabled"] = True
    project.data["routing"]["ospf"]["networks"] = [
        {"network": "10.0.0.0", "wildcard": "0.0.0.255", "area": "0"}]
    project.data["vlans"]["dai"]["enabled"] = True
    project.data["vlans"]["dai"]["vlans"] = "10"
    issues = issues_of(project, profiles, section="platform")
    assert has_message(issues, "nat is not supported")
    assert has_message(issues, "ospf is not supported")
    # DAI is supported on the classic 2960 with LAN Base (Cisco 15.0(2)SE
    # config guide); the validator surfaces the image dependency instead.
    assert not has_message(issues, "dynamic arp inspection is not supported")
    assert has_message(issues, "lan base")


def test_routed_port_on_l2_switch_is_error(profiles):
    from ciscogen.models import Project
    project = Project()
    project.device_model = "Catalyst 2960"
    project.data["interfaces"]["physical"] = [
        {"name": "Gi0/1", "mode": "routed", "ip": "10.0.0.1",
         "mask": "255.255.255.0"}]
    errors = issues_of(project, profiles, severity="error",
                       section="platform")
    assert has_message(errors, "routed ports are not supported")


def test_unknown_os_version_warns(project, profiles):
    project.os_version = "99.9"
    warnings = issues_of(project, profiles, severity="warning",
                         section="platform")
    assert has_message(warnings, "not in the known list")
