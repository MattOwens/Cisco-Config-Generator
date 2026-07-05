"""Generator tests: every section renders correct, well-ordered Cisco CLI."""

from conftest import gen


# ------------------------------------------------------------------ base --
def test_base_config(project, profiles):
    project.data["system"].update({
        "hostname": "SW1", "domain_name": "corp.local",
        "enable_secret": "Sup3rSecret!",
        "banner_motd": "Keep out",
    })
    project.data["system"]["users"].append(
        {"username": "admin", "password": "Passw0rd!23", "privilege": "15",
         "use_secret": True})
    config = gen(project, profiles)
    assert "hostname SW1" in config
    assert "ip domain-name corp.local" in config
    assert "enable secret Sup3rSecret!" in config
    assert "service password-encryption" in config
    assert "service timestamps log datetime msec" in config
    assert "no ip domain-lookup" in config
    assert "banner motd ^" in config and "Keep out" in config
    assert "crypto key generate rsa modulus 2048" in config
    assert "ip ssh version 2" in config
    assert "username admin privilege 15 secret Passw0rd!23" in config
    assert "line con 0" in config
    assert "line vty 0 15" in config
    assert " transport input ssh" in config
    assert config.rstrip().endswith("end")


def test_timestamps_disabled(project, profiles):
    project.data["system"]["timestamps"] = "disabled"
    config = gen(project, profiles)
    assert "no service timestamps debug" in config
    assert "no service timestamps log" in config


def test_username_password_variant(project, profiles):
    project.data["system"]["users"].append(
        {"username": "viewer", "password": "V1ewOnly!9", "privilege": "1",
         "use_secret": False})
    config = gen(project, profiles)
    assert "username viewer password V1ewOnly!9" in config


def test_ordering_of_sections(project, profiles):
    project.sections_enabled["vlans"] = True
    project.data["system"]["hostname"] = "SW1"
    project.data["vlans"]["vlans"] = [{"id": "10", "name": "USERS"}]
    project.data["interfaces"]["physical"] = [
        {"name": "Gi1/0/1", "mode": "access", "access_vlan": "10"}]
    config = gen(project, profiles)
    assert config.index("service timestamps") < config.index("hostname SW1")
    assert config.index("hostname SW1") < config.index("vlan 10")
    assert config.index("vlan 10") < config.index("interface GigabitEthernet1/0/1")
    assert config.index("interface") < config.index("line con 0")


# ----------------------------------------------------------------- vlans --
def test_vlan_generation(project, profiles):
    project.sections_enabled["vlans"] = True
    project.data["vlans"]["vlans"] = [
        {"id": "10", "name": "USERS"}, {"id": "20", "name": "VOICE VLAN"}]
    project.data["vlans"]["blackhole_vlan"] = "999"
    project.data["vlans"]["stp"].update(
        {"mode": "rapid-pvst", "portfast_default": True,
         "bpduguard_default": True, "root_primary": "10, 20"})
    config = gen(project, profiles)
    assert "vlan 10\n name USERS" in config
    assert "vlan 20\n name VOICE_VLAN" in config
    assert "vlan 999\n name BLACKHOLE-UNUSED" in config
    assert "spanning-tree mode rapid-pvst" in config
    assert "spanning-tree portfast default" in config
    assert "spanning-tree portfast bpduguard default" in config
    assert "spanning-tree vlan 10,20 root primary" in config


# ------------------------------------------------------------ interfaces --
def test_access_interface(project, profiles):
    project.data["interfaces"]["physical"] = [{
        "name": "gi1/0/5", "mode": "access", "access_vlan": "10",
        "voice_vlan": "20", "description": "Desk port", "portfast": True,
        "bpduguard": True, "ps_enabled": True, "ps_max": "2",
        "ps_violation": "restrict", "ps_sticky": True, "storm_bc": "5.00",
        "enabled": True,
    }]
    config = gen(project, profiles)
    block = config[config.index("interface GigabitEthernet1/0/5"):]
    assert " description Desk port" in block
    assert " switchport mode access" in block
    assert " switchport access vlan 10" in block
    assert " switchport voice vlan 20" in block
    assert " spanning-tree portfast" in block
    assert " spanning-tree bpduguard enable" in block
    assert " storm-control broadcast level 5.00" in block
    assert " switchport port-security\n" in block
    assert " switchport port-security maximum 2" in block
    assert " switchport port-security violation restrict" in block
    assert " switchport port-security mac-address sticky" in block
    assert " no shutdown" in block


def test_trunk_interface_and_encap(profiles):
    from ciscogen.models import Project
    for model, expect_encap in (("Catalyst 3560", True),
                                ("Catalyst 9300", False)):
        project = Project()
        project.device_model = model
        name = "Fa0/1" if model == "Catalyst 3560" else "Gi1/0/1"
        project.data["interfaces"]["physical"] = [{
            "name": name, "mode": "trunk", "native_vlan": "99",
            "allowed_vlans": "10,20,99", "nonegotiate": True,
        }]
        config = gen(project, profiles)
        assert " switchport mode trunk" in config
        assert " switchport trunk native vlan 99" in config
        assert " switchport trunk allowed vlan 10,20,99" in config
        assert " switchport nonegotiate" in config
        assert (" switchport trunk encapsulation dot1q" in config) is expect_encap


def test_routed_interface_on_switch_and_router(profiles):
    from ciscogen.models import Project
    project = Project()
    project.device_model = "Catalyst 9300"
    project.data["interfaces"]["physical"] = [{
        "name": "Te1/1/1", "mode": "routed", "ip": "10.0.12.1",
        "mask": "255.255.255.252",
    }]
    config = gen(project, profiles)
    assert " no switchport" in config
    assert " ip address 10.0.12.1 255.255.255.252" in config

    project = Project()
    project.device_model = "Cisco ISR 4331"
    project.data["interfaces"]["physical"] = [{
        "name": "Gi0/0/0", "mode": "routed", "ip": "203.0.113.1",
        "mask": "255.255.255.0", "helper": "10.0.0.5",
    }]
    config = gen(project, profiles)
    assert " no switchport" not in config
    assert " ip address 203.0.113.1 255.255.255.0" in config
    assert " ip helper-address 10.0.0.5" in config


def test_svi_generation(project, profiles):
    project.data["interfaces"]["svis"] = [{
        "vlan": "10", "description": "Users", "ip": "10.10.0.1",
        "mask": "255.255.255.0", "helper": "10.30.0.5, 10.30.0.6",
        "enabled": True,
    }]
    config = gen(project, profiles)
    block = config[config.index("interface Vlan10"):]
    assert " ip address 10.10.0.1 255.255.255.0" in block
    assert " ip helper-address 10.30.0.5" in block
    assert " ip helper-address 10.30.0.6" in block
    assert " no shutdown" in block


def test_subinterface_router_on_a_stick(profiles):
    from ciscogen.models import Project
    project = Project()
    project.device_model = "Cisco 2911"
    project.data["interfaces"]["subinterfaces"] = [
        {"parent": "gi0/0", "vlan": "10", "ip": "10.10.0.1",
         "mask": "255.255.255.0", "description": "Users"},
        {"parent": "gi0/0", "vlan": "99", "ip": "10.99.0.1",
         "mask": "255.255.255.0", "native": True},
    ]
    config = gen(project, profiles)
    assert "interface GigabitEthernet0/0.10" in config
    assert " encapsulation dot1Q 10" in config
    assert "interface GigabitEthernet0/0.99" in config
    assert " encapsulation dot1Q 99 native" in config


def test_etherchannel(project, profiles):
    project.data["interfaces"]["physical"] = [
        {"name": "Gi1/0/47", "mode": "trunk", "channel_group": "1",
         "channel_mode": "active"},
    ]
    project.data["interfaces"]["port_channels"] = [
        {"id": "1", "mode": "trunk", "native_vlan": "99",
         "allowed_vlans": "10,99", "description": "Uplink"},
    ]
    config = gen(project, profiles)
    assert " channel-group 1 mode active" in config
    assert "interface Port-channel1" in config


# ---------------------------------------------------------- static routes --
def test_static_route_generation(project, profiles):
    project.sections_enabled["layer3"] = True
    project.data["layer3"]["static_routes"] = [
        {"prefix": "0.0.0.0", "mask": "0.0.0.0", "next_hop": "10.0.0.1"},
        {"prefix": "172.16.0.0", "mask": "255.255.0.0",
         "next_hop": "10.0.0.2", "distance": "250", "name": "BACKUP",
         "permanent": True},
        {"prefix": "192.168.5.0", "mask": "255.255.255.0",
         "exit_interface": "gi1/0/1", "next_hop": ""},
    ]
    config = gen(project, profiles)
    assert "ip route 0.0.0.0 0.0.0.0 10.0.0.1" in config
    assert "ip route 172.16.0.0 255.255.0.0 10.0.0.2 250 name BACKUP permanent" in config
    assert "ip route 192.168.5.0 255.255.255.0 GigabitEthernet1/0/1" in config
    assert "ip routing" in config  # L3 switch


def test_default_gateway_for_l2_switch(profiles):
    from ciscogen.models import Project
    project = Project()
    project.device_model = "Catalyst 2960"
    project.data["system"]["default_gateway"] = "10.99.0.1"
    config = gen(project, profiles)
    assert "ip default-gateway 10.99.0.1" in config


# ------------------------------------------------------------------ dhcp --
def test_dhcp_generation(project, profiles):
    project.sections_enabled["dhcp"] = True
    project.data["dhcp"]["excluded"] = [
        {"start": "10.10.0.1", "end": "10.10.0.10"},
        {"start": "10.10.0.255", "end": ""},
    ]
    project.data["dhcp"]["pools"] = [{
        "name": "USERS", "network": "10.10.0.0", "mask": "255.255.255.0",
        "default_router": "10.10.0.1", "dns": "8.8.8.8, 8.8.4.4",
        "domain": "corp.local", "lease_days": "7", "option150": "10.5.5.5",
    }]
    config = gen(project, profiles)
    assert "ip dhcp excluded-address 10.10.0.1 10.10.0.10" in config
    assert "ip dhcp excluded-address 10.10.0.255\n" in config
    assert "ip dhcp pool USERS" in config
    assert " network 10.10.0.0 255.255.255.0" in config
    assert " default-router 10.10.0.1" in config
    assert " dns-server 8.8.8.8 8.8.4.4" in config
    assert " domain-name corp.local" in config
    assert " lease 7" in config
    assert " option 150 ip 10.5.5.5" in config


# ------------------------------------------------------------------ acls --
def test_acl_generation(project, profiles):
    project.sections_enabled["acls"] = True
    project.data["acls"]["acls"] = [
        {"type": "standard", "id": "10", "rules": [
            {"action": "remark", "remark": "mgmt subnet"},
            {"action": "permit", "src": "10.99.0.0",
             "src_wildcard": "0.0.0.255"},
            {"action": "deny", "src": "any"},
        ]},
        {"type": "extended", "id": "WEB-IN", "rules": [
            {"action": "permit", "protocol": "tcp", "src": "any",
             "dst": "10.0.0.80", "dst_port_op": "eq", "dst_port": "443"},
            {"action": "permit", "protocol": "tcp", "src": "any",
             "dst": "any", "established": True},
            {"action": "permit", "protocol": "icmp", "src": "10.0.0.0",
             "src_wildcard": "0.0.255.255", "dst": "any",
             "icmp_type": "echo"},
            {"action": "deny", "protocol": "ip", "src": "any", "dst": "any",
             "log": True},
        ]},
    ]
    project.data["acls"]["interface_apply"] = [
        {"acl": "WEB-IN", "interface": "gi1/0/10", "direction": "in"}]
    project.data["acls"]["vty_acl"] = "10"
    config = gen(project, profiles)
    assert "access-list 10 remark mgmt subnet" in config
    assert "access-list 10 permit 10.99.0.0 0.0.0.255" in config
    assert "access-list 10 deny any" in config
    assert "ip access-list extended WEB-IN" in config
    assert " permit tcp any host 10.0.0.80 eq 443" in config
    assert " permit tcp any any established" in config
    assert " permit icmp 10.0.0.0 0.0.255.255 any echo" in config
    assert " deny ip any any log" in config
    # binding merged into standalone interface block
    assert "interface GigabitEthernet1/0/10" in config
    assert " ip access-group WEB-IN in" in config
    assert " access-class 10 in" in config
    # rule order preserved
    assert config.index("permit tcp any host 10.0.0.80") < \
        config.index("permit tcp any any established")


# ------------------------------------------------------------------- nat --
def test_nat_generation(profiles):
    from ciscogen.models import Project
    project = Project()
    project.device_model = "Cisco ISR 4331"
    project.sections_enabled["nat"] = True
    project.data["interfaces"]["physical"] = [
        {"name": "Gi0/0/0", "mode": "routed", "ip": "203.0.113.2",
         "mask": "255.255.255.0"},
        {"name": "Gi0/0/1", "mode": "routed", "ip": "10.0.0.1",
         "mask": "255.255.255.0"},
    ]
    project.data["nat"].update({
        "inside_interfaces": "Gi0/0/1",
        "outside_interfaces": "Gi0/0/0",
        "static_rules": [{"inside_local": "10.0.0.5",
                          "inside_global": "203.0.113.5"},
                         {"inside_local": "10.0.0.8", "protocol": "tcp",
                          "local_port": "8080", "global_port": "80",
                          "inside_global": "203.0.113.8"}],
        "dynamic_enabled": True, "dynamic_acl": "NAT-SOURCES",
        "use_pool": True, "pool_name": "PUBLIC",
        "pool_start": "203.0.113.10", "pool_end": "203.0.113.20",
        "pool_mask": "255.255.255.0", "overload": True,
    })
    config = gen(project, profiles)
    assert "ip nat inside source static 10.0.0.5 203.0.113.5" in config
    assert "ip nat inside source static tcp 10.0.0.8 8080 203.0.113.8 80" in config
    assert "ip nat pool PUBLIC 203.0.113.10 203.0.113.20 netmask 255.255.255.0" in config
    assert "ip nat inside source list NAT-SOURCES pool PUBLIC overload" in config
    # inside/outside merged into the defined interface blocks
    inside_block = config[config.index("interface GigabitEthernet0/0/1"):]
    assert " ip nat inside" in inside_block.split("!")[0]
    outside_block = config[config.index("interface GigabitEthernet0/0/0"):]
    assert " ip nat outside" in outside_block.split("!")[0]


def test_nat_interface_pat(profiles):
    from ciscogen.models import Project
    project = Project()
    project.device_model = "Cisco ISR 4331"
    project.sections_enabled["nat"] = True
    project.data["nat"].update({
        "inside_interfaces": "Gi0/0/1", "outside_interfaces": "Gi0/0/0",
        "dynamic_enabled": True, "dynamic_acl": "10", "use_pool": False,
        "overload_interface": "Gi0/0/0",
    })
    config = gen(project, profiles)
    assert ("ip nat inside source list 10 interface "
            "GigabitEthernet0/0/0 overload") in config


# --------------------------------------------------------------- routing --
def test_ospf_generation(project, profiles):
    project.sections_enabled["routing"] = True
    project.data["routing"]["ospf"].update({
        "enabled": True, "process_id": "10", "router_id": "1.1.1.1",
        "passive_default": True, "passive_interfaces": "Vlan99",
        "default_originate": True, "redistribute_static": True,
        "area_auth_area": "0",
    })
    project.data["routing"]["ospf"]["networks"] = [
        {"network": "10.0.0.0", "wildcard": "0.0.255.255", "area": "0"}]
    config = gen(project, profiles)
    assert "router ospf 10" in config
    assert " router-id 1.1.1.1" in config
    assert " passive-interface default" in config
    assert " no passive-interface Vlan99" in config
    assert " network 10.0.0.0 0.0.255.255 area 0" in config
    assert " area 0 authentication message-digest" in config
    assert " redistribute static subnets" in config
    assert " default-information originate" in config


def test_eigrp_bgp_rip_generation(profiles):
    from ciscogen.models import Project
    project = Project()
    project.device_model = "Cisco ISR 4331"
    project.sections_enabled["routing"] = True
    routing = project.data["routing"]
    routing["eigrp"].update({"enabled": True, "asn": "100",
                             "router_id": "2.2.2.2",
                             "passive_interfaces": "Gi0/0/2"})
    routing["eigrp"]["networks"] = [
        {"network": "10.0.0.0", "wildcard": "0.0.0.255"},
        {"network": "192.168.1.0", "wildcard": ""}]
    routing["bgp"].update({"enabled": True, "asn": "65001",
                           "router_id": "3.3.3.3"})
    routing["bgp"]["neighbors"] = [
        {"ip": "203.0.113.1", "remote_as": "65000",
         "description": "ISP uplink", "update_source": "lo0",
         "ebgp_multihop": "2"}]
    routing["bgp"]["networks"] = [
        {"network": "198.51.100.0", "mask": "255.255.255.0"}]
    routing["rip"].update({"enabled": True, "networks": "10.0.0.0",
                           "passive_interfaces": "Gi0/0/1"})
    config = gen(project, profiles)
    assert "router eigrp 100" in config
    assert " eigrp router-id 2.2.2.2" in config
    assert " network 10.0.0.0 0.0.0.255" in config
    assert " network 192.168.1.0\n" in config
    assert " no auto-summary" in config
    assert " passive-interface GigabitEthernet0/0/2" in config
    assert "router bgp 65001" in config
    assert " bgp router-id 3.3.3.3" in config
    assert " neighbor 203.0.113.1 remote-as 65000" in config
    assert " neighbor 203.0.113.1 description ISP uplink" in config
    assert " neighbor 203.0.113.1 update-source Loopback0" in config
    assert " neighbor 203.0.113.1 ebgp-multihop 2" in config
    assert " network 198.51.100.0 mask 255.255.255.0" in config
    assert "router rip" in config
    assert " version 2" in config


# -------------------------------------------------------------- security --
def test_security_hardening(project, profiles):
    project.sections_enabled["security"] = True
    project.data["security"].update({
        "login_block_enabled": True, "min_password_length": "12",
    })
    project.data["system"]["vty"]["transport"] = "ssh telnet"
    config = gen(project, profiles)
    assert "no ip http server" in config
    assert "no ip http secure-server" in config
    assert "no service tcp-small-servers" in config
    assert "no service pad" in config
    assert "no ip source-route" in config
    assert "service tcp-keepalives-in" in config
    assert "login block-for 120 attempts 3 within 60" in config
    assert "security passwords min-length 12" in config
    # ssh_only forces SSH transport even though system form allows telnet
    assert " transport input ssh\n" in config
    assert " transport input ssh telnet" not in config


# ------------------------------------------------------------------ misc --
def test_misc_generation(project, profiles):
    project.sections_enabled["misc"] = True
    project.data["misc"].update({
        "cdp_run": False, "lldp_run": True,
        "clock_timezone_name": "PST", "clock_timezone_hours": "-8",
        "archive_enabled": True,
    })
    config = gen(project, profiles)
    assert "no cdp run" in config
    assert "lldp run" in config
    assert "clock timezone PST -8 0" in config
    assert "archive\n path flash:archive\n write-memory\n time-period 1440" in config


def test_per_interface_cdp_lldp(project, profiles):
    project.data["interfaces"]["physical"] = [
        {"name": "Gi1/0/1", "mode": "access", "access_vlan": "10",
         "cdp_disabled": True, "lldp_disabled": True}]
    config = gen(project, profiles)
    assert " no cdp enable" in config
    assert " no lldp transmit" in config
    assert " no lldp receive" in config


# ----------------------------------------------------------- orchestrator --
def test_no_duplicate_global_commands(project, profiles):
    project.sections_enabled["layer3"] = True
    project.data["system"]["default_route"] = "10.0.0.1"
    project.data["layer3"]["static_routes"] = [
        {"prefix": "0.0.0.0", "mask": "0.0.0.0", "next_hop": "10.0.0.1"}]
    config = gen(project, profiles)
    assert config.count("ip route 0.0.0.0 0.0.0.0 10.0.0.1") == 1


def test_include_comments_option(project, profiles):
    project.data["system"]["hostname"] = "SW1"
    config = gen(project, profiles)
    assert "! ---" not in config
    project.options["include_comments"] = True
    config = gen(project, profiles)
    assert "! --- Identity & security basics ---" in config


def test_disabled_sections_not_rendered(project, profiles):
    project.sections_enabled["dhcp"] = False
    project.data["dhcp"]["pools"] = [{
        "name": "HIDDEN", "network": "10.0.0.0", "mask": "255.255.255.0",
        "default_router": "10.0.0.1"}]
    config = gen(project, profiles)
    assert "HIDDEN" not in config
