"""Tests for the IP Tunnels & VPN section (Phase 2 refactor)."""

from conftest import gen

from ciscogen.models import Project, default_tunnel
from ciscogen.validators import validate_project


def messages(issues):
    return " | ".join(f"{i.severity}:{i.message}" for i in issues).lower()


def isr(model="Cisco ISR 4331"):
    p = Project()
    p.device_model = model
    p.os_type = "IOS-XE"
    p.os_version = "17.6"
    p.sections_enabled["tunnels"] = True
    return p


# --------------------------------------------------------------- migration
def test_legacy_dmvpn_migrates_to_tunnels():
    old = {
        "device": {"model": "Cisco ISR 4331", "os_type": "IOS-XE",
                   "os_version": "17.6"},
        "sections_enabled": {"dmvpn": True},
        "data": {"dmvpn": {
            "enabled": True, "role": "Hub", "phase": "Phase 3",
            "tunnel_number": "100", "tunnel_ip": "10.255.0.1",
            "tunnel_mask": "255.255.255.0",
            "tunnel_source_interface": "Gi0/0/0", "nhrp_network_id": "100",
            "ipsec_enabled": True, "pre_shared_key": "Str0ngKey!x99"}},
    }
    p = Project.from_dict(old)
    assert p.sections_enabled["tunnels"] is True
    assert p.sections_enabled["dmvpn"] is False
    assert p.data["dmvpn"]["enabled"] is False        # prevents double-gen
    tunnels = p.data["tunnels"]["tunnels"]
    assert len(tunnels) == 1
    assert tunnels[0]["type"] == "GRE multipoint (DMVPN)"
    assert tunnels[0]["nhrp_network_id"] == "100"


def test_migration_is_idempotent():
    old = {
        "device": {"model": "Cisco ISR 4331"},
        "sections_enabled": {"dmvpn": True},
        "data": {"dmvpn": {"enabled": True, "tunnel_number": "100",
                           "nhrp_network_id": "100"}},
    }
    p1 = Project.from_dict(old)
    # Reload the saved dict: dmvpn now disabled, tunnel already present.
    p2 = Project.from_dict(p1.to_dict())
    assert len(p2.data["tunnels"]["tunnels"]) == 1


# --------------------------------------------------------------- generation
def test_gre_point_to_point_generation():
    p = isr()
    t = default_tunnel("GRE point-to-point")
    t.update(name="GRE0", tunnel_number="0", tunnel_ip="10.0.0.1",
             tunnel_mask="255.255.255.252",
             tunnel_source_interface="Gi0/0/0",
             tunnel_destination="203.0.113.9", keepalive="10 3")
    p.data["tunnels"]["tunnels"] = [t]
    from ciscogen.profiles import load_profiles
    config = gen(p, load_profiles())
    assert "interface Tunnel0" in config
    assert " ip address 10.0.0.1 255.255.255.252" in config
    assert " tunnel source GigabitEthernet0/0/0" in config
    assert " tunnel destination 203.0.113.9" in config
    assert " keepalive 10 3" in config
    assert "tunnel mode gre multipoint" not in config    # p2p uses default
    assert "tunnel mode ipsec" not in config


def test_dmvpn_hub_generation(profiles):
    p = isr()
    t = default_tunnel("GRE multipoint (DMVPN)")
    t.update(name="DMVPN", tunnel_number="100", role="Hub", phase="Phase 3",
             tunnel_ip="10.255.0.1", tunnel_mask="255.255.255.0",
             tunnel_source_interface="Gi0/0/0", nhrp_network_id="100",
             ipsec_enabled=True, pre_shared_key="Str0ngKey!x99")
    p.data["tunnels"]["tunnels"] = [t]
    config = gen(p, profiles)
    assert "interface Tunnel100" in config
    assert " tunnel mode gre multipoint" in config
    assert " ip nhrp network-id 100" in config
    assert " ip nhrp redirect" in config
    assert " tunnel protection ipsec profile TUNNEL-IPSEC-PROFILE-100" in config
    assert "crypto ikev2 profile TUNNEL-IKEV2-PROFILE-100" in config


def test_dmvpn_spoke_generation(profiles):
    p = isr()
    t = default_tunnel("GRE multipoint (DMVPN)")
    t.update(name="SPOKE", tunnel_number="100", role="Spoke", phase="Phase 3",
             tunnel_ip="10.255.0.11", tunnel_mask="255.255.255.0",
             tunnel_source_interface="Gi0/0/0", nhrp_network_id="100")
    t["nhrp_nhs"] = [{"address": "10.255.0.1", "nbma": "203.0.113.10"}]
    p.data["tunnels"]["tunnels"] = [t]
    config = gen(p, profiles)
    assert " ip nhrp nhs 10.255.0.1" in config
    assert " ip nhrp map 10.255.0.1 203.0.113.10" in config
    assert " ip nhrp shortcut" in config


def test_static_vti_generation(profiles):
    p = isr()
    t = default_tunnel("Static VTI")
    t.update(name="VTI1", tunnel_number="1", tunnel_ip="10.1.0.1",
             tunnel_mask="255.255.255.252",
             tunnel_source_interface="Gi0/0/0",
             tunnel_destination="198.51.100.9", ipsec_enabled=True,
             pre_shared_key="Str0ngKey!x99")
    p.data["tunnels"]["tunnels"] = [t]
    config = gen(p, profiles)
    assert "interface Tunnel1" in config
    assert " tunnel mode ipsec ipv4" in config
    assert " tunnel destination 198.51.100.9" in config
    assert " tunnel protection ipsec profile TUNNEL-IPSEC-PROFILE-1" in config


def test_multiple_encrypted_tunnels_do_not_collide(profiles):
    p = isr()
    dm = default_tunnel("GRE multipoint (DMVPN)")
    dm.update(name="DM", tunnel_number="100", tunnel_ip="10.255.0.1",
              tunnel_mask="255.255.255.0", tunnel_source_interface="Gi0/0/0",
              nhrp_network_id="100", ipsec_enabled=True,
              pre_shared_key="Str0ngKey!x99")
    vti = default_tunnel("Static VTI")
    vti.update(name="VTI", tunnel_number="1", tunnel_ip="10.1.0.1",
               tunnel_mask="255.255.255.252",
               tunnel_source_interface="Gi0/0/0",
               tunnel_destination="198.51.100.9", ipsec_enabled=True,
               pre_shared_key="Str0ngKey!x99")
    p.data["tunnels"]["tunnels"] = [dm, vti]
    config = gen(p, profiles)
    # Each tunnel gets its own crypto objects (match full lines to avoid
    # PROFILE-1 matching inside PROFILE-100).
    assert "crypto ipsec profile TUNNEL-IPSEC-PROFILE-100\n" in config
    assert "crypto ipsec profile TUNNEL-IPSEC-PROFILE-1\n" in config
    # No crypto block bleeds into another (proposal lines belong to a header).
    assert "TUNNEL-IPSEC-PROFILE-100\n encryption" not in config
    assert "TUNNEL-IPSEC-PROFILE-1\n encryption" not in config


def test_routing_over_tunnel_generation(profiles):
    p = isr()
    t = default_tunnel("GRE multipoint (DMVPN)")
    t.update(name="DM", tunnel_number="100", role="Hub",
             tunnel_ip="10.255.0.1", tunnel_mask="255.255.255.0",
             tunnel_source_interface="Gi0/0/0", nhrp_network_id="100")
    t["routing"]["eigrp"].update(enabled=True, asn="100")
    t["routing"]["eigrp"]["networks"] = [
        {"network": "10.255.0.0", "wildcard": "0.0.0.255"}]
    p.data["tunnels"]["tunnels"] = [t]
    config = gen(p, profiles)
    assert " ip ospf" not in config
    assert "router eigrp 100" in config
    assert " network 10.255.0.0 0.0.0.255" in config
    assert " no ip split-horizon eigrp 100" in config


# --------------------------------------------------------------- validation
def test_missing_tunnel_source_warns(profiles):
    p = isr()
    t = default_tunnel("GRE point-to-point")
    t.update(name="G", tunnel_number="0", tunnel_ip="10.0.0.1",
             tunnel_mask="255.255.255.252", tunnel_destination="1.1.1.1")
    p.data["tunnels"]["tunnels"] = [t]
    issues = validate_project(p, profiles[p.device_model])
    assert "tunnel source is missing" in messages(issues)


def test_missing_nhrp_warns(profiles):
    p = isr()
    t = default_tunnel("GRE multipoint (DMVPN)")
    t.update(name="DM", tunnel_number="100", tunnel_ip="10.255.0.1",
             tunnel_mask="255.255.255.0", tunnel_source_interface="Gi0/0/0")
    p.data["tunnels"]["tunnels"] = [t]
    issues = validate_project(p, profiles[p.device_model])
    assert "nhrp network id is missing" in messages(issues)


def test_missing_psk_warns(profiles):
    p = isr()
    t = default_tunnel("Static VTI")
    t.update(name="VTI", tunnel_number="1", tunnel_ip="10.1.0.1",
             tunnel_mask="255.255.255.252",
             tunnel_source_interface="Gi0/0/0",
             tunnel_destination="1.1.1.1", ipsec_enabled=True,
             pre_shared_key="")
    p.data["tunnels"]["tunnels"] = [t]
    issues = validate_project(p, profiles[p.device_model])
    assert "pre-shared key is empty" in messages(issues)


def test_missing_destination_on_vti_warns(profiles):
    p = isr()
    t = default_tunnel("Static VTI")
    t.update(name="VTI", tunnel_number="1", tunnel_ip="10.1.0.1",
             tunnel_mask="255.255.255.252",
             tunnel_source_interface="Gi0/0/0", ipsec_enabled=True,
             pre_shared_key="Str0ngKey!x99")
    p.data["tunnels"]["tunnels"] = [t]
    issues = validate_project(p, profiles[p.device_model])
    assert "requires a tunnel destination" in messages(issues)


def test_unsupported_tunnel_on_l2_switch_warns(profiles):
    p = Project()
    p.device_model = "Catalyst 2960"
    p.os_type = "IOS"
    p.os_version = "15.2"
    p.sections_enabled["tunnels"] = True
    t = default_tunnel("Static VTI")
    t.update(name="VTI", tunnel_number="1", tunnel_ip="10.1.0.1",
             tunnel_mask="255.255.255.252",
             tunnel_source_interface="Gi0/1",
             tunnel_destination="1.1.1.1", ipsec_enabled=True,
             pre_shared_key="Str0ngKey!x99")
    p.data["tunnels"]["tunnels"] = [t]
    issues = validate_project(p, profiles["Catalyst 2960"])
    text = messages(issues)
    assert "vti" in text and "does not list" in text


def test_duplicate_tunnel_number_is_error(profiles):
    p = isr()
    a = default_tunnel("GRE point-to-point")
    a.update(name="A", tunnel_number="5", tunnel_ip="10.0.0.1",
             tunnel_mask="255.255.255.252", tunnel_source_interface="Gi0/0/0",
             tunnel_destination="1.1.1.1")
    b = default_tunnel("GRE point-to-point")
    b.update(name="B", tunnel_number="5", tunnel_ip="10.0.1.1",
             tunnel_mask="255.255.255.252", tunnel_source_interface="Gi0/0/0",
             tunnel_destination="2.2.2.2")
    p.data["tunnels"]["tunnels"] = [a, b]
    issues = validate_project(p, profiles[p.device_model])
    assert "tunnel5 is defined" in messages(issues)


def test_disabled_tunnel_not_generated(profiles):
    p = isr()
    t = default_tunnel("GRE point-to-point")
    t.update(name="OFF", tunnel_number="9", enabled=False,
             tunnel_ip="10.0.0.1", tunnel_mask="255.255.255.252",
             tunnel_source_interface="Gi0/0/0", tunnel_destination="1.1.1.1")
    p.data["tunnels"]["tunnels"] = [t]
    config = gen(p, profiles)
    assert "interface Tunnel9" not in config
