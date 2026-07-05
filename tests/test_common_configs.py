"""Tests for the commonly-used config additions (DNS, SSH hardening,
login banner, DHCP static reservations)."""

from conftest import gen

from ciscogen.validators import validate_project


def messages(issues):
    return " | ".join(f"{i.severity}:{i.message}" for i in issues).lower()


def test_dns_name_servers(project, profiles):
    project.data["system"]["name_servers"] = "8.8.8.8, 1.1.1.1"
    config = gen(project, profiles)
    assert "ip name-server 8.8.8.8 1.1.1.1" in config


def test_invalid_name_server_errors(project, profiles):
    project.data["system"]["name_servers"] = "8.8.8.8, not-an-ip"
    issues = validate_project(project, profiles[project.device_model])
    assert "dns name-server 'not-an-ip'" in messages(issues)


def test_ssh_hardening(project, profiles):
    project.data["system"]["ssh_timeout"] = "90"
    project.data["system"]["ssh_auth_retries"] = "2"
    config = gen(project, profiles)
    assert "ip ssh time-out 90" in config
    assert "ip ssh authentication-retries 2" in config


def test_ssh_hardening_bounds(project, profiles):
    project.data["system"]["ssh_timeout"] = "999"
    issues = validate_project(project, profiles[project.device_model])
    assert "ssh timeout must be 1-120" in messages(issues)


def test_login_banner(project, profiles):
    project.data["system"]["banner_login"] = "Authorized users only"
    config = gen(project, profiles)
    assert "banner login ^" in config
    assert "Authorized users only" in config


def test_dhcp_static_binding_mac(project, profiles):
    project.sections_enabled["dhcp"] = True
    project.data["dhcp"]["static_bindings"] = [{
        "name": "PRINTER", "host_ip": "10.0.0.50", "mask": "255.255.255.0",
        "mac": "aabb.ccdd.eeff", "default_router": "10.0.0.1"}]
    config = gen(project, profiles)
    assert "ip dhcp pool PRINTER" in config
    assert " host 10.0.0.50 255.255.255.0" in config
    assert " hardware-address aabb.ccdd.eeff" in config
    assert " default-router 10.0.0.1" in config


def test_dhcp_static_binding_client_id(project, profiles):
    project.sections_enabled["dhcp"] = True
    project.data["dhcp"]["static_bindings"] = [{
        "name": "SRV", "host_ip": "10.0.0.60",
        "client_id": "0100.1122.3344.55"}]
    config = gen(project, profiles)
    assert " client-identifier 0100.1122.3344.55" in config
    assert "hardware-address" not in config


def test_dhcp_static_binding_needs_match(project, profiles):
    project.sections_enabled["dhcp"] = True
    project.data["dhcp"]["static_bindings"] = [{
        "name": "SRV", "host_ip": "10.0.0.60"}]
    issues = validate_project(project, profiles[project.device_model])
    assert "hardware-address) or client-identifier" in messages(issues)


def test_common_config_fields_reload(project, tmp_path, profiles):
    from ciscogen.models import Project
    project.data["system"]["name_servers"] = "8.8.8.8"
    project.data["system"]["ssh_timeout"] = "45"
    project.data["dhcp"]["static_bindings"] = [
        {"name": "A", "host_ip": "10.0.0.9", "mac": "aabb.ccdd.eeff"}]
    path = tmp_path / "p.json"
    project.save(path)
    loaded = Project.load(path)
    assert loaded.data["system"]["name_servers"] == "8.8.8.8"
    assert loaded.data["system"]["ssh_timeout"] == "45"
    assert loaded.data["dhcp"]["static_bindings"][0]["host_ip"] == "10.0.0.9"
