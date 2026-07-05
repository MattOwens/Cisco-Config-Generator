"""Project save/load round-trips and the bundled sample project."""

from pathlib import Path

from conftest import gen

from ciscogen.models import Project
from ciscogen.utils import expand_interface_range, normalize_interface_name

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "sample_project.json"


def test_save_load_roundtrip(tmp_path, project, profiles):
    project.data["system"]["hostname"] = "ROUNDTRIP"
    project.sections_enabled["dhcp"] = True
    project.data["dhcp"]["pools"].append({
        "name": "P1", "network": "10.1.0.0", "mask": "255.255.255.0",
        "default_router": "10.1.0.1"})
    project.options["include_comments"] = True
    project.last_generated = gen(project, profiles)
    project.edited_config = project.last_generated + "! manual edit\n"

    path = tmp_path / "proj.json"
    project.save(path)
    loaded = Project.load(path)

    assert loaded.device_model == project.device_model
    assert loaded.os_version == project.os_version
    assert loaded.sections_enabled == project.sections_enabled
    assert loaded.data["system"]["hostname"] == "ROUNDTRIP"
    assert loaded.data["dhcp"]["pools"][0]["name"] == "P1"
    assert loaded.options["include_comments"] is True
    assert loaded.last_generated == project.last_generated
    assert loaded.edited_config.endswith("! manual edit\n")


def test_load_merges_missing_keys(tmp_path, project):
    """Older project files without newer keys still load with defaults."""
    path = tmp_path / "old.json"
    path.write_text('{"device": {"model": "Catalyst 9300"}, '
                    '"data": {"system": {"hostname": "OLD"}}}',
                    encoding="utf-8")
    loaded = Project.load(path)
    assert loaded.data["system"]["hostname"] == "OLD"
    assert loaded.data["system"]["vty"]["transport"] == "ssh"
    assert loaded.data["nat"]["overload"] is True


def test_sample_project_loads_and_generates(profiles):
    project = Project.load(SAMPLE)
    assert project.device_model in profiles
    config = gen(project, profiles)
    assert "hostname SW-ACCESS-01" in config
    assert "router ospf 1" in config
    assert "ip dhcp pool USERS" in config
    assert "interface Port-channel1" in config
    # The bundled sample must be free of validation errors.
    assert all(w["severity"] != "error" for w in project.warnings)


def test_interface_name_helpers():
    assert normalize_interface_name("gi1/0/1") == "GigabitEthernet1/0/1"
    assert normalize_interface_name("Gig1/0/2") == "GigabitEthernet1/0/2"
    assert normalize_interface_name("fa0/1") == "FastEthernet0/1"
    assert normalize_interface_name("te1/1/1") == "TenGigabitEthernet1/1/1"
    assert normalize_interface_name("twe1/0/1") == "TwentyFiveGigE1/0/1"
    assert normalize_interface_name("po1") == "Port-channel1"
    assert normalize_interface_name("port-channel2") == "Port-channel2"
    assert normalize_interface_name("vlan10") == "Vlan10"
    assert normalize_interface_name("lo0") == "Loopback0"
    assert normalize_interface_name("GigabitEthernet0/0.10") == \
        "GigabitEthernet0/0.10"
    assert expand_interface_range("Gi1/0/1-4") == [
        "Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4"]
    assert expand_interface_range("Gi1/0/5") == ["Gi1/0/5"]
