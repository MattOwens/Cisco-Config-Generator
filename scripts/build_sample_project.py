"""Build samples/sample_project.json - a realistic Catalyst 9300 access
switch project - using the real Project model and generators so the file
always matches the current schema.

Run from the repository root:  python scripts/build_sample_project.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ciscogen.generators import generate_config          # noqa: E402
from ciscogen.models import Project                      # noqa: E402
from ciscogen.profiles import load_profiles              # noqa: E402
from ciscogen.validators import validate_project         # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "samples" / "sample_project.json"


def build() -> Project:
    project = Project()
    project.device_model = "Catalyst 9300"
    project.os_type = "IOS-XE"
    project.os_version = "17.9"
    project.sections_enabled.update({
        "system": True, "interfaces": True, "vlans": True, "layer3": True,
        "dhcp": True, "acls": True, "routing": True, "security": True,
        "misc": True, "nat": False,
    })

    sys_data = project.data["system"]
    sys_data.update({
        "hostname": "SW-ACCESS-01",
        "domain_name": "corp.example.local",
        "enable_secret": "S3cure-Enable!24",
        "banner_motd": "Unauthorized access is prohibited.\n"
                       "All activity is monitored and logged.",
        "logging_hosts": "10.99.0.100",
        "ntp_servers": "10.99.0.1, 10.99.0.2",
        "default_route": "",
        "aaa_new_model": True,
        "aaa_local_auth": True,
    })
    sys_data["users"].append({"username": "netadmin",
                              "password": "N3tadmin!Pass24",
                              "privilege": "15", "use_secret": True})
    sys_data["snmp"]["communities"].append({"community": "corp-netmon-ro",
                                            "mode": "RO"})
    sys_data["snmp"]["location"] = "HQ - IDF 2, Rack 4"
    sys_data["snmp"]["contact"] = "noc@corp.example.local"

    project.data["vlans"].update({
        "vlans": [
            {"id": "10", "name": "USERS"},
            {"id": "20", "name": "VOICE"},
            {"id": "30", "name": "SERVERS"},
            {"id": "99", "name": "MGMT"},
        ],
        "blackhole_vlan": "999",
    })
    project.data["vlans"]["stp"].update({
        "mode": "rapid-pvst",
        "root_primary": "10,20,30,99",
    })
    project.data["vlans"]["dhcp_snooping"].update({
        "enabled": True, "vlans": "10,20",
        "trusted_interfaces": "Port-channel1",
    })
    project.data["vlans"]["dai"].update({
        "enabled": True, "vlans": "10,20",
        "trusted_interfaces": "Port-channel1",
    })
    project.data["vlans"]["vtp"].update({
        "enabled": True, "mode": "transparent", "domain": "CORP",
    })

    access_common = {
        "mode": "access", "access_vlan": "10", "voice_vlan": "20",
        "portfast": True, "bpduguard": True, "ps_enabled": True,
        "ps_max": "3", "ps_violation": "restrict", "ps_sticky": True,
        "enabled": True, "description": "User + phone",
    }
    physical = [dict(access_common, name=f"GigabitEthernet1/0/{i}")
                for i in range(1, 9)]
    physical += [
        {"name": "TenGigabitEthernet1/1/1", "mode": "trunk",
         "native_vlan": "99", "allowed_vlans": "10,20,30,99",
         "nonegotiate": True, "channel_group": "1", "channel_mode": "active",
         "description": "Uplink to CORE-01 Te1/1/1", "enabled": True},
        {"name": "TenGigabitEthernet1/1/2", "mode": "trunk",
         "native_vlan": "99", "allowed_vlans": "10,20,30,99",
         "nonegotiate": True, "channel_group": "1", "channel_mode": "active",
         "description": "Uplink to CORE-02 Te1/1/1", "enabled": True},
    ]
    project.data["interfaces"].update({
        "physical": physical,
        "port_channels": [
            {"id": "1", "mode": "trunk", "native_vlan": "99",
             "allowed_vlans": "10,20,30,99",
             "description": "Uplink bundle to core"},
        ],
        "svis": [
            {"vlan": "10", "description": "Users gateway",
             "ip": "10.10.0.1", "mask": "255.255.255.0", "enabled": True},
            {"vlan": "30", "description": "Servers gateway",
             "ip": "10.30.0.1", "mask": "255.255.255.0", "enabled": True},
            {"vlan": "99", "description": "Management",
             "ip": "10.99.0.10", "mask": "255.255.255.0", "enabled": True},
        ],
    })

    project.data["layer3"]["static_routes"].append({
        "prefix": "0.0.0.0", "mask": "0.0.0.0", "next_hop": "10.99.0.1",
        "exit_interface": "", "distance": "", "name": "DEFAULT",
        "permanent": False,
    })

    project.data["dhcp"].update({
        "excluded": [{"start": "10.10.0.1", "end": "10.10.0.20"}],
        "pools": [{
            "name": "USERS", "network": "10.10.0.0",
            "mask": "255.255.255.0", "default_router": "10.10.0.1",
            "dns": "10.30.0.53, 10.30.0.54",
            "domain": "corp.example.local", "lease_days": "7",
            "option150": "",
        }],
    })

    project.data["acls"].update({
        "acls": [{
            "type": "standard", "id": "MGMT-ACCESS",
            "rules": [
                {"action": "remark", "remark": "Management subnet only"},
                {"action": "permit", "src": "10.99.0.0",
                 "src_wildcard": "0.0.0.255"},
            ],
        }],
        "vty_acl": "MGMT-ACCESS",
    })

    project.data["routing"]["ospf"].update({
        "enabled": True, "process_id": "1", "router_id": "10.99.0.10",
        "networks": [
            {"network": "10.10.0.0", "wildcard": "0.0.0.255", "area": "0"},
            {"network": "10.30.0.0", "wildcard": "0.0.0.255", "area": "0"},
            {"network": "10.99.0.0", "wildcard": "0.0.0.255", "area": "0"},
        ],
        "passive_interfaces": "Vlan10, Vlan30",
    })

    project.data["security"].update({
        "login_block_enabled": True,
        "min_password_length": "10",
    })

    project.data["misc"].update({
        "lldp_run": True,
        "clock_timezone_name": "EST",
        "clock_timezone_hours": "-5",
        "archive_enabled": True,
    })
    return project


def main() -> None:
    project = build()
    profile = load_profiles()[project.device_model]
    project.last_generated = generate_config(project, profile)
    project.warnings = [issue.to_dict()
                        for issue in validate_project(project, profile)]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    project.save(OUT)
    print(f"Wrote {OUT}")
    print(f"Config lines: {len(project.last_generated.splitlines())}, "
          f"issues: {len(project.warnings)}")


if __name__ == "__main__":
    main()
