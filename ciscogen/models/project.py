"""Project model: everything the user configures, serialised to JSON.

The project holds plain dicts/lists/strings so that save/load is a direct
json.dump/json.load.  UI forms bind directly into ``project.data``; the
generators and validators read from the same structure.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

SCHEMA_VERSION = 2

# Section keys in UI order.  "dmvpn" is retained for backward compatibility
# (old projects and in-memory construction) but is superseded by "tunnels";
# it is hidden from the sidebar and auto-migrated on load.
SECTIONS = [
    "system", "vrf", "interfaces", "vlans", "layer3", "ipv6", "dhcp",
    "nat", "acls", "routing", "tunnels", "ipsla", "zbf", "qos", "ha",
    "security", "misc", "custom_cli", "dmvpn",
]

# Sections hidden from the sidebar (kept only for compatibility/migration).
LEGACY_SECTIONS = {"dmvpn"}

SECTION_LABELS = {
    "system": "Base System",
    "vrf": "VRF-Lite",
    "interfaces": "Interfaces",
    "vlans": "VLANs & Layer 2",
    "layer3": "Static Routing & PBR",
    "ipv6": "IPv6",
    "dhcp": "DHCP Server",
    "nat": "NAT / PAT",
    "acls": "Access Lists",
    "routing": "Routing Protocols",
    "tunnels": "IP Tunnels & VPN",
    "ipsla": "IP SLA & Tracking",
    "zbf": "Zone Firewall",
    "qos": "QoS",
    "ha": "Gateway HA",
    "security": "Security Hardening",
    "misc": "Miscellaneous",
    "custom_cli": "Custom CLI",
    "dmvpn": "DMVPN & IPsec (legacy)",
}


def default_data() -> dict:
    """Full default form data for every section."""
    return {
        "system": {
            "hostname": "",
            "domain_name": "",
            "enable_secret": "",
            "service_password_encryption": True,
            "timestamps": "datetime msec",   # "datetime msec" | "uptime" | "disabled"
            "no_domain_lookup": True,
            "name_servers": "",             # comma separated DNS servers
            "banner_motd": "",
            "banner_login": "",
            "users": [],                     # {username, password, privilege, use_secret}
            "aaa_new_model": False,
            "aaa_local_auth": False,
            "ssh_enabled": True,
            "ssh_version2": True,
            "generate_rsa": True,
            "rsa_modulus": "2048",
            "ssh_timeout": "60",
            "ssh_auth_retries": "3",
            "console": {
                "login_local": True,
                "password": "",
                "exec_timeout_min": "10",
                "exec_timeout_sec": "0",
                "logging_sync": True,
            },
            "vty": {
                "login_local": True,
                "transport": "ssh",          # ssh | telnet | ssh telnet | none
                "exec_timeout_min": "10",
                "exec_timeout_sec": "0",
                "logging_sync": True,
                "lines": "0 15",             # "0 4" | "0 15"
            },
            "logging_buffered": "16384",
            "logging_hosts": "",             # comma separated
            "ntp_servers": "",               # comma separated
            "logging_severity": "",
            "logging_source_interface": "",
            "ntp_source_interface": "",
            "snmp": {
                "communities": [],           # {community, mode}
                "location": "",
                "contact": "",
                "views": [],                 # {name, oid, action}
                "groups": [],                # {name, version, view, acl}
                "users": [],                 # {username, group, auth, priv}
                "source_interface": "",
            },
            "tacacs": {
                "servers": [],               # {name, address, key, timeout}
                "source_interface": "",
            },
            "radius": {
                "servers": [],               # {name, address, key, auth_port, acct_port}
                "source_interface": "",
            },
            "aaa_methods": {
                "login": "local",            # local | tacacs local | radius local
                "authorization_exec": False,
                "accounting_commands": False,
                "local_fallback": True,
            },
            "ntp_authentication": {
                "enabled": False,
                "key_id": "",
                "key": "",
                "trusted_key": "",
            },
            "netflow": {
                "enabled": False,
                "exporter": "",
                "destination": "",
                "source_interface": "",
                "transport_port": "2055",
                "interfaces": "",      # comma separated, monitor applied input
            },
            "restconf_enabled": False,
            "netconf_enabled": False,
            "scp_server_enabled": False,
            "banner_exec": "",
            "mgmt_svi": {"enabled": False, "vlan": "99", "ip": "", "mask": "",
                         "description": "Management"},
            "mgmt_interface": {"enabled": False, "name": "", "ip": "", "mask": ""},
            "default_gateway": "",
            "default_route": "",
        },
        "interfaces": {
            "physical": [],       # see forms/interfaces.py for the field list
            "port_channels": [],
            "subinterfaces": [],
            "svis": [],
        },
        "vlans": {
            "vlans": [],          # {id, name}
            "blackhole_vlan": "",
            "stp": {
                "mode": "rapid-pvst",
                "portfast_default": False,
                "bpduguard_default": False,
                "root_primary": "",
                "root_secondary": "",
                "priority_vlans": "",
                "priority_value": "",
            },
            "dhcp_snooping": {"enabled": False, "vlans": "", "trusted_interfaces": ""},
            "dai": {"enabled": False, "vlans": "", "trusted_interfaces": ""},
            "vtp": {"enabled": False, "mode": "transparent", "domain": "", "password": ""},
            "errdisable_recovery": {"enabled": False, "causes": "", "interval": "300"},
            "private_vlans": [],  # {primary, secondary, type}
            "span_sessions": [],  # {session, source, direction, destination}
            "stackwise": {"enabled": False, "switch_number": "", "priority": ""},
        },
        "vrf": {
            "vrfs": [],           # {name, rd, description, address_family_ipv4}
            "interface_assignments": [],  # {interface, vrf}
            "static_routes": [],  # {vrf, prefix, mask, next_hop, exit_interface, distance}
            "dhcp_relays": [],    # {interface, vrf, helper}
            "ospf": [],           # {vrf, process_id, router_id, networks}
            "bgp": [],            # {vrf, asn, router_id, neighbors, networks}
        },
        "layer3": {
            "ip_routing": True,
            "static_routes": [],  # {prefix, mask, next_hop, exit_interface, distance, name, permanent}
            "prefix_lists": [],   # {name, seq, action, prefix, ge, le}
            "route_maps": [],     # {name, seq, action, match_acl, match_prefix_list, set_next_hop}
            "pbr_apply": [],      # {interface, route_map}
        },
        "ipv6": {
            "unicast_routing": False,
            "interface_addresses": [],  # {interface, address, eui64, suppress_ra}
            "static_routes": [],        # {prefix, next_hop, exit_interface, distance, vrf}
            "acls": [],                 # {name, rules}
            "ospfv3": {
                "enabled": False,
                "process_id": "1",
                "router_id": "",
                "interfaces": [],       # {interface, area, network_type, cost}
            },
            "dhcp_relays": [],          # {interface, destination}
        },
        "dhcp": {
            "excluded": [],       # {start, end}
            "pools": [],          # {name, network, mask, default_router, dns, domain, lease_days, option150}
            "static_bindings": [],  # {name, host_ip, mask, mac, client_id, default_router}
        },
        "nat": {
            "inside_interfaces": "",
            "outside_interfaces": "",
            "static_rules": [],   # {inside_local, inside_global, protocol, local_port, global_port}
            "dynamic_enabled": False,
            "dynamic_acl": "",
            "use_pool": False,
            "pool_name": "",
            "pool_start": "",
            "pool_end": "",
            "pool_mask": "",
            "overload": True,
            "overload_interface": "",
        },
        "acls": {
            "acls": [],           # {type, id, rules: [...]}
            "interface_apply": [],  # {acl, interface, direction}
            "vty_acl": "",
            "vty_bindings": [],   # {acl, direction, lines}
            "route_map_bindings": [],  # {acl, route_map}
            "management_plane_acl": "",
        },
        "routing": {
            "ospf": {
                "enabled": False, "process_id": "1", "router_id": "",
                "networks": [],   # {network, wildcard, area}
                "passive_default": False, "passive_interfaces": "",
                "default_originate": False, "default_originate_always": False,
                "area_auth_area": "", "area_auth_md5": True,
                "redistribute_static": False, "redistribute_connected": False,
            },
            "eigrp": {
                "enabled": False, "asn": "", "router_id": "",
                "networks": [],   # {network, wildcard}
                "passive_interfaces": "", "no_auto_summary": True,
                "redistribute_static": False,
            },
            "bgp": {
                "enabled": False, "asn": "", "router_id": "",
                "networks": [],   # {network, mask}
                "neighbors": [],  # {ip, remote_as, description, update_source, ebgp_multihop}
            },
            "rip": {
                "enabled": False, "version2": True, "no_auto_summary": True,
                "networks": "", "passive_interfaces": "",
            },
        },
        "dmvpn": {
            "enabled": False,
            "role": "Hub",
            "phase": "Phase 3",
            "tunnel_number": "0",
            "description": "",
            "tunnel_ip": "",
            "tunnel_mask": "",
            "tunnel_source_interface": "",
            "tunnel_source_ip": "",
            "tunnel_key": "",
            "tunnel_mode": "gre multipoint",
            "nhrp_network_id": "",
            "nhrp_authentication": "",
            "nhrp_holdtime": "600",
            "nhrp_map_multicast": "dynamic",
            "nhrp_nhs": [],       # {address, nbma}
            "nhrp_static_maps": [],  # {tunnel_ip, nbma, multicast}
            "nhrp_redirect": True,
            "nhrp_shortcut": True,
            "ip_mtu": "1400",
            "tcp_mss": "1360",
            "bandwidth": "",
            "delay": "",
            "ipsec_enabled": False,
            "ike_version": "IKEv2",
            "pre_shared_key": "",
            "ikev1_policy": {
                "number": "10", "encryption": "aes 256", "hash": "sha256",
                "authentication": "pre-share", "group": "14", "lifetime": "86400",
            },
            "ikev1_transform_set": "DMVPN-TS",
            "ikev2_proposal": "DMVPN-IKEV2-PROP",
            "ikev2_policy": "DMVPN-IKEV2-POLICY",
            "ikev2_keyring": "DMVPN-KEYRING",
            "ikev2_profile": "DMVPN-IKEV2-PROFILE",
            "ipsec_profile": "DMVPN-IPSEC-PROFILE",
            "tunnel_protection_profile": "DMVPN-IPSEC-PROFILE",
            "nat_traversal_note": True,
            "vrf": "",
            "routing": {
                "static_routes": [],   # {prefix, mask, next_hop}
                "ospf": {"enabled": False, "process_id": "1", "area": "0",
                         "network_type": "point-to-multipoint", "cost": "",
                         "authentication": ""},
                "eigrp": {"enabled": False, "asn": "", "networks": [],
                          "hub_disable_split_horizon": True,
                          "hub_disable_next_hop_self": True},
                "bgp": {"enabled": False, "local_as": "", "neighbors": [],
                        "networks": [], "route_reflector": False,
                        "next_hop_self": True},
            },
        },
        "tunnels": {
            "tunnels": [],          # list of tunnel entries (see default_tunnel())
        },
        "ipsla": {
            "operations": [],       # {id, type, target, source_interface, port, frequency, timeout, threshold}
            "tracks": [],           # {id, sla_id, type, delay_up, delay_down}
            "tracked_routes": [],   # {prefix, mask, next_hop, track_id, distance, name}
            "floating_routes": [],  # {prefix, mask, next_hop, distance, name}
            "eem": [],              # {name, track_id, state, action_cli}
        },
        "zbf": {
            "zones": [],            # {name, description}
            "interface_memberships": [],  # {interface, zone}
            "class_maps": [],       # {name, match_type, protocols, acl}
            "policy_maps": [],      # {name, classes}
            "zone_pairs": [],       # {name, source, destination, policy}
            "self_zone_warnings": True,
        },
        "qos": {
            "trust": [],             # {interface, mode}
            "autoqos": [],           # {interface, template}
            "class_maps": [],        # {name, match_type, dscp, acl, protocol}
            "policy_maps": [],       # {name, classes}
            "service_policies": [],  # {interface, direction, policy}
        },
        "ha": {
            "groups": [],            # {protocol, interface, group, virtual_ip, priority, preempt, auth, track_id, decrement}
        },
        "security": {
            "disable_http": True,
            "disable_https": True,
            "no_small_servers": True,
            "no_pad": True,
            "no_ip_source_route": True,
            "tcp_keepalives": True,
            "login_block_enabled": False,
            "login_block_seconds": "120",
            "login_block_attempts": "3",
            "login_block_within": "60",
            "min_password_length": "",
            "ssh_only": True,
        },
        "misc": {
            "cdp_run": True,
            "lldp_run": False,
            "clock_timezone_name": "",
            "clock_timezone_hours": "",
            "clock_timezone_minutes": "0",
            "archive_enabled": False,
            "archive_path": "flash:archive",
            "archive_write_memory": True,
            "archive_time_period": "1440",
        },
        "custom_cli": {
            "global": "",
            "pre_interface": "",
            "interface_snippets": [],  # {interface, cli}
            "post_routing": "",
            "end": "",
            "unparsed_imported_lines": "",
        },
    }


def default_tunnel(tunnel_type: str = "GRE point-to-point") -> dict:
    """A single tunnel entry for the IP Tunnels & VPN section.

    Field names deliberately match the legacy ``dmvpn`` structure so the
    DMVPN generator/validator helpers can be reused per tunnel.
    """
    return {
        "enabled": True,
        "name": "",
        "type": tunnel_type,
        "tunnel_number": "0",
        "description": "",
        "tunnel_ip": "",
        "tunnel_mask": "",
        "ipv6_address": "",
        "tunnel_source_interface": "",
        "tunnel_source_ip": "",
        "tunnel_destination": "",
        "tunnel_key": "",
        "tunnel_mode": "",
        "vrf": "",
        "ip_mtu": "1400",
        "tcp_mss": "1360",
        "keepalive": "",
        "bandwidth": "",
        "delay": "",
        # DMVPN-specific
        "role": "Hub",
        "phase": "Phase 3",
        "nhrp_network_id": "",
        "nhrp_authentication": "",
        "nhrp_holdtime": "600",
        "nhrp_map_multicast": "dynamic",
        "nhrp_nhs": [],
        "nhrp_static_maps": [],
        "nhrp_redirect": True,
        "nhrp_shortcut": True,
        # IPsec/IKE
        "ipsec_enabled": False,
        "ike_version": "IKEv2",
        "pre_shared_key": "",
        "pfs_group": "",
        "lifetime": "",
        "ikev1_policy": {
            "number": "10", "encryption": "aes 256", "hash": "sha256",
            "authentication": "pre-share", "group": "14", "lifetime": "86400",
        },
        "ikev1_transform_set": "TUNNEL-TS",
        "ikev2_proposal": "TUNNEL-IKEV2-PROP",
        "ikev2_policy": "TUNNEL-IKEV2-POLICY",
        "ikev2_keyring": "TUNNEL-KEYRING",
        "ikev2_profile": "TUNNEL-IKEV2-PROFILE",
        "ipsec_profile": "TUNNEL-IPSEC-PROFILE",
        "tunnel_protection_profile": "TUNNEL-IPSEC-PROFILE",
        "nat_traversal_note": True,
        "routing": {
            "static_routes": [],
            "ospf": {"enabled": False, "process_id": "1", "area": "0",
                     "network_type": "point-to-multipoint", "cost": "",
                     "authentication": ""},
            "eigrp": {"enabled": False, "asn": "", "networks": [],
                      "hub_disable_split_horizon": True,
                      "hub_disable_next_hop_self": True},
            "bgp": {"enabled": False, "local_as": "", "neighbors": [],
                    "networks": [], "route_reflector": False,
                    "next_hop_self": True},
        },
    }


def _tunnel_from_legacy_dmvpn(dmvpn: dict) -> dict:
    """Convert a legacy single-DMVPN dict into a tunnels[] entry."""
    tunnel = default_tunnel("GRE multipoint (DMVPN)")
    for key, value in dmvpn.items():
        if key == "enabled":
            continue
        tunnel[key] = copy.deepcopy(value)
    tunnel["enabled"] = True
    tunnel["name"] = tunnel.get("description") or "DMVPN"
    return tunnel


def _migrate_legacy_dmvpn(project) -> None:
    """Move an enabled legacy single-DMVPN config into the tunnels list.

    Runs on load so old project files keep working under the new IP Tunnels
    & VPN section without double-generating.  In-memory construction that
    sets ``data['dmvpn']`` directly is untouched (its enabled flag stays and
    the legacy generator still handles it).
    """
    dmvpn = project.data.get("dmvpn", {})
    if not dmvpn.get("enabled"):
        return
    already = {(t.get("type"), t.get("tunnel_number"), t.get("nhrp_network_id"))
               for t in project.data.get("tunnels", {}).get("tunnels", [])}
    key = ("GRE multipoint (DMVPN)", dmvpn.get("tunnel_number"),
           dmvpn.get("nhrp_network_id"))
    if key in already:
        return
    project.data.setdefault("tunnels", {}).setdefault("tunnels", []).append(
        _tunnel_from_legacy_dmvpn(dmvpn))
    # Prevent the legacy generator from also emitting this tunnel.
    project.data["dmvpn"]["enabled"] = False
    project.sections_enabled["tunnels"] = True
    project.sections_enabled["dmvpn"] = False


def _deep_merge(defaults, loaded):
    """Recursively overlay loaded values onto defaults (keeps new keys valid)."""
    if isinstance(defaults, dict) and isinstance(loaded, dict):
        merged = {}
        for key, dval in defaults.items():
            merged[key] = _deep_merge(dval, loaded[key]) if key in loaded else copy.deepcopy(dval)
        for key, lval in loaded.items():
            if key not in merged:
                merged[key] = copy.deepcopy(lval)
        return merged
    return copy.deepcopy(loaded)


class Project:
    """Application state: device selection, section toggles and all form data."""

    def __init__(self):
        self.device_model: str = ""
        self.os_type: str = ""
        self.os_version: str = ""
        self.sections_enabled: dict[str, bool] = {k: k in ("system", "interfaces")
                                                  for k in SECTIONS}
        self.data: dict = default_data()
        self.options: dict = {"include_comments": False}
        self.last_generated: str = ""
        self.edited_config: str = ""
        self.imported_config: str = ""
        self.import_warnings: list[str] = []
        self.warnings: list[dict] = []
        self.file_path: str = ""

    # -- serialisation ----------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "device": {
                "model": self.device_model,
                "os_type": self.os_type,
                "os_version": self.os_version,
            },
            "sections_enabled": dict(self.sections_enabled),
            "options": dict(self.options),
            "data": self.data,
            "last_generated": self.last_generated,
            "edited_config": self.edited_config,
            "imported_config": self.imported_config,
            "import_warnings": list(self.import_warnings),
            "warnings": self.warnings,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "Project":
        project = cls()
        device = raw.get("device", {})
        project.device_model = device.get("model", "")
        project.os_type = device.get("os_type", "")
        project.os_version = device.get("os_version", "")
        # Note: legacy per-project license fields (license_profile,
        # capability_overrides, ...) are intentionally ignored; feature
        # availability comes from the device profile.
        for key in SECTIONS:
            if key in raw.get("sections_enabled", {}):
                project.sections_enabled[key] = bool(raw["sections_enabled"][key])
        project.options.update(raw.get("options", {}))
        project.data = _deep_merge(default_data(), raw.get("data", {}))
        _migrate_legacy_dmvpn(project)
        project.last_generated = raw.get("last_generated", "")
        project.edited_config = raw.get("edited_config", "")
        project.imported_config = raw.get("imported_config", "")
        project.import_warnings = list(raw.get("import_warnings", []))
        project.warnings = list(raw.get("warnings", []))
        return project

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        self.file_path = str(path)

    @classmethod
    def load(cls, path: str | Path) -> "Project":
        path = Path(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        project = cls.from_dict(raw)
        project.file_path = str(path)
        return project


def new_project() -> Project:
    return Project()
