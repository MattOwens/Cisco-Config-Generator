"""Basic Cisco IOS running-config importer."""

from __future__ import annotations

from .utils import normalize_interface_name, s


def parse_running_config(text: str) -> tuple[dict, list[str]]:
    data: dict = {
        "system": {"users": [], "snmp": {"communities": []}},
        "vlans": {"vlans": []},
        "interfaces": {"physical": [], "subinterfaces": [], "svis": []},
        "layer3": {"static_routes": []},
        "dhcp": {"pools": [], "excluded": []},
        "acls": {"acls": []},
        "routing": {
            "ospf": {"enabled": False, "networks": []},
            "eigrp": {"enabled": False, "networks": []},
            "bgp": {"enabled": False, "neighbors": [], "networks": []},
            "rip": {"enabled": False},
        },
        "nat": {"inside_interfaces": "", "outside_interfaces": "", "dynamic_enabled": False},
        "ipsla": {"operations": [], "tracks": []},
        "dmvpn": {"enabled": False, "nhrp_nhs": [], "nhrp_static_maps": []},
        "custom_cli": {"unparsed_imported_lines": ""},
    }
    unparsed: list[str] = []
    lines = (text or "").splitlines()
    index = 0
    current_acl = None
    while index < len(lines):
        raw = lines[index].rstrip()
        line = raw.strip()
        index += 1
        if not line or line == "!":
            continue
        parts = line.split()
        if parts[:1] == ["hostname"] and len(parts) > 1:
            data["system"]["hostname"] = parts[1]
        elif parts[:2] == ["ip", "domain-name"] and len(parts) > 2:
            data["system"]["domain_name"] = parts[2]
        elif parts[:2] == ["enable", "secret"] and len(parts) > 2:
            data["system"]["enable_secret"] = " ".join(parts[2:])
        elif parts[:1] == ["username"] and len(parts) >= 4:
            username = parts[1]
            privilege = "1"
            if "privilege" in parts:
                pos = parts.index("privilege")
                if pos + 1 < len(parts):
                    privilege = parts[pos + 1]
            keyword = "secret" if "secret" in parts else "password"
            pos = parts.index(keyword) if keyword in parts else len(parts) - 1
            data["system"]["users"].append({
                "username": username,
                "privilege": privilege,
                "use_secret": keyword == "secret",
                "password": " ".join(parts[pos + 1:]),
            })
        elif parts[:1] == ["vlan"] and len(parts) > 1:
            vlan = {"id": parts[1], "name": ""}
            while index < len(lines) and lines[index].startswith(" "):
                child = lines[index].strip()
                index += 1
                if child.startswith("name "):
                    vlan["name"] = child[5:]
                else:
                    unparsed.append(child)
            data["vlans"]["vlans"].append(vlan)
        elif parts[:1] == ["interface"] and len(parts) > 1:
            interface, consumed_unparsed = _parse_interface(parts[1], lines, index)
            index = interface.pop("_next_index")
            unparsed.extend(consumed_unparsed)
            name = interface.get("name", "")
            if interface.pop("_nat_inside", False):
                current = data["nat"].get("inside_interfaces", "")
                data["nat"]["inside_interfaces"] = ", ".join(v for v in (current, name) if v)
            if interface.pop("_nat_outside", False):
                current = data["nat"].get("outside_interfaces", "")
                data["nat"]["outside_interfaces"] = ", ".join(v for v in (current, name) if v)
            if name.startswith("Vlan"):
                interface["vlan"] = name[4:]
                data["interfaces"]["svis"].append(interface)
            elif "." in name:
                parent, _, vlan = name.partition(".")
                interface["parent"] = parent
                interface["vlan"] = vlan
                data["interfaces"]["subinterfaces"].append(interface)
            elif name.startswith("Tunnel"):
                data["dmvpn"].update(interface.pop("_dmvpn", {}))
                data["dmvpn"]["enabled"] = True
            else:
                data["interfaces"]["physical"].append(interface)
        elif parts[:2] == ["ip", "route"] and len(parts) >= 5:
            data["layer3"]["static_routes"].append({
                "prefix": parts[2],
                "mask": parts[3],
                "next_hop": parts[4],
                "exit_interface": "",
            })
        elif parts[:3] == ["ip", "dhcp", "excluded-address"] and len(parts) >= 4:
            data["dhcp"]["excluded"].append({"start": parts[3], "end": parts[4] if len(parts) > 4 else ""})
        elif parts[:3] == ["ip", "dhcp", "pool"] and len(parts) >= 4:
            pool, next_index, pool_unparsed = _parse_dhcp_pool(parts[3], lines, index)
            index = next_index
            unparsed.extend(pool_unparsed)
            data["dhcp"]["pools"].append(pool)
        elif parts[:3] == ["ip", "access-list", "standard"] and len(parts) >= 4:
            current_acl, index = _parse_named_acl("standard", parts[3], lines, index)
            data["acls"]["acls"].append(current_acl)
        elif parts[:3] == ["ip", "access-list", "extended"] and len(parts) >= 4:
            current_acl, index = _parse_named_acl("extended", parts[3], lines, index)
            data["acls"]["acls"].append(current_acl)
        elif parts[:1] == ["access-list"] and len(parts) >= 3:
            acl_id = parts[1]
            acl_type = "extended" if acl_id.isdigit() and 100 <= int(acl_id) <= 2699 else "standard"
            acl = next((a for a in data["acls"]["acls"] if a.get("id") == acl_id), None)
            if acl is None:
                acl = {"id": acl_id, "type": acl_type, "rules": []}
                data["acls"]["acls"].append(acl)
            acl["rules"].append({"action": parts[2], "remark": " ".join(parts[3:])})
        elif parts[:2] == ["router", "ospf"] and len(parts) > 2:
            data["routing"]["ospf"]["enabled"] = True
            data["routing"]["ospf"]["process_id"] = parts[2]
        elif parts[:2] == ["router", "eigrp"] and len(parts) > 2:
            data["routing"]["eigrp"]["enabled"] = True
            data["routing"]["eigrp"]["asn"] = parts[2]
        elif parts[:2] == ["router", "bgp"] and len(parts) > 2:
            data["routing"]["bgp"]["enabled"] = True
            data["routing"]["bgp"]["asn"] = parts[2]
        elif parts[:2] == ["ip", "sla"] and len(parts) > 2:
            op, next_index = _parse_ipsla(parts[2], lines, index)
            index = next_index
            data["ipsla"]["operations"].append(op)
        elif parts[:1] == ["track"] and len(parts) >= 5 and parts[2:4] == ["ip", "sla"]:
            data["ipsla"]["tracks"].append({"id": parts[1], "sla_id": parts[4], "type": parts[5] if len(parts) > 5 else "reachability"})
        else:
            unparsed.append(raw)
    return data, unparsed


def _parse_interface(name: str, lines: list[str], index: int) -> tuple[dict, list[str]]:
    item = {"name": normalize_interface_name(name), "enabled": True}
    unparsed = []
    dmvpn = {}
    inside = outside = False
    while index < len(lines) and lines[index].startswith(" "):
        child = lines[index].strip()
        index += 1
        parts = child.split()
        if child.startswith("description "):
            item["description"] = child[12:]
        elif parts[:3] == ["switchport", "mode", "access"]:
            item["mode"] = "access"
        elif parts[:3] == ["switchport", "mode", "trunk"]:
            item["mode"] = "trunk"
        elif parts[:3] == ["switchport", "access", "vlan"] and len(parts) > 3:
            item["access_vlan"] = parts[3]
        elif parts[:3] == ["switchport", "voice", "vlan"] and len(parts) > 3:
            item["voice_vlan"] = parts[3]
        elif parts[:2] == ["ip", "address"] and len(parts) >= 4:
            item["mode"] = item.get("mode", "routed")
            item["ip"] = parts[2]
            item["mask"] = parts[3]
            dmvpn["tunnel_ip"] = parts[2]
            dmvpn["tunnel_mask"] = parts[3]
        elif parts[:2] == ["ip", "nat"] and len(parts) > 2:
            inside = parts[2] == "inside"
            outside = parts[2] == "outside"
        elif parts[:3] == ["ip", "nhrp", "network-id"] and len(parts) > 3:
            dmvpn["nhrp_network_id"] = parts[3]
        elif parts[:2] == ["tunnel", "source"] and len(parts) > 2:
            dmvpn["tunnel_source_interface"] = parts[2]
        elif parts[:2] == ["tunnel", "key"] and len(parts) > 2:
            dmvpn["tunnel_key"] = parts[2]
        elif child == "shutdown":
            item["enabled"] = False
        elif child == "no shutdown":
            item["enabled"] = True
        else:
            unparsed.append(child)
    if dmvpn:
        dmvpn["tunnel_number"] = item["name"].replace("Tunnel", "")
        item["_dmvpn"] = dmvpn
    item["_next_index"] = index
    if inside:
        item["_nat_inside"] = True
    if outside:
        item["_nat_outside"] = True
    return item, unparsed


def _parse_dhcp_pool(name: str, lines: list[str], index: int) -> tuple[dict, int, list[str]]:
    pool = {"name": name}
    unparsed = []
    while index < len(lines) and lines[index].startswith(" "):
        child = lines[index].strip()
        index += 1
        parts = child.split()
        if parts[:1] == ["network"] and len(parts) >= 3:
            pool["network"], pool["mask"] = parts[1], parts[2]
        elif parts[:1] == ["default-router"] and len(parts) > 1:
            pool["default_router"] = parts[1]
        elif parts[:1] == ["dns-server"] and len(parts) > 1:
            pool["dns"] = ", ".join(parts[1:])
        elif parts[:1] == ["domain-name"] and len(parts) > 1:
            pool["domain"] = parts[1]
        else:
            unparsed.append(child)
    return pool, index, unparsed


def _parse_named_acl(acl_type: str, acl_id: str, lines: list[str], index: int) -> tuple[dict, int]:
    acl = {"type": acl_type, "id": acl_id, "rules": []}
    while index < len(lines) and lines[index].startswith(" "):
        child = lines[index].strip()
        index += 1
        parts = child.split()
        if not parts:
            continue
        if parts[0] == "remark":
            acl["rules"].append({"action": "remark", "remark": " ".join(parts[1:])})
        else:
            acl["rules"].append({"action": parts[0], "protocol": parts[1] if len(parts) > 1 else "ip",
                                 "src": parts[2] if len(parts) > 2 else "any",
                                 "dst": parts[3] if len(parts) > 3 else "any"})
    return acl, index


def _parse_ipsla(op_id: str, lines: list[str], index: int) -> tuple[dict, int]:
    op = {"id": op_id}
    while index < len(lines) and lines[index].startswith(" "):
        child = lines[index].strip()
        index += 1
        parts = child.split()
        if parts and parts[0] in ("icmp-echo", "tcp-connect", "udp-jitter"):
            op["type"] = parts[0]
            op["target"] = parts[1] if len(parts) > 1 else ""
        elif parts and parts[0] in ("frequency", "timeout", "threshold") and len(parts) > 1:
            op[parts[0]] = parts[1]
    return op, index


def apply_import(project, text: str) -> list[str]:
    parsed, unparsed = parse_running_config(text)
    for section, section_data in parsed.items():
        if section in project.data and isinstance(project.data[section], dict):
            project.data[section].update(section_data)
            if section in project.sections_enabled:
                project.sections_enabled[section] = True
    project.imported_config = text
    project.import_warnings = [f"Unparsed line: {line}" for line in unparsed]
    project.data.setdefault("custom_cli", {})["unparsed_imported_lines"] = "\n".join(unparsed)
    project.sections_enabled["custom_cli"] = bool(unparsed)
    return project.import_warnings
