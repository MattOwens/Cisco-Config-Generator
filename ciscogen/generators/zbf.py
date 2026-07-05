"""Zone-Based Firewall generator."""

from __future__ import annotations

from ..utils import normalize_interface_name, parse_list, s


def collect_interface_extras(zbf_data: dict, extras: dict[str, list[str]]) -> None:
    for item in zbf_data.get("interface_memberships", []):
        interface = normalize_interface_name(s(item.get("interface")))
        zone = s(item.get("zone"))
        if interface and zone:
            extras.setdefault(interface, []).append(f" zone-member security {zone}")


def generate(zbf_data: dict, profile) -> dict[str, list[str]]:
    lines: list[str] = []
    for zone in zbf_data.get("zones", []):
        name = s(zone.get("name"))
        if not name:
            continue
        lines.append(f"zone security {name}")
        description = s(zone.get("description"))
        if description:
            lines.append(f" description {description}")
    for class_map in zbf_data.get("class_maps", []):
        name = s(class_map.get("name"))
        if not name:
            continue
        match_type = s(class_map.get("match_type", "match-any")) or "match-any"
        lines.append(f"class-map type inspect {match_type} {name}")
        protocols = parse_list(class_map.get("protocols"))
        for protocol in protocols:
            lines.append(f" match protocol {protocol}")
        acl = s(class_map.get("acl"))
        if acl:
            lines.append(f" match access-group name {acl}")
    for policy in zbf_data.get("policy_maps", []):
        name = s(policy.get("name"))
        if not name:
            continue
        lines.append(f"policy-map type inspect {name}")
        classes = policy.get("classes", [])
        if isinstance(classes, str):
            classes = [{"class_name": c.strip(), "action": "inspect"}
                       for c in classes.split(",") if c.strip()]
        for item in classes:
            class_name = s(item.get("class_name") or item.get("class"))
            action = s(item.get("action", "inspect")) or "inspect"
            if not class_name:
                continue
            lines.append(f" class type inspect {class_name}")
            lines.append(f"  {action}")
        if s(policy.get("class_default_action")):
            lines.append(" class class-default")
            lines.append(f"  {s(policy.get('class_default_action'))}")
    for pair in zbf_data.get("zone_pairs", []):
        name = s(pair.get("name"))
        source = s(pair.get("source"))
        destination = s(pair.get("destination"))
        policy = s(pair.get("policy"))
        if not name or not source or not destination or not policy:
            continue
        lines.append(f"zone-pair security {name} source {source} destination {destination}")
        lines.append(f" service-policy type inspect {policy}")
    return {"zbf": lines}
