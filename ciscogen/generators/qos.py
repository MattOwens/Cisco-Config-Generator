"""QoS generator: class/policy maps, trust and service-policy bindings."""

from __future__ import annotations

from ..utils import normalize_interface_name, s


def _classic_ios_switch(profile) -> bool:
    """Catalyst switches on classic IOS use the 'mls qos' command family;
    IOS-XE switches (3650/3850/9k) are MQC-only, and 'mls qos' does not
    exist on routers or CBS/Business switches."""
    return profile is not None and profile.is_switch \
        and profile.os_type == "IOS"


def collect_interface_extras(qos_data: dict, extras: dict[str, list[str]],
                             profile=None) -> None:
    if _classic_ios_switch(profile):
        for item in qos_data.get("trust", []):
            interface = normalize_interface_name(s(item.get("interface")))
            mode = s(item.get("mode", "dscp")) or "dscp"
            if interface:
                extras.setdefault(interface, []).append(f" mls qos trust {mode}")
    if profile is None or profile.is_switch:
        for item in qos_data.get("autoqos", []):
            interface = normalize_interface_name(s(item.get("interface")))
            template = s(item.get("template", "voip cisco-phone")) or "voip cisco-phone"
            if interface:
                extras.setdefault(interface, []).append(f" auto qos {template}")
    for item in qos_data.get("service_policies", []):
        interface = normalize_interface_name(s(item.get("interface")))
        direction = s(item.get("direction", "output")) or "output"
        policy = s(item.get("policy"))
        if interface and policy:
            extras.setdefault(interface, []).append(f" service-policy {direction} {policy}")


def generate(qos_data: dict, profile) -> dict[str, list[str]]:
    lines: list[str] = []
    if qos_data.get("trust") or qos_data.get("class_maps") or qos_data.get("policy_maps"):
        if _classic_ios_switch(profile):
            lines.append("mls qos")
    for class_map in qos_data.get("class_maps", []):
        name = s(class_map.get("name"))
        if not name:
            continue
        match_type = s(class_map.get("match_type", "match-any")) or "match-any"
        lines.append(f"class-map {match_type} {name}")
        if s(class_map.get("dscp")):
            lines.append(f" match dscp {s(class_map.get('dscp'))}")
        if s(class_map.get("acl")):
            lines.append(f" match access-group name {s(class_map.get('acl'))}")
        if s(class_map.get("protocol")):
            lines.append(f" match protocol {s(class_map.get('protocol'))}")
    for policy in qos_data.get("policy_maps", []):
        name = s(policy.get("name"))
        if not name:
            continue
        lines.append(f"policy-map {name}")
        classes = policy.get("classes", [])
        if isinstance(classes, str):
            classes = [{"class_name": c.strip()} for c in classes.split(",") if c.strip()]
        for item in classes:
            class_name = s(item.get("class_name") or item.get("class"))
            if not class_name:
                continue
            lines.append(f" class {class_name}")
            if s(item.get("set_dscp")):
                lines.append(f"  set dscp {s(item.get('set_dscp'))}")
            if s(item.get("police")):
                lines.append(f"  police {s(item.get('police'))}")
            if s(item.get("shape")):
                lines.append(f"  shape average {s(item.get('shape'))}")
            if s(item.get("bandwidth_percent")):
                lines.append(f"  bandwidth percent {s(item.get('bandwidth_percent'))}")
    return {"qos": lines}
