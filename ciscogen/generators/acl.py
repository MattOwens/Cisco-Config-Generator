"""ACL generator: standard/extended, numbered/named, plus interface bindings.

Rule order is preserved exactly as entered by the user.
"""

from __future__ import annotations

from ..utils import normalize_interface_name, s, safe_int, truthy

TCP_UDP = ("tcp", "udp")


def collect_interface_extras(acl_data: dict, extras: dict[str, list[str]]) -> None:
    for app in acl_data.get("interface_apply", []):
        acl_ref = s(app.get("acl"))
        interface = normalize_interface_name(s(app.get("interface")))
        direction = s(app.get("direction", "in")) or "in"
        if acl_ref and interface:
            extras.setdefault(interface, []).append(
                f" ip access-group {acl_ref} {direction}")


def _address_part(rule: dict, side: str) -> str:
    value = s(rule.get(side))
    wildcard = s(rule.get(f"{side}_wildcard"))
    if value == "any" or not value:
        return "any"
    if not wildcard or wildcard == "0.0.0.0":
        return f"host {value}"
    return f"{value} {wildcard}"


def _port_part(rule: dict, side: str) -> str:
    op = s(rule.get(f"{side}_port_op"))
    port = s(rule.get(f"{side}_port"))
    if not op or op == "none" or not port:
        return ""
    return f" {op} {port}"


def _standard_rule_text(rule: dict) -> str | None:
    action = s(rule.get("action", "permit"))
    if action == "remark":
        remark = s(rule.get("remark"))
        return f"remark {remark}" if remark else None
    value = s(rule.get("src"))
    wildcard = s(rule.get("src_wildcard"))
    if not value:
        return None
    if value == "any":
        src = "any"
    elif not wildcard or wildcard == "0.0.0.0":
        src = value
    else:
        src = f"{value} {wildcard}"
    return f"{action} {src}"


def _extended_rule_text(rule: dict) -> str | None:
    action = s(rule.get("action", "permit"))
    if action == "remark":
        remark = s(rule.get("remark"))
        return f"remark {remark}" if remark else None
    protocol = s(rule.get("protocol", "ip")) or "ip"
    text = f"{action} {protocol} {_address_part(rule, 'src')}"
    if protocol in TCP_UDP:
        text += _port_part(rule, "src")
    text += f" {_address_part(rule, 'dst')}"
    if protocol in TCP_UDP:
        text += _port_part(rule, "dst")
    if protocol == "icmp":
        icmp_type = s(rule.get("icmp_type"))
        if icmp_type:
            text += f" {icmp_type}"
    if protocol == "tcp" and truthy(rule.get("established")):
        text += " established"
    if truthy(rule.get("log")):
        text += " log"
    return text


def generate(acl_data: dict, profile) -> dict[str, list[str]]:
    lines: list[str] = []
    for acl in acl_data.get("acls", []):
        acl_id = s(acl.get("id"))
        if not acl_id:
            continue
        acl_type = s(acl.get("type", "standard"))
        numbered = safe_int(acl_id) is not None
        rule_text = _standard_rule_text if acl_type == "standard" \
            else _extended_rule_text
        if numbered:
            for rule in acl.get("rules", []):
                text = rule_text(rule)
                if text:
                    lines.append(f"access-list {acl_id} {text}")
        else:
            lines.append(f"ip access-list {acl_type} {acl_id}")
            for rule in acl.get("rules", []):
                text = rule_text(rule)
                if text:
                    lines.append(f" {text}")
    for binding in acl_data.get("route_map_bindings", []):
        acl_ref = s(binding.get("acl"))
        route_map = s(binding.get("route_map"))
        seq = s(binding.get("seq", "10")) or "10"
        action = s(binding.get("action", "permit")) or "permit"
        if acl_ref and route_map:
            lines.append(f"route-map {route_map} {action} {seq}")
            lines.append(f" match ip address {acl_ref}")

    vty_lines: list[str] = []
    for binding in acl_data.get("vty_bindings", []):
        acl_ref = s(binding.get("acl"))
        if not acl_ref:
            continue
        vty_range = s(binding.get("lines", "0 4")) or "0 4"
        direction = s(binding.get("direction", "in")) or "in"
        vty_lines.append(f"line vty {vty_range}")
        vty_lines.append(f" access-class {acl_ref} {direction}")
    return {"acls": lines, "lines": vty_lines}
