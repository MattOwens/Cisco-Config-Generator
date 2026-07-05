"""Base system generator: services, identity, AAA/users, lines, management."""

from __future__ import annotations

from ..utils import normalize_interface_name, parse_list, s, safe_int, truthy

BANNER_DELIM = "^"


NETFLOW_RECORD = "CISCOGEN-RECORD"
NETFLOW_MONITOR = "CISCOGEN-MONITOR"


def generate(sys_data: dict, profile) -> dict[str, list[str]]:
    """Services, identity, AAA/users and management interfaces/routes."""
    segments: dict[str, list[str]] = {}
    segments["services"] = _services(sys_data) + _netflow(sys_data)
    segments["identity"] = _identity(sys_data, profile)
    segments["aaa_users"] = _aaa_users(sys_data)
    segments["interfaces"] = _management_interfaces(sys_data, profile)
    segments["static_routes"] = _default_reachability(sys_data, profile)
    return segments


def collect_interface_extras(sys_data: dict, extras: dict[str, list[str]]) -> None:
    """Apply the NetFlow monitor to the interfaces named in the form."""
    netflow = sys_data.get("netflow", {})
    if not (truthy(netflow.get("enabled")) and s(netflow.get("exporter"))):
        return
    for name in parse_list(netflow.get("interfaces")):
        extras.setdefault(normalize_interface_name(name), []).append(
            f" ip flow monitor {NETFLOW_MONITOR} input")


def _netflow(sys_data: dict) -> list[str]:
    """Flow record + exporter + monitor.  Defined early (services segment)
    so interface 'ip flow monitor' references resolve."""
    netflow = sys_data.get("netflow", {})
    if not (truthy(netflow.get("enabled")) and s(netflow.get("exporter"))):
        return []
    exporter = s(netflow.get("exporter"))
    lines = [
        f"flow record {NETFLOW_RECORD}",
        " match ipv4 protocol",
        " match ipv4 source address",
        " match ipv4 destination address",
        " match transport source-port",
        " match transport destination-port",
        " collect counter bytes long",
        " collect counter packets long",
        f"flow exporter {exporter}",
    ]
    if s(netflow.get("destination")):
        lines.append(f" destination {s(netflow.get('destination'))}")
    if s(netflow.get("source_interface")):
        lines.append(f" source "
                     f"{normalize_interface_name(s(netflow.get('source_interface')))}")
    if s(netflow.get("transport_port")):
        lines.append(f" transport udp {s(netflow.get('transport_port'))}")
    lines.extend([
        f"flow monitor {NETFLOW_MONITOR}",
        f" record {NETFLOW_RECORD}",
        f" exporter {exporter}",
    ])
    return lines


def _services(sys_data: dict) -> list[str]:
    lines: list[str] = []
    timestamps = s(sys_data.get("timestamps", "datetime msec"))
    if timestamps == "disabled":
        lines.append("no service timestamps debug")
        lines.append("no service timestamps log")
    else:
        lines.append(f"service timestamps debug {timestamps}")
        lines.append(f"service timestamps log {timestamps}")
    if truthy(sys_data.get("service_password_encryption")):
        lines.append("service password-encryption")
    if truthy(sys_data.get("no_domain_lookup")):
        lines.append("no ip domain-lookup")
    servers = parse_list(sys_data.get("name_servers"))
    if servers:
        lines.append(f"ip name-server {' '.join(servers)}")
    return lines


def _identity(sys_data: dict, profile) -> list[str]:
    lines: list[str] = []
    hostname = s(sys_data.get("hostname"))
    if hostname:
        lines.append(f"hostname {hostname}")
    domain = s(sys_data.get("domain_name"))
    if domain:
        lines.append(f"ip domain-name {domain}")
    secret = s(sys_data.get("enable_secret"))
    if secret:
        lines.append(f"enable secret {secret}")
    banner = s(sys_data.get("banner_motd"))
    if banner:
        body = banner.replace(BANNER_DELIM, "")
        lines.append(f"banner motd {BANNER_DELIM}")
        lines.extend(body.splitlines())
        lines.append(BANNER_DELIM)
    exec_banner = s(sys_data.get("banner_exec"))
    if exec_banner:
        body = exec_banner.replace(BANNER_DELIM, "")
        lines.append(f"banner exec {BANNER_DELIM}")
        lines.extend(body.splitlines())
        lines.append(BANNER_DELIM)
    login_banner = s(sys_data.get("banner_login"))
    if login_banner:
        body = login_banner.replace(BANNER_DELIM, "")
        lines.append(f"banner login {BANNER_DELIM}")
        lines.extend(body.splitlines())
        lines.append(BANNER_DELIM)
    if truthy(sys_data.get("ssh_enabled")):
        if truthy(sys_data.get("generate_rsa")):
            modulus = safe_int(sys_data.get("rsa_modulus"), 2048) or 2048
            lines.append(f"crypto key generate rsa modulus {modulus}")
        if truthy(sys_data.get("ssh_version2")):
            lines.append("ip ssh version 2")
        timeout = safe_int(sys_data.get("ssh_timeout"))
        if timeout is not None:
            lines.append(f"ip ssh time-out {timeout}")
        retries = safe_int(sys_data.get("ssh_auth_retries"))
        if retries is not None:
            lines.append(f"ip ssh authentication-retries {retries}")
    return lines


def _aaa_users(sys_data: dict) -> list[str]:
    lines: list[str] = []
    if truthy(sys_data.get("aaa_new_model")):
        lines.append("aaa new-model")
        methods = sys_data.get("aaa_methods", {})
        login_method = s(methods.get("login")) or (
            "local" if truthy(sys_data.get("aaa_local_auth")) else "")
        # Server-based methods need the 'group' keyword on modern IOS:
        # 'aaa authentication login default group tacacs+ local'.
        login_method = (login_method
                        .replace("tacacs+", "group tacacs+")
                        .replace("radius", "group radius")
                        .replace("group group", "group"))
        if login_method:
            lines.append(f"aaa authentication login default {login_method}")
        if truthy(methods.get("authorization_exec")):
            fallback = " local" if truthy(methods.get("local_fallback", True)) else ""
            lines.append(f"aaa authorization exec default group tacacs+{fallback}")
        if truthy(methods.get("accounting_commands")):
            lines.append("aaa accounting commands 15 default start-stop group tacacs+")
    for server in sys_data.get("tacacs", {}).get("servers", []):
        name, address = s(server.get("name")), s(server.get("address"))
        if not name or not address:
            continue
        lines.append(f"tacacs server {name}")
        lines.append(f" address ipv4 {address}")
        if s(server.get("key")):
            lines.append(f" key {s(server.get('key'))}")
        if s(server.get("timeout")):
            lines.append(f" timeout {s(server.get('timeout'))}")
    for server in sys_data.get("radius", {}).get("servers", []):
        name, address = s(server.get("name")), s(server.get("address"))
        if not name or not address:
            continue
        auth_port = s(server.get("auth_port", "1812")) or "1812"
        acct_port = s(server.get("acct_port", "1813")) or "1813"
        lines.append(f"radius server {name}")
        lines.append(f" address ipv4 {address} auth-port {auth_port} acct-port {acct_port}")
        if s(server.get("key")):
            lines.append(f" key {s(server.get('key'))}")
    for user in sys_data.get("users", []):
        username = s(user.get("username"))
        password = s(user.get("password"))
        if not username or not password:
            continue
        privilege = safe_int(user.get("privilege"), 1) or 1
        keyword = "secret" if truthy(user.get("use_secret", True)) else "password"
        priv_part = f" privilege {privilege}" if privilege != 1 else ""
        lines.append(f"username {username}{priv_part} {keyword} {password}")
    return lines


def _management_interfaces(sys_data: dict, profile) -> list[str]:
    lines: list[str] = []
    svi = sys_data.get("mgmt_svi", {})
    if truthy(svi.get("enabled")) and s(svi.get("vlan")):
        lines.append(f"interface Vlan{s(svi.get('vlan'))}")
        if s(svi.get("description")):
            lines.append(f" description {s(svi.get('description'))}")
        if s(svi.get("ip")) and s(svi.get("mask")):
            lines.append(f" ip address {s(svi.get('ip'))} {s(svi.get('mask'))}")
        lines.append(" no shutdown")
    mgmt = sys_data.get("mgmt_interface", {})
    if truthy(mgmt.get("enabled")) and s(mgmt.get("name")):
        lines.append(f"interface {normalize_interface_name(s(mgmt.get('name')))}")
        lines.append(" description Management")
        if s(mgmt.get("ip")) and s(mgmt.get("mask")):
            lines.append(f" ip address {s(mgmt.get('ip'))} {s(mgmt.get('mask'))}")
        lines.append(" no shutdown")
    return lines


def _default_reachability(sys_data: dict, profile) -> list[str]:
    lines: list[str] = []
    gateway = s(sys_data.get("default_gateway"))
    if gateway:
        lines.append(f"ip default-gateway {gateway}")
    route = s(sys_data.get("default_route"))
    if route:
        lines.append(f"ip route 0.0.0.0 0.0.0.0 {route}")
    return lines


def generate_lines(sys_data: dict, profile, vty_acl: str = "",
                   force_ssh: bool = False) -> dict[str, list[str]]:
    """Console and VTY line configuration."""
    lines: list[str] = []
    con = sys_data.get("console", {})
    lines.append("line con 0")
    if s(con.get("password")):
        lines.append(f" password {s(con.get('password'))}")
    if truthy(con.get("login_local")):
        lines.append(" login local")
    elif s(con.get("password")):
        lines.append(" login")
    timeout_min = safe_int(con.get("exec_timeout_min"))
    if timeout_min is not None:
        timeout_sec = safe_int(con.get("exec_timeout_sec"), 0) or 0
        lines.append(f" exec-timeout {timeout_min} {timeout_sec}")
    if truthy(con.get("logging_sync")):
        lines.append(" logging synchronous")

    vty = sys_data.get("vty", {})
    vty_range = s(vty.get("lines", "0 15")) or "0 15"
    lines.append(f"line vty {vty_range}")
    if truthy(vty.get("login_local")):
        lines.append(" login local")
    timeout_min = safe_int(vty.get("exec_timeout_min"))
    if timeout_min is not None:
        timeout_sec = safe_int(vty.get("exec_timeout_sec"), 0) or 0
        lines.append(f" exec-timeout {timeout_min} {timeout_sec}")
    if truthy(vty.get("logging_sync")):
        lines.append(" logging synchronous")
    transport = "ssh" if force_ssh else s(vty.get("transport", "ssh")) or "ssh"
    lines.append(f" transport input {transport}")
    if s(vty_acl):
        lines.append(f" access-class {s(vty_acl)} in")
    return {"lines": lines}


def generate_management(sys_data: dict, profile,
                        mgmt_acl: str = "") -> dict[str, list[str]]:
    """Logging, NTP and SNMP.  ``mgmt_acl`` (from the Access Lists
    section's management-plane ACL) is appended to SNMP community lines."""
    lines: list[str] = []
    buffered = s(sys_data.get("logging_buffered"))
    if buffered:
        severity = s(sys_data.get("logging_severity"))
        suffix = f" {severity}" if severity else ""
        lines.append(f"logging buffered {buffered}{suffix}")
    if s(sys_data.get("logging_source_interface")):
        lines.append(f"logging source-interface "
                     f"{normalize_interface_name(s(sys_data.get('logging_source_interface')))}")
    for host in parse_list(sys_data.get("logging_hosts")):
        lines.append(f"logging host {host}")
    ntp_auth = sys_data.get("ntp_authentication", {})
    if truthy(ntp_auth.get("enabled")) and s(ntp_auth.get("key_id")) and s(ntp_auth.get("key")):
        lines.append("ntp authenticate")
        lines.append(f"ntp authentication-key {s(ntp_auth.get('key_id'))} md5 {s(ntp_auth.get('key'))}")
        trusted = s(ntp_auth.get("trusted_key")) or s(ntp_auth.get("key_id"))
        lines.append(f"ntp trusted-key {trusted}")
    if s(sys_data.get("ntp_source_interface")):
        lines.append(f"ntp source {normalize_interface_name(s(sys_data.get('ntp_source_interface')))}")
    for server in parse_list(sys_data.get("ntp_servers")):
        lines.append(f"ntp server {server}")
    snmp = sys_data.get("snmp", {})
    for community in snmp.get("communities", []):
        name = s(community.get("community"))
        if not name:
            continue
        mode = s(community.get("mode", "RO")).upper() or "RO"
        acl_part = f" {s(mgmt_acl)}" if s(mgmt_acl) else ""
        lines.append(f"snmp-server community {name} {mode}{acl_part}")
    if s(snmp.get("location")):
        lines.append(f"snmp-server location {s(snmp.get('location'))}")
    if s(snmp.get("contact")):
        lines.append(f"snmp-server contact {s(snmp.get('contact'))}")
    if s(snmp.get("source_interface")):
        lines.append("snmp-server trap-source "
                     f"{normalize_interface_name(s(snmp.get('source_interface')))}")
    for view in snmp.get("views", []):
        name, oid = s(view.get("name")), s(view.get("oid"))
        action = s(view.get("action", "included")) or "included"
        if name and oid:
            lines.append(f"snmp-server view {name} {oid} {action}")
    for group in snmp.get("groups", []):
        name = s(group.get("name"))
        if not name:
            continue
        version = s(group.get("version", "v3 priv")) or "v3 priv"
        line = f"snmp-server group {name} {version}"
        if s(group.get("view")):
            line += f" read {s(group.get('view'))}"
        if s(group.get("acl")):
            line += f" access {s(group.get('acl'))}"
        lines.append(line)
    for user in snmp.get("users", []):
        username, group = s(user.get("username")), s(user.get("group"))
        if not username or not group:
            continue
        line = f"snmp-server user {username} {group} v3"
        if s(user.get("auth_protocol")) and s(user.get("auth_key")):
            line += f" auth {s(user.get('auth_protocol'))} {s(user.get('auth_key'))}"
        if s(user.get("priv_protocol")) and s(user.get("priv_key")):
            line += f" priv {s(user.get('priv_protocol'))} {s(user.get('priv_key'))}"
        lines.append(line)
    tacacs_source = s(sys_data.get("tacacs", {}).get("source_interface"))
    if tacacs_source:
        lines.append(f"ip tacacs source-interface {normalize_interface_name(tacacs_source)}")
    radius_source = s(sys_data.get("radius", {}).get("source_interface"))
    if radius_source:
        lines.append(f"ip radius source-interface {normalize_interface_name(radius_source)}")
    # RESTCONF/NETCONF are IOS-XE-only programmability features; never emit
    # them on classic IOS or CBS platforms even if a loaded project set the
    # flag (the validator warns separately).
    if profile.os_type == "IOS-XE":
        if truthy(sys_data.get("restconf_enabled")):
            lines.append("restconf")
        if truthy(sys_data.get("netconf_enabled")):
            lines.append("netconf-yang")
    if truthy(sys_data.get("scp_server_enabled")):
        lines.append("ip scp server enable")
    return {"management": lines}
