"""Base System form: identity, services, SSH, AAA/users, lines, logging,
NTP, SNMP and management addressing."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class SystemForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["system"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("Identity")
        form.entry(group, "hostname", "Hostname")
        form.entry(group, "domain_name", "Domain name")
        form.entry(group, "enable_secret", "Enable secret")
        form.newline(group)
        form.text(group, "banner_motd", "Banner MOTD", height=3)
        form.text(group, "banner_login", "Banner Login", height=3)
        form.text(group, "banner_exec", "Banner EXEC", height=3)

        group = form.group("Global services")
        form.check(group, "service_password_encryption",
                   "service password-encryption", default=True)
        form.check(group, "no_domain_lookup", "no ip domain-lookup",
                   default=True)
        form.combo(group, "timestamps", "Service timestamps",
                   ["datetime msec", "datetime", "uptime", "disabled"],
                   default="datetime msec")
        form.entry(group, "name_servers",
                   "DNS name-servers (comma separated)")

        group = form.group("SSH")
        form.check(group, "ssh_enabled", "Enable SSH", default=True)
        form.check(group, "ssh_version2", "SSH version 2", default=True)
        form.check(group, "generate_rsa",
                   "Include RSA key generation command", default=True)
        form.combo(group, "rsa_modulus", "RSA modulus",
                   ["1024", "2048", "4096"], default="2048")
        form.entry(group, "ssh_timeout", "SSH timeout (sec)", default="60",
                   width=8)
        form.entry(group, "ssh_auth_retries", "SSH auth retries", default="3",
                   width=8)
        form.note(group, "Note: 'crypto key generate rsa' is an EXEC command; "
                         "when pasting the config, run it manually if the "
                         "device rejects it in config mode.")

        group = form.group("AAA and local users")
        form.check(group, "aaa_new_model", "aaa new-model")
        form.check(group, "aaa_local_auth",
                   "aaa authentication login default local")
        form.combo(group, "aaa_methods.login", "Login method",
                   ["local", "tacacs+ local", "radius local"],
                   default="local")
        form.check(group, "aaa_methods.authorization_exec",
                   "AAA authorization exec")
        form.check(group, "aaa_methods.accounting_commands",
                   "AAA accounting commands 15")
        form.check(group, "aaa_methods.local_fallback",
                   "Keep local fallback", default=True)
        form.newline(group)
        users = TableEditor(
            group, "Local users",
            columns=[("username", "Username", 140), ("privilege", "Priv", 60),
                     ("use_secret", "Secret", 70)],
            fields=[
                {"key": "username", "label": "Username"},
                {"key": "password", "label": "Password"},
                {"key": "privilege", "label": "Privilege (0-15)", "default": "15"},
                {"key": "use_secret", "label": "Use 'secret' (hashed)",
                 "type": "check", "default": True},
            ],
            items=data.setdefault("users", []), on_change=on_change, height=4)
        form.widget(group, users)

        tacacs = TableEditor(
            group, "TACACS+ servers",
            columns=[("name", "Name", 120), ("address", "Address", 120)],
            fields=[
                {"key": "name", "label": "Server name"},
                {"key": "address", "label": "IPv4 address"},
                {"key": "key", "label": "Key"},
                {"key": "timeout", "label": "Timeout", "width": 8},
            ],
            items=data.setdefault("tacacs", {}).setdefault("servers", []),
            on_change=on_change, height=3)
        form.widget(group, tacacs)
        form.entry(group, "tacacs.source_interface", "TACACS source interface")
        radius = TableEditor(
            group, "RADIUS servers",
            columns=[("name", "Name", 120), ("address", "Address", 120)],
            fields=[
                {"key": "name", "label": "Server name"},
                {"key": "address", "label": "IPv4 address"},
                {"key": "key", "label": "Key"},
                {"key": "auth_port", "label": "Auth port", "default": "1812", "width": 8},
                {"key": "acct_port", "label": "Acct port", "default": "1813", "width": 8},
            ],
            items=data.setdefault("radius", {}).setdefault("servers", []),
            on_change=on_change, height=3)
        form.widget(group, radius)
        form.entry(group, "radius.source_interface", "RADIUS source interface")

        group = form.group("Console line")
        form.check(group, "console.login_local", "login local", default=True)
        form.entry(group, "console.password", "Console password (optional)")
        form.entry(group, "console.exec_timeout_min", "Exec timeout (min)",
                   default="10", width=8)
        form.entry(group, "console.exec_timeout_sec", "Exec timeout (sec)",
                   default="0", width=8)
        form.check(group, "console.logging_sync", "logging synchronous",
                   default=True)

        group = form.group("VTY lines")
        form.combo(group, "vty.lines", "VTY range", ["0 4", "0 15"],
                   default="0 15")
        form.combo(group, "vty.transport", "Transport input",
                   ["ssh", "telnet", "ssh telnet", "none"], default="ssh")
        form.check(group, "vty.login_local", "login local", default=True)
        form.check(group, "vty.logging_sync", "logging synchronous",
                   default=True)
        form.entry(group, "vty.exec_timeout_min", "Exec timeout (min)",
                   default="10", width=8)
        form.entry(group, "vty.exec_timeout_sec", "Exec timeout (sec)",
                   default="0", width=8)
        form.note(group, "A VTY access-class can be applied from the "
                         "Access Lists section.")

        group = form.group("Logging and NTP")
        form.entry(group, "logging_buffered", "Logging buffered (bytes)",
                   default="16384", width=12)
        form.combo(group, "logging_severity", "Buffered severity",
                   ["", "debugging", "informational", "notifications",
                    "warnings", "errors", "critical"], default="")
        form.entry(group, "logging_source_interface", "Logging source interface")
        form.entry(group, "logging_hosts", "Logging hosts (comma separated)")
        form.entry(group, "ntp_source_interface", "NTP source interface")
        form.entry(group, "ntp_servers", "NTP servers (comma separated)")
        form.check(group, "ntp_authentication.enabled", "NTP authentication")
        form.entry(group, "ntp_authentication.key_id", "NTP auth key ID", width=8)
        form.entry(group, "ntp_authentication.key", "NTP auth key")
        form.entry(group, "ntp_authentication.trusted_key", "Trusted key", width=8)

        group = form.group("SNMP")
        form.entry(group, "snmp.location", "Location")
        form.entry(group, "snmp.contact", "Contact")
        form.entry(group, "snmp.source_interface", "SNMP source interface")
        form.newline(group)
        communities = TableEditor(
            group, "Communities",
            columns=[("community", "Community", 160), ("mode", "Mode", 60)],
            fields=[
                {"key": "community", "label": "Community string"},
                {"key": "mode", "label": "Mode", "type": "combo",
                 "values": ["RO", "RW"], "default": "RO"},
            ],
            items=data.setdefault("snmp", {}).setdefault("communities", []),
            on_change=on_change, height=3)
        form.widget(group, communities)
        views = TableEditor(
            group, "SNMPv3 views",
            columns=[("name", "View", 120), ("oid", "OID", 120),
                     ("action", "Action", 80)],
            fields=[
                {"key": "name", "label": "View name"},
                {"key": "oid", "label": "OID", "default": "iso"},
                {"key": "action", "label": "Action", "type": "combo",
                 "values": ["included", "excluded"], "default": "included"},
            ],
            items=data.setdefault("snmp", {}).setdefault("views", []),
            on_change=on_change, height=3)
        form.widget(group, views)
        groups = TableEditor(
            group, "SNMPv3 groups",
            columns=[("name", "Group", 120), ("version", "Version", 90),
                     ("view", "View", 100), ("acl", "ACL", 80)],
            fields=[
                {"key": "name", "label": "Group name"},
                {"key": "version", "label": "Version/security", "type": "combo",
                 "values": ["v3 priv", "v3 auth", "v3 noauth"], "default": "v3 priv"},
                {"key": "view", "label": "Read view"},
                {"key": "acl", "label": "Access ACL"},
            ],
            items=data["snmp"].setdefault("groups", []),
            on_change=on_change, height=3)
        form.widget(group, groups)
        snmp_users = TableEditor(
            group, "SNMPv3 users",
            columns=[("username", "User", 120), ("group", "Group", 120)],
            fields=[
                {"key": "username", "label": "Username"},
                {"key": "group", "label": "Group"},
                {"key": "auth_protocol", "label": "Auth protocol", "type": "combo",
                 "values": ["", "sha", "md5"], "default": "sha"},
                {"key": "auth_key", "label": "Auth key"},
                {"key": "priv_protocol", "label": "Privacy protocol", "type": "combo",
                 "values": ["", "aes 128", "des"], "default": "aes 128"},
                {"key": "priv_key", "label": "Privacy key"},
            ],
            items=data["snmp"].setdefault("users", []),
            on_change=on_change, height=3)
        form.widget(group, snmp_users)

        group = form.group("Automation and monitoring services")
        if profile.os_type == "IOS-XE":
            form.check(group, "restconf_enabled", "Enable RESTCONF")
            form.check(group, "netconf_enabled", "Enable NETCONF/YANG")
        else:
            form.note(group, "RESTCONF/NETCONF are IOS-XE features and are "
                             "not offered for this platform.")
        form.check(group, "scp_server_enabled", "Enable SCP server")
        form.check(group, "netflow.enabled", "Flexible NetFlow")
        form.entry(group, "netflow.exporter", "Exporter name")
        form.entry(group, "netflow.destination", "Collector IP")
        form.entry(group, "netflow.source_interface", "Source interface")
        form.entry(group, "netflow.transport_port", "UDP port",
                   default="2055", width=8)
        form.entry(group, "netflow.interfaces",
                   "Monitor input on interfaces (comma separated)")

        group = form.group("Management addressing")
        if profile.supports("svi"):
            form.check(group, "mgmt_svi.enabled", "Management SVI")
            form.entry(group, "mgmt_svi.vlan", "SVI VLAN", default="99",
                       width=8)
            form.entry(group, "mgmt_svi.ip", "SVI IP address")
            form.entry(group, "mgmt_svi.mask", "SVI subnet mask")
            form.entry(group, "mgmt_svi.description", "SVI description",
                       default="Management")
            form.newline(group)
        form.check(group, "mgmt_interface.enabled",
                   "Dedicated management interface")
        form.entry(group, "mgmt_interface.name", "Interface name")
        form.entry(group, "mgmt_interface.ip", "IP address")
        form.entry(group, "mgmt_interface.mask", "Subnet mask")
        form.newline(group)
        if profile.is_switch and not profile.is_l3:
            form.entry(group, "default_gateway",
                       "Default gateway (ip default-gateway)")
        else:
            form.entry(group, "default_route",
                       "Default route next hop (0.0.0.0/0)")
