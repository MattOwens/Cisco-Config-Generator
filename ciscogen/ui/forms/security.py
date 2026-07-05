"""Security hardening form."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder


class SecurityForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["security"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("Disable unused services")
        form.check(group, "disable_http", "no ip http server", default=True)
        form.check(group, "disable_https", "no ip http secure-server",
                   default=True)
        form.check(group, "no_small_servers",
                   "no tcp/udp small servers", default=True)
        form.check(group, "no_pad", "no service pad", default=True)
        form.check(group, "no_ip_source_route", "no ip source-route",
                   default=True)
        form.check(group, "tcp_keepalives",
                   "service tcp-keepalives in/out", default=True)

        group = form.group("Login protection")
        form.check(group, "login_block_enabled", "login block-for")
        form.newline(group)
        form.entry(group, "login_block_seconds", "Block for (seconds)",
                   default="120", width=8)
        form.entry(group, "login_block_attempts", "Failed attempts",
                   default="3", width=8)
        form.entry(group, "login_block_within", "Within (seconds)",
                   default="60", width=8)
        form.entry(group, "min_password_length",
                   "Minimum password length (blank = off)", width=8)

        group = form.group("Management plane")
        form.check(group, "ssh_only",
                   "SSH only: force 'transport input ssh' on VTY "
                   "(disables Telnet)", default=True)
        form.note(group, "Enable secret, service password-encryption, local "
                         "user privilege levels, AAA, NTP, logging, SNMP and "
                         "the management SVI/interface are configured in the "
                         "Base System section. Secure the VTY lines with an "
                         "access-class from the Access Lists section.")
