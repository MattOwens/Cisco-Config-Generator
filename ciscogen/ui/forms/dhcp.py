"""DHCP server form: excluded ranges and pools."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class DhcpForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["dhcp"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("Excluded addresses")
        excluded = TableEditor(
            group, "",
            columns=[("start", "Start", 150), ("end", "End (optional)", 150)],
            fields=[
                {"key": "start", "label": "Start address"},
                {"key": "end", "label": "End address (blank = single)"},
            ],
            items=data.setdefault("excluded", []), on_change=on_change,
            height=4)
        form.widget(group, excluded)

        group = form.group("DHCP pools")
        pools = TableEditor(
            group, "",
            columns=[("name", "Pool", 110), ("network", "Network", 110),
                     ("mask", "Mask", 110),
                     ("default_router", "Gateway", 110),
                     ("dns", "DNS", 130)],
            fields=[
                {"key": "name", "label": "Pool name"},
                {"key": "network", "label": "Network"},
                {"key": "mask", "label": "Subnet mask"},
                {"key": "default_router", "label": "Default router"},
                {"key": "dns", "label": "DNS servers (comma separated)"},
                {"key": "domain", "label": "Domain name"},
                {"key": "lease_days", "label": "Lease (days)", "width": 6},
                {"key": "option150", "label": "Option 150 (TFTP for phones)"},
            ],
            items=data.setdefault("pools", []), on_change=on_change, height=5)
        form.widget(group, pools)
        form.note(group, "DHCP relay: set 'IP helper addresses' on the SVI or "
                         "routed interface in the Interfaces section.")

        group = form.group("Static address reservations")
        bindings = TableEditor(
            group, "",
            columns=[("name", "Pool", 120), ("host_ip", "Host IP", 130),
                     ("mac", "MAC", 150),
                     ("default_router", "Gateway", 120)],
            fields=[
                {"key": "name", "label": "Reservation pool name"},
                {"key": "host_ip", "label": "Host IP"},
                {"key": "mask", "label": "Mask", "default": "255.255.255.0"},
                {"key": "mac", "label": "Hardware address (aabb.ccdd.eeff)"},
                {"key": "client_id", "label": "Client-identifier (optional)"},
                {"key": "default_router", "label": "Default router (optional)"},
            ],
            items=data.setdefault("static_bindings", []), on_change=on_change,
            height=4)
        form.widget(group, bindings)
