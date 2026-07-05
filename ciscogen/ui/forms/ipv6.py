"""IPv6 form."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class Ipv6Form(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["ipv6"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("Global IPv6")
        form.check(group, "unicast_routing", "ipv6 unicast-routing")

        group = form.group("Interface IPv6")
        addresses = TableEditor(
            group, "",
            columns=[("interface", "Interface", 160), ("address", "Address", 180),
                     ("suppress_ra", "RA suppress", 90)],
            fields=[
                {"key": "interface", "label": "Interface"},
                {"key": "address", "label": "IPv6 address/prefix"},
                {"key": "eui64", "label": "Use eui-64", "type": "check"},
                {"key": "suppress_ra", "label": "Suppress RA", "type": "check"},
            ],
            items=data.setdefault("interface_addresses", []),
            on_change=on_change, height=5)
        form.widget(group, addresses)
        relays = TableEditor(
            group, "IPv6 DHCP relay",
            columns=[("interface", "Interface", 160), ("destination", "Destination", 180)],
            fields=[
                {"key": "interface", "label": "Interface"},
                {"key": "destination", "label": "Relay destination IPv6"},
            ],
            items=data.setdefault("dhcp_relays", []), on_change=on_change,
            height=3)
        form.widget(group, relays)

        group = form.group("IPv6 static routes")
        routes = TableEditor(
            group, "",
            columns=[("prefix", "Prefix", 180), ("next_hop", "Next hop", 160),
                     ("exit_interface", "Exit interface", 140)],
            fields=[
                {"key": "prefix", "label": "Prefix (2001:db8::/64)"},
                {"key": "next_hop", "label": "Next hop"},
                {"key": "exit_interface", "label": "Exit interface"},
                {"key": "distance", "label": "Admin distance", "width": 8},
                {"key": "vrf", "label": "VRF (optional)"},
            ],
            items=data.setdefault("static_routes", []), on_change=on_change,
            height=4)
        form.widget(group, routes)

        group = form.group("IPv6 ACLs")
        acls = TableEditor(
            group, "IPv6 ACLs (simple rule rows)",
            columns=[("name", "Name", 140), ("rules", "Rules", 260)],
            fields=[
                {"key": "name", "label": "ACL name"},
                {"key": "rules", "label": "Rules as JSON/list (advanced)", "width": 32},
            ],
            items=data.setdefault("acls", []), on_change=on_change, height=3)
        form.widget(group, acls)

        group = form.group("OSPFv3")
        form.check(group, "ospfv3.enabled", "Enable OSPFv3")
        form.entry(group, "ospfv3.process_id", "Process ID", default="1", width=8)
        form.entry(group, "ospfv3.router_id", "Router ID")
        ospf_ints = TableEditor(
            group, "OSPFv3 interfaces",
            columns=[("interface", "Interface", 160), ("area", "Area", 80),
                     ("network_type", "Network type", 140)],
            fields=[
                {"key": "interface", "label": "Interface"},
                {"key": "area", "label": "Area", "default": "0", "width": 8},
                {"key": "network_type", "label": "Network type", "type": "combo",
                 "values": ["", "point-to-point", "broadcast", "point-to-multipoint"],
                 "default": ""},
                {"key": "cost", "label": "Cost", "width": 8},
            ],
            items=data.setdefault("ospfv3", {}).setdefault("interfaces", []),
            on_change=on_change, height=3)
        form.widget(group, ospf_ints)
