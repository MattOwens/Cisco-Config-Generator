"""VRF-Lite form."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class VrfForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["vrf"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("VRF definitions")
        vrfs = TableEditor(
            group, "",
            columns=[("name", "Name", 120), ("rd", "RD", 100),
                     ("description", "Description", 180)],
            fields=[
                {"key": "name", "label": "VRF name"},
                {"key": "rd", "label": "Route distinguisher"},
                {"key": "description", "label": "Description"},
                {"key": "address_family_ipv4", "label": "Address-family IPv4",
                 "type": "check", "default": True},
            ],
            items=data.setdefault("vrfs", []), on_change=on_change, height=4)
        form.widget(group, vrfs)

        group = form.group("Interface assignments and relay")
        assignments = TableEditor(
            group, "Assign interfaces to VRFs",
            columns=[("interface", "Interface", 170), ("vrf", "VRF", 120)],
            fields=[
                {"key": "interface", "label": "Interface"},
                {"key": "vrf", "label": "VRF name"},
            ],
            items=data.setdefault("interface_assignments", []),
            on_change=on_change, height=4)
        form.widget(group, assignments)
        relays = TableEditor(
            group, "VRF-aware DHCP relay helpers",
            columns=[("interface", "Interface", 160), ("vrf", "VRF", 100),
                     ("helper", "Helper", 120)],
            fields=[
                {"key": "interface", "label": "Interface"},
                {"key": "vrf", "label": "VRF name"},
                {"key": "helper", "label": "Helper address"},
            ],
            items=data.setdefault("dhcp_relays", []), on_change=on_change,
            height=3)
        form.widget(group, relays)

        group = form.group("VRF-aware static routes")
        routes = TableEditor(
            group, "",
            columns=[("vrf", "VRF", 100), ("prefix", "Prefix", 120),
                     ("next_hop", "Next hop", 120), ("distance", "AD", 40)],
            fields=[
                {"key": "vrf", "label": "VRF name"},
                {"key": "prefix", "label": "Prefix"},
                {"key": "mask", "label": "Mask"},
                {"key": "exit_interface", "label": "Exit interface"},
                {"key": "next_hop", "label": "Next hop"},
                {"key": "distance", "label": "Admin distance", "width": 8},
            ],
            items=data.setdefault("static_routes", []), on_change=on_change,
            height=4)
        form.widget(group, routes)
