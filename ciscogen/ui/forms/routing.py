"""Routing protocols form: OSPF, EIGRP, BGP, RIP."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class RoutingForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["routing"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        # ---------------------------------------------------------- OSPF --
        group = form.group("OSPF")
        form.check(group, "ospf.enabled", "Enable OSPF")
        form.newline(group)
        form.entry(group, "ospf.process_id", "Process ID", default="1",
                   width=8)
        form.entry(group, "ospf.router_id", "Router ID (a.b.c.d)")
        networks = TableEditor(
            group, "Networks",
            columns=[("network", "Network", 130),
                     ("wildcard", "Wildcard", 130), ("area", "Area", 70)],
            fields=[
                {"key": "network", "label": "Network"},
                {"key": "wildcard", "label": "Wildcard mask"},
                {"key": "area", "label": "Area", "default": "0", "width": 8},
            ],
            items=data.setdefault("ospf", {}).setdefault("networks", []),
            on_change=on_change, height=3)
        form.widget(group, networks)
        form.check(group, "ospf.passive_default", "passive-interface default")
        form.entry(group, "ospf.passive_interfaces",
                   "Passive interfaces (comma separated)")
        form.check(group, "ospf.default_originate",
                   "default-information originate")
        form.check(group, "ospf.default_originate_always", "... always")
        form.entry(group, "ospf.area_auth_area",
                   "Area authentication for area (optional)", width=8)
        form.check(group, "ospf.area_auth_md5", "Use MD5 (message-digest)",
                   default=True)
        form.check(group, "ospf.redistribute_connected",
                   "redistribute connected subnets")
        form.check(group, "ospf.redistribute_static",
                   "redistribute static subnets")

        # --------------------------------------------------------- EIGRP --
        group = form.group("EIGRP")
        form.check(group, "eigrp.enabled", "Enable EIGRP")
        form.newline(group)
        form.entry(group, "eigrp.asn", "AS number", width=8)
        form.entry(group, "eigrp.router_id", "Router ID (optional)")
        eigrp_networks = TableEditor(
            group, "Networks",
            columns=[("network", "Network", 140),
                     ("wildcard", "Wildcard (optional)", 140)],
            fields=[
                {"key": "network", "label": "Network"},
                {"key": "wildcard", "label": "Wildcard mask (optional)"},
            ],
            items=data.setdefault("eigrp", {}).setdefault("networks", []),
            on_change=on_change, height=3)
        form.widget(group, eigrp_networks)
        form.entry(group, "eigrp.passive_interfaces",
                   "Passive interfaces (comma separated)")
        form.check(group, "eigrp.no_auto_summary", "no auto-summary",
                   default=True)
        form.check(group, "eigrp.redistribute_static", "redistribute static")

        # ----------------------------------------------------------- BGP --
        group = form.group("BGP")
        form.check(group, "bgp.enabled", "Enable BGP")
        form.newline(group)
        form.entry(group, "bgp.asn", "Local AS number", width=12)
        form.entry(group, "bgp.router_id", "Router ID (optional)")
        neighbors = TableEditor(
            group, "Neighbors",
            columns=[("ip", "Neighbor IP", 120), ("remote_as", "Remote AS", 80),
                     ("description", "Description", 140),
                     ("update_source", "Update source", 110)],
            fields=[
                {"key": "ip", "label": "Neighbor IP"},
                {"key": "remote_as", "label": "Remote AS", "width": 10},
                {"key": "description", "label": "Description"},
                {"key": "update_source",
                 "label": "Update source (e.g. Loopback0)"},
                {"key": "ebgp_multihop", "label": "eBGP multihop TTL "
                                                  "(optional)", "width": 6},
            ],
            items=data.setdefault("bgp", {}).setdefault("neighbors", []),
            on_change=on_change, height=3)
        form.widget(group, neighbors)
        bgp_networks = TableEditor(
            group, "Networks",
            columns=[("network", "Network", 140), ("mask", "Mask", 140)],
            fields=[
                {"key": "network", "label": "Network"},
                {"key": "mask", "label": "Mask (optional, classful if blank)"},
            ],
            items=data.setdefault("bgp", {}).setdefault("networks", []),
            on_change=on_change, height=3)
        form.widget(group, bgp_networks)

        # ----------------------------------------------------------- RIP --
        group = form.group("RIP (legacy)")
        form.check(group, "rip.enabled", "Enable RIP")
        form.newline(group)
        form.check(group, "rip.version2", "Version 2", default=True)
        form.check(group, "rip.no_auto_summary", "no auto-summary",
                   default=True)
        form.entry(group, "rip.networks",
                   "Networks (classful, comma separated)", width=32)
        form.entry(group, "rip.passive_interfaces",
                   "Passive interfaces (comma separated)", width=32)
