"""Static routing & PBR form."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class Layer3Form(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["layer3"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        static_routing_supported = (
            profile.is_router
            or profile.supports("layer3")
            or profile.supports("static_routing")
        )
        pbr_supported = profile.is_router or profile.supports("layer3") \
            or profile.supports("pbr")

        if profile.is_switch and static_routing_supported:
            group = form.group("Layer 3 switching")
            form.check(group, "ip_routing", "Enable 'ip routing' globally",
                       default=True)

        group = form.group("Static routes")
        routes = TableEditor(
            group, "",
            columns=[("prefix", "Prefix", 120), ("mask", "Mask", 120),
                     ("next_hop", "Next hop", 110),
                     ("exit_interface", "Exit intf", 100),
                     ("distance", "AD", 40), ("name", "Name", 100)],
            fields=[
                {"key": "prefix", "label": "Destination prefix"},
                {"key": "mask", "label": "Subnet mask"},
                {"key": "next_hop", "label": "Next hop IP"},
                {"key": "exit_interface", "label": "Exit interface (optional)"},
                {"key": "distance", "label": "Admin distance (floating)",
                 "width": 8},
                {"key": "name", "label": "Route name (optional)"},
                {"key": "permanent", "label": "Permanent", "type": "check"},
            ],
            items=data.setdefault("static_routes", []), on_change=on_change,
            height=6)
        form.widget(group, routes)
        form.note(group, "Default route: prefix 0.0.0.0 mask 0.0.0.0. "
                         "Floating static: set a higher admin distance "
                         "(e.g. 250).")

        if pbr_supported:
            group = form.group("Prefix lists")
            prefix_lists = TableEditor(
                group, "",
                columns=[("name", "Name", 120), ("seq", "Seq", 50),
                         ("action", "Action", 70), ("prefix", "Prefix", 140)],
                fields=[
                    {"key": "name", "label": "List name"},
                    {"key": "seq", "label": "Sequence", "width": 8},
                    {"key": "action", "label": "Action", "type": "combo",
                     "values": ["permit", "deny"], "default": "permit"},
                    {"key": "prefix", "label": "Prefix (a.b.c.d/len)"},
                    {"key": "ge", "label": "ge (optional)", "width": 6},
                    {"key": "le", "label": "le (optional)", "width": 6},
                ],
                items=data.setdefault("prefix_lists", []), on_change=on_change,
                height=3)
            form.widget(group, prefix_lists)

            group = form.group("Route maps (policy-based routing)")
            route_maps = TableEditor(
                group, "",
                columns=[("name", "Name", 120), ("seq", "Seq", 50),
                         ("action", "Action", 70),
                         ("match_acl", "Match ACL", 100),
                         ("set_next_hop", "Set next-hop", 110)],
                fields=[
                    {"key": "name", "label": "Route-map name"},
                    {"key": "seq", "label": "Sequence", "default": "10",
                     "width": 8},
                    {"key": "action", "label": "Action", "type": "combo",
                     "values": ["permit", "deny"], "default": "permit"},
                    {"key": "match_acl", "label": "Match ACL (optional)"},
                    {"key": "match_prefix_list",
                     "label": "Match prefix-list (optional)"},
                    {"key": "set_next_hop", "label": "Set IP next-hop"},
                ],
                items=data.setdefault("route_maps", []), on_change=on_change,
                height=3)
            form.widget(group, route_maps)

            pbr_apply = TableEditor(
                group, "Apply route-map to interface (ip policy)",
                columns=[("interface", "Interface", 160),
                         ("route_map", "Route-map", 140)],
                fields=[
                    {"key": "interface", "label": "Interface"},
                    {"key": "route_map", "label": "Route-map name"},
                ],
                items=data.setdefault("pbr_apply", []), on_change=on_change,
                height=3)
            form.widget(group, pbr_apply)
            form.note(group, "Redistribution into dynamic protocols is configured "
                             "in the Routing Protocols section.")
