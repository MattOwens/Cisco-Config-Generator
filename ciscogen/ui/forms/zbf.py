"""Zone-Based Firewall form."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class ZbfForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["zbf"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("Zones")
        zones = TableEditor(
            group, "",
            columns=[("name", "Zone", 120), ("description", "Description", 220)],
            fields=[
                {"key": "name", "label": "Zone name"},
                {"key": "description", "label": "Description"},
            ],
            items=data.setdefault("zones", []), on_change=on_change, height=4)
        form.widget(group, zones)
        memberships = TableEditor(
            group, "Interface zone membership",
            columns=[("interface", "Interface", 160), ("zone", "Zone", 120)],
            fields=[
                {"key": "interface", "label": "Interface"},
                {"key": "zone", "label": "Zone"},
            ],
            items=data.setdefault("interface_memberships", []),
            on_change=on_change, height=4)
        form.widget(group, memberships)

        group = form.group("Class maps")
        classes = TableEditor(
            group, "",
            columns=[("name", "Class map", 140), ("protocols", "Protocols", 180),
                     ("acl", "ACL", 100)],
            fields=[
                {"key": "name", "label": "Class map name"},
                {"key": "match_type", "label": "Match type", "type": "combo",
                 "values": ["match-any", "match-all"], "default": "match-any"},
                {"key": "protocols", "label": "Protocols (comma separated)"},
                {"key": "acl", "label": "Match ACL name"},
            ],
            items=data.setdefault("class_maps", []), on_change=on_change,
            height=4)
        form.widget(group, classes)

        group = form.group("Policy maps and zone pairs")
        policies = TableEditor(
            group, "Policy maps",
            columns=[("name", "Policy", 140), ("classes", "Classes", 180),
                     ("class_default_action", "Default", 80)],
            fields=[
                {"key": "name", "label": "Policy map name"},
                {"key": "classes", "label": "Classes (comma list; action inspect)"},
                {"key": "class_default_action", "label": "Class-default action",
                 "type": "combo", "values": ["", "drop", "pass", "inspect"],
                 "default": "drop"},
            ],
            items=data.setdefault("policy_maps", []), on_change=on_change,
            height=4)
        form.widget(group, policies)
        pairs = TableEditor(
            group, "Zone pairs",
            columns=[("name", "Name", 130), ("source", "Source", 100),
                     ("destination", "Destination", 110), ("policy", "Policy", 130)],
            fields=[
                {"key": "name", "label": "Zone-pair name"},
                {"key": "source", "label": "Source zone"},
                {"key": "destination", "label": "Destination zone"},
                {"key": "policy", "label": "Policy map"},
            ],
            items=data.setdefault("zone_pairs", []), on_change=on_change,
            height=4)
        form.widget(group, pairs)
        form.check(group, "self_zone_warnings", "Warn on self-zone exposure",
                   default=True)
