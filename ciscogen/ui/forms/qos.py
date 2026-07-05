"""QoS form."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class QosForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["qos"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("Interface QoS helpers")
        trust = TableEditor(
            group, "Trust boundaries",
            columns=[("interface", "Interface", 160), ("mode", "Trust", 80)],
            fields=[
                {"key": "interface", "label": "Interface"},
                {"key": "mode", "label": "Trust mode", "type": "combo",
                 "values": ["dscp", "cos"], "default": "dscp"},
            ],
            items=data.setdefault("trust", []), on_change=on_change, height=3)
        form.widget(group, trust)
        autoqos = TableEditor(
            group, "AutoQoS helper",
            columns=[("interface", "Interface", 160), ("template", "Template", 160)],
            fields=[
                {"key": "interface", "label": "Interface"},
                {"key": "template", "label": "AutoQoS template",
                 "default": "voip cisco-phone"},
            ],
            items=data.setdefault("autoqos", []), on_change=on_change, height=3)
        form.widget(group, autoqos)

        group = form.group("Class maps and policy maps")
        classes = TableEditor(
            group, "Class maps",
            columns=[("name", "Class", 140), ("dscp", "DSCP", 100),
                     ("acl", "ACL", 100), ("protocol", "Protocol", 100)],
            fields=[
                {"key": "name", "label": "Class map name"},
                {"key": "match_type", "label": "Match type", "type": "combo",
                 "values": ["match-any", "match-all"], "default": "match-any"},
                {"key": "dscp", "label": "Match DSCP"},
                {"key": "acl", "label": "Match ACL"},
                {"key": "protocol", "label": "Match protocol"},
            ],
            items=data.setdefault("class_maps", []), on_change=on_change,
            height=4)
        form.widget(group, classes)
        policies = TableEditor(
            group, "Policy maps",
            columns=[("name", "Policy", 140), ("classes", "Classes", 220)],
            fields=[
                {"key": "name", "label": "Policy map name"},
                {"key": "classes", "label": "Classes (comma list)"},
            ],
            items=data.setdefault("policy_maps", []), on_change=on_change,
            height=4)
        form.widget(group, policies)
        service = TableEditor(
            group, "Service policy bindings",
            columns=[("interface", "Interface", 160), ("direction", "Direction", 80),
                     ("policy", "Policy", 140)],
            fields=[
                {"key": "interface", "label": "Interface"},
                {"key": "direction", "label": "Direction", "type": "combo",
                 "values": ["input", "output"], "default": "output"},
                {"key": "policy", "label": "Policy map"},
            ],
            items=data.setdefault("service_policies", []),
            on_change=on_change, height=4)
        form.widget(group, service)
