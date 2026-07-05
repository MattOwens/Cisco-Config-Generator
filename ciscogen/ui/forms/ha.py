"""Gateway redundancy form."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class HaForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["ha"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("Gateway redundancy groups")
        groups = TableEditor(
            group, "",
            columns=[("protocol", "Protocol", 80), ("interface", "Interface", 150),
                     ("group", "Group", 60), ("virtual_ip", "Virtual IP", 120),
                     ("priority", "Pri", 50), ("preempt", "Preempt", 70)],
            fields=[
                {"key": "protocol", "label": "Protocol", "type": "combo",
                 "values": ["hsrp", "vrrp", "glbp"], "default": "hsrp"},
                {"key": "interface", "label": "Interface/SVI"},
                {"key": "group", "label": "Group number", "default": "1", "width": 8},
                {"key": "virtual_ip", "label": "Virtual IP"},
                {"key": "priority", "label": "Priority", "default": "110", "width": 8},
                {"key": "preempt", "label": "Preempt", "type": "check", "default": True},
                {"key": "auth", "label": "Authentication text"},
                {"key": "track_id", "label": "Track ID", "width": 8},
                {"key": "decrement", "label": "Track decrement", "default": "10", "width": 8},
            ],
            items=data.setdefault("groups", []), on_change=on_change, height=6)
        form.widget(group, groups)
