"""IP SLA and object tracking form."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class IpslaForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["ipsla"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("IP SLA operations")
        operations = TableEditor(
            group, "",
            columns=[("id", "ID", 50), ("type", "Type", 100),
                     ("target", "Target", 140), ("frequency", "Freq", 60)],
            fields=[
                {"key": "id", "label": "Operation ID", "width": 8},
                {"key": "type", "label": "Type", "type": "combo",
                 "values": ["icmp-echo", "tcp-connect", "udp-jitter"],
                 "default": "icmp-echo"},
                {"key": "target", "label": "Target IP/host"},
                {"key": "source_interface", "label": "Source interface"},
                {"key": "port", "label": "TCP/UDP port", "width": 8},
                {"key": "frequency", "label": "Frequency", "default": "5", "width": 8},
                {"key": "timeout", "label": "Timeout ms", "default": "1000", "width": 8},
                {"key": "threshold", "label": "Threshold ms", "width": 8},
                {"key": "schedule", "label": "Schedule",
                 "default": "life forever start-time now", "width": 28},
            ],
            items=data.setdefault("operations", []), on_change=on_change, height=5)
        form.widget(group, operations)

        group = form.group("Object tracking")
        tracks = TableEditor(
            group, "",
            columns=[("id", "Track", 60), ("sla_id", "SLA", 60),
                     ("type", "Type", 100)],
            fields=[
                {"key": "id", "label": "Track ID", "width": 8},
                {"key": "sla_id", "label": "IP SLA ID", "width": 8},
                {"key": "type", "label": "Track type", "type": "combo",
                 "values": ["reachability"], "default": "reachability"},
                {"key": "delay_up", "label": "Delay up", "width": 8},
                {"key": "delay_down", "label": "Delay down", "width": 8},
            ],
            items=data.setdefault("tracks", []), on_change=on_change, height=4)
        form.widget(group, tracks)

        group = form.group("Tracked and floating routes")
        tracked = TableEditor(
            group, "Primary tracked static routes",
            columns=[("prefix", "Prefix", 120), ("next_hop", "Next hop", 110),
                     ("track_id", "Track", 60), ("distance", "AD", 40)],
            fields=[
                {"key": "prefix", "label": "Prefix"},
                {"key": "mask", "label": "Mask"},
                {"key": "next_hop", "label": "Next hop"},
                {"key": "track_id", "label": "Track ID", "width": 8},
                {"key": "distance", "label": "Admin distance", "width": 8},
                {"key": "name", "label": "Route name"},
            ],
            items=data.setdefault("tracked_routes", []), on_change=on_change,
            height=3)
        form.widget(group, tracked)
        floating = TableEditor(
            group, "Backup floating static routes",
            columns=[("prefix", "Prefix", 120), ("next_hop", "Next hop", 110),
                     ("distance", "AD", 50)],
            fields=[
                {"key": "prefix", "label": "Prefix"},
                {"key": "mask", "label": "Mask"},
                {"key": "next_hop", "label": "Next hop"},
                {"key": "distance", "label": "Admin distance", "default": "250", "width": 8},
                {"key": "name", "label": "Route name"},
            ],
            items=data.setdefault("floating_routes", []), on_change=on_change,
            height=3)
        form.widget(group, floating)

        group = form.group("EEM on track state")
        eem = TableEditor(
            group, "",
            columns=[("name", "Applet", 120), ("track_id", "Track", 60),
                     ("state", "State", 70), ("action_cli", "Action", 180)],
            fields=[
                {"key": "name", "label": "Applet name"},
                {"key": "track_id", "label": "Track ID", "width": 8},
                {"key": "state", "label": "State", "type": "combo",
                 "values": ["up", "down"], "default": "down"},
                {"key": "action_cli", "label": "CLI action", "width": 32},
            ],
            items=data.setdefault("eem", []), on_change=on_change, height=3)
        form.widget(group, eem)
