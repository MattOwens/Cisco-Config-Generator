"""NAT / PAT form."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class NatForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["nat"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("NAT interface roles")
        form.entry(group, "inside_interfaces",
                   "Inside interfaces (comma separated)", width=32)
        form.entry(group, "outside_interfaces",
                   "Outside interfaces (comma separated)", width=32)
        form.note(group, "These interfaces get 'ip nat inside' / "
                         "'ip nat outside'. Interface names are merged into "
                         "the Interfaces section output when defined there.")

        group = form.group("Static NAT")
        static = TableEditor(
            group, "",
            columns=[("inside_local", "Inside local", 130),
                     ("inside_global", "Inside global", 130),
                     ("protocol", "Proto", 60),
                     ("local_port", "L.port", 60),
                     ("global_port", "G.port", 60)],
            fields=[
                {"key": "inside_local", "label": "Inside local IP"},
                {"key": "inside_global", "label": "Inside global IP"},
                {"key": "protocol", "label": "Protocol (port static)",
                 "type": "combo", "values": ["", "tcp", "udp"], "default": ""},
                {"key": "local_port", "label": "Local port", "width": 8},
                {"key": "global_port", "label": "Global port", "width": 8},
            ],
            items=data.setdefault("static_rules", []), on_change=on_change,
            height=4)
        form.widget(group, static)

        group = form.group("Dynamic NAT / PAT")
        form.check(group, "dynamic_enabled", "Enable dynamic NAT/PAT")
        form.entry(group, "dynamic_acl", "Source ACL (name or number)")
        form.check(group, "use_pool", "Use address pool (else interface PAT)")
        form.entry(group, "overload_interface",
                   "Outside interface for PAT (e.g. Gi0/0/0)")
        form.entry(group, "pool_name", "Pool name")
        form.check(group, "overload", "Overload (PAT) on pool", default=True)
        form.entry(group, "pool_start", "Pool start address")
        form.entry(group, "pool_end", "Pool end address")
        form.entry(group, "pool_mask", "Pool netmask")
        form.note(group, "Define the source ACL in the Access Lists section "
                         "(e.g. a standard ACL permitting your inside "
                         "subnets).")
