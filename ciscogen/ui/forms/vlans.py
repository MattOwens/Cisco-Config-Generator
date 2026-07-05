"""VLANs & Layer 2 form: VLAN table, STP, DHCP snooping, DAI, VTP."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class VlansForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["vlans"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("VLANs")
        vlans = TableEditor(
            group, "",
            columns=[("id", "VLAN ID", 80), ("name", "Name", 220)],
            fields=[
                {"key": "id", "label": "VLAN ID (1-4094)", "width": 8},
                {"key": "name", "label": "Name"},
            ],
            items=data.setdefault("vlans", []), on_change=on_change, height=6)
        form.widget(group, vlans)
        if not profile.supports("layer2"):
            form.note(group, "Routed-only routers do not use switchport VLANs. "
                             "Use these VLAN IDs for planning and configure "
                             "router-on-a-stick under Interfaces > Subinterfaces.")
            return
        form.entry(group, "blackhole_vlan",
                   "Blackhole VLAN for unused ports (optional)", width=8)

        group = form.group("Spanning tree")
        form.combo(group, "stp.mode", "STP mode",
                   ["pvst", "rapid-pvst", "mst"], default="rapid-pvst")
        form.newline(group)
        form.check(group, "stp.portfast_default", "PortFast default")
        form.check(group, "stp.bpduguard_default", "BPDU Guard default")
        form.entry(group, "stp.root_primary",
                   "Root primary for VLANs (e.g. 10,20)")
        form.entry(group, "stp.root_secondary", "Root secondary for VLANs")
        form.entry(group, "stp.priority_vlans", "Set priority for VLANs")
        form.entry(group, "stp.priority_value",
                   "Priority value (0-61440, step 4096)", width=10)

        if profile.supports("dhcp_snooping"):
            group = form.group("DHCP snooping")
            form.check(group, "dhcp_snooping.enabled", "Enable DHCP snooping")
            form.newline(group)
            form.entry(group, "dhcp_snooping.vlans", "VLAN list (e.g. 10,20)")
            form.entry(group, "dhcp_snooping.trusted_interfaces",
                       "Trusted interfaces (comma separated)")

        if profile.supports("dai"):
            group = form.group("Dynamic ARP Inspection")
            form.check(group, "dai.enabled", "Enable DAI")
            form.newline(group)
            form.entry(group, "dai.vlans", "VLAN list")
            form.entry(group, "dai.trusted_interfaces",
                       "Trusted interfaces (comma separated)")

        if profile.supports("vtp"):
            group = form.group("VTP")
            form.check(group, "vtp.enabled", "Configure VTP")
            form.combo(group, "vtp.mode", "Mode",
                       ["transparent", "server", "client", "off"],
                       default="transparent")
            form.entry(group, "vtp.domain", "Domain")
            form.entry(group, "vtp.password", "Password (optional)")

        group = form.group("Enterprise switch extras")
        form.check(group, "errdisable_recovery.enabled",
                   "Enable errdisable recovery")
        form.entry(group, "errdisable_recovery.causes",
                   "Recovery causes (comma separated)")
        form.entry(group, "errdisable_recovery.interval",
                   "Recovery interval seconds", default="300", width=8)
        private_vlans = TableEditor(
            group, "Private VLANs",
            columns=[("primary", "Primary", 80), ("secondary", "Secondary", 90),
                     ("type", "Type", 100)],
            fields=[
                {"key": "primary", "label": "Primary VLAN", "width": 8},
                {"key": "secondary", "label": "Secondary VLAN", "width": 8},
                {"key": "type", "label": "Type", "type": "combo",
                 "values": ["isolated", "community"], "default": "isolated"},
            ],
            items=data.setdefault("private_vlans", []),
            on_change=on_change, height=3)
        form.widget(group, private_vlans)
        span = TableEditor(
            group, "SPAN sessions",
            columns=[("session", "Session", 70), ("source", "Source", 150),
                     ("destination", "Destination", 150)],
            fields=[
                {"key": "session", "label": "Session", "width": 8},
                {"key": "source", "label": "Source interface"},
                {"key": "direction", "label": "Direction", "type": "combo",
                 "values": ["both", "rx", "tx"], "default": "both"},
                {"key": "destination", "label": "Destination interface"},
            ],
            items=data.setdefault("span_sessions", []),
            on_change=on_change, height=3)
        form.widget(group, span)
        form.check(group, "stackwise.enabled", "StackWise priority")
        form.entry(group, "stackwise.switch_number", "Switch number", width=8)
        form.entry(group, "stackwise.priority", "Priority", width=8)
