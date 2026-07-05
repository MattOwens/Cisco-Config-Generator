"""Interfaces form: physical ports, port-channels, subinterfaces and SVIs."""

from __future__ import annotations

from tkinter import ttk

from ...utils import expand_interface_range
from ..widgets import Binder, FormBuilder, RowDialog, TableEditor

SPEEDS = ["auto", "10", "100", "1000", "10000"]
DUPLEX = ["auto", "full", "half"]
CHANNEL_MODES = ["active", "passive", "on", "desirable", "auto"]
VIOLATIONS = ["shutdown", "restrict", "protect"]


def physical_fields(profile) -> list[dict]:
    modes = []
    if profile.supports("layer2"):
        modes += ["access", "trunk"]
    if profile.supports("routed_ports") or profile.is_router:
        modes += ["routed"]
    if not modes:
        modes = ["access"]
    default_mode = "routed" if profile.is_router else "access"
    fields = [
        {"key": "name", "label": "Interface name", "width": 26},
        {"key": "description", "label": "Description", "width": 26},
        {"key": "enabled", "label": "Enabled (no shutdown)", "type": "check",
         "default": True},
        {"key": "mode", "label": "Mode", "type": "combo", "values": modes,
         "default": default_mode},
    ]
    if profile.supports("layer2"):
        fields += [
            {"key": "access_vlan", "label": "Access VLAN", "width": 10},
            {"key": "voice_vlan", "label": "Voice VLAN", "width": 10},
            {"key": "native_vlan", "label": "Trunk native VLAN", "width": 10},
            {"key": "allowed_vlans", "label": "Trunk allowed VLANs",
             "width": 18},
            {"key": "nonegotiate", "label": "Nonegotiate (trunk)",
             "type": "check"},
        ]
    fields += [
        {"key": "ip", "label": "IP address (routed)", "width": 18},
        {"key": "mask", "label": "Subnet mask (routed)", "width": 18},
        {"key": "helper", "label": "IP helper addresses", "width": 18},
    ]
    if profile.supports("layer2"):
        fields += [
            {"key": "portfast", "label": "PortFast (access)", "type": "check"},
            {"key": "bpduguard", "label": "BPDU Guard (access)",
             "type": "check"},
            {"key": "rootguard", "label": "Root Guard", "type": "check"},
            {"key": "storm_bc", "label": "Storm ctrl broadcast %",
             "width": 10},
            {"key": "storm_mc", "label": "Storm ctrl multicast %",
             "width": 10},
            {"key": "storm_uc", "label": "Storm ctrl unicast %",
             "width": 10},
            {"key": "ps_enabled", "label": "Port security", "type": "check"},
            {"key": "ps_max", "label": "Port security max MACs", "width": 8},
            {"key": "ps_violation", "label": "Violation mode",
             "type": "combo", "values": VIOLATIONS, "default": "shutdown"},
            {"key": "ps_sticky", "label": "Sticky MAC", "type": "check"},
            {"key": "ip_source_guard", "label": "IP Source Guard",
             "type": "check"},
            {"key": "loopguard", "label": "Loop Guard", "type": "check"},
            {"key": "udld", "label": "UDLD", "type": "check"},
            {"key": "udld_mode", "label": "UDLD mode", "type": "combo",
             "values": ["port", "port aggressive"], "default": "port aggressive"},
        ]
    if profile.supports("etherchannel"):
        fields += [
            {"key": "channel_group", "label": "Channel-group #", "width": 8},
            {"key": "channel_mode", "label": "Channel mode", "type": "combo",
             "values": CHANNEL_MODES, "default": "active"},
        ]
    fields += [
        {"key": "speed", "label": "Speed", "type": "combo", "values": SPEEDS,
         "default": "auto"},
        {"key": "duplex", "label": "Duplex", "type": "combo",
         "values": DUPLEX, "default": "auto"},
        {"key": "mtu", "label": "MTU", "width": 8},
        {"key": "cdp_disabled", "label": "Disable CDP on port",
         "type": "check"},
        {"key": "lldp_disabled", "label": "Disable LLDP on port",
         "type": "check"},
    ]
    return fields


class InterfacesForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["interfaces"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        hint = ttk.Label(
            self, style="Muted.TLabel", wraplength=640, justify="left",
            text=(f"{profile.model} ports: {profile.interface_naming}. "
                  f"{profile.interface_count} typical interfaces, e.g. "
                  f"{profile.interfaces[0]} ... {profile.interfaces[-1]}. "
                  "Short names (gi1/0/1) are expanded automatically."))
        hint.pack(fill="x", padx=12, pady=(10, 0))

        group = form.group("Physical interfaces")
        fields = physical_fields(profile)

        def add_range(editor: TableEditor):
            dialog = RowDialog(editor, "Add interface range "
                                       "(e.g. GigabitEthernet1/0/1-8)", fields)
            if dialog.result is None:
                return
            for name in expand_interface_range(dialog.result.get("name", "")):
                item = dict(dialog.result)
                item["name"] = name
                editor.items.append(item)
            editor.refresh()
            on_change()

        physical = TableEditor(
            group, "",
            columns=[("name", "Interface", 170), ("mode", "Mode", 70),
                     ("access_vlan", "VLAN", 60), ("ip", "IP address", 110),
                     ("description", "Description", 160)],
            fields=fields,
            items=data.setdefault("physical", []), on_change=on_change,
            height=8, extra_buttons=[("Add Range...", add_range)])
        form.widget(group, physical)

        if profile.supports("etherchannel"):
            group = form.group("Port-channel interfaces")
            pc_modes = ["trunk", "access"]
            if profile.supports("routed_ports") or profile.is_router:
                pc_modes.append("routed")
            port_channels = TableEditor(
                group, "",
                columns=[("id", "ID", 50), ("mode", "Mode", 70),
                         ("allowed_vlans", "Allowed VLANs", 120),
                         ("description", "Description", 180)],
                fields=[
                    {"key": "id", "label": "Port-channel ID", "width": 8},
                    {"key": "description", "label": "Description"},
                    {"key": "mode", "label": "Mode", "type": "combo",
                     "values": pc_modes, "default": pc_modes[0]},
                    {"key": "access_vlan", "label": "Access VLAN", "width": 10},
                    {"key": "native_vlan", "label": "Native VLAN", "width": 10},
                    {"key": "allowed_vlans", "label": "Allowed VLANs",
                     "width": 18},
                    {"key": "ip", "label": "IP address (routed)", "width": 18},
                    {"key": "mask", "label": "Subnet mask (routed)",
                     "width": 18},
                ],
                items=data.setdefault("port_channels", []),
                on_change=on_change, height=3)
            form.widget(group, port_channels)
            form.note(group, "Assign members with the Channel-group field on "
                             "physical interfaces. LACP: active/passive; "
                             "PAgP: desirable/auto; static: on.")

        if profile.supports("subinterfaces"):
            group = form.group("Subinterfaces (router-on-a-stick)")
            subinterfaces = TableEditor(
                group, "",
                columns=[("parent", "Parent", 150), ("vlan", "VLAN", 60),
                         ("ip", "IP address", 120),
                         ("description", "Description", 160)],
                fields=[
                    {"key": "parent", "label": "Parent interface"},
                    {"key": "vlan", "label": "Dot1Q VLAN", "width": 8},
                    {"key": "description", "label": "Description"},
                    {"key": "ip", "label": "IP address"},
                    {"key": "mask", "label": "Subnet mask"},
                    {"key": "helper", "label": "IP helper addresses"},
                    {"key": "native", "label": "Native VLAN (dot1Q native)",
                     "type": "check"},
                ],
                items=data.setdefault("subinterfaces", []),
                on_change=on_change, height=4)
            form.widget(group, subinterfaces)

        if profile.supports("svi"):
            group = form.group("SVIs (interface Vlan)")
            svis = TableEditor(
                group, "",
                columns=[("vlan", "VLAN", 60), ("ip", "IP address", 130),
                         ("mask", "Mask", 120),
                         ("description", "Description", 160)],
                fields=[
                    {"key": "vlan", "label": "VLAN ID", "width": 8},
                    {"key": "description", "label": "Description"},
                    {"key": "ip", "label": "IP address"},
                    {"key": "mask", "label": "Subnet mask"},
                    {"key": "helper", "label": "IP helper addresses"},
                    {"key": "enabled", "label": "Enabled (no shutdown)",
                     "type": "check", "default": True},
                ],
                items=data.setdefault("svis", []), on_change=on_change,
                height=4)
            form.widget(group, svis)
