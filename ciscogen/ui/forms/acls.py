"""Access Lists form: ACL definitions, per-ACL rule editor, bindings."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor

PROTOCOLS = ["ip", "tcp", "udp", "icmp", "gre", "esp", "ospf"]
PORT_OPS = ["", "eq", "gt", "lt", "neq", "range"]

RULE_FIELDS = [
    {"key": "action", "label": "Action", "type": "combo",
     "values": ["permit", "deny", "remark"], "default": "permit"},
    {"key": "remark", "label": "Remark text (remark only)", "width": 30},
    {"key": "protocol", "label": "Protocol (extended)", "type": "combo",
     "values": PROTOCOLS, "default": "ip"},
    {"key": "log", "label": "Log matches", "type": "check"},
    {"key": "src", "label": "Source ('any' or IP)", "default": "any"},
    {"key": "src_wildcard", "label": "Source wildcard (blank = host)"},
    {"key": "src_port_op", "label": "Src port operator", "type": "combo",
     "values": PORT_OPS, "default": ""},
    {"key": "src_port", "label": "Src port(s)", "width": 12},
    {"key": "dst", "label": "Destination ('any' or IP)", "default": "any"},
    {"key": "dst_wildcard", "label": "Dest wildcard (blank = host)"},
    {"key": "dst_port_op", "label": "Dst port operator", "type": "combo",
     "values": PORT_OPS, "default": ""},
    {"key": "dst_port", "label": "Dst port(s)", "width": 12},
    {"key": "icmp_type", "label": "ICMP type (echo, echo-reply...)",
     "width": 14},
    {"key": "established", "label": "Established (TCP)", "type": "check"},
]


class AclsForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["acls"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)
        self._acls = data.setdefault("acls", [])

        group = form.group("Access lists")
        self.acl_table = TableEditor(
            group, "ACLs (select one to edit its rules below)",
            columns=[("id", "Name / number", 140), ("type", "Type", 90)],
            fields=[
                {"key": "id", "label": "Name or number"},
                {"key": "type", "label": "Type", "type": "combo",
                 "values": ["standard", "extended"], "default": "standard"},
            ],
            items=self._acls, on_change=self._acl_list_changed, height=4,
            on_select=self._acl_selected)
        form.widget(group, self.acl_table)

        self.rules_label = ttk.Label(group, text="Rules: (no ACL selected)",
                                     font=("Segoe UI", 10, "bold"))
        form.widget(group, self.rules_label, pady=(8, 0))
        self.rule_table = TableEditor(
            group, "",
            columns=[("action", "Action", 70), ("protocol", "Proto", 60),
                     ("src", "Source", 110), ("src_wildcard", "Src wc", 90),
                     ("dst", "Destination", 110),
                     ("dst_port", "Dst port", 70),
                     ("remark", "Remark", 130)],
            fields=RULE_FIELDS,
            items=[], on_change=on_change, height=6)
        form.widget(group, self.rule_table)
        form.note(group, "Rule order is preserved exactly. Standard ACLs use "
                         "only Action/Source/Wildcard (+Remark). Every ACL "
                         "ends with an implicit 'deny any'.")
        self.summary = ttk.Label(group, text=self._summary_text(),
                                 style="Muted.TLabel", wraplength=600,
                                 justify="left")
        form.widget(group, self.summary)

        group = form.group("Apply ACLs")
        apply_table = TableEditor(
            group, "Interface bindings",
            columns=[("acl", "ACL", 120), ("interface", "Interface", 170),
                     ("direction", "Direction", 80)],
            fields=[
                {"key": "acl", "label": "ACL name/number"},
                {"key": "interface", "label": "Interface"},
                {"key": "direction", "label": "Direction", "type": "combo",
                 "values": ["in", "out"], "default": "in"},
            ],
            items=data.setdefault("interface_apply", []),
            on_change=on_change, height=3)
        form.widget(group, apply_table)
        form.entry(group, "vty_acl",
                   "VTY access-class ACL (management plane)", width=20)
        vty_bindings = TableEditor(
            group, "VTY line-range bindings",
            columns=[("acl", "ACL", 120), ("lines", "Lines", 80),
                     ("direction", "Direction", 80)],
            fields=[
                {"key": "acl", "label": "ACL name/number"},
                {"key": "lines", "label": "VTY range", "type": "combo",
                 "values": ["0 4", "0 15"], "default": "0 4"},
                {"key": "direction", "label": "Direction", "type": "combo",
                 "values": ["in", "out"], "default": "in"},
            ],
            items=data.setdefault("vty_bindings", []),
            on_change=on_change, height=3)
        form.widget(group, vty_bindings)
        route_maps = TableEditor(
            group, "Route-map ACL bindings",
            columns=[("acl", "ACL", 120), ("route_map", "Route-map", 140),
                     ("seq", "Seq", 50)],
            fields=[
                {"key": "acl", "label": "ACL name/number"},
                {"key": "route_map", "label": "Route-map name"},
                {"key": "action", "label": "Action", "type": "combo",
                 "values": ["permit", "deny"], "default": "permit"},
                {"key": "seq", "label": "Sequence", "default": "10", "width": 8},
            ],
            items=data.setdefault("route_map_bindings", []),
            on_change=on_change, height=3)
        form.widget(group, route_maps)
        form.entry(group, "management_plane_acl", "Management plane ACL")
        form.note(group, "The management-plane ACL is applied to "
                         "snmp-server community lines. NAT source ACLs are "
                         "referenced directly from the NAT / PAT section.")

        self._on_change = on_change

    def _acl_selected(self, index: int | None):
        if index is None or index >= len(self._acls):
            self.rules_label.configure(text="Rules: (no ACL selected)")
            self.rule_table.set_items([])
            return
        acl = self._acls[index]
        acl.setdefault("rules", [])
        label = acl.get("id") or "(unnamed)"
        self.rules_label.configure(
            text=f"Rules of ACL '{label}' ({acl.get('type', 'standard')})")
        self.rule_table.set_items(acl["rules"])

    def _acl_list_changed(self):
        # Rows may have been edited via the dialog, which replaces dict
        # contents; make sure each ACL keeps its rules list.
        for acl in self._acls:
            acl.setdefault("rules", [])
        self._acl_selected(self.acl_table.selected_index())
        self.summary.configure(text=self._summary_text())
        self._on_change()

    def _summary_text(self) -> str:
        if not self._acls:
            return "ACL summary: no ACLs configured."
        parts = []
        for acl in self._acls:
            rules = len(acl.get("rules", []))
            parts.append(f"{acl.get('id') or '(unnamed)'}: {acl.get('type', 'standard')} / {rules} rules")
        return "ACL summary: " + "; ".join(parts)
