"""IP Tunnels & VPN form (master/detail over a list of tunnels)."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from ...generators.tunnels import TUNNEL_TYPES, GRE_MULTIPOINT
from ...models import default_tunnel
from ..widgets import Binder, FormBuilder, RowDialog, ScrollableFrame, TableEditor


def build_tunnel_detail(parent, tunnel: dict, on_change) -> None:
    """Render the editor for a single tunnel dict into ``parent``."""
    binder = Binder(tunnel, on_change)
    form = FormBuilder(parent, binder)
    ttype = tunnel.get("type", GRE_MULTIPOINT)
    is_dmvpn = ttype == GRE_MULTIPOINT

    group = form.group("Tunnel")
    form.check(group, "enabled", "Enabled (no shutdown)", default=True)
    form.combo(group, "type", "Tunnel type", TUNNEL_TYPES, default=ttype)
    form.entry(group, "name", "Name / label")
    form.entry(group, "tunnel_number", "Tunnel number", default="0", width=8)
    form.entry(group, "description", "Description")
    form.entry(group, "vrf", "Tunnel VRF (optional)")
    form.entry(group, "tunnel_ip", "Tunnel IP")
    form.entry(group, "tunnel_mask", "Tunnel mask")
    form.entry(group, "ipv6_address", "IPv6 address (optional)")
    form.entry(group, "tunnel_source_interface", "Tunnel source interface")
    form.entry(group, "tunnel_source_ip", "Tunnel source IP")
    if not is_dmvpn:
        form.entry(group, "tunnel_destination", "Tunnel destination")
        form.entry(group, "keepalive", "Keepalive (sec retries)", width=10)
    form.entry(group, "tunnel_key", "Tunnel key (GRE)")
    form.entry(group, "ip_mtu", "IP MTU", default="1400", width=8)
    form.entry(group, "tcp_mss", "TCP MSS", default="1360", width=8)
    form.entry(group, "bandwidth", "Bandwidth", width=8)
    form.entry(group, "delay", "Delay", width=8)
    form.note(group, f"Type '{ttype}'. Change the type then reselect the "
                     "tunnel to refresh type-specific fields.")

    if is_dmvpn:
        group = form.group("DMVPN role / NHRP")
        form.combo(group, "role", "Role",
                   ["Hub", "Spoke", "Dual Hub", "Spoke with redundant hubs"],
                   default="Hub")
        form.combo(group, "phase", "Phase",
                   ["Phase 1", "Phase 2", "Phase 3"], default="Phase 3")
        form.entry(group, "nhrp_network_id", "NHRP network ID")
        form.entry(group, "nhrp_authentication", "NHRP authentication")
        form.entry(group, "nhrp_holdtime", "NHRP holdtime", default="600", width=8)
        form.combo(group, "nhrp_map_multicast", "Hub multicast map",
                   ["dynamic"], default="dynamic", editable=True)
        form.check(group, "nhrp_redirect", "Phase 3 hub: ip nhrp redirect",
                   default=True)
        form.check(group, "nhrp_shortcut", "Phase 3 spoke: ip nhrp shortcut",
                   default=True)
        nhs = TableEditor(
            group, "NHRP NHS / hub maps",
            columns=[("address", "NHS tunnel IP", 130), ("nbma", "Hub NBMA", 130)],
            fields=[
                {"key": "address", "label": "NHS tunnel IP"},
                {"key": "nbma", "label": "Hub NBMA/public IP"},
            ],
            items=tunnel.setdefault("nhrp_nhs", []), on_change=on_change, height=3)
        form.widget(group, nhs)
        maps = TableEditor(
            group, "Additional static NHRP maps",
            columns=[("tunnel_ip", "Tunnel IP", 130), ("nbma", "NBMA", 130),
                     ("multicast", "Multicast", 80)],
            fields=[
                {"key": "tunnel_ip", "label": "Tunnel IP"},
                {"key": "nbma", "label": "NBMA/public IP"},
                {"key": "multicast", "label": "Map multicast", "type": "check"},
            ],
            items=tunnel.setdefault("nhrp_static_maps", []), on_change=on_change,
            height=3)
        form.widget(group, maps)

    group = form.group("IPsec protection")
    form.check(group, "ipsec_enabled", "Protect tunnel with IPsec")
    form.combo(group, "ike_version", "IKE version", ["IKEv1", "IKEv2"],
               default="IKEv2")
    form.entry(group, "pre_shared_key", "Pre-shared key")
    form.entry(group, "pfs_group", "PFS group (optional)", width=8)
    form.entry(group, "ikev1_transform_set", "IKEv1 transform set",
               default="TUNNEL-TS")
    form.entry(group, "ikev2_proposal", "IKEv2 proposal",
               default="TUNNEL-IKEV2-PROP")
    form.entry(group, "ipsec_profile", "IPsec profile",
               default="TUNNEL-IPSEC-PROFILE")
    form.entry(group, "tunnel_protection_profile",
               "Tunnel protection profile", default="TUNNEL-IPSEC-PROFILE")
    form.check(group, "nat_traversal_note", "Show NAT traversal note",
               default=True)

    group = form.group("Routing over tunnel")
    routes = TableEditor(
        group, "Static routes over tunnel",
        columns=[("prefix", "Prefix", 120), ("mask", "Mask", 120),
                 ("next_hop", "Next hop", 120)],
        fields=[
            {"key": "prefix", "label": "Prefix"},
            {"key": "mask", "label": "Mask"},
            {"key": "next_hop", "label": "Next hop (blank = tunnel)"},
        ],
        items=tunnel.setdefault("routing", {}).setdefault("static_routes", []),
        on_change=on_change, height=3)
    form.widget(group, routes)
    form.check(group, "routing.ospf.enabled", "OSPF over tunnel")
    form.entry(group, "routing.ospf.process_id", "OSPF process", default="1", width=8)
    form.entry(group, "routing.ospf.area", "OSPF area", default="0", width=8)
    form.combo(group, "routing.ospf.network_type", "OSPF network type",
               ["point-to-multipoint", "broadcast", "non-broadcast"],
               default="point-to-multipoint")
    form.check(group, "routing.eigrp.enabled", "EIGRP over tunnel")
    form.entry(group, "routing.eigrp.asn", "EIGRP AS", width=8)
    eigrp_nets = TableEditor(
        group, "EIGRP networks",
        columns=[("network", "Network", 130), ("wildcard", "Wildcard", 120)],
        fields=[
            {"key": "network", "label": "Network"},
            {"key": "wildcard", "label": "Wildcard"},
        ],
        items=tunnel["routing"].setdefault("eigrp", {}).setdefault("networks", []),
        on_change=on_change, height=2)
    form.widget(group, eigrp_nets)
    form.check(group, "routing.bgp.enabled", "BGP over tunnel")
    form.entry(group, "routing.bgp.local_as", "Local ASN", width=10)
    bgp_neighbors = TableEditor(
        group, "BGP neighbors (update-source = tunnel)",
        columns=[("ip", "Neighbor", 130), ("remote_as", "Remote AS", 90),
                 ("description", "Description", 150)],
        fields=[
            {"key": "ip", "label": "Neighbor tunnel IP"},
            {"key": "remote_as", "label": "Remote AS"},
            {"key": "description", "label": "Description"},
        ],
        items=tunnel["routing"].setdefault("bgp", {}).setdefault("neighbors", []),
        on_change=on_change, height=3)
    form.widget(group, bgp_neighbors)


class TunnelsForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        self.on_change = on_change
        self.tunnels = project.data["tunnels"].setdefault("tunnels", [])

        header = ttk.Label(
            self, style="Muted.TLabel", wraplength=640, justify="left",
            padding=(12, 8, 12, 0),
            text=("Define one or more tunnels. GRE point-to-point, GRE "
                  "multipoint (DMVPN) and static VTI are supported; DMVPN "
                  "tunnels expose NHRP and phase options. Select a tunnel to "
                  "edit its details below."))
        header.pack(fill="x")

        top = ttk.Frame(self, padding=(12, 6))
        top.pack(fill="x")
        self.table = TableEditor(
            top, "Tunnels",
            columns=[("name", "Name", 140), ("type", "Type", 180),
                     ("tunnel_number", "Tun#", 50),
                     ("tunnel_ip", "Tunnel IP", 130)],
            fields=[{"key": "name", "label": "Name"}],
            items=self.tunnels, on_change=self._changed,
            height=5, on_select=self._select,
            extra_buttons=[("Add GRE p2p", lambda e: self._add("GRE point-to-point")),
                           ("Add DMVPN", lambda e: self._add(GRE_MULTIPOINT)),
                           ("Add VTI", lambda e: self._add("Static VTI"))])
        self.table.pack(fill="x")

        self.detail_host = ScrollableFrame(self)
        self.detail_host.pack(fill="both", expand=True)
        self._select(None)

    def _add(self, tunnel_type: str):
        tunnel = default_tunnel(tunnel_type)
        tunnel["tunnel_number"] = str(self._next_number())
        tunnel["name"] = f"{tunnel_type.split()[0]}-{tunnel['tunnel_number']}"
        self.tunnels.append(tunnel)
        self.table.refresh()
        self.table.tree.selection_set(str(len(self.tunnels) - 1))
        self._select(len(self.tunnels) - 1)
        self.on_change()

    def _next_number(self) -> int:
        used = {int(t["tunnel_number"]) for t in self.tunnels
                if str(t.get("tunnel_number", "")).isdigit()}
        n = 0
        while n in used:
            n += 1
        return n

    def _changed(self):
        self._refresh_detail()
        self.on_change()

    def _select(self, index):
        for child in self.detail_host.inner.winfo_children():
            child.destroy()
        if index is None or index >= len(self.tunnels):
            ttk.Label(self.detail_host.inner, style="Muted.TLabel",
                      padding=(12, 12),
                      text="Add or select a tunnel to edit its configuration."
                      ).pack(anchor="w")
            return
        build_tunnel_detail(self.detail_host.inner, self.tunnels[index],
                            self._changed)

    def _refresh_detail(self):
        self.table.refresh()
