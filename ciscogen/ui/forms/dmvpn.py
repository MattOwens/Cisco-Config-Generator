"""DMVPN and IPsec form."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class DmvpnForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["dmvpn"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("Tunnel")
        form.check(group, "enabled", "Enable DMVPN")
        form.combo(group, "role", "Role",
                   ["Hub", "Spoke", "Dual Hub", "Spoke with redundant hubs"],
                   default="Hub")
        form.combo(group, "phase", "Phase",
                   ["Phase 1", "Phase 2", "Phase 3"], default="Phase 3")
        form.entry(group, "tunnel_number", "Tunnel number", default="0", width=8)
        form.entry(group, "description", "Description")
        form.entry(group, "vrf", "Tunnel VRF (optional)")
        form.entry(group, "tunnel_ip", "Tunnel IP")
        form.entry(group, "tunnel_mask", "Tunnel mask")
        form.entry(group, "tunnel_source_interface", "Tunnel source interface")
        form.entry(group, "tunnel_source_ip", "Tunnel source IP")
        form.entry(group, "tunnel_key", "Tunnel key")
        form.combo(group, "tunnel_mode", "Tunnel mode",
                   ["gre multipoint"], default="gre multipoint")
        form.entry(group, "ip_mtu", "IP MTU", default="1400", width=8)
        form.entry(group, "tcp_mss", "TCP MSS", default="1360", width=8)
        form.entry(group, "bandwidth", "Bandwidth", width=8)
        form.entry(group, "delay", "Delay", width=8)

        group = form.group("NHRP")
        form.entry(group, "nhrp_network_id", "Network ID")
        form.entry(group, "nhrp_authentication", "Authentication")
        form.entry(group, "nhrp_holdtime", "Holdtime", default="600", width=8)
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
            items=data.setdefault("nhrp_nhs", []), on_change=on_change, height=3)
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
            items=data.setdefault("nhrp_static_maps", []), on_change=on_change,
            height=3)
        form.widget(group, maps)

        group = form.group("IPsec")
        form.check(group, "ipsec_enabled", "Protect tunnel with IPsec")
        form.combo(group, "ike_version", "IKE version", ["IKEv1", "IKEv2"],
                   default="IKEv2")
        form.entry(group, "pre_shared_key", "Pre-shared key")
        form.entry(group, "ikev1_policy.number", "IKEv1 policy #", default="10", width=8)
        form.entry(group, "ikev1_policy.encryption", "IKEv1 encryption",
                   default="aes 256")
        form.entry(group, "ikev1_policy.hash", "IKEv1 hash", default="sha256")
        form.entry(group, "ikev1_policy.group", "IKEv1 DH group", default="14", width=8)
        form.entry(group, "ikev1_transform_set", "IKEv1 transform set",
                   default="DMVPN-TS")
        form.entry(group, "ikev2_proposal", "IKEv2 proposal",
                   default="DMVPN-IKEV2-PROP")
        form.entry(group, "ikev2_policy", "IKEv2 policy",
                   default="DMVPN-IKEV2-POLICY")
        form.entry(group, "ikev2_keyring", "IKEv2 keyring",
                   default="DMVPN-KEYRING")
        form.entry(group, "ikev2_profile", "IKEv2 profile",
                   default="DMVPN-IKEV2-PROFILE")
        form.entry(group, "ipsec_profile", "IPsec profile",
                   default="DMVPN-IPSEC-PROFILE")
        form.entry(group, "tunnel_protection_profile",
                   "Tunnel protection profile", default="DMVPN-IPSEC-PROFILE")
        form.check(group, "nat_traversal_note", "Show NAT traversal warning",
                   default=True)

        group = form.group("Routing over DMVPN")
        routes = TableEditor(
            group, "Static routes over tunnel",
            columns=[("prefix", "Prefix", 120), ("mask", "Mask", 120),
                     ("next_hop", "Next hop", 120)],
            fields=[
                {"key": "prefix", "label": "Prefix"},
                {"key": "mask", "label": "Mask"},
                {"key": "next_hop", "label": "Next hop (blank = tunnel)"},
            ],
            items=data.setdefault("routing", {}).setdefault("static_routes", []),
            on_change=on_change, height=3)
        form.widget(group, routes)
        form.check(group, "routing.ospf.enabled", "OSPF over tunnel")
        form.entry(group, "routing.ospf.process_id", "OSPF process", default="1", width=8)
        form.entry(group, "routing.ospf.area", "OSPF area", default="0", width=8)
        form.combo(group, "routing.ospf.network_type", "OSPF network type",
                   ["point-to-multipoint", "broadcast", "non-broadcast"],
                   default="point-to-multipoint")
        form.entry(group, "routing.ospf.cost", "OSPF cost", width=8)
        form.check(group, "routing.eigrp.enabled", "EIGRP over tunnel")
        form.entry(group, "routing.eigrp.asn", "EIGRP AS", width=8)
        form.check(group, "routing.eigrp.hub_disable_split_horizon",
                   "Hub: no ip split-horizon", default=True)
        form.check(group, "routing.eigrp.hub_disable_next_hop_self",
                   "Hub: no ip next-hop-self", default=True)
        eigrp_nets = TableEditor(
            group, "EIGRP networks",
            columns=[("network", "Network", 130), ("wildcard", "Wildcard", 120)],
            fields=[
                {"key": "network", "label": "Network"},
                {"key": "wildcard", "label": "Wildcard"},
            ],
            items=data["routing"].setdefault("eigrp", {}).setdefault("networks", []),
            on_change=on_change, height=2)
        form.widget(group, eigrp_nets)
        form.check(group, "routing.bgp.enabled", "BGP over tunnel")
        form.entry(group, "routing.bgp.local_as", "Local ASN", width=10)
        form.check(group, "routing.bgp.route_reflector", "Hub route reflector")
        form.check(group, "routing.bgp.next_hop_self", "Next-hop-self",
                   default=True)
        bgp_neighbors = TableEditor(
            group, "BGP neighbors",
            columns=[("ip", "Neighbor", 130), ("remote_as", "Remote AS", 90),
                     ("description", "Description", 150)],
            fields=[
                {"key": "ip", "label": "Neighbor tunnel IP"},
                {"key": "remote_as", "label": "Remote AS"},
                {"key": "description", "label": "Description"},
            ],
            items=data["routing"].setdefault("bgp", {}).setdefault("neighbors", []),
            on_change=on_change, height=3)
        form.widget(group, bgp_neighbors)
