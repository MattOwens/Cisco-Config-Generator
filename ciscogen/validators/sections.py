"""Per-section validators.  Each takes the section's data dict and the device
profile and returns a list of Issue objects."""

from __future__ import annotations

from ..utils import normalize_interface_name, parse_list, s, safe_int, truthy
from . import Issue, error, warning, info
from .network import (
    RESERVED_VLANS, is_valid_ipv4, is_valid_mask, is_valid_vlan,
    is_valid_wildcard, is_valid_ipv6, is_valid_ipv6_interface,
    is_valid_ipv6_network, networks_overlap, parse_ipv4, ranges_overlap,
)

WEAK_VALUES = {"cisco", "cisco123", "admin", "password", "class", "secret",
               "1234", "12345", "123456", "letmein", "changeme"}


def _is_weak(value: str) -> bool:
    return s(value).lower() in WEAK_VALUES or (0 < len(s(value)) < 6)


def _known_interface(name: str, profile) -> bool:
    """True when a name plausibly exists on the selected device."""
    norm = normalize_interface_name(name)
    if not norm:
        return False
    base = norm.split(".")[0]
    if base in profile.interfaces:
        return True
    # Logical interfaces are always creatable.
    for prefix in ("Vlan", "Loopback", "Tunnel", "Port-channel"):
        if base.startswith(prefix):
            return True
    return False


# ---------------------------------------------------------------- system --
def validate_system(sys_data: dict, profile,
                    acl_data: dict | None = None) -> list[Issue]:
    acl_data = acl_data or {}
    issues = []
    if not s(sys_data.get("hostname")):
        issues.append(error("system", "Hostname is not set."))
    secret = s(sys_data.get("enable_secret"))
    if not secret:
        issues.append(warning("system", "Enable secret is empty; the device will "
                                        "not require a password for privileged EXEC."))
    elif _is_weak(secret):
        issues.append(warning("system", "Enable secret looks weak or is a well-known "
                                        "default value."))
    for user in sys_data.get("users", []):
        if not s(user.get("username")):
            issues.append(error("system", "A local user has an empty username."))
        if not s(user.get("password")):
            issues.append(error("system", f"Local user '{s(user.get('username'))}' "
                                          "has an empty password."))
        elif _is_weak(user.get("password")):
            issues.append(warning("system", f"Password for user "
                                            f"'{s(user.get('username'))}' looks weak."))
        priv = safe_int(user.get("privilege"), 1)
        if priv is None or not 0 <= priv <= 15:
            issues.append(error("system", f"Privilege level for user "
                                          f"'{s(user.get('username'))}' must be 0-15."))

    ssh = truthy(sys_data.get("ssh_enabled"))
    if ssh and not s(sys_data.get("domain_name")):
        issues.append(error("system", "SSH is enabled but no domain name is set; "
                                      "RSA key generation requires 'ip domain-name'."))
    if ssh and not truthy(sys_data.get("generate_rsa")):
        issues.append(warning("system", "SSH is enabled but the RSA key generation "
                                        "command is not included; SSH will not work "
                                        "until keys exist."))
    vty = sys_data.get("vty", {})
    transport = s(vty.get("transport", "ssh"))
    if "telnet" in transport:
        issues.append(warning("system", "VTY lines allow Telnet; credentials will "
                                        "cross the network in clear text."))
    if truthy(sys_data.get("mgmt_svi", {}).get("enabled")):
        svi = sys_data["mgmt_svi"]
        if not is_valid_vlan(svi.get("vlan")):
            issues.append(error("system", "Management SVI VLAN ID must be 1-4094."))
        if not is_valid_ipv4(s(svi.get("ip"))):
            issues.append(error("system", "Management SVI IP address is invalid."))
        if not is_valid_mask(s(svi.get("mask"))):
            issues.append(error("system", "Management SVI subnet mask is invalid."))
    if truthy(sys_data.get("mgmt_interface", {}).get("enabled")):
        mgmt = sys_data["mgmt_interface"]
        if not s(mgmt.get("name")):
            issues.append(error("system", "Management interface name is empty."))
        if not is_valid_ipv4(s(mgmt.get("ip"))):
            issues.append(error("system", "Management interface IP address is invalid."))
        if not is_valid_mask(s(mgmt.get("mask"))):
            issues.append(error("system", "Management interface subnet mask is invalid."))
    gateway = s(sys_data.get("default_gateway"))
    if gateway and not is_valid_ipv4(gateway):
        issues.append(error("system", "Default gateway is not a valid IPv4 address."))
    route = s(sys_data.get("default_route"))
    if route and not is_valid_ipv4(route):
        issues.append(error("system", "Default route next hop is not a valid "
                                      "IPv4 address."))
    for host in parse_list(sys_data.get("logging_hosts")):
        if not is_valid_ipv4(host):
            issues.append(error("system", f"Logging host '{host}' is not a valid "
                                          "IPv4 address."))
    for server in parse_list(sys_data.get("ntp_servers")):
        if not is_valid_ipv4(server):
            issues.append(error("system", f"NTP server '{server}' is not a valid "
                                          "IPv4 address."))
    for server in parse_list(sys_data.get("name_servers")):
        if not is_valid_ipv4(server):
            issues.append(error("system", f"DNS name-server '{server}' is not a "
                                          "valid IPv4 address."))
    for field, label, lo, hi in (("ssh_timeout", "SSH timeout", 1, 120),
                                 ("ssh_auth_retries", "SSH auth retries", 0, 5)):
        value = s(sys_data.get(field))
        if value:
            num = safe_int(value)
            if num is None or not lo <= num <= hi:
                issues.append(error("system", f"{label} must be {lo}-{hi}."))
    for community in sys_data.get("snmp", {}).get("communities", []):
        name = s(community.get("community"))
        if name.lower() in ("public", "private"):
            issues.append(warning("system", f"SNMP community '{name}' is a well-known "
                                            "default; choose a unique string."))
        if s(community.get("mode")).upper() == "RW":
            issues.append(warning("system", f"SNMP community '{name}' is read-write; "
                                            "prefer read-only unless writes are needed."))
    if truthy(sys_data.get("aaa_new_model")):
        methods = sys_data.get("aaa_methods", {})
        if s(methods.get("login")) in ("tacacs", "radius") \
                and not truthy(methods.get("local_fallback", True)):
            issues.append(warning("system", "AAA login uses remote servers without "
                                            "local fallback; loss of AAA reachability "
                                            "can lock out administrators."))
    for server in sys_data.get("tacacs", {}).get("servers", []):
        address = s(server.get("address"))
        if address and not is_valid_ipv4(address):
            issues.append(error("system", f"TACACS+ server '{address}' is not a valid IPv4 address."))
    for server in sys_data.get("radius", {}).get("servers", []):
        address = s(server.get("address"))
        if address and not is_valid_ipv4(address):
            issues.append(error("system", f"RADIUS server '{address}' is not a valid IPv4 address."))
    snmp = sys_data.get("snmp", {})
    if snmp.get("communities") and not s(acl_data.get("management_plane_acl")):
        issues.append(warning("system", "SNMPv2 communities are configured; restrict "
                                        "management access by setting the "
                                        "management-plane ACL in the Access "
                                        "Lists section."))
    for user in snmp.get("users", []):
        if not s(user.get("username")) or not s(user.get("group")):
            issues.append(error("system", "SNMPv3 users require both username and group."))
    restconf_on = truthy(sys_data.get("restconf_enabled")) \
        or truthy(sys_data.get("netconf_enabled"))
    if restconf_on and profile.os_type != "IOS-XE":
        issues.append(warning("system", "RESTCONF/NETCONF is enabled but "
                                        f"{profile.model} runs {profile.os_type}; "
                                        "these are IOS-XE features and will not be "
                                        "generated for this platform."))
    if restconf_on and profile.os_type == "IOS-XE" \
            and not s(sys_data.get("mgmt_svi", {}).get("ip")) \
            and not s(sys_data.get("mgmt_interface", {}).get("ip")):
        issues.append(warning("system", "RESTCONF/NETCONF is enabled without a "
                                        "management interface address in the project."))
    for label, key in (("logging", "logging_source_interface"),
                       ("NTP", "ntp_source_interface")):
        if (parse_list(sys_data.get("logging_hosts")) if label == "logging"
                else parse_list(sys_data.get("ntp_servers"))) and not s(sys_data.get(key)):
            issues.append(info("system", f"{label} source interface is not set; "
                                         "consider pinning management traffic to a "
                                         "stable interface."))
    return issues


# ------------------------------------------------------------ interfaces --
def validate_interfaces(if_data: dict, profile) -> list[Issue]:
    issues = []
    seen: set[str] = set()
    for item in if_data.get("physical", []):
        name = normalize_interface_name(s(item.get("name")))
        if not name:
            issues.append(error("interfaces", "An interface entry has no name."))
            continue
        if name in seen:
            issues.append(error("interfaces", f"Interface {name} is defined more "
                                              "than once."))
        seen.add(name)
        if not _known_interface(name, profile):
            issues.append(warning("interfaces", f"Interface {name} does not match "
                                                f"the {profile.model} port layout "
                                                f"({profile.interface_naming})."))
        mode = s(item.get("mode", "access"))
        if mode == "access":
            if not s(item.get("access_vlan")):
                issues.append(warning("interfaces", f"{name}: access port has no "
                                                    "access VLAN (defaults to VLAN 1)."))
            elif not is_valid_vlan(item.get("access_vlan")):
                issues.append(error("interfaces", f"{name}: access VLAN must be 1-4094."))
        if mode == "trunk":
            if not s(item.get("native_vlan")):
                issues.append(warning("interfaces", f"{name}: trunk has no native "
                                                    "VLAN configured (defaults to VLAN 1)."))
            if not s(item.get("allowed_vlans")):
                issues.append(warning("interfaces", f"{name}: trunk allows all VLANs; "
                                                    "consider pruning with an allowed list."))
            if truthy(item.get("ps_enabled")):
                issues.append(warning("interfaces", f"{name}: port security on a trunk "
                                                    "port is unusual; verify intent."))
            if truthy(item.get("portfast")):
                issues.append(warning("interfaces", f"{name}: PortFast on a trunk "
                                                    "port can create STP risk; verify "
                                                    "this is an edge trunk."))
        if mode == "access" and truthy(item.get("portfast")) \
                and not truthy(item.get("bpduguard")):
            issues.append(warning("interfaces", f"{name}: PortFast is enabled without "
                                                "BPDU Guard."))
        if mode == "routed":
            if not is_valid_ipv4(s(item.get("ip"))):
                issues.append(error("interfaces", f"{name}: routed port needs a valid "
                                                  "IPv4 address."))
            if not is_valid_mask(s(item.get("mask"))):
                issues.append(error("interfaces", f"{name}: routed port needs a valid "
                                                  "subnet mask."))
        voice = s(item.get("voice_vlan"))
        if voice and not is_valid_vlan(voice):
            issues.append(error("interfaces", f"{name}: voice VLAN must be 1-4094."))
        if voice and mode != "access":
            issues.append(warning("interfaces", f"{name}: voice VLAN is usually "
                                                "configured on access ports."))
        mtu = s(item.get("mtu"))
        if mtu:
            mtu_val = safe_int(mtu)
            if mtu_val is None or not 64 <= mtu_val <= 9216:
                issues.append(error("interfaces", f"{name}: MTU must be 64-9216."))
            elif not profile.supports("interface_mtu"):
                note = profile.warning_for("interface_mtu") or (
                    f"Per-interface MTU may not be supported on {profile.model}.")
                issues.append(warning("interfaces", f"{name}: {note}"))
        for helper in parse_list(item.get("helper")):
            if not is_valid_ipv4(helper):
                issues.append(error("interfaces", f"{name}: helper address "
                                                  f"'{helper}' is invalid."))
    # Port-channels
    pc_ids = set()
    for pc in if_data.get("port_channels", []):
        pc_id = safe_int(pc.get("id"))
        if pc_id is None or not 1 <= pc_id <= 128:
            issues.append(error("interfaces", "Port-channel ID must be 1-128."))
            continue
        if pc_id in pc_ids:
            issues.append(error("interfaces", f"Port-channel {pc_id} is defined "
                                              "more than once."))
        pc_ids.add(pc_id)
        if s(pc.get("mode")) == "routed":
            if not is_valid_ipv4(s(pc.get("ip"))) or not is_valid_mask(s(pc.get("mask"))):
                issues.append(error("interfaces", f"Port-channel {pc_id}: routed mode "
                                                  "needs a valid IP and mask."))
    members: dict[int, set] = {}
    for item in if_data.get("physical", []):
        group = safe_int(item.get("channel_group"))
        if group is not None:
            members.setdefault(group, set()).add(s(item.get("channel_mode", "active")))
    for group, modes in members.items():
        if len(modes) > 1:
            issues.append(warning("interfaces", f"Channel-group {group} members use "
                                                f"mixed modes ({', '.join(sorted(modes))}); "
                                                "keep members consistent."))
    # Subinterfaces
    seen_sub = set()
    for sub in if_data.get("subinterfaces", []):
        parent = normalize_interface_name(s(sub.get("parent")))
        vlan = s(sub.get("vlan"))
        name = f"{parent}.{vlan}"
        if not parent:
            issues.append(error("interfaces", "A subinterface has no parent interface."))
            continue
        if name in seen_sub:
            issues.append(error("interfaces", f"Subinterface {name} is defined more "
                                              "than once."))
        seen_sub.add(name)
        if not is_valid_vlan(vlan):
            issues.append(error("interfaces", f"Subinterface on {parent}: dot1Q VLAN "
                                              "must be 1-4094."))
        if not is_valid_ipv4(s(sub.get("ip"))) or not is_valid_mask(s(sub.get("mask"))):
            issues.append(error("interfaces", f"Subinterface {name}: needs a valid "
                                              "IP address and mask."))
    # SVIs
    seen_svi = set()
    for svi in if_data.get("svis", []):
        vlan = s(svi.get("vlan"))
        if not is_valid_vlan(vlan):
            issues.append(error("interfaces", f"SVI VLAN '{vlan}' must be 1-4094."))
            continue
        if vlan in seen_svi:
            issues.append(error("interfaces", f"SVI Vlan{vlan} is defined more "
                                              "than once."))
        seen_svi.add(vlan)
        if not is_valid_ipv4(s(svi.get("ip"))) or not is_valid_mask(s(svi.get("mask"))):
            issues.append(error("interfaces", f"SVI Vlan{vlan}: needs a valid IP "
                                              "address and mask."))
    return issues


# ----------------------------------------------------------------- vlans --
def validate_vlans(vlan_data: dict, profile) -> list[Issue]:
    issues = []
    seen = set()
    for vlan in vlan_data.get("vlans", []):
        vid_raw = s(vlan.get("id"))
        if not is_valid_vlan(vid_raw):
            issues.append(error("vlans", f"VLAN ID '{vid_raw}' is invalid; "
                                         "VLAN IDs are 1-4094."))
            continue
        vid = int(vid_raw)
        if vid in seen:
            issues.append(error("vlans", f"VLAN {vid} is defined more than once."))
        seen.add(vid)
        if vid in RESERVED_VLANS:
            issues.append(warning("vlans", f"VLAN {vid} is reserved for legacy "
                                           "Token Ring/FDDI and cannot be used."))
        if vid == 1:
            issues.append(info("vlans", "VLAN 1 is the default VLAN; best practice "
                                        "is to avoid using it for user traffic."))
    snooping = vlan_data.get("dhcp_snooping", {})
    if truthy(snooping.get("enabled")):
        if not s(snooping.get("vlans")):
            issues.append(warning("vlans", "DHCP snooping is enabled but no VLAN "
                                           "list is set; snooping will not inspect "
                                           "any VLAN."))
        if not s(snooping.get("trusted_interfaces")):
            issues.append(warning("vlans", "DHCP snooping has no trusted interfaces; "
                                           "uplinks toward the DHCP server must be "
                                           "trusted or clients will lose DHCP."))
    dai = vlan_data.get("dai", {})
    if truthy(dai.get("enabled")):
        if not truthy(snooping.get("enabled")):
            issues.append(warning("vlans", "Dynamic ARP Inspection relies on the DHCP "
                                           "snooping binding table; enable DHCP "
                                           "snooping too."))
        if not s(dai.get("vlans")):
            issues.append(warning("vlans", "DAI is enabled but no VLAN list is set."))
    vtp = vlan_data.get("vtp", {})
    if truthy(vtp.get("enabled")) and s(vtp.get("mode")) in ("server", "client") \
            and not s(vtp.get("domain")):
        issues.append(warning("vlans", "VTP server/client mode without a domain "
                                       "name; the switch will join the first domain "
                                       "it hears."))
    return issues


# ---------------------------------------------------------------- layer3 --
def validate_layer3(l3_data: dict, profile) -> list[Issue]:
    issues = []
    for route in l3_data.get("static_routes", []):
        prefix, mask = s(route.get("prefix")), s(route.get("mask"))
        next_hop = s(route.get("next_hop"))
        exit_if = s(route.get("exit_interface"))
        label = f"{prefix} {mask}".strip() or "(empty)"
        if not is_valid_ipv4(prefix):
            issues.append(error("layer3", f"Static route {label}: destination "
                                          "prefix is invalid."))
        if not is_valid_mask(mask):
            issues.append(error("layer3", f"Static route {label}: subnet mask "
                                          "is invalid."))
        if not next_hop and not exit_if:
            issues.append(error("layer3", f"Static route {label}: needs a next hop "
                                          "or an exit interface."))
        if next_hop and not is_valid_ipv4(next_hop):
            issues.append(error("layer3", f"Static route {label}: next hop "
                                          f"'{next_hop}' is invalid."))
        distance = s(route.get("distance"))
        if distance:
            ad = safe_int(distance)
            if ad is None or not 1 <= ad <= 255:
                issues.append(error("layer3", f"Static route {label}: administrative "
                                              "distance must be 1-255."))
    for pl in l3_data.get("prefix_lists", []):
        prefix = s(pl.get("prefix"))
        if "/" not in prefix:
            issues.append(error("layer3", f"Prefix list {s(pl.get('name'))}: prefix "
                                          f"'{prefix}' must be network/length."))
            continue
        net, _, length = prefix.partition("/")
        if not is_valid_ipv4(net) or safe_int(length) is None \
                or not 0 <= safe_int(length, -1) <= 32:
            issues.append(error("layer3", f"Prefix list {s(pl.get('name'))}: "
                                          f"'{prefix}' is not a valid prefix."))
    for rm in l3_data.get("route_maps", []):
        nh = s(rm.get("set_next_hop"))
        if nh and not is_valid_ipv4(nh):
            issues.append(error("layer3", f"Route-map {s(rm.get('name'))}: set "
                                          f"next-hop '{nh}' is invalid."))
    return issues


# ------------------------------------------------------------------ dhcp --
def validate_dhcp(dhcp_data: dict, profile) -> list[Issue]:
    issues = []
    pools = dhcp_data.get("pools", [])
    for pool in pools:
        name = s(pool.get("name")) or "(unnamed)"
        if not s(pool.get("name")):
            issues.append(error("dhcp", "A DHCP pool has no name."))
        network, mask = s(pool.get("network")), s(pool.get("mask"))
        if not is_valid_ipv4(network) or not is_valid_mask(mask):
            issues.append(error("dhcp", f"Pool {name}: network/mask is invalid."))
        router = s(pool.get("default_router"))
        if not router:
            issues.append(warning("dhcp", f"Pool {name}: no default router; clients "
                                          "will get an address but no gateway."))
        elif not is_valid_ipv4(router):
            issues.append(error("dhcp", f"Pool {name}: default router "
                                        f"'{router}' is invalid."))
        for dns in parse_list(pool.get("dns")):
            if not is_valid_ipv4(dns):
                issues.append(error("dhcp", f"Pool {name}: DNS server '{dns}' "
                                            "is invalid."))
        opt150 = s(pool.get("option150"))
        if opt150 and not is_valid_ipv4(opt150):
            issues.append(error("dhcp", f"Pool {name}: option 150 address "
                                        f"'{opt150}' is invalid."))
    # Pool network overlaps
    for i, pool_a in enumerate(pools):
        for pool_b in pools[i + 1:]:
            if networks_overlap(s(pool_a.get("network")), s(pool_a.get("mask")),
                                s(pool_b.get("network")), s(pool_b.get("mask"))):
                issues.append(error("dhcp", f"Pools {s(pool_a.get('name'))} and "
                                            f"{s(pool_b.get('name'))} have "
                                            "overlapping networks."))
    # Excluded ranges
    excluded = dhcp_data.get("excluded", [])
    for rng in excluded:
        start, end = s(rng.get("start")), s(rng.get("end")) or s(rng.get("start"))
        if not is_valid_ipv4(start) or (end and not is_valid_ipv4(end)):
            issues.append(error("dhcp", f"Excluded range '{start} - {end}' contains "
                                        "an invalid address."))
        elif end and parse_ipv4(start) > parse_ipv4(end):
            issues.append(error("dhcp", f"Excluded range '{start} - {end}': start "
                                        "is after end."))
    for i, range_a in enumerate(excluded):
        for range_b in excluded[i + 1:]:
            a_start = s(range_a.get("start"))
            a_end = s(range_a.get("end")) or a_start
            b_start = s(range_b.get("start"))
            b_end = s(range_b.get("end")) or b_start
            if ranges_overlap(a_start, a_end, b_start, b_end):
                issues.append(warning("dhcp", f"Excluded ranges '{a_start} - {a_end}' "
                                              f"and '{b_start} - {b_end}' overlap."))
    for binding in dhcp_data.get("static_bindings", []):
        name = s(binding.get("name")) or "(unnamed)"
        if not s(binding.get("name")):
            issues.append(error("dhcp", "A DHCP static binding has no pool name."))
        if not is_valid_ipv4(s(binding.get("host_ip"))):
            issues.append(error("dhcp", f"Static binding {name}: host IP is invalid."))
        if not s(binding.get("mac")) and not s(binding.get("client_id")):
            issues.append(warning("dhcp", f"Static binding {name}: set a MAC "
                                          "(hardware-address) or client-identifier "
                                          "or the reservation will not match."))
        router = s(binding.get("default_router"))
        if router and not is_valid_ipv4(router):
            issues.append(error("dhcp", f"Static binding {name}: default router "
                                        f"'{router}' is invalid."))
    return issues


# ------------------------------------------------------------------- nat --
def validate_nat(nat_data: dict, if_data: dict, profile) -> list[Issue]:
    issues = []
    inside = parse_list(nat_data.get("inside_interfaces"))
    outside = parse_list(nat_data.get("outside_interfaces"))
    uses_nat = (nat_data.get("static_rules")
                or truthy(nat_data.get("dynamic_enabled")))
    if uses_nat and not inside:
        issues.append(error("nat", "NAT rules exist but no interface is marked "
                                   "'ip nat inside'."))
    if uses_nat and not outside:
        issues.append(error("nat", "NAT rules exist but no interface is marked "
                                   "'ip nat outside'."))
    for rule in nat_data.get("static_rules", []):
        local, global_ = s(rule.get("inside_local")), s(rule.get("inside_global"))
        if not is_valid_ipv4(local) or not is_valid_ipv4(global_):
            issues.append(error("nat", f"Static NAT '{local} -> {global_}' has an "
                                       "invalid address."))
    if truthy(nat_data.get("dynamic_enabled")):
        if not s(nat_data.get("dynamic_acl")):
            issues.append(error("nat", "Dynamic NAT is enabled but no source ACL "
                                       "is referenced."))
        if truthy(nat_data.get("use_pool")):
            if not s(nat_data.get("pool_name")):
                issues.append(error("nat", "Dynamic NAT uses a pool but the pool "
                                           "has no name."))
            for field, label in (("pool_start", "start"), ("pool_end", "end")):
                if not is_valid_ipv4(s(nat_data.get(field))):
                    issues.append(error("nat", f"NAT pool {label} address is invalid."))
            if not is_valid_mask(s(nat_data.get("pool_mask"))):
                issues.append(error("nat", "NAT pool netmask is invalid."))
        elif not s(nat_data.get("overload_interface")):
            issues.append(error("nat", "Interface PAT is selected but no outside "
                                       "interface is chosen for overload."))
    return issues


# ------------------------------------------------------------------ acls --
def _rule_matches_everything(rule: dict, acl_type: str) -> bool:
    if s(rule.get("action")) not in ("permit", "deny"):
        return False
    if acl_type == "standard":
        return s(rule.get("src")) == "any"
    return (s(rule.get("src")) == "any" and s(rule.get("dst")) == "any"
            and not s(rule.get("src_port")) and not s(rule.get("dst_port")))


def validate_acls(acl_data: dict, if_data: dict, profile) -> list[Issue]:
    issues = []
    names = set()
    permissive_acls: set[str] = set()
    for acl in acl_data.get("acls", []):
        acl_id = s(acl.get("id"))
        acl_type = s(acl.get("type", "standard"))
        if not acl_id:
            issues.append(error("acls", "An ACL has no name or number."))
            continue
        if acl_id in names:
            issues.append(error("acls", f"ACL '{acl_id}' is defined more than once."))
        names.add(acl_id)
        number = safe_int(acl_id)
        if number is not None:
            if acl_type == "standard" and not (1 <= number <= 99 or 1300 <= number <= 1999):
                issues.append(error("acls", f"ACL {number}: standard numbered ACLs "
                                            "use 1-99 or 1300-1999."))
            if acl_type == "extended" and not (100 <= number <= 199 or 2000 <= number <= 2699):
                issues.append(error("acls", f"ACL {number}: extended numbered ACLs "
                                            "use 100-199 or 2000-2699."))
        rules = [r for r in acl.get("rules", []) if s(r.get("action")) != "remark"]
        if not rules:
            issues.append(warning("acls", f"ACL '{acl_id}' has no permit/deny rules; "
                                          "remember every ACL ends with an implicit "
                                          "'deny any'."))
            continue
        issues.append(info("acls", f"ACL '{acl_id}': remember the implicit "
                                   "'deny any' at the end."))
        for rule in rules:
            if s(rule.get("action")) == "permit" and \
                    _rule_matches_everything(rule, acl_type) and \
                    s(rule.get("protocol", "ip")) in ("", "ip"):
                permissive_acls.add(acl_id)
                issues.append(warning("acls", f"ACL '{acl_id}' contains "
                                              "'permit ip any any' (or equivalent); "
                                              "this defeats the purpose of the ACL."))
            for field in ("src", "dst") if acl_type == "extended" else ("src",):
                value = s(rule.get(field))
                if value and value != "any" and not is_valid_ipv4(value):
                    issues.append(error("acls", f"ACL '{acl_id}': {field} address "
                                                f"'{value}' is invalid."))
                wildcard = s(rule.get(f"{field}_wildcard"))
                if wildcard and not is_valid_wildcard(wildcard):
                    issues.append(error("acls", f"ACL '{acl_id}': wildcard "
                                                f"'{wildcard}' is not a valid "
                                                "wildcard mask."))
        # Rule-order shadowing: an all-matching rule before other rules
        for pos, rule in enumerate(rules[:-1]):
            if _rule_matches_everything(rule, acl_type):
                issues.append(warning("acls", f"ACL '{acl_id}': rule {pos + 1} matches "
                                              "all traffic, so later rules are "
                                              "unreachable. Check rule order."))
                break
    # Applications
    for app in acl_data.get("interface_apply", []):
        acl_ref = s(app.get("acl"))
        if acl_ref and acl_ref not in names:
            issues.append(warning("acls", f"ACL '{acl_ref}' is applied to "
                                          f"{s(app.get('interface'))} but is not "
                                          "defined in this project."))
        direction = s(app.get("direction", "in"))
        if direction not in ("in", "out"):
            issues.append(error("acls", f"ACL binding for '{acl_ref}' must use "
                                        "direction in or out."))
    applied: dict[str, set[str]] = {}
    for app in acl_data.get("interface_apply", []):
        interface = normalize_interface_name(s(app.get("interface")))
        if interface:
            applied.setdefault(interface, set()).add(s(app.get("direction", "in")))
    for interface, directions in applied.items():
        if {"in", "out"} <= directions:
            issues.append(info("acls", f"{interface} has both inbound and outbound "
                                       "ACLs; confirm return traffic is permitted."))
    vty_acl = s(acl_data.get("vty_acl"))
    if vty_acl and vty_acl not in names:
        issues.append(warning("acls", f"VTY access-class references ACL '{vty_acl}' "
                                      "which is not defined in this project."))
    if vty_acl and vty_acl in permissive_acls:
        issues.append(warning("acls", f"VTY access-class ACL '{vty_acl}' permits "
                                      "any source; restrict management access."))
    for binding in acl_data.get("vty_bindings", []):
        acl_ref = s(binding.get("acl"))
        if acl_ref and acl_ref not in names:
            issues.append(warning("acls", f"VTY binding references ACL '{acl_ref}' "
                                          "which is not defined in this project."))
        if acl_ref in permissive_acls:
            issues.append(warning("acls", f"VTY binding ACL '{acl_ref}' permits "
                                          "any source; restrict management access."))
        if s(binding.get("direction", "in")) not in ("in", "out"):
            issues.append(error("acls", "VTY access-class direction must be in or out."))
    for binding in acl_data.get("route_map_bindings", []):
        acl_ref = s(binding.get("acl"))
        if acl_ref and acl_ref not in names:
            issues.append(warning("acls", f"Route-map binding references ACL "
                                          f"'{acl_ref}' which is not defined."))
    mgmt_acl = s(acl_data.get("management_plane_acl"))
    if mgmt_acl and mgmt_acl not in names:
        issues.append(warning("acls", f"Management ACL '{mgmt_acl}' is not defined."))
    if mgmt_acl and mgmt_acl in permissive_acls:
        issues.append(warning("acls", f"Management ACL '{mgmt_acl}' is too permissive."))
    return issues


# --------------------------------------------------------------- routing --
def validate_routing(routing: dict, profile) -> list[Issue]:
    issues = []
    ospf = routing.get("ospf", {})
    if truthy(ospf.get("enabled")):
        if safe_int(ospf.get("process_id")) is None:
            issues.append(error("routing", "OSPF process ID must be a number."))
        rid = s(ospf.get("router_id"))
        if rid and not is_valid_ipv4(rid):
            issues.append(error("routing", "OSPF router-id must look like an "
                                           "IPv4 address."))
        if not ospf.get("networks"):
            issues.append(warning("routing", "OSPF is enabled but has no network "
                                             "statements."))
        for net in ospf.get("networks", []):
            network, wildcard, area = s(net.get("network")), s(net.get("wildcard")), \
                s(net.get("area"))
            if not is_valid_ipv4(network):
                issues.append(error("routing", f"OSPF network '{network}' is invalid."))
            if not wildcard:
                issues.append(error("routing", f"OSPF network {network}: wildcard "
                                               "mask is missing."))
            elif not is_valid_wildcard(wildcard):
                issues.append(error("routing", f"OSPF network {network}: "
                                               f"'{wildcard}' is not a valid "
                                               "wildcard mask."))
            if not area:
                issues.append(error("routing", f"OSPF network {network}: area "
                                               "is missing."))
    eigrp = routing.get("eigrp", {})
    if truthy(eigrp.get("enabled")):
        asn = safe_int(eigrp.get("asn"))
        if asn is None or not 1 <= asn <= 65535:
            issues.append(error("routing", "EIGRP AS number must be 1-65535."))
        for net in eigrp.get("networks", []):
            if not is_valid_ipv4(s(net.get("network"))):
                issues.append(error("routing", f"EIGRP network "
                                               f"'{s(net.get('network'))}' is invalid."))
            wildcard = s(net.get("wildcard"))
            if wildcard and not is_valid_wildcard(wildcard):
                issues.append(error("routing", f"EIGRP wildcard '{wildcard}' is not "
                                               "a valid wildcard mask."))
    bgp = routing.get("bgp", {})
    if truthy(bgp.get("enabled")):
        asn = safe_int(bgp.get("asn"))
        if asn is None or not 1 <= asn <= 4294967295:
            issues.append(error("routing", "BGP AS number must be 1-4294967295."))
        if not bgp.get("neighbors"):
            issues.append(warning("routing", "BGP is enabled but has no neighbors."))
        for neighbor in bgp.get("neighbors", []):
            ip = s(neighbor.get("ip"))
            if not is_valid_ipv4(ip):
                issues.append(error("routing", f"BGP neighbor '{ip}' is not a valid "
                                               "IPv4 address."))
            if safe_int(neighbor.get("remote_as")) is None:
                issues.append(error("routing", f"BGP neighbor {ip}: remote AS "
                                               "is missing or invalid."))
        for net in bgp.get("networks", []):
            if not is_valid_ipv4(s(net.get("network"))):
                issues.append(error("routing", f"BGP network "
                                               f"'{s(net.get('network'))}' is invalid."))
            mask = s(net.get("mask"))
            if mask and not is_valid_mask(mask):
                issues.append(error("routing", f"BGP network mask '{mask}' is invalid."))
    rip = routing.get("rip", {})
    if truthy(rip.get("enabled")):
        for network in parse_list(rip.get("networks")):
            if not is_valid_ipv4(network):
                issues.append(error("routing", f"RIP network '{network}' must be a "
                                               "classful network address."))
    return issues


# ------------------------------------------------------------------- vrf --
def validate_vrf(vrf_data: dict, if_data: dict, profile) -> list[Issue]:
    issues = []
    names = {s(v.get("name")) for v in vrf_data.get("vrfs", []) if s(v.get("name"))}
    for vrf in vrf_data.get("vrfs", []):
        name = s(vrf.get("name"))
        if not name:
            issues.append(error("vrf", "A VRF definition has no name."))
        if s(vrf.get("rd")) and ":" not in s(vrf.get("rd")):
            issues.append(warning("vrf", f"VRF {name}: RD usually uses ASN:number or IP:number format."))
    for item in vrf_data.get("interface_assignments", []):
        name = s(item.get("vrf"))
        interface = s(item.get("interface"))
        if name and name not in names:
            issues.append(warning("vrf", f"Interface {interface} references missing VRF '{name}'."))
        if interface and not _known_interface(interface, profile):
            issues.append(warning("vrf", f"VRF interface {interface} is not in the selected profile."))
        issues.append(info("vrf", f"Applying vrf forwarding on {interface or '(interface)'} "
                                  "removes the existing interface IP on a live device."))
    for route in vrf_data.get("static_routes", []):
        name = s(route.get("vrf"))
        if name and name not in names:
            issues.append(warning("vrf", f"Static route references missing VRF '{name}'."))
        if not is_valid_ipv4(s(route.get("prefix"))):
            issues.append(error("vrf", "VRF static route destination prefix is invalid."))
        if not is_valid_mask(s(route.get("mask"))):
            issues.append(error("vrf", "VRF static route mask is invalid."))
        if s(route.get("next_hop")) and not is_valid_ipv4(s(route.get("next_hop"))):
            issues.append(error("vrf", f"VRF route next hop '{s(route.get('next_hop'))}' is invalid."))
    return issues


# ------------------------------------------------------------------ ipv6 --
def validate_ipv6(ipv6_data: dict, profile) -> list[Issue]:
    issues = []
    uses_ipv6 = bool(ipv6_data.get("interface_addresses")
                     or ipv6_data.get("static_routes")
                     or ipv6_data.get("acls")
                     or truthy(ipv6_data.get("ospfv3", {}).get("enabled")))
    if uses_ipv6 and not truthy(ipv6_data.get("unicast_routing")):
        issues.append(warning("ipv6", "IPv6 features are configured but ipv6 "
                                      "unicast-routing is not enabled."))
    for item in ipv6_data.get("interface_addresses", []):
        interface = s(item.get("interface"))
        address = s(item.get("address"))
        if not interface:
            issues.append(error("ipv6", "An IPv6 interface address row has no interface."))
        if address and not is_valid_ipv6_interface(address):
            issues.append(error("ipv6", f"IPv6 address '{address}' must include a valid prefix length."))
    for route in ipv6_data.get("static_routes", []):
        prefix = s(route.get("prefix"))
        if not is_valid_ipv6_network(prefix):
            issues.append(error("ipv6", f"IPv6 route prefix '{prefix}' is invalid."))
        next_hop = s(route.get("next_hop"))
        if next_hop and not is_valid_ipv6(next_hop):
            issues.append(error("ipv6", f"IPv6 next hop '{next_hop}' is invalid."))
    ospfv3 = ipv6_data.get("ospfv3", {})
    if truthy(ospfv3.get("enabled")) and s(ospfv3.get("router_id")) \
            and not is_valid_ipv4(s(ospfv3.get("router_id"))):
        issues.append(error("ipv6", "OSPFv3 router-id must be an IPv4-style router ID."))
    return issues


# ----------------------------------------------------------------- dmvpn --
def validate_dmvpn(dmvpn: dict, profile, section: str = "dmvpn",
                   label: str = "DMVPN") -> list[Issue]:
    issues = []
    if not truthy(dmvpn.get("enabled")):
        return issues
    role = s(dmvpn.get("role", "Hub")).lower()
    phase = s(dmvpn.get("phase", "Phase 3")).lower()
    if not s(dmvpn.get("tunnel_source_interface")) and not s(dmvpn.get("tunnel_source_ip")):
        issues.append(warning(section, f"{label} tunnel source is missing."))
    if not is_valid_ipv4(s(dmvpn.get("tunnel_ip"))) or not is_valid_mask(s(dmvpn.get("tunnel_mask"))):
        issues.append(warning(section, f"{label} tunnel IP address/mask is incomplete or invalid."))
    if not s(dmvpn.get("nhrp_network_id")):
        issues.append(warning(section, f"{label} NHRP network ID is missing."))
    if "spoke" in role:
        if not dmvpn.get("nhrp_nhs"):
            issues.append(warning(section, f"{label} spoke has no NHRP NHS."))
        has_map = any(s(item.get("nbma")) for item in dmvpn.get("nhrp_nhs", [])) \
            or any(s(item.get("nbma")) for item in dmvpn.get("nhrp_static_maps", []))
        if not has_map:
            issues.append(warning(section, f"{label} spoke has no NHRP map to hub NBMA."))
    if "3" in phase and "hub" in role and "spoke" not in role \
            and not truthy(dmvpn.get("nhrp_redirect", True)):
        issues.append(warning(section, "Phase 3 hub should enable ip nhrp redirect."))
    if "3" in phase and "spoke" in role and not truthy(dmvpn.get("nhrp_shortcut", True)):
        issues.append(warning(section, "Phase 3 spoke should enable ip nhrp shortcut."))
    if truthy(dmvpn.get("ipsec_enabled")):
        if not s(dmvpn.get("ipsec_profile")) and not s(dmvpn.get("tunnel_protection_profile")):
            issues.append(warning(section, "IPsec is enabled but no IPsec profile is named."))
        psk = s(dmvpn.get("pre_shared_key"))
        if not psk:
            issues.append(warning(section, "IPsec pre-shared key is empty."))
        elif _is_weak(psk):
            issues.append(warning(section, "IPsec pre-shared key looks weak."))
        if not s(dmvpn.get("ip_mtu")) or not s(dmvpn.get("tcp_mss")):
            issues.append(warning(section, "Encrypted DMVPN should set tunnel IP MTU and TCP MSS."))
        if truthy(dmvpn.get("nat_traversal_note", True)):
            issues.append(info(section, "If any peer sits behind NAT, IPsec "
                                        "NAT-T (UDP/4500) must be reachable "
                                        "end-to-end; transport mode is used "
                                        "so NAT devices must not rewrite "
                                        "ESP. Disable this note in the DMVPN "
                                        "form once verified."))
    routing = dmvpn.get("routing", {})
    if truthy(routing.get("ospf", {}).get("enabled")):
        network_type = s(routing.get("ospf", {}).get("network_type"))
        if network_type in ("broadcast", "non-broadcast"):
            issues.append(warning(section, f"OSPF network type {network_type} on DMVPN "
                                           "requires careful DR/NBMA design."))
    if truthy(routing.get("eigrp", {}).get("enabled")) and "hub" in role:
        if not truthy(routing.get("eigrp", {}).get("hub_disable_split_horizon", True)):
            issues.append(warning(section, "EIGRP split horizon on a hub tunnel can "
                                           "break spoke-to-spoke routing."))
        if "1" not in phase and not truthy(routing.get("eigrp", {}).get("hub_disable_next_hop_self", True)):
            issues.append(warning(section, "EIGRP next-hop-self on Phase 2/3 DMVPN "
                                           "can break spoke-to-spoke routing."))
    if truthy(routing.get("bgp", {}).get("enabled")):
        tunnel_net = ".".join(s(dmvpn.get("tunnel_ip")).split(".")[:3])
        for neighbor in routing.get("bgp", {}).get("neighbors", []):
            ip = s(neighbor.get("ip"))
            if ip and tunnel_net and not ip.startswith(tunnel_net):
                issues.append(warning(section, f"BGP neighbor {ip} does not appear "
                                               "to be in the DMVPN tunnel subnet."))
    for route in routing.get("static_routes", []):
        if s(route.get("prefix")) and not s(route.get("next_hop")):
            issues.append(warning(section, f"Static route {s(route.get('prefix'))} "
                                           "points at the multipoint GRE tunnel "
                                           "with no next hop; mGRE cannot resolve "
                                           "a bare interface route. Set the "
                                           "next-hop tunnel IP."))
    return issues


# --------------------------------------------------------------- tunnels --
DMVPN_TYPE = "GRE multipoint (DMVPN)"
VTI_TYPE = "Static VTI"
GRE_P2P_TYPE = "GRE point-to-point"
IPIP_TYPE = "IP-in-IP"

_TUNNEL_TYPE_CAPABILITY = {
    GRE_P2P_TYPE: "gre",
    DMVPN_TYPE: "dmvpn",
    VTI_TYPE: "vti",
    IPIP_TYPE: "gre",
}


def validate_tunnels(tunnels_data: dict, profile,
                     resolved_caps=None) -> list[Issue]:
    issues = []
    resolved_caps = resolved_caps or set()
    numbers: dict[str, int] = {}
    for tunnel in tunnels_data.get("tunnels", []):
        if not truthy(tunnel.get("enabled", True)):
            continue
        ttype = s(tunnel.get("type", GRE_P2P_TYPE))
        name = s(tunnel.get("name")) or f"Tunnel{s(tunnel.get('tunnel_number'))}"
        number = s(tunnel.get("tunnel_number"))
        numbers[number] = numbers.get(number, 0) + 1

        # platform/capability support
        required = _TUNNEL_TYPE_CAPABILITY.get(ttype)
        if required and resolved_caps and required not in resolved_caps:
            issues.append(warning("tunnels", f"{name}: {ttype} needs the "
                                             f"'{required}' capability, which "
                                             f"{profile.model} does not list. "
                                             "Verify platform/license support."))

        # generic tunnel completeness
        if not s(tunnel.get("tunnel_source_interface")) \
                and not s(tunnel.get("tunnel_source_ip")):
            issues.append(warning("tunnels", f"{name}: tunnel source is missing."))
        has_v4 = is_valid_ipv4(s(tunnel.get("tunnel_ip"))) \
            and is_valid_mask(s(tunnel.get("tunnel_mask")))
        has_v6 = bool(s(tunnel.get("ipv6_address")))
        if not has_v4 and not has_v6:
            issues.append(warning("tunnels", f"{name}: tunnel needs a valid IPv4 "
                                             "address/mask or an IPv6 address."))
        if ttype in (GRE_P2P_TYPE, VTI_TYPE, IPIP_TYPE) \
                and not s(tunnel.get("tunnel_destination")):
            issues.append(warning("tunnels", f"{name}: {ttype} requires a tunnel "
                                             "destination."))
        if ttype == VTI_TYPE and not truthy(tunnel.get("ipsec_enabled")):
            issues.append(warning("tunnels", f"{name}: a static VTI without IPsec "
                                             "tunnel protection carries traffic in "
                                             "clear text; enable IPsec."))
        if s(tunnel.get("vrf")):
            issues.append(info("tunnels", f"{name}: 'vrf forwarding' on the tunnel "
                                          "removes any existing tunnel IP on a live "
                                          "device; apply the address afterwards."))
        # DMVPN-specific + IPsec/routing checks reuse the DMVPN validator.
        if ttype == DMVPN_TYPE:
            working = dict(tunnel)
            working["enabled"] = True
            issues += validate_dmvpn(working, profile, section="tunnels",
                                     label=name)
        elif truthy(tunnel.get("ipsec_enabled")):
            psk = s(tunnel.get("pre_shared_key"))
            if not psk:
                issues.append(warning("tunnels", f"{name}: IPsec pre-shared key "
                                                 "is empty."))
            elif _is_weak(psk):
                issues.append(warning("tunnels", f"{name}: IPsec pre-shared key "
                                                 "looks weak."))
            if not s(tunnel.get("ip_mtu")) or not s(tunnel.get("tcp_mss")):
                issues.append(warning("tunnels", f"{name}: encrypted tunnel should "
                                                 "set IP MTU and TCP MSS to avoid "
                                                 "fragmentation."))
    for number, count in numbers.items():
        if count > 1:
            issues.append(error("tunnels", f"Tunnel{number} is defined "
                                           f"{count} times; tunnel numbers must "
                                           "be unique."))
    return issues


# ----------------------------------------------------------------- ipsla --
def validate_ipsla(ipsla: dict, profile) -> list[Issue]:
    issues = []
    op_ids = set()
    for op in ipsla.get("operations", []):
        op_id = s(op.get("id"))
        if not op_id:
            issues.append(error("ipsla", "An IP SLA operation has no ID."))
            continue
        op_ids.add(op_id)
        if not s(op.get("target")):
            issues.append(warning("ipsla", f"IP SLA {op_id} target is missing."))
        for field in ("frequency", "timeout", "threshold"):
            value = s(op.get(field))
            if value and (safe_int(value) is None or safe_int(value, 0) < 1):
                issues.append(error("ipsla", f"IP SLA {op_id} {field} must be a positive number."))
    track_ids = set()
    for track in ipsla.get("tracks", []):
        track_id, sla_id = s(track.get("id")), s(track.get("sla_id"))
        if track_id:
            track_ids.add(track_id)
        if sla_id and sla_id not in op_ids:
            issues.append(warning("ipsla", f"Track {track_id} references missing IP SLA {sla_id}."))
    tracked_ads: dict[tuple[str, str], set[str]] = {}
    floating_ads: dict[tuple[str, str], set[str]] = {}
    for route in ipsla.get("tracked_routes", []):
        track_id = s(route.get("track_id"))
        if track_id and track_id not in track_ids:
            issues.append(warning("ipsla", f"Tracked route references missing track {track_id}."))
        key = (s(route.get("prefix")), s(route.get("mask")))
        tracked_ads.setdefault(key, set()).add(s(route.get("distance")) or "1")
    for route in ipsla.get("floating_routes", []):
        key = (s(route.get("prefix")), s(route.get("mask")))
        floating_ads.setdefault(key, set()).add(s(route.get("distance")) or "250")
    # A tracked primary and its floating backup must differ in
    # administrative distance, or the backup never takes over cleanly.
    for key in tracked_ads.keys() & floating_ads.keys():
        if key == ("", ""):
            continue
        if tracked_ads[key] & floating_ads[key]:
            issues.append(warning("ipsla", f"Primary (tracked) and floating "
                                           f"backup route for {key[0]} use the "
                                           "same administrative distance."))
    return issues


# -------------------------------------------------------------------- zbf --
def validate_zbf(zbf_data: dict, profile, if_data: dict | None = None,
                 dmvpn_data: dict | None = None,
                 tunnels_data: dict | None = None) -> list[Issue]:
    issues = []
    zones = {s(z.get("name")) for z in zbf_data.get("zones", []) if s(z.get("name"))}
    policies = {s(p.get("name")) for p in zbf_data.get("policy_maps", []) if s(p.get("name"))}
    memberships: dict[str, set[str]] = {}
    for item in zbf_data.get("interface_memberships", []):
        interface = normalize_interface_name(s(item.get("interface")))
        zone = s(item.get("zone"))
        if zone and zone not in zones:
            issues.append(warning("zbf", f"Interface {interface} references missing zone '{zone}'."))
        if interface:
            memberships.setdefault(interface, set()).add(zone)
    for interface, member_zones in memberships.items():
        if len(member_zones) > 1:
            issues.append(error("zbf", f"{interface} belongs to multiple security zones."))
    for policy in zbf_data.get("policy_maps", []):
        if not policy.get("classes"):
            issues.append(warning("zbf", f"Policy map {s(policy.get('name'))} has no class actions."))
    for pair in zbf_data.get("zone_pairs", []):
        for field in ("source", "destination"):
            value = s(pair.get(field))
            if value and value != "self" and value not in zones:
                issues.append(warning("zbf", f"Zone pair {s(pair.get('name'))} references "
                                             f"missing {field} zone '{value}'."))
        if s(pair.get("policy")) and s(pair.get("policy")) not in policies:
            issues.append(warning("zbf", f"Zone pair {s(pair.get('name'))} references "
                                         f"missing policy '{s(pair.get('policy'))}'."))
        if s(pair.get("source")).lower() in ("outside", "untrust") \
                and s(pair.get("destination")).lower() in ("inside", "trust"):
            issues.append(warning("zbf", "Outside-to-inside zone pair exists; ensure "
                                         "the policy is not overly permissive."))
        if truthy(zbf_data.get("self_zone_warnings", True)) and \
                "self" in (s(pair.get("source")).lower(),
                           s(pair.get("destination")).lower()):
            issues.append(warning("zbf", "Self-zone policy affects management/control "
                                         "plane traffic; verify SSH, routing and VPN keepalives."))
    # Interfaces that forward traffic but sit in no zone cannot exchange
    # traffic with zoned interfaces - a classic ZBF black hole.
    if memberships and if_data:
        zoned = set(memberships)
        unzoned: list[str] = []
        for item in if_data.get("physical", []):
            if s(item.get("mode")) == "routed":
                name = normalize_interface_name(s(item.get("name")))
                if name and name not in zoned:
                    unzoned.append(name)
        for sub in if_data.get("subinterfaces", []):
            name = f"{normalize_interface_name(s(sub.get('parent')))}." \
                   f"{s(sub.get('vlan'))}"
            if s(sub.get("parent")) and name not in zoned:
                unzoned.append(name)
        for svi in if_data.get("svis", []):
            name = f"Vlan{s(svi.get('vlan'))}"
            if s(svi.get("vlan")) and name not in zoned:
                unzoned.append(name)
        if dmvpn_data and truthy(dmvpn_data.get("enabled")):
            tunnel = f"Tunnel{s(dmvpn_data.get('tunnel_number', '0')) or '0'}"
            if tunnel not in zoned:
                unzoned.append(tunnel)
        for tun in (tunnels_data or {}).get("tunnels", []):
            if not truthy(tun.get("enabled", True)):
                continue
            tunnel = f"Tunnel{s(tun.get('tunnel_number', '0')) or '0'}"
            if tunnel not in zoned:
                unzoned.append(tunnel)
        if unzoned:
            issues.append(warning("zbf", "These L3 interfaces are in no security "
                                         "zone and will not pass traffic to/from "
                                         "zoned interfaces: "
                                         f"{', '.join(unzoned[:6])}."))
    return issues


# -------------------------------------------------------------------- qos --
def validate_qos(qos_data: dict, if_data: dict, profile) -> list[Issue]:
    issues = []
    if qos_data.get("trust") and not (profile.is_switch
                                      and profile.os_type == "IOS"):
        issues.append(info("qos", "'mls qos trust' exists only on classic IOS "
                                  "Catalyst switches; on IOS-XE platforms "
                                  "trust is MQC/default behaviour, so no "
                                  "trust command is generated for this "
                                  "device."))
    class_names = {s(c.get("name")) for c in qos_data.get("class_maps", []) if s(c.get("name"))}
    policy_names = {s(p.get("name")) for p in qos_data.get("policy_maps", []) if s(p.get("name"))}
    for policy in qos_data.get("policy_maps", []):
        classes = policy.get("classes", [])
        if isinstance(classes, str):
            names = [c.strip() for c in classes.split(",") if c.strip()]
        else:
            names = [s(c.get("class_name") or c.get("class")) for c in classes]
        for name in names:
            if name and name not in class_names and name != "class-default":
                issues.append(warning("qos", f"QoS policy {s(policy.get('name'))} "
                                            f"references missing class map '{name}'."))
    for item in qos_data.get("service_policies", []):
        policy = s(item.get("policy"))
        if policy and policy not in policy_names:
            issues.append(warning("qos", f"Service policy references missing policy '{policy}'."))
    voice_interfaces = {
        normalize_interface_name(s(i.get("name")))
        for i in if_data.get("physical", [])
        if s(i.get("voice_vlan"))
    }
    for item in qos_data.get("trust", []):
        interface = normalize_interface_name(s(item.get("interface")))
        if interface and interface not in voice_interfaces:
            issues.append(info("qos", f"Trust on {interface} has no voice VLAN/phone "
                                      "context in the project; verify the endpoint is trusted."))
    return issues


# --------------------------------------------------------------------- ha --
def validate_ha(ha_data: dict, ipsla_data: dict, profile) -> list[Issue]:
    issues = []
    seen_vips: set[str] = set()
    tracks = {s(t.get("id")) for t in ipsla_data.get("tracks", []) if s(t.get("id"))}
    for group in ha_data.get("groups", []):
        protocol = s(group.get("protocol", "hsrp")).lower() or "hsrp"
        vip = s(group.get("virtual_ip"))
        if vip:
            if not is_valid_ipv4(vip):
                issues.append(error("ha", f"{protocol.upper()} virtual IP '{vip}' is invalid."))
            if vip in seen_vips:
                issues.append(warning("ha", f"Duplicate gateway redundancy virtual IP {vip}."))
            seen_vips.add(vip)
        if protocol not in ("hsrp", "vrrp", "glbp"):
            issues.append(error("ha", f"Unsupported HA protocol '{protocol}'."))
        if s(group.get("track_id")) and s(group.get("track_id")) not in tracks:
            issues.append(warning("ha", f"{protocol.upper()} group {s(group.get('group'))} "
                                      f"references missing track {s(group.get('track_id'))}."))
        if s(group.get("priority")) and safe_int(group.get("priority")) \
                and safe_int(group.get("priority")) > 100 \
                and not truthy(group.get("preempt")):
            issues.append(warning("ha", f"{protocol.upper()} group {s(group.get('group'))} "
                                      "has active/standby intent but preempt is disabled."))
    return issues


# -------------------------------------------------------------- custom cli --
def validate_custom_cli(cli_data: dict, profile) -> list[Issue]:
    issues = []
    issues.append(info("custom_cli", "Custom CLI is preserved but not deeply validated."))
    dangerous = (
        "reload", "erase startup-config", "write erase", "no username",
        "no ip route 0.0.0.0 0.0.0.0", "no interface",
    )
    blocks = [
        cli_data.get("global", ""),
        cli_data.get("pre_interface", ""),
        cli_data.get("post_routing", ""),
        cli_data.get("end", ""),
        cli_data.get("unparsed_imported_lines", ""),
    ]
    blocks.extend(item.get("cli", "") for item in cli_data.get("interface_snippets", []))
    text = "\n".join(s(block).lower() for block in blocks)
    for command in dangerous:
        if command in text:
            issues.append(warning("custom_cli", f"Custom CLI contains potentially dangerous command '{command}'."))
    return issues


# -------------------------------------------------------------- security --
def validate_security(sec: dict, sys_data: dict, profile) -> list[Issue]:
    issues = []
    if truthy(sec.get("login_block_enabled")):
        for field, label in (("login_block_seconds", "block time"),
                             ("login_block_attempts", "attempt count"),
                             ("login_block_within", "window")):
            if safe_int(sec.get(field)) is None:
                issues.append(error("security", f"Login block {label} must be "
                                                "a number."))
    min_len = s(sec.get("min_password_length"))
    if min_len:
        value = safe_int(min_len)
        if value is None or not 1 <= value <= 127:
            issues.append(error("security", "Minimum password length must be 1-127."))
    if truthy(sec.get("ssh_only")) and \
            "telnet" in s(sys_data.get("vty", {}).get("transport", "")):
        issues.append(warning("security", "'SSH only' hardening is selected but the "
                                          "VTY transport in Base System still allows "
                                          "Telnet; SSH-only will win in the output."))
    if truthy(sys_data.get("restconf_enabled")) and truthy(sec.get("disable_https")):
        issues.append(warning("security", "RESTCONF requires the HTTPS server, but "
                                          "Security Hardening emits 'no ip http "
                                          "secure-server'; RESTCONF will not work. "
                                          "Untick 'no ip http secure-server' or "
                                          "disable RESTCONF."))
    return issues


# --------------------------------------------------- cross-section checks --
def validate_duplicate_ips(data: dict, enabled: dict) -> list[Issue]:
    """Duplicate IPv4 addresses across routed ports, SVIs, subinterfaces and
    management interfaces."""
    issues = []
    assigned: dict[str, str] = {}

    def check(ip_value, owner):
        ip_clean = s(ip_value)
        if not ip_clean or not is_valid_ipv4(ip_clean):
            return
        if ip_clean in assigned:
            issues.append(error("interfaces", f"IP address {ip_clean} is assigned to "
                                              f"both {assigned[ip_clean]} and {owner}."))
        else:
            assigned[ip_clean] = owner

    if enabled.get("interfaces"):
        if_data = data.get("interfaces", {})
        for item in if_data.get("physical", []):
            if s(item.get("mode")) == "routed":
                check(item.get("ip"), normalize_interface_name(s(item.get("name"))))
        for pc in if_data.get("port_channels", []):
            if s(pc.get("mode")) == "routed":
                check(pc.get("ip"), f"Port-channel{s(pc.get('id'))}")
        for sub in if_data.get("subinterfaces", []):
            parent = normalize_interface_name(s(sub.get("parent")))
            check(sub.get("ip"), f"{parent}.{s(sub.get('vlan'))}")
        for svi in if_data.get("svis", []):
            check(svi.get("ip"), f"Vlan{s(svi.get('vlan'))}")
    if enabled.get("system"):
        sys_data = data.get("system", {})
        if truthy(sys_data.get("mgmt_svi", {}).get("enabled")):
            check(sys_data["mgmt_svi"].get("ip"),
                  f"management SVI Vlan{s(sys_data['mgmt_svi'].get('vlan'))}")
        if truthy(sys_data.get("mgmt_interface", {}).get("enabled")):
            check(sys_data["mgmt_interface"].get("ip"), "management interface")
    return issues
