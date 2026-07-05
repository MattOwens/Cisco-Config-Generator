"""Security hardening generator.

VTY 'transport input ssh' enforcement is handled by the lines generator
(base.generate_lines with force_ssh=True); password encryption and enable
secret live in Base System.  Duplicate global commands are removed by the
orchestrator, so overlap with Base System options is safe.
"""

from __future__ import annotations

from ..utils import s, safe_int, truthy


def generate(sec: dict, profile) -> dict[str, list[str]]:
    services: list[str] = []
    if truthy(sec.get("disable_http")):
        services.append("no ip http server")
    if truthy(sec.get("disable_https")):
        services.append("no ip http secure-server")
    if truthy(sec.get("no_small_servers")):
        services.append("no service tcp-small-servers")
        services.append("no service udp-small-servers")
    if truthy(sec.get("no_pad")):
        services.append("no service pad")
    if truthy(sec.get("no_ip_source_route")):
        services.append("no ip source-route")
    if truthy(sec.get("tcp_keepalives")):
        services.append("service tcp-keepalives-in")
        services.append("service tcp-keepalives-out")

    identity: list[str] = []
    if truthy(sec.get("login_block_enabled")):
        seconds = safe_int(sec.get("login_block_seconds"), 120) or 120
        attempts = safe_int(sec.get("login_block_attempts"), 3) or 3
        within = safe_int(sec.get("login_block_within"), 60) or 60
        identity.append(f"login block-for {seconds} attempts {attempts} "
                        f"within {within}")
    min_length = s(sec.get("min_password_length"))
    if min_length and safe_int(min_length):
        identity.append(f"security passwords min-length {min_length}")

    return {"services": services, "identity": identity}
