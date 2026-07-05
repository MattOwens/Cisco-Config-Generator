"""Small shared helpers used by generators, validators and the UI."""

from __future__ import annotations

# Abbreviation -> canonical IOS interface type name.  Matching picks the
# longest abbreviation whose remainder starts with a digit, so "twe1/0/1"
# resolves to TwentyFiveGigE and "tw1/0/1" to TwoGigabitEthernet.
_IF_TYPES = [
    ("hundredgige", "HundredGigE"),
    ("fortygigabitethernet", "FortyGigabitEthernet"),
    ("twentyfivegige", "TwentyFiveGigE"),
    ("tengigabitethernet", "TenGigabitEthernet"),
    ("twogigabitethernet", "TwoGigabitEthernet"),
    ("gigabitethernet", "GigabitEthernet"),
    ("fastethernet", "FastEthernet"),
    ("port-channel", "Port-channel"),
    ("portchannel", "Port-channel"),
    ("loopback", "Loopback"),
    ("ethernet", "Ethernet"),
    ("tunnel", "Tunnel"),
    ("serial", "Serial"),
    ("vlan", "Vlan"),
    ("hu", "HundredGigE"),
    ("fo", "FortyGigabitEthernet"),
    ("twe", "TwentyFiveGigE"),
    ("ten", "TenGigabitEthernet"),
    ("te", "TenGigabitEthernet"),
    ("tw", "TwoGigabitEthernet"),
    ("gig", "GigabitEthernet"),
    ("gi", "GigabitEthernet"),
    ("fas", "FastEthernet"),
    ("fa", "FastEthernet"),
    ("po", "Port-channel"),
    ("lo", "Loopback"),
    ("eth", "Ethernet"),
    ("tu", "Tunnel"),
    ("se", "Serial"),
    ("vl", "Vlan"),
]


def normalize_interface_name(name: str) -> str:
    """Expand abbreviated interface names ('gi1/0/1' -> 'GigabitEthernet1/0/1')."""
    raw = (name or "").strip().replace(" ", "")
    if not raw:
        return ""
    lower = raw.lower()
    best = None
    for short, canonical in _IF_TYPES:
        if lower.startswith(short):
            rest = raw[len(short):]
            if rest == "" or rest[0].isdigit():
                if best is None or len(short) > len(best[0]):
                    best = (short, canonical, rest)
    if best:
        return best[1] + best[2]
    return raw


def interface_base(name: str) -> str:
    """Return the physical parent of a subinterface name."""
    return normalize_interface_name(name).split(".")[0]


def parse_list(value) -> list[str]:
    """Parse a comma/space separated string (or list) into a clean list."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    parts = str(value).replace(",", " ").split()
    return [p.strip() for p in parts if p.strip()]


def safe_int(value, default: int | None = None) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def s(value) -> str:
    """Stringify and strip a form value; None becomes ''."""
    return str(value).strip() if value is not None else ""


def truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return s(value).lower() in ("1", "true", "yes", "on")


def expand_interface_range(text: str) -> list[str]:
    """Expand 'Gi1/0/1-8' into ['Gi1/0/1', ..., 'Gi1/0/8'].

    Only the last numeric component may be a range; anything else is
    returned unchanged as a single name.
    """
    import re

    text = s(text)
    match = re.match(r"^(.*?)(\d+)\s*-\s*(\d+)$", text)
    if not match:
        return [text] if text else []
    prefix, start, end = match.group(1), int(match.group(2)), int(match.group(3))
    if end < start:
        start, end = end, start
    if end - start > 96:  # sanity cap
        end = start + 96
    return [f"{prefix}{i}" for i in range(start, end + 1)]
