"""Miscellaneous generator: CDP/LLDP, clock timezone, archive."""

from __future__ import annotations

from ..utils import s, safe_int, truthy


def generate(misc: dict, profile) -> dict[str, list[str]]:
    services: list[str] = []
    if not truthy(misc.get("cdp_run", True)):
        services.append("no cdp run")
    if truthy(misc.get("lldp_run")):
        services.append("lldp run")
    tz_name = s(misc.get("clock_timezone_name"))
    tz_hours = s(misc.get("clock_timezone_hours"))
    if tz_name and tz_hours:
        tz_minutes = safe_int(misc.get("clock_timezone_minutes"), 0) or 0
        services.append(f"clock timezone {tz_name} {tz_hours} {tz_minutes}")

    archive: list[str] = []
    if truthy(misc.get("archive_enabled")):
        archive.append("archive")
        path = s(misc.get("archive_path")) or "flash:archive"
        archive.append(f" path {path}")
        if truthy(misc.get("archive_write_memory", True)):
            archive.append(" write-memory")
        period = s(misc.get("archive_time_period"))
        if period:
            archive.append(f" time-period {period}")

    return {"services": services, "archive": archive}
