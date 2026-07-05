"""Custom CLI generator.

The custom section is intentionally simple: the app preserves user-supplied
blocks and places them in deterministic locations around generated config.
"""

from __future__ import annotations

from ..utils import normalize_interface_name, s


def _block(text: str) -> list[str]:
    return [line.rstrip() for line in s(text).splitlines() if line.strip()]


def collect_interface_extras(cli_data: dict, extras: dict[str, list[str]]) -> None:
    for item in cli_data.get("interface_snippets", []):
        interface = normalize_interface_name(s(item.get("interface")))
        cli = _block(item.get("cli", ""))
        if interface and cli:
            extras.setdefault(interface, []).extend(f" {line.lstrip()}" for line in cli)


def generate(cli_data: dict, profile) -> dict[str, list[str]]:
    return {
        "custom_global": _block(cli_data.get("global", "")),
        "custom_pre_interface": _block(cli_data.get("pre_interface", "")),
        "custom_post_routing": _block(cli_data.get("post_routing", "")),
        "custom_end": _block(cli_data.get("end", "")) + _block(cli_data.get("unparsed_imported_lines", "")),
    }
