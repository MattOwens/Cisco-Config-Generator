"""JSON-based device profile system.

Each profile in profiles/data/ describes one device model: its OS, versions,
interfaces and feature capabilities.  Generators and validators consult the
profile so the application can warn about unsupported features.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"

REQUIRED_KEYS = [
    "model", "family", "device_class", "os_type", "supported_os_versions",
    "interface_naming", "interfaces", "interface_count", "capabilities",
    "syntax_notes", "platform_warnings", "feature_warnings",
]


@dataclass
class DeviceProfile:
    model: str
    family: str
    device_class: str          # "switch" | "router"
    os_type: str               # "IOS" | "IOS-XE" | "IOS-like (CBS)"
    supported_os_versions: list[str]
    interface_naming: str
    interfaces: list[str]
    interface_count: int
    capabilities: dict = field(default_factory=dict)
    syntax_notes: list[str] = field(default_factory=list)
    platform_warnings: list[str] = field(default_factory=list)
    feature_warnings: dict = field(default_factory=dict)
    source_file: str = ""

    def supports(self, feature: str) -> bool:
        return bool(self.capabilities.get(feature, False))

    def warning_for(self, feature: str) -> str | None:
        """Warning text for a feature that is conditional or unsupported."""
        return self.feature_warnings.get(feature)

    @property
    def is_switch(self) -> bool:
        return self.device_class == "switch"

    @property
    def is_router(self) -> bool:
        return self.device_class == "router"

    @property
    def is_l3(self) -> bool:
        return self.supports("layer3")


class ProfileError(Exception):
    pass


def load_profile_file(path: Path) -> DeviceProfile:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError(f"Cannot read profile {path.name}: {exc}") from exc
    missing = [k for k in REQUIRED_KEYS if k not in data]
    if missing:
        raise ProfileError(f"Profile {path.name} missing keys: {', '.join(missing)}")
    return DeviceProfile(source_file=str(path), **{k: data[k] for k in REQUIRED_KEYS})


def load_profiles(data_dir: Path | None = None) -> dict[str, DeviceProfile]:
    """Load every profile, returned as {model: DeviceProfile} sorted by class/model."""
    directory = data_dir or DATA_DIR
    profiles: dict[str, DeviceProfile] = {}
    for path in sorted(directory.glob("*.json")):
        profile = load_profile_file(path)
        profiles[profile.model] = profile
    if not profiles:
        raise ProfileError(f"No device profiles found in {directory}")
    ordered = sorted(profiles.values(),
                     key=lambda p: (p.device_class, p.family.lower(),
                                    p.model.lower()))
    return {p.model: p for p in ordered}
