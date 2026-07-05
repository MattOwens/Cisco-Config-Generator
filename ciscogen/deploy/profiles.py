"""Safe SSH profile storage for guarded deployment workflows."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

SECRET_FIELD_NAMES = {
    "password", "enable_secret", "secret", "passphrase", "private_key_passphrase",
}


def default_profile_path() -> Path:
    base = Path(os.environ.get("APPDATA") or Path.home() / ".ciscogen")
    return base / "CiscoConfigGenerator" / "ssh_profiles.json"


def _clean_tags(value) -> list[str]:
    if isinstance(value, str):
        raw = value.replace(";", ",").split(",")
    else:
        raw = value or []
    return [str(tag).strip() for tag in raw if str(tag).strip()]


@dataclass
class SSHProfile:
    """Connection metadata only; never stores passwords or enable secrets."""

    name: str
    host: str
    port: int = 22
    username: str = ""
    auth_method: str = "prompt"       # prompt | env | key
    key_path: str = ""
    password_env: str = ""
    enable_secret_env: str = ""
    prompt_for_enable: bool = False
    device_model: str = ""
    os_type: str = ""
    os_version: str = ""
    capability_profile: str = "device-profile"
    site: str = ""
    role: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    folder: str = ""
    last_connected: str = ""
    status: str = "Not connected"
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    @classmethod
    def from_dict(cls, raw: dict) -> "SSHProfile":
        clean = {
            key: value for key, value in dict(raw or {}).items()
            if key in cls.__dataclass_fields__ and key not in SECRET_FIELD_NAMES
        }
        clean["name"] = str(clean.get("name") or clean.get("host") or "New Profile")
        clean["host"] = str(clean.get("host") or "")
        try:
            clean["port"] = int(clean.get("port", 22) or 22)
        except (TypeError, ValueError):
            clean["port"] = 22
        clean["tags"] = _clean_tags(clean.get("tags", []))
        clean["prompt_for_enable"] = bool(clean.get("prompt_for_enable", False))
        return cls(**clean)

    def to_dict(self) -> dict:
        data = asdict(self)
        for key in SECRET_FIELD_NAMES:
            data.pop(key, None)
        data["tags"] = _clean_tags(data.get("tags", []))
        return data

    def mark_connected(self) -> None:
        self.last_connected = datetime.now().isoformat(timespec="seconds")
        self.status = "Connected"

    def duplicate(self) -> "SSHProfile":
        data = self.to_dict()
        data["id"] = uuid.uuid4().hex
        data["name"] = f"{self.name} Copy"
        data["last_connected"] = ""
        data["status"] = "Not connected"
        return SSHProfile.from_dict(data)


class SSHProfileStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else default_profile_path()

    def load(self) -> list[SSHProfile]:
        if not self.path.exists():
            return []
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        items = raw.get("profiles", raw if isinstance(raw, list) else [])
        return [SSHProfile.from_dict(item) for item in items]

    def save(self, profiles: list[SSHProfile]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": 1,
            "profiles": [profile.to_dict() for profile in profiles],
        }
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def upsert(self, profile: SSHProfile) -> None:
        profiles = self.load()
        for index, existing in enumerate(profiles):
            if existing.id == profile.id:
                profiles[index] = profile
                self.save(profiles)
                return
        profiles.append(profile)
        self.save(profiles)

    def delete(self, profile_id: str) -> bool:
        profiles = self.load()
        kept = [profile for profile in profiles if profile.id != profile_id]
        changed = len(kept) != len(profiles)
        if changed:
            self.save(kept)
        return changed

    def duplicate(self, profile_id: str) -> SSHProfile | None:
        for profile in self.load():
            if profile.id == profile_id:
                copy = profile.duplicate()
                self.upsert(copy)
                return copy
        return None

    def import_file(self, source: str | Path) -> list[SSHProfile]:
        source_path = Path(source)
        raw = json.loads(source_path.read_text(encoding="utf-8"))
        items = raw.get("profiles", raw if isinstance(raw, list) else [])
        imported = [SSHProfile.from_dict(item) for item in items]
        current = {profile.id: profile for profile in self.load()}
        for profile in imported:
            current[profile.id] = profile
        self.save(list(current.values()))
        return imported

    def export_file(self, destination: str | Path,
                    profile_ids: list[str] | None = None) -> Path:
        dest = Path(destination)
        selected = self.load()
        if profile_ids is not None:
            wanted = set(profile_ids)
            selected = [profile for profile in selected if profile.id in wanted]
        payload = {
            "schema_version": 1,
            "profiles": [profile.to_dict() for profile in selected],
        }
        dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return dest


def filter_profiles(profiles: list[SSHProfile], query: str = "",
                    folder: str = "") -> list[SSHProfile]:
    needle = (query or "").strip().lower()
    folder_l = (folder or "").strip().lower()
    result = []
    for profile in profiles:
        haystack = " ".join([
            profile.name, profile.host, profile.username, profile.device_model,
            profile.os_type, profile.os_version, profile.site, profile.role,
            profile.notes, profile.folder, " ".join(profile.tags),
        ]).lower()
        if needle and needle not in haystack:
            continue
        if folder_l and folder_l != profile.folder.lower():
            continue
        result.append(profile)
    return result
