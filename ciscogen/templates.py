"""JSON template/preset loading and merge helpers."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from .models.project import SECTIONS

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "samples" / "templates"


def available_templates(directory: Path | None = None) -> list[Path]:
    root = directory or TEMPLATE_DIR
    return sorted(root.glob("*.json"))


def load_template(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _merge_value(current, incoming):
    if isinstance(current, dict) and isinstance(incoming, dict):
        result = copy.deepcopy(current)
        for key, value in incoming.items():
            result[key] = _merge_value(result.get(key), value)
        return result
    if isinstance(current, list) and isinstance(incoming, list):
        return copy.deepcopy(current) + copy.deepcopy(incoming)
    return copy.deepcopy(incoming)


def apply_template(project, template: dict) -> list[str]:
    """Merge a template into a project and return sections that were touched."""
    touched: list[str] = []
    for key, value in template.get("sections_enabled", {}).items():
        if key in project.sections_enabled:
            project.sections_enabled[key] = bool(value)
            touched.append(key)
    data = template.get("data", {})
    for section, section_data in data.items():
        if section not in project.data:
            continue
        project.data[section] = _merge_value(project.data[section], section_data)
        touched.append(section)
        if section in SECTIONS:
            project.sections_enabled[section] = True
    for attr in ("device_model", "os_type", "os_version"):
        if attr in template:
            setattr(project, attr, template[attr])
    return sorted(set(touched), key=lambda k: SECTIONS.index(k) if k in SECTIONS else 999)
