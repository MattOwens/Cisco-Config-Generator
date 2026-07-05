"""Custom CLI form."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder, TableEditor


class CustomCliForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["custom_cli"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("Global custom CLI")
        form.text(group, "global", "Global block", height=5)
        form.text(group, "pre_interface", "Pre-interface block", height=4)

        group = form.group("Interface snippets")
        snippets = TableEditor(
            group, "",
            columns=[("interface", "Interface", 160), ("cli", "CLI", 280)],
            fields=[
                {"key": "interface", "label": "Interface"},
                {"key": "cli", "label": "CLI snippet (single/multiline)", "width": 40},
            ],
            items=data.setdefault("interface_snippets", []),
            on_change=on_change, height=4)
        form.widget(group, snippets)

        group = form.group("Post-routing and end blocks")
        form.text(group, "post_routing", "Post-routing block", height=4)
        form.text(group, "end", "End-of-config block", height=4)
        form.text(group, "unparsed_imported_lines",
                  "Preserved unparsed imported lines", height=5)
        form.note(group, "Custom CLI is exported in deterministic order but "
                         "is not deeply validated. Dangerous commands are "
                         "flagged in validation.")
