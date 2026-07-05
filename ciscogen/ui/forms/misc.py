"""Miscellaneous form: CDP/LLDP, clock, archive."""

from __future__ import annotations

from tkinter import ttk

from ..widgets import Binder, FormBuilder


class MiscForm(ttk.Frame):
    def __init__(self, parent, project, profile, on_change):
        super().__init__(parent)
        data = project.data["misc"]
        binder = Binder(data, on_change)
        form = FormBuilder(self, binder)

        group = form.group("Discovery protocols (global)")
        form.check(group, "cdp_run", "CDP enabled (uncheck for 'no cdp run')",
                   default=True)
        form.check(group, "lldp_run", "LLDP enabled ('lldp run')")
        form.note(group, "Per-interface CDP/LLDP can be disabled in each "
                         "interface's settings in the Interfaces section.")

        group = form.group("Clock")
        form.entry(group, "clock_timezone_name", "Timezone name (e.g. EST)",
                   width=10)
        form.entry(group, "clock_timezone_hours", "UTC offset hours "
                                                  "(e.g. -5)", width=6)
        form.entry(group, "clock_timezone_minutes", "Offset minutes",
                   default="0", width=6)

        group = form.group("Configuration archive")
        form.check(group, "archive_enabled", "Enable archive")
        form.newline(group)
        form.entry(group, "archive_path", "Archive path",
                   default="flash:archive", width=28)
        form.check(group, "archive_write_memory",
                   "Archive on write-memory", default=True)
        form.entry(group, "archive_time_period",
                   "Time period (minutes)", default="1440", width=10)
        form.note(group, "The archive feature also enables 'configure "
                         "replace' rollbacks from saved archives.")
