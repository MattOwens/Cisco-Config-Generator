"""Right-hand panels: live CLI preview / editable final config, warnings."""

from __future__ import annotations

import difflib
import tkinter as tk
from tkinter import ttk

from . import theme


def _console_text(parent) -> tk.Text:
    text = tk.Text(parent, wrap="none", font=theme.FONT_MONO,
                   background=theme.CONSOLE_BG, foreground=theme.CONSOLE_FG,
                   insertbackground="#ffffff", relief="flat",
                   padx=10, pady=8, undo=True)
    scroll_y = ttk.Scrollbar(parent, orient="vertical", command=text.yview)
    scroll_x = ttk.Scrollbar(parent, orient="horizontal", command=text.xview)
    text.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
    scroll_y.pack(side="right", fill="y")
    scroll_x.pack(side="bottom", fill="x")
    text.pack(side="left", fill="both", expand=True)
    return text


class PreviewPanel(ttk.Frame):
    """Notebook with the live (read-only) preview and the editable final
    configuration."""

    def __init__(self, parent):
        super().__init__(parent)
        self.previous_live = ""
        self._last_final_generated = ""
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        live_tab = ttk.Frame(self.notebook)
        live_tools = ttk.Frame(live_tab, padding=(4, 2))
        live_tools.pack(fill="x")
        ttk.Label(live_tools, text="Search").pack(side="left")
        self.search_var = tk.StringVar()
        ttk.Entry(live_tools, textvariable=self.search_var, width=20).pack(
            side="left", padx=(4, 6))
        ttk.Button(live_tools, text="Find",
                   command=lambda: self._search(self.live_text)).pack(side="left")
        ttk.Button(live_tools, text="Copy Selected",
                   command=lambda: self._copy_selected(self.live_text)).pack(
            side="left", padx=(6, 0))
        self.live_text = _console_text(live_tab)
        self.live_text.configure(state="disabled")
        self.notebook.add(live_tab, text="  Live Preview  ")

        final_tab = ttk.Frame(self.notebook)
        header = ttk.Frame(final_tab, padding=(4, 2))
        header.pack(fill="x")
        self.final_indicator = ttk.Label(
            header, style="Muted.TLabel",
            text="Editable. Generated content, no manual edits.")
        self.final_indicator.pack(side="left", fill="x", expand=True)
        ttk.Button(header, text="Find",
                   command=lambda: self._search(self.final_text)).pack(side="right")
        ttk.Button(header, text="Copy Selected",
                   command=lambda: self._copy_selected(self.final_text)).pack(
            side="right", padx=(0, 6))
        self.final_text = _console_text(final_tab)
        self.final_text.bind("<<Modified>>", self._final_modified)
        self.notebook.add(final_tab, text="  Final Config (editable)  ")

        diff_tab = ttk.Frame(self.notebook)
        diff_header = ttk.Label(
            diff_tab, style="Muted.TLabel", padding=(4, 2),
            text="Diff between previous live generation and current live generation.")
        diff_header.pack(fill="x")
        self.diff_text = _console_text(diff_tab)
        self.diff_text.configure(state="disabled")
        self.notebook.add(diff_tab, text="  Diff  ")

    def set_live(self, text: str) -> None:
        current = self.get_live()
        if current.strip() and current != text:
            self.previous_live = current
        self.live_text.configure(state="normal")
        self.live_text.delete("1.0", "end")
        self.live_text.insert("1.0", text)
        self.live_text.configure(state="disabled")
        self._update_diff(text)

    def set_final(self, text: str) -> None:
        self.final_text.delete("1.0", "end")
        self.final_text.insert("1.0", text)
        self._last_final_generated = text
        self.final_text.edit_reset()
        self.final_text.edit_modified(False)
        self._set_final_indicator(False)

    def get_final(self) -> str:
        return self.final_text.get("1.0", "end-1c")

    def get_live(self) -> str:
        return self.live_text.get("1.0", "end-1c")

    def show_final_tab(self) -> None:
        self.notebook.select(1)

    def show_diff_tab(self) -> None:
        self.notebook.select(2)

    def _update_diff(self, current: str) -> None:
        diff = "\n".join(difflib.unified_diff(
            self.previous_live.splitlines(),
            current.splitlines(),
            fromfile="previous",
            tofile="current",
            lineterm=""))
        self.diff_text.configure(state="normal")
        self.diff_text.delete("1.0", "end")
        self.diff_text.insert("1.0", diff or "No previous generation to diff yet.\n")
        self.diff_text.configure(state="disabled")

    def _final_modified(self, _event=None):
        modified = self.final_text.edit_modified()
        self._set_final_indicator(modified and self.get_final() != self._last_final_generated)
        self.final_text.edit_modified(False)

    def _set_final_indicator(self, edited: bool):
        text = "Manual edits present. Generate will ask before overwriting." \
            if edited else "Editable. Generated content, no manual edits."
        self.final_indicator.configure(text=text)

    def _search(self, text_widget: tk.Text):
        needle = self.search_var.get()
        if not needle:
            return
        start = text_widget.search(needle, "insert +1c", stopindex="end",
                                   nocase=True)
        if not start:
            start = text_widget.search(needle, "1.0", stopindex="end",
                                       nocase=True)
        if start:
            end = f"{start}+{len(needle)}c"
            text_widget.tag_remove("sel", "1.0", "end")
            text_widget.tag_add("sel", start, end)
            text_widget.mark_set("insert", start)
            text_widget.see(start)

    def _copy_selected(self, text_widget: tk.Text):
        try:
            selected = text_widget.get("sel.first", "sel.last")
        except tk.TclError:
            return
        root = self.winfo_toplevel()
        root.clipboard_clear()
        root.clipboard_append(selected)


class WarningsPanel(ttk.Frame):
    """Validation results table with severity colouring."""

    def __init__(self, parent):
        super().__init__(parent)
        self.header = ttk.Label(self, text="Validation", font=theme.FONT_UI_BOLD,
                                padding=(4, 4))
        self.header.pack(fill="x")

        table = ttk.Frame(self)
        table.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(table, columns=("severity", "section", "message"),
                                 show="headings", height=6)
        self.tree.heading("severity", text="Severity")
        self.tree.heading("section", text="Section")
        self.tree.heading("message", text="Message")
        self.tree.column("severity", width=80, stretch=False)
        self.tree.column("section", width=90, stretch=False)
        self.tree.column("message", width=430)
        scroll = ttk.Scrollbar(table, orient="vertical",
                               command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.tree.tag_configure("error", foreground=theme.ERROR)
        self.tree.tag_configure("warning", foreground=theme.WARNING)
        self.tree.tag_configure("info", foreground=theme.INFO)

    def set_issues(self, issues) -> None:
        self.tree.delete(*self.tree.get_children())
        counts = {"error": 0, "warning": 0, "info": 0}
        for issue in issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
            self.tree.insert("", "end", values=(issue.severity.upper(),
                                                issue.section, issue.message),
                             tags=(issue.severity,))
        self.header.configure(
            text=f"Validation - {counts['error']} errors, "
                 f"{counts['warning']} warnings, {counts['info']} notes")

    def error_count(self) -> int:
        return sum(1 for iid in self.tree.get_children()
                   if self.tree.item(iid, "values")[0] == "ERROR")
