"""Reusable UI building blocks: dict binding, scrollable frames, form
builders and a generic table editor with an add/edit dialog."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from . import theme


# ------------------------------------------------------------------ binding
class Binder:
    """Binds tk variables to keys (dotted paths supported) of a data dict.

    Writing to a bound variable updates the dict and fires on_change, which
    the app uses to debounce live preview regeneration.
    """

    def __init__(self, data: dict, on_change):
        self.data = data
        self.on_change = on_change

    def _resolve(self, key: str):
        node = self.data
        parts = key.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        return node, parts[-1]

    def string(self, key: str, default: str = "") -> tk.StringVar:
        node, leaf = self._resolve(key)
        var = tk.StringVar(value=str(node.get(leaf, default)))
        node.setdefault(leaf, default)

        def _write(*_):
            node[leaf] = var.get()
            self.on_change()
        var.trace_add("write", _write)
        return var

    def boolean(self, key: str, default: bool = False) -> tk.BooleanVar:
        node, leaf = self._resolve(key)
        var = tk.BooleanVar(value=bool(node.get(leaf, default)))
        node.setdefault(leaf, default)

        def _write(*_):
            node[leaf] = bool(var.get())
            self.on_change()
        var.trace_add("write", _write)
        return var


# --------------------------------------------------------------- scrolling
class ScrollableFrame(ttk.Frame):
    """Vertical scrollable container; build content into ``.inner``."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self._canvas = tk.Canvas(self, highlightthickness=0,
                                 background=theme.BG)
        scrollbar = ttk.Scrollbar(self, orient="vertical",
                                  command=self._canvas.yview)
        self.inner = ttk.Frame(self._canvas)
        self._window = self._canvas.create_window((0, 0), window=self.inner,
                                                  anchor="nw")
        self._canvas.configure(yscrollcommand=scrollbar.set)
        self._canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.inner.bind("<Configure>", self._on_inner_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)
        self._canvas.bind("<Enter>", lambda e: self._bind_wheel())
        self._canvas.bind("<Leave>", lambda e: self._unbind_wheel())

    def _on_inner_configure(self, _event):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self._canvas.itemconfigure(self._window, width=event.width)

    def _bind_wheel(self):
        self._canvas.bind_all("<MouseWheel>", self._on_wheel)

    def _unbind_wheel(self):
        self._canvas.unbind_all("<MouseWheel>")

    def _on_wheel(self, event):
        self._canvas.yview_scroll(int(-event.delta / 120), "units")


# ------------------------------------------------------------- form builder
class FormBuilder:
    """Lays out labelled fields bound through a Binder, grouped in
    LabelFrames with a two-column grid."""

    def __init__(self, parent: ttk.Frame, binder: Binder):
        self.parent = parent
        self.binder = binder

    def group(self, title: str) -> ttk.Labelframe:
        frame = ttk.Labelframe(self.parent, text=title, padding=(12, 8))
        frame.pack(fill="x", padx=12, pady=(10, 2))
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)
        frame._row = 0        # next grid row
        frame._col = 0        # 0 = left column pair, 1 = right column pair
        return frame

    def _slot(self, frame) -> tuple[int, int]:
        row, col = frame._row, frame._col * 2
        frame._col += 1
        if frame._col > 1:
            frame._col = 0
            frame._row += 1
        return row, col

    def newline(self, frame) -> None:
        if frame._col != 0:
            frame._col = 0
            frame._row += 1

    def entry(self, frame, key: str, label: str, default: str = "",
              width: int = 26) -> ttk.Entry:
        row, col = self._slot(frame)
        ttk.Label(frame, text=label).grid(row=row, column=col, sticky="w",
                                          padx=(0, 8), pady=3)
        widget = ttk.Entry(frame, textvariable=self.binder.string(key, default),
                           width=width)
        widget.grid(row=row, column=col + 1, sticky="we", padx=(0, 16), pady=3)
        return widget

    def combo(self, frame, key: str, label: str, values: list[str],
              default: str = "", editable: bool = False,
              width: int = 24) -> ttk.Combobox:
        row, col = self._slot(frame)
        ttk.Label(frame, text=label).grid(row=row, column=col, sticky="w",
                                          padx=(0, 8), pady=3)
        state = "normal" if editable else "readonly"
        widget = ttk.Combobox(frame, values=values, state=state, width=width,
                              textvariable=self.binder.string(key, default))
        widget.grid(row=row, column=col + 1, sticky="we", padx=(0, 16), pady=3)
        return widget

    def check(self, frame, key: str, label: str,
              default: bool = False) -> ttk.Checkbutton:
        row, col = self._slot(frame)
        widget = ttk.Checkbutton(frame, text=label,
                                 variable=self.binder.boolean(key, default))
        widget.grid(row=row, column=col, columnspan=2, sticky="w",
                    padx=(0, 16), pady=3)
        return widget

    def text(self, frame, key: str, label: str, height: int = 4) -> tk.Text:
        self.newline(frame)
        row, _ = self._slot(frame)
        frame._col = 0
        frame._row = row + 1
        ttk.Label(frame, text=label).grid(row=row, column=0, sticky="nw",
                                          padx=(0, 8), pady=3)
        widget = tk.Text(frame, height=height, width=48, font=theme.FONT_UI,
                         relief="solid", borderwidth=1,
                         highlightthickness=0, wrap="word")
        widget.grid(row=row, column=1, columnspan=3, sticky="we", pady=3)
        node, leaf = self.binder._resolve(key)
        widget.insert("1.0", str(node.get(leaf, "")))

        def _write(_event=None):
            node[leaf] = widget.get("1.0", "end-1c")
            self.binder.on_change()
        widget.bind("<KeyRelease>", _write)
        return widget

    def widget(self, frame, widget, pady=(6, 2)) -> None:
        """Place a prebuilt widget (e.g. TableEditor) across the full width."""
        self.newline(frame)
        widget.grid(row=frame._row, column=0, columnspan=4, sticky="we",
                    pady=pady)
        frame._row += 1

    def note(self, frame, text: str) -> None:
        self.newline(frame)
        row, _ = self._slot(frame)
        frame._col = 0
        frame._row = row + 1
        ttk.Label(frame, text=text, style="Muted.TLabel", wraplength=560,
                  justify="left").grid(row=row, column=0, columnspan=4,
                                       sticky="w", pady=(2, 4))


# -------------------------------------------------------------- row dialog
class RowDialog(tk.Toplevel):
    """Modal dialog generated from field specs; returns .result dict."""

    def __init__(self, parent, title: str, fields: list[dict],
                 initial: dict | None = None):
        super().__init__(parent)
        self.title(title)
        self.transient(parent.winfo_toplevel())
        self.resizable(False, False)
        self.configure(background=theme.BG)
        self.result: dict | None = None
        self._fields = fields
        self._vars: dict[str, tk.Variable] = {}
        initial = initial or {}

        body = ttk.Frame(self, padding=14)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.columnconfigure(3, weight=1)

        row = col = 0
        for field in fields:
            key = field["key"]
            ftype = field.get("type", "entry")
            label = field.get("label", key)
            default = initial.get(key, field.get("default",
                                                 False if ftype == "check" else ""))
            if field.get("fullrow") and col == 1:
                row, col = row + 1, 0
            if ftype == "check":
                var = tk.BooleanVar(value=bool(default))
                ttk.Checkbutton(body, text=label, variable=var).grid(
                    row=row, column=col * 2, columnspan=2, sticky="w",
                    padx=6, pady=3)
            else:
                var = tk.StringVar(value=str(default))
                ttk.Label(body, text=label).grid(row=row, column=col * 2,
                                                 sticky="w", padx=6, pady=3)
                if ftype == "combo":
                    state = "normal" if field.get("editable") else "readonly"
                    ttk.Combobox(body, textvariable=var, state=state,
                                 values=field.get("values", []),
                                 width=field.get("width", 20)).grid(
                        row=row, column=col * 2 + 1, sticky="we",
                        padx=(0, 10), pady=3)
                else:
                    ttk.Entry(body, textvariable=var,
                              width=field.get("width", 22)).grid(
                        row=row, column=col * 2 + 1, sticky="we",
                        padx=(0, 10), pady=3)
            self._vars[key] = var
            col += 1
            if col > 1 or field.get("fullrow"):
                row, col = row + 1, 0

        buttons = ttk.Frame(self, padding=(14, 0, 14, 12))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(
            side="right", padx=(6, 0))
        ttk.Button(buttons, text="OK", style="Accent.TButton",
                   command=self._ok).pack(side="right")

        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self.destroy())
        self.wait_visibility()
        self.grab_set()
        self.focus_set()
        # Block until closed so callers can read .result right away.
        self.wait_window(self)

    def _ok(self):
        result = {}
        for field in self._fields:
            var = self._vars[field["key"]]
            value = var.get()
            result[field["key"]] = value.strip() if isinstance(value, str) else value
        self.result = result
        self.destroy()


# ------------------------------------------------------------ table editor
class TableEditor(ttk.Frame):
    """Treeview-backed list-of-dicts editor with Add/Edit/Remove/reorder.

    ``items`` is mutated in place so the project dict stays authoritative.
    """

    def __init__(self, parent, title: str, columns: list[tuple],
                 fields: list[dict], items: list[dict], on_change,
                 height: int = 5, extra_buttons: list[tuple] | None = None,
                 on_select=None):
        super().__init__(parent)
        self.columns = columns
        self.fields = fields
        self.items = items
        self.on_change = on_change
        self.on_select = on_select
        self.dialog_title = title

        if title:
            ttk.Label(self, text=title, font=theme.FONT_UI_BOLD).pack(
                anchor="w", pady=(0, 4))

        table_frame = ttk.Frame(self)
        table_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(table_frame,
                                 columns=[c[0] for c in columns],
                                 show="headings", height=height,
                                 selectmode="browse")
        for key, heading, width in columns:
            self.tree.heading(key, text=heading)
            self.tree.column(key, width=width, stretch=True)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical",
                                  command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda e: self.edit_selected())
        self.tree.bind("<<TreeviewSelect>>", self._selected_changed)

        buttons = ttk.Frame(self)
        buttons.pack(fill="x", pady=(4, 0))
        ttk.Button(buttons, text="Add", command=self.add).pack(side="left")
        ttk.Button(buttons, text="Edit", command=self.edit_selected).pack(
            side="left", padx=(6, 0))
        ttk.Button(buttons, text="Remove", command=self.remove_selected).pack(
            side="left", padx=(6, 0))
        ttk.Button(buttons, text="▲", width=3,
                   command=lambda: self.move(-1)).pack(side="left", padx=(12, 0))
        ttk.Button(buttons, text="▼", width=3,
                   command=lambda: self.move(1)).pack(side="left", padx=(4, 0))
        for label, callback in (extra_buttons or []):
            ttk.Button(buttons, text=label,
                       command=lambda cb=callback: cb(self)).pack(
                side="left", padx=(12, 0))
        self.refresh()

    # -- data helpers ------------------------------------------------------
    def set_items(self, items: list[dict]) -> None:
        self.items = items
        self.refresh()

    def refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for index, item in enumerate(self.items):
            values = []
            for key, _heading, _width in self.columns:
                value = item.get(key, "")
                if isinstance(value, bool):
                    value = "yes" if value else ""
                values.append(value)
            self.tree.insert("", "end", iid=str(index), values=values)

    def selected_index(self) -> int | None:
        selection = self.tree.selection()
        if not selection:
            return None
        return int(selection[0])

    def _selected_changed(self, _event):
        if self.on_select:
            self.on_select(self.selected_index())

    # -- actions -----------------------------------------------------------
    def add(self) -> None:
        dialog = RowDialog(self, f"Add - {self.dialog_title or 'entry'}",
                           self.fields)
        if dialog.result is not None:
            self.items.append(dialog.result)
            self.refresh()
            self.on_change()

    def edit_selected(self) -> None:
        index = self.selected_index()
        if index is None:
            messagebox.showinfo("Edit", "Select a row first.", parent=self)
            return
        dialog = RowDialog(self, f"Edit - {self.dialog_title or 'entry'}",
                           self.fields, initial=self.items[index])
        if dialog.result is not None:
            # Update (not replace) so keys outside the dialog fields, such
            # as an ACL's nested "rules" list, are preserved.
            self.items[index].update(dialog.result)
            self.refresh()
            self.tree.selection_set(str(index))
            self.on_change()

    def remove_selected(self) -> None:
        index = self.selected_index()
        if index is None:
            return
        del self.items[index]
        self.refresh()
        if self.on_select:
            self.on_select(None)
        self.on_change()

    def move(self, delta: int) -> None:
        index = self.selected_index()
        if index is None:
            return
        target = index + delta
        if not 0 <= target < len(self.items):
            return
        self.items[index], self.items[target] = \
            self.items[target], self.items[index]
        self.refresh()
        self.tree.selection_set(str(target))
        self.on_change()
