"""Left sidebar: device selection, section list with toggles, options."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from .. import DISCLAIMER
from ..models import SECTIONS, SECTION_LABELS
from . import theme


class Sidebar(tk.Frame):
    """Dark sidebar.  The app wires the callbacks:

    on_device_change(model), on_os_version_change(version),
    on_section_toggle(key, enabled), on_section_select(key),
    on_option_change()
    """

    def __init__(self, parent, profiles: dict, callbacks: dict):
        super().__init__(parent, background=theme.SIDEBAR_BG, width=270)
        self.pack_propagate(False)
        self.profiles = profiles
        self.callbacks = callbacks
        self._section_rows: dict[str, tuple[tk.Frame, tk.Label]] = {}
        self._section_vars: dict[str, tk.BooleanVar] = {}
        self._visible_sections: set[str] = set(SECTIONS)
        self.selected_section = "system"

        self._label("CISCO CONFIG", font=("Segoe UI", 13, "bold"),
                    fg="#ffffff", pady=(16, 0))
        self._label("GENERATOR", font=("Segoe UI", 13, "bold"),
                    fg=theme.ACCENT, pady=(0, 10))

        # ------------------------------------------------------- device --
        self._label("DEVICE", muted=True)
        box = tk.Frame(self, background=theme.SIDEBAR_BG)
        box.pack(fill="x", padx=14)

        classes = ["Switches", "Routers"]
        self.class_var = tk.StringVar(value="Switches")
        self.class_combo = ttk.Combobox(box, values=classes, state="readonly",
                                        textvariable=self.class_var)
        self.class_combo.pack(fill="x", pady=(2, 4))
        self.class_combo.bind("<<ComboboxSelected>>",
                              lambda e: self._refill_models())

        self.model_var = tk.StringVar()
        self.model_combo = ttk.Combobox(box, state="readonly",
                                        textvariable=self.model_var)
        self.model_combo.pack(fill="x", pady=(0, 4))
        self.model_combo.bind("<<ComboboxSelected>>", self._model_changed)

        os_row = tk.Frame(box, background=theme.SIDEBAR_BG)
        os_row.pack(fill="x", pady=(0, 2))
        self.os_type_label = tk.Label(os_row, text="", anchor="w",
                                      background=theme.SIDEBAR_BG,
                                      foreground=theme.SIDEBAR_TEXT,
                                      font=theme.FONT_SMALL)
        self.os_type_label.pack(side="left")

        self.version_var = tk.StringVar()
        self.version_combo = ttk.Combobox(box, textvariable=self.version_var,
                                          state="normal")
        self.version_combo.pack(fill="x", pady=(2, 4))
        self.version_combo.bind("<<ComboboxSelected>>", self._version_changed)
        self.version_combo.bind("<FocusOut>", self._version_changed)
        self.version_combo.bind("<Return>", self._version_changed)

        self.device_info = tk.Label(box, text="", anchor="w", justify="left",
                                    background=theme.SIDEBAR_BG,
                                    foreground=theme.SIDEBAR_MUTED,
                                    font=theme.FONT_SMALL, wraplength=230)
        self.device_info.pack(fill="x", pady=(0, 6))

        # ----------------------------------------------------- sections --
        self._label("CONFIGURATION SECTIONS", muted=True)
        self.sections_box = tk.Frame(self, background=theme.SIDEBAR_BG)
        self.sections_box.pack(fill="x", padx=8)
        for key in SECTIONS:
            var = tk.BooleanVar(value=False)
            row = tk.Frame(self.sections_box, background=theme.SIDEBAR_BG)
            row.pack(fill="x", pady=1)
            check = tk.Checkbutton(
                row, variable=var, background=theme.SIDEBAR_BG,
                activebackground=theme.SIDEBAR_BG,
                selectcolor=theme.SIDEBAR_BG, foreground=theme.SIDEBAR_TEXT,
                highlightthickness=0, borderwidth=0,
                command=lambda k=key, v=var: self.callbacks
                ["on_section_toggle"](k, v.get()))
            check.pack(side="left")
            label = tk.Label(row, text=SECTION_LABELS[key], anchor="w",
                             background=theme.SIDEBAR_BG,
                             foreground=theme.SIDEBAR_TEXT, font=theme.FONT_UI,
                             padx=6, pady=2, cursor="hand2")
            label.pack(side="left", fill="x", expand=True)
            label.bind("<Button-1>",
                       lambda e, k=key: self.select_section(k, notify=True))
            self._section_rows[key] = (row, label)
            self._section_vars[key] = var

        # ------------------------------------------------------ options --
        self._label("OPTIONS", muted=True, pady=(12, 2))
        options_box = tk.Frame(self, background=theme.SIDEBAR_BG)
        options_box.pack(fill="x", padx=14)
        self.comments_var = tk.BooleanVar(value=False)
        tk.Checkbutton(options_box, text="Include section comments",
                       variable=self.comments_var,
                       background=theme.SIDEBAR_BG,
                       activebackground=theme.SIDEBAR_BG,
                       selectcolor=theme.SIDEBAR_BG,
                       foreground=theme.SIDEBAR_TEXT,
                       activeforeground=theme.SIDEBAR_TEXT,
                       highlightthickness=0, anchor="w",
                       command=lambda: self.callbacks["on_option_change"]()
                       ).pack(fill="x")

        # --------------------------------------------------- disclaimer --
        disclaimer = tk.Label(self, text=DISCLAIMER, justify="left",
                              wraplength=236, background=theme.SIDEBAR_BG,
                              foreground=theme.SIDEBAR_MUTED,
                              font=("Segoe UI", 8))
        disclaimer.pack(side="bottom", fill="x", padx=14, pady=12)

        self._refill_models()

    # ------------------------------------------------------------ helpers
    def _label(self, text, muted=False, font=None, fg=None, pady=(12, 2)):
        tk.Label(self, text=text,
                 background=theme.SIDEBAR_BG,
                 foreground=fg or (theme.SIDEBAR_MUTED if muted
                                   else theme.SIDEBAR_TEXT),
                 font=font or ("Segoe UI", 8, "bold"),
                 anchor="w").pack(fill="x", padx=14, pady=pady)

    def _models_for_class(self) -> list[str]:
        wanted = "switch" if self.class_var.get() == "Switches" else "router"
        return [m for m, p in self.profiles.items()
                if p.device_class == wanted]

    def _refill_models(self, keep: str | None = None):
        models = self._models_for_class()
        self.model_combo.configure(values=models)
        if keep and keep in models:
            self.model_var.set(keep)
        elif models:
            self.model_var.set(models[0])
        self._model_changed()

    def _model_changed(self, _event=None):
        profile = self.profiles.get(self.model_var.get())
        if not profile:
            return
        self.os_type_label.configure(text=f"OS: {profile.os_type}")
        self.version_combo.configure(values=profile.supported_os_versions)
        if self.version_var.get() not in profile.supported_os_versions:
            self.version_var.set(profile.supported_os_versions[-1])
        self.device_info.configure(
            text=f"{profile.family} - {profile.interface_count} interfaces\n"
                 f"{profile.interface_naming}")
        self.callbacks["on_device_change"](profile.model)

    def _version_changed(self, _event=None):
        self.callbacks["on_os_version_change"](self.version_var.get())

    # --------------------------------------------------------- public API
    def set_device(self, model: str, os_version: str):
        profile = self.profiles.get(model)
        if not profile:
            return
        self.class_var.set("Switches" if profile.is_switch else "Routers")
        models = self._models_for_class()
        self.model_combo.configure(values=models)
        self.model_var.set(model)
        self.os_type_label.configure(text=f"OS: {profile.os_type}")
        self.version_combo.configure(values=profile.supported_os_versions)
        self.version_var.set(os_version or profile.supported_os_versions[-1])
        self.device_info.configure(
            text=f"{profile.family} - {profile.interface_count} interfaces\n"
                 f"{profile.interface_naming}")

    def set_sections(self, enabled: dict):
        for key, var in self._section_vars.items():
            var.set(bool(enabled.get(key)))

    def set_section_enabled(self, key: str, enabled: bool):
        if key in self._section_vars:
            self._section_vars[key].set(bool(enabled))

    def set_visible_sections(self, visible: list[str] | set[str]):
        self._visible_sections = set(visible)
        for row, _label in self._section_rows.values():
            row.pack_forget()
        for key in SECTIONS:
            if key in self._visible_sections:
                row, _label = self._section_rows[key]
                row.pack(fill="x", pady=1)

    def set_options(self, options: dict):
        self.comments_var.set(bool(options.get("include_comments")))

    def select_section(self, key: str, notify: bool = False):
        if key not in self._visible_sections:
            key = "system"
        self.selected_section = key
        for section_key, (row, label) in self._section_rows.items():
            selected = section_key == key
            bg = theme.SIDEBAR_SELECTED if selected else theme.SIDEBAR_BG
            row.configure(background=bg)
            label.configure(background=bg,
                            foreground="#ffffff" if selected
                            else theme.SIDEBAR_TEXT)
            for child in row.winfo_children():
                if isinstance(child, tk.Checkbutton):
                    child.configure(background=bg, activebackground=bg,
                                    selectcolor=bg)
        if notify:
            self.callbacks["on_section_select"](key)
