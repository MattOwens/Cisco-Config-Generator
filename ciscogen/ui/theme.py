"""Application theme: colours, fonts and ttk style configuration."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from tkinter import font as tkfont

# Palette
BG = "#f5f7fa"
SURFACE = "#ffffff"
BORDER = "#d7dee8"
TEXT = "#1f2933"
TEXT_MUTED = "#616e7c"
ACCENT = "#2f6fed"
ACCENT_DARK = "#1d4fbf"
SIDEBAR_BG = "#1f2d3d"
SIDEBAR_TEXT = "#e5ecf5"
SIDEBAR_MUTED = "#8fa3b8"
SIDEBAR_SELECTED = "#2f6fed"
CONSOLE_BG = "#1e1e1e"
CONSOLE_FG = "#d4d4d4"
ERROR = "#c0392b"
WARNING = "#9c6b1f"
INFO = "#2c7a7b"

FONT_UI = ("Segoe UI", 10)
FONT_UI_BOLD = ("Segoe UI", 10, "bold")
FONT_SMALL = ("Segoe UI", 9)
FONT_TITLE = ("Segoe UI", 12, "bold")
FONT_MONO = ("Consolas", 10)


def apply_theme(root: tk.Tk) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    default_font = tkfont.nametofont("TkDefaultFont")
    default_font.configure(family="Segoe UI", size=10)
    root.option_add("*Font", default_font)

    root.configure(background=BG)
    style.configure(".", background=BG, foreground=TEXT, font=FONT_UI)
    style.configure("TFrame", background=BG)
    style.configure("Surface.TFrame", background=SURFACE)
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Muted.TLabel", background=BG, foreground=TEXT_MUTED,
                    font=FONT_SMALL)
    style.configure("Title.TLabel", background=BG, foreground=TEXT,
                    font=FONT_TITLE)
    style.configure("TLabelframe", background=BG, bordercolor=BORDER,
                    relief="solid")
    style.configure("TLabelframe.Label", background=BG, foreground=ACCENT_DARK,
                    font=FONT_UI_BOLD)

    style.configure("TButton", padding=(10, 5))
    style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                    bordercolor=ACCENT, focuscolor=ACCENT, padding=(12, 5))
    style.map("Accent.TButton",
              background=[("active", ACCENT_DARK), ("disabled", "#9db6e8")])

    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", padding=(14, 6), font=FONT_UI)
    style.map("TNotebook.Tab",
              background=[("selected", SURFACE)],
              foreground=[("selected", ACCENT_DARK)])

    style.configure("Treeview", background=SURFACE, fieldbackground=SURFACE,
                    foreground=TEXT, rowheight=24, bordercolor=BORDER)
    style.configure("Treeview.Heading", font=FONT_UI_BOLD, padding=(6, 4))
    style.map("Treeview", background=[("selected", ACCENT)],
              foreground=[("selected", "#ffffff")])

    style.configure("TEntry", fieldbackground=SURFACE)
    style.configure("TCombobox", fieldbackground=SURFACE)
    style.configure("TCheckbutton", background=BG)
    style.configure("Status.TLabel", background="#e8edf4", foreground=TEXT_MUTED,
                    font=FONT_SMALL, padding=(8, 3))
