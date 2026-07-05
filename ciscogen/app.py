"""Main application window for the Cisco Config Generator."""

from __future__ import annotations

import tkinter as tk
import traceback
from tkinter import filedialog, messagebox, ttk

from . import APP_NAME, DISCLAIMER, __version__
from .deploy import (
    DEPLOYMENT_WARNING,
    InventoryDevice,
    dry_run_plan,
    missing_dependency_message,
    optional_dependency_status,
)
from .exporting import (
    deployment_checklist_markdown,
    export_deployment_bundle,
    rollback_checklist_markdown,
    validation_report_markdown,
)
from .generators import generate_config
from .importer import apply_import
from .models import SECTION_LABELS, SECTIONS, Project
from .profiles import load_profiles
from .profiles.capabilities import feature_lock_state, resolve_capabilities
from .templates import apply_template, available_templates, load_template
from .ui import theme
from .ui.deployment import DeploymentWorkspace
from .ui.forms import FORM_CLASSES
from .ui.panels import PreviewPanel, WarningsPanel
from .ui.sidebar import Sidebar
from .ui.widgets import ScrollableFrame
from .validators import validate_project

DEFAULT_MODEL = "Catalyst 9300"
REGEN_DELAY_MS = 350

PROJECT_FILETYPES = [("Config Generator project", "*.json"),
                     ("All files", "*.*")]
EXPORT_FILETYPES = [("Cisco config", "*.cfg"), ("Text file", "*.txt"),
                    ("All files", "*.*")]
REPORT_FILETYPES = [("Markdown", "*.md"), ("Text file", "*.txt"),
                    ("All files", "*.*")]


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1500x900")
        self.minsize(1180, 720)
        theme.apply_theme(self)

        self.profiles = load_profiles()
        self.project = Project()
        default = DEFAULT_MODEL if DEFAULT_MODEL in self.profiles \
            else next(iter(self.profiles))
        self.project.device_model = default
        self._loading = True          # suppress on_change during (re)builds
        self._regen_job: str | None = None
        self._forms: dict[str, tk.Widget] = {}

        self._build_menu()
        self._build_toolbar()
        self._build_body()
        self._build_statusbar()

        # Sidebar construction selects its first model; restore the default.
        self.project.device_model = default
        self.sidebar.set_device(self.project.device_model,
                                self.project.os_version)
        self.sidebar.set_sections(self.project.sections_enabled)
        self.sidebar.set_options(self.project.options)
        self._refresh_visible_sections()
        self.sidebar.select_section("system")
        self._sync_device_from_sidebar()
        self._loading = False
        self.show_section("system")
        self.regenerate()
        self._update_status()
        self.protocol("WM_DELETE_WINDOW", self.quit_app)

    # ------------------------------------------------------------ layout
    def _build_menu(self):
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Project", accelerator="Ctrl+N",
                              command=self.new_project)
        file_menu.add_command(label="Load Project...", accelerator="Ctrl+O",
                              command=self.load_project)
        file_menu.add_command(label="Save Project", accelerator="Ctrl+S",
                              command=self.save_project)
        file_menu.add_command(label="Save Project As...",
                              command=lambda: self.save_project(save_as=True))
        file_menu.add_separator()
        file_menu.add_command(label="Export Config...", accelerator="Ctrl+E",
                              command=self.export_config)
        file_menu.add_command(label="Export Validation/Lint Report...",
                              command=self.export_validation_report)
        file_menu.add_command(label="Export Deployment Bundle...",
                              command=self.export_deployment_bundle)
        file_menu.add_command(label="Import Running Config...",
                              command=self.import_running_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit_app)
        menubar.add_cascade(label="File", menu=file_menu)

        config_menu = tk.Menu(menubar, tearoff=0)
        config_menu.add_command(label="Generate", accelerator="F5",
                                command=self.generate_to_final)
        config_menu.add_command(label="Copy to Clipboard",
                                command=self.copy_config)
        config_menu.add_command(label="Apply Template...",
                                command=self.apply_template_dialog)
        config_menu.add_command(label="Reset All Forms",
                                command=self.reset_forms)
        menubar.add_cascade(label="Config", menu=config_menu)

        deployment_menu = tk.Menu(menubar, tearoff=0)
        deployment_menu.add_command(label="Open SSH Workspace...",
                                    command=self.open_deployment_workspace)
        deployment_menu.add_separator()
        deployment_menu.add_command(label="Deployment Dependency Status",
                                    command=self.show_deployment_status)
        deployment_menu.add_separator()
        deployment_menu.add_command(label="Test Connection...",
                                    command=self.open_deployment_workspace)
        deployment_menu.add_command(label="Run Pre-check...",
                                    command=self.open_deployment_workspace)
        deployment_menu.add_command(label="Backup Running Config...",
                                    command=self.open_deployment_workspace)
        deployment_menu.add_command(label="Show Diff / Dry Run",
                                    command=self.show_dry_run_plan)
        deployment_menu.add_command(label="Deploy Candidate...",
                                    command=self.open_deployment_workspace)
        deployment_menu.add_command(label="Run Post-check...",
                                    command=self.open_deployment_workspace)
        deployment_menu.add_command(label="Save Running Config...",
                                    command=self.open_deployment_workspace)
        deployment_menu.add_command(label="Export Deployment Report...",
                                    command=self.export_deployment_report)
        menubar.add_cascade(label="Deployment", menu=deployment_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.configure(menu=menubar)

        self.bind("<Control-n>", lambda e: self.new_project())
        self.bind("<Control-o>", lambda e: self.load_project())
        self.bind("<Control-s>", lambda e: self.save_project())
        self.bind("<Control-e>", lambda e: self.export_config())
        self.bind("<F5>", lambda e: self.generate_to_final())

    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=(10, 8))
        bar.pack(fill="x")
        ttk.Button(bar, text="New Project",
                   command=self.new_project).pack(side="left")
        ttk.Button(bar, text="Load Project",
                   command=self.load_project).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Save Project",
                   command=self.save_project).pack(side="left", padx=(6, 0))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y",
                                                   padx=12)
        ttk.Button(bar, text="Generate", style="Accent.TButton",
                   command=self.generate_to_final).pack(side="left")
        ttk.Button(bar, text="Copy",
                   command=self.copy_config).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Export",
                   command=self.export_config).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Template",
                   command=self.apply_template_dialog).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Bundle",
                   command=self.export_deployment_bundle).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="SSH Workspace",
                   command=self.open_deployment_workspace).pack(side="left", padx=(6, 0))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y",
                                                   padx=12)
        ttk.Button(bar, text="Reset",
                   command=self.reset_forms).pack(side="left")

    def _build_body(self):
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True)

        self.sidebar = Sidebar(paned, self.profiles, {
            "on_device_change": self.on_device_change,
            "on_os_version_change": self.on_os_version_change,
            "on_section_toggle": self.on_section_toggle,
            "on_section_select": self.show_section,
            "on_option_change": self.on_option_change,
        })
        paned.add(self.sidebar, weight=0)

        center = ttk.Frame(paned)
        paned.add(center, weight=3)
        self.section_title = ttk.Label(center, text="", style="Title.TLabel",
                                       padding=(14, 10, 14, 0))
        self.section_title.pack(fill="x")
        self.section_hint = ttk.Label(center, text="", style="Muted.TLabel",
                                      padding=(14, 0))
        self.section_hint.pack(fill="x")
        self.workspace = ttk.Frame(center)
        self.workspace.pack(fill="both", expand=True)

        right = ttk.PanedWindow(paned, orient="vertical", width=520)
        paned.add(right, weight=2)
        self.preview = PreviewPanel(right)
        right.add(self.preview, weight=3)
        self.warnings = WarningsPanel(right)
        right.add(self.warnings, weight=1)

    def _build_statusbar(self):
        self.status = ttk.Label(self, style="Status.TLabel", anchor="w")
        self.status.pack(fill="x", side="bottom")
        self._update_status()

    def _update_status(self):
        file_part = self.project.file_path or "(unsaved project)"
        self.status.configure(
            text=f"{self.project.device_model}  |  {self.project.os_type} "
                 f"{self.project.os_version}  |  {file_part}  |  "
                 "Review and test all generated configurations before "
                 "production use.")

    # ------------------------------------------------------------- forms
    @property
    def profile(self):
        return self.profiles[self.project.device_model]

    def show_section(self, key: str):
        if key not in self._all_visible_sections():
            key = "system"
        self.sidebar.select_section(key)
        for child in self.workspace.winfo_children():
            child.pack_forget()
        if key not in self._forms:
            container = ScrollableFrame(self.workspace)
            form_cls = FORM_CLASSES[key]
            self._loading = True
            try:
                form_cls(container.inner, self.project, self.profile,
                         self.on_form_change).pack(fill="both", expand=True)
            finally:
                self._loading = False
            self._forms[key] = container
        self._forms[key].pack(fill="both", expand=True)
        enabled = self.project.sections_enabled.get(key)
        self.section_title.configure(text=SECTION_LABELS[key])
        hint = "" if enabled else (
            "This section is disabled and will not be included in the "
            "generated config. Tick its checkbox in the sidebar to enable it.")
        if key not in self._visible_sections():
            # Visible only because it holds user configuration; explain why
            # the capability is not offered for this device.
            state = feature_lock_state(self.project, self.profile, key)
            hint = (f"Not in the {self.project.device_model} device profile: "
                    f"{state['reason']}. Your configuration is preserved and "
                    "generated with platform warnings.")
        self.section_hint.configure(text=hint)

    def rebuild_forms(self):
        for widget in self._forms.values():
            widget.destroy()
        self._forms.clear()
        self.show_section(self.sidebar.selected_section)

    # --------------------------------------------------------- callbacks
    def on_form_change(self):
        if self._loading:
            return
        key = self.sidebar.selected_section
        if key in self.project.sections_enabled and not self.project.sections_enabled.get(key):
            self.project.sections_enabled[key] = True
            self.sidebar.set_section_enabled(key, True)
        self.schedule_regen()

    def on_device_change(self, model: str):
        changed = model != self.project.device_model
        self.project.device_model = model
        if self._loading:
            # During construction the sidebar may not be attached yet.
            return
        self._sync_device_from_sidebar()
        if changed:
            self._refresh_visible_sections()
            self.rebuild_forms()
            self.schedule_regen()
        self._update_status()

    def _sync_device_from_sidebar(self):
        self.project.os_type = self.profile.os_type
        self.project.os_version = self.sidebar.version_var.get()

    def on_os_version_change(self, version: str):
        self.project.os_version = version
        if not self._loading:
            self.schedule_regen()
            self._update_status()

    def on_section_toggle(self, key: str, enabled: bool):
        self.project.sections_enabled[key] = enabled
        if self.sidebar.selected_section == key:
            self.show_section(key)
        if not self._loading:
            self.schedule_regen()

    def on_option_change(self):
        self.project.options["include_comments"] = \
            bool(self.sidebar.comments_var.get())
        if not self._loading:
            self.schedule_regen()

    # -------------------------------------------------------- generation
    def schedule_regen(self):
        if self._regen_job is not None:
            self.after_cancel(self._regen_job)
        self._regen_job = self.after(REGEN_DELAY_MS, self.regenerate)

    def regenerate(self):
        self._regen_job = None
        try:
            config = generate_config(self.project, self.profile)
            issues = validate_project(self.project, self.profile)
        except Exception:  # defensive: never let a bug kill the UI loop
            self.preview.set_live("! Generation error:\n"
                                  + traceback.format_exc())
            return
        self.project.last_generated = config
        self.project.warnings = [issue.to_dict() for issue in issues]
        self.preview.set_live(config)
        self.warnings.set_issues(issues)

    def generate_to_final(self):
        self.regenerate()
        current_final = self.preview.get_final().strip()
        if current_final and current_final != self.project.last_generated.strip():
            if not messagebox.askyesno(
                    "Overwrite edits?",
                    "The Final Config tab contains manual edits. Overwrite "
                    "them with the freshly generated configuration?"):
                return
        self.preview.set_final(self.project.last_generated)
        self.preview.show_final_tab()

    def _exportable_config(self) -> str:
        final = self.preview.get_final().strip()
        if final:
            return self.preview.get_final()
        return self.project.last_generated

    # ------------------------------------------------------------ actions
    def copy_config(self):
        text = self._exportable_config()
        if not text.strip():
            messagebox.showinfo("Copy", "Nothing to copy yet - fill in some "
                                        "forms first.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copy", "Configuration copied to clipboard.")

    def export_config(self):
        self.regenerate()
        text = self._exportable_config()
        if not text.strip():
            messagebox.showinfo("Export", "Nothing to export yet.")
            return
        errors = sum(1 for w in self.project.warnings
                     if w.get("severity") == "error")
        if errors and not messagebox.askyesno(
                "Validation errors",
                f"The validation panel reports {errors} error(s). "
                "Export anyway?"):
            return
        hostname = self.project.data["system"].get("hostname") or "config"
        path = filedialog.asksaveasfilename(
            title="Export configuration", defaultextension=".cfg",
            initialfile=f"{hostname}.cfg", filetypes=EXPORT_FILETYPES)
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo("Export", f"Configuration exported to:\n{path}")

    def export_validation_report(self):
        self.regenerate()
        path = filedialog.asksaveasfilename(
            title="Export validation/lint report", defaultextension=".md",
            filetypes=REPORT_FILETYPES)
        if not path:
            return
        text = validation_report_markdown(self.project, self.profile,
                                          self._exportable_config())
        if path.lower().endswith(".txt"):
            text = text.replace("|", " ")
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo("Export", f"Report exported to:\n{path}")

    def export_deployment_report(self):
        self.regenerate()
        path = filedialog.asksaveasfilename(
            title="Export deployment report", defaultextension=".md",
            filetypes=REPORT_FILETYPES)
        if not path:
            return
        text = deployment_checklist_markdown(self.project, self.profile,
                                             self._exportable_config())
        text += "\n" + rollback_checklist_markdown(
            self.project, self.profile, self._exportable_config())
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo("Export", f"Deployment report exported to:\n{path}")

    def export_deployment_bundle(self):
        self.regenerate()
        folder = filedialog.askdirectory(title="Export deployment bundle")
        if not folder:
            return
        try:
            zip_path = export_deployment_bundle(
                self.project, self.profile, self._exportable_config(), folder)
        except OSError as exc:
            messagebox.showerror("Bundle export failed", str(exc))
            return
        messagebox.showinfo("Deployment bundle",
                            f"Deployment bundle exported to:\n{zip_path}")

    def import_running_config(self):
        path = filedialog.askopenfilename(
            title="Import Cisco running-config",
            filetypes=[("Cisco config", "*.cfg *.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            text = open(path, "r", encoding="utf-8").read()
        except OSError as exc:
            messagebox.showerror("Import failed", str(exc))
            return
        warnings = apply_import(self.project, text)
        self.rebuild_forms()
        self.regenerate()
        messagebox.showinfo(
            "Import complete",
            f"Imported recognized configuration. Preserved {len(warnings)} "
            "unparsed line(s) in Custom CLI.")

    def save_project(self, save_as: bool = False):
        self.regenerate()
        final = self.preview.get_final()
        self.project.edited_config = final \
            if final.strip() and final != self.project.last_generated else ""
        path = self.project.file_path
        if save_as or not path:
            path = filedialog.asksaveasfilename(
                title="Save project", defaultextension=".json",
                filetypes=PROJECT_FILETYPES)
            if not path:
                return
        try:
            self.project.save(path)
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc))
            return
        self._update_status()
        messagebox.showinfo("Save", f"Project saved to:\n{path}")

    def load_project(self):
        path = filedialog.askopenfilename(title="Load project",
                                          filetypes=PROJECT_FILETYPES)
        if not path:
            return
        try:
            project = Project.load(path)
        except Exception as exc:
            messagebox.showerror("Load failed",
                                 f"Could not load project:\n{exc}")
            return
        if project.device_model not in self.profiles:
            messagebox.showerror(
                "Load failed",
                f"Unknown device model '{project.device_model}' - the "
                "project needs a device profile that is not installed.")
            return
        self.project = project
        self._loading = True
        self.sidebar.set_device(project.device_model, project.os_version)
        self.sidebar.set_sections(project.sections_enabled)
        self.sidebar.set_options(project.options)
        self._sync_device_from_sidebar()
        self.project.os_version = project.os_version or self.project.os_version
        self._refresh_visible_sections()
        self._loading = False
        self.rebuild_forms()
        self.regenerate()
        self.preview.set_final(project.edited_config
                               or self.project.last_generated)
        self._update_status()

    def new_project(self):
        if not messagebox.askyesno("New project",
                                   "Discard the current project and start a "
                                   "new one?"):
            return
        model = self.project.device_model
        self.project = Project()
        self.project.device_model = model
        self._loading = True
        self.sidebar.set_sections(self.project.sections_enabled)
        self.sidebar.set_options(self.project.options)
        self._sync_device_from_sidebar()
        self._refresh_visible_sections()
        self._loading = False
        self.rebuild_forms()
        self.preview.set_final("")
        self.regenerate()
        self._update_status()

    def reset_forms(self):
        if not messagebox.askyesno("Reset",
                                   "Clear all form data (device selection is "
                                   "kept)?"):
            return
        from .models.project import default_data
        self.project.data = default_data()
        self.project.edited_config = ""
        self.rebuild_forms()
        self.preview.set_final("")
        self.regenerate()

    def apply_template_dialog(self):
        templates = available_templates()
        if not templates:
            messagebox.showinfo("Templates", "No templates were found in samples/templates.")
            return
        path = filedialog.askopenfilename(
            title="Apply template",
            initialdir=str(templates[0].parent),
            filetypes=[("Template JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        if not messagebox.askyesno(
                "Apply template",
                "Apply this template by merging it into the current project? "
                "Existing populated lists are preserved and template rows are added."):
            return
        try:
            touched = apply_template(self.project, load_template(path))
        except Exception as exc:
            messagebox.showerror("Template failed", str(exc))
            return
        self.sidebar.set_sections(self.project.sections_enabled)
        self._refresh_visible_sections()
        self.rebuild_forms()
        self.regenerate()
        messagebox.showinfo("Template applied",
                            "Updated sections: " + ", ".join(touched))

    def show_deployment_status(self):
        status = optional_dependency_status()
        lines = [DEPLOYMENT_WARNING, "", missing_dependency_message(), ""]
        lines.extend(f"{name}: {'installed' if present else 'missing'}"
                     for name, present in status.items())
        messagebox.showinfo("Deployment status", "\n".join(lines))

    def open_deployment_workspace(self):
        self.regenerate()
        workspace = DeploymentWorkspace(self)
        workspace.load_final()
        workspace.focus_set()

    def show_dry_run_plan(self):
        self.regenerate()
        device = InventoryDevice(
            name=self.project.data["system"].get("hostname") or self.project.device_model,
            host="prompt-at-deployment",
            device_model=self.project.device_model,
            os_type=self.project.os_type)
        plan = dry_run_plan(device, self._exportable_config())
        messagebox.showinfo(
            "Dry run plan",
            "\n".join([
                plan["warning"],
                "",
                f"Target: {plan['target']}",
                f"Candidate lines: {plan['candidate_lines']}",
                "Pre-checks: " + ", ".join(plan["precheck_commands"][:6]) + "...",
                "Confirmations required: " + str(len(plan["requires_confirmations"])),
            ]))

    def show_about(self):
        messagebox.showinfo(
            "About",
            f"{APP_NAME} v{__version__}\n\n"
            "A modular Cisco IOS / IOS-XE configuration generator.\n\n"
            f"{DISCLAIMER}")

    def _visible_sections(self) -> list[str]:
        profile = self.profile
        caps = resolve_capabilities(self.project, profile)
        visible = ["system", "interfaces", "acls", "security", "misc",
                   "custom_cli"]
        # Keep VLAN planning visible on routers too; router-on-a-stick and
        # lab designs often still need VLAN IDs even without switchports.
        visible.append("vlans")
        if profile.is_router or profile.supports("layer3") or "static_routing" in caps:
            visible.append("layer3")
        if "ipv6" in caps:
            visible.append("ipv6")
        if profile.supports("dhcp_server") or "dhcp_server" in caps:
            visible.append("dhcp")
        if profile.supports("nat") or "nat" in caps:
            visible.append("nat")
        if profile.is_router or profile.supports("layer3") \
                or any(cap in caps for cap in ("ospf", "eigrp", "bgp", "rip")):
            visible.append("routing")
        if "vrf_lite" in caps:
            visible.append("vrf")
        if "tunnel" in caps or "gre" in caps:
            visible.append("tunnels")
        if "ip_sla" in caps:
            visible.append("ipsla")
        if "zone_based_firewall" in caps:
            visible.append("zbf")
        if "qos" in caps:
            visible.append("qos")
        if any(cap in caps for cap in ("hsrp", "vrrp", "glbp")):
            visible.append("ha")
        return [key for key in SECTIONS if key in visible]

    def _all_visible_sections(self) -> list[str]:
        """Capability-visible sections plus any the user has enabled.

        Sections stay visible (and enabled) when the device changes so
        configuration is never silently dropped; the platform validator
        warns about capabilities the new device does not list.
        """
        from .models import LEGACY_SECTIONS
        capability_visible = set(self._visible_sections())
        preserved = {key for key, on in self.project.sections_enabled.items()
                     if on}
        return [key for key in SECTIONS
                if (key in capability_visible or key in preserved)
                and key not in LEGACY_SECTIONS]

    def _refresh_visible_sections(self):
        visible = self._all_visible_sections()
        selected_changed = self.sidebar.selected_section not in visible
        self.sidebar.set_visible_sections(visible)
        self.sidebar.set_sections(self.project.sections_enabled)
        if selected_changed:
            self.sidebar.select_section("system")
        return selected_changed

    def quit_app(self):
        if messagebox.askyesno("Exit", "Exit the application? Unsaved "
                                       "changes will be lost."):
            self.destroy()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
