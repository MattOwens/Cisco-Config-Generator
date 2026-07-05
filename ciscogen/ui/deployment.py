"""Integrated SSH profile manager and guarded deployment workspace."""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from ..deploy import (
    DEPLOYMENT_WARNING,
    DeploymentUnavailable,
    InventoryDevice,
    NetmikoDeploymentClient,
    install_optional_dependencies,
    missing_dependency_message,
    optional_dependency_status,
    redact_secrets,
)
from ..deploy.guards import (
    DeploymentSelection,
    assess_deployment,
    backup_running_config,
    config_diff,
    deployment_report_json,
    deployment_report_markdown,
    deployment_report_text,
    detect_cli_errors,
    identity_warnings,
    new_report,
    parse_device_facts,
    postcheck_commands,
    precheck_commands,
    prepare_deployment_commands,
    rollback_notes,
    summarize_diff,
)
from ..deploy.profiles import SSHProfile, SSHProfileStore, filter_profiles
from ..models import SECTION_LABELS, SECTIONS
from ..validators import validate_project
from . import theme
from .widgets import RowDialog


def _text(parent, height: int = 12) -> tk.Text:
    frame = ttk.Frame(parent)
    frame.pack(fill="both", expand=True)
    widget = tk.Text(frame, wrap="none", height=height, font=theme.FONT_MONO,
                     background=theme.CONSOLE_BG, foreground=theme.CONSOLE_FG,
                     insertbackground="#ffffff", relief="flat",
                     padx=10, pady=8)
    y = ttk.Scrollbar(frame, orient="vertical", command=widget.yview)
    x = ttk.Scrollbar(frame, orient="horizontal", command=widget.xview)
    widget.configure(yscrollcommand=y.set, xscrollcommand=x.set)
    y.pack(side="right", fill="y")
    x.pack(side="bottom", fill="x")
    widget.pack(side="left", fill="both", expand=True)
    return widget


PROFILE_FIELDS = [
    {"key": "name", "label": "Profile name"},
    {"key": "host", "label": "Hostname/IP"},
    {"key": "port", "label": "SSH port", "default": "22", "width": 8},
    {"key": "username", "label": "Username"},
    {"key": "auth_method", "label": "Auth method", "type": "combo",
     "values": ["prompt", "env", "key"], "default": "prompt"},
    {"key": "key_path", "label": "SSH key path"},
    {"key": "password_env", "label": "Password env var"},
    {"key": "enable_secret_env", "label": "Enable env var"},
    {"key": "prompt_for_enable", "label": "Prompt for enable secret",
     "type": "check"},
    {"key": "device_model", "label": "Device model"},
    {"key": "os_type", "label": "OS type"},
    {"key": "os_version", "label": "OS version"},
    {"key": "site", "label": "Site/location"},
    {"key": "role", "label": "Role"},
    {"key": "folder", "label": "Folder/group"},
    {"key": "tags", "label": "Tags"},
    {"key": "notes", "label": "Notes", "fullrow": True},
]


COMMON_COMMANDS = [
    "show version",
    "show running-config",
    "show startup-config",
    "show ip interface brief",
    "show interfaces status",
    "show vlan brief",
    "show ip route",
    "show cdp neighbors",
    "show lldp neighbors",
    "show spanning-tree summary",
    "show etherchannel summary",
    "show access-lists",
    "show license",
    "show license all",
    "show crypto isakmp sa",
    "show crypto ikev2 sa",
    "show crypto ipsec sa",
    "show dmvpn",
    "show ip nhrp",
    "show ip ospf neighbor",
    "show ip eigrp neighbors",
    "show ip bgp summary",
    "show ip sla summary",
    "show track",
]


def _action_menu(parent, label: str, items: list[tuple[str, object]]):
    button = ttk.Menubutton(parent, text=label)
    menu = tk.Menu(button, tearoff=0)
    button.configure(menu=menu)
    for item_label, command in items:
        if item_label == "-":
            menu.add_separator()
        else:
            menu.add_command(label=item_label, command=command)
    return button


class DeploymentWorkspace(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("SSH Manager and Guarded Deployment")
        self.geometry("1480x880")
        self.minsize(1100, 700)
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.store = SSHProfileStore()
        self.profiles: list[SSHProfile] = []
        self.selected_profile: SSHProfile | None = None
        self.client: NetmikoDeploymentClient | None = None
        self.worker_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.backup_path = ""
        self.running_config = ""
        self.startup_config = ""
        self.last_report = None
        self.command_history: list[str] = []
        self.terminal_reader_active = False
        # Device facts captured from the live connection, used for
        # hostname/model/version mismatch detection and reports.
        self.detected_facts: dict[str, str] = {}
        self.precheck_summary: dict[str, str] = {}
        self.postcheck_summary: dict[str, str] = {}

        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True)
        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=1)
        paned.add(right, weight=1)
        self._build_candidate(left)
        self._build_ssh(right)
        self._load_profiles()
        self._poll_worker()

    # ------------------------------------------------------------ left side
    def _build_candidate(self, parent):
        top = ttk.Frame(parent, padding=(8, 6))
        top.pack(fill="x")
        ttk.Button(top, text="Load Generated",
                   command=self.load_generated).pack(side="left")
        ttk.Button(top, text="Load Final",
                   command=self.load_final).pack(side="left", padx=(6, 0))
        ttk.Button(top, text="Validate",
                   command=self.validate_candidate).pack(side="left", padx=(6, 0))
        _action_menu(top, "Deploy Actions", [
            ("Dry Run", self.dry_run),
            ("Deploy Candidate", self.deploy_candidate),
            ("Save Running Config", self.save_running_config),
            ("Export Report", self.export_report),
        ]).pack(side="left", padx=(6, 0))

        options = ttk.Frame(parent, padding=(8, 0, 8, 4))
        options.pack(fill="x")
        ttk.Label(options, text="Mode").pack(side="left")
        self.mode_var = tk.StringVar(value="dry-run")
        ttk.Combobox(options, textvariable=self.mode_var, state="readonly",
                     width=16, values=[
                         "dry-run", "selected-lines", "selected-section", "full",
                     ]).pack(side="left", padx=(4, 12))
        ttk.Label(options, text="Section").pack(side="left")
        self.section_var = tk.StringVar(value="system")
        ttk.Combobox(options, textvariable=self.section_var, state="readonly",
                     width=22, values=SECTIONS).pack(side="left", padx=(4, 12))
        self.backup_var = tk.StringVar(value="No running-config backup yet")
        ttk.Label(options, textvariable=self.backup_var,
                  style="Muted.TLabel").pack(side="left", fill="x", expand=True)

        self.left_tabs = ttk.Notebook(parent)
        self.left_tabs.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        candidate_tab = ttk.Frame(self.left_tabs)
        self.candidate_text = _text(candidate_tab)
        self.left_tabs.add(candidate_tab, text="  Candidate  ")
        warnings_tab = ttk.Frame(self.left_tabs)
        self.validation_text = _text(warnings_tab)
        self.left_tabs.add(warnings_tab, text="  Validation  ")
        deploy_tab = ttk.Frame(self.left_tabs)
        self.deploy_log = _text(deploy_tab)
        self.left_tabs.add(deploy_tab, text="  Deployment Log  ")

    # ----------------------------------------------------------- right side
    def _build_ssh(self, parent):
        status = ttk.Frame(parent, padding=(8, 6))
        status.pack(fill="x")
        self.dependency_var = tk.StringVar(value=missing_dependency_message())
        ttk.Label(status, textvariable=self.dependency_var,
                  style="Muted.TLabel", wraplength=420).pack(
            side="left", fill="x", expand=True)
        self.install_button = ttk.Button(
            status, text="Install SSH Support", command=self.install_ssh_support)
        if not optional_dependency_status().get("netmiko"):
            self.install_button.pack(side="left", padx=(8, 0))
        self.connection_var = tk.StringVar(value="Disconnected")
        ttk.Label(status, textvariable=self.connection_var,
                  font=theme.FONT_UI_BOLD).pack(side="right")

        profile_tools = ttk.Frame(parent, padding=(8, 0, 8, 4))
        profile_tools.pack(fill="x")
        ttk.Label(profile_tools, text="Search").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh_profile_tree())
        ttk.Entry(profile_tools, textvariable=self.search_var, width=20).pack(
            side="left", padx=(4, 8))
        _action_menu(profile_tools, "Profiles", [
            ("New", self.new_profile),
            ("Edit", self.edit_profile),
            ("Duplicate", self.duplicate_profile),
            ("Delete", self.delete_profile),
            ("-", None),
            ("Import", self.import_profiles),
            ("Export", self.export_profiles),
        ]).pack(side="left", padx=(0, 6))
        ttk.Button(profile_tools, text="Connect",
                   command=self.connect).pack(side="left", padx=(0, 5))
        ttk.Button(profile_tools, text="Disconnect",
                   command=self.disconnect).pack(side="left", padx=(0, 5))

        table_frame = ttk.Frame(parent, padding=(8, 0))
        table_frame.pack(fill="x")
        self.profile_tree = ttk.Treeview(
            table_frame, columns=("folder", "name", "host", "user", "model", "status"),
            show="headings", height=6)
        for key, label, width in [
            ("folder", "Group", 100),
            ("name", "Profile", 150),
            ("host", "Host", 140),
            ("user", "User", 90),
            ("model", "Device", 130),
            ("status", "Status", 100),
        ]:
            self.profile_tree.heading(key, text=label)
            self.profile_tree.column(key, width=width, stretch=True)
        self.profile_tree.pack(fill="x")
        self.profile_tree.bind("<<TreeviewSelect>>", lambda e: self._profile_selected())

        cmd = ttk.Frame(parent, padding=(8, 6))
        cmd.pack(fill="x")
        self.command_var = tk.StringVar(value="show version")
        ttk.Combobox(cmd, textvariable=self.command_var, values=COMMON_COMMANDS,
                     width=28).pack(side="left", fill="x", expand=True)
        ttk.Button(cmd, text="Send", command=self.send_command).pack(
            side="left", padx=(6, 0))
        _action_menu(cmd, "Checks", [
            ("Pre-checks", self.run_prechecks),
            ("Backup Running Config", self.backup_running),
            ("Post-checks", self.run_postchecks),
        ]).pack(side="left", padx=(6, 0))
        _action_menu(cmd, "Session", [
            ("Enable Mode", self.enter_enable),
            ("Reconnect", self.reconnect),
            ("Copy Output", self.copy_console),
            ("Clear Output", self.clear_console),
            ("Save Session Log", self.save_session_log),
        ]).pack(side="left", padx=(6, 0))

        tabs = ttk.Notebook(parent)
        tabs.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        terminal_tab = ttk.Frame(tabs)
        self.terminal_text = _text(terminal_tab)
        self.terminal_text.bind("<Key>", self._terminal_key)
        self.terminal_text.bind("<Control-v>", self._terminal_paste)
        self.terminal_text.bind("<Button-1>", lambda _event: self.terminal_text.focus_set())
        tabs.add(terminal_tab, text="  Interactive CLI  ")

        console_tab = ttk.Frame(tabs)
        self.console_text = _text(console_tab)
        tabs.add(console_tab, text="  Command Output  ")
        running_tab = ttk.Frame(tabs)
        self.running_text = _text(running_tab)
        tabs.add(running_tab, text="  Running Config  ")

    # -------------------------------------------------------- profile CRUD
    def _load_profiles(self):
        try:
            self.profiles = self.store.load()
        except Exception as exc:
            self.profiles = []
            self._append_log(f"Could not load SSH profiles: {exc}")
        self._refresh_profile_tree()

    def _refresh_profile_tree(self):
        self.profile_tree.delete(*self.profile_tree.get_children())
        for profile in filter_profiles(self.profiles, self.search_var.get()):
            self.profile_tree.insert("", "end", iid=profile.id, values=(
                profile.folder, profile.name, profile.host, profile.username,
                profile.device_model, profile.status,
            ))

    def _profile_selected(self):
        selection = self.profile_tree.selection()
        if not selection:
            self.selected_profile = None
            return
        profile_id = selection[0]
        self.selected_profile = next(
            (profile for profile in self.profiles if profile.id == profile_id),
            None)

    def _profile_dialog(self, profile: SSHProfile | None = None) -> SSHProfile | None:
        initial = profile.to_dict() if profile else {
            "device_model": self.app.project.device_model,
            "os_type": self.app.project.os_type,
            "os_version": self.app.project.os_version,
            "capability_profile": "device-profile",
        }
        dialog = RowDialog(self, "SSH Profile", PROFILE_FIELDS, initial=initial)
        if dialog.result is None:
            return None
        result = dict(initial)
        result.update(dialog.result)
        if profile:
            result["id"] = profile.id
            result["last_connected"] = profile.last_connected
            result["status"] = profile.status
        return SSHProfile.from_dict(result)

    def new_profile(self):
        profile = self._profile_dialog()
        if not profile:
            return
        self.store.upsert(profile)
        self._load_profiles()

    def edit_profile(self):
        if not self.selected_profile:
            messagebox.showinfo("SSH Profiles", "Select a profile first.", parent=self)
            return
        profile = self._profile_dialog(self.selected_profile)
        if not profile:
            return
        self.store.upsert(profile)
        self._load_profiles()

    def duplicate_profile(self):
        if not self.selected_profile:
            return
        self.store.duplicate(self.selected_profile.id)
        self._load_profiles()

    def delete_profile(self):
        if not self.selected_profile:
            return
        if not messagebox.askyesno("Delete profile",
                                   f"Delete '{self.selected_profile.name}'?",
                                   parent=self):
            return
        self.store.delete(self.selected_profile.id)
        self.selected_profile = None
        self._load_profiles()

    def import_profiles(self):
        path = filedialog.askopenfilename(title="Import SSH profiles",
                                          filetypes=[("JSON", "*.json"),
                                                     ("All files", "*.*")])
        if path:
            imported = self.store.import_file(path)
            self._load_profiles()
            self._append_log(f"Imported {len(imported)} SSH profile(s).")

    def export_profiles(self):
        path = filedialog.asksaveasfilename(title="Export SSH profiles",
                                            defaultextension=".json",
                                            filetypes=[("JSON", "*.json"),
                                                       ("All files", "*.*")])
        if path:
            ids = [self.selected_profile.id] if self.selected_profile else None
            self.store.export_file(path, ids)
            self._append_log(f"Exported SSH profiles to {path}.")

    # ----------------------------------------------------------- SSH worker
    def connect(self):
        if not self.selected_profile:
            messagebox.showinfo("Connect", "Select an SSH profile first.", parent=self)
            return
        if not optional_dependency_status().get("netmiko"):
            messagebox.showinfo("Optional dependency", missing_dependency_message(),
                                parent=self)
            return
        password = self._password_for(self.selected_profile)
        if password is None:
            return
        enable_secret = ""
        if self.selected_profile.prompt_for_enable:
            enable_secret = simpledialog.askstring(
                "Enable Secret", "Enable secret", parent=self, show="*") or ""
        self._run_worker("connect", self._connect_worker,
                         self.selected_profile, password, enable_secret)

    def install_ssh_support(self):
        if optional_dependency_status().get("netmiko"):
            self.dependency_var.set(missing_dependency_message())
            self.install_button.pack_forget()
            return
        if not messagebox.askyesno(
                "Install SSH support",
                "Install Netmiko SSH support into this Python environment now?",
                parent=self):
            return
        self.install_button.configure(state="disabled")
        self.dependency_var.set("Installing SSH support...")
        self._run_worker("install_deps", install_optional_dependencies)

    def reconnect(self):
        self.disconnect()
        self.connect()

    def _password_for(self, profile: SSHProfile) -> str | None:
        if profile.auth_method == "key":
            return ""
        if profile.auth_method == "env" and profile.password_env:
            import os
            value = os.environ.get(profile.password_env)
            if value:
                return value
            messagebox.showerror("Password", f"Environment variable "
                                 f"{profile.password_env} is not set.",
                                 parent=self)
            return None
        return simpledialog.askstring("SSH Password", "SSH password",
                                      parent=self, show="*")

    def _connect_worker(self, profile: SSHProfile, password: str,
                        enable_secret: str):
        device = InventoryDevice(
            name=profile.name,
            host=profile.host,
            username=profile.username,
            auth_method=profile.auth_method,
            key_path=profile.key_path,
            ssh_port=profile.port,
            device_model=profile.device_model,
            os_type=profile.os_type,
            role=profile.role,
            site=profile.site,
            tags=list(profile.tags),
        )
        client = NetmikoDeploymentClient(device, password, enable_secret)
        client.connect()
        prompt = ""
        try:
            prompt = client.connection.find_prompt()
        except Exception:
            prompt = "connected"
        # Capture device facts so hostname/model/version mismatches can be
        # flagged against the selected project profile.
        facts: dict[str, str] = {}
        try:
            facts = parse_device_facts(client.run_command("show version"))
        except Exception:
            facts = {}
        return client, prompt, facts

    def disconnect(self):
        self.terminal_reader_active = False
        if self.client is not None:
            try:
                self.client.disconnect()
            except Exception as exc:
                self._append_console(f"Disconnect warning: {exc}")
        self.client = None
        self.connection_var.set("Disconnected")

    def send_command(self):
        command = self.command_var.get().strip()
        if not command:
            return
        if self.client is None:
            messagebox.showinfo("SSH Console", "Connect first.", parent=self)
            return
        self.command_history.append(command)
        self._run_worker("command", lambda: self.client.run_command(command), command)

    def enter_enable(self):
        if self.client is None:
            messagebox.showinfo("SSH Console", "Connect first.", parent=self)
            return
        enable_secret = simpledialog.askstring(
            "Enable Secret", "Enable secret", parent=self, show="*") or ""
        self._run_worker("enable",
                         lambda: self.client.enter_enable(enable_secret))

    def run_prechecks(self):
        self._run_commands("precheck", precheck_commands(self.app.project, self.app.profile))

    def run_postchecks(self):
        self._run_commands("postcheck", postcheck_commands(self.app.project, self.app.profile))

    def _run_commands(self, kind: str, commands: list[str]):
        if self.client is None:
            messagebox.showinfo("SSH Console", "Connect first.", parent=self)
            return
        self._run_worker(kind, lambda: self.client.run_show_commands(commands))

    def _run_worker(self, kind: str, func, *args):
        def _target():
            try:
                result = func(*args)
                self.worker_queue.put((kind, result))
            except Exception as exc:
                self.worker_queue.put(("error", f"{kind}: {exc}"))
        threading.Thread(target=_target, daemon=True).start()

    def _poll_worker(self):
        try:
            while True:
                kind, result = self.worker_queue.get_nowait()
                self._handle_worker_result(kind, result)
        except queue.Empty:
            pass
        self.after(150, self._poll_worker)

    def _handle_worker_result(self, kind: str, result):
        if kind == "connect":
            self.client, prompt, facts = result
            self.detected_facts = facts or {}
            self.connection_var.set(f"Connected: {prompt}")
            if self.selected_profile:
                self.selected_profile.mark_connected()
                self.store.upsert(self.selected_profile)
                self._load_profiles()
            self._append_console(f"Connected. Prompt: {prompt}")
            if self.detected_facts:
                self._append_console(f"Detected: {self.detected_facts}")
            for warning in identity_warnings(self.app.project, self.detected_facts):
                self._append_log("Identity check: " + warning)
            self._append_terminal(f"Connected. Prompt: {prompt}\n")
            self._start_terminal_reader()
        elif kind == "command":
            command = self.command_history[-1] if self.command_history else "command"
            self._append_console(f"\n$ {command}\n{redact_secrets(str(result))}\n")
        elif kind in ("precheck", "postcheck"):
            summary = {}
            for command, output in dict(result).items():
                errors = detect_cli_errors(output)
                summary[command] = "errors" if errors else "ok"
                self._append_console(f"\n$ {command}\n{redact_secrets(output)}\n")
            if kind == "precheck":
                self.precheck_summary = summary
            else:
                self.postcheck_summary = summary
            self._append_log(f"{kind.title()} complete: {summary}")
        elif kind == "enable":
            self.connection_var.set(f"Enabled: {result}")
            self._append_console(f"Enable mode prompt: {result}")
        elif kind == "backup":
            self.running_config = str(result)
            self._set_text(self.running_text, redact_secrets(self.running_config))
            profile_name = self.selected_profile.name if self.selected_profile else "device"
            path = backup_running_config(self.running_config, profile_name)
            self.backup_path = str(path)
            self.backup_var.set(f"Backup: {path}")
            self._append_log(f"Running-config backed up to {path}.")
        elif kind == "deploy":
            output = redact_secrets(str(result))
            errors = detect_cli_errors(output)
            self._append_log(output)
            if errors:
                self._append_log("CLI errors detected. Review output before continuing.")
        elif kind == "save":
            self._append_log(redact_secrets(str(result)))
        elif kind == "install_deps":
            output = ""
            if getattr(result, "stdout", ""):
                output += result.stdout
            if getattr(result, "stderr", ""):
                output += "\n" + result.stderr
            self._append_log(redact_secrets(output.strip() or "Install completed."))
            self.dependency_var.set(missing_dependency_message())
            if optional_dependency_status().get("netmiko"):
                self.install_button.pack_forget()
                messagebox.showinfo("SSH support", "SSH support is installed.",
                                    parent=self)
            else:
                self.install_button.configure(state="normal")
                messagebox.showwarning(
                    "SSH support",
                    "Install finished, but Netmiko is still not importable. "
                    "Review the deployment log.",
                    parent=self)
        elif kind == "error":
            self._append_log(str(result))
            self._append_console(str(result))
            self.install_button.configure(state="normal")
        elif kind == "terminal":
            self._append_terminal(str(result))

    # ------------------------------------------------------------- actions
    def load_generated(self):
        self.app.regenerate()
        self._set_text(self.candidate_text, self.app.project.last_generated)

    def load_final(self):
        self.app.regenerate()
        final = self.app.preview.get_final()
        self._set_text(self.candidate_text, final or self.app.project.last_generated)

    def validate_candidate(self):
        self.app.regenerate()
        issues = validate_project(self.app.project, self.app.profile)
        lines = [f"{issue.severity.upper()} [{issue.section}] {issue.message}"
                 for issue in issues]
        self._set_text(self.validation_text, "\n".join(lines) or "No validation issues.")
        return issues

    def dry_run(self):
        candidate = self.candidate_text.get("1.0", "end-1c")
        selection = self._selection()
        assessment = assess_deployment(selection, candidate,
                                       self.validate_candidate(),
                                       self.backup_path,
                                       confirmation=False)
        self._append_log("Dry-run assessment")
        self._append_log("Commands prepared: " + str(len(assessment.commands)))
        for warning in assessment.warnings:
            self._append_log("Warning: " + warning)
        for blocker in assessment.blockers:
            self._append_log("Blocker: " + blocker)

    def backup_running(self):
        if self.client is None:
            messagebox.showinfo("Backup", "Connect first.", parent=self)
            return
        self._run_worker("backup", self.client.backup_running_config)

    def deploy_candidate(self):
        if self.client is None:
            messagebox.showinfo("Deploy", "Connect first.", parent=self)
            return
        candidate = self.candidate_text.get("1.0", "end-1c")
        selection = self._selection()
        if selection.mode == "dry-run":
            self.dry_run()
            return
        issues = self.validate_candidate()
        assessment = assess_deployment(selection, candidate, issues,
                                       self.backup_path, confirmation=True)
        if assessment.blockers:
            messagebox.showwarning("Deployment blocked",
                                   "\n".join(assessment.blockers), parent=self)
            self._append_log("Deployment blocked: " + "; ".join(assessment.blockers))
            return
        if not messagebox.askyesno("Confirm deployment",
                                   "Send selected candidate commands to the "
                                   "connected device?", parent=self):
            return
        if not assessment.allowed:
            messagebox.showwarning("Deployment blocked",
                                   "\n".join(assessment.blockers), parent=self)
            return
        commands = assessment.commands
        self._append_log(f"Deploying {len(commands)} command(s).")
        self._run_worker("deploy",
                         lambda: self.client.send_config_commands(commands))

    def save_running_config(self):
        if self.client is None:
            messagebox.showinfo("Save Running Config", "Connect first.", parent=self)
            return
        if not messagebox.askyesno(
                "Save running-config",
                "This is separate from deployment. Save running-config now?",
                parent=self):
            return
        self._run_worker("save", lambda: self.client.save_running_config(True))

    def export_report(self):
        path = filedialog.asksaveasfilename(
            title="Export deployment report", defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("Text", "*.txt"),
                       ("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        candidate = self.candidate_text.get("1.0", "end-1c")
        diff = config_diff(candidate, self.running_config,
                           "candidate", "running-config")
        warnings = identity_warnings(self.app.project, self.detected_facts)
        report = new_report(
            self.selected_profile,
            self.app.project,
            detected_hostname=self.detected_facts.get("hostname", ""),
            detected_platform=self.detected_facts.get("model", ""),
            detected_version=self.detected_facts.get("version", ""),
            backup_path=self.backup_path,
            diff_summary=summarize_diff(diff),
            deployment_mode=self.mode_var.get(),
            commands_sent=prepare_deployment_commands(candidate, self._selection()),
            precheck_summary=dict(self.precheck_summary),
            postcheck_summary=dict(self.postcheck_summary),
            rollback_notes=rollback_notes(self.backup_path),
            warnings=warnings,
        )
        suffix = Path(path).suffix.lower()
        if suffix == ".json":
            text = deployment_report_json(report)
        elif suffix == ".txt":
            text = deployment_report_text(report)
        else:
            text = deployment_report_markdown(report)
        Path(path).write_text(text, encoding="utf-8", newline="\n")
        self._append_log(f"Deployment report exported to {path}.")

    def copy_console(self):
        try:
            text = self.console_text.get("sel.first", "sel.last")
        except tk.TclError:
            text = self.console_text.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(redact_secrets(text))

    def clear_console(self):
        self.console_text.delete("1.0", "end")
        self.terminal_text.delete("1.0", "end")

    def save_session_log(self):
        path = filedialog.asksaveasfilename(
            title="Save SSH session log", defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        text = self.console_text.get("1.0", "end-1c")
        Path(path).write_text(redact_secrets(text), encoding="utf-8",
                              newline="\n")
        self._append_log(f"Session log saved to {path}.")

    # --------------------------------------------------------------- utils
    def _selection(self) -> DeploymentSelection:
        selected_text = ""
        try:
            selected_text = self.candidate_text.get("sel.first", "sel.last")
        except tk.TclError:
            pass
        return DeploymentSelection(
            mode=self.mode_var.get(),
            selected_text=selected_text,
            section_key=self.section_var.get(),
        )

    def _start_terminal_reader(self):
        if self.terminal_reader_active:
            return
        self.terminal_reader_active = True

        def _reader():
            while self.terminal_reader_active:
                try:
                    if self.client is not None:
                        data = self.client.terminal_read()
                        if data:
                            self.worker_queue.put(("terminal", data))
                except Exception as exc:
                    self.worker_queue.put(("terminal", f"\nTerminal read stopped: {exc}\n"))
                    self.terminal_reader_active = False
                    break
                time.sleep(0.15)

        threading.Thread(target=_reader, daemon=True).start()

    def _terminal_key(self, event):
        if self.client is None:
            return "break"
        key_map = {
            "Return": "\n",
            "BackSpace": "\x08",
            "Tab": "\t",
            "Escape": "\x1b",
            "Up": "\x1b[A",
            "Down": "\x1b[B",
            "Right": "\x1b[C",
            "Left": "\x1b[D",
            "Delete": "\x7f",
        }
        data = ""
        if event.state & 0x4 and event.keysym.lower() == "c":
            data = "\x03"
        elif event.keysym in key_map:
            data = key_map[event.keysym]
        elif event.char and event.char >= " ":
            data = event.char
        if data:
            self.client.terminal_write(data)
        return "break"

    def _terminal_paste(self, _event=None):
        if self.client is None:
            return "break"
        try:
            text = self.clipboard_get()
        except tk.TclError:
            return "break"
        if text:
            self.client.terminal_write(text)
        return "break"

    def _append_console(self, text: str):
        self.console_text.insert("end", redact_secrets(text) + "\n")
        self.console_text.see("end")

    def _append_terminal(self, text: str):
        self.terminal_text.insert("end", redact_secrets(text))
        self.terminal_text.see("end")

    def _append_log(self, text: str):
        self.deploy_log.insert("end", redact_secrets(text) + "\n")
        self.deploy_log.see("end")

    def _set_text(self, widget: tk.Text, text: str):
        widget.delete("1.0", "end")
        widget.insert("1.0", redact_secrets(text))
