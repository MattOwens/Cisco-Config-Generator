"""Optional live deployment helpers.

This module has no required third-party imports.  When Netmiko is installed,
callers may create a client explicitly; otherwise the offline app continues
to work and reports what optional packages are missing.
"""

from __future__ import annotations

import subprocess
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime
from importlib.util import find_spec
from pathlib import Path

from ..exporting import POSTCHECK_ITEMS, PRECHECK_COMMANDS

DEPLOYMENT_WARNING = (
    "Only connect to devices you own or are authorized to administer. "
    "Always test generated configs in a lab first."
)

# Keywords whose FOLLOWING token is a secret in IOS-style config lines.
SECRET_KEYWORDS = ("password", "secret", "key", "pre-shared-key",
                   "community", "token", "authentication-key")


@dataclass
class InventoryDevice:
    name: str
    host: str
    platform_type: str = "cisco_ios"
    device_model: str = ""
    os_type: str = ""
    username: str = ""
    auth_method: str = "prompt"
    key_path: str = ""
    ssh_port: int = 22
    enable_secret_env: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    site: str = ""
    role: str = ""


def optional_dependency_status() -> dict[str, bool]:
    return {
        "netmiko": find_spec("netmiko") is not None,
        "paramiko": find_spec("paramiko") is not None,
        "scrapli": find_spec("scrapli") is not None,
        "asyncssh": find_spec("asyncssh") is not None,
        "keyring": find_spec("keyring") is not None,
    }


def missing_dependency_message() -> str:
    missing = [name for name, present in optional_dependency_status().items()
               if not present and name in ("netmiko",)]
    if not missing:
        return "Optional deployment dependencies are available."
    return ("SSH support is not installed yet. Use the SSH Workspace install "
            "button, or run `pip install -r requirements-deploy.txt`.")


def deployment_requirements_path() -> Path:
    return Path(__file__).resolve().parents[2] / "requirements-deploy.txt"


def install_optional_dependencies(python_executable: str | None = None,
                                  requirements_path: str | Path | None = None
                                  ) -> subprocess.CompletedProcess:
    """Install SSH dependencies through pip.

    The app calls this only after the user clicks the install button. It is
    kept here so tests can mock the subprocess call and the UI stays simple.
    """
    python = python_executable or sys.executable
    req = Path(requirements_path) if requirements_path else deployment_requirements_path()
    return subprocess.run(
        [python, "-m", "pip", "install", "-r", str(req)],
        check=False,
        capture_output=True,
        text=True,
    )


def redact_secrets(text: str) -> str:
    """Replace the token that follows a secret keyword with <redacted>.

    Redacts the value itself (e.g. the PSK in
    'crypto isakmp key PSK address 0.0.0.0 0.0.0.0'), not whatever token
    happens to end the line.  'ntp authentication-key 1 md5 KEY' style
    lines are handled by also redacting after an intermediate digest
    keyword.
    """
    digest_keywords = ("md5", "sha", "sha256", "0", "5", "7", "8", "9")
    redacted_lines = []
    for line in (text or "").splitlines():
        parts = line.split()
        for index, token in enumerate(parts[:-1]):
            if token.lower() in SECRET_KEYWORDS:
                value_index = index + 1
                # skip encryption-type / digest keywords between the
                # keyword and the actual secret value
                while (value_index < len(parts) - 1
                       and parts[value_index].lower() in digest_keywords):
                    value_index += 1
                if value_index < len(parts):
                    parts[value_index] = "<redacted>"
        rebuilt = " ".join(parts)
        if line[:1] == " ":  # preserve leading indentation
            rebuilt = " " * (len(line) - len(line.lstrip())) + rebuilt
        redacted_lines.append(rebuilt)
    return "\n".join(redacted_lines)


def dry_run_plan(device: InventoryDevice, candidate_config: str) -> dict:
    return {
        "warning": DEPLOYMENT_WARNING,
        "dry_run": True,
        "target": device.name or device.host,
        "host": device.host,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "precheck_commands": list(PRECHECK_COMMANDS),
        "candidate_lines": len((candidate_config or "").splitlines()),
        "postcheck_items": list(POSTCHECK_ITEMS),
        "requires_confirmations": [
            "Confirm target hostname/model before deployment.",
            "Confirm before applying candidate configuration.",
            "Confirm again before saving running-config.",
        ],
    }


class DeploymentUnavailable(RuntimeError):
    pass


class NetmikoDeploymentClient:
    """Small guarded wrapper around Netmiko; imported only when instantiated."""

    def __init__(self, device: InventoryDevice, password: str,
                 enable_secret: str = ""):
        if find_spec("netmiko") is None:
            raise DeploymentUnavailable(missing_dependency_message())
        from netmiko import ConnectHandler  # type: ignore

        self._connect_handler = ConnectHandler
        self.device = device
        self.password = password
        self.enable_secret = enable_secret
        self.connection = None
        self._io_lock = threading.RLock()

    def connect(self):
        params = {
            "device_type": self.device.platform_type,
            "host": self.device.host,
            "username": self.device.username,
            "password": self.password,
            "port": self.device.ssh_port,
        }
        if self.device.auth_method == "key" and self.device.key_path:
            params["use_keys"] = True
            params["key_file"] = self.device.key_path
        if self.enable_secret:
            params["secret"] = self.enable_secret
        self.connection = self._connect_handler(**params)
        if self.enable_secret:
            self.connection.enable()
        return self.connection

    def disconnect(self) -> None:
        if self.connection is not None:
            self.connection.disconnect()
            self.connection = None

    def enter_enable(self, enable_secret: str = "") -> str:
        if self.connection is None:
            self.connect()
        if enable_secret:
            self.connection.secret = enable_secret
        self.connection.enable()
        try:
            return self.connection.find_prompt()
        except Exception:
            return "enable mode requested"

    def run_command(self, command: str) -> str:
        if self.connection is None:
            self.connect()
        with self._io_lock:
            return self.connection.send_command(command)

    def terminal_write(self, data: str) -> None:
        if self.connection is None:
            self.connect()
        with self._io_lock:
            self.connection.write_channel(data)

    def terminal_read(self) -> str:
        if self.connection is None:
            return ""
        if not self._io_lock.acquire(blocking=False):
            return ""
        try:
            return self.connection.read_channel()
        finally:
            self._io_lock.release()

    def run_show_commands(self, commands: list[str]) -> dict[str, str]:
        if self.connection is None:
            self.connect()
        return {command: self.run_command(command) for command in commands}

    def backup_running_config(self) -> str:
        return self.run_show_commands(["show running-config"])["show running-config"]

    def send_candidate(self, candidate_config: str, dry_run: bool = True,
                       chunk_size: int = 40) -> dict:
        if dry_run:
            return {"dry_run": True, "candidate": redact_secrets(candidate_config)}
        if self.connection is None:
            self.connect()
        commands = [line for line in candidate_config.splitlines()
                    if line and not line.startswith("!") and line != "end"]
        output = self.send_config_commands(commands, chunk_size)
        return {"dry_run": False, "output": output}

    def send_config_commands(self, commands: list[str],
                             chunk_size: int = 40) -> str:
        if self.connection is None:
            self.connect()
        outputs = []
        with self._io_lock:
            for index in range(0, len(commands), max(1, chunk_size)):
                chunk = commands[index:index + chunk_size]
                outputs.append(self.connection.send_config_set(chunk))
        output = "\n".join(outputs)
        return redact_secrets(output)

    def save_running_config(self, confirm: bool = False) -> str:
        if not confirm:
            raise DeploymentUnavailable("Saving running-config requires explicit confirmation.")
        if self.connection is None:
            self.connect()
        return self.connection.save_config()
