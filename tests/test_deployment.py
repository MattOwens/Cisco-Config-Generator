import threading
from dataclasses import dataclass

import ciscogen.app  # noqa: F401
from ciscogen.deploy import (
    DeploymentUnavailable,
    NetmikoDeploymentClient,
    install_optional_dependencies,
    missing_dependency_message,
    optional_dependency_status,
)
from ciscogen.deploy.guards import (
    DeploymentReport,
    DeploymentSelection,
    assess_deployment,
    backup_running_config,
    config_diff,
    deployment_report_json,
    deployment_report_markdown,
    detect_cli_errors,
    identity_warnings,
    parse_device_facts,
    postcheck_commands,
    precheck_commands,
    prepare_deployment_commands,
    rollback_notes,
)
from ciscogen.deploy.profiles import SSHProfile, SSHProfileStore, filter_profiles
from ciscogen.models import Project


@dataclass
class FakeIssue:
    severity: str
    message: str


class FakeClient:
    def __init__(self):
        self.saved = False

    def save_running_config(self, confirm=False):
        if not confirm:
            raise DeploymentUnavailable("Saving running-config requires explicit confirmation.")
        self.saved = True
        return "saved"


class FakeChannel:
    def __init__(self):
        self.written = []

    def write_channel(self, data):
        self.written.append(data)

    def read_channel(self):
        return "SW1#"


def test_deployment_imports_without_optional_dependencies(monkeypatch):
    import ciscogen.deploy as deploy

    monkeypatch.setattr(deploy, "find_spec", lambda name: None)
    status = optional_dependency_status()
    assert status["netmiko"] is False
    assert "Install" in missing_dependency_message() or "requirements-deploy.txt" in missing_dependency_message()


def test_install_optional_dependencies_invokes_pip(monkeypatch, tmp_path):
    calls = []

    def fake_run(command, check, capture_output, text):
        calls.append((command, check, capture_output, text))

        class Result:
            returncode = 0
            stdout = "ok"
            stderr = ""

        return Result()

    import ciscogen.deploy as deploy
    monkeypatch.setattr(deploy.subprocess, "run", fake_run)
    req = tmp_path / "requirements-deploy.txt"
    req.write_text("netmiko\n", encoding="utf-8")
    result = install_optional_dependencies("python-test", req)
    assert result.returncode == 0
    assert calls[0][0] == ["python-test", "-m", "pip", "install", "-r", str(req)]


def test_terminal_channel_read_write_methods():
    client = NetmikoDeploymentClient.__new__(NetmikoDeploymentClient)
    client.connection = FakeChannel()
    client._io_lock = threading.RLock()
    client.terminal_write("show clock\n")
    assert client.connection.written == ["show clock\n"]
    assert client.terminal_read() == "SW1#"


def test_ssh_profile_save_load_never_writes_plaintext_passwords(tmp_path):
    store = SSHProfileStore(tmp_path / "profiles.json")
    raw = {
        "name": "Core",
        "host": "10.0.0.1",
        "username": "admin",
        "password": "PlainTextPassword!",
        "enable_secret": "EnableSecret!",
        "tags": "core,dc",
    }
    profile = SSHProfile.from_dict(raw)
    store.save([profile])
    text = (tmp_path / "profiles.json").read_text(encoding="utf-8")
    assert "PlainTextPassword" not in text
    assert "EnableSecret" not in text
    loaded = store.load()[0]
    assert loaded.name == "Core"
    assert loaded.tags == ["core", "dc"]


def test_profile_import_export_and_filter(tmp_path):
    store = SSHProfileStore(tmp_path / "profiles.json")
    p1 = SSHProfile(name="Access 1", host="10.0.0.11", folder="Campus",
                    tags=["access"])
    p2 = SSHProfile(name="WAN Edge", host="10.0.0.12", folder="WAN",
                    tags=["edge"])
    store.save([p1, p2])
    exported = store.export_file(tmp_path / "export.json", [p1.id])
    imported_store = SSHProfileStore(tmp_path / "imported.json")
    imported = imported_store.import_file(exported)
    assert len(imported) == 1
    assert imported_store.load()[0].name == "Access 1"
    assert filter_profiles([p1, p2], "edge")[0].name == "WAN Edge"


def test_dry_run_default_and_backup_required(project):
    candidate = "hostname TEST\ninterface Vlan10\n ip address 10.0.0.1 255.255.255.0\n"
    dry = assess_deployment(DeploymentSelection(), candidate, [], "", False)
    assert dry.dry_run is True
    assert dry.allowed is False
    assert "Dry-run only" in dry.warnings[0]

    full = assess_deployment(DeploymentSelection(mode="full"),
                             candidate, [], "", True)
    assert full.allowed is False
    assert "Back up running-config" in full.blockers[0]


def test_deployment_blocked_on_critical_validation_errors(tmp_path):
    candidate = "hostname TEST\n"
    backup = str(tmp_path / "backup.cfg")
    assessment = assess_deployment(
        DeploymentSelection(mode="full"),
        candidate,
        [FakeIssue("error", "Missing domain name")],
        backup,
        True,
    )
    assert assessment.allowed is False
    assert any("Critical validation" in blocker for blocker in assessment.blockers)


def test_selected_line_and_section_command_preparation():
    selected = "interface Vlan10\n ip address 10.0.0.1 255.255.255.0\n!\nend\n"
    commands = prepare_deployment_commands(
        "hostname ignored",
        DeploymentSelection(mode="selected-lines", selected_text=selected),
    )
    assert commands == [
        "interface Vlan10",
        " ip address 10.0.0.1 255.255.255.0",
    ]

    candidate = "\n".join([
        "!",
        "! --- Static routes ---",
        "ip route 0.0.0.0 0.0.0.0 10.0.0.1",
        "!",
        "! --- Routing protocols ---",
        "router ospf 1",
    ])
    commands = prepare_deployment_commands(
        candidate,
        DeploymentSelection(mode="selected-section", section_key="layer3"),
    )
    assert commands == ["ip route 0.0.0.0 0.0.0.0 10.0.0.1"]


def test_save_running_config_requires_separate_confirmation():
    client = FakeClient()
    try:
        client.save_running_config(False)
    except DeploymentUnavailable as exc:
        assert "explicit confirmation" in str(exc)
    else:
        raise AssertionError("save_running_config should require confirmation")
    assert client.save_running_config(True) == "saved"


def test_precheck_and_postcheck_commands_follow_enabled_features(project):
    project.sections_enabled.update({
        "dmvpn": True, "routing": True, "ipsla": True, "nat": True,
        "vlans": False,
    })
    pre = precheck_commands(project)
    post = postcheck_commands(project)
    assert "show running-config" in pre
    assert "show interfaces tunnel" in pre
    assert "show ip nat translations" in post
    assert "show ip sla summary" in post

    project.sections_enabled.update({"dmvpn": False, "ipsla": False})
    post = postcheck_commands(project)
    assert "show dmvpn" not in post
    assert "show ip sla summary" not in post


def test_backup_diff_redaction_cli_errors_and_report(tmp_path):
    backup = backup_running_config("enable secret MySecret\n", "core", tmp_path)
    assert backup.exists()
    diff = config_diff("enable secret NewSecret\nhostname A\n",
                       "enable secret OldSecret\nhostname B\n")
    assert "NewSecret" not in diff
    assert "OldSecret" not in diff
    assert detect_cli_errors("% Invalid input detected at '^' marker.")

    report = DeploymentReport(
        timestamp="2026-07-04T12:00:00",
        ssh_profile_name="Core",
        target="10.0.0.1:22",
        backup_path=str(backup),
        deployment_mode="dry-run",
        commands_sent=["enable secret NewSecret"],
        errors_detected=["% Invalid input"],
        rollback_notes=rollback_notes(str(backup)),
    )
    markdown = deployment_report_markdown(report)
    payload = deployment_report_json(report)
    assert "Deployment Report" in markdown
    assert "NewSecret" not in markdown
    assert "NewSecret" not in payload


def test_device_mismatch_warnings(project):
    project.device_model = "Catalyst 9300"
    project.os_version = "17.9"
    project.data["system"]["hostname"] = "SW1"
    warnings = identity_warnings(project, {
        "hostname": "SW2",
        "model": "ISR 4331",
        "version": "16.12",
    })
    assert any("hostname" in warning.lower() for warning in warnings)
    assert any("platform" in warning.lower() for warning in warnings)
    assert any("version" in warning.lower() for warning in warnings)


def test_parse_device_facts_from_show_version():
    output = (
        "Cisco IOS XE Software, Version 17.09.04a\n"
        "Cisco IOS Software [Cupertino], ...\n"
        "SW-CORE uptime is 5 weeks, 2 days\n"
        "cisco C9300-48P (X86) processor with 1· memory.\n"
    )
    facts = parse_device_facts(output)
    assert facts["hostname"] == "SW-CORE"
    assert facts["model"] == "C9300-48P"
    assert facts["version"].startswith("17.09")


def test_parse_device_facts_empty_is_safe():
    assert parse_device_facts("") == {}
    assert parse_device_facts(None) == {}
