# Cisco Config Generator

**CREATED WITH CLAUDE AND CODEX**

- This is not affiliated with, endorsed by, or sponsored by Cisco.
- Generated configs are a starting point and must be reviewed/lab-tested before production.
- Only use SSH/deployment features on devices you own or are authorized to administer.
- Project files/exports may contain secrets if users enter passwords, SNMP communities, or IPsec keys.
- The .exe is unsigned, so Windows SmartScreen may warn on first launch.
- No warranty / use at your own risk.

A standalone Python/Tkinter desktop app for planning, validating, generating,
exporting and optionally deploying Cisco IOS / IOS-XE configurations.

The app still launches and generates configs if SSH libraries are missing.
The normal `requirements.txt` now includes SSH support so a standard install
works out of the box, and the SSH Workspace can install the same dependencies
from inside the app if needed.

Generated configurations are a starting point. Review, validate and lab-test
all output before production use. Only connect to devices you own or are
authorized to administer.

## Run

Offline/core mode:

```powershell
python run.py
```

Alternative:

```powershell
python -m ciscogen
```

Tests:

```powershell
python -m pytest tests -v
```

Install all app dependencies, including SSH support:

```powershell
pip install -r requirements.txt
```

Install only the SSH/deployment extras:

```powershell
pip install -r requirements-deploy.txt
```

Netmiko is the selected live SSH backend because it is built for
Cisco-style network-device command and configuration workflows. Paramiko is
used underneath Netmiko. Scrapli and AsyncSSH were considered, but this app
uses a conservative Tkinter command/response console instead of a full async
terminal emulator. If Netmiko is not available, open **SSH Workspace** and use
**Install SSH Support** instead of running a command manually.

## Build a Windows EXE

The release includes a unsigned .exe for a single-file
Windows executable that bundles Python, Tkinter, Netmiko/Paramiko and the app's
profile/template data


Copy that `.exe` to test users. It should open directly without requiring them
to install Python or run `pip`.

## Device capability system

Device profiles live in `ciscogen/profiles/data/*.json`. The app reads those
profiles to decide which sections to show and which platform warnings to
display. It does not ask you to select a license package; instead,
license-gated features (e.g. IPsec/DMVPN/ZBF on ISR routers requiring the
securityk9 package, DAI on 2960 requiring the LAN Base image) generate a
validation warning naming the required license or image.

Sections that hold configuration stay visible and enabled when you switch
to a device that does not list the capability - nothing is silently
disabled - and the section header explains why the capability is not
offered for the selected device.

Generated configurations are still a starting point. Exact support can vary by
hardware SKU, IOS/IOS-XE image and release, so verify against Cisco data sheets,
Cisco Feature Navigator, release notes and the target device before deployment.

## Configuration sections

- Base System: hostname, users, SSH, AAA, TACACS/RADIUS, SNMP/SNMPv3,
  logging, NTP, NetFlow, RESTCONF/NETCONF, SCP, banners and management IPs.
- VRF-Lite: VRF definitions, interface assignment, VRF static routes,
  VRF DHCP relay and basic VRF-aware OSPF/BGP.
- Interfaces: physical ports, port-channels, subinterfaces, SVIs, port
  security, guard features, storm control, source guard, UDLD and helpers.
- VLANs and Layer 2: VLANs, STP, DHCP snooping, DAI, VTP, errdisable
  recovery, private VLAN basics, SPAN and StackWise priority.
- Static Routing and PBR: static/default/floating routes, prefix lists,
  route maps and `ip policy`.
- IPv6: global routing, interface IPv6 addresses, static routes, ACL basics,
  DHCP relay and OSPFv3 basics.
- IP Tunnels & VPN: a list of tunnels, each of a selectable type - GRE
  point-to-point, GRE multipoint (DMVPN Phase 1/2/3), static VTI or
  IP-in-IP - with per-tunnel IKEv1/IKEv2 + IPsec tunnel protection, NHRP
  (for DMVPN) and routing over the tunnel (static, OSPF, EIGRP, BGP).
  Crypto object names are auto-uniquified per tunnel so multiple encrypted
  tunnels do not collide. Old single-DMVPN projects migrate automatically.
- IP SLA and Tracking: ICMP echo, TCP connect, UDP jitter, track objects,
  tracked routes, floating routes and simple EEM actions.
- ZBF: zones, zone membership, class maps, policy maps and zone pairs.
- QoS: trust DSCP/CoS, AutoQoS helper, class maps, policy maps and
  service-policy bindings.
- Gateway HA: HSRP, VRRP and GLBP interface configuration with tracking.
- Custom CLI: global, pre-interface, per-interface, post-routing and end
  blocks, with dangerous-command warnings.

## Templates

Templates are partial JSON snippets in `samples/templates/`. Use
**Config -> Apply Template...** to merge a template into the current project.
Lists are appended and dictionaries are merged; the current project is not
blindly replaced.

Included presets cover access switches, L3 switches, router-on-a-stick, NAT
edge, WAN failover with IP SLA, DMVPN hub/spoke, secure management, ISR and
Catalyst baselines, OSPF/BGP, voice VLAN and ZBF router patterns.

## Export and deployment bundle

The File menu can export:

- Final config as `.cfg` or `.txt`
- Project JSON
- Validation/lint report as Markdown
- Deployment checklist as Markdown
- Rollback checklist as Markdown
- Deployment bundle folder plus `deployment_bundle.zip`

The deployment checklist includes device model, OS, enabled sections,
device-profile capabilities, pre-check commands, backup steps, deployment
method, rollback guidance, post-checks and current validation warnings.

## Optional live deployment

Open **Deployment -> Open SSH Workspace...** or use the **SSH Workspace**
toolbar button. Live deployment is opt-in and guarded:

- Never runs on startup.
- Never runs after config generation.
- Dry-run/diff is the default workflow.
- Running-config backup is required before an actual config push.
- Deploying candidate commands requires explicit confirmation.
- Saving running-config requires a separate explicit confirmation.
- Device/deployment credentials are never saved in project JSON or SSH
  profile JSON. Passwords and enable secrets are prompted at connection time
  or can be read from environment variables. (Note:
  configuration secrets you type into forms - enable secret, local user
  secrets, SNMP communities, IPsec pre-shared keys - are part of the
  generated config and ARE stored in project files and exported bundles;
  protect those files accordingly.)
- Logs/reports redact secret values (passwords, keys, pre-shared keys,
  SNMP communities).
- Deployment is blocked by default when critical validation issues exist.
- Logs, reports, previews and diffs redact common secret values.
- CLI errors are detected from command output and surfaced in the deployment
  log.

### SSH profile manager

Profiles store connection metadata only: profile name, host, port, username,
auth method, SSH key path, optional environment variable names, selected app
device model, OS type/version, site, role, notes, tags and folder/group.
Profiles can be created, edited, duplicated, deleted, imported, exported,
searched and grouped. Exported profiles do not include passwords or enable
secrets.

### Interactive SSH CLI

The SSH Workspace includes an **Interactive CLI** tab for Putty/SecureCRT-style
typing. Click the terminal area and type directly; Enter, Backspace, Tab,
arrow keys, Ctrl-C and paste are sent to the live SSH channel while output is
streamed back in the background. A separate command-output tab still provides
show-command helpers, running-config pull, pre-checks, post-checks and
connection status.

### Side-by-side deployment workflow

The left side holds the candidate configuration, validation results and
deployment log. Load either the generated config or the final edited config,
select dry-run, selected lines, selected section or full candidate, then run
validation. The right side holds SSH profiles, the interactive CLI, command
output and running-config viewer.

Recommended guarded flow:

1. Select or create an SSH profile.
2. Connect and run pre-checks.
3. Back up running-config.
4. Load generated or final candidate config.
5. Resolve validation errors.
6. Choose selected lines, selected section or full candidate.
7. Confirm deployment.
8. Review output and post-checks.
9. Separately confirm save running-config.
10. Export the deployment report.

Rollback guidance is report-driven: keep the timestamped backup, compare
after deployment, and manually paste known-good rollback commands or restore
only through a lab-tested procedure. The app does not default to
`config replace`.

## Import existing config

**File -> Import Running Config...** parses common IOS syntax:

hostname, domain name, users, VLANs, interfaces, descriptions, access/trunk
mode, IP addresses, SVIs, subinterfaces, static routes, DHCP pools, ACLs,
OSPF/EIGRP/BGP basics, NAT inside/outside markers, IP SLA, track objects and
DMVPN tunnel basics.

Commands that are not recognized are preserved in Custom CLI under
`unparsed_imported_lines` and surfaced as import warnings.

## Add a device profile

Create a JSON file in `ciscogen/profiles/data/` using a similar device as a
starting point. Required keys are `model`, `family`, `device_class`,
`os_type`, `supported_os_versions`, `interface_naming`, `interfaces`,
`interface_count`, `capabilities`, `syntax_notes`, `platform_warnings` and
`feature_warnings`.

Profile capabilities control which sections are visible and which validation
warnings are raised.

## Add a generator module

1. Create `ciscogen/generators/my_feature.py`.
2. Expose `generate(section_data, profile) -> dict[str, list[str]]`.
3. If the feature adds interface-level commands, expose
   `collect_interface_extras(section_data, extras)`.
4. Wire it into `ciscogen/generators/__init__.py`.
5. Add defaults in `ciscogen/models/project.py`, a form in
   `ciscogen/ui/forms/`, validators and tests.

## Add a UI form

Forms use `Binder`, `FormBuilder` and `TableEditor` from
`ciscogen/ui/widgets.py`. Bind directly to `project.data[section]` and
register the form in `ciscogen/ui/forms/__init__.py`.

## Honest limitations

- The app generates valid-looking IOS/IOS-XE CLI, but it is not a substitute
  for device parser validation or lab testing.
- Live deployment currently uses a conservative Netmiko command/response
  workflow; full terminal emulation, persistent job history and structured
  pyATS/Genie parsing can be expanded later.
- The running-config importer is intentionally conservative and preserves
  unparsed lines rather than guessing.
- Some advanced features are broad Cisco domains; this release implements
  practical baselines and warnings, not every platform-specific knob.
