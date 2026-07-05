# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the Cisco Config Generator desktop app.

Build with:

    pyinstaller --clean --noconfirm CiscoConfigGenerator.spec
"""

from PyInstaller.utils.hooks import (
    collect_data_files,
    collect_submodules,
    copy_metadata,
)


block_cipher = None

datas = [
    ("ciscogen/profiles/data", "ciscogen/profiles/data"),
    ("ciscogen/profiles/capability_data", "ciscogen/profiles/capability_data"),
    ("samples", "samples"),
    ("README.md", "."),
    ("requirements-deploy.txt", "."),
]

for package in (
    "netmiko",
    "ntc_templates",
    "textfsm",
    "paramiko",
    "cryptography",
    "bcrypt",
    "nacl",
    "scp",
    "serial",
    "yaml",
    "ruamel.yaml",
    "rich",
    "keyring",
):
    try:
        datas += collect_data_files(package)
    except Exception:
        pass
    try:
        datas += copy_metadata(package)
    except Exception:
        pass

hiddenimports = []
for package in (
    "netmiko",
    "ntc_templates",
    "textfsm",
    "paramiko",
    "cryptography",
    "bcrypt",
    "nacl",
    "scp",
    "serial",
    "yaml",
    "ruamel",
    "rich",
    "keyring",
    "jaraco",
):
    try:
        hiddenimports += collect_submodules(package)
    except Exception:
        pass


a = Analysis(
    ["run.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "tests"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="CiscoConfigGenerator",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
