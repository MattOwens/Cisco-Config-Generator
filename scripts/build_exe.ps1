param(
    [string]$Python = "C:\Users\Matth\AppData\Local\Python\pythoncore-3.14-64\python.exe",
    [switch]$SkipDependencyInstall
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Python executable not found: $Python"
}

if (-not $SkipDependencyInstall) {
    & $Python -m pip install -r requirements.txt
    & $Python -m pip install pyinstaller
}

& $Python -m PyInstaller --clean --noconfirm CiscoConfigGenerator.spec

$Exe = Join-Path $Root "dist\CiscoConfigGenerator.exe"
if (-not (Test-Path -LiteralPath $Exe)) {
    throw "Build completed without creating $Exe"
}

Write-Host ""
Write-Host "Built: $Exe"
Write-Host "This is a single-file executable. Copy it to a test machine and run it."
