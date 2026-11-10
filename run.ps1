param(
    [string]$SshDir = "",
    [ValidateSet("dark", "light")]
    [string]$Theme = ""
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
if (-not $root) {
    $root = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$python = Join-Path $root ".conda\python.exe"

if (-not (Test-Path $python)) {
    throw "conda environment not found: $python. Create it with: conda create --prefix .conda python=3.12 -y"
}

$arguments = @((Join-Path $root "main.py"))
if ($SshDir) { $arguments += @("--ssh-dir", $SshDir) }
if ($Theme) { $arguments += @("--theme", $Theme) }

& $python @arguments
exit $LASTEXITCODE
