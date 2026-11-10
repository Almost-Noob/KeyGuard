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
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "Python environment not found: $python. Rebuild .venv using the instructions in README.md."
}

$arguments = @((Join-Path $root "main.py"))
if ($SshDir) { $arguments += @("--ssh-dir", $SshDir) }
if ($Theme) { $arguments += @("--theme", $Theme) }

& $python @arguments
exit $LASTEXITCODE
