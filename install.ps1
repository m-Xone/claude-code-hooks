# cchooks installer for Windows PowerShell 5.1+ and PowerShell 7+.
# Finds a real Python 3.9+ interpreter (skipping the Microsoft Store stub)
# and hands off to installer\install.py, which records that interpreter's
# absolute path in the hook entries. Arguments are passed through:
#   .\install.ps1 --mode warn
#   .\install.ps1 --uninstall
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Get-PythonPath([string[]]$cmd) {
    try {
        $exe = $cmd[0]
        $rest = @()
        if ($cmd.Length -gt 1) { $rest = $cmd[1..($cmd.Length - 1)] }
        $found = Get-Command $exe -ErrorAction SilentlyContinue
        if (-not $found) { return $null }
        # The WindowsApps python.exe is a Store installer stub, not Python.
        if ($found.Source -like '*\WindowsApps\*') {
            $probe = & $exe @rest -c "import sys; print(sys.executable)" 2>$null
            if (-not $probe -or $probe -like '*\WindowsApps\*') { return $null }
        }
        & $exe @rest -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { return $null }
        $path = & $exe @rest -c "import sys; print(sys.executable)" 2>$null
        if ($path) { return $path.Trim() }
    } catch { }
    return $null
}

$candidates = @()
if ($env:CCHOOKS_PYTHON) { $candidates += ,@($env:CCHOOKS_PYTHON) }
$candidates += ,@('py', '-3')
$candidates += ,@('python')
$candidates += ,@('python3')

$py = $null
foreach ($c in $candidates) {
    $py = Get-PythonPath $c
    if ($py) { break }
}

if (-not $py) {
    Write-Error ("cchooks: no Python 3.9+ found (tried CCHOOKS_PYTHON, py -3, python, python3).`n" +
                 "Install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH') and re-run.`n" +
                 "Without it the hooks would fail to start, and Claude Code treats that as 'allow'.")
    exit 1
}

Write-Host "Using Python: $py"
& $py (Join-Path $here 'installer\install.py') @args
exit $LASTEXITCODE
