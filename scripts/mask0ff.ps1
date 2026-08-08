[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Mask0ffArguments
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$router = Join-Path $scriptRoot 'mask0ff.py'
$candidates = [System.Collections.Generic.List[object]]::new()

if ($env:MASK0FF_PYTHON) {
    $candidates.Add([pscustomobject]@{ Executable = $env:MASK0FF_PYTHON; Prefix = @() })
}

foreach ($name in @('python3', 'python')) {
    $command = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) {
        $candidates.Add([pscustomobject]@{ Executable = $command.Source; Prefix = @() })
    }
}

$pyLauncher = Get-Command 'py' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($pyLauncher) {
    $candidates.Add([pscustomobject]@{ Executable = $pyLauncher.Source; Prefix = @('-3') })
}

if ($env:USERPROFILE) {
    $bundled = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    if (Test-Path -LiteralPath $bundled -PathType Leaf) {
        $candidates.Add([pscustomobject]@{ Executable = $bundled; Prefix = @() })
    }
}

$selected = $null
foreach ($candidate in $candidates) {
    try {
        & $candidate.Executable @($candidate.Prefix) -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>$null
        if ($LASTEXITCODE -eq 0) {
            $selected = $candidate
            break
        }
    }
    catch {
        continue
    }
}

if (-not $selected) {
    Write-Error 'mask0ff requires Python 3.10 or newer. Set MASK0FF_PYTHON to a usable interpreter.'
    exit 2
}

$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONDONTWRITEBYTECODE = '1'
& $selected.Executable @($selected.Prefix) $router @Mask0ffArguments
exit $LASTEXITCODE
