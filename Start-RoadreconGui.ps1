<#
.SYNOPSIS
    Start the ROADrecon web GUI without PowerShell treating Flask stderr as a fatal error.

.DESCRIPTION
    ROADrecon's Flask dev server prints a normal Werkzeug WARNING to stderr. PowerShell
    often displays that as a red NativeCommandError even though the GUI is running.

    This helper sets PYTHONUNBUFFERED=1 and runs roadrecon with ErrorAction Continue so
    startup lines print cleanly. Open http://127.0.0.1:5000 in a browser on the same
    host (RDP session on the DC). Press Ctrl+C here to stop the server.

    Requires roadrecon.db from `roadrecon gather` in the current directory (or use -DbPath).

.PARAMETER MsGraph
    Pass --msgraph when gather was run with --msgraph.

.PARAMETER DbPath
    Optional path to roadrecon.db (forwarded as roadrecon -d if supported by your version).

.EXAMPLE
    .\Start-RoadreconGui.ps1

.NOTES
    The Werkzeug "development server" line is expected - not a failure.
#>

[CmdletBinding()]
param(
    [switch]$MsGraph,
    [string]$DbPath
)

$ErrorActionPreference = "Stop"

function Write-RoadreconWarn {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

$roadrecon = Get-Command roadrecon -ErrorAction SilentlyContinue
if (-not $roadrecon) {
    throw "roadrecon not found in PATH. Run: .\Install-AzureReviewTools.ps1 -InstallPythonTools -AddToolsToUserPath"
}

$dbFile = if ($DbPath) { $DbPath } else { Join-Path (Get-Location) "roadrecon.db" }
if (-not (Test-Path $dbFile)) {
    Write-RoadreconWarn @"
roadrecon.db not found at: $dbFile
Run roadrecon gather first (after Start-RoadreconAuth.ps1).
"@
}

$pArgs = @("gui")
if ($MsGraph) { $pArgs += "--msgraph" }
if ($DbPath) { $pArgs += @("-d", $DbPath) }

Write-Host "Starting ROADrecon GUI (Flask may print a stderr WARNING - that is normal)." -ForegroundColor Cyan
Write-Host "Open http://127.0.0.1:5000 in a browser on this machine. Ctrl+C here stops the server.`n" -ForegroundColor DarkGray

$savedUnbuffered = $env:PYTHONUNBUFFERED
$savedUtf8 = $env:PYTHONUTF8
$prevEap = $ErrorActionPreference
try {
    $env:PYTHONUNBUFFERED = "1"
    $env:PYTHONUTF8 = "1"
    $ErrorActionPreference = "Continue"
    & $roadrecon.Source @pArgs 2>&1 | ForEach-Object { Write-Host $_.ToString() }
}
finally {
    $ErrorActionPreference = $prevEap
    if ($null -eq $savedUnbuffered) { Remove-Item Env:PYTHONUNBUFFERED -ErrorAction SilentlyContinue }
    else { $env:PYTHONUNBUFFERED = $savedUnbuffered }
    if ($null -eq $savedUtf8) { Remove-Item Env:PYTHONUTF8 -ErrorAction SilentlyContinue }
    else { $env:PYTHONUTF8 = $savedUtf8 }
}
