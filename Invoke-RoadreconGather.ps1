<#
.SYNOPSIS
    ROADrecon `gather` wrapper with Windows-safe streaming output and a clear pass/fail summary.

.DESCRIPTION
    Wraps `roadrecon gather` (optionally `--mfa`) for Entra ID enumeration (section 35), matching
    the conventions of Start-RoadreconAuth.ps1 / Start-RoadreconGui.ps1:

    - Sets PYTHONUNBUFFERED=1 / PYTHONUTF8=1 so progress lines print immediately and cleanly on
      Windows Server.
    - Streams `roadrecon`'s output live line-by-line (same `2>&1 | ForEach-Object` pattern as the
      other ROADrecon helpers) rather than buffering to completion - this avoids both the
      "looks stuck" perception of a fully-buffered wrapper and the classic .NET Process
      redirected-stream deadlock that buffering both stdout/stderr synchronously can trigger.
    - Highlights `Error 40x/5xx` lines (per ROADtools docs, these indicate incomplete
      collection - usually a permission/role gap, not a fatal failure) instead of letting them
      scroll past unnoticed.
    - Confirms the database file was actually created/updated (not just that the process
      returned exit code 0) before declaring success.

    Requires `.roadtools_auth` from Start-RoadreconAuth.ps1 (or `-TokenFile`) in the current
    directory before running.

.PARAMETER Mfa
    Pass --mfa to also dump per-user MFA method details. Requires a privileged account (Global
    Reader / Security Reader / Authentication Administrator or above) - see AZURE_README.md.

.PARAMETER DbPath
    Optional path to the output database (forwarded as `-d`). Default: roadrecon.db (cwd).

.PARAMETER TokenFile
    Optional path to the token file from `roadrecon auth` (forwarded as `-f`). Default:
    .roadtools_auth (cwd).

.PARAMETER Tenant
    Optional tenant ID (forwarded as `-t`). Only needed if not already stored in the token file.

.PARAMETER SkipAzure
    Pass --skip-azure to skip Azure PIM collection (documented upstream as "slooooow").

.PARAMETER Evade
    Pass --evade to evade common AAD Graph enumeration detections.

.PARAMETER SkipFirstPhase
    Pass --skip-first-phase to assume phase 1 (object collection) already completed.

.EXAMPLE
    .\Invoke-RoadreconGather.ps1

.EXAMPLE
    .\Invoke-RoadreconGather.ps1 -Mfa

.EXAMPLE
    .\Invoke-RoadreconGather.ps1 -DbPath .\roadrecon-tenantA.db -SkipAzure

.NOTES
    Requires: roadrecon (pip), a valid .roadtools_auth from Start-RoadreconAuth.ps1.
    Next step after a successful gather: .\Start-RoadreconGui.ps1 (or -MsGraph only if you are
    running an unofficial Microsoft-Graph fork build - see AZURE_README.md).
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [switch]$Mfa,
    [string]$DbPath,
    [string]$TokenFile,
    [string]$Tenant,
    [switch]$SkipAzure,
    [switch]$Evade,
    [switch]$SkipFirstPhase
)

$ErrorActionPreference = "Stop"

# With EAP=Stop, an unhandled exception raised deep inside a nested helper call unwinds
# through every calling function before PowerShell's default host display shows it - and
# that default display only shows the OUTERMOST call site, not the actual line that
# failed. $_.ScriptStackTrace still has the real, innermost-first call chain, so surface
# it here instead of relying on the default one-line error display.
trap {
    Write-Host ""
    Write-Host "=== UNHANDLED ERROR ===" -ForegroundColor Red
    Write-Host "Message: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Call chain (innermost first):" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace
    exit 1
}

$roadrecon = Get-Command roadrecon -ErrorAction SilentlyContinue
if (-not $roadrecon) {
    throw "roadrecon not found in PATH. Run: .\Install-AzureReviewTools.ps1 -InstallPythonTools -AddToolsToUserPath"
}

$tokenFileToCheck = if ($TokenFile) { $TokenFile } else { ".roadtools_auth" }
if (-not (Test-Path $tokenFileToCheck)) {
    throw "$tokenFileToCheck not found in $(Get-Location). Run .\Start-RoadreconAuth.ps1 first (or pass -TokenFile)."
}

$dbFile = if ($DbPath) { $DbPath } else { Join-Path (Get-Location) "roadrecon.db" }
$dbExistedBefore = Test-Path $dbFile
$dbMTimeBefore = if ($dbExistedBefore) { (Get-Item $dbFile).LastWriteTimeUtc } else { $null }

$pArgs = @("gather")
if ($Mfa) { $pArgs += "--mfa" }
if ($DbPath) { $pArgs += @("-d", $DbPath) }
if ($TokenFile) { $pArgs += @("-f", $TokenFile) }
if ($Tenant) { $pArgs += @("-t", $Tenant) }
if ($SkipAzure) { $pArgs += "--skip-azure" }
if ($Evade) { $pArgs += "--evade" }
if ($SkipFirstPhase) { $pArgs += "--skip-first-phase" }

Write-Host "ROADrecon gather | mfa: $([bool]$Mfa) | db: $dbFile" -ForegroundColor Cyan
if ($Mfa) {
    Write-Host "MFA dump requires a privileged account (Global Reader / Security Reader / Authentication Administrator or above)." -ForegroundColor DarkGray
}
Write-Host "This can take a while on larger tenants (can issue hundreds to thousands of HTTP requests).`n" -ForegroundColor DarkGray

$errorLines = New-Object System.Collections.Generic.List[string]
$summaryLine = $null

$savedUnbuffered = $env:PYTHONUNBUFFERED
$savedUtf8 = $env:PYTHONUTF8
$prevEap = $ErrorActionPreference
try {
    $env:PYTHONUNBUFFERED = "1"
    $env:PYTHONUTF8 = "1"
    $ErrorActionPreference = "Continue"
    & $roadrecon.Source @pArgs 2>&1 | ForEach-Object {
        $line = $_.ToString()
        if ($line -match '\bError (4\d{2}|5\d{2})\b') {
            $errorLines.Add($line)
            Write-Host $line -ForegroundColor Red
        }
        elseif ($line -match 'executed in .* seconds and issued .* HTTP requests') {
            $summaryLine = $line
            Write-Host $line -ForegroundColor Green
        }
        else {
            Write-Host $line
        }
    }
    $gatherExit = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $prevEap
    if ($null -eq $savedUnbuffered) { Remove-Item Env:PYTHONUNBUFFERED -ErrorAction SilentlyContinue }
    else { $env:PYTHONUNBUFFERED = $savedUnbuffered }
    if ($null -eq $savedUtf8) { Remove-Item Env:PYTHONUTF8 -ErrorAction SilentlyContinue }
    else { $env:PYTHONUTF8 = $savedUtf8 }
}

$dbExistsAfter = Test-Path $dbFile
$dbUpdated = $dbExistsAfter -and ((-not $dbExistedBefore) -or ((Get-Item $dbFile).LastWriteTimeUtc -gt $dbMTimeBefore))

Write-Host ""
Write-Host "=== GATHER SUMMARY ===" -ForegroundColor Cyan
Write-Host "Exit code : $gatherExit"
Write-Host "Database  : $dbFile $(if ($dbExistsAfter) { '(exists)' } else { '(MISSING)' })"
if ($summaryLine) { Write-Host "Result    : $summaryLine" }
if ($errorLines.Count -gt 0) {
    Write-Host "HTTP 4xx/5xx lines: $($errorLines.Count)" -ForegroundColor Yellow
    Write-Host "  These usually mean incomplete collection due to a permission/role gap on the signed-in account" -ForegroundColor DarkGray
    Write-Host "  (Global Reader / Security Reader or above), not necessarily a fatal error - see AZURE_README.md." -ForegroundColor DarkGray
}

if ($gatherExit -eq 0 -and $dbUpdated) {
    Write-Host "`nGATHER SUCCEEDED" -ForegroundColor Green
    if ($errorLines.Count -gt 0) {
        Write-Host "  (completed with $($errorLines.Count) HTTP error line(s) above - some relationships may be incomplete)" -ForegroundColor Yellow
    }
    Write-Host "`nNext: .\Start-RoadreconGui.ps1" -ForegroundColor Cyan
}
else {
    Write-Host "`nGATHER FAILED" -ForegroundColor Red
    if ($gatherExit -ne 0) { Write-Host "  roadrecon exited with code $gatherExit" -ForegroundColor Red }
    if (-not $dbUpdated) { Write-Host "  $dbFile was not created/updated" -ForegroundColor Red }
    exit 1
}
