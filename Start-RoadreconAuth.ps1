<#
.SYNOPSIS
    ROADrecon device-code auth with correct tenant/client and Windows-safe console output.

.DESCRIPTION
    Wraps `roadrecon auth --device-code` for Entra ID enumeration (section 35).

    - Uses the Azure CLI public client (04b07795-...) and an explicit tenant (-t), per ROADtools
      guidance — plain `roadrecon auth --device-code` often lands in the wrong tenant or hits
      AAD Graph 403s.
    - Sets PYTHONUNBUFFERED=1 so the device code appears immediately in PowerShell on Windows
      Server (without this, output may not show until Ctrl+C).
    - Writes tokens to .roadtools_auth in the current directory (ROADrecon default).

    Auth only — run `Invoke-RoadreconGather.ps1` (or `roadrecon gather`) and `roadrecon gui`
    afterward. Do not reuse this token for AzureHound (use Get-AzureHoundRefreshToken.ps1).

.PARAMETER Tenant
    Tenant domain (e.g. contoso.onmicrosoft.com) or tenant GUID. Defaults to az account tenant.

.PARAMETER ForceReauth
    Delete .roadtools_auth in the current directory before starting.

.EXAMPLE
    .\Start-RoadreconAuth.ps1

.EXAMPLE
    .\Start-RoadreconAuth.ps1 -Tenant halflukelive.onmicrosoft.com -ForceReauth

.NOTES
    Requires: roadrecon (pip), network to login.microsoftonline.com, az CLI optional for default tenant.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Tenant,
    [switch]$ForceReauth
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

$RoadreconClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
$TokenFileName = ".roadtools_auth"

$roadrecon = Get-Command roadrecon -ErrorAction SilentlyContinue
if (-not $roadrecon) {
    throw "roadrecon not found in PATH. Run: .\Install-AzureReviewTools.ps1 -InstallPythonTools -AddToolsToUserPath"
}

if (-not $Tenant) {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "az CLI not found. Run az login or pass -Tenant <domain-or-guid>."
    }
    $Tenant = az account show --query tenantDefaultDomain -o tsv 2>$null
    if (-not $Tenant) {
        $Tenant = az account show --query tenantId -o tsv 2>$null
    }
    if (-not $Tenant) {
        throw "No az account context. Run az login or pass -Tenant."
    }
}

if ($ForceReauth -and (Test-Path $TokenFileName)) {
    Remove-Item $TokenFileName -Force
    Write-Host "Removed stale $TokenFileName" -ForegroundColor Yellow
}

Write-Host "ROADrecon device-code auth | tenant: $Tenant | client: Azure CLI ($RoadreconClientId)" -ForegroundColor Cyan
Write-Host "Complete sign-in in the browser when the code appears. Do not press Ctrl+C while waiting.`n" -ForegroundColor DarkGray

$pArgs = @(
    "auth", "--device-code",
    "-c", $RoadreconClientId,
    "-t", $Tenant
)

$savedUnbuffered = $env:PYTHONUNBUFFERED
$savedUtf8 = $env:PYTHONUTF8
$prevEap = $ErrorActionPreference
try {
    $env:PYTHONUNBUFFERED = "1"
    $env:PYTHONUTF8 = "1"
    $ErrorActionPreference = "Continue"
    & $roadrecon.Source @pArgs 2>&1 | ForEach-Object { Write-Host $_.ToString() }
    if ($LASTEXITCODE -ne 0) {
        throw "roadrecon auth failed (exit $LASTEXITCODE)."
    }
}
finally {
    $ErrorActionPreference = $prevEap
    if ($null -eq $savedUnbuffered) { Remove-Item Env:PYTHONUNBUFFERED -ErrorAction SilentlyContinue }
    else { $env:PYTHONUNBUFFERED = $savedUnbuffered }
    if ($null -eq $savedUtf8) { Remove-Item Env:PYTHONUTF8 -ErrorAction SilentlyContinue }
    else { $env:PYTHONUTF8 = $savedUtf8 }
}

if (-not (Test-Path $TokenFileName)) {
    throw "Auth finished but $TokenFileName was not created in $(Get-Location)."
}

Write-Host "`nSuccess. Token saved to $(Join-Path (Get-Location) $TokenFileName)" -ForegroundColor Green
Write-Host "Next: .\Invoke-RoadreconGather.ps1   then   .\Start-RoadreconGui.ps1" -ForegroundColor Cyan
