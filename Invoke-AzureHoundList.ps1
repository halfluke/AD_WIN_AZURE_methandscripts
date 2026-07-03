<#
.SYNOPSIS
    Run AzureHound collection (step 2 of the two-step workflow) with clear pass/fail reporting.

.DESCRIPTION
    Step 1 is Get-AzureHoundRefreshToken.ps1 (writes ./tools/azurehound.refresh). This script
    reads that token and runs `azurehound list`, capturing its output via .NET Process directly
    instead of invoking it as a plain PowerShell native command. That matters because PowerShell
    wraps ANY stderr line from a native executable in a red NativeCommandError/RemoteException
    block - even harmless informational lines like AzureHound's "no config.json found" notice -
    which makes a fully successful run look like it crashed.

    This script instead classifies AzureHound's own log lines:
      - Known-benign lines (missing config.json; missing Entra P1/P2 premium license;
        missing PIM/RoleManagement read scopes; a built-in role template absent from this
        tenant) are shown dimmed, not as PowerShell errors - these are expected on free/lab
        tenants and documented in AZURE_README.md's "Expected errors" table.
      - Anything else AzureHound logs at ERR level is shown in red so it stands out.
    The final PASS/FAIL verdict is based on AzureHound's actual exit code and whether the
    output JSON file was written - not on whether any stderr lines were seen.

.PARAMETER Tenant
    Tenant domain (e.g. contoso.onmicrosoft.com) or GUID. Defaults to the signed-in az account
    (same auto-detection as Get-AzureHoundRefreshToken.ps1).

.PARAMETER RefreshTokenPath
    Path to the refresh token file written by Get-AzureHoundRefreshToken.ps1.
    Default: ./tools/azurehound.refresh

.PARAMETER OutputPath
    Where AzureHound writes its collection JSON. Default: ./tools/azurehound.json

.PARAMETER SubscriptionId
    Optional: limit collection to a single subscription (AzureHound's -b flag). Default: all
    subscriptions the token can reach.

.PARAMETER AzureHoundPath
    Optional: explicit path to the azurehound binary. Default: azurehound in PATH, else
    ./tools/azurehound.exe (Windows) or ./tools/azurehound (Linux/macOS).

.EXAMPLE
    .\Get-AzureHoundRefreshToken.ps1
    .\Invoke-AzureHoundList.ps1

.EXAMPLE
    .\Invoke-AzureHoundList.ps1 -SubscriptionId (az account show --query id -o tsv)

.NOTES
    Cross-platform: PowerShell 5.1+ on Windows, PowerShell 7 (pwsh) on Linux/macOS.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Tenant,
    [string]$RefreshTokenPath,
    [string]$OutputPath,
    [string]$SubscriptionId,
    [string]$AzureHoundPath
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

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$toolsDir = Join-Path $scriptDir "tools"

if (-not $RefreshTokenPath) { $RefreshTokenPath = Join-Path $toolsDir "azurehound.refresh" }
if (-not $OutputPath) { $OutputPath = Join-Path $toolsDir "azurehound.json" }

if (-not (Test-Path -LiteralPath $RefreshTokenPath)) {
    throw "Refresh token file not found at '$RefreshTokenPath'. Run .\Get-AzureHoundRefreshToken.ps1 first."
}

if (-not $Tenant) {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "az CLI not found. Sign in with az login or pass -Tenant <domain-or-guid>."
    }
    $Tenant = az account show --query tenantDefaultDomain -o tsv 2>$null
    if (-not $Tenant) {
        throw "No az account context. Run az login or pass -Tenant."
    }
}

function Resolve-AzureHoundExecutable {
    param([string]$ExplicitPath, [string]$ToolsDir)
    if ($ExplicitPath) {
        if (Test-Path -LiteralPath $ExplicitPath) { return (Resolve-Path -LiteralPath $ExplicitPath).Path }
        throw "azurehound not found at explicit path '$ExplicitPath'."
    }
    $cmd = Get-Command azurehound -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $isWindowsHost = $env:OS -match "Windows" -or ($PSVersionTable.PSVersion.Major -le 5)
    $candidateName = if ($isWindowsHost) { "azurehound.exe" } else { "azurehound" }
    $candidate = Join-Path $ToolsDir $candidateName
    if (Test-Path -LiteralPath $candidate) { return $candidate }
    throw "azurehound not found in PATH or in '$ToolsDir'. Run .\Install-AzureReviewTools.ps1 -InstallAzureHound."
}

$azureHoundExe = Resolve-AzureHoundExecutable -ExplicitPath $AzureHoundPath -ToolsDir $toolsDir

$refreshToken = (Get-Content -LiteralPath $RefreshTokenPath -Raw).Trim()
if (-not $refreshToken) {
    throw "Refresh token file '$RefreshTokenPath' is empty. Re-run .\Get-AzureHoundRefreshToken.ps1."
}

$outDir = Split-Path -Parent $OutputPath
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
if (Test-Path -LiteralPath $OutputPath) {
    Remove-Item -LiteralPath $OutputPath -Force
}

$argList = @("list", "-r", $refreshToken, "-t", $Tenant)
if ($SubscriptionId) { $argList += @("-b", $SubscriptionId) }
$argList += @("-o", $OutputPath)

# Known-benign AzureHound log lines on free/lab tenants or when no config.json is present
# (our documented workflow never creates one) - see AZURE_README.md "Expected errors on
# free / lab tenants (often OK)". Matched here instead of relying on PowerShell's default
# NativeCommandError display, which would otherwise flag every one of these as a scary red
# "error" even on a fully successful collection run.
$benignPatterns = @(
    "No configuration file located at",
    "PermissionScopeNotGranted",
    "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
    "Request_ResourceNotFound"
)

function Test-BenignAzureHoundLine {
    param([string]$Line)
    foreach ($pattern in $benignPatterns) {
        if ($Line -match [regex]::Escape($pattern)) { return $true }
    }
    return $false
}

function ConvertTo-ProcessArgumentString {
    param([string[]]$ArgumentList)
    return ($ArgumentList | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join " "
}

Write-Host "Tenant     : $Tenant"
Write-Host "AzureHound : $azureHoundExe"
Write-Host "Output     : $OutputPath"
Write-Host ""

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $azureHoundExe
$psi.Arguments = ConvertTo-ProcessArgumentString -ArgumentList $argList
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

try {
    $proc = [System.Diagnostics.Process]::Start($psi)
}
catch {
    throw "Failed to start AzureHound at '$azureHoundExe': $($_.Exception.Message)"
}

# Buffered (not streamed) on purpose: AzureHound collection on lab-sized tenants finishes in
# seconds, and buffering avoids the scoping/ordering pitfalls of Register-ObjectEvent-based
# async reads in a plain (non-module) script.
#
# IMPORTANT: both streams must be read concurrently, not one after the other. If AzureHound
# writes enough to stderr to fill the OS pipe buffer while we're still blocked synchronously
# draining stdout (ReadToEnd() only returns at EOF/process exit), AzureHound itself blocks on
# the full stderr pipe and can never finish - and we're stuck waiting for stdout to close. Both
# sides deadlock forever. Kicking off both reads as async Tasks before waiting avoids this.
$stdoutTask = $proc.StandardOutput.ReadToEndAsync()
$stderrTask = $proc.StandardError.ReadToEndAsync()
$proc.WaitForExit()
$stdout = $stdoutTask.GetAwaiter().GetResult()
$stderr = $stderrTask.GetAwaiter().GetResult()

$benignCount = 0
$unexpectedErrLines = [System.Collections.Generic.List[string]]::new()

foreach ($line in (@($stdout -split "`r?`n") + @($stderr -split "`r?`n"))) {
    if (-not $line) { continue }
    if (Test-BenignAzureHoundLine -Line $line) {
        $benignCount++
        Write-Host "  [expected] $line" -ForegroundColor DarkGray
    }
    elseif ($line -match '\bERR\b') {
        $unexpectedErrLines.Add($line)
        Write-Host $line -ForegroundColor Red
    }
    else {
        Write-Host $line -ForegroundColor Gray
    }
}

Write-Host ""

$outputWritten = (Test-Path -LiteralPath $OutputPath) -and ((Get-Item -LiteralPath $OutputPath).Length -gt 0)
$success = ($proc.ExitCode -eq 0) -and $outputWritten

if ($success) {
    Write-Host "=== COLLECTION SUCCEEDED ===" -ForegroundColor Green
    Write-Host "Output: $OutputPath"
    if ($benignCount -gt 0) {
        Write-Host "$benignCount expected warning(s) (tenant licensing / permission-scope limits - see AZURE_README.md 'Expected errors on free / lab tenants') - not a failure." -ForegroundColor DarkGray
    }
    if ($unexpectedErrLines.Count -gt 0) {
        Write-Host "$($unexpectedErrLines.Count) unexpected ERR line(s) were logged above (shown in red) - review them; collection still completed and wrote output." -ForegroundColor Yellow
    }
    exit 0
}
else {
    Write-Host "=== COLLECTION FAILED ===" -ForegroundColor Red
    Write-Host "Exit code: $($proc.ExitCode)"
    Write-Host "Output file written: $outputWritten"
    if ($unexpectedErrLines.Count -gt 0) {
        Write-Host "Unexpected error(s):" -ForegroundColor Red
        $unexpectedErrLines | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    }
    exit 1
}
