<#
.SYNOPSIS
    Install and verify AD review tooling on Windows.

.DESCRIPTION
    Checks PATH and .\tools for SharpHound, PingCastle, and Purple Knight signals.
    Can download:
      - SharpHound.exe from SpecterOps/SharpHound latest release (-InstallSharpHound)
      - PingCastle.exe from vletoux/PingCastle latest release (-InstallPingCastle)

    Purple Knight (Semperis) is commercial/community — not auto-downloaded. Install from
    https://www.semperis.com/purple-knight/ then re-run this script to verify.

    Microsoft Graph PowerShell SDK (optional) for ADReviewv1.ps1 -IncludeEntra hybrid checks.

.PARAMETER InstallGraphModule
    Install Microsoft.Graph module (CurrentUser) for Connect-MgGraph / Invoke-MgGraphRequest.

.PARAMETER InstallSharpHound
    Download SharpHound.exe into .\tools

.PARAMETER InstallPingCastle
    Download PingCastle.exe into .\tools

.PARAMETER InstallAll
    Equivalent to -InstallSharpHound -InstallPingCastle (not Microsoft.Graph; use -InstallGraphModule for hybrid Entra)

.PARAMETER Upgrade
    Download SharpHound and/or PingCastle when missing, tag is unknown, or a newer GitHub release is available.
    Skips re-download when already at latest. Use with -InstallSharpHound / -InstallPingCastle (or -InstallAll).
    Without -Upgrade, existing binaries are kept when present.

.PARAMETER AddToolsToUserPath
    Append .\tools to the user PATH permanently.

.PARAMETER CheckOnly
    Report only; do not install anything (default when no install switches are passed).

.EXAMPLE
    .\Install-ADReviewTools.ps1

.EXAMPLE
    .\Install-ADReviewTools.ps1 -InstallAll -AddToolsToUserPath

.EXAMPLE
    .\Install-ADReviewTools.ps1 -InstallAll -Upgrade

.NOTES
    BloodHound CE GUI: Docker Desktop + bloodhound-cli — https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart
    Shared tools folder with Install-AzureReviewTools.ps1 (.\tools).
#>

[CmdletBinding()]
param(
    [switch]$InstallSharpHound,
    [switch]$InstallPingCastle,
    [switch]$InstallGraphModule,
    [switch]$InstallAll,
    [switch]$Upgrade,
    [switch]$AddToolsToUserPath,
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$toolsDir = Join-Path $scriptDir "tools"
$sharpHoundPath = Join-Path $toolsDir "SharpHound.exe"
$pingCastlePath = Join-Path $toolsDir "PingCastle.exe"
$sharpHoundMetaPath = Join-Path $toolsDir "sharphound.release"
$pingCastleMetaPath = Join-Path $toolsDir "pingcastle.release"

if ($InstallAll) {
    $InstallSharpHound = $true
    $InstallPingCastle = $true
}

$anyInstallSwitch = $InstallSharpHound -or $InstallPingCastle -or $InstallGraphModule -or $AddToolsToUserPath -or $Upgrade
if ($CheckOnly -and $anyInstallSwitch) {
    Write-Error "-CheckOnly cannot be combined with install switches."
}
if (-not $CheckOnly -and -not $anyInstallSwitch) {
    $CheckOnly = $true
}

function Write-BloodHoundCeInstallHint {
    Write-Host "`nBloodHound CE (Docker + bloodhound-cli - not a single .exe):" -ForegroundColor DarkGray
    Write-Host "  Quickstart: https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart" -ForegroundColor DarkGray
    Write-Host "  1) Install Docker Desktop" -ForegroundColor DarkGray
    Write-Host "  2) Download bloodhound-cli: https://github.com/SpecterOps/bloodhound-cli/releases/latest" -ForegroundColor DarkGray
    Write-Host "  3) Run: bloodhound-cli install -> UI: http://localhost:8080/ui/login" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Write-WarnStep {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Test-ToolCommand {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$ExtraPaths = @()
    )

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) {
        return [PSCustomObject]@{
            Name       = $Name
            Found      = $true
            Source     = $cmd.Source
            Detail     = $cmd.Source
            InPathHint = $true
        }
    }

    foreach ($dir in $ExtraPaths) {
        if (-not $dir -or -not (Test-Path $dir)) { continue }
        $candidate = Join-Path $dir $Name
        if ($Name -notmatch '\.') { $candidate = Join-Path $dir "$Name.exe" }
        if (Test-Path $candidate) {
            return [PSCustomObject]@{
                Name       = $Name
                Found      = $true
                Source     = $candidate
                Detail     = $candidate
                InPathHint = $false
            }
        }
    }

    return [PSCustomObject]@{
        Name       = $Name
        Found      = $false
        Source     = $null
        Detail     = "Not found in PATH or .\tools"
        InPathHint = $false
    }
}

function Add-DirectoryToUserPath {
    param([Parameter(Mandatory)][string]$Directory)

    if (-not (Test-Path $Directory)) { return }

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = $userPath -split ';' | Where-Object { $_ -and $_.Trim() -ne "" }
    if ($parts -contains $Directory) {
        Write-Step "Already in user PATH: $Directory"
        return
    }

    $newPath = ($parts + $Directory) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    $env:Path = "$env:Path;$Directory"
    Write-Step "Added to user PATH: $Directory"
}

function Get-InstalledReleaseTag {
    param(
        [string]$MetaPath,
        [string]$BinaryPath
    )

    if ($MetaPath -and (Test-Path $MetaPath)) {
        $tag = (Get-Content -Path $MetaPath -Raw -ErrorAction SilentlyContinue).Trim()
        if ($tag) { return $tag }
    }

    if ($BinaryPath -and (Test-Path $BinaryPath)) {
        try {
            $vi = (Get-Item -LiteralPath $BinaryPath).VersionInfo
            if ($vi.ProductVersion) { return "file:$($vi.ProductVersion)" }
        }
        catch { }
    }

    return $null
}

function Save-ReleaseTag {
    param(
        [Parameter(Mandatory)][string]$MetaPath,
        [Parameter(Mandatory)][string]$Tag
    )
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    Set-Content -Path $MetaPath -Value $Tag -Encoding utf8 -NoNewline
}

function Get-LatestGitHubRelease {
    param([Parameter(Mandatory)][string]$Repo)
    Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{
        "User-Agent" = "Install-ADReviewTools.ps1"
    }
}

function Install-GitHubReleaseBinary {
    param(
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][string]$AssetPattern,
        [Parameter(Mandatory)][string]$BinaryName,
        [Parameter(Mandatory)][string]$DestinationPath,
        [Parameter(Mandatory)][string]$MetaPath,
        [switch]$ForceUpgrade
    )

    $existing = Test-ToolCommand -Name $BinaryName -ExtraPaths @($toolsDir)
    $release = Get-LatestGitHubRelease -Repo $Repo
    $installedTag = Get-InstalledReleaseTag -MetaPath $MetaPath -BinaryPath $DestinationPath

    if ($existing.Found) {
        if ($installedTag -eq $release.tag_name) {
            Write-Step "$BinaryName already at latest release ($($release.tag_name))"
            return
        }
        if (-not $ForceUpgrade) {
            if ($installedTag) {
                Write-WarnStep "$BinaryName present ($installedTag) but latest is $($release.tag_name). Re-run with -Upgrade to update."
            }
            else {
                Write-WarnStep "$BinaryName present but release tag unknown. Re-run with -Upgrade to refresh from $($release.tag_name)."
            }
            return
        }
        Write-Step "Upgrading $BinaryName to $($release.tag_name)"
    }
    else {
        Write-Step "Downloading $BinaryName from $Repo release $($release.tag_name)"
    }

    $asset = $release.assets | Where-Object { $_.name -match $AssetPattern } | Select-Object -First 1
    if (-not $asset) {
        throw "Could not find asset matching '$AssetPattern' in $($release.tag_name)."
    }

    New-Item -ItemType Directory -Path (Split-Path -Parent $DestinationPath) -Force | Out-Null
    $zipPath = Join-Path $env:TEMP "$BinaryName-$($release.tag_name).zip"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing

    $extractDir = Join-Path $env:TEMP "$BinaryName-extract"
    if (Test-Path $extractDir) { Remove-Item -Path $extractDir -Recurse -Force }
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    $binary = Get-ChildItem -Path $extractDir -Recurse -Filter $BinaryName | Select-Object -First 1
    if (-not $binary) {
        throw "$BinaryName not found inside $($asset.name)."
    }

    Copy-Item -Path $binary.FullName -Destination $DestinationPath -Force
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    Save-ReleaseTag -MetaPath $MetaPath -Tag $release.tag_name

    Write-Step "$BinaryName saved to $DestinationPath (release $($release.tag_name))"
}

function Install-SharpHoundBinary {
    param([switch]$ForceUpgrade)

    Install-GitHubReleaseBinary -Repo "SpecterOps/SharpHound" `
        -AssetPattern '(?i)SharpHound.*\.zip$' `
        -BinaryName "SharpHound.exe" `
        -DestinationPath $sharpHoundPath `
        -MetaPath $sharpHoundMetaPath `
        -ForceUpgrade:$ForceUpgrade
}

function Install-PingCastleBinary {
    param([switch]$ForceUpgrade)

    Install-GitHubReleaseBinary -Repo "vletoux/PingCastle" `
        -AssetPattern '(?i)^PingCastle_.*\.zip$' `
        -BinaryName "PingCastle.exe" `
        -DestinationPath $pingCastlePath `
        -MetaPath $pingCastleMetaPath `
        -ForceUpgrade:$ForceUpgrade
}

function Test-GraphModuleReady {
    $connect = Get-Command Connect-MgGraph -ErrorAction SilentlyContinue
    $request = Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue
    return ($connect -and $request)
}

function Install-MicrosoftGraphModule {
    if (Test-GraphModuleReady) {
        Write-Step "Microsoft.Graph already available (Connect-MgGraph, Invoke-MgGraphRequest)"
        return
    }

    if (-not (Get-Command Install-Module -ErrorAction SilentlyContinue)) {
        throw "Install-Module not available. Run PowerShell 5.1+ with PowerShellGet, or install the module manually."
    }

    Write-Step "Installing Microsoft.Graph (CurrentUser) for ADReview -IncludeEntra"
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
}

Write-Host "`nAD Review Tools - install / verify" -ForegroundColor Green
Write-Host "Tools directory: $toolsDir`n"

if (-not $CheckOnly) {
    if ($InstallSharpHound) { Install-SharpHoundBinary -ForceUpgrade:$Upgrade }
    if ($InstallPingCastle) { Install-PingCastleBinary -ForceUpgrade:$Upgrade }
    if ($InstallGraphModule) { Install-MicrosoftGraphModule }
    if ($AddToolsToUserPath) { Add-DirectoryToUserPath -Directory $toolsDir }
}

$latestSharpHound = $null
$latestPingCastle = $null
try { $latestSharpHound = Get-LatestGitHubRelease -Repo "SpecterOps/SharpHound" } catch { }
try { $latestPingCastle = Get-LatestGitHubRelease -Repo "vletoux/PingCastle" } catch { }

$extraPaths = @($toolsDir)
$toolChecks = @(
    @{ Label = "SharpHound.exe"; Name = "SharpHound.exe"; MetaPath = $sharpHoundMetaPath; BinaryPath = $sharpHoundPath; Latest = $latestSharpHound }
    @{ Label = "PingCastle.exe"; Name = "PingCastle.exe"; MetaPath = $pingCastleMetaPath; BinaryPath = $pingCastlePath; Latest = $latestPingCastle }
)

Write-Host ("{0,-18} {1,-8} {2}" -f "Tool", "Status", "Location / version") -ForegroundColor DarkGray
Write-Host ("-" * 80) -ForegroundColor DarkGray

foreach ($tool in $toolChecks) {
    $info = Test-ToolCommand -Name $tool.Name -ExtraPaths $extraPaths
    $installedTag = Get-InstalledReleaseTag -MetaPath $tool.MetaPath -BinaryPath $tool.BinaryPath
    $latestTag = if ($tool.Latest) { $tool.Latest.tag_name } else { $null }
    $needsUpgrade = $false

    if (-not $info.Found) {
        $status = "MISSING"
        $color = "Red"
        $detail = $info.Detail
    }
    elseif ($latestTag -and $installedTag -ne $latestTag) {
        $status = "UPDATE"
        $color = "Yellow"
        $needsUpgrade = $true
        if ($installedTag) { $detail = "installed $installedTag -> latest $latestTag" }
        else { $detail = "installed (unknown tag) -> latest $latestTag" }
    }
    else {
        $status = "OK"
        $color = "Green"
        $detail = if ($installedTag) { "release $installedTag" } else { $info.Detail }
    }

    Write-Host ("{0,-18} {1,-8} {2}" -f $tool.Label, $status, $detail) -ForegroundColor $color
    if ($info.Found -and -not $info.InPathHint) {
        Write-WarnStep "$($tool.Label) found outside PATH: $($info.Source)"
    }
}

$pkCmdlet = Get-Command Invoke-PKAssessment -ErrorAction SilentlyContinue
$pkStatus = if ($pkCmdlet) { "OK" } else { "MISSING" }
$pkColor = if ($pkCmdlet) { "Green" } else { "Yellow" }
Write-Host ("{0,-18} {1,-8} {2}" -f "Purple Knight", $pkStatus, $(if ($pkCmdlet) { $pkCmdlet.Source } else { "Manual install from Semperis" })) -ForegroundColor $pkColor

$graphReady = Test-GraphModuleReady
$graphStatus = if ($graphReady) { "OK" } else { "MISSING" }
$graphColor = if ($graphReady) { "Green" } else { "Yellow" }
Write-Host ("{0,-18} {1,-8} {2}" -f "Microsoft.Graph", $graphStatus, $(if ($graphReady) { "Connect-MgGraph ready" } else { "Optional: -IncludeEntra hybrid checks" })) -ForegroundColor $graphColor

Write-Host ""
if (-not (Test-ToolCommand "SharpHound.exe" -ExtraPaths $extraPaths).Found -or
    -not (Test-ToolCommand "PingCastle.exe" -ExtraPaths $extraPaths).Found) {
    Write-Host "Suggested install:" -ForegroundColor Yellow
    Write-Host "  .\Install-ADReviewTools.ps1 -InstallAll -AddToolsToUserPath`n" -ForegroundColor White
}
else {
    $sh = Get-InstalledReleaseTag -MetaPath $sharpHoundMetaPath -BinaryPath $sharpHoundPath
    $pc = Get-InstalledReleaseTag -MetaPath $pingCastleMetaPath -BinaryPath $pingCastlePath
    $shLatest = if ($latestSharpHound) { $latestSharpHound.tag_name } else { $null }
    $pcLatest = if ($latestPingCastle) { $latestPingCastle.tag_name } else { $null }
    if (($shLatest -and $sh -ne $shLatest) -or ($pcLatest -and $pc -ne $pcLatest)) {
        Write-Host "Update available:" -ForegroundColor Yellow
        Write-Host "  .\Install-ADReviewTools.ps1 -InstallAll -Upgrade`n" -ForegroundColor White
    }
}

if (-not $pkCmdlet) {
    Write-Host "Purple Knight: install from https://www.semperis.com/purple-knight/ (not redistributable via this script).`n" -ForegroundColor DarkGray
}

if (-not $graphReady) {
    Write-Host "Hybrid Entra (-IncludeEntra): .\Install-ADReviewTools.ps1 -InstallGraphModule" -ForegroundColor DarkGray
    Write-Host "  Then: Connect-MgGraph -TenantId <tenant.onmicrosoft.com> -Scopes Policy.Read.All,User.Read.All,RoleManagement.Read.Directory" -ForegroundColor DarkGray
    Write-Host "       Sign in as your normal account (not #EXT# UPN). Add -UseDeviceCode on Server.`n" -ForegroundColor DarkGray
}

Write-BloodHoundCeInstallHint

Write-Host "Run AD review with optional tool execution:" -ForegroundColor Cyan
Write-Host "  .\ADReviewv1.ps1 -RunSharpHound -RunPingCastle"
Write-Host "  .\ADReviewv1.ps1 -RunPurpleKnight   # when Invoke-PKAssessment is available"
Write-Host "  .\ADReviewv1.ps1 -IncludeEntra        # after Connect-MgGraph`n"
