<#
.SYNOPSIS
    Install and verify Azure cloud review tooling on Windows.

.DESCRIPTION
    Checks PATH for az, prowler, roadrecon, and azurehound. Optionally installs:
      - Azure CLI via winget (-InstallAzCli)
      - Python packages prowler and roadrecon via pip (-InstallPythonTools)
      - AzureHound Windows binary into .\tools (-InstallAzureHound)

    Run without switches to report status only. Use -InstallAll for a typical lab setup.

.PARAMETER InstallAzCli
    Install Microsoft Azure CLI using winget when az is missing.

.PARAMETER InstallPythonTools
    pip install prowler and roadrecon (and ensure pip is available).

.PARAMETER InstallAzureHound
    Download azurehound.exe from SpecterOps/AzureHound latest release into .\tools.

.PARAMETER InstallAll
    Equivalent to -InstallAzCli -InstallPythonTools -InstallAzureHound.

.PARAMETER Upgrade
    Pass --upgrade to pip when installing Python packages.

.PARAMETER AddToolsToUserPath
    Append .\tools and the current Python Scripts directory to the user PATH permanently.

.PARAMETER CheckOnly
    Report only; do not install anything (default when no install switches are passed).

.EXAMPLE
    .\Install-AzureReviewTools.ps1

.EXAMPLE
    .\Install-AzureReviewTools.ps1 -InstallAll -AddToolsToUserPath

.EXAMPLE
    .\Install-AzureReviewTools.ps1 -InstallPythonTools -Upgrade

.NOTES
    Requires an internet connection for downloads. Azure CLI and AzureHound installs may
    need an elevated shell or winget user consent prompts.

    BloodHound CE GUI: Docker Desktop + bloodhound-cli — https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart
#>

[CmdletBinding()]
param(
    [switch]$InstallAzCli,
    [switch]$InstallPythonTools,
    [switch]$InstallAzureHound,
    [switch]$InstallAll,
    [switch]$Upgrade,
    [switch]$AddToolsToUserPath,
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$toolsDir = Join-Path $scriptDir "tools"
$azureHoundPath = Join-Path $toolsDir "azurehound.exe"

if ($InstallAll) {
    $InstallAzCli = $true
    $InstallPythonTools = $true
    $InstallAzureHound = $true
}

$anyInstallSwitch = $InstallAzCli -or $InstallPythonTools -or $InstallAzureHound -or $AddToolsToUserPath
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
            Version    = $null
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
                Version    = $null
                Detail     = $candidate
                InPathHint = $false
            }
        }
    }

    return [PSCustomObject]@{
        Name       = $Name
        Found      = $false
        Source     = $null
        Version    = $null
        Detail     = "Not found in PATH"
        InPathHint = $false
    }
}

function Get-PythonCommand {
    foreach ($name in @("python", "py", "python3")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd }
    }
    return $null
}

function Get-PythonScriptsDirectory {
    param([Parameter(Mandatory)]$PythonCommand)

    $pythonExe = $PythonCommand.Source
    if ($pythonExe -match '\\py\.exe$') {
        $versionOutput = & $pythonExe -3 -c "import sys; print(sys.executable)" 2>$null
        if ($versionOutput) { $pythonExe = $versionOutput.Trim() }
    }

    try {
        $scriptsDir = & $pythonExe -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null
        if ($scriptsDir) {
            $scriptsDir = $scriptsDir.Trim()
            if (Test-Path $scriptsDir) { return $scriptsDir }
        }
    }
    catch { }

    $scriptsDir = Join-Path (Split-Path -Parent $pythonExe) "Scripts"
    if (Test-Path $scriptsDir) { return $scriptsDir }

    try {
        $userBase = & $pythonExe -m site --user-base 2>$null
        if ($userBase) {
            $userScripts = Join-Path $userBase.Trim() "Scripts"
            if (Test-Path $userScripts) { return $userScripts }
        }
    }
    catch { }

    return $null
}

function Test-PythonPackageInstalled {
    param(
        [Parameter(Mandatory)]$PythonCommand,
        [Parameter(Mandatory)][string]$PackageName
    )

    & $PythonCommand.Source -m pip show $PackageName 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Invoke-PipInstall {
    param(
        [Parameter(Mandatory)]$PythonCommand,
        [Parameter(Mandatory)][string[]]$Packages,
        [switch]$UpgradePackages,
        [switch]$Quiet
    )

    $pipArgs = @("-m", "pip", "install")
    if ($UpgradePackages) { $pipArgs += "--upgrade" }
    if ($Quiet) { $pipArgs += "-q" }
    $pipArgs += $Packages

    Write-Step "Installing Python packages: $($Packages -join ', ')"
    & $PythonCommand.Source @pipArgs
    if ($LASTEXITCODE -ne 0) {
        throw "pip install failed for: $($Packages -join ', ')"
    }
}

function Install-PythonReviewTools {
    param(
        [Parameter(Mandatory)]$PythonCommand,
        [switch]$UpgradePackages
    )

    $packages = @("prowler", "roadrecon")
    $missing = @($packages | Where-Object { -not (Test-PythonPackageInstalled -PythonCommand $PythonCommand -PackageName $_) })

    if ($missing.Count -eq 0 -and -not $UpgradePackages) {
        Write-Step "Python packages already installed: $($packages -join ', ')"
        return
    }

    $toInstall = if ($UpgradePackages) { $packages } else { $missing }
    Invoke-PipInstall -PythonCommand $PythonCommand -Packages $toInstall -UpgradePackages:$UpgradePackages -Quiet:(-not $UpgradePackages)
}

function Install-AzureCli {
    if ((Test-ToolCommand "az").Found) {
        Write-Step "Azure CLI already available"
        return
    }

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw "winget not found. Install Azure CLI manually: https://learn.microsoft.com/cli/azure/install-azure-cli"
    }

    Write-Step "Installing Azure CLI via winget"
    & winget install --id Microsoft.AzureCLI -e --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) {
        throw "winget Azure CLI install failed (exit $LASTEXITCODE). Install manually from Microsoft docs."
    }

    Write-WarnStep "Open a new PowerShell window if 'az' is still not found (PATH refresh)."
}

function Install-AzureHoundBinary {
    if ((Test-ToolCommand "azurehound" -ExtraPaths @($toolsDir)).Found) {
        Write-Step "AzureHound already available"
        return
    }

    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    Write-Step "Downloading AzureHound from SpecterOps/AzureHound latest release"

    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/SpecterOps/AzureHound/releases/latest" -Headers @{
        "User-Agent" = "Install-AzureReviewTools.ps1"
    }

    $asset = $release.assets | Where-Object { $_.name -match 'windows.*amd64.*\.zip$' } | Select-Object -First 1
    if (-not $asset) {
        $asset = $release.assets | Where-Object { $_.name -match 'windows.*\.zip$' } | Select-Object -First 1
    }
    if (-not $asset) {
        throw "Could not find a Windows AzureHound zip in the latest GitHub release."
    }

    $zipPath = Join-Path $env:TEMP "azurehound-$($release.tag_name).zip"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing

    $extractDir = Join-Path $env:TEMP "azurehound-extract"
    if (Test-Path $extractDir) { Remove-Item -Path $extractDir -Recurse -Force }
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    $binary = Get-ChildItem -Path $extractDir -Recurse -Filter "azurehound.exe" | Select-Object -First 1
    if (-not $binary) {
        throw "azurehound.exe not found inside downloaded archive."
    }

    Copy-Item -Path $binary.FullName -Destination $azureHoundPath -Force
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $extractDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Step "AzureHound saved to $azureHoundPath"
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

function Get-ToolVersion {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$SourcePath = $null
    )

    try {
        switch ($Name) {
            "az" {
                $json = & az version --output json 2>$null | ConvertFrom-Json
                return "azure-cli $($json.'azure-cli')"
            }
            "prowler" {
                $out = & prowler -v 2>&1 | Out-String
                if ($out.Trim()) { return ($out.Trim() -split "`n" | Select-Object -First 1) }
            }
            "roadrecon" {
                $out = & roadrecon --version 2>&1 | Out-String
                if ($out.Trim()) { return ($out.Trim() -split "`n" | Select-Object -First 1) }
            }
            "azurehound" {
                $exe = if ($SourcePath) { $SourcePath } else { "azurehound" }
                $out = & $exe version 2>&1 | Out-String
                if ($out.Trim()) { return ($out.Trim() -split "`n" | Select-Object -First 1) }
            }
        }
    }
    catch { }

    return $null
}

function Format-Status {
    param([bool]$Found)
    if ($Found) { return "OK" }
    return "MISSING"
}

Write-Host "`nAzure Review Tools - install / verify" -ForegroundColor Green
Write-Host "Script directory: $scriptDir`n"

if (-not $CheckOnly) {
    if ($InstallAzCli) {
        Install-AzureCli
    }

    $pythonCmd = Get-PythonCommand
    if ($InstallPythonTools) {
        if (-not $pythonCmd) {
            throw "Python not found. Install Python 3.10+ from https://www.python.org/downloads/ (check 'Add python.exe to PATH')."
        }
        Install-PythonReviewTools -PythonCommand $pythonCmd -UpgradePackages:$Upgrade
    }

    if ($InstallAzureHound) {
        Install-AzureHoundBinary
    }

    if ($AddToolsToUserPath) {
        if (Test-Path $toolsDir) { Add-DirectoryToUserPath -Directory $toolsDir }
        $pythonCmd = Get-PythonCommand
        if ($pythonCmd) {
            $scriptsDir = Get-PythonScriptsDirectory -PythonCommand $pythonCmd
            if ($scriptsDir) {
                Add-DirectoryToUserPath -Directory $scriptsDir
            }
            elseif ($InstallPythonTools) {
                Write-WarnStep "Could not resolve Python Scripts directory for PATH. Run: python -m pip install --upgrade prowler roadrecon; then add the Scripts path pip reports to user PATH."
            }
        }
    }
}

$pythonScriptsDir = $null
$pythonCmd = Get-PythonCommand
if ($pythonCmd) {
    $pythonScriptsDir = Get-PythonScriptsDirectory -PythonCommand $pythonCmd
}

$extraPaths = @($toolsDir)
if ($pythonScriptsDir) { $extraPaths += $pythonScriptsDir }

$toolNames = @("az", "prowler", "roadrecon", "azurehound")
$results = foreach ($tool in $toolNames) {
    $extra = if ($tool -eq "azurehound") { @($toolsDir) } else { $extraPaths }
    $info = Test-ToolCommand -Name $tool -ExtraPaths $extra
    if ($info.Found) {
        $info.Version = Get-ToolVersion -Name $tool -SourcePath $info.Source
    }
    $info
}

Write-Host ("{0,-12} {1,-8} {2}" -f "Tool", "Status", "Location / version") -ForegroundColor DarkGray
Write-Host ("-" * 80) -ForegroundColor DarkGray

foreach ($item in $results) {
    $status = Format-Status $item.Found
    $color = if ($item.Found) { "Green" } else { "Red" }
    $location = if ($item.Version) { $item.Version } else { $item.Detail }
    Write-Host ("{0,-12} {1,-8} {2}" -f $item.Name, $status, $location) -ForegroundColor $color
    if ($item.Found -and -not $item.InPathHint) {
        Write-WarnStep "$($item.Name) found outside PATH: $($item.Source)"
    }
}

$missing = @($results | Where-Object { -not $_.Found })
if ($missing.Count -eq 0) {
    Write-Host "`nAll tools are available." -ForegroundColor Green
}
else {
    Write-Host "`nMissing tools: $($missing.Name -join ', ')" -ForegroundColor Yellow
    Write-Host "Suggested install command:" -ForegroundColor Yellow
    Write-Host "  .\Install-AzureReviewTools.ps1 -InstallAll -AddToolsToUserPath`n" -ForegroundColor White

    if ($missing.Name -contains "az") {
        Write-Host "  az        : winget install Microsoft.AzureCLI" -ForegroundColor DarkGray
    }
    if ($missing.Name -contains "prowler" -or $missing.Name -contains "roadrecon") {
        Write-Host "  prowler / roadrecon : pip install prowler roadrecon" -ForegroundColor DarkGray
        if ($pythonScriptsDir) {
            Write-Host "  add to PATH: $pythonScriptsDir" -ForegroundColor DarkGray
            Write-Host "  or re-run: .\Install-AzureReviewTools.ps1 -AddToolsToUserPath" -ForegroundColor DarkGray
        }
        else {
            $py = Get-PythonCommand
            if ($py) {
                $hint = & $py.Source -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null
                if ($hint) { Write-Host "  add to PATH: $($hint.Trim())" -ForegroundColor DarkGray }
            }
        }
    }
    if ($missing.Name -contains "azurehound") {
        Write-Host "  azurehound: .\Install-AzureReviewTools.ps1 -InstallAzureHound -AddToolsToUserPath" -ForegroundColor DarkGray
    }
}

Write-Host "`nAfter installing, log in and run the review:" -ForegroundColor Cyan
Write-Host "  az login"
Write-Host "  .\AzureCloudReviewv1.ps1 -RunProwler"
Write-Host "  roadrecon auth --device-code -c 04b07795-8ddb-461a-bbee-02f9e1bf7b46 -t <tenant.onmicrosoft.com>; roadrecon gather"
Write-Host "  `$rt = (Get-Content .roadtools_auth -Raw | ConvertFrom-Json).refreshToken"
Write-Host "  azurehound list -r `$rt -a 04b07795-8ddb-461a-bbee-02f9e1bf7b46 -t <tenant.onmicrosoft.com> -o azurehound.json"
Write-BloodHoundCeInstallHint
