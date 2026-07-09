<#
.SYNOPSIS
    Install and verify winPEAS for Windows build review on Windows.

.DESCRIPTION
    Checks PATH and .\tools for winPEAS (PEASS-ng). Default (no switches) compares the
    installed release tag to the latest GitHub release.

    Use -InstallAll to download winPEAS and PEASS parsers when missing. Use -Upgrade to update when newer or tag is unknown (skips if already at latest).
    Shared .\tools folder with AD/Azure installers.

.PARAMETER InstallAll
    Download winPEAS and PEASS parsers into .\tools when missing (skips if already present unless -Upgrade).

.PARAMETER Upgrade
    Download winPEAS when missing, tag is unknown, or a newer GitHub release is available. Skips re-download when already at latest (also with -InstallAll -Upgrade).

.PARAMETER AddToolsToUserPath
    Append .\tools to the user PATH permanently.

.PARAMETER CheckOnly
    Report only; do not install anything (default when no install switches are passed).

.EXAMPLE
    .\Install-WinBuildReviewTools.ps1

.EXAMPLE
    .\Install-WinBuildReviewTools.ps1 -InstallAll -AddToolsToUserPath

.EXAMPLE
    .\Install-WinBuildReviewTools.ps1 -Upgrade

.NOTES
    Version     : 1.1.0
    winPEAS is optional for WinBuildReview.ps1 -RunWinPeas.
    -InstallAll also installs PEASS output parsers (peas2json, json2html, json2pdf) under .\tools\parsers.
    Release tags stored in .\tools\winpeas.release and .\tools\parsers\parsers.release.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [switch]$InstallAll,
    [switch]$Upgrade,
    [switch]$AddToolsToUserPath,
    [switch]$CheckOnly
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
$winPeasName = if ([Environment]::Is64BitOperatingSystem) { "winPEASx64.exe" } else { "winPEASx86.exe" }
$winPeasPath = Join-Path $toolsDir $winPeasName
$winPeasMetaPath = Join-Path $toolsDir "winpeas.release"
$parsersDir = Join-Path $toolsDir "parsers"
$parsersMetaPath = Join-Path $parsersDir "parsers.release"
$ReleaseRepo = "peass-ng/PEASS-ng"
$ParserFileNames = @("peas2json.ps1", "peas2json.py", "json2html.ps1", "json2pdf.py")

$anyInstallSwitch = $InstallAll -or $Upgrade -or $AddToolsToUserPath
if ($CheckOnly -and $anyInstallSwitch) {
    # Plain usage error, not a bug - use Write-Host/exit instead of Write-Error so this doesn't
    # get routed through the trap below and printed as a scary "UNHANDLED ERROR" call stack.
    Write-Host "-CheckOnly cannot be combined with install switches (-InstallAll, -Upgrade, -AddToolsToUserPath)." -ForegroundColor Red
    Write-Host "Run with -CheckOnly alone to report status, or drop -CheckOnly to install." -ForegroundColor Yellow
    exit 1
}
if (-not $CheckOnly -and -not $anyInstallSwitch) {
    $CheckOnly = $true
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

function Get-LatestWinPeasRelease {
    Invoke-RestMethod -Uri "https://api.github.com/repos/$ReleaseRepo/releases/latest" -Headers @{
        "User-Agent" = "Install-WinBuildReviewTools.ps1"
    }
}

function Get-InstalledWinPeasReleaseTag {
    if (Test-Path $winPeasMetaPath) {
        $tag = (Get-Content -Path $winPeasMetaPath -Raw -ErrorAction SilentlyContinue).Trim()
        if ($tag) { return $tag }
    }

    if (Test-Path $winPeasPath) {
        try {
            $vi = (Get-Item -LiteralPath $winPeasPath).VersionInfo
            if ($vi.ProductVersion) { return "file:$($vi.ProductVersion)" }
        }
        catch { }
    }

    return $null
}

function Save-WinPeasReleaseTag {
    param([Parameter(Mandatory)][string]$Tag)
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    Set-Content -Path $winPeasMetaPath -Value $Tag -Encoding utf8 -NoNewline
}

function Get-WinPeasReleaseAsset {
    param(
        [Parameter(Mandatory)]$Release,
        [Parameter(Mandatory)][string]$BinaryName
    )

    $asset = $Release.assets | Where-Object { $_.name -eq $BinaryName } | Select-Object -First 1
    if (-not $asset) {
        $asset = $Release.assets | Where-Object { $_.name -match '(?i)^winPEAS.*\.exe$' } | Select-Object -First 1
    }
    return $asset
}

function Install-WinPeasBinary {
    param([switch]$ForceUpgrade)

    $existing = Test-ToolCommand -Name $winPeasName -ExtraPaths @($toolsDir)
    $latest = Get-LatestWinPeasRelease
    $installedTag = Get-InstalledWinPeasReleaseTag

    if ($existing.Found) {
        if ($installedTag -eq $latest.tag_name) {
            Write-Step "winPEAS already at latest release ($($latest.tag_name))"
            return
        }
        if (-not $ForceUpgrade) {
            if ($installedTag) {
                Write-WarnStep "winPEAS present ($installedTag) but latest is $($latest.tag_name). Re-run with -Upgrade to update."
            }
            else {
                Write-WarnStep "winPEAS present but release tag unknown. Re-run with -Upgrade to refresh from $($latest.tag_name)."
            }
            return
        }
        Write-Step "Upgrading winPEAS to $($latest.tag_name)"
    }
    else {
        Write-Step "Downloading $winPeasName from $ReleaseRepo release $($latest.tag_name)"
    }

    $asset = Get-WinPeasReleaseAsset -Release $latest -BinaryName $winPeasName
    if (-not $asset) {
        throw "Could not find $winPeasName in $($latest.tag_name)."
    }

    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    # Download to a staging file first (mirrors the SharpHound/PingCastle/AzureHound pattern) so
    # an interrupted download can't overwrite a previously-working winPEASx64.exe with a
    # truncated/corrupt binary while leaving the saved release tag pointing at the old (correct)
    # version - which would otherwise report "OK release vX" for a broken binary on disk.
    $stagingPath = "$winPeasPath.download"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $stagingPath -UseBasicParsing
    Move-Item -Path $stagingPath -Destination $winPeasPath -Force
    Save-WinPeasReleaseTag -Tag $latest.tag_name
    Write-Step "$($asset.name) saved to $winPeasPath (release $($latest.tag_name))"
}

function Get-PythonCommand {
    foreach ($name in @("python", "py", "python3")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        # Skip the Windows Store app-execution-alias stub - it's a no-op placeholder when no
        # real Python is installed and fails confusingly under pip/non-interactive invocation.
        if ($cmd -and $cmd.Source -notmatch '(?i)\\WindowsApps\\python(3)?\.exe$') {
            return $cmd
        }
    }
    $pythonCoreRoot = Join-Path $env:LOCALAPPDATA "Python"
    if (Test-Path $pythonCoreRoot) {
        $pythonExe = Get-ChildItem -Path $pythonCoreRoot -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($pythonExe) { return (Get-Command $pythonExe.FullName -ErrorAction SilentlyContinue) }
    }
    return $null
}

function Invoke-PythonSilently {
    param(
        [Parameter(Mandatory)]$PythonCommand,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        & $PythonCommand.Source @Arguments 1>$null 2>$null
        if ($null -ne $LASTEXITCODE) { return $LASTEXITCODE }
        return 0
    }
    finally {
        $ErrorActionPreference = $prevEap
    }
}

function Test-ReportLabInstalled {
    $python = Get-PythonCommand
    if (-not $python) { return $false }
    return (Invoke-PythonSilently $python -c "import reportlab") -eq 0
}

function Install-ReportLabForPdfParser {
    $python = Get-PythonCommand
    if (-not $python) {
        Write-WarnStep "Python not found; json2pdf.py needs Python + reportlab (peas2json/json2html still work)."
        return
    }
    if (Test-ReportLabInstalled) {
        Write-Step "Python package reportlab already available"
        return
    }
    Write-Step "Installing Python package reportlab (for json2pdf.py)"
    $pipExit = Invoke-PythonSilently $python -m pip install --upgrade reportlab --quiet
    if ($pipExit -ne 0 -or -not (Test-ReportLabInstalled)) {
        Write-WarnStep "reportlab install did not succeed; PDF parser may fail until: python -m pip install reportlab"
    }
    else {
        Write-Step "reportlab installed"
    }
}

function Get-InstalledParsersReleaseTag {
    if (Test-Path $parsersMetaPath) {
        $tag = (Get-Content -Path $parsersMetaPath -Raw -ErrorAction SilentlyContinue).Trim()
        if ($tag) { return $tag }
    }
    return $null
}

function Save-ParsersReleaseTag {
    param([Parameter(Mandatory)][string]$Tag)
    New-Item -ItemType Directory -Path $parsersDir -Force | Out-Null
    Set-Content -Path $parsersMetaPath -Value $Tag -Encoding utf8 -NoNewline
}

function Test-WinPeasParsersPresent {
    foreach ($name in $ParserFileNames) {
        if (-not (Test-Path (Join-Path $parsersDir $name))) { return $false }
    }
    return $true
}

function Test-PeassParserScriptParameterized {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) { return $false }

    foreach ($line in (Get-Content -LiteralPath $Path -TotalCount 30)) {
        if ($line -match '^\s*param\s*\(') { return $true }
        if ($line -match '^\s*#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
        return $false
    }

    return $false
}

function Test-PeassParserLogicPatched {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    $head = (Get-Content -LiteralPath $Path -TotalCount 3 -ErrorAction SilentlyContinue) -join "`n"
    if ($head -notmatch 'WinBuildReview peas2json fixes applied') { return $false }
    # The header comment alone isn't proof the patch actually succeeded - a regressed regex
    # could leave a marked-as-patched file that is still a syntax error and never self-heals
    # on subsequent runs. Verify the file actually parses before trusting the marker.
    $errors = $null
    $tokens = $null
    try {
        [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors) | Out-Null
    }
    catch { return $false }
    return (@($errors).Count -eq 0)
}

function Repair-PeassParserLogic {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) { return }
    if (Test-PeassParserLogicPatched -Path $Path) { return }

    $content = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    # NOTE: these regexes must consume the statement's trailing ")" (the closing paren of the
    # original .add(...)/.Add(...) call) as well as its "$title," prefix - matching only up to
    # the comma left a dangling unmatched ")" after the rewrite to "[...] = <hashtable>", which
    # is a PowerShell syntax error that broke every freshly-patched peas2json.ps1.
    $content = $content -replace '\$FINAL_JSON\.add\(\$title,\s*(@\{.*\})\)', '$FINAL_JSON[$title] = $1'
    $content = $content -replace "(?i)\`$global:C_MAIN_SECTION\.'sections'\.Add\(\`$title,\s*(@\{.*\})\)", '$global:C_MAIN_SECTION.''sections''[$title] = $1'
    $content = $content -replace "(?i)\`$global:C_2_SECTION\.'sections'\.add\(\`$title,\s*(@\{.*\})\)", '$global:C_2_SECTION.''sections''[$title] = $1'
    $content = $content -replace '\$global:C_SECTION\[''lines''\] \+= @\{"raw_text" = \$line; "colors" = get_colors \$line;"clean_text" = clean_title\(clean_colors \$line\)\}', '$global:C_SECTION[''lines''] += ,([ordered]@{ raw_text = $line; colors = (get_colors $line); clean_text = (clean_title(clean_colors $line)) })'

    if ($content -notmatch 'WinBuildReview peas2json fixes applied') {
        $content = "# WinBuildReview peas2json fixes applied`r`n" + $content
    }

    Set-Content -LiteralPath $Path -Value $content -Encoding utf8 -NoNewline
}

function Initialize-PeassParserScripts {
    $peas2Path = Join-Path $parsersDir "peas2json.ps1"
    $html2Path = Join-Path $parsersDir "json2html.ps1"
    $pyPath = Join-Path $parsersDir "peas2json.py"

    if (-not (Test-PeassParserScriptParameterized -Path $peas2Path)) {
        Set-PeassParserParameters -Path $peas2Path -Kind Peas2Json
    }
    if (-not (Test-PeassParserScriptParameterized -Path $html2Path)) {
        Set-PeassParserParameters -Path $html2Path -Kind Json2Html
    }

    Repair-PeassParserLogic -Path $peas2Path

    if (-not (Test-Path $pyPath)) {
        $tag = Get-InstalledParsersReleaseTag
        if (-not $tag) {
            try { $tag = (Get-LatestWinPeasRelease).tag_name } catch { $tag = 'master' }
        }
        Write-Step "Adding missing peas2json.py from $ReleaseRepo ($tag)"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/$ReleaseRepo/$tag/parsers/peas2json.py" -OutFile $pyPath -UseBasicParsing
    }
}

function Set-PeassParserParameters {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Peas2Json', 'Json2Html')]
        [string]$Kind
    )

    if (Test-PeassParserScriptParameterized -Path $Path) {
        return
    }

    $content = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    # Remove prior broken patch (param block appended at end of script)
    $content = $content -replace '(?s)\r?\nparam\s*\([\s\S]*?\r?\nmain\r?\s*$', ''
    # Remove upstream interactive tail
    $content = $content -replace '(?s)\r?\ntry \{[\s\S]*?\r?\nmain\r?\s*$', ''

    $header = switch ($Kind) {
        'Peas2Json' {
            @'
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][string]$JsonPath
)
$OUTPUT_PATH = $OutputPath
$JSON_PATH = $JsonPath

'@
        }
        'Json2Html' {
            @'
param(
    [Parameter(Mandatory = $true)][string]$JsonPath,
    [Parameter(Mandatory = $true)][string]$HtmlPath
)
$JSON_PATH = $JsonPath
$HTML_PATH = $HtmlPath

'@
        }
    }

    $lines = $content -split "\r?\n", -1
    $idx = 0
    while ($idx -lt $lines.Count) {
        $trimmed = $lines[$idx].Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) {
            $idx++
            continue
        }
        break
    }

    $commentBlock = if ($idx -gt 0) { ($lines[0..($idx - 1)] -join "`r`n") } else { '' }
    $body = if ($idx -lt $lines.Count) { ($lines[$idx..($lines.Count - 1)] -join "`r`n").TrimEnd() } else { '' }

    $newContent = $commentBlock
    if ($newContent) { $newContent += "`r`n" }
    $newContent += $header
    if ($body) { $newContent += $body + "`r`n" }
    $newContent += "main`r`n"

    Set-Content -LiteralPath $Path -Value $newContent -Encoding utf8 -NoNewline
}

function Install-WinPeasParsers {
    param([switch]$ForceUpgrade)

    $latest = Get-LatestWinPeasRelease
    $installedTag = Get-InstalledParsersReleaseTag
    $present = Test-WinPeasParsersPresent

    if ($present) {
        if ($installedTag -eq $latest.tag_name) {
            $peas2Path = Join-Path $parsersDir "peas2json.ps1"
            $html2Path = Join-Path $parsersDir "json2html.ps1"
            $needsRepair = (-not (Test-PeassParserScriptParameterized -Path $peas2Path)) `
                -or (-not (Test-PeassParserScriptParameterized -Path $html2Path)) `
                -or (-not (Test-PeassParserLogicPatched -Path $peas2Path)) `
                -or (-not (Test-Path (Join-Path $parsersDir "peas2json.py")))
            if ($needsRepair) {
                Write-Step "Repairing PEASS parser scripts"
                Initialize-PeassParserScripts
            }
            else {
                Write-Step "PEASS parsers already at latest release ($($latest.tag_name))"
            }
            Install-ReportLabForPdfParser
            return
        }
        if (-not $ForceUpgrade) {
            if ($installedTag) {
                Write-WarnStep "PEASS parsers present ($installedTag) but latest is $($latest.tag_name). Re-run with -Upgrade to update."
            }
            else {
                Write-WarnStep "PEASS parsers present but release tag unknown. Re-run with -Upgrade to refresh from $($latest.tag_name)."
            }
            return
        }
        Write-Step "Upgrading PEASS parsers to $($latest.tag_name)"
    }
    else {
        Write-Step "Downloading PEASS parsers from $ReleaseRepo release $($latest.tag_name)"
    }

    New-Item -ItemType Directory -Path $parsersDir -Force | Out-Null
    $rawBase = "https://raw.githubusercontent.com/$ReleaseRepo/$($latest.tag_name)/parsers"
    foreach ($fileName in $ParserFileNames) {
        $dest = Join-Path $parsersDir $fileName
        Invoke-WebRequest -Uri "$rawBase/$fileName" -OutFile $dest -UseBasicParsing
    }

    Set-PeassParserParameters -Path (Join-Path $parsersDir "peas2json.ps1") -Kind Peas2Json
    Set-PeassParserParameters -Path (Join-Path $parsersDir "json2html.ps1") -Kind Json2Html
    Repair-PeassParserLogic -Path (Join-Path $parsersDir "peas2json.ps1")
    Save-ParsersReleaseTag -Tag $latest.tag_name
    Write-Step "PEASS parsers saved to $parsersDir (release $($latest.tag_name))"
    Install-ReportLabForPdfParser
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

Write-Host "`nWindows Build Review Tools - winPEAS install / verify" -ForegroundColor Green
Write-Host "Tools directory: $toolsDir`n"

$latestRelease = $null
try {
    $latestRelease = Get-LatestWinPeasRelease
}
catch {
    Write-WarnStep "Could not query latest PEASS-ng release: $($_.Exception.Message)"
}

if (-not $CheckOnly) {
    if ($InstallAll) {
        Install-WinPeasBinary -ForceUpgrade:$Upgrade
        Install-WinPeasParsers -ForceUpgrade:$Upgrade
    }
    elseif ($Upgrade) {
        Install-WinPeasBinary -ForceUpgrade:$true
        Install-WinPeasParsers -ForceUpgrade:$true
    }
    if ($AddToolsToUserPath) { Add-DirectoryToUserPath -Directory $toolsDir }
}

$info = Test-ToolCommand -Name $winPeasName -ExtraPaths @($toolsDir)
$installedTag = Get-InstalledWinPeasReleaseTag
$latestTag = if ($latestRelease) { $latestRelease.tag_name } else { $null }
$needsUpgrade = $false

if (-not $info.Found) {
    $status = "MISSING"
    $color = "Yellow"
    $versionSummary = $info.Detail
}
elseif ($latestTag -and $installedTag -ne $latestTag) {
    $status = "UPDATE"
    $color = "Yellow"
    $needsUpgrade = $true
    if ($installedTag) { $versionSummary = "installed $installedTag -> latest $latestTag" }
    else { $versionSummary = "installed (unknown tag) -> latest $latestTag" }
}
else {
    $status = "OK"
    $color = "Green"
    $versionSummary = if ($installedTag) { "release $installedTag" } else { $info.Detail }
}

Write-Host ("{0,-18} {1,-8} {2}" -f "Tool", "Status", "Location / version") -ForegroundColor DarkGray
Write-Host ("-" * 80) -ForegroundColor DarkGray
Write-Host ("{0,-18} {1,-8} {2}" -f $winPeasName, $status, $versionSummary) -ForegroundColor $color
if ($info.Found -and -not $info.InPathHint) {
    Write-WarnStep "$winPeasName found outside PATH: $($info.Source)"
}

$parsersInstalledTag = Get-InstalledParsersReleaseTag
$parsersLatestTag = $latestTag
$parsersPresent = Test-WinPeasParsersPresent
$parsersNeedsUpgrade = $false

if (-not $parsersPresent) {
    $parserStatus = "MISSING"
    $parserColor = "Yellow"
    $parserSummary = "Not in .\tools\parsers"
}
elseif ($parsersLatestTag -and $parsersInstalledTag -ne $parsersLatestTag) {
    $parserStatus = "UPDATE"
    $parserColor = "Yellow"
    $parsersNeedsUpgrade = $true
    if ($parsersInstalledTag) { $parserSummary = "installed $parsersInstalledTag -> latest $parsersLatestTag" }
    else { $parserSummary = "installed (unknown tag) -> latest $parsersLatestTag" }
}
else {
    $parserStatus = "OK"
    $parserColor = "Green"
    $parserSummary = if ($parsersInstalledTag) { "release $parsersInstalledTag" } else { $parsersDir }
}

Write-Host ("{0,-18} {1,-8} {2}" -f "PEASS parsers", $parserStatus, $parserSummary) -ForegroundColor $parserColor

$reportLabOk = Test-ReportLabInstalled
if ($parsersPresent) {
    $rlStatus = if ($reportLabOk) { "OK" } else { "MISSING" }
    $rlColor = if ($reportLabOk) { "Green" } else { "Yellow" }
    $rlSummary = if ($reportLabOk) { "import reportlab" } else { "python -m pip install reportlab (for PDF)" }
    Write-Host ("{0,-18} {1,-8} {2}" -f "reportlab (PDF)", $rlStatus, $rlSummary) -ForegroundColor $rlColor
}

Write-Host ""
if (-not $info.Found -or -not $parsersPresent) {
    Write-Host "Install:" -ForegroundColor Yellow
    Write-Host "  .\Install-WinBuildReviewTools.ps1 -InstallAll -AddToolsToUserPath`n" -ForegroundColor White
}
elseif ($needsUpgrade -or $parsersNeedsUpgrade) {
    Write-Host "Update available:" -ForegroundColor Yellow
    Write-Host "  .\Install-WinBuildReviewTools.ps1 -Upgrade`n" -ForegroundColor White
}

Write-Host "Run build review with deep privesc enumeration:" -ForegroundColor Cyan
Write-Host "  .\WinBuildReview.ps1 -RunWinPeas    # winpeas-<host>-<timestamp>.* when parsers installed"
Write-Host "  .\WinBuildReview.ps1                    # full CIS + native privesc review`n"
