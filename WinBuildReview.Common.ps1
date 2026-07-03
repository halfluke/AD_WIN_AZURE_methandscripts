# Windows Build Review - shared helpers (dot-sourced by WinBuildReview.ps1)

function Write-Log {
    param([string]$Message)
    Add-Content -Path $script:TxtLog -Value $Message -Encoding utf8
}

function Test-CommandAvailable {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}

function Get-CisAlignedStatus {
    param(
        [Parameter(Mandatory)][bool]$Compliant,
        [ValidateSet('REVIEW', 'FAIL')]
        [string]$NonCompliantStatus = 'REVIEW'
    )
    if ($Compliant) { return 'PASS' }
    if ($script:StrictCis) { return 'FAIL' }
    return $NonCompliantStatus
}

function Add-ReviewResult {
    param(
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet("PASS", "FAIL", "REVIEW", "SKIP", "ERROR", "MANUAL", "INFO")]
        [string]$Status,
        [string]$Summary = "",
        $Evidence = $null,
        [string]$Severity = "Medium",
        [string]$CisRef = "",
        [string]$Remediation = "",
        [switch]$SkipCatalogCisRef
    )

    if (-not $SkipCatalogCisRef -and $CheckId -and (Get-Command Get-CisRefForCheck -ErrorAction SilentlyContinue)) {
        $CisRef = Get-CisRefForCheck -CheckId $CheckId -Fallback $CisRef
    }

    $entry = [PSCustomObject]@{
        Timestamp     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Section       = $Section
        CheckId       = $CheckId
        Title         = $Title
        OsProfile     = $script:OsProfile
        CisBenchmark  = $script:CisBenchmarkLabel
        CisRef        = $CisRef
        Status        = $Status
        Severity      = $Severity
        Summary       = $Summary
        Evidence      = if ($Evidence) { ($Evidence | Out-String).Trim() } else { "" }
        Remediation   = $Remediation
    }
    $script:Results.Add($entry)

    $color = switch ($Status) {
        "PASS"   { "Green" }
        "FAIL"   { "Red" }
        "REVIEW" { "Yellow" }
        "SKIP"   { "DarkGray" }
        "ERROR"  { "Red" }
        "MANUAL" { "Cyan" }
        default  { "White" }
    }
    Write-Host ('[{0}] {1} - {2}' -f $Status, $Title, $Summary) -ForegroundColor $color

    $logLines = @(
        "",
        ("=" * 80),
        ('[{0}] {1} - {2}' -f $Status, $Section, $Title),
        "CheckId : $CheckId | OS: $($script:OsProfile) | CIS: $CisRef | Benchmark: $($script:CisBenchmarkLabel) | Severity: $Severity",
        "Summary : $Summary"
    )
    if ($Remediation) { $logLines += "Remediation: $Remediation" }
    $logLines += "Evidence:"
    $logLines += if ($Evidence) { ($Evidence | Out-String).Trim() } else { "(none)" }
    Write-Log ($logLines -join [Environment]::NewLine)
}

function Invoke-Check {
    param(
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][scriptblock]$Test,
        [string]$Severity = "Medium",
        [string]$CisRef = "",
        $SkipIf = $null,
        [string]$MinOsProfile = ""
    )
    try {
        if ($SkipIf -and (& $SkipIf)) {
            Add-ReviewResult -Section $Section -CheckId $CheckId -Title $Title -Status "SKIP" `
                -Summary "Not applicable for this host role or environment." -Severity $Severity -CisRef $CisRef
            return
        }

        if (-not $CisRef -and (Get-Command Get-CisRefForCheck -ErrorAction SilentlyContinue)) {
            $CisRef = Get-CisRefForCheck -CheckId $CheckId
        }

        if ($MinOsProfile -and (Get-Command Test-OsProfileAtLeast -ErrorAction SilentlyContinue)) {
            if (-not (Test-OsProfileAtLeast $MinOsProfile)) {
                Add-ReviewResult -Section $Section -CheckId $CheckId -Title $Title -Status "SKIP" `
                    -Summary "Requires Windows Server $MinOsProfile or later (detected: $($script:OsProfile))." `
                    -Severity $Severity -CisRef $CisRef
                return
            }
        }
        elseif (Get-Command Test-CisCheckApplicable -ErrorAction SilentlyContinue) {
            $applic = Test-CisCheckApplicable -CheckId $CheckId
            if (-not $applic.Applicable) {
                Add-ReviewResult -Section $Section -CheckId $CheckId -Title $Title -Status "SKIP" `
                    -Summary $applic.Reason -Severity $Severity -CisRef $CisRef
                return
            }
        }

        & $Test
    }
    catch {
        Add-ReviewResult -Section $Section -CheckId $CheckId -Title $Title -Status "ERROR" `
            -Summary $_.Exception.Message -Severity $Severity -CisRef $CisRef
    }
}

function Get-WindowsBuildRole {
    $cs = Get-CimInstance Win32_ComputerSystem
    switch ([int]$cs.DomainRole) {
        4 { return "Domain Controller" }
        5 { return "Domain Controller" }
        3 { return "Member Server" }
        default { return "Standalone" }
    }
}

function Test-IsDomainController {
    return (Get-WindowsBuildRole) -eq "Domain Controller"
}

function Test-IsMemberServer {
    return (Get-WindowsBuildRole) -eq "Member Server"
}

function Invoke-RegistryCheck {
    param(
        [string]$Path,
        [string]$Name,
        $Expected,
        [switch]$AllowMissing
    )
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if (-not $item) {
        return @{ Present = $false; Value = $null; Match = [bool]$AllowMissing }
    }
    $val = $item.$Name
    $match = if ($Expected -is [scriptblock]) { & $Expected $val } else { $val -eq $Expected }
    return @{ Present = $true; Value = $val; Match = $match }
}

function Get-ObjectCount {
    param($Object)
    if ($null -eq $Object) { return 0 }
    if ($Object -is [array]) { return $Object.Count }
    return 1
}

function Get-ServiceBinaryPath {
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    if ($PathName -match '^"([^"]+)"') { return $Matches[1] }
    # Lazily match up to (and including) the first ".exe" so paths with spaces in an
    # unquoted directory name (e.g. "C:\Program Files\App\svc.exe -k netsvcs") resolve
    # to the true binary path rather than just the first whitespace-delimited token.
    $exeMatch = [regex]::Match($PathName, '(?i)^(.*?\.exe)')
    if ($exeMatch.Success) { return $exeMatch.Groups[1].Value }
    return ($PathName -split '\s', 2)[0]
}

function Test-UnquotedServicePath {
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName) -or $PathName -match '^"') { return $false }
    $bin = Get-ServiceBinaryPath $PathName
    if (-not $bin) { return $false }
    return ($bin -match '\s')
}
