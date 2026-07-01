# CIS benchmark profiles for Windows Server 2012 through 2025.
# Control IDs are best-effort mappings to each benchmark revision (L1 MS where applicable).
# Authoritative CIS prose: download benchmark PDFs from CIS Workbench
# https://www.cisecurity.org/cis-benchmarks

$script:CisWorkbenchUrl = 'https://www.cisecurity.org/cis-benchmarks'

$script:OsProfileOrder = @('2012', '2012R2', '2016', '2019', '2022', '2025')

$script:CisBenchmarkProfiles = @{
    '2012' = @{
        Label        = 'CIS Microsoft Windows Server 2012 (non-R2) Benchmark v3.0.0 L1'
        Version      = 'v3.0.0'
        BuildNumbers = @(9200)
    }
    '2012R2' = @{
        Label        = 'CIS Microsoft Windows Server 2012 R2 Benchmark v3.0.0 L1'
        Version      = 'v3.0.0'
        BuildNumbers = @(9600)
    }
    '2016' = @{
        Label        = 'CIS Microsoft Windows Server 2016 Benchmark v4.0.0 L1 MS'
        Version      = 'v4.0.0'
        BuildNumbers = @(14393)
    }
    '2019' = @{
        Label        = 'CIS Microsoft Windows Server 2019 Benchmark v5.0.0 L1 MS'
        Version      = 'v5.0.0'
        BuildNumbers = @(17763)
    }
    '2022' = @{
        Label        = 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0 L1 MS'
        Version      = 'v5.0.0'
        BuildNumbers = @(20348)
    }
    '2025' = @{
        Label        = 'CIS Microsoft Windows Server 2025 Benchmark v2.0.0 L1 MS'
        Version      = 'v2.0.0'
        BuildNumbers = @(26100, 26200, 26300)
    }
}

# MinProfile = earliest server generation where CIS includes this control.
# Refs = CIS recommendation ID per profile (pentest-only checks omit Refs).
$script:CisCheckCatalog = @{
    'ps-logging' = @{
        MinProfile = '2012R2'
        Refs = @{
            '2012R2' = '18.4.14.1'
            '2016'   = '18.9.76.1.1'
            '2019'   = '18.9.76.1.1'
            '2022'   = '18.10.86.1'
            '2025'   = '18.10.86.1'
        }
        Note = 'CIS L2 control on most profiles.'
    }
    'smb-signing' = @{
        MinProfile = '2012'
        Refs = @{
            '2012'   = '2.3.9.2 / 2.3.9.3'
            '2012R2' = '2.3.9.2 / 2.3.9.3'
            '2016'   = '2.3.9.2 / 2.3.9.3'
            '2019'   = '2.3.9.2 / 2.3.9.3'
            '2022'   = '2.3.9.2 / 2.3.9.3'
            '2025'   = '2.3.9.2 / 2.3.9.3'
        }
    }
    'llmnr' = @{
        MinProfile = '2016'
        Refs = @{
            '2016' = '18.4.12.1'
            '2019' = '18.4.12.1'
            '2022' = '18.6.4.1'
            '2025' = '18.6.4.1'
        }
    }
    'netbios' = @{
        MinProfile = '2012R2'
        Refs = @{
            '2012R2' = '18.4.8.1'
            '2016'   = '18.4.8.1'
            '2019'   = '18.4.8.1'
            '2022'   = '18.6.4.2'
            '2025'   = '18.6.4.2'
        }
    }
    'firewall-domain' = @{
        MinProfile = '2012'
        Refs = @{
            '2012'   = '9.1.1'
            '2012R2' = '9.1.1'
            '2016'   = '9.1.1'
            '2019'   = '9.1.1'
            '2022'   = '9.1.1'
            '2025'   = '9.1.1'
        }
    }
    'audit-policy' = @{
        MinProfile = '2012'
        Refs = @{
            '2012'   = '17.1 / 17.5'
            '2012R2' = '17.x'
            '2016'   = '17.x'
            '2019'   = '17.x'
            '2022'   = '17.x'
            '2025'   = '17.x'
        }
    }
    'winverifytrust' = @{
        MinProfile = '2012'
        Refs = @{
            '2012'   = '18.4.5'
            '2012R2' = '18.4.5'
            '2016'   = '18.4.5'
            '2019'   = '18.4.5'
            '2022'   = '18.4.5'
            '2025'   = '18.4.5'
        }
    }
    'laps-policy' = @{
        MinProfile = '2012R2'
        Refs = @{
            '2012R2' = '18.4.6 (legacy LAPS)'
            '2016'   = '18.4.6 (legacy LAPS)'
            '2019'   = '18.4.6 (legacy LAPS)'
            '2022'   = '18.9.25.x (Windows LAPS)'
            '2025'   = '18.9.25.x (Windows LAPS)'
        }
    }
    'ntlm' = @{
        MinProfile = '2012'
        Refs = @{
            '2012'   = '2.3.11.x'
            '2012R2' = '2.3.11.x'
            '2016'   = '2.3.11.x'
            '2019'   = '2.3.11.x'
            '2022'   = '2.3.11.x'
            '2025'   = '2.3.11.x'
        }
    }
    'hardened-unc' = @{
        MinProfile = '2012'
        Refs = @{
            '2012'   = '18.7.x'
            '2012R2' = '18.7.x'
            '2016'   = '18.7.x'
            '2019'   = '18.7.x'
            '2022'   = '18.7.x'
            '2025'   = '18.7.x'
        }
    }
    'runasppl' = @{
        MinProfile = '2016'
        Refs = @{
            '2016' = '18.4.7 (RunAsPPL advisory)'
            '2019' = '18.4.7'
            '2022' = '18.4.7'
            '2025' = '18.4.7'
        }
        Note = 'RunAsPPL not applicable on Server 2012 / 2012 R2.'
    }
    'defender' = @{
        MinProfile = '2012R2'
        Refs = @{
            '2012R2' = '18.4.1.x'
            '2016'   = '18.4.1.x'
            '2019'   = '18.4.1.x'
            '2022'   = '18.4.1.x'
            '2025'   = '18.4.1.x'
        }
    }
    'password-policy' = @{
        MinProfile = '2012'
        Refs = @{
            '2012'   = '1.1.1 / 1.2.1'
            '2012R2' = '1.1.x / 1.2.x'
            '2016'   = '1.1.x / 1.2.x'
            '2019'   = '1.1.x / 1.2.x'
            '2022'   = '1.1.x / 1.2.x'
            '2025'   = '1.1.x / 1.2.x'
        }
    }
    'dc-spooler' = @{
        MinProfile = '2012R2'
        Refs = @{
            '2012R2' = '5.1'
            '2016'   = '5.1'
            '2019'   = '5.1'
            '2022'   = '5.1'
            '2025'   = '5.1'
        }
    }
    'dc-webclient' = @{
        MinProfile = '2012R2'
        Pentest  = $true
        Refs = @{ '2012R2' = 'Best practice'; '2016' = 'Best practice'; '2019' = 'Best practice'; '2022' = 'Best practice'; '2025' = 'Best practice' }
    }
    'dc-ldap' = @{
        MinProfile = '2012'
        Refs = @{
            '2012'   = '2.3.5.3'
            '2012R2' = '2.3.5.3'
            '2016'   = '2.3.5.3'
            '2019'   = '2.3.5.3 / 2.3.5.4'
            '2022'   = '2.3.5.3 / 2.3.5.4'
            '2025'   = '2.3.5.3 / 2.3.5.4'
        }
        Note = 'LDAP channel binding enforced from Server 2019 CIS onward.'
    }
    'dc-netlogon' = @{
        MinProfile = '2012'
        Refs = @{
            '2012'   = '2.3.5.2'
            '2012R2' = '2.3.5.2'
            '2016'   = '2.3.5.2'
            '2019'   = '2.3.5.2'
            '2022'   = '2.3.5.2'
            '2025'   = '2.3.5.2'
        }
    }
    'dc-hotfix' = @{ MinProfile = '2012'; Pentest = $true }
    'dc-uptime' = @{ MinProfile = '2012'; Pentest = $true }
    'ms-spooler' = @{
        MinProfile = '2012R2'
        Refs = @{
            '2012R2' = '5.2'
            '2016'   = '5.2'
            '2019'   = '5.2'
            '2022'   = '5.2'
            '2025'   = '5.2'
        }
    }
    'ms-wsus' = @{ MinProfile = '2012'; Pentest = $true }
    'device-guard' = @{
        MinProfile = '2016'
        Refs = @{
            '2016' = '18.5.x (Device Guard / VBS)'
            '2019' = '18.5.x'
            '2022' = '18.5.x'
            '2025' = '18.5.x'
        }
    }
    'wsl-presence' = @{ MinProfile = '2022'; Pentest = $true; Note = 'WSL on server is rare; review only.' }
    'applocker' = @{
        MinProfile = '2012R2'
        Refs = @{
            '2012R2' = '18.4.2'
            '2016'   = '18.4.2'
            '2019'   = '18.4.2'
            '2022'   = '18.4.2'
            '2025'   = '18.4.2'
        }
    }
    'rdp' = @{
        MinProfile = '2012'
        Refs = @{
            '2012'   = '18.4.9 / 18.4.10'
            '2012R2' = '18.4.9 / 18.4.10'
            '2016'   = '18.4.9 / 18.4.10'
            '2019'   = '18.4.9 / 18.4.10'
            '2022'   = '18.4.9 / 18.4.10'
            '2025'   = '18.4.9 / 18.4.10'
        }
    }
    'crash-dump' = @{
        MinProfile = '2012'
        Refs = @{
            '2012'   = '18.5.1'
            '2012R2' = '18.5.1'
            '2016'   = '18.5.1'
            '2019'   = '18.5.1'
            '2022'   = '18.5.1'
            '2025'   = '18.5.1'
        }
    }
    'cis-scan' = @{ MinProfile = '2012' }
}

function Get-OsProfileIndex {
    param([string]$OsProfileName)
    return [array]::IndexOf($script:OsProfileOrder, $OsProfileName)
}

function Test-OsProfileAtLeast {
    param([string]$MinimumProfile)
    if (-not $script:OsProfile -or $script:OsProfile -eq 'Unknown') { return $false }
    $cur = Get-OsProfileIndex $script:OsProfile
    $min = Get-OsProfileIndex $MinimumProfile
    if ($cur -lt 0 -or $min -lt 0) { return $false }
    return ($cur -ge $min)
}

function Get-WindowsServerProfile {
    param(
        [CimInstance]$OperatingSystem = $null,
        [string]$OverrideProfile = ''
    )

    if ($OverrideProfile) {
        if ($OverrideProfile -notin $script:OsProfileOrder) {
            throw "Invalid OsProfile '$OverrideProfile'. Valid: $($script:OsProfileOrder -join ', ')"
        }
        return $OverrideProfile
    }

    if (-not $OperatingSystem) {
        $OperatingSystem = Get-CimInstance Win32_OperatingSystem
    }

    $caption = [string]$OperatingSystem.Caption
    $build = [int]$OperatingSystem.BuildNumber
    $isServer = ($OperatingSystem.ProductType -in 2, 3) -or ($caption -match 'Server')

    if ($caption -match '2012 R2') { return '2012R2' }
    if ($caption -match '2012') { return '2012' }
    if ($caption -match '2016') { return '2016' }
    if ($caption -match '2019') { return '2019' }
    if ($caption -match '2022') { return '2022' }
    if ($caption -match '2025') { return '2025' }

    switch ($build) {
        9200 { return '2012' }
        9600 { return '2012R2' }
        14393 { return '2016' }
        17763 { return '2019' }
        20348 { return '2022' }
        default {
            if ($build -ge 26100) { return '2025' }
            if (-not $isServer) { return 'Unknown' }
            return 'Unknown'
        }
    }
}

function Initialize-WindowsBuildCisProfile {
    param([string]$OsProfileOverride = '')

    $os = Get-CimInstance Win32_OperatingSystem
    $script:OsCaption = [string]$os.Caption
    $script:OsBuild = [int]$os.BuildNumber
    $script:IsWindowsServer = ($os.ProductType -in 2, 3) -or ($script:OsCaption -match 'Server')
    $script:OsProfile = Get-WindowsServerProfile -OperatingSystem $os -OverrideProfile $OsProfileOverride

    if ($script:OsProfile -eq 'Unknown' -or -not $script:CisBenchmarkProfiles.ContainsKey($script:OsProfile)) {
        $script:CisBenchmarkLabel = 'CIS benchmark mapping unavailable for this OS'
        $script:CisBenchmarkVersion = 'N/A'
        return
    }

    $bench = $script:CisBenchmarkProfiles[$script:OsProfile]
    $script:CisBenchmarkLabel = $bench.Label
    $script:CisBenchmarkVersion = $bench.Version
}

function Get-CisCheckMeta {
    param([Parameter(Mandatory)][string]$CheckId)
    if ($script:CisCheckCatalog.ContainsKey($CheckId)) {
        return $script:CisCheckCatalog[$CheckId]
    }
    return $null
}

function Get-CisRefForCheck {
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [string]$Fallback = ''
    )

    if (-not $script:OsProfile -or $script:OsProfile -eq 'Unknown') {
        return $(if ($Fallback) { $Fallback } else { 'N/A' })
    }

    $meta = Get-CisCheckMeta -CheckId $CheckId
    if (-not $meta) {
        return $(if ($Fallback) { $Fallback } else { 'N/A (pentest)' })
    }

    if ($meta.Pentest -and -not $meta.Refs) {
        return 'N/A (pentest)'
    }

    if ($meta.Refs -and $meta.Refs.ContainsKey($script:OsProfile)) {
        return [string]$meta.Refs[$script:OsProfile]
    }

    if ($meta.MinProfile -and -not (Test-OsProfileAtLeast $meta.MinProfile)) {
        return 'N/A (not in CIS for this OS version)'
    }

    # Walk back to nearest defined ref for this profile generation
    $idx = Get-OsProfileIndex $script:OsProfile
    for ($i = $idx; $i -ge 0; $i--) {
        $p = $script:OsProfileOrder[$i]
        if ($meta.Refs -and $meta.Refs.ContainsKey($p)) {
            return [string]$meta.Refs[$p]
        }
    }

    return $(if ($Fallback) { $Fallback } else { 'N/A' })
}

function Test-CisCheckApplicable {
    param([Parameter(Mandatory)][string]$CheckId)

    if ($script:OsProfile -eq 'Unknown') {
        return @{ Applicable = $true; Reason = 'Unknown server generation - running with generic expectations.' }
    }

    $meta = Get-CisCheckMeta -CheckId $CheckId
    if (-not $meta -or -not $meta.MinProfile) {
        if (-not $script:IsWindowsServer) {
            return @{ Applicable = $true; Reason = 'Client OS - CIS mapping is indicative only.' }
        }
        return @{ Applicable = $true; Reason = '' }
    }

    if (-not (Test-OsProfileAtLeast $meta.MinProfile)) {
        $note = if ($meta.Note) { " $($meta.Note)" } else { '' }
        return @{
            Applicable = $false
            Reason     = "Not in CIS profile for $($script:OsProfile) (requires Server $($meta.MinProfile)+).$note"
        }
    }

    if (-not $script:IsWindowsServer) {
        return @{ Applicable = $true; Reason = 'Client OS - CIS mapping is indicative only.' }
    }

    return @{ Applicable = $true; Reason = '' }
}

function Get-CisScanGuidance {
    if (-not $script:CisBenchmarkLabel -or $script:CisBenchmarkVersion -eq 'N/A') {
        return @{
            CisRef  = 'N/A'
            Summary = 'Download the matching Windows Server CIS benchmark PDF from CIS Workbench and review all L1 controls for your OS generation.'
        }
    }

    $summary = "Manual pass against '$($script:CisBenchmarkLabel)' PDF from CIS Workbench: $($script:CisWorkbenchUrl). "
    $summary += 'WinBuildReview.ps1 automates a subset; complete remaining controls from the PDF checklist.'

    return @{
        CisRef  = $script:CisBenchmarkVersion
        Summary = $summary
    }
}

function Test-UseLegacyLapsPath {
    return (Test-OsProfileAtLeast '2012R2') -and -not (Test-OsProfileAtLeast '2022')
}

function Test-RequiresLdapChannelBinding {
    return (Test-OsProfileAtLeast '2019') -and (Test-IsDomainController)
}
