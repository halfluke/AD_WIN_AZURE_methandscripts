# AD Review - shared helpers (dot-sourced by ADReviewv1.ps1)

$script:BloodHoundCeQuickstartUrl = "https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart"
$script:BloodHoundCliReleasesUrl = "https://github.com/SpecterOps/bloodhound-cli/releases/latest"
$script:BloodHoundCeUiUrl = "http://localhost:8080/ui/login"
# Legacy name used in remediation columns — points at official CE install guide (not a single .exe download).
$script:BloodHoundCeDownloadUrl = $script:BloodHoundCeQuickstartUrl

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
        [string]$Remediation = ""
    )

    $entry = [PSCustomObject]@{
        Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Section     = $Section
        CheckId     = $CheckId
        Title       = $Title
        Status      = $Status
        Severity    = $Severity
        Summary     = $Summary
        Evidence    = if ($Evidence) { ($Evidence | Out-String).Trim() } else { "" }
        Remediation = $Remediation
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
        "CheckId : $CheckId | Severity: $Severity",
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
        $SkipIf = $null
    )
    try {
        if ($SkipIf -and (& $SkipIf)) {
            Add-ReviewResult -Section $Section -CheckId $CheckId -Title $Title -Status "SKIP" `
                -Summary "Precondition not met for this check." -Severity $Severity
            return
        }
        & $Test
    }
    catch {
        Add-ReviewResult -Section $Section -CheckId $CheckId -Title $Title -Status "ERROR" `
            -Summary $_.Exception.Message -Severity $Severity
    }
}

function Invoke-EntraCheck {
    param(
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Title,
        [string]$Severity = "Medium",
        [Parameter(Mandatory)][bool]$GraphModuleReady,
        [Parameter(Mandatory)][bool]$GraphConnected,
        [Parameter(Mandatory)][string]$GraphRemediation,
        [Parameter(Mandatory)][scriptblock]$Test
    )

    if (-not $GraphModuleReady) {
        Add-ReviewResult -Section $Section -CheckId $CheckId -Title $Title -Status "MANUAL" `
            -Summary "Microsoft Graph PowerShell SDK not available." -Severity $Severity `
            -Remediation $GraphRemediation
        return
    }
    if (-not $GraphConnected) {
        Add-ReviewResult -Section $Section -CheckId $CheckId -Title $Title -Status "MANUAL" `
            -Summary "Connect-MgGraph failed or was cancelled." -Severity $Severity `
            -Remediation $GraphRemediation
        return
    }
    try {
        & $Test
    }
    catch {
        Add-ReviewResult -Section $Section -CheckId $CheckId -Title $Title -Status "ERROR" `
            -Summary $_.Exception.Message -Severity $Severity
    }
}

function Initialize-ADReviewSession {
    param(
        [string]$Domain,
        [string]$Server
    )

    if (-not (Test-CommandAvailable "Get-ADDomain")) {
        throw "ActiveDirectory module not available. Install RSAT or run from a domain-joined admin host."
    }

    $params = @{}
    if ($Domain) { $params.DomainName = $Domain }
    if ($Server) { $params.Server = $Server }

    $script:ADDomain   = Get-ADDomain @params
    $script:ADForest   = Get-ADForest @params
    $script:DomainDns = $script:ADDomain.DNSRoot
    $script:DomainDn   = $script:ADDomain.DistinguishedName

    if ($Server) {
        $script:ReviewServer = $Server
    }
    else {
        $script:ReviewServer = ($script:ADDomain.PDCEmulator).Split('.')[0]
    }

    Write-Log "Domain  : $($script:ADDomain.DNSRoot)"
    Write-Log "Forest  : $($script:ADForest.Name)"
    Write-Log "DC used : $($script:ReviewServer)"
    Write-Log "Domain functional level: $($script:ADDomain.DomainMode)"
    Write-Log "Forest functional level: $($script:ADForest.ForestMode)"
    Write-Log ""
}

function Test-RunningOnDomainController {
    try {
        $role = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).DomainRole
        return $role -ge 4
    }
    catch {
        return $false
    }
}

function Test-ADDomainModeAtLeast {
    param([Parameter(Mandatory)][string]$MinimumMode)

    $ranks = @{
        'Windows2000Domain'  = 0
        'Windows2003Domain'  = 1
        'Windows2008Domain'  = 2
        'Windows2008R2Domain' = 3
        'Windows2012Domain'  = 4
        'Windows2012R2Domain' = 5
        'Windows2016Domain'  = 6
        'Windows2019Domain'  = 7
        'Windows2022Domain'  = 8
        'Windows2025Domain'  = 9
    }

    $current = $ranks[[string]$script:ADDomain.DomainMode]
    $minimum = $ranks[$MinimumMode]
    if ($null -eq $current -or $null -eq $minimum) { return $false }
    return ($current -ge $minimum)
}

function Search-ADObjectsByAttribute {
    param([Parameter(Mandatory)][string]$AttributeName)

    try {
        return @(Get-ADObject -Filter "$AttributeName -like '*'" -Properties $AttributeName -ErrorAction Stop)
    }
    catch {
        if ($_.Exception.Message -match 'invalid|not exist|unknown|not recognized') {
            return @()
        }
        throw
    }
}

function Get-DirectoryServiceConfig {
    $root = Get-ADRootDSE
    $cfg = $root.configurationNamingContext
    return Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$cfg" -Properties dsHeuristics, tombstoneLifetime
}

function Invoke-GraphGet {
    param([Parameter(Mandatory)][string]$Uri)
    if (-not (Test-CommandAvailable "Invoke-MgGraphRequest")) {
        return $null
    }
    try {
        return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
    }
    catch {
        return $null
    }
}

$script:ADReviewEntraGraphScopes = @(
    'Policy.Read.All'
    'User.Read.All'
    'RoleManagement.Read.Directory'
)

$script:ADReviewEntraGraphConnectHint = "Connect-MgGraph -TenantId <tenant.onmicrosoft.com> -Scopes Policy.Read.All,User.Read.All,RoleManagement.Read.Directory -UseDeviceCode (sign in as your normal MSA/work account, not the #EXT# UPN)"

function Connect-ADReviewEntraGraph {
    param([string]$TenantId = "")

    if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
        if (Get-MgContext) { return $true }
    }
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        return $false
    }

    $scopes = $script:ADReviewEntraGraphScopes
    $connectParams = @{
        Scopes    = $scopes
        NoWelcome = $true
        ErrorAction = 'Stop'
    }
    if ($TenantId) { $connectParams.TenantId = $TenantId }

    $productType = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType
    # ProductType 1 = workstation; 2/3 = domain controller / server
    $preferDeviceCode = ($productType -ne 1)

    try {
        if ($preferDeviceCode) {
            Connect-MgGraph @connectParams -UseDeviceCode | Out-Null
            return $true
        }

        try {
            Connect-MgGraph @connectParams | Out-Null
            return $true
        }
        catch {
            Connect-MgGraph @connectParams -UseDeviceCode | Out-Null
            return $true
        }
    }
    catch {
        return $false
    }
}

function Resolve-SharpHoundCollectionZip {
    param(
        [Parameter(Mandatory)][string]$OutputDirectory,
        [string]$ExpectedBaseName = "",
        [datetime]$NotBefore
    )

    if (-not (Test-Path $OutputDirectory)) { return $null }

    $candidates = @(Get-ChildItem -Path $OutputDirectory -Filter *.zip -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $NotBefore })

    if ($ExpectedBaseName) {
        $named = @($candidates | Where-Object { $_.Name -like "*$ExpectedBaseName*" } |
            Sort-Object LastWriteTime -Descending)
        if ($named.Count -gt 0) { return $named[0].FullName }
    }

    $bloodhound = @($candidates | Where-Object { $_.Name -match '(?i)sharphound|bloodhound' } |
        Sort-Object LastWriteTime -Descending)
    if ($bloodhound.Count -gt 0) { return $bloodhound[0].FullName }

    if ($candidates.Count -gt 0) {
        return ($candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
    }

    return $null
}

function New-CheckId {
    param([string]$Text)
    $slug = ($Text -replace '[^a-zA-Z0-9]+', '-').Trim('-').ToLower()
    if ($slug.Length -gt 48) { $slug = $slug.Substring(0, 48) }
    return $slug
}

# Well-known accounts excluded from specific heuristics (not engagement findings).
$script:InactiveUserExcludeSam = @('krbtgt', 'Guest')

function Test-IsKrbtgtAccount {
    param([Parameter(Mandatory)][string]$SamAccountName)
    return ($SamAccountName -eq 'krbtgt')
}

function Test-IsBuiltInDomainAdministrator {
    param($User)
    if (-not $User) { return $false }
    if ($User.SamAccountName -eq 'Administrator') { return $true }
    if ($User.objectSid -and ($User.objectSid.Value -match '-500$')) { return $true }
    return $false
}

function Initialize-ADReviewToolPaths {
    param([Parameter(Mandatory)][string]$ScriptDirectory)
    $script:AdReviewToolsDir = Join-Path $ScriptDirectory "tools"
}

function Resolve-ADReviewTool {
    param([Parameter(Mandatory)][string]$ToolName)

    $cmd = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    if ($script:AdReviewToolsDir) {
        $candidate = Join-Path $script:AdReviewToolsDir $ToolName
        if (Test-Path $candidate) { return $candidate }
    }

    return $null
}

function Test-ADReviewToolAvailable {
    param([Parameter(Mandatory)][string]$ToolName)
    return [bool](Resolve-ADReviewTool -ToolName $ToolName)
}
