<#
.SYNOPSIS
    Windows Build Review v2.0 - host OS hardening audit (member server and DC).

.DESCRIPTION
    Passive build review aligned with Draft_Windows-Build-Review-Methodology_FINAL.xlsx.
    Auto-detects Windows Server generation (2012 / 2012 R2 / 2016 / 2019 / 2022 / 2025)
    and maps each check to the matching CIS benchmark control ID.

.PARAMETER OutputPath
    Directory for TXT, CSV, and HTML reports.

.PARAMETER OsProfile
    Override auto-detected server profile (2012, 2012R2, 2016, 2019, 2022, 2025).
    Useful for dry-run / documentation against a target generation.

.PARAMETER CisBaselineOnly
    Run CIS host baseline and role-specific (DC/member server) checks only.
    Skips pentest/hygiene and inventory rows that are always REVIEW (reduces noise on test runs).

.PARAMETER StrictCis
    Promote ambiguous CIS baseline gaps from REVIEW to FAIL (e.g. LLMNR/LAPS/RunAsPPL not configured).
    Does not skip pentest/hygiene checks — combine with -CisBaselineOnly for a shorter lab run.

.PARAMETER RunWinPeas
    Run winPEAS when available in PATH or .\tools; writes timestamped files under -OutputPath (see -WinPeasProfile).
    When PEASS parsers are installed (Install-WinBuildReviewTools.ps1 -InstallAll), also writes matching winpeas-<host>-<timestamp>.json, .html, and .pdf.

.PARAMETER WinPeasProfile
    **Focused** (default): privesc-oriented modules only; skips eventsinfo and file crawls.
    **Full**: adds network, browser, cloud checks; still skips eventsinfo and filesinfo.

.PARAMETER SkipExternalTools
    Skip the winPEAS automation row (native deep privesc checks still run on full review).

.EXAMPLE
    .\WinBuildReview.ps1

.EXAMPLE
    .\WinBuildReview.ps1 -CisBaselineOnly

.EXAMPLE
    .\WinBuildReview.ps1 -RunWinPeas

.EXAMPLE
    .\WinBuildReview.ps1 -RunWinPeas -WinPeasProfile Full

.EXAMPLE
    .\WinBuildReview.ps1 -OutputPath "C:\Reviews\Build" -OsProfile 2012R2

.NOTES
    Version     : 2.0.6
    Methodology : Draft_Windows-Build-Review-Methodology_FINAL.xlsx
    CIS profiles: WinBuildReview.CisProfiles.ps1
    Requires    : Administrator recommended for full coverage
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [ValidateSet('', '2012', '2012R2', '2016', '2019', '2022', '2025')]
    [string]$OsProfile = "",
    [switch]$CisBaselineOnly,
    [switch]$StrictCis,
    [switch]$RunWinPeas,
    [ValidateSet('Focused', 'Full')]
    [string]$WinPeasProfile = 'Focused',
    [switch]$SkipExternalTools
)

$ErrorActionPreference = "Stop"
$script:ErrorActionPreference = "Continue"

$scriptVersion = "2.0.6"
$startTime       = Get-Date
$timestamp       = $startTime.ToString("yyyyMMdd-HHmmss")
$scriptPath      = $MyInvocation.MyCommand.Path
$scriptDir       = Split-Path -Parent $scriptPath
if (-not $OutputPath) { $OutputPath = $scriptDir }
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$hostname = $env:COMPUTERNAME
$domain   = $env:USERDOMAIN
$txtLog   = Join-Path $OutputPath "BuildReview-$hostname-$timestamp.txt"
$csvLog   = Join-Path $OutputPath "BuildReview-$hostname-$timestamp.csv"
$htmlLog  = Join-Path $OutputPath "BuildReview-$hostname-$timestamp.html"

$script:Results = [System.Collections.Generic.List[object]]::new()
$script:TxtLog  = $txtLog

. (Join-Path $scriptDir "WinBuildReview.Common.ps1")
. (Join-Path $scriptDir "WinBuildReview.CisProfiles.ps1")
. (Join-Path $scriptDir "WinBuildReview.PrivEscDeep.ps1")

Initialize-WinBuildReviewToolPaths -ScriptDirectory $scriptDir

# Param $OsProfile and $script:OsProfile share script scope; Initialize sets the latter on auto-detect.
$osProfileOverrideRequested = [bool]$OsProfile

Initialize-WindowsBuildCisProfile -OsProfileOverride $OsProfile

$script:StrictCis = [bool]$StrictCis
$modeNote = @()
if ($CisBaselineOnly) { $modeNote += "CisBaselineOnly" }
if ($StrictCis) { $modeNote += "StrictCis" }
$modeText = if ($modeNote.Count) { " | Mode: $($modeNote -join ', ')" } else { "" }

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
$hostRole = Get-WindowsBuildRole
$elevatedText = if ($elevated) { "Yes" } else { "No (some checks limited)" }
$profileNote = if ($osProfileOverrideRequested) { " (override)" } else { "" }

@"
Windows Build Review v$scriptVersion - $timestamp
Methodology: Draft_Windows-Build-Review-Methodology_FINAL (multi-version CIS)
Host: $hostname | Domain: $domain | Role: $hostRole | Elevated: $elevatedText
OS: $($script:OsCaption) | Profile: $($script:OsProfile)$profileNote | Build: $($script:OsBuild)
CIS Benchmark: $($script:CisBenchmarkLabel)
Scope: Host/DC OS build - NOT AD object review (see ADReviewv1.ps1)
"@ | Set-Content $txtLog -Encoding utf8

Write-Host "`nWindows Build Review v$scriptVersion" -ForegroundColor Cyan
Write-Host "Host: $hostname | Role: $hostRole | OS Profile: $($script:OsProfile)$profileNote" -ForegroundColor Cyan
Write-Host "CIS: $($script:CisBenchmarkLabel)$modeText" -ForegroundColor Cyan
if ($StrictCis -and -not $CisBaselineOnly) {
    Write-Host "Note: -StrictCis promotes CIS baseline REVIEW to FAIL only. Add -CisBaselineOnly to skip hygiene/inventory REVIEW rows." -ForegroundColor DarkYellow
}
Write-Host "Output: $OutputPath`n" -ForegroundColor Cyan

$secCis  = "CIS HOST BASELINE"
$secDc   = "DOMAIN CONTROLLER BUILD"
$secMs   = "MEMBER SERVER BUILD"
$secPriv = "PRIVILEGE ESCALATION"
$secPers = "PERSISTENCE"
$secCred = "CREDENTIAL ACCESS"
$secLat  = "LATERAL MOVEMENT"
$secDisc = "DISCOVERY"
$secSys  = "SYSTEM AND DOMAIN"

# --- CIS Host Baseline ---

Invoke-Check -Section $secCis -CheckId "ps-logging" -CisRef "18.10.86.1" `
    -Title "PowerShell Script Block Logging" -Severity "Medium" -Test {
    $v = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
    $enabled = $v -and [int]$v.EnableScriptBlockLogging -eq 1
    Add-ReviewResult -Section $secCis -CheckId "ps-logging" -Title "PowerShell Script Block Logging" `
        -CisRef "18.10.86.1" -Status $(if ($enabled) { "PASS" } else { "FAIL" }) `
        -Summary "EnableScriptBlockLogging=$(if ($v) { $v.EnableScriptBlockLogging } else { 'not set' })" `
        -Evidence $v -Remediation "Enable script block logging via GPO (CIS L2)."
}

Invoke-Check -Section $secCis -CheckId "smb-signing" -CisRef "2.3.9.2/2.3.9.3" `
    -Title "SMB Signing Status" -Severity "High" -Test {
    if (-not (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue)) {
        Add-ReviewResult -Section $secCis -CheckId "smb-signing" -Title "SMB Signing Status" `
            -Status "MANUAL" -Summary "Get-SmbServerConfiguration unavailable on this OS." -CisRef "2.3.9.2"
        return
    }
    $smb = Get-SmbServerConfiguration
    $ok = $smb.EnableSecuritySignature -and $smb.RequireSecuritySignature -and (-not $smb.EnableSMB1Protocol)
    Add-ReviewResult -Section $secCis -CheckId "smb-signing" -Title "SMB Signing Status" `
        -CisRef "2.3.9.2" -Status $(if ($ok) { "PASS" } else { "FAIL" }) `
        -Summary "Sign=$($smb.EnableSecuritySignature); Require=$($smb.RequireSecuritySignature); SMB1=$($smb.EnableSMB1Protocol)" `
        -Evidence $smb
}

Invoke-Check -Section $secCis -CheckId "llmnr" -CisRef "18.6.x" `
    -Title "LLMNR Disabled" -Severity "Medium" -Test {
    $v = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
        -Name EnableMulticast -ErrorAction SilentlyContinue
    $disabled = $v -and [int]$v.EnableMulticast -eq 0
    Add-ReviewResult -Section $secCis -CheckId "llmnr" -Title "LLMNR Disabled" `
        -CisRef "18.6.x" -Status $(Get-CisAlignedStatus -Compliant $disabled) `
        -Summary "EnableMulticast=$(if ($v) { $v.EnableMulticast } else { 'not set' })" -Evidence $v
}

Invoke-Check -Section $secCis -CheckId "netbios" -CisRef "18.6.4.2" `
    -Title "NetBIOS Policy" -Severity "Medium" -Test {
    $v = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
        -Name EnableNetbios -ErrorAction SilentlyContinue
    Add-ReviewResult -Section $secCis -CheckId "netbios" -Title "NetBIOS Policy" `
        -CisRef "18.6.4.2" -Status $(Get-CisAlignedStatus -Compliant ($v -and [int]$v.EnableNetbios -eq 2)) `
        -Summary "EnableNetbios=$(if ($v) { $v.EnableNetbios } else { 'not set' })" -Evidence $v
}

Invoke-Check -Section $secCis -CheckId "firewall-domain" -CisRef "9.1.x" `
    -Title "Windows Firewall Domain Profile" -Severity "Medium" -Test {
    $p = Get-NetFirewallProfile -Profile Domain -ErrorAction SilentlyContinue
    $ok = $p -and $p.Enabled -and ($p.DefaultInboundAction -eq 'Block')
    Add-ReviewResult -Section $secCis -CheckId "firewall-domain" -Title "Windows Firewall Domain Profile" `
        -CisRef "9.1.x" -Status $(Get-CisAlignedStatus -Compliant $ok) `
        -Summary "Enabled=$($p.Enabled); Inbound=$($p.DefaultInboundAction)" -Evidence $p
}

Invoke-Check -Section $secCis -CheckId "audit-policy" -CisRef "17.x" `
    -Title "Audit Policy Coverage" -Severity "Medium" -Test {
    $logon = auditpol /get /subcategory:"Logon" 2>&1 | Out-String
    $priv  = auditpol /get /subcategory:"Privilege Use" 2>&1 | Out-String
    $proc  = auditpol /get /subcategory:"Process Creation" 2>&1 | Out-String
    $review = ($logon -notmatch "Success and Failure") -or ($priv -notmatch "Success and Failure") -or ($proc -notmatch "Success")
    Add-ReviewResult -Section $secCis -CheckId "audit-policy" -Title "Audit Policy Coverage" `
        -CisRef "17.x" -Status $(Get-CisAlignedStatus -Compliant (-not $review)) `
        -Summary "Verify Logon, Privilege Use, and Process Creation auditing." `
        -Evidence @{ Logon = $logon.Trim(); PrivilegeUse = $priv.Trim(); ProcessCreation = $proc.Trim() }
}

Invoke-Check -Section $secCis -CheckId "winverifytrust" -CisRef "18.4.5" `
    -Title "WinVerifyTrust Mitigation (CVE-2013-3900)" -Severity "Medium" -Test {
    $v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config' `
        -Name EnableCertPaddingCheck -ErrorAction SilentlyContinue
    $ok = $v -and [int]$v.EnableCertPaddingCheck -eq 1
    Add-ReviewResult -Section $secCis -CheckId "winverifytrust" `
        -Title "WinVerifyTrust Mitigation (CVE-2013-3900)" `
        -CisRef "18.4.5" -Status $(if ($ok) { "PASS" } else { "FAIL" }) `
        -Summary "EnableCertPaddingCheck=$(if ($v) { $v.EnableCertPaddingCheck } else { 'not set' })" -Evidence $v
}

Invoke-Check -Section $secCis -CheckId "laps-policy" `
    -Title "Windows LAPS Policy Present" -Severity "Medium" -Test {
    if (Test-UseLegacyLapsPath) {
        $legacy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue
        $present = [bool]$legacy
        $summary = if ($present) { "Legacy LAPS (AdmPwd) policy registry present" } else { "No legacy LAPS policy key found" }
        Add-ReviewResult -Section $secCis -CheckId "laps-policy" -Title "Windows LAPS Policy Present" `
            -Status $(Get-CisAlignedStatus -Compliant $present) -Summary $summary -Evidence $legacy
    }
    else {
        $v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -ErrorAction SilentlyContinue
        Add-ReviewResult -Section $secCis -CheckId "laps-policy" -Title "Windows LAPS Policy Present" `
            -Status $(Get-CisAlignedStatus -Compliant ([bool]$v)) `
            -Summary $(if ($v) { "Windows LAPS policy registry present" } else { "No Windows LAPS policy key found" }) -Evidence $v
    }
}

Invoke-Check -Section $secCis -CheckId "ntlm" -CisRef "2.3.11.x" `
    -Title "NTLM Restrictions" -Severity "Medium" -Test {
    $msv = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
        -Name RestrictSendingNTLMTraffic -ErrorAction SilentlyContinue
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue
    # LmCompatibilityLevel=5 ("Send NTLMv2 response only. Refuse LM & NTLM") is the CIS/DISA
    # required value; levels 3-4 still let clients negotiate legacy NTLM/LM in some paths.
    $ok = ($msv -and [int]$msv.RestrictSendingNTLMTraffic -ge 1) -and ($lsa -and [int]$lsa.LmCompatibilityLevel -ge 5)
    Add-ReviewResult -Section $secCis -CheckId "ntlm" -Title "NTLM Restrictions" `
        -CisRef "2.3.11.x" -Status $(Get-CisAlignedStatus -Compliant $ok) `
        -Summary "RestrictSendingNTLMTraffic=$($msv.RestrictSendingNTLMTraffic); LmCompatibilityLevel=$($lsa.LmCompatibilityLevel)" `
        -Evidence @{ MSV = $msv; Lsa = $lsa }
}

Invoke-Check -Section $secCis -CheckId "hardened-unc" -CisRef "18.7.x" `
    -Title "Hardened UNC Paths" -Severity "Medium" -Test {
    $v = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -ErrorAction SilentlyContinue
    $uncConfigured = $false
    if ($v) {
        $props = $v.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
        foreach ($prop in $props) {
            if ($prop.Name -match '\\\\.*\\(NETLOGON|SYSVOL)' -and [string]$prop.Value -match 'RequireMutualAuthentication=1') {
                $uncConfigured = $true
                break
            }
        }
    }
    Add-ReviewResult -Section $secCis -CheckId "hardened-unc" -Title "Hardened UNC Paths" `
        -CisRef "18.7.x" -Status $(Get-CisAlignedStatus -Compliant $uncConfigured) `
        -Summary "Validate NETLOGON/SYSVOL hardened path values in GPO." -Evidence $v
}

Invoke-Check -Section $secCis -CheckId "runasppl" -CisRef "N/A" `
    -Title "LSASS Protection Status (RunAsPPL)" -Severity "High" -Test {
    $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue
    $ok = $v -and [int]$v.RunAsPPL -eq 1
    Add-ReviewResult -Section $secCis -CheckId "runasppl" -Title "LSASS Protection Status (RunAsPPL)" `
        -Status $(Get-CisAlignedStatus -Compliant $ok) `
        -Summary "RunAsPPL=$(if ($v) { $v.RunAsPPL } else { 'not set' })" -Evidence $v
}

Invoke-Check -Section $secCis -CheckId "defender" -CisRef "N/A" `
    -Title "Defender Status" -Severity "High" -Test {
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        Add-ReviewResult -Section $secCis -CheckId "defender" -Title "Defender Status" `
            -Status "MANUAL" -Summary "Defender cmdlets unavailable - third-party AV may be in use."
        return
    }
    $d = Get-MpComputerStatus
    $ok = $d.AMServiceEnabled -and $d.AntivirusEnabled -and $d.RealTimeProtectionEnabled
    Add-ReviewResult -Section $secCis -CheckId "defender" -Title "Defender Status" `
        -Status $(if ($ok) { "PASS" } else { "FAIL" }) `
        -Summary "RealTime=$($d.RealTimeProtectionEnabled); AV=$($d.AntivirusEnabled)" -Evidence $d
}

Invoke-Check -Section $secCis -CheckId "password-policy" -CisRef "1.1.x/1.2.x" `
    -Title "Password and Lockout Policy" -Severity "Medium" -Test {
    $net = net accounts 2>&1 | Out-String
    Add-ReviewResult -Section $secCis -CheckId "password-policy" -Title "Password and Lockout Policy" `
        -CisRef "1.1.x" -Status "REVIEW" `
        -Summary "Review net accounts output; CIS expects min length 14 on servers via GPO." `
        -Evidence $net.Trim()
}

# --- DC-only ---

Invoke-Check -Section $secDc -CheckId "dc-spooler" -CisRef "5.1" `
    -Title "Print Spooler Disabled on DC" -Severity "High" `
    -SkipIf { -not (Test-IsDomainController) } -Test {
    $svc = Get-Service Spooler
    $ok = $svc.StartType -eq 'Disabled' -and $svc.Status -ne 'Running'
    Add-ReviewResult -Section $secDc -CheckId "dc-spooler" -Title "Print Spooler Disabled on DC" `
        -CisRef "5.1" -Status $(if ($ok) { "PASS" } else { "FAIL" }) `
        -Summary "Spooler Status=$($svc.Status); StartType=$($svc.StartType)" -Evidence $svc
}

Invoke-Check -Section $secDc -CheckId "dc-webclient" -CisRef "N/A" `
    -Title "WebClient Service Disabled on DC" -Severity "Medium" `
    -SkipIf { -not (Test-IsDomainController) } -Test {
    $svc = Get-Service WebClient -ErrorAction SilentlyContinue
    if (-not $svc) {
        Add-ReviewResult -Section $secDc -CheckId "dc-webclient" -Title "WebClient Service Disabled on DC" `
            -Status "PASS" -Summary "WebClient service not present."
        return
    }
    $ok = $svc.StartType -eq 'Disabled'
    Add-ReviewResult -Section $secDc -CheckId "dc-webclient" -Title "WebClient Service Disabled on DC" `
        -Status $(if ($ok) { "PASS" } else { "FAIL" }) `
        -Summary "WebClient StartType=$($svc.StartType)" -Evidence $svc
}

Invoke-Check -Section $secDc -CheckId "dc-ldap" `
    -Title "LDAP Signing and Channel Binding" -Severity "High" `
    -SkipIf { -not (Test-IsDomainController) } -Test {
    $ntds = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
        -Name LDAPServerIntegrity, LdapEnforceChannelBinding -ErrorAction SilentlyContinue
    if (Test-RequiresLdapChannelBinding) {
        $ok = ($ntds.LDAPServerIntegrity -eq 2) -and ($ntds.LdapEnforceChannelBinding -in 1, 2)
        $expect = "LDAPServerIntegrity=2; ChannelBinding=1|2"
    }
    else {
        $ok = ($ntds.LDAPServerIntegrity -eq 2)
        $expect = "LDAPServerIntegrity=2 (channel binding not required on $($script:OsProfile))"
    }
    Add-ReviewResult -Section $secDc -CheckId "dc-ldap" -Title "LDAP Signing and Channel Binding" `
        -Status $(if ($ok) { "PASS" } else { "FAIL" }) `
        -Summary "$expect | Actual: Integrity=$($ntds.LDAPServerIntegrity); CB=$($ntds.LdapEnforceChannelBinding)" `
        -Evidence $ntds
}

Invoke-Check -Section $secDc -CheckId "dc-netlogon" -CisRef "2.3.5.2" `
    -Title "Netlogon Secure Channel" -Severity "High" `
    -SkipIf { -not (Test-IsDomainController) } -Test {
    $p = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
        -Name RequireSignOrSeal -ErrorAction SilentlyContinue
    $ok = $p -and [int]$p.RequireSignOrSeal -eq 1
    Add-ReviewResult -Section $secDc -CheckId "dc-netlogon" -Title "Netlogon Secure Channel" `
        -CisRef "2.3.5.2" -Status $(if ($ok) { "PASS" } else { "FAIL" }) `
        -Summary "RequireSignOrSeal=$($p.RequireSignOrSeal)" -Evidence $p
}

Invoke-Check -Section $secDc -CheckId "dc-hotfix" -CisRef "N/A" `
    -Title "Patch Posture (Hotfixes)" -Severity "Medium" `
    -SkipIf { -not (Test-IsDomainController) } -Test {
    $hf = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, InstalledOn
    Add-ReviewResult -Section $secDc -CheckId "dc-hotfix" -Title "Patch Posture (Hotfixes)" `
        -Status "REVIEW" -Summary "Review recent cumulative updates against patch baseline." -Evidence $hf
}

Invoke-Check -Section $secDc -CheckId "dc-uptime" -CisRef "N/A" `
    -Title "DC Uptime / Pending Reboot" -Severity "Low" `
    -SkipIf { -not (Test-IsDomainController) } -Test {
    $os = Get-CimInstance Win32_OperatingSystem
    $days = ((Get-Date) - $os.LastBootUpTime).TotalDays
    $reboot = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $status = if ($reboot -or $days -gt 180) { "REVIEW" } else { "PASS" }
    Add-ReviewResult -Section $secDc -CheckId "dc-uptime" -Title "DC Uptime / Pending Reboot" `
        -Status $status -Summary "UptimeDays=$([math]::Round($days,1)); RebootPending=$reboot" -Evidence $os
}

# --- Member server ---

Invoke-Check -Section $secMs -CheckId "ms-spooler" -CisRef "5.2" `
    -Title "Print Spooler Disabled (Member Server)" -Severity "Medium" `
    -SkipIf { -not (Test-IsMemberServer) } -Test {
    $svc = Get-Service Spooler -ErrorAction SilentlyContinue
    if (-not $svc) {
        Add-ReviewResult -Section $secMs -CheckId "ms-spooler" -Title "Print Spooler Disabled (Member Server)" `
            -Status "SKIP" -Summary "Spooler service not found."
        return
    }
    $ok = $svc.StartType -eq 'Disabled'
    Add-ReviewResult -Section $secMs -CheckId "ms-spooler" -Title "Print Spooler Disabled (Member Server)" `
        -CisRef "5.2" -Status $(if ($ok) { "PASS" } else { "REVIEW" }) `
        -Summary "StartType=$($svc.StartType) (disabled unless print server)" -Evidence $svc
}

Invoke-Check -Section $secMs -CheckId "ms-wsus" -CisRef "N/A" `
    -Title "WSUS / Update Source Configuration" -Severity "Medium" `
    -SkipIf { -not (Test-IsMemberServer) } -Test {
    $wu = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
    $au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
    Add-ReviewResult -Section $secMs -CheckId "ms-wsus" -Title "WSUS / Update Source Configuration" `
        -Status "REVIEW" -Summary "Validate WU/WSUS uses HTTPS and trusted update source." `
        -Evidence @{ WindowsUpdate = $wu; AU = $au }
}

if (-not $CisBaselineOnly) {
# --- Pentest / hygiene (REVIEW-oriented) ---

Invoke-Check -Section $secPriv -CheckId "whoami-priv" -Title "PrivEsc - Token Privileges" -Severity "Medium" -Test {
    $o = whoami /priv 2>&1 | Out-String
    Add-ReviewResult -Section $secPriv -CheckId "whoami-priv" -Title "PrivEsc - Token Privileges" `
        -Status "REVIEW" -Summary "Review SeDebug/SeImpersonate/SeBackup." -Evidence $o.Trim()
}

Invoke-Check -Section $secPriv -CheckId "whoami-groups" -Title "PrivEsc - Group Memberships" -Severity "Medium" -Test {
    $o = whoami /groups 2>&1 | Out-String
    Add-ReviewResult -Section $secPriv -CheckId "whoami-groups" -Title "PrivEsc - Group Memberships" `
        -Status "REVIEW" -Summary "Review privileged group membership for assessment account." -Evidence $o.Trim()
}

Invoke-Check -Section $secPriv -CheckId "unquoted-services" -Title "PrivEsc - Services (Unquoted Paths)" -Severity "High" -Test {
    $hits = Get-CimInstance Win32_Service | Where-Object {
        Test-UnquotedServicePath $_.PathName
    } | Select-Object Name, PathName, StartName
    $count = Get-ObjectCount $hits
    Add-ReviewResult -Section $secPriv -CheckId "unquoted-services" -Title "PrivEsc - Services (Unquoted Paths)" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count service(s) with unquoted binary paths containing spaces." -Evidence $hits
}

Invoke-Check -Section $secPriv -CheckId "programfiles-acl" -Title "PrivEsc - ACLs (Program Files)" -Severity "Medium" -Test {
    $risky = (Get-Acl 'C:\Program Files').Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.IdentityReference -match '(^|\\)(Everyone|Users|Authenticated Users)$' -and
        $_.FileSystemRights -match 'Write|Modify|FullControl'
    }
    $count = Get-ObjectCount $risky
    Add-ReviewResult -Section $secPriv -CheckId "programfiles-acl" -Title "PrivEsc - ACLs (Program Files)" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count risky ACE(s) on C:\Program Files." -Evidence $risky
}

Invoke-Check -Section $secPriv -CheckId "modifiable-service-keys" -Title "Modifiable Registry Keys - Services" -Severity "High" -Test {
    $hits = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $acl = Get-Acl $_.PsPath -ErrorAction Stop
            $risky = $acl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                $_.IdentityReference -match '(^|\\)(Everyone|Users|Authenticated Users)$' -and
                $_.RegistryRights -match 'SetValue|FullControl|WriteKey'
            }
            if ($risky) { [PSCustomObject]@{ Key = $_.PSChildName; Risky = $risky } }
        }
        catch { }
    } | Select-Object -First 25
    $count = Get-ObjectCount $hits
    Add-ReviewResult -Section $secPriv -CheckId "modifiable-service-keys" -Title "Modifiable Registry Keys - Services" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count service registry key(s) modifiable by low-priv principals." -Evidence $hits
}

Invoke-Check -Section $secPriv -CheckId "privesc-hotfixes" -Title "PrivEsc - Hotfixes" -Severity "Medium" -Test {
    $hf = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, InstalledOn, Description
    Add-ReviewResult -Section $secPriv -CheckId "privesc-hotfixes" -Title "PrivEsc - Hotfixes" `
        -Status "REVIEW" -Summary "Correlate recent KBs with in-scope CVEs." -Evidence $hf
}

Invoke-Check -Section $secPriv -CheckId "always-install-elevated" -Title "PrivEsc - AlwaysInstallElevated" -Severity "Critical" -Test {
    $msi = Test-AlwaysInstallElevatedEnabled
    Add-ReviewResult -Section $secPriv -CheckId "always-install-elevated" -Title "PrivEsc - AlwaysInstallElevated" `
        -Status $(if ($msi.Enabled) { "FAIL" } else { "PASS" }) `
        -Summary "AlwaysInstallElevated HKCU=$($msi.HKCU) HKLM=$($msi.HKLM)" -Evidence $msi `
        -Remediation "Remove AlwaysInstallElevated=1 from HKCU/HKLM ...\Policies\Microsoft\Windows\Installer."
}

Invoke-Check -Section $secPriv -CheckId "token-impersonation" -Title "PrivEsc - Token Impersonation Privileges" -Severity "High" -Test {
    $enabled = @(Get-EnabledWhoamiPrivileges)
    $critical = @('SeImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege')
    $risky = @('SeDebugPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege')
    $critHit = @($enabled | Where-Object { $_ -in $critical })
    $riskHit = @($enabled | Where-Object { $_ -in $risky })
    $status = if ($critHit.Count -gt 0) { "FAIL" } elseif ($riskHit.Count -gt 0) { "REVIEW" } else { "PASS" }
    Add-ReviewResult -Section $secPriv -CheckId "token-impersonation" -Title "PrivEsc - Token Impersonation Privileges" `
        -Status $status `
        -Summary "Enabled token privs for current context: critical=$($critHit -join ', '); other-risk=$($riskHit -join ', ')" `
        -Evidence $enabled `
        -Remediation "Review service accounts and group memberships granting SeImpersonate / SeAssignPrimaryToken / SeDebug."
}

Invoke-Check -Section $secPriv -CheckId "service-binary-acl" -Title "PrivEsc - Writable Service Binaries" -Severity "High" -Test {
    $hits = @(Get-WeakServiceBinaryHits -MaxHits 25)
    $count = $hits.Count
    Add-ReviewResult -Section $secPriv -CheckId "service-binary-acl" -Title "PrivEsc - Writable Service Binaries" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count running service binary path(s) writable by low-priv principals (sampled)." -Evidence $hits
}

Invoke-Check -Section $secPriv -CheckId "service-dacl" -Title "PrivEsc - Service DACL Permissions" -Severity "High" -Test {
    $hits = @(Get-WeakServiceDaclHits -MaxHits 20)
    $count = $hits.Count
    Add-ReviewResult -Section $secPriv -CheckId "service-dacl" -Title "PrivEsc - Service DACL Permissions" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count privileged service(s) with low-priv modify/start rights in sc sdshow (sampled)." -Evidence $hits `
        -Remediation "Review sc.exe sdshow output; restrict service DACLs and change service account if needed."
}

Invoke-Check -Section $secPriv -CheckId "path-dll-hijack" -Title "PrivEsc - Writable PATH Entries (DLL Hijack)" -Severity "High" -Test {
    $hits = @(Get-WritablePathEntries -MaxHits 20)
    $count = $hits.Count
    Add-ReviewResult -Section $secPriv -CheckId "path-dll-hijack" -Title "PrivEsc - Writable PATH Entries (DLL Hijack)" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count PATH director(ies) writable by low-priv principals." -Evidence $hits `
        -Remediation "Remove world-writable directories from Machine/User PATH; prefer paths ahead of system directories."
}

Invoke-Check -Section $secPers -CheckId "autoruns" -Title "Persistence - Registry Autoruns" -Severity "Medium" -Test {
    $hkcu = reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /s 2>&1 | Out-String
    $hklm = reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run /s 2>&1 | Out-String
    Add-ReviewResult -Section $secPers -CheckId "autoruns" -Title "Persistence - Registry Autoruns" `
        -Status "REVIEW" -Summary "Review Run keys for suspicious paths." `
        -Evidence @{ HKCU = $hkcu.Trim(); HKLM = $hklm.Trim() }
}

Invoke-Check -Section $secPers -CheckId "startup-folder" -Title "Persistence - Startup Folder" -Severity "Medium" -Test {
    $paths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    $items = foreach ($p in $paths) {
        Get-ChildItem $p -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime
    }
    Add-ReviewResult -Section $secPers -CheckId "startup-folder" -Title "Persistence - Startup Folder" `
        -Status "REVIEW" -Summary "$(Get-ObjectCount $items) startup folder item(s)." -Evidence $items
}

Invoke-Check -Section $secPers -CheckId "scheduled-tasks" -Title "Scheduled Tasks" -Severity "High" -Test {
    $o = schtasks /query /fo LIST /v 2>&1 | Out-String
    Add-ReviewResult -Section $secPers -CheckId "scheduled-tasks" -Title "Scheduled Tasks" `
        -Status "REVIEW" -Summary "Review SYSTEM/user tasks launching scripts." `
        -Evidence ($o.Substring(0, [Math]::Min(4000, $o.Length)))
}

Invoke-Check -Section $secCred -CheckId "gpp-cpassword" -Title "Credential Access - GPP Credential Exposure" -Severity "Critical" -Test {
    $hits = Get-ChildItem "$env:ProgramData\Microsoft\Group Policy" -Recurse -Include Groups.xml `
        -ErrorAction SilentlyContinue | Select-String -Pattern 'cpassword' | Select-Object -First 10
    $count = Get-ObjectCount $hits
    Add-ReviewResult -Section $secCred -CheckId "gpp-cpassword" `
        -Title "Credential Access - GPP Credential Exposure" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count Groups.xml line(s) containing cpassword." -Evidence $hits
}

Invoke-Check -Section $secCred -CheckId "cloud-cli" -Title "Credential Access - Cloud CLI Config" -Severity "Low" -Test {
    $ev = [ordered]@{
        AWS   = Test-Path "$env:USERPROFILE\.aws\credentials"
        Azure = Test-Path "$env:USERPROFILE\.azure\azureProfile.json"
        GCP   = Test-Path "$env:USERPROFILE\AppData\Roaming\gcloud\credentials.db"
    }
    Add-ReviewResult -Section $secCred -CheckId "cloud-cli" -Title "Credential Access - Cloud CLI Config" `
        -Status "REVIEW" -Summary "CLI credential files present: $($ev.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key })" `
        -Evidence $ev
}

Invoke-Check -Section $secCred -CheckId "config-secrets" -Title "Credential Access - Config File Secrets" -Severity "Medium" -Test {
    $roots = @($env:ProgramData, $env:USERPROFILE) | Where-Object { $_ -and (Test-Path $_) }
    $hits = foreach ($root in $roots) {
        Get-ChildItem $root -Recurse -Include *.config, *.xml, *.env, *.ps1 -ErrorAction SilentlyContinue |
            Select-String -Pattern 'password|secret|token' -SimpleMatch:$false -ErrorAction SilentlyContinue |
            Select-Object -First 10
    }
    $count = Get-ObjectCount $hits
    Add-ReviewResult -Section $secCred -CheckId "config-secrets" -Title "Credential Access - Config File Secrets" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count potential secret string(s) in config-like files (sampled)." -Evidence $hits
}

Invoke-Check -Section $secCred -CheckId "clipboard" -Title "Credential Access - Clipboard" -Severity "Low" -Test {
    Add-ReviewResult -Section $secCred -CheckId "clipboard" -Title "Credential Access - Clipboard" `
        -Status "MANUAL" `
        -Summary "Clipboard content not auto-collected; inspect manually if engagement scope includes host clipboard." `
        -Remediation "Use [Windows.Clipboard]::GetText() only with explicit customer approval."
}

Invoke-Check -Section $secLat -CheckId "net-share" -Title "Lateral Movement - Shares" -Severity "Medium" -Test {
    $o = net share 2>&1 | Out-String
    Add-ReviewResult -Section $secLat -CheckId "net-share" -Title "Lateral Movement - Shares" `
        -Status "REVIEW" -Summary "Review share permissions." -Evidence $o.Trim()
}

Invoke-Check -Section $secLat -CheckId "local-admins" -Title "Lateral Movement - Local Administrators" -Severity "High" -Test {
    $o = net localgroup Administrators 2>&1 | Out-String
    Add-ReviewResult -Section $secLat -CheckId "local-admins" -Title "Lateral Movement - Local Administrators" `
        -Status "REVIEW" -Summary "Review local Administrators membership." -Evidence $o.Trim()
}

Invoke-Check -Section $secDisc -CheckId "firewall-rules" -Title "Discovery - Firewall Rules" -Severity "Medium" -Test {
    $rules = Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Direction, Action, Profile -First 40
    Add-ReviewResult -Section $secDisc -CheckId "firewall-rules" -Title "Discovery - Firewall Rules" `
        -Status "REVIEW" -Summary "Sample of $($rules.Count) enabled rules." -Evidence $rules
}

Invoke-Check -Section $secDisc -CheckId "proxy" -Title "Discovery - Proxy Settings" -Severity "Low" -Test {
    $o = netsh winhttp show proxy 2>&1 | Out-String
    Add-ReviewResult -Section $secDisc -CheckId "proxy" -Title "Discovery - Proxy Settings" `
        -Status "REVIEW" -Summary "Review WinHTTP proxy configuration." -Evidence $o.Trim()
}

Invoke-Check -Section $secDisc -CheckId "drive-acl" -Title "Discovery - Drive ACL (C:)" -Severity "High" -Test {
    $risky = (Get-Acl C:\).Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.IdentityReference -match '(^|\\)(Everyone|Users|Authenticated Users)$' -and
        $_.FileSystemRights -match 'Write|Modify|FullControl'
    }
    $count = Get-ObjectCount $risky
    Add-ReviewResult -Section $secDisc -CheckId "drive-acl" -Title "Discovery - Drive ACL (C:)" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count risky ACE(s) on C:\ root." -Evidence $risky
}

} # end -not CisBaselineOnly (pentest / discovery)

Invoke-Check -Section $secSys -CheckId "rdp" -Title "RDP Access Audit" -Severity "High" -Test {
    $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
        -Name fDenyTSConnections -ErrorAction SilentlyContinue
    $nla = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
        -Name UserAuthentication -ErrorAction SilentlyContinue
    $rdpEnabled = $ts -and [int]$ts.fDenyTSConnections -eq 0
    $nlaOk = $nla -and [int]$nla.UserAuthentication -eq 1
    $status = if ($rdpEnabled -and -not $nlaOk) { "FAIL" } elseif ($rdpEnabled) { "REVIEW" } else { "PASS" }
    Add-ReviewResult -Section $secSys -CheckId "rdp" -Title "RDP Access Audit" `
        -Status $status -Summary "RDP enabled=$rdpEnabled; NLA=$nlaOk" -Evidence @{ TS = $ts; NLA = $nla }
}

if (-not $CisBaselineOnly) {

Invoke-Check -Section $secSys -CheckId "local-users" -Title "User Account Audit - Local Users" -Severity "Medium" -Test {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $users = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object Enabled |
            Select-Object Name, LastLogon, PasswordLastSet
        $count = Get-ObjectCount $users
        $evidence = $users
    }
    else {
        $raw = net user 2>&1 | Out-String
        $count = ([regex]::Matches($raw, '(?m)^User accounts for')).Count
        if ($count -eq 0) { $count = ($raw -split "`n" | Where-Object { $_ -match '\S' }).Count }
        $evidence = $raw.Trim()
    }
    Add-ReviewResult -Section $secSys -CheckId "local-users" -Title "User Account Audit - Local Users" `
        -Status "REVIEW" -Summary "Review enabled local accounts (count signal: $count)." -Evidence $evidence
}

Invoke-Check -Section $secSys -CheckId "installed-apps" -Title "Installed Apps" -Severity "Low" -Test {
    $apps = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object DisplayName |
        Select-Object DisplayName, DisplayVersion |
        Sort-Object DisplayName |
        Select-Object -First 50
    Add-ReviewResult -Section $secSys -CheckId "installed-apps" -Title "Installed Apps" `
        -Status "REVIEW" -Summary "$(Get-ObjectCount $apps) installed application(s) sampled." -Evidence $apps
}

} # end -not CisBaselineOnly (inventory)

Invoke-Check -Section $secSys -CheckId "domain-membership" -Title "Domain Membership" -Severity "Info" -Test {
    $cs = Get-CimInstance Win32_ComputerSystem
    $dc = nltest /dsgetdc:$env:USERDOMAIN 2>&1 | Out-String
    Add-ReviewResult -Section $secSys -CheckId "domain-membership" -Title "Domain Membership" `
        -Status "INFO" -Summary "Role=$hostRole; Domain=$($cs.Domain); PartOfDomain=$($cs.PartOfDomain)" `
        -Evidence @{ ComputerSystem = $cs; DsGetDc = $dc.Trim() }
}

if (-not $CisBaselineOnly) {

Invoke-Check -Section $secSys -CheckId "gpo" -Title "GPO Summary" -Severity "Medium" -Test {
    $o = gpresult /r 2>&1 | Out-String
    Add-ReviewResult -Section $secSys -CheckId "gpo" -Title "GPO Summary" `
        -Status "REVIEW" -Summary "Review applied GPO list." -Evidence ($o.Substring(0, [Math]::Min(3000, $o.Length)))
}

Invoke-Check -Section $secSys -CheckId "features" -Title "Installed Windows Features" -Severity "Low" `
    -SkipIf { -not $elevated } -Test {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $f = Get-WindowsFeature | Where-Object Installed | Select-Object Name, DisplayName
    }
    else {
        $f = Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
            Where-Object State -eq Enabled | Select-Object FeatureName, State
    }
    Add-ReviewResult -Section $secSys -CheckId "features" -Title "Installed Windows Features" `
        -Status "REVIEW" -Summary "$(Get-ObjectCount $f) installed feature(s)/role(s)." -Evidence ($f | Select-Object -First 30)
}

Invoke-Check -Section $secSys -CheckId "applocker" -Title "AppLocker Policy" -Severity "Medium" -Test {
    try {
        $xml = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
        $status = if ($xml) { "REVIEW" } else { "REVIEW" }
        Add-ReviewResult -Section $secSys -CheckId "applocker" -Title "AppLocker Policy" `
            -Status $status -Summary "Effective AppLocker policy retrieved." -Evidence ($xml.ToString().Substring(0, [Math]::Min(500, $xml.ToString().Length)))
    }
    catch {
        Add-ReviewResult -Section $secSys -CheckId "applocker" -Title "AppLocker Policy" `
            -Status "REVIEW" -Summary "AppLocker not configured or unavailable."
    }
}

Invoke-Check -Section $secSys -CheckId "device-guard" -Title "Device Guard / Credential Guard" -Severity "Medium" -Test {
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName DeviceGuard -ErrorAction SilentlyContinue
    Add-ReviewResult -Section $secSys -CheckId "device-guard" -Title "Device Guard / Credential Guard" `
        -Status "REVIEW" -Summary "VBS/CG status captured." -Evidence $dg
}

Invoke-Check -Section $secSys -CheckId "wsl-presence" -Title "Defense Evasion - WSL Presence" -Severity "Low" -Test {
    $wsl = @{
        BashExe  = Test-Path 'C:\Windows\System32\bash.exe'
        WslExe   = Test-Path 'C:\Windows\System32\wsl.exe'
        WslConfig = Test-Path "$env:USERPROFILE\.wslconfig"
    }
    $present = $wsl.BashExe -or $wsl.WslExe
    Add-ReviewResult -Section $secSys -CheckId "wsl-presence" -Title "Defense Evasion - WSL Presence" `
        -Status $(if ($present) { "REVIEW" } else { "PASS" }) `
        -Summary "WSL components present=$present" -Evidence $wsl
}

Invoke-Check -Section $secSys -CheckId "crash-dump" -Title "Crash Dump Settings" -Severity "Low" -Test {
    # CrashDumpEnabled itself encodes the dump type: 0=None, 1=Complete, 2=Kernel, 3=Small,
    # 7=Automatic. There is no separate "CrashDumpType" value under this key.
    $cc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction SilentlyContinue
    $fullDump = $cc -and [int]$cc.CrashDumpEnabled -eq 1
    Add-ReviewResult -Section $secSys -CheckId "crash-dump" -Title "Crash Dump Settings" `
        -Status $(if ($fullDump) { "REVIEW" } else { "PASS" }) `
        -Summary "CrashDumpEnabled=$($cc.CrashDumpEnabled) (1=Complete memory dump may contain sensitive data; 0=None,2=Kernel,3=Small,7=Automatic are lower risk)" -Evidence $cc
}

Invoke-Check -Section $secSys -CheckId "env-vars" -Title "System Info - Environment Variables" -Severity "Low" -Test {
    $sample = Get-ChildItem Env: | Where-Object { $_.Name -notmatch 'PASSWORD|SECRET|TOKEN|KEY' } |
        Select-Object Name, Value -First 30
    Add-ReviewResult -Section $secSys -CheckId "env-vars" -Title "System Info - Environment Variables" `
        -Status "REVIEW" -Summary "Sample of non-sensitive environment variables." -Evidence $sample
}

Invoke-Check -Section $secSys -CheckId "app-crash-logs" -Title "App Crash Logs" -Severity "Low" -Test {
    try {
        $crashes = Get-WinEvent -FilterHashtable @{
            LogName   = 'Application'
            Id        = 1000, 1001
            StartTime = (Get-Date).AddDays(-30)
        } -MaxEvents 10 -ErrorAction Stop |
            Select-Object TimeCreated, Id, ProviderName, @{ n = 'Message'; e = { $_.Message.Substring(0, [Math]::Min(100, $_.Message.Length)) } }
        Add-ReviewResult -Section $secSys -CheckId "app-crash-logs" -Title "App Crash Logs" `
            -Status "REVIEW" -Summary "$($crashes.Count) application crash/error event(s) in last 30 days." -Evidence $crashes
    }
    catch {
        Add-ReviewResult -Section $secSys -CheckId "app-crash-logs" -Title "App Crash Logs" `
            -Status "REVIEW" -Summary "Application log query failed: $($_.Exception.Message)"
    }
}

Invoke-Check -Section $secSys -CheckId "w32time" -Title "Time Sync Status" -Severity "Medium" -Test {
    $o = w32tm /query /status 2>&1 | Out-String
    Add-ReviewResult -Section $secSys -CheckId "w32time" -Title "Time Sync Status" `
        -Status "REVIEW" -Summary "Verify sync source and skew." -Evidence $o.Trim()
}

Invoke-Check -Section $secSys -CheckId "dns" -Title "DNS Configuration" -Severity "Low" -Test {
    $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, ServerAddresses
    Add-ReviewResult -Section $secSys -CheckId "dns" -Title "DNS Configuration" `
        -Status "REVIEW" -Summary "Review DNS server assignments." -Evidence $dns
}

Invoke-Check -Section $secSys -CheckId "security-logs" -Title "Security Logs Sample" -Severity "Low" -Test {
    try {
        $events = Get-WinEvent -LogName Security -MaxEvents 15 -ErrorAction Stop |
            Select-Object TimeCreated, Id, LevelDisplayName, @{ n = 'Message'; e = { $_.Message.Substring(0, [Math]::Min(120, $_.Message.Length)) } }
        Add-ReviewResult -Section $secSys -CheckId "security-logs" -Title "Security Logs Sample" `
            -Status "REVIEW" -Summary "$($events.Count) recent Security log event(s) retrieved." -Evidence $events
    }
    catch {
        Add-ReviewResult -Section $secSys -CheckId "security-logs" -Title "Security Logs Sample" `
            -Status "REVIEW" -Summary "Security log not readable: $($_.Exception.Message)"
    }
}

} # end -not CisBaselineOnly (system inventory)

if (-not $CisBaselineOnly -and -not $SkipExternalTools) {
    Write-Host "`n[>] Automation: winPEAS check..." -ForegroundColor DarkCyan
    Invoke-Check -Section "AUTOMATION" -CheckId "winpeas" -Title "winPEAS local privesc enumeration" -Severity "Info" -Test {
        $binaryName = Get-WinPeasBinaryName
        $winPeas = Resolve-WinBuildReviewTool -ToolName $binaryName
        if ($RunWinPeas) {
            if (-not $winPeas) {
                Add-ReviewResult -Section "AUTOMATION" -CheckId "winpeas" -Title "winPEAS local privesc enumeration" `
                    -Status "MANUAL" `
                    -Summary "$binaryName not found in PATH or .\tools." `
                    -Remediation "Run Install-WinBuildReviewTools.ps1 -InstallAll -AddToolsToUserPath"
                return
            }
            try {
                $result = Invoke-WinPeasCollection -OutputDirectory $OutputPath `
                    -Profile $WinPeasProfile `
                    -FileTimestamp $timestamp `
                    -IncludeDomainChecks:((Get-WindowsBuildRole) -eq 'Domain Controller')
                $summaryParts = @("winPEAS ($WinPeasProfile) -> $($result.OutputFile) (exit $($result.ExitCode))")
                if ($result.Parsers.Ran) {
                    $derived = @()
                    if ($result.Parsers.JsonFile) { $derived += (Split-Path -Leaf $result.Parsers.JsonFile) }
                    if ($result.Parsers.HtmlFile) { $derived += (Split-Path -Leaf $result.Parsers.HtmlFile) }
                    if ($result.Parsers.PdfFile) { $derived += (Split-Path -Leaf $result.Parsers.PdfFile) }
                    if ($derived.Count -gt 0) {
                        $summaryParts += "parsers: $($derived -join ', ')"
                    }
                    if ($result.Parsers.Errors.Count -gt 0) {
                        $summaryParts += "parser warnings: $($result.Parsers.Errors -join '; ')"
                    }
                }
                Add-ReviewResult -Section "AUTOMATION" -CheckId "winpeas" -Title "winPEAS local privesc enumeration" `
                    -Status "INFO" `
                    -Summary ($summaryParts -join '. ') `
                    -Evidence @{
                        Binary     = $result.Binary
                        OutputFile = $result.OutputFile
                        ExitCode   = $result.ExitCode
                        Profile    = $result.Profile
                        Arguments  = $result.Arguments
                        JsonFile   = $result.Parsers.JsonFile
                        HtmlFile   = $result.Parsers.HtmlFile
                        PdfFile    = $result.Parsers.PdfFile
                        ParserErrors = $result.Parsers.Errors
                    } `
                    -Remediation "Review winPEAS output for AlwaysInstallElevated, services, tokens, DLL hijacks, and credential stores."
            }
            catch {
                Add-ReviewResult -Section "AUTOMATION" -CheckId "winpeas" -Title "winPEAS local privesc enumeration" `
                    -Status "ERROR" -Summary $_.Exception.Message `
                    -Remediation "Re-run with elevated shell or increase timeout; verify $binaryName runs manually."
            }
            return
        }

        if ($winPeas) {
            Add-ReviewResult -Section "AUTOMATION" -CheckId "winpeas" -Title "winPEAS local privesc enumeration" `
                -Status "MANUAL" `
                -Summary "$binaryName found at $winPeas - run with -RunWinPeas (Focused profile by default)" `
                -Remediation "Install-WinBuildReviewTools.ps1 -InstallAll -AddToolsToUserPath; WinBuildReview.ps1 -RunWinPeas"
        }
        else {
            Add-ReviewResult -Section "AUTOMATION" -CheckId "winpeas" -Title "winPEAS local privesc enumeration" `
                -Status "MANUAL" `
                -Summary "$binaryName not installed. Native deep privesc checks still run in PRIVILEGE ESCALATION section." `
                -Remediation "Run Install-WinBuildReviewTools.ps1 -InstallAll -AddToolsToUserPath"
        }
    }
}
elseif ($SkipExternalTools) {
    Add-ReviewResult -Section "AUTOMATION" -CheckId "winpeas" -Title "winPEAS local privesc enumeration" `
        -Status "SKIP" -Summary "Skipped (-SkipExternalTools)." -Severity "Info"
}

$cisScan = Get-CisScanGuidance
Add-ReviewResult -Section "AUTOMATION" -CheckId "cis-scan" -Title "CIS Benchmark Scan (MS/DC)" `
    -Status "MANUAL" -Severity "Info" -CisRef $cisScan.CisRef `
    -Summary $cisScan.Summary `
    -Remediation "Download benchmark PDF from CIS Workbench for $($script:OsProfile)."

# --- Export ---

$script:Results | Export-Csv -Path $csvLog -NoTypeInformation -Encoding utf8

$statusSummary = $script:Results | Group-Object Status | Sort-Object Name |
    ForEach-Object { "  $($_.Name): $($_.Count)" }

$summaryText = @"

================================================================================
SUMMARY - Windows Build Review v$scriptVersion
Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Duration : $([math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)) minutes
Host Role: $hostRole
OS Profile: $($script:OsProfile)$profileNote
CIS Benchmark: $($script:CisBenchmarkLabel)
Checks   : $($script:Results.Count)
$($statusSummary -join "`n")

Outputs:
  Log : $txtLog
  CSV : $csvLog
  HTML: $htmlLog

AD object review is out of scope - use ADReviewv1.ps1
"@

Write-Log $summaryText
Write-Host $summaryText -ForegroundColor Cyan

$htmlRows = ($script:Results | ForEach-Object {
    $cls = $_.Status
    "<tr class=`"$cls`"><td>$(ConvertTo-HtmlEncoded $_.Status)</td><td>$(ConvertTo-HtmlEncoded $_.Section)</td><td>$(ConvertTo-HtmlEncoded $_.Title)</td><td>$(ConvertTo-HtmlEncoded $_.OsProfile)</td><td>$(ConvertTo-HtmlEncoded $_.CisBenchmark)</td><td>$(ConvertTo-HtmlEncoded $_.CisRef)</td><td>$(ConvertTo-HtmlEncoded $_.Summary)</td></tr>"
}) -join "`n"

@"

<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Build Review $timestamp</title>
<style>
body{font-family:Segoe UI,sans-serif;margin:24px;background:#f5f5f5}
table{border-collapse:collapse;width:100%;background:#fff}
th,td{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top;font-size:13px}
th{background:#107c10;color:#fff}
tr:nth-child(even){background:#f9f9f9}
.FAIL,.ERROR{color:#b00020;font-weight:bold}.PASS{color:#107c10;font-weight:bold}
.REVIEW,.MANUAL{color:#ca5010}.SKIP{color:#666}
</style></head><body>
<h1>Windows Build Review v$scriptVersion</h1>
<p>Host: $hostname | Role: $hostRole | OS Profile: $($script:OsProfile)$profileNote | Elevated: $elevatedText | Generated: $timestamp</p>
<p>CIS Benchmark: $(ConvertTo-HtmlEncoded $script:CisBenchmarkLabel)</p>
<table>
<tr><th>Status</th><th>Section</th><th>Check</th><th>OS Profile</th><th>CIS Benchmark</th><th>CIS Ref</th><th>Summary</th></tr>
$htmlRows
</table>
<p>Methodology: Draft_Windows-Build-Review-Methodology_FINAL.xlsx | Profiles: WinBuildReview.CisProfiles.ps1 | AD review: ADReviewv1.ps1</p>
</body></html>
"@ | Set-Content $htmlLog -Encoding utf8

Write-Host "`nDone. Review $csvLog for structured results." -ForegroundColor Green
