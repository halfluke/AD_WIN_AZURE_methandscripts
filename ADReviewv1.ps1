<#
.SYNOPSIS
    Active Directory Review v1 - automates checks from Draft_AD_Methodology_FINAL.xlsx.

.DESCRIPTION
    Passive AD posture audit. Uses ActiveDirectory module (RSAT) from a domain-joined
    host with appropriate read rights. Does not modify AD objects or GPOs.

    Scope: AD objects, domain/forest policy, trusts, delegation, AD-integrated
    services, hybrid Entra signals. NOT Windows Server/DC OS build hardening
    (use WinBuildReview.ps1 for that).

.PARAMETER Domain
    DNS domain name. Defaults to current logon domain.

.PARAMETER Server
    Domain controller to bind queries. Defaults to PDC emulator.

.PARAMETER OutputPath
    Directory for TXT, CSV, and HTML output.

.PARAMETER RunPingCastle
    Run PingCastle healthcheck when PingCastle.exe is available (PATH or .\tools).

.PARAMETER PingCastleServer
    Domain controller FQDN passed to PingCastle --server. Defaults to the PDC emulator.
    Open-source PingCastle has no --timeout switch; it probes every DC registered in AD.

.PARAMETER RunSharpHound
    Run SharpHound collection when SharpHound.exe is available (PATH or .\tools).

.PARAMETER RunPurpleKnight
    Run Invoke-PKAssessment when the Purple Knight PowerShell module is installed.

.PARAMETER SkipExternalTools
    Skip automation rows for SharpHound, PingCastle, and Purple Knight.

.PARAMETER IncludeEntra
    Run hybrid Entra ID checks via Microsoft Graph (requires Connect-MgGraph).

.PARAMETER EntraTenantId
    Entra tenant for Connect-MgGraph (domain.onmicrosoft.com or GUID). Recommended for
    Microsoft accounts (MSA) and guest (#EXT#) identities tied to an Azure subscription.

.EXAMPLE
    .\ADReviewv1.ps1 -Domain "corp.example.com"

.EXAMPLE
    .\ADReviewv1.ps1 -Server "DC01" -OutputPath "C:\Reviews\AD" -IncludeEntra

.NOTES
    Version     : 1.1.0
    Methodology : Draft_AD_Methodology_FINAL.xlsx
    Requires    : RSAT ActiveDirectory module, domain user with AD read access
    Optional    : PingCastle, Purple Knight, SharpHound (see Install-ADReviewTools.ps1), Microsoft Graph PowerShell
#>

[CmdletBinding()]
param(
    [string]$Domain = "",
    [string]$Server = "",
    [string]$OutputPath = "",
    [switch]$RunPingCastle,
    [string]$PingCastleServer = "",
    [switch]$RunSharpHound,
    [switch]$RunPurpleKnight,
    [switch]$SkipExternalTools,
    [switch]$IncludeEntra,
    [string]$EntraTenantId = ""
)

$ErrorActionPreference = "Stop"

$scriptVersion = "1.1.0"
$startTime     = Get-Date
$timestamp     = $startTime.ToString("yyyyMMdd-HHmmss")
$scriptPath    = $MyInvocation.MyCommand.Path
$scriptDir     = Split-Path -Parent $scriptPath
if (-not $OutputPath) { $OutputPath = $scriptDir }
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$txtLog  = Join-Path $OutputPath "ADReview-$timestamp.txt"
$csvLog  = Join-Path $OutputPath "ADReview-$timestamp.csv"
$htmlLog = Join-Path $OutputPath "ADReview-$timestamp.html"

$script:Results = [System.Collections.Generic.List[object]]::new()
$script:TxtLog  = $txtLog

. (Join-Path $scriptDir "ADReview.Common.ps1")
Initialize-ADReviewToolPaths -ScriptDirectory $scriptDir

$installToolsHint = ".\Install-ADReviewTools.ps1 -InstallAll -AddToolsToUserPath"
$bloodHoundCeHint = "BloodHound CE: Docker Desktop + bloodhound-cli install - $script:BloodHoundCeQuickstartUrl"

$secAuto   = "AUTOMATION / SCANNING"
$secAcct   = "ACCOUNT SETTINGS"
$secGroup  = "GROUP SETTINGS"
$secDomain = "DOMAIN SETTINGS"
$secSvc    = "SERVICE SETTINGS"
$secDeleg  = "PRIVILEGE DELEGATION"
$secCert   = "CERTIFICATE SETTINGS"
$secMaint  = "MAINTENANCE"
$secEntra  = "HYBRID ENTRA ID"

@"
Active Directory Review v$scriptVersion - $timestamp
Methodology: Draft_AD_Methodology_FINAL (AD-only; not DC/OS build review)
Host: $env:COMPUTERNAME | User: $env:USERDOMAIN\$env:USERNAME
"@ | Set-Content $txtLog -Encoding utf8

try {
    Initialize-ADReviewSession -Domain $Domain -Server $Server
}
catch {
    Write-Error $_.Exception.Message
}

Write-Host "`nActive Directory Review v$scriptVersion" -ForegroundColor Cyan
Write-Host "Domain: $($script:DomainDns) | Output: $OutputPath`n" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Automation / external tools
# ---------------------------------------------------------------------------

if (-not $SkipExternalTools) {
    Invoke-Check -Section $secAuto -CheckId "bloodhound" -Title "Run bloodhound COLLECTORS (review on kali machine later)" -Severity "Info" -Test {
        $sharpHound = Resolve-ADReviewTool -ToolName "SharpHound.exe"
        if ($RunSharpHound) {
            if (-not $sharpHound) {
                Add-ReviewResult -Section $secAuto -CheckId "bloodhound" -Title "Run bloodhound COLLECTORS (review on kali machine later)" `
                    -Status "MANUAL" `
                    -Summary "SharpHound.exe not found in PATH or .\tools." `
                    -Remediation "$installToolsHint | $bloodHoundCeHint"
                return
            }
            $sanitizedDomain = ($script:DomainDns -replace '[^\w\-]', '-')
            $zipBase = "sharphound-$sanitizedDomain"
            $collectionStart = Get-Date
            try {
                & $sharpHound -c All --domain $script:DomainDns --outputdirectory $OutputPath --zipfilename $zipBase --nocache 2>&1 | ForEach-Object { Write-Host $_ }
                $zipPath = Resolve-SharpHoundCollectionZip -OutputDirectory $OutputPath `
                    -ExpectedBaseName $zipBase -NotBefore $collectionStart.AddMinutes(-1)
                if (-not $zipPath) {
                    throw "SharpHound finished but no zip was found under $OutputPath (SharpHound prepends its own timestamp to the filename)."
                }
                if ($LASTEXITCODE -ne 0) {
                    throw "SharpHound exited with code $LASTEXITCODE. Latest zip: $zipPath"
                }
                Add-ReviewResult -Section $secAuto -CheckId "bloodhound" -Title "Run bloodhound COLLECTORS (review on kali machine later)" `
                    -Status "INFO" -Summary "SharpHound collection saved to $zipPath (ingest into BloodHound CE)." `
                    -Remediation "Ingest zip in BloodHound CE (Administration -> File Ingest). $bloodHoundCeHint"
            }
            catch {
                Add-ReviewResult -Section $secAuto -CheckId "bloodhound" -Title "Run bloodhound COLLECTORS (review on kali machine later)" `
                    -Status "ERROR" -Summary $_.Exception.Message
            }
            return
        }

        if ($sharpHound) {
            Add-ReviewResult -Section $secAuto -CheckId "bloodhound" -Title "Run bloodhound COLLECTORS (review on kali machine later)" `
                -Status "MANUAL" `
                -Summary "SharpHound found at $sharpHound - run with -RunSharpHound or: SharpHound.exe -c All --domain $($script:DomainDns) --nocache" `
                -Remediation "Ingest zip into BloodHound CE for attack-path analysis. $bloodHoundCeHint"
        }
        else {
            Add-ReviewResult -Section $secAuto -CheckId "bloodhound" -Title "Run bloodhound COLLECTORS (review on kali machine later)" `
                -Status "MANUAL" `
                -Summary "SharpHound not installed. Run Install-ADReviewTools.ps1 for SharpHound.exe; install BloodHound CE GUI separately." `
                -Remediation "$installToolsHint | $bloodHoundCeHint"
        }
    }

    Invoke-Check -Section $secAuto -CheckId "pingcastle" -Title "PurpleKnight / Pingcastle" -Severity "Info" -Test {
        $pingCastle = Resolve-ADReviewTool -ToolName "PingCastle.exe"
        if ($RunPingCastle) {
            if (-not $pingCastle) {
                Add-ReviewResult -Section $secAuto -CheckId "pingcastle" -Title "PurpleKnight / Pingcastle" `
                    -Status "MANUAL" `
                    -Summary "PingCastle.exe not found in PATH or .\tools." `
                    -Remediation $installToolsHint
                return
            }
            $pcOut = Join-Path $OutputPath "pingcastle-$timestamp"
            New-Item -ItemType Directory -Path $pcOut -Force | Out-Null
            $pcServer = if ($PingCastleServer) { $PingCastleServer } else { $script:ADDomain.PDCEmulator }
            try {
                Push-Location $pcOut
                # --log is a switch (no path argument); reports are written to the current directory.
                # OSS PingCastle has no --timeout; it still probes every DC registered in AD (slow if one is off).
                & $pingCastle --healthcheck --server $pcServer --log 2>&1 | ForEach-Object { Write-Host $_ }
                if ($LASTEXITCODE -ne 0) {
                    throw "PingCastle exited with code $LASTEXITCODE"
                }
                Add-ReviewResult -Section $secAuto -CheckId "pingcastle" -Title "PurpleKnight / Pingcastle" `
                    -Status "INFO" -Summary "PingCastle output saved to $pcOut (server $pcServer)." `
                    -Remediation "Powered-off or stale DCs still add minutes (PingCastle has no --timeout). Demote/remove stale DCs or use -PingCastleServer for a known-online DC."
            }
            catch {
                Add-ReviewResult -Section $secAuto -CheckId "pingcastle" -Title "PurpleKnight / Pingcastle" `
                    -Status "ERROR" -Summary $_.Exception.Message
            }
            finally {
                Pop-Location
            }
            return
        }

        if ($pingCastle) {
            Add-ReviewResult -Section $secAuto -CheckId "pingcastle" -Title "PurpleKnight / Pingcastle" `
                -Status "MANUAL" `
                -Summary "PingCastle found at $pingCastle - run with -RunPingCastle or: PingCastle.exe --healthcheck --server $($script:ADDomain.PDCEmulator)" `
                -Remediation "Use -RunPingCastle to execute during ADReview."
        }
        else {
            Add-ReviewResult -Section $secAuto -CheckId "pingcastle" -Title "PurpleKnight / Pingcastle" `
                -Status "MANUAL" `
                -Summary "PingCastle not installed. Install via Install-ADReviewTools.ps1." `
                -Remediation $installToolsHint
        }
    }

    Invoke-Check -Section $secAuto -CheckId "purple-knight" -Title "PurpleKnight / Pingcastle" -Severity "Info" -Test {
        $pkCmdlet = Get-Command Invoke-PKAssessment -ErrorAction SilentlyContinue
        if ($RunPurpleKnight) {
            if (-not $pkCmdlet) {
                Add-ReviewResult -Section $secAuto -CheckId "purple-knight" -Title "PurpleKnight / Pingcastle" `
                    -Status "MANUAL" `
                    -Summary "Invoke-PKAssessment not available. Install Purple Knight from Semperis." `
                    -Remediation "https://www.semperis.com/purple-knight/"
                return
            }
            $pkOut = Join-Path $OutputPath "purple-knight-$timestamp"
            New-Item -ItemType Directory -Path $pkOut -Force | Out-Null
            try {
                Push-Location $pkOut
                & Invoke-PKAssessment
                Add-ReviewResult -Section $secAuto -CheckId "purple-knight" -Title "PurpleKnight / Pingcastle" `
                    -Status "INFO" -Summary "Purple Knight assessment output directory: $pkOut"
            }
            catch {
                Add-ReviewResult -Section $secAuto -CheckId "purple-knight" -Title "PurpleKnight / Pingcastle" `
                    -Status "ERROR" -Summary $_.Exception.Message
            }
            finally {
                Pop-Location
            }
            return
        }

        if ($pkCmdlet) {
            Add-ReviewResult -Section $secAuto -CheckId "purple-knight" -Title "PurpleKnight / Pingcastle" `
                -Status "MANUAL" `
                -Summary "Invoke-PKAssessment available - run with -RunPurpleKnight or use the Purple Knight GUI." `
                -Remediation "Map results to methodology Automated Tooling column."
        }
        else {
            Add-ReviewResult -Section $secAuto -CheckId "purple-knight" -Title "PurpleKnight / Pingcastle" `
                -Status "MANUAL" `
                -Summary "Purple Knight not detected. Install from Semperis (not auto-downloaded by this repo)." `
                -Remediation "https://www.semperis.com/purple-knight/"
        }
    }
}
else {
    foreach ($tool in @(
        @{ Id = "bloodhound"; Title = "Run bloodhound COLLECTORS (review on kali machine later)" }
        @{ Id = "pingcastle"; Title = "PurpleKnight / Pingcastle" }
        @{ Id = "purple-knight"; Title = "PurpleKnight / Pingcastle" }
    )) {
        Add-ReviewResult -Section $secAuto -CheckId $tool.Id -Title $tool.Title -Status "SKIP" `
            -Summary "Skipped (-SkipExternalTools)." -Severity "Info"
    }
}

# ---------------------------------------------------------------------------
# Account settings
# ---------------------------------------------------------------------------

Invoke-Check -Section $secAcct -CheckId "pwd-not-required" `
    -Title "Account does not require password" -Severity "High" -Test {
    # Enabled accounts only — disabled Guest often retains PASSWD_NOTREQD by default.
    $hits = Get-ADUser -Filter 'PasswordNotRequired -eq $true -and Enabled -eq $true' `
        -Properties PasswordNotRequired, Enabled |
        Select-Object Name, SamAccountName, Enabled
    $count = @($hits).Count
    Add-ReviewResult -Section $secAcct -CheckId "pwd-not-required" -Title "Account does not require password" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count enabled account(s) with PasswordNotRequired" -Evidence $hits `
        -Remediation "Clear PASSWD_NOTREQD; enforce password on all enabled user accounts."
}

Invoke-Check -Section $secAcct -CheckId "pwd-never-expires" `
    -Title "Account password does not expire" -Severity "Medium" -Test {
    # Enabled accounts only — disabled Guest often has PasswordNeverExpires by default.
    $hits = Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' `
        -Properties PasswordNeverExpires, MemberOf |
        Select-Object Name, SamAccountName, Enabled, MemberOf
    $count = @($hits).Count
    Add-ReviewResult -Section $secAcct -CheckId "pwd-never-expires" -Title "Account password does not expire" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count enabled account(s) with PasswordNeverExpires" -Evidence ($hits | Select-Object -First 25)
}

Invoke-Check -Section $secAcct -CheckId "no-preauth" `
    -Title "Accounts do not require kerberos pre-authentication" -Severity "High" -Test {
    $hits = Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol |
        Select-Object Name, SamAccountName, useraccountcontrol
    $count = @($hits).Count
    Add-ReviewResult -Section $secAcct -CheckId "no-preauth" `
        -Title "Accounts do not require kerberos pre-authentication" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count account(s) with DONT_REQ_PREAUTH" -Evidence $hits
}

Invoke-Check -Section $secAcct -CheckId "duplicate-spn" `
    -Title "Check for Duplicated SPNS" -Severity "High" -Test {
    $map = @{}
    $dups = [System.Collections.Generic.List[string]]::new()
    Get-ADObject -Filter 'servicePrincipalName -like "*"' -Properties servicePrincipalName, sAMAccountName |
        ForEach-Object {
            foreach ($spn in $_.servicePrincipalName) {
                if ($map.ContainsKey($spn)) {
                    $dups.Add("$spn -> $($map[$spn]) + $($_.sAMAccountName)")
                }
                else {
                    $map[$spn] = $_.sAMAccountName
                }
            }
        }
    Add-ReviewResult -Section $secAcct -CheckId "duplicate-spn" -Title "Check for Duplicated SPNS" `
        -Status $(if ($dups.Count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$($dups.Count) duplicate SPN occurrence(s)" -Evidence $dups
}

Invoke-Check -Section $secAcct -CheckId "kerberoast-spn" `
    -Title "User Accounts with SPN Configured" -Severity "Medium" -Test {
    $hits = Get-ADUser -Filter 'servicePrincipalName -like "*"' -Properties servicePrincipalName, MemberOf |
        Where-Object { -not (Test-IsKrbtgtAccount $_.SamAccountName) } |
        Select-Object Name, SamAccountName, servicePrincipalName, MemberOf
    $count = @($hits).Count
    Add-ReviewResult -Section $secAcct -CheckId "kerberoast-spn" -Title "User Accounts with SPN Configured" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count user(s) with SPN (excluding krbtgt) - review for Kerberoastable privileged accounts." `
        -Evidence ($hits | Select-Object -First 25)
}

Invoke-Check -Section $secAcct -CheckId "guest-enabled" `
    -Title "Guest Accounts Enabled" -Severity "High" -Test {
    $guest = Get-ADUser -Filter { SamAccountName -eq 'Guest' } -Properties Enabled -ErrorAction SilentlyContinue
    $enabled = $guest -and $guest.Enabled
    Add-ReviewResult -Section $secAcct -CheckId "guest-enabled" -Title "Guest Accounts Enabled" `
        -Status $(if (-not $enabled) { "PASS" } else { "FAIL" }) `
        -Summary "Guest account enabled = $enabled" -Evidence $guest
}

Invoke-Check -Section $secAcct -CheckId "machine-account-quota" `
    -Title "Non-Admin Users can Register Computers" -Severity "Medium" -Test {
    $maq = (Get-ADObject -Identity $script:DomainDn -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
    $status = if ($maq -eq 0) { "PASS" } elseif ($maq -le 10) { "REVIEW" } else { "FAIL" }
    Add-ReviewResult -Section $secAcct -CheckId "machine-account-quota" `
        -Title "Non-Admin Users can Register Computers" -Status $status `
        -Summary "ms-DS-MachineAccountQuota = $maq (0 = admins only)" -Evidence @{ Quota = $maq }
}

Invoke-Check -Section $secAcct -CheckId "builtin-rename" `
    -Title "Built-in AD accounts not renamed" -Severity "Medium" -Test {
    $builtins = Get-ADUser -Filter { SamAccountName -eq 'Administrator' -or SamAccountName -eq 'Guest' } |
        Select-Object Name, SamAccountName, Enabled
    $defaultNames = @($builtins | Where-Object { $_.SamAccountName -in @('Administrator', 'Guest') }).Count
    Add-ReviewResult -Section $secAcct -CheckId "builtin-rename" -Title "Built-in AD accounts not renamed" `
        -Status $(if ($defaultNames -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$defaultNames built-in account(s) still use default SamAccountName" -Evidence $builtins
}

Invoke-Check -Section $secAcct -CheckId "domain-lockout" `
    -Title "Domain account lockout policy weak or missing" -Severity "Medium" -Test {
    $p = Get-ADDefaultDomainPasswordPolicy
    $issues = @()
    if ($p.LockoutThreshold -eq 0 -or $p.LockoutThreshold -gt 5) { $issues += "LockoutThreshold=$($p.LockoutThreshold)" }
    if ($p.LockoutDuration.TotalMinutes -lt 15 -and $p.LockoutThreshold -gt 0) { $issues += "LockoutDuration=$($p.LockoutDuration)" }
    if ($p.LockoutObservationWindow.TotalMinutes -lt 15 -and $p.LockoutThreshold -gt 0) { $issues += "ObservationWindow=$($p.LockoutObservationWindow)" }
    Add-ReviewResult -Section $secAcct -CheckId "domain-lockout" `
        -Title "Domain account lockout policy weak or missing" `
        -Status $(if ($issues.Count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary $(if ($issues) { $issues -join '; ' } else { "Lockout policy within expected bounds." }) `
        -Evidence $p
}

Invoke-Check -Section $secAcct -CheckId "weak-password-policy" `
    -Title "Weak Password Policy" -Severity "High" -Test {
    $p = Get-ADDefaultDomainPasswordPolicy
    $issues = @()
    if ($p.MinPasswordLength -lt 14) { $issues += "MinPasswordLength=$($p.MinPasswordLength)" }
    if (-not $p.ComplexityEnabled) { $issues += "ComplexityEnabled=False" }
    if ($p.ReversibleEncryptionEnabled) { $issues += "ReversibleEncryptionEnabled=True" }
    if ($p.PasswordHistoryCount -lt 24) { $issues += "PasswordHistoryCount=$($p.PasswordHistoryCount)" }
    Add-ReviewResult -Section $secAcct -CheckId "weak-password-policy" -Title "Weak Password Policy" `
        -Status $(if ($issues.Count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary $(if ($issues) { $issues -join '; ' } else { "Default domain password policy looks strong." }) `
        -Evidence $p
}

Invoke-Check -Section $secAcct -CheckId "reversible-encryption" `
    -Title "Insecure Password Storage" -Severity "High" -Test {
    $users = Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl |
        Select-Object Name, SamAccountName
    $count = @($users).Count
    Add-ReviewResult -Section $secAcct -CheckId "reversible-encryption" -Title "Insecure Password Storage" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count user(s) with reversible encryption enabled" -Evidence ($users | Select-Object -First 20)
}

Invoke-Check -Section $secAcct -CheckId "dcsync-rights" `
    -Title "Non-default principals with Directory Replication Permissions" -Severity "Critical" -Test {
    # DCSync = ExtendedRight ACEs for DS-Replication-Get-Changes / -All (and the "all extended
    # rights" wildcard GUID). ActiveDirectoryRights never renders as the extended right's display
    # name - it must be matched via ObjectType GUID, not a string match on ActiveDirectoryRights.
    $dcsyncGuids = @(
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', # DS-Replication-Get-Changes
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', # DS-Replication-Get-Changes-All
        '00000000-0000-0000-0000-000000000000'  # all extended rights
    )
    $acl = Get-Acl "AD:\$($script:DomainDn)"
    $hits = $acl.Access | Where-Object {
        $_.ActiveDirectoryRights -match 'ExtendedRight' -and
        $_.ObjectType.ToString() -in $dcsyncGuids -and
        $_.AccessControlType -eq 'Allow' -and
        $_.IdentityReference -notmatch 'NT AUTHORITY\\SYSTEM|Enterprise Domain Controllers|Domain Admins|Administrators'
    } | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType, AccessControlType
    $count = @($hits).Count
    Add-ReviewResult -Section $secAcct -CheckId "dcsync-rights" `
        -Title "Non-default principals with Directory Replication Permissions" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count non-default principal(s) with DS-Replication-Get-Changes[-All] (DCSync) rights on domain root" -Evidence $hits
}

Invoke-Check -Section $secAcct -CheckId "svc-domain-admin" `
    -Title "Service Account with Administrator Privileges" -Severity "Critical" -Test {
    $admins = Get-ADGroupMember 'Domain Admins' | Where-Object { $_.objectClass -eq 'user' } |
        ForEach-Object {
            Get-ADUser $_.SamAccountName -Properties PasswordNeverExpires, servicePrincipalName, objectSid `
                -ErrorAction SilentlyContinue
        }
    $hits = @($admins | Where-Object {
        -not (Test-IsBuiltInDomainAdministrator $_) -and
        ($_.PasswordNeverExpires -or $_.servicePrincipalName)
    } | Select-Object Name, SamAccountName, PasswordNeverExpires, servicePrincipalName)
    $count = $hits.Count
    Add-ReviewResult -Section $secAcct -CheckId "svc-domain-admin" `
        -Title "Service Account with Administrator Privileges" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count non-built-in Domain Admin account(s) look like service accounts (excludes RID 500 Administrator)." `
        -Evidence $hits
}

Invoke-Check -Section $secAcct -CheckId "nondefault-pgid" `
    -Title "Users and computers with non-default Primary Group IDs" -Severity "Medium" -Test {
    $defaults = 513, 514, 515, 516, 521
    $users = Get-ADUser -Filter * -Properties primaryGroupID |
        Where-Object { $_.primaryGroupID -and ($_.primaryGroupID -notin $defaults) } |
        Select-Object Name, SamAccountName, primaryGroupID -First 25
    $comps = Get-ADComputer -Filter * -Properties primaryGroupID |
        Where-Object { $_.primaryGroupID -and ($_.primaryGroupID -notin $defaults) } |
        Select-Object Name, primaryGroupID -First 25
    $count = @($users).Count + @($comps).Count
    Add-ReviewResult -Section $secAcct -CheckId "nondefault-pgid" `
        -Title "Users and computers with non-default Primary Group IDs" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count object(s) with non-default primaryGroupID" -Evidence @{ Users = $users; Computers = $comps }
}

Invoke-Check -Section $secAcct -CheckId "alt-security-identities" `
    -Title "Accounts with altSecurityIdentities configured" -Severity "Medium" -Test {
    $hits = Get-ADObject -LDAPFilter '(altSecurityIdentities=*)' -Properties altSecurityIdentities, objectClass |
        Select-Object Name, objectClass, altSecurityIdentities
    $count = @($hits).Count
    Add-ReviewResult -Section $secAcct -CheckId "alt-security-identities" `
        -Title "Accounts with altSecurityIdentities configured" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count object(s) with altSecurityIdentities mappings (certificate/Kerberos name mapping - verify each mapping is expected)." `
        -Evidence ($hits | Select-Object -First 25)
}

Invoke-Check -Section $secAcct -CheckId "computer-pwd-prohibited" `
    -Title "Computer Account Password Change Prohibited" -Severity "Medium" -Test {
    $cantChangeFlag = 0x40
    $flagged = Get-ADComputer -Filter * -Properties userAccountControl, PasswordLastSet |
        Where-Object {
            ($_.userAccountControl -band $cantChangeFlag) -or
            (-not $_.PasswordLastSet) -or
            ($_.PasswordLastSet -lt (Get-Date).AddDays(-90))
        } | Select-Object Name, userAccountControl, PasswordLastSet
    $count = @($flagged).Count
    Add-ReviewResult -Section $secAcct -CheckId "computer-pwd-prohibited" `
        -Title "Computer Account Password Change Prohibited" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count computer account(s) with PASSWD_CANT_CHANGE set, no PasswordLastSet, or PasswordLastSet stale >90 days (default machine password rotation is ~30 days)." `
        -Evidence ($flagged | Select-Object -First 25)
}

Invoke-Check -Section $secAcct -CheckId "logon-script-acl" `
    -Title "Users Able to Modify Logon Scripts" -Severity "Medium" -Test {
    $usersWithScript = Get-ADUser -Filter 'scriptPath -like "*"' -Properties scriptPath |
        Select-Object Name, SamAccountName, scriptPath
    $count = @($usersWithScript).Count
    $writable = @()
    if (Test-RunningOnDomainController) {
        $sysvolScripts = "\\$($script:DomainDns)\SYSVOL\$($script:DomainDns)\scripts"
        try {
            $acl = Get-Acl $sysvolScripts -ErrorAction Stop
            $writable = @($acl.Access | Where-Object {
                $_.FileSystemRights -match 'Write|Modify|FullControl' -and
                $_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|CREATOR OWNER'
            } | Select-Object IdentityReference, FileSystemRights)
        }
        catch {
            # SYSVOL scripts share may not exist or may be unreachable; fall back to inventory-only result.
        }
    }
    $status = if ($writable.Count -gt 0) { "FAIL" } elseif ($count -gt 0) { "REVIEW" } else { "PASS" }
    Add-ReviewResult -Section $secAcct -CheckId "logon-script-acl" `
        -Title "Users Able to Modify Logon Scripts" -Status $status `
        -Summary "$count user(s) with scriptPath configured; $($writable.Count) non-default writer(s) found on SYSVOL scripts share (checked only when run on a DC)." `
        -Evidence @{ Users = ($usersWithScript | Select-Object -First 25); SysvolScriptsAcl = $writable }
}

Invoke-Check -Section $secAcct -CheckId "dpapi-acl" `
    -Title "Non-default principals with access to DPAPI key" -Severity "Critical" -Test {
    # BCKUPKEY_* DPAPI backup key objects (objectClass=secret) live directly under CN=System
    # in the domain partition, not under a CN=Secrets sub-container (see DSInternals research).
    $dpapiBase = "CN=System,$($script:DomainDn)"
    try {
        $dpapiObjects = @(Get-ADObject -SearchBase $dpapiBase -SearchScope OneLevel -Filter 'objectClass -eq "secret"' -ErrorAction Stop)
    }
    catch {
        Add-ReviewResult -Section $secAcct -CheckId "dpapi-acl" `
            -Title "Non-default principals with access to DPAPI key" -Status "MANUAL" `
            -Summary "Could not read $dpapiBase - verify read rights or check manually with DSInternals Get-ADReplBackupKey / Get-BootKey."
        return
    }
    if ($dpapiObjects.Count -eq 0) {
        Add-ReviewResult -Section $secAcct -CheckId "dpapi-acl" `
            -Title "Non-default principals with access to DPAPI key" -Status "REVIEW" `
            -Summary "No DPAPI backup key secret objects found under $dpapiBase (unexpected on a healthy domain - verify manually)."
        return
    }
    $hits = @()
    foreach ($obj in $dpapiObjects) {
        $acl = Get-Acl "AD:\$($obj.DistinguishedName)" -ErrorAction SilentlyContinue
        if (-not $acl) { continue }
        $hits += $acl.Access | Where-Object {
            $_.IdentityReference -notmatch 'NT AUTHORITY\\SYSTEM|Domain Admins|Enterprise Admins|Administrators|Domain Controllers|Enterprise Domain Controllers'
        } | Select-Object @{N='Object';E={$obj.Name}}, IdentityReference, ActiveDirectoryRights, AccessControlType
    }
    $count = @($hits).Count
    Add-ReviewResult -Section $secAcct -CheckId "dpapi-acl" `
        -Title "Non-default principals with access to DPAPI key" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count non-default ACE(s) on DPAPI backup key object(s) under $dpapiBase" -Evidence ($hits | Select-Object -First 25)
}

Invoke-Check -Section $secAcct -CheckId "server-trust-delegation" `
    -Title "Users with permissions to set Server Trust Account" -Severity "High" -Test {
    $schemaNc = (Get-ADRootDSE).schemaNamingContext
    $computerSchema = Get-ADObject -SearchBase $schemaNc -Filter "lDAPDisplayName -eq 'computer'" -Properties schemaIDGUID
    if (-not $computerSchema) {
        Add-ReviewResult -Section $secAcct -CheckId "server-trust-delegation" `
            -Title "Users with permissions to set Server Trust Account" -Status "MANUAL" `
            -Summary "Could not resolve 'computer' class schemaIDGUID - verify Create Computer Objects delegation manually."
        return
    }
    $computerGuid = [System.Guid]$computerSchema.schemaIDGUID
    $acl = Get-Acl "AD:\$($script:DomainDn)"
    $hits = $acl.Access | Where-Object {
        $_.ActiveDirectoryRights -match 'CreateChild' -and
        $_.ObjectType -eq $computerGuid -and
        $_.IdentityReference -notmatch 'NT AUTHORITY\\SYSTEM|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Administrators|Account Operators'
    } | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType
    $count = @($hits).Count
    Add-ReviewResult -Section $secAcct -CheckId "server-trust-delegation" `
        -Title "Users with permissions to set Server Trust Account" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count non-default principal(s) delegated Create Computer Objects at domain root (OU-level delegation not scanned - review manually with dsacls)." `
        -Evidence $hits
}

Invoke-Check -Section $secAcct -CheckId "native-da-usage" `
    -Title "Native Domain Controller Administrator in Use" -Severity "Medium" -Test {
    $admin = Get-ADUser -Filter { SamAccountName -eq 'Administrator' } -Properties LastLogonDate, PasswordLastSet `
        -ErrorAction SilentlyContinue
    if (-not $admin) {
        Add-ReviewResult -Section $secAcct -CheckId "native-da-usage" `
            -Title "Native Domain Controller Administrator in Use" -Status "MANUAL" `
            -Summary "Built-in Administrator (RID 500) account not found by SamAccountName - verify manually if renamed."
        return
    }
    $recentlyUsed = $admin.LastLogonDate -and ($admin.LastLogonDate -gt (Get-Date).AddDays(-30))
    Add-ReviewResult -Section $secAcct -CheckId "native-da-usage" `
        -Title "Native Domain Controller Administrator in Use" `
        -Status $(if ($recentlyUsed) { "REVIEW" } else { "PASS" }) `
        -Summary "Built-in Administrator LastLogonDate=$($admin.LastLogonDate) (LastLogonDate is not replicated - value reflects only the queried DC)." `
        -Evidence $admin `
        -Remediation "Use named, tiered admin accounts instead of the built-in RID 500 Administrator for day-to-day tasks."
}

# ---------------------------------------------------------------------------
# Group settings
# ---------------------------------------------------------------------------

Invoke-Check -Section $secGroup -CheckId "excessive-domain-admins" `
    -Title "Excessive Domain Admins Configured" -Severity "High" -Test {
    $members = @(Get-ADGroupMember 'Domain Admins')
    $count = $members.Count
    $status = if ($count -le 5) { "PASS" } elseif ($count -le 10) { "REVIEW" } else { "FAIL" }
    Add-ReviewResult -Section $secGroup -CheckId "excessive-domain-admins" `
        -Title "Excessive Domain Admins Configured" -Status $status `
        -Summary "Domain Admins count: $count" -Evidence ($members | Select-Object Name, SamAccountName, objectClass)
}

Invoke-Check -Section $secGroup -CheckId "protected-users" `
    -Title "Protected Users Group Misconfigured" -Severity "Medium" -Test {
    if (-not (Test-ADDomainModeAtLeast 'Windows2012R2Domain')) {
        Add-ReviewResult -Section $secGroup -CheckId "protected-users" `
            -Title "Protected Users Group Misconfigured" -Status "SKIP" `
            -Summary "Protected Users requires domain functional level Windows Server 2012 R2 or higher (current: $($script:ADDomain.DomainMode))."
        return
    }
    try {
        $pu = Get-ADGroup 'Protected Users' -ErrorAction Stop
    }
    catch {
        Add-ReviewResult -Section $secGroup -CheckId "protected-users" `
            -Title "Protected Users Group Misconfigured" -Status "REVIEW" `
            -Summary "Protected Users group not found on this domain."
        return
    }
    $puMembers = @(Get-ADGroupMember $pu -ErrorAction SilentlyContinue)
    $daMembers = @(Get-ADGroupMember 'Domain Admins')
    $missing = @()
    foreach ($da in $daMembers) {
        if ($da.objectClass -ne 'user') { continue }
        if ($puMembers.SamAccountName -notcontains $da.SamAccountName) { $missing += $da.Name }
    }
    Add-ReviewResult -Section $secGroup -CheckId "protected-users" `
        -Title "Protected Users Group Misconfigured" `
        -Status $(if ($missing.Count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "Protected Users members: $($puMembers.Count); privileged users not in group: $($missing.Count)" `
        -Evidence @{ MissingFromProtectedUsers = $missing }
}

Invoke-Check -Section $secGroup -CheckId "operator-groups" `
    -Title "Operator Groups in Use" -Severity "Medium" -Test {
    $groups = 'Account Operators', 'Server Operators', 'Backup Operators', 'Print Operators'
    $nonEmpty = @()
    foreach ($g in $groups) {
        $m = @(Get-ADGroupMember $g -ErrorAction SilentlyContinue)
        if ($m.Count -gt 0) { $nonEmpty += [PSCustomObject]@{ Group = $g; Count = $m.Count; Members = ($m.Name -join ', ') } }
    }
    Add-ReviewResult -Section $secGroup -CheckId "operator-groups" -Title "Operator Groups in Use" `
        -Status $(if ($nonEmpty.Count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$($nonEmpty.Count) operator group(s) contain members" -Evidence $nonEmpty
}

Invoke-Check -Section $secGroup -CheckId "prewin2000" `
    -Title "Pre-Windows 2000 compatibility Group Misconfigured" -Severity "High" -Test {
    $members = @(Get-ADGroupMember 'Pre-Windows 2000 Compatible Access' -ErrorAction SilentlyContinue)
    $bad = $members | Where-Object { $_.Name -match 'Authenticated Users|Everyone|Anonymous' }
    Add-ReviewResult -Section $secGroup -CheckId "prewin2000" `
        -Title "Pre-Windows 2000 compatibility Group Misconfigured" `
        -Status $(if (@($bad).Count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "Pre-Windows 2000 Compatible Access members: $($members.Count); risky: $(@($bad).Count)" `
        -Evidence $members
}

Invoke-Check -Section $secGroup -CheckId "computer-in-priv-group" `
    -Title "Computer Accounts in Privileged Group" -Severity "High" -Test {
    $hits = @()
    foreach ($g in @('Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
        $hits += Get-ADGroupMember $g -ErrorAction SilentlyContinue | Where-Object { $_.objectClass -eq 'computer' } |
            Select-Object @{N='Group';E={$g}}, Name, SamAccountName
    }
    $count = @($hits).Count
    Add-ReviewResult -Section $secGroup -CheckId "computer-in-priv-group" `
        -Title "Computer Accounts in Privileged Group" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count computer account(s) in privileged groups" -Evidence $hits
}

Invoke-Check -Section $secGroup -CheckId "fsp-priv-group" `
    -Title "Foreign Security Principals in Privileged Group" -Severity "High" -Test {
    $hits = @()
    foreach ($g in @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')) {
        $hits += Get-ADGroupMember $g -ErrorAction SilentlyContinue |
            Where-Object { $_.objectClass -eq 'foreignSecurityPrincipal' } |
            Select-Object @{N='Group';E={$g}}, Name, SID
    }
    $count = @($hits).Count
    Add-ReviewResult -Section $secGroup -CheckId "fsp-priv-group" `
        -Title "Foreign Security Principals in Privileged Group" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count foreign security principal(s) in privileged groups (cross-domain/cross-forest trust identity - verify expected)." `
        -Evidence $hits
}

# ---------------------------------------------------------------------------
# Domain settings
# ---------------------------------------------------------------------------

Invoke-Check -Section $secDomain -CheckId "ds-heuristics" `
    -Title "Weak DsHeuristics Configuration" -Severity "Medium" -Test {
    $ds = Get-DirectoryServiceConfig
    $h = $ds.dsHeuristics
    Add-ReviewResult -Section $secDomain -CheckId "ds-heuristics" -Title "Weak DsHeuristics Configuration" `
        -Status "INFO" `
        -Summary "dsHeuristics=$(if ($h) { $h } else { '(not set - all defaults apply)' }). Anonymous LDAP (pos 7) and AdminSDHolder exclusions (pos 16) are scored individually by the anonymous-ldap and adminsdholder checks." `
        -Evidence $ds
}

Invoke-Check -Section $secDomain -CheckId "adminsdholder" `
    -Title "AdminSDHolder protection Disabled" -Severity "High" -Test {
    $ds = Get-DirectoryServiceConfig
    $h = $ds.dsHeuristics
    $maskChar = if ($h -and $h.Length -ge 16) { $h[15] } else { '0' }
    $maskValue = 0
    try { $maskValue = [Convert]::ToInt32([string]$maskChar, 16) } catch { $maskValue = 0 }
    $excludedGroups = [System.Collections.Generic.List[string]]::new()
    if ($maskValue -band 0x1) { $excludedGroups.Add('Account Operators') }
    if ($maskValue -band 0x2) { $excludedGroups.Add('Server Operators') }
    if ($maskValue -band 0x4) { $excludedGroups.Add('Print Operators') }
    if ($maskValue -band 0x8) { $excludedGroups.Add('Backup Operators') }
    Add-ReviewResult -Section $secDomain -CheckId "adminsdholder" `
        -Title "AdminSDHolder protection Disabled" `
        -Status $(if ($excludedGroups.Count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "dwAdminSDExMask (dsHeuristics pos 16)='$maskChar'; groups excluded from AdminSDHolder/SDProp protection: $(if ($excludedGroups.Count -gt 0) { $excludedGroups -join ', ' } else { 'none' })" `
        -Evidence @{ DsHeuristics = $h; DwAdminSDExMask = $maskChar; ExcludedGroups = $excludedGroups } `
        -Remediation "Set dsHeuristics position 16 back to '0' so all default operator groups remain protected by AdminSDHolder/SDProp."
}

Invoke-Check -Section $secDomain -CheckId "sid-history" `
    -Title "SID History Misconfiguration" -Severity "High" -Test {
    $users = @(Get-ADUser -Filter 'sidHistory -like "*"' -Properties sidHistory -ErrorAction SilentlyContinue)
    $comps = @(Get-ADComputer -Filter 'sidHistory -like "*"' -Properties sidHistory -ErrorAction SilentlyContinue)
    $count = $users.Count + $comps.Count
    Add-ReviewResult -Section $secDomain -CheckId "sid-history" -Title "SID History Misconfiguration" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count object(s) with sidHistory populated" `
        -Evidence @{ Users = ($users | Select-Object -First 10 Name, sidHistory); Computers = ($comps | Select-Object -First 10 Name, sidHistory) }
}

Invoke-Check -Section $secDomain -CheckId "trust-sid-filter" `
    -Title "SID Filtering not Enabled" -Severity "High" -Test {
    $trusts = Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, TrustAttributes
    $issues = @()
    foreach ($t in $trusts) {
        if ($t.TrustType -eq 'External') { continue }
        if ($t.TrustAttributes -band 0x4) { continue } # quarantined / selective
        if ($t.Direction -eq 'Inbound' -or $t.Direction -eq 'BiDirectional') {
            $issues += "$($t.Name) ($($t.Direction))"
        }
    }
    Add-ReviewResult -Section $secDomain -CheckId "trust-sid-filter" -Title "SID Filtering not Enabled" `
        -Status $(if ($issues.Count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$($issues.Count) inbound/bidirectional trust(s) to review for SID filtering" `
        -Evidence $trusts
}

Invoke-Check -Section $secDomain -CheckId "nt4-trusts" `
    -Title "NT4 Trusts Configured" -Severity "Medium" -Test {
    $hits = Get-ADTrust -Filter * | Where-Object { $_.TrustType -eq 'Downlevel' }
    $count = @($hits).Count
    Add-ReviewResult -Section $secDomain -CheckId "nt4-trusts" -Title "NT4 Trusts Configured" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count downlevel (NT4) trust(s)" -Evidence $hits
}

Invoke-Check -Section $secDomain -CheckId "weak-password-hashing" `
    -Title "Weak Password Hashing Permitted" -Severity "High" -Test {
    $useDesOnlyFlag = 0x200000
    $users = Get-ADUser -Filter 'userAccountControl -band 2097152' -Properties userAccountControl |
        Select-Object Name, SamAccountName, userAccountControl
    $count = @($users).Count
    Add-ReviewResult -Section $secDomain -CheckId "weak-password-hashing" `
        -Title "Weak Password Hashing Permitted" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count account(s) with USE_DES_KEY_ONLY (0x$('{0:X}' -f $useDesOnlyFlag)) set - forces weak DES Kerberos keys." `
        -Evidence $users
}

Invoke-Check -Section $secDomain -CheckId "kerberos-weak-objects" `
    -Title "Weak Kerberos Configuration" -Severity "High" -Test {
    $desOrRc4 = Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=*)' -Properties msDS-SupportedEncryptionTypes, objectClass |
        Where-Object {
            $v = [int]$_.'msDS-SupportedEncryptionTypes'
            ($v -band 0x1) -or ($v -band 0x2) -or ($v -band 0x4)
        } | Select-Object Name, objectClass, @{N='SupportedEncryptionTypes';E={$_.'msDS-SupportedEncryptionTypes'}}
    $count = @($desOrRc4).Count
    Add-ReviewResult -Section $secDomain -CheckId "kerberos-weak-objects" `
        -Title "Weak Kerberos Configuration" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count object(s) with msDS-SupportedEncryptionTypes permitting DES/RC4 (bits 0x1/0x2/0x4)." `
        -Evidence ($desOrRc4 | Select-Object -First 25) `
        -Remediation "Set msDS-SupportedEncryptionTypes to AES only (0x18) where supported by the account's clients/services."
}

Invoke-Check -Section $secDomain -CheckId "domain-ntlm-restrict" `
    -Title "Domain NTLM authentication policy not restricted" -Severity "Medium" -Test {
    if (-not (Test-RunningOnDomainController)) {
        Add-ReviewResult -Section $secDomain -CheckId "domain-ntlm-restrict" `
            -Title "Domain NTLM authentication policy not restricted" -Status "MANUAL" `
            -Summary "Run on a DC, or review 'Network security: Restrict NTLM' GPO settings via RSOP/PingCastle." `
            -Remediation "Set Network security: Restrict NTLM: Incoming/Outgoing NTLM traffic policies to Deny or Audit-then-Deny."
        return
    }
    # Values: 0/unset = Allow all (not restricted), 1 = Audit all (logs only, nothing blocked),
    # 2 = Deny all (actually enforced). Only 2 constitutes real restriction; 1 is audit-only.
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
        -Name RestrictSendingNTLMTraffic, RestrictReceivingNTLMTraffic -ErrorAction SilentlyContinue
    $incoming = $lsa.RestrictReceivingNTLMTraffic
    $outgoing = $lsa.RestrictSendingNTLMTraffic
    $enforced = ($incoming -eq 2) -or ($outgoing -eq 2)
    $auditOnly = (-not $enforced) -and (($incoming -eq 1) -or ($outgoing -eq 1))
    $status = if ($enforced) { "PASS" } else { "REVIEW" }
    $summary = if ($enforced) {
        "RestrictSendingNTLMTraffic=$outgoing; RestrictReceivingNTLMTraffic=$incoming (Deny all enforced on at least one direction)."
    }
    elseif ($auditOnly) {
        "RestrictSendingNTLMTraffic=$outgoing; RestrictReceivingNTLMTraffic=$incoming (Audit-only - NTLM traffic is logged but NOT blocked; set to 2/Deny to enforce)."
    }
    else {
        "RestrictSendingNTLMTraffic=$outgoing; RestrictReceivingNTLMTraffic=$incoming (0/unset = not restricted)."
    }
    Add-ReviewResult -Section $secDomain -CheckId "domain-ntlm-restrict" `
        -Title "Domain NTLM authentication policy not restricted" `
        -Status $status -Summary $summary -Evidence $lsa
}

Invoke-Check -Section $secDomain -CheckId "recycle-bin" `
    -Title "Recycle Bin Disabled" -Severity "Low" -Test {
    $rb = Get-ADOptionalFeature -Filter 'Name -like "*Recycle Bin*"' -ErrorAction SilentlyContinue
    $enabled = $rb -and $rb.EnabledScopes.Count -gt 0
    Add-ReviewResult -Section $secDomain -CheckId "recycle-bin" -Title "Recycle Bin Disabled" `
        -Status $(if ($enabled) { "PASS" } else { "REVIEW" }) `
        -Summary "AD Recycle Bin enabled = $enabled" -Evidence $rb
}

Invoke-Check -Section $secDomain -CheckId "functional-level" `
    -Title "Obsolete Domain Functional Level" -Severity "Medium" -Test {
    $domainMode = [string]$script:ADDomain.DomainMode
    $forestMode = [string]$script:ADForest.ForestMode
    $old = @('Windows2000', 'Windows2003', 'Windows2008', 'Windows2008R2')
    $isOld = ($old | Where-Object { $domainMode -like "*$_*" -or $forestMode -like "*$_*" }).Count -gt 0
    Add-ReviewResult -Section $secDomain -CheckId "functional-level" -Title "Obsolete Domain Functional Level" `
        -Status $(if (-not $isOld) { "PASS" } else { "REVIEW" }) `
        -Summary "DomainMode=$domainMode; ForestMode=$forestMode" `
        -Evidence @{ DomainMode = $domainMode; ForestMode = $forestMode }
}

Invoke-Check -Section $secDomain -CheckId "ntfrs-sysvol" `
    -Title "NTFRS Enabled" -Severity "Medium" -Test {
    Add-ReviewResult -Section $secDomain -CheckId "ntfrs-sysvol" -Title "NTFRS Enabled" `
        -Status "MANUAL" -Summary "Run dfsrmig /getmigrationstate on a DC to confirm DFSR SYSVOL replication." `
        -Remediation "Migrate off NTFRS if migration state is not Native."
}

if (Test-RunningOnDomainController) {
    Invoke-Check -Section $secDomain -CheckId "net-cease" `
        -Title "Net Cease not Enabled" -Severity "Medium" -Test {
        $netSessionEnum = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity' `
            -Name SrvsvcSessionInfo -ErrorAction SilentlyContinue
        $hardened = [bool]$netSessionEnum
        Add-ReviewResult -Section $secDomain -CheckId "net-cease" -Title "Net Cease not Enabled" `
            -Status $(if ($hardened) { "PASS" } else { "REVIEW" }) `
            -Summary $(if ($hardened) { "SrvsvcSessionInfo ACL override present (NetSessionEnum access appears restricted)." } `
                else { "No SrvsvcSessionInfo ACL override found - NetSessionEnum (NetCease) likely not hardened." }) `
            -Remediation "Apply the NetCease (harden-srvsvc-config) ACL to restrict NetSessionEnum to admins."
    }

    Invoke-Check -Section $secDomain -CheckId "null-sessions" `
        -Title "Null Sessions Permitted" -Severity "High" -Test {
        $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
            -Name RestrictAnonymous, RestrictAnonymousSAM, EveryoneIncludesAnonymous -ErrorAction SilentlyContinue
        $issues = @()
        if (-not ($lsa.RestrictAnonymous -ge 1)) { $issues += "RestrictAnonymous=$($lsa.RestrictAnonymous)" }
        if (-not ($lsa.RestrictAnonymousSAM -ge 1)) { $issues += "RestrictAnonymousSAM=$($lsa.RestrictAnonymousSAM)" }
        if ($lsa.EveryoneIncludesAnonymous -eq 1) { $issues += "EveryoneIncludesAnonymous=1" }
        Add-ReviewResult -Section $secDomain -CheckId "null-sessions" -Title "Null Sessions Permitted" `
            -Status $(if ($issues.Count -eq 0) { "PASS" } else { "FAIL" }) `
            -Summary $(if ($issues) { $issues -join '; ' } else { "Anonymous access restrictions look enforced on this DC." }) `
            -Evidence $lsa
    }

    Invoke-Check -Section $secDomain -CheckId "anonymous-ldap" `
        -Title "Anonymous Access to the Domain Configured" -Severity "High" -Test {
        $ds = Get-DirectoryServiceConfig
        $h = $ds.dsHeuristics
        # Per [MS-ADTS] dSHeuristics spec: position 7 (fLDAPBlockAnonOps) - if this character
        # is '2', the block-anonymous-ops heuristic is FALSE (anonymous LDAP beyond RootDSE is
        # ALLOWED, insecure - also DISA STIG V-243503). Any other value (including unset/default)
        # means the heuristic is TRUE (blocking enforced, secure).
        $anonymousLdapAllowed = ($h -and $h.Length -ge 7 -and $h[6] -eq '2')
        Add-ReviewResult -Section $secDomain -CheckId "anonymous-ldap" -Title "Anonymous Access to the Domain Configured" `
            -Status $(if ($anonymousLdapAllowed) { "FAIL" } else { "PASS" }) `
            -Summary "dsHeuristics fLDAPBlockAnonOps (pos 7)=$(if ($h -and $h.Length -ge 7) { $h[6] } else { '(not set - defaults to blocked)' }) ('2' allows anonymous LDAP beyond RootDSE if ACLs permit - insecure; any other value/unset blocks it)." `
            -Evidence $ds
    }
}
else {
    foreach ($manualDc in @(
        @{ Id = "net-cease"; Title = "Net Cease not Enabled" }
        @{ Id = "null-sessions"; Title = "Null Sessions Permitted" }
        @{ Id = "anonymous-ldap"; Title = "Anonymous Access to the Domain Configured" }
    )) {
        Add-ReviewResult -Section $secDomain -CheckId $manualDc.Id -Title $manualDc.Title -Status "MANUAL" `
            -Summary "Run ADReview on a domain controller for this registry-based check, or verify via PingCastle/Purple Knight."
    }
}

Add-ReviewResult -Section $secDomain -CheckId "gpo-delegation-manual" `
    -Title "Excessive Privileges Configured / Weak GPO Configuration" -Status "MANUAL" -Severity "High" `
    -Summary "Review dangerous OU/GPO delegations with PingCastle/Purple Knight or BloodHound ACL analysis." `
    -Remediation "Map ACLs on OUs, AdminSDHolder, and GPO links."

# ---------------------------------------------------------------------------
# Service settings (AD-integrated)
# ---------------------------------------------------------------------------

Invoke-Check -Section $secSvc -CheckId "dns-admins" `
    -Title "Weak DNS Configuration" -Severity "High" -Test {
    $dnsAdmins = @(Get-ADGroupMember 'DnsAdmins' -ErrorAction SilentlyContinue)
    $nonStandard = $dnsAdmins | Where-Object { $_.Name -notmatch 'Administrator|SYSTEM|DnsAdmins' }
    Add-ReviewResult -Section $secSvc -CheckId "dns-admins" -Title "Weak DNS Configuration" `
        -Status $(if (@($nonStandard).Count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "DnsAdmins members: $($dnsAdmins.Count); non-standard: $(@($nonStandard).Count)" `
        -Evidence $dnsAdmins
}

Invoke-Check -Section $secSvc -CheckId "gmsa-inventory" `
    -Title "Weak gMSA Configuration" -Severity "Medium" -Test {
    $gmsa = @(Get-ADServiceAccount -Filter * -Properties PasswordLastSet, Enabled -ErrorAction SilentlyContinue)
    $old = $gmsa | Where-Object { $_.PasswordLastSet -and $_.PasswordLastSet -lt (Get-Date).AddDays(-180) }
    Add-ReviewResult -Section $secSvc -CheckId "gmsa-inventory" -Title "Weak gMSA Configuration" `
        -Status $(if (@($old).Count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "gMSA count: $($gmsa.Count); password last set >180d: $(@($old).Count)" `
        -Evidence ($gmsa | Select-Object Name, Enabled, PasswordLastSet)
}

Invoke-Check -Section $secSvc -CheckId "laps-ad-storage" `
    -Title "Windows LAPS passwords not stored in Active Directory" -Severity "Medium" -Test {
    $legacy = @(Search-ADObjectsByAttribute -AttributeName 'ms-Mcs-AdmPwdExpirationTime')
    $modern = @(Search-ADObjectsByAttribute -AttributeName 'msLAPS-PasswordExpirationTime')
    $count = $legacy.Count + $modern.Count
    $schemaNote = if ($legacy.Count -eq 0 -and $modern.Count -eq 0) {
        'No LAPS attributes in AD schema or no objects populated (legacy LAPS / Windows LAPS not in use).'
    } else { '' }
    Add-ReviewResult -Section $secSvc -CheckId "laps-ad-storage" `
        -Title "Windows LAPS passwords not stored in Active Directory" `
        -Status $(if ($count -gt 0) { "PASS" } else { "REVIEW" }) `
        -Summary "Objects with LAPS password attributes: $count (legacy=$($legacy.Count), modern=$($modern.Count)). $schemaNote"
}

if (Test-RunningOnDomainController) {
    Invoke-Check -Section $secSvc -CheckId "ldap-signing-dc" `
        -Title "Weak LDAP Configuration" -Severity "High" -Test {
        $ntds = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
            -Name LdapEnforceChannelBinding, LDAPServerIntegrity -ErrorAction SilentlyContinue
        $issues = @()
        if ($ntds.LDAPServerIntegrity -ne 2) { $issues += "LDAPServerIntegrity=$($ntds.LDAPServerIntegrity) (expect 2=Require signing)" }
        if ($ntds.LdapEnforceChannelBinding -notin 1, 2) { $issues += "LdapEnforceChannelBinding=$($ntds.LdapEnforceChannelBinding)" }
        Add-ReviewResult -Section $secSvc -CheckId "ldap-signing-dc" -Title "Weak LDAP Configuration" `
            -Status $(if ($issues.Count -eq 0) { "PASS" } else { "FAIL" }) `
            -Summary $(if ($issues) { $issues -join '; ' } else { "LDAP signing/channel binding look enforced on this DC." }) `
            -Evidence $ntds
    }

    Invoke-Check -Section $secSvc -CheckId "kerberos-encryption" `
        -Title "Weak Encryption Methods Supported" -Severity "High" -Test {
        $k = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
            -Name SupportedEncryptionTypes -ErrorAction SilentlyContinue
        $val = [int]$k.SupportedEncryptionTypes
        # Bitmask: 0x1=DES-CBC-CRC, 0x2=DES-CBC-MD5, 0x4=RC4-HMAC (weak); 0x8=AES128, 0x10=AES256 (strong).
        $weak = ($val -band 0x1) -or ($val -band 0x2) -or ($val -band 0x4)
        Add-ReviewResult -Section $secSvc -CheckId "kerberos-encryption" `
            -Title "Weak Encryption Methods Supported" `
            -Status $(if (-not $weak) { "PASS" } else { "FAIL" }) `
            -Summary "SupportedEncryptionTypes=$val (DES/RC4 bits may be enabled)" -Evidence $k
    }
}
else {
    Add-ReviewResult -Section $secSvc -CheckId "ldap-signing-dc" -Title "Weak LDAP Configuration" `
        -Status "MANUAL" -Summary "Run ADReview on a DC, or verify LDAP signing via PingCastle / GPO on DCs." `
        -Remediation "LDAPServerIntegrity=2; LdapEnforceChannelBinding=1 or 2 on each DC."
    Add-ReviewResult -Section $secSvc -CheckId "kerberos-encryption" `
        -Title "Weak Encryption Methods Supported" -Status "MANUAL" `
        -Summary "Run on a DC for SupportedEncryptionTypes registry check, or use PingCastle S-DesEnabled."
}

Invoke-Check -Section $secSvc -CheckId "aad-connect-account" `
    -Title "AAD Connect sync account not secured" -Severity "High" -Test {
    $sync = Get-ADUser -Filter "Description -like '*Azure*AD*Connect*'" -Properties PasswordLastSet, Enabled -ErrorAction SilentlyContinue
    if (-not $sync) {
        $sync = Get-ADUser -Filter "Name -like '*Sync_*'" -Properties PasswordLastSet -ErrorAction SilentlyContinue | Select-Object -First 5
    }
    Add-ReviewResult -Section $secSvc -CheckId "aad-connect-account" `
        -Title "AAD Connect sync account not secured" `
        -Status $(if ($sync) { "REVIEW" } else { "SKIP" }) `
        -Summary $(if ($sync) { "Hybrid sync account(s) found - review password rotation and group membership." } else { "No obvious AAD Connect account in AD." }) `
        -Evidence $sync
}

# ---------------------------------------------------------------------------
# Privilege delegation
# ---------------------------------------------------------------------------

Invoke-Check -Section $secDeleg -CheckId "unconstrained-delegation" `
    -Title "Unconstrained Delegation Configured" -Severity "Critical" -Test {
    $computers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
        -Properties TrustedForDelegation, servicePrincipalName, PrimaryGroupID |
        Where-Object { $_.PrimaryGroupID -notin 516, 521 } |
        Select-Object Name, TrustedForDelegation, servicePrincipalName
    $users = Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
        Select-Object Name, SamAccountName, TrustedForDelegation
    $count = @($computers).Count + @($users).Count
    Add-ReviewResult -Section $secDeleg -CheckId "unconstrained-delegation" `
        -Title "Unconstrained Delegation Configured" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count object(s) with TrustedForDelegation (excluding DC/RODC groups)" `
        -Evidence @{ Computers = $computers; Users = $users }
}

Invoke-Check -Section $secDeleg -CheckId "constrained-delegation" `
    -Title "Kerberos Constrained Delegation Misconfigured" -Severity "High" -Test {
    $hits = Get-ADObject -Filter 'msDS-AllowedToDelegateTo -like "*"' -Properties msDS-AllowedToDelegateTo, objectClass |
        Select-Object Name, objectClass, msDS-AllowedToDelegateTo -First 30
    $count = @(Get-ADObject -Filter 'msDS-AllowedToDelegateTo -like "*"').Count
    Add-ReviewResult -Section $secDeleg -CheckId "constrained-delegation" `
        -Title "Kerberos Constrained Delegation Misconfigured" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count object(s) with msDS-AllowedToDelegateTo" -Evidence $hits
}

Invoke-Check -Section $secDeleg -CheckId "rbcd-delegation" `
    -Title "Domain Controller with Constrained Delegation Enabled" -Severity "Critical" -Test {
    $hits = Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, PrimaryGroupID |
        Where-Object { $_.PrimaryGroupID -eq 516 -and $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } |
        Select-Object Name, msDS-AllowedToActOnBehalfOfOtherIdentity
    $count = @($hits).Count
    Add-ReviewResult -Section $secDeleg -CheckId "rbcd-delegation" `
        -Title "Domain Controller with Constrained Delegation Enabled" `
        -Status $(if ($count -eq 0) { "PASS" } else { "FAIL" }) `
        -Summary "$count DC(s) with RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) configured" -Evidence $hits
}

Invoke-Check -Section $secDeleg -CheckId "delegation-orphan-spn" `
    -Title "Delegations with no Receiver" -Severity "Medium" -Test {
    $spnMap = @{}
    Get-ADObject -Filter 'servicePrincipalName -like "*"' -Properties servicePrincipalName |
        ForEach-Object {
            foreach ($spn in $_.servicePrincipalName) { $spnMap[$spn.ToLowerInvariant()] = $_.DistinguishedName }
        }
    $delegators = Get-ADObject -Filter 'msDS-AllowedToDelegateTo -like "*"' -Properties msDS-AllowedToDelegateTo, Name
    $orphans = [System.Collections.Generic.List[object]]::new()
    foreach ($d in $delegators) {
        foreach ($target in $d.'msDS-AllowedToDelegateTo') {
            if (-not $spnMap.ContainsKey($target.ToLowerInvariant())) {
                $orphans.Add([PSCustomObject]@{ Delegator = $d.Name; TargetSpn = $target })
            }
        }
    }
    $count = $orphans.Count
    Add-ReviewResult -Section $secDeleg -CheckId "delegation-orphan-spn" `
        -Title "Delegations with no Receiver" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count constrained-delegation target SPN(s) do not match any currently registered SPN (orphaned target - could be re-registered by an attacker)." `
        -Evidence ($orphans | Select-Object -First 25) `
        -Remediation "Remove stale msDS-AllowedToDelegateTo entries pointing at SPNs no longer in use."
}

Add-ReviewResult -Section $secDeleg -CheckId "delegation-acl-manual" `
    -Title "Delegation granted to Any User / GPO Linking Delegation" -Status "MANUAL" -Severity "High" `
    -Summary "Use BloodHound/PingCastle for Everyone/Authenticated Users delegation and GPO link ACLs." `
    -Remediation "Review AdminSDHolder, OU ACLs, and GPO link permissions."

# ---------------------------------------------------------------------------
# Certificate settings (ADCS) - manual on non-CA hosts
# ---------------------------------------------------------------------------

Add-ReviewResult -Section $secCert -CheckId "adcs-templates" `
    -Title "AD CS template and enrollment posture" -Status "MANUAL" -Severity "High" `
    -Summary "Run certutil -template -v on an enterprise CA, or use PingCastle/Purple Knight ADCS rules." `
    -Remediation "Review ESC1-ESC8 patterns, HTTP enrollment, and template ACLs."

# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------

Invoke-Check -Section $secMaint -CheckId "tombstone-lifetime" `
    -Title "Check AD Tombstone Lifetime is > 180 Days" -Severity "Medium" -Test {
    $ds = Get-DirectoryServiceConfig
    $days = [int]$ds.tombstoneLifetime
    Add-ReviewResult -Section $secMaint -CheckId "tombstone-lifetime" -Title "Check AD Tombstone Lifetime is > 180 Days" `
        -Status $(if ($days -ge 180) { "PASS" } else { "REVIEW" }) `
        -Summary "tombstoneLifetime = $days days" -Evidence $ds
}

Invoke-Check -Section $secMaint -CheckId "dc-count" `
    -Title "Too Few Domain Controllers for Effective Redundancy" -Severity "Medium" -Test {
    $dcs = @(Get-ADDomainController -Filter *)
    $count = $dcs.Count
    Add-ReviewResult -Section $secMaint -CheckId "dc-count" `
        -Title "Too Few Domain Controllers for Effective Redundancy" `
        -Status $(if ($count -ge 2) { "PASS" } else { "FAIL" }) `
        -Summary "Domain controller count: $count" -Evidence ($dcs | Select-Object Name, Site, IsGlobalCatalog)
}

Invoke-Check -Section $secMaint -CheckId "inactive-users" `
    -Title "Inactive Objects" -Severity "Medium" -Test {
    $allInactive = @(Search-ADAccount -AccountInactive -TimeSpan 90 -UsersOnly -ErrorAction SilentlyContinue |
        Where-Object { $_.SamAccountName -notin $script:InactiveUserExcludeSam })
    $inactive = $allInactive | Select-Object Name, SamAccountName, LastLogonDate -First 25
    $count = $allInactive.Count
    Add-ReviewResult -Section $secMaint -CheckId "inactive-users" -Title "Inactive Objects" `
        -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "$count user account(s) inactive >90 days (excludes krbtgt, Guest; sample in evidence)" `
        -Evidence $inactive
}

Invoke-Check -Section $secMaint -CheckId "schema-admins" `
    -Title "Schema Admins Present" -Severity "Medium" -Test {
    $members = @(Get-ADGroupMember 'Schema Admins' -ErrorAction SilentlyContinue)
    Add-ReviewResult -Section $secMaint -CheckId "schema-admins" -Title "Schema Admins Present" `
        -Status $(if ($members.Count -eq 0) { "PASS" } else { "REVIEW" }) `
        -Summary "Schema Admins count: $($members.Count)" -Evidence $members
}

Invoke-Check -Section $secMaint -CheckId "krbtgt-password" `
    -Title "Domain Objects with Aged Passwords" -Severity "High" -Test {
    $krbtgt = Get-ADUser -Filter { SamAccountName -eq 'krbtgt' } -Properties PasswordLastSet -ErrorAction SilentlyContinue
    $stale = $krbtgt -and $krbtgt.PasswordLastSet -and ($krbtgt.PasswordLastSet -lt (Get-Date).AddDays(-180))
    Add-ReviewResult -Section $secMaint -CheckId "krbtgt-password" `
        -Title "Domain Objects with Aged Passwords" `
        -Status $(if (-not $stale) { "PASS" } else { "REVIEW" }) `
        -Summary $(if ($krbtgt) {
            "krbtgt PasswordLastSet = $($krbtgt.PasswordLastSet) (REVIEW if older than 180 days)"
        } else { "krbtgt not found" }) `
        -Evidence $krbtgt -Remediation "Rotate krbtgt password twice per Microsoft guidance."
}

Invoke-Check -Section $secMaint -CheckId "ad-backup" `
    -Title "Backup not Performed Regularly" -Severity "Medium" -Test {
    Add-ReviewResult -Section $secMaint -CheckId "ad-backup" -Title "Backup not Performed Regularly" `
        -Status "MANUAL" -Summary "Run repadmin /showbackup on a DC and verify system state backup within policy." `
        -Remediation "repadmin /showbackup"
}

# ---------------------------------------------------------------------------
# Hybrid Entra ID (optional)
# ---------------------------------------------------------------------------

if ($IncludeEntra) {
    $entraGraphRemediation = "Install-Module Microsoft.Graph -Scope CurrentUser; $($script:ADReviewEntraGraphConnectHint)"
    $entraGraphModuleReady = (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue) -and
        (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)
    $entraGraphConnected = $false

    if ($entraGraphModuleReady) {
        if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
            $entraGraphConnected = [bool](Get-MgContext)
        }
        if (-not $entraGraphConnected) {
            Write-Host "`nHybrid Entra (-IncludeEntra): sign in to Microsoft Graph once for this run." -ForegroundColor Cyan
            Write-Host "Use the NEW code shown below at https://microsoft.com/devicelogin (each Connect-MgGraph attempt invalidates prior codes).`n" -ForegroundColor DarkGray
            $entraGraphConnected = Connect-ADReviewEntraGraph -TenantId $EntraTenantId
            if (-not $entraGraphConnected) {
                Write-Warning "Connect-MgGraph did not complete. Entra rows will report MANUAL."
            }
        }
    }

    Invoke-Check -Section $secEntra -CheckId "entra-security-defaults" `
        -Title "No Security Defaults Enabled" -Severity "Medium" -Test {
        if (-not $entraGraphModuleReady) {
            Add-ReviewResult -Section $secEntra -CheckId "entra-security-defaults" `
                -Title "No Security Defaults Enabled" -Status "MANUAL" `
                -Summary "Microsoft Graph PowerShell SDK not available." `
                -Remediation $entraGraphRemediation
            return
        }
        if (-not $entraGraphConnected) {
            Add-ReviewResult -Section $secEntra -CheckId "entra-security-defaults" `
                -Title "No Security Defaults Enabled" -Status "MANUAL" `
                -Summary "Connect-MgGraph failed or was cancelled." `
                -Remediation $entraGraphRemediation
            return
        }
        $sd = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
        if (-not $sd) {
            Add-ReviewResult -Section $secEntra -CheckId "entra-security-defaults" `
                -Title "No Security Defaults Enabled" -Status "MANUAL" `
                -Summary "Graph request failed - verify Connect-MgGraph and tenant permissions." `
                -Remediation $entraGraphRemediation
            return
        }
        $enabled = $sd.isEnabled
        Add-ReviewResult -Section $secEntra -CheckId "entra-security-defaults" `
            -Title "No Security Defaults Enabled" `
            -Status $(if ($enabled) { "PASS" } else { "REVIEW" }) `
            -Summary "Security Defaults isEnabled=$enabled (disabled may be OK if CA enforces MFA)" -Evidence $sd
    }

    Invoke-Check -Section $secEntra -CheckId "entra-global-admins" `
        -Title "Excessive  Admins Configured" -Severity "High" -Test {
        if (-not $entraGraphModuleReady) {
            Add-ReviewResult -Section $secEntra -CheckId "entra-global-admins" `
                -Title "Excessive  Admins Configured" -Status "MANUAL" `
                -Summary "Microsoft Graph PowerShell SDK not available." `
                -Remediation $entraGraphRemediation
            return
        }
        if (-not $entraGraphConnected) {
            Add-ReviewResult -Section $secEntra -CheckId "entra-global-admins" `
                -Title "Excessive  Admins Configured" -Status "MANUAL" `
                -Summary "Connect-MgGraph failed or was cancelled." `
                -Remediation $entraGraphRemediation
            return
        }

        $gaTemplateId = '62e90394-69f5-4237-9190-012177145e10'
        $members = @()
        $graphFailed = $false
        $roles = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/directoryRoles"
        $gaRole = if ($roles -and $roles.value) {
            @($roles.value) | Where-Object { $_.displayName -eq 'Global Administrator' } | Select-Object -First 1
        }
        if ($gaRole) {
            $memberResult = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($gaRole.id)/members"
            if ($memberResult) { $members = @($memberResult.value) } else { $graphFailed = $true }
        }
        else {
            $filter = [uri]::EscapeDataString("roleDefinitionId eq '$gaTemplateId'")
            $assignments = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=$filter"
            if ($assignments) { $members = @($assignments.value) } else { $graphFailed = $true }
        }

        if ($graphFailed) {
            Add-ReviewResult -Section $secEntra -CheckId "entra-global-admins" `
                -Title "Excessive  Admins Configured" -Status "MANUAL" `
                -Summary "Could not enumerate Global Administrator assignments via Graph." `
                -Remediation $entraGraphRemediation
            return
        }

        $count = $members.Count
        Add-ReviewResult -Section $secEntra -CheckId "entra-global-admins" `
            -Title "Excessive  Admins Configured" `
            -Status $(if ($count -le 5) { "PASS" } else { "REVIEW" }) `
            -Summary "Global Administrator count: $count" -Evidence ($members | Select-Object -First 15 Id, AdditionalProperties, principalId)
    }

    $entraAuthPolicy = $null
    $entraCaPolicies = $null
    if ($entraGraphModuleReady -and $entraGraphConnected) {
        $entraAuthPolicy = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
        $entraCaPolicies = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    }

    Invoke-EntraCheck -Section $secEntra -CheckId "entra-app-registration" `
        -Title "Non-Admin Users able to Register Apps" -Severity "Medium" `
        -GraphModuleReady $entraGraphModuleReady -GraphConnected $entraGraphConnected -GraphRemediation $entraGraphRemediation -Test {
        if (-not $entraAuthPolicy) {
            Add-ReviewResult -Section $secEntra -CheckId "entra-app-registration" `
                -Title "Non-Admin Users able to Register Apps" -Status "MANUAL" `
                -Summary "Graph request for authorizationPolicy failed - verify tenant permissions (Policy.Read.All)." `
                -Remediation $entraGraphRemediation
            return
        }
        $allowed = $entraAuthPolicy.defaultUserRolePermissions.allowedToCreateApps
        Add-ReviewResult -Section $secEntra -CheckId "entra-app-registration" `
            -Title "Non-Admin Users able to Register Apps" `
            -Status $(if ($allowed) { "FAIL" } else { "PASS" }) `
            -Summary "defaultUserRolePermissions.allowedToCreateApps=$allowed" `
            -Evidence $entraAuthPolicy.defaultUserRolePermissions `
            -Remediation "Disable 'Users can register applications' in Entra ID > Users > User settings unless required."
    }

    Invoke-EntraCheck -Section $secEntra -CheckId "entra-guest-invite" `
        -Title "Guests can Invite new guests" -Severity "Medium" `
        -GraphModuleReady $entraGraphModuleReady -GraphConnected $entraGraphConnected -GraphRemediation $entraGraphRemediation -Test {
        if (-not $entraAuthPolicy) {
            Add-ReviewResult -Section $secEntra -CheckId "entra-guest-invite" `
                -Title "Guests can Invite new guests" -Status "MANUAL" `
                -Summary "Graph request for authorizationPolicy failed - verify tenant permissions (Policy.Read.All)." `
                -Remediation $entraGraphRemediation
            return
        }
        $allowInvitesFrom = $entraAuthPolicy.allowInvitesFrom
        $restricted = $allowInvitesFrom -in @('none', 'adminsAndGuestInviters')
        Add-ReviewResult -Section $secEntra -CheckId "entra-guest-invite" `
            -Title "Guests can Invite new guests" `
            -Status $(if ($restricted) { "PASS" } else { "REVIEW" }) `
            -Summary "allowInvitesFrom=$allowInvitesFrom" -Evidence $entraAuthPolicy `
            -Remediation "Set External collaboration settings > Guest invite restrictions to 'Only users with the Guest Inviter role' or stricter."
    }

    Invoke-EntraCheck -Section $secEntra -CheckId "entra-user-consent" `
        -Title "Azure AD Permits Unrestricted user consent" -Severity "High" `
        -GraphModuleReady $entraGraphModuleReady -GraphConnected $entraGraphConnected -GraphRemediation $entraGraphRemediation -Test {
        if (-not $entraAuthPolicy) {
            Add-ReviewResult -Section $secEntra -CheckId "entra-user-consent" `
                -Title "Azure AD Permits Unrestricted user consent" -Status "MANUAL" `
                -Summary "Graph request for authorizationPolicy failed - verify tenant permissions (Policy.Read.All)." `
                -Remediation $entraGraphRemediation
            return
        }
        $grantPolicies = @($entraAuthPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
        $legacyBroad = $grantPolicies | Where-Object { $_ -match 'legacy' }
        $status = if (@($legacyBroad).Count -gt 0) { "FAIL" } elseif ($grantPolicies.Count -gt 0) { "REVIEW" } else { "PASS" }
        Add-ReviewResult -Section $secEntra -CheckId "entra-user-consent" `
            -Title "Azure AD Permits Unrestricted user consent" -Status $status `
            -Summary "permissionGrantPoliciesAssigned=$($grantPolicies -join ', ')" -Evidence $grantPolicies `
            -Remediation "Restrict user consent to verified publishers with low-risk permissions, or require admin consent."
    }

    Invoke-EntraCheck -Section $secEntra -CheckId "entra-mfa-posture" `
        -Title "Weak Azure MFA Configuration" -Severity "High" `
        -GraphModuleReady $entraGraphModuleReady -GraphConnected $entraGraphConnected -GraphRemediation $entraGraphRemediation -Test {
        if (-not $entraCaPolicies) {
            Add-ReviewResult -Section $secEntra -CheckId "entra-mfa-posture" `
                -Title "Weak Azure MFA Configuration" -Status "MANUAL" `
                -Summary "Graph request for Conditional Access policies failed (requires Policy.Read.All and Entra ID P1/P2)." `
                -Remediation $entraGraphRemediation
            return
        }
        $mfaPolicies = @($entraCaPolicies.value) | Where-Object {
            $_.state -eq 'enabled' -and $_.grantControls -and $_.grantControls.builtInControls -contains 'mfa'
        }
        Add-ReviewResult -Section $secEntra -CheckId "entra-mfa-posture" `
            -Title "Weak Azure MFA Configuration" `
            -Status $(if (@($mfaPolicies).Count -ge 1) { "PASS" } else { "REVIEW" }) `
            -Summary "$(@($mfaPolicies).Count) enabled Conditional Access polic(ies) require MFA. Cross-check Security Defaults status separately." `
            -Evidence ($mfaPolicies | Select-Object displayName, state)
    }

    Invoke-EntraCheck -Section $secEntra -CheckId "entra-legacy-auth" `
        -Title "Legacy Authentication Enabled in Azure" -Severity "High" `
        -GraphModuleReady $entraGraphModuleReady -GraphConnected $entraGraphConnected -GraphRemediation $entraGraphRemediation -Test {
        if (-not $entraCaPolicies) {
            Add-ReviewResult -Section $secEntra -CheckId "entra-legacy-auth" `
                -Title "Legacy Authentication Enabled in Azure" -Status "MANUAL" `
                -Summary "Graph request for Conditional Access policies failed (requires Policy.Read.All and Entra ID P1/P2)." `
                -Remediation $entraGraphRemediation
            return
        }
        $legacyBlockPolicies = @($entraCaPolicies.value) | Where-Object {
            $_.state -eq 'enabled' -and $_.conditions.clientAppTypes -and
            (($_.conditions.clientAppTypes -contains 'exchangeActiveSync') -or ($_.conditions.clientAppTypes -contains 'other')) -and
            $_.grantControls -and $_.grantControls.builtInControls -contains 'block'
        }
        Add-ReviewResult -Section $secEntra -CheckId "entra-legacy-auth" `
            -Title "Legacy Authentication Enabled in Azure" `
            -Status $(if (@($legacyBlockPolicies).Count -ge 1) { "PASS" } else { "REVIEW" }) `
            -Summary "$(@($legacyBlockPolicies).Count) enabled Conditional Access polic(ies) block legacy authentication clients. If 0, verify via Entra sign-in logs (legacy client filter)." `
            -Evidence ($legacyBlockPolicies | Select-Object displayName, state) `
            -Remediation "Block legacy authentication (basic auth / exchangeActiveSync / other clients) via Conditional Access."
    }

    Invoke-EntraCheck -Section $secEntra -CheckId "entra-sync-priv-admins" `
        -Title "AD privileged users synced to AAD" -Severity "High" `
        -GraphModuleReady $entraGraphModuleReady -GraphConnected $entraGraphConnected -GraphRemediation $entraGraphRemediation -Test {
        $onPremPriv = @()
        foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Schema Admins') {
            $onPremPriv += Get-ADGroupMember $g -ErrorAction SilentlyContinue | Where-Object { $_.objectClass -eq 'user' }
        }
        $onPremPriv = @($onPremPriv | Sort-Object SamAccountName -Unique)
        $syncedPrivRoles = [System.Collections.Generic.List[object]]::new()
        foreach ($p in $onPremPriv) {
            $sidValue = $p.SID.Value
            $filter = [uri]::EscapeDataString("onPremisesSecurityIdentifier eq '$sidValue'")
            $userResult = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/users?`$filter=$filter&`$select=id,displayName,onPremisesSyncEnabled"
            if (-not $userResult -or -not $userResult.value -or $userResult.value.Count -eq 0) { continue }
            $u = $userResult.value[0]
            $rolesResult = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/users/$($u.id)/memberOf/microsoft.graph.directoryRole?`$select=displayName"
            $roleNames = if ($rolesResult -and $rolesResult.value) { @($rolesResult.value.displayName) } else { @() }
            if ($roleNames.Count -gt 0) {
                $syncedPrivRoles.Add([PSCustomObject]@{
                    OnPremUser = $p.SamAccountName
                    CloudUser  = $u.displayName
                    CloudRoles = ($roleNames -join ', ')
                })
            }
        }
        $count = $syncedPrivRoles.Count
        Add-ReviewResult -Section $secEntra -CheckId "entra-sync-priv-admins" `
            -Title "AD privileged users synced to AAD" `
            -Status $(if ($count -eq 0) { "PASS" } else { "REVIEW" }) `
            -Summary "$count on-prem privileged account(s) (Domain/Enterprise/Schema Admins) also hold an Entra directory role while synced." `
            -Evidence $syncedPrivRoles `
            -Remediation "Exclude on-prem Tier-0 admins from Entra Connect sync, or ensure they hold no cloud-only privileged roles."
    }
}
else {
    Add-ReviewResult -Section $secEntra -CheckId "entra-skipped" -Title "Hybrid Entra ID checks" `
        -Status "SKIP" -Severity "Info" `
        -Summary "Re-run with -IncludeEntra to assess Entra ID / hybrid controls from methodology Azure AD section."
}

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

$script:Results | Export-Csv -Path $csvLog -NoTypeInformation -Encoding utf8

$statusSummary = $script:Results | Group-Object Status | Sort-Object Name |
    ForEach-Object { "  $($_.Name): $($_.Count)" }

$summaryText = @"

================================================================================
SUMMARY - Active Directory Review v$scriptVersion
Completed: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Duration : $([math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)) minutes
Domain   : $($script:DomainDns)
Checks   : $($script:Results.Count)
$($statusSummary -join "`n")

Outputs:
  Log : $txtLog
  CSV : $csvLog
  HTML: $htmlLog

Note: OS/DC build hardening is out of scope - use WinBuildReview.ps1 on domain controllers.
"@

Write-Log $summaryText
Write-Host $summaryText -ForegroundColor Cyan

$htmlRows = ($script:Results | ForEach-Object {
    "<tr class=`"$($_.Status)`"><td>$(ConvertTo-HtmlEncoded $_.Status)</td><td>$(ConvertTo-HtmlEncoded $_.Section)</td><td>$(ConvertTo-HtmlEncoded $_.Title)</td><td>$(ConvertTo-HtmlEncoded $_.Summary)</td></tr>"
}) -join "`n"

@"

<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>AD Review $timestamp</title>
<style>
body{font-family:Segoe UI,sans-serif;margin:24px;background:#f5f5f5}
table{border-collapse:collapse;width:100%;background:#fff}
th,td{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top;font-size:13px}
th{background:#004578;color:#fff}
tr:nth-child(even){background:#f9f9f9}
.FAIL,.ERROR{color:#b00020;font-weight:bold}.PASS{color:#107c10;font-weight:bold}
.REVIEW,.MANUAL{color:#ca5010}.SKIP{color:#666}
</style></head><body>
<h1>Active Directory Review v$scriptVersion</h1>
<p>Domain: $($script:DomainDns) | Generated: $timestamp</p>
<table>
<tr><th>Status</th><th>Section</th><th>Check</th><th>Summary</th></tr>
$htmlRows
</table>
<p>Methodology: Draft_AD_Methodology_FINAL.xlsx (AD-only). DC/OS build review: WinBuildReview.ps1</p>
</body></html>
"@ | Set-Content $htmlLog -Encoding utf8

Write-Host "`nDone. Review $csvLog for structured results." -ForegroundColor Green
