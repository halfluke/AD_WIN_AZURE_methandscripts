<#
.SYNOPSIS
    Azure Cloud Review v1  -  automates checks from Draft_Methodology_Azure_FINAL.xlsx.

.DESCRIPTION
    Passive audit script for Azure subscriptions. Uses az CLI (and optional Prowler /
    Graph) internally. No resources are modified. Skips service-specific checks
    when the resource type is not present in scope.

    Aligns with CIS 5.0 L1-oriented methodology; triage FAIL/REVIEW output manually.

.PARAMETER SubscriptionId
    One or more subscription GUIDs. Defaults to all enabled subscriptions from az account list.

.PARAMETER OutputPath
    Directory for logs and CSV summary.

.PARAMETER RunProwler
    If Prowler is installed, run CIS 5.0 L1 compliance scan before individual checks.

.PARAMETER SkipIdentityTools
    Skip ROADrecon / AzureHound launch attempts (Identity & Attack Path section).

.EXAMPLE
    .\AzureCloudReviewv1.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000"

.NOTES
    Version : 1.0.1
    Requires: Azure CLI (az), Reader or higher on in-scope subscriptions.
    Optional: Prowler, Microsoft Graph PowerShell, AzureHound, ROADrecon.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$SubscriptionId,

    [string]$OutputPath = "",

    [switch]$RunProwler,

    [switch]$SkipIdentityTools
)

$ErrorActionPreference = "Stop"

# Note: StrictMode disabled  -  check scriptblocks reference many script-level variables.

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

$scriptVersion = "1.0.1"
$startTime     = Get-Date
$timestamp     = $startTime.ToString("yyyyMMdd-HHmmss")
$scriptPath    = $MyInvocation.MyCommand.Path
$scriptDir     = Split-Path -Parent $scriptPath
if (-not $OutputPath) { $OutputPath = $scriptDir }

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$txtLog   = Join-Path $OutputPath "AzureCloudReview-$timestamp.txt"
$csvLog   = Join-Path $OutputPath "AzureCloudReview-$timestamp.csv"
$htmlLog  = Join-Path $OutputPath "AzureCloudReview-$timestamp.html"

$script:Results      = [System.Collections.Generic.List[object]]::new()
$script:SubIds       = @()
$script:TenantId     = $null
$script:CurrentUser  = $null
$script:TxtLog       = $txtLog

. (Join-Path $scriptDir "AzureCloudReview.Common.ps1")

$installAzureToolsHint = ".\Install-AzureReviewTools.ps1 -InstallAzureHound -AddToolsToUserPath"
$bloodHoundCeHint = "BloodHound CE: Docker Desktop + bloodhound-cli install - $script:BloodHoundCeQuickstartUrl"

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

@"
Azure Cloud Review v$scriptVersion  -  $timestamp
Methodology: Draft_Methodology_Azure_FINAL (CIS 5.0 L1 oriented)
Host: $env:COMPUTERNAME | User: $env:USERNAME
"@ | Set-Content $txtLog -Encoding utf8

if (-not (Test-CommandAvailable "az")) {
    Write-Error "Azure CLI (az) is required. Install: https://learn.microsoft.com/cli/azure/install-azure-cli"
}

try {
    $null = Resolve-AzCliExecutable
}
catch {
    Write-Error $_.Exception.Message
}

$account = Invoke-AzCliJson -ArgumentList @("account", "show") -AllowFailure
if (-not $account) {
    Write-Error "Not logged in to Azure CLI. Run: az login"
}

$script:TenantId    = $account.tenantId
$script:CurrentUser = (Invoke-AzCliJson -ArgumentList @("ad", "signed-in-user", "show") -AllowFailure).userPrincipalName

if ($SubscriptionId) {
    $script:SubIds = @($SubscriptionId)
}
else {
    $all = Invoke-AzCliJson -ArgumentList @("account", "list", "--query", '[?state==''Enabled''].id', "-o", "json")
    $script:SubIds = @($all)
}

Write-Log "Tenant: $script:TenantId"
Write-Log "Subscriptions: $($script:SubIds -join ', ')"
Write-Log "Signed-in user: $script:CurrentUser"
Write-Log ""

Write-Host "`nAzure Cloud Review v$scriptVersion" -ForegroundColor Cyan
Write-Host "Subscriptions: $($script:SubIds.Count) | Output: $OutputPath`n" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Optional Prowler CIS scan
# ---------------------------------------------------------------------------

if ($RunProwler) {
    if (Test-CommandAvailable "prowler") {
        foreach ($sub in $script:SubIds) {
            Write-Host "Running Prowler CIS 5.0 L1 for $sub ..." -ForegroundColor Magenta
            $prowlerOut = Join-Path $OutputPath "prowler-$sub-$timestamp"
            New-Item -ItemType Directory -Path $prowlerOut -Force | Out-Null
            $pArgs = @(
                "azure", "--az-cli-auth", "--subscription-ids", $sub,
                "--compliance", "cis_5.0_azure",
                "-M", "csv", "html",
                "-o", $prowlerOut,
                "--ignore-exit-code-3"
            )
            try {
                $prowlerExit = Invoke-ProwlerNative -ArgumentList $pArgs
                $reportFiles = @(Get-ChildItem -Path $prowlerOut -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in ".csv", ".html" })

                if ($reportFiles.Count -gt 0 -and ($prowlerExit -eq 0 -or $prowlerExit -eq 3)) {
                    Add-ReviewResult -Section "1. AUTOMATION" -CheckId "prowler-cis" `
                        -Title "CIS 5.0 L1 benchmark scan (Prowler)" -Status "INFO" `
                        -Summary "Scan completed. Review CSV/HTML in $prowlerOut (finding FAILs are expected in the lab)." -Severity "Info"
                }
                else {
                    throw "Prowler did not produce reports (exit $prowlerExit). Review console output above."
                }
            }
            catch {
                Add-ReviewResult -Section "1. AUTOMATION" -CheckId "prowler-cis" `
                    -Title "CIS 5.0 L1 benchmark scan (Prowler)" -Status "ERROR" `
                    -Summary $_.Exception.Message -Severity "High"
            }
        }
    }
    else {
        Add-ReviewResult -Section "1. AUTOMATION" -CheckId "prowler-cis" `
            -Title "CIS 5.0 L1 benchmark scan (Prowler)" -Status "MANUAL" `
            -Summary "Prowler not found in PATH. Install or run manually." -Severity "Info"
    }
}

# ---------------------------------------------------------------------------
# Section 2  -  Entra ID
# ---------------------------------------------------------------------------

$secEntra = "2. AZURE ENTRA ID"

Invoke-Check -Section $secEntra -CheckId "entra-guest-users" `
    -Title "Microsoft Entra ID Guest Users Detected" -Severity "Medium" -Test {
    $guests = Invoke-AzCliJson -ArgumentList @("ad", "user", "list", "--filter", "userType eq 'Guest'") -AllowFailure
    $count = if ($guests) { @($guests).Count } else { 0 }
    $status = if ($count -eq 0) { "PASS" } else { "REVIEW" }
    Add-ReviewResult -Section $secEntra -CheckId "entra-guest-users" -Title "Microsoft Entra ID Guest Users Detected" `
        -Status $status -Summary "Guest user count: $count" -Evidence $guests `
        -Remediation "Review guest accounts periodically (CIS 5.3.2)."
}

Invoke-Check -Section $secEntra -CheckId "entra-tenant-create" `
    -Title "Unrestricted Tenant Creation by Non-Admin Users" -Severity "High" -Test {
    $policy = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    $allowed = $policy.defaultUserRolePermissions.allowedToCreateTenants
    $status = if ($allowed -eq $false) { "PASS" } else { "FAIL" }
    Add-ReviewResult -Section $secEntra -CheckId "entra-tenant-create" `
        -Title "Unrestricted Tenant Creation by Non-Admin Users" -Status $status `
        -Summary "allowedToCreateTenants = $allowed" -Evidence $policy
}

Invoke-Check -Section $secEntra -CheckId "entra-security-defaults" `
    -Title "Security Defaults Not Enabled" -Severity "High" -Test {
    $sd = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    if (-not $sd) {
        Add-ReviewResult -Section $secEntra -CheckId "entra-security-defaults" `
            -Title "Security Defaults Not Enabled" -Status "MANUAL" `
            -Summary "Graph API unavailable  -  verify Security Defaults in Entra portal." -Severity "High"
        return
    }
    $enabled = $sd.isEnabled
    $status = if ($enabled) { "PASS" } else { "REVIEW" }
    Add-ReviewResult -Section $secEntra -CheckId "entra-security-defaults" `
        -Title "Security Defaults Not Enabled" -Status $status `
        -Summary "Security Defaults isEnabled = $enabled" -Evidence $sd `
        -Remediation "Enable Security Defaults or equivalent Conditional Access baseline."
}

Invoke-Check -Section $secEntra -CheckId "entra-guest-perms" `
    -Title "Guest User Permissions Not Limited" -Severity "Medium" -Test {
    $policy = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    $roleId = $policy.guestUserRoleId
    # Restricted guest role GUID (limited permissions)
    $restricted = "10dae515-f9bd-4fe7-8711-eecc663ab2e5"
    $status = if ($roleId -eq $restricted) { "PASS" } else { "REVIEW" }
    Add-ReviewResult -Section $secEntra -CheckId "entra-guest-perms" `
        -Title "Guest User Permissions Not Limited" -Status $status `
        -Summary "guestUserRoleId = $roleId (restricted = $restricted)" -Evidence $policy
}

Invoke-Check -Section $secEntra -CheckId "entra-mfa-all-users" `
    -Title "Insufficient Multi-Factor Authentication Coverage for User Accounts" -Severity "High" -Test {
    $users = Invoke-AzCliJson -ArgumentList @("ad", "user", "list") -AllowFailure
    if (-not $users) {
        Add-ReviewResult -Section $secEntra -CheckId "entra-mfa-all-users" -Title "Insufficient MFA Coverage" `
            -Status "MANUAL" -Summary "az ad user list failed  -  use Graph MFA report or Prowler." -Severity "High"
        return
    }
    $noMfa = @($users | Where-Object { -not $_.strongAuthenticationMethods -or $_.strongAuthenticationMethods.Count -eq 0 })
    $status = if ($noMfa.Count -eq 0) { "PASS" } else { "FAIL" }
    Add-ReviewResult -Section $secEntra -CheckId "entra-mfa-all-users" `
        -Title "Insufficient Multi-Factor Authentication Coverage for User Accounts" -Status $status `
        -Summary "$($noMfa.Count) user(s) without registered MFA methods (legacy az signal)." `
        -Evidence ($noMfa | Select-Object userPrincipalName, userType) `
        -Remediation "Enforce MFA via Security Defaults or Conditional Access."
}

Invoke-Check -Section $secEntra -CheckId "entra-mfa-privileged" `
    -Title "MFA enabled for all privileged users" -Severity "High" -Test {
    $roles = Invoke-AzCliJson -ArgumentList @("rest", "--method", "get", "--url",
        "https://graph.microsoft.com/v1.0/directoryRoles") -AllowFailure
    $privileged = @()
    if ($roles.value) {
        foreach ($role in $roles.value) {
            $members = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members"
            if ($members.value) { $privileged += $members.value }
        }
    }
    Add-ReviewResult -Section $secEntra -CheckId "entra-mfa-privileged" `
        -Title "MFA enabled for all privileged users" -Status "REVIEW" `
        -Summary "Directory role members enumerated  -  verify MFA via CA policies / Prowler." `
        -Evidence ($privileged | Select-Object -First 50 displayName, userPrincipalName, id) `
        -Remediation "Run: prowler azure --check entra_conditional_access_policy_require_mfa_for_admin_portals"
}

Invoke-Check -Section $secEntra -CheckId "entra-admin-portal" `
    -Title "Unrestricted Access To The Administration Portal" -Severity "Medium" -Test {
    $policy = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    Add-ReviewResult -Section $secEntra -CheckId "entra-admin-portal" `
        -Title "Unrestricted Access To The Administration Portal" -Status "REVIEW" `
        -Summary "Verify admin portal restriction in Entra user settings (partial Graph signal)." `
        -Evidence $policy -Remediation 'Entra ID - User settings - Restrict access to Microsoft Entra admin center.'
}

Invoke-Check -Section $secEntra -CheckId "entra-guest-access" `
    -Title "Unrestricted Guest Users Access" -Severity "Medium" -Test {
    $policy = Invoke-AzCliJson -ArgumentList @("ad", "policy", "show", "--id", "GuestUserPolicy") -AllowFailure
    $roleId = $policy.GuestUserRoleId
    $restricted = "10dae515-f9bd-4fe7-8711-eecc663ab2e5"
    $status = if ($roleId -eq $restricted) { "PASS" } else { "REVIEW" }
    Add-ReviewResult -Section $secEntra -CheckId "entra-guest-access" `
        -Title "Unrestricted Guest Users Access" -Status $status `
        -Summary "GuestUserRoleId = $roleId" -Evidence $policy
}

Invoke-Check -Section $secEntra -CheckId "entra-user-consent" `
    -Title "Users Can Consent To Apps Accessing Company Data" -Severity "High" -Test {
    $policy = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    $consentPolicies = $policy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
    Add-ReviewResult -Section $secEntra -CheckId "entra-user-consent" `
        -Title "Users Can Consent To Apps Accessing Company Data" -Status "REVIEW" `
        -Summary "Review user consent settings (permissionGrantPoliciesAssigned: $($consentPolicies -join ', '))." `
        -Evidence $policy
}

Invoke-Check -Section $secEntra -CheckId "entra-app-register" `
    -Title "Users Can Register Applications" -Severity "High" -Test {
    $policy = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    $allowed = $policy.defaultUserRolePermissions.allowedToCreateApps
    $status = if ($allowed -eq $false) { "PASS" } else { "FAIL" }
    Add-ReviewResult -Section $secEntra -CheckId "entra-app-register" `
        -Title "Users Can Register Applications" -Status $status `
        -Summary "allowedToCreateApps = $allowed" -Evidence $policy
}

Invoke-Check -Section $secEntra -CheckId "entra-guest-review" `
    -Title "Guest users reviewed on a regular basis (CIS 5.3.2)" -Severity "Medium" -Test {
    $guests = Invoke-AzCliJson -ArgumentList @("ad", "user", "list", "--filter", "userType eq 'Guest'") -AllowFailure
    Add-ReviewResult -Section $secEntra -CheckId "entra-guest-review" `
        -Title "Guest users reviewed on a regular basis (CIS 5.3.2)" -Status "REVIEW" `
        -Summary "Export guest list for periodic access review." -Evidence ($guests | Select-Object displayName, userPrincipalName, createdDateTime)
}

# ---------------------------------------------------------------------------
# Section 3  -  Storage
# ---------------------------------------------------------------------------

$secStorage = "3. AZURE STORAGE ACCOUNTS"

Invoke-Check -Section $secStorage -CheckId "storage-accounts-exist" `
    -Title "Storage account security baseline" -Severity "High" `
    -SkipIf { (Get-ResourceCount "Microsoft.Storage/storageAccounts") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $accounts = Invoke-AzCliJson -ArgumentList @("storage", "account", "list")
        $findings = foreach ($sa in @($accounts)) {
            $name = $sa.name
            $rg   = $sa.resourceGroup
            $detail = Invoke-AzCliJson -ArgumentList @("storage", "account", "show", "-n", $name, "-g", $rg)
            [PSCustomObject]@{
                Subscription          = $sub
                Name                  = $name
                ResourceGroup         = $rg
                AllowBlobPublicAccess = $detail.allowBlobPublicAccess
                SupportsHttpsOnly     = $detail.enableHttpsTrafficOnly
                MinimumTlsVersion     = $detail.minimumTlsVersion
                PublicNetworkAccess   = $detail.publicNetworkAccess
                DefaultToOAuth        = $detail.defaultToOAuthAuthentication
            }
        }
        $bad = @($findings | Where-Object {
            $_.AllowBlobPublicAccess -eq $true -or
            $_.SupportsHttpsOnly -eq $false -or
            ($_.PublicNetworkAccess -eq "Enabled")
        })
        $status = if ($bad.Count -eq 0) { "PASS" } else { "FAIL" }
        Add-ReviewResult -Section $secStorage -CheckId "storage-accounts-exist" `
            -Title "Storage  -  HTTPS, public access, network restrictions" -Status $status `
            -Summary "Sub $sub : $($bad.Count) storage account(s) with risky settings." `
            -Evidence $findings -Severity "High"
    }
}

Invoke-Check -Section $secStorage -CheckId "storage-blob-anonymous" `
    -Title "Anonymous Access to Blob Containers Enabled" -Severity "High" `
    -SkipIf { (Get-ResourceCount "Microsoft.Storage/storageAccounts") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $accounts = Invoke-AzCliJson -ArgumentList @("storage", "account", "list")
        $publicAccounts = @($accounts | Where-Object { $_.allowBlobPublicAccess -eq $true })
        $status = if ($publicAccounts.Count -eq 0) { "PASS" } else { "FAIL" }
        Add-ReviewResult -Section $secStorage -CheckId "storage-blob-anonymous" `
            -Title "Anonymous Access to Blob Containers Enabled" -Status $status `
            -Summary "Sub $sub : $($publicAccounts.Count) account(s) with allowBlobPublicAccess=true." `
            -Evidence ($publicAccounts | Select-Object name, resourceGroup)
    }
}

Invoke-Check -Section $secStorage -CheckId "storage-entra-auth-default" `
    -Title "Default to Microsoft Entra authorization in the Azure portal" -Severity "Medium" `
    -SkipIf { (Get-ResourceCount "Microsoft.Storage/storageAccounts") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $accounts = Invoke-AzCliJson -ArgumentList @("storage", "account", "list")
        $bad = @($accounts | Where-Object { $_.defaultToOAuthAuthentication -ne $true })
        $status = if ($bad.Count -eq 0) { "PASS" } else { "REVIEW" }
        Add-ReviewResult -Section $secStorage -CheckId "storage-entra-auth-default" `
            -Title "Default to Microsoft Entra authorization" -Status $status `
            -Summary "Sub $sub : $($bad.Count) account(s) without defaultToOAuthAuthentication." `
            -Evidence ($bad | Select-Object name, resourceGroup, defaultToOAuthAuthentication)
    }
}

Invoke-Check -Section $secStorage -CheckId "storage-sas-http" `
    -Title "Shared Access Signature Tokens Over HTTP Allowed" -Severity "Medium" `
    -SkipIf { (Get-ResourceCount "Microsoft.Storage/storageAccounts") -eq 0 } -Test {
    Add-ReviewResult -Section $secStorage -CheckId "storage-sas-http" `
        -Title "Shared Access Signature Tokens Over HTTP Allowed" -Status "MANUAL" `
        -Summary "Review SAS URLs in use  -  ensure onlyHttps=true and short expiry." `
        -Remediation "Audit application configs and shared links for http:// SAS tokens."
}

# ---------------------------------------------------------------------------
# Section 4  -  AI Services
# ---------------------------------------------------------------------------

$secAI = "4. AI SERVICES"

Invoke-Check -Section $secAI -CheckId "ai-public-access" `
    -Title "Cognitive Services / Azure OpenAI  -  public network access restricted" -Severity "High" `
    -SkipIf { (Get-ResourceCount "Microsoft.CognitiveServices/accounts") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $accounts = Invoke-AzCliJson -ArgumentList @("cognitiveservices", "account", "list") -AllowFailure -AllowEmpty
        $bad = @($accounts | Where-Object { $_.properties.publicNetworkAccess -eq "Enabled" })
        $status = if ($bad.Count -eq 0) { "PASS" } else { "FAIL" }
        Add-ReviewResult -Section $secAI -CheckId "ai-public-access" -Title "Cognitive/OpenAI public access" `
            -Status $status -Summary "Sub $sub : $($bad.Count) account(s) with public network access enabled." `
            -Evidence ($bad | Select-Object name, resourceGroup, @{N='Public';E={$_.properties.publicNetworkAccess}})
    }
}

# ---------------------------------------------------------------------------
# Section 5  -  Functions
# ---------------------------------------------------------------------------

$secFunc = "5. AZURE FUNCTIONS"

Invoke-Check -Section $secFunc -CheckId "function-security" -Title "Azure Functions security" -Severity "Medium" `
    -SkipIf { (Get-ResourceCount "Microsoft.Web/sites") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $apps = Invoke-AzCliJson -ArgumentList @("functionapp", "list") -AllowFailure -AllowEmpty
        $findings = foreach ($app in @($apps)) {
            $cfg = Invoke-AzCliJson -ArgumentList @("functionapp", "config", "show", "-n", $app.name, "-g", $app.resourceGroup) -AllowFailure
            $id  = Invoke-AzCliJson -ArgumentList @("functionapp", "identity", "show", "-n", $app.name, "-g", $app.resourceGroup) -AllowFailure
            [PSCustomObject]@{
                Name              = $app.name
                ResourceGroup     = $app.resourceGroup
                HttpsOnly         = $app.httpsOnly
                RemoteDebugging   = $cfg.remoteDebuggingEnabled
                ManagedIdentity   = [bool]($id.type)
            }
        }
        $bad = @($findings | Where-Object { $_.RemoteDebugging -eq $true -or $_.HttpsOnly -eq $false -or -not $_.ManagedIdentity })
        $status = if ($bad.Count -eq 0) { "PASS" } else { "REVIEW" }
        Add-ReviewResult -Section $secFunc -CheckId "function-security" -Title "Azure Functions security" `
            -Status $status -Summary "Sub $sub : $($bad.Count) function app(s) need review." -Evidence $findings
    }
}

# ---------------------------------------------------------------------------
# Section 6  -  Cosmos DB
# ---------------------------------------------------------------------------

$secCosmos = "6. AZURE COSMOSDB"

Invoke-Check -Section $secCosmos -CheckId "cosmos-security" -Title 'Cosmos DB public access and Defender' -Severity "High" `
    -SkipIf { (Get-ResourceCount "Microsoft.DocumentDB/databaseAccounts") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $dbs = Invoke-AzCliJson -ArgumentList @("cosmosdb", "list") -AllowFailure -AllowEmpty
        $findings = foreach ($db in @($dbs)) {
            [PSCustomObject]@{
                Name                = $db.name
                ResourceGroup       = $db.resourceGroup
                PublicNetworkAccess = $db.publicNetworkAccess
            }
        }
        $bad = @($findings | Where-Object { $_.PublicNetworkAccess -ne "Disabled" })
        $status = if ($bad.Count -eq 0) { "PASS" } else { "FAIL" }
        Add-ReviewResult -Section $secCosmos -CheckId "cosmos-security" -Title "Cosmos DB public access" `
            -Status $status -Summary "Sub $sub : $($bad.Count) account(s) with public access." -Evidence $findings
    }
}

# ---------------------------------------------------------------------------
# Section 7  -  Network
# ---------------------------------------------------------------------------

$secNet = "7. NETWORK"

Invoke-Check -Section $secNet -CheckId "network-nsg-permissive" -Severity "High" `
    -Title "NSG rules overly permissive inbound 0.0.0.0/0" `
    -SkipIf { (Get-ResourceCount "Microsoft.Network/networkSecurityGroups") -eq 0 } `
    -Test {
    Invoke-PerSubscription {
        param($sub)
        $nsgs = Invoke-AzCliJson -ArgumentList @("network", "nsg", "list") -AllowFailure -AllowEmpty
        $risky = [System.Collections.Generic.List[object]]::new()
        foreach ($nsg in @($nsgs)) {
            $rules = Invoke-AzCliJson -ArgumentList @("network", "nsg", "rule", "list", "--nsg-name", $nsg.name, "-g", $nsg.resourceGroup) -AllowFailure
            foreach ($rule in @($rules)) {
                if ($rule.access -ne "Allow" -or $rule.direction -ne "Inbound") { continue }
                $src = @($rule.sourceAddressPrefix) + @($rule.sourceAddressPrefixes)
                if ($src -contains "*" -or $src -contains "0.0.0.0/0" -or $src -contains "Internet") {
                    $risky.Add([PSCustomObject]@{
                        NSG = $nsg.name; Rule = $rule.name; Port = $rule.destinationPortRange
                        Source = ($src -join ","); Priority = $rule.priority
                    })
                }
            }
        }
        $status = if ($risky.Count -eq 0) { "PASS" } else { "FAIL" }
        Add-ReviewResult -Section $secNet -CheckId "network-nsg-permissive" `
            -Title "NSG rules overly permissive inbound 0.0.0.0/0" -Status $status `
            -Summary "Sub $sub : $($risky.Count) permissive inbound rule(s)." -Evidence $risky
    }
}

Invoke-Check -Section $secNet -CheckId "network-watcher" `
    -Title "Enable Azure Network Watcher" -Severity "Medium" -Test {
    Invoke-PerSubscription {
        param($sub)
        $watchers = Invoke-AzCliJson -ArgumentList @("network", "watcher", "list") -AllowFailure -AllowEmpty
        $regions = Invoke-AzCliJson -ArgumentList @("account", "list-locations", "-o", "json", "--query", '[?metadata.regionType==''Physical''].name') -AllowFailure
        $count = if ($watchers) { @($watchers).Count } else { 0 }
        $regionCount = if ($regions) { @($regions).Count } else { 0 }
        $status = if ($count -gt 0) { "REVIEW" } else { "FAIL" }
        Add-ReviewResult -Section $secNet -CheckId "network-watcher" -Title "Enable Azure Network Watcher" `
            -Status $status -Summary "Sub $sub : $count Network Watcher instance(s); $regionCount physical region(s) in subscription." `
            -Evidence @{ Watchers = $watchers; PhysicalRegions = $regions } -Remediation "Enable Network Watcher per region; configure NSG flow logs."
    }
}

Invoke-Check -Section $secNet -CheckId "network-ip-forwarding" `
    -Title "Network Interfaces with IP Forwarding Enabled" -Severity "Medium" `
    -SkipIf { (Get-ResourceCount "Microsoft.Network/networkInterfaces") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $nics = Invoke-AzCliJson -ArgumentList @("network", "nic", "list", "--query", '[?enableIpForwarding==`true`]') -AllowFailure -AllowEmpty
        $count = if ($nics) { @($nics).Count } else { 0 }
        $status = if ($count -eq 0) { "PASS" } else { "REVIEW" }
        Add-ReviewResult -Section $secNet -CheckId "network-ip-forwarding" `
            -Title "Network Interfaces with IP Forwarding Enabled" -Status $status `
            -Summary "Sub $sub : $count NIC(s) with IP forwarding." -Evidence $nics
    }
}

# ---------------------------------------------------------------------------
# Section 8  -  AKS
# ---------------------------------------------------------------------------

$secAks = "8. AKS"

Invoke-Check -Section $secAks -CheckId "aks-security" -Title "AKS cluster security" -Severity "High" `
    -SkipIf { (Get-ResourceCount "Microsoft.ContainerService/managedClusters") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $clusters = Invoke-AzCliJson -ArgumentList @("aks", "list") -AllowFailure -AllowEmpty
        $findings = foreach ($c in @($clusters)) {
            $detail = Invoke-AzCliJson -ArgumentList @("aks", "show", "-n", $c.name, "-g", $c.resourceGroup) -AllowFailure
            [PSCustomObject]@{
                Name           = $c.name
                ResourceGroup  = $c.resourceGroup
                PrivateCluster = $detail.apiServerAccessProfile.enablePrivateCluster
                PublicFQDN     = $detail.publicFqdn
                AadEnabled     = [bool]$detail.aadProfile
                RBAC           = $detail.enableRbac
            }
        }
        $bad = @($findings | Where-Object { -not $_.PrivateCluster -or -not $_.AadEnabled })
        $status = if ($bad.Count -eq 0) { "PASS" } else { "REVIEW" }
        Add-ReviewResult -Section $secAks -CheckId "aks-security" -Title "AKS cluster security" `
            -Status $status -Summary "Sub $sub : $($bad.Count) cluster(s) need review." -Evidence $findings
    }
}

# ---------------------------------------------------------------------------
# Section 9  -  API Management
# ---------------------------------------------------------------------------

$secApim = "9. API MANAGEMENT"

Invoke-Check -Section $secApim -CheckId "apim-security" -Title 'API Management public access and TLS' -Severity "Medium" `
    -SkipIf { (Get-ResourceCount "Microsoft.ApiManagement/service") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $services = Invoke-AzCliJson -ArgumentList @("apim", "list") -AllowFailure -AllowEmpty
        $findings = foreach ($s in @($services)) {
            [PSCustomObject]@{
                Name                = $s.name
                ResourceGroup       = $s.resourceGroup
                PublicNetworkAccess = $s.publicNetworkAccess
                CustomProperties    = ($s.customProperties | ConvertTo-Json -Compress)
            }
        }
        $bad = @($findings | Where-Object { $_.PublicNetworkAccess -eq "Enabled" })
        $status = if ($bad.Count -eq 0) { "PASS" } else { "FAIL" }
        Add-ReviewResult -Section $secApim -CheckId "apim-security" -Title "API Management public access" `
            -Status $status -Summary "Sub $sub : $($bad.Count) APIM instance(s) publicly accessible." -Evidence $findings
    }
}

# ---------------------------------------------------------------------------
# Section 10  -  Access Control
# ---------------------------------------------------------------------------

$secRBAC = "10. ACCESS CONTROL"

Invoke-Check -Section $secRBAC -CheckId "rbac-custom-owner" -Title "Custom Owner roles" -Severity "High" -Test {
    Invoke-PerSubscription {
        param($sub)
        $custom = Invoke-AzCliJson -ArgumentList @("role", "definition", "list", "--custom-role-only") -AllowFailure
        $ownerLike = @($custom | Where-Object { $_.roleName -match "Owner" })
        $status = if ($ownerLike.Count -eq 0) { "PASS" } else { "REVIEW" }
        Add-ReviewResult -Section $secRBAC -CheckId "rbac-custom-owner" -Title "Remove Custom Owner Roles" `
            -Status $status -Summary "Sub $sub : $($ownerLike.Count) custom role(s) matching Owner." -Evidence $ownerLike
    }
}

Invoke-Check -Section $secRBAC -CheckId "rbac-custom-roles" -Title "Subscription Administrator Custom Role" -Severity "Medium" -Test {
    Invoke-PerSubscription {
        param($sub)
        $custom = Invoke-AzCliJson -ArgumentList @("role", "definition", "list", "--custom-role-only") -AllowFailure
        Add-ReviewResult -Section $secRBAC -CheckId "rbac-custom-roles" `
            -Title "Subscription Administrator Custom Role" -Status "REVIEW" `
            -Summary "Sub $sub : $(@($custom).Count) custom role definition(s)  -  review for excessive permissions." `
            -Evidence ($custom | Select-Object roleName, description, assignableScopes)
    }
}

# ---------------------------------------------------------------------------
# Section 11  -  Activity Log
# ---------------------------------------------------------------------------

$secActivity = "11. ACTIVITY LOG"

Invoke-Check -Section $secActivity -CheckId "activity-alerts" `
    -Title "Activity Log alerts for critical resource changes" -Severity "High" -Test {
    Invoke-PerSubscription {
        param($sub)
        $alerts = Invoke-AzCliJson -ArgumentList @("monitor", "activity-log", "alert", "list") -AllowFailure -AllowEmpty
        $count = if ($alerts) { @($alerts).Count } else { 0 }
        $status = if ($count -ge 5) { "REVIEW" } else { "FAIL" }
        Add-ReviewResult -Section $secActivity -CheckId "activity-alerts" `
            -Title "Activity Log alerts for critical resource changes" -Status $status `
            -Summary "Sub $sub : $count activity log alert(s) configured." -Evidence ($alerts | Select-Object name, condition)
    }
}

Invoke-Check -Section $secActivity -CheckId "activity-service-health" `
    -Title "Create Alert for Service Health Events" -Severity "Medium" -Test {
    Invoke-PerSubscription {
        param($sub)
        $alerts = Invoke-AzCliJson -ArgumentList @("monitor", "activity-log", "alert", "list") -AllowFailure -AllowEmpty
        $health = @($alerts | Where-Object { $_.condition.allOf.category -eq "ServiceHealth" -or $_.description -match "service health" })
        $status = if ($health.Count -gt 0) { "PASS" } else { "REVIEW" }
        Add-ReviewResult -Section $secActivity -CheckId "activity-service-health" `
            -Title "Create Alert for Service Health Events" -Status $status `
            -Summary "Sub $sub : $($health.Count) service health alert(s)." -Evidence $health
    }
}

# ---------------------------------------------------------------------------
# Section 12  -  Advisor
# ---------------------------------------------------------------------------

$secAdvisor = "12. ADVISOR"

Invoke-Check -Section $secAdvisor -CheckId "advisor-security" `
    -Title "Check for Azure Advisor Recommendations" -Severity "Low" -Test {
    Invoke-PerSubscription {
        param($sub)
        $recs = Invoke-AzCliJson -ArgumentList @("advisor", "recommendation", "list", "--category", "Security") -AllowFailure -AllowEmpty
        $count = if ($recs) { @($recs).Count } else { 0 }
        Add-ReviewResult -Section $secAdvisor -CheckId "advisor-security" `
            -Title "Check for Azure Advisor Recommendations" -Status "INFO" `
            -Summary "Sub $sub : $count open Security recommendation(s)." -Evidence ($recs | Select-Object -First 20 shortDescription, resourceMetadata)
    }
}

# ---------------------------------------------------------------------------
# Section 13  -  App Service
# ---------------------------------------------------------------------------

$secApp = "13. APPSERVICE"

Invoke-Check -Section $secApp -CheckId "appservice-security" -Title "App Service security" -Severity "Medium" `
    -SkipIf { (Get-ResourceCount "Microsoft.Web/sites") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $apps = Invoke-AzCliJson -ArgumentList @("webapp", "list") -AllowFailure -AllowEmpty
        $findings = foreach ($app in @($apps)) {
            $cfg  = Invoke-AzCliJson -ArgumentList @("webapp", "config", "show", "-n", $app.name, "-g", $app.resourceGroup) -AllowFailure
            $auth = Invoke-AzCliJson -ArgumentList @("webapp", "auth", "show", "-n", $app.name, "-g", $app.resourceGroup) -AllowFailure
            $settings = Invoke-AzCliJson -ArgumentList @("webapp", "config", "appsettings", "list", "-n", $app.name, "-g", $app.resourceGroup) -AllowFailure
            $kvRefs = @($settings | Where-Object { $_.value -match "@Microsoft.KeyVault" })
            [PSCustomObject]@{
                Name            = $app.name
                ResourceGroup   = $app.resourceGroup
                RemoteDebugging = $cfg.remoteDebuggingEnabled
                AuthEnabled     = [bool]$auth.enabled
                KeyVaultRefs    = $kvRefs.Count
            }
        }
        $bad = @($findings | Where-Object { $_.RemoteDebugging -eq $true -or -not $_.AuthEnabled })
        $status = if ($bad.Count -eq 0) { "PASS" } else { "REVIEW" }
        Add-ReviewResult -Section $secApp -CheckId "appservice-security" -Title "App Service security" `
            -Status $status -Summary "Sub $sub : $($bad.Count) web app(s) need review." -Evidence $findings
    }
}

# ---------------------------------------------------------------------------
# Sections 14–15  -  Container Apps & ACR
# ---------------------------------------------------------------------------

$secCa = "14. CONTAINER APPS"
Invoke-Check -Section $secCa -CheckId "containerapp-security" -Title "Container Apps security" -Severity "Medium" `
    -SkipIf { (Get-ResourceCount "Microsoft.App/containerApps") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $apps = Invoke-AzCliJson -ArgumentList @("containerapp", "list") -AllowFailure -AllowEmpty
        $findings = foreach ($app in @($apps)) {
            $id = Invoke-AzCliJson -ArgumentList @("containerapp", "identity", "show", "-n", $app.name, "-g", $app.resourceGroup) -AllowFailure
            [PSCustomObject]@{ Name = $app.name; ResourceGroup = $app.resourceGroup; ManagedIdentity = [bool]$id.type }
        }
        $bad = @($findings | Where-Object { -not $_.ManagedIdentity })
        $status = if ($bad.Count -eq 0) { "PASS" } else { "REVIEW" }
        Add-ReviewResult -Section $secCa -CheckId "containerapp-security" -Title "Container Apps managed identity" `
            -Status $status -Summary "Sub $sub : $($bad.Count) app(s) without managed identity." -Evidence $findings
    }
}

$secAcr = "15. CONTAINER REGISTRY"
Invoke-Check -Section $secAcr -CheckId "acr-security" -Title "Container Registry network access" -Severity "Medium" `
    -SkipIf { (Get-ResourceCount "Microsoft.ContainerRegistry/registries") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $registries = Invoke-AzCliJson -ArgumentList @("acr", "list") -AllowFailure -AllowEmpty
        $findings = foreach ($r in @($registries)) {
            $pe = Invoke-AzCliJson -ArgumentList @("acr", "private-endpoint-connection", "list", "--registry-name", $r.name) -AllowFailure
            [PSCustomObject]@{
                Name                = $r.name
                PublicNetworkAccess = $r.publicNetworkAccess
                PrivateEndpoints    = @($pe).Count
            }
        }
        $bad = @($findings | Where-Object { $_.PublicNetworkAccess -eq "Enabled" -and $_.PrivateEndpoints -eq 0 })
        $status = if ($bad.Count -eq 0) { "PASS" } else { "FAIL" }
        Add-ReviewResult -Section $secAcr -CheckId "acr-security" -Title "ACR public access / private endpoints" `
            -Status $status -Summary "Sub $sub : $($bad.Count) registry(ies) exposed publicly without PE." -Evidence $findings
    }
}

# ---------------------------------------------------------------------------
# Sections 16-34 - remaining services (condensed resource loops)
# ---------------------------------------------------------------------------

Test-ServiceResources -Section "16. DATABRICKS" -CheckId "databricks-vnet" `
    -Title "Databricks VNet injection" -ResourceType "Microsoft.Databricks/workspaces" -Evaluate {
    param($sub, $items)
    $bad = @()
    foreach ($ws in @($items)) {
        $detail = Invoke-AzCliJson -ArgumentList @("databricks", "workspace", "show", "-n", $ws.name, "-g", $ws.resourceGroup) -AllowFailure
        if (-not $detail.parameters.customVirtualNetworkId) { $bad += $detail.name }
    }
    $status = if ($bad.Count -eq 0) { "PASS" } else { "REVIEW" }
    Add-ReviewResult -Section "16. DATABRICKS" -CheckId "databricks-vnet" -Title "Databricks VNet injection" `
        -Status $status -Summary "Sub $sub : $($bad.Count) workspace(s) without VNet injection." -Evidence $bad
}

Test-ServiceResources -Section "17. FRONT DOOR" -CheckId "afd-security" `
    -Title 'Front Door WAF and TLS' -ResourceType "Microsoft.Cdn/profiles" -Evaluate {
    param($sub, $items)
    Add-ReviewResult -Section "17. FRONT DOOR" -CheckId "afd-security" -Title 'Front Door WAF and TLS' `
        -Status "REVIEW" -Summary "Sub $sub : $(@($items).Count) CDN/Front Door profile(s)  -  verify WAF and min TLS via portal/az afd." `
        -Evidence ($items | Select-Object name, resourceGroup, type)
}

Test-ServiceResources -Section "18. KEY VAULT" -CheckId "keyvault-security" `
    -Title "Key Vault security baseline" -ResourceType "Microsoft.KeyVault/vaults" -Severity "High" -Evaluate {
    param($sub, $items)
    $findings = foreach ($v in @($items)) {
        $name = $v.name
        $detail = Invoke-AzCliJson -ArgumentList @("keyvault", "show", "-n", $name) -AllowFailure
        [PSCustomObject]@{
            Name          = $name
            SoftDelete    = $detail.properties.enableSoftDelete
            PurgeProtect  = $detail.properties.enablePurgeProtection
            RBAC          = $detail.properties.enableRbacAuthorization
            NetworkAcls   = ($detail.properties.networkAcls.defaultAction)
        }
    }
    $bad = @($findings | Where-Object { -not $_.SoftDelete -or -not $_.PurgeProtect -or $_.NetworkAcls -eq "Allow" })
    $status = if ($bad.Count -eq 0) { "PASS" } else { "FAIL" }
    Add-ReviewResult -Section "18. KEY VAULT" -CheckId "keyvault-security" -Title "Key Vault security baseline" `
        -Status $status -Summary "Sub $sub : $($bad.Count) vault(s) with weak settings." -Evidence $findings
}

Invoke-Check -Section "19. LOCKS" -CheckId "resource-locks" -Title "Enable Azure Resource Locks" -Severity "Low" -Test {
    Invoke-PerSubscription {
        param($sub)
        $locks = Invoke-AzCliJson -ArgumentList @("lock", "list", "--scope", "/subscriptions/$sub") -AllowFailure -AllowEmpty
        $count = if ($locks) { @($locks).Count } else { 0 }
        $status = if ($count -gt 0) { "REVIEW" } else { "FAIL" }
        Add-ReviewResult -Section "19. LOCKS" -CheckId "resource-locks" -Title "Enable Azure Resource Locks" `
            -Status $status -Summary "Sub $sub : $count subscription-level lock(s)." -Evidence $locks
    }
}

Test-ServiceResources -Section "20. MACHINE LEARNING" -CheckId "ml-cmk" `
    -Title "ML workspace CMK encryption" -ResourceType "Microsoft.MachineLearningServices/workspaces" -Evaluate {
    param($sub, $items)
    Add-ReviewResult -Section "20. MACHINE LEARNING" -CheckId "ml-cmk" -Title "ML workspace CMK encryption" `
        -Status "REVIEW" -Summary "Sub $sub : review encryption settings on $(@($items).Count) workspace(s)." `
        -Evidence ($items | Select-Object name, resourceGroup)
}

Invoke-Check -Section "21. MONITOR" -CheckId "monitor-diagnostics" `
    -Title 'Activity log export and diagnostic settings' -Severity "Medium" -Test {
    Invoke-PerSubscription {
        param($sub)
        $subDiag = Invoke-AzCliJson -ArgumentList @("monitor", "diagnostic-settings", "subscription", "list") -AllowFailure -AllowEmpty
        $count = if ($subDiag) { @($subDiag).Count } else { 0 }
        $status = if ($count -gt 0) { "PASS" } else { "FAIL" }
        Add-ReviewResult -Section "21. MONITOR" -CheckId "monitor-diagnostics" `
            -Title "Enable Exporting Activity Logs for Azure Cloud Resources" -Status $status `
            -Summary "Sub $sub : $count subscription diagnostic setting(s)." -Evidence $subDiag
    }
}

Test-ServiceResources -Section "22. MYSQL" -CheckId "mysql-ssl" `
    -Title "MySQL in-transit encryption" -ResourceType "Microsoft.DBforMySQL/flexibleServers" -Evaluate {
    param($sub, $items)
    Add-ReviewResult -Section "22. MYSQL" -CheckId "mysql-ssl" -Title "MySQL in-transit encryption" `
        -Status "REVIEW" -Summary "Sub $sub : verify TLS on $(@($items).Count) flexible server(s)." `
        -Evidence ($items | Select-Object name, resourceGroup)
}

Invoke-Check -Section "23. POLICY" -CheckId "policy-assignments" -Title "Policy Assignment Created" -Severity "Medium" -Test {
    Invoke-PerSubscription {
        param($sub)
        $assignments = Invoke-AzCliJson -ArgumentList @("policy", "assignment", "list") -AllowFailure -AllowEmpty
        $count = if ($assignments) { @($assignments).Count } else { 0 }
        $status = if ($count -gt 0) { "PASS" } else { "FAIL" }
        Add-ReviewResult -Section "23. POLICY" -CheckId "policy-assignments" -Title "Policy Assignment Created" `
            -Status $status -Summary "Sub $sub : $count policy assignment(s)." -Evidence ($assignments | Select-Object -First 15 displayName, name)
    }
}

Test-ServiceResources -Section "24. POSTGRESQL" -CheckId "postgres-entra" `
    -Title "PostgreSQL Entra admin" -ResourceType "Microsoft.DBforPostgreSQL/flexibleServers" -Evaluate {
    param($sub, $items)
    foreach ($srv in @($items)) {
        $admins = Invoke-AzCliJson -ArgumentList @("postgres", "flexible-server", "ad-admin", "list", "-g", $srv.resourceGroup, "-s", $srv.name) -AllowFailure
        Add-ReviewResult -Section "24. POSTGRESQL" -CheckId "postgres-entra" -Title "PostgreSQL Entra admin" `
            -Status $(if ($admins) { "PASS" } else { "REVIEW" }) `
            -Summary "Server $($srv.name): Entra admin configured = $([bool]$admins)." -Evidence $admins
    }
}

Invoke-Check -Section "25. RECOVERY SERVICES" -CheckId "backup-alerts" `
    -Title "Backup email notifications" -Severity "Low" `
    -SkipIf { (Get-ResourceCount "Microsoft.RecoveryServices/vaults") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $vaults = Invoke-AzCliJson -ArgumentList @("backup", "vault", "list") -AllowFailure -AllowEmpty
        Add-ReviewResult -Section "25. RECOVERY SERVICES" -CheckId "backup-alerts" `
            -Title "Enable Email Notifications for Backup Alerts" -Status "REVIEW" `
            -Summary "Sub $sub : $(@($vaults).Count) Recovery Services vault(s)  -  verify alert contacts in portal." `
            -Evidence ($vaults | Select-Object name, resourceGroup)
    }
}

Test-ServiceResources -Section "26. REDIS CACHE" -CheckId "redis-ssl" `
    -Title "Redis in-transit encryption" -ResourceType "Microsoft.Cache/Redis" -Evaluate {
    param($sub, $items)
    $findings = foreach ($r in @($items)) {
        $detail = Invoke-AzCliJson -ArgumentList @("redis", "show", "-n", $r.name, "-g", $r.resourceGroup) -AllowFailure
        [PSCustomObject]@{ Name = $r.name; EnableNonSslPort = $detail.enableNonSslPort }
    }
    $bad = @($findings | Where-Object { $_.EnableNonSslPort -eq $true })
    $status = if ($bad.Count -eq 0) { "PASS" } else { "FAIL" }
    Add-ReviewResult -Section "26. REDIS CACHE" -CheckId "redis-ssl" -Title "Redis in-transit encryption" `
        -Status $status -Summary "Sub $sub : $($bad.Count) Redis instance(s) with non-SSL port enabled." -Evidence $findings
}

Invoke-Check -Section "27. RESOURCES" -CheckId "resource-tags" -Title "Missing Tags" -Severity "Low" -Test {
    Invoke-PerSubscription {
        param($sub)
        $resources = Invoke-AzCliJson -ArgumentList @("resource", "list") -AllowFailure
        $untagged = @($resources | Where-Object { -not $_.tags -or $_.tags.PSObject.Properties.Count -eq 0 })
        $status = if ($untagged.Count -eq 0) { "PASS" } else { "REVIEW" }
        Add-ReviewResult -Section "27. RESOURCES" -CheckId "resource-tags" -Title "Missing Tags" `
            -Status $status -Summary "Sub $sub : $($untagged.Count) resource(s) without tags." `
            -Evidence ($untagged | Select-Object -First 30 name, type, resourceGroup)
    }
}

Test-ServiceResources -Section "28. SEARCH" -CheckId "search-security" `
    -Title 'AI Search public access and managed identity' -ResourceType "Microsoft.Search/searchServices" -Evaluate {
    param($sub, $items)
    $findings = foreach ($s in @($items)) {
        $detail = Invoke-AzCliJson -ArgumentList @("search", "service", "show", "-n", $s.name, "-g", $s.resourceGroup) -AllowFailure
        [PSCustomObject]@{
            Name              = $s.name
            PublicNetworkAccess = $detail.publicNetworkAccess
            HasIdentity       = [bool]$detail.identity
        }
    }
    $bad = @($findings | Where-Object { $_.PublicNetworkAccess -eq "enabled" -or -not $_.HasIdentity })
    $status = if ($bad.Count -eq 0) { "PASS" } else { "FAIL" }
    Add-ReviewResult -Section "28. SEARCH" -CheckId "search-security" -Title "AI Search security" `
        -Status $status -Summary "Sub $sub : $($bad.Count) search service(s) need review." -Evidence $findings
}

Invoke-Check -Section "29. DEFENDER" -CheckId "defender-posture" -Title "Defender for Cloud" -Severity "High" -Test {
    Invoke-PerSubscription {
        param($sub)
        $assessments = Invoke-AzCliJson -ArgumentList @(
            "security", "assessment", "list",
            "--query", "[].{displayName:displayName, statusCode:status.code}"
        ) -AllowFailure -AllowEmpty
        $unhealthy = @($assessments | Where-Object { $_.statusCode -eq "Unhealthy" })
        $alerts = Invoke-AzCliJson -ArgumentList @(
            "security", "alert", "list",
            "--query", "[].{alertDisplayName:alertDisplayName, severity:severity}"
        ) -AllowFailure -AllowEmpty
        Add-ReviewResult -Section "29. DEFENDER" -CheckId "defender-posture" -Title "Microsoft Defender for Cloud Recommendations" `
            -Status "INFO" -Summary "Sub $sub : $($unhealthy.Count) unhealthy assessment(s); $(@($alerts).Count) alert(s)." `
            -Evidence @{ Unhealthy = ($unhealthy | Select-Object -First 10 displayName); Alerts = ($alerts | Select-Object -First 10 alertDisplayName) }
    }
}

Invoke-Check -Section "29. DEFENDER" -CheckId "defender-external-write" `
    -Title "Monitor External Accounts with Write Permissions" -Severity "High" -Test {
    Invoke-PerSubscription {
        param($sub)
        $assignments = Invoke-AzCliJson -ArgumentList @("role", "assignment", "list", "--all") -AllowFailure
        $external = @($assignments | Where-Object {
            $_.principalName -match "#EXT#" -and
            $_.roleDefinitionName -match "Contributor|Owner|User Access Administrator|Write"
        })
        $status = if ($external.Count -eq 0) { "PASS" } else { "REVIEW" }
        Add-ReviewResult -Section "29. DEFENDER" -CheckId "defender-external-write" `
            -Title "Monitor External Accounts with Write Permissions" -Status $status `
            -Summary "Sub $sub : $($external.Count) external assignment(s) with write-capable roles." -Evidence $external
    }
}

Test-ServiceResources -Section "30. SERVICE BUS" -CheckId "servicebus-public" `
    -Title "Service Bus public network access" -ResourceType "Microsoft.ServiceBus/namespaces" -Evaluate {
    param($sub, $items)
    $findings = foreach ($n in @($items)) {
        $detail = Invoke-AzCliJson -ArgumentList @("servicebus", "namespace", "show", "-n", $n.name, "-g", $n.resourceGroup) -AllowFailure
        [PSCustomObject]@{ Name = $n.name; PublicNetworkAccess = $detail.publicNetworkAccess }
    }
    $bad = @($findings | Where-Object { $_.PublicNetworkAccess -eq "Enabled" })
    $status = if ($bad.Count -eq 0) { "PASS" } else { "FAIL" }
    Add-ReviewResult -Section "30. SERVICE BUS" -CheckId "servicebus-public" -Title "Service Bus public access" `
        -Status $status -Summary "Sub $sub : $($bad.Count) namespace(s) publicly accessible." -Evidence $findings
}

Invoke-Check -Section "31. SQL" -CheckId "sql-security" -Title "SQL Server security" -Severity "High" `
    -SkipIf { (Get-ResourceCount "Microsoft.Sql/servers") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $servers = Invoke-AzCliJson -ArgumentList @("sql", "server", "list") -AllowFailure -AllowEmpty
        $findings = foreach ($s in @($servers)) {
            $fw = Invoke-AzCliJson -ArgumentList @("sql", "server", "firewall-rule", "list", "-s", $s.name, "-g", $s.resourceGroup) -AllowFailure
            $audit = Invoke-AzCliJson -ArgumentList @("sql", "server", "audit-policy", "show", "-s", $s.name, "-g", $s.resourceGroup) -AllowFailure
            $open = @($fw | Where-Object { $_.startIpAddress -eq "0.0.0.0" -and $_.endIpAddress -eq "255.255.255.255" })
            [PSCustomObject]@{
                Name               = $s.name
                PublicNetworkAccess = $s.publicNetworkAccess
                OpenFirewallRules  = $open.Count
                AuditingEnabled    = $audit.state -eq "Enabled"
            }
        }
        $bad = @($findings | Where-Object { $_.PublicNetworkAccess -eq "Enabled" -or $_.OpenFirewallRules -gt 0 -or -not $_.AuditingEnabled })
        $status = if ($bad.Count -eq 0) { "PASS" } else { "FAIL" }
        Add-ReviewResult -Section "31. SQL" -CheckId "sql-security" -Title "SQL Server security" `
            -Status $status -Summary "Sub $sub : $($bad.Count) SQL server(s) need review." -Evidence $findings
    }
}

Invoke-Check -Section "32. SUBSCRIPTIONS" -CheckId "subscription-governance" `
    -Title "Subscription governance" -Severity "High" -Test {
    Invoke-PerSubscription {
        param($sub)
        $owners = Invoke-AzCliJson -ArgumentList @("role", "assignment", "list", "--role", "Owner", "--scope", "/subscriptions/$sub") -AllowFailure
        $uaa = Invoke-AzCliJson -ArgumentList @("role", "assignment", "list", "--role", "User Access Administrator", "--scope", "/subscriptions/$sub") -AllowFailure
        $budgets = Invoke-AzCliJson -ArgumentList @("consumption", "budget", "list") -AllowFailure -AllowEmpty
        $policies = Invoke-AzCliJson -ArgumentList @("policy", "assignment", "list") -AllowFailure
        $notAllowed = @($policies | Where-Object { $_.displayName -match "Not allowed" })
        $ownerCount = @($owners).Count
        $status = "REVIEW"
        if ($ownerCount -gt 3) { $status = "FAIL" }
        Add-ReviewResult -Section "32. SUBSCRIPTIONS" -CheckId "subscription-governance" `
            -Title "Subscription governance (Owners, UAA, budgets, policies)" -Status $status `
            -Summary "Sub $sub : Owners=$ownerCount, UAA=$(@($uaa).Count), Budgets=$(@($budgets).Count), NotAllowedPolicy=$(@($notAllowed).Count)." `
            -Evidence @{ Owners = $owners; UAA = $uaa; Budgets = $budgets; NotAllowedPolicies = $notAllowed }
    }
}

Test-ServiceResources -Section "33. SYNAPSE" -CheckId "synapse-tde" `
    -Title "Synapse dedicated SQL pool TDE" -ResourceType "Microsoft.Synapse/workspaces" -Evaluate {
    param($sub, $items)
    Add-ReviewResult -Section "33. SYNAPSE" -CheckId "synapse-tde" -Title "Synapse TDE" `
        -Status "REVIEW" -Summary "Sub $sub : verify TDE on dedicated SQL pools in $(@($items).Count) workspace(s)." `
        -Evidence ($items | Select-Object name, resourceGroup)
}

Invoke-Check -Section "34. VIRTUAL MACHINES" -CheckId "vm-security" -Title "VM security baseline" -Severity "High" `
    -SkipIf { (Get-ResourceCount "Microsoft.Compute/virtualMachines") -eq 0 } -Test {
    Invoke-PerSubscription {
        param($sub)
        $vms = Invoke-AzCliJson -ArgumentList @("vm", "list", "-d") -AllowFailure -AllowEmpty
        $vmss = Invoke-AzCliJson -ArgumentList @("vmss", "list") -AllowFailure -AllowEmpty
        $jit = Invoke-AzCliJson -ArgumentList @("security", "jit-policy", "list") -AllowFailure -AllowEmpty
        $publicVms = @($vms | Where-Object { $_.publicIps })
        Add-ReviewResult -Section "34. VIRTUAL MACHINES" -CheckId "vm-security" -Title "VM security baseline" `
            -Status $(if ($publicVms.Count -eq 0) { "REVIEW" } else { "FAIL" }) `
            -Summary "Sub $sub : $($publicVms.Count) VM(s) with public IP; $(@($vmss).Count) VMSS; $(@($jit).Count) JIT policy/policies." `
            -Evidence @{ PublicVms = ($publicVms | Select-Object name, resourceGroup, publicIps); VmssCount = @($vmss).Count; JitPolicies = $jit }
    }
}

# ---------------------------------------------------------------------------
# Section 35  -  Identity & Attack Path
# ---------------------------------------------------------------------------

$secIdentity = "35. IDENTITY & ATTACK PATH"

if (-not $SkipIdentityTools) {
    Invoke-Check -Section $secIdentity -CheckId "identity-roadrecon" `
        -Title "Entra ID tenant recon (ROADrecon)" -Severity "Info" -Test {
        if (Test-CommandAvailable "roadrecon") {
            Add-ReviewResult -Section $secIdentity -CheckId "identity-roadrecon" `
                -Title "Entra ID tenant recon (ROADrecon)" -Status "MANUAL" `
                -Summary "roadrecon found  -  Step 1: .\Start-RoadreconAuth.ps1  Step 2: roadrecon gather  Step 3: .\Start-RoadreconGui.ps1" `
                -Remediation "Auth: Start-RoadreconAuth.ps1. Gather: roadrecon gather. GUI: Start-RoadreconGui.ps1 (http://127.0.0.1:5000). See AZURE_README.md."
        }
        else {
            Add-ReviewResult -Section $secIdentity -CheckId "identity-roadrecon" `
                -Title "Entra ID tenant recon (ROADrecon)" -Status "MANUAL" `
                -Summary "ROADrecon not installed. pip install roadrecon"
        }
    }

    Invoke-Check -Section $secIdentity -CheckId "identity-azurehound" `
        -Title "Collect Entra + Azure RM data for BloodHound" -Severity "Info" -Test {
        if (Test-CommandAvailable "azurehound") {
            Add-ReviewResult -Section $secIdentity -CheckId "identity-azurehound" `
                -Title "AzureHound collection" -Status "MANUAL" `
                -Summary "azurehound found  -  Step 1: .\Get-AzureHoundRefreshToken.ps1  Step 2: azurehound list -r (from .\tools\azurehound.refresh). Do not reuse .roadtools_auth." `
                -Remediation "Ingest azurehound.json in BloodHound CE. v2+: azurehound list -o json with Azure PowerShell refresh token. See AZURE_README.md. $bloodHoundCeHint"
        }
        else {
            Add-ReviewResult -Section $secIdentity -CheckId "identity-azurehound" `
                -Title "AzureHound collection" -Status "MANUAL" `
                -Summary "AzureHound not installed. Install collector via Install-AzureReviewTools.ps1; BloodHound CE GUI is separate." `
                -Remediation "$installAzureToolsHint | $bloodHoundCeHint"
        }
    }
}

Invoke-Check -Section $secIdentity -CheckId "identity-rbac-paths" `
    -Title "RBAC paths  -  Owner / UAA / current user" -Severity "High" -Test {
    Invoke-PerSubscription {
        param($sub)
        $owners = Invoke-AzCliJson -ArgumentList @("role", "assignment", "list", "--role", "Owner", "--scope", "/subscriptions/$sub") -AllowFailure
        $uaa = Invoke-AzCliJson -ArgumentList @("role", "assignment", "list", "--role", "User Access Administrator", "--scope", "/subscriptions/$sub") -AllowFailure
        $mine = Invoke-AzCliJson -ArgumentList @("role", "assignment", "list", "--assignee", $script:CurrentUser, "--all") -AllowFailure
        Add-ReviewResult -Section $secIdentity -CheckId "identity-rbac-paths" `
            -Title "Paths to subscription Owner or User Access Administrator" -Status "INFO" `
            -Summary "Sub $sub : enumerate Owner/UAA/current-user assignments for BloodHound cross-check." `
            -Evidence @{ Owners = $owners; UAA = $uaa; CurrentUser = $mine }
    }
}

Invoke-Check -Section $secIdentity -CheckId "identity-sp-apps" `
    -Title 'App registrations and service principals (recon signal)' -Severity "Medium" -Test {
    $apps = Invoke-AzCliJson -ArgumentList @("ad", "app", "list") -AllowFailure -AllowEmpty
    $sps  = Invoke-AzCliJson -ArgumentList @("ad", "sp", "list", "--all") -AllowFailure -AllowEmpty
    Add-ReviewResult -Section $secIdentity -CheckId "identity-sp-apps" `
        -Title "Abusable app registrations and service principals" -Status "REVIEW" `
        -Summary "$(@($apps).Count) app registration(s), $(@($sps).Count) service principal(s)  -  analyze in ROADrecon/BloodHound." `
        -Evidence @{ Apps = ($apps | Select-Object -First 20 displayName, appId); SPs = ($sps | Select-Object -First 20 displayName, appId) }
}

Add-ReviewResult -Section $secIdentity -CheckId "identity-bloodhound-queries" `
    -Title "BloodHound CE attack path queries" -Status "MANUAL" -Severity "Info" `
    -Summary "Run AZ prebuilt queries after AzureHound ingest (Global Admin paths, KV/storage via MI)." `
    -Remediation "Install BloodHound CE (Docker Linux containers + bloodhound-cli): $script:BloodHoundCeQuickstartUrl - ingest azurehound.json; see AZURE_README.md BloodHound CE Azure pathfinding."

# ---------------------------------------------------------------------------
# Export results
# ---------------------------------------------------------------------------

$script:Results | Export-Csv -Path $csvLog -NoTypeInformation -Encoding utf8

$statusSummary = $script:Results | Group-Object Status | Sort-Object Name |
    ForEach-Object { "  $($_.Name): $($_.Count)" }

$summaryText = @"

================================================================================
SUMMARY  -  Azure Cloud Review v$scriptVersion
Completed: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Duration : $([math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)) minutes
Checks   : $($script:Results.Count)
$($statusSummary -join "`n")

Outputs:
  Log : $txtLog
  CSV : $csvLog
  HTML: $htmlLog
"@

Write-Log $summaryText
Write-Host $summaryText -ForegroundColor Cyan

# Minimal HTML report
$htmlRows = ($script:Results | ForEach-Object {
    "<tr><td>$(ConvertTo-HtmlEncoded $_.Status)</td><td>$(ConvertTo-HtmlEncoded $_.Section)</td><td>$(ConvertTo-HtmlEncoded $_.Title)</td><td>$(ConvertTo-HtmlEncoded $_.Summary)</td></tr>"
}) -join "`n"

@"

<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Azure Cloud Review $timestamp</title>
<style>
body{font-family:Segoe UI,sans-serif;margin:24px;background:#f5f5f5}
table{border-collapse:collapse;width:100%;background:#fff}
th,td{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top;font-size:13px}
th{background:#0078d4;color:#fff}
tr:nth-child(even){background:#f9f9f9}
.FAIL{color:#b00020;font-weight:bold}.PASS{color:#107c10;font-weight:bold}
.REVIEW,.MANUAL{color:#ca5010}.SKIP{color:#666}.ERROR{color:#b00020}
</style></head><body>
<h1>Azure Cloud Review v$scriptVersion</h1>
<p>Tenant: $script:TenantId | User: $script:CurrentUser | Generated: $timestamp</p>
<table>
<tr><th>Status</th><th>Section</th><th>Check</th><th>Summary</th></tr>
$htmlRows
</table>
</body></html>
"@ | Set-Content $htmlLog -Encoding utf8

Write-Host "`nDone. Review $csvLog for structured results." -ForegroundColor Green
