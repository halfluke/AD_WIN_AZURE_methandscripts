<#
.SYNOPSIS
    Delete the Tier 2 Azure review lab and purge lingering billable objects.

.DESCRIPTION
    Removes the resource group created by Deploy-AzureReviewLab.ps1, waits for deletion
    to finish, then cleans up objects that often survive RG delete:
      - Soft-deleted Key Vaults (must be purged or they linger in the subscription)
      - Soft-deleted Cognitive Services accounts (same name cannot be recreated until purged)
      - Orphaned resources still tagged Purpose=CloudReviewLab
      - Leftover public IPs / disks tagged for the lab (outside the RG)

    Does not delete subscription-wide defaults (e.g. NetworkWatcherRG) unless they
    carry the lab tag.

.PARAMETER ResourceGroupName
    Resource group to delete. Default: rg-cloudreview-lab or manifest value.

.PARAMETER SubscriptionId
    Subscription containing the group. Default: current az account or manifest value.

.PARAMETER Force
    Skip confirmation prompt.

.PARAMETER KeepManifest
    Do not remove AzureReviewLab-manifest.json after delete.

.PARAMETER WaitTimeoutMinutes
    Maximum minutes to wait for resource group deletion. Default: 20.

.EXAMPLE
    .\Destroy-AzureReviewLab.ps1

.EXAMPLE
    .\Destroy-AzureReviewLab.ps1 -Force

.NOTES
    Requires az login and permission to delete the resource group (Contributor or Owner).
    Script version: 1.0.2
#>

[CmdletBinding()]
param(
    [string]$ResourceGroupName = "",
    [string]$SubscriptionId = "",
    [switch]$Force,
    [switch]$KeepManifest,
    [int]$WaitTimeoutMinutes = 20
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

$destroyScriptVersion = "1.0.2"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$manifestPath = Join-Path $scriptDir "AzureReviewLab-manifest.json"
$script:LabTagKey = "Purpose"
$script:LabTagValue = "CloudReviewLab"
$script:LabManagedBy = "Deploy-AzureReviewLab.ps1"
$script:CleanupWarnings = [System.Collections.Generic.List[string]]::new()

. (Join-Path $scriptDir "AzureCloudReview.Common.ps1")

function Write-Step {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Write-WarnStep {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
    if ($null -eq $script:CleanupWarnings) {
        $script:CleanupWarnings = [System.Collections.Generic.List[string]]::new()
    }
    $script:CleanupWarnings.Add($Message) | Out-Null
}

function Test-ExpectedLabName {
    param(
        [string[]]$ExpectedNames,
        [string]$Name
    )
    if (-not $ExpectedNames -or -not $Name) { return $false }
    return ($ExpectedNames -icontains $Name)
}

function Invoke-AzCli {
    param(
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [switch]$AllowFailure
    )
    $result = Invoke-AzCliRaw -ArgumentList $ArgumentList -AllowFailure:$AllowFailure
    if ($result.ExitCode -ne 0 -and -not $AllowFailure) {
        throw "az $($ArgumentList -join ' ') failed: $($result.StdErr)"
    }
    return $result
}

function Get-LabManifest {
    if (-not (Test-Path $manifestPath)) { return $null }
    return (Get-Content -Path $manifestPath -Raw | ConvertFrom-Json)
}

function Get-LabResourceNames {
    param($Manifest)
    $names = [System.Collections.Generic.List[string]]::new()
    if (-not $Manifest) { return @() }

    foreach ($prop in @(
        'StorageAccount', 'KeyVault', 'SqlServer', 'AppServicePlan',
        'WebApp', 'VirtualNetwork', 'NetworkSecurityGroup', 'VirtualMachine',
        'PublicIp', 'NetworkInterface',
        'ContainerRegistry', 'ServiceBusNamespace', 'CognitiveAccount', 'CosmosDb'
    )) {
        if ($Manifest.PSObject.Properties.Name -contains $prop) {
            $value = [string]$Manifest.$prop
            if ($value) { [void]$names.Add($value) }
        }
    }

    if ($Manifest.Prefix -and $Manifest.Suffix) {
        [void]$names.Add("$($Manifest.Prefix)-plan-$($Manifest.Suffix)")
        [void]$names.Add("$($Manifest.Prefix)-app-$($Manifest.Suffix)")
        [void]$names.Add("$($Manifest.Prefix)-pip-$($Manifest.Suffix)")
        [void]$names.Add("$($Manifest.Prefix)-nic-$($Manifest.Suffix)")
        [void]$names.Add("$($Manifest.Prefix)-sb-$($Manifest.Suffix)")
        [void]$names.Add("$($Manifest.Prefix)-cog-$($Manifest.Suffix)")
    }

    return @($names)
}

function Stop-LabVirtualMachine {
    param(
        [string]$ResourceGroup,
        [string]$VmName
    )
    if (-not $VmName) { return }

    $vm = Invoke-AzCliJson -ArgumentList @(
        "vm", "show", "-g", $ResourceGroup, "-n", $VmName, "--query", "name", "-o", "tsv"
    ) -AllowFailure
    if (-not $vm) { return }

    Write-Step "Stopping VM '$VmName' before delete (reduces lock delays)"
    Invoke-AzCli -ArgumentList @("vm", "deallocate", "-g", $ResourceGroup, "-n", $VmName) -AllowFailure | Out-Null
}

function Remove-LabKeyVaultBeforeGroupDelete {
    param(
        [string]$ResourceGroup,
        [string]$VaultName
    )
    if (-not $VaultName) { return }

    $exists = Invoke-AzCliJson -ArgumentList @(
        "keyvault", "show", "-n", $VaultName, "-g", $ResourceGroup, "--query", "name", "-o", "tsv"
    ) -AllowFailure
    if (-not $exists) { return }

    Write-Step "Deleting Key Vault '$VaultName' explicitly (soft-delete; purge after RG delete)"
    Invoke-AzCli -ArgumentList @("keyvault", "delete", "-n", $VaultName) -AllowFailure | Out-Null
}

function Wait-ResourceGroupDeleted {
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$TimeoutMinutes
    )

    Write-Step "Waiting for resource group '$Name' deletion (timeout ${TimeoutMinutes}m)..."
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while ((Get-Date) -lt $deadline) {
        $exists = Invoke-AzCliJson -ArgumentList @("group", "exists", "-n", $Name) -AllowFailure
        if ($exists -ne $true) {
            Write-Host "Resource group deleted." -ForegroundColor Green
            return $true
        }
        Start-Sleep -Seconds 15
    }

    throw "Timed out after ${TimeoutMinutes} minutes waiting for resource group '$Name' to delete. Check Azure Portal -> Resource groups, then re-run this script."
}

function Remove-SoftDeletedKeyVaults {
    param(
        [string[]]$ExpectedNames = @(),
        [string]$PreferredLocation = ""
    )

    if (-not $ExpectedNames) { $ExpectedNames = @() }

    $deleted = Invoke-AzCliJson -ArgumentList @("keyvault", "list-deleted") -AllowFailure -AllowEmpty
    if (-not $deleted) { return }

    foreach ($vault in @($deleted)) {
        if (-not $vault) { continue }

        $name = [string]$vault.name
        if (-not $name) { continue }

        $location = ""
        if ($vault.properties -and $vault.properties.location) {
            $location = [string]$vault.properties.location
        }
        elseif ($PreferredLocation) {
            $location = $PreferredLocation
        }

        $isLabVault = (Test-ExpectedLabName -ExpectedNames $ExpectedNames -Name $name) -or ($name -match '^crlabkv[a-z0-9]{0,18}$')

        if (-not $isLabVault) { continue }

        if (-not $location) {
            Write-WarnStep "Soft-deleted Key Vault '$name' has no location; cannot purge automatically."
            continue
        }

        if ($PreferredLocation -and $location -ne $PreferredLocation) {
            Write-WarnStep "Soft-deleted Key Vault '$name' is in '$location' (manifest location '$PreferredLocation'); attempting purge anyway."
        }

        Write-Step "Purging soft-deleted Key Vault '$name' in '$location'"
        Invoke-AzCli -ArgumentList @("keyvault", "purge", "-n", $name, "-l", $location) -AllowFailure | Out-Null
    }
}

function Remove-SoftDeletedCognitiveAccounts {
    param(
        [string[]]$ExpectedNames = @(),
        [string]$PreferredLocation = "",
        [string]$ResourceGroupName = ""
    )

    if (-not $ExpectedNames) { $ExpectedNames = @() }

    $deletedAccounts = Invoke-AzCliJson -ArgumentList @("cognitiveservices", "account", "list-deleted") -AllowFailure -AllowEmpty
    if (-not $deletedAccounts) { return }

    foreach ($account in @($deletedAccounts)) {
        if (-not $account) { continue }

        $fields = Get-CognitiveDeletedAccountFields -Account $account `
            -DefaultResourceGroup $ResourceGroupName -PreferredLocation $PreferredLocation
        $name = $fields.Name
        if (-not $name) { continue }

        $isLabAccount = (Test-ExpectedLabName -ExpectedNames $ExpectedNames -Name $name) -or
            ($name -match '^crlab-cog-[a-z0-9]{6}$')
        if (-not $isLabAccount) { continue }

        if (-not $fields.Location) {
            Write-WarnStep "Soft-deleted Cognitive account '$name' has no location; cannot purge automatically."
            continue
        }

        if (-not $fields.ResourceGroup -and -not $ResourceGroupName) { continue }
        $rg = if ($fields.ResourceGroup) { $fields.ResourceGroup } else { $ResourceGroupName }
        Invoke-PurgeSoftDeletedCognitiveAccount -ResourceGroupName $rg -CognitiveName $name -Location $fields.Location | Out-Null
    }
}

function Remove-TaggedLabResources {
    param([string]$ExcludeResourceGroup = "")

    $tagFilter = "$($script:LabTagKey)=$($script:LabTagValue)"
    $resources = Invoke-AzCliJson -ArgumentList @("resource", "list", "--tag", $tagFilter) -AllowFailure -AllowEmpty
    if (-not $resources) { return }

    foreach ($resource in @($resources)) {
        if (-not $resource) { continue }
        $rg = [string]$resource.resourceGroup
        $id = [string]$resource.id
        $name = [string]$resource.name
        $type = [string]$resource.type

        if (-not $id) { continue }
        if ($ExcludeResourceGroup -and ($rg -eq $ExcludeResourceGroup)) { continue }
        # az cli's --tag filter only matches one key=value pair; also require the ManagedBy tag
        # this script applies so a resource merely sharing Purpose=CloudReviewLab (e.g. from a
        # different tool/tenant) isn't swept up by this subscription-wide deletion.
        $managedBy = if ($resource.tags) { [string]$resource.tags.ManagedBy } else { $null }
        if ($managedBy -ne $script:LabManagedBy) { continue }

        Write-Step "Deleting tagged orphan: $type '$name' (RG: $rg)"
        Invoke-AzCli -ArgumentList @("resource", "delete", "--ids", $id, "--yes") -AllowFailure | Out-Null
    }
}

function Remove-LabPublicIpOrphans {
    $ips = Invoke-AzCliJson -ArgumentList @(
        "network", "public-ip", "list",
        "--query", "[?tags.$($script:LabTagKey)=='$($script:LabTagValue)' && tags.ManagedBy=='$($script:LabManagedBy)'].{name:name,group:resourceGroup,id:id}"
    ) -AllowFailure -AllowEmpty
    if (-not $ips) { return }

    foreach ($ip in @($ips)) {
        if (-not $ip) { continue }
        $ipId = [string]$ip.id
        if (-not $ipId) { continue }

        Write-Step "Deleting tagged public IP '$($ip.name)' in '$($ip.group)'"
        Invoke-AzCli -ArgumentList @("resource", "delete", "--ids", $ipId, "--yes") -AllowFailure | Out-Null
    }
}

function Remove-LabManagedDisks {
    $disks = Invoke-AzCliJson -ArgumentList @(
        "disk", "list",
        "--query", "[?tags.$($script:LabTagKey)=='$($script:LabTagValue)' && tags.ManagedBy=='$($script:LabManagedBy)'].{name:name,group:resourceGroup,id:id}"
    ) -AllowFailure -AllowEmpty
    if (-not $disks) { return }

    foreach ($disk in @($disks)) {
        if (-not $disk) { continue }
        $diskId = [string]$disk.id
        if (-not $diskId) { continue }

        Write-Step "Deleting tagged managed disk '$($disk.name)' in '$($disk.group)'"
        Invoke-AzCli -ArgumentList @("resource", "delete", "--ids", $diskId, "--yes") -AllowFailure | Out-Null
    }
}

function Test-LabCleanupComplete {
    param(
        [string]$ResourceGroup,
        [string[]]$ExpectedNames = @(),
        [string]$PreferredLocation = ""
    )

    if (-not $ExpectedNames) { $ExpectedNames = @() }

    $issues = [System.Collections.Generic.List[string]]::new()

    $rgExists = Invoke-AzCliJson -ArgumentList @("group", "exists", "-n", $ResourceGroup) -AllowFailure
    if ($rgExists -eq $true) {
        $issues.Add("Resource group '$ResourceGroup' still exists.") | Out-Null
    }

    $tagFilter = "$($script:LabTagKey)=$($script:LabTagValue)"
    $tagged = Invoke-AzCliJson -ArgumentList @("resource", "list", "--tag", $tagFilter) -AllowFailure -AllowEmpty
    if ($tagged -and @($tagged).Count -gt 0) {
        $issues.Add("$(@($tagged).Count) resource(s) still tagged '$tagFilter'.") | Out-Null
    }

    $deletedVaults = Invoke-AzCliJson -ArgumentList @("keyvault", "list-deleted") -AllowFailure -AllowEmpty
    if ($deletedVaults) {
        foreach ($vault in @($deletedVaults)) {
            if (-not $vault) { continue }
            $name = [string]$vault.name
            if (-not $name) { continue }
            if ((Test-ExpectedLabName -ExpectedNames $ExpectedNames -Name $name) -or ($name -match '^crlabkv[a-z0-9]{0,18}$')) {
                $issues.Add("Soft-deleted Key Vault '$name' still present (purge required).") | Out-Null
            }
        }
    }

    $deletedCognitive = Invoke-AzCliJson -ArgumentList @("cognitiveservices", "account", "list-deleted") -AllowFailure -AllowEmpty
    if ($deletedCognitive) {
        foreach ($account in @($deletedCognitive)) {
            if (-not $account) { continue }
            $name = [string]$account.name
            if (-not $name) { continue }
            if ((Test-ExpectedLabName -ExpectedNames $ExpectedNames -Name $name) -or ($name -match '^crlab-cog-[a-z0-9]{6}$')) {
                $issues.Add("Soft-deleted Cognitive account '$name' still present (purge required).") | Out-Null
            }
        }
    }

    if ($issues.Count -eq 0) {
        Write-Host "`nCleanup verification: no lab resources or soft-deleted vaults/cognitive accounts detected." -ForegroundColor Green
        return $true
    }

    Write-WarnStep "Cleanup verification found possible leftovers:"
    foreach ($issue in $issues) {
        Write-Host "  - $issue" -ForegroundColor Yellow
    }
    return $false
}

function Invoke-LabCleanupStep {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    try {
        & $Action
    }
    catch {
        $detail = $_.InvocationInfo.PositionMessage
        if ($detail) {
            Write-WarnStep "Post-delete cleanup step '$Name' failed: $($_.Exception.Message) ($detail)"
        }
        else {
            Write-WarnStep "Post-delete cleanup step '$Name' failed: $($_.Exception.Message)"
        }
    }
}

if (-not (Test-CommandAvailable "az")) {
    Write-Error "Azure CLI (az) is required."
}

try {
    $null = Resolve-AzCliExecutable
}
catch {
    Write-Error $_.Exception.Message
}

$account = Invoke-AzCliJson -ArgumentList @("account", "show") -AllowFailure
if (-not $account) {
    Write-Error "Not logged in. Run: az login"
}

$manifest = Get-LabManifest
if ($manifest) {
    if (-not $ResourceGroupName) { $ResourceGroupName = [string]$manifest.ResourceGroup }
    if (-not $SubscriptionId) { $SubscriptionId = [string]$manifest.SubscriptionId }
}

if (-not $ResourceGroupName) {
    $ResourceGroupName = "rg-cloudreview-lab"
}

if ($SubscriptionId) {
    Invoke-AzCli -ArgumentList @("account", "set", "--subscription", $SubscriptionId) | Out-Null
}
else {
    $SubscriptionId = [string](Invoke-AzCliJson -ArgumentList @("account", "show", "--query", "id", "-o", "tsv"))
}

$expectedNames = @(Get-LabResourceNames -Manifest $manifest)
$preferredLocation = if ($manifest) { [string]$manifest.Location } else { "" }
$vaultName = if ($manifest) { [string]$manifest.KeyVault } else { "" }
$vmName = if ($manifest) { [string]$manifest.VirtualMachine } else { "" }

Write-Host "`nAzure Review Lab - teardown (script v$destroyScriptVersion)" -ForegroundColor Yellow
Write-Host "Subscription  : $SubscriptionId"
Write-Host "Resource group  : $ResourceGroupName"
if ($preferredLocation) { Write-Host "Location        : $preferredLocation" }
Write-Host ""

# NOTE: the confirmation prompt must gate every destructive step below, not just the resource
# group delete - Remove-TaggedLabResources / Remove-LabPublicIpOrphans / Remove-LabManagedDisks
# are subscription-wide sweeps (not scoped to $ResourceGroupName) that ran unconditionally even
# without -Force whenever the RG didn't exist (e.g. typo'd name, already deleted, or the
# "group exists" query itself failed and -AllowFailure silently returned a falsy result).
if (-not $Force) {
    $answer = Read-Host "Delete resource group '$ResourceGroupName' and purge lingering/tagged lab objects across the subscription? [y/N]"
    if ($answer -notmatch '^[yY]') {
        Write-Host "Cancelled."
        return
    }
}

$rgExists = Invoke-AzCliJson -ArgumentList @("group", "exists", "-n", $ResourceGroupName) -AllowFailure

if ($rgExists -eq $true) {
    Stop-LabVirtualMachine -ResourceGroup $ResourceGroupName -VmName $vmName
    Remove-LabKeyVaultBeforeGroupDelete -ResourceGroup $ResourceGroupName -VaultName $vaultName

    Write-Step "Deleting resource group '$ResourceGroupName' (waiting for completion)"
    Invoke-AzCli -ArgumentList @("group", "delete", "-n", $ResourceGroupName, "--yes") | Out-Null
    Wait-ResourceGroupDeleted -Name $ResourceGroupName -TimeoutMinutes $WaitTimeoutMinutes | Out-Null
}
else {
    if ($null -eq $rgExists) {
        Write-WarnStep "Could not confirm whether resource group '$ResourceGroupName' exists (query failed) - continuing with orphan/Key Vault purge checks only; verify manually."
    }
    else {
        Write-Host "[i] Resource group '$ResourceGroupName' not found; continuing orphan and Key Vault purge checks." -ForegroundColor DarkGray
    }
}

Invoke-LabCleanupStep -Name "soft-deleted Key Vault purge" -Action {
    Remove-SoftDeletedKeyVaults -ExpectedNames $expectedNames -PreferredLocation $preferredLocation
}
Invoke-LabCleanupStep -Name "soft-deleted Cognitive Services purge" -Action {
    Remove-SoftDeletedCognitiveAccounts -ExpectedNames $expectedNames `
        -PreferredLocation $preferredLocation -ResourceGroupName $ResourceGroupName
}
Invoke-LabCleanupStep -Name "tagged orphan resources" -Action {
    Remove-TaggedLabResources -ExcludeResourceGroup $ResourceGroupName
}
Invoke-LabCleanupStep -Name "tagged public IPs" -Action {
    Remove-LabPublicIpOrphans
}
Invoke-LabCleanupStep -Name "tagged managed disks" -Action {
    Remove-LabManagedDisks
}
Invoke-LabCleanupStep -Name "cleanup verification" -Action {
    [void](Test-LabCleanupComplete -ResourceGroup $ResourceGroupName -ExpectedNames $expectedNames -PreferredLocation $preferredLocation)
}

if ((Test-Path $manifestPath) -and -not $KeepManifest) {
    Remove-Item -Path $manifestPath -Force
    Write-Step "Removed manifest: $manifestPath"
}

Write-Host ""
if ($script:CleanupWarnings.Count -eq 0) {
    Write-Host "Done. Lab resources removed; soft-deleted Key Vaults and Cognitive accounts purged where found." -ForegroundColor Green
}
else {
    Write-Host "Done with warnings. Review items above in Azure Portal -> Cost Management / Resource groups." -ForegroundColor Yellow
}

Write-Host @"

Cost notes:
  - This script purges soft-deleted Key Vaults and Cognitive Services accounts (common hidden leftovers).
  - It deletes resources tagged Purpose=CloudReviewLab outside the lab RG.
  - It does NOT remove subscription defaults such as NetworkWatcherRG unless tagged by this lab.
  - Confirm `$0 ongoing spend: Azure Portal -> Cost Management -> Cost analysis (filter by resource group '$ResourceGroupName').

"@ -ForegroundColor DarkGray
