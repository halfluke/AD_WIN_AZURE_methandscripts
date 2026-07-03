<#
.SYNOPSIS
    Deploy a Tier 2 Azure lab with intentionally weak settings for AzureCloudReviewv1.ps1 testing.

.DESCRIPTION
    Creates a tagged resource group and a small set of misconfigured resources that should
    produce FAIL/REVIEW rows in the cloud review script (storage, network, Key Vault, SQL,
    App Service; optional VM and extended services with -IncludeExtendedLab). Does not modify
    Entra tenant settings.

    Requires: Azure CLI (az), Contributor on the target subscription, az login completed.

.PARAMETER ResourceGroupName
    Resource group name. Default: rg-cloudreview-lab

.PARAMETER Location
    Azure region for most lab resources. Default: eastus

.PARAMETER SqlLocation
    Region for the SQL logical server. Defaults to -Location, then automatic fallbacks if that
    region is not accepting new SQL servers (common in eastus on free subscriptions).

.PARAMETER SkipSql
    Skip SQL server deployment (SQL review checks will SKIP in AzureCloudReview).

.PARAMETER SkipAppService
    Skip App Service plan and web app (App Service review checks will SKIP).

.PARAMETER ComputeLocation
    Region for App Service and VM. Defaults to -Location, then automatic fallbacks if
    compute/VM quota is zero in the primary region (common on free subscriptions in uksouth).

.PARAMETER SubscriptionId
    Target subscription. Default: current az account.

.PARAMETER Prefix
    Base name for resources (must be lowercase alphanumeric). Default: crlab

.PARAMETER IncludeVm
    Also deploy a small Linux VM with a public IP (~ ongoing compute cost).

.PARAMETER IncludeExtendedLab
    Also deploy misconfigured ACR (Basic), Service Bus (Basic), Cognitive Services (S0),
    and Cosmos DB (serverless) for extended AzureCloudReview FAIL rows (~ modest extra cost).

.EXAMPLE
    .\Deploy-AzureReviewLab.ps1

.EXAMPLE
    .\Deploy-AzureReviewLab.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -Location uksouth

.EXAMPLE
    .\Deploy-AzureReviewLab.ps1 -IncludeExtendedLab

.NOTES
    Delete with .\Destroy-AzureReviewLab.ps1 when finished to stop charges.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$ResourceGroupName = "rg-cloudreview-lab",
    [string]$Location = "eastus",
    [string]$SqlLocation = "",
    [switch]$SkipSql,
    [switch]$SkipAppService,
    [string]$ComputeLocation = "",
    [string]$SubscriptionId = "",
    [ValidatePattern('^[a-z][a-z0-9]{0,8}$')]
    [string]$Prefix = "crlab",
    [switch]$IncludeVm,
    [switch]$IncludeExtendedLab
)

$ErrorActionPreference = "Stop"

# With EAP=Stop, an unhandled exception raised deep inside a nested helper call unwinds
# through every calling function before PowerShell's default host display shows it - and
# that default display only shows the OUTERMOST call site (e.g. "New-LabExtendedServices"
# at its top-level call), not the actual line that failed. $_.ScriptStackTrace still has
# the real, innermost-first call chain, so surface it here instead of relying on the
# default one-line error display.
trap {
    Write-Host ""
    Write-Host "=== UNHANDLED ERROR ===" -ForegroundColor Red
    Write-Host "Message: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Call chain (innermost first):" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace
    exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$manifestPath = Join-Path $scriptDir "AzureReviewLab-manifest.json"

. (Join-Path $scriptDir "AzureCloudReview.Common.ps1")

function Write-Step {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Format-AzCliCommandForDisplay {
    param([Parameter(Mandatory)][string[]]$ArgumentList)
    $safe = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $ArgumentList.Count; $i++) {
        if ($i -gt 0 -and ($ArgumentList[$i - 1] -eq '-p' -or $ArgumentList[$i - 1] -eq '--password')) {
            $safe.Add('***') | Out-Null
        }
        else {
            $safe.Add($ArgumentList[$i]) | Out-Null
        }
    }
    return ($safe -join ' ')
}

function Invoke-AzCli {
    param(
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [switch]$AllowFailure
    )
    $result = Invoke-AzCliRaw -ArgumentList $ArgumentList -AllowFailure:$AllowFailure
    if ($result.ExitCode -ne 0 -and -not $AllowFailure) {
        throw "az $(Format-AzCliCommandForDisplay -ArgumentList $ArgumentList) failed ($($result.ExitCode)): $($result.StdErr)"
    }
    return $result
}

function Get-ComputeLocationCandidates {
    param(
        [string]$Preferred,
        [string]$Explicit
    )
    if ($Explicit) { return @($Explicit) }
    # eastus / westus2 first: free-tier subscriptions often have compute quota there but not uksouth
    $fallbacks = @("eastus", "westus2", "centralus", "eastus2", "northeurope", "uksouth", "southcentralus")
    $ordered = @($Preferred) + @($fallbacks | Where-Object { $_ -ne $Preferred })
    return $ordered
}

function Test-AzureComputeQuotaError {
    param([string]$Text)
    if (-not $Text) { return $false }
    # VM subscription quota and App Service regional capacity (different Azure error text)
    return ($Text -match 'Operation cannot be completed without additional quota|Additional details - Location:|Current Limit \(Total VMs\)|additional quota|No available instances to satisfy this request|attempting to increase capacity')
}

function Test-AzureUnsupportedRuntimeError {
    param([string]$Text)
    if (-not $Text) { return $false }
    return ($Text -match 'is not supported|list-runtimes')
}

function Get-LabLinuxNodeRuntimes {
    $listed = Invoke-AzCliJson -ArgumentList @("webapp", "list-runtimes", "--os-type", "linux") -AllowFailure -AllowEmpty
    $node = @()
    if ($listed) {
        $node = @($listed | Where-Object { $_ -match '^NODE:' } | Sort-Object -Descending)
    }
    if ($node.Count -eq 0) {
        $node = @("NODE:22-lts", "NODE:20-lts", "NODE:18-lts")
    }
    return $node
}

function New-LabAppService {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$PlanName,
        [Parameter(Mandatory)][string]$WebAppName,
        [Parameter(Mandatory)][string[]]$LocationCandidates,
        [Parameter(Mandatory)][string[]]$Tags
    )

    $runtimeCandidates = Get-LabLinuxNodeRuntimes

    foreach ($loc in $LocationCandidates) {
        Write-Host "  trying App Service region: $loc" -ForegroundColor DarkGray

        $planExists = Test-LabAzureResourceExists -ShowArgumentList @(
            "appservice", "plan", "show", "-g", $ResourceGroupName, "-n", $PlanName
        )
        if (-not $planExists) {
            $planResult = Invoke-AzCliRaw -ArgumentList (@(
                "appservice", "plan", "create",
                "-g", $ResourceGroupName,
                "-n", $PlanName,
                "-l", $loc,
                "--sku", "F1",
                "--is-linux",
                "--tags"
            ) + $Tags) -AllowFailure

            if ($planResult.ExitCode -ne 0) {
                if (Test-AzureComputeQuotaError -Text $planResult.StdErr) {
                    Write-Warning "App Service plan: no compute quota in '$loc'; trying next region."
                    continue
                }
                if (-not (Test-AzCliStdErrResourceExists -StdErr $planResult.StdErr)) {
                    throw "az appservice plan create failed in ${loc}: $($planResult.StdErr)"
                }
            }
        }

        if (Test-LabAzureResourceExists -ShowArgumentList @("webapp", "show", "-g", $ResourceGroupName, "-n", $WebAppName)) {
            Invoke-AzCli -ArgumentList @(
                "webapp", "config", "set",
                "-g", $ResourceGroupName,
                "-n", $WebAppName,
                "--remote-debugging-enabled", "true"
            ) -AllowFailure | Out-Null

            $webDetail = Invoke-AzCliJson -ArgumentList @("webapp", "show", "-g", $ResourceGroupName, "-n", $WebAppName) -AllowFailure
            $webLoc = if ($webDetail -and $webDetail.location) { [string]$webDetail.location } else { $loc }
            Write-Host "[i] Web app '$WebAppName' already exists; refreshed lab settings." -ForegroundColor DarkGray
            return @{ Created = $true; Location = $webLoc; Runtime = $null; AlreadyExisted = $true }
        }

        foreach ($runtime in $runtimeCandidates) {
            Write-Host "    runtime: $runtime" -ForegroundColor DarkGray
            $webResult = Invoke-AzCliRaw -ArgumentList (@(
                "webapp", "create",
                "-g", $ResourceGroupName,
                "-n", $WebAppName,
                "-p", $PlanName,
                "--runtime", $runtime,
                "--tags"
            ) + $Tags) -AllowFailure

            if ($webResult.ExitCode -eq 0) {
                Invoke-AzCli -ArgumentList @(
                    "webapp", "config", "set",
                    "-g", $ResourceGroupName,
                    "-n", $WebAppName,
                    "--remote-debugging-enabled", "true"
                ) -AllowFailure | Out-Null

                return @{ Created = $true; Location = $loc; Runtime = $runtime; AlreadyExisted = $false }
            }

            if (Test-AzureComputeQuotaError -Text $webResult.StdErr) {
                Write-Warning "Web app: no compute quota in '$loc'; trying next region."
                break
            }
            if (Test-AzureUnsupportedRuntimeError -Text $webResult.StdErr) {
                Write-Warning "Runtime '$runtime' not supported in '$loc'; trying next runtime."
                continue
            }

            throw "az webapp create failed in ${loc} (runtime ${runtime}): $($webResult.StdErr)"
        }
    }

    return @{ Created = $false; Location = $null; Runtime = $null; AlreadyExisted = $false }
}

function New-LabVirtualMachine {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$PrimaryLocation,
        [Parameter(Mandatory)][string]$PrimaryVnetName,
        [Parameter(Mandatory)][string]$PrimaryNsgName,
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][string]$PublicIpName,
        [Parameter(Mandatory)][string]$NicName,
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Suffix,
        [Parameter(Mandatory)][string[]]$LocationCandidates,
        [Parameter(Mandatory)][string[]]$Tags
    )

    foreach ($loc in $LocationCandidates) {
        Write-Host "  trying VM region: $loc" -ForegroundColor DarkGray

        if (Test-LabAzureResourceExists -ShowArgumentList @("vm", "show", "-g", $ResourceGroupName, "-n", $VmName)) {
            $vmDetail = Invoke-AzCliJson -ArgumentList @("vm", "show", "-g", $ResourceGroupName, "-n", $VmName) -AllowFailure
            Write-Host "[i] VM '$VmName' already exists." -ForegroundColor DarkGray

            # Don't assume the primary-region resource names: if this VM was actually created in
            # a prior run's fallback region, its real NIC/PIP/VNet/NSG carry region-suffixed names
            # (see below) that differ from $PublicIpName/$NicName/$PrimaryVnetName/$PrimaryNsgName -
            # returning the primary names unconditionally previously wrote wrong data into the
            # manifest. Derive the real names from the VM's actual NIC when possible.
            $realPipName = $PublicIpName
            $realNicName = $NicName
            $realVnetName = $PrimaryVnetName
            $realNsgName = $PrimaryNsgName
            $nicId = $null
            if ($vmDetail.networkProfile -and $vmDetail.networkProfile.networkInterfaces) {
                $nicId = [string]@($vmDetail.networkProfile.networkInterfaces)[0].id
            }
            if ($nicId) {
                $nicDetail = Invoke-AzCliJson -ArgumentList @("network", "nic", "show", "--ids", $nicId) -AllowFailure
                if ($nicDetail) {
                    $realNicName = [string]$nicDetail.name
                    if ($nicDetail.networkSecurityGroup -and $nicDetail.networkSecurityGroup.id) {
                        $realNsgName = Split-Path -Leaf ([string]$nicDetail.networkSecurityGroup.id)
                    }
                    $ipConfig = @($nicDetail.ipConfigurations) | Select-Object -First 1
                    if ($ipConfig) {
                        if ($ipConfig.publicIPAddress -and $ipConfig.publicIPAddress.id) {
                            $realPipName = Split-Path -Leaf ([string]$ipConfig.publicIPAddress.id)
                        }
                        if ($ipConfig.subnet -and $ipConfig.subnet.id) {
                            # subnet id: .../virtualNetworks/<vnet>/subnets/<subnet>
                            $subnetId = [string]$ipConfig.subnet.id
                            $vnetSegment = ($subnetId -split '/virtualNetworks/')[1]
                            if ($vnetSegment) { $realVnetName = ($vnetSegment -split '/')[0] }
                        }
                    }
                }
            }

            return @{
                Created      = $true
                Location     = if ($vmDetail.location) { [string]$vmDetail.location } else { $loc }
                PublicIpName = $realPipName
                NicName      = $realNicName
                VnetName     = $realVnetName
                NsgName      = $realNsgName
            }
        }

        $vnetName = $PrimaryVnetName
        $nsgName = $PrimaryNsgName
        $subnetName = "default"
        $pipName = $PublicIpName
        $nicNameLocal = $NicName

        if ($loc -ne $PrimaryLocation) {
            $vnetName = "${Prefix}-vmnet-$Suffix-$loc".Substring(0, [Math]::Min(64, "${Prefix}-vmnet-$Suffix-$loc".Length))
            $nsgName = "${Prefix}-vmnsg-$Suffix-$loc".Substring(0, [Math]::Min(64, "${Prefix}-vmnsg-$Suffix-$loc".Length))
            $subnetName = "default"
            $pipName = "${Prefix}-vmpip-$Suffix-$loc".Substring(0, [Math]::Min(64, "${Prefix}-vmpip-$Suffix-$loc".Length))
            $nicNameLocal = "${Prefix}-vmnic-$Suffix-$loc".Substring(0, [Math]::Min(64, "${Prefix}-vmnic-$Suffix-$loc".Length))

            $vnetExists = Invoke-AzCliJson -ArgumentList @(
                "network", "vnet", "show", "-g", $ResourceGroupName, "-n", $vnetName, "--query", "name", "-o", "tsv"
            ) -AllowFailure
            if (-not $vnetExists) {
                Invoke-AzCli -ArgumentList (@(
                    "network", "vnet", "create",
                    "-g", $ResourceGroupName,
                    "-n", $vnetName,
                    "-l", $loc,
                    "--address-prefix", "10.51.0.0/16",
                    "--subnet-name", $subnetName,
                    "--subnet-prefix", "10.51.1.0/24",
                    "--tags"
                ) + $Tags) | Out-Null

                Invoke-AzCli -ArgumentList (@(
                    "network", "nsg", "create",
                    "-g", $ResourceGroupName,
                    "-n", $nsgName,
                    "-l", $loc,
                    "--tags"
                ) + $Tags) | Out-Null

                Invoke-AzCli -ArgumentList @(
                    "network", "nsg", "rule", "create",
                    "-g", $ResourceGroupName,
                    "--nsg-name", $nsgName,
                    "-n", "AllowAllInboundInternet",
                    "--priority", "100",
                    "--direction", "Inbound",
                    "--access", "Allow",
                    "--protocol", "*",
                    "--source-address-prefixes", "0.0.0.0/0",
                    "--source-port-ranges", "*",
                    "--destination-address-prefixes", "*",
                    "--destination-port-ranges", "*"
                ) -AllowFailure | Out-Null
            }
        }

        $pipExists = Invoke-AzCliJson -ArgumentList @(
            "network", "public-ip", "show", "-g", $ResourceGroupName, "-n", $pipName, "--query", "name", "-o", "tsv"
        ) -AllowFailure
        if (-not $pipExists) {
            $pipResult = Invoke-AzCliRaw -ArgumentList (@(
                "network", "public-ip", "create",
                "-g", $ResourceGroupName,
                "-n", $pipName,
                "-l", $loc,
                "--sku", "Basic",
                "--tags"
            ) + $Tags) -AllowFailure
            if ($pipResult.ExitCode -ne 0) {
                if (Test-AzureComputeQuotaError -Text $pipResult.StdErr) { continue }
                throw "az network public-ip create failed in ${loc}: $($pipResult.StdErr)"
            }
        }

        $nicExists = Invoke-AzCliJson -ArgumentList @(
            "network", "nic", "show", "-g", $ResourceGroupName, "-n", $nicNameLocal, "--query", "name", "-o", "tsv"
        ) -AllowFailure
        if (-not $nicExists) {
            $nicResult = Invoke-AzCliRaw -ArgumentList (@(
                "network", "nic", "create",
                "-g", $ResourceGroupName,
                "-n", $nicNameLocal,
                "-l", $loc,
                "--vnet-name", $vnetName,
                "--subnet", $subnetName,
                "--network-security-group", $nsgName,
                "--public-ip-address", $pipName,
                "--tags"
            ) + $Tags) -AllowFailure
            if ($nicResult.ExitCode -ne 0) {
                if (Test-AzureComputeQuotaError -Text $nicResult.StdErr) { continue }
                throw "az network nic create failed in ${loc}: $($nicResult.StdErr)"
            }
        }

        $vmResult = Invoke-AzCliRaw -ArgumentList (@(
            "vm", "create",
            "-g", $ResourceGroupName,
            "-n", $VmName,
            "-l", $loc,
            "--nics", $nicNameLocal,
            "--image", "Ubuntu2204",
            "--size", "Standard_B1s",
            "--admin-username", "labuser",
            "--generate-ssh-keys",
            "--tags"
        ) + $Tags) -AllowFailure

        if ($vmResult.ExitCode -eq 0) {
            return @{
                Created      = $true
                Location     = $loc
                PublicIpName = $pipName
                NicName      = $nicNameLocal
                VnetName     = $vnetName
                NsgName      = $nsgName
            }
        }

        if (Test-AzureComputeQuotaError -Text $vmResult.StdErr) {
            Write-Warning "VM: no compute quota in '$loc'; trying next region."
            continue
        }

        throw "az vm create failed in ${loc}: $($vmResult.StdErr)"
    }

    return @{ Created = $false; Location = $null }
}

function Test-AzureCognitiveQuotaError {
    param([string]$Text)
    if (-not $Text) { return $false }
    return ($Text -match 'SpecialFeatureOrQuotaIdRequired|QuotaId/Feature|SkuNotAvailable|InvalidSkuId|not available in region')
}

function New-LabExtendedServices {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$AcrName,
        [Parameter(Mandatory)][string]$ServiceBusName,
        [Parameter(Mandatory)][string]$CognitiveName,
        [Parameter(Mandatory)][string]$CosmosName,
        [Parameter(Mandatory)][string[]]$Tags
    )

    $result = @{
        AcrCreated         = $false
        ServiceBusCreated  = $false
        CognitiveCreated   = $false
        CosmosCreated      = $false
    }

    Write-Step "Container Registry (Basic, public network enabled)"
    if (Test-LabAzureResourceExists -ShowArgumentList @("acr", "show", "-n", $AcrName, "-g", $ResourceGroupName)) {
        Write-Host "[i] ACR '$AcrName' already exists." -ForegroundColor DarkGray
        $result.AcrCreated = $true
    }
    else {
        $acrResult = Invoke-AzCliRaw -ArgumentList (@(
            "acr", "create",
            "-g", $ResourceGroupName,
            "-n", $AcrName,
            "-l", $Location,
            "--sku", "Basic",
            "--public-network-enabled", "true",
            "--tags"
        ) + $Tags) -AllowFailure
        if ($acrResult.ExitCode -eq 0) {
            $result.AcrCreated = $true
        }
        elseif (Test-LabAzureResourceExists -ShowArgumentList @("acr", "show", "-n", $AcrName, "-g", $ResourceGroupName)) {
            Write-Host "[i] ACR '$AcrName' already exists." -ForegroundColor DarkGray
            $result.AcrCreated = $true
        }
        else {
            Write-Warning "ACR create failed: $($acrResult.StdErr)"
        }
    }
    if ($result.AcrCreated) {
        Invoke-AzCli -ArgumentList @(
            "acr", "update", "-n", $AcrName, "-g", $ResourceGroupName,
            "--public-network-enabled", "true"
        ) -AllowFailure | Out-Null
    }

    Write-Step "Service Bus namespace (Basic, public network access)"
    if (Test-LabAzureResourceExists -ShowArgumentList @("servicebus", "namespace", "show", "-g", $ResourceGroupName, "-n", $ServiceBusName)) {
        Write-Host "[i] Service Bus '$ServiceBusName' already exists." -ForegroundColor DarkGray
        $result.ServiceBusCreated = $true
    }
    else {
        $sbResult = Invoke-AzCliRaw -ArgumentList (@(
            "servicebus", "namespace", "create",
            "-g", $ResourceGroupName,
            "-n", $ServiceBusName,
            "-l", $Location,
            "--sku", "Basic",
            "--tags"
        ) + $Tags) -AllowFailure
        if ($sbResult.ExitCode -eq 0) {
            $result.ServiceBusCreated = $true
        }
        elseif (Test-LabAzureResourceExists -ShowArgumentList @("servicebus", "namespace", "show", "-g", $ResourceGroupName, "-n", $ServiceBusName)) {
            Write-Host "[i] Service Bus '$ServiceBusName' already exists." -ForegroundColor DarkGray
            $result.ServiceBusCreated = $true
        }
        else {
            Write-Warning "Service Bus create failed: $($sbResult.StdErr)"
        }
    }

    Write-Step "Cognitive Services account (public network access enabled)"
    $cognitiveShowArgs = @("cognitiveservices", "account", "show", "-g", $ResourceGroupName, "-n", $CognitiveName)
    if (Test-LabAzureResourceExists -ShowArgumentList $cognitiveShowArgs) {
        Write-Host "[i] Cognitive account '$CognitiveName' already exists." -ForegroundColor DarkGray
        $result.CognitiveCreated = $true
    }
    else {
        $cognitiveProfiles = @(
            @{ Kind = "TextAnalytics"; Sku = "F0"; Label = "TextAnalytics F0" },
            @{ Kind = "CognitiveServices"; Sku = "F0"; Label = "CognitiveServices F0" },
            @{ Kind = "FormRecognizer"; Sku = "F0"; Label = "FormRecognizer F0" },
            @{ Kind = "TextAnalytics"; Sku = "S0"; Label = "TextAnalytics S0" }
        )
        foreach ($cogProfile in $cognitiveProfiles) {
            Write-Host "  trying Cognitive: $($cogProfile.Label)" -ForegroundColor DarkGray
            $cogResult = New-AzureCognitiveAccount -ResourceGroupName $ResourceGroupName `
                -CognitiveName $CognitiveName -Location $Location `
                -Kind $cogProfile.Kind -Sku $cogProfile.Sku -Tags $Tags
            if ($cogResult.ExitCode -eq 0) {
                $result.CognitiveCreated = $true
                break
            }
            if (Test-LabAzureResourceExists -ShowArgumentList $cognitiveShowArgs) {
                Write-Host "[i] Cognitive account '$CognitiveName' already exists." -ForegroundColor DarkGray
                $result.CognitiveCreated = $true
                break
            }
            if (Test-AzureCognitiveQuotaError -Text $cogResult.StdErr) {
                Write-Warning "Cognitive $($cogProfile.Label) not available on this subscription; trying next SKU."
                continue
            }
            if (Test-AzureCognitiveSoftDeletedError -Text $cogResult.StdErr) {
                Write-Warning "Cognitive account '$CognitiveName' is still soft-deleted after purge attempt."
            }
            Write-Warning "Cognitive Services create failed ($($cogProfile.Label)): $($cogResult.StdErr)"
            break
        }
        if (-not $result.CognitiveCreated) {
            Write-Warning "Cognitive Services was not created. AI Services review checks will SKIP."
        }
    }
    if ($result.CognitiveCreated) {
        Invoke-AzCli -ArgumentList @(
            "cognitiveservices", "account", "update",
            "-g", $ResourceGroupName, "-n", $CognitiveName,
            "--allow-public-network", "true"
        ) -AllowFailure | Out-Null
    }

    Write-Step "Cosmos DB (serverless, public network access enabled)"
    if (Test-LabAzureResourceExists -ShowArgumentList @("cosmosdb", "show", "-g", $ResourceGroupName, "-n", $CosmosName)) {
        Write-Host "[i] Cosmos DB '$CosmosName' already exists." -ForegroundColor DarkGray
        $result.CosmosCreated = $true
    }
    else {
        $cosmosResult = Invoke-AzCliRaw -ArgumentList (@(
            "cosmosdb", "create",
            "-g", $ResourceGroupName,
            "-n", $CosmosName,
            "--locations", "regionName=$Location",
            "--capabilities", "EnableServerless",
            "--default-consistency-level", "Session",
            "--public-network-access", "Enabled",
            "--tags"
        ) + $Tags) -AllowFailure
        if ($cosmosResult.ExitCode -eq 0) {
            $result.CosmosCreated = $true
        }
        elseif (Test-LabAzureResourceExists -ShowArgumentList @("cosmosdb", "show", "-g", $ResourceGroupName, "-n", $CosmosName)) {
            Write-Host "[i] Cosmos DB '$CosmosName' already exists." -ForegroundColor DarkGray
            $result.CosmosCreated = $true
        }
        else {
            Write-Warning "Cosmos DB create failed: $($cosmosResult.StdErr)"
        }
    }
    if ($result.CosmosCreated) {
        Invoke-AzCli -ArgumentList @(
            "cosmosdb", "update",
            "-g", $ResourceGroupName, "-n", $CosmosName,
            "--public-network-access", "Enabled"
        ) -AllowFailure | Out-Null
    }

    return $result
}

function Get-SqlLocationCandidates {
    param(
        [string]$Preferred,
        [string]$Explicit
    )
    if ($Explicit) { return @($Explicit) }
    $fallbacks = @("westus2", "centralus", "southcentralus", "eastus2", "uksouth", "northeurope")
    $ordered = @($Preferred) + @($fallbacks | Where-Object { $_ -ne $Preferred })
    return $ordered
}

function Get-PlainTextFromSecureString {
    param(
        [Parameter(Mandatory)][Security.SecureString]$SecureString
    )

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function New-LabSqlServer {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$ServerName,
        [Parameter(Mandatory)][Security.SecureString]$AdminPassword,
        [Parameter(Mandatory)][string[]]$LocationCandidates,
        [Parameter(Mandatory)][string[]]$Tags
    )

    $existing = Invoke-AzCliJson -ArgumentList @(
        "sql", "server", "show", "-g", $ResourceGroupName, "-n", $ServerName
    ) -AllowFailure
    if ($existing) {
        Write-Host "[i] SQL server '$ServerName' already exists." -ForegroundColor DarkGray
        Invoke-AzCli -ArgumentList @(
            "sql", "server", "firewall-rule", "create",
            "-g", $ResourceGroupName,
            "-s", $ServerName,
            "-n", "AllowAllAzureAndInternet",
            "--start-ip-address", "0.0.0.0",
            "--end-ip-address", "255.255.255.255"
        ) -AllowFailure | Out-Null
        return @{ Created = $true; Location = [string]$existing.location }
    }

    foreach ($loc in $LocationCandidates) {
        Write-Host "  trying region: $loc" -ForegroundColor DarkGray

        $plainPassword = Get-PlainTextFromSecureString -SecureString $AdminPassword
        try {
            $create = Invoke-AzCliRaw -ArgumentList (@(
                "sql", "server", "create",
                "-g", $ResourceGroupName,
                "-n", $ServerName,
                "-l", $loc,
                "-u", "labadmin",
                "-p", $plainPassword,
                "--enable-public-network", "true",
                "--tags"
            ) + $Tags) -AllowFailure
        }
        finally {
            $plainPassword = $null
        }

        if ($create.ExitCode -eq 0) {
            Invoke-AzCli -ArgumentList @(
                "sql", "server", "firewall-rule", "create",
                "-g", $ResourceGroupName,
                "-s", $ServerName,
                "-n", "AllowAllAzureAndInternet",
                "--start-ip-address", "0.0.0.0",
                "--end-ip-address", "255.255.255.255"
            ) | Out-Null
            return @{ Created = $true; Location = $loc }
        }

        if ($create.StdErr -notmatch 'RegionDoesNotAllowProvisioning') {
            throw "az sql server create failed in ${loc}: $($create.StdErr)"
        }

        Write-Warning "Region '$loc' is not accepting new SQL servers; trying next region."
    }

    return @{ Created = $false; Location = $null }
}

function Get-LabSuffix {
    param([string]$Seed)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Seed)
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return ([BitConverter]::ToString($hash) -replace '-', '').Substring(0, 6).ToLower()
}

function New-LabSecurePassword {
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%'
    $plain = -join (1..24 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return (ConvertTo-SecureString -String $plain -AsPlainText -Force)
}

function Test-LabResourceGroup {
    param([string]$Name)
    $existing = Invoke-AzCliJson -ArgumentList @("group", "exists", "-n", $Name) -AllowFailure
    return ($existing -eq $true)
}

function Test-LabAzureResourceExists {
    param(
        [Parameter(Mandatory)][string[]]$ShowArgumentList
    )

    $name = Invoke-AzCliJson -ArgumentList ($ShowArgumentList + @("--query", "name", "-o", "tsv")) -AllowFailure
    return [bool]($name -and ([string]$name).Trim().Length -gt 0)
}

function Test-AzCliStdErrResourceExists {
    param([string]$StdErr)
    if (-not $StdErr) { return $false }
    return ($StdErr -match 'already exists|AlreadyExists|Conflict|InUse')
}

function Get-LabManifestFromDisk {
    if (-not (Test-Path $manifestPath)) { return $null }
    try {
        return (Get-Content -Path $manifestPath -Raw | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

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
    Write-Error "Not logged in. Run: az login"
}

if ($SubscriptionId) {
    Invoke-AzCli -ArgumentList @("account", "set", "--subscription", $SubscriptionId) | Out-Null
}
else {
    $SubscriptionId = [string](Invoke-AzCliJson -ArgumentList @("account", "show", "--query", "id", "-o", "tsv"))
}

$tenantId = [string]$account.tenantId
$suffix = Get-LabSuffix -Seed "$SubscriptionId-$ResourceGroupName-$Prefix"
$labManagedBy = "Deploy-AzureReviewLab.ps1"
# Must stay an array of separate "Key=Value" tokens - az cli's --tags parser treats each argv
# token as one tag; a single pre-joined string previously collapsed all three tags into one
# malformed "Purpose" value and silently dropped Tier/ManagedBy from every deployed resource.
$tags = @("Purpose=CloudReviewLab", "Tier=2", "ManagedBy=$labManagedBy")

$storageName = "${Prefix}st$suffix".Substring(0, [Math]::Min(24, "${Prefix}st$suffix".Length))
$vaultName   = "${Prefix}kv$suffix".Substring(0, [Math]::Min(24, "${Prefix}kv$suffix".Length))
$sqlServer   = "${Prefix}sql$suffix".Substring(0, [Math]::Min(24, "${Prefix}sql$suffix".Length))
$planName    = "${Prefix}-plan-$suffix"
$webAppName  = "${Prefix}-app-$suffix"
$vnetName    = "${Prefix}-vnet-$suffix"
$nsgName     = "${Prefix}-nsg-$suffix"
$sqlPasswordSecure = $null

Write-Host "`nAzure Review Lab - Tier 2 deploy" -ForegroundColor Green
Write-Host "Subscription : $SubscriptionId"
Write-Host "Resource group : $ResourceGroupName ($Location)"
Write-Host "Name suffix    : $suffix`n"

$labProviders = @(
    "Microsoft.Storage",
    "Microsoft.Network",
    "Microsoft.KeyVault",
    "Microsoft.Sql",
    "Microsoft.Web"
)
if ($IncludeVm) { $labProviders += "Microsoft.Compute" }
if ($IncludeExtendedLab) {
    $labProviders += @(
        "Microsoft.ContainerRegistry",
        "Microsoft.ServiceBus",
        "Microsoft.CognitiveServices",
        "Microsoft.DocumentDB"
    )
}
Register-AzureResourceProviders -Namespaces $labProviders

if (Test-LabResourceGroup -Name $ResourceGroupName) {
    Write-Warning "Resource group '$ResourceGroupName' already exists. Re-run will update/create individual resources."
}
else {
    Write-Step "Creating resource group"
    Invoke-AzCli -ArgumentList (@(
        "group", "create", "-n", $ResourceGroupName, "-l", $Location, "--tags"
    ) + $tags) | Out-Null
}

Write-Step "Storage account (public blob access enabled)"
if (-not (Test-LabAzureResourceExists -ShowArgumentList @("storage", "account", "show", "-n", $storageName, "-g", $ResourceGroupName))) {
    $storageResult = Invoke-AzCli -ArgumentList (@(
        "storage", "account", "create",
        "-n", $storageName,
        "-g", $ResourceGroupName,
        "-l", $Location,
        "--sku", "Standard_LRS",
        "--allow-blob-public-access", "true",
        "--min-tls-version", "TLS1_0",
        "--tags"
    ) + $tags) -AllowFailure
    # Storage account names are globally unique across all of Azure - unlike ACR/ServiceBus/
    # Cognitive/Cosmos below, this previously had no failure check at all, so a name collision
    # would fail silently and the manifest would still record $storageName as if it succeeded.
    if ($storageResult.ExitCode -ne 0) {
        Write-Warning "Storage account create failed for '$storageName': $($storageResult.StdErr)"
    }
}
else {
    Write-Host "[i] Storage account '$storageName' already exists." -ForegroundColor DarkGray
}
$storageAccountReady = [bool](Test-LabAzureResourceExists -ShowArgumentList @("storage", "account", "show", "-n", $storageName, "-g", $ResourceGroupName))
if (-not $storageAccountReady) {
    Write-Warning "Storage account '$storageName' does not exist after create attempt; manifest will record it as unavailable."
}
Invoke-AzCli -ArgumentList @(
    "storage", "account", "update",
    "-n", $storageName,
    "-g", $ResourceGroupName,
    "--allow-blob-public-access", "true",
    "--min-tls-version", "TLS1_0"
) -AllowFailure | Out-Null

Write-Step "Virtual network and permissive NSG"
if (-not (Test-LabAzureResourceExists -ShowArgumentList @("network", "vnet", "show", "-g", $ResourceGroupName, "-n", $vnetName))) {
    Invoke-AzCli -ArgumentList (@(
        "network", "vnet", "create",
        "-g", $ResourceGroupName,
        "-n", $vnetName,
        "-l", $Location,
        "--address-prefix", "10.50.0.0/16",
        "--subnet-name", "default",
        "--subnet-prefix", "10.50.1.0/24",
        "--tags"
    ) + $tags) -AllowFailure | Out-Null
}
else {
    Write-Host "[i] Virtual network '$vnetName' already exists." -ForegroundColor DarkGray
}

if (-not (Test-LabAzureResourceExists -ShowArgumentList @("network", "nsg", "show", "-g", $ResourceGroupName, "-n", $nsgName))) {
    Invoke-AzCli -ArgumentList (@(
        "network", "nsg", "create",
        "-g", $ResourceGroupName,
        "-n", $nsgName,
        "-l", $Location,
        "--tags"
    ) + $tags) -AllowFailure | Out-Null
}
else {
    Write-Host "[i] NSG '$nsgName' already exists." -ForegroundColor DarkGray
}

Invoke-AzCli -ArgumentList @(
    "network", "nsg", "rule", "create",
    "-g", $ResourceGroupName,
    "--nsg-name", $nsgName,
    "-n", "AllowAllInboundInternet",
    "--priority", "100",
    "--direction", "Inbound",
    "--access", "Allow",
    "--protocol", "*",
    "--source-address-prefixes", "0.0.0.0/0",
    "--source-port-ranges", "*",
    "--destination-address-prefixes", "*",
    "--destination-port-ranges", "*"
) -AllowFailure | Out-Null

Write-Step "Key Vault (permissive network ACLs, no purge protection)"
if (-not (Test-LabAzureResourceExists -ShowArgumentList @("keyvault", "show", "-n", $vaultName, "-g", $ResourceGroupName))) {
    $keyVaultResult = Invoke-AzCli -ArgumentList (@(
        "keyvault", "create",
        "-g", $ResourceGroupName,
        "-n", $vaultName,
        "-l", $Location,
        "--enable-rbac-authorization", "false",
        "--tags"
    ) + $tags) -AllowFailure
    # Key Vault names are globally unique across all of Azure - unlike ACR/ServiceBus/Cognitive/
    # Cosmos below, this previously had no failure check at all, so a name collision would fail
    # silently and the manifest would still record $vaultName as if it succeeded.
    if ($keyVaultResult.ExitCode -ne 0) {
        Write-Warning "Key Vault create failed for '$vaultName': $($keyVaultResult.StdErr)"
    }
}
else {
    Write-Host "[i] Key Vault '$vaultName' already exists; applying lab settings." -ForegroundColor DarkGray
}
$keyVaultReady = [bool](Test-LabAzureResourceExists -ShowArgumentList @("keyvault", "show", "-n", $vaultName, "-g", $ResourceGroupName))
if (-not $keyVaultReady) {
    Write-Warning "Key Vault '$vaultName' does not exist after create attempt; manifest will record it as unavailable."
}

Invoke-AzCli -ArgumentList @(
    "keyvault", "update",
    "-n", $vaultName,
    "-g", $ResourceGroupName,
    "--set", "properties.enablePurgeProtection=false",
    "properties.networkAcls.defaultAction=Allow",
    "properties.networkAcls.bypass=AzureServices"
) -AllowFailure | Out-Null

Write-Step "SQL server (public access + open firewall rule)"
$sqlLocationUsed = $null
$sqlCreated = $false
if ($SkipSql) {
    Write-Warning "Skipping SQL server (-SkipSql)."
}
else {
    $existingSql = Invoke-AzCliJson -ArgumentList @("sql", "server", "show", "-g", $ResourceGroupName, "-n", $sqlServer) -AllowFailure
    if ($existingSql) {
        $sqlCreated = $true
        $sqlLocationUsed = [string]$existingSql.location
        Write-Host "[i] SQL server '$sqlServer' already exists." -ForegroundColor DarkGray
        Invoke-AzCli -ArgumentList @(
            "sql", "server", "firewall-rule", "create",
            "-g", $ResourceGroupName,
            "-s", $sqlServer,
            "-n", "AllowAllAzureAndInternet",
            "--start-ip-address", "0.0.0.0",
            "--end-ip-address", "255.255.255.255"
        ) -AllowFailure | Out-Null
    }
    else {
        $sqlPasswordSecure = New-LabSecurePassword
        $sqlLocations = Get-SqlLocationCandidates -Preferred $Location -Explicit $SqlLocation
        $sqlResult = New-LabSqlServer -ResourceGroupName $ResourceGroupName `
            -ServerName $sqlServer -AdminPassword $sqlPasswordSecure -LocationCandidates $sqlLocations -Tags $tags
        $sqlCreated = $sqlResult.Created
        $sqlLocationUsed = $sqlResult.Location
        if (-not $sqlCreated) {
            Write-Warning "SQL server was not created (no region accepted new servers). SQL review checks will SKIP. Retry with -SqlLocation westus2 or deploy other resources only."
            $sqlServer = $null
            $sqlPasswordSecure = $null
        }
        elseif ($sqlLocationUsed -ne $Location) {
            Write-Host "[i] SQL server created in '$sqlLocationUsed' (primary lab region is '$Location')." -ForegroundColor DarkGray
        }
    }
}

Write-Step "App Service plan (F1) and web app (remote debugging enabled)"
$appServiceCreated = $false
$appServiceLocationUsed = $null
if ($SkipAppService) {
    Write-Warning "Skipping App Service (-SkipAppService)."
    $planName = $null
    $webAppName = $null
}
else {
    $computeLocations = Get-ComputeLocationCandidates -Preferred $Location -Explicit $ComputeLocation
    $appResult = New-LabAppService -ResourceGroupName $ResourceGroupName `
        -PlanName $planName -WebAppName $webAppName -LocationCandidates $computeLocations -Tags $tags
    $appServiceCreated = $appResult.Created
    $appServiceLocationUsed = $appResult.Location
    if (-not $appServiceCreated) {
        Write-Warning "App Service could not be created in any tried region ($($computeLocations -join ', ')). App Service review checks will SKIP."
        Write-Warning "Retry with -ComputeLocation eastus, or request quota in the Azure Portal (see README Tier 2 lab -> Request compute quota)."
        $planName = $null
        $webAppName = $null
    }
    elseif ($appResult.AlreadyExisted) {
        if ($appServiceLocationUsed -and ($appServiceLocationUsed -ne $Location)) {
            Write-Host "[i] App Service already deployed in '$appServiceLocationUsed' (primary lab region is '$Location')." -ForegroundColor DarkGray
        }
    }
    elseif ($appServiceLocationUsed -ne $Location) {
        Write-Host "[i] App Service created in '$appServiceLocationUsed' (primary lab region is '$Location')." -ForegroundColor DarkGray
    }
}

$vmName = $null
$publicIpName = $null
$nicName = $null
$vmCreated = $false
$vmLocationUsed = $null
$vmVnetName = $null
$vmNsgName = $null
if ($IncludeVm) {
    Write-Step "Linux VM with public IP (B1s - ongoing cost)"
    # Azure VM name limits are 1-64 chars for Linux (vs. 1-15 for Windows NetBIOS names) - this VM
    # is always the Linux "Ubuntu2204" image, so truncating to 15 needlessly risked cutting into
    # the trailing hash suffix (reducing collision-avoidance entropy) for longer -Prefix values.
    $vmName = "${Prefix}vm$suffix".Substring(0, [Math]::Min(64, "${Prefix}vm$suffix".Length))
    $publicIpName = "${Prefix}-pip-$suffix"
    $nicName = "${Prefix}-nic-$suffix"

    $computeLocations = Get-ComputeLocationCandidates -Preferred $Location -Explicit $ComputeLocation
    $vmResult = New-LabVirtualMachine -ResourceGroupName $ResourceGroupName `
        -PrimaryLocation $Location -PrimaryVnetName $vnetName -PrimaryNsgName $nsgName `
        -VmName $vmName -PublicIpName $publicIpName -NicName $nicName `
        -Prefix $Prefix -Suffix $suffix -LocationCandidates $computeLocations -Tags $tags
    $vmCreated = $vmResult.Created
    $vmLocationUsed = $vmResult.Location
    if ($vmCreated) {
        $publicIpName = $vmResult.PublicIpName
        $nicName = $vmResult.NicName
        if ($vmResult.VnetName -and ($vmResult.VnetName -ne $vnetName)) {
            $vmVnetName = $vmResult.VnetName
            $vmNsgName = $vmResult.NsgName
        }
        if ($vmLocationUsed -ne $Location) {
            Write-Host "[i] VM created in '$vmLocationUsed' (primary lab region is '$Location')." -ForegroundColor DarkGray
        }
    }
    else {
        Write-Warning "VM could not be created in any tried region ($($computeLocations -join ', ')). VM review checks will SKIP."
        Write-Warning "Retry with -ComputeLocation eastus -IncludeVm, or request quota in the Azure Portal (see README Tier 2 lab -> Request compute quota)."
        $vmName = $null
        $publicIpName = $null
        $nicName = $null
    }
}

$acrName = $null
$serviceBusName = $null
$cognitiveName = $null
$cosmosName = $null
$extendedLabDeployed = $false
$acrCreated = $false
$serviceBusCreated = $false
$cognitiveCreated = $false
$cosmosCreated = $false
if ($IncludeExtendedLab) {
    $acrName = ("${Prefix}acr$suffix" -replace '[^a-z0-9]', '').Substring(0, [Math]::Min(50, ("${Prefix}acr$suffix" -replace '[^a-z0-9]', '').Length))
    if ($acrName.Length -lt 5) { $acrName = ("crlabacr$suffix" -replace '[^a-z0-9]', '').Substring(0, 12) }
    $serviceBusName = "${Prefix}-sb-$suffix".Substring(0, [Math]::Min(50, "${Prefix}-sb-$suffix".Length))
    $cognitiveName = "${Prefix}-cog-$suffix".Substring(0, [Math]::Min(64, "${Prefix}-cog-$suffix".Length))
    $cosmosName = ("${Prefix}cosmos$suffix" -replace '[^a-z0-9-]', '').ToLowerInvariant()
    $cosmosName = $cosmosName.Substring(0, [Math]::Min(44, $cosmosName.Length))

    $extendedResult = New-LabExtendedServices -ResourceGroupName $ResourceGroupName -Location $Location `
        -AcrName $acrName -ServiceBusName $serviceBusName -CognitiveName $cognitiveName `
        -CosmosName $cosmosName -Tags $tags
    $acrCreated = $extendedResult.AcrCreated
    $serviceBusCreated = $extendedResult.ServiceBusCreated
    $cognitiveCreated = $extendedResult.CognitiveCreated
    $cosmosCreated = $extendedResult.CosmosCreated
    $extendedLabDeployed = ($acrCreated -or $serviceBusCreated -or $cognitiveCreated -or $cosmosCreated)

    if (-not $acrCreated) { $acrName = $null }
    if (-not $serviceBusCreated) { $serviceBusName = $null }
    if (-not $cognitiveCreated) { $cognitiveName = $null }
    if (-not $cosmosCreated) { $cosmosName = $null }
}

$sqlAdminPasswordForManifest = $null
if ($sqlCreated -and $sqlPasswordSecure) {
    $sqlAdminPasswordForManifest = Get-PlainTextFromSecureString -SecureString $sqlPasswordSecure
}
elseif ($sqlCreated) {
    $previousManifest = Get-LabManifestFromDisk
    if ($previousManifest -and $previousManifest.SqlAdminPassword) {
        $sqlAdminPasswordForManifest = [string]$previousManifest.SqlAdminPassword
    }
}

$manifest = [ordered]@{
    DeployedAt       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    SubscriptionId   = $SubscriptionId
    TenantId         = $tenantId
    ResourceGroup    = $ResourceGroupName
    Location         = $Location
    SqlLocation      = $sqlLocationUsed
    SqlDeployed      = $sqlCreated
    AppServiceDeployed = $appServiceCreated
    AppServiceLocation = $appServiceLocationUsed
    VmDeployed       = $vmCreated
    VmLocation       = $vmLocationUsed
    Prefix           = $Prefix
    Suffix           = $suffix
    StorageAccount   = if ($storageAccountReady) { $storageName } else { $null }
    KeyVault         = if ($keyVaultReady) { $vaultName } else { $null }
    SqlServer        = $sqlServer
    SqlAdminUser     = "labadmin"
    SqlAdminPassword = $sqlAdminPasswordForManifest
    AppServicePlan   = $planName
    WebApp           = $webAppName
    VirtualNetwork   = $vnetName
    NetworkSecurityGroup = $nsgName
    VirtualMachine   = $vmName
    VmVirtualNetwork = $vmVnetName
    VmNetworkSecurityGroup = $vmNsgName
    PublicIp         = $publicIpName
    NetworkInterface = $nicName
    ExtendedLabDeployed = $extendedLabDeployed
    ContainerRegistry  = $acrName
    AcrDeployed        = $acrCreated
    ServiceBusNamespace = $serviceBusName
    ServiceBusDeployed = $serviceBusCreated
    CognitiveAccount   = $cognitiveName
    CognitiveDeployed  = $cognitiveCreated
    CosmosDb           = $cosmosName
    CosmosDeployed     = $cosmosCreated
    ExpectedReviewFindings = @(
        "Storage: allowBlobPublicAccess, TLS1_0"
        "Network: NSG inbound 0.0.0.0/0"
        "Key Vault: network Allow, no purge protection"
        "SQL: open firewall 0.0.0.0-255.255.255.255"
        "App Service: remote debugging enabled"
        "VM: public IP (if -IncludeVm)"
        "ACR: public network, no private endpoint (if -IncludeExtendedLab)"
        "Service Bus: public network access (if -IncludeExtendedLab)"
        "Cognitive Services: public network access (if -IncludeExtendedLab)"
        "Cosmos DB: serverless, public network access (if -IncludeExtendedLab)"
    )
}

$manifest | ConvertTo-Json -Depth 4 | Set-Content -Path $manifestPath -Encoding utf8
$sqlPasswordSecure = $null
$sqlAdminPasswordForManifest = $null

Write-Host "`nDeploy complete." -ForegroundColor Green
if (-not $SkipAppService -and -not $appServiceCreated) {
    Write-Host "Note: App Service was skipped (no compute quota in any tried region)." -ForegroundColor Yellow
}
if ($IncludeVm -and -not $vmCreated) {
    Write-Host "Note: VM was skipped (no compute quota in any tried region)." -ForegroundColor Yellow
}
if ($IncludeExtendedLab -and -not $extendedLabDeployed) {
    Write-Host "Note: Extended lab resources were not created (see warnings above)." -ForegroundColor Yellow
}
elseif ($IncludeExtendedLab) {
    $extendedParts = @()
    if ($acrCreated) { $extendedParts += "ACR" }
    if ($serviceBusCreated) { $extendedParts += "Service Bus" }
    if ($cognitiveCreated) { $extendedParts += "Cognitive" }
    if ($cosmosCreated) { $extendedParts += "Cosmos" }
    Write-Host "Extended lab : $($extendedParts -join ', ')" -ForegroundColor DarkGray
}
Write-Host "Manifest : $manifestPath"
Write-Host "SQL admin: $(if ($sqlCreated) { 'labadmin / (saved in manifest only - lab use)' } else { '(not deployed)' })`n"

Write-Host "Run the review:" -ForegroundColor Yellow
Write-Host "  .\AzureCloudReviewv1.ps1 -SubscriptionId `"$SubscriptionId`""
Write-Host "  .\AzureCloudReviewv1.ps1 -SubscriptionId `"$SubscriptionId`" -RunProwler`n"
Write-Host "Teardown:" -ForegroundColor Yellow
Write-Host "  .\Destroy-AzureReviewLab.ps1`n"
