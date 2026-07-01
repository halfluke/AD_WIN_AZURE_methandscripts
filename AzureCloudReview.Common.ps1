# Azure Cloud Review - shared helpers (dot-sourced by AzureCloudReviewv1.ps1)

$script:BloodHoundCeQuickstartUrl = "https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart"
$script:BloodHoundCliReleasesUrl = "https://github.com/SpecterOps/bloodhound-cli/releases/latest"
$script:BloodHoundCeUiUrl = "http://localhost:8080/ui/login"
$script:BloodHoundCeDownloadUrl = $script:BloodHoundCeQuickstartUrl

function Write-Log {
    param([string]$Message)
    Add-Content -Path $script:TxtLog -Value $Message -Encoding utf8
}

function Test-CommandAvailable {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Resolve-AzCliExecutable {
    if ($script:AzCliExecutable -and (Test-Path -LiteralPath $script:AzCliExecutable)) {
        return $script:AzCliExecutable
    }

    $cmd = Get-Command az -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -and (Test-Path -LiteralPath $cmd.Source)) {
        $script:AzCliExecutable = $cmd.Source
        return $script:AzCliExecutable
    }

    $candidates = @(
        "${env:ProgramFiles}\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
        "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            $script:AzCliExecutable = $candidate
            return $script:AzCliExecutable
        }
    }

    throw "Azure CLI (az) not found in PATH. Install: https://learn.microsoft.com/cli/azure/install-azure-cli (or winget install Microsoft.AzureCLI), then open a new PowerShell window."
}

function ConvertTo-AzCliArgumentString {
    param([Parameter(Mandatory)][string[]]$ArgumentList)

    $parts = foreach ($arg in $ArgumentList) {
        if ($null -eq $arg) { continue }
        $text = [string]$arg
        # cmd.exe treats | & ^ < > and spaces as special; quote so values like NODE|18-lts are not piped
        if ($text -match '[\s|&^<>"]') {
            '"' + ($text -replace '"', '""') + '"'
        }
        else {
            $text
        }
    }
    return ($parts -join ' ')
}

function Invoke-AzCliRaw {
    param(
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [switch]$AllowFailure
    )

    $azExe = Resolve-AzCliExecutable
    $allArgs = $ArgumentList + @("--only-show-errors")
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $azExe
    $psi.Arguments = ConvertTo-AzCliArgumentString -ArgumentList $allArgs
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
    }
    catch {
        throw "Failed to start Azure CLI at '$azExe': $($_.Exception.Message). Install Azure CLI and open a new PowerShell session."
    }
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    if ($proc.ExitCode -ne 0 -and -not $AllowFailure) {
        throw "az $(ConvertTo-AzCliArgumentString -ArgumentList $ArgumentList) failed ($($proc.ExitCode)): $stderr"
    }
    return @{
        ExitCode = $proc.ExitCode
        StdOut   = if ($null -ne $stdout) { $stdout.Trim() } else { "" }
        StdErr   = if ($null -ne $stderr) { $stderr.Trim() } else { "" }
    }
}

function Invoke-AzCliJson {
    param(
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [switch]$AllowFailure,
        [switch]$AllowEmpty
    )
    $azArgs = $ArgumentList + @("--output", "json")
    $result = Invoke-AzCliRaw -ArgumentList $azArgs -AllowFailure:$AllowFailure
    if ($result.ExitCode -ne 0) {
        if ($AllowFailure) { return $null }
        throw $result.StdErr
    }
    if (-not $result.StdOut) {
        if ($AllowEmpty) { return $null }
        return @()
    }
    return ($result.StdOut | ConvertFrom-Json)
}

function Register-AzureResourceProviders {
    <#
    .SYNOPSIS
        Register Azure resource providers required by Deploy-AzureReviewLab.ps1.
        New or free-tier subscriptions often need first-time registration (1-3 minutes each).
    #>
    param(
        [Parameter(Mandatory)][string[]]$Namespaces
    )

    foreach ($ns in $Namespaces) {
        $state = [string](Invoke-AzCliJson -ArgumentList @(
            "provider", "show", "--namespace", $ns, "--query", "registrationState", "-o", "tsv"
        ) -AllowFailure)
        if ($state -eq "Registered") { continue }

        Write-Host "[+] Registering Azure provider $ns (first use on this subscription; may take 1-3 minutes)" -ForegroundColor Cyan
        Invoke-AzCliRaw -ArgumentList @("provider", "register", "--namespace", $ns, "--wait") | Out-Null
    }
}

function Invoke-GraphGet {
    param([Parameter(Mandatory)][string]$Uri)
    return Invoke-AzCliJson -ArgumentList @("rest", "--method", "get", "--url", $Uri) -AllowFailure
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
                -Summary "No in-scope resources for this check." -Severity $Severity
            return
        }
        & $Test
    }
    catch {
        Add-ReviewResult -Section $Section -CheckId $CheckId -Title $Title -Status "ERROR" `
            -Summary $_.Exception.Message -Severity $Severity
    }
}

function Invoke-PerSubscription {
    param([Parameter(Mandatory)][scriptblock]$Action)
    foreach ($sub in $script:SubIds) {
        Invoke-AzCliRaw -ArgumentList @("account", "set", "--subscription", $sub) | Out-Null
        & $Action $sub
    }
}

function Get-ResourceCount {
    param([string]$ResourceType)
    $items = Invoke-AzCliJson -ArgumentList @("resource", "list", "--resource-type", $ResourceType) -AllowFailure -AllowEmpty
    if (-not $items) { return 0 }
    if ($items -isnot [array]) { return 1 }
    return $items.Count
}

function Test-ServiceResources {
    param(
        [string]$Section, [string]$CheckId, [string]$Title,
        [string]$ResourceType, [scriptblock]$Evaluate,
        [string]$Severity = "Medium"
    )
    Invoke-Check -Section $Section -CheckId $CheckId -Title $Title -Severity $Severity `
        -SkipIf { (Get-ResourceCount $ResourceType) -eq 0 } -Test {
        Invoke-PerSubscription {
            param($sub)
            $items = Invoke-AzCliJson -ArgumentList @("resource", "list", "--resource-type", $ResourceType) -AllowFailure -AllowEmpty
            & $Evaluate $sub $items
        }
    }
}

function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}

function Test-AzureCognitiveSoftDeletedError {
    param([string]$Text)
    if (-not $Text) { return $false }
    return ($Text -match 'FlagMustBeSetForRestore|has been soft-deleted|please purge it first')
}

function Get-CognitiveDeletedAccountFields {
    param(
        $Account,
        [string]$DefaultResourceGroup = "",
        [string]$PreferredLocation = ""
    )

    $name = [string]$Account.name
    $location = ""
    if ($Account.location) { $location = [string]$Account.location }
    elseif ($Account.properties -and $Account.properties.location) { $location = [string]$Account.properties.location }
    elseif ($PreferredLocation) { $location = $PreferredLocation }

    $resourceGroup = ""
    if ($Account.resourceGroup) { $resourceGroup = [string]$Account.resourceGroup }
    elseif ($Account.id -match '/resourceGroups/([^/]+)/') { $resourceGroup = $Matches[1] }
    elseif ($DefaultResourceGroup) { $resourceGroup = $DefaultResourceGroup }

    return @{
        Name          = $name
        Location      = $location
        ResourceGroup = $resourceGroup
    }
}

function Invoke-PurgeSoftDeletedCognitiveAccount {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$CognitiveName,
        [Parameter(Mandatory)][string]$Location
    )

    $locationCandidates = @($Location, 'uksouth', 'eastus', 'westus2', 'northeurope') |
        Where-Object { $_ } |
        Select-Object -Unique

    foreach ($loc in $locationCandidates) {
        $deleted = Invoke-AzCliJson -ArgumentList @(
            "cognitiveservices", "account", "show-deleted",
            "-g", $ResourceGroupName, "-n", $CognitiveName, "-l", $loc
        ) -AllowFailure
        if (-not $deleted) { continue }

        Write-Host "[+] Purging soft-deleted Cognitive account '$CognitiveName' in '$loc'" -ForegroundColor Cyan
        $purge = Invoke-AzCliRaw -ArgumentList @(
            "cognitiveservices", "account", "purge",
            "-g", $ResourceGroupName, "-n", $CognitiveName, "-l", $loc
        ) -AllowFailure
        if ($purge.ExitCode -eq 0) { return $true }
    }

    $deletedAccounts = Invoke-AzCliJson -ArgumentList @("cognitiveservices", "account", "list-deleted") -AllowFailure -AllowEmpty
    if (-not $deletedAccounts) { return $false }

    foreach ($account in @($deletedAccounts)) {
        if (-not $account) { continue }
        $fields = Get-CognitiveDeletedAccountFields -Account $account `
            -DefaultResourceGroup $ResourceGroupName -PreferredLocation $Location
        if ($fields.Name -ne $CognitiveName) { continue }
        if (-not $fields.Location) {
            Write-Warning "Soft-deleted Cognitive account '$CognitiveName' has no location; cannot purge automatically."
            return $false
        }

        $rg = if ($fields.ResourceGroup) { $fields.ResourceGroup } else { $ResourceGroupName }
        Write-Host "[+] Purging soft-deleted Cognitive account '$CognitiveName' in '$($fields.Location)' (RG: $rg)" -ForegroundColor Cyan
        $purge = Invoke-AzCliRaw -ArgumentList @(
            "cognitiveservices", "account", "purge",
            "-g", $rg, "-n", $CognitiveName, "-l", $fields.Location
        ) -AllowFailure
        return ($purge.ExitCode -eq 0)
    }

    return $false
}

function New-AzureCognitiveAccount {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$CognitiveName,
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Sku,
        [Parameter(Mandatory)][string]$Tags
    )

    Invoke-PurgeSoftDeletedCognitiveAccount -ResourceGroupName $ResourceGroupName `
        -CognitiveName $CognitiveName -Location $Location | Out-Null

    $createArgs = @(
        "cognitiveservices", "account", "create",
        "-g", $ResourceGroupName,
        "-n", $CognitiveName,
        "-l", $Location,
        "--kind", $Kind,
        "--sku", $Sku,
        "--yes",
        "--tags", $Tags
    )
    $result = Invoke-AzCliRaw -ArgumentList $createArgs -AllowFailure
    if ($result.ExitCode -eq 0) { return $result }

    if (Test-AzureCognitiveSoftDeletedError -Text $result.StdErr) {
        if (Invoke-PurgeSoftDeletedCognitiveAccount -ResourceGroupName $ResourceGroupName `
                -CognitiveName $CognitiveName -Location $Location) {
            return (Invoke-AzCliRaw -ArgumentList $createArgs -AllowFailure)
        }
    }

    return $result
}
