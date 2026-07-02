<#
.SYNOPSIS
    Acquire a refresh token for AzureHound via device code (Azure PowerShell public client).

.DESCRIPTION
    Auth only — does not run AzureHound. ROADrecon stores a refresh token for the Azure CLI
    client (04b07795-...). AzureHound expects a token from the Azure PowerShell client
    (1950a258-...). Reusing .roadtools_auth typically fails with AADSTS70000 invalid_grant.

    Token is written to a local file (default: .\tools\azurehound.refresh). Run azurehound
    list in a separate step so auth and collection stay independent.

    https://bloodhound.specterops.io/collect-data/ce-collection/azurehound

.PARAMETER Tenant
    Tenant domain (e.g. contoso.onmicrosoft.com) or tenant GUID. Defaults to the signed-in az account.

.PARAMETER SavePath
    File path for the refresh token (plain text, one line). Default: ./tools/azurehound.refresh

.EXAMPLE
    .\Get-AzureHoundRefreshToken.ps1

.EXAMPLE
    pwsh ./Get-AzureHoundRefreshToken.ps1

.EXAMPLE
    $tenant = (az account show --query tenantDefaultDomain -o tsv)
    $rt = Get-Content ./tools/azurehound.refresh -Raw
    azurehound list -r $rt -t $tenant -o ./tools/azurehound.json

.NOTES
    Cross-platform: PowerShell 5.1+ on Windows, PowerShell 7 (pwsh) on Linux/macOS.
    Requires network access to login.microsoftonline.com. Optional: az CLI for default tenant.
#>

[CmdletBinding()]
param(
    [string]$Tenant,
    [string]$SavePath
)

$ErrorActionPreference = "Stop"

if (-not $SavePath) {
    $SavePath = Join-Path (Join-Path $PSScriptRoot "tools") "azurehound.refresh"
}

$AzurePsClientId = "1950a258-227b-4e31-a9cf-717495945fc2"
$DeviceCodeUri = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"
$TokenUri = "https://login.microsoftonline.com/common/oauth2/token?api-version=1.0"

if (-not $Tenant) {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "az CLI not found. Sign in with az login or pass -Tenant <domain-or-guid>."
    }
    $Tenant = az account show --query tenantDefaultDomain -o tsv 2>$null
    if (-not $Tenant) {
        throw "No az account context. Run az login or pass -Tenant."
    }
}

Write-Host "Tenant: $Tenant"
Write-Host "Requesting device code (Azure PowerShell client)..."

$dcBody = @{
    client_id = $AzurePsClientId
    resource  = "https://graph.microsoft.com"
}

$dc = Invoke-RestMethod -Method POST -Uri $DeviceCodeUri -Body $dcBody
Write-Host ""
Write-Host $dc.message
Write-Host ""

$tokenBody = @{
    client_id  = $AzurePsClientId
    grant_type = "urn:ietf:params:oauth:grant-type:device_code"
    code       = $dc.device_code
}

$deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
$pollSeconds = [Math]::Max(3, [int]$dc.interval)
$refreshToken = $null

# Do not use "continue" inside catch — Windows PowerShell falls through to rethrow.
while ((Get-Date) -lt $deadline -and -not $refreshToken) {
    $pollAgain = $false
    try {
        $tok = Invoke-RestMethod -Method POST -Uri $TokenUri -Body $tokenBody -ErrorAction Stop
        $refreshToken = $tok.refresh_token
    }
    catch {
        $raw = $_.ErrorDetails.Message
        if ($raw -match '"error"\s*:\s*"authorization_pending"') {
            $pollAgain = $true
        }
        elseif ($raw -match '"error"\s*:\s*"authorization_declined"') {
            throw "Device code sign-in was declined."
        }
        elseif ($raw -match '"error"\s*:\s*"expired_token"') {
            throw "Device code expired before sign-in completed."
        }
        else {
            throw
        }
    }

    if ($pollAgain) {
        Write-Host "Waiting for browser sign-in (poll every ${pollSeconds}s)..."
        Start-Sleep -Seconds $pollSeconds
    }
}

if (-not $refreshToken) {
    throw "Timed out waiting for device code authentication."
}

Write-Host "Refresh token acquired (starts with: $($refreshToken.Substring(0, [Math]::Min(12, $refreshToken.Length)))...)"

$dir = Split-Path -Parent $SavePath
if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($SavePath, $refreshToken, $utf8NoBom)
Write-Host "Saved to $SavePath"
Write-Host ""
Write-Host "Run AzureHound separately:"
Write-Host "  tenant=$Tenant"
Write-Host "  rt file: $SavePath"
Write-Host "  azurehound list -r `"<refresh-token>`" -t $Tenant -o $(Join-Path (Split-Path -Parent $SavePath) 'azurehound.json')"
