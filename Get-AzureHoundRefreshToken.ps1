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

[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Tenant,
    [string]$SavePath
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
        elseif ($raw -match '"error"\s*:\s*"slow_down"') {
            # Per the OAuth2 device authorization grant spec (RFC 8628 3.5), the client must
            # back off by increasing its polling interval, not treat this as a fatal error.
            $pollSeconds += 5
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

# Restrict the plaintext refresh token to the current user only - it otherwise inherits the
# parent directory's ACLs, which on a shared/jump-box host could leave a live credential
# readable by other local users/groups.
try {
    $acl = Get-Acl -LiteralPath $SavePath
    $acl.SetAccessRuleProtection($true, $false)
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "Allow")
    $acl.ResetAccessRule($rule)
    Set-Acl -LiteralPath $SavePath -AclObject $acl
}
catch {
    Write-Warning "Could not restrict ACL on ${SavePath}: $($_.Exception.Message)"
}

Write-Host "Saved to $SavePath"
Write-Host ""
Write-Host "Run AzureHound separately (copy/paste as-is):"
Write-Host "  `$rt = Get-Content `"$SavePath`" -Raw"
Write-Host "  azurehound list -r `$rt -t $Tenant -o `"$(Join-Path (Split-Path -Parent $SavePath) 'azurehound.json')`""
Write-Host ""
Write-Host "IMPORTANT: -r takes the TOKEN VALUE (the contents of the file above), never the" -ForegroundColor Yellow
Write-Host "file path/name itself - passing the filename as -r produces AADSTS9002313" -ForegroundColor Yellow
Write-Host "(""Invalid request. Request is malformed or invalid."")." -ForegroundColor Yellow
