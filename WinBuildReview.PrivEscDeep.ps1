# Windows Build Review - deep local privesc helpers (dot-sourced by WinBuildReview.ps1)

function Initialize-WinBuildReviewToolPaths {
    param([Parameter(Mandatory)][string]$ScriptDirectory)
    $script:WinBuildToolsDir = Join-Path $ScriptDirectory "tools"
}

function Resolve-WinBuildReviewTool {
    param([Parameter(Mandatory)][string]$ToolName)

    $cmd = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    if ($script:WinBuildToolsDir) {
        $candidate = Join-Path $script:WinBuildToolsDir $ToolName
        if (Test-Path $candidate) { return $candidate }
    }

    return $null
}

function Test-WinBuildReviewToolAvailable {
    param([Parameter(Mandatory)][string]$ToolName)
    return [bool](Resolve-WinBuildReviewTool -ToolName $ToolName)
}

function Test-WeakPrincipalAce {
    param(
        $AccessEntry,
        [string]$RightsPattern = 'Write|Modify|FullControl|TakeOwnership|ChangePermissions'
    )
    if (-not $AccessEntry) { return $false }
    $id = [string]$AccessEntry.IdentityReference
    if ($id -notmatch '^(Everyone|Authenticated Users|BUILTIN\\Users|Users)$') { return $false }

    if ($AccessEntry.PSObject.Properties['FileSystemRights']) {
        return [bool]([string]$AccessEntry.FileSystemRights -match $RightsPattern)
    }
    if ($AccessEntry.PSObject.Properties['RegistryRights']) {
        return [bool]([string]$AccessEntry.RegistryRights -match $RightsPattern)
    }
    return $false
}

function Get-EnabledWhoamiPrivileges {
    $raw = whoami /priv 2>&1 | Out-String
    $enabled = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($raw -split "`r?`n")) {
        if ($line -match '^\s*(Se\w+Privilege)\s+.*?\s+Enabled\b') {
            $enabled.Add($Matches[1]) | Out-Null
        }
    }
    return $enabled
}

function Test-AlwaysInstallElevatedEnabled {
    $hkcu = Get-ItemProperty 'HKCU:\Software\Policies\Microsoft\Windows\Installer' `
        -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
    $hklm = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\Installer' `
        -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
    $enabled = ($hkcu -and [int]$hkcu.AlwaysInstallElevated -eq 1) -and `
        ($hklm -and [int]$hklm.AlwaysInstallElevated -eq 1)
    return [PSCustomObject]@{
        Enabled = $enabled
        HKCU    = if ($hkcu) { $hkcu.AlwaysInstallElevated } else { $null }
        HKLM    = if ($hklm) { $hklm.AlwaysInstallElevated } else { $null }
    }
}

function Get-WeakServiceBinaryHits {
    param([int]$MaxHits = 25)

    $hits = [System.Collections.Generic.List[object]]::new()
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.PathName -and $_.State -eq 'Running' }

    foreach ($svc in $services) {
        if ($hits.Count -ge $MaxHits) { break }
        $bin = Get-ServiceBinaryPath $svc.PathName
        if (-not $bin -or -not (Test-Path -LiteralPath $bin)) { continue }
        try {
            $acl = Get-Acl -LiteralPath $bin -ErrorAction Stop
            $risky = @($acl.Access | Where-Object { Test-WeakPrincipalAce $_ })
            if ($risky.Count -gt 0) {
                $hits.Add([PSCustomObject]@{
                        Service   = $svc.Name
                        StartName = $svc.StartName
                        Binary    = $bin
                        RiskyAce  = $risky | Select-Object IdentityReference, FileSystemRights
                    }) | Out-Null
            }
        }
        catch { }
    }

    return $hits
}

function Get-WritablePathEntries {
    param([int]$MaxHits = 20)

    $paths = @()
    foreach ($scope in @('Machine', 'User')) {
        $raw = [Environment]::GetEnvironmentVariable('Path', $scope)
        if ($raw) { $paths += $raw -split ';' }
    }

    $hits = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in ($paths | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() } | Select-Object -Unique)) {
        if ($hits.Count -ge $MaxHits) { break }
        if (-not (Test-Path -LiteralPath $entry)) { continue }
        try {
            $acl = Get-Acl -LiteralPath $entry -ErrorAction Stop
            $risky = @($acl.Access | Where-Object { Test-WeakPrincipalAce $_ })
            if ($risky.Count -gt 0) {
                $hits.Add([PSCustomObject]@{
                        Path     = $entry
                        RiskyAce = $risky | Select-Object IdentityReference, FileSystemRights
                    }) | Out-Null
            }
        }
        catch { }
    }

    return $hits
}

function Get-WeakServiceDaclHits {
    param([int]$MaxHits = 20)

    $hits = [System.Collections.Generic.List[object]]::new()
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -and $_.StartName -match 'LocalSystem|NetworkService|LocalService' }

    foreach ($svc in ($services | Select-Object -First 120)) {
        if ($hits.Count -ge $MaxHits) { break }
        $sd = sc.exe sdshow $svc.Name 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0 -or -not $sd.Trim()) { continue }
        if ($sd -match '(?i)(A|OA);;[^;]*(GA|GW|GR|SW|WO|RPWP|WP)[^;]*;;(BU|AU|WD)\)') {
            $hits.Add([PSCustomObject]@{
                    Service   = $svc.Name
                    StartName = $svc.StartName
                    SdShow    = $sd.Trim()
                }) | Out-Null
        }
    }

    return $hits
}

function Get-WinPeasBinaryName {
    if ([Environment]::Is64BitOperatingSystem) { return 'winPEASx64.exe' }
    return 'winPEASx86.exe'
}

function Get-WinPeasArgumentList {
    param(
        [ValidateSet('Focused', 'Full')]
        [string]$Profile = 'Focused',
        [switch]$IncludeDomainChecks
    )

    # Valid winPEAS module names (see PEASS-ng Checks.cs). Do NOT pass "cmd" — it is not a
    # module and causes winPEAS to run all checks (including slow eventsinfo log trawls).
    $modules = switch ($Profile) {
        'Focused' {
            @(
                'systeminfo', 'userinfo', 'processinfo', 'servicesinfo',
                'windowscreds', 'registryinfo', 'applicationsinfo'
            )
        }
        'Full' {
            @(
                'systeminfo', 'userinfo', 'processinfo', 'servicesinfo',
                'applicationsinfo', 'networkinfo', 'windowscreds', 'registryinfo',
                'browserinfo', 'cloudinfo'
            )
        }
    }

    if ($IncludeDomainChecks) {
        $modules += 'activedirectoryinfo'
    }

    return @($modules + @('quiet'))
}

function Get-WinPeasParsersDirectory {
    if ($script:WinBuildToolsDir) {
        $dir = Join-Path $script:WinBuildToolsDir 'parsers'
        if (Test-Path $dir) { return $dir }
    }
    return $null
}

function Test-WinPeasParsersInstalled {
    $dir = Get-WinPeasParsersDirectory
    if (-not $dir) { return $false }
    foreach ($name in @('peas2json.ps1', 'json2html.ps1', 'json2pdf.py')) {
        if (-not (Test-Path (Join-Path $dir $name))) { return $false }
    }
    return $true
}

function Get-WinPeasParserPythonCommand {
    foreach ($name in @('python', 'py', 'python3')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd }
    }
    return $null
}

function Get-WinPeasPythonExecutable {
    $cmd = Get-WinPeasParserPythonCommand
    if (-not $cmd) { return $null }

    $pythonExe = if ($cmd.Source) { $cmd.Source } elseif ($cmd.Path) { $cmd.Path } else { $null }
    if (-not $pythonExe) { return $null }

    if ($pythonExe -match '(?i)\\py\.exe$') {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        try {
            $resolved = & $pythonExe -3 -c "import sys; print(sys.executable)" 2>$null
            if ($resolved) { return $resolved.Trim() }
        }
        finally {
            $ErrorActionPreference = $prevEap
        }
    }

    return $pythonExe
}

function Test-WinPeasReportLabAvailable {
    $pythonExe = Get-WinPeasPythonExecutable
    if (-not $pythonExe) { return $false }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        & $pythonExe -c "import reportlab" 1>$null 2>$null
        return ($LASTEXITCODE -eq 0)
    }
    finally {
        $ErrorActionPreference = $prevEap
    }
}

function Resolve-WinPeasParserPath {
    param([Parameter(Mandatory)][string]$Path)

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    if (Test-Path -LiteralPath $Path) {
        return (Resolve-Path -LiteralPath $Path).Path
    }
    return [System.IO.Path]::GetFullPath($Path)
}

function Write-WinPeasParserWarning {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Get-TrimmedFileText {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ($null -eq $raw) { return '' }
    return $raw.Trim()
}

function Get-WinPeasPdfPageCount {
    param([Parameter(Mandatory)][string]$PdfFile)

    if (-not (Test-Path -LiteralPath $PdfFile)) { return $null }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($PdfFile)
        if ($bytes.Length -lt 64) { return $null }

        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        $match = [regex]::Match($text, '/Count\s+(\d+)')
        if ($match.Success) {
            return [int]$match.Groups[1].Value
        }
    }
    catch { }

    return $null
}

function Test-WinPeasPdfLikelyComplete {
    param(
        [Parameter(Mandatory)][string]$PdfFile,
        [Parameter(Mandatory)][string]$JsonFile
    )

    if (-not (Test-Path -LiteralPath $PdfFile)) { return $false }

    $pdfLen = (Get-Item -LiteralPath $PdfFile).Length
    if ($pdfLen -lt 8192) { return $false }

    $pageCount = Get-WinPeasPdfPageCount -PdfFile $PdfFile
    if ($pageCount -and $pageCount -lt 4) { return $false }

    if (Test-Path -LiteralPath $JsonFile) {
        $jsonLen = (Get-Item -LiteralPath $JsonFile).Length
        if ($jsonLen -gt 100000 -and $pdfLen -lt [math]::Max(8192, [int]($jsonLen / 50))) {
            return $false
        }
        if ($jsonLen -gt 500000 -and $pageCount -and $pageCount -lt 20) {
            return $false
        }
    }

    return $true
}

function Invoke-PythonScriptWithTimeout {
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string[]]$ScriptArguments,
        [string]$WorkingDirectory = '',
        [int]$TimeoutSeconds = 600
    )

    $pythonExe = Get-WinPeasPythonExecutable
    if (-not $pythonExe -or -not (Test-Path -LiteralPath $pythonExe)) {
        throw "Could not resolve Python executable"
    }

    $ScriptPath = Resolve-WinPeasParserPath -Path $ScriptPath
    $ScriptArguments = @($ScriptArguments | ForEach-Object { Resolve-WinPeasParserPath -Path $_ })

    if (-not $WorkingDirectory) {
        $WorkingDirectory = Split-Path -Parent $ScriptArguments[0]
    }
    if ($WorkingDirectory) {
        $WorkingDirectory = Resolve-WinPeasParserPath -Path $WorkingDirectory
    }

    $proc = $null
    try {
        # Do not redirect stdout/stderr here: filled pipe buffers can block json2pdf
        # during long reportlab multiBuild runs and leave a truncated PDF on disk.
        $startParams = @{
            FilePath     = $pythonExe
            ArgumentList = @('-u', $ScriptPath) + $ScriptArguments
            PassThru     = $true
            WindowStyle  = 'Hidden'
        }
        if ($WorkingDirectory) {
            $startParams['WorkingDirectory'] = $WorkingDirectory
        }

        $proc = Start-Process @startParams
        if (-not $proc) {
            throw "Failed to start Python process for $(Split-Path -Leaf $ScriptPath)"
        }

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while (-not $proc.HasExited) {
            if ((Get-Date) -gt $deadline) {
                try {
                    if (-not $proc.HasExited) { $proc.Kill() }
                }
                catch { }
                throw "timed out after $TimeoutSeconds seconds"
            }
            Start-Sleep -Milliseconds 500
        }

        if ($proc.ExitCode -ne 0) {
            throw "Python exit code $($proc.ExitCode) (run json2pdf.py manually on the JSON file for traceback)"
        }
    }
    finally {
        if ($proc -and -not $proc.HasExited) {
            try { $proc.Kill() } catch { }
        }
    }
}

function Invoke-PeasOutputToJson {
    param(
        [Parameter(Mandatory)][string]$ParserDir,
        [Parameter(Mandatory)][string]$RawOutputFile,
        [Parameter(Mandatory)][string]$JsonFile
    )

    $rawOutputFile = Resolve-WinPeasParserPath -Path $RawOutputFile
    $jsonFile = Resolve-WinPeasParserPath -Path $JsonFile

    $pythonExe = Get-WinPeasPythonExecutable
    $pyParser = Resolve-WinPeasParserPath -Path (Join-Path $ParserDir 'peas2json.py')
    if ($pythonExe -and (Test-Path -LiteralPath $pyParser)) {
        Write-Host "[>] peas2json.py" -ForegroundColor DarkGray
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        try {
            & $pythonExe $pyParser $rawOutputFile $jsonFile 2>$null
            if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
                throw "peas2json.py exit code $LASTEXITCODE"
            }
        }
        finally {
            $ErrorActionPreference = $prevEap
        }
        return 'peas2json.py'
    }

    Write-Host "[>] peas2json.ps1" -ForegroundColor DarkGray
    & (Join-Path $ParserDir 'peas2json.ps1') -OutputPath $rawOutputFile -JsonPath $jsonFile
    return 'peas2json.ps1'
}

function Get-WinPeasOutputBaseName {
    param([string]$FileTimestamp = '')

    if (-not $FileTimestamp) {
        $FileTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    }
    return "winpeas-$($env:COMPUTERNAME)-$FileTimestamp"
}

function Invoke-WinPeasParserPipeline {
    param(
        [Parameter(Mandatory)][string]$RawOutputFile,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string]$FileBaseName
    )

    if (-not (Test-WinPeasParsersInstalled)) {
        return [PSCustomObject]@{
            Ran      = $false
            Reason   = 'PEASS parsers not installed (Install-WinBuildReviewTools.ps1 -InstallAll)'
            JsonFile = $null
            HtmlFile = $null
            PdfFile  = $null
            Errors   = @()
        }
    }

    $OutputDirectory = Resolve-WinPeasParserPath -Path $OutputDirectory
    $RawOutputFile = Resolve-WinPeasParserPath -Path $RawOutputFile

    $parserDir = Get-WinPeasParsersDirectory
    $jsonFile = Resolve-WinPeasParserPath -Path (Join-Path $OutputDirectory "$FileBaseName.json")
    $htmlFile = Resolve-WinPeasParserPath -Path (Join-Path $OutputDirectory "$FileBaseName.html")
    $pdfFile = Resolve-WinPeasParserPath -Path (Join-Path $OutputDirectory "$FileBaseName.pdf")
    $errors = [System.Collections.Generic.List[string]]::new()

    Write-Host "[>] Running PEASS parsers on $(Split-Path -Leaf $RawOutputFile)" -ForegroundColor Yellow

    try {
        $jsonTool = Invoke-PeasOutputToJson -ParserDir $parserDir -RawOutputFile $RawOutputFile -JsonFile $jsonFile
        if (-not (Test-Path -LiteralPath $jsonFile)) { throw "$jsonTool did not create $jsonFile" }
        Write-Host "[+] $(Split-Path -Leaf $jsonFile) ($jsonTool)" -ForegroundColor Green
    }
    catch {
        $msg = "peas2json: $($_.Exception.Message)"
        $errors.Add($msg) | Out-Null
        Write-WinPeasParserWarning $msg
        return [PSCustomObject]@{
            Ran      = $true
            Reason   = $null
            JsonFile = $null
            HtmlFile = $null
            PdfFile  = $null
            Errors   = @($errors)
        }
    }

    try {
        & (Join-Path $parserDir 'json2html.ps1') -JsonPath $jsonFile -HtmlPath $htmlFile
        if (-not (Test-Path -LiteralPath $htmlFile)) { throw "json2html.ps1 did not create $htmlFile" }
        Write-Host "[+] $(Split-Path -Leaf $htmlFile)" -ForegroundColor Green
    }
    catch {
        $msg = "json2html: $($_.Exception.Message)"
        $errors.Add($msg) | Out-Null
        Write-WinPeasParserWarning $msg
    }

    $pdfCreated = $null
    if (Get-WinPeasPythonExecutable) {
        if (-not (Test-WinPeasReportLabAvailable)) {
            $msg = 'json2pdf: reportlab not installed (python -m pip install reportlab)'
            $errors.Add($msg) | Out-Null
            Write-WinPeasParserWarning $msg
        }
        else {
            try {
                Write-Host "[>] json2pdf.py -> $(Split-Path -Leaf $pdfFile) (large Full-profile reports can take several minutes; timeout 10m)" -ForegroundColor DarkGray
                if (Test-Path -LiteralPath $pdfFile) {
                    Remove-Item -LiteralPath $pdfFile -Force -ErrorAction SilentlyContinue
                }
                Invoke-PythonScriptWithTimeout `
                    -ScriptPath (Join-Path $parserDir 'json2pdf.py') `
                    -ScriptArguments @($jsonFile, $pdfFile) `
                    -WorkingDirectory $OutputDirectory `
                    -TimeoutSeconds 600
                if ((Test-Path -LiteralPath $pdfFile) -and (Test-WinPeasPdfLikelyComplete -PdfFile $pdfFile -JsonFile $jsonFile)) {
                    $pdfCreated = $pdfFile
                    $pdfBytes = (Get-Item -LiteralPath $pdfFile).Length
                    $pageCount = Get-WinPeasPdfPageCount -PdfFile $pdfFile
                    $pageNote = if ($pageCount) {
                        "$pageCount pages (pages 1-3 are TOC; findings from about page 4 - use Page Down or thumbnail view)"
                    } else {
                        'open in a full PDF reader (not Photos); early pages are TOC only'
                    }
                    Write-Host "[+] $(Split-Path -Leaf $pdfFile) ($pdfBytes bytes; $pageNote)" -ForegroundColor Green
                }
                elseif (Test-Path -LiteralPath $pdfFile) {
                    $pdfBytes = (Get-Item -LiteralPath $pdfFile).Length
                    $jsonBytes = (Get-Item -LiteralPath $jsonFile).Length
                    $pageCount = Get-WinPeasPdfPageCount -PdfFile $pdfFile
                    $pagePart = if ($pageCount) { "$pageCount pages" } else { 'unknown page count' }
                    $msg = "json2pdf: PDF looks truncated ($pdfBytes bytes, $pagePart vs JSON $jsonBytes bytes). Re-run json2pdf.py manually or delete the partial PDF and run WinBuildReview again."
                    $errors.Add($msg) | Out-Null
                    Write-WinPeasParserWarning $msg
                }
                else {
                    $msg = "json2pdf: PDF not created at $pdfFile (or empty after generation)"
                    $errors.Add($msg) | Out-Null
                    Write-WinPeasParserWarning $msg
                }
            }
            catch {
                $msg = "json2pdf: $($_.Exception.Message)"
                $errors.Add($msg) | Out-Null
                Write-WinPeasParserWarning $msg
            }
        }
    }
    else {
        $msg = 'json2pdf: Python not found (install Python + reportlab for PDF output)'
        $errors.Add($msg) | Out-Null
        Write-WinPeasParserWarning $msg
    }

    return [PSCustomObject]@{
        Ran      = $true
        Reason   = $null
        JsonFile = $jsonFile
        HtmlFile = if ((Test-Path -LiteralPath $htmlFile) -and ((Get-Item -LiteralPath $htmlFile).Length -gt 0)) { $htmlFile } else { $null }
        PdfFile  = $pdfCreated
        Errors   = @($errors)
    }
}

function Invoke-WinPeasCollection {
    param(
        [Parameter(Mandatory)][string]$OutputDirectory,
        [ValidateSet('Focused', 'Full')]
        [string]$Profile = 'Focused',
        [switch]$IncludeDomainChecks,
        [string]$FileTimestamp = '',
        [int]$TimeoutMinutes = 15
    )

    $binaryName = Get-WinPeasBinaryName
    $winPeas = Resolve-WinBuildReviewTool -ToolName $binaryName
    if (-not $winPeas) { throw "$binaryName not found in PATH or .\tools" }

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    $OutputDirectory = Resolve-WinPeasParserPath -Path $OutputDirectory

    $fileBaseName = Get-WinPeasOutputBaseName -FileTimestamp $FileTimestamp
    $outFile = Join-Path $OutputDirectory "$fileBaseName.out"
    $startedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $argList = @(Get-WinPeasArgumentList -Profile $Profile -IncludeDomainChecks:$IncludeDomainChecks)

    Write-Host "[>] Running winPEAS ($Profile profile) -> $outFile (live console output)" -ForegroundColor Yellow
    Write-Host "[>] Modules: $($argList -join ' ') (eventsinfo / filesinfo excluded)" -ForegroundColor DarkGray

    $exitCode = 0
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $writer = New-Object System.IO.StreamWriter($outFile, $false, $utf8NoBom)
    try {
        & $winPeas @argList 2>&1 | ForEach-Object {
            $text = $_.ToString()
            Write-Host $text
            $writer.WriteLine($text)
        }
        if ($null -ne $LASTEXITCODE) { $exitCode = $LASTEXITCODE }
    }
    finally {
        $writer.Flush()
        $writer.Close()
    }

    if (-not (Test-Path $outFile)) {
        throw "winPEAS did not create log file: $outFile"
    }

    $parserResult = Invoke-WinPeasParserPipeline -RawOutputFile $outFile -OutputDirectory $OutputDirectory -FileBaseName $fileBaseName

    $finishedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $outFile -Value "" -Encoding utf8
    Add-Content -Path $outFile -Value "# WinBuildReview wrapper" -Encoding utf8
    Add-Content -Path $outFile -Value "Started: $startedAt" -Encoding utf8
    Add-Content -Path $outFile -Value "Finished: $finishedAt" -Encoding utf8
    Add-Content -Path $outFile -Value "ExitCode: $exitCode" -Encoding utf8
    if ($parserResult.Ran) {
        Add-Content -Path $outFile -Value "Parsers: json=$($parserResult.JsonFile) html=$($parserResult.HtmlFile) pdf=$($parserResult.PdfFile)" -Encoding utf8
    }

    return [PSCustomObject]@{
        OutputFile = $outFile
        ExitCode   = $exitCode
        Binary     = $winPeas
        Profile    = $Profile
        Arguments  = ($argList -join ' ')
        Parsers    = $parserResult
    }
}
