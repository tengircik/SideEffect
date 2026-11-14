[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $SideEffectPath
)

$ErrorActionPreference = 'Stop'

function Assert-UnderPath {
    param(
        [Parameter(Mandatory = $true)][string] $Child,
        [Parameter(Mandatory = $true)][string] $Parent,
        [Parameter(Mandatory = $true)][string] $Label
    )

    $childPath = [System.IO.Path]::GetFullPath($Child)
    $parentPath = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if (-not $childPath.StartsWith($parentPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escaped its allowed parent path."
    }
}

function Invoke-WixTool {
    param(
        [Parameter(Mandatory = $true)][string] $Tool,
        [Parameter(Mandatory = $true)][string[]] $Arguments
    )

    & $Tool @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "WiX tool failed with exit code ${LASTEXITCODE}: $Tool"
    }
}

function New-MsiFixture {
    param(
        [Parameter(Mandatory = $true)][string] $WxsPath,
        [Parameter(Mandatory = $true)][string] $WixObjPath,
        [Parameter(Mandatory = $true)][string] $MsiPath,
        [Parameter(Mandatory = $true)][string] $PayloadPath,
        [Parameter(Mandatory = $true)][string] $Version,
        [Parameter(Mandatory = $true)][string] $ProductCode,
        [Parameter(Mandatory = $true)][string] $UpgradeCode,
        [Parameter(Mandatory = $true)][string] $ComponentCode,
        [Parameter(Mandatory = $true)][string] $DefaultDirectoryName,
        [Parameter(Mandatory = $true)][string] $DefaultInstallRoot,
        [Parameter(Mandatory = $true)][string] $CabinetName,
        [Parameter(Mandatory = $true)][string] $ExpectedCabinet,
        [Parameter(Mandatory = $true)][string] $CandlePath,
        [Parameter(Mandatory = $true)][string] $LightPath
    )

    $wxs = @'
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="$(var.ProductCode)"
           Name="SideEffect R5 Synthetic MSI Fixture"
           Language="1033"
           Version="$(var.ProductVersion)"
           Manufacturer="SideEffect Test Fixture"
           UpgradeCode="$(var.UpgradeCode)">
    <Package InstallerVersion="500"
             Compressed="yes"
             InstallScope="perUser"
             InstallPrivileges="limited" />
    <MajorUpgrade DowngradeErrorMessage="A later synthetic fixture version is already installed." />
    <Media Id="1" Cabinet="$(var.CabinetName)" EmbedCab="yes" />
    <Property Id="INSTALLROOT" Value="$(var.DefaultInstallRoot)" Secure="yes" />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="INSTALLROOT" Name="$(var.DefaultDirectoryName)" />
    </Directory>
    <Feature Id="FixtureFeature" Title="Synthetic fixture payload" Level="1">
      <ComponentRef Id="FixturePayload" />
    </Feature>
    <DirectoryRef Id="INSTALLROOT">
      <Component Id="FixturePayload" Guid="$(var.ComponentCode)">
        <File Id="FixturePayloadFile"
              Name="payload.bin"
              Source="$(var.PayloadPath)"
              KeyPath="yes" />
      </Component>
    </DirectoryRef>
  </Product>
</Wix>
'@
    Set-Content -LiteralPath $WxsPath -Value $wxs -Encoding utf8

    [xml] $source = Get-Content -LiteralPath $WxsPath -Raw
    foreach ($forbiddenElement in @('CustomAction', 'ServiceInstall', 'ServiceControl', 'RegistryKey', 'RegistryValue', 'Shortcut')) {
        if ($source.SelectSingleNode("//*[local-name()='$forbiddenElement']")) {
            throw "Synthetic MSI fixture must not contain $forbiddenElement."
        }
    }

    $compileArguments = @(
        '-nologo',
        "-dProductCode=$ProductCode",
        "-dProductVersion=$Version",
        "-dUpgradeCode=$UpgradeCode",
        "-dComponentCode=$ComponentCode",
        "-dDefaultDirectoryName=$DefaultDirectoryName",
        "-dDefaultInstallRoot=$DefaultInstallRoot",
        "-dCabinetName=$CabinetName",
        "-dPayloadPath=$PayloadPath",
        '-out', $WixObjPath,
        $WxsPath
    )
    Invoke-WixTool -Tool $CandlePath -Arguments $compileArguments
    Invoke-WixTool -Tool $LightPath -Arguments @('-nologo', '-out', $MsiPath, $WixObjPath)

    if (-not (Test-Path -LiteralPath $MsiPath -PathType Leaf)) {
        throw "WiX completed without creating the expected MSI package: $MsiPath"
    }
    if ((Get-Item -LiteralPath $MsiPath).Length -le 0) {
        throw "WiX created an empty MSI package: $MsiPath"
    }
    $cabinets = @(Get-MsiCabinetIdentifiers -MsiPath $MsiPath)
    if ($cabinets.Count -ne 1 -or $cabinets[0] -ne $ExpectedCabinet -or -not $cabinets[0].StartsWith('#', [System.StringComparison]::Ordinal)) {
        throw "MSI Media table did not contain the expected independently embedded cabinet '$ExpectedCabinet'; observed: $($cabinets -join ', ')."
    }
}

function Get-MsiCabinetIdentifiers {
    param([Parameter(Mandatory = $true)][string] $MsiPath)

    $installer = $null
    $database = $null
    $view = $null
    $identifiers = [System.Collections.Generic.List[string]]::new()
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.OpenDatabase([System.IO.Path]::GetFullPath($MsiPath), 0) # MSIDBOPEN_READONLY
        $view = $database.OpenView('SELECT `Cabinet` FROM `Media`')
        [void]$view.Execute($null)
        while ($true) {
            $record = $view.Fetch()
            if ($null -eq $record) {
                break
            }
            try {
                $identifiers.Add([string]$record.StringData(1))
            }
            finally {
                [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($record)
            }
        }
        return @($identifiers.ToArray() | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    finally {
        if ($null -ne $view) {
            try { [void]$view.Close() } catch { }
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($view)
        }
        if ($null -ne $database) {
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($database)
        }
        if ($null -ne $installer) {
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
        }
    }
}

function Invoke-Msi {
    param(
        [Parameter(Mandatory = $true)][string] $ArgumentLine,
        [Parameter(Mandatory = $true)][string] $Description,
        [Parameter(Mandatory = $true)][string] $LogPath,
        [Parameter()][string] $PackagePath,
        [Parameter()][int[]] $AcceptedExitCodes = @()
    )

    $LogPath = [System.IO.Path]::GetFullPath($LogPath)
    Assert-UnderPath -Child $LogPath -Parent $script:TestRoot -Label 'MSI log'
    if (-not [string]::IsNullOrWhiteSpace($PackagePath)) {
        $PackagePath = [System.IO.Path]::GetFullPath($PackagePath)
        Assert-UnderPath -Child $PackagePath -Parent $script:TestRoot -Label 'MSI package'
        if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
            throw "$Description cannot start because the MSI package does not exist: $PackagePath"
        }
        if ((Get-Item -LiteralPath $PackagePath).Length -le 0) {
            throw "$Description cannot start because the MSI package is empty: $PackagePath"
        }
    }

    # Start-Process receives one explicit Windows command line. Quote package and log
    # paths literally because Windows Installer parses its own command-line grammar.
    $processId = [Guid]::NewGuid().ToString('N')
    $stdoutPath = Join-Path $script:TestRoot "msiexec-$processId.stdout.txt"
    $stderrPath = Join-Path $script:TestRoot "msiexec-$processId.stderr.txt"
    Assert-UnderPath -Child $stdoutPath -Parent $script:TestRoot -Label 'MSI stdout'
    Assert-UnderPath -Child $stderrPath -Parent $script:TestRoot -Label 'MSI stderr'
    $process = Start-Process -FilePath $script:MsiexecPath -ArgumentList $ArgumentLine `
        -WorkingDirectory $script:TestRoot -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath -Wait -PassThru -NoNewWindow
    $exitCode = $process.ExitCode
    if ($exitCode -eq 0 -or $AcceptedExitCodes -contains $exitCode) {
        return
    }
    if ($exitCode -ne 0) {
        $hint = switch ($exitCode) {
            1619 { 'Windows Installer could not open the package; check the package path, access, and MSI validity.' }
            1618 { 'Another Windows Installer operation is in progress on this runner.' }
            1603 { 'Windows Installer reported a fatal installation error; inspect the verbose log.' }
            default { 'Inspect the verbose log for the Windows Installer diagnostic.' }
        }
        $packageDetail = if (-not [string]::IsNullOrWhiteSpace($PackagePath)) { "`nMSI package: $PackagePath" } else { '' }
        $logDetail = ''
        if (Test-Path -LiteralPath $LogPath -PathType Leaf) {
            $tail = @(Get-Content -LiteralPath $LogPath -Tail 30 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
            $logDetail = "`nVerbose log: $LogPath`nLast log lines:`n$tail"
        }
        else {
            $logDetail = "`nVerbose log was not created at: $LogPath"
        }
        foreach ($streamPath in @($stdoutPath, $stderrPath)) {
            if (Test-Path -LiteralPath $streamPath -PathType Leaf) {
                $streamTail = @(Get-Content -LiteralPath $streamPath -Tail 20 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
                if (-not [string]::IsNullOrWhiteSpace($streamTail)) {
                    $logDetail += "`nProcess output ($streamPath):`n$streamTail"
                }
            }
        }
        throw "$Description failed with msiexec exit code $exitCode. $hint`nCommand line: $ArgumentLine$packageDetail$logDetail"
    }
}

function Install-Msi {
    param(
        [Parameter(Mandatory = $true)][string] $MsiPath,
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [Parameter(Mandatory = $true)][string] $LogPath,
        [Parameter(Mandatory = $true)][string] $Description
    )

    Assert-UnderPath -Child $MsiPath -Parent $script:TestRoot -Label 'MSI fixture'
    Assert-UnderPath -Child $InstallRoot -Parent $script:TestRoot -Label 'MSI install root'
    Assert-UnderPath -Child $LogPath -Parent $script:TestRoot -Label 'MSI log'
    $quotedMsiPath = '"' + [System.IO.Path]::GetFullPath($MsiPath) + '"'
    $quotedLogPath = '"' + [System.IO.Path]::GetFullPath($LogPath) + '"'
    $quotedInstallRoot = '"' + [System.IO.Path]::GetFullPath($InstallRoot) + '"'
    $argumentLine = "/i $quotedMsiPath /qn /norestart /l*v $quotedLogPath INSTALLROOT=$quotedInstallRoot"
    Invoke-Msi -Description $Description -ArgumentLine $argumentLine -LogPath $LogPath -PackagePath $MsiPath
}

function Uninstall-Msi {
    param(
        [Parameter(Mandatory = $true)][string] $ProductCode,
        [Parameter(Mandatory = $true)][string] $LogPath,
        [Parameter(Mandatory = $true)][string] $Description,
        [switch] $AllowMissing
    )

    Assert-UnderPath -Child $LogPath -Parent $script:TestRoot -Label 'MSI log'
    $quotedLogPath = '"' + [System.IO.Path]::GetFullPath($LogPath) + '"'
    $argumentLine = "/x $ProductCode /qn /norestart /l*v $quotedLogPath"
    $acceptedExitCodes = if ($AllowMissing) { @(1605) } else { @() }
    Invoke-Msi -Description $Description -ArgumentLine $argumentLine -LogPath $LogPath -AcceptedExitCodes $acceptedExitCodes
}

function Get-MsiProductProperty {
    param(
        [Parameter(Mandatory = $true)][string] $ProductCode,
        [Parameter(Mandatory = $true)][uint32] $Context,
        [Parameter(Mandatory = $true)][string] $Property
    )

    $value = [System.Text.StringBuilder]::new(512)
    [uint32] $length = 511
    $status = [SideEffectMsiNative]::GetProductInfoEx($ProductCode, $script:CurrentUserSid, $Context, $Property, $value, [ref]$length)
    [pscustomobject]@{
        Status = $status
        Value = if ($status -eq 0) { $value.ToString() } else { $null }
    }
}

function Get-ProductRegistration {
    param([Parameter(Mandatory = $true)][string] $ProductCode)

    # The fixture requests per-user limited installation. Query Windows Installer's
    # own current-user contexts rather than assuming an ARP uninstall-key layout.
    foreach ($context in @(2, 1)) { # USERUNMANAGED, then USERMANAGED for cleanup diagnostics.
        $name = Get-MsiProductProperty -ProductCode $ProductCode -Context $context -Property 'InstalledProductName'
        if ($name.Status -eq 1605) {
            continue
        }
        if ($name.Status -ne 0) {
            throw "MsiGetProductInfoEx could not query product $ProductCode in context $context (Win32 status $($name.Status))."
        }
        $version = Get-MsiProductProperty -ProductCode $ProductCode -Context $context -Property 'VersionString'
        $state = Get-MsiProductProperty -ProductCode $ProductCode -Context $context -Property 'State'
        foreach ($propertyResult in @($version, $state)) {
            if ($propertyResult.Status -ne 0) {
                throw "MsiGetProductInfoEx could not retrieve a required property for product $ProductCode in context $context (Win32 status $($propertyResult.Status))."
            }
        }
        return [pscustomobject]@{
            DisplayName = $name.Value
            DisplayVersion = $version.Value
            ProductState = $state.Value
            Context = $context
        }
    }
    return $null
}

function Get-MsiStageDiagnostics {
    param(
        [Parameter(Mandatory = $true)][string] $ProductCode,
        [Parameter(Mandatory = $true)][string] $LogPath,
        [Parameter(Mandatory = $true)][string] $PayloadPath,
        [Parameter(Mandatory = $true)][string] $DefaultPayloadPath
    )

    $registrationText = 'Windows Installer API query returned no current-user product.'
    try {
        $registration = Get-ProductRegistration -ProductCode $ProductCode
        if ($null -ne $registration) {
            $registrationText = "Windows Installer API: name='$($registration.DisplayName)', version='$($registration.DisplayVersion)', state='$($registration.ProductState)', context=$($registration.Context)."
        }
    }
    catch {
        $registrationText = "Windows Installer API query failed: $($_.Exception.Message)"
    }

    $payloadState = if (Test-Path -LiteralPath $PayloadPath -PathType Leaf) {
        $file = Get-Item -LiteralPath $PayloadPath
        "present at '$PayloadPath' ($($file.Length) bytes)"
    }
    else {
        "absent at '$PayloadPath'"
    }
    if ($DefaultPayloadPath -ne $PayloadPath -and (Test-Path -LiteralPath $DefaultPayloadPath -PathType Leaf)) {
        $fallbackFile = Get-Item -LiteralPath $DefaultPayloadPath
        $payloadState += "; also found at authored fallback '$DefaultPayloadPath' ($($fallbackFile.Length) bytes)"
    }
    $logTail = if (Test-Path -LiteralPath $LogPath -PathType Leaf) {
        (Get-Content -LiteralPath $LogPath -Tail 35 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
    }
    else {
        'MSI verbose log was not created.'
    }
    if ($logTail.Length -gt 12000) {
        $logTail = $logTail.Substring($logTail.Length - 12000)
    }
    "`n$registrationText`nPayload: $payloadState`nMSI log tail ($LogPath):`n$logTail"
}

function Assert-InstalledPayload {
    param(
        [Parameter(Mandatory = $true)][string] $ProductCode,
        [Parameter(Mandatory = $true)][string] $LogPath,
        [Parameter(Mandatory = $true)][string] $PayloadPath,
        [Parameter(Mandatory = $true)][byte[]] $ExpectedBytes
    )

    $expectedHash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($ExpectedBytes)).ToLowerInvariant()
    if (-not (Test-Path -LiteralPath $PayloadPath -PathType Leaf)) {
        throw "MSI stage did not write the expected payload.$(Get-MsiStageDiagnostics -ProductCode $ProductCode -LogPath $LogPath -PayloadPath $PayloadPath -DefaultPayloadPath $script:DefaultInstallRootPayload)"
    }
    $actualHash = (Get-FileHash -LiteralPath $PayloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "MSI stage wrote different payload bytes than expected (expected SHA-256 $expectedHash, observed $actualHash).$(Get-MsiStageDiagnostics -ProductCode $ProductCode -LogPath $LogPath -PayloadPath $PayloadPath -DefaultPayloadPath $script:DefaultInstallRootPayload)"
    }
}

function Assert-ProductVersion {
    param(
        [Parameter(Mandatory = $true)][string] $ProductCode,
        [Parameter(Mandatory = $true)][string] $Version,
        [Parameter(Mandatory = $true)][string] $LogPath,
        [Parameter(Mandatory = $true)][string] $PayloadPath
    )

    $registrationQueryFailure = $null
    try {
        $registration = Get-ProductRegistration -ProductCode $ProductCode
    }
    catch {
        $registration = $null
        $registrationQueryFailure = $_.Exception.Message
    }
    if ($null -ne $registrationQueryFailure) {
        throw "Windows Installer registration query failed: $registrationQueryFailure.$(Get-MsiStageDiagnostics -ProductCode $ProductCode -LogPath $LogPath -PayloadPath $PayloadPath -DefaultPayloadPath $script:DefaultInstallRootPayload)"
    }
    if ($null -eq $registration -or $registration.ProductState -ne '5') {
        throw "MSI product $ProductCode was not installed in a current-user Windows Installer context.$(Get-MsiStageDiagnostics -ProductCode $ProductCode -LogPath $LogPath -PayloadPath $PayloadPath -DefaultPayloadPath $script:DefaultInstallRootPayload)"
    }
    if ($registration.DisplayName -ne 'SideEffect R5 Synthetic MSI Fixture' -or $registration.DisplayVersion -ne $Version) {
        throw "MSI registration did not report expected version $Version.$(Get-MsiStageDiagnostics -ProductCode $ProductCode -LogPath $LogPath -PayloadPath $PayloadPath -DefaultPayloadPath $script:DefaultInstallRootPayload)"
    }
    if ($registration.Context -ne 2) {
        throw "MSI fixture registered in unexpected Windows Installer context $($registration.Context), expected current-user unmanaged context.$(Get-MsiStageDiagnostics -ProductCode $ProductCode -LogPath $LogPath -PayloadPath $PayloadPath -DefaultPayloadPath $script:DefaultInstallRootPayload)"
    }
}

function Assert-ProductAbsent {
    param([Parameter(Mandatory = $true)][string] $ProductCode)
    if ($null -ne (Get-ProductRegistration -ProductCode $ProductCode)) {
        throw "MSI product $ProductCode remains registered after the operation."
    }
}

function Get-InventorySnapshot {
    param([Parameter(Mandatory = $true)][string] $Path)

    Assert-UnderPath -Child $Path -Parent $script:TestRoot -Label 'SideEffect snapshot'
    & $script:SideEffectPath 'inventory' 'root' '--hash-regular-files' '--output' $Path $script:InstallRoot
    if ($LASTEXITCODE -ne 0) {
        throw "SideEffect root snapshot failed with exit code $LASTEXITCODE."
    }
    $document = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($document.schema -ne 'sideeffect.selected_root_inventory' -or $document.schema_version -ne 2 -or $document.status -ne 'complete') {
        throw 'SideEffect snapshot did not report a complete selected-root v2 document.'
    }
    return $document
}

function Get-PayloadEntry {
    param([Parameter(Mandatory = $true)] $Document)
    $entries = @($Document.entries | Where-Object { $_.display_name -eq 'payload.bin' })
    if ($entries.Count -ne 1) {
        throw "Expected one payload.bin entry, found $($entries.Count)."
    }
    $entry = $entries[0]
    if ($entry.content_hash_status -ne 'observed' -or $entry.evidence.source -ne 'selected_root_directory_entry' -or $entry.evidence.entry_ordinal -ne $entry.ordinal) {
        throw 'Payload snapshot row is missing its observed hash or entry evidence binding.'
    }
    return $entry
}

function Get-InventoryDiff {
    param(
        [Parameter(Mandatory = $true)][string] $BeforePath,
        [Parameter(Mandatory = $true)][string] $AfterPath
    )

    $output = & $script:SideEffectPath 'explain' '--inventory-diff' $BeforePath $AfterPath | Out-String
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "SideEffect inventory diff failed with exit code $exitCode."
    }
    return $output | ConvertFrom-Json
}

function Get-SoftwareSnapshot {
    param([Parameter(Mandatory = $true)][string] $Path)

    Assert-UnderPath -Child $Path -Parent $script:TestRoot -Label 'SideEffect software snapshot'
    & $script:SideEffectPath 'inventory' 'packages' '--output' $Path
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and $exitCode -ne 2) {
        throw "SideEffect software snapshot failed with exit code $exitCode."
    }
    $document = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($document.schema -ne 'sideeffect.windows_software_inventory' -or $document.schema_version -ne 1 -or $document.platform -ne 'windows') {
        throw 'SideEffect software snapshot did not report the Windows software-registration v1 contract.'
    }
    foreach ($sourceId in @('current_user_native_uninstall', 'current_user_32_uninstall')) {
        $source = @($document.sources | Where-Object { $_.id -eq $sourceId })
        if ($source.Count -ne 1 -or $source[0].status -notin @('complete', 'not_present')) {
            throw "SideEffect current-user Uninstall source '$sourceId' was not complete: $($source | ConvertTo-Json -Compress -Depth 8)"
        }
    }
    return $document
}

function Get-FixtureSoftwareRegistrations {
    param(
        [Parameter(Mandatory = $true)] $Document,
        [Parameter(Mandatory = $true)][string] $DisplayName,
        [Parameter(Mandatory = $true)][string] $Version
    )

    $matches = @($Document.registrations | Where-Object {
        $_.display_name -eq $DisplayName -and
        $_.evidence.hive -eq 'HKEY_CURRENT_USER' -and
        $_.evidence.registry_view -in @('native', 'wow64_32') -and
        (@($_.values | Where-Object { $_.name -eq 'DisplayVersion' -and $_.text -eq $Version }).Count -eq 1)
    })
    foreach ($view in @('native', 'wow64_32')) {
        if (@($matches | Where-Object { $_.evidence.registry_view -eq $view }).Count -gt 1) {
            throw "SideEffect reported duplicate current-user $view fixture registrations at version $Version."
        }
    }
    return $matches
}

function Get-GeneratedUninstallKeyDiagnostics {
    param(
        [Parameter(Mandatory = $true)][string] $ProductCode,
        [Parameter(Mandatory = $true)][string] $ExpectedDisplayName,
        [Parameter(Mandatory = $true)][string] $ExpectedVersion
    )

    $basePath = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($view in @(
        [pscustomobject]@{ Name = 'native'; Value = [Microsoft.Win32.RegistryView]::Registry64 },
        [pscustomobject]@{ Name = 'wow64_32'; Value = [Microsoft.Win32.RegistryView]::Registry32 }
    )) {
        $root = $null
        $key = $null
        try {
            $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, $view.Value)
            $key = $root.OpenSubKey("$basePath\$ProductCode", $false)
            $displayNameMatches = $false
            $displayVersionMatches = $false
            if ($null -ne $key) {
                $displayName = $key.GetValue('DisplayName', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $displayVersion = $key.GetValue('DisplayVersion', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $displayNameMatches = $displayName -is [string] -and $displayName -ceq $ExpectedDisplayName
                $displayVersionMatches = $displayVersion -is [string] -and $displayVersion -ceq $ExpectedVersion
            }
            $results.Add([pscustomobject]@{
                RegistryView = $view.Name
                GeneratedProductKeyPresent = ($null -ne $key)
                DisplayNameMatchesFixture = $displayNameMatches
                DisplayVersionMatchesFixture = $displayVersionMatches
                QueryFailed = $false
            })
        }
        catch {
            $results.Add([pscustomobject]@{
                RegistryView = $view.Name
                GeneratedProductKeyPresent = $false
                DisplayNameMatchesFixture = $false
                DisplayVersionMatchesFixture = $false
                QueryFailed = $true
            })
        }
        finally {
            if ($null -ne $key) { $key.Dispose() }
            if ($null -ne $root) { $root.Dispose() }
        }
    }
    return @($results.ToArray())
}

function New-HostedRegistryFixtureRegistration {
    param(
        [Parameter(Mandatory = $true)][string] $ProductCode,
        [Parameter(Mandatory = $true)][string] $DisplayName,
        [Parameter(Mandatory = $true)][string] $Version
    )

    $path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
    $root = $null
    $existing = $null
    $key = $null
    try {
        $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
        $existing = $root.OpenSubKey($path, $false)
        if ($null -ne $existing) {
            throw 'Generated registry fixture key unexpectedly exists before creation.'
        }
        $script:HostedRegistryFixtureProductCode = $ProductCode
        $key = $root.CreateSubKey($path)
        if ($null -eq $key) {
            throw 'Could not create the generated current-user registry fixture key.'
        }
        $script:HostedRegistryFixtureCreated = $true
        $key.SetValue('DisplayName', $DisplayName, [Microsoft.Win32.RegistryValueKind]::String)
        $key.SetValue('DisplayVersion', $Version, [Microsoft.Win32.RegistryValueKind]::String)
        $key.Flush()
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $existing) { $existing.Dispose() }
        if ($null -ne $root) { $root.Dispose() }
    }
}

function Remove-HostedRegistryFixtureRegistration {
    if (-not $script:HostedRegistryFixtureCreated) {
        return
    }
    $root = $null
    try {
        $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
        $path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($script:HostedRegistryFixtureProductCode)"
        $root.DeleteSubKey($path, $false)
        $script:HostedRegistryFixtureCreated = $false
    }
    finally {
        if ($null -ne $root) { $root.Dispose() }
    }
}

function Get-SoftwareInventoryDiff {
    param(
        [Parameter(Mandatory = $true)][string] $BeforePath,
        [Parameter(Mandatory = $true)][string] $AfterPath
    )

    $output = & $script:SideEffectPath 'explain' '--inventory-diff' $BeforePath $AfterPath | Out-String
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and $exitCode -ne 2) {
        throw "SideEffect software inventory diff failed with exit code $exitCode."
    }
    $diff = $output | ConvertFrom-Json
    if ($diff.schema -ne 'sideeffect.windows_software_inventory_diff' -or $diff.schema_version -ne 1) {
        throw 'SideEffect did not return the Windows software-registration diff v1 contract.'
    }
    return $diff
}

function Assert-SoftwareDiffSideEvidence {
    param(
        [Parameter(Mandatory = $true)] $Delta,
        [Parameter(Mandatory = $true)][string] $Side,
        [Parameter(Mandatory = $true)] $Snapshot
    )

    $facts = $Delta.$Side
    if ($null -eq $facts) {
        throw "Software diff $Side side did not contain registration facts."
    }
    $evidence = $facts.evidence
    if ($evidence.source_id -notin @('current_user_native_uninstall', 'current_user_32_uninstall') -or $Delta.identity.source_id -ne $evidence.source_id) {
        throw "Software diff $Side side did not retain a current-user source identity."
    }
    $rows = @($Snapshot.registrations | Where-Object {
        $_.evidence.registration_index -eq $evidence.registration_index -and
        $_.evidence.hive -eq 'HKEY_CURRENT_USER' -and
        $_.evidence.registry_view -eq $Delta.identity.registry_view -and
        $_.registry_subkey -eq $Delta.identity.registry_subkey
    })
    if ($rows.Count -ne 1 -or $rows[0].evidence.registration_index -ne $evidence.registration_index) {
        throw "Software diff $Side evidence did not resolve to exactly one source registration row."
    }
}

function Assert-SoftwareLifecycleDiff {
    param(
        [Parameter(Mandatory = $true)] $Diff,
        [Parameter(Mandatory = $true)] $Before,
        [Parameter(Mandatory = $true)] $After,
        [Parameter()][string[]] $AddedVersions = @(),
        [Parameter()][string[]] $RemovedVersions = @(),
        [Parameter()][string] $DisplayName = 'SideEffect R5 Synthetic MSI Fixture',
        [switch] $Force
    )

    if (-not $Force -and $script:MsiRegistrationObservationStatus -ne 'observed') {
        return
    }
    foreach ($sourceId in @('current_user_native_uninstall', 'current_user_32_uninstall')) {
        $source = @($Diff.sources | Where-Object { $_.source_id -eq $sourceId })
        if ($source.Count -ne 1 -or
            $source[0].before_status -notin @('complete', 'not_present') -or
            $source[0].after_status -notin @('complete', 'not_present')) {
            throw "Software diff did not preserve complete comparison states for current-user source '$sourceId'."
        }
    }
    $expectedDeltaCount = 0
    foreach ($version in $AddedVersions) {
        $beforeRegistrations = @(Get-FixtureSoftwareRegistrations -Document $Before -DisplayName $DisplayName -Version $version)
        if ($beforeRegistrations.Count -ne 0) {
            throw "Fixture version $version was already present in the before software snapshot."
        }
        $afterRegistrations = @(Get-FixtureSoftwareRegistrations -Document $After -DisplayName $DisplayName -Version $version)
        if ($afterRegistrations.Count -eq 0) {
            throw "SideEffect did not observe current-user fixture registration '$DisplayName' version $version."
        }
        foreach ($registration in $afterRegistrations) {
            $sourceId = if ($registration.evidence.registry_view -eq 'native') { 'current_user_native_uninstall' } else { 'current_user_32_uninstall' }
            $deltas = @($Diff.deltas | Where-Object {
                $_.kind -eq 'added' -and $_.identity.source_id -eq $sourceId -and
                $_.identity.registry_view -eq $registration.evidence.registry_view -and
                $_.identity.registry_subkey -eq $registration.registry_subkey -and
                $_.after.display_name -eq $DisplayName -and $_.after.display_version -eq $version
            })
            if ($deltas.Count -ne 1) {
                throw "Software diff did not report exactly one evidence-linked addition for fixture version $version in $($registration.evidence.registry_view)."
            }
            Assert-SoftwareDiffSideEvidence -Delta $deltas[0] -Side 'after' -Snapshot $After
            $expectedDeltaCount++
        }
    }
    foreach ($version in $RemovedVersions) {
        $beforeRegistrations = @(Get-FixtureSoftwareRegistrations -Document $Before -DisplayName $DisplayName -Version $version)
        if ($beforeRegistrations.Count -eq 0) {
            throw "SideEffect did not observe current-user fixture registration '$DisplayName' version $version before removal."
        }
        if (@(Get-FixtureSoftwareRegistrations -Document $After -DisplayName $DisplayName -Version $version).Count -ne 0) {
            throw "Fixture version $version remained in the after software snapshot."
        }
        foreach ($registration in $beforeRegistrations) {
            $sourceId = if ($registration.evidence.registry_view -eq 'native') { 'current_user_native_uninstall' } else { 'current_user_32_uninstall' }
            $deltas = @($Diff.deltas | Where-Object {
                $_.kind -eq 'removed' -and $_.identity.source_id -eq $sourceId -and
                $_.identity.registry_view -eq $registration.evidence.registry_view -and
                $_.identity.registry_subkey -eq $registration.registry_subkey -and
                $_.before.display_name -eq $DisplayName -and $_.before.display_version -eq $version
            })
            if ($deltas.Count -ne 1) {
                throw "Software diff did not report exactly one evidence-linked removal for fixture version $version in $($registration.evidence.registry_view)."
            }
            Assert-SoftwareDiffSideEvidence -Delta $deltas[0] -Side 'before' -Snapshot $Before
            $expectedDeltaCount++
        }
    }
    $fixtureDeltas = @($Diff.deltas | Where-Object {
        $_.identity.source_id -in @('current_user_native_uninstall', 'current_user_32_uninstall') -and
        ($_.before.display_name -eq $DisplayName -or $_.after.display_name -eq $DisplayName)
    })
    if ($fixtureDeltas.Count -ne $expectedDeltaCount) {
        throw "Software diff contained $($fixtureDeltas.Count) fixture registration deltas; expected $expectedDeltaCount."
    }
}

function Assert-DiffEvidence {
    param(
        [Parameter(Mandatory = $true)] $Diff,
        [Parameter(Mandatory = $true)][string] $Kind,
        [Parameter(Mandatory = $true)][string] $CountField,
        [Parameter(Mandatory = $true)][object] $Count,
        [Parameter()][object] $BeforeEntry,
        [Parameter()][object] $AfterEntry,
        [switch] $RequireContentChange
    )

    if ($Diff.status -ne 'complete' -or $Diff.counts.$CountField -ne $Count -or $Diff.deltas.Count -ne 1 -or $Diff.deltas[0].kind -ne $Kind) {
        throw "SideEffect diff did not report the expected complete $Kind delta."
    }
    $delta = $Diff.deltas[0]
    if ($null -ne $BeforeEntry) {
        if ($delta.before.evidence_source -ne 'selected_root_directory_entry' -or $delta.before.entry_ordinal -ne $BeforeEntry.ordinal) {
            throw 'Before-side diff evidence did not match the selected-root snapshot row.'
        }
    }
    elseif ($null -ne $delta.before) {
        throw 'Addition delta unexpectedly has a before-side evidence row.'
    }
    if ($null -ne $AfterEntry) {
        if ($delta.after.evidence_source -ne 'selected_root_directory_entry' -or $delta.after.entry_ordinal -ne $AfterEntry.ordinal) {
            throw 'After-side diff evidence did not match the selected-root snapshot row.'
        }
    }
    elseif ($null -ne $delta.after) {
        throw 'Removal delta unexpectedly has an after-side evidence row.'
    }
    if ($RequireContentChange -and -not (@($delta.changed_fields) -contains 'content_sha256')) {
        throw 'Diff did not report a content_sha256 change.'
    }
}

if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This MSI integration acceptance may run only on a disposable GitHub-hosted runner.'
}
if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or [string]::IsNullOrWhiteSpace($env:WIX)) {
    throw 'RUNNER_TEMP and WIX must be provided by the GitHub-hosted Windows runner.'
}

Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
using System.Text;

public static class SideEffectMsiNative
{
    [DllImport("msi.dll", EntryPoint = "MsiGetProductInfoExW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern uint GetProductInfoEx(
        string productCode,
        string userSid,
        uint installContext,
        string property,
        StringBuilder value,
        ref uint valueLength);
}
'@
$script:CurrentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ([string]::IsNullOrWhiteSpace($script:CurrentUserSid)) {
    throw 'Could not resolve the current Windows user SID for the per-user MSI registration check.'
}

$script:SideEffectPath = [System.IO.Path]::GetFullPath($SideEffectPath)
if (-not (Test-Path -LiteralPath $script:SideEffectPath -PathType Leaf)) {
    throw "SideEffect CLI was not found at $script:SideEffectPath."
}
$script:MsiexecPath = Join-Path $env:WINDIR 'System32\msiexec.exe'
$wixBin = Join-Path $env:WIX 'bin'
$candlePath = Join-Path $wixBin 'candle.exe'
$lightPath = Join-Path $wixBin 'light.exe'
foreach ($tool in @($script:MsiexecPath, $candlePath, $lightPath)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
        throw "Required hosted Windows installer tool was not found: $tool"
    }
}

$runnerTemp = [System.IO.Path]::GetFullPath($env:RUNNER_TEMP)
$runId = [Guid]::NewGuid().ToString('N')
$script:TestRoot = Join-Path $runnerTemp "sideeffect-r5-msi-lifecycle-$runId"
Assert-UnderPath -Child $script:TestRoot -Parent $runnerTemp -Label 'MSI lifecycle fixture'
$script:InstallRoot = Join-Path $script:TestRoot 'install-root'
$defaultDirectoryName = "SideEffectR5Msi-$runId"
$script:DefaultInstallRootPayload = Join-Path $script:InstallRoot 'payload.bin'
$upgradeCode = ([Guid]::NewGuid()).ToString('B').ToUpperInvariant()
$productCodeV1 = ([Guid]::NewGuid()).ToString('B').ToUpperInvariant()
$productCodeV2 = ([Guid]::NewGuid()).ToString('B').ToUpperInvariant()
$componentCode = ([Guid]::NewGuid()).ToString('B').ToUpperInvariant()
$createdTestRoot = $false
$installationStarted = $false
$script:MsiRegistrationObservationStatus = 'pending'
$script:HostedRegistryFixtureCreated = $false
$script:HostedRegistryFixtureProductCode = $null
$testFailure = $null
$cleanupErrors = [System.Collections.Generic.List[string]]::new()

try {
    New-Item -ItemType Directory -Path $script:TestRoot -ErrorAction Stop | Out-Null
    $createdTestRoot = $true
    Assert-UnderPath -Child $script:TestRoot -Parent $runnerTemp -Label 'created MSI lifecycle fixture'
    Assert-UnderPath -Child $script:InstallRoot -Parent $script:TestRoot -Label 'MSI install root'
    Assert-UnderPath -Child $script:InstallRoot -Parent $script:TestRoot -Label 'MSI default directory'
    New-Item -ItemType Directory -Path $script:InstallRoot -ErrorAction Stop | Out-Null

    $productCodeV1Key = Get-ProductRegistration -ProductCode $productCodeV1
    $productCodeV2Key = Get-ProductRegistration -ProductCode $productCodeV2
    if ($null -ne $productCodeV1Key -or $null -ne $productCodeV2Key) {
        throw 'A generated MSI product code was already registered; aborting before install.'
    }

    $payloadV1 = [System.Text.Encoding]::UTF8.GetBytes("synthetic benign MSI fixture revision A`n")
    $payloadV2 = [System.Text.Encoding]::UTF8.GetBytes("synthetic benign MSI fixture revision B`n")
    $payloadV1Path = Join-Path $script:TestRoot 'payload-v1.bin'
    $payloadV2Path = Join-Path $script:TestRoot 'payload-v2.bin'
    [System.IO.File]::WriteAllBytes($payloadV1Path, $payloadV1)
    [System.IO.File]::WriteAllBytes($payloadV2Path, $payloadV2)
    $wxsV1 = Join-Path $script:TestRoot 'fixture-v1.wxs'
    $wxsV2 = Join-Path $script:TestRoot 'fixture-v2.wxs'
    $objV1 = Join-Path $script:TestRoot 'fixture-v1.wixobj'
    $objV2 = Join-Path $script:TestRoot 'fixture-v2.wixobj'
    $msiV1 = Join-Path $script:TestRoot 'fixture-v1.msi'
    $msiV2 = Join-Path $script:TestRoot 'fixture-v2.msi'
    New-MsiFixture -WxsPath $wxsV1 -WixObjPath $objV1 -MsiPath $msiV1 -PayloadPath $payloadV1Path -Version '1.0.0' -ProductCode $productCodeV1 -UpgradeCode $upgradeCode -ComponentCode $componentCode -DefaultDirectoryName $defaultDirectoryName -DefaultInstallRoot $script:InstallRoot -CabinetName 'r5v1.cab' -ExpectedCabinet '#r5v1.cab' -CandlePath $candlePath -LightPath $lightPath
    New-MsiFixture -WxsPath $wxsV2 -WixObjPath $objV2 -MsiPath $msiV2 -PayloadPath $payloadV2Path -Version '2.0.0' -ProductCode $productCodeV2 -UpgradeCode $upgradeCode -ComponentCode $componentCode -DefaultDirectoryName $defaultDirectoryName -DefaultInstallRoot $script:InstallRoot -CabinetName 'r5v2.cab' -ExpectedCabinet '#r5v2.cab' -CandlePath $candlePath -LightPath $lightPath

    $beforePath = Join-Path $script:TestRoot 'before-install.json'
    $snapshotV1Path = Join-Path $script:TestRoot 'installed-v1.json'
    $snapshotV2Path = Join-Path $script:TestRoot 'installed-v2.json'
    $snapshotDowngradePath = Join-Path $script:TestRoot 'downgraded-v1.json'
    $snapshotUninstallPath = Join-Path $script:TestRoot 'uninstalled.json'
    $softwareBeforePath = Join-Path $script:TestRoot 'software-before-install.json'
    $softwareV1Path = Join-Path $script:TestRoot 'software-installed-v1.json'
    $softwareV2Path = Join-Path $script:TestRoot 'software-installed-v2.json'
    $softwareV2UninstallPath = Join-Path $script:TestRoot 'software-uninstalled-v2-for-downgrade.json'
    $softwareDowngradePath = Join-Path $script:TestRoot 'software-downgraded-v1.json'
    $softwareUninstallPath = Join-Path $script:TestRoot 'software-uninstalled-v1.json'
    $before = Get-InventorySnapshot -Path $beforePath
    if (@($before.entries).Count -ne 0) {
        throw 'Fresh MSI install root was not empty before installation.'
    }
    $softwareBefore = Get-SoftwareSnapshot -Path $softwareBeforePath
    if (@(Get-FixtureSoftwareRegistrations -Document $softwareBefore -DisplayName 'SideEffect R5 Synthetic MSI Fixture' -Version '1.0.0').Count -ne 0 -or
        @(Get-FixtureSoftwareRegistrations -Document $softwareBefore -DisplayName 'SideEffect R5 Synthetic MSI Fixture' -Version '2.0.0').Count -ne 0) {
        throw 'A generated fixture version was already present in SideEffect current-user native software inventory before installation.'
    }

    $installationStarted = $true
    Install-Msi -MsiPath $msiV1 -InstallRoot $script:InstallRoot -LogPath (Join-Path $script:TestRoot 'install-v1.log') -Description 'MSI v1 install'
    Assert-ProductVersion -ProductCode $productCodeV1 -Version '1.0.0' -LogPath (Join-Path $script:TestRoot 'install-v1.log') -PayloadPath (Join-Path $script:InstallRoot 'payload.bin')
    Assert-InstalledPayload -ProductCode $productCodeV1 -LogPath (Join-Path $script:TestRoot 'install-v1.log') -PayloadPath (Join-Path $script:InstallRoot 'payload.bin') -ExpectedBytes $payloadV1
    $entryV1 = Get-PayloadEntry (Get-InventorySnapshot -Path $snapshotV1Path)
    $softwareV1 = Get-SoftwareSnapshot -Path $softwareV1Path
    $v1FixtureRegistrations = @(Get-FixtureSoftwareRegistrations -Document $softwareV1 -DisplayName 'SideEffect R5 Synthetic MSI Fixture' -Version '1.0.0')
    if ($v1FixtureRegistrations.Count -gt 0) {
        $script:MsiRegistrationObservationStatus = 'observed'
    }
    else {
        $generatedKeyDiagnostics = @(Get-GeneratedUninstallKeyDiagnostics -ProductCode $productCodeV1 -ExpectedDisplayName 'SideEffect R5 Synthetic MSI Fixture' -ExpectedVersion '1.0.0')
        $keyMatchesFixture = @($generatedKeyDiagnostics | Where-Object { $_.GeneratedProductKeyPresent -and $_.DisplayNameMatchesFixture -and $_.DisplayVersionMatchesFixture })
        if ($keyMatchesFixture.Count -gt 0) {
            throw "SideEffect missed an exact generated HKCU Uninstall key in a complete source; the MSI registration adapter needs investigation. Diagnostic: $($generatedKeyDiagnostics | ConvertTo-Json -Compress)"
        }
        $script:MsiRegistrationObservationStatus = 'unknown_not_observed_in_selected_uninstall_views'
        Write-Output "MSI ProductCode $productCodeV1 is installed per MsiGetProductInfoEx, but SideEffect did not observe its fixture registration. Registration correlation: unknown. Exact generated-key-only HKCU Uninstall diagnostics: $($generatedKeyDiagnostics | ConvertTo-Json -Compress)"
    }
    if ($entryV1.content_sha256 -ne (Get-FileHash -LiteralPath (Join-Path $script:InstallRoot 'payload.bin') -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'SideEffect v1 hash did not match the installed payload bytes.'
    }
    $installDiff = Get-InventoryDiff -BeforePath $beforePath -AfterPath $snapshotV1Path
    Assert-DiffEvidence -Diff $installDiff -Kind 'added' -CountField 'additions' -Count 1 -AfterEntry $entryV1
    $softwareInstallDiff = Get-SoftwareInventoryDiff -BeforePath $softwareBeforePath -AfterPath $softwareV1Path
    Assert-SoftwareLifecycleDiff -Diff $softwareInstallDiff -Before $softwareBefore -After $softwareV1 -AddedVersions @('1.0.0')
    Write-Output "MSI v1 installed; observed selected-root SHA-256: $($entryV1.content_sha256)"

    Install-Msi -MsiPath $msiV2 -InstallRoot $script:InstallRoot -LogPath (Join-Path $script:TestRoot 'update-v2.log') -Description 'MSI v2 major upgrade'
    Assert-ProductAbsent -ProductCode $productCodeV1
    Assert-ProductVersion -ProductCode $productCodeV2 -Version '2.0.0' -LogPath (Join-Path $script:TestRoot 'update-v2.log') -PayloadPath (Join-Path $script:InstallRoot 'payload.bin')
    Assert-InstalledPayload -ProductCode $productCodeV2 -LogPath (Join-Path $script:TestRoot 'update-v2.log') -PayloadPath (Join-Path $script:InstallRoot 'payload.bin') -ExpectedBytes $payloadV2
    $entryV2 = Get-PayloadEntry (Get-InventorySnapshot -Path $snapshotV2Path)
    $softwareV2 = Get-SoftwareSnapshot -Path $softwareV2Path
    if ($entryV2.content_sha256 -ne (Get-FileHash -LiteralPath (Join-Path $script:InstallRoot 'payload.bin') -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'SideEffect v2 hash did not match the installed payload bytes.'
    }
    if ($entryV1.content_sha256 -eq $entryV2.content_sha256) {
        throw 'Synthetic v1 and v2 payload fingerprints unexpectedly matched.'
    }
    $updateDiff = Get-InventoryDiff -BeforePath $snapshotV1Path -AfterPath $snapshotV2Path
    Assert-DiffEvidence -Diff $updateDiff -Kind 'changed' -CountField 'changes' -Count 1 -BeforeEntry $entryV1 -AfterEntry $entryV2 -RequireContentChange
    $softwareUpdateDiff = Get-SoftwareInventoryDiff -BeforePath $softwareV1Path -AfterPath $softwareV2Path
    Assert-SoftwareLifecycleDiff -Diff $softwareUpdateDiff -Before $softwareV1 -After $softwareV2 -AddedVersions @('2.0.0') -RemovedVersions @('1.0.0')
    Write-Output "MSI v2 major upgrade completed; observed selected-root SHA-256: $($entryV2.content_sha256)"

    Uninstall-Msi -ProductCode $productCodeV2 -LogPath (Join-Path $script:TestRoot 'uninstall-v2-for-downgrade.log') -Description 'MSI v2 uninstall for downgrade strategy'
    Assert-ProductAbsent -ProductCode $productCodeV2
    $softwareV2Uninstalled = Get-SoftwareSnapshot -Path $softwareV2UninstallPath
    $softwareV2UninstallDiff = Get-SoftwareInventoryDiff -BeforePath $softwareV2Path -AfterPath $softwareV2UninstallPath
    Assert-SoftwareLifecycleDiff -Diff $softwareV2UninstallDiff -Before $softwareV2 -After $softwareV2Uninstalled -RemovedVersions @('2.0.0')
    Install-Msi -MsiPath $msiV1 -InstallRoot $script:InstallRoot -LogPath (Join-Path $script:TestRoot 'downgrade-reinstall-v1.log') -Description 'MSI v1 reinstall downgrade strategy'
    Assert-ProductVersion -ProductCode $productCodeV1 -Version '1.0.0' -LogPath (Join-Path $script:TestRoot 'downgrade-reinstall-v1.log') -PayloadPath (Join-Path $script:InstallRoot 'payload.bin')
    Assert-InstalledPayload -ProductCode $productCodeV1 -LogPath (Join-Path $script:TestRoot 'downgrade-reinstall-v1.log') -PayloadPath (Join-Path $script:InstallRoot 'payload.bin') -ExpectedBytes $payloadV1
    $entryDowngrade = Get-PayloadEntry (Get-InventorySnapshot -Path $snapshotDowngradePath)
    $softwareDowngrade = Get-SoftwareSnapshot -Path $softwareDowngradePath
    if ($entryDowngrade.content_sha256 -ne $entryV1.content_sha256) {
        throw 'Downgrade reinstall did not restore the v1 payload fingerprint.'
    }
    $downgradeDiff = Get-InventoryDiff -BeforePath $snapshotV2Path -AfterPath $snapshotDowngradePath
    Assert-DiffEvidence -Diff $downgradeDiff -Kind 'changed' -CountField 'changes' -Count 1 -BeforeEntry $entryV2 -AfterEntry $entryDowngrade -RequireContentChange
    $softwareDowngradeDiff = Get-SoftwareInventoryDiff -BeforePath $softwareV2UninstallPath -AfterPath $softwareDowngradePath
    Assert-SoftwareLifecycleDiff -Diff $softwareDowngradeDiff -Before $softwareV2Uninstalled -After $softwareDowngrade -AddedVersions @('1.0.0')
    Write-Output "Downgrade strategy restored MSI v1; observed selected-root SHA-256: $($entryDowngrade.content_sha256)"

    Uninstall-Msi -ProductCode $productCodeV1 -LogPath (Join-Path $script:TestRoot 'uninstall-v1.log') -Description 'MSI v1 final uninstall'
    Assert-ProductAbsent -ProductCode $productCodeV1
    $uninstalled = Get-InventorySnapshot -Path $snapshotUninstallPath
    $softwareUninstalled = Get-SoftwareSnapshot -Path $softwareUninstallPath
    if (@($uninstalled.entries).Count -ne 0 -or (Test-Path -LiteralPath (Join-Path $script:InstallRoot 'payload.bin'))) {
        throw 'Final MSI uninstall left the synthetic payload in the selected root.'
    }
    $uninstallDiff = Get-InventoryDiff -BeforePath $snapshotDowngradePath -AfterPath $snapshotUninstallPath
    Assert-DiffEvidence -Diff $uninstallDiff -Kind 'removed' -CountField 'removals' -Count 1 -BeforeEntry $entryDowngrade
    $softwareFinalUninstallDiff = Get-SoftwareInventoryDiff -BeforePath $softwareDowngradePath -AfterPath $softwareUninstallPath
    Assert-SoftwareLifecycleDiff -Diff $softwareFinalUninstallDiff -Before $softwareDowngrade -After $softwareUninstalled -RemovedVersions @('1.0.0')
    Write-Output 'MSI v1 uninstall removed the observed selected-root payload.'

    $registryFixtureCode = ([Guid]::NewGuid()).ToString('B').ToUpperInvariant()
    $registryFixtureName = "SideEffect R5 Synthetic Uninstall Registry Fixture $($registryFixtureCode.Trim('{}'))"
    $registryFixtureVersion = 'synthetic-1'
    $softwareRegistryFixturePath = Join-Path $script:TestRoot 'software-synthetic-registry-fixture.json'
    $softwareRegistryFixtureRemovedPath = Join-Path $script:TestRoot 'software-synthetic-registry-fixture-removed.json'
    New-HostedRegistryFixtureRegistration -ProductCode $registryFixtureCode -DisplayName $registryFixtureName -Version $registryFixtureVersion
    $directRegistryDiagnostics = @(Get-GeneratedUninstallKeyDiagnostics -ProductCode $registryFixtureCode -ExpectedDisplayName $registryFixtureName -ExpectedVersion $registryFixtureVersion)
    if (@($directRegistryDiagnostics | Where-Object { $_.GeneratedProductKeyPresent -and $_.DisplayNameMatchesFixture -and $_.DisplayVersionMatchesFixture }).Count -eq 0) {
        throw "The generated current-user synthetic registry row did not read back through either selected view: $($directRegistryDiagnostics | ConvertTo-Json -Compress)"
    }
    $softwareRegistryFixture = Get-SoftwareSnapshot -Path $softwareRegistryFixturePath
    $registryFixtureDiff = Get-SoftwareInventoryDiff -BeforePath $softwareUninstallPath -AfterPath $softwareRegistryFixturePath
    Assert-SoftwareLifecycleDiff -Diff $registryFixtureDiff -Before $softwareUninstalled -After $softwareRegistryFixture -DisplayName $registryFixtureName -AddedVersions @($registryFixtureVersion) -Force
    Remove-HostedRegistryFixtureRegistration
    $softwareRegistryFixtureRemoved = Get-SoftwareSnapshot -Path $softwareRegistryFixtureRemovedPath
    $registryFixtureRemovalDiff = Get-SoftwareInventoryDiff -BeforePath $softwareRegistryFixturePath -AfterPath $softwareRegistryFixtureRemovedPath
    Assert-SoftwareLifecycleDiff -Diff $registryFixtureRemovalDiff -Before $softwareRegistryFixture -After $softwareRegistryFixtureRemoved -DisplayName $registryFixtureName -RemovedVersions @($registryFixtureVersion) -Force
    Write-Output "Separate hosted-only HKCU Uninstall fixture produced evidence-linked addition/removal deltas in the observed current-user view(s): $((Get-FixtureSoftwareRegistrations -Document $softwareRegistryFixture -DisplayName $registryFixtureName -Version $registryFixtureVersion | ForEach-Object { $_.evidence.registry_view }) -join ', ')"
}
catch {
    $testFailure = $_
}
finally {
    try {
        if ($installationStarted) {
            foreach ($productCode in @($productCodeV2, $productCodeV1)) {
                try {
                    Uninstall-Msi -ProductCode $productCode -LogPath (Join-Path $script:TestRoot "cleanup-$($productCode.Trim('{}')).log") -Description 'MSI lifecycle cleanup' -AllowMissing
                }
                catch {
                    Write-Warning "Could not clean up fixture MSI ${productCode}: $_"
                    $cleanupErrors.Add("Could not uninstall fixture MSI ${productCode}: $($_.Exception.Message)")
                }
            }
        }
        Remove-HostedRegistryFixtureRegistration
        $registeredFixtureRemains = $false
        foreach ($productCode in @($productCodeV2, $productCodeV1)) {
            if ($null -ne (Get-ProductRegistration -ProductCode $productCode)) {
                $registeredFixtureRemains = $true
            }
        }
        if ($createdTestRoot -and (Test-Path -LiteralPath $script:TestRoot)) {
            if ($registeredFixtureRemains) {
                Write-Warning "Fixture files were retained because an MSI product remains registered: $script:TestRoot"
                $cleanupErrors.Add("Fixture MSI registration remains; retained fixture files at $script:TestRoot")
            }
            else {
                Assert-UnderPath -Child $script:TestRoot -Parent $runnerTemp -Label 'MSI cleanup target'
                Remove-Item -LiteralPath $script:TestRoot -Recurse -Force -ErrorAction Stop
            }
        }
    }
    catch {
        Write-Warning "Fixture cleanup failed without replacing the test result: $_"
        Write-Warning "Fixture files and installer logs remain under: $script:TestRoot"
        $cleanupErrors.Add("Fixture cleanup failed; retained files at ${script:TestRoot}: $($_.Exception.Message)")
    }
}

if ($null -ne $testFailure) {
    throw $testFailure
}
if ($cleanupErrors.Count -gt 0) {
    throw "MSI lifecycle passed, but fixture cleanup failed: $($cleanupErrors -join '; ')"
}
exit 0
