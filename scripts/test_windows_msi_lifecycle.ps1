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
    <MediaTemplate />
    <Property Id="INSTALLROOT" Secure="yes" />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="TempFolder">
        <Directory Id="INSTALLROOT" Name="$(var.DefaultDirectoryName)" />
      </Directory>
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
        "-dPayloadPath=$PayloadPath",
        '-out', $WixObjPath,
        $WxsPath
    )
    Invoke-WixTool -Tool $CandlePath -Arguments $compileArguments
    Invoke-WixTool -Tool $LightPath -Arguments @('-nologo', '-out', $MsiPath, $WixObjPath)
}

function Invoke-Msi {
    param(
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $Description
    )

    & $script:MsiexecPath @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Description failed with msiexec exit code $exitCode."
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
    Invoke-Msi -Description $Description -Arguments @(
        '/i', $MsiPath, '/qn', '/norestart', '/l*v', $LogPath,
        "INSTALLROOT=$InstallRoot"
    )
}

function Uninstall-Msi {
    param(
        [Parameter(Mandatory = $true)][string] $ProductCode,
        [Parameter(Mandatory = $true)][string] $LogPath,
        [Parameter(Mandatory = $true)][string] $Description,
        [switch] $AllowMissing
    )

    Assert-UnderPath -Child $LogPath -Parent $script:TestRoot -Label 'MSI log'
    & $script:MsiexecPath '/x' $ProductCode '/qn' '/norestart' '/l*v' $LogPath
    $exitCode = $LASTEXITCODE
    if ($AllowMissing -and $exitCode -eq 1605) {
        return
    }
    if ($exitCode -ne 0) {
        throw "$Description failed with msiexec exit code $exitCode."
    }
}

function Get-ProductRegistration {
    param([Parameter(Mandatory = $true)][string] $ProductCode)

    $subKeyPath = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, $view)
        try {
            $productKey = $baseKey.OpenSubKey($subKeyPath)
            if ($null -ne $productKey) {
                try {
                    return [pscustomobject]@{
                        DisplayName = $productKey.GetValue('DisplayName')
                        DisplayVersion = $productKey.GetValue('DisplayVersion')
                    }
                }
                finally {
                    $productKey.Dispose()
                }
            }
        }
        finally {
            $baseKey.Dispose()
        }
    }
    return $null
}

function Assert-ProductVersion {
    param(
        [Parameter(Mandatory = $true)][string] $ProductCode,
        [Parameter(Mandatory = $true)][string] $Version
    )

    $registration = Get-ProductRegistration -ProductCode $ProductCode
    if ($null -eq $registration) {
        throw "MSI product $ProductCode is not registered for the current user."
    }
    if ($registration.DisplayName -ne 'SideEffect R5 Synthetic MSI Fixture' -or $registration.DisplayVersion -ne $Version) {
        throw "MSI registration did not report expected version $Version."
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
$tempFallbackRoot = Join-Path $script:TestRoot $defaultDirectoryName
$upgradeCode = ([Guid]::NewGuid()).ToString('B').ToUpperInvariant()
$productCodeV1 = ([Guid]::NewGuid()).ToString('B').ToUpperInvariant()
$productCodeV2 = ([Guid]::NewGuid()).ToString('B').ToUpperInvariant()
$componentCode = ([Guid]::NewGuid()).ToString('B').ToUpperInvariant()
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
$createdTestRoot = $false
$installationStarted = $false

try {
    New-Item -ItemType Directory -Path $script:TestRoot -ErrorAction Stop | Out-Null
    $createdTestRoot = $true
    Assert-UnderPath -Child $script:TestRoot -Parent $runnerTemp -Label 'created MSI lifecycle fixture'
    Assert-UnderPath -Child $script:InstallRoot -Parent $script:TestRoot -Label 'MSI install root'
    Assert-UnderPath -Child $tempFallbackRoot -Parent $script:TestRoot -Label 'MSI default directory'
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
    New-MsiFixture -WxsPath $wxsV1 -WixObjPath $objV1 -MsiPath $msiV1 -PayloadPath $payloadV1Path -Version '1.0.0' -ProductCode $productCodeV1 -UpgradeCode $upgradeCode -ComponentCode $componentCode -DefaultDirectoryName $defaultDirectoryName -CandlePath $candlePath -LightPath $lightPath
    New-MsiFixture -WxsPath $wxsV2 -WixObjPath $objV2 -MsiPath $msiV2 -PayloadPath $payloadV2Path -Version '2.0.0' -ProductCode $productCodeV2 -UpgradeCode $upgradeCode -ComponentCode $componentCode -DefaultDirectoryName $defaultDirectoryName -CandlePath $candlePath -LightPath $lightPath

    $beforePath = Join-Path $script:TestRoot 'before-install.json'
    $snapshotV1Path = Join-Path $script:TestRoot 'installed-v1.json'
    $snapshotV2Path = Join-Path $script:TestRoot 'installed-v2.json'
    $snapshotDowngradePath = Join-Path $script:TestRoot 'downgraded-v1.json'
    $snapshotUninstallPath = Join-Path $script:TestRoot 'uninstalled.json'
    $before = Get-InventorySnapshot -Path $beforePath
    if (@($before.entries).Count -ne 0) {
        throw 'Fresh MSI install root was not empty before installation.'
    }

    $env:TEMP = $script:TestRoot
    $env:TMP = $script:TestRoot
    $installationStarted = $true
    Install-Msi -MsiPath $msiV1 -InstallRoot $script:InstallRoot -LogPath (Join-Path $script:TestRoot 'install-v1.log') -Description 'MSI v1 install'
    Assert-ProductVersion -ProductCode $productCodeV1 -Version '1.0.0'
    $entryV1 = Get-PayloadEntry (Get-InventorySnapshot -Path $snapshotV1Path)
    if ($entryV1.content_sha256 -ne (Get-FileHash -LiteralPath (Join-Path $script:InstallRoot 'payload.bin') -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'SideEffect v1 hash did not match the installed payload bytes.'
    }
    $installDiff = Get-InventoryDiff -BeforePath $beforePath -AfterPath $snapshotV1Path
    Assert-DiffEvidence -Diff $installDiff -Kind 'added' -CountField 'additions' -Count 1 -AfterEntry $entryV1
    Write-Output "MSI v1 installed; observed selected-root SHA-256: $($entryV1.content_sha256)"

    Install-Msi -MsiPath $msiV2 -InstallRoot $script:InstallRoot -LogPath (Join-Path $script:TestRoot 'update-v2.log') -Description 'MSI v2 major upgrade'
    Assert-ProductAbsent -ProductCode $productCodeV1
    Assert-ProductVersion -ProductCode $productCodeV2 -Version '2.0.0'
    $entryV2 = Get-PayloadEntry (Get-InventorySnapshot -Path $snapshotV2Path)
    if ($entryV2.content_sha256 -ne (Get-FileHash -LiteralPath (Join-Path $script:InstallRoot 'payload.bin') -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'SideEffect v2 hash did not match the installed payload bytes.'
    }
    if ($entryV1.content_sha256 -eq $entryV2.content_sha256) {
        throw 'Synthetic v1 and v2 payload fingerprints unexpectedly matched.'
    }
    $updateDiff = Get-InventoryDiff -BeforePath $snapshotV1Path -AfterPath $snapshotV2Path
    Assert-DiffEvidence -Diff $updateDiff -Kind 'changed' -CountField 'changes' -Count 1 -BeforeEntry $entryV1 -AfterEntry $entryV2 -RequireContentChange
    Write-Output "MSI v2 major upgrade completed; observed selected-root SHA-256: $($entryV2.content_sha256)"

    Uninstall-Msi -ProductCode $productCodeV2 -LogPath (Join-Path $script:TestRoot 'uninstall-v2-for-downgrade.log') -Description 'MSI v2 uninstall for downgrade strategy'
    Assert-ProductAbsent -ProductCode $productCodeV2
    Install-Msi -MsiPath $msiV1 -InstallRoot $script:InstallRoot -LogPath (Join-Path $script:TestRoot 'downgrade-reinstall-v1.log') -Description 'MSI v1 reinstall downgrade strategy'
    Assert-ProductVersion -ProductCode $productCodeV1 -Version '1.0.0'
    $entryDowngrade = Get-PayloadEntry (Get-InventorySnapshot -Path $snapshotDowngradePath)
    if ($entryDowngrade.content_sha256 -ne $entryV1.content_sha256) {
        throw 'Downgrade reinstall did not restore the v1 payload fingerprint.'
    }
    $downgradeDiff = Get-InventoryDiff -BeforePath $snapshotV2Path -AfterPath $snapshotDowngradePath
    Assert-DiffEvidence -Diff $downgradeDiff -Kind 'changed' -CountField 'changes' -Count 1 -BeforeEntry $entryV2 -AfterEntry $entryDowngrade -RequireContentChange
    Write-Output "Downgrade strategy restored MSI v1; observed selected-root SHA-256: $($entryDowngrade.content_sha256)"

    Uninstall-Msi -ProductCode $productCodeV1 -LogPath (Join-Path $script:TestRoot 'uninstall-v1.log') -Description 'MSI v1 final uninstall'
    Assert-ProductAbsent -ProductCode $productCodeV1
    $uninstalled = Get-InventorySnapshot -Path $snapshotUninstallPath
    if (@($uninstalled.entries).Count -ne 0 -or (Test-Path -LiteralPath (Join-Path $script:InstallRoot 'payload.bin'))) {
        throw 'Final MSI uninstall left the synthetic payload in the selected root.'
    }
    $uninstallDiff = Get-InventoryDiff -BeforePath $snapshotDowngradePath -AfterPath $snapshotUninstallPath
    Assert-DiffEvidence -Diff $uninstallDiff -Kind 'removed' -CountField 'removals' -Count 1 -BeforeEntry $entryDowngrade
    Write-Output 'MSI v1 uninstall removed the observed selected-root payload.'
}
finally {
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
    if ($installationStarted) {
        foreach ($productCode in @($productCodeV2, $productCodeV1)) {
            if ($null -ne (Get-ProductRegistration -ProductCode $productCode)) {
                try {
                    Uninstall-Msi -ProductCode $productCode -LogPath (Join-Path $script:TestRoot "cleanup-$($productCode.Trim('{}')).log") -Description 'MSI lifecycle failure cleanup'
                }
                catch {
                    Write-Warning "Could not clean up fixture MSI ${productCode}: $_"
                }
            }
        }
    }
    if ($createdTestRoot -and (Test-Path -LiteralPath $script:TestRoot)) {
        Assert-UnderPath -Child $script:TestRoot -Parent $runnerTemp -Label 'MSI cleanup target'
        Remove-Item -LiteralPath $script:TestRoot -Recurse -Force
    }
}
