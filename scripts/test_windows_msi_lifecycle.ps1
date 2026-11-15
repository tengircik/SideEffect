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
    $argumentLine = Get-MsiInstallArgumentLine -MsiPath $MsiPath -InstallRoot $InstallRoot -LogPath $LogPath
    Invoke-Msi -Description $Description -ArgumentLine $argumentLine -LogPath $LogPath -PackagePath $MsiPath
}

function Get-MsiInstallArgumentVector {
    param(
        [Parameter(Mandatory = $true)][string] $MsiPath,
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [Parameter(Mandatory = $true)][string] $LogPath
    )

    return ,@(
        '/i', [System.IO.Path]::GetFullPath($MsiPath),
        '/qn', '/norestart', '/l*v', [System.IO.Path]::GetFullPath($LogPath),
        "INSTALLROOT=$([System.IO.Path]::GetFullPath($InstallRoot))"
    )
}

function Get-SafeFileIoOperationClass {
    param([AllowNull()][string] $Operation)

    $known = @(
        'name', 'create_name', 'delete_name', 'rundown_name', 'create_request',
        'read_request', 'write_request', 'set_information_request', 'delete_request',
        'rename_request', 'query_information_request', 'file_system_control_request',
        'cleanup', 'close', 'flush_request'
    )
    if ($Operation -cin $known) { return $Operation }
    if ([string]::IsNullOrEmpty($Operation)) { return 'unknown' }
    return 'other'
}

function Get-SafePathNamespaceClass {
    param([AllowNull()][string] $Path)

    if ([string]::IsNullOrEmpty($Path)) { return 'unknown' }
    if ($Path -cmatch '^[A-Za-z]:\\') { return 'dos_drive' }
    if ($Path.StartsWith('\Device\', [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith('\??\', [StringComparison]::OrdinalIgnoreCase)) {
        return 'nt_device'
    }
    if ($Path.StartsWith('\\?\', [StringComparison]::Ordinal)) { return 'verbatim' }
    if ($Path.StartsWith('\\', [StringComparison]::Ordinal)) { return 'unc' }
    return 'relative_or_other'
}

function Get-SafeEtwDiagnosticClass {
    param([AllowNull()][string] $Diagnostic)

    if ([string]::IsNullOrEmpty($Diagnostic)) { return 'unknown' }
    switch -Regex ($Diagnostic) {
        '^event_or_payload_limit_reached$' { return 'event_or_payload_limit_reached' }
        '^invalid_or_unsupported_etw_record_seen$' { return 'invalid_or_unsupported_etw_record_seen' }
        '^oversized_or_null_etw_payload_events:[0-9]+$' { return 'oversized_or_null_etw_payload_events' }
        '^unexpected_provider_events:[0-9]+$' { return 'unexpected_provider_events' }
        '^etw_reported_event_loss$' { return 'etw_reported_event_loss' }
        '^etw_loss_statistics_unavailable$' { return 'etw_loss_statistics_unavailable' }
        '^etw_final_loss_statistics_unavailable$' { return 'etw_final_loss_statistics_unavailable' }
        '^etw_pre_stop_query_failed:[0-9]+$' { return 'etw_pre_stop_query_failed' }
        '^etw_stop_failed:[0-9]+$' { return 'etw_stop_failed' }
        '^duration_limit_reached;' { return 'duration_limit_reached' }
        default { return 'other' }
    }
}

function Get-SafeAssociationDiagnosticClass {
    param([AllowNull()][string] $Diagnostic)

    $known = @(
        'different_namespaces_remain_unresolved',
        'raw_cross_check_rejected_file_name_events',
        'no_same_namespace_exact_path_candidate_was_observed',
        'runtime_observation_limit_reached',
        'association_output_limit_reached',
        'selected_root_is_not_a_dos_drive_path',
        'runtime_capture_completeness_is_unknown'
    )
    if ($Diagnostic -cin $known) { return $Diagnostic }
    if ([string]::IsNullOrEmpty($Diagnostic)) { return 'unknown' }
    return 'other'
}

function Add-SafeSummaryCount {
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary] $Counts,
        [Parameter(Mandatory = $true)][string] $Class
    )

    if (-not $Counts.Contains($Class)) { $Counts[$Class] = 0 }
    $Counts[$Class] = [int]$Counts[$Class] + 1
}

function Get-StartupSourceStatus {
    param(
        [Parameter(Mandatory = $true)] $Document,
        [Parameter(Mandatory = $true)][string] $SourceId
    )

    $sources = @($Document.sources | Where-Object { $_.id -ceq $SourceId })
    if ($sources.Count -ne 1) {
        throw "Startup snapshot did not contain exactly one '$SourceId' source status."
    }
    return [string]$sources[0].status
}

function Assert-StartupObservation {
    param(
        [Parameter(Mandatory = $true)] $Comparison,
        [Parameter(Mandatory = $true)][string] $SessionPath,
        [Parameter(Mandatory = $true)][string] $ServiceName,
        [Parameter(Mandatory = $true)][string] $TaskPath,
        [Parameter(Mandatory = $true)][string] $InertImagePath
    )

    if ($Comparison.startup_comparison_status -cnotin @('complete', 'partial') -or
        $Comparison.startup_source_status -cnotin @('complete', 'partial', 'unknown', 'not_checked', 'unsupported', 'not_applicable', 'unavailable', 'access_denied', 'failed', 'timed_out', 'output_limit_exceeded') -or
        $null -eq $Comparison.startup_diff -or
        $Comparison.startup_diff.schema -cne 'sideeffect.startup_inventory_diff' -or
        $Comparison.startup_diff.platform -cne 'windows') {
        throw 'The verified observation did not expose a bounded paired Windows startup comparison with supported status values.'
    }
    $beforeRef = $Comparison.startup_before_artifact
    $afterRef = $Comparison.startup_after_artifact
    if ($null -eq $beforeRef -or $null -eq $afterRef -or $beforeRef.path -ceq $afterRef.path -or
        $beforeRef.kind -cne 'windows_startup' -or $afterRef.kind -cne 'windows_startup_after' -or
        $beforeRef.schema -cne 'sideeffect.windows_startup_inventory' -or
        $afterRef.schema -cne 'sideeffect.windows_startup_inventory' -or
        $beforeRef.schema_version -ne 10 -or $afterRef.schema_version -ne 10) {
        throw 'The comparison did not link distinct before and after startup artifacts from the same session.'
    }
    $beforePath = Join-Path $SessionPath ([string]$beforeRef.path)
    $afterPath = Join-Path $SessionPath ([string]$afterRef.path)
    Assert-UnderPath -Child $beforePath -Parent $SessionPath -Label 'before startup artifact'
    Assert-UnderPath -Child $afterPath -Parent $SessionPath -Label 'after startup artifact'
    foreach ($path in @($beforePath, $afterPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -gt 64MB) {
            throw 'A linked startup artifact was missing or exceeded the acceptance read bound.'
        }
    }
    $before = Get-Content -LiteralPath $beforePath -Raw | ConvertFrom-Json
    $after = Get-Content -LiteralPath $afterPath -Raw | ConvertFrom-Json
    foreach ($document in @($before, $after)) {
        if ($document.schema -cne 'sideeffect.windows_startup_inventory' -or $document.schema_version -ne 10 -or
            $document.status -cnotin @('complete', 'partial')) {
            throw 'A linked startup artifact did not retain the supported Windows startup v10 contract and explicit status.'
        }
    }
    if ($Comparison.startup_before_document_status -cne $before.status -or
        $Comparison.startup_after_document_status -cne $after.status) {
        throw 'The comparison did not preserve the explicit before and after startup document statuses.'
    }

    $beforeServices = @($before.service_entries | Where-Object { $_.service_name -ceq $ServiceName })
    $beforeTasks = @($before.scheduled_task_entries | Where-Object { $_.task_path -ceq $TaskPath })
    $beforeActions = @($before.scheduled_task_actions | Where-Object { $_.task_path -ceq $TaskPath })
    $afterServices = @($after.service_entries | Where-Object { $_.service_name -ceq $ServiceName })
    $afterTasks = @($after.scheduled_task_entries | Where-Object { $_.task_path -ceq $TaskPath })
    $serviceStatusBefore = Get-StartupSourceStatus -Document $before -SourceId 'service_start_configuration'
    $serviceStatusAfter = Get-StartupSourceStatus -Document $after -SourceId 'service_start_configuration'
    $taskStatusBefore = Get-StartupSourceStatus -Document $before -SourceId 'scheduled_task_triggers'
    $taskStatusAfter = Get-StartupSourceStatus -Document $after -SourceId 'scheduled_task_triggers'
    foreach ($status in @($serviceStatusBefore, $serviceStatusAfter, $taskStatusBefore, $taskStatusAfter)) {
        if ($status -cnotin @('complete', 'partial', 'not_present', 'unavailable', 'inaccessible', 'unsupported', 'not_checked', 'error')) {
            throw "Startup source returned an unsupported status '$status'."
        }
    }
    if ($beforeServices.Count -ne 0 -or $beforeTasks.Count -ne 0 -or $beforeActions.Count -ne 0) {
        throw 'A generated startup fixture identity was present in the before artifact.'
    }

    $serviceAvailable = $serviceStatusAfter -cin @('complete', 'partial')
    $taskAvailable = $taskStatusAfter -cin @('complete', 'partial')
    if ($serviceAvailable) {
        if ($afterServices.Count -ne 1) {
            throw "The SCM source status is $serviceStatusAfter but did not expose exactly one authored fixture service row (observed $($afterServices.Count))."
        }
        $serviceIndex = [Array]::IndexOf($after.service_entries, $afterServices[0])
        if ($afterServices[0].evidence.source -cne 'EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W' -or
            $serviceIndex -lt 0 -or $afterServices[0].evidence.service_index -ne $serviceIndex -or
            $afterServices[0].start_type -cne 'disabled' -or
            $afterServices[0].binary_path -notlike "*$([IO.Path]::GetFileName($InertImagePath))*") {
            throw 'The after artifact did not show exactly one disabled SCM fixture with its unique inert image path.'
        }
    }
    elseif ($afterServices.Count -ne 0) {
        throw 'An unavailable SCM source unexpectedly exposed a fixture service row.'
    }
    $afterActions = @($after.scheduled_task_actions | Where-Object {
        $_.task_path -ceq $TaskPath
    })
    if ($taskAvailable) {
        if ($afterTasks.Count -ne 1 -or $afterActions.Count -ne 1) {
            throw "The Task Scheduler source status is $taskStatusAfter but did not expose exactly one authored fixture trigger and one action row (triggers=$($afterTasks.Count), actions=$($afterActions.Count))."
        }
        $taskRow = $afterTasks[0]
        $actionRow = $afterActions[0]
        if ($actionRow.action_index -ne 0) {
            throw 'The authored fixture action did not retain its expected first-action index.'
        }
        if ($taskRow.trigger_type -cne 'logon' -or $taskRow.task_enabled -ne $false -or
            $taskRow.trigger_enabled -ne $false -or
            $taskRow.startup_state.configured -cne 'present' -or
            $taskRow.startup_state.effective.status -cne 'unknown' -or
            $taskRow.startup_state.observed.status -cne 'unknown' -or
            $taskRow.evidence.source -cne 'Task Scheduler IRegisteredTask/ITaskDefinition/ITrigger' -or
            -not ($taskRow.evidence.task_index -is [ValueType]) -or
            -not ($taskRow.evidence.trigger_index -is [ValueType]) -or
            $taskRow.evidence.trigger_index -ne 0) {
            throw 'The after artifact did not show exactly one disabled fixture task and disabled logon trigger with exact source indexes.'
        }
        if ($actionRow.status -cne 'observed' -or $actionRow.action_type -cne 'exec' -or
            $actionRow.executable_path -cne [IO.Path]::GetFullPath($InertImagePath) -or
            (Test-Path -LiteralPath $InertImagePath) -or
            $actionRow.startup_state.effective.status -cne 'unknown' -or
            $actionRow.startup_state.observed.status -cne 'unknown' -or
            $actionRow.evidence.source -cne 'Task Scheduler IActionCollection/IExecAction' -or
            $actionRow.evidence.task_index -ne $taskRow.evidence.task_index -or
            $actionRow.evidence.action_index -ne 0) {
            throw 'The after artifact did not preserve exactly one inert fixture Exec action with indexed evidence and unknown effective/observed state.'
        }
    }
    elseif ($afterTasks.Count -ne 0 -or $afterActions.Count -ne 0) {
        throw 'An unavailable Task Scheduler source unexpectedly exposed a fixture row.'
    }

    $startupDiff = $Comparison.startup_diff
    if ($Comparison.startup_comparison_status -ceq 'complete') {
        $expected = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
        if ($serviceStatusAfter -ceq 'complete') {
            [void]$expected.Add('service_configuration', "/service_entries/$([array]::IndexOf($after.service_entries, $afterServices[0]))")
        }
        if ($taskStatusAfter -ceq 'complete') {
            [void]$expected.Add('scheduled_task_trigger', "/scheduled_task_entries/$([array]::IndexOf($after.scheduled_task_entries, $afterTasks[0]))")
            $actionRow = @($after.scheduled_task_actions | Where-Object { $_.task_path -ceq $TaskPath -and $_.action_index -eq 0 })[0]
            [void]$expected.Add('scheduled_task_action_sequence', "/scheduled_task_actions/$([array]::IndexOf($after.scheduled_task_actions, $actionRow))")
        }
        foreach ($category in $expected.Keys) {
            $deltas = @($startupDiff.deltas | Where-Object {
                $_.category -ceq $category -and $_.kind -ceq 'observed_after_only' -and
                $null -eq $_.before -and $null -ne $_.after -and
                @($_.after.references | Where-Object { $_ -ceq $expected[$category] }).Count -eq 1
            })
            if ($deltas.Count -ne 1) {
                throw "Complete startup diff did not link exactly one after-only $category delta to its startup artifact."
            }
        }
    }
    else {
        if ($startupDiff.status -cne 'partial') {
            throw 'Partial startup comparison did not retain its explicit partial status.'
        }
        Write-Output "Startup comparison remained partial; source statuses: SCM $serviceStatusBefore -> $serviceStatusAfter, Task Scheduler $taskStatusBefore -> $taskStatusAfter. Unavailable configuration remains unknown."
    }
    Write-Output "Same-session startup links verified: before='$($beforeRef.path)' ($($before.status)); after='$($afterRef.path)' ($($after.status)); source statuses SCM=$serviceStatusAfter, TaskScheduler=$taskStatusAfter; no causal inference."
}

function Remove-MsiObservationFixtures {
    param(
        [Parameter(Mandatory = $true)][string] $ServiceName,
        [Parameter(Mandatory = $true)][string] $TaskName,
        [Parameter(Mandatory = $true)][string] $OwnershipMarkerPath
    )

    if (-not (Test-Path -LiteralPath $OwnershipMarkerPath -PathType Leaf) -or
        (Get-Item -LiteralPath $OwnershipMarkerPath).Length -gt 4096) {
        throw 'The exact startup fixture ownership marker was missing or exceeded its bound; refusing cleanup by name alone.'
    }
    $ownership = Get-Content -LiteralPath $OwnershipMarkerPath -Raw | ConvertFrom-Json
    if ($ownership.service_name -cne $ServiceName -or $ownership.task_name -cne $TaskName -or
        $ServiceName -cnotmatch '^SeR5-[0-9a-f]{32}$' -or $TaskName -cnotmatch '^SideEffectR5Msi-[0-9a-f]{32}$') {
        throw 'The startup fixture ownership marker did not match the generated exact identities.'
    }

    $failures = [System.Collections.Generic.List[string]]::new()
    $taskMatches = @()
    try {
        $taskMatches = @(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object { $_.TaskName -ceq $TaskName })
        if ($taskMatches.Count -gt 1) {
            $failures.Add('multiple exact Task Scheduler fixture identities were returned')
        }
        elseif ($taskMatches.Count -eq 1) {
            Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false -ErrorAction Stop | Out-Null
            $deadline = [DateTime]::UtcNow.AddSeconds(10)
            do {
                Start-Sleep -Milliseconds 100
                $remaining = @(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object { $_.TaskName -ceq $TaskName })
            } while ($remaining.Count -gt 0 -and [DateTime]::UtcNow -lt $deadline)
            if ($remaining.Count -gt 0) { $failures.Add('exact Task Scheduler fixture did not disappear within the bounded wait') }
        }
    }
    catch { $failures.Add("Task Scheduler removal failed: $($_.Exception.Message)") }

    $sc = Join-Path $env:WINDIR 'System32\sc.exe'
    try {
        $probe = Start-Process -FilePath $sc -ArgumentList @('query', $ServiceName) -Wait -PassThru -NoNewWindow
        if ($probe.ExitCode -eq 0) {
            $delete = Start-Process -FilePath $sc -ArgumentList @('delete', $ServiceName) -Wait -PassThru -NoNewWindow
            if ($delete.ExitCode -ne 0) { $failures.Add("SCM rejected deletion of exact service fixture (exit $($delete.ExitCode))") }
            $deadline = [DateTime]::UtcNow.AddSeconds(10)
            do {
                Start-Sleep -Milliseconds 100
                $probe = Start-Process -FilePath $sc -ArgumentList @('query', $ServiceName) -Wait -PassThru -NoNewWindow
            } while ($probe.ExitCode -eq 0 -and [DateTime]::UtcNow -lt $deadline)
            if ($probe.ExitCode -ne 1060) { $failures.Add('exact SCM fixture did not disappear within the bounded wait') }
        }
        elseif ($probe.ExitCode -ne 1060) {
            $failures.Add("SCM could not verify exact service fixture absence (exit $($probe.ExitCode))")
        }
    }
    catch { $failures.Add("SCM fixture removal failed: $($_.Exception.Message)") }
    if ($failures.Count -gt 0) { throw ($failures -join '; ') }
}

function Get-MsiInstallArgumentLine {
    param(
        [Parameter(Mandatory = $true)][string] $MsiPath,
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [Parameter(Mandatory = $true)][string] $LogPath
    )

    $arguments = Get-MsiInstallArgumentVector -MsiPath $MsiPath -InstallRoot $InstallRoot -LogPath $LogPath
    return "/i `"$($arguments[1])`" /qn /norestart /l*v `"$($arguments[5])`" INSTALLROOT=`"$([System.IO.Path]::GetFullPath($InstallRoot))`""
}

function Invoke-ObservedMsiInstall {
    param(
        [Parameter(Mandatory = $true)][string] $MsiPath,
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [Parameter(Mandatory = $true)][string] $LogPath,
        [Parameter(Mandatory = $true)][string] $SessionPath,
        [Parameter(Mandatory = $true)][ValidateSet('added', 'changed')][string] $ExpectedDeltaKind,
        [Parameter(Mandatory = $true)][string] $ExpectedPayloadSha256,
        [Parameter()][string] $ExpectedPreviousPayloadSha256,
        [Parameter(Mandatory = $true)][string] $ExpectedProductCode,
        [Parameter()][string] $ExpectedPreviousProductCode,
        [Parameter(Mandatory = $true)][string] $Description
    )

    $ExpectedPayloadSha256 = $ExpectedPayloadSha256.ToLowerInvariant()
    if ($ExpectedDeltaKind -eq 'added') {
        if (-not [string]::IsNullOrWhiteSpace($ExpectedPreviousPayloadSha256)) {
            throw 'An added selected-root delta cannot have a previous payload SHA-256.'
        }
    }
    else {
        $ExpectedPreviousPayloadSha256 = $ExpectedPreviousPayloadSha256.ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($ExpectedPreviousPayloadSha256)) {
            throw 'A changed selected-root delta requires the previous payload SHA-256.'
        }
        if ($ExpectedPreviousPayloadSha256 -ceq $ExpectedPayloadSha256) {
            throw 'A changed selected-root delta requires distinct before and after payload SHA-256 values.'
        }
    }

    Assert-UnderPath -Child $MsiPath -Parent $script:TestRoot -Label 'observed MSI fixture'
    Assert-UnderPath -Child $InstallRoot -Parent $script:TestRoot -Label 'observed MSI install root'
    Assert-UnderPath -Child $LogPath -Parent $script:TestRoot -Label 'observed MSI log'
    Assert-UnderPath -Child $SessionPath -Parent $script:TestRoot -Label 'MSI observation session'
    $msiArguments = Get-MsiInstallArgumentVector -MsiPath $MsiPath -InstallRoot $InstallRoot -LogPath $LogPath
    $fixtureId = [Guid]::NewGuid().ToString('N')
    $fixtureServiceName = "SeR5-$fixtureId"
    $fixtureTaskName = "SideEffectR5Msi-$fixtureId"
    $fixtureTaskPath = "\$fixtureTaskName"
    $inertImagePath = Join-Path $script:TestRoot "intentionally-absent-$fixtureId.exe"
    $exitCodePath = Join-Path $script:TestRoot "msiexec-exit-$fixtureId.txt"
    $ownershipMarkerPath = Join-Path $script:TestRoot "startup-fixture-owner-$fixtureId.json"
    $wrapperPath = Join-Path $PSScriptRoot 'test_windows_msi_observation_wrapper.ps1'
    $powershellPath = Join-Path $PSHOME 'pwsh.exe'
    if (-not (Test-Path -LiteralPath $wrapperPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $powershellPath -PathType Leaf)) {
        throw 'The fixed hosted-runner observation wrapper or PowerShell 7 executable was unavailable.'
    }
    foreach ($path in @($inertImagePath, $exitCodePath, $ownershipMarkerPath)) {
        Assert-UnderPath -Child $path -Parent $script:TestRoot -Label 'startup observation fixture path'
        if (Test-Path -LiteralPath $path) {
            throw 'A generated startup fixture path already exists; refusing to reuse it.'
        }
    }
    if (Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object { $_.TaskName -ceq $fixtureTaskName }) {
        throw 'The generated Task Scheduler identity already exists; refusing to alter it.'
    }
    $scPath = Join-Path $env:WINDIR 'System32\sc.exe'
    $serviceProbe = Start-Process -FilePath $scPath -ArgumentList @('query', $fixtureServiceName) -Wait -PassThru -NoNewWindow
    if ($serviceProbe.ExitCode -ne 1060) {
        throw 'The generated SCM identity already exists or could not be verified absent.'
    }
    [IO.File]::WriteAllText($ownershipMarkerPath, (@{ service_name = $fixtureServiceName; task_name = $fixtureTaskName } | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    $argumentsBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($msiArguments | ConvertTo-Json -Compress)))
    $wrapperArguments = @(
        '-NoProfile', '-NonInteractive', '-File', $wrapperPath,
        '-ServiceName', $fixtureServiceName,
        '-TaskName', $fixtureTaskName,
        '-InertImagePath', $inertImagePath,
        '-MsiexecPath', $script:MsiexecPath,
        '-ArgumentsJsonBase64', $argumentsBase64,
        '-ExitCodePath', $exitCodePath,
        '-OwnershipMarkerPath', $ownershipMarkerPath
    )
    $auditArguments = @(
        'audit', '--output', $SessionPath,
        '--observe-root', $InstallRoot, '--hash-regular-files',
        '--startup', '--packages', '--runtime-source', 'windows-etw', '--runtime-duration-seconds', '30',
        '--', $powershellPath
    ) + $wrapperArguments
    try {
        & $script:SideEffectPath @auditArguments
        $auditExitCode = $LASTEXITCODE
    }
    finally {
        try {
            Remove-MsiObservationFixtures -ServiceName $fixtureServiceName -TaskName $fixtureTaskName -OwnershipMarkerPath $ownershipMarkerPath
        }
        catch {
            $script:ObservationFixtureCleanupErrors.Add("$Description startup fixture cleanup failed: $($_.Exception.Message)")
        }
    }
    if ($auditExitCode -ne 2) {
        throw "SideEffect observed MSI install returned exit code $auditExitCode; expected partial exit 2 because ETW completeness is unknown."
    }
    $global:LASTEXITCODE = 0

    if (-not (Test-Path -LiteralPath $exitCodePath -PathType Leaf) -or (Get-Item -LiteralPath $exitCodePath).Length -gt 128) {
        throw 'The hosted wrapper did not produce its bounded msiexec result sidecar.'
    }
    $msiexecResult = Get-Content -LiteralPath $exitCodePath -Raw | ConvertFrom-Json
    $msiExitCode = 0
    $msiexecPid = [uint32]0
    if (-not [int]::TryParse([string]$msiexecResult.exit_code, [ref]$msiExitCode) -or
        -not [uint32]::TryParse([string]$msiexecResult.process_id, [ref]$msiexecPid) -or $msiexecPid -eq 0) {
        throw 'The wrapper msiexec result sidecar was malformed.'
    }
    if ($msiExitCode -ne 0) {
        throw "$Description preserved msiexec exit code $msiExitCode; installation did not succeed."
    }

    $comparisonOutput = & $script:SideEffectPath 'compare-observation' $SessionPath | Out-String
    $comparisonExitCode = $LASTEXITCODE
    if ($comparisonExitCode -ne 2) {
        throw "SideEffect observation comparison returned exit code $comparisonExitCode; expected partial exit 2 because runtime completeness is unknown."
    }
    $global:LASTEXITCODE = 0
    $comparison = $comparisonOutput | ConvertFrom-Json
    if ($comparison.schema -ne 'sideeffect.observation_window_diff' -or
        $comparison.schema_version -ne 1 -or
        $comparison.status -ne 'partial' -or
        $comparison.root_comparison_status -ne 'complete' -or
        $comparison.root_source_status -ne 'complete' -or
        $comparison.runtime_source_status -ne 'partial' -or
        $comparison.runtime_capture_completeness -ne 'unknown') {
        throw "Observed MSI session status was not complete selected-root plus partial/unknown ETW (root=$($comparison.root_comparison_status), runtime=$($comparison.runtime_source_status), completeness=$($comparison.runtime_capture_completeness))."
    }
    Assert-ObservedSessionSoftwareComparison -SessionPath $SessionPath -Comparison $comparison `
        -ProductCode $ExpectedProductCode -PreviousProductCode $ExpectedPreviousProductCode
    $counts = $comparison.root_diff.counts
    $expectedAdditions = if ($ExpectedDeltaKind -eq 'added') { 1 } else { 0 }
    $expectedChanges = if ($ExpectedDeltaKind -eq 'changed') { 1 } else { 0 }
    $deltas = @($comparison.root_diff.deltas)
    if ($counts.additions -ne $expectedAdditions -or $counts.changes -ne $expectedChanges -or
        $counts.removals -ne 0 -or $deltas.Count -ne 1) {
        throw "Observed MSI session did not report exactly one selected-root $ExpectedDeltaKind delta (additions=$($counts.additions), changes=$($counts.changes), removals=$($counts.removals), rows=$($deltas.Count))."
    }
    $delta = $deltas[0]
    $payloadPath = Join-Path $InstallRoot 'payload.bin'
    $afterRootPath = Join-Path $SessionPath 'root-snapshot-after.json'
    $afterRoot = Get-Content -LiteralPath $afterRootPath -Raw | ConvertFrom-Json
    $afterRows = @($afterRoot.entries | Where-Object { $_.display_name -ceq 'payload.bin' })
    $payloadHash = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($payloadHash -cne $ExpectedPayloadSha256) {
        throw "Installed payload SHA-256 $payloadHash did not match the expected post-transition payload SHA-256 $ExpectedPayloadSha256."
    }
    if ($delta.kind -ne $ExpectedDeltaKind -or $delta.name -cne 'payload.bin' -or
        $delta.after.evidence_source -ne 'selected_root_directory_entry' -or
        $afterRows.Count -ne 1 -or $delta.after.entry_ordinal -ne $afterRows[0].ordinal -or
        $afterRows[0].content_sha256 -cne $ExpectedPayloadSha256 -or $afterRows[0].content_hash_status -ne 'observed') {
        throw "Observed MSI root $ExpectedDeltaKind did not match the installed payload SHA-256 and verified after-snapshot evidence ordinal."
    }
    if ($ExpectedDeltaKind -eq 'changed') {
        $beforeRootPath = Join-Path $SessionPath 'root-snapshot.json'
        $beforeRoot = Get-Content -LiteralPath $beforeRootPath -Raw | ConvertFrom-Json
        $beforeRows = @($beforeRoot.entries | Where-Object { $_.display_name -ceq 'payload.bin' })
        if ($null -eq $delta.before -or $delta.before.evidence_source -ne 'selected_root_directory_entry' -or
            $beforeRows.Count -ne 1 -or $delta.before.entry_ordinal -ne $beforeRows[0].ordinal -or
            $beforeRows[0].content_sha256 -cne $ExpectedPreviousPayloadSha256 -or $beforeRows[0].content_hash_status -ne 'observed') {
            throw 'Observed MSI root change did not match the previous payload SHA-256 and verified before-snapshot evidence ordinal.'
        }
        if (-not (@($delta.changed_fields) -contains 'content_sha256')) {
            throw 'Observed MSI root change did not report the selected-root content_sha256 change.'
        }
    }

    $expectedPath = [System.IO.Path]::GetFullPath($payloadPath)
    $association = $comparison.root_runtime_association
    if ($null -eq $association -or $association.claim -ne 'exact_lexical_dos_drive_path_candidate_only_no_success_ownership_or_causation' -or
        $association.status -ne 'partial' -or $association.capture_completeness -ne 'unknown') {
        throw 'Observation comparison did not retain the bounded lexical-candidate claim and unknown ETW completeness.'
    }

    $runtimeArtifact = @($comparison.runtime_artifacts | Where-Object { $_.path -eq 'runtime.windows.json' })
    if ($runtimeArtifact.Count -ne 1 -or $runtimeArtifact[0].schema -ne 'sideeffect.windows_runtime_capture' -or $runtimeArtifact[0].schema_version -ne 3) {
        throw 'Observation comparison did not reference exactly one Windows ETW v3 capture artifact.'
    }
    $capturePath = Join-Path $SessionPath 'runtime.windows.json'
    Assert-UnderPath -Child $capturePath -Parent $SessionPath -Label 'ETW capture artifact'
    $captureBytes = [System.IO.File]::ReadAllBytes($capturePath)
    $captureSha256 = [System.Security.Cryptography.SHA256]::HashData($captureBytes)
    $captureArtifactHash = [System.BitConverter]::ToString($captureSha256).Replace('-', '').ToLowerInvariant()
    if ($captureArtifactHash -cne $runtimeArtifact[0].sha256) {
        throw 'ETW capture artifact bytes did not match the verified session artifact digest.'
    }
    $capture = [System.Text.Encoding]::UTF8.GetString($captureBytes) | ConvertFrom-Json
    if ($capture.schema -ne 'sideeffect.windows_runtime_capture' -or $capture.schema_version -ne 3 -or
        $capture.document_sha256 -cne $association.capture_document_sha256 -or
        $association.capture_artifact_sha256 -cne $captureArtifactHash -or
        $capture.target.exit_code -ne $msiExitCode) {
        throw 'ETW capture digests or target exit code did not match the verified MSI child result.'
    }
    $targetPid = [uint32]$capture.target.process_id
    $targetStarts = @($capture.events | Where-Object {
        $_.event_kind -eq 'process_start' -and $_.payload_decoding.status -eq 'decoded' -and
        [uint32]$_.payload_decoding.process_id -eq $targetPid -and
        [System.IO.Path]::GetFileName([string]$_.payload_decoding.image_file_name) -ieq 'pwsh.exe'
    })
    if ($targetPid -eq 0 -or $targetStarts.Count -eq 0) {
        throw 'ETW capture did not contain a decoded process-start row for the fixed PowerShell harness target PID.'
    }
    $msiexecStarts = @($capture.events | Where-Object {
        $_.event_kind -eq 'process_start' -and $_.payload_decoding.status -eq 'decoded' -and
        [uint32]$_.payload_decoding.process_id -eq $msiexecPid -and
        [System.IO.Path]::GetFileName([string]$_.payload_decoding.image_file_name) -ieq 'msiexec.exe'
    })
    if ($msiexecStarts.Count -eq 0) {
        throw 'ETW capture did not contain a decoded process-start row for the exact waited msiexec child PID; no relationship is inferred when its row is missing.'
    }
    $rawPayloadHashes = @{}
    $payloadNameEvidence = [System.Collections.Generic.List[object]]::new()
    $payloadOperationClassCounts = [ordered]@{}
    $payloadNamespaceClassCounts = [ordered]@{}
    for ($eventIndex = 0; $eventIndex -lt $capture.events.Count; $eventIndex++) {
        $event = $capture.events[$eventIndex]
        if ($event.event_kind -ne 'file_io_observation' -or $event.observation_decoding.status -ne 'decoded' -or
            $event.observation_decoding.observation.activity.kind -ne 'file' -or
            [System.IO.Path]::GetFileName([string]$event.observation_decoding.observation.activity.observation.path) -ine 'payload.bin') {
            continue
        }
        $fileObservation = $event.observation_decoding.observation.activity.observation
        Add-SafeSummaryCount -Counts $payloadOperationClassCounts -Class (Get-SafeFileIoOperationClass -Operation ([string]$fileObservation.operation))
        Add-SafeSummaryCount -Counts $payloadNamespaceClassCounts -Class (Get-SafePathNamespaceClass -Path ([string]$fileObservation.path))
        $rawPayload = [Convert]::FromHexString([string]$event.raw_payload_hex)
        $rawPayloadHash = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($rawPayload)).Replace('-', '').ToLowerInvariant()
        $payloadNameUtf16 = [System.Text.Encoding]::Unicode.GetBytes('payload.bin')
        $rawHex = [System.BitConverter]::ToString($rawPayload).Replace('-', '').ToLowerInvariant()
        $payloadNameHex = [System.BitConverter]::ToString($payloadNameUtf16).Replace('-', '').ToLowerInvariant()
        if (-not $rawHex.Contains($payloadNameHex)) {
            throw 'Decoded ETW payload-name row did not retain the expected basename in its raw payload bytes.'
        }
        $rawPayloadHashes[[string]$event.record_ordinal] = $rawPayloadHash
        $payloadNameEvidence.Add([pscustomobject]@{
            capture_document_sha256 = $capture.document_sha256
            json_pointer = "/events/$eventIndex"
            record_ordinal = $event.record_ordinal
            raw_payload_sha256 = $rawPayloadHash
        })
    }
    if ($payloadNameEvidence.Count -eq 0) {
        throw 'ETW capture did not contain a decoded file-name observation for the fixture payload basename.'
    }
    Assert-ObservedNtRootRuntimeAssociation -SessionPath $SessionPath -Comparison $comparison `
        -ExpectedDeltaKind $ExpectedDeltaKind -Capture $capture -CaptureArtifactHash $captureArtifactHash `
        -RawPayloadHashes $rawPayloadHashes

    $candidate = @($association.associations | Where-Object { $_.candidate_path -ceq $expectedPath -and $_.delta_kind -eq $ExpectedDeltaKind -and $_.etw_operation -eq 'create_name' })
    if ($candidate.Count -gt 0) {
        foreach ($evidence in $candidate[0].runtime_evidence) {
            if ($evidence.capture_document_sha256 -cne $capture.document_sha256 -or $evidence.etw_operation -ne 'create_name' -or
                $evidence.json_pointer -notmatch '^/events/([0-9]+)$') {
                throw 'ETW evidence reference did not match the capture document digest, event pointer, and create-name observation.'
            }
            $eventIndex = [int]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
            if ($eventIndex -lt 0 -or $eventIndex -ge $capture.events.Count) {
                throw 'ETW evidence JSON pointer was outside the actual capture events array.'
            }
            $event = $capture.events[$eventIndex]
            if (-not $rawPayloadHashes.ContainsKey([string]$event.record_ordinal) -or
                $event.record_ordinal -ne $evidence.record_ordinal -or
                $rawPayloadHashes[[string]$event.record_ordinal] -cne $evidence.raw_payload_sha256 -or
                $event.observation_decoding.observation.activity.observation.path -cne $expectedPath) {
                throw "ETW evidence pointer /events/$eventIndex did not resolve to the matching raw-payload-verified exact DOS path observation."
            }
        }
        Write-Output "ETW exact DOS-path candidate linked to the installed payload; $($candidate[0].runtime_evidence.Count) raw evidence reference(s)."
    }
    elseif ($association.association_status -eq 'insufficient_evidence' -and
        $association.summary.candidate_match_count -eq 0 -and
        @($association.diagnostics | Where-Object { $_ -in @('different_namespaces_remain_unresolved', 'no_same_namespace_exact_path_candidate_was_observed') }).Count -gt 0) {
        $captureDiagnosticClassCounts = [ordered]@{}
        foreach ($diagnostic in @($capture.diagnostics)) {
            Add-SafeSummaryCount -Counts $captureDiagnosticClassCounts -Class (Get-SafeEtwDiagnosticClass -Diagnostic ([string]$diagnostic))
        }
        $associationDiagnosticClassCounts = [ordered]@{}
        foreach ($diagnostic in @($association.diagnostics)) {
            Add-SafeSummaryCount -Counts $associationDiagnosticClassCounts -Class (Get-SafeAssociationDiagnosticClass -Diagnostic ([string]$diagnostic))
        }
        $loss = $capture.event_loss
        $lossCountersAvailable = $null -ne $loss -and $loss.loss_statistics_available -eq $true
        $crossCheckCountAvailable = $null -ne $association.summary -and
            $null -ne $association.summary.PSObject.Properties['cross_check_rejected_event_count'] -and
            $association.summary.cross_check_rejected_event_count -is [ValueType]
        $collectionClass = if ($capture.collection_status -cin @('complete', 'partial')) { [string]$capture.collection_status } else { 'other' }
        $stopReasonClass = if ($capture.stop_reason -cin @('target_exited', 'duration_limit_reached', 'event_limit_reached', 'etw_loss_reported', 'etw_statistics_unavailable')) { [string]$capture.stop_reason } else { 'other' }
        $safeAssociationSummary = [ordered]@{
            capture_collection_status = $collectionClass
            capture_stop_reason = $stopReasonClass
            payload_name_observation_count = $payloadNameEvidence.Count
            raw_payload_basename_byte_check_count = $payloadNameEvidence.Count
            file_io_operation_class_counts = $payloadOperationClassCounts
            payload_path_namespace_class_counts = $payloadNamespaceClassCounts
            association_namespace_counts = [ordered]@{
                name_bearing_file_events = [long]$association.summary.name_bearing_file_event_count
                directional_file_name_events = [long]$association.summary.directional_file_name_event_count
                same_dos_drive_events = [long]$association.summary.same_dos_drive_event_count
                nt_device_namespace_events = [long]$association.summary.nt_device_namespace_event_count
                unc_namespace_events = [long]$association.summary.unc_namespace_event_count
                verbatim_namespace_events = [long]$association.summary.verbatim_namespace_event_count
                relative_or_other_namespace_events = [long]$association.summary.relative_or_other_namespace_event_count
                different_dos_drive_events = [long]$association.summary.different_dos_drive_event_count
                runtime_rows_omitted = [long]$association.summary.runtime_observation_rows_omitted_to_limit
            }
            raw_cross_check_count_available = $crossCheckCountAvailable
            association_capture_wide_cross_check_rejected_file_name_event_count = if ($crossCheckCountAvailable) { [long]$association.summary.cross_check_rejected_event_count } else { $null }
            association_diagnostic_class_counts = $associationDiagnosticClassCounts
            capture_diagnostic_array_available = $null -ne $capture.PSObject.Properties['diagnostics']
            capture_diagnostic_entry_count = @($capture.diagnostics).Count
            capture_diagnostic_class_counts = $captureDiagnosticClassCounts
            loss_counters_available = $lossCountersAvailable
            final_loss_snapshot_available = ($null -ne $loss -and $loss.final_snapshot_available -eq $true)
            events_lost = if ($lossCountersAvailable) { [long]$loss.events_lost } else { $null }
            log_buffers_lost = if ($lossCountersAvailable) { [long]$loss.log_buffers_lost } else { $null }
            real_time_buffers_lost = if ($lossCountersAvailable) { [long]$loss.real_time_buffers_lost } else { $null }
        }
        Write-Output "ETW recorded decoded payload-basename observations, but no exact path candidate was available; the selected-root/runtime relationship remains unresolved. Bounded enum/count diagnostics only: $($safeAssociationSummary | ConvertTo-Json -Compress -Depth 6). Evidence references (capped at 8): $(@($payloadNameEvidence | Select-Object -First 8) | ConvertTo-Json -Compress -Depth 4)"
    }
    else {
        throw 'ETW payload-name evidence was not supported by a candidate or an explicit unresolved namespace diagnostic.'
    }
    Assert-StartupObservation -Comparison $comparison -SessionPath $SessionPath -ServiceName $fixtureServiceName -TaskPath $fixtureTaskPath -InertImagePath $inertImagePath
    Write-Output "$Description produced one selected-root $ExpectedDeltaKind delta for the expected payload SHA-256. ETW separately recorded the wrapper target and an msiexec child process-start row; completeness and causality remain unknown."
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
        [Parameter(Mandatory = $true)][string] $Version,
        [Parameter()][string] $ProductCode
    )

    $matches = @($Document.registrations | Where-Object {
        $_.display_name -eq $DisplayName -and
        $_.evidence.hive -eq 'HKEY_CURRENT_USER' -and
        $_.evidence.registry_view -in @('native', 'wow64_32') -and
        ([string]::IsNullOrEmpty($ProductCode) -or $_.registry_subkey -ceq $ProductCode) -and
        (@($_.values | Where-Object { $_.name -eq 'DisplayVersion' -and $_.text -eq $Version }).Count -eq 1)
    })
    foreach ($view in @('native', 'wow64_32')) {
        if (@($matches | Where-Object { $_.evidence.registry_view -eq $view }).Count -gt 1) {
            throw "SideEffect reported duplicate current-user $view fixture registrations at version $Version."
        }
    }
    return $matches
}

function Assert-ObservedSessionSoftwareComparison {
    param(
        [Parameter(Mandatory = $true)][string] $SessionPath,
        [Parameter(Mandatory = $true)] $Comparison,
        [Parameter(Mandatory = $true)][string] $ProductCode,
        [Parameter()][string] $PreviousProductCode
    )

    if ($Comparison.software_comparison_status -notin @('complete', 'partial') -or
        $null -eq $Comparison.software_diff -or
        $Comparison.software_diff.schema -ne 'sideeffect.windows_software_inventory_diff' -or
        $Comparison.software_diff.schema_version -ne 1) {
        throw 'Observed MSI session did not provide a typed Windows software-registration v1 comparison.'
    }

    $manifestPath = Join-Path $SessionPath 'session.json'
    Assert-UnderPath -Child $manifestPath -Parent $SessionPath -Label 'observation session manifest'
    $manifestItem = Get-Item -LiteralPath $manifestPath
    if ($manifestItem.Length -gt 1048576) { throw 'Observation session manifest exceeded the bounded acceptance size.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 'sideeffect.audit_session' -or $manifest.schema_version -ne 19) {
        throw 'Observed MSI package session did not use the v19 observation manifest.'
    }
    $packageSources = @($manifest.sources | Where-Object { $_.role -eq 'packages' })
    if ($packageSources.Count -ne 1) { throw 'Observed MSI session did not have exactly one manifest-linked package source.' }
    if ($Comparison.software_source_status -cne $packageSources[0].status) {
        throw 'Observed MSI software source status did not match its session manifest source.'
    }

    $artifactSpecs = @(
        [pscustomobject]@{ Property = 'software_before_artifact'; Kind = 'windows_software'; Path = 'software.windows.json'; Side = 'before' },
        [pscustomobject]@{ Property = 'software_after_artifact'; Kind = 'windows_software_after'; Path = 'software-after.windows.json'; Side = 'after' }
    )
    $documents = @{}
    foreach ($spec in $artifactSpecs) {
        $comparisonReference = $Comparison.($spec.Property)
        $manifestReferences = @($packageSources[0].artifacts | Where-Object { $_.kind -eq $spec.Kind -and $_.path -eq $spec.Path })
        if ($null -eq $comparisonReference -or $manifestReferences.Count -ne 1) {
            throw "Observed MSI $($spec.Side) software artifact was not linked exactly once by comparison and manifest."
        }
        $reference = $manifestReferences[0]
        foreach ($field in @('path', 'schema', 'schema_version', 'byte_length', 'sha256')) {
            if ($comparisonReference.$field -cne $reference.$field) {
                throw "Observed MSI $($spec.Side) software artifact comparison reference differed from the manifest."
            }
        }
        if ($reference.schema -ne 'sideeffect.windows_software_inventory' -or $reference.schema_version -ne 1) {
            throw "Observed MSI $($spec.Side) software artifact was not the Windows software v1 schema."
        }
        $artifactPath = Join-Path $SessionPath $spec.Path
        Assert-UnderPath -Child $artifactPath -Parent $SessionPath -Label 'software session artifact'
        $item = Get-Item -LiteralPath $artifactPath
        if ($item.Length -gt 8388608 -or $item.Length -ne [long]$reference.byte_length) {
            throw "Observed MSI $($spec.Side) software artifact exceeded its bound or manifest byte length."
        }
        $bytes = [System.IO.File]::ReadAllBytes($artifactPath)
        $digest = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        if ($digest -cne $reference.sha256) { throw "Observed MSI $($spec.Side) software artifact did not match its manifest digest." }
        $document = [System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        if ($document.schema -ne 'sideeffect.windows_software_inventory' -or $document.schema_version -ne 1 -or $document.platform -ne 'windows') {
            throw "Observed MSI $($spec.Side) software artifact did not decode as Windows software v1."
        }
        $documents[$spec.Side] = $document
    }
    if ($Comparison.software_before_document_status -ne $documents.before.status -or
        $Comparison.software_after_document_status -ne $documents.after.status) {
        throw 'Observed MSI software document statuses did not match their manifest-linked artifacts.'
    }

    $displayName = 'SideEffect R5 Synthetic MSI Fixture'
    $productVersion = if ([string]::IsNullOrWhiteSpace($PreviousProductCode)) { '1.0.0' } else { '2.0.0' }
    $expected = @([pscustomobject]@{
        Code = $ProductCode
        Version = $productVersion
        Kind = 'added'
    })
    if (-not [string]::IsNullOrWhiteSpace($PreviousProductCode)) {
        $expected += [pscustomobject]@{ Code = $PreviousProductCode; Version = '1.0.0'; Kind = 'removed' }
    }
    $unknown = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $expected) {
        $beforeRows = @(Get-FixtureSoftwareRegistrations -Document $documents.before -DisplayName $displayName -Version $entry.Version -ProductCode $entry.Code)
        $afterRows = @(Get-FixtureSoftwareRegistrations -Document $documents.after -DisplayName $displayName -Version $entry.Version -ProductCode $entry.Code)
        $views = @($beforeRows | ForEach-Object { $_.evidence.registry_view })
        $views += @($afterRows | ForEach-Object { $_.evidence.registry_view })
        $views = @($views | Sort-Object -Unique)
        if ($views.Count -eq 0) {
            $unknown.Add("$($entry.Version):not_observed")
            continue
        }
        foreach ($view in $views) {
            $sourceId = if ($view -eq 'native') { 'current_user_native_uninstall' } else { 'current_user_32_uninstall' }
            $source = @($Comparison.software_diff.sources | Where-Object { $_.source_id -eq $sourceId })
            if ($source.Count -ne 1 -or $source[0].before_status -notin @('complete', 'not_present') -or
                $source[0].after_status -notin @('complete', 'not_present')) {
                $unknown.Add("$($entry.Version):$view`_source_partial")
                continue
            }
            $beforePresent = @($beforeRows | Where-Object { $_.evidence.registry_view -eq $view }).Count -eq 1
            $afterPresent = @($afterRows | Where-Object { $_.evidence.registry_view -eq $view }).Count -eq 1
            if ($entry.Kind -eq 'added') {
                if ($beforePresent) {
                    throw "Observed MSI ProductCode addition was already present before the transition in $view."
                }
                if (-not $afterPresent) { continue }
            }
            else {
                if ($afterPresent) {
                    throw "Observed MSI ProductCode removal remained present after the transition in $view."
                }
                if (-not $beforePresent) { continue }
            }
            $kind = $entry.Kind
            $deltas = @($Comparison.software_diff.deltas | Where-Object {
                $_.kind -eq $kind -and $_.identity.source_id -eq $sourceId -and
                $_.identity.registry_view -eq $view -and $_.identity.registry_subkey -ceq $entry.Code
            })
            if ($deltas.Count -ne 1) {
                throw "Observed MSI ProductCode registration transition for $($entry.Version) lacked exactly one evidence-linked $kind delta in $view."
            }
            if ($kind -eq 'added') {
                Assert-SoftwareDiffSideEvidence -Delta $deltas[0] -Side 'after' -Snapshot $documents.after
                if ($deltas[0].after.display_name -cne $displayName -or $deltas[0].after.display_version -cne $entry.Version) {
                    throw "Observed MSI ProductCode addition did not retain the expected fixture facts for $($entry.Version)."
                }
            }
            else {
                Assert-SoftwareDiffSideEvidence -Delta $deltas[0] -Side 'before' -Snapshot $documents.before
                if ($deltas[0].before.display_name -cne $displayName -or $deltas[0].before.display_version -cne $entry.Version) {
                    throw "Observed MSI ProductCode removal did not retain the expected fixture facts for $($entry.Version)."
                }
            }
        }
    }
    if ($unknown.Count -gt 0) {
        Write-Output "Observed-session MSI ProductCode registration evidence is unknown or partial for bounded views ($($unknown -join ', ')); MSI API success is not treated as an Uninstall-registry observation."
    }
    else {
        Write-Output 'Observed-session MSI ProductCode transitions were matched to exact current-user Uninstall subkeys and evidence-linked software diff rows.'
    }
}

function Assert-ObservedNtRootRuntimeAssociation {
    param(
        [Parameter(Mandatory = $true)][string] $SessionPath,
        [Parameter(Mandatory = $true)] $Comparison,
        [Parameter(Mandatory = $true)][string] $ExpectedDeltaKind,
        [Parameter(Mandatory = $true)] $Capture,
        [Parameter(Mandatory = $true)][string] $CaptureArtifactHash,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary] $RawPayloadHashes
    )

    $association = $Comparison.root_nt_runtime_association
    if ($null -eq $association -or
        $association.schema -cne 'sideeffect.windows_root_nt_runtime_association' -or
        $association.schema_version -ne 1 -or $association.platform -cne 'windows' -or
        $association.status -cne 'partial' -or $association.capture_completeness -cne 'unknown' -or
        $association.claim -cne 'exact_stable_held_handle_nt_device_path_candidate_only_no_success_ownership_or_causation' -or
        $association.root_diff_status -cne 'complete') {
        throw 'Observation did not provide the bounded partial/unknown v19 NT namespace comparison.'
    }

    $manifestPath = Join-Path $SessionPath 'session.json'
    Assert-UnderPath -Child $manifestPath -Parent $SessionPath -Label 'v19 observation manifest'
    if ((Get-Item -LiteralPath $manifestPath).Length -gt 1048576) {
        throw 'The v19 observation manifest exceeded the bounded acceptance read size.'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema -cne 'sideeffect.audit_session' -or $manifest.schema_version -ne 19) {
        throw 'The NT namespace comparison did not use the v19 observation envelope.'
    }
    $rootSource = @($manifest.sources | Where-Object { $_.role -eq 'selected_root' })
    $runtimeSource = @($manifest.sources | Where-Object { $_.role -eq 'runtime' })
    if ($rootSource.Count -ne 1 -or $runtimeSource.Count -ne 1) {
        throw 'The v19 NT comparison did not have unique selected-root and runtime sources.'
    }
    $namespaceRef = @($rootSource[0].artifacts | Where-Object { $_.kind -eq 'windows_root_namespace_identity' -and $_.path -eq 'root-namespace.windows.json' })
    $beforeRef = @($rootSource[0].artifacts | Where-Object { $_.kind -eq 'selected_root' -and $_.path -eq 'root-snapshot.json' })
    $afterRef = @($rootSource[0].artifacts | Where-Object { $_.kind -eq 'selected_root_after' -and $_.path -eq 'root-snapshot-after.json' })
    $captureRef = @($runtimeSource[0].artifacts | Where-Object { $_.kind -eq 'windows_runtime_capture' -and $_.path -eq 'runtime.windows.json' })
    if ($namespaceRef.Count -ne 1 -or $beforeRef.Count -ne 1 -or $afterRef.Count -ne 1 -or $captureRef.Count -ne 1) {
        throw 'The v19 selected-root namespace or ETW artifact references were missing or ambiguous.'
    }
    if ($namespaceRef[0].schema -cne 'sideeffect.windows_root_namespace_identity' -or
        $namespaceRef[0].schema_version -ne 1 -or
        $beforeRef[0].schema -cne 'sideeffect.selected_root_inventory' -or
        $afterRef[0].schema -cne 'sideeffect.selected_root_inventory') {
        throw 'The v19 root namespace or selected-root artifact references did not use their fixed schemas.'
    }
    $namespacePath = Join-Path $SessionPath 'root-namespace.windows.json'
    Assert-UnderPath -Child $namespacePath -Parent $SessionPath -Label 'root namespace artifact'
    $namespaceItem = Get-Item -LiteralPath $namespacePath
    if ($namespaceItem.Length -gt 1048576 -or $namespaceItem.Length -ne [long]$namespaceRef[0].byte_length) {
        throw 'The root namespace identity artifact exceeded its v19 byte bound or manifest length.'
    }
    $namespaceBytes = [System.IO.File]::ReadAllBytes($namespacePath)
    $namespaceDigest = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($namespaceBytes)).ToLowerInvariant()
    if ($namespaceDigest -cne $namespaceRef[0].sha256 -or
        $association.root_namespace_artifact_sha256 -cne $namespaceDigest -or
        $association.before_root_artifact_sha256 -cne $beforeRef[0].sha256 -or
        $association.after_root_artifact_sha256 -cne $afterRef[0].sha256 -or
        $association.capture_artifact_sha256 -cne $captureRef[0].sha256 -or
        $association.capture_artifact_sha256 -cne $CaptureArtifactHash -or
        $association.capture_document_sha256 -cne $Capture.document_sha256) {
        throw 'The v19 NT comparison artifact digests did not match the session-linked root and ETW evidence.'
    }
    $namespace = [System.Text.Encoding]::UTF8.GetString($namespaceBytes) | ConvertFrom-Json
    if ($namespace.schema -cne 'sideeffect.windows_root_namespace_identity' -or
        $namespace.schema_version -ne 1 -or $namespace.platform -cne 'windows' -or
        $namespace.status -cnotin @('complete', 'partial') -or
        $namespace.before.root_snapshot_sha256 -cne $beforeRef[0].sha256 -or
        $namespace.after.root_snapshot_sha256 -cne $afterRef[0].sha256) {
        throw 'The root namespace identity artifact did not bind both selected-root snapshots.'
    }

    $summary = $association.summary
    $boundedCounts = @(
        $summary.delta_count, $summary.raw_checked_nt_device_event_count,
        $summary.raw_cross_check_rejected_event_count, $summary.opposite_direction_event_count,
        $summary.runtime_observation_rows_omitted_to_limit,
        $summary.candidate_match_count, $summary.ambiguous_candidate_count, $summary.unmatched_delta_count
    )
    foreach ($count in $boundedCounts) {
        if ($count -isnot [ValueType] -or [long]$count -lt 0 -or [long]$count -gt 100000) {
            throw 'The v19 NT comparison contained a missing or out-of-range bounded summary count.'
        }
    }
    $associations = @($association.associations)
    if ($associations.Count -gt 20000 -or $summary.candidate_match_count -ne $associations.Count -or
        $summary.delta_count -ne 1 -or $summary.runtime_observation_rows_omitted_to_limit -gt 50000) {
        throw 'The v19 NT comparison summary did not match its bounded retained association rows.'
    }
    $allowedDiagnostics = @(
        'root_namespace_artifact_reference_mismatch', 'root_namespace_or_identity_changed',
        'root_namespace_identity_unavailable', 'root_nt_device_namespace_unsupported',
        'association_output_limit_reached'
    )
    $diagnostics = @($association.diagnostics)
    if ($diagnostics.Count -gt 8 -or @($diagnostics | Where-Object { $_ -cnotin $allowedDiagnostics }).Count -gt 0) {
        throw 'The v19 NT comparison returned an unknown or unbounded diagnostic.'
    }

    $associationsOmitted = [long]$association.associations_omitted_to_output_limit
    $evidenceReferencesOmitted = [long]$association.evidence_references_omitted_to_output_limit
    if ($associationsOmitted -lt 0 -or $associationsOmitted -gt 20000 -or
        $evidenceReferencesOmitted -lt 0 -or $evidenceReferencesOmitted -gt 50000) {
        throw 'The v19 NT comparison association omission count was outside its output bound.'
    }
    if ($summary.candidate_match_count -eq 0) {
        if ($association.association_status -cne 'insufficient_evidence' -or $associations.Count -ne 0 -or
            ($summary.unmatched_delta_count -eq 0 -and $associationsOmitted -eq 0)) {
            throw 'The v19 NT comparison lacked both an exact candidate and an explicit unmatched-delta count.'
        }
        $namespaceState = if ($namespace.status -eq 'complete' -and $namespace.before.nt_path_utf16le_hex -eq $namespace.after.nt_path_utf16le_hex) {
            'stable_root_namespace'
        }
        else {
            'namespace_partial_or_changed'
        }
        Write-Output "No exact NT device path candidate was retained (status=$($association.association_status); namespace=$namespaceState; raw_checked_nt_events=$($summary.raw_checked_nt_device_event_count); raw_cross_check_rejected=$($summary.raw_cross_check_rejected_event_count); opposite_direction_events=$($summary.opposite_direction_event_count); unmatched_deltas=$($summary.unmatched_delta_count); omitted_rows=$($summary.runtime_observation_rows_omitted_to_limit); association_rows_omitted=$associationsOmitted; evidence_refs_omitted=$evidenceReferencesOmitted; diagnostic_codes=$($diagnostics -join ',')). NT comparison remains partial/unknown and does not establish causation."
        return
    }

    if ($association.association_status -cne 'candidate_match') {
        throw 'The v19 NT comparison retained candidates without reporting candidate_match.'
    }
    $expectedRootHex = [string]$namespace.after.nt_path_utf16le_hex
    if ([string]::IsNullOrWhiteSpace($expectedRootHex) -or
        $namespace.before.status -cne 'observed' -or $namespace.after.status -cne 'observed' -or
        $namespace.before.nt_path_utf16le_hex -cne $namespace.after.nt_path_utf16le_hex -or
        $namespace.before.volume_serial -ne $namespace.after.volume_serial -or
        $namespace.before.file_index -ne $namespace.after.file_index) {
        throw 'An NT candidate was present without stable before/after root-handle identity evidence.'
    }
    if (-not $expectedRootHex.EndsWith('5c00', [System.StringComparison]::Ordinal)) { $expectedRootHex += '5c00' }
    $payloadNameHex = [System.BitConverter]::ToString([System.Text.Encoding]::Unicode.GetBytes('payload.bin')).Replace('-', '').ToLowerInvariant()
    $expectedNtPathHex = $expectedRootHex + $payloadNameHex
    $expectedNtPath = [System.Text.Encoding]::Unicode.GetString([Convert]::FromHexString($expectedNtPathHex))
    $rootDelta = @($Comparison.root_diff.deltas | Where-Object {
        $_.kind -eq $ExpectedDeltaKind -and $_.name -ceq 'payload.bin'
    })
    if ($rootDelta.Count -ne 1) { throw 'The selected-root payload delta was not unique for NT candidate validation.' }
    foreach ($candidate in $associations) {
        if ($candidate.candidate_path_namespace -cne 'nt_device' -or
            $candidate.candidate_path_utf16le_hex -cne $expectedNtPathHex -or
            $candidate.status -notin @('candidate_match', 'ambiguous_candidate_match', 'partial_candidate_match') -or
            $candidate.delta_kind -cne $ExpectedDeltaKind -or
            $candidate.delta_name_identity_hex -cne $rootDelta[0].name_identity_hex -or
            $candidate.etw_operation -cne 'create_name' -or @($candidate.runtime_evidence).Count -eq 0) {
            throw 'The v19 NT candidate did not exactly match the expected payload delta and NT device path.'
        }
        foreach ($evidence in @($candidate.runtime_evidence)) {
            if ($evidence.capture_document_sha256 -cne $Capture.document_sha256 -or
                $evidence.etw_operation -cne 'create_name' -or $evidence.json_pointer -notmatch '^/events/([0-9]+)$') {
                throw 'An NT candidate evidence reference did not bind to the v19 capture document and create-name operation.'
            }
            $eventIndex = [int]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
            if ($eventIndex -lt 0 -or $eventIndex -ge $Capture.events.Count) {
                throw 'An NT candidate evidence pointer was outside the capture event array.'
            }
            $event = $Capture.events[$eventIndex]
            if (-not $RawPayloadHashes.Contains([string]$event.record_ordinal) -or
                $event.record_ordinal -ne $evidence.record_ordinal -or
                $RawPayloadHashes[[string]$event.record_ordinal] -cne $evidence.raw_payload_sha256 -or
                $event.observation_decoding.observation.activity.observation.path -cne $expectedNtPath) {
                throw 'An NT candidate evidence pointer did not resolve to the exact raw-verified NT payload path.'
            }
        }
    }
    Write-Output "Verified $($summary.candidate_match_count) exact NT device path candidate(s) against the held-root namespace, selected-root delta, and raw-checked ETW evidence; this is candidate evidence only and does not establish success, ownership, or causation."
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
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The hosted runner token is not already administrative; the MSI acceptance will not elevate.'
}
foreach ($commandName in @('Get-ScheduledTask', 'New-ScheduledTask', 'New-ScheduledTaskAction', 'New-ScheduledTaskPrincipal', 'New-ScheduledTaskSettingsSet', 'New-ScheduledTaskTrigger', 'Register-ScheduledTask', 'Unregister-ScheduledTask')) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required Task Scheduler command $commandName is unavailable."
    }
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
$script:ObservationFixtureCleanupErrors = [System.Collections.Generic.List[string]]::new()

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
    $payloadV1Sha256 = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($payloadV1)).ToLowerInvariant()
    $payloadV2Sha256 = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($payloadV2)).ToLowerInvariant()
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
    $observationV1Path = Join-Path $script:TestRoot 'observed-install-v1'
    $observationV2Path = Join-Path $script:TestRoot 'observed-upgrade-v2'
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
    Invoke-ObservedMsiInstall -MsiPath $msiV1 -InstallRoot $script:InstallRoot -LogPath (Join-Path $script:TestRoot 'install-v1.log') -SessionPath $observationV1Path -ExpectedDeltaKind 'added' -ExpectedPayloadSha256 $payloadV1Sha256 -ExpectedProductCode $productCodeV1 -Description 'Observed v1 MSI install'
    Assert-ProductVersion -ProductCode $productCodeV1 -Version '1.0.0' -LogPath (Join-Path $script:TestRoot 'install-v1.log') -PayloadPath (Join-Path $script:InstallRoot 'payload.bin')
    Assert-InstalledPayload -ProductCode $productCodeV1 -LogPath (Join-Path $script:TestRoot 'install-v1.log') -PayloadPath (Join-Path $script:InstallRoot 'payload.bin') -ExpectedBytes $payloadV1
    $snapshotV1 = Get-InventorySnapshot -Path $snapshotV1Path
    $entryV1 = Get-PayloadEntry $snapshotV1
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

    Invoke-ObservedMsiInstall -MsiPath $msiV2 -InstallRoot $script:InstallRoot -LogPath (Join-Path $script:TestRoot 'update-v2.log') -SessionPath $observationV2Path -ExpectedDeltaKind 'changed' -ExpectedPayloadSha256 $payloadV2Sha256 -ExpectedPreviousPayloadSha256 $payloadV1Sha256 -ExpectedProductCode $productCodeV2 -ExpectedPreviousProductCode $productCodeV1 -Description 'Observed v2 MSI major upgrade'
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
        foreach ($cleanupError in $script:ObservationFixtureCleanupErrors) {
            $cleanupErrors.Add($cleanupError)
        }
        $registeredFixtureRemains = $false
        foreach ($productCode in @($productCodeV2, $productCodeV1)) {
            if ($null -ne (Get-ProductRegistration -ProductCode $productCode)) {
                $registeredFixtureRemains = $true
            }
        }
        if ($createdTestRoot -and (Test-Path -LiteralPath $script:TestRoot)) {
            if ($registeredFixtureRemains -or $script:ObservationFixtureCleanupErrors.Count -gt 0) {
                if ($registeredFixtureRemains) {
                    Write-Warning "Fixture files were retained because an MSI product remains registered: $script:TestRoot"
                    $cleanupErrors.Add("Fixture MSI registration remains; retained fixture files at $script:TestRoot")
                }
                else {
                    Write-Warning "Startup fixture cleanup was incomplete; retained test evidence at $script:TestRoot"
                }
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
