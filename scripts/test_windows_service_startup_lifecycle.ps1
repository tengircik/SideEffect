[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $SideEffectPath
)

$ErrorActionPreference = 'Stop'
$script:TestFailure = $null
$script:CleanupErrors = [System.Collections.Generic.List[string]]::new()
$script:ServiceCreated = $false
$script:FixtureRoot = $null
$script:ServiceName = $null

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

function Invoke-Sc {
    param(
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $Description
    )

    $output = & $script:ScExe @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Description failed with sc.exe exit code ${exitCode}: $($output -join ' ')"
    }
}

function Test-FixtureServiceKeyPresent {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:RegistryServicePath)
    if ($null -eq $key) {
        return $false
    }
    $key.Dispose()
    return $true
}

function Remove-FixtureServiceAndWait {
    if (Test-FixtureServiceKeyPresent) {
        $output = & $script:ScExe delete $script:ServiceName 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0 -and (Test-FixtureServiceKeyPresent)) {
            throw "sc.exe delete failed with exit code ${exitCode}: $($output -join ' ')"
        }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ((Test-FixtureServiceKeyPresent) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 100
    }
    if (Test-FixtureServiceKeyPresent) {
        throw 'SCM did not remove the exact fixture service key within the bounded wait.'
    }
}

function Get-StartupDocument {
    param([Parameter(Mandatory = $true)][string] $Name)

    $path = Join-Path $script:FixtureRoot $Name
    Assert-UnderPath -Child $path -Parent $script:FixtureRoot -Label 'startup inventory output'
    $result = & $script:SideEffectPath inventory startup --output $path 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "SideEffect startup inventory returned exit code ${exitCode}; complete lifecycle evidence is required."
    }
    $item = Get-Item -LiteralPath $path
    if ($item.Length -gt 64MB) {
        throw 'SideEffect startup inventory exceeded the acceptance read bound.'
    }
    $document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($document.schema -cne 'sideeffect.windows_startup_inventory' -or $document.schema_version -ne 10) {
        throw 'SideEffect emitted an unexpected startup inventory contract.'
    }
    if ($document.status -cne 'complete') {
        throw 'SideEffect startup inventory was partial; the lifecycle result remains unknown.'
    }
    foreach ($source in $document.sources) {
        if ($source.status -cnotin @('complete', 'not_present')) {
            throw "Startup source $($source.id) was $($source.status); presence comparisons are not accepted."
        }
    }
    return [pscustomobject]@{ Path = $path; Document = $document }
}

function Invoke-StartupDiff {
    param(
        [Parameter(Mandatory = $true)] $Before,
        [Parameter(Mandatory = $true)] $After
    )

    $output = & $script:SideEffectPath explain --inventory-diff $Before.Path $After.Path 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "SideEffect startup diff returned exit code ${exitCode}; complete lifecycle evidence is required."
    }
    $text = $output -join [Environment]::NewLine
    $report = $text | ConvertFrom-Json
    if ($report.schema -cne 'sideeffect.startup_inventory_diff' -or $report.status -cne 'complete') {
        throw 'SideEffect did not produce a complete startup comparison.'
    }
    return $report
}

function Get-FixtureService {
    param([Parameter(Mandatory = $true)] $Document)

    $matches = @($Document.service_entries | Where-Object { $_.service_name -ceq $script:ServiceName })
    if ($matches.Count -ne 1) {
        throw "Expected exactly one fixture service row, observed $($matches.Count)."
    }
    $service = $matches[0]
    if ($service.evidence.source -cne 'EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W') {
        throw 'The fixture service row did not carry the expected SCM source evidence.'
    }
    if ($service.startup_state.configured -cne 'present' -or
        $service.startup_state.effective.status -cne 'unknown' -or
        $service.startup_state.observed.status -cne 'unknown') {
        throw 'The SCM configuration row did not preserve configured/effective/observed distinctions.'
    }
    if ($service.service_observation.status -cne 'known' -or $service.service_observation.state -cne 'stopped') {
        throw 'SCM did not report the fixture service as stopped.'
    }
    $serviceIndex = [Array]::IndexOf($Document.service_entries, $service)
    if ($serviceIndex -lt 0 -or $service.evidence.service_index -ne $serviceIndex) {
        throw 'The fixture SCM source index did not match its exact inventory row.'
    }
    return $service
}

function Assert-FixtureDelta {
    param(
        [Parameter(Mandatory = $true)] $Report,
        [Parameter(Mandatory = $true)][string] $Kind,
        [Parameter()][AllowEmptyString()][string] $ExpectedChangedField = '',
        [Parameter()][int] $BeforeIndex = -1,
        [Parameter()][int] $AfterIndex = -1
    )

    $matches = @($Report.deltas | Where-Object {
        $_.category -ceq 'service_configuration' -and
        $_.kind -ceq $Kind -and
        (($BeforeIndex -lt 0 -and $null -eq $_.before) -or
         ($BeforeIndex -ge 0 -and $_.before.references -contains "/service_entries/$BeforeIndex")) -and
        (($AfterIndex -lt 0 -and $null -eq $_.after) -or
         ($AfterIndex -ge 0 -and $_.after.references -contains "/service_entries/$AfterIndex"))
    })
    if ($matches.Count -ne 1) {
        throw "Expected one $Kind service delta linked to the fixture row; found $($matches.Count)."
    }
    $delta = $matches[0]
    if ($ExpectedChangedField -and $delta.changed_fields -notcontains $ExpectedChangedField) {
        throw "Service delta did not include the expected changed field $ExpectedChangedField."
    }
}

# This script mutates SCM state and is intentionally unusable outside disposable hosted CI.
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted') {
    throw 'Windows service startup acceptance is restricted to disposable GitHub-hosted runners.'
}
if (-not $env:RUNNER_TEMP) {
    throw 'RUNNER_TEMP is required for the isolated service fixture and inventory artifacts.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The hosted runner token is not already administrative; the script will not elevate.'
}

$script:SideEffectPath = (Resolve-Path -LiteralPath $SideEffectPath).Path
$script:ScExe = Join-Path $env:SystemRoot 'System32\sc.exe'
if (-not (Test-Path -LiteralPath $script:SideEffectPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $script:ScExe -PathType Leaf)) {
    throw 'SideEffect CLI or the Windows service-control utility is missing.'
}

$runnerTemp = [System.IO.Path]::GetFullPath($env:RUNNER_TEMP)
$guid = [Guid]::NewGuid().ToString('N')
$script:FixtureRoot = Join-Path $runnerTemp "sideeffect-service-startup-$guid"
$script:ServiceName = "SideEffectR5-$guid"
$displayName = "SideEffect R5 disabled fixture $guid"
$updatedDisplayName = "SideEffect R5 updated disabled fixture $guid"
$inertBinaryPath = Join-Path $script:FixtureRoot "intentionally-absent-$guid.exe"
$registryServicePath = "SYSTEM\CurrentControlSet\Services\$($script:ServiceName)"
$script:RegistryServicePath = $registryServicePath
$registryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($registryServicePath)
if ($null -ne $registryKey) {
    $registryKey.Dispose()
    throw 'The generated service name already exists; refusing to alter it.'
}
if (Test-Path -LiteralPath $inertBinaryPath) {
    throw 'The generated inert service image unexpectedly exists.'
}
if (Test-Path -LiteralPath $script:FixtureRoot) {
    throw 'The generated fixture directory already exists; refusing to reuse it.'
}
Assert-UnderPath -Child $script:FixtureRoot -Parent $runnerTemp -Label 'service acceptance fixture'

try {
    [System.IO.Directory]::CreateDirectory($script:FixtureRoot) | Out-Null
    $before = Get-StartupDocument -Name 'before.json'
    if (@($before.Document.service_entries | Where-Object { $_.service_name -ceq $script:ServiceName }).Count -ne 0) {
        throw 'Generated service name was already present in the baseline; refusing to compare it.'
    }

    $quotedInertBinaryPath = '"' + $inertBinaryPath + '"'
    Invoke-Sc -Arguments @('create', $script:ServiceName, 'binPath=', $quotedInertBinaryPath, 'start=', 'disabled', 'DisplayName=', $displayName) -Description 'Create disabled inert fixture service'
    $script:ServiceCreated = $true
    $created = Get-StartupDocument -Name 'created.json'
    $createdService = Get-FixtureService -Document $created.Document
    if ($createdService.start_type -cne 'disabled' -or $createdService.start_type_code -ne 4) {
        throw 'Fixture service was not observed as disabled after creation.'
    }
    if ($createdService.binary_path -cne $quotedInertBinaryPath -or (Test-Path -LiteralPath $inertBinaryPath)) {
        throw 'SCM inventory did not preserve the inert nonexistent binary path exactly.'
    }
    $createdIndex = [Array]::IndexOf($created.Document.service_entries, $createdService)
    $addDiff = Invoke-StartupDiff -Before $before -After $created
    Assert-FixtureDelta -Report $addDiff -Kind 'observed_after_only' -ExpectedChangedField '' -BeforeIndex -1 -AfterIndex $createdIndex

    Invoke-Sc -Arguments @('config', $script:ServiceName, 'DisplayName=', $updatedDisplayName) -Description 'Change inert fixture display name'
    $changed = Get-StartupDocument -Name 'changed.json'
    $changedService = Get-FixtureService -Document $changed.Document
    if ($changedService.display_name -cne $updatedDisplayName -or
        $changedService.start_type -cne 'disabled' -or
        $changedService.start_type_code -ne 4) {
        throw 'SCM did not report the expected static display-name change with service still disabled.'
    }
    $changedIndex = [Array]::IndexOf($changed.Document.service_entries, $changedService)
    $changeDiff = Invoke-StartupDiff -Before $created -After $changed
    Assert-FixtureDelta -Report $changeDiff -Kind 'changed' -ExpectedChangedField 'display_name' -BeforeIndex $createdIndex -AfterIndex $changedIndex

    Remove-FixtureServiceAndWait
    $script:ServiceCreated = $false
    $removed = Get-StartupDocument -Name 'removed.json'
    if (@($removed.Document.service_entries | Where-Object { $_.service_name -ceq $script:ServiceName }).Count -ne 0) {
        throw 'Fixture service remained visible after its SCM deletion completed.'
    }
    $removeDiff = Invoke-StartupDiff -Before $changed -After $removed
    Assert-FixtureDelta -Report $removeDiff -Kind 'observed_before_only' -ExpectedChangedField '' -BeforeIndex $changedIndex -AfterIndex -1

    Write-Output 'Hosted SCM startup lifecycle acceptance passed: disabled fixture add/change/remove deltas link to SideEffect source rows.'
}
catch {
    $script:TestFailure = $_.Exception
}
finally {
    if ($script:ServiceCreated) {
        try {
            Remove-FixtureServiceAndWait
            $script:ServiceCreated = $false
        }
        catch {
            $script:CleanupErrors.Add("Exact fixture service cleanup failed: $($_.Exception.Message)")
        }
    }
    if (Test-Path -LiteralPath $script:FixtureRoot) {
        try {
            Assert-UnderPath -Child $script:FixtureRoot -Parent $runnerTemp -Label 'service acceptance cleanup target'
            if ([System.IO.Path]::GetFullPath($script:FixtureRoot) -ceq [System.IO.Path]::GetFullPath($runnerTemp)) {
                throw 'Refusing to remove RUNNER_TEMP as the service fixture directory.'
            }
            Remove-Item -LiteralPath $script:FixtureRoot -Recurse -Force
        }
        catch {
            $script:CleanupErrors.Add("Fixture output cleanup failed: $($_.Exception.Message)")
        }
    }
}

if ($null -ne $script:TestFailure) {
    throw $script:TestFailure
}
if ($script:CleanupErrors.Count -gt 0) {
    throw "Service startup lifecycle passed, but fixture cleanup failed: $($script:CleanupErrors -join '; ')"
}
exit 0
