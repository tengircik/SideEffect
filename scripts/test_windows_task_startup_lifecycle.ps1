[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $SideEffectPath
)

$ErrorActionPreference = 'Stop'
$script:TestFailure = $null
$script:CleanupErrors = [System.Collections.Generic.List[string]]::new()
$script:TaskCreated = $false
$script:FixtureRoot = $null
$script:TaskName = $null
$script:TaskPath = $null

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

function Get-RootFixtureTask {
    $tasks = @(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop)
    $matches = @($tasks | Where-Object { $_.TaskName -ceq $script:TaskName })
    if ($matches.Count -gt 1) {
        throw 'More than one root task matched the generated fixture name.'
    }
    if ($matches.Count -eq 0) {
        return $null
    }
    return $matches[0]
}

function Test-FixtureTaskPresent {
    return ($null -ne (Get-RootFixtureTask))
}

function Remove-FixtureTaskAndWait {
    if (Test-FixtureTaskPresent) {
        Unregister-ScheduledTask -TaskName $script:TaskName -TaskPath '\' -Confirm:$false -ErrorAction Stop | Out-Null
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ((Test-FixtureTaskPresent) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 100
    }
    if (Test-FixtureTaskPresent) {
        throw 'Task Scheduler did not remove the exact fixture task within the bounded wait.'
    }
}

function Get-StartupDocument {
    param([Parameter(Mandatory = $true)][string] $Name)

    $path = Join-Path $script:FixtureRoot $Name
    Assert-UnderPath -Child $path -Parent $script:FixtureRoot -Label 'startup inventory output'
    $null = & $script:SideEffectPath inventory startup --output $path 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -notin @(0, 2)) {
        throw "SideEffect startup inventory failed with exit code ${exitCode}."
    }
    $item = Get-Item -LiteralPath $path
    if ($item.Length -gt 64MB) {
        throw 'SideEffect startup inventory exceeded the acceptance read bound.'
    }
    $document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($document.schema -cne 'sideeffect.windows_startup_inventory' -or $document.schema_version -ne 10) {
        throw 'SideEffect emitted an unexpected startup inventory contract.'
    }
    if (($document.status -ceq 'complete' -and $exitCode -ne 0) -or
        ($document.status -ceq 'partial' -and $exitCode -ne 2) -or
        $document.status -cnotin @('complete', 'partial')) {
        throw 'SideEffect startup inventory status did not match its documented CLI exit code.'
    }
    Assert-TaskSourceComparable -Document $document -Label $Name
    return [pscustomobject]@{ Path = $path; Document = $document }
}

function Assert-TaskSourceComparable {
    param(
        [Parameter(Mandatory = $true)] $Document,
        [Parameter(Mandatory = $true)][string] $Label
    )

    $sources = @($Document.sources | Where-Object { $_.id -ceq 'scheduled_task_triggers' })
    if ($sources.Count -ne 1) {
        throw "Startup snapshot $Label did not contain exactly one Task Scheduler source."
    }
    if ($sources[0].status -cne 'complete') {
        $codes = @($sources[0].diagnostics | Select-Object -First 8 | ForEach-Object {
            if ($_.code -is [string] -and $_.code.Length -le 128) { $_.code }
        }) -join ','
        if (-not $codes) { $codes = 'none' }
        throw "Task Scheduler source for $Label is $($sources[0].status); diagnostic_codes=$codes. The task lifecycle remains unknown."
    }
}

function Invoke-StartupDiff {
    param(
        [Parameter(Mandatory = $true)] $Before,
        [Parameter(Mandatory = $true)] $After
    )

    $output = & $script:SideEffectPath explain --inventory-diff $Before.Path $After.Path 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -notin @(0, 2)) {
        throw "SideEffect startup diff failed with exit code ${exitCode}."
    }
    $report = ($output -join [Environment]::NewLine) | ConvertFrom-Json
    if ($report.schema -cne 'sideeffect.startup_inventory_diff' -or
        ($report.status -ceq 'complete' -and $exitCode -ne 0) -or
        ($report.status -ceq 'partial' -and $exitCode -ne 2) -or
        $report.status -cnotin @('complete', 'partial')) {
        throw 'SideEffect startup diff status did not match its documented CLI exit code.'
    }
    Assert-TaskSourceComparable -Document $Before.Document -Label 'before diff'
    Assert-TaskSourceComparable -Document $After.Document -Label 'after diff'
    return $report
}

function Get-FixtureTaskRow {
    param([Parameter(Mandatory = $true)] $Document)

    $matches = @($Document.scheduled_task_entries | Where-Object {
        $_.task_path -ceq $script:TaskPath -and $_.trigger_type -ceq 'logon'
    })
    if ($matches.Count -ne 1) {
        throw "Expected exactly one fixture logon-trigger row, observed $($matches.Count)."
    }
    $task = $matches[0]
    if ($task.task_enabled -ne $false -or $task.trigger_enabled -ne $false) {
        throw 'The fixture task and its supported logon trigger must both remain disabled.'
    }
    if ($task.startup_state.configured -cne 'present' -or
        $task.startup_state.effective.status -cne 'unknown' -or
        $task.startup_state.observed.status -cne 'unknown') {
        throw 'The task row did not preserve configured/effective/observed distinctions.'
    }
    if ($task.evidence.source -cne 'Task Scheduler IRegisteredTask/ITaskDefinition/ITrigger' -or
        -not ($task.evidence.task_index -is [ValueType]) -or -not ($task.evidence.trigger_index -is [ValueType])) {
        throw 'The fixture trigger row did not carry its exact Task Scheduler source indexes.'
    }
    $index = [Array]::IndexOf($Document.scheduled_task_entries, $task)
    if ($index -lt 0 -or $task.evidence.trigger_index -ne 0) {
        throw 'The fixture trigger evidence index did not identify the expected first trigger; inventory row linkage is checked by the emitted row pointer.'
    }
    return [pscustomobject]@{ Row = $task; Index = $index }
}

function Get-FixtureActionRow {
    param(
        [Parameter(Mandatory = $true)] $Document,
        [Parameter(Mandatory = $true)][string] $ExpectedPath,
        [Parameter(Mandatory = $true)][long] $ExpectedTaskIndex
    )

    $matches = @($Document.scheduled_task_actions | Where-Object {
        $_.task_path -ceq $script:TaskPath -and $_.action_index -eq 0
    })
    if ($matches.Count -ne 1) {
        throw "Expected exactly one fixture Exec action row, observed $($matches.Count)."
    }
    $action = $matches[0]
    if ($action.action_type -cne 'exec' -or $action.status -cne 'observed' -or
        $action.executable_path -cne $ExpectedPath -or (Test-Path -LiteralPath $ExpectedPath)) {
        throw 'The fixture action is not the expected inert, nonexistent executable path.'
    }
    if ($action.startup_state.configured -cne 'present' -or
        $action.startup_state.effective.status -cne 'unknown' -or
        $action.startup_state.observed.status -cne 'unknown') {
        throw 'The action row did not preserve configured/effective/observed distinctions.'
    }
    if ($action.evidence.source -cne 'Task Scheduler IActionCollection/IExecAction' -or
        $action.evidence.task_index -ne $ExpectedTaskIndex -or
        $action.evidence.action_index -ne 0) {
        throw 'The fixture Exec action row did not carry its indexed source evidence.'
    }
    $index = [Array]::IndexOf($Document.scheduled_task_actions, $action)
    if ($index -lt 0) {
        throw 'The fixture action evidence index did not identify an exact inventory row.'
    }
    return [pscustomobject]@{ Row = $action; Index = $index }
}

function Assert-TaskDelta {
    param(
        [Parameter(Mandatory = $true)] $Report,
        [Parameter(Mandatory = $true)][string] $Category,
        [Parameter(Mandatory = $true)][string] $Kind,
        [Parameter(Mandatory = $true)][string] $Pointer,
        [Parameter(Mandatory = $true)][ValidateSet('before', 'after')][string] $EvidenceSide,
        [Parameter()][string] $ExpectedChangedField
    )

    $matches = @($Report.deltas | Where-Object {
        $_.category -ceq $Category -and $_.kind -ceq $Kind -and
        $_.PSObject.Properties[$EvidenceSide].Value.references -contains $Pointer
    })
    if ($matches.Count -ne 1) {
        throw "Expected one $Kind $Category delta linked to $Pointer; found $($matches.Count)."
    }
    if ($ExpectedChangedField -and $matches[0].changed_fields -notcontains $ExpectedChangedField) {
        throw "The $Category delta did not include the expected field $ExpectedChangedField."
    }
}

function Assert-TaskPresenceOutcome {
    param(
        [Parameter(Mandatory = $true)] $Report,
        [Parameter(Mandatory = $true)][string] $Kind,
        [Parameter(Mandatory = $true)][string] $Category,
        [Parameter(Mandatory = $true)][int] $RowIndex,
        [Parameter(Mandatory = $true)][ValidateSet('before', 'after')][string] $EvidenceSide
    )

    $pointer = if ($Category -ceq 'scheduled_task_trigger') {
        "/scheduled_task_entries/$RowIndex"
    } else {
        "/scheduled_task_actions/$RowIndex"
    }
    $matches = @($Report.deltas | Where-Object {
        $_.category -ceq $Category -and $_.kind -ceq $Kind -and
        $_.PSObject.Properties[$EvidenceSide].Value.references -contains $pointer
    })
    if ($Report.status -ceq 'complete') {
        if ($matches.Count -ne 1) {
            throw "Complete startup comparison did not contain one $Kind $Category delta linked to $pointer."
        }
        return
    }
    if ($matches.Count -ne 0) {
        throw "Partial startup comparison made an unsupported $Kind presence claim for $pointer."
    }
    if ($Report.counts.unmatched_rows_suppressed_for_incomplete_source -lt 1) {
        throw "Partial startup comparison did not report unmatched-row suppression for $pointer."
    }
    Write-Output "Startup comparison is partial; $Kind presence for the exact fixture row was conservatively suppressed."
}

# Task Scheduler writes are confined to disposable GitHub-hosted CI.
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted') {
    throw 'Windows Task Scheduler acceptance is restricted to disposable GitHub-hosted runners.'
}
if (-not $env:RUNNER_TEMP) {
    throw 'RUNNER_TEMP is required for the isolated task fixture and inventory artifacts.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The hosted runner token is not already administrative; the script will not elevate.'
}

$script:SideEffectPath = (Resolve-Path -LiteralPath $SideEffectPath).Path
foreach ($commandName in @('Get-ScheduledTask', 'New-ScheduledTask', 'New-ScheduledTaskAction', 'New-ScheduledTaskPrincipal', 'New-ScheduledTaskSettingsSet', 'New-ScheduledTaskTrigger', 'Register-ScheduledTask', 'Set-ScheduledTask', 'Unregister-ScheduledTask')) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required Task Scheduler command $commandName is unavailable."
    }
}
if (-not (Test-Path -LiteralPath $script:SideEffectPath -PathType Leaf)) {
    throw 'SideEffect CLI is missing.'
}

$runnerTemp = [System.IO.Path]::GetFullPath($env:RUNNER_TEMP)
$guid = [Guid]::NewGuid().ToString('N')
$script:FixtureRoot = Join-Path $runnerTemp "sideeffect-task-startup-$guid"
$script:TaskName = "SideEffectR5Task-$guid"
$script:TaskPath = "\$($script:TaskName)"
$initialInertImage = Join-Path $script:FixtureRoot "intentionally-absent-$guid.exe"
$updatedInertImage = Join-Path $script:FixtureRoot "intentionally-absent-updated-$guid.exe"
Assert-UnderPath -Child $script:FixtureRoot -Parent $runnerTemp -Label 'Task Scheduler acceptance fixture'
if (Test-Path -LiteralPath $script:FixtureRoot) {
    throw 'The generated fixture directory already exists; refusing to reuse it.'
}
if ((Test-Path -LiteralPath $initialInertImage) -or (Test-Path -LiteralPath $updatedInertImage)) {
    throw 'A generated inert task action image unexpectedly exists.'
}
if (Get-RootFixtureTask) {
    throw 'The generated Task Scheduler name already exists; refusing to alter it.'
}

try {
    [System.IO.Directory]::CreateDirectory($script:FixtureRoot) | Out-Null
    $before = Get-StartupDocument -Name 'before.json'
    if (@($before.Document.scheduled_task_entries | Where-Object { $_.task_path -ceq $script:TaskPath }).Count -ne 0 -or
        @($before.Document.scheduled_task_actions | Where-Object { $_.task_path -ceq $script:TaskPath }).Count -ne 0) {
        throw 'The generated task identity was already present in the baseline; refusing to compare it.'
    }

    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
    $trigger.Enabled = $false
    $action = New-ScheduledTaskAction -Execute $initialInertImage
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    $disabledSettings = New-ScheduledTaskSettingsSet -Disable -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
    $definition = New-ScheduledTask -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $disabledSettings
    Register-ScheduledTask -TaskName $script:TaskName -InputObject $definition -ErrorAction Stop | Out-Null
    $script:TaskCreated = $true

    $created = Get-StartupDocument -Name 'created.json'
    $createdTask = Get-FixtureTaskRow -Document $created.Document
    $createdAction = Get-FixtureActionRow -Document $created.Document -ExpectedPath $initialInertImage -ExpectedTaskIndex $createdTask.Row.evidence.task_index
    $createdDiff = Invoke-StartupDiff -Before $before -After $created
    Assert-TaskPresenceOutcome -Report $createdDiff -Kind 'observed_after_only' -Category 'scheduled_task_trigger' -RowIndex $createdTask.Index -EvidenceSide 'after'
    Assert-TaskPresenceOutcome -Report $createdDiff -Kind 'observed_after_only' -Category 'scheduled_task_action_sequence' -RowIndex $createdAction.Index -EvidenceSide 'after'

    $updatedAction = New-ScheduledTaskAction -Execute $updatedInertImage
    Set-ScheduledTask -TaskName $script:TaskName -TaskPath '\' -Action $updatedAction -ErrorAction Stop | Out-Null
    $changed = Get-StartupDocument -Name 'changed.json'
    $changedTask = Get-FixtureTaskRow -Document $changed.Document
    $changedAction = Get-FixtureActionRow -Document $changed.Document -ExpectedPath $updatedInertImage -ExpectedTaskIndex $changedTask.Row.evidence.task_index
    $changedDiff = Invoke-StartupDiff -Before $created -After $changed
    Assert-TaskDelta -Report $changedDiff -Category 'scheduled_task_action_sequence' -Kind 'changed' -Pointer "/scheduled_task_actions/$($createdAction.Index)" -EvidenceSide 'before' -ExpectedChangedField 'action_sequence'
    Assert-TaskDelta -Report $changedDiff -Category 'scheduled_task_action_sequence' -Kind 'changed' -Pointer "/scheduled_task_actions/$($changedAction.Index)" -EvidenceSide 'after' -ExpectedChangedField 'action_sequence'

    Remove-FixtureTaskAndWait
    $script:TaskCreated = $false
    $removed = Get-StartupDocument -Name 'removed.json'
    if (@($removed.Document.scheduled_task_entries | Where-Object { $_.task_path -ceq $script:TaskPath }).Count -ne 0 -or
        @($removed.Document.scheduled_task_actions | Where-Object { $_.task_path -ceq $script:TaskPath }).Count -ne 0) {
        throw 'Fixture task remained visible after exact Task Scheduler deletion.'
    }
    $removedDiff = Invoke-StartupDiff -Before $changed -After $removed
    Assert-TaskPresenceOutcome -Report $removedDiff -Kind 'observed_before_only' -Category 'scheduled_task_trigger' -RowIndex $changedTask.Index -EvidenceSide 'before'
    Assert-TaskPresenceOutcome -Report $removedDiff -Kind 'observed_before_only' -Category 'scheduled_task_action_sequence' -RowIndex $changedAction.Index -EvidenceSide 'before'

    Write-Output 'Hosted Task Scheduler lifecycle acceptance passed: disabled task configuration add/change/remove checks preserve exact source evidence.'
}
catch {
    $script:TestFailure = $_.Exception
}
finally {
    if ($script:TaskCreated) {
        try {
            Remove-FixtureTaskAndWait
            $script:TaskCreated = $false
        }
        catch {
            $script:CleanupErrors.Add("Exact fixture task cleanup failed: $($_.Exception.Message)")
        }
    }
    if (Test-Path -LiteralPath $script:FixtureRoot) {
        try {
            Assert-UnderPath -Child $script:FixtureRoot -Parent $runnerTemp -Label 'Task Scheduler fixture cleanup target'
            if ([System.IO.Path]::GetFullPath($script:FixtureRoot) -ceq [System.IO.Path]::GetFullPath($runnerTemp)) {
                throw 'Refusing to remove RUNNER_TEMP as the Task Scheduler fixture directory.'
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
    throw "Task Scheduler startup lifecycle passed, but fixture cleanup failed: $($script:CleanupErrors -join '; ')"
}
exit 0
