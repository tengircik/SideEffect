[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $ServiceName,
    [Parameter(Mandatory = $true)][string] $TaskName,
    [Parameter(Mandatory = $true)][string] $InertImagePath,
    [Parameter(Mandatory = $true)][string] $MsiexecPath,
    [Parameter(Mandatory = $true)][string] $ArgumentsJsonBase64,
    [Parameter(Mandatory = $true)][string] $ExitCodePath,
    [Parameter(Mandatory = $true)][string] $OwnershipMarkerPath
)

$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw 'The MSI startup-observation wrapper is restricted to a disposable GitHub-hosted runner.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The existing hosted-runner token is not administrative; the wrapper will not elevate.'
}
if ($ServiceName -cnotmatch '^SeR5-[0-9a-f]{32}$' -or $TaskName -cnotmatch '^SideEffectR5Msi-[0-9a-f]{32}$' -or
    [IO.Path]::GetFileName($InertImagePath) -cnotmatch '^intentionally-absent-[0-9a-f]{32}\.exe$') {
    throw 'Fixture identities must be unique, generated GUID names from the fixed parent harness.'
}
$guid = $ServiceName.Substring('SeR5-'.Length)
if ($TaskName -cne "SideEffectR5Msi-$guid" -or
    [IO.Path]::GetFileName($InertImagePath) -cne "intentionally-absent-$guid.exe" -or
    [IO.Path]::GetFileName($ExitCodePath) -cne "msiexec-exit-$guid.txt" -or
    [IO.Path]::GetFileName($OwnershipMarkerPath) -cne "startup-fixture-owner-$guid.json") {
    throw 'The fixture names and bounded sidecars must share the exact generated GUID identity.'
}

$runnerTemp = [System.IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
foreach ($path in @($InertImagePath, $ExitCodePath, $OwnershipMarkerPath)) {
    $full = [IO.Path]::GetFullPath($path)
    if (-not $full.StartsWith($runnerTemp, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Wrapper paths must remain under RUNNER_TEMP.'
    }
}
if (-not (Test-Path -LiteralPath $OwnershipMarkerPath -PathType Leaf) -or
    (Get-Item -LiteralPath $OwnershipMarkerPath).Length -gt 4096) {
    throw 'The parent harness ownership marker is missing or exceeded its bound.'
}
$ownership = Get-Content -LiteralPath $OwnershipMarkerPath -Raw | ConvertFrom-Json
if ($ownership.service_name -cne $ServiceName -or $ownership.task_name -cne $TaskName) {
    throw 'The parent harness ownership marker did not match the exact fixture identities.'
}
$expectedMsiexec = [IO.Path]::GetFullPath((Join-Path $env:WINDIR 'System32\msiexec.exe'))
if ([IO.Path]::GetFullPath($MsiexecPath) -cne $expectedMsiexec -or $ArgumentsJsonBase64.Length -gt 65536) {
    throw 'The wrapper accepts only the fixed system msiexec executable and a bounded argument vector.'
}
if (Test-Path -LiteralPath $InertImagePath) {
    throw 'The generated inert fixture image unexpectedly exists.'
}
if (Test-Path -LiteralPath $ExitCodePath) {
    throw 'The generated child exit-code sidecar already exists.'
}
if (Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object { $_.TaskName -ceq $TaskName }) {
    throw 'The generated Task Scheduler identity already exists; refusing to alter it.'
}

$sc = Join-Path $env:WINDIR 'System32\sc.exe'
$query = Start-Process -FilePath $sc -ArgumentList @('query', $ServiceName) -Wait -PassThru -NoNewWindow
if ($query.ExitCode -ne 1060) {
    throw 'The generated service identity already exists or SCM could not verify its absence.'
}

$msiExitCode = $null
$createService = [Diagnostics.ProcessStartInfo]::new()
$createService.FileName = $sc
$createService.UseShellExecute = $false
foreach ($argument in @(
    'create', $ServiceName,
    'binPath=', "`"$([IO.Path]::GetFullPath($InertImagePath))`"",
    'start=', 'disabled', 'type=', 'own', 'DisplayName=', $ServiceName
)) { [void]$createService.ArgumentList.Add($argument) }
$serviceProcess = [Diagnostics.Process]::Start($createService)
$serviceProcess.WaitForExit()
if ($serviceProcess.ExitCode -ne 0) {
    throw "SCM did not create the disabled synthetic service (exit $($serviceProcess.ExitCode))."
}

$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$trigger.Enabled = $false
$action = New-ScheduledTaskAction -Execute ([IO.Path]::GetFullPath($InertImagePath))
$taskPrincipal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -Disable -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
$definition = New-ScheduledTask -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings
Register-ScheduledTask -TaskName $TaskName -InputObject $definition -ErrorAction Stop | Out-Null

$argumentsJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ArgumentsJsonBase64))
$msiArguments = @($argumentsJson | ConvertFrom-Json)
if ($argumentsJson.Length -gt 65536 -or $msiArguments.Count -ne 7 -or
    @($msiArguments | Where-Object { $_ -isnot [string] -or $_.Length -gt 32768 }).Count -gt 0) {
    throw 'The fixed MSI argument vector was malformed or exceeded its bound.'
}
$msiPath = [IO.Path]::GetFullPath($msiArguments[1])
$logPath = [IO.Path]::GetFullPath($msiArguments[5])
if ($msiArguments[6] -cnotmatch '^INSTALLROOT=.+$') {
    throw 'The fixed MSI argument vector omitted its selected install root.'
}
$installRoot = [IO.Path]::GetFullPath($msiArguments[6].Substring('INSTALLROOT='.Length))
if ($msiArguments[0] -cne '/i' -or $msiArguments[2] -cne '/qn' -or
    $msiArguments[3] -cne '/norestart' -or $msiArguments[4] -cne '/l*v' -or
    -not $msiPath.StartsWith($runnerTemp, [StringComparison]::OrdinalIgnoreCase) -or
    -not $logPath.StartsWith($runnerTemp, [StringComparison]::OrdinalIgnoreCase) -or
    -not $installRoot.StartsWith($runnerTemp, [StringComparison]::OrdinalIgnoreCase) -or
    -not (Test-Path -LiteralPath $msiPath -PathType Leaf)) {
    throw 'The wrapper received an unexpected MSI argument vector or path outside RUNNER_TEMP.'
}
$installer = [Diagnostics.ProcessStartInfo]::new()
$installer.FileName = [IO.Path]::GetFullPath($MsiexecPath)
$installer.UseShellExecute = $false
foreach ($argument in $msiArguments) { [void]$installer.ArgumentList.Add($argument) }
$child = [Diagnostics.Process]::Start($installer)
$msiexecPid = $child.Id
$child.WaitForExit()
$msiExitCode = $child.ExitCode
$sidecar = @{ process_id = $msiexecPid; exit_code = $msiExitCode } | ConvertTo-Json -Compress
[IO.File]::WriteAllText($ExitCodePath, $sidecar, [Text.UTF8Encoding]::new($false))

exit [int]$msiExitCode
