# Standalone behavioral tests for scripts/SideEffectRuntimeLifecycle.psm1.
# Compatible with Windows PowerShell 5.1; uses only disposable local files.
[CmdletBinding()]
param(
    [string] $TemporaryRoot = [IO.Path]::GetTempPath()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $repositoryRoot 'scripts\SideEffectRuntimeLifecycle.psm1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    throw "Lifecycle module not found: $modulePath"
}
Import-Module -Name $modulePath -Force

function Assert-True {
    param([Parameter(Mandatory = $true)][bool] $Condition,
          [Parameter(Mandatory = $true)][string] $Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Assert-Throws {
    param([Parameter(Mandatory = $true)][scriptblock] $Action,
          [Parameter(Mandatory = $true)][string] $Message)
    $threw = $false
    try { & $Action } catch { $threw = $true }
    Assert-True -Condition $threw -Message $Message
}

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $runningElevated = ([Security.Principal.WindowsPrincipal]::new($currentIdentity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}
finally {
    $currentIdentity.Dispose()
}
if ($runningElevated) {
    Assert-Throws -Action { Assert-SideEffectRuntimeNotElevated } -Message 'mutating lifecycle operations must refuse elevated tokens'
} else {
    Assert-SideEffectRuntimeNotElevated
}

$temporaryRoot = Join-Path $TemporaryRoot ('sideeffect-runtime-lifecycle-' + [Guid]::NewGuid().ToString('N'))
$localAppData = Join-Path $temporaryRoot 'LocalAppData'
$release = 'b11938'
$relativePath = "SideEffect\runtimes\llama.cpp\$release\windows-x64"
$revision = '19cce6919992fdffd92e0ac152caaf1e2b8f254e'
$backend = 'cpu'
$expectedRemoval = 'REMOVE LLAMA.CPP b11938 CPU'
$junctionPath = $null

try {
    [IO.Directory]::CreateDirectory($localAppData) | Out-Null

    # Relative paths containing traversal or a drive/root are rejected.
    Assert-Throws -Action {
        Get-SideEffectRuntimeInstallPath -LocalAppData $localAppData -RelativePath '..\escape' -Release $release -Backend $backend
    } -Message 'path traversal must be rejected'
    Assert-Throws -Action {
        Get-SideEffectRuntimeInstallPath -LocalAppData $localAppData -RelativePath 'C:\outside' -Release $release -Backend $backend
    } -Message 'rooted paths must be rejected'

    # A junction in the exact supported path must be rejected as a reparse point.
    $junctionTarget = Join-Path $temporaryRoot 'junction-target'
    [IO.Directory]::CreateDirectory($junctionTarget) | Out-Null
    $junctionPath = Join-Path $localAppData 'SideEffect'
    try {
        New-Item -ItemType Junction -Path $junctionPath -Target $junctionTarget -ErrorAction Stop | Out-Null
    } catch {
        throw "Could not create the junction required for the reparse-path test: $($_.Exception.Message)"
    }
    Assert-Throws -Action {
        Get-SideEffectRuntimeInstallPath -LocalAppData $localAppData -RelativePath $relativePath -Release $release -Backend $backend
    } -Message 'reparse points in the installation path must be rejected'
    [IO.Directory]::Delete($junctionPath, $false)

    $junctionPath = $null
    $installRoot = Get-SideEffectRuntimeInstallPath -LocalAppData $localAppData -RelativePath $relativePath -Release $release -Backend $backend
    [IO.Directory]::CreateDirectory((Join-Path $installRoot 'bin')) | Out-Null
    $executablePath = Join-Path $installRoot 'bin\llama-completion.exe'
    $libraryPath = Join-Path $installRoot 'bin\ggml-base.dll'
    [IO.File]::WriteAllBytes($executablePath, [byte[]](0, 1, 2, 3, 4))
    [IO.File]::WriteAllBytes($libraryPath, [byte[]](5, 6, 7, 8))

    $manifest = New-SideEffectRuntimeManifest -Root $installRoot -Release $release -Revision $revision -Backend $backend
    Assert-True -Condition ($manifest.schema -eq 'sideeffect.windows_llama_runtime_install') -Message 'manifest schema must be emitted'
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $installRoot '.sideeffect-runtime-manifest.json') -PathType Leaf) -Message 'manifest file must be created'
    $inspection = Test-SideEffectRuntimeInstallation -Root $installRoot -Release $release -Revision $revision -Backend $backend
    Assert-True -Condition ($inspection.status -eq 'verified') -Message 'fresh manifest must inspect as verified'
    Assert-True -Condition ($inspection.file_count -eq 2) -Message 'inspection must report both pinned files'

    # A second manifest write must fail without replacing the original manifest.
    $manifestPath = Join-Path $installRoot '.sideeffect-runtime-manifest.json'
    $manifestBefore = [IO.File]::ReadAllBytes($manifestPath)
    Assert-Throws -Action {
        New-SideEffectRuntimeManifest -Root $installRoot -Release $release -Revision $revision -Backend $backend
    } -Message 'manifest creation must not clobber an existing manifest'
    $manifestAfter = [IO.File]::ReadAllBytes($manifestPath)
    Assert-True -Condition ([Convert]::ToBase64String($manifestBefore) -ceq [Convert]::ToBase64String($manifestAfter)) -Message 'failed manifest creation must preserve existing bytes'

    # Modified and unexpected files must both invalidate the manifest.
    [IO.File]::AppendAllText($executablePath, 'changed')
    $inspection = Test-SideEffectRuntimeInstallation -Root $installRoot -Release $release -Revision $revision -Backend $backend
    Assert-True -Condition ($inspection.status -eq 'unverified' -and (@($inspection.problems) -join ' ') -match 'changed file') -Message 'modified files must be rejected by inspection'
    Assert-Throws -Action {
        Remove-SideEffectRuntimeInstallation -LocalAppData $localAppData -RelativePath $relativePath -Release $release -Revision $revision -Backend $backend -Confirmation $expectedRemoval
    } -Message 'modified files must prevent managed removal'
    [IO.File]::WriteAllBytes($executablePath, [byte[]](0, 1, 2, 3, 4))
    [IO.File]::WriteAllText((Join-Path $installRoot 'unlisted.txt'), 'unexpected')
    $inspection = Test-SideEffectRuntimeInstallation -Root $installRoot -Release $release -Revision $revision -Backend $backend
    Assert-True -Condition ($inspection.status -eq 'unverified' -and (@($inspection.problems) -join ' ') -match 'unexpected file') -Message 'unexpected files must be rejected by inspection'
    Assert-Throws -Action {
        Remove-SideEffectRuntimeInstallation -LocalAppData $localAppData -RelativePath $relativePath -Release $release -Revision $revision -Backend $backend -Confirmation $expectedRemoval
    } -Message 'unexpected files must prevent managed removal'
    Remove-Item -LiteralPath (Join-Path $installRoot 'unlisted.txt') -Force

    # Reparse points inside the runtime tree are rejected and never followed.
    $externalDirectory = Join-Path $temporaryRoot 'external-directory'
    [IO.Directory]::CreateDirectory($externalDirectory) | Out-Null
    $insideJunction = Join-Path $installRoot 'unexpected-link'
    New-Item -ItemType Junction -Path $insideJunction -Target $externalDirectory -ErrorAction Stop | Out-Null
    $inspection = Test-SideEffectRuntimeInstallation -Root $installRoot -Release $release -Revision $revision -Backend $backend
    Assert-True -Condition ($inspection.status -eq 'unverified' -and (@($inspection.problems) -join ' ') -match 'reparse point') -Message 'reparse points inside the runtime tree must be rejected'
    Assert-Throws -Action {
        Remove-SideEffectRuntimeInstallation -LocalAppData $localAppData -RelativePath $relativePath -Release $release -Revision $revision -Backend $backend -Confirmation $expectedRemoval
    } -Message 'reparse points must prevent managed removal'
    [IO.Directory]::Delete($insideJunction, $false)

    # A wrong confirmation must leave the complete pinned tree intact.
    Assert-Throws -Action {
        Remove-SideEffectRuntimeInstallation -LocalAppData $localAppData -RelativePath $relativePath -Release $release -Revision $revision -Backend $backend -Confirmation 'REMOVE LLAMA.CPP b11938 CUDA'
    } -Message 'wrong removal confirmation must be rejected'
    Assert-True -Condition (Test-Path -LiteralPath $executablePath -PathType Leaf) -Message 'wrong confirmation must preserve installed files'
    Assert-True -Condition (Test-Path -LiteralPath $manifestPath -PathType Leaf) -Message 'wrong confirmation must preserve the manifest'

    # Exact confirmation removes only the verified installation tree.
    $outsideSentinel = Join-Path $localAppData 'keep-me.txt'
    [IO.File]::WriteAllText($outsideSentinel, 'outside the pinned tree')
    $removed = Remove-SideEffectRuntimeInstallation -LocalAppData $localAppData -RelativePath $relativePath -Release $release -Revision $revision -Backend $backend -Confirmation $expectedRemoval
    Assert-True -Condition ($removed.status -eq 'removed' -and $removed.file_count -eq 2) -Message 'exact confirmation must report successful removal'
    Assert-True -Condition (-not (Test-Path -LiteralPath $installRoot)) -Message 'exact confirmation must remove the pinned runtime tree'
    Assert-True -Condition (Test-Path -LiteralPath $outsideSentinel -PathType Leaf) -Message 'removal must preserve files outside the pinned tree'

    Write-Host 'Passed: runtime path validation, manifest create/inspect/no-clobber, modified/unexpected-file rejection, confirmation safety, and bounded removal.'
}
finally {
    Remove-Module SideEffectRuntimeLifecycle -ErrorAction SilentlyContinue
    if ($null -ne $junctionPath -and (Test-Path -LiteralPath $junctionPath)) {
        [IO.Directory]::Delete($junctionPath, $false)
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
