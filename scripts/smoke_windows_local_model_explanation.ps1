<#
.SYNOPSIS
Opt-in Windows CPU smoke of the documented local-model explanation CLI.

.DESCRIPTION
Exercises the documented explanation workflow on a repository synthetic
strace fixture with a llama.cpp runtime and the pinned experimental
explanation-qwen3.5-0.8b-q4-0 GGUF that you already obtained:

  1. creates a fresh throw-away model store by pointing LOCALAPPDATA at a new
     temporary directory for every child process (the supported per-user store
     override), so your own model registry is untouched;
  2. checks the supplied GGUF's byte length and SHA-256 against the catalog pin
     reported by `sideeffect model show explanation-qwen3.5-0.8b-q4-0`;
  3. registers the existing file with `model add` (never `model install` or
     `model setup`) and selects it for explanation in the isolated store;
  4. runs `model doctor --task explanation --backend cpu` and requires the
     runtime's reported `--version` revision prefix to match the pinned
     llama.cpp revision;
  5. runs `model-explain-preview --backend cpu` and then
     `model-explain --backend cpu --confirm-sha256 <preview digest>`.

This script never downloads weights or a runtime, never records a trace, and
never selects a GPU backend. Doctor runs the runtime once with `--version`;
that version string does not authenticate the executable or its libraries.
The analysis step is an unverified evidence-selection aid on a synthetic
fixture: no quality, semantic-correctness, performance, GPU, or real-capture
claim follows from it. Every file it creates is removed on exit.

.PARAMETER SideeffectPath
Path to a built native Windows x86_64 sideeffect.exe.

.PARAMETER RuntimePath
Path to an already-obtained llama-completion.exe reporting the pinned
llama.cpp revision.

.PARAMETER ModelPath
Path to an already-obtained Qwen3.5-0.8B-Q4_0.gguf matching the catalog pin.

The trace fixture and question are fixed: the checked-in synthetic
tests/fixtures/local_model_explain_v1/connect-and-exec.trace, which carries one
exec and one refused connection, and a two-part question that both rows can
support.

.EXAMPLE
pwsh -NoProfile -File .\scripts\smoke_windows_local_model_explanation.ps1 `
  -SideeffectPath .\sideeffect.exe `
  -RuntimePath .\llama-completion.exe `
  -ModelPath .\Qwen3.5-0.8B-Q4_0.gguf
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SideeffectPath,

    [Parameter(Mandatory = $true)]
    [string]$RuntimePath,

    [Parameter(Mandatory = $true)]
    [string]$ModelPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pinnedModelId = 'explanation-qwen3.5-0.8b-q4-0'
$pinnedRevision = '19cce6919992fdffd92e0ac152caaf1e2b8f254e'
$traceFileRelative = 'tests/fixtures/local_model_explain_v1/connect-and-exec.trace'
$question = 'Did the observed connection succeed, and which executable was started?'

function Write-Step {
    param([string]$Message)
    Write-Host "STEP: $Message"
}

function Resolve-RegularFile {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is not an existing file: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label is a reparse point, which this smoke does not accept: $Path"
    }
    return $item
}

function Invoke-IsolatedSideEffect {
    param([string[]]$Arguments)
    $previous = $env:LOCALAPPDATA
    $env:LOCALAPPDATA = $script:DataRoot
    $exitCode = $null
    try {
        $lines = & $script:SideEffectFile @Arguments
        $exitCode = $LASTEXITCODE
    }
    finally {
        $env:LOCALAPPDATA = $previous
    }
    if ($null -eq $exitCode) {
        throw 'SideEffect invocation did not report an exit code.'
    }
    return [pscustomobject]@{
        ExitCode = [int]$exitCode
        Output   = (@($lines) -join "`n").Trim()
    }
}

function Convert-FromJsonOutput {
    param([string]$Text, [string]$Label)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        throw "$Label produced no JSON output."
    }
    try {
        return $Text | ConvertFrom-Json
    }
    catch {
        throw "$Label did not produce parseable JSON: $($_.Exception.Message)"
    }
}

$sideeffectItem = Resolve-RegularFile -Path $SideeffectPath -Label 'SideEffect executable'
$runtimeItem = Resolve-RegularFile -Path $RuntimePath -Label 'Runtime executable'
$modelItem = Resolve-RegularFile -Path $ModelPath -Label 'Model file'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$traceItem = Resolve-RegularFile -Path (Join-Path $repositoryRoot $traceFileRelative) -Label 'Synthetic trace fixture'

$script:SideEffectFile = $sideeffectItem.FullName
$runtimeFile = $runtimeItem.FullName
$modelFile = $modelItem.FullName
$traceFile = $traceItem.FullName

$script:DataRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sideeffect-local-model-smoke-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:DataRoot -Force | Out-Null
$registryPath = Join-Path (Join-Path $script:DataRoot 'SideEffect') 'model-registry.json'
$modelsDirectory = Join-Path (Join-Path $script:DataRoot 'SideEffect') 'models'

Write-Host 'SideEffect Windows CPU local-model explanation smoke (opt-in).'
Write-Host 'Synthetic fixture, existing runtime and GGUF, isolated model registry. No downloads.'
Write-Host "Trace fixture: $(Split-Path -Leaf $traceFile)"
Write-Host ''

try {
    if (Test-Path -LiteralPath $registryPath) {
        throw 'The isolated model registry already exists; refusing to reuse it.'
    }

    Write-Step 'Reading the catalog pin for the explanation workflow-test candidate'
    $showResult = Invoke-IsolatedSideEffect -Arguments @('model', 'show', $pinnedModelId)
    if ($showResult.ExitCode -ne 0) {
        throw "model show failed with exit code $($showResult.ExitCode): $($showResult.Output)"
    }
    $catalogEntry = (Convert-FromJsonOutput -Text $showResult.Output -Label 'model show').catalog_entry
    $pinnedSize = [int64]$catalogEntry.size_bytes
    $pinnedSha256 = ([string]$catalogEntry.sha256).ToLowerInvariant()
    if ($pinnedSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'The catalog entry did not report a usable SHA-256 pin.'
    }
    Write-Host "  catalog pin: $pinnedSize bytes, SHA-256 $pinnedSha256"

    Write-Step 'Verifying the supplied GGUF against that catalog pin'
    if ($modelItem.Length -ne $pinnedSize) {
        throw "Model size $($modelItem.Length) does not match the catalog pin $pinnedSize."
    }
    $modelSha256 = (Get-FileHash -LiteralPath $modelFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($modelSha256 -ne $pinnedSha256) {
        throw "Model SHA-256 $modelSha256 does not match the catalog pin $pinnedSha256."
    }
    if ([string]$catalogEntry.evaluation -ne 'not_assessed') {
        Write-Host "  note: catalog evaluation status is $($catalogEntry.evaluation)"
    }

    Write-Step 'Registering the existing file in the isolated registry (no download, no copy)'
    $addResult = Invoke-IsolatedSideEffect -Arguments @(
        'model', 'add',
        '--name', 'Qwen3.5 0.8B Q4_0 (synthetic smoke)',
        '--path', $modelFile,
        '--for', 'explanation'
    )
    if ($addResult.ExitCode -ne 0) {
        throw "model add failed with exit code $($addResult.ExitCode): $($addResult.Output)"
    }
    $modelIdMatch = [regex]::Match($addResult.Output, ' as ([^ ]+)\. It is user-provided')
    if (-not $modelIdMatch.Success) {
        throw "Could not read the registered model ID from: $($addResult.Output)"
    }
    $registeredId = $modelIdMatch.Groups[1].Value

    $selectResult = Invoke-IsolatedSideEffect -Arguments @('model', 'select', 'explanation', $registeredId)
    if ($selectResult.ExitCode -ne 0) {
        throw "model select failed with exit code $($selectResult.ExitCode): $($selectResult.Output)"
    }
    if (-not (Test-Path -LiteralPath $registryPath -PathType Leaf)) {
        throw 'The isolated registry file was not created where expected.'
    }
    Write-Host "  isolated registry: $registryPath"
    Write-Host "  selected model: $registeredId"

    Write-Step 'Checking the runtime reported build with the product doctor (CPU, no inference)'
    $doctorResult = Invoke-IsolatedSideEffect -Arguments @(
        'model', 'doctor',
        '--task', 'explanation',
        '--runtime', $runtimeFile,
        '--backend', 'cpu'
    )
    if ($doctorResult.ExitCode -ne 0) {
        throw "model doctor reported not ready (exit $($doctorResult.ExitCode)): $($doctorResult.Output)"
    }
    $doctor = Convert-FromJsonOutput -Text $doctorResult.Output -Label 'model doctor'
    if ([string]$doctor.readiness -ne 'registration_and_runtime_checks_passed') {
        throw "Unexpected doctor readiness: $($doctor.readiness)"
    }
    if (([bool]$doctor.inference_not_run) -ne $true) {
        throw 'Doctor did not report that inference was skipped.'
    }
    if ([string]$doctor.runtime.executable_status -ne 'verified_revision_prefix') {
        throw "The runtime reported build was not proven by the CLI: $($doctor.runtime.executable_status) $($doctor.runtime.executable_diagnostic)"
    }
    if ([string]$doctor.runtime.expected_source_revision -ne $pinnedRevision) {
        throw "Doctor expected an unexpected source revision: $($doctor.runtime.expected_source_revision)"
    }
    if ([string]$doctor.runtime.backend_readiness -ne 'ready_cpu_requested') {
        throw "Doctor did not report CPU readiness: $($doctor.runtime.backend_readiness)"
    }
    if (([string]$doctor.selected_model.sha256).ToLowerInvariant() -ne $pinnedSha256) {
        throw 'Doctor reported a selected model SHA-256 different from the verified file.'
    }
    Write-Host "  runtime: $($doctor.runtime.runtime_path)"
    Write-Host "  reported revision: $($doctor.runtime.expected_source_revision) (version-string check only)"

    Write-Step 'Previewing the exact question, evidence, and request digest (CPU)'
    $previewResult = Invoke-IsolatedSideEffect -Arguments @(
        'model-explain-preview',
        '--question', $question,
        '--backend', 'cpu',
        $traceFile
    )
    if ($previewResult.ExitCode -ne 0) {
        throw "model-explain-preview failed with exit code $($previewResult.ExitCode): $($previewResult.Output)"
    }
    $preview = Convert-FromJsonOutput -Text $previewResult.Output -Label 'model-explain-preview'
    if ($null -ne $preview.deterministic_abstain_reason) {
        throw "The preview returned a deterministic abstention ($($preview.deterministic_abstain_reason)); analysis would not start a runtime, so this is not a CPU inference smoke."
    }
    if ([string]$preview.backend_preference -ne 'cpu') {
        throw "Preview did not bind the CPU backend: $($preview.backend_preference)"
    }
    if (([string]$preview.model_sha256).ToLowerInvariant() -ne $pinnedSha256) {
        throw 'Preview bound a model SHA-256 different from the verified file.'
    }
    if ([int64]$preview.model_size_bytes -ne $pinnedSize) {
        throw 'Preview bound a model size different from the catalog pin.'
    }
    if ([string]$preview.runtime_source_revision -ne $pinnedRevision) {
        throw "Preview bound an unexpected runtime revision: $($preview.runtime_source_revision)"
    }
    $digest = [string]$preview.request_sha256
    if ($digest -notmatch '^[0-9a-f]{64}$') {
        throw 'Preview did not return a 64-character lowercase request digest.'
    }
    Write-Host 'Complete preview JSON follows. Review the question, evidence, prompt, and digest before confirming.'
    Write-Host $previewResult.Output
    Write-Host ''
    Write-Host 'The analysis step needs the exact request digest shown above. Inference is not run until it is typed.'
    $typedDigest = Read-Host 'Type the exact request_sha256 to run the CPU analysis'
    if ($typedDigest -cne $digest) {
        throw 'The typed digest did not match the preview request_sha256; analysis was not run.'
    }

    Write-Step 'Running the confirmed CPU analysis with the exact preview digest'
    $analysisResult = Invoke-IsolatedSideEffect -Arguments @(
        'model-explain',
        '--question', $question,
        '--backend', 'cpu',
        '--runtime', $runtimeFile,
        '--confirm-sha256', $digest,
        $traceFile
    )
    if ($analysisResult.ExitCode -ne 0 -and $analysisResult.ExitCode -ne 2) {
        throw "model-explain failed with exit code $($analysisResult.ExitCode): $($analysisResult.Output)"
    }
    $analysis = Convert-FromJsonOutput -Text $analysisResult.Output -Label 'model-explain'
    if ([string]$analysis.request_sha256 -ne $digest) {
        throw 'Analysis did not echo the confirmed request digest.'
    }
    if ([string]$analysis.backend_used -ne 'cpu') {
        throw "Analysis did not report the CPU backend: $($analysis.backend_used)"
    }
    if (([string]$analysis.model_sha256).ToLowerInvariant() -ne $pinnedSha256) {
        throw 'Analysis reported a model SHA-256 different from the verified file.'
    }
    if ([string]$analysis.runtime_source_revision -ne $pinnedRevision) {
        throw "Analysis reported an unexpected runtime revision: $($analysis.runtime_source_revision)"
    }
    [pscustomobject]@{
        schema           = $analysis.schema
        schema_version   = $analysis.schema_version
        backend_used     = $analysis.backend_used
        backend_status   = $analysis.backend_status
        selection_status = $analysis.interpretation.selection_status
        evidence_count   = @($analysis.interpretation.selected_facts).Count
        exit_code        = $analysisResult.ExitCode
    } | ConvertTo-Json -Depth 4 | Write-Host

    if (Test-Path -LiteralPath $modelsDirectory) {
        throw 'The smoke wrote files into the isolated models directory; it must not install weights.'
    }

    Write-Step 'Result'
    Write-Host '  PASS: documented preview-then-confirmed CPU explanation workflow completed on the synthetic fixture.'
    Write-Host '  This is an unverified evidence-selection aid on synthetic input: it is not a quality score.'
    Write-Host '  GPU/CUDA use, semantic correctness, performance, and real captures were not tested.'
}
finally {
    if ($null -ne $script:DataRoot -and (Test-Path -LiteralPath $script:DataRoot)) {
        $scratchPath = $null
        $cleanupProblem = $null
        try {
            $scratchPath = [System.IO.Path]::GetFullPath($script:DataRoot)
            $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
            $tempRoot = $tempRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
            $scratchName = Split-Path -Leaf $scratchPath
            $scratchParent = Split-Path -Parent $scratchPath
            if ($scratchName -notmatch '^sideeffect-local-model-smoke-[0-9a-f]{32}$') {
                throw "refusing to remove a scratch path with an unexpected name: $scratchPath"
            }
            if (-not [string]::Equals($scratchParent, $tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "refusing to remove a scratch path that is not a direct child of the temp root: $scratchPath"
            }
            $scratchItem = Get-Item -LiteralPath $scratchPath -Force
            if (($scratchItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "refusing to remove a reparse-point scratch directory: $scratchPath"
            }
            if (-not $scratchItem.PSIsContainer) {
                throw "scratch path is not a directory: $scratchPath"
            }
            Remove-Item -LiteralPath $scratchPath -Recurse -Force
            if (Test-Path -LiteralPath $scratchPath) {
                throw "scratch directory still exists after removal: $scratchPath"
            }
        }
        catch {
            $cleanupProblem = $_.Exception.Message
        }
        if ($null -ne $cleanupProblem) {
            Write-Warning "Isolated scratch model store was not cleaned up: $cleanupProblem"
        }
        elseif ($null -ne $scratchPath) {
            Write-Host "Removed isolated scratch model store: $scratchPath"
        }
    }
}
