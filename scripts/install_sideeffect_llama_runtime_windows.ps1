#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('cpu', 'cuda')]
    [string] $Backend,
    [ValidateSet('install', 'inspect', 'remove')]
    [string] $Action = 'install'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Release = 'b11938'
$Revision = '19cce6919992fdffd92e0ac152caaf1e2b8f254e'
$RuntimeRelativePath = "SideEffect\runtimes\llama.cpp\$Release\windows-x64"
$MaximumArchiveEntries = 2048
$MaximumSingleEntryBytes = 1GB
$MaximumExpandedBytes = 2GB
$DownloadBufferBytes = 64KB
$MaximumRedirects = 5
$MaximumExtractionTime = [TimeSpan]::FromMinutes(15)
$script:ExpandedBytes = 0L
$script:ExtractionStopwatch = $null
$AllowedRedirectHosts = @(
    'github.com',
    'release-assets.githubusercontent.com',
    'objects.githubusercontent.com'
)

Import-Module (Join-Path $PSScriptRoot 'SideEffectRuntimeLifecycle.psm1') -Force

$Assets = @{
    cpu = @(
        @{
            Name = 'llama-b11938-bin-win-cpu-x64.zip'
            Size = 24260998L
            Sha256 = '9e2fc62604446d86809ca09094d3c7a7329b723bda636e4bbd23c3ce62cb77dc'
            Role = 'llama.cpp CPU runtime'
        }
    )
    cuda = @(
        @{
            Name = 'llama-b11938-bin-win-cuda-12.4-x64.zip'
            Size = 279447765L
            Sha256 = '91e8c63d59c080ea1b4f042911489b27d3ee019f323bc0556111c83dcab410c8'
            Role = 'llama.cpp CUDA runtime'
        },
        @{
            Name = 'cudart-llama-bin-win-cuda-12.4-x64.zip'
            Size = 391443627L
            Sha256 = '8c79a9b226de4b3cacfd1f83d24f962d0773be79f1e7b75c6af4ded7e32ae1d6'
            Role = 'bundled NVIDIA CUDA runtime libraries'
        }
    )
}

function Assert-AllowedHttpsUri {
    param([Parameter(Mandatory = $true)][Uri] $Uri)

    if (-not $Uri.IsAbsoluteUri -or $Uri.Scheme -cne 'https' -or
        -not $Uri.IsDefaultPort -or $Uri.UserInfo.Length -ne 0 -or
        $Uri.Host -cnotin $AllowedRedirectHosts) {
        throw 'The runtime download source or redirect is not an approved HTTPS host.'
    }
}

function Get-RedirectedResponse {
    param(
        [Parameter(Mandatory = $true)][System.Net.Http.HttpClient] $Client,
        [Parameter(Mandatory = $true)][Uri] $StartUri
    )

    $currentUri = $StartUri
    Assert-AllowedHttpsUri $currentUri

    for ($redirectCount = 0; $redirectCount -le $MaximumRedirects; $redirectCount++) {
        $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $currentUri)
        $response = $Client.SendAsync(
            $request,
            [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
        ).GetAwaiter().GetResult()
        $request.Dispose()

        if ([int]$response.StatusCode -notin @(301, 302, 303, 307, 308)) {
            return $response
        }

        if ($redirectCount -eq $MaximumRedirects) {
            $response.Dispose()
            throw 'The runtime download exceeded the redirect limit.'
        }

        $location = $response.Headers.Location
        if ($null -eq $location) {
            $response.Dispose()
            throw 'The runtime download returned a redirect without a destination.'
        }

        $nextUri = if ($location.IsAbsoluteUri) { $location } else { [Uri]::new($currentUri, $location) }
        $response.Dispose()
        Assert-AllowedHttpsUri $nextUri
        $currentUri = $nextUri
    }

    throw 'The runtime download did not produce a response.'
}

function Download-VerifiedAsset {
    param(
        [Parameter(Mandatory = $true)][Uri] $Uri,
        [Parameter(Mandatory = $true)][hashtable] $Asset,
        [Parameter(Mandatory = $true)][string] $Destination
    )

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseDefaultCredentials = $false
    $handler.PreAuthenticate = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromHours(1)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('SideEffect-runtime-installer/1.0')
    $response = $null
    $inputStream = $null
    $outputStream = $null
    $hasher = $null

    try {
        $response = Get-RedirectedResponse -Client $client -StartUri $Uri
        if (-not $response.IsSuccessStatusCode) {
            throw 'The pinned runtime source returned an unsuccessful HTTP status.'
        }
        Assert-AllowedHttpsUri $response.RequestMessage.RequestUri
        if ($null -ne $response.Content.Headers.ContentLength -and
            $response.Content.Headers.ContentLength -ne $Asset.Size) {
            throw 'The runtime archive length does not match its pinned size.'
        }

        $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $outputStream = [System.IO.File]::Open(
            $Destination,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $hasher = [System.Security.Cryptography.IncrementalHash]::CreateHash(
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        )
        $buffer = [byte[]]::new($DownloadBufferBytes)
        [long] $received = 0

        while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $received += $read
            if ($received -gt $Asset.Size) {
                throw 'The runtime source exceeded its pinned download size.'
            }
            $outputStream.Write($buffer, 0, $read)
            $hasher.AppendData($buffer, 0, $read)
        }

        $outputStream.Flush($true)
        $actualHash = [BitConverter]::ToString($hasher.GetHashAndReset()).Replace('-', '').ToLowerInvariant()
        if ($received -ne $Asset.Size -or $actualHash -cne $Asset.Sha256) {
            throw 'The runtime archive failed its pinned size or SHA-256 check.'
        }
    }
    finally {
        if ($null -ne $hasher) { $hasher.Dispose() }
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        if ($null -ne $inputStream) { $inputStream.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        $client.Dispose()
        $handler.Dispose()
    }
}

function Get-SafeEntryDestination {
    param(
        [Parameter(Mandatory = $true)][System.IO.Compression.ZipArchiveEntry] $Entry,
        [Parameter(Mandatory = $true)][string] $ExtractionRoot
    )

    $name = $Entry.FullName.Normalize([Text.NormalizationForm]::FormC)
    if ([string]::IsNullOrWhiteSpace($name) -or $name.Contains('\') -or
        $name.StartsWith('/') -or $name.Contains(':')) {
        throw 'The runtime archive contains an unsupported entry path.'
    }

    $isDirectory = $name.EndsWith('/')
    $trimmedName = $name.TrimEnd('/')
    $parts = $trimmedName.Split('/')
    if ($parts.Count -eq 0 -or @($parts | Where-Object { $_ -in @('', '.', '..') }).Count -gt 0) {
        throw 'The runtime archive contains a rooted or traversal entry path.'
    }
    foreach ($part in $parts) {
        if ($part -notmatch '^[A-Za-z0-9 _().+-]+$' -or $part.EndsWith('.') -or $part.EndsWith(' ') -or
            $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$') {
            throw 'The runtime archive contains an unsupported Windows filename.'
        }
    }

    $attributes = [long]$Entry.ExternalAttributes -band 0xFFFFFFFFL
    $unixType = ($attributes -shr 16) -band 0xF000
    $dosAttributes = $attributes -band 0xFFFF
    if (($unixType -ne 0 -and $unixType -notin @(0x8000, 0x4000)) -or
        ($unixType -eq 0x4000 -and -not $isDirectory) -or
        ($unixType -eq 0x8000 -and $isDirectory) -or
        ($dosAttributes -band 0x400) -ne 0) {
        throw 'The runtime archive contains a symbolic link, reparse point, or special-file entry.'
    }

    $relative = $parts -join [System.IO.Path]::DirectorySeparatorChar
    $destination = [System.IO.Path]::GetFullPath((Join-Path $ExtractionRoot $relative))
    $rootPrefix = $ExtractionRoot.TrimEnd('\') + '\'
    if (-not $destination.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The runtime archive entry escapes its staging directory.'
    }

    return @{
        Path = $destination
        IsDirectory = $isDirectory
    }
}

function Expand-VerifiedArchive {
    param(
        [Parameter(Mandatory = $true)][string] $ArchivePath,
        [Parameter(Mandatory = $true)][string] $ExtractionRoot
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        if ($archive.Entries.Count -eq 0 -or $archive.Entries.Count -gt $MaximumArchiveEntries) {
            throw 'The runtime archive entry count is outside the allowed bounds.'
        }

        $seenPaths = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        foreach ($entry in $archive.Entries) {
            $target = Get-SafeEntryDestination -Entry $entry -ExtractionRoot $ExtractionRoot
            if (-not $seenPaths.Add($target.Path)) {
                throw 'The runtime archive contains duplicate paths for Windows.'
            }
            if ($entry.Length -lt 0 -or $entry.Length -gt $MaximumSingleEntryBytes) {
                throw 'A runtime archive member exceeds the per-file expansion limit.'
            }

            $script:ExpandedBytes += $entry.Length
            if ($script:ExpandedBytes -gt $MaximumExpandedBytes) {
                throw 'The runtime archive exceeds the total expansion limit.'
            }

            if ($target.IsDirectory) {
                [System.IO.Directory]::CreateDirectory($target.Path) | Out-Null
                continue
            }

            $parent = [System.IO.Path]::GetDirectoryName($target.Path)
            [System.IO.Directory]::CreateDirectory($parent) | Out-Null
            $input = $entry.Open()
            $output = $null
            try {
                $output = [System.IO.File]::Open(
                    $target.Path,
                    [System.IO.FileMode]::CreateNew,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None
                )
                [long] $written = 0
                $buffer = [byte[]]::new($DownloadBufferBytes)
                while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if ($script:ExtractionStopwatch.Elapsed -gt $MaximumExtractionTime) {
                        throw 'Runtime archive extraction exceeded its time limit.'
                    }
                    $written += $read
                    if ($written -gt $entry.Length -or $written -gt $MaximumSingleEntryBytes) {
                        throw 'A runtime archive member expanded beyond its declared limit.'
                    }
                    $output.Write($buffer, 0, $read)
                }
                $output.Flush($true)
                if ($written -ne $entry.Length) {
                    throw 'A runtime archive member length did not match its declaration.'
                }
            }
            finally {
                try {
                    if ($null -ne $output) { $output.Dispose() }
                }
                finally {
                    $input.Dispose()
                }
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string] $Path)

    $stream = [System.IO.File]::OpenRead($Path)
    $hasher = [System.Security.Cryptography.IncrementalHash]::CreateHash(
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try {
        $buffer = [byte[]]::new($DownloadBufferBytes)
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $hasher.AppendData($buffer, 0, $read)
        }
        return [BitConverter]::ToString($hasher.GetHashAndReset()).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

function Install-CudaRuntimeLibraries {
    param(
        [Parameter(Mandatory = $true)][string] $CudaRoot,
        [Parameter(Mandatory = $true)][string] $RuntimeDirectory
    )

    $libraries = @(Get-ChildItem -LiteralPath $CudaRoot -Filter '*.dll' -File -Recurse)
    if ($libraries.Count -eq 0) {
        throw 'The pinned CUDA runtime library archive contains no DLLs.'
    }
    foreach ($library in $libraries) {
        if ($library.Length -le 0 -or $library.Length -gt $MaximumSingleEntryBytes) {
            throw 'A bundled CUDA runtime library has an invalid size.'
        }
        $destinationPath = Join-Path $RuntimeDirectory $library.Name
        if (Test-Path -LiteralPath $destinationPath) {
            $existing = Get-Item -LiteralPath $destinationPath -Force
            if (-not $existing.PSIsContainer -and
                (Get-FileSha256 -Path $existing.FullName) -ceq (Get-FileSha256 -Path $library.FullName)) {
                continue
            }
            throw "The CUDA runtime archive conflicts with an existing runtime file: $($library.Name)"
        }
        if (($script:ExpandedBytes + $library.Length) -gt $MaximumExpandedBytes) {
            throw 'Bundled CUDA libraries would exceed the total installed-file size limit.'
        }
        $script:ExpandedBytes += $library.Length

        $input = [System.IO.File]::OpenRead($library.FullName)
        $output = [System.IO.File]::Open(
            $destinationPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        try {
            $input.CopyTo($output, $DownloadBufferBytes)
            $output.Flush($true)
        }
        finally {
            $output.Dispose()
            $input.Dispose()
        }
    }

    $notices = @(Get-ChildItem -LiteralPath $CudaRoot -File -Recurse | Where-Object {
        $_.Name -match '(?i)(LICENSE|NOTICE|EULA)'
    })
    if ($notices.Count -gt 64) {
        throw 'The CUDA runtime bundle contains too many license/notice files.'
    }
    $noticeRoot = Join-Path $RuntimeDirectory 'third-party-notices\cuda-runtime'
    [long] $noticeBytes = 0
    foreach ($notice in $notices) {
        if ($notice.Length -gt 1MB) {
            throw 'A bundled CUDA license/notice file exceeds its size limit.'
        }
        $noticeBytes += $notice.Length
        if ($noticeBytes -gt 8MB) {
            throw 'Bundled CUDA license/notice files exceed their total size limit.'
        }
        if (($script:ExpandedBytes + $notice.Length) -gt $MaximumExpandedBytes) {
            throw 'Bundled CUDA notices would exceed the total installed-file size limit.'
        }
        $script:ExpandedBytes += $notice.Length
        $relative = $notice.FullName.Substring($CudaRoot.TrimEnd('\').Length).TrimStart('\')
        $noticeDestination = [System.IO.Path]::GetFullPath((Join-Path $noticeRoot $relative))
        $noticePrefix = [System.IO.Path]::GetFullPath($noticeRoot).TrimEnd('\') + '\'
        if (-not $noticeDestination.StartsWith($noticePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'A bundled CUDA license/notice path escapes its destination.'
        }
        $noticeDirectory = [System.IO.Path]::GetDirectoryName($noticeDestination)
        [System.IO.Directory]::CreateDirectory($noticeDirectory) | Out-Null
        $input = [System.IO.File]::OpenRead($notice.FullName)
        $output = [System.IO.File]::Open(
            $noticeDestination,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        try {
            $input.CopyTo($output, $DownloadBufferBytes)
            $output.Flush($true)
        }
        finally {
            $output.Dispose()
            $input.Dispose()
        }
    }
}

function Assert-PrivateDirectoryPath {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $AllowedRoot
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($AllowedRoot).TrimEnd('\') + '\'
    if (-not $fullPath.StartsWith($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The runtime installer path is outside the per-user runtime directory.'
    }
    return $fullPath
}

function Assert-NoReparsePointsBelowRoot {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $Candidate
    )

    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $fullCandidate = Assert-PrivateDirectoryPath -Path $Candidate -AllowedRoot $fullRoot
    $relative = $fullCandidate.Substring($fullRoot.Length).TrimStart('\')
    $current = $fullRoot
    foreach ($component in $relative.Split('\')) {
        if ([string]::IsNullOrEmpty($component)) { continue }
        $current = Join-Path $current $component
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'The runtime install path contains a reparse point.'
            }
        }
    }
}

$appData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
$destination = Get-SideEffectRuntimeInstallPath -LocalAppData $appData -RelativePath $RuntimeRelativePath -Release $Release -Backend $Backend

if ($Action -eq 'inspect') {
    $inspection = Test-SideEffectRuntimeInstallation -Root $destination -Release $Release -Revision $Revision -Backend $Backend
    $inspection | ConvertTo-Json -Depth 6
    if ($inspection.status -eq 'unverified') { exit 2 }
    exit 0
}

Assert-SideEffectRuntimeNotElevated

if ($Action -eq 'remove') {
    $inspection = Test-SideEffectRuntimeInstallation -Root $destination -Release $Release -Revision $Revision -Backend $Backend
    if ($inspection.status -ne 'verified') {
        $inspection | ConvertTo-Json -Depth 6
        throw 'Removal refused: the runtime is missing, modified, or contains files outside its verified install manifest.'
    }
    Write-Host "Verified runtime directory: $destination"
    Write-Host ("The removal deletes exactly this directory and its {0} manifest-listed files." -f $inspection.file_count)
    Write-Host 'If this exact executable is registered for explanation, clear it first with: sideeffect model runtime clear explanation'
    Write-Host 'If this exact executable is registered for ETW query, clear it first with: sideeffect model runtime clear query'
    $expectedConfirmation = "REMOVE LLAMA.CPP $Release $($Backend.ToUpperInvariant())"
    $confirmation = Read-Host "Type exactly '$expectedConfirmation' to continue"
    if ($confirmation -cne $expectedConfirmation) {
        throw 'Runtime removal cancelled; no files were changed.'
    }
    $result = Remove-SideEffectRuntimeInstallation -LocalAppData $appData -RelativePath $RuntimeRelativePath -Release $Release -Revision $Revision -Backend $Backend -Confirmation $confirmation
    Write-Host "Removed the verified llama.cpp runtime directory: $($result.path)"
    Write-Host 'No SideEffect registry entry or model weights were changed.'
    exit 0
}

$assets = $Assets[$Backend]
$totalDownloadBytes = Get-SideEffectRuntimeAssetTotalSize -Assets $assets
$expectedConfirmation = "INSTALL LLAMA.CPP $Release $($Backend.ToUpperInvariant())"
Write-Host "This downloads executable code from the pinned llama.cpp GitHub release ($Release)."
Write-Host "Backend: $Backend; total download: $totalDownloadBytes bytes (~$([Math]::Round($totalDownloadBytes / 1000000)) MB; up to 2 GiB extracted)."
foreach ($asset in $assets) {
    Write-Host ("  {0}: {1} bytes; SHA-256 {2}" -f $asset.Role, $asset.Size, $asset.Sha256)
}
Write-Host 'llama.cpp source and the CPU package use MIT terms: https://github.com/ggml-org/llama.cpp/blob/b11938/LICENSE'
if ($Backend -eq 'cuda') {
    Write-Host 'The CUDA option also bundles NVIDIA CUDA runtime libraries; review the CUDA 12.4.0 NVIDIA EULA before accepting: https://docs.nvidia.com/cuda/archive/12.4.0/eula/index.html'
}
Write-Host 'The archive will be verified and extracted under LOCALAPPDATA. No executable will be started.'
Write-Host 'Pinned hashes establish byte integrity, not the identity of the build publisher.'
$confirmation = Read-Host "Type exactly '$expectedConfirmation' to continue"
if ($confirmation -cne $expectedConfirmation) {
    throw 'Runtime installation cancelled before network access.'
}

$parent = Split-Path -Parent $destination
Assert-NoReparsePointsBelowRoot -Root $appData -Candidate $parent
[System.IO.Directory]::CreateDirectory($parent) | Out-Null
$parent = Assert-PrivateDirectoryPath -Path $parent -AllowedRoot $appData
Assert-NoReparsePointsBelowRoot -Root $appData -Candidate $parent
if (Test-Path -LiteralPath $destination) {
    throw 'A runtime already exists at the destination; this installer never overwrites it.'
}

$stage = Join-Path $parent ('.staging-' + [Guid]::NewGuid().ToString('N'))
$stage = Assert-PrivateDirectoryPath -Path $stage -AllowedRoot $parent
[System.IO.Directory]::CreateDirectory($stage) | Out-Null
$published = $false
$script:ExtractionStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

try {
    $runtimeExtractRoot = Join-Path $stage 'runtime'
    [System.IO.Directory]::CreateDirectory($runtimeExtractRoot) | Out-Null
    foreach ($asset in $assets) {
        $archivePath = Join-Path $stage $asset.Name
        $uri = [Uri]::new("https://github.com/ggml-org/llama.cpp/releases/download/$Release/$($asset.Name)")
        Download-VerifiedAsset -Uri $uri -Asset $asset -Destination $archivePath
        $extractionRoot = if ($asset.Role -eq 'bundled NVIDIA CUDA runtime libraries') {
            Join-Path $stage 'cuda-libraries'
        } else {
            $runtimeExtractRoot
        }
        [System.IO.Directory]::CreateDirectory($extractionRoot) | Out-Null
        Expand-VerifiedArchive -ArchivePath $archivePath -ExtractionRoot $extractionRoot
        Remove-Item -LiteralPath $archivePath -Force
    }

    $runtimeExecutables = @(Get-ChildItem -LiteralPath $runtimeExtractRoot -Filter 'llama-completion.exe' -File -Recurse)
    if ($runtimeExecutables.Count -ne 1) {
        throw 'The verified runtime archive must contain exactly one llama-completion.exe.'
    }
    $runtimeDirectory = $runtimeExecutables[0].DirectoryName

    if ($Backend -eq 'cuda') {
        Install-CudaRuntimeLibraries -CudaRoot (Join-Path $stage 'cuda-libraries') -RuntimeDirectory $runtimeDirectory
        Remove-Item -LiteralPath (Join-Path $stage 'cuda-libraries') -Recurse -Force
    }

    New-SideEffectRuntimeManifest -Root $stage -Release $Release -Revision $Revision -Backend $Backend | Out-Null

    $runtimePath = [System.IO.Path]::GetFullPath($runtimeExecutables[0].FullName)
    if (-not $runtimePath.StartsWith(($stage.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The runtime executable resolved outside its staging directory.'
    }

    [System.IO.Directory]::Move($stage, $destination)
    $published = $true
    $runtimePath = $runtimePath.Replace($stage, $destination)
    Write-Host ''
    Write-Host "Installed, hash-verified llama.cpp runtime build $Release ($Revision)."
    Write-Host "Installed directory: $destination"
    Write-Host 'The executable was not run and SideEffect registry was not changed.'
    Write-Host "Inspect this install with: powershell.exe -NoProfile -File .\scripts\install_sideeffect_llama_runtime_windows.ps1 -Backend $Backend -Action inspect"
    Write-Host "Remove this install with: powershell.exe -NoProfile -File .\scripts\install_sideeffect_llama_runtime_windows.ps1 -Backend $Backend -Action remove"
    Write-Host 'Next, inspect and register it explicitly for the task you intend to use:'
    Write-Host "sideeffect model runtime set explanation `"$runtimePath`""
    Write-Host "sideeffect model runtime set query `"$runtimePath`"  # native Windows ETW query"
    Write-Host 'Check the selected task with one of these commands:'
    Write-Host 'sideeffect model doctor --task explanation --backend auto'
    Write-Host 'sideeffect model doctor --task query --backend auto'
}
finally {
    if (-not $published -and (Test-Path -LiteralPath $stage -PathType Container)) {
        $resolvedStage = Assert-PrivateDirectoryPath -Path $stage -AllowedRoot $parent
        if ((Split-Path -Leaf $resolvedStage) -notmatch '^\.staging-[0-9a-f]{32}$') {
            throw 'Refusing to remove an unexpected runtime staging path.'
        }
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
}
