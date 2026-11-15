Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ManifestName = '.sideeffect-runtime-manifest.json'
$script:ManifestSchema = 'sideeffect.windows_llama_runtime_install'
$script:MaximumManifestBytes = 2MB
$script:MaximumFiles = 4096
$script:MaximumFileBytes = 1GB
$script:MaximumInstallBytes = 2GB

function Assert-SideEffectRuntimeNotElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Runtime installation and removal must run from a non-elevated user session.'
        }
    }
    finally {
        $identity.Dispose()
    }
}

function Get-SideEffectRuntimeAssetTotalSize {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary[]] $Assets)

    if ($Assets.Count -eq 0) {
        throw 'At least one pinned runtime asset is required.'
    }

    [long] $totalBytes = 0
    foreach ($asset in $Assets) {
        if (-not $asset.Contains('Size') -or $asset['Size'] -isnot [long] -or $asset['Size'] -le 0) {
            throw 'A pinned runtime asset has an invalid size.'
        }

        [long] $size = $asset['Size']
        if ($totalBytes -gt ([long]::MaxValue - $size)) {
            throw 'The pinned runtime asset total exceeds the supported integer range.'
        }
        $totalBytes += $size
    }

    return $totalBytes
}

function Get-SideEffectRuntimeInstallPath {
    param(
        [Parameter(Mandatory = $true)][string] $LocalAppData,
        [Parameter(Mandatory = $true)][string] $RelativePath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,32}$')][string] $Release,
        [Parameter(Mandatory = $true)][ValidateSet('cpu', 'cuda')][string] $Backend
    )

    $expectedRelativePath = "SideEffect\runtimes\llama.cpp\$Release\windows-x64"
    if ([string]::IsNullOrWhiteSpace($LocalAppData) -or
        [string]::IsNullOrWhiteSpace($RelativePath) -or
        $RelativePath -cne $expectedRelativePath -or
        [System.IO.Path]::IsPathRooted($RelativePath) -or
        $RelativePath -match '(^|[\\/])\.\.?([\\/]|$)' -or
        $RelativePath.Contains(':')) {
        throw 'The runtime installation root is invalid.'
    }

    $root = [System.IO.Path]::GetFullPath($LocalAppData).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'LOCALAPPDATA is unavailable or is not a directory.'
    }
    $rootItem = Get-Item -LiteralPath $root -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'LOCALAPPDATA must not be a reparse point.'
    }

    $relativeParts = @($RelativePath -split '[\\/]') + $Backend
    if (@($relativeParts | Where-Object { $_ -notmatch '^[A-Za-z0-9._-]+$' }).Count -gt 0) {
        throw 'The runtime installation path contains an unsupported component.'
    }
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $root (($relativeParts -join '\'))))
    $prefix = $root.TrimEnd('\') + '\'
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The runtime installation path escapes LOCALAPPDATA.'
    }

    $current = $root
    $relativeCandidate = $candidate.Substring($prefix.Length)
    foreach ($component in $relativeCandidate.Split('\')) {
        $current = Join-Path $current $component
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'The runtime installation path contains a reparse point.'
            }
        }
    }
    return $candidate
}

function Get-SideEffectInstallTree {
    param([Parameter(Mandatory = $true)][string] $Root)

    $files = [System.Collections.Generic.List[object]]::new()
    $directories = [System.Collections.Generic.List[string]]::new()
    [long] $totalBytes = 0
    $pendingDirectories = [System.Collections.Generic.Stack[string]]::new()
    $pendingDirectories.Push([System.IO.Path]::GetFullPath($Root))
    $visited = 0
    while ($pendingDirectories.Count -gt 0) {
        $parent = $pendingDirectories.Pop()
        foreach ($item in Get-ChildItem -LiteralPath $parent -Force) {
            $visited++
            if ($visited -gt ($script:MaximumFiles * 2)) {
                throw 'The runtime installation contains too many files or directories.'
            }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'The runtime installation contains a reparse point.'
            }
            $relative = $item.FullName.Substring($Root.TrimEnd('\').Length).TrimStart('\').Replace('\', '/')
            if ([string]::IsNullOrWhiteSpace($relative) -or $relative.Length -gt 1024 -or
                $relative -match '(^|/)\.\.?(/|$)' -or $relative.Contains(':') -or
                $relative -match '[\x00-\x1f\x7f]') {
                throw 'The runtime installation contains an unsupported relative path.'
            }
            if ($item.PSIsContainer) {
                $directories.Add($relative)
                $pendingDirectories.Push($item.FullName)
                continue
            }
            if ($relative -ceq $script:ManifestName) { continue }
            if ($files.Count -ge $script:MaximumFiles -or $item.Length -lt 0 -or
                $item.Length -gt $script:MaximumFileBytes) {
                throw 'The runtime installation exceeds its file-count or per-file size limit.'
            }
            $totalBytes += $item.Length
            if ($totalBytes -gt $script:MaximumInstallBytes) {
                throw 'The runtime installation exceeds its total file size limit.'
            }
            $files.Add([pscustomobject]@{
                path = $relative
                size = [long]$item.Length
                sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            })
        }
    }
    $fileArray = @($files | Sort-Object -Property path)
    $directoryArray = @($directories | Sort-Object)
    return [pscustomobject]@{
        files = $fileArray
        directories = $directoryArray
        total_bytes = $totalBytes
    }
}

function New-SideEffectRuntimeManifest {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,32}$')][string] $Release,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string] $Revision,
        [Parameter(Mandatory = $true)][ValidateSet('cpu', 'cuda')][string] $Backend
    )

    $rootPath = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $rootPath -PathType Container)) {
        throw 'The runtime staging directory is unavailable.'
    }
    $rootItem = Get-Item -LiteralPath $rootPath -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The runtime staging directory must not be a reparse point.'
    }
    $tree = Get-SideEffectInstallTree -Root $rootPath
    if ($tree.files.Count -eq 0 -or $tree.files.Count -gt $script:MaximumFiles) {
        throw 'The runtime staging directory has no files or exceeds the manifest limit.'
    }
    $manifest = [pscustomobject]@{
        schema = $script:ManifestSchema
        version = 1
        release = $Release
        revision = $Revision
        backend = $Backend
        files = $tree.files
        directories = $tree.directories
    }
    $json = ConvertTo-Json -InputObject $manifest -Depth 6 -Compress
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $bytes = $encoding.GetBytes($json)
    if ($bytes.Length -gt $script:MaximumManifestBytes) {
        throw 'The runtime file manifest exceeds its size limit.'
    }
    $manifestPath = Join-Path $rootPath $script:ManifestName
    $stream = [System.IO.File]::Open(
        $manifestPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    return $manifest
}

function Test-SideEffectRuntimeInstallation {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,32}$')][string] $Release,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string] $Revision,
        [Parameter(Mandatory = $true)][ValidateSet('cpu', 'cuda')][string] $Backend
    )

    $rootPath = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $rootPath -PathType Container)) {
        return [pscustomobject]@{ status = 'not_installed'; release = $Release; backend = $Backend; path = $rootPath }
    }
    try {
        $rootItem = Get-Item -LiteralPath $rootPath -Force
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'The runtime directory is a reparse point.'
        }
        $manifestPath = Join-Path $rootPath $script:ManifestName
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw 'The runtime install manifest is missing.'
        }
        $manifestItem = Get-Item -LiteralPath $manifestPath -Force
        if (($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $manifestItem.Length -le 0 -or $manifestItem.Length -gt $script:MaximumManifestBytes) {
            throw 'The runtime install manifest is not a bounded regular file.'
        }
        $manifestStream = [System.IO.File]::Open(
            $manifestPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        try {
            if ($manifestStream.Length -le 0 -or $manifestStream.Length -gt $script:MaximumManifestBytes) {
                throw 'The runtime install manifest changed beyond its read limit.'
            }
            $manifestBytes = [byte[]]::new([int]$manifestStream.Length)
            $offset = 0
            while ($offset -lt $manifestBytes.Length) {
                $read = $manifestStream.Read($manifestBytes, $offset, $manifestBytes.Length - $offset)
                if ($read -le 0) { throw 'The runtime install manifest ended unexpectedly.' }
                $offset += $read
            }
            if ($manifestStream.ReadByte() -ne -1) { throw 'The runtime install manifest exceeded its read limit.' }
        }
        finally {
            $manifestStream.Dispose()
        }
        $encoding = [System.Text.UTF8Encoding]::new($false, $true)
        $json = $encoding.GetString($manifestBytes)
        $manifestHasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            $manifestSha256 = [BitConverter]::ToString($manifestHasher.ComputeHash($manifestBytes))
            $manifestSha256 = $manifestSha256.Replace('-', '').ToLowerInvariant()
        }
        finally {
            $manifestHasher.Dispose()
        }
        $manifest = ConvertFrom-Json -InputObject $json -ErrorAction Stop
        $expectedProperties = @('schema', 'version', 'release', 'revision', 'backend', 'files', 'directories')
        $actualProperties = @($manifest.PSObject.Properties.Name | Sort-Object)
        if (($actualProperties -join '|') -cne (($expectedProperties | Sort-Object) -join '|') -or
            $manifest.schema -cne $script:ManifestSchema -or $manifest.version -ne 1 -or
            $manifest.release -cne $Release -or $manifest.revision -cne $Revision -or
            $manifest.backend -cne $Backend -or @($manifest.files).Count -eq 0 -or
            @($manifest.files).Count -gt $script:MaximumFiles -or
            @($manifest.directories).Count -gt $script:MaximumFiles) {
            throw 'The runtime install manifest is unsupported or does not match this pinned runtime.'
        }

        $expectedFiles = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
        [long] $declaredBytes = 0
        foreach ($file in @($manifest.files)) {
            $relative = [string]$file.path
            $fileProperties = @($file.PSObject.Properties.Name | Sort-Object)
            if (($fileProperties -join '|') -cne 'path|sha256|size') {
                throw 'The runtime install manifest contains an unsupported file entry.'
            }
            if ([string]::IsNullOrWhiteSpace($relative) -or $relative.StartsWith('/') -or
                $relative.Length -gt 1024 -or $relative.Contains('\') -or $relative.Contains(':') -or
                $relative -match '(^|/)\.\.?(/|$)' -or $relative -match '[\x00-\x1f\x7f]' -or
                $relative -ceq $script:ManifestName -or
                [long]$file.size -lt 0 -or [long]$file.size -gt $script:MaximumFileBytes -or
                [string]$file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $expectedFiles.ContainsKey($relative)) {
                throw 'The runtime install manifest contains an invalid file entry.'
            }
            $declaredBytes += [long]$file.size
            if ($declaredBytes -gt $script:MaximumInstallBytes) {
                throw 'The runtime install manifest exceeds its total size limit.'
            }
            $expectedFiles.Add($relative, $file)
        }
        $expectedDirectories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($directory in @($manifest.directories)) {
            $relative = [string]$directory
            if ([string]::IsNullOrWhiteSpace($relative) -or $relative.StartsWith('/') -or
                $relative.Length -gt 1024 -or $relative.Contains('\') -or $relative.Contains(':') -or
                $relative -match '(^|/)\.\.?(/|$)' -or $relative -match '[\x00-\x1f\x7f]' -or
                $relative -ceq $script:ManifestName -or -not $expectedDirectories.Add($relative)) {
                throw 'The runtime install manifest contains an invalid directory entry.'
            }
        }
        $tree = Get-SideEffectInstallTree -Root $rootPath
        $actualFiles = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($file in @($tree.files)) { $actualFiles.Add([string]$file.path, $file) }
        $actualDirectories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($directory in @($tree.directories)) { [void]$actualDirectories.Add([string]$directory) }

        $problems = [System.Collections.Generic.List[string]]::new()
        foreach ($path in $actualFiles.Keys) {
            if (-not $expectedFiles.ContainsKey($path)) { $problems.Add("unexpected file: $path") }
        }
        foreach ($path in $actualDirectories) {
            if (-not $expectedDirectories.Contains($path)) { $problems.Add("unexpected directory: $path") }
        }
        foreach ($path in $expectedFiles.Keys) {
            if (-not $actualFiles.ContainsKey($path)) {
                $problems.Add("missing file: $path")
                continue
            }
            $expected = $expectedFiles[$path]
            $actual = $actualFiles[$path]
            if ([long]$expected.size -ne [long]$actual.size -or
                [string]$expected.sha256 -cne [string]$actual.sha256) {
                $problems.Add("changed file: $path")
            }
        }
        foreach ($path in $expectedDirectories) {
            if (-not $actualDirectories.Contains($path)) { $problems.Add("missing directory: $path") }
        }
        $status = if ($problems.Count -eq 0) { 'verified' } else { 'unverified' }
        return [pscustomobject]@{
            status = $status
            release = $Release
            revision = $Revision
            backend = $Backend
            path = $rootPath
            file_count = $actualFiles.Count
            total_bytes = $tree.total_bytes
            manifest_sha256 = $manifestSha256
            file_paths = @($expectedFiles.Keys | Sort-Object)
            directory_paths = @($expectedDirectories | Sort-Object)
            problems = @($problems | Select-Object -First 64)
        }
    }
    catch {
        return [pscustomobject]@{
            status = 'unverified'
            release = $Release
            revision = $Revision
            backend = $Backend
            path = $rootPath
            file_count = 0
            total_bytes = 0
            manifest_sha256 = $null
            file_paths = @()
            directory_paths = @()
            problems = @($_.Exception.Message)
        }
    }
}

function Remove-SideEffectRuntimeInstallation {
    param(
        [Parameter(Mandatory = $true)][string] $LocalAppData,
        [Parameter(Mandatory = $true)][string] $RelativePath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,32}$')][string] $Release,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string] $Revision,
        [Parameter(Mandatory = $true)][ValidateSet('cpu', 'cuda')][string] $Backend,
        [Parameter(Mandatory = $true)][string] $Confirmation
    )

    Assert-SideEffectRuntimeNotElevated
    $expectedConfirmation = "REMOVE LLAMA.CPP $Release $($Backend.ToUpperInvariant())"
    if ($Confirmation -cne $expectedConfirmation) {
        throw 'Runtime removal confirmation did not match; no files were changed.'
    }
    $root = Get-SideEffectRuntimeInstallPath -LocalAppData $LocalAppData -RelativePath $RelativePath -Release $Release -Backend $Backend
    $inspection = Test-SideEffectRuntimeInstallation -Root $root -Release $Release -Revision $Revision -Backend $Backend
    if ($inspection.status -ne 'verified') {
        throw 'Removal refused: the runtime is missing, modified, or contains files outside its verified install manifest.'
    }
    $inspection = Test-SideEffectRuntimeInstallation -Root $root -Release $Release -Revision $Revision -Backend $Backend
    if ($inspection.status -ne 'verified') {
        throw 'Runtime contents changed before removal; no files were changed.'
    }
    $pathsToDelete = [System.Collections.Generic.List[string]]::new()
    foreach ($relative in @($inspection.file_paths)) { $pathsToDelete.Add([string]$relative) }
    $pathsToDelete.Add($script:ManifestName)
    foreach ($relative in $pathsToDelete) {
        $path = Join-Path $root ($relative.Replace('/', '\'))
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Runtime contents changed during removal; refusing to delete an unexpected path.'
        }
        if ($relative -ceq $script:ManifestName -and
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $inspection.manifest_sha256) {
            throw 'The runtime install manifest changed during removal; refusing to continue.'
        }
        [System.IO.File]::Delete($path)
    }
    foreach ($relative in @($inspection.directory_paths | Sort-Object Length -Descending)) {
        $path = Join-Path $root ($relative.Replace('/', '\'))
        $item = Get-Item -LiteralPath $path -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Runtime directories changed during removal; refusing recursive deletion.'
        }
        [System.IO.Directory]::Delete($path, $false)
    }
    [System.IO.Directory]::Delete($root, $false)
    return [pscustomobject]@{
        status = 'removed'
        release = $Release
        revision = $Revision
        backend = $Backend
        path = $root
        file_count = $inspection.file_count
        total_bytes = $inspection.total_bytes
    }
}

Export-ModuleMember -Function Assert-SideEffectRuntimeNotElevated, Get-SideEffectRuntimeAssetTotalSize, Get-SideEffectRuntimeInstallPath, New-SideEffectRuntimeManifest, Test-SideEffectRuntimeInstallation, Remove-SideEffectRuntimeInstallation
