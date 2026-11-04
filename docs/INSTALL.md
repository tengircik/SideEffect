# Build and run SideEffect

## Scope and prerequisites

Versioned binary archives, when published, are available from [GitHub Releases](https://github.com/tengircik/SideEffect/releases/latest). Verify the archive checksum and build provenance before installation. If no release is available for your platform, use the source-build instructions below. Linux x86_64 provides the runtime tracing workflow using external `strace`. Native Windows provides bounded software, process, explicit-path permission, and startup inventory slices plus Windows audit sessions. Its ETW process/FileIo/DiskIo/TCP/UDP workflow supports bounded capture, offline inspection, category and event-level comparison, conservative evidence-linked attribution candidates, and static HTML reports. The live process/file/loopback integration test passed on hosted Windows Server 2022 and 2025 for exact source commit [`797ba86`](https://github.com/tengircik/SideEffect/commit/797ba86dc41d024129da35b2fc4be7ad5eca6756) ([CI run](https://github.com/tengircik/SideEffect/actions/runs/40867530573)). Native Windows ETW is not an evidence-complete or exhaustive system audit. Linux `record --trace` and trace-diff HTML file export are Linux-only; Windows has a separate ETW HTML report.

For agent-assisted workflows, use the portable [SideEffect Agent Skill](AGENT_SKILL.md). The skill runs the local CLI through an agent and model selected by the user; it does not require a SideEffect local model.

## Install a published release archive

Release archives do not require Rust. Download the release assets to a temporary directory, verify `SHA256SUMS`, and verify the archive's GitHub build-provenance attestation before extracting it. These examples use GitHub CLI (`gh`); browser downloads are also available from the [release page](https://github.com/tengircik/SideEffect/releases/latest).

Linux x86_64:

```sh
release_dir="$(mktemp -d)"
gh release download --repo tengircik/SideEffect --dir "$release_dir"
(cd "$release_dir" && sha256sum --check SHA256SUMS)
archive="$(find "$release_dir" -maxdepth 1 -type f -name 'sideeffect-*-linux-x86_64.tar.gz' -print -quit)"
test -n "$archive"
gh attestation verify "$archive" --repo tengircik/SideEffect
tar -tzf "$archive"
package_name="$(basename "$archive" .tar.gz)"
install_root="$HOME/.local/opt/SideEffect"
install_dir="$install_root/$package_name"
test ! -e "$install_dir" || { echo "Install directory already exists: $install_dir" >&2; exit 1; }
mkdir -p "$install_root"
tar -xzf "$archive" -C "$install_root"
test ! -e "$HOME/.local/bin/sideeffect" || { echo "CLI already exists at ~/.local/bin/sideeffect; check it before replacing it" >&2; exit 1; }
mkdir -p "$HOME/.local/bin"
install -m 0755 "$install_dir/sideeffect" "$HOME/.local/bin/sideeffect"
```

The commands above extract the archive to a new versioned directory under `~/.local/opt/SideEffect/` and copy its executable to `~/.local/bin/sideeffect` only if that destination does not already exist. Add `~/.local/bin` to the current shell with `export PATH="$HOME/.local/bin:$PATH"`, then run `sideeffect version`. To make it available in future login shells, add that `export` line to the startup file used by your shell (for example, `~/.profile` for a typical login shell) and open a new shell. Do not overwrite an existing CLI without checking its version and location first.

### Update, roll back, or remove a Linux release install

For an update, follow the download, checksum, attestation, and extraction steps above for the new release. Keep each extracted version directory under `~/.local/opt/SideEffect/`; do not extract over an existing version. Check the new executable directly before switching to it:

```sh
"$install_dir/sideeffect" version
```

To try or use the new version in the current shell only, put its exact version directory first in that shell's PATH:

```sh
export PATH="$install_dir:$PATH"
hash -r
command -v sideeffect
sideeffect version
```

This affects the current shell and programs it starts. It does not change the PATH saved for future login shells. To make the update persistent, add one SideEffect-specific line to the login startup file you use, with the new version directory before `$PATH`:

```sh
export PATH="$HOME/.local/opt/SideEffect/sideeffect-v0.2.0-linux-x86_64:$PATH"
```

Replace the example directory with the exact versioned directory you installed. On later updates, edit only this SideEffect-specific line to name the new version; keep the other startup-file lines and the `$PATH` suffix. Do not add a second SideEffect line. Open a new shell and check `command -v sideeffect` and `sideeffect version`. Keep the older version directory so you can roll back: change that same startup line to the older directory, or put the older directory first in the current shell with `export PATH="$old_install_dir:$PATH"` followed by `hash -r`.

Set `old_install_dir` to the exact existing version directory you are keeping, for example:

```sh
old_install_dir="$HOME/.local/opt/SideEffect/sideeffect-v0.1.0-linux-x86_64"
```

The original `~/.local/bin/sideeffect` copy remains available if it was created by the initial install. Check `command -v sideeffect` before removing or changing anything; do not replace or remove a CLI there unless you have confirmed it is the SideEffect release copy. To uninstall one release, set `install_dir` to the full path of the version being removed, then verify that the resolved directory is an immediate, non-symlink SideEffect release directory before deleting it:

```sh
install_root="$HOME/.local/opt/SideEffect"
printf 'Selected install: %s\n' "$install_dir"
test ! -L "$install_root" || { echo "Refusing to use a symlink install root" >&2; exit 1; }
test ! -L "$install_dir" || { echo "Refusing to remove a symlink" >&2; exit 1; }
resolved_root="$(realpath -e -- "$install_root")" || exit 1
resolved_install="$(realpath -e -- "$install_dir")" || exit 1
test "$(dirname -- "$resolved_install")" = "$resolved_root" || {
  echo "Refusing to remove a directory outside the SideEffect install root" >&2
  exit 1
}
case "$(basename -- "$resolved_install")" in
  sideeffect-v*-linux-x86_64) ;;
  *) echo "Refusing to remove an unexpected directory name" >&2; exit 1 ;;
esac
test -d "$resolved_install" || exit 1
rm -r -- "$resolved_install"
```

This removes one exact version directory; other version directories remain. Remove the SideEffect-specific PATH line from your login startup file if it points to a version you removed. Remove `~/.local/bin/sideeffect` only if you confirmed it is the copy installed by this guide; use `rm -- "$HOME/.local/bin/sideeffect"` for that exact file. Do not remove the shared `~/.local/bin` or `~/.local/opt/SideEffect` parent directories.

Windows x64 PowerShell:

```powershell
$releaseDir = Join-Path $env:TEMP ("sideeffect-release-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $releaseDir | Out-Null
gh release download --repo tengircik/SideEffect --dir $releaseDir
$sumFile = Join-Path $releaseDir "SHA256SUMS"
$archives = @(Get-ChildItem $releaseDir -Filter "sideeffect-*-windows-x86_64.zip")
if ($archives.Count -ne 1) { throw "Expected exactly one Windows release archive" }
$archive = $archives[0]
$sumLine = Get-Content $sumFile | Where-Object { $_ -match ("  " + [regex]::Escape($archive.Name) + "$") }
if (-not $sumLine) { throw "Expected Windows archive checksum is missing" }
$expected = ($sumLine -split "\s+")[0]
$actual = (Get-FileHash $archive.FullName -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw "Release archive SHA-256 mismatch" }
gh attestation verify $archive.FullName --repo tengircik/SideEffect
$installRoot = Join-Path $env:LOCALAPPDATA "Programs\SideEffect"
$installDir = Join-Path $installRoot $archive.BaseName
if (Test-Path -LiteralPath $installDir) { throw "Install directory already exists; choose a new versioned directory" }
New-Item -ItemType Directory -Path $installDir | Out-Null
Expand-Archive -LiteralPath $archive.FullName -DestinationPath $installDir
```

The commands above extract to a new versioned directory without replacing an existing installation. Add it to this PowerShell session and verify the command:

```powershell
$env:Path = "$installDir;$env:Path"
sideeffect.exe version
```

To make that version available in future user sessions, add its directory to your user PATH (no administrator access is needed). This command preserves the existing user PATH and avoids adding the same directory twice:

```powershell
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = @($userPath -split ';' | Where-Object { $_ })
if (-not ($pathEntries | Where-Object { $_.TrimEnd('\') -ieq $installDir.TrimEnd('\') })) {
    [Environment]::SetEnvironmentVariable("Path", (@($pathEntries) + $installDir) -join ';', "User")
}
```

Close and reopen PowerShell and any terminal or agent that should use the updated PATH. Because the directory is versioned, update the PATH entry when you install a newer version. You can always run `sideeffect.exe` directly from the versioned directory.

### Update, roll back, or remove a Windows release install

For an update, repeat the download, checksum, attestation, and extraction steps above. Each release goes into its own versioned directory under `%LOCALAPPDATA%\Programs\SideEffect`; do not extract over an existing version. Check the new executable directly first:

```powershell
& (Join-Path $installDir "sideeffect.exe") version
```

To switch versions in this PowerShell window only, prepend the new directory to this process's PATH and verify what runs:

```powershell
$env:Path = "$installDir;$env:Path"
Get-Command sideeffect.exe | Select-Object -ExpandProperty Source
sideeffect.exe version
```

This change applies to this PowerShell process and child processes; it does not edit the saved user PATH. To persist the update, set `$oldInstallDir` to the exact previous SideEffect version directory, then run the following. It removes only exact matches for the previous and new SideEffect directories (ignoring case and a trailing backslash), puts the new directory first, and preserves all other user PATH entries and their order:

```powershell
$oldInstallDir = Join-Path $env:LOCALAPPDATA "Programs\SideEffect\sideeffect-v0.1.0-windows-x86_64"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = @($userPath -split ';' | Where-Object { $_ })
$keptEntries = @($pathEntries | Where-Object {
    $_.Trim().TrimEnd('\') -ine $oldInstallDir.TrimEnd('\') -and
    $_.Trim().TrimEnd('\') -ine $installDir.TrimEnd('\')
})
[Environment]::SetEnvironmentVariable("Path", (@($installDir) + $keptEntries) -join ';', "User")
```

Replace the example `$oldInstallDir` with the exact older directory that is in your user PATH. The directory is retained for rollback. To roll back persistently, use the older directory as `$installDir` and the currently selected directory as `$oldInstallDir` in the same PATH update; alternatively, prepend the older directory to `$env:Path` for this PowerShell window only. Close and reopen PowerShell and any terminal or agent after a persistent PATH change, then confirm the resolved executable path and `sideeffect.exe version`.

To uninstall one version, remove only its exact directory from the saved user PATH, then remove that version's files. Set `$removeInstallDir` to the exact version directory being uninstalled:

```powershell
$removeInstallDir = Join-Path $env:LOCALAPPDATA "Programs\SideEffect\sideeffect-v0.1.0-windows-x86_64"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = @($userPath -split ';' | Where-Object { $_ })
$keptEntries = @($pathEntries | Where-Object {
    $_.Trim().TrimEnd('\') -ine $removeInstallDir.TrimEnd('\')
})
[Environment]::SetEnvironmentVariable("Path", ($keptEntries -join ';'), "User")
```

Replace the example directory with the exact version being removed. Resolve and inspect it, confirm it is an immediate, non-reparse child of the SideEffect install root with the expected versioned archive name, and then remove only that literal directory:

```powershell
$installRoot = Join-Path $env:LOCALAPPDATA "Programs\SideEffect"
$rootItem = Get-Item -LiteralPath $installRoot
if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Refusing to use a reparse point as the SideEffect install root"
}
$resolvedRoot = [System.IO.Path]::GetFullPath($installRoot).TrimEnd('\')
$resolvedTarget = [System.IO.Path]::GetFullPath($removeInstallDir).TrimEnd('\')
if ([System.IO.Path]::GetDirectoryName($resolvedTarget) -ine $resolvedRoot) {
    throw "Refusing to remove a path outside the SideEffect install root"
}
if ([System.IO.Path]::GetFileName($resolvedTarget) -notmatch '^sideeffect-v[0-9].*-windows-x86_64$') {
    throw "Refusing to remove an unexpected directory name"
}
$targetItem = Get-Item -LiteralPath $resolvedTarget
if (($targetItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Refusing to recursively remove a reparse point"
}
$targetItem | Select-Object FullName, Attributes
Get-ChildItem -LiteralPath $resolvedTarget | Select-Object Name, Length
Remove-Item -LiteralPath $resolvedTarget -Recurse
```

`-LiteralPath` prevents wildcard interpretation. Other version directories remain available for rollback. Do not remove the shared `Programs\SideEffect` parent directory while it contains versions. Open a new PowerShell window after changing the saved PATH.

The Linux and Windows binary archives contain the CLI, README, installation and Agent Skill guides, project license, third-party notices, and the version-specific release notes. A separate `sideeffect-<version>-source.tar.gz` archive contains the corresponding tagged source tree. All published archives and notices appear in `SHA256SUMS`; the Linux and Windows binaries and source archive carry GitHub build-provenance attestations. Linux release archives target x86_64 GNU and are built on Ubuntu 22.04; Windows archives target x64 MSVC. The compatibility matrix below lists the exact validation boundaries.

Windows is a first-class product target. The documented bounded M10 inventory criteria have passed deterministic tests, native Windows smoke tests, and hosted Windows Server 2022/2025 CI. These results validate only the listed source slices, not exhaustive inventory coverage. The ETW acceptance job runs a real bounded process, file, and loopback capture on hosted Windows Server images; it does not establish Windows 11 desktop compatibility or exhaustive observation. WSL2 runs count only as Linux-environment validation.

Builds use Rust and Cargo. `Cargo.toml` declares Rust 1.85 as its minimum version. The hosted Linux MSRV job has passed with Rust 1.85.0. Install Rust and Cargo using the [official Rust installation instructions](https://rust-lang.org/tools/install/). The Linux system also needs a C toolchain/linker for Rust targets; install one with your distribution's package manager if it is not already present.

The `record` command requires an external `strace` version 6.8 or newer. This is the lowest release exercised by the real-tracer integration tests; strace introduced `--kill-on-exit` in 6.6, but SideEffect does not declare 6.6 or 6.7 supported. Check the installed version before recording:

```sh
strace --version
```

For example, Ubuntu 24.04's `strace` package is version 6.8 in the Ubuntu package archive ([package details](https://packages.ubuntu.com/noble/strace)). Package versions in other distributions and repositories differ; if `strace --version` reports a version below 6.8, do not use `record` with it. The Linux real-tracer integration test has passed with strace 6.8 in Ubuntu 24.04 CI and WSL, and 6.19 in WSL, without installing the WSL copies system-wide. This does not verify every later version or kernel/distribution combination. Parser, diff, and evidence commands consume an existing trace and do not launch `strace`.

## Compatibility and observation matrix

The minimums below describe declared support requirements, while the validation column lists only environments actually exercised. A successful test does not establish complete syscall observation.

| Area | Declared scope or behavior | Exercised | Not established |
| --- | --- | --- | --- |
| Product platform | Linux x86_64 for recording and HTML file export | Ubuntu 24.04 hosted CI; WSL2 integration runs | Other Linux distributions, architectures, or kernel-version range |
| Rust | Rust 1.85 minimum from `Cargo.toml` | Linux CI on Rust 1.85.0 and stable; Windows build/test job | Other target/toolchain combinations beyond the listed jobs |
| External tracer | `strace` 6.8 or newer is SideEffect's tested minimum; `--kill-on-exit` itself was introduced in 6.6 | 6.8 in Ubuntu 24.04 CI and WSL; 6.19 in WSL | Versions other than 6.8 and 6.19, and a general kernel compatibility range |
| Capture filter | `-f -ttt -yy -s 256 -e trace=%process,%file,%network --kill-on-exit` | Narrow real capture of a child exec, temporary-file operation, and loopback TCP activity | Exhaustive syscall coverage, capture completeness, and identical output across tracer/kernel combinations |
| Trace parsing | Bounded outer `strace` text syntax; preserves raw rows and classifies complete, unfinished, resumed, control, and unparsed rows | Synthetic parser fixtures and real integration traces above | Full semantic decoding of every syscall or every `strace` output format |
| Derived syscall outcomes | Strict results for `execve`, `execveat`, `openat`, `openat2`, and `connect` only | Parser fixtures and the narrow real-tracer workflow | Higher-level effects, unsupported result spellings, or outcomes for other syscalls |
| Lexical path hints | Narrow `openat`/`openat2` argument subset only; display-only | Deterministic parser fixtures | Filesystem resolution, symlink behavior, descriptor identity, or canonical paths |
| Linux permission inventory | Explicit paths; metadata, supported POSIX ACL xattrs, and Linux VFS file-capability revisions 1–3 | Deterministic ACL/capability byte fixtures, metadata/path handling, and xattr-backed filesystem tests when supported | Recursive or complete inventory, effective access decisions, and other ACL/permission sources |
| Linux package inventory | dpkg, RPM, pacman, APK, and optional Flatpak refs at fixed system paths; XBPS, Nix, Guix, and Snap are unsupported | Adapter/parser fixtures and live dpkg CLI inventory in Linux CI; Flatpak live smoke runs only when already installed | Complete software inventory, custom/user manager paths, and all distributions or package formats |
| Linux process inventory | Visible `/proc` status fields, bounded `/proc/PID/exe` link text, start ticks, namespace links, boot-ID evidence, and caller PID-namespace inode hint | Synthetic procfs fixtures and Linux CLI tests | Atomic or exhaustive process coverage; command lines or executable contents; host or durable namespace identity authenticated by boot ID/inode |
| Linux startup configuration | Aggregate schema v2: curated XDG, systemd, SysV, and cron source snapshots with inert evidence | CLI tests and deterministic source/parser fixtures | Effective applicability, manager runtime state, all distribution-specific paths, or exhaustive startup coverage |
| Diff | Exact multiset comparison of parsed syscall rows; PID/timestamp prefixes alone are ignored | Synthetic pairs plus real integration trace pair | Root cause, causal links, normalized paths/FDs, or complete OS observation |
| Windows native x64 | Bounded inventory and experimental ETW v3 capture, inspection, event-level diff summary v3, evidence lookup, attribution candidate view, and audit-session integration | Local Windows x64 `cargo test --locked --all-targets`, Clippy and format checks; hosted Windows Server 2022/2025 build/test and live process/file/loopback acceptance at exact commit [`797ba86`](https://github.com/tengircik/SideEffect/commit/797ba86dc41d024129da35b2fc4be7ad5eca6756) ([CI run](https://github.com/tengircik/SideEffect/actions/runs/40867530573)) | Windows 11 x64 privileged live ETW validation, ETL import, exhaustive inventory/event coverage, all provider/version combinations, and general Windows compatibility |

The capture filter selects syscall families using `strace`'s own versioned definitions. SideEffect's parser is not an exhaustive syscall allowlist: it recognizes supported outer record syntax and preserves raw arguments/results, while the outcome and path-hint derivations above remain deliberately narrow. Diff category labels are syscall-name buckets, not claims about successful effects.

The latest complete hosted validation is exact source commit [`984a2f8`](https://github.com/tengircik/SideEffect/commit/984a2f8fb65835a0caa01c872ae98858cd4bf424) on 2026-10-29: Linux, Rust 1.85 MSRV, Ubuntu 24.04 real-tracer compatibility, and Windows Server 2022/2025 jobs passed; both Windows jobs ran the live ETW acceptance fixture. See [CI run 40873617494](https://github.com/tengircik/SideEffect/actions/runs/40873617494). Dependency license and advisory checks passed for the same candidate in [audit run 40873617184](https://github.com/tengircik/SideEffect/actions/runs/40873617184). These point-in-time checks are not legal clearance, broad compatibility proof, or release approval.

## Optional local model setup

Model management is available through `sideeffect model list`, `show ID`, `install ID`, `setup ID [--runtime EXISTING_FILE]`, `add`, `select TASK ID`, `remove ID`, and `runtime set|show|clear`. The registry records a separate model and runtime-path selection for evidence selection, explanation, and query-plan analysis. It stores bounded model metadata and selections in a private per-user `model-registry.json`: `%LOCALAPPDATA%\SideEffect` on Windows, or `$XDG_DATA_HOME/SideEffect` on Linux (default `$HOME/.local/share/SideEffect`). Downloaded weights are stored in the sibling `models` directory with restrictive user-only permissions or ACLs. A custom model registration refers to the file the user supplied; unregistering it does not delete that file. Registry v1 is migrated in memory to v2 on read; unknown fields and unsupported versions are rejected.

Use `model list` to see each catalog entry's platform support, task selection, installation state, license acceptance, and evaluation status. Use `model show ID` for a structured view of one model. A “supported here” status means the CLI has a workflow for that task and platform; it does not mean the model is accurate or recommended.

Catalog installation is an explicit user action and is available only for catalog entries whose analysis task is supported on the current platform. The catalog contains evidence-selection and query-plan models for Linux x86_64, plus an explanation model for Linux x86_64 and native Windows. Run `sideeffect model setup ID [--runtime EXISTING_FILE]`; setup displays the immutable source, size, platform scope, license terms and evaluation note, downloads after the exact `ACCEPT <license-id>` response, verifies the file, and selects it for its declared task. If `--runtime EXISTING_FILE` is supplied, it must name a runtime you already obtained. Before displaying the catalog license prompt, setup resolves it to a canonical regular file and checks its bounded size and SHA-256. Setup neither downloads nor executes that runtime. After the pinned weights install successfully, setup saves the already-obtained runtime path for the same task; for the explanation task, `model doctor --task explanation` checks the reported runtime revision and readiness. Omitting `--runtime` leaves the separate `model runtime set` flow available. `sideeffect model install ID` downloads without selecting. Acceptance for that exact catalog model/revision/license is persisted in the local registry before network access, including if the transfer later fails or is cancelled. The downloader fetches only the pinned Hugging Face file over HTTPS, allows only approved HTTPS redirects, enforces the catalog size and SHA-256, writes a private staging file, and publishes without replacing an existing destination. It sends no trace or prompt data. No model is positively recommended for quality.

After obtaining and reviewing an existing llama.cpp runtime, save its path for the explanation task. `set`, `show`, and `clear` only handle the path and do not execute it:

```powershell
sideeffect.exe model runtime set explanation .\path\to\llama-completion.exe
sideeffect.exe model runtime show explanation
sideeffect.exe model doctor --task explanation --backend auto
```

`model doctor` uses the configured path when `--runtime` is omitted; an explicit `--runtime PATH` overrides it for that doctor call. The doctor verifies the selected model file hash and executes the runtime's bounded version/device checks. It does not read a trace or load model weights for inference. Its CUDA device result is not proof of successful GPU inference. See [the local model readiness check](LOCAL_MODEL_DOCTOR.md) for details and exit statuses.

After installation, select the model for its task. An existing local GGUF can instead be registered with `sideeffect model add --name NAME --path FILE --for evidence|explanation|query[,TASK...] [--license ID]`; the user-provided license label is unverified metadata. `model select TASK ID` checks the model file and hash before saving the per-task selection. The exact model ID, hash, source/revision or user-provided marker, license/evaluation status and pinned runtime/backend metadata are included in each relevant preview digest and output. Changing the selection invalidates the old confirmation and requires a fresh preview. `model remove ID` requires typing the exact ID before deleting a verified catalog file; removing a custom model only removes its registration.

The model manager and catalog can be inspected on Windows. Catalog query-plan inference and the evidence-selection command are Linux x86_64 only; the catalog explanation model and explanation command support Linux x86_64 and native Windows. Windows explanation supports `auto`, `cpu`, or `cuda`. A local custom GGUF can be registered only for a task supported on that platform. Runtime acquisition remains user-managed: SideEffect does not download or install llama.cpp or another runtime. The optional setup `--runtime EXISTING_FILE` only registers a runtime already obtained by the user, after bounded canonical-file, size, and hash validation; it does not execute it. The analysis commands accept a saved per-task path or an explicit `--runtime PATH`; configured runtime files are re-hashed before use and rejected if missing or changed. Model/runtime compatibility does not imply model quality, and no candidate has passed its applicable semantic gate. For the Windows/NVIDIA explanation setup and its CUDA, runtime, and resource limitations, see [Windows local explanation model setup](LOCAL_MODEL_WINDOWS_SETUP.md). Also see the task-specific setup and limitations in [evidence selection](LOCAL_MODEL_EVALUATION.md), [query plans](LOCAL_QUERY_PLAN_EVALUATION.md), and [explanations](LOCAL_MODEL_EXPLANATION_EVALUATION.md).

## Create and resolve an investigation case

Create a private schema-v2 JSON draft bound to one or more verified audit sessions from the same platform:

```sh
sideeffect case init --output ./review.case.json --title "Review selected behavior" --session ./audit-session
```

On Windows PowerShell:

```powershell
sideeffect.exe case init --output .\review.case.json --title "Review selected behavior" --session .\audit-session
```

Repeat `--session` to bind up to 16 sessions. To add one note or assertion without editing the case file directly, provide a bounded entry JSON object, pass every bound session for strict verification, and write a new private revision:

```json
{"id":"N001","kind":"note","authorship":"analyst_supplied_unverified","text":"Review this observation","evidence":[]}
```

```sh
sideeffect case add-entry --case ./review.case.json --entry ./note.json --output ./review-with-note.case.json --session ./audit-session
```

For assertions, include exact evidence locators copied from the session artifacts. Assertions require evidence references and stay labeled analyst-supplied and unverified. Entries can be added only in `draft` or `open` status. The command checks the supplied sessions and referenced artifacts, increments the branch-local revision, and writes a new private file without replacing the source.

Use `case set-status` to move between workflow states. Allowed transitions are `draft` to `open` or `cancelled`, `open` to `in_review`, `closed`, or `cancelled`, and `in_review` to `open`, `closed`, or `cancelled`. `closed` and `cancelled` are terminal. Status is an analyst workflow label; it does not indicate evidence quality or completeness. Every transition rechecks the bound sessions and evidence locators and writes a new no-clobber file:

```powershell
sideeffect.exe case set-status --case .\review-with-note.case.json --status in_review --output .\review-in-review.case.json --session .\audit-session
```

Schema-v1 cases remain readable and resolvable, but v1 did not record a status. Convert one with an explicit initial `draft` or `open` status. Migration preserves the case ID, session identities, entries, and evidence locators, hashes the exact v1 bytes as its parent, and leaves the v1 source unchanged:

```powershell
sideeffect.exe case migrate --case .\legacy.case.json --status open --output .\review-v2.case.json --session .\audit-session
```

Resolve the case against those same session directories:

```sh
sideeffect case resolve --case ./review.case.json --session ./audit-session
```

```powershell
sideeffect.exe case resolve --case .\review.case.json --session .\audit-session
```

For a private static HTML report that links each analyst entry to its resolved evidence facts:

```powershell
sideeffect.exe case resolve --format html --output .\review.html --case .\review.case.json --session .\audit-session
```

The default bounded JSON result includes exact matched source rows; the optional HTML report is static, offline, size-bounded, private, and no-clobber. Both include v2 case status/revision and preserve session/source/parser/loss status. V1 cases show that status is not tracked. Exit status `2` means a source remains partial or unknown. Manifest, artifact, and parent-case hashes establish byte consistency, not producer authenticity, a tamper-proof history, or assertion truth. Resolved output may contain raw trace rows, paths, arguments, analyst text, or ETW payloads represented as hex. Keep it local and review it before sharing. The workflow still has no interactive editor, role-specific reports, or general investigation query engine.

## Build from source

The source repository is public and can be cloned over HTTPS or SSH:

```sh
git clone https://github.com/tengircik/SideEffect.git
cd SideEffect
cargo build --locked --release --bin sideeffect
./target/release/sideeffect --version
```

The binary remains in `target/release/`; this project does not install it into a system directory. Cargo may download locked Rust dependencies from the configured registry. Review organization or network policy before allowing dependency downloads.

### Windows PowerShell: `sideeffect` is not recognized

When installed from this source with `cargo install --path . --locked --bin sideeffect`, Cargo normally places `sideeffect.exe` in `%USERPROFILE%\.cargo\bin`. Check that the executable exists and runs:

```powershell
$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
$sideeffectExe = Join-Path $cargoBin "sideeffect.exe"
Test-Path -LiteralPath $sideeffectExe
if (Test-Path -LiteralPath $sideeffectExe) { & $sideeffectExe --version }
```

Inspect which command PowerShell resolves and whether the Cargo bin directory is on this terminal's PATH:

```powershell
Get-Command sideeffect -All -ErrorAction SilentlyContinue | Format-List CommandType, Source, Definition
where.exe sideeffect
$env:Path -split ';' | Where-Object { $_ -ieq $cargoBin }
```

If PATH was just changed, close and reopen PowerShell (and any terminal or agent that should use it) so it receives the updated environment. You can run the verified installed executable directly without relying on PATH:

```powershell
& (Join-Path $env:USERPROFILE ".cargo\bin\sideeffect.exe") --version
```

To use the Cargo-installed command in the current session, add Cargo's bin directory to that session's PATH:

```powershell
$env:Path = "$(Join-Path $env:USERPROFILE '.cargo\bin');$env:Path"
sideeffect version
```

To persist it for your Windows user, add the Cargo bin directory to the user PATH without duplicating it:

```powershell
$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = @($userPath -split ';' | Where-Object { $_ })
if (-not ($pathEntries | Where-Object { $_.TrimEnd('\') -ieq $cargoBin.TrimEnd('\') })) {
    [Environment]::SetEnvironmentVariable("Path", (@($pathEntries) + $cargoBin) -join ';', "User")
}
```

Restart PowerShell and the agent or terminal after changing the user PATH. If `sideeffect version` still fails, use `Get-Command sideeffect -All` and check the executable's location before changing PATH again.

If you used `cargo build --release` instead of `cargo install`, the binary is in the repository's `target\release\sideeffect.exe`; from the repository root, invoke it as `& .\target\release\sideeffect.exe --version`.

Try the parser with the included synthetic trace:

```sh
./target/release/sideeffect inspect tests/fixtures/strace/synthetic-minimal.trace
```

This does not require `strace`. The fixture is illustrative data, not a capture from a real machine.

## Inventory processes on Windows

```powershell
.\target\release\sideeffect.exe inventory processes --output .\processes.json
```

This native Windows inventory writes `sideeffect.windows_process_inventory` v4 from one Tool Help process snapshot and queries image paths, creation FILETIME, and token facts through one process handle per PID. Handle-bound facts are internally generation-consistent, but the snapshot PID-only row cannot be bound to that later handle and stays candidate context. Windows host boot identity is unknown. Inaccessible, vanished, malformed, or failed queries remain unknown and make the result partial. SID strings are retained as identifiers; SideEffect does not resolve account names. It does not read command lines, inspect memory, start processes, or request elevation. The snapshot and handle queries happen at different times, so processes can exit or identifiers can be reused between them. The scan is limited to 8,192 process entries, 10 seconds, 32,768 UTF-16 code units per path, 4 Mi aggregate path code units, 256 UTF-16 code units per SID, 2 Mi aggregate SID code units, and 64 MiB of JSON. The output is staged under an explicit current-user-only Windows DACL and is published without replacing an existing destination. Process names, image paths, and SIDs can be sensitive; review before sharing.

## Find executable candidates on the current PATH

```sh
sideeffect inventory path-executables --output ./path-executables.json
```

The same command works on native Windows. It snapshots only the invoking process's current `PATH` and, on Windows, captured `PATHEXT`. It checks each directory one level deep, preserves order and duplicate components, and maps empty components to the current working directory with an explicit marker. Linux candidates are regular files with an execute bit; Windows candidates are regular files with a captured `PATHEXT` suffix; if `PATHEXT` is unavailable, regular-file rows remain unknown. These are metadata heuristics: SideEffect does not execute candidate files or recursively inspect directories. It skips symlinks/reparse points observed by metadata checks; concurrent filesystem replacements can race between a check and enumeration. It does not determine shell command resolution. Limits are 256 components, 4 KiB per Linux component or 32,767 UTF-16 units per Windows component, 20,000 directory entries, 16 MiB aggregate path/name bytes on Linux or UTF-16 code units on Windows, five seconds checked between operations, and 64 MiB serialized output. Limit, inaccessible, symlink/reparse, and unavailable-source conditions are represented as partial/unknown; partial results are written and exit with status `2`. The output is private and no-clobber. PATH values, names, and paths are sensitive; inspect the JSON before sharing.

## Snapshot one selected directory

```sh
sideeffect inventory root --output ./root-before.json ./selected-directory
```

On native Windows, use `sideeffect.exe inventory root --output .\root-before.json .\selected-directory`. This opens the explicitly selected directory and records only its direct children. It reports exact platform path/name encodings, entry type, size, modification time, and available platform-local file-ID hints. By default it does not read contents; add `--hash-regular-files` to opt in to schema v2 SHA-256 fingerprints of direct-child regular files. Those reads cap each file at 16 MiB and the aggregate at 64 MiB, and check a five-second deadline between chunks; an in-flight filesystem read can extend it. Symlinks/reparse points and nonregular files are never followed or hashed. A hash is a sensitive equality fingerprint, not authenticity evidence. File IDs are point-in-time hints and are not persistent identities. Enumeration order is unspecified, and the snapshot is non-atomic: entries may change during collection. Limits are one root path of at most 4,095 Linux path bytes or 32,766 Windows UTF-16 units, 10,000 direct entries, 32,767 bytes/UTF-16 units per name, 8 MiB aggregate name bytes (Windows UTF-16 units count as two bytes), and the standard 64 MiB JSON output cap. Limits and access/race failures produce a partial artifact and exit status `2`; a syscall already in progress cannot be cancelled. The output is private and no-clobber. Paths, metadata, and hashes may reveal sensitive information; inspect before sharing. A single snapshot does not establish installation, deletion, or absence.

To review a before/after directory snapshot pair, run `sideeffect explain --inventory-diff ./root-before.json ./root-after.json` (PowerShell: `sideeffect.exe explain --inventory-diff .\root-before.json .\root-after.json`). The comparator accepts at most 32 MiB across both inputs, requires identical same-platform exact root-path encodings, matches children by exact name encoding, and retains both source row indices and enumeration ordinals as evidence. When both matching regular-file rows contain observed SHA-256 values, differing digests are reported as a content change; if either requested hash is unavailable or absent, that field is reported as unknown. Additions/removals are shown only if both snapshots are complete and known root file-ID hints do not conflict. A hint conflict is recorded as uncertainty and conservatively suppresses unmatched presence claims; it does not establish that a different root object was observed. Duplicate names suppress that identity group; partial snapshots suppress all unmatched rows while retaining matched metadata changes. Output remains sensitive. This is a two-snapshot path comparison, not filesystem history, persistent object identity, or proof of installation, deletion cause, or absence.

## Experimental Windows process, file, and network capture

```powershell
.\target\release\sideeffect.exe record --windows-etw .\capture.json --duration-seconds 10 -- cmd.exe /C exit 0
```

This workflow starts the NT Kernel Logger before launching the selected program with arguments passed directly, without shell-string reconstruction. It enables process, selected FileIo, DiskIo, and TCP/UDP event classes; FileIo name records require both `DISK_FILE_IO` and `DISK_IO`. Its target runtime deadline begins after the real-time consumer is ready; the recorded interval begins immediately after ETW session start. It writes `sideeffect.windows_runtime_capture` v3 JSON with ETW event headers, exact raw user-data payload bytes, and strict process, selected file/disk-operation, and TCP/UDP observations. Process payloads are accepted only after event identity, version, TDH schema, property types, and lengths validate. File/network payload decoding accepts only event ID 0, schema version 2, explicit opcodes and bounded layouts; for the tested Windows Server 2022/2025 network events, connection IDs are 4 bytes even when the event header is 64-bit. The decoder accepts this observed form only when it exactly ends the payload, as well as the exact pointer-sized form; truncation and trailing bytes remain malformed. DiskIo decoding accepts event ID 0, schema version 0, and the supported read/write/flush layouts. Unknown/malformed enabled events retain raw bytes and make collection partial. File names may omit the drive letter; read/write records report requested bytes, not completed bytes. Target PID/exit status, capture interval, configured bounds, and session loss statistics are included. Final loss counters come from a successful STOP response. If STOP fails, the available pre-stop query is labeled non-final and collection is partial; cleanup retries STOP once. The capture is system-wide. Header PID/TID remain separate event-context fields. Review output with `sideeffect inspect --windows-runtime capture.json` or `sideeffect attribute --windows-runtime capture.json`; inspection validates the bounded v3 representation, while attribution emits conservative candidate relationships without changing the capture. Neither authenticates the source or proves capture completeness. The dedicated `diff --windows-runtime BEFORE.json AFTER.json` command compares category counts and event-level records; exact matches ignore only record ordinal and QPC timestamp, while unique changed identities are labeled candidate pairs. ETW captures remain unsupported by ordinary Linux trace diff and bundles.

The NT Kernel Logger may be in use by another application. Controlling this kernel session requires administrative privileges. SideEffect never elevates automatically and fails before launching the target when session creation or consumer startup is denied. Capture includes process, selected FileIo/DiskIo, and TCP/UDP observations as described above; the stream remains system-wide and events are not attributed to the selected target. Duration is limited to 1–60 seconds. On timeout SideEffect terminates only the selected direct process; descendants can continue after capture stops. Limits are 50,000 events, 8 MiB aggregate payload, 64 KiB per event, and 32 MiB serialized JSON. The serialized-output budget is enforced as events arrive; reaching any event or output limit stops retaining additional records and marks the capture partial. Session loss counters, unavailable statistics, unsupported process opcodes, limits, timeout, or stop failures make collection partial. Even a clean session has `capture_completeness: unknown`; it does not claim complete system capture.

Output is private to the current Windows user and published without replacing an existing file. Raw event payloads can reveal process metadata; review before sharing and delete the file when no longer needed. This format retains event payloads, not the ETL container or ETW extended data. A manual ignored acceptance test is available with `cargo test --locked --test windows_runtime_etw_integration -- --ignored`; it requires permission to control the NT Kernel Logger. The Windows CI workflow explicitly runs the test after verifying that the hosted runner token is already administrative; SideEffect never elevates automatically.

Create a static HTML review of one validated capture on native Windows:

```powershell
.\target\release\sideeffect.exe inspect --format html --output .\capture-report.html --windows-runtime .\capture.json
```

The report is capped at 64 MiB, written through the protected current-user-only publisher, and never replaces an existing destination. It has a restrictive CSP, no scripts, remote assets, or network requests, and escapes capture-derived text. It shows document event ordinals, fingerprints, and the limits of authenticity and completeness. This is a report for one capture, not a comparison; its contents can still be sensitive.

Compare two validated Windows runtime captures with:

```powershell
.\target\release\sideeffect.exe diff --windows-runtime .\before.json .\after.json
.\target\release\sideeffect.exe diff --windows-runtime --format text .\before.json .\after.json
.\target\release\sideeffect.exe diff --format html --output .\diff-report.html --windows-runtime .\before.json .\after.json
```

Both inputs must pass the bounded v3 reader and representation-fingerprint check. Summary schema v3 reports whether canonical validated capture representation fingerprints match, preserves fixed category counts and ordinals, compares exact normalized event records as multisets (excluding only record ordinal and QPC timestamp), and labels unique supported operation/path or process/image matches as candidates. Fingerprint equality does not compare JSON formatting or authenticate a producer. Its normalization ledger explains both exclusions and each event reference retains the original before/after ordinal and QPC value beside its capture fingerprint. Each event group points to both capture fingerprints and record ordinals. Partial/loss-affected inputs do not turn one-sided observations into removals or additions; ambiguity and capture diagnostics remain visible. No count, exact representation match, or candidate identity proves cause or system-level absence. Capture completeness remains unknown; partial status yields exit `2`. The HTML variant is native Windows only and uses the protected, no-clobber publisher, CSP that blocks scripts/network sources, and the 64 MiB output cap. The result may contain sensitive local evidence.

To see a separate process and event attribution view for the selected runtime capture, run `sideeffect.exe attribute --windows-runtime .\capture.json`. Attribution output v2 uses the shared raw Kernel-Process v0-v3 validator: process-start and process-end PID/parent-PID bytes must match the serialized TDH sidecar, and the event header must declare one supported pointer width. Unsupported, malformed, truncated, zero-PID, or mismatched lifecycle rows remain unassigned, mark the result partial, and invalidate active lifecycle continuity conservatively. Image names remain untrusted decoder metadata for display and are not used as process identity. Network links require the shared raw TCP/UDP decoder to match the serialized observation exactly. File/disk header PID context candidates, capture loss, and PID-reuse ambiguity retain their candidate-only limits; this view does not infer file ownership or causation. Attribution schema v1 is historical and is not imported.

The Windows startup command writes `sideeffect.windows_startup_inventory` v5 (v4 remains readable). It checks selected current-user and accessible machine Run/RunOnce registry values, current-user/common Startup folders, visible Win32/driver service configuration, and boot/logon triggers from local Task Scheduler tasks visible to the current token (including hidden tasks). Task rows include task path, task/trigger enabled states, trigger kind, and a logon user when available. For those tasks, indexed action rows preserve the action kind; Exec actions include inert executable path, arguments, and working directory. Registry, folder, service, task-trigger, and action rows include `startup_state` v1 with configured `present` and effective/observed `unknown`; enabled flags and service start types remain source facts. Unsupported action kinds and unreadable/over-limit values remain explicit with partial status/diagnostics. No task action is run, expanded, or shell-parsed; task XML is not collected. COM connects locally using the current token and no alternate credentials; there is no automatic elevation. Values, paths, and task metadata stay inert: environment variables are not expanded, commands are not parsed/executed, and shortcut contents are not opened. Task collection bounds traversal to 1,024 folders at depth 16 and 8,192 tasks, trigger rows, and action rows; 256 triggers and actions per task; 32,768 UTF-16 units per stored string; 4 Mi UTF-16 units in aggregate; 256 diagnostics; and the shared 10-second deadline checked between calls. The deadline cannot cancel an in-flight Windows API call. Service enumeration/query is bounded to 8,192 entries, a 256 KiB SCM enumeration buffer, 64 KiB per service configuration and 4 MiB aggregate configuration bytes, 32,768 UTF-16 code units per service string and 4 Mi aggregate service-string units. Registry values/folder entries are capped at 4,096 each; registry data at 64 KiB per value and 4 MiB aggregate; value names at 16,384 UTF-16 units each and 1 Mi aggregate; and paths at 32,768 units each and 4 Mi aggregate. Output uses the current-user-only DACL and no-clobber publisher. Inaccessible or over-limit sources remain partial/unknown. Task Scheduler's current-token-visible task set is not an all-users guarantee, and this inventory does not establish that an entry applies or ran.

On Windows, `inventory packages` writes the separate `sideeffect.windows_software_inventory` v1 schema. It reads selected values from HKCU native/32-bit and accessible HKLM 64/32-bit `Software\Microsoft\Windows\CurrentVersion\Uninstall` views. The collector does not use `Win32_Product`, expand `REG_EXPAND_SZ`, parse commands, or launch uninstallers. It limits registrations to 8,192 total and 2,048 per registry view; subkey names to 16,384 UTF-16 code units; selected value data to 64 KiB each and 4 MiB aggregate; aggregate subkey names to 1 Mi UTF-16 code units; and the scan to a 10-second deadline checked between registry calls. An in-flight Windows API call cannot be cancelled and can exceed that interval. Exact returned value bytes are retained as hexadecimal. Inaccessible, malformed, unsupported, and limit-affected data remain partial/unknown. Output uses the current-user-only DACL and no-clobber publisher. Portable, unregistered, and other package formats can be absent.

To inspect App Paths registrations separately, run:

```powershell
sideeffect.exe inventory app-paths --output .\app-paths.json
```

The `sideeffect.windows_app_path_inventory` v1 snapshot reads subkey names and the default and `Path` values from HKCU's native view and accessible HKLM 32-bit and 64-bit views of `Software\Microsoft\Windows\CurrentVersion\App Paths`. The default and `Path` values remain inert; `REG_EXPAND_SZ` is displayed literally, not expanded. It does not inspect the referenced filesystem path, parse command text, or establish that a target exists, is installed, available, or launchable. It caps enumeration at 4,096 entries total, names at 1,024 UTF-16 code units each and 1 Mi aggregate, registry values at 64 KiB each and 4 MiB aggregate, and collection at a 10-second cooperative deadline between API calls. A registry call already in progress cannot be cancelled. Raw returned bytes and exact UTF-16 subkey encodings are retained; paths and names can disclose sensitive local information. The output uses the current-user-only DACL and no-clobber publisher. Inaccessible, malformed, unsupported, and limit-affected data remain partial/unknown; partial artifacts are written and exit with status `2`. This is a separate registration snapshot and has no offline comparison command.

To inspect current-user AppX/MSIX package registrations, run:

```powershell
sideeffect.exe inventory msix --output .\msix.json
```

The `sideeffect.windows_msix_inventory` v1 snapshot uses the Windows package query API for the calling user only. It reads package name, publisher, full/family names, version, install-location text, and package-type flags where available. It does not query other users, activate packages, inspect package files, or establish availability, launchability, health, or execution. Collection is capped at 4,096 rows, 32,768 UTF-16 code units per string, 1 Mi aggregate string units, 512 diagnostics, a cooperative 10-second deadline, and the shared report-output limit. Exact UTF-16 code units accompany display text, and malformed display decoding is flagged. The output uses the current-user-only DACL and no-clobber publisher. Partial or inaccessible data remains explicit, partial artifacts exit with status `2`. Package names, publishers, and installation paths can be sensitive. This standalone snapshot has no comparison or audit-session integration. Windows Server CI compilation is not live API acceptance; native Windows 10/11 package-query acceptance remains open.

## Inspect selected Linux file permissions and ACLs

```sh
./target/release/sideeffect inventory permissions --output ./permissions.json ./some/file ./some/directory
```

This is a read-only check of explicit paths only. It records file type, UID/GID, mode, and supported POSIX access ACLs (and directory default ACLs); it does not recurse or determine effective access for any user. Final-component symlinks are not followed, and intermediate path components use normal Linux resolution. The collector uses `/proc/self/fd` to read ACL xattrs from its pinned object descriptor, so procfs must be available for ACL collection. Permission denial, unsupported xattrs, malformed data, and configured limits produce a partial JSON snapshot and exit status `2`; no privilege escalation is requested. Its five-second deadline is checked between paths; a filesystem syscall already in progress cannot be canceled and may run longer. The output is private mode `0600`, does not replace an existing path, and stays until you delete it. It contains sensitive paths, account IDs, modes, and raw ACL bytes; review it before sharing.

## Inspect selected Windows file permissions

```powershell
.\target\release\sideeffect.exe inventory permissions --output .\permissions.json .\some\file .\some\directory
```

This writes `sideeffect.windows_permission_inventory` v1 for explicit paths only. SideEffect opens each final path with `FILE_FLAG_OPEN_REPARSE_POINT`, then reads file attributes and owner/group/DACL from that same handle using read-control and file-attribute access. It records security descriptor bytes and hash, DACL state and control flags, and ACEs in original order; recognized basic allow/deny/audit ACE fields are decoded, while unknown ACEs remain raw evidence. It does not request SACLs, recurse, request elevation, follow the final reparse point, or calculate effective access. Inaccessible, malformed, unsupported, and over-limit items remain visible as partial or unknown. Bounds are 256 paths, 32,767 UTF-16 units per path, 1 Mi aggregate path units, 64 KiB per descriptor, 1,024 ACEs per descriptor, 8 MiB aggregate descriptor data, a five-second deadline checked between paths, and 64 MiB serialized output. An in-flight Windows API call cannot be canceled and may exceed that interval. Output uses the current-user-only DACL and no-clobber publisher; paths and ACL bytes are sensitive and should be reviewed before sharing.

## Run a partial access check

On Linux, run a non-mutating permission preflight for the current calling thread:

```sh
./target/release/sideeffect inventory access-check --operation read --output ./access-check.json /absolute/path/to/file
```

Use `read`, `write`, or `execute` and an absolute path. Linux pins the resolved final object and records the `faccessat2` result plus selected credentials and metadata. `execute` requests `X_OK`; for directories this checks search/traversal permission, and for files it does not prove that `execve` will succeed. This is only a preflight under the current thread's credentials; it does not perform the requested operation or evaluate all configured policy. The calculated conclusion remains `unknown`. The report is private, no-clobber JSON and the command exits `2` to indicate a partial result.

On Windows, first collect a process snapshot and use the selected process row's PID and observed `creation_time.filetime_100ns` value:

```powershell
sideeffect.exe inventory processes --output .\processes.json
sideeffect.exe inventory access-check `
  --pid 1234 `
  --creation-time-filetime 134379260545106360 `
  --operation read `
  --output .\access-check.json `
  C:\path\to\file.exe
```

Replace the example PID and FILETIME with values from the same process row in your snapshot. Windows evaluates only the selected local file object's DACL against that process's primary token. After opening the selected object, SideEffect checks the handle's final NT volume path and evaluates only recognized `\Device\HarddiskVolume` paths with a numeric volume suffix; an unrecognized or remote final device path is returned unsupported. A DACL grant or denial is not a complete effective-access verdict: ancestor traversal, thread impersonation, integrity labels, remote policy, and other controls are not evaluated. Directories, reparse points, AppContainer processes, and unsupported ACE semantics return unsupported or unknown. No elevation is requested. The command writes a private, no-clobber report and exits `2` for its conditional/partial result. Treat the path, process identity, and descriptor digest as sensitive evidence.

## Inventory Linux startup configuration

```sh
./target/release/sideeffect inventory startup --output ./startup.json
```

This writes aggregate `sideeffect.startup_inventory` v3 (v2 remains readable) with separate XDG autostart, systemd unit-file/drop-in and enablement-link, common SysV init/runlevel, and common cron configuration/periodic sources. Each XDG, systemd, and legacy entry includes `startup_state` v1 with configured `present` and effective/observed `unknown`. Evidence keeps source locations and line or link-target hashes; commands and scripts are inert. It does not evaluate applicability or effective manager state, establish that a configured item runs, or cover every distribution-specific path. Missing optional paths are distinguished from inaccessible or limit-affected sources. The snapshot is sensitive and should be reviewed before sharing.

To compare a saved startup snapshot with a saved raw `strace` trace:

```sh
./target/release/sideeffect correlate-startup ./startup.json ./capture.trace
```

This writes bounded `sideeffect.startup_correlation` v1 JSON to stdout. Inventory input is capped at 64 MiB, raw trace input at 32 MiB, supported configuration rows at 50,000, copied configuration/source metadata at 8 MiB, parsed trace rows at 100,000, and JSON output at 64 MiB. Only simple literal absolute executable paths from XDG `Exec` and systemd `Service.Exec*` values are compared with the filename argument of successful `execve`/`execveat` rows. Both sides retain exact evidence references and duplicate matches remain grouped. The command never executes or shell-parses configuration values, and carries startup references from the supplied snapshot without re-reading source files. It does not parse cron/SysV or perform PATH lookup or `argv[0]` matching. It compares exact path strings as written and never resolves symlink targets or canonical paths, so a configured literal path may itself name a symlink. Unsupported values make the output partial. `complete` means processing completed only within this narrow supported subset, not full correlation coverage. Complete inputs exit `0`; partial inputs or unsupported relevant rows publish status and exit `2`; invalid inputs exit `1`. Runtime evidence calls the `strace -f` row-prefix identifier `caller_task_id`; it may identify a thread and is not necessarily a process or parent PID. A candidate is not proof that a startup hook ran or caused a process; no match does not establish non-execution. The separate snapshots are not an atomic view, and raw trace capture completeness remains unknown.

To emit an associated-behavior summary from Linux startup and trace inputs:

```sh
./target/release/sideeffect associated-behavior ./startup.json ./capture.trace
```

This command writes bounded `sideeffect.associated_behavior_summary` v1 JSON to stdout. The Linux adapter preserves source references and labels literal path equality as `candidate_match`; no match is `insufficient_evidence`, not a negative finding.

On Windows, use a saved Windows startup inventory and ETW capture:

```powershell
.\target\release\sideeffect.exe associated-behavior .\startup.json .\runtime.windows.json
```

The Windows adapter writes `sideeffect.windows_associated_behavior_summary` v1. It considers only observed Exec scheduled-task actions and decoded ETW process-start events whose executable strings are identical drive-rooted paths. It does not expand environment variables, normalize paths, or match basenames. The output retains startup action references and ETW event ordinals, labels associations as candidates, and keeps partial capture or event-loss status visible. A match does not establish that the task ran or caused the process. No match is `insufficient_evidence`, not a negative finding. The live process/file/loopback integration test passed on hosted Windows Server 2022 and 2025 in CI run [40867530573](https://github.com/tengircik/SideEffect/actions/runs/40867530573); broader provider and Windows desktop validation remain outside that test. Partial input or coverage exits `2`.

## Collect a Linux audit session

```sh
./target/release/sideeffect audit --output ./audit-session \
  --packages --processes --startup --path-executables \
  --permission ./some/file --permission ./some/directory
```

Specify one or more source selectors: `--packages`, `--processes`, `--startup`, `--path-executables`, `--root PATH`, and repeated `--permission PATH` options. Permission inspection is limited to the paths you name. The PATH source records the same one-level metadata heuristic as `inventory path-executables`; it does not execute candidates or resolve commands through a shell. `--root PATH` records metadata for direct children only by default. Add `--hash-regular-files` with `--root` to opt into schema v2 SHA-256 fingerprints; this reads direct-child regular files only, capped at 16 MiB each and 64 MiB total with a five-second cooperative deadline. Symlinks/reparse points are never followed, hashes are sensitive equality fingerprints rather than authenticity evidence, and the command does not recurse. New sessions use envelope v8; older v7 sessions retain their exact selected-root v1 contract. The command does not record runtime activity. It stores each selected inventory in its native JSON schema beside a `session.json` manifest with per-source scope, timestamps, status, selected key limits, diagnostics, artifact length, schema, and SHA-256. Collections run over a best-effort interval, not an atomic system snapshot. Partial artifacts are retained and cause exit status `2`.

The complete directory is built in a private sibling staging directory and atomically published without overwriting an existing destination. On Linux, the session directory is mode `0700` and its files are mode `0600`. Windows inventory sessions and inspection are supported using a current-user-owned directory with a protected current-user-only DACL. An explicitly selected Windows runtime source can add its bounded ETW v3 capture as a fixed `runtime.windows.json` artifact in the same audit session; runtime and containing session status remain partial because capture completeness is unknown. Artifacts can contain sensitive system and user data. There is no automatic redaction, upload, or deletion.

To verify and review the session metadata:

```sh
./target/release/sideeffect inspect --format text --session ./audit-session
```

The reader requires a current-user-owned private directory and private regular files, rejects symlinks and unlisted entries, checks bounded JSON syntax and declared schema/version headers, and verifies every declared artifact's length and SHA-256 before writing a review. It does not fully validate each inventory artifact's domain schema or print raw inventory rows. Use `--format json` for the versioned `sideeffect.audit_session_review` v7 output, which includes recorded host OS/version and caller privilege context, source settings, runtime loss state, and artifact provenance. The display-only review escapes non-ASCII and control characters in all string values as ASCII so imported metadata cannot inject terminal formatting; this encoding does not modify stored session files. Older session versions retain absent host context; it is not reconstructed. A hash match does not authenticate the session producer. Partial sessions are still reviewable and return exit status `2`.

Compare the declared collection context of two validated sessions:

```sh
./target/release/sideeffect compare-sessions ./before-session ./after-session
```

This emits `sideeffect.audit_session_diff` v2 with the existing metadata comparability status and stable reason codes, plus item-level package/software, process, startup, selected-path permission, selected-root, and Linux strace or Windows ETW runtime comparisons when both sessions contain compatible verified artifacts. Linux runtime requires matching `run.json` metadata and raw trace fingerprints before parsing. Exit status `0` means metadata `comparable` is true, including when a matching partial source is reported with the `partial_source` review reason; status `2` means it is false. Check each `source_diffs` status and reason: partial, missing, unsupported, incompatible, invalid, and over-budget source pairs do not imply empty data. PATH-executable and selected-root artifacts are compared when both sessions select those sources. Root comparisons cover direct children and require an exact root path match. Content changes are reported only when both v1/v2 artifacts contain observed hashes; absent or unavailable hashes remain unknown and make the item comparison partial. Session v7 root artifacts remain metadata-only v1; session v8 can compare v1/v2 artifacts through the verified readers. Partial sources suppress unmatched presence claims. Invalid or insecure session inputs fail through the same verified readers used by `inspect --session`. Comparable sessions do not establish equal observations, exhaustive coverage, event absence, equal caller privilege context, causation, or source authenticity.

### Sign an audit session

Create a local Ed25519 keypair explicitly:

```sh
./target/release/sideeffect provenance keygen ./sideeffect-signing-key.pk8 ./sideeffect-public-key.hex
```

The private key is an unencrypted PKCS#8 file. Protect it and keep a secure backup; anyone who obtains it can create signatures that verify under its public key. Key files are written with owner-only access and existing outputs are never replaced.

Sign a validated session. Review the displayed session metadata and type `sign` when prompted. The signature envelope is a separate file outside the session directory:

```sh
./target/release/sideeffect provenance sign-session ./audit-session \
  --private-key ./sideeffect-signing-key.pk8 \
  --output ./audit-session.signature.json
```

Verify offline by supplying the matching public key:

```sh
./target/release/sideeffect provenance verify-session ./audit-session \
  --signature ./audit-session.signature.json \
  --public-key ./sideeffect-public-key.hex
```

Verification checks the session artifacts first, then verifies the signature over the exact `session.json` bytes. Using only `--public-key` reports cryptographic validity and leaves key trust unevaluated. The recorded signing time comes from the local clock and is not a trusted timestamp. Keep the detached signature file with the session when moving or archiving it.

To make a local trust decision for a public key, import it into a user-selected trust store. Import shows the computed fingerprint and asks you to type that exact fingerprint; the label is only a local annotation:

```sh
./target/release/sideeffect provenance trust import ./sideeffect-public-key.hex \
  --trust-store ./sideeffect-trust-store \
  --label "review team"
./target/release/sideeffect provenance trust list --trust-store ./sideeffect-trust-store
./target/release/sideeffect provenance verify-session ./audit-session \
  --signature ./audit-session.signature.json \
  --trust-store ./sideeffect-trust-store
```

The trust store is explicit; SideEffect has no default/global store or network lookup. A successful trust-aware verification reports cryptographic validity and a matching local key decision separately. Unknown keys are not cryptographically verified unless you also supply `--public-key`; a valid signature from a key absent from the store is reported as valid but untrusted and exits with status 2. Remove a local trust decision with `provenance trust remove KEY_ID --trust-store DIR` and type the requested fingerprint. Removal does not publish revocation. Store permissions and the limits of local labels are described in [PROVENANCE_FORMAT.md](PROVENANCE_FORMAT.md). Trust does not establish signer identity, collector honesty, or capture completeness.

## Record a command on Linux

Install `strace` from a trusted distribution repository and confirm it reports version 6.8 or newer. On Ubuntu, these commands install system packages and change that Linux installation system-wide; they typically require administrator privileges, so run them only if you intend to make that change. `python3` is required for the Linux real-tracer integration test, not for the `record` command itself:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends strace python3
strace --version
```

Then record a command by passing the program and its arguments after `--`:

```sh
./target/release/sideeffect record --trace ./run.trace --duration-seconds 30 -- /usr/bin/printf 'hello\n'
./target/release/sideeffect inspect ./run.trace
```

SideEffect runs the selected program with your permissions; it is not a sandbox. The program can modify files, access the network, and perform actions otherwise available to your account. Recording is bounded. If the trace exceeds its byte limit, the direct `strace` process is terminated and the partial trace is discarded. Add `--duration-seconds <seconds>` with an integer from 1 to 3600 for an optional wall-clock limit; if reached, the available nonempty partial trace is published (bundle mode publishes a partial bundle) and the command exits `2`, with target outcome and capture completeness unknown. Inspecting a timed bundle also exits `2` and warns that absence is not evidence of non-occurrence; bundle diff refuses timed bundles. After a nonempty trace is finalized and published, SideEffect propagates `strace`'s reported exit code or signal. In bundle mode, a duration-limited run records `time_limit_reached` in schema v2; schema v1 bundles remain readable. The `strace(1)` manual says it normally mirrors the wrapped command's outcome. Capture errors take precedence; a propagated status does not prove tracer success or capture completeness.

Raw traces may contain command arguments, file paths, socket addresses, and other sensitive values. Keep them local unless you have reviewed them. Detailed diff reports retain event-level values. `diff-summary` omits event strings and source references but still exposes category/count patterns, which may also be sensitive; it is not a safe-to-share verdict. These commands do not upload data.

## Adapt runtime evidence into a common event envelope

```sh
./target/release/sideeffect events --trace ./run.trace
```

On native Windows, adapt a saved ETW v3 capture after the strict bounded schema and fingerprint checks:

```powershell
.\target\release\sideeffect.exe events --windows-runtime .\runtime.windows.json
```

Both commands write JSON only to stdout and read the selected file without modifying it or running represented commands. The envelope preserves source-local row order, timestamps, attempt/result or observation semantics, diagnostics, and evidence references. Its status is `partial` or `unknown` when the source or adapter cannot establish a complete supported result; those outcomes exit `2`. ETW header PID is event context and is not ownership or an actor identity. Neither adapter creates global event order, parentage, or causation. The common envelope is an output format, not a persisted capture or event graph; see [schema compatibility](SCHEMA_COMPATIBILITY.md).

Use a strict, model-independent JSON query against one source at a time. For example, save this as `query.json`:

```json
{
  "schema": "sideeffect.event_query",
  "schema_version": 1,
  "filters": {
    "event_kind": "connect",
    "operation_kind": "syscall_attempt",
    "outcome": "failure"
  },
  "limit": 100
}
```

Run it against a Linux trace:

```sh
./target/release/sideeffect query --query ./query.json --trace ./run.trace
```

Or, on native Windows, against a validated ETW capture:

```powershell
sideeffect.exe query --query .\query.json --windows-runtime .\runtime.windows.json
```

The same query can select the runtime artifact from one verified audit session:

```sh
./target/release/sideeffect query --query ./query.json --session ./audit-session --source runtime
```

```powershell
sideeffect.exe query --query .\query.json --session .\audit-session --source runtime
```

Search multiple sessions from the same native platform by repeating `--session`:

```sh
./target/release/sideeffect query --query ./query.json \
  --session ./before-session --session ./after-session --source runtime
```

```powershell
sideeffect.exe query --query .\query.json `
  --session .\before-session --session .\after-session --source runtime
```

JSON output is the default; add `--format text` for a terminal-safe summary. Version 1 allows exact `event_kind`, `operation_kind` (`syscall_attempt` or `native_observation`), typed syscall `outcome`, source-local `process_observation_id`, and an exact source-native `evidence` locator copied from an event result. Linux locators match the complete `raw_trace_record` tuple (`line_number`, `byte_offset`, `byte_length`). Windows locators match the complete `windows_etw_record` tuple (`record_ordinal`, `json_pointer`, `raw_payload_sha256`). These locators identify one source record; they do not filter or reinterpret path or time values. Unsupported fields such as path, endpoint, and timestamp filters are rejected rather than approximated. The query JSON is capped at 16 KiB, matching results at 5,000 (overflow is an error, never silent truncation), filtering at two seconds, and serialized output at 8 MiB. A multi-session query accepts 2–16 sessions, caps aggregate runtime-artifact bytes at 256 MiB, aggregate matches at 5,000, a cooperative 10-second total-work budget checked between sessions, and output at 8 MiB. Results remain nested under session IDs with separate source-local evidence; `process_observation_id` and `evidence` are rejected across sessions because their identifiers are capture-local. The result keeps exact evidence references and diagnostics/status for the entire input even if few or no events match. Session mode first uses the platform's verified session reader, then queries only each selected session's declared runtime artifact: Linux `run.json` must bind the verified `trace.strace` by exact schema, length and SHA-256; Windows requires the declared ETW v3 artifact and validates its capture fingerprint. Session status, runtime-source status, capture completeness and event parse/adaptation status stay separate. Missing or invalid selected sessions are errors, not empty results. Partial or unknown evidence exits `2`; an empty filtered result does not establish that activity was absent.

To query selected-root snapshots from one or more verified sessions, use a separate `sideeffect.inventory_query` v1 contract with exact native path/name encodings:

```json
{
  "schema": "sideeffect.inventory_query",
  "schema_version": 1,
  "filters": {
    "root_path_hex": "2f746d702f617070",
    "entry_name_hex": "636f6e6669672e6a736f6e"
  },
  "limit": 100
}
```

On Linux, the hex values encode exact path/name bytes. On native Windows, they encode exact UTF-16LE code units. No display-name decoding or path normalization is used for matching. Select one session or repeat `--session` for 2–16 sessions, then pass `--source selected_root`; JSON is the default and `--format text` prints a terminal-safe view. The query reads only each session's verified `root-snapshot.json` artifact and accepts selected-root schema v1 or v2. It validates the full document before filtering, caps one document at 64 MiB, each artifact at 10,000 entries and 8 MiB aggregate encoded names, matching rows at 5,000, aggregate selected-root input at 256 MiB, total work at 10 seconds checked between sessions, and output at 8 MiB. Results retain session/source status, source and artifact diagnostics, artifact schema/version/length/SHA-256, native root/name encodings, content-hash metadata when present, and each entry's source ordinal. A partial source stays partial. Zero matches mean only that no matching entry appears in the selected one-level snapshot; they do not establish system-wide absence or prove that entries/changes were absent. The query makes no claim that file IDs or paths establish persistent object identity.

To organize the adapted facts into an evidence-linked graph, run:

```sh
./target/release/sideeffect graph --trace ./run.trace --event-kind openat
```

On native Windows:

```powershell
sideeffect.exe graph --windows-runtime .\runtime.windows.json --event-kind file_io_observation
```

To select a source-local process observation from the graph:

```sh
./target/release/sideeffect graph --trace ./run.trace --process-observation 1
```

The same option is available with `graph --windows-runtime` on native Windows. IDs are envelope-local `ProcessObservation.source_local_id` values shown in graph output; they are neither PIDs nor identifiers that can be reused across captures. The filter retains directly linked event rows with their existing link roles, statuses, and bases, plus one-hop process relationships. It does not match unlinked events by PID. If a valid observation has no linked events, the observation node remains in the result; an empty event selection is not evidence that activity was absent. Both filters are recorded in graph schema v4. Diagnostics and completeness still describe the full input. PID-only context nodes stay separate from process observations, and the graph does not imply ownership, causation, or a complete process tree. Linux task epochs are trace-local context segments bounded by exact prefixed termination rows, not process identities or generations.

For a source-local timeline over Linux strace evidence, use an exact event-kind filter, a source-local process observation filter, or both:

```sh
./target/release/sideeffect timeline --trace ./run.trace --event-kind openat
./target/release/sideeffect timeline --trace ./run.trace --process-observation 1
```

Each item retains its source ordinal, original timestamp text, and raw trace line/byte reference for drilldown against the supplied trace. Parser diagnostics remain present after filtering. The command does not merge sources or infer causal order.

On native Windows, the same timeline view and filters are available over a strictly validated ETW v3 capture:

```powershell
sideeffect.exe timeline --windows-runtime .\runtime.windows.json --event-kind file_io_observation
sideeffect.exe timeline --windows-runtime .\runtime.windows.json --process-observation 1
```

Timeline schema v4 records the selected filters and includes all event-to-process links for displayed items, preserving each link role, status, and basis. A `--process-observation ID` uses only `ProcessObservation.source_local_id` emitted by that adapted capture; it is not a PID and cannot be reused across captures. When both filters are supplied, events must match both the exact event kind and a direct link to the selected observation; the options work in either order and duplicate or incomplete options fail clearly. The selected observation and its `evidence`/`end_evidence` remain in output when it has no linked events or the combined selection has no events. For Linux task observations, `evidence` is the first observed row, not proof of task start; for returned-child-PID observations it is only the caller's syscall result row. `end_evidence` is an exact prefixed termination row when available. An empty item selection or missing link is not proof that activity was absent. Linux items retain raw line/byte references; ETW items retain capture-local ordinal, QPC timestamp text, payload digest, and JSON pointer back to the source event. Full-source diagnostics and partial or unknown status remain visible; partial or unknown exits with status `2`. This is a source-local timeline, not a merged graph or causal sequence. Resolve a single event with `sideeffect.exe evidence --windows-runtime .\runtime.windows.json CAPTURE_SHA256 RECORD_ORDINAL RAW_PAYLOAD_SHA256`. The lookup validates the capture, then requires the fingerprint, ordinal, and raw-payload digest to match before returning that row and its source pointer. It includes capture status, loss, and diagnostics; serialized decode metadata and producer authenticity are not independently verified. Unknown completeness exits with status `2`.

## Use an existing WSL2 installation

If you already have a WSL2 Linux distribution, open its shell and follow the Linux build steps there. Rust, Cargo, `strace`, the repository checkout, and generated Linux traces belong to that environment. WSL runs do not validate native Windows ETW capture. If WSL is not installed, consult [Microsoft's WSL installation guide](https://learn.microsoft.com/windows/wsl/install); installing WSL and a Linux distribution changes Windows system configuration and is outside this project setup.

## Run the checks

The Linux all-target test suite includes a real-tracer integration test and requires both `strace` 6.8 or newer and `python3`. The test uses temporary files and a loopback-only TCP connection; it fails rather than silently skipping when a prerequisite is missing. Captures are temporary and are not uploaded as CI artifacts.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

`rustfmt` and `clippy` components are needed for the first two commands. Follow the repository's contribution guide for the current tested workflows and their limits.
