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
```

After verification, extract the archive to a new versioned directory under `~/.local/opt/SideEffect/`. Copy its `sideeffect` executable to `~/.local/bin/sideeffect` only if that destination does not already exist. Add `~/.local/bin` to the current agent or shell `PATH`, then run `sideeffect version`. Do not overwrite an existing CLI without checking its version and location first.

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
```

After verification, expand the archive into a new versioned directory under `$env:LOCALAPPDATA\Programs\SideEffect`. Do not extract over an existing installation. Run `sideeffect.exe version` from that directory; add that directory to the current agent process `PATH` if you want to invoke `sideeffect` by name. A user-level PATH entry can be added separately for future sessions; administrator access is not required.

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
| Linux package inventory | dpkg, RPM, pacman, and APK adapters at fixed system paths; other detected managers are unsupported | Adapter/parser fixtures and live dpkg CLI inventory in Linux CI | Complete software inventory, custom/user manager paths, and all distributions or package formats |
| Linux process inventory | Visible `/proc` status fields and bounded `/proc/PID/exe` link text | Synthetic procfs fixtures and Linux CLI tests | Atomic or exhaustive process coverage; command lines or executable contents |
| Linux startup configuration | Aggregate schema v2: curated XDG, systemd, SysV, and cron source snapshots with inert evidence | CLI tests and deterministic source/parser fixtures | Effective applicability, manager runtime state, all distribution-specific paths, or exhaustive startup coverage |
| Diff | Exact multiset comparison of parsed syscall rows; PID/timestamp prefixes alone are ignored | Synthetic pairs plus real integration trace pair | Root cause, causal links, normalized paths/FDs, or complete OS observation |
| Windows native x64 | Bounded inventory and experimental ETW v3 capture, inspection, event-level diff v2, attribution candidate view, and audit-session integration | Local Windows x64 `cargo test --locked --all-targets`, Clippy and format checks; hosted Windows Server 2022/2025 build/test and live process/file/loopback acceptance at exact commit [`797ba86`](https://github.com/tengircik/SideEffect/commit/797ba86dc41d024129da35b2fc4be7ad5eca6756) ([CI run](https://github.com/tengircik/SideEffect/actions/runs/40867530573)) | Windows 11 x64 privileged live ETW validation, ETL import, exhaustive inventory/event coverage, all provider/version combinations, and general Windows compatibility |

The capture filter selects syscall families using `strace`'s own versioned definitions. SideEffect's parser is not an exhaustive syscall allowlist: it recognizes supported outer record syntax and preserves raw arguments/results, while the outcome and path-hint derivations above remain deliberately narrow. Diff category labels are syscall-name buckets, not claims about successful effects.

The latest complete hosted validation is exact source commit [`984a2f8`](https://github.com/tengircik/SideEffect/commit/984a2f8fb65835a0caa01c872ae98858cd4bf424) on 2026-10-29: Linux, Rust 1.85 MSRV, Ubuntu 24.04 real-tracer compatibility, and Windows Server 2022/2025 jobs passed; both Windows jobs ran the live ETW acceptance fixture. See [CI run 40873617494](https://github.com/tengircik/SideEffect/actions/runs/40873617494). Dependency license and advisory checks passed for the same candidate in [audit run 40873617184](https://github.com/tengircik/SideEffect/actions/runs/40873617184). These point-in-time checks are not legal clearance, broad compatibility proof, or release approval.

## Optional local model setup

Model management is available through `sideeffect model list`, `show ID`, `install ID`, `setup ID`, `add`, `select TASK ID`, and `remove ID`. The registry records a separate selection for evidence selection, explanation, and query-plan analysis. It stores bounded model metadata and selected IDs in a private per-user `model-registry.json`: `%LOCALAPPDATA%\SideEffect` on Windows, or `$XDG_DATA_HOME/SideEffect` on Linux (default `$HOME/.local/share/SideEffect`). Downloaded weights are stored in the sibling `models` directory with restrictive user-only permissions or ACLs. A custom model registration refers to the file the user supplied; unregistering it does not delete that file.

Catalog installation is an explicit user action and is available only for catalog entries whose analysis task is supported on the current platform. The catalog contains evidence-selection and query-plan models for Linux x86_64, plus an explanation model for Linux x86_64 and native Windows. For the shortest flow, run `sideeffect model setup ID`; it displays the immutable source, size, platform scope, license terms and evaluation note, downloads after the exact `ACCEPT <license-id>` response, verifies the file, and selects it for its declared task. `sideeffect model install ID` downloads without selecting. Acceptance for that exact catalog model/revision/license is persisted in the local registry before network access, including if the transfer later fails or is cancelled. The downloader fetches only the pinned Hugging Face file over HTTPS, allows only approved HTTPS redirects, enforces the catalog size and SHA-256, writes a private staging file, and publishes without replacing an existing destination. It sends no trace or prompt data. No model is positively recommended for quality. The inference runtime remains separately obtained and installed by the user.

After installation, select the model for its task. An existing local GGUF can instead be registered with `sideeffect model add --name NAME --path FILE --for evidence|explanation|query[,TASK...] [--license ID]`; the user-provided license label is unverified metadata. `model select TASK ID` checks the model file and hash before saving the per-task selection. The exact model ID, hash, source/revision or user-provided marker, license/evaluation status and pinned runtime/backend metadata are included in each relevant preview digest and output. Changing the selection invalidates the old confirmation and requires a fresh preview. `model remove ID` requires typing the exact ID before deleting a verified catalog file; removing a custom model only removes its registration.

The model manager and catalog can be inspected on Windows. Catalog query-plan inference and the evidence-selection command are Linux x86_64 only; the catalog explanation model and explanation command support Linux x86_64 and native Windows. Windows explanation supports `auto`, `cpu`, or `cuda`. A local custom GGUF can be registered only for a task supported on that platform. Runtime setup remains separate: SideEffect does not download or install llama.cpp or another runtime. Model/runtime compatibility does not imply model quality, and no candidate has passed its applicable semantic gate. See the task-specific setup and limitations in [evidence selection](LOCAL_MODEL_EVALUATION.md), [query plans](LOCAL_QUERY_PLAN_EVALUATION.md), and [explanations](LOCAL_MODEL_EXPLANATION_EVALUATION.md).

## Build from source

The source repository is public and can be cloned over HTTPS or SSH:

```sh
git clone https://github.com/tengircik/SideEffect.git
cd SideEffect
cargo build --locked --release --bin sideeffect
./target/release/sideeffect --version
```

The binary remains in `target/release/`; this project does not install it into a system directory. Cargo may download locked Rust dependencies from the configured registry. Review organization or network policy before allowing dependency downloads.

Try the parser with the included synthetic trace:

```sh
./target/release/sideeffect inspect tests/fixtures/strace/synthetic-minimal.trace
```

This does not require `strace`. The fixture is illustrative data, not a capture from a real machine.

## Inventory processes on Windows

```powershell
.\target\release\sideeffect.exe inventory processes --output .\processes.json
```

This first native Windows inventory writes `sideeffect.windows_process_inventory` v1 using one Tool Help process snapshot and queries image paths only where `PROCESS_QUERY_LIMITED_INFORMATION` is available. It does not read command lines, inspect memory, start processes, or request elevation. The snapshot and path queries happen at different times, so processes can exit or identifiers can be reused between them. Protected or inaccessible paths are reported as unknown, make the result partial, and produce exit status `2`. The scan is limited to 8,192 process entries, 10 seconds, 32,768 UTF-16 code units per path, 4 Mi aggregate path code units, and 64 MiB of JSON. The output is staged under an explicit current-user-only Windows DACL and is published without replacing an existing destination. Process names and image paths can be sensitive; review before sharing.

## Experimental Windows process, file, and network capture

```powershell
.\target\release\sideeffect.exe record --windows-etw .\capture.json --duration-seconds 10 -- cmd.exe /C exit 0
```

This workflow starts the NT Kernel Logger before launching the selected program with arguments passed directly, without shell-string reconstruction. It enables process, selected FileIo, DiskIo, and TCP/UDP event classes; FileIo name records require both `DISK_FILE_IO` and `DISK_IO`. Its target runtime deadline begins after the real-time consumer is ready; the recorded interval begins immediately after ETW session start. It writes `sideeffect.windows_runtime_capture` v3 JSON with ETW event headers, exact raw user-data payload bytes, and strict process, selected file/disk-operation, and TCP/UDP observations. Process payloads are accepted only after event identity, version, TDH schema, property types, and lengths validate. File/network payload decoding accepts only event ID 0, schema version 2, explicit opcodes and bounded layouts; for the tested Windows Server 2022/2025 network events, connection IDs are 4 bytes even when the event header is 64-bit. The decoder accepts this observed form only when it exactly ends the payload, as well as the exact pointer-sized form; truncation and trailing bytes remain malformed. DiskIo decoding accepts event ID 0, schema version 0, and the supported read/write/flush layouts. Unknown/malformed enabled events retain raw bytes and make collection partial. File names may omit the drive letter; read/write records report requested bytes, not completed bytes. Target PID/exit status, capture interval, configured bounds, and session loss statistics are included. Final loss counters come from a successful STOP response. If STOP fails, the available pre-stop query is labeled non-final and collection is partial; cleanup retries STOP once. The capture is system-wide. Header PID/TID remain separate event-context fields. Review output with `sideeffect inspect --windows-runtime capture.json` or `sideeffect attribute --windows-runtime capture.json`; inspection validates the bounded v3 representation, while attribution emits conservative candidate relationships without changing the capture. Neither authenticates the source or proves capture completeness. The dedicated `diff --windows-runtime BEFORE.json AFTER.json` command compares category counts and event-level records; exact matches ignore only record ordinal and QPC timestamp, while unique changed identities are labeled candidate pairs. ETW captures remain unsupported by ordinary Linux trace diff and bundles.

The NT Kernel Logger may be in use by another application. Controlling this kernel session requires administrative privileges. SideEffect never elevates automatically and fails before launching the target when session creation or consumer startup is denied. Capture includes process, selected FileIo/DiskIo, and TCP/UDP observations as described above; the stream remains system-wide and events are not attributed to the selected target. Duration is limited to 1–60 seconds. On timeout SideEffect terminates only the selected direct process; descendants can continue after capture stops. Limits are 50,000 events, 8 MiB aggregate payload, 64 KiB per event, and 32 MiB serialized JSON. Session loss counters, unavailable statistics, unsupported process opcodes, limits, timeout, or stop failures make collection partial. Even a clean session has `capture_completeness: unknown`; it does not claim complete system capture.

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

Both inputs must pass the bounded v3 reader and representation-fingerprint check. Summary schema v2 preserves fixed category counts and ordinals, compares exact normalized event records as multisets (excluding only record ordinal and QPC timestamp), and labels unique supported operation/path or process/image matches as candidates. Each event group points to both capture fingerprints and record ordinals. Partial/loss-affected inputs do not turn one-sided observations into removals or additions; ambiguity and capture diagnostics remain visible. No count, exact representation match, or candidate identity proves cause or system-level absence. Capture completeness remains unknown; partial status yields exit `2`. The HTML variant is native Windows only and uses the protected, no-clobber publisher, CSP that blocks scripts/network sources, and the 64 MiB output cap. The result may contain sensitive local evidence.

To see a separate process and event attribution view for the selected runtime capture, run `sideeffect.exe attribute --windows-runtime .\capture.json`. It uses only validated process-start parent IDs, documented network payload process IDs, and file/disk header IDs as context candidates. It reports source ordinals, ambiguity, unsupported lifecycle records, and loss; it does not infer file ownership or causation.

The Windows startup command writes `sideeffect.windows_startup_inventory` v4. It checks selected current-user and accessible machine Run/RunOnce registry values, current-user/common Startup folders, visible Win32/driver service configuration, and boot/logon triggers from local Task Scheduler tasks visible to the current token (including hidden tasks). Task rows include task path, task/trigger enabled states, trigger kind, and a logon user when available. For those tasks, indexed action rows preserve the action kind; Exec actions include inert executable path, arguments, and working directory. Unsupported action kinds and unreadable/over-limit values remain explicit with partial status/diagnostics. No task action is run, expanded, or shell-parsed; task XML is not collected. COM connects locally using the current token and no alternate credentials; there is no automatic elevation. Values, paths, and task metadata stay inert: environment variables are not expanded, commands are not parsed/executed, and shortcut contents are not opened. Task collection bounds traversal to 1,024 folders at depth 16 and 8,192 tasks, trigger rows, and action rows; 256 triggers and actions per task; 32,768 UTF-16 units per stored string; 4 Mi UTF-16 units in aggregate; 256 diagnostics; and the shared 10-second deadline checked between calls. The deadline cannot cancel an in-flight Windows API call. Service enumeration/query is bounded to 8,192 entries, a 256 KiB SCM enumeration buffer, 64 KiB per service configuration and 4 MiB aggregate configuration bytes, 32,768 UTF-16 code units per service string and 4 Mi aggregate service-string units. Registry values/folder entries are capped at 4,096 each; registry data at 64 KiB per value and 4 MiB aggregate; value names at 16,384 UTF-16 units each and 1 Mi aggregate; and paths at 32,768 units each and 4 Mi aggregate. Output uses the current-user-only DACL and no-clobber publisher. Inaccessible or over-limit sources remain partial/unknown. Task Scheduler's current-token-visible task set is not an all-users guarantee, and this inventory does not establish that an entry applies or ran.

On Windows, `inventory packages` writes the separate `sideeffect.windows_software_inventory` v1 schema. It reads selected values from HKCU native/32-bit and accessible HKLM 64/32-bit `Software\Microsoft\Windows\CurrentVersion\Uninstall` views. The collector does not use `Win32_Product`, expand `REG_EXPAND_SZ`, parse commands, or launch uninstallers. It limits registrations to 8,192 total and 2,048 per registry view; subkey names to 16,384 UTF-16 code units; selected value data to 64 KiB each and 4 MiB aggregate; aggregate subkey names to 1 Mi UTF-16 code units; and the scan to a 10-second deadline checked between registry calls. An in-flight Windows API call cannot be cancelled and can exceed that interval. Exact returned value bytes are retained as hexadecimal. Inaccessible, malformed, unsupported, and limit-affected data remain partial/unknown. Output uses the current-user-only DACL and no-clobber publisher. Portable, unregistered, and other package formats can be absent.

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

## Inventory Linux startup configuration

```sh
./target/release/sideeffect inventory startup --output ./startup.json
```

This writes aggregate `sideeffect.startup_inventory` v2 with separate XDG autostart, systemd unit-file/drop-in and enablement-link, common SysV init/runlevel, and common cron configuration/periodic sources. Evidence keeps source locations and line or link-target hashes; commands and scripts are inert. It does not evaluate applicability or effective manager state, establish that a configured item runs, or cover every distribution-specific path. Missing optional paths are distinguished from inaccessible or limit-affected sources. The snapshot is sensitive and should be reviewed before sharing.

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
  --packages --processes --startup \
  --permission ./some/file --permission ./some/directory
```

Specify one or more source selectors: `--packages`, `--processes`, `--startup`, and repeated `--permission PATH` options. Permission inspection is limited to the paths you name. The command does not record runtime activity. It stores each selected inventory in its native JSON schema beside a `session.json` manifest with per-source scope, timestamps, status, selected key limits, diagnostics, artifact length, schema, and SHA-256. Collections run over a best-effort interval, not an atomic system snapshot. Partial artifacts are retained and cause exit status `2`.

The complete directory is built in a private sibling staging directory and atomically published without overwriting an existing destination. On Linux, the session directory is mode `0700` and its files are mode `0600`. Windows inventory sessions and inspection are supported using a current-user-owned directory with a protected current-user-only DACL. An explicitly selected Windows runtime source can add its bounded ETW v3 capture as a fixed `runtime.windows.json` artifact in the same audit session; runtime and containing session status remain partial because capture completeness is unknown. Artifacts can contain sensitive system and user data. There is no automatic redaction, upload, or deletion.

To verify and review the session metadata:

```sh
./target/release/sideeffect inspect --format text --session ./audit-session
```

The reader requires a current-user-owned private directory and private regular files, rejects symlinks and unlisted entries, checks bounded JSON syntax and declared schema/version headers, and verifies every declared artifact's length and SHA-256 before writing a review. It does not fully validate each inventory artifact's domain schema or print raw inventory rows. Use `--format json` for the versioned `sideeffect.audit_session_review` v2 output. A hash match does not authenticate the session producer. Partial sessions are still reviewable and return exit status `2`.

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
