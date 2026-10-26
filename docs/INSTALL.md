# Build and run SideEffect

## Scope and prerequisites

The current full product target is Linux x86_64. This repository provides source code; it does not currently publish prebuilt binaries or a package repository. Windows currently supports parser/comparison workflows, a native process snapshot, and a bounded startup-configuration slice; package, selected-path permission, service/task startup, runtime-capture, and HTML-report workflows remain incomplete. Linux command recording and HTML file export are Linux-only. SideEffect does not provide native Windows tracing.

Windows is a first-class product target in the roadmap. The process snapshot and selected startup configuration sources are initial M10 slices; most native inventory sources and bounded runtime capture are not implemented yet. Passing Windows builds and smoke tests do not mean Windows is ready for the full audit. The cross-platform 1.0 release gate requires broader native Windows inventory and record/inspect/diff workflows with real Windows validation. WSL2 runs count only as Linux-environment validation.

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
| Windows | Current: parser/comparison workflows, Tool Help process snapshot, and partial Run/RunOnce + Startup-folder inventory. Planned: package, permission, service/task startup, bounded runtime capture, and offline reports | Windows CI build, Clippy, tests, process/startup inventory smoke tests | Other native inventory sources, service/task startup, recording, report export, and broader Windows validation matrix |

The capture filter selects syscall families using `strace`'s own versioned definitions. SideEffect's parser is not an exhaustive syscall allowlist: it recognizes supported outer record syntax and preserves raw arguments/results, while the outcome and path-hint derivations above remain deliberately narrow. Diff category labels are syscall-name buckets, not claims about successful effects.

The latest hosted validation snapshot before this documentation-only update is commit `a6bb3a7a2b2a691f182bf7fbc194f8bb7a703721` on 2026-10-25: Linux, Rust 1.85 MSRV, Ubuntu 24.04 real-tracer compatibility, and Windows CI jobs passed, including Clippy, tests, debug/release builds, and release CLI smoke check. See the [CI run](https://github.com/tengircik/SideEffect/actions/runs/40204100065). The dependency advisory and declared-license jobs passed at commit `bd0316079edd46449cfbdec4127a2c80f5365da4` in the [dependency audit run](https://github.com/tengircik/SideEffect/actions/runs/40201712795); dependencies and package metadata were unchanged afterward. These point-in-time checks are not legal clearance, broad compatibility proof, or release approval.

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

This first native Windows inventory writes `sideeffect.windows_process_inventory` v1 using one Tool Help process snapshot and queries image paths only where `PROCESS_QUERY_LIMITED_INFORMATION` is available. It does not read command lines, inspect memory, start processes, or request elevation. The snapshot and path queries happen at different times, so processes can exit or identifiers can be reused between them. Protected or inaccessible paths are reported as unknown, make the result partial, and produce exit status `2`. The scan is limited to 8,192 process entries, 10 seconds, 32,768 UTF-16 code units per path, 4 Mi aggregate path code units, and 64 MiB of JSON. The output is staged under an explicit current-user-only Windows DACL and is published without replacing an existing destination. Process names and image paths can be sensitive; review before sharing. Other Windows inventory sources and runtime capture are not yet implemented.

The partial Windows startup command writes `sideeffect.windows_startup_inventory` v1. It checks current-user and accessible machine Run/RunOnce registry values plus current-user/common Startup folders; registry strings are inert, environment variables are not expanded, and shortcut contents are not opened. Service-start configuration and scheduled-task triggers are explicitly `not_checked`, so the overall status remains partial. The scan caps registry values and folder entries at 4,096 each, registry data at 64 KiB per value and 4 MiB aggregate, value names at 16,384 UTF-16 code units each and 1 Mi aggregate, paths at 32,768 code units each and 4 Mi aggregate, and duration at 10 seconds. Output uses the same current-user-only DACL and no-clobber publisher.

## Inspect selected Linux file permissions and ACLs

```sh
./target/release/sideeffect inventory permissions --output ./permissions.json ./some/file ./some/directory
```

This is a read-only check of explicit paths only. It records file type, UID/GID, mode, and supported POSIX access ACLs (and directory default ACLs); it does not recurse or determine effective access for any user. Final-component symlinks are not followed, and intermediate path components use normal Linux resolution. The collector uses `/proc/self/fd` to read ACL xattrs from its pinned object descriptor, so procfs must be available for ACL collection. Permission denial, unsupported xattrs, malformed data, and configured limits produce a partial JSON snapshot and exit status `2`; no privilege escalation is requested. Its five-second deadline is checked between paths; a filesystem syscall already in progress cannot be canceled and may run longer. The output is private mode `0600`, does not replace an existing path, and stays until you delete it. It contains sensitive paths, account IDs, modes, and raw ACL bytes; review it before sharing.

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

If you already have a WSL2 Linux distribution, open its shell and follow the Linux build steps there. Rust, Cargo, `strace`, the repository checkout, and generated traces belong to that Linux environment. Native Windows tracing is not supported. If WSL is not installed, consult [Microsoft's WSL installation guide](https://learn.microsoft.com/windows/wsl/install); installing WSL and a Linux distribution changes Windows system configuration and is outside this project setup.

## Run the checks

The Linux all-target test suite includes a real-tracer integration test and requires both `strace` 6.8 or newer and `python3`. The test uses temporary files and a loopback-only TCP connection; it fails rather than silently skipping when a prerequisite is missing. Captures are temporary and are not uploaded as CI artifacts.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

`rustfmt` and `clippy` components are needed for the first two commands. Follow the repository's contribution guide for the current tested workflows and their limits.
