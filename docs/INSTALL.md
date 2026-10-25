# Build and run SideEffect

## Scope and prerequisites

The current supported product target is Linux x86_64. This repository provides source code; it does not currently publish prebuilt binaries or a package repository. Windows builds cover parser/comparison workflows, but command recording and HTML file export are Linux-only. SideEffect does not provide native Windows tracing.

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
| Linux permission inventory | Explicit paths; metadata and supported POSIX ACL xattrs only | Deterministic ACL byte fixtures, metadata/path handling, and xattr-backed filesystem tests when supported | Recursive or complete inventory, effective access decisions, and other ACL/permission sources |
| Diff | Exact multiset comparison of parsed syscall rows; PID/timestamp prefixes alone are ignored | Synthetic pairs plus real integration trace pair | Root cause, causal links, normalized paths/FDs, or complete OS observation |
| Windows | Parser/comparison build workflows only | Windows CI build, Clippy, and tests | Native Windows recording or HTML file export |

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

## Inspect selected Linux file permissions and ACLs

```sh
./target/release/sideeffect inventory permissions --output ./permissions.json ./some/file ./some/directory
```

This is a read-only check of explicit paths only. It records file type, UID/GID, mode, and supported POSIX access ACLs (and directory default ACLs); it does not recurse or determine effective access for any user. Final-component symlinks are not followed, and intermediate path components use normal Linux resolution. The collector uses `/proc/self/fd` to read ACL xattrs from its pinned object descriptor, so procfs must be available for ACL collection. Permission denial, unsupported xattrs, malformed data, and configured limits produce a partial JSON snapshot and exit status `2`; no privilege escalation is requested. Its five-second deadline is checked between paths; a filesystem syscall already in progress cannot be canceled and may run longer. The output is private mode `0600`, does not replace an existing path, and stays until you delete it. It contains sensitive paths, account IDs, modes, and raw ACL bytes; review it before sharing.

## Record a command on Linux

Install `strace` from a trusted distribution repository and confirm it reports version 6.8 or newer. On Ubuntu, these commands install system packages and change that Linux installation system-wide; they typically require administrator privileges, so run them only if you intend to make that change. `python3` is required for the Linux real-tracer integration test, not for the `record` command itself:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends strace python3
strace --version
```

Then record a command by passing the program and its arguments after `--`:

```sh
./target/release/sideeffect record --trace ./run.trace -- /usr/bin/printf 'hello\n'
./target/release/sideeffect inspect ./run.trace
```

SideEffect runs the selected program with your permissions; it is not a sandbox. The program can modify files, access the network, and perform actions otherwise available to your account. Recording is bounded, but if the trace exceeds its limit the direct `strace` process is terminated and the partial trace is discarded. After a nonempty trace is finalized and published, SideEffect propagates `strace`'s reported exit code or signal. The `strace(1)` manual says it normally mirrors the wrapped command's outcome. Capture errors take precedence; a propagated status does not prove tracer success or capture completeness.

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
