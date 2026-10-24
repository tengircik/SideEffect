# Build and run SideEffect

## Scope and prerequisites

The current supported product target is Linux x86_64. This repository provides source code; it does not currently publish prebuilt binaries or a package repository. Windows builds cover parser/comparison workflows, but command recording and HTML file export are Linux-only. SideEffect does not provide native Windows tracing.

Builds use Rust and Cargo. `Cargo.toml` declares Rust 1.85 as its minimum version, and CI now has a dedicated Linux job configured to run formatting, Clippy, tests, and a build with Rust 1.85. Its hosted result has not yet been confirmed. Install Rust and Cargo using the [official Rust installation instructions](https://rust-lang.org/tools/install/). The Linux system also needs a C toolchain/linker for Rust targets; install one with your distribution's package manager if it is not already present.

The `record` command requires an external `strace` version 6.6 or newer. Check the installed version before recording:

```sh
strace --version
```

For example, Ubuntu 24.04's `strace` package is version 6.8 in the Ubuntu package archive ([package details](https://packages.ubuntu.com/noble/strace)). Package versions in other distributions and repositories differ; if `strace --version` reports a version below 6.6, do not use `record` with it. The Linux real-tracer integration test has passed in WSL with extracted Ubuntu packages for strace 6.8 and 6.19, without installing them system-wide; this does not verify every 6.6 build or kernel combination. Parser, diff, and evidence commands consume an existing trace and do not launch `strace`.

## Build from source

You need repository access to obtain the source. Anonymous HTTPS access to the repository has not been confirmed; if access has been granted to your account, use the clone method configured for that account (HTTPS or SSH). The HTTPS command below is an example, not a promise that the repository is publicly readable:

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

## Record a command on Linux

Install `strace` from a trusted distribution repository and confirm it reports version 6.6 or newer. On Ubuntu, these commands install system packages and change that Linux installation system-wide; they typically require administrator privileges, so run them only if you intend to make that change. `python3` is required for the Linux real-tracer integration test, not for the `record` command itself:

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

The Linux all-target test suite includes a real-tracer integration test and requires both `strace` 6.6 or newer and `python3`. The test uses temporary files and a loopback-only TCP connection; it fails rather than silently skipping when a prerequisite is missing. Captures are temporary and are not uploaded as CI artifacts.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

`rustfmt` and `clippy` components are needed for the first two commands. Follow the repository's contribution guide for the current tested workflows and their limits.
