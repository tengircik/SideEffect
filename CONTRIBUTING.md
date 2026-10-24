# Contributing to SideEffect

Thank you for your interest in SideEffect.

## Current project state

The repository has an early Rust implementation of `sideeffect inspect TRACE`: it reads one bounded local trace file and writes a schema-v1 JSON evidence document to stdout. Capture, paired-run comparison, HTML reporting, and CI are not implemented yet. A synthetic fixture exercises the parser but is not a real `strace` capture. Please do not report a real-tracer integration as passing unless it was run with `strace` installed.

Before proposing implementation work, read:

- [`docs/PRODUCT.md`](docs/PRODUCT.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/PLAN.md`](docs/PLAN.md)
- [`SECURITY.md`](SECURITY.md)

The intended capture target is a Rust CLI for Linux x86_64 using an external `strace` executable. Existing WSL2 may be used as a Linux environment, but native Windows tracing is not in the initial scope. The current parser-only command does not invoke `strace`; no LLM or hosted service is required.

## Local checks

From the repository root, the current checks are:

```sh
cargo fmt --all --check
cargo test --all-targets
cargo run -- inspect tests/fixtures/strace/synthetic-minimal.trace
```

The included trace is synthetic. Parser and CLI tests do not validate compatibility with a real `strace` release. A real capture integration test remains future work and requires an installed supported tracer.

`cargo fmt --all --check` requires the `rustfmt` component; no toolchain components are installed automatically by this repository.

## How to propose a change

1. Check the current planning documents and open work, if repository issues are enabled, to avoid duplicating a decision or proposal.
2. Keep a change focused. For a scope change, explain the user problem, the expected evidence or output, platform/dependency impact, and security or privacy implications.
3. Open a pull request with a clear summary and list the checks you actually performed. If a check could not be run, say so.
4. Update the relevant planning and security documentation when a change affects product claims, capture scope, data handling, platform support, or limitations.

There is no contribution agreement, DCO sign-off, or code style tool configured at this stage. Contributions intentionally submitted for inclusion are governed by the Apache License, Version 2.0, as described in [`LICENSE`](LICENSE).

## Documentation changes

There is no configured documentation build or link checker. Review Markdown rendering and links manually when practical, and identify that review in the pull request. Do not claim automated validation that has not been set up and run.

## Future implementation contributions

New behavior should include automated tests. The planning documents describe remaining acceptance targets for capture, comparison, incomplete traces, JSON compatibility, and offline HTML; those targets are not tests that currently exist. Keep synthetic fixtures clearly labeled and add real-tracer tests only when the external prerequisite is available.

Use synthetic or deliberately generated fixtures. Do not commit traces, command output, screenshots, or reports from real systems unless they have been carefully reviewed and sanitized. SideEffect traces may contain sensitive command arguments, paths, network endpoints, or output, and there is no automatic secret-removal guarantee.

Keep implementation claims consistent with the security boundary: the traced command runs with the caller's permissions; SideEffect is not a sandbox or security verdict; and event order or correlation is not proof of cause. See [`SECURITY.md`](SECURITY.md) before proposing changes to capture, parsing, export, or reporting behavior.
