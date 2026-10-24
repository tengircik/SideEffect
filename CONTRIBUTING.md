# Contributing to SideEffect

Thank you for your interest in SideEffect.

## Current project state

The repository is currently at the planning and documentation stage. There is no implemented CLI, build command, automated test suite, or CI workflow yet. The command examples in the planning documents are sketches, not executable commands. Please do not report a build or test as passing unless that check exists and you actually ran it.

For now, useful contributions include correcting or clarifying the product brief, architecture plan, delivery plan, and security guidance. Before proposing implementation work, read:

- [`docs/PRODUCT.md`](docs/PRODUCT.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/PLAN.md`](docs/PLAN.md)
- [`SECURITY.md`](SECURITY.md)

The current target is a Rust CLI for Linux x86_64 using an external `strace` executable. Use through an already installed WSL2 environment may be possible, but native Windows tracing is not in the initial scope. The product is local-first and does not require an LLM or hosted service.

## How to propose a change

1. Check the current planning documents and open work, if repository issues are enabled, to avoid duplicating a decision or proposal.
2. Keep a change focused. For a scope change, explain the user problem, the expected evidence or output, platform/dependency impact, and security or privacy implications.
3. Open a pull request with a clear summary and list the checks you actually performed. If a check could not be run, say so.
4. Update the relevant planning and security documentation when a change affects product claims, capture scope, data handling, platform support, or limitations.

There is no contribution agreement, DCO sign-off, or code style tool configured at this stage. Contributions intentionally submitted for inclusion are governed by the Apache License, Version 2.0, as described in [`LICENSE`](LICENSE).

## Documentation changes

There is no configured documentation build or link checker yet. Review Markdown rendering and links manually when practical, and identify that review in the pull request. Do not claim automated validation that has not been set up and run.

## Future implementation contributions

When implementation begins, new behavior should include automated tests. The planning documents describe acceptance targets for capture, parsing, comparison, incomplete traces, JSON, and offline HTML; those targets are not tests that currently exist. The project should add and document real build and test commands before asking contributors to run them.

Use synthetic or deliberately generated fixtures. Do not commit traces, command output, screenshots, or reports from real systems unless they have been carefully reviewed and sanitized. SideEffect traces may contain sensitive command arguments, paths, network endpoints, or output, and there is no automatic secret-removal guarantee.

Keep implementation claims consistent with the security boundary: the traced command runs with the caller's permissions; SideEffect is not a sandbox or security verdict; and event order or correlation is not proof of cause. See [`SECURITY.md`](SECURITY.md) before proposing changes to capture, parsing, export, or reporting behavior.
