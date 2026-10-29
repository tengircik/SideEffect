# Release notes

There is no tagged release yet. This page records the current source-candidate scope and compatibility evidence; it is not a release approval.

## Unreleased — Windows runtime evidence and schema compatibility

### Windows runtime workflows

- Added `attribute --windows-runtime` as a separate evidence-linked view over a validated ETW v3 capture.
- Upgraded `sideeffect.windows_runtime_diff_summary` to v2 with exact normalized record multiset groups, conservative unique-identity candidate groups, one-sided observations, capture-loss details, and source references. Version 1 was an output-only format and is not imported.
- Updated Windows text and HTML comparison reports for event-level output. Reports remain static/offline and use the existing bounded, no-clobber publisher.
- Added a hosted CI step that checks the Windows runner token is already administrative before running the real process/file/loopback ETW acceptance test. SideEffect does not elevate a process.

### Compatibility evidence

| Environment or source | Tested evidence | Not established |
| --- | --- | --- |
| Windows x64 developer host (Windows 11, build 26300) | `cargo test --locked --all-targets`, `cargo clippy --locked --all-targets -- -D warnings`, and `cargo fmt --all -- --check` passed on 2026-10-29. The privileged live ETW test was skipped locally because the token cannot control the NT Kernel Logger. | Live ETW capture on Windows 11 desktop; broad desktop-version/provider compatibility. |
| Hosted Windows Server 2022/2025 | Existing hosted build/test matrices cover native Windows inventory, session, CLI, and deterministic ETW schema behavior. The live ETW acceptance step is configured and its result must be recorded for the exact release candidate before claiming it passed. | A successful live-ETW result for an unrun source revision; Windows 11 x64 privileged behavior. |
| Linux x86_64 | Ubuntu 24.04 CI and WSL2 runs exercised the Linux CLI and real `strace` 6.8; WSL2 also exercised `strace` 6.19. | Other Linux distributions, architectures, kernels, or general `strace` compatibility beyond the explicitly exercised versions. |
| Native Windows ETW sources | Synthetic and mutation tests validate process, selected FileIo/DiskIo, TCP/UDP decoding contracts, output references, loss handling, and attribution boundaries. The live fixture targets process start, a temporary file, and loopback TCP. | ETL import, all ETW providers/opcodes, exhaustive OS activity, complete capture, or event causation. |

Review the exact linked CI runs and update this table before tagging. WSL2 is Linux validation, not Windows support. Captures and reports may contain sensitive local evidence.
