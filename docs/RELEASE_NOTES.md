# Release notes

There is no tagged release yet. This page records the current source-candidate scope and compatibility evidence; it is not a release approval.

## Unreleased — Windows runtime evidence and schema compatibility

### Portable Agent Skill

- Added the `sideeffect-audit` Agent Skill for Codex, Claude Code, OpenCode, and compatible agents, with separate native installation guidance for Oh My Pi (OMP).
- The skill uses the installed deterministic SideEffect CLI and the user's selected agent/model; SideEffect's optional local-model commands are not a prerequisite.
- Added a telemetry-opt-out installer command pinned to the reviewed skill commit, update/removal/privacy guidance, a CI validator for package structure and safety requirements, and a capability-led README with local SVG visuals.
- Source-candidate commit [`984a2f8`](https://github.com/tengircik/SideEffect/commit/984a2f8fb65835a0caa01c872ae98858cd4bf424) passed the full [CI run](https://github.com/tengircik/SideEffect/actions/runs/40873617494) and [dependency checks](https://github.com/tengircik/SideEffect/actions/runs/40873617184), including live ETW acceptance on hosted Windows Server 2022 and 2025.
- There is not yet a tagged release or prebuilt binary distribution. The documented installation builds from source; Windows 11 desktop live ETW remains unverified.

### Windows runtime workflows

- Added `attribute --windows-runtime` as a separate evidence-linked view over a validated ETW v3 capture.
- Upgraded `sideeffect.windows_runtime_diff_summary` to v2 with exact normalized record multiset groups, conservative unique-identity candidate groups, one-sided observations, capture-loss details, and source references. Version 1 was an output-only format and is not imported.
- Updated Windows text and HTML comparison reports for event-level output. Reports remain static/offline and use the existing bounded, no-clobber publisher.
- Added a hosted CI step that checks the Windows runner token is already administrative before running the real process/file/loopback ETW acceptance test. SideEffect does not elevate a process.
- Corrected the strict ETW network decoder to accept the exact 4-byte connection-ID layout observed in Windows Server 2022/2025 records with 64-bit event headers. The documented pointer-sized form remains supported; unknown/truncated/trailing layouts remain partial and retain their raw events.
- Hosted CI run [40867530573](https://github.com/tengircik/SideEffect/actions/runs/40867530573) passed Linux, Rust 1.85 MSRV, Ubuntu 24.04 real `strace`, and live process/file/loopback ETW acceptance on Windows Server 2022 and 2025 at source commit [`797ba86`](https://github.com/tengircik/SideEffect/commit/797ba86dc41d024129da35b2fc4be7ad5eca6756).

### Compatibility evidence

| Environment or source | Tested evidence | Not established |
| --- | --- | --- |
| Windows x64 developer host (Windows 11, build 26300) | `cargo test --locked --all-targets` passed on 2026-10-30; `cargo clippy --locked --all-targets -- -D warnings` and `cargo fmt --all -- --check` passed on 2026-10-29. The privileged live ETW test was ignored locally because the process token cannot control the NT Kernel Logger. | Live ETW capture on Windows 11 desktop; broad desktop-version/provider compatibility. |
| Hosted Windows Server 2022/2025 | At source commit [`797ba86`](https://github.com/tengircik/SideEffect/commit/797ba86dc41d024129da35b2fc4be7ad5eca6756), hosted CI passed build/tests and live process, file-name, and loopback TCP ETW acceptance on both images ([run](https://github.com/tengircik/SideEffect/actions/runs/40867530573)). | Windows 11 x64 privileged behavior; other provider/version combinations or exhaustive coverage. |
| Linux x86_64 | Ubuntu 24.04 CI and WSL2 runs exercised the Linux CLI and real `strace` 6.8; WSL2 also exercised `strace` 6.19. | Other Linux distributions, architectures, kernels, or general `strace` compatibility beyond the explicitly exercised versions. |
| Native Windows ETW sources | Synthetic and mutation tests validate process, selected FileIo/DiskIo, TCP/UDP decoding contracts, output references, loss handling, and attribution boundaries. The live fixture targets process start, a temporary file, and loopback TCP. | ETL import, all ETW providers/opcodes, exhaustive OS activity, complete capture, or event causation. |

This is a point-in-time source-candidate result, not release approval. Revalidate the exact candidate before tagging. WSL2 is Linux validation, not Windows support. Captures and reports may contain sensitive local evidence.
