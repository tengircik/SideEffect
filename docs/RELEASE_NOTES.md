# Release notes

Version 0.1.0 was published on 2026-10-30. This page records its release scope and compatibility evidence. Download the release archives and provenance from the [GitHub release page](https://github.com/tengircik/SideEffect/releases/tag/v0.1.0).

## v0.1.0 — Portable skill, Windows runtime evidence, and schema compatibility

### Portable Agent Skill

- Added the `sideeffect-audit` Agent Skill for Codex, Claude Code, OpenCode, and compatible agents, with separate native installation guidance for Oh My Pi (OMP).
- The skill uses the installed deterministic SideEffect CLI and the user's selected agent/model; SideEffect's optional local-model commands are not a prerequisite.
- Added a telemetry-opt-out installer command pinned to the reviewed skill commit, update/removal/privacy guidance, a CI validator for package structure and safety requirements, and a capability-led README with local SVG visuals.
- Release tag [`v0.1.0`](https://github.com/tengircik/SideEffect/releases/tag/v0.1.0) points to main merge commit [`dfff59f`](https://github.com/tengircik/SideEffect/commit/dfff59ffa6ea01995bf121c6c59de9a52ba8ac4c). The [release workflow run 41104218442](https://github.com/tengircik/SideEffect/actions/runs/41104218442) passed all 13 jobs, including Linux and Windows builds, full CI, dependency checks, third-party notice verification, asset checksums, and provenance generation.
- Downloadable Linux x86_64 and Windows x64 archives, a tagged source archive, `SHA256SUMS`, third-party notices, and build-provenance attestations are published. Windows 11 desktop live ETW remains unverified.

### Windows runtime workflows

- Added `attribute --windows-runtime` as a separate evidence-linked view over a validated ETW v3 capture.
- Upgraded `sideeffect.windows_runtime_diff_summary` to v2 with exact normalized record multiset groups, conservative unique-identity candidate groups, one-sided observations, capture-loss details, and source references. Version 1 was an output-only format and is not imported.
- Updated Windows text and HTML comparison reports for event-level output. Reports remain static/offline and use the existing bounded, no-clobber publisher.
- Added a hosted CI step that checks the Windows runner token is already administrative before running the real process/file/loopback ETW acceptance test. SideEffect does not elevate a process.
- Corrected the strict ETW network decoder to accept the exact 4-byte connection-ID layout observed in Windows Server 2022/2025 records with 64-bit event headers. The documented pointer-sized form remains supported; unknown/truncated/trailing layouts remain partial and retain their raw events.
- The v0.1.0 [release workflow](https://github.com/tengircik/SideEffect/actions/runs/41104218442) passed build and live process/file/loopback ETW acceptance on Windows Server 2022 and 2025, as well as Linux, Rust 1.85 MSRV, real Ubuntu `strace`, and Agent Skill installation.

### Compatibility evidence

| Environment or source | Tested evidence | Not established |
| --- | --- | --- |
| Windows x64 developer host (Windows 11, build 26300) | `cargo test --locked --all-targets` passed on 2026-10-30; `cargo clippy --locked --all-targets -- -D warnings` and `cargo fmt --all -- --check` passed on 2026-10-29. The privileged live ETW test was ignored locally because the process token cannot control the NT Kernel Logger. | Live ETW capture on Windows 11 desktop; broad desktop-version/provider compatibility. |
| Hosted Windows Server 2022/2025 | v0.1.0 release CI passed builds/tests and live process, file-name, and loopback TCP ETW acceptance on both images ([run 41104218442](https://github.com/tengircik/SideEffect/actions/runs/41104218442)). | Windows 11 x64 privileged behavior; other provider/version combinations or exhaustive coverage. |
| Linux x86_64 | Ubuntu 24.04 CI and WSL2 runs exercised the Linux CLI and real `strace` 6.8; WSL2 also exercised `strace` 6.19. | Other Linux distributions, architectures, kernels, or general `strace` compatibility beyond the explicitly exercised versions. |
| Native Windows ETW sources | Synthetic and mutation tests validate process, selected FileIo/DiskIo, TCP/UDP decoding contracts, output references, loss handling, and attribution boundaries. The live fixture targets process start, a temporary file, and loopback TCP. | ETL import, all ETW providers/opcodes, exhaustive OS activity, complete capture, or event causation. |

This is a point-in-time v0.1.0 validation record, not a guarantee of exhaustive coverage. WSL2 is Linux validation, not Windows support. Revalidate the exact source candidate for future releases. Captures and reports may contain sensitive local evidence.
