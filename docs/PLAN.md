# SideEffect Delivery Plan

**Status:** proposed sequence for future implementation. This is not a schedule, a claim of completed work, or permission to change scope. All commands/features below remain proposed until implemented and verified.

## Milestone 0 — Repository and dependency decision

- Review repository guidance and existing project state before implementation.
- Confirm available Rust toolchain and Linux x86_64 development/test environment; do not install a toolchain as part of documentation work.
- Define the supported `strace` range, exact initial syscall set, command/exit-status contract, storage layout, and JSON schema policy.
- Record explicit resource budgets before parser/report implementation: input bytes, record and string length, event/collection counts, comparison growth, and rendered-output size. The budgets must be reviewed and documented; no numeric threshold is assumed by this plan.
- Decide the Linux filesystem operations needed to create evidence bundles and atomically publish reports without following attacker-controlled symlinks or replacing existing user files. See [SECURITY.md](../SECURITY.md).
- Resolve licensing and packaging implications of depending on an external `strace` executable before distribution.

**Exit criteria:** written implementation decisions identify supported platform/tool versions, known observation limits, status/error semantics, documented resource budgets, safe no-follow/no-clobber output semantics, and unresolved items. No unsupported native Windows promise.

## Milestone 1 — Capture a single run

- Implement proposed command wrapping and external `strace` invocation.
- Record raw trace, stdout/stderr, command exit status, tracer status/version/arguments, and capture diagnostics.
- Follow child processes where the chosen trace mode supports it.
- Keep command status distinct from tracer/parser/report failures.

**Exit criteria:** automated integration fixtures prove a child execution and selected file/network calls are captured; command stdout/stderr and exit result are handled according to the documented contract; missing tracer and tracer failure produce clear diagnostics; raw records remain inspectable; output tests prove an existing destination or symlink target is not overwritten/followed and failed writes do not publish partial final bundles.

## Milestone 2 — Parse and model evidence

- Implement a bounded parser for the supported `strace` version/output mode.
- Add a versioned run record and event schema with raw-evidence references.
- Represent process, file, and connection-related observations without overstating success or identity.
- Track parse errors, unsupported records, and detectable incomplete/truncated input.

The parser and renderer must enforce the explicit budgets recorded in Milestone 0. Test each chosen file, record, string, event/collection, comparison, and rendered-output limit at the accepted boundary and just beyond it. Oversized, malformed, and truncated input must not cause unbounded allocation or silent truncation.

**Exit criteria:** fixture tests cover success/failure returns, child processes, cwd/dirfd/path resolution, concurrent or unfinished calls, malformed and unsupported records, and evidence-reference integrity. Unresolved path or process data remains explicitly unresolved.

## Milestone 3 — Compare two runs

- Define and document canonical event keys separately from exact captured values.
- Implement added/removed/changed event grouping with links to both runs' source evidence.
- Add only justified normalization for run-local identities and timing; keep descriptor/path uncertainty visible.
- Preserve and explain ambiguous matches instead of hiding them.

**Exit criteria:** fixtures show that timestamp/PID-only changes do not create spurious differences when a justified mapping exists; meaningful process/file/network changes are reported; unstable event ordering and ambiguous matches are represented; normalization never destroys raw values.

## Milestone 4 — Export JSON and offline HTML

- Serialize versioned JSON.
- Render a self-contained, offline HTML comparison report.
- Escape all trace-derived content and keep raw evidence references accessible.
- Show per-run capture status, diagnostics, observed changes, and uncertainty.
- State clearly that reports may contain secrets and are not automatically sanitized.

Report generation must enforce the documented event/string/output budgets. Create completed reports atomically without following destination symlinks or replacing existing files; define cleanup behavior for failed or interrupted writes.

**Exit criteria:** schema/round-trip tests pass; HTML tests prove trace-provided markup is inert and no remote assets are required; incomplete captures are conspicuous; export failures do not corrupt raw run evidence.

Additional exit criteria: report generation respects documented event/string/output budgets; completed exports are published atomically without following destination symlinks or replacing existing files; interrupted or failed exports leave no partial final report and do not corrupt raw run evidence.

## Milestone 5 — Release readiness

- Finalize installation and `strace` prerequisite instructions for supported Linux distributions.
- Document optional use through an already installed WSL2 environment, without promising native Windows capture.
- Review data retention/deletion behavior, output redaction decisions, supported syscall set, and known limitations.
- Verify dependency versions and the committed lockfile, check dependency licenses and advisories, and document the separately installed `strace` dependency. Resolve any compatibility or redistribution question before packaging.
- Run the complete automated test suite, including real-tracer capture integration and parser, diff, incomplete-capture, JSON, HTML-injection, offline-rendering, and privacy-focused fixtures. Review a sample report for evidence accuracy and leakage.
- Review the exact release contents and staged repository changes for raw captures, generated reports, credentials, tokens, environment files, and machine-specific data; keep only clearly identified synthetic fixtures.
- Enable and verify the repository's private vulnerability reporting route. See [SECURITY.md](../SECURITY.md).

**Exit criteria:** documented platform/dependency matrix; tested release artifact; meaningful capture, parser, diff, export, and privacy/security tests actually run and pass; dependency and license checks plus lockfile review completed; exact release content reviewed for secrets and real capture data; private vulnerability reporting route verified; no claim of complete observation or root-cause proof; users can identify, inspect, and delete local trace data according to documented behavior; all test commands and results are real and recorded at release time.

Additional exit criteria: resource-boundary and output-path/symlink safety tests actually run and pass, including tests at each chosen budget boundary and just beyond it.

## Deferred work

Potential future work requires separate scoping and evidence:

- additional Linux architectures or tracing backends;
- native Windows tracing;
- network payload capture or DNS identity correlation;
- upload, hosted reports, or team collaboration;
- automatic redaction or secret detection;
- stronger process causality or provenance claims;
- LLM-based interpretation.

None of these capabilities is implied by the v0 plan.
