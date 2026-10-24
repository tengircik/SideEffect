# SideEffect Delivery Plan

**Status:** implementation is underway; this is not a schedule or release claim. Bounded `inspect`, conservative `diff`, exact-reference `evidence` lookup, terminal-safe text output, Linux-only static HTML export, and Linux `record` are implemented. A Linux integration test exercises real strace captures of a child's successful `execve`, represented as one complete row or separate continuation rows depending on tracer output, a temporary file operation, and loopback-only TCP activity through record, inspect, and diff; WSL runs used task-local extracted Ubuntu strace packages 6.8 and 6.19, without system installation. It checks for selected trace sentinels in captured command output and removes its private temporary directory; CI has no artifact-upload step. These runs do not validate every 6.6 build or kernel combination. Broad syscall coverage, other tracer/kernel combinations, and browser compatibility remain unverified.

## Current implementation slice

`sideeffect inspect TRACE` reads a regular local file, accepts a bounded subset of `strace` text, preserves raw lines and source byte offsets in a schema-v3 JSON document, and writes that document to stdout. Its `source_sha256` fingerprints the exact bounded byte buffer parsed. For `openat` and `openat2`, it may include an optional `lexical_path_hint` derived from a plain printable-ASCII path and an absolute `-yy` directory annotation; the hint does not query the filesystem, normalize path segments, follow symlinks, or establish descriptor identity. Earlier schema-v1/v2 exports are standalone; the CLI reads raw `strace` text only and does not import/migrate previous SideEffect JSON exports. `sideeffect inspect --format text TRACE` writes an ASCII-only terminal-safe view of every parsed, control, and unparsed row plus parser diagnostics and labels any hint as lexical. `sideeffect diff LEFT RIGHT` compares completely parsed raw trace inputs and writes schema-v3 JSON observed deltas with source offsets and separate left/right SHA-256 fingerprints; it includes optional side-specific lexical path hints as display-only fields, while `matching_policy.exact_fields` documents exact row/result comparison and `matching_policy.display_only_fields` explicitly excludes the hints. Fingerprints identify bytes only; they do not authenticate capture or establish completeness. `sideeffect evidence TRACE SHA256 LINE BYTE_OFFSET BYTE_LENGTH` verifies the supplied lowercase fingerprint against the exact parsed bytes before checking the source tuple against exactly one parsed syscall row. Partial input is labeled, and malformed/mismatched fingerprints and control, unparsed, out-of-range, or mismatched tuples are rejected. A successful lookup establishes byte identity relative to the supplied fingerprint and position within those bytes; it does not establish authenticity or capture completeness. Fingerprints are sensitive metadata, can reveal equality, and may be guessable for low-entropy traces; trace bytes are not uploaded. `sideeffect diff --format text LEFT RIGHT` writes a human-readable ASCII-only view with terminal controls escaped and clearly labels path hints as display-only. Linux `sideeffect diff --format html --output REPORT LEFT RIGHT` writes a bounded static offline report, with no scripts or remote assets, mode 0600, and no-clobber publication. It omits local input paths but can contain sensitive trace values. Parser and diff fixtures remain synthetic. The Linux integration test uses the real tracer for a narrow file plus loopback scenario; compatibility with broader tracer output remains unverified.
`sideeffect diff-summary` writes a separate `sideeffect_redacted_diff_summary` schema containing only added/changed/removed diff-group counts by fixed category. Its schema omits syscall names, raw arguments/results, lexical hints, source fingerprints, evidence references, and local input paths. It does not detect secrets or certify that the remaining counts are safe to share. JSON is written to stdout; Linux HTML is capped at 64 MiB, mode 0600, and published without replacing an existing file. This command uploads nothing and is not a redacted detailed diff.

Current hard limits are 32 MiB per input file (64 MiB combined for a diff), 64 KiB per physical record excluding LF, 100,000 records per input, 200,000 diff rows, and 64 MiB for serialized JSON, text, or HTML output. These initial values need review against real captures. `parse_status` describes syntax/continuation parsing only and cannot establish capture completeness. The diff fails closed on partial parses, ignores only parser-level PID/timestamp prefixes when matching, compares exact arguments/results, treats rows as a multiset, and reports excluded control-row counts. It emits a changed row only when exactly one unmatched same-signature record remains on each side; ambiguous result multiplicities remain additions/removals. Before/after references point to the first/second CLI input respectively. Unfinished and resumed rows remain separate observations.

## Milestone 0 — Repository and dependency decision

- Review repository guidance and existing project state before implementation.
- Confirm available Rust toolchain and Linux x86_64 development/test environment; do not install a toolchain without explicit authorization.
- Define the supported `strace` range, exact initial syscall set, command/exit-status contract, capture storage layout, and JSON schema policy. The parser's current v1 JSON document is not the planned run-bundle schema.
- Record explicit resource budgets before parser/report implementation. `inspect` currently uses 32 MiB input, 64 KiB physical records, 100,000 records, and a shared 64 MiB JSON/text output cap; validate these values against real captures before release. The initial diff is bounded to 200,000 rows and the same JSON/text output cap; define further budgets for capture bundles and future report features.
- Decide the Linux filesystem operations needed to create evidence bundles and atomically publish reports without following attacker-controlled symlinks or replacing existing user files. See [SECURITY.md](../SECURITY.md).
- Resolve licensing and packaging implications of depending on an external `strace` executable before distribution.

**Exit criteria:** written implementation decisions identify supported platform/tool versions, known observation limits, status/error semantics, documented resource budgets, safe no-follow/no-clobber output semantics, and unresolved items. No unsupported native Windows promise.

The initial Rust/MSRV and parser limits are recorded in `Cargo.toml` and `src/limits.rs`; supported `strace` versions, real-capture compatibility, and final release budgets remain open.

## Milestone 1 — Capture a single run

The first bounded recorder slice is implemented as `sideeffect record --trace OUTPUT -- PROGRAM [ARGS...]`. It sends strace output to a generated private FIFO, enforces the same 32 MiB cap as `inspect`, and publishes a non-empty raw trace only if the output name remains unused. Overflow kills only the direct strace process and discards the staged file. Traces are staged with mode 0600 in a private mode-0700 directory; command stdout/stderr remain inherited. `--kill-on-exit` requires strace 6.6 or newer but is only best-effort cleanup; descendants created with `CLONE_UNTRACED` can escape tracing. A Linux integration test records two small Python targets: both create unique temp files, the baseline opens a TCP connection to a local `127.0.0.1` listener, and the candidate starts a fixed Python child. The child's successful `execve` may appear as one complete row or as unfinished and matching-PID resumed rows, depending on tracer output; the parser keeps continuation rows separate. The paired diff asserts the observed child row and its evidence reference without reconstructing a logical call. The test captures command output in memory, checks selected fixture sentinels do not appear there, and verifies its private temp directory is removed. The workflow has no artifact-upload step. The test fails if `strace` or `python3` is missing; Linux CI installs those packages before running it. The WSL integration test passed with extracted, non-installed Ubuntu strace 6.8 and 6.19 packages. This narrow case does not validate every 6.6 build, broad syscall coverage, or all supported tracer/kernel combinations. `--syscall-limit` detaches tracees after a call count and must not be treated as a complete run. Never pass a user-controlled `-o` value directly: strace treats output names beginning with `|` or `!` as commands. See the [`strace(1)` manual](https://man7.org/linux/man-pages/man1/strace.1.html).

- Exercise `record` against a real supported strace version and a harmless shell-free target; confirm the selected option profile and FIFO output behavior.
- Decide whether to capture tracer diagnostics/version metadata and how to distinguish tracer failure from target exit. The current CLI reports only the raw strace status; it does not capture stderr or make a command-status claim.
- Validate cleanup behavior and document that this is not a sandbox and may not terminate descendants that escape tracing.
- Test output caps, no-clobber publication, symlink safety, and cleanup on real tracer startup and termination failures.
- Follow child processes where the chosen trace mode supports it.
- Keep command status distinct from tracer/parser/report failures.

**Exit criteria:** broader automated real-tracer integration covers a child execution and selected file/network calls; command stdout/stderr and exit result are handled according to the documented contract; missing tracer and tracer failure produce clear diagnostics; raw records remain inspectable; output tests prove an existing destination or symlink target is not overwritten/followed and failed writes do not publish partial final bundles. The current Linux test now proves one controlled child/file/loopback scenario with temporary-output cleanup and selected trace-output leakage checks. It does not settle the target exit-status contract and remains an early, partially validated feature, not release-ready.

## Milestone 2 — Parse and model evidence

- The initial `inspect` parser is implemented for the documented bounded text subset. Continue validating it against real supported `strace` captures and add explicit format/version support before release.
- Add a versioned run record and event schema with raw-evidence references.
- Represent process, file, and connection-related observations without overstating success or identity.
- Track parse errors, unsupported records, and detectable incomplete/truncated input.

The parser and renderer must enforce the explicit budgets recorded in Milestone 0. Test each chosen file, record, string, event/collection, comparison, and rendered-output limit at the accepted boundary and just beyond it. Oversized, malformed, and truncated input must not cause unbounded allocation or silent truncation.

**Exit criteria:** fixture tests cover success/failure returns, child processes, conservative lexical path hints and unresolved cwd/dirfd cases, concurrent or unfinished calls, malformed and unsupported records, and evidence-reference integrity. Full filesystem path resolution remains open; unresolved path or process data must remain explicitly unresolved.

## Milestone 3 — Compare two runs

- The first `diff` slice is implemented for completely parsed trace documents. It groups raw syscall rows as a multiset, ignores only parsed PID/timestamp prefixes for matching, compares exact syscall names, arguments, and results, and links deltas to source offsets.
- Control rows are excluded from the initial event comparison, with per-input counts in the JSON output. Unfinished and resumed rows are retained and compared as separate observations rather than reconstructed into logical calls.
- Process/file/network labels are transparent syscall-name buckets, not claims about completed effects. The report says capture completeness is unknown; parser completeness does not establish absence of events.
- Extend matching only with independently justified rules for run-local identities. Keep descriptor/path uncertainty visible and preserve original values in source evidence. Never apply blanket path or file-descriptor normalization.

**Exit criteria:** fixture pairs cover timestamp/PID-prefix changes, added/removed/changed observations, duplicate multiplicity, and unstable event ordering; incomplete input is rejected; every emitted delta links to source evidence; any future normalization is explicit and never destroys raw values. The current exact-argument matcher can still report changes caused by run-local values inside arguments or results; resolve those only through separately reviewed rules.

## Milestone 4 — Export human-readable output and offline HTML

- Versioned JSON diff output is implemented.
- `inspect --format text` is implemented as an ASCII-only listing of every parsed/control/unparsed record and diagnostic. It may show the narrowly scoped lexical path hint; it does not canonicalize paths or infer syscall effects.
- `diff --format text` is implemented as an ASCII-only terminal view; escape trace-derived controls, quotes, backslashes, and non-ASCII scalars and enforce the shared output cap.
- Linux `diff --format html --output REPORT LEFT RIGHT` renders a self-contained offline report with static CSS, no scripts or remote assets, escaped trace-derived content, and evidence references.
- The HTML report shows comparison context, observed changes, and uncertainty; rendering is capped before no-clobber publication.
- State clearly that reports may contain secrets and are not automatically sanitized; HTML file export is currently Linux-only.

Report generation must enforce the documented event/string/output budgets. Create completed reports atomically without following destination symlinks or replacing existing files; define cleanup behavior for failed or interrupted writes.

**Exit criteria:** schema/round-trip tests pass; HTML tests prove trace-provided markup is inert and no remote assets are required; incomplete captures are conspicuous; export failures do not corrupt raw run evidence. Current renderer tests cover static markup safety and a keyboard skip link/main landmark; browser compatibility and broad accessibility review remain open.

Additional exit criteria: report generation respects documented event/string/output budgets; completed exports are published atomically without following destination symlinks or replacing existing files; interrupted or failed exports leave no partial final report and do not corrupt raw run evidence.

## Milestone 5 — Release readiness

- A source-build guide now records the Linux x86_64 scope, Rust/Cargo and `strace` prerequisites, a verified Ubuntu 24.04 `strace` example, existing-WSL2 usage, trace sensitivity, and the no-prebuilt-binary status. Remaining distribution/package coverage is not established.
- Document optional use through an already installed WSL2 environment, without promising native Windows capture.
- Review data retention/deletion behavior, output redaction decisions, supported syscall set, and known limitations.
- Verify dependency versions and the committed lockfile, check dependency licenses and advisories, and document the separately installed `strace` dependency. Resolve any compatibility or redistribution question before packaging.
- A point-in-time advisory scan was run on 2026-10-24 with RustSec `cargo-audit` 0.22.2 against the committed lockfile. The updated advisory database was commit [`21d909e4c8bd4e14c7aea58bf980c881a0053ab1`](https://github.com/RustSec/advisory-db/commit/21d909e4c8bd4e14c7aea58bf980c881a0053ab1); `cargo audit` reported its `last-updated` value as `2026-10-24T10:30:13+02:00` (the commit's author timestamp is `2026-10-24T06:07:13Z`). The scan reported 22 lockfile packages and no known vulnerabilities. This is an advisory-database snapshot, not an exploitability assessment or release clearance; rerun before release. `cargo metadata --locked` also enumerated the 21 registry package license expressions, but their legal compatibility and redistribution obligations have not been cleared. The tool and advisory checkout used for this scan were kept in a temporary directory. See the official [`cargo-audit` usage](https://github.com/RustSec/rustsec/blob/main/cargo-audit/README.md).
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
