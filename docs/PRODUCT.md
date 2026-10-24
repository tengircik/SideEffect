# SideEffect Product Brief

**Status:** early implementation. The repository implements bounded `inspect`, conservative `diff` with JSON or terminal-safe text output, Linux-only static HTML report export, and a Linux `record` command that sends strace output through a bounded FIFO. A narrow real-tracer integration test checks temporary file and loopback events through inspect and diff; broad real-tracer coverage and browser compatibility remain unvalidated. No security guarantee is claimed.

## Product summary

The product is a local command-line tool for observing selected operating-system interactions made while a command runs, comparing two runs, and exporting an evidence-backed report. Its central result is a paired behavior delta: a reader can see which observed process, file, and network-related syscall rows differ and inspect their source evidence. The current implementation can parse local traces, compare two fully parsed traces, and record a command under external strace on Linux. A Linux integration test has passed with extracted strace 6.19 in WSL and verifies a temporary file operation plus loopback-only TCP activity; broad compatibility and event coverage remain unverified.

The initial implementation is planned for Linux x86_64 and uses an external `strace` executable. Windows users may develop or run it through an existing WSL2 installation, but native Windows support is not part of v0. Rust is the planned implementation language for the CLI, parser, event schema, comparison engine, and local report renderer. No LLM or hosted service is required.

## Problem

Developers often know that two executions behaved differently but cannot quickly see the OS-level interactions that changed. Raw syscall logs contain useful evidence, but they are difficult to compare: process IDs, file descriptors, timestamps, and concurrent event ordering vary between runs. Existing runtime tracers can collect broad events, but a useful review artifact needs to connect a compact difference back to the exact observed events without presenting correlation as proof of cause.

## Intended users and use cases

- A developer reviewing what changed after a dependency, build, or configuration update.
- A maintainer investigating why a command behaves differently on a second machine or environment.
- A security-conscious user inspecting a local tool before deciding whether to run it. The report is an observation aid, not a security verdict or sandbox.

The first release should focus on one reproducible pair of command runs. It is not a continuously running endpoint monitor or a general tracing platform.

## Current implementation

`sideeffect inspect TRACE` reads a regular file without executing the represented command and writes schema-v3 JSON to stdout; it fingerprints the exact bounded bytes parsed with SHA-256. `inspect --format text TRACE` renders all rows and diagnostics as ASCII-only terminal-safe text. Some `openat`/`openat2` records include a clearly labeled lexical path hint; it is not canonical or filesystem-resolved. The inspector does not infer syscall effects. `sideeffect diff LEFT RIGHT` compares complete parses and writes schema-v3 JSON deltas with raw source line/byte references and independent hashes for the exact left/right inputs; `--format text` renders the same differences as ASCII-only terminal-safe text. `sideeffect evidence TRACE SHA256 LINE BYTE_OFFSET BYTE_LENGTH` checks that the supplied lowercase SHA-256 matches the exact bounded bytes parsed, then verifies a diff reference against one parsed syscall row and prints that row safely. Partial inputs carry a warning and status 2; malformed or mismatched hashes and control, unparsed, missing, or mismatched references are rejected. The hash helps identify bytes, but does not authenticate them, redact data, or prove capture completeness; hashes can reveal equality or be guessed for low-entropy inputs. Trace bytes remain local. On Linux, `--format html --output REPORT LEFT RIGHT` writes a bounded static offline report with no scripts or remote assets. Linux `sideeffect record --trace OUTPUT -- PROGRAM [ARGS...]` runs the selected program under external strace, inheriting its stdout/stderr, and writes a bounded raw trace. The diff fails closed on partial parses, compares syscall rows as a multiset, ignores only parsed timestamp and PID prefixes for matching, and compares raw syscall arguments/results exactly; `matching_policy.exact_fields` names these fields. Optional before/after lexical path hints are display-only, listed in `matching_policy.display_only_fields`, and cannot affect matching. A result change is shown as changed only when one unmatched same-signature row remains on each side; ambiguous residual multiplicities stay as additions/removals. It reports control-row counts outside the comparison. Paired unfinished/resumed records are treated as separate rows. Capture completeness remains unknown, and process/file/network labels are syscall-name buckets rather than claims of successful effects. Text escaping prevents terminal control injection; HTML escaping prevents markup interpretation; neither redacts sensitive content.
`sideeffect diff-summary` is a separate aggregate-only export with its own schema. It includes counts of added, changed, and removed diff groups by fixed category, omitting syscall names, raw arguments/results, lexical path hints, source fingerprints, evidence references, and input paths. The command does not attempt secret detection; remaining categories and counts can still be sensitive. The summary is not a safe-to-share verdict and does not retain event-level evidence. JSON goes to stdout; Linux HTML is local, bounded, mode 0600, offline, and no-clobber.

The parser and recorder enforce a 32 MiB trace limit; the parser also enforces a 64 KiB physical-record limit and a 100,000-record limit. Diff results are bounded to 200,000 rows; inspect JSON/text and diff JSON/text output are capped at 64 MiB before stdout is written. Invalid UTF-8 and hard limit violations fail without producing an inspect document. Included trace fixtures and fake-tracer tests are synthetic. A limited real capture integration test exists but does not validate broad syscall output or file/network event coverage; strace remains uninstalled system-wide in the WSL environment.

## Planned capture and comparison workflow

1. Record two command runs with `sideeffect record` or obtain external `strace` text files.
2. Run `sideeffect diff LEFT RIGHT` to compare parsed syscall rows and receive exact source references.
3. Inspect the source rows for each reported delta; the tool does not infer a cause or prove capture coverage.
4. On Linux, `sideeffect diff --format html --output REPORT LEFT RIGHT` creates a static offline report with source references; review it before sharing.

The recorder uses a private FIFO sink with a 32 MiB ceiling and publishes a bounded nonempty raw trace without replacing an existing file or symlink. If the limit is exceeded, it terminates only the direct strace process and discards staging. Strace 6.6 or newer is required for `--kill-on-exit`; it is best-effort cleanup, and descendants using `CLONE_UNTRACED` may escape. The command runs without a shell under the user's permissions, and stdout/stderr are inherited. The CLI reports raw strace status only; it does not claim a verified target exit code or tracer success. Capture is not a sandbox and may change process timing or behavior. One real smoke test confirms FIFO capture and parsing for trivial process invocations, but broader option compatibility, cleanup, and event coverage remain unvalidated. The HTML exporter is Linux-only, caps the rendered file, publishes mode-0600 output without replacing an existing destination, and includes no local input paths. Raw syscall values can still be sensitive. The initial diff does not normalize file descriptors, paths, or PID-like values embedded in syscall arguments/results; those may appear as differences. Its fixture pair is synthetic.

## Product principles

### Evidence before interpretation

Reports state what the capture observed: for example, a process executed a child command, a syscall attempted to open a path, or a process attempted a socket connection to an IP address and port. A failed syscall is still an observed attempt, not a successful effect. Event ancestry and timing can help readers investigate; they do not establish complete causal attribution.

Derived comparison fields must retain references to the raw events from which they were derived. Exact captured values remain available in the local run record; normalization is a separate, documented comparison view.

### Capture completeness is visible

Each run must record capture status and relevant limitations, including tracer startup/exit status, command exit status, parser warnings, and indications of truncated or incomplete input when detectable. Missing data must not be rendered as evidence that an event did not occur. A report should make incomplete or unsupported observation conspicuous.

### Local by default, sensitive by design

`inspect` and `diff` read local inputs and write to stdout; `record` creates one local trace file. There is no upload or telemetry path. Traces retain raw syscall text and can contain sensitive arguments, paths, endpoint details, and other values. Command stdout/stderr are inherited rather than collected. Users must inspect traces before sharing them.

### Honest network representation

The first release may observe connection-related syscalls. It must distinguish an observed destination IP address and port from a hostname or DNS identity. It must not claim that the process contacted a particular hostname unless that information is independently and explicitly observed. Network payload capture and DNS identity resolution are outside v0.

## Proposed v0 scope

- Inspect one selected local, regular `strace` text file and emit a versioned JSON evidence document to stdout, with an optional terminal-safe text listing of all parser records and diagnostics.
- Preserve raw records and source byte offsets; report malformed, unsupported, or unpaired continuation lines as diagnostics.
- Enforce the current parser budgets: 32 MiB per input, 64 KiB per physical record, 100,000 records, and 64 MiB JSON or text output. These initial limits require review against real captures before release.
- Linux x86_64 with a separately installed `strace` executable.
- Run one command under tracing and save a local evidence bundle.
- Capture process execution/lifecycle, selected file-related calls, and connection-related calls supported by the chosen trace configuration.
- Parse and preserve raw trace evidence; create a versioned canonical event representation.
- Compare two runs with explainable normalization and event-level references.
- Produce JSON and offline HTML reports with escaped untrusted values.
- Preserve the wrapped command's exit status and stdout/stderr behavior as closely as the implementation permits, and document any differences.
- Include deterministic fixtures for parser, normalization, diff, incomplete-capture, and report-rendering behavior.

## Explicit non-goals for v0

- Native Windows tracing or a promise of identical behavior across platforms.
- A sandbox, malware detector, vulnerability scanner, or guarantee that all relevant behavior was observed.
- Full syscall coverage independent of `strace` and kernel support.
- Network payload capture, packet inspection, or authoritative DNS-to-process attribution.
- Automatic secret removal or a guarantee that an exported report is safe to publish.
- Automatic root-cause analysis, LLM-generated explanations, or claims that an event caused another event.
- Cloud accounts, hosted dashboards, telemetry, team collaboration, or report upload.
- Blanket suppression of temporary paths or other changing values. Any comparison normalization must be explicit and inspectable.

## Success criteria for the first usable release

- A user can record two supported command runs and receive a report that identifies added, removed, and changed observed event groups.
- Every reported event difference links back to raw evidence and identifies which run it came from.
- The report distinguishes observed facts, derived comparison keys, and unavailable/uncertain fields.
- The run record exposes capture warnings and does not treat incomplete observation as proof of absence.
- A stable fixture pair with changed top-level PIDs and timestamps does not create differences solely because those prefixes changed, while the exact raw source lines remain available.
- A fixture with a real added child execution, file operation, and connection event displays those changes accurately without claiming root cause or successful connection unless the trace shows success.
- Malicious markup in trace strings renders as inert text in the offline HTML report.
- Documentation states the Linux/strace prerequisite, local storage behavior, sensitive-data risk, and observation limits before asking users to share reports.

These are acceptance targets for future implementation and tests, not claims about the current repository.

## Open decisions

- Exact `strace` version range, supported distributions, and behavior when a requested event class is unavailable.
- Trace storage layout, retention/deletion behavior, and whether raw traces are compressed.
- Capture command syntax and capture/tracer/command exit-code contract. The parser-only `inspect TRACE` syntax and its partial-parse/error statuses are implemented.
- Safe handling of command output when stdout/stderr are streamed or captured.
- JSON schema versioning and compatibility policy.
- License compatibility, packaging, and whether/how an external `strace` dependency is pinned or installed. No licensing or redistribution conclusion is made here.
- Which normalization rules are sufficiently reliable for v0 and how ambiguous path resolution is presented.
