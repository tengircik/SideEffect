# SideEffect Product Brief

**Status:** early implementation. The repository implements bounded `sideeffect inspect TRACE` parsing and a conservative `sideeffect diff LEFT RIGHT` JSON comparison. Capture and HTML report generation remain planned; no security guarantee is claimed.

## Product summary

The planned product is a local command-line tool for observing selected operating-system interactions made while a command runs, comparing two runs, and exporting an evidence-backed report. Its central result is a paired behavior delta: a reader can see which observed process, file, and network-related syscall rows differ and inspect their source evidence. The current implementation parses one user-selected local `strace` text file or compares two fully parsed traces; it does not capture a command.

The initial implementation is planned for Linux x86_64 and uses an external `strace` executable. Windows users may develop or run it through an existing WSL2 installation, but native Windows support is not part of v0. Rust is the planned implementation language for the CLI, parser, event schema, comparison engine, and local report renderer. No LLM or hosted service is required.

## Problem

Developers often know that two executions behaved differently but cannot quickly see the OS-level interactions that changed. Raw syscall logs contain useful evidence, but they are difficult to compare: process IDs, file descriptors, timestamps, and concurrent event ordering vary between runs. Existing runtime tracers can collect broad events, but a useful review artifact needs to connect a compact difference back to the exact observed events without presenting correlation as proof of cause.

## Intended users and use cases

- A developer reviewing what changed after a dependency, build, or configuration update.
- A maintainer investigating why a command behaves differently on a second machine or environment.
- A security-conscious user inspecting a local tool before deciding whether to run it. The report is an observation aid, not a security verdict or sandbox.

The first release should focus on one reproducible pair of command runs. It is not a continuously running endpoint monitor or a general tracing platform.

## Current implementation

`sideeffect inspect TRACE` reads a regular file without executing the traced command, invokes no external program, and writes schema-v1 JSON to stdout. `sideeffect diff LEFT RIGHT` compares complete parses and writes schema-v1 JSON deltas with raw source line/byte references. The diff fails closed on partial parses, compares syscall rows as a multiset, ignores only parsed timestamp and PID prefixes for matching, and compares raw syscall arguments/results exactly. A result change is shown as changed only when one unmatched same-signature row remains on each side; ambiguous residual multiplicities stay as additions/removals. It reports control-row counts outside the comparison. Paired unfinished/resumed records are treated as separate rows. Capture completeness remains unknown, and process/file/network labels are syscall-name buckets rather than claims of successful effects.

The parser enforces a 32 MiB input limit, a 64 KiB physical-record limit, a 100,000-record limit, and a 64 MiB JSON output limit. Diff results are bounded to 200,000 rows. Invalid UTF-8 and hard limit violations fail without producing an evidence document. Included traces are synthetic, not real system captures. Real `strace` integration has not been tested because `strace` is not installed in the current WSL environment.

## Planned capture and comparison workflow

1. Obtain two `strace` text files from runs of interest (manual capture is currently required).
2. Run `sideeffect diff LEFT RIGHT` to compare parsed syscall rows and receive exact source references.
3. Inspect the source rows for each reported delta; the tool does not infer a cause or prove capture coverage.
4. Future capture and offline HTML export will build on this evidence-linked JSON comparison.

The command capture runner and HTML export are not implemented. The initial diff does not normalize file descriptors, paths, or PID-like values embedded in syscall arguments/results; those may appear as differences. Its fixture pair is synthetic and is not an integration test against real `strace` output.

## Product principles

### Evidence before interpretation

Reports state what the capture observed: for example, a process executed a child command, a syscall attempted to open a path, or a process attempted a socket connection to an IP address and port. A failed syscall is still an observed attempt, not a successful effect. Event ancestry and timing can help readers investigate; they do not establish complete causal attribution.

Derived comparison fields must retain references to the raw events from which they were derived. Exact captured values remain available in the local run record; normalization is a separate, documented comparison view.

### Capture completeness is visible

Each run must record capture status and relevant limitations, including tracer startup/exit status, command exit status, parser warnings, and indications of truncated or incomplete input when detectable. Missing data must not be rendered as evidence that an event did not occur. A report should make incomplete or unsupported observation conspicuous.

### Local by default, sensitive by design

The current `inspect` command reads the selected local input and writes JSON to stdout; it has no upload or telemetry path. The resulting JSON retains raw trace text and can contain sensitive command arguments, paths, endpoint details, and other syscall values. The absent capture runner means it does not currently collect stdout/stderr or start a command. Future capture output will need separate retention, privacy, and sanitization decisions. Users must inspect JSON before sharing it.

### Honest network representation

The first release may observe connection-related syscalls. It must distinguish an observed destination IP address and port from a hostname or DNS identity. It must not claim that the process contacted a particular hostname unless that information is independently and explicitly observed. Network payload capture and DNS identity resolution are outside v0.

## Proposed v0 scope

- Inspect one selected local, regular `strace` text file and emit a versioned JSON evidence document to stdout.
- Preserve raw records and source byte offsets; report malformed, unsupported, or unpaired continuation lines as diagnostics.
- Enforce the current parser budgets: 32 MiB per input, 64 KiB per physical record, 100,000 records, and 64 MiB serialized JSON output. These initial limits require review against real captures before release.
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
