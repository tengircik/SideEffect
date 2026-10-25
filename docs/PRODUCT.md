# SideEffect Product Brief

**Status:** early implementation; the product target is not yet implemented. The repository currently provides bounded `inspect`, conservative `diff`, evidence lookup, Linux-only static HTML export, Linux recording of one selected command and traced children, and a narrow Linux Debian package database snapshot. The first real-tracer scenario covers a child execution, temporary-file activity, and loopback TCP; it has passed with strace 6.8 and 6.19 in WSL and with strace 6.8 in Ubuntu 24.04 CI. Broad runtime coverage, complete system inventory, process inventory, permission inspection, hooks/scripts inventory, and browser compatibility remain unvalidated. No security guarantee is claimed.

## Product summary

SideEffect is intended to be a user-triggered, local audit of software on a computer. An audit should show what software is present or running, which permission/configuration facts can be read, what startup hooks or scripts are configured, and what activity was observed during an explicitly bounded capture. Every claim should link to the source record or system artifact that supports it. The report must distinguish configured facts from observed runtime behavior and derived analysis, and label inaccessible or unsupported areas as unknown or not checked. SideEffect does not run as an always-on monitor.

The current implementation is a narrower technical foundation: on Linux it reads a point-in-time package listing from the local Debian dpkg database, parses local `strace` text, compares two fully parsed traces, and records one selected command under external strace. The package command does not inventory all installed software: manually copied or otherwise unregistered programs are outside its source. It does not inspect processes, permissions, startup hooks/scripts, or runtime activity. A Linux integration test covers a child execution, temporary-file activity, and loopback-only TCP; broad compatibility and event coverage remain unverified.

The first implementation platform is Linux x86_64 and the current capture backend uses an external `strace` executable. Native Windows tracing and inventory are not currently supported; a native Windows adapter is planned as a separate milestone, while WSL2 remains only an option for users who already have it. Rust is the implementation language. A future optional local model may explain selected audit evidence, but the core audit must work without an LLM or hosted service.

Published traces, bundles, report files, and Debian inventory snapshots are written to paths chosen by the user and remain there until the user deletes them. SideEffect does not upload, rotate, or automatically delete published data. Handled failures and cancellation clean up private staging directories; a machine crash can leave one behind. Treat traces, reports, and inventory snapshots as sensitive data.

## Problem

People often cannot tell what installed or running software is configured to do, which permissions or startup entries it has, or what it does when they run it. OS tools expose these facts in different places and formats. SideEffect should bring supported sources into a local report while preserving the source of each claim, distinguishing configured access from observed behavior, and showing areas it could not inspect. Runtime traces can help explain a selected program's actions, but correlation must not be presented as proof of cause.

## Intended users and use cases

- A computer user reviewing installed and running software, supported permission facts, and startup hooks or scripts.
- A developer or maintainer inspecting a selected program's bounded runtime activity or comparing two runs.
- A security-conscious user auditing a local tool before deciding whether to run it. The report is an observation aid, not a security verdict or sandbox.

The current foundation release focuses on one reproducible pair of command runs. The broader product goal is an on-demand audit, not a continuously running endpoint monitor or a claim to enumerate every possible behavior.

## Current implementation

`sideeffect inventory packages --output FILE` is a Linux-only, user-triggered, read-only point-in-time snapshot of the local dpkg package database. It runs the fixed `/usr/bin/dpkg-query` binary with a fixed package/version/architecture/status query, a cleared environment, and `LC_ALL=C`; it passes no user-supplied command or arguments to that process and requests no privilege escalation. JSON schema `sideeffect.inventory` v1 records the platform, source scope, capture timestamp, source status, and package rows. Valid rows retain their raw source record and line/byte evidence with a SHA-256 record fingerprint; malformed rows remain represented with diagnostics and raw bytes encoded as hex. A source status other than complete yields overall `partial`; the command still publishes that document and exits `2`. The snapshot is bounded (32 MiB stdout, 64 KiB stderr, 8 KiB per row, 200,000 rows, 20-second command timeout, and 64 MiB serialized output). The selected output file is private (mode `0600`) and no-clobber; it remains until the user deletes it. This source is not a complete software inventory: manually copied and otherwise unregistered software is out of scope. No process snapshot, permissions/ACLs, startup hooks/scripts, or runtime activity are collected by this command. Package metadata and raw rows are sensitive; output is not automatically redacted or uploaded.

Linux `sideeffect diff --bundles LEFT_DIR RIGHT_DIR` directly compares two current `sideeffect.run` v1 bundles after applying the same strict bundle validation used by `inspect --bundle`. The JSON and text outputs match the corresponding raw-trace comparison semantics, and the Linux offline HTML export is available with `diff --bundles --format html --output REPORT LEFT_DIR RIGHT_DIR`. Manifest status fields are metadata and do not prove command success or capture completeness; partial parsed traces still fail before a comparison document is written.

`sideeffect inspect TRACE` reads a regular file without executing the represented command and writes schema-v4 JSON to stdout; it fingerprints the exact bounded bytes parsed with SHA-256. Linux `sideeffect inspect --bundle DIR` validates the current `sideeffect.run` v1 bundle and emits the same document as inspecting its raw trace, without exposing the local bundle path. `inspect --format text TRACE` renders all rows and diagnostics as ASCII-only terminal-safe text. Some `openat`/`openat2` records include a clearly labeled lexical path hint; it is not canonical or filesystem-resolved. Complete `execve`/`execveat`, `openat`/`openat2`, and `connect` rows include a conservative `outcome` derived only from strict syscall result spellings: recognized success, recognized Linux `-1 ERRNO (message)` failure, `connect` in progress for `EINPROGRESS`, or `unknown`. Unfinished/resumed rows and other syscalls have no outcome. The outcome does not infer higher-level effects, and the raw line/result and evidence reference remain available. `sideeffect diff LEFT RIGHT` compares complete parses and writes schema-v3 JSON deltas with raw source line/byte references and independent hashes for the exact left/right inputs; `--format text` renders the same differences as ASCII-only terminal-safe text. `sideeffect evidence TRACE SHA256 LINE BYTE_OFFSET BYTE_LENGTH` checks that the supplied lowercase SHA-256 matches the exact bounded bytes parsed, then verifies a diff reference against one parsed syscall row and prints that row safely. Partial inputs carry a warning and status 2; malformed or mismatched hashes and control, unparsed, missing, or mismatched references are rejected. The hash helps identify bytes, but does not authenticate them, redact data, or prove capture completeness; hashes can reveal equality or be guessed for low-entropy inputs. Trace bytes remain local. On Linux, `--format html --output REPORT LEFT RIGHT` writes a bounded static offline report with no scripts or remote assets. Linux `sideeffect record --trace OUTPUT -- PROGRAM [ARGS...]` runs the selected program under external strace, inheriting its stdout/stderr, and writes a bounded raw trace. The diff fails closed on partial parses, compares syscall rows as a multiset, ignores only parsed timestamp and PID prefixes for matching, and compares raw syscall arguments/results exactly; `matching_policy.exact_fields` names these fields. Optional before/after lexical path hints are display-only, listed in `matching_policy.display_only_fields`, and cannot affect matching. A result change is shown as changed only when one unmatched same-signature row remains on each side; ambiguous residual multiplicities stay as additions/removals. It reports control-row counts outside the comparison. Paired unfinished/resumed records are treated as separate rows. Capture completeness remains unknown, and process/file/network labels are syscall-name buckets rather than claims of successful effects. Text escaping prevents terminal control injection; HTML escaping prevents markup interpretation; neither redacts sensitive content.
`sideeffect diff-summary` is a separate aggregate-only export with its own schema. It includes counts of added, changed, and removed diff groups by fixed category, omitting syscall names, raw arguments/results, lexical path hints, source fingerprints, evidence references, and input paths. The command does not attempt secret detection; remaining categories and counts can still be sensitive. The summary is not a safe-to-share verdict and does not retain event-level evidence. JSON goes to stdout; Linux HTML is local, bounded, mode 0600, offline, and no-clobber.

The parser and recorder enforce a 32 MiB trace limit; the parser also enforces a 64 KiB physical-record limit and a 100,000-record limit. Diff results are bounded to 200,000 rows; inspect JSON/text and diff JSON/text output are capped at 64 MiB before stdout is written. Invalid UTF-8 and hard limit violations fail without producing an inspect document. Included trace fixtures and fake-tracer tests are synthetic. A limited real capture integration test exists but does not validate broad syscall output or file/network event coverage; strace remains uninstalled system-wide in the WSL environment.

## Planned capture and comparison workflow

1. Record two command runs with `sideeffect record` or obtain external `strace` text files.
2. Run `sideeffect diff LEFT RIGHT` to compare parsed syscall rows and receive exact source references.
3. Inspect the source rows for each reported delta; the tool does not infer a cause or prove capture coverage.
4. On Linux, `sideeffect diff --format html --output REPORT LEFT RIGHT` creates a static offline report with source references; review it before sharing.

The recorder uses a private FIFO sink with a 32 MiB ceiling and publishes a bounded nonempty raw trace without replacing an existing file or symlink. `record --bundle` instead stages `run.json` and `trace.strace` together and publishes the directory atomically with no-clobber semantics. The mode-0700 bundle directory contains mode-0600 files. Its `sideeffect.run` v1 manifest stores tool/platform/tracer/profile metadata, raw strace status, explicit unknown/unverified markers, and exact trace length/hash, while omitting the command, argv, environment, cwd, username, absolute paths, output streams, tracer diagnostics, and parsed events. The trace remains sensitive and its hash can reveal equality; neither authenticity nor completeness is established. Bundle inspection accepts only the current strict schema and fixed files; it rejects extra entries, symlinks, wrong ownership/modes, over-limit inputs, and trace length or hash mismatches before parsing. If the limit is exceeded, the recorder terminates only the direct strace process and discards staging. SideEffect's tested minimum is strace 6.8; strace introduced `--kill-on-exit` in 6.6. The option is best-effort cleanup, and descendants using `CLONE_UNTRACED` may escape. The command runs without a shell under the user's permissions, and stdout/stderr are inherited. After finalizing and publishing a nonempty trace or complete bundle, the CLI propagates strace's reported exit code or signal. The strace manual says it normally mirrors the wrapped command's outcome; this does not independently verify the target status, tracer success, or capture completeness. Detected SideEffect capture errors take precedence. Capture is not a sandbox and may change process timing or behavior. One real smoke test confirms FIFO capture and parsing for trivial process invocations, but broader option compatibility, cleanup, and event coverage remain unvalidated. The HTML exporter is Linux-only, caps the rendered file, publishes mode-0600 output without replacing an existing destination, and includes no local input paths. Raw syscall values can still be sensitive. The initial diff does not normalize file descriptors, paths, or PID-like values embedded in syscall arguments/results; those may appear as differences. Its fixture pair is synthetic.

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

## Success criteria for the v0 technical foundation

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
- Whether raw traces should be compressed; published-data retention and deletion are user-controlled as described above.
- Capture diagnostics needed to independently distinguish tracer failure from a wrapped command result. `record` currently propagates strace's reported status only after successful trace publication and does not independently verify tracer success or command status.
- Safe handling of command output when stdout/stderr are streamed or captured.
- JSON schema versioning and compatibility policy.
- License compatibility, packaging, and whether/how an external `strace` dependency is pinned or installed. No licensing or redistribution conclusion is made here.
- Which normalization rules are sufficiently reliable for v0 and how ambiguous path resolution is presented.
