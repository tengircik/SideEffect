# SideEffect Architecture Plan

**Status:** early implementation. The source implements read-only `inspect`, conservative `diff`, and an ASCII-only terminal text view over bounded line-oriented trace parsing. Capture orchestration, run bundles, and HTML rendering below remain planned, not implemented.

The security requirements for future implementation are summarized in [SECURITY.md](../SECURITY.md); the input-budget and safe-output behavior below are release requirements, not implemented protections.

## Goals

- Build a local-first Linux x86_64 CLI in Rust, using an external `strace` executable for initial capture.
- Preserve raw evidence while making paired-run differences readable and reviewable.
- Keep uncertain or incomplete observations explicit.
- Render portable JSON and offline HTML without executing trace-provided content.
- Keep dependencies and runtime infrastructure small; no hosted service or LLM is required.

## Proposed data path

```text
CLI request
    │
    ▼
Capture coordinator ───────► command stdout/stderr + exit status
    │
    ├───────────────────────► raw strace output + tracer status
    ▼
Trace parser ───────────────► parse diagnostics / completeness indicators
    ▼
Versioned run record ───────► raw event references + capture metadata
    │
    ├── Run A ─┐
    └── Run B ─┴─► canonical comparison keys ─► paired diff
                                                   │
                                      ┌────────────┴──────────┐
                                      ▼                       ▼
                               versioned JSON          offline HTML
```

The current paths are `inspect <trace-file>` → bounded regular-file read → strict UTF-8 and line parsing → versioned JSON, and `diff <left-trace> <right-trace>` → parse both inputs → conservative multiset comparison → versioned JSON or ASCII-only escaped text. They do not start `strace` or execute the command represented by the trace.

## Current parser contract

The parser accepts a bounded subset of line-oriented `strace` output. A proposed profile for a future capture command is `-f -ttt -yy -s 256 -e trace=%process,%file,%network -o FILE`; `inspect` does not verify how its input was produced. For current `strace` option and output behavior, see the [`strace(1)` manual](https://man7.org/linux/man-pages/man1/strace.1.html). No real-tracer integration test has been run yet because `strace` is not installed in the available WSL Ubuntu environment.

The parser recognizes PID and timestamp prefixes, syscall calls, common control records, and unfinished/resumed calls. It retains the original raw line and byte offset/length, plus raw syscall argument/result text. Unknown, malformed, or unpaired continuation lines remain in the JSON with diagnostics; invalid UTF-8 and hard budget violations return an error and no document. `parse_status` reports whether the parser classified and reconciled the supplied text; it never asserts capture completeness.

For `-yy` output, an unquoted `<` begins a file-descriptor annotation and the parser skips through its next `>`. An unterminated annotation makes that line malformed. Other valid strace representations may be reported as partial until fixtures demonstrate support.

The current hard budgets are 32 MiB total input bytes, 64 KiB per physical record (excluding LF), 100,000 physical records, and 64 MiB for the serialized JSON document. Records include control and unparsed lines. The event fields duplicate portions of raw text and have bounded string lengths because every source record and the overall input are bounded; the serialized document is independently capped before it is written to stdout. These initial values need review against real captures before release.

## Component responsibilities

### CLI and capture coordinator

The future CLI validates inputs, checks for the required external tracer, starts the wrapped command, manages trace/output files, records tool versions and invocation metadata, and returns a documented status. It must preserve the wrapped command's argument boundaries and run it with the invoking user's normal permissions; it is an observer, not a sandbox. No automatic privilege escalation or capture of arbitrary environment variables is planned. The command's stdout/stderr should remain inherited rather than being captured unless a separately reviewed feature changes that contract. Trace output may contain command arguments, paths, sockaddr values, and other sensitive data.

Recording is deferred until a bounded trace-output sink and explicit stop behavior are designed. A regular `strace -o FILE` output can grow without an application-enforced ceiling. `--syscall-limit` detaches tracees after a call count, so it cannot silently stand in for a complete run. `--kill-on-exit` needs strace 6.6 or newer and is not a complete cleanup guarantee because descendants can escape tracing via `CLONE_UNTRACED`. The project has not selected a supported minimum strace version or validated cleanup behavior. Strace also treats output names beginning with `|` or `!` as commands, so future capture must use a generated internal output path and never pass a user-provided destination directly as `-o`. Strace normally returns the traced command's exit status; that status is not an independent proof that the tracer completed without warnings. See the [`strace(1)` manual](https://man7.org/linux/man-pages/man1/strace.1.html).

The exact process supervision strategy and how stdout/stderr are forwarded while being recorded must be validated during implementation. The product must document any behavioral differences from direct command execution, including interactive terminal limitations if applicable.

Evidence bundles and report exports must use conservative output-path handling. Creating a new run must not follow attacker-controlled symlinks or overwrite an existing unrelated bundle. Report publication must use a temporary file created exclusively in the destination directory, then publish it atomically without replacing an existing destination; failures must remove partial temporary output where possible and leave existing user data unchanged. The implementation must select Linux filesystem operations that preserve these semantics under path races, not rely only on a preflight `exists` check. Tests must cover existing destinations, symlink targets, and interrupted/failed writes. Any deliberate overwrite option requires separate product/security review.

### `strace` integration

The initial capture backend invokes external `strace` on Linux x86_64 with child-following enabled and a scoped set of process, file, and network-related syscalls. The exact syscall selection is an implementation decision and should be tested against the acceptance fixtures. The capture bundle records tracer version, arguments, start/finish status, and relevant warnings.

The backend does not claim complete coverage. Kernel/version support, permissions, tracing restrictions, untraced code paths, tracer failures, and event loss or truncation can limit observation. When detectable, those conditions are represented as capture diagnostics. A successful tracer exit is not equivalent to a proof that every relevant OS interaction was captured.

### Raw trace and parser

Raw trace text is retained as the evidence source. The parser converts supported records into structured events while keeping a stable reference to each raw record (for example, raw-log offset or record index plus source-file identity). Parse failures are diagnostics with partial results where safe; they must not silently drop an entire run or imply completeness.

The parser must tolerate concurrent processes and unfinished/resumed syscall records according to supported `strace` output formats. Unsupported record forms are surfaced as unsupported or unparsed evidence rather than guessed into structured events.

Each parser input is limited to 32 MiB, 64 KiB per physical record excluding LF, and 100,000 physical records. A diff therefore reads at most 64 MiB combined; output is bounded to at most 200,000 grouped rows and JSON or text serialization has a 64 MiB cap before stdout is written. The comparison borrows argument/result strings from parsed inputs and retains source offsets rather than copying full raw lines into deltas. The current diff compares parsed syscall rows as a multiset, ignores only parser-level PID/timestamp prefixes, and keeps syscall names, arguments, and results exact. It refuses partial parses, reports excluded control-row counts, and treats unfinished/resumed rows separately. Its category labels are syscall-name buckets. Capture completeness remains unknown. Future capture and HTML rendering still need their own budgets. Oversized input fails explicitly; malformed or unsupported lines remain raw evidence with diagnostics rather than implying they were understood.

### Versioned run record

The run record separates:

- **Capture metadata:** OS/architecture, tracer name/version/arguments, timestamps, command metadata, and capture status.
- **Exact evidence:** raw trace reference, stdout/stderr references, and exact parsed values.
- **Canonical event data:** typed event kind, process identity within the run, operation, observed arguments/result, and raw-evidence references.
- **Diagnostics:** parser warnings, truncation or unsupported conditions, and capture errors.

The JSON format receives an explicit schema version before it is treated as a user-facing interface. Unknown future fields should be handled according to a documented compatibility policy.

### Event model and provenance

The canonical event vocabulary should initially include process execution/lifecycle, supported file operations, and connection-related operations. Event fields distinguish request/attempt from successful result where the syscall result provides that distinction.

Process ancestry may be represented from observed process IDs and parent relationships when the trace provides enough evidence. File paths may be resolved using observed working-directory changes, directory file descriptors, and path arguments where the parser can do so reliably. If resolution is ambiguous, preserve the original path and mark the canonical path unresolved rather than inventing a location.

For network events, retain the observed address family, IP address, port, operation, and result as available. Do not silently convert an IP to a hostname or claim DNS identity. DNS-related events are out of scope unless separately and explicitly captured by a future backend.

Every derived field and rendered finding should link to the source event(s). This provenance supports review; it does not turn temporal proximity into causal proof.

### Comparison engine

The initial comparison engine keys observed rows by record kind, category, syscall, and exact raw arguments, then compares raw result values with multiset semantics. It classifies added, removed, and uniquely paired changed rows and preserves source references on both sides. It emits a changed row only if exactly one unmatched same-signature row remains on each side after exact matches; ambiguous residual multiplicities stay as additions/removals. `before` references the first CLI input and `after` the second. Parsed PID and timestamp prefixes are ignored only for matching and remain in the original input records. The comparison output does not claim to merge continuation rows into logical calls or prove that a capture observed every event.

The initial rule omits only the parser's top-level PID and timestamp prefixes; values inside syscall arguments or results are not normalized. This can produce differences from run-local identifiers embedded in arguments/results. Future normalization requires explicit evidence and tests. File descriptor numbers and paths are currently compared exactly; there is no blanket rule that removes temporary directories or equates paths by suffix.

Concurrency can change event order even when behavior is similar. The diff should avoid presenting raw sequence order as semantic equivalence. A matching algorithm may group equivalent events, but must surface ambiguous matches and retain original ordering/timestamps in evidence. Unstable matching or normalization must be visible in the output.

### Renderers

JSON is the machine-readable output. The current text view escapes quotes, backslashes, control characters, and all non-ASCII scalars to ASCII, preventing trace input from emitting terminal control sequences. It is still sensitive and not redacted. Future HTML must be a self-contained local report with no remote assets, network calls, or active content sourced from the trace. Every trace-derived string must be escaped or inserted as text; scripts must not evaluate trace values. Reports should show capture status, run identity, observed differences, uncertainty, and direct raw-evidence references.

An export must not be described as sanitized or safe to publish by default. Command arguments, paths, output, and syscall arguments may contain secrets or personal information. If a future redaction option is added, the report must distinguish redacted data from absent data and preserve the original local evidence separately according to an explicit policy.

## Error and status model

The implementation should distinguish at least:

- command's own exit status;
- tracer startup/runtime/exit failure;
- parser errors or unsupported records;
- incomplete or potentially truncated capture;
- comparison ambiguity;
- report export failure.

Resource exhaustion, unsafe output-path resolution, destination collision, and atomic publication failure must also be surfaced distinctly enough for a user to understand whether evidence was captured and whether any final output was written.

The exact CLI exit-code scheme remains open. It must not overwrite or conceal the wrapped command's result; the interface needs a documented way to retrieve both outcomes.

## Security and privacy considerations

See [SECURITY.md](../SECURITY.md) for the project threat model, privacy guidance, and release requirements.

- Treat raw traces, command output, imported traces, and report fields as untrusted input.
- Escape trace-derived content in HTML and avoid remote scripts/assets.
- Enforce the documented input, record, string, event/collection, comparison, and rendered-output budgets for malformed or unusually large traces. Boundary tests must cover the exact chosen limits and limit-plus-one cases.
- Create bundles and reports without following attacker-controlled symlinks or overwriting existing user data; publish completed reports atomically and test collision, symlink, and interrupted-write cases.
- Avoid shell-string interpolation for user-provided command arguments; preserve argument boundaries.
- Do not collect environment variables intentionally unless a separately reviewed feature explicitly requires it.
- Still warn that syscall arguments and stdout/stderr can contain sensitive values.
- Keep data local by default; no telemetry or upload path in v0.
- Do not market the tool as a sandbox, malware detector, complete audit, or proof that a command is safe.

## Runtime and distribution assumptions

Rust is the planned implementation stack for the core CLI, parser, schema, diff engine, and renderer to support a compact distributable executable. The external `strace` dependency remains required and must be checked at runtime. Supported version range, installation instructions, packaging, and license compatibility are unresolved implementation decisions. This plan does not authorize installing toolchains or modifying source code.

The initial platform target is Linux x86_64. Existing WSL2 environments may be used by Windows developers/users as a Linux environment, but SideEffect v0 makes no native Windows tracing claim and does not assume WSL2 is installed.

## Validation strategy

Future implementation must include meaningful automated tests before release:

- parser fixtures covering successful and failed syscalls, child process execution, path handling, concurrent/unfinished records, and unsupported or malformed input;
- capture integration fixtures verifying child following, output handling, tracer status, and preservation of the command exit result;
- comparison fixtures for stable pairs with varied PIDs/timestamps, added/removed/changed events, ambiguous descriptor/path resolution, and nondeterministic order;
- incomplete-capture and diagnostic fixtures proving missing events are not reported as absent behavior;
- JSON schema and round-trip fixtures;
- HTML tests showing malicious trace strings are inert and offline assets are self-contained;
- tests for large or malformed inputs that exercise resource bounds.

No benchmark or coverage percentage is promised in this planning document.
