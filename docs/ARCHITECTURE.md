# SideEffect Architecture Plan

**Status:** early implementation. The source implements a Linux-only, read-only Debian dpkg package inventory snapshot, bounded `inspect`, conservative `diff`, fingerprint-verified evidence lookup, a separate aggregate-only diff summary schema, an ASCII-only terminal text view, Linux static HTML exports, and Linux `record` using an external `strace` process with a bounded FIFO sink. Opt-in `record --bundle` publishes a `sideeffect.run` v1 manifest and raw trace together; Linux `inspect --bundle DIR` validates and reads only that fixed v1 format. Trace inspection JSON uses schema v4 and detailed diff JSON uses schema v3; both carry SHA-256 fingerprints over exact parsed input bytes. Earlier trace schema v1-v3 and diff schema v1-v2 JSON are not imported or migrated. The aggregate summary uses its own schema v1 and omits event-level source values and references. A real-tracer integration test covers a child `execve` and successful return, either together or as separate continuation records depending on output, plus temporary file and loopback TCP observations through inspect/diff; broader coverage remains unverified.

The security requirements and current safeguards are summarized in [SECURITY.md](../SECURITY.md); requirements marked future remain release gates.

## Goals
- Build a local-first Linux x86_64 CLI in Rust, using an external `strace` executable for initial capture.
- Preserve raw evidence while making paired-run differences readable and reviewable.
- Keep uncertain or incomplete observations explicit.
- Render portable JSON and offline HTML without executing trace-provided content.
- Keep dependencies and runtime infrastructure small; no hosted service or LLM is required.

## Debian package inventory slice

`inventory packages --output FILE` collects one on-demand snapshot from `/usr/bin/dpkg-query` on Linux. Its fixed query asks for binary package name, version, architecture, and dpkg status abbreviation; the child receives a cleared environment with `LC_ALL=C`, no stdin, and no user-provided command arguments. This is a read-only read of the local package database, not a complete inventory of software on the computer. Manually copied or otherwise unregistered programs are not represented. The command does not enumerate running processes or inspect permissions, ACLs, startup hooks/scripts, or runtime activity.

`inventory processes --output FILE` separately walks visible numeric `/proc` directories and reads only each `status` file, once. Its process inventory schema v1 stores selected Name, PID/TGID/PPID/State, four UID and GID values, `CapInh`/`CapPrm`/`CapEff`/`CapBnd`/`CapAmb`, `NoNewPrivs`, and `Seccomp`; each present selected field links to its raw source line with relative byte offset/length and SHA-256. It deliberately excludes `cmdline`, `exe`, and all other procfs files. Start/end timestamps describe the interval of a non-atomic walk; processes can change or vanish, and visibility restrictions and caps mean the result is not exhaustive. Missing or malformed selected fields, read/entry errors, races, and bounds produce diagnostics, partial status, and exit status 2 after publishing the document. Limits are 8,192 numeric process entries, 64 KiB per status read, 32 MiB aggregate bytes, a 10-second scan deadline, and the 64 MiB serialized-output ceiling. The collector accepts an injected procfs root for synthetic tests. Output reuses the private mode-0600 no-clobber writer. This remains a narrow process status inventory, not a process security assessment.

The schema-v1 document records scope, collection timestamp, source status, package row values, raw-row evidence and diagnostics. The collector bounds stdout to 32 MiB, stderr to 64 KiB, each row to 8 KiB, rows to 200,000, execution time to 20 seconds, and serialized output to 64 MiB. Malformed or missing row terminators remain diagnostics; source failures, timeout, and limit conditions make the document partial rather than presenting affected data as absent. The user-selected output file is published privately with mode `0600` and no-clobber semantics. Package values and raw rows can disclose installed software or system details, remain on disk until deleted, and are not automatically redacted.

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

The current paths are `inspect <trace-file>` → bounded regular-file read → strict UTF-8 and line parsing → versioned JSON by default or ASCII-only escaped text with `--format text`; `diff <left-trace> <right-trace>` → parse both inputs → conservative multiset comparison → versioned JSON or ASCII-only escaped text; Linux `diff --format html --output REPORT LEFT RIGHT` → bounded HTML buffer → mode-0600 no-clobber report publication; Linux `record --trace OUTPUT -- PROGRAM [ARGS...]` → private FIFO → bounded raw trace → no-clobber file publication; and Linux `record --bundle DIR -- PROGRAM [ARGS...]` → the same bounded capture → trace hash plus fixed schema-v1 metadata → fsynced two-file staging directory → atomic sibling `renameat2(RENAME_NOREPLACE)`. The record command executes the selected program under strace with the user's normal permissions.

## Current parser contract

Linux `sideeffect diff --bundles LEFT_DIR RIGHT_DIR` reads both operands through the same strict v1 bundle validator used by `inspect --bundle`, then parses and compares the contained trace bytes. JSON and text output preserve raw-trace diff semantics and omit local bundle paths; HTML is also available through the existing bounded offline report writer. The manifest's status fields do not establish capture completeness or command success, and the diff engine still rejects partial parses before emitting output.

The parser accepts a bounded subset of line-oriented `strace` output. Record uses `-f -ttt -yy -s 256 -e trace=%process,%file,%network --kill-on-exit -o <generated FIFO>`; `inspect` does not verify how an input was produced. For current `strace` option and output behavior, see the [`strace(1)` manual](https://man7.org/linux/man-pages/man1/strace.1.html). A smoke test used an extracted strace 6.19 package in WSL without installing it system-wide: `/usr/bin/true` and `/usr/bin/false` produced bounded traces which parsed completely. This does not validate broad syscall or file/network-event coverage.

The parser recognizes PID and timestamp prefixes, syscall calls, common control records, and unfinished/resumed calls. It retains the original raw line and byte offset/length, plus raw syscall argument/result text. Unknown, malformed, or unpaired continuation lines remain in the JSON with diagnostics; invalid UTF-8 and hard budget violations return an error and no document. `parse_status` reports whether the parser classified and reconciled the supplied text; it never asserts capture completeness.

For `openat` and `openat2`, an optional `lexical_path_hint` is derived only from a plain printable-ASCII quoted path operand. An absolute operand is preserved as written; a relative operand is joined to an absolute `AT_FDCWD</...>` or numeric `<...>` directory annotation from `-yy`. The derived JSON value names its basis and stays attached to the original record evidence. Trace inspection schema v4 and comparison schema v3 include the source fingerprints; earlier trace schema v1-v3 and diff schema v1-v2 JSON exports are not imported or migrated. The CLI reads raw `strace` text and does not import or migrate prior SideEffect JSON exports. The hint does not query the filesystem, normalize `.`/`..`, follow symlinks, or track descriptor identity; it may be wrong around symlinks, descriptor reuse/deletion, `openat2` resolution flags, or truncated traces. Escaped, non-ASCII, deleted, truncated, malformed, or unsupported cases omit the hint. Raw arguments are authoritative. Diff output may carry a separate hint from each side strictly for display; `matching_policy.display_only_fields` marks it as display-only, and the matcher never consults it. The text and HTML renderers label it accordingly and keep original arguments visible.

For complete `execve`/`execveat`, `openat`/`openat2`, and `connect` rows, inspection attaches a conservative `outcome` enum to the same record as its exact evidence reference. It recognizes only strict success forms, Linux `-1 ERRNO (message)` failure forms, and `connect`'s `EINPROGRESS` as `in_progress`; other result spellings are `unknown`. Unfinished/resumed rows and other syscall names have no outcome. This is a syscall-result summary only and does not infer a higher-level effect.

For `-yy` output, an unquoted `<` begins a file-descriptor annotation and the parser skips through its next `>`. An unterminated annotation makes that line malformed. Other valid strace representations may be reported as partial until fixtures demonstrate support.

The current hard budgets are 32 MiB total input bytes, 64 KiB per physical record (excluding LF), 100,000 physical records, and 64 MiB for the serialized JSON document. Records include control and unparsed lines. The event fields duplicate portions of raw text and have bounded string lengths because every source record and the overall input are bounded; the serialized document is independently capped before it is written to stdout. These initial values need review against real captures before release.

## Component responsibilities

### CLI and capture coordinator

The CLI preserves argument boundaries, starts the external tracer, manages private staging, and publishes either one raw trace file or one complete run bundle. Linux `inspect --bundle DIR` securely opens and validates the fixed v1 bundle before passing its bounded trace bytes through the same parser and renderer as raw trace inspection. The target runs with the invoking user's normal permissions; tracing is observation, not isolation. No automatic privilege escalation or capture of arbitrary environment variables occurs. The command's stdout/stderr remain inherited. Trace output may contain command arguments, paths, socket addresses, and other sensitive data.

Recording uses a generated FIFO instead of `strace -o FILE`, allowing the parent to read incrementally and enforce the same 32 MiB cap used by `inspect`. When the cap is exceeded, it stops reading, kills only its direct strace process, and discards the staged partial trace without publishing it. SideEffect's tested minimum is strace 6.8; strace introduced `--kill-on-exit` in 6.6, and the option also depends on supported kernel behavior. It is best-effort cleanup; descendants that escape tracing via `CLONE_UNTRACED` may survive. A smoke test with extracted strace 6.19 ran `/usr/bin/true` and `/usr/bin/false`; their traces were bounded, mode 0600, and parsed completely. This test does not establish broad compatibility or file/network-event coverage. The recorder rejects an empty trace to avoid presenting a tracer startup/option failure as a usable artifact. Existing destinations, including symlinks, are rejected. Publication first uses same-directory `linkat`; only errors indicating hard links are unsupported trigger an anchored `renameat2(RENAME_NOREPLACE)` fallback. Both routes atomically preserve no-clobber behavior, and other link errors are returned without fallback. If the kernel or filesystem does not support the no-replace rename operation either, publication fails closed. The selected parent directory is canonicalized and opened once; subsequent FIFO, staging, publication, and cleanup operations are relative to held directory descriptors, so renaming that directory during capture does not redirect writes. Traces are staged with mode 0600 in a private mode-0700 directory. After SideEffect finalizes and publishes a nonempty trace, it propagates the normal exit code reported by strace or re-raises the reported signal (with a conventional 128+signal fallback if re-raising fails). The strace manual says it normally mirrors the wrapped command's exit status or signal; this is not independent verification of command outcome, tracer success, or capture completeness. Detected SideEffect capture failures take precedence and are reported as errors. Command stdout/stderr remain inherited, and arbitrary environment values are not collected by SideEffect. SIGINT, SIGTERM, SIGHUP, and SIGQUIT received by SideEffect trigger direct tracer termination and staged-output cleanup; parent death sends SIGKILL to strace, which requests best-effort traced-process cleanup. A system crash can leave a private staging directory. See the [`strace(1)` manual](https://man7.org/linux/man-pages/man1/strace.1.html).

The FIFO anchor is opened with `O_CLOEXEC`, so the traced command cannot keep it open. Parent supervision polls the FIFO and strace child; there is no separate reader process or shell command string. A hard kill or system crash can leave a private staging directory behind. Command execution remains unrestricted and tracing may alter timing or behavior.

Evidence bundles and report exports use conservative output-path handling. The HTML exporter is Linux-only, buffers rendered output up to the shared 64 MiB cap before creating a staged report, writes it with mode 0600, and publishes without replacing an existing destination using the same hard-link and narrowly selected no-replace rename fallback as trace output. It uses a static HTML/CSS template, restrictive CSP, no script or remote assets, and inserts trace values only as escaped text; local input paths are omitted. Reports can still contain sensitive raw arguments, paths, and endpoints. Tests cover injection strings, controls/bidi formatting, output limits, existing destinations, symlink targets, and staged cleanup. Any deliberate overwrite option requires separate product/security review.

### `strace` integration

The initial capture backend invokes external `strace` on Linux x86_64 with child-following enabled and a scoped set of process, file, and network-related syscalls. The selected capture profile is versioned as `linux_process_file_network_v1`. In bundle mode, the manifest records parsed strace major/minor, the raw strace-reported exit code or signal, command outcome `not_independently_verified`, capture completeness `unknown`, and inherited-but-not-captured markers for command streams and tracer diagnostics. It does not store the program/argv, environment, cwd, username, absolute paths, streams, diagnostics, or parsed event copies. The same raw trace remains the evidence artifact; its byte length and SHA-256 are recorded. The hash identifies bytes only and does not establish authenticity or completeness. Bundle mode is opt-in. `inspect --bundle DIR` accepts only the current v1 schema, rejects unknown fields and extra directory entries, requires the invoking user to own the directory and its mode-0700 directory/mode-0600 single-link regular files, and verifies the bounded manifest and trace length/SHA-256 before parsing. If the atomic rename succeeds but syncing the parent directory fails, the complete bundle is visible and the CLI warns that persistence across sudden power loss is uncertain while propagating the recorded strace status.

The backend does not claim complete coverage. Kernel/version support, permissions, tracing restrictions, untraced code paths, tracer failures, and event loss or truncation can limit observation. When detectable, those conditions are represented as capture diagnostics. A successful tracer exit is not equivalent to a proof that every relevant OS interaction was captured.

### Raw trace and parser

Raw trace text is retained as the evidence source. The parser converts supported records into structured events while keeping a stable reference to each raw record (for example, raw-log offset or record index plus source-file identity). Parse failures are diagnostics with partial results where safe; they must not silently drop an entire run or imply completeness.

The parser must tolerate concurrent processes and unfinished/resumed syscall records according to supported `strace` output formats. Unsupported record forms are surfaced as unsupported or unparsed evidence rather than guessed into structured events.

Each parser input is limited to 32 MiB, 64 KiB per physical record excluding LF, and 100,000 physical records. A diff therefore reads at most 64 MiB combined; output is bounded to at most 200,000 grouped rows and JSON, text, or HTML serialization has a 64 MiB cap. Console formats are buffered before stdout is written; HTML is buffered before file publication. The comparison borrows argument/result strings from parsed inputs and retains source offsets rather than copying full raw lines into deltas. The current diff compares parsed syscall rows as a multiset, ignores only parser-level PID/timestamp prefixes, and keeps syscall names, arguments, and results exact. It refuses partial parses, reports excluded control-row counts, and treats unfinished/resumed rows separately. Its category labels are syscall-name buckets. Capture completeness remains unknown. Oversized input fails explicitly; malformed or unsupported lines remain raw evidence with diagnostics rather than implying they were understood.

### Versioned run record

The run record separates:

- **Capture metadata:** OS/architecture, tracer name/version/arguments, timestamps, command metadata, and capture status.
- **Exact evidence:** raw trace reference, stdout/stderr references, and exact parsed values.
- **Canonical event data:** typed event kind, process identity within the run, operation, observed arguments/result, and raw-evidence references.
- **Diagnostics:** parser warnings, truncation or unsupported conditions, and capture errors.

The JSON format receives an explicit schema version before it is treated as a user-facing interface. Current inspection documents are schema v4; diff documents remain schema v3. The source fingerprint fields were added in v3; outcome summaries are added to inspection records in v4. Earlier trace schema v1-v3 and diff schema v1-v2 exports remain standalone and are not imported by this CLI. Unknown future fields should be handled according to a documented compatibility policy.

### Event model and provenance

The canonical event vocabulary should initially include process execution/lifecycle, supported file operations, and connection-related operations. Event fields distinguish request/attempt from successful result where the syscall result provides that distinction.

Process ancestry may be represented from observed process IDs and parent relationships when the trace provides enough evidence. File paths may be resolved using observed working-directory changes, directory file descriptors, and path arguments where the parser can do so reliably. If resolution is ambiguous, preserve the original path and mark the canonical path unresolved rather than inventing a location.

For network events, retain the observed address family, IP address, port, operation, and result as available. Do not silently convert an IP to a hostname or claim DNS identity. DNS-related events are out of scope unless separately and explicitly captured by a future backend.

Every derived field and rendered finding should link to the source event(s). This provenance supports review; it does not turn temporal proximity into causal proof.

### Comparison engine

The initial comparison engine keys observed rows by record kind, category, syscall, and exact raw arguments, then compares raw result values with multiset semantics. The JSON `matching_policy.exact_fields` names those fields, and `display_only_fields` marks `lexical_path_hint` as excluded from matching. It classifies added, removed, and uniquely paired changed rows and preserves source references on both sides. It emits a changed row only if exactly one unmatched same-signature row remains on each side after exact matches; ambiguous residual multiplicities stay as additions/removals. `before` references the first CLI input and `after` the second. Parsed PID and timestamp prefixes are ignored only for matching and remain in the original input records. Optional lexical path hints stay side-specific and are explicitly excluded from the matching key; if a grouped evidence row has inconsistent side hints, that side's hint is omitted. The comparison output does not claim to merge continuation rows into logical calls or prove that a capture observed every event.

`sideeffect evidence TRACE SHA256 LINE BYTE_OFFSET BYTE_LENGTH` is a read-only drilldown for a diff's source tuple. The parser computes `source_sha256` from the same bounded byte buffer used to parse records, avoiding a separate read/hash race. The command first verifies the supplied lowercase SHA-256 against that field, then requires an exact match to one parsed syscall, unfinished-syscall, or resumed-syscall record, including the physical line, byte offset, and byte length. It rejects malformed or mismatched fingerprints, control and unparsed rows, and does not print output for a mismatch. On a partially parsed file, it can display a selected parsed row only while marking the input partial; this does not make the trace usable for comparison or establish capture coverage. The fingerprint is an identity check relative to the supplied bytes, not authenticity or completeness; hashes may reveal equality and be guessed for low-entropy inputs. Trace bytes are not uploaded.

The initial rule omits only the parser's top-level PID and timestamp prefixes; values inside syscall arguments or results are not normalized. This can produce differences from run-local identifiers embedded in arguments/results. Future normalization requires explicit evidence and tests. File descriptor numbers and paths are currently compared exactly; there is no blanket rule that removes temporary directories or equates paths by suffix.

Concurrency can change event order even when behavior is similar. The diff should avoid presenting raw sequence order as semantic equivalence. A matching algorithm may group equivalent events, but must surface ambiguous matches and retain original ordering/timestamps in evidence. Unstable matching or normalization must be visible in the output.

### Renderers

JSON is the machine-readable output. The current text view escapes quotes, backslashes, control characters, and all non-ASCII scalars to ASCII, preventing trace input from emitting terminal control sequences. It is still sensitive and not redacted. The Linux HTML exporter creates a self-contained local report with static CSS, restrictive CSP, no scripts, remote assets, or active content sourced from the trace. Every trace-derived value is escaped into a text node; controls and known bidi/default-ignorable characters are presented as literal visible spellings. The report shows comparison context, observed differences, uncertainty, and direct raw-evidence references, but does not include local input file paths.

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
