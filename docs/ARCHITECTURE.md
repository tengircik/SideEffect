# SideEffect Architecture Plan

**Status:** early implementation. The source implements Linux-only, read-only bounded package snapshots from available dpkg, RPM, pacman, and APK databases; process status and executable-link snapshots; explicit-path metadata/POSIX ACL/file-capability snapshots; curated XDG/systemd/SysV/cron startup discovery; bounded `inspect`, conservative `diff`, fingerprint-verified evidence lookup, a separate aggregate-only diff summary schema, an ASCII-only terminal text view, Linux static HTML exports, and Linux `record` using an external `strace` process with a bounded FIFO sink. Opt-in `record --bundle` writes a `sideeffect.run` v2 manifest and raw trace together; Linux `inspect --bundle DIR` validates supported v1 and v2 formats. Trace inspection JSON uses schema v7 and detailed diff JSON uses schema v3; both carry SHA-256 fingerprints over exact parsed input bytes. Inventory package JSON uses schema v2; the separate process and permission schemas remain v1. Earlier trace schema v1-v5 and diff schema v1-v2 JSON are not imported or migrated. The aggregate summary uses its own schema v1 and omits event-level source values and references. A real-tracer integration test covers a child `execve` and successful return, either together or as separate continuation records depending on output, plus temporary file and loopback TCP observations through inspect/diff; broader coverage remains unverified.

The security requirements and current safeguards are summarized in [SECURITY.md](../SECURITY.md); requirements marked future remain release gates.

## Goals
- Windows is a first-class product target, not a compatibility promise for the current Linux adapters. Windows implementations must use native evidence sources and expose their own scope, permissions, timestamps, and collection-loss states. Shared command concepts should remain familiar while platform-specific coverage stays explicit. Cross-platform 1.0 is gated on native Windows inventories and bounded process/file/network runtime capture; WSL2 does not meet that gate. See [the delivery plan](PLAN.md#milestone-10--native-windows-inventory-and-startup-audit).
- Build a local-first Rust CLI whose first implementation is Linux x86_64 with external `strace`, then provide useful native Windows workflows for the same core audit jobs.
- Preserve raw evidence while making paired-run differences readable and reviewable.
- Keep uncertain or incomplete observations explicit.
- Render portable JSON and offline HTML without executing trace-provided content.
- Keep dependencies and runtime infrastructure small; no hosted service or LLM is required.

## Package database inventory slice

`inventory packages --output FILE` queries available dpkg, RPM, pacman, and APK databases at fixed system paths on Linux. Every adapter uses fixed arguments and a cleared child environment; APK explicitly disables network access. A shared stdout, stderr, row, and 20-second aggregate deadline bounds the combined snapshot. Schema `sideeffect.inventory` v2 associates each row with its source ID and retains source-row evidence. Known inapplicable adapters can be marked `not_applicable`; unavailable, unsupported, failed, or skipped sources remain explicit and prevent an unjustified complete result. Unknown distribution metadata remains conservative. Unsupported-manager detection checks documented fixed paths for XBPS, Nix, Guix, Snap, and Flatpak; custom/user installs outside those paths can be missed. This is not a complete inventory: manually copied or otherwise unregistered software and unsupported package formats are not represented.

`inventory processes --output FILE` separately walks visible numeric `/proc` directories and reads each `status` file and `exe` link. Its process inventory schema v1 stores selected Name, PID/TGID/PPID/State, UID/GID values, capability masks, `NoNewPrivs`, and `Seccomp`; selected status fields link to their raw source lines with relative byte offset/length and SHA-256. The executable-link observation stores exact target bytes as bounded hex, an optional UTF-8 display, and a SHA-256 fingerprint; SideEffect does not open the target. It excludes `cmdline` and other procfs files. Start/end timestamps describe the interval of a non-atomic walk; processes can change or vanish, and visibility restrictions and caps mean the result is not exhaustive. Missing, duplicate/ambiguous, malformed, inaccessible, vanished, and limit-affected values produce diagnostics and partial status. Limits are 8,192 numeric process entries, 64 KiB per status read, 32 MiB aggregate status bytes, 4 KiB per executable link, 4 MiB aggregate executable-link bytes, a 10-second scan deadline, and the 64 MiB serialized-output ceiling. Output reuses the private mode-0600 no-clobber writer. This remains a narrow process inventory, not a process security assessment.

`inventory permissions --output FILE PATH...` collects a separate `sideeffect.permission_inventory` v1 document for explicitly selected Linux paths. It accepts at most 256 paths (4 KiB of path bytes each), and checks only regular files and directories. It first opens each path with `O_PATH|O_NOFOLLOW|O_CLOEXEC` and reads metadata from the pinned descriptor; final-component symlinks are reported but not followed. It reopens `/proc/self/fd/N` read-only to call `fgetxattr` on the pinned object, then checks device/inode/type identity against the original descriptor. Access ACLs are checked for both object types; default ACLs only for directories; `security.capability` is also read and strictly decoded for Linux VFS revisions 1–3. ACL and capability xattr data each have 64 KiB per-attribute and 8 MiB aggregate budgets and are retained as hex with byte length and SHA-256. ACL absence, access denial, unsupported xattrs, malformed bytes, I/O failures, and limit hits have distinct states/diagnostics. Any incomplete requested item makes the document partial and the CLI exits 2 after publishing through the existing private no-clobber writer. Non-UTF-8 path bytes are preserved as hex alongside an optional UTF-8 display path. The collector does not recurse, request elevation, execute a selected path, follow final symlinks, or calculate effective access. Intermediate components follow normal Linux path resolution. The 5-second deadline is checked between paths; an in-flight filesystem syscall cannot be canceled by the collector and can take longer. This is a selected-object observation, not a complete permission inventory or an atomic snapshot of filesystem state.

The `sideeffect.inventory` v2 document records scope, collection timestamp, source status, package row values/source IDs, raw-row evidence, and diagnostics. The collector shares stdout (32 MiB), stderr (64 KiB), row (8 KiB each, 200,000 total), a 20-second aggregate deadline, and serialized-output (64 MiB) bounds across adapters. Malformed or missing row terminators remain diagnostics; source failures, timeout, and limit conditions make the document partial rather than presenting affected data as absent. The user-selected output file is published privately with mode `0600` and no-clobber semantics. Package values and raw rows can disclose installed software or system details, remain on disk until deleted, and are not automatically redacted.

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

The current paths are `inspect <trace-file>` → bounded regular-file read → strict UTF-8 and line parsing → versioned JSON by default or ASCII-only escaped text with `--format text`; `diff <left-trace> <right-trace>` → parse both inputs → conservative multiset comparison → versioned JSON or ASCII-only escaped text; `explain <trace-file>` → bounded typed summary retaining selected outcome/evidence references and known unknowns; `explain --diff LEFT RIGHT` → the conservative diff engine → bounded count/evidence summary; `explain --inventory-diff BEFORE AFTER` → strict schema-v2 package snapshot parsing → bounded package additions/removals/version/status changes where source completeness permits; Linux `diff --format html --output REPORT LEFT RIGHT` → bounded HTML buffer → mode-0600 no-clobber report publication; Linux `record --trace OUTPUT -- PROGRAM [ARGS...]` → private FIFO → bounded raw trace → no-clobber file publication; and Linux `record --bundle DIR -- PROGRAM [ARGS...]` → the same bounded capture → trace hash plus fixed schema-v2 metadata → fsynced two-file staging directory → atomic sibling `renameat2(RENAME_NOREPLACE)`. The record command executes the selected program under strace with the user's normal permissions.

Deterministic explanations do not invoke a language model and omit raw arguments, raw result strings, source fingerprints, and free-form diagnostics. Package inventory comparison covers only listed package-manager sources. Process, permission, and startup inventory change comparisons remain unimplemented. The optional local trace model adapter has a separate preview and digest-confirmed execution path. It passes typed facts only to a pinned local llama.cpp CLI, applies resource limits and Linux network-syscall denial, and validates generated summary citations against preview evidence IDs. This is defense in depth rather than a sandbox; generated prose remains unverified interpretation. It is implemented for Linux x86_64 and remains subject to the M8 validation and release review in `docs/LOCAL_MODEL_EVALUATION.md`.

## Current parser contract

Linux `sideeffect diff --bundles LEFT_DIR RIGHT_DIR` reads both operands through the strict v1/v2 bundle validator used by `inspect --bundle`, then parses and compares the contained trace bytes. JSON and text output preserve raw-trace diff semantics and omit local bundle paths; HTML is also available through the existing bounded offline report writer. The manifest status fields do not establish capture completeness or command success. A bundle stopped by its requested time limit is rejected before comparison because its event set is known to be incomplete.

The parser accepts a bounded subset of line-oriented `strace` output. Record uses `-f -ttt -yy -s 256 -e trace=%process,%file,%network --kill-on-exit -o <generated FIFO>`; `inspect` does not verify how an input was produced. For current `strace` option and output behavior, see the [`strace(1)` manual](https://man7.org/linux/man-pages/man1/strace.1.html). A smoke test used an extracted strace 6.19 package in WSL without installing it system-wide: `/usr/bin/true` and `/usr/bin/false` produced bounded traces which parsed completely. This does not validate broad syscall or file/network-event coverage.

The parser recognizes PID and timestamp prefixes, syscall calls, common control records, and unfinished/resumed calls. It retains the original raw line and byte offset/length, plus raw syscall argument/result text. Unknown, malformed, or unpaired continuation lines remain in the JSON with diagnostics; invalid UTF-8 and hard budget violations return an error and no document. `parse_status` reports whether the parser classified and reconciled the supplied text; it never asserts capture completeness.

For `openat` and `openat2`, an optional `lexical_path_hint` is derived only from a plain printable-ASCII quoted path operand. An absolute operand is preserved as written; a relative operand is joined to an absolute `AT_FDCWD</...>` or numeric `<...>` directory annotation from `-yy`. The derived JSON value names its basis and stays attached to the original record evidence. Trace inspection schema v7 and comparison schema v3 include the source fingerprints; earlier trace schema v1-v5 and diff schema v1-v2 JSON exports are not imported or migrated. The CLI reads raw `strace` text and does not import or migrate prior SideEffect JSON exports. The hint does not query the filesystem, normalize `.`/`..`, follow symlinks, or track descriptor identity; it may be wrong around symlinks, descriptor reuse/deletion, `openat2` resolution flags, or truncated traces. Escaped, non-ASCII, deleted, truncated, malformed, or unsupported cases omit the hint. Raw arguments are authoritative. Diff output may carry a separate hint from each side strictly for display; `matching_policy.display_only_fields` marks it as display-only, and the matcher never consults it. The text and HTML renderers label it accordingly and keep original arguments visible.

For complete `execve`/`execveat`, `openat`/`openat2`, and `connect` rows, inspection attaches a conservative `outcome` enum to the same record as its exact evidence reference. It recognizes only strict success forms, Linux `-1 ERRNO (message)` failure forms, and `connect`'s `EINPROGRESS` as `in_progress`; other result spellings are `unknown`. Unfinished/resumed rows and other syscall names have no outcome. This is a syscall-result summary only and does not infer a higher-level effect.

For `-yy` output, an unquoted `<` begins a file-descriptor annotation and the parser skips through its next `>`. An unterminated annotation makes that line malformed. Other valid strace representations may be reported as partial until fixtures demonstrate support.

The current hard budgets are 32 MiB total input bytes, 64 KiB per physical record (excluding LF), 100,000 physical records, and 64 MiB for the serialized JSON document. Records include control and unparsed lines. The event fields duplicate portions of raw text and have bounded string lengths because every source record and the overall input are bounded; the serialized document is independently capped before it is written to stdout. These initial values need review against real captures before release.

## Component responsibilities

### CLI and capture coordinator

The CLI preserves argument boundaries, starts the external tracer, manages private staging, and publishes either one raw trace file or one complete run bundle. Linux `inspect --bundle DIR` securely opens and validates supported v1 and v2 bundles before passing its bounded trace bytes through the same parser and renderer as raw trace inspection. The target runs with the invoking user's normal permissions; tracing is observation, not isolation. `--duration-seconds <seconds>` (integer from 1 to 3600) optionally bounds wall-clock capture time; on expiry SideEffect stops the direct tracer, publishes available nonempty partial evidence, and exits `2`, while target outcome and capture completeness remain unknown. No automatic privilege escalation or capture of arbitrary environment variables occurs. The command's stdout/stderr remain inherited. Trace output may contain command arguments, paths, socket addresses, and other sensitive data.

Recording uses a generated FIFO instead of `strace -o FILE`, allowing the parent to read incrementally and enforce the same 32 MiB cap used by `inspect`. When the cap is exceeded, it stops reading, kills only its direct strace process, and discards the staged partial trace without publishing it. SideEffect's tested minimum is strace 6.8; strace introduced `--kill-on-exit` in 6.6, and the option also depends on supported kernel behavior. It is best-effort cleanup; descendants that escape tracing via `CLONE_UNTRACED` may survive. A smoke test with extracted strace 6.19 ran `/usr/bin/true` and `/usr/bin/false`; their traces were bounded, mode 0600, and parsed completely. This test does not establish broad compatibility or file/network-event coverage. The recorder rejects an empty trace to avoid presenting a tracer startup/option failure as a usable artifact. Existing destinations, including symlinks, are rejected. Publication first uses same-directory `linkat`; only errors indicating hard links are unsupported trigger an anchored `renameat2(RENAME_NOREPLACE)` fallback. Both routes atomically preserve no-clobber behavior, and other link errors are returned without fallback. If the kernel or filesystem does not support the no-replace rename operation either, publication fails closed. The selected parent directory is canonicalized and opened once; subsequent FIFO, staging, publication, and cleanup operations are relative to held directory descriptors, so renaming that directory during capture does not redirect writes. Traces are staged with mode 0600 in a private mode-0700 directory. After SideEffect finalizes and publishes a nonempty trace, it propagates the normal exit code reported by strace or re-raises the reported signal (with a conventional 128+signal fallback if re-raising fails). The strace manual says it normally mirrors the wrapped command's exit status or signal; this is not independent verification of command outcome, tracer success, or capture completeness. Detected SideEffect capture failures take precedence and are reported as errors. Command stdout/stderr remain inherited, and arbitrary environment values are not collected by SideEffect. SIGINT, SIGTERM, SIGHUP, and SIGQUIT received by SideEffect trigger direct tracer termination and staged-output cleanup; parent death sends SIGKILL to strace, which requests best-effort traced-process cleanup. A system crash can leave a private staging directory. See the [`strace(1)` manual](https://man7.org/linux/man-pages/man1/strace.1.html).

The FIFO anchor is opened with `O_CLOEXEC`, so the traced command cannot keep it open. Parent supervision polls the FIFO and strace child; there is no separate reader process or shell command string. A hard kill or system crash can leave a private staging directory behind. Command execution remains unrestricted and tracing may alter timing or behavior.

Evidence bundles and report exports use conservative output-path handling. The HTML exporter is Linux-only, buffers rendered output up to the shared 64 MiB cap before creating a staged report, writes it with mode 0600, and publishes without replacing an existing destination using the same hard-link and narrowly selected no-replace rename fallback as trace output. It uses a static HTML/CSS template, restrictive CSP, no script or remote assets, and inserts trace values only as escaped text; local input paths are omitted. Reports can still contain sensitive raw arguments, paths, and endpoints. Tests cover injection strings, controls/bidi formatting, output limits, existing destinations, symlink targets, and staged cleanup. Any deliberate overwrite option requires separate product/security review.

### `strace` integration

The initial capture backend invokes external `strace` on Linux x86_64 with child-following enabled and a scoped set of process, file, and network-related syscalls. The selected capture profile is versioned as `linux_process_file_network_v1`. New bundle schema v2 records optional requested duration and stop reason; schema v1 remains readable. In bundle mode, the manifest records parsed strace major/minor, the raw strace-reported exit code or signal, command outcome `not_independently_verified`, capture completeness `unknown`, and inherited-but-not-captured markers for command streams and tracer diagnostics. It does not store the program/argv, environment, cwd, username, absolute paths, streams, diagnostics, or parsed event copies. The same raw trace remains the evidence artifact; its byte length and SHA-256 are recorded. The hash identifies bytes only and does not establish authenticity or completeness. Bundle mode is opt-in. `inspect --bundle DIR` accepts supported v1 and v2 schemas, rejects unknown fields and extra directory entries, requires the invoking user to own the directory and its mode-0700 directory/mode-0600 single-link regular files, and verifies the bounded manifest and trace length/SHA-256 before parsing. Inspecting a bundle stopped at its time limit returns status `2` and warns that absence from the trace is not evidence of non-occurrence; `diff --bundles` refuses such bundles because their event sets are incomplete. If the atomic rename succeeds but syncing the parent directory fails, the complete bundle is visible and the CLI warns that persistence across sudden power loss is uncertain while propagating the recorded strace status.

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

The JSON format receives an explicit schema version before it is treated as a user-facing interface. Current inspection documents are schema v7; diff documents remain schema v3. Schema-v2 bundle inspection adds its stop reason and optional requested time limit as `bundle_capture`; raw traces and legacy schema-v1 bundles omit the field. The source fingerprint fields were added in v3, outcome summaries in v4, process-creation evidence relations in v5, schema v6 was not published; schema v7 adds optional schema-v2-bundle capture context and clarifies `caller_task_id`. Earlier trace schema v1-v5 and diff schema v1-v2 exports remain standalone and are not imported by this CLI. Unknown future fields should be handled according to a documented compatibility policy.

### Inventory startup configuration

Linux `inventory startup` emits aggregate `sideeffect.startup_inventory` v2 with distinct XDG autostart, systemd unit-file/enablement-reference, common SysV init/runlevel, and common cron components. Each component retains source paths, source status, diagnostics, and bounded line or link-target evidence. Commands and scripts are inert; no parser executes or shell-interprets them. The scan uses curated paths rather than an exhaustive view of systemd's effective load paths or distribution-specific startup mechanisms. It does not determine whether an item is applicable, enabled in a running manager, or executed. Missing optional paths are distinct from inaccessible/unsupported/limit-affected source data.
### Event model and provenance

The canonical event vocabulary should initially include process execution/lifecycle, supported file operations, and connection-related operations. Event fields distinguish request/attempt from successful result where the syscall result provides that distinction.

Schema v5 introduced `process_lineage`; current schema v7 records a `caller_task_id` and the positive child PID returned by supported process-creation calls. The `strace -f` line prefix identifies the calling task/thread ID, not necessarily the Linux parent process PID when a non-leader thread creates a process. These relations link syscall caller evidence to the returned PID and do not assert an OS parent-child relationship. Complete successful `fork`/`vfork` calls and qualifying `clone`/`clone3` calls are considered. A uniquely paired unfinished/resumed `clone3` call may supply its flags and result across two rows; the relation links to the result row and supporting unfinished row. Unpaired continuation rows, ambiguous child-PID claims, unsupported clone flags, and configured bounds produce diagnostics and omitted relations. No OS parent PID, PID generation, transitive tree, capture root, or configured-startup causation is inferred. The separate `correlate-startup` operation reports only exact literal absolute executable-path candidate matches between selected XDG/systemd configuration values and successful exec filename arguments in saved inputs. It retains source and trace references and all duplicates; its runtime evidence calls the `strace -f` row-prefix identifier `caller_task_id`, which can be a thread ID. Unsupported relevant syntax makes correlation partial; copied configuration/source metadata is capped at 8 MiB. It does not resolve command semantics, symlink targets, or canonical paths, and leaves cron/SysV unassociated. Exact literal paths are compared as written and can themselves name symlinks. File paths may be resolved using observed working-directory changes, directory file descriptors, and path arguments where the parser can do so reliably. If resolution is ambiguous, preserve the original path and mark the canonical path unresolved rather than inventing a location.

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

Rust is the implementation stack for the core CLI, parser, schema, diff engine, and renderer. The source crate declares Apache-2.0 in `Cargo.toml` and includes the matching `LICENSE`. Runtime capture requires a separately installed external `strace` 6.8 or newer; SideEffect does not link, bundle, or redistribute `strace`. Upstream identifies `strace` itself as LGPL-2.1-or-later ([upstream license statement](https://github.com/strace/strace/blob/master/README.md)). Users obtain it through their operating-system package source. Any future installer or binary distribution that includes `strace` requires a separate review of the exact binary's license, notices, and package obligations; current source-only distribution does not establish legal clearance for such bundling.

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
