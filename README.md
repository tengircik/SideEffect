# SideEffect

SideEffect's product goal is an on-demand, local audit that helps people understand software on their computer: available permissions and startup hooks/scripts, plus observed runtime activity, all tied to evidence. It does not continuously monitor the computer.

> **Status: early implementation; the product goal is not yet implemented.** The current Linux x86_64 CLI inspects local `strace` text and bundles, compares two complete traces, resolves exact evidence references, and can record one selected command with its traced children. This is not a computer-wide software, permission, or hooks/scripts inventory. A narrow Linux integration test records temporary-file and loopback TCP activity plus a child process, then verifies inspect and diff evidence; it has passed in WSL against extracted Ubuntu strace 6.8 and 6.19 packages and in Ubuntu 24.04 CI. These runs do not verify every supported kernel or trace event. Recording is not a sandbox.

## Try the current command

From the repository root, run:

```sh
cargo run -- inspect tests/fixtures/strace/synthetic-minimal.trace
```

This prints a schema-v4 JSON document containing parsed records, raw trace lines, source byte offsets, diagnostics, optional `lexical_path_hint` values, conservative `outcome` summaries for selected syscalls, and the SHA-256 fingerprint of the exact bytes parsed. The fixture is synthetic; it is not a real system capture. A fingerprint identifies bytes but does not authenticate them or establish capture completeness. For a readable, terminal-safe view of every parsed and unparsed record, run:

```sh
cargo run -- inspect --format text tests/fixtures/strace/synthetic-minimal.trace
```

Exit status `0` means every input record was classified and continuation records were reconciled; `2` means JSON or text was produced with a partial parse; `1` means the input or output could not be processed. Text output retains raw values and is not redacted. **Parse status says nothing about whether the original OS capture observed every event.**

For `openat` and `openat2`, records may also include a `lexical_path_hint` when the path argument is unambiguously printable and either absolute or paired with an absolute `-yy` directory annotation. It preserves `.` and `..` segments and is not a canonical or filesystem-resolved path; symlinks, descriptor reuse, resolution flags, and trace truncation can make it differ from the path the kernel ultimately used. Raw arguments remain the evidence source.

Inspection text shows an `Outcome` line for complete `execve`/`execveat`, `openat`/`openat2`, and `connect` records. It is a conservative summary of the syscall result only; unfinished/resumed rows and other syscall names have no outcome.

`inspect` and ordinary `diff` consume raw `strace` text; `inspect --bundle DIR` reads only a validated `sideeffect.run` v1 recording bundle. `diff --bundles LEFT_DIR RIGHT_DIR` validates both bundles and compares their contained traces with the same JSON, text, or Linux HTML output as raw trace comparison. Bundle validation checks the fixed `run.json` and `trace.strace` entries, ownership and private modes, symlink and size rules, supported manifest fields, and exact trace length and SHA-256 before parsing; manifest status fields do not establish capture completeness or command success. Earlier schema-v1 through v3 trace exports and schema-v1/v2 diff exports remain standalone; the current CLI does not import or migrate them. Trace inspection uses schema v4, while diff output remains schema v3. A SHA-256 fingerprint is identity metadata, not a signature, authenticity proof, redaction, or completeness signal. Because traces may be sensitive, fingerprints are sensitive metadata too; low-entropy traces may be guessed, and exact trace bytes never leave the local machine through these commands.

Published traces, bundles, and report files stay at the output paths you choose until you delete them. SideEffect does not upload, rotate, or automatically delete published data. Handled failures and cancellation clean up private staging; a machine crash can leave a private staging directory behind.

## What the parser accepts

The parser handles bounded outer syntax for line-oriented `strace` text, including syscall records, common control lines, and `-yy` file-descriptor annotations; it preserves raw arguments and results rather than fully decoding each syscall. `record` uses `-f -ttt -yy -s 256 -e trace=%process,%file,%network --kill-on-exit` and a generated FIFO output path; `inspect` does not verify how an input was produced. See the [`strace(1)` manual](https://man7.org/linux/man-pages/man1/strace.1.html). Narrow real-tracer checks have exercised strace 6.8 in Ubuntu 24.04 CI and WSL, and 6.19 in WSL; they do not validate all records or events. See the [compatibility and observation matrix](docs/INSTALL.md#compatibility-and-observation-matrix).

Input is limited to 32 MiB, each physical record to 64 KiB, and the document to 100,000 records. JSON and text output are limited to 64 MiB. Oversized or invalid UTF-8 input fails without emitting an inspection document. Unrecognized, malformed, or unpaired continuation lines remain visible as raw records with diagnostics.

## Compare two traces

```sh
cargo run -- diff tests/fixtures/diff/baseline.synthetic.trace tests/fixtures/diff/updated.synthetic.trace
```

`diff` emits schema-v3 observed syscall-row additions, removals, and uniquely paired result changes with source line/byte references and separate SHA-256 fingerprints for the exact baseline and candidate bytes. `matching_policy.exact_fields` names the compared row/result fields, while `matching_policy.display_only_fields` identifies lexical hints that never participate in matching. References use the baseline input for `before` and candidate input for `after`, in command argument order. Optional side-specific lexical path hints are display-only; matching uses exact raw arguments and results, never the hints. Fingerprints identify each input but do not authenticate it or establish capture completeness. The fixture pair is synthetic and is not a real capture. A comparison requires both inputs to parse completely; parser status still cannot prove capture completeness. The initial matcher treats records as a multiset, ignores only the parsed PID and timestamp prefixes for matching, and keeps exact arguments/results (including path and file-descriptor text). When multiple same-signature result records remain and no pairing is justified, they remain separate additions/removals instead of an invented changed-event pair. Paired unfinished/resumed rows are compared as separate trace rows, not merged into a reconstructed call. Control rows are outside the initial comparison and their counts are reported. The process/file/network labels are syscall-name buckets; they do not claim that an operation succeeded or caused another event.

For complete `execve`/`execveat`, `openat`/`openat2`, and `connect` records, inspection may include an `outcome` of `success`, `failure`, `in_progress`, or `unknown`. The summary is derived only from strict result spellings (`connect`'s `EINPROGRESS` is in progress); unsupported or malformed result forms are `unknown`. It does not describe a higher-level effect. The exact `raw_result`, `raw_line`, and sibling evidence reference remain available. Other syscalls and unfinished/resumed rows have no outcome field.

## Create an aggregate diff summary

For an export that omits event-level values, run:

```sh
sideeffect diff-summary BASELINE CANDIDATE
```

This emits a separate `sideeffect_redacted_diff_summary` schema containing only added/changed/removed diff-group counts by fixed category. It omits syscall names, raw arguments/results, lexical path hints, source hashes, evidence references, and local input paths. This is field omission, not secret detection: categories and counts may still be sensitive, so the summary is not a safe-to-share verdict.

On Linux, write the same aggregate as a local static HTML report with:

```sh
sideeffect diff-summary --format html --output SUMMARY.html BASELINE CANDIDATE
```

The HTML output is bounded, mode `0600`, no-clobber, offline, and contains no scripts or remote assets. JSON goes to stdout; neither command uploads data. This summary is a distinct aggregate export, not a redacted detailed diff, and it contains no event-level references.

To look up a diff reference from the baseline fixture, use its `before` tuple (`line=2 byte=65 length=72`) and source hash:

```sh
sideeffect evidence tests/fixtures/diff/baseline.synthetic.trace d75a97b3058387a94ca085ed28ab08826671f305be8c70e947df902de553ca9d 2 65 72
```

The command first verifies that the supplied lowercase SHA-256 fingerprint matches the exact bounded bytes parsed, then requires an exact line, byte-offset, and byte-length match to one parsed syscall row. It rejects malformed or mismatched fingerprints and control, unparsed, out-of-range, or mismatched references. If the trace has a partial parse, it prints a warning and exits with status `2`. A successful lookup establishes byte identity relative to the supplied fingerprint and a positional match within those bytes; it does not establish authenticity or capture completeness. Fingerprints are not redaction and can reveal equality or be guessed for low-entropy inputs.

Each input remains bounded by the parser limits above (64 MiB combined maximum); a diff has at most 200,000 grouped delta rows and JSON/text output is capped at 64 MiB before stdout is written. The comparison keeps argument/result strings borrowed from parsed input and emits source references rather than copies of entire raw lines. Review reports before sharing: they may contain sensitive paths, arguments, and endpoint details.

On Linux, create a self-contained static report with:

```sh
sideeffect diff --format html --output REPORT.html BASELINE CANDIDATE
```

The report is capped at 64 MiB, mode 0600, and never replaces an existing destination. It uses no scripts, external assets, or network requests; trace-derived markup is escaped, and control/bidi formatting characters are shown as visible spellings. Local input paths are omitted, but raw arguments, paths, and endpoint details may remain. HTML file export is not available in the native Windows build; Windows users with WSL2 can run the Linux build there. Review the report before sharing it.

For a readable terminal view of the same comparison, use:

```sh
cargo run -- diff --format text tests/fixtures/diff/baseline.synthetic.trace tests/fixtures/diff/updated.synthetic.trace
```

Text output is ASCII-only: quotes, control characters, terminal escapes, and non-ASCII scalars in trace values are escaped, so imported content cannot inject ANSI terminal control sequences. The output remains sensitive and is not sanitized for sharing.

## Record one command (Linux only)

To compare two existing validated run bundles directly, use `sideeffect diff --bundles BASELINE_DIR CANDIDATE_DIR`. Add `--format text` for terminal-safe text or, on Linux, `--format html --output REPORT.html` for the bounded offline report. Bundle paths are not included in comparison output. The strict reader verifies each manifest and trace before parsing; manifest status fields do not prove successful execution or complete capture, and partial traces are rejected before diff output.

```sh
sideeffect record --trace ./run.trace -- /usr/bin/printf 'hello\n'
```

This requires Linux and an external `strace` version 6.8 or newer. Although `--kill-on-exit` exists in strace 6.6, 6.8 is the lowest release exercised by SideEffect's real-tracer integration checks. SideEffect passes the program and each argument separately, without a shell; the command runs with the invoking user's permissions. Its stdout and stderr remain attached to the terminal. The trace is written with mode `0600`, capped at 32 MiB, and published only if that destination does not already exist. Once SideEffect has finalized and published a nonempty trace, it propagates the `strace`-reported exit code; if `strace` reports signal termination, SideEffect terminates with that signal. The `strace(1)` manual says the tracer normally mirrors the wrapped command's exit status or signal. SideEffect capture errors take precedence and are reported as errors. The propagated status is not an independent verification of command outcome, tracer success, or capture completeness.

If the trace exceeds the limit, SideEffect terminates its `strace` process and discards the partial trace. `--kill-on-exit` asks supported strace/kernel combinations to kill tracees when the tracer exits, but descendants that escape tracing (for example, through `CLONE_UNTRACED`) may survive. This feature does not constrain the command: it can modify files, access the network, and perform other actions available to the user. Tracing can also change timing or behavior. Do not use it as a sandbox or run untrusted programs without separate OS isolation. Raw traces can contain arguments, paths, socket addresses, and other sensitive values.

To retain a minimal local run manifest beside the raw evidence, use:

```sh
sideeffect record --bundle ./run.sideeffect -- /usr/bin/printf 'hello\n'
```

The bundle directory contains exactly `run.json` and `trace.strace`. It is staged beside the requested destination and published with one no-clobber directory rename; the directory is mode `0700` and both files are mode `0600`. Bundle creation rejects destination parents writable by other users unless the sticky bit protects entries (as in `/tmp`). Processes running as the same user are within the trusted local-user boundary and can still alter files they own. The schema `sideeffect.run` version 1 records SideEffect and strace versions, the fixed capture profile, raw strace-reported exit code or signal, the exact trace byte length and SHA-256, and explicit unknown/unverified status fields. It deliberately omits program/argument strings, environment, working directory, user identity, absolute paths, command output, tracer diagnostics, and parsed event copies. The raw trace itself may contain arguments, paths, and endpoint values. Hashes can reveal equality and are not authenticity proofs. Files and the staging directory are synced before publication; if syncing the parent directory fails after the atomic rename, the complete bundle is visible and the CLI warns that persistence across sudden power loss is uncertain while still propagating the strace-reported status. Bundle creation and inspection are Linux-only. `sideeffect inspect --bundle DIR` validates the fixed schema and files, then emits the same document as inspecting `trace.strace` directly; the bundle path is not included in that document.

## Planned product

The broader product goal is a user-triggered, local audit of software on supported platforms: show available permission and startup-hook/script configuration, then observed activity from an explicitly requested capture, with each result tied to its evidence. The current Linux x86_64 CLI is only the trace-inspection and paired-comparison foundation; inventory and native Windows support are future milestones. SideEffect does not continuously monitor the computer. Static HTML export exists on Linux; browser compatibility beyond renderer tests remains unverified.

## Limits and privacy

`inspect` and `diff` read local files and write JSON or escaped terminal text to stdout. `record` executes the selected command under `strace` and writes a local raw trace. No command uploads data or uses telemetry. Traces and output retain arguments, paths, network endpoints, or other sensitive values. Review them before sharing.

The current capture feature is an observation aid, not a sandbox, malware detector, exhaustive computer audit, or safety verdict. A syscall attempt does not necessarily mean it succeeded, and event proximity does not prove causation. See [SECURITY.md](SECURITY.md).

## Documentation

- [Build and install from source](docs/INSTALL.md)
- [Product brief](docs/PRODUCT.md)
- [Architecture plan](docs/ARCHITECTURE.md)
- [Delivery plan](docs/PLAN.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE)
