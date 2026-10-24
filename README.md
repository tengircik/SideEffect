# SideEffect

SideEffect is a local-first Rust CLI for inspecting `strace` text and preserving event-level evidence in JSON.

> **Status: early implementation.** `inspect` reads a local trace file and writes versioned JSON by default, or terminal-safe text with `--format text`. `diff` compares two complete parses as JSON or terminal-safe text; Linux can also write a bounded, offline HTML report. `evidence` resolves an exact diff line/byte/length reference to a parsed row in the selected trace file. On Linux, `record` can run a command under external `strace` and publish one bounded raw trace. A Linux integration test records temporary file and loopback TCP activity, plus a child process on one side, then verifies inspect and diff evidence; it has passed in WSL against extracted Ubuntu strace 6.8 and 6.19 packages without system installation. It checks a child's successful `execve` as one complete row or as separate unfinished/resumed records, depending on tracer output, and verifies the observed diff row's source reference. It also tests that selected trace sentinels do not appear in captured command output, removes its temporary traces, and stores no CI artifacts. These runs do not verify every strace 6.6 build or kernel combination. Recording is not a sandbox.

## Try the current command

From the repository root, run:

```sh
cargo run -- inspect tests/fixtures/strace/synthetic-minimal.trace
```

This prints a schema-v3 JSON document containing parsed records, raw trace lines, source byte offsets, diagnostics, optional `lexical_path_hint` values, and the SHA-256 fingerprint of the exact bytes parsed. The fixture is synthetic; it is not a real system capture. A fingerprint identifies bytes but does not authenticate them or establish capture completeness. For a readable, terminal-safe view of every parsed and unparsed record, run:

```sh
cargo run -- inspect --format text tests/fixtures/strace/synthetic-minimal.trace
```

Exit status `0` means every input record was classified and continuation records were reconciled; `2` means JSON or text was produced with a partial parse; `1` means the input or output could not be processed. Text output retains raw values and is not redacted. **Parse status says nothing about whether the original OS capture observed every event.**

For `openat` and `openat2`, records may also include a `lexical_path_hint` when the path argument is unambiguously printable and either absolute or paired with an absolute `-yy` directory annotation. It preserves `.` and `..` segments and is not a canonical or filesystem-resolved path; symlinks, descriptor reuse, resolution flags, and trace truncation can make it differ from the path the kernel ultimately used. Raw arguments remain the evidence source.

`inspect` and `diff` consume raw `strace` text, not previously exported SideEffect JSON documents. Earlier schema-v1 and schema-v2 trace and diff JSON exports remain standalone; the current CLI does not import or migrate them. A SHA-256 fingerprint is identity metadata, not a signature, authenticity proof, redaction, or completeness signal. Because traces may be sensitive, fingerprints are sensitive metadata too; low-entropy traces may be guessed, and exact trace bytes never leave the local machine through these commands.

## What the parser accepts

The parser handles a bounded subset of line-oriented `strace` text, including syscall records, common control lines, and `-yy` file-descriptor annotations. `record` uses `-f -ttt -yy -s 256 -e trace=%process,%file,%network --kill-on-exit` and a generated FIFO output path; `inspect` does not verify how an input was produced. See the [`strace(1)` manual](https://man7.org/linux/man-pages/man1/strace.1.html). Smoke testing used extracted strace 6.19 in WSL, not a system installation, and does not validate all supported records or events.

Input is limited to 32 MiB, each physical record to 64 KiB, and the document to 100,000 records. JSON and text output are limited to 64 MiB. Oversized or invalid UTF-8 input fails without emitting an inspection document. Unrecognized, malformed, or unpaired continuation lines remain visible as raw records with diagnostics.

## Compare two traces

```sh
cargo run -- diff tests/fixtures/diff/baseline.synthetic.trace tests/fixtures/diff/updated.synthetic.trace
```

`diff` emits schema-v3 observed syscall-row additions, removals, and uniquely paired result changes with source line/byte references and separate SHA-256 fingerprints for the exact baseline and candidate bytes. `matching_policy.exact_fields` names the compared row/result fields, while `matching_policy.display_only_fields` identifies lexical hints that never participate in matching. References use the baseline input for `before` and candidate input for `after`, in command argument order. Optional side-specific lexical path hints are display-only; matching uses exact raw arguments and results, never the hints. Fingerprints identify each input but do not authenticate it or establish capture completeness. The fixture pair is synthetic and is not a real capture. A comparison requires both inputs to parse completely; parser status still cannot prove capture completeness. The initial matcher treats records as a multiset, ignores only the parsed PID and timestamp prefixes for matching, and keeps exact arguments/results (including path and file-descriptor text). When multiple same-signature result records remain and no pairing is justified, they remain separate additions/removals instead of an invented changed-event pair. Paired unfinished/resumed rows are compared as separate trace rows, not merged into a reconstructed call. Control rows are outside the initial comparison and their counts are reported. The process/file/network labels are syscall-name buckets; they do not claim that an operation succeeded or caused another event.

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

```sh
sideeffect record --trace ./run.trace -- /usr/bin/printf 'hello\n'
```

This requires Linux and an external `strace` version 6.6 or newer. SideEffect passes the program and each argument separately, without a shell; the command runs with the invoking user's permissions. Its stdout and stderr remain attached to the terminal. The trace is written with mode `0600`, capped at 32 MiB, and published only if that destination does not already exist. The tool prints the raw `strace` exit status; that value does not independently identify the command's exit status or prove that tracing completed without warnings.

If the trace exceeds the limit, SideEffect terminates its `strace` process and discards the partial trace. `--kill-on-exit` asks supported strace/kernel combinations to kill tracees when the tracer exits, but descendants that escape tracing (for example, through `CLONE_UNTRACED`) may survive. This feature does not constrain the command: it can modify files, access the network, and perform other actions available to the user. Tracing can also change timing or behavior. Do not use it as a sandbox or run untrusted programs without separate OS isolation. Raw traces can contain arguments, paths, socket addresses, and other sensitive values.

## Planned product

The broader goal is to compare selected process, file, and network-related observations from two command runs and produce an evidence-linked offline report. The initial target is Linux x86_64; an existing WSL2 installation may be used, but native Windows tracing is not in scope. Static HTML export exists on Linux; browser compatibility beyond renderer tests remains unverified.

## Limits and privacy

`inspect` and `diff` read local files and write JSON or escaped terminal text to stdout. `record` executes the selected command under `strace` and writes a local raw trace. No command uploads data or uses telemetry. Traces and output retain arguments, paths, network endpoints, or other sensitive values. Review them before sharing.

The planned capture product will be an observation aid, not a sandbox, malware detector, complete audit, or safety verdict. A syscall attempt does not necessarily mean it succeeded, and event proximity does not prove causation. See [SECURITY.md](SECURITY.md).

## Documentation

- [Build and install from source](docs/INSTALL.md)
- [Product brief](docs/PRODUCT.md)
- [Architecture plan](docs/ARCHITECTURE.md)
- [Delivery plan](docs/PLAN.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE)
