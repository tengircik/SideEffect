# SideEffect

SideEffect is a local-first Rust CLI for inspecting `strace` text and preserving event-level evidence in JSON.

> **Status: early implementation.** `inspect` reads a local trace file and writes versioned JSON. `diff` compares two complete parses as JSON or terminal-safe text. On Linux, `record` can run a command under external `strace` and publish one bounded raw trace. A smoke test with extracted strace 6.19 captured `/usr/bin/true` and `/usr/bin/false` under WSL; broad trace coverage and compatibility are still unvalidated. Recording is not a sandbox. HTML reports are not implemented.

## Try the current command

From the repository root, run:

```sh
cargo run -- inspect tests/fixtures/strace/synthetic-minimal.trace
```

This prints a schema-v1 JSON document containing parsed records, raw trace lines, source byte offsets, and diagnostics. The fixture is synthetic; it is not a real system capture. Exit status `0` means every input record was classified and continuation records were reconciled; `2` means JSON was produced with a partial parse; `1` means the input or output could not be processed. **Parse status says nothing about whether the original OS capture observed every event.**

## What the parser accepts

The parser handles a bounded subset of line-oriented `strace` text, including syscall records, common control lines, and `-yy` file-descriptor annotations. `record` uses `-f -ttt -yy -s 256 -e trace=%process,%file,%network --kill-on-exit` and a generated FIFO output path; `inspect` does not verify how an input was produced. See the [`strace(1)` manual](https://man7.org/linux/man-pages/man1/strace.1.html). Smoke testing used extracted strace 6.19 in WSL, not a system installation, and does not validate all supported records or events.

Input is limited to 32 MiB, each physical record to 64 KiB, and the document to 100,000 records. JSON output is limited to 64 MiB. Oversized or invalid UTF-8 input fails without emitting JSON. Unrecognized, malformed, or unpaired continuation lines remain visible as raw records with diagnostics.

## Compare two traces

```sh
cargo run -- diff tests/fixtures/diff/baseline.synthetic.trace tests/fixtures/diff/updated.synthetic.trace
```

`diff` emits schema-v1 observed syscall-row additions, removals, and uniquely paired result changes with source line/byte references. References use the baseline input for `before` and candidate input for `after`, in command argument order. The fixture pair is synthetic and is not a real capture. A comparison requires both inputs to parse completely; parser status still cannot prove capture completeness. The initial matcher treats records as a multiset, ignores only the parsed PID and timestamp prefixes for matching, and keeps exact arguments/results (including path and file-descriptor text). When multiple same-signature result records remain and no pairing is justified, they remain separate additions/removals instead of an invented changed-event pair. Paired unfinished/resumed rows are compared as separate trace rows, not merged into a reconstructed call. Control rows are outside the initial comparison and their counts are reported. The process/file/network labels are syscall-name buckets; they do not claim that an operation succeeded or caused another event.

Each input remains bounded by the parser limits above (64 MiB combined maximum); a diff has at most 200,000 grouped delta rows and JSON/text output is capped at 64 MiB before stdout is written. The comparison keeps argument/result strings borrowed from parsed input and emits source references rather than copies of entire raw lines. Review reports before sharing: they may contain sensitive paths, arguments, and endpoint details.

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

The broader goal is to compare selected process, file, and network-related observations from two command runs and produce an evidence-linked offline report. The initial target is Linux x86_64; an existing WSL2 installation may be used, but native Windows tracing is not in scope. HTML reporting is not implemented.

## Limits and privacy

`inspect` and `diff` read local files and write JSON or escaped terminal text to stdout. `record` executes the selected command under `strace` and writes a local raw trace. No command uploads data or uses telemetry. Traces and output retain arguments, paths, network endpoints, or other sensitive values. Review them before sharing.

The planned capture product will be an observation aid, not a sandbox, malware detector, complete audit, or safety verdict. A syscall attempt does not necessarily mean it succeeded, and event proximity does not prove causation. See [SECURITY.md](SECURITY.md).

## Documentation

- [Product brief](docs/PRODUCT.md)
- [Architecture plan](docs/ARCHITECTURE.md)
- [Delivery plan](docs/PLAN.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE)
