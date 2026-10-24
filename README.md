# SideEffect

SideEffect is a local-first Rust CLI for inspecting `strace` text and preserving event-level evidence in JSON.

> **Status: early implementation.** `inspect` reads one local trace file and writes a versioned JSON document. `diff` compares two fully parsed traces and writes a versioned JSON comparison. Neither command runs `strace` or executes a command; HTML reports and capture orchestration are not implemented.

## Try the current command

From the repository root, run:

```sh
cargo run -- inspect tests/fixtures/strace/synthetic-minimal.trace
```

This prints a schema-v1 JSON document containing parsed records, raw trace lines, source byte offsets, and diagnostics. The fixture is synthetic; it is not a real system capture. Exit status `0` means every input record was classified and continuation records were reconciled; `2` means JSON was produced with a partial parse; `1` means the input or output could not be processed. **Parse status says nothing about whether the original OS capture observed every event.**

## What the parser accepts

The parser handles a bounded subset of line-oriented `strace` text, including syscall records, common control lines, and `-yy` file-descriptor annotations. A recommended input profile for future capture support is `-f -ttt -yy -s 256 -e trace=%process,%file,%network -o FILE`; `inspect` does not verify that a file was generated with those exact options. See the [`strace(1)` manual](https://man7.org/linux/man-pages/man1/strace.1.html). Compatibility with a real `strace` capture has not yet been integration-tested in this environment.

Input is limited to 32 MiB, each physical record to 64 KiB, and the document to 100,000 records. JSON output is limited to 64 MiB. Oversized or invalid UTF-8 input fails without emitting JSON. Unrecognized, malformed, or unpaired continuation lines remain visible as raw records with diagnostics.

## Compare two traces

```sh
cargo run -- diff tests/fixtures/diff/baseline.trace tests/fixtures/diff/candidate.trace
```

`diff` emits schema-v1 observed syscall-row additions, removals, and uniquely paired result changes with source line/byte references. References use the baseline input for `before` and candidate input for `after`, in command argument order. The fixture pair is synthetic and is not a real capture. A comparison requires both inputs to parse completely; parser status still cannot prove capture completeness. The initial matcher treats records as a multiset, ignores only the parsed PID and timestamp prefixes for matching, and keeps exact arguments/results (including path and file-descriptor text). When multiple same-signature result records remain and no pairing is justified, they remain separate additions/removals instead of an invented changed-event pair. Paired unfinished/resumed rows are compared as separate trace rows, not merged into a reconstructed call. Control rows are outside the initial comparison and their counts are reported. The process/file/network labels are syscall-name buckets; they do not claim that an operation succeeded or caused another event.

Each input remains bounded by the parser limits above (64 MiB combined maximum); a diff has at most 200,000 grouped delta rows and uses the 64 MiB JSON output cap. The comparison keeps argument/result strings borrowed from parsed input and emits source references rather than copies of entire raw lines. Review reports before sharing: they may contain sensitive paths, arguments, and endpoint details.

## Planned product

The broader goal is to capture selected process, file, and network-related events from a command and produce an evidence-linked offline report. Capture and HTML reporting are not implemented. The initial target is Linux x86_64 with an externally installed `strace`; WSL2 may be used if already installed, but native Windows tracing is not in scope.

## Limits and privacy

The current command only reads a regular input file and writes JSON to stdout; it does not execute the traced command or upload data. JSON retains raw trace lines and may expose command arguments, paths, network endpoints, or other sensitive values. Review it before sharing.

The planned capture product will be an observation aid, not a sandbox, malware detector, complete audit, or safety verdict. A syscall attempt does not necessarily mean it succeeded, and event proximity does not prove causation. See [SECURITY.md](SECURITY.md).

## Documentation

- [Product brief](docs/PRODUCT.md)
- [Architecture plan](docs/ARCHITECTURE.md)
- [Delivery plan](docs/PLAN.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE)
