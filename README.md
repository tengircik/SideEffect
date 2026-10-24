# SideEffect

SideEffect is a local-first Rust CLI for inspecting `strace` text and preserving event-level evidence in JSON.

> **Status: early implementation.** The current `inspect` command reads one local trace file and writes a versioned JSON document to stdout. It does not run `strace`, execute a command, compare runs, or generate HTML reports.

## Try the current command

From the repository root, run:

```sh
cargo run -- inspect tests/fixtures/strace/synthetic-minimal.trace
```

This prints a schema-v1 JSON document containing parsed records, raw trace lines, source byte offsets, and diagnostics. The fixture is synthetic; it is not a real system capture. Exit status `0` means every input record was classified and continuation records were reconciled; `2` means JSON was produced with a partial parse; `1` means the input or output could not be processed. **Parse status says nothing about whether the original OS capture observed every event.**

## What the parser accepts

The parser handles a bounded subset of line-oriented `strace` text, including syscall records, common control lines, and `-yy` file-descriptor annotations. A recommended input profile for future capture support is `-f -ttt -yy -s 256 -e trace=%process,%file,%network -o FILE`; `inspect` does not verify that a file was generated with those exact options. See the [`strace(1)` manual](https://man7.org/linux/man-pages/man1/strace.1.html). Compatibility with a real `strace` capture has not yet been integration-tested in this environment.

Input is limited to 32 MiB, each physical record to 64 KiB, and the document to 100,000 records. JSON output is limited to 64 MiB. Oversized or invalid UTF-8 input fails without emitting JSON. Unrecognized, malformed, or unpaired continuation lines remain visible as raw records with diagnostics.

## Planned product

The broader goal is to capture selected process, file, and network-related events from a command, compare two runs, and produce an evidence-linked offline report. Those capture, comparison, and HTML-report features are not implemented yet. The initial target is Linux x86_64 with an externally installed `strace`; WSL2 may be used if already installed, but native Windows tracing is not in scope.

## Limits and privacy

The current command only reads a regular input file and writes JSON to stdout; it does not execute the traced command or upload data. JSON retains raw trace lines and may expose command arguments, paths, network endpoints, or other sensitive values. Review it before sharing.

The planned capture product will be an observation aid, not a sandbox, malware detector, complete audit, or safety verdict. A syscall attempt does not necessarily mean it succeeded, and event proximity does not prove causation. See [SECURITY.md](SECURITY.md).

## Documentation

- [Product brief](docs/PRODUCT.md)
- [Architecture plan](docs/ARCHITECTURE.md)
- [Delivery plan](docs/PLAN.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE)
