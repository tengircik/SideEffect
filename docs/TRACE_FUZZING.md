# Trace parser fuzzing

The `fuzz/` package uses cargo-fuzz and libFuzzer to call
`parse_trace_bytes` with arbitrary byte slices. The harness sets explicit
limits of 64 KiB per input, 4 KiB per physical record, and 512 records. Parser
errors are valid outcomes; panics are left visible to libFuzzer as crashes.

The checked-in corpus seed is synthetic and contains no data from a real
capture. New corpus entries created during local fuzzing may contain sensitive
input and should be reviewed before retaining or sharing them. Crash artifacts
and build output are ignored by Git.

On Linux x86_64 with nightly Rust and cargo-fuzz installed, run sustained local
fuzzing from the repository root:

```sh
cargo fuzz run parse_trace_bytes
```

CI runs a bounded smoke session with 100 libFuzzer executions and a maximum
input length of 64 KiB. This confirms that the harness builds and executes; it
is not a coverage, parser-completeness, or robustness guarantee. No generated
inputs or crash artifacts are uploaded by CI.
