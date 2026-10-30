# Linux trace scaling benchmark

`scripts/trace_scale_benchmark.py` measures real `strace` capture, SideEffect `inspect`, and SideEffect `diff` at increasing parsed-record counts. It is an additional scaling harness; it does not replace `scripts/trace_benchmark.py`, validate R1 acceptance, or establish product-wide performance.

## Run

The harness requires Linux, Python 3, `strace`, and an already-built SideEffect executable. It does not build software or install dependencies. For the default matrix:

```sh
cargo build --release --locked --bin sideeffect
python3 scripts/trace_scale_benchmark.py \
  --sideeffect target/release/sideeffect \
  --output "$PWD/trace-scale-benchmark.json"
```

The report path must not already exist. The report is created exclusively with mode `0600`; it includes host identity and should be treated as private. Raw traces and CLI reports live only in a mode-0700 temporary directory and are removed on normal completion or failure. The final JSON report is capped at 1 MiB and excludes temporary paths and trace contents.

For a short smoke run, select a smaller size and one measured run:

```sh
python3 scripts/trace_scale_benchmark.py \
  --sideeffect target/release/sideeffect \
  --sizes 100 \
  --runs 1 --warmups 0 \
  --output "$PWD/trace-scale-smoke.json"
```

The workload source is generated in that temporary directory. It calls `os.getpid()` exactly N times; `strace` records only `getpid`, so unrelated Python startup file activity does not inflate the target. No command, path, dataset, or network input is accepted from the caller. This is intentionally a narrow synthetic syscall profile.

## Matrix and limits

Defaults are 10,000 and 100,000 requested records, plus a 1,000,000 row marked `not_attempted_limit`. The million-row capture is not started because SideEffect's parser accepts at most 100,000 records per input. This avoids knowingly generating an input that the actual CLI cannot fully parse. Sizes above the cap remain visible as explicit unattempted entries; other requested sizes above the trace or report budget are bounded by the same subprocess limits.

Each requested size uses one warm-up capture and three measured captures by default. Warm-ups are retained only inside the temporary directory and excluded from reported measured runs. For each capture the harness records trace bytes and invokes the real `sideeffect inspect TRACE`; the report includes inspect wall time, harness-observed child CPU time, inspect JSON bytes, parsed-record count, parse status, and return status. It invokes `sideeffect diff LEFT RIGHT` on the first two distinct complete measured traces. With `--runs 1`, it compares the one capture to itself and labels that fact. A size is marked `measured` only when every measured run parses completely and yields exactly the requested row count. Partial, failed, and limit-exceeded outcomes stay explicit.

The harness enforces these boundaries:

| Resource | Limit |
| --- | ---: |
| Trace file / trace subprocess file-size limit | 32 MiB |
| Inspect or diff stdout / file-size limit | 64 MiB per output |
| Parsed rows requested | 100,000 per trace |
| Parser physical record size | 64 KiB |
| Process-group wall timeout | 300 seconds per command |
| Final benchmark JSON | 1 MiB |
| Requested matrix sizes | 16 entries; each requested count at most 10,000,000 |
| Measured captures per size | 10 |
| Warm-ups per size | 3 |
| Scheduled cases | 100 total; each attempted capture+inspect pair or diff invocation counts as one |

The subprocess file-size limit also bounds captured stderr to the per-command output cap. The fixed parser/report limits match the production limits documented in `src/limits.rs`; they are not raised for benchmarking. CLI arguments are validated before creating workload files or starting commands. The hard record cap makes the million-record scenario unavailable. Status `not_attempted_limit` is a methodology result, not a performance failure.

## Results record

The following smoke result was measured during harness development. It checks execution and field collection only; it is not an estimate for larger traces.

| Environment / settings | Result |
| --- | --- |
| Run identity | 2026-10-30; workspace `HEAD` was `c933ec45a308a436bd6e4a9beea7e22c91d3e09a`; exact build provenance of the pre-existing SideEffect binary was not independently verified |
| Environment / settings | WSL2 Ubuntu, Linux x86_64; kernel `6.6.87.2-microsoft-standard-WSL2`; Python 3.14.4; `strace` 6.19; SideEffect 0.1.0; one measured capture, no warm-up, requested 100 rows; all reported hard limits above applied |
| Real capture | 4,800 trace bytes; 100 parsed rows; complete |
| Capture timing | 0.1159 s wall; child CPU 0.0172 s user + 0.0634 s system |
| Inspect | 0.0205 s wall; 33,036 JSON bytes; child CPU 0.0056 s system (0 user seconds reported) |
| Diff | 0.0199 s wall; 745 JSON bytes; child CPU 0.0055 s system (0 user seconds reported); one capture supplied twice |

### Measured scale run

This run followed the smoke check and exercised the 10,000- and 100,000-row cases. It used WSL2 Ubuntu on x86_64 with kernel `6.6.87.2-microsoft-standard-WSL2`, Python 3.14.4, `strace` 6.19, Cargo 1.93.1, and rustc 1.93.1. The SideEffect binary reported version 0.1.0. The workspace revision was `a67eef0c0f544ebdcaf5cfd7bc257c45ddd5064b`; tracked source files were clean at build time. The release binary was built from that worktree with:

```sh
cargo build --release --locked --bin sideeffect
```

The build completed with exit code 0. The resulting Linux x86_64 ELF was 8,139,448 bytes, build ID `e761abc8368b9efc1f79aac353e1680e85a6c6ed`, SHA-256 `7f7b2bf6f7b1542558e70c1fc470c4b4e4343ad1d06a6b432e0f50ac3c0cb3f1`.

The exact benchmark settings were one warm-up and three measured captures per size, with sizes `10000,100000,1000000`. The command exited 0:

```sh
python3 scripts/trace_scale_benchmark.py \
  --sideeffect target/release/sideeffect \
  --sizes 10000,100000,1000000 \
  --runs 3 --warmups 1 \
  --output /tmp/sideeffect-trace-scale-r1-20261031.json
```

The report was mode 0600 in WSL `/tmp`; traces and inspect/diff output were removed with the temporary directory. Results:

| Requested / observed rows | Trace bytes (each run) | Inspect JSON bytes (each run) | Capture wall seconds, measured runs 0 / 1 / 2 | Inspect wall seconds, measured runs 0 / 1 / 2 | Diff wall / JSON bytes | Status |
| ---: | ---: | ---: | --- | --- | --- | --- |
| 10,000 / 10,000 | 480,000 | 3,306,947 | 1.620252 / 1.670228 / 1.620090 | 0.069400 / 0.069089 / 0.068709 | 0.068947 s / 2,254,354 | complete |
| 100,000 / 100,000 | 4,800,000 | 33,266,115 | 20.984382 / 15.809563 / 15.358108 | 0.325700 / 0.324082 / 0.273743 | 0.324100 s / 22,932,688 | complete |

CPU values below are `RUSAGE_CHILDREN` deltas in seconds in measured-run order; they are aggregate child-process CPU, not isolated per-tool profiles.

| Rows | Capture user | Capture system | Inspect user | Inspect system | Diff user / system |
| ---: | --- | --- | --- | --- | --- |
| 10,000 | 0.164610 / 0.127381 / 0.111533 | 1.293877 / 1.342043 / 1.321866 | 0.009401 / 0.007842 / 0.009188 | 0.018803 / 0.019605 / 0.018377 | 0.010654 / 0.024858 |
| 100,000 | 1.475074 / 1.188920 / 0.966470 | 17.641231 / 13.036709 / 12.864390 | 0.086800 / 0.122780 / 0.100024 | 0.177733 / 0.143245 / 0.156037 | 0.142009 / 0.145954 |

Warm-up captures and inspections were complete at both sizes. The 10k warm-up used 480,000 trace bytes and 3,306,947 inspect bytes; capture wall was 1.619582 s and inspect wall was 0.068522 s. The 100k warm-up used 4,800,000 trace bytes and 33,266,115 inspect bytes; capture wall was 15.504640 s and inspect wall was 0.320974 s. Diffs compare the first two distinct measured captures. The million-row entry was `not_attempted_limit`: it exceeds the parser's 100,000-record cap. No trace-byte, report-byte, record-size, or timeout limit was reached in attempted cases.

The workspace and binary were accessed under `/mnt/c` while trace/report temporary files were under WSL `/tmp`; these results therefore include WSL and mounted-worktree effects. The `getpid`-only filter exercises record-count scaling, not broad capture integration or representative syscall behavior. The earlier 100-row smoke figures remain a separate one-run smoke check. These WSL2 figures do not characterize native Linux or Windows. Save the private JSON report from each exact run and, when publishing a results summary, record:

- date and exact source revision;
- OS/distribution, kernel, architecture, Python, `strace`, and SideEffect versions from the report;
- exact command-line settings, warm-up count, run count, and all configured limits;
- every requested size, measured parsed-row count, trace bytes, inspect wall/CPU/output, diff wall/CPU/output, and status;
- failures, partial parses, limit stops, and unattempted sizes with their reported reasons.

Do not substitute requested rows for observed parsed rows, omit failed runs, or infer timings for an unattempted size. If run under WSL, label all results WSL-only and include the WSL kernel/version details; they do not establish native Linux distribution performance or native Windows behavior. Do not commit raw captures or private reports.

## Measurement limits

- Each timed command includes process startup and file I/O. Inspect also includes parsing and JSON serialization; diff parses both inputs and serializes its output.
- `RUSAGE_CHILDREN` deltas are aggregate CPU reported for waited child processes; they do not isolate workload, tracer, and SideEffect CPU. They are not per-process profiles.
- Warm-ups reduce some first-run effects but do not remove filesystem cache, scheduler, thermal, host load, or run-order effects. Use repeated runs on a stable, otherwise idle host before comparing revisions.
- `getpid` rows exercise record-count growth with short, uniform records. They do not represent the diversity, length, continuations, malformed records, event normalization, or output expansion of real software traces.
- A successful synthetic capture proves only that this generated command produced a trace accepted by this CLI run. It does not prove complete syscall observation, broad `strace` compatibility, safe behavior, or an R1 acceptance result.
