#!/usr/bin/env python3
"""Measure bounded SideEffect inspect/diff scaling on generated Linux traces.

The default matrix uses real strace captures of a deterministic, local Python
workload. It never accepts a workload command or trace path from the caller.
"""

import argparse
import json
import os
import platform
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


MAX_TRACE_BYTES = 32 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_SECONDS = 300
MAX_FINAL_REPORT_BYTES = 1024 * 1024
MAX_MATRIX_SIZES = 16
MAX_RUNS = 10
MAX_WARMUPS = 3
MAX_SCHEDULED_CASES = 100
MAX_REQUESTED_SIZE = 10_000_000
DEFAULT_SIZES = (10_000, 100_000, 1_000_000)

WORKLOADS = {
    "getpid": """import os, sys
count = int(sys.argv[1])
for _ in range(count):
    os.getpid()
""",
    "file_io": """import os, sys
count = int(sys.argv[1])
root = sys.argv[2]
source = os.path.join(root, "source.bin")
destination = os.path.join(root, "destination.bin")
with open(source, "wb") as stream:
    stream.write(b"S")
source_fd = os.open(source, os.O_RDONLY)
destination_fd = os.open(destination, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
try:
    for _ in range(count):
        if os.sendfile(destination_fd, source_fd, 0, 1) != 1:
            raise RuntimeError("short sendfile operation")
finally:
    os.close(destination_fd)
    os.close(source_fd)
if os.path.getsize(destination) != count:
    raise RuntimeError("destination size did not match the requested transfer count")
""",
}
TRACE_FILTERS = {"getpid": "getpid", "file_io": "sendfile"}
WORKLOAD_DESCRIPTIONS = {
    "getpid": "calls os.getpid() exactly N times; no user inputs or network",
    "file_io": "transfers one byte per os.sendfile() call from a generated private source file to a generated private destination file",
}


def _limit_file_size(limit):
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


def _child_cpu():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime, usage.ru_stime


def _run(command, stdout_path, stdout_limit, stderr_path, timeout=MAX_SECONDS):
    before_cpu = _child_cpu()
    start = time.perf_counter_ns()
    with stdout_path.open("wb") as stdout_stream, stderr_path.open("wb") as stderr_stream:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=stdout_stream,
            stderr=stderr_stream,
            start_new_session=True,
            preexec_fn=lambda: _limit_file_size(stdout_limit),
        )
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise RuntimeError("process group exceeded the %d-second timeout" % timeout)
    elapsed = (time.perf_counter_ns() - start) / 1_000_000_000
    after_cpu = _child_cpu()
    out_size = stdout_path.stat().st_size
    err_size = stderr_path.stat().st_size
    if out_size > stdout_limit:
        raise RuntimeError("stdout exceeded the %d-byte output limit" % stdout_limit)
    return {
        "return_code": return_code,
        "wall_seconds": elapsed,
        "child_cpu_seconds": {
            "user": max(0.0, after_cpu[0] - before_cpu[0]),
            "system": max(0.0, after_cpu[1] - before_cpu[1]),
        },
        "stdout_bytes": out_size,
        "stderr_bytes": err_size,
        "stderr_tail": _read_tail(stderr_path),
    }


def _read_tail(path, limit=2000):
    with path.open("rb") as stream:
        stream.seek(max(0, path.stat().st_size - limit))
        return stream.read(limit).decode("utf-8", "replace")


def _version(command):
    result = subprocess.run(command, check=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=10)
    return result.stdout.strip().splitlines()[0]


def _write_exclusive(path, payload):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sanitize_temporary_paths(value, temporary_root):
    if isinstance(value, dict):
        return {key: _sanitize_temporary_paths(item, temporary_root)
                for key, item in value.items() if not key.startswith("_")}
    if isinstance(value, list):
        return [_sanitize_temporary_paths(item, temporary_root) for item in value]
    if isinstance(value, str):
        return value.replace(temporary_root, "[temporary]")
    return value


def _trace_case(root, sideeffect, python, size, repetitions, warmups, profile):
    result = {
        "requested_records": size,
        "status": "failed",
        "warmup_runs": [],
        "runs": [],
        "diff": {"status": "not_run"},
    }
    script = root / ("workload-%d.py" % size)
    descriptor = os.open(script, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(WORKLOADS[profile])
    workload_arguments = [python, str(script), str(size)]
    if profile == "file_io":
        workload_root = root / ("file-io-%d" % size)
        workload_root.mkdir(mode=0o700)
        workload_arguments.append(str(workload_root))

    total_runs = warmups + repetitions
    for index in range(total_runs):
        is_warmup = index < warmups
        label = "warmup-%d" % index if is_warmup else "run-%d" % (index - warmups)
        trace = root / ("%s-%d.strace" % (label, size))
        inspect = root / ("%s-%d.inspect.json" % (label, size))
        stderr = root / ("%s-%d.stderr" % (label, size))
        trace_stdout = root / ("%s-%d.stdout" % (label, size))
        record = {"label": label}
        try:
            traced = _run(
                ["strace", "-f", "-qq", "-e", "trace=" + TRACE_FILTERS[profile],
                 "-o", str(trace), "--"] + workload_arguments,
                trace_stdout, MAX_TRACE_BYTES, stderr,
            )
            trace_bytes = trace.stat().st_size if trace.exists() else 0
            record["capture"] = {**traced, "trace_bytes": trace_bytes}
            if traced["return_code"] != 0:
                limited = trace_bytes >= MAX_TRACE_BYTES
                record["capture"]["status"] = "limit_exceeded" if limited else "failed"
                record["capture"]["reason"] = ("trace reached its file-size cap" if limited else
                                                  "strace/workload exit status was nonzero")
                (result["warmup_runs"] if is_warmup else result["runs"]).append(record)
                continue
            if trace_bytes > MAX_TRACE_BYTES:
                record["capture"]["status"] = "limit_exceeded"
                (result["warmup_runs"] if is_warmup else result["runs"]).append(record)
                continue
            record["capture"]["status"] = "complete"
            record["trace_status"] = "complete"
            inspected = _run([str(sideeffect), "inspect", str(trace)], inspect,
                             MAX_REPORT_BYTES, stderr)
            inspection = None
            if inspect.exists() and inspect.stat().st_size <= MAX_REPORT_BYTES:
                try:
                    with inspect.open("rb") as stream:
                        inspection = json.load(stream)
                except (ValueError, OSError):
                    pass
            count = len(inspection.get("records", [])) if isinstance(inspection, dict) else None
            parse_status = inspection.get("parse_status") if isinstance(inspection, dict) else None
            inspect_status = ("complete" if inspected["return_code"] == 0 and parse_status == "complete"
                              else "partial" if inspection is not None and parse_status != "complete"
                              else "limit_exceeded" if inspect.stat().st_size >= MAX_REPORT_BYTES
                              else "failed")
            record["inspect"] = {
                **{key: inspected[key] for key in ("return_code", "wall_seconds", "child_cpu_seconds", "stdout_bytes", "stderr_bytes")},
                "status": inspect_status,
                "parsed_records": count,
                "parse_status": parse_status,
                "json_bytes": inspect.stat().st_size if inspect.exists() else 0,
                "diagnostic_tail": inspected["stderr_tail"],
            }
            record["_trace_path"] = str(trace)
            (result["warmup_runs"] if is_warmup else result["runs"]).append(record)
        except (OSError, subprocess.SubprocessError, RuntimeError) as error:
            record["error"] = str(error)
            (result["warmup_runs"] if is_warmup else result["runs"]).append(record)

    measured = result["runs"]
    complete = [item for item in measured if item.get("inspect", {}).get("status") == "complete"]
    if complete and len(complete) == len(measured) and all(
        item["inspect"]["parsed_records"] == size for item in measured
    ):
        result["status"] = "measured"
    elif any(item.get("inspect", {}).get("status") == "partial" for item in measured):
        result["status"] = "partial"
    elif any(item.get("capture", {}).get("status") == "limit_exceeded" for item in measured):
        result["status"] = "limit_exceeded"
    elif any(item.get("inspect", {}).get("status") == "limit_exceeded" for item in measured):
        result["status"] = "limit_exceeded"

    diff_left = complete[0] if complete else None
    diff_right = complete[1] if len(complete) > 1 else diff_left
    if diff_left:
        diff_path = root / ("diff-%d.json" % size)
        diff_stderr = root / ("diff-%d.stderr" % size)
        try:
            diff = _run([str(sideeffect), "diff", diff_left["_trace_path"], diff_right["_trace_path"]],
                        diff_path, MAX_REPORT_BYTES, diff_stderr)
            result["diff"] = {
                "status": ("complete" if diff["return_code"] == 0 else
                           "limit_exceeded" if diff["stdout_bytes"] >= MAX_REPORT_BYTES else "failed"),
                "wall_seconds": diff["wall_seconds"],
                "child_cpu_seconds": diff["child_cpu_seconds"],
                "json_bytes": diff["stdout_bytes"],
                "return_code": diff["return_code"],
                "diagnostic_tail": diff["stderr_tail"],
                "inputs": "two distinct measured captures" if diff_right is not diff_left else "same capture supplied twice",
            }
        except (OSError, subprocess.SubprocessError, RuntimeError) as error:
            result["diff"] = {"status": "failed", "error": str(error)}
    return result


def main():
    if not sys.platform.startswith("linux"):
        raise SystemExit("This benchmark supports Linux only.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sideeffect", required=True, help="path to a built SideEffect executable")
    parser.add_argument("--output", required=True, help="new private JSON report path")
    parser.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)),
                        help="comma-separated positive requested record counts (default: 10000,100000,1000000)")
    parser.add_argument("--profile", choices=tuple(WORKLOADS), default="getpid",
                        help="generated workload profile (default: getpid)")
    parser.add_argument("--runs", type=int, default=3, help="measured captures per size (default: 3)")
    parser.add_argument("--warmups", type=int, default=1, help="discarded captures per size (default: 1)")
    args = parser.parse_args()
    if len(args.sizes) > 256:
        raise SystemExit("--sizes exceeds the %d-character argument limit" % 256)
    try:
        sizes = tuple(int(value) for value in args.sizes.split(","))
    except ValueError:
        raise SystemExit("--sizes must be comma-separated positive integers")
    if not sizes or any(size <= 0 for size in sizes) or len(set(sizes)) != len(sizes):
        raise SystemExit("--sizes must contain unique positive integers")
    if len(sizes) > MAX_MATRIX_SIZES:
        raise SystemExit("--sizes exceeds the %d-entry matrix limit" % MAX_MATRIX_SIZES)
    if any(size > MAX_REQUESTED_SIZE for size in sizes):
        raise SystemExit("each requested size must be at most %d" % MAX_REQUESTED_SIZE)
    if args.runs < 1 or args.warmups < 0:
        raise SystemExit("--runs must be positive and --warmups must not be negative")
    if args.runs > MAX_RUNS:
        raise SystemExit("--runs must not exceed %d" % MAX_RUNS)
    if args.warmups > MAX_WARMUPS:
        raise SystemExit("--warmups must not exceed %d" % MAX_WARMUPS)
    attempted_sizes = sum(1 for size in sizes if size <= MAX_RECORDS)
    scheduled_cases = attempted_sizes * (args.runs + args.warmups + 1)
    if scheduled_cases > MAX_SCHEDULED_CASES:
        raise SystemExit("requested matrix schedules %d cases; maximum is %d" %
                         (scheduled_cases, MAX_SCHEDULED_CASES))
    sideeffect = Path(args.sideeffect).resolve(strict=True)
    output = Path(args.output).absolute()
    if not sideeffect.is_file():
        raise SystemExit("--sideeffect must name a regular file")
    if shutil.which("strace") is None:
        raise SystemExit("required command not found: strace")
    python = shutil.which("python3")
    if python is None:
        raise SystemExit("required command not found: python3")

    versions = {
        "python": _version([python, "--version"]),
        "strace": _version(["strace", "--version"]),
        "sideeffect": _version([str(sideeffect), "--version"]),
    }
    matrix = []
    try:
        with tempfile.TemporaryDirectory(prefix="sideeffect-trace-scale-") as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            for size in sizes:
                if size > MAX_RECORDS:
                    matrix.append({
                        "requested_records": size,
                        "status": "not_attempted_limit",
                        "reason": "requested count exceeds SideEffect's %d-record parser cap" % MAX_RECORDS,
                        "runs": [],
                        "diff": {"status": "not_run"},
                    })
                    continue
                matrix.append(_trace_case(root, sideeffect, python, size, args.runs,
                                          args.warmups, args.profile))
            report = {
                "kind": "sideeffect_linux_trace_scale_benchmark",
                "host": {
                    "hostname": platform.node(),
                    "system": platform.system(),
                    "release": platform.release(),
                    "machine": platform.machine(),
                    **versions,
                },
                "method": {
                    "profile": args.profile,
                    "capture": "real strace, -f -qq -e trace=%s, around generated fixed Python workload" % TRACE_FILTERS[args.profile],
                    "workload": WORKLOAD_DESCRIPTIONS[args.profile],
                    "warmups_per_size": args.warmups,
                    "measured_runs_per_size": args.runs,
                    "cpu_measurement": "harness getrusage(RUSAGE_CHILDREN) deltas around each waited child process group",
                    "diff": "compares the first two measured complete captures; with one measured run, uses that same capture twice",
                },
                "limits": {
                    "trace_bytes": MAX_TRACE_BYTES,
                    "report_bytes_per_cli_stdout": MAX_REPORT_BYTES,
                    "final_report_bytes": MAX_FINAL_REPORT_BYTES,
                    "parser_records": MAX_RECORDS,
                    "parser_record_bytes": 64 * 1024,
                    "timeout_seconds_per_process_group": MAX_SECONDS,
                    "matrix_sizes": MAX_MATRIX_SIZES,
                    "measured_runs_per_size": MAX_RUNS,
                    "warmups_per_size": MAX_WARMUPS,
                    "scheduled_cases": MAX_SCHEDULED_CASES,
                },
                "matrix": matrix,
                "caveats": [
                    "Parsed-record targets are checked against the actual inspect JSON count; mismatches are not reported as measured target runs.",
                    "Child CPU aggregates what the harness receives through RUSAGE_CHILDREN and does not isolate Python workload, strace, or SideEffect CPU.",
                    "Wall time includes process startup, file I/O, parsing, and JSON serialization as applicable.",
                    "The selected synthetic workload profile does not represent arbitrary software or establish capture completeness.",
                    "Temporary generated source, captures, inspect JSON, diff JSON, and diagnostics are removed on exit, including errors.",
                    "The report includes host identity and should be treated as private.",
                ],
            }
            report = _sanitize_temporary_paths(report, str(root))
            payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
            if len(payload) > MAX_FINAL_REPORT_BYTES:
                raise RuntimeError("final benchmark report exceeds the %d-byte limit" %
                                   MAX_FINAL_REPORT_BYTES)
            _write_exclusive(output, payload)
    except FileExistsError:
        raise SystemExit("refusing to overwrite existing output: " + str(output))
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as error:
        raise SystemExit(str(error))
    print(json.dumps(report, indent=2, sort_keys=True))
    print("Private report written: %s (mode 0600)" % output)


if __name__ == "__main__":
    main()
