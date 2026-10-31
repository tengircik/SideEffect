#!/usr/bin/env python3
"""Run a small, local workload with and without real strace and inspect the trace."""

import argparse
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    import resource
except ImportError:  # The platform check gives Windows a clean, intentional error.
    resource = None


MAX_TRACE_BYTES = 16 * 1024 * 1024
MAX_INSPECT_BYTES = 64 * 1024 * 1024
FILE_COUNT = 24
FILE_BYTES = 4096
HASH_ROUNDS = 48

WORKLOAD = r'''import hashlib, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
source = root / "source"
output = root / "output"
source.mkdir(mode=0o700)
output.mkdir(mode=0o700)
for index in range(24):
    payload = bytes(((index * 17 + offset) % 256 for offset in range(4096)))
    (source / ("item-%02d.bin" % index)).write_bytes(payload)
for path in sorted(source.iterdir()):
    data = path.read_bytes()
    digest = hashlib.sha256()
    for _ in range(48):
        digest.update(data)
    (output / (path.stem + ".sha256")).write_text(digest.hexdigest() + "\n", encoding="ascii")
assert len(list(output.iterdir())) == 24
'''


def version(command):
    result = subprocess.run(command, check=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=10)
    return result.stdout.strip().splitlines()[0]


def cpu_usage():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime, usage.ru_stime


def run_measured(command, **kwargs):
    before_cpu = cpu_usage()
    start = time.perf_counter_ns()
    child = subprocess.Popen(command, start_new_session=True, **kwargs)
    try:
        stdout, stderr = child.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGTERM)
        try:
            stdout, stderr = child.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            stdout, stderr = child.communicate()
        raise RuntimeError("command exceeded the 60-second process-group timeout")
    elapsed = time.perf_counter_ns() - start
    after_cpu = cpu_usage()
    result = subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
    return result, elapsed / 1_000_000_000, {
        "user_seconds": max(0.0, after_cpu[0] - before_cpu[0]),
        "system_seconds": max(0.0, after_cpu[1] - before_cpu[1]),
    }


def count_trace_lines(path):
    count = 0
    last = b""
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            count += chunk.count(b"\n")
            last = chunk[-1:]
    size = path.stat().st_size
    if size and last != b"\n":
        count += 1
    return count


def run_workload(python, workload, directory, trace_path=None):
    command = [python, str(workload), str(directory)]
    process_options = {}
    if trace_path is not None:
        command = ["strace", "-f", "-qq", "-e", "trace=%file,%process",
                   "-o", str(trace_path), "--"] + command
        process_options["preexec_fn"] = limit_file_size
    result, wall, cpu = run_measured(command, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, text=True,
                                     **process_options)
    if result.returncode != 0:
        raise RuntimeError("workload command failed (exit %d): %s" %
                           (result.returncode, result.stderr[-2000:]))
    return {"wall_seconds": wall, "child_cpu_seconds": cpu}


def limit_file_size():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_TRACE_BYTES, MAX_TRACE_BYTES))


def write_private_exclusive(path, payload):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def main():
    if not sys.platform.startswith("linux"):
        raise SystemExit("This benchmark supports Linux only.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sideeffect", required=True,
                        help="path to a previously built SideEffect executable")
    parser.add_argument("--output", required=True,
                        help="new JSON report path (created exclusively with mode 0600)")
    args = parser.parse_args()

    sideeffect = Path(args.sideeffect).resolve(strict=True)
    output = Path(args.output).absolute()
    if not sideeffect.is_file():
        raise SystemExit("--sideeffect must name a regular file")
    for dependency in ("strace", "python3", "rustc"):
        if shutil.which(dependency) is None:
            raise SystemExit("required command not found: " + dependency)

    tracer_version = version(["strace", "--version"])
    rust_version = version(["rustc", "--version"])
    sideeffect_version = version([str(sideeffect), "--version"])
    python_version = version(["python3", "--version"])

    try:
        with tempfile.TemporaryDirectory(prefix="sideeffect-trace-benchmark-") as temp:
            root = Path(temp)
            os.chmod(root, 0o700)
            workload = root / "workload.py"
            fd = os.open(workload, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(WORKLOAD)
            untraced_dir = root / "untraced"
            traced_dir = root / "traced"
            untraced_dir.mkdir(mode=0o700)
            traced_dir.mkdir(mode=0o700)

            untraced = run_workload("python3", workload, untraced_dir)
            trace_path = root / "capture.strace"
            traced = run_workload("python3", workload, traced_dir, trace_path)
            trace_bytes = trace_path.stat().st_size
            if trace_bytes > MAX_TRACE_BYTES:
                raise RuntimeError("trace exceeded the %d-byte benchmark limit" % MAX_TRACE_BYTES)
            trace_records = count_trace_lines(trace_path)

            inspect_path = root / "inspect.json"
            with inspect_path.open("xb") as inspect_output:
                result, inspect_wall, inspect_cpu = run_measured(
                    [str(sideeffect), "inspect", str(trace_path)],
                    stdout=inspect_output, stderr=subprocess.PIPE)
                inspect_output.flush()
            if result.returncode != 0:
                raise RuntimeError("sideeffect inspect failed (exit %d): %s" %
                                   (result.returncode, result.stderr.decode("utf-8", "replace")[-2000:]))
            inspect_bytes = inspect_path.stat().st_size
            if inspect_bytes > MAX_INSPECT_BYTES:
                raise RuntimeError("inspect JSON exceeded the %d-byte benchmark limit" % MAX_INSPECT_BYTES)
            with inspect_path.open("rb") as stream:
                document = json.load(stream)
            parsed_records = len(document.get("records", []))

            report = {
                "kind": "local_real_strace_benchmark",
                "method": "single fixed workload run untraced, once under strace, then SideEffect inspect",
                "host": {
                    "hostname": platform.node(),
                    "system": platform.system(),
                    "release": platform.release(),
                    "machine": platform.machine(),
                    "python": python_version,
                    "rustc": rust_version,
                    "sideeffect": sideeffect_version,
                    "strace": tracer_version,
                },
                "workload": {
                    "description": "Python creates and reads 24 deterministic 4096-byte local files, hashes each 48 times, and writes 24 digest files; no network or external input.",
                    "file_count": FILE_COUNT,
                    "bytes_per_input_file": FILE_BYTES,
                    "hash_rounds_per_file": HASH_ROUNDS,
                },
                "measurements": {
                    "untraced": untraced,
                    "traced": traced,
                    "strace_over_untraced_wall_ratio": (traced["wall_seconds"] / untraced["wall_seconds"] if untraced["wall_seconds"] else None),
                    "trace_bytes": trace_bytes,
                    "trace_line_records": trace_records,
                    "inspect_wall_seconds": inspect_wall,
                    "inspect_child_cpu_seconds": inspect_cpu,
                    "inspect_json_bytes": inspect_bytes,
                    "parsed_records": parsed_records,
                    "parse_status": document.get("parse_status", "unknown"),
                },
                "limits": {
                    "max_trace_bytes": MAX_TRACE_BYTES,
                    "max_inspect_json_bytes": MAX_INSPECT_BYTES,
                    "wall_timeout_seconds_per_command": 60,
                    "trace_filter": "%file,%process",
                    "trace_file_retained": False,
                    "capture_window": "one command execution; no explicit duration option",
                },
                "notes": [
                    "Real local strace capture; the capture was parsed by the supplied SideEffect executable.",
                    "One run per condition; this is a harness smoke benchmark, not a statistically stable estimate.",
                    "Child CPU is the user/system CPU reported to this harness for waited child processes; it does not isolate workload CPU from tracer CPU.",
                    "Trace line count and parsed record count have different meanings and may differ.",
                    "Temporary workload data, trace, and inspect JSON are removed on exit. The report includes host identity and should be treated as private.",
                ],
            }
            payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
            write_private_exclusive(output, payload)
    except FileExistsError:
        raise SystemExit("refusing to overwrite existing output: " + str(output))
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(str(error))

    print(json.dumps(report, indent=2, sort_keys=True))
    print("Private report written: %s (mode 0600)" % output)


if __name__ == "__main__":
    main()
