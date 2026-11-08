#!/usr/bin/env python3
"""Bounded local NVIDIA GPU-memory sampling for an actual SideEffect command.

This records sampled NVIDIA-SMI counters; it is not a VRAM limit or an
unsampled peak guarantee. The command is launched directly with shell=False.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

MAX_DURATION_SECONDS = 600
MIN_INTERVAL_MS = 250
MAX_INTERVAL_MS = 10_000
MAX_SAMPLES = 600
MAX_TOOL_OUTPUT = 64 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_GPUS = 8
MAX_PROCESS_SNAPSHOT_ENTRIES = 8_192
MAX_COMPUTE_PROCESSES = 256
MAX_MATCHED_PROCESSES_PER_SAMPLE = 4

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def process_snapshot() -> dict[int, tuple[int, str]]:
    """Take one bounded Tool Help snapshot: PID -> (parent PID, image basename)."""
    if os.name != "nt":
        raise RuntimeError("This harness supports native Windows only.")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    rows: dict[int, tuple[int, str]] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            if len(rows) >= MAX_PROCESS_SNAPSHOT_ENTRIES:
                raise RuntimeError("Process snapshot exceeded the 8,192-process bound.")
            rows[int(entry.th32ProcessID)] = (int(entry.th32ParentProcessID), str(entry.szExeFile))
            more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        error = ctypes.get_last_error()
        if error not in (0, 18):  # ERROR_NO_MORE_FILES
            raise ctypes.WinError(error)
    finally:
        kernel32.CloseHandle(snapshot)
    return rows


def descendants(root_pid: int, parents: dict[int, tuple[int, str]]) -> set[int]:
    found = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, (ppid, _name) in parents.items():
            if ppid in found and pid not in found:
                found.add(pid)
                changed = True
    return found


def identity_chain(root_pid: int, pid: int, parents: dict[int, tuple[int, str]]) -> list[int] | None:
    """Return sampled parent links from a driver-reported PID to the CLI PID."""
    chain = [pid]
    seen = {pid}
    while chain[-1] != root_pid:
        row = parents.get(chain[-1])
        if row is None:
            return None
        parent = row[0]
        if parent in seen:
            return None
        chain.append(parent)
        seen.add(parent)
        if len(chain) > 64:
            return None
    return chain


def run_nvidia_smi(smi: str, args: list[str]) -> tuple[int, str, str]:
    try:
        proc = subprocess.Popen([smi, *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False)
    except OSError as exc:
        return 1, "", f"nvidia-smi query failed ({type(exc).__name__})"
    output = bytearray()
    overflow = threading.Event()

    def drain_stdout() -> None:
        assert proc.stdout is not None
        while True:
            block = proc.stdout.read(4096)
            if not block:
                return
            if len(output) + len(block) > MAX_TOOL_OUTPUT:
                overflow.set()
                try:
                    proc.kill()
                except OSError:
                    pass
                return
            output.extend(block)

    reader = threading.Thread(target=drain_stdout, name="nvidia-smi-output-reader", daemon=True)
    reader.start()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=1)
        return 1, "", "nvidia-smi query exceeded its five-second timeout"
    reader.join(timeout=1)
    if reader.is_alive():
        if proc.stdout:
            proc.stdout.close()
        return 1, "", "nvidia-smi output reader did not finish within its bound"
    if overflow.is_set():
        return 1, "", "nvidia-smi output exceeded the 64 KiB bound"
    return proc.returncode, output.decode("utf-8", errors="replace"), "nvidia-smi exited with a nonzero status" if proc.returncode else ""


def parse_gpu_rows(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        fields = [part.strip() for part in line.split(",")]
        if len(fields) != 3 or fields[1].lower() in {"[n/a]", "n/a"}:
            raise ValueError("GPU query returned an unsupported or malformed row")
        try:
            rows.append({"gpu_index": int(fields[0]), "memory_used_mib": int(fields[1]), "reported_at": fields[2]})
        except ValueError as exc:
            raise ValueError("GPU query returned a malformed row") from exc
        if len(rows) > MAX_GPUS:
            raise ValueError("GPU query exceeded the 8-device bound")
    return rows


def parse_compute_rows(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        fields = [part.strip() for part in line.split(",")]
        if len(fields) != 3:
            raise ValueError("Compute-process query returned an unsupported or malformed row")
        try:
            pid = int(fields[0])
        except ValueError as exc:
            raise ValueError("Compute-process query returned a malformed row") from exc
        if pid < 0 or not fields[2] or fields[2].lower() in {"[n/a]", "n/a"}:
            raise ValueError("Compute-process query returned an unsupported or malformed identity")
        if fields[1].lower() in {"[n/a]", "n/a"}:
            rows.append({
                "pid": pid,
                "memory_used_mib": None,
                "memory_status": "unsupported_driver_reported_n_a",
                "gpu_uuid": fields[2],
            })
        else:
            try:
                memory_used_mib = int(fields[1])
            except ValueError as exc:
                raise ValueError("Compute-process query returned a malformed memory value") from exc
            if memory_used_mib < 0:
                raise ValueError("Compute-process query returned a negative memory value")
            rows.append({
                "pid": pid,
                "memory_used_mib": memory_used_mib,
                "memory_status": "sampled",
                "gpu_uuid": fields[2],
            })
        if len(rows) > MAX_COMPUTE_PROCESSES:
            raise ValueError("Compute-process query exceeded the 256-process bound")
    return rows


def process_memory_status(
    runtime_peaks: dict[tuple[str, int], int],
    matched_n_a_count: int,
    global_peaks: dict[int, int],
) -> tuple[str, str]:
    """Classify process-memory evidence without converting missing values to zero."""
    if runtime_peaks:
        return (
            "matched_driver_pid_to_sideeffect_process_tree",
            "sampled_with_unsupported_rows" if matched_n_a_count else "sampled",
        )
    if matched_n_a_count:
        return "runtime_pid_matched_memory_unsupported", "unsupported_driver_reported_n_a"
    if global_peaks:
        return "global_only_process_isolated_peak_unknown", "unknown_no_runtime_pid_memory"
    return "unknown", "unknown_no_usable_gpu_sample"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def write_report_no_overwrite(path: Path, report: dict[str, Any]) -> None:
    payload = (json.dumps(report, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(payload) > MAX_OUTPUT_BYTES:
        raise RuntimeError("Report exceeds the 2 MiB output bound")
    # Exclusive creation prevents replacing an existing file or following a final symlink.
    with path.open("xb") as stream:
        stream.write(payload)


def collect(command: list[str], duration: int, interval_ms: int, runtime_process_name: str, output: Path) -> int:
    if os.name != "nt":
        raise RuntimeError("This harness supports native Windows only.")
    smi = shutil.which("nvidia-smi")
    start_utc = utc_now()
    report: dict[str, Any] = {
        "schema": "sideeffect.windows_local_model_gpu_memory_sample",
        "schema_version": 1,
        "measurement": "sampled NVIDIA-SMI memory counters; not a hard limit or unsampled peak",
        "started_at_utc": start_utc,
        "requested_duration_seconds": duration,
        "sample_interval_ms": interval_ms,
        "runtime_process_name_filter": runtime_process_name,
        "command_arguments_recorded": False,
        "upload": "none",
        "sampling_status": "unknown",
        "process_measurement_status": "unknown",
        "per_process_memory_status": "unknown",
        "global_gpu_peaks": [],
        "matched_runtime_process_peaks": [],
        "samples": [],
        "diagnostics": [],
    }
    if not smi:
        report["diagnostics"].append("nvidia-smi was not found on PATH; GPU memory is unknown")
        write_report_no_overwrite(output, report)
        return 2

    child = subprocess.Popen(command, shell=False)
    report["sideeffect_pid"] = child.pid
    deadline = time.monotonic() + duration
    global_peaks: dict[int, int] = {}
    runtime_peaks: dict[tuple[str, int], int] = {}
    matched_n_a_count = 0
    sample_count = 0
    while time.monotonic() < deadline and sample_count < MAX_SAMPLES:
        sample_started = time.monotonic()
        diagnostic: list[str] = []
        parents: dict[int, tuple[int, str]] = {}
        try:
            parents = process_snapshot()
            pids = descendants(child.pid, parents)
        except (OSError, RuntimeError) as exc:
            pids = set()
            diagnostic.append(f"process identity snapshot unavailable: {type(exc).__name__}")

        rc, gpu_text, err = run_nvidia_smi(smi, ["--query-gpu=index,memory.used,timestamp", "--format=csv,noheader,nounits"])
        gpu_rows: list[dict[str, Any]] = []
        if rc == 0:
            try:
                gpu_rows = parse_gpu_rows(gpu_text)
                for row in gpu_rows:
                    index = row["gpu_index"]
                    global_peaks[index] = max(global_peaks.get(index, 0), row["memory_used_mib"])
            except ValueError as exc:
                diagnostic.append(str(exc))
        else:
            diagnostic.append(err or "global GPU memory query failed")

        rc_proc, proc_text, err_proc = run_nvidia_smi(smi, ["--query-compute-apps=pid,used_memory,gpu_uuid", "--format=csv,noheader,nounits"])
        matched = []
        if rc_proc == 0:
            try:
                for row in parse_compute_rows(proc_text):
                    process_info = parents.get(row["pid"])
                    if row["pid"] in pids and process_info and process_info[1].casefold() == runtime_process_name.casefold():
                        if len(matched) >= MAX_MATCHED_PROCESSES_PER_SAMPLE:
                            diagnostic.append("More than 4 SideEffect-related GPU processes matched in one sample; additional rows are omitted")
                            break
                        matched.append({**row, "parent_pid_chain_to_sideeffect": identity_chain(child.pid, row["pid"], parents)})
                        if row["memory_used_mib"] is None:
                            matched_n_a_count += 1
                        else:
                            key = (row["gpu_uuid"], row["pid"])
                            runtime_peaks[key] = max(runtime_peaks.get(key, 0), row["memory_used_mib"])
            except ValueError as exc:
                diagnostic.append(str(exc))
        else:
            diagnostic.append(err_proc or "per-process GPU memory query unavailable")

        report["samples"].append({
            "sample": sample_count,
            "sampled_at_utc": utc_now(),
            "global_gpu_memory": gpu_rows,
            "matched_sideeffect_processes": matched,
            "diagnostics": diagnostic,
        })
        report["diagnostics"].extend(diagnostic[:2])
        sample_count += 1
        if child.poll() is not None:
            break
        remaining = deadline - time.monotonic()
        delay = min(interval_ms / 1000, max(0, remaining - (time.monotonic() - sample_started)))
        if delay > 0:
            time.sleep(delay)

    command_status = child.poll()
    report["finished_at_utc"] = utc_now()
    report["sample_count"] = sample_count
    report["command_exit_code"] = command_status
    report["sampling_status"] = "sampled" if global_peaks else "unknown"
    report["global_gpu_peaks"] = [
        {"gpu_index": gpu, "sampled_peak_memory_used_mib": peak}
        for gpu, peak in sorted(global_peaks.items())
    ]
    report["matched_runtime_process_peaks"] = [
        {"gpu_uuid": gpu_uuid, "pid": pid, "sampled_peak_memory_used_mib": peak}
        for (gpu_uuid, pid), peak in sorted(runtime_peaks.items())
    ]
    report["process_measurement_status"], report["per_process_memory_status"] = process_memory_status(
        runtime_peaks, matched_n_a_count, global_peaks
    )
    if report["per_process_memory_status"] == "unknown_no_runtime_pid_memory":
        report["diagnostics"].append("No NVIDIA-SMI process PID matched the observed SideEffect process tree; process-isolated GPU memory is unknown, not zero.")
    elif report["per_process_memory_status"] == "unsupported_driver_reported_n_a":
        report["diagnostics"].append("NVIDIA-SMI matched the runtime PID but reported its per-process memory as N/A; process-isolated GPU memory is unsupported and unknown, not zero.")
    elif report["per_process_memory_status"] == "sampled_with_unsupported_rows":
        report["diagnostics"].append("Some matched runtime rows reported per-process memory as N/A; only numeric rows contribute to the sampled peak.")
    elif report["process_measurement_status"] == "unknown":
        report["diagnostics"].append("No usable GPU memory sample was observed; memory use is unknown, not zero.")
    if sample_count >= MAX_SAMPLES and command_status is None:
        report["command_status"] = "still_running_when_sample_limit_reached"
        report["diagnostics"].append("The 600-sample bound ended collection while the command was still running; the harness did not terminate it.")
    elif command_status is None:
        report["command_status"] = "still_running_when_sampling_window_ended"
        report["diagnostics"].append("The bounded sampling window ended while the command was still running; the harness did not terminate it.")
    else:
        report["command_status"] = "exited"
    report["diagnostics"] = list(dict.fromkeys(report["diagnostics"]))[:256]
    write_report_no_overwrite(output, report)
    return 0 if command_status is not None else 2


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-seconds", type=int, default=120, help="sampling window, 1..600 seconds (default: 120)")
    parser.add_argument("--interval-ms", type=int, default=500, help="sample interval, 250..10000 ms (default: 500)")
    parser.add_argument("--runtime-process-name", required=True, help="runtime executable basename, such as llama-completion.exe; used only to confirm process identity")
    parser.add_argument("--output", required=True, type=Path, help="new local JSON report path; existing files are never replaced")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="SideEffect CLI command, separated by --")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.duration_seconds <= MAX_DURATION_SECONDS:
        parser.error("--duration-seconds must be between 1 and 600")
    if not MIN_INTERVAL_MS <= args.interval_ms <= MAX_INTERVAL_MS:
        parser.error("--interval-ms must be between 250 and 10000")
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or not command[0]:
        parser.error("provide the SideEffect command after --")
    if Path(command[0]).name.lower() not in {"sideeffect", "sideeffect.exe"}:
        parser.error("the command must be the SideEffect CLI executable")
    if not args.output.is_absolute() or str(args.output).startswith("\\\\"):
        parser.error("--output must be an absolute local path")
    if args.output.exists():
        parser.error("--output already exists; choose a new path")
    try:
        return collect(command, args.duration_seconds, args.interval_ms, args.runtime_process_name, args.output)
    except (OSError, RuntimeError) as exc:
        print(f"measurement failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
