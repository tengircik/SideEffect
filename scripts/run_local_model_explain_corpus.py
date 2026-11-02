#!/usr/bin/env python3
"""Run the pinned synthetic explanation corpus through SideEffect's real CLI.

This creates selector-results v2 or v3 diagnostics only. It does not install a
model/runtime, change the corpus or prompt, or judge semantic correctness.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Sequence

import evaluate_local_model_explain as evaluator


MAX_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_RESULTS_BYTES = evaluator.MAX_RESULTS_BYTES
MAX_TIMEOUT_SECONDS = 120
EVIDENCE_ID_PATTERN = evaluator.EVIDENCE_ID_PATTERN
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class RunnerError(ValueError):
    """A failure that can be safely reported without subprocess contents."""


def _strict_object(raw: bytes, label: str) -> dict[str, Any]:
    value = evaluator._decode_json(raw, label)
    evaluator._require(isinstance(value, dict), f"{label} must be an object")
    return value


def _process_group_kwargs() -> dict[str, Any]:
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    """Stop the CLI process group so its runtime child is not left behind."""
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
            killer = subprocess.Popen(
                [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            try:
                killer.wait(timeout=3)
            except subprocess.TimeoutExpired:
                killer.kill()
                killer.wait(timeout=1)
            if process.poll() is None:
                process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _invoke(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    output_limit: int = MAX_COMMAND_OUTPUT_BYTES,
) -> tuple[int | None, bytes, str | None]:
    """Run one argv vector with bounded captured output and no shell."""
    if not argv or not all(isinstance(part, str) and part for part in argv):
        return None, b"", "launch_error"
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            cwd=evaluator.ROOT,
            **_process_group_kwargs(),
        )
    except (OSError, ValueError):
        return None, b"", "launch_error"

    stdout_data = bytearray()
    total_bytes = 0
    count_lock = threading.Lock()
    output_exceeded = threading.Event()

    def drain(stream: Any, *, retain: bool) -> None:
        nonlocal total_bytes
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    return
                with count_lock:
                    total_bytes += len(chunk)
                    if total_bytes > output_limit:
                        output_exceeded.set()
                    elif retain:
                        stdout_data.extend(chunk)
        except (OSError, ValueError):
            return

    readers = [
        threading.Thread(target=drain, args=(process.stdout,), kwargs={"retain": True}, daemon=True),
        threading.Thread(target=drain, args=(process.stderr,), kwargs={"retain": False}, daemon=True),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout_seconds
    failure: str | None = None
    while process.poll() is None:
        if output_exceeded.is_set():
            failure = "output_limit"
            _stop_process(process)
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            failure = "timeout"
            _stop_process(process)
            break
        time.sleep(min(0.01, remaining))
    if process.poll() is None:
        _stop_process(process)
    for reader in readers:
        reader.join(timeout=1)
    for pipe in (process.stdout, process.stderr):
        try:
            pipe.close()
        except OSError:
            pass
    if output_exceeded.is_set():
        failure = "output_limit"
    if failure is not None:
        return process.returncode, b"", failure
    return process.returncode, bytes(stdout_data), None


def _parse_command_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        return _strict_object(raw, label)
    except (evaluator.ContractError, UnicodeError, ValueError):
        raise RunnerError("invalid_json") from None


def _preview_evidence(preview: dict[str, Any], question: str) -> tuple[str, list[dict[str, Any]], dict[str, dict[str, Any]]]:
    evaluator._require(preview.get("schema") == "sideeffect.local_model_explanation_preview", "unsupported preview schema")
    evaluator._require(preview.get("schema_version") == 3, "unsupported preview version")
    evaluator._require(preview.get("question") == question, "preview question does not match corpus")
    request_digest = preview.get("request_sha256")
    evaluator._require(isinstance(request_digest, str) and SHA256_PATTERN.fullmatch(request_digest), "invalid preview digest")
    summary = preview.get("evidence_summary")
    evaluator._require(isinstance(summary, dict), "preview evidence summary is missing")
    parse_status = summary.get("parse_status")
    evaluator._require(parse_status in {"complete", "partial"}, "invalid preview parse status")
    prompt_text = preview.get("prompt")
    evaluator._require(isinstance(prompt_text, str) and len(prompt_text.encode("utf-8")) <= 128 * 1024, "invalid or oversized preview prompt")
    prompt = _strict_object(prompt_text.encode("utf-8"), "preview prompt")
    allowed: dict[str, dict[str, Any]] = {}
    selectable: list[dict[str, Any]] = []

    syscall_rows = prompt.get("observed_syscall_results")
    relation_rows = prompt.get("process_relations")
    evaluator._require(isinstance(syscall_rows, list) and isinstance(relation_rows, list), "preview evidence sections are missing")
    for row in syscall_rows:
        evaluator._require(isinstance(row, dict), "invalid syscall evidence row")
        evidence_id = row.get("evidence_id")
        evaluator._require(isinstance(evidence_id, str) and EVIDENCE_ID_PATTERN.fullmatch(evidence_id), "invalid syscall evidence ID")
        evaluator._require(evidence_id not in allowed, "duplicate preview evidence ID")
        allowed[evidence_id] = row
        selectable.append({"evidence_id": evidence_id, "semantic_labels": []})
    for relation in relation_rows:
        evaluator._require(isinstance(relation, dict) and isinstance(relation.get("evidence"), dict), "invalid process relation evidence")
        evidence = relation["evidence"]
        evidence_id = evidence.get("evidence_id")
        evaluator._require(isinstance(evidence_id, str) and EVIDENCE_ID_PATTERN.fullmatch(evidence_id), "invalid relation evidence ID")
        evaluator._require(evidence_id not in allowed, "duplicate preview evidence ID")
        allowed[evidence_id] = evidence
        selectable.append({"evidence_id": evidence_id, "semantic_labels": []})

    evaluator._require(len(selectable) <= 64, "preview evidence exceeds the result bound")
    return parse_status, selectable, allowed


def _run_identity(preview: dict[str, Any], backend: str) -> dict[str, str]:
    model_id = preview.get("model_id")
    model_sha256 = preview.get("model_sha256")
    runtime_revision = preview.get("runtime_source_revision")
    evaluator._bounded_string(model_id, "preview model_id", evaluator.MAX_RUN_MODEL_ID_BYTES)
    evaluator._require(
        model_id not in {".", ".."} and not any(separator in model_id for separator in ("/", "\\", ":")),
        "preview model_id must not contain a filesystem path",
    )
    evaluator._require(isinstance(model_sha256, str) and SHA256_PATTERN.fullmatch(model_sha256), "invalid preview model digest")
    evaluator._require(isinstance(runtime_revision, str) and REVISION_PATTERN.fullmatch(runtime_revision), "invalid preview runtime revision")
    evaluator._require(preview.get("backend_preference") == backend, "preview backend does not match requested backend")
    return {
        "model_id": model_id,
        "model_sha256": model_sha256,
        "runtime_source_revision": runtime_revision,
        "backend_preference": backend,
    }


def _analysis_response(
    analysis: dict[str, Any],
    preview: dict[str, Any],
    allowed: dict[str, dict[str, Any]],
    source_parse_status: str,
) -> tuple[dict[str, Any], str]:
    evaluator._require(analysis.get("schema") == "sideeffect.local_model_explanation", "unsupported analysis schema")
    evaluator._require(analysis.get("schema_version") == 3, "unsupported analysis version")
    request_digest = preview["request_sha256"]
    evaluator._require(analysis.get("request_sha256") == request_digest, "analysis digest does not match preview")
    evaluator._require(analysis.get("model_id") == preview["model_id"], "analysis model does not match preview")
    interpretation = analysis.get("interpretation")
    evaluator._require(isinstance(interpretation, dict), "analysis interpretation is missing")
    selection_status = interpretation.get("selection_status")
    evaluator._require(selection_status in evaluator.SELECTION_STATUS_VALUES, "invalid selection status")
    evidence_ids = interpretation.get("evidence_ids")
    evaluator._require(isinstance(evidence_ids, list) and len(evidence_ids) <= evaluator.MAX_SELECTED_EVIDENCE_IDS, "invalid or oversized evidence ID array")
    evaluator._require(all(isinstance(item, str) and EVIDENCE_ID_PATTERN.fullmatch(item) for item in evidence_ids), "invalid selected evidence ID")
    evaluator._require(len(evidence_ids) == len(set(evidence_ids)), "duplicate selected evidence ID")
    evaluator._require(all(item in allowed for item in evidence_ids), "analysis selected evidence outside preview")
    selected_facts = interpretation.get("selected_facts")
    evaluator._require(isinstance(selected_facts, list), "analysis selected facts are missing")
    evaluator._require(selected_facts == [allowed[item] for item in evidence_ids], "analysis selected facts do not map to exact preview rows")
    expected_status = (
        "abstained" if not evidence_ids
        else "selected" if source_parse_status == "complete"
        else "partial_selection"
    )
    evaluator._require(selection_status == expected_status, "selection status disagrees with evidence and parse status")
    backend_used = analysis.get("backend_used")
    evaluator._require(backend_used in {"not_run", "cpu", "cuda"}, "invalid used backend")
    evaluator._require(
        preview["backend_preference"] == "auto" or backend_used == "not_run" or preview["backend_preference"] == backend_used,
        "used backend does not match backend preference",
    )
    evaluator._require(backend_used != "not_run" or selection_status == "abstained", "not_run backend requires an abstention")
    response = {
        "selection_status": selection_status,
        "evidence_ids": evidence_ids,
    }
    return response, backend_used


def _error_message(phase: str, failure: str, *, preview_completed: bool = False) -> str:
    prefix = "analysis" if phase == "analysis" else "preview"
    if failure == "timeout":
        detail = "timed out"
    elif failure == "output_limit":
        detail = "exceeded the subprocess output limit"
    elif failure == "launch_error":
        detail = "could not be started"
    elif failure == "capture_error":
        detail = "output capture failed"
    elif failure == "invalid_json":
        detail = "returned invalid JSON"
    elif failure == "contract_error":
        detail = "returned output that did not match the expected contract"
    elif failure == "exit_status":
        detail = "exited with an unexpected status"
    else:
        detail = "failed"
    suffix = " after preview completed" if phase == "analysis" and preview_completed else ""
    return f"{prefix} {detail}{suffix}; subprocess output was discarded"


def run_corpus(
    *,
    sideeffect_command: Sequence[str],
    backend: str,
    runtime: str | None,
    timeout_seconds: int,
    results_version: int = 3,
    invoke=_invoke,
) -> dict[str, Any]:
    """Run every pinned synthetic case, recording one row or safe error per case."""
    evaluator._require(backend in {"auto", "cpu", "cuda"}, "backend must be auto, cpu, or cuda")
    evaluator._require(type(timeout_seconds) is int and 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS, "timeout must be between 1 and 120 seconds")
    evaluator._require(results_version in {2, 3}, "results version must be 2 or 3")
    corpus, corpus_digest = evaluator.load_corpus()
    results: dict[str, Any] = {
        "schema": "sideeffect.local_model_explain_development_results",
        "schema_version": results_version,
        "corpus_sha256": corpus_digest,
        "run": {},
        "cases": [],
    }
    errors: list[dict[str, str]] = []
    run_identity: dict[str, str] | None = None

    for case in corpus["cases"]:
        fixture = evaluator.FIXTURE_DIRECTORY / case["fixture"]
        trace_path = str(fixture.resolve())
        case_started = time.monotonic()
        preview_argv = [
            *sideeffect_command,
            "model-explain-preview",
            "--question", case["question"],
            "--backend", backend,
            trace_path,
        ]
        preview_code, preview_raw, failure = invoke(
            preview_argv, timeout_seconds=timeout_seconds, output_limit=MAX_COMMAND_OUTPUT_BYTES
        )
        if failure is not None:
            if run_identity is None:
                raise RunnerError("the first preview failed; no verified run identity is available")
            errors.append({"case_id": case["id"], "phase": "preview", "error": _error_message("preview", failure)})
            continue
        if preview_code not in {0, 2}:
            if run_identity is None:
                raise RunnerError("the first preview failed; no verified run identity is available")
            errors.append({"case_id": case["id"], "phase": "preview", "error": _error_message("preview", "exit_status")})
            continue

        try:
            preview = _parse_command_json(preview_raw, "SideEffect preview")
            source_parse_status, available_evidence, allowed = _preview_evidence(preview, case["question"])
            current_identity = _run_identity(preview, backend)
        except (RunnerError, evaluator.ContractError, UnicodeError, ValueError):
            if run_identity is None:
                raise RunnerError("the first preview failed contract validation; no verified run identity is available") from None
            errors.append({"case_id": case["id"], "phase": "preview", "error": _error_message("preview", "contract_error")})
            continue

        if run_identity is None:
            run_identity = current_identity
            results["run"] = run_identity
        elif current_identity != run_identity:
            errors.append({"case_id": case["id"], "phase": "preview", "error": _error_message("preview", "contract_error")})
            continue

        elapsed = time.monotonic() - case_started
        remaining = timeout_seconds - elapsed
        if remaining <= 0:
            errors.append({"case_id": case["id"], "phase": "analysis", "error": _error_message("analysis", "timeout", preview_completed=True)})
            continue

        analysis_argv = [*sideeffect_command, "model-explain"]
        if runtime is not None:
            analysis_argv.extend(["--runtime", runtime])
        analysis_argv.extend([
            "--question", case["question"],
            "--backend", backend,
            "--confirm-sha256", preview["request_sha256"],
            trace_path,
        ])
        analysis_started = time.monotonic()
        analysis_code, analysis_raw, failure = invoke(
            analysis_argv, timeout_seconds=remaining, output_limit=MAX_COMMAND_OUTPUT_BYTES
        )
        latency_ms = max(0, min(timeout_seconds * 1000, int((time.monotonic() - analysis_started) * 1000)))
        if failure is not None:
            errors.append({"case_id": case["id"], "phase": "analysis", "error": _error_message("analysis", failure, preview_completed=True)})
            continue
        if analysis_code not in {0, 2}:
            errors.append({"case_id": case["id"], "phase": "analysis", "error": _error_message("analysis", "exit_status", preview_completed=True)})
            continue

        try:
            analysis = _parse_command_json(analysis_raw, "SideEffect analysis")
            response, backend_used = _analysis_response(analysis, preview, allowed, source_parse_status)
            if (analysis_code == 0) != (response["selection_status"] == "selected"):
                raise RunnerError("exit/selection status mismatch")
        except (RunnerError, evaluator.ContractError, UnicodeError, ValueError):
            errors.append({"case_id": case["id"], "phase": "analysis", "error": _error_message("analysis", "contract_error", preview_completed=True)})
            continue

        row: dict[str, Any] = {
            "case_id": case["id"],
            "response": response,
            "source_parse_status": source_parse_status,
            "backend_used": backend_used,
            "available_evidence": available_evidence,
            "latency_ms": latency_ms,
        }
        if results_version == 3:
            row["preview_request_sha256"] = preview["request_sha256"]
            row["human_reviews"] = []
            row["review_target_sha256"] = evaluator._review_target_sha256(row, case["question"], corpus_digest)
        results["cases"].append(row)

    if run_identity is None:
        raise RunnerError("no preview completed; no output can be recorded in the evaluator schema")
    if errors:
        results["errors"] = errors

    encoded = json.dumps(results, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    evaluator._require(len(encoded) <= MAX_RESULTS_BYTES, "results exceed the evaluator byte limit")
    if results_version == 2:
        evaluator._validate_results_v2(results, corpus, corpus_digest)
    else:
        evaluator._validate_results_v3(results, corpus, corpus_digest)
    return results


def _write_new_private_file(path: Path, data: bytes) -> None:
    if os.name == "nt":
        _write_new_private_windows_file(path, data)
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _write_new_private_windows_file(path: Path, data: bytes) -> None:
    """Create the destination with a protected DACL granting only this user."""
    if os.name != "nt":
        raise OSError("Windows private-file creation is only available on Windows")

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", ctypes.c_void_p), ("attributes", ctypes.c_uint32)]

    class TokenUser(ctypes.Structure):
        _fields_ = [("user", SidAndAttributes)]

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", ctypes.c_uint32),
            ("security_descriptor", ctypes.c_void_p),
            ("inherit_handle", ctypes.c_int),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.OpenProcessToken.restype = ctypes.c_int
    advapi32.GetTokenInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)
    ]
    advapi32.GetTokenInformation.restype = ctypes.c_int
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    advapi32.ConvertSidToStringSidW.restype = ctypes.c_int
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(SecurityAttributes),
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.WriteFile.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p
    ]
    kernel32.WriteFile.restype = ctypes.c_int
    kernel32.FlushFileBuffers.argtypes = [ctypes.c_void_p]
    kernel32.FlushFileBuffers.restype = ctypes.c_int
    kernel32.DeleteFileW.argtypes = [ctypes.c_wchar_p]
    kernel32.DeleteFileW.restype = ctypes.c_int

    token = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    sid_string = ctypes.c_wchar_p()
    file_handle = ctypes.c_void_p()
    created = False
    try:
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        needed = ctypes.c_uint32()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if needed.value == 0 or needed.value > 64 * 1024:
            raise OSError("could not determine current-user SID buffer size")
        token_buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, 1, token_buffer, needed, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        user = ctypes.cast(token_buffer, ctypes.POINTER(TokenUser)).contents
        if not advapi32.ConvertSidToStringSidW(user.user.sid, ctypes.byref(sid_string)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = sid_string.value
        if not sid or len(sid) > 256:
            raise OSError("current-user SID is empty or oversized")
        sddl = f"D:P(A;;FA;;;{sid})"
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, 0)
        file_handle = ctypes.c_void_p(kernel32.CreateFileW(
            str(path),
            0x40000000,  # GENERIC_WRITE
            0,  # no sharing while writing
            ctypes.byref(attributes),
            1,  # CREATE_NEW; existing files and reparse points are never opened
            0x80 | 0x00200000,  # FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
            None,
        ))
        invalid_handle = ctypes.c_void_p(-1).value
        if file_handle.value in (None, invalid_handle):
            raise ctypes.WinError(ctypes.get_last_error())
        created = True
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + 1024 * 1024]
            buffer = ctypes.create_string_buffer(chunk)
            written = ctypes.c_uint32()
            if not kernel32.WriteFile(file_handle, buffer, len(chunk), ctypes.byref(written), None):
                raise ctypes.WinError(ctypes.get_last_error())
            if written.value == 0:
                raise OSError("Windows private results write made no progress")
            offset += written.value
        if not kernel32.FlushFileBuffers(file_handle):
            raise ctypes.WinError(ctypes.get_last_error())
    except BaseException:
        if created:
            if file_handle.value not in (None, ctypes.c_void_p(-1).value):
                kernel32.CloseHandle(file_handle)
                file_handle = ctypes.c_void_p()
            kernel32.DeleteFileW(str(path))
        raise
    finally:
        if file_handle.value not in (None, ctypes.c_void_p(-1).value):
            kernel32.CloseHandle(file_handle)
        if descriptor.value:
            kernel32.LocalFree(descriptor)
        if sid_string.value:
            kernel32.LocalFree(ctypes.cast(sid_string, ctypes.c_void_p))
        if token.value:
            kernel32.CloseHandle(token)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sideeffect", required=True, help="path to the already-built SideEffect CLI")
    parser.add_argument("--runtime", help="optional explicit runtime path; otherwise use the configured explanation runtime")
    parser.add_argument("--backend", choices=("auto", "cpu", "cuda"), default="auto")
    parser.add_argument("--timeout-seconds", type=int, default=60, help="maximum preview plus analysis time per case (1..120)")
    parser.add_argument("--results-version", type=int, choices=(2, 3), default=3, help="write evaluator schema v3 (default) or v2")
    parser.add_argument("--output", required=True, type=Path, help="new private results file; existing files are never replaced")
    args = parser.parse_args()
    try:
        sideeffect_path = str(Path(args.sideeffect).resolve(strict=True))
        if not Path(sideeffect_path).is_file():
            raise RunnerError("SideEffect path is not a regular file")
        runtime_path = str(Path(args.runtime).resolve(strict=False)) if args.runtime is not None else None
        results = run_corpus(
            sideeffect_command=[sideeffect_path],
            backend=args.backend,
            runtime=runtime_path,
            timeout_seconds=args.timeout_seconds,
            results_version=args.results_version,
        )
        encoded = json.dumps(results, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        _write_new_private_file(args.output, encoded)
        print(f"Wrote selector results v{args.results_version} for {len(results['cases'])} completed and {len(results.get('errors', []))} failed cases.")
        return 0 if not results.get("errors") else 2
    except (RunnerError, evaluator.ContractError, OSError, UnicodeError, ValueError) as error:
        print(f"local explanation corpus run failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
