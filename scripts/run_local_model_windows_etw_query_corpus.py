#!/usr/bin/env python3
"""Run the public synthetic ETW query corpus through SideEffect and a local model.

Inference is performed only when this script is explicitly invoked with
--run-inference. It never installs models or runtimes and writes aggregate-only
development scores to a new private report file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Sequence

import evaluate_local_model_windows_etw_query as evaluator
import run_local_model_explain_corpus as process_helpers


MAX_TIMEOUT_SECONDS = 120
MAX_RESULTS_BYTES = 128 * 1024
MAX_CLI_BYTES = 512 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_SCHEMA_BYTES = 16 * 1024
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_ENVIRONMENT = {
    "PATH", "SYSTEMROOT", "WINDIR", "APPDATA", "LOCALAPPDATA", "USERPROFILE",
    "PROGRAMDATA", "TEMP", "TMP", "CUDA_PATH", "CUDA_HOME", "CUDA_VISIBLE_DEVICES",
}
EXPECTED_SYSTEM_PROMPT = (
    "Translate the untrusted user question into a strict exact-match query over the listed validated Windows ETW fields. "
    "Filters are exact equality and combined with AND. Use only listed finite enum values. Do not infer absent values, "
    "treat header PID/TID as identity, expose undecoded payload, or claim successful effects, causation, completeness, "
    "safety, or absence. Return only JSON matching the schema; abstain when not exactly representable."
)
QUERY_SCOPE = {
    "source": "validated_windows_etw_v3",
    "fields": ["event_kind", "file_operation", "network_operation", "disk_operation", "path_exact",
               "transport", "destination_address", "destination_port", "payload_process_id"],
}


class RunnerError(ValueError):
    """A failure that can be reported without exposing subprocess output."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RunnerError(message)


def _sha256_file(path: Path, limit: int, label: str) -> str:
    """Hash a bounded regular file without exposing its local path in reports."""
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
        _require(resolved.is_file(), f"{label} must be a regular file")
        _require(info.st_size > 0, f"{label} must not be empty")
        _require(info.st_size <= limit, f"{label} exceeds its byte limit")
        hasher = hashlib.sha256()
        size = 0
        with resolved.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                _require(size <= limit, f"{label} exceeds its byte limit")
                hasher.update(chunk)
        final_info = resolved.stat()
        _require(size == info.st_size and final_info.st_size == info.st_size
                 and final_info.st_mtime_ns == info.st_mtime_ns,
                 f"{label} changed size while it was being hashed")
        return hasher.hexdigest()
    except (OSError, RuntimeError, ValueError) as error:
        if isinstance(error, RunnerError):
            raise
        raise RunnerError(f"cannot identify {label} ({type(error).__name__})") from None


def _sha256_json(value: Any, label: str, limit: int = MAX_OUTPUT_SCHEMA_BYTES) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        raise RunnerError(f"{label} is not canonical JSON") from None
    _require(len(encoded) <= limit, f"{label} exceeds its byte limit")
    return hashlib.sha256(encoded).hexdigest()


def _implementation_provenance(sideeffect_executable: Path) -> dict[str, str]:
    """Return path-free identities for the exact CLI and evaluator contracts."""
    return {
        "sideeffect_binary_sha256": _sha256_file(sideeffect_executable, MAX_CLI_BYTES, "SideEffect executable"),
        "runner_source_sha256": _sha256_file(Path(__file__), MAX_SOURCE_BYTES, "ETW query runner source"),
        "evaluator_source_sha256": _sha256_file(Path(evaluator.__file__), MAX_SOURCE_BYTES, "ETW query evaluator source"),
        "capture_contract_source_sha256": _sha256_file(
            Path(evaluator.capture_contract.__file__), MAX_SOURCE_BYTES, "ETW capture contract source"),
        "subprocess_helper_source_sha256": _sha256_file(
            Path(process_helpers.__file__), MAX_SOURCE_BYTES, "subprocess helper source"),
        "system_prompt_sha256": hashlib.sha256(EXPECTED_SYSTEM_PROMPT.encode("utf-8")).hexdigest(),
        "query_scope_sha256": _sha256_json(QUERY_SCOPE, "query scope"),
    }


def _runtime_provenance(runtime: str | None) -> dict[str, str | None]:
    if runtime is None:
        return {
            "binary_sha256": None,
            "identity_status": "unavailable_for_implicitly_configured_runtime",
        }
    return {
        "binary_sha256": _sha256_file(Path(runtime), MAX_CLI_BYTES, "explicit inference runtime"),
        "identity_status": "sha256_of_explicit_runtime_file",
    }


def _decode_output(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = evaluator.capture_contract.decode_json(raw, label)
    except (evaluator.capture_contract.ContractError, UnicodeError, ValueError):
        raise RunnerError(f"{label} was not strict JSON") from None
    _require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def _identity(preview: dict[str, Any], backend: str) -> dict[str, str]:
    model_id = preview.get("model_id")
    _require(isinstance(model_id, str) and 0 < len(model_id.encode("utf-8")) <= 128
             and model_id not in {".", ".."}
             and not any(separator in model_id for separator in ("/", "\\", ":")),
             "preview model identity is invalid")
    model_sha256 = preview.get("model_sha256")
    runtime_revision = preview.get("runtime_source_revision")
    _require(isinstance(model_sha256, str) and SHA256_PATTERN.fullmatch(model_sha256) is not None,
             "preview model digest is invalid")
    _require(isinstance(runtime_revision, str) and REVISION_PATTERN.fullmatch(runtime_revision) is not None,
             "preview runtime revision is invalid")
    _require(preview.get("backend_preference") == backend, "preview backend differs from requested backend")
    return {"model_id": model_id, "model_sha256": model_sha256,
            "runtime_source_revision": runtime_revision, "backend_preference": backend}


def _validated_backend_used(preference: str, used: Any, status: Any) -> str:
    _require(preference in {"auto", "cpu", "cuda"}, "backend preference is invalid")
    _require(isinstance(used, str) and used in {"cpu", "cuda"}
             and (preference == "auto" or used == preference),
             "analysis backend does not match the reviewed backend preference")
    expected_status = {
        ("cpu", "cpu"): "cpu_explicitly_selected",
        ("cuda", "cuda"): "cuda_requested_device_available",
        ("auto", "cpu"): "cpu_used_no_cuda_device_available",
        ("auto", "cuda"): "cuda_preferred_device_available",
    }[(preference, used)]
    _require(status == expected_status, "analysis backend status contradicts requested and effective backends")
    return used


def _effective_backend_summary(backends: list[str]) -> dict[str, Any]:
    _require(all(backend in {"cpu", "cuda"} for backend in backends),
             "effective backend list contains an unsupported value")
    unique = sorted(set(backends))
    return {
        "effective_backend_counts": {"cpu": backends.count("cpu"), "cuda": backends.count("cuda")},
        "effective_backends": unique,
        "backend_consistency": (
            "not_observed" if not unique else "single_backend" if len(unique) == 1 else "mixed_backends"
        ),
    }


def _expected_queryable_rows(capture: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for fact in evaluator._capture_facts(capture):
        ordinal = fact["record_ordinal"]
        event_kind = fact["event_kind"]
        activity_kind = {
            "file_io_observation": "file", "network_observation": "network",
            "disk_io_observation": "disk",
        }[event_kind]
        rows.append({
            "event_kind": event_kind,
            "activity_kind": activity_kind,
            "operation": fact["operation"],
            "path": fact["path"],
            "transport": fact["transport"],
            "destination_address": fact["destination_address"],
            "destination_port": fact["destination_port"],
            "payload_process_id": fact["payload_process_id"],
            "evidence_id": f"W{ordinal:05}",
            "evidence": {"capture_sha256": capture["document_sha256"], "record_ordinal": ordinal,
                         "json_pointer": f"/events/{ordinal - 1}"},
        })
    return rows


def _validate_preview(preview: dict[str, Any], case: dict[str, Any], capture: dict[str, Any],
                      capture_bytes: bytes, backend: str) -> dict[str, str]:
    _require(set(preview) == {
        "schema", "schema_version", "question", "request_sha256", "capture_sha256",
        "capture_bytes_sha256", "model_id", "model_sha256", "model_source", "model_revision",
        "license_id", "evaluation_status", "runtime_source_revision", "backend_preference",
        "system_prompt", "prompt", "output_schema", "queryable_events", "coverage",
    }, "preview has missing or unknown fields")
    _require(preview.get("schema") == "sideeffect.windows_etw_query_preview"
             and preview.get("schema_version") == 1, "preview schema is unsupported")
    _require(preview.get("question") == case["question"], "preview question differs from pinned corpus")
    for key in ("request_sha256", "capture_sha256", "capture_bytes_sha256"):
        _require(isinstance(preview.get(key), str) and SHA256_PATTERN.fullmatch(preview[key]) is not None,
                 f"preview {key} is invalid")
    _require(preview["capture_sha256"] == capture["document_sha256"], "preview references a different capture")
    _require(preview["capture_bytes_sha256"] == hashlib.sha256(capture_bytes).hexdigest(),
             "preview capture bytes differ from the pinned fixture")
    _require(preview.get("system_prompt") == EXPECTED_SYSTEM_PROMPT,
             "preview system prompt differs from the reviewed task contract")
    prompt_text = preview.get("prompt")
    _require(isinstance(prompt_text, str) and 0 < len(prompt_text.encode("utf-8")) <= 4096,
             "preview prompt is missing or oversized")
    prompt = _decode_output(prompt_text.encode("utf-8"), "Windows ETW model prompt")
    _require(set(prompt) == {"user_question", "supported_query_scope"}
             and prompt["user_question"] == case["question"]
             and prompt["supported_query_scope"] == QUERY_SCOPE,
             "model prompt contains evidence or differs from the bounded query scope")
    _require(isinstance(preview.get("output_schema"), dict), "preview output schema is missing")
    output_schema_sha256 = _sha256_json(preview["output_schema"], "preview output schema")
    _require(isinstance(preview.get("model_revision"), str) and 0 < len(preview["model_revision"]) <= 128,
             "preview model revision is invalid")
    coverage = preview.get("coverage")
    omitted = coverage.get("omitted_unvalidated_or_limited_event_count") if isinstance(coverage, dict) else None
    _require(isinstance(coverage, dict) and coverage.get("capture_completeness") == "unknown"
             and coverage.get("queryable_event_count") == len(preview.get("queryable_events", [])),
             "preview coverage is missing or inconsistent")
    _require(type(omitted) is int and omitted >= 0, "preview omitted-event count is invalid")
    _require(isinstance(coverage.get("query_status"), str)
             and coverage["query_status"] in {"bounded_source_complete", "partial_or_unknown"},
             "preview query status is invalid")
    rows = preview.get("queryable_events")
    _require(isinstance(rows, list) and rows == _expected_queryable_rows(capture),
             "preview queryable facts do not exactly match the pinned decoded fixture")
    _require((coverage["query_status"] == "partial_or_unknown") == (omitted > 0
             or capture["capture_completeness"] != "complete"), "preview query status hides capture uncertainty")
    identity = _identity(preview, backend)
    identity["output_schema_sha256"] = output_schema_sha256
    return identity


def _matched_rows(rows: list[dict[str, Any]], plan: dict[str, Any]) -> list[dict[str, Any]]:
    if plan["decision"] == "abstain":
        return []
    aliases = {"file_operation": "operation", "network_operation": "operation",
               "disk_operation": "operation", "path_exact": "path"}
    filters = plan["filters"]
    return [row for row in rows if all(value is None or row.get(aliases.get(key, key)) == value
                                       for key, value in filters.items())]


def _validate_result(result: dict[str, Any], preview: dict[str, Any], case: dict[str, Any],
                     capture: dict[str, Any], identity: dict[str, str]) -> tuple[dict[str, Any], list[int]]:
    _require(set(result) == {
        "schema", "schema_version", "request_sha256", "capture_sha256", "capture_bytes_sha256",
        "model_id", "model_sha256", "model_source", "model_revision", "license_id",
        "evaluation_status", "runtime_source_revision", "backend_preference", "backend_used",
        "backend_status", "execution_status", "plan", "matched_events", "capture_completeness",
        "collection_status", "event_loss", "diagnostics", "coverage", "result_status",
    }, "analysis result has missing or unknown fields")
    _require(result.get("schema") == "sideeffect.windows_etw_query_result"
             and result.get("schema_version") == 1, "analysis result schema is unsupported")
    for key in ("request_sha256", "capture_sha256", "capture_bytes_sha256", "model_id", "model_sha256",
                "model_source", "model_revision", "license_id", "evaluation_status", "runtime_source_revision"):
        _require(result.get(key) == preview.get(key), f"analysis {key} differs from preview")
    _require(result.get("backend_preference") == identity["backend_preference"],
             "analysis backend preference differs from preview")
    _validated_backend_used(identity["backend_preference"], result.get("backend_used"),
                            result.get("backend_status"))
    _require(result.get("evaluation_status") == preview.get("evaluation_status"),
             "analysis changed the model evaluation status")
    plan = evaluator._validate_plan(result.get("plan"), case["id"])
    expected_execution = "executed" if plan["decision"] == "filter" else "not_executed"
    _require(result.get("execution_status") == expected_execution,
             "analysis execution status contradicts its query plan")
    _require(result.get("capture_completeness") == "unknown", "analysis must preserve unknown capture completeness")
    _require(result.get("collection_status") == capture.get("collection_status")
             and result.get("event_loss") == capture.get("event_loss")
             and result.get("diagnostics") == capture.get("diagnostics")
             and result.get("coverage") == preview.get("coverage"),
             "analysis changed or omitted the capture coverage evidence")
    expected_matches = _matched_rows(preview["queryable_events"], plan)
    actual_matches = result.get("matched_events")
    _require(isinstance(actual_matches, list) and actual_matches == expected_matches,
             "analysis results differ from deterministic exact-match execution")
    ordinals = [row["evidence"]["record_ordinal"] for row in actual_matches]
    return plan, ordinals


def _percentile95(values: list[int]) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[(95 * len(ordered) + 99) // 100 - 1]


def _safe_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key.upper() in ALLOWED_ENVIRONMENT}


def run_corpus(*, sideeffect_command: Sequence[str], backend: str, runtime: str | None,
               timeout_seconds: int = 120, environment: dict[str, str] | None = None,
               invoke=process_helpers._invoke,
               implementation: dict[str, str] | None = None) -> dict[str, Any]:
    _require(backend in {"auto", "cpu", "cuda"}, "backend must be auto, cpu, or cuda")
    _require(type(timeout_seconds) is int and 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS,
             "timeout must be between 1 and 120 seconds")
    _require(bool(sideeffect_command) and all(isinstance(part, str) and part for part in sideeffect_command),
             "SideEffect command must contain non-empty string arguments")
    if environment is None:
        environment = _safe_environment()
    _require(isinstance(environment, dict) and all(
        isinstance(key, str) and key.upper() in ALLOWED_ENVIRONMENT and isinstance(value, str)
        for key, value in environment.items()), "subprocess environment contains an unapproved value")
    verify_implementation_files = implementation is None
    if implementation is None:
        _require(bool(sideeffect_command) and isinstance(sideeffect_command[0], str),
                 "SideEffect command must begin with its executable path")
        implementation = _implementation_provenance(Path(sideeffect_command[0]))
    else:
        required_implementation = {
            "sideeffect_binary_sha256", "runner_source_sha256", "evaluator_source_sha256",
            "capture_contract_source_sha256", "subprocess_helper_source_sha256",
            "system_prompt_sha256", "query_scope_sha256",
        }
        _require(set(implementation) == required_implementation
                 and all(isinstance(value, str) and SHA256_PATTERN.fullmatch(value)
                         for value in implementation.values()),
                 "implementation provenance is invalid")
    runtime_identity = _runtime_provenance(runtime)
    corpus, corpus_sha256, corpus_summary = evaluator.load_corpus()
    fixtures: dict[str, tuple[bytes, dict[str, Any]]] = {}
    for manifest in corpus["fixtures"]:
        path = evaluator.FIXTURE_DIRECTORY / manifest["path"]
        raw = evaluator._read_regular_file(path, evaluator.MAX_FIXTURE_BYTES, f"fixture {manifest['path']}")
        fixtures[manifest["path"]] = (raw, evaluator._decode(raw, f"fixture {manifest['path']}"))

    outcomes: list[dict[str, Any]] = []
    failures: dict[str, int] = {}
    latencies: list[int] = []
    effective_backends: list[str] = []
    identity: dict[str, str] | None = None
    for case in corpus["cases"]:
        raw, capture = fixtures[case["fixture"]]
        capture_path = str((evaluator.FIXTURE_DIRECTORY / case["fixture"]).resolve())
        preview_argv = [*sideeffect_command, "model-etw-query-preview", "--question", case["question"],
                        "--backend", backend, "--windows-runtime", capture_path]
        try:
            started = time.monotonic()
            code, preview_raw, failure = invoke(preview_argv, timeout_seconds=timeout_seconds,
                                                output_limit=process_helpers.MAX_COMMAND_OUTPUT_BYTES,
                                                env=environment)
            if failure is not None or code not in {0, 2}:
                raise RunnerError("preview_failed")
            preview = _decode_output(preview_raw, "Windows ETW preview")
            current_identity = _validate_preview(preview, case, capture, raw, backend)
            preview_partial = preview["coverage"]["query_status"] == "partial_or_unknown"
            if (code == 2) != preview_partial:
                raise RunnerError("preview_exit_status_mismatch")
            if identity is None:
                identity = current_identity
            elif identity != current_identity:
                raise RunnerError("model_or_runtime_changed")
            analysis_argv = [*sideeffect_command, "model-etw-query", "--question", case["question"],
                             "--backend", backend]
            if runtime is not None:
                analysis_argv.extend(["--runtime", runtime])
            analysis_argv.extend(["--confirm-sha256", preview["request_sha256"],
                                  "--windows-runtime", capture_path])
            analysis_started = time.monotonic()
            result_code, result_raw, failure = invoke(analysis_argv, timeout_seconds=timeout_seconds,
                                                      output_limit=process_helpers.MAX_COMMAND_OUTPUT_BYTES,
                                                      env=environment)
            latency = max(0, min(timeout_seconds * 1000, int((time.monotonic() - analysis_started) * 1000)))
            if failure is not None or result_code not in {0, 2}:
                raise RunnerError("analysis_failed")
            result = _decode_output(result_raw, "Windows ETW query result")
            plan, matched_ordinals = _validate_result(result, preview, case, capture, current_identity)
            _require(isinstance(result.get("result_status"), str)
                     and result["result_status"] in {"capture_completeness_unknown", "partial_or_unknown"},
                     "analysis result status overstates or omits capture uncertainty")
            event_loss = result.get("event_loss")
            _require(isinstance(event_loss, dict), "analysis event-loss status is missing")
            _require(set(event_loss) == {
                "events_lost", "log_buffers_lost", "real_time_buffers_lost", "loss_statistics_available",
                "observation", "final_snapshot_available",
            } and all(type(event_loss[key]) is int and event_loss[key] >= 0
                      for key in ("events_lost", "log_buffers_lost", "real_time_buffers_lost"))
                and type(event_loss["loss_statistics_available"]) is bool
                and type(event_loss["final_snapshot_available"]) is bool,
                "analysis event-loss status is malformed")
            partial = (result["result_status"] == "partial_or_unknown"
                       or result.get("capture_completeness") != "complete"
                       or result.get("collection_status") != "complete"
                       or bool(result.get("diagnostics"))
                       or any(event_loss.get(key, 0) > 0
                              for key in ("events_lost", "log_buffers_lost", "real_time_buffers_lost")))
            if (result_code == 2) != partial:
                raise RunnerError("result_exit_status_mismatch")
            latencies.append(latency)
            effective_backends.append(result["backend_used"])
            outcomes.append({"case_id": case["id"], "behavior": case["behavior"],
                             "plan_exact": plan == case["expected_plan"],
                             "result_exact": matched_ordinals == case["expected_record_ordinals"],
                             "abstained": plan["decision"] == "abstain",
                             "false_filter_on_abstain": case["behavior"] == "must_abstain" and plan["decision"] == "filter",
                             "latency_ms": latency})
        except (RunnerError, evaluator.ContractError, OSError, UnicodeError, ValueError, TypeError, IndexError):
            failures["invalid_or_failed_case"] = failures.get("invalid_or_failed_case", 0) + 1

    completed_answerable = [row for row in outcomes if row["behavior"] == "answerable"]
    completed_abstain = [row for row in outcomes if row["behavior"] == "must_abstain"]
    expected_answerable = corpus_summary["answerable_cases"]
    expected_abstain = corpus_summary["must_abstain_cases"]
    plan_correct = sum(row["plan_exact"] for row in outcomes)
    result_correct = sum(row["result_exact"] for row in outcomes)
    abstain_correct = sum(row["abstained"] for row in completed_abstain)
    false_filters = sum(row["false_filter_on_abstain"] for row in completed_abstain)
    outcomes_by_id = {row["case_id"]: row for row in outcomes}
    passing_groups = sum(
        all(member in outcomes_by_id and outcomes_by_id[member]["plan_exact"]
            and outcomes_by_id[member]["result_exact"] for member in group["case_ids"])
        for group in corpus["permutation_groups"]
    )
    if verify_implementation_files:
        current_implementation = _implementation_provenance(Path(sideeffect_command[0]))
        _require(current_implementation == implementation,
                 "SideEffect executable or evaluation source changed during inference")
    if runtime is not None:
        _require(_runtime_provenance(runtime) == runtime_identity,
                 "explicit inference runtime changed during inference")
    report = {
        "schema": "sideeffect.local_model_windows_etw_query_development_results",
        "schema_version": 2,
        "qualification_result": "not_assessed",
        "semantic_quality_assessed": False,
        "independent_label_review": "not_verified",
        "hidden_holdout": False,
        "inference_performed": True,
        "corpus_sha256": corpus_sha256,
        "label_review_status": corpus["label_review_status"],
        "implementation": implementation,
        "runtime_binary": runtime_identity,
        "requested_backend": backend,
        "run": identity,
        "counts": {"cases": len(corpus["cases"]), "completed": len(outcomes),
                   "failed": len(corpus["cases"]) - len(outcomes)},
        "metrics": {
            "exact_plan_cases": plan_correct,
            "exact_result_cases": result_correct,
            "answerable_plan_accuracy": {"correct": sum(row["plan_exact"] for row in completed_answerable),
                                         "total": expected_answerable},
            "answerable_result_accuracy": {"correct": sum(row["result_exact"] for row in completed_answerable),
                                           "total": expected_answerable},
            "must_abstain_accuracy": {"correct": abstain_correct, "total": expected_abstain},
            "false_filters_on_must_abstain": false_filters,
            **_effective_backend_summary(effective_backends),
            "p95_latency_ms": _percentile95(latencies),
            "p95_latency_scope": "successful_analysis_cases_only",
            "permutation_groups": {"passed": passing_groups, "total": len(corpus["permutation_groups"])},
        },
        "failure_counts": failures,
        "development_corpus_counts": corpus_summary,
    }
    encoded = json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    _require(len(encoded) <= MAX_RESULTS_BYTES, "aggregate report exceeds its byte limit")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sideeffect", required=True, type=Path, help="already-built SideEffect CLI")
    parser.add_argument("--runtime", help="optional existing local inference runtime")
    parser.add_argument("--backend", choices=("auto", "cpu", "cuda"), default="auto")
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--output", required=True, type=Path, help="new private report file; existing files are not replaced")
    parser.add_argument("--run-inference", action="store_true", help="explicitly run the selected local model for every case")
    args = parser.parse_args()
    if not args.run_inference:
        parser.error("full scoring performs local inference; pass --run-inference explicitly")
    try:
        executable = str(args.sideeffect.resolve(strict=True))
        if not Path(executable).is_file():
            raise RunnerError("SideEffect path is not a regular file")
        runtime = str(Path(args.runtime).resolve(strict=False)) if args.runtime else None
        environment = _safe_environment()
        report = run_corpus(sideeffect_command=[executable], backend=args.backend,
                            runtime=runtime, timeout_seconds=args.timeout_seconds,
                            environment=environment)
        encoded = json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        _require(len(encoded) <= MAX_RESULTS_BYTES, "aggregate report exceeds its byte limit")
        process_helpers._write_new_private_file(args.output, encoded)
        print("Wrote aggregate-only Windows ETW development scores; model qualification remains unassessed.")
        return 0 if report["counts"]["failed"] == 0 else 2
    except (RunnerError, evaluator.ContractError, OSError, UnicodeError, ValueError) as error:
        print(f"Windows ETW query corpus run failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
