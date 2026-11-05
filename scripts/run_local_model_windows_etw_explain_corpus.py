#!/usr/bin/env python3
"""Run the synthetic Windows ETW explanation corpus through SideEffect's CLI.

This produces selector diagnostics for development only. It does not install a
model/runtime, assign semantic labels, or qualify model quality.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Sequence

import evaluate_local_model_windows_etw_explain as evaluator
import run_local_model_explain_corpus as process_helpers


MAX_TIMEOUT_SECONDS = 120
MAX_COMMAND_OUTPUT_BYTES = process_helpers.MAX_COMMAND_OUTPUT_BYTES
MAX_PROMPT_BYTES = 128 * 1024
MAX_EVIDENCE_ROWS = 16
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class RunnerError(ValueError):
    """A safely reportable preview or selector contract failure."""


def _strict_object(raw: bytes, label: str) -> dict[str, Any]:
    value = evaluator.decode_json(raw, label)
    evaluator._require(isinstance(value, dict), f"{label} must be an object")
    return value


def _parse_cli_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        return _strict_object(raw, label)
    except (evaluator.ContractError, UnicodeError, ValueError):
        raise RunnerError("CLI output did not match strict JSON") from None


def _run_identity(preview: dict[str, Any], backend: str) -> dict[str, str]:
    model_id = evaluator._bounded_string(preview.get("model_id"), "preview model_id", 128)
    evaluator._require(
        model_id not in {".", ".."} and not any(separator in model_id for separator in ("/", "\\", ":")),
        "preview model_id must not contain a filesystem path",
    )
    model_sha = preview.get("model_sha256")
    runtime_revision = preview.get("runtime_source_revision")
    evaluator._require(isinstance(model_sha, str) and SHA256_PATTERN.fullmatch(model_sha) is not None,
                       "invalid preview model digest")
    evaluator._require(isinstance(runtime_revision, str) and REVISION_PATTERN.fullmatch(runtime_revision) is not None,
                       "invalid preview runtime revision")
    evaluator._require(preview.get("backend_preference") == backend, "preview backend does not match runner backend")
    return {
        "model_id": model_id,
        "model_sha256": model_sha,
        "runtime_source_revision": runtime_revision,
        "backend_preference": backend,
    }


def _preview_evidence(
    preview: dict[str, Any],
    question: str,
    capture: dict[str, Any],
) -> tuple[str, list[dict[str, Any]], dict[str, dict[str, Any]]]:
    evaluator._require(preview.get("schema") == "sideeffect.local_model_windows_runtime_explanation_preview",
                       "preview is not the Windows ETW explanation schema")
    evaluator._require(preview.get("schema_version") == 1, "unsupported Windows ETW preview version")
    evaluator._require(preview.get("question") == question, "preview question does not match the corpus")
    request_digest = preview.get("request_sha256")
    evaluator._require(isinstance(request_digest, str) and SHA256_PATTERN.fullmatch(request_digest) is not None,
                       "invalid Windows ETW request digest")
    summary = preview.get("evidence_summary")
    evaluator._require(isinstance(summary, dict), "Windows ETW evidence summary is missing")
    parse_status = summary.get("parse_status")
    evaluator._require(isinstance(parse_status, str) and parse_status in evaluator.PARSE_STATUSES,
                       "invalid Windows ETW parse status")
    evaluator._require(summary.get("capture_completeness") == "unknown", "ETW completeness must remain unknown")
    evaluator._require(summary.get("capture_sha256") == capture["document_sha256"],
                       "preview capture digest does not match the pinned fixture")
    prompt_text = preview.get("prompt")
    evaluator._require(isinstance(prompt_text, str) and len(prompt_text.encode("utf-8")) <= MAX_PROMPT_BYTES,
                       "missing or oversized ETW prompt")
    prompt = _strict_object(prompt_text.encode("utf-8"), "Windows ETW prompt")
    evaluator._require(set(prompt) == {"user_question", "source", "coverage", "observed_windows_etw_events"},
                       "Windows ETW prompt has missing or unknown fields")
    evaluator._require(prompt["user_question"] == question, "prompt question does not match the corpus")
    evaluator._require(prompt["source"] == "windows_etw_capture_v3", "prompt source is not native Windows ETW")
    evaluator._require(prompt["coverage"] == summary, "prompt coverage differs from its preview summary")
    rows = prompt["observed_windows_etw_events"]
    events = capture["events"]
    evaluator._require(isinstance(rows, list) and len(rows) == len(events) <= MAX_EVIDENCE_ROWS,
                       "preview must retain every bounded fixture event")
    allowed: dict[str, dict[str, Any]] = {}
    available: list[dict[str, Any]] = []
    for index, (row, event) in enumerate(zip(rows, events)):
        evaluator._require(isinstance(row, dict), "ETW preview evidence row must be an object")
        evidence_id = row.get("evidence_id")
        expected_id = f"W{index + 1:05d}"
        evaluator._require(evidence_id == expected_id and evaluator.WINDOWS_EVIDENCE_ID_PATTERN.fullmatch(evidence_id),
                           "ETW preview evidence ID does not match its source ordinal")
        evaluator._require(evidence_id not in allowed, "duplicate ETW preview evidence ID")
        evidence = row.get("evidence")
        evaluator._require(isinstance(evidence, dict), "ETW evidence link is missing")
        evaluator._require(evidence.get("capture_sha256") == capture["document_sha256"],
                           "ETW evidence link references another capture")
        evaluator._require(evidence.get("record_ordinal") == index + 1
                           and evidence.get("json_pointer") == f"/events/{index}",
                           "ETW evidence ordinal or pointer does not match the pinned fixture")
        raw_payload = bytes.fromhex(event["raw_payload_hex"])
        evaluator._require(evidence.get("raw_payload_sha256") == hashlib.sha256(raw_payload).hexdigest(),
                           "ETW evidence raw-payload digest does not match the pinned event")
        reported_identity = row.get("capture_reported_event_identity")
        evaluator._require(isinstance(reported_identity, dict)
                           and reported_identity.get("event_kind") == event["event_kind"],
                           "ETW preview changed the capture-reported event identity")
        decode_status = row.get("payload_decode_status")
        expected_observation = evaluator._supported_tcp_send_observation(event)
        if expected_observation is not None:
            evaluator._require(decode_status == "decoded_and_sidecar_matched"
                               and row.get("payload_observation") == expected_observation["observation"],
                               "supported ETW payload did not reproduce its exact sidecar observation")
            evaluator._require(row.get("payload_observation") is not None
                               and reported_identity.get("verification_status") ==
                               "event_kind_corroborated_by_raw_payload_decoder_and_sidecar",
                               "ETW decoded event lacks matching raw-payload corroboration")
        elif event["payload_decoding"] is not None:
            evaluator._require(decode_status == "process_payload_requires_live_tdh_schema"
                               and row.get("payload_observation") is None,
                               "imported process payload must remain unknown without live TDH schema")
            evaluator._require(reported_identity.get("verification_status") == "capture_reported_unverified",
                               "unknown process payload must not corroborate capture metadata")
        elif decode_status == "unsupported_or_malformed_raw_payload":
            evaluator._require(row.get("payload_observation") is None
                               and reported_identity.get("verification_status") == "capture_reported_unverified",
                               "unsupported ETW payload must remain unknown and unverified")
        else:
            raise evaluator.ContractError("ETW preview contains an unknown or mismatched payload status")
        allowed[evidence_id] = row
        available.append({"evidence_id": evidence_id, "semantic_labels": []})
    return parse_status, available, allowed


def _analysis_response(
    analysis: dict[str, Any],
    preview: dict[str, Any],
    allowed: dict[str, dict[str, Any]],
    parse_status: str,
) -> tuple[dict[str, Any], str]:
    evaluator._require(analysis.get("schema") == "sideeffect.local_model_windows_runtime_explanation"
                       and analysis.get("schema_version") == 1,
                       "analysis is not the Windows ETW explanation schema")
    evaluator._require(analysis.get("request_sha256") == preview["request_sha256"],
                       "analysis digest does not match the exact preview")
    evaluator._require(analysis.get("model_id") == preview["model_id"], "analysis model differs from preview")
    interpretation = analysis.get("interpretation")
    evaluator._require(isinstance(interpretation, dict), "ETW analysis interpretation is missing")
    status = interpretation.get("selection_status")
    evaluator._require(isinstance(status, str) and status in evaluator.SELECTION_STATUSES,
                       "invalid ETW selection status")
    ids = interpretation.get("evidence_ids")
    evaluator._require(isinstance(ids, list) and len(ids) <= evaluator.MAX_SELECTED_IDS,
                       "invalid or oversized ETW selected ID array")
    evaluator._require(all(isinstance(item, str) and evaluator.WINDOWS_EVIDENCE_ID_PATTERN.fullmatch(item) for item in ids),
                       "analysis selected a non-Windows evidence ID")
    evaluator._require(len(ids) == len(set(ids)), "analysis selected duplicate ETW evidence IDs")
    evaluator._require(all(item in allowed for item in ids), "analysis selected evidence outside the exact preview")
    selected_facts = interpretation.get("selected_facts")
    evaluator._require(isinstance(selected_facts, list)
                       and selected_facts == [allowed[item] for item in ids],
                       "selected ETW facts do not exactly match preview rows")
    expected_status = "abstained" if not ids else ("selected" if parse_status == "complete" else "partial_selection")
    evaluator._require(status == expected_status, "ETW selection status conflicts with evidence or parse status")
    abstain_reason = interpretation.get("abstain_reason")
    evaluator._require(abstain_reason is None or (isinstance(abstain_reason, str) and abstain_reason in {
        "ambiguous", "unsupported_scope", "insufficient_evidence",
    }), "invalid ETW abstain reason")
    backend_used = analysis.get("backend_used")
    evaluator._require(backend_used in evaluator.BACKENDS, "invalid ETW backend used")
    requested_backend = preview["backend_preference"]
    evaluator._require(requested_backend == "auto" or backend_used == "not_run" or requested_backend == backend_used,
                       "ETW used backend conflicts with preview preference")
    evaluator._require(backend_used != "not_run" or status == "abstained", "not_run backend requires an abstention")
    return {"selection_status": status, "evidence_ids": ids, "abstain_reason": abstain_reason}, backend_used


def _load_manifest_capture(fixture: dict[str, Any]) -> dict[str, Any]:
    """Reload fixture bytes only if they still match the just-validated manifest."""
    name = fixture["path"]
    raw = evaluator.read_regular_file(evaluator.FIXTURE_DIRECTORY / name,
                                      evaluator.MAX_FIXTURE_BYTES, f"fixture {name}")
    evaluator._require(len(raw) == fixture["size_bytes"], f"fixture byte length changed after manifest validation: {name}")
    evaluator._require(hashlib.sha256(raw).hexdigest() == fixture["sha256"],
                       f"fixture SHA-256 changed after manifest validation: {name}")
    capture = evaluator.decode_json(raw, f"fixture {name}")
    evaluator.validate_capture_document(capture)
    return capture


def run_corpus(
    *,
    sideeffect_command: Sequence[str],
    backend: str,
    runtime: str | None,
    timeout_seconds: int,
    invoke=process_helpers._invoke,
) -> dict[str, Any]:
    evaluator._require(backend in {"auto", "cpu", "cuda"}, "backend must be auto, cpu, or cuda")
    evaluator._require(type(timeout_seconds) is int and 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS,
                       "timeout must be between 1 and 120 seconds")
    corpus, corpus_digest = evaluator.load_corpus()
    captures = {row["path"]: _load_manifest_capture(row) for row in corpus["fixtures"]}
    results: dict[str, Any] = {
        "schema": "sideeffect.local_model_windows_etw_explanation_development_results",
        "schema_version": 1,
        "corpus_sha256": corpus_digest,
        "evaluation_status": corpus["evaluation_status"],
        "label_review_status": corpus["label_review_status"],
        "run": {},
        "cases": [],
        "errors": [],
    }
    run_identity: dict[str, str] | None = None
    for case in corpus["cases"]:
        capture_path = evaluator.FIXTURE_DIRECTORY / case["fixture"]
        capture = captures[case["fixture"]]
        started = time.monotonic()
        preview_argv = [
            *sideeffect_command, "model-explain-preview", "--question", case["question"],
            "--backend", backend, "--windows-runtime", str(capture_path.resolve()),
        ]
        code, raw, failure = invoke(preview_argv, timeout_seconds=timeout_seconds,
                                    output_limit=MAX_COMMAND_OUTPUT_BYTES)
        if failure is not None or code not in {0, 2}:
            if run_identity is None:
                raise RunnerError("first ETW preview failed; no verified run identity is available")
            results["errors"].append({"case_id": case["id"], "phase": "preview", "error": "ETW preview failed; subprocess output was discarded"})
            continue
        try:
            preview = _parse_cli_json(raw, "Windows ETW preview")
            parse_status, available, allowed = _preview_evidence(preview, case["question"], capture)
            current_identity = _run_identity(preview, backend)
        except (RunnerError, evaluator.ContractError, UnicodeError, ValueError):
            if run_identity is None:
                raise RunnerError("first ETW preview violated its pinned source contract") from None
            results["errors"].append({"case_id": case["id"], "phase": "preview", "error": "ETW preview violated its source contract; output was discarded"})
            continue
        if run_identity is None:
            run_identity = current_identity
            results["run"] = run_identity
        elif current_identity != run_identity:
            results["errors"].append({"case_id": case["id"], "phase": "preview", "error": "ETW model/runtime identity changed; output was discarded"})
            continue
        remaining = timeout_seconds - (time.monotonic() - started)
        if remaining <= 0:
            results["errors"].append({"case_id": case["id"], "phase": "analysis", "error": "ETW case timed out after preview; output was discarded"})
            continue
        analysis_argv = [*sideeffect_command, "model-explain", "--question", case["question"], "--backend", backend]
        if runtime is not None:
            analysis_argv.extend(["--runtime", runtime])
        analysis_argv.extend(["--confirm-sha256", preview["request_sha256"], "--windows-runtime", str(capture_path.resolve())])
        analysis_started = time.monotonic()
        analysis_code, analysis_raw, failure = invoke(analysis_argv, timeout_seconds=remaining,
                                                      output_limit=MAX_COMMAND_OUTPUT_BYTES)
        latency = max(0, min(timeout_seconds * 1000, int((time.monotonic() - analysis_started) * 1000)))
        if failure is not None or analysis_code not in {0, 2}:
            results["errors"].append({"case_id": case["id"], "phase": "analysis", "error": "ETW analysis failed; subprocess output was discarded"})
            continue
        try:
            analysis = _parse_cli_json(analysis_raw, "Windows ETW analysis")
            response, backend_used = _analysis_response(analysis, preview, allowed, parse_status)
            if (analysis_code == 0) != (response["selection_status"] == "selected"):
                raise RunnerError("ETW exit code conflicts with selector status")
        except (RunnerError, evaluator.ContractError, UnicodeError, ValueError):
            results["errors"].append({"case_id": case["id"], "phase": "analysis", "error": "ETW analysis violated the source contract; output was discarded"})
            continue
        results["cases"].append({
            "case_id": case["id"],
            "response": response,
            "source_parse_status": parse_status,
            "backend_used": backend_used,
            "available_evidence": available,
            "preview_request_sha256": preview["request_sha256"],
            "latency_ms": latency,
        })
    if run_identity is None:
        raise RunnerError("no valid Windows ETW preview completed")
    encoded = json.dumps(results, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    evaluator._require(len(encoded) <= evaluator.MAX_RESULTS_BYTES, "ETW results exceed the output bound")
    evaluator.validate_results(results, corpus, corpus_digest)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sideeffect", required=True, help="path to the already-built SideEffect CLI")
    parser.add_argument("--runtime", help="optional path to an already-installed local runtime")
    parser.add_argument("--backend", choices=("auto", "cpu", "cuda"), default="auto")
    parser.add_argument("--timeout-seconds", type=int, default=60, help="maximum preview plus analysis time per case (1..120)")
    parser.add_argument("--output", required=True, type=Path, help="new private result file; existing files are never replaced")
    args = parser.parse_args()
    try:
        sideeffect_path = str(Path(args.sideeffect).resolve(strict=True))
        if not Path(sideeffect_path).is_file():
            raise RunnerError("SideEffect path is not a regular file")
        runtime_path = str(Path(args.runtime).resolve(strict=False)) if args.runtime is not None else None
        results = run_corpus(sideeffect_command=[sideeffect_path], backend=args.backend,
                             runtime=runtime_path, timeout_seconds=args.timeout_seconds)
        encoded = json.dumps(results, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        process_helpers._write_new_private_file(args.output, encoded)
        print(f"Wrote Windows ETW development selector results for {len(results['cases'])} cases; {len(results['errors'])} failed.")
        return 0 if not results["errors"] else 2
    except (RunnerError, evaluator.ContractError, OSError, UnicodeError, ValueError) as error:
        print(f"Windows ETW explanation corpus run failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
