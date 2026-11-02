"""Build one identity-blinded packet from a validated synthetic selector run.

This tool never launches a model. It checks the pinned results file and the
provided SideEffect preview/result pair, then emits only the review contract.
It does not prove reviewer independence or that the supplied files originated
from an authentic capture.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import evaluate_local_model_explain as evaluator


MAX_PREVIEW_BYTES = 12 * 1024 * 1024
MAX_ANALYSIS_BYTES = 2 * 1024 * 1024
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
PREVIEW_CONTRACTS = {
    "sideeffect.local_model_explanation_preview": (
        3,
        "sideeffect.local_model_explanation",
        3,
    ),
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise evaluator.ContractError(message)


def _decode_json(raw: bytes, label: str) -> Any:
    def reject_constant(value: str) -> None:
        raise evaluator.ContractError(f"{label} contains invalid JSON constant {value}")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=evaluator._unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise evaluator.ContractError(f"{label} is not strict UTF-8 JSON: {error}") from error


def _load_json(path: Path, limit: int, label: str) -> Any:
    raw = evaluator._read_regular_file(path, limit, label)
    return _decode_json(raw, label)


def _object(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _bounded_json_string(value: Any, label: str, limit: int) -> str:
    _require(isinstance(value, str), f"{label} must be a string")
    _require(len(value.encode("utf-8")) <= limit, f"{label} exceeds {limit} UTF-8 bytes")
    return value


def _source_rows(prompt: dict[str, Any]) -> dict[str, dict[str, Any]]:
    _require("source" not in prompt, "blind packet preparation currently supports Linux strace previews only")
    rows = prompt.get("observed_syscall_results")
    label = "Linux syscall rows"
    _require(isinstance(rows, list) and len(rows) <= 50_000, f"{label} must be a bounded array")
    by_id: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        row = _object(row, f"{label}[{index}]")
        evidence_id = row.get("evidence_id")
        _require(isinstance(evidence_id, str), f"{label}[{index}] has no evidence ID")
        _require(evidence_id not in by_id, f"duplicate evidence ID in {label}")
        by_id[evidence_id] = row

    relations = prompt.get("process_relations", [])
    _require(isinstance(relations, list) and len(relations) <= 50_000, "process relations must be a bounded array")
    for index, relation in enumerate(relations):
        relation = _object(relation, f"process_relations[{index}]")
        evidence = _object(relation.get("evidence"), f"process_relations[{index}].evidence")
        evidence_id = evidence.get("evidence_id")
        _require(isinstance(evidence_id, str), f"process_relations[{index}] has no selectable evidence ID")
        _require(evidence_id not in by_id, "duplicate evidence ID across preview sections")
        by_id[evidence_id] = relation

    return by_id


def prepare_packet(
    *,
    case_id: str,
    corpus: dict[str, Any],
    corpus_digest: str,
    results: dict[str, Any],
    preview: dict[str, Any],
    analysis: dict[str, Any],
) -> dict[str, Any]:
    _require(results.get("schema_version") == 3, "review preparation requires a validated results v3 file")
    case_by_id = {row["id"]: row for row in corpus["cases"]}
    _require(case_id in case_by_id, f"unknown case ID: {case_id}")
    case = case_by_id[case_id]
    result_rows = [row for row in results["cases"] if row.get("case_id") == case_id]
    _require(len(result_rows) == 1, f"results must contain exactly one row for case {case_id}")
    result_row = result_rows[0]

    preview_schema = preview.get("schema")
    _require(isinstance(preview_schema, str), "preview schema must be a string")
    contract = PREVIEW_CONTRACTS.get(preview_schema)
    _require(contract is not None, "unsupported SideEffect explanation preview schema")
    preview_version, analysis_schema, analysis_version = contract
    _require(preview.get("schema_version") == preview_version, "unsupported preview schema version")
    _require(preview.get("question") == case["question"], "preview question does not match the pinned corpus case")
    request_digest = preview.get("request_sha256")
    _require(isinstance(request_digest, str) and SHA256_PATTERN.fullmatch(request_digest) is not None, "preview request digest is invalid")
    _require(request_digest == result_row["preview_request_sha256"], "preview digest does not match the pinned result row")

    prompt_text = _bounded_json_string(preview.get("prompt"), "preview prompt", evaluator.MAX_RESULTS_BYTES)
    prompt_value = _decode_json(prompt_text.encode("utf-8"), "preview prompt")
    prompt_value = _object(prompt_value, "preview prompt")
    _require(prompt_value.get("user_question") == case["question"], "prompt question does not match the pinned corpus case")
    by_id = _source_rows(prompt_value)
    output_schema = _object(preview.get("output_schema"), "preview output_schema")
    properties = _object(output_schema.get("properties"), "preview output_schema.properties")
    evidence_property = _object(properties.get("evidence_ids"), "preview output_schema.properties.evidence_ids")
    evidence_items = _object(evidence_property.get("items"), "preview output_schema.properties.evidence_ids.items")
    enum_ids = evidence_items.get("enum")
    _require(isinstance(enum_ids, list) and all(isinstance(item, str) for item in enum_ids), "preview selector schema has no bounded evidence ID enum")
    _require(len(enum_ids) == len(set(enum_ids)) and set(enum_ids) == set(by_id), "preview selector enum does not match exact preview rows")
    result_evidence = result_row["available_evidence"]
    _require(
        {item["evidence_id"] for item in result_evidence} == set(by_id),
        "results evidence IDs do not match exact preview rows",
    )

    _require(analysis.get("schema") == analysis_schema, "analysis schema does not match preview source")
    _require(analysis.get("schema_version") == analysis_version, "analysis schema version does not match preview source")
    _require(analysis.get("request_sha256") == request_digest, "analysis digest does not match preview digest")
    interpretation = _object(analysis.get("interpretation"), "analysis interpretation")
    response = {
        "selection_status": interpretation.get("selection_status"),
        "evidence_ids": interpretation.get("evidence_ids"),
        "abstain_reason": interpretation.get("abstain_reason"),
    }
    _require(isinstance(response["selection_status"], str) and response["selection_status"] in evaluator.SELECTION_STATUS_VALUES, "analysis selection status is invalid")
    evidence_ids = response["evidence_ids"]
    _require(isinstance(evidence_ids, list) and len(evidence_ids) <= evaluator.MAX_SELECTED_EVIDENCE_IDS, "analysis evidence IDs are invalid or oversized")
    _require(all(isinstance(item, str) and item in by_id for item in evidence_ids), "analysis selected an ID outside the exact preview")
    _require(len(evidence_ids) == len(set(evidence_ids)), "analysis selected duplicate evidence IDs")
    _require(result_row["response"] == {"selection_status": response["selection_status"], "evidence_ids": evidence_ids}, "analysis selection does not match the pinned results row")
    _require(analysis.get("backend_used") == result_row["backend_used"], "analysis backend does not match the pinned results row")
    _require(analysis.get("evidence_summary") == preview.get("evidence_summary"), "analysis coverage does not match the reviewed preview")
    _require(analysis["evidence_summary"].get("parse_status") == result_row["source_parse_status"], "source parse status does not match the pinned results row")

    selected_facts = interpretation.get("selected_facts")
    _require(isinstance(selected_facts, list) and selected_facts == [by_id[item] for item in evidence_ids], "analysis selected facts do not map to exact preview rows")
    if response["selection_status"] == "abstained":
        _require(not evidence_ids, "an abstained analysis cannot select evidence")
    else:
        _require(bool(evidence_ids), "a selected analysis must contain evidence IDs")
    deterministic_reason = preview.get("deterministic_abstain_reason")
    if deterministic_reason is not None:
        _require(isinstance(deterministic_reason, str) and deterministic_reason in evaluator.ABSTAIN_REASONS, "preview deterministic abstention reason is invalid")
        _require(response["selection_status"] == "abstained", "a deterministic scope abstention cannot select evidence")
        _require(response["abstain_reason"] == deterministic_reason, "analysis abstention does not match the deterministic preview reason")
        _require(analysis.get("backend_used") == "not_run", "a deterministic scope abstention must not report model inference")

    result_target_digest = result_row["review_target_sha256"]
    expected_target_digest = evaluator._review_target_sha256(result_row, case["question"], corpus_digest)
    _require(result_target_digest == expected_target_digest, "results review-target digest is invalid")

    packet = {
        "schema": "sideeffect.local_model_explain_blind_review_packet",
        "schema_version": 1,
        "corpus_sha256": corpus_digest,
        "case_id": case_id,
        "question": case["question"],
        "preview_schema": preview_schema,
        "preview_schema_version": preview_version,
        "deterministic_abstain_reason": preview.get("deterministic_abstain_reason"),
        "system_prompt": _bounded_json_string(preview.get("system_prompt"), "preview system_prompt", 16 * 1024),
        "prompt": prompt_text,
        "output_schema": output_schema,
        "evidence_summary": _object(preview.get("evidence_summary"), "preview evidence_summary"),
        "response": response,
        "preview_request_sha256": request_digest,
        "review_target_sha256": result_target_digest,
    }
    return packet


def _write_new_private_file(path: Path, packet: dict[str, Any]) -> None:
    encoded = json.dumps(packet, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", required=True, help="pinned synthetic corpus case ID")
    parser.add_argument("--results", required=True, type=Path, help="complete validated schema-v3 selector results JSON")
    parser.add_argument("--preview", required=True, type=Path, help="exact SideEffect model-explain-preview output JSON")
    parser.add_argument("--analysis", required=True, type=Path, help="exact SideEffect model-explain output JSON")
    parser.add_argument("--output", type=Path, help="new output path; existing paths are never overwritten (default: stdout)")
    args = parser.parse_args()
    try:
        corpus, corpus_digest = evaluator.load_corpus()
        results = _load_json(args.results, evaluator.MAX_RESULTS_BYTES, "pre-recorded results")
        _require(isinstance(results, dict), "pre-recorded results must be an object")
        _require(results.get("schema_version") == 3, "pre-recorded results must use schema version 3")
        evaluator._validate_results_v3(results, corpus, corpus_digest)
        preview = _load_json(args.preview, MAX_PREVIEW_BYTES, "SideEffect preview")
        analysis = _load_json(args.analysis, MAX_ANALYSIS_BYTES, "SideEffect analysis")
        _require(isinstance(preview, dict), "SideEffect preview must be an object")
        _require(isinstance(analysis, dict), "SideEffect analysis must be an object")
        packet = prepare_packet(
            case_id=args.case_id,
            corpus=corpus,
            corpus_digest=corpus_digest,
            results=results,
            preview=preview,
            analysis=analysis,
        )
        if args.output is None:
            print(json.dumps(packet, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False))
        else:
            _write_new_private_file(args.output, packet)
        return 0
    except (evaluator.ContractError, OSError, UnicodeError, ValueError) as error:
        print(f"local model explanation review preparation error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
