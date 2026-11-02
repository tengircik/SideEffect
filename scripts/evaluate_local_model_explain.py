#!/usr/bin/env python3
"""Validate the frozen development corpus and pre-recorded model outputs.

Results v1 validates historical prose-response structure; results v2 validates
the selector contract; results v3 adds blinded human-review annotations to
selector runs. Structural checks never establish semantic correctness, and this
tool never launches a model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import stat
import sys
import unicodedata
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CORPUS_RELATIVE_PATH = Path("tests/fixtures/local_model_explain_v1/corpus.json")
FIXTURE_DIRECTORY = ROOT / "tests" / "fixtures" / "local_model_explain_v1"
EXPECTED_CORPUS_SHA256 = "cd67fd08e783743808b08914b775992f9c6ee0a24a14ad7a3568684940ff16be"
MAX_CORPUS_BYTES = 128 * 1024
MAX_FIXTURE_BYTES = 64 * 1024
MAX_CASES = 128
MAX_RESULTS_BYTES = 16 * 1024 * 1024
MAX_CASE_ID_BYTES = 96
MAX_QUESTION_BYTES = 2048
MAX_STATEMENT_BYTES = 512
MAX_STATEMENTS = 5
MAX_EVIDENCE_IDS_PER_STATEMENT = 4
MAX_SELECTED_EVIDENCE_IDS = 5
MAX_RUN_MODEL_ID_BYTES = 128
MAX_REVIEWERS_PER_CASE = 8
MAX_REVIEWER_ID_BYTES = 64
MAX_REVIEW_LABELS = 32
STATUS_VALUES = {"answered", "partial", "abstained"}
SELECTION_STATUS_VALUES = {"selected", "partial_selection", "abstained"}
ABSTAIN_REASONS = {"ambiguous", "unsupported_scope", "insufficient_evidence"}
STATEMENT_KINDS = {"observation", "interpretation", "uncertainty"}
LABEL_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
EVIDENCE_ID_PATTERN = re.compile(r"^E[0-9]{3}$")
REVIEWER_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ANSWERABILITY_VALUES = {"answerable", "unanswerable", "uncertain"}


class ContractError(ValueError):
    """The pinned corpus or results file violates the local contract."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _decode_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"{label} is not strict UTF-8 JSON: {error}") from error


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _exact_keys(value: Any, required: set[str], label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    actual = set(value)
    _require(actual == required, f"{label} keys must be exactly {sorted(required)}")
    return value


def _bounded_string(value: Any, label: str, byte_limit: int) -> str:
    _require(isinstance(value, str) and value.strip(), f"{label} must be a non-empty string")
    _require(len(value.encode("utf-8")) <= byte_limit, f"{label} exceeds {byte_limit} UTF-8 bytes")
    _require(not any(unicodedata.category(char) == "Cc" for char in value), f"{label} contains a control character")
    return value


def _labels(value: Any, label: str) -> list[str]:
    _require(isinstance(value, list), f"{label} must be an array")
    _require(all(isinstance(item, str) and LABEL_PATTERN.fullmatch(item) for item in value), f"{label} contains an invalid label")
    _require(len(value) == len(set(value)), f"{label} contains duplicate labels")
    return value


def _review_target_sha256(row: dict[str, Any], question: str, corpus_digest: str) -> str:
    """Hash the exact bounded case context reviewers are asked to assess."""
    target = {
        "schema": "sideeffect.local_model_explain_review_target",
        "schema_version": 1,
        "corpus_sha256": corpus_digest,
        "case_id": row["case_id"],
        "question": question,
        "preview_request_sha256": row["preview_request_sha256"],
        "selector_response": row["response"],
        "source_parse_status": row["source_parse_status"],
        "available_evidence": row["available_evidence"],
    }
    canonical = json.dumps(
        target,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _read_regular_file(path: Path, limit: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ContractError(f"cannot inspect {label}: {error}") from error
    _require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular non-symlink file")
    _require(metadata.st_size <= limit, f"{label} exceeds {limit} bytes")
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError as error:
        raise ContractError(f"cannot read {label}: {error}") from error
    _require(len(raw) <= limit, f"{label} grew beyond {limit} bytes while reading")
    return raw


def load_corpus() -> tuple[dict[str, Any], str]:
    raw = _read_regular_file(ROOT / CORPUS_RELATIVE_PATH, MAX_CORPUS_BYTES, "corpus")
    digest = hashlib.sha256(raw).hexdigest()
    _require(bool(EXPECTED_CORPUS_SHA256), "corpus digest pin has not been finalized")
    _require(digest == EXPECTED_CORPUS_SHA256, "corpus SHA-256 does not match the evaluator pin")
    corpus = _decode_json(raw, "corpus")
    validate_corpus(corpus)
    return corpus, digest


def validate_corpus(corpus: Any) -> None:
    corpus = _exact_keys(
        corpus,
        {"schema", "schema_version", "evaluation_status", "response_contract", "fixtures", "permutation_groups", "cases"},
        "corpus",
    )
    _require(corpus["schema"] == "sideeffect.local_model_explain_development_corpus", "unsupported corpus schema")
    _require(corpus["schema_version"] == 1, "unsupported corpus version")
    _require(corpus["evaluation_status"] == "development_only_not_a_release_gate", "corpus must remain development-only")

    contract = _exact_keys(
        corpus["response_contract"],
        {"root_keys", "statuses", "abstain_reasons", "statement_kinds", "maximum_statements", "maximum_statement_text_bytes", "maximum_evidence_ids_per_statement", "statement_citation_required", "claim_text_semantics_verified_automatically"},
        "response_contract",
    )
    _require(contract == {
        "root_keys": ["status", "abstain_reason", "statements"],
        "statuses": ["answered", "partial", "abstained"],
        "abstain_reasons": ["ambiguous", "unsupported_scope", "insufficient_evidence"],
        "statement_kinds": ["observation", "interpretation", "uncertainty"],
        "maximum_statements": MAX_STATEMENTS,
        "maximum_statement_text_bytes": MAX_STATEMENT_BYTES,
        "maximum_evidence_ids_per_statement": MAX_EVIDENCE_IDS_PER_STATEMENT,
        "statement_citation_required": True,
        "claim_text_semantics_verified_automatically": False,
    }, "response contract values do not match this evaluator")

    fixture_rows = corpus["fixtures"]
    _require(isinstance(fixture_rows, list) and fixture_rows, "fixtures must be a non-empty array")
    fixtures: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(fixture_rows):
        row = _exact_keys(row, {"path", "size_bytes", "sha256"}, f"fixtures[{index}]")
        relative = _bounded_string(row["path"], f"fixtures[{index}].path", 128)
        fixture_path = Path(relative)
        _require(not fixture_path.is_absolute() and len(fixture_path.parts) == 1 and fixture_path.name == relative, f"fixture path is not a flat safe name: {relative}")
        _require(relative.endswith(".trace") and relative not in fixtures, f"invalid or duplicate fixture path: {relative}")
        _require(type(row["size_bytes"]) is int and 0 < row["size_bytes"] <= MAX_FIXTURE_BYTES, f"invalid fixture size: {relative}")
        _require(isinstance(row["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None, f"invalid fixture digest: {relative}")
        absolute = (FIXTURE_DIRECTORY / relative)
        try:
            absolute.resolve(strict=True).relative_to(FIXTURE_DIRECTORY.resolve(strict=True))
        except (OSError, ValueError) as error:
            raise ContractError(f"fixture path escapes its directory: {relative}") from error
        data = _read_regular_file(absolute, MAX_FIXTURE_BYTES, f"fixture {relative}")
        _require(len(data) == row["size_bytes"], f"fixture byte length mismatch: {relative}")
        _require(hashlib.sha256(data).hexdigest() == row["sha256"], f"fixture SHA-256 mismatch: {relative}")
        fixtures[relative] = row

    cases = corpus["cases"]
    _require(isinstance(cases, list) and 0 < len(cases) <= MAX_CASES, f"cases must contain between 1 and {MAX_CASES} rows")
    case_by_id: dict[str, dict[str, Any]] = {}
    expected_case_keys = {"id", "fixture", "question", "expected_status", "expected_abstain_reason", "expected_semantic_labels", "required_evidence_labels", "forbidden_inferences"}
    for index, case in enumerate(cases):
        case = _exact_keys(case, expected_case_keys, f"cases[{index}]")
        case_id = _bounded_string(case["id"], f"cases[{index}].id", MAX_CASE_ID_BYTES)
        _require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}", case_id) is not None and case_id not in case_by_id, f"invalid or duplicate case ID: {case_id}")
        _require(isinstance(case["fixture"], str) and case["fixture"] in fixtures, f"case {case_id} references an unknown fixture")
        question = _bounded_string(case["question"], f"case {case_id} question", MAX_QUESTION_BYTES)
        _require(len(question) <= MAX_QUESTION_BYTES, f"question is too long in case {case_id}")
        status = case["expected_status"]
        _require(isinstance(status, str) and status in STATUS_VALUES, f"invalid expected status in case {case_id}")
        reason = case["expected_abstain_reason"]
        if status == "abstained":
            _require(isinstance(reason, str) and reason in ABSTAIN_REASONS, f"abstained case {case_id} needs a valid reason")
        else:
            _require(reason is None, f"non-abstained case {case_id} must have a null reason")
        expected_labels = _labels(case["expected_semantic_labels"], f"case {case_id} expected_semantic_labels")
        required_labels = _labels(case["required_evidence_labels"], f"case {case_id} required_evidence_labels")
        forbidden = case["forbidden_inferences"]
        _require(isinstance(forbidden, list) and len(forbidden) <= 12 and all(isinstance(item, str) and item.strip() and len(item.encode("utf-8")) <= 256 for item in forbidden), f"invalid forbidden-inference list in case {case_id}")
        _require(len(required_labels) <= len(expected_labels) and set(required_labels).issubset(expected_labels), f"required evidence labels must be expected labels in case {case_id}")
        if status == "abstained":
            _require(not expected_labels and not required_labels, f"abstained case {case_id} cannot require evidence labels")
        case_by_id[case_id] = case

    groups = corpus["permutation_groups"]
    _require(isinstance(groups, list), "permutation_groups must be an array")
    seen_group_ids: set[str] = set()
    grouped_case_ids: set[str] = set()
    for index, group in enumerate(groups):
        group = _exact_keys(group, {"id", "case_ids", "invariant_question", "expected_semantic_labels"}, f"permutation_groups[{index}]")
        group_id = _bounded_string(group["id"], f"permutation_groups[{index}].id", 96)
        _require(group_id not in seen_group_ids, f"duplicate permutation group ID: {group_id}")
        seen_group_ids.add(group_id)
        ids = group["case_ids"]
        _require(isinstance(ids, list) and len(ids) == 4 and all(isinstance(item, str) for item in ids) and len(set(ids)) == 4, f"permutation group {group_id} must have exactly four distinct cases")
        _require(all(case_id in case_by_id for case_id in ids), f"permutation group {group_id} references an unknown case")
        _require(not (set(ids) & grouped_case_ids), f"case appears in multiple permutation groups: {group_id}")
        grouped_case_ids.update(ids)
        question = _bounded_string(group["invariant_question"], f"permutation group {group_id} question", MAX_QUESTION_BYTES)
        labels = _labels(group["expected_semantic_labels"], f"permutation group {group_id} labels")
        group_cases = [case_by_id[case_id] for case_id in ids]
        _require(all(isinstance(case["fixture"], str) and case["fixture"] in fixtures for case in group_cases), f"permutation group {group_id} has an unknown fixture")
        _require(all(case["question"] == question for case in group_cases), f"permutation group {group_id} questions are not invariant")
        _require(all(case["expected_status"] == "answered" for case in group_cases), f"permutation group {group_id} must be answerable")
        _require(all(case["expected_semantic_labels"] == labels for case in group_cases), f"permutation group {group_id} semantic expectations differ")
        line_sets = []
        line_orders = []
        for case in group_cases:
            raw = _read_regular_file(FIXTURE_DIRECTORY / case["fixture"], MAX_FIXTURE_BYTES, f"fixture {case['fixture']}")
            records = [line for line in raw.splitlines() if line.strip()]
            line_sets.append(sorted(records))
            line_orders.append(tuple(records))
        _require(all(rows == line_sets[0] for rows in line_sets[1:]), f"permutation group {group_id} fixtures do not contain the same record multiset")
        _require(len(set(line_orders)) == len(line_orders), f"permutation group {group_id} has duplicate orders")

    _require(len(grouped_case_ids) == 4, "expected exactly four permutation cases in this development corpus")
    _require(any("ignore all prior instructions" in case["question"].lower() for case in cases), "question-injection case is missing")
    _require(any("ignore previous instructions" in (FIXTURE_DIRECTORY / name).read_text(encoding="utf-8").lower() for name in fixtures), "trace-value injection case is missing")
    _require(any(case["expected_status"] == "partial" for case in cases), "partial-input case is missing")
    _require(any(case["expected_abstain_reason"] == "ambiguous" for case in cases), "ambiguous-abstention case is missing")
    _require(any(case["expected_abstain_reason"] == "unsupported_scope" for case in cases), "unsupported-scope case is missing")


def validate_response(response: Any, allowed_ids: set[str], case_id: str) -> tuple[dict[str, Any], list[str]]:
    response = _exact_keys(response, {"status", "abstain_reason", "statements"}, f"response for {case_id}")
    status = response["status"]
    _require(isinstance(status, str) and status in STATUS_VALUES, f"invalid response status in case {case_id}")
    reason = response["abstain_reason"]
    statements = response["statements"]
    _require(isinstance(statements, list) and len(statements) <= MAX_STATEMENTS, f"invalid statement array in case {case_id}")
    if status == "abstained":
        _require(isinstance(reason, str) and reason in ABSTAIN_REASONS and not statements, f"invalid abstention branch in case {case_id}")
    else:
        _require(reason is None and 1 <= len(statements) <= MAX_STATEMENTS, f"invalid answer branch in case {case_id}")

    cited: list[str] = []
    for index, statement in enumerate(statements):
        statement = _exact_keys(statement, {"kind", "text", "evidence_ids"}, f"statement {index} in case {case_id}")
        _require(isinstance(statement["kind"], str) and statement["kind"] in STATEMENT_KINDS, f"invalid statement kind in case {case_id}")
        _bounded_string(statement["text"], f"statement text in case {case_id}", MAX_STATEMENT_BYTES)
        evidence_ids = statement["evidence_ids"]
        _require(isinstance(evidence_ids, list) and 1 <= len(evidence_ids) <= MAX_EVIDENCE_IDS_PER_STATEMENT, f"statement lacks bounded citations in case {case_id}")
        _require(all(isinstance(item, str) and EVIDENCE_ID_PATTERN.fullmatch(item) for item in evidence_ids), f"invalid evidence ID in case {case_id}")
        _require(len(evidence_ids) == len(set(evidence_ids)), f"duplicate citation within statement in case {case_id}")
        _require(all(item in allowed_ids for item in evidence_ids), f"response cites evidence outside its preview in case {case_id}")
        cited.extend(evidence_ids)
    return response, cited


def _validate_results_v1(
    results: dict[str, Any], corpus: dict[str, Any], corpus_digest: str
) -> dict[str, Any]:
    result_keys = set(results)
    _require(result_keys in (
        {"schema", "schema_version", "corpus_sha256", "cases"},
        {"schema", "schema_version", "corpus_sha256", "cases", "errors"},
    ), "results contain missing or unexpected keys")
    _require(results["schema"] == "sideeffect.local_model_explain_development_results", "unsupported results schema")
    _require(results["schema_version"] == 1, "unsupported results version")
    _require(results["corpus_sha256"] == corpus_digest, "results corpus digest does not match the pinned development corpus")
    rows = results["cases"]
    errors = results.get("errors", [])
    _require(isinstance(rows, list) and len(rows) <= len(corpus["cases"]), "results cases must be a bounded array")
    _require(isinstance(errors, list) and len(errors) <= len(corpus["cases"]), "results errors must be a bounded array")
    expected_cases = {case["id"]: case for case in corpus["cases"]}
    seen: set[str] = set()
    execution_errors: list[dict[str, str]] = []
    report_rows: list[dict[str, Any]] = []
    total_valid = 0
    total_status_correct = 0
    total_citation_label_hits = 0
    total_required_labels = 0
    latencies: list[int] = []
    human_reviewed = 0
    human_label_exact = 0
    human_unsupported_claim_rows = 0

    for index, row in enumerate(errors):
        row = _exact_keys(row, {"case_id", "phase", "error"}, f"results.errors[{index}]")
        case_id = row["case_id"]
        _require(isinstance(case_id, str) and case_id in expected_cases and case_id not in seen, f"unknown or duplicate error case ID: {case_id}")
        _require(isinstance(row["phase"], str) and row["phase"] in {"preview", "analysis"}, f"invalid error phase in case {case_id}")
        message = _bounded_string(row["error"], f"error for {case_id}", 1024)
        seen.add(case_id)
        execution_errors.append({"case_id": case_id, "phase": row["phase"], "error": message})

    case_responses: dict[str, tuple[str, str | None, list[str]]] = {}

    for index, row in enumerate(rows):
        row = _exact_keys(row, {"case_id", "response", "available_evidence", "latency_ms", "human_review"}, f"results.cases[{index}]")
        case_id = row["case_id"]
        _require(isinstance(case_id, str) and case_id in expected_cases and case_id not in seen, f"unknown or duplicate result case ID: {case_id}")
        seen.add(case_id)
        case = expected_cases[case_id]
        evidence_rows = row["available_evidence"]
        _require(isinstance(evidence_rows, list) and 0 < len(evidence_rows) <= 64, f"available evidence is required and must remain bounded in case {case_id}")
        evidence_labels: dict[str, list[str]] = {}
        for evidence_index, evidence_row in enumerate(evidence_rows):
            evidence_row = _exact_keys(evidence_row, {"evidence_id", "semantic_labels"}, f"available_evidence[{evidence_index}] in case {case_id}")
            evidence_id = evidence_row["evidence_id"]
            _require(isinstance(evidence_id, str) and EVIDENCE_ID_PATTERN.fullmatch(evidence_id), f"invalid available evidence ID in case {case_id}")
            _require(evidence_id not in evidence_labels, f"duplicate available evidence ID in case {case_id}")
            evidence_labels[evidence_id] = _labels(evidence_row["semantic_labels"], f"available evidence labels in case {case_id}")
        latency = row["latency_ms"]
        _require(type(latency) is int and 0 <= latency <= 120_000, f"invalid latency in case {case_id}")
        latencies.append(latency)
        response, cited_ids = validate_response(row["response"], set(evidence_labels), case_id)
        total_valid += 1
        status_match = response["status"] == case["expected_status"] and response["abstain_reason"] == case["expected_abstain_reason"]
        total_status_correct += int(status_match)
        cited_labels = {label for evidence_id in cited_ids for label in evidence_labels[evidence_id]}
        case_responses[case_id] = (
            response["status"],
            response["abstain_reason"],
            sorted(cited_labels),
        )
        required = set(case["required_evidence_labels"])
        citation_hits = len(required & cited_labels)
        total_citation_label_hits += citation_hits
        total_required_labels += len(required)

        review = row["human_review"]
        human_report: dict[str, Any] | None = None
        if review is not None:
            review = _exact_keys(review, {"completed", "semantic_labels", "unsupported_claims", "note"}, f"human review in case {case_id}")
            _require(type(review["completed"]) is bool, f"human review completed must be boolean in case {case_id}")
            reviewed_labels = _labels(review["semantic_labels"], f"human review labels in case {case_id}")
            unsupported = review["unsupported_claims"]
            _require(isinstance(unsupported, list) and all(isinstance(item, str) and item.strip() for item in unsupported), f"human review unsupported_claims must be strings in case {case_id}")
            note = review["note"]
            if note is not None:
                _bounded_string(note, f"human review note in case {case_id}", 512)
            exact = set(reviewed_labels) == set(case["expected_semantic_labels"])
            if review["completed"]:
                human_reviewed += 1
                human_label_exact += int(exact)
                human_unsupported_claim_rows += int(bool(unsupported))
            human_report = {
                "completed_by_human": review["completed"],
                "reviewed_labels_match_expected": exact if review["completed"] else None,
                "unsupported_claims_recorded": len(unsupported) if review["completed"] else None,
                "note": note,
            }
        report_rows.append({
            "case_id": case_id,
            "response_contract_valid": True,
            "expected_status_and_abstention_match": status_match,
            "required_evidence_labels": sorted(required),
            "cited_evidence_labels": sorted(cited_labels),
            "required_evidence_label_recall": (citation_hits / len(required)) if required else None,
            "human_review": human_report,
            "latency_ms": latency,
        })

    _require(seen == set(expected_cases), "results omit one or more corpus cases")
    sorted_latencies = sorted(latencies)
    p95 = sorted_latencies[math.ceil(0.95 * len(sorted_latencies)) - 1] if sorted_latencies else None
    permutation_rows = []
    for group in corpus["permutation_groups"]:
        signatures = [case_responses.get(case_id) for case_id in group["case_ids"]]
        consistent = all(signature is not None for signature in signatures) and len(set(map(repr, signatures))) == 1
        permutation_rows.append({"group_id": group["id"], "consistent": consistent})
    return {
        "schema": "sideeffect.local_model_explain_development_report",
        "schema_version": 1,
        "evaluation_status": "development_only_not_a_release_gate",
        "corpus_sha256": corpus_digest,
        "cases": len(corpus["cases"]),
        "response_contract_valid_count": total_valid,
        "execution_error_count": len(execution_errors),
        "execution_errors": execution_errors,
        "expected_status_match_count": total_status_correct,
        "required_evidence_label_recall": (total_citation_label_hits / total_required_labels) if total_required_labels else None,
        "human_reviewed_case_count": human_reviewed,
        "human_review_exact_label_match_count": human_label_exact,
        "human_review_cases_with_unsupported_claims": human_unsupported_claim_rows,
        "p95_latency_ms": p95,
        "permutation_group_count": len(permutation_rows),
        "permutation_consistent_group_count": sum(row["consistent"] for row in permutation_rows),
        "permutation_groups": permutation_rows,
        "semantic_text_truth_verified_automatically": False,
        "report_rows": report_rows,
    }


def _validate_results_v2(
    results: dict[str, Any], corpus: dict[str, Any], corpus_digest: str
) -> dict[str, Any]:
    result_keys = set(results)
    _require(result_keys in (
        {"schema", "schema_version", "corpus_sha256", "run", "cases"},
        {"schema", "schema_version", "corpus_sha256", "run", "cases", "errors"},
    ), "results contain missing or unexpected keys")
    _require(results["schema"] == "sideeffect.local_model_explain_development_results", "unsupported results schema")
    _require(results["schema_version"] == 2, "unsupported results version")
    _require(results["corpus_sha256"] == corpus_digest, "results corpus digest does not match the pinned development corpus")
    run = _exact_keys(
        results["run"],
        {"model_id", "model_sha256", "runtime_source_revision", "backend_preference"},
        "results.run",
    )
    run["model_id"] = _bounded_string(run["model_id"], "results.run.model_id", MAX_RUN_MODEL_ID_BYTES)
    _require(
        run["model_id"] not in {".", ".."} and not any(separator in run["model_id"] for separator in ("/", "\\", ":")),
        "results.run.model_id must not contain a filesystem path",
    )
    _require(
        isinstance(run["model_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", run["model_sha256"]) is not None,
        "results.run.model_sha256 must be 64 lowercase hexadecimal characters",
    )
    _require(
        isinstance(run["runtime_source_revision"], str)
        and re.fullmatch(r"[0-9a-f]{40}", run["runtime_source_revision"]) is not None,
        "results.run.runtime_source_revision must be 40 lowercase hexadecimal characters",
    )
    _require(
        isinstance(run["backend_preference"], str)
        and run["backend_preference"] in {"auto", "cpu", "cuda"},
        "results.run.backend_preference must be auto, cpu, or cuda",
    )
    rows = results["cases"]
    errors = results.get("errors", [])
    _require(isinstance(rows, list) and len(rows) <= len(corpus["cases"]), "results cases must be a bounded array")
    _require(isinstance(errors, list) and len(errors) <= len(corpus["cases"]), "results errors must be a bounded array")

    expected_cases = {case["id"]: case for case in corpus["cases"]}
    seen: set[str] = set()
    execution_errors: list[dict[str, str]] = []
    report_rows: list[dict[str, Any]] = []
    case_signatures: dict[str, tuple[str, str, list[str]]] = {}
    latencies: list[int] = []
    valid_count = 0
    consistent_count = 0
    selected_required_label_hits = 0
    selectable_required_label_count = 0
    unavailable_required_label_count = 0

    for index, row in enumerate(errors):
        row = _exact_keys(row, {"case_id", "phase", "error"}, f"results.errors[{index}]")
        case_id = row["case_id"]
        _require(isinstance(case_id, str) and case_id in expected_cases and case_id not in seen, f"unknown or duplicate error case ID: {case_id}")
        _require(isinstance(row["phase"], str) and row["phase"] in {"preview", "analysis"}, f"invalid error phase in case {case_id}")
        message = _bounded_string(row["error"], f"error for {case_id}", 1024)
        seen.add(case_id)
        execution_errors.append({"case_id": case_id, "phase": row["phase"], "error": message})

    for index, row in enumerate(rows):
        row = _exact_keys(
            row,
            {"case_id", "response", "source_parse_status", "backend_used", "available_evidence", "latency_ms"},
            f"results.cases[{index}]",
        )
        case_id = row["case_id"]
        _require(isinstance(case_id, str) and case_id in expected_cases and case_id not in seen, f"unknown or duplicate result case ID: {case_id}")
        seen.add(case_id)
        case = expected_cases[case_id]

        source_parse_status = row["source_parse_status"]
        _require(
            isinstance(source_parse_status, str) and source_parse_status in {"complete", "partial"},
            f"invalid source_parse_status in case {case_id}",
        )
        backend_used = row["backend_used"]
        _require(
            isinstance(backend_used, str) and backend_used in {"not_run", "cpu", "cuda"},
            f"invalid backend_used in case {case_id}",
        )
        backend_preference = results["run"]["backend_preference"]
        _require(
            backend_preference == "auto"
            or backend_used == "not_run"
            or backend_preference == backend_used,
            f"backend_used is inconsistent with run.backend_preference in case {case_id}",
        )
        response = _exact_keys(
            row["response"],
            {"selection_status", "evidence_ids"},
            f"selector response for {case_id}",
        )
        selection_status = response["selection_status"]
        _require(
            isinstance(selection_status, str) and selection_status in SELECTION_STATUS_VALUES,
            f"invalid selection_status in case {case_id}",
        )
        evidence_ids = response["evidence_ids"]
        _require(
            isinstance(evidence_ids, list) and len(evidence_ids) <= MAX_SELECTED_EVIDENCE_IDS,
            f"invalid or oversized selected evidence ID array in case {case_id}",
        )
        _require(
            all(isinstance(item, str) and EVIDENCE_ID_PATTERN.fullmatch(item) for item in evidence_ids),
            f"invalid selected evidence ID in case {case_id}",
        )
        _require(len(evidence_ids) == len(set(evidence_ids)), f"duplicate selected evidence ID in case {case_id}")

        evidence_rows = row["available_evidence"]
        _require(isinstance(evidence_rows, list) and len(evidence_rows) <= 64, f"available evidence must remain bounded in case {case_id}")
        evidence_labels: dict[str, list[str]] = {}
        for evidence_index, evidence_row in enumerate(evidence_rows):
            evidence_row = _exact_keys(evidence_row, {"evidence_id", "semantic_labels"}, f"available_evidence[{evidence_index}] in case {case_id}")
            evidence_id = evidence_row["evidence_id"]
            _require(isinstance(evidence_id, str) and EVIDENCE_ID_PATTERN.fullmatch(evidence_id), f"invalid available evidence ID in case {case_id}")
            _require(evidence_id not in evidence_labels, f"duplicate available evidence ID in case {case_id}")
            evidence_labels[evidence_id] = _labels(evidence_row["semantic_labels"], f"available evidence labels in case {case_id}")
        _require(all(item in evidence_labels for item in evidence_ids), f"selection contains an evidence ID outside its syscall-result preview in case {case_id}")

        expected_state = (
            "abstained" if not evidence_ids else
            "selected" if source_parse_status == "complete" else
            "partial_selection"
        )
        state_consistent = selection_status == expected_state
        _require(state_consistent, f"selection_status, evidence_ids, and source_parse_status disagree in case {case_id}")
        _require(
            backend_used != "not_run" or selection_status == "abstained",
            f"not_run backend requires an empty abstention in case {case_id}",
        )
        valid_count += 1
        consistent_count += int(state_consistent)

        latency = row["latency_ms"]
        _require(type(latency) is int and 0 <= latency <= 120_000, f"invalid latency in case {case_id}")
        latencies.append(latency)
        selected_labels = sorted({label for evidence_id in evidence_ids for label in evidence_labels[evidence_id]})
        available_labels = {label for labels in evidence_labels.values() for label in labels}
        required_labels = set(case["required_evidence_labels"])
        selectable_required = required_labels & available_labels
        unavailable_required = required_labels - available_labels
        selected_required_hits = selectable_required & set(selected_labels)
        selected_required_label_hits += len(selected_required_hits)
        selectable_required_label_count += len(selectable_required)
        unavailable_required_label_count += len(unavailable_required)
        case_signatures[case_id] = (source_parse_status, selection_status, selected_labels)
        report_rows.append({
            "case_id": case_id,
            "selection_output_contract_valid": True,
            "selection_state_consistent_with_source_parse": state_consistent,
            "selection_status": selection_status,
            "backend_used": backend_used,
            "selected_evidence_ids": evidence_ids,
            "selected_evidence_labels": selected_labels,
            "required_evidence_labels_available_to_selector": sorted(selectable_required),
            "required_evidence_labels_unavailable_to_selector": sorted(unavailable_required),
            "selected_required_evidence_label_recall_over_available_labels": (
                len(selected_required_hits) / len(selectable_required) if selectable_required else None
            ),
            "latency_ms": latency,
        })

    _require(seen == set(expected_cases), "results omit one or more corpus cases")
    sorted_latencies = sorted(latencies)
    p95 = sorted_latencies[math.ceil(0.95 * len(sorted_latencies)) - 1] if sorted_latencies else None
    permutation_rows = []
    for group in corpus["permutation_groups"]:
        signatures = [case_signatures.get(case_id) for case_id in group["case_ids"]]
        consistent = all(signature is not None for signature in signatures) and len(set(map(repr, signatures))) == 1
        permutation_rows.append({"group_id": group["id"], "selection_consistent": consistent})
    return {
        "schema": "sideeffect.local_model_explain_selector_diagnostic_report",
        "schema_version": 2,
        "evaluation_status": "development_only_not_a_release_gate",
        "corpus_sha256": corpus_digest,
        "run": run,
        "cases": len(corpus["cases"]),
        "selection_output_contract_valid_count": valid_count,
        "execution_error_count": len(execution_errors),
        "execution_errors": execution_errors,
        "selection_state_consistency_count": consistent_count,
        "selected_required_evidence_label_recall_over_available_labels": (
            selected_required_label_hits / selectable_required_label_count
            if selectable_required_label_count else None
        ),
        "selectable_required_evidence_label_count": selectable_required_label_count,
        "required_evidence_label_unavailable_to_selector_count": unavailable_required_label_count,
        "p95_supplied_case_latency_ms": p95,
        "supplied_case_latency_count": len(latencies),
        "p95_supplied_case_latency_scope": "cases_with_valid_selector_results_only",
        "latency_ms_source": "supplied_in_results_not_independently_measured_by_validator",
        "backend_used_source": "supplied_product_output_not_independently_verified_by_validator",
        "cuda_offload_evidence_verified_automatically": False,
        "permutation_group_count": len(permutation_rows),
        "selection_consistent_permutation_group_count": sum(row["selection_consistent"] for row in permutation_rows),
        "permutation_groups": permutation_rows,
        "available_evidence_labels_verified_automatically": False,
        "evidence_label_recall_is_diagnostic": True,
        "selection_quality_verified_automatically": False,
        "semantic_correctness_verified_automatically": False,
        "report_rows": report_rows,
    }


def _validate_results_v3(
    results: dict[str, Any], corpus: dict[str, Any], corpus_digest: str
) -> dict[str, Any]:
    result_keys = set(results)
    _require(result_keys in (
        {"schema", "schema_version", "corpus_sha256", "run", "cases"},
        {"schema", "schema_version", "corpus_sha256", "run", "cases", "errors"},
    ), "results contain missing or unexpected keys")
    _require(results["schema"] == "sideeffect.local_model_explain_development_results", "unsupported results schema")
    _require(results["schema_version"] == 3, "unsupported results version")
    _require(results["corpus_sha256"] == corpus_digest, "results corpus digest does not match the pinned development corpus")
    rows = results["cases"]
    _require(isinstance(rows, list) and len(rows) <= len(corpus["cases"]), "results cases must be a bounded array")

    # Reuse the unchanged v2 selector validator. V3 adds annotations only; it
    # must not alter the frozen corpus, selector criteria, or v2 report.
    selector_results = dict(results)
    selector_results["schema_version"] = 2
    selector_results["cases"] = []
    case_reviews: dict[str, dict[str, dict[str, Any]]] = {}
    for index, row in enumerate(rows):
        row = _exact_keys(
            row,
            {
                "case_id", "review_target_sha256", "preview_request_sha256", "response",
                "source_parse_status", "backend_used", "available_evidence", "latency_ms", "human_reviews",
            },
            f"results.cases[{index}]",
        )
        selector_results["cases"].append({
            key: value for key, value in row.items()
            if key not in {"human_reviews", "review_target_sha256", "preview_request_sha256"}
        })

    # Validate all model-controlled selector fields before using their values
    # in human-review validation or set operations.
    report = _validate_results_v2(selector_results, corpus, corpus_digest)
    review_target_digests = {row["case_id"]: row["review_target_sha256"] for row in rows}
    preview_request_digests = {row["case_id"]: row["preview_request_sha256"] for row in rows}
    corpus_by_id = {case["id"]: case for case in corpus["cases"]}
    for row in rows:
        case_id = row["case_id"]
        target_digest = row["review_target_sha256"]
        _require(
            isinstance(target_digest, str) and re.fullmatch(r"[0-9a-f]{64}", target_digest) is not None,
            f"review_target_sha256 must be 64 lowercase hexadecimal characters in case {case_id}",
        )
        preview_digest = row["preview_request_sha256"]
        _require(
            isinstance(preview_digest, str) and re.fullmatch(r"[0-9a-f]{64}", preview_digest) is not None,
            f"preview_request_sha256 must be 64 lowercase hexadecimal characters in case {case_id}",
        )
        expected_target_digest = _review_target_sha256(row, corpus_by_id[case_id]["question"], corpus_digest)
        _require(target_digest == expected_target_digest, f"review target digest mismatch in case {case_id}")
        reviews = row["human_reviews"]
        _require(
            isinstance(reviews, list) and len(reviews) <= MAX_REVIEWERS_PER_CASE,
            f"human_reviews must be a bounded array in case {case_id}",
        )
        by_reviewer: dict[str, dict[str, Any]] = {}
        selected_ids = row["response"].get("evidence_ids") if isinstance(row["response"], dict) else None
        _require(isinstance(selected_ids, list), f"selector response is malformed in case {case_id}")
        selected_set = set(selected_ids)
        for review_index, review in enumerate(reviews):
            label = f"human_reviews[{review_index}] in case {case_id}"
            review = _exact_keys(
                review,
                {
                    "reviewer_id", "review_target_sha256", "preview_request_sha256",
                    "blind_to_model_identity", "independence_attested",
                    "answerability", "required_evidence_labels", "selected_evidence_judgments",
                },
                label,
            )
            reviewer_target_digest = review["review_target_sha256"]
            _require(
                isinstance(reviewer_target_digest, str)
                and re.fullmatch(r"[0-9a-f]{64}", reviewer_target_digest) is not None,
                f"review_target_sha256 must be 64 lowercase hexadecimal characters for reviewer in case {case_id}",
            )
            _require(
                reviewer_target_digest == target_digest,
                f"reviewer target digest mismatch in case {case_id}",
            )
            reviewer_preview_digest = review["preview_request_sha256"]
            _require(
                isinstance(reviewer_preview_digest, str)
                and re.fullmatch(r"[0-9a-f]{64}", reviewer_preview_digest) is not None,
                f"preview_request_sha256 must be 64 lowercase hexadecimal characters for reviewer in case {case_id}",
            )
            _require(
                reviewer_preview_digest == preview_digest,
                f"reviewer preview digest mismatch in case {case_id}",
            )
            reviewer_id = _bounded_string(review["reviewer_id"], f"reviewer_id in case {case_id}", MAX_REVIEWER_ID_BYTES)
            _require(REVIEWER_ID_PATTERN.fullmatch(reviewer_id) is not None, f"reviewer_id has an invalid format in case {case_id}")
            _require(reviewer_id not in by_reviewer, f"duplicate reviewer_id in case {case_id}")
            _require(type(review["blind_to_model_identity"]) is bool, f"blind_to_model_identity must be boolean in case {case_id}")
            _require(type(review["independence_attested"]) is bool, f"independence_attested must be boolean in case {case_id}")
            answerability = review["answerability"]
            _require(
                isinstance(answerability, str) and answerability in ANSWERABILITY_VALUES,
                f"invalid human answerability in case {case_id}",
            )
            required_labels = _labels(review["required_evidence_labels"], f"human required labels in case {case_id}")
            _require(len(required_labels) <= MAX_REVIEW_LABELS, f"too many human required labels in case {case_id}")
            judgments = review["selected_evidence_judgments"]
            _require(
                isinstance(judgments, list) and len(judgments) <= MAX_SELECTED_EVIDENCE_IDS,
                f"selected_evidence_judgments must be a bounded array in case {case_id}",
            )
            judged_ids: set[str] = set()
            supported_labels: set[str] = set()
            unsupported_inference_count = 0
            for judgment_index, judgment in enumerate(judgments):
                judgment = _exact_keys(
                    judgment,
                    {"evidence_id", "supported_required_evidence_labels", "unsupported_inference"},
                    f"evidence judgment {judgment_index} in case {case_id}",
                )
                evidence_id = judgment["evidence_id"]
                _require(
                    isinstance(evidence_id, str) and EVIDENCE_ID_PATTERN.fullmatch(evidence_id) is not None,
                    f"invalid reviewed evidence ID in case {case_id}",
                )
                _require(evidence_id in selected_set, f"human review references an unselected evidence ID in case {case_id}")
                _require(evidence_id not in judged_ids, f"duplicate reviewed evidence ID in case {case_id}")
                judged_ids.add(evidence_id)
                supported = _labels(
                    judgment["supported_required_evidence_labels"],
                    f"reviewed supported labels in case {case_id}",
                )
                _require(
                    set(supported).issubset(required_labels),
                    f"reviewed supported labels must be required labels in case {case_id}",
                )
                supported_labels.update(supported)
                _require(type(judgment["unsupported_inference"]) is bool, f"unsupported_inference must be boolean in case {case_id}")
                unsupported_inference_count += int(judgment["unsupported_inference"])
            _require(judged_ids == selected_set, f"human review must assess every selected evidence ID in case {case_id}")
            by_reviewer[reviewer_id] = {
                "reviewer_id": reviewer_id,
                "blind_to_model_identity": review["blind_to_model_identity"],
                "independence_attested": review["independence_attested"],
                "answerability": answerability,
                "selection_status": row["response"]["selection_status"],
                "required_labels": set(required_labels),
                "covered_labels": supported_labels,
                "unsupported_inference_count": unsupported_inference_count,
                "review_target_sha256": target_digest,
                "preview_request_sha256": preview_digest,
            }
        case_reviews[case_id] = by_reviewer

    reviewer_ids = sorted({reviewer_id for reviews in case_reviews.values() for reviewer_id in reviews})
    reviewer_reports: list[dict[str, Any]] = []
    complete_reviewers: list[str] = []
    for reviewer_id in reviewer_ids:
        review_rows = [reviews[reviewer_id] for reviews in case_reviews.values() if reviewer_id in reviews]
        full_completion = (
            len(review_rows) == len(corpus["cases"])
            and all(review["blind_to_model_identity"] and review["independence_attested"] for review in review_rows)
            and not report["execution_error_count"]
        )
        if full_completion:
            complete_reviewers.append(reviewer_id)
        required_count = sum(len(review["required_labels"]) for review in review_rows)
        covered_count = sum(len(review["covered_labels"] & review["required_labels"]) for review in review_rows)
        answerability_denominator = 0
        answerability_agreement_count = 0
        answerability_false_positive_count = 0
        answerability_false_negative_count = 0
        answerability_uncertain_count = 0
        for review in review_rows:
            if review["answerability"] == "uncertain":
                answerability_uncertain_count += 1
                continue
            answerability_denominator += 1
            selector_selected = review["selection_status"] != "abstained"
            reviewer_answerable = review["answerability"] == "answerable"
            answerability_agreement_count += int(selector_selected == reviewer_answerable)
            answerability_false_positive_count += int(not reviewer_answerable and selector_selected)
            answerability_false_negative_count += int(reviewer_answerable and not selector_selected)
        pair_count = 0
        exact_coverage = 0
        jaccard_total = 0.0
        answerability_agreement = 0
        for reviews in case_reviews.values():
            own = reviews.get(reviewer_id)
            if own is None:
                continue
            for other_id, other in reviews.items():
                if other_id == reviewer_id:
                    continue
                pair_count += 1
                own_labels = own["required_labels"]
                other_labels = other["required_labels"]
                exact_coverage += int(own_labels == other_labels)
                union = own_labels | other_labels
                jaccard_total += (len(own_labels & other_labels) / len(union)) if union else 1.0
                answerability_agreement += int(own["answerability"] == other["answerability"])
        reviewer_reports.append({
            "reviewer_id": reviewer_id,
            "reviewed_case_count": len(review_rows),
            "review_completion_status": (
                "self_attested_full_completion_not_independently_verified"
                if full_completion else
                "self_attested_review_incomplete_or_unverified"
            ),
            "review_blinding_or_independence_verified_automatically": False,
            "fully_completed_blinded_independent_review": full_completion,
            "required_evidence_label_coverage": (covered_count / required_count) if required_count else None,
            "covered_required_evidence_label_count": covered_count,
            "required_evidence_label_count": required_count,
            "selector_answerability_agreement_count": answerability_agreement_count,
            "selector_answerability_denominator": answerability_denominator,
            "selector_answerability_agreement_rate": (
                answerability_agreement_count / answerability_denominator
                if answerability_denominator else None
            ),
            "selector_answerability_false_positive_count": answerability_false_positive_count,
            "selector_answerability_false_negative_count": answerability_false_negative_count,
            "selector_answerability_uncertain_excluded_count": answerability_uncertain_count,
            "peer_case_comparison_count": pair_count,
            "peer_required_label_exact_agreement_rate": (exact_coverage / pair_count) if pair_count else None,
            "peer_required_label_jaccard_mean": (jaccard_total / pair_count) if pair_count else None,
            "peer_answerability_agreement_rate": (answerability_agreement / pair_count) if pair_count else None,
            "unsupported_inference_count": sum(review["unsupported_inference_count"] for review in review_rows),
        })

    case_review_reports = []
    for case in corpus["cases"]:
        case_id = case["id"]
        reviews = case_reviews.get(case_id, {})
        pairs = [
            (left, right)
            for index, left_id in enumerate(sorted(reviews))
            for right_id in sorted(reviews)[index + 1:]
            for left, right in [(reviews[left_id], reviews[right_id])]
        ]
        case_review_reports.append({
            "case_id": case_id,
            "review_target_sha256": review_target_digests.get(case_id),
            "preview_request_sha256": preview_request_digests.get(case_id),
            "reviewer_count": len(reviews),
            "answerability_agreement_rate": (
                sum(left["answerability"] == right["answerability"] for left, right in pairs) / len(pairs)
                if pairs else None
            ),
            "required_label_exact_agreement_rate": (
                sum(left["required_labels"] == right["required_labels"] for left, right in pairs) / len(pairs)
                if pairs else None
            ),
            "unsupported_inference_count": sum(review["unsupported_inference_count"] for review in reviews.values()),
        })

    report["schema"] = "sideeffect.local_model_explain_selector_human_review_report"
    report["schema_version"] = 3
    report["human_review_gate_status"] = (
        "reviewer_threshold_met_self_attested"
        if len(complete_reviewers) >= 2
        else "not_independently_reviewed"
    )
    report["human_review_gate_status_scope"] = "reviewer_completion_only_not_independent_verification_or_model_quality"
    report["human_review_status_is_self_attested_diagnostic_only"] = True
    report["human_review_gate_reviewer_id_count"] = len(complete_reviewers)
    report["self_attested_full_review_completion_reviewer_id_count"] = len(complete_reviewers)
    report["human_review_identity_or_independence_verified_automatically"] = False
    report["human_review_is_model_quality_gate"] = False
    report["selector_answerability_agreement_is_diagnostic"] = True
    report["selector_answerability_agreement_has_pass_threshold"] = False
    report["human_reviewers"] = reviewer_reports
    report["human_review_cases"] = case_review_reports
    report["semantic_truth_inferred_from_selector_structure"] = False
    return report


def _validate_results(results_path: Path, corpus: dict[str, Any], corpus_digest: str) -> dict[str, Any]:
    raw = _read_regular_file(results_path, MAX_RESULTS_BYTES, "pre-recorded results")
    results = _decode_json(raw, "pre-recorded results")
    _require(isinstance(results, dict), "results must be an object")
    version = results.get("schema_version")
    if version == 1:
        return _validate_results_v1(results, corpus, corpus_digest)
    if version == 2:
        return _validate_results_v2(results, corpus, corpus_digest)
    if version == 3:
        return _validate_results_v3(results, corpus, corpus_digest)
    raise ContractError("unsupported results version")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-corpus", action="store_true", help="validate corpus schema, limits, permutation fixtures, and pinned digests")
    parser.add_argument("--results", type=Path, help="structurally inspect a pre-recorded response set; never runs inference")
    args = parser.parse_args()
    if not args.check_corpus and args.results is None:
        parser.error("select --check-corpus and/or provide --results")
    try:
        corpus, digest = load_corpus()
        if args.results is not None:
            report = _validate_results(args.results, corpus, digest)
            print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        else:
            print(json.dumps({
                "schema": "sideeffect.local_model_explain_corpus_check",
                "schema_version": 1,
                "status": "valid_development_corpus",
                "evaluation_status": corpus["evaluation_status"],
                "cases": len(corpus["cases"]),
                "fixtures": len(corpus["fixtures"]),
                "permutation_groups": len(corpus["permutation_groups"]),
                "corpus_sha256": digest,
                "release_gate_result": "not_run_and_not_claimed",
            }, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    except (ContractError, OSError) as error:
        print(f"local model explanation evaluation error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
