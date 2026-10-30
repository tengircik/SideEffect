#!/usr/bin/env python3
"""Validate the development-only corpus and pre-recorded local-model responses.

This tool performs structural, digest, citation-ID, status, and explicitly
human-supplied label checks. It does not judge whether model-authored claims
are true or supported by cited evidence, and it never launches a model.
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
STATUS_VALUES = {"answered", "partial", "abstained"}
ABSTAIN_REASONS = {"ambiguous", "unsupported_scope", "insufficient_evidence"}
STATEMENT_KINDS = {"observation", "interpretation", "uncertainty"}
LABEL_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
EVIDENCE_ID_PATTERN = re.compile(r"^E[0-9]{3}$")


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


def _validate_results(results_path: Path, corpus: dict[str, Any], corpus_digest: str) -> dict[str, Any]:
    raw = _read_regular_file(results_path, MAX_RESULTS_BYTES, "pre-recorded results")
    results = _decode_json(raw, "pre-recorded results")
    _require(isinstance(results, dict), "results must be an object")
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
