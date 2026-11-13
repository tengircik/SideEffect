#!/usr/bin/env python3
"""Validate and aggregate self-attested reviews for the public ETW dev corpus.

This tool checks completed packet structure, exact packet-to-private-map joins,
and reviewer consistency. It writes aggregate-only diagnostics; it cannot prove
reviewer identity, independence, blinding, label truth, or model qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import evaluate_local_model_windows_etw_query as evaluator
import prepare_local_model_windows_etw_query_review as packet_tool
import run_local_model_windows_etw_query_corpus as corpus_runner
import run_local_model_explain_corpus as private_files


MAX_PACKET_BYTES = packet_tool.MAX_REVIEW_PACKET_BYTES
MAX_MAP_BYTES = packet_tool.MAX_PRIVATE_MAP_BYTES
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 200_000
MAX_REVIEWERS = 8
REVIEW_ID_PATTERN = re.compile(r"^R-[0-9a-f]{24}$")
SOURCE_ID_PATTERN = re.compile(r"^S-[0-9a-f]{24}$")
BATCH_ID_PATTERN = re.compile(r"^B-[0-9a-f]{32}$")
PRIVATE_MAP_SCHEMA = "sideeffect.windows_etw_query_blind_review_private_map"
PLAN_RESPONSE_KEYS = {"review_id", "decision", "abstain_reason", "filters", "rationale"}
PACKET_CASE_KEYS = {
    "review_id", "question", "source_id", "source_status", "queryable_facts", "review",
}


class ReviewValidationError(ValueError):
    """A returned review packet or its private map violates the contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewValidationError(message)


def _exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == keys, f"{label} has missing or unknown fields")
    return value


def _check_json_bounds(raw: bytes) -> None:
    depth = 0
    nodes = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
                nodes += 1
        elif byte == ord('"'):
            in_string = True
        elif byte in (ord("{"), ord("[")):
            depth += 1
            nodes += 1
            _require(depth <= MAX_JSON_DEPTH, "review JSON exceeds its nesting limit")
        elif byte in (ord("}"), ord("]")):
            depth -= 1
            _require(depth >= 0, "review JSON structure is malformed")
        elif byte in (ord(","), ord(":")):
            nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ReviewValidationError("review JSON exceeds its node limit")


def _decode_file(path: Path, limit: int, label: str) -> tuple[dict[str, Any], int]:
    try:
        raw = evaluator._read_regular_file(path, limit, label)
        _check_json_bounds(raw)
        value = evaluator._decode(raw, label)
    except (evaluator.ContractError, OSError, UnicodeError, ValueError, RecursionError):
        raise ReviewValidationError(f"cannot read a bounded regular {label}") from None
    _require(isinstance(value, dict), f"{label} must be a JSON object")
    return value, len(raw)


def _canonical(value: Any, label: str, limit: int) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise ReviewValidationError(f"{label} is not strict JSON") from None
    _require(len(raw) <= limit, f"{label} exceeds its byte limit")
    return raw


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0


def _validate_reviewer_metadata(packet: dict[str, Any]) -> str:
    metadata = _exact_keys(
        packet.get("reviewer_metadata"),
        {"reviewer_id", "reviewed_at_utc", "independence_declaration"},
        "reviewer metadata",
    )
    reviewer_id = metadata["reviewer_id"]
    _require(isinstance(reviewer_id, str) and 0 < len(reviewer_id.encode("utf-8")) <= 64
             and all(character.isprintable() for character in reviewer_id),
             "reviewer identifier is invalid")
    _require(_valid_timestamp(metadata["reviewed_at_utc"]), "review timestamp must be ISO-8601 UTC ending in Z")
    _require(metadata["independence_declaration"] is True,
             "reviewer must self-declare independence for this diagnostic")
    return reviewer_id


def _load_fixture(case: dict[str, Any], fixture_manifest: dict[str, dict[str, Any]]) -> tuple[bytes, dict[str, Any]]:
    name = case["fixture"]
    manifest = fixture_manifest.get(name)
    _require(isinstance(manifest, dict), "corpus fixture manifest is missing")
    try:
        raw = evaluator._read_regular_file(
            evaluator.FIXTURE_DIRECTORY / name, evaluator.MAX_FIXTURE_BYTES, "pinned synthetic ETW fixture",
        )
    except (evaluator.ContractError, OSError, ValueError):
        raise ReviewValidationError("cannot read a pinned synthetic fixture") from None
    _require(len(raw) == manifest["size_bytes"] and hashlib.sha256(raw).hexdigest() == manifest["sha256"],
             "synthetic fixture differs from the validated corpus pin")
    try:
        capture = evaluator._decode(raw, "pinned synthetic ETW fixture")
    except (evaluator.ContractError, UnicodeError, ValueError):
        raise ReviewValidationError("pinned synthetic fixture is invalid") from None
    return raw, capture


def _validate_map(
    mapping: dict[str, Any], corpus: dict[str, Any], corpus_sha256: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    _exact_keys(mapping, {"schema", "schema_version", "review_batch_id", "corpus_sha256", "mapping"},
                "private map")
    _require(mapping.get("schema") == PRIVATE_MAP_SCHEMA and mapping.get("schema_version") == 1,
             "private map schema is unsupported")
    _require(mapping.get("corpus_sha256") == corpus_sha256, "private map references a different corpus")
    batch_id = mapping.get("review_batch_id")
    _require(isinstance(batch_id, str) and BATCH_ID_PATTERN.fullmatch(batch_id) is not None,
             "private map review batch identity is invalid")

    corpus_cases = {case["id"]: case for case in corpus["cases"]}
    fixtures = {row["path"]: row for row in corpus["fixtures"]}
    rows = mapping.get("mapping")
    _require(isinstance(rows, list) and len(rows) == len(corpus_cases), "private map case count is invalid")
    by_review_id: dict[str, dict[str, Any]] = {}
    by_case_id: dict[str, dict[str, Any]] = {}
    source_by_fixture: dict[str, str] = {}
    fixture_by_source: dict[str, str] = {}
    for row in rows:
        _exact_keys(row, {"review_id", "corpus_case_id", "source_id", "fixture_path", "fixture_sha256"},
                    "private map row")
        review_id, case_id, source_id = row["review_id"], row["corpus_case_id"], row["source_id"]
        _require(isinstance(review_id, str) and REVIEW_ID_PATTERN.fullmatch(review_id) is not None
                 and review_id not in by_review_id, "private map has an invalid or duplicate review ID")
        _require(isinstance(case_id, str) and case_id in corpus_cases and case_id not in by_case_id,
                 "private map has an invalid or duplicate corpus case")
        _require(isinstance(source_id, str) and SOURCE_ID_PATTERN.fullmatch(source_id) is not None,
                 "private map has an invalid source ID")
        case = corpus_cases[case_id]
        fixture_name = row["fixture_path"]
        fixture_manifest = fixtures.get(case["fixture"])
        _require(fixture_name == case["fixture"] and isinstance(fixture_manifest, dict)
                 and row["fixture_sha256"] == fixture_manifest["sha256"],
                 "private map fixture does not match the pinned corpus")
        _require(isinstance(row["fixture_sha256"], str)
                 and evaluator.SHA256_PATTERN.fullmatch(row["fixture_sha256"]) is not None,
                 "private map fixture digest is malformed")
        previous_source = source_by_fixture.setdefault(fixture_name, source_id)
        previous_fixture = fixture_by_source.setdefault(source_id, fixture_name)
        _require(previous_source == source_id and previous_fixture == fixture_name,
                 "private map source IDs do not correspond one-to-one with fixtures")
        by_review_id[review_id] = row
        by_case_id[case_id] = row
    _require(set(by_case_id) == set(corpus_cases), "private map does not cover the exact corpus case set")
    return by_review_id, by_case_id


def _validate_packet(
    packet: dict[str, Any], map_value: dict[str, Any], by_review_id: dict[str, dict[str, Any]],
    corpus: dict[str, Any], captures: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, dict[str, Any]]]:
    _exact_keys(packet, {
        "schema", "schema_version", "review_batch_id", "evaluation_status", "reviewer_instructions",
        "supported_plan_schema", "reviewer_metadata", "reviewer_metadata_contract", "cases",
    }, "review packet")
    _require(packet.get("schema") == packet_tool.REVIEW_SCHEMA
             and packet.get("schema_version") == packet_tool.REVIEW_SCHEMA_VERSION,
             "review packet schema is unsupported")
    _require(packet.get("review_batch_id") == map_value["review_batch_id"],
             "review packet and private map batch IDs differ")
    _require(packet.get("evaluation_status") == packet_tool.REVIEW_EVALUATION_STATUS,
             "review packet status was changed")
    _require(packet.get("reviewer_instructions") == {
        "task": packet_tool.REVIEWER_TASK, "rules": packet_tool.REVIEWER_RULES,
    }, "review packet instructions were changed")
    _require(packet.get("supported_plan_schema") == packet_tool.SUPPORTED_PLAN_SCHEMA,
             "review packet plan schema was changed")
    _require(packet.get("reviewer_metadata_contract") == packet_tool.REVIEWER_METADATA_CONTRACT,
             "review packet reviewer contract was changed")
    reviewer_id = _validate_reviewer_metadata(packet)

    packet_cases = packet.get("cases")
    _require(isinstance(packet_cases, list) and len(packet_cases) == len(by_review_id),
             "review packet case count is invalid")
    corpus_cases = {case["id"]: case for case in corpus["cases"]}
    output_by_case: dict[str, dict[str, Any]] = {}
    seen_review_ids: set[str] = set()
    for packet_case in packet_cases:
        _exact_keys(packet_case, PACKET_CASE_KEYS, "review packet case")
        review_id = packet_case.get("review_id")
        _require(isinstance(review_id, str) and review_id in by_review_id and review_id not in seen_review_ids,
                 "review packet has an unknown or duplicate review ID")
        seen_review_ids.add(review_id)
        mapped = by_review_id[review_id]
        case_id = mapped["corpus_case_id"]
        corpus_case = corpus_cases[case_id]
        fixture_name = corpus_case["fixture"]
        capture = captures[fixture_name]
        facts = packet_tool._review_facts(capture)
        expected_status = {
            "capture_completeness": capture["capture_completeness"],
            "collection_status": capture["collection_status"],
            "queryable_fact_count": len(facts),
        }
        _require(packet_case.get("question") == corpus_case["question"]
                 and packet_case.get("source_id") == mapped["source_id"]
                 and packet_case.get("source_status") == expected_status
                 and packet_case.get("queryable_facts") == facts,
                 "review packet facts or case mapping differ from the pinned corpus")

        review = _exact_keys(packet_case.get("review"), PLAN_RESPONSE_KEYS, "review response")
        _require(review.get("review_id") == review_id, "review response ID differs from its case")
        plan = {
            "decision": review.get("decision"),
            "abstain_reason": review.get("abstain_reason"),
            "filters": review.get("filters"),
        }
        try:
            evaluator._validate_plan(plan, case_id)
        except (evaluator.ContractError, UnicodeError, ValueError, TypeError):
            raise ReviewValidationError("review response plan is invalid") from None
        rationale = review.get("rationale")
        _require(isinstance(rationale, str) and 0 < len(rationale.encode("utf-8")) <= packet_tool.MAX_RATIONALE_BYTES
                 and rationale.strip() and all(character.isprintable() or character in "\r\n\t" for character in rationale),
                 "review rationale is empty, oversized, or contains unsupported controls")
        matched = evaluator._matched_ordinals(evaluator._capture_facts(capture), plan)
        expected_ordinals = corpus_case["expected_record_ordinals"]
        selected_rows = corpus_runner._matched_rows(facts, plan)
        semantic_rows = [
            {key: value for key, value in fact.items() if key not in {"evidence_id", "record_ordinal"}}
            for fact in selected_rows
        ]
        semantic_rows.sort(key=lambda row: _canonical(row, "selected fact", MAX_PACKET_BYTES))
        output_by_case[case_id] = {
            "decision": plan["decision"],
            "plan_exact": plan == corpus_case["expected_plan"],
            "plan_sha256": hashlib.sha256(_canonical(plan, "review plan", 16 * 1024)).hexdigest(),
            "matched_ordinals_exact": matched == expected_ordinals,
            "semantic_facts_sha256": hashlib.sha256(_canonical(semantic_rows, "semantic matches", MAX_PACKET_BYTES)).hexdigest(),
        }
    _require(seen_review_ids == set(by_review_id), "review packet omits one or more mapped cases")
    return reviewer_id, output_by_case


def validate_reviews(pairs: list[tuple[Path, Path]]) -> dict[str, Any]:
    _require(2 <= len(pairs) <= MAX_REVIEWERS, "provide two through eight completed reviewer packet/map pairs")
    resolved_inputs: set[Path] = set()
    loaded: list[tuple[dict[str, Any], dict[str, Any]]] = []
    total_bytes = 0
    for packet_path, map_path in pairs:
        try:
            packet_resolved = packet_path.resolve(strict=True)
            map_resolved = map_path.resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            raise ReviewValidationError("a review input path could not be resolved") from None
        _require(packet_resolved != map_resolved and packet_resolved not in resolved_inputs
                 and map_resolved not in resolved_inputs, "review inputs must be distinct files")
        resolved_inputs.update((packet_resolved, map_resolved))
        packet, packet_size = _decode_file(packet_path, MAX_PACKET_BYTES, "review packet")
        mapping, map_size = _decode_file(map_path, MAX_MAP_BYTES, "private map")
        total_bytes += packet_size + map_size
        _require(total_bytes <= MAX_INPUT_BYTES, "aggregate review inputs exceed their byte limit")
        loaded.append((packet, mapping))

    corpus, corpus_sha256, _summary = evaluator.load_corpus()
    fixture_manifest = {row["path"]: row for row in corpus["fixtures"]}
    captures: dict[str, dict[str, Any]] = {}
    for case in corpus["cases"]:
        fixture_name = case["fixture"]
        if fixture_name not in captures:
            _, captures[fixture_name] = _load_fixture(case, fixture_manifest)

    reviewers: list[dict[str, Any]] = []
    reviewer_ids: set[str] = set()
    batch_ids: set[str] = set()
    for index, (packet, mapping) in enumerate(loaded, start=1):
        map_by_review_id, _map_by_case_id = _validate_map(mapping, corpus, corpus_sha256)
        batch_id = packet.get("review_batch_id")
        _require(isinstance(batch_id, str) and BATCH_ID_PATTERN.fullmatch(batch_id) is not None
                 and batch_id not in batch_ids, "review batches must be distinct and valid")
        batch_ids.add(batch_id)
        reviewer_id, responses = _validate_packet(packet, mapping, map_by_review_id, corpus, captures)
        _require(reviewer_id not in reviewer_ids, "reviewer IDs must be distinct")
        reviewer_ids.add(reviewer_id)
        cases = {case["id"]: case for case in corpus["cases"]}
        answerable_ids = [case_id for case_id, case in cases.items() if case["behavior"] == "answerable"]
        abstain_ids = [case_id for case_id, case in cases.items() if case["behavior"] == "must_abstain"]
        reviewers.append({
            "responses": responses,
            "metrics": {
                "completed_cases": len(responses),
                "public_oracle_exact_plan_alignment_diagnostic": sum(responses[key]["plan_exact"] for key in responses),
                "public_oracle_exact_result_alignment_diagnostic": sum(responses[key]["matched_ordinals_exact"] for key in responses),
                "answerable_cases_abstained_diagnostic": sum(responses[key]["decision"] == "abstain" for key in answerable_ids),
                "must_abstain_cases_filtered_diagnostic": sum(responses[key]["decision"] == "filter" for key in abstain_ids),
            },
        })

    response_maps = [reviewer["responses"] for reviewer in reviewers]
    pairwise_decision_matches = 0
    pairwise_plan_matches = 0
    pairwise_result_matches = 0
    pairwise_case_total = 0
    pair_count = 0
    for left_index in range(len(response_maps)):
        for right_index in range(left_index + 1, len(response_maps)):
            left, right = response_maps[left_index], response_maps[right_index]
            _require(set(left) == set(right), "reviewers did not cover the same corpus cases")
            pair_count += 1
            pairwise_case_total += len(left)
            pairwise_decision_matches += sum(left[case_id]["decision"] == right[case_id]["decision"] for case_id in left)
            pairwise_plan_matches += sum(left[case_id]["plan_sha256"] == right[case_id]["plan_sha256"]
                                         for case_id in left)
            pairwise_result_matches += sum(left[case_id]["semantic_facts_sha256"]
                                           == right[case_id]["semantic_facts_sha256"] for case_id in left)

    report = {
        "schema": "sideeffect.windows_etw_query_review_adjudication_diagnostic",
        "schema_version": 1,
        "corpus_sha256": corpus_sha256,
        "reviewer_count": len(reviewers),
        "case_count_per_reviewer": len(corpus["cases"]),
        "independence_declarations": "self_attested_not_independently_verified",
        "label_truth": "not_established",
        "qualification_result": "not_assessed",
        "semantic_quality_assessed": False,
        "hidden_holdout": False,
        "public_oracle_alignment_is_diagnostic_only": True,
        "per_reviewer": [reviewer["metrics"] for reviewer in reviewers],
        "pairwise_agreement": {
            "reviewer_pairs": pair_count,
            "case_comparisons": pairwise_case_total,
            "decision_agreement_cases": pairwise_decision_matches,
            "decision_agreement_total": pairwise_case_total,
            "exact_plan_agreement_cases": pairwise_plan_matches,
            "exact_plan_agreement_total": pairwise_case_total,
            "semantic_match_agreement_cases": pairwise_result_matches,
            "semantic_match_agreement_total": pairwise_case_total,
        },
    }
    _canonical(report, "aggregate report", MAX_REPORT_BYTES)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-pair", required=True, action="append", nargs=2, metavar=("PACKET", "PRIVATE_MAP"),
                        help="completed reviewer packet and its separate private mapping; provide at least two pairs")
    parser.add_argument("--output", required=True, type=Path,
                        help="new private aggregate-only report; existing files are never replaced")
    args = parser.parse_args()
    try:
        pairs = [(Path(packet), Path(mapping)) for packet, mapping in args.review_pair]
        output_path = args.output.absolute().resolve(strict=False)
        for packet_path, mapping_path in pairs:
            _require(output_path != packet_path.absolute().resolve(strict=False)
                     and output_path != mapping_path.absolute().resolve(strict=False),
                     "report output must not replace an input")
        report = validate_reviews(pairs)
        private_files._write_new_private_file(
            args.output, _canonical(report, "aggregate report", MAX_REPORT_BYTES),
        )
        print("Wrote private review-consensus diagnostics; independence, label truth, and model qualification remain unverified.")
        return 0
    except (ReviewValidationError, evaluator.ContractError, OSError, UnicodeError, ValueError, TypeError) as error:
        print(f"ETW query review validation failed: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
