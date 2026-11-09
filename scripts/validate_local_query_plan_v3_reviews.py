#!/usr/bin/env python3
"""Validate and compare returned reviews for the public Linux query-plan v3 corpus.

The private aggregate report contains no reviewer IDs, questions, plans,
rationales, case IDs, or per-case rows. Agreement and oracle alignment are
diagnostics only; this public corpus is not a hidden holdout or qualification.
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

import evaluate_local_query_plan as query
import evaluate_local_query_plan_v3 as evaluator
import prepare_local_query_plan_v3_review as packet_tool
import run_local_model_explain_corpus as private_files


MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024
MAX_FACT_BYTES = 16 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 200_000
MAX_REVIEWERS = 8
REVIEW_ID = re.compile(r"^R-[0-9a-f]{24}$")
BATCH_ID = re.compile(r"^B-[0-9a-f]{32}$")
PACKET_CASE_KEYS = {"review_id", "question", "review"}
REVIEW_KEYS = {"plan", "rationale"}


class ReviewValidationError(ValueError):
    """A review packet or private map violates the bounded contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewValidationError(message)


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == keys, f"{label} has missing or unknown fields")
    return value


def _json_bounds(raw: bytes) -> None:
    depth = 0
    nodes = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                in_string = False
                nodes += 1
        elif byte == 34:
            in_string = True
        elif byte in (91, 123):
            depth += 1
            nodes += 1
            _require(depth <= MAX_JSON_DEPTH, "review JSON exceeds its nesting limit")
        elif byte in (93, 125):
            depth -= 1
            _require(depth >= 0, "review JSON structure is malformed")
        elif byte in (44, 58):
            nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ReviewValidationError("review JSON exceeds its node limit")


def _decode(path: Path, limit: int, label: str) -> tuple[dict[str, Any], int]:
    try:
        raw = evaluator._read_regular_nofollow(path, limit, label)
        _json_bounds(raw)
        value = query._strict_json_loads(raw, label)
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise ReviewValidationError(f"cannot read a bounded regular {label}") from None
    _require(isinstance(value, dict), f"{label} must be a JSON object")
    return value, len(raw)


def _encode(value: Any, label: str, limit: int) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise ReviewValidationError(f"{label} is not strict JSON") from None
    _require(len(raw) <= limit, f"{label} exceeds its byte limit")
    return raw


def _timestamp(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 64 or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0


def _validate_map(mapping: dict[str, Any], corpus: dict[str, Any], corpus_digest: str) -> dict[str, dict[str, str]]:
    _exact(mapping, {"schema", "schema_version", "review_batch_id", "corpus_sha256", "mapping"}, "private map")
    _require(mapping.get("schema") == packet_tool.MAP_SCHEMA and mapping.get("schema_version") == 1,
             "private map schema is unsupported")
    _require(mapping.get("corpus_sha256") == corpus_digest, "private map references a different corpus")
    _require(isinstance(mapping.get("review_batch_id"), str)
             and BATCH_ID.fullmatch(mapping["review_batch_id"]) is not None, "private map batch ID is invalid")
    cases = {case["id"] for case in corpus["cases"]}
    rows = mapping.get("mapping")
    _require(isinstance(rows, list) and len(rows) == len(cases), "private map case count is invalid")
    by_review: dict[str, dict[str, str]] = {}
    by_case: set[str] = set()
    for row in rows:
        _exact(row, {"review_id", "corpus_case_id"}, "private map row")
        review_id, case_id = row["review_id"], row["corpus_case_id"]
        _require(isinstance(review_id, str) and REVIEW_ID.fullmatch(review_id) is not None
                 and review_id not in by_review, "private map has invalid or duplicate review IDs")
        _require(isinstance(case_id, str) and case_id in cases and case_id not in by_case,
                 "private map has invalid or duplicate corpus cases")
        by_review[review_id] = row
        by_case.add(case_id)
    _require(by_case == cases, "private map does not cover the exact corpus case set")
    return by_review


def _validate_packet(
    packet: dict[str, Any], mapping: dict[str, Any], by_review: dict[str, dict[str, str]], corpus: dict[str, Any],
) -> tuple[str, dict[str, dict[str, Any]]]:
    _exact(packet, {
        "schema", "schema_version", "review_batch_id", "evaluation_status", "corpus_sha256",
        "reviewer_instructions", "supported_plan_schema", "reviewer_metadata", "reviewer_metadata_contract", "cases",
    }, "review packet")
    _require(packet.get("schema") == packet_tool.SCHEMA and packet.get("schema_version") == 1,
             "review packet schema is unsupported")
    _require(packet.get("review_batch_id") == mapping["review_batch_id"]
             and packet.get("corpus_sha256") == mapping["corpus_sha256"], "packet and map bindings differ")
    _require(packet.get("evaluation_status") == packet_tool.STATUS
             and packet.get("reviewer_instructions") == packet_tool.INSTRUCTIONS
             and packet.get("supported_plan_schema") == packet_tool.PLAN_CONTRACT
             and packet.get("reviewer_metadata_contract") == packet_tool.METADATA_CONTRACT,
             "review instructions or contract were changed")
    metadata = _exact(packet.get("reviewer_metadata"),
                      {"reviewer_id", "reviewed_at_utc", "independence_declaration"}, "reviewer metadata")
    reviewer_id = metadata.get("reviewer_id")
    _require(isinstance(reviewer_id, str) and 0 < len(reviewer_id.encode("utf-8")) <= 64
             and all(char.isprintable() for char in reviewer_id), "reviewer ID is invalid")
    _require(_timestamp(metadata.get("reviewed_at_utc")), "review timestamp must be ISO-8601 UTC ending in Z")
    _require(metadata.get("independence_declaration") is True,
             "reviewer must self-declare independence for this diagnostic")
    cases = {case["id"]: case for case in corpus["cases"]}
    packet_cases = packet.get("cases")
    _require(isinstance(packet_cases, list) and len(packet_cases) == len(by_review),
             "review packet case count is invalid")
    responses: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    for packet_case in packet_cases:
        _exact(packet_case, PACKET_CASE_KEYS, "packet case")
        review_id = packet_case.get("review_id")
        _require(isinstance(review_id, str) and review_id in by_review and review_id not in seen,
                 "packet has an unknown or duplicate review ID")
        seen.add(review_id)
        corpus_case = cases[by_review[review_id]["corpus_case_id"]]
        _require(packet_case.get("question") == corpus_case["question"], "packet question does not match its map")
        review = _exact(packet_case.get("review"), REVIEW_KEYS, "review response")
        plan = review.get("plan")
        try:
            query.validate_plan(plan)
        except (ValueError, TypeError, UnicodeError):
            raise ReviewValidationError("review response contains an invalid query plan") from None
        rationale = review.get("rationale")
        _require(isinstance(rationale, str) and 0 < len(rationale.encode("utf-8")) <= 2048
                 and rationale.strip() and all(char.isprintable() or char in "\r\n\t" for char in rationale),
                 "review rationale is empty, oversized, or contains unsupported controls")
        exact = plan == corpus_case["expected_plan"]
        responses[corpus_case["id"]] = {
            "plan": plan,
            "plan_exact": exact,
            "decision": plan["decision"],
        }
    _require(seen == set(by_review), "packet omits one or more mapped cases")
    return reviewer_id, responses


def _matched_semantic_rows(
    plan: dict[str, Any], case_id: str, corpus_cases: dict[str, dict[str, Any]],
    fixture_rows: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    if plan["decision"] == "abstain":
        return []
    rows = fixture_rows[corpus_cases[case_id]["evaluation_fixture"]]
    return [
        {key: value for key, value in row.items() if key != "line"}
        for row in rows
        if ("child_pid" in row) == (plan["entity"] == "process_relation")
        and all(value is None or row.get(key) == value for key, value in plan["filters"].items())
    ]


def validate_reviews(pairs: list[tuple[Path, Path]]) -> dict[str, Any]:
    _require(2 <= len(pairs) <= MAX_REVIEWERS, "provide two through eight reviewer packet/map pairs")
    corpus, corpus_digest, fixtures = evaluator._load_corpus(evaluator.CORPUS_PATH)
    inputs: set[Path] = set()
    loaded: list[tuple[dict[str, Any], dict[str, Any]]] = []
    total = 0
    for packet_path, map_path in pairs:
        try:
            packet_real = packet_path.resolve(strict=True)
            map_real = map_path.resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            raise ReviewValidationError("a review input path could not be resolved") from None
        _require(packet_real != map_real and packet_real not in inputs and map_real not in inputs,
                 "review inputs must be distinct files")
        inputs.update((packet_real, map_real))
        packet, packet_size = _decode(packet_path, packet_tool.MAX_PACKET_BYTES, "review packet")
        mapping, map_size = _decode(map_path, packet_tool.MAX_MAP_BYTES, "private map")
        total += packet_size + map_size
        _require(total <= MAX_INPUT_BYTES, "aggregate review inputs exceed their byte limit")
        loaded.append((packet, mapping))

    by_case = {case["id"]: case for case in corpus["cases"]}
    fixture_rows = {
        name: evaluator.v3_validator.parse_trace(raw, name, corpus["limits"])
        for name, raw in fixtures.items()
    }
    reviewer_ids: set[str] = set()
    batch_ids: set[str] = set()
    reviewers: list[dict[str, Any]] = []
    for packet, mapping in loaded:
        by_review = _validate_map(mapping, corpus, corpus_digest)
        batch = packet.get("review_batch_id")
        _require(isinstance(batch, str) and BATCH_ID.fullmatch(batch) is not None and batch not in batch_ids,
                 "review batches must be distinct and valid")
        batch_ids.add(batch)
        reviewer_id, responses = _validate_packet(packet, mapping, by_review, corpus)
        _require(reviewer_id not in reviewer_ids, "reviewer IDs must be distinct")
        reviewer_ids.add(reviewer_id)
        exact = 0
        correct_decision = 0
        false_filter = 0
        for case_id, response in responses.items():
            case = by_case[case_id]
            exact += response["plan_exact"]
            correct_decision += (response["decision"] == case["expected_plan"]["decision"])
            false_filter += (case["behavior"] == "must_abstain" and response["decision"] == "filter")
        reviewers.append({"responses": responses, "metrics": {
            "completed_cases": len(responses),
            "public_oracle_exact_plan_alignment_diagnostic": exact,
            "public_oracle_exact_intent_group_alignment_diagnostic": sum(
                all(responses[case["id"]]["plan"] == case["expected_plan"]
                    for case in corpus["cases"] if case["intent_group"] == group)
                for group in {case["intent_group"] for case in corpus["cases"]}
            ),
            "public_oracle_decision_alignment_diagnostic": correct_decision,
            "must_abstain_false_filter_diagnostic": false_filter,
        }})

    decision_matches = plan_matches = semantic_matches = case_total = pair_count = 0
    group_plan_matches = group_semantic_matches = group_total = 0
    response_maps = [reviewer["responses"] for reviewer in reviewers]
    groups: dict[str, list[str]] = {}
    for case in corpus["cases"]:
        groups.setdefault(case["intent_group"], []).append(case["id"])
    for left_index, left in enumerate(response_maps):
        for right in response_maps[left_index + 1:]:
            _require(set(left) == set(right), "reviewers did not cover the same cases")
            pair_count += 1
            case_total += len(left)
            for case_id in left:
                left_response, right_response = left[case_id], right[case_id]
                decision_matches += left_response["decision"] == right_response["decision"]
                plan_matches += left_response["plan"] == right_response["plan"]
                left_rows = sorted(_encode(row, "matched fact", MAX_FACT_BYTES)
                                   for row in _matched_semantic_rows(left_response["plan"], case_id, by_case, fixture_rows))
                right_rows = sorted(_encode(row, "matched fact", MAX_FACT_BYTES)
                                    for row in _matched_semantic_rows(right_response["plan"], case_id, by_case, fixture_rows))
                semantic_matches += left_rows == right_rows
            group_total += len(groups)
            for group_cases in groups.values():
                exact_group = all(left[case_id]["plan"] == right[case_id]["plan"] for case_id in group_cases)
                semantic_group = all(
                    sorted(_encode(row, "matched fact", MAX_FACT_BYTES)
                           for row in _matched_semantic_rows(left[case_id]["plan"], case_id, by_case, fixture_rows))
                    == sorted(_encode(row, "matched fact", MAX_FACT_BYTES)
                              for row in _matched_semantic_rows(right[case_id]["plan"], case_id, by_case, fixture_rows))
                    for case_id in group_cases
                )
                group_plan_matches += exact_group
                group_semantic_matches += semantic_group

    report = {
        "schema": "sideeffect.local_query_plan_v3_review_agreement_diagnostic",
        "schema_version": 1,
        "corpus_sha256": corpus_digest,
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
            "case_comparisons": case_total,
            "decision_agreement_cases": decision_matches,
            "exact_plan_agreement_cases": plan_matches,
            "semantic_match_agreement_cases": semantic_matches,
            "intent_group_comparisons": group_total,
            "exact_plan_agreement_intent_groups": group_plan_matches,
            "semantic_match_agreement_intent_groups": group_semantic_matches,
        },
    }
    _encode(report, "aggregate report", MAX_REPORT_BYTES)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-pair", required=True, action="append", nargs=2, metavar=("PACKET", "PRIVATE_MAP"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        pairs = [(Path(packet), Path(mapping)) for packet, mapping in args.review_pair]
        output = args.output.resolve(strict=False)
        for packet, mapping in pairs:
            _require(output not in {packet.resolve(strict=False), mapping.resolve(strict=False)},
                     "report output must not replace an input")
        report = validate_reviews(pairs)
        private_files._write_new_private_file(args.output, _encode(report, "aggregate report", MAX_REPORT_BYTES))
        print("Wrote private reviewer-agreement diagnostics; label truth and model qualification remain unverified.")
        return 0
    except (ReviewValidationError, OSError, ValueError, TypeError, UnicodeError) as error:
        print(f"Query-plan review validation failed: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
