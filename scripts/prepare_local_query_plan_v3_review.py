#!/usr/bin/env python3
"""Prepare a blinded human-review packet for the public Linux query-plan v3 corpus.

Packets contain only questions, the finite plan contract, and blank response
fields. A separate private map joins randomized IDs to the public corpus. The
workflow cannot hide a public corpus from a reviewer with repository access or
establish a hidden holdout, reviewer independence, or model qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from pathlib import Path
from typing import Any

import evaluate_local_query_plan_v3 as evaluator
import run_local_model_explain_corpus as private_files


MAX_PACKET_BYTES = 512 * 1024
MAX_MAP_BYTES = 64 * 1024
SCHEMA = "sideeffect.local_query_plan_v3_blind_review"
MAP_SCHEMA = "sideeffect.local_query_plan_v3_blind_review_private_map"
STATUS = "public_synthetic_development_only_not_a_qualification_holdout"
PLAN_FIELDS = ["decision", "abstain_reason", "entity", "filters", "combine"]
FILTER_FIELDS = sorted(evaluator.v2.FILTER_FIELDS)
PLAN_CONTRACT = {
    "required_keys": PLAN_FIELDS,
    "decision": ["filter", "abstain"],
    "abstain_reason": sorted(evaluator.v2.ABSTAIN_REASONS),
    "entity": ["syscall_result", "process_relation", None],
    "filter_keys": FILTER_FIELDS,
    "combine": "all",
    "rule": "Exact equality; all non-null filters are combined with AND.",
}
INSTRUCTIONS = {
    "task": "Independently translate each question into one supported exact-match query plan.",
    "rules": [
        "Use only explicit information in the question and the finite plan contract.",
        "Do not infer selectors that the question does not specify.",
        "Use decision=filter with at least one non-null predicate, or decision=abstain with no predicates.",
        "For a filter, set abstain_reason to null; for abstention, set entity to null and choose an allowed reason.",
        "Keep all required filter keys and set unused values to null.",
        "Do not inspect expected plans, corpus labels, or model outputs before submitting.",
        "Use a pseudonymous reviewer ID and UTC completion timestamp. Declare independence only if true.",
        "Complete every response plan and rationale; do not change review IDs or omit cases.",
    ],
}
METADATA_CONTRACT = {
    "reviewer_id": "required pseudonymous identifier, 1..64 UTF-8 bytes",
    "reviewed_at_utc": "required ISO-8601 UTC timestamp ending in Z",
    "independence_declaration": "required boolean; true means the reviewer did not inspect expected labels before review",
}


class ReviewPacketError(ValueError):
    """A public corpus or review packet cannot be handled safely."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewPacketError(message)


def _encode(value: Any, label: str, limit: int) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise ReviewPacketError(f"{label} is not strict JSON") from None
    _require(len(raw) <= limit, f"{label} exceeds its byte limit")
    return raw


def _opaque(existing: set[str], prefix: str, suffix_bytes: int) -> str:
    for _ in range(8):
        candidate = prefix + secrets.token_hex(suffix_bytes)
        if candidate not in existing:
            existing.add(candidate)
            return candidate
    raise ReviewPacketError("could not generate unique opaque review identifiers")


def prepare_review(corpus: dict[str, Any], corpus_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    _require(corpus.get("schema_version") == 3 and corpus.get("status") == "public_development",
             "only the registered public query-plan v3 corpus is supported")
    _require(corpus.get("release_quality_evidence") is False,
             "corpus must remain explicitly marked as non-qualification evidence")
    review_ids: set[str] = set()
    mapping_rows: list[dict[str, str]] = []
    packet_cases: list[dict[str, Any]] = []
    for case in corpus["cases"]:
        review_id = _opaque(review_ids, "R-", 12)
        packet_cases.append({
            "review_id": review_id,
            "question": case["question"],
            "review": {"plan": None, "rationale": ""},
        })
        mapping_rows.append({"review_id": review_id, "corpus_case_id": case["id"]})
    secrets.SystemRandom().shuffle(packet_cases)
    secrets.SystemRandom().shuffle(mapping_rows)
    batch_id = _opaque(set(), "B-", 16)
    packet = {
        "schema": SCHEMA,
        "schema_version": 1,
        "review_batch_id": batch_id,
        "evaluation_status": STATUS,
        "corpus_sha256": corpus_sha256,
        "reviewer_instructions": INSTRUCTIONS,
        "supported_plan_schema": PLAN_CONTRACT,
        "reviewer_metadata": {"reviewer_id": "", "reviewed_at_utc": "", "independence_declaration": None},
        "reviewer_metadata_contract": METADATA_CONTRACT,
        "cases": packet_cases,
    }
    mapping = {
        "schema": MAP_SCHEMA,
        "schema_version": 1,
        "review_batch_id": batch_id,
        "corpus_sha256": corpus_sha256,
        "mapping": mapping_rows,
    }
    _encode(packet, "review packet", MAX_PACKET_BYTES)
    _encode(mapping, "private map", MAX_MAP_BYTES)
    return packet, mapping


def _write_outputs(packet_path: Path, map_path: Path, packet: dict[str, Any], mapping: dict[str, Any]) -> None:
    packet_path = packet_path.absolute()
    map_path = map_path.absolute()
    _require(packet_path != map_path, "packet and private map require separate output paths")
    created: list[Path] = []
    try:
        private_files._write_new_private_file(map_path, _encode(mapping, "private map", MAX_MAP_BYTES))
        created.append(map_path)
        private_files._write_new_private_file(packet_path, _encode(packet, "review packet", MAX_PACKET_BYTES))
        created.append(packet_path)
    except (OSError, ValueError):
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewer-packet", required=True, type=Path)
    parser.add_argument("--private-map", required=True, type=Path,
                        help="keep this ID-to-case map private and separate from the reviewer packet")
    args = parser.parse_args()
    try:
        corpus, digest, _fixtures = evaluator._load_corpus(evaluator.CORPUS_PATH)
        packet, mapping = prepare_review(corpus, digest)
        _write_outputs(args.reviewer_packet, args.private_map, packet, mapping)
        print("Wrote private reviewer packet and map; review remains unverified and is not qualification evidence.")
        return 0
    except (ReviewPacketError, ValueError, OSError, TypeError) as error:
        print(f"Query-plan review preparation failed: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
