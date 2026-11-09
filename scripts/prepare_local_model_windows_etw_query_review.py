#!/usr/bin/env python3
"""Prepare a blinded human label-review packet for the public ETW query corpus.

This tool validates the pinned synthetic corpus, then emits query questions and
only the corresponding corroborated, queryable facts. The expected plans and
expected matching ordinals are kept out of the reviewer packet. A separate
protected map binds opaque review IDs back to corpus cases for a later adjudication step.

It does not establish reviewer independence, hide the public corpus from a
reviewer who can access the repository, create a hidden holdout, execute
SideEffect, or invoke a model/runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from pathlib import Path
from typing import Any

import evaluate_local_model_windows_etw_query as evaluator
import run_local_model_explain_corpus as private_files


MAX_REVIEW_PACKET_BYTES = 4 * 1024 * 1024
MAX_PRIVATE_MAP_BYTES = 64 * 1024
MAX_RATIONALE_BYTES = 2048
REVIEW_SCHEMA = "sideeffect.windows_etw_query_blind_label_review"
REVIEW_SCHEMA_VERSION = 1
QUERYABLE_EVENT_KINDS = sorted(evaluator.EVENT_KINDS)
SUPPORTED_PLAN_SCHEMA = {
    "required_keys": ["decision", "abstain_reason", "filters"],
    "filter_keys": sorted(evaluator.FILTER_KEYS),
    "decision": ["filter", "abstain"],
    "abstain_reason": ["ambiguous", "unsupported_scope", "insufficient_evidence"],
    "combine": "all",
    "max_filters": 4,
    "constraints": [
        "abstain requires one abstain_reason and every filter must be null",
        "filter requires a null abstain_reason and one through four non-null filters",
        "file_operation and path_exact require event_kind=file_io_observation",
        "network_operation, transport, destination_address, destination_port, and payload_process_id require event_kind=network_observation",
        "disk_operation requires event_kind=disk_io_observation",
        "fields from incompatible event kinds cannot be combined",
        "destination_address must be a literal IP address; do not infer hostnames",
        "an exact literal may match zero listed records; zero matches do not establish absence outside this bounded source",
    ],
    "filters": {
        "event_kind": QUERYABLE_EVENT_KINDS,
        "file_operation": sorted(evaluator.FILE_OPERATIONS),
        "network_operation": sorted(evaluator.NETWORK_OPERATIONS),
        "disk_operation": sorted(evaluator.DISK_OPERATIONS),
        "path_exact": "non-empty case-sensitive path literal, at most 4096 UTF-8 bytes and without NUL",
        "transport": ["tcp", "udp"],
        "destination_address": "literal IP address from a corroborated network payload",
        "destination_port": "integer from 0 through 65535",
        "payload_process_id": "integer from 1 through 4294967295, only when present in a corroborated network payload",
    },
}


class ReviewPacketError(ValueError):
    """The bounded review packet cannot be prepared safely."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewPacketError(message)


def _encode(value: Any, label: str, limit: int) -> bytes:
    try:
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ReviewPacketError(f"{label} cannot be serialized as strict JSON: {type(error).__name__}") from None
    _require(len(encoded) <= limit, f"{label} exceeds its {limit}-byte limit")
    return encoded


def _new_id(existing: set[str], prefix: str) -> str:
    for _ in range(8):
        candidate = prefix + secrets.token_hex(12)
        if candidate not in existing:
            existing.add(candidate)
            return candidate
    raise ReviewPacketError("could not generate unique opaque identifiers")


def _review_facts(capture: dict[str, Any]) -> list[dict[str, Any]]:
    facts = evaluator._capture_facts(capture)
    rows: list[dict[str, Any]] = []
    for fact in facts:
        if fact["event_kind"] not in evaluator.EVENT_KINDS:
            continue
        ordinal = fact["record_ordinal"]
        _require(type(ordinal) is int and ordinal > 0, "decoded fixture has an invalid record ordinal")
        rows.append({
            "evidence_id": f"W{ordinal:05}",
            "record_ordinal": ordinal,
            "event_kind": fact["event_kind"],
            "operation": fact["operation"],
            "path": fact["path"],
            "transport": fact["transport"],
            "destination_address": fact["destination_address"],
            "destination_port": fact["destination_port"],
            "payload_process_id": fact["payload_process_id"],
        })
    _require(len(rows) <= evaluator.capture_contract.MAX_CAPTURE_EVENTS, "fixture has too many reviewable facts")
    return rows


def _blank_response(review_id: str) -> dict[str, Any]:
    return {
        "review_id": review_id,
        "decision": None,
        "abstain_reason": None,
        "filters": {name: None for name in sorted(evaluator.FILTER_KEYS)},
        "rationale": "",
    }


def prepare_review(corpus: dict[str, Any], corpus_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    summary = evaluator.validate_corpus(corpus)
    fixture_manifest = {item["path"]: item for item in corpus["fixtures"]}
    review_ids: set[str] = set()
    source_ids: set[str] = set()
    source_by_fixture: dict[str, str] = {}
    packets: list[dict[str, Any]] = []
    mapping_rows: list[dict[str, Any]] = []

    for case in corpus["cases"]:
        fixture_name = case["fixture"]
        raw_fixture = evaluator._read_regular_file(
            evaluator.FIXTURE_DIRECTORY / fixture_name,
            evaluator.MAX_FIXTURE_BYTES,
            "pinned synthetic ETW fixture",
        )
        manifest = fixture_manifest.get(fixture_name)
        _require(
            isinstance(manifest, dict)
            and len(raw_fixture) == manifest["size_bytes"]
            and hashlib.sha256(raw_fixture).hexdigest() == manifest["sha256"],
            "synthetic ETW fixture changed after corpus validation",
        )
        capture = evaluator._decode(raw_fixture, "pinned synthetic ETW fixture")
        source_id = source_by_fixture.get(fixture_name)
        if source_id is None:
            source_id = _new_id(source_ids, "S-")
            source_by_fixture[fixture_name] = source_id
        review_id = _new_id(review_ids, "R-")
        facts = _review_facts(capture)
        packet_case = {
            "review_id": review_id,
            "question": case["question"],
            "source_id": source_id,
            "source_status": {
                "capture_completeness": capture["capture_completeness"],
                "collection_status": capture["collection_status"],
                "queryable_fact_count": len(facts),
            },
            "queryable_facts": facts,
            "review": _blank_response(review_id),
        }
        packets.append(packet_case)
        mapping_rows.append({
            "review_id": review_id,
            "corpus_case_id": case["id"],
            "source_id": source_id,
            "fixture_path": fixture_name,
            "fixture_sha256": next(item["sha256"] for item in corpus["fixtures"] if item["path"] == fixture_name),
        })

    secrets.SystemRandom().shuffle(packets)
    packet = {
        "schema": REVIEW_SCHEMA,
        "schema_version": REVIEW_SCHEMA_VERSION,
        "review_batch_id": "B-" + secrets.token_hex(16),
        "evaluation_status": "public_synthetic_development_only_not_a_qualification_holdout",
        "reviewer_instructions": {
            "task": "Independently translate each English question into one supported exact-match plan over only the listed corroborated facts.",
            "rules": [
                "Do not infer facts that are absent from the listed evidence.",
                "Use only the finite fields and values described by supported_plan_schema.",
                "Use exact equality; multiple filters are combined with AND.",
                "Abstain when the question is ambiguous, unsupported, or cannot be answered from the available scope.",
                "For decision=filter, set abstain_reason to null and provide one through four non-null filters.",
                "For decision=abstain, provide an allowed abstain_reason and leave every filter null.",
                "Do not inspect model outputs or expected labels while preparing this review.",
                "Use a pseudonymous reviewer_id, an ISO-8601 UTC reviewed_at_utc ending in Z, and set independence_declaration true only if you did not inspect expected labels before completing this review.",
                "Complete reviewer_metadata and every case.review object; keep the case order and review IDs unchanged.",
            ],
        },
        "supported_plan_schema": SUPPORTED_PLAN_SCHEMA,
        "reviewer_metadata": {
            "reviewer_id": "",
            "reviewed_at_utc": "",
            "independence_declaration": None,
        },
        "reviewer_metadata_contract": {
            "reviewer_id": "required pseudonymous identifier, 1..64 UTF-8 bytes",
            "reviewed_at_utc": "required ISO-8601 UTC timestamp ending in Z",
            "independence_declaration": "required boolean; true means the reviewer did not inspect expected labels before completing the review",
        },
        "cases": packets,
    }
    mapping = {
        "schema": "sideeffect.windows_etw_query_blind_review_private_map",
        "schema_version": 1,
        "review_batch_id": packet["review_batch_id"],
        "corpus_sha256": corpus_sha256,
        "mapping": mapping_rows,
    }
    _require(len(packets) == summary["cases"], "review packet case count differs from validated corpus")
    return packet, mapping


def _write_outputs(packet_path: Path, mapping_path: Path, packet: dict[str, Any], mapping: dict[str, Any]) -> None:
    packet_absolute = packet_path.absolute()
    mapping_absolute = mapping_path.absolute()
    _require(packet_absolute != mapping_absolute, "reviewer packet and private map must use different paths")
    packet_raw = _encode(packet, "reviewer packet", MAX_REVIEW_PACKET_BYTES)
    mapping_raw = _encode(mapping, "private review map", MAX_PRIVATE_MAP_BYTES)
    created: list[Path] = []
    try:
        private_files._write_new_private_file(mapping_path, mapping_raw)
        created.append(mapping_path)
        private_files._write_new_private_file(packet_path, packet_raw)
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
    parser.add_argument("--reviewer-packet", required=True, type=Path,
                        help="new private reviewer-facing JSON packet; existing files are never replaced")
    parser.add_argument("--private-map", required=True, type=Path,
                        help="separate new private ID-to-corpus mapping; do not share with reviewers")
    args = parser.parse_args()
    try:
        corpus, corpus_sha256, _ = evaluator.load_corpus()
        packet, mapping = prepare_review(corpus, corpus_sha256)
        _write_outputs(args.reviewer_packet, args.private_map, packet, mapping)
        print("Prepared blinded development review files; this does not create a hidden holdout or qualify a model.")
        return 0
    except (ReviewPacketError, evaluator.ContractError, OSError, UnicodeError, ValueError) as error:
        print(f"ETW query label-review preparation failed: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
