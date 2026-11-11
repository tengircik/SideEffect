#!/usr/bin/env python3
"""Validate a synthetic, development-only Windows ETW explanation corpus.

This tool validates fixture and selector-result structure only. It never runs
SideEffect, a model, or a runtime and does not verify semantic labels.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import struct
import sys
import unicodedata
from pathlib import Path
from typing import Any, Sequence

from bounded_input import read_regular_file as read_bounded_input


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "tests" / "fixtures" / "local_model_windows_etw_explain_v1" / "corpus.json"
FIXTURE_DIRECTORY = CORPUS_PATH.parent
EXPECTED_CORPUS_SHA256 = "a30b2d59e996dfe85a55773d1c965d80d7c983151dd44c2469857bff923ab6b3"
MAX_CORPUS_BYTES = 128 * 1024
MAX_FIXTURE_BYTES = 512 * 1024
MAX_CAPTURE_EVENTS = 16
MAX_EVENT_PAYLOAD_BYTES = 64 * 1024
MAX_CASES = 64
MAX_QUESTION_BYTES = 2048
MAX_RESULTS_BYTES = 8 * 1024 * 1024
MAX_SELECTED_IDS = 5
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
CASE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
LABEL_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
WINDOWS_EVIDENCE_ID_PATTERN = re.compile(r"^W[0-9]{5}$")
SELECTION_STATUSES = {"selected", "partial_selection", "abstained"}
PARSE_STATUSES = {"complete", "partial"}
BACKENDS = {"not_run", "cpu", "cuda"}
TCP_IP_GUID = "9a280ac0-c8e0-11d1-84e2-00c04fb998a2"


class ContractError(ValueError):
    """The pinned ETW corpus or result violates its dedicated contract."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode_json(raw: bytes, label: str) -> Any:
    def reject_constant(value: str) -> None:
        raise ContractError(f"{label} contains invalid JSON constant {value}")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"{label} is not strict UTF-8 JSON: {error}") from error


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _exact_keys(value: Any, required: set[str], label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    _require(set(value) == required, f"{label} has missing or unknown keys")
    return value


def _bounded_string(value: Any, label: str, limit: int) -> str:
    _require(isinstance(value, str) and value.strip(), f"{label} must be a non-empty string")
    _require(len(value.encode("utf-8")) <= limit, f"{label} exceeds {limit} UTF-8 bytes")
    _require(not any(unicodedata.category(char) == "Cc" for char in value), f"{label} contains a control character")
    return value


def read_regular_file(path: Path, limit: int, label: str) -> bytes:
    try:
        return read_bounded_input(path, limit, label)
    except ValueError as error:
        raise ContractError(str(error)) from error
    except OSError as error:
        raise ContractError(f"cannot read {label}: {error}") from error


_CAPTURE_KEYS = {
    "schema", "schema_version", "platform", "capture_profile", "collection_status",
    "capture_completeness", "started_at_unix_ms", "ended_at_unix_ms",
    "requested_duration_seconds", "stop_reason", "target", "session", "limits",
    "event_loss", "document_sha256", "events", "diagnostics",
}
_EVENT_KEYS = {
    "record_ordinal", "provider_guid", "event_id", "event_version", "opcode",
    "event_kind", "header_process_id", "header_thread_id", "header_flags",
    "timestamp_qpc", "raw_payload_hex", "payload_decoding", "observation_decoding",
}

# These orders mirror the Rust serde struct declarations in
# `src/windows_runtime.rs`. `observation_decoding` is the one dynamic
# `serde_json::Value` in the capture; serde_json's default map representation
# sorts those object keys lexicographically, unlike Python's insertion-ordered
# dictionaries. The fingerprint is over the Rust serialization, not the input
# JSON's formatting or key order.
_CAPTURE_FIELD_ORDER = (
    "schema", "schema_version", "platform", "capture_profile", "collection_status",
    "capture_completeness", "started_at_unix_ms", "ended_at_unix_ms",
    "requested_duration_seconds", "stop_reason", "target", "session", "limits",
    "event_loss", "document_sha256", "events", "diagnostics",
)
_TARGET_FIELD_ORDER = ("process_id", "exit_code", "status_available")
_SESSION_FIELD_ORDER = (
    "name", "provider", "scope", "buffer_size_kb_requested", "minimum_buffers_requested",
    "maximum_buffers_requested", "buffer_count_reported", "provider_process_id_header_semantics",
)
_LIMITS_FIELD_ORDER = (
    "maximum_duration_seconds", "maximum_events", "maximum_total_payload_bytes",
    "maximum_payload_bytes_per_event", "maximum_document_bytes",
)
_EVENT_LOSS_FIELD_ORDER = (
    "events_lost", "log_buffers_lost", "real_time_buffers_lost", "loss_statistics_available",
    "observation", "final_snapshot_available",
)
_EVENT_FIELD_ORDER = (
    "record_ordinal", "provider_guid", "event_id", "event_version", "opcode", "event_kind",
    "header_process_id", "header_thread_id", "header_flags", "timestamp_qpc", "raw_payload_hex",
    "payload_decoding", "observation_decoding",
)
_PROCESS_DECODING_FIELD_ORDER = (
    "status", "schema_name", "schema_version", "pointer_size_bytes", "process_id",
    "parent_process_id", "image_file_name", "diagnostic",
)


def _ordered_fields(value: dict[str, Any], order: Sequence[str]) -> dict[str, Any]:
    return {key: value[key] for key in order}


def _sort_json_value(value: Any) -> Any:
    """Match serde_json::Value's default lexicographic object-key order."""
    if isinstance(value, dict):
        return {key: _sort_json_value(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_sort_json_value(item) for item in value]
    return value


def canonical_capture_bytes(capture: dict[str, Any]) -> bytes:
    """Serialize the capture in the exact field/map order used by Rust serde."""
    canonical = _ordered_fields(capture, _CAPTURE_FIELD_ORDER)
    canonical["document_sha256"] = ""
    canonical["target"] = _ordered_fields(capture["target"], _TARGET_FIELD_ORDER)
    canonical["session"] = _ordered_fields(capture["session"], _SESSION_FIELD_ORDER)
    canonical["limits"] = _ordered_fields(capture["limits"], _LIMITS_FIELD_ORDER)
    canonical["event_loss"] = _ordered_fields(capture["event_loss"], _EVENT_LOSS_FIELD_ORDER)
    events = []
    for event in capture["events"]:
        canonical_event = _ordered_fields(event, _EVENT_FIELD_ORDER)
        if canonical_event["payload_decoding"] is not None:
            canonical_event["payload_decoding"] = _ordered_fields(
                canonical_event["payload_decoding"], _PROCESS_DECODING_FIELD_ORDER
            )
        if canonical_event["observation_decoding"] is not None:
            canonical_event["observation_decoding"] = _sort_json_value(canonical_event["observation_decoding"])
        events.append(canonical_event)
    canonical["events"] = events
    return json.dumps(canonical, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _supported_tcp_send_observation(event: dict[str, Any]) -> dict[str, Any] | None:
    """Recompute the one supported synthetic TCP/IPv4 Send layout used here."""
    if not (
        event["provider_guid"].strip("{}").lower() == TCP_IP_GUID
        and event["event_id"] == 0
        and event["event_version"] == 2
        and event["opcode"] == 10
        and event["header_flags"] & 0x0040 != 0
        and event["header_flags"] & 0x0020 == 0
    ):
        return None
    raw_hex = event["raw_payload_hex"]
    if len(raw_hex) != 80 or not re.fullmatch(r"[0-9a-f]{80}", raw_hex):
        raise ContractError("supported TCP/IPv4 fixture payload has an invalid bounded layout")
    payload = bytes.fromhex(raw_hex)
    process_id, packet_size = struct.unpack_from("<II", payload, 0)
    destination = str(ipaddress.IPv4Address(payload[8:12]))
    source = str(ipaddress.IPv4Address(payload[12:16]))
    destination_port, source_port = struct.unpack_from(">HH", payload, 16)
    # The opcode-10 send record includes start/end times before sequence and
    # connection IDs; these fields are present in the payload but not exposed
    # by the product's current observation schema.
    sequence_number = struct.unpack_from("<I", payload, 28)[0]
    connection_id = struct.unpack_from("<Q", payload, 32)[0]
    return {
        "status": "decoded",
        "diagnostic": None,
        "observation": {
            "schema": "windows.kernel_tcp_ipv4_send",
            "schema_version": 2,
            "activity": {
                "kind": "network",
                "observation": {
                    "transport": "tcp",
                    "operation": "send",
                    "payload_process_id": process_id,
                    "source_address": {"v4": list(ipaddress.IPv4Address(source).packed)},
                    "destination_address": {"v4": list(ipaddress.IPv4Address(destination).packed)},
                    "source_port": source_port,
                    "destination_port": destination_port,
                    "packet_size": packet_size,
                    "sequence_number": sequence_number,
                    "connection_id": connection_id,
                },
            },
        },
    }


def validate_capture_document(capture: Any) -> None:
    capture = _exact_keys(capture, _CAPTURE_KEYS, "Windows ETW capture")
    _require(capture["schema"] == "sideeffect.windows_runtime_capture"
             and type(capture["schema_version"]) is int and capture["schema_version"] == 3,
             "fixture must use the supported Windows runtime capture v3 schema")
    _require(capture["platform"] == "windows", "fixture platform must be windows")
    _require(capture["capture_profile"] == "synthetic_etw_fixture", "ETW corpus fixtures must be explicitly synthetic")
    _require(isinstance(capture["collection_status"], str)
             and capture["collection_status"] in {"complete", "partial"}, "invalid capture collection status")
    _require(capture["capture_completeness"] == "unknown", "capture completeness must remain unknown")
    for key in ("started_at_unix_ms", "ended_at_unix_ms", "requested_duration_seconds"):
        _require(type(capture[key]) is int and capture[key] >= 0, f"invalid capture {key}")
    _require(capture["started_at_unix_ms"] <= capture["ended_at_unix_ms"], "capture interval is invalid")
    _require(1 <= capture["requested_duration_seconds"] <= 60, "capture duration exceeds the supported bound")

    target = _exact_keys(capture["target"], {"process_id", "exit_code", "status_available"}, "target")
    _require(type(target["process_id"]) is int and 0 <= target["process_id"] <= 0xFFFFFFFF, "invalid target PID")
    _require(target["exit_code"] is None or type(target["exit_code"]) is int, "invalid target exit code")
    _require(type(target["status_available"]) is bool, "invalid target status flag")
    session = _exact_keys(capture["session"], {
        "name", "provider", "scope", "buffer_size_kb_requested", "minimum_buffers_requested",
        "maximum_buffers_requested", "buffer_count_reported", "provider_process_id_header_semantics",
    }, "session")
    for key, limit in (("name", 256), ("provider", 512), ("scope", 512), ("provider_process_id_header_semantics", 256)):
        _bounded_string(session[key], f"session.{key}", limit)
    limits = _exact_keys(capture["limits"], {
        "maximum_duration_seconds", "maximum_events", "maximum_total_payload_bytes",
        "maximum_payload_bytes_per_event", "maximum_document_bytes",
    }, "limits")
    limits_bounds = {
        "maximum_duration_seconds": (1, 60),
        "maximum_events": (1, 50_000),
        "maximum_total_payload_bytes": (1, 8 * 1024 * 1024),
        "maximum_payload_bytes_per_event": (1, MAX_EVENT_PAYLOAD_BYTES),
        "maximum_document_bytes": (1, 32 * 1024 * 1024),
    }
    for key, (minimum, maximum) in limits_bounds.items():
        _require(type(limits[key]) is int and minimum <= limits[key] <= maximum,
                 f"capture-declared {key} exceeds product bounds")
    _require(capture["requested_duration_seconds"] <= limits["maximum_duration_seconds"],
             "fixture capture duration exceeds its declared limit")
    _require(isinstance(capture["events"], list) and len(capture["events"]) <= limits["maximum_events"],
             "fixture exceeds its declared event-count limit")
    event_loss = _exact_keys(capture["event_loss"], {
        "events_lost", "log_buffers_lost", "real_time_buffers_lost", "loss_statistics_available",
        "observation", "final_snapshot_available",
    }, "event_loss")
    _require(all(type(event_loss[key]) is int and event_loss[key] >= 0 for key in
                 ("events_lost", "log_buffers_lost", "real_time_buffers_lost")), "invalid event-loss count")
    _require(type(event_loss["loss_statistics_available"]) is bool and type(event_loss["final_snapshot_available"]) is bool,
             "invalid event-loss availability flag")
    _bounded_string(event_loss["observation"], "event_loss.observation", 64)

    events = capture["events"]
    _require(isinstance(events, list) and len(events) <= MAX_CAPTURE_EVENTS, "fixture exceeds the ETW development event limit")
    aggregate_payload_bytes = 0
    for index, event in enumerate(events):
        event = _exact_keys(event, _EVENT_KEYS, f"events[{index}]")
        _require(type(event["record_ordinal"]) is int and event["record_ordinal"] == index + 1,
                 "ETW event ordinals must be sequential")
        _bounded_string(event["provider_guid"], "event provider GUID", 64)
        _bounded_string(event["event_kind"], "event kind", 128)
        for key, max_value in (("event_id", 65535), ("event_version", 255), ("opcode", 255),
                               ("header_process_id", 0xFFFFFFFF), ("header_thread_id", 0xFFFFFFFF),
                               ("header_flags", 65535)):
            _require(type(event[key]) is int and 0 <= event[key] <= max_value, f"invalid event {key}")
        _require(type(event["timestamp_qpc"]) is int, "invalid event timestamp")
        raw_hex = event["raw_payload_hex"]
        _require(isinstance(raw_hex, str) and len(raw_hex) <= MAX_EVENT_PAYLOAD_BYTES * 2
                 and len(raw_hex) % 2 == 0 and re.fullmatch(r"[0-9a-f]*", raw_hex) is not None,
                 "invalid, malformed, or oversized raw event payload")
        aggregate_payload_bytes += len(raw_hex) // 2
        _require(aggregate_payload_bytes <= 8 * 1024 * 1024, "fixture aggregate payload exceeds the product bound")
        _require(len(raw_hex) // 2 <= limits["maximum_payload_bytes_per_event"],
                 "event payload exceeds its declared per-event limit")
        _require(aggregate_payload_bytes <= limits["maximum_total_payload_bytes"],
                 "fixture payload exceeds its declared aggregate limit")
        payload_decoding = event["payload_decoding"]
        observation_decoding = event["observation_decoding"]
        _require((payload_decoding is None) != (observation_decoding is None),
                 "each ETW event must contain exactly one decoder result")
        if payload_decoding is not None:
            payload_decoding = _exact_keys(payload_decoding, {
                "status", "schema_name", "schema_version", "pointer_size_bytes", "process_id",
                "parent_process_id", "image_file_name", "diagnostic",
            }, "event payload decoding")
            _require(isinstance(payload_decoding["status"], str) and payload_decoding["status"] in {
                "decoded", "unsupported_version", "unsupported_opcode", "ambiguous_pointer_size",
                "schema_unavailable", "schema_mismatch", "malformed_payload",
            }, "unknown process payload decoder status")
            for text_key in ("schema_name", "image_file_name", "diagnostic"):
                value = payload_decoding[text_key]
                if value is not None:
                    _bounded_string(value, f"payload_decoding.{text_key}", 2048)
            _require(payload_decoding["status"] != "decoded" or payload_decoding["image_file_name"] is None,
                     "imported process decoder sidecar must not claim live TDH facts")
        if observation_decoding is not None:
            observation_decoding = _exact_keys(observation_decoding, {"status", "diagnostic", "observation"},
                                               "event observation decoding")
            _require(isinstance(observation_decoding["status"], str)
                     and observation_decoding["status"] in {"decoded", "unsupported", "malformed"},
                     "unknown observation payload decoder status")
            expected = _supported_tcp_send_observation(event)
            if expected is not None:
                _require(observation_decoding == expected, "TCP payload and serialized observation sidecar mismatch")
            elif observation_decoding["status"] == "decoded":
                raise ContractError("unsupported event payload cannot carry a decoded observation sidecar")
            else:
                _require(observation_decoding["observation"] is None,
                         "unsupported or malformed event payload cannot carry an observation")

    diagnostics = capture["diagnostics"]
    _require(isinstance(diagnostics, list) and len(diagnostics) <= 1024, "invalid or oversized capture diagnostics")
    for diagnostic in diagnostics:
        _bounded_string(diagnostic, "capture diagnostic", 4096)
    claimed_digest = capture["document_sha256"]
    _require(isinstance(claimed_digest, str) and SHA256_PATTERN.fullmatch(claimed_digest) is not None,
             "invalid Windows capture document digest")
    canonical = canonical_capture_bytes(capture)
    _require(hashlib.sha256(canonical).hexdigest() == claimed_digest, "Windows capture document fingerprint mismatch")


def load_capture_bytes(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = read_regular_file(path, MAX_FIXTURE_BYTES, f"fixture {path.name}")
    capture = decode_json(raw, f"fixture {path.name}")
    validate_capture_document(capture)
    return raw, capture


def validate_corpus(corpus: Any) -> None:
    corpus = _exact_keys(corpus, {
        "schema", "schema_version", "evaluation_status", "label_review_status", "fixtures",
        "cases", "permutation_groups",
    }, "corpus")
    _require(corpus["schema"] == "sideeffect.local_model_windows_etw_explanation_development_corpus"
             and type(corpus["schema_version"]) is int and corpus["schema_version"] == 1,
             "unsupported Windows ETW corpus contract")
    _require(corpus["evaluation_status"] == "development_only_not_a_release_gate", "Windows ETW corpus must remain development-only")
    _require(corpus["label_review_status"] == "unreviewed_labels_not_semantically_validated", "corpus labels must remain explicitly unreviewed")
    fixture_rows = corpus["fixtures"]
    _require(isinstance(fixture_rows, list) and 0 < len(fixture_rows) <= 32, "invalid fixture manifest")
    fixture_map: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(fixture_rows):
        row = _exact_keys(row, {"path", "size_bytes", "sha256"}, f"fixtures[{index}]")
        name = _bounded_string(row["path"], "fixture path", 128)
        _require(Path(name).name == name and name.endswith(".json") and name not in fixture_map,
                 "fixture path must be a unique flat .json filename")
        _require(type(row["size_bytes"]) is int and 0 < row["size_bytes"] <= MAX_FIXTURE_BYTES,
                 "fixture size is outside the bounded range")
        _require(isinstance(row["sha256"], str) and SHA256_PATTERN.fullmatch(row["sha256"]) is not None,
                 "invalid fixture manifest digest")
        raw, capture = load_capture_bytes(FIXTURE_DIRECTORY / name)
        _require(len(raw) == row["size_bytes"], f"fixture byte length mismatch: {name}")
        _require(hashlib.sha256(raw).hexdigest() == row["sha256"], f"fixture SHA-256 mismatch: {name}")
        fixture_map[name] = capture

    cases = corpus["cases"]
    _require(isinstance(cases, list) and 0 < len(cases) <= MAX_CASES, "invalid ETW case list")
    case_ids: set[str] = set()
    for index, case in enumerate(cases):
        case = _exact_keys(case, {"id", "fixture", "question", "expected_evidence_labels", "expected_abstain"},
                           f"cases[{index}]")
        case_id = _bounded_string(case["id"], "case id", 96)
        _require(CASE_ID_PATTERN.fullmatch(case_id) is not None and case_id not in case_ids,
                 "invalid or duplicate ETW case id")
        case_ids.add(case_id)
        _require(isinstance(case["fixture"], str) and case["fixture"] in fixture_map,
                 f"case {case_id} references an unknown fixture")
        _bounded_string(case["question"], f"case {case_id} question", MAX_QUESTION_BYTES)
        labels = case["expected_evidence_labels"]
        _require(isinstance(labels, list) and len(labels) <= MAX_CAPTURE_EVENTS
                 and all(isinstance(label, str) and LABEL_PATTERN.fullmatch(label) for label in labels)
                 and len(labels) == len(set(labels)), f"invalid expected evidence labels in {case_id}")
        _require(type(case["expected_abstain"]) is bool, f"invalid abstention annotation in {case_id}")
    groups = corpus["permutation_groups"]
    _require(isinstance(groups, list) and len(groups) <= 16, "invalid ETW permutation groups")
    for group in groups:
        group = _exact_keys(group, {"id", "case_ids"}, "permutation group")
        _bounded_string(group["id"], "permutation group id", 96)
        members = group["case_ids"]
        _require(isinstance(members, list) and len(members) >= 2 and len(members) <= MAX_CASES
                 and all(isinstance(member, str) for member in members)
                 and len(members) == len(set(members)) and all(member in case_ids for member in members),
                 "invalid ETW permutation group members")


def load_corpus() -> tuple[dict[str, Any], str]:
    raw = read_regular_file(CORPUS_PATH, MAX_CORPUS_BYTES, "Windows ETW corpus manifest")
    digest = hashlib.sha256(raw).hexdigest()
    _require(bool(EXPECTED_CORPUS_SHA256) and digest == EXPECTED_CORPUS_SHA256,
             "Windows ETW corpus SHA-256 does not match the evaluator pin")
    corpus = decode_json(raw, "Windows ETW corpus manifest")
    validate_corpus(corpus)
    return corpus, digest


def validate_results(results: Any, corpus: dict[str, Any], corpus_digest: str) -> dict[str, Any]:
    results = _exact_keys(results, {
        "schema", "schema_version", "corpus_sha256", "evaluation_status", "label_review_status",
        "run", "cases", "errors",
    }, "ETW results")
    _require(results["schema"] == "sideeffect.local_model_windows_etw_explanation_development_results"
             and type(results["schema_version"]) is int and results["schema_version"] == 1,
             "unsupported ETW results contract")
    _require(results["corpus_sha256"] == corpus_digest, "ETW results corpus digest mismatch")
    _require(results["evaluation_status"] == corpus["evaluation_status"]
             and results["label_review_status"] == corpus["label_review_status"],
             "ETW result review status cannot be upgraded")
    run = _exact_keys(results["run"], {
        "model_id", "model_sha256", "runtime_source_revision", "backend_preference",
    }, "ETW run identity")
    _bounded_string(run["model_id"], "model_id", 128)
    _require(isinstance(run["model_sha256"], str) and SHA256_PATTERN.fullmatch(run["model_sha256"]) is not None,
             "invalid ETW model digest")
    _require(isinstance(run["runtime_source_revision"], str)
             and re.fullmatch(r"[0-9a-f]{40}", run["runtime_source_revision"]) is not None,
             "invalid ETW runtime revision")
    _require(isinstance(run["backend_preference"], str)
             and run["backend_preference"] in {"auto", "cpu", "cuda"}, "invalid ETW backend preference")
    rows = results["cases"]
    _require(isinstance(rows, list) and len(rows) <= len(corpus["cases"]), "invalid ETW results cases")
    cases_by_id = {case["id"]: case for case in corpus["cases"]}
    fixture_event_ids = {
        fixture["path"]: [f"W{index + 1:05d}" for index in range(len(load_capture_bytes(FIXTURE_DIRECTORY / fixture["path"])[1]["events"]))]
        for fixture in corpus["fixtures"]
    }
    seen_cases: set[str] = set()
    for index, row in enumerate(rows):
        row = _exact_keys(row, {
            "case_id", "response", "source_parse_status", "backend_used", "available_evidence",
            "preview_request_sha256", "latency_ms",
        }, f"results.cases[{index}]")
        case_id = row["case_id"]
        _require(isinstance(case_id, str) and case_id in cases_by_id and case_id not in seen_cases,
                 "unknown or duplicate ETW results case")
        seen_cases.add(case_id)
        _require(isinstance(row["source_parse_status"], str)
                 and row["source_parse_status"] in PARSE_STATUSES, "invalid ETW source parse status")
        _require(isinstance(row["backend_used"], str) and row["backend_used"] in BACKENDS,
                 "invalid ETW backend status")
        _require(isinstance(row["preview_request_sha256"], str)
                 and SHA256_PATTERN.fullmatch(row["preview_request_sha256"]) is not None,
                 "invalid ETW preview digest")
        _require(type(row["latency_ms"]) is int and 0 <= row["latency_ms"] <= 120_000,
                 "invalid ETW analysis latency")
        response = _exact_keys(row["response"], {"selection_status", "evidence_ids", "abstain_reason"},
                               f"result response {case_id}")
        _require(isinstance(response["selection_status"], str)
                 and response["selection_status"] in SELECTION_STATUSES, "invalid ETW selection status")
        ids = response["evidence_ids"]
        _require(isinstance(ids, list) and len(ids) <= MAX_SELECTED_IDS
                 and all(isinstance(item, str) and WINDOWS_EVIDENCE_ID_PATTERN.fullmatch(item) for item in ids)
                 and len(ids) == len(set(ids)), "invalid ETW selected evidence IDs")
        evidence = row["available_evidence"]
        _require(isinstance(evidence, list) and len(evidence) <= MAX_CAPTURE_EVENTS,
                 "invalid ETW available evidence")
        allowed: set[str] = set()
        for item in evidence:
            item = _exact_keys(item, {"evidence_id", "semantic_labels"}, "ETW evidence map item")
            evidence_id = item["evidence_id"]
            _require(isinstance(evidence_id, str) and WINDOWS_EVIDENCE_ID_PATTERN.fullmatch(evidence_id)
                     and evidence_id not in allowed, "invalid or duplicate W evidence ID")
            allowed.add(evidence_id)
            _require(item["semantic_labels"] == [], "runner must not promote unreviewed corpus labels into row annotations")
        expected_ids = fixture_event_ids[cases_by_id[case_id]["fixture"]]
        _require([item["evidence_id"] for item in evidence] == expected_ids,
                 "ETW result evidence map does not match the complete pinned fixture order")
        _require(set(ids).issubset(allowed), "ETW result selected evidence outside its exact preview")
        expected_status = "abstained" if not ids else ("selected" if row["source_parse_status"] == "complete" else "partial_selection")
        _require(response["selection_status"] == expected_status, "ETW selection status contradicts selected IDs or source completeness")
        _require(response["abstain_reason"] is None or (isinstance(response["abstain_reason"], str)
                 and response["abstain_reason"] in {
            "ambiguous", "unsupported_scope", "insufficient_evidence",
        }), "invalid ETW abstain reason")
        _require(row["backend_used"] != "not_run" or not ids, "not_run backend cannot have selected evidence")
    errors = results["errors"]
    _require(isinstance(errors, list) and len(errors) <= len(corpus["cases"]), "invalid ETW error list")
    for error in errors:
        error = _exact_keys(error, {"case_id", "phase", "error"}, "ETW runner error")
        _require(isinstance(error["case_id"], str) and error["case_id"] in cases_by_id
                 and isinstance(error["phase"], str) and error["phase"] in {"preview", "analysis"},
                 "invalid ETW runner error identity")
        _bounded_string(error["error"], "ETW safe error", 256)
    _require(seen_cases.isdisjoint({error["case_id"] for error in errors}), "ETW case cannot be both a result and an error")
    _require(seen_cases | {error["case_id"] for error in errors} == set(cases_by_id), "ETW result set is incomplete")
    return {
        "schema": "sideeffect.local_model_windows_etw_explanation_results_check",
        "schema_version": 1,
        "status": "structurally_valid_development_results",
        "evaluation_status": results["evaluation_status"],
        "label_review_status": results["label_review_status"],
        "cases": len(rows),
        "errors": len(errors),
        "corpus_sha256": corpus_digest,
        "semantic_quality_assessed": False,
        "qualification_result": "not_run_and_not_claimed",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-corpus", action="store_true", help="validate pinned synthetic ETW fixtures and manifest")
    parser.add_argument("--results", type=Path, help="validate a separately generated ETW selector result file")
    args = parser.parse_args()
    if not args.check_corpus and args.results is None:
        parser.error("select --check-corpus and/or provide --results")
    try:
        corpus, digest = load_corpus()
        if args.results is not None:
            raw = read_regular_file(args.results, MAX_RESULTS_BYTES, "ETW results")
            report = validate_results(decode_json(raw, "ETW results"), corpus, digest)
        else:
            report = {
                "schema": "sideeffect.local_model_windows_etw_explanation_corpus_check",
                "schema_version": 1,
                "status": "valid_synthetic_development_corpus",
                "evaluation_status": corpus["evaluation_status"],
                "label_review_status": corpus["label_review_status"],
                "cases": len(corpus["cases"]),
                "fixtures": len(corpus["fixtures"]),
                "permutation_groups": len(corpus["permutation_groups"]),
                "corpus_sha256": digest,
                "semantic_quality_assessed": False,
                "qualification_result": "not_run_and_not_claimed",
            }
        print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    except (ContractError, OSError, UnicodeError, ValueError) as error:
        print(f"Windows ETW explanation evaluation error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
