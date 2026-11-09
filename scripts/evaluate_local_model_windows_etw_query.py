#!/usr/bin/env python3
"""Validate the synthetic Windows ETW query development corpus only.

This checks bounded corpus structure, pinned capture integrity, and oracle
consistency. It does not execute SideEffect or run local model inference.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any

import evaluate_local_model_windows_etw_explain as capture_contract


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "tests" / "fixtures" / "local_model_windows_etw_query_v1" / "corpus.json"
FIXTURE_DIRECTORY = CORPUS_PATH.parent
EXPECTED_CORPUS_SHA256 = "015aa36516c2215dc1528a5b0681543a17476f920be03dc1a82c75c6595c7694"
MAX_CORPUS_BYTES = 128 * 1024
MAX_FIXTURE_BYTES = 512 * 1024
MAX_CASES = 64
MAX_QUESTION_BYTES = 2048
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
CASE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
EVENT_KINDS = {"file_io_observation", "network_observation", "disk_io_observation"}
FILE_OPERATIONS = {
    "name", "create_name", "delete_name", "rundown_name", "create_request", "read_request",
    "write_request", "set_information_request", "delete_request", "rename_request",
    "query_information_request", "file_system_control_request", "cleanup", "close", "flush_request",
}
NETWORK_OPERATIONS = {
    "connect", "accept", "disconnect", "send", "receive", "retransmit", "reconnect", "tcp_copy",
}
DISK_OPERATIONS = {"read", "write", "flush_buffers"}
FILTER_KEYS = {
    "event_kind", "file_operation", "network_operation", "disk_operation", "path_exact", "transport",
    "destination_address", "destination_port", "payload_process_id",
}


class ContractError(ValueError):
    """The pinned query corpus violates its bounded development contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == keys, f"{label} has missing or unknown fields")
    return value


def _read_regular_file(path: Path, limit: int, label: str) -> bytes:
    try:
        info = path.lstat()
    except OSError as error:
        raise ContractError(f"cannot inspect {label}: {error}") from error
    _require(stat.S_ISREG(info.st_mode), f"{label} must be a regular non-symlink file")
    _require(info.st_size <= limit, f"{label} exceeds its byte limit")
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError as error:
        raise ContractError(f"cannot read {label}: {error}") from error
    _require(len(raw) <= limit, f"{label} grew beyond its byte limit")
    return raw


def _decode(raw: bytes, label: str) -> Any:
    try:
        return capture_contract.decode_json(raw, label)
    except (capture_contract.ContractError, UnicodeError, ValueError) as error:
        raise ContractError(str(error)) from error


def _validate_plan(plan: Any, case_id: str) -> dict[str, Any]:
    plan = _exact_keys(plan, {"decision", "abstain_reason", "filters"}, f"case {case_id} expected plan")
    filters = _exact_keys(plan["filters"], FILTER_KEYS, f"case {case_id} filters")
    populated = {key: value for key, value in filters.items() if value is not None}
    if plan["decision"] == "abstain":
        _require(isinstance(plan["abstain_reason"], str)
                 and plan["abstain_reason"] in {"ambiguous", "unsupported_scope", "insufficient_evidence"}
                 and not populated, f"case {case_id} has an invalid abstention")
        return plan
    _require(plan["decision"] == "filter" and plan["abstain_reason"] is None
             and 1 <= len(populated) <= 4, f"case {case_id} has an invalid filter decision")
    enum_sets = {
        "event_kind": EVENT_KINDS, "file_operation": FILE_OPERATIONS,
        "network_operation": NETWORK_OPERATIONS, "disk_operation": DISK_OPERATIONS,
        "transport": {"tcp", "udp"},
    }
    for key, values in enum_sets.items():
        _require(filters[key] is None or (isinstance(filters[key], str) and filters[key] in values),
                 f"case {case_id} has invalid {key}")
    _require(filters["path_exact"] is None or (isinstance(filters["path_exact"], str)
             and 0 < len(filters["path_exact"].encode("utf-8")) <= 4096
             and "\x00" not in filters["path_exact"]), f"case {case_id} has invalid path_exact")
    _require(filters["destination_address"] is None or (
        isinstance(filters["destination_address"], str)
        and len(filters["destination_address"]) <= 64
        and _is_ip_address(filters["destination_address"])
    ), f"case {case_id} has invalid destination_address")
    _require(filters["destination_port"] is None or (type(filters["destination_port"]) is int
             and 0 <= filters["destination_port"] <= 65535), f"case {case_id} has invalid destination_port")
    _require(filters["payload_process_id"] is None or (type(filters["payload_process_id"]) is int
             and 1 <= filters["payload_process_id"] <= 0xFFFFFFFF), f"case {case_id} has invalid payload_process_id")
    required_kind = {
        "file_operation": "file_io_observation", "path_exact": "file_io_observation",
        "network_operation": "network_observation", "disk_operation": "disk_io_observation",
        "transport": "network_observation", "destination_address": "network_observation",
        "destination_port": "network_observation", "payload_process_id": "network_observation",
    }
    for key, event_kind in required_kind.items():
        if filters[key] is not None:
            _require(filters["event_kind"] == event_kind, f"case {case_id} omits the required {event_kind} selector")
    return plan


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _capture_facts(capture: dict[str, Any]) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for event in capture["events"]:
        decoding = event["observation_decoding"]
        if not decoding or decoding["status"] != "decoded":
            continue
        observation = decoding["observation"]["activity"]["observation"]
        address = observation.get("destination_address")
        if isinstance(address, dict):
            if "v4" in address:
                address = ".".join(str(part) for part in address["v4"])
            elif "v6" in address:
                import ipaddress

                address = str(ipaddress.IPv6Address(bytes(address["v6"])))
            else:
                address = None
        facts.append({
            "event_kind": event["event_kind"], "operation": observation.get("operation"),
            "path": observation.get("path"), "transport": observation.get("transport"),
            "destination_address": address, "destination_port": observation.get("destination_port"),
            "payload_process_id": observation.get("payload_process_id"),
            "record_ordinal": event["record_ordinal"],
        })
    return facts


def _matched_ordinals(facts: list[dict[str, Any]], plan: dict[str, Any]) -> list[int]:
    if plan["decision"] == "abstain":
        return []
    aliases = {"file_operation": "operation", "network_operation": "operation", "disk_operation": "operation",
               "path_exact": "path"}
    filters = plan["filters"]
    return [fact["record_ordinal"] for fact in facts
            if all(value is None or fact.get(aliases.get(key, key)) == value for key, value in filters.items())]


def validate_corpus(corpus: Any, base_directory: Path = FIXTURE_DIRECTORY) -> dict[str, Any]:
    corpus = _exact_keys(corpus, {
        "schema", "schema_version", "evaluation_status", "label_review_status",
        "fixtures", "cases", "permutation_groups",
    }, "corpus")
    _require(corpus["schema"] == "sideeffect.local_model_windows_etw_query_development_corpus"
             and type(corpus["schema_version"]) is int and corpus["schema_version"] == 1,
             "unsupported ETW query corpus contract")
    _require(corpus["evaluation_status"] == "development_only_not_a_release_gate"
             and corpus["label_review_status"] == "unreviewed_labels_not_semantically_validated",
             "ETW query corpus must remain explicitly unreviewed development data")
    fixtures = corpus["fixtures"]
    _require(isinstance(fixtures, list) and 0 < len(fixtures) <= 32, "invalid ETW query fixture manifest")
    captures: dict[str, dict[str, Any]] = {}
    fixture_names: set[str] = set()
    for index, fixture in enumerate(fixtures):
        fixture = _exact_keys(fixture, {"path", "size_bytes", "sha256"}, f"fixtures[{index}]")
        name = fixture["path"]
        _require(isinstance(name, str) and Path(name).name == name and "/" not in name
                 and "\\" not in name and ":" not in name and name.endswith(".json")
                 and name not in fixture_names, "fixture path must be a unique flat JSON filename")
        _require(type(fixture["size_bytes"]) is int and 0 < fixture["size_bytes"] <= MAX_FIXTURE_BYTES,
                 "fixture size is outside bounds")
        _require(isinstance(fixture["sha256"], str) and SHA256_PATTERN.fullmatch(fixture["sha256"]) is not None,
                 "invalid fixture SHA-256")
        raw = _read_regular_file(base_directory / name, MAX_FIXTURE_BYTES, f"ETW fixture {name}")
        _require(len(raw) == fixture["size_bytes"] and hashlib.sha256(raw).hexdigest() == fixture["sha256"],
                 f"fixture size or digest mismatch: {name}")
        capture = _decode(raw, f"ETW fixture {name}")
        capture_contract.validate_capture_document(capture)
        _require(capture["capture_profile"] == "synthetic_etw_fixture", "query fixture must be synthetic")
        captures[name] = capture
        fixture_names.add(name)
    cases = corpus["cases"]
    _require(isinstance(cases, list) and 0 < len(cases) <= MAX_CASES, "invalid ETW query case list")
    case_by_id: dict[str, dict[str, Any]] = {}
    for index, case in enumerate(cases):
        case = _exact_keys(case, {"id", "fixture", "question", "behavior", "expected_plan",
                                   "expected_record_ordinals"}, f"cases[{index}]")
        case_id = case["id"]
        _require(isinstance(case_id, str) and CASE_ID_PATTERN.fullmatch(case_id) is not None
                 and case_id not in case_by_id, "invalid or duplicate ETW query case ID")
        _require(isinstance(case["fixture"], str) and case["fixture"] in captures,
                 f"case {case_id} references an unknown fixture")
        question = case["question"]
        _require(isinstance(question, str) and 0 < len(question.encode("utf-8")) <= MAX_QUESTION_BYTES,
                 f"case {case_id} question is empty or oversized")
        _require(isinstance(case["behavior"], str) and case["behavior"] in {"answerable", "must_abstain"},
                 f"case {case_id} has invalid behavior")
        plan = _validate_plan(case["expected_plan"], case_id)
        _require((case["behavior"] == "must_abstain") == (plan["decision"] == "abstain"),
                 f"case {case_id} behavior conflicts with its plan")
        ordinals = case["expected_record_ordinals"]
        _require(isinstance(ordinals, list) and len(ordinals) <= capture_contract.MAX_CAPTURE_EVENTS
                 and all(type(item) is int and 1 <= item <= len(captures[case["fixture"]]["events"])
                         for item in ordinals) and len(ordinals) == len(set(ordinals)),
                 f"case {case_id} has invalid expected event ordinals")
        _require(ordinals == _matched_ordinals(_capture_facts(captures[case["fixture"]]), plan),
                 f"case {case_id} expected matches disagree with exact-match plan semantics")
        case_by_id[case_id] = case
    groups = corpus["permutation_groups"]
    _require(isinstance(groups, list) and len(groups) <= 16, "invalid permutation group list")
    group_ids: set[str] = set()
    for group in groups:
        group = _exact_keys(group, {"id", "case_ids"}, "permutation group")
        group_id, members = group["id"], group["case_ids"]
        _require(isinstance(group_id, str) and CASE_ID_PATTERN.fullmatch(group_id) is not None
                 and group_id not in group_ids, "invalid or duplicate permutation group ID")
        _require(isinstance(members, list) and 2 <= len(members) <= len(cases)
                 and all(isinstance(member, str) for member in members)
                 and len(members) == len(set(members)) and all(member in case_by_id for member in members),
                 f"invalid members in permutation group {group_id}")
        members_data = [case_by_id[member] for member in members]
        first = members_data[0]
        signature = json.dumps(first["expected_plan"], sort_keys=True, separators=(",", ":"))
        _require(all(case["question"] == first["question"]
                     and json.dumps(case["expected_plan"], sort_keys=True, separators=(",", ":")) == signature
                     for case in members_data), f"permutation group {group_id} changes its question or oracle plan")
        _require(len({case["fixture"] for case in members_data}) == len(members_data),
                 f"permutation group {group_id} must use distinct reordered fixtures")
        group_ids.add(group_id)
    return {"cases": len(cases), "fixtures": len(fixtures), "permutation_groups": len(groups),
            "must_abstain_cases": sum(case["behavior"] == "must_abstain" for case in cases),
            "answerable_cases": sum(case["behavior"] == "answerable" for case in cases),
            "unreviewed_labels": True, "semantic_quality_assessed": False}


def load_corpus() -> tuple[dict[str, Any], str, dict[str, Any]]:
    raw = _read_regular_file(CORPUS_PATH, MAX_CORPUS_BYTES, "ETW query corpus")
    digest = hashlib.sha256(raw).hexdigest()
    _require(digest == EXPECTED_CORPUS_SHA256, "ETW query corpus SHA-256 does not match its evaluator pin")
    corpus = _decode(raw, "ETW query corpus")
    return corpus, digest, validate_corpus(corpus)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-corpus", action="store_true", help="validate the pinned synthetic corpus only")
    args = parser.parse_args()
    if not args.check_corpus:
        parser.error("select --check-corpus")
    try:
        corpus, digest, summary = load_corpus()
        report = {"schema": "sideeffect.windows_etw_query_corpus_check", "schema_version": 1,
                  "status": "valid_synthetic_development_corpus", "corpus_sha256": digest,
                  "evaluation_status": corpus["evaluation_status"],
                  "label_review_status": corpus["label_review_status"], **summary,
                  "qualification_result": "not_run_and_not_claimed"}
        print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    except (ContractError, OSError, UnicodeError, ValueError) as error:
        print(f"Windows ETW query evaluation error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
