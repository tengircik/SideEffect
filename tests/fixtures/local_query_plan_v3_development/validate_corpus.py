"""Strict validator for the public local-query-plan v3 development corpus."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SCHEMA = "sideeffect.local_query_plan_evaluation_corpus"
ABSTENTION_CONTEXT_FIXTURE = "abstention-context.trace"
PLAN_FIELDS = {"decision", "abstain_reason", "entity", "filters", "combine"}
FILTER_KEYS = {
    "syscall", "outcome", "observed_errno", "lexical_path_exact",
    "process_id", "caller_task_id", "child_pid", "relation_type",
}
SYSCALLS = {"execve", "execveat", "openat", "openat2", "connect"}
RELATIONS = {"fork", "vfork", "clone", "clone3"}
OUTCOMES = {"success", "failure", "in_progress", "unknown"}
ERRNOS = {"EACCES", "ENOENT", "ECONNREFUSED", "EINPROGRESS"}
ABSTAIN_REASONS = {"ambiguous", "unsupported_scope", "insufficient_evidence"}
ABSTAIN_CLASS_REASONS = {
    "ambiguous": "ambiguous",
    "unsupported": "unsupported_scope",
    "insufficient": "insufficient_evidence",
    "adversarial": "ambiguous",
}
CASE_KEYS = {
    "id", "intent_group", "source_order_group", "class", "behavior", "question",
    "fixture", "evaluation_fixture", "target_line", "expected_match_count", "expected_plan", "selector_support",
}
TOP_KEYS = {
    "schema", "schema_version", "status", "data_classification", "release_quality_evidence",
    "plan_schema_version", "selector_grounding", "synonym_rules", "case_count",
    "behavior_counts", "answerable_class_counts", "must_abstain_class_counts",
    "answerable_intent_group_count", "source_order_group_sizes", "limits", "fixture_sha256", "cases",
}
EXPECTED_ANSWERABLE_COUNTS = {
    "source_order": 20, "syscall": 15, "conjunction": 15,
    "process_id": 15, "process_relation": 15,
}
EXPECTED_ABSTAIN_COUNTS = {
    "ambiguous": 10, "unsupported": 10, "insufficient": 10, "adversarial": 10,
}
DEFAULT_LIMITS = {
    "corpus_bytes_max": 524288,
    "fixture_bytes_max": 131072,
    "fixture_record_bytes_max": 65536,
    "fixture_records_max": 1000,
    "question_bytes_max": 2048,
}
LINE_RE = re.compile(r"^(\d+) ([A-Za-z][A-Za-z0-9_]*)\((.*)\) = (.+)$")
ERRNO_RE = re.compile(r"^-1 ([A-Z][A-Z0-9_]*) \(")
PATH_RE = re.compile(r'"(/[^"\\]*)"')


class CorpusError(ValueError):
    pass


def _fail(message: str) -> None:
    raise CorpusError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            _fail(f"duplicate JSON object key: {key}")
        out[key] = value
    return out


def _load_json(raw: bytes, limit: int, description: str) -> Any:
    if len(raw) > limit:
        _fail(f"{description} exceeds its {limit}-byte limit")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"{description} is not strict UTF-8 JSON: {exc}")


def _stringify(value: object) -> str:
    if isinstance(value, bool) or value is None:
        return str(value).lower()
    return str(value)


def _normalize_template(question: str, support: dict[str, Any]) -> str:
    normalized = question.casefold()
    values = sorted(
        {row["canonical_value"] for row in support.values()},
        key=len,
        reverse=True,
    )
    for value in values:
        normalized = normalized.replace(value.casefold(), " <value> ")
    normalized = re.sub(r"[^a-z0-9<>]+", " ", normalized)
    return " ".join(normalized.split())


def parse_trace(raw: bytes, name: str, limits: dict[str, int]) -> list[dict[str, Any]]:
    if len(raw) > limits["fixture_bytes_max"]:
        _fail(f"fixture {name} exceeds its byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        _fail(f"fixture {name} is not UTF-8: {exc}")
    if not text.endswith("\n"):
        _fail(f"fixture {name} must end with LF")
    lines = text.splitlines()
    if len(lines) > limits["fixture_records_max"]:
        _fail(f"fixture {name} exceeds its record-count limit")
    rows = []
    for line_number, line in enumerate(lines, 1):
        if not line or len(line.encode("utf-8")) > limits["fixture_record_bytes_max"]:
            _fail(f"fixture {name} has an empty or over-limit line {line_number}")
        match = LINE_RE.fullmatch(line)
        if not match:
            _fail(f"fixture {name} line {line_number} is not a supported synthetic strace record")
        pid, syscall, args, result = match.groups()
        row: dict[str, Any] = {"process_id": int(pid), "syscall": syscall}
        errno_match = ERRNO_RE.match(result)
        if errno_match:
            row["observed_errno"] = errno_match.group(1)
            row["outcome"] = "in_progress" if row["observed_errno"] == "EINPROGRESS" else "failure"
        else:
            try:
                result_number = int(result.split()[0])
            except (ValueError, IndexError):
                _fail(f"fixture {name} line {line_number} has an unsupported result")
            row["outcome"] = "success" if result_number >= 0 else "unknown"
        if syscall in {"openat", "openat2"}:
            path_match = PATH_RE.search(args)
            if path_match:
                row["lexical_path_exact"] = path_match.group(1)
        if syscall in RELATIONS and row["outcome"] == "success":
            try:
                child_pid = int(result.split()[0])
            except (ValueError, IndexError):
                _fail(f"fixture {name} line {line_number} has an invalid child PID")
            if child_pid > 0:
                row["caller_task_id"] = int(pid)
                row["child_pid"] = child_pid
                row["relation_type"] = syscall
        row["line"] = line_number
        rows.append(row)
    return rows


def _matches(filters: dict[str, Any], row: dict[str, Any]) -> bool:
    return all(value is None or row.get(key) == value for key, value in filters.items())


def _validate_plan(case: dict[str, Any]) -> None:
    plan = case["expected_plan"]
    if not isinstance(plan, dict) or set(plan) != PLAN_FIELDS:
        _fail(f"{case['id']}: expected plan does not have the exact v2 plan fields")
    filters = plan["filters"]
    if not isinstance(filters, dict) or set(filters) != FILTER_KEYS:
        _fail(f"{case['id']}: expected filter object has an invalid schema")
    if plan["combine"] != "all":
        _fail(f"{case['id']}: only exact AND plans are supported")
    nonnull = {key for key, value in filters.items() if value is not None}
    if plan["decision"] == "abstain":
        if plan["abstain_reason"] not in ABSTAIN_REASONS or plan["entity"] is not None or nonnull:
            _fail(f"{case['id']}: invalid abstain plan")
    elif plan["decision"] == "filter":
        if plan["abstain_reason"] is not None or plan["entity"] not in {"syscall_result", "process_relation"} or not nonnull:
            _fail(f"{case['id']}: invalid filter-plan decision/entity/filters")
        if plan["entity"] == "syscall_result" and nonnull - {"syscall", "outcome", "observed_errno", "lexical_path_exact", "process_id"}:
            _fail(f"{case['id']}: syscall-result plan uses relation-only fields")
        if plan["entity"] == "process_relation" and nonnull - {"process_id", "caller_task_id", "child_pid", "relation_type"}:
            _fail(f"{case['id']}: process-relation plan uses syscall-only fields")
        for key in ("process_id", "caller_task_id", "child_pid"):
            value = filters[key]
            if value is not None and (type(value) is not int or not 1 <= value <= 0xFFFFFFFF):
                _fail(f"{case['id']}: {key} is not a positive u32")
        if filters["syscall"] is not None and filters["syscall"] not in SYSCALLS:
            _fail(f"{case['id']}: unsupported syscall enum value")
        if filters["outcome"] is not None and filters["outcome"] not in OUTCOMES:
            _fail(f"{case['id']}: unsupported outcome enum value")
        if filters["observed_errno"] is not None and filters["observed_errno"] not in ERRNOS:
            _fail(f"{case['id']}: unsupported errno enum value for this corpus")
        if filters["relation_type"] is not None and filters["relation_type"] not in RELATIONS:
            _fail(f"{case['id']}: unsupported relation enum value")
        path = filters["lexical_path_exact"]
        if path is not None and (not isinstance(path, str) or not path.startswith("/") or len(path.encode("utf-8")) > 256 or not path.isascii() or any(ord(ch) < 0x20 for ch in path)):
            _fail(f"{case['id']}: invalid lexical_path_exact value")
    else:
        _fail(f"{case['id']}: unknown plan decision")


def validate_data(data: Any, base_dir: Path, corpus_size: int | None = None) -> dict[str, int]:
    if corpus_size is not None and corpus_size > DEFAULT_LIMITS["corpus_bytes_max"]:
        _fail("corpus exceeds its byte limit")
    if not isinstance(data, dict) or set(data) != TOP_KEYS:
        _fail("corpus top-level schema is invalid")
    if data["schema"] != SCHEMA or data["schema_version"] != 3:
        _fail("corpus schema/version is unsupported")
    if data["status"] != "public_development" or data["data_classification"] != "public_development_not_hidden_holdout" or data["release_quality_evidence"] is not False:
        _fail("corpus must remain labeled public development data, not release evidence")
    if data["plan_schema_version"] != 2 or data["selector_grounding"] != "field_value_literal_only" or data["synonym_rules"] != []:
        _fail("corpus must use query-plan schema v2 and literal-only grounding")
    if data["case_count"] != 120 or len(data["cases"]) != 120:
        _fail("corpus must contain exactly 120 cases")
    if data["limits"] != DEFAULT_LIMITS:
        _fail("corpus limits do not match the validator limits")
    if data["behavior_counts"] != {"answerable": 80, "must_abstain": 40}:
        _fail("corpus behavior counts are invalid")
    if data["answerable_class_counts"] != EXPECTED_ANSWERABLE_COUNTS or data["must_abstain_class_counts"] != EXPECTED_ABSTAIN_COUNTS:
        _fail("corpus class counts are invalid")

    cases = data["cases"]
    ids: set[str] = set()
    case_classes: Counter[str] = Counter()
    group_members: dict[str, list[dict[str, Any]]] = defaultdict(list)
    answerable_intents: set[str] = set()
    templates: dict[str, str] = {}
    fixtures_needed: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != CASE_KEYS:
            _fail("case record schema is invalid")
        case_id = case["id"]
        if not isinstance(case_id, str) or not re.fullmatch(r"[a-z0-9_]+", case_id) or case_id in ids:
            _fail("case ID is invalid or duplicated")
        ids.add(case_id)
        if not isinstance(case["intent_group"], str) or not case["intent_group"]:
            _fail(f"{case_id}: intent_group is missing")
        if case["source_order_group"] is not None:
            if not isinstance(case["source_order_group"], str):
                _fail(f"{case_id}: source_order_group must be a string or null")
            group_members[case["source_order_group"]].append(case)
        if case["class"] not in EXPECTED_ANSWERABLE_COUNTS | EXPECTED_ABSTAIN_COUNTS:
            _fail(f"{case_id}: unknown class")
        case_classes[case["class"]] += 1
        if not isinstance(case["question"], str) or not case["question"] or len(case["question"].encode("utf-8")) > DEFAULT_LIMITS["question_bytes_max"]:
            _fail(f"{case_id}: question is empty or over limit")
        evaluation_fixture = case["evaluation_fixture"]
        if not isinstance(evaluation_fixture, str) or Path(evaluation_fixture).name != evaluation_fixture or not evaluation_fixture.endswith(".trace"):
            _fail(f"{case_id}: invalid evaluation fixture name")
        fixtures_needed.add(evaluation_fixture)
        if case["behavior"] not in {"answerable", "must_abstain"}:
            _fail(f"{case_id}: invalid behavior")
        _validate_plan(case)
        plan = case["expected_plan"]
        support = case["selector_support"]
        nonnull = {key: value for key, value in plan["filters"].items() if value is not None}
        if plan["decision"] == "filter":
            if case["behavior"] != "answerable" or case["class"] not in EXPECTED_ANSWERABLE_COUNTS:
                _fail(f"{case_id}: filter plan is in a non-answerable class")
            if not isinstance(support, dict) or set(support) != set(nonnull):
                _fail(f"{case_id}: selector support must cover each and only each non-null filter")
            if case["fixture"] is None or type(case["expected_match_count"]) is not int or case["expected_match_count"] < 0:
                _fail(f"{case_id}: answerable case must name a fixture and a nonnegative match count")
            zero_match = case["expected_match_count"] == 0
            if zero_match and case["target_line"] is not None:
                _fail(f"{case_id}: zero-match query must have a null target_line")
            if not zero_match and (type(case["target_line"]) is not int or case["target_line"] < 1):
                _fail(f"{case_id}: matching query must have a positive target_line")
            if not isinstance(case["fixture"], str) or Path(case["fixture"]).name != case["fixture"] or not case["fixture"].endswith(".trace"):
                _fail(f"{case_id}: invalid fixture name")
            if evaluation_fixture != case["fixture"]:
                _fail(f"{case_id}: answerable evaluation fixture must equal its oracle fixture")
            fixtures_needed.add(case["fixture"])
            for key, value in nonnull.items():
                proof = support[key]
                if not isinstance(proof, dict) or set(proof) != {"canonical_value", "question_literal", "source_line"}:
                    _fail(f"{case_id}: support metadata for {key} has an invalid shape")
                canonical = _stringify(value)
                literal = f"[{key}={canonical}]"
                literal_pattern = rf"(?<![A-Za-z0-9_]){re.escape(literal)}(?![A-Za-z0-9_])"
                if proof["canonical_value"] != canonical or proof["question_literal"] != literal or not re.search(literal_pattern, case["question"]):
                    _fail(f"{case_id}: selector {key}={canonical} is not literally grounded in the question")
                if proof["source_line"] != case["target_line"]:
                    _fail(f"{case_id}: selector {key} support does not cite the target fixture row")
            source_group = case["source_order_group"]
            if source_group is None:
                if case["class"] == "source_order" or case["intent_group"] in answerable_intents:
                    _fail(f"{case_id}: answerable intent group is duplicated or has wrong source-order class")
                answerable_intents.add(case["intent_group"])
                template = _normalize_template(case["question"], support)
                if template in templates:
                    _fail(f"{case_id}: repeated query template with {templates[template]}")
                templates[template] = case_id
            elif case["class"] != "source_order" or case["intent_group"] != source_group:
                _fail(f"{case_id}: source-order case must share its explicit intent group")
        else:
            if case["behavior"] != "must_abstain" or case["class"] not in EXPECTED_ABSTAIN_COUNTS or support != {}:
                _fail(f"{case_id}: abstention requires an abstain class and empty support")
            if evaluation_fixture != ABSTENTION_CONTEXT_FIXTURE:
                _fail(f"{case_id}: abstention must use the shared evaluation context fixture")
            if plan["abstain_reason"] != ABSTAIN_CLASS_REASONS[case["class"]]:
                _fail(f"{case_id}: abstain reason does not match its class")
            if case["fixture"] is not None or case["target_line"] is not None or case["expected_match_count"] is not None:
                _fail(f"{case_id}: abstention must not carry a fixture, target row, or match count")
            if case["source_order_group"] is not None:
                _fail(f"{case_id}: abstention cannot be a source-order case")

    if case_classes != Counter(EXPECTED_ANSWERABLE_COUNTS) + Counter(EXPECTED_ABSTAIN_COUNTS):
        _fail("case classes do not match the declared counts")
    if len(answerable_intents) + len(group_members) != data["answerable_intent_group_count"]:
        _fail("answerable intent-group count is wrong")
    declared_groups = data["source_order_group_sizes"]
    if not isinstance(declared_groups, dict) or set(group_members) != set(declared_groups):
        _fail("declared source-order groups do not match case groups")

    fixture_hashes = data["fixture_sha256"]
    if not isinstance(fixture_hashes, dict) or set(fixture_hashes) != fixtures_needed:
        _fail("fixture digest allowlist does not exactly match referenced fixtures")
    parsed_fixtures: dict[str, list[dict[str, Any]]] = {}
    for name, digest in fixture_hashes.items():
        if not re.fullmatch(r"[a-z0-9-]+\.trace", name) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            _fail("fixture name or SHA-256 format is invalid")
        path = base_dir / name
        if path.is_symlink() or not path.is_file():
            _fail(f"fixture {name} is missing or is a link")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            _fail(f"fixture {name} SHA-256 mismatch")
        parsed_fixtures[name] = parse_trace(raw, name, DEFAULT_LIMITS)

    for case in cases:
        plan = case["expected_plan"]
        if plan["decision"] != "filter":
            continue
        rows = parsed_fixtures[case["fixture"]]
        target_line = case["target_line"]
        matches = [row for row in rows if _matches(plan["filters"], row)]
        if case["expected_match_count"] == 0:
            if target_line is not None or matches:
                _fail(f"{case['id']}: zero-match query has a target row or matches fixture evidence")
            continue
        if target_line < 1 or target_line > len(rows):
            _fail(f"{case['id']}: target line is outside fixture")
        target = rows[target_line - 1]
        if not _matches(plan["filters"], target) or case["expected_match_count"] != len(matches):
            _fail(f"{case['id']}: selector does not match the stated fixture rows/count")
        if plan["entity"] == "syscall_result" and target["syscall"] not in SYSCALLS:
            _fail(f"{case['id']}: target row is outside syscall-result schema scope")
        if plan["entity"] == "process_relation" and not all(key in target for key in ("caller_task_id", "child_pid", "relation_type")):
            _fail(f"{case['id']}: target row does not produce a process relation")

    for group_name, members in group_members.items():
        if declared_groups[group_name] != 4 or len(members) != 4:
            _fail(f"source-order group {group_name} must contain exactly four cases")
        if len({case["intent_group"] for case in members}) != 1 or members[0]["intent_group"] != group_name:
            _fail(f"source-order group {group_name} must count as one intent_group")
        if any(case["class"] != "source_order" for case in members):
            _fail(f"source-order group {group_name} has a non-source-order class")
        if len({case["question"] for case in members}) != 1:
            _fail(f"source-order group {group_name} must use an identical question across permutations")
        signatures = {json.dumps(case["expected_plan"], sort_keys=True) for case in members}
        if len(signatures) != 1:
            _fail(f"source-order group {group_name} has differing expected plans")
        fixture_names = [case["fixture"] for case in members]
        if len(set(fixture_names)) != 4:
            _fail(f"source-order group {group_name} must reference four distinct fixtures")
        fact_sets = [
            sorted(json.dumps({k: v for k, v in row.items() if k != "line"}, sort_keys=True) for row in parsed_fixtures[name])
            for name in fixture_names
        ]
        if any(fact_set != fact_sets[0] for fact_set in fact_sets[1:]):
            _fail(f"source-order group {group_name} fixtures do not contain the same facts")
        target_lines = {case["target_line"] for case in members}
        if len(target_lines) != 4:
            _fail(f"source-order group {group_name} does not move the target across four ordinals")

    return {
        "cases": len(cases),
        "answerable": sum(EXPECTED_ANSWERABLE_COUNTS.values()),
        "must_abstain": sum(EXPECTED_ABSTAIN_COUNTS.values()),
        "answerable_intent_groups": data["answerable_intent_group_count"],
        "source_order_groups": len(group_members),
        "fixture_files": len(parsed_fixtures),
        "fully_supported_answerable_cases": 80,
        "zero_match_cases": sum(1 for case in cases if case["expected_match_count"] == 0),
    }


def validate_path(corpus_path: Path = ROOT / "corpus.json") -> dict[str, int]:
    raw = corpus_path.read_bytes()
    data = _load_json(raw, DEFAULT_LIMITS["corpus_bytes_max"], "corpus")
    return validate_data(data, corpus_path.parent, len(raw))


if __name__ == "__main__":
    try:
        summary = validate_path(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "corpus.json")
    except (CorpusError, OSError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print("VALID public development corpus (not hidden holdout or release-quality evidence)")
    for key, value in summary.items():
        print(f"{key}: {value}")
