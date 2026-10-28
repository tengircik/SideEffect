#!/usr/bin/env python3
"""Validate the flat development corpus against bounded current preview facts."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[2]
FIELDS = (
    "syscall", "outcome", "observed_errno", "lexical_path_exact", "process_id",
    "caller_task_id", "child_pid", "relation_type",
)
SYSCALLS = {"execve", "execveat", "openat", "openat2", "connect"}
OUTCOMES = {"success", "failure", "in_progress", "unknown"}
RELATIONS = {"fork", "vfork", "clone", "clone3"}
REASONS = {"ambiguous", "unsupported_scope", "insufficient_evidence"}


def load_evaluator() -> Any:
    path = REPOSITORY / "scripts" / "evaluate_local_query_plan.py"
    spec = importlib.util.spec_from_file_location("sideeffect_query_plan_evaluator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the repository's pinned query-plan evaluator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def check_flat_plan(case: dict[str, Any], errno_values: set[str]) -> dict[str, Any]:
    plan = case["expected_plan"]
    if set(plan) != {"decision", "abstain_reason", "entity", *FIELDS}:
        raise ValueError(f"{case['id']}: flat plan keys differ from the v1 schema")
    decision, entity = plan["decision"], plan["entity"]
    selectors = {field: plan[field] for field in FIELDS}
    if decision == "abstain":
        if entity is not None or any(value is not None for value in selectors.values()):
            raise ValueError(f"{case['id']}: abstention must null entity and selectors")
        if plan["abstain_reason"] not in REASONS:
            raise ValueError(f"{case['id']}: invalid abstention reason")
        if case["expected_behavior"] != "must_abstain":
            raise ValueError(f"{case['id']}: abstention behavior label disagrees")
    elif decision == "filter":
        if entity not in {"syscall_result", "process_relation"} or plan["abstain_reason"] is not None:
            raise ValueError(f"{case['id']}: invalid filter decision/entity/reason")
        if case["expected_behavior"] != "answerable":
            raise ValueError(f"{case['id']}: filter behavior label disagrees")
        if selectors["syscall"] is not None and selectors["syscall"] not in SYSCALLS:
            raise ValueError(f"{case['id']}: syscall is outside the closed enum")
        if selectors["outcome"] is not None and selectors["outcome"] not in OUTCOMES:
            raise ValueError(f"{case['id']}: outcome is outside the closed enum")
        if selectors["relation_type"] is not None and selectors["relation_type"] not in RELATIONS:
            raise ValueError(f"{case['id']}: relation type is outside the closed enum")
        if selectors["observed_errno"] is not None and selectors["observed_errno"] not in errno_values:
            raise ValueError(f"{case['id']}: errno is outside the closed enum")
        for key in ("process_id", "caller_task_id", "child_pid"):
            value = selectors[key]
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 4294967295):
                raise ValueError(f"{case['id']}: {key} must be a positive u32")
        for key in ("observed_errno", "lexical_path_exact"):
            value = selectors[key]
            limit = 32 if key == "observed_errno" else 256
            if value is not None and (not isinstance(value, str) or not value or len(value.encode("utf-8")) > limit):
                raise ValueError(f"{case['id']}: {key} must be a nonempty string within its byte limit")
        if entity == "syscall_result" and any(selectors[k] is not None for k in ("caller_task_id", "child_pid", "relation_type")):
            raise ValueError(f"{case['id']}: relation selector used on syscall-result entity")
        if entity == "process_relation" and any(selectors[k] is not None for k in ("syscall", "outcome", "observed_errno", "lexical_path_exact")):
            raise ValueError(f"{case['id']}: syscall selector used on process-relation entity")
    else:
        raise ValueError(f"{case['id']}: decision is outside the closed enum")
    # The flat candidate differs only in structural shape. Fixture checks use the current
    # product contract, without changing the Rust validator or product schema.
    return {
        "decision": decision,
        "abstain_reason": plan["abstain_reason"],
        "entity": entity,
        "filters": selectors,
        "combine": "all",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sideeffect", type=Path, required=True, help="Built release sideeffect executable")
    args = parser.parse_args()
    binary = args.sideeffect.resolve(strict=True)
    if not binary.is_file():
        parser.error("--sideeffect must name a regular file")
    evaluator = load_evaluator()
    corpus_path = ROOT / "corpus.json"
    raw = corpus_path.read_bytes()
    if len(raw) > 128 * 1024:
        raise ValueError("corpus exceeds evaluator size limit")
    corpus = json.loads(raw.decode("utf-8"))
    errno_values = corpus["plan_schema"].get("observed_errno_values")
    if not isinstance(errno_values, list) or not errno_values or len(errno_values) != len(set(errno_values)):
        raise ValueError("plan schema must list unique closed errno values")
    if errno_values != evaluator.EXPECTED_QUERY_ERRNOS:
        raise ValueError("closed errno enum differs from the repository's supported errno values")
    cases = corpus["cases"]
    if corpus["case_count"] != 32 or len(cases) != 32:
        raise ValueError("expected exactly 32 cases")
    if sum(c["expected_behavior"] == "answerable" for c in cases) != 20 or sum(c["expected_behavior"] == "must_abstain" for c in cases) != 12:
        raise ValueError("expected exactly 20 answerable and 12 must-abstain cases")
    ids: set[str] = set()
    for name, pin in corpus["traces"].items():
        trace = ROOT / name
        data = trace.read_bytes()
        if pin["status"] != "synthetic_fixture_not_a_capture" or len(data) != pin["byte_length"] or hashlib.sha256(data).hexdigest() != pin["sha256"]:
            raise ValueError(f"fixture integrity mismatch: {name}")
    for case in cases:
        if case["id"] in ids:
            raise ValueError("duplicate case ID")
        ids.add(case["id"])
        if case["trace"] not in corpus["traces"]:
            raise ValueError(f"{case['id']}: unpinned fixture")
        product_plan = check_flat_plan(case, set(errno_values))
        trace = ROOT / case["trace"]
        trace_bytes = trace.read_bytes()
        completed = subprocess.run(
            [str(binary), "model-query-preview", "--question", case["question"], str(trace)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
        )
        if completed.returncode not in (0, 2):
            raise ValueError(f"{case['id']}: preview failed with status {completed.returncode}")
        preview = json.loads(completed.stdout.decode("utf-8"))
        evaluator._validate_preview(preview, {"question": case["question"]}, trace_bytes)
        facts = evaluator.facts_with_ids(preview)
        if case["expected_behavior"] == "must_abstain":
            expected_class = "must_abstain"
        elif case["class"] == "deliberate_no_match":
            expected_class = "no_match"
        elif case["class"] == "multi_match":
            expected_class = "multi_match"
        else:
            expected_class = "single_predicate"
        evaluator.validate_expected_fact_matches(
            {"id": case["id"], "class": expected_class,
             "expected_behavior": case["expected_behavior"], "expected_plan": product_plan},
            facts,
        )
    print(f"passed: {len(cases)} current preview and evaluator fixture checks; no model inference")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"validation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
