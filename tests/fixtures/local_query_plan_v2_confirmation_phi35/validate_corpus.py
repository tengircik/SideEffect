#!/usr/bin/env python3
"""Validate Phi-3.5 corpus with SideEffect preview and evaluator fixture helpers."""
from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[2]
FIELDS = {"syscall", "outcome", "observed_errno", "lexical_path_exact", "process_id", "caller_task_id", "child_pid", "relation_type"}
SYSCALLS = {"execve", "execveat", "openat", "openat2", "connect"}
OUTCOMES = {"success", "failure", "in_progress", "unknown"}
RELATIONS = {"fork", "vfork", "clone", "clone3"}
REASONS = {"ambiguous", "unsupported_scope", "insufficient_evidence"}
ANSWERABLE_CLASSES = {"answerable", "single_predicate", "conjunction", "paraphrase", "multi_match", "process_relation", "no_match"}
ABSTAIN_CLASSES = {"unsupported", "insufficient", "ambiguous", "adversarial"}
PROMPT_RELATIVE = Path("tests/fixtures/local_query_plan_v2_confirmation/experimental-two-shot-system-prompt.txt")
PROMPT_SHA256 = "ef343d6996d9bd0fc0e881224374fa78ca574d1ab5826a65b86e1e9505025ef1"


def evaluator_module() -> Any:
    source = REPOSITORY / "scripts" / "evaluate_local_query_plan.py"
    spec = importlib.util.spec_from_file_location("phi35_corpus_evaluator", source)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not import repository evaluator helpers")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def validate_plan(case: dict[str, Any], errnos: set[str]) -> dict[str, Any]:
    p = case["expected_plan"]
    if set(p) != {"decision", "abstain_reason", "entity", "filters", "combine"}:
        raise ValueError(f"{case['id']}: strict v2 plan keys mismatch")
    f = p["filters"]
    if not isinstance(f, dict) or set(f) != FIELDS or p["combine"] != "all":
        raise ValueError(f"{case['id']}: strict filter object/combine mismatch")
    if case["expected_behavior"] == "must_abstain":
        if p["decision"] != "abstain" or p["entity"] is not None or p["abstain_reason"] not in REASONS or any(v is not None for v in f.values()):
            raise ValueError(f"{case['id']}: invalid abstention plan")
        if case["class"] not in ABSTAIN_CLASSES:
            raise ValueError(f"{case['id']}: abstention class outside registered taxonomy")
        return p
    if p["decision"] != "filter" or p["entity"] not in {"syscall_result", "process_relation"} or p["abstain_reason"] is not None:
        raise ValueError(f"{case['id']}: invalid filter plan header")
    if case["expected_behavior"] != "answerable" or not any(v is not None for v in f.values()):
        raise ValueError(f"{case['id']}: filter must select at least one field")
    if case["class"] not in ANSWERABLE_CLASSES:
        raise ValueError(f"{case['id']}: answerable class outside registered taxonomy")
    if f["syscall"] is not None and f["syscall"] not in SYSCALLS:
        raise ValueError(f"{case['id']}: unsupported syscall")
    if f["outcome"] is not None and f["outcome"] not in OUTCOMES:
        raise ValueError(f"{case['id']}: unsupported outcome")
    if f["observed_errno"] is not None and f["observed_errno"] not in errnos:
        raise ValueError(f"{case['id']}: unsupported errno")
    if f["relation_type"] is not None and f["relation_type"] not in RELATIONS:
        raise ValueError(f"{case['id']}: unsupported relation type")
    for key in ("process_id", "caller_task_id", "child_pid"):
        value = f[key]
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 4294967295):
            raise ValueError(f"{case['id']}: invalid {key}")
    for key, cap in (("observed_errno", 32), ("lexical_path_exact", 256)):
        value = f[key]
        if value is not None and (not isinstance(value, str) or not value or len(value.encode("utf-8")) > cap):
            raise ValueError(f"{case['id']}: invalid {key}")
    if p["entity"] == "syscall_result":
        if any(f[k] is not None for k in ("caller_task_id", "child_pid", "relation_type")):
            raise ValueError(f"{case['id']}: cross-entity relation selector")
    elif any(f[k] is not None for k in ("syscall", "outcome", "observed_errno", "lexical_path_exact")):
        raise ValueError(f"{case['id']}: cross-entity syscall selector")
    question = case["question"].casefold()
    for key, value in f.items():
        if value is None:
            continue
        if key == "outcome":
            synonyms = {"success": ("success", "successful"), "failure": ("failure", "failed"),
                        "in_progress": ("in progress",), "unknown": ("unknown",)}[value]
            if not any(word in question for word in synonyms):
                raise ValueError(f"{case['id']}: outcome not stated by question")
        elif str(value).casefold() not in question:
            raise ValueError(f"{case['id']}: {key} not stated by question")
    return p


def validate_permutation(corpus: dict[str, Any]) -> None:
    cases = {c["id"]: c for c in corpus["cases"]}
    groups = corpus.get("source_order_groups")
    if not isinstance(groups, list) or not groups:
        raise ValueError("a four-way source-order group is required")
    for group in groups:
        members = [cases[cid] for cid in group["case_ids"]]
        traces = group["traces"]
        if len(members) != 4 or len(traces) != 4 or len(set(traces)) != 4:
            raise ValueError(f"{group['id']}: expected four unique variants")
        if [case["trace"] for case in members] != traces:
            raise ValueError(f"{group['id']}: case/trace mapping mismatch")
        if any(case["expected_plan"] != group["invariant_expected_plan"] for case in members):
            raise ValueError(f"{group['id']}: expected plan changes by source order")
        if any(case.get("source_order_group") != group["id"] for case in members):
            raise ValueError(f"{group['id']}: group membership not pinned separately")
        rows = [(ROOT / name).read_text("ascii").splitlines() for name in traces]
        if any(len(rowset) != group["fact_count"] for rowset in rows):
            raise ValueError(f"{group['id']}: row count mismatch")
        base = collections.Counter(rows[0])
        if any(collections.Counter(rowset) != base for rowset in rows[1:]):
            raise ValueError(f"{group['id']}: source-order variants do not share the same rows")
        positions = {row: [rowset.index(row) for rowset in rows] for row in base}
        if any(len(set(ps)) != 4 for ps in positions.values()):
            raise ValueError(f"{group['id']}: each row must visit four distinct ordinals")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sideeffect", required=True, type=Path, help="Built Linux release executable")
    args = parser.parse_args()
    binary = args.sideeffect.resolve(strict=True)
    if not binary.is_file():
        parser.error("--sideeffect must name a regular file")
    evaluator = evaluator_module()
    raw = (ROOT / "corpus.json").read_bytes()
    if len(raw) > evaluator.MAX_CORPUS_BYTES:
        raise ValueError("corpus exceeds evaluator byte limit")
    corpus = json.loads(raw.decode("utf-8"))
    cases = corpus["cases"]
    if corpus.get("case_count") != 40 or len(cases) != 40:
        raise ValueError("expected exactly 40 cases")
    if corpus.get("class_counts") != {"answerable": 24, "must_abstain": 16}:
        raise ValueError("aggregate case counts must be 24/16")
    if sum(c["expected_behavior"] == "answerable" for c in cases) != 24 or sum(c["expected_behavior"] == "must_abstain" for c in cases) != 16:
        raise ValueError("case behavior balance is not 24/16")
    if len({c["id"] for c in cases}) != 40:
        raise ValueError("case IDs must be unique")
    if dict(collections.Counter(c["class"] for c in cases)) != corpus.get("class_distribution"):
        raise ValueError("registered class distribution mismatch")
    prompt_ref = corpus["prompt_reference"]
    prompt = (REPOSITORY / PROMPT_RELATIVE).read_bytes()
    if (prompt_ref.get("path") != "../local_query_plan_v2_confirmation/experimental-two-shot-system-prompt.txt"
        or prompt_ref.get("byte_length") != len(prompt)
        or prompt_ref.get("sha256") != PROMPT_SHA256
        or hashlib.sha256(prompt).hexdigest() != PROMPT_SHA256):
        raise ValueError("pinned existing prompt reference mismatch")
    for name, pin in corpus["traces"].items():
        data = (ROOT / name).read_bytes()
        if pin.get("status") != "synthetic_fixture_not_a_capture" or len(data) != pin.get("byte_length") or hashlib.sha256(data).hexdigest() != pin.get("sha256"):
            raise ValueError(f"trace hash/length mismatch: {name}")
    validate_permutation(corpus)
    errnos = set(evaluator.EXPECTED_QUERY_ERRNOS)
    for case in cases:
        if case["trace"] not in corpus["traces"]:
            raise ValueError(f"{case['id']}: trace not registered")
        plan = validate_plan(case, errnos)
        trace = ROOT / case["trace"]
        data = trace.read_bytes()
        result = subprocess.run([str(binary), "model-query-preview", "--question", case["question"], str(trace)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        if result.returncode not in (0, 2):
            raise ValueError(f"{case['id']}: preview failed with status {result.returncode}")
        preview = json.loads(result.stdout.decode("utf-8"))
        evaluator._validate_preview(preview, {"question": case["question"]}, data)
        facts = evaluator.facts_with_ids(preview)
        match_class = "must_abstain" if case["expected_behavior"] == "must_abstain" else case["class"]
        evaluator.validate_expected_fact_matches(
            {"id": case["id"], "class": match_class,
             "expected_behavior": case["expected_behavior"], "expected_plan": plan}, facts,
        )
    print(f"passed: {len(cases)} current preview/evaluator fixture checks; no model inference")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
