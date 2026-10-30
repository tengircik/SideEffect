#!/usr/bin/env python3
"""Validate OLMo-2 corpus plans using preview and fixture-only evaluator helpers."""
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


def load_evaluator() -> Any:
    path = REPOSITORY / "scripts" / "evaluate_local_query_plan.py"
    spec = importlib.util.spec_from_file_location("olmo2_corpus_evaluator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load repository evaluator helpers")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def validate_plan(case: dict[str, Any], errnos: set[str]) -> dict[str, Any]:
    plan = case["expected_plan"]
    if set(plan) != {"decision", "abstain_reason", "entity", "filters", "combine"}:
        raise ValueError(f"{case['id']}: expected exact strict v2 plan keys")
    f = plan["filters"]
    if not isinstance(f, dict) or set(f) != FIELDS or plan["combine"] != "all":
        raise ValueError(f"{case['id']}: filter object/combine mismatch")
    if plan["decision"] == "abstain":
        if plan["entity"] is not None or plan["abstain_reason"] not in REASONS or any(v is not None for v in f.values()):
            raise ValueError(f"{case['id']}: malformed abstention plan")
        if case["expected_behavior"] != "must_abstain":
            raise ValueError(f"{case['id']}: abstention label mismatch")
        return plan
    if plan["decision"] != "filter" or plan["entity"] not in {"syscall_result", "process_relation"} or plan["abstain_reason"] is not None:
        raise ValueError(f"{case['id']}: malformed filter header")
    if case["expected_behavior"] != "answerable" or not any(v is not None for v in f.values()):
        raise ValueError(f"{case['id']}: filters require selectors and answerable label")
    if f["syscall"] is not None and f["syscall"] not in SYSCALLS:
        raise ValueError(f"{case['id']}: unsupported syscall enum")
    if f["outcome"] is not None and f["outcome"] not in OUTCOMES:
        raise ValueError(f"{case['id']}: unsupported outcome enum")
    if f["observed_errno"] is not None and f["observed_errno"] not in errnos:
        raise ValueError(f"{case['id']}: unsupported errno")
    if f["relation_type"] is not None and f["relation_type"] not in RELATIONS:
        raise ValueError(f"{case['id']}: unsupported relation enum")
    for key in ("process_id", "caller_task_id", "child_pid"):
        v = f[key]
        if v is not None and (not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 4294967295):
            raise ValueError(f"{case['id']}: invalid {key}")
    for key, limit in (("observed_errno", 32), ("lexical_path_exact", 256)):
        v = f[key]
        if v is not None and (not isinstance(v, str) or not v or len(v.encode("utf-8")) > limit):
            raise ValueError(f"{case['id']}: invalid {key}")
    if plan["entity"] == "syscall_result":
        if any(f[k] is not None for k in ("caller_task_id", "child_pid", "relation_type")):
            raise ValueError(f"{case['id']}: process selector on syscall-result entity")
    elif any(f[k] is not None for k in ("syscall", "outcome", "observed_errno", "lexical_path_exact")):
        raise ValueError(f"{case['id']}: syscall selector on process-relation entity")
    question = case["question"].casefold()
    for key, value in f.items():
        if value is None:
            continue
        if key == "outcome":
            synonyms = {"success": ("success", "successful"), "failure": ("failure", "failed"),
                        "in_progress": ("in progress",), "unknown": ("unknown",)}[value]
            if not any(word in question for word in synonyms):
                raise ValueError(f"{case['id']}: outcome not specified by question")
        elif str(value).casefold() not in question:
            raise ValueError(f"{case['id']}: {key} not specified by question")
    return plan


def validate_permutation(corpus: dict[str, Any]) -> None:
    cases = {c["id"]: c for c in corpus["cases"]}
    groups = corpus.get("permutation_groups")
    if not isinstance(groups, list) or not groups:
        raise ValueError("a four-way order permutation group is required")
    for group in groups:
        members = [cases[cid] for cid in group["case_ids"]]
        traces = group["traces"]
        if len(members) != 4 or len(traces) != 4 or len(set(traces)) != 4:
            raise ValueError(f"{group['id']}: expected four distinct fixture variants")
        if [c["trace"] for c in members] != traces:
            raise ValueError(f"{group['id']}: case and fixture order mismatch")
        if any(c["expected_plan"] != group["invariant_expected_plan"] for c in members):
            raise ValueError(f"{group['id']}: expected plan varies across orderings")
        rows = [(ROOT / name).read_text("ascii").splitlines() for name in traces]
        if any(len(rowset) != group["fact_count"] for rowset in rows):
            raise ValueError(f"{group['id']}: fact count mismatch")
        base = collections.Counter(rows[0])
        if any(collections.Counter(rowset) != base for rowset in rows[1:]):
            raise ValueError(f"{group['id']}: variants do not share identical rows")
        ordinals = {row: [rowset.index(row) for rowset in rows] for row in base}
        if any(len(set(xs)) != 4 for xs in ordinals.values()):
            raise ValueError(f"{group['id']}: each row must move through four ordinal positions")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sideeffect", required=True, type=Path, help="Built Linux release executable")
    args = parser.parse_args()
    binary = args.sideeffect.resolve(strict=True)
    if not binary.is_file():
        parser.error("--sideeffect must name a regular file")
    evaluator = load_evaluator()
    body = (ROOT / "corpus.json").read_bytes()
    if len(body) > evaluator.MAX_CORPUS_BYTES:
        raise ValueError("corpus exceeds evaluator byte cap")
    corpus = json.loads(body.decode("utf-8"))
    cases = corpus["cases"]
    if corpus.get("case_count") != 40 or len(cases) != 40:
        raise ValueError("expected exactly 40 cases")
    if sum(c["expected_behavior"] == "answerable" for c in cases) != 24 or sum(c["expected_behavior"] == "must_abstain" for c in cases) != 16:
        raise ValueError("case classes must be 24 answerable and 16 must-abstain")
    if corpus.get("class_counts") != {"answerable": 24, "must_abstain": 16}:
        raise ValueError("aggregate class counts must remain 24/16")
    observed_classes = collections.Counter(c["class"] for c in cases)
    if corpus.get("class_distribution") != dict(observed_classes):
        raise ValueError("registered class distribution does not match cases")
    for case in cases:
        allowed = ANSWERABLE_CLASSES if case["expected_behavior"] == "answerable" else ABSTAIN_CLASSES
        if case["class"] not in allowed:
            raise ValueError(f"{case['id']}: class is outside the registered evaluator taxonomy")
    if len({c["id"] for c in cases}) != 40:
        raise ValueError("case IDs must be unique")
    prompt = corpus["prompt_reference"]
    prompt_bytes = (REPOSITORY / PROMPT_RELATIVE).read_bytes()
    if (prompt["path"] != "../local_query_plan_v2_confirmation/experimental-two-shot-system-prompt.txt"
        or prompt["byte_length"] != len(prompt_bytes)
        or prompt["sha256"] != hashlib.sha256(prompt_bytes).hexdigest()):
        raise ValueError("existing two-shot prompt reference is not pinned correctly")
    pins = corpus["traces"]
    for name, pin in pins.items():
        data = (ROOT / name).read_bytes()
        if pin.get("status") != "synthetic_fixture_not_a_capture" or len(data) != pin.get("byte_length") or hashlib.sha256(data).hexdigest() != pin.get("sha256"):
            raise ValueError(f"trace integrity mismatch: {name}")
    validate_permutation(corpus)
    errnos = set(evaluator.EXPECTED_QUERY_ERRNOS)
    for case in cases:
        if case["trace"] not in pins:
            raise ValueError(f"{case['id']}: trace not registered")
        plan = validate_plan(case, errnos)
        trace = ROOT / case["trace"]
        trace_bytes = trace.read_bytes()
        result = subprocess.run([str(binary), "model-query-preview", "--question", case["question"], str(trace)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        if result.returncode not in (0, 2):
            raise ValueError(f"{case['id']}: preview exited {result.returncode}")
        preview = json.loads(result.stdout.decode("utf-8"))
        evaluator._validate_preview(preview, {"question": case["question"]}, trace_bytes)
        facts = evaluator.facts_with_ids(preview)
        if case["expected_behavior"] == "must_abstain":
            check_class = "must_abstain"
        elif case["class"] == "no_match":
            check_class = "no_match"
        else:
            check_class = case["class"]
        evaluator.validate_expected_fact_matches(
            {"id": case["id"], "class": check_class,
             "expected_behavior": case["expected_behavior"], "expected_plan": plan}, facts,
        )
    print(f"passed: {len(cases)} preview/evaluator fixture checks; no model inference")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
