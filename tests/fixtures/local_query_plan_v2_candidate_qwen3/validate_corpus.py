#!/usr/bin/env python3
"""Validate the Qwen3-4B development corpus with preview-only Rust checks."""
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
REFERENCE_VALIDATOR = (
    REPOSITORY
    / "tests"
    / "fixtures"
    / "local_query_plan_v2_confirmation_olmo2"
    / "validate_corpus.py"
)


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load validator module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sideeffect", required=True, type=Path, help="Built Linux SideEffect executable")
    parser.add_argument(
        "--expected-model-sha256",
        required=True,
        help="SHA-256 of the selected user-provided model used for exact preview-pin checks",
    )
    args = parser.parse_args()
    if len(args.expected_model_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in args.expected_model_sha256
    ):
        parser.error("--expected-model-sha256 must be 64 lowercase hexadecimal characters")
    binary = args.sideeffect.resolve(strict=True)
    if not binary.is_file():
        parser.error("--sideeffect must name a regular file")

    evaluator = load_module("qwen3_candidate_evaluator", REPOSITORY / "scripts" / "evaluate_local_query_plan.py")
    evaluator.EXPECTED_MODEL_SHA256 = args.expected_model_sha256
    contract = load_module("qwen3_candidate_contract", REFERENCE_VALIDATOR)
    contract.ROOT = ROOT

    corpus_bytes = (ROOT / "corpus.json").read_bytes()
    if len(corpus_bytes) > evaluator.MAX_CORPUS_BYTES:
        raise ValueError("corpus exceeds the evaluator byte cap")
    corpus = json.loads(corpus_bytes.decode("utf-8"))
    cases = corpus["cases"]
    if corpus.get("status") != "development_only_not_a_holdout" or len(cases) != 40:
        raise ValueError("expected the 40-case development-only corpus")
    if len({case["id"] for case in cases}) != 40:
        raise ValueError("case IDs must be unique")
    if sum(case["expected_behavior"] == "answerable" for case in cases) != 24:
        raise ValueError("expected 24 answerable cases")
    if sum(case["expected_behavior"] == "must_abstain" for case in cases) != 16:
        raise ValueError("expected 16 must-abstain cases")
    answerable_classes = {
        "answerable",
        "single_predicate",
        "conjunction",
        "paraphrase",
        "multi_match",
        "process_relation",
        "no_match",
    }
    abstain_classes = {"unsupported", "insufficient", "ambiguous", "adversarial"}
    for case in cases:
        allowed = answerable_classes if case["expected_behavior"] == "answerable" else abstain_classes
        if case["class"] not in allowed:
            raise ValueError(f"{case['id']}: class does not match expected behavior")

    errnos = set(evaluator.EXPECTED_QUERY_ERRNOS)
    for name, pin in corpus["trace_sha256"].items():
        if pin.get("status") != "synthetic_fixture_not_a_capture":
            raise ValueError(f"{name}: fixture status is not explicit")
        data = (ROOT / name).read_bytes()
        if len(data) != pin.get("byte_length") or hashlib.sha256(data).hexdigest() != pin.get("sha256"):
            raise ValueError(f"{name}: length or SHA-256 mismatch")
    contract.validate_permutation(corpus)

    for case in cases:
        plan = contract.validate_plan(case, errnos)
        if case["trace"] not in corpus["trace_sha256"] or Path(case["trace"]).name != case["trace"]:
            raise ValueError(f"{case['id']}: trace name is not a registered basename")
        trace_path = ROOT / case["trace"]
        trace_bytes = trace_path.read_bytes()
        result = subprocess.run(
            [str(binary), "model-query-preview", "--question", case["question"], str(trace_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if result.returncode not in (0, 2):
            raise ValueError(f"{case['id']}: preview exited {result.returncode}")
        preview = json.loads(result.stdout.decode("utf-8"))
        evaluator._validate_preview(preview, {"question": case["question"]}, trace_bytes)
        facts = evaluator.facts_with_ids(preview)
        check_class = (
            "must_abstain"
            if case["expected_behavior"] == "must_abstain"
            else "no_match"
            if case["class"] == "no_match"
            else case["class"]
        )
        evaluator.validate_expected_fact_matches(
            {
                "id": case["id"],
                "class": check_class,
                "expected_behavior": case["expected_behavior"],
                "expected_plan": plan,
            },
            facts,
        )

    print(f"passed: {len(cases)} preview-only contract and fixture checks; no model inference")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f"validation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
