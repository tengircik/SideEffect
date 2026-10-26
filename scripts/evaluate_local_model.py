#!/usr/bin/env python3
"""Interactively evaluate SideEffect's opt-in local model on synthetic traces."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def run(arguments: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments, capture_output=True, text=True, check=False, timeout=timeout
    )


def is_match(selected: list[str], expected: list[str]) -> bool:
    if not expected:
        return not selected
    return len(selected) == 1 and selected[0] in expected


def deterministic_selection(preview: dict[str, Any]) -> list[str]:
    """Select one matching typed fact without model inference."""
    try:
        prompt = json.loads(preview["prompt"])
        facts = prompt["observed_syscall_results"]
        question = prompt["user_question"].lower()
    except (KeyError, TypeError, json.JSONDecodeError):
        return []

    words = {word.strip(".,?!:;()[]{}\"'") for word in question.split()}
    syscall_matches = [
        fact for fact in facts if fact.get("syscall", "").lower() in words
    ]
    candidates = syscall_matches or facts
    if any(
        term in words
        for term in ("failed", "failure", "error", "denied", "unsuccessful")
    ):
        candidates = [
            fact
            for fact in candidates
            if fact.get("outcome") in ("failure", "in_progress")
        ]
    elif any(term in words for term in ("succeeded", "success", "successful")):
        candidates = [fact for fact in candidates if fact.get("outcome") == "success"]

    if not candidates:
        return []
    evidence_id = candidates[0].get("evidence_id")
    return [evidence_id] if isinstance(evidence_id, str) else []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sideeffect", required=True, type=Path, help="Built SideEffect executable")
    parser.add_argument("--runtime", required=True, type=Path, help="Reviewed local llama.cpp llama-cli")
    parser.add_argument("--model", required=True, type=Path, help="Manually obtained pinned GGUF model")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "tests/fixtures/local_model_synthetic/corpus.json",
        help="Synthetic corpus metadata JSON",
    )
    args = parser.parse_args()

    root = args.corpus.resolve(strict=True).parent
    corpus: dict[str, Any] = json.loads(args.corpus.read_text(encoding="utf-8"))
    if corpus.get("schema") != "sideeffect.local_model_evaluation_corpus":
        parser.error("unsupported evaluation corpus schema")

    outcomes: list[dict[str, Any]] = []
    for case in corpus["cases"]:
        trace = (root / case["trace"]).resolve(strict=True)
        if trace.parent != root or not trace.is_file():
            parser.error(f"trace must be a regular file directly under the corpus directory: {case['id']}")

        preview_result = run(
            [str(args.sideeffect), "model-preview", "--question", case["question"], str(trace)]
        )
        if preview_result.returncode not in (0, 2):
            print(f"{case['id']}: preview failed: {preview_result.stderr.strip()}", file=sys.stderr)
            return 1
        try:
            preview = json.loads(preview_result.stdout)
        except json.JSONDecodeError:
            print(f"{case['id']}: preview did not return JSON", file=sys.stderr)
            return 1

        print(f"\n[{case['id']}] {case['question']}")
        print(f"Parse status: {preview['evidence_summary']['parse_status']}")
        print(f"Model SHA-256: {preview['model_sha256']}")
        print(f"Model repository revision: {preview['model_repository_revision']}")
        print(f"Runtime source revision: {preview['runtime_source_revision']}")
        print(f"System prompt: {preview['system_prompt']}")
        print(f"Model facts: {preview['prompt']}")
        print(f"Allowed output schema: {json.dumps(preview['output_schema'], sort_keys=True)}")
        deterministic = deterministic_selection(preview)
        print(f"Question-aware deterministic selection: {deterministic}")
        digest = preview["request_sha256"]
        confirmation = input(f"Review the request, then type its digest to run: {digest}\n> ").strip()
        if confirmation != digest:
            print("Request was not confirmed; stopping without running this or later cases.", file=sys.stderr)
            return 1

        started = time.perf_counter()
        analysis_result = run(
            [
                str(args.sideeffect),
                "model-analyze",
                "--question",
                case["question"],
                "--runtime",
                str(args.runtime),
                "--model",
                str(args.model),
                "--confirm-sha256",
                digest,
                str(trace),
            ],
            timeout=150,
        )
        elapsed = time.perf_counter() - started
        expected_parse = case.get("expected_parse_status", "complete")
        expected_exit = 2 if expected_parse == "partial" else 0
        if analysis_result.returncode != expected_exit:
            print(
                f"{case['id']}: model run failed with exit {analysis_result.returncode}: "
                f"{analysis_result.stderr.strip()}",
                file=sys.stderr,
            )
            outcomes.append({"id": case["id"], "valid": False, "elapsed_seconds": elapsed})
            continue
        try:
            analysis = json.loads(analysis_result.stdout)
            selected = analysis["selection"]["evidence_ids"]
        except (json.JSONDecodeError, KeyError, TypeError):
            print(f"{case['id']}: model output did not match the analysis contract", file=sys.stderr)
            outcomes.append({"id": case["id"], "valid": False, "elapsed_seconds": elapsed})
            continue

        expected = case["expected_evidence_ids"]
        baseline = case["outcome_priority_baseline"]
        model_match = is_match(selected, expected)
        baseline_match = is_match(baseline, expected)
        deterministic_match = is_match(deterministic, expected)
        outcomes.append(
            {
                "id": case["id"],
                "selected": selected,
                "expected_evidence_ids": expected,
                "model_match": model_match,
                "baseline_match": baseline_match,
                "query_aware_deterministic_selection": deterministic,
                "query_aware_deterministic_match": deterministic_match,
                "elapsed_seconds": elapsed,
            }
        )
        print(
            f"Selected: {selected}; expected set: {expected}; "
            f"model={'PASS' if model_match else 'FAIL'}; "
            f"outcome-priority baseline={'PASS' if baseline_match else 'FAIL'}; "
            f"query-aware deterministic baseline={'PASS' if deterministic_match else 'FAIL'}; "
            f"elapsed={elapsed:.2f}s"
        )

    valid = [case for case in outcomes if "model_match" in case]
    print("\nEvaluation summary")
    print(json.dumps(outcomes, indent=2))
    if valid:
        model_correct = sum(case["model_match"] for case in valid)
        baseline_correct = sum(case["baseline_match"] for case in valid)
        deterministic_correct = sum(case["query_aware_deterministic_match"] for case in valid)
        print(
            f"Scored: {len(valid)}/{len(corpus['cases'])}; "
            f"model: {model_correct}/{len(valid)}; "
            f"outcome-priority baseline: {baseline_correct}/{len(valid)}; "
            f"query-aware deterministic baseline: {deterministic_correct}/{len(valid)}"
        )
    return 0 if len(valid) == len(corpus["cases"]) and all(case["model_match"] for case in valid) else 2


if __name__ == "__main__":
    raise SystemExit(main())
