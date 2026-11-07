#!/usr/bin/env python3
"""Evaluate public v3 query-plan development cases through the SideEffect CLI.

This tool reports diagnostics only. The public labels have not been independently
reviewed and no score from this script qualifies a model.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import evaluate_local_query_plan as v2


REPOSITORY = Path(__file__).resolve().parents[1]
CORPUS_DIR = REPOSITORY / "tests" / "fixtures" / "local_query_plan_v3_development"
CORPUS_PATH = CORPUS_DIR / "corpus.json"
MAX_CORPUS_BYTES = 512 * 1024
MAX_FIXTURE_BYTES = 128 * 1024
MAX_FIXTURE_TOTAL_BYTES = 512 * 1024
MAX_MODEL_BYTES = v2.MAX_MODEL_BYTES
MAX_CHILD_OUTPUT_BYTES = v2.MAX_CHILD_OUTPUT_BYTES
MAX_SIDEEFFECT_BYTES = 256 * 1024 * 1024
PREVIEW_TIMEOUT_SECONDS = 30
ANALYSIS_TIMEOUT_SECONDS = 120
EXPECTED_CASES = 120
RUNTIME_VERSION = v2.EXPECTED_RUNTIME_VERSION
RUNTIME_REVISION = v2.EXPECTED_RUNTIME_SOURCE_REVISION


def _load_v3_validator():
    path = CORPUS_DIR / "validate_corpus.py"
    spec = importlib.util.spec_from_file_location("sideeffect_v3_corpus_validator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("v3 corpus validator could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


v3_validator = _load_v3_validator()


def _read_regular_nofollow(path: Path, limit: int, label: str) -> bytes:
    try:
        safe_path = v2._reject_symlink_components(path, label)
        fd = v2._open_regular_nofollow(safe_path)
    except (OSError, ValueError) as error:
        raise ValueError(f"{label} must be a regular non-symlink file ({type(error).__name__})") from None
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"{label} exceeds the {limit}-byte limit")
    return raw


def _load_corpus(corpus_path: Path) -> tuple[dict[str, Any], str, dict[str, bytes]]:
    absolute = v2._reject_symlink_components(corpus_path, "corpus")
    if absolute.name != "corpus.json" or absolute.parent != CORPUS_DIR.resolve(strict=True):
        raise ValueError("the v3 evaluator accepts only the registered public development corpus")
    raw = _read_regular_nofollow(absolute, MAX_CORPUS_BYTES, "corpus")
    digest = hashlib.sha256(raw).hexdigest()
    data = v2._strict_json_loads(raw, "v3 corpus")
    if (not isinstance(data, dict) or not isinstance(data.get("cases"), list)
            or len(data["cases"]) != EXPECTED_CASES
            or data.get("status") != "public_development"
            or data.get("release_quality_evidence") is not False):
        raise ValueError("v3 corpus has an invalid root or case count")
    fixtures: dict[str, bytes] = {}
    total = 0
    hashes = data.get("fixture_sha256")
    if not isinstance(hashes, dict):
        raise ValueError("v3 corpus fixture digest table is invalid")
    for name, expected_digest in hashes.items():
        if not isinstance(name, str) or re.fullmatch(r"[a-z0-9-]+\.trace", name) is None:
            raise ValueError("v3 corpus contains an unsafe fixture name")
        path = CORPUS_DIR / name
        raw_fixture = _read_regular_nofollow(path, MAX_FIXTURE_BYTES, f"fixture {name}")
        total += len(raw_fixture)
        if total > MAX_FIXTURE_TOTAL_BYTES:
            raise ValueError("v3 fixtures exceed the aggregate byte limit")
        if hashlib.sha256(raw_fixture).hexdigest() != expected_digest:
            raise ValueError(f"fixture SHA-256 mismatch: {name}")
        fixtures[name] = raw_fixture
    staged, _ = _stage_fixtures(fixtures)
    try:
        try:
            v3_validator.validate_data(data, Path(staged.name), corpus_size=len(raw))
        except (ValueError, OSError) as error:
            raise ValueError(f"v3 corpus validation failed: {error}") from None
    finally:
        staged.cleanup()
    return data, digest, fixtures


def _stage_fixtures(fixtures: dict[str, bytes]) -> tuple[tempfile.TemporaryDirectory[str], dict[str, Path]]:
    private = tempfile.TemporaryDirectory(prefix="sideeffect-query-plan-v3-fixtures-")
    root = Path(private.name)
    paths: dict[str, Path] = {}
    try:
        for name, raw in fixtures.items():
            path = root / name
            path.write_bytes(raw)
            if os.name == "posix":
                os.chmod(path, 0o600)
            paths[name] = path
    except Exception:
        private.cleanup()
        raise
    return private, paths


def _verify_pinned_file(path: Path, expected_sha256: str, byte_limit: int, label: str) -> tuple[str, int]:
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError(f"{label} SHA-256 pin must be 64 lowercase hexadecimal characters")
    try:
        safe_path = v2._reject_symlink_components(path, label)
        fd = v2._open_regular_nofollow(safe_path)
    except (OSError, ValueError) as error:
        raise ValueError(f"{label} must be a readable regular non-symlink file ({type(error).__name__})") from None
    size = 0
    hasher = hashlib.sha256()
    try:
        if os.fstat(fd).st_size > byte_limit:
            raise ValueError(f"{label} exceeds the {byte_limit}-byte limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > byte_limit:
                    raise ValueError(f"{label} exceeds the {byte_limit}-byte limit")
                hasher.update(chunk)
    finally:
        os.close(fd)
    digest = hasher.hexdigest()
    if digest != expected_sha256:
        raise ValueError(f"{label} SHA-256 does not match its caller-supplied pin")
    return digest, size


def _hash_regular_file(path: Path, byte_limit: int, label: str) -> tuple[str, int]:
    """Hash a bounded regular non-symlink artifact without loading it into memory."""
    try:
        safe_path = v2._reject_symlink_components(path, label)
        fd = v2._open_regular_nofollow(safe_path)
    except (OSError, ValueError) as error:
        raise ValueError(f"{label} must be a readable regular non-symlink file ({type(error).__name__})") from None
    hasher = hashlib.sha256()
    size = 0
    try:
        initial_size = os.fstat(fd).st_size
        if initial_size > byte_limit:
            raise ValueError(f"{label} exceeds the {byte_limit}-byte limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > byte_limit:
                    raise ValueError(f"{label} exceeds the {byte_limit}-byte limit")
                hasher.update(chunk)
        if size != initial_size or os.fstat(fd).st_size != initial_size:
            raise ValueError(f"{label} changed size while it was being hashed")
    finally:
        os.close(fd)
    return hasher.hexdigest(), size


def _validate_preview(preview: dict[str, Any], case: dict[str, Any], trace_bytes: bytes,
                      model_sha256: str) -> dict[str, dict[str, Any]]:
    if (preview.get("schema") != "sideeffect.local_query_plan_preview"
            or preview.get("schema_version") != 2
            or preview.get("question") != case["question"]
            or preview.get("model_sha256") != model_sha256
            or preview.get("model_id") != f"custom-{model_sha256[:16]}"
            or preview.get("model_source") != {"kind": "user_provided"}
            or preview.get("model_repository") != "user-provided"
            or preview.get("model_repository_revision") != "user-provided"
            or preview.get("runtime_source_revision") != RUNTIME_REVISION
            or preview.get("trace_sha256") != hashlib.sha256(trace_bytes).hexdigest()
            or preview.get("system_prompt") != v2.EXPECTED_SYSTEM_PROMPT
            or preview.get("output_schema") != v2.expected_output_schema()
            or not v2._valid_sha256(preview.get("request_sha256"))
            or not isinstance(preview.get("evidence_summary"), dict)
            or preview.get("coverage") != preview.get("evidence_summary")):
        raise ValueError("preview schema, model pin, question, request digest, or trace digest mismatch")
    prompt = v2._prompt_object(preview)
    expected_scope = {
        "entities": ["syscall_result", "process_relation"],
        "syscalls": ["execve", "execveat", "openat", "openat2", "connect"],
        "outcomes": ["success", "failure", "in_progress", "unknown"],
        "relation_types": ["fork", "vfork", "clone", "clone3"],
        "filters": ["syscall", "outcome", "observed_errno", "lexical_path_exact",
                    "process_id", "caller_task_id", "child_pid", "relation_type"],
    }
    if prompt != {"user_question": case["question"], "supported_query_scope": expected_scope}:
        raise ValueError("preview model prompt contains unexpected or trace-derived fields")
    if preview["evidence_summary"].get("parse_status") not in {"complete", "partial"}:
        raise ValueError("preview parse status is unsupported")
    facts = v2.facts_with_ids(preview)
    for item in facts.values():
        for field in ("process_id", "caller_task_id", "child_pid"):
            value = item["fact"].get(field)
            if value is not None and value > 0xFFFFFFFF:
                raise ValueError(f"preview fact {field} exceeds the product u32 limit")
    return facts


def _validate_analysis(analysis: Any, preview: dict[str, Any], facts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    fields = {
        "schema", "schema_version", "request_sha256", "model_id", "model_sha256", "model_source",
        "license_id", "license_status", "evaluation_status", "model_repository_revision",
        "runtime_source_revision", "backend", "execution_status", "query_plan", "matched_evidence", "coverage",
    }
    if not isinstance(analysis, dict) or set(analysis) != fields:
        raise ValueError("analysis fields differ from the product schema")
    for key in ("model_id", "model_sha256", "model_source", "license_id", "license_status",
                "evaluation_status", "model_repository_revision"):
        if analysis.get(key) != preview.get(key):
            raise ValueError(f"analysis {key} differs from its preview")
    if (analysis.get("schema") != "sideeffect.local_query_plan_analysis"
            or analysis.get("schema_version") != 2
            or analysis.get("request_sha256") != preview.get("request_sha256")
            or analysis.get("runtime_source_revision") != RUNTIME_REVISION
            or analysis.get("backend") != "cpu"
            or analysis.get("coverage") != preview.get("evidence_summary")):
        raise ValueError("analysis provenance, request digest, backend, or coverage mismatch")
    plan = v2.validate_plan(analysis.get("query_plan"))
    for field in ("process_id", "caller_task_id", "child_pid"):
        value = plan["filters"].get(field)
        if value is not None and value > 0xFFFFFFFF:
            raise ValueError(f"analysis plan {field} exceeds the product u32 limit")
    expected_status = "executed" if plan["decision"] == "filter" else "not_executed"
    if analysis.get("execution_status") != expected_status:
        raise ValueError("analysis execution status disagrees with the validated plan")
    matched = analysis.get("matched_evidence")
    if not isinstance(matched, list) or len(matched) > 2048:
        raise ValueError("analysis matched_evidence is missing or exceeds its bound")
    validated = [v2._valid_evidence(item, facts) for item in matched]
    if any(item is None for item in validated):
        raise ValueError("analysis contains evidence not present in the preview")
    ids = [item["evidence_id"] for item in validated if item is not None]
    if len(ids) != len(set(ids)):
        raise ValueError("analysis contains duplicate evidence IDs")
    expected_ids = v2.plan_match_ids(plan, facts)
    if ids != expected_ids:
        raise ValueError("analysis results differ from Rust's expected exact-filter execution")
    return {"query_plan": plan, "execution_status": expected_status, "matched_ids": ids}


def _evaluate_cases(corpus: dict[str, Any], trace_paths: dict[str, Path], sideeffect: Path,
                    env: dict[str, str], model_sha256: str, runtime: Path | None,
                    preview_only: bool) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for case in corpus["cases"]:
        trace = trace_paths[case["evaluation_fixture"]]
        trace_bytes = trace.read_bytes()
        record: dict[str, Any] = {"id": case["id"], "intent_group": case["intent_group"],
                                  "class": case["class"], "behavior": case["behavior"],
                                  "status": "invalid", "preview_valid": False,
                                  "plan_exact_match": None, "result_exact_match": None,
                                  "abstention_correct": None, "false_filter_on_abstain": None}
        analysis_started: float | None = None
        try:
            preview_result, preview_seconds = v2.run_bounded(
                [str(sideeffect), "model-query-preview", "--question", case["question"], str(trace)],
                PREVIEW_TIMEOUT_SECONDS, env=env)
            if preview_result.returncode not in (0, 2):
                raise ValueError(v2.process_exit_failure("preview command", preview_result, (0, 2)))
            preview = v2._decode_json(preview_result.stdout, "model-query-preview")
            facts = _validate_preview(preview, case, trace_bytes, model_sha256)
            record.update({"preview_valid": True, "preview_elapsed_seconds": round(preview_seconds, 3),
                           "request_sha256": preview["request_sha256"]})
            expected_ids = v2.plan_match_ids(case["expected_plan"], facts)
            if case["behavior"] == "answerable" and len(expected_ids) != case["expected_match_count"]:
                raise ValueError("product preview facts disagree with the corpus oracle match count")
            record["expected_result_count"] = len(expected_ids)
            if preview_only:
                record.update({"status": "preview_valid", "failure_kind": None})
                cases.append(record)
                continue

            assert runtime is not None
            analysis_started = time.perf_counter()
            result, elapsed = v2.run_bounded(
                [str(sideeffect), "model-query", "--question", case["question"], "--runtime", str(runtime),
                 "--confirm-sha256", preview["request_sha256"], str(trace)],
                ANALYSIS_TIMEOUT_SECONDS, env=env)
            expected_exit = 2 if preview["evidence_summary"].get("parse_status") == "partial" else 0
            record["elapsed_seconds"] = round(elapsed, 3)
            if result.returncode != expected_exit:
                raise ValueError(v2.process_exit_failure("model query", result, (expected_exit,)))
            analysis = v2._decode_json(result.stdout, "model-query")
            validated = _validate_analysis(analysis, preview, facts)
            plan = validated["query_plan"]
            actual_ids = validated["matched_ids"]
            plan_exact = _exact_plan_match(plan, case["expected_plan"])
            result_exact = v2.rows_equal(v2.semantic_rows(actual_ids, facts),
                                         v2.semantic_rows(expected_ids, facts))
            abstain = case["behavior"] == "must_abstain"
            false_filter = abstain and plan["decision"] == "filter"
            record.update({"status": "valid_output", "failure_kind": None,
                           "plan_exact_match": plan_exact, "result_exact_match": result_exact,
                           "predicted_decision": plan["decision"],
                           "abstention_correct": abstain and plan["decision"] == "abstain",
                           "execution_status": validated["execution_status"],
                           "returned_result_count": len(actual_ids),
                           "false_filter_on_abstain": false_filter})
        except (ValueError, OSError, v2.OutputLimitExceeded, TimeoutError) as error:
            record["failure_kind"] = "timeout" if isinstance(error, TimeoutError) else "invalid_output"
            if analysis_started is not None:
                record["elapsed_seconds"] = round(time.perf_counter() - analysis_started, 3)
            record["diagnostic_type"] = type(error).__name__
            record["diagnostic_sha256"] = hashlib.sha256(str(error).encode("utf-8", "replace")).hexdigest()
        except subprocess.TimeoutExpired:
            record["failure_kind"] = "timeout"
            if analysis_started is not None:
                record["elapsed_seconds"] = round(time.perf_counter() - analysis_started, 3)
            record["diagnostic_type"] = "TimeoutExpired"
        except Exception as error:
            record["failure_kind"] = type(error).__name__
            if analysis_started is not None:
                record["elapsed_seconds"] = round(time.perf_counter() - analysis_started, 3)
            record["diagnostic"] = "bounded evaluator failure"
        cases.append(record)
    return cases


def _group_accuracy(cases: list[dict[str, Any]], key: str, selector) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for case in cases:
        if selector(case):
            groups[case["intent_group"]].append(case)
    per_group = {group: all(case.get(key) is True for case in members)
                 for group, members in sorted(groups.items())}
    return {"intent_groups": len(groups), "correct_intent_groups": sum(per_group.values()),
            "accuracy": sum(per_group.values()) / len(groups) if groups else None,
            "per_intent_group_all_correct": per_group}


def _exact_plan_match(actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    """Require every plan field, including abstention reason, to match the oracle."""
    return actual == expected


def _metrics(cases: list[dict[str, Any]], corpus: dict[str, Any], preview_only: bool) -> dict[str, Any]:
    if preview_only:
        valid = sum(case["preview_valid"] for case in cases)
        return {"mode": "preview_only", "case_count": len(cases), "valid_previews": valid,
                "invalid_previews": len(cases) - valid,
                "preview_valid_rate": valid / len(cases) if cases else None}
    answerable = lambda case: case["behavior"] == "answerable"
    abstain = lambda case: case["behavior"] == "must_abstain"
    valid = [case for case in cases if case["status"] == "valid_output"]
    classes = sorted({case["class"] for case in cases if answerable(case)})
    by_class: dict[str, Any] = {}
    for class_name in classes:
        subset = [case for case in cases if answerable(case) and case["class"] == class_name]
        by_class[class_name] = {
            "plan": _group_accuracy(subset, "plan_exact_match", lambda _: True),
            "result": _group_accuracy(subset, "result_exact_match", lambda _: True),
        }
    permutation = {}
    for group, expected_size in corpus["source_order_group_sizes"].items():
        members = [case for case in cases if case.get("source_order_group") == group]
        permutation[group] = {"expected_cases": expected_size, "observed_cases": len(members),
                              "all_cases_plan_and_result_correct": len(members) == expected_size and
                              all(case["status"] == "valid_output" and case["plan_exact_match"] and
                                  case["result_exact_match"] for case in members)}
    abstentions = [case for case in cases if abstain(case)]
    false_filters = sum(case["false_filter_on_abstain"] is True for case in abstentions)
    abstain_groups: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for case in abstentions:
        abstain_groups[case["intent_group"]].append(case)
    false_filter_groups = sum(any(case.get("false_filter_on_abstain") is True for case in group)
                              for group in abstain_groups.values())
    return {
        "mode": "full", "case_count": len(cases), "valid_outputs": len(valid),
        "invalid_outputs": len(cases) - len(valid),
        "answerable_result_accuracy": _group_accuracy(cases, "result_exact_match", answerable),
        "answerable_plan_accuracy": _group_accuracy(cases, "plan_exact_match", answerable),
        "exact_plan_accuracy_by_answerable_class": by_class,
        "zero_match_plan_accuracy": _group_accuracy(
            cases, "plan_exact_match",
            lambda case: answerable(case) and case.get("expected_result_count") == 0),
        "must_abstain_intent_accuracy": _group_accuracy(cases, "abstention_correct", abstain),
        "false_filter_on_abstain_cases": false_filters,
        "false_filter_on_abstain_rate": false_filters / len(abstentions) if abstentions else None,
        "must_abstain_intent_groups": len(abstain_groups),
        "false_filter_on_abstain_intent_groups": false_filter_groups,
        "false_filter_on_abstain_intent_group_rate": (false_filter_groups / len(abstain_groups)
                                                       if abstain_groups else None),
        "source_order_groups": permutation,
        "latency_seconds": v2.distribution([case["elapsed_seconds"] for case in cases
                                             if isinstance(case.get("elapsed_seconds"), (int, float))]),
    }


def _write_report(path: Path, report: dict[str, Any]) -> str:
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(REPOSITORY.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise ValueError("evaluation reports must be written outside the Git worktree")
    raw = (json.dumps(report, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    if len(raw) > v2.MAX_REPORT_BYTES:
        raise ValueError("evaluation report exceeds its byte limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(resolved, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def _repository_revision() -> str | None:
    """Collect Git provenance when available, without making it a run prerequisite."""
    try:
        return v2.repository_provenance(REPOSITORY, require_clean=False)["repository_revision"]
    except (OSError, ValueError, subprocess.SubprocessError, KeyError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sideeffect", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, default=CORPUS_PATH)
    parser.add_argument("--model", type=Path, required=True,
                        help="existing local model file; preview-only also needs a selected model")
    parser.add_argument("--expected-model-sha256", required=True)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--expected-runtime-sha256")
    parser.add_argument("--preview-only", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    if not args.preview_only and (args.runtime is None or args.expected_runtime_sha256 is None):
        parser.error("full mode requires --runtime and --expected-runtime-sha256")
    if args.preview_only and (args.runtime is not None or args.expected_runtime_sha256 is not None):
        parser.error("preview-only mode does not accept a runtime")
    model_store = tempfile.TemporaryDirectory(prefix="sideeffect-query-plan-v3-registry-")
    fixture_temp: tempfile.TemporaryDirectory[str] | None = None
    try:
        corpus, corpus_sha256, fixture_bytes = _load_corpus(args.corpus)
        fixture_temp, trace_paths = _stage_fixtures(fixture_bytes)
        model_sha256, model_size = _verify_pinned_file(args.model, args.expected_model_sha256, MAX_MODEL_BYTES, "model")
        sideeffect = v2._reject_symlink_components(args.sideeffect, "SideEffect executable")
        if not sideeffect.is_file():
            raise ValueError("SideEffect executable is unavailable")
        sideeffect_sha256, sideeffect_size = _hash_regular_file(
            sideeffect, MAX_SIDEEFFECT_BYTES, "SideEffect executable"
        )
        runtime_sha256 = None
        if not args.preview_only:
            runtime_sha256, _ = _verify_pinned_file(args.runtime, args.expected_runtime_sha256,
                                                     1024 * 1024 * 1024, "runtime")
            version_result, _ = v2.run_bounded([str(args.runtime), "--version"], 10)
            version = (version_result.stdout + version_result.stderr).decode("utf-8", "replace")
            if version_result.returncode != 0 or RUNTIME_VERSION not in version:
                raise ValueError("runtime version does not match the version supported by the Rust query path")

        env = os.environ.copy()
        env["XDG_DATA_HOME"] = model_store.name
        registration, _ = v2.run_bounded(
            [str(sideeffect), "model", "add", "--name", "Pinned v3 query-plan evaluation candidate",
             "--path", str(args.model.absolute()), "--for", "query"], 30, env=env)
        if registration.returncode != 0:
            raise ValueError("isolated model registration failed")
        model_id = f"custom-{model_sha256[:16]}"
        selection, _ = v2.run_bounded([str(sideeffect), "model", "select", "query", model_id], 30, env=env)
        if selection.returncode != 0:
            raise ValueError("isolated query-model selection failed")

        repository_revision = _repository_revision()
        cases = _evaluate_cases(corpus, trace_paths, sideeffect, env, model_sha256,
                                args.runtime, args.preview_only)
        report = {
            "schema": "sideeffect.local_query_plan_v3_development_evaluation",
            "schema_version": 1, "qualification": "not_assessed",
            "independent_label_review": "not_verified", "hidden_holdout": False,
            "corpus_sha256": corpus_sha256, "model_sha256": model_sha256,
            "sideeffect_sha256": sideeffect_sha256, "sideeffect_size_bytes": sideeffect_size,
            "model_size_bytes": model_size, "runtime_sha256": runtime_sha256,
            "runtime_version": RUNTIME_VERSION if runtime_sha256 else None,
            "runtime_source_revision": RUNTIME_REVISION if runtime_sha256 else None,
            "repository_revision": repository_revision,
            "repository_revision_status": "available" if repository_revision else "unavailable",
            "evaluator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "inference_performed": not args.preview_only,
            "metrics": _metrics(cases, corpus, args.preview_only), "cases": cases,
        }
        if args.report:
            report_sha256 = _write_report(args.report, report)
            print(json.dumps({"report_written": True, "report_sha256": report_sha256}))
        else:
            print(json.dumps(report, indent=2, ensure_ascii=True))
        return 0 if all(case["preview_valid"] for case in cases) else 2
    except subprocess.TimeoutExpired:
        parser.error("bounded subprocess timed out")
    except (OSError, ValueError, v2.OutputLimitExceeded) as error:
        parser.error(str(error))
    finally:
        if fixture_temp is not None:
            fixture_temp.cleanup()
        model_store.cleanup()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
