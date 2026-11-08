"""Tests for the public v3 evaluator using a mocked SideEffect CLI boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evaluate_local_query_plan as v2
import evaluate_local_query_plan_v3 as v3


class V3EvaluatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus, cls.corpus_sha256, cls.fixtures = v3._load_corpus(v3.CORPUS_PATH)

    def test_loads_frozen_corpus_and_checks_fixture_digests(self) -> None:
        self.assertEqual(len(self.corpus["cases"]), 120)
        self.assertEqual(len(self.fixtures), 25)
        self.assertEqual(self.corpus_sha256, hashlib.sha256(v3.CORPUS_PATH.read_bytes()).hexdigest())
        abstain = [case for case in self.corpus["cases"] if case["behavior"] == "must_abstain"]
        self.assertTrue(all(case["fixture"] is None for case in abstain))
        self.assertTrue(all(case["evaluation_fixture"] == "abstention-context.trace" for case in abstain))

    def test_rejects_nonregistered_corpus_location(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corpus.json"
            path.write_bytes(v3.CORPUS_PATH.read_bytes())
            with self.assertRaisesRegex(ValueError, "only the registered public"):
                v3._load_corpus(path)

    def test_verifies_pinned_file_digest_and_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.gguf"
            raw = b"fake model bytes; no inference is performed"
            path.write_bytes(raw)
            digest, size = v3._verify_pinned_file(path, hashlib.sha256(raw).hexdigest(), 1024, "model")
            self.assertEqual((digest, size), (hashlib.sha256(raw).hexdigest(), len(raw)))
            with self.assertRaisesRegex(ValueError, "caller-supplied pin"):
                v3._verify_pinned_file(path, "0" * 64, 1024, "model")
            with self.assertRaisesRegex(ValueError, "byte limit"):
                v3._verify_pinned_file(path, hashlib.sha256(raw).hexdigest(), 4, "model")

    def test_hashes_sideeffect_binary_with_a_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sideeffect"
            raw = b"synthetic cli bytes"
            path.write_bytes(raw)
            self.assertEqual(
                v3._hash_regular_file(path, 1024, "SideEffect executable"),
                (hashlib.sha256(raw).hexdigest(), len(raw)),
            )
            with self.assertRaisesRegex(ValueError, "byte limit"):
                v3._hash_regular_file(path, 4, "SideEffect executable")

    def test_repository_provenance_is_optional_for_non_git_mounts(self) -> None:
        with patch.object(v2, "repository_provenance", side_effect=v2.subprocess.CalledProcessError(128, "git")):
            self.assertIsNone(v3._repository_revision())

    def _abstain_case(self) -> dict:
        return copy.deepcopy(next(case for case in self.corpus["cases"]
                                  if case["behavior"] == "must_abstain"))

    def _preview(self, case: dict, trace: Path, model_sha256: str) -> dict:
        return {
            "schema": "sideeffect.local_query_plan_preview", "schema_version": 2,
            "question": case["question"], "request_sha256": "a" * 64,
            "model_id": f"custom-{model_sha256[:16]}", "model_repository": "user-provided",
            "model_sha256": model_sha256, "model_source": {"kind": "user_provided"},
            "license_id": None, "license_status": "not_provided",
            "evaluation_status": "not_assessed", "model_repository_revision": "user-provided",
            "runtime_source_revision": v3.RUNTIME_REVISION, "backend": "cpu",
            "trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
            "system_prompt": v2.EXPECTED_SYSTEM_PROMPT,
            "prompt": json.dumps({"user_question": case["question"], "supported_query_scope": {
                "entities": ["syscall_result", "process_relation"],
                "syscalls": ["execve", "execveat", "openat", "openat2", "connect"],
                "outcomes": ["success", "failure", "in_progress", "unknown"],
                "relation_types": ["fork", "vfork", "clone", "clone3"],
                "filters": ["syscall", "outcome", "observed_errno", "lexical_path_exact",
                            "process_id", "caller_task_id", "child_pid", "relation_type"],
            }}, separators=(",", ":")),
            "output_schema": v2.expected_output_schema(),
            "evidence_summary": {"parse_status": "complete"},
            "coverage": {"parse_status": "complete"}, "queryable_facts": [],
        }

    def test_preview_only_uses_real_cli_contract_without_analysis_call(self) -> None:
        case = self._abstain_case()
        model_sha = "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / case["evaluation_fixture"]
            trace.write_bytes(self.fixtures[case["evaluation_fixture"]])
            calls: list[list[str]] = []

            def fake_cli(arguments, timeout, *, env=None):
                calls.append(arguments)
                self.assertEqual(env["XDG_DATA_HOME"], directory)
                self.assertEqual(arguments[0], "sideeffect")
                self.assertEqual(timeout, v3.PREVIEW_TIMEOUT_SECONDS)
                self.assertEqual(arguments[1], "model-query-preview")
                payload = json.dumps(self._preview(case, trace, model_sha)).encode()
                return v2.RunResult(0, payload, b"", None, None), 0.01

            with patch.object(v2, "run_bounded", side_effect=fake_cli):
                records = v3._evaluate_cases({"cases": [case]}, {case["evaluation_fixture"]: trace},
                                             Path("sideeffect"), {"XDG_DATA_HOME": directory},
                                             model_sha, None, True)
            self.assertEqual(len(calls), 1)
            self.assertEqual(records[0]["status"], "preview_valid")
            metrics = v3._metrics(records, self.corpus, True)
            self.assertEqual(metrics["valid_previews"], 1)
            self.assertIsNone(records[0]["plan_exact_match"])
            self.assertIsNone(records[0]["result_exact_match"])

    def test_full_runner_uses_digest_confirmation_and_counts_abstain_filter(self) -> None:
        case = self._abstain_case()
        model_sha = "c" * 64
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / case["evaluation_fixture"]
            trace.write_bytes(self.fixtures[case["evaluation_fixture"]])
            calls: list[list[str]] = []

            def fake_cli(arguments, timeout, *, env=None):
                calls.append(arguments)
                self.assertEqual(env["XDG_DATA_HOME"], directory)
                if arguments[1] == "model-query-preview":
                    return v2.RunResult(0, json.dumps(self._preview(case, trace, model_sha)).encode(), b"", None, None), 0.01
                self.assertEqual(arguments[1], "model-query")
                self.assertEqual(arguments[arguments.index("--confirm-sha256") + 1], "a" * 64)
                plan = copy.deepcopy(case["expected_plan"])
                # A filter on a must-abstain case is false regardless of its result count.
                plan = {"decision": "filter", "abstain_reason": None, "entity": "syscall_result",
                        "filters": {key: None for key in v2.FILTER_FIELDS}, "combine": "all"}
                plan["filters"]["syscall"] = "openat"
                analysis = {"schema": "sideeffect.local_query_plan_analysis", "schema_version": 2,
                            "request_sha256": "a" * 64, "model_id": f"custom-{model_sha[:16]}",
                            "model_sha256": model_sha, "model_source": {"kind": "user_provided"},
                            "license_id": None, "license_status": "not_provided",
                            "evaluation_status": "not_assessed", "model_repository_revision": "user-provided",
                            "runtime_source_revision": v3.RUNTIME_REVISION, "backend": "cpu",
                            "execution_status": "executed", "query_plan": plan,
                            "matched_evidence": [], "coverage": {"parse_status": "complete"}}
                return v2.RunResult(0, json.dumps(analysis).encode(), b"", None, None), 0.03

            with patch.object(v2, "run_bounded", side_effect=fake_cli):
                records = v3._evaluate_cases({"cases": [case]}, {case["evaluation_fixture"]: trace},
                                             Path("sideeffect"), {"XDG_DATA_HOME": directory},
                                             model_sha, Path("runtime"), False)
            self.assertEqual([call[1] for call in calls], ["model-query-preview", "model-query"])
            self.assertTrue(records[0]["false_filter_on_abstain"])
            self.assertFalse(records[0]["abstention_correct"])
            self.assertEqual(calls[1][2:4], ["--question", case["question"]])
            self.assertEqual(calls[1][calls[1].index("--confirm-sha256") + 1], "a" * 64)
            metrics = v3._metrics(records, self.corpus, False)
            self.assertEqual(metrics["false_filter_on_abstain_cases"], 1)
            self.assertEqual(metrics["must_abstain_intent_groups"], 1)
            self.assertEqual(metrics["false_filter_on_abstain_intent_groups"], 1)
            self.assertEqual(metrics["must_abstain_intent_accuracy"]["accuracy"], 0.0)

    def test_intent_metrics_collapse_source_order_variants(self) -> None:
        source_cases = [case for case in self.corpus["cases"] if case["source_order_group"]]
        source_group = source_cases[0]["source_order_group"]
        records = [{"intent_group": case["intent_group"], "source_order_group": case["source_order_group"],
                    "behavior": "answerable", "class": "source_order", "status": "valid_output",
                    "plan_exact_match": True, "result_exact_match": True,
                    "expected_result_count": case["expected_match_count"], "elapsed_seconds": 1.0}
                   for case in source_cases if case["source_order_group"] == source_group]
        metrics = v3._metrics(records, self.corpus, False)
        self.assertEqual(metrics["answerable_result_accuracy"]["intent_groups"], 1)
        self.assertEqual(metrics["answerable_result_accuracy"]["correct_intent_groups"], 1)
        self.assertTrue(metrics["source_order_groups"][source_group]["all_cases_plan_and_result_correct"])

    def test_exact_plan_includes_abstention_reason(self) -> None:
        case = self._abstain_case()
        actual = copy.deepcopy(case["expected_plan"])
        actual["abstain_reason"] = next(
            reason for reason in ("ambiguous", "unsupported_scope", "insufficient_evidence")
            if reason != actual["abstain_reason"]
        )
        self.assertFalse(v3._exact_plan_match(actual, case["expected_plan"]))
        self.assertTrue(v3._exact_plan_match(case["expected_plan"], case["expected_plan"]))


if __name__ == "__main__":
    unittest.main()
