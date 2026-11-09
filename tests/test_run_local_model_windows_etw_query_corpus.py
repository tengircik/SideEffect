"""Tests for the native Windows ETW query runner through a mocked CLI boundary."""

from __future__ import annotations

import json
import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import evaluate_local_model_windows_etw_query as evaluation
import run_local_model_windows_etw_query_corpus as runner


class WindowsEtwQueryRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus, _, _ = evaluation.load_corpus()
        cls.cases = {case["id"]: case for case in cls.corpus["cases"]}

    def test_scores_actual_cli_contract_with_aggregate_only_report(self) -> None:
        identity = {"model_id": "synthetic-test-model", "model_sha256": "b" * 64,
                    "runtime_source_revision": "c" * 40, "backend_preference": "auto"}
        calls: list[list[str]] = []
        environment = {"PATH": "C:\\Windows\\System32", "SYSTEMROOT": "C:\\Windows"}

        def fake_invoke(argv, *, timeout_seconds, output_limit, env):
            calls.append(argv)
            self.assertEqual(timeout_seconds, 45)
            self.assertGreater(output_limit, 0)
            self.assertEqual(env, environment)
            case_question = argv[argv.index("--question") + 1]
            capture_path = Path(argv[argv.index("--windows-runtime") + 1])
            case = next(case for case in self.corpus["cases"]
                        if case["question"] == case_question and case["fixture"] == capture_path.name)
            capture_bytes = capture_path.read_bytes()
            capture = evaluation._decode(capture_bytes, "test fixture")
            queryable = runner._expected_queryable_rows(capture)
            coverage = {"capture_completeness": "unknown", "queryable_event_count": len(queryable),
                        "omitted_unvalidated_or_limited_event_count": len(capture["events"]) - len(queryable),
                        "query_status": "partial_or_unknown"}
            if argv[1] == "model-etw-query-preview":
                preview = {
                    "schema": "sideeffect.windows_etw_query_preview", "schema_version": 1,
                    "question": case_question, "request_sha256": "a" * 64,
                    "capture_sha256": capture["document_sha256"],
                    "capture_bytes_sha256": hashlib.sha256(capture_bytes).hexdigest(),
                    **identity, "model_source": {"kind": "user_provided"}, "model_revision": "user-provided",
                    "license_id": None, "evaluation_status": "not_assessed",
                    "backend_preference": "auto", "system_prompt": runner.EXPECTED_SYSTEM_PROMPT,
                    "prompt": json.dumps({"user_question": case_question,
                                          "supported_query_scope": runner.QUERY_SCOPE}, separators=(",", ":")),
                    "output_schema": {}, "queryable_events": queryable, "coverage": coverage,
                }
                return 2, json.dumps(preview).encode(), None
            self.assertEqual(argv[argv.index("--confirm-sha256") + 1], "a" * 64)
            plan = case["expected_plan"]
            result = {
                "schema": "sideeffect.windows_etw_query_result", "schema_version": 1,
                "request_sha256": "a" * 64, "capture_sha256": capture["document_sha256"],
                "capture_bytes_sha256": hashlib.sha256(capture_bytes).hexdigest(),
                **identity, "model_source": {"kind": "user_provided"}, "model_revision": "user-provided",
                "license_id": None, "evaluation_status": "not_assessed", "backend_preference": "auto",
                "backend_used": "cpu", "backend_status": "cpu", "execution_status":
                "executed" if plan["decision"] == "filter" else "not_executed",
                "plan": plan, "matched_events": runner._matched_rows(queryable, plan),
                "capture_completeness": "unknown", "collection_status": capture["collection_status"],
                "event_loss": capture["event_loss"], "diagnostics": capture["diagnostics"],
                "coverage": coverage, "result_status": "partial_or_unknown",
            }
            return 2, json.dumps(result).encode(), None

        report = runner.run_corpus(sideeffect_command=["sideeffect.exe"], backend="auto", runtime=None,
                                   timeout_seconds=45, environment=environment, invoke=fake_invoke)
        self.assertEqual(len(calls), len(self.corpus["cases"]) * 2)
        self.assertEqual(report["counts"], {"cases": 11, "completed": 11, "failed": 0})
        self.assertEqual(report["metrics"]["exact_plan_cases"], 11)
        self.assertEqual(report["metrics"]["exact_result_cases"], 11)
        self.assertEqual(report["metrics"]["answerable_plan_accuracy"], {"correct": 6, "total": 6})
        self.assertEqual(report["metrics"]["must_abstain_accuracy"], {"correct": 5, "total": 5})
        self.assertEqual(report["metrics"]["false_filters_on_must_abstain"], 0)
        self.assertEqual(report["metrics"]["permutation_groups"], {"passed": 1, "total": 1})
        self.assertNotIn("case_id", json.dumps(report))
        self.assertFalse(report["semantic_quality_assessed"])
        self.assertEqual(report["qualification_result"], "not_assessed")

    def test_rejects_invalid_backend_before_invoking_cli(self) -> None:
        with self.assertRaisesRegex(runner.RunnerError, "backend"):
            runner.run_corpus(sideeffect_command=["sideeffect"], backend="other", runtime=None)

    def test_failed_cases_count_against_the_full_corpus_denominator(self) -> None:
        def fail_preview(*args, **kwargs):
            return None, b"", "launch_error"

        report = runner.run_corpus(sideeffect_command=["sideeffect.exe"], backend="auto", runtime=None,
                                   invoke=fail_preview)
        self.assertEqual(report["run"], None)
        self.assertEqual(report["counts"], {"cases": 11, "completed": 0, "failed": 11})
        self.assertEqual(report["metrics"]["answerable_plan_accuracy"], {"correct": 0, "total": 6})
        self.assertEqual(report["metrics"]["must_abstain_accuracy"], {"correct": 0, "total": 5})


if __name__ == "__main__":
    unittest.main()
