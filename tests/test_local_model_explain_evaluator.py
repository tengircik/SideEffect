"""Pure contract tests for the historical and selector-only explain evaluators."""

from __future__ import annotations

import json
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "evaluate_local_model_explain.py"
SPEC = importlib.util.spec_from_file_location("sideeffect_explain_evaluator", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
evaluation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evaluation
SPEC.loader.exec_module(evaluation)


def _result(corpus: dict[str, Any], digest: str, version: int) -> dict[str, Any]:
    cases = []
    for case in corpus["cases"]:
        labels = case["required_evidence_labels"]
        evidence = [{"evidence_id": "E001", "semantic_labels": labels}]
        if version == 1:
            status = case["expected_status"]
            statements = [] if status == "abstained" else [{
                "kind": "observation",
                "text": "Synthetic historical test statement.",
                "evidence_ids": ["E001"],
            }]
            response = {
                "status": status,
                "abstain_reason": case["expected_abstain_reason"],
                "statements": statements,
            }
            row = {
                "case_id": case["id"],
                "response": response,
                "available_evidence": evidence,
                "latency_ms": 1,
                "human_review": None,
            }
        else:
            parse_status = "partial" if case["expected_status"] == "partial" else "complete"
            if case["expected_status"] == "abstained":
                selection_status, evidence_ids = "abstained", []
            elif parse_status == "partial":
                selection_status, evidence_ids = "partial_selection", ["E001"]
            else:
                selection_status, evidence_ids = "selected", ["E001"]
            row = {
                "case_id": case["id"],
                "response": {
                    "selection_status": selection_status,
                    "evidence_ids": evidence_ids,
                },
                "source_parse_status": parse_status,
                "backend_used": "not_run" if selection_status == "abstained" else "cpu",
                "available_evidence": evidence,
                "latency_ms": 1,
            }
        cases.append(row)
    results = {
        "schema": "sideeffect.local_model_explain_development_results",
        "schema_version": version,
        "corpus_sha256": digest,
        "cases": cases,
    }
    if version == 2:
        results["run"] = {
            "model_id": "test-model",
            "model_sha256": "a" * 64,
            "runtime_source_revision": "b" * 40,
            "backend_preference": "auto",
        }
    return results


class ExplainEvaluatorV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus, cls.digest = evaluation.load_corpus()

    def _validate(self, results: dict[str, Any]) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.json"
            path.write_text(json.dumps(results), encoding="utf-8")
            return evaluation._validate_results(path, self.corpus, self.digest)

    def test_historical_v1_validation_and_report_fields_are_preserved(self) -> None:
        report = self._validate(_result(self.corpus, self.digest, version=1))
        self.assertEqual(report["schema"], "sideeffect.local_model_explain_development_report")
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(set(report), {
            "schema", "schema_version", "evaluation_status", "corpus_sha256", "cases",
            "response_contract_valid_count", "execution_error_count", "execution_errors",
            "expected_status_match_count", "required_evidence_label_recall",
            "human_reviewed_case_count", "human_review_exact_label_match_count",
            "human_review_cases_with_unsupported_claims", "p95_latency_ms",
            "permutation_group_count", "permutation_consistent_group_count",
            "permutation_groups", "semantic_text_truth_verified_automatically", "report_rows",
        })
        self.assertEqual(set(report["report_rows"][0]), {
            "case_id", "response_contract_valid", "expected_status_and_abstention_match",
            "required_evidence_labels", "cited_evidence_labels",
            "required_evidence_label_recall", "human_review", "latency_ms",
        })
        self.assertEqual(report["response_contract_valid_count"], 26)
        self.assertEqual(report["expected_status_match_count"], 26)
        self.assertEqual(report["required_evidence_label_recall"], 1.0)
        self.assertIn("semantic_text_truth_verified_automatically", report)

    def test_v2_validates_selector_states_and_reports_diagnostic_only_metrics(self) -> None:
        report = self._validate(_result(self.corpus, self.digest, version=2))
        self.assertEqual(report["schema"], "sideeffect.local_model_explain_selector_diagnostic_report")
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["selection_output_contract_valid_count"], 26)
        self.assertEqual(report["selection_state_consistency_count"], 26)
        self.assertEqual(report["selected_required_evidence_label_recall_over_available_labels"], 1.0)
        self.assertEqual(report["run"]["model_id"], "test-model")
        self.assertEqual(report["run"]["backend_preference"], "auto")
        self.assertFalse(report["cuda_offload_evidence_verified_automatically"])
        self.assertEqual(report["backend_used_source"], "supplied_product_output_not_independently_verified_by_validator")
        self.assertFalse(report["available_evidence_labels_verified_automatically"])
        self.assertTrue(report["evidence_label_recall_is_diagnostic"])
        self.assertEqual(report["supplied_case_latency_count"], 26)
        self.assertEqual(report["p95_supplied_case_latency_scope"], "cases_with_valid_selector_results_only")
        self.assertFalse(report["selection_quality_verified_automatically"])
        self.assertFalse(report["semantic_correctness_verified_automatically"])
        self.assertNotIn("expected_status_match_count", report)

    def test_v2_rejects_unknown_duplicate_over_limit_and_inconsistent_selection(self) -> None:
        base = _result(self.corpus, self.digest, version=2)
        cases = [
            ("unknown ID", lambda row: row["response"].update(evidence_ids=["E999"])),
            ("duplicate IDs", lambda row: row["response"].update(evidence_ids=["E001", "E001"])),
            ("too many IDs", lambda row: row["response"].update(evidence_ids=[f"E{i:03}" for i in range(1, 7)])),
            ("status mismatch", lambda row: row["response"].update(selection_status="partial_selection")),
            ("unknown parse status", lambda row: row.update(source_parse_status="unknown")),
            ("not-run with selection", lambda row: row.update(backend_used="not_run")),
        ]
        for name, mutate in cases:
            with self.subTest(name=name):
                changed = json.loads(json.dumps(base))
                row = next(item for item in changed["cases"] if item["case_id"] == "exec-success-name")
                if name == "too many IDs":
                    row["available_evidence"] = [
                        {"evidence_id": f"E{i:03}", "semantic_labels": []}
                        for i in range(1, 7)
                    ]
                mutate(row)
                with self.assertRaises(evaluation.ContractError):
                    self._validate(changed)

        changed = json.loads(json.dumps(base))
        changed["run"]["backend_preference"] = "cpu"
        row = next(item for item in changed["cases"] if item["case_id"] == "exec-success-name")
        row["backend_used"] = "cuda"
        with self.assertRaisesRegex(evaluation.ContractError, "backend_used is inconsistent"):
            self._validate(changed)

    def test_v2_rejects_malformed_run_metadata(self) -> None:
        base = _result(self.corpus, self.digest, version=2)
        for name, mutate in [
            ("model ID path", lambda run: run.update(model_id="C:/private/model")),
            ("bad model hash", lambda run: run.update(model_sha256="not-a-sha")),
            ("bad runtime revision", lambda run: run.update(runtime_source_revision="short")),
            ("bad backend preference", lambda run: run.update(backend_preference="gpu")),
            ("filesystem path", lambda run: run.update(runtime_path="C:/private/runtime.exe")),
        ]:
            with self.subTest(name=name):
                changed = json.loads(json.dumps(base))
                mutate(changed["run"])
                with self.assertRaises(evaluation.ContractError):
                    self._validate(changed)

    def test_v2_reports_required_labels_unavailable_to_syscall_selector(self) -> None:
        results = _result(self.corpus, self.digest, version=2)
        row = next(item for item in results["cases"] if item["case_id"] == "child-exec")
        row["available_evidence"] = [{
            "evidence_id": "E001",
            "semantic_labels": ["child_exec_sideeffect_child"],
        }]
        report = self._validate(results)
        child = next(item for item in report["report_rows"] if item["case_id"] == "child-exec")
        self.assertEqual(
            child["required_evidence_labels_unavailable_to_selector"],
            ["clone3_child_pid_910"],
        )
        self.assertEqual(
            child["required_evidence_labels_available_to_selector"],
            ["child_exec_sideeffect_child"],
        )
        self.assertEqual(
            child["selected_required_evidence_label_recall_over_available_labels"],
            1.0,
        )
        self.assertEqual(report["required_evidence_label_unavailable_to_selector_count"], 1)

    def test_v2_accepts_empty_preview_for_deterministic_abstention(self) -> None:
        results = _result(self.corpus, self.digest, version=2)
        row = next(item for item in results["cases"] if item["case_id"] == "unsupported-cause")
        row["response"] = {"selection_status": "abstained", "evidence_ids": []}
        row["backend_used"] = "not_run"
        row["available_evidence"] = []
        report = self._validate(results)
        case = next(item for item in report["report_rows"] if item["case_id"] == "unsupported-cause")
        self.assertEqual(case["selected_evidence_ids"], [])
        self.assertEqual(case["required_evidence_labels_available_to_selector"], [])
        self.assertEqual(case["required_evidence_labels_unavailable_to_selector"], [])

    def test_v2_accounts_for_execution_errors_without_latency_samples(self) -> None:
        results = _result(self.corpus, self.digest, version=2)
        failed = results["cases"].pop()
        results["errors"] = [{
            "case_id": failed["case_id"],
            "phase": "analysis",
            "error": "Synthetic test failure.",
        }]
        report = self._validate(results)
        self.assertEqual(report["execution_error_count"], 1)
        self.assertEqual(report["selection_output_contract_valid_count"], 25)
        self.assertEqual(report["supplied_case_latency_count"], 25)
        self.assertEqual(report["execution_errors"][0]["case_id"], failed["case_id"])

        missing = _result(self.corpus, self.digest, version=2)
        missing["cases"].pop()
        with self.assertRaisesRegex(evaluation.ContractError, "omit one or more corpus cases"):
            self._validate(missing)


if __name__ == "__main__":
    unittest.main()
