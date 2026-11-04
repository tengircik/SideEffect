"""Pure contract tests for the historical and selector-only explain evaluators."""

from __future__ import annotations

import json
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

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
    if version in {2, 3}:
        results["run"] = {
            "model_id": "test-model",
            "model_sha256": "a" * 64,
            "runtime_source_revision": "b" * 40,
            "backend_preference": "auto",
        }
    if version == 3:
        for row in results["cases"]:
            case = next(item for item in corpus["cases"] if item["id"] == row["case_id"])
            row["preview_request_sha256"] = "c" * 64
            row["review_packet_sha256"] = "d" * 64
            row["run_case_input_sha256"] = "e" * 64
            target_digest = evaluation._review_target_sha256(row, case["question"], digest)
            row["review_target_sha256"] = target_digest
            selected_ids = row["response"]["evidence_ids"]
            row["human_reviews"] = [
                {
                    "review_target_sha256": target_digest,
                    "preview_request_sha256": row["preview_request_sha256"],
                    "review_packet_sha256": row["review_packet_sha256"],
                    "run_case_input_sha256": row["run_case_input_sha256"],
                    "reviewer_id": reviewer_id,
                    "blind_to_model_identity": True,
                    "independence_attested": True,
                    "answerability": "answerable",
                    "required_evidence_labels": ["requested_fact"],
                    "selected_evidence_judgments": [
                        {
                            "evidence_id": evidence_id,
                            "supported_required_evidence_labels": ["requested_fact"],
                            "unsupported_inference": False,
                        }
                        for evidence_id in selected_ids
                    ],
                }
                for reviewer_id in ("reviewer-a", "reviewer-b")
            ]
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


class ExplainEvaluatorV3HumanReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus, cls.digest = evaluation.load_corpus()

    def _validate(self, results: dict[str, Any], packet_mutator=None, directory_mutator=None) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.json"
            packet_directory = Path(directory) / "packets"
            packet_directory.mkdir()
            for row in results.get("cases", []):
                if not row.get("human_reviews"):
                    continue
                case = next(item for item in self.corpus["cases"] if item["id"] == row["case_id"])
                packet = {
                    "schema": "sideeffect.local_model_explain_blind_review_packet", "schema_version": 1,
                    "corpus_sha256": self.digest, "case_id": row["case_id"], "question": case["question"],
                    "preview_schema": "sideeffect.local_model_explanation_preview", "preview_schema_version": 3,
                    "deterministic_abstain_reason": None, "system_prompt": "synthetic", "prompt": "{}",
                    "output_schema": {}, "evidence_summary": {},
                    "response": {**row["response"], "abstain_reason": None},
                    "preview_request_sha256": row["preview_request_sha256"],
                    "review_target_sha256": row["review_target_sha256"],
                    "run_case_input_sha256": row["run_case_input_sha256"],
                }
                packet["packet_sha256"] = evaluation._canonical_sha256(packet)
                if row.get("review_packet_sha256") == "d" * 64:
                    row["review_packet_sha256"] = packet["packet_sha256"]
                for review in row["human_reviews"]:
                    if review.get("review_packet_sha256") == "d" * 64:
                        review["review_packet_sha256"] = packet["packet_sha256"]
                if packet_mutator is not None:
                    packet_mutator(packet, row)
                (packet_directory / f"{row['case_id']}.json").write_text(json.dumps(packet), encoding="utf-8")
            if directory_mutator is not None:
                directory_mutator(packet_directory)
            path.write_text(json.dumps(results), encoding="utf-8")
            return evaluation._validate_results(path, self.corpus, self.digest, packet_directory)

    def test_v3_reports_blinded_peer_agreement_and_reviewed_inference_counts(self) -> None:
        results = _result(self.corpus, self.digest, version=3)
        changed = next(item for item in results["cases"] if item["case_id"] == "exec-success-name")
        changed["human_reviews"][1]["answerability"] = "uncertain"
        changed["human_reviews"][1]["required_evidence_labels"] = ["different_fact"]
        if changed["human_reviews"][1]["selected_evidence_judgments"]:
            changed["human_reviews"][1]["selected_evidence_judgments"][0]["supported_required_evidence_labels"] = ["different_fact"]
            changed["human_reviews"][1]["selected_evidence_judgments"][0]["unsupported_inference"] = True

        report = self._validate(results)
        self.assertEqual(report["schema_version"], 3)
        self.assertEqual(
            report["human_review_gate_status"],
            "reviewer_threshold_met_self_attested",
        )
        self.assertEqual(
            report["human_review_gate_status_scope"],
            "reviewer_completion_only_not_independent_verification_or_model_quality",
        )
        self.assertTrue(report["human_review_status_is_self_attested_diagnostic_only"])
        self.assertEqual(report["human_review_gate_reviewer_id_count"], 2)
        self.assertEqual(report["self_attested_full_review_completion_reviewer_id_count"], 2)
        self.assertFalse(report["human_review_identity_or_independence_verified_automatically"])
        self.assertFalse(report["human_review_is_model_quality_gate"])
        self.assertTrue(report["selector_answerability_agreement_is_diagnostic"])
        self.assertFalse(report["selector_answerability_agreement_has_pass_threshold"])
        self.assertFalse(report["semantic_truth_inferred_from_selector_structure"])
        reviewers = {row["reviewer_id"]: row for row in report["human_reviewers"]}
        self.assertTrue(reviewers["reviewer-a"]["fully_completed_blinded_independent_review"])
        self.assertEqual(
            reviewers["reviewer-a"]["review_completion_status"],
            "self_attested_full_completion_not_independently_verified",
        )
        self.assertFalse(reviewers["reviewer-a"]["review_blinding_or_independence_verified_automatically"])
        self.assertEqual(reviewers["reviewer-a"]["required_evidence_label_coverage"], 17 / 26)
        self.assertLess(reviewers["reviewer-a"]["peer_answerability_agreement_rate"], 1.0)
        self.assertEqual(reviewers["reviewer-a"]["selector_answerability_denominator"], 26)
        self.assertEqual(reviewers["reviewer-a"]["selector_answerability_false_positive_count"], 0)
        expected_false_negatives = sum(
            row["response"]["selection_status"] == "abstained"
            for row in results["cases"]
        )
        self.assertEqual(reviewers["reviewer-a"]["selector_answerability_false_negative_count"], expected_false_negatives)
        self.assertEqual(
            reviewers["reviewer-a"]["selector_answerability_agreement_count"],
            26 - expected_false_negatives,
        )
        self.assertEqual(reviewers["reviewer-b"]["selector_answerability_denominator"], 25)
        self.assertEqual(reviewers["reviewer-b"]["selector_answerability_uncertain_excluded_count"], 1)
        self.assertEqual(reviewers["reviewer-b"]["unsupported_inference_count"], 1)
        case = next(row for row in report["human_review_cases"] if row["case_id"] == "exec-success-name")
        self.assertEqual(case["unsupported_inference_count"], 1)
        self.assertEqual(case["answerability_agreement_rate"], 0.0)

    def test_v3_requires_two_distinct_fully_blinded_reviewer_ids_for_gate_status(self) -> None:
        results = _result(self.corpus, self.digest, version=3)
        for row in results["cases"]:
            row["human_reviews"] = row["human_reviews"][:1]
        report = self._validate(results)
        self.assertEqual(
            report["human_review_gate_status"],
            "not_independently_reviewed",
        )
        self.assertTrue(report["human_review_status_is_self_attested_diagnostic_only"])
        self.assertEqual(
            report["human_review_gate_status_scope"],
            "reviewer_completion_only_not_independent_verification_or_model_quality",
        )
        self.assertFalse(report["human_review_identity_or_independence_verified_automatically"])
        self.assertFalse(report["human_review_is_model_quality_gate"])
        self.assertEqual(report["human_review_gate_reviewer_id_count"], 1)

        results = _result(self.corpus, self.digest, version=3)
        row = results["cases"][0]
        row["human_reviews"][1]["blind_to_model_identity"] = False
        report = self._validate(results)
        self.assertEqual(
            report["human_review_gate_status"],
            "not_independently_reviewed",
        )
        self.assertTrue(report["human_review_status_is_self_attested_diagnostic_only"])
        self.assertEqual(
            report["human_review_gate_status_scope"],
            "reviewer_completion_only_not_independent_verification_or_model_quality",
        )
        self.assertFalse(report["human_review_is_model_quality_gate"])

    def test_v3_rejects_incomplete_or_mismatched_case_reviews(self) -> None:
        mutations = [
            ("unselected evidence", lambda row: row["human_reviews"][0]["selected_evidence_judgments"].append({
                "evidence_id": "E999",
                "supported_required_evidence_labels": [],
                "unsupported_inference": False,
            })),
            ("missing selected judgment", lambda row: row["human_reviews"][0].update(selected_evidence_judgments=[])),
            ("unknown review field", lambda row: row["human_reviews"][0].update(private_note="unexpected")),
            ("review digest mismatch", lambda row: row["human_reviews"][0].update(review_target_sha256="0" * 64)),
            ("preview digest mismatch", lambda row: row["human_reviews"][0].update(preview_request_sha256="0" * 64)),
            ("packet binding mismatch", lambda row: row["human_reviews"][0].update(review_packet_sha256="0" * 64)),
            ("missing packet binding", lambda row: row.pop("review_packet_sha256")),
            ("duplicate reviewer", lambda row: row["human_reviews"].__setitem__(1, dict(row["human_reviews"][0]))),
            ("unblinded false type", lambda row: row["human_reviews"][0].update(blind_to_model_identity="yes")),
            ("unsupported label", lambda row: row["human_reviews"][0]["selected_evidence_judgments"][0].update(
                supported_required_evidence_labels=["not-required"]
            )),
        ]
        for name, mutate in mutations:
            with self.subTest(name=name):
                results = _result(self.corpus, self.digest, version=3)
                row = next(item for item in results["cases"] if item["case_id"] == "exec-success-name")
                mutate(row)
                with self.assertRaises(evaluation.ContractError):
                    self._validate(results)

    def test_v3_binds_digest_to_validated_selector_target_fields(self) -> None:
        results = _result(self.corpus, self.digest, version=3)
        row = next(item for item in results["cases"] if item["case_id"] == "exec-success-name")
        row["available_evidence"][0]["semantic_labels"] = ["changed_after_review"]
        with self.assertRaisesRegex(evaluation.ContractError, "review target digest mismatch"):
            self._validate(results)

    def test_v3_rejects_tampered_or_mismatched_packet_files(self) -> None:
        results = _result(self.corpus, self.digest, version=3)
        with self.assertRaisesRegex(evaluation.ContractError, "tampering detected"):
            self._validate(results, lambda packet, row: packet.update(question="altered without hash update"))

        results = _result(self.corpus, self.digest, version=3)
        def alter_and_rehash(packet, row):
            packet["question"] = "altered and rehashed packet"
            packet["packet_sha256"] = evaluation._canonical_sha256({key: value for key, value in packet.items() if key != "packet_sha256"})
        with self.assertRaisesRegex(evaluation.ContractError, "corpus or question mismatch"):
            self._validate(results, alter_and_rehash)

        for name, mutate in (
            ("missing", lambda directory: (directory / "exec-success-name.json").unlink()),
            ("unknown", lambda directory: (directory / "unknown-case.json").write_text("{}", encoding="utf-8")),
            ("duplicate", lambda directory: (directory / "duplicate.json").write_bytes((directory / "exec-success-name.json").read_bytes())),
        ):
            with self.subTest(name=name):
                results = _result(self.corpus, self.digest, version=3)
                with self.assertRaises(evaluation.ContractError):
                    self._validate(results, directory_mutator=mutate)

        results = _result(self.corpus, self.digest, version=3)
        row = next(item for item in results["cases"] if item["case_id"] == "exec-success-name")
        row["source_parse_status"] = "partial"
        row["response"]["selection_status"] = "partial_selection"
        with self.assertRaisesRegex(evaluation.ContractError, "review target digest mismatch"):
            self._validate(results)

        results = _result(self.corpus, self.digest, version=3)
        with patch.object(evaluation, "MAX_REVIEW_PACKET_TOTAL_BYTES", 1):
            with self.assertRaisesRegex(evaluation.ContractError, "aggregate byte limit"):
                self._validate(results)

        results = _result(self.corpus, self.digest, version=3)
        row = next(item for item in results["cases"] if item["case_id"] == "exec-success-name")
        row["review_target_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(evaluation.ContractError, "64 lowercase hexadecimal"):
            self._validate(results)

        results = _result(self.corpus, self.digest, version=3)
        row = next(item for item in results["cases"] if item["case_id"] == "exec-success-name")
        row["preview_request_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(evaluation.ContractError, "preview_request_sha256 must be 64 lowercase hexadecimal"):
            self._validate(results)

        results = _result(self.corpus, self.digest, version=3)
        row = next(item for item in results["cases"] if item["case_id"] == "exec-success-name")
        row["preview_request_sha256"] = "d" * 64
        with self.assertRaisesRegex(evaluation.ContractError, "review target digest mismatch"):
            self._validate(results)

    def test_review_target_canonical_bytes_ignore_object_key_insertion_order(self) -> None:
        results = _result(self.corpus, self.digest, version=3)
        row = next(item for item in results["cases"] if item["case_id"] == "exec-success-name")
        case = next(item for item in self.corpus["cases"] if item["id"] == row["case_id"])
        baseline = evaluation._review_target_sha256(row, case["question"], self.digest)
        reordered = json.loads(json.dumps(row))
        reordered["response"] = dict(reversed(list(reordered["response"].items())))
        reordered["available_evidence"][0] = dict(reversed(list(reordered["available_evidence"][0].items())))
        self.assertEqual(
            evaluation._review_target_sha256(reordered, case["question"], self.digest),
            baseline,
        )

    def test_review_target_binds_question_response_parse_state_and_evidence_ids(self) -> None:
        results = _result(self.corpus, self.digest, version=3)
        row = next(item for item in results["cases"] if item["case_id"] == "exec-success-name")
        case = next(item for item in self.corpus["cases"] if item["id"] == row["case_id"])
        baseline = evaluation._review_target_sha256(row, case["question"], self.digest)
        self.assertNotEqual(evaluation._review_target_sha256(row, case["question"] + "?", self.digest), baseline)
        for mutate in (
            lambda target: target["response"].update(selection_status="partial_selection"),
            lambda target: target.update(source_parse_status="partial"),
            lambda target: target["available_evidence"][0].update(evidence_id="E002"),
            lambda target: target.update(preview_request_sha256="d" * 64),
            lambda target: target.update(case_id="different-case"),
        ):
            changed = json.loads(json.dumps(row))
            mutate(changed)
            self.assertNotEqual(
                evaluation._review_target_sha256(changed, case["question"], self.digest),
                baseline,
            )

    def test_v3_execution_errors_prevent_full_review_completion(self) -> None:
        results = _result(self.corpus, self.digest, version=3)
        failed = results["cases"].pop()
        results["errors"] = [{
            "case_id": failed["case_id"],
            "phase": "analysis",
            "error": "Synthetic test failure.",
        }]
        report = self._validate(results)
        self.assertEqual(
            report["human_review_gate_status"],
            "not_independently_reviewed",
        )
        self.assertTrue(all(not reviewer["fully_completed_blinded_independent_review"] for reviewer in report["human_reviewers"]))


if __name__ == "__main__":
    unittest.main()
