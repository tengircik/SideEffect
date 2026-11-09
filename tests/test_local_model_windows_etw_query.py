"""Contract tests for the synthetic Windows ETW query corpus validator."""

from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import evaluate_local_model_windows_etw_query as evaluator


class WindowsEtwQueryCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus, cls.digest, cls.summary = evaluator.load_corpus()

    def test_pinned_synthetic_development_corpus_and_oracles_are_consistent(self) -> None:
        self.assertEqual(self.summary["cases"], 11)
        self.assertEqual(self.summary["fixtures"], 2)
        self.assertEqual(self.summary["answerable_cases"], 6)
        self.assertEqual(self.summary["must_abstain_cases"], 5)
        self.assertEqual(self.summary["semantic_quality_assessed"], False)
        self.assertEqual(self.corpus["label_review_status"], "unreviewed_labels_not_semantically_validated")
        self.assertEqual(self.digest, evaluator.EXPECTED_CORPUS_SHA256)

    def test_rejects_match_oracle_that_disagrees_with_deterministic_filtering(self) -> None:
        corpus = copy.deepcopy(self.corpus)
        corpus["cases"][0]["expected_record_ordinals"] = []
        with self.assertRaisesRegex(evaluator.ContractError, "exact-match plan semantics"):
            evaluator.validate_corpus(corpus)

    def test_rejects_unreviewed_corpus_claim_upgrade(self) -> None:
        corpus = copy.deepcopy(self.corpus)
        corpus["label_review_status"] = "independently_reviewed"
        with self.assertRaisesRegex(evaluator.ContractError, "explicitly unreviewed"):
            evaluator.validate_corpus(corpus)

    def test_rejects_oversized_input_file_before_reading_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_bytes(b"12345")
            with self.assertRaisesRegex(evaluator.ContractError, "exceeds its byte limit"):
                evaluator._read_regular_file(path, 4, "oversized test input")

    def test_rejects_unsupported_filter_fields(self) -> None:
        corpus = copy.deepcopy(self.corpus)
        corpus["cases"][0]["expected_plan"]["filters"]["header_process_id"] = 4242
        with self.assertRaisesRegex(evaluator.ContractError, "missing or unknown"):
            evaluator.validate_corpus(corpus)

    def test_rejects_boolean_as_numeric_port(self) -> None:
        corpus = copy.deepcopy(self.corpus)
        corpus["cases"][0]["expected_plan"]["filters"]["destination_port"] = True
        with self.assertRaisesRegex(evaluator.ContractError, "invalid destination_port"):
            evaluator.validate_corpus(corpus)

    def test_rejects_fixture_digest_mismatch_and_symlink(self) -> None:
        fixture = self.corpus["fixtures"][0]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / fixture["path"]).write_bytes(b"changed")
            with self.assertRaisesRegex(evaluator.ContractError, "size or digest mismatch"):
                evaluator.validate_corpus(self.corpus, base)
            (base / fixture["path"]).unlink()
            try:
                (base / fixture["path"]).symlink_to(evaluator.FIXTURE_DIRECTORY / fixture["path"])
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaisesRegex(evaluator.ContractError, "regular non-symlink"):
                evaluator._read_regular_file(base / fixture["path"], evaluator.MAX_FIXTURE_BYTES, "test fixture")

    def test_rejects_duplicate_case_ids_and_permutation_plan_drift(self) -> None:
        corpus = copy.deepcopy(self.corpus)
        corpus["cases"][1]["id"] = corpus["cases"][0]["id"]
        with self.assertRaisesRegex(evaluator.ContractError, "duplicate ETW query case ID"):
            evaluator.validate_corpus(corpus)
        corpus = copy.deepcopy(self.corpus)
        corpus["cases"][1]["expected_plan"]["filters"]["destination_port"] = 80
        with self.assertRaisesRegex(evaluator.ContractError, "exact-match plan semantics"):
            evaluator.validate_corpus(corpus)


if __name__ == "__main__":
    unittest.main()
