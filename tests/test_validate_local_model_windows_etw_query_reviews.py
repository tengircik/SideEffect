"""Tests for bounded, aggregate-only validation of returned ETW query reviews."""

from __future__ import annotations

import json
import copy
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import evaluate_local_model_windows_etw_query as evaluator
import prepare_local_model_windows_etw_query_review as packet_tool
import validate_local_model_windows_etw_query_reviews as review_validator


class WindowsEtwQueryReviewValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus, cls.corpus_digest, _ = evaluator.load_corpus()

    def _completed_pair(self, reviewer_id: str):
        packet, mapping = packet_tool.prepare_review(self.corpus, self.corpus_digest)
        packet["reviewer_metadata"] = {
            "reviewer_id": reviewer_id,
            "reviewed_at_utc": "2026-11-09T18:00:00Z",
            "independence_declaration": True,
        }
        case_by_id = {case["id"]: case for case in self.corpus["cases"]}
        map_by_review_id = {row["review_id"]: row for row in mapping["mapping"]}
        for packet_case in packet["cases"]:
            mapped = map_by_review_id[packet_case["review_id"]]
            expected = case_by_id[mapped["corpus_case_id"]]["expected_plan"]
            packet_case["review"].update(copy.deepcopy(expected))
            packet_case["review"]["rationale"] = "The listed facts support this exact decision."
        return packet, mapping

    def test_two_distinct_complete_reviews_produce_aggregate_only_diagnostics(self) -> None:
        first = self._completed_pair("reviewer-alpha")
        second = self._completed_pair("reviewer-beta")
        report = self._validate_values(first, second)

        self.assertEqual(report["reviewer_count"], 2)
        self.assertEqual(report["case_count_per_reviewer"], 13)
        self.assertEqual(report["per_reviewer"][0]["public_oracle_exact_plan_alignment_diagnostic"], 13)
        self.assertEqual(report["pairwise_agreement"]["exact_plan_agreement_cases"], 13)
        self.assertEqual(report["pairwise_agreement"]["semantic_match_agreement_cases"], 13)
        self.assertEqual(report["qualification_result"], "not_assessed")
        self.assertFalse(report["semantic_quality_assessed"])
        self.assertFalse(report["hidden_holdout"])
        rendered = json.dumps(report)
        self.assertNotIn("reviewer-alpha", rendered)
        self.assertNotIn("reviewer-beta", rendered)
        self.assertNotIn("The listed facts", rendered)
        self.assertNotIn("tcp-send-port-443", rendered)
        self.assertNotIn("Filter network observations", rendered)

    def _validate_values(self, first, second):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pairs = []
            for index, (packet, mapping) in enumerate((first, second), start=1):
                packet_path = root / f"review-{index}.json"
                mapping_path = root / f"map-{index}.json"
                packet_path.write_text(json.dumps(packet), encoding="utf-8")
                mapping_path.write_text(json.dumps(mapping), encoding="utf-8")
                pairs.append((packet_path, mapping_path))
            return review_validator.validate_reviews(pairs)

    def test_rejects_duplicate_reviewer_identity(self) -> None:
        first = self._completed_pair("reviewer-same")
        second = self._completed_pair("reviewer-same")
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "reviewer IDs must be distinct"):
            self._validate_values(first, second)

    def test_rejects_packet_facts_that_do_not_match_the_pinned_fixture(self) -> None:
        first = self._completed_pair("reviewer-alpha")
        second = self._completed_pair("reviewer-beta")
        first[0]["cases"][0]["queryable_facts"][0]["operation"] = "tampered"
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "facts or case mapping"):
            self._validate_values(first, second)

    def test_rejects_invalid_plan_and_extra_response_fields(self) -> None:
        first = self._completed_pair("reviewer-alpha")
        second = self._completed_pair("reviewer-beta")
        first[0]["cases"][0]["review"]["filters"]["unexpected"] = "value"
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "invalid"):
            self._validate_values(first, second)

    def test_rejects_map_from_another_batch(self) -> None:
        first = self._completed_pair("reviewer-alpha")
        second = self._completed_pair("reviewer-beta")
        first[1]["review_batch_id"] = "B-" + "0" * 32
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "batch IDs differ"):
            self._validate_values(first, second)

    def test_rejects_rationale_over_limit_and_false_independence_declaration(self) -> None:
        first = self._completed_pair("reviewer-alpha")
        second = self._completed_pair("reviewer-beta")
        first[0]["cases"][0]["review"]["rationale"] = "x" * (packet_tool.MAX_RATIONALE_BYTES + 1)
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "rationale"):
            self._validate_values(first, second)
        first = self._completed_pair("reviewer-alpha")
        first[0]["reviewer_metadata"]["independence_declaration"] = False
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "self-declare independence"):
            self._validate_values(first, second)

    def test_rejects_single_reviewer(self) -> None:
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "two through eight"):
            review_validator.validate_reviews([(Path("packet"), Path("map"))])

    def test_rejects_excessive_json_nesting_before_decode(self) -> None:
        nested = b"[" * (review_validator.MAX_JSON_DEPTH + 1) + b"null" + b"]" * (review_validator.MAX_JSON_DEPTH + 1)
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "nesting limit"):
            review_validator._check_json_bounds(nested)


if __name__ == "__main__":
    unittest.main()
