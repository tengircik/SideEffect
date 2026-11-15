"""Tests for the bounded Linux query-plan v3 reviewer handoff and validator."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import evaluate_local_query_plan_v3 as evaluator
import prepare_local_query_plan_v3_review as packet_tool
import validate_local_query_plan_v3_reviews as review_validator


class QueryPlanV3ReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus, cls.digest, _fixtures = evaluator._load_corpus(evaluator.CORPUS_PATH)

    def _completed(self, reviewer_id: str):
        packet, mapping = packet_tool.prepare_review(self.corpus, self.digest)
        packet["reviewer_metadata"] = {
            "reviewer_id": reviewer_id,
            "reviewed_at_utc": "2026-11-09T19:00:00Z",
            "independence_declaration": True,
        }
        cases = {case["id"]: case for case in self.corpus["cases"]}
        rows = {row["review_id"]: row for row in mapping["mapping"]}
        for response in packet["cases"]:
            case_id = rows[response["review_id"]]["corpus_case_id"]
            response["review"]["plan"] = copy.deepcopy(cases[case_id]["expected_plan"])
            response["review"]["rationale"] = "The literal selectors support this plan."
        return packet, mapping

    def _validate(self, *pairs):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for index, (packet, mapping) in enumerate(pairs):
                packet_path = root / f"packet-{index}.json"
                map_path = root / f"map-{index}.json"
                packet_path.write_text(json.dumps(packet), encoding="utf-8")
                map_path.write_text(json.dumps(mapping), encoding="utf-8")
                paths.append((packet_path, map_path))
            return review_validator.validate_reviews(paths)

    def test_two_complete_reviewers_produce_only_aggregate_diagnostics(self) -> None:
        report = self._validate(self._completed("alpha"), self._completed("beta"))
        self.assertEqual(report["reviewer_count"], 2)
        self.assertEqual(report["case_count_per_reviewer"], 120)
        self.assertEqual(report["per_reviewer"][0]["public_oracle_exact_plan_alignment_diagnostic"], 120)
        self.assertEqual(report["per_reviewer"][0]["public_oracle_exact_intent_group_alignment_diagnostic"], 105)
        self.assertEqual(report["pairwise_agreement"]["exact_plan_agreement_cases"], 120)
        self.assertEqual(report["pairwise_agreement"]["semantic_match_agreement_cases"], 120)
        self.assertEqual(report["pairwise_agreement"]["intent_group_comparisons"], 105)
        self.assertEqual(report["pairwise_agreement"]["exact_plan_agreement_intent_groups"], 105)
        self.assertEqual(report["qualification_result"], "not_assessed")
        self.assertFalse(report["hidden_holdout"])
        rendered = json.dumps(report)
        for private_value in ("alpha", "beta", "The literal selectors", "order1_variant1", "[syscall=openat2]"):
            self.assertNotIn(private_value, rendered)

    def test_packet_has_no_case_ids_or_expected_labels_and_uses_distinct_batch_ids(self) -> None:
        packet_a, map_a = packet_tool.prepare_review(self.corpus, self.digest)
        packet_b, map_b = packet_tool.prepare_review(self.corpus, self.digest)
        self.assertNotEqual(packet_a["review_batch_id"], packet_b["review_batch_id"])
        self.assertNotEqual(packet_a["cases"][0]["review_id"], packet_b["cases"][0]["review_id"])
        self.assertEqual(set(packet_a["cases"][0]), {"review_id", "question", "review"})
        rendered = json.dumps(packet_a)
        self.assertNotIn("order1_variant1", rendered)
        self.assertNotIn('"expected_plan"', rendered)
        self.assertEqual(len(map_a["mapping"]), 120)
        self.assertEqual(len(map_b["mapping"]), 120)

    def test_output_creation_is_private_and_never_overwrites(self) -> None:
        packet, mapping = packet_tool.prepare_review(self.corpus, self.digest)
        with tempfile.TemporaryDirectory() as directory:
            packet_path = Path(directory) / "packet.json"
            map_path = Path(directory) / "private-map.json"
            packet_tool._write_outputs(packet_path, map_path, packet, mapping)
            original_packet = packet_path.read_bytes()
            map_collision = Path(directory) / "private-map-collision.json"
            with self.assertRaises(FileExistsError):
                packet_tool._write_outputs(packet_path, map_collision, packet, mapping)
            self.assertEqual(packet_path.read_bytes(), original_packet)
            self.assertTrue(map_path.is_file())
            self.assertFalse(map_collision.exists())
            if sys.platform != "win32":
                self.assertEqual(packet_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(map_path.stat().st_mode & 0o777, 0o600)

    def test_rejects_duplicate_reviewer_identity(self) -> None:
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "reviewer IDs must be distinct"):
            self._validate(self._completed("same"), self._completed("same"))

    def test_rejects_map_from_another_review_batch(self) -> None:
        first = self._completed("alpha")
        second = self._completed("beta")
        first[1]["review_batch_id"] = "B-" + "0" * 32
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "bindings differ"):
            self._validate(first, second)

    def test_rejects_invalid_plan_and_extra_response_fields(self) -> None:
        first = self._completed("alpha")
        second = self._completed("beta")
        first[0]["cases"][0]["review"]["plan"]["unexpected"] = True
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "invalid query plan"):
            self._validate(first, second)

    def test_rejects_missing_case_and_false_independence_declaration(self) -> None:
        first = self._completed("alpha")
        second = self._completed("beta")
        first[0]["cases"].pop()
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "case count"):
            self._validate(first, second)
        first = self._completed("alpha")
        first[0]["reviewer_metadata"]["independence_declaration"] = False
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "self-declare independence"):
            self._validate(first, second)

    def test_rejects_excessive_json_depth_before_decoding(self) -> None:
        depth = review_validator.MAX_JSON_DEPTH + 1
        raw = b"[" * depth + b"null" + b"]" * depth
        with self.assertRaisesRegex(review_validator.ReviewValidationError, "nesting limit"):
            review_validator._json_bounds(raw)


if __name__ == "__main__":
    unittest.main()
