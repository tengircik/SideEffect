from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import evaluate_local_model_windows_etw_query as evaluator
import prepare_local_model_windows_etw_query_review as review_tool


class _ReverseShuffle:
    def shuffle(self, items: list[dict[str, object]]) -> None:
        items.reverse()


class WindowsEtwQueryBlindReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus, self.digest, _ = evaluator.load_corpus()

    def test_packet_hides_oracle_and_model_identity_but_mapping_retains_case_join(self) -> None:
        with patch.object(review_tool.secrets, "SystemRandom", return_value=_ReverseShuffle()):
            packet, mapping = review_tool.prepare_review(self.corpus, self.digest)

        self.assertEqual(packet["schema"], review_tool.REVIEW_SCHEMA)
        self.assertEqual(len(packet["cases"]), len(self.corpus["cases"]))
        self.assertEqual(len(mapping["mapping"]), len(self.corpus["cases"]))
        packet_ids = {row["review_id"] for row in packet["cases"]}
        mapping_ids = {row["review_id"] for row in mapping["mapping"]}
        self.assertEqual(packet_ids, mapping_ids)
        self.assertEqual(len(packet_ids), len(self.corpus["cases"]))

        packet_bytes = json.dumps(packet, ensure_ascii=False, sort_keys=True)
        self.assertNotIn("expected_plan", packet_bytes)
        self.assertNotIn("expected_record_ordinals", packet_bytes)
        self.assertNotIn("tcp-send-port-443", packet_bytes)
        self.assertNotIn("network-event-order", packet_bytes)
        self.assertNotIn("model_sha256", packet_bytes)
        self.assertNotIn("model_id", packet_bytes)
        self.assertNotIn("runtime_source_revision", packet_bytes)
        self.assertNotIn("fixture_path", packet_bytes)
        self.assertNotIn("corpus_sha256", packet_bytes)
        self.assertEqual(mapping["corpus_sha256"], self.digest)
        self.assertIn("destination_port", packet["supported_plan_schema"]["filters"])
        self.assertIn("rationale", packet["cases"][0]["review"])
        self.assertIn("independence_declaration", packet["reviewer_metadata"])

    def test_packet_contains_only_decoded_finite_queryable_fact_fields(self) -> None:
        packet, _ = review_tool.prepare_review(self.corpus, self.digest)
        allowed = {
            "evidence_id", "record_ordinal", "event_kind", "operation", "path", "transport",
            "destination_address", "destination_port", "payload_process_id",
        }
        for case in packet["cases"]:
            self.assertEqual(case["source_status"]["capture_completeness"], "unknown")
            for fact in case["queryable_facts"]:
                self.assertEqual(set(fact), allowed)
                self.assertIn(fact["event_kind"], evaluator.EVENT_KINDS)
                self.assertRegex(fact["evidence_id"], r"^W[0-9]{5}$")

    def test_outputs_are_exclusive_and_mapping_is_not_embedded_in_packet(self) -> None:
        packet, mapping = review_tool.prepare_review(self.corpus, self.digest)
        with tempfile.TemporaryDirectory() as directory:
            packet_path = Path(directory) / "reviewer.json"
            mapping_path = Path(directory) / "private-map.json"
            review_tool._write_outputs(packet_path, mapping_path, packet, mapping)
            saved_packet = json.loads(packet_path.read_text(encoding="utf-8"))
            saved_mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
            self.assertNotIn("corpus_case_id", saved_packet)
            self.assertNotIn("fixture_path", saved_packet)
            self.assertEqual(saved_mapping["mapping"], mapping["mapping"])
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(packet_path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(mapping_path.stat().st_mode), 0o600)

            packet_before = packet_path.read_bytes()
            mapping_before = mapping_path.read_bytes()
            with self.assertRaises(FileExistsError):
                review_tool._write_outputs(packet_path, mapping_path, packet, mapping)
            self.assertEqual(packet_path.read_bytes(), packet_before)
            self.assertEqual(mapping_path.read_bytes(), mapping_before)

    def test_same_output_path_is_rejected(self) -> None:
        packet, mapping = review_tool.prepare_review(self.corpus, self.digest)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "same.json"
            with self.assertRaises(review_tool.ReviewPacketError):
                review_tool._write_outputs(path, path, packet, mapping)
            self.assertFalse(path.exists())

    def test_rejects_fixture_changed_after_pinned_corpus_validation(self) -> None:
        target_fixture = self.corpus["cases"][0]["fixture"]
        original_read = evaluator._read_regular_file
        read_count = 0

        def read_with_change(path: Path, limit: int, label: str) -> bytes:
            nonlocal read_count
            raw = original_read(path, limit, label)
            if path.name == target_fixture:
                read_count += 1
                if read_count == 2:
                    return raw + b"!"
            return raw

        with patch.object(evaluator, "_read_regular_file", side_effect=read_with_change):
            with self.assertRaisesRegex(review_tool.ReviewPacketError, "changed after corpus validation"):
                review_tool.prepare_review(self.corpus, self.digest)

    def test_response_contract_has_all_filter_keys_and_blanks(self) -> None:
        response = review_tool._blank_response("R-opaque")
        self.assertEqual(response["review_id"], "R-opaque")
        self.assertEqual(response["decision"], None)
        self.assertEqual(response["abstain_reason"], None)
        self.assertEqual(response["filters"], {key: None for key in sorted(evaluator.FILTER_KEYS)})
        self.assertEqual(response["rationale"], "")


if __name__ == "__main__":
    unittest.main()
