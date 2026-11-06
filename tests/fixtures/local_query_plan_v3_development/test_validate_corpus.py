"""Adversarial checks for the v3 public development-corpus validator."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_corpus as validator  # noqa: E402


ROOT = Path(__file__).resolve().parent


def load_data() -> dict:
    return json.loads((ROOT / "corpus.json").read_text(encoding="utf-8"))


class CorpusValidatorTests(unittest.TestCase):
    def test_public_development_corpus_validates_with_expected_group_summary(self) -> None:
        summary = validator.validate_path()
        self.assertEqual(summary["cases"], 120)
        self.assertEqual(summary["answerable"], 80)
        self.assertEqual(summary["must_abstain"], 40)
        self.assertEqual(summary["answerable_intent_groups"], 65)
        self.assertEqual(summary["source_order_groups"], 5)
        self.assertEqual(summary["zero_match_cases"], 5)

    def test_accepts_explicitly_grounded_zero_match_conjunctions(self) -> None:
        data = load_data()
        zero_match_cases = [case for case in data["cases"] if case["expected_match_count"] == 0]
        self.assertEqual(len(zero_match_cases), 5)
        for case in zero_match_cases:
            self.assertIsNone(case["target_line"])
            self.assertTrue(case["selector_support"])
            self.assertTrue(all(row["source_line"] is None for row in case["selector_support"].values()))
        self.assertEqual(validator.validate_data(data, ROOT)["zero_match_cases"], 5)

    def test_answerable_and_abstain_cases_have_evaluation_context(self) -> None:
        data = load_data()
        abstentions = [case for case in data["cases"] if case["behavior"] == "must_abstain"]
        answerable = [case for case in data["cases"] if case["behavior"] == "answerable"]
        self.assertTrue(all(case["evaluation_fixture"] == case["fixture"] for case in answerable))
        self.assertTrue(all(case["fixture"] is None for case in abstentions))
        contexts = {case["evaluation_fixture"] for case in abstentions}
        self.assertEqual(contexts, {"abstention-context.trace"})
        self.assertIn("abstention-context.trace", data["fixture_sha256"])
        self.assertEqual(validator.validate_data(data, ROOT)["fixture_files"], 25)

    def test_rejects_answerable_evaluation_fixture_mismatch(self) -> None:
        data = load_data()
        case = next(row for row in data["cases"] if row["behavior"] == "answerable")
        case["evaluation_fixture"] = "abstention-context.trace"
        with self.assertRaisesRegex(validator.CorpusError, "must equal its oracle fixture"):
            validator.validate_data(data, ROOT)

    def test_rejects_missing_evaluation_fixture(self) -> None:
        data = load_data()
        del data["cases"][0]["evaluation_fixture"]
        with self.assertRaisesRegex(validator.CorpusError, "case record schema is invalid"):
            validator.validate_data(data, ROOT)

    def test_rejects_noncanonical_abstention_context_fixture(self) -> None:
        data = load_data()
        case = next(row for row in data["cases"] if row["behavior"] == "must_abstain")
        case["evaluation_fixture"] = next(
            row["fixture"] for row in data["cases"] if row["behavior"] == "answerable"
        )
        with self.assertRaisesRegex(validator.CorpusError, "shared evaluation context fixture"):
            validator.validate_data(data, ROOT)

    def test_rejects_zero_match_oracle_when_fixture_has_a_matching_row(self) -> None:
        data = load_data()
        case = next(row for row in data["cases"] if row["id"] == "conjunction_11")
        query_path = case["expected_plan"]["filters"]["lexical_path_exact"]
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            for name in data["fixture_sha256"]:
                shutil.copy2(ROOT / name, temp_root / name)
            path = temp_root / "conjunctions.trace"
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertIn("/tmp/se-v3/conjunction/case-11/record.dat", lines[10])
            lines[10] = lines[10].replace("/tmp/se-v3/conjunction/case-11/record.dat", query_path)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
            data["fixture_sha256"]["conjunctions.trace"] = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(validator.CorpusError, "zero-match query has a target row or matches fixture evidence"):
                validator.validate_data(data, temp_root)

    def test_rejects_question_ungrounded_selector(self) -> None:
        data = load_data()
        case = next(row for row in data["cases"] if row["id"] == "syscall_01")
        case["question"] = "Filter this syscall-result fixture."
        with self.assertRaisesRegex(validator.CorpusError, "not literally grounded"):
            validator.validate_data(data, ROOT)

    def test_rejects_openat_when_question_says_openat2(self) -> None:
        data = load_data()
        case = next(row for row in data["cases"] if row["id"] == "syscall_01")
        case["expected_plan"]["filters"]["syscall"] = "openat"
        case["selector_support"]["syscall"]["canonical_value"] = "openat"
        case["selector_support"]["syscall"]["question_literal"] = "[syscall=openat]"
        case["question"] = case["question"].replace("[syscall=openat]", "[syscall=openat2]")
        with self.assertRaisesRegex(validator.CorpusError, "not literally grounded"):
            validator.validate_data(data, ROOT)

    def test_rejects_missing_support_for_non_null_filter(self) -> None:
        data = load_data()
        case = next(row for row in data["cases"] if row["id"] == "conjunction_01")
        del case["selector_support"]["syscall"]
        with self.assertRaisesRegex(validator.CorpusError, "selector support"):
            validator.validate_data(data, ROOT)

    def test_rejects_unsupported_schema_enum(self) -> None:
        data = load_data()
        case = next(row for row in data["cases"] if row["id"] == "syscall_01")
        case["expected_plan"]["filters"]["syscall"] = "read"
        case["selector_support"]["syscall"]["canonical_value"] = "read"
        case["selector_support"]["syscall"]["question_literal"] = "read"
        case["question"] += " `read`"
        with self.assertRaisesRegex(validator.CorpusError, "unsupported syscall enum"):
            validator.validate_data(data, ROOT)

    def test_rejects_duplicate_case_id(self) -> None:
        data = load_data()
        data["cases"][1]["id"] = data["cases"][0]["id"]
        with self.assertRaisesRegex(validator.CorpusError, "invalid or duplicated"):
            validator.validate_data(data, ROOT)

    def test_rejects_incorrect_declared_behavior_counts(self) -> None:
        data = load_data()
        data["behavior_counts"]["answerable"] = 79
        with self.assertRaisesRegex(validator.CorpusError, "behavior counts are invalid"):
            validator.validate_data(data, ROOT)

    def test_rejects_duplicate_normalized_answerable_template(self) -> None:
        data = load_data()
        first = next(row for row in data["cases"] if row["id"] == "syscall_01")
        second = next(row for row in data["cases"] if row["id"] == "syscall_02")
        first_template = validator._normalize_template(first["question"], first["selector_support"])
        second["question"] = first["question"].replace("openat", "connect")
        self.assertEqual(
            first_template,
            validator._normalize_template(second["question"], second["selector_support"]),
        )
        with self.assertRaisesRegex(validator.CorpusError, "repeated query template"):
            validator.validate_data(data, ROOT)

    def test_rejects_source_order_group_with_wrong_declared_size(self) -> None:
        data = load_data()
        data["source_order_group_sizes"]["order_syscall_failure"] = 3
        with self.assertRaisesRegex(validator.CorpusError, "exactly four cases"):
            validator.validate_data(data, ROOT)

    def test_rejects_different_expected_plans_inside_order_group(self) -> None:
        data = load_data()
        case = next(row for row in data["cases"] if row["id"] == "order1_variant4")
        case["expected_plan"]["filters"]["outcome"] = "success"
        with self.assertRaisesRegex(validator.CorpusError, "not literally grounded|differing expected plans"):
            validator.validate_data(data, ROOT)

    def test_rejects_different_questions_inside_order_group(self) -> None:
        data = load_data()
        case = next(row for row in data["cases"] if row["id"] == "order1_variant4")
        case["question"] += " Reworded."
        with self.assertRaisesRegex(validator.CorpusError, "identical question"):
            validator.validate_data(data, ROOT)

    def test_rejects_fixture_hash_mismatch(self) -> None:
        data = load_data()
        data["fixture_sha256"]["syscall-results.trace"] = "0" * 64
        with self.assertRaisesRegex(validator.CorpusError, "SHA-256 mismatch"):
            validator.validate_data(data, ROOT)

    def test_rejects_invalid_plan_schema(self) -> None:
        data = load_data()
        del data["cases"][0]["expected_plan"]["combine"]
        with self.assertRaisesRegex(validator.CorpusError, "exact v2 plan fields"):
            validator.validate_data(data, ROOT)

    def test_rejects_oversized_corpus_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            path.write_bytes(b" " * (validator.DEFAULT_LIMITS["corpus_bytes_max"] + 1))
            with self.assertRaisesRegex(validator.CorpusError, "exceeds its .*limit"):
                validator.validate_path(path)

    def test_rejects_oversized_fixture(self) -> None:
        limits = copy.deepcopy(validator.DEFAULT_LIMITS)
        raw = b"x" * (limits["fixture_bytes_max"] + 1)
        with self.assertRaisesRegex(validator.CorpusError, "fixture synthetic.trace exceeds its byte limit"):
            validator.parse_trace(raw, "synthetic.trace", limits)

    def test_rejects_duplicate_json_keys(self) -> None:
        with self.assertRaisesRegex(validator.CorpusError, "duplicate JSON object key"):
            validator._load_json(b'{"schema":1,"schema":2}', 100, "synthetic corpus")

    def test_rejects_overlong_fixture_record(self) -> None:
        limits = copy.deepcopy(validator.DEFAULT_LIMITS)
        raw = b"x" * (limits["fixture_record_bytes_max"] + 1) + b"\n"
        with self.assertRaisesRegex(validator.CorpusError, "over-limit line"):
            validator.parse_trace(raw, "synthetic.trace", limits)

    def test_rejects_fixture_record_count_over_limit(self) -> None:
        limits = copy.deepcopy(validator.DEFAULT_LIMITS)
        line = b"8101 openat(AT_FDCWD, \"/tmp/x\", O_RDONLY) = 3\n"
        raw = line * (limits["fixture_records_max"] + 1)
        with self.assertRaisesRegex(validator.CorpusError, "record-count limit"):
            validator.parse_trace(raw, "synthetic.trace", limits)

    def test_rejects_abstain_reason_mismatched_to_class(self) -> None:
        data = load_data()
        case = next(row for row in data["cases"] if row["id"] == "abstain_adversarial_01")
        case["expected_plan"]["abstain_reason"] = "insufficient_evidence"
        with self.assertRaisesRegex(validator.CorpusError, "abstain reason does not match its class"):
            validator.validate_data(data, ROOT)

    def test_adversarial_abstentions_allow_ambiguous_and_unsupported_scope(self) -> None:
        data = load_data()
        reasons = {
            case["expected_plan"]["abstain_reason"]
            for case in data["cases"] if case["class"] == "adversarial"
        }
        self.assertEqual(reasons, {"ambiguous", "unsupported_scope"})
        self.assertEqual(validator.validate_data(data, ROOT)["must_abstain"], 40)


if __name__ == "__main__":
    unittest.main()
