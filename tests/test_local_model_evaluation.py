"""Pure tests for the bounded, preregistered local-model evaluation helper."""

from __future__ import annotations

import json
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from scripts import evaluate_local_model as evaluation


def preview(facts: list[dict[str, Any]], question: str) -> dict[str, Any]:
    evidence_ids = [fact["evidence_id"] for fact in facts]
    return {
        "schema": "sideeffect.local_model_preview",
        "schema_version": evaluation.EXPECTED_SCHEMA_VERSION,
        "model_sha256": evaluation.EXPECTED_MODEL_SHA256,
        "model_repository_revision": evaluation.EXPECTED_MODEL_REPOSITORY_REVISION,
        "runtime_source_revision": evaluation.EXPECTED_RUNTIME_SOURCE_REVISION,
        "request_sha256": "a" * 64,
        "prompt": json.dumps({"user_question": question, "observed_syscall_results": facts}),
        "output_schema": {
            "type": "object",
            "properties": {
                "evidence_ids": {
                    "type": "array",
                    "minItems": 0,
                    "maxItems": 1,
                    "items": {"enum": evidence_ids},
                }
            },
        },
        "evidence_summary": {
            "result_facts": [
                {"evidence": {"evidence_id": evidence_id}} for evidence_id in evidence_ids
            ]
        },
    }


def analysis(selection: list[str], summary: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": "sideeffect.local_model_analysis",
        "schema_version": evaluation.EXPECTED_SCHEMA_VERSION,
        "selection_label": evaluation.EXPECTED_SELECTION_LABEL,
        "request_sha256": "a" * 64,
        "model_sha256": evaluation.EXPECTED_MODEL_SHA256,
        "model_repository_revision": evaluation.EXPECTED_MODEL_REPOSITORY_REVISION,
        "runtime_source_revision": evaluation.EXPECTED_RUNTIME_SOURCE_REVISION,
        "evidence_summary": summary or {"parse_status": "complete"},
        "selection": {"evidence_ids": selection},
    }


class EvaluationHelperTests(unittest.TestCase):
    def test_path_targets_require_exact_equality(self) -> None:
        facts = [
            {"evidence_id": "E001", "lexical_path_hint": {"path": "/foo/a"}},
            {"evidence_id": "E002", "lexical_path_hint": {"path": "/foo/ab"}},
        ]
        result = preview(facts, "Which file was opened?")
        self.assertEqual(
            evaluation.resolve_expected_ids(
                result,
                {"kind": "syscall_result", "match": {"lexical_path_hint": "/foo/a"}},
            ),
            ["E001"],
        )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            evaluation.resolve_expected_ids(
                result,
                {"kind": "syscall_result", "match": {"lexical_path_hint": "/foo"}},
            )

    def test_preview_schema_must_expose_every_evidence_id(self) -> None:
        result = preview(
            [
                {"evidence_id": "E001", "syscall": "connect", "outcome": "success"},
                {"evidence_id": "E002", "syscall": "connect", "outcome": "failure"},
            ],
            "Which connect syscall failed?",
        )
        self.assertEqual(evaluation._output_evidence_ids(result), {"E001", "E002"})
        result["output_schema"]["properties"]["evidence_ids"]["items"]["enum"] = ["E002"]
        with self.assertRaisesRegex(ValueError, "every bounded evidence ID"):
            evaluation._output_evidence_ids(result)

    def test_duplicate_semantic_targets_need_explicit_allow_multiple(self) -> None:
        facts = [
            {"evidence_id": "E001", "syscall": "connect", "outcome": "failure"},
            {"evidence_id": "E002", "syscall": "connect", "outcome": "failure"},
        ]
        result = preview(facts, "Which connect syscall failed?")
        target = {
            "kind": "syscall_result",
            "match": {"syscall": "connect", "outcome": "failure"},
        }
        with self.assertRaisesRegex(ValueError, "exactly one"):
            evaluation.resolve_expected_ids(result, target)
        target["allow_multiple_matches"] = True
        self.assertEqual(evaluation.resolve_expected_ids(result, target), ["E001", "E002"])

    def test_baseline_recognizes_plain_language_errno_and_abstains_on_ties(self) -> None:
        facts = [
            {"evidence_id": "E001", "syscall": "openat", "outcome": "failure", "observed_errno": "EACCES"},
            {"evidence_id": "E002", "syscall": "connect", "outcome": "failure", "observed_errno": "ECONNREFUSED"},
            {"evidence_id": "E003", "syscall": "connect", "outcome": "in_progress", "observed_errno": "EINPROGRESS"},
        ]
        self.assertEqual(evaluation.deterministic_selection(preview(facts, "Which file was denied permission?")), ["E001"])
        self.assertEqual(evaluation.deterministic_selection(preview(facts, "Which connect syscall failed?")), ["E002"])
        self.assertEqual(evaluation.deterministic_selection(preview(facts, "Which connection is still pending?")), ["E003"])
        self.assertEqual(evaluation.deterministic_selection(preview(facts, "Which connection was refused?")), ["E002"])
        self.assertEqual(evaluation.deterministic_selection(preview(facts, "Why did the service fail?")), [])

    def test_unknown_requested_pid_does_not_select_unrelated_relation(self) -> None:
        result = preview([], "Which child process was created by task 999?")
        prompt = json.loads(result["prompt"])
        prompt["process_relations"] = [{"evidence_id": "E001", "caller_task_id": 700, "child_pid": 701}]
        result["prompt"] = json.dumps(prompt)
        result["evidence_summary"]["process_relations"] = [
            {"evidence": {"evidence_id": "E001"}}
        ]
        result["output_schema"]["properties"]["evidence_ids"]["items"]["enum"] = ["E001"]
        self.assertEqual(evaluation.deterministic_selection(result), [])

    def test_baseline_matches_explicit_paths_without_prefix_collisions(self) -> None:
        facts = [
            {"evidence_id": "E001", "syscall": "openat", "outcome": "success", "lexical_path_hint": {"path": "/foo/a"}},
            {"evidence_id": "E002", "syscall": "openat", "outcome": "success", "lexical_path_hint": {"path": "/foo/ab"}},
        ]
        self.assertEqual(
            evaluation.deterministic_selection(preview(facts, "Which file was opened at /foo/a?")),
            ["E001"],
        )

    def test_valid_empty_selection_is_distinct_from_invalid_output(self) -> None:
        summary = {"parse_status": "complete"}
        valid = analysis([], summary)
        self.assertEqual(
            evaluation.valid_selection(
                valid,
                {"E001"},
                request_sha256="a" * 64,
                parse_status="complete",
                expected_evidence_summary=summary,
            ),
            [],
        )
        valid["schema_version"] = 3
        self.assertIsNone(
            evaluation.valid_selection(
                valid,
                {"E001"},
                request_sha256="a" * 64,
                parse_status="complete",
                expected_evidence_summary=summary,
            )
        )
        pinned_mismatch = analysis([], summary)
        pinned_mismatch["model_sha256"] = "0" * 64
        self.assertIsNone(
            evaluation.valid_selection(
                pinned_mismatch,
                {"E001"},
                request_sha256="a" * 64,
                parse_status="complete",
                expected_evidence_summary=summary,
            )
        )
        summary_mismatch = analysis([], summary)
        summary_mismatch["evidence_summary"] = {"parse_status": "complete", "result_facts": []}
        self.assertIsNone(
            evaluation.valid_selection(
                summary_mismatch,
                {"E001"},
                request_sha256="a" * 64,
                parse_status="complete",
                expected_evidence_summary=summary,
            )
        )

    def test_corpus_bounds_and_duplicate_case_ids_are_enforced(self) -> None:
        base = {
            "schema": "sideeffect.local_model_evaluation_corpus",
            "schema_version": 4,
            "status": "preregistered_synthetic_cases",
            "acceptance_criteria": {
                "minimum_answerable_accuracy_gain": 0.1,
                "maximum_false_selection_rate": 0.0,
                "maximum_p95_latency_seconds": 30,
            },
            "cases": [
                {"id": "case_one", "trace": "one.trace", "question": "Question?", "expected_target": None}
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            corpus_path = Path(directory) / "corpus.json"
            corpus_path.write_text(json.dumps(base), encoding="utf-8")
            _, loaded = evaluation.load_corpus(corpus_path)
            self.assertEqual(len(loaded["cases"]), 1)
            duplicate = dict(base)
            duplicate["cases"] = base["cases"] * 2
            corpus_path.write_text(json.dumps(duplicate), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unique"):
                evaluation.load_corpus(corpus_path)
            too_many = dict(base)
            too_many["cases"] = [
                {"id": f"case_{index}", "trace": "one.trace", "question": "Question?", "expected_target": None}
                for index in range(evaluation.MAX_CASES + 1)
            ]
            corpus_path.write_text(json.dumps(too_many), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "1 to"):
                evaluation.load_corpus(corpus_path)
            corpus_path.write_bytes(b" " * (evaluation.MAX_CORPUS_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "no larger than"):
                evaluation.load_corpus(corpus_path)

    def test_preregistered_corpus_digest_and_permutation_groups_are_pinned(self) -> None:
        corpus_path = (
            Path(__file__).resolve().parents[1]
            / "tests/fixtures/local_model_synthetic/corpus.json"
        )
        _, corpus = evaluation.load_corpus(corpus_path, enforce_preregistered=True)
        self.assertEqual(len(corpus["cases"]), 51)
        self.assertEqual(
            corpus["permutation_group_sizes"],
            evaluation.REGISTERED_PERMUTATION_GROUP_SIZES,
        )
        self.assertEqual(
            corpus["acceptance_criteria"],
            evaluation.REGISTERED_ACCEPTANCE_CRITERIA,
        )

    def test_fixture_copy_rejects_unpinned_trace_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "synthetic.trace"
            fixture.write_bytes(b"synthetic evidence\n")
            digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
            corpus = {"trace_sha256": {fixture.name: digest}}
            temporary, copies = evaluation.prepare_verified_fixtures(root, corpus)
            try:
                self.assertEqual(copies[fixture.name].read_bytes(), fixture.read_bytes())
            finally:
                temporary.cleanup()

            fixture.write_bytes(b"changed evidence\n")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                evaluation.prepare_verified_fixtures(root, corpus)

    def test_child_output_is_capped(self) -> None:
        old_limit = evaluation.MAX_CHILD_OUTPUT_BYTES
        evaluation.MAX_CHILD_OUTPUT_BYTES = 64
        try:
            with self.assertRaises(evaluation.OutputLimitExceeded):
                evaluation.run([sys.executable, "-c", "print('x' * 1000)"])
        finally:
            evaluation.MAX_CHILD_OUTPUT_BYTES = old_limit

    def test_empty_and_nonempty_latency_distributions(self) -> None:
        self.assertIsNone(evaluation.distribution([])["p95_seconds"])
        result = evaluation.distribution([1.0, 2.0, 3.0], "kib")
        self.assertEqual(result["p95_kib"], 3.0)

    def test_baseline_phrase_matching_preserves_question_word_order(self) -> None:
        facts = [
            {"evidence_id": "E001", "syscall": "openat", "outcome": "failure", "observed_errno": "EACCES"},
            {"evidence_id": "E002", "syscall": "openat", "outcome": "failure", "observed_errno": "ENOENT"},
        ]
        result = preview(facts, "Which file had permission denied?")
        self.assertEqual(evaluation.deterministic_selection(result), ["E001"])


if __name__ == "__main__":
    unittest.main()
