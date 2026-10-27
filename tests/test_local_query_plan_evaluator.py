import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "evaluate_local_query_plan.py"
SPEC = importlib.util.spec_from_file_location("sideeffect_query_plan_evaluator", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
EVALUATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVALUATOR
SPEC.loader.exec_module(EVALUATOR)


class RustContractTests(unittest.TestCase):
    def test_candidate_pins_and_limits_are_read_from_rust_contract(self) -> None:
        source = EVALUATOR._rust_contract_source()
        self.assertEqual(
            EVALUATOR._rust_integer_constant(source, "LOCAL_QUERY_PLAN_SCHEMA_VERSION", "u32"),
            2,
        )
        self.assertEqual(
            EVALUATOR._rust_string_constant(source, "LOCAL_QUERY_PLAN_MODEL_REPOSITORY"),
            "gguf/Qwen3.5-2B-GGUF",
        )
        self.assertEqual(
            EVALUATOR._rust_string_constant(source, "LOCAL_QUERY_PLAN_MODEL_REVISION"),
            "47f5192dcee31b32db0ba0acc04cccef89cb4b2c",
        )
        self.assertEqual(
            EVALUATOR._rust_string_constant(source, "LOCAL_QUERY_PLAN_MODEL_SHA256"),
            "9a3d0aa6c920f096441139b6a254542da855223fdad06855ea00c6c087fd713d",
        )
        self.assertEqual(EVALUATOR.MAX_MODEL_BYTES, 1_610_612_736)
        self.assertEqual(EVALUATOR.ADDRESS_SPACE_LIMIT_BYTES, 4 * 1024 * 1024 * 1024)
        self.assertEqual(EVALUATOR.EXPECTED_SCHEMA_VERSION, 2)

    def test_v2_schema_matches_disjoint_strict_rust_output_contract(self) -> None:
        schema = EVALUATOR.expected_output_schema()
        branches = schema["anyOf"]
        self.assertEqual(len(branches), 3)
        self.assertEqual(EVALUATOR.EXPECTED_SCHEMA_VERSION, 2)
        required_root = ["decision", "abstain_reason", "entity", "filters", "combine"]
        filter_fields = [
            "syscall", "outcome", "observed_errno", "lexical_path_exact",
            "process_id", "caller_task_id", "child_pid", "relation_type",
        ]

        for branch in branches:
            self.assertEqual(branch["type"], "object")
            self.assertFalse(branch["additionalProperties"])
            self.assertEqual(branch["required"], required_root)

        abstain = branches[0]
        self.assertEqual(abstain["properties"]["decision"], {"const": "abstain"})
        self.assertEqual(abstain["properties"]["entity"], {"const": None})
        self.assertEqual(abstain["properties"]["combine"], {"const": "all"})
        abstain_filters = abstain["properties"]["filters"]
        self.assertEqual(abstain_filters["required"], filter_fields)
        self.assertFalse(abstain_filters["additionalProperties"])
        self.assertTrue(all(value == {"const": None} for value in abstain_filters["properties"].values()))

        for branch, expected_entity, expected_alternatives in zip(
            branches[1:], ("syscall_result", "process_relation"), (5, 4)
        ):
            self.assertEqual(branch["properties"]["decision"], {"const": "filter"})
            self.assertEqual(branch["properties"]["entity"], {"const": expected_entity})
            self.assertEqual(branch["properties"]["abstain_reason"], {"const": None})
            union = branch["properties"]["filters"]["anyOf"]
            self.assertEqual(len(union), expected_alternatives)
            for alternative in union:
                self.assertEqual(alternative["required"], filter_fields)
                self.assertFalse(alternative["additionalProperties"])
                self.assertEqual(set(alternative["properties"]), set(filter_fields))
            for left in range(len(union)):
                for right in range(left + 1, len(union)):
                    distinguishing = next(
                        key for key in filter_fields
                        if union[left]["properties"][key] != union[right]["properties"][key]
                    )
                    self.assertTrue(
                        union[left]["properties"][distinguishing].get("type")
                        or union[left]["properties"][distinguishing].get("anyOf")
                    )
                    self.assertEqual(
                        union[right]["properties"][distinguishing], {"const": None}
                    )

    def test_v2_corpus_is_preregistered_against_current_candidate(self) -> None:
        path = ROOT / EVALUATOR.CORPUS_RELATIVE_PATH
        self.assertEqual(path.relative_to(ROOT).as_posix(), "tests/fixtures/local_query_plan_v2/corpus.json")
        _, corpus, digest = EVALUATOR.load_corpus(path, require_registered_digest=False)
        self.assertEqual(corpus["schema_version"], 2)
        self.assertEqual(corpus["candidate_pins"]["model_repository"], EVALUATOR.EXPECTED_MODEL_REPOSITORY)
        self.assertEqual(corpus["candidate_pins"]["model_file_sha256"], EVALUATOR.EXPECTED_MODEL_SHA256)
        self.assertEqual(corpus["resource_budgets"]["model_file_limit_bytes"], EVALUATOR.MAX_MODEL_BYTES)
        self.assertEqual(corpus["resource_budgets"]["address_space_bytes_max"], EVALUATOR.ADDRESS_SPACE_LIMIT_BYTES)
        self.assertEqual(len(digest), 64)

    def test_v2_corpus_rejects_candidate_revision_or_resource_drift(self) -> None:
        _, corpus, _ = EVALUATOR.load_corpus(
            ROOT / EVALUATOR.CORPUS_RELATIVE_PATH, require_registered_digest=False
        )
        for section, key in (("candidate_pins", "model_revision"), ("resource_budgets", "model_file_limit_bytes")):
            altered = json.loads(json.dumps(corpus))
            altered[section][key] = "changed" if isinstance(altered[section][key], str) else 1
            with self.subTest(section=section, key=key):
                with self.assertRaises(ValueError):
                    EVALUATOR.validate_candidate_provenance(altered)

    def test_preview_validator_requires_exact_v2_schema_and_candidate_pins(self) -> None:
        trace = b"fixture trace bytes"
        question = "Which observed connect call failed?"
        scope = {
            "entities": ["syscall_result", "process_relation"],
            "syscalls": ["execve", "execveat", "openat", "openat2", "connect"],
            "outcomes": ["success", "failure", "in_progress", "unknown"],
            "relation_types": ["fork", "vfork", "clone", "clone3"],
            "filters": [
                "syscall", "outcome", "observed_errno", "lexical_path_exact",
                "process_id", "caller_task_id", "child_pid", "relation_type",
            ],
        }
        evidence_summary = {"parse_status": "complete"}
        preview = {
            "schema": "sideeffect.local_query_plan_preview",
            "schema_version": EVALUATOR.EXPECTED_SCHEMA_VERSION,
            "question": question,
            "request_sha256": "0" * 64,
            "model_repository": EVALUATOR.EXPECTED_MODEL_REPOSITORY,
            "model_sha256": EVALUATOR.EXPECTED_MODEL_SHA256,
            "model_repository_revision": EVALUATOR.EXPECTED_MODEL_REPOSITORY_REVISION,
            "runtime_source_revision": EVALUATOR.EXPECTED_RUNTIME_SOURCE_REVISION,
            "trace_sha256": EVALUATOR.hashlib.sha256(trace).hexdigest(),
            "system_prompt": EVALUATOR.EXPECTED_SYSTEM_PROMPT,
            "prompt": json.dumps(
                {"user_question": question, "supported_query_scope": scope},
                separators=(",", ":"),
            ),
            "output_schema": EVALUATOR.expected_output_schema(),
            "evidence_summary": evidence_summary,
            "queryable_facts": [],
            "coverage": evidence_summary,
        }
        case = {"question": question}
        EVALUATOR._validate_preview(preview, case, trace)

        altered_schema = json.loads(json.dumps(preview))
        altered_schema["output_schema"]["anyOf"][1]["properties"]["entity"]["const"] = "process_relation"
        with self.assertRaises(ValueError):
            EVALUATOR._validate_preview(altered_schema, case, trace)

        altered_pin = json.loads(json.dumps(preview))
        altered_pin["model_repository"] = "unreviewed/model"
        with self.assertRaises(ValueError):
            EVALUATOR._validate_preview(altered_pin, case, trace)

    def test_v2_fixture_preparation_uses_only_the_pinned_v2_directory(self) -> None:
        root, corpus, _ = EVALUATOR.load_corpus(
            ROOT / EVALUATOR.CORPUS_RELATIVE_PATH, require_registered_digest=True
        )
        temporary, traces = EVALUATOR.prepare_fixtures(root, corpus)
        try:
            self.assertEqual(len(traces), len(corpus["trace_sha256"]))
            self.assertTrue(all(path.is_file() for path in traces.values()))
            self.assertTrue(all(path.parent == Path(temporary.name) for path in traces.values()))
        finally:
            temporary.cleanup()


class FailureAndAggregationTests(unittest.TestCase):
    def test_expected_plan_is_checked_against_fixture_match_behavior(self) -> None:
        filters = {field: None for field in EVALUATOR.FILTER_FIELDS}
        filters["syscall"] = "openat2"
        filters["outcome"] = "failure"
        plan = {
            "decision": "filter", "abstain_reason": None,
            "entity": "syscall_result", "filters": filters, "combine": "all",
        }
        facts = {
            "E001": {
                "entity": "syscall_result",
                "fact": {"syscall": "openat2", "outcome": "failure", "process_id": 12},
            },
            "E002": {
                "entity": "syscall_result",
                "fact": {"syscall": "connect", "outcome": "failure", "process_id": 13},
            },
        }
        case = {
            "id": "fixture-case", "class": "single_predicate",
            "expected_behavior": "answerable", "expected_plan": plan,
        }
        self.assertEqual(EVALUATOR.validate_expected_fact_matches(case, facts), ["E001"])

        case["class"] = "no_match"
        with self.assertRaisesRegex(ValueError, "no-match plan unexpectedly matches"):
            EVALUATOR.validate_expected_fact_matches(case, facts)

    def test_multi_match_class_requires_multiple_fixture_rows(self) -> None:
        filters = {field: None for field in EVALUATOR.FILTER_FIELDS}
        filters["syscall"] = "openat2"
        case = {
            "id": "multi-case", "class": "multi_match",
            "expected_behavior": "answerable",
            "expected_plan": {
                "decision": "filter", "abstain_reason": None,
                "entity": "syscall_result", "filters": filters, "combine": "all",
            },
        }
        one_fact = {
            "E001": {"entity": "syscall_result", "fact": {"syscall": "openat2"}},
        }
        with self.assertRaisesRegex(ValueError, "does not match at least two"):
            EVALUATOR.validate_expected_fact_matches(case, one_fact)

    def test_nonzero_exit_diagnostic_is_bounded_and_never_echoes_stderr(self) -> None:
        sentinel = b"SENSITIVE_QUESTION_AND_TRACE_PAYLOAD"
        result = EVALUATOR.RunResult(23, b"", sentinel, None, None)
        diagnostic = EVALUATOR.process_exit_failure("model query", result, (0,))
        self.assertIn("exit_code=23", diagnostic)
        self.assertIn(f"stderr_bytes={len(sentinel)}", diagnostic)
        self.assertIn(EVALUATOR.hashlib.sha256(sentinel).hexdigest(), diagnostic)
        self.assertNotIn(sentinel.decode(), diagnostic)

    def test_invalid_runs_aggregate_by_failure_kind_and_exit_code(self) -> None:
        cases = [
            {"status": "valid_output"},
            {"status": "invalid", "failure_kind": "exit_status", "exit_code": 2},
            {"status": "invalid", "failure_kind": "exit_status", "exit_code": 23},
            {"status": "invalid", "failure_kind": "timeout", "exit_code": None},
            {"status": "invalid", "failure_kind": "invalid_output", "exit_code": None},
        ]
        self.assertEqual(
            EVALUATOR.aggregate_invalid_runs(cases),
            {
                "invalid_run_count": 4,
                "by_failure_kind": {"exit_status": 2, "invalid_output": 1, "timeout": 1},
                "by_exit_code": {"2": 1, "23": 1},
            },
        )

    def test_invalid_missing_and_wrong_class_results_lower_class_accuracy(self) -> None:
        answerable = [
            {"class": "conjunction", "result_exact_match": True},
            {"class": "conjunction", "status": "invalid"},
            {"class": "single_predicate", "result_exact_match": False},
        ]
        self.assertEqual(
            EVALUATOR.per_answerable_class_accuracy(
                answerable, ["conjunction", "single_predicate", "no_match"]
            ),
            {"conjunction": 0.5, "single_predicate": 0.0, "no_match": 0.0},
        )

    def test_model_file_with_wrong_hash_is_rejected_without_echoing_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "model.gguf"
            path.write_bytes(b"MODEL_SECRET_SENTINEL")
            with self.assertRaises(ValueError) as raised:
                EVALUATOR.verify_model_candidate(path)
            self.assertNotIn("MODEL_SECRET_SENTINEL", str(raised.exception))
            self.assertIn("SHA-256", str(raised.exception))

    def test_model_file_size_is_checked_before_hash_acceptance(self) -> None:
        original_limit = EVALUATOR.MAX_MODEL_BYTES
        try:
            EVALUATOR.MAX_MODEL_BYTES = 2
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "oversized.gguf"
                path.write_bytes(b"more than the test cap")
                with self.assertRaisesRegex(ValueError, "pinned 2-byte limit"):
                    EVALUATOR.verify_model_candidate(path)
        finally:
            EVALUATOR.MAX_MODEL_BYTES = original_limit


if __name__ == "__main__":
    unittest.main()
