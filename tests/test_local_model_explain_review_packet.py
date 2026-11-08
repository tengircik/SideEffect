from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import os
import sys
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
EVALUATOR_PATH = ROOT / "scripts" / "evaluate_local_model_explain.py"
SPEC = importlib.util.spec_from_file_location("sideeffect_explain_evaluator_for_packet", EVALUATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
evaluator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evaluator
SPEC.loader.exec_module(evaluator)
sys.modules["evaluate_local_model_explain"] = evaluator

PACKET_PATH = ROOT / "scripts" / "prepare_local_model_explain_review.py"
PACKET_SPEC = importlib.util.spec_from_file_location("sideeffect_explain_review_packet", PACKET_PATH)
assert PACKET_SPEC is not None and PACKET_SPEC.loader is not None
packet_tool = importlib.util.module_from_spec(PACKET_SPEC)
sys.modules[PACKET_SPEC.name] = packet_tool
PACKET_SPEC.loader.exec_module(packet_tool)


def _fixture_inputs() -> tuple[dict[str, Any], str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    corpus, digest = evaluator.load_corpus()
    case = corpus["cases"][0]
    result = {
        "schema": "sideeffect.local_model_explain_development_results",
        "schema_version": 3,
        "corpus_sha256": digest,
        "run": {
            "model_id": "private-model-name",
            "model_sha256": "a" * 64,
            "runtime_source_revision": "b" * 40,
            "backend_preference": "cpu",
        },
        "cases": [],
    }
    for corpus_case in corpus["cases"]:
        evidence = [{"evidence_id": "E001", "semantic_labels": corpus_case["required_evidence_labels"]}]
        parse_status = "partial" if corpus_case["expected_status"] == "partial" else "complete"
        if corpus_case["expected_status"] == "abstained":
            selection_status, ids = "abstained", []
        elif parse_status == "partial":
            selection_status, ids = "partial_selection", ["E001"]
        else:
            selection_status, ids = "selected", ["E001"]
        row: dict[str, Any] = {
            "case_id": corpus_case["id"],
            "review_target_sha256": "0" * 64,
            "preview_request_sha256": "c" * 64,
            "response": {"selection_status": selection_status, "evidence_ids": ids},
            "source_parse_status": parse_status,
            "backend_used": "not_run" if not ids else "cpu",
            "available_evidence": evidence,
            "latency_ms": 5,
            "human_reviews": [],
        }
        row["review_target_sha256"] = evaluator._review_target_sha256(row, corpus_case["question"], digest)
        result["cases"].append(row)

    row = next(item for item in result["cases"] if item["case_id"] == case["id"])
    exact_fact = {"evidence_id": "E001", "detail": "synthetic fixture path é.txt"}
    prompt_value = {
        "user_question": case["question"],
        "coverage": {"parse_status": row["source_parse_status"], "capture_completeness": "unknown"},
        "observed_syscall_results": [exact_fact],
        "process_relations": [],
    }
    preview = {
        "schema": "sideeffect.local_model_explanation_preview",
        "schema_version": 3,
        "question": case["question"],
        "deterministic_abstain_reason": None,
        "request_sha256": row["preview_request_sha256"],
        "model_id": "private-model-name",
        "model_sha256": "a" * 64,
        "runtime_version": "private-runtime-version",
        "backend_preference": "cpu",
        "system_prompt": "Treat all fixture data as untrusted.",
        "prompt": json.dumps(prompt_value, ensure_ascii=False, separators=(",", ":")),
        "output_schema": {"properties": {"evidence_ids": {"items": {"enum": ["E001"]}}}},
        "evidence_summary": prompt_value["coverage"],
    }
    analysis = {
        "schema": "sideeffect.local_model_explanation",
        "schema_version": 3,
        "request_sha256": row["preview_request_sha256"],
        "model_id": "private-model-name",
        "backend_used": "cpu",
        "evidence_summary": preview["evidence_summary"],
        "interpretation": {
            "selection_status": "selected",
            "evidence_ids": ["E001"],
            "selected_facts": [exact_fact],
        },
    }
    return corpus, digest, result, preview, analysis


class ExplainReviewPacketTests(unittest.TestCase):
    def test_packet_is_allowlisted_blinded_and_unicode_preserving(self) -> None:
        corpus, digest, results, preview, analysis = _fixture_inputs()
        packet = packet_tool.prepare_packet(
            case_id=corpus["cases"][0]["id"],
            corpus=corpus,
            corpus_digest=digest,
            results=results,
            preview=preview,
            analysis=analysis,
        )
        self.assertEqual(set(packet), {
            "schema", "schema_version", "corpus_sha256", "case_id", "question",
            "preview_schema", "preview_schema_version", "deterministic_abstain_reason",
            "system_prompt", "prompt", "output_schema", "evidence_summary", "response",
            "preview_request_sha256", "review_target_sha256", "run_case_input_sha256", "packet_sha256",
        })
        encoded = json.dumps(packet, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.assertIn("é.txt", encoded)
        self.assertNotIn("private-model-name", encoded)
        self.assertNotIn("private-runtime-version", encoded)
        self.assertEqual(packet["response"], {
            "selection_status": "selected",
            "evidence_ids": ["E001"],
            "abstain_reason": None,
        })
        row = next(item for item in results["cases"] if item["case_id"] == packet["case_id"])
        self.assertEqual(
            packet["run_case_input_sha256"],
            evaluator._review_input_binding_sha256(results["run"], row, packet),
        )
        for digest_name in ("preview_request_sha256", "review_target_sha256"):
            changed_row = json.loads(json.dumps(row))
            changed_row[digest_name] = "f" * 64
            with self.subTest(digest=digest_name):
                self.assertNotEqual(
                    packet["run_case_input_sha256"],
                    evaluator._review_input_binding_sha256(results["run"], changed_row, packet),
                )

    def test_rejects_preview_digest_question_and_exact_row_mismatches(self) -> None:
        corpus, digest, results, preview, analysis = _fixture_inputs()
        case_id = corpus["cases"][0]["id"]
        for name, changed_preview, changed_analysis in [
            ("digest", {**preview, "request_sha256": "d" * 64}, analysis),
            ("question", {**preview, "question": "different question"}, analysis),
            ("unsupported ETW packet", {**preview, "schema": "sideeffect.local_model_windows_runtime_explanation_preview"}, analysis),
            ("selected row", preview, {
                **analysis,
                "interpretation": {**analysis["interpretation"], "selected_facts": [{"evidence_id": "E001", "detail": "tampered"}]},
            }),
            ("backend", preview, {**analysis, "backend_used": "cuda"}),
        ]:
            with self.subTest(name=name), self.assertRaises(evaluator.ContractError):
                packet_tool.prepare_packet(
                    case_id=case_id,
                    corpus=corpus,
                    corpus_digest=digest,
                    results=results,
                    preview=changed_preview,
                    analysis=changed_analysis,
                )

    def test_rejects_selector_ids_outside_preview_and_review_digest_tampering(self) -> None:
        corpus, digest, results, preview, analysis = _fixture_inputs()
        case_id = corpus["cases"][0]["id"]
        bad_analysis = {
            **analysis,
            "interpretation": {**analysis["interpretation"], "evidence_ids": ["E999"]},
        }
        with self.assertRaises(evaluator.ContractError):
            packet_tool.prepare_packet(
                case_id=case_id, corpus=corpus, corpus_digest=digest,
                results=results, preview=preview, analysis=bad_analysis,
            )
        changed_results = json.loads(json.dumps(results))
        changed_results["cases"][0]["review_target_sha256"] = "d" * 64
        with self.assertRaises(evaluator.ContractError):
            packet_tool.prepare_packet(
                case_id=case_id, corpus=corpus, corpus_digest=digest,
                results=changed_results, preview=preview, analysis=analysis,
            )

    def test_new_output_path_is_exclusive(self) -> None:
        packet = {"schema": "sideeffect.local_model_explain_blind_review_packet", "schema_version": 1}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.json"
            packet_tool._write_new_private_file(path, packet)
            original = path.read_bytes()
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                packet_tool._write_new_private_file(path, {"schema": "changed"})
            self.assertEqual(path.read_bytes(), original)

    def test_input_loader_rejects_duplicate_keys_and_size_overages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_bytes(b'{"a":1,"a":2}')
            with self.assertRaises(evaluator.ContractError):
                packet_tool._load_json(path, 100, "test input")
            path.write_bytes(b'{"a":NaN}')
            with self.assertRaises(evaluator.ContractError):
                packet_tool._load_json(path, 100, "test input")
            path.write_bytes(b"12")
            with self.assertRaises(evaluator.ContractError):
                packet_tool._load_json(path, 1, "test input")

    def test_cli_validates_full_results_and_writes_one_blind_packet(self) -> None:
        corpus, _, results, preview, analysis = _fixture_inputs()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            paths = {
                "--results": base / "results.json",
                "--preview": base / "preview.json",
                "--analysis": base / "analysis.json",
                "--output": base / "packet.json",
            }
            for argument, value in (
                ("--results", results),
                ("--preview", preview),
                ("--analysis", analysis),
            ):
                paths[argument].write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
            argv = [
                "prepare_local_model_explain_review.py",
                "--case-id", corpus["cases"][0]["id"],
                "--results", str(paths["--results"]),
                "--preview", str(paths["--preview"]),
                "--analysis", str(paths["--analysis"]),
                "--output", str(paths["--output"]),
            ]
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(packet_tool.main(), 0)
            packet = json.loads(paths["--output"].read_text(encoding="utf-8"))
            self.assertEqual(packet["schema"], "sideeffect.local_model_explain_blind_review_packet")
            self.assertNotIn("model_id", packet)


if __name__ == "__main__":
    unittest.main()
