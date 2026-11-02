#!/usr/bin/env python3
"""Contract tests for the local model explanation corpus runner."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import ctypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_local_model_explain_corpus as runner


FAKE_CLI = r'''
import json, pathlib, sys
mode = sys.argv[1]
trace = pathlib.Path(sys.argv[-1])
row = {"evidence_id": "E001", "kind": "syscall_result", "result": "success"}
if mode == "model-explain-preview":
    question = sys.argv[sys.argv.index("--question") + 1]
    value = {
        "schema": "sideeffect.local_model_explanation_preview",
        "schema_version": 3,
        "question": question,
        "request_sha256": "a" * 64,
        "backend_preference": sys.argv[sys.argv.index("--backend") + 1],
        "model_id": "test-model",
        "model_sha256": "b" * 64,
        "runtime_source_revision": "c" * 40,
        "evidence_summary": {"parse_status": "complete"},
        "prompt": json.dumps({"observed_syscall_results": [row], "process_relations": []}),
    }
    print(json.dumps(value))
elif mode == "model-explain":
    question = sys.argv[sys.argv.index("--question") + 1]
    value = {
        "schema": "sideeffect.local_model_explanation",
        "schema_version": 3,
        "request_sha256": "a" * 64,
        "model_id": "test-model",
        "backend_used": "cpu",
        "interpretation": {
            "selection_status": "selected",
            "evidence_ids": ["E001"],
            "selected_facts": [row],
        },
    }
    print(json.dumps(value))
else:
    raise SystemExit(9)
'''


class CorpusRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fake_cli = Path(self.temp.name) / "fake_cli.py"
        self.fake_cli.write_text(FAKE_CLI, encoding="utf-8")

    def _run(self, *, version: int = 3, runtime: str | None = None, invoke=runner._invoke):
        return runner.run_corpus(
            sideeffect_command=[sys.executable, str(self.fake_cli)],
            backend="auto",
            runtime=runtime,
            timeout_seconds=5,
            results_version=version,
            invoke=invoke,
        )

    def test_preview_without_empty_process_relations_section_is_valid(self) -> None:
        row = {"evidence_id": "E001", "kind": "syscall_result", "result": "success"}
        preview = {
            "schema": "sideeffect.local_model_explanation_preview",
            "schema_version": 3,
            "question": "Which executable started?",
            "request_sha256": "a" * 64,
            "evidence_summary": {"parse_status": "complete"},
            "prompt": json.dumps({"observed_syscall_results": [row]}),
        }

        parse_status, available, allowed = runner._preview_evidence(preview, preview["question"])

        self.assertEqual(parse_status, "complete")
        self.assertEqual(available, [{"evidence_id": "E001", "semantic_labels": []}])
        self.assertEqual(allowed, {"E001": row})

    def test_runs_full_corpus_and_emits_valid_v3_without_labels_or_paths(self) -> None:
        results = self._run()
        corpus, digest = runner.evaluator.load_corpus()
        self.assertEqual(len(results["cases"]), len(corpus["cases"]))
        self.assertNotIn("errors", results)
        self.assertEqual(results["run"]["model_id"], "test-model")
        runner.evaluator._validate_results_v3(results, corpus, digest)
        for row in results["cases"]:
            self.assertEqual(row["available_evidence"], [{"evidence_id": "E001", "semantic_labels": []}])
            self.assertEqual(row["human_reviews"], [])
            self.assertNotIn("fixture", json.dumps(row))
        self.assertNotIn(str(ROOT), json.dumps(results))
        self.assertNotIn("required_evidence_labels", json.dumps(results))

    def test_emits_valid_v2_when_requested(self) -> None:
        results = self._run(version=2)
        corpus, digest = runner.evaluator.load_corpus()
        self.assertEqual(results["schema_version"], 2)
        runner.evaluator._validate_results_v2(results, corpus, digest)
        self.assertNotIn("preview_request_sha256", results["cases"][0])

    def test_configured_runtime_uses_cli_option_order(self) -> None:
        analysis_argv: list[str] = []

        def capture_analysis(argv, **kwargs):
            if len(argv) > 2 and argv[2] == "model-explain" and not analysis_argv:
                analysis_argv.extend(argv)
            return runner._invoke(argv, **kwargs)

        results = self._run(runtime="C:/tools/llama-completion.exe", invoke=capture_analysis)

        self.assertEqual(len(results["cases"]), 26)
        self.assertNotIn("errors", results)
        corpus, _digest = runner.evaluator.load_corpus()
        self.assertEqual(
            analysis_argv[2:8],
            [
                "model-explain",
                "--question",
                corpus["cases"][0]["question"],
                "--backend",
                "auto",
                "--runtime",
            ],
        )
        self.assertEqual(analysis_argv[8], "C:/tools/llama-completion.exe")
        self.assertEqual(analysis_argv[9], "--confirm-sha256")

    def test_records_partial_analysis_timeout_without_losing_other_cases(self) -> None:
        calls = 0

        def timeout_one_analysis(argv, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                return None, b"", "timeout"
            return runner._invoke(argv, **kwargs)

        results = self._run(invoke=timeout_one_analysis)
        self.assertEqual(len(results["cases"]), 25)
        self.assertEqual(results["errors"][0]["phase"], "analysis")
        self.assertEqual(results["errors"][0]["error"], "analysis timed out after preview completed; subprocess output was discarded")
        corpus, digest = runner.evaluator.load_corpus()
        runner.evaluator._validate_results_v3(results, corpus, digest)

    def test_invoke_bounds_output_and_runtime(self) -> None:
        output = [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1000000)"]
        code, data, failure = runner._invoke(output, timeout_seconds=5, output_limit=2048)
        self.assertEqual(failure, "output_limit")
        self.assertEqual(data, b"")

        sleeper = [sys.executable, "-c", "import time; time.sleep(10)"]
        _code, data, failure = runner._invoke(sleeper, timeout_seconds=0.1, output_limit=2048)
        self.assertEqual(failure, "timeout")
        self.assertEqual(data, b"")

    def test_destination_creation_is_exclusive_and_private_on_posix(self) -> None:
        output = Path(self.temp.name) / "results.json"
        runner._write_new_private_file(output, b"{}")
        with self.assertRaises(FileExistsError):
            runner._write_new_private_file(output, b"replacement")
        self.assertEqual(output.read_bytes(), b"{}")
        if os.name != "nt":
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(os.name == "nt", "Windows DACL contract test")
    def test_windows_destination_has_explicit_protected_single_user_ace(self) -> None:
        output = Path(self.temp.name) / "results.json"
        runner._write_new_private_file(output, b"private")
        with self.assertRaises(OSError):
            runner._write_new_private_file(output, b"replacement")

        class Acl(ctypes.Structure):
            _fields_ = [("revision", ctypes.c_ubyte), ("reserved", ctypes.c_ubyte), ("size", ctypes.c_ushort), ("ace_count", ctypes.c_ushort)]

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi32.GetFileSecurityW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        advapi32.GetFileSecurityW.restype = ctypes.c_int
        advapi32.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_uint32)]
        advapi32.GetSecurityDescriptorControl.restype = ctypes.c_int
        advapi32.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int)]
        advapi32.GetSecurityDescriptorDacl.restype = ctypes.c_int
        advapi32.GetAce.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
        advapi32.GetAce.restype = ctypes.c_int
        advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        advapi32.EqualSid.restype = ctypes.c_int
        advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
        advapi32.OpenProcessToken.restype = ctypes.c_int
        advapi32.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        advapi32.GetTokenInformation.restype = ctypes.c_int
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        needed = ctypes.c_uint32()
        advapi32.GetFileSecurityW(str(output), 0x4, None, 0, ctypes.byref(needed))
        self.assertGreater(needed.value, 0)
        descriptor = ctypes.create_string_buffer(needed.value)
        self.assertTrue(advapi32.GetFileSecurityW(str(output), 0x4, descriptor, needed, ctypes.byref(needed)))
        control = ctypes.c_ushort()
        revision = ctypes.c_uint32()
        self.assertTrue(advapi32.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)))
        self.assertTrue(control.value & 0x1000, "DACL must be protected from parent inheritance")
        present = ctypes.c_int()
        dacl = ctypes.c_void_p()
        defaulted = ctypes.c_int()
        self.assertTrue(advapi32.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)))
        self.assertTrue(present.value)
        self.assertEqual(ctypes.cast(dacl, ctypes.POINTER(Acl)).contents.ace_count, 1)
        ace = ctypes.c_void_p()
        self.assertTrue(advapi32.GetAce(dacl, 0, ctypes.byref(ace)))
        self.assertEqual(ctypes.c_ubyte.from_address(ace.value).value, 0, "the only ACE must be an allow ACE")
        self.assertEqual(ctypes.c_uint32.from_address(ace.value + 4).value, 0x001F01FF, "the current user must have full access")

        token = ctypes.c_void_p()
        self.assertTrue(advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x8, ctypes.byref(token)))
        try:
            token_size = ctypes.c_uint32()
            advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(token_size))
            token_data = ctypes.create_string_buffer(token_size.value)
            self.assertTrue(advapi32.GetTokenInformation(token, 1, token_data, token_size, ctypes.byref(token_size)))

            class SidAndAttributes(ctypes.Structure):
                _fields_ = [("sid", ctypes.c_void_p), ("attributes", ctypes.c_uint32)]

            class TokenUser(ctypes.Structure):
                _fields_ = [("user", SidAndAttributes)]

            current_sid = ctypes.cast(token_data, ctypes.POINTER(TokenUser)).contents.user.sid
            ace_sid = ctypes.c_void_p(ace.value + 8)
            self.assertTrue(advapi32.EqualSid(ace_sid, current_sid), "the only allow ACE must name the current user's token SID")
        finally:
            kernel32.CloseHandle(token)


if __name__ == "__main__":
    unittest.main()
