#!/usr/bin/env python3
"""Interactively evaluate SideEffect's opt-in local model on synthetic traces."""

from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import re
import signal
import stat
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_CORPUS_BYTES = 64 * 1024
MAX_CASES = 128
MAX_CHILD_OUTPUT_BYTES = 1024 * 1024
EXPECTED_SCHEMA_VERSION = 5
EXPECTED_CORPUS_SHA256 = "3ce5920da93503d0c1ccdee3fa65b5078433a2d91397a52acb7bd33806c7ca1f"
REGISTERED_ACCEPTANCE_CRITERIA = {
    "minimum_answerable_accuracy_gain": 0.10,
    "maximum_false_selection_rate": 0.0,
    "maximum_p95_latency_seconds": 30,
}
REGISTERED_PERMUTATION_GROUP_SIZES = {
    "same_facts_source_order": 4,
    "errno_source_order": 4,
    "path_source_order": 4,
}
MAX_TRACE_FIXTURE_BYTES = 32 * 1024 * 1024
MAX_MODEL_BYTES = 512 * 1024 * 1024
EXPECTED_MODEL_SHA256 = "da2572f16c06133561ce56accaa822216f2391ef4d37fba427801cd6736417d4"
EXPECTED_MODEL_REPOSITORY_REVISION = "a41486f827d17edd055fe6b3b0ba3f8d427c0519"
EXPECTED_RUNTIME_SOURCE_REVISION = "4762ad7316dcdec20016ab5985fb46a27902204d"
EXPECTED_SELECTION_LABEL = "model_selected_single_evidence_for_human_review_not_verified_findings"


class OutputLimitExceeded(RuntimeError):
    """A child exceeded the evaluator's bounded stdout/stderr capture."""


def verify_model_candidate(path: Path) -> Path:
    """Verify the exact pinned model through a no-follow bounded file handle."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_MODEL_BYTES:
            raise ValueError("model candidate must be a bounded regular file")
        hasher = hashlib.sha256()
        total = 0
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_MODEL_BYTES:
                    raise ValueError("model candidate exceeds the evaluator's file-size limit")
                hasher.update(chunk)
        if hasher.hexdigest() != EXPECTED_MODEL_SHA256:
            raise ValueError("model file SHA-256 does not match the evaluator's pinned candidate")
        return path.absolute()
    finally:
        os.close(descriptor)


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str


def run(arguments: list[str], timeout: int = 30, *, env: dict[str, str] | None = None) -> RunResult:
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        shell=False,
        env=env,
        start_new_session=os.name == "posix",
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    outputs: list[bytes | None] = [None, None]
    exceeded = threading.Event()

    def drain(stream: Any, index: int) -> None:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_CHILD_OUTPUT_BYTES:
                exceeded.set()
                break
            chunks.append(chunk)
        outputs[index] = b"".join(chunks)

    assert process.stdout is not None and process.stderr is not None
    readers = [
        threading.Thread(target=drain, args=(process.stdout, 0), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, 1), daemon=True),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout
    timed_out = False

    def terminate_tree() -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass

    while process.poll() is None:
        if exceeded.is_set():
            terminate_tree()
            break
        if time.monotonic() >= deadline:
            timed_out = True
            terminate_tree()
            break
        time.sleep(0.01)
    returncode = process.wait()
    for reader in readers:
        reader.join(timeout=1)
    if exceeded.is_set():
        terminate_tree()
    if not readers[0].is_alive():
        process.stdout.close()
    if not readers[1].is_alive():
        process.stderr.close()
    stdout = outputs[0] or b""
    stderr = outputs[1] or b""
    if exceeded.is_set():
        raise OutputLimitExceeded(
            f"child output exceeded {MAX_CHILD_OUTPUT_BYTES} bytes per stream"
        )
    if timed_out:
        raise subprocess.TimeoutExpired(
            arguments, timeout, output=stdout, stderr=stderr
        )
    return RunResult(
        returncode,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


def _prompt(preview: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(preview["prompt"])
    if not isinstance(value, dict):
        raise ValueError("preview prompt must be a JSON object")
    return value


def _event_facts(prompt: dict[str, Any]) -> list[dict[str, Any]]:
    facts = prompt.get("observed_syscall_results", [])
    return [fact for fact in facts if isinstance(fact, dict)] if isinstance(facts, list) else []


def _relation_facts(prompt: dict[str, Any]) -> list[dict[str, Any]]:
    facts = prompt.get("process_relations", [])
    return [fact for fact in facts if isinstance(fact, dict)] if isinstance(facts, list) else []


def _evidence_id(fact: dict[str, Any]) -> str | None:
    value = fact.get("evidence_id")
    if isinstance(value, str):
        return value
    evidence = fact.get("evidence")
    if isinstance(evidence, dict) and isinstance(evidence.get("evidence_id"), str):
        return evidence["evidence_id"]
    return None


def _summary_evidence_ids(value: Any) -> set[str]:
    """Collect only IDs that the exact preview summary actually assigned."""
    ids: set[str] = set()
    if isinstance(value, dict):
        evidence = value.get("evidence")
        if isinstance(evidence, dict) and isinstance(evidence.get("evidence_id"), str):
            ids.add(evidence["evidence_id"])
        for child in value.values():
            ids.update(_summary_evidence_ids(child))
    elif isinstance(value, list):
        for child in value:
            ids.update(_summary_evidence_ids(child))
    return ids


def _output_evidence_ids(preview: dict[str, Any]) -> set[str]:
    schema = preview.get("output_schema")
    property_schema = schema.get("properties", {}).get("evidence_ids") if isinstance(schema, dict) else None
    enum = property_schema.get("items", {}).get("enum") if isinstance(property_schema, dict) else None
    if not isinstance(enum, list) or any(not isinstance(item, str) for item in enum):
        raise ValueError("preview output schema has no valid evidence ID enum")
    if (
        len(enum) != len(set(enum))
        or schema.get("type") != "object"
        or property_schema.get("type") != "array"
        or property_schema.get("minItems") != 0
        or property_schema.get("maxItems") != 1
    ):
        raise ValueError("preview output schema does not enforce the one-ID-or-abstain contract")
    evidence_ids = _summary_evidence_ids(preview.get("evidence_summary"))
    if set(enum) != evidence_ids:
        raise ValueError("preview schema must expose every bounded evidence ID without question filtering")
    return evidence_ids


def _matches(fact: dict[str, Any], criteria: dict[str, Any]) -> bool:
    """Match a preregistered semantic target; corpus cases never pin E### IDs."""
    for key, expected in criteria.items():
        actual = fact.get(key)
        if key == "observed_errno" and actual is None:
            actual = fact.get("errno")
        if key == "lexical_path_hint" and actual is None:
            actual = fact.get("path_hint")
        if key in {"lexical_path_hint", "observed_errno"} and isinstance(expected, str):
            if isinstance(actual, dict):
                actual = (
                    actual.get("path", actual.get("value"))
                    if key == "lexical_path_hint"
                    else actual.get("name", actual.get("value"))
                )
            if not isinstance(actual, str):
                return False
            if key == "lexical_path_hint":
                if expected != actual:
                    return False
            elif expected.casefold() != actual.casefold():
                return False
        elif actual != expected:
            return False
    return True


def resolve_expected_ids(preview: dict[str, Any], target: dict[str, Any] | None) -> list[str]:
    """Resolve a semantic target against exact preview facts and assigned evidence IDs."""
    if target is None:
        return []
    prompt = _prompt(preview)
    summary = preview["evidence_summary"]
    allowed = _summary_evidence_ids(summary)
    if target.get("kind") == "syscall_result":
        facts = _event_facts(prompt)
    elif target.get("kind") == "process_relation":
        facts = _relation_facts(prompt)
    else:
        raise ValueError(f"unsupported target kind: {target.get('kind')!r}")
    criteria = target.get("match")
    if not isinstance(criteria, dict) or not criteria:
        raise ValueError("semantic target must have a non-empty match object")
    matches = [fact for fact in facts if _matches(fact, criteria)]
    ids = [_evidence_id(fact) for fact in matches]
    ids = [evidence_id for evidence_id in ids if evidence_id in allowed]
    allow_multiple = target.get("allow_multiple_matches") is True
    if not ids or (len(ids) != 1 and not allow_multiple):
        raise ValueError(
            f"semantic target must resolve to exactly one preview evidence reference; got {ids}"
        )
    return ids


def deterministic_selection(preview: dict[str, Any]) -> list[str]:
    """Question-aware lexical baseline over the exact typed facts supplied to the model."""
    try:
        prompt = _prompt(preview)
        raw_question = str(prompt["user_question"])
        question = raw_question.casefold()
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return []

    tokens = set(re.findall(r"[a-z0-9_./-]+", question))
    asks_failure = bool(
        tokens
        & {
            "absent",
            "denied",
            "error",
            "failed",
            "fail",
            "failure",
            "forbidden",
            "missing",
            "nonexistent",
            "refused",
            "unsuccessful",
        }
    )
    asks_success = bool(tokens & {"succeeded", "success", "successful"})
    asks_in_progress = bool(tokens & {"pending", "progress", "ongoing"})
    asks_relation = bool(
        tokens & {"child", "descendant", "created", "parent", "caller", "linked", "pid", "task", "process", "launched"}
    )
    requested_paths = re.findall(r"/[a-zA-Z0-9_./-]+", raw_question)
    normalized_question = " ".join(re.findall(r"[a-z0-9_./-]+", question))
    errno_synonyms = {
        "ENOENT": ("missing", "not found", "does not exist", "doesn't exist", "absent"),
        "EACCES": ("permission", "permission denied", "access denied", "forbidden"),
        "ECONNREFUSED": (
            "connection refused",
            "connection was refused",
            "refused connection",
            "was refused",
        ),
        "EINPROGRESS": ("pending", "connection pending", "pending connection", "in progress"),
    }
    requested_errnos = {
        errno
        for errno, phrases in errno_synonyms.items()
        if any(" ".join(re.findall(r"[a-z0-9_./-]+", phrase)) in normalized_question for phrase in phrases)
    }
    asks_path = bool(tokens & {"path", "file", "filename", "directory", "folder", "target"})
    candidates: list[tuple[int, int, dict[str, Any]]] = []
    for index, fact in enumerate(_event_facts(prompt)):
        syscall = fact.get("syscall")
        outcome = fact.get("outcome")
        score = 0
        if isinstance(syscall, str) and syscall.casefold() in tokens:
            score += 4
        if asks_failure:
            if outcome != "failure":
                continue
            score += 2
        elif asks_in_progress:
            if outcome != "in_progress":
                continue
            score += 2
        elif asks_success:
            if outcome != "success":
                continue
            score += 2
        errno = fact.get("observed_errno", fact.get("errno"))
        errno_name = errno.get("name", errno.get("value")) if isinstance(errno, dict) else errno
        if isinstance(errno_name, str) and errno_name.casefold() in tokens:
            score += 5
        elif isinstance(errno_name, str) and errno_name in requested_errnos:
            score += 5
        hint = fact.get("lexical_path_hint", fact.get("path_hint"))
        hint_path = hint.get("path", hint.get("value")) if isinstance(hint, dict) else hint
        if isinstance(hint_path, str) and any(path == hint_path for path in requested_paths):
            score += 3
        elif asks_path and not requested_paths:
            components = set(re.findall(r"[a-z0-9_]+", hint_path.casefold())) if isinstance(hint_path, str) else set()
            query_terms = tokens - {"which", "what", "the", "a", "an", "is", "was", "did", "by", "for", "from", "file", "path", "directory", "folder", "target", "openat", "openat2"}
            if components.intersection(query_terms):
                score += 2
        candidates.append((score, index, fact))

    for index, fact in enumerate(_relation_facts(prompt)):
        if asks_relation:
            score = 2
            caller, child = fact.get("caller_task_id"), fact.get("child_pid")
            requested_pids = {token for token in tokens if token.isdigit()}
            matched_pid = False
            if isinstance(caller, int) and str(caller) in requested_pids:
                score += 4
                matched_pid = True
            if isinstance(child, int) and str(child) in requested_pids:
                score += 4
                matched_pid = True
            if not requested_pids or matched_pid:
                candidates.append((score, len(_event_facts(prompt)) + index, fact))

    if not candidates:
        return []
    best = max(score for score, _, _ in candidates)
    winners = [(index, fact) for score, index, fact in candidates if score == best]
    if best == 0 or len(winners) != 1:
        return []
    evidence_id = _evidence_id(winners[0][1])
    allowed = _output_evidence_ids(preview)
    return [evidence_id] if evidence_id in allowed else []


def valid_selection(
    analysis: Any,
    allowed: set[str],
    *,
    request_sha256: str,
    parse_status: str,
    expected_evidence_summary: dict[str, Any],
) -> list[str] | None:
    """Validate the complete output contract, separating malformed output from abstention."""
    if not isinstance(analysis, dict):
        return None
    if set(analysis) != {
        "schema",
        "schema_version",
        "selection_label",
        "request_sha256",
        "model_sha256",
        "model_repository_revision",
        "runtime_source_revision",
        "evidence_summary",
        "selection",
    }:
        return None
    if (
        analysis.get("schema") != "sideeffect.local_model_analysis"
        or analysis.get("schema_version") != EXPECTED_SCHEMA_VERSION
        or analysis.get("request_sha256") != request_sha256
        or analysis.get("model_sha256") != EXPECTED_MODEL_SHA256
        or analysis.get("model_repository_revision") != "user-provided"
        or analysis.get("runtime_source_revision") != EXPECTED_RUNTIME_SOURCE_REVISION
        or analysis.get("selection_label") != EXPECTED_SELECTION_LABEL
    ):
        return None
    evidence_summary = analysis.get("evidence_summary")
    if not isinstance(evidence_summary, dict) or evidence_summary != expected_evidence_summary:
        return None
    if evidence_summary.get("parse_status") != parse_status:
        return None
    selection = analysis.get("selection")
    if not isinstance(selection, dict):
        return None
    if set(selection) != {"evidence_ids"}:
        return None
    selected = selection.get("evidence_ids")
    if (
        not isinstance(selected, list)
        or len(selected) > 1
        or any(not isinstance(value, str) or value not in allowed for value in selected)
    ):
        return None
    return selected


def validate_preview(preview: Any) -> dict[str, Any]:
    if not isinstance(preview, dict):
        raise ValueError("model-preview output must be an object")
    if (
        preview.get("schema") != "sideeffect.local_model_preview"
        or preview.get("schema_version") != EXPECTED_SCHEMA_VERSION
        or preview.get("model_sha256") != EXPECTED_MODEL_SHA256
        or preview.get("model_repository_revision") != "user-provided"
        or preview.get("runtime_source_revision") != EXPECTED_RUNTIME_SOURCE_REVISION
        or not isinstance(preview.get("request_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", preview["request_sha256"])
        or not isinstance(preview.get("evidence_summary"), dict)
    ):
        raise ValueError("model-preview schema, model/runtime pins, digest, or evidence summary mismatch")
    return preview


def load_corpus(
    path: Path, *, enforce_preregistered: bool = False
) -> tuple[Path, dict[str, Any]]:
    root = path.resolve(strict=True).parent
    if not path.is_file() or path.stat().st_size > MAX_CORPUS_BYTES:
        raise ValueError(f"corpus must be a regular file no larger than {MAX_CORPUS_BYTES} bytes")
    with path.open("rb") as source:
        raw = source.read(MAX_CORPUS_BYTES + 1)
    if len(raw) > MAX_CORPUS_BYTES:
        raise ValueError(f"corpus exceeds {MAX_CORPUS_BYTES} bytes")
    corpus = json.loads(raw.decode("utf-8"))
    if not isinstance(corpus, dict) or corpus.get("schema") != "sideeffect.local_model_evaluation_corpus":
        raise ValueError("unsupported evaluation corpus schema")
    if corpus.get("schema_version") != 4 or corpus.get("status") != "preregistered_synthetic_cases":
        raise ValueError("unsupported evaluation corpus version or status")
    if enforce_preregistered:
        if hashlib.sha256(raw).hexdigest() != EXPECTED_CORPUS_SHA256:
            raise ValueError("corpus does not match the preregistered SHA-256")
        if corpus.get("acceptance_criteria") != REGISTERED_ACCEPTANCE_CRITERIA:
            raise ValueError("corpus acceptance criteria differ from the preregistered gate")
        if corpus.get("permutation_group_sizes") != REGISTERED_PERMUTATION_GROUP_SIZES:
            raise ValueError("corpus permutation groups differ from the preregistered gate")
        if len(corpus.get("cases", [])) != 51:
            raise ValueError("preregistered corpus must contain exactly 51 cases")
        trace_hashes = corpus.get("trace_sha256")
        referenced_traces = {case.get("trace") for case in corpus["cases"] if isinstance(case, dict)}
        if (
            not isinstance(trace_hashes, dict)
            or set(trace_hashes) != referenced_traces
            or any(
                not isinstance(name, str)
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                for name, digest in trace_hashes.items()
            )
        ):
            raise ValueError("corpus must pin every referenced trace fixture SHA-256")
    criteria = corpus.get("acceptance_criteria")
    if not isinstance(criteria, dict) or not criteria:
        raise ValueError("corpus must carry preregistered acceptance criteria")
    required_criteria = {
        "minimum_answerable_accuracy_gain",
        "maximum_false_selection_rate",
        "maximum_p95_latency_seconds",
    }
    if set(criteria) != required_criteria:
        raise ValueError("acceptance criteria have an unsupported shape")
    if (
        isinstance(criteria["minimum_answerable_accuracy_gain"], bool)
        or not isinstance(criteria["minimum_answerable_accuracy_gain"], (int, float))
        or not 0 <= criteria["minimum_answerable_accuracy_gain"] <= 1
        or isinstance(criteria["maximum_false_selection_rate"], bool)
        or criteria["maximum_false_selection_rate"] != 0
        or isinstance(criteria["maximum_p95_latency_seconds"], bool)
        or not isinstance(criteria["maximum_p95_latency_seconds"], (int, float))
        or not 1 <= criteria["maximum_p95_latency_seconds"] <= 150
    ):
        raise ValueError("acceptance criteria contain invalid numeric bounds")
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases or len(cases) > MAX_CASES:
        raise ValueError(f"corpus must contain 1 to {MAX_CASES} cases")
    seen_ids: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("every corpus case must be an object")
        case_id, trace, question = case.get("id"), case.get("trace"), case.get("question")
        if (
            not isinstance(case_id, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", case_id)
            or case_id in seen_ids
        ):
            raise ValueError("case IDs must be unique bounded lowercase identifiers")
        seen_ids.add(case_id)
        if (
            not isinstance(trace, str)
            or Path(trace).name != trace
            or not trace.endswith(".trace")
            or not isinstance(question, str)
            or not question.strip()
            or len(question) > 512
        ):
            raise ValueError(f"case {case_id} has an invalid trace name or question")
        target = case.get("expected_target")
        if target is not None and (
            not isinstance(target, dict)
            or target.get("kind") not in {"syscall_result", "process_relation"}
            or not isinstance(target.get("match"), dict)
            or not target["match"]
            or any(not isinstance(key, str) for key in target["match"])
        ):
            raise ValueError(f"case {case_id} has an invalid semantic target")
        if case.get("expected_parse_status", "complete") not in {"complete", "partial"}:
            raise ValueError(f"case {case_id} has an invalid expected parse status")
        if case.get("expected_path_hint_status") not in {None, "included", "not_derived", "omitted_limit"}:
            raise ValueError(f"case {case_id} has an invalid path-hint expectation")
        if case.get("permutation_group") is not None and not isinstance(case.get("permutation_group"), str):
            raise ValueError(f"case {case_id} has an invalid permutation group")
        if target is not None and "allow_multiple_matches" in target and not isinstance(target["allow_multiple_matches"], bool):
            raise ValueError(f"case {case_id} has an invalid multiple-match setting")
    return root, corpus


def repository_provenance(repository: Path, *, require_clean: bool) -> dict[str, Any]:
    revision_result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        timeout=5,
        check=True,
    )
    status_result = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        timeout=5,
        check=True,
    )
    dirty = bool(status_result.stdout.strip())
    if require_clean and dirty:
        raise ValueError("model evaluation requires a clean Git worktree at its recorded revision")
    script_bytes = Path(__file__).resolve().read_bytes()
    return {
        "repository_revision": revision_result.stdout.strip(),
        "worktree_clean": not dirty,
        "evaluator_sha256": hashlib.sha256(script_bytes).hexdigest(),
    }


def prepare_verified_fixtures(
    root: Path, corpus: dict[str, Any]
) -> tuple[tempfile.TemporaryDirectory, dict[str, Path]]:
    expected_hashes = corpus["trace_sha256"]
    fixture_dir = tempfile.TemporaryDirectory(prefix="sideeffect-m8-fixtures-")
    private_root = Path(fixture_dir.name)
    verified_paths: dict[str, Path] = {}
    try:
        for name, expected_digest in expected_hashes.items():
            source = (root / name).resolve(strict=True)
            if source.parent != root or not source.is_file():
                raise ValueError(f"trace fixture must be a regular file directly under the corpus directory: {name}")
            if source.stat().st_size > MAX_TRACE_FIXTURE_BYTES:
                raise ValueError(f"trace fixture exceeds {MAX_TRACE_FIXTURE_BYTES} bytes: {name}")
            with source.open("rb") as stream:
                content = stream.read(MAX_TRACE_FIXTURE_BYTES + 1)
            if len(content) > MAX_TRACE_FIXTURE_BYTES:
                raise ValueError(f"trace fixture exceeds {MAX_TRACE_FIXTURE_BYTES} bytes: {name}")
            actual_digest = hashlib.sha256(content).hexdigest()
            if actual_digest != expected_digest:
                raise ValueError(f"trace fixture SHA-256 mismatch: {name}")
            private_copy = private_root / name
            private_copy.write_bytes(content)
            if os.name == "posix":
                os.chmod(private_copy, 0o600)
            verified_paths[name] = private_copy
    except Exception:
        fixture_dir.cleanup()
        raise
    return fixture_dir, verified_paths


def matches_expected(selected: list[str], expected: list[str]) -> bool:
    """A semantic target may have several equally acceptable evidence references."""
    if not expected:
        return not selected
    return len(selected) == 1 and selected[0] in expected


def distribution(samples: list[float], unit: str = "seconds") -> dict[str, float | int | None]:
    if not samples:
        return {
            "count": 0,
            f"min_{unit}": None,
            f"median_{unit}": None,
            f"mean_{unit}": None,
            f"p95_{unit}": None,
            f"max_{unit}": None,
        }
    ordered = sorted(samples)
    p95_index = max(0, min(len(ordered) - 1, int(0.95 * len(ordered) + 0.999999) - 1))
    return {
        "count": len(samples),
        f"min_{unit}": round(ordered[0], 3),
        f"median_{unit}": round(statistics.median(ordered), 3),
        f"mean_{unit}": round(statistics.mean(ordered), 3),
        f"p95_{unit}": round(ordered[p95_index], 3),
        f"max_{unit}": round(ordered[-1], 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sideeffect", required=True, type=Path, help="Built SideEffect executable")
    parser.add_argument("--runtime", required=True, type=Path, help="Reviewed local llama.cpp llama-cli")
    parser.add_argument("--model", required=True, type=Path, help="Manually obtained pinned GGUF model")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "tests/fixtures/local_model_synthetic/corpus.json",
        help="Synthetic corpus metadata JSON",
    )
    parser.add_argument(
        "--preview-only",
        action="store_true",
        help="Validate every semantic target against model-preview without running inference",
    )
    args = parser.parse_args()

    try:
        repository = Path(__file__).resolve().parents[1]
        provenance = repository_provenance(repository, require_clean=not args.preview_only)
        root, corpus = load_corpus(args.corpus, enforce_preregistered=True)
        fixture_dir, trace_paths = prepare_verified_fixtures(root, corpus)
        atexit.register(fixture_dir.cleanup)
        model_path = verify_model_candidate(args.model)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        parser.error(f"cannot read corpus: {error}")

    model_store = tempfile.TemporaryDirectory(prefix="sideeffect-eval-model-store-")
    atexit.register(model_store.cleanup)
    sideeffect_env = os.environ.copy()
    sideeffect_env["XDG_DATA_HOME"] = model_store.name
    try:
        registered = run(
            [str(args.sideeffect), "model", "add", "--name", "Pinned evaluation candidate",
             "--path", str(model_path), "--for", "evidence"],
            env=sideeffect_env,
        )
        if registered.returncode != 0:
            raise ValueError(f"could not register pinned evaluation model: {registered.stderr.strip()}")
        model_id = f"custom-{EXPECTED_MODEL_SHA256[:16]}"
        selected = run(
            [str(args.sideeffect), "model", "select", "evidence", model_id],
            env=sideeffect_env,
        )
        if selected.returncode != 0:
            raise ValueError(f"could not select pinned evaluation model: {selected.stderr.strip()}")
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        model_store.cleanup()
        parser.error(str(error))

    outcomes: list[dict[str, Any]] = []
    preview_results: list[dict[str, Any]] = []
    for case in corpus["cases"]:
        trace = trace_paths[case["trace"]]

        try:
            preview_result = run(
                [str(args.sideeffect), "model-preview", "--question", case["question"], str(trace)],
                env=sideeffect_env,
            )
        except (OutputLimitExceeded, subprocess.TimeoutExpired) as error:
            print(f"{case['id']}: preview process exceeded its output/time bound: {error}", file=sys.stderr)
            return 1
        if preview_result.returncode not in (0, 2):
            print(f"{case['id']}: preview failed: {preview_result.stderr.strip()}", file=sys.stderr)
            return 1
        try:
            preview = validate_preview(json.loads(preview_result.stdout))
            expected = resolve_expected_ids(preview, case.get("expected_target"))
            deterministic = deterministic_selection(preview)
            allowed = _output_evidence_ids(preview)
            expected_hint_status = case.get("expected_path_hint_status")
            if expected_hint_status is not None:
                prompt = _prompt(preview)
                statuses = [
                    fact.get("lexical_path_hint_status")
                    for fact in _event_facts(prompt)
                ]
                if expected_hint_status not in statuses:
                    raise ValueError(
                        f"expected lexical path-hint status {expected_hint_status!r} not present"
                    )
                if expected_hint_status == "omitted_limit" and any(
                    isinstance(fact.get("lexical_path_hint"), dict)
                    and fact["lexical_path_hint"].get("path")
                    for fact in _event_facts(prompt)
                ):
                    raise ValueError("omitted path expectation unexpectedly exposed a path")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            print(f"{case['id']}: preview/corpus mismatch: {error}", file=sys.stderr)
            return 1

        print(f"\n[{case['id']}] {case['question']}")
        print(f"Parse status: {preview['evidence_summary']['parse_status']}")
        print(f"Model SHA-256: {preview['model_sha256']}")
        print(f"Model repository revision: {preview['model_repository_revision']}")
        print(f"Runtime source revision: {preview['runtime_source_revision']}")
        print(f"System prompt: {preview['system_prompt']}")
        print(f"Model facts: {preview['prompt']}")
        print(f"Allowed output schema: {json.dumps(preview['output_schema'], sort_keys=True)}")
        print(f"Question-aware deterministic selection: {deterministic}")
        print(f"Semantic expected evidence (resolved from preview): {expected}")
        if args.preview_only:
            preview_results.append(
                {
                    "id": case["id"],
                    "expected_evidence_ids_resolved_from_preview": expected,
                    "baseline_selection": deterministic,
                    "parse_status": preview["evidence_summary"].get("parse_status"),
                    "request_sha256": preview["request_sha256"],
                }
            )
            continue
        digest = preview["request_sha256"]
        confirmation = input(f"Review the exact request, then type its digest to run: {digest}\n> ").strip()
        if confirmation != digest:
            print("Request was not confirmed; stopping without running this or later cases.", file=sys.stderr)
            return 1

        started = time.perf_counter()
        try:
            analysis_result = run(
                [
                    str(args.sideeffect), "model-analyze", "--question", case["question"],
                    "--runtime", str(args.runtime),
                    "--confirm-sha256", digest, str(trace),
                ],
                timeout=150,
                env=sideeffect_env,
            )
            elapsed = time.perf_counter() - started
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - started
            outcome = {"id": case["id"], "status": "invalid_timeout", "elapsed_seconds": elapsed}
            outcomes.append(outcome)
            print(f"{case['id']}: timed out; counted as invalid output, not abstention")
            continue
        except OutputLimitExceeded as error:
            elapsed = time.perf_counter() - started
            outcome = {"id": case["id"], "status": "invalid_output_limit", "elapsed_seconds": elapsed}
            outcomes.append(outcome)
            print(f"{case['id']}: {error}; counted as invalid output, not abstention")
            continue

        expected_parse = case.get("expected_parse_status", "complete")
        expected_exit = 2 if expected_parse == "partial" else 0
        if analysis_result.returncode != expected_exit:
            outcomes.append({"id": case["id"], "status": "invalid_exit", "exit_code": analysis_result.returncode, "elapsed_seconds": elapsed})
            print(f"{case['id']}: invalid run (exit {analysis_result.returncode}); not scored as abstention")
            continue
        try:
            analysis = json.loads(analysis_result.stdout)
            selected = valid_selection(
                analysis,
                allowed,
                request_sha256=digest,
                parse_status=expected_parse,
                expected_evidence_summary=preview["evidence_summary"],
            )
        except json.JSONDecodeError:
            selected = None
        if selected is None:
            outcomes.append({"id": case["id"], "status": "invalid_output", "elapsed_seconds": elapsed})
            print(f"{case['id']}: invalid model output; not scored as abstention")
            continue

        is_answerable = case.get("expected_target") is not None
        outcome = {
            "id": case["id"], "status": "valid_output", "selected": selected,
            "expected_evidence_ids_resolved_from_preview": expected,
            "answerable": is_answerable,
            "exact_match": matches_expected(selected, expected),
            "answerable_correct": matches_expected(selected, expected) if is_answerable else None,
            "false_selection_on_abstention": bool(selected) if not is_answerable else None,
            "baseline_selection": deterministic,
            "baseline_exact_match": matches_expected(deterministic, expected),
            "permutation_group": case.get("permutation_group"),
            "elapsed_seconds": elapsed,
        }
        outcomes.append(outcome)
        print(f"Selected: {selected}; model={'PASS' if outcome['exact_match'] else 'FAIL'}; elapsed={elapsed:.2f}s")

    if args.preview_only:
        print("\nPreview-only corpus validation (no model inference was run)")
        print(
            json.dumps(
                {
                    "previewed_cases": len(preview_results),
                    "provenance": {
                        **provenance,
                        "corpus_sha256": EXPECTED_CORPUS_SHA256,
                        "trace_sha256": corpus["trace_sha256"],
                    },
                    "cases": preview_results,
                },
                indent=2,
            )
        )
        fixture_dir.cleanup()
        model_store.cleanup()
        return 0

    total = len(outcomes)
    valid = [case for case in outcomes if case["status"] == "valid_output"]
    answerable = [case for case in valid if case["answerable"]]
    unanswerable = [case for case in valid if not case["answerable"]]
    latencies = [case["elapsed_seconds"] for case in outcomes]
    metrics = {
        "cases_attempted": total,
        "valid_output_rate": len(valid) / total if total else None,
        "valid_outputs": len(valid),
        "invalid_runs": total - len(valid),
        "exact_accuracy_all_valid": sum(case["exact_match"] for case in valid) / len(valid) if valid else None,
        "answerable_accuracy": sum(case["answerable_correct"] for case in answerable) / len(answerable) if answerable else None,
        "answerable_valid_cases": len(answerable),
        "abstention_false_selection_rate": sum(case["false_selection_on_abstention"] for case in unanswerable) / len(unanswerable) if unanswerable else None,
        "unanswerable_valid_cases": len(unanswerable),
        "baseline_exact_accuracy_all_valid": sum(case["baseline_exact_match"] for case in valid) / len(valid) if valid else None,
        "baseline_answerable_accuracy": sum(case["baseline_exact_match"] for case in answerable) / len(answerable) if answerable else None,
        "baseline_abstention_false_selection_rate": sum(bool(case["baseline_selection"]) for case in unanswerable) / len(unanswerable) if unanswerable else None,
        "latency_seconds_all_model_run_attempts": distribution(latencies),
        "latency_seconds_valid_outputs": distribution([case["elapsed_seconds"] for case in valid]),
    }
    criteria = corpus["acceptance_criteria"]
    permutation_groups: dict[str, list[dict[str, Any]]] = {}
    for case in valid:
        group = case.get("permutation_group")
        if isinstance(group, str):
            permutation_groups.setdefault(group, []).append(case)
    expected_group_sizes = corpus.get("permutation_group_sizes", {})
    permutation_consistent = bool(expected_group_sizes) and all(
        len(permutation_groups.get(group, [])) == expected_size
        and all(case["exact_match"] for case in permutation_groups[group])
        for group, expected_size in expected_group_sizes.items()
    )
    baseline_answerable = metrics["baseline_answerable_accuracy"]
    answerable_accuracy = metrics["answerable_accuracy"]
    acceptance = {
        "all_outputs_valid": len(valid) == total,
        "answerable_accuracy_gain": (
            answerable_accuracy - baseline_answerable
            if answerable_accuracy is not None and baseline_answerable is not None
            else None
        ),
        "zero_false_selections_on_unanswerable": metrics["abstention_false_selection_rate"] is not None
        and metrics["abstention_false_selection_rate"]
        <= criteria["maximum_false_selection_rate"],
        "permutation_outcomes_consistent": permutation_consistent,
        "latency_p95_within_limit": (
            metrics["latency_seconds_all_model_run_attempts"]["p95_seconds"] is not None
            and metrics["latency_seconds_all_model_run_attempts"]["p95_seconds"]
            <= criteria["maximum_p95_latency_seconds"]
        ),
    }
    acceptance["answerable_gain_meets_limit"] = (
        acceptance["answerable_accuracy_gain"] is not None
        and acceptance["answerable_accuracy_gain"]
        >= criteria["minimum_answerable_accuracy_gain"]
    )
    print("\nEvaluation summary (invalid outputs remain separate from abstentions)")
    print(
        json.dumps(
            {
                "provenance": {
                    **provenance,
                    "corpus_sha256": EXPECTED_CORPUS_SHA256,
                    "trace_sha256": corpus["trace_sha256"],
                },
                "metrics": metrics,
                "acceptance": acceptance,
                "criteria": criteria,
                "cases": outcomes,
            },
            indent=2,
        )
    )
    fixture_dir.cleanup()
    model_store.cleanup()
    return 0 if all(value is True for value in acceptance.values() if isinstance(value, bool)) else 2


if __name__ == "__main__":
    raise SystemExit(main())
