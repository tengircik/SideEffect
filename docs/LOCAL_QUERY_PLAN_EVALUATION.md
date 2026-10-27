# Local query-plan evaluation

**Status: experimental and not release-approved.** This is a separately gated M8 experiment. It is not a claim that local model analysis is useful, accurate on real captures, or supported outside Linux x86_64.

## What it does

The model translates one reviewed English question into a strict JSON query plan. SideEffect validates the plan and applies exact equality filters joined by AND to a bounded set of typed syscall-result or process-relation facts. Every match carries its source evidence reference. The model cannot write commands, shell expressions, arbitrary predicates, prose, safety verdicts, root-cause claims, effective-permission claims, or completeness claims. A zero-row result means only that no matching record appears in the bounded input.

The preview separates four things:

- `prompt`: only the question and a fixed supported-query scope, sent to the model;
- `queryable_facts`: bounded typed evidence shown to the user and evaluator, never included in the model prompt;
- `coverage` / `evidence_summary`: deterministic parser and capture limitations;
- `request_sha256`: binds the trace bytes, question and scope, system prompt, schema, and pinned model/runtime metadata.

Inspect the exact preview locally before passing its digest to `model-query`. Trace paths and other evidence may be sensitive. Nothing is uploaded, no model is downloaded, and the runtime is executable code that must be obtained and trusted separately. Linux limits, the private temporary workspace, offline runtime mode, and network-denial filter are defense in depth, not a sandbox.

## Pinned candidate and corpus

- Model repository: `ggml-org/Qwen3.5-0.8B-GGUF`
- Model revision: `9447f74101aeb4e93621884dfa36ee8effb8831b`
- Model file SHA-256: `57d1997790d1744fba5b40a7317df71ea5e2acee28c47e78f0cce39c0703f8cf`
- llama.cpp source revision: `19cce6919992fdffd92e0ac152caaf1e2b8f254e`
- Reported runtime version: `0.7.0-dev (build 11938, commit 19cce6919)`
- Corpus: 100 preregistered cases, SHA-256 `069c93fc6f8d1bd8212f28e6aaf7f63de453a6a666d77fea74e06f3ed501266f`

The corpus has 70 answerable questions across six classes and 30 cases that must abstain. It includes five source-order permutation groups, no-match questions, adversarial prompt text, and explicit partial-input coverage. All traces are hand-authored synthetic fixtures; they are not real captures. See [the corpus contract](../tests/fixtures/local_query_plan/README.md) and its pinned [corpus data](../tests/fixtures/local_query_plan/corpus.json).

## Frozen release gate

The candidate must achieve all of these in one clean, digest-pinned run:

- 100% strictly valid model plans;
- at least 85% exact plan and exact result-set accuracy over answerable cases;
- at least 75% exact result-set accuracy in every answerable class;
- at least 10 percentage points above the fixed lexical baseline;
- 100% exact plan accuracy on answerable no-match cases;
- zero query execution for the 30 required abstentions;
- identical semantic results across every permutation group;
- p95 model latency at or below 30 seconds.

Timeouts, invalid output, and runtime failures count as failures, not abstentions. Do not relax the gate to fit a candidate. Passing establishes results only for this synthetic corpus and does not establish usefulness on actual user traces.

Resource limits are 576 MiB for the model file, 2 GiB address space, 120 seconds wall/CPU time, 16 KiB model output, 128 KiB corpus, and no automatic network access. The evaluator reports process-tree RSS as a sampled peak where available, not as a precise peak measurement.

## Reproduction

Build the pinned llama.cpp revision locally with the completion binary and without network support. Obtain the pinned GGUF file from its upstream repository outside this checkout and verify its SHA-256. SideEffect never performs these actions automatically. Do not put model weights or captures in Git.

Build SideEffect and first validate every preview without inference:

```sh
cargo build --release --locked
python3 scripts/evaluate_local_query_plan.py \
  --sideeffect ./target/release/sideeffect \
  --preview-only
```

Run a single reviewed request manually if desired:

```sh
sideeffect model-query-preview --question "Which observed syscall failed?" TRACE
sideeffect model-query \
  --question "Which observed syscall failed?" \
  --runtime "$PWD/llama.cpp/build/bin/llama-completion" \
  --model "$HOME/.cache/sideeffect/models/Qwen3.5-0.8B-Q4_0.gguf" \
  --confirm-sha256 REVIEWED_REQUEST_SHA256 TRACE
```

The full evaluator requires a clean repository state so that candidate code, corpus, evaluator, and fixtures have stable provenance. Save its report outside the repository:

```sh
python3 scripts/evaluate_local_query_plan.py \
  --sideeffect ./target/release/sideeffect \
  --runtime "$PWD/llama.cpp/build/bin/llama-completion" \
  --model "$HOME/.cache/sideeffect/models/Qwen3.5-0.8B-Q4_0.gguf" \
  --report "$HOME/sideeffect-local-query-plan-report.json"
```

The evaluator does not silently accept a candidate result, fallback to a deterministic answer, or upload its report. Check the report for exact pins, repository provenance, all per-case outcomes, error counts, latency, and the registered gate before changing the release status.

## Full candidate run — 2026-10-27

The pinned Qwen3.5-0.8B candidate was run across all 100 cases from clean commit `42fa08d3c6e83fc787ef6e94acabb20662214069`, using the registered evaluator SHA-256 `6f6242d496a7dbc2640904e0491c6da8bb40f006d7097fdb5b94e79263763064`, corpus SHA-256 above, the pinned llama.cpp build, and the pinned model file.

**Result: failed; do not release this model candidate.** All 100 model responses were rejected by SideEffect validation (0/100 schema-and-semantics-valid plans). Consequently, answerable exact plan/result accuracy was 0%, versus 78.57% for the fixed lexical baseline; all five permutation groups failed. The model's p95 latency was 8.045 seconds, maximum sampled process-tree RSS was 1,047,364 KiB, and no runtime timeout occurred. The invalid-output rate alone fails the 100% validity gate, and the quality metrics fail independently. The report's zero accepted executions on required abstentions is not evidence of safe abstention behavior because no model plan was accepted.

A bounded diagnostic reproduction for a supported question returned an abstention with `entity` still set to `syscall_result` and all filters null. The strict Rust cross-field validator correctly rejected this inconsistent plan. The raw diagnostic was run only against a synthetic fixture. Do not weaken validation to accept inconsistent plans. A future candidate may evaluate a schema with mutually exclusive filter/abstain branches or another model, but it must be developed against separate development examples and rerun against this unchanged corpus; do not tune on or relax the frozen gate using these test results.

The report was saved outside the repository during evaluation. No real capture, model weight, runtime binary, or generated report was added to Git. This result supersedes the “full model run remains outstanding” status for the Qwen3.5-0.8B query-plan candidate. The pre-existing single-evidence model experiment remains a separate failed candidate; its results do not count for this query-plan design.
