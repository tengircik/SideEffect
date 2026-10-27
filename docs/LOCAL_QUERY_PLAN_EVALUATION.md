# Local query-plan evaluation

**Status: experimental and not release-approved.** This is a separately gated M8 experiment. No model candidate has passed the frozen v2 usefulness gate. This is not a claim that local model analysis is useful or accurate on real captures. The model-query command is currently implemented only for Linux x86_64; GPU model experiments below were run separately on Windows and do not establish native Windows product support.

## What it does

The model translates one reviewed English question into a strict JSON query plan. SideEffect validates the plan and applies exact equality filters joined by AND to a bounded set of typed syscall-result or process-relation facts. Every match carries its source evidence reference. The model cannot write commands, shell expressions, arbitrary predicates, prose, safety verdicts, root-cause claims, effective-permission claims, or completeness claims. A zero-row result means only that no matching record appears in the bounded input.

The preview separates four things:

- `prompt`: only the question and a fixed supported-query scope, sent to the model;
- `queryable_facts`: bounded typed evidence shown to the user and evaluator, never included in the model prompt;
- `coverage` / `evidence_summary`: deterministic parser and capture limitations;
- `request_sha256`: binds the trace bytes, question and scope, system prompt, schema, and pinned model/runtime metadata.

Inspect the exact preview locally before passing its digest to `model-query`. Trace paths and other evidence may be sensitive. Nothing is uploaded, no model is downloaded, and the runtime is executable code that must be obtained and trusted separately. Linux limits, the private temporary workspace, offline runtime mode, and network-denial filter are defense in depth, not a sandbox.

## Current contract, candidate pin, and corpus

- Query-plan schema: version 2
- In-code development model pin: `gguf/Qwen3.5-2B-GGUF`, revision `47f5192dcee31b32db0ba0acc04cccef89cb4b2c`
- Model file: `qwen3.5-2b-Q4_K_M.gguf`, 1,312,164,352 bytes, SHA-256 `9a3d0aa6c920f096441139b6a254542da855223fdad06855ea00c6c087fd713d`
- llama.cpp source revision: `19cce6919992fdffd92e0ac152caaf1e2b8f254e`
- Reported runtime version: `0.7.0-dev (build 11938, commit 19cce6919)`
- Independent v2 corpus: 100 preregistered cases, SHA-256 `cdd73fe2a9847a7c78f40ba1f63496ee23b65cac303d7fc423013536333dbdea`

The corpus has 70 answerable questions and 30 cases that must abstain. It includes five source-order permutation groups, no-match questions, adversarial prompt text, and explicit partial-input coverage. All traces are hand-authored synthetic fixtures; they are not real captures. See [the v2 corpus contract](../tests/fixtures/local_query_plan_v2/README.md) and its pinned [corpus data](../tests/fixtures/local_query_plan_v2/corpus.json).

## Frozen release gate

The candidate must achieve all of these in one clean, digest-pinned run:

- 100% strictly valid model plans;
- at least 85% exact plan and exact result-set accuracy over answerable cases;
- at least 75% exact result-set accuracy in every answerable class;
- at least 10 percentage points above the fixed lexical baseline;
- 100% exact plan accuracy on answerable no-match cases;
- zero emitted filters for the 30 required abstentions;
- all four cases correct in every source-order permutation group;
- p95 model latency at or below 30 seconds.

Timeouts, invalid output, and runtime failures count as failures, not abstentions. Do not relax the gate to fit a candidate. Passing establishes results only for this synthetic corpus and does not establish usefulness on actual user traces.

The evaluator reports plan accuracy and result-set accuracy separately. Plan accuracy requires an exact match with the case's expected query plan. Result-set accuracy compares the returned semantic rows with the rows selected by that case's frozen expected plan over the validated preview facts; it is independent of plan identity. The lexical baseline uses the same result-row comparison, and its plan-signature accuracy is recorded separately. This prevents equivalent or different plans from being counted as correct results solely because their JSON matches (or fails to match) the expected plan. Required abstentions and no-match plans retain their separate false-filter and exact-plan checks.

### Frozen baseline measurement — 2026-10-27

A clean preview-only run at commit `f115e648db4b16dd7e676f764b5bfb1774c88fec` validated all 100 previews against corpus SHA-256 `cdd73fe2a9847a7c78f40ba1f63496ee23b65cac303d7fc423013536333dbdea` with evaluator SHA-256 `5073b7b559f3cf80a41eecfc34fad5b08cddfd5dc85844e2098a62ba11cd0a0c`. The frozen lexical baseline returned the expected semantic rows in 40/70 answerable cases (57.14%) and matched the expected plan signature in 10/70 (14.29%). By result class it scored 11/20 answerable, 2/10 single-predicate, 5/10 conjunction, 3/5 paraphrase, 0/5 multi-match, 9/10 process-relation, and 10/10 no-match. This run did not invoke a model and is not a model gate result. A candidate therefore needs at least 67.14% exact result-set accuracy to clear the baseline-improvement threshold, while still meeting the separate 85% result and plan thresholds and every other frozen criterion. The full preview report was saved outside the repository; no model weights or captures were used.

### Full v2 candidate run — 2026-10-28

The pinned Qwen3.5-2B Q4_K_M candidate (1,312,164,352 bytes; SHA-256 `9a3d0aa6c920f096441139b6a254542da855223fdad06855ea00c6c087fd713d`) was evaluated on the unchanged 100-case corpus at clean commit `407b2914a2905753b96e80915e1f5aa65b6c997f`, with evaluator SHA-256 `5073b7b559f3cf80a41eecfc34fad5b08cddfd5dc85844e2098a62ba11cd0a0c` and llama.cpp revision `19cce6919992fdffd92e0ac152caaf1e2b8f254e`. This was a CPU run in WSL2; the pinned runtime reported no accelerator device.

**Result: failed; do not release this candidate.** All 100 outputs were schema- and reference-valid, but all 100 abstained with `unsupported_scope`, including supported answerable questions and zero-result queries. Exact answerable plans: 0/70; exact answerable result sets: 10/70 (14.29%), all from the no-match result class; fixed baseline: 40/70 (57.14%). The accuracy difference was -42.86 percentage points. No-match exact-plan accuracy was 0/10. All five order-permutation groups failed. There were 0 false filters on the 30 required abstentions, the deterministic matcher consistency check was 100%, and p95 latency was 15.458 seconds. Sampled process-tree RSS peaked at 2,069,516 KiB; this is an approximate Linux `/proc` sample. Schema validity, abstention safety, latency, and deterministic consistency passed their individual checks; the usefulness, plan-accuracy, class, no-match-plan, and permutation criteria failed. The complete report is retained outside the repository at `~/sideeffect-queryplan-v2-2b-report.json`. This confirms the candidate's over-abstention; it does not justify weakening the gate.

Resource limits are 1.5 GiB for the model file, 4 GiB address space, 120 seconds wall/CPU time, 16 KiB model output, 128 KiB corpus, and no automatic network access. The evaluator reports process-tree RSS as a sampled peak where available, not as a precise peak measurement. GPU inference has not been integrated into the SideEffect command or its sandboxed Linux runtime; CUDA measurements below are separate development experiments.

## GPU implementation direction

If a local model candidate first passes the frozen usefulness gate, prefer GPU acceleration on hardware and a backend that SideEffect can support and validate. Keep a clearly reported CPU fallback for systems without a supported accelerator. The command must report which backend actually ran and any resource-limit or fallback outcome; it must never silently claim GPU execution. GPU support must preserve explicit user opt-in, offline behavior, strict plan validation, and bounded execution. Define and validate accelerator-memory behavior for each supported backend before claiming that its resource use is bounded. GPU availability or speed does not change the model-quality gate, and this direction is not an implemented feature or a release claim.

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
  --model "$HOME/.cache/sideeffect/models/qwen3.5-2b-Q4_K_M.gguf" \
  --confirm-sha256 REVIEWED_REQUEST_SHA256 TRACE
```

The full evaluator requires a clean repository state so that candidate code, corpus, evaluator, and fixtures have stable provenance. Save its report outside the repository:

```sh
python3 scripts/evaluate_local_query_plan.py \
  --sideeffect ./target/release/sideeffect \
  --runtime "$PWD/llama.cpp/build/bin/llama-completion" \
  --model "$HOME/.cache/sideeffect/models/qwen3.5-2b-Q4_K_M.gguf" \
  --report "$HOME/sideeffect-local-query-plan-report.json"
```

The evaluator does not silently accept a candidate result, fallback to a deterministic answer, or upload its report. Check the report for exact pins, repository provenance, all per-case outcomes, error counts, latency, and the registered gate before changing the release status.

## Full candidate run — 2026-10-27

The Qwen3.5-0.8B candidate was run across all 100 cases of the earlier schema-v1 corpus from clean commit `42fa08d3c6e83fc787ef6e94acabb20662214069`, using evaluator SHA-256 `6f6242d496a7dbc2640904e0491c6da8bb40f006d7097fdb5b94e79263763064` and the then-pinned llama.cpp build and model file.

**Result: failed; do not release this model candidate.** All 100 model responses were rejected by SideEffect validation (0/100 schema-and-semantics-valid plans). Consequently, answerable exact plan/result accuracy was 0%, versus 78.57% for the fixed lexical baseline; all five permutation groups failed. The model's p95 latency was 8.045 seconds, maximum sampled process-tree RSS was 1,047,364 KiB, and no runtime timeout occurred. The invalid-output rate alone fails the 100% validity gate, and the quality metrics fail independently. The report's zero accepted executions on required abstentions is not evidence of safe abstention behavior because no model plan was accepted.

A bounded diagnostic reproduction for a supported question returned an abstention with `entity` still set to `syscall_result` and all filters null. The strict Rust cross-field validator correctly rejected this inconsistent plan. The raw diagnostic was run only against a synthetic fixture. Do not weaken validation to accept inconsistent plans. A future candidate may evaluate a schema with mutually exclusive filter/abstain branches or another model, but it must be developed against separate development examples and rerun against this unchanged corpus; do not tune on or relax the frozen gate using these test results.

The report was saved outside the repository during evaluation. No real capture, model weight, runtime binary, or generated report was added to Git. This v1 result does not evaluate the v2 schema or corpus. The pre-existing single-evidence model experiment is a separate failed candidate and does not count for this query-plan design.

## GPU development experiment — 2026-10-27

To check whether local GPU inference materially improves response time, a pinned llama.cpp CUDA build was compiled with CUDA Toolkit 13.0.88 and MSVC 19.44 for the NVIDIA GeForce RTX 3060 (8 GiB). This build ran separately from SideEffect and did not use the product's Linux sandbox or command path. A Qwen3.5-4B Q4_K_M GGUF file (2,783,446,368 bytes, SHA-256 `c3c2cf023efdbd913c2363a14d5c7266db5e05c4602f1c0790eaed567d8aff23`) was tested with ten newly authored synthetic development questions, not the frozen corpus.

**Result: development-only no-go.** The model returned schema-valid JSON in 10/10 cases and the correct decision category in 10/10, but the full expected plan was exact in only 7/10. It confused supported values in two filter plans and gave the wrong abstention reason once. Mean latency was 4.328 seconds and nearest-rank p95 was 4.976 seconds. Host working set peaked at a sampled 3,091.4 MiB; whole-device sampled peak use was 4,638 MiB and is not attributable to this process alone. This is a ten-case prompt-development result, not a corpus gate run, release validation, or evidence about real traces. GPU speed did not resolve the accuracy shortfall. The runtime command, exact prompt, model file, and results remain in a local temporary directory outside Git.

Other separated development smokes also failed to justify release: Qwen3.5-2B CPU produced 4/10 semantic matches on one set and 2/8 on another; Qwen3.5-4B CPU produced 3/10 on a separate set; Granite 3.3 2B CPU produced 0/8 before stopping; Qwen3-1.7B CPU produced 0/5 before stopping. These were fresh synthetic examples, not comparable benchmarks or frozen-corpus results. Keep the gate unchanged and do not claim that a GPU-capable candidate is approved. A candidate must pass the full v2 evaluator on the pinned corpus before this status changes.
