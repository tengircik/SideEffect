# Local query-plan evaluation

**Status: experimental and not release-approved.** This is a separately gated M8 experiment. No model candidate has passed the frozen v2 usefulness gate. This is not a claim that local model analysis is useful or accurate on real captures. The model-query command is currently implemented only for Linux x86_64; GPU model experiments below were run separately on Windows and do not establish native Windows product support.

## Select a query model

On Linux x86_64, inspect the pinned query-plan candidates and their explicit no-go quality status with `sideeffect model list`, then use `sideeffect model show ID` for one entry. To install and select a listed candidate in one guided step, run `sideeffect model setup ID`, review its pinned source, revision, exact size, license terms, platform scope, and evaluation note, then type exactly `ACCEPT <license-id>`. Alternatively, `sideeffect model install ID` downloads without selecting. License acceptance is saved locally against that model ID, revision, license ID, and terms URL before the HTTPS request. It may remain saved if the transfer fails or is cancelled. Downloads are size-capped, SHA-256 checked, staged in the private per-user model store, and published without replacing an existing file. The manager does not install the runtime.

```sh
sideeffect model list
sideeffect model show query-qwen3-1.7b-q4-k-m
sideeffect model install query-qwen3-1.7b-q4-k-m
sideeffect model select query query-qwen3-1.7b-q4-k-m
sideeffect model-query-preview --question "Find failed connect calls." TRACE
sideeffect model-query --question "Find failed connect calls." \
  --runtime /path/to/llama-completion \
  --confirm-sha256 REVIEWED_PREVIEW_SHA256 TRACE
```

All catalog candidates have failed at least one quality check and are not recommendations. A custom GGUF may be registered with `sideeffect model add --name NAME --path FILE --for query [--license ID]`; the license string is user-provided and not verified. The file must fit the query task's 1,610,612,736-byte cap. Model registration and selection are user-initiated. The `model-query` inference path remains Linux x86_64 only; WSL2 is a Linux environment and does not establish native Windows support. A selected model's ID/hash, source and revision or user-provided marker, license/evaluation status, and pinned runtime/backend metadata appear in the preview/output and are bound to `request_sha256`; selecting a different model requires a new preview and digest confirmation.

## What it does

The model translates one reviewed English question into a strict JSON query plan. SideEffect validates the plan and applies exact equality filters joined by AND to a bounded set of typed syscall-result or process-relation facts. Every match carries its source evidence reference. The model cannot write commands, shell expressions, arbitrary predicates, prose, safety verdicts, root-cause claims, effective-permission claims, or completeness claims. A zero-row result means only that no matching record appears in the bounded input.

The preview separates four things:

- `prompt`: only the question and a fixed supported-query scope, sent to the model;
- `queryable_facts`: bounded typed evidence shown to the user and evaluator, never included in the model prompt;
- `coverage` / `evidence_summary`: deterministic parser and capture limitations;
- `request_sha256`: binds the trace bytes, question and scope, system prompt, schema, and pinned model/runtime metadata.

Inspect the exact preview locally before passing its digest to `model-query`. Trace paths and other evidence may be sensitive. Nothing is uploaded. Model weights are downloaded only by the explicit `model install` command after license confirmation; inference does not download models. The runtime is executable code that must be obtained and trusted separately. Linux limits, the private temporary workspace, offline runtime mode, and network-denial filter are defense in depth, not a sandbox.

## Current contract, candidate pin, and corpus

- Query-plan schema: version 2
- Historical in-code development pin: `gguf/Qwen3.5-2B-GGUF`, revision `47f5192dcee31b32db0ba0acc04cccef89cb4b2c`. Runtime selection now uses the per-task model registry; a preview reports the actual selected identity.
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

### Schema and prompt development experiment — 2026-10-28

After the full-gate failure, the generation schema was tightened so `syscall`, `observed_errno`, and `relation_type` use the same closed values as the Rust validator. The Rust validator remains authoritative and unchanged in behavior. This prevents a constrained decoder from emitting empty or unsupported selector strings that the application would reject.

A separate, synthetic development-only corpus of 32 cases (20 answerable, 12 required abstentions; corpus SHA-256 `7c8fdd8d478db815b2d7a878efba69a2bc15199deda38372af444f12790435e6`) was checked through the real Linux `model-query-preview` command for all 32 cases, including expected fixture matches. It uses two newly authored synthetic traces and is not the frozen holdout. A 2x2 prompt/schema experiment then used the pinned Qwen3.5-2B model and llama.cpp build on a Windows RTX 3060. A direct `nvidia-smi` memory sample during a separate bounded inference rose from 740 MiB to 2,607 MiB, confirming GPU allocation for that probe; this did not measure an isolated peak or establish product GPU support.

| Prompt and generation schema | Strictly valid plans | Exact answerable plans | Exact answerable result sets | Accepted filters on required abstentions |
| --- | ---: | ---: | ---: | ---: |
| Current prompt, closed selector enums | 32/32 | 0/20 | 3/20 | 0/12 |
| Two-example prompt, closed selector enums | 32/32 | 4/20 | 8/20 | 0/12 |
| Current prompt, open selector strings | 0/32 | 0/20 | 0/20 | 0/12 |
| Two-example prompt, open selector strings | 31/32 | 4/20 | 8/20 | 0/12 |

The open-string schema weakened decoder constraints and produced outputs rejected by the strict Rust validator; those invalid outputs are not counted as accepted false filters. The closed-enum schema is retained as an alignment and validity correction, but the prompt candidate is not adopted: its 20% exact-plan and 40% exact-result scores are far below the registered 85% thresholds, and it has not been run through the frozen gate. The zero accepted false-filter count is only a small synthetic development result, not a safety guarantee. This experiment is not a release-gate run and does not establish behavior on real captures. Preserve the frozen corpus, gate, and M8 no-go status.

### Flat-schema development experiment — 2026-10-28

To test whether the nested schema structure itself caused the remaining over-abstention, a new independent synthetic corpus was authored with 32 cases (20 answerable, 12 required abstentions; SHA-256 `5d93f787666ec33bb91e585d81d30fe87f0d16ac55b51a6eb74262a34f2b4982`). All 32 cases passed the real `model-query-preview` and fixture checks. The experiment transformed the generated schema in memory to a flat top-level selector format with closed enums; it did not change the product schema, query semantics, or Rust validation. Flattened model outputs were mapped back to the product plan shape and passed through the unchanged strict validator.

| Prompt and schema | Strictly valid plans | Exact answerable plans | Exact answerable result sets | Answerable abstentions | Accepted filters on required abstentions | p95 latency |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Current prompt, product schema | 32/32 | 0/20 | 1/20 | 20/20 | 0/12 | 3.909 s |
| Nested-format examples, product schema | 32/32 | 0/20 | 1/20 | 19/20 | 0/12 | 2.962 s |
| Current prompt, flat schema | 31/32 | 0/20 | 1/20 | 19/20 | 0/12 | 2.679 s |
| Flat-format examples, flat schema | 32/32 | 0/20 | 1/20 | 20/20 | 0/12 | 2.384 s |

A separate `nvidia-smi` probe during inference on the pinned Qwen3.5-2B runtime observed device memory rise from 740 MiB to 2,608 MiB. These were Windows RTX 3060 development runs outside the product command; the measurement is not an isolated process peak or a resource bound. Neither schema nor prompt variant improved exact plan quality on this independent set. One current-prompt flat-schema output had the wrong JSON shape and was rejected; it was not counted as a false filter. All variants emitted zero accepted filters on the required-abstention cases, but this small result does not establish safety. The test set has no source-order permutation controls and is not a release gate. The flat schema is not adopted, and local-model quality qualification remains unfinished.

### Two-example prompt transfer and frozen v2 measurement — 2026-10-28

The two-example prompt that showed the strongest exact-result signal in the earlier 32-case development experiment was frozen byte-for-byte as [`experimental-two-shot-system-prompt.txt`](../tests/fixtures/local_query_plan_v2_confirmation/experimental-two-shot-system-prompt.txt), SHA-256 `ef343d6996d9bd0fc0e881224374fa78ca574d1ab5826a65b86e1e9505025ef1`. Its line endings are preserved by `.gitattributes`. The transfer experiment did not change the model, product schema, Rust validator, question, or expected answers. It used the pinned Qwen3.5-2B model and a separately built Windows llama.cpp CUDA runtime on an NVIDIA GeForce RTX 3060 (runtime source revision `19cce6919992fdffd92e0ac152caaf1e2b8f254e`; runtime binary SHA-256 `21f282d2f0755cbabdf6e773eb8312494fb714165eaf649c7469b28bdcc8bcd0`).

On the independent 40-case confirmation set (24 answerable, 16 required abstentions), 39/40 outputs passed strict Rust plan validation. Exact answerable plans were 11/24 (45.83%) and exact answerable result sets were 19/24 (79.17%). Two answerable requests abstained, one required-abstention case produced a filter, and one answerable path value was rejected. Nearest-rank p95 latency was 2.947 seconds. This transfer signal justified one unchanged measurement on the frozen corpus, but it did not meet the plan-accuracy or zero-false-filter requirements.

The same prompt was then measured once on the unchanged frozen v2 corpus: 100 synthetic cases, SHA-256 `cdd73fe2a9847a7c78f40ba1f63496ee23b65cac303d7fc423013536333dbdea`. The temporary Windows runner used the exact pinned 1,312,164,352-byte model (SHA-256 `9a3d0aa6c920f096441139b6a254542da855223fdad06855ea00c6c087fd713d`), requested 99 CUDA layers, imposed a 4 GiB host-process limit, 60-second timeout, and 16 KiB output bound, then passed accepted plans through Rust `validate_query_plan` and `execute_query_plan`. The runtime used offline mode. Sampled GPU allocation reached about 2.7 GiB on the RTX 3060, but that is not an isolated peak or a VRAM bound. This temporary Windows route does not use SideEffect's Linux model command or its product network-denial filter, so it is experimental corpus evidence, not the canonical release-gate run or proof of native Windows model support.

**Result: failed; do not release.** Strict plans were accepted in 98/100 cases; two paths containing unsupported characters were rejected (`lookup_34`, `lookup_48`). Exact answerable plans were 6/70 (8.57%) and exact result sets were 13/70 (18.57%), versus the fixed baseline's 40/70 (57.14%): a decrease of 38.57 percentage points. Accuracy by answerable class was 5% answerable, 10% single-predicate, 10% conjunction, 20% paraphrase, 0% multi-match, 30% process-relation, and 60% no-match. Exact no-match plans were 3/10. The model emitted filters on 8/30 required abstentions: two ambiguous, one unsupported, four insufficient-evidence, and one adversarial case. Every source-order permutation group failed. The deterministic Rust matcher agreed with the independently computed result rows for all 98 accepted plans. p95 latency was 2.848 seconds.

The run passed latency and deterministic matcher consistency only. It failed strict validity, answerable plan and result accuracy, improvement over baseline, every answerable-class threshold, exact no-match plans, zero false filters, and all permutation groups. The per-case synthetic report is [experimental-two-shot-windows-cuda-report.json](../tests/fixtures/local_query_plan_v2/experimental-two-shot-windows-cuda-report.json), SHA-256 `01c3d72ff8c269e00ae60215132af8e997d576be48003fcdfbed39c512eb58cf`. The model and temporary runner are not retained. This candidate is not adopted; the corpus and thresholds remain unchanged, and local-model quality qualification remains unfinished.

### OLMo-2 Q8_0 independent confirmation — 2026-10-28

After the previous candidates failed, a fresh 40-case synthetic confirmation corpus was prepared and checked against existing fixtures before inference. It contains 24 answerable cases and 16 required abstentions, uses the registered answerable class labels, and has one four-case source-order permutation group. Its exact corpus SHA-256 is `6bb7624565e9aaca7952dea7e87c6fad8e6c58883e880d9b76526ba0d0402e48`; the corpus was committed before model inference at `8639b3be85b075b76274d91ee64cd5669b0a8f61`. The Windows product preview and fixture validator passed all 40 cases before the run.

The candidate was AI2's Apache-2.0 [OLMo-2-0425-1B-Instruct](https://huggingface.co/allenai/OLMo-2-0425-1B-Instruct) GGUF at immutable revision `62f8c199538474c3e33ed5d7e0580abd66686a27`, Q8_0 file size 1,581,667,488 bytes and SHA-256 `4a180742923d27d2434e53062b21f508257a5ee15abda398a3db13385e33d6e6`. The fixed two-example system prompt was not changed (2,683 bytes, SHA-256 `ef343d6996d9bd0fc0e881224374fa78ca574d1ab5826a65b86e1e9505025ef1`). The one-time run used llama.cpp revision `19cce6919992fdffd92e0ac152caaf1e2b8f254e`, runtime binary SHA-256 `21f282d2f0755cbabdf6e773eb8312494fb714165eaf649c7469b28bdcc8bcd0`, and requested CUDA0 with 99 GPU layers on the Windows RTX 3060. Every plan was passed through the unchanged Rust validator and executor. The temporary runner limited the host process to 4 GiB, each run to 60 seconds, and output to 16 KiB. Device-wide sampled GPU memory reached 3,056 MiB; this is not process-attributed or a VRAM cap. Windows Job Objects did not constrain CUDA memory or deny network access. All inputs were synthetic.

**Result: failed; do not release this candidate.** All 40 model outputs passed strict plan and execution validation, but only 7/24 answerable plans were exact (29.17%) and only 15/24 result sets were exact (62.5%). The fixed lexical baseline matched 22/24 result sets (91.67%), so the model was 29.17 percentage points worse. Exact result rates by answerable class were 87.5% conjunction, 100% multi-match, 100% no-match, 50% paraphrase, 75% process-relation, and 14.29% single-predicate. The model emitted filters in all 16 required-abstention cases (100% false-filter rate), including unsupported and adversarial questions. It matched all four permutation result sets but missed the exact expected plan across the group. Mean/p95 latency was 2.398/2.558 seconds. The candidate failed correctness, baseline improvement, and abstention safety despite valid JSON and low latency. Do not run the frozen 100-case corpus for this candidate.

The complete per-case report is [model_run_report.json](../tests/fixtures/local_query_plan_v2_confirmation_olmo2/model_run_report.json), SHA-256 `62b4ac63b23254e6c3dc35227c2ea275b53b042fe82a932632d841203deb6b6f`. The model weights and temporary runner source were deleted after the run. The model was not integrated; strict validation and the registered gate remain unchanged, and local-model quality qualification remains unfinished.

### Phi-3.5-mini Q2_K independent confirmation — 2026-10-28

A new, independently authored 40-case synthetic corpus was preview-validated and committed before inference. It contains 24 answerable cases, 16 required abstentions, the registered answerable class taxonomy, and a four-case source-order group. The corpus SHA-256 is `b89bff8708b142b1979a65f0682af0cf8751713d92aa17012045c23ec491bc35`; its pre-inference commit is `5a6d4163ab098b09911bf5a872d7741b9ee0458d`. Windows preview and fixture checks passed 40/40 before evaluation.

The candidate was Microsoft's MIT-licensed [Phi-3.5-mini-instruct](https://huggingface.co/microsoft/Phi-3.5-mini-instruct) in GGUF format at immutable revision `6d70da17e749a471ccb62ade694486011a75cda3`, Q2_K file size 1,416,204,576 bytes and SHA-256 `7425cb5fec0d2673151c95d1418f5e11bdf102edd0d8b22986d17210adb05bbd`. Q2_K is a severe quantization compromise; the less quantized Q3 variants exceed the configured model-file cap. The unchanged two-example prompt was 2,683 bytes, SHA-256 `ef343d6996d9bd0fc0e881224374fa78ca574d1ab5826a65b86e1e9505025ef1`. The temporary CUDA run used llama.cpp revision `19cce6919992fdffd92e0ac152caaf1e2b8f254e`, runtime binary SHA-256 `21f282d2f0755cbabdf6e773eb8312494fb714165eaf649c7469b28bdcc8bcd0`, CUDA0 with 99 requested GPU layers, and a Windows RTX 3060. Every generated plan was checked by the unchanged Rust validator and executor. The runner bounded the host process to 4 GiB, each invocation to 60 seconds, and output to 16 KiB. Sampled device-wide GPU memory reached 3,534 MiB; this is neither process-attributed nor a VRAM cap. Windows Job Objects did not limit CUDA memory or deny network access. Inputs were synthetic.

**Result: failed; do not release this candidate.** All 40 plans were structurally valid, but exact answerable plans were 4/24 (16.67%) and exact answerable result sets were 10/24 (41.67%). The fixed lexical baseline matched 21/24 result sets (87.5%), a 45.83 percentage-point advantage over the model. Exact result rates by answerable class were 62.5% conjunction, 100% multi-match, 50% no-match, 50% paraphrase, 25% process-relation, and 14.29% single-predicate. The model emitted filters on all 16 required abstentions (100% false-filter rate). It matched the result sets for the four source-order variants but did not produce the exact expected plan across that group. Mean/p95 latency was 3.057/3.284 seconds. It failed answerable usefulness, baseline improvement, exact no-match plans, and abstention safety; do not run the frozen 100-case corpus for this candidate.

The complete per-case report is [model_run_report.json](../tests/fixtures/local_query_plan_v2_confirmation_phi35/model_run_report.json), SHA-256 `16a9bfdb9fa68847c69afa9d21e8c545dc907f5a3805d569c9e018bb27066f35`. The weights and temporary evaluation source were deleted after the run. This candidate was not integrated; local-model quality qualification remains unfinished.

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
# Register an already obtained local GGUF and use the ID printed by model add.
sideeffect model add --name "Query model" --path /path/to/model.gguf --for query --license LICENSE-ID
sideeffect model select query custom-MODEL_ID
sideeffect model-query-preview --question "Which observed syscall failed?" TRACE
sideeffect model-query \
  --question "Which observed syscall failed?" \
  --runtime "$PWD/llama.cpp/build/bin/llama-completion" \
  --confirm-sha256 REVIEWED_REQUEST_SHA256 TRACE
```

`model add` records the current file hash and returns a stable `custom-...` ID; replace `custom-MODEL_ID` with that exact printed value. A license label supplied for a local model is not verified by SideEffect. Catalog installation uses `model install ID` and its separate explicit license prompt; the current catalog candidates are not quality recommendations.

The evaluator registers the pinned candidate and selects its deterministic custom ID in a private temporary `XDG_DATA_HOME`; it does not modify the user's model registry. Preview and analysis subprocesses use the current selected-model CLI, and the evaluator checks the candidate's pinned size and SHA-256. Existing candidate reports below are historical measurements; they do not validate the updated adapter or establish new model quality. Preview-only mode still creates an isolated model selection so previews bind to the same exact candidate identity.

After the adapter is aligned, run the full evaluator from a clean repository state and save its report outside the repository. The evaluator must receive the same selected local model and runtime used by the preview. It must not silently accept a candidate result, fall back to a deterministic answer, or upload its report. Check exact pins, repository provenance, all per-case outcomes, error counts, latency, and the registered gate before changing the release status.

## Full candidate run — 2026-10-27

The Qwen3.5-0.8B candidate was run across all 100 cases of the earlier schema-v1 corpus from clean commit `42fa08d3c6e83fc787ef6e94acabb20662214069`, using evaluator SHA-256 `6f6242d496a7dbc2640904e0491c6da8bb40f006d7097fdb5b94e79263763064` and the then-pinned llama.cpp build and model file.

**Result: failed; do not release this model candidate.** All 100 model responses were rejected by SideEffect validation (0/100 schema-and-semantics-valid plans). Consequently, answerable exact plan/result accuracy was 0%, versus 78.57% for the fixed lexical baseline; all five permutation groups failed. The model's p95 latency was 8.045 seconds, maximum sampled process-tree RSS was 1,047,364 KiB, and no runtime timeout occurred. The invalid-output rate alone fails the 100% validity gate, and the quality metrics fail independently. The report's zero accepted executions on required abstentions is not evidence of safe abstention behavior because no model plan was accepted.

A bounded diagnostic reproduction for a supported question returned an abstention with `entity` still set to `syscall_result` and all filters null. The strict Rust cross-field validator correctly rejected this inconsistent plan. The raw diagnostic was run only against a synthetic fixture. Do not weaken validation to accept inconsistent plans. A future candidate may evaluate a schema with mutually exclusive filter/abstain branches or another model, but it must be developed against separate development examples and rerun against this unchanged corpus; do not tune on or relax the frozen gate using these test results.

The report was saved outside the repository during evaluation. No real capture, model weight, runtime binary, or generated report was added to Git. This v1 result does not evaluate the v2 schema or corpus. The pre-existing single-evidence model experiment is a separate failed candidate and does not count for this query-plan design.

## GPU development experiment — 2026-10-27

To check whether local GPU inference materially improves response time, a pinned llama.cpp CUDA build was compiled with CUDA Toolkit 13.0.88 and MSVC 19.44 for the NVIDIA GeForce RTX 3060 (8 GiB). This build ran separately from SideEffect and did not use the product's Linux sandbox or command path. A Qwen3.5-4B Q4_K_M GGUF file (2,783,446,368 bytes, SHA-256 `c3c2cf023efdbd913c2363a14d5c7266db5e05c4602f1c0790eaed567d8aff23`) was tested with ten newly authored synthetic development questions, not the frozen corpus.

**Result: development-only no-go.** The model returned schema-valid JSON in 10/10 cases and the correct decision category in 10/10, but the full expected plan was exact in only 7/10. It confused supported values in two filter plans and gave the wrong abstention reason once. Mean latency was 4.328 seconds and nearest-rank p95 was 4.976 seconds. Host working set peaked at a sampled 3,091.4 MiB; whole-device sampled peak use was 4,638 MiB and is not attributable to this process alone. This is a ten-case prompt-development result, not a corpus gate run, release validation, or evidence about real traces. GPU speed did not resolve the accuracy shortfall. The runtime command, exact prompt, model file, and results remain in a local temporary directory outside Git.

Other separated development smokes also failed to justify release: Qwen3.5-2B CPU produced 4/10 semantic matches on one set and 2/8 on another; Qwen3.5-4B CPU produced 3/10 on a separate set; Granite 3.3 2B CPU produced 0/8 before stopping; Qwen3-1.7B CPU produced 0/5 before stopping. These were fresh synthetic examples, not comparable benchmarks or frozen-corpus results. Keep the gate unchanged and do not claim that a GPU-capable candidate is approved. A candidate must pass the full v2 evaluator on the pinned corpus before this status changes.

## SmolLM3-3B Q3_K_M triage smoke — 2026-10-28

The Apache-2.0 `HuggingFaceTB/SmolLM3-3B` candidate was checked because the pinned llama.cpp revision explicitly supports its architecture and chat template, and its quantized GGUF fits below the configured 1.5 GiB file cap. The tested file was `bartowski/HuggingFaceTB_SmolLM3-3B-GGUF` at revision `86b3536ed1ca0dcb4716745642db4e6804bf3d32`, `HuggingFaceTB_SmolLM3-3B-Q3_K_M.gguf`, 1,571,069,760 bytes, SHA-256 `5e5c70fdc3429023ed88ead8af2a70684047e2628258b650bdb729c8437639d0`. It was run once on a Windows RTX 3060 with llama.cpp `19cce6919992fdffd92e0ac152caaf1e2b8f254e` (`llama-completion` SHA-256 `21f282d2f0755cbabdf6e773eb8312494fb714165eaf649c7469b28bdcc8bcd0`), using the product's unchanged system prompt, schema, and synthetic preview for `Find failed connect calls.`

**Result: triage no-go.** The runtime exited successfully and generated an abstain-shaped response, but chose `unsupported_scope` for this plainly supported query instead of filtering for `syscall=connect` and `outcome=failure`. The model was therefore not run on a larger corpus. This was one direct Windows CUDA smoke outside the product command, Linux guard, and frozen evaluator; it does not establish model safety or Windows product support. The downloaded weights and smoke inputs/output were removed after the result was recorded. Local-model quality qualification remains unfinished and no candidate is release-approved.

## Qwen3-1.7B Q4_K_M triage smoke — 2026-10-28

The Apache-2.0 `Qwen/Qwen3-1.7B` candidate was evaluated as a fresh triage candidate because its quantized GGUF fits below the configured 1.5 GiB model-file cap. The tested file was `bartowski/Qwen_Qwen3-1.7B-GGUF` at immutable revision `dcb19155b962dbb6389f4691a982043a8e651022`, `Qwen_Qwen3-1.7B-Q4_K_M.gguf`, 1,282,439,584 bytes, SHA-256 `72c5c3cb38fa32d5256e2fe30d03e7a64c6c79e668ad84057e3bd66e250b24fb`. It was run once on a Windows host with an NVIDIA GeForce RTX 3060 and the pinned CUDA-capable llama.cpp `19cce6919992fdffd92e0ac152caaf1e2b8f254e` (`llama-completion` SHA-256 `21f282d2f0755cbabdf6e773eb8312494fb714165eaf649c7469b28bdcc8bcd0`). The model received the unchanged product prompt and schema for the synthetic product preview `Find failed connect calls.` (preview SHA-256 `41a092807f8fa51e5d3c9c52050f2942bdf41cbf2d2cc40d34218e1baca7f9b2`). Runtime arguments matched the product's offline, single-turn, 2,048-token context, 256-token output, zero-temperature configuration. The probe was outside the product command and canonical Linux evaluator; actual CUDA layer offload was not measured for this run.

**Result: triage no-go.** The runtime exited successfully and emitted schema-shaped JSON, but returned `decision=abstain` with `abstain_reason=unsupported_scope` for the supported query. The expected plan was `decision=filter`, entity `syscall_result`, with exact `syscall=connect` and `outcome=failure` filters. This one-case smoke does not measure overall quality or safety, but it fails the candidate's minimum supported-query check, so no larger run is justified. The model weights and temporary smoke directory were deleted after recording the result. No prompt, schema, corpus, validator, or release threshold was changed; local-model quality qualification remains unfinished and no candidate is release-approved.

## Qwen3-1.7B LoRA development check — 2026-10-28

This is a development-only experiment on the existing 40-case corpus at [`tests/fixtures/local_query_plan_v2_development`](../tests/fixtures/local_query_plan_v2_development/README.md), separate from the frozen 100-case gate. The corpus contains 24 answerable questions and 16 required abstentions; all trace data is synthetic. A normalized exact-question comparison found no duplicate questions between its 40 questions and the model's 4,000 training questions. That check does not establish semantic independence or make this development set a holdout.

The candidate was Qwen/Qwen3-1.7B-Base at revision `ea980cb0a6c2ae4b936e82123acc929f1cec04c1` (base `model.safetensors` SHA-256 `6df85b39330e5a425ee36253d0f894e4387e4f0a15b9c53cb467d668e6b3a841`). Training data SHA-256 was `233171b84f6b60dccc6495854c393af875c94aa816f2d1e34cb0eade415c508b`; the existing 800-case development data SHA-256 was `875cf7f6b12143e35e09e86b772a7d2c0dcda481904ba3f3e784fca984aa53ba`. The early-stopped training sweep had already failed its strict-output prerequisite on the first 200 cases (160/200 validator-valid, 126/200 exact plans), so this LoRA was not a recommended candidate before the present check.

For this one-time experiment, the adapter was converted to GGUF and run with the quantized Q4_K_M base. Base GGUF: 1,107,408,576 bytes, SHA-256 `ff4fedad60b8a98f0829bc96c1a8f702f872b38747d40ddf95908eaa9e3f82bc`. LoRA adapter GGUF: 17,459,840 bytes, SHA-256 `7d3633fa7fdc8dd155553cf7aaab1b0c15d3c1d581ec6710988d8ebb67e4e1c3`. The run used the exact preview system prompt, question prompt, and output schema produced by the packaged SideEffect preview command, then invoked the pinned llama.cpp Windows CUDA build at revision `19cce6919992fdffd92e0ac152caaf1e2b8f254e` (binary SHA-256 `21f282d2f0755cbabdf6e773eb8312494fb714165eaf649c7469b28bdcc8bcd0`) with `--lora`, requested 99 GPU layers, two threads, a 2,048-token context, 256-token output, zero temperature, and offline single-turn mode. This direct runtime experiment bypassed SideEffect's inference command, Linux resource/security wrapper, and Rust plan validator. The independent evaluator imported the repository's Python `validate_plan`, fact matching, and baseline helpers. No per-process GPU-memory peak or retained GPU-offload log is available.

**Result: no-go.** All 40 outputs parsed and passed the Python plan-contract validator, but only 13/24 answerable plans were exact (54.2%), equal to the lexical baseline's 13/24. Exact semantic result rows were 15/24 (62.5%), below the baseline's 18/24 (75%). The model correctly abstained in only 8/16 required-abstention cases and emitted a filter in the other 8; the frozen gate requires zero such filters. The lexical baseline correctly abstained in 3/16 on this development set, but this does not excuse the model's gate failure. Mean/p95/max inference latency was 2.223/2.259/3.567 seconds in this Windows environment. These are development measurements, not canonical evaluator, Rust-validator, or real-capture results. A per-case metrics report was retained outside the repository (SHA-256 `465b523dc94717335c204555e5cf4d8c933467d442b1aa96c6f61922264ab508`); it contains no generated prompts or raw model responses. No frozen-gate run was made, and the candidate was not integrated or added to the catalog. Keep the candidate as a no-go and continue model-quality work without changing the registered gate.
