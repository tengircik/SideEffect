# Local evidence explanation development

**Status:** experimental development path; not a release endorsement. The original local evidence-selection and query-plan experiments have separate frozen quality gates. This explanation path has a separate, development-only corpus and has not passed a semantic quality gate. Do not use generated statements for safety, security, permission, or operational decisions.

## Data flow

`sideeffect model-explain-preview --question QUESTION --backend auto|cpu|cuda TRACE` parses the bounded local trace and previews the exact question, typed evidence facts, coverage metadata, prompt, output schema, pinned model identity, and request SHA-256. It may include a conservative, plain-ASCII lexical executable path hint derived from the `execve`/`execveat` path argument and lexical file path hints for selected `openat`/`openat2` rows. It does not include argv or environment strings, resolve paths, or establish which file was ultimately executed. These hints and evidence labels may still disclose sensitive information; inspect the preview before running inference.

`sideeffect model-explain` requires the selected runtime and model paths plus the exact preview digest. It stages a hash-verified copy of the pinned model and private, bounded prompt files in a per-user temporary directory, invokes the local runtime once without a shell, and removes the staging directory on completion. The runtime receives no command-execution interface. Output is bounded JSON; every statement must cite evidence IDs from the exact preview. Unknown IDs, extra fields, invalid status combinations, controls, oversized text, and malformed JSON are rejected. Citation validity proves only that a cited row was supplied, not that the generated sentence is true or supported by it.

The model is Qwen3.5-4B Q4_K_M, repository `gguf/Qwen3.5-4B-GGUF`, revision `76e05555d64c8d045dd4b9c9f1ebaef1e35d99f7`, file size 2,783,446,368 bytes, SHA-256 `c3c2cf023efdbd913c2363a14d5c7266db5e05c4602f1c0790eaed567d8aff23`. The selected llama.cpp runtime must report revision `19cce6919992fdffd92e0ac152caaf1e2b8f254e`; the reported version string does not authenticate the executable binary. Treat the runtime and its loaded libraries as trusted code running with the current user's permissions. SideEffect does not download either artifact or send evidence to a hosted service.

## Windows GPU path

Native Windows inference supports explicit `cpu`, explicit `cuda`, and `auto`. `auto` prefers CUDA when the selected runtime reports `CUDA0`; otherwise it reports CPU. A CUDA initialization or inference failure is returned as an error, partial output is discarded, and there is no silent CPU fallback. CUDA is reported as used only if the runtime diagnostics contain positive layer-offload evidence.

The runtime is llama.cpp's `llama-completion` built from the pinned source revision with CUDA enabled. For example, from a llama.cpp checkout at that revision, configure with `cmake -B build -DGGML_CUDA=ON` and build the `llama-completion` target. Download the model yourself from the pinned model repository and verify its SHA-256 before use. SideEffect verifies the model hash again before inference.

The Windows runner starts the child suspended, assigns it to a kill-on-close Job Object before resuming it, limits the process tree to one process, caps host process memory at 6 GiB, bounds runtime and captured output, and stages the verified model privately. It clears the inherited environment and supplies only required Windows and validated runtime dependencies. These controls do **not** limit CUDA VRAM or deny network access. `--offline` is a runtime option, not an isolation boundary. The result includes this limitation. GPU availability is not a promise of a hard VRAM ceiling; allocation failures are surfaced and CUDA usage is not measured as process-isolated peak VRAM.

Example, after obtaining and verifying the pinned artifacts:

```powershell
$preview = sideeffect model-explain-preview --question "What happened to the observed connection?" --backend cuda TRACE.strace | ConvertFrom-Json
sideeffect model-explain --question "What happened to the observed connection?" --backend cuda --runtime LLAMA_COMPLETION.exe --model Qwen3.5-4B-Q4_K_M.gguf --confirm-sha256 $preview.request_sha256 TRACE.strace
```

Review the preview's complete JSON and sensitive fields before confirming. Replace the placeholder paths with local paths. There is no automatic model or runtime download.

## Development corpus and release gate

`tests/fixtures/local_model_explain_v1/corpus.json` pins 26 synthetic cases, 14 synthetic traces, one four-case source-order permutation group, and its expected semantic/evidence labels. Its SHA-256 is `b67fe04f43674a61fb4e1c472f19824bf0f1110a120dd0f304d57c581cbad8af`. The evaluator command `py -3 scripts/evaluate_local_model_explain.py --check-corpus` verifies only corpus structure and fixture hashes. `--results` additionally checks result shape, status labels, evidence-ID membership, declared semantic labels, and optional human-entered review fields. It never launches a model and cannot verify claim truth. The corpus is development-only, must not be used as the final release gate, and must not replace or modify the frozen local query-plan v2 holdout.

The first direct CUDA quality sweep of the explanation path returned an answer for only 4 of 26 synthetic cases; the remaining cases abstained, including several with explicit requested facts. A follow-up four-case prompt experiment with concrete examples also abstained on all four cases. CUDA layer offload and output-schema validity do not establish useful semantic quality. These results are a no-go for treating the current explanation model/prompt as a user-ready capability. Do not describe M8 as complete based on GPU execution or schema-valid output.

Before release consideration, create an independently reviewed, frozen corpus with preregistered scoring, meaningful unanswerable cases, order controls, injection cases, independent reviewers for semantic support and unsafe claims, repeatable latency/resource measurement, and explicit platform/runtime coverage. Keep candidate prompt development separate from the frozen holdout. Require zero invalid citations, zero unsupported safety/root-cause/effective-access/completeness conclusions, strong answerable evidence-label recall, correct abstention on unanswerable cases, and improvement over a deterministic baseline. Passing synthetic criteria would still not prove real-world accuracy. Until that gate and platform security review pass, the feature remains experimental and M8 is not complete.
