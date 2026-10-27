# Optional local model analysis

**Status:** M8 preview; not a release endorsement. This feature is opt-in and runs only on Linux x86_64. SideEffect does not bundle or automatically download weights or a runtime, and sends no evidence to a hosted service.

**Reviewed on:** 2026-10-26.

## Reviewed inputs

- Model: `ggml-org/Qwen3-0.6B-GGUF`, file `Qwen3-0.6B-Q4_0.gguf`.
- Model repository revision: `a41486f827d17edd055fe6b3b0ba3f8d427c0519`.
- Model SHA-256: `da2572f16c06133561ce56accaa822216f2391ef4d37fba427801cd6736417d4`.
- Runtime: llama.cpp version `6000`, source revision `4762ad7316dcdec20016ab5985fb46a27902204d`.
- The runtime source revision was verified as a signed upstream commit. The runtime binary is built locally; SideEffect checks its reported version/revision prefix and checks the full model hash before inference. It does not verify a binary hash or attest the compiler/build environment.
- The model file page and llama.cpp project declare Apache-2.0 and MIT respectively. Review upstream notices and current license terms before redistribution. SideEffect does not redistribute either artifact.

Primary references: [Qwen GGUF file](https://huggingface.co/ggml-org/Qwen3-0.6B-GGUF/blob/a41486f827d17edd055fe6b3b0ba3f8d427c0519/Qwen3-0.6B-Q4_0.gguf), [Qwen GGUF repository](https://huggingface.co/ggml-org/Qwen3-0.6B-GGUF/tree/a41486f827d17edd055fe6b3b0ba3f8d427c0519), [Qwen3-0.6B model card](https://huggingface.co/Qwen/Qwen3-0.6B), and [llama.cpp source](https://github.com/ggml-org/llama.cpp/tree/4762ad7316dcdec20016ab5985fb46a27902204d).

## Data flow and limits

1. `sideeffect model-preview --question QUESTION TRACE` strictly parses the local trace and prints the exact bounded typed event facts, question, separate system/user prompt messages, JSON output schema, model/runtime pins, and `request_sha256` for review. The schema exposes all evidence IDs in the bounded summary; question wording does not filter or reorder the model's choices. For selected `openat`/`openat2` rows, the request may include the parser's conservative lexical path hint when it is ASCII and at most 256 bytes. Each row reports `lexical_path_hint_status` as `included`, `not_derived`, or `omitted_limit`; an omitted path value is not silently treated as complete evidence. The path is untrusted, potentially sensitive, and not canonical or filesystem-resolved. For strictly recognized failure or in-progress results, the request may include the observed Linux errno name (for example, `ENOENT`); it does not include the raw result or message. Inspect the exact request and deterministic summary before confirming. The digest covers both messages, both revisions, and the schema. It omits raw arguments, raw results, raw lines, free-form parser diagnostics, capture metadata, and local input paths. Partial parsing remains visible and exits with status 2.
2. `sideeffect model-analyze --question QUESTION` requires the same trace, question, and exact preview digest copied by the user. A changed request is rejected before the runtime starts. The model receives the same bounded syscall result facts, eligible lexical path hints and observed errno names, and direct process relations shown in the preview; it does not receive raw traces, diffs, package/process/startup/permission inventories, or capture metadata. The model may choose at most one evidence ID from the full preview enum or abstain. This allows evaluation to measure actual model selection rather than deterministic answer preselection.
3. The program streams the selected model into a private mode-0600 temporary file while hashing it, then gives llama.cpp that verified copy. A private temporary JSON schema is also created for the run. The child environment is cleared, inference uses a private working directory and offline one-shot mode, and CPU, address-space, file-size, core-dump, file-descriptor, wall-clock, and output limits apply. A Linux seccomp filter denies socket syscalls and `io_uring_setup`; it rejects non-x86_64 and x32 syscall ABIs. The runtime is still an executable attack surface and this is defense in depth, not a sandbox. It can read or alter files accessible to the user; provide only a trusted locally built runtime and a verified model.
4. SideEffect independently parses the model output, rejects unknown fields and malformed/duplicate/unknown evidence IDs, and accepts at most one ID already present in the request. The output label is `model_selected_single_evidence_for_human_review_not_verified_findings`; the deterministic evidence summary remains present beside it. A valid ID establishes only that the cited record was included in the request, not that it answers the question. The model cannot emit factual prose in this schema. Invalid or malformed output is rejected.

The preview includes at most 48 result facts, 16 process relations, and 4 evidence references per relation. A lexical path hint is included only when it is ASCII and no longer than 256 bytes. The serialized request is capped at 32 KiB. Runtime generation is capped at 128 tokens, 16 KiB output, 120 seconds wall time and CPU time, 2 GiB address space, and two inference threads. Input follows the normal 32 MiB trace limit, and model files are capped at 512 MiB. Path hints, errno names, captures, and previews may reveal sensitive local details; review the exact preview locally before confirming. Nothing is uploaded.

The seccomp network-denial behavior was exercised under WSL2 with a Linux x86_64 runtime: attempts to create IPv4, IPv6, and Unix sockets returned `EPERM`, and a real llama.cpp inference run completed with the filter active. This validates that run and tested syscall set only; it does not prove every kernel interface or runtime build has no network path. `--offline` is an additional runtime option, not the security boundary.

## Reproducible local setup for Linux x86_64

The project does not run these downloads or build steps automatically. Obtain the files from the pinned upstream locations, check them, and keep them outside the repository. Example commands:

```sh
git clone https://github.com/ggml-org/llama.cpp.git
git -C llama.cpp checkout 4762ad7316dcdec20016ab5985fb46a27902204d
cmake -S llama.cpp -B llama.cpp/build \
  -DGGML_NATIVE=ON -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_SERVER=OFF -DLLAMA_CURL=OFF
cmake --build llama.cpp/build --target llama-cli --parallel 2

mkdir -p "$HOME/.cache/sideeffect/models"
curl -L --fail --output "$HOME/.cache/sideeffect/models/Qwen3-0.6B-Q4_0.gguf" \
  'https://huggingface.co/ggml-org/Qwen3-0.6B-GGUF/resolve/a41486f827d17edd055fe6b3b0ba3f8d427c0519/Qwen3-0.6B-Q4_0.gguf'
printf '%s  %s\n' \
  da2572f16c06133561ce56accaa822216f2391ef4d37fba427801cd6736417d4 \
  "$HOME/.cache/sideeffect/models/Qwen3-0.6B-Q4_0.gguf" | sha256sum --check
```

Then inspect the request and run only after reviewing it:

```sh
sideeffect model-preview --question "Which observed syscall failed?" TRACE
sideeffect model-analyze \
  --question "Which observed syscall failed?" \
  --runtime "$PWD/llama.cpp/build/bin/llama-cli" \
  --model "$HOME/.cache/sideeffect/models/Qwen3-0.6B-Q4_0.gguf" \
  --confirm-sha256 REVIEWED_REQUEST_SHA256 TRACE
```

To replay the preregistered synthetic evaluation corpus, use the interactive helper below. It displays each exact typed request and output schema, derives expected evidence references from semantic criteria against that exact preview, reports a question-aware deterministic selection from the same typed facts, and requires you to enter that request's full SHA-256 digest before invoking the local model. Invalid output and timeouts are not scored as abstentions. The report includes answer and false-selection-on-abstention metrics and latency distributions. It does not auto-confirm requests or download dependencies.

```sh
python3 scripts/evaluate_local_model.py \
  --sideeffect ./target/release/sideeffect \
  --runtime "$PWD/llama.cpp/build/bin/llama-cli" \
  --model "$HOME/.cache/sideeffect/models/Qwen3-0.6B-Q4_0.gguf"
```

The fixture files and preregistered expectations are under [`tests/fixtures/local_model_synthetic`](../tests/fixtures/local_model_synthetic/README.md). They are synthetic test data, not captures from a user's machine.

## Preregistered acceptance gate

Corpus version 3's attempted 29-case gate is invalidated: its candidate filter preselected most answers, forced abstentions, and its RSS measurement wrapped SideEffect rather than the inference child. No result from that gate is evidence of model quality. The replacement corpus freezes 51 cases (15 answerable natural-language variations, 12 unanswerable cases, the prior coverage cases, and source-order controls) against the full-evidence schema version 5. Its SHA-256 is 3ce5920da93503d0c1ccdee3fa65b5078433a2d91397a52acb7bd33806c7ca1f. The evaluation helper bounds corpus metadata at 64 KiB/128 cases and each child output stream at 1 MiB. It reports wall time; memory enforcement is provided by the runtime's address-space limit and is not represented as measured peak RSS. The preregistered gate requires valid output, at least a 10 percentage-point answerable-accuracy gain over a declared lexical baseline, zero false selections on unanswerable questions, all four source-order permutations in each required group to select the correct semantic target, and p95 model-run latency no greater than 30 seconds. The corpus pins the SHA-256 of every fixture, and the evaluator requires a clean Git worktree and records the commit and evaluator-script SHA-256 with every result. The evaluator also pins the corpus digest, criteria, case count, and required permutation groups. Passing synthetic criteria still does not establish real-world accuracy or justify a safety claim.

Do not pass server, repository, URL, tools, or hosted API options to another runtime. The supported command checks for the reviewed llama.cpp version and exact model hash. Native Windows analysis is not supported; WSL2 can be used by users who already have it, but does not constitute native Windows support.

## Validation and known limitations

- On 2026-10-26, the pinned model was run through SideEffect against the synthetic `tests/fixtures/strace/synthetic-minimal.trace` fixture. Under the original prose schema it repeated prompt instructions rather than facts. After moving instructions into the system message and keeping facts in a separate user message, it named the successful `execve`/`openat` calls and failed `connect` attempt, but also incorrectly described parsing as partial although `parse_status` was `complete`. This is direct evidence that evidence-ID citations and prose constraints do not prevent false claims. The current output schema therefore permits only evidence-ID selection, not model-authored claims.
- A 48-fact synthetic prioritization probe used 47 successful `execve` rows followed by one failed `connect` row (E048). The pinned 0.6B model, run through SideEffect, selected E001–E003 and omitted the failure. A second probe used the exact SideEffect system message, fact payload, and output schema with `Qwen3-1.7B-Q4_K_M.gguf`; this larger candidate also selected E001–E003 and omitted E048. A third probe with instruction-tuned `SmolLM2-1.7B-Instruct-Q4_K_M.gguf` returned the same IDs and missed E048. Both alternative models were direct offline `llama-cli` probes, not runs through SideEffect's model-hash gate or seccomp wrapper. All three results show positional selection rather than useful prioritization on this case.
- A controlled follow-up used the pinned 0.6B model with a JSON schema whose evidence-ID item used the pattern `^E[0-9]{3}$` instead of a sorted dynamic enum. With the failure at E048 and the original fact order, it still selected E001–E003. When the same failure was moved to the first prompt position, it selected E048, E001, and E002; when placed at E024, it again selected E001–E003 and omitted the failure. These direct offline `llama-cli` probes show that the observed failure is not explained by the sorted enum alone and that the model follows prompt position on these inputs. They are not runs through SideEffect's model-hash gate or seccomp wrapper.
- An additional end-to-end check used the current SideEffect `model-preview` and `model-analyze` commands, the pinned Qwen3-0.6B model, and the pinned llama.cpp runtime through SideEffect's hash check, digest confirmation, and Linux network-denial filter. Three generated synthetic traces each had 48 syscall results, with one failed `connect` at result positions 1, 24, or 48. The model selected `E001`–`E003` in all three cases: it included the failure only when the failure was at position 1 and missed it at positions 24 and 48. Each full invocation took about 23 seconds in this WSL environment, including model staging and process startup; peak memory was not measured. This confirms position sensitivity through the guarded application path, not useful general prioritization.
- After the model-only prompt was changed to put already-observed failure/in-progress results first while preserving their original evidence IDs, the same three cases were rerun through SideEffect's guarded `model-analyze` path. The selections were E001–E003, E024/E001/E002, and E048/E001/E002; the failed record was included in all three. Each run took about 23–24 seconds. This result shows the deterministic prompt ordering prevents the observed single-failure omission in these cases. Since a deterministic outcome-based baseline would also put that failure first, this does not yet demonstrate added ranking value from the model.
- The official [Qwen2.5-0.5B-Instruct-GGUF model card](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/tree/9217f5db79a29953eb74d5343926648285ec7e67) describes a 0.49B-parameter instruction-tuned model and declares Apache-2.0. Its Q4_0 file at revision `9217f5db79a29953eb74d5343926648285ec7e67` was 428,730,208 bytes with SHA-256 `7671c0c304e6ce5a7fc577bcb12aba01e2c155cc2efd29b2213c95b18edaf6ed`. Direct offline llama.cpp probes with the exact SideEffect prompt/schema returned E001–E003 for failure positions 1, 24, and 48, catching only the first-position failure. These comparison runs did not use SideEffect's model-hash gate or seccomp wrapper and this model is not configured by the application.
- The 1.7B comparison file was fetched from the official [ggml-org Qwen3-1.7B GGUF repository](https://huggingface.co/ggml-org/Qwen3-1.7B-GGUF/tree/daeb8e2d528a760970442092f6bf1e55c3b659eb). Its pinned revision was `daeb8e2d528a760970442092f6bf1e55c3b659eb`, file SHA-256 was `d2387ca2dbfee2ffabce7120d3770dadca0b293052bc2f0e138fdc940d9bc7b5`, and size was about 1.28 GB. It was used only for this local evaluation and is not the configured SideEffect model.
- The instruction-tuned comparison used the [HuggingFaceTB SmolLM2-1.7B-Instruct model](https://huggingface.co/HuggingFaceTB/SmolLM2-1.7B-Instruct) quantized as [SmolLM2-1.7B-Instruct-Q4_K_M.gguf](https://huggingface.co/bartowski/SmolLM2-1.7B-Instruct-GGUF/blob/1f03464768bfcc0319fc50da8ff5fb20b6417ba2/SmolLM2-1.7B-Instruct-Q4_K_M.gguf). The quantization repository revision was `1f03464768bfcc0319fc50da8ff5fb20b6417ba2`, file SHA-256 was `77665ea4815999596525c636fbeb56ba8b080b46ae85efef4f0d986a139834d7`, and size was about 1.06 GB. It was used only for this local evaluation and is not the configured SideEffect model.
- A guarded trial of the Qwen3-1.7B Q4_K_M candidate exceeded the application's 2 GiB address-space limit on all three test cases (about 1.97 GiB peak RSS before the runtime failed). It is not configured; the Qwen3-0.6B model remains the supported model.
- Network denial was tested for IPv4, IPv6, and Unix socket creation with the runtime subprocess filter active. This is not a proof of complete isolation.
- The earlier three-position probes used a broader candidate list and exposed order sensitivity. The current implementation narrows failure-question candidates and prioritizes a syscall named by the question. The expanded result below supersedes those exploratory accuracy figures but does not erase them.

### Historical eight-case corpus results (2026-10-26)

The results in this subsection were measured before the prompt was enriched with `observed_errno` and `lexical_path_hint`. They are historical results for the earlier evidence-only prompt and do not validate the current request format. The current preregistered corpus and its semantic targets are in `tests/fixtures/local_model_synthetic/corpus.json`; the expanded corpus has not yet been run through the model.

Before those inference runs, eight synthetic cases were recorded in `tests/fixtures/local_model_synthetic/corpus.json`. The corpus covered a single failure at first/middle/last positions, a success-only trace queried for a failure, a targeted syscall among two failures, duplicate failure evidence, a partial trace, and a question about successful activity. The pinned Qwen3-0.6B model ran through SideEffect's model hash check, exact request digest check, resource limits, and Linux network-denial filter for every case.

| Case | Expected | Model | Outcome-priority baseline |
|---|---|---|---|
| Failure first | E001 | E001 | E001 |
| Failure middle | E024 | E024 | E024 |
| Failure last | E048 | E048 | E048 |
| Success-only, asked for failure | Empty | Empty | Empty |
| Two failures, asked for `connect` | E002 | E002 | E001 |
| Duplicate failed connections | E001 or E002 | E001 | E001 |
| Partial trace with one observed failure | E001, status stays partial | E001, status stays partial | E001 |
| Asked which syscall succeeded | E002 | E002 | E001 |

The model matched the expected answer set in 8/8 cases; the simple outcome-priority baseline matched 6/8. A separate deterministic selector that uses the question's named syscall and requested outcome also matched 8/8, using the same bounded typed facts and no inference. The model therefore showed no added accuracy on this corpus and took a mean 2.64 seconds, with peak RSS of 975,908 KiB (about 953 MiB) on this WSL2 host; the deterministic baseline runs without that inference cost. These measurements are host-specific. This small synthetic corpus does not establish broad real-world performance, and no representative user-reviewed real capture has been evaluated. M8 has no release endorsement: the current model path is experimental and has not demonstrated value beyond deterministic selection. Do not describe it as reliable or as decision-making software.

### Historical four-case probe before candidate filtering (2026-10-26)

The first question-oriented change still returned every available evidence ID for a failure question. The output was restricted to one ID, the question was moved to the first field of the serialized prompt, and only event facts were retained in the model request. These changes were then checked through SideEffect's actual model hash, request digest, resource-limit, and seccomp path using the pinned 0.6B model and a synthetic fixture. This exploratory four-case permutation probe produced:

| Synthetic case | Expected | Selected | Result |
|---|---|---|---|
| Failure first | E001 | E001 | Correct |
| Failure middle | E002 | E001 | Incorrect |
| Failure last | E003 | E003 | Correct |
| Success-only, question asks for a failure | empty | Output rejected as schema-invalid | Incorrect; no valid abstention |

All four inference runs averaged about 14.4 seconds and peaked near 977 MiB RSS in this WSL2 environment. The model produced valid, expected selections in 2/4 cases and no valid abstention for a success-only trace, so it has not met the release gate. The timings and memory are environment-specific. A Qwen3-4B IQ2_M candidate also failed to produce schema-valid output through the guarded application path after about 80 seconds with roughly 1.9 GiB peak RSS; it is not configured. No model selection is currently reliable enough to endorse for release. Keep this feature experimental until a preregistered expanded corpus shows useful value over a deterministic baseline, including success-only abstention and order permutations.
