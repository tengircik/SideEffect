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

1. `sideeffect model-preview --question QUESTION TRACE` strictly parses the local trace and prints the exact bounded typed event facts, question, separate system/user prompt messages, JSON output schema, model/runtime pins, and `request_sha256` for review. The digest covers both messages, both revisions, and the schema. It omits raw arguments, raw results, raw lines, free-form parser diagnostics, capture metadata, and local input paths. Partial parsing remains visible and exits with status 2.
2. `sideeffect model-analyze --question QUESTION` requires the same trace, question, and exact preview digest copied by the user. A changed request is rejected before the runtime starts. The model receives only syscall result facts and direct process relations; it does not receive traces, diffs, package/process/startup/permission inventories, or capture metadata.
3. The program streams the selected model into a private mode-0600 temporary file while hashing it, then gives llama.cpp that verified copy. A private temporary JSON schema is also created for the run. The child environment is cleared, inference uses a private working directory and offline one-shot mode, and CPU, address-space, file-size, core-dump, file-descriptor, wall-clock, and output limits apply. A Linux seccomp filter denies socket syscalls and `io_uring_setup`; it rejects non-x86_64 and x32 syscall ABIs. The runtime is still an executable attack surface and this is defense in depth, not a sandbox. It can read or alter files accessible to the user; provide only a trusted locally built runtime and a verified model.
4. SideEffect independently parses the model output, rejects unknown fields and malformed/duplicate/unknown evidence IDs, and accepts at most one ID already present in the request. The output label is `model_selected_single_evidence_for_human_review_not_verified_findings`; the deterministic evidence summary remains present beside it. A valid ID establishes only that the cited record was included in the request, not that it answers the question. The model cannot emit factual prose in this schema. Invalid or malformed output is rejected.

The preview includes at most 48 result facts, 16 process relations, and 4 evidence references per relation, with a 32 KiB serialized request limit. Runtime generation is capped at 128 tokens, 16 KiB output, 120 seconds wall time and CPU time, 2 GiB address space, and two inference threads. Input follows the normal 32 MiB trace limit, and model files are capped at 512 MiB. Captures and previews may contain sensitive facts; review the preview locally before confirming. Nothing is uploaded.

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
- The structured evidence-selection output has not yet passed a multi-case corpus. There is no representative real-capture usefulness, prioritization-accuracy rate, latency, or peak-memory study.
- Network denial was tested for IPv4, IPv6, and Unix socket creation with the runtime subprocess filter active. This is not a proof of complete isolation.
- With chronological prompt order, the Qwen3-0.6B model and two 1.7B comparisons selected the first three IDs and omitted a later failure; Qwen2.5-0.5B showed the same behavior. Outcome-based ordering now puts known failure/in-progress records first in the model-only prompt, and the pinned application model selected a single failure at each tested position. Treat selections as unverified review aids and inspect the deterministic summary directly. The current evidence still does not establish that the model adds useful ranking beyond deterministic ordering.
- M8 release readiness remains unmet: structured selection must show useful ranking across diverse synthetic cases and reviewed examples, followed by code review, CI, and product-security review of the current boundary. A completed standard security scan of immutable revision `5365c84` reported three low-severity findings in package-diagnostic allocation, local-runtime timeout handling, and unsupported startup record completeness. They were fixed in later commits `60f934c`, `229ed10`, and `bea728e`, respectively. The scan is partial because tests, fixtures, and some documentation were inventoried but not reviewed line by line. CI passed through commit `bb516a6`; no model weights are included in SideEffect releases.
- The next usefulness evaluation should use a preregistered synthetic corpus and compare model selections with a deterministic outcome-based baseline. Vary actionable failures across first, middle, and last positions; include success-only, partial, duplicate-row, and varied-length inputs. Record failure recall, top-three precision, omission rate, permutation sensitivity, latency, and peak memory. This experiment is planned; no results are claimed yet.

### Question-focused single-record probe (2026-10-26)

The first question-oriented change still returned every available evidence ID for a failure question. The output was restricted to one ID, the question was moved to the first field of the serialized prompt, and only event facts were retained in the model request. These changes were then checked through SideEffect's actual model hash, request digest, resource-limit, and seccomp path using the pinned 0.6B model and a synthetic fixture. This exploratory four-case permutation probe produced:

| Synthetic case | Expected | Selected | Result |
|---|---|---|---|
| Failure first | E001 | E001 | Correct |
| Failure middle | E002 | E001 | Incorrect |
| Failure last | E003 | E003 | Correct |
| Success-only, question asks for a failure | empty | E001 | Incorrect; should abstain |

The three inference runs averaged about 14.5 seconds and peaked near 980 MiB RSS in this WSL2 environment. The model got 2/4 cases correct and did not abstain on a success-only trace, so it has not met the release gate. The timings and memory are environment-specific. A Qwen3-4B IQ2_M candidate also failed to produce schema-valid output through the guarded application path after about 80 seconds with roughly 1.9 GiB peak RSS; it is not configured. No model selection is currently reliable enough to endorse for release. Keep this feature experimental until a preregistered expanded corpus shows useful value over a deterministic baseline, including success-only abstention and order permutations.
