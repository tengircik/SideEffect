# Optional local model analysis

**Status:** M8 implementation candidate; not a release endorsement. This feature is opt-in and runs only on Linux x86_64. SideEffect does not bundle or automatically download weights or a runtime, and sends no evidence to a hosted service.

**Reviewed on:** 2026-10-25.

## Reviewed inputs

- Model: `ggml-org/Qwen3-0.6B-GGUF`, file `Qwen3-0.6B-Q4_0.gguf`.
- Model repository revision: `a41486f827d17edd055fe6b3b0ba3f8d427c0519`.
- Model SHA-256: `da2572f16c06133561ce56accaa822216f2391ef4d37fba427801cd6736417d4`.
- Runtime: llama.cpp version `6000`, source revision `4762ad7316dcdec20016ab5985fb46a27902204d`.
- The runtime source revision was verified as a signed upstream commit. The runtime binary is built locally; SideEffect checks its reported version/revision prefix and checks the full model hash before inference. It does not verify a binary hash or attest the compiler/build environment.
- The model file page and llama.cpp project declare Apache-2.0 and MIT respectively. Review upstream notices and current license terms before redistribution. SideEffect does not redistribute either artifact.

Primary references: [Qwen GGUF file](https://huggingface.co/ggml-org/Qwen3-0.6B-GGUF/blob/a41486f827d17edd055fe6b3b0ba3f8d427c0519/Qwen3-0.6B-Q4_0.gguf), [Qwen GGUF repository](https://huggingface.co/ggml-org/Qwen3-0.6B-GGUF/tree/a41486f827d17edd055fe6b3b0ba3f8d427c0519), [Qwen3-0.6B model card](https://huggingface.co/Qwen/Qwen3-0.6B), and [llama.cpp source](https://github.com/ggml-org/llama.cpp/tree/4762ad7316dcdec20016ab5985fb46a27902204d).

## Data flow and limits

1. `sideeffect model-preview TRACE` strictly parses the local trace and prints the exact bounded typed facts, generated prompt, JSON output schema, model/runtime pins, and `request_sha256` for review. It omits raw arguments, raw results, raw lines, free-form parser diagnostics, and local input paths. Partial parsing remains visible and exits with status 2.
2. `sideeffect model-analyze` requires the same trace and an exact preview digest copied by the user. A changed request is rejected before the runtime starts. The initial adapter analyzes trace summaries only; it does not analyze full traces, diffs, or inventory snapshots.
3. The program streams the selected model into a private mode-0600 temporary file while hashing it, then gives llama.cpp that verified copy. A private temporary JSON schema is also created for the run. The child environment is cleared, inference uses a private working directory and offline one-shot mode, and CPU, address-space, file-size, core-dump, file-descriptor, wall-clock, and output limits apply. A Linux seccomp filter denies socket syscalls and `io_uring_setup`; it rejects non-x86_64 and x32 syscall ABIs. The runtime is still an executable attack surface and this is defense in depth, not a sandbox. It can read or alter files accessible to the user; provide only a trusted locally built runtime and a verified model.
4. SideEffect independently parses the model output, rejects unknown fields and malformed/duplicate/unknown evidence IDs, and accepts one bounded summary with up to eight citations. Output is labeled `model_generated_interpretation_not_verified_facts`; deterministic evidence remains present beside it. A valid citation establishes only that the ID was included in the request, not that the model's wording is correct. Invalid or malformed model output is rejected and not displayed as an accepted interpretation.

The initial preview includes at most 48 result facts, 16 process relations, and 4 evidence references per relation, with a 32 KiB serialized request limit. Runtime generation is capped at 256 tokens, 16 KiB output, 120 seconds wall time and CPU time, 2 GiB address space, and two inference threads. Input still follows the normal 32 MiB trace limit, and model files are capped at 512 MiB. Captures and previews may contain sensitive facts; review the preview locally before confirming. Nothing is uploaded.

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
sideeffect model-preview TRACE
sideeffect model-analyze \
  --runtime "$PWD/llama.cpp/build/bin/llama-cli" \
  --model "$HOME/.cache/sideeffect/models/Qwen3-0.6B-Q4_0.gguf" \
  --confirm-sha256 REVIEWED_REQUEST_SHA256 TRACE
```

Do not pass server, repository, URL, tools, or hosted API options to another runtime. The supported command checks for the reviewed llama.cpp version and exact model hash. Native Windows analysis is not supported; WSL2 can be used by users who already have it, but does not constitute native Windows support.

## Validation and known limitations

- A manual inference on the synthetic `tests/fixtures/strace/synthetic-minimal.trace` fixture produced schema-constrained JSON citing all three supplied result evidence IDs and correctly labeled the observed `execve`/`openat` returns as successful and `connect` as failed. The summary was shallow and only restated the supplied syscall/outcome labels. This is a smoke check, not a quality, accuracy, or false-claim evaluation.
- Network denial was tested for IPv4, IPv6, and Unix socket creation with the runtime subprocess filter active. This is not a proof of complete isolation.
- No representative real capture quality study, false-claim rate, broad latency benchmark, or peak-memory measurement exists.
- The 0.6B quantized model may produce shallow, repetitive, or incorrect text. Do not use its prose as a finding or decision. Read the evidence and deterministic summary directly.
- M8 release readiness still requires code review, CI, and product-security review of these boundaries. No model weights are included in SideEffect releases.
