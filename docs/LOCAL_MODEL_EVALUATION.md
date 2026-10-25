# Local model evaluation record

**Status:** research only. SideEffect does not bundle model weights, download weights, invoke a model runtime, or send evidence to a hosted service.

**Reviewed on:** 2026-10-25.

## Candidate

The first candidate is the `ggml-org/Qwen3-0.6B-GGUF` conversion, file `Qwen3-0.6B-Q4_0.gguf`. The model file page reports Apache-2.0, a 429 MB file, short revision `a41486f`, and SHA-256 `da2572f16c06133561ce56accaa822216f2391ef4d37fba427801cd6736417d4`. The page's short revision is not a full immutable commit identifier. The exact full revision, conversion provenance, and license applicability must be verified before any release decision. The original [Qwen3-0.6B model card](https://huggingface.co/Qwen/Qwen3-0.6B) and [GGUF conversion repository](https://huggingface.co/ggml-org/Qwen3-0.6B-GGUF) are reference sources; a hash does not authenticate the publisher.

## Runtime candidate

The candidate runtime is [llama.cpp](https://github.com/ggml-org/llama.cpp), whose upstream repository identifies an MIT license. Its [CLI documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/cli/README.md) documents loading a local model with `--model`, an `--offline` option described as preventing network access, one-shot generation, a token limit, and JSON-schema-constrained output. These are upstream claims, not validation of an installed or pinned runtime binary. The runtime version/source/binary provenance is not yet selected or pinned, and network behavior has not been independently tested.

The proposed interface, if approved for implementation, is a user-selected local model file and an explicit preview/confirmation of a bounded evidence request. SideEffect must never use model-repository, model-URL, server, tool, or hosted API options. It must clear runtime environment overrides, set the runtime's offline option, independently validate output against a strict schema and the evidence-ID allowlist, cap prompt/output/context/time/resources, and keep generated prose labeled as interpretation beside deterministic facts. A local runtime and model are executable attack surface; users must obtain them from a trusted source and verify pinned hashes. A prompt-injection string remains untrusted input even when no tools are available.

## Validation not yet performed

- No model weights were downloaded or run.
- No quality, false-claim, latency, peak-memory, or failure-resource measurements exist.
- No runtime binary version or immutable source revision has been selected.
- The runtime's offline behavior and any operating-system network restriction have not been validated.
- No model-derived analysis is a released or supported SideEffect capability.

Do not describe local model analysis as shipped, offline, safe, or validated until the open checks are completed and reviewed.
