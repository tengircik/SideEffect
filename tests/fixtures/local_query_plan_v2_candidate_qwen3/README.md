# Qwen3-4B query-plan development screen

**Status: development-only; not a frozen holdout, release gate, real-capture benchmark, or evidence of model quality.** No model inference or prompt tuning was performed while authoring the corpus. After it was frozen, its `glintwater_a.trace` fixture was used to construct a product preview for the separate question `Find failed connect calls.` in two Qwen3-4B quantization triage runs. Both returned `unsupported_scope`. The trace-derived facts are excluded from the model prompt, that question is not a corpus case, no corpus case was scored, and no full-corpus inference was performed.

## Purpose and scope

`corpus.json` contains 40 synthetic cases: 24 answerable plans and 16 cases that must abstain. It covers single predicates, exact-equality conjunctions, paraphrased requests, process relations, valid filters with zero matches, unsupported requests, ambiguity, insufficient evidence, adversarial text, and one four-case order permutation. The expected answerable selectors are explicit in their questions; trace rows only establish whether those selectors match.

The eight `.trace` files are hand-authored synthetic strace-like fixtures, not computer captures. Their hostnames, paths, PIDs, ports, and documentation-range IP addresses are fictional. This audit does not inspect any model pretraining data and does not claim model-training-data independence.

## Output contract and diagnostic screen

The expected plan uses the unchanged strict query-plan v2 schema: exactly `decision`, `abstain_reason`, `entity`, `filters`, and `combine`; the filter object always has all eight registered fields; values use exact equality and non-null fields combine with AND. A must-abstain plan has a null entity and all-null filters. The canonical frozen 100-case gate is unchanged and is not applied to this 40-case development set.

For any further development experiment, record the candidate model revision and file digest, the product-generated preview/prompt digest, the runtime revision/binary digest, GPU backend/offload evidence, and evaluator version. Keep base-model comparisons paired on identical prompts and decoding. Treat direct Windows CUDA inference as development evidence only: SideEffect's query-plan product path and its resource/security wrapper are Linux x86_64, so a Windows run does not establish product-path or native Windows support. The tested Qwen3-4B IQ2_M file fits the current 1.5 GiB product catalog limit; Q4_K_M does not. Neither quantization passed even the single supported-query smoke.

The preregistered **diagnostic-only** screen requires: 40/40 outputs accepted by the unchanged Rust validator; at least 23/24 exact result sets and 22/24 exact plans on answerable cases; zero filters on all 16 must-abstain cases; all four order permutations exact; and at least one exact-result improvement over the fixed lexical baseline. Failure is a no-go for this candidate/configuration. Passing would only justify a separate full frozen-gate run through the supported product path; it would not approve release.

## Separation audit

At authoring time, the audit loaded all 10 other `tests/fixtures/**/corpus.json` files available in the repository (501 case questions) plus non-empty lines from the repository's only `*prompt*.txt` fixture (11 lines). Questions were case-folded and reduced to ASCII alphanumeric tokens. For each distinct new question, Jaccard token similarity selected the eight nearest old texts; Python `difflib.SequenceMatcher.ratio` then measured the maximum among those candidates. There were 0 normalized exact question collisions, 0 similarities above 0.82, and maximum measured similarity 0.718. The audit is a deterministic lexical check, not semantic independence proof.

The audit compared 40 new trace rows with 112 rows found through the trace maps declared by the prior corpora. There were 0 byte-identical row collisions. After removing `[pid N]`, replacing hexadecimal pointers and every numeric literal with placeholders, 17 new rows matched an old canonical row exactly. Those are shared generic syscall/argument-shape templates; values and paths differ. Thus the fixtures are not entirely novel at the syntax-pattern level, and no stronger novelty claim is made.

## Integrity

`corpus.json`: 32549 bytes; SHA-256 `c3d0835106ff414684e53af57d646070a674d5327eceb50b3840d9e15f487ab5`.

All trace digests cover exact ASCII bytes including the final LF.

| Synthetic fixture | Bytes | SHA-256 |
|---|---:|---|
| `glintwater_a.trace` | 561 | `5f2486a110d158c02ec59a3907bd86e34d4220df6bce09fa956961fc48602387` |
| `glintwater_b.trace` | 605 | `2b0a952440556387e8d82b99de24adf95375b141d916d7b8cb4be398a7ee7ff9` |
| `glintwater_c.trace` | 547 | `720242f71530caaf341b1504cdfac46336d1eb19568e5a9d513eb81600a3f477` |
| `glintwater_d.trace` | 631 | `3ceb013062e7350891e39c64c96ce61bae387d0bb99e07119725885a4cde9c13` |
| `order-1.trace` | 400 | `ebc77b9585dfb1b84659d4a2f41250666b6c443ee553372cf047cbf4f2c5893d` |
| `order-2.trace` | 400 | `63f2626a6d3d3c350a592da8715db8839273e5960862a1d7cf6efab47d2180ff` |
| `order-3.trace` | 400 | `1b31d9e8d2bb39e83463da16a1cafc6fe24f3f178c27253512b026626d0b25e3` |
| `order-4.trace` | 400 | `9335b7edfcdd5dad4146e1bc42750ddfc6f6c9761ca4bd59827ea8b30d577bab` |

## Preview-only corpus validation

From a Linux x86_64 checkout with the Rust toolchain and Python 3, select a registered query model, build SideEffect, and run the corpus-local validator. Supply that model's SHA-256 so every preview pin is checked against the same selected model:

```sh
cargo build --release --locked --bin sideeffect
python3 tests/fixtures/local_query_plan_v2_candidate_qwen3/validate_corpus.py \
  --sideeffect target/release/sideeffect \
  --expected-model-sha256 <selected-model-sha256>
```

The validator checks the strict expected-plan contract, explicit query selectors, trace hashes, permutation structure, product preview construction, and deterministic fixture matching. It does not invoke a model. On 2026-10-28 it passed all 40 cases with selected model SHA-256 `0aa56060b35246fb4f826e9242843b7f2faae20e771c193e0b7216c63f4dff9d`; this is preview/request and synthetic-fixture validation only, not a model-quality result.

`validate_corpus.py` SHA-256: `4071a37e72a8bb8ff3350091d45593f363f5a6dad147f2ca198e308171b2e3d4`.

## Validation boundaries

Before any inference, validate all trace hashes and expected plans against the unchanged Rust query-plan validator and fixture matcher. A preview-only pass checks request construction and fixture consistency; it is not model inference, runtime capture, or product security validation. This corpus is limited to synthetic text traces and cannot establish correctness on real captures, complete observation, causal relationships, effective permissions, or safety.
