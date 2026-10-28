# Phi-3.5-mini-instruct Q2_K query-plan confirmation corpus

**Status: development-only; not a frozen holdout, release gate, model result, or real-capture benchmark. No model inference or prompt tuning was performed while creating or validating this corpus.** The candidate intent is Microsoft Phi-3.5-mini-instruct Q2_K only; this folder records no candidate result.

## Cases and separation

`corpus.json` contains 40 cases: 24 answerable plans and 16 required abstentions. The answerable class counts use the registered evaluator taxonomy: `conjunction` 8, `single_predicate` 7, `process_relation` 4, `paraphrase` 2, `no_match` 2, and `multi_match` 1. Abstention labels are `unsupported` 11, `ambiguous` 2, `insufficient` 2, and `adversarial` 1. The unchanged strict query-plan v2 schema is used. Source-order membership is recorded separately in the four-case `opalweft_quartet` group and does not introduce a new class.

The four `opalweft_*.trace` fixtures contain the same four synthetic records with every record moved to a different line ordinal in each variant. `harborflax.trace` and `teatonic.trace` hold the other synthetic facts. All six files are hand-authored strace-like fixtures, not captures from any computer. Names, paths, IDs, and documentation-range IP addresses are fictional. Expected selectors for answerable plans appear in the question text; traces validate the returned fixture rows only.

An exact independence check against the other query-plan corpus fixtures found no repeated trace filenames, rows, process IDs, paths, or IP addresses; question text had no exact match or similarity above 0.82. The separate one-case smoke is excluded and must not be combined with these 40 cases.

## Existing two-shot prompt pin

The candidate intent references the existing [`experimental two-shot system prompt`](../local_query_plan_v2_confirmation/experimental-two-shot-system-prompt.txt), SHA-256 `ef343d6996d9bd0fc0e881224374fa78ca574d1ab5826a65b86e1e9505025ef1` (2,683 bytes). The prompt is not copied or modified. Preview-only validation does not invoke the candidate or the two-shot prompt; it checks SideEffect's current request construction, including that the preview prompt contains only the question and fixed supported scope.

## Validation

From a Linux x86_64 checkout with the repository's Rust toolchain and Python 3:

```sh
cargo build --release --locked --bin sideeffect
python3 tests/fixtures/local_query_plan_v2_confirmation_phi35/validate_corpus.py \
  --sideeffect target/release/sideeffect
```

The local validator runs the real `sideeffect model-query-preview` for all 40 questions, uses the repository evaluator's pinned preview and fixture-match helpers, validates the strict v2 plan structure and registered classes, verifies fixture hashes, and checks the four source orders. It does not perform model inference. Passing this check establishes request and synthetic-fixture consistency only; it does not establish model accuracy, real-capture correctness, complete observation, safety, causation, or effective access.

## Integrity

Hashes cover exact file bytes. The corpus records each synthetic trace's byte length and SHA-256.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `corpus.json` | 32,880 | `b89bff8708b142b1979a65f0682af0cf8751713d92aa17012045c23ec491bc35` |
| `opalweft_a.trace` | 413 | `51031e7b1cdb2fb52afb79d9b468721c67a9e062077c3796f011c95a21f3f8d7` |
| `opalweft_b.trace` | 413 | `568944479bec13ef0d3e974fdfe775d855fbd2118e52c47fa6a99985e730d6ce` |
| `opalweft_c.trace` | 413 | `59a8ba4609409e851faa00d15a1e89eb93f042576f52880ddb31442c69974287` |
| `opalweft_d.trace` | 413 | `8d40eeef3e6c9f6fc2976d549446e1613644b1c911757e69efef410bb284763b` |
| `harborflax.trace` | 764 | `df1dd8e203d314d9814571e5d4ba3c00efecf3229e6ae605f276047fcf64ed19` |
| `teatonic.trace` | 640 | `9c34ea814238f9a6982eedad96565d02d89c65925c29863558fab58d655e8d78` |
| `validate_corpus.py` | 10,462 | `836e5990326eed51abd70a2fa667bf067c6348cdffeab6c79abca8736a8bead9` |
