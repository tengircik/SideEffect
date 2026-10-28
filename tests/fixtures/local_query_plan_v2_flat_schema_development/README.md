# Local query-plan v2 flat-schema development corpus

**Status: development-only; not a frozen holdout, release gate, or real-capture benchmark.** This corpus supports experiments with a flatter, simpler closed-value JSON Schema for local query plans. It changes only the candidate generation shape. The product schema and strict Rust validator remain unchanged.

## Scope and separation

`corpus.json` contains 32 cases: 20 answerable exact-match queries and 12 required abstentions. The answerable cases cover supported syscall filters, outcomes, observed errno, exact lexical paths, process IDs, process relations, conjunctions, multi-match selection, and a deliberate no-match selector. The abstentions cover ambiguous and missing selectors, root-cause and safety claims, proof of absence, completeness, effective permissions, unsupported host identity, unbounded scope, and hostile prompt injection.

The candidate plan schema is `sideeffect.local_query_plan_flat_development_corpus` version 1. It has one flat object with fixed top-level keys, `additionalProperties: false`, closed enums for decision, entity, abstention reason, syscall, outcome, relation type, and the 134 supported errno names. Selector values are nullable. Non-null values use exact equality and are combined with implicit AND; there is no nested `filters` object or `combine` selector. Dynamic exact paths and positive u32 process IDs remain bounded typed values. An abstention requires a reason and null entity/selectors. A filter requires an entity, null abstention reason, and only selector fields for that entity.

Every expected plan is determined by its question text alone. Fixture contents are used only to validate whether the requested selectors yield rows. Trace values are never inserted into the model prompt. `orbit.trace` and `kepler.trace` are hand-authored synthetic strace-like fixtures, not captures from any computer. The names, paths, IDs, and documentation-range IP addresses are fictional. The cases and fixtures were authored independently of the frozen v2 corpus and the earlier development, confirmation, schema-development, and model-synthetic corpora.

This small corpus has no source-order permutation group; repeated tuning can overfit it. Do not use it to change frozen holdout thresholds or support product claims. Mapping each candidate plan to the current nested schema in the validator is an in-memory fixture-checking adapter only. It neither edits product files nor loosens Rust validation.

## Validation

From a Linux x86_64 checkout with the repository's Rust toolchain and Python 3:

```sh
cargo build --release --locked --bin sideeffect
python3 tests/fixtures/local_query_plan_v2_flat_schema_development/validate_corpus.py \
  --sideeffect target/release/sideeffect
```

The validator runs the real `sideeffect model-query-preview` command for all 32 cases, uses the repository evaluator's pinned preview checks (including the fixed question-only prompt and preview/model/runtime pins), validates the flat plan shape and enums, and checks expected fixture matches using the evaluator's fixture functions. It accepts answerable rows, zero rows for the deliberate no-match case, and zero selector rows for required abstentions. It performs no model inference. A successful run validates request construction and synthetic fixture consistency only; it says nothing about model accuracy, real captures, complete observation, safety, causation, or effective permissions.

## Integrity

Hashes cover the exact UTF-8/ASCII bytes in each file.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `corpus.json` | 24,625 | `5d93f787666ec33bb91e585d81d30fe87f0d16ac55b51a6eb74262a34f2b4982` |
| `orbit.trace` | 712 | `88c475b42d9508b7089366a67accd39aaa917ac84e86f3e9a56284396ed0a162` |
| `kepler.trace` | 802 | `2ec4b071dd902829b1eb396ec56375c52e369adc75a8ee8f64a596ca2b440bf2` |
| `validate_corpus.py` | 8,351 | `1f25d6aa80f71a8e3cdfe9cce8aa766c18255ec7c08f86d1ec231c189d2fae2f` |
