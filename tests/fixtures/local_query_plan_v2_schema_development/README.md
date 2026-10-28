# Local query-plan schema development corpus

**Status: development-only; not a frozen holdout, release gate, or real-capture benchmark.** This corpus is intended for experiments that change the JSON Schema shape used for constrained model generation while leaving the schema-v2 query-plan semantics and strict Rust validator unchanged.

## Scope and separation

`corpus.json` has 32 cases: 20 supported selectors and 12 required abstentions. The answerable set covers the supported syscall-result and process-relation fields, conjunctions, multiple-match and deliberate no-match queries. Abstentions cover unsupported conclusions and fields, ambiguous selectors, missing referents, and instruction-like hostile questions. Every expected selector is expressible from the question text alone; trace facts validate whether a selector matches fixture rows and are not sent to the model.

The set uses two new hand-authored fixtures, `meridian.trace` and `atlas.trace`. Both are synthetic examples, not captures from computers. The cases and trace values were authored independently of the frozen query-plan v2 corpus and the earlier query-plan development/confirmation sets. The corpus is small and contains no order-permutation control; repeated tuning against it can overfit. A result here is only a development signal.

Schema experiments must preserve all public schema-v2 plan semantics, exact-match AND filtering, and the existing strict Rust-side validation. A relaxed generation schema does not authorize SideEffect to accept invalid, cross-entity, or inconsistent plans. Do not modify the frozen 100-case corpus or its registered thresholds.

## Integrity

- Cases: 32 total (20 answerable, 12 required abstentions)
- `corpus.json` SHA-256: `7c8fdd8d478db815b2d7a878efba69a2bc15199deda38372af444f12790435e6`
- `meridian.trace`: 752 bytes; SHA-256 `b270f5a3e205a30d3468ee1d948a2984340b9f7aeeab8cf922528cf03ebab553`
- `atlas.trace`: 673 bytes; SHA-256 `d8c465af703255840d9bb7678e100f0a89b6e55b7fc6e65dd065ae720b1c2b02`

## Validation

Every case should be passed through the real `sideeffect model-query-preview` command. Check the model prompt contains only the question and fixed scope, verify each expected plan against the preview's bounded facts, and record malformed/runtime outputs as failures. No model was run while creating this corpus. Preview validation does not establish model quality, correctness on real captures, complete observation, safety, causation, or effective access.
