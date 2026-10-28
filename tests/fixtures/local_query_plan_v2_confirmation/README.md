# Local query-plan confirmation corpus

**Status: development-only confirmation set. It is not a frozen holdout, release gate, user-capture benchmark, or evidence of real-world accuracy.**

## Purpose and separation

This corpus is intended to check whether a prompt candidate selected on `local_query_plan_v2_development` transfers to new synthetic questions. It contains 40 cases: 24 supported selectors and 16 required abstentions. The questions and trace values are newly authored for this set; they do not reuse the frozen v2 corpus or the earlier development corpus. Each answerable expected plan is expressible from the question text alone. Trace contents are used only to validate whether the expected selector returns rows, including deliberate no-match cases; the model prompt does not receive those facts.

The corpus uses two separate hand-authored synthetic strace-like fixtures, `comet.trace` and `aurora.trace`. Neither is a real capture. The paths, process IDs, and documentation-range IP addresses are fictional fixture values. They must not be presented as observations from a real computer.

The set is small, has no source-order permutation control, and shares only two synthetic traces. It is a confirmation aid, not proof of generalization. Repeatedly tuning on this set would overfit it. Keep candidate code/prompt frozen while running it, and preserve the canonical 100-case gate unchanged.

## Coverage

Supported cases include exact syscall/outcome/errno/path/process-ID selectors, explicit AND conjunctions, paraphrases, process relations, and valid selectors that intentionally match no records. Abstention cases cover unsupported conclusions/actions, ambiguous requests, missing values or referents, and instruction-like hostile text. Abstentions must keep every filter null.

## Integrity

- Cases: 40 total (24 answerable, 16 must abstain)
- `corpus.json` SHA-256: `0a7f03fc617bbc42ddb4d389d14e9e54f44de2dc7363081dac459b2230906f59`
- `comet.trace`: 878 bytes; SHA-256 `217f80da7aa56c747243eb3b763af5bd94a8c9da02669910e5254c2dd1b03d89`
- `aurora.trace`: 706 bytes; SHA-256 `cbbb21b448c33cbd081b608087f3b9d4e2469e3c618698f98a70a6212a0f1265`

## Validation performed

All 40 questions were passed through the real `sideeffect model-query-preview` command using the synthetic fixture files. The canonical evaluator's preview validation confirmed request shape, fixed scope, model/runtime pins, and trace digests. Each expected selector was checked against the preview facts: answerable selectors matched fixture rows, must-abstain selectors returned no rows, and no-match selectors returned no rows. No model inference was run while creating or validating this corpus.

A successful preview validates request construction and expected fixture consistency only. It says nothing about model accuracy, real captures, completeness, safety, causation, or effective permissions. Do not modify or weaken the frozen v2 corpus or its registered release criteria to fit results from this development set.
