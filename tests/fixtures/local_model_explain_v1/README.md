# Local evidence explanation development corpus

This directory contains hand-authored synthetic `strace` examples for developing an evidence-grounded local-model explanation flow. These files are not captures from a computer. Paths, process IDs, executable names, and network addresses are inert test data. Addresses use documentation-only ranges.

`corpus.json` is a historical v1 development set, not a release gate. Its saved-response contract predates the current selector-only `model-explain` output and must not be treated as a current runtime schema. It must not replace or modify the existing local query-plan v2 holdout, and no candidate should be accepted based on tuning against this set. The evaluator checks corpus structure, fixture digests, and optional pre-recorded v1 output structure; it does not judge whether model-authored prose is true. Semantic review must be performed separately by a human against the exact evidence preview.

The cases exercise direct observations, errno and outcome interpretation, lexical path hints, process relations, multiple related facts, partial parses, unknown capture coverage, ambiguous or unsupported questions, prompt-injection-like question/path text, and source-order permutations. Expected semantic labels and evidence constraints are review guides, not a claim that synthetic results generalize to real traces.

The historical v1 model response was a strict JSON object with `status`, `abstain_reason`, and `statements`; each statement contained `kind`, `text`, and `evidence_ids`. Those fields are retained only to validate preregistered historical results. The current runtime instead accepts only unique syscall-result `evidence_ids` and returns the exact matching rows from the reviewed preview. It does not expose model-authored prose.

## Checks

From the repository root, run:

```sh
python3 scripts/evaluate_local_model_explain.py --check-corpus
```

To structurally inspect a separately saved set of inference responses without running a model:

```sh
python3 scripts/evaluate_local_model_explain.py --check-corpus \
  --results PATH_TO_PRE_RECORDED_RESULTS.json
```

The result file must name the exact corpus digest. Its optional human-review fields are explicitly reported as human-provided and are never inferred from model text.
