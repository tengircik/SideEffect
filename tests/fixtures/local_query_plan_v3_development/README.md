# Local query-plan v3 public development corpus

This directory contains public, synthetic development data for the unchanged SideEffect query-plan schema v2. The corpus container is schema v3. It is not a hidden holdout, independent release evaluation, model-quality gate, or release-quality evidence. Do not use its scores to approve or recommend a model.

## Cases and intent groups

`corpus.json` contains 120 cases: 80 filter plans and 40 required abstentions. The 80 answerable cases consist of five four-variant source-order groups (20 rows but five intent groups) plus 15 unique intents each for syscall, conjunction, process-ID/multi-match, and process-relation queries. Each of the 40 abstentions has no oracle fixture, selectors, or selector-support metadata; each uses the same bounded synthetic `evaluation_fixture` so an external evaluator can provide parseable trace context to the CLI. The cases cover ambiguous, unsupported, insufficient, and adversarial questions (10 each). Adversarial cases may use `ambiguous` or `unsupported_scope`; other classes have one fixed reason.

The 20 source-order fixtures each contain the same four synthetic records within their group, permuted so the selected record occupies four different line ordinals. Each group's four expected plans are identical. The other 60 answerable cases have unique intent groups and distinct normalized question templates.

Every non-null expected filter value must appear in an exact field/value token such as `[syscall=openat]` in the question. `selector_support` records that full token and the matching fixture line; for zero-match cases, its `source_line` is null. No synonym mapping is allowed. The model's supported query inputs remain only the question and fixed schema scope; fixture records are validator evidence and are not question content.

Five of the 15 conjunction cases are explicit zero-match queries: their questions contain the exact canonical path and other selector values, but that path is absent from the referenced fixture. Those cases use `expected_match_count: 0`, `target_line: null`, and null `source_line` for each selector. The validator scans the full bounded fixture and accepts the case only when there are no matching rows. The PID/multi-match class is expected to match two rows; every other answerable query has a cited matching row. This small zero-match slice does not establish broader no-match behavior or query usefulness on real captures.

## Fixture and plan contract

Fixtures are short hand-authored synthetic strace-like text files, never captures from a computer. `evaluation_fixture` is pinned and parsed for every case; for answerable cases it equals the oracle fixture, while abstentions use `abstention-context.trace` and retain null oracle fields. The validator checks exact fixture hashes, record bounds, query-plan schema v2 fields, strict supported entities/enums and entity-specific fields, selector grounding, selector-to-row matches (including zero-match selectors), expected result counts, counts, unique IDs and templates, and source-order invariance. Source-order permutations use the same exact question text within each group. The schema still supports exact equality and AND only; syscall and relation values are limited to those in the product schema. This development set primarily measures exact field-value extraction and serialization, not broad natural-language robustness: selector literals are explicit and templates are synthetic. The corpus does not cover endpoint or timestamp queries or semantic model quality. These fixtures are parsed only by this local validator; no SideEffect product parser integration is exercised.

The corpus is bounded to 512 KiB. Each fixture is capped at 128 KiB, 64 KiB per physical record, and 1,000 records. Questions are capped at 2,048 UTF-8 bytes. These are development-corpus validation limits, not new product limits.

At generation time, `corpus.json` is 145,092 bytes with SHA-256 `93a70b85150d81c52586670600e36c472dbd0f2c40ec74f6b8065944eea0aec7`. Per-fixture SHA-256 values are pinned in the corpus document and verified by the validator.

## Reproduction

From the repository root:

```text
python tests/fixtures/local_query_plan_v3_development/generate_corpus.py
python tests/fixtures/local_query_plan_v3_development/validate_corpus.py
python -m unittest discover -s tests/fixtures/local_query_plan_v3_development -p 'test_*.py' -v
python -m unittest scripts.test_evaluate_local_query_plan_v3 -v
```

The generator only writes files in this directory. Corpus validation and both test suites use Python's standard library and do not load or run a model. The evaluator tests use a mocked CLI boundary; they do not validate a built SideEffect binary or runtime capture. To validate previews through a built Linux CLI, use `scripts/evaluate_local_query_plan_v3.py --sideeffect PATH --model PATH --expected-model-sha256 SHA256 --preview-only`; this registers the model only in a temporary local registry and runs no inference. A full run additionally requires `--runtime PATH --expected-runtime-sha256 SHA256` and executes local CPU inference. Both modes produce development diagnostics only, not model qualification.
