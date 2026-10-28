# Local query-plan v2 development corpus

**Status: development-only. This corpus is for controlled prompt/schema experiments. It is not a frozen release gate, a user-capture benchmark, or evidence of real-world accuracy.**

## Scope and separation

`corpus.json` contains 40 independently worded questions over one hand-authored synthetic trace: 24 supported selectors and 16 required abstentions. It covers exact syscall, outcome, errno, path, process ID, and process-relation filters; conjunctions; paraphrases; supported filters expected to return no rows; unsupported conclusions and actions; ambiguous or underspecified requests; and hostile instruction-like text.

The questions and trace are new and do not reuse the frozen v2 holdout cases or the earlier synthetic model corpus. The frozen corpus at `../local_query_plan_v2/corpus.json` and every registered acceptance threshold must remain unchanged. Do not report this development set as a release pass or use it to support product claims.

All cases share one small fixture. They are independent question examples, **not 40 independent traces or runtime environments**. The set has no source-order permutation group and is too small for statistical claims. Repeated tuning against it can overfit; keep experiment variants and results explicit, and freeze any final candidate before running the canonical holdout once.

## Fixture

`development.trace` is synthetic strace-like text authored solely for this corpus. It is not a real capture. Its paths, process IDs, and documentation-only IP addresses are fictional test values. It contains observed examples of `openat`, `openat2`, `connect`, `execve`, `execveat`, `clone`, and `vfork`, including both successful and failed results.

## Integrity

- Corpus: 40 cases (24 answerable, 16 must-abstain), 27,650 bytes
- `corpus.json` SHA-256: `458b893b4941c6a74d77ce3535fef16558d1c45bfe1e816af3175861fbe6fa53`
- `development.trace` SHA-256: `cc3b622c6d0d22513b8a66bd9d20b6af82da9595b5795fb7c0511eab43175236`
- `development.trace` size: 893 bytes

## Preview validation

The canonical evaluator is intentionally pinned to the separate 100-case frozen corpus and cannot be pointed at this development corpus. To inspect the current request and verify that a case's trace/question builds a preview, build SideEffect and run one case manually:

```sh
cargo build --release --locked
./target/release/sideeffect model-query-preview \
  --question "List records for the openat syscall." \
  tests/fixtures/local_query_plan_v2_development/development.trace
```

For prompt/schema A/B experiments, compare variants on all 40 case IDs with identical model, runtime, decoding settings, and resource caps. Isolate factors: current prompt/current schema ordering, candidate prompt/current ordering, current prompt/filter-first ordering, and (only after separately interpreting those results) both changes together. Score exact plan accuracy, answerable result-row accuracy, false filters on required abstentions, abstention reasons, and runtime failures separately. A zero-row filter is an answerable search and does not assert that an event occurred. Do not weaken Rust-side validation or the frozen gate to improve this development score.

The preview command does not invoke a model. A successful preview validates request construction only; it does not validate model quality or whether the expected plan is correct. No model was run while creating this corpus.
