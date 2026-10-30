# OLMo-2 query-plan confirmation corpus

**Status: development-only; not a frozen holdout, release gate, model result, or real-capture benchmark. No model inference or prompt tuning was performed while authoring or validating this corpus.** This is a fresh, independent synthetic set for the OLMo-2-0425-1B-Instruct candidate.

## Corpus and separation

`corpus.json` contains 40 cases: 24 answerable plans and 16 required abstentions. It uses the unchanged strict local query-plan v2 object and covers individual predicates, AND combinations, paraphrases, process relations, intentional no-match filters, ambiguity, insufficient referents, unsupported conclusions and actions, and hostile instruction text. Every answerable expected selector is stated in its question; fixture rows are used only to check the selected result set. Answerable `class` values use the registered evaluator taxonomy (`conjunction`: 8, `single_predicate`: 7, `process_relation`: 4, `paraphrase`: 2, `no_match`: 2, `multi_match`: 1); abstentions use `unsupported`: 11, `ambiguous`: 2, `insufficient`: 2, and `adversarial`: 1. Permutation membership is recorded separately from class labels.

The four-case `copperveil_rotation` group contains identical facts in four distinct source orders. Each fact moves to a different line ordinal in each trace, while all four questions and expected plans remain the same. This single small synthetic group is an order-control example, not broad order-invariance evidence.

The six traces (`copperveil_a.trace` through `copperveil_d.trace`, `siltwarden.trace`, and `quincet.trace`) are newly hand-authored synthetic strace-like fixtures, not captures from computers. Their names, paths, PIDs, and documentation-range IP addresses are fictional. A comparison against the other query-plan corpora found no exact question overlap, no question with sequence similarity above 0.82, and no exact trace-row overlap. The simple-prompt smoke and its examples, traces, outputs, and results are outside this corpus and must not be counted with it.

## Candidate prompt reference

The candidate prompt is the existing [`experimental two-shot prompt`](../local_query_plan_v2_confirmation/experimental-two-shot-system-prompt.txt), pinned in `corpus.json` at 2,683 bytes and SHA-256 `ef343d6996d9bd0fc0e881224374fa78ca574d1ab5826a65b86e1e9505025ef1`. It is referenced without copying or editing. The preview-only validation below does not load or execute that prompt; it verifies SideEffect's current request construction and checks that the product preview prompt contains only the question and fixed supported scope. Subsequent model results are recorded separately.

## Validation

From a Linux x86_64 checkout with the repository's Rust toolchain and Python 3:

```sh
cargo build --release --locked --bin sideeffect
python3 tests/fixtures/local_query_plan_v2_confirmation_olmo2/validate_corpus.py \
  --sideeffect target/release/sideeffect
```

The corpus-local validator runs the real `sideeffect model-query-preview` command for all 40 cases, applies the repository evaluator's pinned preview checks and fixture-match functions, validates the unchanged strict v2 plan shape, verifies every trace hash, and checks the order permutation. It does not invoke a model. A passing run establishes request-construction and synthetic fixture consistency only; it says nothing about model accuracy, real captures, complete observation, safety, causation, or effective access.

## Integrity

Hashes cover each file's exact bytes. The corpus records each trace's status, byte length, and SHA-256.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `corpus.json` | 32,650 | `6bb7624565e9aaca7952dea7e87c6fad8e6c58883e880d9b76526ba0d0402e48` |
| `copperveil_a.trace` | 400 | `574025d190b7595d3289f1e3b653ba2ab9a3ba845dde88171b9020eb4d35187e` |
| `copperveil_b.trace` | 400 | `4cb4c4b63a9da4e1eb9d2a552c90c090ed9a0adce7d6c72b89d2628e0c02c5f8` |
| `copperveil_c.trace` | 400 | `92187ecb78338db41cf6f9467e61a64c497f73bc46193f0edadf34d9d015f3e8` |
| `copperveil_d.trace` | 400 | `8dd85b6071ad5382a52ae2e35aa3a6adbbea02c6f18ea4037ebdfd6f10393dbb` |
| `siltwarden.trace` | 770 | `e0462981783d6fbde850b0374389c6826d9df544b9c12aca9bf253aeb57d2e57` |
| `quincet.trace` | 626 | `380001116e6a34d18c7e9f3966402b9b67cf42d9388011a5d93453133b6c8d0f` |
| `validate_corpus.py` | 10,486 | `7ecd6eb188808942fa0fa4291ded81d7ae8f2b3d5dab6b1df482d57419f7791f` |
| `model_run_report.json` | 62,796 | `62b4ac63b23254e6c3dc35227c2ea275b53b042fe82a932632d841203deb6b6f` |

## Candidate result

The one-time OLMo-2 Q8_0 GPU evaluation failed the confirmation checks: 7/24 exact plans and 15/24 exact result sets, versus 22/24 for the fixed lexical baseline. The model generated filters for all 16 cases that required abstention. This synthetic result is a no-go and not a release gate; see [the full per-case report](model_run_report.json).
