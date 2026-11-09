# Windows ETW query development corpus v1

This public corpus is a small synthetic development aid for the experimental native Windows x86_64 ETW query-plan workflow. It is not a reviewed benchmark, hidden holdout, release gate, or model-quality claim. The labels have not been independently reviewed. The capture fixtures are synthetic and must not be described as real machine observations.

The cases exercise exact finite-field extraction, conjunctions, zero-match filters, event-order stability, prompt-injection text, and abstention when a request asks for a hostname, an unsupported success outcome, unavailable process details, or ETW header identity. Questions use deliberately literal selectors; the corpus does not measure broad natural-language understanding.

`corpus.json` pins each fixture's exact bytes. `scripts/evaluate_local_model_windows_etw_query.py --check-corpus` validates bounded strict JSON, capture integrity, plan shapes, and that the expected plan selects the declared fixture ordinals under SideEffect's documented exact-match AND semantics. This only checks corpus structure and internal oracle consistency. It does not prove the question entails its label, run the product CLI, invoke a model/runtime, score model quality, or qualify a model.

The query fixtures are separate copies of the small synthetic captures used by the Windows ETW explanation development corpus. Keeping the manifests independent lets each task evolve without silently changing the other task's pinned inputs.
