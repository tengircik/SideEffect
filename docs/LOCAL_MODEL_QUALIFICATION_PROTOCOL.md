# Local model qualification protocol

**Status: proposed protocol; not approved or executed.** SideEffect's local model features remain experimental, optional, and not release-approved. No model currently qualifies for user decisions. This document defines the evidence needed to consider qualification; it does not change a task's existing frozen corpus, score, threshold, platform support, or release status.

## Qualification unit and prerequisites

Qualification applies to one exact tuple: task, product schema and validator, prompt, model artifact, runtime build/backend, operating system/source type, and resource profile. A result for one tuple does not qualify another model, task, prompt, backend, or platform. Report native Linux `strace` and native Windows ETW separately. WSL2 is not native Linux acceptance, and Windows-host inference over Linux fixtures is not Windows ETW evidence.

Before starting a model-quality run, the maintainer must record and review:

- The deterministic evidence, query, citation, coverage, and privacy contracts consumed by the task, including the relevant R3–R7 prerequisites. Unsupported or incomplete source states must remain explicit.
- The frozen task schema and validator, user-visible data flow and consent, resource limits, local runtime/model handling, and the deterministic baseline. The model must not collect data, execute commands, broaden scope, or create evidence.
- A written benchmark plan: task/platform scope, case strata, labeling rubric, independent reviewers, scoring code, candidate-specific pass criteria, resource environment, and stop conditions. Freeze this before candidate inference. Existing task-specific frozen gates remain authoritative unless a separately reviewed change is approved before a new run.

If a prerequisite, independent review, ground-truth source, or reproducible measurement is missing, stop and retain the no-go status. Do not infer qualification from schema validity, one-case triage, prompt improvement, or a synthetic-only result.

## Corpus design and ground truth

Build separate development material and a hidden qualification holdout. Candidate prompts may be iterated only on development material. Keep the holdout unavailable to prompt authors and candidate tuning until its final one-time scoring; any exposure or tuning invalidates it as a holdout and requires a fresh independently authored set.

For each supported platform, include source-specific examples tied to the exact evidence contract:

- Linux: bounded SideEffect previews derived from pinned synthetic traces and, where approved and available, controlled real `strace` captures. Record tracer and kernel versions, capture status, source digests, parser diagnostics, and exact evidence locators.
- Windows: native bounded ETW captures and previews from controlled benign workloads, plus documented synthetic fixtures for edge cases. Record Windows build, provider/session configuration, loss counters, capture status, payload decoding limits, and exact source-event ordinals/digests. Synthetic ETW fixtures test the adapter contract; they do not substitute for live capture or establish model quality on live ETW.
- In both: include directly answerable, unanswerable, ambiguous, unsupported-scope, partial/incomplete, empty-evidence, similar-event, and misleading-context cases. Include ordinary benign activity, failed and successful operations, repeated or reordered records, and questions that invite conclusions beyond the evidence. Label each case with the answerability class and the exact allowable evidence set; do not equate a missing row with proof of absence.

Each oracle must be derived from retained source records by a documented deterministic procedure. Preserve raw source artifacts separately from labels and outputs. Two reviewers independently label semantic support and answerability without seeing candidate outputs; reconcile disagreements with a recorded adjudication. Reviewers must not be the sole authors of the examples they adjudicate. Record reviewer roles and disagreement counts without publishing personal data. If independent review cannot be arranged, label the corpus development-only and do not use it to qualify a model.

For evidence-selection/explanation tasks, the oracle identifies all acceptable source rows and required semantic labels, not one brittle row ID where source order can change IDs. For query planning, it specifies the complete expected validated plan, result rows, and expected abstention. Record acceptable alternatives and prohibited interpretations in advance. Include source-order permutations and equivalent question wording as paired groups, with comparison performed on semantic evidence identity rather than generated IDs.

Real local captures may contain personal, operational, or security-sensitive information. Prefer controlled benign workloads and synthetic fixtures. Obtain explicit owner consent and review before using real captures; minimize, redact, and access-control retained data while preserving the fields required for evaluation. Never commit raw captures, private reports, model outputs containing local data, or credentials. Public benchmark material must be reviewed for re-identification and secret leakage before publication.

## Scoring contract

Freeze metric definitions and case-level outputs before inference. Report numerators, denominators, per-stratum results, uncertainty, and excluded/invalid cases; aggregate scores must not hide a failing platform or safety-critical stratum. At minimum measure:

- **Contract validity:** strict product-validator acceptance, unknown/duplicate/out-of-scope evidence references, malformed output, timeout, and runtime failure. Invalid output is a failure, not an abstention.
- **Evidence selection:** precision and recall against the independently reviewed allowable evidence set, plus exact or semantic correctness for the task. Preserve per-case results and permutation-group consistency.
- **Citation validity:** whether each selected reference resolves to the exact supplied artifact and record, and whether the selected record supports the requested statement under the frozen rubric. A syntactically valid ID alone is not a correct citation.
- **Unsupported claims:** count claims that imply causation, root cause, safety, complete coverage, absence, effective access, process ownership, or execution when the source does not establish them. For structured selection tasks, score the semantic interpretation of selected rows under the same rubric; do not treat prose suppression as proof of semantic correctness.
- **Abstention and refusal:** correct abstention on unanswerable, ambiguous, unsupported-scope, and insufficient/partial evidence cases; false selections and false refusal on answerable supported cases. Report each class separately.
- **Deterministic baseline:** run the same cases and same available facts through the frozen non-model method. Compare task-appropriate correctness and abstention measures; do not let the model's output filter or preselect its baseline inputs.
- **Privacy and adversarial robustness:** test instruction-like text in paths, arguments, process names, event payloads, and metadata; malformed/oversized records; reordered/duplicated evidence; and questions requesting hidden data or unsupported conclusions. Verify that input remains inert data, output stays within the schema, references remain allow-listed, and no network transfer or telemetry occurs.
- **Resources:** record per-case and aggregate latency (including warm/cold conditions), timeout/error rates, child-process peak RSS/working set, model-load and inference resource use, and GPU backend/offload plus process-attributable VRAM where available. Record host/device, OS/build, driver, runtime revision/binary digest, model digest/quantization, thread/context/token settings, power/thermal caveats, and sampling method. Mark unavailable measurements explicitly; whole-device VRAM is not process-attributable. Resource compliance is distinct from semantic quality.

Maintainers must choose and justify task-specific minimums for quality, abstention, unsupported-claim tolerance, baseline advantage, privacy, and resources before candidate inference. Existing frozen gates in the relevant evaluation documents may supply those minimums for their named task and corpus. This proposal does not create numeric thresholds. Any new or changed threshold requires review and a new pre-registered run; never relax criteria after seeing candidate results.

For an implementation-grounded scenario map, see the proposed [scenario-to-oracle matrix](LOCAL_MODEL_BENCHMARK_MATRIX.md). It maps existing Linux and Windows evidence fields to candidate benchmark classes and records which classes currently lack an adequate oracle or platform corpus.

## Run record and reproducibility

Use an isolated, user-controlled model registry and the supported SideEffect inference path. Do not start a runtime or download/register weights without explicit user action. Keep inference local and offline; verify that the runtime's actual behavior matches the documented controls. A local model/runtime is executable code and is not automatically sandboxed.

For each run, freeze and record before candidate execution:

1. Clean source commit and working-tree status; evaluator and scoring-script digests.
2. Corpus manifest and per-artifact SHA-256 digests; corpus provenance, platform strata, review/adjudication status, and pre-registered criteria.
3. Exact task/schema/validator/prompt versions and digests; model source/revision, file digest, quantization and license status; runtime source revision and binary digest; selected backend and effective resource settings.
4. Host and OS/device details, commands and environment needed to reproduce the run, with secrets and user-specific paths omitted.

Retain a bounded machine-readable per-case report outside the repository unless a separate privacy review explicitly approves a sanitized report. Report all errors and every case; no silent retries, candidate filtering, deterministic fallback presented as model output, or selective omission. If code, prompt, validator, model, runtime, corpus, or gate changes during evaluation, stop and begin a new pinned run. Do not publish raw captures or local model artifacts.

## Decision and release boundary

Qualification requires all predeclared gates to pass on the same pinned run, independent review of the complete per-case report, no unresolved privacy/security blocker, and separate platform evidence for every advertised platform/task tuple. A pass qualifies only the named tuple and benchmark conditions. It does not establish general accuracy, safety, root-cause ability, exhaustive observation, or suitability for operational decisions.

Any false unsupported claim, invalid citation, unsafe injection behavior, scope expansion, undeclared network behavior, failed resource bound, missing required platform capture, or unreviewed label blocks qualification. Publish limitations, failed strata, independent-review status, and measured resources alongside any later positive result. Keep deterministic workflows fully usable without a model; an unqualified optional model must remain clearly labeled experimental and must not be recommended for security or operational decisions.

## Current state

Existing records show failed or incomplete results for evidence selection and query planning. The native Windows explanation work is development-only; it has no independently reviewed ETW model-quality corpus and no candidate has been approved. Existing synthetic development corpora and live adapter contract tests do not satisfy this protocol by themselves. See [the R9 roadmap](IMPROVEMENT_ROADMAP.md#r9--optional-ai-investigation-evaluation-and-implementation), [local model evaluation](LOCAL_MODEL_EVALUATION.md), [query-plan evaluation](LOCAL_QUERY_PLAN_EVALUATION.md), and [explanation evaluation](LOCAL_MODEL_EXPLANATION_EVALUATION.md). No model-quality run is authorized by this proposal; the protocol and candidate-specific acceptance plan must first be reviewed and frozen.
