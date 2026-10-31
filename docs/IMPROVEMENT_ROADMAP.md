# SideEffect Improvement Roadmap

**Status:** active investigation and delivery plan; this document is not a schedule, completion claim, or release promise. It expands the existing bounded audit product into a staged investigation workflow. Every phase is gated by evidence, privacy, and platform validation. Linux and native Windows have equal product priority. A capability is not considered part of the shared product until its supported workflow and limitations are documented and validated on both platforms, or an explicit platform-specific limitation is accepted and shown to users.

This roadmap is based on the repository documentation and the technical critiques listed in the traceability matrix below. It is a planning synthesis, not a new code audit. Existing implementation status remains governed by `PRODUCT.md`, `ARCHITECTURE.md`, `PLAN.md`, the [source acceptance matrix](SOURCE_ACCEPTANCE.md), compatibility records, and the security policy. A planned capability does not imply that a collector can observe every relevant system action.

## Implementation status (2026-10-31)

These are audited status summaries, not phase acceptance. “Partial” means useful code exists while the named phase gate remains open.

| Milestone | Current status | Evidence and open gate |
|---|---|---|
| R0 — Scope and evidence quality | Partial | Audit-session v2-v6 coverage/source/host/collector metadata, process-generation evidence, and session comparability exist. Coverage manifest v2 adds bounded Linux trace and Windows ETW unsupported-category counts; legacy coverage v1 remains readable, and missing/different runtime detail cannot make sessions comparable. `SOURCE_ACCEPTANCE.md` defines the `SourceStatus` to `CoverageStatus` crosswalk, with table-driven coverage for every source status; `not_observed` remains reserved because empty results do not establish absence. A phase-wide source-by-source acceptance review and stronger process identity evidence remain open. |
| R1 — Collector reliability | Partial | Bounded Linux trace fuzzing and real `strace` integration exist, including successful file/loopback activity, a real `ECONNREFUSED` attempt retained as failure, and a real SIGTERM cancellation check that verifies partial-trace discard and traced-target cleanup. The cancellation scenario was run locally under WSL Ubuntu with strace 6.19; Ubuntu 24.04 hosted CI passes the named real-capture cases. WSL2 synthetic scale runs cover `getpid` and `sendfile` at 10k/100k rows. The 1M case was not attempted because it exceeds the parser cap. Broad OS/provider matrices, other loss/failure scenarios, sustained fuzzing, and native-Linux/Windows performance acceptance remain open. |
| R2 — Software/process/startup discovery | Partial | Package, process, and startup snapshots exist; `inventory path-executables` covers current PATH on Linux and Windows, Linux audit sessions can include that bounded snapshot, and Linux package discovery includes optional Flatpak refs. Process schema v3 now adds Linux `NSpid`/namespace-link evidence and Windows generation-checked token SID, integrity RID, and session context; session readers retain process schema v1-v3 compatibility. Additional discovery adapters and configured/effective/observed startup separation remain open. |
| R3 — Event model and timeline | Partial | Common event envelope v2 is exposed through bounded Linux strace and native Windows ETW CLI adapters. `graph` v1 now builds source-local event/process nodes and evidence-linked relationship/link edges; unresolved PID context is never merged into process instances. `timeline` provides exact event-kind filtering and per-item source references; both commands preserve partial/unknown status. Hosted Ubuntu 24.04 tests exercise graph and timeline on real `strace` captures; Windows Server 2022/2025 live ETW acceptance exercises them over the real process/file/loopback capture. These named scenarios do not establish broad OS or event coverage. Graph filtering, broader timeline filters, service-mediated links, and richer interactive drilldown remain open. |
| R4 — Semantic diff and baselines | Partial | Exact Linux trace diff, Linux package and process snapshot comparisons, conservative Windows ETW comparison, and Windows uninstall-registration and process snapshot comparisons exist. Process identities require observed platform-specific generations and presence claims are suppressed for incomplete or ambiguous snapshots. Three-layer diff, normalized-field ledger, additional source comparisons, and reviewed behavioral baselines remain open. |
| R5 — System-change intelligence | Partial | Package/ETW comparisons, Windows software-registration and Linux/Windows process snapshot comparisons, same-platform Linux v2/Windows v4 startup snapshot comparisons, and candidate startup correlation exist. General before/after session and selected-root change review plus controlled cross-platform change scenarios remain open. Process/startup snapshots do not establish lifecycle or execution history or prove absence. |
| R6 — Effective access analysis | Partial, intentionally conditional | Linux has a current-calling-thread `faccessat2` probe whose policy conclusion remains unknown; Windows can evaluate a supported local file DACL against a generation-checked process primary token, while the overall result remains conditional. Broad identity- and policy-aware effective-access analysis is not complete. |
| R7 — Queries, cases, reports, and GUI | Partial | Trace-specific optional model query paths, metadata review, and static reports exist. A deterministic cross-session query engine, case files, shared findings model, GUI, and reviewed redaction workflow remain open. |
| R8 — Signed provenance | Partial | Audit sessions support explicit Ed25519 key generation and detached signatures over exact validated `session.json` bytes, with offline verification against a supplied public key. Local trust, revocation, encrypted backup, key import/export workflow, chain links, bundle signing, and broader lifecycle/privacy acceptance remain open. |
| R9 — Optional local-model assistance | Active evaluation; experimental | `model list/show/install/setup/add/select/remove` and task-specific previews/analyses exist, but no catalog candidate passes its quality gate. The current explanation output is selector-only; an additive results-v2 validator and CI contract tests check its structure and diagnostic evidence-label coverage, but do not verify semantic correctness, supplied labels, timing, or backend evidence. The inference runtime is a separate user-managed executable; only the explanation task exposes a product CUDA selector, with no recorded Linux CUDA acceptance. R3-R7 evidence/query/case prerequisites, a GPU/CPU usability review, and an independently reviewed integrated benchmark remain open; no model is approved. R9 implementation and qualification are active under the current project objective. Core SideEffect workflows must remain useful without a local model. |

The short Linux benchmark method is documented in [TRACE_BENCHMARKING.md](TRACE_BENCHMARKING.md); the 10k–1M scale procedure is documented in [TRACE_SCALE_BENCHMARKING.md](TRACE_SCALE_BENCHMARKING.md). WSL2 measurements are not native-Linux or release-performance acceptance. R9 evaluation details and frozen results remain in the task-specific evaluation documents; schema-valid output alone is not evidence of useful analysis.

## Product outcome and boundaries

The intended outcome is an on-demand local audit that helps a user discover software, inspect bounded configuration and access facts, capture selected runtime activity, compare scoped snapshots, and investigate evidence-linked changes. A GUI may make these relationships easier to review, but it must expose the same source scope and uncertainty as the CLI.

Every result must distinguish:

- **Observed:** a collector recorded a specific event or system value.
- **Configured:** a source contains a setting, registration, permission, or startup definition.
- **Derived:** a deterministic transformation, match, comparison, or rule result with links to its inputs.
- **Unknown / not checked / unsupported:** the source was unavailable, outside scope, inaccessible, ambiguous, or not collected.
- **Interpretation:** a human or optional model explanation that does not replace evidence.

SideEffect remains user-triggered and local by default. It is not an always-on monitor, sandbox, malware verdict, complete system inventory, or causal analysis engine. Capture windows, selected paths, sources, and resource limits stay explicit. A lack of an event is never proof that the event did not occur. Correlation, timing, process relationships, and signed records do not prove why an event occurred or that the recorded machine was uncompromised.

Windows and Linux must receive equal product investment and be reviewed against the same user jobs: discover software and startup configuration; inspect bounded permissions and identity context; capture a selected runtime scope; inspect and compare evidence; and export/review a local report. Their collectors and coverage will differ. WSL2 is not native Windows validation. No phase may silently use a Linux result to satisfy the Windows gate or vice versa.

## Delivery rules and shared gates

1. **Preserve raw evidence.** Every parsed event, normalized key, graph edge, finding, and report statement must link to stable source records or source artifacts. Derived records must retain their transformation and uncertainty.
2. **Make collection quality first-class.** Record source/provider versions, scope, interval, privilege context, requested and effective configuration, loss counters where available, truncation, timeouts, parser status, and limits. Distinguish unavailable, not checked, unsupported, inaccessible, and observed-empty sources.
3. **Compare only comparable sessions.** Comparison must consider platform, collector/profile and schema version, scope, source status, time window, identity confidence, and completeness. Partial or mismatched evidence must not create confident removal or absence claims.
4. **Keep configuration, capability, and behavior separate.** Effective-access analysis answers a bounded policy question under a stated identity and policy snapshot. Runtime attempts and results remain independent evidence.
5. **Protect local evidence.** No telemetry, upload, hosted inference, or automatic elevation. User-selected output remains sensitive. Redaction is explicit and reviewable, not a promise that all secrets were found.
6. **Validate both platforms with real sources.** Synthetic fixtures validate parsing and deterministic rules; they do not prove collector compatibility. Platform acceptance requires real supported OS/source runs with recorded prerequisites and explicit tested scope.
7. **Do not overstate an acceptance gate.** Passing a phase proves only its named test envelope. It cannot establish complete OS coverage, safe software, authenticity of original events, or causal certainty.

## Phased milestones

Milestones are ordered by dependency. Work may be split into independently reviewable platform adapters, but each shared capability has a Linux gate and a native Windows gate. No calendar estimates are assigned.

### R0 — Scope, coverage, and event-quality contract

**Purpose:** establish common terminology and comparable confidence reporting before adding more collectors or analysis.

**Work:**

**Implemented partial slice:** `inventory access-check` now has a Linux current-thread non-mutating `faccessat2` probe and a Windows local-file DACL check for a selected process primary token identified by PID plus creation FILETIME. These narrow probes preserve their observed result separately from the overall conclusion. Linux always reports the calculated conclusion as unknown; Windows reports conditional after a supported DACL evaluation. Neither is a complete effective-access verdict.

- Define versioned coverage manifests for inventory, runtime capture, startup, permissions, and snapshots. Include platform/OS build, architecture, collector/provider and version, requested/effective settings, selected scope, interval, privilege context, event-loss/truncation indicators, source status, diagnostics, and unsupported categories.
- Define stable status vocabulary for `observed`, `configured`, `not observed`, `not checked`, `unsupported`, `inaccessible`, `partial`, and `unknown`; document which statuses are source facts and which are derived.
- Specify process-instance identity as more than PID: include observed start time or generation where available, image identity, source and confidence; retain races and reuse as ambiguity. Do not merge process records when identity evidence is insufficient.
- Establish cross-platform event and artifact versioning, provenance links, size/count/time bounds, comparability rules, and migration policy before consumers depend on them.
- Map existing source gaps to explicit future research: IPC and Unix sockets, shared memory, memory mapping, D-Bus/service-mediated operations, scheduled execution, external processes, kernel/module activity, Windows provider/schema variation, and interactions performed by another service on a program's behalf.

**Dependencies:** none; use existing product, architecture, security, and compatibility contracts as constraints.

**Acceptance gate:** a reviewer can identify, for every current source, what is collected, what is not collected, how loss/partial status is represented, what identity is used, and whether two snapshots are comparable. Linux and Windows manifests have documented platform-specific fields and cannot imply equal low-level coverage. Unsupported aspirations remain visible as limitations, not silently dropped.

**Failure gate:** if collector status cannot distinguish missing evidence from observed absence, or a session cannot identify its selected scope and source status, downstream semantic analysis and baselining do not proceed.

### R1 — Collector reliability and broad real validation

**Purpose:** measure and improve what current collectors actually capture before using their output for behavioral conclusions.

**Work:**

- Expand Linux real `strace` validation across the supported version range, distributions/kernels, ordinary and concurrent workloads, threads/children, failures, signals, timeouts, large traces, and relevant process/file/network operations. Measure trace overhead and identify timing perturbation.
- Expand native Windows ETW validation across the supported Windows client/server versions and event provider/schema versions. Exercise provider conflicts, access-denied setup, buffer adjustment/overflow, event loss, stop failures, malformed payloads, and capture-window boundaries. Expose final loss counters and label non-final counters when stop fails.
- Maintain safe, deterministic real-source scenarios on both platforms for process start/exit, file operations, network attempts/results, startup changes, and known unsupported events. Clearly separate generated fixture data from actual captures.
- Research selected additional collection sources by event class and platform. Linux eBPF and audit subsystem adapters are optional future backends, not replacements assumed to be universally available. Evaluate kernel/BTF/verifier compatibility, privileges, event loss, overhead, packaging, and support burden. Research IPC/Unix sockets/shared memory/mmap, D-Bus-mediated work, services and external actors as separate evidence sources. On Windows, assess provider additions only with documented schemas and loss handling.
- Define collector capability profiles and source-specific prerequisites. An unavailable backend must fail or report unavailable before target launch when possible; never auto-elevate.
- Benchmark real workloads at representative event volumes for CPU, memory, throughput, disk/output size, parse time, report time, and loss. Start with 10k/100k/1M-event envelopes where feasible, label workload and host, and set limits from measured data. Do not publish synthetic figures as measured performance.
- Add malformed/oversized/hostile-input test coverage and sustained resource-boundary testing for parsers, decoders, correlators, comparison, and renderers. Add coverage-guided fuzzing for parsers and structured payload decoders where practical, with reproducible corpus and crash triage.

**Dependencies:** R0 coverage/status contract and approved test workload/privacy procedures.

**Acceptance gate:** per-platform reports show tested source/OS/provider/version combinations, reproducible real collector scenarios, measured event-loss behavior, status behavior for partial capture, and overhead/resource measurements. Fuzz/property testing has bounded inputs and actionable crash handling. Unsupported platforms/providers and privilege requirements are documented. This gate validates only those named combinations.

**Failure gate:** unresolved silent loss, failure states presented as empty success, unbounded parsing/collection, inability to reproduce real-capture checks, or unacceptable measured impact pauses dependent features and narrows the supported profile.

### R2 — Software, process, and startup discovery

**Purpose:** broaden bounded inventory beyond one package database or registration family and make identity uncertainty explicit.

**Work:**

- Add opt-in, user-selected discovery roots and adapters rather than an unrestricted whole-disk scan. Candidate sources include OS package managers; Windows software registrations; PATH; running process image paths; Python virtual environments; npm packages; Cargo/Rust installations; AppImage; Flatpak; Snap; and Windows MSIX/AppX registrations. Each source gets its own scope, limits, availability state, and evidence.
- Keep software identity dimensions separate: package/registration identity, product or software ID, version, publisher/signer identity and verification status, install origin, binary path, and cryptographic file hash. A binary hash is not a stable software ID; signer metadata does not authenticate the rest of an audit. Preserve conflicts and one-to-many mappings rather than forcing a single merged identity.
- Extend process snapshots with available start time/generation, executable file identity/hash when safely obtainable, parent relationship source, user/group or token context, integrity/session, and Linux namespace/container facts where supported. Handle exit/reuse races as unknown. PID alone is never a cross-snapshot identity.
- Expand startup source coverage by platform under explicit scopes: Linux systemd manager/runtime/generated/transient and user manager paths, SysV/cron/XDG and distribution-specific sources; Windows Run/RunOnce views, Startup locations, services, scheduled tasks and separately researched persistence registrations such as WMI subscriptions. Keep values inert; do not expand environment variables, shell-parse, or execute them.
- Represent startup in three independent states: **configured** (source entry exists), **effective** (the OS's relevant policy/dependencies indicate enabled/applicable under a captured context), and **observed** (execution was directly observed in a bounded window). `Not observed` does not mean did not run. Unknown effective state is preferred over guessed state.
- Add explicit source-attribution candidates only when a source operation is directly observed and identity/path match rules are qualified. Label temporal or path-based links as candidates and preserve duplicates and ambiguity.

**Dependencies:** R0 source/status and identity contract; R1 validation of existing inventory/runtime inputs; platform source research and privacy review for each new discovery root.

**Acceptance gate:** user-selected discovery returns bounded, evidence-linked rows on Linux and Windows; each adapter reports partial/unavailable/unsupported state; duplicate/conflicting identities remain visible; PID reuse and process races are not silently merged; startup configured/effective/observed states are distinct and tested with real platform examples. No whole-disk scan or all-users claim is implied.

**Failure gate:** inability to bound discovery, ambiguous identities presented as definitive, startup commands executed/interpreted, or untested source claims block release of the affected adapter.

### R3 — Common event model, process relationship graph, and timeline

**Purpose:** let users explore evidence across sources without erasing platform-specific meaning.

**Work:**

- Define a versioned common event envelope for process, file, network, startup, service, permission/configuration, IPC and collector-diagnostic observations. Keep exact platform-specific raw records and typed fields alongside common fields.
- Distinguish attempt, return/result, and higher-level effect. A successful `open` is not proof of content read; a connection attempt is not a completed session; an IP is not a hostname; a file/disk ETW header PID is not automatically the actor.
- Model process instances with start-time/generation evidence and parent/child source, not PID-only nodes. Preserve caller task/thread identity separately from OS parent identity. Graph edges carry type, source references, confidence basis, candidate/confirmed semantics, and time range.
- Build process-to-process, process-to-file, process-to-network, process-to-service/startup, and service-mediated candidate relationships where direct evidence supports them. IPC and delegated service actions remain separate nodes/edges with explicit collection limits.
- Provide a timeline retaining original timestamps/order and capture-local order where available. Concurrent operations may be partially ordered or unordered; do not manufacture a total causal sequence.
- Allow graph and timeline filters by source, process instance, operation, outcome, interval, and evidence status; every rendered node/edge opens its source evidence and diagnostics.

**Dependencies:** R0 identity and event contract; R1 collector-quality metadata; R2 process/software/startup identities for corresponding graph nodes.

**Acceptance gate:** synthetic fixtures cover ambiguous and reused PIDs, thread callers, reordered concurrent events, service-mediated gaps, missing timestamps, and loss. Real Linux and Windows captures demonstrate supported edges for named event classes. Every edge traces to records and its UI wording never asserts causation. Platform fields remain accessible in detail.

**Failure gate:** if graph attribution overstates actor identity or implies unsupported service causality, affected edge types are omitted or clearly labeled candidates.

### R4 — Three-layer diff and comparable behavioral baselines

**Purpose:** move from exact row comparison to explainable behavioral changes without losing raw comparison or creating false certainty.

**Work:**

- Keep three parallel views: (1) raw source/record comparison, (2) normalized comparison with an explicit per-field transformation ledger and before/after values, and (3) semantic grouping such as process start, file attempt/result, network attempt/result, startup configuration change, or installation change. Each view links to the same immutable source evidence.
- Keep PID and timestamp prefix handling distinct from PID-like values embedded in arguments. Use process-instance identity with start time/generation only when evidence supports it. Never normalize all paths or all temporary-looking values.
- Resolve file descriptor identity only through observed lifecycle evidence in the same run and with bounded tracking. Numeric FD equality or difference alone must not be suppressed. Handle close, reuse, dup, inherited descriptors, and `-yy` annotations explicitly; unresolved descriptor targets stay distinct/unknown.
- Compare event multisets where ordering is not a semantic property, while preserving event order/time and using partial-order or sequence evidence only for operations whose ordering is meaningful. Surface ambiguous repeated matches rather than pairing arbitrarily. Keep unfinished/resumed call representation policy explicit and evidence-linked.
- Define semantic rules as deterministic, versioned, testable transformations with separate severity and evidence confidence. Examples include new sensitive-path attempt, new child process, changed endpoint, new startup entry, and changed persistence configuration. Rules describe observed changes, not malware or safety.
- Introduce baselines only after R0/R1/R3 and the comparability contract. A profile stores source coverage, platform, software/binary identity, version/signer facts, scope, collector profile, time window, completeness, and contributing sessions. Users review and explicitly approve baseline inputs; a first or partial run cannot silently become trusted normal behavior.
- Detect contamination and drift: flag baseline inputs with partial/lost capture, changed software identity, incompatible scopes, collector/schema changes, suspicious/unreviewed findings, or divergent behavior. Permit quarantine/rebuild; never automatically absorb a candidate into the trusted baseline. Explain limited sample counts and baseline age.
- Show baseline deviation as “different from these reviewed observations,” not an anomaly verdict. Deterministic anomaly rules run only on comparable evidence and expose the rule/version, threshold, evidence and limits. Machine learning is not required.

**Dependencies:** R0 comparability rules; R1 validated capture status; R3 common model and identities. Baselines depend on stable raw references and review workflow.

**Acceptance gate:** test dynamic paths without blanket normalization, FD lifecycle/reuse, PID generation, duplicate events, reordered concurrent operations, partial/lost runs, incompatible scopes, changed binaries/signers, contaminated baselines, and ambiguous matching. Demonstrate raw, normalized and semantic results side-by-side. Removed/absent claims require comparable complete source coverage; otherwise return unknown or candidate change.

**Failure gate:** any untraceable normalization, silent baseline contamination, partial-run removal claim, or false match that cannot be bounded blocks semantic/baseline release.

### R5 — Scoped installation and persistence change intelligence

**Purpose:** compare before/after system snapshots around a user-selected install, update, or run, within a declared set of observable sources.

**Work:**

- Add explicit before/after snapshot sessions for selected roots and supported inventory sources. Include file identity/metadata and optional content hashes where chosen, software registrations, process and startup configuration, services, scheduled tasks, and supported security/firewall/environment configuration sources only after separate scope and privacy review.
- Add a user-triggered bounded observation window around an installer or selected command when the user explicitly consents. Preserve separate snapshots and runtime evidence; do not label temporal changes as caused by the selected program without direct operation evidence.
- Correlate new/changed/removed files, services, startup entries, tasks and software registrations to observed actor operations when exact evidence and process identity permit. Otherwise label a time/path/source candidate or leave unattributed.
- Show persistence mechanisms as configured/effective/observed, with installer association separate from later execution evidence.
- Handle sources that mutate during collection as non-atomic and partial. A scoped snapshot is not a filesystem journal or guarantee that every transient change was captured.

**Dependencies:** R2 expanded inventories and startup state; R3 event/identity graph; R4 comparable snapshot and evidence-link semantics.

**Acceptance gate:** real controlled install/update scenarios on Linux and Windows produce expected source changes and known limitations; synthetic tests cover create/modify/delete, transient changes, inaccessible sources, race conditions, partial snapshots and ambiguous actor links. Reports distinguish observed operation, before/after difference, candidate association, and unsupported source.

**Failure gate:** if the product cannot tell a direct operation from temporal proximity or cannot surface snapshot races and blind spots, use neutral change summaries without causal wording.

### R6 — Bounded effective-access analysis

**Purpose:** answer constrained “could this identity access this selected resource under these observed policy inputs?” questions without confusing them with runtime behavior.

**Work:**

- Define a query requiring a selected process/software identity, resource/path, operation, and evaluation context. Capture or accept the applicable token/credential and policy snapshot; do not claim machine-wide permission enumeration.
- Linux evaluation research and staged support: UID/GID and supplementary groups, mode bits, POSIX ACLs, capabilities, user/mount namespaces, mount flags, SELinux, AppArmor, and seccomp. Track each input source and mark unsupported or unenforced policy as unevaluated. Avoid a single “allowed” answer if relevant policy is missing.
- Resolve ancestor-directory traversal permissions and symlink/path-resolution context under the selected process identity. Preserve final/intermediate component policy and mount/namespace context. If path resolution or policy context is ambiguous, return conditional/unknown rather than evaluating only the final object's mode bits.
- Windows evaluation research and staged support: access token user/groups/restricted SIDs/privileges, DACL deny/allow ordering, integrity/MIC, service identity, and relevant filesystem/object policy. SACLs and protected scopes require explicit privacy/privilege review and are not collected by default.
- Keep a three-part result: observed attempt/result, configured permission facts, and calculated access conclusion with evaluated inputs and omitted policy. If inputs are incomplete, say conditional/unknown rather than allowed/denied.
- Test against native OS access-check APIs or controlled fixtures where available, including deny rules, group membership, inheritance, namespaces/containers, service accounts and policy restrictions.

**Dependencies:** R0 status/identity contract; R2 process/token facts; R1 platform validation. This is independent of behavioral baselines but depends on a narrowly defined policy evaluation scope.

**Acceptance gate:** Linux and Windows evaluations match their documented oracle cases for fully supported policy subsets; every result names evaluated and unevaluated controls and the exact identity/context; runtime observed access remains a separate field. No broad “all files this app can access” claim is allowed.

**Failure gate:** if relevant policy cannot be enumerated or results cannot be validated against OS behavior, keep the feature as selected-path configuration evidence and return unknown for effective access.

### R7 — Investigation queries, case files, reports, and GUI

**Purpose:** make evidence practical to investigate and review while retaining an offline, inspectable workflow.

**Work:**

- Design a local query engine over versioned event/session records. Compare a constrained typed-filter design with a restricted SQL-like interface, potentially backed by SQLite, before choosing the smallest maintainable option. Whichever design is selected must be read-only, schema-aware, parameterized, allowlisted, and bounded by query time, rows, memory and output quotas. Support event category, process identity, path, endpoint, result, source, time and evidence state; provide saved query definitions and reject unsupported syntax. A query must not execute commands or mutate system state.
- Add investigation cases that group sessions, questions, evidence references, findings, analyst notes and status. Cases store copied or referenced evidence according to a documented retention policy; they do not silently alter raw captures.
- Provide technical, analyst/security, and concise summary reports from the same structured findings. Each assertion carries evidence references, source scope, severity separate from confidence, and unresolved questions. The concise report must not hide incomplete capture or source limitations.
- Implement a local GUI or static interactive report only after the event/query contracts stabilize. Prioritize process graph, timeline, file/network activity, startup/configuration changes, permissions/access, coverage/diagnostics, baseline comparison, and evidence drilldown. Include keyboard/accessibility and large-data performance review.
- Keep reports offline with no scripts that evaluate evidence or make network requests. If a richer local GUI uses active code, apply the same untrusted-input and local-data threat model and security review.
- Add optional shareable-report redaction controls with preview, explicit selected fields/rules, reversible local source preservation, and “redacted/omitted/unknown” markers. Run deterministic tests for paths, usernames, endpoints, command args, credentials, Unicode confusables and HTML injection. Redaction cannot guarantee removal of undiscovered secrets; the user reviews the output before sharing.
- Treat cases, query history, report outputs and graph databases as sensitive local evidence with user-controlled retention/deletion and bounded storage. No background watcher is introduced.

**Dependencies:** R3 model and evidence links; R4 semantic/baseline schemas; R5 snapshots and R6 access result as those panels are added. A small initial query/report can precede all analysis features, but cannot claim missing categories.

**Acceptance gate:** GUI/query/case/report workflows are fully usable offline on both platforms, bounded on large and hostile inputs, keyboard accessible, and every derived item drills down to raw evidence. Test injection, malformed schemas, output limits, interrupted writes, retention/deletion, redaction false negatives and export scope. User study/review should establish that “unknown,” “not observed,” and “candidate” are understandable, without claiming user comprehension as proof of technical correctness.

**Failure gate:** unsafe rendering, uncontrolled network access, report claims without evidence, unreviewable redaction, or unbounded local case storage blocks sharing/export release.

### R8 — Signed provenance manifests and key lifecycle

**Purpose:** improve tamper evidence and chain-of-custody metadata while stating exactly what a signature can and cannot prove.

**Work:**

- Design a canonical, versioned manifest that binds session ID, platform/host facts selected by the user, collector and schema versions, source scopes and intervals, requested/effective settings, privilege context, artifact names/lengths/hashes, diagnostics, partial/loss state, and parent/related session IDs. Do not place command arguments, personal paths, or raw environment values in the manifest by default.
- Add optional signature over canonical manifest bytes or a manifest digest, with a local key identifier and algorithm. Support user-controlled key creation/import/export/rotation/revocation and backup guidance; never silently create a cloud identity or upload keys.
- Define signing-time and trust semantics. A local clock is not a trusted timestamp. A valid signature shows that a key signed those manifest bytes and that signed bytes have not changed since; it does not show that the collector was honest, the host uncompromised, the event happened, the capture was complete, or the signer is a specific human absent a separately verified key binding.
- Evaluate optional previous-manifest digest links for a user-selected session sequence to make reordering or removal detectable within that sequence. Define reset, fork, missing-link and privacy/equality-leak behavior. A hash chain is not tamper-proof storage and cannot prevent deletion or prove collection truth.
- Review Ed25519 as a candidate signing algorithm, including a vetted implementation, key format/storage, rotation/revocation and interoperability. Select it only after review; algorithm choice alone does not establish trustworthy key custody.
- Make unsigned, signature missing, unknown key, invalid signature, and valid signature distinct states. Verification must work offline. Preserve artifact hashes as byte-integrity checks independent of signature verification.
- Review metadata minimization and equality leakage: hashes/session links and host metadata can identify repeat captures. Offer privacy-minimized manifest fields and user preview before signing.

**Dependencies:** R0 artifact/source contract and R7 case/session workflows. Best introduced before external case exchange, but local audit workflows remain useful unsigned.

**Acceptance gate:** canonicalization, signature verification, tampering, unknown/rotated keys, malformed manifests, privacy fields, offline verification, and key-loss cases are tested. Documentation and UI use narrow integrity wording and never equate signature with authenticity/completeness of underlying events.

**Failure gate:** key custody or canonicalization is ambiguous, signed scope omits important diagnostics, or UI overstates trust; retain hashes only until resolved.

### R9 — Optional AI investigation evaluation and implementation

**Status:** active under the current project objective; experimental and not release-approved. No model is approved, and core product workflows do not depend on one. Continue implementation only behind the deterministic evidence, privacy, security, resource, and quality gates below.

**Purpose:** evaluate whether an optional local model can help a user navigate already validated evidence without becoming a collector, fact source, or required runtime.

**Prerequisites and evaluation:**

- Complete and qualify deterministic event normalization, query, evidence references, privacy controls, and coverage reporting first. Models may only consume user-selected, bounded structured evidence; they cannot create evidence IDs, run shell/commands, alter settings, capture more data, or replace source inspection.
- Create a versioned, representative benchmark with reviewed ground truth across ordinary and unusual file/network/process/startup behavior, failures, false associations, changed software identity, baseline contamination, incomplete/lost captures, unsupported sources, misleading names, malformed evidence and prompt-injection text in paths, arguments, startup values and imported artifacts.
- Score evidence selection precision/recall, citation validity, unsupported claim rate, uncertainty handling, query translation correctness, refusal behavior, privacy leakage, latency and resource use. Include adversarial and red-team review; report model/runtime/version, quantization, hardware and sample limits. No fabricated “500 case” threshold or accuracy claim is assumed; maintainers must justify the benchmark size and acceptance bounds before a model can pass.
- Compare against deterministic query and explanation baselines. A model must show meaningful user benefit with an acceptable error profile before packaging/integration is considered. Any failed quality gate leaves the feature experimental/deferred and does not block the core product.
- Once R3–R7 deterministic data and privacy prerequisites are ready, implement natural-language-to-query that emits only a validated read-only query. Show the query, scope, data sources and resource limits for user review before execution; ambiguous or unsupported questions abstain. Natural-language interpretation never runs shell commands or broadens collection scope.
- Add evidence-linked graph/diff explanations, technical report drafting and follow-up questions inside a user-selected case. Outputs may summarize evidence already in scope, cite only existing IDs, state uncertainty and open cited records; they cannot invent findings or cause.
- Complete model lifecycle UX: inspect pinned model/runtime identity, source, revision, size, license and evaluation status; user-confirmed install/download; per-task selection; preview/remove registration; and user-controlled update to a new pinned revision. Never auto-download or silently replace model files. Analysis remains optional and works with no model installed.
- Existing `model setup` already guides a user through pinned model download, typed license acceptance, hash verification, and per-task selection, but runtime acquisition/configuration remains separate and each inference command needs a runtime path and preview digest. Improve this flow without removing license consent, integrity checks, or the unqualified-quality warning.
- Evaluate optional CPU and GPU execution with a clearly reported backend and bounded host-resource behavior for each task and platform. The current CUDA selector is exposed by the explanation task; evidence selection and query planning remain CPU-only. A CUDA device listed by a runtime and a positive offload log are separate evidence from measured GPU memory or performance. Record real Linux/WSL and native Windows acceptance separately. GPU-to-CPU fallback may occur only under an explicit policy and must be visible; neither backend is sandboxed by default, and platform support is separately qualified. Core SideEffect must not depend on either backend.
- Prefer local inference only if the user explicitly selects and trusts runtime/model. No automatic weight downloads, hosted API, telemetry, or implicit evidence transfer. Model/runtime and libraries are executable dependencies, not sandboxed by default. Any future hosted option requires a separate explicit product/security/privacy review and user decision.
- Treat all evidence as untrusted data, delimit it from instructions, prevent prompt injection from changing tool behavior, and constrain output to validated structured claims or navigation suggestions. Every output must cite existing evidence IDs and preserve source facts, unknowns, and conflict status. The model cannot decide “safe,” “malicious,” root cause, or effective access.
- Agent Skills remain an orchestration interface under the user's chosen agent/provider. Their documentation must warn that provider handling is controlled by that agent configuration, preserve user-confirmed runtime scope, and prevent evidence text from authorizing new actions. A user-selected agent/model is not a SideEffect core dependency.

**Dependencies:** R3–R7 deterministic data and privacy controls; an approved benchmark protocol. Do not claim the integrated assistant or approve a model until these prerequisites are established.

**Acceptance gate:** independently reviewed benchmark and privacy threat model; reproducible task-specific results; verified evidence references; no unsupported factual or safety claims; user-visible model/runtime/data-flow consent; test coverage for injection and refusal; clear opt-out and no model-required CLI path. Results qualify only that named model/runtime/task.

**Failure gate:** any material fabricated fact, evidence reference not present in the request, injection-driven action, undisclosed data transfer, or failure to outperform the deterministic baseline keeps the feature experimental and not release-approved.

## Cross-phase release gates

The core product may advance without all future aspirations, but it must not be described as the complete system-behavior platform until the selected release scope passes all applicable gates below:

- **Platform parity:** Linux and native Windows each support the advertised end-to-end workflow with independent real-source acceptance. Document different event and permission semantics; do not claim identical coverage.
- **Evidence integrity:** every derived comparison, graph edge, baseline deviation, access result, case finding and report assertion traces to exact source evidence and a transformation/rule version.
- **Comparability:** mismatched or partial captures result in unknown/candidate comparisons, not confident absence/removal.
- **Data safety:** bounded hostile-input handling, inert rendering, private/no-clobber output, local-only defaults, sensitive-data warnings, reviewed redaction and retention controls.
- **Collector quality:** real platform tests, observable event-loss diagnostics, compatibility records, measured overhead and documented prerequisites for each promoted backend.
- **User interpretation:** distinguish observed fact, configured fact, calculated result, derived comparison, candidate association and optional interpretation in CLI and GUI/report views.
- **Honest claims:** no completeness, safety, authenticity, or causal claim exceeds what the named source and validation can support.

An unpassed gate narrows the supported feature/platform claim; it does not authorize guessing, hiding uncertainty, or silently treating unsupported data as empty.

## Critique traceability matrix

Status describes the coverage in current repository documentation as reviewed for this plan, not a fresh implementation audit. **Existing** means documented as implemented/tested for a bounded scope; **Partial** means a narrow implementation or plan exists but does not meet the critique's broader proposal; **Missing** means no matching capability is documented; **Explicit limitation** means the gap is deliberately stated and not promised. Roadmap IDs point to the milestones above.

### `se.txt` section and subsection coverage

| Critique section | Topic / subtopic | Current documented status | Roadmap coverage |
|---|---|---|---|
| 1 | Observation is not total system behavior; observed / not observed / not covered distinctions | Partial; source-specific bounded scopes and unknowns exist, but broad cross-source coverage manifest is incomplete | R0, R1; product boundaries |
| 1 | Kernel, IPC, Unix sockets, shared memory, mmap, modules, D-Bus, scheduled and external/service-mediated work | Explicit limitation; these sources are not generally captured or correlated | R0 research register, R1 backend/source research, R3 graph |
| 1 | Coverage manifest and per-platform source limits | Partial; schemas expose source statuses and some capture diagnostics, not a unified coverage report for all ambitions | R0, R1, R7 |
| 2 | strace performance/timing perturbation, scope, privilege/process boundaries, trace volume | Partial; bounded Linux child tracing exists; broad overhead/compatibility/loss validation remains incomplete | R1 |
| 2 Linux proposal | strace basic, optional eBPF and audit collectors; compatibility, privilege and support burden | Missing as promoted collectors; current backend is external strace | R1 |
| 2 Windows | ETW provider/schema/version differences, privilege, buffer loss and attribution limits | Partial; bounded ETW and loss handling are documented, but broader version/provider matrix remains limited | R1, R3 |
| 2 Windows session fields | Start/end, provider list, loss, overflow, privilege, disabled collectors, unsupported categories | Partial; some fields and diagnostics exist, but a unified coverage manifest remains future work | R0, R1 |
| 3 | Diff's run-local IDs, dynamic values, path normalization risk | Partial; exact comparison is conservative, semantic/path normalization is not implemented | R4 |
| 3.1 | Dynamic temporary values versus sensitive path changes | Explicit limitation of exact matcher; no generalized safe normalizer | R4 |
| 3.2 | File descriptor numbers differ; resolve FD to target only with evidence | Explicit limitation; FD identity is not tracked as a normalization identity | R4 |
| 3.3 | Concurrency, event order, race semantics | Partial; multiset diff exists; raw order retained, semantic partial ordering is future work | R4 |
| 3 recommendations | Raw / normalized / semantic diff layers and explainable transformations | Partial; raw multiset diff only | R4 |
| 4 | Package, process, startup inventories are bounded and incomplete | Partial; Linux/Windows slices documented with limitations | R2 |
| 4.1 | Portable, user-installed and ecosystem software omitted by package/registry sources | Explicit limitation | R2 |
| 4.1 discovery table | Package managers, filesystem roots, PATH, registry, process image paths, manifests | Partial; package/registry/process sources exist; bounded discovery-root engine does not | R2 |
| 4.1 software identity | software ID, origin, version, publisher, signature status, binary paths | Partial; source-specific package/registration identities exist; reconciled identity and signer dimensions do not | R2, R8 (manifest identity only where selected) |
| 4.2 | Process snapshot races and PID reuse | Partial; current Windows non-atomicity and Linux scoped walk are documented; generation-safe cross-snapshot identity is absent | R0, R2, R3, R4 |
| 4.2 identity details | Start time, image fingerprint, parent source, UID/GID/token, integrity, session, namespaces/container | Partial; some source fields exist, but not a unified identity/context view | R2, R3 |
| 4.3 | Startup configured entry does not prove execution/effectiveness | Explicit limitation and already documented distinction between configuration and execution | R2, R5 |
| 4.3 analysis states | Configured / effective / observed states | Partial; configured inventory and narrow observed candidates exist; effective state is not calculated | R2, R5, R6 |
| 5 | Selected-path permission facts do not equal effective access | Explicit limitation; no effective-access calculation | R6 |
| 5 Linux | ACL/groups, parent traversal, SELinux/AppArmor, namespaces, capabilities | Partial; selected path metadata/ACL/capability evidence exists; integrated evaluation is missing | R6 |
| 5 Windows | Token/groups, deny ACE, integrity and other policy effects | Partial; selected-path owner/group/DACL facts exist; effective token-aware evaluation is missing | R6 |
| 6 | Hash checks byte identity, not source authenticity | Explicit limitation; current hashes are not signatures/authentication | R8 |
| 6 provenance manifest | Evidence ID, source, collector/OS, interval, privilege, settings, hashes, diagnostics, parent session | Partial; bundles and audit sessions carry bounded metadata, not the proposed signed provenance package/key lifecycle | R0, R8 |
| 6 signatures | Ed25519/signing key ID/time/hash links; limits of signature claims | Missing; signatures are not established as implemented | R8 |
| 7 | AI can help but cannot be evidence or security authority | Partial; optional local model is experimental and unqualified; core deterministic path exists | R9 (active evaluation) |
| 7.1 | Prompt injection in paths, args, process names and reports; provider privacy | Partial; untrusted input and Agent Skill boundaries are documented; investigation workflow needs benchmarked adversarial controls | R7, R9 |
| 7.1 layered design | collectors → deterministic analysis → structured findings → AI interpretation → human review | Partial; components exist separately but full bounded investigation interface does not | R3–R7, R9 |
| 7.1 evidence IDs | Model restricted to supplied evidence IDs and user remains decision maker | Partial; existing model tasks validate selected IDs within bounded requests; no approved quality claim | R9 |
| 7.2 | Local model currently experimental; usefulness benchmark before expansion | Explicit limitation; implementation/evaluation active, no model release-approved | R9 |
| 7.2 benchmark scenarios | Normal/suspicious, failed operation, misleading names, incomplete capture, similar traces, injection | Missing as a broad reviewed benchmark | R9 |
| 8 | Self-security architecture: local, no auto-elevation, safe output, bounded input | Partial/existing for documented commands; broader future collectors/UI need equivalent review | R1, R7, cross-phase gates |
| 8.1 | Long lines, invalid UTF-8, controls, numbers, continuations, contradictions, HTML injection, fuzzing | Partial; bounds and selected tests exist; broad fuzzing and hostile-schema coverage remain future work | R1, R7 |
| 8.2 | 10k/100k/1M events, many children, high-rate workloads, RAM/CPU and truncation | Partial; configured limits exist, broad real workload benchmarks are not established | R1 |
| 8.3 | Full-evidence vs shareable report, path/endpoint/argument/token sensitivity | Partial; outputs are local and sensitive; aggregate diff summary is not secret detection; explicit redaction workflow is absent | R7 |
| 9 | Audience needs differ; developer, researcher, desktop user, admin, responder | Partial; product user groups are documented, role-specific investigation workflow is not | R7 |
| 9 target audience | Stage advanced review then approachable UX without overstating | Partial | R7 |
| 9 GUI | Graph, file/network, startup, access, timeline, coverage and evidence drilldown | Missing as an integrated GUI; static HTML exists for bounded reports | R7 |
| 10 | Preserve CLI/evidence architecture while evolving into discover-observe-correlate-analyze-investigate-explain | Partial; CLI foundation and some correlation exist | R2–R7 |
| 10.1 | Cross-platform real collector validation and performance measurements | Partial; narrow real Linux and hosted Windows evidence exists; broad matrix/benchmarks remain open | R1 |
| 10.2 | Unified event model with common concepts and native fields | Partial; platform schemas exist; investigation-wide common model is missing | R3 |
| 10.2 graph | Process/process-file/network/service/startup graph, typed evidence-linked edges, DNS honesty | Partial; narrow process relations and ETW attribution candidates exist; integrated graph absent | R3 |
| 10.3 | Timeline with source-linked events and outcome distinctions | Partial; timestamps/source records exist in individual schemas; integrated timeline absent | R3, R7 |
| 10.3 baselines | Repeat-run profile and deviations without security verdict | Missing as a persistent reviewed baseline | R4 |
| 10.3 deterministic anomalies | New executable, sensitive path, startup/service, child process, endpoint, self-change; separate severity/confidence | Missing as a qualified rule engine | R4 |
| 10.3 profiles | Application-type context; first-run contamination caution | Missing; contamination controls are explicitly planned | R4 |
| 10.4 effective permission | Linux identity, ACL, MAC, namespace, mount and seccomp policy | Partial facts; evaluator missing | R6 |
| 10.4 effective permission | Windows tokens, SIDs, DACL/SACL, MIC, restricted tokens, privileges, service accounts | Partial selected-path DACL; evaluator missing; SACL not collected by default | R6 |
| 10.4 access graph | Identity + evaluated allow/deny/conditional + omitted controls | Missing | R6, R7 |
| 10.5 system change intelligence | Before/after files, registrations, services, startup, task, firewall/env and scoped install diff | Partial; same-platform Linux startup v2 and Windows startup v4 snapshot comparison is implemented, while files, broad session comparison, cross-source attribution, and install inference remain open | R5 |
| 10.5 persistence attribution | Direct observed creator vs temporal/path candidate; configured vs execution | Partial exact-path startup candidate support; causal attribution intentionally not claimed | R2, R3, R5 |
| 10.6 query engine | Read-only structured/SQL-like search over events and relationships | Missing as a general investigation query engine | R7 |
| 10.6 cases | Saved scope, evidence, findings and investigation status | Missing | R7 |
| 10.6 reports | Technical, security/analyst and executive views from evidence-linked facts | Partial static HTML and deterministic summaries exist; role-specific report set missing | R7 |
| 10.7 AI assistant | Natural language query, explanation and report only after deterministic engine | Experimental task-specific plumbing exists; no general approved assistant | R9 active, gated by R3–R7 |
| 11 | Priority order and acceptance before expanding analysis | Partial; existing milestones are gated, comprehensive future gates are now proposed | R0–R9 |
| 12 | Local evidence-based software behavior product, not AV/EDR/SIEM/sandbox | Existing product boundary; future broader platform is bounded and not complete coverage | Product boundaries; R0–R9 |
| 12 questions 1–10 | Origin, files, children, endpoints, access, startup, changes, diffs, deviations, evidence | Partial across separate bounded commands; integrated answers vary by current source scope | R2–R7; unknowns stay explicit |
| 13 strengths | Rust, platform collectors, evidence-first, diff, offline, Agent Skill | Existing for documented scopes; not widened by this roadmap | Preserve; R0–R9 gates |
| 13 weaknesses | Coverage, semantics, software breadth, startup effectiveness, effective access, anomaly engine, validation | Partial or explicit limitation as listed above | R1–R6 |
| 13 top investments | Process graph; baseline/semantic diff; system change intelligence | Missing as integrated capabilities | R3, R4, R5 |

### `se özet.txt` coverage

| Summary item | Current documented status | Roadmap coverage |
|---|---|---|
| Complete system behavior is not observable | Explicit product limitation; no total coverage claim | R0, R1, product boundaries |
| Diff does not sufficiently interpret behavior | Partial exact-row diff; semantic layer missing | R4 |
| Real/effective software access is not fully calculated | Explicit limitation; selected-path facts exist | R6 |
| Startup registration does not always show whether it runs | Explicit limitation; effective state missing | R2, R5 |
| Anomaly and behavioral analysis need development | Missing as qualified baseline/rule engine | R4 |
| Collector reliability needs broader tests | Partial narrow acceptance; broad matrix and benchmarks missing | R1 |
| Process Relationship Graph | Missing as integrated graph | R3, R7 |
| Behavioral Baseline | Missing as reviewed persistent profile | R4 |
| Semantic Diff | Missing beyond raw multiset matching | R4 |
| Anomaly Detection | Missing as deterministic qualified findings | R4 |
| System Change Intelligence | Partial source inventories, no scoped cross-source install diff | R5 |
| Effective Access Analyzer | Missing beyond selected-path facts | R6 |
| Investigation Engine | Missing general query/case/report engine | R7 |
| AI Investigation Assistant | Active evaluation; experimental, no model release-approved | R9 |
| Top three: baseline, semantic diff, system change intelligence | Not integrated; prioritized after reliability and event/identity foundations | R1 → R3 → R4/R5 |

## Relationship to existing planning documents

`PLAN.md` remains the historical and current implementation record for M0–M13 and release status. This document adds work after those bounded milestones; it does not rewrite acceptance already met, silently upgrade claims, or replace the compatibility matrix. Update this roadmap's status and the relevant source documentation as each milestone is implemented and validated. R9 and further M8/local-model work are active under the current project objective, remain experimental and optional, and must preserve the quality, privacy, security, and core-independence gates defined above.
