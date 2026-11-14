# Reviewed behavioral baselines

SideEffect can save a small, explicitly reviewed set of verified audit sessions
as a local behavioral baseline profile, then compare later candidate sessions
against it. The profile is a review record over observations, not a security
verdict, an inventory of all software, or proof that the reviewed host was
uncompromised.

## Preview and approval

```
sideeffect baseline preview --label "workstation before update" \
  --session SESSION_DIR [--session SESSION_DIR...]
```

The command reads each session through the native verified reader, rejects
duplicate session IDs, and prints a bounded `sideeffect.baseline_preview` v1
document. The preview contains:

- session IDs and exact `session.json` SHA-256 digests;
- platform, architecture, and session intervals;
- declared source coverage, preserving unknown coverage as unknown;
- metadata comparability reason codes between all unordered session pairs;
- a promotion decision derived from verified manifest evidence: partial
  sessions, non-complete sources, and reported or unknown runtime loss block
  promotion while remaining visible as diagnostics; and
- a deterministic `sha256` over the label, manifest digests, coverage,
  comparability, and promotion decision.

Previewing the same verified inputs produces the same digest. Changing a
manifest, its bytes, the label, or declared coverage changes the digest.

## Create a protected profile

```
sideeffect baseline create --profile NEW_PROFILE.json \
  --label "workstation before update" \
  --confirm-sha256 PREVIEW_SHA256 \
  --session SESSION_DIR [--session SESSION_DIR...]
```

Creation recomputes the preview and requires the exact lowercase digest printed
by preview. A mismatch writes nothing. Partial, incomplete, or loss-affected
inputs also write nothing: `create` returns `PromotionBlocked` with stable
reason codes such as `session_partial`, `source_incomplete`,
`runtime_loss_reported`, or `runtime_loss_unknown`. The preview still preserves
their coverage as unknown or partial so the user can inspect why promotion was
refused. The profile is serialized as
`sideeffect.behavioral_baseline` v1 and published with the platform's protected
current-user writer using no-replacement semantics. Linux uses owner-only file
mode; native Windows uses a current-user-only DACL and `CREATE_NEW`. An existing
file, symlink, or reparse-point destination is never replaced.

A profile records the reviewed sessions, coverage, comparability summary,
review timestamp, and approval mode. It explicitly records
`software_identity: not_recorded` and `signer_identity: not_recorded`. It does
not establish software authorship, signer identity, or trusted behavior.

Limits: 1 through 16 sessions, a 128-byte label, a 1 MiB profile, and an 8 MiB
serialized comparison output. Each baseline operation reserves artifact bytes
across all supplied verified sessions against a 64 MiB aggregate read budget.
Each artifact's declared length is reserved before it is opened and also caps
the actual read. Labels reject control characters.

## Compare a candidate

```
sideeffect baseline compare --profile PROFILE.json \
  --baseline-session SESSION_DIR [--baseline-session SESSION_DIR...] \
  --session CANDIDATE_SESSION_DIR [--session CANDIDATE_SESSION_DIR...]
```

The exact reviewed baseline sessions must be supplied. Before any item
comparison, the command verifies that:

- every approved session is present exactly once;
- no additional baseline session is supplied;
- each supplied session ID matches an approved session; and
- each exact manifest SHA-256 matches the approved digest.

A missing, added, or byte-changed baseline session produces
`status: refused_contaminated_baseline`, the `baseline_manifest_changed`
error diagnostic, no item comparisons, and exit status 2. This prevents a
replaced baseline directory from silently becoming the trusted reference.

Creation and comparison both use verified manifest evidence. A contaminated
comparison refuses item deltas before producing a result, and a partial or
loss-affected input is never promoted into the reviewed baseline.

When the baseline is verified, the command uses the existing
`sideeffect.audit_session_diff` item comparison for each baseline/candidate
pair. Each pair retains verified artifact paths, schemas, digests, native
comparator counts, and evidence-linked deltas. Metadata incompatibility reason
codes also remain visible.

## Drift, coverage, and absorption

`deviation: different_from_reviewed_observations` means at least one item
comparison reported a difference. It is not an anomaly or safety verdict, and
it does not prove causation. `no_item_differences_reported` covers only the
selected verified sources and does not prove that no system change occurred.

Any reviewed or candidate source with `partial`, `unknown`, `not_checked`,
`inaccessible`, or `unsupported` coverage is listed in `coverage_gaps`.
Whenever gaps exist, `removal_claims_withheld` is true and the comparison emits
`incomplete_coverage_removal_withheld`. Consumers must not turn one-sided rows
or empty source comparisons into confident removal or absence claims. Nested
native item diffs also have their removal rows and counters suppressed for any
role with incomplete or unknown session coverage. Metadata-incompatible pairs
may retain item-level evidence for inspection, but do not contribute to the
baseline drift classification.

A candidate is never added to the profile. Every comparison reports
`automatic_absorption: false` and the `automatic_absorption_refused`
diagnostic. Creating a new reviewed baseline is a separate, explicit workflow.
Baseline age, sample count, collector/schema changes, and host-context changes
remain visible through the supplied sessions and comparison diagnostics.

## Exit status and limits

Comparison exits 0 only when metadata is comparable and item comparison is
complete with no coverage gaps. Partial, incomparable, or contaminated
comparisons exit 2. Invalid input exits 1.

This slice covers reviewed baselines over existing verified session artifacts.
Broader semantic baselines, automatic quarantine/rebuild workflows, qualified
anomaly rules, baseline age policy, and the full R4 exit review remain open.

Synthetic fixtures in `tests/baseline_cli.rs` exercise digest mismatch,
no-replacement creation, contamination refusal, evidence-linked drift,
automatic-absorption refusal, and unknown-coverage withholding. They are
synthetic test sessions, not real captures.
