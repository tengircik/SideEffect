//! Bounded deterministic summaries of parsed trace evidence and trace diffs.
//!
//! The summaries intentionally omit raw arguments, result text, command output,
//! fingerprints, source strings, and diagnostic messages. Evidence references
//! remain exact offsets into their corresponding source document.

use serde::Serialize;

use crate::model::{
    CaptureCompleteness, DeltaKind, EventCategory, ObservedDelta, ParseCompleteness,
    SyscallOutcome, TraceDiff, TraceDocument, TraceRecordKind,
};
use crate::trace::process_tree::ProcessRelation;

/// Maximum number of per-row facts retained by a trace explanation.
pub const MAX_EXPLANATION_FACTS: usize = 1_024;
/// Maximum number of changes retained by a diff explanation.
pub const MAX_EXPLANATION_CHANGES: usize = 1_024;
/// Maximum total exact evidence references included in one explanation.
pub const MAX_EXPLANATION_REFERENCES: usize = 4_096;
/// Independently bound iteration for caller-constructed documents/diffs.
pub const MAX_EXPLANATION_INPUT_ROWS: usize = 200_000;

const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureContext {
    /// Raw trace and legacy sources do not include capture stop metadata.
    NotProvided,
    /// Capture metadata was present; its free-form values are deliberately omitted.
    MetadataPresent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStopReason {
    TracerExited,
    TimeLimitReached,
    Unknown,
    NotProvided,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KnownUnknown {
    CaptureCompletenessUnknown,
    PartialParse,
    ProcessRelationsPartial,
    TraceRecordsOmittedByLimit,
    ResultFactsOmittedByLimit,
    ProcessRelationsOmittedByLimit,
    CaptureStoppedByTimeLimit,
    DiffChangesOmittedByLimit,
    EvidenceReferencesOmittedByLimit,
    DiffInputRowsOmittedByLimit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TraceExplanation {
    pub schema_version: u32,
    pub parse_status: ParseCompleteness,
    /// Parsing is not a capture completeness check; this is always unknown.
    pub capture_completeness: CaptureCompleteness,
    pub capture_context: CaptureContext,
    pub capture_stop_reason: CaptureStopReason,
    pub requested_time_limit_present: bool,
    pub scanned_record_count: usize,
    pub record_counts: RecordKindCounts,
    pub selected_syscall_rows_without_outcome: usize,
    /// One evidence-linked fact for each retained supported result row.
    pub result_facts: Vec<SyscallResultFact>,
    pub omitted_result_fact_count: usize,
    pub process_relations: Vec<ProcessRelationFact>,
    pub omitted_process_relation_count: usize,
    pub parser_diagnostic_count: usize,
    pub process_lineage_diagnostic_count: usize,
    pub process_lineage_diagnostics_truncated: bool,
    pub known_unknowns: Vec<KnownUnknown>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RecordKindCounts {
    pub syscall: usize,
    pub unfinished_syscall: usize,
    pub resumed_syscall: usize,
    pub control: usize,
    pub unparsed: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportedSyscall {
    Execve,
    Execveat,
    Openat,
    Openat2,
    Connect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultMeaning {
    /// The selected syscall returned a result recognized as successful.
    RecognizedSuccessfulReturn,
    /// The result was a recognized Linux -1/errno failure; this is an attempt,
    /// and does not establish that a higher-level effect occurred.
    RecognizedFailureAttempt,
    /// For connect only, the recognized EINPROGRESS result was observed.
    ConnectionInProgress,
    /// No supported interpretation of this result was available.
    UnknownResult,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyscallResultFact {
    pub syscall: SupportedSyscall,
    /// Parser classification of the observed result. This is not a claim about
    /// a higher-level effect beyond the syscall's returned status.
    pub outcome: SyscallOutcome,
    pub meaning: ResultMeaning,
    pub evidence: crate::model::EvidenceReference,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessRelationFact {
    /// The trace row prefix's caller task ID; under strace -f this can be a TID.
    pub caller_task_id: u32,
    pub child_pid: u32,
    pub evidence: crate::model::EvidenceReference,
    pub supporting_evidence: Vec<crate::model::EvidenceReference>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiffExplanation {
    pub schema_version: u32,
    /// Rows differ under the supplied diff's matching policy. No causal meaning
    /// is assigned to the comparison.
    pub capture_completeness: CaptureCompleteness,
    pub scanned_change_count: usize,
    pub delta_counts: Vec<DeltaCount>,
    pub changes: Vec<DiffChangeFact>,
    pub omitted_change_count: usize,
    pub omitted_reference_count: usize,
    pub left_excluded_control_records: u64,
    pub right_excluded_control_records: u64,
    pub known_unknowns: Vec<KnownUnknown>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DeltaCount {
    pub category: EventCategory,
    pub kind: DeltaKind,
    pub count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiffChangeFact {
    pub category: EventCategory,
    pub kind: DeltaKind,
    pub record_kind: TraceRecordKind,
    /// Result text is omitted; these booleans only indicate whether the diff
    /// row supplied a before/after result field.
    pub before_result_present: bool,
    pub after_result_present: bool,
    pub before: Vec<crate::model::EvidenceReference>,
    pub after: Vec<crate::model::EvidenceReference>,
}

/// Build a bounded, deterministic summary of a parsed trace document.
///
/// All trace-derived strings are omitted. The returned facts only copy typed
/// classifications, numeric process identifiers, and exact evidence tuples.
pub fn explain_trace(document: &TraceDocument) -> TraceExplanation {
    let scan_count = document.records.len().min(MAX_EXPLANATION_INPUT_ROWS);
    let mut record_counts = RecordKindCounts::default();
    let mut result_facts = Vec::new();
    let mut selected_syscall_rows_without_outcome = 0_usize;
    let mut omitted_result_fact_count = 0_usize;
    let mut used_references = 0_usize;

    for row in &document.records[..scan_count] {
        increment_record_count(&mut record_counts, row.kind);
        if let Some(syscall) = row.syscall.as_deref().and_then(supported_syscall) {
            if let Some(outcome) = row.outcome {
                if result_facts.len() < MAX_EXPLANATION_FACTS
                    && used_references < MAX_EXPLANATION_REFERENCES
                {
                    result_facts.push(SyscallResultFact {
                        syscall,
                        outcome,
                        meaning: result_meaning(syscall, outcome),
                        evidence: row.evidence.clone(),
                    });
                    used_references += 1;
                } else {
                    omitted_result_fact_count = omitted_result_fact_count.saturating_add(1);
                }
            } else {
                selected_syscall_rows_without_outcome =
                    selected_syscall_rows_without_outcome.saturating_add(1);
            }
        }
    }

    let lineage = &document.process_lineage;
    let relation_scan_count = lineage.relations.len().min(MAX_EXPLANATION_INPUT_ROWS);
    let mut process_relations = Vec::new();
    let mut omitted_process_relation_count =
        lineage.relations.len().saturating_sub(relation_scan_count);
    for relation in &lineage.relations[..relation_scan_count] {
        let needed = 1_usize.saturating_add(relation.supporting_evidence.len());
        if process_relations.len() >= MAX_EXPLANATION_FACTS
            || needed > MAX_EXPLANATION_REFERENCES.saturating_sub(used_references)
        {
            omitted_process_relation_count = omitted_process_relation_count.saturating_add(1);
            continue;
        }
        used_references += needed;
        process_relations.push(process_relation_fact(relation));
    }

    let mut known_unknowns = vec![KnownUnknown::CaptureCompletenessUnknown];
    if document.parse_status == ParseCompleteness::Partial {
        known_unknowns.push(KnownUnknown::PartialParse);
    }
    if lineage.partial {
        known_unknowns.push(KnownUnknown::ProcessRelationsPartial);
    }
    if document
        .bundle_capture
        .as_ref()
        .is_some_and(|capture| capture.stop_reason == "time_limit_reached")
    {
        known_unknowns.push(KnownUnknown::CaptureStoppedByTimeLimit);
    }
    if document.records.len() > scan_count {
        known_unknowns.push(KnownUnknown::TraceRecordsOmittedByLimit);
    }
    if omitted_result_fact_count > 0 {
        known_unknowns.push(KnownUnknown::ResultFactsOmittedByLimit);
    }
    if omitted_process_relation_count > 0 {
        known_unknowns.push(KnownUnknown::ProcessRelationsOmittedByLimit);
    }

    TraceExplanation {
        schema_version: SCHEMA_VERSION,
        parse_status: document.parse_status,
        capture_completeness: CaptureCompleteness::Unknown,
        capture_context: if document.bundle_capture.is_some() {
            CaptureContext::MetadataPresent
        } else {
            CaptureContext::NotProvided
        },
        capture_stop_reason: document.bundle_capture.as_ref().map_or(
            CaptureStopReason::NotProvided,
            |capture| match capture.stop_reason.as_str() {
                "tracer_exited" => CaptureStopReason::TracerExited,
                "time_limit_reached" => CaptureStopReason::TimeLimitReached,
                _ => CaptureStopReason::Unknown,
            },
        ),
        requested_time_limit_present: document
            .bundle_capture
            .as_ref()
            .and_then(|capture| capture.time_limit_milliseconds)
            .is_some(),
        scanned_record_count: scan_count,
        record_counts,
        selected_syscall_rows_without_outcome,
        result_facts,
        omitted_result_fact_count,
        process_relations,
        omitted_process_relation_count,
        parser_diagnostic_count: document.diagnostics.len(),
        process_lineage_diagnostic_count: lineage.diagnostics.len(),
        process_lineage_diagnostics_truncated: lineage.diagnostics_truncated,
        known_unknowns,
    }
}

/// Build a bounded summary of observed differences already computed by the
/// conservative diff engine. Raw arguments, result values, and syscall names
/// are deliberately omitted.
pub fn explain_diff(diff: &TraceDiff<'_>) -> DiffExplanation {
    let scan_count = diff.changes.len().min(MAX_EXPLANATION_INPUT_ROWS);
    let kept_change_count = scan_count.min(MAX_EXPLANATION_CHANGES);
    let mut counts = Vec::new();
    let mut changes = Vec::new();
    let mut used_references = 0_usize;
    let mut omitted_reference_count = 0_usize;

    for delta in &diff.changes[..scan_count] {
        increment_delta_count(&mut counts, delta.category, delta.kind);
    }

    for delta in &diff.changes[..kept_change_count] {
        let before_capacity = delta
            .before
            .len()
            .min(MAX_EXPLANATION_REFERENCES.saturating_sub(used_references));
        used_references += before_capacity;
        let after_capacity = delta
            .after
            .len()
            .min(MAX_EXPLANATION_REFERENCES.saturating_sub(used_references));
        used_references += after_capacity;
        omitted_reference_count = omitted_reference_count
            .saturating_add(delta.before.len().saturating_sub(before_capacity))
            .saturating_add(delta.after.len().saturating_sub(after_capacity));
        changes.push(diff_change_fact(delta, before_capacity, after_capacity));
    }

    let omitted_change_count = diff.changes.len().saturating_sub(kept_change_count);
    let mut known_unknowns = vec![KnownUnknown::CaptureCompletenessUnknown];
    if omitted_change_count > 0 {
        known_unknowns.push(if diff.changes.len() > scan_count {
            KnownUnknown::DiffInputRowsOmittedByLimit
        } else {
            KnownUnknown::DiffChangesOmittedByLimit
        });
    }
    if omitted_reference_count > 0 {
        known_unknowns.push(KnownUnknown::EvidenceReferencesOmittedByLimit);
    }

    DiffExplanation {
        schema_version: SCHEMA_VERSION,
        capture_completeness: diff.capture_completeness,
        scanned_change_count: scan_count,
        delta_counts: counts,
        changes,
        omitted_change_count,
        omitted_reference_count,
        left_excluded_control_records: diff.left_excluded_control_records,
        right_excluded_control_records: diff.right_excluded_control_records,
        known_unknowns,
    }
}

fn increment_record_count(counts: &mut RecordKindCounts, kind: TraceRecordKind) {
    let target = match kind {
        TraceRecordKind::Syscall => &mut counts.syscall,
        TraceRecordKind::UnfinishedSyscall => &mut counts.unfinished_syscall,
        TraceRecordKind::ResumedSyscall => &mut counts.resumed_syscall,
        TraceRecordKind::Control => &mut counts.control,
        TraceRecordKind::Unparsed => &mut counts.unparsed,
    };
    *target = target.saturating_add(1);
}

fn supported_syscall(name: &str) -> Option<SupportedSyscall> {
    match name {
        "execve" => Some(SupportedSyscall::Execve),
        "execveat" => Some(SupportedSyscall::Execveat),
        "openat" => Some(SupportedSyscall::Openat),
        "openat2" => Some(SupportedSyscall::Openat2),
        "connect" => Some(SupportedSyscall::Connect),
        _ => None,
    }
}

fn result_meaning(syscall: SupportedSyscall, outcome: SyscallOutcome) -> ResultMeaning {
    match outcome {
        SyscallOutcome::Success => ResultMeaning::RecognizedSuccessfulReturn,
        SyscallOutcome::Failure => ResultMeaning::RecognizedFailureAttempt,
        SyscallOutcome::InProgress if syscall == SupportedSyscall::Connect => {
            ResultMeaning::ConnectionInProgress
        }
        SyscallOutcome::InProgress | SyscallOutcome::Unknown => ResultMeaning::UnknownResult,
    }
}

fn process_relation_fact(relation: &ProcessRelation) -> ProcessRelationFact {
    ProcessRelationFact {
        caller_task_id: relation.caller_task_id,
        child_pid: relation.child_pid,
        evidence: relation.evidence.clone(),
        supporting_evidence: relation.supporting_evidence.clone(),
    }
}

fn increment_delta_count(counts: &mut Vec<DeltaCount>, category: EventCategory, kind: DeltaKind) {
    if let Some(count) = counts
        .iter_mut()
        .find(|count| count.category == category && count.kind == kind)
    {
        count.count = count.count.saturating_add(1);
    } else {
        counts.push(DeltaCount {
            category,
            kind,
            count: 1,
        });
    }
}

fn diff_change_fact(
    delta: &ObservedDelta<'_>,
    before_capacity: usize,
    after_capacity: usize,
) -> DiffChangeFact {
    DiffChangeFact {
        category: delta.category,
        kind: delta.kind,
        record_kind: delta.record_kind,
        before_result_present: delta.before_result.is_some(),
        after_result_present: delta.after_result.is_some(),
        before: delta.before.iter().take(before_capacity).cloned().collect(),
        after: delta.after.iter().take(after_capacity).cloned().collect(),
    }
}
