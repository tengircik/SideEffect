use sideeffect::explain::{
    KnownUnknown, ResultMeaning, SupportedSyscall, explain_diff, explain_trace,
};
use sideeffect::model::{
    CaptureCompleteness, DeltaKind, EventCategory, EvidenceReference, MatchingPolicy,
    ObservedDelta, ParseCompleteness, SyscallOutcome, TRACE_DIFF_SCHEMA_VERSION, TraceDiagnostic,
    TraceDiff, TraceDocument, TraceRecord, TraceRecordKind,
};
use sideeffect::trace::process_tree::{ProcessLineage, ProcessRelation};

fn reference(line_number: u64, byte_offset: u64) -> EvidenceReference {
    EvidenceReference {
        line_number,
        byte_offset,
        byte_length: 32,
    }
}

#[test]
fn trace_explanation_keeps_exact_evidence_and_surfaces_partial_unknowns() {
    let evidence = reference(4, 91);
    let supporting = reference(3, 60);
    let document = TraceDocument {
        schema_version: 7,
        source_format: "synthetic".to_owned(),
        source_sha256: "not-for-summary".to_owned(),
        input_bytes: 123,
        parse_status: ParseCompleteness::Partial,
        records: vec![TraceRecord {
            kind: TraceRecordKind::Syscall,
            evidence: evidence.clone(),
            raw_line: "connect(...secret...) = -1 EINPROGRESS".to_owned(),
            process_id: Some(21),
            timestamp: None,
            syscall: Some("connect".to_owned()),
            raw_arguments: Some("token=do-not-copy".to_owned()),
            raw_result: Some("-1 EINPROGRESS (Operation now in progress)".to_owned()),
            outcome: Some(SyscallOutcome::InProgress),
            lexical_path_hint: None,
        }],
        diagnostics: vec![TraceDiagnostic {
            code: "malformed_record".to_owned(),
            line_number: 5,
            byte_offset: 122,
            message: "diagnostic text omitted".to_owned(),
        }],
        process_lineage: ProcessLineage {
            relations: vec![ProcessRelation {
                caller_task_id: 21,
                child_pid: 34,
                evidence: reference(8, 200),
                supporting_evidence: vec![supporting.clone()],
            }],
            diagnostics: Vec::new(),
            partial: true,
            diagnostics_truncated: false,
        },
        bundle_capture: None,
    };

    let explanation = explain_trace(&document);
    assert_eq!(explanation.parse_status, ParseCompleteness::Partial);
    assert_eq!(
        explanation.capture_completeness,
        CaptureCompleteness::Unknown
    );
    assert_eq!(explanation.result_facts.len(), 1);
    assert_eq!(
        explanation.result_facts[0].syscall,
        SupportedSyscall::Connect
    );
    assert_eq!(
        explanation.result_facts[0].meaning,
        ResultMeaning::ConnectionInProgress
    );
    assert_eq!(explanation.result_facts[0].evidence, evidence);
    assert_eq!(
        explanation.process_relations[0].supporting_evidence,
        vec![supporting]
    );
    assert!(
        explanation
            .known_unknowns
            .contains(&KnownUnknown::PartialParse)
    );
    assert!(
        explanation
            .known_unknowns
            .contains(&KnownUnknown::ProcessRelationsPartial)
    );

    let serialized = serde_json::to_string(&explanation).unwrap();
    assert!(!serialized.contains("token=do-not-copy"));
    assert!(!serialized.contains("EINPROGRESS"));
    assert!(!serialized.contains("not-for-summary"));
}

#[test]
fn diff_explanation_summarizes_delta_without_raw_values() {
    let left_ref = reference(2, 40);
    let right_ref = reference(7, 200);
    let diff = TraceDiff {
        schema_version: TRACE_DIFF_SCHEMA_VERSION,
        left_source_format: "strace_text",
        right_source_format: "strace_text",
        left_source_sha256: "left-fingerprint",
        right_source_sha256: "right-fingerprint",
        capture_completeness: CaptureCompleteness::Unknown,
        matching_policy: MatchingPolicy {
            ignored_prefix_fields: Vec::new(),
            multiplicity: "multiset".to_owned(),
            exact_fields: Vec::new(),
            display_only_fields: Vec::new(),
        },
        left_excluded_control_records: 2,
        right_excluded_control_records: 3,
        changes: vec![ObservedDelta {
            kind: DeltaKind::Changed,
            category: EventCategory::Network,
            record_kind: TraceRecordKind::Syscall,
            syscall: "connect",
            raw_arguments: "secret-address-and-token",
            before_lexical_path_hint: None,
            after_lexical_path_hint: None,
            before_result: Some("private-before-result"),
            after_result: Some("private-after-result"),
            before: vec![left_ref.clone()],
            after: vec![right_ref.clone()],
        }],
    };

    let explanation = explain_diff(&diff);
    assert_eq!(explanation.scanned_change_count, 1);
    assert_eq!(explanation.delta_counts[0].kind, DeltaKind::Changed);
    assert_eq!(explanation.changes[0].before, vec![left_ref]);
    assert_eq!(explanation.changes[0].after, vec![right_ref]);
    assert!(explanation.changes[0].before_result_present);
    assert!(explanation.changes[0].after_result_present);
    let serialized = serde_json::to_string(&explanation).unwrap();
    assert!(!serialized.contains("secret-address-and-token"));
    assert!(!serialized.contains("private-before-result"));
    assert!(!serialized.contains("left-fingerprint"));
}
