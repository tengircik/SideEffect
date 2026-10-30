use sideeffect::event::{
    EvidenceReference, OperationSemantics, SourceCompleteness, from_linux_strace,
};
use sideeffect::limits::ParseLimits;
use sideeffect::model::{SyscallOutcome, TraceRecordKind};
use sideeffect::trace::strace::parse_trace_bytes;

const SYNTHETIC_TRACE: &[u8] = b"[pid 417] 1700000000.000001 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"203.0.113.8\")}, 16) = -1 ECONNREFUSED (Connection refused)\n[pid 417] 1700000000.000002 +++ exited with 0 +++\n";

#[test]
fn adapts_syscall_attempt_with_failure_and_exact_source_reference() {
    let parsed = parse_trace_bytes(SYNTHETIC_TRACE, ParseLimits::default()).unwrap();
    let envelope = from_linux_strace(&parsed, SYNTHETIC_TRACE, "trace.txt");

    assert_eq!(envelope.schema, "sideeffect.common_event_envelope");
    assert_eq!(envelope.schema_version, 1);
    assert_eq!(envelope.source.schema_version, 7);
    assert_eq!(
        envelope.source.sha256.as_deref(),
        Some(parsed.source_sha256.as_str())
    );
    assert_eq!(envelope.events.len(), 1);
    let event = &envelope.events[0];
    assert_eq!(event.source_local_ordinal, 1);
    assert_eq!(
        event.source_timestamp.as_ref().unwrap().value,
        "1700000000.000001"
    );
    assert!(matches!(
        event.operation,
        OperationSemantics::SyscallAttempt {
            result: Some(SyscallOutcome::Failure)
        }
    ));
    assert!(matches!(
        event.evidence,
        EvidenceReference::RawTraceRecord {
            line_number: 1,
            byte_offset: 0,
            byte_length: _
        }
    ));
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Partial
    );
    assert_eq!(envelope.diagnostics[0].code, "unsupported_source_row");
    assert_eq!(envelope.diagnostics[0].source_local_ordinal, Some(2));
}

#[test]
fn invalid_linux_source_digest_is_omitted_and_reported() {
    let mut parsed = parse_trace_bytes(SYNTHETIC_TRACE, ParseLimits::default()).unwrap();
    parsed.source_sha256 = "invalid".to_owned();
    let envelope = from_linux_strace(&parsed, SYNTHETIC_TRACE, "synthetic-invalid-digest.trace");

    assert_eq!(envelope.source.sha256, None);
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Partial
    );
    assert!(
        envelope
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "source_fingerprint_mismatch")
    );
    assert!(serde_json::to_value(envelope).unwrap()["source"]["sha256"].is_null());
}

#[test]
fn same_length_raw_byte_change_invalidates_the_source_digest() {
    let parsed = parse_trace_bytes(SYNTHETIC_TRACE, ParseLimits::default()).unwrap();
    let mut changed_bytes = SYNTHETIC_TRACE.to_vec();
    changed_bytes[0] = b'{';
    assert_eq!(changed_bytes.len(), SYNTHETIC_TRACE.len());

    let envelope = from_linux_strace(&parsed, &changed_bytes, "synthetic-changed-bytes.trace");
    assert!(envelope.events.is_empty());
    assert_eq!(envelope.source.sha256, None);
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Partial
    );
    assert!(
        envelope
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "source_fingerprint_mismatch")
    );
}

#[test]
fn invalid_source_references_are_reported_and_not_adapted() {
    let mut parsed = parse_trace_bytes(SYNTHETIC_TRACE, ParseLimits::default()).unwrap();
    parsed.records[0].evidence.byte_offset = parsed.input_bytes + 1;
    let envelope = from_linux_strace(
        &parsed,
        SYNTHETIC_TRACE,
        "synthetic-invalid-reference.trace",
    );

    assert!(envelope.events.is_empty());
    assert_eq!(envelope.diagnostics[0].code, "invalid_evidence_reference");
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Partial
    );
}

#[test]
fn line_number_must_match_the_referenced_source_offset() {
    let bytes = b"1700000000.000001 close(3) = 0\n";
    let mut parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    parsed.records[0].evidence.line_number = 2;
    let envelope = from_linux_strace(&parsed, bytes, "synthetic-invalid-line.trace");

    assert!(envelope.events.is_empty());
    assert_eq!(envelope.diagnostics[0].code, "invalid_evidence_reference");
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Partial
    );
}

#[test]
fn clean_full_parse_is_marked_complete() {
    let bytes = b"1700000000.000001 close(3) = 0\n";
    let parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    let envelope = from_linux_strace(&parsed, bytes, "synthetic-clean.trace");

    assert_eq!(envelope.events.len(), 1);
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Complete
    );
}

#[test]
fn unfinished_syscalls_remain_attempts_without_inventing_a_result() {
    let bytes = b"1700000000.000001 read(3, <unfinished ...>\n";
    let parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    let envelope = from_linux_strace(&parsed, bytes, "synthetic-unfinished.trace");

    assert_eq!(envelope.events.len(), 1);
    assert_eq!(envelope.events[0].event_kind, "read:unfinished");
    assert_eq!(
        envelope.events[0]
            .source_timestamp
            .as_ref()
            .unwrap()
            .clock_unit,
        "strace_timestamp_decimal; unit not independently verified"
    );
    assert!(matches!(
        envelope.events[0].operation,
        OperationSemantics::SyscallAttempt { result: None }
    ));
    assert_eq!(parsed.records[0].kind, TraceRecordKind::UnfinishedSyscall);
}
