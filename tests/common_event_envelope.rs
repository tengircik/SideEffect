use sideeffect::event::{
    EvidenceReference, LinuxTaskEpochBasis, OperationSemantics, SourceCompleteness,
    from_linux_strace, graph, timeline,
};
use sideeffect::limits::ParseLimits;
use sideeffect::model::{SyscallOutcome, TraceRecord, TraceRecordKind};
use sideeffect::trace::strace::parse_trace_bytes;

const SYNTHETIC_TRACE: &[u8] = b"[pid 417] 1700000000.000001 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"203.0.113.8\")}, 16) = -1 ECONNREFUSED (Connection refused)\n[pid 417] 1700000000.000002 +++ exited with 0 +++\n";

fn raw_reference(record: &TraceRecord) -> EvidenceReference {
    EvidenceReference::RawTraceRecord {
        line_number: record.evidence.line_number,
        byte_offset: record.evidence.byte_offset,
        byte_length: record.evidence.byte_length,
    }
}

#[test]
fn adapts_syscall_attempt_with_failure_and_exact_source_reference() {
    let parsed = parse_trace_bytes(SYNTHETIC_TRACE, ParseLimits::default()).unwrap();
    let envelope = from_linux_strace(&parsed, SYNTHETIC_TRACE, "trace.txt");

    assert_eq!(envelope.schema, "sideeffect.common_event_envelope");
    assert_eq!(envelope.schema_version, 4);
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
        SourceCompleteness::Complete
    );
    assert!(envelope.diagnostics.is_empty());
    assert_eq!(envelope.process_observations.len(), 1);
    assert_eq!(
        envelope.process_observations[0].end_evidence,
        Some(EvidenceReference::RawTraceRecord {
            line_number: 2,
            byte_offset: b"[pid 417] 1700000000.000001 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"203.0.113.8\")}, 16) = -1 ECONNREFUSED (Connection refused)\n".len() as u64,
            byte_length: b"[pid 417] 1700000000.000002 +++ exited with 0 +++".len() as u64,
        })
    );
}

#[test]
fn line_references_are_checked_incrementally_across_blank_lines() {
    let bytes = b"[pid 417] 1700000000.000001 getpid() = 417\n\n[pid 417] 1700000000.000002 getpid() = 417\n[pid 417] 1700000000.000003 getpid() = 417\n";
    let parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    let envelope = from_linux_strace(&parsed, bytes, "synthetic-line-reference.trace");

    assert_eq!(envelope.events.len(), 3);
    assert_eq!(
        envelope
            .events
            .iter()
            .map(|event| match event.evidence {
                EvidenceReference::RawTraceRecord { line_number, .. } => line_number,
                EvidenceReference::WindowsEtwRecord { .. } => panic!("unexpected ETW reference"),
            })
            .collect::<Vec<_>>(),
        vec![1, 3, 4]
    );
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Partial
    );
    assert!(envelope.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "unsupported_source_row" && diagnostic.source_local_ordinal == Some(2)
    }));
}

#[test]
fn process_creation_links_caller_task_to_returned_child_pid_without_parentage_claim() {
    let bytes = b"[pid 500] 1700000000.000001 fork() = 501\n";
    let parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    let envelope = from_linux_strace(&parsed, bytes, "synthetic-fork.trace");

    assert_eq!(envelope.schema_version, 4);
    assert_eq!(envelope.process_observations.len(), 2);
    assert!(matches!(
        envelope.process_observations[0].identity,
        sideeffect::event::ProcessIdentity::LinuxTraceTaskContext {
            task_id: 500,
            observed_task_epoch: Some(1),
            epoch_basis: sideeffect::event::LinuxTaskEpochBasis::FirstObservedTaskContext,
            identity_status: sideeffect::event::ProcessIdentityStatus::TaskIdOnlyGenerationUnknown
        }
    ));
    assert!(matches!(
        envelope.process_observations[1].identity,
        sideeffect::event::ProcessIdentity::LinuxReturnedChildPid {
            process_id: 501,
            identity_status: sideeffect::event::ProcessIdentityStatus::ReturnedChildPidOnly
        }
    ));
    let relation = &envelope.process_relationships[0];
    assert_eq!(
        relation.kind,
        sideeffect::event::ProcessRelationshipKind::StraceCallerTaskReturnedChildPid
    );
    assert_eq!(relation.from_observation_id, Some(1));
    assert_eq!(relation.to_observation_id, 2);
    assert_eq!(relation.reported_from_process_id, None);
    assert!(relation.basis.contains("returned_child_pid"));
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Complete
    );
}

#[test]
fn explicit_task_termination_splits_only_source_local_task_epochs() {
    let bytes = b"[pid 42] 1700000000.000001 read(0, \"a\", 1) = 1\n[pid 42] 1700000000.000002 +++ exited with 0 +++\n[pid 42] 1700000000.000003 read(0, \"b\", 1) = 1\n[pid 42] 1700000000.000004 +++ killed by SIGTERM (core dumped) +++\n[pid 42] 1700000000.000005 write(1, \"c\", 1) = 1\n";
    let parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    let envelope = from_linux_strace(&parsed, bytes, "synthetic-task-epochs.trace");

    assert_eq!(envelope.process_observations.len(), 3);
    assert_eq!(
        envelope.process_observations[0].evidence,
        raw_reference(&parsed.records[0])
    );
    let task_epochs = envelope
        .process_observations
        .iter()
        .map(|observation| match &observation.identity {
            sideeffect::event::ProcessIdentity::LinuxTraceTaskContext {
                task_id,
                observed_task_epoch,
                epoch_basis,
                identity_status,
            } => {
                assert_eq!(*task_id, 42);
                assert_eq!(
                    *identity_status,
                    sideeffect::event::ProcessIdentityStatus::TaskIdOnlyGenerationUnknown
                );
                (*observed_task_epoch, *epoch_basis)
            }
            other => panic!("unexpected task identity: {other:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        task_epochs,
        vec![
            (Some(1), LinuxTaskEpochBasis::FirstObservedTaskContext),
            (Some(2), LinuxTaskEpochBasis::AfterObservedTaskTermination),
            (Some(3), LinuxTaskEpochBasis::AfterObservedTaskTermination),
        ]
    );
    assert_eq!(
        envelope.process_observations[0].end_evidence,
        Some(raw_reference(&parsed.records[1]))
    );
    assert_eq!(
        envelope.process_observations[1].end_evidence,
        Some(raw_reference(&parsed.records[3]))
    );
    assert_eq!(envelope.process_observations[2].end_evidence, None);
    assert_eq!(
        envelope
            .event_process_links
            .iter()
            .map(|link| link.process_observation_id)
            .collect::<Vec<_>>(),
        vec![Some(1), Some(2), Some(3)]
    );
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Complete
    );

    let selected = timeline(&envelope, None, Some(2)).unwrap();
    assert_eq!(selected.schema_version, 4);
    assert_eq!(selected.items.len(), 1);
    assert_eq!(
        selected.selected_process_observation.unwrap().end_evidence,
        Some(raw_reference(&parsed.records[3]))
    );
    let selected_graph = graph(&envelope, None, Some(2)).unwrap();
    let process_node = selected_graph
        .nodes
        .iter()
        .find(|node| node.id == "process:2")
        .unwrap();
    assert_eq!(
        process_node.process_observation.as_ref().unwrap().evidence,
        raw_reference(&parsed.records[2])
    );
    assert_eq!(
        process_node
            .process_observation
            .as_ref()
            .unwrap()
            .end_evidence,
        Some(raw_reference(&parsed.records[3]))
    );
}

#[test]
fn partial_parse_keeps_task_contexts_merged_without_advertising_epochs() {
    let bytes = b"[pid 42] 1700000000.000001 read(0, \"a\", 1) = 1\n[pid 42] 1700000000.000002 +++ exited with 0 +++\nnot a recognized row\n[pid 42] 1700000000.000003 read(0, \"b\", 1) = 1\n";
    let parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    assert_eq!(
        parsed.parse_status,
        sideeffect::model::ParseCompleteness::Partial
    );
    let envelope = from_linux_strace(&parsed, bytes, "synthetic-partial-task-epochs.trace");

    assert_eq!(envelope.process_observations.len(), 1);
    assert_eq!(envelope.process_observations[0].end_evidence, None);
    assert!(matches!(
        envelope.process_observations[0].identity,
        sideeffect::event::ProcessIdentity::LinuxTraceTaskContext {
            task_id: 42,
            observed_task_epoch: None,
            epoch_basis: LinuxTaskEpochBasis::ContinuityUnknownDueToPartialParse,
            ..
        }
    ));
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Partial
    );
}

#[test]
fn returned_child_pid_stays_separate_from_equal_task_prefix_id() {
    let bytes =
        b"[pid 10] 1700000000.000001 fork() = 42\n[pid 42] 1700000000.000002 getpid() = 42\n";
    let parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    let envelope = from_linux_strace(&parsed, bytes, "synthetic-pid-tid-equality.trace");

    assert_eq!(envelope.process_observations.len(), 3);
    assert!(matches!(
        envelope.process_observations[1].identity,
        sideeffect::event::ProcessIdentity::LinuxTraceTaskContext {
            task_id: 42,
            observed_task_epoch: Some(1),
            ..
        }
    ));
    assert!(matches!(
        envelope.process_observations[2].identity,
        sideeffect::event::ProcessIdentity::LinuxReturnedChildPid { process_id: 42, .. }
    ));
    assert_eq!(
        envelope.event_process_links[1].process_observation_id,
        Some(2)
    );
    assert_eq!(
        envelope.process_relationships[0].from_observation_id,
        Some(1)
    );
    assert_eq!(envelope.process_relationships[0].to_observation_id, 3);
}

#[test]
fn unmatched_and_duplicate_task_termination_rows_are_diagnostic() {
    let bytes = b"[pid 7] 1700000000.000001 +++ exited with 0 +++\n[pid 7] 1700000000.000002 getpid() = 7\n[pid 7] 1700000000.000003 +++ exited with 0 +++\n[pid 7] 1700000000.000004 +++ exited with 0 +++\n[pid 42] 1700000000.000005 read(0, \"a\", 1) = 1\n[pid 42] 1700000000.000006 +++ exited with 0 +++\n[pid 42] 1700000000.000007 +++ exited with 0 +++\n+++ killed by SIGTERM +++\n";
    let parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    let envelope = from_linux_strace(&parsed, bytes, "synthetic-unmatched-task-termination.trace");

    assert!(
        envelope
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "task_termination_without_observed_context" })
    );
    assert!(
        envelope
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "task_termination_without_active_observation" })
    );
    assert!(
        envelope
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "task_termination_missing_task_id" })
    );
    assert!(matches!(
        envelope.process_observations[0].identity,
        sideeffect::event::ProcessIdentity::LinuxTraceTaskContext {
            task_id: 7,
            observed_task_epoch: Some(1),
            epoch_basis: LinuxTaskEpochBasis::AfterObservedTaskTermination,
            ..
        }
    ));
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Partial
    );
}

#[test]
fn near_match_control_rows_do_not_split_task_epochs() {
    let bytes = b"[pid 42] 1700000000.000001 read(0, \"a\", 1) = 1\n[pid 42] 1700000000.000002 +++ exited with success +++\n[pid 42] 1700000000.000003 read(0, \"b\", 1) = 1\n[pid 42] 1700000000.000004 +++ killed by SIGFOO +++\n[pid 42] 1700000000.000005 read(0, \"c\", 1) = 1\n";
    let parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    let envelope = from_linux_strace(&parsed, bytes, "synthetic-unrecognized-termination.trace");

    assert_eq!(envelope.process_observations.len(), 1);
    assert_eq!(envelope.process_observations[0].end_evidence, None);
    assert!(matches!(
        envelope.process_observations[0].identity,
        sideeffect::event::ProcessIdentity::LinuxTraceTaskContext {
            task_id: 42,
            observed_task_epoch: Some(1),
            epoch_basis: LinuxTaskEpochBasis::FirstObservedTaskContext,
            ..
        }
    ));
    assert!(envelope.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "unsupported_source_row" && diagnostic.source_local_ordinal == Some(2)
    }));
    assert!(envelope.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "unsupported_source_row" && diagnostic.source_local_ordinal == Some(4)
    }));
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Partial
    );
}

#[test]
fn unmatched_task_termination_diagnostics_remain_bounded() {
    let mut bytes = String::new();
    for task_id in 1..=300 {
        bytes.push_str(&format!(
            "[pid {task_id}] 1700000000.000001 +++ exited with 0 +++\n"
        ));
    }
    let parsed = parse_trace_bytes(bytes.as_bytes(), ParseLimits::default()).unwrap();
    let envelope = from_linux_strace(
        &parsed,
        bytes.as_bytes(),
        "synthetic-many-unmatched-terminations.trace",
    );

    assert_eq!(envelope.diagnostics.len(), 256);
    assert_eq!(
        envelope
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "process_diagnostics_truncated")
            .count(),
        1
    );
    assert_eq!(
        envelope
            .source_state
            .diagnostics
            .iter()
            .filter(|code| { code.as_str() == "task_termination_without_observed_context" })
            .count(),
        1
    );
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Partial
    );
}

#[test]
fn invalid_supplied_process_lineage_is_partial_and_omitted() {
    let bytes = b"[pid 500] 1700000000.000001 fork() = 501\n";
    let mut parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    parsed.process_lineage.relations[0].evidence.byte_offset += 1;
    let envelope = from_linux_strace(&parsed, bytes, "synthetic-invalid-lineage.trace");

    assert!(envelope.process_relationships.is_empty());
    assert_eq!(
        envelope.source_state.completeness,
        SourceCompleteness::Partial
    );
    assert!(
        envelope
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "process_lineage_mismatch")
    );
}

#[test]
fn mismatched_child_result_and_non_creation_rows_cannot_support_relationships() {
    let bytes = b"[pid 500] 1700000000.000001 fork() = 501\n";
    let parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();

    let mut mismatched_child = parsed.clone();
    mismatched_child.process_lineage.relations[0].child_pid = 502;
    let mismatch = from_linux_strace(&mismatched_child, bytes, "synthetic-mismatched-child.trace");
    assert!(mismatch.process_relationships.is_empty());
    assert_eq!(
        mismatch.source_state.completeness,
        SourceCompleteness::Partial
    );
    assert!(
        mismatch
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "process_lineage_mismatch" })
    );

    let mut non_creation = parsed;
    non_creation.records[0].syscall = Some("execve".to_owned());
    let invalid = from_linux_strace(&non_creation, bytes, "synthetic-non-creation.trace");
    assert!(invalid.process_relationships.is_empty());
    assert_eq!(
        invalid.source_state.completeness,
        SourceCompleteness::Partial
    );
    assert!(
        invalid
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "process_lineage_mismatch" })
    );
}

#[test]
fn unknown_clone3_prefixed_syscall_cannot_create_a_process_relationship() {
    let bytes = b"[pid 500] 1700000000.000001 clone3_extra({flags=CLONE_VM|SIGCHLD}, 88) = 501\n";
    let parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    assert_eq!(parsed.records[0].syscall.as_deref(), Some("clone3_extra"));
    assert!(parsed.process_lineage.relations.is_empty());

    let envelope = from_linux_strace(&parsed, bytes, "synthetic-unknown-clone3.trace");
    assert!(envelope.process_relationships.is_empty());
    assert!(
        envelope
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != "process_lineage_mismatch")
    );
}

#[test]
fn mutated_supporting_reference_must_match_unfinished_creation_caller_and_syscall() {
    let bytes = b"[pid 500] 1700000000.000001 clone3({flags=CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND, exit_signal=SIGCHLD}, 88 <unfinished ...>\n[pid 500] 1700000000.000002 <... clone3 resumed>) = 501\n[pid 500] 1700000000.000003 read(3, <unfinished ...>\n[pid 500] 1700000000.000004 clone3({flags=CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND, exit_signal=SIGCHLD}, 88 <unfinished ...>\n";
    let parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    assert_eq!(parsed.process_lineage.relations.len(), 1);
    assert_eq!(
        parsed.process_lineage.relations[0]
            .supporting_evidence
            .len(),
        1
    );
    for wrong_support_index in [2, 3] {
        let mut mutated = parsed.clone();
        mutated.process_lineage.relations[0].supporting_evidence[0] =
            parsed.records[wrong_support_index].evidence.clone();

        let envelope = from_linux_strace(&mutated, bytes, "synthetic-mutated-support.trace");
        assert!(envelope.process_relationships.is_empty());
        assert_eq!(
            envelope.source_state.completeness,
            SourceCompleteness::Partial
        );
        assert!(
            envelope
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "process_lineage_mismatch")
        );
    }
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

#[test]
fn process_filtered_graph_keeps_selected_observation_when_it_has_no_event_link() {
    let bytes = b"[pid 417] 1700000000.000001 getpid() = 417\n";
    let parsed = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
    let mut envelope = from_linux_strace(&parsed, bytes, "synthetic-no-event-link.trace");
    envelope.event_process_links.clear();

    let graph = graph(&envelope, None, Some(1)).unwrap();
    assert_eq!(graph.schema, "sideeffect.event_graph");
    assert_eq!(graph.schema_version, 4);
    assert_eq!(graph.filter.process_observation_id, Some(1));
    assert!(graph.nodes.iter().any(|node| {
        node.kind == sideeffect::event::EventGraphNodeKind::ProcessObservation
            && node.id == "process:1"
    }));
    assert!(
        graph
            .nodes
            .iter()
            .all(|node| node.kind != sideeffect::event::EventGraphNodeKind::Event)
    );
    assert!(graph.edges.is_empty());
    assert!(graph.semantics.contains("not proof of absence"));
    assert_eq!(graph.source_state, envelope.source_state);
    assert_eq!(graph.diagnostics, envelope.diagnostics);
}
