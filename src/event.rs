//! Versioned common event envelope over source-native runtime evidence.
//!
//! Adapters preserve local positions and clocks. They do not establish a
//! cross-platform clock, causal relation, parentage, or process ownership.

use serde::Serialize;
use sha2::Digest;
#[cfg(windows)]
use std::collections::BTreeSet;
use std::collections::{BTreeMap, HashMap};

use crate::model::{
    EvidenceReference as TraceEvidenceReference, ParseCompleteness, SyscallOutcome, TraceDocument,
    TraceRecordKind,
};

pub const COMMON_EVENT_SCHEMA: &str = "sideeffect.common_event_envelope";
pub const COMMON_EVENT_SCHEMA_VERSION: u32 = 2;
#[cfg(windows)]
const WINDOWS_RUNTIME_SCHEMA: &str = "sideeffect.windows_runtime_capture";
#[cfg(windows)]
const WINDOWS_RUNTIME_SCHEMA_VERSION: u32 = 3;
const MAX_COMMON_EVENTS: usize = 100_000;
const MAX_COMMON_PROCESS_RELATIONS: usize = 50_000;
const MAX_COMMON_PROCESS_DIAGNOSTICS: usize = 256;
const MAX_COMMON_PROCESS_OBSERVATIONS: usize = MAX_COMMON_EVENTS + MAX_COMMON_PROCESS_RELATIONS;
#[cfg(windows)]
const MAX_ETW_EVENTS: usize = 50_000;
#[cfg(windows)]
const MAX_ETW_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
#[cfg(windows)]
const MAX_ETW_PAYLOAD_BYTES_PER_EVENT: usize = 64 * 1024;
#[cfg(windows)]
const MAX_CAPTURE_DIAGNOSTICS: usize = 256;
#[cfg(windows)]
const MAX_CAPTURE_DIAGNOSTIC_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourcePlatform {
    Linux,
    Windows,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceDescriptor {
    pub platform: SourcePlatform,
    pub schema: String,
    pub schema_version: u32,
    /// Fixed caller-selected artifact label; not a filesystem path to open.
    pub artifact: String,
    /// Fingerprint of the source document or exact raw trace bytes.
    /// Omitted as `null` when the source fingerprint is malformed or invalid.
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceTimestamp {
    /// Kept in its source representation; never converted or compared globally.
    pub value: String,
    pub clock_unit: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceReference {
    RawTraceRecord {
        line_number: u64,
        byte_offset: u64,
        byte_length: u64,
    },
    WindowsEtwRecord {
        record_ordinal: u64,
        json_pointer: String,
        raw_payload_sha256: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "source_kind", rename_all = "snake_case")]
pub enum OperationSemantics {
    SyscallAttempt { result: Option<SyscallOutcome> },
    NativeObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventIdentityContext {
    pub kind: String,
    pub value: String,
    pub ambiguity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommonEvent {
    /// Source-local one-based row position, not a cross-source sequence.
    pub source_local_ordinal: u64,
    pub source_timestamp: Option<SourceTimestamp>,
    pub event_kind: String,
    pub operation: OperationSemantics,
    pub evidence: EvidenceReference,
    pub identity_context: Vec<EventIdentityContext>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LossMetadata {
    pub reported_events_lost: u64,
    pub reported_buffers_lost: u64,
    pub statistics_available: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCompleteness {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceState {
    pub completeness: SourceCompleteness,
    pub diagnostics: Vec<String>,
    pub loss: Option<LossMetadata>,
    pub identity_ambiguity_present: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventDiagnostic {
    pub code: String,
    pub message: String,
    pub source_local_ordinal: Option<u64>,
    pub evidence: Option<EvidenceReference>,
}

/// A bounded source-local process observation. `source_local_id` is an index
/// within this envelope, not a stable identity across captures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessObservation {
    pub source_local_id: u64,
    pub identity: ProcessIdentity,
    pub evidence: EvidenceReference,
    pub end_evidence: Option<EvidenceReference>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessIdentity {
    /// The strace line prefix identifies a task/thread context. It is not
    /// normalized to an OS process identity or a PID generation.
    LinuxTraceTaskContext {
        task_id: u32,
        identity_status: ProcessIdentityStatus,
    },
    /// A successful creation syscall returned this child PID. No later rows
    /// are assigned to the PID without generation evidence.
    LinuxReturnedChildPid {
        process_id: u32,
        identity_status: ProcessIdentityStatus,
    },
    /// A validated ETW process-start payload anchors this instance to its
    /// source-local start record.
    WindowsProcessInstance {
        process_id: u32,
        start_record_ordinal: u64,
        reported_parent_process_id: Option<u32>,
        identity_status: ProcessIdentityStatus,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessIdentityStatus {
    TaskIdOnlyGenerationUnknown,
    ReturnedChildPidOnly,
    ObservedStart,
    AmbiguousPidReuse,
    LifecycleContinuityUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessRelationshipKind {
    StraceCallerTaskReturnedChildPid,
    WindowsPayloadParentToChildInstance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipResolution {
    Observed,
    ParentInstanceUnresolved,
    ParentPidAmbiguous,
    ProcessInstanceAmbiguous,
    ProcessInstanceUnresolved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessRelationship {
    pub kind: ProcessRelationshipKind,
    /// Missing when the source reports only a PID and no unique instance is
    /// evidenced by this capture.
    pub from_observation_id: Option<u64>,
    pub to_observation_id: u64,
    /// Preserves an ETW payload parent PID when it cannot be linked to a
    /// unique observed process instance.
    pub reported_from_process_id: Option<u32>,
    pub resolution: RelationshipResolution,
    pub basis: String,
    pub evidence: Vec<EvidenceReference>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventProcessLinkRole {
    LinuxTraceCallerTaskContext,
    LinuxProcessCreationResult,
    WindowsProcessStartPayload,
    WindowsProcessEndPayload,
    WindowsNetworkPayloadPid,
    WindowsFileDiskHeaderPidContextCandidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventProcessLinkStatus {
    Observed,
    ContextCandidate,
    Unresolved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventProcessLink {
    pub event: EvidenceReference,
    /// Missing when only an event-local process ID is observed, without a
    /// unique process instance in the retained capture.
    pub process_observation_id: Option<u64>,
    /// Preserves payload/header PID context when no unique instance resolves.
    pub reported_process_id: Option<u32>,
    pub role: EventProcessLinkRole,
    pub status: EventProcessLinkStatus,
    pub basis: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommonEventEnvelope {
    pub schema: &'static str,
    pub schema_version: u32,
    pub source: SourceDescriptor,
    pub source_state: SourceState,
    pub events: Vec<CommonEvent>,
    /// Source-local process observations; these do not merge process IDs
    /// across captures or claim a complete process tree.
    pub process_observations: Vec<ProcessObservation>,
    /// Direct evidence-linked relationships with platform-specific basis.
    pub process_relationships: Vec<ProcessRelationship>,
    /// Event-to-process references retain whether the link is context only.
    pub event_process_links: Vec<EventProcessLink>,
    /// Unsupported or invalid source rows remain visible here.
    pub diagnostics: Vec<EventDiagnostic>,
}

fn push_process_diagnostic(
    diagnostics: &mut Vec<EventDiagnostic>,
    process_diagnostic_count: &mut usize,
    code: &str,
    message: &str,
    source_local_ordinal: Option<u64>,
    evidence: Option<EvidenceReference>,
) {
    if *process_diagnostic_count < MAX_COMMON_PROCESS_DIAGNOSTICS - 1 {
        diagnostics.push(EventDiagnostic {
            code: code.to_owned(),
            message: message.to_owned(),
            source_local_ordinal,
            evidence,
        });
        *process_diagnostic_count += 1;
    } else if *process_diagnostic_count == MAX_COMMON_PROCESS_DIAGNOSTICS - 1 {
        diagnostics.push(EventDiagnostic {
            code: "process_diagnostics_truncated".to_owned(),
            message: "process relationship diagnostics exceeded the 256 entry limit".to_owned(),
            source_local_ordinal: None,
            evidence: None,
        });
        *process_diagnostic_count += 1;
    }
}

fn push_bounded_process_link(
    links: &mut Vec<EventProcessLink>,
    maximum: usize,
    link: EventProcessLink,
    diagnostics: &mut Vec<EventDiagnostic>,
    process_diagnostic_count: &mut usize,
    source_local_ordinal: Option<u64>,
    evidence: Option<EvidenceReference>,
) -> bool {
    if links.len() < maximum {
        links.push(link);
        true
    } else {
        push_process_diagnostic(
            diagnostics,
            process_diagnostic_count,
            "process_event_link_limit_reached",
            "event-to-process link limit reached; later links were omitted",
            source_local_ordinal,
            evidence,
        );
        false
    }
}

struct AdaptedLinuxTraceRow {
    process_id: Option<u32>,
    syscall: Option<String>,
    kind: TraceRecordKind,
    raw_result: Option<String>,
}

/// Adapt a parsed source document while validating every row reference against
/// the parser's source length and the row's retained source representation.
/// `artifact` is a stable label supplied by the caller and is never opened.
pub fn from_linux_strace(
    trace: &TraceDocument,
    source_bytes: &[u8],
    artifact: &str,
) -> CommonEventEnvelope {
    let process_lineage_matches_records =
        crate::trace::process_tree::derive_process_lineage(&trace.records) == trace.process_lineage;
    let mut events = Vec::with_capacity(trace.records.len().min(MAX_COMMON_EVENTS));
    let mut process_observations = Vec::new();
    let mut process_relationships = Vec::new();
    let mut event_process_links = Vec::new();
    let mut task_observations = BTreeMap::<u32, u64>::new();
    let mut adapted_evidence = HashMap::<(u64, u64, u64), AdaptedLinuxTraceRow>::new();
    let mut diagnostics = Vec::new();
    let mut process_diagnostic_count = 0;
    let mut source_state_diagnostics = trace
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect::<Vec<_>>();
    let mut process_relationships_partial = false;
    if process_lineage_matches_records {
        for diagnostic in &trace.process_lineage.diagnostics {
            source_state_diagnostics.push(diagnostic.code.to_owned());
            push_process_diagnostic(
                &mut diagnostics,
                &mut process_diagnostic_count,
                diagnostic.code,
                diagnostic.message,
                diagnostic
                    .evidence
                    .as_ref()
                    .map(|evidence| evidence.line_number),
                diagnostic
                    .evidence
                    .as_ref()
                    .map(|evidence| EvidenceReference::RawTraceRecord {
                        line_number: evidence.line_number,
                        byte_offset: evidence.byte_offset,
                        byte_length: evidence.byte_length,
                    }),
            );
        }
    } else {
        diagnostics.push(EventDiagnostic {
            code: "process_lineage_mismatch".to_owned(),
            message: "supplied process lineage does not match bounded derivation from the trace records; process relationships were rejected".to_owned(),
            source_local_ordinal: None,
            evidence: None,
        });
        source_state_diagnostics.push("process_lineage_mismatch".to_owned());
    }
    let artifact_valid = artifact.len() <= 256 && !artifact.chars().any(char::is_control);
    if !artifact_valid {
        diagnostics.push(EventDiagnostic {
            code: "invalid_artifact_label".to_owned(),
            message: "artifact label exceeds 256 UTF-8 bytes or contains a control character"
                .to_owned(),
            source_local_ordinal: None,
            evidence: None,
        });
        source_state_diagnostics.push("invalid_artifact_label".to_owned());
    }
    let mut previous_ordinal = 0_u64;
    let source_fingerprint_valid = source_bytes.len() as u64 == trace.input_bytes
        && is_sha256_hex(&trace.source_sha256)
        && format!("{:x}", sha2::Sha256::digest(source_bytes)) == trace.source_sha256;
    if !source_fingerprint_valid {
        diagnostics.push(EventDiagnostic {
            code: "source_fingerprint_mismatch".to_owned(),
            message: "raw trace bytes do not match the parsed document length and fingerprint"
                .to_owned(),
            source_local_ordinal: None,
            evidence: None,
        });
        source_state_diagnostics.push("source_fingerprint_mismatch".to_owned());
    }

    for (index, record) in trace.records.iter().enumerate() {
        let ordinal = index as u64 + 1;
        let evidence = EvidenceReference::RawTraceRecord {
            line_number: record.evidence.line_number,
            byte_offset: record.evidence.byte_offset,
            byte_length: record.evidence.byte_length,
        };
        let source_slice_matches = usize::try_from(record.evidence.byte_offset)
            .ok()
            .and_then(|start| {
                usize::try_from(record.evidence.byte_length)
                    .ok()
                    .and_then(|length| start.checked_add(length).map(|end| (start, end)))
            })
            .and_then(|(start, end)| source_bytes.get(start..end))
            .is_some_and(|slice| slice == record.raw_line.as_bytes());
        let line_number_matches = usize::try_from(record.evidence.byte_offset)
            .ok()
            .and_then(|start| source_bytes.get(..start))
            .and_then(|prefix| {
                u64::try_from(prefix.iter().filter(|byte| **byte == b'\n').count() + 1).ok()
            })
            .is_some_and(|expected_line| expected_line == record.evidence.line_number);
        let ref_valid = source_fingerprint_valid
            && source_slice_matches
            && line_number_matches
            && record.evidence.line_number > 0
            && record.evidence.line_number > previous_ordinal
            && record.evidence.byte_length == record.raw_line.len() as u64
            && record
                .evidence
                .byte_offset
                .checked_add(record.evidence.byte_length)
                .is_some_and(|end| end <= trace.input_bytes);
        if !ref_valid {
            diagnostics.push(EventDiagnostic {
                code: "invalid_evidence_reference".to_owned(),
                message: "strace row has an invalid line or byte reference".to_owned(),
                source_local_ordinal: Some(ordinal),
                evidence: Some(evidence),
            });
            source_state_diagnostics.push("invalid_evidence_reference".to_owned());
            continue;
        }
        previous_ordinal = record.evidence.line_number;

        if events.len() >= MAX_COMMON_EVENTS {
            diagnostics.push(EventDiagnostic {
                code: "event_limit_reached".to_owned(),
                message: "common envelope row limit reached; remaining rows were not adapted"
                    .to_owned(),
                source_local_ordinal: Some(ordinal),
                evidence: Some(evidence),
            });
            source_state_diagnostics.push("event_limit_reached".to_owned());
            break;
        }

        let event_kind = match record.kind {
            TraceRecordKind::Syscall => record.syscall.as_deref().map(str::to_owned),
            TraceRecordKind::UnfinishedSyscall => record
                .syscall
                .as_deref()
                .map(|name| format!("{name}:unfinished")),
            TraceRecordKind::ResumedSyscall => record
                .syscall
                .as_deref()
                .map(|name| format!("{name}:resumed")),
            TraceRecordKind::Control | TraceRecordKind::Unparsed => None,
        };
        let Some(event_kind) = event_kind else {
            diagnostics.push(EventDiagnostic {
                code: "unsupported_source_row".to_owned(),
                message: format!(
                    "strace row kind {:?} is retained as a diagnostic",
                    record.kind
                ),
                source_local_ordinal: Some(ordinal),
                evidence: Some(evidence),
            });
            source_state_diagnostics.push("unsupported_source_row".to_owned());
            continue;
        };

        let event = CommonEvent {
            source_local_ordinal: ordinal,
            source_timestamp: record.timestamp.as_ref().map(|value| SourceTimestamp {
                value: value.clone(),
                clock_unit: "strace_timestamp_decimal; unit not independently verified".to_owned(),
            }),
            event_kind,
            operation: OperationSemantics::SyscallAttempt {
                result: record.outcome,
            },
            evidence,
            identity_context: record.process_id.map(|pid| vec![EventIdentityContext {
                kind: "strace_process_id".to_owned(),
                value: pid.to_string(),
                ambiguity: "source-local tracing context; no ownership or cross-platform identity asserted".to_owned(),
            }]).unwrap_or_default(),
        };
        if let Some(task_id) = record.process_id {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                task_observations.entry(task_id)
            {
                if process_observations.len() < MAX_COMMON_PROCESS_OBSERVATIONS {
                    let id = process_observations.len() as u64 + 1;
                    process_observations.push(ProcessObservation {
                        source_local_id: id,
                        identity: ProcessIdentity::LinuxTraceTaskContext {
                            task_id,
                            identity_status: ProcessIdentityStatus::TaskIdOnlyGenerationUnknown,
                        },
                        evidence: event.evidence.clone(),
                        end_evidence: None,
                    });
                    entry.insert(id);
                } else {
                    push_process_diagnostic(
                        &mut diagnostics,
                        &mut process_diagnostic_count,
                        "process_observation_limit_reached",
                        "process observation limit reached; later task contexts were not linked",
                        Some(ordinal),
                        Some(event.evidence.clone()),
                    );
                    process_relationships_partial = true;
                }
            }
            if let Some(observation_id) = task_observations.get(&task_id).copied()
                && !push_bounded_process_link(
                    &mut event_process_links,
                    MAX_COMMON_EVENTS + MAX_COMMON_PROCESS_RELATIONS,
                    EventProcessLink {
                        event: event.evidence.clone(),
                        process_observation_id: Some(observation_id),
                        reported_process_id: None,
                        role: EventProcessLinkRole::LinuxTraceCallerTaskContext,
                        status: EventProcessLinkStatus::Observed,
                        basis: "strace_row_prefix_task_id_context_only".to_owned(),
                    },
                    &mut diagnostics,
                    &mut process_diagnostic_count,
                    Some(ordinal),
                    Some(event.evidence.clone()),
                )
            {
                process_relationships_partial = true;
            }
        }
        if let EvidenceReference::RawTraceRecord {
            line_number,
            byte_offset,
            byte_length,
        } = &event.evidence
        {
            adapted_evidence.insert(
                (*line_number, *byte_offset, *byte_length),
                AdaptedLinuxTraceRow {
                    process_id: record.process_id,
                    syscall: record.syscall.clone(),
                    kind: record.kind,
                    raw_result: record.raw_result.clone(),
                },
            );
        }
        events.push(event);
    }

    process_relationships_partial |=
        trace.process_lineage.partial || !process_lineage_matches_records;
    let validated_relation_count = if process_lineage_matches_records {
        trace.process_lineage.relations.len()
    } else {
        0
    };
    for relation in trace
        .process_lineage
        .relations
        .iter()
        .take(validated_relation_count)
    {
        if process_relationships.len() >= MAX_COMMON_PROCESS_RELATIONS
            || process_observations.len() >= MAX_COMMON_PROCESS_OBSERVATIONS
        {
            diagnostics.push(EventDiagnostic {
                code: "process_relationship_limit_reached".to_owned(),
                message: "common process relationship limit reached; remaining relations were not adapted".to_owned(),
                source_local_ordinal: None,
                evidence: None,
            });
            source_state_diagnostics.push("process_relationship_limit_reached".to_owned());
            process_relationships_partial = true;
            break;
        }
        let TraceEvidenceReference {
            line_number,
            byte_offset,
            byte_length,
        } = relation.evidence.clone();
        let Some(adapted_row) = adapted_evidence.get(&(line_number, byte_offset, byte_length))
        else {
            push_process_diagnostic(
                &mut diagnostics,
                &mut process_diagnostic_count,
                "invalid_process_relationship_reference",
                "strace process relation does not reference an adapted source row",
                Some(line_number),
                Some(EvidenceReference::RawTraceRecord {
                    line_number,
                    byte_offset,
                    byte_length,
                }),
            );
            source_state_diagnostics.push("invalid_process_relationship_reference".to_owned());
            process_relationships_partial = true;
            continue;
        };
        let result_pid = adapted_row
            .raw_result
            .as_deref()
            .and_then(parse_positive_process_id);
        let is_creation_syscall = adapted_row
            .syscall
            .as_deref()
            .is_some_and(is_process_creation_syscall);
        let complete_result_row = matches!(
            adapted_row.kind,
            TraceRecordKind::Syscall | TraceRecordKind::ResumedSyscall
        );
        if adapted_row.process_id != Some(relation.caller_task_id)
            || !is_creation_syscall
            || !complete_result_row
            || result_pid != Some(relation.child_pid)
        {
            push_process_diagnostic(
                &mut diagnostics,
                &mut process_diagnostic_count,
                "invalid_process_relationship_reference",
                "strace process relation does not match the referenced successful creation syscall result and caller task ID",
                Some(line_number),
                Some(EvidenceReference::RawTraceRecord {
                    line_number,
                    byte_offset,
                    byte_length,
                }),
            );
            source_state_diagnostics.push("invalid_process_relationship_reference".to_owned());
            process_relationships_partial = true;
            continue;
        }
        let mut relation_evidence = vec![EvidenceReference::RawTraceRecord {
            line_number,
            byte_offset,
            byte_length,
        }];
        let mut supporting_valid = relation.supporting_evidence.len() <= 1;
        for supporting in &relation.supporting_evidence {
            if relation_evidence.len() >= 3 {
                supporting_valid = false;
                break;
            }
            let key = (
                supporting.line_number,
                supporting.byte_offset,
                supporting.byte_length,
            );
            let Some(supporting_row) = adapted_evidence.get(&key) else {
                supporting_valid = false;
                break;
            };
            if adapted_row.kind != TraceRecordKind::ResumedSyscall
                || supporting_row.kind != TraceRecordKind::UnfinishedSyscall
                || supporting_row.process_id != adapted_row.process_id
                || supporting_row.process_id != Some(relation.caller_task_id)
                || supporting_row.syscall != adapted_row.syscall
                || !supporting_row
                    .syscall
                    .as_deref()
                    .is_some_and(is_process_creation_syscall)
            {
                supporting_valid = false;
                break;
            }
            relation_evidence.push(EvidenceReference::RawTraceRecord {
                line_number: supporting.line_number,
                byte_offset: supporting.byte_offset,
                byte_length: supporting.byte_length,
            });
        }
        if relation.supporting_evidence.is_empty() && adapted_row.kind != TraceRecordKind::Syscall {
            supporting_valid = false;
        }
        if !supporting_valid {
            push_process_diagnostic(
                &mut diagnostics,
                &mut process_diagnostic_count,
                "invalid_process_relationship_reference",
                "strace process relation has unsupported or unadapted supporting evidence",
                Some(line_number),
                Some(relation_evidence[0].clone()),
            );
            source_state_diagnostics.push("invalid_process_relationship_reference".to_owned());
            process_relationships_partial = true;
            continue;
        }
        let Some(from_observation_id) = task_observations.get(&relation.caller_task_id).copied()
        else {
            push_process_diagnostic(
                &mut diagnostics,
                &mut process_diagnostic_count,
                "invalid_process_relationship_reference",
                "strace process relation has no retained caller task observation",
                Some(line_number),
                Some(relation_evidence[0].clone()),
            );
            source_state_diagnostics.push("invalid_process_relationship_reference".to_owned());
            process_relationships_partial = true;
            continue;
        };
        let to_observation_id = process_observations.len() as u64 + 1;
        process_observations.push(ProcessObservation {
            source_local_id: to_observation_id,
            identity: ProcessIdentity::LinuxReturnedChildPid {
                process_id: relation.child_pid,
                identity_status: ProcessIdentityStatus::ReturnedChildPidOnly,
            },
            evidence: relation_evidence[0].clone(),
            end_evidence: None,
        });
        process_relationships.push(ProcessRelationship {
            kind: ProcessRelationshipKind::StraceCallerTaskReturnedChildPid,
            from_observation_id: Some(from_observation_id),
            to_observation_id,
            reported_from_process_id: None,
            resolution: RelationshipResolution::Observed,
            basis: "successful_strace_process_creation_syscall_returned_child_pid".to_owned(),
            evidence: relation_evidence.clone(),
        });
        if !push_bounded_process_link(
            &mut event_process_links,
            MAX_COMMON_EVENTS + MAX_COMMON_PROCESS_RELATIONS,
            EventProcessLink {
                event: EvidenceReference::RawTraceRecord {
                    line_number,
                    byte_offset,
                    byte_length,
                },
                process_observation_id: Some(to_observation_id),
                reported_process_id: None,
                role: EventProcessLinkRole::LinuxProcessCreationResult,
                status: EventProcessLinkStatus::Observed,
                basis: "successful_process_creation_result_row_reports_returned_child_pid"
                    .to_owned(),
            },
            &mut diagnostics,
            &mut process_diagnostic_count,
            Some(line_number),
            Some(relation_evidence[0].clone()),
        ) {
            process_relationships_partial = true;
        }
    }

    if trace.parse_status == ParseCompleteness::Partial {
        source_state_diagnostics.push("source_parse_partial".to_owned());
    }
    CommonEventEnvelope {
        schema: COMMON_EVENT_SCHEMA,
        schema_version: COMMON_EVENT_SCHEMA_VERSION,
        source: SourceDescriptor {
            platform: SourcePlatform::Linux,
            schema: "sideeffect.trace_inspection".to_owned(),
            schema_version: trace.schema_version,
            artifact: if artifact_valid {
                artifact.to_owned()
            } else {
                "invalid-artifact-label".to_owned()
            },
            sha256: source_fingerprint_valid.then(|| trace.source_sha256.clone()),
        },
        source_state: SourceState {
            completeness: if trace.parse_status == ParseCompleteness::Partial
                || !source_state_diagnostics.is_empty()
                || process_relationships_partial
            {
                SourceCompleteness::Partial
            } else {
                SourceCompleteness::Complete
            },
            diagnostics: source_state_diagnostics,
            loss: None,
            identity_ambiguity_present: events
                .iter()
                .any(|event| !event.identity_context.is_empty()),
        },
        events,
        process_observations,
        process_relationships,
        event_process_links,
        diagnostics,
    }
}

fn parse_positive_process_id(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let process_id = value.parse::<u32>().ok()?;
    (process_id > 0).then_some(process_id)
}

fn is_process_creation_syscall(syscall: &str) -> bool {
    syscall == "fork" || syscall == "vfork" || syscall == "clone" || syscall == "clone3"
}

#[cfg(windows)]
pub fn from_windows_etw(capture: &crate::record::WindowsRuntimeCapture) -> CommonEventEnvelope {
    from_windows_etw_source(capture)
}

#[cfg(windows)]
pub fn from_windows_runtime_capture(
    capture: &crate::windows_runtime::WindowsRuntimeCapture,
) -> CommonEventEnvelope {
    from_windows_etw_source(capture)
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EtwStopReason {
    TargetExited,
    DurationLimitReached,
    EventLimitReached,
    LossReported,
    StatisticsUnavailable,
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct EtwLossView {
    events_lost: u32,
    log_buffers_lost: u32,
    real_time_buffers_lost: u32,
    loss_statistics_available: bool,
    final_snapshot_available: bool,
}

#[cfg(windows)]
struct EtwEventView<'a> {
    record_ordinal: u64,
    provider_guid: &'a str,
    event_id: u16,
    event_version: u8,
    opcode: u8,
    event_kind: &'a str,
    header_process_id: u32,
    timestamp_qpc: i64,
    raw_payload_hex: &'a str,
    process_payload: Option<EtwProcessPayloadView<'a>>,
    observation_decoding: Option<&'a serde_json::Value>,
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct EtwProcessPayloadView<'a> {
    decoded: bool,
    schema_name: Option<&'a str>,
    schema_version: Option<u8>,
    pointer_size_bytes: Option<u8>,
    process_id: Option<u32>,
    parent_process_id: Option<u32>,
    image_file_name: Option<&'a str>,
}

#[cfg(windows)]
trait EtwCaptureView {
    fn document_sha256(&self) -> &str;
    fn collection_is_partial(&self) -> bool;
    fn capture_completeness(&self) -> &str;
    fn stop_reason(&self) -> EtwStopReason;
    fn event_loss(&self) -> EtwLossView;
    fn diagnostics(&self) -> &[String];
    fn event_count(&self) -> usize;
    fn event(&self, index: usize) -> Option<EtwEventView<'_>>;
}

#[cfg(windows)]
impl EtwCaptureView for crate::record::WindowsRuntimeCapture {
    fn document_sha256(&self) -> &str {
        &self.document_sha256
    }
    fn collection_is_partial(&self) -> bool {
        self.collection_status == crate::record::WindowsRuntimeCollectionStatus::Partial
    }
    fn capture_completeness(&self) -> &str {
        self.capture_completeness
    }
    fn stop_reason(&self) -> EtwStopReason {
        match self.stop_reason {
            crate::record::WindowsRuntimeStopReason::TargetExited => EtwStopReason::TargetExited,
            crate::record::WindowsRuntimeStopReason::DurationLimitReached => {
                EtwStopReason::DurationLimitReached
            }
            crate::record::WindowsRuntimeStopReason::EventLimitReached => {
                EtwStopReason::EventLimitReached
            }
            crate::record::WindowsRuntimeStopReason::EtwLossReported => EtwStopReason::LossReported,
            crate::record::WindowsRuntimeStopReason::EtwStatisticsUnavailable => {
                EtwStopReason::StatisticsUnavailable
            }
        }
    }
    fn event_loss(&self) -> EtwLossView {
        EtwLossView {
            events_lost: self.event_loss.events_lost,
            log_buffers_lost: self.event_loss.log_buffers_lost,
            real_time_buffers_lost: self.event_loss.real_time_buffers_lost,
            loss_statistics_available: self.event_loss.loss_statistics_available,
            final_snapshot_available: self.event_loss.final_snapshot_available,
        }
    }
    fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }
    fn event_count(&self) -> usize {
        self.events.len()
    }
    fn event(&self, index: usize) -> Option<EtwEventView<'_>> {
        let event = self.events.get(index)?;
        Some(EtwEventView {
            record_ordinal: event.record_ordinal,
            provider_guid: &event.provider_guid,
            event_id: event.event_id,
            event_version: event.event_version,
            opcode: event.opcode,
            event_kind: event.event_kind,
            header_process_id: event.header_process_id,
            timestamp_qpc: event.timestamp_qpc,
            raw_payload_hex: &event.raw_payload_hex,
            process_payload: event
                .payload_decoding
                .as_ref()
                .map(|payload| EtwProcessPayloadView {
                    decoded: payload.status == crate::record::WindowsRuntimeDecodeStatus::Decoded,
                    schema_name: payload.schema_name,
                    schema_version: payload.schema_version,
                    pointer_size_bytes: payload.pointer_size_bytes,
                    process_id: payload.process_id,
                    parent_process_id: payload.parent_process_id,
                    image_file_name: payload.image_file_name.as_deref(),
                }),
            observation_decoding: event.observation_decoding.as_ref(),
        })
    }
}

#[cfg(windows)]
impl EtwCaptureView for crate::windows_runtime::WindowsRuntimeCapture {
    fn document_sha256(&self) -> &str {
        &self.document_sha256
    }
    fn collection_is_partial(&self) -> bool {
        self.collection_status == crate::windows_runtime::CollectionStatus::Partial
    }
    fn capture_completeness(&self) -> &str {
        &self.capture_completeness
    }
    fn stop_reason(&self) -> EtwStopReason {
        match self.stop_reason {
            crate::windows_runtime::StopReason::TargetExited => EtwStopReason::TargetExited,
            crate::windows_runtime::StopReason::DurationLimitReached => {
                EtwStopReason::DurationLimitReached
            }
            crate::windows_runtime::StopReason::EventLimitReached => {
                EtwStopReason::EventLimitReached
            }
            crate::windows_runtime::StopReason::EtwLossReported => EtwStopReason::LossReported,
            crate::windows_runtime::StopReason::EtwStatisticsUnavailable => {
                EtwStopReason::StatisticsUnavailable
            }
        }
    }
    fn event_loss(&self) -> EtwLossView {
        EtwLossView {
            events_lost: self.event_loss.events_lost,
            log_buffers_lost: self.event_loss.log_buffers_lost,
            real_time_buffers_lost: self.event_loss.real_time_buffers_lost,
            loss_statistics_available: self.event_loss.loss_statistics_available,
            final_snapshot_available: self.event_loss.final_snapshot_available,
        }
    }
    fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }
    fn event_count(&self) -> usize {
        self.events.len()
    }
    fn event(&self, index: usize) -> Option<EtwEventView<'_>> {
        let event = self.events.get(index)?;
        Some(EtwEventView {
            record_ordinal: event.record_ordinal,
            provider_guid: &event.provider_guid,
            event_id: event.event_id,
            event_version: event.event_version,
            opcode: event.opcode,
            event_kind: &event.event_kind,
            header_process_id: event.header_process_id,
            timestamp_qpc: event.timestamp_qpc,
            raw_payload_hex: &event.raw_payload_hex,
            process_payload: event
                .payload_decoding
                .as_ref()
                .map(|payload| EtwProcessPayloadView {
                    decoded: payload.status == crate::windows_runtime::ProcessDecodeStatus::Decoded,
                    schema_name: payload.schema_name.as_deref(),
                    schema_version: payload.schema_version,
                    pointer_size_bytes: payload.pointer_size_bytes,
                    process_id: payload.process_id,
                    parent_process_id: payload.parent_process_id,
                    image_file_name: payload.image_file_name.as_deref(),
                }),
            observation_decoding: event.observation_decoding.as_ref(),
        })
    }
}

#[cfg(windows)]
fn from_windows_etw_source(capture: &impl EtwCaptureView) -> CommonEventEnvelope {
    use sha2::{Digest, Sha256};

    let mut events = Vec::with_capacity(capture.event_count().min(MAX_ETW_EVENTS));
    let mut process_observations = Vec::new();
    let mut process_relationships = Vec::new();
    let mut event_process_links = Vec::new();
    let mut adapted_event_evidence = BTreeMap::<u64, EvidenceReference>::new();
    let mut diagnostics = Vec::new();
    let mut source_diagnostics = capture
        .diagnostics()
        .iter()
        .take(MAX_CAPTURE_DIAGNOSTICS)
        .map(|diagnostic| truncate_utf8(diagnostic, MAX_CAPTURE_DIAGNOSTIC_BYTES))
        .collect::<Vec<String>>();
    let any_diagnostic_text_truncated = capture
        .diagnostics()
        .iter()
        .take(MAX_CAPTURE_DIAGNOSTICS)
        .any(|diagnostic| diagnostic.len() > MAX_CAPTURE_DIAGNOSTIC_BYTES);
    if capture.diagnostics().len() > MAX_CAPTURE_DIAGNOSTICS || any_diagnostic_text_truncated {
        source_diagnostics.push("source_diagnostics_truncated".to_owned());
    }
    let source_fingerprint_valid = is_sha256_hex(capture.document_sha256());
    if !source_fingerprint_valid {
        source_diagnostics.push("invalid_source_fingerprint".to_owned());
    }
    let mut payload_bytes = 0_usize;
    for index in 0..capture.event_count() {
        if index >= MAX_ETW_EVENTS {
            diagnostics.push(EventDiagnostic {
                code: "event_limit_reached".to_owned(),
                message: "ETW source exceeds the 50000 row adapter limit; remaining rows were not adapted".to_owned(),
                source_local_ordinal: Some(index as u64 + 1),
                evidence: None,
            });
            source_diagnostics.push("event_limit_reached".to_owned());
            break;
        }
        let Some(event) = capture.event(index) else {
            diagnostics.push(EventDiagnostic {
                code: "invalid_evidence_reference".to_owned(),
                message: "ETW source row is unavailable".to_owned(),
                source_local_ordinal: Some(index as u64 + 1),
                evidence: None,
            });
            source_diagnostics.push("invalid_evidence_reference".to_owned());
            continue;
        };
        let expected = index as u64 + 1;
        if event.record_ordinal != expected {
            diagnostics.push(EventDiagnostic {
                code: "invalid_evidence_reference".to_owned(),
                message: "ETW event ordinal does not match its source row".to_owned(),
                source_local_ordinal: Some(event.record_ordinal),
                evidence: None,
            });
            source_diagnostics.push("invalid_evidence_reference".to_owned());
            continue;
        }
        if event.raw_payload_hex.len() > MAX_ETW_PAYLOAD_BYTES_PER_EVENT * 2 {
            diagnostics.push(EventDiagnostic {
                code: "payload_size_limit_exceeded".to_owned(),
                message: "ETW event exceeds the 64 KiB payload adapter limit".to_owned(),
                source_local_ordinal: Some(expected),
                evidence: None,
            });
            source_diagnostics.push("payload_size_limit_exceeded".to_owned());
            continue;
        }
        if event.raw_payload_hex.len() % 2 != 0 {
            diagnostics.push(EventDiagnostic {
                code: "invalid_raw_payload".to_owned(),
                message: "ETW event payload hex has an odd number of characters".to_owned(),
                source_local_ordinal: Some(expected),
                evidence: None,
            });
            source_diagnostics.push("invalid_raw_payload".to_owned());
            continue;
        }
        let decoded_payload_length = event.raw_payload_hex.len() / 2;
        let Some(total_payload_bytes) = payload_bytes.checked_add(decoded_payload_length) else {
            diagnostics.push(EventDiagnostic {
                code: "payload_byte_limit_exceeded".to_owned(),
                message: "ETW payload byte total overflowed the adapter budget".to_owned(),
                source_local_ordinal: Some(expected),
                evidence: None,
            });
            source_diagnostics.push("payload_byte_limit_exceeded".to_owned());
            break;
        };
        if total_payload_bytes > MAX_ETW_PAYLOAD_BYTES {
            diagnostics.push(EventDiagnostic {
                code: "payload_byte_limit_exceeded".to_owned(),
                message: "ETW source exceeds the 8 MiB aggregate payload adapter limit; remaining rows were not adapted".to_owned(),
                source_local_ordinal: Some(expected),
                evidence: None,
            });
            source_diagnostics.push("payload_byte_limit_exceeded".to_owned());
            break;
        }
        payload_bytes = total_payload_bytes;
        let bytes = match decode_hex(event.raw_payload_hex) {
            Some(bytes) => bytes,
            None => {
                diagnostics.push(EventDiagnostic {
                    code: "invalid_raw_payload".to_owned(),
                    message: "ETW raw payload is not valid hexadecimal".to_owned(),
                    source_local_ordinal: Some(expected),
                    evidence: None,
                });
                source_diagnostics.push("invalid_raw_payload".to_owned());
                continue;
            }
        };
        let raw_payload_sha256 = format!("{:x}", Sha256::digest(bytes));
        let evidence = EvidenceReference::WindowsEtwRecord {
            record_ordinal: expected,
            json_pointer: format!("/events/{}", index),
            raw_payload_sha256,
        };
        let identity_context = vec![EventIdentityContext {
            kind: "etw_header_process_id_context".to_owned(),
            value: event.header_process_id.to_string(),
            ambiguity:
                "ETW event-header context only; it may not identify the payload subject or an owner"
                    .to_owned(),
        }];
        adapted_event_evidence.insert(expected, evidence.clone());
        events.push(CommonEvent {
            source_local_ordinal: expected,
            source_timestamp: Some(SourceTimestamp {
                value: event.timestamp_qpc.to_string(),
                clock_unit: "ETW_QPC_ticks".to_owned(),
            }),
            event_kind: event.event_kind.to_owned(),
            operation: OperationSemantics::NativeObservation,
            evidence,
            identity_context,
        });
    }
    let loss = capture.event_loss();
    let generation_evidence_unreliable = loss.events_lost > 0
        || loss.log_buffers_lost > 0
        || loss.real_time_buffers_lost > 0
        || !loss.loss_statistics_available
        || !loss.final_snapshot_available
        || capture.stop_reason() == EtwStopReason::LossReported;
    let process_relationships_partial = derive_windows_process_relationships(
        capture,
        &adapted_event_evidence,
        generation_evidence_unreliable,
        &mut process_observations,
        &mut process_relationships,
        &mut event_process_links,
        &mut diagnostics,
    );
    if process_relationships_partial {
        source_diagnostics.push("process_relationship_adaptation_partial".to_owned());
    }
    let loss_metadata = Some(LossMetadata {
        reported_events_lost: u64::from(loss.events_lost),
        reported_buffers_lost: u64::from(loss.log_buffers_lost)
            + u64::from(loss.real_time_buffers_lost),
        statistics_available: loss.loss_statistics_available && loss.final_snapshot_available,
    });
    if capture.collection_is_partial() {
        source_diagnostics.push("windows_etw_collection_partial".to_owned());
    }
    let has_losses =
        loss.events_lost > 0 || loss.log_buffers_lost > 0 || loss.real_time_buffers_lost > 0;
    if has_losses {
        source_diagnostics.push("windows_etw_loss_reported".to_owned());
    }
    if !loss.loss_statistics_available || !loss.final_snapshot_available {
        source_diagnostics.push("windows_etw_loss_statistics_incomplete".to_owned());
    }
    let loss_statistics_complete = loss.loss_statistics_available && loss.final_snapshot_available;
    let statistics_unavailable_only = !loss_statistics_complete
        && capture.stop_reason() == EtwStopReason::StatisticsUnavailable
        && capture
            .diagnostics()
            .iter()
            .take(MAX_CAPTURE_DIAGNOSTICS)
            .all(|diagnostic| {
                matches!(
                    diagnostic.as_str(),
                    "etw_loss_statistics_unavailable" | "etw_final_loss_statistics_unavailable"
                )
            });
    let has_other_capture_diagnostic = capture
        .diagnostics()
        .iter()
        .take(MAX_CAPTURE_DIAGNOSTICS)
        .any(|diagnostic| {
            !matches!(
                diagnostic.as_str(),
                "etw_loss_statistics_unavailable" | "etw_final_loss_statistics_unavailable"
            )
        });
    let known_partial_reason = has_losses
        || matches!(
            capture.stop_reason(),
            EtwStopReason::DurationLimitReached
                | EtwStopReason::EventLimitReached
                | EtwStopReason::LossReported
        )
        || has_other_capture_diagnostic
        || (capture.collection_is_partial() && !statistics_unavailable_only)
        || !diagnostics.is_empty()
        || process_relationships_partial
        || !source_fingerprint_valid
        || capture.diagnostics().len() > MAX_CAPTURE_DIAGNOSTICS;
    let completeness = if known_partial_reason {
        SourceCompleteness::Partial
    } else if capture.capture_completeness() == "complete" && loss_statistics_complete {
        SourceCompleteness::Complete
    } else {
        SourceCompleteness::Unknown
    };
    CommonEventEnvelope {
        schema: COMMON_EVENT_SCHEMA,
        schema_version: COMMON_EVENT_SCHEMA_VERSION,
        source: SourceDescriptor {
            platform: SourcePlatform::Windows,
            schema: WINDOWS_RUNTIME_SCHEMA.to_owned(),
            schema_version: WINDOWS_RUNTIME_SCHEMA_VERSION,
            artifact: "runtime.windows.json".to_owned(),
            sha256: source_fingerprint_valid
                .then(|| capture.document_sha256().to_ascii_lowercase()),
        },
        source_state: SourceState {
            completeness,
            diagnostics: source_diagnostics,
            loss: loss_metadata,
            identity_ambiguity_present: !events.is_empty(),
        },
        events,
        process_observations,
        process_relationships,
        event_process_links,
        diagnostics,
    }
}

#[cfg(windows)]
struct ActiveWindowsProcess {
    observation_index: usize,
    parent_process_id: u32,
    image_file_name: String,
}

#[cfg(windows)]
fn derive_windows_process_relationships(
    capture: &impl EtwCaptureView,
    adapted_event_evidence: &BTreeMap<u64, EvidenceReference>,
    generation_evidence_unreliable: bool,
    observations: &mut Vec<ProcessObservation>,
    relationships: &mut Vec<ProcessRelationship>,
    links: &mut Vec<EventProcessLink>,
    diagnostics: &mut Vec<EventDiagnostic>,
) -> bool {
    let mut active = BTreeMap::<u32, ActiveWindowsProcess>::new();
    let mut ambiguous_pids = BTreeSet::<u32>::new();
    let mut lifecycle_unknown_pids = BTreeSet::<u32>::new();
    let mut process_diagnostic_count = 0;
    let mut partial = false;

    for index in 0..capture.event_count().min(MAX_ETW_EVENTS) {
        let Some(event) = capture.event(index) else {
            continue;
        };
        let Some(event_evidence) = adapted_event_evidence.get(&event.record_ordinal).cloned()
        else {
            continue;
        };

        if event.event_kind == "process_start" {
            let Some(payload) = validated_process_payload(&event, "process_start") else {
                invalidate_active_windows_instances(
                    &mut active,
                    &mut lifecycle_unknown_pids,
                    observations,
                    relationships,
                    links,
                );
                if let Some(process_id) = event
                    .process_payload
                    .and_then(|payload| payload.process_id)
                    .filter(|process_id| *process_id > 0)
                {
                    lifecycle_unknown_pids.insert(process_id);
                }
                push_process_diagnostic(
                    diagnostics,
                    &mut process_diagnostic_count,
                    "process_start_payload_unavailable",
                    "process-start row lacks a supported, validated process payload; active lifecycle continuity is unknown",
                    Some(event.record_ordinal),
                    Some(event_evidence),
                );
                partial = true;
                continue;
            };
            let process_id = payload.process_id.expect("validated process ID");
            let parent_id = payload
                .parent_process_id
                .expect("validated parent process ID");
            let image = payload.image_file_name.expect("validated image name");
            let existing = active.remove(&process_id);
            let previously_ambiguous = ambiguous_pids.contains(&process_id);
            let identity_status = if existing.is_some() || ambiguous_pids.contains(&process_id) {
                if let Some(existing) = existing {
                    mark_windows_observation_unresolved(
                        observations,
                        existing.observation_index,
                        if generation_evidence_unreliable && !previously_ambiguous {
                            ProcessIdentityStatus::LifecycleContinuityUnknown
                        } else {
                            ProcessIdentityStatus::AmbiguousPidReuse
                        },
                        relationships,
                        links,
                    );
                }
                if generation_evidence_unreliable && !previously_ambiguous {
                    lifecycle_unknown_pids.insert(process_id);
                    push_process_diagnostic(
                        diagnostics,
                        &mut process_diagnostic_count,
                        "process_lifecycle_continuity_unknown",
                        "reported ETW loss or unavailable loss statistics prevents PID generation resolution",
                        Some(event.record_ordinal),
                        Some(event_evidence.clone()),
                    );
                    partial = true;
                    ProcessIdentityStatus::LifecycleContinuityUnknown
                } else {
                    ambiguous_pids.insert(process_id);
                    push_process_diagnostic(
                        diagnostics,
                        &mut process_diagnostic_count,
                        "process_pid_reuse_ambiguous",
                        "overlapping or previously ambiguous PID prevents a unique process instance",
                        Some(event.record_ordinal),
                        Some(event_evidence.clone()),
                    );
                    partial = true;
                    ProcessIdentityStatus::AmbiguousPidReuse
                }
            } else if generation_evidence_unreliable || lifecycle_unknown_pids.contains(&process_id)
            {
                lifecycle_unknown_pids.insert(process_id);
                ProcessIdentityStatus::LifecycleContinuityUnknown
            } else {
                ProcessIdentityStatus::ObservedStart
            };
            if observations.len() >= MAX_ETW_EVENTS {
                push_process_diagnostic(
                    diagnostics,
                    &mut process_diagnostic_count,
                    "process_observation_limit_reached",
                    "process observation limit reached; remaining lifecycle rows were not linked",
                    Some(event.record_ordinal),
                    Some(event_evidence),
                );
                partial = true;
                break;
            }
            let observation_id = observations.len() as u64 + 1;
            observations.push(ProcessObservation {
                source_local_id: observation_id,
                identity: ProcessIdentity::WindowsProcessInstance {
                    process_id,
                    start_record_ordinal: event.record_ordinal,
                    reported_parent_process_id: Some(parent_id),
                    identity_status,
                },
                evidence: event_evidence.clone(),
                end_evidence: None,
            });
            if identity_status == ProcessIdentityStatus::AmbiguousPidReuse {
                continue;
            }
            if identity_status == ProcessIdentityStatus::ObservedStart {
                active.insert(
                    process_id,
                    ActiveWindowsProcess {
                        observation_index: usize::try_from(observation_id - 1)
                            .expect("bounded process observation index"),
                        parent_process_id: parent_id,
                        image_file_name: image.to_owned(),
                    },
                );
            }
            if !push_bounded_process_link(
                links,
                MAX_ETW_EVENTS,
                EventProcessLink {
                    event: event_evidence.clone(),
                    process_observation_id: Some(observation_id),
                    reported_process_id: None,
                    role: EventProcessLinkRole::WindowsProcessStartPayload,
                    status: EventProcessLinkStatus::Observed,
                    basis: "validated_process_start_payload_identifies_new_process_instance"
                        .to_owned(),
                },
                diagnostics,
                &mut process_diagnostic_count,
                Some(event.record_ordinal),
                Some(event_evidence.clone()),
            ) {
                partial = true;
            }

            if relationships.len() >= MAX_ETW_EVENTS {
                push_process_diagnostic(
                    diagnostics,
                    &mut process_diagnostic_count,
                    "process_relationship_limit_reached",
                    "process relationship limit reached; remaining parent links were not emitted",
                    Some(event.record_ordinal),
                    Some(event_evidence),
                );
                partial = true;
                break;
            }
            if parent_id > 0 {
                let resolved_parent = if generation_evidence_unreliable
                    || ambiguous_pids.contains(&parent_id)
                    || lifecycle_unknown_pids.contains(&parent_id)
                {
                    None
                } else {
                    active
                        .get(&parent_id)
                        .map(|process| process.observation_index)
                };
                let resolution = if ambiguous_pids.contains(&parent_id) {
                    RelationshipResolution::ParentPidAmbiguous
                } else if generation_evidence_unreliable
                    || lifecycle_unknown_pids.contains(&parent_id)
                {
                    RelationshipResolution::ParentInstanceUnresolved
                } else if resolved_parent.is_some() && parent_id != process_id {
                    RelationshipResolution::Observed
                } else {
                    RelationshipResolution::ParentInstanceUnresolved
                };
                let from_observation_id = resolved_parent
                    .filter(|_| resolution == RelationshipResolution::Observed)
                    .map(|parent_index| parent_index as u64 + 1);
                let mut evidence = vec![event_evidence.clone()];
                if let Some(parent_index) =
                    resolved_parent.filter(|_| from_observation_id.is_some())
                {
                    evidence.push(observations[parent_index].evidence.clone());
                }
                relationships.push(ProcessRelationship {
                    kind: ProcessRelationshipKind::WindowsPayloadParentToChildInstance,
                    from_observation_id,
                    to_observation_id: observation_id,
                    reported_from_process_id: Some(parent_id),
                    resolution,
                    basis: if resolution == RelationshipResolution::Observed {
                        "validated_parent_pid_matches_one_active_process_start_instance".to_owned()
                    } else if resolution == RelationshipResolution::ParentPidAmbiguous {
                        "validated_parent_pid_is_ambiguous_in_capture".to_owned()
                    } else if generation_evidence_unreliable {
                        "reported_etw_loss_or_unavailable_loss_statistics_prevents_unique_parent_instance_resolution".to_owned()
                    } else if lifecycle_unknown_pids.contains(&parent_id) {
                        "invalid_or_unsupported_lifecycle_row_prevents_unique_parent_instance_resolution".to_owned()
                    } else {
                        "validated_parent_pid_has_no_unique_active_process_start_instance"
                            .to_owned()
                    },
                    evidence,
                });
            }
            continue;
        }

        if event.event_kind == "process_end" {
            let Some(payload) = validated_process_payload(&event, "process_end") else {
                invalidate_active_windows_instances(
                    &mut active,
                    &mut lifecycle_unknown_pids,
                    observations,
                    relationships,
                    links,
                );
                push_process_diagnostic(
                    diagnostics,
                    &mut process_diagnostic_count,
                    "process_end_payload_unavailable",
                    "unsupported process-end row breaks lifecycle continuity; active instances are no longer linked",
                    Some(event.record_ordinal),
                    Some(event_evidence),
                );
                partial = true;
                continue;
            };
            let process_id = payload.process_id.expect("validated process ID");
            let parent_id = payload
                .parent_process_id
                .expect("validated parent process ID");
            let image = payload.image_file_name.expect("validated image name");
            if ambiguous_pids.contains(&process_id)
                || lifecycle_unknown_pids.contains(&process_id)
                || generation_evidence_unreliable
            {
                if !push_bounded_process_link(
                    links,
                    MAX_ETW_EVENTS,
                    EventProcessLink {
                        event: event_evidence.clone(),
                        process_observation_id: None,
                        reported_process_id: Some(process_id),
                        role: EventProcessLinkRole::WindowsProcessEndPayload,
                        status: EventProcessLinkStatus::Unresolved,
                        basis: if generation_evidence_unreliable {
                            "reported_etw_loss_or_unavailable_loss_statistics_prevents_instance_end_resolution".to_owned()
                        } else if ambiguous_pids.contains(&process_id) {
                            "process_end_pid_has_ambiguous_process_instances".to_owned()
                        } else {
                            "invalid_or_unsupported_lifecycle_row_prevents_instance_end_resolution"
                                .to_owned()
                        },
                    },
                    diagnostics,
                    &mut process_diagnostic_count,
                    Some(event.record_ordinal),
                    Some(event_evidence),
                ) {
                    partial = true;
                }
                continue;
            }
            if let Some(process) = active.remove(&process_id) {
                if process.parent_process_id == parent_id && process.image_file_name == image {
                    observations[process.observation_index].end_evidence =
                        Some(event_evidence.clone());
                    if !push_bounded_process_link(
                        links,
                        MAX_ETW_EVENTS,
                        EventProcessLink {
                            event: event_evidence.clone(),
                            process_observation_id: Some(process.observation_index as u64 + 1),
                            reported_process_id: None,
                            role: EventProcessLinkRole::WindowsProcessEndPayload,
                            status: EventProcessLinkStatus::Observed,
                            basis: "validated_process_end_pid_parent_and_image_match_active_start"
                                .to_owned(),
                        },
                        diagnostics,
                        &mut process_diagnostic_count,
                        Some(event.record_ordinal),
                        Some(event_evidence.clone()),
                    ) {
                        partial = true;
                    }
                } else {
                    lifecycle_unknown_pids.insert(process_id);
                    mark_windows_observation_unresolved(
                        observations,
                        process.observation_index,
                        ProcessIdentityStatus::LifecycleContinuityUnknown,
                        relationships,
                        links,
                    );
                    push_process_diagnostic(
                        diagnostics,
                        &mut process_diagnostic_count,
                        "process_end_identity_mismatch",
                        "process-end payload does not match the active process start identity",
                        Some(event.record_ordinal),
                        Some(event_evidence),
                    );
                    partial = true;
                }
            }
            continue;
        }

        if let Some(process_id) = validated_network_payload_pid(&event) {
            let unique_process = if generation_evidence_unreliable
                || ambiguous_pids.contains(&process_id)
                || lifecycle_unknown_pids.contains(&process_id)
            {
                None
            } else {
                active.get(&process_id)
            };
            let (process_observation_id, status, basis) = if let Some(process) = unique_process {
                (
                    Some(process.observation_index as u64 + 1),
                    EventProcessLinkStatus::Observed,
                    "documented_network_payload_pid_matches_active_process_instance",
                )
            } else if generation_evidence_unreliable {
                (
                    None,
                    EventProcessLinkStatus::Unresolved,
                    "reported_etw_loss_or_unavailable_loss_statistics_prevents_unique_process_instance_resolution",
                )
            } else if ambiguous_pids.contains(&process_id) {
                (
                    None,
                    EventProcessLinkStatus::Unresolved,
                    "documented_network_payload_pid_has_ambiguous_process_instances",
                )
            } else if lifecycle_unknown_pids.contains(&process_id) {
                (
                    None,
                    EventProcessLinkStatus::Unresolved,
                    "documented_network_payload_pid_has_unknown_lifecycle_continuity",
                )
            } else {
                (
                    None,
                    EventProcessLinkStatus::Unresolved,
                    "documented_network_payload_pid_has_no_observed_process_start_instance",
                )
            };
            if !push_bounded_process_link(
                links,
                MAX_ETW_EVENTS,
                EventProcessLink {
                    event: event_evidence.clone(),
                    process_observation_id,
                    reported_process_id: process_observation_id.is_none().then_some(process_id),
                    role: EventProcessLinkRole::WindowsNetworkPayloadPid,
                    status,
                    basis: basis.to_owned(),
                },
                diagnostics,
                &mut process_diagnostic_count,
                Some(event.record_ordinal),
                Some(event_evidence.clone()),
            ) {
                partial = true;
            }
        } else if is_file_or_disk_observation(&event)
            && event.header_process_id > 0
            && !ambiguous_pids.contains(&event.header_process_id)
            && !lifecycle_unknown_pids.contains(&event.header_process_id)
        {
            if let Some(process) = active.get(&event.header_process_id) {
                if !push_bounded_process_link(
                    links,
                    MAX_ETW_EVENTS,
                    EventProcessLink {
                        event: event_evidence.clone(),
                        process_observation_id: Some(process.observation_index as u64 + 1),
                        reported_process_id: None,
                        role: EventProcessLinkRole::WindowsFileDiskHeaderPidContextCandidate,
                        status: EventProcessLinkStatus::ContextCandidate,
                        basis:
                            "file_or_disk_header_pid_matches_active_process_but_remains_context_only"
                                .to_owned(),
                    },
                    diagnostics,
                    &mut process_diagnostic_count,
                    Some(event.record_ordinal),
                    Some(event_evidence),
                ) {
                    partial = true;
                }
            }
        }
    }
    partial
}

#[cfg(windows)]
fn invalidate_active_windows_instances(
    active: &mut BTreeMap<u32, ActiveWindowsProcess>,
    lifecycle_unknown_pids: &mut BTreeSet<u32>,
    observations: &mut [ProcessObservation],
    relationships: &mut [ProcessRelationship],
    links: &mut [EventProcessLink],
) {
    for (process_id, process) in std::mem::take(active) {
        lifecycle_unknown_pids.insert(process_id);
        mark_windows_observation_unresolved(
            observations,
            process.observation_index,
            ProcessIdentityStatus::LifecycleContinuityUnknown,
            relationships,
            links,
        );
    }
}

#[cfg(windows)]
fn mark_windows_observation_unresolved(
    observations: &mut [ProcessObservation],
    index: usize,
    new_identity_status: ProcessIdentityStatus,
    relationships: &mut [ProcessRelationship],
    links: &mut [EventProcessLink],
) {
    let Some(ProcessObservation {
        identity:
            ProcessIdentity::WindowsProcessInstance {
                process_id,
                identity_status,
                ..
            },
        ..
    }) = observations.get_mut(index)
    else {
        return;
    };
    *identity_status = new_identity_status;
    let observation_id = index as u64 + 1;
    let observed_reuse = new_identity_status == ProcessIdentityStatus::AmbiguousPidReuse;
    for relationship in relationships {
        if relationship.to_observation_id == observation_id {
            relationship.resolution = if observed_reuse {
                RelationshipResolution::ProcessInstanceAmbiguous
            } else {
                RelationshipResolution::ProcessInstanceUnresolved
            };
        }
        if relationship.from_observation_id == Some(observation_id) {
            relationship.from_observation_id = None;
            relationship.resolution = if observed_reuse {
                RelationshipResolution::ParentPidAmbiguous
            } else {
                RelationshipResolution::ParentInstanceUnresolved
            };
        }
    }
    for link in links {
        if link.process_observation_id != Some(observation_id)
            || link.role == EventProcessLinkRole::WindowsProcessStartPayload
        {
            continue;
        }
        link.process_observation_id = None;
        link.reported_process_id = Some(*process_id);
        if link.role == EventProcessLinkRole::WindowsNetworkPayloadPid {
            link.status = EventProcessLinkStatus::Unresolved;
        }
    }
}

#[cfg(windows)]
fn validated_process_payload<'a>(
    event: &EtwEventView<'a>,
    expected_kind: &str,
) -> Option<EtwProcessPayloadView<'a>> {
    const PROCESS_PROVIDER_GUID: &str = "3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c";
    let payload = event.process_payload?;
    let process_id = payload.process_id?;
    let parent_id = payload.parent_process_id?;
    let image = payload.image_file_name?;
    if normalized_guid(event.provider_guid).as_deref() != Some(PROCESS_PROVIDER_GUID)
        || event.event_id != 0
        || event.event_kind != expected_kind
        || (expected_kind == "process_start" && event.opcode != 1)
        || (expected_kind == "process_end" && event.opcode != 2)
        || !payload.decoded
        || !matches!(
            (payload.schema_name, payload.schema_version),
            (Some("windows.kernel_process_typegroup1"), Some(version))
                if version == event.event_version
        ) && !matches!(
            (payload.schema_name, payload.schema_version),
            (Some("Process_V2_TypeGroup1"), Some(2))
        )
        || event.event_version > 3
        || !matches!(payload.pointer_size_bytes, Some(4 | 8))
        || process_id == 0
        || image.is_empty()
    {
        return None;
    }
    let _ = parent_id;
    Some(payload)
}

#[cfg(windows)]
fn normalized_guid(value: &str) -> Option<String> {
    let value = value.trim();
    let value = value
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(value);
    (value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        }))
    .then(|| value.to_ascii_lowercase())
}

#[cfg(windows)]
fn validated_network_payload_pid(event: &EtwEventView<'_>) -> Option<u32> {
    let value = event.observation_decoding?;
    if value.get("status").and_then(serde_json::Value::as_str) != Some("decoded")
        || value
            .pointer("/observation/activity/kind")
            .and_then(serde_json::Value::as_str)
            != Some("network")
        || value
            .pointer("/observation/schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(2)
        || event.event_kind != "network_observation"
        || event.event_id != 0
        || event.event_version != 2
    {
        return None;
    }
    let schema = value.pointer("/observation/schema")?.as_str()?;
    let guid = normalized_guid(event.provider_guid)?;
    let supported = match guid.as_str() {
        "9a280ac0-c8e0-11d1-84e2-00c04fb998a2" => match event.opcode {
            10 => schema == "windows.kernel_tcp_ipv4_send",
            11 | 13 | 14 | 16 | 18 => schema == "windows.kernel_tcp_ipv4_typegroup1",
            12 | 15 => schema == "windows.kernel_tcp_ipv4_typegroup2",
            26 => schema == "windows.kernel_tcp_ipv6_send",
            27 | 29 | 30 | 32 | 34 => schema == "windows.kernel_tcp_ipv6_typegroup3",
            28 | 31 => schema == "windows.kernel_tcp_ipv6_typegroup4",
            _ => false,
        },
        "bf3a50c5-a9c9-4988-a005-2df0b7c80f80" => match event.opcode {
            10 | 11 => schema == "windows.kernel_udp_ipv4_typegroup1",
            26 | 27 => schema == "windows.kernel_udp_ipv6_typegroup2",
            _ => false,
        },
        _ => false,
    };
    if !supported {
        return None;
    }
    value
        .pointer("/observation/activity/observation/payload_process_id")?
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
}

#[cfg(windows)]
fn is_file_or_disk_observation(event: &EtwEventView<'_>) -> bool {
    let Some(value) = event.observation_decoding else {
        return false;
    };
    if value.get("status").and_then(serde_json::Value::as_str) != Some("decoded") {
        return false;
    }
    let schema = value
        .pointer("/observation/schema")
        .and_then(serde_json::Value::as_str);
    let schema_version = value
        .pointer("/observation/schema_version")
        .and_then(serde_json::Value::as_u64);
    let activity = value
        .pointer("/observation/activity/kind")
        .and_then(serde_json::Value::as_str);
    let guid = normalized_guid(event.provider_guid);
    matches!(
        (guid.as_deref(), activity, schema, schema_version, event.event_id, event.event_version, event.opcode),
        (Some("90cbdc39-4a3e-11d1-84f4-0000f80464e3"), Some("file"), Some("windows.kernel_file_io"), Some(2), 0, 2, 0 | 32 | 35 | 36 | 64 | 65 | 66 | 67 | 68 | 69 | 70 | 71 | 73 | 74 | 75)
            if event.event_kind == "file_io_observation"
    ) || matches!(
        (guid.as_deref(), activity, schema, schema_version, event.event_id, event.event_version, event.opcode),
        (Some("3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c"), Some("disk"), Some("windows.kernel_disk_io"), Some(0), 0, 0, 10 | 11 | 14)
            if event.event_kind == "disk_io_observation"
    )
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(windows)]
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            Some(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect()
}

#[cfg(windows)]
fn truncate_utf8(value: &str, maximum_bytes: usize) -> String {
    let mut end = value.len().min(maximum_bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
