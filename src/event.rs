//! Versioned common event envelope over source-native runtime evidence.
//!
//! Adapters preserve local positions and clocks. They do not establish a
//! cross-platform clock, causal relation, parentage, or process ownership.

use serde::Serialize;
use sha2::Digest;

use crate::model::{ParseCompleteness, SyscallOutcome, TraceDocument, TraceRecordKind};

pub const COMMON_EVENT_SCHEMA: &str = "sideeffect.common_event_envelope";
pub const COMMON_EVENT_SCHEMA_VERSION: u32 = 1;
#[cfg(windows)]
const WINDOWS_RUNTIME_SCHEMA: &str = "sideeffect.windows_runtime_capture";
#[cfg(windows)]
const WINDOWS_RUNTIME_SCHEMA_VERSION: u32 = 3;
const MAX_COMMON_EVENTS: usize = 100_000;
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommonEventEnvelope {
    pub schema: &'static str,
    pub schema_version: u32,
    pub source: SourceDescriptor,
    pub source_state: SourceState,
    pub events: Vec<CommonEvent>,
    /// Unsupported or invalid source rows remain visible here.
    pub diagnostics: Vec<EventDiagnostic>,
}

/// Adapt a parsed source document while validating every row reference against
/// the parser's source length and the row's retained source representation.
/// `artifact` is a stable label supplied by the caller and is never opened.
pub fn from_linux_strace(
    trace: &TraceDocument,
    source_bytes: &[u8],
    artifact: &str,
) -> CommonEventEnvelope {
    let mut events = Vec::with_capacity(trace.records.len().min(MAX_COMMON_EVENTS));
    let mut diagnostics = Vec::new();
    let mut source_state_diagnostics = trace
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect::<Vec<_>>();
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

        events.push(CommonEvent {
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
        });
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
        diagnostics,
    }
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
    event_kind: &'a str,
    header_process_id: u32,
    timestamp_qpc: i64,
    raw_payload_hex: &'a str,
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
            event_kind: event.event_kind,
            header_process_id: event.header_process_id,
            timestamp_qpc: event.timestamp_qpc,
            raw_payload_hex: &event.raw_payload_hex,
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
            event_kind: &event.event_kind,
            header_process_id: event.header_process_id,
            timestamp_qpc: event.timestamp_qpc,
            raw_payload_hex: &event.raw_payload_hex,
        })
    }
}

#[cfg(windows)]
fn from_windows_etw_source(capture: &impl EtwCaptureView) -> CommonEventEnvelope {
    use sha2::{Digest, Sha256};

    let mut events = Vec::with_capacity(capture.event_count().min(MAX_ETW_EVENTS));
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
        diagnostics,
    }
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
