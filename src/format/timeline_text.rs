use std::io::{self, Write};

use crate::event::{
    EventProcessLink, EventTimeline, EvidenceReference, OperationSemantics, ProcessIdentity,
    ProcessObservation, SourceCompleteness,
};

pub const MAX_TIMELINE_TEXT_BYTES: usize = 8 * 1024 * 1024;

/// Render a bounded ASCII-only terminal review of a source-local event timeline.
pub fn write_timeline_text<W: Write>(timeline: &EventTimeline, writer: &mut W) -> io::Result<()> {
    let mut output = TimelineBuffer::default();
    render(timeline, &mut output)?;
    writer.write_all(&output.bytes)
}

fn render(timeline: &EventTimeline, output: &mut TimelineBuffer) -> io::Result<()> {
    output.raw("SideEffect source-local timeline\nSource: platform=")?;
    output.escaped(&format!("{:?}", timeline.source.platform).to_ascii_lowercase())?;
    output.raw(" schema=")?;
    output.escaped(&timeline.source.schema)?;
    output.raw(" version=")?;
    output.number(timeline.source.schema_version)?;
    output.raw(" artifact=")?;
    output.escaped(&timeline.source.artifact)?;
    output.raw(" sha256=")?;
    match &timeline.source.sha256 {
        Some(value) => output.escaped(value)?,
        None => output.raw("unknown")?,
    }
    output.raw("\nCompleteness: ")?;
    output.raw(completeness_name(timeline.source_state.completeness))?;
    if let Some(loss) = &timeline.source_state.loss {
        output.raw("; reported_events_lost=")?;
        output.number(loss.reported_events_lost)?;
        output.raw(" reported_buffers_lost=")?;
        output.number(loss.reported_buffers_lost)?;
        output.raw(" loss_statistics_available=")?;
        output.raw(if loss.statistics_available {
            "true"
        } else {
            "false"
        })?;
    }
    output.raw("\nOrdering: ")?;
    output.escaped(timeline.ordering)?;
    output.raw("\nSemantics: ")?;
    output.escaped(timeline.semantics)?;
    output.raw("\nFilter: event_kind=")?;
    match &timeline.filter.event_kind {
        Some(value) => output.escaped(value)?,
        None => output.raw("*")?,
    }
    output.raw(" process_observation_id=")?;
    match timeline.filter.process_observation_id {
        Some(value) => output.number(value)?,
        None => output.raw("*")?,
    }
    output.raw("\nTimestamp note: source-local timestamp representation only; timestamps do not establish causality.\n")?;
    output.raw("Source diagnostics: ")?;
    if timeline.source_state.diagnostics.is_empty() {
        output.raw("none")?;
    } else {
        for (index, diagnostic) in timeline.source_state.diagnostics.iter().enumerate() {
            if index > 0 {
                output.raw(",")?;
            }
            output.escaped(diagnostic)?;
        }
    }
    output.raw("\nIdentity ambiguity present: ")?;
    output.raw(if timeline.source_state.identity_ambiguity_present {
        "true\n"
    } else {
        "false\n"
    })?;

    if let Some(observation) = &timeline.selected_process_observation {
        output.raw("\nSelected process observation:\n  ")?;
        write_observation(output, observation)?;
    }

    output.raw("\nEvents in source-local order (count=")?;
    output.number(timeline.items.len())?;
    output.raw("):\n")?;
    for event in &timeline.items {
        output.raw("  ordinal=")?;
        output.number(event.source_local_ordinal)?;
        output.raw(" timestamp=")?;
        match &event.source_timestamp {
            Some(timestamp) => {
                output.escaped(&timestamp.value)?;
                output.raw(" [")?;
                output.escaped(&timestamp.clock_unit)?;
                output.raw("]")?;
            }
            None => output.raw("unknown")?,
        }
        output.raw(" kind=")?;
        output.escaped(&event.event_kind)?;
        output.raw(" operation=")?;
        write_operation(output, &event.operation)?;
        output.raw(" evidence=")?;
        write_evidence(output, &event.evidence)?;
        output.raw("\n")?;
        for context in &event.identity_context {
            output.raw("    identity ")?;
            output.escaped(&context.kind)?;
            output.raw("=")?;
            output.escaped(&context.value)?;
            output.raw(" ambiguity=")?;
            output.escaped(&context.ambiguity)?;
            output.raw("\n")?;
        }
        if let Some(path) = &event.path_observation {
            output.raw("    path=")?;
            output.escaped(&path.path)?;
            output.raw(" basis=")?;
            output.escaped(&format!("{:?}", path.basis).to_ascii_lowercase())?;
            output.raw("\n")?;
        }
    }

    output.raw("\nDirect event-process links (count=")?;
    output.number(timeline.event_process_links.len())?;
    output.raw("):\n")?;
    for link in &timeline.event_process_links {
        write_link(output, link)?;
    }

    output.raw("\nDiagnostics (count=")?;
    output.number(timeline.diagnostics.len())?;
    output.raw("):\n")?;
    if timeline.diagnostics.is_empty() {
        output.raw("  none\n")?;
    }
    for diagnostic in &timeline.diagnostics {
        output.raw("  code=")?;
        output.escaped(&diagnostic.code)?;
        output.raw(" message=")?;
        output.escaped(&diagnostic.message)?;
        output.raw(" ordinal=")?;
        match diagnostic.source_local_ordinal {
            Some(value) => output.number(value)?,
            None => output.raw("unknown")?,
        }
        output.raw(" evidence=")?;
        match &diagnostic.evidence {
            Some(evidence) => write_evidence(output, evidence)?,
            None => output.raw("none")?,
        }
        output.raw("\n")?;
    }
    output.raw("\nA filtered or empty timeline does not prove absence; source completeness and diagnostics apply to the full input.\n")?;
    Ok(())
}

fn write_observation(
    output: &mut TimelineBuffer,
    observation: &ProcessObservation,
) -> io::Result<()> {
    output.raw("source_local_id=")?;
    output.number(observation.source_local_id)?;
    output.raw(" identity=")?;
    match &observation.identity {
        ProcessIdentity::LinuxTraceTaskContext {
            task_id,
            observed_task_epoch,
            epoch_basis,
            identity_status,
        } => {
            output.raw("linux_trace_task_context task_id=")?;
            output.number(*task_id)?;
            output.raw(" observed_task_epoch=")?;
            write_optional_number(output, *observed_task_epoch)?;
            output.raw(" epoch_basis=")?;
            output.escaped(&debug_snake(&format!("{epoch_basis:?}")))?;
            output.raw(" identity_status=")?;
            output.escaped(&debug_snake(&format!("{identity_status:?}")))?;
        }
        ProcessIdentity::LinuxReturnedChildPid {
            process_id,
            identity_status,
        } => {
            output.raw("linux_returned_child_pid process_id=")?;
            output.number(*process_id)?;
            output.raw(" identity_status=")?;
            output.escaped(&debug_snake(&format!("{identity_status:?}")))?;
        }
        ProcessIdentity::WindowsProcessInstance {
            process_id,
            start_record_ordinal,
            reported_parent_process_id,
            identity_status,
        } => {
            output.raw("windows_process_instance process_id=")?;
            output.number(*process_id)?;
            output.raw(" start_record_ordinal=")?;
            output.number(*start_record_ordinal)?;
            output.raw(" reported_parent_process_id=")?;
            write_optional_number(output, *reported_parent_process_id)?;
            output.raw(" identity_status=")?;
            output.escaped(&debug_snake(&format!("{identity_status:?}")))?;
        }
    }
    output.raw(" evidence=")?;
    write_evidence(output, &observation.evidence)?;
    output.raw(" end_evidence=")?;
    match &observation.end_evidence {
        Some(evidence) => write_evidence(output, evidence)?,
        None => output.raw("none")?,
    }
    output.raw("\n")
}

fn write_link(output: &mut TimelineBuffer, link: &EventProcessLink) -> io::Result<()> {
    output.raw("  event=")?;
    write_evidence(output, &link.event)?;
    output.raw(" process_observation_id=")?;
    write_optional_number(output, link.process_observation_id)?;
    output.raw(" reported_process_id=")?;
    write_optional_number(output, link.reported_process_id)?;
    output.raw(" role=")?;
    output.escaped(&debug_snake(&format!("{:?}", link.role)))?;
    output.raw(" status=")?;
    output.escaped(&debug_snake(&format!("{:?}", link.status)))?;
    output.raw(" basis=")?;
    output.escaped(&link.basis)?;
    output.raw("\n")
}

fn write_operation(output: &mut TimelineBuffer, operation: &OperationSemantics) -> io::Result<()> {
    match operation {
        OperationSemantics::SyscallAttempt { result } => {
            output.raw("syscall_attempt result=")?;
            match result {
                Some(value) => output.escaped(&format!("{value:?}").to_ascii_lowercase())?,
                None => output.raw("unknown")?,
            }
        }
        OperationSemantics::NativeObservation => output.raw("native_observation")?,
    }
    Ok(())
}

fn write_evidence(output: &mut TimelineBuffer, evidence: &EvidenceReference) -> io::Result<()> {
    match evidence {
        EvidenceReference::RawTraceRecord {
            line_number,
            byte_offset,
            byte_length,
        } => {
            output.raw("raw_trace_record(line=")?;
            output.number(*line_number)?;
            output.raw(",byte=")?;
            output.number(*byte_offset)?;
            output.raw(",length=")?;
            output.number(*byte_length)?;
            output.raw(")")
        }
        EvidenceReference::WindowsEtwRecord {
            record_ordinal,
            json_pointer,
            raw_payload_sha256,
        } => {
            output.raw("windows_etw_record(ordinal=")?;
            output.number(*record_ordinal)?;
            output.raw(",json_pointer=")?;
            output.escaped(json_pointer)?;
            output.raw(",raw_payload_sha256=")?;
            output.escaped(raw_payload_sha256)?;
            output.raw(")")
        }
    }
}

fn write_optional_number<T: std::fmt::Display + Copy>(
    output: &mut TimelineBuffer,
    value: Option<T>,
) -> io::Result<()> {
    match value {
        Some(value) => output.number(value),
        None => output.raw("unknown"),
    }
}

fn completeness_name(value: SourceCompleteness) -> &'static str {
    match value {
        SourceCompleteness::Complete => "complete",
        SourceCompleteness::Partial => "partial",
        SourceCompleteness::Unknown => "unknown",
    }
}

fn debug_snake(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 8);
    for (index, character) in value.chars().enumerate() {
        if character.is_ascii_uppercase() && index > 0 {
            output.push('_');
        }
        output.push(character.to_ascii_lowercase());
    }
    output
}

#[derive(Default)]
struct TimelineBuffer {
    bytes: Vec<u8>,
}

impl TimelineBuffer {
    fn raw(&mut self, text: &str) -> io::Result<()> {
        self.push(text.as_bytes())
    }
    fn number(&mut self, number: impl std::fmt::Display) -> io::Result<()> {
        self.raw(&number.to_string())
    }
    fn escaped(&mut self, value: &str) -> io::Result<()> {
        for character in value.chars() {
            match character {
                ' '..='~' if character != '\\' => self.raw(&character.to_string())?,
                '\\' => self.raw("\\\\")?,
                _ => self.raw(&format!("\\u{{{:x}}}", character as u32))?,
            }
        }
        Ok(())
    }
    fn push(&mut self, bytes: &[u8]) -> io::Result<()> {
        let new_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("timeline text size overflow"))?;
        if new_len > MAX_TIMELINE_TEXT_BYTES {
            return Err(io::Error::other("timeline text output limit exceeded"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| io::Error::other("timeline text allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_TIMELINE_TEXT_BYTES, TimelineBuffer, write_timeline_text};
    use crate::event::*;

    fn source(platform: SourcePlatform) -> SourceDescriptor {
        SourceDescriptor {
            platform,
            schema: "synthetic.capture".to_owned(),
            schema_version: 3,
            artifact: "fixture".to_owned(),
            sha256: Some("a".repeat(64)),
        }
    }

    #[test]
    fn linux_text_preserves_timestamp_evidence_and_inerts_controls() {
        let timeline = EventTimeline {
            schema: EVENT_TIMELINE_SCHEMA,
            schema_version: EVENT_TIMELINE_SCHEMA_VERSION,
            source: source(SourcePlatform::Linux),
            source_state: SourceState {
                completeness: SourceCompleteness::Partial,
                diagnostics: vec!["partial\x1b[2J\u{202e}".to_owned()],
                loss: None,
                identity_ambiguity_present: false,
            },
            ordering: "source ordinal",
            semantics: "no causal inference",
            filter: EventTimelineFilter {
                event_kind: None,
                process_observation_id: None,
            },
            selected_process_observation: None,
            items: vec![CommonEvent {
                source_local_ordinal: 8,
                source_timestamp: Some(SourceTimestamp {
                    value: "1700000000.01\n".to_owned(),
                    clock_unit: "strace_seconds".to_owned(),
                }),
                event_kind: "openat\x1b]0;title\u{7}".to_owned(),
                operation: OperationSemantics::SyscallAttempt {
                    result: Some(crate::model::SyscallOutcome::Success),
                },
                evidence: EvidenceReference::RawTraceRecord {
                    line_number: 8,
                    byte_offset: 150,
                    byte_length: 40,
                },
                identity_context: vec![],
                path_observation: Some(EventPathObservation {
                    path: "/tmp/\x1b[31m\u{202e}".to_owned(),
                    basis: EventPathBasis::LinuxStraceLexicalHint {
                        lexical_basis: crate::trace::LexicalPathBasis::AbsoluteArgument,
                    },
                }),
            }],
            event_process_links: vec![EventProcessLink {
                event: EvidenceReference::RawTraceRecord {
                    line_number: 8,
                    byte_offset: 150,
                    byte_length: 40,
                },
                process_observation_id: Some(1),
                reported_process_id: Some(123),
                role: EventProcessLinkRole::LinuxTraceCallerTaskContext,
                status: EventProcessLinkStatus::ContextCandidate,
                basis: "exact\nsource row".to_owned(),
            }],
            diagnostics: vec![EventDiagnostic {
                code: "bad\x1b[2J".to_owned(),
                message: "malformed\n\u{202e}".to_owned(),
                source_local_ordinal: Some(9),
                evidence: Some(EvidenceReference::RawTraceRecord {
                    line_number: 9,
                    byte_offset: 200,
                    byte_length: 3,
                }),
            }],
        };
        let mut bytes = Vec::new();
        write_timeline_text(&timeline, &mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.is_ascii());
        assert!(text.contains("ordinal=8 timestamp=1700000000.01\\u{a}"));
        assert!(text.contains("raw_trace_record(line=8,byte=150,length=40)"));
        assert!(text.contains("status=context_candidate"));
        assert!(text.contains("\\u{1b}"));
        assert!(text.contains("\\u{202e}"));
        assert!(text.contains("Source diagnostics: partial\\u{1b}[2J\\u{202e}"));
        assert!(!text.contains('\u{001b}'));
        assert!(!text.contains('\u{202e}'));
        assert!(text.contains("timestamps do not establish causality"));
    }

    #[test]
    fn windows_text_keeps_observation_end_evidence_links_and_diagnostics() {
        let evidence = EvidenceReference::WindowsEtwRecord {
            record_ordinal: 2,
            json_pointer: "/events/1".to_owned(),
            raw_payload_sha256: "b".repeat(64),
        };
        let timeline = EventTimeline {
            schema: EVENT_TIMELINE_SCHEMA,
            schema_version: EVENT_TIMELINE_SCHEMA_VERSION,
            source: source(SourcePlatform::Windows),
            source_state: SourceState {
                completeness: SourceCompleteness::Unknown,
                diagnostics: vec!["capture_unknown".to_owned()],
                loss: Some(LossMetadata {
                    reported_events_lost: 2,
                    reported_buffers_lost: 1,
                    statistics_available: true,
                }),
                identity_ambiguity_present: true,
            },
            ordering: "QPC source order",
            semantics: "candidate links only",
            filter: EventTimelineFilter {
                event_kind: Some("process_start".to_owned()),
                process_observation_id: Some(1),
            },
            selected_process_observation: Some(ProcessObservation {
                source_local_id: 1,
                identity: ProcessIdentity::WindowsProcessInstance {
                    process_id: 77,
                    start_record_ordinal: 1,
                    reported_parent_process_id: Some(5),
                    identity_status: ProcessIdentityStatus::ObservedStart,
                },
                evidence: EvidenceReference::WindowsEtwRecord {
                    record_ordinal: 1,
                    json_pointer: "/events/0".to_owned(),
                    raw_payload_sha256: "c".repeat(64),
                },
                end_evidence: Some(evidence.clone()),
            }),
            items: vec![CommonEvent {
                source_local_ordinal: 2,
                source_timestamp: Some(SourceTimestamp {
                    value: "987654".to_owned(),
                    clock_unit: "ETW_QPC_ticks".to_owned(),
                }),
                event_kind: "network_connect".to_owned(),
                operation: OperationSemantics::NativeObservation,
                evidence: evidence.clone(),
                identity_context: vec![EventIdentityContext {
                    kind: "process_id".to_owned(),
                    value: "77".to_owned(),
                    ambiguity: "observed".to_owned(),
                }],
                path_observation: None,
            }],
            event_process_links: vec![EventProcessLink {
                event: evidence.clone(),
                process_observation_id: Some(1),
                reported_process_id: None,
                role: EventProcessLinkRole::WindowsNetworkPayloadPid,
                status: EventProcessLinkStatus::Observed,
                basis: "validated payload PID".to_owned(),
            }],
            diagnostics: vec![EventDiagnostic {
                code: "partial\x1b]0;bad".to_owned(),
                message: "synthetic diagnostic".to_owned(),
                source_local_ordinal: Some(2),
                evidence: Some(evidence),
            }],
        };
        let mut bytes = Vec::new();
        write_timeline_text(&timeline, &mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.is_ascii());
        assert!(text.contains("reported_events_lost=2"));
        assert!(text.contains("end_evidence=windows_etw_record(ordinal=2,json_pointer=/events/1"));
        assert!(text.contains("raw_payload_sha256="));
        assert!(text.contains(
            "role=windows_network_payload_pid status=observed basis=validated payload PID"
        ));
        assert!(text.contains("Diagnostics (count=1)"));
        assert!(text.contains("\\u{1b}"));
        assert!(!text.contains('\u{001b}'));
    }

    #[test]
    fn timeline_text_output_is_bounded_before_writing() {
        let mut buffer = TimelineBuffer::default();
        buffer.bytes.resize(MAX_TIMELINE_TEXT_BYTES, b'x');
        assert!(buffer.raw("y").is_err());

        let timeline = EventTimeline {
            schema: EVENT_TIMELINE_SCHEMA,
            schema_version: EVENT_TIMELINE_SCHEMA_VERSION,
            source: source(SourcePlatform::Linux),
            source_state: SourceState {
                completeness: SourceCompleteness::Complete,
                diagnostics: Vec::new(),
                loss: None,
                identity_ambiguity_present: false,
            },
            ordering: "source order",
            semantics: "bounded",
            filter: EventTimelineFilter {
                event_kind: None,
                process_observation_id: None,
            },
            selected_process_observation: None,
            items: Vec::new(),
            event_process_links: Vec::new(),
            diagnostics: Vec::new(),
        };
        let mut oversized = timeline;
        oversized.source.artifact = "x".repeat(MAX_TIMELINE_TEXT_BYTES + 1);
        let mut destination = Vec::new();
        assert!(write_timeline_text(&oversized, &mut destination).is_err());
        assert!(destination.is_empty());
    }
}
