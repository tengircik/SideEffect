use std::io::{self, Write};

use crate::event::{
    EventGraph, EventGraphNodeKind, EvidenceReference, OperationSemantics, ProcessIdentity,
    ProcessObservation, SourceCompleteness,
};

pub const MAX_EVENT_GRAPH_TEXT_BYTES: usize = 8 * 1024 * 1024;

/// Render a bounded ASCII-only terminal review of a source-local event graph.
pub fn write_event_graph_text<W: Write>(graph: &EventGraph, writer: &mut W) -> io::Result<()> {
    let mut output = GraphBuffer::default();
    render(graph, &mut output)?;
    writer.write_all(&output.bytes)
}

fn render(graph: &EventGraph, output: &mut GraphBuffer) -> io::Result<()> {
    output.raw("SideEffect source-local event graph\nGraph contract: schema=")?;
    output.escaped(graph.schema)?;
    output.raw(" version=")?;
    output.number(graph.schema_version)?;
    output.raw("\nSource: platform=")?;
    output.escaped(&debug_snake(&format!("{:?}", graph.source.platform)))?;
    output.raw(" schema=")?;
    output.escaped(&graph.source.schema)?;
    output.raw(" version=")?;
    output.number(graph.source.schema_version)?;
    output.raw(" artifact=")?;
    output.escaped(&graph.source.artifact)?;
    output.raw(" sha256=")?;
    match &graph.source.sha256 {
        Some(sha256) => output.escaped(sha256)?,
        None => output.raw("unknown")?,
    }
    if !graph.supplemental_sources.is_empty() {
        output.raw("\nSupplemental inputs:")?;
        for source in &graph.supplemental_sources {
            output.raw(" schema=")?;
            output.escaped(&source.schema)?;
            output.raw(" version=")?;
            output.number(source.schema_version)?;
            output.raw(" sha256=")?;
            output.escaped(&source.sha256)?;
            output.raw(" status=")?;
            output.escaped(&source.status)?;
            output.raw(" association_status=")?;
            output.escaped(&source.association_status)?;
        }
    }
    output.raw("\nCompleteness: ")?;
    output.raw(completeness_name(graph.source_state.completeness))?;
    if let Some(loss) = &graph.source_state.loss {
        output.raw(" reported_events_lost=")?;
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
    output.raw("\nFilter: event_kind=")?;
    match &graph.filter.event_kind {
        Some(value) => output.escaped(value)?,
        None => output.raw("*")?,
    }
    output.raw(" process_observation_id=")?;
    match graph.filter.process_observation_id {
        Some(id) => output.number(id)?,
        None => output.raw("*")?,
    }
    output.raw("\nSemantics: ")?;
    output.escaped(graph.semantics)?;
    output.raw("\nIdentity rule: process-observation IDs are source-local IDs, not PIDs or cross-capture identities. PID-only context nodes remain separate; they do not establish ownership.\nSource diagnostics: ")?;
    if graph.source_state.diagnostics.is_empty() {
        output.raw("none")?;
    } else {
        for (index, diagnostic) in graph.source_state.diagnostics.iter().enumerate() {
            if index > 0 {
                output.raw(",")?;
            }
            output.escaped(diagnostic)?;
        }
    }
    output.raw("\nIdentity ambiguity present: ")?;
    output.raw(if graph.source_state.identity_ambiguity_present {
        "true\n"
    } else {
        "false\n"
    })?;

    output.raw("\nNodes (count=")?;
    output.number(graph.nodes.len())?;
    output.raw("):\n")?;
    if graph.nodes.is_empty() {
        output.raw("  none selected; this does not establish absence\n")?;
    }
    for node in &graph.nodes {
        output.raw("  node id=")?;
        output.escaped(&node.id)?;
        output.raw(" kind=")?;
        output.escaped(&debug_snake(&format!("{:?}", node.kind)))?;
        if let Some(ordinal) = node.source_local_ordinal {
            output.raw(" source_local_ordinal=")?;
            output.number(ordinal)?;
        }
        if let Some(evidence) = &node.evidence {
            output.raw(" evidence=")?;
            write_evidence(output, evidence)?;
        }
        if let Some(reported_pid) = node.reported_process_id {
            output.raw(" reported_process_id=")?;
            output.number(reported_pid)?;
        }
        if let Some(note) = node.context_note {
            output.raw(" warning=")?;
            output.escaped(note)?;
        }
        if let Some(service) = &node.service_startup_configuration {
            output.raw(" service_index=")?;
            output.number(service.service_index)?;
            output.raw(" service_name=")?;
            output.escaped(&service.service_name)?;
            output.raw(" configured_binary_path=")?;
            output.escaped(&service.binary_path)?;
        }
        if let Some(evidence) = &node.supplemental_evidence {
            output.raw(" startup_evidence=")?;
            write_supplemental_evidence(output, evidence)?;
        }
        if let Some(service) = &node.service_startup_configuration {
            output
                .raw("    SCM startup configuration; no launch or trigger event is inferred.\n")?;
            output.raw("    service_name=")?;
            output.escaped(&service.service_name)?;
            output.raw(" configured_binary_path=")?;
            output.escaped(&service.binary_path)?;
            output.raw("\n")?;
        }
        output.raw("\n")?;
        if let Some(event) = &node.event {
            output.raw("    event kind=")?;
            output.escaped(&event.event_kind)?;
            output.raw(" operation=")?;
            write_operation(output, &event.operation)?;
            output.raw(" timestamp=")?;
            match &event.source_timestamp {
                Some(timestamp) => {
                    output.escaped(&timestamp.value)?;
                    output.raw(" ")?;
                    output.escaped(&timestamp.clock_unit)?;
                }
                None => output.raw("unknown")?,
            }
            output.raw(" evidence=")?;
            write_evidence(output, &event.evidence)?;
            output.raw("\n")?;
            for context in &event.identity_context {
                output.raw("      identity ")?;
                output.escaped(&context.kind)?;
                output.raw("=")?;
                output.escaped(&context.value)?;
                output.raw(" ambiguity=")?;
                output.escaped(&context.ambiguity)?;
                output.raw("\n")?;
            }
            if let Some(path) = &event.path_observation {
                output.raw("      path=")?;
                output.escaped(&path.path)?;
                output.raw(" basis=")?;
                output.escaped(&debug_snake(&format!("{:?}", path.basis)))?;
                output.raw("\n")?;
            }
        }
        if let Some(observation) = &node.process_observation {
            output.raw("    process observation (source-local, not a PID key): ")?;
            write_observation(output, observation)?;
        }
        if node.kind == EventGraphNodeKind::ProcessIdContext {
            output
                .raw("    PID context only; no ownership or instance identity is established.\n")?;
        }
    }

    output.raw("\nEdges (count=")?;
    output.number(graph.edges.len())?;
    output.raw("):\n")?;
    if graph.edges.is_empty() {
        output.raw("  none selected; this does not establish absence\n")?;
    }
    for edge in &graph.edges {
        output.raw("  edge from=")?;
        output.escaped(&edge.from_node_id)?;
        output.raw(" to=")?;
        output.escaped(&edge.to_node_id)?;
        output.raw(" kind=")?;
        output.escaped(edge.kind)?;
        if let Some(kind) = edge.relationship_kind {
            output.raw(" relationship_kind=")?;
            output.escaped(&debug_snake(&format!("{kind:?}")))?;
        }
        if let Some(resolution) = edge.relationship_resolution {
            output.raw(" resolution=")?;
            output.escaped(&debug_snake(&format!("{resolution:?}")))?;
        }
        if let Some(role) = edge.event_link_role {
            output.raw(" role=")?;
            output.escaped(&debug_snake(&format!("{role:?}")))?;
        }
        if let Some(status) = edge.event_link_status {
            output.raw(" status=")?;
            output.escaped(&debug_snake(&format!("{status:?}")))?;
        }
        output.raw(" basis=")?;
        output.escaped(&edge.basis)?;
        output.raw(" evidence=")?;
        if edge.evidence.is_empty() {
            output.raw("none")?;
        } else {
            for (index, evidence) in edge.evidence.iter().enumerate() {
                if index > 0 {
                    output.raw(";")?;
                }
                write_evidence(output, evidence)?;
            }
        }
        if !edge.supplemental_evidence.is_empty() {
            output.raw(" startup_evidence=")?;
            for (index, evidence) in edge.supplemental_evidence.iter().enumerate() {
                if index > 0 {
                    output.raw(";")?;
                }
                write_supplemental_evidence(output, evidence)?;
            }
        }
        output.raw("\n")?;
    }

    output.raw("\nDiagnostics (count=")?;
    output.number(graph.diagnostics.len())?;
    output.raw("):\n")?;
    if graph.diagnostics.is_empty() {
        output.raw("  none\n")?;
    }
    for diagnostic in &graph.diagnostics {
        output.raw("  code=")?;
        output.escaped(&diagnostic.code)?;
        output.raw(" message=")?;
        output.escaped(&diagnostic.message)?;
        output.raw(" source_local_ordinal=")?;
        match diagnostic.source_local_ordinal {
            Some(ordinal) => output.number(ordinal)?,
            None => output.raw("unknown")?,
        }
        output.raw(" evidence=")?;
        match &diagnostic.evidence {
            Some(evidence) => write_evidence(output, evidence)?,
            None => output.raw("none")?,
        }
        output.raw("\n")?;
    }
    output.raw("\nLimits: graph nodes and edges preserve source-local observations and references; they do not establish ownership, causality, ancestry, or total coverage. Empty selections do not prove absence.\n")?;
    Ok(())
}

fn write_observation(output: &mut GraphBuffer, observation: &ProcessObservation) -> io::Result<()> {
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

fn write_operation(output: &mut GraphBuffer, operation: &OperationSemantics) -> io::Result<()> {
    match operation {
        OperationSemantics::SyscallAttempt { result } => {
            output.raw("syscall_attempt result=")?;
            match result {
                Some(result) => output.escaped(&debug_snake(&format!("{result:?}")))?,
                None => output.raw("unknown")?,
            }
        }
        OperationSemantics::NativeObservation => output.raw("native_observation")?,
    }
    Ok(())
}

fn write_evidence(output: &mut GraphBuffer, evidence: &EvidenceReference) -> io::Result<()> {
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

fn write_supplemental_evidence(
    output: &mut GraphBuffer,
    evidence: &crate::event::SupplementalArtifactEvidence,
) -> io::Result<()> {
    output.raw("artifact_row(schema=")?;
    output.escaped(&evidence.source_schema)?;
    output.raw(",version=")?;
    output.number(evidence.source_schema_version)?;
    output.raw(",sha256=")?;
    output.escaped(&evidence.artifact_sha256)?;
    output.raw(",json_pointer=")?;
    output.escaped(&evidence.json_pointer)?;
    output.raw(")")
}

fn write_optional_number<T: std::fmt::Display + Copy>(
    output: &mut GraphBuffer,
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
struct GraphBuffer {
    bytes: Vec<u8>,
}

impl GraphBuffer {
    fn raw(&mut self, value: &str) -> io::Result<()> {
        self.push(value.as_bytes())
    }
    fn number(&mut self, value: impl std::fmt::Display) -> io::Result<()> {
        self.raw(&value.to_string())
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
            .ok_or_else(|| io::Error::other("event graph text size overflow"))?;
        if new_len > MAX_EVENT_GRAPH_TEXT_BYTES {
            return Err(io::Error::other("event graph text output limit exceeded"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| io::Error::other("event graph text allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{GraphBuffer, MAX_EVENT_GRAPH_TEXT_BYTES, write_event_graph_text};
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
    fn linux_graph_text_preserves_evidence_identity_context_and_escapes_hostile_strings() {
        let evidence = EvidenceReference::RawTraceRecord {
            line_number: 5,
            byte_offset: 90,
            byte_length: 30,
        };
        let graph = EventGraph {
            schema: EVENT_GRAPH_SCHEMA,
            schema_version: EVENT_GRAPH_SCHEMA_VERSION,
            filter: EventGraphFilter {
                event_kind: Some("openat".to_owned()),
                process_observation_id: Some(1),
            },
            source: source(SourcePlatform::Linux),
            source_state: SourceState {
                completeness: SourceCompleteness::Partial,
                diagnostics: vec!["partial\x1b[2J\u{202e}".to_owned()],
                loss: None,
                identity_ambiguity_present: true,
            },
            semantics: "no causal claims",
            supplemental_sources: Vec::new(),
            nodes: vec![
                EventGraphNode {
                    id: "event:5".to_owned(),
                    kind: EventGraphNodeKind::Event,
                    source_local_ordinal: Some(5),
                    evidence: Some(evidence.clone()),
                    event: Some(CommonEvent {
                        source_local_ordinal: 5,
                        source_timestamp: Some(SourceTimestamp {
                            value: "12.5\x1b[2J".to_owned(),
                            clock_unit: "seconds".to_owned(),
                        }),
                        event_kind: "openat\x1b]0;bad\u{7}".to_owned(),
                        operation: OperationSemantics::SyscallAttempt {
                            result: Some(crate::model::SyscallOutcome::Failure),
                        },
                        evidence: evidence.clone(),
                        identity_context: vec![EventIdentityContext {
                            kind: "path".to_owned(),
                            value: "/tmp/\x1b[31m\u{202e}".to_owned(),
                            ambiguity: "lexical\nonly".to_owned(),
                        }],
                        network_endpoints: None,
                        path_observation: None,
                    }),
                    process_observation: None,
                    reported_process_id: None,
                    context_note: None,
                    supplemental_evidence: None,
                    service_startup_configuration: None,
                },
                EventGraphNode {
                    id: "pid_context:1".to_owned(),
                    kind: EventGraphNodeKind::ProcessIdContext,
                    source_local_ordinal: None,
                    evidence: Some(evidence.clone()),
                    event: None,
                    process_observation: None,
                    reported_process_id: Some(123),
                    context_note: Some("PID context is not merged into a process instance"),
                    supplemental_evidence: None,
                    service_startup_configuration: None,
                },
            ],
            edges: vec![EventGraphEdge {
                from_node_id: "event:5".to_owned(),
                to_node_id: "pid_context:1".to_owned(),
                kind: "event_process_link",
                relationship_kind: None,
                relationship_resolution: None,
                event_link_role: Some(EventProcessLinkRole::LinuxTraceCallerTaskContext),
                event_link_status: Some(EventProcessLinkStatus::ContextCandidate),
                basis: "source row\nonly".to_owned(),
                evidence: vec![evidence],
                supplemental_evidence: Vec::new(),
            }],
            diagnostics: vec![EventDiagnostic {
                code: "unsupported\x1b[2J".to_owned(),
                message: "malformed\r\n\u{202e}".to_owned(),
                source_local_ordinal: Some(6),
                evidence: None,
            }],
        };
        let mut bytes = Vec::new();
        write_event_graph_text(&graph, &mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.is_ascii());
        assert!(text.contains("Nodes (count=2)"));
        assert!(text.contains("Graph contract: schema=sideeffect.event_graph version=6"));
        assert!(text.contains("timestamp=12.5\\u{1b}[2J seconds"));
        assert!(text.contains("Edges (count=1)"));
        assert!(text.contains("process_observation_id=1"));
        assert!(text.contains("raw_trace_record(line=5,byte=90,length=30)"));
        assert!(text.contains("reported_process_id=123"));
        assert!(text.contains("PID context only"));
        assert!(text.contains("role=linux_trace_caller_task_context status=context_candidate"));
        assert!(text.contains("\\u{1b}"));
        assert!(text.contains("\\u{202e}"));
        assert!(!text.contains('\u{001b}'));
        assert!(!text.contains('\u{202e}'));
        assert!(text.contains("Empty selections do not prove absence"));
    }

    #[test]
    fn windows_synthetic_graph_shows_etw_refs_and_partial_diagnostics() {
        let evidence = EvidenceReference::WindowsEtwRecord {
            record_ordinal: 2,
            json_pointer: "/events/1".to_owned(),
            raw_payload_sha256: "b".repeat(64),
        };
        let graph = EventGraph {
            schema: EVENT_GRAPH_SCHEMA,
            schema_version: EVENT_GRAPH_SCHEMA_VERSION,
            filter: EventGraphFilter {
                event_kind: None,
                process_observation_id: Some(1),
            },
            source: source(SourcePlatform::Windows),
            source_state: SourceState {
                completeness: SourceCompleteness::Unknown,
                diagnostics: vec!["capture_incomplete".to_owned()],
                loss: Some(LossMetadata {
                    reported_events_lost: 2,
                    reported_buffers_lost: 1,
                    statistics_available: false,
                }),
                identity_ambiguity_present: true,
            },
            semantics: "source-local only",
            supplemental_sources: Vec::new(),
            nodes: vec![EventGraphNode {
                id: "process:1".to_owned(),
                kind: EventGraphNodeKind::ProcessObservation,
                source_local_ordinal: None,
                evidence: Some(evidence.clone()),
                event: None,
                process_observation: Some(ProcessObservation {
                    source_local_id: 1,
                    identity: ProcessIdentity::WindowsProcessInstance {
                        process_id: 42,
                        start_record_ordinal: 1,
                        reported_parent_process_id: Some(1),
                        identity_status: ProcessIdentityStatus::ObservedStart,
                    },
                    evidence: evidence.clone(),
                    end_evidence: Some(evidence.clone()),
                }),
                reported_process_id: None,
                context_note: None,
                supplemental_evidence: None,
                service_startup_configuration: None,
            }],
            edges: vec![EventGraphEdge {
                from_node_id: "pid_context:1".to_owned(),
                to_node_id: "process:1".to_owned(),
                kind: "process_relationship",
                relationship_kind: Some(
                    ProcessRelationshipKind::WindowsPayloadParentToChildInstance,
                ),
                relationship_resolution: Some(RelationshipResolution::ParentInstanceUnresolved),
                event_link_role: None,
                event_link_status: None,
                basis: "payload\x1b[2J".to_owned(),
                evidence: vec![evidence.clone()],
                supplemental_evidence: Vec::new(),
            }],
            diagnostics: vec![EventDiagnostic {
                code: "synthetic\x1b]0;title".to_owned(),
                message: "fixture diagnostic".to_owned(),
                source_local_ordinal: Some(2),
                evidence: Some(evidence),
            }],
        };
        let mut bytes = Vec::new();
        write_event_graph_text(&graph, &mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.is_ascii());
        assert!(text.contains("Completeness: unknown"));
        assert!(text.contains("reported_events_lost=2"));
        assert!(text.contains("source_local_id=1 identity=windows_process_instance"));
        assert!(text.contains("windows_etw_record(ordinal=2,json_pointer=/events/1"));
        assert!(text.contains("relationship_kind=windows_payload_parent_to_child_instance resolution=parent_instance_unresolved"));
        assert!(text.contains("end_evidence=windows_etw_record(ordinal=2"));
        assert!(text.contains("\\u{1b}"));
        assert!(!text.contains('\u{001b}'));
    }

    #[test]
    fn empty_graph_text_is_not_an_absence_claim_and_output_is_bounded() {
        let mut buffer = GraphBuffer::default();
        buffer.bytes.resize(MAX_EVENT_GRAPH_TEXT_BYTES, b'x');
        assert!(buffer.raw("y").is_err());
        let graph = EventGraph {
            schema: EVENT_GRAPH_SCHEMA,
            schema_version: EVENT_GRAPH_SCHEMA_VERSION,
            filter: EventGraphFilter {
                event_kind: Some("not-present".to_owned()),
                process_observation_id: None,
            },
            source: source(SourcePlatform::Linux),
            source_state: SourceState {
                completeness: SourceCompleteness::Complete,
                diagnostics: Vec::new(),
                loss: None,
                identity_ambiguity_present: false,
            },
            semantics: "empty selection",
            supplemental_sources: Vec::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            diagnostics: Vec::new(),
        };
        let mut output = Vec::new();
        write_event_graph_text(&graph, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("none selected; this does not establish absence"));
        assert!(text.contains("Empty selections do not prove absence"));
    }
}
