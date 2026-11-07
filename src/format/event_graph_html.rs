use std::io::{self, Write};

use crate::event::{
    EventGraph, EventGraphNode, EventGraphNodeKind, EvidenceReference, OperationSemantics,
    ProcessIdentity, ProcessObservation, SourceCompleteness,
};
use crate::limits::MAX_REPORT_BYTES;

const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; frame-src 'none'; media-src 'none'; script-src 'none'";

pub const MAX_EVENT_GRAPH_HTML_BYTES: usize = MAX_REPORT_BYTES;

/// Render a bounded, static offline HTML review of one source-local event graph.
///
/// The complete document is buffered before the writer is touched, so a size or
/// formatting failure cannot publish a partial report when the caller writes to a file.
pub fn write_event_graph_html<W: Write>(graph: &EventGraph, writer: &mut W) -> io::Result<()> {
    let mut output = HtmlBuffer::default();
    render(graph, &mut output)?;
    writer.write_all(&output.bytes)
}

fn render(graph: &EventGraph, output: &mut HtmlBuffer) -> io::Result<()> {
    output.raw("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta http-equiv=\"Content-Security-Policy\" content=\"")?;
    output.raw(CSP)?;
    output.raw("\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>SideEffect event graph report</title>\n<style>:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{max-width:78rem;margin:2rem auto;padding:0 1rem}h1,h2,h3{line-height:1.25}.notice{border-left:.25rem solid #b87900;padding:.5rem 1rem}.card{border:1px solid #8886;border-radius:.5rem;padding:1rem;margin:1rem 0}dl{display:grid;grid-template-columns:minmax(12rem,18rem) minmax(0,1fr);gap:.35rem 1rem}dt{font-weight:600}.value{unicode-bidi:isolate;white-space:pre-wrap;overflow-wrap:anywhere}code{overflow-wrap:anywhere}.skip-link{position:absolute;left:1rem;top:0;z-index:1;transform:translateY(-150%);background:Canvas;color:CanvasText;padding:.5rem 1rem;border:2px solid currentColor}.skip-link:focus{transform:translateY(1rem)}@media(max-width:42rem){dl{grid-template-columns:1fr;gap:0}dt{margin-top:.5rem}}</style>\n</head>\n<body>\n<a class=\"skip-link\" href=\"#report-content\">Skip to report content</a>\n<main id=\"report-content\" tabindex=\"-1\">\n<header><h1>SideEffect source-local event graph</h1><p class=\"notice\">This offline report renders one bounded graph from the selected input. It does not authenticate the producer or establish ownership, causality, ancestry, total coverage, or safety. Review sensitive paths, process details, and payload-derived values before sharing.</p></header>\n")?;

    output.raw("<section class=\"card\"><h2>Graph and source</h2><dl>")?;
    field(output, "Graph schema", graph.schema)?;
    field_number(output, "Graph schema version", graph.schema_version)?;
    field(output, "Graph semantics", graph.semantics)?;
    field(
        output,
        "Source platform",
        &debug_snake(&format!("{:?}", graph.source.platform)),
    )?;
    field(output, "Source schema", &graph.source.schema)?;
    field_number(output, "Source schema version", graph.source.schema_version)?;
    field(output, "Source artifact label", &graph.source.artifact)?;
    field_option(output, "Source SHA-256", graph.source.sha256.as_deref())?;
    field(
        output,
        "Source completeness",
        completeness_name(graph.source_state.completeness),
    )?;
    field(
        output,
        "Identity ambiguity present",
        bool_name(graph.source_state.identity_ambiguity_present),
    )?;
    if let Some(loss) = &graph.source_state.loss {
        field(
            output,
            "Reported loss",
            &format!(
                "events={} buffers={} statistics_available={}",
                loss.reported_events_lost,
                loss.reported_buffers_lost,
                bool_name(loss.statistics_available)
            ),
        )?;
    }
    field(
        output,
        "Event-kind filter",
        graph.filter.event_kind.as_deref().unwrap_or("Any"),
    )?;
    field(
        output,
        "Process-observation filter (source-local ID, not PID)",
        &graph
            .filter
            .process_observation_id
            .map(|value| value.to_string())
            .unwrap_or_else(|| "Any".to_owned()),
    )?;
    output.raw("</dl><h3>Source diagnostics</h3>")?;
    write_string_list(
        output,
        &graph.source_state.diagnostics,
        "No source diagnostics were recorded.",
    )?;
    output.raw("</section>\n<section><h2>Nodes (")?;
    output.number(graph.nodes.len())?;
    output.raw(")</h2>")?;
    if graph.nodes.is_empty() {
        output.raw("<p class=\"notice\">No nodes were selected by these filters. An empty selection does not establish absence.</p>")?;
    }
    for (index, node) in graph.nodes.iter().enumerate() {
        write_node(output, index, node)?;
    }
    output.raw("</section>\n<section><h2>Edges (")?;
    output.number(graph.edges.len())?;
    output.raw(")</h2>")?;
    if graph.edges.is_empty() {
        output.raw("<p class=\"notice\">No edges were selected. This does not establish that a relationship is absent.</p>")?;
    }
    for (index, edge) in graph.edges.iter().enumerate() {
        output.raw("<article class=\"card\"><h3>Edge ")?;
        output.number(index + 1)?;
        output.raw("</h3><dl><dt>From node</dt><dd>")?;
        write_node_reference(output, graph, &edge.from_node_id)?;
        output.raw("</dd><dt>To node</dt><dd>")?;
        write_node_reference(output, graph, &edge.to_node_id)?;
        output.raw("</dd>")?;
        field(output, "Edge kind", edge.kind)?;
        field_option(
            output,
            "Relationship kind",
            edge.relationship_kind
                .map(|value| debug_snake(&format!("{value:?}")))
                .as_deref(),
        )?;
        field_option(
            output,
            "Relationship resolution",
            edge.relationship_resolution
                .map(|value| debug_snake(&format!("{value:?}")))
                .as_deref(),
        )?;
        field_option(
            output,
            "Event-link role",
            edge.event_link_role
                .map(|value| debug_snake(&format!("{value:?}")))
                .as_deref(),
        )?;
        field_option(
            output,
            "Event-link status",
            edge.event_link_status
                .map(|value| debug_snake(&format!("{value:?}")))
                .as_deref(),
        )?;
        field(output, "Basis", &edge.basis)?;
        output.raw("<dt>Evidence references</dt><dd>")?;
        write_evidence_list(output, &edge.evidence)?;
        output.raw("</dd></dl></article>")?;
    }
    output.raw("</section>\n<section><h2>Graph diagnostics (")?;
    output.number(graph.diagnostics.len())?;
    output.raw(")</h2>")?;
    if graph.diagnostics.is_empty() {
        output.raw("<p>No graph diagnostics were recorded.</p>")?;
    } else {
        output.raw("<ul>")?;
        for diagnostic in &graph.diagnostics {
            output.raw("<li><dl>")?;
            field(output, "Code", &diagnostic.code)?;
            field(output, "Message", &diagnostic.message)?;
            field_option(
                output,
                "Source-local ordinal",
                diagnostic
                    .source_local_ordinal
                    .map(|value| value.to_string())
                    .as_deref(),
            )?;
            output.raw("<dt>Evidence</dt><dd>")?;
            match &diagnostic.evidence {
                Some(evidence) => write_evidence(output, evidence)?,
                None => output.raw("Not available")?,
            }
            output.raw("</dd></dl></li>")?;
        }
        output.raw("</ul>")?;
    }
    output.raw("</section>\n<p class=\"notice\">Process-observation IDs and event references remain local to this source. PID-only context is separate from process instances. Edges and timestamps do not establish ownership, launch, causation, ancestry, or complete operating-system coverage. Partial or unknown source status remains visible.</p>\n</main>\n</body>\n</html>\n")
}

fn write_node(output: &mut HtmlBuffer, index: usize, node: &EventGraphNode) -> io::Result<()> {
    output.raw("<article class=\"card\" id=\"node-")?;
    output.number(index)?;
    output.raw("\"><h3>Node ")?;
    output.number(index + 1)?;
    output.raw(": <code>")?;
    value(output, &node.id)?;
    output.raw("</code></h3><dl>")?;
    field(
        output,
        "Node kind",
        &debug_snake(&format!("{:?}", node.kind)),
    )?;
    field_option(
        output,
        "Source-local ordinal",
        node.source_local_ordinal
            .map(|value| value.to_string())
            .as_deref(),
    )?;
    field_option(
        output,
        "Reported PID context (not instance identity)",
        node.reported_process_id
            .map(|value| value.to_string())
            .as_deref(),
    )?;
    field_option(output, "Context note", node.context_note)?;
    if let Some(evidence) = &node.evidence {
        output.raw("<dt>Node evidence</dt><dd>")?;
        write_evidence(output, evidence)?;
        output.raw("</dd>")?;
    }
    output.raw("</dl>")?;
    if let Some(event) = &node.event {
        output.raw("<h4>Event observation</h4><dl>")?;
        field(output, "Event kind", &event.event_kind)?;
        field(output, "Operation", &operation_label(&event.operation))?;
        if let Some(timestamp) = &event.source_timestamp {
            field(
                output,
                "Source timestamp (representation retained; no causal ordering)",
                &format!("{} {}", timestamp.value, timestamp.clock_unit),
            )?;
        }
        output.raw("<dt>Event evidence</dt><dd>")?;
        write_evidence(output, &event.evidence)?;
        output.raw("</dd></dl>")?;
        if !event.identity_context.is_empty() {
            output.raw("<h4>Identity context</h4><dl>")?;
            for context in &event.identity_context {
                field(
                    output,
                    &format!("{} (ambiguity)", context.kind),
                    &context.ambiguity,
                )?;
                field(
                    output,
                    &format!("{} (observed value)", context.kind),
                    &context.value,
                )?;
            }
            output.raw("</dl>")?;
        }
        if let Some(path) = &event.path_observation {
            output.raw("<h4>Path observation</h4><dl>")?;
            field(output, "Observed path spelling", &path.path)?;
            field(
                output,
                "Path basis",
                &debug_snake(&format!("{:?}", path.basis)),
            )?;
            output.raw("</dl>")?;
        }
    }
    if let Some(observation) = &node.process_observation {
        write_observation(output, observation)?;
    }
    if node.kind == EventGraphNodeKind::ProcessIdContext {
        output.raw("<p class=\"notice\">PID context only; this does not establish an owning process instance.</p>")?;
    }
    output.raw("</article>")
}

fn write_observation(output: &mut HtmlBuffer, observation: &ProcessObservation) -> io::Result<()> {
    output.raw("<h4>Process observation (source-local ID, not a PID key)</h4><dl>")?;
    field_number(
        output,
        "Source-local observation ID",
        observation.source_local_id,
    )?;
    match &observation.identity {
        ProcessIdentity::LinuxTraceTaskContext {
            task_id,
            observed_task_epoch,
            epoch_basis,
            identity_status,
        } => {
            field(output, "Identity kind", "linux_trace_task_context")?;
            field_number(
                output,
                "Trace task ID (not normalized to OS process identity)",
                *task_id,
            )?;
            field_option(
                output,
                "Observed task epoch",
                observed_task_epoch
                    .map(|value| value.to_string())
                    .as_deref(),
            )?;
            field(
                output,
                "Epoch basis",
                &debug_snake(&format!("{epoch_basis:?}")),
            )?;
            field(
                output,
                "Identity status",
                &debug_snake(&format!("{identity_status:?}")),
            )?;
        }
        ProcessIdentity::LinuxReturnedChildPid {
            process_id,
            identity_status,
        } => {
            field(output, "Identity kind", "linux_returned_child_pid")?;
            field_number(output, "Returned process ID", *process_id)?;
            field(
                output,
                "Identity status",
                &debug_snake(&format!("{identity_status:?}")),
            )?;
        }
        ProcessIdentity::WindowsProcessInstance {
            process_id,
            start_record_ordinal,
            reported_parent_process_id,
            identity_status,
        } => {
            field(output, "Identity kind", "windows_process_instance")?;
            field_number(output, "Process ID", *process_id)?;
            field_number(output, "Start-record ordinal", *start_record_ordinal)?;
            field_option(
                output,
                "Reported parent process ID (context)",
                reported_parent_process_id
                    .map(|value| value.to_string())
                    .as_deref(),
            )?;
            field(
                output,
                "Identity status",
                &debug_snake(&format!("{identity_status:?}")),
            )?;
        }
    }
    output.raw("<dt>Observation evidence</dt><dd>")?;
    write_evidence(output, &observation.evidence)?;
    output.raw("</dd><dt>End evidence</dt><dd>")?;
    match &observation.end_evidence {
        Some(evidence) => write_evidence(output, evidence)?,
        None => output.raw("Not available")?,
    }
    output.raw("</dd></dl>")
}

fn write_node_reference(output: &mut HtmlBuffer, graph: &EventGraph, id: &str) -> io::Result<()> {
    if let Some(index) = graph.nodes.iter().position(|node| node.id == id) {
        output.raw("<a href=\"#node-")?;
        output.number(index)?;
        output.raw("\"><code>")?;
        value(output, id)?;
        output.raw("</code></a>")
    } else {
        output.raw("<code>")?;
        value(output, id)?;
        output.raw("</code> (node not present in selected graph)")
    }
}

fn write_evidence_list(output: &mut HtmlBuffer, evidence: &[EvidenceReference]) -> io::Result<()> {
    if evidence.is_empty() {
        return output.raw("No evidence reference is attached.");
    }
    output.raw("<ul>")?;
    for item in evidence {
        output.raw("<li>")?;
        write_evidence(output, item)?;
        output.raw("</li>")?;
    }
    output.raw("</ul>")
}

fn write_evidence(output: &mut HtmlBuffer, evidence: &EvidenceReference) -> io::Result<()> {
    output.raw("<code>")?;
    match evidence {
        EvidenceReference::RawTraceRecord {
            line_number,
            byte_offset,
            byte_length,
        } => {
            output.raw("raw_trace_record line=")?;
            output.number(*line_number)?;
            output.raw(" byte_offset=")?;
            output.number(*byte_offset)?;
            output.raw(" byte_length=")?;
            output.number(*byte_length)?;
        }
        EvidenceReference::WindowsEtwRecord {
            record_ordinal,
            json_pointer,
            raw_payload_sha256,
        } => {
            output.raw("windows_etw_record ordinal=")?;
            output.number(*record_ordinal)?;
            output.raw(" json_pointer=")?;
            value(output, json_pointer)?;
            output.raw(" raw_payload_sha256=")?;
            value(output, raw_payload_sha256)?;
        }
    }
    output.raw("</code>")
}

fn field(output: &mut HtmlBuffer, label: &str, text: &str) -> io::Result<()> {
    output.raw("<dt>")?;
    value(output, label)?;
    output.raw("</dt><dd>")?;
    value(output, text)?;
    output.raw("</dd>")
}

fn field_number(
    output: &mut HtmlBuffer,
    label: &str,
    number: impl std::fmt::Display,
) -> io::Result<()> {
    field(output, label, &number.to_string())
}

fn field_option(output: &mut HtmlBuffer, label: &str, text: Option<&str>) -> io::Result<()> {
    if let Some(text) = text {
        field(output, label, text)
    } else {
        field(output, label, "Not available")
    }
}

fn write_string_list(output: &mut HtmlBuffer, values: &[String], empty: &str) -> io::Result<()> {
    if values.is_empty() {
        output.raw("<p>")?;
        value(output, empty)?;
        return output.raw("</p>");
    }
    output.raw("<ul>")?;
    for item in values {
        output.raw("<li>")?;
        value(output, item)?;
        output.raw("</li>")?;
    }
    output.raw("</ul>")
}

fn value(output: &mut HtmlBuffer, text: &str) -> io::Result<()> {
    output.raw("<bdi dir=\"auto\" class=\"value\">")?;
    let mut plain_start = 0;
    for (index, character) in text.char_indices() {
        if character.is_control() || is_bidi_control(character) {
            output.raw(&text[plain_start..index])?;
            output.raw("&amp;#x")?;
            output.raw(&format!("{:X}", character as u32))?;
            output.raw(";")?;
            plain_start = index + character.len_utf8();
            continue;
        }
        let escaped = match character {
            '&' => Some("&amp;"),
            '<' => Some("&lt;"),
            '>' => Some("&gt;"),
            '"' => Some("&quot;"),
            '\'' => Some("&#39;"),
            _ => None,
        };
        if let Some(escaped) = escaped {
            output.raw(&text[plain_start..index])?;
            output.raw(escaped)?;
            plain_start = index + character.len_utf8();
        }
    }
    output.raw(&text[plain_start..])?;
    output.raw("</bdi>")
}

fn is_bidi_control(character: char) -> bool {
    matches!(character as u32, 0x061C | 0x200E..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069)
}

fn operation_label(operation: &OperationSemantics) -> String {
    match operation {
        OperationSemantics::SyscallAttempt { result } => format!(
            "syscall_attempt result={}",
            result
                .map(|value| debug_snake(&format!("{value:?}")))
                .unwrap_or_else(|| "unknown".to_owned())
        ),
        OperationSemantics::NativeObservation => "native_observation".to_owned(),
    }
}

fn completeness_name(value: SourceCompleteness) -> &'static str {
    match value {
        SourceCompleteness::Complete => "complete",
        SourceCompleteness::Partial => "partial",
        SourceCompleteness::Unknown => "unknown",
    }
}

fn bool_name(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn debug_snake(value: &str) -> String {
    let mut result = String::with_capacity(value.len() + 8);
    for (index, character) in value.chars().enumerate() {
        if character.is_ascii_uppercase() && index > 0 {
            result.push('_');
        }
        result.push(character.to_ascii_lowercase());
    }
    result
}

#[derive(Default)]
struct HtmlBuffer {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl HtmlBuffer {
    fn raw(&mut self, text: &str) -> io::Result<()> {
        self.write_all(text.as_bytes())
    }
    fn number(&mut self, value: impl std::fmt::Display) -> io::Result<()> {
        self.raw(&value.to_string())
    }
}

impl Write for HtmlBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(new_len) = self.bytes.len().checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("event graph HTML size overflow"));
        };
        if new_len > MAX_EVENT_GRAPH_HTML_BYTES {
            self.exceeded = true;
            return Err(io::Error::other("event graph HTML output limit exceeded"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_EVENT_GRAPH_HTML_BYTES, write_event_graph_html};
    use crate::event::*;
    use crate::limits::MAX_REPORT_BYTES;

    fn descriptor(platform: SourcePlatform) -> SourceDescriptor {
        SourceDescriptor {
            platform,
            schema: "synthetic.capture".to_owned(),
            schema_version: 3,
            artifact: "synthetic-fixture-only".to_owned(),
            sha256: Some("a".repeat(64)),
        }
    }

    fn linux_graph() -> EventGraph {
        let evidence = EvidenceReference::RawTraceRecord {
            line_number: 9,
            byte_offset: 72,
            byte_length: 45,
        };
        EventGraph {
            schema: EVENT_GRAPH_SCHEMA,
            schema_version: EVENT_GRAPH_SCHEMA_VERSION,
            filter: EventGraphFilter {
                event_kind: Some("openat".to_owned()),
                process_observation_id: None,
            },
            source: descriptor(SourcePlatform::Linux),
            source_state: SourceState {
                completeness: SourceCompleteness::Partial,
                diagnostics: vec!["synthetic_partial_diagnostic".to_owned()],
                loss: None,
                identity_ambiguity_present: false,
            },
            semantics: "source-local event graph",
            nodes: vec![
                EventGraphNode {
                    id: "event:9".to_owned(),
                    kind: EventGraphNodeKind::Event,
                    source_local_ordinal: Some(9),
                    evidence: Some(evidence.clone()),
                    event: Some(CommonEvent {
                        source_local_ordinal: 9,
                        source_timestamp: Some(SourceTimestamp {
                            value: "1700000000.1".to_owned(),
                            clock_unit: "seconds".to_owned(),
                        }),
                        event_kind: "openat</title><script>alert(1)</script>\x1b[2J\u{202e}"
                            .to_owned(),
                        operation: OperationSemantics::SyscallAttempt {
                            result: Some(crate::model::SyscallOutcome::Success),
                        },
                        evidence: evidence.clone(),
                        identity_context: vec![EventIdentityContext {
                            kind: "path".to_owned(),
                            value: "<img src=x onerror=alert(1)>\u{202e}".to_owned(),
                            ambiguity: "lexical hint".to_owned(),
                        }],
                        path_observation: Some(EventPathObservation {
                            path: "/tmp/<script>.txt".to_owned(),
                            basis: EventPathBasis::LinuxStraceLexicalHint {
                                lexical_basis: crate::trace::LexicalPathBasis::AbsoluteArgument,
                            },
                        }),
                    }),
                    process_observation: None,
                    reported_process_id: None,
                    context_note: None,
                },
                EventGraphNode {
                    id: "pid_context:9".to_owned(),
                    kind: EventGraphNodeKind::ProcessIdContext,
                    source_local_ordinal: None,
                    evidence: Some(evidence.clone()),
                    event: None,
                    process_observation: None,
                    reported_process_id: Some(777),
                    context_note: Some("PID context only"),
                },
            ],
            edges: vec![EventGraphEdge {
                from_node_id: "event:9".to_owned(),
                to_node_id: "pid_context:9".to_owned(),
                kind: "event_process_link",
                relationship_kind: None,
                relationship_resolution: None,
                event_link_role: Some(EventProcessLinkRole::LinuxTraceCallerTaskContext),
                event_link_status: Some(EventProcessLinkStatus::ContextCandidate),
                basis: "synthetic source-row linkage".to_owned(),
                evidence: vec![evidence],
            }],
            diagnostics: vec![EventDiagnostic {
                code: "synthetic_diag".to_owned(),
                message: "fixture only".to_owned(),
                source_local_ordinal: Some(10),
                evidence: None,
            }],
        }
    }

    #[test]
    fn linux_html_escapes_hostile_values_and_links_nodes_offline() {
        let graph = linux_graph();
        let mut html = Vec::new();
        write_event_graph_html(&graph, &mut html).unwrap();
        let html = String::from_utf8(html).unwrap();
        assert!(html.contains("<a href=\"#node-1\">"));
        assert!(html.contains("id=\"node-0\""));
        assert!(html.contains("raw_trace_record line=9 byte_offset=72 byte_length=45"));
        assert!(html.contains("Source completeness"));
        assert!(html.contains("synthetic_partial_diagnostic"));
        assert!(html.contains("&lt;/title&gt;&lt;script&gt;"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("&amp;#x1B;[2J"));
        assert!(html.contains("&amp;#x202E;"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("default-src 'none'"));
        assert!(html.contains("script-src 'none'"));
        assert!(!html.contains("https://"));
        assert!(html.contains("synthetic-fixture-only"));
    }

    #[test]
    fn windows_synthetic_html_preserves_etw_links_and_process_end_evidence() {
        let evidence = EvidenceReference::WindowsEtwRecord {
            record_ordinal: 4,
            json_pointer: "/events/3</code><img src=x>\x1b[2J\u{202e}".to_owned(),
            raw_payload_sha256: "b".repeat(64),
        };
        let graph = EventGraph {
            schema: EVENT_GRAPH_SCHEMA,
            schema_version: EVENT_GRAPH_SCHEMA_VERSION,
            filter: EventGraphFilter {
                event_kind: None,
                process_observation_id: Some(2),
            },
            source: descriptor(SourcePlatform::Windows),
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
            semantics: "source-local",
            nodes: vec![EventGraphNode {
                id: "process:2".to_owned(),
                kind: EventGraphNodeKind::ProcessObservation,
                source_local_ordinal: None,
                evidence: Some(evidence.clone()),
                event: None,
                process_observation: Some(ProcessObservation {
                    source_local_id: 2,
                    identity: ProcessIdentity::WindowsProcessInstance {
                        process_id: 4321,
                        start_record_ordinal: 2,
                        reported_parent_process_id: Some(100),
                        identity_status: ProcessIdentityStatus::ObservedStart,
                    },
                    evidence: evidence.clone(),
                    end_evidence: Some(evidence.clone()),
                }),
                reported_process_id: None,
                context_note: None,
            }],
            edges: vec![EventGraphEdge {
                from_node_id: "pid_context:100".to_owned(),
                to_node_id: "process:2".to_owned(),
                kind: "process_relationship",
                relationship_kind: Some(
                    ProcessRelationshipKind::WindowsPayloadParentToChildInstance,
                ),
                relationship_resolution: Some(RelationshipResolution::ParentInstanceUnresolved),
                event_link_role: None,
                event_link_status: None,
                basis: "synthetic parent payload".to_owned(),
                evidence: vec![evidence.clone()],
            }],
            diagnostics: vec![EventDiagnostic {
                code: "fixture_diagnostic".to_owned(),
                message: "synthetic ETW only".to_owned(),
                source_local_ordinal: Some(4),
                evidence: Some(evidence),
            }],
        };
        let mut html = Vec::new();
        write_event_graph_html(&graph, &mut html).unwrap();
        let html = String::from_utf8(html).unwrap();
        assert!(html.contains("windows_etw_record ordinal=4"));
        assert!(html.contains("&lt;/code&gt;&lt;img src=x&gt;"));
        assert!(html.contains("&amp;#x1B;[2J"));
        assert!(html.contains("&amp;#x202E;"));
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("raw_payload_sha256="));
        assert!(html.contains("End evidence"));
        assert!(html.contains("Relationship resolution"));
        assert!(html.contains("parent_instance_unresolved"));
        assert!(html.contains("Reported loss"));
        assert!(html.contains("capture_incomplete"));
        assert!(html.contains("synthetic-fixture-only"));
    }

    #[test]
    fn empty_selection_notice_and_render_limit_are_fail_closed() {
        let mut graph = linux_graph();
        graph.nodes.clear();
        graph.edges.clear();
        let mut html = Vec::new();
        write_event_graph_html(&graph, &mut html).unwrap();
        assert!(
            String::from_utf8(html)
                .unwrap()
                .contains("An empty selection does not establish absence")
        );

        let mut too_large = linux_graph();
        too_large.source.artifact = "x".repeat(MAX_EVENT_GRAPH_HTML_BYTES + 1);
        let mut destination = Vec::new();
        assert!(write_event_graph_html(&too_large, &mut destination).is_err());
        assert!(
            destination.is_empty(),
            "writer must receive no partial document"
        );
        assert_eq!(MAX_EVENT_GRAPH_HTML_BYTES, MAX_REPORT_BYTES);
    }
}
