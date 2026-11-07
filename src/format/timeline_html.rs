use std::io::{self, Write};

use crate::event::{
    EventTimeline, EvidenceReference, OperationSemantics, ProcessIdentity, ProcessObservation,
    SourceCompleteness,
};
use crate::limits::MAX_REPORT_BYTES;

const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; frame-src 'none'; media-src 'none'; script-src 'none'";
pub const MAX_TIMELINE_HTML_BYTES: usize = MAX_REPORT_BYTES;

/// Render a bounded, static offline HTML review of one source-local timeline.
/// The complete bounded document is prepared before writing to the destination.
pub fn write_event_timeline_html<W: Write>(
    timeline: &EventTimeline,
    writer: &mut W,
) -> io::Result<()> {
    let mut out = HtmlBuffer::default();
    render(timeline, &mut out)?;
    writer.write_all(&out.bytes)
}

fn render(t: &EventTimeline, o: &mut HtmlBuffer) -> io::Result<()> {
    o.raw("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"")?;
    o.raw(CSP)?;
    o.raw("\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>SideEffect event timeline report</title><style>:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{max-width:78rem;margin:2rem auto;padding:0 1rem}.card{border:1px solid #8886;border-radius:.5rem;padding:1rem;margin:1rem 0}.notice{border-left:.25rem solid #b87900;padding:.5rem 1rem}dl{display:grid;grid-template-columns:minmax(12rem,18rem) minmax(0,1fr);gap:.35rem 1rem}dt{font-weight:600}.value{unicode-bidi:isolate;white-space:pre-wrap;overflow-wrap:anywhere}code{overflow-wrap:anywhere}@media(max-width:42rem){dl{grid-template-columns:1fr}}</style></head><body><main><h1>SideEffect source-local event timeline</h1><p class=\"notice\">This offline report shows one selected source-local timeline. Timestamps and links do not establish causality, ancestry, ownership, complete coverage, or safety. Review sensitive values before sharing.</p>")?;
    o.raw("<section class=\"card\"><h2>Source and selection</h2><dl>")?;
    field(o, "Timeline schema", t.schema)?;
    numfield(o, "Timeline schema version", t.schema_version)?;
    field(
        o,
        "Source platform",
        &snake(&format!("{:?}", t.source.platform)),
    )?;
    field(o, "Source schema", &t.source.schema)?;
    numfield(o, "Source schema version", t.source.schema_version)?;
    field(o, "Source artifact label", &t.source.artifact)?;
    option_field(o, "Source SHA-256", t.source.sha256.as_deref())?;
    field(
        o,
        "Source completeness",
        complete(t.source_state.completeness),
    )?;
    field(o, "Ordering", t.ordering)?;
    field(o, "Semantics", t.semantics)?;
    field(
        o,
        "Event-kind filter",
        t.filter.event_kind.as_deref().unwrap_or("Any"),
    )?;
    option_field(
        o,
        "Process observation filter (source-local ID)",
        t.filter
            .process_observation_id
            .map(|n| n.to_string())
            .as_deref(),
    )?;
    field(
        o,
        "Identity ambiguity present",
        if t.source_state.identity_ambiguity_present {
            "true"
        } else {
            "false"
        },
    )?;
    if let Some(loss) = &t.source_state.loss {
        field(
            o,
            "Reported loss",
            &format!(
                "events={} buffers={} statistics_available={}",
                loss.reported_events_lost, loss.reported_buffers_lost, loss.statistics_available
            ),
        )?;
    }
    o.raw("</dl><h3>Source diagnostics</h3>")?;
    strings(
        o,
        &t.source_state.diagnostics,
        "No source diagnostics were recorded.",
    )?;
    o.raw("</section>")?;
    if let Some(p) = &t.selected_process_observation {
        o.raw("<section><h2>Selected process observation</h2><article class=\"card\"><dl>")?;
        observation(o, p)?;
        o.raw("</dl></article></section>")?;
    }
    o.raw("<section><h2>Events (")?;
    o.number(t.items.len())?;
    o.raw(")</h2>")?;
    if t.items.is_empty() {
        o.raw("<p class=\"notice\">No events matched this selection. An empty or filtered timeline does not establish absence.</p>")?;
    }
    for (i, e) in t.items.iter().enumerate() {
        o.raw("<article class=\"card\"><h3>Event ")?;
        o.number(i + 1)?;
        o.raw("</h3><dl>")?;
        numfield(o, "Source-local ordinal", e.source_local_ordinal)?;
        match &e.source_timestamp {
            Some(ts) => field(
                o,
                "Source timestamp",
                &format!("{} [{}]", ts.value, ts.clock_unit),
            )?,
            None => field(o, "Source timestamp", "Unknown")?,
        }
        field(o, "Event kind", &e.event_kind)?;
        field(o, "Operation semantics", &operation(&e.operation))?;
        o.raw("<dt>Evidence locator</dt><dd>")?;
        evidence(o, &e.evidence)?;
        o.raw("</dd>")?;
        for c in &e.identity_context {
            field(
                o,
                &format!("Identity context: {}", c.kind),
                &format!("{} (ambiguity: {})", c.value, c.ambiguity),
            )?;
        }
        if let Some(p) = &e.path_observation {
            field(o, "Path observation", &p.path)?;
            field(o, "Path basis", &snake(&format!("{:?}", p.basis)))?;
        }
        o.raw("</dl></article>")?;
    }
    o.raw("</section><section><h2>Event-process links (")?;
    o.number(t.event_process_links.len())?;
    o.raw(")</h2>")?;
    if t.event_process_links.is_empty() {
        o.raw("<p>No event-process links are attached.</p>")?;
    }
    for (i, l) in t.event_process_links.iter().enumerate() {
        o.raw("<article class=\"card\"><h3>Link ")?;
        o.number(i + 1)?;
        o.raw("</h3><dl><dt>Event evidence locator</dt><dd>")?;
        evidence(o, &l.event)?;
        o.raw("</dd>")?;
        option_field(
            o,
            "Process observation ID (source-local)",
            l.process_observation_id.map(|v| v.to_string()).as_deref(),
        )?;
        option_field(
            o,
            "Reported process ID",
            l.reported_process_id.map(|v| v.to_string()).as_deref(),
        )?;
        field(o, "Role", &snake(&format!("{:?}", l.role)))?;
        field(o, "Status", &snake(&format!("{:?}", l.status)))?;
        field(o, "Basis", &l.basis)?;
        o.raw("</dl></article>")?;
    }
    o.raw("</section><section><h2>Timeline diagnostics (")?;
    o.number(t.diagnostics.len())?;
    o.raw(")</h2>")?;
    if t.diagnostics.is_empty() {
        o.raw("<p>No timeline diagnostics were recorded.</p>")?;
    } else {
        for d in &t.diagnostics {
            o.raw("<article class=\"card\"><dl>")?;
            field(o, "Code", &d.code)?;
            field(o, "Message", &d.message)?;
            option_field(
                o,
                "Source-local ordinal",
                d.source_local_ordinal.map(|v| v.to_string()).as_deref(),
            )?;
            o.raw("<dt>Evidence locator</dt><dd>")?;
            if let Some(e) = &d.evidence {
                evidence(o, e)?
            } else {
                o.raw("Not available")?;
            }
            o.raw("</dd></dl></article>")?;
        }
    }
    o.raw("</section><p class=\"notice\">Evidence locators refer to records in this source. Process observation IDs are local to this timeline. Partial or unknown source status remains visible.</p></main></body></html>\n")
}

fn observation(o: &mut HtmlBuffer, p: &ProcessObservation) -> io::Result<()> {
    numfield(o, "Source-local observation ID", p.source_local_id)?;
    match &p.identity {
        ProcessIdentity::LinuxTraceTaskContext {
            task_id,
            observed_task_epoch,
            epoch_basis,
            identity_status,
        } => {
            field(o, "Identity kind", "linux_trace_task_context")?;
            numfield(o, "Task ID", *task_id)?;
            option_field(
                o,
                "Observed task epoch",
                observed_task_epoch.map(|v| v.to_string()).as_deref(),
            )?;
            field(o, "Epoch basis", &snake(&format!("{:?}", epoch_basis)))?;
            field(
                o,
                "Identity status",
                &snake(&format!("{:?}", identity_status)),
            )?
        }
        ProcessIdentity::LinuxReturnedChildPid {
            process_id,
            identity_status,
        } => {
            field(o, "Identity kind", "linux_returned_child_pid")?;
            numfield(o, "Process ID", *process_id)?;
            field(
                o,
                "Identity status",
                &snake(&format!("{:?}", identity_status)),
            )?
        }
        ProcessIdentity::WindowsProcessInstance {
            process_id,
            start_record_ordinal,
            reported_parent_process_id,
            identity_status,
        } => {
            field(o, "Identity kind", "windows_process_instance")?;
            numfield(o, "Process ID", *process_id)?;
            numfield(o, "Start-record ordinal", *start_record_ordinal)?;
            option_field(
                o,
                "Reported parent process ID (context)",
                reported_parent_process_id.map(|v| v.to_string()).as_deref(),
            )?;
            field(
                o,
                "Identity status",
                &snake(&format!("{:?}", identity_status)),
            )?
        }
    }
    o.raw("<dt>Observation evidence</dt><dd>")?;
    evidence(o, &p.evidence)?;
    o.raw("</dd><dt>End evidence</dt><dd>")?;
    if let Some(e) = &p.end_evidence {
        evidence(o, e)?
    } else {
        o.raw("Not available")?;
    }
    o.raw("</dd>")
}
fn operation(v: &OperationSemantics) -> String {
    match v {
        OperationSemantics::SyscallAttempt { result } => format!(
            "syscall_attempt result={}",
            result
                .map(|x| snake(&format!("{x:?}")))
                .unwrap_or_else(|| "unknown".into())
        ),
        OperationSemantics::NativeObservation => "native_observation".into(),
    }
}
fn evidence(o: &mut HtmlBuffer, e: &EvidenceReference) -> io::Result<()> {
    o.raw("<code>")?;
    match e {
        EvidenceReference::RawTraceRecord {
            line_number,
            byte_offset,
            byte_length,
        } => {
            o.raw("raw_trace_record line=")?;
            o.number(*line_number)?;
            o.raw(" byte_offset=")?;
            o.number(*byte_offset)?;
            o.raw(" byte_length=")?;
            o.number(*byte_length)?
        }
        EvidenceReference::WindowsEtwRecord {
            record_ordinal,
            json_pointer,
            raw_payload_sha256,
        } => {
            o.raw("windows_etw_record ordinal=")?;
            o.number(*record_ordinal)?;
            o.raw(" json_pointer=")?;
            value(o, json_pointer)?;
            o.raw(" raw_payload_sha256=")?;
            value(o, raw_payload_sha256)?
        }
    }
    o.raw("</code>")
}
fn field(o: &mut HtmlBuffer, k: &str, v: &str) -> io::Result<()> {
    o.raw("<dt>")?;
    value(o, k)?;
    o.raw("</dt><dd>")?;
    value(o, v)?;
    o.raw("</dd>")
}
fn numfield(o: &mut HtmlBuffer, k: &str, v: impl std::fmt::Display) -> io::Result<()> {
    field(o, k, &v.to_string())
}
fn option_field(o: &mut HtmlBuffer, k: &str, v: Option<&str>) -> io::Result<()> {
    field(o, k, v.unwrap_or("Not available"))
}
fn strings(o: &mut HtmlBuffer, items: &[String], empty: &str) -> io::Result<()> {
    if items.is_empty() {
        return field(o, "Status", empty);
    }
    o.raw("<ul>")?;
    for s in items {
        o.raw("<li>")?;
        value(o, s)?;
        o.raw("</li>")?;
    }
    o.raw("</ul>")
}
fn complete(c: SourceCompleteness) -> &'static str {
    match c {
        SourceCompleteness::Complete => "complete",
        SourceCompleteness::Partial => "partial",
        SourceCompleteness::Unknown => "unknown",
    }
}
fn snake(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push('_')
        }
        out.push(c.to_ascii_lowercase())
    }
    out
}
fn value(o: &mut HtmlBuffer, s: &str) -> io::Result<()> {
    o.raw("<bdi dir=\"auto\" class=\"value\">")?;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        if c.is_control() || bidi(c) {
            o.raw(&s[start..i])?;
            o.raw("&amp;#x")?;
            o.raw(&format!("{:X}", c as u32))?;
            o.raw(";")?;
            start = i + c.len_utf8();
            continue;
        }
        let e = match c {
            '&' => Some("&amp;"),
            '<' => Some("&lt;"),
            '>' => Some("&gt;"),
            '"' => Some("&quot;"),
            '\'' => Some("&#39;"),
            _ => None,
        };
        if let Some(e) = e {
            o.raw(&s[start..i])?;
            o.raw(e)?;
            start = i + c.len_utf8();
        }
    }
    o.raw(&s[start..])?;
    o.raw("</bdi>")
}
fn bidi(c: char) -> bool {
    matches!(c as u32,0x061c|0x200e..=0x200f|0x202a..=0x202e|0x2066..=0x2069)
}
#[derive(Default)]
struct HtmlBuffer {
    bytes: Vec<u8>,
}
impl HtmlBuffer {
    fn raw(&mut self, s: &str) -> io::Result<()> {
        self.write_all(s.as_bytes())
    }
    fn number(&mut self, n: impl std::fmt::Display) -> io::Result<()> {
        self.raw(&n.to_string())
    }
}
impl Write for HtmlBuffer {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self
            .bytes
            .len()
            .checked_add(b.len())
            .ok_or_else(|| io::Error::other("timeline HTML size overflow"))?;
        if n > MAX_TIMELINE_HTML_BYTES {
            return Err(io::Error::other("timeline HTML output limit exceeded"));
        }
        self.bytes.try_reserve(b.len()).map_err(io::Error::other)?;
        self.bytes.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
