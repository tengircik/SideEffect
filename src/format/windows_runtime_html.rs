use std::io::{self, Write};

use crate::windows_runtime::{CollectionStatus, WindowsRuntimeCapture};

const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; frame-src 'none'; media-src 'none'; script-src 'none'";

/// Write a static, self-contained HTML review of one validated Windows runtime capture.
/// Capture-derived values are emitted only as escaped text; the caller enforces the output cap.
pub fn write_windows_runtime_html<W: Write>(
    capture: &WindowsRuntimeCapture,
    source_sha256: &str,
    writer: &mut W,
) -> io::Result<()> {
    writer.write_all(b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")?;
    writer.write_all(b"<meta http-equiv=\"Content-Security-Policy\" content=\"")?;
    writer.write_all(CSP.as_bytes())?;
    writer.write_all(b"\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>SideEffect Windows runtime report</title>\n<style>:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{max-width:72rem;margin:2rem auto;padding:0 1rem}h1,h2{line-height:1.2}.context,.event{border:1px solid #8886;border-radius:.5rem;padding:1rem;margin:1rem 0}dl{display:grid;grid-template-columns:minmax(12rem,18rem) minmax(0,1fr);gap:.35rem 1rem}dt{font-weight:600}.value{unicode-bidi:isolate;white-space:pre-wrap;overflow-wrap:anywhere}.notice{border-left:.25rem solid #b87900;padding:.5rem 1rem}.skip-link{position:absolute;left:1rem;top:0;z-index:1;transform:translateY(-150%);background:Canvas;color:CanvasText;padding:.5rem 1rem;border:2px solid currentColor}.skip-link:focus{transform:translateY(1rem)}@media(max-width:40rem){dl{grid-template-columns:1fr;gap:0}dt{margin-top:.5rem}}</style>\n</head>\n<body>\n<a class=\"skip-link\" href=\"#report-content\">Skip to report content</a>\n<main id=\"report-content\" tabindex=\"-1\">\n<header><h1>SideEffect Windows runtime report</h1><p class=\"notice\">This is a review of one bounded, system-wide ETW capture. It may contain sensitive paths, process metadata, or network endpoints. Review before sharing.</p></header>\n<section class=\"context\"><h2>Capture context</h2><dl>\n<dt>Capture schema</dt><dd>")?;
    write_value(writer, &capture.schema)?;
    write!(
        writer,
        " v{}</dd>\n<dt>Capture profile</dt><dd>",
        capture.schema_version
    )?;
    write_value(writer, &capture.capture_profile)?;
    writer.write_all(b"</dd>\n<dt>Source file SHA-256</dt><dd>")?;
    write_value(writer, source_sha256)?;
    writer.write_all(b"</dd>\n<dt>Document representation SHA-256</dt><dd>")?;
    write_value(writer, &capture.document_sha256)?;
    writer.write_all(b"</dd>\n<dt>Fingerprint meaning</dt><dd>Identity and representation metadata only; not authenticity, redaction, or capture completeness.</dd>\n<dt>Authenticity</dt><dd>Not verified</dd>\n<dt>Capture completeness</dt><dd>Unknown</dd>\n<dt>Producer-reported collection status</dt><dd>")?;
    writer.write_all(status_name(capture.collection_status).as_bytes())?;
    writer.write_all(
        b" (not independently authenticated)</dd>\n<dt>Capture window (Unix milliseconds)</dt><dd>",
    )?;
    write!(
        writer,
        "{} to {}",
        capture.started_at_unix_ms, capture.ended_at_unix_ms
    )?;
    writer.write_all(b"</dd>\n<dt>Requested target process ID</dt><dd>")?;
    write!(writer, "{}", capture.target.process_id)?;
    writer.write_all(b"</dd>\n<dt>Provider scope</dt><dd>")?;
    write_value(writer, &capture.session.scope)?;
    writer.write_all(b"</dd>\n<dt>Providers</dt><dd>")?;
    write_value(writer, &capture.session.provider)?;
    writer.write_all(b"</dd>\n<dt>Reported event loss</dt><dd>")?;
    write!(
        writer,
        "events={} log_buffers={} real_time_buffers={} statistics_available={} final_snapshot_available={}",
        capture.event_loss.events_lost,
        capture.event_loss.log_buffers_lost,
        capture.event_loss.real_time_buffers_lost,
        capture.event_loss.loss_statistics_available,
        capture.event_loss.final_snapshot_available
    )?;
    writer.write_all(b"</dd>\n</dl></section>\n<p>Event evidence IDs are capture-document ordinals. They are not byte offsets into an ETL file. Header process/thread IDs are event context; they do not establish target attribution or causation. No root cause or system-wide completeness is inferred.</p>\n<section><h2>Observed event records (")?;
    write!(writer, "{}", capture.events.len())?;
    writer.write_all(b")</h2>")?;
    if capture.events.is_empty() {
        writer.write_all(b"<p>No event records were retained in this document.</p>")?;
    } else {
        for event in &capture.events {
            writer.write_all(b"<article class=\"event\"><h3>Event evidence ID ")?;
            write!(writer, "{}", event.record_ordinal)?;
            writer.write_all(b"</h3><dl>\n<dt>Event kind</dt><dd>")?;
            write_value(writer, &event.event_kind)?;
            writer.write_all(b"</dd>\n<dt>Provider GUID</dt><dd>")?;
            write_value(writer, &event.provider_guid)?;
            writer.write_all(b"</dd>\n<dt>Descriptor</dt><dd>")?;
            write!(
                writer,
                "id={} version={} opcode={}",
                event.event_id, event.event_version, event.opcode
            )?;
            writer.write_all(b"</dd>\n<dt>Header context (not payload identity)</dt><dd>")?;
            write!(
                writer,
                "process_id={} thread_id={} flags={}",
                event.header_process_id, event.header_thread_id, event.header_flags
            )?;
            writer.write_all(b"</dd>\n<dt>Timestamp (QPC ticks)</dt><dd>")?;
            write!(writer, "{}", event.timestamp_qpc)?;
            writer.write_all(b"</dd>\n<dt>Raw payload (hex)</dt><dd>")?;
            write_value(writer, &event.raw_payload_hex)?;
            writer.write_all(b"</dd>\n<dt>Decoded process payload</dt><dd>")?;
            match &event.payload_decoding {
                Some(value) => {
                    let serialized = serde_json::to_string(value).map_err(io::Error::other)?;
                    write_value(writer, &serialized)?;
                }
                None => writer.write_all(b"(not applicable or not present)")?,
            }
            writer.write_all(b"</dd>\n<dt>Decoded observation</dt><dd>")?;
            match &event.observation_decoding {
                Some(value) => {
                    let serialized = serde_json::to_string(value).map_err(io::Error::other)?;
                    write_value(writer, &serialized)?;
                }
                None => writer.write_all(b"(not applicable or not present)")?,
            }
            writer.write_all(b"</dd>\n</dl></article>\n")?;
        }
    }
    writer.write_all(b"</section>\n<section><h2>Diagnostics (")?;
    write!(writer, "{}", capture.diagnostics.len())?;
    writer.write_all(b")</h2><ul>")?;
    for diagnostic in &capture.diagnostics {
        writer.write_all(b"<li>")?;
        write_value(writer, diagnostic)?;
        writer.write_all(b"</li>")?;
    }
    writer.write_all(b"</ul></section>\n</main>\n</body>\n</html>\n")
}

fn write_value<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    writer.write_all(b"<span class=\"value\">")?;
    let mut plain_start = 0;
    for (index, character) in value.char_indices() {
        if character.is_control() || is_default_ignorable(character) {
            writer.write_all(&value.as_bytes()[plain_start..index])?;
            write!(writer, "&amp;#x{:X};", character as u32)?;
            plain_start = index + character.len_utf8();
            continue;
        }
        let escaped = match character {
            '&' => Some(&b"&amp;"[..]),
            '<' => Some(&b"&lt;"[..]),
            '>' => Some(&b"&gt;"[..]),
            '"' => Some(&b"&quot;"[..]),
            '\'' => Some(&b"&#39;"[..]),
            _ => None,
        };
        if let Some(escaped) = escaped {
            writer.write_all(&value.as_bytes()[plain_start..index])?;
            writer.write_all(escaped)?;
            plain_start = index + character.len_utf8();
        }
    }
    writer.write_all(&value.as_bytes()[plain_start..])?;
    writer.write_all(b"</span>")
}

fn is_default_ignorable(character: char) -> bool {
    matches!(
        character as u32,
        0x00AD
            | 0x034F
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2028..=0x2029
            | 0x2060..=0x206F
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
            | 0xE0100..=0xE01EF
    )
}

fn status_name(value: CollectionStatus) -> &'static str {
    match value {
        CollectionStatus::Complete => "complete",
        CollectionStatus::Partial => "partial",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::MAX_REPORT_BYTES;
    use crate::windows_runtime::{
        AppliedLimits, DecodedProcessPayload, EventLoss, MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES, MAX_WINDOWS_RUNTIME_EVENTS,
        MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES, NativeRuntimeEvent, ProcessDecodeStatus,
        SessionMetadata, StopReason, TargetOutcome, WINDOWS_RUNTIME_CAPTURE_SCHEMA,
        WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
    };

    fn make_capture(image: &str, observation: Option<serde_json::Value>) -> WindowsRuntimeCapture {
        WindowsRuntimeCapture {
            schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
            schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
            platform: "windows".to_owned(),
            capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
            collection_status: CollectionStatus::Partial,
            capture_completeness: "unknown".to_owned(),
            started_at_unix_ms: 1,
            ended_at_unix_ms: 2,
            requested_duration_seconds: 1,
            stop_reason: StopReason::TargetExited,
            target: TargetOutcome {
                process_id: 123,
                exit_code: None,
                status_available: false,
            },
            session: SessionMetadata {
                name: "NT Kernel Logger".to_owned(),
                provider: "<script>alert(1)</script>\u{202e}".to_owned(),
                scope: "system_wide_capture".to_owned(),
                buffer_size_kb_requested: 16,
                minimum_buffers_requested: 8,
                maximum_buffers_requested: 32,
                buffer_count_reported: 8,
                provider_process_id_header_semantics: "header process id is event context"
                    .to_owned(),
            },
            limits: AppliedLimits {
                maximum_duration_seconds: 60,
                maximum_events: MAX_WINDOWS_RUNTIME_EVENTS,
                maximum_total_payload_bytes: MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES,
                maximum_payload_bytes_per_event: MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
                maximum_document_bytes: MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
            },
            event_loss: EventLoss {
                events_lost: 1,
                log_buffers_lost: 0,
                real_time_buffers_lost: 0,
                loss_statistics_available: true,
                observation: "loss_reported".to_owned(),
                final_snapshot_available: true,
            },
            document_sha256: "a".repeat(64),
            events: vec![NativeRuntimeEvent {
                record_ordinal: 1,
                provider_guid: "{provider-guid}".to_owned(),
                event_id: 0,
                event_version: 2,
                opcode: 10,
                event_kind: "network_observation".to_owned(),
                header_process_id: 7,
                header_thread_id: 8,
                header_flags: 0,
                timestamp_qpc: 9,
                raw_payload_hex: "deadbeef".to_owned(),
                payload_decoding: observation.is_none().then(|| DecodedProcessPayload {
                    status: ProcessDecodeStatus::Decoded,
                    schema_name: Some("Process_V2".to_owned()),
                    schema_version: Some(2),
                    pointer_size_bytes: Some(8),
                    process_id: Some(123),
                    parent_process_id: Some(1),
                    image_file_name: Some(image.to_owned()),
                    diagnostic: None,
                }),
                observation_decoding: observation,
            }],
            diagnostics: vec!["capture may have lost events".to_owned()],
        }
    }

    fn render(capture: &WindowsRuntimeCapture, source: &str) -> String {
        let mut bytes = Vec::new();
        write_windows_runtime_html(capture, source, &mut bytes).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    struct Counter {
        bytes: usize,
        cap: usize,
    }
    impl Write for Counter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            let available = self.cap.saturating_sub(self.bytes);
            if available == 0 {
                return Err(io::Error::other("output cap exceeded"));
            }
            let count = available.min(buffer.len());
            self.bytes += count;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn emits_csp_and_escapes_injected_values_as_inert_text() {
        let html = render(
            &make_capture(
                "<script>alert(1)</script>\u{202e}",
                Some(
                    serde_json::json!({"url":"https://example.invalid/x?y=1&z=2","path":"<img src=x onerror=alert(1)>"}),
                ),
            ),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        assert!(html.contains("Content-Security-Policy"));
        assert!(html.contains("default-src 'none'"));
        assert!(html.contains("connect-src 'none'"));
        assert!(html.contains("script-src 'none'"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("<img"));
        assert!(html.contains("https://example.invalid")); // visible text only; never a link
        assert!(!html.contains("href=\"https://example.invalid"));
        assert!(!html.contains("src=\"https://example.invalid"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&amp;#x202E;"));
        assert!(html.contains("Event evidence ID 1"));
        assert!(html.contains("Authenticity</dt><dd>Not verified"));
        assert!(html.contains("Capture completeness</dt><dd>Unknown"));
        assert!(html.contains("capture may have lost events"));
        assert!(!html.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn exact_report_limit_is_accepted_and_one_byte_over_is_rejected() {
        let source = "b".repeat(64);
        let base = render(&make_capture("", None), &source);
        let exact = make_capture(&"x".repeat(MAX_REPORT_BYTES - base.len()), None);
        let mut counter = Counter {
            bytes: 0,
            cap: MAX_REPORT_BYTES,
        };
        write_windows_runtime_html(&exact, &source, &mut counter).unwrap();
        assert_eq!(counter.bytes, MAX_REPORT_BYTES);

        let over = make_capture(&"x".repeat(MAX_REPORT_BYTES + 1 - base.len()), None);
        let mut counter = Counter {
            bytes: 0,
            cap: MAX_REPORT_BYTES,
        };
        assert_eq!(
            write_windows_runtime_html(&over, &source, &mut counter)
                .unwrap_err()
                .to_string(),
            "output cap exceeded"
        );
        assert_eq!(counter.bytes, MAX_REPORT_BYTES);
    }
}
