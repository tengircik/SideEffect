use std::io::{self, Write};

use crate::windows_runtime::{CollectionStatus, WindowsRuntimeCapture};

/// Render a validated Windows runtime capture using terminal-safe ASCII text.
/// Dynamic values are escaped and the producer's status remains an unverified claim.
pub fn write_windows_runtime_text<W: Write>(
    capture: &WindowsRuntimeCapture,
    writer: &mut W,
) -> io::Result<()> {
    writer.write_all(b"SideEffect Windows runtime inspection\n")?;
    writeln!(
        writer,
        "Schema: {} v{}",
        capture.schema, capture.schema_version
    )?;
    writer.write_all(b"Document SHA-256: ")?;
    write_quoted(writer, &capture.document_sha256)?;
    writer.write_all(b"\nRepresentation fingerprint: verified\nAuthenticity: not verified\n")?;
    writer.write_all(b"Capture completeness: unknown\nProducer-reported collection status: ")?;
    writer.write_all(status_name(capture.collection_status).as_bytes())?;
    writer.write_all(b" (not independently authenticated)\n")?;
    writeln!(
        writer,
        "Requested duration: {} seconds",
        capture.requested_duration_seconds
    )?;
    writeln!(
        writer,
        "Capture interval: {}..{} Unix ms",
        capture.started_at_unix_ms, capture.ended_at_unix_ms
    )?;
    writer.write_all(b"Stop reason: ")?;
    write_quoted(
        writer,
        &format!("{:?}", capture.stop_reason).to_ascii_lowercase(),
    )?;
    writeln!(writer, "\nTarget process ID: {}", capture.target.process_id)?;
    match capture.target.exit_code {
        Some(code) => writeln!(writer, "Target exit code: {code}")?,
        None => writer.write_all(b"Target exit code: unavailable\n")?,
    }
    writeln!(
        writer,
        "Target status available: {}",
        capture.target.status_available
    )?;
    writer.write_all(b"Session provider: ")?;
    write_quoted(writer, &capture.session.provider)?;
    writer.write_all(b"\nSession scope: ")?;
    write_quoted(writer, &capture.session.scope)?;
    writeln!(
        writer,
        "\nETW loss statistics available: {}",
        if capture.event_loss.loss_statistics_available {
            "yes"
        } else {
            "no"
        }
    )?;
    writeln!(
        writer,
        "ETW final loss snapshot: {}",
        if capture.event_loss.final_snapshot_available {
            "yes"
        } else {
            "no"
        }
    )?;
    writeln!(
        writer,
        "\nETW events lost: {}; log buffers lost: {}; real-time buffers lost: {}",
        capture.event_loss.events_lost,
        capture.event_loss.log_buffers_lost,
        capture.event_loss.real_time_buffers_lost
    )?;
    writer.write_all(b"ETW loss observation: ")?;
    write_quoted(writer, &capture.event_loss.observation)?;
    writeln!(writer, "\nEvents: {}", capture.events.len())?;

    for event in &capture.events {
        writeln!(writer, "\nEvent evidence ID: {}", event.record_ordinal)?;
        writer.write_all(b"  Event kind: ")?;
        write_quoted(writer, &event.event_kind)?;
        writer.write_all(b"\n")?;
        writer.write_all(b"  Provider GUID: ")?;
        write_quoted(writer, &event.provider_guid)?;
        writeln!(
            writer,
            "\n  Descriptor: id={} version={} opcode={}",
            event.event_id, event.event_version, event.opcode
        )?;
        writeln!(
            writer,
            "  Header context: process_id={} thread_id={} flags={}",
            event.header_process_id, event.header_thread_id, event.header_flags
        )?;
        writeln!(writer, "  QPC timestamp: {}", event.timestamp_qpc)?;
        writer.write_all(b"  Raw payload hex: ")?;
        write_quoted(writer, &event.raw_payload_hex)?;
        if let Some(decoded) = &event.payload_decoding {
            writer.write_all(b"\n  Process payload status: ")?;
            write_quoted(
                writer,
                &format!("{:?}", decoded.status).to_ascii_lowercase(),
            )?;
            if let Some(pid) = decoded.process_id {
                writeln!(writer, "\n  Payload process ID: {pid}")?;
            }
            if let Some(image) = &decoded.image_file_name {
                writer.write_all(b"  Image file name: ")?;
                write_quoted(writer, image)?;
                writer.write_all(b"\n")?;
            }
            if let Some(diagnostic) = &decoded.diagnostic {
                writer.write_all(b"  Process decode diagnostic: ")?;
                write_quoted(writer, diagnostic)?;
                writer.write_all(b"\n")?;
            }
        }
        if let Some(observation) = &event.observation_decoding {
            writer.write_all(b"  Observation decode: ")?;
            let rendered = serde_json::to_string(observation).map_err(io::Error::other)?;
            write_quoted(writer, &rendered)?;
            writer.write_all(b"\n")?;
        }
    }

    writeln!(writer, "\nDiagnostics: {}", capture.diagnostics.len())?;
    for diagnostic in &capture.diagnostics {
        writer.write_all(b"  ")?;
        write_quoted(writer, diagnostic)?;
        writer.write_all(b"\n")?;
    }
    writer.write_all(b"\nEvent evidence IDs are array ordinals in this document. They do not identify ETW source byte offsets. No command attribution, causation, or complete-coverage claim is made.\n")
}

fn write_quoted<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    writer.write_all(b"\"")?;
    for character in value.chars() {
        match character {
            '"' => writer.write_all(b"\\\"")?,
            '\\' => writer.write_all(b"\\\\")?,
            ' '..='~' => {
                let mut buffer = [0; 1];
                writer.write_all(character.encode_utf8(&mut buffer).as_bytes())?;
            }
            _ => write!(writer, "\\u{{{:X}}}", character as u32)?,
        }
    }
    writer.write_all(b"\"")
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
    use crate::windows_runtime::*;

    #[test]
    fn terminal_text_escapes_untrusted_event_strings_and_exposes_ordinals() {
        let capture = WindowsRuntimeCapture {
            schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
            schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
            platform: "windows".to_owned(),
            capture_profile: "test".to_owned(),
            collection_status: CollectionStatus::Partial,
            capture_completeness: "unknown".to_owned(),
            started_at_unix_ms: 1,
            ended_at_unix_ms: 2,
            requested_duration_seconds: 1,
            stop_reason: StopReason::TargetExited,
            target: TargetOutcome {
                process_id: 7,
                exit_code: None,
                status_available: false,
            },
            session: SessionMetadata {
                name: "logger".to_owned(),
                provider: "provider\u{1b}[31m".to_owned(),
                scope: "scope".to_owned(),
                buffer_size_kb_requested: 1,
                minimum_buffers_requested: 1,
                maximum_buffers_requested: 1,
                buffer_count_reported: 1,
                provider_process_id_header_semantics: "context".to_owned(),
            },
            limits: AppliedLimits {
                maximum_duration_seconds: 60,
                maximum_events: MAX_WINDOWS_RUNTIME_EVENTS,
                maximum_total_payload_bytes: MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES,
                maximum_payload_bytes_per_event: MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
                maximum_document_bytes: MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
            },
            event_loss: EventLoss {
                events_lost: 0,
                log_buffers_lost: 0,
                real_time_buffers_lost: 0,
                loss_statistics_available: false,
                observation: "unknown".to_owned(),
                final_snapshot_available: false,
            },
            document_sha256: "a".repeat(64),
            events: vec![NativeRuntimeEvent {
                record_ordinal: 1,
                provider_guid: "guid\nnext".to_owned(),
                event_id: 0,
                event_version: 0,
                opcode: 0,
                event_kind: "<script>".to_owned(),
                header_process_id: 1,
                header_thread_id: 2,
                header_flags: 0,
                timestamp_qpc: 3,
                raw_payload_hex: "".to_owned(),
                payload_decoding: None,
                observation_decoding: Some(serde_json::json!({"diagnostic": "\u{1b}[2J"})),
            }],
            diagnostics: vec!["ignored\rdiagnostic".to_owned()],
        };
        let mut output = Vec::new();
        write_windows_runtime_text(&capture, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Event evidence ID: 1"));
        assert!(output.contains("\\u{1B}[31m"));
        assert!(output.contains("\\u{A}"));
        assert!(!output.contains('\u{1b}'));
    }
}
