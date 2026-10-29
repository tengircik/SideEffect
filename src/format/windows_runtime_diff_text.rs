use std::io::{self, Write};

use crate::windows_runtime::{CollectionStatus, WindowsRuntimeCapture};
use crate::windows_runtime_diff::{ComparisonStatus, WindowsRuntimeDiffSummary};

/// Render an aggregate comparison of validated Windows runtime captures.
/// Dynamic fingerprints are escaped as terminal-safe ASCII.
pub fn write_windows_runtime_diff_text<W: Write>(
    summary: &WindowsRuntimeDiffSummary,
    before: &WindowsRuntimeCapture,
    after: &WindowsRuntimeCapture,
    writer: &mut W,
) -> io::Result<()> {
    writer.write_all(b"SideEffect Windows runtime aggregate comparison\n")?;
    writeln!(
        writer,
        "Schema: {} v{}",
        summary.schema, summary.schema_version
    )?;
    writer.write_all(b"Algorithm: ")?;
    write_quoted(writer, summary.algorithm.id)?;
    writeln!(writer, " v{}", summary.algorithm.version)?;
    writer.write_all(b"Comparison status: ")?;
    writer.write_all(status_name(summary.comparison_status).as_bytes())?;
    writer.write_all(b"\nCapture completeness: unknown\n")?;
    write_side(writer, "Before", &summary.before, before.collection_status)?;
    write_side(writer, "After", &summary.after, after.collection_status)?;
    writer.write_all(b"\nObserved category deltas (records are not paired):\n")?;
    if summary.categories.is_empty() {
        writer.write_all(b"  No supported categories were observed in either capture.\n")?;
    }
    for category in &summary.categories {
        writeln!(
            writer,
            "  {}: before={} after={} observed_count_delta={}",
            category.category,
            category.before_count,
            category.after_count,
            category.observed_count_delta
        )?;
        writer.write_all(b"    Before event ordinals: ")?;
        write_ordinals(writer, &category.before_event_ordinals)?;
        writer.write_all(b"\n    After event ordinals: ")?;
        write_ordinals(writer, &category.after_event_ordinals)?;
        writer.write_all(b"\n")?;
    }
    writer.write_all(b"\nInterpretation limits:\n")?;
    writer.write_all(
        b"  Counts describe observed category records only; individual records are not paired.\n",
    )?;
    writer.write_all(b"  A count difference does not establish event absence, operation success, causation, or target attribution.\n")?;
    writer.write_all(b"  Capture completeness remains unknown, even when both producers report complete collection.\n")?;
    writer.write_all(b"  Event ordinals refer to positions in their own capture documents, not source byte offsets.\n")?;
    if !summary.diagnostics.is_empty() {
        writer.write_all(b"\nDiagnostics:\n")?;
        for diagnostic in &summary.diagnostics {
            writer.write_all(b"  ")?;
            write_quoted(writer, diagnostic)?;
            writer.write_all(b"\n")?;
        }
    }
    Ok(())
}

fn write_side<W: Write>(
    writer: &mut W,
    label: &str,
    side: &crate::windows_runtime_diff::CaptureSide,
    status: CollectionStatus,
) -> io::Result<()> {
    write!(writer, "{label} capture SHA-256: ")?;
    write_quoted(writer, &side.document_sha256)?;
    write!(
        writer,
        "\n{label} producer collection status: {} (not independently authenticated)\n{label} retained event records: {}\n",
        collection_status_name(status),
        side.observed_event_count
    )
}

fn write_ordinals<W: Write>(writer: &mut W, ordinals: &[u64]) -> io::Result<()> {
    if ordinals.is_empty() {
        return writer.write_all(b"none");
    }
    for (index, ordinal) in ordinals.iter().enumerate() {
        if index > 0 {
            writer.write_all(b", ")?;
        }
        write!(writer, "{ordinal}")?;
    }
    Ok(())
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

fn status_name(value: ComparisonStatus) -> &'static str {
    match value {
        ComparisonStatus::Complete => "complete",
        ComparisonStatus::Partial => "partial",
    }
}

fn collection_status_name(value: CollectionStatus) -> &'static str {
    match value {
        CollectionStatus::Complete => "complete",
        CollectionStatus::Partial => "partial",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_terminal_safe_and_states_comparison_limits() {
        let mut summary = WindowsRuntimeDiffSummary {
            schema: "sideeffect.windows_runtime_diff_summary",
            schema_version: 1,
            algorithm: crate::windows_runtime_diff::ComparisonAlgorithm {
                id: "test\u{1b}[31m",
                version: 1,
                basis: "counts_only",
            },
            comparison_status: ComparisonStatus::Partial,
            capture_completeness: "unknown",
            before: crate::windows_runtime_diff::CaptureSide {
                document_sha256: "before\u{202e}".to_owned(),
                producer_collection_status: CollectionStatus::Complete,
                capture_completeness: "unknown",
                observed_event_count: 1,
            },
            after: crate::windows_runtime_diff::CaptureSide {
                document_sha256: "after".to_owned(),
                producer_collection_status: CollectionStatus::Partial,
                capture_completeness: "unknown",
                observed_event_count: 1,
            },
            categories: vec![crate::windows_runtime_diff::CategoryCountDelta {
                category: "process.start",
                before_count: 1,
                after_count: 0,
                observed_count_delta: -1,
                before_event_ordinals: vec![1],
                after_event_ordinals: vec![],
            }],
            diagnostics: vec!["partial"],
            limitations: vec![],
        };
        summary.before.document_sha256.push('\u{1b}');
        let capture = |status| WindowsRuntimeCapture {
            schema: "sideeffect.windows_runtime_capture".to_owned(),
            schema_version: 3,
            platform: "windows".to_owned(),
            capture_profile: "test".to_owned(),
            collection_status: status,
            capture_completeness: "unknown".to_owned(),
            started_at_unix_ms: 0,
            ended_at_unix_ms: 0,
            requested_duration_seconds: 1,
            stop_reason: crate::windows_runtime::StopReason::TargetExited,
            target: crate::windows_runtime::TargetOutcome {
                process_id: 1,
                exit_code: Some(0),
                status_available: true,
            },
            session: crate::windows_runtime::SessionMetadata {
                name: "session".to_owned(),
                provider: "provider".to_owned(),
                scope: "scope".to_owned(),
                buffer_size_kb_requested: 1,
                minimum_buffers_requested: 1,
                maximum_buffers_requested: 1,
                buffer_count_reported: 1,
                provider_process_id_header_semantics: "context".to_owned(),
            },
            limits: crate::windows_runtime::AppliedLimits {
                maximum_duration_seconds: 60,
                maximum_events: 50_000,
                maximum_total_payload_bytes: 8 * 1024 * 1024,
                maximum_payload_bytes_per_event: 64 * 1024,
                maximum_document_bytes: 32 * 1024 * 1024,
            },
            event_loss: crate::windows_runtime::EventLoss {
                events_lost: 0,
                log_buffers_lost: 0,
                real_time_buffers_lost: 0,
                loss_statistics_available: true,
                observation: "none".to_owned(),
                final_snapshot_available: true,
            },
            document_sha256: "hash".to_owned(),
            events: vec![],
            diagnostics: vec![],
        };
        let before = capture(CollectionStatus::Complete);
        let after = capture(CollectionStatus::Partial);
        let mut output = Vec::new();
        write_windows_runtime_diff_text(&summary, &before, &after, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Observed category deltas"));
        assert!(output.contains("records are not paired"));
        assert!(
            output.contains("event absence, operation success, causation, or target attribution")
        );
        assert!(output.contains("\\u{1B}[31m"));
        assert!(output.contains("\\u{202E}"));
        assert!(!output.contains('\u{1b}'));
        assert!(output.contains("Before event ordinals: 1"));
        assert!(output.contains("After event ordinals: none"));
    }
}
