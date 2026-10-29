use std::io::{self, Write};

use crate::windows_runtime::{CollectionStatus, WindowsRuntimeCapture};
use crate::windows_runtime_diff::{
    ComparisonStatus, EventDelta, EventDeltaStatus, EventEvidenceReference,
    WindowsRuntimeDiffSummary,
};

/// Render an aggregate comparison of validated Windows runtime captures.
/// Dynamic fingerprints are escaped as terminal-safe ASCII.
pub fn write_windows_runtime_diff_text<W: Write>(
    summary: &WindowsRuntimeDiffSummary,
    before: &WindowsRuntimeCapture,
    after: &WindowsRuntimeCapture,
    writer: &mut W,
) -> io::Result<()> {
    writer.write_all(b"SideEffect Windows runtime capture comparison\n")?;
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
    writer.write_all(b"\nObserved category count deltas:\n")?;
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
    writer.write_all(
        b"\nEvent-level observations (candidate matches do not prove event identity):\n",
    )?;
    if summary.event_changes.is_empty() {
        writer.write_all(b"  No event-level differences or candidate matches were observed.\n")?;
    }
    for change in &summary.event_changes {
        write_event_delta(writer, change)?;
    }
    writer.write_all(b"\nInterpretation limits:\n")?;
    writer.write_all(b"  Exact unchanged groups compare normalized records as multisets, ignoring only capture-local ordinal and QPC timestamp.\n")?;
    writer.write_all(b"  Candidate-changed groups use a unique operation/path or process/image key; this does not prove the same execution.\n")?;
    writer.write_all(b"  One-sided observations are not removals or additions; incomplete capture evidence can hide records.\n")?;
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
        "\n{label} producer collection status: {} (not independently authenticated)\n{label} retained event records: {}\n{label} reported event loss: events={} log_buffers={} realtime_buffers={}\n{label} loss statistics available: {}\n{label} final loss snapshot available: {}\n{label} capture diagnostics: {}\n{label} loss observation: ",
        collection_status_name(status),
        side.observed_event_count,
        side.event_loss.events_lost,
        side.event_loss.log_buffers_lost,
        side.event_loss.real_time_buffers_lost,
        side.event_loss.loss_statistics_available,
        side.event_loss.final_snapshot_available,
        side.diagnostics_count
    )?;
    write_quoted(writer, &side.event_loss.observation)?;
    writer.write_all(b"\n")
}

fn write_event_delta<W: Write>(writer: &mut W, delta: &EventDelta) -> io::Result<()> {
    writeln!(
        writer,
        "  {} [confidence={}; basis={}] category={}",
        event_status_name(delta.status),
        delta.confidence,
        delta.basis,
        delta.category
    )?;
    if let Some(diagnostic) = delta.diagnostic {
        writer.write_all(b"    Diagnostic: ")?;
        write_quoted(writer, diagnostic)?;
        writer.write_all(b"\n")?;
    }
    writer.write_all(b"    Before evidence:\n")?;
    write_event_references(writer, &delta.before)?;
    writer.write_all(b"    After evidence:\n")?;
    write_event_references(writer, &delta.after)
}

fn write_event_references<W: Write>(
    writer: &mut W,
    references: &[EventEvidenceReference],
) -> io::Result<()> {
    if references.is_empty() {
        return writer.write_all(b"      none\n");
    }
    for reference in references {
        writer.write_all(b"      capture=")?;
        write_quoted(writer, &reference.capture_sha256)?;
        write!(writer, " ordinal={} provider=", reference.record_ordinal)?;
        write_quoted(writer, &reference.provider_guid)?;
        writeln!(
            writer,
            " event_id={} version={} opcode={} kind={} category={}",
            reference.event_id,
            reference.event_version,
            reference.opcode,
            reference.event_kind,
            reference.category
        )?;
    }
    Ok(())
}

fn event_status_name(value: EventDeltaStatus) -> &'static str {
    match value {
        EventDeltaStatus::Unchanged => "unchanged",
        EventDeltaStatus::CandidateChanged => "candidate_changed",
        EventDeltaStatus::ObservedOnlyBefore => "observed_only_before",
        EventDeltaStatus::ObservedOnlyAfter => "observed_only_after",
    }
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
            schema_version: 2,
            algorithm: crate::windows_runtime_diff::ComparisonAlgorithm {
                id: "test\u{1b}[31m",
                version: 2,
                basis: "multiset_and_candidate_diff",
            },
            comparison_status: ComparisonStatus::Partial,
            capture_completeness: "unknown",
            before: crate::windows_runtime_diff::CaptureSide {
                document_sha256: "before\u{202e}".to_owned(),
                producer_collection_status: CollectionStatus::Complete,
                capture_completeness: "unknown",
                observed_event_count: 1,
                event_loss: crate::windows_runtime_diff::EventLossSummary {
                    events_lost: 0,
                    log_buffers_lost: 0,
                    real_time_buffers_lost: 0,
                    loss_statistics_available: true,
                    final_snapshot_available: true,
                    observation: "none".to_owned(),
                },
                diagnostics_count: 0,
            },
            after: crate::windows_runtime_diff::CaptureSide {
                document_sha256: "after".to_owned(),
                producer_collection_status: CollectionStatus::Partial,
                capture_completeness: "unknown",
                observed_event_count: 1,
                event_loss: crate::windows_runtime_diff::EventLossSummary {
                    events_lost: 0,
                    log_buffers_lost: 0,
                    real_time_buffers_lost: 0,
                    loss_statistics_available: true,
                    final_snapshot_available: true,
                    observation: "none".to_owned(),
                },
                diagnostics_count: 0,
            },
            categories: vec![crate::windows_runtime_diff::CategoryCountDelta {
                category: "process.start",
                before_count: 1,
                after_count: 0,
                observed_count_delta: -1,
                before_event_ordinals: vec![1],
                after_event_ordinals: vec![],
            }],
            event_changes: vec![],
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
        assert!(output.contains("Observed category count deltas"));
        assert!(output.contains("Event-level observations"));
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
