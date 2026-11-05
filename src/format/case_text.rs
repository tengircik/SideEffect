use crate::audit_session::{SessionStatus, SourceStatus};
use crate::case_evidence::{ArtifactReview, ResolvedCase, ResolvedEvidence};
use std::io::{self, Write};
pub const MAX_CASE_TEXT_BYTES: usize = 8 * 1024 * 1024;
/// Write a bounded terminal-review summary. Dynamic strings are rendered as inert ASCII.
pub fn write_case_text<W: Write>(case: &ResolvedCase, writer: &mut W) -> io::Result<()> {
    let mut bounded = BoundedOutput::default();
    render(case, &mut bounded)?;
    writer.write_all(&bounded.bytes)
}
fn render(case: &ResolvedCase, output: &mut BoundedOutput) -> io::Result<()> {
    output.raw("SideEffect case review\nCase: ")?;
    output.escaped(&case.case_id)?;
    output.raw("\nTitle: ")?;
    output.escaped(&case.title)?;
    output.raw("\nLifecycle: ")?;
    match &case.lifecycle {
        Some(lifecycle) => {
            output.raw(lifecycle.status.as_str())?;
            output.raw(" (revision ")?;
            output.number(lifecycle.revision)?;
            output.raw(")")?;
        }
        None => output.raw("untracked (legacy case; no lifecycle status)")?,
    }
    output.raw("\nResolution: ")?;
    output.raw(if incomplete(case) {
        "partial_or_unknown"
    } else {
        "complete_sources"
    })?;
    output.raw("\n\nSessions and sources:\n")?;
    if case.sessions.is_empty() {
        output.raw("  No sessions are bound to this case.\n")?;
    }
    for session in &case.sessions {
        output.raw("  session ")?;
        output.escaped(&session.session_id)?;
        output.raw(" platform=")?;
        output.escaped(&session.platform)?;
        output.raw(" status=")?;
        output.raw(session_status(session.status))?;
        output.raw(" manifest=v")?;
        output.number(session.manifest_schema_version)?;
        output.raw("\n")?;
        if session.sources.is_empty() {
            output.raw("    no sources declared\n")?;
        }
        for source in &session.sources {
            output.raw("    source ")?;
            output.raw(source_role(source.role))?;
            output.raw(" status=")?;
            output.raw(source_status(source.status))?;
            output.raw(" diagnostics=")?;
            if source.diagnostic_codes.is_empty() {
                output.raw("none")?;
            } else {
                for (index, diagnostic) in source.diagnostic_codes.iter().enumerate() {
                    if index > 0 {
                        output.raw(",")?;
                    }
                    output.escaped(diagnostic)?;
                }
            }
            output.raw("\n")?;
            if let Some(review) = &source.artifact_review {
                write_review(output, review)?;
            }
        }
    }
    output.raw("\nCase entries and evidence references:\n")?;
    if case.entries.is_empty() {
        output.raw("  No entries.\n")?;
    }
    for entry in &case.entries {
        output.raw("  entry ")?;
        output.escaped(&entry.id)?;
        output.raw(" kind=")?;
        output.raw(&format!("{:?}", entry.kind).to_ascii_lowercase())?;
        output.raw(" authorship=")?;
        output.escaped(&entry.authorship)?;
        output.raw(" text=")?;
        output.escaped(&entry.text)?;
        output.raw("\n")?;
        if entry.evidence_fact_indexes.is_empty() {
            output.raw("    unresolved: no evidence locator is attached\n")?;
        }
        for index in &entry.evidence_fact_indexes {
            if let Some(fact) = case.facts.get(*index) {
                write_fact(output, fact)?;
            } else {
                output.raw("    unresolved: evidence fact reference is unavailable\n")?;
            }
        }
    }
    output.raw("\nLimits: this summary reports supplied case entries and verified source references; it does not establish authenticity, causation, complete system coverage, or that analyst text is true.\n")?;
    Ok(())
}
fn write_fact(
    output: &mut BoundedOutput,
    fact: &crate::case_evidence::ResolvedEvidenceFact,
) -> io::Result<()> {
    let (session_id, manifest_sha256, artifact_sha256) = match &fact.locator {
        crate::case::CaseEvidenceLocator::LinuxTraceRecord {
            session_id,
            manifest_sha256,
            artifact_sha256,
            ..
        }
        | crate::case::CaseEvidenceLocator::WindowsEtwRecord {
            session_id,
            manifest_sha256,
            artifact_sha256,
            ..
        }
        | crate::case::CaseEvidenceLocator::SelectedRootEntry {
            session_id,
            manifest_sha256,
            artifact_sha256,
            ..
        } => (session_id, manifest_sha256, artifact_sha256),
    };
    output.raw("    evidence session=")?;
    output.escaped(session_id)?;
    output.raw(" manifest_sha256=")?;
    output.escaped(manifest_sha256)?;
    output.raw(" artifact_sha256=")?;
    output.escaped(artifact_sha256)?;
    output.raw("\n")?;
    match &fact.fact {
        ResolvedEvidence::LinuxTraceRecord {
            parse_status,
            record,
        } => {
            output.raw("    Linux trace record status=")?;
            output.raw(
                if *parse_status == crate::model::ParseCompleteness::Complete {
                    "complete"
                } else {
                    "partial"
                },
            )?;
            output.raw(" artifact=")?;
            output.escaped(&fact.artifact_path)?;
            output.raw(" locator=line:")?;
            output.number(record.evidence.line_number)?;
            output.raw(" byte:")?;
            output.number(record.evidence.byte_offset)?;
            output.raw("+")?;
            output.number(record.evidence.byte_length)?;
            if let Some(pid) = record.process_id {
                output.raw(" pid=")?;
                output.number(pid)?;
            }
            if let Some(syscall) = &record.syscall {
                output.raw(" syscall=")?;
                output.escaped(syscall)?;
            }
            if let Some(outcome) = record.outcome {
                output.raw(" outcome=")?;
                output.raw(&format!("{outcome:?}").to_ascii_lowercase())?;
            }
            output.raw("\n")?;
        }
        ResolvedEvidence::WindowsEtwRecord {
            collection_status,
            capture_completeness,
            record,
            ..
        } => {
            output.raw("    Windows ETW record collection=")?;
            output.raw(&format!("{collection_status:?}").to_ascii_lowercase())?;
            output.raw(" completeness=")?;
            output.escaped(capture_completeness)?;
            output.raw(" ordinal=")?;
            output.number(record.record_ordinal)?;
            if let crate::case::CaseEvidenceLocator::WindowsEtwRecord {
                capture_sha256,
                json_pointer,
                raw_payload_sha256,
                ..
            } = &fact.locator
            {
                output.raw(" capture=")?;
                output.escaped(capture_sha256)?;
                output.raw(" payload=")?;
                output.escaped(json_pointer)?;
                output.raw(" sha256=")?;
                output.escaped(raw_payload_sha256)?;
            }
            output.raw(" event=")?;
            output.escaped(&record.event_kind)?;
            output.raw("\n")?;
        }
        ResolvedEvidence::SelectedRootEntry {
            inventory_status,
            entry,
        } => {
            output.raw("    Selected-root entry status=")?;
            output.escaped(inventory_status)?;
            output.raw(" artifact=")?;
            output.escaped(&fact.artifact_path)?;
            output.raw(" entry=")?;
            output.number(entry.ordinal)?;
            output.raw(" name=")?;
            output.escaped(&entry.display_name)?;
            output.raw(" type=")?;
            output.escaped(&entry.object_type)?;
            output.raw("\n")?;
        }
    }
    Ok(())
}
fn write_review(output: &mut BoundedOutput, review: &ArtifactReview) -> io::Result<()> {
    match review {
        ArtifactReview::LinuxTrace {
            parse_status,
            diagnostics,
        } => {
            output.raw("      artifact parse=")?;
            output.raw(
                if *parse_status == crate::model::ParseCompleteness::Complete {
                    "complete"
                } else {
                    "partial"
                },
            )?;
            output.raw(" diagnostics=")?;
            for (index, diagnostic) in diagnostics.iter().enumerate() {
                if index > 0 {
                    output.raw(",")?;
                }
                output.escaped(&diagnostic.code)?;
            }
            if diagnostics.is_empty() {
                output.raw("none")?;
            }
            output.raw("\n")?;
        }
        ArtifactReview::WindowsEtw {
            collection_status,
            capture_completeness,
            event_loss,
            diagnostics,
            ..
        } => {
            output.raw("      artifact collection=")?;
            output.raw(&format!("{collection_status:?}").to_ascii_lowercase())?;
            output.raw(" completeness=")?;
            output.escaped(capture_completeness)?;
            output.raw(" loss=")?;
            output.number(event_loss.events_lost)?;
            output.raw(" diagnostics=")?;
            if diagnostics.is_empty() {
                output.raw("none")?;
            }
            for (index, diagnostic) in diagnostics.iter().enumerate() {
                if index > 0 {
                    output.raw(",")?;
                }
                output.escaped(diagnostic)?;
            }
            output.raw("\n")?;
        }
        ArtifactReview::SelectedRoot {
            inventory_status,
            diagnostics,
        } => {
            output.raw("      artifact inventory=")?;
            output.escaped(inventory_status)?;
            output.raw(" diagnostics=")?;
            if diagnostics.is_empty() {
                output.raw("none")?;
            }
            for (index, diagnostic) in diagnostics.iter().enumerate() {
                if index > 0 {
                    output.raw(",")?;
                }
                output.escaped(&diagnostic.code)?;
            }
            output.raw("\n")?;
        }
    }
    Ok(())
}
fn incomplete(case: &ResolvedCase) -> bool {
    case.sessions.is_empty()
        || case.sessions.iter().any(|session| {
            session.sources.is_empty()
                || session.status != SessionStatus::Complete
                || session
                    .sources
                    .iter()
                    .any(|source| source.status != SourceStatus::Complete)
        })
        || case.facts.iter().any(|fact| match &fact.fact {
            ResolvedEvidence::LinuxTraceRecord { parse_status, .. } => {
                *parse_status != crate::model::ParseCompleteness::Complete
            }
            ResolvedEvidence::WindowsEtwRecord {
                collection_status,
                capture_completeness,
                ..
            } => {
                *collection_status != crate::windows_runtime::CollectionStatus::Complete
                    || capture_completeness != "complete"
            }
            ResolvedEvidence::SelectedRootEntry {
                inventory_status, ..
            } => inventory_status != "complete",
        })
}
fn session_status(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Complete => "complete",
        SessionStatus::Partial => "partial",
    }
}
fn source_role(role: crate::audit_session::SourceRole) -> &'static str {
    match role {
        crate::audit_session::SourceRole::Packages => "packages",
        crate::audit_session::SourceRole::Processes => "processes",
        crate::audit_session::SourceRole::Permissions => "permissions",
        crate::audit_session::SourceRole::Startup => "startup",
        crate::audit_session::SourceRole::Runtime => "runtime",
        crate::audit_session::SourceRole::PathExecutables => "path_executables",
        crate::audit_session::SourceRole::SelectedRoot => "selected_root",
        crate::audit_session::SourceRole::Msix => "msix",
        crate::audit_session::SourceRole::AppPaths => "app_paths",
    }
}

fn source_status(status: SourceStatus) -> &'static str {
    match status {
        SourceStatus::Complete => "complete",
        SourceStatus::Partial => "partial",
        SourceStatus::Unknown => "unknown",
        SourceStatus::NotChecked => "not_checked",
        SourceStatus::Unsupported => "unsupported",
        SourceStatus::NotApplicable => "not_applicable",
        SourceStatus::Unavailable => "unavailable",
        SourceStatus::AccessDenied => "access_denied",
        SourceStatus::Failed => "failed",
        SourceStatus::TimedOut => "timed_out",
        SourceStatus::OutputLimitExceeded => "output_limit_exceeded",
    }
}
#[derive(Default)]
struct BoundedOutput {
    bytes: Vec<u8>,
}
impl BoundedOutput {
    fn raw(&mut self, text: &str) -> io::Result<()> {
        self.push(text.as_bytes())
    }
    fn number(&mut self, number: impl std::fmt::Display) -> io::Result<()> {
        self.raw(&number.to_string())
    }
    fn escaped(&mut self, text: &str) -> io::Result<()> {
        for ch in text.chars() {
            match ch {
                ' '..='~' if ch != '\\' => self.raw(&ch.to_string())?,
                '\\' => self.raw("\\\\")?,
                _ => {
                    let escaped = format!("\\u{{{:x}}}", ch as u32);
                    self.raw(&escaped)?;
                }
            }
        }
        Ok(())
    }
    fn push(&mut self, bytes: &[u8]) -> io::Result<()> {
        let new_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("case text size overflow"))?;
        if new_len > MAX_CASE_TEXT_BYTES {
            return Err(io::Error::other("case text output limit exceeded"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| io::Error::other("case text allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::{BoundedOutput, MAX_CASE_TEXT_BYTES, write_case_text};
    use crate::audit_session::{SessionStatus, SourceRole, SourceStatus};
    use crate::case::{CaseEntryKind, CaseEvidenceLocator, CaseLifecycle, CaseStatus};
    use crate::case_evidence::{
        ArtifactReview, ResolvedCase, ResolvedCaseEntry, ResolvedEvidence, ResolvedEvidenceFact,
        ResolvedSession, ResolvedSource,
    };
    use crate::model::{EvidenceReference, ParseCompleteness, TraceRecord, TraceRecordKind};
    use crate::query::{RootQueryEntry, RootQueryEvidence};
    use crate::windows_runtime::{CollectionStatus, EventLoss, NativeRuntimeEvent};
    #[test]
    fn terminal_controls_bidi_and_non_ascii_are_inert_ascii() {
        let mut output = BoundedOutput::default();
        output.escaped("a\x1b[31m\n\u{202e}é\\z").unwrap();
        let rendered = String::from_utf8(output.bytes).unwrap();
        assert_eq!(rendered, "a\\u{1b}[31m\\u{a}\\u{202e}\\u{e9}\\\\z");
        assert!(rendered.is_ascii());
    }
    #[test]
    fn bounded_output_rejects_growth_without_partial_export() {
        let mut output = BoundedOutput::default();
        output.bytes.resize(MAX_CASE_TEXT_BYTES, b'x');
        assert!(output.raw("y").is_err());
        assert_eq!(output.bytes.len(), MAX_CASE_TEXT_BYTES);
    }

    #[test]
    fn oversized_case_text_is_rejected_before_any_bytes_are_written() {
        let case = ResolvedCase {
            schema: "sideeffect.resolved_investigation_case",
            schema_version: 2,
            disclosure_note: "unused",
            case_id: "case".to_owned(),
            title: "x".repeat(MAX_CASE_TEXT_BYTES + 1),
            lifecycle: None,
            facts: Vec::new(),
            entries: Vec::new(),
            sessions: Vec::new(),
        };
        let mut destination = Vec::new();
        assert!(write_case_text(&case, &mut destination).is_err());
        assert!(destination.is_empty());
    }

    #[test]
    fn missing_sessions_or_declared_sources_remain_partial_or_unknown() {
        let mut case = ResolvedCase {
            schema: "sideeffect.resolved_investigation_case",
            schema_version: 2,
            disclosure_note: "unused",
            case_id: "case".to_owned(),
            title: "Title".to_owned(),
            lifecycle: None,
            facts: Vec::new(),
            entries: Vec::new(),
            sessions: Vec::new(),
        };
        let mut output = Vec::new();
        write_case_text(&case, &mut output).unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("Resolution: partial_or_unknown")
        );

        case.sessions.push(ResolvedSession {
            session_id: "0123456789abcdef0123456789abcdef".to_owned(),
            platform: "linux".to_owned(),
            manifest_schema_version: 12,
            manifest_sha256: "a".repeat(64),
            status: SessionStatus::Complete,
            sources: Vec::new(),
        });
        let mut output = Vec::new();
        write_case_text(&case, &mut output).unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("Resolution: partial_or_unknown")
        );
    }

    #[test]
    fn summary_keeps_source_status_diagnostics_and_each_evidence_locator() {
        let session_id = "0123456789abcdef0123456789abcdef".to_owned();
        let windows_session_id = "fedcba9876543210fedcba9876543210".to_owned();
        let root_session_id = "11112222333344445555666677778888".to_owned();
        let duplicate_root_session_id = "99990000aaaabbbbccccddddeeeeffff".to_owned();
        let digest = "a".repeat(64);
        let locators = [
            CaseEvidenceLocator::LinuxTraceRecord {
                session_id: session_id.clone(),
                manifest_sha256: "a".repeat(64),
                artifact_sha256: "b".repeat(64),
                line_number: 7,
                byte_offset: 40,
                byte_length: 12,
            },
            CaseEvidenceLocator::WindowsEtwRecord {
                session_id: windows_session_id.clone(),
                manifest_sha256: "c".repeat(64),
                artifact_sha256: "d".repeat(64),
                capture_sha256: "e".repeat(64),
                record_ordinal: 3,
                json_pointer: "/events/2".to_owned(),
                raw_payload_sha256: "f".repeat(64),
            },
            CaseEvidenceLocator::SelectedRootEntry {
                session_id: root_session_id.clone(),
                manifest_sha256: "1".repeat(64),
                artifact_sha256: "2".repeat(64),
                entry_ordinal: 9,
            },
        ];
        let mut facts = vec![
            ResolvedEvidenceFact {
                locator: locators[0].clone(),
                artifact_path: "trace.strace".to_owned(),
                fact: ResolvedEvidence::LinuxTraceRecord {
                    parse_status: ParseCompleteness::Partial,
                    record: TraceRecord {
                        kind: TraceRecordKind::Syscall,
                        evidence: EvidenceReference {
                            line_number: 7,
                            byte_offset: 40,
                            byte_length: 12,
                        },
                        raw_line: "ignored".to_owned(),
                        process_id: Some(22),
                        timestamp: None,
                        syscall: Some("openat".to_owned()),
                        raw_arguments: None,
                        raw_result: None,
                        outcome: None,
                        lexical_path_hint: None,
                    },
                },
            },
            ResolvedEvidenceFact {
                locator: locators[1].clone(),
                artifact_path: "runtime.windows.json".to_owned(),
                fact: ResolvedEvidence::WindowsEtwRecord {
                    collection_status: CollectionStatus::Partial,
                    capture_completeness: "unknown".to_owned(),
                    event_loss: EventLoss {
                        events_lost: 1,
                        log_buffers_lost: 0,
                        real_time_buffers_lost: 0,
                        loss_statistics_available: true,
                        observation: "test".to_owned(),
                        final_snapshot_available: true,
                    },
                    record: NativeRuntimeEvent {
                        record_ordinal: 3,
                        provider_guid: "provider".to_owned(),
                        event_id: 1,
                        event_version: 0,
                        opcode: 1,
                        event_kind: "ProcessStart".to_owned(),
                        header_process_id: 22,
                        header_thread_id: 1,
                        header_flags: 0,
                        timestamp_qpc: 5,
                        raw_payload_hex: "00".to_owned(),
                        payload_decoding: None,
                        observation_decoding: None,
                    },
                },
            },
            ResolvedEvidenceFact {
                locator: locators[2].clone(),
                artifact_path: "root-snapshot.json".to_owned(),
                fact: ResolvedEvidence::SelectedRootEntry {
                    inventory_status: "partial".to_owned(),
                    entry: RootQueryEntry {
                        ordinal: 9,
                        name_hex: "78".to_owned(),
                        display_name: "x".to_owned(),
                        object_type: "file".to_owned(),
                        size_bytes: Some(1),
                        modified_at_unix_ms: None,
                        content_sha256: None,
                        content_hash_status: None,
                        evidence: RootQueryEvidence {
                            artifact_path: "root-snapshot.json".to_owned(),
                            source: "selected_root".to_owned(),
                            entry_ordinal: 9,
                        },
                    },
                },
            },
        ];
        let mut duplicate_root = facts[2].clone();
        duplicate_root.locator = CaseEvidenceLocator::SelectedRootEntry {
            session_id: duplicate_root_session_id.clone(),
            manifest_sha256: "3".repeat(64),
            artifact_sha256: "4".repeat(64),
            entry_ordinal: 9,
        };
        facts.push(duplicate_root);
        let case = ResolvedCase {
            schema: "sideeffect.resolved_investigation_case",
            schema_version: 2,
            disclosure_note: "unused",
            case_id: "case-1".to_owned(),
            title: "Title".to_owned(),
            lifecycle: Some(CaseLifecycle {
                status: CaseStatus::InReview,
                revision: 2,
                previous_case_sha256: Some(digest),
            }),
            facts,
            entries: vec![
                ResolvedCaseEntry {
                    id: "E001".to_owned(),
                    kind: CaseEntryKind::Assertion,
                    authorship: "analyst_supplied_unverified".to_owned(),
                    text: "claim".to_owned(),
                    severity: None,
                    confidence: None,
                    evidence_fact_indexes: vec![0, 1, 2, 3],
                },
                ResolvedCaseEntry {
                    id: "N001".to_owned(),
                    kind: CaseEntryKind::Note,
                    authorship: "analyst_supplied_unverified".to_owned(),
                    text: "no evidence".to_owned(),
                    severity: None,
                    confidence: None,
                    evidence_fact_indexes: vec![],
                },
            ],
            sessions: vec![ResolvedSession {
                session_id: session_id.clone(),
                platform: "linux".to_owned(),
                manifest_schema_version: 12,
                manifest_sha256: "b".repeat(64),
                status: SessionStatus::Partial,
                sources: vec![ResolvedSource {
                    role: SourceRole::Runtime,
                    status: SourceStatus::Unknown,
                    diagnostic_codes: vec!["source-warning".to_owned()],
                    artifact_review: Some(ArtifactReview::LinuxTrace {
                        parse_status: ParseCompleteness::Partial,
                        diagnostics: vec![],
                    }),
                }],
            }],
        };
        let mut output = Vec::new();
        write_case_text(&case, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.is_ascii());
        assert!(text.contains("Resolution: partial_or_unknown"));
        assert!(text.contains("source runtime status=unknown diagnostics=source-warning"));
        assert!(text.contains(&format!(
            "evidence session={session_id} manifest_sha256={} artifact_sha256={}",
            "a".repeat(64),
            "b".repeat(64)
        )));
        assert!(text.contains(&format!(
            "evidence session={windows_session_id} manifest_sha256={} artifact_sha256={}",
            "c".repeat(64),
            "d".repeat(64)
        )));
        assert!(text.contains(&format!(
            "evidence session={root_session_id} manifest_sha256={} artifact_sha256={}",
            "1".repeat(64),
            "2".repeat(64)
        )));
        assert!(text.contains(&format!(
            "evidence session={duplicate_root_session_id} manifest_sha256={} artifact_sha256={}",
            "3".repeat(64),
            "4".repeat(64)
        )));
        assert_eq!(
            text.matches("artifact=root-snapshot.json entry=9 name=x")
                .count(),
            2
        );
        assert!(text.contains(
            "Linux trace record status=partial artifact=trace.strace locator=line:7 byte:40+12"
        ));
        assert!(text.contains(&format!(
            "Windows ETW record collection=partial completeness=unknown ordinal=3 capture={} payload=/events/2 sha256={}",
            "e".repeat(64),
            "f".repeat(64)
        )));
        assert!(
            text.contains("Selected-root entry status=partial artifact=root-snapshot.json entry=9")
        );
        assert!(text.contains("unresolved: no evidence locator is attached"));
    }
}
