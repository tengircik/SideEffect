use std::io::{self, Write};

use crate::case_evidence::{ResolvedCase, ResolvedEvidenceFact};

const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; frame-src 'none'; media-src 'none'; script-src 'none'";

/// Exact renderer field groups that an analyst can omit from a resolved case HTML export.
/// This is deliberately not a substring detector or secret scanner.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaseHtmlRedactionPolicy {
    pub case_text: bool,
    pub artifact_paths: bool,
    pub source_records: bool,
    pub evidence_identifiers: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedactionPreviewItem {
    pub field_group: &'static str,
    pub selected_for_redaction: bool,
    /// The existing redaction-policy omission count. This remains unchanged.
    pub affected_field_occurrences: usize,
    /// Renderer-known field/record occurrences before applying policy; this is
    /// not a scan or content taxonomy.
    pub known_rendered_occurrences: usize,
    /// Renderer-known occurrences visible under the selected policy.
    pub retained_rendered_occurrences: usize,
    /// Known occurrences not visible under the selected policy.
    pub omitted_rendered_occurrences: usize,
}

/// Return counts only; preview output intentionally never includes the values being removed.
pub fn preview_case_html_redactions(
    case: &ResolvedCase,
    policy: CaseHtmlRedactionPolicy,
) -> Result<Vec<RedactionPreviewItem>, serde_json::Error> {
    let case_text_count = 1 + case.entries.len();
    let nested_artifact_paths = case.facts.iter().try_fold(0usize, |count, fact| {
        let source_record = serde_json::to_value(&fact.fact)?;
        Ok::<usize, serde_json::Error>(
            count + count_exact_named_fields(&source_record, "artifact_path"),
        )
    })?;
    let artifact_path_count = case.facts.len() + nested_artifact_paths;
    // Preserve the historical selected-omission count: when source records
    // are also omitted, only the separate top-level artifact fields belong to
    // the artifact-path policy's count.
    let artifact_path_affected = if policy.artifact_paths {
        case.facts.len()
            + if policy.source_records {
                0
            } else {
                nested_artifact_paths
            }
    } else {
        0
    };
    let artifact_path_retained = if policy.artifact_paths {
        0
    } else {
        case.facts.len()
            + if policy.source_records {
                0
            } else {
                nested_artifact_paths
            }
    };
    let source_record_count = case.facts.len();
    let source_records_retained = if policy.source_records {
        0
    } else {
        source_record_count
    };
    let evidence_identifier_count =
        1 + case.entries.len() + case.sessions.len() * 2 + case.facts.len();

    Ok(vec![
        preview_item(
            "case-text",
            policy.case_text,
            if policy.case_text { case_text_count } else { 0 },
            case_text_count,
            if policy.case_text { 0 } else { case_text_count },
        ),
        preview_item(
            "artifact-paths",
            policy.artifact_paths,
            artifact_path_affected,
            artifact_path_count,
            artifact_path_retained,
        ),
        preview_item(
            "source-records",
            policy.source_records,
            if policy.source_records {
                source_record_count
            } else {
                0
            },
            source_record_count,
            source_records_retained,
        ),
        preview_item(
            "evidence-identifiers",
            policy.evidence_identifiers,
            if policy.evidence_identifiers {
                evidence_identifier_count
            } else {
                0
            },
            evidence_identifier_count,
            if policy.evidence_identifiers {
                0
            } else {
                evidence_identifier_count
            },
        ),
    ])
}

fn preview_item(
    field_group: &'static str,
    selected_for_redaction: bool,
    affected_field_occurrences: usize,
    known_rendered_occurrences: usize,
    retained_rendered_occurrences: usize,
) -> RedactionPreviewItem {
    RedactionPreviewItem {
        field_group,
        selected_for_redaction,
        affected_field_occurrences,
        known_rendered_occurrences,
        retained_rendered_occurrences,
        omitted_rendered_occurrences: known_rendered_occurrences - retained_rendered_occurrences,
    }
}

/// Render resolved case evidence as a static offline report.
///
/// Case text and source evidence are untrusted and may be sensitive. Dynamic strings are emitted
/// only as escaped text; the caller must enforce a rendered-output byte limit.
pub fn write_case_html<W: Write>(case: &ResolvedCase, writer: &mut W) -> io::Result<()> {
    write_case_html_with_redactions(case, writer, CaseHtmlRedactionPolicy::default())
}

pub fn write_case_html_with_redactions<W: Write>(
    case: &ResolvedCase,
    writer: &mut W,
    redactions: CaseHtmlRedactionPolicy,
) -> io::Result<()> {
    writer.write_all(b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta http-equiv=\"Content-Security-Policy\" content=\"")?;
    writer.write_all(CSP.as_bytes())?;
    writer.write_all(b"\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>SideEffect investigation case</title>\n<style>:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{max-width:76rem;margin:2rem auto;padding:0 1rem}h1,h2,h3{line-height:1.25}.notice{border-left:.25rem solid #b87900;padding:.5rem 1rem}.card{border:1px solid #8886;border-radius:.5rem;padding:1rem;margin:1rem 0}dl{display:grid;grid-template-columns:minmax(10rem,16rem) minmax(0,1fr);gap:.35rem 1rem}dt{font-weight:600}.value{unicode-bidi:isolate;white-space:pre-wrap;overflow-wrap:anywhere}pre{overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid #8886;border-radius:.35rem;padding:1rem}.skip-link{position:absolute;left:1rem;top:0;z-index:1;transform:translateY(-150%);background:Canvas;color:CanvasText;padding:.5rem 1rem;border:2px solid currentColor}.skip-link:focus{transform:translateY(1rem)}@media(max-width:40rem){dl{grid-template-columns:1fr;gap:0}dt{margin-top:.5rem}}</style>\n</head>\n<body>\n<a class=\"skip-link\" href=\"#report-content\">Skip to report content</a>\n<main id=\"report-content\" tabindex=\"-1\">\n<header><h1>Investigation case: ")?;
    write_redacted_text(writer, &case.title, redactions.case_text, "case text")?;
    if has_redactions(redactions) {
        writer.write_all(b"</h1><p class=\"notice\">Redacted export. Only the explicitly selected structured fields were omitted. This does not detect sensitive substrings in remaining text or guarantee that the report is safe to share; review the complete output.</p><p class=\"notice\">This report does not authenticate session producers or verify analyst assertions.</p></header>\n<section class=\"card\"><h2>Case context</h2><dl><dt>Case ID</dt><dd>")?;
    } else {
        writer.write_all(b"</h1><p class=\"notice\">This report contains local audit evidence and analyst-supplied text. It may expose sensitive paths, arguments, process data, or payloads. Review before sharing. It does not authenticate session producers or verify analyst assertions.</p></header>\n<section class=\"card\"><h2>Case context</h2><dl><dt>Case ID</dt><dd>")?;
    }
    write_redacted_text(
        writer,
        &case.case_id,
        redactions.evidence_identifiers,
        "evidence identifier",
    )?;
    let lifecycle_html = if let Some(lifecycle) = &case.lifecycle {
        format!(
            "</dd><dt>Case status</dt><dd>{}</dd><dt>Case revision</dt><dd>{}",
            lifecycle.status.as_str(),
            lifecycle.revision
        )
    } else {
        "</dd><dt>Case status</dt><dd>not tracked in schema v1".to_owned()
    };
    writeln!(
        writer,
        "{lifecycle_html}</dd><dt>Schema</dt><dd>{} v{}</dd><dt>Sessions</dt><dd>{}</dd><dt>Entries</dt><dd>{}</dd><dt>Resolved evidence facts</dt><dd>{}</dd></dl></section>",
        case.schema,
        case.schema_version,
        case.sessions.len(),
        case.entries.len(),
        case.facts.len()
    )?;

    if has_redactions(redactions) {
        write_redaction_receipt(writer, case, redactions)?;
    }

    writer.write_all(b"<section><h2>Sessions</h2>")?;
    for session in &case.sessions {
        writer.write_all(b"<article class=\"card\"><h3>Session ")?;
        write_redacted_text(
            writer,
            &session.session_id,
            redactions.evidence_identifiers,
            "evidence identifier",
        )?;
        writer.write_all(b"</h3><dl><dt>Platform</dt><dd>")?;
        write_text(writer, &session.platform)?;
        write!(
            writer,
            "</dd><dt>Manifest schema version</dt><dd>{}</dd><dt>Manifest SHA-256</dt><dd>",
            session.manifest_schema_version
        )?;
        write_redacted_text(
            writer,
            &session.manifest_sha256,
            redactions.evidence_identifiers,
            "evidence identifier",
        )?;
        writer.write_all(b"</dd><dt>Session status</dt><dd>")?;
        write_text(writer, status_name(session.status))?;
        writer.write_all(b"</dd></dl><h4>Sources</h4><ul>")?;
        for source in &session.sources {
            writer.write_all(b"<li>")?;
            write_text(
                writer,
                &format!("{:?}: {}", source.role, source_status_name(source.status)),
            )?;
            if !source.diagnostic_codes.is_empty() {
                writer.write_all(b"; diagnostics: ")?;
                write_text(writer, &source.diagnostic_codes.join(", "))?;
            }
            writer.write_all(b"</li>")?;
        }
        writer.write_all(b"</ul></article>")?;
    }
    writer.write_all(b"</section>\n<section><h2>Analyst entries</h2>")?;
    if case.entries.is_empty() {
        writer.write_all(b"<p>No analyst entries were added.</p>")?;
    }
    for entry in &case.entries {
        writer.write_all(b"<article class=\"card\"><h3>Entry ")?;
        write_redacted_text(
            writer,
            &entry.id,
            redactions.evidence_identifiers,
            "evidence identifier",
        )?;
        writer.write_all(b"</h3><dl><dt>Kind</dt><dd>")?;
        write_text(writer, entry.kind.label())?;
        writer.write_all(b"</dd><dt>Authorship</dt><dd>")?;
        write_text(writer, &entry.authorship)?;
        writer.write_all(b"</dd><dt>Statement</dt><dd><span class=\"value\">")?;
        write_redacted_text(writer, &entry.text, redactions.case_text, "case text")?;
        writer.write_all(b"</span></dd>")?;
        if let Some(severity) = entry.severity {
            writer.write_all(b"<dt>Analyst severity</dt><dd>")?;
            write_text(writer, &format!("{severity:?}"))?;
            writer.write_all(b" (analyst supplied)</dd>")?;
        }
        if let Some(confidence) = entry.confidence {
            writer.write_all(b"<dt>Analyst confidence</dt><dd>")?;
            write_text(writer, &format!("{confidence:?}"))?;
            writer.write_all(b" (analyst supplied)</dd>")?;
        }
        writer.write_all(b"<dt>Evidence references</dt><dd>")?;
        if entry.evidence_fact_indexes.is_empty() {
            writer.write_all(b"None")?;
        } else {
            for (position, fact_index) in entry.evidence_fact_indexes.iter().enumerate() {
                if position > 0 {
                    writer.write_all(b", ")?;
                }
                if *fact_index < case.facts.len() {
                    write!(
                        writer,
                        "<a href=\"#fact-{fact_index}\">Fact {}</a>",
                        fact_index + 1
                    )?;
                } else {
                    write!(writer, "Unavailable fact reference {}", fact_index + 1)?;
                }
            }
        }
        writer.write_all(b"</dd></dl></article>")?;
    }
    writer.write_all(b"</section>\n<section><h2>Resolved evidence</h2>")?;
    if case.facts.is_empty() {
        writer.write_all(b"<p>No evidence locators were resolved.</p>")?;
    }
    for (index, fact) in case.facts.iter().enumerate() {
        write_fact(index, fact, writer, redactions)?;
    }
    writer.write_all(b"</section>\n</main>\n</body>\n</html>\n")
}

fn write_redaction_receipt<W: Write>(
    writer: &mut W,
    case: &ResolvedCase,
    policy: CaseHtmlRedactionPolicy,
) -> io::Result<()> {
    let inventory = preview_case_html_redactions(case, policy).map_err(io::Error::other)?;
    writer.write_all(b"<section class=\"card\" aria-labelledby=\"redaction-receipt-heading\"><h2 id=\"redaction-receipt-heading\">Redaction receipt</h2><p>Counts describe renderer-known field occurrences and source-record blocks only. This is structural information; no content or secret scan was performed. It is not a secret scan and does not make this report safe to share.</p><ul>")?;
    for item in inventory.iter().filter(|item| item.selected_for_redaction) {
        let unit = if item.field_group == "source-records" {
            "source-record block(s)"
        } else {
            "renderer field occurrence(s)"
        };
        writer.write_all(b"<li>")?;
        write_text(writer, item.field_group)?;
        write!(
            writer,
            ": {} retained / {} known {}; {} omitted</li>",
            item.retained_rendered_occurrences,
            item.known_rendered_occurrences,
            unit,
            item.omitted_rendered_occurrences
        )?;
    }
    writer.write_all(b"</ul></section>\n")
}

fn write_fact<W: Write>(
    index: usize,
    fact: &ResolvedEvidenceFact,
    writer: &mut W,
    redactions: CaseHtmlRedactionPolicy,
) -> io::Result<()> {
    write!(
        writer,
        "<article class=\"card\" id=\"fact-{index}\"><h3>Evidence fact {}</h3><dl><dt>Artifact</dt><dd>",
        index + 1
    )?;
    write_redacted_text(
        writer,
        &fact.artifact_path,
        redactions.artifact_paths,
        "artifact path",
    )?;
    writer.write_all(b"</dd><dt>Locator</dt><dd>")?;
    if redactions.evidence_identifiers {
        write_redaction_marker(writer, "evidence identifier")?;
    } else {
        let locator = serde_json::to_string(&fact.locator).map_err(io::Error::other)?;
        write_text(writer, &locator)?;
    }
    writer.write_all(b"</dd></dl>")?;
    if redactions.source_records {
        writer.write_all(
            b"<p class=\"notice\">Source record omitted by the selected redaction policy.</p>",
        )?;
    } else {
        writer.write_all(b"<details><summary>Source record (JSON)</summary><pre>")?;
        let evidence = if redactions.artifact_paths {
            let mut value = serde_json::to_value(&fact.fact).map_err(io::Error::other)?;
            replace_exact_named_fields(&mut value, "artifact_path", "[OMITTED: artifact path]");
            serde_json::to_string_pretty(&value).map_err(io::Error::other)?
        } else {
            serde_json::to_string_pretty(&fact.fact).map_err(io::Error::other)?
        };
        write_text(writer, &evidence)?;
        writer.write_all(b"</pre></details>")?;
    }
    writer.write_all(b"</article>")
}

fn has_redactions(policy: CaseHtmlRedactionPolicy) -> bool {
    policy.case_text
        || policy.artifact_paths
        || policy.source_records
        || policy.evidence_identifiers
}

fn write_redacted_text<W: Write>(
    writer: &mut W,
    value: &str,
    redacted: bool,
    field_group: &str,
) -> io::Result<()> {
    if redacted {
        write_redaction_marker(writer, field_group)
    } else {
        write_text(writer, value)
    }
}

fn write_redaction_marker<W: Write>(writer: &mut W, field_group: &str) -> io::Result<()> {
    writer.write_all(b"<span class=\"value\">[OMITTED: ")?;
    write_text(writer, field_group)?;
    writer.write_all(b"]</span>")
}

fn count_exact_named_fields(value: &serde_json::Value, field_name: &str) -> usize {
    match value {
        serde_json::Value::Object(object) => object.iter().fold(0usize, |count, (key, value)| {
            count + usize::from(key == field_name) + count_exact_named_fields(value, field_name)
        }),
        serde_json::Value::Array(values) => values
            .iter()
            .map(|value| count_exact_named_fields(value, field_name))
            .sum(),
        _ => 0,
    }
}

fn replace_exact_named_fields(value: &mut serde_json::Value, field_name: &str, replacement: &str) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                if key == field_name {
                    *value = serde_json::Value::String(replacement.to_owned());
                } else {
                    replace_exact_named_fields(value, field_name, replacement);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                replace_exact_named_fields(value, field_name, replacement);
            }
        }
        _ => {}
    }
}

fn status_name(status: crate::audit_session::SessionStatus) -> &'static str {
    match status {
        crate::audit_session::SessionStatus::Complete => "complete",
        crate::audit_session::SessionStatus::Partial => "partial",
    }
}

fn source_status_name(status: crate::audit_session::SourceStatus) -> &'static str {
    match status {
        crate::audit_session::SourceStatus::Complete => "complete",
        crate::audit_session::SourceStatus::Partial => "partial",
        crate::audit_session::SourceStatus::Unsupported => "unsupported",
        crate::audit_session::SourceStatus::NotChecked => "not_checked",
        crate::audit_session::SourceStatus::Unknown => "unknown",
        crate::audit_session::SourceStatus::NotApplicable => "not_applicable",
        crate::audit_session::SourceStatus::Unavailable => "unavailable",
        crate::audit_session::SourceStatus::AccessDenied => "access_denied",
        crate::audit_session::SourceStatus::Failed => "failed",
        crate::audit_session::SourceStatus::TimedOut => "timed_out",
        crate::audit_session::SourceStatus::OutputLimitExceeded => "output_limit_exceeded",
    }
}

trait EntryKindLabel {
    fn label(self) -> &'static str;
}

impl EntryKindLabel for crate::case::CaseEntryKind {
    fn label(self) -> &'static str {
        match self {
            crate::case::CaseEntryKind::Note => "note",
            crate::case::CaseEntryKind::Assertion => "assertion",
        }
    }
}

fn write_text<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    for character in value.chars() {
        match character {
            '&' => writer.write_all(b"&amp;")?,
            '<' => writer.write_all(b"&lt;")?,
            '>' => writer.write_all(b"&gt;")?,
            '"' => writer.write_all(b"&quot;")?,
            '\'' => writer.write_all(b"&#39;")?,
            character if character.is_control() || is_default_ignorable(character) => {
                write!(writer, "&amp;#x{:X};", character as u32)?;
            }
            character => {
                let mut bytes = [0; 4];
                writer.write_all(character.encode_utf8(&mut bytes).as_bytes())?;
            }
        }
    }
    Ok(())
}

fn is_default_ignorable(character: char) -> bool {
    matches!(
        character as u32,
        0x00AD | 0x034F | 0x061C | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x206F
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CaseHtmlRedactionPolicy, count_exact_named_fields, preview_case_html_redactions,
        replace_exact_named_fields, write_case_html, write_case_html_with_redactions,
    };
    use crate::audit_session::SessionStatus;
    use crate::case::{CaseEntryKind, CaseEvidenceLocator};
    use crate::case_evidence::{
        ResolvedCase, ResolvedCaseEntry, ResolvedEvidence, ResolvedEvidenceFact,
    };
    use crate::query::{RootQueryEntry, RootQueryEvidence};

    #[test]
    fn report_is_offline_escapes_hostile_text_and_links_entry_to_evidence() {
        let case = ResolvedCase {
            schema: "sideeffect.resolved_investigation_case",
            schema_version: 2,
            disclosure_note: "not producer authenticity",
            case_id: "case-test".to_owned(),
            title: "Review <script>alert(1)</script>".to_owned(),
            lifecycle: Some(crate::case::CaseLifecycle {
                status: crate::case::CaseStatus::InReview,
                revision: 3,
                previous_case_sha256: Some("a".repeat(64)),
            }),
            facts: vec![ResolvedEvidenceFact {
                locator: CaseEvidenceLocator::SelectedRootEntry {
                    session_id: "0123456789abcdef0123456789abcdef".to_owned(),
                    manifest_sha256: "a".repeat(64),
                    artifact_sha256: "b".repeat(64),
                    entry_ordinal: 0,
                },
                artifact_path: "root-snapshot.json".to_owned(),
                fact: ResolvedEvidence::SelectedRootEntry {
                    inventory_status: "complete".to_owned(),
                    entry: RootQueryEntry {
                        ordinal: 0,
                        name_hex: "3c7363726970743e".to_owned(),
                        display_name: "C:\\Users\\alice\\<script>".to_owned(),
                        object_type: "regular_file".to_owned(),
                        size_bytes: Some(1),
                        modified_at_unix_ms: None,
                        content_sha256: None,
                        content_hash_status: None,
                        evidence: RootQueryEvidence {
                            artifact_path: "root-snapshot.json".to_owned(),
                            source: "selected_root_directory_entry".to_owned(),
                            entry_ordinal: 0,
                        },
                    },
                },
            }],
            entries: vec![ResolvedCaseEntry {
                id: "A001".to_owned(),
                kind: CaseEntryKind::Assertion,
                authorship: "analyst_supplied_unverified".to_owned(),
                text: "Inspect <script>alert(1)</script> at C:\\Users\\alice; arg=--token secret; endpoint=203.0.113.9\u{202e}".to_owned(),
                severity: None,
                confidence: None,
                evidence_fact_indexes: vec![0],
            }],
            sessions: vec![crate::case_evidence::ResolvedSession {
                session_id: "0123456789abcdef0123456789abcdef".to_owned(),
                platform: "linux".to_owned(),
                manifest_schema_version: 1,
                manifest_sha256: "a".repeat(64),
                status: SessionStatus::Partial,
                sources: Vec::new(),
            }],
        };
        let mut html = Vec::new();
        write_case_html(&case, &mut html).unwrap();
        let html = String::from_utf8(html).unwrap();
        assert!(html.contains("default-src 'none'"));
        assert!(html.contains("script-src 'none'"));
        assert!(html.contains("<a href=\"#fact-0\">Fact 1</a>"));
        assert!(html.contains("id=\"fact-0\""));
        assert!(html.contains("<dt>Case status</dt><dd>in_review</dd>"));
        assert!(html.contains("<dt>Case revision</dt><dd>3</dd>"));
        assert!(!html.contains("Redaction receipt"));
        assert!(html.contains("Inspect &lt;script&gt;alert(1)&lt;/script&gt; at C:\\Users\\alice; arg=--token secret; endpoint=203.0.113.9&amp;#x202E;"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("<img"));
        assert!(!html.contains("https://"));

        let policy = CaseHtmlRedactionPolicy {
            case_text: true,
            artifact_paths: true,
            source_records: true,
            evidence_identifiers: true,
        };
        let preview = preview_case_html_redactions(&case, policy).unwrap();
        assert_eq!(
            preview
                .iter()
                .map(|item| (item.field_group, item.affected_field_occurrences))
                .collect::<Vec<_>>(),
            vec![
                ("case-text", 2),
                ("artifact-paths", 1),
                ("source-records", 1),
                ("evidence-identifiers", 5),
            ]
        );
        assert_eq!(
            preview
                .iter()
                .map(|item| (
                    item.field_group,
                    item.known_rendered_occurrences,
                    item.retained_rendered_occurrences,
                    item.omitted_rendered_occurrences,
                ))
                .collect::<Vec<_>>(),
            vec![
                ("case-text", 2, 0, 2),
                ("artifact-paths", 2, 0, 2),
                ("source-records", 1, 0, 1),
                ("evidence-identifiers", 5, 0, 5),
            ]
        );
        let preview_text = format!("{preview:?}");
        assert!(!preview_text.contains("alice"));
        assert!(!preview_text.contains("secret"));
        assert!(!preview_text.contains("203.0.113.9"));

        let mut redacted = Vec::new();
        write_case_html_with_redactions(&case, &mut redacted, policy).unwrap();
        let redacted = String::from_utf8(redacted).unwrap();
        assert!(redacted.contains("Redacted export"));
        assert!(redacted.contains("does not detect sensitive substrings"));
        let receipt_start = redacted
            .find("<h2 id=\"redaction-receipt-heading\">")
            .unwrap();
        let receipt_end = receipt_start + redacted[receipt_start..].find("</section>").unwrap();
        let receipt = &redacted[receipt_start..receipt_end];
        assert!(receipt.contains("Redaction receipt"));
        assert!(receipt.contains("no content or secret scan was performed"));
        assert!(receipt.contains("does not make this report safe to share"));
        for item in preview.iter().filter(|item| item.selected_for_redaction) {
            let unit = if item.field_group == "source-records" {
                "source-record block(s)"
            } else {
                "renderer field occurrence(s)"
            };
            let expected = format!(
                "{}: {} retained / {} known {}; {} omitted",
                item.field_group,
                item.retained_rendered_occurrences,
                item.known_rendered_occurrences,
                unit,
                item.omitted_rendered_occurrences
            );
            assert!(
                receipt.contains(&expected),
                "missing receipt count: {expected}"
            );
        }
        assert!(!receipt.contains("alice"));
        assert!(!receipt.contains("arg=--token secret"));
        assert!(!receipt.contains("203.0.113.9"));
        assert!(!receipt.contains("root-snapshot.json"));
        assert!(redacted.contains("[OMITTED: case text]"));
        assert!(redacted.contains("[OMITTED: artifact path]"));
        assert!(redacted.contains("[OMITTED: evidence identifier]"));
        assert!(redacted.contains("Source record omitted by the selected redaction policy."));
        assert!(!redacted.contains("alice"));
        assert!(!redacted.contains("arg=--token secret"));
        assert!(!redacted.contains("203.0.113.9"));
        assert!(!redacted.contains("root-snapshot.json"));

        let artifact_paths_only = CaseHtmlRedactionPolicy {
            artifact_paths: true,
            ..CaseHtmlRedactionPolicy::default()
        };
        let path_preview = preview_case_html_redactions(&case, artifact_paths_only).unwrap();
        let path_item = path_preview
            .iter()
            .find(|item| item.field_group == "artifact-paths")
            .unwrap();
        assert_eq!(path_item.affected_field_occurrences, 2);
        assert_eq!(path_item.known_rendered_occurrences, 2);
        assert_eq!(path_item.retained_rendered_occurrences, 0);
        assert_eq!(path_item.omitted_rendered_occurrences, 2);
        let mut path_only_html = Vec::new();
        write_case_html_with_redactions(&case, &mut path_only_html, artifact_paths_only).unwrap();
        let path_only_html = String::from_utf8(path_only_html).unwrap();
        let receipt_start = path_only_html
            .find("<h2 id=\"redaction-receipt-heading\">")
            .unwrap();
        let receipt_end =
            receipt_start + path_only_html[receipt_start..].find("</section>").unwrap();
        let receipt = &path_only_html[receipt_start..receipt_end];
        assert!(receipt.contains("artifact-paths:"));
        assert!(!receipt.contains("case-text:"));
        assert!(!receipt.contains("source-records:"));
        assert!(!receipt.contains("evidence-identifiers:"));
        assert!(!receipt.contains("alice"));
        assert!(!receipt.contains("arg=--token secret"));
        assert!(!receipt.contains("root-snapshot.json"));
        assert!(!path_only_html.contains("root-snapshot.json"));
        assert!(path_only_html.contains("[OMITTED: artifact path]"));
        assert!(path_only_html.contains("alice"));

        let source_records_only = CaseHtmlRedactionPolicy {
            source_records: true,
            ..CaseHtmlRedactionPolicy::default()
        };
        let source_preview = preview_case_html_redactions(&case, source_records_only).unwrap();
        let path_item = source_preview
            .iter()
            .find(|item| item.field_group == "artifact-paths")
            .unwrap();
        assert_eq!(path_item.affected_field_occurrences, 0);
        assert_eq!(path_item.known_rendered_occurrences, 2);
        assert_eq!(path_item.retained_rendered_occurrences, 1);
        assert_eq!(path_item.omitted_rendered_occurrences, 1);

        let mut exact_key_fixture = serde_json::json!({
            "artifact_path": "C:/private/artifact.json",
            "path": "C:/observed/event/path",
            "display_name": "path=C:/free-text/path",
            "nested": [{"artifact_path": "C:/private/nested.json", "path": "C:/nested/event/path"}]
        });
        assert_eq!(
            count_exact_named_fields(&exact_key_fixture, "artifact_path"),
            2
        );
        replace_exact_named_fields(
            &mut exact_key_fixture,
            "artifact_path",
            "[OMITTED: artifact path]",
        );
        assert_eq!(
            exact_key_fixture["artifact_path"],
            "[OMITTED: artifact path]"
        );
        assert_eq!(
            exact_key_fixture["nested"][0]["artifact_path"],
            "[OMITTED: artifact path]"
        );
        assert_eq!(exact_key_fixture["path"], "C:/observed/event/path");
        assert_eq!(
            exact_key_fixture["nested"][0]["path"],
            "C:/nested/event/path"
        );
        assert_eq!(exact_key_fixture["display_name"], "path=C:/free-text/path");
    }
}
