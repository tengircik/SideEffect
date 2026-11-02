use std::io::{self, Write};

use crate::case_evidence::{ResolvedCase, ResolvedEvidenceFact};

const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; frame-src 'none'; media-src 'none'; script-src 'none'";

/// Render resolved case evidence as a static offline report.
///
/// Case text and source evidence are untrusted and may be sensitive. Dynamic strings are emitted
/// only as escaped text; the caller must enforce a rendered-output byte limit.
pub fn write_case_html<W: Write>(case: &ResolvedCase, writer: &mut W) -> io::Result<()> {
    writer.write_all(b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta http-equiv=\"Content-Security-Policy\" content=\"")?;
    writer.write_all(CSP.as_bytes())?;
    writer.write_all(b"\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>SideEffect investigation case</title>\n<style>:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{max-width:76rem;margin:2rem auto;padding:0 1rem}h1,h2,h3{line-height:1.25}.notice{border-left:.25rem solid #b87900;padding:.5rem 1rem}.card{border:1px solid #8886;border-radius:.5rem;padding:1rem;margin:1rem 0}dl{display:grid;grid-template-columns:minmax(10rem,16rem) minmax(0,1fr);gap:.35rem 1rem}dt{font-weight:600}.value{unicode-bidi:isolate;white-space:pre-wrap;overflow-wrap:anywhere}pre{overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid #8886;border-radius:.35rem;padding:1rem}.skip-link{position:absolute;left:1rem;top:0;z-index:1;transform:translateY(-150%);background:Canvas;color:CanvasText;padding:.5rem 1rem;border:2px solid currentColor}.skip-link:focus{transform:translateY(1rem)}@media(max-width:40rem){dl{grid-template-columns:1fr;gap:0}dt{margin-top:.5rem}}</style>\n</head>\n<body>\n<a class=\"skip-link\" href=\"#report-content\">Skip to report content</a>\n<main id=\"report-content\" tabindex=\"-1\">\n<header><h1>Investigation case: ")?;
    write_text(writer, &case.title)?;
    writer.write_all(b"</h1><p class=\"notice\">This report contains local audit evidence and analyst-supplied text. It may expose sensitive paths, arguments, process data, or payloads. Review before sharing. It does not authenticate session producers or verify analyst assertions.</p></header>\n<section class=\"card\"><h2>Case context</h2><dl><dt>Case ID</dt><dd>")?;
    write_text(writer, &case.case_id)?;
    writeln!(
        writer,
        "</dd><dt>Schema</dt><dd>{} v{}</dd><dt>Sessions</dt><dd>{}</dd><dt>Entries</dt><dd>{}</dd><dt>Resolved evidence facts</dt><dd>{}</dd></dl></section>",
        case.schema,
        case.schema_version,
        case.sessions.len(),
        case.entries.len(),
        case.facts.len()
    )?;

    writer.write_all(b"<section><h2>Sessions</h2>")?;
    for session in &case.sessions {
        writer.write_all(b"<article class=\"card\"><h3>Session ")?;
        write_text(writer, &session.session_id)?;
        writer.write_all(b"</h3><dl><dt>Platform</dt><dd>")?;
        write_text(writer, &session.platform)?;
        write!(
            writer,
            "</dd><dt>Manifest schema version</dt><dd>{}</dd><dt>Manifest SHA-256</dt><dd>",
            session.manifest_schema_version
        )?;
        write_text(writer, &session.manifest_sha256)?;
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
        write_text(writer, &entry.id)?;
        writer.write_all(b"</h3><dl><dt>Kind</dt><dd>")?;
        write_text(writer, entry.kind.label())?;
        writer.write_all(b"</dd><dt>Authorship</dt><dd>")?;
        write_text(writer, &entry.authorship)?;
        writer.write_all(b"</dd><dt>Statement</dt><dd><span class=\"value\">")?;
        write_text(writer, &entry.text)?;
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
        write_fact(index, fact, writer)?;
    }
    writer.write_all(b"</section>\n</main>\n</body>\n</html>\n")
}

fn write_fact<W: Write>(
    index: usize,
    fact: &ResolvedEvidenceFact,
    writer: &mut W,
) -> io::Result<()> {
    write!(
        writer,
        "<article class=\"card\" id=\"fact-{index}\"><h3>Evidence fact {}</h3><dl><dt>Artifact</dt><dd>",
        index + 1
    )?;
    write_text(writer, &fact.artifact_path)?;
    writer.write_all(b"</dd><dt>Locator</dt><dd>")?;
    let locator = serde_json::to_string(&fact.locator).map_err(io::Error::other)?;
    write_text(writer, &locator)?;
    writer.write_all(b"</dd></dl><details><summary>Source record (JSON)</summary><pre>")?;
    let evidence = serde_json::to_string_pretty(&fact.fact).map_err(io::Error::other)?;
    write_text(writer, &evidence)?;
    writer.write_all(b"</pre></details></article>")
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
    use super::write_case_html;
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
            schema_version: 1,
            disclosure_note: "not producer authenticity",
            case_id: "case-test".to_owned(),
            title: "Review <script>alert(1)</script>".to_owned(),
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
                        display_name: "<script>".to_owned(),
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
                text: "Inspect <script>alert(1)</script>\u{202e}".to_owned(),
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
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&amp;#x202E;"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("<img"));
        assert!(!html.contains("https://"));
    }
}
