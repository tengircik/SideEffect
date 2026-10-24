use std::io::{self, Write};

use serde::Serialize;

use crate::model::{CaptureCompleteness, DeltaKind, EventCategory, TraceDiff};

pub const REDACTED_DIFF_SUMMARY_SCHEMA: &str = "sideeffect_redacted_diff_summary";
pub const REDACTED_DIFF_SUMMARY_SCHEMA_VERSION: u32 = 1;

const WARNING: &str = "This is an aggregate-only export, not a safe-to-share verdict. Category and change counts may still be sensitive. No secret detection is performed.";

/// A deliberately separate aggregate export with no event-level or source-derived strings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedactedDiffSummary {
    schema: &'static str,
    schema_version: u32,
    parse_status: &'static str,
    capture_completeness: CaptureCompleteness,
    disclosure: RedactionDisclosure,
    changes_by_category: [CategoryChangeCounts; 4],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedactionDisclosure {
    mode: &'static str,
    omitted_fields: [&'static str; 7],
    warning: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CategoryChangeCounts {
    category: EventCategory,
    added_groups: u64,
    changed_groups: u64,
    removed_groups: u64,
}

/// Build the aggregate export without cloning or retaining source-derived strings.
pub fn summarize_diff(diff: &TraceDiff<'_>) -> RedactedDiffSummary {
    let mut counts = [
        CategoryChangeCounts::new(EventCategory::File),
        CategoryChangeCounts::new(EventCategory::Network),
        CategoryChangeCounts::new(EventCategory::Other),
        CategoryChangeCounts::new(EventCategory::Process),
    ];

    for change in &diff.changes {
        let category = match change.category {
            EventCategory::File => 0,
            EventCategory::Network => 1,
            EventCategory::Other => 2,
            EventCategory::Process => 3,
        };
        match change.kind {
            DeltaKind::Added => counts[category].added_groups += 1,
            DeltaKind::Changed => counts[category].changed_groups += 1,
            DeltaKind::Removed => counts[category].removed_groups += 1,
        }
    }

    RedactedDiffSummary {
        schema: REDACTED_DIFF_SUMMARY_SCHEMA,
        schema_version: REDACTED_DIFF_SUMMARY_SCHEMA_VERSION,
        parse_status: "complete",
        capture_completeness: diff.capture_completeness,
        disclosure: RedactionDisclosure {
            mode: "category_group_counts_only",
            omitted_fields: [
                "syscall_names",
                "raw_arguments",
                "raw_results",
                "lexical_path_hints",
                "source_fingerprints",
                "source_evidence_references",
                "local_input_paths",
            ],
            warning: WARNING,
        },
        changes_by_category: counts,
    }
}

impl CategoryChangeCounts {
    const fn new(category: EventCategory) -> Self {
        Self {
            category,
            added_groups: 0,
            changed_groups: 0,
            removed_groups: 0,
        }
    }
}

/// Write an offline HTML rendering of the aggregate summary. Dynamic trace text is not retained
/// by the summary type; all rendered data is fixed enums, counts, and static disclosure text.
pub fn write_html_summary<W: Write>(
    summary: &RedactedDiffSummary,
    writer: &mut W,
) -> io::Result<()> {
    writer.write_all(b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")?;
    writer.write_all(b"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; frame-src 'none'; media-src 'none'; script-src 'none'\">\n<title>SideEffect aggregate diff summary</title>\n<style>body{max-width:60rem;margin:2rem auto;padding:0 1rem;font:16px/1.5 system-ui,sans-serif}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #888;padding:.5rem;text-align:left}.notice{border-left:.25rem solid #b87900;padding:.5rem 1rem}.skip-link{position:absolute;left:1rem;top:0;z-index:1;transform:translateY(-150%);background:Canvas;color:CanvasText;padding:.5rem 1rem;border:2px solid currentColor}.skip-link:focus{transform:translateY(1rem)}</style>\n</head>\n<body>\n<a class=\"skip-link\" href=\"#report-content\">Skip to report content</a>\n<main id=\"report-content\" tabindex=\"-1\">\n<h1>SideEffect aggregate diff summary</h1>\n<p class=\"notice\">")?;
    writer.write_all(summary.disclosure.warning.as_bytes())?;
    writer.write_all(b"</p>\n<p>Schema: sideeffect_redacted_diff_summary v1. Parse status: complete. Capture completeness: unknown; parsing cannot establish that every interaction was observed.</p>\n<p>This separate summary contains category-level counts only. It does not preserve event-level evidence.</p>\n<table><caption>Observed change groups by category</caption><thead><tr><th>Category</th><th>Added groups</th><th>Changed groups</th><th>Removed groups</th></tr></thead><tbody>\n")?;
    for row in &summary.changes_by_category {
        writeln!(
            writer,
            "<tr><th>{}</th><td>{}</td><td>{}</td><td>{}</td></tr>",
            category_name(row.category),
            row.added_groups,
            row.changed_groups,
            row.removed_groups
        )?;
    }
    writer.write_all(b"</tbody></table>\n<p>Omitted from this export: syscall names, raw arguments and results, lexical path hints, source fingerprints, source evidence references, and local input paths. The command performs no upload.</p>\n</main>\n</body>\n</html>\n")
}

fn category_name(category: EventCategory) -> &'static str {
    match category {
        EventCategory::File => "File",
        EventCategory::Network => "Network",
        EventCategory::Other => "Other",
        EventCategory::Process => "Process",
    }
}

#[cfg(test)]
mod tests {
    use super::{summarize_diff, write_html_summary};
    use crate::model::{
        CaptureCompleteness, DeltaKind, EventCategory, EvidenceReference, MatchingPolicy,
        ObservedDelta, TRACE_DIFF_SCHEMA_VERSION, TraceDiff, TraceRecordKind,
    };
    use crate::trace::{LexicalPathBasis, LexicalPathHint};

    fn summary_source_fixture<'a>(hint: &'a LexicalPathHint) -> TraceDiff<'a> {
        TraceDiff {
            schema_version: TRACE_DIFF_SCHEMA_VERSION,
            left_source_format: "strace_text",
            right_source_format: "strace_text",
            left_source_sha256: "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            right_source_sha256: "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
            capture_completeness: CaptureCompleteness::Unknown,
            matching_policy: MatchingPolicy {
                ignored_prefix_fields: vec!["process_id".to_owned(), "timestamp".to_owned()],
                multiplicity: "multiset".to_owned(),
                exact_fields: vec![
                    "record_kind".to_owned(),
                    "category".to_owned(),
                    "syscall".to_owned(),
                    "raw_arguments".to_owned(),
                    "raw_result".to_owned(),
                ],
                display_only_fields: vec!["lexical_path_hint".to_owned()],
            },
            left_excluded_control_records: 0,
            right_excluded_control_records: 0,
            changes: vec![ObservedDelta {
                kind: DeltaKind::Added,
                category: EventCategory::Network,
                record_kind: TraceRecordKind::Syscall,
                syscall: "connect",
                raw_arguments: "sentinel-secret-arg /private/sentinel/path",
                before_lexical_path_hint: None,
                after_lexical_path_hint: Some(hint),
                before_result: None,
                after_result: Some("sentinel-result-token"),
                before: vec![],
                after: vec![EvidenceReference {
                    line_number: 17,
                    byte_offset: 1024,
                    byte_length: 80,
                }],
            }],
        }
    }

    #[test]
    fn summary_schema_omits_event_strings_fingerprints_and_source_references() {
        let hint = LexicalPathHint {
            path: "/private/sentinel/path".to_owned(),
            basis: LexicalPathBasis::AbsoluteArgument,
        };
        let source = summary_source_fixture(&hint);
        let summary = summarize_diff(&source);
        let json = serde_json::to_string(&summary).unwrap();
        let sentinel_hash = "a1".repeat(32);

        assert!(json.contains("sideeffect_redacted_diff_summary"));
        assert!(json.contains("category_group_counts_only"));
        assert!(json.contains("may still be sensitive"));
        for sentinel in [
            "sentinel-secret-arg",
            "/private/sentinel/path",
            "sentinel-result-token",
            sentinel_hash.as_str(),
            "byte_offset",
            "line_number",
            "connect",
        ] {
            assert!(!json.contains(sentinel), "leaked {sentinel}");
        }
    }

    #[test]
    fn html_summary_is_static_and_discloses_remaining_sensitivity() {
        let hint = LexicalPathHint {
            path: "/private/sentinel/path".to_owned(),
            basis: LexicalPathBasis::AbsoluteArgument,
        };
        let summary = summarize_diff(&summary_source_fixture(&hint));
        let mut output = Vec::new();
        write_html_summary(&summary, &mut output).unwrap();
        let html = String::from_utf8(output).unwrap();
        assert!(html.contains(
            r##"<a class="skip-link" href="#report-content">Skip to report content</a>"##
        ));
        assert!(html.contains(r#"<main id="report-content" tabindex="-1">"#));
        assert!(html.contains("transform:translateY(-150%)"));
        assert!(html.contains(".skip-link:focus{transform:translateY(1rem)}"));
        assert!(html.contains("<caption>Observed change groups by category</caption>"));
        assert!(html.contains("</main>\n</body>"));
        assert_eq!(html.matches("href=").count(), 1);
        assert!(!html.contains("href=\"http"));
        assert!(html.contains("Content-Security-Policy"));
        assert!(html.contains("default-src 'none'"));
        assert!(html.contains("script-src 'none'"));
        assert!(html.contains("not a safe-to-share verdict"));
        assert!(html.contains("Category</th><th>Added groups"));
        assert!(html.contains("Schema: sideeffect_redacted_diff_summary v1"));
        assert!(!html.contains("sentinel-secret-arg"));
        assert!(!html.contains("/private/sentinel/path"));
        assert!(!html.contains("sentinel-result-token"));
    }
}
