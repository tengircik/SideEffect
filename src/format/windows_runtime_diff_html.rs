use std::io::{self, Write};

use crate::windows_runtime_diff::{ComparisonStatus, WindowsRuntimeDiffSummary};

const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; frame-src 'none'; media-src 'none'; script-src 'none'";

/// Write a static offline aggregate comparison report. Dynamic values are inert
/// escaped text; the caller enforces the report byte limit and publishes safely.
pub fn write_windows_runtime_diff_html<W: Write>(
    summary: &WindowsRuntimeDiffSummary,
    writer: &mut W,
) -> io::Result<()> {
    writer.write_all(b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta http-equiv=\"Content-Security-Policy\" content=\"")?;
    writer.write_all(CSP.as_bytes())?;
    writer.write_all(b"\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>SideEffect Windows runtime comparison</title>\n<style>:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{max-width:72rem;margin:2rem auto;padding:0 1rem}h1,h2{line-height:1.2}.notice,.summary,.category{border:1px solid #8886;border-radius:.5rem;padding:1rem;margin:1rem 0}.notice{border-left:.25rem solid #b87900}.skip-link{position:absolute;left:1rem;top:0;z-index:1;transform:translateY(-150%);background:Canvas;color:CanvasText;padding:.5rem 1rem;border:2px solid currentColor}.skip-link:focus{transform:translateY(1rem)}.value{unicode-bidi:isolate;white-space:pre-wrap;overflow-wrap:anywhere}dl{display:grid;grid-template-columns:minmax(12rem,18rem) minmax(0,1fr);gap:.35rem 1rem}dt{font-weight:600}.ordinals{overflow-wrap:anywhere}@media(max-width:40rem){dl{grid-template-columns:1fr;gap:0}dt{margin-top:.5rem}}</style>\n</head>\n<body>\n<a class=\"skip-link\" href=\"#report-content\">Skip to report content</a>\n<main id=\"report-content\" tabindex=\"-1\">\n<header><h1>SideEffect Windows runtime aggregate comparison</h1><p class=\"notice\">This report compares category counts from two separately captured Windows ETW documents. Individual records are not paired. Capture data and fingerprints may be sensitive; review before sharing.</p></header>\n<section class=\"summary\"><h2>Comparison context</h2><dl>\n<dt>Summary schema</dt><dd>")?;
    write_value(writer, summary.schema)?;
    write!(
        writer,
        " v{}</dd>\n<dt>Algorithm</dt><dd>",
        summary.schema_version
    )?;
    write_value(writer, summary.algorithm.id)?;
    write!(
        writer,
        " v{}</dd>\n<dt>Comparison status</dt><dd>{}</dd>\n<dt>Capture completeness</dt><dd>Unknown</dd>\n<dt>Before capture SHA-256</dt><dd>",
        summary.algorithm.version,
        comparison_status(summary.comparison_status)
    )?;
    write_value(writer, &summary.before.document_sha256)?;
    writer.write_all(b"</dd>\n<dt>Before producer status</dt><dd>")?;
    write_value(
        writer,
        collection_status(summary.before.producer_collection_status),
    )?;
    writer.write_all(
        b" (not independently authenticated)</dd>\n<dt>Before retained records</dt><dd>",
    )?;
    write!(writer, "{}", summary.before.observed_event_count)?;
    writer.write_all(b"</dd>\n<dt>After capture SHA-256</dt><dd>")?;
    write_value(writer, &summary.after.document_sha256)?;
    writer.write_all(b"</dd>\n<dt>After producer status</dt><dd>")?;
    write_value(
        writer,
        collection_status(summary.after.producer_collection_status),
    )?;
    writer.write_all(
        b" (not independently authenticated)</dd>\n<dt>After retained records</dt><dd>",
    )?;
    write!(
        writer,
        "{}</dd>\n</dl></section>",
        summary.after.observed_event_count
    )?;
    writer.write_all(b"\n<p>Observed category counts do not establish event absence, operation success, causation, or target attribution. Event ordinals refer to positions in one capture document; they are not byte offsets or matched event identities.</p>\n<section><h2>Category deltas (")?;
    write!(writer, "{}", summary.categories.len())?;
    writer.write_all(b")</h2>")?;
    if summary.categories.is_empty() {
        writer.write_all(b"<p>No supported categories were observed in either capture.</p>")?;
    }
    for category in &summary.categories {
        writer.write_all(b"<article class=\"category\"><h3>")?;
        write_value(writer, category.category)?;
        writer.write_all(b"</h3><dl><dt>Before count</dt><dd>")?;
        write!(writer, "{}", category.before_count)?;
        writer.write_all(b"</dd><dt>After count</dt><dd>")?;
        write!(writer, "{}", category.after_count)?;
        writer.write_all(b"</dd><dt>Observed count delta</dt><dd>")?;
        write!(
            writer,
            "{}</dd><dt>Before event ordinals</dt><dd class=\"ordinals\">",
            category.observed_count_delta
        )?;
        write_ordinals(writer, &category.before_event_ordinals)?;
        writer.write_all(b"</dd><dt>After event ordinals</dt><dd class=\"ordinals\">")?;
        write_ordinals(writer, &category.after_event_ordinals)?;
        writer.write_all(b"</dd></dl></article>\n")?;
    }
    writer.write_all(b"</section>\n<section><h2>Diagnostics (")?;
    write!(writer, "{}", summary.diagnostics.len())?;
    writer.write_all(b")</h2><ul>")?;
    for diagnostic in &summary.diagnostics {
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

fn write_ordinals<W: Write>(writer: &mut W, values: &[u64]) -> io::Result<()> {
    if values.is_empty() {
        return writer.write_all(b"none");
    }
    for (index, ordinal) in values.iter().enumerate() {
        if index > 0 {
            writer.write_all(b", ")?;
        }
        write!(writer, "{ordinal}")?;
    }
    Ok(())
}

fn comparison_status(value: ComparisonStatus) -> &'static str {
    match value {
        ComparisonStatus::Complete => "complete",
        ComparisonStatus::Partial => "partial",
    }
}

fn collection_status(value: crate::windows_runtime::CollectionStatus) -> &'static str {
    match value {
        crate::windows_runtime::CollectionStatus::Complete => "complete",
        crate::windows_runtime::CollectionStatus::Partial => "partial",
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_runtime_diff::{CaptureSide, CategoryCountDelta, ComparisonAlgorithm};

    fn summary(before_hash: &str, after_hash: &str) -> WindowsRuntimeDiffSummary {
        WindowsRuntimeDiffSummary {
            schema: "sideeffect.windows_runtime_diff_summary",
            schema_version: 1,
            algorithm: ComparisonAlgorithm {
                id: "windows_etw_observed_event_category_counts",
                version: 1,
                basis: "fixed_category_record_counts_without_individual_event_pairing",
            },
            comparison_status: ComparisonStatus::Partial,
            capture_completeness: "unknown",
            before: CaptureSide {
                document_sha256: before_hash.to_owned(),
                producer_collection_status: crate::windows_runtime::CollectionStatus::Complete,
                capture_completeness: "unknown",
                observed_event_count: 1,
            },
            after: CaptureSide {
                document_sha256: after_hash.to_owned(),
                producer_collection_status: crate::windows_runtime::CollectionStatus::Partial,
                capture_completeness: "unknown",
                observed_event_count: 0,
            },
            categories: vec![CategoryCountDelta {
                category: "process.start",
                before_count: 1,
                after_count: 0,
                observed_count_delta: -1,
                before_event_ordinals: vec![1],
                after_event_ordinals: vec![],
            }],
            diagnostics: vec!["one_or_both_captures_report_partial_collection"],
            limitations: vec![],
        }
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
    fn emits_strict_csp_escapes_untrusted_text_and_keeps_ordinals() {
        let mut html = Vec::new();
        write_windows_runtime_diff_html(
            &summary("<script>alert(1)</script>", "b\u{202e}b"),
            &mut html,
        )
        .unwrap();
        let html = String::from_utf8(html).unwrap();
        assert!(html.contains("default-src 'none'"));
        assert!(html.contains("connect-src 'none'"));
        assert!(html.contains("script-src 'none'"));
        assert!(!html.contains("<script"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&amp;#x202E;"));
        assert!(html.contains("Before count"));
        assert!(html.contains(">1</dd>"));
        assert!(html.contains(">none</dd>"));
        assert!(html.contains("Individual records are not paired"));
        assert!(
            html.contains("event absence, operation success, causation, or target attribution")
        );
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("https://"));
    }

    #[test]
    fn output_writer_cap_failure_propagates() {
        let mut writer = Counter { bytes: 0, cap: 64 };
        assert_eq!(
            write_windows_runtime_diff_html(&summary("a", "b"), &mut writer)
                .unwrap_err()
                .to_string(),
            "output cap exceeded"
        );
        assert_eq!(writer.bytes, writer.cap);
    }
}
