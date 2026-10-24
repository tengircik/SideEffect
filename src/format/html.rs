use std::io::{self, Write};

use crate::model::{
    CaptureCompleteness, DeltaKind, EventCategory, EvidenceReference, ObservedDelta, TraceDiff,
    TraceRecordKind,
};
use crate::trace::{LexicalPathBasis, LexicalPathHint};

const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; frame-src 'none'; media-src 'none'; script-src 'none'";

/// Stream a self-contained HTML rendering of a paired trace comparison.
///
/// Trace-derived strings are emitted only in text nodes. HTML metacharacters are escaped, and
/// controls and known default-ignorable formatting characters are rendered as visible numeric
/// entity spellings (for example, `&amp;#x202E;`, displayed literally as `&#x202E;`). The caller
/// is responsible for enforcing a rendered-output byte budget.
pub fn write_html_diff<W: Write>(diff: &TraceDiff<'_>, writer: &mut W) -> io::Result<()> {
    writer.write_all(b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")?;
    writer.write_all(b"<meta http-equiv=\"Content-Security-Policy\" content=\"")?;
    writer.write_all(CSP.as_bytes())?;
    writer.write_all(
        b"\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>SideEffect trace comparison</title>\n<style>\n:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{max-width:72rem;margin:2rem auto;padding:0 1rem}h1,h2,h3{line-height:1.2}.context,.delta{border:1px solid #8886;border-radius:.5rem;padding:1rem;margin:1rem 0}dl{display:grid;grid-template-columns:minmax(10rem,15rem) minmax(0,1fr);gap:.35rem 1rem}dt{font-weight:600}.value{unicode-bidi:isolate;white-space:pre-wrap;overflow-wrap:anywhere}.evidence{margin:.25rem 0 1rem 1.25rem;padding:0}.evidence li{font-family:ui-monospace,monospace}code{font-family:ui-monospace,monospace}.notice{border-left:.25rem solid #b87900;padding:.5rem 1rem} @media(max-width:40rem){dl{grid-template-columns:1fr;gap:0}dt{margin-top:.5rem}}\n.skip-link{position:absolute;left:1rem;top:0;z-index:1;transform:translateY(-150%);background:Canvas;color:CanvasText;padding:.5rem 1rem;border:2px solid currentColor}.skip-link:focus{transform:translateY(1rem)}\n</style>\n</head>\n<body>\n<a class=\"skip-link\" href=\"#report-content\">Skip to report content</a>\n<main id=\"report-content\" tabindex=\"-1\">\n<header><h1>SideEffect trace comparison</h1><p class=\"notice\">Trace values may contain sensitive data. Review this report before sharing it. Parsing does not establish complete capture coverage.</p></header>\n<p>Categories are syscall-name buckets. A recorded attempt or comparison does not establish a completed effect or causation.</p>\n<section class=\"context\"><h2>Comparison context</h2><dl>\n<dt>Schema version</dt><dd>",
    )?;
    write!(writer, "{}", diff.schema_version)?;
    writer.write_all(b"</dd>\n<dt>Capture completeness</dt><dd>")?;
    match diff.capture_completeness {
        CaptureCompleteness::Unknown => {
            writer.write_all(b"unknown (not established by parsing)")?
        }
    }
    writer.write_all(b"</dd>\n<dt>Before (CLI argument 1) source format</dt><dd>")?;
    write_value(writer, diff.left_source_format)?;
    writer.write_all(b"</dd>\n<dt>After (CLI argument 2) source format</dt><dd>")?;
    write_value(writer, diff.right_source_format)?;
    writer.write_all(b"</dd>\n<dt>Before (CLI argument 1) source SHA-256</dt><dd>")?;
    write_value(writer, diff.left_source_sha256)?;
    writer.write_all(b"</dd>\n<dt>After (CLI argument 2) source SHA-256</dt><dd>")?;
    write_value(writer, diff.right_source_sha256)?;
    writer.write_all(b"</dd>\n<dt>Fingerprint note</dt><dd>Identity metadata only; not authentication, redaction, or capture completeness.</dd>\n<dt>Matching multiplicity</dt><dd>")?;
    write_value(writer, &diff.matching_policy.multiplicity)?;
    writer.write_all(b"</dd>\n<dt>Ignored prefix fields</dt><dd>")?;
    if diff.matching_policy.ignored_prefix_fields.is_empty() {
        writer.write_all(b"(none)")?;
    } else {
        for (index, field) in diff
            .matching_policy
            .ignored_prefix_fields
            .iter()
            .enumerate()
        {
            if index != 0 {
                writer.write_all(b", ")?;
            }
            write_value(writer, field)?;
        }
    }
    writer.write_all(b"</dd>\n<dt>Exact matching fields</dt><dd>")?;
    if diff.matching_policy.exact_fields.is_empty() {
        writer.write_all(b"(none)")?;
    } else {
        for (index, field) in diff.matching_policy.exact_fields.iter().enumerate() {
            if index != 0 {
                writer.write_all(b", ")?;
            }
            write_value(writer, field)?;
        }
    }
    writer.write_all(b"</dd>\n<dt>Display-only fields</dt><dd>")?;
    if diff.matching_policy.display_only_fields.is_empty() {
        writer.write_all(b"(none)")?;
    } else {
        for (index, field) in diff.matching_policy.display_only_fields.iter().enumerate() {
            if index != 0 {
                writer.write_all(b", ")?;
            }
            write_value(writer, field)?;
        }
    }
    writer.write_all(b"</dd>\n<dt>Excluded control records</dt><dd>Baseline: ")?;
    write!(writer, "{}", diff.left_excluded_control_records)?;
    writer.write_all(b"; candidate: ")?;
    write!(writer, "{}", diff.right_excluded_control_records)?;
    writer.write_all(b"</dd>\n</dl></section>\n<p>To verify a cited row locally, run <code>sideeffect evidence TRACE SHA256 LINE BYTE_OFFSET BYTE_LENGTH</code>. For Before evidence, substitute the first input path and Before source SHA-256 shown above; for After, use the second input and After source SHA-256. Use that reference's line, byte, and length values. Input paths are omitted from this report.</p>\n<section><h2>Observed differences (")?;
    write!(writer, "{}", diff.changes.len())?;
    writer.write_all(b")</h2>")?;

    if diff.changes.is_empty() {
        writer.write_all(b"<p>No observed syscall-row differences.</p>")?;
    } else {
        writer.write_all(b"<ol>\n")?;
        for change in &diff.changes {
            write_delta(writer, change)?;
        }
        writer.write_all(b"</ol>\n")?;
    }
    writer.write_all(b"</section>\n</main>\n</body>\n</html>\n")
}

fn write_delta<W: Write>(writer: &mut W, change: &ObservedDelta<'_>) -> io::Result<()> {
    writer.write_all(b"<li class=\"delta\"><h3>")?;
    writer.write_all(delta_name(change.kind).as_bytes())?;
    writer.write_all(b"</h3><dl>\n<dt>Category</dt><dd>")?;
    writer.write_all(category_name(change.category).as_bytes())?;
    writer.write_all(b"</dd>\n<dt>Record kind</dt><dd>")?;
    writer.write_all(record_kind_name(change.record_kind).as_bytes())?;
    writer.write_all(b"</dd>\n<dt>Syscall</dt><dd>")?;
    write_value(writer, change.syscall)?;
    writer.write_all(b"</dd>\n<dt>Arguments</dt><dd>")?;
    write_value(writer, change.raw_arguments)?;
    writer.write_all(
        b"</dd>\n<dt>Before lexical path hint (display only; not used for matching)</dt><dd>",
    )?;
    write_optional_path_hint(writer, change.before_lexical_path_hint)?;
    writer.write_all(
        b"</dd>\n<dt>After lexical path hint (display only; not used for matching)</dt><dd>",
    )?;
    write_optional_path_hint(writer, change.after_lexical_path_hint)?;
    writer.write_all(b"</dd>\n<dt>Before result (CLI argument 1)</dt><dd>")?;
    write_optional_value(writer, change.before_result)?;
    writer.write_all(b"</dd>\n<dt>After result (CLI argument 2)</dt><dd>")?;
    write_optional_value(writer, change.after_result)?;
    writer.write_all(b"</dd>\n</dl>\n")?;
    write_evidence(writer, "Before evidence (CLI argument 1)", &change.before)?;
    write_evidence(writer, "After evidence (CLI argument 2)", &change.after)?;
    writer.write_all(b"</li>\n")
}

fn write_optional_path_hint<W: Write>(
    writer: &mut W,
    hint: Option<&LexicalPathHint>,
) -> io::Result<()> {
    match hint {
        Some(hint) => {
            write_value(writer, &hint.path)?;
            writer.write_all(b" (basis=")?;
            writer.write_all(path_basis_name(hint.basis).as_bytes())?;
            writer.write_all(b")")
        }
        None => writer.write_all(b"(not available)"),
    }
}

fn path_basis_name(basis: LexicalPathBasis) -> &'static str {
    match basis {
        LexicalPathBasis::AbsoluteArgument => "absolute_argument",
        LexicalPathBasis::AtFdcwdAnnotation => "at_fdcwd_annotation",
        LexicalPathBasis::DirectoryFdAnnotation => "directory_fd_annotation",
    }
}

fn write_evidence<W: Write>(
    writer: &mut W,
    label: &str,
    evidence: &[EvidenceReference],
) -> io::Result<()> {
    writer.write_all(b"<h4>")?;
    writer.write_all(label.as_bytes())?;
    writer.write_all(b"</h4>")?;
    if evidence.is_empty() {
        return writer.write_all(b"<p>(none)</p>\n");
    }
    writer.write_all(b"<ul class=\"evidence\">\n")?;
    for reference in evidence {
        writer.write_all(b"<li>line=")?;
        write!(writer, "{}", reference.line_number)?;
        writer.write_all(b" byte=")?;
        write!(writer, "{}", reference.byte_offset)?;
        writer.write_all(b" length=")?;
        write!(writer, "{}", reference.byte_length)?;
        writer.write_all(b"</li>\n")?;
    }
    writer.write_all(b"</ul>\n")
}

fn write_optional_value<W: Write>(writer: &mut W, value: Option<&str>) -> io::Result<()> {
    match value {
        Some(value) => write_value(writer, value),
        None => writer.write_all(b"(not present)"),
    }
}

fn write_value<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    writer.write_all(b"<span class=\"value\">")?;
    for character in value.chars() {
        if character.is_control() || is_default_ignorable(character) {
            // Escape the ampersand so the browser displays a literal numeric-reference spelling
            // instead of interpreting it as a bidi/control character.
            write!(writer, "&amp;#x{:X};", character as u32)?;
            continue;
        }
        match character {
            '&' => writer.write_all(b"&amp;")?,
            '<' => writer.write_all(b"&lt;")?,
            '>' => writer.write_all(b"&gt;")?,
            '"' => writer.write_all(b"&quot;")?,
            '\'' => writer.write_all(b"&#39;")?,
            _ => {
                let mut buffer = [0; 4];
                writer.write_all(character.encode_utf8(&mut buffer).as_bytes())?;
            }
        }
    }
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

fn delta_name(kind: DeltaKind) -> &'static str {
    match kind {
        DeltaKind::Added => "Added",
        DeltaKind::Changed => "Changed",
        DeltaKind::Removed => "Removed",
    }
}

fn category_name(category: EventCategory) -> &'static str {
    match category {
        EventCategory::File => "file",
        EventCategory::Network => "network",
        EventCategory::Other => "other",
        EventCategory::Process => "process",
    }
}

fn record_kind_name(kind: TraceRecordKind) -> &'static str {
    match kind {
        TraceRecordKind::Syscall => "syscall",
        TraceRecordKind::UnfinishedSyscall => "unfinished_syscall",
        TraceRecordKind::ResumedSyscall => "resumed_syscall",
        TraceRecordKind::Control => "control",
        TraceRecordKind::Unparsed => "unparsed",
    }
}

#[cfg(test)]
mod tests {
    use super::write_html_diff;
    use crate::model::{
        CaptureCompleteness, DeltaKind, EventCategory, EvidenceReference, MatchingPolicy,
        ObservedDelta, TRACE_DIFF_SCHEMA_VERSION, TraceDiff, TraceRecordKind,
    };
    use crate::trace::{LexicalPathBasis, LexicalPathHint};
    use std::io::{self, Write};

    fn make_diff(args: &str) -> TraceDiff<'_> {
        TraceDiff {
            schema_version: TRACE_DIFF_SCHEMA_VERSION,
            left_source_format: "strace_text_v1",
            right_source_format: "strace_text_v1",
            left_source_sha256: "1111111111111111111111111111111111111111111111111111111111111111",
            right_source_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
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
            left_excluded_control_records: 1,
            right_excluded_control_records: 2,
            changes: vec![ObservedDelta {
                kind: DeltaKind::Changed,
                category: EventCategory::File,
                record_kind: TraceRecordKind::Syscall,
                syscall: "openat",
                raw_arguments: args,
                before_lexical_path_hint: None,
                after_lexical_path_hint: None,
                before_result: Some("-1 ENOENT"),
                after_result: Some("3"),
                before: vec![EvidenceReference {
                    line_number: 4,
                    byte_offset: 32,
                    byte_length: 25,
                }],
                after: vec![EvidenceReference {
                    line_number: 7,
                    byte_offset: 77,
                    byte_length: 25,
                }],
            }],
        }
    }

    fn render(diff: &TraceDiff<'_>) -> String {
        let mut bytes = Vec::new();
        write_html_diff(diff, &mut bytes).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn renders_diff_content_and_provenance_in_static_offline_document() {
        let output = render(&make_diff("AT_FDCWD, \"config.ini\", O_RDONLY"));
        assert!(output.starts_with("<!doctype html>\n<html lang=\"en\">"));
        assert!(output.contains(
            r##"<a class="skip-link" href="#report-content">Skip to report content</a>"##
        ));
        assert!(output.contains(r#"<main id="report-content" tabindex="-1">"#));
        assert!(output.contains("</main>\n</body>"));
        assert!(output.contains("transform:translateY(-150%)"));
        assert!(output.contains(".skip-link:focus{transform:translateY(1rem)}"));
        assert!(output.contains("Content-Security-Policy"));
        assert!(output.contains("default-src 'none'; style-src 'unsafe-inline'"));
        assert!(output.contains("script-src 'none'"));
        assert!(output.contains("Capture completeness</dt><dd>unknown"));
        assert!(output.contains("Before (CLI argument 1) source SHA-256</dt><dd><span class=\"value\">1111111111111111111111111111111111111111111111111111111111111111"));
        assert!(output.contains("After (CLI argument 2) source SHA-256</dt><dd><span class=\"value\">2222222222222222222222222222222222222222222222222222222222222222"));
        assert!(output.contains(
            "Identity metadata only; not authentication, redaction, or capture completeness."
        ));
        assert!(output.contains("Excluded control records</dt><dd>Baseline: 1; candidate: 2"));
        assert!(output.contains("<h3>Changed</h3>"));
        assert!(output.contains("Before evidence (CLI argument 1)"));
        assert!(output.contains("After evidence (CLI argument 2)"));
        assert!(output.contains("sideeffect evidence TRACE SHA256 LINE BYTE_OFFSET BYTE_LENGTH"));
        assert!(output.contains("Input paths are omitted from this report."));
        assert!(output.contains("line=4 byte=32 length=25"));
        assert!(output.contains("line=7 byte=77 length=25"));
        assert!(
            output
                .contains("Before result (CLI argument 1)</dt><dd><span class=\"value\">-1 ENOENT")
        );
        assert!(output.contains("After result (CLI argument 2)</dt><dd><span class=\"value\">3"));
        assert!(output.contains("config.ini"));
        assert!(output.contains("Exact matching fields</dt><dd><span class=\"value\">record_kind</span>, <span class=\"value\">category</span>, <span class=\"value\">syscall</span>, <span class=\"value\">raw_arguments</span>, <span class=\"value\">raw_result</span>"));
        assert!(output.contains(
            "Display-only fields</dt><dd><span class=\"value\">lexical_path_hint</span>"
        ));
        assert!(!output.contains("<script"));
        assert!(!output.contains("src=\"http"));
        assert_eq!(output.matches("href=").count(), 1);
        assert!(!output.contains("href=\"http"));
    }

    #[test]
    fn renders_side_hints_as_escaped_text_without_making_them_match_keys() {
        let before_hint = LexicalPathHint {
            path: "/before/<img src=x onerror=alert(1)>".to_owned(),
            basis: LexicalPathBasis::DirectoryFdAnnotation,
        };
        let after_hint = LexicalPathHint {
            path: "/after/relative.txt".to_owned(),
            basis: LexicalPathBasis::AtFdcwdAnnotation,
        };
        let mut diff = make_diff("AT_FDCWD, \"relative.txt\", O_RDONLY");
        diff.changes[0].before_lexical_path_hint = Some(&before_hint);
        diff.changes[0].after_lexical_path_hint = Some(&after_hint);
        let output = render(&diff);
        assert!(output.contains("Before lexical path hint (display only; not used for matching)"));
        assert!(output.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(output.contains("basis=directory_fd_annotation"));
        assert!(output.contains("After lexical path hint (display only; not used for matching)"));
        assert!(!output.contains("<img"));
    }

    #[test]
    fn escapes_markup_quotes_and_css_or_url_payloads_as_text() {
        let output = render(&make_diff(
            "</script><img src=x onerror=alert(1)></pre></style><link href=\"https://evil\"> & \"quote\"",
        ));
        assert!(output.contains(
            "&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;&lt;/pre&gt;&lt;/style&gt;&lt;link href=&quot;https://evil&quot;&gt; &amp; &quot;quote&quot;"
        ));
        assert!(!output.contains("</script>"));
        assert!(!output.contains("<img"));
        assert!(!output.contains("</pre>"));
        assert_eq!(
            output.matches("</style>").count(),
            1,
            "only the static style block closes"
        );
        assert!(!output.contains("<link"));
        assert!(!output.contains("onerror=\""));
    }

    #[test]
    fn shows_controls_and_bidi_formatters_as_literal_numeric_spellings() {
        let output = render(&make_diff(
            "nul=\u{0}; esc=\u{1B}; cr\nlf; bidi=\u{202E}ABC; zwsp=\u{200B}; cafe=é",
        ));
        assert!(output.contains(
            "nul=&amp;#x0;; esc=&amp;#x1B;; cr&amp;#xA;lf; bidi=&amp;#x202E;ABC; zwsp=&amp;#x200B;"
        ));
        assert!(output.contains("cafe=é"));
        assert!(!output.contains('\u{0}'));
        assert!(!output.contains('\u{1B}'));
        assert!(!output.contains('\u{202E}'));
        assert!(!output.contains('\u{200B}'));
    }

    struct RejectWrites;

    impl Write for RejectWrites {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("write rejected"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct CappedWriter {
        bytes: Vec<u8>,
        cap: usize,
    }

    impl Write for CappedWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let remaining = self.cap.saturating_sub(self.bytes.len());
            if remaining == 0 {
                return Err(io::Error::other("output cap exceeded"));
            }
            let written = remaining.min(buffer.len());
            self.bytes.extend_from_slice(&buffer[..written]);
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn propagates_writer_and_output_cap_errors() {
        let diff = make_diff("long enough output to cross the tiny cap");
        let error = write_html_diff(&diff, &mut RejectWrites).unwrap_err();
        assert_eq!(error.to_string(), "write rejected");

        let mut capped = CappedWriter {
            bytes: Vec::new(),
            cap: 48,
        };
        let error = write_html_diff(&diff, &mut capped).unwrap_err();
        assert_eq!(error.to_string(), "output cap exceeded");
        assert_eq!(capped.bytes.len(), 48);
    }
}
