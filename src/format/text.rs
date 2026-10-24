use std::io::{self, Write};

use crate::model::{
    CaptureCompleteness, DeltaKind, EventCategory, EvidenceReference, TraceDiff, TraceRecordKind,
};
use crate::trace::{LexicalPathBasis, LexicalPathHint};

/// Write a terminal-safe, ASCII-only rendering of a paired trace comparison.
///
/// Trace-derived strings are quoted and escaped as Unicode code points. This
/// keeps control sequences inert while preserving their exact scalar values.
/// The caller is responsible for enforcing an output byte budget.
pub fn write_text_diff<W: Write>(diff: &TraceDiff<'_>, writer: &mut W) -> io::Result<()> {
    writer.write_all(b"SideEffect trace comparison\n")?;
    writeln!(writer, "Schema version: {}", diff.schema_version)?;
    writer.write_all(b"Capture completeness: ")?;
    match diff.capture_completeness {
        CaptureCompleteness::Unknown => {
            writer.write_all(b"unknown (not established by parsing)\n")?
        }
    }

    writer.write_all(b"Baseline source format: ")?;
    write_quoted(writer, diff.left_source_format)?;
    writer.write_all(b"\nCandidate source format: ")?;
    write_quoted(writer, diff.right_source_format)?;
    writer.write_all(b"\nBaseline source SHA-256: ")?;
    write_fingerprint(writer, diff.left_source_sha256)?;
    writer.write_all(b"\nCandidate source SHA-256: ")?;
    write_fingerprint(writer, diff.right_source_sha256)?;
    writer.write_all(b"\n")?;
    writer.write_all(b"\nMatching policy: multiplicity=")?;
    write_quoted(writer, &diff.matching_policy.multiplicity)?;
    writer.write_all(b"; exact fields: ")?;
    write_quoted_list(writer, &diff.matching_policy.exact_fields)?;
    writer.write_all(b"; ignored prefix fields: ")?;
    write_quoted_list(writer, &diff.matching_policy.ignored_prefix_fields)?;
    writer.write_all(b"; matching uses exact syscall names, raw arguments, and results; lexical_path_hint is display-only.\n")?;
    writeln!(
        writer,
        "Excluded control records: baseline={}, candidate={}",
        diff.left_excluded_control_records, diff.right_excluded_control_records
    )?;

    if diff.changes.is_empty() {
        writer.write_all(b"\nNo observed syscall-row differences.\n")?;
        return Ok(());
    }

    writeln!(writer, "\nObserved differences: {}", diff.changes.len())?;
    for (index, change) in diff.changes.iter().enumerate() {
        writeln!(writer, "\n{}. {}", index + 1, delta_name(change.kind))?;
        writer.write_all(b"   Category: ")?;
        writer.write_all(category_name(change.category).as_bytes())?;
        writer.write_all(b"\n   Record kind: ")?;
        writer.write_all(record_kind_name(change.record_kind).as_bytes())?;
        writer.write_all(b"\n   Syscall: ")?;
        write_quoted(writer, change.syscall)?;
        writer.write_all(b"\n   Arguments: ")?;
        write_quoted(writer, change.raw_arguments)?;
        writer.write_all(
            b"\n   Baseline lexical path hint (display only; not used for matching): ",
        )?;
        write_optional_path_hint(writer, change.before_lexical_path_hint)?;
        writer.write_all(
            b"\n   Candidate lexical path hint (display only; not used for matching): ",
        )?;
        write_optional_path_hint(writer, change.after_lexical_path_hint)?;
        writer.write_all(b"\n   Baseline result: ")?;
        write_optional_quoted(writer, change.before_result)?;
        writer.write_all(b"\n   Candidate result: ")?;
        write_optional_quoted(writer, change.after_result)?;
        writer.write_all(b"\n")?;
        write_evidence_section(writer, "Baseline evidence", &change.before)?;
        write_evidence_section(writer, "Candidate evidence", &change.after)?;
    }
    Ok(())
}

fn write_optional_path_hint<W: Write>(
    writer: &mut W,
    hint: Option<&LexicalPathHint>,
) -> io::Result<()> {
    match hint {
        Some(hint) => {
            write_quoted(writer, &hint.path)?;
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

fn write_evidence_section<W: Write>(
    writer: &mut W,
    label: &str,
    evidence: &[EvidenceReference],
) -> io::Result<()> {
    writeln!(writer, "   {label}:")?;
    if evidence.is_empty() {
        writer.write_all(b"     (none)\n")?;
        return Ok(());
    }
    for reference in evidence {
        writeln!(
            writer,
            "     line={} byte={} length={}",
            reference.line_number, reference.byte_offset, reference.byte_length
        )?;
    }
    Ok(())
}

fn write_optional_quoted<W: Write>(writer: &mut W, value: Option<&str>) -> io::Result<()> {
    match value {
        Some(value) => write_quoted(writer, value),
        None => writer.write_all(b"(not present)"),
    }
}

fn write_fingerprint<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        writer.write_all(value.as_bytes())
    } else {
        write_quoted(writer, value)
    }
}

fn write_quoted_list<W: Write>(writer: &mut W, values: &[String]) -> io::Result<()> {
    if values.is_empty() {
        return writer.write_all(b"(none)");
    }
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            writer.write_all(b", ")?;
        }
        write_quoted(writer, value)?;
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
    use super::write_text_diff;
    use crate::model::{
        CaptureCompleteness, DeltaKind, EventCategory, EvidenceReference, MatchingPolicy,
        ObservedDelta, TRACE_DIFF_SCHEMA_VERSION, TraceDiff, TraceRecordKind,
    };
    use crate::trace::{LexicalPathBasis, LexicalPathHint};
    use std::io::{self, Write};

    fn diff_with<'a>(changes: Vec<ObservedDelta<'a>>) -> TraceDiff<'a> {
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
            left_excluded_control_records: 2,
            right_excluded_control_records: 3,
            changes,
        }
    }

    fn delta<'a>(
        kind: DeltaKind,
        category: EventCategory,
        syscall: &'a str,
        args: &'a str,
        results: (Option<&'a str>, Option<&'a str>),
        evidence: (Vec<EvidenceReference>, Vec<EvidenceReference>),
    ) -> ObservedDelta<'a> {
        ObservedDelta {
            kind,
            category,
            record_kind: TraceRecordKind::Syscall,
            syscall,
            raw_arguments: args,
            before_lexical_path_hint: None,
            after_lexical_path_hint: None,
            before_result: results.0,
            after_result: results.1,
            before: evidence.0,
            after: evidence.1,
        }
    }

    fn reference(line_number: u64, byte_offset: u64, byte_length: u64) -> EvidenceReference {
        EvidenceReference {
            line_number,
            byte_offset,
            byte_length,
        }
    }

    #[test]
    fn renders_added_removed_and_changed_with_baseline_candidate_provenance() {
        let diff = diff_with(vec![
            delta(
                DeltaKind::Added,
                EventCategory::File,
                "openat",
                "AT_FDCWD, \"new.txt\", O_RDONLY",
                (None, Some("3")),
                (vec![], vec![reference(9, 104, 32)]),
            ),
            delta(
                DeltaKind::Removed,
                EventCategory::Process,
                "execve",
                "\"old-tool\", []",
                (Some("0"), None),
                (vec![reference(2, 0, 28)], vec![]),
            ),
            delta(
                DeltaKind::Changed,
                EventCategory::Network,
                "connect",
                "3, {sa_family=AF_INET, sin_port=htons(443)}",
                (Some("-1 ECONNREFUSED"), Some("0")),
                (vec![reference(4, 40, 51)], vec![reference(5, 50, 48)]),
            ),
        ]);
        let mut output = Vec::new();
        write_text_diff(&diff, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.starts_with("SideEffect trace comparison\nSchema version: 3\n"));
        assert!(output.contains("Baseline source SHA-256: 1111111111111111111111111111111111111111111111111111111111111111"));
        assert!(output.contains("Candidate source SHA-256: 2222222222222222222222222222222222222222222222222222222222222222"));
        assert!(output.contains("Capture completeness: unknown (not established by parsing)"));
        assert!(output.contains("Excluded control records: baseline=2, candidate=3"));
        assert!(output.contains("1. Added\n"));
        assert!(output.contains("2. Removed\n"));
        assert!(output.contains("3. Changed\n"));
        assert!(output.contains("line=9 byte=104 length=32"));
        assert!(output.contains("line=2 byte=0 length=28"));
        assert!(
            output.contains("Baseline result: \"-1 ECONNREFUSED\"\n   Candidate result: \"0\"")
        );
        assert!(output.is_ascii());
    }

    #[test]
    fn empty_diff_says_no_observed_rows_changed() {
        let diff = diff_with(vec![]);
        let mut output = Vec::new();
        write_text_diff(&diff, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("No observed syscall-row differences."));
        assert!(output.is_ascii());
    }

    #[test]
    fn renders_each_evidence_reference_without_collapsing_multiplicity() {
        let diff = diff_with(vec![delta(
            DeltaKind::Added,
            EventCategory::File,
            "read",
            "4, buf, 8",
            (None, Some("8")),
            (vec![], vec![reference(3, 20, 16), reference(7, 99, 16)]),
        )]);
        let mut output = Vec::new();
        write_text_diff(&diff, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("line=3 byte=20 length=16\n     line=7 byte=99 length=16"));
    }

    #[test]
    fn renders_side_specific_lexical_hints_as_display_only() {
        let before_hint = LexicalPathHint {
            path: "/before/relative.txt".to_owned(),
            basis: LexicalPathBasis::DirectoryFdAnnotation,
        };
        let after_hint = LexicalPathHint {
            path: "/after/relative.txt".to_owned(),
            basis: LexicalPathBasis::AtFdcwdAnnotation,
        };
        let mut changed = delta(
            DeltaKind::Changed,
            EventCategory::File,
            "openat",
            "AT_FDCWD, \"relative.txt\", O_RDONLY",
            (Some("3"), Some("4")),
            (vec![reference(1, 0, 25)], vec![reference(1, 0, 25)]),
        );
        changed.before_lexical_path_hint = Some(&before_hint);
        changed.after_lexical_path_hint = Some(&after_hint);
        let diff = diff_with(vec![changed]);
        let mut output = Vec::new();
        write_text_diff(&diff, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("exact fields: \"record_kind\", \"category\", \"syscall\", \"raw_arguments\", \"raw_result\""));
        assert!(output.contains("matching uses exact syscall names, raw arguments, and results; lexical_path_hint is display-only."));
        assert!(output.contains("Baseline lexical path hint (display only; not used for matching): \"/before/relative.txt\" (basis=directory_fd_annotation)"));
        assert!(output.contains("Candidate lexical path hint (display only; not used for matching): \"/after/relative.txt\" (basis=at_fdcwd_annotation)"));
    }

    #[test]
    fn escapes_terminal_controls_quotes_backslashes_bidi_and_non_ascii() {
        let mut diff = diff_with(vec![delta(
            DeltaKind::Added,
            EventCategory::Other,
            "write\u{1B}[31m\u{202E}é",
            "line1\r\nline2\t\u{7F} \"quoted\" \\",
            (None, Some("\u{1B}]0;title\u{7}״")),
            (vec![], vec![reference(1, 0, 4)]),
        )]);
        diff.left_source_sha256 = "\u{1B}[31m";
        let mut output = Vec::new();
        write_text_diff(&diff, &mut output).unwrap();
        let bytes = output;
        assert!(bytes.is_ascii());
        let output = String::from_utf8(bytes).unwrap();
        assert!(output.contains("write\\u{1B}[31m\\u{202E}\\u{E9}"));
        assert!(output.contains("Baseline source SHA-256: \"\\u{1B}[31m\""));
        assert!(output.contains("line1\\u{D}\\u{A}line2\\u{9}\\u{7F}"));
        assert!(output.contains("\\\"quoted\\\" \\\\"));
        assert!(output.contains("\\u{1B}]0;title\\u{7}\\u{5F4}"));
        assert!(!output.as_bytes().contains(&0x1b));
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

    #[test]
    fn propagates_writer_error_immediately() {
        let diff = diff_with(vec![]);
        let error = write_text_diff(&diff, &mut RejectWrites).unwrap_err();
        assert_eq!(error.to_string(), "write rejected");
    }
}
