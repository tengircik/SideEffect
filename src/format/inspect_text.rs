use std::io::{self, Write};

use crate::model::{
    EvidenceReference, ParseCompleteness, TraceDiagnostic, TraceDocument, TraceRecordKind,
};
use crate::trace::LexicalPathBasis;

/// Write a terminal-safe, ASCII-only view of every parsed trace record and diagnostic.
///
/// Trace text is rendered as quoted, escaped Unicode scalar values. The caller
/// is responsible for enforcing an output byte limit.
pub fn write_trace_text<W: Write>(document: &TraceDocument, writer: &mut W) -> io::Result<()> {
    writer.write_all(b"SideEffect trace inspection\n")?;
    writeln!(writer, "Schema version: {}", document.schema_version)?;
    writer.write_all(b"Source format: ")?;
    write_quoted(writer, &document.source_format)?;
    writer.write_all(b"\nSource SHA-256: ")?;
    write_fingerprint(writer, &document.source_sha256)?;
    writer.write_all(b"\n")?;
    writeln!(writer, "Input bytes: {}", document.input_bytes)?;
    writer.write_all(b"Parse status: ")?;
    writer.write_all(parse_status_name(document.parse_status).as_bytes())?;
    writeln!(writer, "\nRecords: {}", document.records.len())?;

    for (index, record) in document.records.iter().enumerate() {
        writeln!(writer, "\nRecord {}", index + 1)?;
        write_record_details(writer, record)?;
    }

    writeln!(writer, "\nDiagnostics: {}", document.diagnostics.len())?;
    for (index, diagnostic) in document.diagnostics.iter().enumerate() {
        write_diagnostic(writer, index + 1, diagnostic)?;
    }
    Ok(())
}

/// Write one parsed source record after the CLI has matched its line/offset/length reference.
///
/// A partial input is labeled explicitly; the caller has verified the content fingerprint, but
/// this view does not certify authenticity or capture completeness.
pub fn write_trace_evidence_text<W: Write>(
    record: &crate::model::TraceRecord,
    parse_status: ParseCompleteness,
    source_sha256: &str,
    writer: &mut W,
) -> io::Result<()> {
    writer.write_all(b"SideEffect evidence lookup\n")?;
    writer.write_all(b"Parse status: ")?;
    writer.write_all(parse_status_name(parse_status).as_bytes())?;
    writer.write_all(b"\n")?;
    writer.write_all(b"Source SHA-256: ")?;
    write_fingerprint(writer, source_sha256)?;
    writer.write_all(b"\n")?;
    if parse_status == ParseCompleteness::Partial {
        writer.write_all(b"Warning: the input parse is partial; the fingerprint identifies these bytes, but this is not a complete comparison or capture-coverage claim.\n")?;
    }
    writer.write_all(b"Reference: ")?;
    writeln!(
        writer,
        "line={} byte={} length={}",
        record.evidence.line_number, record.evidence.byte_offset, record.evidence.byte_length
    )?;
    writer.write_all(b"Reference scope: exact bytes matched the supplied SHA-256 fingerprint; this is identity metadata, not authenticity or capture completeness.\n\n")?;
    write_record_details(writer, record)
}

fn write_record_details<W: Write>(
    writer: &mut W,
    record: &crate::model::TraceRecord,
) -> io::Result<()> {
    writer.write_all(b"  Kind: ")?;
    writer.write_all(record_kind_name(record.kind).as_bytes())?;
    writer.write_all(b"\n")?;
    write_optional_u32(writer, "  Process ID", record.process_id)?;
    write_optional_quoted(writer, "  Timestamp", record.timestamp.as_deref())?;
    write_optional_quoted(writer, "  Syscall", record.syscall.as_deref())?;
    write_optional_quoted(writer, "  Arguments", record.raw_arguments.as_deref())?;
    write_optional_quoted(writer, "  Result", record.raw_result.as_deref())?;
    if let Some(hint) = record.lexical_path_hint.as_ref() {
        write_optional_quoted(writer, "  Lexical path hint", Some(&hint.path))?;
        writer.write_all(b"  Path hint basis: ")?;
        writer.write_all(path_hint_basis_name(hint.basis).as_bytes())?;
        writer.write_all(b"\n")?;
    }
    write_evidence(writer, &record.evidence)?;
    writer.write_all(b"  Raw line: ")?;
    write_quoted(writer, &record.raw_line)?;
    writer.write_all(b"\n")
}

fn write_optional_u32<W: Write>(writer: &mut W, label: &str, value: Option<u32>) -> io::Result<()> {
    if let Some(value) = value {
        writeln!(writer, "{label}: {value}")?;
    }
    Ok(())
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

fn write_optional_quoted<W: Write>(
    writer: &mut W,
    label: &str,
    value: Option<&str>,
) -> io::Result<()> {
    if let Some(value) = value {
        writer.write_all(label.as_bytes())?;
        writer.write_all(b": ")?;
        write_quoted(writer, value)?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn write_evidence<W: Write>(writer: &mut W, evidence: &EvidenceReference) -> io::Result<()> {
    writeln!(
        writer,
        "  Evidence: line={} byte={} length={}",
        evidence.line_number, evidence.byte_offset, evidence.byte_length
    )
}

fn write_diagnostic<W: Write>(
    writer: &mut W,
    index: usize,
    diagnostic: &TraceDiagnostic,
) -> io::Result<()> {
    writeln!(writer, "\nDiagnostic {index}")?;
    writer.write_all(b"  Code: ")?;
    write_quoted(writer, &diagnostic.code)?;
    writeln!(
        writer,
        "\n  Location: line={} byte={}",
        diagnostic.line_number, diagnostic.byte_offset
    )?;
    writer.write_all(b"  Message: ")?;
    write_quoted(writer, &diagnostic.message)?;
    writer.write_all(b"\n")
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

fn parse_status_name(status: ParseCompleteness) -> &'static str {
    match status {
        ParseCompleteness::Complete => "complete",
        ParseCompleteness::Partial => "partial",
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

fn path_hint_basis_name(basis: LexicalPathBasis) -> &'static str {
    match basis {
        LexicalPathBasis::AbsoluteArgument => "absolute_argument",
        LexicalPathBasis::AtFdcwdAnnotation => "at_fdcwd_annotation",
        LexicalPathBasis::DirectoryFdAnnotation => "directory_fd_annotation",
    }
}

#[cfg(test)]
mod tests {
    use super::write_trace_text;
    use crate::model::{
        EvidenceReference, ParseCompleteness, TraceDiagnostic, TraceDocument, TraceRecord,
        TraceRecordKind,
    };
    use crate::trace::{LexicalPathBasis, LexicalPathHint};
    use std::io::{self, Write};

    fn record(
        kind: TraceRecordKind,
        line_number: u64,
        raw_line: &str,
        syscall: Option<&str>,
    ) -> TraceRecord {
        TraceRecord {
            kind,
            evidence: EvidenceReference {
                line_number,
                byte_offset: (line_number - 1) * 20,
                byte_length: raw_line.len() as u64,
            },
            raw_line: raw_line.to_owned(),
            process_id: Some(42),
            timestamp: Some(format!("1700000000.{line_number:06}")),
            syscall: syscall.map(str::to_owned),
            raw_arguments: syscall.map(|_| "AT_FDCWD, \"path\"".to_owned()),
            raw_result: syscall.map(|_| "0".to_owned()),
            lexical_path_hint: None,
        }
    }

    fn document() -> TraceDocument {
        TraceDocument {
            schema_version: crate::model::TRACE_DOCUMENT_SCHEMA_VERSION,
            source_format: "strace_text".to_owned(),
            source_sha256: "00".repeat(32),
            input_bytes: 120,
            parse_status: ParseCompleteness::Partial,
            records: vec![
                record(
                    TraceRecordKind::Syscall,
                    1,
                    "openat(...) = 3",
                    Some("openat"),
                ),
                record(
                    TraceRecordKind::UnfinishedSyscall,
                    2,
                    "read(3,  <unfinished ...>",
                    Some("read"),
                ),
                record(
                    TraceRecordKind::ResumedSyscall,
                    3,
                    "<... read resumed>) = 1",
                    Some("read"),
                ),
                record(TraceRecordKind::Control, 4, "+++ exited with 0 +++", None),
                record(TraceRecordKind::Unparsed, 5, "not a parsed record", None),
            ],
            diagnostics: vec![TraceDiagnostic {
                code: "malformed_record".to_owned(),
                line_number: 5,
                byte_offset: 80,
                message: "unexpected text: \u{202E}\nignored".to_owned(),
            }],
        }
    }

    #[test]
    fn prints_metadata_every_record_in_order_and_all_diagnostics() {
        let mut document = document();
        document.records[0].lexical_path_hint = Some(LexicalPathHint {
            path: "/home/demo/file.txt".to_owned(),
            basis: LexicalPathBasis::AtFdcwdAnnotation,
        });
        let mut bytes = Vec::new();
        write_trace_text(&document, &mut bytes).unwrap();
        assert!(bytes.is_ascii());
        let output = String::from_utf8(bytes).unwrap();

        assert!(output.contains("Schema version: 3"));
        assert!(output.contains("Source format: \"strace_text\""));
        assert!(output.contains(&format!("Source SHA-256: {}", "00".repeat(32))));
        assert!(output.contains("Input bytes: 120"));
        assert!(output.contains("Parse status: partial"));
        assert!(output.contains("Records: 5"));
        let syscall = output.find("Kind: syscall").unwrap();
        let unfinished = output.find("Kind: unfinished_syscall").unwrap();
        let resumed = output.find("Kind: resumed_syscall").unwrap();
        let control = output.find("Kind: control").unwrap();
        let unparsed = output.find("Kind: unparsed").unwrap();
        assert!(
            syscall < unfinished && unfinished < resumed && resumed < control && control < unparsed
        );
        assert!(output.contains("Process ID: 42"));
        assert!(output.contains("Timestamp: \"1700000000.000001\""));
        assert!(output.contains("Syscall: \"openat\""));
        assert!(output.contains("Arguments: \"AT_FDCWD, \\\"path\\\"\""));
        assert!(output.contains("Result: \"0\""));
        assert!(output.contains("Lexical path hint: \"/home/demo/file.txt\""));
        assert!(output.contains("Path hint basis: at_fdcwd_annotation"));
        assert!(output.contains("Evidence: line=5 byte=80 length=19"));
        assert!(output.contains("Raw line: \"not a parsed record\""));
        assert!(output.contains("Diagnostics: 1"));
        assert!(output.contains("Code: \"malformed_record\""));
        assert!(output.contains("Location: line=5 byte=80"));
        assert!(output.contains("Message: \"unexpected text: \\u{202E}\\u{A}ignored\""));
    }

    #[test]
    fn escapes_terminal_controls_bidi_and_non_ascii_as_visible_ascii() {
        let mut trace = document();
        trace.source_format = "strace\u{1B}[31m\u{202E}é".to_owned();
        trace.source_sha256 = "\u{1B}[31m".to_owned();
        trace.records[0].raw_arguments = Some("first\r\nsecond\t\u{7F} \"q\" \\".to_owned());
        trace.records[0].raw_line = "data\u{1B}]0;title\u{7} and café".to_owned();
        trace.diagnostics[0].message = "invisible\u{200B} bidi\u{2066}".to_owned();

        let mut bytes = Vec::new();
        write_trace_text(&trace, &mut bytes).unwrap();
        assert!(bytes.is_ascii());
        assert!(!bytes.contains(&0x1b));
        let output = String::from_utf8(bytes).unwrap();
        assert!(output.contains("strace\\u{1B}[31m\\u{202E}\\u{E9}"));
        assert!(output.contains("Source SHA-256: \"\\u{1B}[31m\""));
        assert!(output.contains("first\\u{D}\\u{A}second\\u{9}\\u{7F}"));
        assert!(output.contains("data\\u{1B}]0;title\\u{7} and caf\\u{E9}"));
        assert!(output.contains("invisible\\u{200B} bidi\\u{2066}"));
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
    fn propagates_writer_errors() {
        let error = write_trace_text(&document(), &mut RejectWrites).unwrap_err();
        assert_eq!(error.to_string(), "write rejected");
    }
}
