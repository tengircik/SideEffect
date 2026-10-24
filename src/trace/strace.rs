//! Parser for the line-oriented text format emitted by the planned `strace` mode.
//!
//! This parser intentionally preserves the original line and does not interpret
//! syscall argument semantics. It only recognizes the outer syscall syntax so
//! callers can attach derived data to exact evidence.

use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt;

use crate::limits::ParseLimits;
use crate::model::{
    EvidenceReference, ParseCompleteness, TRACE_DOCUMENT_SCHEMA_VERSION, TraceDiagnostic,
    TraceDocument, TraceRecord, TraceRecordKind,
};

const SOURCE_FORMAT: &str = "strace_text";
const UNFINISHED_MARKER: &str = "<unfinished ...>";
const RESUMED_MARKER: &str = " resumed>";

/// A hard parser limit or encoding error. No partial document is returned for
/// these errors, so callers cannot mistake a silently truncated trace for a
/// complete one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    InputTooLarge {
        actual_bytes: usize,
        maximum_bytes: usize,
    },
    RecordTooLarge {
        line_number: u64,
        byte_offset: u64,
        actual_bytes: usize,
        maximum_bytes: usize,
    },
    TooManyRecords {
        line_number: u64,
        maximum_records: usize,
    },
    InvalidUtf8 {
        byte_offset: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge {
                actual_bytes,
                maximum_bytes,
            } => write!(
                formatter,
                "trace is {actual_bytes} bytes; configured maximum is {maximum_bytes} bytes"
            ),
            Self::RecordTooLarge {
                line_number,
                byte_offset,
                actual_bytes,
                maximum_bytes,
            } => write!(
                formatter,
                "trace record on line {line_number} at byte {byte_offset} is {actual_bytes} bytes; configured maximum is {maximum_bytes} bytes"
            ),
            Self::TooManyRecords {
                line_number,
                maximum_records,
            } => write!(
                formatter,
                "trace has a record on line {line_number} beyond the configured maximum of {maximum_records} records"
            ),
            Self::InvalidUtf8 { byte_offset } => {
                write!(
                    formatter,
                    "trace contains invalid UTF-8 at byte {byte_offset}"
                )
            }
        }
    }
}

impl Error for ParseError {}

/// Parse a bounded, combined `strace -f -ttt -yy ... -o FILE` text capture.
///
/// Evidence offsets and lengths refer to the original input bytes. The stored
/// `raw_line` excludes LF but retains a preceding CR in CRLF input. A final
/// newline does not create an extra empty record. All other physical lines,
/// including blank lines, are retained.
pub fn parse_trace_bytes(input: &[u8], limits: ParseLimits) -> Result<TraceDocument, ParseError> {
    if input.len() > limits.max_trace_bytes {
        return Err(ParseError::InputTooLarge {
            actual_bytes: input.len(),
            maximum_bytes: limits.max_trace_bytes,
        });
    }

    if let Err(error) = std::str::from_utf8(input) {
        return Err(ParseError::InvalidUtf8 {
            byte_offset: error.valid_up_to(),
        });
    }

    let mut records = Vec::new();
    let mut diagnostics = Vec::new();
    let mut line_number = 0_u64;
    let mut byte_offset = 0_usize;

    for physical_line in input.split_inclusive(|byte| *byte == b'\n') {
        line_number += 1;
        let content = physical_line.strip_suffix(b"\n").unwrap_or(physical_line);

        if content.len() > limits.max_record_bytes {
            return Err(ParseError::RecordTooLarge {
                line_number,
                byte_offset: byte_offset as u64,
                actual_bytes: content.len(),
                maximum_bytes: limits.max_record_bytes,
            });
        }

        if records.len() >= limits.max_records {
            return Err(ParseError::TooManyRecords {
                line_number,
                maximum_records: limits.max_records,
            });
        }

        // UTF-8 was checked above, so each line is safe to borrow as text.
        let raw_line = std::str::from_utf8(content).expect("whole input was validated as UTF-8");
        let parsed = parse_line(
            raw_line,
            line_number,
            byte_offset as u64,
            content.len() as u64,
        );

        match parsed {
            Ok(record) => records.push(record),
            Err(issue) => {
                records.push(unparsed_record(
                    raw_line,
                    line_number,
                    byte_offset as u64,
                    content.len() as u64,
                ));
                diagnostics.push(TraceDiagnostic {
                    code: issue.code.to_owned(),
                    line_number,
                    byte_offset: byte_offset as u64,
                    message: issue.message.to_owned(),
                });
            }
        }

        byte_offset += physical_line.len();
    }

    validate_continuations(&records, &mut diagnostics);
    diagnostics.sort_by(|left, right| {
        (left.line_number, left.byte_offset, &left.code).cmp(&(
            right.line_number,
            right.byte_offset,
            &right.code,
        ))
    });

    let parse_status = if diagnostics.is_empty() {
        ParseCompleteness::Complete
    } else {
        ParseCompleteness::Partial
    };

    Ok(TraceDocument {
        schema_version: TRACE_DOCUMENT_SCHEMA_VERSION,
        source_format: SOURCE_FORMAT.to_owned(),
        input_bytes: input.len() as u64,
        parse_status,
        records,
        diagnostics,
    })
}

#[derive(Clone, Copy)]
struct ParseIssue {
    code: &'static str,
    message: &'static str,
}

impl ParseIssue {
    const fn malformed(message: &'static str) -> Self {
        Self {
            code: "malformed_record",
            message,
        }
    }

    const fn unsupported(message: &'static str) -> Self {
        Self {
            code: "unsupported_record",
            message,
        }
    }
}

fn parse_line(
    raw_line: &str,
    line_number: u64,
    byte_offset: u64,
    byte_length: u64,
) -> Result<TraceRecord, ParseIssue> {
    // CR is a line delimiter only when paired with LF; retain it in raw_line
    // and evidence length, but omit it from syntax recognition.
    let syntax_line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
    let mut cursor = skip_whitespace(syntax_line, 0);

    if cursor == syntax_line.len() {
        return Err(ParseIssue::unsupported(
            "blank line is not a recognized strace record",
        ));
    }

    if syntax_line[cursor..].starts_with("strace:") {
        return Ok(control_record(
            raw_line,
            line_number,
            byte_offset,
            byte_length,
            None,
            None,
        ));
    }

    let mut process_id = None;
    let mut timestamp = None;

    if syntax_line[cursor..].starts_with("[pid") {
        let close = syntax_line[cursor..]
            .find(']')
            .map(|relative| cursor + relative)
            .ok_or(ParseIssue::malformed("unterminated PID prefix"))?;
        let prefix = &syntax_line[cursor..=close];
        process_id = Some(parse_bracketed_pid(prefix)?);
        cursor = skip_whitespace(syntax_line, close + 1);
    } else if let Some((token, end)) = next_token(syntax_line, cursor) {
        if is_decimal_integer(token) {
            process_id = Some(token.parse::<u32>().map_err(|_| {
                ParseIssue::malformed("PID prefix is outside the supported integer range")
            })?);
            cursor = skip_whitespace(syntax_line, end);
        }
    }

    if let Some((token, end)) = next_token(syntax_line, cursor) {
        if is_timestamp(token) {
            timestamp = Some(token.to_owned());
            cursor = skip_whitespace(syntax_line, end);
        }
    }

    let body = &syntax_line[cursor..];
    if is_control_body(body) {
        return Ok(control_record(
            raw_line,
            line_number,
            byte_offset,
            byte_length,
            process_id,
            timestamp,
        ));
    }

    if let Some((name, arguments)) = resumed_marker(body) {
        let (raw_arguments, raw_result) = parse_resumed_tail(arguments)?;
        return Ok(record(
            raw_line,
            line_number,
            byte_offset,
            byte_length,
            TraceRecordKind::ResumedSyscall,
            process_id,
            timestamp,
            Some(name.to_owned()),
            Some(raw_arguments.to_owned()),
            Some(raw_result.to_owned()),
        ));
    }

    if let Some(prefix) = body.strip_suffix(UNFINISHED_MARKER) {
        let (name, open_paren) = parse_call_head(prefix)?;
        return Ok(record(
            raw_line,
            line_number,
            byte_offset,
            byte_length,
            TraceRecordKind::UnfinishedSyscall,
            process_id,
            timestamp,
            Some(name.to_owned()),
            Some(prefix[open_paren + 1..].to_owned()),
            None,
        ));
    }

    let (name, open_paren) = parse_call_head(body)?;
    let close_paren = find_call_close(body, open_paren)?;
    let raw_arguments = &body[open_paren + 1..close_paren];
    let after_call = skip_whitespace(body, close_paren + 1);
    let result_marker = body[after_call..]
        .strip_prefix('=')
        .ok_or(ParseIssue::malformed(
            "syscall record has no result separator",
        ))?;
    let raw_result = result_marker.trim();
    if raw_result.is_empty() {
        return Err(ParseIssue::malformed("syscall record has an empty result"));
    }

    Ok(record(
        raw_line,
        line_number,
        byte_offset,
        byte_length,
        TraceRecordKind::Syscall,
        process_id,
        timestamp,
        Some(name.to_owned()),
        Some(raw_arguments.to_owned()),
        Some(raw_result.to_owned()),
    ))
}

fn parse_bracketed_pid(prefix: &str) -> Result<u32, ParseIssue> {
    let inner = prefix
        .strip_prefix("[pid")
        .and_then(|value| value.strip_suffix(']'))
        .ok_or(ParseIssue::malformed("invalid bracketed PID prefix"))?
        .trim();
    if !is_decimal_integer(inner) {
        return Err(ParseIssue::malformed("invalid bracketed PID value"));
    }
    inner
        .parse::<u32>()
        .map_err(|_| ParseIssue::malformed("PID prefix is outside the supported integer range"))
}

fn is_decimal_integer(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_timestamp(value: &str) -> bool {
    let mut parts = value.split('.');
    matches!((parts.next(), parts.next(), parts.next()),
        (Some(seconds), Some(fraction), None)
            if is_decimal_integer(seconds) && is_decimal_integer(fraction))
}

fn next_token(line: &str, start: usize) -> Option<(&str, usize)> {
    let start = skip_whitespace(line, start);
    if start >= line.len() {
        return None;
    }
    let end = line[start..]
        .find(char::is_whitespace)
        .map_or(line.len(), |relative| start + relative);
    Some((&line[start..end], end))
}

fn skip_whitespace(value: &str, mut cursor: usize) -> usize {
    while cursor < value.len() {
        let character = value[cursor..]
            .chars()
            .next()
            .expect("cursor is on a char boundary");
        if !character.is_whitespace() {
            break;
        }
        cursor += character.len_utf8();
    }
    cursor
}

fn is_control_body(body: &str) -> bool {
    body.starts_with("+++") || body.starts_with("---") || body.starts_with("[ Process")
}

fn resumed_marker(body: &str) -> Option<(&str, &str)> {
    let prefix = body.strip_prefix("<... ")?;
    let end = prefix.find(RESUMED_MARKER)?;
    let name = &prefix[..end];
    if !is_syscall_name(name) {
        return None;
    }
    let rest_start = end + RESUMED_MARKER.len();
    Some((name, &prefix[rest_start..]))
}

fn parse_call_head(body: &str) -> Result<(&str, usize), ParseIssue> {
    let open_paren = body.find('(').ok_or(ParseIssue::unsupported(
        "line is not a recognized syscall record",
    ))?;
    let name = &body[..open_paren];
    if !is_syscall_name(name) {
        return Err(ParseIssue::unsupported(
            "syscall name is not in the supported text form",
        ));
    }
    Ok((name, open_paren))
}

fn is_syscall_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'$'))
}

fn find_call_close(body: &str, open_paren: usize) -> Result<usize, ParseIssue> {
    let bytes = body.as_bytes();
    let mut closers = vec![b')'];
    let mut quote = None;
    let mut escaped = false;
    let mut cursor = open_paren + 1;

    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if let Some(quote_byte) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == quote_byte {
                quote = None;
            }
            cursor += 1;
            continue;
        }

        if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
        } else if byte == b'<' {
            // `-yy` decorates file descriptors with `<path>` annotations. Ignore
            // delimiter characters inside the annotation, including `)`.
            cursor = scan_angle_annotation(bytes, cursor)
                .0
                .ok_or(ParseIssue::malformed(
                    "unterminated file descriptor annotation in syscall arguments",
                ))?;
            continue;
        } else if let Some(closer) = matching_closer(byte) {
            closers.push(closer);
        } else if matches!(byte, b')' | b']' | b'}') {
            if closers.last().copied() != Some(byte) {
                return Err(ParseIssue::malformed(
                    "mismatched delimiter in syscall arguments",
                ));
            }
            closers.pop();
            if closers.is_empty() {
                return Ok(cursor);
            }
        }
        cursor += 1;
    }

    Err(ParseIssue::malformed(if quote.is_some() {
        "unterminated quoted string in syscall arguments"
    } else {
        "syscall argument list has no closing parenthesis"
    }))
}

fn parse_resumed_tail(tail: &str) -> Result<(&str, &str), ParseIssue> {
    let bytes = tail.as_bytes();
    let mut closers: Vec<u8> = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    let mut cursor = 0;
    let mut close_paren = None;

    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if let Some(quote_byte) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == quote_byte {
                quote = None;
            }
            cursor += 1;
            continue;
        }

        if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
        } else if byte == b'<' {
            cursor = scan_angle_annotation(bytes, cursor)
                .0
                .ok_or(ParseIssue::malformed(
                    "unterminated file descriptor annotation in resumed syscall arguments",
                ))?;
            continue;
        } else if let Some(closer) = matching_closer(byte) {
            closers.push(closer);
        } else if matches!(byte, b')' | b']' | b'}') {
            if closers.last().copied() == Some(byte) {
                closers.pop();
            } else if byte == b')' && closers.is_empty() {
                close_paren = Some(cursor);
                break;
            } else {
                return Err(ParseIssue::malformed(
                    "mismatched delimiter in resumed syscall arguments",
                ));
            }
        }
        cursor += 1;
    }

    let close_paren = close_paren.ok_or(ParseIssue::malformed(
        "resumed syscall record has no closing parenthesis",
    ))?;
    let after_call = skip_whitespace(tail, close_paren + 1);
    let result = tail[after_call..]
        .strip_prefix('=')
        .ok_or(ParseIssue::malformed(
            "resumed syscall record has no result separator",
        ))?
        .trim();
    if result.is_empty() {
        return Err(ParseIssue::malformed(
            "resumed syscall record has an empty result",
        ));
    }
    Ok((&tail[..close_paren], result))
}

fn matching_closer(byte: u8) -> Option<u8> {
    match byte {
        b'(' => Some(b')'),
        b'[' => Some(b']'),
        b'{' => Some(b'}'),
        _ => None,
    }
}

fn scan_angle_annotation(bytes: &[u8], open: usize) -> (Option<usize>, usize) {
    let content_start = open.saturating_add(1).min(bytes.len());
    for (relative_end, byte) in bytes[content_start..].iter().enumerate() {
        if *byte == b'>' {
            return (Some(content_start + relative_end + 1), relative_end + 1);
        }
    }
    (None, bytes.len().saturating_sub(content_start))
}

fn record(
    raw_line: &str,
    line_number: u64,
    byte_offset: u64,
    byte_length: u64,
    kind: TraceRecordKind,
    process_id: Option<u32>,
    timestamp: Option<String>,
    syscall: Option<String>,
    raw_arguments: Option<String>,
    raw_result: Option<String>,
) -> TraceRecord {
    TraceRecord {
        kind,
        evidence: EvidenceReference {
            line_number,
            byte_offset,
            byte_length,
        },
        raw_line: raw_line.to_owned(),
        process_id,
        timestamp,
        syscall,
        raw_arguments,
        raw_result,
    }
}

fn control_record(
    raw_line: &str,
    line_number: u64,
    byte_offset: u64,
    byte_length: u64,
    process_id: Option<u32>,
    timestamp: Option<String>,
) -> TraceRecord {
    record(
        raw_line,
        line_number,
        byte_offset,
        byte_length,
        TraceRecordKind::Control,
        process_id,
        timestamp,
        None,
        None,
        None,
    )
}

fn unparsed_record(
    raw_line: &str,
    line_number: u64,
    byte_offset: u64,
    byte_length: u64,
) -> TraceRecord {
    record(
        raw_line,
        line_number,
        byte_offset,
        byte_length,
        TraceRecordKind::Unparsed,
        None,
        None,
        None,
        None,
        None,
    )
}

fn validate_continuations(records: &[TraceRecord], diagnostics: &mut Vec<TraceDiagnostic>) {
    let mut pending: BTreeMap<(u32, String), VecDeque<usize>> = BTreeMap::new();

    for (index, record) in records.iter().enumerate() {
        let Some(syscall) = record.syscall.as_ref() else {
            continue;
        };

        match record.kind {
            TraceRecordKind::UnfinishedSyscall => {
                if let Some(process_id) = record.process_id {
                    pending
                        .entry((process_id, syscall.clone()))
                        .or_default()
                        .push_back(index);
                } else {
                    diagnostics.push(continuation_diagnostic(
                        record,
                        "ambiguous_unfinished_syscall",
                        "unfinished syscall has no PID, so it cannot be safely paired with a resumed record",
                    ));
                }
            }
            TraceRecordKind::ResumedSyscall => {
                let Some(process_id) = record.process_id else {
                    diagnostics.push(continuation_diagnostic(
                        record,
                        "ambiguous_resumed_syscall",
                        "resumed syscall has no PID, so it cannot be safely paired with an unfinished record",
                    ));
                    continue;
                };
                match pending.get_mut(&(process_id, syscall.clone())) {
                    Some(indices) if indices.len() == 1 => {
                        indices.pop_front();
                    }
                    Some(indices) if indices.len() > 1 => {
                        diagnostics.push(continuation_diagnostic(
                            record,
                            "ambiguous_resumed_syscall",
                            "resumed syscall matches multiple unfinished records; association is uncertain",
                        ));
                    }
                    _ => diagnostics.push(continuation_diagnostic(
                        record,
                        "orphan_resumed_syscall",
                        "resumed syscall has no matching unfinished record for this PID and syscall",
                    )),
                }
            }
            _ => {}
        }
    }

    for indices in pending.values() {
        for index in indices {
            diagnostics.push(continuation_diagnostic(
                &records[*index],
                "unfinished_syscall_at_eof",
                "unfinished syscall has no unambiguous resumed record before end of trace",
            ));
        }
    }
}

fn continuation_diagnostic(
    record: &TraceRecord,
    code: &'static str,
    message: &'static str,
) -> TraceDiagnostic {
    TraceDiagnostic {
        code: code.to_owned(),
        line_number: record.evidence.line_number,
        byte_offset: record.evidence.byte_offset,
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod scanner_tests {
    use super::scan_angle_annotation;

    #[test]
    fn unterminated_angle_annotation_scan_is_bounded_by_record_length() {
        let bytes = vec![b'<'; 64 * 1024];
        let (end, inspected) = scan_angle_annotation(&bytes, 0);

        assert_eq!(end, None);
        assert_eq!(inspected, bytes.len() - 1);
        assert!(inspected <= bytes.len());
    }
}
