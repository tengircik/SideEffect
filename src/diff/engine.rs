use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

use crate::limits::{MAX_DIFF_INPUT_BYTES, MAX_DIFF_RECORDS};
use crate::model::{
    CaptureCompleteness, DeltaKind, EventCategory, MatchingPolicy, ObservedDelta,
    ParseCompleteness, TRACE_DIFF_SCHEMA_VERSION, TraceDiff, TraceDocument, TraceRecordKind,
};
use crate::trace::LexicalPathHint;

/// Which side of a pair failed validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffSide {
    Left,
    Right,
}

/// Errors that prevent a trustworthy comparison from being produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiffError {
    PartialParse {
        side: DiffSide,
    },
    InconsistentDocument {
        side: DiffSide,
        line_number: u64,
        reason: &'static str,
    },
    TooManyRecords {
        actual: usize,
        maximum: usize,
    },
    InputTooLarge {
        actual_bytes: u64,
        maximum_bytes: usize,
    },
    AllocationFailed {
        requested: usize,
    },
}

impl fmt::Display for DiffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PartialParse { side } => {
                write!(formatter, "{side:?} trace is not completely parsed")
            }
            Self::InconsistentDocument {
                side,
                line_number,
                reason,
            } => write!(
                formatter,
                "{side:?} trace has an inconsistent record at line {line_number}: {reason}"
            ),
            Self::TooManyRecords { actual, maximum } => write!(
                formatter,
                "paired traces contain {actual} records; configured maximum is {maximum}"
            ),
            Self::InputTooLarge {
                actual_bytes,
                maximum_bytes,
            } => write!(
                formatter,
                "paired traces contain {actual_bytes} input bytes; configured maximum is {maximum_bytes} bytes"
            ),
            Self::AllocationFailed { requested } => write!(
                formatter,
                "could not reserve bounded comparison storage for {requested} records"
            ),
        }
    }
}

impl Error for DiffError {}

#[derive(Clone, Copy)]
struct Row<'a> {
    record_kind: TraceRecordKind,
    category: EventCategory,
    syscall: &'a str,
    raw_arguments: &'a str,
    raw_result: Option<&'a str>,
    lexical_path_hint: Option<&'a LexicalPathHint>,
    evidence: &'a crate::model::EvidenceReference,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Signature<'a> {
    category: EventCategory,
    record_kind: TraceRecordKind,
    syscall: &'a str,
    raw_arguments: &'a str,
}

impl<'a> Signature<'a> {
    fn from_row(row: &Row<'a>) -> Self {
        Self {
            category: row.category,
            record_kind: row.record_kind,
            syscall: row.syscall,
            raw_arguments: row.raw_arguments,
        }
    }
}

fn compare_signatures(left: Signature<'_>, right: Signature<'_>) -> Ordering {
    (
        left.category,
        left.syscall,
        left.raw_arguments,
        record_kind_rank(left.record_kind),
    )
        .cmp(&(
            right.category,
            right.syscall,
            right.raw_arguments,
            record_kind_rank(right.record_kind),
        ))
}

fn compare_rows(left: &Row<'_>, right: &Row<'_>) -> Ordering {
    compare_signatures(Signature::from_row(left), Signature::from_row(right))
        .then_with(|| left.raw_result.cmp(&right.raw_result))
        .then_with(|| left.evidence.byte_offset.cmp(&right.evidence.byte_offset))
        .then_with(|| left.evidence.line_number.cmp(&right.evidence.line_number))
}

/// Compare two parsed traces as exact multisets of observed syscall records.
///
/// Only PID and timestamp prefixes are ignored. Record kind, syscall name,
/// argument text, and result text remain exact matching fields. No argument,
/// path, file descriptor, or result normalization is applied. `Control` rows
/// are excluded from event matching and reported as counts. The output always
/// says capture completeness is unknown: a complete parse cannot establish
/// complete OS observation.
pub fn compare_traces<'a>(
    left: &'a TraceDocument,
    right: &'a TraceDocument,
) -> Result<TraceDiff<'a>, DiffError> {
    let combined_input_bytes =
        left.input_bytes
            .checked_add(right.input_bytes)
            .ok_or(DiffError::InputTooLarge {
                actual_bytes: u64::MAX,
                maximum_bytes: MAX_DIFF_INPUT_BYTES,
            })?;
    if combined_input_bytes > MAX_DIFF_INPUT_BYTES as u64 {
        return Err(DiffError::InputTooLarge {
            actual_bytes: combined_input_bytes,
            maximum_bytes: MAX_DIFF_INPUT_BYTES,
        });
    }

    let combined_count =
        left.records
            .len()
            .checked_add(right.records.len())
            .ok_or(DiffError::TooManyRecords {
                actual: usize::MAX,
                maximum: MAX_DIFF_RECORDS,
            })?;
    if combined_count > MAX_DIFF_RECORDS {
        return Err(DiffError::TooManyRecords {
            actual: combined_count,
            maximum: MAX_DIFF_RECORDS,
        });
    }

    validate_document(left, DiffSide::Left)?;
    validate_document(right, DiffSide::Right)?;

    let left_syscall_count = left
        .records
        .iter()
        .filter(|record| is_compared_record(record.kind))
        .count();
    let right_syscall_count = right
        .records
        .iter()
        .filter(|record| is_compared_record(record.kind))
        .count();

    let mut left_rows = Vec::new();
    left_rows
        .try_reserve_exact(left_syscall_count)
        .map_err(|_| DiffError::AllocationFailed {
            requested: left_syscall_count,
        })?;
    let mut right_rows = Vec::new();
    right_rows
        .try_reserve_exact(right_syscall_count)
        .map_err(|_| DiffError::AllocationFailed {
            requested: right_syscall_count,
        })?;

    let left_excluded_control_records = collect_rows(left, &mut left_rows);
    let right_excluded_control_records = collect_rows(right, &mut right_rows);
    left_rows.sort_by(compare_rows);
    right_rows.sort_by(compare_rows);

    let mut changes = Vec::new();
    changes
        .try_reserve_exact(left_rows.len().saturating_add(right_rows.len()))
        .map_err(|_| DiffError::AllocationFailed {
            requested: left_rows.len().saturating_add(right_rows.len()),
        })?;
    let mut unmatched_left = Vec::new();
    unmatched_left
        .try_reserve_exact(left_rows.len())
        .map_err(|_| DiffError::AllocationFailed {
            requested: left_rows.len(),
        })?;
    let mut unmatched_right = Vec::new();
    unmatched_right
        .try_reserve_exact(right_rows.len())
        .map_err(|_| DiffError::AllocationFailed {
            requested: right_rows.len(),
        })?;

    compare_sorted_rows(
        &left_rows,
        &right_rows,
        &mut unmatched_left,
        &mut unmatched_right,
        &mut changes,
    )?;
    changes.sort_by(compare_deltas);

    Ok(TraceDiff {
        schema_version: TRACE_DIFF_SCHEMA_VERSION,
        left_source_format: &left.source_format,
        right_source_format: &right.source_format,
        left_source_sha256: &left.source_sha256,
        right_source_sha256: &right.source_sha256,
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
        left_excluded_control_records,
        right_excluded_control_records,
        changes,
    })
}

fn validate_document(document: &TraceDocument, side: DiffSide) -> Result<(), DiffError> {
    if document.parse_status != ParseCompleteness::Complete {
        return Err(DiffError::PartialParse { side });
    }
    if !document.diagnostics.is_empty() {
        return Err(DiffError::InconsistentDocument {
            side,
            line_number: document.diagnostics[0].line_number,
            reason: "complete parse status includes diagnostics",
        });
    }

    for record in &document.records {
        match record.kind {
            TraceRecordKind::Control => {}
            TraceRecordKind::Syscall
            | TraceRecordKind::UnfinishedSyscall
            | TraceRecordKind::ResumedSyscall => {
                if record.syscall.is_none() || record.raw_arguments.is_none() {
                    return Err(DiffError::InconsistentDocument {
                        side,
                        line_number: record.evidence.line_number,
                        reason: "parsed syscall record is missing its name or argument text",
                    });
                }
                let result_is_required = matches!(
                    record.kind,
                    TraceRecordKind::Syscall | TraceRecordKind::ResumedSyscall
                );
                if result_is_required != record.raw_result.is_some() {
                    return Err(DiffError::InconsistentDocument {
                        side,
                        line_number: record.evidence.line_number,
                        reason: "parsed syscall record has an inconsistent result field",
                    });
                }
            }
            TraceRecordKind::Unparsed => {
                return Err(DiffError::InconsistentDocument {
                    side,
                    line_number: record.evidence.line_number,
                    reason: "unparsed record is marked complete",
                });
            }
        }
    }
    Ok(())
}

fn is_compared_record(kind: TraceRecordKind) -> bool {
    matches!(
        kind,
        TraceRecordKind::Syscall
            | TraceRecordKind::UnfinishedSyscall
            | TraceRecordKind::ResumedSyscall
    )
}

fn collect_rows<'a>(document: &'a TraceDocument, rows: &mut Vec<Row<'a>>) -> u64 {
    let mut control_count = 0_u64;
    for record in &document.records {
        match record.kind {
            TraceRecordKind::Control => control_count += 1,
            TraceRecordKind::Unparsed => unreachable!("document was validated"),
            kind => {
                let syscall = record.syscall.as_deref().expect("document was validated");
                let raw_arguments = record
                    .raw_arguments
                    .as_deref()
                    .expect("document was validated");
                rows.push(Row {
                    record_kind: kind,
                    category: classify_syscall(syscall),
                    syscall,
                    raw_arguments,
                    raw_result: record.raw_result.as_deref(),
                    lexical_path_hint: record.lexical_path_hint.as_ref(),
                    evidence: &record.evidence,
                });
            }
        }
    }
    control_count
}

fn compare_sorted_rows<'a>(
    left: &[Row<'a>],
    right: &[Row<'a>],
    unmatched_left: &mut Vec<usize>,
    unmatched_right: &mut Vec<usize>,
    changes: &mut Vec<ObservedDelta<'a>>,
) -> Result<(), DiffError> {
    let mut left_start = 0;
    let mut right_start = 0;

    while left_start < left.len() || right_start < right.len() {
        let left_end = group_end(left, left_start);
        let right_end = group_end(right, right_start);

        let ordering = match (left.get(left_start), right.get(right_start)) {
            (Some(left_row), Some(right_row)) => compare_signatures(
                Signature::from_row(left_row),
                Signature::from_row(right_row),
            ),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => break,
        };

        unmatched_left.clear();
        unmatched_right.clear();

        match ordering {
            Ordering::Equal => {
                compare_group_results(
                    &left[left_start..left_end],
                    &right[right_start..right_end],
                    unmatched_left,
                    unmatched_right,
                );
                emit_unmatched_changes(
                    &left[left_start..left_end],
                    &right[right_start..right_end],
                    unmatched_left,
                    unmatched_right,
                    changes,
                )?;
                left_start = left_end;
                right_start = right_end;
            }
            Ordering::Less => {
                unmatched_left.extend(0..left_end - left_start);
                emit_unmatched_changes(
                    &left[left_start..left_end],
                    &[],
                    unmatched_left,
                    unmatched_right,
                    changes,
                )?;
                left_start = left_end;
            }
            Ordering::Greater => {
                unmatched_right.extend(0..right_end - right_start);
                emit_unmatched_changes(
                    &[],
                    &right[right_start..right_end],
                    unmatched_left,
                    unmatched_right,
                    changes,
                )?;
                right_start = right_end;
            }
        }
    }
    Ok(())
}

fn group_end(rows: &[Row<'_>], start: usize) -> usize {
    if start >= rows.len() {
        return start;
    }
    let signature = Signature::from_row(&rows[start]);
    let mut end = start + 1;
    while end < rows.len()
        && compare_signatures(signature, Signature::from_row(&rows[end])) == Ordering::Equal
    {
        end += 1;
    }
    end
}

fn compare_group_results(
    left: &[Row<'_>],
    right: &[Row<'_>],
    unmatched_left: &mut Vec<usize>,
    unmatched_right: &mut Vec<usize>,
) {
    let mut left_index = 0;
    let mut right_index = 0;

    while left_index < left.len() && right_index < right.len() {
        let left_result = left[left_index].raw_result;
        let right_result = right[right_index].raw_result;
        let left_end = result_group_end(left, left_index);
        let right_end = result_group_end(right, right_index);

        match left_result.cmp(&right_result) {
            Ordering::Equal => {
                let exact_matches = (left_end - left_index).min(right_end - right_index);
                unmatched_left.extend(left_index + exact_matches..left_end);
                unmatched_right.extend(right_index + exact_matches..right_end);
                left_index = left_end;
                right_index = right_end;
            }
            Ordering::Less => {
                unmatched_left.extend(left_index..left_end);
                left_index = left_end;
            }
            Ordering::Greater => {
                unmatched_right.extend(right_index..right_end);
                right_index = right_end;
            }
        }
    }
    unmatched_left.extend(left_index..left.len());
    unmatched_right.extend(right_index..right.len());
}

fn result_group_end(rows: &[Row<'_>], start: usize) -> usize {
    let result = rows[start].raw_result;
    let mut end = start + 1;
    while end < rows.len() && rows[end].raw_result == result {
        end += 1;
    }
    end
}

fn emit_unmatched_changes<'a>(
    left: &[Row<'a>],
    right: &[Row<'a>],
    unmatched_left: &[usize],
    unmatched_right: &[usize],
    changes: &mut Vec<ObservedDelta<'a>>,
) -> Result<(), DiffError> {
    // A result change is a defensible one-to-one match only when one residual
    // record remains on each side after exact multiset matches. If several
    // same-signature calls remain, their identities are not available here.
    let paired = usize::from(unmatched_left.len() == 1 && unmatched_right.len() == 1);
    for index in 0..paired {
        let before = &left[unmatched_left[index]];
        let after = &right[unmatched_right[index]];
        let mut before_refs = one_reference(before)?;
        let mut after_refs = one_reference(after)?;
        // Keep vectors concretely owned in the serialized result while all text
        // remains borrowed from the source trace document.
        changes.push(ObservedDelta {
            kind: DeltaKind::Changed,
            category: before.category,
            record_kind: before.record_kind,
            syscall: before.syscall,
            raw_arguments: before.raw_arguments,
            before_lexical_path_hint: before.lexical_path_hint,
            after_lexical_path_hint: after.lexical_path_hint,
            before_result: before.raw_result,
            after_result: after.raw_result,
            before: std::mem::take(&mut before_refs),
            after: std::mem::take(&mut after_refs),
        });
    }

    emit_residuals(left, &unmatched_left[paired..], DeltaKind::Removed, changes)?;
    emit_residuals(right, &unmatched_right[paired..], DeltaKind::Added, changes)?;
    Ok(())
}

fn one_reference(row: &Row<'_>) -> Result<Vec<crate::model::EvidenceReference>, DiffError> {
    let mut refs = Vec::new();
    refs.try_reserve_exact(1)
        .map_err(|_| DiffError::AllocationFailed { requested: 1 })?;
    refs.push(row.evidence.clone());
    Ok(refs)
}

fn emit_residuals<'a>(
    rows: &[Row<'a>],
    residual_indices: &[usize],
    kind: DeltaKind,
    changes: &mut Vec<ObservedDelta<'a>>,
) -> Result<(), DiffError> {
    let mut start = 0;
    while start < residual_indices.len() {
        let first = &rows[residual_indices[start]];
        let mut end = start + 1;
        while end < residual_indices.len()
            && rows[residual_indices[end]].raw_result == first.raw_result
        {
            end += 1;
        }

        let mut references = Vec::new();
        references
            .try_reserve_exact(end - start)
            .map_err(|_| DiffError::AllocationFailed {
                requested: end - start,
            })?;
        references.extend(
            residual_indices[start..end]
                .iter()
                .map(|index| rows[*index].evidence.clone()),
        );

        let (before, after, before_result, after_result) = match kind {
            DeltaKind::Removed => (references, Vec::new(), first.raw_result, None),
            DeltaKind::Added => (Vec::new(), references, None, first.raw_result),
            DeltaKind::Changed => unreachable!("changed rows are emitted as pairs"),
        };
        changes.push(ObservedDelta {
            kind,
            category: first.category,
            record_kind: first.record_kind,
            syscall: first.syscall,
            raw_arguments: first.raw_arguments,
            before_lexical_path_hint: match kind {
                DeltaKind::Removed => consistent_group_hint(rows, &residual_indices[start..end]),
                DeltaKind::Added => None,
                DeltaKind::Changed => unreachable!("changed rows are emitted as pairs"),
            },
            after_lexical_path_hint: match kind {
                DeltaKind::Added => consistent_group_hint(rows, &residual_indices[start..end]),
                DeltaKind::Removed => None,
                DeltaKind::Changed => unreachable!("changed rows are emitted as pairs"),
            },
            before_result,
            after_result,
            before,
            after,
        });
        start = end;
    }
    Ok(())
}

fn consistent_group_hint<'a>(rows: &[Row<'a>], indices: &[usize]) -> Option<&'a LexicalPathHint> {
    let first = rows[indices.first().copied()?].lexical_path_hint;
    indices
        .iter()
        .all(|index| rows[*index].lexical_path_hint == first)
        .then_some(first)
        .flatten()
}

fn compare_deltas(left: &ObservedDelta<'_>, right: &ObservedDelta<'_>) -> Ordering {
    (
        left.category,
        left.syscall,
        left.raw_arguments,
        record_kind_rank(left.record_kind),
        left.before_result,
        left.after_result,
        delta_kind_rank(left.kind),
        first_offset(&left.before, &left.after),
    )
        .cmp(&(
            right.category,
            right.syscall,
            right.raw_arguments,
            record_kind_rank(right.record_kind),
            right.before_result,
            right.after_result,
            delta_kind_rank(right.kind),
            first_offset(&right.before, &right.after),
        ))
}

fn first_offset(
    before: &[crate::model::EvidenceReference],
    after: &[crate::model::EvidenceReference],
) -> u64 {
    before
        .first()
        .or_else(|| after.first())
        .map_or(u64::MAX, |reference| reference.byte_offset)
}

fn record_kind_rank(kind: TraceRecordKind) -> u8 {
    match kind {
        TraceRecordKind::Syscall => 0,
        TraceRecordKind::UnfinishedSyscall => 1,
        TraceRecordKind::ResumedSyscall => 2,
        TraceRecordKind::Control => 3,
        TraceRecordKind::Unparsed => 4,
    }
}

fn delta_kind_rank(kind: DeltaKind) -> u8 {
    match kind {
        DeltaKind::Added => 0,
        DeltaKind::Changed => 1,
        DeltaKind::Removed => 2,
    }
}

fn classify_syscall(syscall: &str) -> EventCategory {
    match syscall {
        "execve" | "execveat" | "clone" | "clone3" | "fork" | "vfork" | "wait4" | "waitid"
        | "exit" | "exit_group" | "getpid" | "getppid" | "gettid" => EventCategory::Process,
        "open" | "openat" | "openat2" | "creat" | "access" | "faccessat" | "faccessat2"
        | "stat" | "lstat" | "fstat" | "newfstatat" | "statx" | "readlink" | "readlinkat"
        | "unlink" | "unlinkat" | "rename" | "renameat" | "renameat2" | "mkdir" | "mkdirat"
        | "rmdir" | "link" | "linkat" | "symlink" | "symlinkat" | "chmod" | "fchmod"
        | "fchmodat" | "truncate" | "ftruncate" | "chown" | "lchown" | "fchownat" | "mknod"
        | "mknodat" => EventCategory::File,
        "socket" | "socketpair" | "connect" | "bind" | "listen" | "accept" | "accept4"
        | "sendto" | "recvfrom" | "sendmsg" | "recvmsg" | "sendmmsg" | "recvmmsg" | "shutdown"
        | "getsockname" | "getpeername" | "setsockopt" | "getsockopt" => EventCategory::Network,
        _ => EventCategory::Other,
    }
}
