use sideeffect::diff::{DiffError, compare_traces};
use sideeffect::limits::{MAX_DIFF_RECORDS, MAX_RECORDS};
use sideeffect::model::{
    CaptureCompleteness, DeltaKind, EventCategory, EvidenceReference, ParseCompleteness,
    TraceDocument, TraceRecord, TraceRecordKind,
};
use sideeffect::trace::strace::parse_trace_bytes;
use sideeffect::trace::{LexicalPathBasis, LexicalPathHint};

const BASELINE: &[u8] = include_bytes!("fixtures/diff/baseline.synthetic.trace");
const UPDATED: &[u8] = include_bytes!("fixtures/diff/updated.synthetic.trace");

fn parse(input: &[u8]) -> TraceDocument {
    parse_trace_bytes(input, Default::default()).unwrap()
}

#[test]
fn synthetic_pair_reports_observed_file_network_and_process_deltas_with_evidence() {
    let left = parse(BASELINE);
    let right = parse(UPDATED);
    let diff = compare_traces(&left, &right).unwrap();

    assert_eq!(diff.schema_version, 1);
    assert_eq!(diff.capture_completeness, CaptureCompleteness::Unknown);
    assert_eq!(
        diff.matching_policy.ignored_prefix_fields,
        ["process_id", "timestamp"]
    );
    assert_eq!(diff.matching_policy.multiplicity, "multiset");
    assert_eq!(diff.left_excluded_control_records, 1);
    assert_eq!(diff.right_excluded_control_records, 1);
    assert_eq!(diff.changes.len(), 4);

    let changed_open = diff
        .changes
        .iter()
        .find(|change| change.kind == DeltaKind::Changed && change.syscall == "openat")
        .unwrap();
    assert_eq!(changed_open.category, EventCategory::File);
    assert_eq!(
        changed_open.raw_arguments,
        "AT_FDCWD, \"/tmp/config.json\", O_RDONLY"
    );
    assert_eq!(changed_open.before_result, Some("3"));
    assert_eq!(
        changed_open.after_result,
        Some("-1 EACCES (Permission denied)")
    );
    assert_eq!(changed_open.before.len(), 1);
    assert_eq!(changed_open.after.len(), 1);
    assert_eq!(changed_open.before[0].line_number, 2);
    assert_eq!(changed_open.after[0].line_number, 2);
    assert_eq!(
        changed_open.before[0].byte_offset,
        BASELINE[..BASELINE.iter().position(|byte| *byte == b'\n').unwrap() + 1].len() as u64
    );

    let added_child = diff
        .changes
        .iter()
        .find(|change| change.kind == DeltaKind::Added && change.syscall == "execve")
        .unwrap();
    assert_eq!(added_child.category, EventCategory::Process);
    assert!(added_child.raw_arguments.contains("/usr/bin/helper"));
    assert!(added_child.before.is_empty());
    assert_eq!(added_child.after[0].line_number, 3);

    let connection_changes: Vec<_> = diff
        .changes
        .iter()
        .filter(|change| change.syscall == "connect")
        .collect();
    assert_eq!(connection_changes.len(), 2);
    let removed_old_destination = connection_changes
        .iter()
        .find(|change| change.kind == DeltaKind::Removed)
        .unwrap();
    let added_new_destination = connection_changes
        .iter()
        .find(|change| change.kind == DeltaKind::Added)
        .unwrap();
    assert_eq!(removed_old_destination.category, EventCategory::Network);
    assert!(
        removed_old_destination
            .raw_arguments
            .contains("203.0.113.7")
    );
    assert_eq!(removed_old_destination.before[0].line_number, 3);
    assert_eq!(added_new_destination.category, EventCategory::Network);
    assert!(added_new_destination.raw_arguments.contains("203.0.113.8"));
    assert_eq!(added_new_destination.after[0].line_number, 4);
}

#[test]
fn timestamp_and_pid_prefix_changes_do_not_create_deltas() {
    let left =
        parse(b"10 1700000000.000001 statx(AT_FDCWD, \"/tmp/item\", 0, STATX_ALL, 0x1) = 0\n");
    let right =
        parse(b"9999 1800000000.999999 statx(AT_FDCWD, \"/tmp/item\", 0, STATX_ALL, 0x1) = 0\n");

    let diff = compare_traces(&left, &right).unwrap();
    assert!(diff.changes.is_empty());
    assert_eq!(left.records[0].process_id, Some(10));
    assert_eq!(right.records[0].process_id, Some(9999));
    assert_ne!(left.records[0].timestamp, right.records[0].timestamp);
    assert_ne!(left.records[0].raw_line, right.records[0].raw_line);
}

#[test]
fn diff_matching_ignores_derived_lexical_hints_and_keeps_raw_arguments_authoritative() {
    let input = b"10 1700000000.000001 openat(AT_FDCWD</work>, \"file.txt\", O_RDONLY) = 3\n";
    let left = parse(input);
    let mut right = parse(input);
    right.records[0].lexical_path_hint = Some(LexicalPathHint {
        path: "/different/derived/value".to_owned(),
        basis: LexicalPathBasis::AbsoluteArgument,
    });

    assert_eq!(
        left.records[0].raw_arguments,
        right.records[0].raw_arguments
    );
    assert!(compare_traces(&left, &right).unwrap().changes.is_empty());
}

#[test]
fn multiplicity_is_compared_as_a_multiset() {
    let left = parse(
        b"1 1700000000.000001 openat(AT_FDCWD, \"/tmp/item\", O_RDONLY) = 3\n1 1700000000.000002 openat(AT_FDCWD, \"/tmp/item\", O_RDONLY) = 3\n",
    );
    let right = parse(b"2 1800000000.000001 openat(AT_FDCWD, \"/tmp/item\", O_RDONLY) = 3\n");

    let diff = compare_traces(&left, &right).unwrap();
    assert_eq!(diff.changes.len(), 1);
    let removed = &diff.changes[0];
    assert_eq!(removed.kind, DeltaKind::Removed);
    assert_eq!(removed.syscall, "openat");
    assert_eq!(removed.before_result, Some("3"));
    assert_eq!(removed.before.len(), 1);
    assert!(removed.after.is_empty());
    assert_eq!(removed.before[0].line_number, 2);
}

#[test]
fn changed_arguments_are_not_normalized_or_paired_as_result_changes() {
    let left = parse(b"1 1700000000.000001 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"203.0.113.7\")}, 16) = 0\n");
    let right = parse(b"2 1800000000.000001 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"203.0.113.7\")}, 16) = 0\n");

    let diff = compare_traces(&left, &right).unwrap();
    assert_eq!(diff.changes.len(), 2);
    assert!(
        diff.changes
            .iter()
            .any(|change| change.kind == DeltaKind::Removed)
    );
    assert!(
        diff.changes
            .iter()
            .any(|change| change.kind == DeltaKind::Added)
    );
    assert!(
        diff.changes
            .iter()
            .all(|change| change.kind != DeltaKind::Changed)
    );
}

#[test]
fn pid_like_syscall_results_remain_exact_changed_values() {
    let left = parse(b"10 1700000000.000001 getpid() = 101\n");
    let right = parse(b"20 1800000000.000001 getpid() = 202\n");

    let diff = compare_traces(&left, &right).unwrap();
    assert_eq!(diff.changes.len(), 1);
    let changed = &diff.changes[0];
    assert_eq!(changed.kind, DeltaKind::Changed);
    assert_eq!(changed.category, EventCategory::Process);
    assert_eq!(changed.raw_arguments, "");
    assert_eq!(changed.before_result, Some("101"));
    assert_eq!(changed.after_result, Some("202"));
}

#[test]
fn ambiguous_duplicate_result_changes_remain_added_and_removed() {
    let left = parse(b"10 1700000000.000001 getpid() = 101\n10 1700000000.000002 getpid() = 102\n");
    let right =
        parse(b"20 1800000000.000001 getpid() = 201\n20 1800000000.000002 getpid() = 202\n");

    let diff = compare_traces(&left, &right).unwrap();
    assert_eq!(diff.changes.len(), 4);
    assert!(
        diff.changes
            .iter()
            .all(|change| change.kind != DeltaKind::Changed)
    );
    assert_eq!(
        diff.changes
            .iter()
            .filter(|change| change.kind == DeltaKind::Removed)
            .count(),
        2
    );
    assert_eq!(
        diff.changes
            .iter()
            .filter(|change| change.kind == DeltaKind::Added)
            .count(),
        2
    );
}

#[test]
fn continuation_rows_remain_separate_observations() {
    let left = parse(
        b"7 1700000000.000001 read(3,  <unfinished ...>\n7 1700000000.000002 <... read resumed> \"x\", 1) = 1\n",
    );
    let right = parse(
        b"8 1800000000.000001 read(3,  <unfinished ...>\n8 1800000000.000002 <... read resumed> \"x\", 1) = 1\n",
    );

    let diff = compare_traces(&left, &right).unwrap();
    assert!(diff.changes.is_empty());
}

#[test]
fn partial_documents_and_inconsistent_complete_documents_fail_closed() {
    let mut partial = parse(b"close(3) = 0\n");
    partial.parse_status = ParseCompleteness::Partial;
    assert!(matches!(
        compare_traces(&partial, &parse(b"close(3) = 0\n")),
        Err(DiffError::PartialParse { .. })
    ));

    let mut inconsistent = parse(b"close(3) = 0\n");
    inconsistent
        .diagnostics
        .push(sideeffect::model::TraceDiagnostic {
            code: "unexpected".to_owned(),
            line_number: 1,
            byte_offset: 0,
            message: "diagnostic on complete document".to_owned(),
        });
    assert!(matches!(
        compare_traces(&inconsistent, &parse(b"close(3) = 0\n")),
        Err(DiffError::InconsistentDocument { .. })
    ));
}

#[test]
fn syscall_name_buckets_are_explicit_and_conservative() {
    let file = parse(b"1 1700000000.000001 openat(AT_FDCWD, \"/tmp/x\", O_RDONLY) = 3\n");
    let network = parse(b"1 1700000000.000001 connect(4, {sa_family=AF_INET}, 16) = 0\n");
    let process = parse(b"1 1700000000.000001 execve(\"/bin/x\", [\"x\"], 0x0) = 0\n");
    let ambiguous_io = parse(b"1 1700000000.000001 write(1, \"x\", 1) = 1\n");

    let category = |document: &TraceDocument| {
        compare_traces(document, &parse(b""))
            .unwrap()
            .changes
            .first()
            .map(|delta| delta.category)
    };
    assert_eq!(category(&file), Some(EventCategory::File));
    assert_eq!(category(&network), Some(EventCategory::Network));
    assert_eq!(category(&process), Some(EventCategory::Process));
    assert_eq!(category(&ambiguous_io), Some(EventCategory::Other));
}

#[test]
fn ordering_is_stable_when_independent_events_are_interleaved_differently() {
    let left_a = parse(
        b"1 1700000000.000001 connect(4, {addr=\"203.0.113.1\"}, 16) = 0\n1 1700000000.000002 openat(AT_FDCWD, \"/tmp/a\", O_RDONLY) = 3\n1 1700000000.000003 execve(\"/bin/x\", [\"x\"], 0x0) = 0\n",
    );
    let right_a = parse(
        b"2 1800000000.000001 connect(4, {addr=\"203.0.113.2\"}, 16) = 0\n2 1800000000.000002 openat(AT_FDCWD, \"/tmp/a\", O_RDONLY) = -1 EACCES (Permission denied)\n2 1800000000.000003 execve(\"/bin/y\", [\"y\"], 0x0) = 0\n",
    );
    let left_b = parse(
        b"1 1700000000.000003 execve(\"/bin/x\", [\"x\"], 0x0) = 0\n1 1700000000.000001 connect(4, {addr=\"203.0.113.1\"}, 16) = 0\n1 1700000000.000002 openat(AT_FDCWD, \"/tmp/a\", O_RDONLY) = 3\n",
    );
    let right_b = parse(
        b"2 1800000000.000003 execve(\"/bin/y\", [\"y\"], 0x0) = 0\n2 1800000000.000001 connect(4, {addr=\"203.0.113.2\"}, 16) = 0\n2 1800000000.000002 openat(AT_FDCWD, \"/tmp/a\", O_RDONLY) = -1 EACCES (Permission denied)\n",
    );

    let first = compare_traces(&left_a, &right_a).unwrap();
    let second = compare_traces(&left_b, &right_b).unwrap();
    assert_eq!(project(&first), project(&second));
}

#[test]
fn combined_record_budget_accepts_exact_limit_and_rejects_limit_plus_one() {
    let left = control_document(MAX_RECORDS);
    let right = control_document(MAX_RECORDS);
    let exact = compare_traces(&left, &right).unwrap();
    assert!(exact.changes.is_empty());
    assert_eq!(exact.left_excluded_control_records, MAX_RECORDS as u64);
    assert_eq!(exact.right_excluded_control_records, MAX_RECORDS as u64);

    let oversized_left = control_document(MAX_RECORDS + 1);
    assert_eq!(
        compare_traces(&oversized_left, &right),
        Err(DiffError::TooManyRecords {
            actual: MAX_DIFF_RECORDS + 1,
            maximum: MAX_DIFF_RECORDS,
        })
    );
}

#[test]
fn combined_input_byte_budget_accepts_exact_limit_and_rejects_limit_plus_one() {
    let mut left = control_document(0);
    let mut right = control_document(0);
    let half = (sideeffect::limits::MAX_DIFF_INPUT_BYTES / 2) as u64;
    left.input_bytes = half;
    right.input_bytes = (sideeffect::limits::MAX_DIFF_INPUT_BYTES as u64) - half;

    assert!(compare_traces(&left, &right).is_ok());
    right.input_bytes += 1;
    assert_eq!(
        compare_traces(&left, &right),
        Err(DiffError::InputTooLarge {
            actual_bytes: sideeffect::limits::MAX_DIFF_INPUT_BYTES as u64 + 1,
            maximum_bytes: sideeffect::limits::MAX_DIFF_INPUT_BYTES,
        })
    );
}

fn control_document(count: usize) -> TraceDocument {
    let records = (0..count)
        .map(|index| TraceRecord {
            kind: TraceRecordKind::Control,
            evidence: EvidenceReference {
                line_number: index as u64 + 1,
                byte_offset: index as u64 * 10,
                byte_length: 9,
            },
            raw_line: "+++ exited +++".to_owned(),
            process_id: Some(1),
            timestamp: None,
            syscall: None,
            raw_arguments: None,
            raw_result: None,
            lexical_path_hint: None,
        })
        .collect();
    TraceDocument {
        schema_version: 1,
        source_format: "synthetic_fixture".to_owned(),
        input_bytes: 0,
        parse_status: ParseCompleteness::Complete,
        records,
        diagnostics: Vec::new(),
    }
}

fn project<'a>(diff: &sideeffect::model::TraceDiff<'a>) -> Vec<DeltaProjection<'a>> {
    diff.changes
        .iter()
        .map(|change| {
            (
                change.kind,
                change.category,
                change.record_kind,
                change.syscall,
                change.raw_arguments,
                change.before_result,
                change.after_result,
            )
        })
        .collect()
}

type DeltaProjection<'a> = (
    DeltaKind,
    EventCategory,
    TraceRecordKind,
    &'a str,
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
);
