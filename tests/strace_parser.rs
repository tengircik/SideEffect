use sideeffect::limits::{MAX_RECORD_BYTES, MAX_RECORDS, ParseLimits};
use sideeffect::model::{ParseCompleteness, SyscallOutcome, TraceRecordKind};
use sideeffect::trace::strace::{ParseError, parse_trace_bytes};

fn limits(max_trace_bytes: usize, max_record_bytes: usize, max_records: usize) -> ParseLimits {
    ParseLimits {
        max_trace_bytes,
        max_record_bytes,
        max_records,
    }
}

#[test]
fn parses_the_labeled_synthetic_trace_fixture() {
    let input = include_bytes!("fixtures/strace/synthetic-minimal.trace");
    let document = parse_trace_bytes(input, ParseLimits::default()).unwrap();

    assert_eq!(document.parse_status, ParseCompleteness::Complete);
    assert_eq!(document.records.len(), 6);
    assert_eq!(document.records[0].syscall.as_deref(), Some("execve"));
    assert_eq!(document.records[1].syscall.as_deref(), Some("openat"));
    assert_eq!(document.records[2].syscall.as_deref(), Some("socket"));
    assert_eq!(document.records[3].syscall.as_deref(), Some("connect"));
    assert!(
        document.records[3]
            .raw_result
            .as_deref()
            .unwrap()
            .contains("ECONNREFUSED")
    );
    assert!(document.records[0].raw_line.contains("sideeffect-demo"));
}

#[test]
fn parses_pid_timestamp_nested_arguments_and_fd_annotations() {
    let input = b"123 1700000000.123456 ioctl(5</tmp/with)name>, 0x123, {a=[1, 2], b=\"quoted \\\"text\\\" (safe)\"}) = 0\n";

    let document = parse_trace_bytes(input, ParseLimits::default()).unwrap();
    assert_eq!(document.parse_status, ParseCompleteness::Complete);
    assert_eq!(document.records.len(), 1);

    let record = &document.records[0];
    assert_eq!(record.kind, TraceRecordKind::Syscall);
    assert_eq!(record.process_id, Some(123));
    assert_eq!(record.timestamp.as_deref(), Some("1700000000.123456"));
    assert_eq!(record.syscall.as_deref(), Some("ioctl"));
    assert_eq!(
        record.raw_arguments.as_deref(),
        Some("5</tmp/with)name>, 0x123, {a=[1, 2], b=\"quoted \\\"text\\\" (safe)\"}")
    );
    assert_eq!(record.raw_result.as_deref(), Some("0"));
    assert_eq!(record.evidence.byte_offset, 0);
    assert_eq!(record.evidence.byte_length, input.len() as u64 - 1);
    assert_eq!(record.raw_line.as_bytes(), &input[..input.len() - 1]);
}

#[test]
fn parses_tcp_peer_arrow_inside_strace_fd_annotation() {
    let input = b"123 1700000000.123456 getsockname(3<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, {sa_family=AF_INET, sin_port=htons(42000), sin_addr=inet_addr(\"127.0.0.1\")}, [16]) = 0\n";

    let document = parse_trace_bytes(input, ParseLimits::default()).unwrap();
    assert_eq!(document.parse_status, ParseCompleteness::Complete);
    assert_eq!(document.records.len(), 1);
    let record = &document.records[0];
    assert_eq!(record.syscall.as_deref(), Some("getsockname"));
    assert_eq!(
        record.raw_arguments.as_deref(),
        Some(
            "3<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, {sa_family=AF_INET, sin_port=htons(42000), sin_addr=inet_addr(\"127.0.0.1\")}, [16]"
        )
    );
    assert_eq!(record.raw_result.as_deref(), Some("0"));
}

#[test]
fn legacy_openat_text_without_yy_annotations_remains_inspectable_in_schema_v4() {
    let input = b"123 1700000000.123456 openat(AT_FDCWD, \"relative/file.txt\", O_RDONLY) = 3\n";

    let document = parse_trace_bytes(input, ParseLimits::default()).unwrap();
    assert_eq!(
        document.schema_version,
        sideeffect::model::TRACE_DOCUMENT_SCHEMA_VERSION
    );
    assert_eq!(document.parse_status, ParseCompleteness::Complete);
    assert_eq!(
        document.records[0].raw_arguments.as_deref(),
        Some("AT_FDCWD, \"relative/file.txt\", O_RDONLY")
    );
    assert!(document.records[0].lexical_path_hint.is_none());
    assert_eq!(
        document.source_sha256,
        "b73a1d5fb794a28ef14fa5b71cad35afe38ae9c24c66a2ebc1e2cd27a4f92ca4"
    );
}

#[test]
fn classifies_only_selected_complete_syscalls_from_strict_results() {
    let input = concat!(
        "1 execve(\"/bin/tool\", [\"tool\"], 0x0) = 0\n",
        "1 execveat(3, \"tool\", [\"tool\"], 0x0, 0) = -1 ENOENT (No such file or directory)\n",
        "1 openat(AT_FDCWD, \"/tmp/file\", O_RDONLY) = 3</tmp/file>\n",
        "1 openat2(AT_FDCWD, \"/tmp/file\", {flags=O_RDONLY}, 24) = -1 EACCES (Permission denied)\n",
        "1 connect(3, {sa_family=AF_INET}, 16) = -1 EINPROGRESS (Operation now in progress)\n",
        "1 connect(3, {sa_family=AF_INET}, 16) = 0\n",
        "1 connect(3, {sa_family=AF_INET}, 16) = -1 ERESTARTSYS (restart_syscall)\n",
        "1 connect(3, {sa_family=AF_INET}, 16) = -1 ENOT_A_REAL_ERRNO (not recognized)\n",
        "1 connect(3, {sa_family=AF_INET}, 16) = -1 ECONNREFUSED\n",
        "1 read(3, \"x\", 1) = 1\n",
    );
    let document = parse_trace_bytes(input.as_bytes(), ParseLimits::default()).unwrap();
    assert_eq!(document.parse_status, ParseCompleteness::Complete);

    let outcomes: Vec<_> = document
        .records
        .iter()
        .map(|record| record.outcome)
        .collect();
    assert_eq!(
        outcomes,
        [
            Some(SyscallOutcome::Success),
            Some(SyscallOutcome::Failure),
            Some(SyscallOutcome::Success),
            Some(SyscallOutcome::Failure),
            Some(SyscallOutcome::InProgress),
            Some(SyscallOutcome::Success),
            Some(SyscallOutcome::Unknown),
            Some(SyscallOutcome::Unknown),
            Some(SyscallOutcome::Unknown),
            None,
        ]
    );

    let open = &document.records[2];
    assert_eq!(open.raw_result.as_deref(), Some("3</tmp/file>"));
    assert_eq!(
        open.raw_line,
        "1 openat(AT_FDCWD, \"/tmp/file\", O_RDONLY) = 3</tmp/file>"
    );
    assert_eq!(open.evidence.line_number, 3);
    assert_eq!(open.evidence.byte_length, open.raw_line.len() as u64);
}

#[test]
fn outcome_is_omitted_for_unlisted_and_continuation_records() {
    let input = concat!(
        "1 execve(\"/bin/tool\", [\"tool\"], 0x0 <unfinished ...>\n",
        "1 <... execve resumed>\"/bin/tool\", [\"tool\"], 0x0) = 0\n",
        "1 socket(AF_INET, SOCK_STREAM, 0) = 3\n",
        "1 openat(AT_FDCWD, \"x\", O_RDONLY) = 3 trailing\n",
        "1 connect(3, {}, 0) = -1 EINVAL (Invalid argument) extra\n",
    );
    let document = parse_trace_bytes(input.as_bytes(), ParseLimits::default()).unwrap();
    assert_eq!(document.parse_status, ParseCompleteness::Complete);
    assert_eq!(document.records[0].kind, TraceRecordKind::UnfinishedSyscall);
    assert_eq!(document.records[1].kind, TraceRecordKind::ResumedSyscall);
    assert_eq!(document.records[0].outcome, None);
    assert_eq!(document.records[1].outcome, None);
    assert_eq!(document.records[2].outcome, None);
    assert_eq!(document.records[3].outcome, Some(SyscallOutcome::Unknown));
    assert_eq!(document.records[4].outcome, Some(SyscallOutcome::Unknown));
}

#[test]
fn tcp_peer_arrow_does_not_accept_a_missing_outer_annotation_close() {
    let input = b"123 1700000000.123456 getsockname(3<TCP:[127.0.0.1:41000->127.0.0.1:42000], {sa_family=AF_INET}, [16]) = 0\n";

    let document = parse_trace_bytes(input, ParseLimits::default()).unwrap();
    assert_eq!(document.parse_status, ParseCompleteness::Partial);
    assert_eq!(document.records[0].kind, TraceRecordKind::Unparsed);
    assert!(document.diagnostics[0].message.contains("unterminated"));
}

#[test]
fn tcp_annotation_outer_close_does_not_hide_a_missing_inner_bracket() {
    let input = b"123 1700000000.123456 getsockname(3<TCP:[127.0.0.1:41000->127.0.0.1:42000>, {sa_family=AF_INET}, [16]) = 0\n";

    let document = parse_trace_bytes(input, ParseLimits::default()).unwrap();
    assert_eq!(document.parse_status, ParseCompleteness::Partial);
    assert_eq!(document.records[0].kind, TraceRecordKind::Unparsed);
    assert!(document.diagnostics[0].message.contains("unterminated"));
}

#[test]
fn accepts_bracketed_pid_and_failed_syscall_result() {
    let input = b"[pid 44] 1700000001.000002 openat(AT_FDCWD, \"/tmp/missing\", O_RDONLY) = -1 ENOENT (No such file or directory)\n";

    let document = parse_trace_bytes(input, ParseLimits::default()).unwrap();
    let record = &document.records[0];
    assert_eq!(record.kind, TraceRecordKind::Syscall);
    assert_eq!(record.process_id, Some(44));
    assert_eq!(record.syscall.as_deref(), Some("openat"));
    assert_eq!(
        record.raw_result.as_deref(),
        Some("-1 ENOENT (No such file or directory)")
    );
}

#[test]
fn retains_control_unfinished_and_resumed_records() {
    let input = concat!(
        "strace: Process 50 attached\n",
        "50 1700000002.000001 read(3,  <unfinished ...>\n",
        "50 1700000002.000002 <... read resumed> \"a) = b\", 3) = 3\n",
        "50 1700000002.000003 +++ exited with 0 +++\n",
        "50 1700000002.000004 --- SIGCHLD {si_signo=SIGCHLD} ---\n",
    );

    let document = parse_trace_bytes(input.as_bytes(), ParseLimits::default()).unwrap();
    assert_eq!(document.parse_status, ParseCompleteness::Complete);
    assert_eq!(document.records[0].kind, TraceRecordKind::Control);
    assert_eq!(document.records[1].kind, TraceRecordKind::UnfinishedSyscall);
    assert_eq!(document.records[1].syscall.as_deref(), Some("read"));
    assert_eq!(document.records[1].raw_arguments.as_deref(), Some("3,  "));
    assert_eq!(document.records[2].kind, TraceRecordKind::ResumedSyscall);
    assert_eq!(document.records[2].syscall.as_deref(), Some("read"));
    assert_eq!(
        document.records[2].raw_arguments.as_deref(),
        Some(" \"a) = b\", 3")
    );
    assert_eq!(document.records[2].raw_result.as_deref(), Some("3"));
    assert_eq!(document.records[3].kind, TraceRecordKind::Control);
    assert_eq!(document.records[4].kind, TraceRecordKind::Control);
}

#[test]
fn malformed_and_unsupported_lines_are_retained_as_partial_evidence() {
    let input = concat!(
        "12 1700000003.000001 openat(AT_FDCWD, \"/tmp/x\", O_RDONLY = 3\n",
        "this is not a strace record\n",
        "12 1700000003.000002 close(4) = 0\n",
    );

    let document = parse_trace_bytes(input.as_bytes(), ParseLimits::default()).unwrap();
    assert_eq!(document.parse_status, ParseCompleteness::Partial);
    assert_eq!(document.records.len(), 3);
    assert_eq!(document.records[0].kind, TraceRecordKind::Unparsed);
    assert_eq!(document.records[1].kind, TraceRecordKind::Unparsed);
    assert_eq!(document.records[1].raw_line, "this is not a strace record");
    assert_eq!(document.records[2].kind, TraceRecordKind::Syscall);
    assert_eq!(document.diagnostics.len(), 2);
    assert_eq!(document.diagnostics[0].code, "malformed_record");
    assert_eq!(document.diagnostics[1].code, "unsupported_record");
    assert_eq!(document.diagnostics[0].byte_offset, 0);
    assert_eq!(
        document.diagnostics[1].byte_offset,
        (input.lines().next().unwrap().len() + 1) as u64
    );
}

#[test]
fn records_preserve_exact_offsets_and_crlf_bytes() {
    let input = b"1 1700000004.000001 close(3) = 0\r\n2 1700000004.000002 close(4) = 0\r\n";
    let document = parse_trace_bytes(input, ParseLimits::default()).unwrap();

    assert_eq!(document.records.len(), 2);
    assert_eq!(
        document.records[0].raw_line,
        "1 1700000004.000001 close(3) = 0\r"
    );
    assert_eq!(document.records[0].evidence.byte_length, 33);
    assert_eq!(document.records[1].evidence.byte_offset, 34);
    assert_eq!(document.records[1].evidence.line_number, 2);
}

#[test]
fn invalid_utf8_is_a_hard_error_with_byte_offset() {
    let input = b"close(3) = 0\n\xff";
    assert_eq!(
        parse_trace_bytes(input, ParseLimits::default()),
        Err(ParseError::InvalidUtf8 { byte_offset: 13 })
    );
}

#[test]
fn trace_size_limit_is_enforced_at_and_beyond_boundary() {
    let input = b"close(3) = 0\n";
    assert!(parse_trace_bytes(input, limits(input.len(), 64, 1)).is_ok());
    assert_eq!(
        parse_trace_bytes(input, limits(input.len() - 1, 64, 1)),
        Err(ParseError::InputTooLarge {
            actual_bytes: input.len(),
            maximum_bytes: input.len() - 1,
        })
    );
}

#[test]
fn physical_record_size_limit_is_enforced_at_and_beyond_boundary() {
    let input = b"close(3) = 0\n";
    let record_bytes = input.len() - 1;
    assert!(parse_trace_bytes(input, limits(input.len(), record_bytes, 1)).is_ok());
    assert_eq!(
        parse_trace_bytes(input, limits(input.len(), record_bytes - 1, 1)),
        Err(ParseError::RecordTooLarge {
            line_number: 1,
            byte_offset: 0,
            actual_bytes: record_bytes,
            maximum_bytes: record_bytes - 1,
        })
    );
}

#[test]
fn configured_record_size_limit_accepts_exactly_max_bytes() {
    let mut record = b"close(3".to_vec();
    record.resize(MAX_RECORD_BYTES - b") = 0".len(), b' ');
    record.extend_from_slice(b") = 0");

    let document = parse_trace_bytes(&record, ParseLimits::default()).unwrap();
    assert_eq!(record.len(), MAX_RECORD_BYTES);
    assert_eq!(document.parse_status, ParseCompleteness::Complete);
    assert_eq!(document.records.len(), 1);
    assert_eq!(document.records[0].kind, TraceRecordKind::Syscall);
    assert_eq!(
        document.records[0].evidence.byte_length,
        MAX_RECORD_BYTES as u64
    );

    record.push(b' ');
    assert_eq!(
        parse_trace_bytes(&record, ParseLimits::default()),
        Err(ParseError::RecordTooLarge {
            line_number: 1,
            byte_offset: 0,
            actual_bytes: MAX_RECORD_BYTES + 1,
            maximum_bytes: MAX_RECORD_BYTES,
        })
    );
}

#[test]
fn within_limit_unterminated_fd_annotation_is_retained_as_malformed() {
    let prefix = b"1 1700000008.000001 close(";
    let mut line = prefix.to_vec();
    line.resize(MAX_RECORD_BYTES, b'<');
    line.push(b'\n');

    let document = parse_trace_bytes(&line, ParseLimits::default()).unwrap();

    assert_eq!(document.parse_status, ParseCompleteness::Partial);
    assert_eq!(document.records[0].kind, TraceRecordKind::Unparsed);
    assert_eq!(document.diagnostics.len(), 1);
    assert_eq!(document.diagnostics[0].code, "malformed_record");
    assert!(
        document.diagnostics[0]
            .message
            .contains("unterminated file descriptor annotation")
    );
}

#[test]
fn within_limit_unterminated_resumed_annotation_is_retained_as_malformed() {
    let prefix = b"1 1700000008.000001 <... read resumed> ";
    let mut line = prefix.to_vec();
    line.resize(MAX_RECORD_BYTES, b'<');
    line.push(b'\n');

    let document = parse_trace_bytes(&line, ParseLimits::default()).unwrap();

    assert_eq!(document.parse_status, ParseCompleteness::Partial);
    assert_eq!(document.records[0].kind, TraceRecordKind::Unparsed);
    assert_eq!(document.diagnostics.len(), 1);
    assert_eq!(document.diagnostics[0].code, "malformed_record");
    assert!(
        document.diagnostics[0]
            .message
            .contains("unterminated file descriptor annotation")
    );
}

#[test]
fn record_count_limit_is_enforced_without_silent_truncation() {
    let input = b"close(3) = 0\nclose(4) = 0\n";
    assert_eq!(
        parse_trace_bytes(input, limits(input.len(), 64, 1)),
        Err(ParseError::TooManyRecords {
            line_number: 2,
            maximum_records: 1,
        })
    );
    assert_eq!(
        parse_trace_bytes(b"close(3) = 0\n", limits(64, 64, 1))
            .unwrap()
            .records
            .len(),
        1
    );
}

#[test]
fn configured_record_count_limit_accepts_exactly_max_records() {
    let row = b"close(3) = 0\n";
    let mut input = Vec::with_capacity(row.len() * (MAX_RECORDS + 1));
    for _ in 0..MAX_RECORDS {
        input.extend_from_slice(row);
    }

    let document = parse_trace_bytes(&input, ParseLimits::default()).unwrap();
    assert_eq!(document.records.len(), MAX_RECORDS);
    assert_eq!(document.parse_status, ParseCompleteness::Complete);

    input.extend_from_slice(row);
    assert_eq!(
        parse_trace_bytes(&input, ParseLimits::default()),
        Err(ParseError::TooManyRecords {
            line_number: (MAX_RECORDS + 1) as u64,
            maximum_records: MAX_RECORDS,
        })
    );
}

#[test]
fn empty_input_and_final_newline_do_not_create_phantom_records() {
    let empty = parse_trace_bytes(b"", ParseLimits::default()).unwrap();
    assert!(empty.records.is_empty());
    assert_eq!(empty.parse_status, ParseCompleteness::Complete);

    let one_line = parse_trace_bytes(b"close(3) = 0\n", ParseLimits::default()).unwrap();
    assert_eq!(one_line.records.len(), 1);
}

#[test]
fn unfinished_at_end_of_trace_marks_parse_partial() {
    let input = b"70 1700000005.000001 read(3,  <unfinished ...>\n";
    let document = parse_trace_bytes(input, ParseLimits::default()).unwrap();

    assert_eq!(document.parse_status, ParseCompleteness::Partial);
    assert_eq!(document.records[0].kind, TraceRecordKind::UnfinishedSyscall);
    assert_eq!(document.diagnostics.len(), 1);
    assert_eq!(document.diagnostics[0].code, "unfinished_syscall_at_eof");
}

#[test]
fn orphan_and_pid_or_syscall_mismatched_resumes_are_partial() {
    let input = concat!(
        "70 1700000006.000001 read(3,  <unfinished ...>\n",
        "71 1700000006.000002 <... read resumed> \"x\", 1) = 1\n",
        "70 1700000006.000003 <... write resumed> 1, \"x\", 1) = 1\n",
        "72 1700000006.000004 <... close resumed> 4) = 0\n",
    );
    let document = parse_trace_bytes(input.as_bytes(), ParseLimits::default()).unwrap();

    assert_eq!(document.parse_status, ParseCompleteness::Partial);
    assert!(document.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "orphan_resumed_syscall" && diagnostic.line_number == 2
    }));
    assert!(document.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "orphan_resumed_syscall" && diagnostic.line_number == 3
    }));
    assert!(document.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "orphan_resumed_syscall" && diagnostic.line_number == 4
    }));
    assert!(document.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "unfinished_syscall_at_eof" && diagnostic.line_number == 1
    }));
}

#[test]
fn continuations_without_pids_are_not_guessed_as_pairs() {
    let input = concat!(
        "1700000007.000001 read(3,  <unfinished ...>\n",
        "1700000007.000002 <... read resumed> \"x\", 1) = 1\n",
    );
    let document = parse_trace_bytes(input.as_bytes(), ParseLimits::default()).unwrap();

    assert_eq!(document.parse_status, ParseCompleteness::Partial);
    assert!(document.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "ambiguous_unfinished_syscall" && diagnostic.line_number == 1
    }));
    assert!(document.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "ambiguous_resumed_syscall" && diagnostic.line_number == 2
    }));
}
