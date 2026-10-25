//! Conservative direct process-creation relations derived from parsed strace rows.
//!
//! This helper does not identify a capture root, build a complete tree, infer
//! PID generations, or attribute unrelated rows. A returned relation means
//! only that one complete successful process-creation syscall row reported the
//! child PID and the row's caller PID.

use crate::model::{EvidenceReference, TraceRecord, TraceRecordKind};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Bound work even when this helper is called independently of the trace parser.
pub const MAX_LINEAGE_INPUT_RECORDS: usize = 100_000;
/// Bound the number of candidate relations retained while resolving duplicate
/// child-PID claims.
pub const MAX_PROCESS_RELATIONS: usize = 50_000;
/// Bound diagnostics while ensuring their truncation remains explicit.
pub const MAX_LINEAGE_DIAGNOSTICS: usize = 256;

const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_PARENT: u64 = 0x0000_8000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessRelation {
    pub parent_pid: u32,
    pub child_pid: u32,
    /// Exact result row for a successful fork/vfork/clone syscall.
    pub evidence: EvidenceReference,
    /// Additional source rows needed to interpret a split syscall, such as
    /// clone flags retained on an unfinished row before its resumed result.
    pub supporting_evidence: Vec<EvidenceReference>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessLineageDiagnostic {
    pub code: &'static str,
    pub evidence: Option<EvidenceReference>,
    pub message: &'static str,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ProcessLineage {
    /// Direct relations only. No transitive ancestry is calculated.
    pub relations: Vec<ProcessRelation>,
    /// Incomplete or ambiguous source rows are reported here rather than used
    /// to guess a relation.
    pub diagnostics: Vec<ProcessLineageDiagnostic>,
    /// True when any relevant row or configured bound made the result partial.
    pub partial: bool,
    /// True if the diagnostic cap prevented retaining every diagnostic.
    pub diagnostics_truncated: bool,
}

#[derive(Clone)]
struct Candidate {
    relation: ProcessRelation,
}

/// Derive direct parent-to-child relations from successful complete creation
/// calls. Only exact decimal positive child PIDs are accepted. For clone calls,
/// a fully understood flags value is required and `CLONE_THREAD` calls are
/// explicitly excluded.
pub fn derive_process_lineage(records: &[TraceRecord]) -> ProcessLineage {
    let mut result = ProcessLineage {
        relations: Vec::new(),
        diagnostics: Vec::new(),
        partial: false,
        diagnostics_truncated: false,
    };
    let mut candidates = Vec::new();
    let scan_count = records.len().min(MAX_LINEAGE_INPUT_RECORDS);

    // Pair only an unambiguous earlier unfinished row with its resumed result.
    // The parser applies the same PID/syscall matching rule for continuation
    // validation; retaining both rows keeps the derived edge auditable.
    let mut pending: BTreeMap<(u32, String), VecDeque<usize>> = BTreeMap::new();
    let mut resumed_from = BTreeMap::new();
    let mut paired_unfinished = BTreeSet::new();
    for (index, record) in records[..scan_count].iter().enumerate() {
        let Some(syscall) = record.syscall.as_deref() else {
            continue;
        };
        if !is_process_creation(syscall) {
            continue;
        }
        let Some(pid) = record.process_id else {
            continue;
        };
        let key = (pid, syscall.to_owned());
        match record.kind {
            TraceRecordKind::UnfinishedSyscall => {
                pending.entry(key).or_default().push_back(index);
            }
            TraceRecordKind::ResumedSyscall => {
                if let Some(indices) = pending.get_mut(&key) {
                    if indices.len() == 1 {
                        if let Some(unfinished_index) = indices.pop_front() {
                            resumed_from.insert(index, unfinished_index);
                            paired_unfinished.insert(unfinished_index);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if records.len() > scan_count {
        add_diagnostic(
            &mut result,
            "input_record_limit",
            None,
            "lineage derivation stopped at its input record limit",
        );
    }

    for (index, record) in records[..scan_count].iter().enumerate() {
        let Some(syscall) = record.syscall.as_deref() else {
            continue;
        };
        let is_clone = syscall == "clone" || syscall.starts_with("clone");
        let is_creation = is_process_creation(syscall);
        if !is_creation {
            continue;
        }

        let paired_arguments = resumed_from
            .get(&index)
            .map(|unfinished_index| records[*unfinished_index].raw_arguments.as_deref());
        if record.kind == TraceRecordKind::UnfinishedSyscall && paired_unfinished.contains(&index) {
            continue;
        }
        if record.kind != TraceRecordKind::Syscall
            && !(record.kind == TraceRecordKind::ResumedSyscall && paired_arguments.is_some())
        {
            add_record_diagnostic(
                &mut result,
                "incomplete_creation_record",
                record,
                "process-creation row is unfinished or resumed; no relation was inferred",
            );
            continue;
        }
        let Some(parent_pid) = record.process_id.filter(|pid| *pid > 0) else {
            add_record_diagnostic(
                &mut result,
                "missing_parent_pid",
                record,
                "process-creation row has no positive caller PID",
            );
            continue;
        };

        if is_clone {
            let arguments = paired_arguments
                .flatten()
                .or(record.raw_arguments.as_deref())
                .unwrap_or_default();
            match clone_flags(arguments) {
                CloneFlags::Thread => {
                    add_record_diagnostic(
                        &mut result,
                        "clone_thread_excluded",
                        record,
                        "clone flags include CLONE_THREAD; this is not a process-tree edge",
                    );
                    continue;
                }
                CloneFlags::Parent => {
                    add_record_diagnostic(
                        &mut result,
                        "clone_parent_semantics",
                        record,
                        "clone flags include CLONE_PARENT; the caller is not the child's parent",
                    );
                    continue;
                }
                CloneFlags::Unsupported => {
                    add_record_diagnostic(
                        &mut result,
                        "unsupported_clone_flags",
                        record,
                        "clone flags are missing, ambiguous, or unsupported; no relation was inferred",
                    );
                    continue;
                }
                CloneFlags::Process => {}
            }
        }

        let Some(child_pid) = record.raw_result.as_deref().and_then(parse_positive_pid) else {
            add_record_diagnostic(
                &mut result,
                "invalid_child_pid_result",
                record,
                "process-creation result is not a strict positive decimal child PID",
            );
            continue;
        };

        if candidates.len() == MAX_PROCESS_RELATIONS {
            add_record_diagnostic(
                &mut result,
                "relation_limit",
                record,
                "process relation candidate limit reached; remaining rows were not analyzed",
            );
            break;
        }
        candidates.push(Candidate {
            relation: ProcessRelation {
                parent_pid,
                child_pid,
                evidence: record.evidence.clone(),
                supporting_evidence: resumed_from
                    .get(&index)
                    .map(|unfinished_index| vec![records[*unfinished_index].evidence.clone()])
                    .unwrap_or_default(),
            },
        });
    }

    // A repeated child PID may reflect reuse, malformed input, or competing
    // creation records. Without a PID generation, none of its candidate edges
    // is safe to choose.
    candidates.sort_by_key(|candidate| {
        (
            candidate.relation.child_pid,
            candidate.relation.parent_pid,
            candidate.relation.evidence.byte_offset,
        )
    });
    let mut index = 0;
    while index < candidates.len() {
        let start = index;
        let child_pid = candidates[index].relation.child_pid;
        index += 1;
        while index < candidates.len() && candidates[index].relation.child_pid == child_pid {
            index += 1;
        }
        if index - start == 1 {
            result.relations.push(candidates[start].relation.clone());
        } else {
            for candidate in &candidates[start..index] {
                add_diagnostic(
                    &mut result,
                    "ambiguous_child_pid",
                    Some(candidate.relation.evidence.clone()),
                    "multiple creation rows claim the same child PID; no relation was selected",
                );
            }
        }
    }

    result.relations.sort_by_key(|relation| {
        (
            relation.parent_pid,
            relation.child_pid,
            relation.evidence.byte_offset,
        )
    });
    result
}

fn is_process_creation(syscall: &str) -> bool {
    syscall == "fork" || syscall == "vfork" || syscall == "clone" || syscall.starts_with("clone3")
}

fn parse_positive_pid(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let pid = value.parse::<u32>().ok()?;
    (pid > 0).then_some(pid)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloneFlags {
    Process,
    Thread,
    Parent,
    Unsupported,
}

fn clone_flags(arguments: &str) -> CloneFlags {
    let Some(after) = exact_flags_value(arguments) else {
        return CloneFlags::Unsupported;
    };
    let value = after.split(',').next().unwrap_or_default().trim();
    if value.is_empty() {
        return CloneFlags::Unsupported;
    }

    if let Some(bits) = parse_integer_flags(value) {
        return if bits & CLONE_THREAD != 0 {
            CloneFlags::Thread
        } else if bits & CLONE_PARENT != 0 {
            CloneFlags::Parent
        } else {
            CloneFlags::Process
        };
    }

    // strace renders symbolic clone flags as a complete `|`-separated list,
    // sometimes with an exit-signal name. Accept only known spellings so an
    // unfamiliar token cannot silently become evidence that THREAD is absent.
    let mut saw_thread = false;
    let mut saw_parent = false;
    for token in value.split('|') {
        if token == "CLONE_THREAD" {
            saw_thread = true;
        } else if token == "CLONE_PARENT" {
            saw_parent = true;
        } else if !known_clone_flag(token) && !known_exit_signal(token) {
            return CloneFlags::Unsupported;
        }
    }
    if saw_thread {
        CloneFlags::Thread
    } else if saw_parent {
        CloneFlags::Parent
    } else {
        CloneFlags::Process
    }
}

fn exact_flags_value(arguments: &str) -> Option<&str> {
    let bytes = arguments.as_bytes();
    let needle = b"flags=";
    let mut found = None;
    let mut index = 0;
    while index + needle.len() <= bytes.len() {
        if &bytes[index..index + needle.len()] == needle {
            let at_field_start = index == 0
                || bytes[..index]
                    .iter()
                    .rev()
                    .find(|byte| !byte.is_ascii_whitespace())
                    .is_some_and(|byte| matches!(*byte, b'{' | b','));
            if at_field_start {
                if found.is_some() {
                    return None;
                }
                found = Some(&arguments[index + needle.len()..]);
            }
            index += needle.len();
        } else {
            index += 1;
        }
    }
    found
}

fn parse_integer_flags(value: &str) -> Option<u64> {
    if let Some(hex) = value.strip_prefix("0x") {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(hex, 16).ok()
    } else if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse().ok()
    } else {
        None
    }
}

fn known_clone_flag(value: &str) -> bool {
    matches!(
        value,
        "CLONE_CHILD_CLEARTID"
            | "CLONE_CHILD_SETTID"
            | "CLONE_CLEAR_SIGHAND"
            | "CLONE_DETACHED"
            | "CLONE_FILES"
            | "CLONE_FS"
            | "CLONE_INTO_CGROUP"
            | "CLONE_IO"
            | "CLONE_NEWCGROUP"
            | "CLONE_NEWIPC"
            | "CLONE_NEWNET"
            | "CLONE_NEWNS"
            | "CLONE_NEWPID"
            | "CLONE_NEWUSER"
            | "CLONE_NEWUTS"
            | "CLONE_PARENT"
            | "CLONE_PARENT_SETTID"
            | "CLONE_PIDFD"
            | "CLONE_PTRACE"
            | "CLONE_SETTLS"
            | "CLONE_SIGHAND"
            | "CLONE_SYSVSEM"
            | "CLONE_UNTRACED"
            | "CLONE_VFORK"
            | "CLONE_VM"
    )
}

fn known_exit_signal(value: &str) -> bool {
    matches!(
        value,
        "SIGCHLD"
            | "SIGHUP"
            | "SIGINT"
            | "SIGQUIT"
            | "SIGILL"
            | "SIGTRAP"
            | "SIGABRT"
            | "SIGBUS"
            | "SIGFPE"
            | "SIGKILL"
            | "SIGUSR1"
            | "SIGSEGV"
            | "SIGUSR2"
            | "SIGPIPE"
            | "SIGALRM"
            | "SIGTERM"
            | "SIGSTKFLT"
            | "SIGCONT"
            | "SIGSTOP"
            | "SIGTSTP"
            | "SIGTTIN"
            | "SIGTTOU"
            | "SIGURG"
            | "SIGXCPU"
            | "SIGXFSZ"
            | "SIGVTALRM"
            | "SIGPROF"
            | "SIGWINCH"
            | "SIGIO"
            | "SIGPWR"
            | "SIGSYS"
    )
}

fn add_record_diagnostic(
    result: &mut ProcessLineage,
    code: &'static str,
    record: &TraceRecord,
    message: &'static str,
) {
    add_diagnostic(result, code, Some(record.evidence.clone()), message);
}

fn add_diagnostic(
    result: &mut ProcessLineage,
    code: &'static str,
    evidence: Option<EvidenceReference>,
    message: &'static str,
) {
    result.partial = true;
    if result.diagnostics.len() < MAX_LINEAGE_DIAGNOSTICS {
        result.diagnostics.push(ProcessLineageDiagnostic {
            code,
            evidence,
            message,
        });
    } else {
        result.diagnostics_truncated = true;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_LINEAGE_DIAGNOSTICS, MAX_LINEAGE_INPUT_RECORDS, MAX_PROCESS_RELATIONS,
        derive_process_lineage,
    };
    use crate::model::{EvidenceReference, TraceRecord, TraceRecordKind};

    fn record(
        index: usize,
        kind: TraceRecordKind,
        pid: Option<u32>,
        syscall: &str,
        arguments: &str,
        result: Option<&str>,
    ) -> TraceRecord {
        TraceRecord {
            kind,
            evidence: EvidenceReference {
                line_number: index as u64 + 1,
                byte_offset: (index * 20) as u64,
                byte_length: 19,
            },
            raw_line: String::new(),
            process_id: pid,
            timestamp: None,
            syscall: Some(syscall.to_owned()),
            raw_arguments: Some(arguments.to_owned()),
            raw_result: result.map(str::to_owned),
            outcome: None,
            lexical_path_hint: None,
        }
    }

    #[test]
    fn successful_fork_vfork_and_supported_clone_create_direct_evidence_links() {
        let rows = vec![
            record(
                0,
                TraceRecordKind::Syscall,
                Some(10),
                "fork",
                "",
                Some("11"),
            ),
            record(
                1,
                TraceRecordKind::Syscall,
                Some(10),
                "vfork",
                "",
                Some("12"),
            ),
            record(
                2,
                TraceRecordKind::Syscall,
                Some(10),
                "clone",
                "child_stack=NULL, flags=CLONE_VM|SIGCHLD, child_tidptr=NULL",
                Some("13"),
            ),
            record(
                3,
                TraceRecordKind::Syscall,
                Some(10),
                "clone3",
                "{flags=0x100000, exit_signal=SIGCHLD}, 88",
                Some("14"),
            ),
        ];

        let result = derive_process_lineage(&rows);
        assert!(!result.partial);
        assert_eq!(result.relations.len(), 4);
        assert_eq!(result.relations[0].parent_pid, 10);
        assert_eq!(result.relations[0].child_pid, 11);
        assert_eq!(result.relations[0].evidence, rows[0].evidence);
        assert!(result.relations.iter().any(|edge| edge.child_pid == 14));
        assert!(result.diagnostics.is_empty());
    }

    #[test]
    fn clone_thread_and_unknown_flags_never_create_edges() {
        let rows = vec![
            record(
                0,
                TraceRecordKind::Syscall,
                Some(10),
                "clone",
                "flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND",
                Some("11"),
            ),
            record(
                1,
                TraceRecordKind::Syscall,
                Some(10),
                "clone3",
                "{flags=CLONE_VM|CLONE_future_flag}",
                Some("12"),
            ),
            record(
                2,
                TraceRecordKind::Syscall,
                Some(10),
                "clone",
                "flags=0x110000",
                Some("13"),
            ),
        ];

        let result = derive_process_lineage(&rows);
        assert!(result.relations.is_empty());
        assert!(result.partial);
        assert_eq!(result.diagnostics.len(), 3);
        assert_eq!(result.diagnostics[0].code, "clone_thread_excluded");
        assert_eq!(result.diagnostics[1].code, "unsupported_clone_flags");
        assert_eq!(result.diagnostics[2].code, "clone_thread_excluded");
    }

    #[test]
    fn clone_parent_never_creates_a_caller_to_child_relation() {
        let rows = vec![
            record(
                0,
                TraceRecordKind::Syscall,
                Some(10),
                "clone",
                "flags=CLONE_VM|CLONE_PARENT|SIGCHLD",
                Some("11"),
            ),
            record(
                1,
                TraceRecordKind::Syscall,
                Some(10),
                "clone3",
                "{flags=0x8000, exit_signal=SIGCHLD}",
                Some("12"),
            ),
        ];

        let result = derive_process_lineage(&rows);
        assert!(result.relations.is_empty());
        assert!(result.partial);
        assert_eq!(result.diagnostics.len(), 2);
        assert!(
            result
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code == "clone_parent_semantics")
        );
        assert_eq!(
            result.diagnostics[0].evidence,
            Some(rows[0].evidence.clone())
        );
        assert_eq!(
            result.diagnostics[1].evidence,
            Some(rows[1].evidence.clone())
        );
    }

    #[test]
    fn nonpositive_malformed_and_nondecimal_child_results_are_rejected() {
        let rows = ["0", "-1", "+22", "0x22", "22 ", "4294967296"]
            .iter()
            .enumerate()
            .map(|(index, value)| {
                record(
                    index,
                    TraceRecordKind::Syscall,
                    Some(10),
                    "fork",
                    "",
                    Some(*value),
                )
            })
            .collect::<Vec<_>>();
        let result = derive_process_lineage(&rows);
        assert!(result.relations.is_empty());
        assert_eq!(result.diagnostics.len(), rows.len());
        assert!(
            result
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code == "invalid_child_pid_result")
        );
    }

    #[test]
    fn failed_incomplete_and_missing_pid_rows_are_not_linked() {
        let rows = vec![
            record(
                0,
                TraceRecordKind::Syscall,
                Some(10),
                "fork",
                "",
                Some("-1 EAGAIN"),
            ),
            record(
                1,
                TraceRecordKind::UnfinishedSyscall,
                Some(10),
                "fork",
                "",
                None,
            ),
            record(2, TraceRecordKind::Syscall, None, "fork", "", Some("12")),
        ];
        let result = derive_process_lineage(&rows);
        assert!(result.relations.is_empty());
        assert_eq!(result.diagnostics.len(), 3);
        assert_eq!(result.diagnostics[0].code, "invalid_child_pid_result");
        assert_eq!(result.diagnostics[1].code, "incomplete_creation_record");
        assert_eq!(result.diagnostics[2].code, "missing_parent_pid");
    }

    #[test]
    fn unique_unfinished_clone_pair_uses_both_exact_source_rows() {
        let rows = vec![
            record(
                0,
                TraceRecordKind::UnfinishedSyscall,
                Some(10),
                "clone3",
                "{flags=CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND, exit_signal=SIGCHLD}",
                None,
            ),
            record(
                1,
                TraceRecordKind::ResumedSyscall,
                Some(10),
                "clone3",
                "",
                Some("11"),
            ),
        ];

        let result = derive_process_lineage(&rows);
        assert!(!result.partial);
        assert_eq!(result.relations.len(), 1);
        assert_eq!(result.relations[0].parent_pid, 10);
        assert_eq!(result.relations[0].child_pid, 11);
        assert_eq!(result.relations[0].evidence, rows[1].evidence);
        assert_eq!(
            result.relations[0].supporting_evidence,
            vec![rows[0].evidence.clone()]
        );
    }

    #[test]
    fn multiple_creation_rows_claiming_one_pid_are_all_ambiguous() {
        let rows = vec![
            record(
                0,
                TraceRecordKind::Syscall,
                Some(10),
                "fork",
                "",
                Some("12"),
            ),
            record(
                1,
                TraceRecordKind::Syscall,
                Some(11),
                "vfork",
                "",
                Some("12"),
            ),
            record(
                2,
                TraceRecordKind::Syscall,
                Some(10),
                "fork",
                "",
                Some("13"),
            ),
        ];
        let result = derive_process_lineage(&rows);
        assert_eq!(result.relations.len(), 1);
        assert_eq!(result.relations[0].child_pid, 13);
        assert!(result.partial);
        assert_eq!(result.diagnostics.len(), 2);
        assert!(
            result
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code == "ambiguous_child_pid")
        );
    }

    #[test]
    fn non_creation_rows_and_non_syscall_rows_are_ignored() {
        let rows = vec![
            record(
                0,
                TraceRecordKind::Syscall,
                Some(10),
                "execve",
                "",
                Some("0"),
            ),
            record(1, TraceRecordKind::Control, None, "", "", None),
        ];
        let result = derive_process_lineage(&rows);
        assert!(result.relations.is_empty());
        assert!(result.diagnostics.is_empty());
        assert!(!result.partial);
    }

    #[test]
    fn input_relation_and_diagnostic_caps_are_explicit() {
        let too_many_records = vec![
            record(0, TraceRecordKind::Control, None, "", "", None);
            MAX_LINEAGE_INPUT_RECORDS + 1
        ];
        let limited = derive_process_lineage(&too_many_records);
        assert!(limited.partial);
        assert_eq!(limited.diagnostics[0].code, "input_record_limit");

        let too_many_relations = (0..=MAX_PROCESS_RELATIONS)
            .map(|index| {
                let child_pid = (index as u32 + 2).to_string();
                record(
                    index,
                    TraceRecordKind::Syscall,
                    Some(1),
                    "fork",
                    "",
                    Some(child_pid.as_str()),
                )
            })
            .collect::<Vec<_>>();
        let limited = derive_process_lineage(&too_many_relations);
        assert!(limited.partial);
        assert!(
            limited
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "relation_limit")
        );

        let unknown_rows = (0..MAX_LINEAGE_DIAGNOSTICS + 1)
            .map(|index| {
                record(
                    index,
                    TraceRecordKind::Syscall,
                    Some(1),
                    "clone",
                    "flags=UNKNOWN",
                    Some("2"),
                )
            })
            .collect::<Vec<_>>();
        let limited = derive_process_lineage(&unknown_rows);
        assert_eq!(limited.diagnostics.len(), MAX_LINEAGE_DIAGNOSTICS);
        assert!(limited.diagnostics_truncated);
        assert!(limited.partial);
    }
}
