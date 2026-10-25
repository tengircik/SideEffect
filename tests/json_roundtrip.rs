use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const BASELINE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/diff/baseline.synthetic.trace"
);
const UPDATED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/diff/updated.synthetic.trace"
);

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempTrace(std::path::PathBuf);

impl TempTrace {
    fn with_contents(contents: &[u8]) -> Self {
        loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-json-roundtrip-{}-{id}.trace",
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(contents).unwrap();
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create temporary trace: {error}"),
            }
        }
    }
}

impl Drop for TempTrace {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct TraceDocument {
    schema_version: u32,
    source_format: String,
    source_sha256: String,
    input_bytes: u64,
    parse_status: ParseCompleteness,
    records: Vec<TraceRecord>,
    diagnostics: Vec<TraceDiagnostic>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ParseCompleteness {
    Complete,
    Partial,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum TraceRecordKind {
    Syscall,
    UnfinishedSyscall,
    ResumedSyscall,
    Control,
    Unparsed,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SyscallOutcome {
    Success,
    Failure,
    InProgress,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct TraceRecord {
    kind: TraceRecordKind,
    evidence: EvidenceReference,
    raw_line: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    syscall: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    raw_arguments: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    raw_result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outcome: Option<SyscallOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lexical_path_hint: Option<LexicalPathHint>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct EvidenceReference {
    line_number: u64,
    byte_offset: u64,
    byte_length: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct LexicalPathHint {
    path: String,
    basis: LexicalPathBasis,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum LexicalPathBasis {
    AbsoluteArgument,
    AtFdcwdAnnotation,
    DirectoryFdAnnotation,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct TraceDiagnostic {
    code: String,
    line_number: u64,
    byte_offset: u64,
    message: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct TraceDiff {
    schema_version: u32,
    left_source_format: String,
    right_source_format: String,
    left_source_sha256: String,
    right_source_sha256: String,
    capture_completeness: CaptureCompleteness,
    matching_policy: MatchingPolicy,
    left_excluded_control_records: u64,
    right_excluded_control_records: u64,
    changes: Vec<ObservedDelta>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum CaptureCompleteness {
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct MatchingPolicy {
    ignored_prefix_fields: Vec<String>,
    multiplicity: String,
    exact_fields: Vec<String>,
    display_only_fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ObservedDelta {
    kind: DeltaKind,
    category: EventCategory,
    record_kind: TraceRecordKind,
    syscall: String,
    raw_arguments: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    before_lexical_path_hint: Option<LexicalPathHint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    after_lexical_path_hint: Option<LexicalPathHint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    before_result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    after_result: Option<String>,
    before: Vec<EvidenceReference>,
    after: Vec<EvidenceReference>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum DeltaKind {
    Added,
    Changed,
    Removed,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum EventCategory {
    File,
    Network,
    Other,
    Process,
}

#[test]
fn inspect_json_round_trips_through_the_typed_trace_schema() {
    let trace = TempTrace::with_contents(
        concat!(
            "9 1700000000.000001 openat(AT_FDCWD</tmp/work>, \"file.txt\", O_RDONLY) = 3\n",
            "9 getpid() = 9\n"
        )
        .as_bytes(),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inspect"])
        .arg(&trace.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let document: TraceDocument = serde_json::from_slice(&output.stdout)
        .expect("inspect output must satisfy the versioned typed trace schema");
    assert_eq!(document.schema_version, 4);
    assert_eq!(document.records[0].outcome, Some(SyscallOutcome::Success));
    assert_eq!(document.records[0].evidence.line_number, 1);
    assert_eq!(
        document.records[0].lexical_path_hint.as_ref().unwrap().path,
        "/tmp/work/file.txt"
    );
    assert_eq!(serde_json::to_value(document).unwrap(), value);
}

#[test]
fn diff_json_round_trips_through_the_typed_diff_schema() {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", BASELINE, UPDATED])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let document: TraceDiff = serde_json::from_slice(&output.stdout)
        .expect("diff output must satisfy the versioned typed diff schema");
    assert_eq!(document.schema_version, 3);
    assert_eq!(document.capture_completeness, CaptureCompleteness::Unknown);
    assert_eq!(document.matching_policy.multiplicity, "multiset");
    assert!(!document.changes.is_empty());
    assert!(
        document
            .changes
            .iter()
            .all(|change| { !change.before.is_empty() || !change.after.is_empty() })
    );
    assert_eq!(serde_json::to_value(document).unwrap(), value);
}
