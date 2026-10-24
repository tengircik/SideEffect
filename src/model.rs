use serde::Serialize;

use crate::trace::LexicalPathHint;

pub const TRACE_DOCUMENT_SCHEMA_VERSION: u32 = 2;
pub const TRACE_DIFF_SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseCompleteness {
    /// Every input line was classified and continuation records reconciled.
    Complete,
    /// One or more input lines could not be parsed or reconciled.
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceRecordKind {
    Syscall,
    UnfinishedSyscall,
    ResumedSyscall,
    Control,
    Unparsed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceReference {
    pub line_number: u64,
    pub byte_offset: u64,
    pub byte_length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TraceRecord {
    pub kind: TraceRecordKind,
    pub evidence: EvidenceReference,
    pub raw_line: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_arguments: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_result: Option<String>,
    /// A conservative path spelling joined with an absolute `-yy` dirfd base.
    /// This is lexical only; it is not canonical or filesystem-resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lexical_path_hint: Option<LexicalPathHint>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TraceDiagnostic {
    pub code: String,
    pub line_number: u64,
    pub byte_offset: u64,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TraceDocument {
    pub schema_version: u32,
    pub source_format: String,
    pub input_bytes: u64,
    /// Parse status only; it does not describe whether an OS capture was complete.
    pub parse_status: ParseCompleteness,
    pub records: Vec<TraceRecord>,
    pub diagnostics: Vec<TraceDiagnostic>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureCompleteness {
    /// Parsing a trace cannot establish whether the capture observed all activity.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    File,
    Network,
    Other,
    Process,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaKind {
    Added,
    Changed,
    Removed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MatchingPolicy {
    /// Parser-level run metadata omitted only from matching; raw records retain it.
    pub ignored_prefix_fields: Vec<String>,
    pub multiplicity: String,
    /// Exact row identity fields and result value used by the comparison.
    pub exact_fields: Vec<String>,
    /// Derived display hints are exposed but never used as comparison keys.
    pub display_only_fields: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObservedDelta<'a> {
    pub kind: DeltaKind,
    pub category: EventCategory,
    pub record_kind: TraceRecordKind,
    pub syscall: &'a str,
    pub raw_arguments: &'a str,
    /// Optional derived path hint from the before-side evidence. Display only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_lexical_path_hint: Option<&'a LexicalPathHint>,
    /// Optional derived path hint from the after-side evidence. Display only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_lexical_path_hint: Option<&'a LexicalPathHint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_result: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_result: Option<&'a str>,
    pub before: Vec<EvidenceReference>,
    pub after: Vec<EvidenceReference>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TraceDiff<'a> {
    pub schema_version: u32,
    pub left_source_format: &'a str,
    pub right_source_format: &'a str,
    pub capture_completeness: CaptureCompleteness,
    pub matching_policy: MatchingPolicy,
    /// Control rows are visible as counts but are outside the initial syscall comparison.
    pub left_excluded_control_records: u64,
    pub right_excluded_control_records: u64,
    pub changes: Vec<ObservedDelta<'a>>,
}
