use serde::Serialize;

pub const TRACE_DOCUMENT_SCHEMA_VERSION: u32 = 1;

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
