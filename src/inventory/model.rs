use serde::Serialize;

pub const INVENTORY_SCHEMA: &str = "sideeffect.inventory";
pub const INVENTORY_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventorySourceStatus {
    Complete,
    Partial,
    Unavailable,
    AccessDenied,
    Failed,
    TimedOut,
    OutputLimitExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub captured_at_unix_ms: u128,
    pub status: InventoryStatus,
    pub sources: Vec<InventorySource>,
    pub packages: Vec<InventoryPackage>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventorySource {
    pub id: &'static str,
    pub status: InventorySourceStatus,
    pub exit_code: Option<i32>,
    pub records_seen: usize,
    pub diagnostics: Vec<InventoryDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryPackage {
    /// Package fields are absent only when the source row could not be parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_abbrev: Option<String>,
    pub evidence: InventoryEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic_code: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryEvidence {
    pub line: usize,
    pub byte_offset: usize,
    pub byte_length: usize,
    pub record_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_record: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_record_hex: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryDiagnostic {
    pub code: &'static str,
    pub line: Option<usize>,
    pub byte_offset: Option<usize>,
    pub byte_length: Option<usize>,
    pub record_sha256: Option<String>,
}
