//! Bounded comparison of Windows uninstall-registration inventory snapshots.

use serde::{Deserialize, Serialize, de};
use std::collections::{BTreeMap, BTreeSet};

const SCHEMA: &str = "sideeffect.windows_software_inventory";
const SCHEMA_VERSION: u32 = 1;
const SCOPE: &str = "current_user_and_accessible_machine_uninstall_registry_entries";
const REGISTRY_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_SOURCES: usize = 4;
const MAX_REGISTRATIONS: usize = 8_192;
const MAX_VALUES_PER_REGISTRATION: usize = 8;
const MAX_DIAGNOSTICS: usize = 65_536;
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_SUBKEY_UTF16_UNITS: usize = 16_384;
const MAX_RAW_VALUE_HEX_BYTES: usize = 128 * 1024;
const MAX_DELTAS: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSoftwareComparisonStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSoftwareChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSoftwareComparisonDiagnostic {
    SourceIncomplete,
    InvalidRegistrationIdentity,
    DuplicateRegistrationIdentity,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WindowsSoftwareIdentity {
    pub source_id: String,
    pub hive: String,
    pub registry_view: String,
    pub registry_key: String,
    pub registry_subkey: String,
    pub registry_subkey_utf16_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsSoftwareEvidenceReference {
    pub source_id: String,
    pub registration_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsSoftwareFacts {
    pub display_name: Option<String>,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    pub evidence: WindowsSoftwareEvidenceReference,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsSoftwareDelta {
    pub kind: WindowsSoftwareChangeKind,
    pub identity: WindowsSoftwareIdentity,
    pub changed_fields: Vec<String>,
    pub before: Option<WindowsSoftwareFacts>,
    pub after: Option<WindowsSoftwareFacts>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsSoftwareSourceComparison {
    pub source_id: String,
    pub before_status: Option<WindowsSoftwareSourceStatus>,
    pub after_status: Option<WindowsSoftwareSourceStatus>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSoftwareSourceStatus {
    Complete,
    Partial,
    NotPresent,
    Inaccessible,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsSoftwareComparisonCounts {
    pub additions: usize,
    pub removals: usize,
    pub changes: usize,
    pub unmatched_rows_with_incomplete_source: usize,
    pub invalid_identity_rows: usize,
    pub ambiguous_identity_groups: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsSoftwareInventoryComparison {
    pub schema: &'static str,
    pub schema_version: u32,
    pub before_captured_at_unix_ms: u128,
    pub after_captured_at_unix_ms: u128,
    pub status: WindowsSoftwareComparisonStatus,
    pub coverage_note: &'static str,
    pub sources: Vec<WindowsSoftwareSourceComparison>,
    pub counts: WindowsSoftwareComparisonCounts,
    pub diagnostics: Vec<WindowsSoftwareComparisonDiagnostic>,
    pub deltas: Vec<WindowsSoftwareDelta>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsSoftwareComparisonError {
    MalformedInput,
    InputTooLarge,
    UnsupportedSchema,
    PlatformMismatch,
    ScopeMismatch,
    InvalidSourceSet,
    LimitExceeded,
}

#[derive(Deserialize)]
struct SchemaHeader {
    schema: String,
}

/// Used by the CLI to route saved inventory documents without accepting them.
pub fn is_windows_software_inventory_json(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_INPUT_BYTES
        && serde_json::from_slice::<SchemaHeader>(bytes).is_ok_and(|header| header.schema == SCHEMA)
}

/// Strictly deserialize and compare two Windows software-registration v1 documents.
pub fn compare_windows_software_inventory_json(
    before_json: &[u8],
    after_json: &[u8],
) -> Result<WindowsSoftwareInventoryComparison, WindowsSoftwareComparisonError> {
    if before_json.len().saturating_add(after_json.len()) > MAX_INPUT_BYTES {
        return Err(WindowsSoftwareComparisonError::InputTooLarge);
    }
    let before: InputDocument = serde_json::from_slice(before_json)
        .map_err(|_| WindowsSoftwareComparisonError::MalformedInput)?;
    let after: InputDocument = serde_json::from_slice(after_json)
        .map_err(|_| WindowsSoftwareComparisonError::MalformedInput)?;
    compare_documents(before, after)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputDocument {
    schema: String,
    schema_version: u32,
    platform: String,
    scope: String,
    capture_started_at_unix_ms: u128,
    capture_ended_at_unix_ms: u128,
    status: InventoryStatus,
    #[serde(deserialize_with = "bounded_sources")]
    sources: Vec<InputSource>,
    #[serde(deserialize_with = "bounded_registrations")]
    registrations: Vec<InputRegistration>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum InventoryStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SourceStatus {
    Complete,
    Partial,
    NotPresent,
    Inaccessible,
    Error,
}

impl From<SourceStatus> for WindowsSoftwareSourceStatus {
    fn from(value: SourceStatus) -> Self {
        match value {
            SourceStatus::Complete => Self::Complete,
            SourceStatus::Partial => Self::Partial,
            SourceStatus::NotPresent => Self::NotPresent,
            SourceStatus::Inaccessible => Self::Inaccessible,
            SourceStatus::Error => Self::Error,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputSource {
    id: String,
    status: SourceStatus,
    registrations_seen: usize,
    hive: String,
    registry_key: String,
    registry_view: RegistryView,
    #[serde(deserialize_with = "bounded_diagnostics")]
    diagnostics: Vec<InputDiagnostic>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum RegistryView {
    Native,
    Wow64_32,
    Wow64_64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputDiagnostic {
    code: String,
    registration_index: Option<usize>,
    value_name: Option<String>,
    message: String,
    win32_error: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputRegistration {
    registry_subkey: String,
    registry_subkey_utf16_hex: String,
    display_name: Option<String>,
    #[serde(deserialize_with = "bounded_values")]
    values: Vec<InputValue>,
    evidence: InputEvidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputEvidence {
    source: String,
    hive: String,
    registry_view: RegistryView,
    registry_key: String,
    registration_index: usize,
    registry_subkey: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputValue {
    name: String,
    registry_type: u32,
    type_name: String,
    text: Option<String>,
    raw_data_hex: String,
}

#[derive(Clone)]
struct Registration {
    identity: WindowsSoftwareIdentity,
    facts: WindowsSoftwareFacts,
    source_id: String,
}

fn compare_documents(
    before: InputDocument,
    after: InputDocument,
) -> Result<WindowsSoftwareInventoryComparison, WindowsSoftwareComparisonError> {
    validate_document(&before)?;
    validate_document(&after)?;
    if before.platform != after.platform || before.platform != "windows" {
        return Err(WindowsSoftwareComparisonError::PlatformMismatch);
    }
    if before.scope != after.scope || before.scope != SCOPE {
        return Err(WindowsSoftwareComparisonError::ScopeMismatch);
    }

    let before_sources = source_map(&before.sources)?;
    let after_sources = source_map(&after.sources)?;
    let mut source_comparisons = Vec::with_capacity(MAX_SOURCES);
    let mut source_complete = BTreeMap::new();
    let mut diagnostics = BTreeSet::new();
    let mut is_complete =
        before.status == InventoryStatus::Complete && after.status == InventoryStatus::Complete;
    for id in source_ids() {
        let left = before_sources.get(id).expect("validated source set");
        let right = after_sources.get(id).expect("validated source set");
        source_comparisons.push(WindowsSoftwareSourceComparison {
            source_id: id.to_owned(),
            before_status: Some(left.status.into()),
            after_status: Some(right.status.into()),
        });
        let comparable = source_is_complete(left.status) && source_is_complete(right.status);
        source_complete.insert(id, comparable);
        if !comparable {
            is_complete = false;
            diagnostics.insert(WindowsSoftwareComparisonDiagnostic::SourceIncomplete);
        }
    }

    let mut left = group_registrations(&before, &before_sources);
    let mut right = group_registrations(&after, &after_sources);
    let mut counts = WindowsSoftwareComparisonCounts {
        additions: 0,
        removals: 0,
        changes: 0,
        unmatched_rows_with_incomplete_source: 0,
        invalid_identity_rows: left.invalid + right.invalid,
        ambiguous_identity_groups: 0,
    };
    if counts.invalid_identity_rows > 0 {
        diagnostics.insert(WindowsSoftwareComparisonDiagnostic::InvalidRegistrationIdentity);
        is_complete = false;
    }
    let duplicates: BTreeSet<_> = left.duplicates.union(&right.duplicates).cloned().collect();
    counts.ambiguous_identity_groups = duplicates.len();
    if !duplicates.is_empty() {
        diagnostics.insert(WindowsSoftwareComparisonDiagnostic::DuplicateRegistrationIdentity);
        is_complete = false;
        for identity in &duplicates {
            left.rows.remove(identity);
            right.rows.remove(identity);
        }
    }

    let identities: BTreeSet<_> = left.rows.keys().chain(right.rows.keys()).cloned().collect();
    let mut deltas = Vec::new();
    for identity in identities {
        let before_row = left.rows.get(&identity);
        let after_row = right.rows.get(&identity);
        match (before_row, after_row) {
            (Some(before_row), Some(after_row)) => {
                let changed_fields = changed_fields(&before_row.facts, &after_row.facts);
                if !changed_fields.is_empty() {
                    push_delta(
                        &mut deltas,
                        WindowsSoftwareDelta {
                            kind: WindowsSoftwareChangeKind::Changed,
                            identity,
                            changed_fields,
                            before: Some(before_row.facts.clone()),
                            after: Some(after_row.facts.clone()),
                        },
                    )?;
                    counts.changes += 1;
                }
            }
            (Some(row), None) | (None, Some(row)) => {
                if !source_complete
                    .get(row.source_id.as_str())
                    .copied()
                    .unwrap_or(false)
                    || left.invalid_unknown_source
                    || right.invalid_unknown_source
                    || left.invalid_sources.contains(row.source_id.as_str())
                    || right.invalid_sources.contains(row.source_id.as_str())
                {
                    counts.unmatched_rows_with_incomplete_source += 1;
                    is_complete = false;
                    diagnostics.insert(WindowsSoftwareComparisonDiagnostic::SourceIncomplete);
                } else if before_row.is_some() {
                    push_delta(
                        &mut deltas,
                        WindowsSoftwareDelta {
                            kind: WindowsSoftwareChangeKind::Removed,
                            identity,
                            changed_fields: Vec::new(),
                            before: Some(row.facts.clone()),
                            after: None,
                        },
                    )?;
                    counts.removals += 1;
                } else {
                    push_delta(
                        &mut deltas,
                        WindowsSoftwareDelta {
                            kind: WindowsSoftwareChangeKind::Added,
                            identity,
                            changed_fields: Vec::new(),
                            before: None,
                            after: Some(row.facts.clone()),
                        },
                    )?;
                    counts.additions += 1;
                }
            }
            (None, None) => unreachable!("identity came from one of the maps"),
        }
    }

    Ok(WindowsSoftwareInventoryComparison {
        schema: "sideeffect.windows_software_inventory_diff",
        schema_version: 1,
        before_captured_at_unix_ms: before.capture_ended_at_unix_ms,
        after_captured_at_unix_ms: after.capture_ended_at_unix_ms,
        status: if is_complete {
            WindowsSoftwareComparisonStatus::Complete
        } else {
            WindowsSoftwareComparisonStatus::Partial
        },
        coverage_note: "Compares selected Windows uninstall-registry registrations only; it does not establish software execution, causation, or exhaustive installation coverage.",
        sources: source_comparisons,
        counts,
        diagnostics: diagnostics.into_iter().collect(),
        deltas,
    })
}

fn validate_document(document: &InputDocument) -> Result<(), WindowsSoftwareComparisonError> {
    if document.schema != SCHEMA || document.schema_version != SCHEMA_VERSION {
        return Err(WindowsSoftwareComparisonError::UnsupportedSchema);
    }
    if document.capture_ended_at_unix_ms < document.capture_started_at_unix_ms {
        return Err(WindowsSoftwareComparisonError::MalformedInput);
    }
    if document.sources.len() != MAX_SOURCES {
        return Err(WindowsSoftwareComparisonError::InvalidSourceSet);
    }
    let source_ids: BTreeSet<_> = document
        .sources
        .iter()
        .map(|source| source.id.as_str())
        .collect();
    if source_ids.len() != MAX_SOURCES || source_ids != source_ids_expected() {
        return Err(WindowsSoftwareComparisonError::InvalidSourceSet);
    }
    let computed_complete = document
        .sources
        .iter()
        .all(|source| source_is_complete(source.status));
    if computed_complete != (document.status == InventoryStatus::Complete) {
        return Err(WindowsSoftwareComparisonError::MalformedInput);
    }
    for source in &document.sources {
        let (expected_hive, expected_view) = expected_source_tuple(&source.id)
            .ok_or(WindowsSoftwareComparisonError::InvalidSourceSet)?;
        if source.hive != expected_hive
            || source.registry_view != expected_view
            || source.registry_key != REGISTRY_KEY
            || source.registrations_seen > MAX_REGISTRATIONS
            || source.diagnostics.len() > MAX_DIAGNOSTICS
        {
            return Err(WindowsSoftwareComparisonError::MalformedInput);
        }
        if source.diagnostics.iter().any(|diagnostic| {
            diagnostic.code.len() > 128
                || diagnostic.message.len() > MAX_TEXT_BYTES
                || diagnostic
                    .value_name
                    .as_ref()
                    .is_some_and(|value| value.len() > 128)
                || diagnostic
                    .registration_index
                    .is_some_and(|index| index >= MAX_REGISTRATIONS)
                || diagnostic.win32_error == Some(0)
                || diagnostic.win32_error.is_some()
                    != matches!(
                        diagnostic.code.as_str(),
                        "uninstall_key_metadata_failed"
                            | "registration_key_read_failed"
                            | "registration_disappeared_or_inaccessible"
                    )
        }) {
            return Err(WindowsSoftwareComparisonError::MalformedInput);
        }
    }
    Ok(())
}

fn source_ids() -> [&'static str; MAX_SOURCES] {
    [
        "current_user_native_uninstall",
        "current_user_32_uninstall",
        "local_machine_64_uninstall",
        "local_machine_32_uninstall",
    ]
}

fn source_ids_expected() -> BTreeSet<&'static str> {
    source_ids().into_iter().collect()
}

fn expected_source_tuple(id: &str) -> Option<(&'static str, RegistryView)> {
    match id {
        "current_user_native_uninstall" => Some(("HKEY_CURRENT_USER", RegistryView::Native)),
        "current_user_32_uninstall" => Some(("HKEY_CURRENT_USER", RegistryView::Wow64_32)),
        "local_machine_64_uninstall" => Some(("HKEY_LOCAL_MACHINE", RegistryView::Wow64_64)),
        "local_machine_32_uninstall" => Some(("HKEY_LOCAL_MACHINE", RegistryView::Wow64_32)),
        _ => None,
    }
}

fn source_is_complete(status: SourceStatus) -> bool {
    matches!(status, SourceStatus::Complete | SourceStatus::NotPresent)
}

fn source_map(
    sources: &[InputSource],
) -> Result<BTreeMap<&str, &InputSource>, WindowsSoftwareComparisonError> {
    let mut map = BTreeMap::new();
    for source in sources {
        if map.insert(source.id.as_str(), source).is_some() {
            return Err(WindowsSoftwareComparisonError::InvalidSourceSet);
        }
    }
    Ok(map)
}

struct GroupedRegistrations {
    rows: BTreeMap<WindowsSoftwareIdentity, Registration>,
    duplicates: BTreeSet<WindowsSoftwareIdentity>,
    invalid: usize,
    invalid_sources: BTreeSet<String>,
    invalid_unknown_source: bool,
}

fn group_registrations(
    document: &InputDocument,
    sources: &BTreeMap<&str, &InputSource>,
) -> GroupedRegistrations {
    let mut grouped = BTreeMap::<WindowsSoftwareIdentity, Vec<Registration>>::new();
    let mut invalid = 0usize;
    let mut invalid_sources = BTreeSet::new();
    let mut invalid_unknown_source = false;
    for row in &document.registrations {
        let Some(registration) = normalize_registration(row, sources) else {
            invalid += 1;
            if let Some(source) = sources.get(row.evidence.source_id()).copied() {
                invalid_sources.insert(source.id.clone());
            } else {
                invalid_unknown_source = true;
            }
            continue;
        };
        grouped
            .entry(registration.identity.clone())
            .or_default()
            .push(registration);
    }
    let mut rows = BTreeMap::new();
    let mut duplicates = BTreeSet::new();
    for (identity, registrations) in grouped {
        if registrations.len() == 1 {
            rows.insert(identity, registrations.into_iter().next().unwrap());
        } else {
            duplicates.insert(identity);
        }
    }
    GroupedRegistrations {
        rows,
        duplicates,
        invalid,
        invalid_sources,
        invalid_unknown_source,
    }
}

fn normalize_registration(
    row: &InputRegistration,
    sources: &BTreeMap<&str, &InputSource>,
) -> Option<Registration> {
    let evidence = &row.evidence;
    let source = sources.get(evidence.source_id()).copied()?;
    if source.status == SourceStatus::NotPresent
        || evidence.source != "RegEnumKeyExW/RegQueryValueExW"
        || evidence.hive != source.hive
        || evidence.registry_view != source.registry_view
        || evidence.registry_key != REGISTRY_KEY
        || evidence.registry_subkey != row.registry_subkey
        || row.registry_subkey.len() > MAX_TEXT_BYTES
        || row
            .display_name
            .as_ref()
            .is_some_and(|name| name.len() > MAX_TEXT_BYTES)
        || evidence.registration_index >= MAX_REGISTRATIONS
        || evidence.registration_index >= source.registrations_seen
        || row.registry_subkey_utf16_hex.len() > MAX_SUBKEY_UTF16_UNITS * 4
    {
        return None;
    }
    let key_units = decode_utf16_hex(&row.registry_subkey_utf16_hex)?;
    if key_units.len() > MAX_SUBKEY_UTF16_UNITS
        || String::from_utf16(&key_units).ok().as_deref() != Some(row.registry_subkey.as_str())
    {
        return None;
    }
    let mut values = BTreeMap::<&str, Option<&str>>::new();
    for value in &row.values {
        if value.name.len() > 64
            || value.type_name.len() > 32
            || value.raw_data_hex.len() > MAX_RAW_VALUE_HEX_BYTES
            || value.raw_data_hex.len() % 2 != 0
            || !is_lower_hex(&value.raw_data_hex)
            || value
                .text
                .as_ref()
                .is_some_and(|text| text.len() > MAX_TEXT_BYTES)
            || !matches!(
                value.name.as_str(),
                "DisplayName"
                    | "DisplayVersion"
                    | "Publisher"
                    | "InstallLocation"
                    | "InstallDate"
                    | "UninstallString"
                    | "QuietUninstallString"
                    | "DisplayIcon"
            )
            || value.type_name.as_str()
                != match value.registry_type {
                    1 => "REG_SZ",
                    2 => "REG_EXPAND_SZ",
                    _ => "unsupported",
                }
        {
            return None;
        }
        let decoded_text = if matches!(value.registry_type, 1 | 2) {
            decode_registry_text(&value.raw_data_hex)
        } else {
            None
        };
        if value.text != decoded_text {
            return None;
        }
        if values
            .insert(value.name.as_str(), value.text.as_deref())
            .is_some()
        {
            return None;
        }
    }
    let safe_value = |name: &str| {
        values
            .get(name)
            .and_then(|text| *text)
            .filter(|text| text.len() <= MAX_TEXT_BYTES)
            .map(str::to_owned)
    };
    let decoded_display_name = safe_value("DisplayName").filter(|name| !name.trim().is_empty());
    if row.display_name != decoded_display_name {
        return None;
    }
    let identity = WindowsSoftwareIdentity {
        source_id: source.id.clone(),
        hive: evidence.hive.clone(),
        registry_view: registry_view_name(evidence.registry_view).to_owned(),
        registry_key: evidence.registry_key.clone(),
        registry_subkey: row.registry_subkey.clone(),
        registry_subkey_utf16_hex: row.registry_subkey_utf16_hex.clone(),
    };
    let facts = WindowsSoftwareFacts {
        display_name: row.display_name.clone(),
        display_version: safe_value("DisplayVersion"),
        publisher: safe_value("Publisher"),
        evidence: WindowsSoftwareEvidenceReference {
            source_id: source.id.clone(),
            registration_index: evidence.registration_index,
        },
    };
    Some(Registration {
        identity,
        facts,
        source_id: source.id.clone(),
    })
}

impl InputEvidence {
    fn source_id(&self) -> &str {
        // The source is resolved by matching the immutable hive/view tuple; this placeholder is
        // replaced by source lookup in `normalize_registration` below.
        match (self.hive.as_str(), self.registry_view) {
            ("HKEY_CURRENT_USER", RegistryView::Native) => "current_user_native_uninstall",
            ("HKEY_CURRENT_USER", RegistryView::Wow64_32) => "current_user_32_uninstall",
            ("HKEY_LOCAL_MACHINE", RegistryView::Wow64_64) => "local_machine_64_uninstall",
            ("HKEY_LOCAL_MACHINE", RegistryView::Wow64_32) => "local_machine_32_uninstall",
            _ => "",
        }
    }
}

fn registry_view_name(view: RegistryView) -> &'static str {
    match view {
        RegistryView::Native => "native",
        RegistryView::Wow64_32 => "wow64_32",
        RegistryView::Wow64_64 => "wow64_64",
    }
}

fn decode_utf16_hex(hex: &str) -> Option<Vec<u16>> {
    if hex.len() % 4 != 0 || !is_lower_hex(hex) {
        return None;
    }
    hex.as_bytes()
        .chunks_exact(4)
        .map(|chunk| u16::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok())
        .collect()
}

fn decode_registry_text(hex: &str) -> Option<String> {
    if hex.len() % 4 != 0 || !is_lower_hex(hex) {
        return None;
    }
    let units = hex
        .as_bytes()
        .chunks_exact(4)
        .map(|chunk| {
            let low = u8::from_str_radix(std::str::from_utf8(&chunk[..2]).ok()?, 16).ok()?;
            let high = u8::from_str_radix(std::str::from_utf8(&chunk[2..]).ok()?, 16).ok()?;
            Some(u16::from_le_bytes([low, high]))
        })
        .collect::<Option<Vec<_>>>()?;
    let end = units
        .iter()
        .rposition(|unit| *unit != 0)
        .map_or(0, |index| index + 1);
    String::from_utf16(&units[..end]).ok()
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn changed_fields(before: &WindowsSoftwareFacts, after: &WindowsSoftwareFacts) -> Vec<String> {
    let mut changed = Vec::new();
    for (field, left, right) in [
        ("display_name", &before.display_name, &after.display_name),
        (
            "display_version",
            &before.display_version,
            &after.display_version,
        ),
        ("publisher", &before.publisher, &after.publisher),
    ] {
        if left.is_some() && right.is_some() && left != right {
            changed.push(field.to_owned());
        }
    }
    changed
}

fn push_delta(
    deltas: &mut Vec<WindowsSoftwareDelta>,
    delta: WindowsSoftwareDelta,
) -> Result<(), WindowsSoftwareComparisonError> {
    if deltas.len() >= MAX_DELTAS {
        return Err(WindowsSoftwareComparisonError::LimitExceeded);
    }
    deltas.push(delta);
    Ok(())
}

fn bounded_sources<'de, D>(deserializer: D) -> Result<Vec<InputSource>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded::<_, _, MAX_SOURCES>(deserializer)
}

fn bounded_registrations<'de, D>(deserializer: D) -> Result<Vec<InputRegistration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded::<_, _, MAX_REGISTRATIONS>(deserializer)
}

fn bounded_values<'de, D>(deserializer: D) -> Result<Vec<InputValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded::<_, _, MAX_VALUES_PER_REGISTRATION>(deserializer)
}

fn bounded_diagnostics<'de, D>(deserializer: D) -> Result<Vec<InputDiagnostic>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded::<_, _, MAX_DIAGNOSTICS>(deserializer)
}

fn deserialize_bounded<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVisitor<T, const LIMIT: usize>(std::marker::PhantomData<T>);
    impl<'de, T, const LIMIT: usize> de::Visitor<'de> for BoundedVisitor<T, LIMIT>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a sequence with at most {LIMIT} entries")
        }
        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut values = Vec::with_capacity(LIMIT.min(sequence.size_hint().unwrap_or(0)));
            while let Some(value) = sequence.next_element()? {
                if values.len() >= LIMIT {
                    return Err(de::Error::custom("sequence limit exceeded"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(BoundedVisitor::<T, MAX>(std::marker::PhantomData))
}
