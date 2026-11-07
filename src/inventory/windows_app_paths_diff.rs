//! Bounded comparison of selected Windows App Paths registrations.

use serde::{Deserialize, Serialize, de};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};

const SCHEMA: &str = "sideeffect.windows_app_path_inventory";
const SCOPE: &str = "selected_current_user_native_and_accessible_machine_32_bit_and_64_bit_app_paths_registry_entries";
const REGISTRY_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths";
const MAX_PAIR_BYTES: usize = 64 * 1024 * 1024;
const MAX_ROWS: usize = 4_096;
const MAX_SOURCES: usize = 3;
const MAX_DIAGNOSTICS_PER_SOURCE: usize = 16_384;
const MAX_DIAGNOSTIC_TEXT_BYTES: usize = 4_096;
const MAX_NAME_UNITS: usize = 1_024;
const MAX_VALUE_BYTES: usize = 64 * 1024;
const MAX_DELTAS: usize = 8_192;
const EVIDENCE_SOURCE: &str = "RegEnumKeyExW/RegQueryValueExW";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAppPathsComparisonStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAppPathsChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAppPathsComparisonDiagnostic {
    SourceIncomplete,
    InvalidIdentity,
    DuplicateIdentity,
    MatchedMetadataIncomplete,
}

/// The registered name is represented by a digest to avoid exposing it or its
/// potentially sensitive local path in comparison output.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WindowsAppPathsIdentity {
    pub source_id: String,
    pub hive: String,
    pub registry_view: String,
    pub registry_key: String,
    pub registered_name_utf16_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsAppPathsEvidenceReference {
    pub source_id: String,
    pub entry_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsAppPathsValueFacts {
    pub registry_type: u32,
    pub raw_data_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsAppPathsFacts {
    pub executable_path: Option<WindowsAppPathsValueFacts>,
    pub search_path: Option<WindowsAppPathsValueFacts>,
    pub evidence: WindowsAppPathsEvidenceReference,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsAppPathsDelta {
    pub kind: WindowsAppPathsChangeKind,
    pub identity: WindowsAppPathsIdentity,
    /// Field labels only; registry text and raw data are never returned.
    pub changed_fields: Vec<String>,
    pub before: Option<WindowsAppPathsFacts>,
    pub after: Option<WindowsAppPathsFacts>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsAppPathsCounts {
    pub additions: usize,
    pub removals: usize,
    pub changes: usize,
    pub unmatched_rows_with_incomplete_source: usize,
    pub invalid_identity_rows: usize,
    pub ambiguous_identity_groups: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsAppPathsInventoryComparison {
    pub schema: &'static str,
    pub schema_version: u32,
    pub before_captured_at_unix_ms: u128,
    pub after_captured_at_unix_ms: u128,
    pub status: WindowsAppPathsComparisonStatus,
    pub coverage_note: &'static str,
    pub counts: WindowsAppPathsCounts,
    pub diagnostics: Vec<WindowsAppPathsComparisonDiagnostic>,
    pub deltas: Vec<WindowsAppPathsDelta>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAppPathsComparisonError {
    MalformedInput,
    InputTooLarge,
    UnsupportedSchema,
    Incompatible,
    InvalidSourceSet,
    LimitExceeded,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    schema_version: u32,
    platform: String,
    scope: String,
    capture_started_at_unix_ms: u128,
    capture_ended_at_unix_ms: u128,
    status: InventoryStatus,
    #[serde(deserialize_with = "bounded_sources")]
    sources: Vec<SourceRecord>,
    #[serde(deserialize_with = "bounded_entries")]
    entries: Vec<Entry>,
    duplicate_registration_names: usize,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum RegistryView {
    Native,
    Wow64_32,
    Wow64_64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRecord {
    id: String,
    status: SourceStatus,
    entries_seen: usize,
    hive: String,
    registry_key: String,
    registry_view: RegistryView,
    #[serde(deserialize_with = "bounded_diagnostics")]
    diagnostics: Vec<SourceDiagnostic>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceDiagnostic {
    code: String,
    entry_index: Option<usize>,
    value_name: Option<String>,
    message: String,
    win32_error: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    registered_name: String,
    registered_name_utf16_hex: String,
    executable_path: Option<Value>,
    search_path: Option<Value>,
    #[serde(rename = "duplicate_registration_name")]
    _duplicate_registration_name: bool,
    evidence: Evidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Value {
    name: String,
    registry_type: u32,
    type_name: String,
    text: Option<String>,
    raw_data_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    source: String,
    hive: String,
    registry_view: RegistryView,
    registry_key: String,
    entry_index: usize,
    registry_subkey: String,
}

#[derive(Clone)]
struct NormalizedEntry {
    identity: WindowsAppPathsIdentity,
    key: IdentityKey,
    facts: WindowsAppPathsFacts,
    source_id: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct IdentityKey {
    source_id: String,
    hive: String,
    registry_view: RegistryView,
    registry_key: String,
    registered_name_utf16_hex: String,
}

/// Strictly deserialize and compare two Windows App Paths v1 artifacts.
pub fn compare_windows_app_paths_inventory_json(
    before_json: &[u8],
    after_json: &[u8],
) -> Result<WindowsAppPathsInventoryComparison, WindowsAppPathsComparisonError> {
    if before_json.len().saturating_add(after_json.len()) > MAX_PAIR_BYTES {
        return Err(WindowsAppPathsComparisonError::InputTooLarge);
    }
    let before: Document = serde_json::from_slice(before_json)
        .map_err(|_| WindowsAppPathsComparisonError::MalformedInput)?;
    let after: Document = serde_json::from_slice(after_json)
        .map_err(|_| WindowsAppPathsComparisonError::MalformedInput)?;
    compare_documents(before, after)
}

fn compare_documents(
    before: Document,
    after: Document,
) -> Result<WindowsAppPathsInventoryComparison, WindowsAppPathsComparisonError> {
    validate_document(&before)?;
    validate_document(&after)?;
    if before.platform != "windows" || after.platform != "windows" {
        return Err(WindowsAppPathsComparisonError::Incompatible);
    }
    if before.scope != SCOPE || after.scope != SCOPE || before.scope != after.scope {
        return Err(WindowsAppPathsComparisonError::Incompatible);
    }

    let mut diagnostics = BTreeSet::new();
    let before_complete = before.status == InventoryStatus::Complete;
    let after_complete = after.status == InventoryStatus::Complete;
    if !before_complete || !after_complete {
        diagnostics.insert(WindowsAppPathsComparisonDiagnostic::SourceIncomplete);
    }
    let (left, left_invalid, left_invalid_sources) = normalize_entries(&before);
    let (right, right_invalid, right_invalid_sources) = normalize_entries(&after);
    let invalid_identity_rows = left_invalid + right_invalid;
    if invalid_identity_rows > 0 {
        diagnostics.insert(WindowsAppPathsComparisonDiagnostic::InvalidIdentity);
    }

    let mut left_groups = group_entries(left);
    let mut right_groups = group_entries(right);
    let ambiguous: BTreeSet<_> = left_groups
        .duplicates
        .union(&right_groups.duplicates)
        .cloned()
        .collect();
    if !ambiguous.is_empty() {
        diagnostics.insert(WindowsAppPathsComparisonDiagnostic::DuplicateIdentity);
    }
    for key in &ambiguous {
        left_groups.rows.remove(key);
        right_groups.rows.remove(key);
    }

    let invalid_sources: BTreeSet<_> = left_invalid_sources
        .union(&right_invalid_sources)
        .cloned()
        .collect();
    let before_sources = source_map(&before.sources)?;
    let after_sources = source_map(&after.sources)?;
    let mut counts = WindowsAppPathsCounts {
        additions: 0,
        removals: 0,
        changes: 0,
        unmatched_rows_with_incomplete_source: 0,
        invalid_identity_rows,
        ambiguous_identity_groups: ambiguous.len(),
    };
    let mut deltas = Vec::new();
    let identities: BTreeSet<_> = left_groups
        .rows
        .keys()
        .chain(right_groups.rows.keys())
        .cloned()
        .collect();
    for key in identities {
        match (left_groups.rows.get(&key), right_groups.rows.get(&key)) {
            (Some(a), Some(b)) => {
                if a.facts.executable_path.is_none()
                    || b.facts.executable_path.is_none()
                    || (a.facts.search_path.is_none() != b.facts.search_path.is_none())
                {
                    diagnostics
                        .insert(WindowsAppPathsComparisonDiagnostic::MatchedMetadataIncomplete);
                }
                let fields = changed_fields(&a.facts, &b.facts);
                if !fields.is_empty() {
                    deltas.push(WindowsAppPathsDelta {
                        kind: WindowsAppPathsChangeKind::Changed,
                        identity: a.identity.clone(),
                        changed_fields: fields,
                        before: Some(a.facts.clone()),
                        after: Some(b.facts.clone()),
                    });
                    counts.changes += 1;
                }
            }
            (Some(row), None) | (None, Some(row)) => {
                let present_on_both_sides = source_is_presence_complete(
                    row.source_id.as_str(),
                    &before_sources,
                    &after_sources,
                );
                let affected_by_invalid_identity = invalid_sources.contains(&row.source_id);
                if !present_on_both_sides || affected_by_invalid_identity {
                    counts.unmatched_rows_with_incomplete_source += 1;
                    if !present_on_both_sides {
                        diagnostics.insert(WindowsAppPathsComparisonDiagnostic::SourceIncomplete);
                    }
                    if affected_by_invalid_identity {
                        diagnostics.insert(WindowsAppPathsComparisonDiagnostic::InvalidIdentity);
                    }
                } else if let Some(before_row) = left_groups.rows.get(&key) {
                    deltas.push(WindowsAppPathsDelta {
                        kind: WindowsAppPathsChangeKind::Removed,
                        identity: before_row.identity.clone(),
                        changed_fields: Vec::new(),
                        before: Some(before_row.facts.clone()),
                        after: None,
                    });
                    counts.removals += 1;
                } else if let Some(after_row) = right_groups.rows.get(&key) {
                    deltas.push(WindowsAppPathsDelta {
                        kind: WindowsAppPathsChangeKind::Added,
                        identity: after_row.identity.clone(),
                        changed_fields: Vec::new(),
                        before: None,
                        after: Some(after_row.facts.clone()),
                    });
                    counts.additions += 1;
                }
            }
            (None, None) => unreachable!("identity came from one of the maps"),
        }
        if deltas.len() > MAX_DELTAS {
            return Err(WindowsAppPathsComparisonError::LimitExceeded);
        }
    }

    Ok(WindowsAppPathsInventoryComparison {
        schema: "sideeffect.windows_app_path_inventory_diff",
        schema_version: 1,
        before_captured_at_unix_ms: before.capture_ended_at_unix_ms,
        after_captured_at_unix_ms: after.capture_ended_at_unix_ms,
        status: if diagnostics.is_empty() {
            WindowsAppPathsComparisonStatus::Complete
        } else {
            WindowsAppPathsComparisonStatus::Partial
        },
        coverage_note: "Compares selected Windows App Paths registry registrations by exact source and UTF-16 subkey evidence; values are hashed and registrations do not establish that a target exists, is installed, available, or launchable.",
        counts,
        diagnostics: diagnostics.into_iter().collect(),
        deltas,
    })
}

fn validate_document(document: &Document) -> Result<(), WindowsAppPathsComparisonError> {
    if document.schema != SCHEMA || document.schema_version != 1 {
        return Err(WindowsAppPathsComparisonError::UnsupportedSchema);
    }
    if document.capture_ended_at_unix_ms < document.capture_started_at_unix_ms
        || document.sources.len() != MAX_SOURCES
        || document.entries.len() > MAX_ROWS
        || document.duplicate_registration_names > MAX_ROWS
    {
        return Err(WindowsAppPathsComparisonError::MalformedInput);
    }
    let expected_complete = document.sources.iter().all(|source| {
        matches!(
            source.status,
            SourceStatus::Complete | SourceStatus::NotPresent
        )
    });
    if expected_complete != (document.status == InventoryStatus::Complete) {
        return Err(WindowsAppPathsComparisonError::MalformedInput);
    }
    let mut ids = BTreeSet::new();
    for source in &document.sources {
        let Some((hive, view)) = expected_source_tuple(&source.id) else {
            return Err(WindowsAppPathsComparisonError::InvalidSourceSet);
        };
        if !ids.insert(source.id.as_str())
            || source.hive != hive
            || source.registry_view != view
            || source.registry_key != REGISTRY_KEY
            || source.entries_seen > MAX_ROWS
            || source.diagnostics.len() > MAX_DIAGNOSTICS_PER_SOURCE
        {
            return Err(WindowsAppPathsComparisonError::MalformedInput);
        }
        if source.status == SourceStatus::Complete && !source.diagnostics.is_empty() {
            return Err(WindowsAppPathsComparisonError::MalformedInput);
        }
        if source.diagnostics.iter().any(|diagnostic| {
            diagnostic.code.len() > 128
                || diagnostic.message.len() > MAX_DIAGNOSTIC_TEXT_BYTES
                || diagnostic
                    .value_name
                    .as_ref()
                    .is_some_and(|name| name.len() > 32)
                || diagnostic
                    .entry_index
                    .is_some_and(|index| index >= MAX_ROWS)
                || diagnostic.win32_error == Some(0)
        }) {
            return Err(WindowsAppPathsComparisonError::MalformedInput);
        }
    }
    if ids != expected_source_ids() {
        return Err(WindowsAppPathsComparisonError::InvalidSourceSet);
    }
    let sources = source_map(&document.sources)?;
    let mut indices = BTreeSet::new();
    let mut entries_per_source = BTreeMap::<&str, usize>::new();
    for entry in &document.entries {
        let source_id = source_id_for(entry.evidence.hive.as_str(), entry.evidence.registry_view);
        let source = source_id.and_then(|id| sources.get(id).copied());
        if entry.evidence.source.len() > 64
            || entry.evidence.hive.len() > 64
            || entry.evidence.registry_key.len() > 256
            || entry.evidence.registry_subkey.len() > MAX_NAME_UNITS * 4
        {
            return Err(WindowsAppPathsComparisonError::MalformedInput);
        }
        if entry.evidence.entry_index >= MAX_ROWS
            || !indices.insert((
                source_id.unwrap_or("unknown").to_owned(),
                entry.evidence.entry_index,
            ))
            || entry.registered_name.len() > MAX_NAME_UNITS * 4
            || !valid_utf16_hex(&entry.registered_name_utf16_hex)
            || entry
                .executable_path
                .as_ref()
                .is_some_and(|v| !valid_value(v, "(Default)"))
            || entry
                .search_path
                .as_ref()
                .is_some_and(|v| !valid_value(v, "Path"))
        {
            return Err(WindowsAppPathsComparisonError::MalformedInput);
        }
        if source.is_some_and(|record| record.status == SourceStatus::NotPresent) {
            return Err(WindowsAppPathsComparisonError::MalformedInput);
        }
        if let Some(source_id) = source_id {
            *entries_per_source.entry(source_id).or_default() += 1;
        }
    }
    for source in &document.sources {
        let rows = entries_per_source
            .get(source.id.as_str())
            .copied()
            .unwrap_or(0);
        if rows > source.entries_seen
            || (source.status == SourceStatus::Complete && rows != source.entries_seen)
        {
            return Err(WindowsAppPathsComparisonError::MalformedInput);
        }
    }
    if document.duplicate_registration_names
        != document
            .entries
            .iter()
            .filter(|entry| entry._duplicate_registration_name)
            .count()
    {
        return Err(WindowsAppPathsComparisonError::MalformedInput);
    }
    Ok(())
}

fn valid_value(value: &Value, expected_name: &str) -> bool {
    let type_name = match value.registry_type {
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        _ => "unsupported",
    };
    value.name == expected_name
        && value.type_name == type_name
        && value.raw_data_hex.len() <= MAX_VALUE_BYTES * 2
        && value.raw_data_hex.len() % 2 == 0
        && value
            .raw_data_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value
            .text
            .as_ref()
            .is_none_or(|text| text.len() <= MAX_VALUE_BYTES * 2)
}

fn valid_utf16_name(text: &str, hex: &str) -> bool {
    let units = decode_utf16_hex(hex);
    units.len() <= MAX_NAME_UNITS && String::from_utf16(&units).ok().as_deref() == Some(text)
}

fn valid_utf16_hex(hex: &str) -> bool {
    if hex.is_empty()
        || hex.len() > MAX_NAME_UNITS * 4
        || hex.len() % 4 != 0
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return false;
    }
    true
}

fn decode_utf16_hex(value: &str) -> Vec<u16> {
    value
        .as_bytes()
        .chunks_exact(4)
        .map(|chunk| u16::from_str_radix(std::str::from_utf8(chunk).unwrap_or(""), 16).unwrap_or(0))
        .collect()
}

fn normalize_entries(document: &Document) -> (Vec<NormalizedEntry>, usize, BTreeSet<String>) {
    let sources = source_map(&document.sources).expect("validated source list");
    let mut entries = Vec::with_capacity(document.entries.len());
    let mut invalid_sources = BTreeSet::new();
    let mut invalid = 0usize;
    for row in &document.entries {
        let evidence = &row.evidence;
        let Some(source_id) = source_id_for(evidence.hive.as_str(), evidence.registry_view) else {
            invalid += 1;
            invalid_sources.extend(source_ids().iter().map(|id| (*id).to_owned()));
            continue;
        };
        let Some(source) = sources.get(source_id) else {
            invalid += 1;
            invalid_sources.extend(source_ids().iter().map(|id| (*id).to_owned()));
            continue;
        };
        let expected = expected_source_tuple(source_id).expect("source set validated");
        let key = IdentityKey {
            source_id: source_id.to_owned(),
            hive: evidence.hive.clone(),
            registry_view: evidence.registry_view,
            registry_key: evidence.registry_key.clone(),
            registered_name_utf16_hex: row.registered_name_utf16_hex.to_ascii_lowercase(),
        };
        let invalid_row = evidence.hive != expected.0
            || evidence.source != EVIDENCE_SOURCE
            || evidence.registry_view != expected.1
            || evidence.registry_key != REGISTRY_KEY
            || evidence.registry_subkey != row.registered_name
            || evidence.entry_index >= source.entries_seen
            || !valid_utf16_name(&row.registered_name, &row.registered_name_utf16_hex);
        if invalid_row {
            invalid += 1;
            invalid_sources.insert(source.id.clone());
            continue;
        }
        let identity = identity(&key);
        entries.push(NormalizedEntry {
            identity,
            key,
            facts: facts(row),
            source_id: source_id.to_owned(),
        });
    }
    (entries, invalid, invalid_sources)
}

struct EntryGroups {
    rows: BTreeMap<IdentityKey, NormalizedEntry>,
    duplicates: BTreeSet<IdentityKey>,
}

fn group_entries(rows: Vec<NormalizedEntry>) -> EntryGroups {
    let mut groups = BTreeMap::<IdentityKey, Vec<NormalizedEntry>>::new();
    for row in rows {
        groups.entry(row.key.clone()).or_default().push(row);
    }
    let mut indexed = BTreeMap::new();
    let mut duplicates = BTreeSet::new();
    for (key, rows) in groups {
        if rows.len() == 1 {
            indexed.insert(key, rows.into_iter().next().unwrap());
        } else {
            duplicates.insert(key);
        }
    }
    EntryGroups {
        rows: indexed,
        duplicates,
    }
}

fn identity(key: &IdentityKey) -> WindowsAppPathsIdentity {
    WindowsAppPathsIdentity {
        source_id: key.source_id.clone(),
        hive: key.hive.clone(),
        registry_view: match key.registry_view {
            RegistryView::Native => "native",
            RegistryView::Wow64_32 => "wow64_32",
            RegistryView::Wow64_64 => "wow64_64",
        }
        .to_owned(),
        registry_key: key.registry_key.clone(),
        registered_name_utf16_sha256: sha256_hex(key.registered_name_utf16_hex.as_bytes()),
    }
}

fn facts(row: &Entry) -> WindowsAppPathsFacts {
    WindowsAppPathsFacts {
        executable_path: row.executable_path.as_ref().map(value_facts),
        search_path: row.search_path.as_ref().map(value_facts),
        evidence: WindowsAppPathsEvidenceReference {
            source_id: source_id_for(row.evidence.hive.as_str(), row.evidence.registry_view)
                .unwrap_or("unknown")
                .to_owned(),
            entry_index: row.evidence.entry_index,
        },
    }
}

fn value_facts(value: &Value) -> WindowsAppPathsValueFacts {
    WindowsAppPathsValueFacts {
        registry_type: value.registry_type,
        raw_data_sha256: sha256_hex(&decode_hex(&value.raw_data_hex)),
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or(""), 16).unwrap_or(0))
        .collect()
}

fn changed_fields(before: &WindowsAppPathsFacts, after: &WindowsAppPathsFacts) -> Vec<String> {
    let mut fields = Vec::new();
    if before.executable_path != after.executable_path {
        fields.push("executable_path".to_owned());
    }
    if before.search_path != after.search_path {
        fields.push("search_path".to_owned());
    }
    fields
}

fn source_is_presence_complete(
    source_id: &str,
    before: &BTreeMap<&str, &SourceRecord>,
    after: &BTreeMap<&str, &SourceRecord>,
) -> bool {
    before
        .get(source_id)
        .is_some_and(|s| matches!(s.status, SourceStatus::Complete | SourceStatus::NotPresent))
        && after
            .get(source_id)
            .is_some_and(|s| matches!(s.status, SourceStatus::Complete | SourceStatus::NotPresent))
}

fn source_map(
    sources: &[SourceRecord],
) -> Result<BTreeMap<&str, &SourceRecord>, WindowsAppPathsComparisonError> {
    let mut map = BTreeMap::new();
    for source in sources {
        if map.insert(source.id.as_str(), source).is_some() {
            return Err(WindowsAppPathsComparisonError::InvalidSourceSet);
        }
    }
    Ok(map)
}

fn expected_source_tuple(id: &str) -> Option<(&'static str, RegistryView)> {
    match id {
        "current_user_native_app_paths" => Some(("HKEY_CURRENT_USER", RegistryView::Native)),
        "local_machine_64_app_paths" => Some(("HKEY_LOCAL_MACHINE", RegistryView::Wow64_64)),
        "local_machine_32_app_paths" => Some(("HKEY_LOCAL_MACHINE", RegistryView::Wow64_32)),
        _ => None,
    }
}

fn source_id_for(hive: &str, view: RegistryView) -> Option<&'static str> {
    source_ids().into_iter().find(|id| {
        expected_source_tuple(id).is_some_and(|(expected_hive, expected_view)| {
            hive == expected_hive && view == expected_view
        })
    })
}

fn source_ids() -> [&'static str; MAX_SOURCES] {
    [
        "current_user_native_app_paths",
        "local_machine_64_app_paths",
        "local_machine_32_app_paths",
    ]
}

fn expected_source_ids() -> BTreeSet<&'static str> {
    source_ids().into_iter().collect()
}

fn bounded_sources<'de, D>(deserializer: D) -> Result<Vec<SourceRecord>, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserialize_bounded::<_, _, MAX_SOURCES>(deserializer)
}
fn bounded_entries<'de, D>(deserializer: D) -> Result<Vec<Entry>, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserialize_bounded::<_, _, MAX_ROWS>(deserializer)
}
fn bounded_diagnostics<'de, D>(deserializer: D) -> Result<Vec<SourceDiagnostic>, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserialize_bounded::<_, _, MAX_DIAGNOSTICS_PER_SOURCE>(deserializer)
}
fn deserialize_bounded<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T, const N: usize>(std::marker::PhantomData<T>);
    impl<'de, T, const N: usize> de::Visitor<'de> for Visitor<T, N>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a sequence with at most {N} entries")
        }
        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(N));
            while let Some(value) = sequence.next_element()? {
                if values.len() >= N {
                    return Err(de::Error::custom("sequence limit exceeded"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Visitor::<T, MAX>(std::marker::PhantomData))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", sha2::Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value as JsonValue, json};
    use std::fmt::Write as _;

    const USER: &str = "current_user_native_app_paths";
    const MACHINE64: &str = "local_machine_64_app_paths";
    const MACHINE32: &str = "local_machine_32_app_paths";

    fn source(id: &str, status: &str, seen: usize) -> JsonValue {
        let (hive, view) = match id {
            USER => ("HKEY_CURRENT_USER", "native"),
            MACHINE64 => ("HKEY_LOCAL_MACHINE", "wow64_64"),
            _ => ("HKEY_LOCAL_MACHINE", "wow64_32"),
        };
        json!({"id":id,"status":status,"entries_seen":seen,"hive":hive,
            "registry_key":REGISTRY_KEY,"registry_view":view,"diagnostics":[]})
    }

    fn entry(index: usize, name: &str, value: &str) -> JsonValue {
        let mut utf16_hex = String::with_capacity(name.encode_utf16().count() * 4);
        for unit in name.encode_utf16() {
            write!(&mut utf16_hex, "{unit:04x}").unwrap();
        }
        let mut value_hex = String::with_capacity(value.encode_utf16().count() * 4);
        for byte in value.encode_utf16().flat_map(u16::to_le_bytes) {
            write!(&mut value_hex, "{byte:02x}").unwrap();
        }
        json!({
            "registered_name":name,
            "registered_name_utf16_hex":utf16_hex,
            "executable_path":{"name":"(Default)","registry_type":1,"type_name":"REG_SZ","text":value,"raw_data_hex":value_hex},
            "search_path":null,
            "duplicate_registration_name":false,
            "evidence":{"source":"RegEnumKeyExW/RegQueryValueExW","hive":"HKEY_CURRENT_USER","registry_view":"native",
                "registry_key":REGISTRY_KEY,"entry_index":index,"registry_subkey":name}
        })
    }

    fn document(entries: Vec<JsonValue>, user_status: &str, user_seen: usize) -> Vec<u8> {
        let duplicate_registration_names = entries
            .iter()
            .filter(|entry| entry["duplicate_registration_name"] == true)
            .count();
        serde_json::to_vec(&json!({
            "schema":SCHEMA,"schema_version":1,"platform":"windows","scope":SCOPE,
            "capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,
            "status":if user_status == "complete" {"complete"} else {"partial"},
            "sources":[source(USER,user_status,user_seen),source(MACHINE64,"not_present",0),source(MACHINE32,"not_present",0)],
            "entries":entries,
            "duplicate_registration_names":duplicate_registration_names
        })).unwrap()
    }

    #[test]
    fn reports_value_changes_without_emitting_registry_text() {
        let before = document(
            vec![entry(0, "demo.exe", "C:\\one\\demo.exe")],
            "complete",
            1,
        );
        let after = document(
            vec![entry(0, "demo.exe", "C:\\two\\demo.exe")],
            "complete",
            1,
        );
        let result = compare_windows_app_paths_inventory_json(&before, &after).unwrap();
        assert_eq!(result.status, WindowsAppPathsComparisonStatus::Complete);
        assert_eq!(result.counts.changes, 1);
        assert_eq!(result.deltas[0].changed_fields, ["executable_path"]);
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("demo.exe"));
        assert!(!encoded.contains("C:\\one"));
        assert_eq!(
            result.deltas[0]
                .before
                .as_ref()
                .unwrap()
                .evidence
                .entry_index,
            0
        );
    }

    #[test]
    fn reports_presence_only_for_complete_source_pairs() {
        let before = document(
            vec![entry(0, "demo.exe", "C:\\one\\demo.exe")],
            "complete",
            1,
        );
        let after = document(vec![], "complete", 0);
        let complete = compare_windows_app_paths_inventory_json(&before, &after).unwrap();
        assert_eq!(complete.counts.removals, 1);

        let after_partial = document(vec![], "partial", 0);
        let partial = compare_windows_app_paths_inventory_json(&before, &after_partial).unwrap();
        assert_eq!(partial.status, WindowsAppPathsComparisonStatus::Partial);
        assert_eq!(partial.counts.removals, 0);
        assert_eq!(partial.counts.unmatched_rows_with_incomplete_source, 1);
    }

    #[test]
    fn duplicate_names_are_ambiguous_and_suppress_presence() {
        let before = document(
            vec![entry(0, "demo.exe", "C:\\one\\demo.exe")],
            "complete",
            1,
        );
        let mut duplicate = entry(1, "demo.exe", "C:\\two\\demo.exe");
        duplicate["duplicate_registration_name"] = json!(true);
        let mut after: JsonValue = serde_json::from_slice(&document(
            vec![entry(0, "demo.exe", "C:\\one\\demo.exe"), duplicate],
            "complete",
            2,
        ))
        .unwrap();
        after["sources"][0]["entries_seen"] = json!(2);
        let after = serde_json::to_vec(&after).unwrap();
        let result = compare_windows_app_paths_inventory_json(&before, &after).unwrap();
        assert_eq!(result.counts.ambiguous_identity_groups, 1);
        assert_eq!(result.counts.additions + result.counts.removals, 0);
        assert!(result.deltas.is_empty());
    }

    #[test]
    fn rejects_bad_contract_and_oversized_pair() {
        let good = document(vec![], "complete", 0);
        let mut wrong: JsonValue = serde_json::from_slice(&good).unwrap();
        wrong["schema_version"] = json!(2);
        assert!(matches!(
            compare_windows_app_paths_inventory_json(&serde_json::to_vec(&wrong).unwrap(), &good),
            Err(WindowsAppPathsComparisonError::UnsupportedSchema)
        ));
        let oversized = vec![b' '; MAX_PAIR_BYTES / 2 + 1];
        assert!(matches!(
            compare_windows_app_paths_inventory_json(&oversized, &oversized),
            Err(WindowsAppPathsComparisonError::InputTooLarge)
        ));
    }

    #[test]
    fn invalid_identity_makes_presence_partial() {
        let before = document(
            vec![entry(0, "demo.exe", "C:\\one\\demo.exe")],
            "complete",
            1,
        );
        let mut invalid = entry(0, "demo.exe", "C:\\two\\demo.exe");
        invalid["registered_name_utf16_hex"] = json!("00d8");
        let after = document(vec![invalid], "complete", 1);
        let result = compare_windows_app_paths_inventory_json(&before, &after).unwrap();
        assert_eq!(result.status, WindowsAppPathsComparisonStatus::Partial);
        assert_eq!(result.counts.invalid_identity_rows, 1);
        assert_eq!(result.counts.removals, 0);
        assert_eq!(result.counts.unmatched_rows_with_incomplete_source, 1);
    }
}
