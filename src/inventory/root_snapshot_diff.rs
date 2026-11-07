//! Bounded comparison of exact selected-root snapshots, including opt-in content hashes.

use serde::Serialize;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const INPUT_SCHEMA: &str = "sideeffect.selected_root_inventory";
const OUTPUT_SCHEMA: &str = "sideeffect.selected_root_inventory_diff";
const OUTPUT_SCHEMA_VERSION: u32 = 1;
const SCOPE_V1: &str = "one_explicit_root_and_its_direct_children_metadata_only";
const SCOPE_V2: &str = "one_explicit_root_and_its_direct_children_metadata_and_opt_in_sha256";
const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_COLLECTION: usize = 20_000;
const MAX_NODES: usize = 400_000;
const MAX_STRING_BYTES: usize = 128 * 1024;
const MAX_OBJECT_KEY_BYTES: usize = 64;
const MAX_ENTRIES: usize = 10_000;
const MAX_DIAGNOSTICS: usize = 256;
const MAX_PATH_BYTES: usize = 4_095;
const MAX_PATH_UNITS: usize = 32_766;
const MAX_NAME_BYTES_OR_UNITS: usize = 32_767;
const MAX_AGGREGATE_NAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_DEADLINE_SECONDS: u64 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootSnapshotDiffError {
    MalformedInput,
    InputTooLarge,
    UnsupportedSchema,
    PlatformMismatch,
    ScopeMismatch,
    RootMismatch,
    LimitExceeded,
}

#[derive(Debug, Serialize)]
pub struct RootSnapshotDiff {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub status: &'static str,
    pub root_path_identity_hex: String,
    pub root_path_encoding: &'static str,
    pub root_identity_hint_conflict: bool,
    pub coverage_note: &'static str,
    pub counts: RootSnapshotDiffCounts,
    pub diagnostics: Vec<&'static str>,
    pub deltas: Vec<RootSnapshotDelta>,
}

#[derive(Debug, Default, Serialize)]
pub struct RootSnapshotDiffCounts {
    pub matched: usize,
    pub unchanged: usize,
    pub additions: usize,
    pub removals: usize,
    pub changes: usize,
    pub uncertain_matches: usize,
    pub ambiguous_name_groups: usize,
    pub unmatched_rows_suppressed: usize,
}

#[derive(Debug, Serialize)]
pub struct RootSnapshotDelta {
    pub kind: &'static str,
    pub name: String,
    pub name_identity_hex: String,
    pub changed_fields: Vec<&'static str>,
    pub unknown_fields: Vec<&'static str>,
    pub before: Option<RootSnapshotSide>,
    pub after: Option<RootSnapshotSide>,
}

#[derive(Debug, Serialize)]
pub struct RootSnapshotSide {
    pub row_index: usize,
    pub entry_ordinal: usize,
    pub evidence_source: &'static str,
    pub object_type: String,
    pub size_bytes: Option<u64>,
    pub modified_at_unix_ms: Option<i128>,
    pub device_or_volume_serial_hint: Option<u64>,
    pub inode_or_file_index_hint: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    schema_version: u32,
    platform: String,
    scope: String,
    captured_started_at_unix_ms: u128,
    captured_ended_at_unix_ms: u128,
    status: String,
    root: Option<RootIdentity>,
    entries: Vec<Entry>,
    diagnostics: Vec<Diagnostic>,
    limits: Limits,
    #[serde(default)]
    content_hashing: Option<ContentHashing>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentHashing {
    requested: bool,
    algorithm: String,
    max_file_bytes: u64,
    max_aggregate_bytes: u64,
    deadline_seconds: u64,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RootIdentity {
    display_path: String,
    #[serde(default)]
    path_bytes_hex: Option<String>,
    #[serde(default)]
    path_utf16le_hex: Option<String>,
    object_type: String,
    device_or_volume_serial: Option<u64>,
    inode_or_file_index: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    ordinal: usize,
    display_name: String,
    #[serde(default)]
    name_bytes_hex: Option<String>,
    #[serde(default)]
    name_utf16le_hex: Option<String>,
    object_type: String,
    size_bytes: Option<u64>,
    modified_at_unix_ms: Option<i128>,
    device_or_volume_serial: Option<u64>,
    inode_or_file_index: Option<u64>,
    evidence: Evidence,
    #[serde(default)]
    content_sha256: Option<String>,
    #[serde(default)]
    content_hash_status: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    source: String,
    entry_ordinal: usize,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Diagnostic {
    code: String,
    entry_ordinal: Option<usize>,
    native_error: Option<u32>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    max_root_path_bytes_or_utf16_units: usize,
    max_entries: usize,
    max_name_bytes_or_utf16_units: usize,
    max_aggregate_name_bytes: usize,
    deadline_seconds: u64,
}

#[derive(Default)]
struct JsonBudget(usize);

struct ValueSeed<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

struct KeySeed;

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > MAX_DEPTH {
            return Err(serde::de::Error::custom("JSON nesting limit exceeded"));
        }
        self.budget.0 = self
            .budget
            .0
            .checked_add(1)
            .ok_or_else(|| serde::de::Error::custom("JSON node limit exceeded"))?;
        if self.budget.0 > MAX_NODES {
            return Err(serde::de::Error::custom("JSON node limit exceeded"));
        }
        deserializer.deserialize_any(ValueVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct ValueVisitor<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
        Ok(Value::Number(
            serde_json::Number::from_f64(value).ok_or_else(|| E::custom("invalid JSON number"))?,
        ))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        if value.len() > MAX_STRING_BYTES {
            return Err(E::custom("JSON string limit exceeded"));
        }
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        if value.len() > MAX_STRING_BYTES {
            return Err(E::custom("JSON string limit exceeded"));
        }
        Ok(Value::String(value))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        ValueSeed {
            budget: self.budget,
            depth: self.depth + 1,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while values.len() < MAX_COLLECTION {
            match seq.next_element_seed(ValueSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })? {
                Some(value) => values.push(value),
                None => return Ok(Value::Array(values)),
            }
        }
        if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom("JSON array limit exceeded"));
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key_seed(KeySeed)? {
            if values.len() >= MAX_COLLECTION || values.contains_key(&key) {
                return Err(serde::de::Error::custom(
                    "JSON object limit or duplicate key",
                ));
            }
            let value = map.next_value_seed(ValueSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

impl<'de> DeserializeSeed<'de> for KeySeed {
    type Value = String;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<String, D::Error> {
        struct KeyVisitor;
        impl Visitor<'_> for KeyVisitor {
            type Value = String;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded JSON object key")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<String, E> {
                if value.len() > MAX_OBJECT_KEY_BYTES {
                    return Err(E::custom("JSON object key limit exceeded"));
                }
                Ok(value.to_owned())
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<String, E> {
                if value.len() > MAX_OBJECT_KEY_BYTES {
                    return Err(E::custom("JSON object key limit exceeded"));
                }
                Ok(value)
            }
        }
        deserializer.deserialize_string(KeyVisitor)
    }
}

fn parse_bounded_value(bytes: &[u8]) -> Result<Value, RootSnapshotDiffError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(RootSnapshotDiffError::InputTooLarge);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let mut budget = JsonBudget::default();
    let value = ValueSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| RootSnapshotDiffError::MalformedInput)?;
    deserializer
        .end()
        .map_err(|_| RootSnapshotDiffError::MalformedInput)?;
    Ok(value)
}

pub fn is_selected_root_inventory_json(bytes: &[u8]) -> bool {
    parse_bounded_value(bytes)
        .ok()
        .and_then(|value| {
            value
                .get("schema")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .is_some_and(|schema| schema == INPUT_SCHEMA)
}

pub fn compare_selected_root_inventory_json(
    before: &[u8],
    after: &[u8],
) -> Result<RootSnapshotDiff, RootSnapshotDiffError> {
    if before.len().saturating_add(after.len()) > MAX_INPUT_BYTES {
        return Err(RootSnapshotDiffError::InputTooLarge);
    }
    let left = parse_document(before)?;
    let right = parse_document(after)?;
    if left.schema != INPUT_SCHEMA
        || right.schema != INPUT_SCHEMA
        || !matches!(left.schema_version, 1 | 2)
        || !matches!(right.schema_version, 1 | 2)
    {
        return Err(RootSnapshotDiffError::UnsupportedSchema);
    }
    if left.platform != right.platform || !matches!(left.platform.as_str(), "linux" | "windows") {
        return Err(RootSnapshotDiffError::PlatformMismatch);
    }
    validate(&left)?;
    validate(&right)?;
    compare(&left, &right)
}

fn parse_document(bytes: &[u8]) -> Result<Document, RootSnapshotDiffError> {
    let value = parse_bounded_value(bytes)?;
    serde_json::from_value(value).map_err(|_| RootSnapshotDiffError::MalformedInput)
}

fn validate(document: &Document) -> Result<(), RootSnapshotDiffError> {
    let expected_scope = match document.schema_version {
        1 => SCOPE_V1,
        2 => SCOPE_V2,
        _ => return Err(RootSnapshotDiffError::UnsupportedSchema),
    };
    if document.scope != expected_scope {
        return Err(RootSnapshotDiffError::ScopeMismatch);
    }
    if !matches!(document.status.as_str(), "complete" | "partial")
        || document.entries.len() > MAX_ENTRIES
        || document.diagnostics.len() > MAX_DIAGNOSTICS
        || (document.status == "complete" && !document.diagnostics.is_empty())
        || document.limits.max_entries != MAX_ENTRIES
        || document.limits.max_name_bytes_or_utf16_units != MAX_NAME_BYTES_OR_UNITS
        || document.limits.max_aggregate_name_bytes != MAX_AGGREGATE_NAME_BYTES
        || document.limits.deadline_seconds != MAX_DEADLINE_SECONDS
        || document.entries.iter().any(|entry| {
            entry.ordinal >= MAX_ENTRIES || entry.evidence.entry_ordinal != entry.ordinal
        })
    {
        return Err(RootSnapshotDiffError::LimitExceeded);
    }
    let expected_root_limit = match document.platform.as_str() {
        "linux" => MAX_PATH_BYTES,
        "windows" => MAX_PATH_UNITS,
        _ => return Err(RootSnapshotDiffError::PlatformMismatch),
    };
    if document.limits.max_root_path_bytes_or_utf16_units != expected_root_limit {
        return Err(RootSnapshotDiffError::LimitExceeded);
    }
    if document.captured_ended_at_unix_ms < document.captured_started_at_unix_ms {
        return Err(RootSnapshotDiffError::MalformedInput);
    }
    match (document.schema_version, document.content_hashing.as_ref()) {
        (1, None) => {}
        (2, Some(h))
            if h.requested
                && h.algorithm == "sha256"
                && h.max_file_bytes == 16 * 1024 * 1024
                && h.max_aggregate_bytes == 64 * 1024 * 1024
                && h.deadline_seconds == 5 => {}
        _ => return Err(RootSnapshotDiffError::MalformedInput),
    }
    let root = document
        .root
        .as_ref()
        .ok_or(RootSnapshotDiffError::MalformedInput)?;
    if root.object_type != "directory"
        || root.display_path.is_empty()
        || root.display_path.len() > MAX_STRING_BYTES
    {
        return Err(RootSnapshotDiffError::MalformedInput);
    }
    root_identity(root, &document.platform)?;

    let mut ordinals = BTreeSet::new();
    let mut aggregate_name_bytes = 0usize;
    for entry in &document.entries {
        if entry.display_name.len() > MAX_STRING_BYTES
            || !valid_object_type(&document.platform, &entry.object_type)
            || entry.evidence.source != "selected_root_directory_entry"
            || !ordinals.insert(entry.ordinal)
        {
            return Err(RootSnapshotDiffError::MalformedInput);
        }
        match (
            entry.content_sha256.as_deref(),
            entry.content_hash_status.as_deref(),
        ) {
            (None, None) if document.schema_version == 1 => {}
            (Some(hash), Some("observed"))
                if document.schema_version == 2
                    && is_regular(&entry.object_type)
                    && valid_sha256(hash) => {}
            (None, Some("unavailable"))
                if document.schema_version == 2 && is_regular(&entry.object_type) => {}
            (None, Some("not_applicable"))
                if document.schema_version == 2 && !is_regular(&entry.object_type) => {}
            _ => return Err(RootSnapshotDiffError::MalformedInput),
        }
        if document.status == "complete"
            && entry.content_hash_status.as_deref() == Some("unavailable")
        {
            return Err(RootSnapshotDiffError::MalformedInput);
        }
        let identity = name_identity(entry, &document.platform)?;
        let name_units = if document.platform == "windows" {
            identity.len() / 4
        } else {
            identity.len() / 2
        };
        let bytes_len = if document.platform == "windows" {
            name_units
                .checked_mul(2)
                .ok_or(RootSnapshotDiffError::LimitExceeded)?
        } else {
            name_units
        };
        aggregate_name_bytes = aggregate_name_bytes
            .checked_add(bytes_len)
            .ok_or(RootSnapshotDiffError::LimitExceeded)?;
        if aggregate_name_bytes > MAX_AGGREGATE_NAME_BYTES {
            return Err(RootSnapshotDiffError::LimitExceeded);
        }
    }
    for diagnostic in &document.diagnostics {
        if diagnostic.code.len() > 128
            || diagnostic
                .entry_ordinal
                .is_some_and(|ordinal| ordinal > MAX_ENTRIES)
        {
            return Err(RootSnapshotDiffError::MalformedInput);
        }
        let _ = diagnostic.native_error;
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_object_type(platform: &str, kind: &str) -> bool {
    match platform {
        "linux" => matches!(
            kind,
            "regular_file"
                | "directory"
                | "symbolic_link"
                | "fifo"
                | "socket"
                | "character_device"
                | "block_device"
                | "unknown"
        ),
        "windows" => matches!(
            kind,
            "directory" | "reparse_point" | "regular_or_other_file"
        ),
        _ => false,
    }
}

fn root_identity<'a>(
    root: &'a RootIdentity,
    platform: &str,
) -> Result<&'a str, RootSnapshotDiffError> {
    match platform {
        "linux" => {
            if root.path_utf16le_hex.is_some() {
                return Err(RootSnapshotDiffError::MalformedInput);
            }
            let identity = root
                .path_bytes_hex
                .as_deref()
                .ok_or(RootSnapshotDiffError::MalformedInput)?;
            validate_hex(identity, 2, MAX_PATH_BYTES, false)?;
            if identity
                .as_bytes()
                .chunks_exact(2)
                .any(|pair| pair == b"00")
            {
                return Err(RootSnapshotDiffError::MalformedInput);
            }
            Ok(identity)
        }
        "windows" => {
            if root.path_bytes_hex.is_some() {
                return Err(RootSnapshotDiffError::MalformedInput);
            }
            let identity = root
                .path_utf16le_hex
                .as_deref()
                .ok_or(RootSnapshotDiffError::MalformedInput)?;
            validate_hex(identity, 4, MAX_PATH_UNITS, false)?;
            if identity
                .as_bytes()
                .chunks_exact(4)
                .any(|unit| unit == b"0000")
            {
                return Err(RootSnapshotDiffError::MalformedInput);
            }
            Ok(identity)
        }
        _ => Err(RootSnapshotDiffError::PlatformMismatch),
    }
}

fn name_identity<'a>(entry: &'a Entry, platform: &str) -> Result<&'a str, RootSnapshotDiffError> {
    match platform {
        "linux" => {
            if entry.name_utf16le_hex.is_some() {
                return Err(RootSnapshotDiffError::MalformedInput);
            }
            let identity = entry
                .name_bytes_hex
                .as_deref()
                .ok_or(RootSnapshotDiffError::MalformedInput)?;
            validate_hex(identity, 2, MAX_NAME_BYTES_OR_UNITS, false)?;
            if identity
                .as_bytes()
                .chunks_exact(2)
                .any(|pair| pair == b"00" || pair == b"2f")
            {
                return Err(RootSnapshotDiffError::MalformedInput);
            }
            if identity == "2e" || identity == "2e2e" {
                return Err(RootSnapshotDiffError::MalformedInput);
            }
            Ok(identity)
        }
        "windows" => {
            if entry.name_bytes_hex.is_some() {
                return Err(RootSnapshotDiffError::MalformedInput);
            }
            let identity = entry
                .name_utf16le_hex
                .as_deref()
                .ok_or(RootSnapshotDiffError::MalformedInput)?;
            validate_hex(identity, 4, MAX_NAME_BYTES_OR_UNITS, false)?;
            if identity
                .as_bytes()
                .chunks_exact(4)
                .any(|unit| unit == b"0000" || unit == b"2f00" || unit == b"5c00")
            {
                return Err(RootSnapshotDiffError::MalformedInput);
            }
            if identity == "2e00" || identity == "2e002e00" {
                return Err(RootSnapshotDiffError::MalformedInput);
            }
            Ok(identity)
        }
        _ => Err(RootSnapshotDiffError::PlatformMismatch),
    }
}

fn validate_hex(
    value: &str,
    chars_per_unit: usize,
    max_units: usize,
    allow_empty: bool,
) -> Result<(), RootSnapshotDiffError> {
    if (value.is_empty() && !allow_empty)
        || value.len() % chars_per_unit != 0
        || value.len() / chars_per_unit > max_units
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RootSnapshotDiffError::MalformedInput);
    }
    Ok(())
}

fn compare(left: &Document, right: &Document) -> Result<RootSnapshotDiff, RootSnapshotDiffError> {
    let left_root = root_identity(
        left.root
            .as_ref()
            .ok_or(RootSnapshotDiffError::RootMismatch)?,
        &left.platform,
    )?;
    let right_root = root_identity(
        right
            .root
            .as_ref()
            .ok_or(RootSnapshotDiffError::RootMismatch)?,
        &right.platform,
    )?;
    if left_root != right_root {
        return Err(RootSnapshotDiffError::RootMismatch);
    }

    let left_root_facts = left
        .root
        .as_ref()
        .ok_or(RootSnapshotDiffError::RootMismatch)?;
    let right_root_facts = right
        .root
        .as_ref()
        .ok_or(RootSnapshotDiffError::RootMismatch)?;
    let root_identity_hint_conflict = both_known_differ(
        left_root_facts.device_or_volume_serial,
        right_root_facts.device_or_volume_serial,
    ) || both_known_differ(
        left_root_facts.inode_or_file_index,
        right_root_facts.inode_or_file_index,
    );

    let left_index = index(&left.entries, &left.platform)?;
    let right_index = index(&right.entries, &right.platform)?;
    let mut all_names = BTreeSet::new();
    all_names.extend(left_index.keys().cloned());
    all_names.extend(right_index.keys().cloned());
    let presence_comparable =
        left.status == "complete" && right.status == "complete" && !root_identity_hint_conflict;
    let mut counts = RootSnapshotDiffCounts::default();
    let mut deltas = Vec::new();
    let mut diagnostics = Vec::new();

    for name in all_names {
        let before_rows = left_index.get(&name).map(Vec::as_slice).unwrap_or_default();
        let after_rows = right_index
            .get(&name)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if before_rows.len() > 1 || after_rows.len() > 1 {
            counts.ambiguous_name_groups = counts.ambiguous_name_groups.saturating_add(1);
            continue;
        }
        match (before_rows.first(), after_rows.first()) {
            (Some(before), Some(after)) => {
                counts.matched = counts.matched.saturating_add(1);
                let (changed_fields, unknown_fields) = changed_fields(
                    before.entry,
                    after.entry,
                    left.content_hashing.is_some() || right.content_hashing.is_some(),
                );
                if !unknown_fields.is_empty() {
                    counts.uncertain_matches = counts.uncertain_matches.saturating_add(1);
                }
                if changed_fields.is_empty() && unknown_fields.is_empty() {
                    counts.unchanged = counts.unchanged.saturating_add(1);
                } else if changed_fields.is_empty() {
                    deltas.push(delta(
                        "uncertain",
                        &name,
                        before,
                        Some(after),
                        changed_fields,
                        unknown_fields,
                    ));
                } else {
                    counts.changes = counts.changes.saturating_add(1);
                    deltas.push(delta(
                        "changed",
                        &name,
                        before,
                        Some(after),
                        changed_fields,
                        unknown_fields,
                    ));
                }
            }
            (Some(before), None) if presence_comparable => {
                counts.removals = counts.removals.saturating_add(1);
                deltas.push(delta(
                    "removed",
                    &name,
                    before,
                    None,
                    Vec::new(),
                    Vec::new(),
                ));
            }
            (None, Some(after)) if presence_comparable => {
                counts.additions = counts.additions.saturating_add(1);
                deltas.push(delta(
                    "added",
                    &name,
                    after,
                    Some(after),
                    Vec::new(),
                    Vec::new(),
                ));
            }
            (Some(_), None) | (None, Some(_)) => {
                counts.unmatched_rows_suppressed =
                    counts.unmatched_rows_suppressed.saturating_add(1);
            }
            (None, None) => {}
        }
        if deltas.len() > MAX_ENTRIES.saturating_mul(2) {
            return Err(RootSnapshotDiffError::LimitExceeded);
        }
    }

    if left.status != "complete" || right.status != "complete" {
        diagnostics.push("partial_snapshot_suppresses_unmatched_presence_claims");
    }
    if root_identity_hint_conflict {
        diagnostics.push("root_identity_hint_conflict_suppresses_unmatched_presence_claims");
    }
    if counts.ambiguous_name_groups > 0 {
        diagnostics.push("duplicate_name_identity_suppressed");
    }
    if counts.unmatched_rows_suppressed > 0 {
        diagnostics.push("unmatched_rows_suppressed");
    }
    if counts.uncertain_matches > 0 {
        diagnostics.push("matched_metadata_incomplete");
    }
    Ok(RootSnapshotDiff {
        schema: OUTPUT_SCHEMA,
        schema_version: OUTPUT_SCHEMA_VERSION,
        platform: if left.platform == "linux" {
            "linux"
        } else {
            "windows"
        },
        status: if presence_comparable
            && counts.ambiguous_name_groups == 0
            && counts.uncertain_matches == 0
        {
            "complete"
        } else {
            "partial"
        },
        root_path_identity_hex: left_root.to_owned(),
        root_path_encoding: if left.platform == "linux" {
            "raw_path_bytes_hex"
        } else {
            "utf16le_code_units_hex"
        },
        root_identity_hint_conflict,
        coverage_note: "Compares metadata for direct children of one exact selected-root path and compares opt-in SHA-256 content fingerprints only when both sides observed a digest. Schema v1 metadata-only and v2 hash-requested snapshots can be compared together; a missing or unavailable requested hash remains unknown and makes the result partial. Complete snapshots of the supported direct-child scopes permit candidate addition/removal labels unless known local root identity hints conflict. Such hints are not durable identities, and a conflict does not prove that a different root object was observed; it only suppresses unmatched presence claims. This does not prove installation, deletion cause, content authenticity, or filesystem history.",
        counts,
        diagnostics,
        deltas,
    })
}

fn both_known_differ<T: Eq>(before: Option<T>, after: Option<T>) -> bool {
    matches!((before, after), (Some(before), Some(after)) if before != after)
}

#[derive(Clone, Copy)]
struct EntryRef<'a> {
    row_index: usize,
    entry: &'a Entry,
}

fn index<'a>(
    entries: &'a [Entry],
    platform: &str,
) -> Result<BTreeMap<String, Vec<EntryRef<'a>>>, RootSnapshotDiffError> {
    let mut result: BTreeMap<String, Vec<EntryRef<'a>>> = BTreeMap::new();
    for (row_index, entry) in entries.iter().enumerate() {
        result
            .entry(name_identity(entry, platform)?.to_owned())
            .or_default()
            .push(EntryRef { row_index, entry });
    }
    Ok(result)
}

fn changed_fields(
    before: &Entry,
    after: &Entry,
    compare_content: bool,
) -> (Vec<&'static str>, Vec<&'static str>) {
    let mut changed = Vec::new();
    let mut unknown = Vec::new();
    if before.object_type == "unknown" || after.object_type == "unknown" {
        unknown.push("object_type");
    } else if before.object_type != after.object_type {
        changed.push("object_type");
    }
    compare_optional(
        before.size_bytes,
        after.size_bytes,
        "size_bytes",
        &mut changed,
        &mut unknown,
    );
    compare_optional(
        before.modified_at_unix_ms,
        after.modified_at_unix_ms,
        "modified_at_unix_ms",
        &mut changed,
        &mut unknown,
    );
    compare_optional(
        before.device_or_volume_serial,
        after.device_or_volume_serial,
        "device_or_volume_serial_hint",
        &mut changed,
        &mut unknown,
    );
    compare_optional(
        before.inode_or_file_index,
        after.inode_or_file_index,
        "inode_or_file_index_hint",
        &mut changed,
        &mut unknown,
    );
    if compare_content && (is_regular(&before.object_type) || is_regular(&after.object_type)) {
        match (
            before.content_sha256.as_deref(),
            after.content_sha256.as_deref(),
        ) {
            (Some(left), Some(right)) if left != right => changed.push("content_sha256"),
            (Some(_), Some(_)) => {}
            _ => unknown.push("content_sha256"),
        }
    }
    (changed, unknown)
}

fn is_regular(kind: &str) -> bool {
    matches!(kind, "regular_file" | "regular_or_other_file")
}

fn compare_optional<T: Eq>(
    before: Option<T>,
    after: Option<T>,
    field: &'static str,
    changed: &mut Vec<&'static str>,
    unknown: &mut Vec<&'static str>,
) {
    match (before, after) {
        (Some(left), Some(right)) if left != right => changed.push(field),
        (Some(_), None) | (None, Some(_)) => unknown.push(field),
        (None, None) => unknown.push(field),
        (Some(_), Some(_)) => {}
    }
}

fn delta(
    kind: &'static str,
    identity: &str,
    representative: &EntryRef<'_>,
    after: Option<&EntryRef<'_>>,
    changed_fields: Vec<&'static str>,
    unknown_fields: Vec<&'static str>,
) -> RootSnapshotDelta {
    let name = representative.entry.display_name.clone();
    RootSnapshotDelta {
        kind,
        name,
        name_identity_hex: identity.to_owned(),
        changed_fields,
        unknown_fields,
        before: if kind == "added" {
            None
        } else {
            Some(side(representative))
        },
        after: after.map(side),
    }
}

fn side(reference: &EntryRef<'_>) -> RootSnapshotSide {
    RootSnapshotSide {
        row_index: reference.row_index,
        entry_ordinal: reference.entry.ordinal,
        evidence_source: "selected_root_directory_entry",
        object_type: reference.entry.object_type.clone(),
        size_bytes: reference.entry.size_bytes,
        modified_at_unix_ms: reference.entry.modified_at_unix_ms,
        device_or_volume_serial_hint: reference.entry.device_or_volume_serial,
        inode_or_file_index_hint: reference.entry.inode_or_file_index,
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_INPUT_BYTES, RootSnapshotDiffError, compare_selected_root_inventory_json};
    use serde_json::{Value, json};

    fn document(
        platform: &str,
        root: &str,
        status: &str,
        rows: &[(&str, &str, u64, Option<i128>)],
    ) -> Vec<u8> {
        let entries = rows.iter().enumerate().map(|(ordinal, (display, exact_name, size, mtime))| {
            let identity = if platform == "linux" {
                json!({"name_bytes_hex": exact_name})
            } else {
                json!({"name_utf16le_hex": exact_name})
            };
            let mut entry = json!({
                "ordinal": ordinal,
                "display_name": display,
                "object_type": if platform == "linux" { "regular_file" } else { "regular_or_other_file" },
                "size_bytes": size,
                "modified_at_unix_ms": mtime,
                "device_or_volume_serial": 4,
                "inode_or_file_index": 7,
                "evidence": {"source":"selected_root_directory_entry", "entry_ordinal":ordinal}
            });
            entry.as_object_mut().unwrap().extend(identity.as_object().unwrap().clone());
            entry
        }).collect::<Vec<_>>();
        let root_identity = if platform == "linux" {
            json!({"path_bytes_hex":root})
        } else {
            json!({"path_utf16le_hex":root})
        };
        let mut root_value = json!({"display_path":"display-only", "object_type":"directory", "device_or_volume_serial":4, "inode_or_file_index":2});
        root_value
            .as_object_mut()
            .unwrap()
            .extend(root_identity.as_object().unwrap().clone());
        serde_json::to_vec(&json!({
            "schema":"sideeffect.selected_root_inventory",
            "schema_version":1,
            "platform":platform,
            "scope":"one_explicit_root_and_its_direct_children_metadata_only",
            "captured_started_at_unix_ms":1,
            "captured_ended_at_unix_ms":2,
            "status":status,
            "root":root_value,
            "entries":entries,
            "diagnostics":[],
            "limits":{
                "max_root_path_bytes_or_utf16_units":if platform == "linux" {4095} else {32766},
                "max_entries":10000,
                "max_name_bytes_or_utf16_units":32767,
                "max_aggregate_name_bytes":8388608,
                "deadline_seconds":5
            }
        }))
        .unwrap()
    }

    fn row<'a>(
        name: &'a str,
        exact: &'a str,
        size: u64,
        mtime: Option<i128>,
    ) -> (&'a str, &'a str, u64, Option<i128>) {
        (name, exact, size, mtime)
    }

    #[test]
    fn exact_linux_names_ignore_display_text_and_match_shuffled_rows_with_evidence() {
        let before = document(
            "linux",
            "2f746d702f73636f7065",
            "complete",
            &[
                row("�x", "ff78", 1, Some(10)),
                row("remove", "72656d6f7665", 2, Some(20)),
            ],
        );
        let after = document(
            "linux",
            "2f746d702f73636f7065",
            "complete",
            &[
                row("add", "616464", 3, Some(30)),
                row("different display", "ff78", 4, Some(11)),
            ],
        );
        let diff = compare_selected_root_inventory_json(&before, &after).unwrap();
        assert_eq!(diff.status, "complete");
        assert_eq!(diff.counts.changes, 1);
        assert_eq!(diff.counts.additions, 1);
        assert_eq!(diff.counts.removals, 1);
        let changed = diff
            .deltas
            .iter()
            .find(|delta| delta.kind == "changed")
            .unwrap();
        assert_eq!(changed.name_identity_hex, "ff78");
        assert_eq!(
            changed.changed_fields,
            ["size_bytes", "modified_at_unix_ms"]
        );
        assert_eq!(changed.before.as_ref().unwrap().row_index, 0);
        assert_eq!(changed.after.as_ref().unwrap().row_index, 1);
        assert_eq!(changed.before.as_ref().unwrap().entry_ordinal, 0);
        assert_eq!(changed.after.as_ref().unwrap().entry_ordinal, 1);
    }

    #[test]
    fn windows_utf16_identity_matches_exact_code_units_not_display_text() {
        let before = document(
            "windows",
            "43003a005c00730063006f0070006500",
            "complete",
            &[row("replacement", "00d84100", 1, Some(10))],
        );
        let after = document(
            "windows",
            "43003a005c00730063006f0070006500",
            "complete",
            &[row("different replacement", "00d84100", 1, Some(12))],
        );
        let diff = compare_selected_root_inventory_json(&before, &after).unwrap();
        assert_eq!(diff.counts.matched, 1);
        assert_eq!(diff.counts.changes, 1);
        assert_eq!(diff.deltas[0].name_identity_hex, "00d84100");
    }

    #[test]
    fn unknown_linux_object_type_is_reported_as_unknown_not_a_type_change() {
        let before = document(
            "linux",
            "2f746d702f73636f7065",
            "complete",
            &[row("entry", "656e747279", 1, Some(10))],
        );
        let after = document(
            "linux",
            "2f746d702f73636f7065",
            "complete",
            &[row("entry", "656e747279", 1, Some(10))],
        );
        let mut before: Value = serde_json::from_slice(&before).unwrap();
        before["entries"][0]["object_type"] = json!("unknown");
        let diff =
            compare_selected_root_inventory_json(&serde_json::to_vec(&before).unwrap(), &after)
                .unwrap();
        assert_eq!(diff.status, "partial");
        assert_eq!(diff.counts.changes, 0);
        assert_eq!(diff.counts.uncertain_matches, 1);
        assert!(diff.deltas[0].changed_fields.is_empty());
        assert_eq!(diff.deltas[0].unknown_fields, ["object_type"]);
    }

    #[test]
    fn paired_missing_metadata_stays_unknown_and_makes_result_partial() {
        let before = document(
            "linux",
            "2f746d702f73636f7065",
            "complete",
            &[row("entry", "656e747279", 1, Some(10))],
        );
        let after = before.clone();
        let mut before: Value = serde_json::from_slice(&before).unwrap();
        let mut after: Value = serde_json::from_slice(&after).unwrap();
        for input in [&mut before, &mut after] {
            input["entries"][0]["size_bytes"] = Value::Null;
            input["entries"][0]["modified_at_unix_ms"] = Value::Null;
            input["entries"][0]["device_or_volume_serial"] = Value::Null;
            input["entries"][0]["inode_or_file_index"] = Value::Null;
        }
        let diff = compare_selected_root_inventory_json(
            &serde_json::to_vec(&before).unwrap(),
            &serde_json::to_vec(&after).unwrap(),
        )
        .unwrap();
        assert_eq!(diff.status, "partial");
        assert_eq!(diff.counts.uncertain_matches, 1);
        assert_eq!(diff.deltas[0].changed_fields, Vec::<&str>::new());
        assert_eq!(
            diff.deltas[0].unknown_fields,
            [
                "size_bytes",
                "modified_at_unix_ms",
                "device_or_volume_serial_hint",
                "inode_or_file_index_hint"
            ]
        );
    }

    #[test]
    fn known_change_with_unknown_field_is_changed_and_partial() {
        let before = document(
            "linux",
            "2f746d702f73636f7065",
            "complete",
            &[row("entry", "656e747279", 1, None)],
        );
        let after = document(
            "linux",
            "2f746d702f73636f7065",
            "complete",
            &[row("entry", "656e747279", 2, None)],
        );
        let diff = compare_selected_root_inventory_json(&before, &after).unwrap();
        assert_eq!(diff.status, "partial");
        assert_eq!(diff.counts.changes, 1);
        assert_eq!(diff.counts.uncertain_matches, 1);
        assert_eq!(diff.deltas.len(), 1);
        assert_eq!(diff.deltas[0].kind, "changed");
        assert_eq!(diff.deltas[0].changed_fields, ["size_bytes"]);
        assert_eq!(diff.deltas[0].unknown_fields, ["modified_at_unix_ms"]);
    }

    #[test]
    fn partial_inputs_keep_matched_changes_but_suppress_presence_claims() {
        let before = document(
            "linux",
            "2f746d702f73636f7065",
            "partial",
            &[
                row("retained", "72657461696e6564", 1, Some(10)),
                row("possibly removed", "72656d6f766564", 2, Some(20)),
            ],
        );
        let after = document(
            "linux",
            "2f746d702f73636f7065",
            "complete",
            &[
                row("retained", "72657461696e6564", 3, Some(11)),
                row("possibly added", "6164646564", 4, Some(30)),
            ],
        );
        let diff = compare_selected_root_inventory_json(&before, &after).unwrap();
        assert_eq!(diff.status, "partial");
        assert_eq!(diff.counts.changes, 1);
        assert_eq!(diff.counts.additions, 0);
        assert_eq!(diff.counts.removals, 0);
        assert_eq!(diff.counts.unmatched_rows_suppressed, 2);
    }

    #[test]
    fn duplicate_names_are_ambiguous_and_do_not_generate_false_presence_deltas() {
        let before = document(
            "linux",
            "2f746d702f73636f7065",
            "complete",
            &[
                row("dup", "647570", 1, Some(1)),
                row("dup", "647570", 2, Some(2)),
            ],
        );
        let after = document("linux", "2f746d702f73636f7065", "complete", &[]);
        let diff = compare_selected_root_inventory_json(&before, &after).unwrap();
        assert_eq!(diff.status, "partial");
        assert_eq!(diff.counts.ambiguous_name_groups, 1);
        assert!(diff.deltas.is_empty());
    }

    #[test]
    fn rejects_scope_root_platform_schema_encoding_and_oversize_mismatches() {
        let valid = document("linux", "2f746d702f73636f7065", "complete", &[]);
        let mut scope: Value = serde_json::from_slice(&valid).unwrap();
        scope["scope"] = json!("another_scope");
        assert_eq!(
            compare_selected_root_inventory_json(&valid, &serde_json::to_vec(&scope).unwrap())
                .unwrap_err(),
            RootSnapshotDiffError::ScopeMismatch
        );

        let other_root = document("linux", "2f746d702f746d70", "complete", &[]);
        assert_eq!(
            compare_selected_root_inventory_json(&valid, &other_root).unwrap_err(),
            RootSnapshotDiffError::RootMismatch
        );

        let windows = document("windows", "43003a00", "complete", &[]);
        assert_eq!(
            compare_selected_root_inventory_json(&valid, &windows).unwrap_err(),
            RootSnapshotDiffError::PlatformMismatch
        );

        let mut unsupported: Value = serde_json::from_slice(&valid).unwrap();
        unsupported["schema_version"] = json!(3);
        assert_eq!(
            compare_selected_root_inventory_json(
                &valid,
                &serde_json::to_vec(&unsupported).unwrap()
            )
            .unwrap_err(),
            RootSnapshotDiffError::UnsupportedSchema
        );

        let mut missing_root: Value = serde_json::from_slice(&valid).unwrap();
        missing_root["root"] = Value::Null;
        assert_eq!(
            compare_selected_root_inventory_json(
                &valid,
                &serde_json::to_vec(&missing_root).unwrap()
            )
            .unwrap_err(),
            RootSnapshotDiffError::MalformedInput
        );

        let mut malformed: Value = serde_json::from_slice(&valid).unwrap();
        malformed["root"]["path_bytes_hex"] = json!("xyz");
        assert_eq!(
            compare_selected_root_inventory_json(&valid, &serde_json::to_vec(&malformed).unwrap())
                .unwrap_err(),
            RootSnapshotDiffError::MalformedInput
        );

        let mut empty_windows_name: Value = serde_json::from_slice(&windows).unwrap();
        empty_windows_name["entries"] = json!([{
            "ordinal":0,
            "display_name":"",
            "name_utf16le_hex":"",
            "object_type":"regular_or_other_file",
            "size_bytes":null,
            "modified_at_unix_ms":null,
            "device_or_volume_serial":null,
            "inode_or_file_index":null,
            "evidence":{"source":"selected_root_directory_entry", "entry_ordinal":0}
        }]);
        assert_eq!(
            compare_selected_root_inventory_json(
                &windows,
                &serde_json::to_vec(&empty_windows_name).unwrap()
            )
            .unwrap_err(),
            RootSnapshotDiffError::MalformedInput
        );

        assert_eq!(
            compare_selected_root_inventory_json(&vec![b' '; MAX_INPUT_BYTES + 1], &valid)
                .unwrap_err(),
            RootSnapshotDiffError::InputTooLarge
        );
    }

    #[test]
    fn conflicting_root_identity_hints_suppress_unmatched_presence_rows_without_claiming_identity()
    {
        let before = document(
            "linux",
            "2f746d702f73636f7065",
            "complete",
            &[row("one", "6f6e65", 1, Some(1))],
        );
        let mut after: Value =
            serde_json::from_slice(&document("linux", "2f746d702f73636f7065", "complete", &[]))
                .unwrap();
        after["root"]["inode_or_file_index"] = json!(99);
        let diff =
            compare_selected_root_inventory_json(&before, &serde_json::to_vec(&after).unwrap())
                .unwrap();
        assert_eq!(diff.status, "partial");
        assert!(diff.root_identity_hint_conflict);
        assert_eq!(diff.counts.removals, 0);
        assert_eq!(diff.counts.unmatched_rows_suppressed, 1);
    }
}
