//! Bounded comparison of Linux and Windows process inventory snapshots.

use serde::Serialize;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MAX_INPUT: usize = 64 * 1024 * 1024;
const MAX_PROCESSES: usize = 8_192;
const MAX_TEXT: usize = 32_768;
const MAX_WINDOWS_PATH_TEXT: usize = 4 * MAX_TEXT;
const MAX_OUTPUT: usize = 16_384;
const MAX_DEPTH: usize = 32;
const MAX_JSON_COLLECTION: usize = 65_536;
const MAX_JSON_NODES: usize = 1_000_000;
const MAX_JSON_STRING_BYTES: usize = 128 * 1024;
const LINUX: &str = "sideeffect.process_inventory";
const WINDOWS: &str = "sideeffect.windows_process_inventory";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessDiffStatus {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessDiff {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub before_captured_at_unix_ms: u128,
    pub after_captured_at_unix_ms: u128,
    pub status: ProcessDiffStatus,
    pub coverage_note: &'static str,
    pub counts: ProcessDiffCounts,
    pub diagnostics: Vec<&'static str>,
    pub deltas: Vec<ProcessDelta>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ProcessDiffCounts {
    pub additions: usize,
    pub removals: usize,
    pub changes: usize,
    pub unmatched_rows_suppressed_for_partial_source: usize,
    pub rows_with_missing_or_unobserved_generation: usize,
    pub ambiguous_pid_groups: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessDelta {
    pub kind: &'static str,
    pub process_id: u32,
    pub generation: Option<u64>,
    pub changed_fields: Vec<&'static str>,
    pub before: Option<ProcessSide>,
    pub after: Option<ProcessSide>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessSide {
    pub evidence: ProcessEvidenceRef,
    pub facts: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessEvidenceRef {
    pub row_index: usize,
    pub source_index: Option<usize>,
    pub field_references: Vec<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessDiffError {
    MalformedInput,
    InputTooLarge,
    UnsupportedSchema,
    SchemaMismatch,
    PlatformMismatch,
    LimitExceeded,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind {
    Linux,
    Windows,
}

/// Routes CLI input without accepting it as a valid process document.
pub fn is_process_inventory_json(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_INPUT
        && parse_bounded_json(bytes)
            .ok()
            .and_then(|v| v.get("schema").and_then(Value::as_str).map(str::to_owned))
            .is_some_and(|s| s == LINUX || s == WINDOWS)
}

pub fn compare_process_inventory_json(
    before: &[u8],
    after: &[u8],
) -> Result<ProcessDiff, ProcessDiffError> {
    if before.len().saturating_add(after.len()) > MAX_INPUT {
        return Err(ProcessDiffError::InputTooLarge);
    }
    let left = parse_bounded_json(before)?;
    let right = parse_bounded_json(after)?;
    let lk = kind(&left)?;
    let rk = kind(&right)?;
    if lk != rk {
        return Err(ProcessDiffError::SchemaMismatch);
    }
    validate(&left, lk)?;
    validate(&right, rk)?;
    compare(&left, &right, lk)
}

struct JsonBudget {
    nodes: usize,
}
struct BoundedValueSeed<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}
struct BoundedStringSeed;

impl<'de> DeserializeSeed<'de> for BoundedValueSeed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > MAX_DEPTH {
            return Err(serde::de::Error::custom("JSON nesting limit exceeded"));
        }
        self.budget.nodes = self
            .budget
            .nodes
            .checked_add(1)
            .ok_or_else(|| serde::de::Error::custom("JSON node limit exceeded"))?;
        if self.budget.nodes > MAX_JSON_NODES {
            return Err(serde::de::Error::custom("JSON node limit exceeded"));
        }
        deserializer.deserialize_any(BoundedValueVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct BoundedValueVisitor<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}
impl<'de> Visitor<'de> for BoundedValueVisitor<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded JSON value")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        Ok(Value::Number(
            serde_json::Number::from_f64(v).ok_or_else(|| E::custom("non-finite JSON number"))?,
        ))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        if v.len() > MAX_JSON_STRING_BYTES {
            return Err(E::custom("JSON string limit exceeded"));
        }
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        if v.len() > MAX_JSON_STRING_BYTES {
            return Err(E::custom("JSON string limit exceeded"));
        }
        Ok(Value::String(v))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        BoundedValueSeed {
            budget: self.budget,
            depth: self.depth + 1,
        }
        .deserialize(d)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while values.len() < MAX_JSON_COLLECTION {
            match seq.next_element_seed(BoundedValueSeed {
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
        while let Some(key) = map.next_key_seed(BoundedStringSeed)? {
            if values.len() >= MAX_JSON_COLLECTION {
                return Err(serde::de::Error::custom("JSON object limit exceeded"));
            }
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value_seed(BoundedValueSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

impl<'de> DeserializeSeed<'de> for BoundedStringSeed {
    type Value = String;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<String, D::Error> {
        deserializer.deserialize_string(BoundedStringVisitor)
    }
}
struct BoundedStringVisitor;
impl Visitor<'_> for BoundedStringVisitor {
    type Value = String;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded JSON object key")
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<String, E> {
        if v.len() > 256 {
            return Err(E::custom("JSON key limit exceeded"));
        }
        Ok(v.to_owned())
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<String, E> {
        if v.len() > 256 {
            return Err(E::custom("JSON key limit exceeded"));
        }
        Ok(v)
    }
}

fn parse_bounded_json(bytes: &[u8]) -> Result<Value, ProcessDiffError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = BoundedValueSeed {
        budget: &mut JsonBudget { nodes: 0 },
        depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| ProcessDiffError::MalformedInput)?;
    deserializer
        .end()
        .map_err(|_| ProcessDiffError::MalformedInput)?;
    Ok(value)
}

fn kind(v: &Value) -> Result<Kind, ProcessDiffError> {
    match v.get("schema").and_then(Value::as_str) {
        Some(LINUX) => Ok(Kind::Linux),
        Some(WINDOWS) => Ok(Kind::Windows),
        _ => Err(ProcessDiffError::UnsupportedSchema),
    }
}

fn object(v: &Value) -> Result<&Map<String, Value>, ProcessDiffError> {
    v.as_object().ok_or(ProcessDiffError::MalformedInput)
}
fn arr<'a>(v: &'a Value, key: &str) -> Result<&'a [Value], ProcessDiffError> {
    v.get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(ProcessDiffError::MalformedInput)
}
fn strv<'a>(v: &'a Value, key: &str) -> Result<&'a str, ProcessDiffError> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or(ProcessDiffError::MalformedInput)
}
fn u64v(v: &Value, key: &str) -> Result<u64, ProcessDiffError> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or(ProcessDiffError::MalformedInput)
}
fn optional_string(v: &Value, key: &str) -> Result<(), ProcessDiffError> {
    if v.get(key).is_some_and(|value| !value.is_string()) {
        return Err(ProcessDiffError::MalformedInput);
    }
    Ok(())
}
fn optional_u64(v: &Value, key: &str) -> Result<(), ProcessDiffError> {
    if v.get(key)
        .is_some_and(|value| !value.is_null() && value.as_u64().is_none())
    {
        return Err(ProcessDiffError::MalformedInput);
    }
    Ok(())
}
fn status_complete(v: &Value) -> bool {
    v.get("status").and_then(Value::as_str) == Some("complete")
}

fn only_keys(v: &Value, allowed: &[&str]) -> Result<(), ProcessDiffError> {
    let m = object(v)?;
    if m.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(ProcessDiffError::MalformedInput);
    }
    Ok(())
}

fn validate(v: &Value, kind: Kind) -> Result<(), ProcessDiffError> {
    let (schema, platform, scope) = match kind {
        Kind::Linux => (
            LINUX,
            "linux",
            "visible_numeric_proc_status_stat_executable_and_namespace_entries",
        ),
        Kind::Windows => (
            WINDOWS,
            "windows",
            "toolhelp_process_snapshot_image_paths_and_token_context",
        ),
    };
    if strv(v, "schema")? != schema || u64v(v, "schema_version")? != 3 {
        return Err(ProcessDiffError::UnsupportedSchema);
    }
    if strv(v, "platform")? != platform {
        return Err(ProcessDiffError::PlatformMismatch);
    }
    if strv(v, "scope")? != scope {
        return Err(ProcessDiffError::MalformedInput);
    }
    let (top, source_keys) = match kind {
        Kind::Linux => (
            &[
                "schema",
                "schema_version",
                "platform",
                "scope",
                "capture_started_at_unix_ms",
                "capture_ended_at_unix_ms",
                "status",
                "source",
                "processes",
            ][..],
            &[
                "id",
                "status",
                "directories_seen",
                "status_bytes_read",
                "diagnostics",
            ][..],
        ),
        Kind::Windows => (
            &[
                "schema",
                "schema_version",
                "platform",
                "scope",
                "capture_started_at_unix_ms",
                "capture_ended_at_unix_ms",
                "status",
                "source",
                "processes",
            ][..],
            &[
                "id",
                "status",
                "entries_seen",
                "image_path_utf16_code_units",
                "token_sid_utf16_code_units",
                "diagnostics",
            ][..],
        ),
    };
    only_keys(v, top)?;
    if !matches!(strv(v, "status")?, "complete" | "partial") {
        return Err(ProcessDiffError::MalformedInput);
    }
    let source = v.get("source").ok_or(ProcessDiffError::MalformedInput)?;
    only_keys(source, source_keys)?;
    if !matches!(strv(source, "status")?, "complete" | "partial") {
        return Err(ProcessDiffError::MalformedInput);
    }
    let expected_source = if kind == Kind::Linux {
        "procfs_status"
    } else {
        "toolhelp_process_snapshot"
    };
    if strv(source, "id")? != expected_source
        || u64v(v, "capture_started_at_unix_ms")? > u64v(v, "capture_ended_at_unix_ms")?
    {
        return Err(ProcessDiffError::MalformedInput);
    }
    let counters: &[&str] = if kind == Kind::Linux {
        &["directories_seen", "status_bytes_read"]
    } else {
        &[
            "entries_seen",
            "image_path_utf16_code_units",
            "token_sid_utf16_code_units",
        ]
    };
    for counter in counters {
        let _ = u64v(source, counter)?;
    }
    let diagnostics = arr(source, "diagnostics")?;
    if diagnostics.len() > 65_536 {
        return Err(ProcessDiffError::LimitExceeded);
    }
    for diagnostic in diagnostics {
        match kind {
            Kind::Linux => only_keys(diagnostic, &["code", "pid", "field", "message", "evidence"])?,
            Kind::Windows => only_keys(diagnostic, &["code", "process_id", "field", "message"])?,
        }
        for key in ["code", "field", "message"] {
            if diagnostic
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|s| s.len() > 4_096)
            {
                return Err(ProcessDiffError::LimitExceeded);
            }
        }
        if let Some(evidence) = diagnostic.get("evidence") {
            validate_process_evidence(evidence)?;
        }
    }
    if arr(v, "processes")?.len() > MAX_PROCESSES {
        return Err(ProcessDiffError::LimitExceeded);
    }
    for row in arr(v, "processes")? {
        match kind {
            Kind::Linux => validate_linux_row(row)?,
            Kind::Windows => validate_windows_row(row)?,
        }
    }
    Ok(())
}

fn validate_linux_row(row: &Value) -> Result<(), ProcessDiffError> {
    only_keys(
        row,
        &[
            "pid",
            "start_time",
            "executable_link",
            "name",
            "tgid",
            "ppid",
            "state",
            "uid",
            "gid",
            "cap_inh",
            "cap_prm",
            "cap_eff",
            "cap_bnd",
            "cap_amb",
            "no_new_privs",
            "seccomp",
            "namespace_pids",
            "namespaces",
            "evidence",
        ],
    )?;
    let _ = u64v(row, "pid")?;
    only_keys(
        row.get("start_time")
            .ok_or(ProcessDiffError::MalformedInput)?,
        &["status", "ticks_since_boot", "evidence"],
    )?;
    if !matches!(
        strv(row.get("start_time").unwrap(), "status")?,
        "observed"
            | "not_checked"
            | "inaccessible"
            | "vanished"
            | "malformed"
            | "pid_mismatch"
            | "changed_during_read"
    ) {
        return Err(ProcessDiffError::MalformedInput);
    }
    if row.pointer("/start_time/status").and_then(Value::as_str) == Some("observed")
        && row
            .pointer("/start_time/ticks_since_boot")
            .and_then(Value::as_u64)
            .is_none()
    {
        return Err(ProcessDiffError::MalformedInput);
    }
    if let Some(evidence) = row.pointer("/start_time/evidence") {
        only_keys(
            evidence,
            &["source", "byte_length", "record_sha256", "field_number"],
        )?;
        let _ = strv(evidence, "source")?;
        let _ = u64v(evidence, "byte_length")?;
        let _ = u64v(evidence, "field_number")?;
        let _ = strv(evidence, "record_sha256")?;
    }
    only_keys(
        row.get("executable_link")
            .ok_or(ProcessDiffError::MalformedInput)?,
        &[
            "status",
            "target_display",
            "target_bytes_hex",
            "byte_length",
            "sha256",
            "evidence",
        ],
    )?;
    if !matches!(
        strv(row.get("executable_link").unwrap(), "status")?,
        "observed" | "inaccessible" | "vanished" | "over_limit" | "unsupported" | "error"
    ) {
        return Err(ProcessDiffError::MalformedInput);
    }
    if row
        .pointer("/executable_link/status")
        .and_then(Value::as_str)
        == Some("observed")
        && row
            .pointer("/executable_link/target_display")
            .and_then(Value::as_str)
            .is_none()
    {
        return Err(ProcessDiffError::MalformedInput);
    }
    if let Some(evidence) = row.pointer("/executable_link/evidence") {
        only_keys(evidence, &["source", "byte_length", "sha256"])?;
        let _ = strv(evidence, "source")?;
        let _ = u64v(evidence, "byte_length")?;
        let _ = strv(evidence, "sha256")?;
    }
    for key in ["target_display", "target_bytes_hex", "sha256"] {
        optional_string(row.get("executable_link").unwrap(), key)?;
    }
    optional_u64(row.get("executable_link").unwrap(), "byte_length")?;
    let evidence = arr(row, "evidence")?;
    if evidence.len() > 32 {
        return Err(ProcessDiffError::LimitExceeded);
    }
    if row
        .pointer("/executable_link/target_display")
        .and_then(Value::as_str)
        .is_some_and(|s| s.len() > 4_096)
    {
        return Err(ProcessDiffError::LimitExceeded);
    }
    for key in ["uid", "gid"] {
        if row.get(key).is_some_and(|value| {
            value.as_array().is_none_or(|values| {
                values.len() != 4
                    || values
                        .iter()
                        .any(|n| n.as_u64().is_none_or(|v| v > u32::MAX as u64))
            })
        }) {
            return Err(ProcessDiffError::MalformedInput);
        }
    }
    for key in ["cap_inh", "cap_prm", "cap_eff", "cap_bnd", "cap_amb"] {
        if row
            .get(key)
            .is_some_and(|value| value.as_str().is_none_or(|s| s.len() > 32))
        {
            return Err(ProcessDiffError::MalformedInput);
        }
    }
    for e in evidence {
        validate_process_evidence(e)?;
    }
    let namespaces = arr(row, "namespaces")?;
    if namespaces.len() > 7 {
        return Err(ProcessDiffError::LimitExceeded);
    }
    for namespace in namespaces {
        only_keys(namespace, &["name", "status", "namespace_id", "evidence"])?;
        let _ = strv(namespace, "name")?;
        let _ = strv(namespace, "status")?;
        optional_u64(namespace, "namespace_id")?;
        if let Some(evidence) = namespace.get("evidence") {
            only_keys(
                evidence,
                &["source", "target_bytes_hex", "byte_length", "sha256"],
            )?;
            let _ = strv(evidence, "source")?;
            let _ = strv(evidence, "target_bytes_hex")?;
            let _ = u64v(evidence, "byte_length")?;
            let _ = strv(evidence, "sha256")?;
        }
    }
    let pid_evidence = row
        .get("namespace_pids")
        .ok_or(ProcessDiffError::MalformedInput)?;
    only_keys(pid_evidence, &["status", "pids", "evidence"])?;
    if pid_evidence
        .get("pids")
        .and_then(Value::as_array)
        .is_some_and(|pids| pids.len() > 8_192)
    {
        return Err(ProcessDiffError::LimitExceeded);
    }
    if pid_evidence
        .get("pids")
        .is_some_and(|pids| !pids.is_array())
        || pid_evidence
            .pointer("/pids")
            .and_then(Value::as_array)
            .is_some_and(|pids| {
                pids.iter()
                    .any(|p| p.as_u64().is_none_or(|n| n > u32::MAX as u64))
            })
    {
        return Err(ProcessDiffError::MalformedInput);
    }
    if let Some(evidence) = pid_evidence.get("evidence") {
        validate_process_evidence(evidence)?;
    }
    let _ = strv(pid_evidence, "status")?;
    for key in [
        "name", "state", "cap_inh", "cap_prm", "cap_eff", "cap_bnd", "cap_amb",
    ] {
        if row.get(key).is_some_and(|value| !value.is_string()) {
            return Err(ProcessDiffError::MalformedInput);
        }
        if row
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|s| s.len() > MAX_TEXT)
        {
            return Err(ProcessDiffError::LimitExceeded);
        }
    }
    for key in ["no_new_privs", "seccomp"] {
        optional_u64(row, key)?;
    }
    for key in ["no_new_privs", "seccomp"] {
        if row
            .get(key)
            .is_some_and(|value| value.as_u64().is_none_or(|n| n > u32::MAX as u64))
        {
            return Err(ProcessDiffError::MalformedInput);
        }
    }
    Ok(())
}

fn validate_process_evidence(evidence: &Value) -> Result<(), ProcessDiffError> {
    only_keys(
        evidence,
        &[
            "field",
            "line",
            "byte_offset",
            "byte_length",
            "line_sha256",
            "raw_source_line",
            "raw_source_line_hex",
        ],
    )?;
    let _ = strv(evidence, "field")?;
    for key in ["line", "byte_offset", "byte_length"] {
        let _ = u64v(evidence, key)?;
    }
    let _ = strv(evidence, "line_sha256")?;
    let _ = strv(evidence, "raw_source_line")?;
    optional_string(evidence, "raw_source_line_hex")?;
    if evidence
        .get("raw_source_line")
        .and_then(Value::as_str)
        .is_some_and(|s| s.len() > 65_536)
    {
        return Err(ProcessDiffError::LimitExceeded);
    }
    Ok(())
}

fn validate_windows_row(row: &Value) -> Result<(), ProcessDiffError> {
    only_keys(
        row,
        &[
            "process_id",
            "parent_process_id",
            "thread_count",
            "executable_name",
            "creation_time",
            "image",
            "token_context",
            "evidence",
        ],
    )?;
    let _ = u64v(row, "process_id")?;
    if u64v(row, "process_id")? > u32::MAX as u64
        || u64v(row, "parent_process_id")? > u32::MAX as u64
        || u64v(row, "thread_count")? > u32::MAX as u64
    {
        return Err(ProcessDiffError::MalformedInput);
    }
    let _ = strv(row, "executable_name")?;
    only_keys(
        row.get("creation_time")
            .ok_or(ProcessDiffError::MalformedInput)?,
        &["status", "filetime_100ns", "source"],
    )?;
    if !matches!(
        strv(row.get("creation_time").unwrap(), "status")?,
        "observed" | "inaccessible" | "vanished" | "error"
    ) {
        return Err(ProcessDiffError::MalformedInput);
    }
    if row.pointer("/creation_time/status").and_then(Value::as_str) == Some("observed")
        && row
            .pointer("/creation_time/filetime_100ns")
            .and_then(Value::as_u64)
            .is_none()
    {
        return Err(ProcessDiffError::MalformedInput);
    }
    optional_u64(row.get("creation_time").unwrap(), "filetime_100ns")?;
    optional_string(row.get("creation_time").unwrap(), "source")?;
    only_keys(
        row.get("image").ok_or(ProcessDiffError::MalformedInput)?,
        &["status", "path", "utf16_code_units"],
    )?;
    if !matches!(
        strv(row.get("image").unwrap(), "status")?,
        "observed" | "inaccessible" | "vanished" | "over_limit" | "malformed_utf16" | "error"
    ) {
        return Err(ProcessDiffError::MalformedInput);
    }
    if row.pointer("/image/status").and_then(Value::as_str) == Some("observed")
        && row.pointer("/image/path").and_then(Value::as_str).is_none()
    {
        return Err(ProcessDiffError::MalformedInput);
    }
    optional_u64(row.get("image").unwrap(), "utf16_code_units")?;
    let token = row
        .get("token_context")
        .ok_or(ProcessDiffError::MalformedInput)?;
    only_keys(
        token,
        &[
            "identity_status",
            "process_creation_time_filetime_100ns",
            "user_sid",
            "integrity_level_rid",
            "session_id",
        ],
    )?;
    for key in ["user_sid", "integrity_level_rid", "session_id"] {
        let field = token.get(key).ok_or(ProcessDiffError::MalformedInput)?;
        only_keys(field, &["status", "value", "source"])?;
        if !matches!(
            strv(field, "status")?,
            "observed"
                | "inaccessible"
                | "vanished"
                | "malformed"
                | "over_limit"
                | "identity_unverified"
                | "error"
        ) {
            return Err(ProcessDiffError::MalformedInput);
        }
        let _ = strv(field, "source")?;
        if field.get("status").and_then(Value::as_str) == Some("observed")
            && field.get("value").is_none()
        {
            return Err(ProcessDiffError::MalformedInput);
        }
    }
    if !matches!(
        strv(token, "identity_status")?,
        "observed" | "identity_unverified" | "changed_during_read"
    ) {
        return Err(ProcessDiffError::MalformedInput);
    }
    if token
        .pointer("/user_sid/value")
        .is_some_and(|value| !value.is_string())
    {
        return Err(ProcessDiffError::MalformedInput);
    }
    optional_u64(token, "process_creation_time_filetime_100ns")?;
    for field in ["integrity_level_rid", "session_id"] {
        if token
            .pointer(&format!("/{field}/value"))
            .is_some_and(|value| value.as_u64().is_none_or(|n| n > u32::MAX as u64))
        {
            return Err(ProcessDiffError::MalformedInput);
        }
    }
    let creation = row
        .pointer("/creation_time/filetime_100ns")
        .and_then(Value::as_u64);
    let creation_observed =
        row.pointer("/creation_time/status").and_then(Value::as_str) == Some("observed");
    let token_creation = token
        .get("process_creation_time_filetime_100ns")
        .and_then(Value::as_u64);
    let token_identity_observed =
        token.get("identity_status").and_then(Value::as_str) == Some("observed");
    if token_identity_observed
        && (!creation_observed
            || creation.is_none()
            || token_creation.is_none()
            || creation != token_creation
            || row
                .pointer("/creation_time/source")
                .and_then(Value::as_str)
                .is_none())
    {
        return Err(ProcessDiffError::MalformedInput);
    }
    only_keys(
        row.get("evidence")
            .ok_or(ProcessDiffError::MalformedInput)?,
        &[
            "snapshot_source",
            "snapshot_index",
            "process_id",
            "parent_process_id",
            "thread_count",
            "executable_name",
            "image_source",
        ],
    )?;
    let row_evidence = row.get("evidence").unwrap();
    for key in ["snapshot_source", "executable_name", "image_source"] {
        let _ = strv(row_evidence, key)?;
    }
    for key in [
        "snapshot_index",
        "process_id",
        "parent_process_id",
        "thread_count",
    ] {
        let _ = u64v(row_evidence, key)?;
    }
    if strv(row, "executable_name")?.len() > MAX_TEXT
        || row
            .pointer("/image/path")
            .and_then(Value::as_str)
            .is_some_and(|s| s.len() > MAX_WINDOWS_PATH_TEXT)
    {
        return Err(ProcessDiffError::LimitExceeded);
    }
    if row
        .pointer("/image/path")
        .is_some_and(|path| !path.is_string())
    {
        return Err(ProcessDiffError::MalformedInput);
    }
    if token
        .pointer("/user_sid/value")
        .and_then(Value::as_str)
        .is_some_and(|s| s.len() > 1_024)
    {
        return Err(ProcessDiffError::LimitExceeded);
    }
    Ok(())
}

fn observed_generation(row: &Value, kind: Kind) -> Option<u64> {
    match kind {
        Kind::Linux
            if row.pointer("/start_time/status").and_then(Value::as_str) == Some("observed") =>
        {
            row.pointer("/start_time/ticks_since_boot")
                .and_then(Value::as_u64)
        }
        Kind::Windows
            if row.pointer("/creation_time/status").and_then(Value::as_str) == Some("observed") =>
        {
            row.pointer("/creation_time/filetime_100ns")
                .and_then(Value::as_u64)
        }
        _ => None,
    }
}

fn pid(row: &Value, kind: Kind) -> Option<u32> {
    row.get(if kind == Kind::Linux {
        "pid"
    } else {
        "process_id"
    })
    .and_then(Value::as_u64)
    .and_then(|n| u32::try_from(n).ok())
}

fn selected_facts(row: &Value, kind: Kind) -> Value {
    let keys: &[&str] = if kind == Kind::Linux {
        &[
            "name",
            "uid",
            "gid",
            "cap_inh",
            "cap_prm",
            "cap_eff",
            "cap_bnd",
            "cap_amb",
            "no_new_privs",
            "seccomp",
        ]
    } else {
        &["parent_process_id", "executable_name"]
    };
    let mut out = Map::new();
    for key in keys {
        if let Some(v) = row.get(*key) {
            out.insert((*key).to_owned(), v.clone());
        }
    }
    if kind == Kind::Linux {
        if let Some(link) = row.get("executable_link") {
            out.insert("executable_link".to_owned(), serde_json::json!({"status":link.get("status"),"target_display":link.get("target_display")}));
        }
    } else {
        if let Some(image) = row.get("image") {
            let observed = image.get("status").and_then(Value::as_str) == Some("observed");
            out.insert(
                "image".to_owned(),
                serde_json::json!({"status":image.get("status"),"path":if observed {image.get("path")} else {None}}),
            );
        }
        if let Some(token) = row.get("token_context") {
            let mut selected = Map::new();
            let verified = token.get("identity_status").and_then(Value::as_str) == Some("observed");
            for k in ["user_sid", "integrity_level_rid", "session_id"] {
                if let Some(field) = token.get(k) {
                    let observed =
                        verified && field.get("status").and_then(Value::as_str) == Some("observed");
                    selected.insert(k.to_owned(),serde_json::json!({"status":field.get("status"),"value":if observed {field.get("value")} else {None}}));
                }
            }
            out.insert("token_context".to_owned(), Value::Object(selected));
        }
    }
    Value::Object(out)
}

fn evidence(row: &Value, index: usize, kind: Kind) -> ProcessEvidenceRef {
    let refs = if kind == Kind::Linux {
        let mut refs: Vec<Value> = row
            .get("evidence")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(|e| {
                        let field = e.get("field")?.as_str()?;
                        ["name", "uid", "gid", "cap_inh", "cap_prm", "cap_eff", "cap_bnd", "cap_amb", "no_new_privs", "seccomp"]
                            .contains(&field)
                            .then(|| serde_json::json!({"field":field,"line":e.get("line"),"byte_offset":e.get("byte_offset"),"byte_length":e.get("byte_length")}))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if let Some(start_time) = row.pointer("/start_time/evidence") {
            refs.push(serde_json::json!({
                "field":"start_time",
                "source":start_time.get("source"),
                "field_number":start_time.get("field_number"),
                "byte_length":start_time.get("byte_length")
            }));
        }
        if let Some(link) = row.pointer("/executable_link/evidence") {
            refs.push(serde_json::json!({"field":"executable_link","source":link.get("source"),"byte_length":link.get("byte_length")}));
        }
        refs
    } else {
        let mut refs = Vec::new();
        if let Some(source) = row
            .pointer("/evidence/snapshot_source")
            .and_then(Value::as_str)
        {
            refs.push(serde_json::json!({"field":"executable_name","source":source}));
            refs.push(serde_json::json!({"field":"parent_process_id","source":source}));
        }
        if let Some(source) = row
            .pointer("/evidence/image_source")
            .and_then(Value::as_str)
        {
            refs.push(serde_json::json!({"field":"image","source":source}));
        }
        if let Some(source) = row.pointer("/creation_time/source").and_then(Value::as_str) {
            refs.push(serde_json::json!({"field":"creation_time","source":source}));
        }
        for field in ["user_sid", "integrity_level_rid", "session_id"] {
            if let Some(source) = row
                .pointer(&format!("/token_context/{field}/source"))
                .and_then(Value::as_str)
            {
                refs.push(serde_json::json!({"field":field,"source":source}));
            }
        }
        refs
    };
    ProcessEvidenceRef {
        row_index: index,
        source_index: row
            .pointer("/evidence/snapshot_index")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok()),
        field_references: refs,
    }
}

fn compare(left: &Value, right: &Value, kind: Kind) -> Result<ProcessDiff, ProcessDiffError> {
    let lrows = arr(left, "processes")?;
    let rrows = arr(right, "processes")?;
    let mut lm = BTreeMap::<(u32, u64), Vec<(usize, &Value)>>::new();
    let mut rm = BTreeMap::<(u32, u64), Vec<(usize, &Value)>>::new();
    let mut lpid = BTreeMap::<u32, usize>::new();
    let mut rpid = BTreeMap::<u32, usize>::new();
    let mut unknown_pids = BTreeSet::<u32>::new();
    let mut counts = ProcessDiffCounts::default();
    for (map, pids, rows) in [(&mut lm, &mut lpid, lrows), (&mut rm, &mut rpid, rrows)] {
        for (i, row) in rows.iter().enumerate() {
            let p = pid(row, kind).ok_or(ProcessDiffError::MalformedInput)?;
            *pids.entry(p).or_default() += 1;
            if let Some(g) = observed_generation(row, kind) {
                map.entry((p, g)).or_default().push((i, row));
            } else {
                counts.rows_with_missing_or_unobserved_generation += 1;
                unknown_pids.insert(p);
            }
        }
    }
    // Any PID repeated within either snapshot is ambiguous regardless of generation.
    let duplicate_pids: BTreeSet<u32> = lpid
        .iter()
        .chain(rpid.iter())
        .filter_map(|(p, n)| (*n > 1).then_some(*p))
        .collect();
    let keys: BTreeSet<(u32, u64)> = lm.keys().chain(rm.keys()).copied().collect();
    let full = status_complete(left)
        && status_complete(right)
        && left.pointer("/source/status").and_then(Value::as_str) == Some("complete")
        && right.pointer("/source/status").and_then(Value::as_str) == Some("complete");
    let mut deltas = Vec::new();
    let mut diagnostics = BTreeSet::new();
    if !full {
        diagnostics.insert("source_incomplete");
    }
    if counts.rows_with_missing_or_unobserved_generation > 0 {
        diagnostics.insert("generation_unknown");
    }
    counts.ambiguous_pid_groups = duplicate_pids.len();
    if !duplicate_pids.is_empty() {
        diagnostics.insert("ambiguous_pid_identity");
    }
    for key @ (p, g) in keys.iter() {
        if duplicate_pids.contains(p) {
            continue;
        }
        let l = lm.get(key).and_then(|v| (v.len() == 1).then_some(v[0]));
        let r = rm.get(key).and_then(|v| (v.len() == 1).then_some(v[0]));
        match (l, r) {
            (Some((li, lv)), Some((ri, rv))) => {
                let a = selected_facts(lv, kind);
                let b = selected_facts(rv, kind);
                if a != b {
                    if deltas.len() >= MAX_OUTPUT {
                        return Err(ProcessDiffError::LimitExceeded);
                    }
                    let changed = a
                        .as_object()
                        .into_iter()
                        .flat_map(|m| m.keys())
                        .chain(b.as_object().into_iter().flat_map(|m| m.keys()))
                        .filter_map(|k| (a.get(k) != b.get(k)).then_some(k.as_str()))
                        .map(|k| match k {
                            "name" => "name",
                            "executable_link" => "executable_link",
                            "uid" => "uid",
                            "gid" => "gid",
                            "cap_inh" => "cap_inh",
                            "cap_prm" => "cap_prm",
                            "cap_eff" => "cap_eff",
                            "cap_bnd" => "cap_bnd",
                            "cap_amb" => "cap_amb",
                            "no_new_privs" => "no_new_privs",
                            "seccomp" => "seccomp",
                            "image" => "image",
                            "executable_name" => "executable_name",
                            "parent_process_id" => "parent_process_id",
                            "token_context" => "token_context",
                            _ => "selected_fact",
                        })
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    deltas.push(ProcessDelta {
                        kind: "changed",
                        process_id: *p,
                        generation: Some(*g),
                        changed_fields: changed,
                        before: Some(ProcessSide {
                            evidence: evidence(lv, li, kind),
                            facts: a,
                        }),
                        after: Some(ProcessSide {
                            evidence: evidence(rv, ri, kind),
                            facts: b,
                        }),
                    });
                    counts.changes += 1;
                }
            }
            (Some((i, row)), None) | (None, Some((i, row))) => {
                if unknown_pids.contains(p) || duplicate_pids.contains(p) {
                    continue;
                }
                if !full {
                    counts.unmatched_rows_suppressed_for_partial_source += 1;
                    continue;
                }
                if deltas.len() >= MAX_OUTPUT {
                    return Err(ProcessDiffError::LimitExceeded);
                }
                let added = l.is_none();
                let facts = selected_facts(row, kind);
                deltas.push(ProcessDelta {
                    kind: if added { "added" } else { "removed" },
                    process_id: *p,
                    generation: Some(*g),
                    changed_fields: Vec::new(),
                    before: if added {
                        None
                    } else {
                        Some(ProcessSide {
                            evidence: evidence(row, i, kind),
                            facts: facts.clone(),
                        })
                    },
                    after: if added {
                        Some(ProcessSide {
                            evidence: evidence(row, i, kind),
                            facts,
                        })
                    } else {
                        None
                    },
                });
                if added {
                    counts.additions += 1
                } else {
                    counts.removals += 1
                }
            }
            _ => (),
        }
    }
    if counts.unmatched_rows_suppressed_for_partial_source > 0 {
        diagnostics.insert("unmatched_rows_suppressed");
    }
    let mut delta = deltas;
    delta.sort_by_key(|d| (d.process_id, d.generation, d.kind));
    let result = ProcessDiff {
        schema: "sideeffect.process_inventory_diff",
        schema_version: 1,
        platform: if kind == Kind::Linux {
            "linux"
        } else {
            "windows"
        },
        before_captured_at_unix_ms: left
            .get("capture_ended_at_unix_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u128,
        after_captured_at_unix_ms: right
            .get("capture_ended_at_unix_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u128,
        status: if full && diagnostics.is_empty() {
            ProcessDiffStatus::Complete
        } else {
            ProcessDiffStatus::Partial
        },
        coverage_note: "A bounded pair of process snapshots, not process start/exit history, exhaustive inventory, causation, or proof of absence. Snapshot timing and source visibility differ; process paths and identifiers are sensitive.",
        counts,
        diagnostics: diagnostics.into_iter().collect(),
        deltas: delta,
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn linux(status: &str, rows: Value) -> Value {
        serde_json::json!({"schema":LINUX,"schema_version":3,"platform":"linux","scope":"visible_numeric_proc_status_stat_executable_and_namespace_entries","capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":status,"source":{"id":"procfs_status","status":status,"directories_seen":rows.as_array().map_or(0,Vec::len),"status_bytes_read":0,"diagnostics":[]},"processes":rows})
    }
    fn lrow(pid: u32, generation: Option<u64>, name: &str) -> Value {
        let start = if let Some(g) = generation {
            serde_json::json!({"status":"observed","ticks_since_boot":g,"evidence":{"source":"/proc/7/stat","byte_length":10,"record_sha256":"private-hash","field_number":22}})
        } else {
            serde_json::json!({"status":"vanished"})
        };
        serde_json::json!({"pid":pid,"start_time":start,"executable_link":{"status":"observed","target_display":"/usr/bin/demo","target_bytes_hex":"2f","byte_length":1,"sha256":"private-path-hash","evidence":{"source":"/proc/7/exe","byte_length":1,"sha256":"private-path-hash"}},"name":name,"uid":[1,1,1,1],"gid":[2,2,2,2],"cap_eff":"0000","seccomp":0,"namespace_pids":{"status":"not_reported"},"namespaces":[],"evidence":[{"field":"name","line":1,"byte_offset":2,"byte_length":3,"line_sha256":"private-line-hash","raw_source_line":"private raw source line"}]})
    }
    fn windows() -> Value {
        serde_json::json!({"schema":WINDOWS,"schema_version":3,"platform":"windows","scope":"toolhelp_process_snapshot_image_paths_and_token_context","capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":"complete","source":{"id":"toolhelp_process_snapshot","status":"complete","entries_seen":1,"image_path_utf16_code_units":10,"token_sid_utf16_code_units":10,"diagnostics":[]},"processes":[{"process_id":10,"parent_process_id":1,"thread_count":2,"executable_name":"demo.exe","creation_time":{"status":"observed","filetime_100ns":123,"source":"GetProcessTimes"},"image":{"status":"observed","path":"C:\\demo.exe","utf16_code_units":10},"token_context":{"identity_status":"observed","process_creation_time_filetime_100ns":123,"user_sid":{"status":"observed","value":"S-1-5-18","source":"TokenUser"},"integrity_level_rid":{"status":"observed","value":8192,"source":"TokenIntegrityLevel"},"session_id":{"status":"observed","value":0,"source":"TokenSessionId"}},"evidence":{"snapshot_source":"Toolhelp32Snapshot","snapshot_index":0,"process_id":10,"parent_process_id":1,"thread_count":2,"executable_name":"demo.exe","image_source":"QueryFullProcessImageNameW"}}]})
    }

    #[test]
    fn exact_identity_changes_selected_facts_and_omits_raw_evidence() {
        let mut before_row = lrow(7, Some(8), "old");
        before_row["state"] = serde_json::json!("private-unselected-state");
        let before = linux("complete", serde_json::json!([before_row]));
        let after = linux("complete", serde_json::json!([lrow(7, Some(8), "new")]));
        let output = compare_process_inventory_json(
            before.to_string().as_bytes(),
            after.to_string().as_bytes(),
        )
        .unwrap();
        assert_eq!(output.counts.changes, 1);
        let text = serde_json::to_string(&output).unwrap();
        assert!(!text.contains("private raw"));
        assert!(!text.contains("private-line-hash"));
        assert!(!text.contains("private-path-hash"));
        assert!(!text.contains("private-unselected-state"));
        assert!(output.deltas[0].changed_fields.contains(&"name"));
        let before_refs = &output.deltas[0]
            .before
            .as_ref()
            .unwrap()
            .evidence
            .field_references;
        let generation_ref = before_refs
            .iter()
            .find(|reference| reference["field"] == "start_time")
            .expect("Linux process identity should retain start-time evidence");
        assert_eq!(generation_ref["source"], "/proc/7/stat");
        assert_eq!(generation_ref["field_number"], 22);
        assert_eq!(generation_ref["byte_length"], 10);
        assert!(!generation_ref.to_string().contains("private-start-hash"));
    }

    #[test]
    fn only_complete_sources_report_presence_and_partial_sources_suppress_it() {
        let before = linux("complete", serde_json::json!([]));
        let after = linux("complete", serde_json::json!([lrow(7, Some(8), "new")]));
        assert_eq!(
            compare_process_inventory_json(
                before.to_string().as_bytes(),
                after.to_string().as_bytes()
            )
            .unwrap()
            .counts
            .additions,
            1
        );
        let partial = linux("partial", serde_json::json!([lrow(7, Some(8), "new")]));
        let diff = compare_process_inventory_json(
            before.to_string().as_bytes(),
            partial.to_string().as_bytes(),
        )
        .unwrap();
        assert_eq!(diff.counts.additions, 0);
        assert_eq!(diff.counts.unmatched_rows_suppressed_for_partial_source, 1);
    }

    #[test]
    fn missing_or_duplicate_generations_are_not_presence_changes() {
        let before = linux("complete", serde_json::json!([lrow(7, None, "old")]));
        let after = linux("complete", serde_json::json!([lrow(7, Some(8), "new")]));
        let diff = compare_process_inventory_json(
            before.to_string().as_bytes(),
            after.to_string().as_bytes(),
        )
        .unwrap();
        assert_eq!(diff.counts.additions, 0);
        assert_eq!(diff.counts.removals, 0);
        assert_eq!(diff.counts.rows_with_missing_or_unobserved_generation, 1);
        let dup = linux(
            "complete",
            serde_json::json!([lrow(7, Some(8), "a"), lrow(7, Some(8), "b")]),
        );
        let diff = compare_process_inventory_json(
            dup.to_string().as_bytes(),
            after.to_string().as_bytes(),
        )
        .unwrap();
        assert_eq!(diff.counts.additions, 0);
        assert_eq!(diff.counts.ambiguous_pid_groups, 1);
    }

    #[test]
    fn windows_identity_uses_creation_generation_and_token_selected_facts() {
        let mut before = windows();
        let mut after = windows();
        after["capture_ended_at_unix_ms"] = serde_json::json!(3);
        after["processes"][0]["token_context"]["session_id"]["value"] = serde_json::json!(2);
        let diff = compare_process_inventory_json(
            before.to_string().as_bytes(),
            after.to_string().as_bytes(),
        )
        .unwrap();
        assert_eq!(diff.counts.changes, 1);
        assert!(diff.deltas[0].changed_fields.contains(&"token_context"));
        assert_eq!(diff.before_captured_at_unix_ms, 2);
        assert_eq!(diff.after_captured_at_unix_ms, 3);
        before["processes"][0]["creation_time"]["filetime_100ns"] = serde_json::json!(124);
        before["processes"][0]["token_context"]["identity_status"] =
            serde_json::json!("changed_during_read");
        for field in ["user_sid", "integrity_level_rid", "session_id"] {
            before["processes"][0]["token_context"][field]["status"] =
                serde_json::json!("identity_unverified");
            before["processes"][0]["token_context"][field]
                .as_object_mut()
                .unwrap()
                .remove("value");
        }
        let diff = compare_process_inventory_json(
            before.to_string().as_bytes(),
            after.to_string().as_bytes(),
        )
        .unwrap();
        assert_eq!(diff.counts.additions, 1);
        assert_eq!(diff.counts.removals, 1);
    }

    #[test]
    fn observed_windows_token_identity_requires_matching_creation_evidence() {
        let valid = windows();
        for (status, creation, token_creation) in [
            ("inaccessible", Value::Null, Value::Null),
            ("observed", serde_json::json!(123), Value::Null),
            ("observed", serde_json::json!(123), serde_json::json!(124)),
        ] {
            let mut invalid = windows();
            invalid["processes"][0]["creation_time"]["status"] = serde_json::json!(status);
            invalid["processes"][0]["creation_time"]["filetime_100ns"] = creation;
            invalid["processes"][0]["token_context"]["process_creation_time_filetime_100ns"] =
                token_creation;
            assert!(matches!(
                compare_process_inventory_json(
                    invalid.to_string().as_bytes(),
                    valid.to_string().as_bytes()
                ),
                Err(ProcessDiffError::MalformedInput)
            ));
        }
    }

    #[test]
    fn rejects_cross_platform_mixed_schema_malformed_unknown_and_oversized_inputs() {
        let l = linux("complete", serde_json::json!([]));
        let w = windows();
        assert!(matches!(
            compare_process_inventory_json(l.to_string().as_bytes(), w.to_string().as_bytes()),
            Err(ProcessDiffError::SchemaMismatch)
        ));
        let mut bad = l.clone();
        bad["unexpected"] = serde_json::json!(true);
        assert!(matches!(
            compare_process_inventory_json(bad.to_string().as_bytes(), l.to_string().as_bytes()),
            Err(ProcessDiffError::MalformedInput)
        ));
        let mut nested = linux("complete", serde_json::json!([lrow(2, Some(4), "demo")]));
        nested["processes"][0]["start_time"]["unexpected"] = serde_json::json!(true);
        assert!(matches!(
            compare_process_inventory_json(nested.to_string().as_bytes(), l.to_string().as_bytes()),
            Err(ProcessDiffError::MalformedInput)
        ));
        let package_schema =
            serde_json::json!({"schema":"sideeffect.inventory","schema_version":2});
        assert!(matches!(
            compare_process_inventory_json(
                l.to_string().as_bytes(),
                package_schema.to_string().as_bytes()
            ),
            Err(ProcessDiffError::UnsupportedSchema)
        ));
        assert!(matches!(
            compare_process_inventory_json(b"{", l.to_string().as_bytes()),
            Err(ProcessDiffError::MalformedInput)
        ));
        assert!(matches!(
            compare_process_inventory_json(&vec![b' '; MAX_INPUT + 1], l.to_string().as_bytes()),
            Err(ProcessDiffError::InputTooLarge)
        ));
        assert!(parse_bounded_json(br#"{"schema":"one","schema":"two"}"#).is_err());
        let deeply_nested = format!(
            "{}0{}",
            "[".repeat(MAX_DEPTH + 2),
            "]".repeat(MAX_DEPTH + 2)
        );
        assert!(parse_bounded_json(deeply_nested.as_bytes()).is_err());
        let oversized_string = format!("\"{}\"", "x".repeat(MAX_JSON_STRING_BYTES + 1));
        assert!(parse_bounded_json(oversized_string.as_bytes()).is_err());
        let oversized_array = format!(
            "[{}]",
            std::iter::repeat_n("null", MAX_JSON_COLLECTION + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(parse_bounded_json(oversized_array.as_bytes()).is_err());
    }
}
