//! Bounded same-platform comparison of selected-path permission inventories.

use serde::Serialize;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MAX_INPUT: usize = 64 * 1024 * 1024;
const MAX_PATHS: usize = 256;
const MAX_LINUX_PATH_HEX: usize = 8_192;
const MAX_WINDOWS_PATH_HEX: usize = 131_068;
const MAX_ACL_BYTES: usize = 64 * 1024;
const MAX_AGGREGATE_ACL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ACE_BYTES: usize = 64 * 1024;
const MAX_ACES: usize = 1024;
const MAX_TEXT: usize = 32_768;
const MAX_WINDOWS_PATH_TEXT: usize = 131_068;
const MAX_OUTPUT_DELTAS: usize = 512;
const MAX_DEPTH: usize = 32;
const MAX_COLLECTION: usize = 65_536;
const MAX_NODES: usize = 1_000_000;
const MAX_JSON_STRING: usize = 128 * 1024;
const LINUX: &str = "sideeffect.permission_inventory";
const WINDOWS: &str = "sideeffect.windows_permission_inventory";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDiffStatus {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Serialize)]
pub struct PermissionDiff {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub before_captured_at_unix_ms: u128,
    pub after_captured_at_unix_ms: u128,
    pub status: PermissionDiffStatus,
    pub coverage_note: &'static str,
    pub counts: PermissionDiffCounts,
    pub diagnostics: Vec<&'static str>,
    pub deltas: Vec<PermissionDelta>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PermissionDiffCounts {
    pub additions: usize,
    pub removals: usize,
    pub changes: usize,
    pub unknown_paths: usize,
    pub ambiguous_path_groups: usize,
    pub unmatched_rows_suppressed_for_partial_source: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct PermissionDelta {
    pub kind: &'static str,
    pub path_identity_hex: String,
    pub changed_fields: Vec<&'static str>,
    pub unknown_fields: Vec<&'static str>,
    pub before: Option<PermissionSide>,
    pub after: Option<PermissionSide>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PermissionSide {
    pub row_index: usize,
    pub facts: Value,
    pub evidence: PermissionEvidenceRef,
}

#[derive(Clone, Debug, Serialize)]
pub struct PermissionEvidenceRef {
    pub row_index: usize,
    pub path_encoding: &'static str,
    pub path_identity_hex: String,
    pub field_references: Vec<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionDiffError {
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

pub fn is_permission_inventory_json(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_INPUT
        && parse_bounded_json(bytes)
            .ok()
            .and_then(|v| v.get("schema").and_then(Value::as_str).map(str::to_owned))
            .is_some_and(|s| s == LINUX || s == WINDOWS)
}

pub fn compare_permission_inventory_json(
    before: &[u8],
    after: &[u8],
) -> Result<PermissionDiff, PermissionDiffError> {
    if before.len().saturating_add(after.len()) > MAX_INPUT {
        return Err(PermissionDiffError::InputTooLarge);
    }
    let left = parse_bounded_json(before)?;
    let right = parse_bounded_json(after)?;
    let lk = kind(&left)?;
    let rk = kind(&right)?;
    if lk != rk {
        return Err(PermissionDiffError::SchemaMismatch);
    }
    validate(&left, lk)?;
    validate(&right, rk)?;
    compare(&left, &right, lk)
}

struct JsonBudget(usize);
struct ValueSeed<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}
struct StringSeed;

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
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
        d.deserialize_any(ValueVisitor {
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
            serde_json::Number::from_f64(v).ok_or_else(|| E::custom("invalid JSON number"))?,
        ))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        if v.len() > MAX_JSON_STRING {
            return Err(E::custom("JSON string limit exceeded"));
        }
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        if v.len() > MAX_JSON_STRING {
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
        ValueSeed {
            budget: self.budget,
            depth: self.depth + 1,
        }
        .deserialize(d)
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
        while let Some(key) = map.next_key_seed(StringSeed)? {
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
impl<'de> DeserializeSeed<'de> for StringSeed {
    type Value = String;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<String, D::Error> {
        d.deserialize_string(StringVisitor)
    }
}
struct StringVisitor;
impl Visitor<'_> for StringVisitor {
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
fn parse_bounded_json(bytes: &[u8]) -> Result<Value, PermissionDiffError> {
    if bytes.len() > MAX_INPUT {
        return Err(PermissionDiffError::InputTooLarge);
    }
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let value = ValueSeed {
        budget: &mut JsonBudget(0),
        depth: 0,
    }
    .deserialize(&mut d)
    .map_err(|_| PermissionDiffError::MalformedInput)?;
    d.end().map_err(|_| PermissionDiffError::MalformedInput)?;
    Ok(value)
}

fn kind(v: &Value) -> Result<Kind, PermissionDiffError> {
    match v.get("schema").and_then(Value::as_str) {
        Some(LINUX) => Ok(Kind::Linux),
        Some(WINDOWS) => Ok(Kind::Windows),
        _ => Err(PermissionDiffError::UnsupportedSchema),
    }
}
fn obj(v: &Value) -> Result<&Map<String, Value>, PermissionDiffError> {
    v.as_object().ok_or(PermissionDiffError::MalformedInput)
}
fn arr<'a>(v: &'a Value, k: &str) -> Result<&'a [Value], PermissionDiffError> {
    v.get(k)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(PermissionDiffError::MalformedInput)
}
fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str, PermissionDiffError> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or(PermissionDiffError::MalformedInput)
}
fn n(v: &Value, k: &str) -> Result<u64, PermissionDiffError> {
    v.get(k)
        .and_then(Value::as_u64)
        .ok_or(PermissionDiffError::MalformedInput)
}
fn opt_string(v: &Value, k: &str) -> Result<(), PermissionDiffError> {
    if v.get(k).is_some_and(|x| !x.is_string()) {
        return Err(PermissionDiffError::MalformedInput);
    }
    Ok(())
}
fn nullable_string(v: &Value, k: &str) -> Result<(), PermissionDiffError> {
    if v.get(k).is_some_and(|x| !x.is_null() && !x.is_string()) {
        return Err(PermissionDiffError::MalformedInput);
    }
    Ok(())
}
fn opt_num(v: &Value, k: &str) -> Result<(), PermissionDiffError> {
    if v.get(k)
        .is_some_and(|x| !x.is_null() && x.as_u64().is_none())
    {
        return Err(PermissionDiffError::MalformedInput);
    }
    Ok(())
}
fn keys(v: &Value, allowed: &[&str]) -> Result<(), PermissionDiffError> {
    if obj(v)?.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(PermissionDiffError::MalformedInput);
    }
    Ok(())
}
fn hex_len(v: &str, max: usize, even: bool) -> bool {
    v.len() <= max && (!even || v.len() % 2 == 0) && v.bytes().all(|b| b.is_ascii_hexdigit())
}
fn canonical_hex(v: &str) -> bool {
    v.bytes().all(|b| !b.is_ascii_uppercase())
}
fn valid_sha(v: Option<&str>) -> bool {
    v.is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) && canonical_hex(s))
}
fn decoded_hex(v: &str) -> Result<Vec<u8>, PermissionDiffError> {
    if !hex_len(v, MAX_ACL_BYTES * 2, true) {
        return Err(PermissionDiffError::MalformedInput);
    }
    let mut out = Vec::with_capacity(v.len() / 2);
    for pair in v.as_bytes().chunks_exact(2) {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        out.push(
            (digit(pair[0]).ok_or(PermissionDiffError::MalformedInput)? << 4)
                | digit(pair[1]).ok_or(PermissionDiffError::MalformedInput)?,
        );
    }
    Ok(out)
}
fn status_in<'a>(
    v: &'a Value,
    key: &str,
    allowed: &[&str],
) -> Result<&'a str, PermissionDiffError> {
    let value = s(v, key)?;
    if !allowed.contains(&value) {
        return Err(PermissionDiffError::MalformedInput);
    }
    Ok(value)
}

fn validate(v: &Value, kind: Kind) -> Result<(), PermissionDiffError> {
    match kind {
        Kind::Linux => validate_linux(v),
        Kind::Windows => validate_windows(v),
    }
}
fn validate_linux(v: &Value) -> Result<(), PermissionDiffError> {
    keys(
        v,
        &[
            "schema",
            "schema_version",
            "platform",
            "scope",
            "captured_at_unix_ms",
            "status",
            "paths_requested",
            "acl_bytes_read",
            "capability_bytes_read",
            "objects",
            "diagnostics",
        ],
    )?;
    if s(v, "schema")? != LINUX || n(v, "schema_version")? != 1 {
        return Err(PermissionDiffError::UnsupportedSchema);
    }
    if s(v, "platform")? != "linux" {
        return Err(PermissionDiffError::PlatformMismatch);
    }
    if s(v, "scope")? != "explicit_paths_metadata_posix_acl_file_capability" {
        return Err(PermissionDiffError::MalformedInput);
    }
    let full = status_in(v, "status", &["complete", "partial"])? == "complete";
    let requested = n(v, "paths_requested")?;
    let acl_bytes = n(v, "acl_bytes_read")?;
    let cap_bytes = n(v, "capability_bytes_read")?;
    if requested > MAX_PATHS as u64
        || acl_bytes > MAX_AGGREGATE_ACL_BYTES
        || cap_bytes > MAX_AGGREGATE_ACL_BYTES
    {
        return Err(PermissionDiffError::LimitExceeded);
    }
    let objects = arr(v, "objects")?;
    if objects.len() > MAX_PATHS || objects.len() > requested as usize {
        return Err(PermissionDiffError::LimitExceeded);
    }
    let diagnostics = arr(v, "diagnostics")?;
    validate_diagnostics(diagnostics)?;
    let mut seen_acl = 0_u64;
    let mut seen_cap = 0_u64;
    for row in objects {
        validate_linux_row(row)?;
        seen_acl = seen_acl.saturating_add(
            row.pointer("/access_acl/byte_length")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        seen_acl = seen_acl.saturating_add(
            row.pointer("/default_acl/byte_length")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        seen_cap = seen_cap.saturating_add(
            row.pointer("/file_capability/byte_length")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
    }
    if seen_acl > MAX_AGGREGATE_ACL_BYTES
        || seen_cap > MAX_AGGREGATE_ACL_BYTES
        || seen_acl > acl_bytes
        || seen_cap > cap_bytes
    {
        return Err(PermissionDiffError::LimitExceeded);
    }
    if full
        && objects
            .iter()
            .any(|r| s(r, "status").ok() != Some("complete"))
    {
        return Err(PermissionDiffError::MalformedInput);
    }
    if full && !diagnostics.is_empty() {
        return Err(PermissionDiffError::MalformedInput);
    }
    if full
        && objects.iter().any(|r| {
            !matches!(
                r.pointer("/access_acl/status").and_then(Value::as_str),
                Some("present" | "absent")
            ) || !matches!(
                r.pointer("/default_acl/status").and_then(Value::as_str),
                Some("present" | "absent" | "not_applicable")
            ) || !matches!(
                r.pointer("/file_capability/status").and_then(Value::as_str),
                Some("present" | "absent")
            ) || r
                .get("diagnostics")
                .and_then(Value::as_array)
                .is_none_or(|d| !d.is_empty())
        })
    {
        return Err(PermissionDiffError::MalformedInput);
    }
    Ok(())
}
fn validate_diagnostics(values: &[Value]) -> Result<(), PermissionDiffError> {
    if values.len() > 65_536 {
        return Err(PermissionDiffError::LimitExceeded);
    }
    for d in values {
        validate_diagnostic(d)?;
    }
    Ok(())
}
fn validate_linux_row(r: &Value) -> Result<(), PermissionDiffError> {
    keys(
        r,
        &[
            "path",
            "path_bytes_hex",
            "status",
            "object_type",
            "uid",
            "gid",
            "mode",
            "device",
            "inode",
            "access_acl",
            "default_acl",
            "file_capability",
            "diagnostics",
        ],
    )?;
    let path = s(r, "path_bytes_hex")?;
    if path.is_empty() || !hex_len(path, MAX_LINUX_PATH_HEX, true) || !canonical_hex(path) {
        return Err(PermissionDiffError::MalformedInput);
    }
    opt_string(r, "path")?;
    if r.get("path")
        .and_then(Value::as_str)
        .is_some_and(|x| x.len() > MAX_TEXT)
    {
        return Err(PermissionDiffError::LimitExceeded);
    }
    let status = status_in(
        r,
        "status",
        &["complete", "partial", "unavailable", "access_denied"],
    )?;
    if let Some(t) = r.get("object_type") {
        if !matches!(
            t.as_str(),
            Some("regular_file" | "directory" | "symbolic_link" | "other")
        ) {
            return Err(PermissionDiffError::MalformedInput);
        }
    }
    for k in ["uid", "gid", "mode", "device", "inode"] {
        opt_num(r, k)?;
    }
    for k in ["uid", "gid", "mode"] {
        if r.get(k)
            .and_then(Value::as_u64)
            .is_some_and(|x| x > u32::MAX as u64)
        {
            return Err(PermissionDiffError::MalformedInput);
        }
    }
    validate_acl(
        r.get("access_acl")
            .ok_or(PermissionDiffError::MalformedInput)?,
        false,
    )?;
    validate_acl(
        r.get("default_acl")
            .ok_or(PermissionDiffError::MalformedInput)?,
        true,
    )?;
    validate_cap(
        r.get("file_capability")
            .ok_or(PermissionDiffError::MalformedInput)?,
    )?;
    validate_diagnostics(arr(r, "diagnostics")?)?;
    if status == "complete"
        && (!arr(r, "diagnostics")?.is_empty()
            || r.get("object_type").is_none()
            || r.get("uid").and_then(Value::as_u64).is_none()
            || r.get("gid").and_then(Value::as_u64).is_none()
            || r.get("mode").and_then(Value::as_u64).is_none()
            || r.get("device").and_then(Value::as_u64).is_none()
            || r.get("inode").and_then(Value::as_u64).is_none())
    {
        return Err(PermissionDiffError::MalformedInput);
    }
    Ok(())
}
fn validate_acl(v: &Value, default_acl: bool) -> Result<(), PermissionDiffError> {
    keys(
        v,
        &[
            "status",
            "source",
            "byte_length",
            "bytes_hex",
            "sha256",
            "entries",
        ],
    )?;
    let status = status_in(
        v,
        "status",
        &[
            "present",
            "absent",
            "not_applicable",
            "inaccessible",
            "unsupported",
            "malformed",
            "limit_exceeded",
            "failed",
        ],
    )?;
    opt_string(v, "source")?;
    opt_string(v, "bytes_hex")?;
    opt_string(v, "sha256")?;
    opt_num(v, "byte_length")?;
    if status == "not_applicable" && !default_acl {
        return Err(PermissionDiffError::MalformedInput);
    }
    if let Some(bytes) = v.get("bytes_hex").and_then(Value::as_str) {
        if !hex_len(bytes, MAX_ACL_BYTES * 2, true) {
            return Err(PermissionDiffError::LimitExceeded);
        }
    }
    if let Some(entries) = v.get("entries") {
        let entries = entries
            .as_array()
            .ok_or(PermissionDiffError::MalformedInput)?;
        if entries.len() > 32 {
            return Err(PermissionDiffError::LimitExceeded);
        }
        for e in entries {
            keys(e, &["tag", "permissions", "id"])?;
            if !matches!(
                s(e, "tag")?,
                "user_object" | "user" | "group_object" | "group" | "mask" | "other"
            ) || n(e, "permissions")? > 7
            {
                return Err(PermissionDiffError::MalformedInput);
            }
            opt_num(e, "id")?;
            if e.get("id")
                .and_then(Value::as_u64)
                .is_some_and(|id| id > u32::MAX as u64)
            {
                return Err(PermissionDiffError::MalformedInput);
            }
        }
    }
    if status == "present" {
        let bytes = v
            .get("bytes_hex")
            .and_then(Value::as_str)
            .ok_or(PermissionDiffError::MalformedInput)?;
        if v.get("byte_length").and_then(Value::as_u64) != Some((bytes.len() / 2) as u64)
            || !valid_sha(v.get("sha256").and_then(Value::as_str))
            || crate::fingerprint::sha256_hex(&decoded_hex(bytes)?)
                != v.get("sha256").and_then(Value::as_str).unwrap_or("")
            || v.get("entries").and_then(Value::as_array).is_none()
        {
            return Err(PermissionDiffError::MalformedInput);
        }
        let raw = decoded_hex(bytes)?;
        if decode_acl_entries(&raw)?
            != *v
                .get("entries")
                .ok_or(PermissionDiffError::MalformedInput)?
        {
            return Err(PermissionDiffError::MalformedInput);
        }
    }
    Ok(())
}
fn validate_cap(v: &Value) -> Result<(), PermissionDiffError> {
    keys(
        v,
        &[
            "status",
            "source",
            "byte_length",
            "bytes_hex",
            "sha256",
            "revision",
            "effective",
            "permitted",
            "inheritable",
            "root_id",
        ],
    )?;
    let status = status_in(
        v,
        "status",
        &[
            "present",
            "absent",
            "inaccessible",
            "unsupported",
            "malformed",
            "limit_exceeded",
            "failed",
        ],
    )?;
    opt_string(v, "source")?;
    opt_string(v, "bytes_hex")?;
    opt_string(v, "sha256")?;
    for k in ["byte_length", "revision", "root_id"] {
        opt_num(v, k)?;
    }
    if v.get("bytes_hex")
        .and_then(Value::as_str)
        .is_some_and(|x| !hex_len(x, MAX_ACL_BYTES * 2, true))
    {
        return Err(PermissionDiffError::LimitExceeded);
    }
    if v.get("effective").is_some_and(|x| !x.is_boolean()) {
        return Err(PermissionDiffError::MalformedInput);
    }
    for k in ["permitted", "inheritable"] {
        if let Some(a) = v.get(k) {
            let a = a.as_array().ok_or(PermissionDiffError::MalformedInput)?;
            if a.len() > 2 || a.iter().any(|x| x.as_u64().is_none_or(|n| n > 255)) {
                return Err(PermissionDiffError::MalformedInput);
            }
        }
    }
    if v.get("root_id")
        .and_then(Value::as_u64)
        .is_some_and(|n| n > u32::MAX as u64)
    {
        return Err(PermissionDiffError::MalformedInput);
    }
    if status == "present" {
        let bytes = v
            .get("bytes_hex")
            .and_then(Value::as_str)
            .ok_or(PermissionDiffError::MalformedInput)?;
        if v.get("byte_length").and_then(Value::as_u64) != Some((bytes.len() / 2) as u64)
            || !valid_sha(v.get("sha256").and_then(Value::as_str))
            || crate::fingerprint::sha256_hex(&decoded_hex(bytes)?)
                != v.get("sha256").and_then(Value::as_str).unwrap_or("")
        {
            return Err(PermissionDiffError::MalformedInput);
        }
        let raw = decoded_hex(bytes)?;
        let decoded = decode_capability(&raw)?;
        if v.get("revision").and_then(Value::as_u64) != Some(decoded.revision)
            || v.get("effective").and_then(Value::as_bool) != Some(decoded.effective)
            || v.get("permitted")
                != Some(&Value::Array(
                    decoded.permitted.into_iter().map(Value::from).collect(),
                ))
            || v.get("inheritable")
                != Some(&Value::Array(
                    decoded.inheritable.into_iter().map(Value::from).collect(),
                ))
            || v.get("root_id").and_then(Value::as_u64) != decoded.root_id
        {
            return Err(PermissionDiffError::MalformedInput);
        }
    }
    Ok(())
}
fn validate_windows(v: &Value) -> Result<(), PermissionDiffError> {
    keys(
        v,
        &[
            "schema",
            "schema_version",
            "platform",
            "scope",
            "capture_started_at_unix_ms",
            "capture_ended_at_unix_ms",
            "status",
            "objects",
            "diagnostics",
            "limits",
        ],
    )?;
    if s(v, "schema")? != WINDOWS || n(v, "schema_version")? != 1 {
        return Err(PermissionDiffError::UnsupportedSchema);
    }
    if s(v, "platform")? != "windows" {
        return Err(PermissionDiffError::PlatformMismatch);
    }
    if s(v, "scope")?
        != "explicit_paths_only; final_reparse_points_opened_without_following; no_sacl; no_effective_access_calculation"
    {
        return Err(PermissionDiffError::MalformedInput);
    }
    if n(v, "capture_started_at_unix_ms")? > n(v, "capture_ended_at_unix_ms")? {
        return Err(PermissionDiffError::MalformedInput);
    }
    let full = status_in(
        v,
        "status",
        &[
            "complete",
            "partial",
            "inaccessible",
            "not_present",
            "limit_reached",
            "error",
        ],
    )? == "complete";
    validate_windows_limits(v.get("limits").ok_or(PermissionDiffError::MalformedInput)?)?;
    let diagnostics = arr(v, "diagnostics")?;
    validate_diagnostics(diagnostics)?;
    let rows = arr(v, "objects")?;
    if rows.len() > MAX_PATHS {
        return Err(PermissionDiffError::LimitExceeded);
    }
    let mut descriptors = 0_u64;
    for r in rows {
        validate_windows_row(r)?;
        descriptors = descriptors.saturating_add(
            r.pointer("/security/descriptor_length")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
    }
    if descriptors > MAX_AGGREGATE_ACL_BYTES {
        return Err(PermissionDiffError::LimitExceeded);
    }
    if full && rows.iter().any(|r| s(r, "status").ok() != Some("complete")) {
        return Err(PermissionDiffError::MalformedInput);
    }
    if full && !diagnostics.is_empty() {
        return Err(PermissionDiffError::MalformedInput);
    }
    if full
        && rows.iter().any(|r| {
            !r.get("diagnostic").is_none_or(Value::is_null)
                || r.pointer("/security/parse_diagnostic")
                    .is_some_and(|d| !d.is_null())
        })
    {
        return Err(PermissionDiffError::MalformedInput);
    }
    Ok(())
}
fn validate_windows_limits(v: &Value) -> Result<(), PermissionDiffError> {
    keys(
        v,
        &[
            "max_paths",
            "max_utf16_units_per_path",
            "max_total_path_utf16_units",
            "max_descriptor_bytes",
            "max_aces_per_descriptor",
            "max_aggregate_descriptor_bytes",
            "deadline_ms_between_paths",
        ],
    )?;
    let expected = [
        ("max_paths", 256),
        ("max_utf16_units_per_path", 32767),
        ("max_total_path_utf16_units", 1_048_576),
        ("max_descriptor_bytes", 65536),
        ("max_aces_per_descriptor", 1024),
        ("max_aggregate_descriptor_bytes", 8 * 1024 * 1024),
        ("deadline_ms_between_paths", 5000),
    ];
    for (k, x) in expected {
        if n(v, k)? != x {
            return Err(PermissionDiffError::MalformedInput);
        }
    }
    Ok(())
}
fn validate_windows_row(r: &Value) -> Result<(), PermissionDiffError> {
    keys(
        r,
        &[
            "path",
            "path_utf16_hex",
            "status",
            "metadata",
            "security",
            "diagnostic",
        ],
    )?;
    let path = s(r, "path_utf16_hex")?;
    if path.is_empty()
        || path.len() > MAX_WINDOWS_PATH_HEX
        || !hex_len(path, MAX_WINDOWS_PATH_HEX, true)
        || !canonical_hex(path)
        || path.len() % 4 != 0
    {
        return Err(PermissionDiffError::MalformedInput);
    }
    opt_string(r, "path")?;
    if r.get("path")
        .and_then(Value::as_str)
        .is_some_and(|x| x.len() > MAX_WINDOWS_PATH_TEXT)
    {
        return Err(PermissionDiffError::LimitExceeded);
    }
    let status = status_in(
        r,
        "status",
        &[
            "complete",
            "partial",
            "inaccessible",
            "not_present",
            "limit_reached",
            "error",
        ],
    )?;
    if let Some(d) = r.get("diagnostic").filter(|d| !d.is_null()) {
        validate_diagnostic(d)?;
    }
    if let Some(m) = r.get("metadata").filter(|m| !m.is_null()) {
        keys(
            m,
            &[
                "attributes",
                "is_directory",
                "is_reparse_point",
                "volume_serial_number",
                "file_index",
                "size_bytes",
                "last_write_filetime",
            ],
        )?;
        for k in [
            "attributes",
            "volume_serial_number",
            "file_index",
            "size_bytes",
            "last_write_filetime",
        ] {
            let _ = n(m, k)?;
        }
        for k in ["is_directory", "is_reparse_point"] {
            if !m.get(k).is_some_and(Value::is_boolean) {
                return Err(PermissionDiffError::MalformedInput);
            }
        }
    }
    if let Some(sec) = r.get("security").filter(|s| !s.is_null()) {
        validate_security(sec)?;
        if let Some(code) = sec.get("parse_diagnostic").and_then(Value::as_str) {
            if status != "partial"
                || r.pointer("/diagnostic/code").and_then(Value::as_str) != Some(code)
            {
                return Err(PermissionDiffError::MalformedInput);
            }
        }
    }
    if status == "complete"
        && (r.get("metadata").is_none_or(Value::is_null)
            || r.get("security").is_none_or(Value::is_null))
    {
        return Err(PermissionDiffError::MalformedInput);
    }
    Ok(())
}
fn validate_diagnostic(v: &Value) -> Result<(), PermissionDiffError> {
    keys(
        v,
        &["code", "path_index", "source", "message", "win32_error"],
    )?;
    let _ = s(v, "code")?;
    nullable_string(v, "source")?;
    opt_string(v, "message")?;
    opt_num(v, "path_index")?;
    opt_num(v, "win32_error")?;
    Ok(())
}
fn validate_security(v: &Value) -> Result<(), PermissionDiffError> {
    keys(
        v,
        &[
            "descriptor_length",
            "descriptor_sha256",
            "descriptor_raw_hex",
            "control",
            "owner_sid_raw_hex",
            "group_sid_raw_hex",
            "dacl_state",
            "dacl_protected",
            "dacl_auto_inherited",
            "aces",
            "parse_diagnostic",
        ],
    )?;
    let length = n(v, "descriptor_length")? as usize;
    if !(20..=MAX_ACL_BYTES).contains(&length) {
        return Err(PermissionDiffError::LimitExceeded);
    }
    let raw = s(v, "descriptor_raw_hex")?;
    if !hex_len(raw, MAX_ACL_BYTES * 2, true) || !canonical_hex(raw) || raw.len() != length * 2 {
        return Err(PermissionDiffError::MalformedInput);
    }
    let hash = s(v, "descriptor_sha256")?;
    if !valid_sha(Some(hash)) || crate::fingerprint::sha256_hex(&decoded_hex(raw)?) != hash {
        return Err(PermissionDiffError::MalformedInput);
    }
    if n(v, "control")? > u16::MAX as u64 {
        return Err(PermissionDiffError::MalformedInput);
    }
    let dacl_state = s(v, "dacl_state")?;
    let parse_diagnostic = v.get("parse_diagnostic").and_then(Value::as_str);
    if !matches!(
        dacl_state,
        "present" | "absent" | "null" | "empty" | "malformed_or_unsupported"
    ) || (dacl_state == "malformed_or_unsupported") != parse_diagnostic.is_some()
        || (dacl_state == "empty" && parse_diagnostic.is_some())
    {
        return Err(PermissionDiffError::MalformedInput);
    }
    for k in ["dacl_protected", "dacl_auto_inherited"] {
        if !v.get(k).is_some_and(Value::is_boolean) {
            return Err(PermissionDiffError::MalformedInput);
        }
    }
    for k in ["owner_sid_raw_hex", "group_sid_raw_hex", "parse_diagnostic"] {
        nullable_string(v, k)?;
    }
    for k in ["owner_sid_raw_hex", "group_sid_raw_hex"] {
        if v.get(k)
            .and_then(Value::as_str)
            .is_some_and(|x| !hex_len(x, 1024, true))
        {
            return Err(PermissionDiffError::MalformedInput);
        }
    }
    if let Some(aces) = v.get("aces") {
        let aces = aces.as_array().ok_or(PermissionDiffError::MalformedInput)?;
        if aces.len() > MAX_ACES {
            return Err(PermissionDiffError::LimitExceeded);
        }
        for (expected_index, a) in aces.iter().enumerate() {
            keys(
                a,
                &[
                    "index",
                    "ace_type",
                    "type_name",
                    "flags",
                    "inherited",
                    "inherit_only",
                    "ace_size",
                    "access_mask",
                    "trustee_sid_raw_hex",
                    "raw_hex",
                    "recognized",
                ],
            )?;
            let index = n(a, "index")?;
            let size = n(a, "ace_size")? as usize;
            if index != expected_index as u64 || !(4..=MAX_ACE_BYTES).contains(&size) {
                return Err(PermissionDiffError::LimitExceeded);
            }
            let _ = n(a, "ace_type")?;
            let _ = n(a, "flags")?;
            let _ = s(a, "type_name")?;
            for k in ["inherited", "inherit_only", "recognized"] {
                if !a.get(k).is_some_and(Value::is_boolean) {
                    return Err(PermissionDiffError::MalformedInput);
                }
            }
            opt_num(a, "access_mask")?;
            if a.get("access_mask")
                .and_then(Value::as_u64)
                .is_some_and(|x| x > u32::MAX as u64)
            {
                return Err(PermissionDiffError::MalformedInput);
            }
            nullable_string(a, "trustee_sid_raw_hex")?;
            if a.get("trustee_sid_raw_hex")
                .and_then(Value::as_str)
                .is_some_and(|x| !hex_len(x, 1024, true))
            {
                return Err(PermissionDiffError::MalformedInput);
            }
            let raw = s(a, "raw_hex")?;
            if !hex_len(raw, MAX_ACE_BYTES * 2, true)
                || !canonical_hex(raw)
                || raw.len() != size * 2
            {
                return Err(PermissionDiffError::MalformedInput);
            }
        }
    }
    if v.get("aces").is_none() {
        return Err(PermissionDiffError::MalformedInput);
    }
    validate_descriptor_sidecars(v)?;
    Ok(())
}

fn decode_acl_entries(bytes: &[u8]) -> Result<Value, PermissionDiffError> {
    if bytes.len() < 4 || (bytes.len() - 4) % 8 != 0 || le32(bytes, 0) != Some(2) {
        return Err(PermissionDiffError::MalformedInput);
    }
    let mut entries = Vec::new();
    for chunk in bytes[4..].chunks_exact(8) {
        let tag = u16::from_le_bytes([chunk[0], chunk[1]]);
        let perms = u16::from_le_bytes([chunk[2], chunk[3]]);
        let id = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
        if perms > 7 {
            return Err(PermissionDiffError::MalformedInput);
        }
        let (name, id) = match (tag, id) {
            (1, u32::MAX) => ("user_object", Value::Null),
            (2, id) if id != u32::MAX => ("user", Value::from(id)),
            (4, u32::MAX) => ("group_object", Value::Null),
            (8, id) if id != u32::MAX => ("group", Value::from(id)),
            (16, u32::MAX) => ("mask", Value::Null),
            (32, u32::MAX) => ("other", Value::Null),
            _ => return Err(PermissionDiffError::MalformedInput),
        };
        let mut e = serde_json::Map::new();
        e.insert("tag".into(), Value::from(name));
        e.insert("permissions".into(), Value::from(perms));
        if !id.is_null() {
            e.insert("id".into(), id);
        }
        entries.push(Value::Object(e));
    }
    if entries.len() < 3
        || entries
            .first()
            .and_then(|e| e.get("tag"))
            .and_then(Value::as_str)
            != Some("user_object")
        || entries
            .last()
            .and_then(|e| e.get("tag"))
            .and_then(Value::as_str)
            != Some("other")
    {
        return Err(PermissionDiffError::MalformedInput);
    }
    let mut phase = 0;
    let mut previous_user = None;
    let mut previous_group = None;
    let mut seen_group_object = false;
    let mut named = false;
    let mut mask = false;
    for entry in entries.iter().skip(1).take(entries.len() - 2) {
        let tag = entry["tag"].as_str().unwrap_or("");
        match tag {
            "user" if phase <= 1 => {
                phase = 1;
                let id = entry
                    .get("id")
                    .and_then(Value::as_u64)
                    .ok_or(PermissionDiffError::MalformedInput)?;
                if previous_user.is_some_and(|prior| prior >= id) {
                    return Err(PermissionDiffError::MalformedInput);
                }
                previous_user = Some(id);
                named = true;
            }
            "group_object" if phase <= 2 && !seen_group_object => {
                phase = 2;
                seen_group_object = true;
            }
            "group" if phase <= 3 => {
                phase = 3;
                let id = entry
                    .get("id")
                    .and_then(Value::as_u64)
                    .ok_or(PermissionDiffError::MalformedInput)?;
                if previous_group.is_some_and(|prior| prior >= id) {
                    return Err(PermissionDiffError::MalformedInput);
                }
                previous_group = Some(id);
                named = true;
            }
            "mask" if phase <= 4 && !mask => {
                phase = 4;
                mask = true;
            }
            _ => return Err(PermissionDiffError::MalformedInput),
        }
    }
    if !seen_group_object || named && !mask {
        return Err(PermissionDiffError::MalformedInput);
    }
    Ok(Value::Array(entries))
}

struct DecodedCapability {
    revision: u64,
    effective: bool,
    permitted: Vec<u64>,
    inheritable: Vec<u64>,
    root_id: Option<u64>,
}
fn decode_capability(bytes: &[u8]) -> Result<DecodedCapability, PermissionDiffError> {
    if bytes.len() < 4 {
        return Err(PermissionDiffError::MalformedInput);
    }
    let magic = le32(bytes, 0).ok_or(PermissionDiffError::MalformedInput)?;
    let version = magic & 0xff00_0000;
    let (revision, expected, words) = match version {
        0x0100_0000 => (1, 12, 1),
        0x0200_0000 => (2, 20, 2),
        0x0300_0000 => (3, 24, 2),
        _ => return Err(PermissionDiffError::MalformedInput),
    };
    if bytes.len() != expected || magic & !(0xff00_0000 | 1) != 0 {
        return Err(PermissionDiffError::MalformedInput);
    }
    let mut permitted = Vec::new();
    let mut inheritable = Vec::new();
    for word in 0..words {
        let p = le32(bytes, 4 + word * 8).ok_or(PermissionDiffError::MalformedInput)?;
        let i = le32(bytes, 8 + word * 8).ok_or(PermissionDiffError::MalformedInput)?;
        for bit in 0..32 {
            if p & (1 << bit) != 0 {
                permitted.push((word * 32 + bit) as u64);
            }
            if i & (1 << bit) != 0 {
                inheritable.push((word * 32 + bit) as u64);
            }
        }
    }
    let root = if revision == 3 {
        Some(le32(bytes, 20).ok_or(PermissionDiffError::MalformedInput)? as u64)
    } else {
        None
    };
    Ok(DecodedCapability {
        revision,
        effective: magic & 1 != 0,
        permitted,
        inheritable,
        root_id: root,
    })
}

fn le16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn le32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn validate_descriptor_sidecars(v: &Value) -> Result<(), PermissionDiffError> {
    if let Some(code) = v.get("parse_diagnostic").and_then(Value::as_str) {
        if code.is_empty()
            || s(v, "dacl_state")? != "malformed_or_unsupported"
            || v.get("owner_sid_raw_hex").is_some_and(|sid| !sid.is_null())
            || v.get("group_sid_raw_hex").is_some_and(|sid| !sid.is_null())
            || !arr(v, "aces")?.is_empty()
            || v.get("dacl_protected").and_then(Value::as_bool) != Some(false)
            || v.get("dacl_auto_inherited").and_then(Value::as_bool) != Some(false)
        {
            return Err(PermissionDiffError::MalformedInput);
        }
        let raw = decoded_hex(s(v, "descriptor_raw_hex")?)?;
        let expected_control = le16(&raw, 2).unwrap_or_default();
        if n(v, "control")? != expected_control as u64 {
            return Err(PermissionDiffError::MalformedInput);
        }
        return Ok(());
    }
    let raw = decoded_hex(s(v, "descriptor_raw_hex")?)?;
    if raw.len() < 20 || raw[0] != 1 {
        return Err(PermissionDiffError::MalformedInput);
    }
    let control = le16(&raw, 2).ok_or(PermissionDiffError::MalformedInput)?;
    if control & 0x8000 == 0 || n(v, "control")? != control as u64 {
        return Err(PermissionDiffError::MalformedInput);
    }
    let sid = |offset: usize| -> Result<Option<String>, PermissionDiffError> {
        let at = le32(&raw, offset).ok_or(PermissionDiffError::MalformedInput)? as usize;
        if at == 0 {
            return Ok(None);
        }
        if at.checked_add(8).is_none_or(|end| end > raw.len()) || raw[at] != 1 {
            return Err(PermissionDiffError::MalformedInput);
        }
        let len = 8 + raw[at + 1] as usize * 4;
        if at + len > raw.len() {
            return Err(PermissionDiffError::MalformedInput);
        }
        Ok(Some(hex(&raw[at..at + len])))
    };
    let owner = sid(4)?;
    let group = sid(8)?;
    if v.get("owner_sid_raw_hex").and_then(Value::as_str) != owner.as_deref()
        || v.get("group_sid_raw_hex").and_then(Value::as_str) != group.as_deref()
        || v.get("dacl_protected").and_then(Value::as_bool) != Some(control & 0x1000 != 0)
        || v.get("dacl_auto_inherited").and_then(Value::as_bool) != Some(control & 0x0400 != 0)
    {
        return Err(PermissionDiffError::MalformedInput);
    }
    let present = control & 4 != 0;
    let dacl = le32(&raw, 16).ok_or(PermissionDiffError::MalformedInput)? as usize;
    let expected_state = if !present {
        "absent"
    } else if dacl == 0 {
        "null"
    } else {
        if dacl.checked_add(8).is_none_or(|end| end > raw.len()) {
            return Err(PermissionDiffError::MalformedInput);
        }
        if le16(&raw, dacl + 4).ok_or(PermissionDiffError::MalformedInput)? == 0 {
            "empty"
        } else {
            "present"
        }
    };
    if s(v, "dacl_state")? != expected_state {
        return Err(PermissionDiffError::MalformedInput);
    }
    let aces = arr(v, "aces")?;
    if !present || dacl == 0 {
        if !aces.is_empty() {
            return Err(PermissionDiffError::MalformedInput);
        }
    } else {
        if dacl < 20 || dacl.checked_add(8).is_none_or(|e| e > raw.len()) {
            return Err(PermissionDiffError::MalformedInput);
        }
        let size = le16(&raw, dacl + 2).ok_or(PermissionDiffError::MalformedInput)? as usize;
        let count = le16(&raw, dacl + 4).ok_or(PermissionDiffError::MalformedInput)? as usize;
        let end = dacl
            .checked_add(size)
            .filter(|e| *e <= raw.len())
            .ok_or(PermissionDiffError::MalformedInput)?;
        if !matches!(raw[dacl], 2 | 4) || size < 8 || count != aces.len() || count > MAX_ACES {
            return Err(PermissionDiffError::MalformedInput);
        }
        let mut at = dacl + 8;
        for (index, ace) in aces.iter().enumerate() {
            if at + 4 > end {
                return Err(PermissionDiffError::MalformedInput);
            }
            let ty = raw[at];
            let flags = raw[at + 1];
            let len = le16(&raw, at + 2).ok_or(PermissionDiffError::MalformedInput)? as usize;
            let next = at
                .checked_add(len)
                .filter(|e| len >= 4 && len % 4 == 0 && *e <= end)
                .ok_or(PermissionDiffError::MalformedInput)?;
            let (mask, trustee) = if ty <= 2 {
                if len < 12 {
                    return Err(PermissionDiffError::MalformedInput);
                }
                let sid_at = at + 8;
                if sid_at + 8 > next || raw[sid_at] != 1 {
                    return Err(PermissionDiffError::MalformedInput);
                }
                let sid_len = 8 + raw[sid_at + 1] as usize * 4;
                if sid_at + sid_len > next {
                    return Err(PermissionDiffError::MalformedInput);
                }
                (
                    Some(le32(&raw, at + 4).ok_or(PermissionDiffError::MalformedInput)? as u64),
                    Some(hex(&raw[sid_at..sid_at + sid_len])),
                )
            } else {
                (None, None)
            };
            if n(ace, "index")? != index as u64
                || n(ace, "ace_type")? != ty as u64
                || n(ace, "flags")? != flags as u64
                || n(ace, "ace_size")? != len as u64
                || s(ace, "raw_hex")? != hex(&raw[at..next])
                || ace.get("access_mask").and_then(Value::as_u64) != mask
                || ace.get("trustee_sid_raw_hex").and_then(Value::as_str) != trustee.as_deref()
                || ace.get("inherited").and_then(Value::as_bool) != Some(flags & 0x10 != 0)
                || ace.get("inherit_only").and_then(Value::as_bool) != Some(flags & 0x08 != 0)
                || ace.get("recognized").and_then(Value::as_bool) != Some(ty <= 2)
            {
                return Err(PermissionDiffError::MalformedInput);
            }
            at = next;
        }
        if s(v, "dacl_state")? != if aces.is_empty() { "empty" } else { "present" } {
            return Err(PermissionDiffError::MalformedInput);
        }
    }
    Ok(())
}

fn identity(row: &Value, kind: Kind) -> Result<&str, PermissionDiffError> {
    s(
        row,
        if kind == Kind::Linux {
            "path_bytes_hex"
        } else {
            "path_utf16_hex"
        },
    )
}
fn source_full(v: &Value, kind: Kind) -> bool {
    match kind {
        Kind::Linux => v.get("status").and_then(Value::as_str) == Some("complete"),
        Kind::Windows => v.get("status").and_then(Value::as_str) == Some("complete"),
    }
}
fn definite_row(row: &Value, kind: Kind) -> bool {
    match kind {
        Kind::Linux => row.get("status").and_then(Value::as_str) == Some("complete"),
        Kind::Windows => row.get("status").and_then(Value::as_str) == Some("complete"),
    }
}
fn facts(row: &Value, kind: Kind) -> Value {
    match kind {
        Kind::Linux => {
            let mut m = Map::new();
            for k in [
                "status",
                "object_type",
                "uid",
                "gid",
                "mode",
                "device",
                "inode",
            ] {
                m.insert(k.into(), row.get(k).cloned().unwrap_or(Value::Null));
            }
            for (k, v) in [
                ("access_acl", "access_acl"),
                ("default_acl", "default_acl"),
                ("file_capability", "file_capability"),
            ] {
                m.insert(k.into(), linux_component(row.get(v).unwrap()));
            }
            Value::Object(m)
        }
        Kind::Windows => {
            let m = row.get("metadata").cloned().unwrap_or(Value::Null);
            let sec = row
                .get("security")
                .map(windows_security_facts)
                .unwrap_or(Value::Null);
            serde_json::json!({"status":row.get("status"),"metadata":m,"security":sec})
        }
    }
}
fn linux_component(v: &Value) -> Value {
    let status = v.get("status").and_then(Value::as_str).unwrap_or("unknown");
    match status {
        "present" => {
            let mut m = Map::new();
            m.insert("status".into(), Value::String(status.into()));
            for k in [
                "sha256",
                "entries",
                "revision",
                "effective",
                "permitted",
                "inheritable",
                "root_id",
            ] {
                if let Some(x) = v.get(k) {
                    m.insert(k.into(), x.clone());
                }
            }
            Value::Object(m)
        }
        "absent" | "not_applicable" => serde_json::json!({"status":status}),
        _ => serde_json::json!({"status":"unknown"}),
    }
}
fn windows_security_facts(v: &Value) -> Value {
    if !v.get("parse_diagnostic").is_none_or(Value::is_null) {
        return serde_json::json!({"status":"unknown","descriptor_sha256":v.get("descriptor_sha256")});
    }
    serde_json::json!({"descriptor_sha256":v.get("descriptor_sha256"),"control":v.get("control"),"owner_sid_raw_hex":v.get("owner_sid_raw_hex"),"group_sid_raw_hex":v.get("group_sid_raw_hex"),"dacl_state":v.get("dacl_state"),"dacl_protected":v.get("dacl_protected"),"dacl_auto_inherited":v.get("dacl_auto_inherited"),"aces":v.get("aces").and_then(Value::as_array).map(|a|a.iter().map(|ace| serde_json::json!({"index":ace.get("index"),"ace_type":ace.get("ace_type"),"flags":ace.get("flags"),"inherited":ace.get("inherited"),"inherit_only":ace.get("inherit_only"),"ace_size":ace.get("ace_size"),"access_mask":ace.get("access_mask"),"trustee_sid_raw_hex":ace.get("trustee_sid_raw_hex"),"recognized":ace.get("recognized")})).collect::<Vec<_>>())})
}
fn evidence(row: &Value, index: usize, kind: Kind) -> PermissionEvidenceRef {
    let identity = identity(row, kind).unwrap_or("").to_owned();
    let fields = match kind {
        Kind::Linux => vec![
            serde_json::json!({"field":"path","encoding":"unix_bytes_hex","value":identity}),
            linux_evidence_ref("access_acl", row.get("access_acl")),
            linux_evidence_ref("default_acl", row.get("default_acl")),
            linux_evidence_ref("file_capability", row.get("file_capability")),
        ],
        Kind::Windows => vec![
            serde_json::json!({"field":"path","encoding":"utf16le_bytes_hex","value":identity}),
            serde_json::json!({"field":"security_descriptor","sha256":row.pointer("/security/descriptor_sha256")}),
        ],
    };
    PermissionEvidenceRef {
        row_index: index,
        path_encoding: if kind == Kind::Linux {
            "unix_bytes_hex"
        } else {
            "utf16le_bytes_hex"
        },
        path_identity_hex: identity,
        field_references: fields,
    }
}
fn linux_evidence_ref(field: &str, v: Option<&Value>) -> Value {
    serde_json::json!({"field":field,"status":v.and_then(|x|x.get("status")),"sha256":v.and_then(|x|x.get("sha256")),"source":v.and_then(|x|x.get("source")),"byte_length":v.and_then(|x|x.get("byte_length"))})
}
fn side(row: &Value, index: usize, kind: Kind) -> PermissionSide {
    PermissionSide {
        row_index: index,
        facts: facts(row, kind),
        evidence: evidence(row, index, kind),
    }
}

fn compare(left: &Value, right: &Value, kind: Kind) -> Result<PermissionDiff, PermissionDiffError> {
    let l = arr(left, "objects")?;
    let r = arr(right, "objects")?;
    let mut lm = BTreeMap::<String, Vec<(usize, &Value)>>::new();
    let mut rm = BTreeMap::<String, Vec<(usize, &Value)>>::new();
    for (map, rows) in [(&mut lm, l), (&mut rm, r)] {
        for (i, row) in rows.iter().enumerate() {
            map.entry(identity(row, kind)?.to_owned())
                .or_default()
                .push((i, row));
        }
    }
    let duplicates: BTreeSet<String> = lm
        .iter()
        .chain(rm.iter())
        .filter_map(|(p, v)| (v.len() > 1).then_some(p.clone()))
        .collect();
    let keys: BTreeSet<String> = lm.keys().chain(rm.keys()).cloned().collect();
    let full = source_full(left, kind) && source_full(right, kind);
    let mut diagnostics = BTreeSet::new();
    let mut counts = PermissionDiffCounts::default();
    let mut deltas = Vec::new();
    if !full {
        diagnostics.insert("source_incomplete");
    }
    counts.ambiguous_path_groups = duplicates.len();
    if !duplicates.is_empty() {
        diagnostics.insert("ambiguous_path_identity");
    }
    for path in keys {
        if duplicates.contains(&path) {
            counts.unknown_paths += 1;
            continue;
        }
        let a = lm.get(&path).and_then(|x| (x.len() == 1).then_some(x[0]));
        let b = rm.get(&path).and_then(|x| (x.len() == 1).then_some(x[0]));
        match (a, b) {
            (Some((ai, av)), Some((bi, bv))) => {
                if !definite_row(av, kind) || !definite_row(bv, kind) {
                    counts.unknown_paths += 1;
                    diagnostics.insert("path_state_unknown");
                    deltas.push(PermissionDelta {
                        kind: "unknown",
                        path_identity_hex: path,
                        changed_fields: Vec::new(),
                        unknown_fields: vec!["object_state"],
                        before: Some(side(av, ai, kind)),
                        after: Some(side(bv, bi, kind)),
                    });
                    continue;
                }
                let (caf, cbf) = comparable_facts(av, bv, kind);
                if caf != cbf {
                    if deltas.len() >= MAX_OUTPUT_DELTAS {
                        return Err(PermissionDiffError::LimitExceeded);
                    }
                    let changed = caf
                        .as_object()
                        .into_iter()
                        .flat_map(|m| m.keys())
                        .chain(cbf.as_object().into_iter().flat_map(|m| m.keys()))
                        .filter_map(|k| (caf.get(k) != cbf.get(k)).then_some(k.as_str()))
                        .map(field_name)
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    let unknown = if kind == Kind::Linux {
                        linux_unknown_fields(av, bv)
                    } else {
                        Vec::new()
                    };
                    if !unknown.is_empty() {
                        diagnostics.insert("permission_facts_unknown");
                    }
                    deltas.push(PermissionDelta {
                        kind: "changed",
                        path_identity_hex: path,
                        changed_fields: changed,
                        unknown_fields: unknown,
                        before: Some(side(av, ai, kind)),
                        after: Some(side(bv, bi, kind)),
                    });
                    counts.changes += 1;
                } else if kind == Kind::Linux && !linux_unknown_fields(av, bv).is_empty() {
                    counts.unknown_paths += 1;
                    diagnostics.insert("permission_facts_unknown");
                    deltas.push(PermissionDelta {
                        kind: "unknown",
                        path_identity_hex: path,
                        changed_fields: Vec::new(),
                        unknown_fields: linux_unknown_fields(av, bv),
                        before: Some(side(av, ai, kind)),
                        after: Some(side(bv, bi, kind)),
                    });
                }
            }
            (Some((i, row)), None) | (None, Some((i, row))) => {
                if !full || !definite_row(row, kind) {
                    counts.unmatched_rows_suppressed_for_partial_source += 1;
                    counts.unknown_paths += 1;
                    diagnostics.insert("unmatched_rows_suppressed");
                    continue;
                }
                if deltas.len() >= MAX_OUTPUT_DELTAS {
                    return Err(PermissionDiffError::LimitExceeded);
                }
                let added = a.is_none();
                let item = side(row, i, kind);
                deltas.push(PermissionDelta {
                    kind: if added { "added" } else { "removed" },
                    path_identity_hex: path,
                    changed_fields: Vec::new(),
                    unknown_fields: Vec::new(),
                    before: if added { None } else { Some(item.clone()) },
                    after: if added { Some(item) } else { None },
                });
                if added {
                    counts.additions += 1
                } else {
                    counts.removals += 1
                }
            }
            _ => {}
        }
    }
    let status = if full && diagnostics.is_empty() {
        PermissionDiffStatus::Complete
    } else {
        PermissionDiffStatus::Partial
    };
    Ok(PermissionDiff {
        schema: "sideeffect.permission_inventory_diff",
        schema_version: 1,
        platform: if kind == Kind::Linux {
            "linux"
        } else {
            "windows"
        },
        before_captured_at_unix_ms: left
            .get(if kind == Kind::Linux {
                "captured_at_unix_ms"
            } else {
                "capture_ended_at_unix_ms"
            })
            .and_then(Value::as_u64)
            .unwrap_or(0) as u128,
        after_captured_at_unix_ms: right
            .get(if kind == Kind::Linux {
                "captured_at_unix_ms"
            } else {
                "capture_ended_at_unix_ms"
            })
            .and_then(Value::as_u64)
            .unwrap_or(0) as u128,
        status,
        coverage_note: "A comparison of explicitly selected paths and bounded permission facts. It does not calculate effective access, cover unselected paths, establish object persistence from inode/file index values, or establish safety.",
        counts,
        diagnostics: diagnostics.into_iter().collect(),
        deltas,
    })
}
fn comparable_facts(a: &Value, b: &Value, kind: Kind) -> (Value, Value) {
    let mut left = facts(a, kind);
    let mut right = facts(b, kind);
    if kind == Kind::Linux {
        for (key, _) in [
            ("access_acl", "access_acl"),
            ("default_acl", "default_acl"),
            ("file_capability", "file_capability"),
        ] {
            let known = |row: &Value| {
                row.get(key)
                    .and_then(|v| v.get("status"))
                    .and_then(Value::as_str)
                    .is_some_and(|s| match key {
                        "default_acl" => matches!(s, "present" | "absent" | "not_applicable"),
                        _ => matches!(s, "present" | "absent"),
                    })
            };
            if !known(a) || !known(b) {
                left.as_object_mut()
                    .unwrap()
                    .insert(key.into(), Value::Null);
                right
                    .as_object_mut()
                    .unwrap()
                    .insert(key.into(), Value::Null);
            }
        }
    }
    (left, right)
}
fn field_name(k: &str) -> &'static str {
    match k {
        "status" => "status",
        "object_type" => "object_type",
        "uid" => "uid",
        "gid" => "gid",
        "mode" => "mode",
        "device" => "device",
        "inode" => "inode",
        "access_acl" => "access_acl",
        "default_acl" => "default_acl",
        "file_capability" => "file_capability",
        "metadata" => "metadata",
        "security" => "security",
        _ => "selected_fact",
    }
}
fn linux_unknown_fields(a: &Value, b: &Value) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (key, name) in [
        ("access_acl", "access_acl"),
        ("default_acl", "default_acl"),
        ("file_capability", "file_capability"),
    ] {
        let is_known = |row: &Value| {
            row.get(key)
                .and_then(|x| x.get("status"))
                .and_then(Value::as_str)
                .is_some_and(|s| match key {
                    "default_acl" => matches!(s, "present" | "absent" | "not_applicable"),
                    _ => matches!(s, "present" | "absent"),
                })
        };
        if !is_known(a) || !is_known(b) {
            out.push(name);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux_row(path: &str, mode: u64) -> Value {
        serde_json::json!({
            "path": "/tmp/fixture", "path_bytes_hex": path, "status": "complete",
            "object_type": "regular_file", "uid": 1000, "gid": 1000, "mode": mode,
            "device": 1, "inode": 2,
            "access_acl": {"status":"absent","source":"fgetxattr/system.posix_acl_access"},
            "default_acl": {"status":"not_applicable","source":"fgetxattr/system.posix_acl_default"},
            "file_capability": {"status":"absent","source":"fgetxattr/security.capability"},
            "diagnostics": []
        })
    }
    fn linux(status: &str, rows: Vec<Value>) -> Value {
        serde_json::json!({"schema":LINUX,"schema_version":1,"platform":"linux","scope":"explicit_paths_metadata_posix_acl_file_capability","captured_at_unix_ms":100,"status":status,"paths_requested":rows.len(),"acl_bytes_read":0,"capability_bytes_read":0,"objects":rows,"diagnostics":[]})
    }
    fn windows_row(path: &str, size: u64) -> Value {
        let mut raw = vec![0_u8; 20];
        raw[0] = 1;
        raw[3] = 0x80;
        let hash = crate::fingerprint::sha256_hex(&raw);
        serde_json::json!({
            "path":"C:\\fixture.txt", "path_utf16_hex":path, "status":"complete",
            "metadata":{"attributes":32,"is_directory":false,"is_reparse_point":false,"volume_serial_number":1,"file_index":2,"size_bytes":size,"last_write_filetime":10},
            "security":{"descriptor_length":20,"descriptor_sha256":hash,"descriptor_raw_hex":hex(&raw),"control":32768,"owner_sid_raw_hex":null,"group_sid_raw_hex":null,"dacl_state":"absent","dacl_protected":false,"dacl_auto_inherited":false,"aces":[],"parse_diagnostic":null},
            "diagnostic":null
        })
    }
    fn windows_empty_acl_row(path: &str) -> Value {
        let mut raw = vec![0_u8; 28];
        raw[0] = 1;
        raw[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
        raw[16..20].copy_from_slice(&20_u32.to_le_bytes());
        raw[20] = 2;
        raw[22..24].copy_from_slice(&8_u16.to_le_bytes());
        let hash = crate::fingerprint::sha256_hex(&raw);
        serde_json::json!({
            "path":"C:\\empty-acl.txt", "path_utf16_hex":path, "status":"complete",
            "metadata":{"attributes":32,"is_directory":false,"is_reparse_point":false,"volume_serial_number":1,"file_index":2,"size_bytes":10,"last_write_filetime":10},
            "security":{"descriptor_length":28,"descriptor_sha256":hash,"descriptor_raw_hex":hex(&raw),"control":32772,"owner_sid_raw_hex":null,"group_sid_raw_hex":null,"dacl_state":"empty","dacl_protected":false,"dacl_auto_inherited":false,"aces":[],"parse_diagnostic":null},
            "diagnostic":null
        })
    }
    fn windows_malformed_row(path: &str) -> Value {
        let mut raw = vec![0_u8; 20];
        raw[0] = 2;
        raw[2..4].copy_from_slice(&0x8000_u16.to_le_bytes());
        let hash = crate::fingerprint::sha256_hex(&raw);
        serde_json::json!({
            "path":"C:\\malformed.txt", "path_utf16_hex":path, "status":"partial",
            "metadata":{"attributes":32,"is_directory":false,"is_reparse_point":false,"volume_serial_number":1,"file_index":2,"size_bytes":10,"last_write_filetime":10},
            "security":{"descriptor_length":20,"descriptor_sha256":hash,"descriptor_raw_hex":hex(&raw),"control":32768,"owner_sid_raw_hex":null,"group_sid_raw_hex":null,"dacl_state":"malformed_or_unsupported","dacl_protected":false,"dacl_auto_inherited":false,"aces":[],"parse_diagnostic":"malformed_descriptor_header"},
            "diagnostic":{"code":"malformed_descriptor_header","path_index":0,"source":null,"message":"Raw security descriptor evidence is retained; one or more descriptor or ACE fields could not be safely decoded.","win32_error":null}
        })
    }
    fn windows(status: &str, rows: Vec<Value>) -> Value {
        serde_json::json!({"schema":WINDOWS,"schema_version":1,"platform":"windows","scope":"explicit_paths_only; final_reparse_points_opened_without_following; no_sacl; no_effective_access_calculation","capture_started_at_unix_ms":100,"capture_ended_at_unix_ms":101,"status":status,"objects":rows,"diagnostics":[],"limits":{"max_paths":256,"max_utf16_units_per_path":32767,"max_total_path_utf16_units":1048576,"max_descriptor_bytes":65536,"max_aces_per_descriptor":1024,"max_aggregate_descriptor_bytes":8388608,"deadline_ms_between_paths":5000}})
    }

    #[test]
    fn compares_exact_paths_and_retains_both_sides_without_raw_xattr_bytes() {
        let before = linux(
            "complete",
            vec![linux_row("2f746d702f66697874757265", 0o640)],
        );
        let after = linux(
            "complete",
            vec![linux_row("2f746d702f66697874757265", 0o600)],
        );
        let result = compare_permission_fixture(&before, &after);
        assert_eq!(result.status, PermissionDiffStatus::Complete);
        assert_eq!(result.counts.changes, 1);
        assert_eq!(result.deltas[0].changed_fields, vec!["mode"]);
        assert_eq!(
            result.deltas[0].before.as_ref().unwrap().evidence.row_index,
            0
        );
        assert_eq!(
            result.deltas[0]
                .after
                .as_ref()
                .unwrap()
                .evidence
                .path_identity_hex,
            "2f746d702f66697874757265"
        );
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("\"bytes_hex\""));
    }

    fn compare_permission_fixture(a: &Value, b: &Value) -> PermissionDiff {
        compare_permission_inventory_json(a.to_string().as_bytes(), b.to_string().as_bytes())
            .unwrap()
    }

    #[test]
    fn suppresses_unmatched_rows_for_partial_sources_and_duplicate_paths() {
        let before = linux("partial", vec![]);
        let after = linux("complete", vec![linux_row("2f746d70", 0o600)]);
        let partial = compare_permission_fixture(&before, &after);
        assert_eq!(partial.counts.additions, 0);
        assert_eq!(
            partial.counts.unmatched_rows_suppressed_for_partial_source,
            1
        );
        assert_eq!(partial.status, PermissionDiffStatus::Partial);

        let duplicate = linux(
            "complete",
            vec![linux_row("2f746d70", 0o600), linux_row("2f746d70", 0o644)],
        );
        let ambiguous = compare_permission_fixture(&duplicate, &duplicate);
        assert_eq!(ambiguous.counts.ambiguous_path_groups, 1);
        assert_eq!(
            ambiguous.counts.additions + ambiguous.counts.removals + ambiguous.counts.changes,
            0
        );
        assert_eq!(ambiguous.status, PermissionDiffStatus::Partial);
    }

    #[test]
    fn malformed_unknown_cross_platform_oversized_and_deep_inputs_are_rejected() {
        let valid = linux("complete", vec![]).to_string();
        let mut unknown = linux("complete", vec![]);
        unknown["unexpected"] = Value::Bool(true);
        assert!(matches!(
            compare_permission_inventory_json(unknown.to_string().as_bytes(), valid.as_bytes()),
            Err(PermissionDiffError::MalformedInput)
        ));
        assert!(matches!(compare_permission_inventory_json(br#"{"schema":"sideeffect.permission_inventory","schema": "sideeffect.windows_permission_inventory"}"#, valid.as_bytes()), Err(PermissionDiffError::MalformedInput)));
        let deep = format!(
            "{}null{}",
            "[".repeat(MAX_DEPTH + 1),
            "]".repeat(MAX_DEPTH + 1)
        );
        assert!(matches!(
            compare_permission_inventory_json(deep.as_bytes(), valid.as_bytes()),
            Err(PermissionDiffError::MalformedInput)
        ));
        assert!(matches!(
            compare_permission_inventory_json(&vec![b' '; MAX_INPUT + 1], valid.as_bytes()),
            Err(PermissionDiffError::InputTooLarge)
        ));
        let win = windows("complete", vec![]);
        assert!(matches!(
            compare_permission_inventory_json(valid.as_bytes(), win.to_string().as_bytes()),
            Err(PermissionDiffError::SchemaMismatch)
        ));

        let mut diagnosed_row = linux_row("2f746d70", 0o600);
        diagnosed_row["diagnostics"] = serde_json::json!([{
            "code":"acl_read_failed","path_index":0,"source":"system.posix_acl_access","message":"ACL xattr could not be read."
        }]);
        let partial_source = linux("partial", vec![diagnosed_row]);
        assert!(matches!(
            compare_permission_inventory_json(
                partial_source.to_string().as_bytes(),
                valid.as_bytes()
            ),
            Err(PermissionDiffError::MalformedInput)
        ));
    }

    #[test]
    fn compares_windows_metadata_and_acl_facts_but_never_raw_descriptor_bytes() {
        let before = windows(
            "complete",
            vec![windows_row(
                "43003a005c0066006900780074007500720065002e00740078007400",
                10,
            )],
        );
        let after = windows(
            "complete",
            vec![windows_row(
                "43003a005c0066006900780074007500720065002e00740078007400",
                11,
            )],
        );
        let result = compare_permission_fixture(&before, &after);
        assert_eq!(result.counts.changes, 1);
        assert_eq!(result.deltas[0].changed_fields, vec!["metadata"]);
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("\"descriptor_raw_hex\""));
        assert!(!encoded.contains("\"raw_hex\""));
        assert!(encoded.contains("descriptor_sha256"));
    }

    #[test]
    fn decoded_evidence_must_match_linux_raw_xattrs_and_windows_raw_descriptor() {
        let acl = [
            2_u32.to_le_bytes().as_slice(),
            &[1, 0, 7, 0, 255, 255, 255, 255],
            &[4, 0, 5, 0, 255, 255, 255, 255],
            &[32, 0, 0, 0, 255, 255, 255, 255],
        ]
        .concat();
        let decoded = decode_acl_entries(&acl).unwrap();
        assert_eq!(decoded.as_array().unwrap().len(), 3);
        let mut wrong = linux_row("2f746d70", 0o600);
        wrong["access_acl"] = serde_json::json!({"status":"present","source":"fgetxattr/system.posix_acl_access","byte_length":acl.len(),"bytes_hex":hex(&acl),"sha256":crate::fingerprint::sha256_hex(&acl),"entries":[{"tag":"user_object","permissions":0},{"tag":"group_object","permissions":5},{"tag":"other","permissions":0}]});
        assert_eq!(
            validate_acl(&wrong["access_acl"], false),
            Err(PermissionDiffError::MalformedInput)
        );

        let mut before = windows("complete", vec![windows_row("4300", 10)]);
        let after = windows("complete", vec![windows_row("4300", 11)]);
        before["objects"][0]["security"]["control"] = Value::from(0);
        assert!(matches!(
            compare_permission_inventory_json(
                before.to_string().as_bytes(),
                after.to_string().as_bytes()
            ),
            Err(PermissionDiffError::MalformedInput)
        ));
    }

    #[test]
    fn accepts_empty_dacl_and_keeps_malformed_descriptor_facts_unknown() {
        let path = "43003a005c0065006d007000740079002e00740078007400";
        let empty = windows("complete", vec![windows_empty_acl_row(path)]);
        let result = compare_permission_fixture(&empty, &empty);
        assert_eq!(result.status, PermissionDiffStatus::Complete);
        assert!(result.deltas.is_empty());

        let path = "43003a005c006d0061006c0066006f0072006d00650064002e00740078007400";
        let malformed = windows("partial", vec![windows_malformed_row(path)]);
        let result = compare_permission_inventory_json(
            malformed.to_string().as_bytes(),
            malformed.to_string().as_bytes(),
        )
        .unwrap();
        assert_eq!(result.status, PermissionDiffStatus::Partial);
        assert_eq!(result.counts.unknown_paths, 1);
        assert_eq!(result.deltas[0].kind, "unknown");
        assert_eq!(
            result.deltas[0]
                .before
                .as_ref()
                .unwrap()
                .facts
                .pointer("/security/status"),
            Some(&Value::String("unknown".into()))
        );
        assert!(
            result.deltas[0]
                .before
                .as_ref()
                .unwrap()
                .facts
                .pointer("/security/control")
                .is_none()
        );

        let mut contradictory_complete = malformed.clone();
        contradictory_complete["objects"][0]["status"] = Value::String("complete".into());
        assert!(matches!(
            compare_permission_inventory_json(
                contradictory_complete.to_string().as_bytes(),
                malformed.to_string().as_bytes()
            ),
            Err(PermissionDiffError::MalformedInput)
        ));

        let mut mismatched_row_diagnostic = malformed.clone();
        mismatched_row_diagnostic["objects"][0]["diagnostic"]["code"] =
            Value::String("different_code".into());
        assert!(matches!(
            compare_permission_inventory_json(
                mismatched_row_diagnostic.to_string().as_bytes(),
                malformed.to_string().as_bytes()
            ),
            Err(PermissionDiffError::MalformedInput)
        ));
    }
}
