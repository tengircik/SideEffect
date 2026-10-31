//! Bounded, deterministic comparison of native startup inventory snapshots.
//!
//! Configuration values are compared in memory but never copied to this output.

use serde::Serialize;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MAX_INPUT: usize = 64 * 1024 * 1024;
const MAX_ROWS: usize = 32_768;
const MAX_DELTAS: usize = 16_384;
const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 1_000_000;
const MAX_COLLECTION: usize = 65_536;
const MAX_STRING: usize = 128 * 1024;
const LINUX: &str = "sideeffect.startup_inventory";
const WINDOWS: &str = "sideeffect.windows_startup_inventory";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupDiffStatus {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Serialize)]
pub struct StartupInventoryDiff {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub before_captured_at_unix_ms: u128,
    pub after_captured_at_unix_ms: u128,
    pub status: StartupDiffStatus,
    pub coverage_note: &'static str,
    pub counts: StartupDiffCounts,
    pub diagnostics: Vec<&'static str>,
    pub deltas: Vec<StartupDelta>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct StartupDiffCounts {
    pub observed_before_only: usize,
    pub observed_after_only: usize,
    pub changed: usize,
    pub unmatched_rows_suppressed_for_incomplete_source: usize,
    pub ambiguous_identities: usize,
    pub lossy_xdg_paths: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct StartupDelta {
    pub kind: &'static str,
    pub category: &'static str,
    /// SHA-256 of the platform-local identity bytes; raw configuration values are omitted.
    pub identity_sha256: String,
    pub changed_fields: Vec<&'static str>,
    pub before: Option<StartupEvidenceSide>,
    pub after: Option<StartupEvidenceSide>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StartupEvidenceSide {
    pub references: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupDiffError {
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

pub fn is_startup_inventory_json(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_INPUT
        && parse(bytes)
            .ok()
            .and_then(|v| v.get("schema").and_then(Value::as_str).map(str::to_owned))
            .is_some_and(|s| s == LINUX || s == WINDOWS)
}

pub fn compare_startup_inventory_json(
    before: &[u8],
    after: &[u8],
) -> Result<StartupInventoryDiff, StartupDiffError> {
    if before.len().saturating_add(after.len()) > MAX_INPUT {
        return Err(StartupDiffError::InputTooLarge);
    }
    let left = parse(before)?;
    let right = parse(after)?;
    let lk = kind(&left)?;
    let rk = kind(&right)?;
    if lk != rk {
        return Err(StartupDiffError::SchemaMismatch);
    }
    validate(&left, lk)?;
    validate(&right, rk)?;
    compare(&left, &right, lk)
}

struct Budget {
    nodes: usize,
}
struct Seed<'a> {
    budget: &'a mut Budget,
    depth: usize,
}
struct KeySeed;
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        if self.depth > MAX_DEPTH {
            return Err(serde::de::Error::custom("nesting limit"));
        }
        self.budget.nodes += 1;
        if self.budget.nodes > MAX_NODES {
            return Err(serde::de::Error::custom("node limit"));
        }
        d.deserialize_any(ValueVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}
struct ValueVisitor<'a> {
    budget: &'a mut Budget,
    depth: usize,
}
impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON")
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
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        if v.len() > MAX_STRING {
            return Err(E::custom("string limit"));
        }
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        if v.len() > MAX_STRING {
            return Err(E::custom("string limit"));
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
        Seed {
            budget: self.budget,
            depth: self.depth + 1,
        }
        .deserialize(d)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut v = Vec::new();
        while v.len() < MAX_COLLECTION {
            match a.next_element_seed(Seed {
                budget: self.budget,
                depth: self.depth + 1,
            })? {
                Some(x) => v.push(x),
                None => return Ok(Value::Array(v)),
            }
        }
        if a.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom("array limit"));
        }
        Ok(Value::Array(v))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut v = Map::new();
        while let Some(k) = a.next_key_seed(KeySeed)? {
            if v.len() >= MAX_COLLECTION || v.contains_key(&k) {
                return Err(serde::de::Error::custom("object limit or duplicate key"));
            }
            let x = a.next_value_seed(Seed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            v.insert(k, x);
        }
        Ok(Value::Object(v))
    }
}
impl<'de> DeserializeSeed<'de> for KeySeed {
    type Value = String;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<String, D::Error> {
        d.deserialize_string(KeyVisitor)
    }
}
struct KeyVisitor;
impl<'de> Visitor<'de> for KeyVisitor {
    type Value = String;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded object key")
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<String, E> {
        if v.len() > 256 {
            return Err(E::custom("key limit"));
        }
        Ok(v.to_owned())
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<String, E> {
        if v.len() > 256 {
            return Err(E::custom("key limit"));
        }
        Ok(v)
    }
}
fn parse(b: &[u8]) -> Result<Value, StartupDiffError> {
    if b.len() > MAX_INPUT {
        return Err(StartupDiffError::InputTooLarge);
    }
    let mut d = serde_json::Deserializer::from_slice(b);
    let v = Seed {
        budget: &mut Budget { nodes: 0 },
        depth: 0,
    }
    .deserialize(&mut d)
    .map_err(|_| StartupDiffError::MalformedInput)?;
    d.end().map_err(|_| StartupDiffError::MalformedInput)?;
    Ok(v)
}
fn kind(v: &Value) -> Result<Kind, StartupDiffError> {
    match v.get("schema").and_then(Value::as_str) {
        Some(LINUX) => Ok(Kind::Linux),
        Some(WINDOWS) => Ok(Kind::Windows),
        _ => Err(StartupDiffError::UnsupportedSchema),
    }
}
fn obj(v: &Value) -> Result<&Map<String, Value>, StartupDiffError> {
    v.as_object().ok_or(StartupDiffError::MalformedInput)
}
fn keys(v: &Value, allowed: &[&str]) -> Result<(), StartupDiffError> {
    if obj(v)?.keys().any(|k| !allowed.contains(&k.as_str())) {
        Err(StartupDiffError::MalformedInput)
    } else {
        Ok(())
    }
}
fn arr<'a>(v: &'a Value, k: &str) -> Result<&'a [Value], StartupDiffError> {
    v.get(k)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(StartupDiffError::MalformedInput)
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, StartupDiffError> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or(StartupDiffError::MalformedInput)
}
fn num(v: &Value, k: &str) -> Result<u64, StartupDiffError> {
    v.get(k)
        .and_then(Value::as_u64)
        .ok_or(StartupDiffError::MalformedInput)
}
fn check_str(v: &Value, k: &str, max: usize) -> Result<(), StartupDiffError> {
    if let Some(x) = v.get(k) {
        if !x.is_null() && (!x.is_string() || x.as_str().unwrap().len() > max) {
            return Err(StartupDiffError::LimitExceeded);
        }
    }
    Ok(())
}
fn optional_counter(v: &Value, key: &str) -> Result<(), StartupDiffError> {
    if v.get(key)
        .is_some_and(|x| !x.is_null() && x.as_u64().is_none())
    {
        return Err(StartupDiffError::MalformedInput);
    }
    Ok(())
}
fn validate_path_diagnostics(items: &[Value], with_raw_path: bool) -> Result<(), StartupDiffError> {
    if items.len() > 256 {
        return Err(StartupDiffError::LimitExceeded);
    }
    for d in items {
        let fields = if with_raw_path {
            &["code", "path", "path_bytes_hex", "line", "byte_offset"][..]
        } else {
            &["code", "path", "line", "byte_offset"][..]
        };
        keys(d, fields)?;
        check_str(d, "code", 256)?;
        check_str(d, "path", 32768)?;
        if with_raw_path {
            check_str(d, "path_bytes_hex", 32768)?;
        }
        optional_counter(d, "line")?;
        optional_counter(d, "byte_offset")?;
    }
    Ok(())
}
fn validate(v: &Value, k: Kind) -> Result<(), StartupDiffError> {
    let (schema, platform, scope, version) = match k {
        Kind::Linux => (LINUX, "linux", "curated_xdg_systemd_sysv_cron_sources", 2),
        Kind::Windows => (
            WINDOWS,
            "windows",
            "current_user_and_accessible_machine_run_keys_startup_folders_services_and_current_token_visible_tasks",
            4,
        ),
    };
    if text(v, "schema")? != schema || num(v, "schema_version")? != version {
        return Err(StartupDiffError::UnsupportedSchema);
    }
    if text(v, "platform")? != platform {
        return Err(StartupDiffError::PlatformMismatch);
    }
    if text(v, "scope")? != scope {
        return Err(StartupDiffError::MalformedInput);
    }
    let top = &[
        "schema",
        "schema_version",
        "platform",
        "scope",
        "capture_started_at_unix_ms",
        "capture_ended_at_unix_ms",
        "status",
    ];
    let top = if k == Kind::Linux {
        [
            &top[..],
            &["xdg_autostart", "systemd_units", "legacy_sources"][..],
        ]
        .concat()
    } else {
        [
            &top[..],
            &[
                "sources",
                "registry_entries",
                "folder_entries",
                "service_entries",
                "scheduled_task_entries",
                "scheduled_task_actions",
            ][..],
        ]
        .concat()
    };
    keys(v, &top)?;
    validate_known_fields(v)?;
    let start = num(v, "capture_started_at_unix_ms")?;
    let end = num(v, "capture_ended_at_unix_ms")?;
    if start > end {
        return Err(StartupDiffError::MalformedInput);
    }
    let status = text(v, "status")?;
    if if k == Kind::Linux {
        !matches!(status, "complete" | "partial")
    } else {
        !win_status(status)
    } {
        return Err(StartupDiffError::MalformedInput);
    }
    if k == Kind::Linux {
        validate_linux(v)?
    } else {
        validate_windows(v)?
    }
    Ok(())
}
fn validate_known_fields(v: &Value) -> Result<(), StartupDiffError> {
    const ALLOWED: &[&str] = &[
        "schema",
        "schema_version",
        "platform",
        "scope",
        "capture_started_at_unix_ms",
        "capture_ended_at_unix_ms",
        "status",
        "xdg_autostart",
        "systemd_units",
        "legacy_sources",
        "sources",
        "registry_entries",
        "folder_entries",
        "service_entries",
        "scheduled_task_entries",
        "scheduled_task_actions",
        "directories",
        "entries",
        "records",
        "diagnostics",
        "path",
        "path_bytes_hex",
        "path_utf16_hex",
        "scope",
        "files_seen",
        "entries_seen",
        "state",
        "kind",
        "entry_kind",
        "source_kind",
        "source_path",
        "source_path_bytes_hex",
        "record_type",
        "symlink_target",
        "symlink_target_hex",
        "symlink_target_sha256",
        "sha256",
        "directives",
        "section",
        "key",
        "value",
        "value_hex",
        "line",
        "line_number",
        "byte_offset",
        "byte_length",
        "line_sha256",
        "raw_line",
        "raw_line_hex",
        "lines",
        "applicability",
        "keys",
        "code",
        "message",
        "item_index",
        "win32_error",
        "hresult",
        "id",
        "registry_hive",
        "registry_key",
        "registry_view",
        "location_path",
        "location_path_utf16_hex",
        "hive",
        "trigger",
        "value_name",
        "value_type",
        "command",
        "command_utf16_hex",
        "evidence",
        "value_index",
        "registry_type",
        "folder_scope",
        "display_path",
        "service_name",
        "display_name",
        "start_type",
        "start_type_code",
        "account",
        "binary_path",
        "service_index",
        "task_path",
        "task_enabled",
        "trigger_type",
        "trigger_enabled",
        "logon_user",
        "task_index",
        "trigger_index",
        "action_index",
        "action_type",
        "action_type_code",
        "executable_path",
        "arguments",
        "working_directory",
        "source",
        "diagnostics",
        "field",
        "pid",
        "process_id",
        "line_number",
        "path",
        "registry_type",
        "not_checked",
    ];
    match v {
        Value::Object(map) => {
            if map.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
                return Err(StartupDiffError::MalformedInput);
            }
            for child in map.values() {
                validate_known_fields(child)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                validate_known_fields(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn win_status(s: &str) -> bool {
    matches!(
        s,
        "complete"
            | "partial"
            | "not_present"
            | "inaccessible"
            | "unavailable"
            | "unsupported"
            | "not_checked"
            | "error"
    )
}
fn validate_header(
    v: &Value,
    schema: &str,
    version: u64,
    platform: &str,
    scope: &str,
    statuses: &[&str],
    extra: &[&str],
) -> Result<(), StartupDiffError> {
    let allowed = [
        "schema",
        "schema_version",
        "platform",
        "scope",
        "capture_started_at_unix_ms",
        "capture_ended_at_unix_ms",
        "status",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .collect::<Vec<_>>();
    keys(v, &allowed)?;
    if text(v, "schema")? != schema
        || num(v, "schema_version")? != version
        || text(v, "platform")? != platform
        || text(v, "scope")? != scope
        || num(v, "capture_started_at_unix_ms")? > num(v, "capture_ended_at_unix_ms")?
        || !statuses.contains(&text(v, "status")?)
    {
        return Err(StartupDiffError::MalformedInput);
    }
    Ok(())
}
fn validate_linux(v: &Value) -> Result<(), StartupDiffError> {
    let x = v
        .get("xdg_autostart")
        .ok_or(StartupDiffError::MalformedInput)?;
    validate_header(
        x,
        "sideeffect.xdg_autostart_inventory",
        1,
        "linux",
        "xdg_autostart_files_only",
        &["complete", "partial"],
        &["directories", "entries"],
    )?;
    for d in arr(x, "directories")? {
        keys(d, &["scope", "path", "status", "files_seen", "diagnostics"])?;
        for f in ["scope", "path"] {
            check_str(d, f, 32768)?;
        }
        if !matches!(text(d, "status")?, "complete" | "partial") {
            return Err(StartupDiffError::MalformedInput);
        }
        validate_path_diagnostics(arr(d, "diagnostics")?, false)?;
    }
    if arr(x, "entries")?.len() > MAX_ROWS {
        return Err(StartupDiffError::LimitExceeded);
    }
    for e in arr(x, "entries")? {
        keys(e, &["scope", "source_path", "applicability", "keys"])?;
        for f in ["scope", "source_path", "applicability"] {
            check_str(e, f, 32768)?;
        }
        for key in arr(e, "keys")? {
            keys(
                key,
                &[
                    "key",
                    "value",
                    "value_hex",
                    "line",
                    "byte_offset",
                    "byte_length",
                    "line_sha256",
                ],
            )?;
            for f in ["key", "value", "value_hex", "line_sha256"] {
                check_str(key, f, 65536)?;
            }
            if key.get("line").and_then(Value::as_u64).is_none()
                || key.get("byte_offset").and_then(Value::as_u64).is_none()
                || key.get("byte_length").and_then(Value::as_u64).is_none()
            {
                return Err(StartupDiffError::MalformedInput);
            }
        }
    }
    let u = v
        .get("systemd_units")
        .ok_or(StartupDiffError::MalformedInput)?;
    validate_header(
        u,
        "sideeffect.systemd_unit_inventory",
        1,
        "linux",
        "systemd_unit_files_and_enablement_symlink_references",
        &["complete", "partial"],
        &["directories", "records"],
    )?;
    for d in arr(u, "directories")? {
        keys(
            d,
            &[
                "scope",
                "path",
                "path_bytes_hex",
                "status",
                "entries_seen",
                "diagnostics",
            ],
        )?;
        for f in ["scope", "path", "path_bytes_hex"] {
            check_str(d, f, 32768)?;
        }
        if !matches!(text(d, "status")?, "complete" | "partial") {
            return Err(StartupDiffError::MalformedInput);
        }
        validate_path_diagnostics(arr(d, "diagnostics")?, true)?;
    }
    if arr(u, "records")?.len() > MAX_ROWS {
        return Err(StartupDiffError::LimitExceeded);
    }
    for r in arr(u, "records")? {
        keys(
            r,
            &[
                "scope",
                "source_path",
                "source_path_bytes_hex",
                "record_type",
                "symlink_target",
                "directives",
            ],
        )?;
        for f in [
            "scope",
            "source_path",
            "source_path_bytes_hex",
            "record_type",
        ] {
            check_str(r, f, 32768)?;
        }
        if let Some(t) = r.get("symlink_target").filter(|x| !x.is_null()) {
            keys(t, &["value", "value_hex", "byte_length", "sha256"])?;
            for f in ["value", "value_hex", "sha256"] {
                check_str(t, f, 65536)?;
            }
        }
        for d in arr(r, "directives")? {
            keys(
                d,
                &[
                    "section",
                    "key",
                    "value",
                    "value_hex",
                    "line",
                    "byte_offset",
                    "byte_length",
                    "line_sha256",
                ],
            )?;
            for f in ["section", "key", "value", "value_hex", "line_sha256"] {
                check_str(d, f, 65536)?;
            }
        }
    }
    let l = v
        .get("legacy_sources")
        .ok_or(StartupDiffError::MalformedInput)?;
    validate_header(
        l,
        "sideeffect.legacy_startup_inventory",
        1,
        "linux",
        "common_sysv_cron_paths_only",
        &["complete", "partial"],
        &["sources", "entries"],
    )?;
    for s in arr(l, "sources")? {
        keys(
            s,
            &[
                "kind",
                "path",
                "path_bytes_hex",
                "state",
                "files_seen",
                "diagnostics",
            ],
        )?;
        for f in ["kind", "path", "path_bytes_hex"] {
            check_str(s, f, 32768)?;
        }
        if !matches!(
            text(s, "state")?,
            "complete" | "partial" | "not_present" | "unchecked"
        ) {
            return Err(StartupDiffError::MalformedInput);
        }
        validate_path_diagnostics(arr(s, "diagnostics")?, false)?;
    }
    if arr(l, "entries")?.len() > MAX_ROWS {
        return Err(StartupDiffError::LimitExceeded);
    }
    let row_total = arr(x, "entries")?
        .len()
        .saturating_add(arr(u, "records")?.len())
        .saturating_add(arr(l, "entries")?.len());
    if row_total > MAX_ROWS {
        return Err(StartupDiffError::LimitExceeded);
    }
    for e in arr(l, "entries")? {
        keys(
            e,
            &[
                "source_kind",
                "entry_kind",
                "path",
                "path_bytes_hex",
                "symlink_target",
                "symlink_target_hex",
                "symlink_target_sha256",
                "lines",
            ],
        )?;
        for f in [
            "source_kind",
            "entry_kind",
            "path",
            "path_bytes_hex",
            "symlink_target",
            "symlink_target_hex",
            "symlink_target_sha256",
        ] {
            check_str(e, f, 65536)?;
        }
        for line in arr(e, "lines")? {
            keys(
                line,
                &[
                    "line_number",
                    "byte_offset",
                    "byte_length",
                    "line_sha256",
                    "raw_line",
                    "raw_line_hex",
                ],
            )?;
            for f in ["line_sha256", "raw_line", "raw_line_hex"] {
                check_str(line, f, 65536)?;
            }
        }
    }
    Ok(())
}
fn validate_windows(v: &Value) -> Result<(), StartupDiffError> {
    let all = &[
        ("sources", 8192usize),
        ("registry_entries", 8192),
        ("folder_entries", 8192),
        ("service_entries", 8192),
        ("scheduled_task_entries", 8192),
        ("scheduled_task_actions", 8192),
    ];
    for (key, cap) in all {
        if arr(v, key)?.len() > *cap {
            return Err(StartupDiffError::LimitExceeded);
        }
    }
    let row_total = [
        "registry_entries",
        "folder_entries",
        "service_entries",
        "scheduled_task_entries",
        "scheduled_task_actions",
    ]
    .into_iter()
    .map(|key| arr(v, key).map(<[Value]>::len))
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .sum::<usize>();
    if row_total > MAX_ROWS {
        return Err(StartupDiffError::LimitExceeded);
    }
    let expected_sources: BTreeSet<&str> = [
        "current_user_run_native",
        "current_user_run_once_native",
        "current_user_run_32",
        "current_user_run_once_32",
        "local_machine_run_64",
        "local_machine_run_once_64",
        "local_machine_run_32",
        "local_machine_run_once_32",
        "user_startup",
        "common_startup",
        "service_start_configuration",
        "scheduled_task_triggers",
    ]
    .into_iter()
    .collect();
    let mut seen_sources = BTreeSet::new();
    for s in arr(v, "sources")? {
        keys(
            s,
            &[
                "id",
                "status",
                "entries_seen",
                "registry_hive",
                "registry_key",
                "registry_view",
                "location_path",
                "location_path_utf16_hex",
                "diagnostics",
            ],
        )?;
        check_str(s, "id", 256)?;
        check_str(s, "status", 32)?;
        let id = text(s, "id")?;
        if !expected_sources.contains(id) || !seen_sources.insert(id) {
            return Err(StartupDiffError::MalformedInput);
        }
        if !win_status(text(s, "status")?) {
            return Err(StartupDiffError::MalformedInput);
        }
        if num(s, "entries_seen")? > MAX_ROWS as u64 {
            return Err(StartupDiffError::LimitExceeded);
        }
        if arr(s, "diagnostics")?.len() > 256 {
            return Err(StartupDiffError::LimitExceeded);
        }
        for d in arr(s, "diagnostics")? {
            keys(
                d,
                &["code", "item_index", "message", "win32_error", "hresult"],
            )?;
            check_str(d, "code", 256)?;
            check_str(d, "message", 4096)?;
            for key in ["item_index", "win32_error", "hresult"] {
                optional_counter(d, key)?;
            }
        }
        for f in [
            "registry_hive",
            "registry_key",
            "registry_view",
            "location_path",
            "location_path_utf16_hex",
        ] {
            check_str(s, f, 131072)?;
        }
    }
    if seen_sources != expected_sources {
        return Err(StartupDiffError::MalformedInput);
    }
    for e in arr(v, "registry_entries")? {
        keys(
            e,
            &[
                "registry_key",
                "hive",
                "registry_view",
                "trigger",
                "value_name",
                "value_type",
                "command",
                "command_utf16_hex",
                "evidence",
            ],
        )?;
        for f in [
            "registry_key",
            "hive",
            "registry_view",
            "trigger",
            "value_name",
            "value_type",
            "command",
            "command_utf16_hex",
        ] {
            check_str(e, f, 131072)?;
        }
        let ev = e.get("evidence").ok_or(StartupDiffError::MalformedInput)?;
        keys(
            ev,
            &[
                "source",
                "hive",
                "registry_view",
                "registry_key",
                "value_index",
                "value_name",
                "registry_type",
            ],
        )?;
        for f in [
            "source",
            "hive",
            "registry_view",
            "registry_key",
            "value_name",
        ] {
            check_str(ev, f, 131072)?;
        }
        for field in ["hive", "registry_view", "registry_key", "value_name"] {
            if e[field] != ev[field] {
                return Err(StartupDiffError::MalformedInput);
            }
        }
        if text(ev, "source")? != "RegEnumValueW" {
            return Err(StartupDiffError::MalformedInput);
        }
        let _ = num(ev, "value_index")?;
        let _ = num(ev, "registry_type")?;
    }
    for e in arr(v, "folder_entries")? {
        keys(
            e,
            &[
                "folder_scope",
                "trigger",
                "display_path",
                "path_utf16_hex",
                "kind",
                "evidence",
            ],
        )?;
        for f in [
            "folder_scope",
            "trigger",
            "display_path",
            "path_utf16_hex",
            "kind",
        ] {
            check_str(e, f, 131072)?;
        }
        let ev = e.get("evidence").ok_or(StartupDiffError::MalformedInput)?;
        keys(
            ev,
            &["source", "folder_scope", "display_path", "path_utf16_hex"],
        )?;
        for field in ["folder_scope", "display_path", "path_utf16_hex"] {
            if e[field] != ev[field] {
                return Err(StartupDiffError::MalformedInput);
            }
        }
        if text(ev, "source")? != "SHGetKnownFolderPath/FindFirstFileW" {
            return Err(StartupDiffError::MalformedInput);
        }
    }
    for e in arr(v, "service_entries")? {
        keys(
            e,
            &[
                "service_name",
                "display_name",
                "start_type",
                "start_type_code",
                "account",
                "binary_path",
                "evidence",
            ],
        )?;
        for f in [
            "service_name",
            "display_name",
            "start_type",
            "account",
            "binary_path",
        ] {
            check_str(e, f, 131072)?;
        }
        let ev = e.get("evidence").ok_or(StartupDiffError::MalformedInput)?;
        keys(ev, &["source", "service_index"])?;
        check_str(ev, "source", 256)?;
        if text(ev, "source")? != "EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW" {
            return Err(StartupDiffError::MalformedInput);
        }
        let _ = num(ev, "service_index")?;
    }
    for e in arr(v, "scheduled_task_entries")? {
        keys(
            e,
            &[
                "task_path",
                "task_enabled",
                "trigger_type",
                "trigger_enabled",
                "logon_user",
                "evidence",
            ],
        )?;
        for f in ["task_path", "trigger_type", "logon_user"] {
            check_str(e, f, 131072)?;
        }
        let ev = e.get("evidence").ok_or(StartupDiffError::MalformedInput)?;
        keys(ev, &["source", "task_index", "trigger_index"])?;
        if text(ev, "source")? != "Task Scheduler IRegisteredTask/ITaskDefinition/ITrigger" {
            return Err(StartupDiffError::MalformedInput);
        }
        let _ = num(ev, "task_index")?;
        let _ = num(ev, "trigger_index")?;
    }
    for e in arr(v, "scheduled_task_actions")? {
        keys(
            e,
            &[
                "task_path",
                "action_index",
                "action_type",
                "action_type_code",
                "status",
                "executable_path",
                "arguments",
                "working_directory",
                "evidence",
            ],
        )?;
        for f in [
            "task_path",
            "action_type",
            "status",
            "executable_path",
            "arguments",
            "working_directory",
        ] {
            check_str(e, f, 131072)?;
        }
        let ev = e.get("evidence").ok_or(StartupDiffError::MalformedInput)?;
        keys(ev, &["source", "task_index", "action_index"])?;
        if !matches!(
            text(ev, "source")?,
            "Task Scheduler IActionCollection/IAction"
                | "Task Scheduler IActionCollection/IExecAction"
        ) || num(ev, "action_index")? != num(e, "action_index")?
        {
            return Err(StartupDiffError::MalformedInput);
        }
        let _ = num(ev, "task_index")?;
    }
    Ok(())
}

#[derive(Clone)]
struct Row {
    category: &'static str,
    key: String,
    facts: Vec<(&'static str, String)>,
    refs: Vec<String>,
    complete: bool,
    lossy_identity: bool,
}
fn digest(s: &str) -> String {
    crate::fingerprint::sha256_hex(s.as_bytes())
}
fn identity_tuple(parts: &[&str]) -> String {
    serde_json::to_string(parts).unwrap_or_default()
}
fn ptr(prefix: &str, i: usize) -> String {
    format!("{prefix}/{i}")
}
fn value(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}
fn objfact(v: &Value, fields: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    fields
        .iter()
        .map(|(n, k)| (*n, v.get(*k).map(value).unwrap_or_else(|| "null".into())))
        .collect()
}
fn side(r: &Row) -> StartupEvidenceSide {
    StartupEvidenceSide {
        references: r.refs.clone(),
    }
}
fn compare(l: &Value, r: &Value, k: Kind) -> Result<StartupInventoryDiff, StartupDiffError> {
    let (mut a, mut b, mut complete, mut lossy) = if k == Kind::Linux {
        (
            linux_rows(l)?,
            linux_rows(r)?,
            linux_complete(l) && linux_complete(r),
            0usize,
        )
    } else {
        (
            windows_rows(l)?,
            windows_rows(r)?,
            windows_complete(l) && windows_complete(r),
            0usize,
        )
    };
    if k == Kind::Linux {
        lossy = a
            .iter()
            .chain(b.iter())
            .filter(|x| x.category == "xdg_autostart" && x.lossy_identity)
            .count();
        a.retain(|x| !x.lossy_identity);
        b.retain(|x| !x.lossy_identity);
    }
    let mut left = BTreeMap::<(String, String), Vec<Row>>::new();
    let mut right = BTreeMap::<(String, String), Vec<Row>>::new();
    for x in a.drain(..) {
        left.entry((x.category.into(), x.key.clone()))
            .or_default()
            .push(x)
    }
    for x in b.drain(..) {
        right
            .entry((x.category.into(), x.key.clone()))
            .or_default()
            .push(x)
    }
    let mut out = Vec::new();
    let mut counts = StartupDiffCounts {
        lossy_xdg_paths: lossy,
        ..Default::default()
    };
    let mut diagnostics = BTreeSet::new();
    if k == Kind::Windows {
        let unkeyed = [l, r]
            .into_iter()
            .flat_map(|doc| {
                doc["scheduled_task_actions"]
                    .as_array()
                    .into_iter()
                    .flatten()
            })
            .filter(|action| {
                action["task_path"]
                    .as_str()
                    .is_none_or(|task_path| task_path.is_empty())
            })
            .count();
        if unkeyed > 0 {
            counts.ambiguous_identities += unkeyed;
            diagnostics
                .insert("task action rows without a usable task path have uncertain identity");
        }
    }
    for key in left
        .keys()
        .chain(right.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
    {
        let ls = left.get(&key).map(Vec::as_slice).unwrap_or(&[]);
        let rs = right.get(&key).map(Vec::as_slice).unwrap_or(&[]);
        if ls.len() > 1 || rs.len() > 1 {
            counts.ambiguous_identities += ls.len().max(rs.len());
            diagnostics.insert("duplicate startup identity is ambiguous");
            continue;
        }
        match (ls.first(), rs.first()) {
            (Some(x), Some(y)) => {
                let changed = x
                    .facts
                    .iter()
                    .filter_map(|(name, val)| {
                        y.facts
                            .iter()
                            .find(|(n, _)| n == name)
                            .filter(|(_, other)| other != val)
                            .map(|_| *name)
                    })
                    .collect::<Vec<_>>();
                if !changed.is_empty() {
                    push_delta(
                        &mut out,
                        StartupDelta {
                            kind: "changed",
                            category: x.category,
                            identity_sha256: digest(&x.key),
                            changed_fields: changed,
                            before: Some(side(x)),
                            after: Some(side(y)),
                        },
                    )?;
                    counts.changed += 1;
                }
            }
            (Some(x), None) | (None, Some(x)) => {
                if complete && x.complete {
                    let before = ls.first();
                    let after = rs.first();
                    let row = before.or(after).unwrap();
                    let (kind, bef, aft) = if before.is_some() {
                        ("observed_before_only", Some(side(row)), None)
                    } else {
                        ("observed_after_only", None, Some(side(row)))
                    };
                    push_delta(
                        &mut out,
                        StartupDelta {
                            kind,
                            category: row.category,
                            identity_sha256: digest(&row.key),
                            changed_fields: Vec::new(),
                            before: bef,
                            after: aft,
                        },
                    )?;
                    if kind == "observed_before_only" {
                        counts.observed_before_only += 1
                    } else {
                        counts.observed_after_only += 1
                    }
                } else {
                    counts.unmatched_rows_suppressed_for_incomplete_source += 1;
                    diagnostics.insert("unmatched rows suppressed because a source is incomplete");
                }
            }
            _ => {}
        }
    }
    if counts.ambiguous_identities > 0 || lossy > 0 || !complete {
        diagnostics.insert("comparison coverage is partial or identity is uncertain");
    }
    if !diagnostics.is_empty() {
        complete = false;
    }
    Ok(StartupInventoryDiff {
        schema: "sideeffect.startup_inventory_diff",
        schema_version: 1,
        platform: if k == Kind::Linux { "linux" } else { "windows" },
        before_captured_at_unix_ms: num(l, "capture_ended_at_unix_ms")? as u128,
        after_captured_at_unix_ms: num(r, "capture_ended_at_unix_ms")? as u128,
        status: if complete {
            StartupDiffStatus::Complete
        } else {
            StartupDiffStatus::Partial
        },
        coverage_note: "A bounded comparison of two native startup configuration snapshots. It is not installed/removed or executed history, effective startup state, exhaustive coverage, causation, or proof of absence. Paths and source evidence can be sensitive.",
        counts,
        diagnostics: diagnostics.into_iter().collect(),
        deltas: out,
    })
}
fn push_delta(out: &mut Vec<StartupDelta>, delta: StartupDelta) -> Result<(), StartupDiffError> {
    if out.len() >= MAX_DELTAS {
        return Err(StartupDiffError::LimitExceeded);
    }
    out.push(delta);
    Ok(())
}
fn linux_complete(v: &Value) -> bool {
    v["status"] == "complete"
        && v["xdg_autostart"]["status"] == "complete"
        && v["xdg_autostart"]["directories"]
            .as_array()
            .is_some_and(|rows| rows.iter().all(|row| row["status"] == "complete"))
        && v["systemd_units"]["status"] == "complete"
        && v["systemd_units"]["directories"]
            .as_array()
            .is_some_and(|rows| rows.iter().all(|row| row["status"] == "complete"))
        && v["legacy_sources"]["status"] == "complete"
        && v["legacy_sources"]["sources"].as_array().is_some_and(|a| {
            a.iter()
                .all(|s| matches!(s["state"].as_str(), Some("complete" | "not_present")))
        })
}
fn linux_rows(v: &Value) -> Result<Vec<Row>, StartupDiffError> {
    let mut rows = Vec::new();
    for (i, e) in arr(&v["xdg_autostart"], "entries")?.iter().enumerate() {
        let path = text(e, "source_path")?;
        let lossy_identity = path.contains('\u{fffd}');
        let key = if lossy_identity {
            identity_tuple(&["LOSSY", text(e, "scope")?, path])
        } else {
            identity_tuple(&[text(e, "scope")?, path])
        };
        let fields = e["keys"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|x| {
                format!(
                    "{}={}",
                    x["key"].as_str().unwrap_or(""),
                    x["value"]
                        .as_str()
                        .or(x["value_hex"].as_str())
                        .unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        rows.push(Row {
            category: "xdg_autostart",
            key,
            facts: vec![("selected_keys", digest(&fields))],
            refs: vec![ptr("/xdg_autostart/entries", i)],
            complete: linux_component_complete(&v["xdg_autostart"]),
            lossy_identity,
        });
    }
    for (i, e) in arr(&v["systemd_units"], "records")?.iter().enumerate() {
        let key = identity_tuple(&[
            text(e, "scope")?,
            text(e, "record_type")?,
            text(e, "source_path_bytes_hex")?,
        ]);
        let facts = vec![
            ("directives", digest(&value(&e["directives"]))),
            ("symlink_target", digest(&value(&e["symlink_target"]))),
        ];
        rows.push(Row {
            category: "systemd_units",
            key,
            facts,
            refs: vec![ptr("/systemd_units/records", i)],
            complete: linux_component_complete(&v["systemd_units"]),
            lossy_identity: false,
        });
    }
    for (i, e) in arr(&v["legacy_sources"], "entries")?.iter().enumerate() {
        let key = identity_tuple(&[
            text(e, "source_kind")?,
            text(e, "entry_kind")?,
            text(e, "path_bytes_hex")?,
        ]);
        let facts = vec![
            ("symlink_target", digest(&value(&e["symlink_target_hex"]))),
            ("line_evidence", digest(&value(&e["lines"]))),
        ];
        rows.push(Row {
            category: "legacy_sources",
            key,
            facts,
            refs: vec![ptr("/legacy_sources/entries", i)],
            complete: linux_component_complete(&v["legacy_sources"]),
            lossy_identity: false,
        });
    }
    Ok(rows)
}
fn linux_component_complete(v: &Value) -> bool {
    v["status"] == "complete"
}
fn windows_complete(v: &Value) -> bool {
    v["status"] == "complete"
        && v["sources"].as_array().is_some_and(|a| {
            a.len() == 12
                && a.iter()
                    .all(|s| matches!(s["status"].as_str(), Some("complete" | "not_present")))
        })
}
fn source_complete(v: &Value, id: &str) -> bool {
    v["sources"].as_array().is_some_and(|a| {
        a.iter().any(|s| {
            s["id"] == id && matches!(s["status"].as_str(), Some("complete" | "not_present"))
        })
    })
}
fn registry_source_complete(v: &Value, entry: &Value) -> bool {
    v["sources"].as_array().is_some_and(|sources| {
        sources.iter().any(|source| {
            source["registry_hive"] == entry["hive"]
                && source["registry_key"] == entry["registry_key"]
                && source["registry_view"] == entry["registry_view"]
                && matches!(source["status"].as_str(), Some("complete" | "not_present"))
        })
    })
}
fn windows_rows(v: &Value) -> Result<Vec<Row>, StartupDiffError> {
    let mut rows = Vec::new();
    for (i, e) in arr(v, "registry_entries")?.iter().enumerate() {
        let ev = &e["evidence"];
        let key = identity_tuple(&[
            ev["source"].as_str().unwrap_or(""),
            ev["hive"].as_str().unwrap_or(""),
            ev["registry_view"].as_str().unwrap_or(""),
            ev["registry_key"].as_str().unwrap_or(""),
            ev["value_name"].as_str().unwrap_or(""),
        ]);
        rows.push(Row {
            category: "registry_entry",
            key,
            facts: objfact(
                e,
                &[
                    ("value_type", "value_type"),
                    ("command", "command"),
                    ("command_encoding", "command_utf16_hex"),
                ],
            ),
            refs: vec![ptr("/registry_entries", i)],
            complete: registry_source_complete(v, e),
            lossy_identity: false,
        });
    }
    for (i, e) in arr(v, "folder_entries")?.iter().enumerate() {
        let key = identity_tuple(&[
            e["folder_scope"].as_str().unwrap_or(""),
            e["trigger"].as_str().unwrap_or(""),
            e["path_utf16_hex"].as_str().unwrap_or(""),
        ]);
        let id = e["folder_scope"].as_str().unwrap_or("");
        rows.push(Row {
            category: "startup_folder_entry",
            key,
            facts: objfact(e, &[("kind", "kind")]),
            refs: vec![ptr("/folder_entries", i)],
            complete: source_complete(v, id),
            lossy_identity: false,
        });
    }
    for (i, e) in arr(v, "service_entries")?.iter().enumerate() {
        let key = text(e, "service_name")?.to_owned();
        let id = "service_start_configuration";
        rows.push(Row {
            category: "service_configuration",
            key,
            facts: objfact(
                e,
                &[
                    ("display_name", "display_name"),
                    ("start_type", "start_type"),
                    ("start_type_code", "start_type_code"),
                    ("account", "account"),
                    ("binary_path", "binary_path"),
                ],
            ),
            refs: vec![ptr("/service_entries", i)],
            complete: source_complete(v, id),
            lossy_identity: false,
        });
    }
    for (i, e) in arr(v, "scheduled_task_entries")?.iter().enumerate() {
        let key = identity_tuple(&[text(e, "task_path")?, text(e, "trigger_type")?]);
        let id = "scheduled_task_triggers";
        rows.push(Row {
            category: "scheduled_task_trigger",
            key,
            facts: objfact(
                e,
                &[
                    ("task_enabled", "task_enabled"),
                    ("trigger_enabled", "trigger_enabled"),
                    ("logon_user", "logon_user"),
                ],
            ),
            refs: vec![ptr("/scheduled_task_entries", i)],
            complete: source_complete(v, id),
            lossy_identity: false,
        });
    }
    let mut groups = BTreeMap::<String, Vec<(usize, &Value)>>::new();
    for (i, e) in arr(v, "scheduled_task_actions")?.iter().enumerate() {
        if let Some(p) = e["task_path"].as_str().filter(|path| !path.is_empty()) {
            groups.entry(p.to_owned()).or_default().push((i, e));
        }
    }
    for (task, mut seq) in groups {
        seq.sort_by_key(|(_, e)| e["action_index"].as_u64().unwrap_or(u64::MAX));
        let indices = seq.iter().map(|(i, _)| *i).collect::<Vec<_>>();
        let facts = seq
            .iter()
            .map(|(_, e)| {
                value(&Value::Array(
                    [
                        "action_type",
                        "action_type_code",
                        "status",
                        "executable_path",
                        "arguments",
                        "working_directory",
                    ]
                    .iter()
                    .map(|k| e[*k].clone())
                    .collect(),
                ))
            })
            .collect::<Vec<_>>()
            .join("\n");
        let id = seq.first().map(|_| "scheduled_task_triggers").unwrap_or("");
        rows.push(Row {
            category: "scheduled_task_action_sequence",
            key: task,
            facts: vec![("action_sequence", digest(&facts))],
            refs: indices
                .iter()
                .map(|i| ptr("/scheduled_task_actions", *i))
                .collect(),
            complete: source_complete(v, id),
            lossy_identity: false,
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn linux() -> Value {
        json!({
            "schema": LINUX, "schema_version": 2, "platform":"linux",
            "scope":"curated_xdg_systemd_sysv_cron_sources", "capture_started_at_unix_ms":1,
            "capture_ended_at_unix_ms":2, "status":"complete",
            "xdg_autostart":{"schema":"sideeffect.xdg_autostart_inventory","schema_version":1,"platform":"linux","scope":"xdg_autostart_files_only","capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":"complete","directories":[],"entries":[]},
            "systemd_units":{"schema":"sideeffect.systemd_unit_inventory","schema_version":1,"platform":"linux","scope":"systemd_unit_files_and_enablement_symlink_references","capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":"complete","directories":[],"records":[]},
            "legacy_sources":{"schema":"sideeffect.legacy_startup_inventory","schema_version":1,"platform":"linux","scope":"common_sysv_cron_paths_only","capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":"complete","sources":[],"entries":[]}
        })
    }
    fn windows() -> Value {
        let ids = [
            "current_user_run_native",
            "current_user_run_once_native",
            "current_user_run_32",
            "current_user_run_once_32",
            "local_machine_run_64",
            "local_machine_run_once_64",
            "local_machine_run_32",
            "local_machine_run_once_32",
            "user_startup",
            "common_startup",
            "service_start_configuration",
            "scheduled_task_triggers",
        ];
        json!({"schema":WINDOWS,"schema_version":4,"platform":"windows","scope":"current_user_and_accessible_machine_run_keys_startup_folders_services_and_current_token_visible_tasks","capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":"complete","sources":ids.into_iter().map(|id|json!({"id":id,"status":"complete","entries_seen":0,"diagnostics":[]})).collect::<Vec<_>>(),"registry_entries":[],"folder_entries":[],"service_entries":[],"scheduled_task_entries":[],"scheduled_task_actions":[]})
    }
    fn bytes(v: &Value) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }

    #[test]
    fn linux_partial_suppresses_presence_and_lossy_paths_are_unknown() {
        let left = linux();
        let mut right = linux();
        right["xdg_autostart"]["entries"] = json!([{"scope":"user","source_path":"/home/u/.config/autostart/�.desktop","applicability":"not_evaluated","keys":[]}]);
        let mut partial = right.clone();
        partial["status"] = json!("partial");
        partial["xdg_autostart"]["status"] = json!("partial");
        let diff = compare_startup_inventory_json(&bytes(&left), &bytes(&right)).unwrap();
        assert_eq!(diff.counts.lossy_xdg_paths, 1);
        assert_eq!(diff.counts.observed_after_only, 0);
        right["xdg_autostart"]["entries"][0]["source_path"] =
            json!("/home/u/.config/autostart/LOSSY.desktop");
        let diff = compare_startup_inventory_json(&bytes(&left), &bytes(&right)).unwrap();
        assert_eq!(diff.counts.lossy_xdg_paths, 0);
        assert_eq!(diff.counts.observed_after_only, 1);
        partial["xdg_autostart"]["entries"][0]["source_path"] =
            json!("/home/u/.config/autostart/app.desktop");
        let diff = compare_startup_inventory_json(&bytes(&left), &bytes(&partial)).unwrap();
        assert_eq!(
            diff.counts.unmatched_rows_suppressed_for_incomplete_source,
            1
        );
        let mut inconsistent = right.clone();
        inconsistent["xdg_autostart"]["entries"][0]["source_path"] =
            json!("/home/u/.config/autostart/app.desktop");
        inconsistent["xdg_autostart"]["directories"] = json!([{
            "scope":"user","path":"/u/autostart","status":"partial","files_seen":0,"diagnostics":[]
        }]);
        let diff = compare_startup_inventory_json(&bytes(&left), &bytes(&inconsistent)).unwrap();
        assert_eq!(diff.counts.observed_after_only, 0);
        assert_eq!(
            diff.counts.unmatched_rows_suppressed_for_incomplete_source,
            1
        );
    }
    #[test]
    fn linux_duplicate_identity_is_ambiguous_and_changed_values_are_not_emitted() {
        let mut left = linux();
        let mut right = linux();
        let entry = |value: &str| json!({"scope":"user","source_path":"/u/a.desktop","applicability":"not_evaluated","keys":[{"key":"Exec","value":value,"value_hex":null,"line":1,"byte_offset":0,"byte_length":value.len(),"line_sha256":"abc"}]});
        left["xdg_autostart"]["entries"] = json!([entry("SECRET_OLD")]);
        right["xdg_autostart"]["entries"] = json!([entry("SECRET_NEW")]);
        let out = compare_startup_inventory_json(&bytes(&left), &bytes(&right)).unwrap();
        let rendered = serde_json::to_string(&out).unwrap();
        assert!(rendered.contains("selected_keys"));
        assert!(!rendered.contains("SECRET_"));
        assert_eq!(out.counts.changed, 1);
        left["xdg_autostart"]["entries"] = json!([entry("a"), entry("b")]);
        let out = compare_startup_inventory_json(&bytes(&left), &bytes(&right)).unwrap();
        assert!(out.counts.ambiguous_identities > 0);
        assert_eq!(out.counts.observed_before_only, 0);
    }
    #[test]
    fn windows_duplicate_task_triggers_are_ambiguous_and_action_order_is_compared_without_values() {
        let mut left = windows();
        let mut right = windows();
        let trigger = |index| json!({"task_path":"\\Task","task_enabled":true,"trigger_type":"boot","trigger_enabled":true,"evidence":{"source":"Task Scheduler IRegisteredTask/ITaskDefinition/ITrigger","task_index":1,"trigger_index":index}});
        left["scheduled_task_entries"] = json!([trigger(0), trigger(1)]);
        right["scheduled_task_entries"] = json!([trigger(0)]);
        let action = |index, path: &str| json!({"task_path":"\\Task","action_index":index,"action_type":"exec","action_type_code":0,"status":"observed","executable_path":path,"arguments":"SENSITIVE_ARGUMENT","working_directory":null,"evidence":{"source":"Task Scheduler IActionCollection/IExecAction","task_index":1,"action_index":index}});
        left["scheduled_task_actions"] = json!([action(0, "old.exe"), action(1, "next.exe")]);
        right["scheduled_task_actions"] = json!([action(0, "next.exe"), action(1, "old.exe")]);
        let out = compare_startup_inventory_json(&bytes(&left), &bytes(&right)).unwrap();
        let rendered = serde_json::to_string(&out).unwrap();
        assert!(out.counts.ambiguous_identities > 0);
        assert!(
            out.deltas
                .iter()
                .any(|d| d.category == "scheduled_task_action_sequence"
                    && d.changed_fields == ["action_sequence"])
        );
        assert!(!rendered.contains("SENSITIVE_ARGUMENT"));
        assert!(!rendered.contains("old.exe"));
    }
    #[test]
    fn windows_incomplete_source_suppresses_presence_and_registry_values_stay_private() {
        let mut left = windows();
        let mut right = windows();
        right["sources"][0]["status"] = json!("partial");
        right["registry_entries"] = json!([{"registry_key":"Run","hive":"HKEY_CURRENT_USER","registry_view":"native","trigger":"user_logon","value_name":"secret","value_type":"REG_SZ","command":"PRIVATE_COMMAND","evidence":{"source":"RegEnumValueW","hive":"HKEY_CURRENT_USER","registry_view":"native","registry_key":"Run","value_index":0,"value_name":"secret","registry_type":1}}]);
        let out = compare_startup_inventory_json(&bytes(&left), &bytes(&right)).unwrap();
        let rendered = serde_json::to_string(&out).unwrap();
        assert_eq!(
            out.counts.unmatched_rows_suppressed_for_incomplete_source,
            1
        );
        assert!(!rendered.contains("PRIVATE_COMMAND"));
        assert!(!rendered.contains("secret"));
        left["scheduled_task_entries"] = json!([]);
    }

    #[test]
    fn windows_actions_without_usable_task_path_are_reported_as_ambiguous() {
        let mut left = windows();
        let right = windows();
        left["scheduled_task_actions"] = json!([
            {
                "task_path":null,"action_index":0,"action_type":"exec","action_type_code":0,
                "status":"observed","executable_path":"private.exe","arguments":null,
                "working_directory":null,"evidence":{"source":"Task Scheduler IActionCollection/IExecAction","task_index":2,"action_index":0}
            },
            {
                "task_path":"","action_index":1,"action_type":"exec","action_type_code":0,
                "status":"observed","executable_path":"private-empty.exe","arguments":null,
                "working_directory":null,"evidence":{"source":"Task Scheduler IActionCollection/IExecAction","task_index":3,"action_index":1}
            }
        ]);
        let out = compare_startup_inventory_json(&bytes(&left), &bytes(&right)).unwrap();
        assert_eq!(out.counts.observed_before_only, 0);
        assert_eq!(out.counts.ambiguous_identities, 2);
        assert!(
            out.diagnostics
                .iter()
                .any(|d| d.contains("without a usable task path"))
        );
        let rendered = serde_json::to_string(&out).unwrap();
        assert!(!rendered.contains("private.exe"));
        assert!(!rendered.contains("private-empty.exe"));
    }

    #[test]
    fn registry_identity_tuple_does_not_collide_on_delimiters() {
        let mut left = windows();
        let mut right = windows();
        let row = |key: &str, name: &str| {
            json!({
                "registry_key":key,"hive":"HKEY_CURRENT_USER","registry_view":"native",
                "trigger":"user_logon","value_name":name,"value_type":"REG_SZ","command":null,
                "evidence":{"source":"RegEnumValueW","hive":"HKEY_CURRENT_USER","registry_view":"native",
                    "registry_key":key,"value_index":0,"value_name":name,"registry_type":1}
            })
        };
        left["sources"][0]["registry_hive"] = json!("HKEY_CURRENT_USER");
        left["sources"][0]["registry_key"] = json!("A:B");
        left["sources"][0]["registry_view"] = json!("native");
        right["sources"][0]["registry_hive"] = json!("HKEY_CURRENT_USER");
        right["sources"][0]["registry_key"] = json!("A");
        right["sources"][0]["registry_view"] = json!("native");
        left["registry_entries"] = json!([row("A:B", "C")]);
        right["registry_entries"] = json!([row("A", "B:C")]);
        let out = compare_startup_inventory_json(&bytes(&left), &bytes(&right)).unwrap();
        assert_eq!(out.counts.observed_before_only, 1);
        assert_eq!(out.counts.observed_after_only, 1);
    }
    #[test]
    fn malformed_unknown_nested_and_oversized_documents_are_rejected() {
        let mut v = linux();
        v["xdg_autostart"]["entries"] = json!([{"scope":"user","source_path":"/x","applicability":"not_evaluated","keys":[],"unknown_nested":true}]);
        assert!(matches!(
            compare_startup_inventory_json(&bytes(&v), &bytes(&linux())),
            Err(StartupDiffError::MalformedInput)
        ));
        assert!(matches!(
            compare_startup_inventory_json(b"{", b"{}"),
            Err(StartupDiffError::MalformedInput)
        ));
        assert!(matches!(
            compare_startup_inventory_json(
                &vec![b' '; MAX_INPUT / 2 + 1],
                &vec![b' '; MAX_INPUT / 2 + 1]
            ),
            Err(StartupDiffError::InputTooLarge)
        ));
    }
}
