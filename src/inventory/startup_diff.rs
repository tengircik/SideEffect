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
const SYSTEMD_DEPENDENCY_DIRECTIVES: &[&str] = &[
    "Requires",
    "Requisite",
    "Wants",
    "BindsTo",
    "PartOf",
    "Upholds",
    "Conflicts",
];
const SYSTEMD_ORDERING_DIRECTIVES: &[&str] = &["Before", "After"];
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
impl Visitor<'_> for KeyVisitor {
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
fn startup_row_keys(
    value: &Value,
    fields: &[&str],
    has_states: bool,
) -> Result<(), StartupDiffError> {
    if !has_states {
        return keys(value, fields);
    }
    let mut allowed = fields.to_vec();
    allowed.push("startup_state");
    keys(value, &allowed)
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
    if items.len() > MAX_COLLECTION {
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
    let version = num(v, "schema_version")?;
    let windows_has_wmi = if k == Kind::Windows {
        windows_has_wmi_contract(v, version)
    } else {
        false
    };
    let (schema, platform, scope, versions) = match k {
        Kind::Linux => (
            LINUX,
            "linux",
            "curated_xdg_systemd_sysv_cron_sources",
            &[2_u64, 3][..],
        ),
        Kind::Windows => (
            WINDOWS,
            "windows",
            if windows_has_wmi && version >= 10 {
                "current_user_and_accessible_machine_run_keys_startup_folders_services_with_delayed_auto_start_dependencies_load_order_group_and_trigger_configuration_and_current_token_visible_tasks_and_local_root_subscription_wmi_objects"
            } else if windows_has_wmi && version >= 9 {
                "current_user_and_accessible_machine_run_keys_startup_folders_services_with_delayed_auto_start_dependencies_and_load_order_group_configuration_and_current_token_visible_tasks_and_local_root_subscription_wmi_objects"
            } else if windows_has_wmi && version >= 8 {
                "current_user_and_accessible_machine_run_keys_startup_folders_services_with_delayed_auto_start_configuration_and_current_token_visible_tasks_and_local_root_subscription_wmi_objects"
            } else if windows_has_wmi {
                "current_user_and_accessible_machine_run_keys_startup_folders_services_current_token_visible_tasks_and_local_root_subscription_wmi_objects"
            } else if version >= 10 {
                "current_user_and_accessible_machine_run_keys_startup_folders_services_with_delayed_auto_start_dependencies_load_order_group_and_trigger_configuration_and_current_token_visible_tasks"
            } else if version >= 9 {
                "current_user_and_accessible_machine_run_keys_startup_folders_services_with_delayed_auto_start_dependencies_and_load_order_group_configuration_and_current_token_visible_tasks"
            } else {
                "current_user_and_accessible_machine_run_keys_startup_folders_services_and_current_token_visible_tasks"
            },
            &[4_u64, 5, 6, 7, 8, 9, 10][..],
        ),
    };
    if text(v, "schema")? != schema || !versions.contains(&version) {
        return Err(StartupDiffError::UnsupportedSchema);
    }
    if k == Kind::Windows {
        validate_windows_wmi_presence(v, version, windows_has_wmi)?;
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
                "wmi_event_filters",
                "wmi_event_consumers",
                "wmi_filter_consumer_bindings",
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
        validate_linux(v, version == 3)?
    } else {
        validate_windows(v, version)?
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
        "wmi_event_filters",
        "wmi_event_consumers",
        "wmi_filter_consumer_bindings",
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
        "startup_state",
        "configured",
        "effective",
        "observed",
        "context",
        "capture_interval",
        "started_at_unix_ms",
        "ended_at_unix_ms",
        "artifact_path",
        "artifact_schema",
        "artifact_schema_version",
        "record_locator",
        "keys",
        "code",
        "diagnostic_code",
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
        "detail_evidence",
        "value_index",
        "registry_type",
        "folder_scope",
        "display_path",
        "service_name",
        "display_name",
        "dependencies",
        "load_order_group",
        "triggers",
        "trigger_type_code",
        "action_code",
        "action",
        "subtype_guid",
        "data_items",
        "data_type_code",
        "data_type",
        "data_hex",
        "delayed_auto_start",
        "start_type",
        "start_type_code",
        "account",
        "binary_path",
        "service_observation",
        "raw_state_code",
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
        "object_path",
        "name",
        "creator_sid",
        "event_namespace",
        "query_language",
        "query",
        "class_name",
        "status",
        "command_line_template",
        "script_file_name",
        "script_text",
        "filter_reference",
        "consumer_reference",
        "filter_reference_status",
        "consumer_reference_status",
        "delivery_qos",
        "namespace",
        "object_index",
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

fn windows_has_wmi_contract(v: &Value, version: u64) -> bool {
    if version == 6 {
        return true;
    }
    if version < 7 {
        return false;
    }
    [
        "wmi_event_filters",
        "wmi_event_consumers",
        "wmi_filter_consumer_bindings",
    ]
    .iter()
    .any(|field| v.get(*field).is_some())
        || v.get("sources")
            .and_then(Value::as_array)
            .is_some_and(|sources| {
                sources
                    .iter()
                    .any(|source| source["id"] == "wmi_permanent_event_subscriptions")
            })
}

fn validate_windows_wmi_presence(
    v: &Value,
    version: u64,
    has_wmi: bool,
) -> Result<(), StartupDiffError> {
    let fields = [
        "wmi_event_filters",
        "wmi_event_consumers",
        "wmi_filter_consumer_bindings",
    ];
    let present_count = fields
        .iter()
        .filter(|field| v.get(**field).is_some())
        .count();
    if version == 6 && present_count != fields.len()
        || version < 6 && (present_count != 0 || has_wmi)
        || version >= 7 && (present_count != 0 && present_count != fields.len())
        || version >= 7 && (present_count == fields.len()) != has_wmi
    {
        return Err(StartupDiffError::MalformedInput);
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
fn validate_startup_state(value: &Value) -> Result<(), StartupDiffError> {
    keys(
        value,
        &["schema_version", "configured", "effective", "observed"],
    )?;
    if num(value, "schema_version")? != 1 {
        return Err(StartupDiffError::UnsupportedSchema);
    }
    if text(value, "configured")? != "present" {
        return Err(StartupDiffError::MalformedInput);
    }
    let effective = value
        .get("effective")
        .ok_or(StartupDiffError::MalformedInput)?;
    keys(effective, &["status", "context", "evidence"])?;
    match text(effective, "status")? {
        "unknown" => {
            if !effective["context"].is_null() || !effective["evidence"].is_null() {
                return Err(StartupDiffError::MalformedInput);
            }
        }
        "effective" | "not_effective" => {
            let context = text(effective, "context")?;
            if context.is_empty() || context.len() > 512 {
                return Err(StartupDiffError::LimitExceeded);
            }
            validate_state_evidence(&effective["evidence"])?;
        }
        _ => return Err(StartupDiffError::MalformedInput),
    }
    let observed = value
        .get("observed")
        .ok_or(StartupDiffError::MalformedInput)?;
    keys(observed, &["status", "capture_interval", "evidence"])?;
    match text(observed, "status")? {
        "unknown" => {
            if !observed["capture_interval"].is_null() || !observed["evidence"].is_null() {
                return Err(StartupDiffError::MalformedInput);
            }
        }
        "observed" => {
            let interval = observed
                .get("capture_interval")
                .ok_or(StartupDiffError::MalformedInput)?;
            keys(interval, &["started_at_unix_ms", "ended_at_unix_ms"])?;
            if num(interval, "started_at_unix_ms")? > num(interval, "ended_at_unix_ms")? {
                return Err(StartupDiffError::MalformedInput);
            }
            validate_state_evidence(&observed["evidence"])?;
        }
        _ => return Err(StartupDiffError::MalformedInput),
    }
    Ok(())
}
fn validate_service_observation(value: &Value) -> Result<(), StartupDiffError> {
    let status = text(value, "status")?;
    let raw_state_code = num(value, "raw_state_code")?;
    if raw_state_code > u64::from(u32::MAX) {
        return Err(StartupDiffError::MalformedInput);
    }
    let expected_state = match raw_state_code {
        1 => Some("stopped"),
        2 => Some("start_pending"),
        3 => Some("stop_pending"),
        4 => Some("running"),
        5 => Some("continue_pending"),
        6 => Some("pause_pending"),
        7 => Some("paused"),
        _ => None,
    };
    match status {
        "known" => {
            keys(value, &["status", "state", "raw_state_code"])?;
            if text(value, "state")? != expected_state.ok_or(StartupDiffError::MalformedInput)? {
                return Err(StartupDiffError::MalformedInput);
            }
        }
        "unknown" => {
            keys(value, &["status", "raw_state_code"])?;
            if expected_state.is_some() {
                return Err(StartupDiffError::MalformedInput);
            }
        }
        _ => return Err(StartupDiffError::MalformedInput),
    }
    Ok(())
}

fn validate_delayed_auto_start(value: &Value) -> Result<(), StartupDiffError> {
    match text(value, "status")? {
        "observed" => {
            keys(value, &["status", "value"])?;
            let _ = value
                .get("value")
                .and_then(Value::as_bool)
                .ok_or(StartupDiffError::MalformedInput)?;
        }
        "unknown" => {
            keys(value, &["status", "diagnostic_code"])?;
            let diagnostic = text(value, "diagnostic_code")?;
            if !matches!(
                diagnostic,
                "service_delayed_auto_start_unsupported"
                    | "service_delayed_auto_start_access_denied"
                    | "service_delayed_auto_start_query_failed"
                    | "service_delayed_auto_start_response_invalid"
                    | "service_delayed_auto_start_budget_exceeded"
                    | "service_delayed_auto_start_deadline_exceeded"
            ) {
                return Err(StartupDiffError::MalformedInput);
            }
        }
        _ => return Err(StartupDiffError::MalformedInput),
    }
    Ok(())
}

fn validate_service_dependencies(value: &Value) -> Result<(), StartupDiffError> {
    match text(value, "status")? {
        "observed" => {
            keys(value, &["status", "entries"])?;
            let entries = arr(value, "entries")?;
            if entries.len() > 4_096 {
                return Err(StartupDiffError::LimitExceeded);
            }
            for entry in entries {
                keys(entry, &["kind", "name"])?;
                if !matches!(text(entry, "kind")?, "service" | "load_order_group") {
                    return Err(StartupDiffError::MalformedInput);
                }
                let name = text(entry, "name")?;
                check_str(entry, "name", 32_768)?;
                if name.is_empty() || name.starts_with('+') {
                    return Err(StartupDiffError::MalformedInput);
                }
            }
        }
        "unknown" => {
            keys(value, &["status", "diagnostic_code"])?;
            if text(value, "diagnostic_code")? != "service_dependencies_response_invalid"
                && text(value, "diagnostic_code")? != "service_dependencies_limit_exceeded"
                && text(value, "diagnostic_code")? != "service_dependency_budget_exceeded"
            {
                return Err(StartupDiffError::MalformedInput);
            }
        }
        _ => return Err(StartupDiffError::MalformedInput),
    }
    Ok(())
}

fn validate_service_load_order_group(value: &Value) -> Result<(), StartupDiffError> {
    match text(value, "status")? {
        "observed" => {
            keys(value, &["status", "value"])?;
            if !value["value"].is_null() {
                check_str(value, "value", 32_768)?;
                if text(value, "value")?.is_empty() {
                    return Err(StartupDiffError::MalformedInput);
                }
            }
        }
        "unknown" => {
            keys(value, &["status", "diagnostic_code"])?;
            if !matches!(
                text(value, "diagnostic_code")?,
                "service_load_order_group_response_invalid"
                    | "service_load_order_group_limit_exceeded"
                    | "service_load_order_group_budget_exceeded"
            ) {
                return Err(StartupDiffError::MalformedInput);
            }
        }
        _ => return Err(StartupDiffError::MalformedInput),
    }
    Ok(())
}

fn validate_service_triggers(value: &Value) -> Result<(), StartupDiffError> {
    match text(value, "status")? {
        "observed" => {
            keys(value, &["status", "entries"])?;
            let entries = arr(value, "entries")?;
            if entries.len() > 256 {
                return Err(StartupDiffError::LimitExceeded);
            }
            for entry in entries {
                keys(
                    entry,
                    &[
                        "trigger_index",
                        "trigger_type_code",
                        "trigger_type",
                        "action_code",
                        "action",
                        "subtype_guid",
                        "data_items",
                    ],
                )?;
                let _ = num(entry, "trigger_index")?;
                let _ = num(entry, "trigger_type_code")?;
                let _ = num(entry, "action_code")?;
                if !matches!(
                    text(entry, "trigger_type")?,
                    "device_interface_arrival"
                        | "ip_address_availability"
                        | "domain_join"
                        | "firewall_port_event"
                        | "group_policy"
                        | "network_endpoint"
                        | "custom"
                        | "unknown"
                ) || !matches!(
                    text(entry, "action")?,
                    "service_start" | "service_stop" | "unknown"
                ) {
                    return Err(StartupDiffError::MalformedInput);
                }
                if entry
                    .get("subtype_guid")
                    .is_some_and(|guid| !guid.is_null())
                {
                    let guid = text(entry, "subtype_guid")?;
                    check_str(entry, "subtype_guid", 36)?;
                    if guid.len() != 36
                        || !guid.bytes().enumerate().all(|(i, byte)| {
                            if [8, 13, 18, 23].contains(&i) {
                                byte == b'-'
                            } else {
                                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                            }
                        })
                    {
                        return Err(StartupDiffError::MalformedInput);
                    }
                }
                let data_items = arr(entry, "data_items")?;
                if data_items.len() > 64 {
                    return Err(StartupDiffError::LimitExceeded);
                }
                for item in data_items {
                    keys(item, &["data_type_code", "data_type", "data_hex"])?;
                    let _ = num(item, "data_type_code")?;
                    if !matches!(
                        text(item, "data_type")?,
                        "binary" | "string" | "level" | "keyword_any" | "keyword_all" | "unknown"
                    ) {
                        return Err(StartupDiffError::MalformedInput);
                    }
                    let hex = text(item, "data_hex")?;
                    check_str(item, "data_hex", 2 * 1024)?;
                    if hex.len() % 2 != 0
                        || !hex
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    {
                        return Err(StartupDiffError::MalformedInput);
                    }
                }
            }
        }
        "unknown" => {
            keys(value, &["status", "diagnostic_code"])?;
            if !matches!(
                text(value, "diagnostic_code")?,
                "service_trigger_unsupported"
                    | "service_trigger_access_denied"
                    | "service_trigger_query_failed"
                    | "service_trigger_response_invalid"
                    | "service_trigger_budget_exceeded"
                    | "service_trigger_count_limit_exceeded"
                    | "service_trigger_deadline_exceeded"
            ) {
                return Err(StartupDiffError::MalformedInput);
            }
        }
        _ => return Err(StartupDiffError::MalformedInput),
    }
    Ok(())
}

fn validate_state_evidence(value: &Value) -> Result<(), StartupDiffError> {
    keys(
        value,
        &[
            "artifact_path",
            "artifact_schema",
            "artifact_schema_version",
            "record_locator",
        ],
    )?;
    let path = text(value, "artifact_path")?;
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(StartupDiffError::MalformedInput);
    }
    for field in ["artifact_path", "artifact_schema", "record_locator"] {
        check_str(value, field, 1024)?;
        if text(value, field)?.is_empty() {
            return Err(StartupDiffError::MalformedInput);
        }
    }
    if num(value, "artifact_schema_version")? == 0 {
        return Err(StartupDiffError::MalformedInput);
    }
    Ok(())
}
fn validate_linux(v: &Value, has_states: bool) -> Result<(), StartupDiffError> {
    let x = v
        .get("xdg_autostart")
        .ok_or(StartupDiffError::MalformedInput)?;
    validate_header(
        x,
        "sideeffect.xdg_autostart_inventory",
        if has_states { 2 } else { 1 },
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
        let allowed = if has_states {
            &[
                "scope",
                "source_path",
                "applicability",
                "startup_state",
                "keys",
            ][..]
        } else {
            &["scope", "source_path", "applicability", "keys"][..]
        };
        keys(e, allowed)?;
        if has_states {
            validate_startup_state(&e["startup_state"])?;
        }
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
            for f in ["key", "value", "line_sha256"] {
                check_str(key, f, 65536)?;
            }
            check_str(key, "value_hex", MAX_STRING)?;
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
        if has_states { 2 } else { 1 },
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
        let allowed = [
            "scope",
            "source_path",
            "source_path_bytes_hex",
            "record_type",
            "symlink_target",
            "directives",
        ];
        let allowed_new = [
            "scope",
            "source_path",
            "source_path_bytes_hex",
            "record_type",
            "startup_state",
            "symlink_target",
            "directives",
        ];
        keys(r, if has_states { &allowed_new } else { &allowed })?;
        if has_states {
            validate_startup_state(&r["startup_state"])?;
        }
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
            for f in ["value", "sha256"] {
                check_str(t, f, 65536)?;
            }
            check_str(t, "value_hex", MAX_STRING)?;
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
            for f in ["section", "key", "value", "line_sha256"] {
                check_str(d, f, 65536)?;
            }
            check_str(d, "value_hex", MAX_STRING)?;
        }
    }
    let l = v
        .get("legacy_sources")
        .ok_or(StartupDiffError::MalformedInput)?;
    validate_header(
        l,
        "sideeffect.legacy_startup_inventory",
        if has_states { 2 } else { 1 },
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
        let allowed = [
            "source_kind",
            "entry_kind",
            "path",
            "path_bytes_hex",
            "symlink_target",
            "symlink_target_hex",
            "symlink_target_sha256",
            "lines",
        ];
        let allowed_new = [
            "source_kind",
            "entry_kind",
            "path",
            "path_bytes_hex",
            "startup_state",
            "symlink_target",
            "symlink_target_hex",
            "symlink_target_sha256",
            "lines",
        ];
        keys(e, if has_states { &allowed_new } else { &allowed })?;
        if has_states {
            validate_startup_state(&e["startup_state"])?;
        }
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
            for f in ["line_sha256", "raw_line"] {
                check_str(line, f, 65536)?;
            }
            check_str(line, "raw_line_hex", MAX_STRING)?;
        }
    }
    Ok(())
}
fn validate_windows(v: &Value, version: u64) -> Result<(), StartupDiffError> {
    let has_states = version >= 5;
    let has_wmi = windows_has_wmi_contract(v, version);
    let has_service_observation = version >= 7;
    let has_delayed_auto_start = version >= 8;
    let has_service_dependencies = version >= 9;
    let has_service_triggers = version >= 10;
    let mut all = vec![
        ("sources", 8192usize),
        ("registry_entries", 8192),
        ("folder_entries", 8192),
        ("service_entries", 8192),
        ("scheduled_task_entries", 8192),
        ("scheduled_task_actions", 8192),
    ];
    if has_wmi {
        all.extend([
            ("wmi_event_filters", 2048),
            ("wmi_event_consumers", 2048),
            ("wmi_filter_consumer_bindings", 2048),
        ]);
    }
    for (key, cap) in all {
        if arr(v, key)?.len() > cap {
            return Err(StartupDiffError::LimitExceeded);
        }
    }
    let mut row_fields = vec![
        "registry_entries",
        "folder_entries",
        "service_entries",
        "scheduled_task_entries",
        "scheduled_task_actions",
    ];
    if has_wmi {
        row_fields.extend([
            "wmi_event_filters",
            "wmi_event_consumers",
            "wmi_filter_consumer_bindings",
        ]);
    }
    let row_total = row_fields
        .into_iter()
        .map(|key| arr(v, key).map(<[Value]>::len))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<usize>();
    if row_total > MAX_ROWS {
        return Err(StartupDiffError::LimitExceeded);
    }
    let mut expected_sources: BTreeSet<&str> = [
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
    if has_wmi {
        expected_sources.insert("wmi_permanent_event_subscriptions");
    }
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
        startup_row_keys(
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
            has_states,
        )?;
        if has_states {
            validate_startup_state(&e["startup_state"])?;
        }
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
        startup_row_keys(
            e,
            &[
                "folder_scope",
                "trigger",
                "display_path",
                "path_utf16_hex",
                "kind",
                "evidence",
            ],
            has_states,
        )?;
        if has_states {
            validate_startup_state(&e["startup_state"])?;
        }
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
        let mut fields = vec![
            "service_name",
            "display_name",
            "start_type",
            "start_type_code",
            "account",
            "binary_path",
            "evidence",
        ];
        if has_service_observation {
            fields.push("service_observation");
        }
        if has_delayed_auto_start {
            fields.push("delayed_auto_start");
        }
        if has_service_dependencies {
            fields.extend(["dependencies", "load_order_group"]);
        }
        if has_service_triggers {
            fields.push("triggers");
        }
        startup_row_keys(e, &fields, has_states)?;
        if has_states {
            validate_startup_state(&e["startup_state"])?;
        }
        if has_service_observation {
            validate_service_observation(&e["service_observation"])?;
        }
        if has_delayed_auto_start {
            validate_delayed_auto_start(&e["delayed_auto_start"])?;
        }
        if has_service_dependencies {
            validate_service_dependencies(&e["dependencies"])?;
            validate_service_load_order_group(&e["load_order_group"])?;
        }
        if has_service_triggers {
            validate_service_triggers(&e["triggers"])?;
        }
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
        let expected_source = if has_delayed_auto_start {
            "EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W"
        } else {
            "EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW"
        };
        if text(ev, "source")? != expected_source {
            return Err(StartupDiffError::MalformedInput);
        }
        let _ = num(ev, "service_index")?;
    }
    for e in arr(v, "scheduled_task_entries")? {
        startup_row_keys(
            e,
            &[
                "task_path",
                "task_enabled",
                "trigger_type",
                "trigger_enabled",
                "logon_user",
                "evidence",
            ],
            has_states,
        )?;
        if has_states {
            validate_startup_state(&e["startup_state"])?;
        }
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
        startup_row_keys(
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
            has_states,
        )?;
        if has_states {
            validate_startup_state(&e["startup_state"])?;
        }
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
    if has_wmi {
        for (field, expected_class) in [
            ("wmi_event_filters", "__EventFilter"),
            ("wmi_event_consumers", "__EventConsumer"),
            ("wmi_filter_consumer_bindings", "__FilterToConsumerBinding"),
        ] {
            for (index, row) in arr(v, field)?.iter().enumerate() {
                let fields: &[&str] = match field {
                    "wmi_event_filters" => &[
                        "object_path",
                        "name",
                        "creator_sid",
                        "event_namespace",
                        "query_language",
                        "query",
                        "evidence",
                    ],
                    "wmi_event_consumers" => &[
                        "object_path",
                        "class_name",
                        "name",
                        "creator_sid",
                        "status",
                        "executable_path",
                        "command_line_template",
                        "script_file_name",
                        "script_text",
                        "evidence",
                        "detail_evidence",
                    ],
                    _ => &[
                        "object_path",
                        "filter_reference",
                        "consumer_reference",
                        "filter_reference_status",
                        "consumer_reference_status",
                        "creator_sid",
                        "delivery_qos",
                        "evidence",
                    ],
                };
                keys(row, fields)?;
                for name in fields
                    .iter()
                    .filter(|name| **name != "evidence" && **name != "detail_evidence")
                {
                    check_str(row, name, 32768)?;
                }
                let evidence = row
                    .get("evidence")
                    .ok_or(StartupDiffError::MalformedInput)?;
                keys(
                    evidence,
                    &["source", "namespace", "class_name", "object_index"],
                )?;
                if text(evidence, "class_name")? != expected_class
                    || text(evidence, "namespace")? != "ROOT\\subscription"
                {
                    return Err(StartupDiffError::MalformedInput);
                }
                if text(evidence, "source")? != "IWbemLocator/IWbemServices/IEnumWbemClassObject" {
                    return Err(StartupDiffError::MalformedInput);
                }
                let _ = num(evidence, "object_index")?;
                if field == "wmi_event_consumers"
                    && !matches!(
                        text(row, "status")?,
                        "observed" | "unsupported_class" | "partial"
                    )
                {
                    return Err(StartupDiffError::MalformedInput);
                }
                if field == "wmi_event_consumers" {
                    if let Some(detail) = row.get("detail_evidence") {
                        keys(
                            detail,
                            &["source", "namespace", "class_name", "object_index"],
                        )?;
                        if text(detail, "source")?
                            != "IWbemLocator/IWbemServices/IEnumWbemClassObject"
                            || text(detail, "namespace")? != "ROOT\\subscription"
                            || !matches!(
                                text(detail, "class_name")?,
                                "CommandLineEventConsumer" | "ActiveScriptEventConsumer"
                            )
                        {
                            return Err(StartupDiffError::MalformedInput);
                        }
                        let _ = num(detail, "object_index")?;
                    }
                }
                if field == "wmi_filter_consumer_bindings"
                    && (!matches!(
                        text(row, "filter_reference_status")?,
                        "resolved" | "unresolved"
                    ) || !matches!(
                        text(row, "consumer_reference_status")?,
                        "resolved" | "unresolved"
                    ))
                {
                    return Err(StartupDiffError::MalformedInput);
                }
                let _ = index;
            }
        }
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
fn startup_state_fact(row: &Value) -> String {
    let Some(state) = row.get("startup_state") else {
        // Legacy startup rows imply only that the source row was configured.
        // They provide no evidence about effectiveness or runtime observation.
        return digest(&value(&serde_json::json!({
            "configured": "present",
            "effective": {"status": "unknown", "context": null},
            "observed": {"status": "unknown"}
        })));
    };
    // These fields express the compared state. Evidence locations and capture
    // intervals stay available in the inputs but may vary between snapshots
    // without changing the state itself.
    digest(&value(&serde_json::json!({
        "configured": state["configured"],
        "effective": {
            "status": state["effective"]["status"],
            "context": state["effective"]["context"]
        },
        "observed": {"status": state["observed"]["status"]}
    })))
}
fn objfact(v: &Value, fields: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    fields
        .iter()
        .map(|(n, k)| {
            (
                *n,
                if *k == "startup_state" {
                    startup_state_fact(v)
                } else {
                    v.get(*k).map(value).unwrap_or_else(|| "null".into())
                },
            )
        })
        .collect()
}
fn side(r: &Row) -> StartupEvidenceSide {
    StartupEvidenceSide {
        references: r.refs.clone(),
    }
}
fn compare(l: &Value, r: &Value, k: Kind) -> Result<StartupInventoryDiff, StartupDiffError> {
    let service_state_incomparable = if k == Kind::Windows {
        let before_version = num(l, "schema_version")?;
        let after_version = num(r, "schema_version")?;
        let has_services =
            !arr(l, "service_entries")?.is_empty() || !arr(r, "service_entries")?.is_empty();
        has_services && (before_version >= 7) != (after_version >= 7)
    } else {
        false
    };
    let delayed_auto_start_incomparable = if k == Kind::Windows {
        let before_version = num(l, "schema_version")?;
        let after_version = num(r, "schema_version")?;
        let has_services =
            !arr(l, "service_entries")?.is_empty() || !arr(r, "service_entries")?.is_empty();
        has_services && (before_version >= 8) != (after_version >= 8)
    } else {
        false
    };
    let service_dependencies_incomparable = if k == Kind::Windows {
        let before_version = num(l, "schema_version")?;
        let after_version = num(r, "schema_version")?;
        let has_services =
            !arr(l, "service_entries")?.is_empty() || !arr(r, "service_entries")?.is_empty();
        has_services && (before_version >= 9) != (after_version >= 9)
    } else {
        false
    };
    let service_triggers_incomparable = if k == Kind::Windows {
        let before_version = num(l, "schema_version")?;
        let after_version = num(r, "schema_version")?;
        let has_services =
            !arr(l, "service_entries")?.is_empty() || !arr(r, "service_entries")?.is_empty();
        has_services && (before_version >= 10) != (after_version >= 10)
    } else {
        false
    };
    let service_dependencies_unknown = k == Kind::Windows
        && [l, r].into_iter().any(|doc| {
            num(doc, "schema_version").is_ok_and(|version| version >= 9)
                && arr(doc, "service_entries").is_ok_and(|entries| {
                    entries.iter().any(|entry| {
                        entry["dependencies"]["status"] != "observed"
                            || entry["load_order_group"]["status"] != "observed"
                    })
                })
        });
    let compare_service_dependencies = !service_dependencies_incomparable
        && !service_dependencies_unknown
        && k == Kind::Windows
        && num(l, "schema_version")? >= 9
        && num(r, "schema_version")? >= 9;
    let service_dependency_presence_comparable =
        !service_dependencies_incomparable && !service_dependencies_unknown;
    let service_triggers_unknown = k == Kind::Windows
        && [l, r].into_iter().any(|doc| {
            num(doc, "schema_version").is_ok_and(|version| version >= 10)
                && arr(doc, "service_entries").is_ok_and(|entries| {
                    entries
                        .iter()
                        .any(|entry| entry["triggers"]["status"] != "observed")
                })
        });
    let compare_service_triggers = !service_triggers_incomparable
        && !service_triggers_unknown
        && k == Kind::Windows
        && num(l, "schema_version")? >= 10
        && num(r, "schema_version")? >= 10;
    let service_trigger_presence_comparable =
        !service_triggers_incomparable && !service_triggers_unknown;
    let (mut a, mut b, mut complete, mut lossy) = if k == Kind::Linux {
        (
            linux_rows(l)?,
            linux_rows(r)?,
            linux_complete(l) && linux_complete(r),
            0usize,
        )
    } else {
        (
            windows_rows(
                l,
                !service_state_incomparable,
                !delayed_auto_start_incomparable,
                compare_service_dependencies,
                service_dependency_presence_comparable,
                compare_service_triggers,
                service_trigger_presence_comparable,
            )?,
            windows_rows(
                r,
                !service_state_incomparable,
                !delayed_auto_start_incomparable,
                compare_service_dependencies,
                service_dependency_presence_comparable,
                compare_service_triggers,
                service_trigger_presence_comparable,
            )?,
            windows_complete(l) && windows_complete(r),
            0usize,
        )
    };
    if service_state_incomparable
        || delayed_auto_start_incomparable
        || service_dependencies_incomparable
        || service_dependencies_unknown
        || service_triggers_incomparable
        || service_triggers_unknown
    {
        complete = false;
    }
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
        if service_state_incomparable {
            diagnostics.insert("service-state observations are not present on both snapshots");
        }
        if delayed_auto_start_incomparable {
            diagnostics.insert("delayed-auto-start configuration is not present on both snapshots");
        }
        if service_dependencies_incomparable {
            diagnostics.insert("service dependency configuration is not present on both snapshots");
        }
        if service_dependencies_unknown {
            diagnostics.insert("service dependency or load-order group configuration is unknown");
        }
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
            facts: vec![
                ("selected_keys", digest(&fields)),
                ("startup_state", startup_state_fact(e)),
            ],
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
            (
                "dependency_directives",
                systemd_directive_group_digest(e, SYSTEMD_DEPENDENCY_DIRECTIVES),
            ),
            (
                "ordering_directives",
                systemd_directive_group_digest(e, SYSTEMD_ORDERING_DIRECTIVES),
            ),
            ("symlink_target", digest(&value(&e["symlink_target"]))),
            ("startup_state", startup_state_fact(e)),
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
            ("startup_state", startup_state_fact(e)),
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

/// Hash only the selected systemd directive group, retaining occurrence order
/// and duplicates so repeated or empty reset assignments remain distinguishable.
/// The comparison result exposes only the static group label, never these values.
fn systemd_directive_group_digest(record: &Value, keys: &[&str]) -> String {
    let selected = record
        .get("directives")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|directive| {
            directive.get("section").and_then(Value::as_str) == Some("Unit")
                && directive
                    .get("key")
                    .and_then(Value::as_str)
                    .is_some_and(|key| keys.contains(&key))
        })
        .map(|directive| {
            serde_json::json!({
                "section": directive.get("section"),
                "key": directive.get("key"),
                "value": directive.get("value"),
                "value_hex": directive.get("value_hex"),
            })
        })
        .collect::<Vec<_>>();
    digest(&value(&serde_json::Value::Array(selected)))
}

fn linux_component_complete(v: &Value) -> bool {
    v["status"] == "complete"
}
fn windows_complete(v: &Value) -> bool {
    v["status"] == "complete"
        && v["sources"].as_array().is_some_and(|a| {
            a.len()
                == if windows_has_wmi_contract(v, num(v, "schema_version").unwrap_or(5)) {
                    13
                } else {
                    12
                }
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
fn windows_rows(
    v: &Value,
    compare_service_observation: bool,
    compare_delayed_auto_start: bool,
    compare_service_dependencies: bool,
    service_dependency_presence_comparable: bool,
    compare_service_triggers: bool,
    service_trigger_presence_comparable: bool,
) -> Result<Vec<Row>, StartupDiffError> {
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
                    ("startup_state", "startup_state"),
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
            facts: objfact(e, &[("kind", "kind"), ("startup_state", "startup_state")]),
            refs: vec![ptr("/folder_entries", i)],
            complete: source_complete(v, id),
            lossy_identity: false,
        });
    }
    for (i, e) in arr(v, "service_entries")?.iter().enumerate() {
        let key = text(e, "service_name")?.to_owned();
        let id = "service_start_configuration";
        let mut facts = objfact(
            e,
            &[
                ("display_name", "display_name"),
                ("start_type", "start_type"),
                ("start_type_code", "start_type_code"),
                ("account", "account"),
                ("binary_path", "binary_path"),
                ("startup_state", "startup_state"),
            ],
        );
        if compare_service_observation && num(v, "schema_version")? >= 7 {
            facts.push(("service_observation", value(&e["service_observation"])));
        }
        if compare_delayed_auto_start
            && num(v, "schema_version")? >= 8
            && e["delayed_auto_start"]["status"] == "observed"
        {
            facts.push((
                "delayed_auto_start",
                value(&e["delayed_auto_start"]["value"]),
            ));
        }
        if compare_service_dependencies
            && num(v, "schema_version")? >= 9
            && e["dependencies"]["status"] == "observed"
            && e["load_order_group"]["status"] == "observed"
        {
            facts.push(("dependencies", value(&e["dependencies"]["entries"])));
            facts.push(("load_order_group", value(&e["load_order_group"]["value"])));
        }
        if compare_service_triggers
            && num(v, "schema_version")? >= 10
            && e["triggers"]["status"] == "observed"
        {
            facts.push(("triggers", value(&e["triggers"]["entries"])));
        }
        rows.push(Row {
            category: "service_configuration",
            key,
            facts,
            refs: vec![ptr("/service_entries", i)],
            complete: source_complete(v, id)
                && service_dependency_presence_comparable
                && service_trigger_presence_comparable,
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
                    ("startup_state", "startup_state"),
                ],
            ),
            refs: vec![ptr("/scheduled_task_entries", i)],
            complete: source_complete(v, id),
            lossy_identity: false,
        });
    }
    if windows_has_wmi_contract(v, num(v, "schema_version").unwrap_or(5)) {
        for (i, e) in arr(v, "wmi_event_filters")?.iter().enumerate() {
            rows.push(Row {
                category: "wmi_event_filter",
                key: text(e, "object_path")?.to_owned(),
                facts: objfact(
                    e,
                    &[
                        ("name", "name"),
                        ("creator_sid", "creator_sid"),
                        ("event_namespace", "event_namespace"),
                        ("query_language", "query_language"),
                        ("query", "query"),
                    ],
                ),
                refs: vec![ptr("/wmi_event_filters", i)],
                complete: source_complete(v, "wmi_permanent_event_subscriptions"),
                lossy_identity: false,
            });
        }
        for (i, e) in arr(v, "wmi_event_consumers")?.iter().enumerate() {
            rows.push(Row {
                category: "wmi_event_consumer",
                key: text(e, "object_path")?.to_owned(),
                facts: objfact(
                    e,
                    &[
                        ("class_name", "class_name"),
                        ("name", "name"),
                        ("creator_sid", "creator_sid"),
                        ("status", "status"),
                        ("executable_path", "executable_path"),
                        ("command_line_template", "command_line_template"),
                        ("script_file_name", "script_file_name"),
                        ("script_text", "script_text"),
                    ],
                ),
                refs: vec![ptr("/wmi_event_consumers", i)],
                complete: source_complete(v, "wmi_permanent_event_subscriptions")
                    && e["status"] == "observed",
                lossy_identity: false,
            });
        }
        for (i, e) in arr(v, "wmi_filter_consumer_bindings")?.iter().enumerate() {
            rows.push(Row {
                category: "wmi_filter_consumer_binding",
                key: text(e, "object_path")?.to_owned(),
                facts: objfact(
                    e,
                    &[
                        ("filter_reference", "filter_reference"),
                        ("consumer_reference", "consumer_reference"),
                        ("filter_reference_status", "filter_reference_status"),
                        ("consumer_reference_status", "consumer_reference_status"),
                        ("creator_sid", "creator_sid"),
                        ("delivery_qos", "delivery_qos"),
                    ],
                ),
                refs: vec![ptr("/wmi_filter_consumer_bindings", i)],
                complete: source_complete(v, "wmi_permanent_event_subscriptions")
                    && e["filter_reference_status"] == "resolved"
                    && e["consumer_reference_status"] == "resolved",
                lossy_identity: false,
            });
        }
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
                        "startup_state",
                    ]
                    .iter()
                    .map(|k| {
                        if *k == "startup_state" {
                            Value::String(startup_state_fact(e))
                        } else {
                            e[*k].clone()
                        }
                    })
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

    fn startup_state() -> Value {
        json!({
            "schema_version": 1,
            "configured": "present",
            "effective": {"status":"unknown", "context":null, "evidence":null},
            "observed": {"status":"unknown", "capture_interval":null, "evidence":null}
        })
    }

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

    fn linux_v3() -> Value {
        let mut value = linux();
        value["schema_version"] = json!(3);
        value["xdg_autostart"]["schema_version"] = json!(2);
        value["systemd_units"]["schema_version"] = json!(2);
        value["legacy_sources"]["schema_version"] = json!(2);
        value
    }

    fn systemd_directive(key: &str, value: &str, line: usize) -> Value {
        json!({
            "section":"Unit",
            "key":key,
            "value":value,
            "value_hex":null,
            "line":line,
            "byte_offset":line * 8,
            "byte_length":value.len(),
            "line_sha256":format!("line-{line}")
        })
    }

    fn systemd_record(directives: Vec<Value>, has_state: bool) -> Value {
        let mut record = json!({
            "scope":"system",
            "source_path":"/etc/systemd/system/example.service",
            "source_path_bytes_hex":"2f6574632f73797374656d642f73797374656d2f6578616d706c652e73657276696365",
            "record_type":"unit_file",
            "symlink_target":null,
            "directives":directives
        });
        if has_state {
            record["startup_state"] = startup_state();
        }
        record
    }

    fn compare_systemd_records(
        before_record: Value,
        after_record: Value,
        before_partial: bool,
        after_v3: bool,
    ) -> StartupInventoryDiff {
        let mut before = linux();
        before["systemd_units"]["records"] = json!([before_record]);
        if before_partial {
            before["status"] = json!("partial");
            before["systemd_units"]["status"] = json!("partial");
        }
        let mut after = if after_v3 { linux_v3() } else { linux() };
        after["systemd_units"]["records"] = json!([after_record]);
        compare_startup_inventory_json(&bytes(&before), &bytes(&after)).unwrap()
    }

    #[test]
    fn systemd_requirement_directive_changes_use_static_dependency_label_only() {
        let diff = compare_systemd_records(
            systemd_record(
                vec![systemd_directive("Requires", "alpha.service", 1)],
                false,
            ),
            systemd_record(
                vec![systemd_directive("Requires", "beta.service", 1)],
                false,
            ),
            false,
            false,
        );
        assert_eq!(diff.deltas.len(), 1);
        assert_eq!(
            diff.deltas[0].changed_fields,
            ["directives", "dependency_directives"]
        );
        let output = serde_json::to_string(&diff).unwrap();
        assert!(!output.contains("alpha.service"));
        assert!(!output.contains("beta.service"));
    }

    #[test]
    fn systemd_ordering_changes_are_separate_from_requirement_changes() {
        let diff = compare_systemd_records(
            systemd_record(vec![systemd_directive("After", "alpha.service", 1)], false),
            systemd_record(vec![systemd_directive("Before", "alpha.service", 1)], false),
            false,
            false,
        );
        assert_eq!(diff.deltas.len(), 1);
        assert_eq!(
            diff.deltas[0].changed_fields,
            ["directives", "ordering_directives"]
        );
        assert!(
            !diff.deltas[0]
                .changed_fields
                .contains(&"dependency_directives")
        );
    }

    #[test]
    fn unrelated_or_non_unit_directives_keep_only_the_general_label() {
        let diff = compare_systemd_records(
            systemd_record(vec![systemd_directive("Description", "first", 1)], false),
            systemd_record(vec![systemd_directive("Description", "second", 1)], false),
            false,
            false,
        );
        assert_eq!(diff.deltas.len(), 1);
        assert_eq!(diff.deltas[0].changed_fields, ["directives"]);

        let mut invalid_section = systemd_directive("After", "alpha.service", 1);
        invalid_section["section"] = json!("Service");
        let mut other_invalid_section = invalid_section.clone();
        other_invalid_section["value"] = json!("beta.service");
        let diff = compare_systemd_records(
            systemd_record(vec![invalid_section], false),
            systemd_record(vec![other_invalid_section], false),
            false,
            false,
        );
        assert_eq!(diff.deltas.len(), 1);
        assert_eq!(diff.deltas[0].changed_fields, ["directives"]);
    }

    #[test]
    fn systemd_duplicate_and_empty_reset_lines_are_compared_as_source_facts() {
        let before = systemd_record(
            vec![
                systemd_directive("Requires", "alpha.service", 1),
                systemd_directive("Requires", "beta.service", 2),
            ],
            false,
        );
        let same = compare_systemd_records(before.clone(), before.clone(), false, false);
        assert_eq!(same.counts.changed, 0);

        let reset = compare_systemd_records(
            before,
            systemd_record(
                vec![
                    systemd_directive("Requires", "alpha.service", 1),
                    systemd_directive("Requires", "", 2),
                ],
                false,
            ),
            false,
            false,
        );
        assert_eq!(reset.deltas.len(), 1);
        assert!(
            reset.deltas[0]
                .changed_fields
                .contains(&"dependency_directives")
        );
        let output = serde_json::to_string(&reset).unwrap();
        assert!(!output.contains("alpha.service"));
        assert!(!output.contains("beta.service"));
    }

    #[test]
    fn systemd_relationship_change_remains_partial_or_compatible_across_versions() {
        let before = systemd_record(vec![systemd_directive("Wants", "alpha.service", 1)], false);
        let after = systemd_record(vec![systemd_directive("Wants", "beta.service", 1)], true);

        let partial = compare_systemd_records(before.clone(), after.clone(), true, true);
        assert_eq!(partial.status, StartupDiffStatus::Partial);
        assert!(
            partial.deltas[0]
                .changed_fields
                .contains(&"dependency_directives")
        );

        let mixed_versions = compare_systemd_records(before, after, false, true);
        assert_eq!(mixed_versions.status, StartupDiffStatus::Complete);
        assert!(
            mixed_versions.deltas[0]
                .changed_fields
                .contains(&"dependency_directives")
        );
    }

    fn windows_v5() -> Value {
        let mut value = windows();
        value["schema_version"] = json!(5);
        value
    }

    fn windows_v6() -> Value {
        let mut value = windows_v5();
        value["schema_version"] = json!(6);
        value["scope"] = json!(
            "current_user_and_accessible_machine_run_keys_startup_folders_services_current_token_visible_tasks_and_local_root_subscription_wmi_objects"
        );
        value["sources"].as_array_mut().unwrap().push(json!({"id":"wmi_permanent_event_subscriptions","status":"complete","entries_seen":0,"location_path":"ROOT\\subscription","diagnostics":[]}));
        value["wmi_event_filters"] = json!([]);
        value["wmi_event_consumers"] = json!([]);
        value["wmi_filter_consumer_bindings"] = json!([]);
        value
    }

    fn windows_v7() -> Value {
        let mut value = windows_v5();
        value["schema_version"] = json!(7);
        for service in value["service_entries"].as_array_mut().unwrap() {
            service["service_observation"] = json!({
                "status":"known", "state":"running", "raw_state_code":4
            });
        }
        value
    }

    fn windows_v8() -> Value {
        let mut value = windows_v7();
        value["schema_version"] = json!(8);
        value["scope"] = json!(
            "current_user_and_accessible_machine_run_keys_startup_folders_services_with_delayed_auto_start_configuration_and_current_token_visible_tasks_and_local_root_subscription_wmi_objects"
        );
        value["sources"].as_array_mut().unwrap().push(json!({"id":"wmi_permanent_event_subscriptions","status":"complete","entries_seen":0,"location_path":"ROOT\\subscription","diagnostics":[]}));
        value["wmi_event_filters"] = json!([]);
        value["wmi_event_consumers"] = json!([]);
        value["wmi_filter_consumer_bindings"] = json!([]);
        value
    }

    fn windows_v9() -> Value {
        let mut value = windows_v8();
        value["schema_version"] = json!(9);
        value["scope"] = json!(
            "current_user_and_accessible_machine_run_keys_startup_folders_services_with_delayed_auto_start_dependencies_and_load_order_group_configuration_and_current_token_visible_tasks_and_local_root_subscription_wmi_objects"
        );
        value
    }

    fn windows_v10() -> Value {
        let mut value = windows_v9();
        value["schema_version"] = json!(10);
        value["scope"] = json!(
            "current_user_and_accessible_machine_run_keys_startup_folders_services_with_delayed_auto_start_dependencies_load_order_group_and_trigger_configuration_and_current_token_visible_tasks_and_local_root_subscription_wmi_objects"
        );
        for service in value["service_entries"].as_array_mut().unwrap() {
            service["triggers"] = json!({"status":"observed","entries":[]});
        }
        value
    }

    #[test]
    fn windows_v10_compares_observed_service_triggers_and_suppresses_unknowns() {
        let mut before = windows_v10();
        let mut after = windows_v10();
        let trigger = json!({
            "trigger_index":0,
            "trigger_type_code":1,
            "trigger_type":"device_interface_arrival",
            "action_code":1,
            "action":"service_start",
            "subtype_guid":"1234abcd-5678-9abc-def0-123456789abc",
            "data_items":[{"data_type_code":2,"data_type":"string","data_hex":"414200"}]
        });
        before["service_entries"] = json!([{
            "service_name":"EditorService","display_name":"Editor Service","start_type":"automatic","start_type_code":2,
            "account":null,"binary_path":"C:\\Apps\\editor.exe","startup_state":startup_state(),
            "service_observation":{"status":"known","state":"running","raw_state_code":4},
            "delayed_auto_start":{"status":"observed","value":false},
            "dependencies":{"status":"observed","entries":[]},
            "load_order_group":{"status":"observed","value":null},
            "triggers":{"status":"observed","entries":[]},
            "evidence":{"source":"EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W","service_index":0}
        }]);
        after["service_entries"] = before["service_entries"].clone();
        after["service_entries"][0]["triggers"]["entries"] = json!([trigger]);
        let report = compare_startup_inventory_json(
            &serde_json::to_vec(&before).unwrap(),
            &serde_json::to_vec(&after).unwrap(),
        )
        .unwrap();
        assert_eq!(report.status, StartupDiffStatus::Complete);
        assert_eq!(report.deltas.len(), 1);
        assert!(report.deltas[0].changed_fields.contains(&"triggers"));
        assert_eq!(
            report.deltas[0].before.as_ref().unwrap().references,
            ["/service_entries/0"]
        );

        after["service_entries"][0]["triggers"] = json!({
            "status":"unknown","diagnostic_code":"service_trigger_access_denied"
        });
        let unknown = compare_startup_inventory_json(
            &serde_json::to_vec(&before).unwrap(),
            &serde_json::to_vec(&after).unwrap(),
        )
        .unwrap();
        assert_eq!(unknown.status, StartupDiffStatus::Partial);
        assert!(unknown.deltas.is_empty());
    }

    #[test]
    fn startup_state_contract_requires_direct_evidence_for_known_dimensions() {
        let state = startup_state();
        validate_startup_state(&state).unwrap();

        let mut effective_without_context = state.clone();
        effective_without_context["effective"]["status"] = json!("effective");
        assert!(validate_startup_state(&effective_without_context).is_err());

        let mut observed_without_interval = state;
        observed_without_interval["observed"]["status"] = json!("observed");
        assert!(validate_startup_state(&observed_without_interval).is_err());
    }

    #[test]
    fn legacy_and_stateful_startup_versions_compare_without_rewriting_inputs() {
        let linux_old = serde_json::to_vec(&linux()).unwrap();
        let linux_new = serde_json::to_vec(&linux_v3()).unwrap();
        assert_eq!(
            compare_startup_inventory_json(&linux_old, &linux_new)
                .unwrap()
                .status,
            StartupDiffStatus::Complete
        );

        let windows_old = serde_json::to_vec(&windows()).unwrap();
        let windows_new = serde_json::to_vec(&windows_v5()).unwrap();
        assert_eq!(
            compare_startup_inventory_json(&windows_old, &windows_new)
                .unwrap()
                .status,
            StartupDiffStatus::Complete
        );
    }

    #[test]
    fn windows_v6_accepts_wmi_scope_and_keeps_legacy_readers() {
        let old = serde_json::to_vec(&windows_v5()).unwrap();
        let current = windows_v6();
        let encoded = serde_json::to_vec(&current).unwrap();
        validate(&parse(&encoded).unwrap(), Kind::Windows).unwrap();
        let report = compare_startup_inventory_json(&old, &encoded).unwrap();
        assert_eq!(report.platform, "windows");

        let filter = json!({
            "object_path":"__EventFilter.Name=\"f\"",
            "name":"f",
            "creator_sid":null,
            "event_namespace":null,
            "query_language":"WQL",
            "query":"SELECT * FROM __InstanceCreationEvent",
            "evidence":{"source":"IWbemLocator/IWbemServices/IEnumWbemClassObject","namespace":"ROOT\\subscription","class_name":"__EventFilter","object_index":0}
        });
        current_filter_smoke(filter);
    }

    #[test]
    fn windows_v7_compares_only_service_state_snapshot_changes() {
        let mut before = windows_v7();
        let mut after = windows_v7();
        let service = |observation: Value| {
            json!({
                "service_name":"EditorService",
                "display_name":"Editor Service",
                "start_type":"SERVICE_AUTO_START",
                "start_type_code":2,
                "account":"LocalSystem",
                "binary_path":"C:\\Tools\\editor.exe --service",
            "startup_state":startup_state(),
                "service_observation":observation,
                "evidence":{"source":"EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW","service_index":0}
            })
        };
        before["service_entries"] = json!([service(json!({
            "status":"known", "state":"stopped", "raw_state_code":1
        }))]);
        after["service_entries"] = json!([service(json!({
            "status":"known", "state":"running", "raw_state_code":4
        }))]);

        let report = compare_startup_inventory_json(&bytes(&before), &bytes(&after)).unwrap();
        assert_eq!(report.status, StartupDiffStatus::Complete);
        assert_eq!(report.counts.changed, 1);
        assert_eq!(report.deltas[0].changed_fields, ["service_observation"]);
    }

    #[test]
    fn windows_v7_preserves_unknown_service_state_codes_and_rejects_guesses() {
        let mut snapshot = windows_v7();
        snapshot["service_entries"] = json!([{
            "service_name":"EditorService",
            "display_name":"Editor Service",
            "start_type":"SERVICE_AUTO_START",
            "start_type_code":2,
            "account":"LocalSystem",
            "binary_path":"C:\\Tools\\editor.exe --service",
            "startup_state":startup_state(),
            "service_observation":{"status":"unknown","raw_state_code":4294967295_u64},
            "evidence":{"source":"EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW","service_index":0}
        }]);
        validate(&snapshot, Kind::Windows).unwrap();
        snapshot["service_entries"][0]["service_observation"] = json!({
            "status":"known", "state":"running", "raw_state_code":0
        });
        assert!(validate(&snapshot, Kind::Windows).is_err());
    }

    #[test]
    fn windows_v8_compares_observed_delayed_auto_start_and_ignores_unknown_values() {
        let mut before = windows_v8();
        let mut after = windows_v8();
        let service = |delayed_auto_start: Value| {
            json!({
                "service_name":"EditorService",
                "display_name":"Editor Service",
                "start_type":"SERVICE_AUTO_START",
                "start_type_code":2,
                "account":"LocalSystem",
                "binary_path":"C:\\Tools\\editor.exe --service",
                "startup_state":startup_state(),
                "service_observation":{"status":"known","state":"running","raw_state_code":4},
                "delayed_auto_start":delayed_auto_start,
                "evidence":{"source":"EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W","service_index":0}
            })
        };
        before["service_entries"] = json!([service(json!({"status":"observed","value":false}))]);
        after["service_entries"] = json!([service(json!({"status":"observed","value":true}))]);
        validate(&before, Kind::Windows).unwrap();
        validate(&after, Kind::Windows).unwrap();
        let report = compare_startup_inventory_json(&bytes(&before), &bytes(&after)).unwrap();
        assert_eq!(report.counts.changed, 1);
        assert_eq!(report.deltas[0].changed_fields, ["delayed_auto_start"]);

        after["service_entries"][0]["delayed_auto_start"] = json!({
            "status":"unknown","diagnostic_code":"service_delayed_auto_start_access_denied"
        });
        after["service_entries"][0]["service_observation"] =
            before["service_entries"][0]["service_observation"].clone();
        after["sources"][10]["status"] = json!("partial");
        after["sources"][10]["diagnostics"] =
            json!([{"code":"service_delayed_auto_start_access_denied"}]);
        after["status"] = json!("partial");
        let report = compare_startup_inventory_json(&bytes(&before), &bytes(&after)).unwrap();
        assert_eq!(report.status, StartupDiffStatus::Partial);
        assert!(report.deltas.is_empty());
    }

    #[test]
    fn mixed_windows_v7_v8_service_snapshots_do_not_compare_delayed_auto_start() {
        let mut before = windows_v7();
        let mut after = windows_v8();
        let mut service = json!({
            "service_name":"EditorService",
            "display_name":"Editor Service",
            "start_type":"SERVICE_AUTO_START",
            "start_type_code":2,
            "account":"LocalSystem",
            "binary_path":"C:\\Tools\\editor.exe --service",
            "startup_state":startup_state(),
            "service_observation":{"status":"known","state":"running","raw_state_code":4},
            "evidence":{"source":"EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW","service_index":0}
        });
        before["service_entries"] = json!([service.clone()]);
        service["delayed_auto_start"] = json!({"status":"observed","value":true});
        service["evidence"]["source"] =
            json!("EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W");
        after["service_entries"] = json!([service]);
        validate(&before, Kind::Windows).unwrap();
        validate(&after, Kind::Windows).unwrap();
        let report = compare_startup_inventory_json(&bytes(&before), &bytes(&after)).unwrap();
        assert_eq!(report.status, StartupDiffStatus::Partial);
        assert!(report.deltas.is_empty());
        assert!(report.diagnostics.iter().any(|diagnostic| {
            *diagnostic == "delayed-auto-start configuration is not present on both snapshots"
        }));
    }

    #[test]
    fn windows_v9_compares_only_observed_dependency_and_load_order_group_configuration() {
        let service = |dependencies: Value, group: Value| {
            json!({
                "service_name":"ExampleSvc",
                "display_name":"Example service",
                "start_type":"automatic",
                "start_type_code":2,
                "account":"LocalSystem",
                "binary_path":"C:\\Example\\svc.exe",
                "startup_state":startup_state(),
                "service_observation":{"status":"known","state":"stopped","raw_state_code":1},
                "delayed_auto_start":{"status":"observed","value":false},
                "dependencies":dependencies,
                "load_order_group":group,
                "evidence":{"source":"EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W","service_index":0}
            })
        };
        let mut before = windows_v9();
        let mut after = windows_v9();
        before["service_entries"] = json!([service(
            json!({"status":"observed","entries":[{"kind":"service","name":"BaseSvc"}]}),
            json!({"status":"observed","value":null})
        )]);
        after["service_entries"] = json!([service(
            json!({"status":"observed","entries":[{"kind":"load_order_group","name":"CoreGroup"}]}),
            json!({"status":"observed","value":"NetworkGroup"})
        )]);
        validate_service_dependencies(&before["service_entries"][0]["dependencies"]).unwrap();
        validate_service_load_order_group(&before["service_entries"][0]["load_order_group"])
            .unwrap();
        validate_service_observation(&before["service_entries"][0]["service_observation"]).unwrap();
        validate_delayed_auto_start(&before["service_entries"][0]["delayed_auto_start"]).unwrap();
        validate_startup_state(&before["service_entries"][0]["startup_state"]).unwrap();
        for field in [
            "service_name",
            "display_name",
            "start_type",
            "account",
            "binary_path",
        ] {
            check_str(&before["service_entries"][0], field, 131072).unwrap();
        }
        startup_row_keys(
            &before["service_entries"][0],
            &[
                "service_name",
                "display_name",
                "start_type",
                "start_type_code",
                "account",
                "binary_path",
                "evidence",
                "service_observation",
                "delayed_auto_start",
                "dependencies",
                "load_order_group",
            ],
            true,
        )
        .unwrap();
        let service_evidence = &before["service_entries"][0]["evidence"];
        keys(service_evidence, &["source", "service_index"]).unwrap();
        check_str(service_evidence, "source", 256).unwrap();
        assert_eq!(
            text(service_evidence, "source").unwrap(),
            "EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W"
        );
        assert_eq!(num(service_evidence, "service_index").unwrap(), 0);
        let mut no_services = before.clone();
        no_services["service_entries"] = json!([]);
        validate(&parse(&bytes(&no_services)).unwrap(), Kind::Windows).unwrap();
        validate(&parse(&bytes(&before)).unwrap(), Kind::Windows).unwrap();
        validate(&parse(&bytes(&after)).unwrap(), Kind::Windows).unwrap();
        let report = compare_startup_inventory_json(&bytes(&before), &bytes(&after)).unwrap();
        assert_eq!(report.status, StartupDiffStatus::Complete);
        assert_eq!(report.deltas.len(), 1);
        assert!(report.deltas[0].changed_fields.contains(&"dependencies"));
        assert!(
            report.deltas[0]
                .changed_fields
                .contains(&"load_order_group")
        );
    }

    #[test]
    fn windows_v9_unknown_and_mixed_schema_facts_suppress_service_presence_claims() {
        let service = |dependency_status: Value| {
            json!({
                "service_name":"ExampleSvc",
                "display_name":"Example service",
                "start_type":"automatic",
                "start_type_code":2,
                "account":"LocalSystem",
                "binary_path":"C:\\Example\\svc.exe",
                "startup_state":startup_state(),
                "service_observation":{"status":"known","state":"stopped","raw_state_code":1},
                "delayed_auto_start":{"status":"observed","value":false},
                "dependencies":dependency_status,
                "load_order_group":{"status":"observed","value":null},
                "evidence":{"source":"EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W","service_index":0}
            })
        };
        let mut unknown_before = windows_v9();
        let mut unknown_after = windows_v9();
        unknown_before["service_entries"] = json!([service(json!({
            "status":"unknown","diagnostic_code":"service_dependencies_response_invalid"
        }))]);
        unknown_after["service_entries"] = json!([]);
        validate(&parse(&bytes(&unknown_before)).unwrap(), Kind::Windows).unwrap();
        validate(&parse(&bytes(&unknown_after)).unwrap(), Kind::Windows).unwrap();
        let unknown =
            compare_startup_inventory_json(&bytes(&unknown_before), &bytes(&unknown_after))
                .unwrap();
        assert_eq!(unknown.status, StartupDiffStatus::Partial);
        assert!(unknown.deltas.is_empty());
        assert_eq!(
            unknown
                .counts
                .unmatched_rows_suppressed_for_incomplete_source,
            1
        );

        let mut v8 = windows_v8();
        v8["service_entries"] = json!([{
            "service_name":"ExampleSvc",
            "display_name":"Example service",
            "start_type":"automatic",
            "start_type_code":2,
            "account":"LocalSystem",
            "binary_path":"C:\\Example\\svc.exe",
            "startup_state":startup_state(),
            "service_observation":{"status":"known","state":"stopped","raw_state_code":1},
            "delayed_auto_start":{"status":"observed","value":false},
            "evidence":{"source":"EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W","service_index":0}
        }]);
        let mixed = compare_startup_inventory_json(&bytes(&v8), &bytes(&unknown_after)).unwrap();
        assert_eq!(mixed.status, StartupDiffStatus::Partial);
        assert!(mixed.deltas.is_empty());
        assert_eq!(
            mixed.counts.unmatched_rows_suppressed_for_incomplete_source,
            1
        );
    }

    #[test]
    fn windows_v9_rejects_invalid_dependency_kind_and_untrusted_group_marker() {
        let mut invalid = windows_v9();
        invalid["service_entries"] = json!([{
            "service_name":"ExampleSvc",
            "display_name":"Example service",
            "start_type":"automatic",
            "start_type_code":2,
            "account":null,
            "binary_path":null,
            "startup_state":startup_state(),
            "service_observation":{"status":"known","state":"stopped","raw_state_code":1},
            "delayed_auto_start":{"status":"observed","value":false},
            "dependencies":{"status":"observed","entries":[{"kind":"command","name":"<script>"}]},
            "load_order_group":{"status":"observed","value":null},
            "evidence":{"source":"EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W","service_index":0}
        }]);
        assert_eq!(
            validate(&parse(&bytes(&invalid)).unwrap(), Kind::Windows),
            Err(StartupDiffError::MalformedInput)
        );
        invalid["service_entries"][0]["dependencies"]["entries"][0]["kind"] = json!("service");
        invalid["service_entries"][0]["dependencies"]["entries"][0]["name"] = json!("+Group");
        assert_eq!(
            validate(&parse(&bytes(&invalid)).unwrap(), Kind::Windows),
            Err(StartupDiffError::MalformedInput)
        );
    }

    #[test]
    fn windows_v9_allows_historical_optional_wmi_absence_with_its_exact_scope() {
        let mut value = windows_v9();
        value["scope"] = json!(
            "current_user_and_accessible_machine_run_keys_startup_folders_services_with_delayed_auto_start_dependencies_and_load_order_group_configuration_and_current_token_visible_tasks"
        );
        for field in [
            "wmi_event_filters",
            "wmi_event_consumers",
            "wmi_filter_consumer_bindings",
        ] {
            value.as_object_mut().unwrap().remove(field);
        }
        value["sources"]
            .as_array_mut()
            .unwrap()
            .retain(|source| source["id"] != "wmi_permanent_event_subscriptions");
        validate(&parse(&bytes(&value)).unwrap(), Kind::Windows).unwrap();
    }

    #[test]
    fn mixed_v6_v7_service_snapshots_do_not_compare_missing_service_state() {
        let mut before = windows_v6();
        let mut after = windows_v7();
        let common = json!({
            "service_name":"EditorService",
            "display_name":"Editor Service",
            "start_type":"SERVICE_AUTO_START",
            "start_type_code":2,
            "account":"LocalSystem",
            "binary_path":"C:\\Tools\\editor.exe --service",
            "startup_state":startup_state(),
            "evidence":{"source":"EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW","service_index":0}
        });
        before["service_entries"] = json!([common.clone()]);
        let mut service = common;
        service["service_observation"] = json!({
            "status":"known", "state":"running", "raw_state_code":4
        });
        after["service_entries"] = json!([service]);
        let report = compare_startup_inventory_json(&bytes(&before), &bytes(&after)).unwrap();
        assert_eq!(report.status, StartupDiffStatus::Partial);
        assert!(report.deltas.is_empty());
        assert!(report.diagnostics.iter().any(|diagnostic| {
            *diagnostic == "service-state observations are not present on both snapshots"
        }));
    }

    fn current_filter_smoke(filter: Value) {
        let mut value = windows_v6();
        value["wmi_event_filters"] = json!([filter]);
        value["sources"][12]["entries_seen"] = json!(1);
        let encoded = serde_json::to_vec(&value).unwrap();
        validate(&parse(&encoded).unwrap(), Kind::Windows).unwrap();
        let report = compare_startup_inventory_json(&encoded, &encoded).unwrap();
        assert!(report.deltas.is_empty());
    }

    #[test]
    fn linux_v2_v3_mixed_rows_ignore_default_state_but_compare_source_facts() {
        let mut old = linux();
        let mut current = linux_v3();
        let entry = |command: &str| {
            json!({
                "scope":"user",
                "source_path":"/home/u/.config/autostart/editor.desktop",
                "applicability":"not_evaluated",
                "keys":[{"key":"Exec","value":command,"value_hex":null,"line":3,"byte_offset":24,"byte_length":command.len(),"line_sha256":"fixture-line-hash"}]
            })
        };
        old["xdg_autostart"]["entries"] = json!([entry("editor --open")]);
        let mut current_entry = entry("editor --open");
        current_entry["startup_state"] = startup_state();
        current["xdg_autostart"]["entries"] = json!([current_entry]);

        let unchanged = compare_startup_inventory_json(&bytes(&old), &bytes(&current)).unwrap();
        assert_eq!(unchanged.counts.changed, 0);
        assert!(unchanged.deltas.is_empty());

        current["xdg_autostart"]["entries"][0]["keys"][0]["value"] = json!("editor --safe-mode");
        let changed = compare_startup_inventory_json(&bytes(&old), &bytes(&current)).unwrap();
        assert_eq!(changed.counts.changed, 1);
        assert_eq!(changed.deltas[0].changed_fields, ["selected_keys"]);
    }

    #[test]
    fn windows_v4_v5_mixed_rows_ignore_default_state_but_compare_source_facts() {
        let mut old = windows();
        let mut current = windows_v5();
        let service = |binary_path: &str| {
            json!({
                "service_name":"EditorService",
                "display_name":"Editor Service",
                "start_type":"SERVICE_AUTO_START",
                "start_type_code":2,
                "account":"LocalSystem",
                "binary_path":binary_path,
                "evidence":{"source":"EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW","service_index":0}
            })
        };
        old["service_entries"] = json!([service("C:\\Tools\\editor.exe --service")]);
        let mut current_service = service("C:\\Tools\\editor.exe --service");
        current_service["startup_state"] = startup_state();
        current["service_entries"] = json!([current_service]);

        let unchanged = compare_startup_inventory_json(&bytes(&old), &bytes(&current)).unwrap();
        assert_eq!(unchanged.counts.changed, 0);
        assert!(unchanged.deltas.is_empty());

        current["service_entries"][0]["binary_path"] = json!("C:\\Tools\\editor.exe --safe-mode");
        let changed = compare_startup_inventory_json(&bytes(&old), &bytes(&current)).unwrap();
        assert_eq!(changed.counts.changed, 1);
        assert_eq!(changed.deltas[0].changed_fields, ["binary_path"]);
    }

    #[test]
    fn startup_state_compares_meaning_while_retaining_evidence_metadata() {
        let mut before = linux_v3();
        let mut after = linux_v3();
        let entry = json!({
            "scope":"user",
            "source_path":"/home/u/.config/autostart/editor.desktop",
            "applicability":"not_evaluated",
            "keys":[{"key":"Exec","value":"editor","value_hex":null,"line":3,"byte_offset":24,"byte_length":6,"line_sha256":"fixture-line-hash"}],
            "startup_state": {
                "schema_version":1,
                "configured":"present",
                "effective":{
                    "status":"effective",
                    "context":"user-session",
                    "evidence":{"artifact_path":"context.json","artifact_schema":"sideeffect.context","artifact_schema_version":1,"record_locator":"/context/0"}
                },
                "observed":{
                    "status":"observed",
                    "capture_interval":{"started_at_unix_ms":10,"ended_at_unix_ms":20},
                    "evidence":{"artifact_path":"runtime.json","artifact_schema":"sideeffect.runtime","artifact_schema_version":1,"record_locator":"/events/0"}
                }
            }
        });
        before["xdg_autostart"]["entries"] = json!([entry]);
        after["xdg_autostart"]["entries"] = json!([entry]);
        after["xdg_autostart"]["entries"][0]["startup_state"]["effective"]["evidence"]["artifact_path"] =
            json!("context-after.json");
        after["xdg_autostart"]["entries"][0]["startup_state"]["effective"]["evidence"]["record_locator"] =
            json!("/context/1");
        after["xdg_autostart"]["entries"][0]["startup_state"]["observed"]["capture_interval"] =
            json!({"started_at_unix_ms":30,"ended_at_unix_ms":40});
        after["xdg_autostart"]["entries"][0]["startup_state"]["observed"]["evidence"]["record_locator"] =
            json!("/events/7");

        let unchanged = compare_startup_inventory_json(&bytes(&before), &bytes(&after)).unwrap();
        assert_eq!(unchanged.counts.changed, 0);
        assert!(unchanged.deltas.is_empty());

        after["xdg_autostart"]["entries"][0]["startup_state"]["effective"]["status"] =
            json!("not_effective");
        let changed = compare_startup_inventory_json(&bytes(&before), &bytes(&after)).unwrap();
        assert_eq!(changed.counts.changed, 1);
        assert_eq!(changed.deltas[0].changed_fields, ["startup_state"]);

        after["xdg_autostart"]["entries"][0]["startup_state"]["effective"]["status"] =
            json!("effective");
        after["xdg_autostart"]["entries"][0]["startup_state"]["effective"]["context"] =
            json!("system-session");
        let changed = compare_startup_inventory_json(&bytes(&before), &bytes(&after)).unwrap();
        assert_eq!(changed.counts.changed, 1);
        assert_eq!(changed.deltas[0].changed_fields, ["startup_state"]);
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

    #[test]
    fn producer_maximum_hex_encoded_line_facts_are_accepted() {
        let long_hex = "ab".repeat(64 * 1024);
        let mut v = linux();
        v["xdg_autostart"]["entries"] = json!([{
            "scope":"user","source_path":"/u/a.desktop","applicability":"not_evaluated",
            "keys":[{"key":"Exec","value":null,"value_hex":long_hex,"line":1,
                "byte_offset":0,"byte_length":65536,"line_sha256":"hash"}]
        }]);
        v["systemd_units"]["records"] = json!([{
            "scope":"system","source_path":"/etc/systemd/system/a.service",
            "source_path_bytes_hex":"2f657463","record_type":"unit_file","symlink_target":null,
            "directives":[{"section":"Service","key":"ExecStart","value":null,
                "value_hex":long_hex,"line":1,"byte_offset":0,"byte_length":65536,
                "line_sha256":"hash"}]
        }]);
        v["legacy_sources"]["entries"] = json!([{
            "source_kind":"sysv_init_scripts","entry_kind":"inert_file",
            "path":"/etc/init.d/a","path_bytes_hex":"2f657463",
            "lines":[{"line_number":1,"byte_offset":0,"byte_length":65536,
                "line_sha256":"hash","raw_line":null,"raw_line_hex":long_hex}]
        }]);
        let encoded = bytes(&v);
        let diff = compare_startup_inventory_json(&encoded, &encoded).unwrap();
        assert_eq!(diff.status, StartupDiffStatus::Complete);
        assert_eq!(diff.counts.changed, 0);
    }

    #[test]
    fn producer_bounded_linux_directory_diagnostics_are_accepted() {
        let diagnostics = (0..300)
            .map(|_| {
                json!({
                    "code":"directory_entry_unreadable",
                    "path":null,
                    "line":null,
                    "byte_offset":null
                })
            })
            .collect::<Vec<_>>();
        let mut snapshot = linux();
        snapshot["status"] = json!("partial");
        snapshot["xdg_autostart"]["status"] = json!("partial");
        snapshot["xdg_autostart"]["directories"] = json!([{
            "scope":"user",
            "path":"/home/user/.config/autostart",
            "status":"partial",
            "files_seen":0,
            "diagnostics":diagnostics
        }]);

        let encoded = bytes(&snapshot);
        let diff = compare_startup_inventory_json(&encoded, &encoded).unwrap();
        assert_eq!(diff.status, StartupDiffStatus::Partial);
        assert_eq!(diff.counts.changed, 0);
    }
}
