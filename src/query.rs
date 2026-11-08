//! Bounded, read-only exact filters over the versioned common event envelope.
//!
//! Query results preserve source status, diagnostics, event evidence, and the
//! source-local process links needed to inspect the selected rows. Path filtering
//! is exact over an optional source-derived lexical/name observation only.

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::marker::PhantomData;
use std::time::{Duration, Instant};

use crate::audit_session::{
    ArtifactKind, AuditSessionManifest, AuditSessionSource, CollectorIdentity, LossMetadata,
    SessionArtifactRef, SessionStatus, SourceRole, SourceStatus,
};
use crate::event::{
    CommonEvent, CommonEventEnvelope, EventDiagnostic, EventProcessLink, OperationSemantics,
    ProcessObservation, ProcessRelationship, SourceCompleteness, SourceDescriptor, SourceState,
};
use crate::model::SyscallOutcome;

pub const QUERY_SCHEMA: &str = "sideeffect.event_query";
pub const QUERY_SCHEMA_VERSION: u32 = 3;
pub const QUERY_RESULT_SCHEMA: &str = "sideeffect.event_query_result";
pub const QUERY_RESULT_SCHEMA_VERSION: u32 = 3;
pub const SESSION_QUERY_RESULT_SCHEMA: &str = "sideeffect.session_event_query_result";
pub const SESSION_QUERY_RESULT_SCHEMA_VERSION: u32 = 3;
pub const MULTI_SESSION_QUERY_RESULT_SCHEMA: &str = "sideeffect.multi_session_event_query_result";
pub const MULTI_SESSION_QUERY_RESULT_SCHEMA_VERSION: u32 = 3;
pub const MAX_QUERY_SESSIONS: usize = 16;
pub const MAX_MULTI_SESSION_RESULTS: usize = MAX_QUERY_RESULTS;
pub const MAX_MULTI_SESSION_INPUT_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_MULTI_SESSION_ELAPSED: Duration = Duration::from_secs(10);
pub const MAX_QUERY_BYTES: usize = 16 * 1024;
pub const MAX_PATH_FILTER_BYTES: usize = 8 * 1024;
pub const MAX_QUERY_RESULTS: usize = 5_000;
pub const MAX_QUERY_ELAPSED: Duration = Duration::from_secs(2);
pub const MAX_QUERY_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub const INVENTORY_QUERY_SCHEMA: &str = "sideeffect.inventory_query";
pub const INVENTORY_QUERY_SCHEMA_VERSION: u32 = 1;
pub const INVENTORY_QUERY_RESULT_SCHEMA: &str = "sideeffect.inventory_query_result";
pub const INVENTORY_QUERY_RESULT_SCHEMA_VERSION: u32 = 1;
pub const MAX_ROOT_QUERY_ENTRIES: usize = 10_000;
pub const MAX_ROOT_QUERY_AGGREGATE_NAME_BYTES: usize = 8 * 1024 * 1024;
pub const STARTUP_QUERY_SCHEMA: &str = "sideeffect.startup_query";
pub const STARTUP_QUERY_SCHEMA_VERSION: u32 = 1;
pub const STARTUP_QUERY_RESULT_SCHEMA: &str = "sideeffect.startup_query_result";
pub const STARTUP_QUERY_RESULT_SCHEMA_VERSION: u32 = 1;
pub const PACKAGE_QUERY_SCHEMA: &str = "sideeffect.package_query";
pub const PACKAGE_QUERY_SCHEMA_VERSION: u32 = 1;
pub const PACKAGE_QUERY_RESULT_SCHEMA: &str = "sideeffect.package_query_result";
pub const PACKAGE_QUERY_RESULT_SCHEMA_VERSION: u32 = 1;
pub const PROCESS_QUERY_SCHEMA: &str = "sideeffect.process_query";
pub const PROCESS_QUERY_SCHEMA_VERSION: u32 = 1;
pub const PROCESS_QUERY_RESULT_SCHEMA: &str = "sideeffect.process_query_result";
pub const PROCESS_QUERY_RESULT_SCHEMA_VERSION: u32 = 1;
pub const MAX_STARTUP_QUERY_ROWS: usize = 20_000;
pub const MAX_STARTUP_QUERY_STRING_BYTES: usize = 16 * 1024;
pub const MAX_PACKAGE_QUERY_ROWS: usize = 200_000;
pub const MAX_LINUX_PACKAGE_QUERY_DIAGNOSTICS: usize = 200_000;
pub const MAX_WINDOWS_SOFTWARE_SOURCE_DIAGNOSTICS: usize = 65_536;
pub const MAX_WINDOWS_SOFTWARE_QUERY_DIAGNOSTICS: usize = 262_144;
pub const MAX_PACKAGE_QUERY_STRING_BYTES: usize = 16 * 1024;
const MAX_FILTER_TEXT_BYTES: usize = 128;

/// Exact, case-sensitive equality over a string field in one native startup row.
/// `source` and `field` are names from that platform's startup artifact; they are
/// intentionally not mapped to a cross-platform identity.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupQueryFilters {
    pub source: Option<String>,
    pub field: Option<String>,
    pub value: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupQuery {
    pub schema: String,
    pub schema_version: u32,
    #[serde(default)]
    pub filters: StartupQueryFilters,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl StartupQuery {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_QUERY_BYTES {
            return Err(format!(
                "startup query input exceeds the {MAX_QUERY_BYTES}-byte limit"
            ));
        }
        let query: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid startup query JSON: {error}"))?;
        if query.schema != STARTUP_QUERY_SCHEMA
            || query.schema_version != STARTUP_QUERY_SCHEMA_VERSION
        {
            return Err(format!(
                "startup query schema must be {STARTUP_QUERY_SCHEMA} version {STARTUP_QUERY_SCHEMA_VERSION}"
            ));
        }
        if query.limit == 0 || query.limit as usize > MAX_QUERY_RESULTS {
            return Err(format!(
                "startup query limit must be between 1 and {MAX_QUERY_RESULTS}"
            ));
        }
        for (label, value) in [
            ("source", query.filters.source.as_deref()),
            ("field", query.filters.field.as_deref()),
            ("value", query.filters.value.as_deref()),
        ] {
            if value.is_some_and(|value| {
                value.is_empty() || value.len() > MAX_STARTUP_QUERY_STRING_BYTES
            }) {
                return Err(format!(
                    "startup query {label} must be non-empty and at most {MAX_STARTUP_QUERY_STRING_BYTES} UTF-8 bytes"
                ));
            }
        }
        if query.filters.field.is_some() != query.filters.value.is_some() {
            return Err(
                "startup query field and value filters must be supplied together".to_owned(),
            );
        }
        Ok(query)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct StartupQueryArtifact {
    pub path: String,
    pub schema: String,
    pub schema_version: u32,
    pub byte_length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct StartupQueryRow {
    pub source: String,
    pub json_pointer: String,
    pub evidence: serde_json::Value,
    pub row: serde_json::Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct StartupQuerySource {
    pub role: SourceRole,
    pub platform: String,
    pub status: SourceStatus,
    pub scope: Option<String>,
    pub started_at_unix_ms: Option<u128>,
    pub ended_at_unix_ms: Option<u128>,
    pub diagnostic_codes: Vec<String>,
    pub inventory_status: Option<String>,
    pub inventory_diagnostics: Vec<serde_json::Value>,
    pub source_states: Vec<serde_json::Value>,
    pub artifact: Option<StartupQueryArtifact>,
    pub matched_count: usize,
    pub rows: Vec<StartupQueryRow>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionStartupQueryResult {
    pub session: SessionQueryIdentity,
    pub startup_source: StartupQuerySource,
}

#[derive(Clone, Debug, Serialize)]
pub struct MultiSessionStartupQueryResult {
    pub schema: &'static str,
    pub schema_version: u32,
    pub session_count: usize,
    pub matched_count: usize,
    pub complete: bool,
    pub filter: StartupQueryFilters,
    pub limit: u32,
    pub sessions: Vec<SessionStartupQueryResult>,
}

pub struct StartupQueryInput<'a> {
    pub platform: &'a str,
    pub source_status: SourceStatus,
    pub scope: Option<String>,
    pub started_at_unix_ms: Option<u128>,
    pub ended_at_unix_ms: Option<u128>,
    pub diagnostic_codes: Vec<String>,
    pub artifact: Option<&'a SessionArtifactRef>,
    pub bytes: Option<&'a [u8]>,
}

fn required_json_object<'a>(
    parent: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, String> {
    parent
        .get(key)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| format!("startup artifact component {key} is missing or malformed"))
}

fn required_json_array<'a>(
    parent: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a Vec<serde_json::Value>, String> {
    parent
        .get(key)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("startup artifact collection {key} is missing or malformed"))
}

/// Query exact string fields from native startup-inventory rows. Rows and JSON
/// pointers stay in the artifact's source schema; no OS identity is inferred.
pub fn query_startup_artifact(
    input: StartupQueryInput<'_>,
    query: &StartupQuery,
) -> Result<StartupQuerySource, String> {
    use serde_json::Value;
    use std::time::Instant;
    let started = Instant::now();
    let StartupQueryInput {
        platform,
        source_status,
        scope,
        started_at_unix_ms,
        ended_at_unix_ms,
        diagnostic_codes,
        artifact,
        bytes,
    } = input;
    if let Some(artifact) = artifact {
        let (schema, path, version_ok) = match platform {
            "linux" => (
                "sideeffect.startup_inventory",
                "startup.json",
                (2..=3).contains(&artifact.schema_version),
            ),
            "windows" => (
                "sideeffect.windows_startup_inventory",
                "startup.windows.json",
                (4..=10).contains(&artifact.schema_version),
            ),
            _ => return Err("startup query session platform is unsupported".to_owned()),
        };
        let bytes =
            bytes.ok_or_else(|| "startup verified artifact bytes are unavailable".to_owned())?;
        if artifact.kind
            != if platform == "windows" {
                ArtifactKind::WindowsStartup
            } else {
                ArtifactKind::Startup
            }
            || artifact.schema != schema
            || artifact.path != path
            || !version_ok
            || bytes.len() as u64 != artifact.byte_length
            || bytes.len() > crate::audit_session::MAX_SESSION_ARTIFACT_BYTES as usize
        {
            return Err(
                "startup artifact contract or verified bytes do not match the session manifest"
                    .to_owned(),
            );
        }
        let document: Value = serde_json::from_slice(bytes)
            .map_err(|_| "startup artifact is malformed JSON".to_owned())?;
        let object = document
            .as_object()
            .ok_or_else(|| "startup artifact root must be an object".to_owned())?;
        let allowed_root: &[&str] = if platform == "linux" {
            &[
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
            ]
        } else {
            &[
                "schema",
                "schema_version",
                "platform",
                "scope",
                "capture_started_at_unix_ms",
                "capture_ended_at_unix_ms",
                "status",
                "sources",
                "registry_entries",
                "folder_entries",
                "service_entries",
                "scheduled_task_entries",
                "scheduled_task_actions",
                "wmi_event_filters",
                "wmi_event_consumers",
                "wmi_filter_consumer_bindings",
            ]
        };
        if object
            .keys()
            .any(|key| !allowed_root.contains(&key.as_str()))
        {
            return Err("startup artifact contains unsupported top-level fields".to_owned());
        }
        if object.get("schema").and_then(Value::as_str) != Some(schema)
            || object.get("schema_version").and_then(Value::as_u64)
                != Some(artifact.schema_version as u64)
            || object.get("platform").and_then(Value::as_str) != Some(platform)
        {
            return Err(
                "startup artifact header does not match its verified native contract".to_owned(),
            );
        }
        let artifact_scope = object
            .get("scope")
            .and_then(Value::as_str)
            .filter(|scope| !scope.is_empty())
            .ok_or_else(|| "startup artifact scope is missing or malformed".to_owned())?;
        let capture_started = object
            .get("capture_started_at_unix_ms")
            .and_then(Value::as_u64)
            .ok_or_else(|| "startup artifact start timestamp is missing or malformed".to_owned())?;
        let capture_ended = object
            .get("capture_ended_at_unix_ms")
            .and_then(Value::as_u64)
            .filter(|ended| *ended >= capture_started)
            .ok_or_else(|| "startup artifact end timestamp is missing or malformed".to_owned())?;
        let _ = (artifact_scope, capture_ended);
        let status = object
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| "startup artifact status is missing".to_owned())?;
        if !matches!(status, "complete" | "partial") {
            return Err("startup artifact status is unsupported".to_owned());
        }
        let mut inventory_diagnostics = Vec::new();
        let mut source_states = Vec::new();
        let mut diagnostic_count = 0usize;
        let mut collect_diagnostics = |owner: &Value| -> Result<(), String> {
            let diagnostics = owner
                .get("diagnostics")
                .and_then(Value::as_array)
                .ok_or_else(|| "startup artifact diagnostics collection is malformed".to_owned())?;
            diagnostic_count = diagnostic_count
                .checked_add(diagnostics.len())
                .ok_or_else(|| "startup artifact diagnostic count overflow".to_owned())?;
            if diagnostic_count > 2048 {
                return Err(
                    "startup artifact diagnostics exceed the 2048-row query limit".to_owned(),
                );
            }
            inventory_diagnostics.extend(diagnostics.iter().cloned());
            Ok(())
        };
        if platform == "windows" {
            let sources = required_json_array(object, "sources")?;
            if sources.len() > 256 {
                return Err("startup artifact source count exceeds its limit".to_owned());
            }
            for source in sources {
                let source_status = source.get("status").and_then(Value::as_str);
                if source.get("id").and_then(Value::as_str).is_none()
                    || source.get("entries_seen").and_then(Value::as_u64).is_none()
                    || source_status.is_none_or(|status| {
                        !matches!(
                            status,
                            "complete"
                                | "partial"
                                | "not_present"
                                | "inaccessible"
                                | "unavailable"
                                | "unsupported"
                                | "not_checked"
                                | "error"
                        )
                    })
                {
                    return Err("startup artifact source status row is malformed".to_owned());
                }
                if status == "complete" && source_status != Some("complete") {
                    return Err(
                        "complete startup artifact contains an incomplete source status".to_owned(),
                    );
                }
                collect_diagnostics(source)?;
                source_states.push(source.clone());
            }
            for key in [
                "registry_entries",
                "folder_entries",
                "service_entries",
                "scheduled_task_entries",
                "scheduled_task_actions",
            ] {
                required_json_array(object, key)?;
            }
            for key in [
                "wmi_event_filters",
                "wmi_event_consumers",
                "wmi_filter_consumer_bindings",
            ] {
                let present = object.get(key).is_some();
                if (artifact.schema_version >= 6) != present
                    || object.get(key).is_some_and(|value| !value.is_array())
                {
                    return Err(format!(
                        "startup artifact collection {key} is missing or malformed for its schema version"
                    ));
                }
            }
        } else {
            let xdg = required_json_object(object, "xdg_autostart")?;
            let systemd = required_json_object(object, "systemd_units")?;
            let legacy = required_json_object(object, "legacy_sources")?;
            let component_version = artifact.schema_version - 1;
            for (component, component_schema) in [
                (xdg, "sideeffect.xdg_autostart_inventory"),
                (systemd, "sideeffect.systemd_units"),
                (legacy, "sideeffect.legacy_startup_inventory"),
            ] {
                if component.get("schema").and_then(Value::as_str) != Some(component_schema)
                    || component.get("schema_version").and_then(Value::as_u64)
                        != Some(component_version as u64)
                    || component.get("platform").and_then(Value::as_str) != Some("linux")
                    || !matches!(
                        component.get("status").and_then(Value::as_str),
                        Some("complete" | "partial")
                    )
                {
                    return Err(
                        "startup artifact nested component header or status is malformed"
                            .to_owned(),
                    );
                }
            }
            if status == "complete"
                && [xdg, systemd, legacy].iter().any(|component| {
                    component.get("status").and_then(Value::as_str) != Some("complete")
                })
            {
                return Err(
                    "complete startup artifact contains an incomplete component status".to_owned(),
                );
            }
            required_json_array(xdg, "entries")?;
            required_json_array(systemd, "records")?;
            required_json_array(legacy, "entries")?;
            let xdg_directories = required_json_array(xdg, "directories")?;
            let systemd_directories = required_json_array(systemd, "directories")?;
            let legacy_sources = required_json_array(legacy, "sources")?;
            for (rows, label) in [
                (xdg_directories, "XDG"),
                (systemd_directories, "systemd"),
                (legacy_sources, "legacy"),
            ] {
                if rows.len() > 256 {
                    return Err(format!(
                        "startup artifact {label} source status count exceeds its limit"
                    ));
                }
                for row in rows {
                    if !row.is_object() {
                        return Err(format!(
                            "startup artifact {label} source status row is malformed"
                        ));
                    }
                    collect_diagnostics(row)?;
                    source_states.push(row.clone());
                }
            }
        }
        let mut rows = Vec::new();
        let row_arrays: &[&str] = if platform == "linux" {
            &[
                "xdg_autostart/entries",
                "systemd_units/records",
                "legacy_sources/entries",
            ]
        } else {
            &[
                "registry_entries",
                "folder_entries",
                "service_entries",
                "scheduled_task_entries",
                "scheduled_task_actions",
                "wmi_event_filters",
                "wmi_event_consumers",
                "wmi_filter_consumer_bindings",
            ]
        };
        let mut seen = 0usize;
        for key in row_arrays {
            let (array_name, parent) = if let Some((parent, name)) = key.split_once('/') {
                (name, object.get(parent).and_then(Value::as_object))
            } else {
                (*key, Some(object))
            };
            let Some(parent) = parent else { continue };
            let Some(value) = parent.get(array_name) else {
                continue;
            };
            let array = value
                .as_array()
                .ok_or_else(|| "startup artifact row collection is malformed".to_owned())?;
            for (index, row) in array.iter().enumerate() {
                seen += 1;
                if seen > MAX_STARTUP_QUERY_ROWS {
                    return Err("startup artifact exceeds the 20000-row query limit".to_owned());
                }
                if started.elapsed() > MAX_QUERY_ELAPSED {
                    return Err("startup query exceeded the 2000 ms execution limit".to_owned());
                }
                let row_object = row
                    .as_object()
                    .ok_or_else(|| "startup artifact contains a non-object row".to_owned())?;
                let evidence = row_object.get("evidence").cloned().unwrap_or(Value::Null);
                let component_name = key
                    .split_once('/')
                    .map_or(array_name, |(component, _)| component);
                let row_source = row_object
                    .get("evidence")
                    .and_then(|v| v.get("source"))
                    .and_then(Value::as_str)
                    .or_else(|| row_object.get("source").and_then(Value::as_str))
                    .unwrap_or(component_name);
                let source_match = query.filters.source.as_deref().is_none_or(|filter| {
                    filter == row_source || filter == array_name || filter == component_name
                });
                let field_match = match (
                    query.filters.field.as_deref(),
                    query.filters.value.as_deref(),
                ) {
                    (Some(field), Some(value)) => {
                        row_object.get(field).and_then(Value::as_str) == Some(value)
                    }
                    _ => true,
                };
                if source_match && field_match {
                    if rows.len() >= query.limit as usize {
                        return Err(format!(
                            "startup query matched more than its {}-row limit",
                            query.limit
                        ));
                    }
                    let pointer = if key.contains('/') {
                        format!(
                            "/{}",
                            key.split('/')
                                .map(|part| part.replace('~', "~0").replace('/', "~1"))
                                .collect::<Vec<_>>()
                                .join("/")
                                + &format!("/{index}")
                        )
                    } else {
                        format!(
                            "/{}/{index}",
                            array_name.replace('~', "~0").replace('/', "~1")
                        )
                    };
                    if document.pointer(&pointer) != Some(row) {
                        return Err("startup row evidence pointer did not resolve to its verified artifact row".to_owned());
                    }
                    rows.push(StartupQueryRow {
                        source: row_source.to_owned(),
                        json_pointer: pointer,
                        evidence,
                        row: row.clone(),
                    });
                }
            }
        }
        let matched_count = rows.len();
        Ok(StartupQuerySource {
            role: SourceRole::Startup,
            platform: platform.to_owned(),
            status: source_status,
            scope,
            started_at_unix_ms,
            ended_at_unix_ms,
            diagnostic_codes,
            inventory_status: Some(status.to_owned()),
            inventory_diagnostics,
            source_states,
            artifact: Some(StartupQueryArtifact {
                path: artifact.path.clone(),
                schema: artifact.schema.clone(),
                schema_version: artifact.schema_version,
                byte_length: artifact.byte_length,
                sha256: artifact.sha256.clone(),
            }),
            matched_count,
            rows,
        })
    } else {
        if bytes.is_some() {
            return Err("startup artifact bytes have no manifest reference".to_owned());
        }
        Ok(StartupQuerySource {
            role: SourceRole::Startup,
            platform: platform.to_owned(),
            status: source_status,
            scope,
            started_at_unix_ms,
            ended_at_unix_ms,
            diagnostic_codes,
            inventory_status: None,
            inventory_diagnostics: Vec::new(),
            source_states: Vec::new(),
            artifact: None,
            matched_count: 0,
            rows: Vec::new(),
        })
    }
}

pub fn multi_session_startup_query_result(
    sessions: Vec<SessionStartupQueryResult>,
    query: &StartupQuery,
) -> Result<MultiSessionStartupQueryResult, String> {
    if !(1..=MAX_QUERY_SESSIONS).contains(&sessions.len()) {
        return Err(format!(
            "startup query requires 1..={MAX_QUERY_SESSIONS} sessions"
        ));
    }
    let mut ids = HashSet::new();
    let mut matched_count = 0usize;
    for session in &sessions {
        if !ids.insert(session.session.session_id.as_str()) {
            return Err("startup query contains duplicate session IDs".to_owned());
        }
        matched_count = matched_count
            .checked_add(session.startup_source.matched_count)
            .ok_or_else(|| "startup query result count overflow".to_owned())?;
        if matched_count > MAX_MULTI_SESSION_RESULTS {
            return Err("startup query exceeds its 5000-row aggregate limit".to_owned());
        }
    }
    let complete = sessions.iter().all(|s| {
        s.session.status == SessionStatus::Complete
            && s.startup_source.status == SourceStatus::Complete
            && s.startup_source.inventory_status.as_deref() == Some("complete")
    });
    Ok(MultiSessionStartupQueryResult {
        schema: STARTUP_QUERY_RESULT_SCHEMA,
        schema_version: STARTUP_QUERY_RESULT_SCHEMA_VERSION,
        session_count: sessions.len(),
        matched_count,
        complete,
        filter: query.filters.clone(),
        limit: query.limit,
        sessions,
    })
}

/// A strict exact query over package rows retained in verified audit sessions.
/// `source` is the Linux package-manager source ID or Windows registry source ID;
/// the other filters name the native row fields without normalization.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageQueryFilters {
    pub source: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub publisher: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageQuery {
    pub schema: String,
    pub schema_version: u32,
    #[serde(default)]
    pub filters: PackageQueryFilters,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl PackageQuery {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_QUERY_BYTES {
            return Err(format!(
                "package query input exceeds the {MAX_QUERY_BYTES}-byte limit"
            ));
        }
        let query: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid package query JSON: {error}"))?;
        if query.schema != PACKAGE_QUERY_SCHEMA
            || query.schema_version != PACKAGE_QUERY_SCHEMA_VERSION
        {
            return Err(format!(
                "package query schema must be {PACKAGE_QUERY_SCHEMA} version {PACKAGE_QUERY_SCHEMA_VERSION}"
            ));
        }
        if query.limit == 0 || query.limit as usize > MAX_QUERY_RESULTS {
            return Err(format!(
                "package query limit must be between 1 and {MAX_QUERY_RESULTS}"
            ));
        }
        for (label, value) in [
            ("source", query.filters.source.as_deref()),
            ("name", query.filters.name.as_deref()),
            ("version", query.filters.version.as_deref()),
            ("publisher", query.filters.publisher.as_deref()),
        ] {
            if value.is_some_and(|value| {
                value.is_empty() || value.len() > MAX_PACKAGE_QUERY_STRING_BYTES
            }) {
                return Err(format!(
                    "package query {label} must be non-empty and at most {MAX_PACKAGE_QUERY_STRING_BYTES} UTF-8 bytes"
                ));
            }
        }
        Ok(query)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PackageQueryArtifact {
    pub path: String,
    pub schema: String,
    pub schema_version: u32,
    pub byte_length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackageQueryRow {
    pub source: String,
    pub json_pointer: String,
    pub evidence: serde_json::Value,
    pub row: serde_json::Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackageQuerySource {
    pub role: SourceRole,
    pub platform: String,
    pub status: SourceStatus,
    pub scope: Option<String>,
    pub started_at_unix_ms: Option<u128>,
    pub ended_at_unix_ms: Option<u128>,
    pub diagnostic_codes: Vec<String>,
    pub inventory_status: Option<String>,
    pub inventory_diagnostics: Vec<serde_json::Value>,
    pub source_states: Vec<serde_json::Value>,
    pub artifact: Option<PackageQueryArtifact>,
    pub matched_count: usize,
    pub rows: Vec<PackageQueryRow>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionPackageQueryResult {
    pub session: SessionQueryIdentity,
    pub package_source: PackageQuerySource,
}

#[derive(Clone, Debug, Serialize)]
pub struct MultiSessionPackageQueryResult {
    pub schema: &'static str,
    pub schema_version: u32,
    pub session_count: usize,
    pub matched_count: usize,
    pub complete: bool,
    pub filter: PackageQueryFilters,
    pub limit: u32,
    pub sessions: Vec<SessionPackageQueryResult>,
}

pub struct PackageQueryInput<'a> {
    pub platform: &'a str,
    pub source_status: SourceStatus,
    pub scope: Option<String>,
    pub started_at_unix_ms: Option<u128>,
    pub ended_at_unix_ms: Option<u128>,
    pub diagnostic_codes: Vec<String>,
    pub artifact: Option<&'a SessionArtifactRef>,
    pub bytes: Option<&'a [u8]>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxPackageDocument {
    schema: String,
    schema_version: u32,
    platform: String,
    scope: String,
    captured_at_unix_ms: u128,
    status: LinuxPackageInventoryStatus,
    sources: BoundedSequence<LinuxPackageSource, 16>,
    packages: BoundedSequence<LinuxPackageRow, MAX_PACKAGE_QUERY_ROWS>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
enum LinuxPackageInventoryStatus {
    Complete,
    Partial,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxPackageSource {
    id: String,
    status: LinuxPackageSourceStatus,
    exit_code: Option<i32>,
    records_seen: usize,
    diagnostics: BoundedSequence<LinuxPackageDiagnostic, MAX_LINUX_PACKAGE_QUERY_DIAGNOSTICS>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum LinuxPackageSourceStatus {
    Complete,
    Partial,
    NotChecked,
    Unsupported,
    NotApplicable,
    Unavailable,
    AccessDenied,
    Failed,
    TimedOut,
    OutputLimitExceeded,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxPackageDiagnostic {
    code: String,
    line: Option<usize>,
    byte_offset: Option<usize>,
    byte_length: Option<usize>,
    record_sha256: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxPackageRow {
    source_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_abbrev: Option<String>,
    evidence: LinuxPackageEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxPackageEvidence {
    line: usize,
    byte_offset: usize,
    byte_length: usize,
    record_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_record: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_record_hex: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsSoftwareDocument {
    schema: String,
    schema_version: u32,
    platform: String,
    scope: String,
    capture_started_at_unix_ms: u128,
    capture_ended_at_unix_ms: u128,
    status: WindowsSoftwareStatus,
    sources: BoundedSequence<WindowsSoftwareSource, 4>,
    registrations: BoundedSequence<WindowsSoftwareRegistration, 8_192>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum WindowsSoftwareStatus {
    Complete,
    Partial,
    NotPresent,
    Inaccessible,
    Error,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsSoftwareSource {
    id: String,
    status: WindowsSoftwareStatus,
    registrations_seen: usize,
    hive: String,
    registry_key: String,
    registry_view: WindowsRegistryView,
    diagnostics:
        BoundedSequence<WindowsSoftwareDiagnostic, MAX_WINDOWS_SOFTWARE_SOURCE_DIAGNOSTICS>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
enum WindowsRegistryView {
    Native,
    Wow64_32,
    Wow64_64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsSoftwareDiagnostic {
    code: String,
    registration_index: Option<usize>,
    value_name: Option<String>,
    message: String,
    win32_error: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsSoftwareRegistration {
    registry_subkey: String,
    registry_subkey_utf16_hex: String,
    display_name: Option<String>,
    values: BoundedSequence<WindowsSoftwareValue, 8>,
    evidence: WindowsSoftwareEvidence,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsSoftwareValue {
    name: String,
    registry_type: u32,
    type_name: String,
    text: Option<String>,
    raw_data_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsSoftwareEvidence {
    source: String,
    hive: String,
    registry_view: WindowsRegistryView,
    registry_key: String,
    registration_index: usize,
    registry_subkey: String,
}

/// Query rows from a source artifact whose bytes were already verified by the
/// platform audit-session reader. Every input document is strictly validated,
/// including rows that do not match the requested filters.
pub fn query_package_artifact(
    input: PackageQueryInput<'_>,
    query: &PackageQuery,
) -> Result<PackageQuerySource, String> {
    let PackageQueryInput {
        platform,
        source_status,
        scope,
        started_at_unix_ms,
        ended_at_unix_ms,
        diagnostic_codes,
        artifact,
        bytes,
    } = input;
    if !matches!(platform, "linux" | "windows") {
        return Err("package query session platform is unsupported".to_owned());
    }
    if platform == "linux" && query.filters.publisher.is_some() {
        return Err("package publisher filter is not supported for Linux package rows".to_owned());
    }
    let Some(artifact) = artifact else {
        if bytes.is_some() {
            return Err("package artifact bytes have no manifest reference".to_owned());
        }
        return Ok(PackageQuerySource {
            role: SourceRole::Packages,
            platform: platform.to_owned(),
            status: source_status,
            scope,
            started_at_unix_ms,
            ended_at_unix_ms,
            diagnostic_codes,
            inventory_status: None,
            inventory_diagnostics: Vec::new(),
            source_states: Vec::new(),
            artifact: None,
            matched_count: 0,
            rows: Vec::new(),
        });
    };
    let bytes =
        bytes.ok_or_else(|| "verified package artifact bytes are unavailable".to_owned())?;
    if bytes.len() as u64 != artifact.byte_length
        || bytes.len() > crate::audit_session::MAX_SESSION_ARTIFACT_BYTES as usize
    {
        return Err("package artifact bytes do not match the verified manifest length".to_owned());
    }
    let mut rows = Vec::new();
    let mut inventory_diagnostics = Vec::new();
    let mut source_states = Vec::new();
    let inventory_status = match platform {
        "linux" => {
            if artifact.kind != ArtifactKind::Packages
                || artifact.schema != "sideeffect.inventory"
                || artifact.schema_version != 2
                || artifact.path != "packages.json"
            {
                return Err(
                    "Linux package artifact contract does not match its session manifest"
                        .to_owned(),
                );
            }
            let document: LinuxPackageDocument = serde_json::from_slice(bytes).map_err(|_| {
                "Linux package artifact is malformed or has unsupported fields".to_owned()
            })?;
            if document.schema != "sideeffect.inventory"
                || document.schema_version != 2
                || document.platform != "linux"
                || document.scope.is_empty()
            {
                return Err("Linux package artifact header is malformed".to_owned());
            }
            let mut source_map = std::collections::HashMap::new();
            let mut diag_count = 0usize;
            for source in &document.sources.0 {
                if !matches!(
                    source.id.as_str(),
                    "dpkg_query"
                        | "rpm_query"
                        | "pacman_query"
                        | "apk_info"
                        | "flatpak"
                        | "xbps_query"
                        | "nix"
                        | "guix"
                        | "snap"
                ) || source.records_seen > MAX_PACKAGE_QUERY_ROWS
                    || source_map
                        .insert(source.id.as_str(), source.status)
                        .is_some()
                {
                    return Err(
                        "Linux package artifact contains invalid or duplicate source IDs"
                            .to_owned(),
                    );
                }
                if document.status == LinuxPackageInventoryStatus::Complete
                    && !matches!(
                        source.status,
                        LinuxPackageSourceStatus::Complete
                            | LinuxPackageSourceStatus::NotApplicable
                    )
                {
                    return Err(
                        "complete Linux package artifact contains an incomplete source".to_owned(),
                    );
                }
                diag_count = diag_count
                    .checked_add(source.diagnostics.0.len())
                    .ok_or_else(|| "package diagnostic count overflow".to_owned())?;
                if diag_count > MAX_LINUX_PACKAGE_QUERY_DIAGNOSTICS {
                    return Err(
                        "Linux package artifact diagnostics exceed their query limit".to_owned(),
                    );
                }
                inventory_diagnostics.extend(
                    source
                        .diagnostics
                        .0
                        .iter()
                        .map(serde_json::to_value)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| "could not serialize package diagnostic".to_owned())?,
                );
                source_states.push(
                    serde_json::to_value(source)
                        .map_err(|_| "could not serialize package source state".to_owned())?,
                );
            }
            let mut row_counts = std::collections::HashMap::<&str, usize>::new();
            for (index, row) in document.packages.0.iter().enumerate() {
                let source_status = source_map
                    .get(row.source_id.as_str())
                    .ok_or_else(|| "Linux package row refers to an unknown source".to_owned())?;
                let ev = &row.evidence;
                *row_counts.entry(row.source_id.as_str()).or_default() += 1;
                let evidence_bytes = ev
                    .raw_record
                    .as_ref()
                    .map(|raw| raw.as_bytes().to_vec())
                    .or_else(|| ev.raw_record_hex.as_deref().and_then(decode_lower_hex));
                if ev.line == 0
                    || ev.byte_length == 0
                    || ev.byte_offset.saturating_add(ev.byte_length)
                        > crate::limits::MAX_INVENTORY_STDOUT_BYTES
                    || ev.line > MAX_PACKAGE_QUERY_ROWS
                    || ev.byte_offset.checked_add(ev.byte_length).is_none()
                    || ev.record_sha256.len() != 64
                    || !ev
                        .record_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || ev.raw_record_hex.as_ref().is_some_and(|hex| {
                        hex.is_empty()
                            || hex.len() % 2 != 0
                            || hex.len() > 2 * crate::limits::MAX_INVENTORY_ROW_BYTES
                            || !hex
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                    || ev
                        .raw_record
                        .as_ref()
                        .is_some_and(|raw| raw.len() > crate::limits::MAX_INVENTORY_ROW_BYTES)
                    || (ev.raw_record.is_some() == ev.raw_record_hex.is_some())
                    || evidence_bytes.as_ref().is_some_and(|raw| {
                        raw.len() != ev.byte_length
                            || crate::fingerprint::sha256_hex(raw) != ev.record_sha256
                    })
                    || (*source_status != LinuxPackageSourceStatus::Complete
                        && *source_status != LinuxPackageSourceStatus::Partial)
                {
                    return Err(
                        "Linux package row evidence or source status is malformed".to_owned()
                    );
                }
                if query
                    .filters
                    .source
                    .as_deref()
                    .is_none_or(|value| value == row.source_id)
                    && query
                        .filters
                        .name
                        .as_deref()
                        .is_none_or(|value| row.name.as_deref() == Some(value))
                    && query
                        .filters
                        .version
                        .as_deref()
                        .is_none_or(|value| row.version.as_deref() == Some(value))
                {
                    if rows.len() >= query.limit as usize {
                        return Err(
                            "package query matched more than its requested row limit".to_owned()
                        );
                    }
                    let value = serde_json::to_value(row)
                        .map_err(|_| "could not serialize Linux package row".to_owned())?;
                    rows.push(PackageQueryRow {
                        source: row.source_id.clone(),
                        json_pointer: format!("/packages/{index}"),
                        evidence: value
                            .get("evidence")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        row: value,
                    });
                }
            }
            if document.sources.0.iter().any(|source| {
                row_counts.get(source.id.as_str()).copied().unwrap_or(0) > source.records_seen
            }) {
                return Err(
                    "Linux package source record count is smaller than its retained rows"
                        .to_owned(),
                );
            }
            match document.status {
                LinuxPackageInventoryStatus::Complete => "complete",
                LinuxPackageInventoryStatus::Partial => "partial",
            }
            .to_owned()
        }
        "windows" => {
            if artifact.kind != ArtifactKind::WindowsSoftware
                || artifact.schema != "sideeffect.windows_software_inventory"
                || artifact.schema_version != 1
                || artifact.path != "software.windows.json"
            {
                return Err(
                    "Windows software artifact contract does not match its session manifest"
                        .to_owned(),
                );
            }
            let document: WindowsSoftwareDocument =
                serde_json::from_slice(bytes).map_err(|_| {
                    "Windows software artifact is malformed or has unsupported fields".to_owned()
                })?;
            if document.schema != "sideeffect.windows_software_inventory"
                || document.schema_version != 1
                || document.platform != "windows"
                || document.scope.is_empty()
                || document.capture_ended_at_unix_ms < document.capture_started_at_unix_ms
            {
                return Err("Windows software artifact header is malformed".to_owned());
            }
            let mut source_ids = std::collections::HashMap::new();
            let mut diag_count = 0usize;
            for source in &document.sources.0 {
                let expected_id = match (source.hive.as_str(), source.registry_view) {
                    ("HKEY_CURRENT_USER", WindowsRegistryView::Native) => {
                        "current_user_native_uninstall"
                    }
                    ("HKEY_CURRENT_USER", WindowsRegistryView::Wow64_32) => {
                        "current_user_32_uninstall"
                    }
                    ("HKEY_LOCAL_MACHINE", WindowsRegistryView::Wow64_64) => {
                        "local_machine_64_uninstall"
                    }
                    ("HKEY_LOCAL_MACHINE", WindowsRegistryView::Wow64_32) => {
                        "local_machine_32_uninstall"
                    }
                    _ => return Err("Windows software source hive/view is unsupported".to_owned()),
                };
                if source.id != expected_id
                    || source.registry_key
                        != "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
                    || source.registrations_seen > 8_192
                    || source_ids
                        .insert(
                            (source.hive.as_str(), source.registry_view),
                            source.id.as_str(),
                        )
                        .is_some()
                {
                    return Err(
                        "Windows software artifact contains invalid or duplicate source identities"
                            .to_owned(),
                    );
                }
                if document.status == WindowsSoftwareStatus::Complete
                    && !matches!(
                        source.status,
                        WindowsSoftwareStatus::Complete | WindowsSoftwareStatus::NotPresent
                    )
                {
                    return Err(
                        "complete Windows software artifact contains an incomplete source"
                            .to_owned(),
                    );
                }
                diag_count = diag_count
                    .checked_add(source.diagnostics.0.len())
                    .ok_or_else(|| "package diagnostic count overflow".to_owned())?;
                if diag_count > MAX_WINDOWS_SOFTWARE_QUERY_DIAGNOSTICS {
                    return Err(
                        "Windows software artifact diagnostics exceed their query limit".to_owned(),
                    );
                }
                if source.diagnostics.0.iter().any(|diagnostic| {
                    diagnostic.code.len() > 128
                        || diagnostic.message.len() > 4_096
                        || diagnostic
                            .value_name
                            .as_ref()
                            .is_some_and(|name| name.len() > 128)
                        || diagnostic
                            .registration_index
                            .is_some_and(|ordinal| ordinal >= 8_192)
                        || diagnostic.win32_error == Some(0)
                }) {
                    return Err("Windows software source diagnostic is malformed".to_owned());
                }
                inventory_diagnostics.extend(
                    source
                        .diagnostics
                        .0
                        .iter()
                        .map(serde_json::to_value)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| "could not serialize software diagnostic".to_owned())?,
                );
                source_states.push(
                    serde_json::to_value(source)
                        .map_err(|_| "could not serialize software source state".to_owned())?,
                );
            }
            if source_ids.len() != 4
                || source_ids.values().any(|id| id.is_empty())
                || document
                    .sources
                    .0
                    .iter()
                    .map(|source| source.registrations_seen)
                    .sum::<usize>()
                    > 8_192
                || (document.status == WindowsSoftwareStatus::Complete)
                    != document.sources.0.iter().all(|source| {
                        matches!(
                            source.status,
                            WindowsSoftwareStatus::Complete | WindowsSoftwareStatus::NotPresent
                        )
                    })
            {
                return Err(
                    "Windows software source set or aggregate status is malformed".to_owned(),
                );
            }
            let mut seen_ordinals = std::collections::HashSet::new();
            for (index, row) in document.registrations.0.iter().enumerate() {
                let ev = &row.evidence;
                let source_id = source_ids
                    .get(&(ev.hive.as_str(), ev.registry_view))
                    .ok_or_else(|| {
                        "Windows software row refers to an unknown registry source".to_owned()
                    })?;
                let source_state = document
                    .sources
                    .0
                    .iter()
                    .find(|source| source.id == *source_id)
                    .ok_or_else(|| "Windows software row refers to an unknown source".to_owned())?;
                if ev.registration_index >= 8_192
                    || ev.registration_index >= source_state.registrations_seen
                    || source_state.status == WindowsSoftwareStatus::NotPresent
                    || !seen_ordinals.insert((
                        ev.hive.as_str(),
                        ev.registry_view,
                        ev.registration_index,
                    ))
                    || ev.source != "RegEnumKeyExW/RegQueryValueExW"
                    || ev.registry_key != "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
                    || ev.registry_subkey != row.registry_subkey
                    || row.registry_subkey_utf16_hex.is_empty()
                    || row.registry_subkey_utf16_hex.len() % 4 != 0
                    || !row
                        .registry_subkey_utf16_hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("Windows software registration evidence is malformed".to_owned());
                }
                let mut value_names = std::collections::HashSet::new();
                for value in &row.values.0 {
                    if !matches!(
                        value.name.as_str(),
                        "DisplayName"
                            | "DisplayVersion"
                            | "Publisher"
                            | "InstallLocation"
                            | "InstallDate"
                            | "UninstallString"
                            | "QuietUninstallString"
                            | "DisplayIcon"
                    ) || !value_names.insert(value.name.as_str())
                        || value.raw_data_hex.len() % 2 != 0
                        || !value
                            .raw_data_hex
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        || (value.registry_type == 1 && value.type_name != "REG_SZ")
                        || (value.registry_type == 2 && value.type_name != "REG_EXPAND_SZ")
                        || (!matches!(value.registry_type, 1 | 2)
                            && value.type_name != "unsupported")
                    {
                        return Err("Windows software registration value is malformed".to_owned());
                    }
                }
                let display_version = row
                    .values
                    .0
                    .iter()
                    .find(|value| value.name == "DisplayVersion")
                    .and_then(|value| value.text.as_deref());
                let publisher = row
                    .values
                    .0
                    .iter()
                    .find(|value| value.name == "Publisher")
                    .and_then(|value| value.text.as_deref());
                if query
                    .filters
                    .source
                    .as_deref()
                    .is_none_or(|value| value == *source_id)
                    && query
                        .filters
                        .name
                        .as_deref()
                        .is_none_or(|value| row.display_name.as_deref() == Some(value))
                    && query
                        .filters
                        .version
                        .as_deref()
                        .is_none_or(|value| display_version == Some(value))
                    && query
                        .filters
                        .publisher
                        .as_deref()
                        .is_none_or(|value| publisher == Some(value))
                {
                    if rows.len() >= query.limit as usize {
                        return Err(
                            "package query matched more than its requested row limit".to_owned()
                        );
                    }
                    let value = serde_json::to_value(row)
                        .map_err(|_| "could not serialize Windows software row".to_owned())?;
                    rows.push(PackageQueryRow {
                        source: (*source_id).to_owned(),
                        json_pointer: format!("/registrations/{index}"),
                        evidence: value
                            .get("evidence")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        row: value,
                    });
                }
            }
            match document.status {
                WindowsSoftwareStatus::Complete => "complete",
                WindowsSoftwareStatus::Partial => "partial",
                WindowsSoftwareStatus::NotPresent => "not_present",
                WindowsSoftwareStatus::Inaccessible => "inaccessible",
                WindowsSoftwareStatus::Error => "error",
            }
            .to_owned()
        }
        _ => return Err("package query session platform is unsupported".to_owned()),
    };
    let artifact_meta = PackageQueryArtifact {
        path: artifact.path.clone(),
        schema: artifact.schema.clone(),
        schema_version: artifact.schema_version,
        byte_length: artifact.byte_length,
        sha256: artifact.sha256.clone(),
    };
    Ok(PackageQuerySource {
        role: SourceRole::Packages,
        platform: platform.to_owned(),
        status: source_status,
        scope,
        started_at_unix_ms,
        ended_at_unix_ms,
        diagnostic_codes,
        inventory_status: Some(inventory_status),
        inventory_diagnostics,
        source_states,
        artifact: Some(artifact_meta),
        matched_count: rows.len(),
        rows,
    })
}

fn decode_lower_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            Some((nibble(pair[0])? << 4) | nibble(pair[1])?)
        })
        .collect()
}

pub fn multi_session_package_query_result(
    sessions: Vec<SessionPackageQueryResult>,
    query: &PackageQuery,
) -> Result<MultiSessionPackageQueryResult, String> {
    if !(1..=MAX_QUERY_SESSIONS).contains(&sessions.len()) {
        return Err(format!(
            "package query requires 1..={MAX_QUERY_SESSIONS} sessions"
        ));
    }
    let mut ids = HashSet::new();
    let mut matched_count = 0usize;
    for session in &sessions {
        if !ids.insert(session.session.session_id.as_str()) {
            return Err("package query contains duplicate session IDs".to_owned());
        }
        matched_count = matched_count
            .checked_add(session.package_source.matched_count)
            .ok_or_else(|| "package query result count overflow".to_owned())?;
        if matched_count > MAX_MULTI_SESSION_RESULTS {
            return Err("package query exceeds its 5000-row aggregate limit".to_owned());
        }
    }
    let complete = sessions.iter().all(|item| {
        item.session.status == SessionStatus::Complete
            && item.package_source.status == SourceStatus::Complete
            && item.package_source.inventory_status.as_deref() == Some("complete")
    });
    Ok(MultiSessionPackageQueryResult {
        schema: PACKAGE_QUERY_RESULT_SCHEMA,
        schema_version: PACKAGE_QUERY_RESULT_SCHEMA_VERSION,
        session_count: sessions.len(),
        matched_count,
        complete,
        filter: query.filters.clone(),
        limit: query.limit,
        sessions,
    })
}

/// Exact, case-sensitive filters over native process snapshot fields. PID is
/// snapshot-local and must not be treated as a stable identity across sessions.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessQueryFilters {
    pub process_id: Option<u32>,
    pub image_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessQuery {
    pub schema: String,
    pub schema_version: u32,
    #[serde(default)]
    pub filters: ProcessQueryFilters,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl ProcessQuery {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_QUERY_BYTES {
            return Err(format!(
                "process query input exceeds the {MAX_QUERY_BYTES}-byte limit"
            ));
        }
        let query: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid process query JSON: {error}"))?;
        if query.schema != PROCESS_QUERY_SCHEMA
            || query.schema_version != PROCESS_QUERY_SCHEMA_VERSION
        {
            return Err(format!(
                "process query schema must be {PROCESS_QUERY_SCHEMA} version {PROCESS_QUERY_SCHEMA_VERSION}"
            ));
        }
        if query.limit == 0 || query.limit as usize > MAX_QUERY_RESULTS {
            return Err(format!(
                "process query limit must be between 1 and {MAX_QUERY_RESULTS}"
            ));
        }
        if query.filters.process_id.is_none() && query.filters.image_name.is_none() {
            return Err("process query requires process_id or image_name".to_owned());
        }
        if query
            .filters
            .image_name
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_PACKAGE_QUERY_STRING_BYTES)
        {
            return Err(format!(
                "process query image_name must be non-empty and at most {MAX_PACKAGE_QUERY_STRING_BYTES} UTF-8 bytes"
            ));
        }
        Ok(query)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessQueryArtifact {
    pub path: String,
    pub schema: String,
    pub schema_version: u32,
    pub byte_length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessQueryRow {
    pub json_pointer: String,
    pub evidence: serde_json::Value,
    pub row: serde_json::Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessQuerySource {
    pub role: SourceRole,
    pub platform: String,
    pub status: SourceStatus,
    pub scope: Option<String>,
    pub started_at_unix_ms: Option<u128>,
    pub ended_at_unix_ms: Option<u128>,
    pub inventory_status: Option<String>,
    pub diagnostic_codes: Vec<String>,
    pub inventory_diagnostics: Vec<serde_json::Value>,
    pub source_state: Option<serde_json::Value>,
    pub artifact: Option<ProcessQueryArtifact>,
    pub matched_count: usize,
    pub rows: Vec<ProcessQueryRow>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionProcessQueryResult {
    pub session: SessionQueryIdentity,
    pub process_source: ProcessQuerySource,
}

#[derive(Clone, Debug, Serialize)]
pub struct MultiSessionProcessQueryResult {
    pub schema: &'static str,
    pub schema_version: u32,
    pub session_count: usize,
    pub matched_count: usize,
    pub complete: bool,
    pub filter: ProcessQueryFilters,
    pub limit: u32,
    pub sessions: Vec<SessionProcessQueryResult>,
}

pub struct ProcessQueryInput<'a> {
    pub platform: &'a str,
    pub source_status: SourceStatus,
    pub scope: Option<String>,
    pub started_at_unix_ms: Option<u128>,
    pub ended_at_unix_ms: Option<u128>,
    pub diagnostic_codes: Vec<String>,
    pub artifact: Option<&'a SessionArtifactRef>,
    pub bytes: Option<&'a [u8]>,
}

/// Query verified native process-snapshot bytes. The shared process-diff
/// validator enforces strict current and historical schemas before matching.
pub fn query_process_artifact(
    input: ProcessQueryInput<'_>,
    query: &ProcessQuery,
) -> Result<ProcessQuerySource, String> {
    let ProcessQueryInput {
        platform,
        source_status,
        scope,
        started_at_unix_ms,
        ended_at_unix_ms,
        mut diagnostic_codes,
        artifact,
        bytes,
    } = input;
    if !matches!(platform, "linux" | "windows") {
        return Err("process query session platform is unsupported".to_owned());
    }
    let Some(artifact) = artifact else {
        if bytes.is_some() {
            return Err("process artifact bytes have no manifest reference".to_owned());
        }
        return Ok(ProcessQuerySource {
            role: SourceRole::Processes,
            platform: platform.to_owned(),
            status: source_status,
            scope,
            started_at_unix_ms,
            ended_at_unix_ms,
            inventory_status: None,
            diagnostic_codes,
            inventory_diagnostics: Vec::new(),
            source_state: None,
            artifact: None,
            matched_count: 0,
            rows: Vec::new(),
        });
    };
    let bytes =
        bytes.ok_or_else(|| "verified process artifact bytes are unavailable".to_owned())?;
    if bytes.len() as u64 != artifact.byte_length
        || bytes.len() > crate::audit_session::MAX_SESSION_ARTIFACT_BYTES as usize
    {
        return Err("process artifact bytes do not match the verified manifest length".to_owned());
    }
    let expected = match platform {
        "linux" => (
            ArtifactKind::Processes,
            "processes.json",
            "sideeffect.process_inventory",
            3..=5,
        ),
        "windows" => (
            ArtifactKind::WindowsProcesses,
            "processes.json",
            "sideeffect.windows_process_inventory",
            3..=4,
        ),
        _ => unreachable!(),
    };
    if artifact.kind != expected.0
        || artifact.path != expected.1
        || artifact.schema != expected.2
        || !expected.3.contains(&artifact.schema_version)
    {
        return Err("process artifact contract does not match its session manifest".to_owned());
    }
    let document = crate::inventory::process_diff::parse_validated_inventory(bytes)
        .map_err(|_| "process artifact is malformed or has an unsupported schema".to_owned())?;
    if document.get("platform").and_then(serde_json::Value::as_str) != Some(platform)
        || document.get("schema").and_then(serde_json::Value::as_str)
            != Some(artifact.schema.as_str())
        || document
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(u64::from(artifact.schema_version))
    {
        return Err(
            "process artifact header does not match its verified native contract".to_owned(),
        );
    }
    let status = document
        .get("status")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "process artifact status is missing".to_owned())?
        .to_owned();
    let source = document
        .get("source")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "process artifact source is missing".to_owned())?;
    let diagnostics = source
        .get("diagnostics")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "process artifact diagnostics are malformed".to_owned())?;
    diagnostic_codes.extend(diagnostics.iter().filter_map(|item| {
        item.get("code")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    }));
    diagnostic_codes.sort();
    diagnostic_codes.dedup();
    let processes = document
        .get("processes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "process artifact rows are malformed".to_owned())?;
    let mut rows = Vec::new();
    for (index, row) in processes.iter().enumerate() {
        let (pid_key, name_key) = if platform == "linux" {
            ("pid", "name")
        } else {
            ("process_id", "executable_name")
        };
        if query.filters.process_id.is_some_and(|expected| {
            row.get(pid_key).and_then(serde_json::Value::as_u64) != Some(u64::from(expected))
        }) || query.filters.image_name.as_ref().is_some_and(|expected| {
            row.get(name_key).and_then(serde_json::Value::as_str) != Some(expected.as_str())
        }) {
            continue;
        }
        if rows.len() >= query.limit as usize {
            return Err(format!(
                "process query matched more than its {}-row limit; narrow the filters",
                query.limit
            ));
        }
        let evidence = row
            .get("evidence")
            .cloned()
            .ok_or_else(|| "process row evidence is missing".to_owned())?;
        rows.push(ProcessQueryRow {
            json_pointer: format!("/processes/{index}"),
            evidence,
            row: row.clone(),
        });
    }
    Ok(ProcessQuerySource {
        role: SourceRole::Processes,
        platform: platform.to_owned(),
        status: source_status,
        scope: Some(
            document
                .get("scope")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "process artifact scope is missing".to_owned())?
                .to_owned(),
        ),
        started_at_unix_ms,
        ended_at_unix_ms,
        inventory_status: Some(status),
        diagnostic_codes,
        inventory_diagnostics: diagnostics.clone(),
        source_state: Some(serde_json::Value::Object(source.clone())),
        artifact: Some(ProcessQueryArtifact {
            path: artifact.path.clone(),
            schema: artifact.schema.clone(),
            schema_version: artifact.schema_version,
            byte_length: artifact.byte_length,
            sha256: artifact.sha256.clone(),
        }),
        matched_count: rows.len(),
        rows,
    })
}

pub fn multi_session_process_query_result(
    sessions: Vec<SessionProcessQueryResult>,
    query: &ProcessQuery,
) -> Result<MultiSessionProcessQueryResult, String> {
    if !(1..=MAX_QUERY_SESSIONS).contains(&sessions.len()) {
        return Err(format!(
            "process query requires 1..={MAX_QUERY_SESSIONS} sessions"
        ));
    }
    let mut ids = HashSet::new();
    let mut matched_count = 0usize;
    for session in &sessions {
        if !ids.insert(session.session.session_id.as_str()) {
            return Err("process query contains duplicate session IDs".to_owned());
        }
        matched_count = matched_count
            .checked_add(session.process_source.matched_count)
            .ok_or_else(|| "process query result count overflow".to_owned())?;
        if matched_count > MAX_MULTI_SESSION_RESULTS {
            return Err("process query exceeds its 5000-row aggregate limit".to_owned());
        }
    }
    let complete = sessions.iter().all(|item| {
        item.session.status == SessionStatus::Complete
            && item.process_source.status == SourceStatus::Complete
            && item.process_source.inventory_status.as_deref() == Some("complete")
    });
    Ok(MultiSessionProcessQueryResult {
        schema: PROCESS_QUERY_RESULT_SCHEMA,
        schema_version: PROCESS_QUERY_RESULT_SCHEMA_VERSION,
        session_count: sessions.len(),
        matched_count,
        complete,
        filter: query.filters.clone(),
        limit: query.limit,
        sessions,
    })
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryQueryFilters {
    /// Exact selected-root path bytes, lowercase hex in the artifact platform's native encoding.
    pub root_path_hex: Option<String>,
    /// Exact direct-child name bytes, lowercase hex in the artifact platform's native encoding.
    pub entry_name_hex: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryQuery {
    pub schema: String,
    pub schema_version: u32,
    #[serde(default)]
    pub filters: InventoryQueryFilters,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl InventoryQuery {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_QUERY_BYTES {
            return Err(format!(
                "inventory query input exceeds the {MAX_QUERY_BYTES}-byte limit"
            ));
        }
        let query: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid inventory query JSON: {error}"))?;
        query.validate()?;
        Ok(query)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != INVENTORY_QUERY_SCHEMA
            || self.schema_version != INVENTORY_QUERY_SCHEMA_VERSION
        {
            return Err(format!(
                "inventory query schema must be {INVENTORY_QUERY_SCHEMA} version {INVENTORY_QUERY_SCHEMA_VERSION}"
            ));
        }
        if self.limit == 0 || self.limit as usize > MAX_QUERY_RESULTS {
            return Err(format!(
                "inventory query limit must be between 1 and {MAX_QUERY_RESULTS}"
            ));
        }
        for (label, value) in [
            ("root_path_hex", self.filters.root_path_hex.as_deref()),
            ("entry_name_hex", self.filters.entry_name_hex.as_deref()),
        ] {
            if let Some(value) = value {
                if value.is_empty()
                    || value.len() > 2 * MAX_ROOT_QUERY_AGGREGATE_NAME_BYTES
                    || value.len() % 2 != 0
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(format!(
                        "{label} must be non-empty, even-length lowercase hexadecimal within the encoded-name limit"
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct InventoryQueryResult {
    pub schema: &'static str,
    pub schema_version: u32,
    pub session_count: usize,
    pub matched_count: usize,
    /// True only when every selected session, selected-root source, and artifact document is complete.
    pub complete: bool,
    pub sessions: Vec<SessionInventoryQueryResult>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionInventoryQueryResult {
    pub session: SessionQueryIdentity,
    pub selected_root_source: SelectedRootQuerySource,
}

#[derive(Clone, Debug, Serialize)]
pub struct SelectedRootQuerySource {
    pub role: SourceRole,
    pub platform: String,
    pub status: SourceStatus,
    pub scope: Option<String>,
    pub started_at_unix_ms: Option<u128>,
    pub ended_at_unix_ms: Option<u128>,
    pub collector: Option<CollectorIdentity>,
    pub diagnostic_codes: Vec<String>,
    pub inventory_status: Option<String>,
    pub inventory_diagnostics: Vec<RootQueryDiagnostic>,
    pub artifact: Option<SelectedRootQueryArtifact>,
    pub root_path_hex: Option<String>,
    pub matched_count: usize,
    pub entries: Vec<RootQueryEntry>,
}

pub struct SelectedRootQueryInput<'a> {
    pub platform: &'a str,
    pub source_status: SourceStatus,
    pub scope: Option<String>,
    pub started_at_unix_ms: Option<u128>,
    pub ended_at_unix_ms: Option<u128>,
    pub collector: Option<CollectorIdentity>,
    pub diagnostic_codes: Vec<String>,
    pub artifact: Option<&'a SessionArtifactRef>,
    pub bytes: Option<&'a [u8]>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SelectedRootQueryArtifact {
    pub path: String,
    pub schema: String,
    pub schema_version: u32,
    pub byte_length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootQueryDiagnostic {
    pub code: String,
    pub entry_ordinal: Option<usize>,
    pub native_error: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootQueryEntry {
    pub ordinal: usize,
    pub name_hex: String,
    pub display_name: String,
    pub object_type: String,
    pub size_bytes: Option<u64>,
    pub modified_at_unix_ms: Option<i128>,
    pub content_sha256: Option<String>,
    pub content_hash_status: Option<String>,
    pub evidence: RootQueryEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootQueryEvidence {
    pub artifact_path: String,
    pub source: String,
    pub entry_ordinal: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct MultiSessionInventoryQueryResult {
    pub schema: &'static str,
    pub schema_version: u32,
    pub session_count: usize,
    pub matched_count: usize,
    pub complete: bool,
    pub filter: InventoryQueryFilters,
    pub limit: u32,
    pub sessions: Vec<SessionInventoryQueryResult>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootSnapshotDocument {
    schema: String,
    schema_version: u32,
    platform: String,
    scope: String,
    captured_started_at_unix_ms: u128,
    captured_ended_at_unix_ms: u128,
    status: String,
    root: Option<RootSnapshotIdentity>,
    entries: BoundedSequence<RootSnapshotEntry, MAX_ROOT_QUERY_ENTRIES>,
    diagnostics: BoundedSequence<RootSnapshotDiagnostic, 256>,
    limits: RootSnapshotLimits,
    #[serde(default)]
    content_hashing: Option<RootSnapshotContentHashing>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootSnapshotContentHashing {
    requested: bool,
    algorithm: String,
    max_file_bytes: u64,
    max_aggregate_bytes: u64,
    deadline_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootSnapshotIdentity {
    display_path: String,
    #[serde(default)]
    path_bytes_hex: Option<String>,
    #[serde(default)]
    path_utf16le_hex: Option<String>,
    object_type: String,
    device_or_volume_serial: Option<u64>,
    inode_or_file_index: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootSnapshotEntry {
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
    #[serde(default)]
    content_sha256: Option<String>,
    #[serde(default)]
    content_hash_status: Option<String>,
    evidence: RootSnapshotEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootSnapshotEvidence {
    source: String,
    entry_ordinal: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootSnapshotDiagnostic {
    code: String,
    entry_ordinal: Option<usize>,
    native_error: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootSnapshotLimits {
    max_root_path_bytes_or_utf16_units: usize,
    max_entries: usize,
    max_name_bytes_or_utf16_units: usize,
    max_aggregate_name_bytes: usize,
    deadline_seconds: u64,
}

#[derive(Debug, Serialize)]
struct BoundedSequence<T, const MAX: usize>(Vec<T>);

impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for BoundedSequence<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedSequenceVisitor<T, const MAX: usize>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for BoundedSequenceVisitor<T, MAX> {
            type Value = BoundedSequence<T, MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array with at most {MAX} items")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                if sequence.size_hint().is_some_and(|size| size > MAX) {
                    return Err(serde::de::Error::custom("array item limit exceeded"));
                }
                let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
                while let Some(value) = sequence.next_element()? {
                    if values.len() == MAX {
                        return Err(serde::de::Error::custom("array item limit exceeded"));
                    }
                    values.push(value);
                }
                Ok(BoundedSequence(values))
            }
        }

        deserializer.deserialize_seq(BoundedSequenceVisitor::<T, MAX>(PhantomData))
    }
}

/// Validate a selected-root artifact against its exact v1/v2 platform contract and return
/// only positive matching rows. Session artifact byte length and digest are supplied by the
/// already-verified reader and retained in the output.
pub fn query_selected_root_artifact(
    input: SelectedRootQueryInput<'_>,
    query: &InventoryQuery,
) -> Result<SelectedRootQuerySource, String> {
    query_selected_root_artifact_inner(input, query, None, query.limit as usize, true)
}

/// Validate the complete selected-root snapshot and retain only the requested entry.
///
/// Snapshot validation still examines every bounded entry for duplicate ordinals, native-name
/// encoding, and aggregate-name limits. The returned query result contains at most one row, so
/// callers resolving a locator do not need to materialize a multi-thousand-row query result.
pub fn query_selected_root_entry_artifact(
    input: SelectedRootQueryInput<'_>,
    entry_ordinal: usize,
) -> Result<SelectedRootQuerySource, String> {
    query_selected_root_entries_artifact(input, &[entry_ordinal])
}

/// Validate one selected-root snapshot and retain only the requested bounded ordinal set.
///
/// The snapshot is fully validated once, including unrequested entries. The returned result
/// contains at most one row per distinct requested ordinal.
pub fn query_selected_root_entries_artifact(
    input: SelectedRootQueryInput<'_>,
    entry_ordinals: &[usize],
) -> Result<SelectedRootQuerySource, String> {
    query_selected_root_entries_artifact_inner(input, entry_ordinals, true)
}

/// Case resolution calls this only after `verify_session_view` has checked the exact artifact
/// length and SHA-256 against the manifest.
pub(crate) fn query_verified_selected_root_entries_artifact(
    input: SelectedRootQueryInput<'_>,
    entry_ordinals: &[usize],
) -> Result<SelectedRootQuerySource, String> {
    query_selected_root_entries_artifact_inner(input, entry_ordinals, false)
}

fn query_selected_root_entries_artifact_inner(
    input: SelectedRootQueryInput<'_>,
    entry_ordinals: &[usize],
    verify_bytes: bool,
) -> Result<SelectedRootQuerySource, String> {
    if entry_ordinals.len() > MAX_ROOT_QUERY_ENTRIES
        || entry_ordinals
            .iter()
            .any(|ordinal| *ordinal >= MAX_ROOT_QUERY_ENTRIES)
    {
        return Err("selected-root entry ordinal set exceeds the supported range".to_owned());
    }
    let ordinals: HashSet<usize> = entry_ordinals.iter().copied().collect();
    let query = InventoryQuery {
        schema: INVENTORY_QUERY_SCHEMA.to_owned(),
        schema_version: INVENTORY_QUERY_SCHEMA_VERSION,
        filters: InventoryQueryFilters::default(),
        limit: 1,
    };
    query_selected_root_artifact_inner(input, &query, Some(&ordinals), ordinals.len(), verify_bytes)
}

fn query_selected_root_artifact_inner(
    input: SelectedRootQueryInput<'_>,
    query: &InventoryQuery,
    exact_ordinals: Option<&HashSet<usize>>,
    result_limit: usize,
    verify_bytes: bool,
) -> Result<SelectedRootQuerySource, String> {
    let SelectedRootQueryInput {
        platform,
        source_status,
        scope,
        started_at_unix_ms,
        ended_at_unix_ms,
        collector,
        diagnostic_codes,
        artifact,
        bytes,
    } = input;
    query.validate()?;
    validate_inventory_filters(query, platform)?;
    let Some(artifact) = artifact else {
        if bytes.is_some() {
            return Err("selected-root artifact bytes have no manifest reference".to_owned());
        }
        return Ok(SelectedRootQuerySource {
            role: SourceRole::SelectedRoot,
            platform: platform.to_owned(),
            status: source_status,
            scope,
            started_at_unix_ms,
            ended_at_unix_ms,
            collector,
            diagnostic_codes,
            inventory_status: None,
            inventory_diagnostics: Vec::new(),
            artifact: None,
            root_path_hex: None,
            matched_count: 0,
            entries: Vec::new(),
        });
    };
    let bytes =
        bytes.ok_or_else(|| "selected-root verified artifact bytes are unavailable".to_owned())?;
    let expected_version = match artifact.schema_version {
        1 => 1,
        2 => 2,
        _ => return Err("selected-root artifact has an unsupported schema version".to_owned()),
    };
    if artifact.kind != ArtifactKind::SelectedRoot
        || artifact.path != "root-snapshot.json"
        || artifact.schema != "sideeffect.selected_root_inventory"
        || artifact.schema_version != expected_version
        || bytes.len() as u64 != artifact.byte_length
        || bytes.len() > crate::audit_session::MAX_SESSION_ARTIFACT_BYTES as usize
        || (verify_bytes && crate::fingerprint::sha256_hex(bytes) != artifact.sha256)
    {
        return Err(
            "selected-root artifact contract or verified bytes do not match the session manifest"
                .to_owned(),
        );
    }
    let document: RootSnapshotDocument = serde_json::from_slice(bytes).map_err(|_| {
        "selected-root artifact is malformed or contains unsupported fields".to_owned()
    })?;
    let root_path_hex =
        validate_root_snapshot(&document, platform, artifact.schema_version)?.map(str::to_owned);
    if query
        .filters
        .root_path_hex
        .as_deref()
        .is_some_and(|value| root_path_hex.as_deref() != Some(value))
    {
        return Ok(SelectedRootQuerySource {
            role: SourceRole::SelectedRoot,
            platform: platform.to_owned(),
            status: source_status,
            scope,
            started_at_unix_ms,
            ended_at_unix_ms,
            collector,
            diagnostic_codes,
            inventory_status: Some(document.status),
            inventory_diagnostics: document
                .diagnostics
                .0
                .into_iter()
                .map(|diagnostic| RootQueryDiagnostic {
                    code: diagnostic.code,
                    entry_ordinal: diagnostic.entry_ordinal,
                    native_error: diagnostic.native_error,
                })
                .collect(),
            artifact: Some(SelectedRootQueryArtifact {
                path: artifact.path.clone(),
                schema: artifact.schema.clone(),
                schema_version: artifact.schema_version,
                byte_length: artifact.byte_length,
                sha256: artifact.sha256.clone(),
            }),
            root_path_hex,
            matched_count: 0,
            entries: Vec::new(),
        });
    }
    let mut entries = Vec::new();
    for entry in document.entries.0 {
        if root_path_hex.is_none() {
            return Err("selected-root artifact has entries but no root identity".to_owned());
        }
        let name_hex = native_name_hex(&entry, platform)?;
        if exact_ordinals.is_none_or(|ordinals| ordinals.contains(&entry.ordinal))
            && query
                .filters
                .entry_name_hex
                .as_deref()
                .is_none_or(|filter| filter == name_hex)
        {
            if entries.len() >= result_limit {
                return Err(format!(
                    "inventory query matched more than its {}-row limit; narrow the filters",
                    query.limit
                ));
            }
            entries.push(RootQueryEntry {
                ordinal: entry.ordinal,
                name_hex: name_hex.to_owned(),
                display_name: entry.display_name,
                object_type: entry.object_type,
                size_bytes: entry.size_bytes,
                modified_at_unix_ms: entry.modified_at_unix_ms,
                content_sha256: entry.content_sha256,
                content_hash_status: entry.content_hash_status,
                evidence: RootQueryEvidence {
                    artifact_path: artifact.path.clone(),
                    source: entry.evidence.source,
                    entry_ordinal: entry.evidence.entry_ordinal,
                },
            });
        }
    }
    let matched_count = entries.len();
    Ok(SelectedRootQuerySource {
        role: SourceRole::SelectedRoot,
        platform: platform.to_owned(),
        status: source_status,
        scope,
        started_at_unix_ms,
        ended_at_unix_ms,
        collector,
        diagnostic_codes,
        inventory_status: Some(document.status),
        inventory_diagnostics: document
            .diagnostics
            .0
            .into_iter()
            .map(|diagnostic| RootQueryDiagnostic {
                code: diagnostic.code,
                entry_ordinal: diagnostic.entry_ordinal,
                native_error: diagnostic.native_error,
            })
            .collect(),
        artifact: Some(SelectedRootQueryArtifact {
            path: artifact.path.clone(),
            schema: artifact.schema.clone(),
            schema_version: artifact.schema_version,
            byte_length: artifact.byte_length,
            sha256: artifact.sha256.clone(),
        }),
        root_path_hex,
        matched_count,
        entries,
    })
}

pub fn multi_session_inventory_query_result(
    sessions: Vec<SessionInventoryQueryResult>,
    query: &InventoryQuery,
) -> Result<MultiSessionInventoryQueryResult, String> {
    query.validate()?;
    if !(1..=MAX_QUERY_SESSIONS).contains(&sessions.len()) {
        return Err(format!(
            "inventory query requires 1..={MAX_QUERY_SESSIONS} sessions"
        ));
    }
    let mut ids = HashSet::with_capacity(sessions.len());
    let mut matched_count = 0usize;
    for session in &sessions {
        if !ids.insert(session.session.session_id.as_str()) {
            return Err("inventory query contains duplicate session IDs".to_owned());
        }
        matched_count = matched_count
            .checked_add(session.selected_root_source.matched_count)
            .ok_or_else(|| "inventory query result count overflow".to_owned())?;
        if matched_count > MAX_MULTI_SESSION_RESULTS {
            return Err(format!(
                "inventory query exceeds the {MAX_MULTI_SESSION_RESULTS}-row aggregate limit"
            ));
        }
    }
    let complete = sessions.iter().all(|session| {
        session.session.status == SessionStatus::Complete
            && session.selected_root_source.status == SourceStatus::Complete
            && session.selected_root_source.inventory_status.as_deref() == Some("complete")
    });
    Ok(MultiSessionInventoryQueryResult {
        schema: INVENTORY_QUERY_RESULT_SCHEMA,
        schema_version: INVENTORY_QUERY_RESULT_SCHEMA_VERSION,
        session_count: sessions.len(),
        matched_count,
        complete,
        filter: query.filters.clone(),
        limit: query.limit,
        sessions,
    })
}

fn validate_root_snapshot<'a>(
    document: &'a RootSnapshotDocument,
    platform: &str,
    artifact_version: u32,
) -> Result<Option<&'a str>, String> {
    let expected_scope = match artifact_version {
        1 => "one_explicit_root_and_its_direct_children_metadata_only",
        2 => "one_explicit_root_and_its_direct_children_metadata_and_opt_in_sha256",
        _ => return Err("selected-root artifact version is unsupported".to_owned()),
    };
    let (path_limit, name_limit) = match platform {
        "linux" => (4_095, 32_767),
        "windows" => (32_766, 32_767),
        _ => return Err("selected-root session platform is unsupported".to_owned()),
    };
    if document.schema != "sideeffect.selected_root_inventory"
        || document.schema_version != artifact_version
        || document.platform != platform
        || document.scope != expected_scope
        || !matches!(document.status.as_str(), "complete" | "partial")
        || document.captured_ended_at_unix_ms < document.captured_started_at_unix_ms
        || document.entries.0.len() > MAX_ROOT_QUERY_ENTRIES
        || document.diagnostics.0.len() > 256
        || document.limits.max_root_path_bytes_or_utf16_units != path_limit
        || document.limits.max_entries != MAX_ROOT_QUERY_ENTRIES
        || document.limits.max_name_bytes_or_utf16_units != name_limit
        || document.limits.max_aggregate_name_bytes != MAX_ROOT_QUERY_AGGREGATE_NAME_BYTES
        || document.limits.deadline_seconds != 5
        || (document.status == "complete" && !document.diagnostics.0.is_empty())
    {
        return Err(
            "selected-root artifact violates its schema, platform, status, or bounds".to_owned(),
        );
    }
    match (artifact_version, document.content_hashing.as_ref()) {
        (1, None) => {}
        (2, Some(h))
            if h.requested
                && h.algorithm == "sha256"
                && h.max_file_bytes == 16 * 1024 * 1024
                && h.max_aggregate_bytes == 64 * 1024 * 1024
                && h.deadline_seconds == 5 => {}
        _ => {
            return Err(
                "selected-root content-hashing metadata does not match its schema version"
                    .to_owned(),
            );
        }
    }
    for diagnostic in &document.diagnostics.0 {
        if diagnostic.code.is_empty()
            || diagnostic.code.len() > 128
            || diagnostic
                .entry_ordinal
                .is_some_and(|ordinal| ordinal > MAX_ROOT_QUERY_ENTRIES)
        {
            return Err("selected-root diagnostics exceed the supported contract".to_owned());
        }
    }
    let Some(root) = document.root.as_ref() else {
        if document.status == "complete" || !document.entries.0.is_empty() {
            return Err(
                "selected-root artifact has no root identity despite complete/entry data"
                    .to_owned(),
            );
        }
        return Ok(None);
    };
    let _root_identity_hints = (root.device_or_volume_serial, root.inode_or_file_index);
    if root.object_type != "directory"
        || root.display_path.is_empty()
        || root.display_path.len() > 128 * 1024
    {
        return Err("selected-root identity is malformed".to_owned());
    }
    let path_hex = match platform {
        "linux" if root.path_utf16le_hex.is_none() => root.path_bytes_hex.as_deref(),
        "windows" if root.path_bytes_hex.is_none() => root.path_utf16le_hex.as_deref(),
        _ => None,
    }
    .ok_or_else(|| "selected-root identity encoding does not match its platform".to_owned())?;
    validate_native_hex(path_hex, platform, path_limit, true, true)?;
    let mut ordinals = HashSet::with_capacity(document.entries.0.len());
    let mut aggregate_names = 0usize;
    for entry in &document.entries.0 {
        let _entry_identity_hints = (entry.device_or_volume_serial, entry.inode_or_file_index);
        if entry.ordinal >= MAX_ROOT_QUERY_ENTRIES
            || entry.evidence.entry_ordinal != entry.ordinal
            || entry.evidence.source != "selected_root_directory_entry"
            || entry.display_name.len() > 128 * 1024
            || !ordinals.insert(entry.ordinal)
            || !valid_root_object_type(platform, &entry.object_type)
        {
            return Err("selected-root entry identity or metadata is malformed".to_owned());
        }
        let name_hex = native_name_hex(entry, platform)?;
        validate_native_hex(name_hex, platform, name_limit, false, false)?;
        let encoded_bytes = decode_hex(name_hex)?.len();
        aggregate_names = aggregate_names
            .checked_add(encoded_bytes)
            .ok_or_else(|| "selected-root aggregate name length overflow".to_owned())?;
        if aggregate_names > MAX_ROOT_QUERY_AGGREGATE_NAME_BYTES {
            return Err("selected-root aggregate names exceed the supported limit".to_owned());
        }
        match (
            entry.content_sha256.as_deref(),
            entry.content_hash_status.as_deref(),
        ) {
            (None, None) if artifact_version == 1 => {}
            (Some(hash), Some("observed"))
                if artifact_version == 2
                    && is_root_regular(&entry.object_type)
                    && valid_sha256_hex(hash) => {}
            (None, Some("unavailable"))
                if artifact_version == 2
                    && is_root_regular(&entry.object_type)
                    && document.status == "partial" => {}
            (None, Some("not_applicable"))
                if artifact_version == 2 && !is_root_regular(&entry.object_type) => {}
            _ => return Err("selected-root entry content-hash metadata is malformed".to_owned()),
        }
    }
    Ok(Some(path_hex))
}

fn native_name_hex<'a>(entry: &'a RootSnapshotEntry, platform: &str) -> Result<&'a str, String> {
    match platform {
        "linux" if entry.name_utf16le_hex.is_none() => entry
            .name_bytes_hex
            .as_deref()
            .ok_or_else(|| "selected-root entry has no Linux name encoding".to_owned()),
        "windows" if entry.name_bytes_hex.is_none() => entry
            .name_utf16le_hex
            .as_deref()
            .ok_or_else(|| "selected-root entry has no Windows name encoding".to_owned()),
        _ => Err("selected-root entry encoding does not match its platform".to_owned()),
    }
}

fn validate_native_hex(
    value: &str,
    platform: &str,
    max_units: usize,
    path: bool,
    allow_slash: bool,
) -> Result<(), String> {
    let decoded = decode_hex(value)?;
    let unit_bytes = if platform == "windows" { 2 } else { 1 };
    if decoded.is_empty()
        || decoded.len() / unit_bytes > max_units
        || decoded.len() % unit_bytes != 0
        || decoded
            .chunks_exact(unit_bytes)
            .any(|unit| unit.iter().all(|byte| *byte == 0))
        || (!path && !allow_slash && platform == "linux" && decoded.contains(&b'/'))
        || (!path
            && !allow_slash
            && platform == "windows"
            && decoded
                .chunks_exact(2)
                .any(|unit| unit == [0x2f, 0] || unit == [0x5c, 0]))
        || (!path && !allow_slash && platform == "linux" && (value == "2e" || value == "2e2e"))
        || (!path
            && !allow_slash
            && platform == "windows"
            && (value == "2e00" || value == "2e002e00"))
    {
        return Err("selected-root exact path/name encoding is malformed or over limit".to_owned());
    }
    Ok(())
}

fn validate_inventory_filters(query: &InventoryQuery, platform: &str) -> Result<(), String> {
    let (path_limit, name_limit) = match platform {
        "linux" => (4_095, 32_767),
        "windows" => (32_766, 32_767),
        _ => return Err("selected-root query platform is unsupported".to_owned()),
    };
    if let Some(value) = &query.filters.root_path_hex {
        validate_native_hex(value, platform, path_limit, true, true)?;
    }
    if let Some(value) = &query.filters.entry_name_hex {
        validate_native_hex(value, platform, name_limit, false, false)?;
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("selected-root encoding must be lowercase even-length hexadecimal".to_owned());
    }
    let mut result = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hexadecimal encoding".to_owned())?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hexadecimal encoding".to_owned())?;
        result.push(((high << 4) | low) as u8);
    }
    Ok(result)
}

fn valid_root_object_type(platform: &str, value: &str) -> bool {
    match platform {
        "linux" => matches!(
            value,
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
            value,
            "directory" | "reparse_point" | "regular_or_other_file"
        ),
        _ => false,
    }
}

fn is_root_regular(value: &str) -> bool {
    matches!(value, "regular_file" | "regular_or_other_file")
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Hash, Eq, PartialEq)]
enum EvidenceKey {
    Trace(u64, u64, u64),
    Windows(u64, String, String),
}

fn evidence_key(evidence: &crate::event::EvidenceReference) -> EvidenceKey {
    match evidence {
        crate::event::EvidenceReference::RawTraceRecord {
            line_number,
            byte_offset,
            byte_length,
        } => EvidenceKey::Trace(*line_number, *byte_offset, *byte_length),
        crate::event::EvidenceReference::WindowsEtwRecord {
            record_ordinal,
            json_pointer,
            raw_payload_sha256,
        } => EvidenceKey::Windows(
            *record_ordinal,
            json_pointer.clone(),
            raw_payload_sha256.clone(),
        ),
    }
}

fn check_elapsed(started: Instant) -> Result<(), String> {
    if started.elapsed() > MAX_QUERY_ELAPSED {
        Err(format!(
            "query exceeded the {} ms execution limit",
            MAX_QUERY_ELAPSED.as_millis()
        ))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    SyscallAttempt,
    NativeObservation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeFilter {
    Success,
    Failure,
    InProgress,
    Unknown,
}

/// One exact source-local event locator. The `kind` tag and fields mirror
/// `event::EvidenceReference`; these values are never normalized.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceFilter {
    RawTraceRecord {
        line_number: u64,
        byte_offset: u64,
        byte_length: u64,
    },
    WindowsEtwRecord {
        record_ordinal: u64,
        json_pointer: String,
        raw_payload_sha256: String,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventQueryFilters {
    /// Exact normalized event-kind match, such as `openat` or `file_io`.
    pub event_kind: Option<String>,
    pub operation_kind: Option<OperationKind>,
    /// Matches only syscall attempts with the corresponding normalized result.
    pub outcome: Option<OutcomeFilter>,
    /// Source-local ProcessObservation ID, not an OS PID or cross-capture ID.
    pub process_observation_id: Option<u64>,
    /// Exact equality against a source-derived path/name field when available.
    /// This does not normalize, resolve, glob, or substring-match the value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_exact: Option<String>,
    /// Literal string prefix against a source-derived path/name, without path semantics.
    /// This can also match a sibling spelling such as `/tmp/a` and `/tmp/abc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    /// Exact source-local evidence tuple; not portable across captures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<EvidenceFilter>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventQuery {
    pub schema: String,
    pub schema_version: u32,
    #[serde(default)]
    pub filters: EventQueryFilters,
    /// Rejects the query if more rows match; results are never silently truncated.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    MAX_QUERY_RESULTS as u32
}

impl EventQuery {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_QUERY_BYTES {
            return Err(format!(
                "query input exceeds the {MAX_QUERY_BYTES}-byte limit"
            ));
        }
        let query: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid event query JSON: {error}"))?;
        query.validate()?;
        Ok(query)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != QUERY_SCHEMA || !matches!(self.schema_version, 1..=3) {
            return Err(format!(
                "query schema must be {QUERY_SCHEMA} version 1, 2, or 3"
            ));
        }
        if self.schema_version == 1 && self.filters.path_exact.is_some() {
            return Err("path_exact requires event query schema version 2".to_owned());
        }
        if self.schema_version < 3 && self.filters.path_prefix.is_some() {
            return Err("path_prefix requires event query schema version 3".to_owned());
        }
        if self.limit == 0 || self.limit as usize > MAX_QUERY_RESULTS {
            return Err(format!(
                "query limit must be between 1 and {MAX_QUERY_RESULTS}"
            ));
        }
        if let Some(kind) = &self.filters.event_kind {
            if kind.is_empty()
                || kind.len() > MAX_FILTER_TEXT_BYTES
                || kind.chars().any(char::is_control)
            {
                return Err(format!(
                    "event_kind must contain 1..{MAX_FILTER_TEXT_BYTES} printable UTF-8 bytes"
                ));
            }
        }
        if let Some(path) = &self.filters.path_exact {
            if path.is_empty()
                || path.len() > MAX_PATH_FILTER_BYTES
                || path.chars().any(char::is_control)
            {
                return Err(format!(
                    "path_exact must contain 1..{MAX_PATH_FILTER_BYTES} printable UTF-8 bytes"
                ));
            }
        }
        if let Some(prefix) = &self.filters.path_prefix {
            if prefix.is_empty()
                || prefix.len() > MAX_PATH_FILTER_BYTES
                || prefix.chars().any(char::is_control)
            {
                return Err(format!(
                    "path_prefix must contain 1..{MAX_PATH_FILTER_BYTES} printable UTF-8 bytes"
                ));
            }
        }
        if self.filters.process_observation_id == Some(0) {
            return Err("process_observation_id must be a positive source-local ID".to_owned());
        }
        if let Some(evidence) = &self.filters.evidence {
            match evidence {
                EvidenceFilter::RawTraceRecord {
                    line_number,
                    byte_offset,
                    byte_length,
                } => {
                    if *line_number == 0
                        || *line_number > crate::limits::MAX_TRACE_BYTES as u64
                        || *byte_length == 0
                        || byte_offset
                            .checked_add(*byte_length)
                            .is_none_or(|end| end > crate::limits::MAX_TRACE_BYTES as u64)
                    {
                        return Err(
                            "raw_trace_record evidence locator is outside the supported bounds"
                                .to_owned(),
                        );
                    }
                }
                EvidenceFilter::WindowsEtwRecord {
                    record_ordinal,
                    json_pointer,
                    raw_payload_sha256,
                } => {
                    if *record_ordinal == 0
                        || *record_ordinal
                            > crate::windows_runtime::MAX_WINDOWS_RUNTIME_EVENTS as u64
                        || !valid_etw_event_pointer(json_pointer)
                        || !valid_lower_sha256(raw_payload_sha256)
                    {
                        return Err("windows_etw_record evidence locator is malformed or outside the supported bounds".to_owned());
                    }
                }
            }
        }
        if self.filters.outcome.is_some()
            && self.filters.operation_kind == Some(OperationKind::NativeObservation)
        {
            return Err("outcome cannot be combined with native_observation".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EventQueryResult {
    pub schema: &'static str,
    pub schema_version: u32,
    pub source: SourceDescriptor,
    /// Full input status is retained even when filters return no rows.
    pub source_state: SourceState,
    pub filter: EventQueryFilters,
    pub matched_count: usize,
    pub events: Vec<CommonEvent>,
    pub event_process_links: Vec<EventProcessLink>,
    pub process_observations: Vec<ProcessObservation>,
    pub process_relationships: Vec<ProcessRelationship>,
    /// Diagnostics for the full source input, not merely the returned rows.
    pub diagnostics: Vec<EventDiagnostic>,
}

/// One session-scoped runtime query. Manifest status and event parsing status
/// remain separate, and the artifact references bind event locators to bytes.
#[derive(Clone, Debug, Serialize)]
pub struct SessionEventQueryResult {
    pub schema: &'static str,
    pub schema_version: u32,
    pub session: SessionQueryIdentity,
    pub runtime_source: SessionRuntimeSource,
    pub capture: SessionCaptureStatus,
    pub event_query_result: EventQueryResult,
}

/// Results for an explicit set of verified sessions. Every event stays nested
/// under its own session identity because source-local ordinals and IDs reset.
#[derive(Clone, Debug, Serialize)]
pub struct MultiSessionEventQueryResult {
    pub schema: &'static str,
    pub schema_version: u32,
    pub session_count: usize,
    pub matched_count: usize,
    pub complete: bool,
    pub sessions: Vec<SessionEventQueryResult>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionQueryIdentity {
    pub session_id: String,
    pub manifest_schema_version: u32,
    pub platform: String,
    pub status: SessionStatus,
    pub started_at_unix_ms: u128,
    pub ended_at_unix_ms: u128,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionRuntimeSource {
    pub role: crate::audit_session::SourceRole,
    pub platform: String,
    pub scope: String,
    pub started_at_unix_ms: u128,
    pub ended_at_unix_ms: u128,
    pub status: SourceStatus,
    pub collector: Option<CollectorIdentity>,
    pub loss: Option<LossMetadata>,
    pub diagnostic_codes: Vec<String>,
    pub artifacts: Vec<SessionArtifactRef>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionCaptureStatus {
    /// The producer's bounded completeness statement; runtime sessions usually say unknown.
    pub completeness: String,
    /// Windows collection status is distinct from completeness. Linux has no counterpart.
    pub collection_status: Option<String>,
    pub stop_reason: Option<String>,
}

pub fn session_query_result(
    manifest: &AuditSessionManifest,
    source: &AuditSessionSource,
    capture: SessionCaptureStatus,
    event_query_result: EventQueryResult,
) -> SessionEventQueryResult {
    SessionEventQueryResult {
        schema: SESSION_QUERY_RESULT_SCHEMA,
        schema_version: SESSION_QUERY_RESULT_SCHEMA_VERSION,
        session: SessionQueryIdentity {
            session_id: manifest.session_id.clone(),
            manifest_schema_version: manifest.schema_version,
            platform: manifest.platform.clone(),
            status: manifest.status,
            started_at_unix_ms: manifest.started_at_unix_ms,
            ended_at_unix_ms: manifest.ended_at_unix_ms,
        },
        runtime_source: SessionRuntimeSource {
            role: source.role,
            platform: source.platform.clone(),
            scope: source.scope.clone(),
            started_at_unix_ms: source.started_at_unix_ms,
            ended_at_unix_ms: source.ended_at_unix_ms,
            status: source.status,
            collector: source.collector.clone(),
            loss: source.loss.clone(),
            diagnostic_codes: source.diagnostic_codes.clone(),
            artifacts: source.artifacts.clone(),
        },
        capture,
        event_query_result,
    }
}

pub fn session_source_is_complete(result: &SessionEventQueryResult) -> bool {
    result.session.status == SessionStatus::Complete
        && result.runtime_source.status == SourceStatus::Complete
        && result.capture.completeness == "complete"
        && result
            .capture
            .collection_status
            .as_deref()
            .is_none_or(|status| status == "complete")
        && source_is_complete(&result.event_query_result.source_state)
}

pub fn multi_session_query_result(
    sessions: Vec<SessionEventQueryResult>,
) -> Result<MultiSessionEventQueryResult, String> {
    use std::collections::HashSet;

    if !(2..=MAX_QUERY_SESSIONS).contains(&sessions.len()) {
        return Err(format!(
            "multi-session query result requires 2..={MAX_QUERY_SESSIONS} sessions"
        ));
    }
    let mut session_ids = HashSet::with_capacity(sessions.len());
    let mut matched_count = 0usize;
    for session in &sessions {
        if !session_ids.insert(session.session.session_id.as_str()) {
            return Err("multi-session query result contains duplicate session IDs".to_owned());
        }
        matched_count = matched_count
            .checked_add(session.event_query_result.matched_count)
            .ok_or_else(|| "multi-session query result count overflow".to_owned())?;
        if matched_count > MAX_MULTI_SESSION_RESULTS {
            return Err(format!(
                "multi-session query result exceeds the {MAX_MULTI_SESSION_RESULTS}-row limit"
            ));
        }
    }
    let complete = sessions.iter().all(session_source_is_complete);
    Ok(MultiSessionEventQueryResult {
        schema: MULTI_SESSION_QUERY_RESULT_SCHEMA,
        schema_version: MULTI_SESSION_QUERY_RESULT_SCHEMA_VERSION,
        session_count: sessions.len(),
        matched_count,
        complete,
        sessions,
    })
}

pub fn execute_query(
    envelope: &CommonEventEnvelope,
    query: &EventQuery,
) -> Result<EventQueryResult, String> {
    query.validate()?;
    if envelope.schema != crate::event::COMMON_EVENT_SCHEMA
        || envelope.schema_version != crate::event::COMMON_EVENT_SCHEMA_VERSION
    {
        return Err("query input has an unsupported common event envelope".to_owned());
    }

    let started = Instant::now();
    let process_evidence = if let Some(selected_id) = query.filters.process_observation_id {
        let mut evidence = HashSet::new();
        for link in &envelope.event_process_links {
            check_elapsed(started)?;
            if link.process_observation_id == Some(selected_id) {
                evidence.insert(evidence_key(&link.event));
            }
        }
        Some(evidence)
    } else {
        None
    };
    let mut matched = Vec::new();
    for event in &envelope.events {
        check_elapsed(started)?;
        if matches_event(event, process_evidence.as_ref(), &query.filters) {
            if matched.len() >= query.limit as usize {
                return Err(format!(
                    "query matched more than its {}-row limit; narrow the filters",
                    query.limit
                ));
            }
            matched.push(event.clone());
        }
    }

    let evidence_keys = matched
        .iter()
        .map(|event| evidence_key(&event.evidence))
        .collect::<HashSet<_>>();
    let mut links = Vec::new();
    for link in &envelope.event_process_links {
        check_elapsed(started)?;
        if evidence_keys.contains(&evidence_key(&link.event))
            && query
                .filters
                .process_observation_id
                .is_none_or(|selected| link.process_observation_id == Some(selected))
        {
            links.push(link.clone());
        }
    }
    let included_ids = links
        .iter()
        .filter_map(|link| link.process_observation_id)
        .collect::<HashSet<_>>();
    let mut process_observations = Vec::new();
    for observation in &envelope.process_observations {
        check_elapsed(started)?;
        if included_ids.contains(&observation.source_local_id) {
            process_observations.push(observation.clone());
        }
    }
    let mut process_relationships = Vec::new();
    for relation in &envelope.process_relationships {
        check_elapsed(started)?;
        if included_ids.contains(&relation.to_observation_id)
            || relation
                .from_observation_id
                .is_some_and(|id| included_ids.contains(&id))
        {
            process_relationships.push(relation.clone());
        }
    }
    let matched_count = matched.len();
    Ok(EventQueryResult {
        schema: QUERY_RESULT_SCHEMA,
        schema_version: QUERY_RESULT_SCHEMA_VERSION,
        source: envelope.source.clone(),
        source_state: envelope.source_state.clone(),
        filter: query.filters.clone(),
        matched_count,
        events: matched,
        event_process_links: links,
        process_observations,
        process_relationships,
        diagnostics: envelope.diagnostics.clone(),
    })
}

fn matches_event(
    event: &CommonEvent,
    process_evidence: Option<&HashSet<EvidenceKey>>,
    filters: &EventQueryFilters,
) -> bool {
    if filters.path_exact.as_ref().is_some_and(|path| {
        event
            .path_observation
            .as_ref()
            .is_none_or(|observation| observation.path != *path)
    }) {
        return false;
    }
    if filters.path_prefix.as_ref().is_some_and(|prefix| {
        event
            .path_observation
            .as_ref()
            .is_none_or(|observation| !observation.path.starts_with(prefix))
    }) {
        return false;
    }
    if filters
        .event_kind
        .as_ref()
        .is_some_and(|kind| event.event_kind != *kind)
    {
        return false;
    }
    if filters.operation_kind.is_some_and(|kind| {
        !matches!(
            (kind, &event.operation),
            (
                OperationKind::SyscallAttempt,
                OperationSemantics::SyscallAttempt { .. }
            ) | (
                OperationKind::NativeObservation,
                OperationSemantics::NativeObservation
            )
        )
    }) {
        return false;
    }
    if let Some(outcome) = filters.outcome {
        let OperationSemantics::SyscallAttempt { result } = &event.operation else {
            return false;
        };
        if !matches!(
            (outcome, result),
            (OutcomeFilter::Success, Some(SyscallOutcome::Success))
                | (OutcomeFilter::Failure, Some(SyscallOutcome::Failure))
                | (OutcomeFilter::InProgress, Some(SyscallOutcome::InProgress))
                | (OutcomeFilter::Unknown, Some(SyscallOutcome::Unknown) | None)
        ) {
            return false;
        }
    }
    if filters
        .evidence
        .as_ref()
        .is_some_and(|filter| !evidence_filter_matches(filter, &event.evidence))
    {
        return false;
    }
    process_evidence.is_none_or(|evidence| evidence.contains(&evidence_key(&event.evidence)))
}

fn evidence_filter_matches(
    filter: &EvidenceFilter,
    evidence: &crate::event::EvidenceReference,
) -> bool {
    use crate::event::EvidenceReference;
    match (filter, evidence) {
        (
            EvidenceFilter::RawTraceRecord {
                line_number: filter_line,
                byte_offset: filter_offset,
                byte_length: filter_length,
            },
            EvidenceReference::RawTraceRecord {
                line_number,
                byte_offset,
                byte_length,
            },
        ) => {
            filter_line == line_number
                && filter_offset == byte_offset
                && filter_length == byte_length
        }
        (
            EvidenceFilter::WindowsEtwRecord {
                record_ordinal: filter_ordinal,
                json_pointer: filter_pointer,
                raw_payload_sha256: filter_hash,
            },
            EvidenceReference::WindowsEtwRecord {
                record_ordinal,
                json_pointer,
                raw_payload_sha256,
            },
        ) => {
            filter_ordinal == record_ordinal
                && filter_pointer == json_pointer
                && filter_hash == raw_payload_sha256
        }
        _ => false,
    }
}

fn valid_etw_event_pointer(pointer: &str) -> bool {
    let Some(index) = pointer.strip_prefix("/events/") else {
        return false;
    };
    if index.is_empty()
        || index.len() > 5
        || (index.len() > 1 && index.starts_with('0'))
        || !index.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    index
        .parse::<usize>()
        .is_ok_and(|value| value < crate::windows_runtime::MAX_WINDOWS_RUNTIME_EVENTS)
}

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Helps callers retain the source's partial/unknown exit status.
pub fn source_is_complete(state: &SourceState) -> bool {
    state.completeness == SourceCompleteness::Complete
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event;
    use crate::limits::ParseLimits;
    use crate::trace::strace::parse_trace_bytes;

    fn linux_envelope(bytes: &[u8]) -> CommonEventEnvelope {
        let trace = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
        event::from_linux_strace(&trace, bytes, "synthetic-query-fixture")
    }

    fn query(filters: EventQueryFilters, limit: u32) -> EventQuery {
        EventQuery {
            schema: QUERY_SCHEMA.to_owned(),
            schema_version: QUERY_SCHEMA_VERSION,
            filters,
            limit,
        }
    }

    fn complete_session_query_result(
        completeness: &str,
        collection_status: Option<&str>,
    ) -> SessionEventQueryResult {
        let envelope = linux_envelope(b"123 1700000000.1 close(1) = 0\n");
        let event_query_result =
            execute_query(&envelope, &query(EventQueryFilters::default(), 5)).unwrap();
        SessionEventQueryResult {
            schema: SESSION_QUERY_RESULT_SCHEMA,
            schema_version: SESSION_QUERY_RESULT_SCHEMA_VERSION,
            session: SessionQueryIdentity {
                session_id: "synthetic-session".to_owned(),
                manifest_schema_version: 7,
                platform: "linux".to_owned(),
                status: crate::audit_session::SessionStatus::Complete,
                started_at_unix_ms: 1,
                ended_at_unix_ms: 2,
            },
            runtime_source: SessionRuntimeSource {
                role: crate::audit_session::SourceRole::Runtime,
                platform: "linux".to_owned(),
                scope: "synthetic fixture".to_owned(),
                started_at_unix_ms: 1,
                ended_at_unix_ms: 2,
                status: crate::audit_session::SourceStatus::Complete,
                collector: None,
                loss: None,
                diagnostic_codes: Vec::new(),
                artifacts: Vec::new(),
            },
            capture: SessionCaptureStatus {
                completeness: completeness.to_owned(),
                collection_status: collection_status.map(str::to_owned),
                stop_reason: None,
            },
            event_query_result,
        }
    }

    #[test]
    fn session_query_exit_gate_requires_complete_capture_statuses() {
        assert!(!session_source_is_complete(&complete_session_query_result(
            "unknown", None
        )));
        assert!(!session_source_is_complete(&complete_session_query_result(
            "complete",
            Some("partial")
        )));
        assert!(session_source_is_complete(&complete_session_query_result(
            "complete", None
        )));
        assert!(session_source_is_complete(&complete_session_query_result(
            "complete",
            Some("complete")
        )));
    }

    #[test]
    fn multi_session_summary_aggregates_counts_and_never_promotes_partial_evidence() {
        let complete = complete_session_query_result("complete", None);
        let mut partial = complete_session_query_result("unknown", None);
        partial.session.session_id = "other-session".to_owned();
        partial.event_query_result.matched_count = 2;
        let result = multi_session_query_result(vec![complete, partial]).unwrap();
        assert_eq!(result.schema, MULTI_SESSION_QUERY_RESULT_SCHEMA);
        assert_eq!(result.session_count, 2);
        assert_eq!(result.matched_count, 3);
        assert!(!result.complete);
        assert_eq!(result.sessions[0].session.session_id, "synthetic-session");
        assert_eq!(result.sessions[1].session.session_id, "other-session");
    }

    #[test]
    fn multi_session_summary_rejects_duplicate_ids_and_out_of_range_counts() {
        let first = complete_session_query_result("complete", None);
        let second = complete_session_query_result("complete", None);
        assert!(multi_session_query_result(vec![first.clone()]).is_err());
        assert!(multi_session_query_result(vec![first.clone(), second]).is_err());
        let too_many =
            vec![complete_session_query_result("complete", None); MAX_QUERY_SESSIONS + 1];
        assert!(multi_session_query_result(too_many).is_err());
    }

    #[test]
    fn strict_query_contract_rejects_unknown_fields_and_unsupported_values() {
        assert!(EventQuery::from_json(
            br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"path":"/tmp"}}"#
        )
        .is_err());
        assert!(
            EventQuery::from_json(
                br#"{"schema":"sideeffect.event_query","schema_version":1,"limit":5001}"#
            )
            .is_err()
        );
        assert!(EventQuery::from_json(&vec![b' '; MAX_QUERY_BYTES + 1]).is_err());
        for invalid_locator in [
            br#"{"kind":"raw_trace_record","line_number":0,"byte_offset":0,"byte_length":1}"#.as_slice(),
            br#"{"kind":"raw_trace_record","line_number":1,"byte_offset":0,"byte_length":0}"#.as_slice(),
            br#"{"kind":"windows_etw_record","record_ordinal":1,"json_pointer":"/events/00","raw_payload_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.as_slice(),
            br#"{"kind":"windows_etw_record","record_ordinal":1,"json_pointer":"/events/0","raw_payload_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.as_slice(),
        ] {
            let query = serde_json::json!({
                "schema": QUERY_SCHEMA,
                "schema_version": QUERY_SCHEMA_VERSION,
                "filters": { "evidence": serde_json::from_slice::<serde_json::Value>(invalid_locator).unwrap() }
            });
            assert!(EventQuery::from_json(&serde_json::to_vec(&query).unwrap()).is_err());
        }
        assert!(EventQuery::from_json(
            br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"evidence":{"kind":"raw_trace_record","line_number":1,"line_number":2,"byte_offset":0,"byte_length":1}}}"#
        )
        .is_err());
        let high_physical_line = serde_json::json!({
            "schema": QUERY_SCHEMA,
            "schema_version": QUERY_SCHEMA_VERSION,
            "filters": {
                "evidence": {
                    "kind": "raw_trace_record",
                    "line_number": crate::limits::MAX_TRACE_BYTES,
                    "byte_offset": 0,
                    "byte_length": 1
                }
            }
        });
        assert!(EventQuery::from_json(&serde_json::to_vec(&high_physical_line).unwrap()).is_ok());
        assert!(EventQuery::from_json(
            br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"evidence":{"kind":"raw_trace_record","line_number":1,"byte_offset":0,"byte_length":1,"extra":true}}}"#
        )
        .is_err());
    }

    #[test]
    fn query_exact_filters_preserve_full_source_diagnostics_and_evidence() {
        let trace = b"1700000000.000001 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"127.0.0.1\")}, 16) = -1 ECONNREFUSED (Connection refused)\ninvalid row\n";
        let envelope = linux_envelope(trace);
        let result = execute_query(
            &envelope,
            &query(
                EventQueryFilters {
                    event_kind: Some("connect".to_owned()),
                    operation_kind: Some(OperationKind::SyscallAttempt),
                    outcome: Some(OutcomeFilter::Failure),
                    process_observation_id: None,
                    path_exact: None,
                    path_prefix: None,
                    evidence: None,
                },
                10,
            ),
        )
        .unwrap();
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].event_kind, "connect");
        assert_eq!(result.events[0].evidence, envelope.events[0].evidence);
        assert_eq!(
            result.source_state.completeness,
            SourceCompleteness::Partial
        );
        assert_eq!(result.diagnostics, envelope.diagnostics);
        assert!(
            result
                .source_state
                .diagnostics
                .contains(&"source_parse_partial".to_owned())
        );
    }

    #[test]
    fn query_path_exact_matches_only_supported_literal_path_observations() {
        let trace = b"123 1700000000.1 openat(AT_FDCWD</tmp>, \"one.txt\", O_RDONLY) = 3\n123 1700000000.2 openat(AT_FDCWD</tmp>, \"two.txt\", O_RDONLY) = 4\n123 1700000000.3 openat(AT_FDCWD, \"unknown.txt\", O_RDONLY) = 5\n";
        let envelope = linux_envelope(trace);
        assert_eq!(
            envelope.events[0].path_observation.as_ref().unwrap().path,
            "/tmp/one.txt"
        );
        assert_eq!(
            envelope.events[1].path_observation.as_ref().unwrap().path,
            "/tmp/two.txt"
        );
        assert!(envelope.events[2].path_observation.is_none());

        let exact = execute_query(
            &envelope,
            &query(
                EventQueryFilters {
                    path_exact: Some("/tmp/one.txt".to_owned()),
                    ..EventQueryFilters::default()
                },
                5,
            ),
        )
        .unwrap();
        assert_eq!(exact.matched_count, 1);
        assert_eq!(exact.events[0].event_kind, "openat");
        assert_eq!(
            exact.events[0].path_observation.as_ref().unwrap().path,
            "/tmp/one.txt"
        );

        for unmatched in ["/tmp/one", "/tmp/ONE.txt", "/tmp/unknown.txt"] {
            let result = execute_query(
                &envelope,
                &query(
                    EventQueryFilters {
                        path_exact: Some(unmatched.to_owned()),
                        ..EventQueryFilters::default()
                    },
                    5,
                ),
            )
            .unwrap();
            assert_eq!(result.matched_count, 0, "filter: {unmatched}");
            assert_eq!(result.source_state, envelope.source_state);
            assert_eq!(result.diagnostics, envelope.diagnostics);
        }
    }

    #[test]
    fn query_path_prefix_is_a_case_sensitive_literal_string_prefix() {
        let trace = b"123 1700000000.1 openat(AT_FDCWD</tmp>, \"alpha\", O_RDONLY) = 3\n123 1700000000.2 openat(AT_FDCWD</tmp>, \"alphabet\", O_RDONLY) = 4\n123 1700000000.3 openat(AT_FDCWD</tmp>, \"Alpha\", O_RDONLY) = 5\n123 1700000000.4 openat(AT_FDCWD, \"unknown\", O_RDONLY) = 6\n";
        let envelope = linux_envelope(trace);
        let prefix = execute_query(
            &envelope,
            &query(
                EventQueryFilters {
                    path_prefix: Some("/tmp/alpha".to_owned()),
                    ..EventQueryFilters::default()
                },
                5,
            ),
        )
        .unwrap();
        assert_eq!(prefix.matched_count, 2);
        assert_eq!(
            prefix.events[0].path_observation.as_ref().unwrap().path,
            "/tmp/alpha"
        );
        assert_eq!(
            prefix.events[1].path_observation.as_ref().unwrap().path,
            "/tmp/alphabet"
        );
        assert_eq!(prefix.source_state, envelope.source_state);
        assert_eq!(prefix.diagnostics, envelope.diagnostics);
    }

    #[test]
    fn path_exact_query_contract_is_bounded_and_versioned() {
        assert!(EventQuery::from_json(
            br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"path_exact":"/tmp/x"}}"#
        )
        .is_err());
        let oversized = "x".repeat(MAX_PATH_FILTER_BYTES + 1);
        for invalid in ["", "x\ny", oversized.as_str()] {
            let value = serde_json::json!({
                "schema": QUERY_SCHEMA,
                "schema_version": 2,
                "filters": { "path_exact": invalid }
            });
            assert!(EventQuery::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let injection_text = "<script>alert(1)</script>";
        let accepted = serde_json::json!({
            "schema": QUERY_SCHEMA,
            "schema_version": 2,
            "filters": { "path_exact": injection_text }
        });
        let query = EventQuery::from_json(&serde_json::to_vec(&accepted).unwrap()).unwrap();
        assert_eq!(query.filters.path_exact.as_deref(), Some(injection_text));

        for version in [1, 2] {
            let legacy_with_prefix = serde_json::json!({
                "schema": QUERY_SCHEMA,
                "schema_version": version,
                "filters": { "path_prefix": "/tmp" }
            });
            assert!(
                EventQuery::from_json(&serde_json::to_vec(&legacy_with_prefix).unwrap()).is_err()
            );
        }
        let oversized_prefix = serde_json::json!({
            "schema": QUERY_SCHEMA,
            "schema_version": 3,
            "filters": { "path_prefix": "x".repeat(MAX_PATH_FILTER_BYTES + 1) }
        });
        assert!(EventQuery::from_json(&serde_json::to_vec(&oversized_prefix).unwrap()).is_err());
        for invalid in ["", "x\ny"] {
            let value = serde_json::json!({
                "schema": QUERY_SCHEMA,
                "schema_version": 3,
                "filters": { "path_prefix": invalid }
            });
            assert!(EventQuery::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }

    #[test]
    fn overflow_is_an_error_and_never_silently_truncates_results() {
        let envelope =
            linux_envelope(b"123 1700000000.1 close(1) = 0\n123 1700000000.2 close(2) = 0\n");
        let error = execute_query(&envelope, &query(EventQueryFilters::default(), 1)).unwrap_err();
        assert!(error.contains("matched more than its 1-row limit"));
    }

    #[test]
    fn source_local_process_filter_keeps_exact_linked_observation() {
        let envelope = linux_envelope(b"123 1700000000.1 close(1) = 0\n");
        let result = execute_query(
            &envelope,
            &query(
                EventQueryFilters {
                    process_observation_id: Some(1),
                    ..EventQueryFilters::default()
                },
                5,
            ),
        )
        .unwrap();
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.event_process_links.len(), 1);
        assert_eq!(
            result.event_process_links[0].process_observation_id,
            Some(1)
        );
        assert_eq!(result.process_observations.len(), 1);
        assert_eq!(result.process_observations[0].source_local_id, 1);
    }

    #[test]
    fn synthetic_windows_normalized_event_uses_the_same_allowlisted_contract() {
        let mut envelope = linux_envelope(b"123 1700000000.1 close(1) = 0\n");
        envelope.source.platform = crate::event::SourcePlatform::Windows;
        envelope.source.schema = "sideeffect.windows_runtime_capture".to_owned();
        envelope.source.schema_version = 3;
        envelope.events[0].event_kind = "file_io".to_owned();
        envelope.events[0].operation = OperationSemantics::NativeObservation;
        envelope.events[0].evidence = crate::event::EvidenceReference::WindowsEtwRecord {
            record_ordinal: 7,
            json_pointer: "/events/6".to_owned(),
            raw_payload_sha256: "a".repeat(64),
        };
        envelope.event_process_links.clear();
        let result = execute_query(
            &envelope,
            &query(
                EventQueryFilters {
                    event_kind: Some("file_io".to_owned()),
                    operation_kind: Some(OperationKind::NativeObservation),
                    ..EventQueryFilters::default()
                },
                5,
            ),
        )
        .unwrap();
        assert_eq!(
            result.source.platform,
            crate::event::SourcePlatform::Windows
        );
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].evidence, envelope.events[0].evidence);
    }
}
