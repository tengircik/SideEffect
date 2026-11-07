use sideeffect::audit_session::{ArtifactKind, SessionArtifactRef, SourceStatus};
use sideeffect::query::{StartupQuery, StartupQueryInput, query_startup_artifact};

fn query() -> StartupQuery {
    StartupQuery::from_json(br#"{"schema":"sideeffect.startup_query","schema_version":1}"#).unwrap()
}

fn query_source(bytes: &[u8]) -> Result<sideeffect::query::StartupQuerySource, String> {
    let artifact = SessionArtifactRef {
        kind: ArtifactKind::Startup,
        path: "startup.json".to_owned(),
        schema: "sideeffect.startup_inventory".to_owned(),
        schema_version: 3,
        byte_length: bytes.len() as u64,
        sha256: "0".repeat(64),
    };
    query_startup_artifact(
        StartupQueryInput {
            platform: "linux",
            source_status: SourceStatus::Complete,
            scope: Some("synthetic test".to_owned()),
            started_at_unix_ms: Some(1),
            ended_at_unix_ms: Some(2),
            diagnostic_codes: Vec::new(),
            artifact: Some(&artifact),
            bytes: Some(bytes),
        },
        &query(),
    )
}

fn query_windows_startup_artifact(version: u32, bytes: &[u8]) -> Result<(), String> {
    let artifact = SessionArtifactRef {
        kind: ArtifactKind::WindowsStartup,
        path: "startup.windows.json".to_owned(),
        schema: "sideeffect.windows_startup_inventory".to_owned(),
        schema_version: version,
        byte_length: bytes.len() as u64,
        sha256: "0".repeat(64),
    };
    query_startup_artifact(
        StartupQueryInput {
            platform: "windows",
            source_status: SourceStatus::Complete,
            scope: Some("synthetic test".to_owned()),
            started_at_unix_ms: Some(1),
            ended_at_unix_ms: Some(2),
            diagnostic_codes: Vec::new(),
            artifact: Some(&artifact),
            bytes: Some(bytes),
        },
        &query(),
    )
    .map(|_| ())
}

#[test]
fn malformed_nested_component_is_rejected_instead_of_reported_complete() {
    let bytes = br#"{
        "schema":"sideeffect.startup_inventory","schema_version":3,"platform":"linux",
        "scope":"synthetic test","capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,
        "status":"complete","xdg_autostart":{"schema":"sideeffect.xdg_autostart_inventory","schema_version":2,"platform":"linux","status":"complete","entries":[],"directories":[]},
        "systemd_units":"malformed","legacy_sources":{"schema":"sideeffect.legacy_startup_inventory","schema_version":2,"platform":"linux","status":"complete","entries":[],"sources":[]}
    }"#;
    assert!(query_source(bytes).is_err());
}

#[test]
fn complete_inventory_cannot_hide_partial_nested_component_status() {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema":"sideeffect.startup_inventory","schema_version":3,"platform":"linux",
        "scope":"synthetic test","capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,
        "status":"complete",
        "xdg_autostart":{"schema":"sideeffect.xdg_autostart_inventory","schema_version":2,"platform":"linux","status":"complete","entries":[],"directories":[]},
        "systemd_units":{"schema":"sideeffect.systemd_units","schema_version":2,"platform":"linux","status":"partial","records":[],"directories":[]},
        "legacy_sources":{"schema":"sideeffect.legacy_startup_inventory","schema_version":2,"platform":"linux","status":"complete","entries":[],"sources":[]}
    }))
    .unwrap();
    assert!(query_source(&bytes).is_err());
}

#[test]
fn diagnostics_limit_rejects_oversized_collection() {
    let diagnostic_values = std::iter::repeat_n("null", 20_000)
        .collect::<Vec<_>>()
        .join(",");
    let bytes = format!(
        "{{\"schema\":\"sideeffect.startup_inventory\",\"schema_version\":3,\"platform\":\"linux\",\"scope\":\"synthetic test\",\"capture_started_at_unix_ms\":1,\"capture_ended_at_unix_ms\":2,\"status\":\"partial\",\"xdg_autostart\":{{\"schema\":\"sideeffect.xdg_autostart_inventory\",\"schema_version\":2,\"platform\":\"linux\",\"status\":\"partial\",\"entries\":[],\"directories\":[{{\"diagnostics\":[{diagnostic_values}]}}]}},\"systemd_units\":{{\"schema\":\"sideeffect.systemd_units\",\"schema_version\":2,\"platform\":\"linux\",\"status\":\"partial\",\"records\":[],\"directories\":[]}},\"legacy_sources\":{{\"schema\":\"sideeffect.legacy_startup_inventory\",\"schema_version\":2,\"platform\":\"linux\",\"status\":\"partial\",\"entries\":[],\"sources\":[]}}}}"
    );
    let result = query_source(bytes.as_bytes());
    assert!(result.is_err());
}

#[test]
fn windows_startup_wmi_collections_follow_historical_schema_contract() {
    let base = r#"{"schema":"sideeffect.windows_startup_inventory","platform":"windows","scope":"synthetic test","capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":"complete","sources":[],"registry_entries":[],"folder_entries":[],"service_entries":[],"scheduled_task_entries":[],"scheduled_task_actions":[]}"#;
    let v5 = base.replace(
        "\"schema\":\"sideeffect.windows_startup_inventory\",\"platform\":",
        "\"schema\":\"sideeffect.windows_startup_inventory\",\"schema_version\":5,\"platform\":",
    );
    assert!(query_windows_startup_artifact(5, v5.as_bytes()).is_ok());
    let v6 = base.replace(
        "\"schema\":\"sideeffect.windows_startup_inventory\",\"platform\":",
        "\"schema\":\"sideeffect.windows_startup_inventory\",\"schema_version\":6,\"platform\":",
    );
    assert!(query_windows_startup_artifact(6, v6.as_bytes()).is_err());
}

#[test]
fn windows_diagnostics_over_limit_are_rejected() {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema":"sideeffect.windows_startup_inventory","schema_version":10,"platform":"windows",
        "scope":"synthetic test","capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,
        "status":"partial","sources":[{"id":"synthetic","status":"partial","entries_seen":0,"diagnostics":vec![serde_json::Value::Null; 2049]}],
        "registry_entries":[],"folder_entries":[],"service_entries":[],"scheduled_task_entries":[],"scheduled_task_actions":[],
        "wmi_event_filters":[],"wmi_event_consumers":[],"wmi_filter_consumer_bindings":[]
    }))
    .unwrap();
    assert!(query_windows_startup_artifact(10, &bytes).is_err());
}
