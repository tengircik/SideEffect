use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(windows)]
use sideeffect::audit_session::{
    ArtifactKind, AuditSessionManifest, AuditSessionSource, ContextFact, ContextFactStatus,
    HostContext, IntervalSemantics, LossMetadata, PrivilegeContext, SessionArtifactRef,
    SessionStatus, SourceRole, SourceStatus,
};
#[cfg(windows)]
use sideeffect::windows_runtime::{
    AppliedLimits, CollectionStatus, EventLoss, SessionMetadata, StopReason, TargetOutcome,
    WindowsRuntimeCapture,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-windows-startup-diff-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create synthetic startup-diff test directory");
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn startup_state() -> Value {
    json!({
        "schema_version":1,
        "configured":"present",
        "effective":{"status":"unknown","context":null,"evidence":null},
        "observed":{"status":"unknown","capture_interval":null,"evidence":null}
    })
}

fn windows_v10() -> Value {
    let source_ids = [
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
        "wmi_permanent_event_subscriptions",
    ];
    json!({
        "schema":"sideeffect.windows_startup_inventory",
        "schema_version":10,
        "platform":"windows",
        "scope":"current_user_and_accessible_machine_run_keys_startup_folders_services_with_delayed_auto_start_dependencies_load_order_group_and_trigger_configuration_and_current_token_visible_tasks_and_local_root_subscription_wmi_objects",
        "capture_started_at_unix_ms":1,
        "capture_ended_at_unix_ms":2,
        "status":"complete",
        "sources":source_ids.into_iter().map(|id| json!({
            "id":id,"status":"complete","entries_seen":0,"diagnostics":[]
        })).collect::<Vec<_>>(),
        "registry_entries":[],
        "folder_entries":[],
        "service_entries":[],
        "scheduled_task_entries":[],
        "scheduled_task_actions":[],
        "wmi_event_filters":[],
        "wmi_event_consumers":[],
        "wmi_filter_consumer_bindings":[]
    })
}

#[cfg(windows)]
fn verified_observation_session(directory: &Path, name: &str) -> PathBuf {
    let mut startup_before = with_entries(
        windows_v10(),
        vec![service("service_start", "stopped", 1)],
        true,
        "C:\\Synthetic\\task.exe",
    );
    let mut startup_after = with_entries(
        windows_v10(),
        vec![service("service_start", "running", 4)],
        true,
        "C:\\Synthetic\\task.exe",
    );
    for startup in [&mut startup_before, &mut startup_after] {
        startup["status"] = json!("partial");
        for source in startup["sources"].as_array_mut().unwrap() {
            source["status"] = json!("partial");
        }
    }
    let artifacts = vec![
        (
            ArtifactKind::SelectedRoot,
            "root-snapshot.json",
            "sideeffect.selected_root_inventory",
            1,
            json!({"schema":"sideeffect.selected_root_inventory","schema_version":1}),
        ),
        (
            ArtifactKind::SelectedRootAfter,
            "root-snapshot-after.json",
            "sideeffect.selected_root_inventory",
            1,
            json!({"schema":"sideeffect.selected_root_inventory","schema_version":1}),
        ),
        (
            ArtifactKind::WindowsRuntimeCapture,
            "runtime.windows.json",
            "sideeffect.windows_runtime_capture",
            3,
            json!({"schema":"sideeffect.windows_runtime_capture","schema_version":3}),
        ),
        (
            ArtifactKind::WindowsStartup,
            "startup.windows.json",
            "sideeffect.windows_startup_inventory",
            10,
            startup_before,
        ),
        (
            ArtifactKind::WindowsStartupAfter,
            "startup-after.windows.json",
            "sideeffect.windows_startup_inventory",
            10,
            startup_after,
        ),
    ];
    let mut references = Vec::new();
    let mut files = Vec::new();
    for (kind, path, schema, version, value) in artifacts {
        let bytes = if path == "runtime.windows.json" {
            synthetic_runtime_capture_bytes()
        } else {
            serde_json::to_vec(&value).unwrap()
        };
        references.push(SessionArtifactRef {
            kind,
            path: path.to_owned(),
            schema: schema.to_owned(),
            schema_version: version,
            byte_length: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
        });
        files.push((path.to_owned(), bytes));
    }
    let sources = vec![
        AuditSessionSource {
            role: SourceRole::SelectedRoot,
            collector: Some(sideeffect::audit_session::collector_identity(
                "windows",
                SourceRole::SelectedRoot,
            )),
            platform: "windows".to_owned(),
            scope: "synthetic selected-root observation fixture".to_owned(),
            started_at_unix_ms: 1000,
            ended_at_unix_ms: 1002,
            status: SourceStatus::Partial,
            applied_limits: vec![],
            requested_settings: vec![],
            effective_settings: vec![],
            loss: None,
            diagnostic_codes: vec!["synthetic_fixture_only".to_owned()],
            artifacts: references[0..2].to_vec(),
        },
        AuditSessionSource {
            role: SourceRole::Runtime,
            collector: Some(sideeffect::audit_session::collector_identity(
                "windows",
                SourceRole::Runtime,
            )),
            platform: "windows".to_owned(),
            scope: "synthetic fixture only; no live ETW capture".to_owned(),
            started_at_unix_ms: 1000,
            ended_at_unix_ms: 1002,
            status: SourceStatus::Partial,
            applied_limits: vec![],
            requested_settings: vec![],
            effective_settings: vec![],
            loss: Some(LossMetadata::unknown()),
            diagnostic_codes: vec!["synthetic_fixture_only".to_owned()],
            artifacts: references[2..3].to_vec(),
        },
        AuditSessionSource {
            role: SourceRole::Startup,
            collector: Some(sideeffect::audit_session::collector_identity(
                "windows",
                SourceRole::Startup,
            )),
            platform: "windows".to_owned(),
            scope: "synthetic before/after startup fixture".to_owned(),
            started_at_unix_ms: 1000,
            ended_at_unix_ms: 1002,
            status: SourceStatus::Partial,
            applied_limits: vec![],
            requested_settings: vec![],
            effective_settings: vec![],
            loss: None,
            diagnostic_codes: vec!["synthetic_fixture_only".to_owned()],
            artifacts: references[3..5].to_vec(),
        },
    ];
    let mut manifest = AuditSessionManifest {
        schema: "sideeffect.audit_session".to_owned(),
        schema_version: sideeffect::audit_session::AUDIT_SESSION_V17_SCHEMA_VERSION,
        session_id: "0123456789abcdef0123456789abcdef".to_owned(),
        platform: "windows".to_owned(),
        architecture: "x86_64".to_owned(),
        host_context: Some(HostContext {
            os_name: ContextFact {
                status: ContextFactStatus::Observed,
                value: Some("Windows".to_owned()),
            },
            os_version: ContextFact {
                status: ContextFactStatus::Unknown,
                value: None,
            },
            privilege: PrivilegeContext::Unknown,
        }),
        started_at_unix_ms: 1000,
        ended_at_unix_ms: 1002,
        interval_semantics: IntervalSemantics::BestEffortNonAtomic,
        status: SessionStatus::Partial,
        coverage_manifest: None,
        sources,
    };
    manifest.coverage_manifest = Some(sideeffect::audit_session::CoverageManifest::from_sources(
        &manifest.sources,
    ));
    manifest.validate().unwrap();
    let mut published_files: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect();
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    published_files.push(("session.json", &manifest_bytes));
    let path = directory.join(name);
    sideeffect::record::publish_private_windows_directory(&path, &published_files, 8 * 1024 * 1024)
        .unwrap();
    path
}

#[cfg(windows)]
fn synthetic_runtime_capture_bytes() -> Vec<u8> {
    let mut capture = WindowsRuntimeCapture {
        schema: sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
        schema_version: sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        platform: "windows".to_owned(),
        capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
        collection_status: CollectionStatus::Partial,
        capture_completeness: "unknown".to_owned(),
        started_at_unix_ms: 1000,
        ended_at_unix_ms: 1002,
        requested_duration_seconds: 1,
        stop_reason: StopReason::EtwStatisticsUnavailable,
        target: TargetOutcome {
            process_id: 42,
            exit_code: Some(0),
            status_available: true,
        },
        session: SessionMetadata {
            name: "synthetic_fixture".to_owned(),
            provider: "synthetic fixture only".to_owned(),
            scope: "synthetic_fixture_only".to_owned(),
            buffer_size_kb_requested: 16,
            minimum_buffers_requested: 8,
            maximum_buffers_requested: 32,
            buffer_count_reported: 8,
            provider_process_id_header_semantics: "fixture context only".to_owned(),
        },
        limits: AppliedLimits {
            maximum_duration_seconds: 60,
            maximum_events: 50_000,
            maximum_total_payload_bytes: 8 * 1024 * 1024,
            maximum_payload_bytes_per_event: 64 * 1024,
            maximum_document_bytes: 32 * 1024 * 1024,
        },
        event_loss: EventLoss {
            events_lost: 0,
            log_buffers_lost: 0,
            real_time_buffers_lost: 0,
            loss_statistics_available: false,
            observation: "unavailable".to_owned(),
            final_snapshot_available: false,
        },
        document_sha256: String::new(),
        events: vec![],
        diagnostics: vec!["synthetic_fixture_not_a_live_capture".to_owned()],
    };
    let canonical = serde_json::to_vec(&capture).unwrap();
    capture.document_sha256 = format!("{:x}", Sha256::digest(canonical));
    serde_json::to_vec(&capture).unwrap()
}

fn service(trigger_action: &str, state: &str, raw_state_code: u64) -> Value {
    json!({
        "service_name":"SyntheticService",
        "display_name":"Synthetic Service",
        "start_type":"automatic",
        "start_type_code":2,
        "account":null,
        "binary_path":"C:\\Synthetic\\service.exe",
        "startup_state":startup_state(),
        "service_observation":{"status":"known","state":state,"raw_state_code":raw_state_code},
        "delayed_auto_start":{"status":"observed","value":false},
        "dependencies":{"status":"observed","entries":[]},
        "load_order_group":{"status":"observed","value":null},
        "triggers":{"status":"observed","entries":[{
            "trigger_index":0,
            "trigger_type_code":1,
            "trigger_type":"device_interface_arrival",
            "action_code":if trigger_action == "service_start" { 1 } else { 2 },
            "action":trigger_action,
            "subtype_guid":"1234abcd-5678-9abc-def0-123456789abc",
            "data_items":[]
        }]},
        "evidence":{"source":"EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W","service_index":0}
    })
}

fn task(trigger_enabled: bool, action_path: &str) -> (Value, Value) {
    let task_path = "\\Synthetic\\Task";
    let task_row = json!({
        "task_path":task_path,
        "task_enabled":true,
        "trigger_type":"boot",
        "trigger_enabled":trigger_enabled,
        "logon_user":null,
        "startup_state":startup_state(),
        "evidence":{"source":"Task Scheduler IRegisteredTask/ITaskDefinition/ITrigger","task_index":0,"trigger_index":0}
    });
    let action_row = json!({
        "task_path":task_path,
        "action_index":0,
        "action_type":"exec",
        "action_type_code":0,
        "status":"observed",
        "executable_path":action_path,
        "arguments":null,
        "working_directory":null,
        "startup_state":startup_state(),
        "evidence":{"source":"Task Scheduler IActionCollection/IExecAction","task_index":0,"action_index":0}
    });
    (task_row, action_row)
}

fn with_entries(
    mut doc: Value,
    service_rows: Vec<Value>,
    task_enabled: bool,
    action_path: &str,
) -> Value {
    let (task_row, action_row) = task(task_enabled, action_path);
    doc["service_entries"] = json!(service_rows);
    doc["scheduled_task_entries"] = json!([task_row]);
    doc["scheduled_task_actions"] = json!([action_row]);
    doc["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["id"] == "service_start_configuration")
        .unwrap()["entries_seen"] = json!(service_rows.len());
    doc["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["id"] == "scheduled_task_triggers")
        .unwrap()["entries_seen"] = json!(2);
    doc
}

fn write_document(dir: &Path, name: &str, document: &Value) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, serde_json::to_vec(document).unwrap()).unwrap();
    path
}

fn compare(before: &Path, after: &Path) -> (Value, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(before)
        .arg(after)
        .output()
        .expect("run synthetic Windows startup inventory diff CLI");
    let code = output.status.code().expect("CLI exits with a status code");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "CLI output was not JSON ({error}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(report["schema"], "sideeffect.startup_inventory_diff");
    (report, code)
}

#[test]
fn windows_v10_service_and_task_lifecycle_diffs_keep_configuration_evidence() {
    let temp = TempDirectory::new();
    let empty = windows_v10();
    let installed = with_entries(
        windows_v10(),
        vec![service("service_start", "stopped", 1)],
        true,
        "C:\\Synthetic\\task.exe",
    );
    let changed = with_entries(
        windows_v10(),
        vec![service("service_stop", "stopped", 1)],
        false,
        "C:\\Synthetic\\task-updated.exe",
    );
    let empty_path = write_document(&temp.0, "empty.json", &empty);
    let installed_path = write_document(&temp.0, "installed.json", &installed);
    let changed_path = write_document(&temp.0, "changed.json", &changed);

    let (added, code) = compare(&empty_path, &installed_path);
    assert_eq!(code, 0);
    assert_eq!(added["counts"]["observed_after_only"], 3);
    let categories = added["deltas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|delta| delta["category"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(categories.contains(&"service_configuration"));
    assert!(categories.contains(&"scheduled_task_trigger"));
    assert!(categories.contains(&"scheduled_task_action_sequence"));
    assert!(added["deltas"].as_array().unwrap().iter().all(|delta| {
        delta["after"]["references"]
            .as_array()
            .is_some_and(|refs| !refs.is_empty())
    }));

    let (updated, code) = compare(&installed_path, &changed_path);
    assert_eq!(code, 0);
    assert_eq!(updated["counts"]["changed"], 3);
    let service_change = updated["deltas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|delta| delta["category"] == "service_configuration")
        .unwrap();
    assert_eq!(service_change["changed_fields"], json!(["triggers"]));
    assert_eq!(
        service_change["before"]["references"],
        json!(["/service_entries/0"])
    );
    assert_eq!(
        service_change["after"]["references"],
        json!(["/service_entries/0"])
    );
    let task_change = updated["deltas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|delta| delta["category"] == "scheduled_task_trigger")
        .unwrap();
    assert_eq!(task_change["changed_fields"], json!(["trigger_enabled"]));
    let action_change = updated["deltas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|delta| delta["category"] == "scheduled_task_action_sequence")
        .unwrap();
    assert_eq!(action_change["changed_fields"], json!(["action_sequence"]));

    let (removed, code) = compare(&changed_path, &empty_path);
    assert_eq!(code, 0);
    assert_eq!(removed["counts"]["observed_before_only"], 3);
    assert!(removed["deltas"].as_array().unwrap().iter().all(|delta| {
        delta["before"]["references"]
            .as_array()
            .is_some_and(|refs| !refs.is_empty())
            && delta["after"].is_null()
    }));
}

#[test]
fn windows_v10_inaccessible_source_suppresses_unmatched_service_and_task_presence() {
    let temp = TempDirectory::new();
    let before = with_entries(
        windows_v10(),
        vec![service("service_start", "stopped", 1)],
        true,
        "C:\\Synthetic\\task.exe",
    );
    let mut after = windows_v10();
    after["status"] = json!("partial");
    after["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["id"] == "service_start_configuration")
        .unwrap()["status"] = json!("inaccessible");
    after["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["id"] == "scheduled_task_triggers")
        .unwrap()["status"] = json!("inaccessible");
    let before_path = write_document(&temp.0, "before.json", &before);
    let after_path = write_document(&temp.0, "after.json", &after);
    let (report, code) = compare(&before_path, &after_path);
    assert_eq!(code, 2);
    assert_eq!(report["status"], "partial");
    assert_eq!(report["counts"]["observed_before_only"], 0);
    assert_eq!(
        report["counts"]["unmatched_rows_suppressed_for_incomplete_source"],
        3
    );
    assert!(report["deltas"].as_array().unwrap().is_empty());
}

#[test]
fn windows_v10_scm_state_is_separate_from_startup_configuration_and_observed_activity() {
    let temp = TempDirectory::new();
    let before = with_entries(
        windows_v10(),
        vec![service("service_start", "stopped", 1)],
        true,
        "C:\\Synthetic\\task.exe",
    );
    let after = with_entries(
        windows_v10(),
        vec![service("service_start", "running", 4)],
        true,
        "C:\\Synthetic\\task.exe",
    );
    let before_path = write_document(&temp.0, "state-before.json", &before);
    let after_path = write_document(&temp.0, "state-after.json", &after);
    let (report, code) = compare(&before_path, &after_path);
    assert_eq!(code, 0);
    assert_eq!(report["counts"]["changed"], 1);
    let delta = &report["deltas"][0];
    assert_eq!(delta["category"], "service_configuration");
    assert_eq!(delta["changed_fields"], json!(["service_observation"]));
    assert_eq!(
        before["service_entries"][0]["startup_state"]["observed"]["status"],
        "unknown"
    );
    assert_eq!(
        after["service_entries"][0]["startup_state"]["observed"]["status"],
        "unknown"
    );
    assert_eq!(
        before["scheduled_task_entries"][0]["startup_state"]["observed"]["status"],
        "unknown"
    );
    assert_eq!(
        before["scheduled_task_actions"][0]["startup_state"]["observed"]["status"],
        "unknown"
    );
}

#[cfg(windows)]
#[test]
fn compare_observation_v17_reads_paired_partial_startup_and_rejects_missing_or_tampered_artifacts()
{
    let temp = TempDirectory::new();
    let valid_session = verified_observation_session(&temp.0, "valid-v17");
    let compared = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-observation")
        .arg(&valid_session)
        .output()
        .unwrap();
    assert_eq!(
        compared.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&compared.stderr)
    );
    let report: Value = serde_json::from_slice(&compared.stdout).unwrap();
    assert_eq!(report["status"], "partial");
    assert_eq!(report["startup_comparison_status"], "partial");
    assert_eq!(report["startup_source_status"], "partial");
    assert_eq!(report["startup_before_document_status"], "partial");
    assert_eq!(report["startup_after_document_status"], "partial");
    assert_eq!(report["startup_diff"]["status"], "partial");
    assert_eq!(report["startup_diff"]["counts"]["changed"], 1);
    assert_eq!(
        report["startup_before_artifact"]["path"],
        "startup.windows.json"
    );
    assert_eq!(
        report["startup_after_artifact"]["path"],
        "startup-after.windows.json"
    );
    for artifact in ["startup_before_artifact", "startup_after_artifact"] {
        assert_eq!(report[artifact]["sha256"].as_str().unwrap().len(), 64);
    }

    let missing_session = verified_observation_session(&temp.0, "missing-v17-artifact");
    fs::remove_file(missing_session.join("startup-after.windows.json")).unwrap();
    let missing = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-observation")
        .arg(&missing_session)
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("could not read audit session"));

    let tampered_session = verified_observation_session(&temp.0, "tampered-v17-artifact");
    let tampered_path = tampered_session.join("startup-after.windows.json");
    let mut tampered_bytes = fs::read(&tampered_path).unwrap();
    let timestamp = b"capture_ended_at_unix_ms\":2";
    let timestamp_end = tampered_bytes
        .windows(timestamp.len())
        .position(|window| window == timestamp)
        .map(|offset| offset + timestamp.len() - 1)
        .expect("synthetic startup fixture timestamp");
    tampered_bytes[timestamp_end] = b'3';
    fs::write(tampered_path, tampered_bytes).unwrap();
    let tampered = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-observation")
        .arg(&tampered_session)
        .output()
        .unwrap();
    assert_eq!(tampered.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&tampered.stderr).contains("does not match its declared SHA-256")
    );
}
