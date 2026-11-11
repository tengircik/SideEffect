#![cfg(windows)]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sideeffect::audit_session::{
    AUDIT_SESSION_SCHEMA, AUDIT_SESSION_SCHEMA_VERSION, ArtifactKind, AuditSessionManifest,
    AuditSessionSource, CoverageManifest, IntervalSemantics, LossMetadata, SessionArtifactRef,
    SessionStatus, SourceRole, SourceStatus, collector_identity,
};
use sideeffect::windows_runtime::{
    AppliedLimits, CollectionStatus, DecodedProcessPayload, EventLoss,
    MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES, MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
    MAX_WINDOWS_RUNTIME_EVENTS, MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES, NativeRuntimeEvent,
    ProcessDecodeStatus, SessionMetadata, StopReason, TargetOutcome,
    WINDOWS_RUNTIME_CAPTURE_SCHEMA, WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION, WindowsRuntimeCapture,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-query-session-windows-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn runtime_capture() -> Vec<u8> {
    let mut capture = WindowsRuntimeCapture {
        schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
        schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        platform: "windows".to_owned(),
        capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
        collection_status: CollectionStatus::Complete,
        capture_completeness: "unknown".to_owned(),
        started_at_unix_ms: 1_000,
        ended_at_unix_ms: 1_002,
        requested_duration_seconds: 1,
        stop_reason: StopReason::TargetExited,
        target: TargetOutcome {
            process_id: 42,
            exit_code: Some(0),
            status_available: true,
        },
        session: SessionMetadata {
            name: "NT Kernel Logger".to_owned(),
            provider: "synthetic Windows ETW fixture".to_owned(),
            scope: "synthetic fixture only".to_owned(),
            buffer_size_kb_requested: 16,
            minimum_buffers_requested: 8,
            maximum_buffers_requested: 32,
            buffer_count_reported: 8,
            provider_process_id_header_semantics: "header PID/TID is event context only".to_owned(),
        },
        limits: AppliedLimits {
            maximum_duration_seconds: 60,
            maximum_events: MAX_WINDOWS_RUNTIME_EVENTS,
            maximum_total_payload_bytes: MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES,
            maximum_payload_bytes_per_event: MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
            maximum_document_bytes: MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        },
        event_loss: EventLoss {
            events_lost: 0,
            log_buffers_lost: 0,
            real_time_buffers_lost: 0,
            loss_statistics_available: true,
            observation: "zero_reported".to_owned(),
            final_snapshot_available: true,
        },
        document_sha256: String::new(),
        events: vec![NativeRuntimeEvent {
            record_ordinal: 1,
            provider_guid: "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}".to_owned(),
            event_id: 0,
            event_version: 2,
            opcode: 1,
            event_kind: "process_start".to_owned(),
            header_process_id: 8,
            header_thread_id: 9,
            header_flags: 0x0040,
            timestamp_qpc: 10,
            raw_payload_hex: "00000000000000002a00000001000000".to_owned(),
            payload_decoding: Some(DecodedProcessPayload {
                status: ProcessDecodeStatus::Decoded,
                schema_name: Some("Process_V2_TypeGroup1".to_owned()),
                schema_version: Some(2),
                pointer_size_bytes: Some(8),
                process_id: Some(42),
                parent_process_id: Some(1),
                image_file_name: Some("synthetic.exe".to_owned()),
                diagnostic: None,
            }),
            observation_decoding: None,
        }],
        diagnostics: Vec::new(),
    };
    let canonical = serde_json::to_vec(&capture).unwrap();
    capture.document_sha256 = digest(&canonical);
    serde_json::to_vec(&capture).unwrap()
}

fn runtime_capture_with_file_path(path: &str) -> Vec<u8> {
    let mut capture: WindowsRuntimeCapture = serde_json::from_slice(&runtime_capture()).unwrap();
    let mut raw_payload = 0x1122_3344_5566_7788_u64.to_le_bytes().to_vec();
    for unit in path.encode_utf16().chain(std::iter::once(0)) {
        raw_payload.extend_from_slice(&unit.to_le_bytes());
    }
    capture.events.push(NativeRuntimeEvent {
        record_ordinal: 2,
        provider_guid: "90cbdc39-4a3e-11d1-84f4-0000f80464e3".to_owned(),
        event_id: 0,
        event_version: 2,
        opcode: 36,
        event_kind: "file_io_observation".to_owned(),
        header_process_id: 42,
        header_thread_id: 43,
        header_flags: 0x0040,
        timestamp_qpc: 11,
        raw_payload_hex: hex(&raw_payload),
        payload_decoding: None,
        observation_decoding: Some(json!({
            "status": "decoded",
            "diagnostic": null,
            "observation": {
                "schema": "windows.kernel_file_io",
                "schema_version": 2,
                "activity": { "kind": "file", "observation": {
                    "operation": "rundown_name",
                    "thread_id": null,
                    "file_object": 0x1122_3344_5566_7788_u64,
                    "file_key": null,
                    "path": path,
                    "requested_bytes": null,
                    "file_offset": null,
                    "create_options": null,
                    "file_attributes": null,
                    "share_access": null,
                    "information_class": null,
                    "extra_info": null
                } }
            }
        })),
    });
    capture.document_sha256.clear();
    capture.document_sha256 = digest(&serde_json::to_vec(&capture).unwrap());
    serde_json::to_vec(&capture).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    encoded
}

fn session_manifest_with_id(runtime: Option<&[u8]>, session_id: &str) -> Vec<u8> {
    let artifacts = runtime
        .map(|bytes| {
            vec![SessionArtifactRef {
                kind: ArtifactKind::WindowsRuntimeCapture,
                path: "runtime.windows.json".to_owned(),
                schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
                schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
                byte_length: bytes.len() as u64,
                sha256: digest(bytes),
            }]
        })
        .unwrap_or_default();
    let source = AuditSessionSource {
        role: SourceRole::Runtime,
        collector: Some(collector_identity("windows", SourceRole::Runtime)),
        platform: "windows".to_owned(),
        scope: "synthetic fixture only; bounded ETW window".to_owned(),
        started_at_unix_ms: 1_000,
        ended_at_unix_ms: 1_002,
        status: if artifacts.is_empty() {
            SourceStatus::Unavailable
        } else {
            SourceStatus::Partial
        },
        applied_limits: vec![],
        requested_settings: vec![],
        effective_settings: vec![],
        loss: Some(LossMetadata::unknown()),
        diagnostic_codes: if artifacts.is_empty() {
            vec!["runtime_capture_unavailable".to_owned()]
        } else {
            vec!["runtime_capture_completeness_unknown".to_owned()]
        },
        artifacts,
    };
    let mut manifest = AuditSessionManifest {
        schema: AUDIT_SESSION_SCHEMA.to_owned(),
        schema_version: AUDIT_SESSION_SCHEMA_VERSION,
        session_id: session_id.to_owned(),
        platform: "windows".to_owned(),
        architecture: "x86_64".to_owned(),
        started_at_unix_ms: 1_000,
        ended_at_unix_ms: 1_002,
        interval_semantics: IntervalSemantics::BestEffortNonAtomic,
        status: SessionStatus::Partial,
        sources: vec![source],
        host_context: Some(sideeffect::audit_session::HostContext {
            os_name: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some("Windows".to_owned()),
            },
            os_version: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some("synthetic fixture".to_owned()),
            },
            privilege: sideeffect::audit_session::PrivilegeContext::NotElevated,
        }),
        coverage_manifest: None,
    };
    manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));
    manifest.validate().unwrap();
    serde_json::to_vec(&manifest).unwrap()
}

fn publish_session(directory: &std::path::Path, runtime: Option<Vec<u8>>) {
    publish_session_with_id(directory, runtime, "0123456789abcdef0123456789abcdef");
}

fn publish_session_with_id(
    directory: &std::path::Path,
    runtime: Option<Vec<u8>>,
    session_id: &str,
) {
    let manifest = session_manifest_with_id(runtime.as_deref(), session_id);
    let mut files = vec![("session.json", manifest.as_slice())];
    if let Some(runtime) = runtime.as_ref() {
        files.push(("runtime.windows.json", runtime.as_slice()));
    }
    sideeffect::record::publish_private_windows_directory(directory, &files, 16 * 1024 * 1024)
        .unwrap();
}

fn publish_startup_session(directory: &std::path::Path, session_id: &str) {
    let startup = serde_json::to_vec(&json!({
        "schema":"sideeffect.windows_startup_inventory", "schema_version":10, "platform":"windows",
        "scope":"synthetic fixture only", "capture_started_at_unix_ms":1000,
        "capture_ended_at_unix_ms":1001, "status":"partial",
        "sources":[{"id":"registry_run_current_user","status":"partial","entries_seen":1,"diagnostics":[]}],
        "registry_entries":[{"value_name":"Synthetic","command":"C:\\Tools\\App.exe","command_utf16_hex":"43003a005c0054006f006f006c0073005c004100700070002e00650078006500","evidence":{"source":"registry_run_current_user","value_index":0}}],
        "folder_entries":[], "service_entries":[], "scheduled_task_entries":[], "scheduled_task_actions":[],
        "wmi_event_filters":[], "wmi_event_consumers":[], "wmi_filter_consumer_bindings":[]
    })).unwrap();
    let artifact = SessionArtifactRef {
        kind: ArtifactKind::WindowsStartup,
        path: "startup.windows.json".into(),
        schema: "sideeffect.windows_startup_inventory".into(),
        schema_version: 10,
        byte_length: startup.len() as u64,
        sha256: digest(&startup),
    };
    let source = AuditSessionSource {
        role: SourceRole::Startup,
        collector: Some(collector_identity("windows", SourceRole::Startup)),
        platform: "windows".into(),
        scope: "synthetic fixture only".into(),
        started_at_unix_ms: 1000,
        ended_at_unix_ms: 1001,
        status: SourceStatus::Partial,
        applied_limits: vec![],
        requested_settings: vec![],
        effective_settings: vec![],
        loss: None,
        diagnostic_codes: vec!["synthetic_partial".into()],
        artifacts: vec![artifact],
    };
    let mut manifest = AuditSessionManifest {
        schema: AUDIT_SESSION_SCHEMA.into(),
        schema_version: AUDIT_SESSION_SCHEMA_VERSION,
        session_id: session_id.into(),
        platform: "windows".into(),
        architecture: "x86_64".into(),
        started_at_unix_ms: 1000,
        ended_at_unix_ms: 1001,
        interval_semantics: IntervalSemantics::BestEffortNonAtomic,
        status: SessionStatus::Partial,
        sources: vec![source],
        host_context: Some(sideeffect::audit_session::HostContext {
            os_name: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some("Windows".into()),
            },
            os_version: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some("synthetic fixture".into()),
            },
            privilege: sideeffect::audit_session::PrivilegeContext::NotElevated,
        }),
        coverage_manifest: None,
    };
    manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));
    manifest.validate().unwrap();
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    sideeffect::record::publish_private_windows_directory(
        directory,
        &[
            ("session.json", manifest_bytes.as_slice()),
            ("startup.windows.json", startup.as_slice()),
        ],
        16 * 1024 * 1024,
    )
    .unwrap();
}

#[test]
fn startup_query_multi_session_matches_exact_windows_native_utf16_hex_field() {
    let directory = TestDirectory::new();
    let one = directory.0.join("startup-one");
    let two = directory.0.join("startup-two");
    publish_startup_session(&one, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    publish_startup_session(&two, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let query = directory.0.join("startup-query.json");
    fs::write(&query,br#"{"schema":"sideeffect.startup_query","schema_version":1,"filters":{"source":"registry_run_current_user","field":"command_utf16_hex","value":"43003a005c0054006f006f006c0073005c004100700070002e00650078006500"},"limit":10}"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(query)
        .args(["--session"])
        .arg(&one)
        .args(["--session"])
        .arg(&two)
        .args(["--source", "startup"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["matched_count"], 2);
    assert_eq!(
        result["sessions"][0]["startup_source"]["rows"][0]["json_pointer"],
        "/registry_entries/0"
    );
    assert_eq!(
        result["sessions"][0]["startup_source"]["rows"][0]["evidence"]["source"],
        "registry_run_current_user"
    );
}

fn query(directory: &TestDirectory, session_path: &PathBuf) -> Output {
    let query_path = directory.0.join("query.json");
    fs::write(
        &query_path,
        br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"event_kind":"process_start","operation_kind":"native_observation"}}"#,
    )
    .unwrap();
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(query_path)
        .args(["--session"])
        .arg(session_path)
        .args(["--source", "runtime"])
        .output()
        .unwrap()
}

fn multi_query(directory: &TestDirectory, session_paths: &[&PathBuf], text: bool) -> Output {
    let query_path = directory.0.join("query.json");
    fs::write(
        &query_path,
        br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"event_kind":"process_start","operation_kind":"native_observation"}}"#,
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
    command.args(["query", "--query"]).arg(query_path);
    for session in session_paths {
        command.args(["--session"]).arg(session);
    }
    command.args(["--source", "runtime"]);
    if text {
        command.args(["--format", "text"]);
    }
    command.output().unwrap()
}

fn utf16_hex(value: &str) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::new();
    for byte in value.encode_utf16().flat_map(u16::to_le_bytes) {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn selected_root_document(version: u32, status: &str, display_name: &str) -> Vec<u8> {
    let mut entry = json!({
        "ordinal": 0,
        "display_name": display_name,
        "name_utf16le_hex": utf16_hex("binary"),
        "object_type": "regular_or_other_file",
        "size_bytes": 12,
        "modified_at_unix_ms": 1700000000000i64,
        "device_or_volume_serial": 1,
        "inode_or_file_index": 2,
        "evidence": {"source":"selected_root_directory_entry", "entry_ordinal":0}
    });
    let mut document = json!({
        "schema":"sideeffect.selected_root_inventory",
        "schema_version":version,
        "platform":"windows",
        "scope":if version == 1 { "one_explicit_root_and_its_direct_children_metadata_only" } else { "one_explicit_root_and_its_direct_children_metadata_and_opt_in_sha256" },
        "captured_started_at_unix_ms":1700000000000u64,
        "captured_ended_at_unix_ms":1700000000001u64,
        "status":status,
        "root":{"display_path":"C:\\synthetic\\root","path_utf16le_hex":utf16_hex("C:\\synthetic\\root"),"object_type":"directory","device_or_volume_serial":1,"inode_or_file_index":3},
        "entries":[entry],
        "diagnostics":if status == "partial" { json!([{"code":"content_hash_unavailable","entry_ordinal":0,"native_error":5}]) } else { json!([]) },
        "limits":{"max_root_path_bytes_or_utf16_units":32766,"max_entries":10000,"max_name_bytes_or_utf16_units":32767,"max_aggregate_name_bytes":8388608,"deadline_seconds":5}
    });
    if version == 2 {
        entry["content_sha256"] = json!("b".repeat(64));
        entry["content_hash_status"] = json!("observed");
        document["entries"] = json!([entry]);
        document["content_hashing"] = json!({
            "requested":true,"algorithm":"sha256","max_file_bytes":16777216,
            "max_aggregate_bytes":67108864,"deadline_seconds":5
        });
    }
    serde_json::to_vec(&document).unwrap()
}

fn write_selected_root_session(
    directory: &std::path::Path,
    session_id: &str,
    artifact_bytes: &[u8],
    source_status: SourceStatus,
    schema_version: u32,
) {
    let artifact = SessionArtifactRef {
        kind: ArtifactKind::SelectedRoot,
        path: "root-snapshot.json".to_owned(),
        schema: "sideeffect.selected_root_inventory".to_owned(),
        schema_version,
        byte_length: artifact_bytes.len() as u64,
        sha256: digest(artifact_bytes),
    };
    let source = AuditSessionSource {
        role: SourceRole::SelectedRoot,
        collector: Some(collector_identity("windows", SourceRole::SelectedRoot)),
        platform: "windows".to_owned(),
        scope: "synthetic fixture only; one selected root".to_owned(),
        started_at_unix_ms: 1_000,
        ended_at_unix_ms: 1_002,
        status: source_status,
        applied_limits: vec![],
        requested_settings: vec![],
        effective_settings: vec![],
        loss: None,
        diagnostic_codes: if source_status == SourceStatus::Complete {
            vec![]
        } else {
            vec!["selected_root_partial".to_owned()]
        },
        artifacts: vec![artifact],
    };
    let mut manifest = AuditSessionManifest {
        schema: AUDIT_SESSION_SCHEMA.to_owned(),
        schema_version: AUDIT_SESSION_SCHEMA_VERSION,
        session_id: session_id.to_owned(),
        platform: "windows".to_owned(),
        architecture: "x86_64".to_owned(),
        started_at_unix_ms: 1_000,
        ended_at_unix_ms: 1_002,
        interval_semantics: IntervalSemantics::BestEffortNonAtomic,
        status: if source_status == SourceStatus::Complete {
            SessionStatus::Complete
        } else {
            SessionStatus::Partial
        },
        sources: vec![source],
        host_context: Some(sideeffect::audit_session::HostContext {
            os_name: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some("Windows".to_owned()),
            },
            os_version: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some("synthetic fixture".to_owned()),
            },
            privilege: sideeffect::audit_session::PrivilegeContext::NotElevated,
        }),
        coverage_manifest: None,
    };
    manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));
    let manifest = serde_json::to_vec(&manifest).unwrap();
    sideeffect::record::publish_private_windows_directory(
        directory,
        &[
            ("session.json", manifest.as_slice()),
            ("root-snapshot.json", artifact_bytes),
        ],
        32 * 1024 * 1024,
    )
    .unwrap();
}

fn write_package_session(directory: &Path, session_id: &str, source_status: SourceStatus) {
    let status = if source_status == SourceStatus::Complete {
        "complete"
    } else {
        "partial"
    };
    let artifact_bytes = serde_json::to_vec(&json!({
        "schema":"sideeffect.windows_software_inventory", "schema_version":1, "platform":"windows",
        "scope":"synthetic fixture only", "capture_started_at_unix_ms":1000,"capture_ended_at_unix_ms":1001,
        "status":status,
        "sources":[
            {"id":"current_user_native_uninstall","status":status,"registrations_seen":1,"hive":"HKEY_CURRENT_USER","registry_key":"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall","registry_view":"native","diagnostics":[]},
            {"id":"current_user_32_uninstall","status":"not_present","registrations_seen":0,"hive":"HKEY_CURRENT_USER","registry_key":"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall","registry_view":"wow64_32","diagnostics":[]},
            {"id":"local_machine_64_uninstall","status":"not_present","registrations_seen":0,"hive":"HKEY_LOCAL_MACHINE","registry_key":"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall","registry_view":"wow64_64","diagnostics":[]},
            {"id":"local_machine_32_uninstall","status":"not_present","registrations_seen":0,"hive":"HKEY_LOCAL_MACHINE","registry_key":"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall","registry_view":"wow64_32","diagnostics":[]}
        ],
        "registrations":[{"registry_subkey":"AlphaKey","registry_subkey_utf16_hex":"41006c007000680061004b0065007900","display_name":"Alpha","values":[{"name":"DisplayName","registry_type":1,"type_name":"REG_SZ","text":"Alpha","raw_data_hex":"41006c00700068006100"},{"name":"DisplayVersion","registry_type":1,"type_name":"REG_SZ","text":"1.2","raw_data_hex":"31002e003200"},{"name":"Publisher","registry_type":1,"type_name":"REG_SZ","text":"Acme","raw_data_hex":"410063006d006500"}],"evidence":{"source":"RegEnumKeyExW/RegQueryValueExW","hive":"HKEY_CURRENT_USER","registry_view":"native","registry_key":"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall","registration_index":0,"registry_subkey":"AlphaKey"}}]
    })).unwrap();
    let artifact = SessionArtifactRef {
        kind: ArtifactKind::WindowsSoftware,
        path: "software.windows.json".to_owned(),
        schema: "sideeffect.windows_software_inventory".to_owned(),
        schema_version: 1,
        byte_length: artifact_bytes.len() as u64,
        sha256: digest(&artifact_bytes),
    };
    let source = AuditSessionSource {
        role: SourceRole::Packages,
        collector: Some(collector_identity("windows", SourceRole::Packages)),
        platform: "windows".to_owned(),
        scope: "synthetic fixture only".to_owned(),
        started_at_unix_ms: 1000,
        ended_at_unix_ms: 1001,
        status: source_status,
        applied_limits: vec![],
        requested_settings: vec![],
        effective_settings: vec![],
        loss: None,
        diagnostic_codes: if source_status == SourceStatus::Complete {
            vec![]
        } else {
            vec!["synthetic_partial".to_owned()]
        },
        artifacts: vec![artifact],
    };
    let mut manifest = AuditSessionManifest {
        schema: AUDIT_SESSION_SCHEMA.to_owned(),
        schema_version: AUDIT_SESSION_SCHEMA_VERSION,
        session_id: session_id.to_owned(),
        platform: "windows".to_owned(),
        architecture: "x86_64".to_owned(),
        started_at_unix_ms: 1000,
        ended_at_unix_ms: 1001,
        interval_semantics: IntervalSemantics::BestEffortNonAtomic,
        status: if source_status == SourceStatus::Complete {
            SessionStatus::Complete
        } else {
            SessionStatus::Partial
        },
        sources: vec![source],
        host_context: Some(sideeffect::audit_session::HostContext {
            os_name: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some("Windows".to_owned()),
            },
            os_version: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some("synthetic fixture".to_owned()),
            },
            privilege: sideeffect::audit_session::PrivilegeContext::NotElevated,
        }),
        coverage_manifest: None,
    };
    manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));
    let manifest = serde_json::to_vec(&manifest).unwrap();
    sideeffect::record::publish_private_windows_directory(
        directory,
        &[
            ("session.json", manifest.as_slice()),
            ("software.windows.json", artifact_bytes.as_slice()),
        ],
        32 * 1024 * 1024,
    )
    .unwrap();
}

fn package_query(directory: &TestDirectory, sessions: &[&PathBuf], query_json: &[u8]) -> Output {
    let query_path = directory.0.join("package-query.json");
    fs::write(&query_path, query_json).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
    command.args(["query", "--query"]).arg(query_path);
    for session in sessions {
        command.args(["--session"]).arg(session);
    }
    command.args(["--source", "packages"]);
    command.output().unwrap()
}

#[test]
fn package_query_filters_windows_registrations_exactly_and_retains_evidence() {
    let directory = TestDirectory::new();
    let session = directory.0.join("software-session");
    write_package_session(
        &session,
        "11111111111111111111111111111111",
        SourceStatus::Complete,
    );
    let query = br#"{"schema":"sideeffect.package_query","schema_version":1,"filters":{"source":"current_user_native_uninstall","name":"Alpha","version":"1.2","publisher":"Acme"},"limit":5}"#;
    let output = package_query(&directory, &[&session], query);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema"], "sideeffect.package_query_result");
    assert_eq!(result["matched_count"], 1);
    assert_eq!(
        result["sessions"][0]["package_source"]["rows"][0]["row"]["display_name"],
        "Alpha"
    );
    assert_eq!(
        result["sessions"][0]["package_source"]["rows"][0]["json_pointer"],
        "/registrations/0"
    );
    assert_eq!(
        result["sessions"][0]["package_source"]["artifact"]["sha256"],
        digest(&fs::read(session.join("software.windows.json")).unwrap())
    );
    let no_case_match =
        br#"{"schema":"sideeffect.package_query","schema_version":1,"filters":{"name":"alpha"}}"#;
    let output = package_query(&directory, &[&session], no_case_match);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["matched_count"],
        0
    );
}

#[test]
fn package_query_preserves_windows_partial_status_and_rejects_duplicate_ids() {
    let directory = TestDirectory::new();
    let first = directory.0.join("partial-one");
    let duplicate = directory.0.join("partial-two");
    write_package_session(
        &first,
        "22222222222222222222222222222222",
        SourceStatus::Partial,
    );
    write_package_session(
        &duplicate,
        "22222222222222222222222222222222",
        SourceStatus::Partial,
    );
    let query =
        br#"{"schema":"sideeffect.package_query","schema_version":1,"filters":{"name":"Alpha"}}"#;
    let output = package_query(&directory, &[&first], query);
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["sessions"][0]["package_source"]["status"], "partial");
    assert_eq!(
        result["sessions"][0]["package_source"]["inventory_status"],
        "partial"
    );
    assert_eq!(
        package_query(&directory, &[&first, &duplicate], query)
            .status
            .code(),
        Some(1)
    );
}

fn selected_root_query(
    directory: &TestDirectory,
    session_paths: &[&PathBuf],
    query_json: &[u8],
    text: bool,
) -> Output {
    let query_path = directory.0.join("inventory-query.json");
    fs::write(&query_path, query_json).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
    command.args(["query", "--query"]).arg(query_path);
    for session in session_paths {
        command.args(["--session"]).arg(session);
    }
    command.args(["--source", "selected_root"]);
    if text {
        command.args(["--format", "text"]);
    }
    command.output().unwrap()
}

#[test]
fn session_query_uses_verified_windows_etw_artifact_and_keeps_capture_status_unknown() {
    let directory = TestDirectory::new();
    let session = directory.0.join("valid-session");
    let runtime = runtime_capture();
    publish_session(&session, Some(runtime.clone()));
    let output = query(&directory, &session);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema"], "sideeffect.session_event_query_result");
    assert_eq!(result["schema_version"], 3);
    assert_eq!(result["session"]["status"], "partial");
    assert_eq!(result["runtime_source"]["status"], "partial");
    assert_eq!(result["capture"]["collection_status"], "complete");
    assert_eq!(result["capture"]["completeness"], "unknown");
    assert_eq!(
        result["event_query_result"]["source_state"]["completeness"],
        "unknown"
    );
    assert_eq!(
        result["runtime_source"]["artifacts"][0]["sha256"],
        digest(&runtime)
    );
    assert_eq!(
        result["event_query_result"]["events"][0]["event_kind"],
        "process_start"
    );
    assert_eq!(
        result["event_query_result"]["events"][0]["evidence"]["kind"],
        "windows_etw_record"
    );

    let timestamp_query = directory.0.join("timestamp-query.json");
    fs::write(
        &timestamp_query,
        br#"{"schema":"sideeffect.event_query","schema_version":4,"filters":{"timestamp":{"clock":"etw_qpc_ticks","from_inclusive":"10","to_inclusive":"10"}}}"#,
    ).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(timestamp_query)
        .arg("--session")
        .arg(session)
        .args(["--source", "runtime"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let timestamp: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(timestamp["schema_version"], 4);
    assert_eq!(timestamp["event_query_result"]["schema_version"], 4);
    assert_eq!(timestamp["event_query_result"]["matched_count"], 1);
    assert_eq!(timestamp["capture"], result["capture"]);
    assert_eq!(
        timestamp["runtime_source"]["artifacts"],
        result["runtime_source"]["artifacts"]
    );
    assert_eq!(
        timestamp["event_query_result"]["events"],
        result["event_query_result"]["events"]
    );
}

#[test]
fn verified_windows_session_query_v2_matches_only_raw_payload_validated_file_names() {
    let directory = TestDirectory::new();
    let session = directory.0.join("path-session");
    let path = r"C:\Windows\Temp\fixture.txt";
    publish_session(&session, Some(runtime_capture_with_file_path(path)));
    let query_path = directory.0.join("path-query.json");
    fs::write(
        &query_path,
        serde_json::to_vec(&json!({
            "schema": "sideeffect.event_query",
            "schema_version": 2,
            "filters": { "path_exact": path },
            "limit": 5
        }))
        .unwrap(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(query_path)
        .args(["--session"])
        .arg(session)
        .args(["--source", "runtime"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["event_query_result"]["matched_count"], 1);
    assert_eq!(
        result["event_query_result"]["events"][0]["path_observation"]["path"],
        path
    );
    assert_eq!(
        result["event_query_result"]["events"][0]["path_observation"]["basis"]["kind"],
        "windows_etw_validated_file_name"
    );

    let prefix_query = directory.0.join("path-prefix-query.json");
    fs::write(
        &prefix_query,
        serde_json::to_vec(&json!({
            "schema": "sideeffect.event_query",
            "schema_version": 3,
            "filters": { "path_prefix": r"C:\Windows\Temp" },
            "limit": 5
        }))
        .unwrap(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(prefix_query)
        .args(["--session"])
        .arg(directory.0.join("path-session"))
        .args(["--source", "runtime"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["event_query_result"]["matched_count"], 1);
    assert_eq!(
        result["event_query_result"]["source_state"]["completeness"],
        "unknown"
    );

    let no_path_query = directory.0.join("no-path-query.json");
    fs::write(
        &no_path_query,
        br#"{"schema":"sideeffect.event_query","schema_version":2,"filters":{"path_exact":"C:\\Windows\\Temp\\other.txt"},"limit":5}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(no_path_query)
        .args(["--session"])
        .arg(directory.0.join("path-session"))
        .args(["--source", "runtime"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["event_query_result"]["matched_count"], 0);
    assert_eq!(
        result["event_query_result"]["source_state"]["completeness"],
        "unknown"
    );
}

#[test]
fn multi_session_query_keeps_windows_etw_evidence_under_each_session() {
    let directory = TestDirectory::new();
    let first = directory.0.join("first");
    let second = directory.0.join("second");
    publish_session_with_id(
        &first,
        Some(runtime_capture()),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    publish_session_with_id(
        &second,
        Some(runtime_capture()),
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    let output = multi_query(&directory, &[&first, &second], false);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["schema"],
        "sideeffect.multi_session_event_query_result"
    );
    assert_eq!(result["session_count"], 2);
    assert_eq!(result["matched_count"], 2);
    assert_eq!(result["complete"], false);
    assert_eq!(
        result["sessions"][0]["session"]["session_id"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        result["sessions"][1]["session"]["session_id"],
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    for session in result["sessions"].as_array().unwrap() {
        assert_eq!(
            session["event_query_result"]["events"][0]["event_kind"],
            "process_start"
        );
        assert_eq!(
            session["event_query_result"]["events"][0]["evidence"]["kind"],
            "windows_etw_record"
        );
    }
}

#[test]
fn multi_session_query_text_lists_each_windows_session() {
    let directory = TestDirectory::new();
    let first = directory.0.join("first-text");
    let second = directory.0.join("second-text");
    publish_session_with_id(
        &first,
        Some(runtime_capture()),
        "cccccccccccccccccccccccccccccccc",
    );
    publish_session_with_id(
        &second,
        Some(runtime_capture()),
        "dddddddddddddddddddddddddddddddd",
    );
    let output = multi_query(&directory, &[&first, &second], true);
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("cccccccccccccccccccccccccccccccc"));
    assert!(text.contains("dddddddddddddddddddddddddddddddd"));
    assert_eq!(text.matches("Event query: windows").count(), 2);
}

#[test]
fn multi_session_query_rejects_source_local_evidence_filter() {
    let directory = TestDirectory::new();
    let query_path = directory.0.join("evidence-query.json");
    fs::write(
        &query_path,
        br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"evidence":{"kind":"windows_etw_record","record_ordinal":1,"json_pointer":"/events/0","raw_payload_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#,
    )
    .unwrap();
    let first = directory.0.join("missing-first");
    let second = directory.0.join("missing-second");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(query_path)
        .args(["--session"])
        .arg(first)
        .args(["--session"])
        .arg(second)
        .args(["--source", "runtime"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("source-local"));
}

#[test]
fn missing_windows_runtime_artifact_is_not_reported_as_an_empty_query() {
    let directory = TestDirectory::new();
    let session = directory.0.join("missing-runtime");
    publish_session(&session, None);
    let output = query(&directory, &session);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("runtime_artifact_missing"));
}

#[test]
fn malformed_windows_runtime_artifact_is_rejected_after_session_verification() {
    let directory = TestDirectory::new();
    let session = directory.0.join("malformed-runtime");
    publish_session(&session, Some(b"{\"schema\":\"wrong\"}".to_vec()));
    let output = query(&directory, &session);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn selected_root_query_multi_session_uses_exact_utf16le_and_preserves_status() {
    let directory = TestDirectory::new();
    let first = directory.0.join("root-v1");
    let second = directory.0.join("root-v2");
    let v1 = selected_root_document(1, "complete", "binary");
    let v2 = selected_root_document(2, "partial", "binary");
    write_selected_root_session(
        &first,
        "11111111111111111111111111111111",
        &v1,
        SourceStatus::Complete,
        1,
    );
    write_selected_root_session(
        &second,
        "22222222222222222222222222222222",
        &v2,
        SourceStatus::Partial,
        2,
    );
    let query = serde_json::to_vec(&json!({
        "schema":"sideeffect.inventory_query",
        "schema_version":1,
        "filters":{"root_path_hex":utf16_hex("C:\\synthetic\\root"),"entry_name_hex":utf16_hex("binary")},
        "limit":10
    })).unwrap();
    let output = selected_root_query(&directory, &[&first, &second], &query, false);
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema"], "sideeffect.inventory_query_result");
    assert_eq!(result["session_count"], 2);
    assert_eq!(result["matched_count"], 2);
    assert_eq!(result["complete"], false);
    assert_eq!(
        result["filter"]["root_path_hex"],
        utf16_hex("C:\\synthetic\\root")
    );
    assert_eq!(result["filter"]["entry_name_hex"], utf16_hex("binary"));
    assert_eq!(result["limit"], 10);
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["artifact"]["schema_version"],
        1
    );
    assert_eq!(
        result["sessions"][1]["selected_root_source"]["artifact"]["schema_version"],
        2
    );
    assert_eq!(
        result["sessions"][1]["selected_root_source"]["status"],
        "partial"
    );
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["entries"][0]["name_hex"],
        utf16_hex("binary")
    );
    assert_eq!(
        result["sessions"][1]["selected_root_source"]["entries"][0]["content_hash_status"],
        "observed"
    );
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["entries"][0]["evidence"]["entry_ordinal"],
        0
    );
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["artifact"]["sha256"],
        digest(&v1)
    );
}

#[test]
fn selected_root_query_text_is_terminal_safe_and_duplicate_session_ids_fail_closed() {
    let directory = TestDirectory::new();
    let first = directory.0.join("safe-text");
    let root = selected_root_document(1, "complete", "file\u{1b}[31m<script>");
    write_selected_root_session(
        &first,
        "33333333333333333333333333333333",
        &root,
        SourceStatus::Complete,
        1,
    );
    let query = br#"{"schema":"sideeffect.inventory_query","schema_version":1}"#;
    let text = selected_root_query(&directory, &[&first], query, true);
    assert_eq!(
        text.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    let rendered = String::from_utf8(text.stdout).unwrap();
    assert!(!rendered.contains('\u{1b}'));
    assert!(rendered.contains("\\u{1b}"));

    let second = directory.0.join("same-id");
    write_selected_root_session(
        &second,
        "33333333333333333333333333333333",
        &root,
        SourceStatus::Complete,
        1,
    );
    let duplicate = selected_root_query(&directory, &[&first, &second], query, false);
    assert_eq!(duplicate.status.code(), Some(1));
    assert!(duplicate.stdout.is_empty());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("duplicate session IDs"));
}

#[test]
fn selected_root_query_rejects_unknown_duplicate_oversized_and_bad_encoding() {
    let directory = TestDirectory::new();
    let base = selected_root_document(1, "complete", "item");
    let malformed = [
        ("unknown", {
            let mut value: Value = serde_json::from_slice(&base).unwrap();
            value["unknown_field"] = json!(true);
            serde_json::to_vec(&value).unwrap()
        }),
        (
            "duplicate",
            String::from_utf8(base.clone())
                .unwrap()
                .replace(
                    "\"status\":\"complete\"",
                    "\"status\":\"complete\",\"status\":\"complete\"",
                )
                .into_bytes(),
        ),
        ("oversized", {
            let mut value: Value = serde_json::from_slice(&base).unwrap();
            let first = value["entries"][0].clone();
            value["entries"] = json!(
                (0..10_001)
                    .map(|ordinal| {
                        let mut entry = first.clone();
                        entry["ordinal"] = json!(ordinal);
                        entry["evidence"]["entry_ordinal"] = json!(ordinal);
                        entry
                    })
                    .collect::<Vec<_>>()
            );
            serde_json::to_vec(&value).unwrap()
        }),
    ];
    for (index, (name, bytes)) in malformed.into_iter().enumerate() {
        let path = directory.0.join(name);
        write_selected_root_session(
            &path,
            &format!("{:032x}", index + 1),
            &bytes,
            SourceStatus::Complete,
            1,
        );
        let query = br#"{"schema":"sideeffect.inventory_query","schema_version":1}"#;
        let output = selected_root_query(&directory, &[&path], query, false);
        assert_eq!(output.status.code(), Some(1), "{name}");
        assert!(output.stdout.is_empty(), "{name}");
    }

    let valid_path = directory.0.join("encoding");
    write_selected_root_session(
        &valid_path,
        "44444444444444444444444444444444",
        &base,
        SourceStatus::Complete,
        1,
    );
    let invalid_query = br#"{"schema":"sideeffect.inventory_query","schema_version":1,"filters":{"entry_name_hex":"61"}}"#;
    let output = selected_root_query(&directory, &[&valid_path], invalid_query, false);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

#[test]
fn selected_root_query_preserves_partial_source_without_root_identity() {
    let directory = TestDirectory::new();
    let path = directory.0.join("root-unknown");
    let mut document: Value =
        serde_json::from_slice(&selected_root_document(1, "partial", "item")).unwrap();
    document["root"] = Value::Null;
    document["entries"] = json!([]);
    let bytes = serde_json::to_vec(&document).unwrap();
    write_selected_root_session(
        &path,
        "66666666666666666666666666666666",
        &bytes,
        SourceStatus::Partial,
        1,
    );
    let query = br#"{"schema":"sideeffect.inventory_query","schema_version":1}"#;
    let output = selected_root_query(&directory, &[&path], query, false);
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["inventory_status"],
        "partial"
    );
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["root_path_hex"],
        Value::Null
    );
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["matched_count"],
        0
    );
}

#[test]
fn selected_root_query_rejects_aggregate_utf16_name_bytes_over_limit() {
    let directory = TestDirectory::new();
    let path = directory.0.join("large-names");
    let mut document: Value =
        serde_json::from_slice(&selected_root_document(1, "complete", "item")).unwrap();
    let first = document["entries"][0].clone();
    let large_name = "6100".repeat(32_767);
    document["entries"] = json!(
        (0..129)
            .map(|ordinal| {
                let mut entry = first.clone();
                entry["ordinal"] = json!(ordinal);
                entry["name_utf16le_hex"] = json!(large_name);
                entry["evidence"]["entry_ordinal"] = json!(ordinal);
                entry
            })
            .collect::<Vec<_>>()
    );
    let bytes = serde_json::to_vec(&document).unwrap();
    write_selected_root_session(
        &path,
        "77777777777777777777777777777777",
        &bytes,
        SourceStatus::Complete,
        1,
    );
    let query = br#"{"schema":"sideeffect.inventory_query","schema_version":1}"#;
    let output = selected_root_query(&directory, &[&path], query, false);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("aggregate names"));
}
