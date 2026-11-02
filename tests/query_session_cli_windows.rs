#![cfg(windows)]

use serde_json::Value;
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
use std::path::PathBuf;
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

#[test]
fn session_query_uses_verified_windows_etw_artifact_and_keeps_capture_status_unknown() {
    let directory = TestDirectory::new();
    let session = directory.0.join("valid-session");
    let runtime = runtime_capture();
    publish_session(&session, Some(runtime.clone()));
    let output = query(&directory, &session);
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema"], "sideeffect.session_event_query_result");
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
    assert_eq!(output.status.code(), Some(2));
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
