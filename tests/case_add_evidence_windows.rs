#![cfg(windows)]

//! Synthetic-only Windows ETW case-add-evidence CLI acceptance.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sideeffect::audit_session::{
    AUDIT_SESSION_SCHEMA, AUDIT_SESSION_SCHEMA_VERSION, ArtifactKind, AuditSessionManifest,
    AuditSessionSource, ContextFact, ContextFactStatus, CoverageManifest, HostContext,
    IntervalSemantics, LossMetadata, PrivilegeContext, SessionArtifactRef, SessionStatus,
    SourceRole, SourceStatus, collector_identity,
};
use sideeffect::windows_runtime::{
    AppliedLimits, CollectionStatus, DecodedProcessPayload, EventLoss, NativeRuntimeEvent,
    ProcessDecodeStatus, SessionMetadata, StopReason, TargetOutcome,
    WINDOWS_RUNTIME_CAPTURE_SCHEMA, WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION, WindowsRuntimeCapture,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-case-add-evidence-windows-{}-{}",
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

fn synthetic_capture() -> Vec<u8> {
    let mut capture = WindowsRuntimeCapture {
        schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
        schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        platform: "windows".to_owned(),
        capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
        collection_status: CollectionStatus::Partial,
        capture_completeness: "unknown".to_owned(),
        started_at_unix_ms: 10,
        ended_at_unix_ms: 11,
        requested_duration_seconds: 1,
        stop_reason: StopReason::TargetExited,
        target: TargetOutcome {
            process_id: 5,
            exit_code: Some(0),
            status_available: true,
        },
        session: SessionMetadata {
            name: "Synthetic ETW fixture".to_owned(),
            provider: "Synthetic fixture only".to_owned(),
            scope: "synthetic only; never a live capture".to_owned(),
            buffer_size_kb_requested: 16,
            minimum_buffers_requested: 8,
            maximum_buffers_requested: 32,
            buffer_count_reported: 8,
            provider_process_id_header_semantics: "header PID/TID is event context only".to_owned(),
        },
        limits: AppliedLimits {
            maximum_duration_seconds: 60,
            maximum_events: sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_EVENTS,
            maximum_total_payload_bytes:
                sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES,
            maximum_payload_bytes_per_event:
                sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
            maximum_document_bytes: sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
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
            event_version: 0,
            opcode: 1,
            event_kind: "process_start".to_owned(),
            header_process_id: 5,
            header_thread_id: 6,
            header_flags: 0,
            timestamp_qpc: 7,
            raw_payload_hex: "00000000000000002a00000001000000".to_owned(),
            payload_decoding: Some(DecodedProcessPayload {
                status: ProcessDecodeStatus::Decoded,
                schema_name: Some("Process_V2_TypeGroup1".to_owned()),
                schema_version: Some(2),
                pointer_size_bytes: Some(8),
                process_id: Some(42),
                parent_process_id: Some(1),
                image_file_name: Some("synthetic-fixture.exe".to_owned()),
                diagnostic: None,
            }),
            observation_decoding: None,
        }],
        diagnostics: vec!["synthetic fixture only".to_owned()],
    };
    capture.document_sha256 = digest(&serde_json::to_vec(&capture).unwrap());
    serde_json::to_vec(&capture).unwrap()
}

fn publish_synthetic_session(
    session_dir: &Path,
    capture_bytes: &[u8],
    session_id: &str,
) -> Vec<u8> {
    let artifact = SessionArtifactRef {
        kind: ArtifactKind::WindowsRuntimeCapture,
        path: "runtime.windows.json".to_owned(),
        schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
        schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        byte_length: capture_bytes.len() as u64,
        sha256: digest(capture_bytes),
    };
    let source = AuditSessionSource {
        role: SourceRole::Runtime,
        collector: Some(collector_identity("windows", SourceRole::Runtime)),
        platform: "windows".to_owned(),
        scope: "synthetic fixture only; bounded ETW window".to_owned(),
        started_at_unix_ms: 10,
        ended_at_unix_ms: 11,
        status: SourceStatus::Partial,
        applied_limits: vec![],
        requested_settings: vec![],
        effective_settings: vec![],
        loss: Some(LossMetadata::unknown()),
        diagnostic_codes: vec!["synthetic_fixture_partial".to_owned()],
        artifacts: vec![artifact],
    };
    let mut manifest = AuditSessionManifest {
        schema: AUDIT_SESSION_SCHEMA.to_owned(),
        schema_version: AUDIT_SESSION_SCHEMA_VERSION,
        session_id: session_id.to_owned(),
        platform: "windows".to_owned(),
        architecture: "x86_64".to_owned(),
        started_at_unix_ms: 10,
        ended_at_unix_ms: 11,
        interval_semantics: IntervalSemantics::BestEffortNonAtomic,
        status: SessionStatus::Partial,
        sources: vec![source],
        host_context: Some(HostContext {
            os_name: ContextFact {
                status: ContextFactStatus::Observed,
                value: Some("Windows".to_owned()),
            },
            os_version: ContextFact {
                status: ContextFactStatus::Observed,
                value: Some("synthetic fixture".to_owned()),
            },
            privilege: PrivilegeContext::NotElevated,
        }),
        coverage_manifest: None,
    };
    manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));
    manifest.validate().unwrap();
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    sideeffect::record::publish_private_windows_directory(
        session_dir,
        &[
            ("session.json", manifest_bytes.as_slice()),
            ("runtime.windows.json", capture_bytes),
        ],
        32 * 1024 * 1024,
    )
    .unwrap();
    manifest_bytes
}

#[test]
fn add_evidence_resolves_synthetic_etw_locator_and_preserves_partial_status() {
    let directory = TestDirectory::new();
    let session = directory.0.join("synthetic-etw-session");
    let capture_bytes = synthetic_capture();
    let session_id = "abcdef0123456789abcdef0123456789";
    let manifest_bytes = publish_synthetic_session(&session, &capture_bytes, session_id);
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let capture: Value = serde_json::from_slice(&capture_bytes).unwrap();
    let case_path = directory.0.join("case.json");
    let init = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("init")
        .arg("--output")
        .arg(&case_path)
        .arg("--title")
        .arg("Synthetic ETW case")
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(init.status.success() || init.status.code() == Some(2));
    let original_case = fs::read(&case_path).unwrap();
    let case: Value = serde_json::from_slice(&original_case).unwrap();
    let payload = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00,
    ];
    let locator = json!([{
        "kind":"windows_etw_record",
        "session_id":case["sessions"][0]["session_id"],
        "manifest_sha256":case["sessions"][0]["manifest_sha256"],
        "artifact_sha256":manifest["sources"][0]["artifacts"][0]["sha256"],
        "capture_sha256":capture["document_sha256"],
        "record_ordinal":1,
        "json_pointer":"/events/0",
        "raw_payload_sha256":digest(&payload)
    }]);
    let locator_path = directory.0.join("locators.json");
    fs::write(&locator_path, serde_json::to_vec(&locator).unwrap()).unwrap();
    let text_path = directory.0.join("text.txt");
    fs::write(&text_path, b"Synthetic process observation note").unwrap();
    let output_path = directory.0.join("updated.case.json");
    let add = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("add-evidence")
        .arg("--case")
        .arg(&case_path)
        .args(["--id", "W001", "--kind", "assertion", "--text-file"])
        .arg(&text_path)
        .arg("--evidence-file")
        .arg(&locator_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert_eq!(
        add.status.code(),
        Some(2),
        "synthetic partial ETW source must remain partial: {}",
        String::from_utf8_lossy(&add.stderr)
    );
    assert!(output_path.is_file());
    assert_eq!(fs::read(&case_path).unwrap(), original_case);
    let updated: Value = serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(updated["entries"][0]["evidence"], locator);
    let resolved = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("resolve")
        .arg("--case")
        .arg(&output_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert_eq!(resolved.status.code(), Some(2));
    let resolved: Value = serde_json::from_slice(&resolved.stdout).unwrap();
    assert_eq!(resolved["facts"].as_array().unwrap().len(), 1);
    assert_eq!(resolved["sessions"][0]["status"], "partial");
    assert_eq!(resolved["facts"][0]["fact"]["kind"], "windows_etw_record");
}
