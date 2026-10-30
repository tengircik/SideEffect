use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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

fn fixture(status: CollectionStatus) -> Vec<u8> {
    let mut capture = WindowsRuntimeCapture {
        schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
        schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        platform: "windows".to_owned(),
        capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
        collection_status: status,
        capture_completeness: "unknown".to_owned(),
        started_at_unix_ms: 1,
        ended_at_unix_ms: 2,
        requested_duration_seconds: 1,
        stop_reason: StopReason::TargetExited,
        target: TargetOutcome {
            process_id: 42,
            exit_code: Some(0),
            status_available: true,
        },
        session: SessionMetadata {
            name: "NT Kernel Logger".to_owned(),
            provider: "NT Kernel Logger process, FileIo, DiskIo, TcpIp, and UdpIp providers"
                .to_owned(),
            scope: "system_wide_process_file_and_network_events_during_capture_window".to_owned(),
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
            event_version: 0,
            opcode: 1,
            event_kind: "process_start".to_owned(),
            header_process_id: 8,
            header_thread_id: 9,
            header_flags: 0,
            timestamp_qpc: 10,
            raw_payload_hex: "01".to_owned(),
            payload_decoding: Some(DecodedProcessPayload {
                status: ProcessDecodeStatus::Decoded,
                schema_name: Some("Process_V2_TypeGroup1".to_owned()),
                schema_version: Some(2),
                pointer_size_bytes: Some(8),
                process_id: Some(42),
                parent_process_id: Some(1),
                image_file_name: Some("fixture.exe\u{1b}[2J".to_owned()),
                diagnostic: None,
            }),
            observation_decoding: None,
        }],
        diagnostics: if status == CollectionStatus::Partial {
            vec!["synthetic_fixture_partial_source".to_owned()]
        } else {
            Vec::new()
        },
    };
    let canonical = serde_json::to_vec(&capture).unwrap();
    capture.document_sha256 = format!("{:x}", Sha256::digest(canonical));
    serde_json::to_vec(&capture).unwrap()
}

fn with_input(bytes: &[u8]) -> (PathBuf, Output) {
    let path = std::env::temp_dir().join(format!(
        "sideeffect-windows-runtime-inspect-{}-{}.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inspect", "--windows-runtime"])
        .arg(&path)
        .output()
        .unwrap();
    (path, output)
}

#[test]
fn inspect_json_preserves_capture_claim_and_disclaims_authenticity() {
    let input = fixture(CollectionStatus::Complete);
    let expected_capture: Value = serde_json::from_slice(&input).unwrap();
    let (path, output) = with_input(&input);
    fs::remove_file(path).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schema"], "sideeffect.windows_runtime_inspection");
    assert_eq!(document["representation_fingerprint_verified"], true);
    assert_eq!(document["authenticity"], "not_verified");
    assert_eq!(document["capture_completeness"], "unknown");
    assert_eq!(document["capture_claimed_status"], "complete");
    assert_eq!(document["capture"], expected_capture);
}

#[test]
fn inspect_text_uses_terminal_safe_output_and_partial_exit_status() {
    let path = std::env::temp_dir().join(format!(
        "sideeffect-windows-runtime-inspect-text-{}-{}.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, fixture(CollectionStatus::Partial)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inspect", "--format", "text", "--windows-runtime"])
        .arg(&path)
        .output()
        .unwrap();
    fs::remove_file(path).unwrap();
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Event evidence ID: 1"));
    assert!(text.contains("\\u{1B}[2J"));
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("Source file SHA-256:"));
}

#[test]
fn inspect_rejects_capture_with_mismatched_representation_fingerprint() {
    let mut value: Value = serde_json::from_slice(&fixture(CollectionStatus::Complete)).unwrap();
    value["target"]["process_id"] = json!(99);
    let (path, output) = with_input(&serde_json::to_vec(&value).unwrap());
    fs::remove_file(path).unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("SHA-256 mismatch"));
}

#[cfg(windows)]
#[test]
fn events_windows_runtime_validates_capture_and_preserves_source_context() {
    let input = fixture(CollectionStatus::Complete);
    let path = std::env::temp_dir().join(format!(
        "sideeffect-windows-events-{}-{}.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, &input).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["events", "--windows-runtime"])
        .arg(&path)
        .output()
        .unwrap();
    fs::remove_file(path).unwrap();

    assert_eq!(output.status.code(), Some(2));
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema"], "sideeffect.common_event_envelope");
    assert_eq!(envelope["source"]["platform"], "windows");
    assert_eq!(envelope["source"]["schema"], WINDOWS_RUNTIME_CAPTURE_SCHEMA);
    assert_eq!(
        envelope["source"]["schema_version"],
        WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION
    );
    assert_eq!(envelope["source_state"]["completeness"], "unknown");
    assert_eq!(envelope["events"][0]["source_local_ordinal"], 1);
    assert_eq!(envelope["events"][0]["source_timestamp"]["value"], "10");
    assert_eq!(
        envelope["events"][0]["source_timestamp"]["clock_unit"],
        "ETW_QPC_ticks"
    );
    assert_eq!(envelope["events"][0]["identity_context"][0]["value"], "8");
    assert!(
        envelope["events"][0]["identity_context"][0]["ambiguity"]
            .as_str()
            .unwrap()
            .contains("header context only")
    );
    assert_eq!(
        envelope["events"][0]["evidence"]["json_pointer"],
        "/events/0"
    );
    assert_eq!(
        envelope["events"][0]["evidence"]["raw_payload_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
}

#[cfg(windows)]
#[test]
fn events_windows_runtime_rejects_unverified_capture_bytes() {
    let mut value: Value = serde_json::from_slice(&fixture(CollectionStatus::Complete)).unwrap();
    value["target"]["process_id"] = json!(99);
    let path = std::env::temp_dir().join(format!(
        "sideeffect-windows-events-invalid-{}-{}.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["events", "--windows-runtime"])
        .arg(&path)
        .output()
        .unwrap();
    fs::remove_file(path).unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("SHA-256 mismatch"));
    assert!(output.stdout.is_empty());
}

#[cfg(windows)]
#[test]
fn events_windows_runtime_preserves_partial_source_status_and_diagnostics() {
    let path = std::env::temp_dir().join(format!(
        "sideeffect-windows-events-partial-{}-{}.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, fixture(CollectionStatus::Partial)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["events", "--windows-runtime"])
        .arg(&path)
        .output()
        .unwrap();
    fs::remove_file(path).unwrap();

    assert_eq!(output.status.code(), Some(2));
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["source_state"]["completeness"], "partial");
    assert!(
        envelope["source_state"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic == "synthetic_fixture_partial_source")
    );
}

fn html_paths() -> (PathBuf, PathBuf) {
    let suffix = NEXT.fetch_add(1, Ordering::Relaxed);
    (
        std::env::temp_dir().join(format!(
            "sideeffect-windows-runtime-html-{}-{suffix}.json",
            std::process::id()
        )),
        std::env::temp_dir().join(format!(
            "sideeffect-windows-runtime-html-{}-{suffix}.html",
            std::process::id()
        )),
    )
}

#[cfg(windows)]
#[test]
fn html_report_uses_no_clobber_publisher_and_rejects_existing_target() {
    let (capture_path, report_path) = html_paths();
    fs::write(&capture_path, fixture(CollectionStatus::Complete)).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .args(["inspect", "--format", "html", "--output"])
            .arg(&report_path)
            .arg("--windows-runtime")
            .arg(&capture_path)
            .output()
            .unwrap()
    };

    let first = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let report = fs::read(&report_path).unwrap();
    let html = String::from_utf8(report.clone()).unwrap();
    assert!(html.contains("default-src 'none'"));
    assert!(html.contains("Event evidence ID 1"));
    assert!(!html.contains("<script"));
    assert!(html.contains("\\u001b"));

    let second = run();
    assert_eq!(second.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&second.stderr).contains("already exists"));
    assert_eq!(fs::read(&report_path).unwrap(), report);
    fs::remove_file(capture_path).unwrap();
    fs::remove_file(report_path).unwrap();
}

#[cfg(not(windows))]
#[test]
fn html_report_is_explicitly_unsupported_outside_native_windows() {
    let (capture_path, report_path) = html_paths();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inspect", "--format", "html", "--output"])
        .arg(&report_path)
        .arg("--windows-runtime")
        .arg(&capture_path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("only in native Windows builds"));
    assert!(!report_path.exists());
}
