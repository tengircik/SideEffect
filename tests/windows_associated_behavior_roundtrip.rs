#![cfg(windows)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-windows-associated-roundtrip-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn synthetic_runtime_capture() -> Vec<u8> {
    use sideeffect::windows_runtime::{
        AppliedLimits, CollectionStatus, EventLoss, SessionMetadata, StopReason, TargetOutcome,
        WindowsRuntimeCapture,
    };

    let mut capture = WindowsRuntimeCapture {
        schema: sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
        schema_version: sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        platform: "windows".to_owned(),
        capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
        collection_status: CollectionStatus::Partial,
        capture_completeness: "unknown".to_owned(),
        started_at_unix_ms: 10,
        ended_at_unix_ms: 11,
        requested_duration_seconds: 1,
        stop_reason: StopReason::EtwStatisticsUnavailable,
        target: TargetOutcome {
            process_id: 1,
            exit_code: Some(0),
            status_available: true,
        },
        session: SessionMetadata {
            name: "NT Kernel Logger".to_owned(),
            provider: "synthetic ETW fixture".to_owned(),
            scope: "synthetic_fixture_not_a_live_capture".to_owned(),
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

#[test]
fn native_startup_v4_output_is_accepted_by_windows_associated_behavior_v1() {
    // This exercises the native startup serializer and offline adapter only.
    // The ETW input is synthetic and does not validate a live provider or capture.
    let temp = Temp::new();
    let startup_path = temp.0.join("startup.windows.json");
    let runtime_path = temp.0.join("synthetic-runtime.windows.json");

    let inventory = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "startup", "--output"])
        .arg(&startup_path)
        .output()
        .unwrap();
    assert!(
        matches!(inventory.status.code(), Some(0 | 2)),
        "native startup inventory failed: {}",
        String::from_utf8_lossy(&inventory.stderr)
    );
    let startup_bytes = fs::read(&startup_path).unwrap();
    let startup: Value = serde_json::from_slice(&startup_bytes).unwrap();
    assert_eq!(startup["schema"], "sideeffect.windows_startup_inventory");
    assert_eq!(startup["schema_version"], 4);
    assert!(matches!(
        startup["status"].as_str(),
        Some("complete" | "partial")
    ));

    fs::write(&runtime_path, synthetic_runtime_capture()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("associated-behavior")
        .arg(&startup_path)
        .arg(&runtime_path)
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(2),
        "synthetic partial ETW input must remain visibly partial: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap_or_else(|error| {
        panic!(
            "associated-behavior produced no JSON: {error}; stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        )
    });

    assert_eq!(
        report["schema"],
        "sideeffect.windows_associated_behavior_summary"
    );
    assert_eq!(report["schema_version"], 1);
    assert_eq!(
        report["platform_adapter"],
        "windows_startup_inventory_v4_windows_runtime_capture_v3"
    );
    assert_eq!(
        report["inputs"]["startup_inventory"]["source_format"],
        "sideeffect.windows_startup_inventory_v4"
    );
    assert_eq!(
        report["inputs"]["startup_inventory"]["source_status"],
        startup["status"]
    );
    assert_eq!(
        report["inputs"]["runtime_capture"]["source_format"],
        "sideeffect.windows_runtime_capture_v3"
    );
    assert_eq!(
        report["inputs"]["runtime_capture"]["source_status"],
        "partial"
    );
    assert_eq!(report["status"], "partial");
    assert_eq!(report["association_status"], "insufficient_evidence");
    assert_eq!(report["summary"]["candidate_path_group_count"], 0);
    assert!(report["associations"].as_array().unwrap().is_empty());
    assert_eq!(report["capture_completeness"], "unknown");
    assert_eq!(
        report["inputs"]["runtime_capture"]["capture_completeness"],
        "unknown"
    );
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "runtime_capture_is_partial_or_has_diagnostics")
    );
    assert!(
        report["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item.as_str().unwrap().contains("does not establish"))
    );
    assert!(
        report["inputs"]["startup_inventory"]["sha256"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64)
    );
}
