#![cfg(all(windows, target_arch = "x86_64"))]

#[path = "common/model_store.rs"]
mod model_store;

use model_store::SelectedTestModel;
use sha2::{Digest, Sha256};
use sideeffect::windows_runtime::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn synthetic_capture() -> Vec<u8> {
    let mut capture = WindowsRuntimeCapture {
        schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.into(),
        schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        platform: "windows".into(),
        capture_profile: "synthetic_fixture_only".into(),
        collection_status: CollectionStatus::Complete,
        capture_completeness: "unknown".into(),
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
            name: "synthetic fixture".into(),
            provider: "synthetic fixture".into(),
            scope: "synthetic fixture only".into(),
            buffer_size_kb_requested: 64,
            minimum_buffers_requested: 2,
            maximum_buffers_requested: 4,
            buffer_count_reported: 2,
            provider_process_id_header_semantics: "context only".into(),
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
            observation: "none_reported".into(),
            final_snapshot_available: true,
        },
        document_sha256: String::new(),
        events: Vec::new(),
        diagnostics: Vec::new(),
    };
    capture.document_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&capture).unwrap())
    );
    serde_json::to_vec(&capture).unwrap()
}

#[test]
fn etw_query_preview_cli_and_stale_digest_contract_are_distinct_and_confirmation_bound() {
    let model = SelectedTestModel::new("query");
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let capture = std::env::temp_dir().join(format!(
        "sideeffect-synthetic-etw-query-{}-{id}.json",
        std::process::id()
    ));
    fs::write(&capture, synthetic_capture()).unwrap();
    let preview = model
        .command()
        .args([
            "model-etw-query-preview",
            "--question",
            "Find TCP events.",
            "--backend",
            "cpu",
            "--windows-runtime",
        ])
        .arg(&capture)
        .output()
        .unwrap();
    assert_eq!(
        preview.status.code(),
        Some(2),
        "unknown completeness must remain partial: {}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(value["schema"], "sideeffect.windows_etw_query_preview");
    assert_eq!(value["coverage"]["capture_completeness"], "unknown");
    assert_eq!(value["model_id"], model.id());
    assert!(
        !value["prompt"]
            .as_str()
            .unwrap()
            .contains("header_process_id")
    );
    let output = model
        .command()
        .args([
            "model-etw-query",
            "--question",
            "Find TCP events.",
            "--backend",
            "cpu",
            "--runtime",
            "missing-runtime.exe",
            "--confirm-sha256",
            &"0".repeat(64),
            "--windows-runtime",
        ])
        .arg(&capture)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("preview digest mismatch"));
    fs::remove_file(capture).unwrap();
}
