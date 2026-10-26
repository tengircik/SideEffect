#![cfg(windows)]

use serde_json::Value;
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Opt-in local acceptance test. This needs permission to control the NT Kernel
/// Logger and is intentionally ignored by normal CI.
#[test]
#[ignore = "manual ETW acceptance; controlling NT Kernel Logger requires administrative privileges"]
fn captures_real_process_lifecycle_events_and_reports_loss_state() {
    let directory = std::env::temp_dir().join(format!(
        "sideeffect-windows-etw-integration-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&directory).unwrap();
    let output = directory.join("capture.json");
    let command = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["record", "--windows-etw", output.to_str().unwrap()])
        .args([
            "--duration-seconds",
            "5",
            "--",
            "cmd.exe",
            "/C",
            "exit",
            "0",
        ])
        .output()
        .unwrap();
    assert!(
        matches!(command.status.code(), Some(0 | 2)),
        "ETW acceptance failed (this host may lack permission to control NT Kernel Logger): {}",
        String::from_utf8_lossy(&command.stderr)
    );
    let document: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(document["schema"], "sideeffect.windows_runtime_capture");
    assert_eq!(document["schema_version"], 2);
    assert_eq!(document["capture_completeness"], "unknown");
    assert_eq!(document["event_loss"]["loss_statistics_available"], true);
    assert!(document["events"].as_array().unwrap().iter().any(|event| {
        event["event_kind"] == "process_start" || event["event_kind"] == "process_end"
    }));
    assert!(document["target"]["process_id"].as_u64().unwrap() > 0);
    let target_pid = document["target"]["process_id"].as_u64().unwrap();
    assert!(document["events"].as_array().unwrap().iter().any(|event| {
        event["event_kind"] == "process_start"
            && event["payload_decoding"]["status"] == "decoded"
            && event["payload_decoding"]["process_id"] == target_pid
    }));
    fs::remove_file(output).unwrap();
    fs::remove_dir(directory).unwrap();
}
