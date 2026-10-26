#![cfg(windows)]

use serde_json::Value;
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temporary_directory() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "sideeffect-windows-startup-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn windows_startup_command_reports_scope_inert_values_and_unchecked_sources() {
    let directory = temporary_directory();
    let output = directory.join("startup.json");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .args(["inventory", "startup", "--output"])
            .arg(&output)
            .output()
            .unwrap()
    };

    let first = run();
    assert_eq!(
        first.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let bytes = fs::read(&output).unwrap();
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(document["schema"], "sideeffect.windows_startup_inventory");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["platform"], "windows");
    assert_eq!(document["status"], "partial");
    assert_eq!(
        document["scope"],
        "current_user_and_accessible_machine_run_keys_and_startup_folders"
    );
    let sources = document["sources"].as_array().unwrap();
    for required in [
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
    ] {
        assert!(sources.iter().any(|source| source["id"] == required));
    }
    for unchecked in ["service_start_configuration", "scheduled_task_triggers"] {
        let source = sources
            .iter()
            .find(|source| source["id"] == unchecked)
            .unwrap();
        assert_eq!(source["status"], "not_checked");
    }
    for entry in document["registry_entries"].as_array().unwrap() {
        assert!(entry["command"].is_null() || entry["command"].is_string());
        assert!(entry["command_utf16_hex"].is_null() || entry["command_utf16_hex"].is_string());
    }

    let second = run();
    assert!(!second.status.success());
    assert_eq!(fs::read(&output).unwrap(), bytes);
    fs::remove_file(output).unwrap();
    fs::remove_dir(directory).unwrap();
}
