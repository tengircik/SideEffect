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
fn windows_startup_command_reports_services_and_leaves_tasks_unchecked() {
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
    assert_eq!(document["schema_version"], 2);
    assert_eq!(document["platform"], "windows");
    assert_eq!(document["status"], "partial");
    assert_eq!(
        document["scope"],
        "current_user_and_accessible_machine_run_keys_startup_folders_and_services"
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
    let service_source = sources
        .iter()
        .find(|source| source["id"] == "service_start_configuration")
        .unwrap();
    assert!(matches!(
        service_source["status"].as_str(),
        Some("complete" | "partial")
    ));
    assert!(service_source["entries_seen"].as_u64().unwrap() > 0);
    assert!(!document["service_entries"].as_array().unwrap().is_empty());
    let scheduled_tasks = sources
        .iter()
        .find(|source| source["id"] == "scheduled_task_triggers")
        .unwrap();
    assert_eq!(scheduled_tasks["status"], "not_checked");
    for entry in document["service_entries"].as_array().unwrap() {
        assert!(entry["service_name"].is_string());
        assert!(entry["display_name"].is_string());
        assert!(entry["start_type"].is_string());
        assert!(entry["start_type_code"].is_number());
        assert!(entry["binary_path"].is_null() || entry["binary_path"].is_string());
        assert!(entry["account"].is_null() || entry["account"].is_string());
        assert_eq!(
            entry["evidence"]["source"],
            "EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW"
        );
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
