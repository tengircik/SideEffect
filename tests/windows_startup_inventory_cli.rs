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
fn windows_startup_command_reports_service_and_task_sources() {
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
    let bytes = fs::read(&output).unwrap();
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(document["schema"], "sideeffect.windows_startup_inventory");
    assert_eq!(document["schema_version"], 4);
    assert_eq!(document["platform"], "windows");
    match document["status"].as_str().unwrap() {
        "complete" => assert_eq!(first.status.code(), Some(0)),
        "partial" => assert_eq!(first.status.code(), Some(2)),
        status => panic!(
            "unexpected startup status {status:?}: {}",
            String::from_utf8_lossy(&first.stderr)
        ),
    }
    assert_eq!(
        document["scope"],
        "current_user_and_accessible_machine_run_keys_startup_folders_services_and_current_token_visible_tasks"
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
    assert!(matches!(
        scheduled_tasks["status"].as_str(),
        Some("complete" | "partial")
    ));
    assert_eq!(
        scheduled_tasks["entries_seen"].as_u64().unwrap(),
        document["scheduled_task_entries"].as_array().unwrap().len() as u64
    );
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
    let task_entries = document["scheduled_task_entries"].as_array().unwrap();
    for entry in task_entries {
        assert!(entry["task_path"].is_string());
        assert!(matches!(
            entry["trigger_type"].as_str(),
            Some("boot" | "logon")
        ));
        assert!(entry["task_enabled"].is_null() || entry["task_enabled"].is_boolean());
        assert!(entry["trigger_enabled"].is_null() || entry["trigger_enabled"].is_boolean());
        assert!(entry["logon_user"].is_null() || entry["logon_user"].is_string());
        assert!(entry["evidence"]["task_index"].is_number());
        assert!(entry["evidence"]["trigger_index"].is_number());
    }
    for action in document["scheduled_task_actions"].as_array().unwrap() {
        assert!(action["task_path"].is_null() || action["task_path"].is_string());
        assert!(action["action_index"].is_number());
        assert!(action["action_type"].is_string());
        assert!(action["action_type_code"].is_number() || action["action_type_code"].is_null());
        assert!(matches!(
            action["status"].as_str(),
            Some("observed" | "unsupported" | "partial")
        ));
        assert!(action["executable_path"].is_null() || action["executable_path"].is_string());
        assert!(action["arguments"].is_null() || action["arguments"].is_string());
        assert!(action["working_directory"].is_null() || action["working_directory"].is_string());
        assert!(action["evidence"]["task_index"].is_number());
        assert!(action["evidence"]["action_index"].is_number());
    }
    for entry in document["registry_entries"].as_array().unwrap() {
        assert!(entry["command"].is_null() || entry["command"].is_string());
        assert!(entry["command_utf16_hex"].is_null() || entry["command_utf16_hex"].is_string());
    }

    let compared = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(&output)
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(
        compared.status.code(),
        Some(if document["status"] == "complete" {
            0
        } else {
            2
        }),
        "{}",
        String::from_utf8_lossy(&compared.stderr)
    );
    let comparison: Value = serde_json::from_slice(&compared.stdout).unwrap();
    assert_eq!(comparison["schema"], "sideeffect.startup_inventory_diff");
    assert_eq!(comparison["platform"], "windows");
    assert_eq!(comparison["counts"]["changed"], 0);

    let second = run();
    assert!(!second.status.success());
    assert_eq!(fs::read(&output).unwrap(), bytes);
    fs::remove_file(output).unwrap();
    fs::remove_dir(directory).unwrap();
}
