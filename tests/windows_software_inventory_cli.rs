#![cfg(windows)]

use serde_json::Value;
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temporary_directory() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "sideeffect-windows-software-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn windows_package_command_reports_registered_software_and_refuses_overwrite() {
    let directory = temporary_directory();
    let output = directory.join("software.json");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .args(["inventory", "packages", "--output"])
            .arg(&output)
            .output()
            .unwrap()
    };

    let first = run();
    assert!(
        first.status.success() || first.status.code() == Some(2),
        "unexpected CLI status: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let bytes = fs::read(&output).unwrap();
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(document["schema"], "sideeffect.windows_software_inventory");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["platform"], "windows");
    assert_eq!(
        document["scope"],
        "current_user_and_accessible_machine_uninstall_registry_entries"
    );
    assert_eq!(document["sources"].as_array().unwrap().len(), 4);
    assert!(document["registrations"].as_array().is_some());
    for source in document["sources"].as_array().unwrap() {
        assert!(source["status"].is_string());
        assert!(source["hive"].is_string());
        assert!(source["registry_view"].is_string());
    }
    for registration in document["registrations"].as_array().unwrap() {
        assert!(registration["registry_subkey"].is_string());
        assert!(registration["evidence"]["registry_key"].is_string());
        for value in registration["values"].as_array().unwrap() {
            assert!(value["name"].is_string());
            assert!(value["raw_data_hex"].is_string());
            assert!(value["text"].is_null() || value["text"].is_string());
        }
    }

    let second = run();
    assert!(!second.status.success());
    assert_eq!(fs::read(&output).unwrap(), bytes);
    fs::remove_file(output).unwrap();
    fs::remove_dir(directory).unwrap();
}
