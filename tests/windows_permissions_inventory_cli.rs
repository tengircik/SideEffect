#![cfg(windows)]

use serde_json::Value;
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temporary_directory() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "sideeffect-windows-permissions-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn windows_permission_command_snapshots_explicit_path_and_refuses_overwrite() {
    let directory = temporary_directory();
    let selected = directory.join("selected.txt");
    fs::write(&selected, b"permission inventory smoke fixture").unwrap();
    let output = directory.join("permissions.json");

    let run = || {
        Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .args(["inventory", "permissions", "--output"])
            .arg(&output)
            .arg(&selected)
            .output()
            .unwrap()
    };
    let first = run();
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let bytes = fs::read(&output).unwrap();
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        document["schema"],
        "sideeffect.windows_permission_inventory"
    );
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["platform"], "windows");
    assert_eq!(
        document["scope"],
        "explicit_paths_only; final_reparse_points_opened_without_following; no_sacl; no_effective_access_calculation"
    );
    assert_eq!(document["status"], "complete");
    assert_eq!(document["objects"].as_array().unwrap().len(), 1);
    assert_eq!(document["objects"][0]["status"], "complete");
    assert_eq!(document["objects"][0]["metadata"]["is_directory"], false);
    assert!(
        document["objects"][0]["security"]["descriptor_raw_hex"]
            .as_str()
            .unwrap()
            .len()
            >= 40
    );
    assert!(document["objects"][0]["security"]["descriptor_sha256"].is_string());
    assert!(document["objects"][0]["security"]["dacl_state"].is_string());

    let second = run();
    assert!(!second.status.success());
    assert_eq!(fs::read(&output).unwrap(), bytes);
    fs::remove_file(output).unwrap();
    fs::remove_file(selected).unwrap();
    fs::remove_dir(directory).unwrap();
}
