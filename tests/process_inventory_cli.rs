#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-process-inventory-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn live_proc_inventory_writes_private_schema_without_fixed_count_assumptions() {
    let directory = Temp::new();
    let output = directory.0.join("processes.json");
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "processes", "--output"])
        .arg(&output)
        .output()
        .expect("start SideEffect process inventory CLI");
    assert!(matches!(result.status.code(), Some(0 | 2)));
    assert!(result.stdout.is_empty());
    let metadata = fs::metadata(&output).expect("process inventory output exists");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(value["schema"], "sideeffect.process_inventory");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["platform"], "linux");
    assert_eq!(value["scope"], "numeric_proc_status_entries");
    assert!(value["capture_started_at_unix_ms"].as_u64().is_some());
    assert!(value["capture_ended_at_unix_ms"].as_u64().is_some());
    assert!(matches!(
        value["status"].as_str(),
        Some("complete" | "partial")
    ));
    assert!(value["processes"].as_array().is_some());
    assert!(
        value["processes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row.get("cmdline").is_none() && row.get("exe").is_none())
    );
    let collision = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "processes", "--output"])
        .arg(&output)
        .output()
        .expect("start collision check");
    assert_eq!(collision.status.code(), Some(1));
}
