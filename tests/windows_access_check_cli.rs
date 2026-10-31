#![cfg(windows)]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        loop {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-windows-access-check-{}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create synthetic fixture directory: {error}"),
            }
        }
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn access_check_uses_process_snapshot_identity_and_reports_conditional_dacl_result() {
    let directory = TempDirectory::new();
    let selected = directory.0.join("synthetic-file.txt");
    let original_contents = b"synthetic Windows DACL fixture";
    fs::write(&selected, original_contents).expect("create synthetic selected file");
    let before_modified = fs::metadata(&selected)
        .expect("read fixture metadata before check")
        .modified()
        .expect("read fixture modification time");
    let process_inventory = directory.0.join("processes.json");
    let snapshot = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "processes", "--output"])
        .arg(&process_inventory)
        .output()
        .expect("start Windows process inventory CLI");
    assert!(
        snapshot.status.success() || snapshot.status.code() == Some(2),
        "unexpected process inventory result: {}",
        String::from_utf8_lossy(&snapshot.stderr)
    );
    let inventory: Value = serde_json::from_slice(
        &fs::read(&process_inventory).expect("process inventory output exists"),
    )
    .expect("process inventory output is JSON");
    assert_eq!(inventory["schema"], "sideeffect.windows_process_inventory");
    assert_eq!(inventory["schema_version"], 3);
    let current_pid = std::process::id();
    let current_process = inventory["processes"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["process_id"] == current_pid));
    let Some(current_process) = current_process else {
        eprintln!(
            "SKIP: host process snapshot did not include this test process (PID {current_pid}); Windows access-check requires a snapshot identity."
        );
        return;
    };
    assert_eq!(
        current_process["evidence"]["snapshot_source"],
        "ToolHelp32Snapshot/PROCESSENTRY32W"
    );
    if current_process["creation_time"]["status"] != "observed" {
        eprintln!(
            "SKIP: host process snapshot could not observe this test process creation FILETIME; Windows access-check requires that generation identity."
        );
        return;
    }
    let Some(creation_time) = current_process["creation_time"]["filetime_100ns"].as_u64() else {
        eprintln!(
            "SKIP: host process snapshot omitted this test process creation FILETIME; Windows access-check requires that generation identity."
        );
        return;
    };
    assert_eq!(
        current_process["creation_time"]["source"],
        "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)/GetProcessTimes"
    );

    let output = directory.0.join("access-check.json");
    let pid_text = current_pid.to_string();
    let creation_time_text = creation_time.to_string();
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "access-check", "--pid"])
        .arg(pid_text)
        .args(["--creation-time-filetime"])
        .arg(creation_time_text)
        .args(["--operation", "read", "--output"])
        .arg(&output)
        .arg(&selected)
        .output()
        .expect("start Windows access-check CLI");
    assert_eq!(
        result.status.code(),
        Some(2),
        "expected a published partial/conditional DACL result: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    let document: Value =
        serde_json::from_slice(&fs::read(&output).expect("access-check output exists"))
            .expect("access-check output is JSON");

    if document["diagnostic_code"] == "appcontainer_token_not_supported" {
        eprintln!(
            "SKIP: host test process uses an AppContainer token, which this DACL check does not support."
        );
        return;
    }
    if document["diagnostic_code"] == "unsupported_dacl_ace"
        || document["diagnostic_code"] == "owner_rights_ace_not_supported"
    {
        eprintln!(
            "SKIP: host temporary-file DACL contains ACE semantics outside the supported basic allow/deny test prerequisite."
        );
        return;
    }
    if document["diagnostic_code"] == "remote_filesystem_not_supported"
        || document["diagnostic_code"] == "network_or_device_path_not_supported"
    {
        eprintln!("SKIP: host temporary directory is not on a supported local filesystem.");
        return;
    }

    assert_eq!(document["schema"], "sideeffect.windows_dacl_evaluation");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["status"], "conditional", "result: {document:#}");
    assert_eq!(
        document["conclusion"], "conditional",
        "result: {document:#}"
    );
    assert_eq!(document["process_id"], current_pid);
    assert_eq!(
        document["expected_creation_time_filetime_100ns"],
        creation_time
    );
    assert_eq!(
        document["observed_creation_time_filetime_100ns"],
        creation_time
    );
    assert_eq!(document["path"], selected.to_str().unwrap());
    assert_eq!(document["operation"], "read_data");
    assert!(matches!(
        document["dacl_decision"].as_str(),
        Some("granted_by_dacl" | "denied_by_dacl")
    ));
    assert!(document["requested_access_mask"].is_u64());
    assert!(document["granted_access_mask"].is_u64());
    assert_eq!(
        document["diagnostic_code"],
        "dacl_only_result_is_conditional"
    );
    let dacl_control = document["controls"]
        .as_array()
        .and_then(|controls| {
            controls
                .iter()
                .find(|control| control["control"] == "selected_object_dacl")
        })
        .expect("DACL control is present");
    assert_eq!(dacl_control["status"], "evaluated", "result: {document:#}");

    let after_metadata = fs::metadata(&selected).expect("read fixture metadata after check");
    assert_eq!(
        fs::read(&selected).expect("DACL check leaves file contents unchanged"),
        original_contents
    );
    assert_eq!(after_metadata.len(), original_contents.len() as u64);
    assert_eq!(
        after_metadata
            .modified()
            .expect("read fixture modification time after check"),
        before_modified
    );
}
