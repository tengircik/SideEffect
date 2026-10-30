#![cfg(windows)]

use serde_json::Value;
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temporary_directory() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "sideeffect-windows-process-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn windows_process_command_includes_current_test_process_and_refuses_overwrite() {
    let directory = temporary_directory();
    let output = directory.join("processes.json");
    let run = |working_directory: &std::path::Path, output_path: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .args(["inventory", "processes", "--output"])
            .arg(output_path)
            .current_dir(working_directory)
            .output()
            .unwrap()
    };

    let first = run(&directory, &output);
    assert!(
        first.status.success() || first.status.code() == Some(2),
        "unexpected CLI result: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let bytes = fs::read(&output).unwrap();
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(document["schema"], "sideeffect.windows_process_inventory");
    assert_eq!(document["platform"], "windows");
    assert_eq!(
        document["scope"],
        "toolhelp_process_snapshot_and_queryable_image_paths"
    );
    assert!(document["processes"].as_array().is_some());
    assert!(document["processes"].as_array().unwrap().iter().any(|row| {
        row["process_id"] == std::process::id()
            && row["evidence"]["snapshot_source"] == "ToolHelp32Snapshot/PROCESSENTRY32W"
    }));

    let second = run(&directory, &output);
    assert!(!second.status.success());
    assert_eq!(fs::read(&output).unwrap(), bytes);

    let relative_output = std::path::Path::new("relative-processes.json");
    let relative = run(&directory, relative_output);
    assert!(
        relative.status.success() || relative.status.code() == Some(2),
        "relative output path failed: {}",
        String::from_utf8_lossy(&relative.stderr)
    );
    assert!(directory.join(relative_output).is_file());
    fs::remove_file(directory.join(relative_output)).unwrap();

    fs::remove_file(output).unwrap();
    fs::remove_dir(directory).unwrap();
}
