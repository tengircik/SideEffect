#![cfg(windows)]

use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temp_dir() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "sideeffect-windows-etw-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn invalid_duration_is_rejected_before_etw_or_target_launch() {
    let directory = temp_dir();
    let output = directory.join("capture.json");
    let marker = directory.join("target-launched");
    let command = cli(&[
        "record",
        "--windows-etw",
        output.to_str().unwrap(),
        "--duration-seconds",
        "0",
        "--",
        "cmd.exe",
        "/C",
        &format!("echo started>{}", marker.display()),
    ]);
    assert!(!command.status.success());
    assert!(String::from_utf8_lossy(&command.stderr).contains("from 1 to 60 seconds"));
    assert!(!output.exists());
    assert!(!marker.exists());
    fs::remove_dir(directory).unwrap();
}

#[test]
fn existing_output_is_refused_before_target_launch() {
    let directory = temp_dir();
    let output = directory.join("capture.json");
    let original = b"leave this file alone";
    fs::write(&output, original).unwrap();
    let marker = directory.join("target-launched");
    let command = cli(&[
        "record",
        "--windows-etw",
        output.to_str().unwrap(),
        "--duration-seconds",
        "1",
        "--",
        "cmd.exe",
        "/C",
        &format!("echo started>{}", marker.display()),
    ]);
    assert!(!command.status.success());
    assert!(String::from_utf8_lossy(&command.stderr).contains("refusing to overwrite"));
    assert_eq!(fs::read(&output).unwrap(), original);
    assert!(!marker.exists());
    fs::remove_file(output).unwrap();
    fs::remove_dir(directory).unwrap();
}

#[test]
fn record_help_explains_system_scope_and_permissions() {
    let output = cli(&["help", "record"]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("system-wide events"));
    assert!(text.contains("No automatic elevation"));
    assert!(text.contains("does not attribute every file event"));
}
