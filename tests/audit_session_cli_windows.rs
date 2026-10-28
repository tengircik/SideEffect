#![cfg(windows)]

use std::fs;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
fn temp_dir() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "sideeffect-audit-session-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(args)
        .output()
        .unwrap()
}
fn published(output: &Output) -> bool {
    matches!(output.status.code(), Some(0 | 2))
}

#[test]
fn windows_session_publishes_and_inspects_selected_source_with_private_acl() {
    let root = temp_dir();
    let session = root.join("audit");
    let output = cli(&["audit", "--output", session.to_str().unwrap(), "--packages"]);
    assert!(
        published(&output),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata = fs::symlink_metadata(&session).unwrap();
    assert!(metadata.is_dir());
    assert!(session.join("session.json").is_file());
    assert!(session.join("software.windows.json").is_file());
    let inspect = cli(&[
        "inspect",
        "--format",
        "json",
        "--session",
        session.to_str().unwrap(),
    ]);
    assert!(
        published(&inspect),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(value["schema"], "sideeffect.audit_session_review");
    assert_eq!(value["platform"], "windows");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_runtime_is_explicitly_unsupported_and_session_is_partial() {
    let root = temp_dir();
    let session = root.join("audit");
    let output = cli(&[
        "audit",
        "--output",
        session.to_str().unwrap(),
        "--runtime-source",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let inspect = cli(&[
        "inspect",
        "--format",
        "json",
        "--session",
        session.to_str().unwrap(),
    ]);
    assert_eq!(inspect.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(value["status"], "partial");
    assert_eq!(value["sources"][0]["status"], "unsupported");
    assert!(
        value["sources"][0]["artifacts"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_inspector_rejects_tampering_unlisted_entries_and_manifest_version_changes() {
    let root = temp_dir();
    let session = root.join("audit");
    let output = cli(&["audit", "--output", session.to_str().unwrap(), "--packages"]);
    assert!(published(&output));
    fs::write(session.join("unlisted.bin"), b"extra").unwrap();
    assert!(
        !cli(&["inspect", "--session", session.to_str().unwrap()])
            .status
            .success()
    );
    fs::remove_file(session.join("unlisted.bin")).unwrap();
    let artifact = session.join("software.windows.json");
    let mut bytes = fs::read(&artifact).unwrap();
    bytes.push(b' ');
    fs::write(&artifact, bytes).unwrap();
    assert!(
        !cli(&["inspect", "--session", session.to_str().unwrap()])
            .status
            .success()
    );
    fs::remove_file(&artifact).unwrap();
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(session.join("session.json")).unwrap()).unwrap();
    manifest["schema_version"] = 99.into();
    fs::write(
        session.join("session.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    assert!(
        !cli(&["inspect", "--session", session.to_str().unwrap()])
            .status
            .success()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_audit_rejects_command_capture_and_never_overwrites_destination() {
    let root = temp_dir();
    let session = root.join("audit");
    let invalid = cli(&[
        "audit",
        "--output",
        session.to_str().unwrap(),
        "--runtime-duration-seconds",
        "1",
        "--",
        "cmd",
    ]);
    assert!(!invalid.status.success());
    fs::create_dir(&session).unwrap();
    fs::write(session.join("sentinel"), b"keep").unwrap();
    let existing = cli(&["audit", "--output", session.to_str().unwrap(), "--packages"]);
    assert!(!existing.status.success());
    assert_eq!(fs::read(session.join("sentinel")).unwrap(), b"keep");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_inspector_rejects_a_reparse_point_when_windows_allows_test_creation() {
    use std::os::windows::fs::symlink_dir;
    let root = temp_dir();
    let session = root.join("audit");
    let output = cli(&["audit", "--output", session.to_str().unwrap(), "--packages"]);
    assert!(published(&output));
    let link = root.join("link");
    if symlink_dir(&session, &link).is_ok() {
        assert!(
            !cli(&["inspect", "--session", link.to_str().unwrap()])
                .status
                .success()
        );
    }
    fs::remove_dir_all(root).unwrap();
}
