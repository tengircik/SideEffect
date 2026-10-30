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
    assert_eq!(value["schema_version"], 4);
    assert_eq!(value["host_context"]["os_name"]["value"], "Windows");
    assert!(value["host_context"]["privilege"].is_string());
    assert_eq!(value["platform"], "windows");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_session_collects_each_inventory_role_and_inspector_preserves_scope() {
    let root = temp_dir();
    let selected_path = root.join("selected.txt");
    fs::write(&selected_path, b"synthetic permission target").unwrap();
    let session = root.join("all-inventories");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&session)
        .arg("--packages")
        .arg("--processes")
        .arg("--startup")
        .arg("--permission")
        .arg(&selected_path)
        .output()
        .unwrap();
    assert!(
        published(&output),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for file in [
        "software.windows.json",
        "processes.windows.json",
        "permissions.windows.json",
        "startup.windows.json",
        "session.json",
    ] {
        assert!(session.join(file).is_file(), "missing {file}");
    }

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
    let review: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(review["platform"], "windows");
    for (role, expected_scope) in [
        ("packages", "bounded uninstall-registry registrations"),
        (
            "processes",
            "visible Tool Help process snapshot and permitted image paths",
        ),
        (
            "permissions",
            "explicit caller-selected paths only; no recursion or effective-access evaluation",
        ),
        (
            "startup",
            "selected Run/RunOnce, Startup folders, services, and visible boot/logon scheduled tasks",
        ),
    ] {
        let source = review["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|source| source["role"] == role)
            .unwrap_or_else(|| panic!("missing {role} source in session review"));
        assert_eq!(source["scope"], expected_scope);
        assert!(source["started_at_unix_ms"].as_u64().is_some());
        assert!(source["ended_at_unix_ms"].as_u64().is_some());
        assert_eq!(source["artifacts"].as_array().unwrap().len(), 1);
    }
    assert_eq!(review["sources"].as_array().unwrap().len(), 4);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_session_keeps_a_missing_selected_path_visible_as_not_applicable() {
    let root = temp_dir();
    let missing_path = root.join("does-not-exist.txt");
    let session = root.join("partial");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&session)
        .arg("--permission")
        .arg(&missing_path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));

    let inspect = cli(&[
        "inspect",
        "--format",
        "json",
        "--session",
        session.to_str().unwrap(),
    ]);
    assert_eq!(inspect.status.code(), Some(2));
    let review: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(review["status"], "partial");
    let permissions = review["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["role"] == "permissions")
        .unwrap();
    assert_eq!(permissions["status"], "not_applicable");
    assert_eq!(permissions["artifacts"].as_array().unwrap().len(), 1);
    assert!(session.join("permissions.windows.json").is_file());
    assert!(
        permissions["diagnostic_codes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|code| code == "source_not_present")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_runtime_requires_explicit_source_duration_and_command_before_capture() {
    let root = temp_dir();
    let session = root.join("audit");
    let output = cli(&[
        "audit",
        "--output",
        session.to_str().unwrap(),
        "--runtime-source",
        "windows-etw",
    ]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires --runtime-duration-seconds")
    );
    assert!(!session.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_runtime_duration_is_rejected_without_a_runtime_source() {
    let root = temp_dir();
    let session = root.join("audit");
    let output = cli(&[
        "audit",
        "--output",
        session.to_str().unwrap(),
        "--packages",
        "--runtime-duration-seconds",
        "1",
    ]);

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--runtime-duration-seconds requires --runtime-source windows-etw")
    );
    assert!(!session.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_runtime_refuses_existing_session_destination_before_target_launch() {
    let root = temp_dir();
    let session = root.join("audit");
    fs::create_dir(&session).unwrap();
    fs::write(session.join("sentinel"), b"keep").unwrap();
    let marker = root.join("target-launched");
    let command = cli(&[
        "audit",
        "--output",
        session.to_str().unwrap(),
        "--runtime-source",
        "windows-etw",
        "--runtime-duration-seconds",
        "1",
        "--",
        "cmd.exe",
        "/C",
        &format!("echo started>{}", marker.display()),
    ]);
    assert!(!command.status.success());
    assert!(String::from_utf8_lossy(&command.stderr).contains("already exists"));
    assert!(!marker.exists());
    assert_eq!(fs::read(session.join("sentinel")).unwrap(), b"keep");
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
