#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use sha2::Digest;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-session-comparability-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn audit(root: &Path, name: &str) -> PathBuf {
    let output_path = root.join(name);
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&output_path)
        .arg("--packages")
        .output()
        .unwrap();
    assert!(
        matches!(output.status.code(), Some(0 | 2)),
        "audit fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output_path
}

fn compare(before: &Path, after: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-sessions")
        .arg(before)
        .arg(after)
        .output()
        .unwrap()
}

fn manifest(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path.join("session.json")).unwrap()).unwrap()
}

fn write_manifest(path: &Path, value: &Value) {
    fs::write(
        path.join("session.json"),
        serde_json::to_vec_pretty(value).unwrap(),
    )
    .unwrap();
    fs::set_permissions(path.join("session.json"), fs::Permissions::from_mode(0o600)).unwrap();
}

fn write_package_artifact(path: &Path, version: &str) {
    let bytes = serde_json::to_vec(&json!({
        "schema":"sideeffect.inventory", "schema_version":2, "platform":"linux",
        "scope":"available_package_manager_databases", "captured_at_unix_ms":1001,
        "status":"complete",
        "sources":[{"id":"dpkg_query","status":"complete","exit_code":0,"records_seen":1,"diagnostics":[]}],
        "packages":[{"source_id":"dpkg_query","name":"synthetic-demo","version":version,"architecture":"amd64","status_abbrev":"ii ","evidence":{"line":1,"byte_offset":0,"byte_length":8,"record_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","raw_record":null,"raw_record_hex":null},"diagnostic_code":null}]
    }))
    .unwrap();
    fs::write(path.join("packages.json"), &bytes).unwrap();
    fs::set_permissions(
        path.join("packages.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut value = manifest(path);
    let reference = &mut value["sources"][0]["artifacts"][0];
    reference["byte_length"] = json!(bytes.len());
    reference["sha256"] = json!(format!("{:x}", sha2::Sha256::digest(&bytes)));
    write_manifest(path, &value);
}

fn report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_code(output: &Output, expected: &str) {
    assert_eq!(output.status.code(), Some(2));
    let value = report(output);
    assert_eq!(value["schema"], "sideeffect.audit_session_diff");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["status"], "incomparable");
    assert!(
        value["reason_codes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|code| code == expected)
    );
}

fn assert_reason(output: &Output, expected: &str) {
    let value = report(output);
    assert!(
        value["reason_codes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|code| code == expected)
    );
}

fn make_windows_peer(path: &Path) {
    let mut value = manifest(path);
    let old_artifact = path.join("packages.json");
    let new_artifact = path.join("software.windows.json");
    let bytes = br#"{"schema":"sideeffect.windows_software_inventory","schema_version":1}"#;
    fs::remove_file(old_artifact).unwrap();
    fs::write(&new_artifact, bytes).unwrap();
    fs::set_permissions(&new_artifact, fs::Permissions::from_mode(0o600)).unwrap();
    value["platform"] = json!("windows");
    value["host_context"]["os_name"]["value"] = json!("Windows");
    let source = &mut value["sources"][0];
    source["platform"] = json!("windows");
    source["collector"]["id"] = json!("windows.software_registry");
    source["scope"] = json!("bounded uninstall-registry registrations");
    source["artifacts"][0] = json!({
        "kind": "windows_software",
        "path": "software.windows.json",
        "schema": "sideeffect.windows_software_inventory",
        "schema_version": 1,
        "byte_length": bytes.len(),
        "sha256": format!("{:x}", sha2::Sha256::digest(bytes)),
    });
    write_manifest(path, &value);
}

#[test]
fn session_comparability_cli_reports_metadata_readiness_and_rejects_unverified_inputs() {
    let root = TestDirectory::new();
    let before = audit(&root.0, "before");
    let after = audit(&root.0, "after");

    let compatible = compare(&before, &after);
    assert_eq!(compatible.status.code(), Some(0));
    let compatible_report = report(&compatible);
    assert_eq!(compatible_report["status"], "comparable");
    assert_eq!(
        compatible_report["metadata_scope"],
        "metadata_readiness_only"
    );
    assert_eq!(
        compatible_report["scope"],
        "metadata_and_item_level_inventory_and_runtime"
    );
    assert!(compatible_report["comparable"].as_bool().unwrap());
    assert_reason(&compatible, "partial_source");
    assert!(compatible_report["limitations"].as_array().unwrap().len() >= 3);
    assert!(
        compatible_report["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item
                == "Caller privilege contexts are not comparability keys and may differ.")
    );
    assert!(compatible_report["source_diffs"].is_array());
    assert_eq!(compatible_report["item_comparison_status"], "partial");

    let mut changed = manifest(&after);
    changed["sources"][0]["scope"] = json!("changed bounded scope");
    write_manifest(&after, &changed);
    assert_code(&compare(&before, &after), "source_scope_mismatch");

    changed["sources"][0]["scope"] = manifest(&before)["sources"][0]["scope"].clone();
    changed["sources"][0]["requested_settings"] = json!([{"code":"fixture_setting","value":1}]);
    write_manifest(&after, &changed);
    assert_code(&compare(&before, &after), "requested_settings_mismatch");

    changed["sources"][0]["requested_settings"] = json!([]);
    changed["status"] = json!("partial");
    changed["sources"][0]["status"] = json!("unknown");
    changed["coverage_manifest"]["sources"][0]["status"] = json!("unknown");
    write_manifest(&after, &changed);
    let partial = compare(&before, &after);
    assert_code(&partial, "coverage_mismatch");
    assert!(
        report(&partial)["reason_codes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "partial_source")
    );

    make_windows_peer(&after);
    assert_code(&compare(&before, &after), "platform_mismatch");

    let legacy_path = audit(&root.0, "legacy");
    let mut legacy = manifest(&legacy_path);
    legacy["schema_version"] = json!(1);
    legacy.as_object_mut().unwrap().remove("host_context");
    legacy.as_object_mut().unwrap().remove("coverage_manifest");
    legacy["sources"][0]
        .as_object_mut()
        .unwrap()
        .remove("collector");
    legacy["sources"][0]
        .as_object_mut()
        .unwrap()
        .remove("requested_settings");
    legacy["sources"][0]
        .as_object_mut()
        .unwrap()
        .remove("effective_settings");
    write_manifest(&legacy_path, &legacy);
    let legacy_result = compare(&legacy_path, &before);
    assert_eq!(legacy_result.status.code(), Some(2));
    let legacy_report = report(&legacy_result);
    for reason in [
        "host_os_unknown",
        "source_settings_unknown",
        "coverage_unknown",
    ] {
        assert!(
            legacy_report["reason_codes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|code| code == reason)
        );
    }

    fs::write(before.join("packages.json"), b"tampered artifact").unwrap();
    let rejected = compare(&before, &before);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(
        {
            let error = String::from_utf8_lossy(&rejected.stderr);
            error.contains("hash") || error.contains("byte length")
        },
        "unexpected rejection: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );

    let insecure = audit(&root.0, "insecure");
    fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755)).unwrap();
    let rejected = compare(&insecure, &insecure);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("private"));
}

#[test]
fn compare_sessions_reports_synthetic_package_change_with_artifact_evidence() {
    let root = TestDirectory::new();
    let before = audit(&root.0, "before-delta");
    let after = audit(&root.0, "after-delta");
    write_package_artifact(&before, "1.0");
    write_package_artifact(&after, "2.0");

    let output = compare(&before, &after);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = report(&output);
    assert_eq!(report["schema"], "sideeffect.audit_session_diff");
    assert_eq!(report["item_comparison_status"], "partial");
    let package = report["source_diffs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["role"] == "packages")
        .unwrap();
    assert_eq!(package["status"], "partial");
    assert_eq!(package["before_artifacts"][0]["path"], "packages.json");
    assert_eq!(
        package["before_artifacts"][0]["sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        package["after_artifacts"][0]["sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(package["comparison"]["deltas"].as_array().unwrap().len(), 1);
    assert_eq!(package["comparison"]["deltas"][0]["kind"], "changed");
    assert_eq!(
        package["comparison"]["deltas"][0]["before"]["version"],
        "1.0"
    );
    assert_eq!(
        package["comparison"]["deltas"][0]["after"]["version"],
        "2.0"
    );
    assert_eq!(
        package["comparison"]["deltas"][0]["before"]["evidence"]["line"],
        1
    );
}
