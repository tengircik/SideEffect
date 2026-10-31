#![cfg(windows)]

use serde_json::{Value, json};
use sha2::Digest;
use std::fs;
use std::io::Write;
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
}

fn report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_code(output: &Output, expected: &str) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "unexpected status; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = report(output);
    assert_eq!(value["schema"], "sideeffect.audit_session_comparability");
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

fn make_linux_peer(path: &Path) {
    let mut value = manifest(path);
    let old_artifact = path.join("software.windows.json");
    let new_artifact = path.join("packages.json");
    let bytes = br#"{"schema":"sideeffect.inventory","schema_version":2}"#;
    fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&old_artifact)
        .unwrap()
        .write_all(bytes)
        .unwrap();
    fs::rename(old_artifact, &new_artifact).unwrap();
    value["platform"] = json!("linux");
    value["host_context"]["os_name"]["value"] = json!("Linux");
    let source = &mut value["sources"][0];
    source["platform"] = json!("linux");
    source["collector"]["id"] = json!("linux.debian_packages");
    source["scope"] = json!("selected package databases");
    source["artifacts"][0] = json!({
        "kind": "packages",
        "path": "packages.json",
        "schema": "sideeffect.inventory",
        "schema_version": 2,
        "byte_length": bytes.len(),
        "sha256": format!("{:x}", sha2::Sha256::digest(bytes)),
    });
    write_manifest(path, &value);
}

#[test]
fn windows_session_comparability_cli_preserves_metadata_only_and_reader_boundaries() {
    let root = TestDirectory::new();
    let before = audit(&root.0, "before");
    let after = audit(&root.0, "after");

    let compatible = compare(&before, &after);
    assert_eq!(compatible.status.code(), Some(0));
    let compatible_report = report(&compatible);
    assert_eq!(
        compatible_report["schema"],
        "sideeffect.audit_session_comparability"
    );
    assert_eq!(compatible_report["status"], "comparable");
    assert_eq!(compatible_report["scope"], "metadata_readiness_only");
    assert!(compatible_report["comparable"].as_bool().unwrap());
    assert_reason(&compatible, "partial_source");
    assert!(compatible_report.get("deltas").is_none());

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

    make_linux_peer(&after);
    assert_code(&compare(&before, &after), "platform_mismatch");

    let mut legacy = manifest(&before);
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
    let legacy_path = before.clone();
    write_manifest(&legacy_path, &legacy);
    let legacy_result = compare(&legacy_path, &after);
    assert_eq!(
        legacy_result.status.code(),
        Some(2),
        "legacy metadata mismatch; stderr: {}",
        String::from_utf8_lossy(&legacy_result.stderr)
    );
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

    fs::write(before.join("software.windows.json"), b"tampered artifact").unwrap();
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

    let malformed_artifact = audit(&root.0, "malformed-artifact");
    fs::write(malformed_artifact.join("software.windows.json"), b"{").unwrap();
    let mut malformed_artifact_manifest = manifest(&malformed_artifact);
    malformed_artifact_manifest["sources"][0]["artifacts"][0]["byte_length"] = json!(1);
    malformed_artifact_manifest["sources"][0]["artifacts"][0]["sha256"] =
        json!(format!("{:x}", sha2::Sha256::digest(b"{")));
    write_manifest(&malformed_artifact, &malformed_artifact_manifest);
    let rejected = compare(&malformed_artifact, &malformed_artifact);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("bounded JSON"));

    let malformed = audit(&root.0, "malformed");
    fs::write(malformed.join("session.json"), b"{").unwrap();
    let rejected = compare(&malformed, &malformed);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("manifest"));
}
