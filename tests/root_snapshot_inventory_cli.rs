use serde_json::Value;
use std::fs;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture_dir(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sideeffect-root-cli-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

struct TempFixture(PathBuf);

impl TempFixture {
    fn new(label: &str) -> Self {
        Self(fixture_dir(label))
    }
}

impl Deref for TempFixture {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for TempFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn inventory_root_writes_bounded_evidence_linked_direct_children() {
    let temp = fixture_dir("complete");
    let root = temp.join("selected");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("fixture.txt"), b"synthetic fixture contents").unwrap();
    fs::create_dir(root.join("nested")).unwrap();
    let output = temp.join("snapshot.json");

    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "root", "--output"])
        .arg(&output)
        .arg(&root)
        .output()
        .unwrap();
    assert!(result.status.success());

    let document: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(document["schema"], "sideeffect.selected_root_inventory");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["status"], "complete");
    assert_eq!(document["entries"].as_array().unwrap().len(), 2);
    for row in document["entries"].as_array().unwrap() {
        assert_eq!(row["evidence"]["source"], "selected_root_directory_entry");
        assert_eq!(row["ordinal"], row["evidence"]["entry_ordinal"]);
    }
    assert!(
        document["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["display_name"] != "synthetic fixture contents")
    );
    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn missing_root_is_written_as_partial_and_returns_status_two() {
    let temp = fixture_dir("missing");
    let output = temp.join("snapshot.json");
    let missing = temp.join("does-not-exist");
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "root", "--output"])
        .arg(&output)
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    let document: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(document["status"], "partial");
    assert_eq!(document["root"], Value::Null);
    assert_eq!(document["diagnostics"][0]["code"], "root_open_failed");
    fs::remove_dir_all(temp).unwrap();
}

fn inventory(root: &std::path::Path, output: &std::path::Path, hash: bool) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
    command.args(["inventory", "root"]);
    if hash {
        command.arg("--hash-regular-files");
    }
    let result = command
        .arg("--output")
        .arg(output)
        .arg(root)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&fs::read(output).unwrap()).unwrap()
}

fn inventory_diff(before: &std::path::Path, after: &std::path::Path) -> Value {
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(before)
        .arg(after)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

fn fixture_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

fn assert_snapshot_hash(document: &Value, expected: &str) -> usize {
    assert_eq!(document["schema"], "sideeffect.selected_root_inventory");
    assert_eq!(document["schema_version"], 2);
    assert_eq!(document["status"], "complete");
    let entries = document["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["content_hash_status"], "observed");
    assert_eq!(entry["content_sha256"], expected);
    assert_eq!(entry["evidence"]["source"], "selected_root_directory_entry");
    assert_eq!(entry["evidence"]["entry_ordinal"], entry["ordinal"]);
    entry["ordinal"].as_u64().unwrap() as usize
}

#[test]
fn synthetic_selected_root_install_update_rollback_uninstall_tracks_content_and_evidence() {
    let temp = TempFixture::new("synthetic-lifecycle");
    let root = temp.join("selected-install-root");
    fs::create_dir(&root).unwrap();
    let install_before_path = temp.join("before-install.json");
    let install_before = inventory(&root, &install_before_path, true);
    assert_eq!(install_before["schema_version"], 2);
    assert_eq!(install_before["status"], "complete");
    assert!(install_before["entries"].as_array().unwrap().is_empty());

    let file = root.join("synthetic-app.bin");
    let version_one = b"synthetic fixture application version one";
    let version_two = b"synthetic fixture application version two";
    fs::write(&file, version_one).unwrap();
    let installed_path = temp.join("installed.json");
    let installed = inventory(&root, &installed_path, true);
    let version_one_hash = fixture_sha256(version_one);
    let installed_ordinal = assert_snapshot_hash(&installed, &version_one_hash);
    let install_diff = inventory_diff(&install_before_path, &installed_path);
    assert_eq!(install_diff["status"], "complete");
    assert_eq!(install_diff["counts"]["additions"], 1);
    assert_eq!(install_diff["deltas"][0]["kind"], "added");
    assert_eq!(
        install_diff["deltas"][0]["after"]["evidence_source"],
        "selected_root_directory_entry"
    );
    assert_eq!(
        install_diff["deltas"][0]["after"]["entry_ordinal"],
        installed_ordinal
    );

    fs::write(&file, version_two).unwrap();
    let updated_path = temp.join("updated.json");
    let updated = inventory(&root, &updated_path, true);
    let version_two_hash = fixture_sha256(version_two);
    let updated_ordinal = assert_snapshot_hash(&updated, &version_two_hash);
    assert_ne!(version_one_hash, version_two_hash);
    let update_diff = inventory_diff(&installed_path, &updated_path);
    assert_eq!(update_diff["status"], "complete");
    assert_eq!(update_diff["counts"]["changes"], 1);
    assert!(
        update_diff["deltas"][0]["changed_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "content_sha256")
    );
    assert_eq!(
        update_diff["deltas"][0]["before"]["entry_ordinal"],
        installed_ordinal
    );
    assert_eq!(
        update_diff["deltas"][0]["after"]["entry_ordinal"],
        updated_ordinal
    );
    for side in ["before", "after"] {
        assert_eq!(
            update_diff["deltas"][0][side]["evidence_source"],
            "selected_root_directory_entry"
        );
    }

    fs::write(&file, version_one).unwrap();
    let rolled_back_path = temp.join("rolled-back.json");
    let rolled_back = inventory(&root, &rolled_back_path, true);
    let rolled_back_ordinal = assert_snapshot_hash(&rolled_back, &version_one_hash);
    let rollback_diff = inventory_diff(&updated_path, &rolled_back_path);
    assert_eq!(rollback_diff["status"], "complete");
    assert_eq!(rollback_diff["counts"]["changes"], 1);
    assert!(
        rollback_diff["deltas"][0]["changed_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "content_sha256")
    );
    assert_eq!(
        rollback_diff["deltas"][0]["before"]["entry_ordinal"],
        updated_ordinal
    );
    assert_eq!(
        rollback_diff["deltas"][0]["after"]["entry_ordinal"],
        rolled_back_ordinal
    );

    fs::remove_file(&file).unwrap();
    let uninstalled_path = temp.join("uninstalled.json");
    let uninstalled = inventory(&root, &uninstalled_path, true);
    assert_eq!(uninstalled["status"], "complete");
    assert!(uninstalled["entries"].as_array().unwrap().is_empty());
    let uninstall_diff = inventory_diff(&rolled_back_path, &uninstalled_path);
    assert_eq!(uninstall_diff["status"], "complete");
    assert_eq!(uninstall_diff["counts"]["removals"], 1);
    assert_eq!(uninstall_diff["deltas"][0]["kind"], "removed");
    assert_eq!(
        uninstall_diff["deltas"][0]["before"]["evidence_source"],
        "selected_root_directory_entry"
    );
    assert_eq!(
        uninstall_diff["deltas"][0]["before"]["entry_ordinal"],
        rolled_back_ordinal
    );
    assert!(uninstall_diff["deltas"][0]["after"].is_null());
}

#[test]
fn regular_file_hashing_is_opt_in_and_diff_detects_same_metadata_content_changes() {
    use std::time::{Duration, UNIX_EPOCH};
    let temp = fixture_dir("hash");
    let root = temp.join("selected");
    fs::create_dir(&root).unwrap();
    let file = root.join("program.bin");
    let at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fs::write(&file, b"AAAA").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(at)
        .unwrap();
    let default = inventory(&root, &temp.join("default.json"), false);
    assert_eq!(default["schema_version"], 1);
    assert!(default["entries"][0].get("content_sha256").is_none());
    let before = inventory(&root, &temp.join("before.json"), true);
    assert_eq!(before["schema_version"], 2);
    assert_eq!(before["entries"][0]["content_hash_status"], "observed");
    let before_mtime = before["entries"][0]["modified_at_unix_ms"].clone();
    fs::write(&file, b"BBBB").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(at)
        .unwrap();
    let after = inventory(&root, &temp.join("after.json"), true);
    assert_eq!(
        after["entries"][0]["size_bytes"],
        before["entries"][0]["size_bytes"]
    );
    assert_eq!(after["entries"][0]["modified_at_unix_ms"], before_mtime);
    let diff = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(temp.join("before.json"))
        .arg(temp.join("after.json"))
        .output()
        .unwrap();
    assert!(
        diff.status.success(),
        "{}",
        String::from_utf8_lossy(&diff.stderr)
    );
    let diff: Value = serde_json::from_slice(&diff.stdout).unwrap();
    assert!(
        diff["deltas"][0]["changed_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "content_sha256")
    );

    fs::write(&file, b"BBBB").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(at)
        .unwrap();
    let same = inventory(&root, &temp.join("same.json"), true);
    let same_diff = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(temp.join("after.json"))
        .arg(temp.join("same.json"))
        .output()
        .unwrap();
    assert!(
        same_diff.status.success(),
        "{}",
        String::from_utf8_lossy(&same_diff.stderr)
    );
    let same_diff: Value = serde_json::from_slice(&same_diff.stdout).unwrap();
    assert_eq!(same_diff["counts"]["unchanged"], 1);
    assert_eq!(
        same["entries"][0]["content_sha256"],
        after["entries"][0]["content_sha256"]
    );

    let mixed = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(temp.join("default.json"))
        .arg(temp.join("after.json"))
        .output()
        .unwrap();
    assert_eq!(mixed.status.code(), Some(2));
    let mixed: Value = serde_json::from_slice(&mixed.stdout).unwrap();
    assert_eq!(mixed["status"], "partial");
    assert!(
        mixed["deltas"][0]["unknown_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "content_sha256")
    );
    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn oversized_regular_file_hash_is_unavailable_and_makes_snapshot_partial() {
    let temp = fixture_dir("hash-limit");
    let root = temp.join("selected");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("large.bin"), vec![0x5a; 16 * 1024 * 1024 + 1]).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "root", "--hash-regular-files", "--output"])
        .arg(temp.join("snapshot.json"))
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    let doc: Value =
        serde_json::from_slice(&fs::read(temp.join("snapshot.json")).unwrap()).unwrap();
    assert_eq!(doc["status"], "partial");
    assert_eq!(doc["entries"][0]["content_hash_status"], "unavailable");
    assert!(doc["entries"][0].get("content_sha256").is_none());
    assert!(
        doc["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "content_hash_file_limit_exceeded")
    );
    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn aggregate_regular_file_hash_limit_is_reported_as_partial() {
    use std::io::Write;
    let temp = fixture_dir("hash-aggregate-limit");
    let root = temp.join("selected");
    fs::create_dir(&root).unwrap();
    for index in 0..4 {
        let file = fs::File::create(root.join(format!("large-{index}.bin"))).unwrap();
        file.set_len(16 * 1024 * 1024).unwrap();
    }
    fs::File::create(root.join("extra.bin"))
        .unwrap()
        .write_all(b"x")
        .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "root", "--hash-regular-files", "--output"])
        .arg(temp.join("snapshot.json"))
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    let doc: Value =
        serde_json::from_slice(&fs::read(temp.join("snapshot.json")).unwrap()).unwrap();
    assert_eq!(doc["status"], "partial");
    assert!(
        doc["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| { d["code"] == "content_hash_aggregate_limit_exceeded" })
    );
    fs::remove_dir_all(temp).unwrap();
}

#[cfg(unix)]
#[test]
fn opt_in_hash_does_not_follow_symlink_children() {
    use std::os::unix::fs::symlink;
    let temp = fixture_dir("symlink");
    let root = temp.join("selected");
    fs::create_dir(&root).unwrap();
    fs::write(temp.join("target"), b"sensitive target contents").unwrap();
    symlink(temp.join("target"), root.join("link")).unwrap();
    let doc = inventory(&root, &temp.join("snapshot.json"), true);
    let row = doc["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["display_name"] == "link")
        .unwrap();
    assert_eq!(row["object_type"], "symbolic_link");
    assert_eq!(row["content_hash_status"], "not_applicable");
    assert!(row.get("content_sha256").is_none() || row["content_sha256"].is_null());
    fs::remove_dir_all(temp).unwrap();
}

#[cfg(windows)]
#[test]
fn opt_in_hash_does_not_follow_reparse_children_when_symlink_creation_is_available() {
    use std::os::windows::fs::symlink_file;
    let temp = fixture_dir("reparse");
    let root = temp.join("selected");
    fs::create_dir(&root).unwrap();
    fs::write(temp.join("target"), b"sensitive target contents").unwrap();
    if symlink_file(temp.join("target"), root.join("link")).is_err() {
        fs::remove_dir_all(temp).unwrap();
        return;
    }
    let doc = inventory(&root, &temp.join("snapshot.json"), true);
    let row = doc["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["display_name"] == "link")
        .unwrap();
    assert_eq!(row["object_type"], "reparse_point");
    assert_eq!(row["content_hash_status"], "not_applicable");
    assert!(row.get("content_sha256").is_none() || row["content_sha256"].is_null());
    fs::remove_dir_all(temp).unwrap();
}
