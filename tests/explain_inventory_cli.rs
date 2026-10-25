use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempJson(std::path::PathBuf);

impl TempJson {
    fn with_contents(contents: &[u8]) -> Self {
        let path = Self::next_path();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create synthetic inventory JSON");
        file.write_all(contents)
            .expect("write synthetic inventory JSON");
        Self(path)
    }

    fn oversized_sparse_file(length: u64) -> Self {
        let path = Self::next_path();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create oversized inventory JSON")
            .set_len(length)
            .expect("extend sparse inventory JSON");
        Self(path)
    }

    fn next_path() -> std::path::PathBuf {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "sideeffect-explain-inventory-cli-{}-{id}.json",
            std::process::id()
        ))
    }
}

impl Drop for TempJson {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn inventory(status: &str, packages: serde_json::Value) -> Vec<u8> {
    serde_json::json!({
        "schema": "sideeffect.inventory",
        "schema_version": 2,
        "platform": "linux",
        "scope": "available_package_manager_databases",
        "captured_at_unix_ms": 10,
        "status": status,
        "sources": [{
            "id": "dpkg_query",
            "status": status,
            "exit_code": 0,
            "records_seen": packages.as_array().map_or(0, Vec::len),
            "diagnostics": []
        }],
        "packages": packages
    })
    .to_string()
    .into_bytes()
}

fn package(name: &str, version: &str, line: usize, raw_record: &str) -> serde_json::Value {
    serde_json::json!({
        "source_id": "dpkg_query",
        "name": name,
        "version": version,
        "architecture": "amd64",
        "status_abbrev": "ii ",
        "evidence": {
            "line": line,
            "byte_offset": line * 10,
            "byte_length": 8,
            "record_sha256": "synthetic-sensitive-fingerprint",
            "raw_record": raw_record
        }
    })
}

#[test]
fn explain_inventory_diff_reports_changes_and_evidence_without_raw_rows_or_hashes() {
    let before = TempJson::with_contents(&inventory(
        "complete",
        serde_json::json!([
            package("retained", "1", 1, "before-private-row"),
            package("removed", "1", 2, "removed-private-row")
        ]),
    ));
    let after = TempJson::with_contents(&inventory(
        "complete",
        serde_json::json!([
            package("retained", "2", 3, "after-private-row"),
            package("added", "1", 4, "added-private-row")
        ]),
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(&before.0)
        .arg(&after.0)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "complete");
    assert_eq!(json["counts"]["additions"], 1);
    assert_eq!(json["counts"]["removals"], 1);
    assert_eq!(json["counts"]["changes"], 1);
    let changed = json["deltas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|delta| delta["kind"] == "changed")
        .unwrap();
    assert_eq!(changed["before"]["evidence"]["byte_offset"], 10);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("private-row"));
    assert!(!text.contains("synthetic-sensitive-fingerprint"));
    assert!(!text.contains("record_sha256"));
    assert!(!text.contains("raw_record"));
}

#[test]
fn explain_inventory_diff_does_not_claim_removals_from_partial_source() {
    let mut before_document: serde_json::Value = serde_json::from_slice(&inventory(
        "partial",
        serde_json::json!([package("maybe-removed", "1", 1, "synthetic")]),
    ))
    .unwrap();
    before_document["sources"][0]["status"] = serde_json::json!("not_checked");
    let before = TempJson::with_contents(before_document.to_string().as_bytes());
    let after = TempJson::with_contents(&inventory("complete", serde_json::json!([])));
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(&before.0)
        .arg(&after.0)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "partial");
    assert_eq!(json["sources"][0]["before_status"], "not_checked");
    assert_eq!(json["counts"]["removals"], 0);
    assert_eq!(json["counts"]["unmatched_rows_with_incomplete_source"], 1);
}

#[test]
fn explain_inventory_diff_rejects_malformed_and_unknown_fields() {
    let malformed = TempJson::with_contents(b"{not-json");
    let valid = TempJson::with_contents(&inventory("complete", serde_json::json!([])));
    let malformed_output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(&malformed.0)
        .arg(&valid.0)
        .output()
        .unwrap();
    assert!(!malformed_output.status.success());
    assert!(malformed_output.stdout.is_empty());

    let mut unknown: serde_json::Value =
        serde_json::from_slice(&inventory("complete", serde_json::json!([]))).unwrap();
    unknown["unexpected"] = serde_json::json!("reject");
    let unknown = TempJson::with_contents(unknown.to_string().as_bytes());
    let unknown_output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(&unknown.0)
        .arg(&valid.0)
        .output()
        .unwrap();
    assert!(!unknown_output.status.success());
    assert!(unknown_output.stdout.is_empty());
}

#[test]
fn explain_inventory_diff_rejects_oversized_input_before_parsing() {
    let limit_plus_one = TempJson::oversized_sparse_file(64 * 1024 * 1024 + 1);
    let valid = TempJson::with_contents(&inventory("complete", serde_json::json!([])));
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(&limit_plus_one.0)
        .arg(&valid.0)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exceeds the 67108864 byte limit"));
}
