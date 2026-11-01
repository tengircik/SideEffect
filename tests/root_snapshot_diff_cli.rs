use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempJson(std::path::PathBuf);

impl TempJson {
    fn new(bytes: &[u8]) -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sideeffect-root-diff-{}-{id}.json",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create synthetic root snapshot");
        file.write_all(bytes)
            .expect("write synthetic root snapshot");
        Self(path)
    }
}

impl Drop for TempJson {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn root_snapshot(rows: Value, status: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema":"sideeffect.selected_root_inventory",
        "schema_version":1,
        "platform":"linux",
        "scope":"one_explicit_root_and_its_direct_children_metadata_only",
        "captured_started_at_unix_ms":1,
        "captured_ended_at_unix_ms":2,
        "status":status,
        "root":{
            "display_path":"/tmp/sideeffect-synthetic-root",
            "path_bytes_hex":"2f746d702f736964656566666563742d73796e7468657469632d726f6f74",
            "object_type":"directory",
            "device_or_volume_serial":1,
            "inode_or_file_index":2
        },
        "entries":rows,
        "diagnostics":if status == "partial" { json!([{"code":"fixture_partial","entry_ordinal":null,"native_error":null}]) } else { json!([]) },
        "limits":{
            "max_root_path_bytes_or_utf16_units":4095,
            "max_entries":10000,
            "max_name_bytes_or_utf16_units":32767,
            "max_aggregate_name_bytes":8388608,
            "deadline_seconds":5
        }
    })).unwrap()
}

fn entry(name: &str, name_hex: &str, ordinal: usize, size: u64) -> Value {
    json!({
        "ordinal":ordinal,
        "display_name":name,
        "name_bytes_hex":name_hex,
        "object_type":"regular_file",
        "size_bytes":size,
        "modified_at_unix_ms":10,
        "device_or_volume_serial":1,
        "inode_or_file_index":ordinal + 10,
        "evidence":{"source":"selected_root_directory_entry","entry_ordinal":ordinal}
    })
}

#[test]
fn explain_inventory_diff_routes_selected_root_snapshots_and_writes_evidence() {
    let before = TempJson::new(&root_snapshot(
        json!([
            entry("kept", "6b657074", 0, 1),
            entry("gone", "676f6e65", 1, 2)
        ]),
        "complete",
    ));
    let after = TempJson::new(&root_snapshot(
        json!([
            entry("new", "6e6577", 0, 3),
            entry("kept", "6b657074", 1, 4)
        ]),
        "complete",
    ));
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(&before.0)
        .arg(&after.0)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let diff: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(diff["schema"], "sideeffect.selected_root_inventory_diff");
    assert_eq!(diff["counts"]["additions"], 1);
    assert_eq!(diff["counts"]["removals"], 1);
    assert_eq!(diff["counts"]["changes"], 1);
    assert_eq!(
        diff["deltas"][0]["before"]["evidence_source"],
        "selected_root_directory_entry"
    );
}

#[test]
fn partial_selected_root_comparison_returns_two_and_suppresses_presence_rows() {
    let before = TempJson::new(&root_snapshot(
        json!([entry("possibly gone", "706f737369626c7920676f6e65", 0, 1)]),
        "partial",
    ));
    let after = TempJson::new(&root_snapshot(json!([]), "complete"));
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(&before.0)
        .arg(&after.0)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    let diff: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(diff["status"], "partial");
    assert_eq!(diff["counts"]["removals"], 0);
    assert_eq!(diff["counts"]["unmatched_rows_suppressed"], 1);
}
