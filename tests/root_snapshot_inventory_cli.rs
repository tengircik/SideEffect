use serde_json::Value;
use std::fs;
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
