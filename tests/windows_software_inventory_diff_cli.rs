use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempJson(std::path::PathBuf);

impl TempJson {
    fn with_value(value: serde_json::Value) -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sideeffect-windows-software-diff-{}-{id}.json",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create synthetic Windows software inventory");
        file.write_all(value.to_string().as_bytes())
            .expect("write synthetic inventory");
        Self(path)
    }
}

impl Drop for TempJson {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn source(
    id: &str,
    hive: &str,
    view: &str,
    status: &str,
    registrations_seen: usize,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "status": status,
        "registrations_seen": registrations_seen,
        "hive": hive,
        "registry_key": "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "registry_view": view,
        "diagnostics": []
    })
}

fn base_document(status: &str, registrations: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "schema": "sideeffect.windows_software_inventory",
        "schema_version": 1,
        "platform": "windows",
        "scope": "current_user_and_accessible_machine_uninstall_registry_entries",
        "capture_started_at_unix_ms": 100,
        "capture_ended_at_unix_ms": 110,
        "status": status,
        "sources": [
            source("current_user_native_uninstall", "HKEY_CURRENT_USER", "native", "complete", registrations.len()),
            source("current_user_32_uninstall", "HKEY_CURRENT_USER", "wow64_32", "complete", 0),
            source("local_machine_64_uninstall", "HKEY_LOCAL_MACHINE", "wow64_64", "complete", 0),
            source("local_machine_32_uninstall", "HKEY_LOCAL_MACHINE", "wow64_32", "complete", 0)
        ],
        "registrations": registrations
    })
}

fn registration(
    subkey: &str,
    display_name: &str,
    version: &str,
    publisher: &str,
    registration_index: usize,
) -> serde_json::Value {
    let subkey_utf16_hex = utf16_units_hex(subkey);
    serde_json::json!({
        "registry_subkey": subkey,
        "registry_subkey_utf16_hex": subkey_utf16_hex,
        "display_name": display_name,
        "values": [
            {"name":"DisplayName","registry_type":1,"type_name":"REG_SZ","text":display_name,"raw_data_hex":utf16le_hex(display_name)},
            {"name":"DisplayVersion","registry_type":1,"type_name":"REG_SZ","text":version,"raw_data_hex":utf16le_hex(version)},
            {"name":"Publisher","registry_type":1,"type_name":"REG_SZ","text":publisher,"raw_data_hex":utf16le_hex(publisher)},
            {"name":"UninstallString","registry_type":1,"type_name":"REG_SZ","text":"C:\\private\\uninstall.exe --secret-argument","raw_data_hex":utf16le_hex("C:\\private\\uninstall.exe --secret-argument")}
        ],
        "evidence": {
            "source":"RegEnumKeyExW/RegQueryValueExW",
            "hive":"HKEY_CURRENT_USER",
            "registry_view":"native",
            "registry_key":"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "registration_index":registration_index,
            "registry_subkey":subkey
        }
    })
}

fn utf16_units_hex(text: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::new();
    for unit in text.encode_utf16() {
        for shift in [12, 8, 4, 0] {
            output.push(HEX[((unit >> shift) & 0xf) as usize] as char);
        }
    }
    output
}

fn utf16le_hex(text: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::new();
    for unit in text.encode_utf16() {
        for byte in unit.to_le_bytes() {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0xf) as usize] as char);
        }
    }
    output
}

fn run_diff(before: &serde_json::Value, after: &serde_json::Value) -> std::process::Output {
    let before = TempJson::with_value(before.clone());
    let after = TempJson::with_value(after.clone());
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(&before.0)
        .arg(&after.0)
        .output()
        .expect("run inventory comparison")
}

#[test]
fn windows_diff_reports_registration_add_remove_and_safe_fact_changes() {
    let before = base_document(
        "complete",
        vec![
            registration("Vendor\\Keep", "Keep App", "1.0", "Vendor A", 0),
            registration("Vendor\\Remove", "Removed App", "1.0", "Vendor B", 1),
        ],
    );
    let after = base_document(
        "complete",
        vec![
            registration("Vendor\\Keep", "Keep App", "2.0", "Vendor A", 1),
            registration("Vendor\\Add", "Added App", "1.0", "Vendor C", 0),
        ],
    );
    let output = run_diff(&before, &after);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["schema"], "sideeffect.windows_software_inventory_diff");
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
    assert_eq!(
        changed["changed_fields"],
        serde_json::json!(["display_version"])
    );
    assert_eq!(changed["before"]["evidence"]["registration_index"], 0);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("uninstall.exe"));
    assert!(!text.contains("secret-argument"));
    assert!(!text.contains("raw_data_hex"));
}

#[test]
fn windows_diff_marks_duplicates_ambiguous_and_incomplete_sources_suppress_removals() {
    let mut before = base_document(
        "partial",
        vec![
            registration("Vendor\\Duplicate", "Duplicate", "1", "Vendor", 0),
            registration("Vendor\\Duplicate", "Duplicate", "1", "Vendor", 1),
            registration("Vendor\\Maybe", "Maybe", "1", "Vendor", 2),
        ],
    );
    before["sources"][0]["status"] = serde_json::json!("partial");
    let after = base_document("complete", vec![]);
    let output = run_diff(&before, &after);
    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "partial");
    assert_eq!(json["counts"]["removals"], 0);
    assert_eq!(json["counts"]["unmatched_rows_with_incomplete_source"], 1);
    assert_eq!(json["counts"]["ambiguous_identity_groups"], 1);
    assert!(json["deltas"].as_array().unwrap().is_empty());
}

#[test]
fn windows_diff_requires_strict_v1_same_platform_inputs_and_exact_key_encoding() {
    let valid = base_document(
        "complete",
        vec![registration("Vendor\\App", "App", "1", "Vendor", 0)],
    );
    let mut unknown = valid.clone();
    unknown["registrations"][0]["unexpected"] = serde_json::json!(true);
    let output = run_diff(&unknown, &valid);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let mut wrong_platform = valid.clone();
    wrong_platform["platform"] = serde_json::json!("linux");
    let output = run_diff(&wrong_platform, &valid);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let mut wrong_key = valid.clone();
    wrong_key["registrations"][0]["registry_subkey_utf16_hex"] = serde_json::json!("ffff");
    let output = run_diff(&wrong_key, &valid);
    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["counts"]["invalid_identity_rows"], 1);
    assert_eq!(json["counts"]["additions"], 0);
    assert_eq!(json["counts"]["removals"], 0);
}
