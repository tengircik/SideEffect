#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-permissions-inventory-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn explicit_path_inventory_is_private_versioned_and_no_clobber() {
    let temp = Temp::new();
    let source = temp.0.join("selected-file");
    fs::write(&source, b"synthetic permission fixture").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
    let output = temp.0.join("permissions.json");
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "permissions", "--output"])
        .arg(&output)
        .arg(&source)
        .output()
        .expect("start SideEffect permission inventory CLI");
    assert!(matches!(result.status.code(), Some(0 | 2)));
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("effective access was not evaluated"));
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(value["schema"], "sideeffect.permission_inventory");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["platform"], "linux");
    assert_eq!(value["scope"], "explicit_paths_metadata_posix_acl");
    assert_eq!(value["objects"].as_array().unwrap().len(), 1);
    assert_eq!(value["objects"][0]["object_type"], "regular_file");
    assert_eq!(value["objects"][0]["mode"].as_u64().unwrap() & 0o777, 0o640);
    assert_eq!(value["objects"][0]["path"], source.to_str().unwrap());

    let original = fs::read(&output).unwrap();
    let collision = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "permissions", "--output"])
        .arg(&output)
        .arg(&source)
        .output()
        .expect("start output collision check");
    assert_eq!(collision.status.code(), Some(1));
    assert_eq!(fs::read(&output).unwrap(), original);
}

#[test]
fn final_symlink_is_reported_and_output_symlink_is_not_followed() {
    let temp = Temp::new();
    let source = temp.0.join("selected-file");
    fs::write(&source, b"synthetic permission fixture").unwrap();
    let source_link = temp.0.join("selected-link");
    symlink(&source, &source_link).unwrap();
    let output = temp.0.join("permissions.json");
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "permissions", "--output"])
        .arg(&output)
        .arg(&source_link)
        .output()
        .expect("start symlink permission inventory");
    assert_eq!(result.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(value["status"], "partial");
    assert_eq!(value["objects"][0]["object_type"], "symlink");
    assert_eq!(
        value["objects"][0]["diagnostics"][0]["code"],
        "final_symlink_not_followed"
    );

    let target = temp.0.join("output-target");
    fs::write(&target, b"keep target").unwrap();
    let output_link = temp.0.join("output-link");
    symlink(&target, &output_link).unwrap();
    let collision = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "permissions", "--output"])
        .arg(&output_link)
        .arg(&source)
        .output()
        .expect("start symlink output collision check");
    assert_eq!(collision.status.code(), Some(1));
    assert_eq!(fs::read(&target).unwrap(), b"keep target");
    assert!(
        fs::symlink_metadata(output_link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn non_utf8_selected_path_bytes_are_preserved() {
    let temp = Temp::new();
    let mut filename = b"file-".to_vec();
    filename.push(0xff);
    let source = temp.0.join(OsString::from_vec(filename));
    fs::write(&source, b"synthetic permission fixture").unwrap();
    let output = temp.0.join("permissions.json");
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "permissions", "--output"])
        .arg(&output)
        .arg(&source)
        .output()
        .expect("start non-UTF-8 path inventory");
    assert!(matches!(result.status.code(), Some(0 | 2)));
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert!(value["objects"][0]["path"].is_null());
    assert!(
        value["objects"][0]["path_bytes_hex"]
            .as_str()
            .unwrap()
            .ends_with("ff")
    );
}
