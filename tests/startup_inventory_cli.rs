#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-startup-inventory-cli-{}-{}",
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
fn discovers_injected_xdg_roots_and_publishes_private_no_clobber_json() {
    let temp = Temp::new();
    let config_home = temp.0.join("config");
    let user_autostart = config_home.join("autostart");
    let system_root = temp.0.join("system");
    let system_autostart = system_root.join("autostart");
    fs::create_dir_all(&user_autostart).unwrap();
    fs::create_dir_all(&system_autostart).unwrap();
    fs::write(
        user_autostart.join("user.desktop"),
        b"[Desktop Entry]\nType=Application\nName=User\nName=Duplicate\nExec=literal %F\n",
    )
    .unwrap();
    fs::write(
        system_autostart.join("system.desktop"),
        b"[Desktop Entry]\nName=System\n",
    )
    .unwrap();
    let output = temp.0.join("startup.json");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .args(["inventory", "startup", "--output"])
            .arg(&output)
            .env("HOME", &temp.0)
            .env("XDG_CONFIG_HOME", &config_home)
            .env("XDG_CONFIG_DIRS", &system_root)
            .output()
            .unwrap()
    };
    let result = run();
    assert_eq!(result.status.code(), Some(0));
    assert!(result.stdout.is_empty());
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(value["schema"], "sideeffect.startup_inventory");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["scope"], "xdg_autostart_files_only");
    let entries = value["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let user = entries.iter().find(|e| e["scope"] == "user").unwrap();
    assert_eq!(user["applicability"], "not_evaluated");
    let keys = user["keys"].as_array().unwrap();
    assert_eq!(keys.iter().filter(|k| k["key"] == "Name").count(), 2);
    assert!(
        keys.iter()
            .any(|k| k["key"] == "Exec" && k["value"] == "literal %F")
    );
    assert_eq!(run().status.code(), Some(1));
}

#[test]
fn malformed_synthetic_desktop_input_publishes_private_partial_inventory() {
    let temp = Temp::new();
    let config_home = temp.0.join("config");
    let user_autostart = config_home.join("autostart");
    fs::create_dir_all(&user_autostart).unwrap();

    let source = user_autostart.join("synthetic-malformed.desktop");
    let contents = b"[Desktop Entry]\nName=Synthetic fixture\nExecWithoutEquals\n";
    fs::write(&source, contents).unwrap();
    let output = temp.0.join("partial-startup.json");
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "startup", "--output"])
        .arg(&output)
        .env("HOME", &temp.0)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_CONFIG_DIRS", temp.0.join("no-system-config"))
        .output()
        .expect("start SideEffect startup inventory CLI");

    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    let metadata = fs::metadata(&output).expect("partial startup inventory output exists");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    let value: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(value["schema"], "sideeffect.startup_inventory");
    assert_eq!(value["status"], "partial");

    let source_path = source.to_string_lossy();
    let malformed_offset = contents
        .windows(b"ExecWithoutEquals".len())
        .position(|window| window == b"ExecWithoutEquals")
        .unwrap();
    let directories = value["directories"].as_array().unwrap();
    let user_directory = directories
        .iter()
        .find(|row| row["scope"] == "user")
        .unwrap();
    assert_eq!(user_directory["status"], "partial");
    let diagnostics = user_directory["diagnostics"].as_array().unwrap();
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic["code"] == "malformed_line"
            && diagnostic["path"].as_str() == Some(source_path.as_ref())
            && diagnostic["line"] == 3
            && diagnostic["byte_offset"] == malformed_offset
    }));
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic["code"] == "malformed_desktop_entry"
            && diagnostic["path"].as_str() == Some(source_path.as_ref())
    }));

    let entries = value["entries"].as_array().unwrap();
    let entry = entries
        .iter()
        .find(|entry| entry["source_path"].as_str() == Some(source_path.as_ref()))
        .expect("malformed source remains represented in the inventory");
    assert!(entry["keys"].as_array().unwrap().iter().any(|evidence| {
        evidence["key"] == "unparsed"
            && evidence["value"] == "ExecWithoutEquals"
            && evidence["line"] == 3
            && evidence["byte_offset"] == malformed_offset
    }));
}
