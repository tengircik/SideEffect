#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-inventory-test-{}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create inventory test directory: {error}"),
            }
        }
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn live_dpkg_query_writes_a_private_point_in_time_inventory() {
    if !PathBuf::from("/usr/bin/dpkg-query").is_file() {
        eprintln!("SKIP: live Debian inventory check requires /usr/bin/dpkg-query");
        return;
    }

    let directory = TempDirectory::new();
    let output = directory.0.join("inventory.json");
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "packages", "--output"])
        .arg(&output)
        .output()
        .expect("start SideEffect inventory CLI");
    assert_eq!(result.status.code(), Some(0));
    assert!(result.stdout.is_empty());

    let metadata = fs::metadata(&output).expect("inventory output exists");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let bytes = fs::read(&output).expect("read inventory output");
    let inventory: serde_json::Value =
        serde_json::from_slice(&bytes).expect("inventory output is valid JSON");
    assert_eq!(inventory["schema"], "sideeffect.inventory");
    assert_eq!(inventory["schema_version"], 1);
    assert_eq!(inventory["status"], "complete");
    assert_eq!(inventory["sources"][0]["id"], "dpkg_query");
    assert_eq!(inventory["sources"][0]["status"], "complete");
    assert!(
        inventory["packages"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
    );
    assert!(inventory.get("stderr").is_none());

    let collision = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "packages", "--output"])
        .arg(&output)
        .output()
        .expect("start second SideEffect inventory CLI");
    assert_eq!(collision.status.code(), Some(1));
    assert_eq!(
        fs::read(&output).expect("original inventory remains"),
        bytes
    );
}
