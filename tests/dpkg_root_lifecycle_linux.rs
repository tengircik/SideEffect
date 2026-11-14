#![cfg(target_os = "linux")]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const PACKAGE_NAME: &str = "sideeffect-r5-synthetic-lifecycle";
const PACKAGE_DIRECTORY: &str = "usr/lib/sideeffect-r5-synthetic-lifecycle";
const PAYLOAD_NAME: &str = "payload.bin";
const ANCHOR_NAME: &str = "fixture-owned-anchor.txt";
const ANCHOR_CONTENT: &[u8] = b"fixture-owned directory anchor\n";
const DPKG: &str = "/usr/bin/dpkg";
const DPKG_DEB: &str = "/usr/bin/dpkg-deb";
const DPKG_QUERY: &str = "/usr/bin/dpkg-query";
const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        for _ in 0..32 {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is after Unix epoch")
                .as_nanos();
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-dpkg-root-lifecycle-{}-{nonce}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .expect("make the fixture parent private");
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create private temporary directory: {error}"),
            }
        }
        panic!("could not allocate a unique private temporary directory")
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn package_tool(program: &str) -> Command {
    assert!(Path::new(program).is_absolute());
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LC_ALL", "C");
    command
}

fn require_tool(program: &str) {
    assert!(
        Path::new(program).is_file(),
        "required tool {program} is missing"
    );
    let output = package_tool(program)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| {
            panic!("required lifecycle test tool {program} is unavailable: {error}")
        });
    assert!(
        output.status.success(),
        "{program} --version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn build_scriptless_deb(parent: &Path, version: &str, payload: &[u8]) -> PathBuf {
    let package_tree = parent.join(format!("package-{version}"));
    let control_dir = package_tree.join("DEBIAN");
    let payload_dir = package_tree.join(PACKAGE_DIRECTORY);
    fs::create_dir_all(&control_dir).unwrap();
    fs::create_dir_all(&payload_dir).unwrap();
    fs::write(
        control_dir.join("control"),
        format!(
            "Package: {PACKAGE_NAME}\nVersion: {version}\nArchitecture: all\nMaintainer: SideEffect Test <test@example.invalid>\nDescription: Scriptless synthetic lifecycle fixture\n"
        ),
    )
    .unwrap();
    fs::write(payload_dir.join(PAYLOAD_NAME), payload).unwrap();
    let control_entries: Vec<_> = fs::read_dir(&control_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(control_entries, vec![std::ffi::OsString::from("control")]);

    let deb = parent.join(format!("{PACKAGE_NAME}_{version}_all.deb"));
    let output = package_tool(DPKG_DEB)
        .args(["--build"])
        .arg(&package_tree)
        .arg(&deb)
        .env("TMPDIR", parent)
        .output()
        .expect("launch dpkg-deb --build");
    assert!(
        output.status.success(),
        "dpkg-deb failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    deb
}

fn isolated_dpkg_command(root: &Path, private_parent: &Path) -> Command {
    let root = root
        .canonicalize()
        .expect("canonicalize isolated dpkg root");
    let parent = private_parent
        .canonicalize()
        .expect("canonicalize private fixture parent");
    assert!(
        root.starts_with(&parent),
        "dpkg root escaped fixture directory"
    );
    assert_ne!(root, Path::new("/"), "refusing to target the host root");

    let admin = root.join("var/lib/dpkg");
    let log = parent.join("dpkg.log");
    assert!(
        admin.starts_with(&root),
        "dpkg admin path escaped private root"
    );
    assert!(
        log.starts_with(&parent),
        "dpkg log path escaped fixture directory"
    );

    let mut command = package_tool(DPKG);
    command
        .arg(format!("--root={}", root.display()))
        .arg(format!("--admindir={}", admin.display()))
        .arg(format!("--instdir={}", root.display()))
        .arg(format!("--log={}", log.display()))
        .args(["--force-not-root", "--no-triggers"])
        .env("TMPDIR", private_parent);
    command
}

fn dpkg_install(root: &Path, private_parent: &Path, deb: &Path, downgrade: bool) {
    let mut command = isolated_dpkg_command(root, private_parent);
    if downgrade {
        command.arg("--force-downgrade");
    }
    let output = command.arg("--install").arg(deb).output().unwrap();
    assert!(
        output.status.success(),
        "isolated dpkg install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn dpkg_purge(root: &Path, private_parent: &Path) {
    let output = isolated_dpkg_command(root, private_parent)
        .args(["--purge", PACKAGE_NAME])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated dpkg purge failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_private_dpkg_query(root: &Path, private_parent: &Path, expected_version: &str) {
    let root = root.canonicalize().unwrap();
    let parent = private_parent.canonicalize().unwrap();
    assert!(root.starts_with(&parent));
    let admin = root.join("var/lib/dpkg");
    assert!(admin.starts_with(&root));
    let showformat = "--showformat=${db:Status-Status}\t${Version}\n";
    let output = package_tool(DPKG_QUERY)
        .arg(format!("--admindir={}", admin.display()))
        .arg("--show")
        .arg(showformat)
        .arg(PACKAGE_NAME)
        .env("TMPDIR", private_parent)
        .output()
        .expect("launch dpkg-query with private admin directory");
    assert!(
        output.status.success(),
        "private dpkg-query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("installed\t{expected_version}\n")
    );
}

fn snapshot(root: &Path, output_path: &Path) -> Value {
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "root", "--hash-regular-files", "--output"])
        .arg(output_path)
        .arg(root)
        .output()
        .expect("launch SideEffect selected-root inventory");
    assert!(
        result.status.success(),
        "SideEffect selected-root snapshot failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&fs::read(output_path).unwrap()).unwrap()
}

fn snapshot_payload_hash(document: &Value, expected_payload: &[u8]) -> usize {
    assert_eq!(document["schema"], "sideeffect.selected_root_inventory");
    assert_eq!(document["schema_version"], 2);
    assert_eq!(document["status"], "complete");
    let entries = document["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let anchor = entries
        .iter()
        .find(|entry| entry["display_name"] == ANCHOR_NAME)
        .expect("fixture-owned anchor keeps the selected directory present");
    assert_eq!(anchor["content_hash_status"], "observed");
    assert_eq!(anchor["content_sha256"], sha256_hex(ANCHOR_CONTENT));
    let entry = entries
        .iter()
        .find(|entry| entry["display_name"] == PAYLOAD_NAME)
        .expect("package payload is present");
    assert_eq!(entry["content_hash_status"], "observed");
    assert_eq!(entry["content_sha256"], sha256_hex(expected_payload));
    assert_eq!(entry["evidence"]["source"], "selected_root_directory_entry");
    assert_eq!(entry["evidence"]["entry_ordinal"], entry["ordinal"]);
    entry["ordinal"].as_u64().unwrap() as usize
}

fn snapshot_diff(before: &Path, after: &Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(before)
        .arg(after)
        .output()
        .expect("launch SideEffect selected-root diff");
    assert!(
        output.status.success(),
        "SideEffect selected-root diff failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn private_dpkg_install_update_downgrade_purge_has_selected_root_evidence() {
    for tool in [DPKG, DPKG_DEB, DPKG_QUERY] {
        require_tool(tool);
    }

    let temporary = TempDirectory::new();
    let private_parent = &temporary.0;
    let private_root = private_parent.join("root");
    fs::create_dir(&private_root).unwrap();
    fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700)).unwrap();
    let install_root = private_root.join(PACKAGE_DIRECTORY);
    fs::create_dir_all(&install_root).unwrap();
    fs::write(install_root.join(ANCHOR_NAME), ANCHOR_CONTENT).unwrap();
    let payload_v1 = b"synthetic benign dpkg fixture revision A\n";
    let payload_v2 = b"synthetic benign dpkg fixture revision B\n";
    let deb_v1 = build_scriptless_deb(private_parent, "1.0-1", payload_v1);
    let deb_v2 = build_scriptless_deb(private_parent, "2.0-1", payload_v2);
    assert!(deb_v1.starts_with(private_parent));
    assert!(deb_v2.starts_with(private_parent));

    let before_install_path = private_parent.join("before-install.json");
    let before_install = snapshot(&install_root, &before_install_path);
    assert_eq!(before_install["status"], "complete");
    let before_entries = before_install["entries"].as_array().unwrap();
    assert_eq!(before_entries.len(), 1);
    assert_eq!(before_entries[0]["display_name"], ANCHOR_NAME);
    assert_eq!(
        before_entries[0]["content_sha256"],
        sha256_hex(ANCHOR_CONTENT)
    );

    dpkg_install(&private_root, private_parent, &deb_v1, false);
    assert_private_dpkg_query(&private_root, private_parent, "1.0-1");
    let v1_snapshot_path = private_parent.join("installed-v1.json");
    let v1_snapshot = snapshot(&install_root, &v1_snapshot_path);
    let v1_ordinal = snapshot_payload_hash(&v1_snapshot, payload_v1);
    let install_diff = snapshot_diff(&before_install_path, &v1_snapshot_path);
    assert_eq!(install_diff["counts"]["additions"], 1);
    assert_eq!(install_diff["deltas"][0]["kind"], "added");
    assert_eq!(
        install_diff["deltas"][0]["after"]["entry_ordinal"],
        v1_ordinal
    );
    assert_eq!(
        install_diff["deltas"][0]["after"]["evidence_source"],
        "selected_root_directory_entry"
    );

    dpkg_install(&private_root, private_parent, &deb_v2, false);
    assert_private_dpkg_query(&private_root, private_parent, "2.0-1");
    let v2_snapshot_path = private_parent.join("installed-v2.json");
    let v2_snapshot = snapshot(&install_root, &v2_snapshot_path);
    let v2_ordinal = snapshot_payload_hash(&v2_snapshot, payload_v2);
    assert_ne!(
        v1_snapshot["entries"][0]["content_sha256"],
        v2_snapshot["entries"][0]["content_sha256"]
    );
    let update_diff = snapshot_diff(&v1_snapshot_path, &v2_snapshot_path);
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
        v1_ordinal
    );
    assert_eq!(
        update_diff["deltas"][0]["after"]["entry_ordinal"],
        v2_ordinal
    );

    dpkg_install(&private_root, private_parent, &deb_v1, true);
    assert_private_dpkg_query(&private_root, private_parent, "1.0-1");
    let downgraded_snapshot_path = private_parent.join("downgraded-v1.json");
    let downgraded_snapshot = snapshot(&install_root, &downgraded_snapshot_path);
    let downgraded_ordinal = snapshot_payload_hash(&downgraded_snapshot, payload_v1);
    assert_eq!(
        downgraded_snapshot["entries"][0]["content_sha256"],
        v1_snapshot["entries"][0]["content_sha256"]
    );
    let downgrade_diff = snapshot_diff(&v2_snapshot_path, &downgraded_snapshot_path);
    assert_eq!(downgrade_diff["counts"]["changes"], 1);
    assert!(
        downgrade_diff["deltas"][0]["changed_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "content_sha256")
    );
    assert_eq!(
        downgrade_diff["deltas"][0]["before"]["entry_ordinal"],
        v2_ordinal
    );
    assert_eq!(
        downgrade_diff["deltas"][0]["after"]["entry_ordinal"],
        downgraded_ordinal
    );

    dpkg_purge(&private_root, private_parent);
    let admin = private_root.join("var/lib/dpkg");
    let query = package_tool(DPKG_QUERY)
        .arg(format!("--admindir={}", admin.display()))
        .arg("--show")
        .arg(PACKAGE_NAME)
        .env("TMPDIR", private_parent)
        .output()
        .expect("query private dpkg database after purge");
    assert!(!query.status.success());
    let purged_snapshot_path = private_parent.join("purged.json");
    let purged_snapshot = snapshot(&install_root, &purged_snapshot_path);
    assert_eq!(purged_snapshot["status"], "complete");
    let purged_entries = purged_snapshot["entries"].as_array().unwrap();
    assert_eq!(purged_entries.len(), 1);
    assert_eq!(purged_entries[0]["display_name"], ANCHOR_NAME);
    let purge_diff = snapshot_diff(&downgraded_snapshot_path, &purged_snapshot_path);
    assert_eq!(purge_diff["counts"]["removals"], 1);
    assert_eq!(purge_diff["deltas"][0]["kind"], "removed");
    assert_eq!(
        purge_diff["deltas"][0]["before"]["entry_ordinal"],
        downgraded_ordinal
    );
    assert_eq!(
        purge_diff["deltas"][0]["before"]["evidence_source"],
        "selected_root_directory_entry"
    );
    assert!(purge_diff["deltas"][0]["after"].is_null());

    assert!(private_root.starts_with(private_parent));
    assert!(admin.starts_with(&private_root));
    let log = private_parent.join("dpkg.log");
    assert!(log.starts_with(private_parent));
    assert!(log.is_file());
}
