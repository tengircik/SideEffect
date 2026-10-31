#![cfg(target_os = "linux")]

use serde_json::Value;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        loop {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-access-check-linux-{}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .expect("restrict synthetic fixture directory");
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create synthetic fixture directory: {error}"),
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
fn access_check_runs_real_faccessat2_and_preserves_unknown_conclusion() {
    let directory = TempDirectory::new();
    let selected = directory.0.join("synthetic-file.txt");
    let original_contents = b"synthetic access-check fixture";
    fs::write(&selected, original_contents).expect("create synthetic selected file");
    fs::set_permissions(&selected, fs::Permissions::from_mode(0o600))
        .expect("set owner-readable fixture mode");
    let before_metadata = fs::metadata(&selected).expect("read fixture metadata before probe");
    let before_modified = before_metadata.modified().expect("read fixture mtime");
    let before_mode = before_metadata.mode();
    let before_inode = before_metadata.ino();
    let before_device = before_metadata.dev();
    let before_uid = before_metadata.uid();
    let before_gid = before_metadata.gid();
    let before_ctime = (before_metadata.ctime(), before_metadata.ctime_nsec());
    let output = directory.0.join("access-check.json");

    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args([
            "inventory",
            "access-check",
            "--operation",
            "read",
            "--output",
        ])
        .arg(&output)
        .arg(&selected)
        .output()
        .expect("start SideEffect access-check CLI");

    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("calculated effective-access conclusion remains unknown")
    );
    assert_eq!(
        fs::metadata(&output)
            .expect("access-check output exists")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let document: Value =
        serde_json::from_slice(&fs::read(&output).expect("read access-check output"))
            .expect("access-check output is JSON");
    assert_eq!(document["schema"], "sideeffect.linux_access_analysis");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["platform"], "linux");
    assert_eq!(
        document["scope"],
        "single_absolute_path_current_calling_thread_non_mutating_permission_probe"
    );
    assert_eq!(document["status"], "partial");
    assert_eq!(document["operation"], "read");
    assert_eq!(
        document["selected_path"]["path_display"],
        selected.to_str().unwrap()
    );
    assert_eq!(
        document["selected_path"]["path_byte_length"].as_u64(),
        Some(selected.as_os_str().as_bytes().len() as u64)
    );
    let expected_path_hex =
        selected
            .as_os_str()
            .as_bytes()
            .iter()
            .fold(String::new(), |mut output, byte| {
                write!(output, "{byte:02x}").expect("write to String");
                output
            });
    assert_eq!(
        document["selected_path"]["path_bytes_hex"],
        expected_path_hex
    );
    assert_eq!(document["selected_path"]["resolution_status"], "observed");
    assert_eq!(document["selected_path"]["device"], before_device);
    assert_eq!(document["selected_path"]["inode"], before_inode);
    assert_eq!(document["selected_path"]["object_type"], "regular_file");
    assert_eq!(document["observed_attempt"], Value::Null);
    assert_eq!(document["configured_facts"]["status"], "observed");
    assert_eq!(
        document["configured_facts"]["source"],
        "fstat_on_pinned_o_path_descriptor"
    );
    assert_eq!(document["configured_facts"]["uid"], before_uid);
    assert_eq!(document["configured_facts"]["gid"], before_gid);
    assert_eq!(document["configured_facts"]["mode"], before_mode);
    assert_eq!(document["observed_kernel_check"]["api"], "faccessat2");
    assert_eq!(
        document["observed_kernel_check"]["path_resolution"],
        "kernel_resolved_to_pinned_object_by_open_o_path; ancestors_and_symlink_chain_not_retained"
    );
    assert_eq!(
        document["observed_kernel_check"]["flags"],
        serde_json::json!(["AT_EMPTY_PATH", "AT_EACCESS"])
    );
    assert_eq!(
        document["observed_kernel_check"]["status"],
        "allowed_by_kernel_probe"
    );
    assert!(document["observed_kernel_check"]["raw_errno"].is_null());
    assert_eq!(document["calculated_conclusion"], "unknown");
    assert_eq!(
        document["controls"][0]["control"],
        "calling_thread_effective_credentials"
    );
    assert_eq!(
        document["controls"][1]["control"],
        "kernel_vfs_permission_probe"
    );
    assert_eq!(document["controls"][1]["status"], "observed");

    let after_metadata = fs::metadata(&selected).expect("read fixture metadata after probe");
    assert_eq!(
        fs::read(&selected).expect("probe leaves file contents unchanged"),
        original_contents
    );
    assert_eq!(after_metadata.mode(), before_mode);
    assert_eq!(after_metadata.ino(), before_inode);
    assert_eq!(
        after_metadata
            .modified()
            .expect("read fixture mtime after probe"),
        before_modified
    );
    assert_eq!(
        (after_metadata.ctime(), after_metadata.ctime_nsec()),
        before_ctime
    );
}
