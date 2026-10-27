#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use sideeffect::audit_session::{SourceRole, SourceStatus, parse_manifest};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let root = std::env::temp_dir();
        for _ in 0..32 {
            let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!(
                "sideeffect-audit-session-test-{}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create test directory: {error}"),
            }
        }
        panic!("could not allocate a unique audit-session test directory")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn audit_cli_publishes_private_session_with_verified_source_intervals_and_hashes() {
    let directory = TestDirectory::new();
    let output = directory.0.join("audit.session");
    let permission_target = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&output)
        .arg("--packages")
        .arg("--processes")
        .arg("--startup")
        .arg("--permission")
        .arg(permission_target)
        .output()
        .unwrap();

    assert!(
        result.status.success() || result.status.code() == Some(2),
        "audit failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let root_metadata = fs::symlink_metadata(&output).unwrap();
    assert!(root_metadata.is_dir());
    assert!(!root_metadata.file_type().is_symlink());
    assert_eq!(root_metadata.permissions().mode() & 0o777, 0o700);

    let mut names = fs::read_dir(&output)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        [
            "packages.json",
            "permissions.json",
            "processes.json",
            "session.json",
            "startup.json"
        ]
    );

    let manifest_bytes = fs::read(output.join("session.json")).unwrap();
    let manifest = parse_manifest(&manifest_bytes).unwrap();
    assert_eq!(manifest.platform, "linux");
    assert_eq!(manifest.sources.len(), 4);
    assert!(manifest.started_at_unix_ms <= manifest.ended_at_unix_ms);
    let roles = manifest
        .sources
        .iter()
        .map(|source| source.role)
        .collect::<Vec<_>>();
    assert_eq!(
        roles,
        [
            SourceRole::Packages,
            SourceRole::Processes,
            SourceRole::Startup,
            SourceRole::Permissions
        ]
    );
    for source in &manifest.sources {
        assert!(source.started_at_unix_ms >= manifest.started_at_unix_ms);
        assert!(source.ended_at_unix_ms <= manifest.ended_at_unix_ms);
        assert!(source.started_at_unix_ms <= source.ended_at_unix_ms);
        assert!(matches!(
            source.status,
            SourceStatus::Complete | SourceStatus::Partial
        ));
        for artifact in &source.artifacts {
            let path = output.join(&artifact.path);
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(metadata.is_file());
            assert!(!metadata.file_type().is_symlink());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            let bytes = fs::read(path).unwrap();
            assert_eq!(artifact.byte_length, bytes.len() as u64);
            assert_eq!(artifact.sha256, format!("{:x}", Sha256::digest(&bytes)));
        }
    }
    let expected_exit = if manifest.status == sideeffect::audit_session::SessionStatus::Complete {
        0
    } else {
        2
    };
    assert_eq!(result.status.code(), Some(expected_exit));
}

#[test]
fn audit_cli_rejects_an_empty_source_selection_without_publishing() {
    let directory = TestDirectory::new();
    let output = directory.0.join("empty.session");
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();

    assert_eq!(result.status.code(), Some(1));
    assert!(!output.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("select at least one source"));
}
