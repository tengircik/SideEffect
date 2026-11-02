use serde_json::Value;
use std::fs;
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
                "sideeffect-case-cli-test-{}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                    }
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create case test directory: {error}"),
            }
        }
        panic!("could not allocate a unique case test directory")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn case_help_describes_the_partial_workflow_and_integrity_boundary() {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("help")
        .arg("case")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("sideeffect case init"));
    assert!(help.contains("sideeffect case resolve"));
    assert!(help.contains("not producer authenticity"));
    assert!(help.contains("sensitive local evidence"));
}

#[test]
fn case_cli_initializes_and_resolves_against_a_verified_session_without_overwriting() {
    let directory = TestDirectory::new();
    let session = directory.0.join("session");
    let audit = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&session)
        .arg("--packages")
        .output()
        .unwrap();
    assert!(
        audit.status.success() || audit.status.code() == Some(2),
        "audit fixture setup failed: {}",
        String::from_utf8_lossy(&audit.stderr)
    );

    let case_path = directory.0.join("review.case.json");
    let init = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("init")
        .arg("--output")
        .arg(&case_path)
        .arg("--title")
        .arg("CLI case workflow integration")
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "case init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let case_bytes = fs::read(&case_path).unwrap();
    let case: Value = serde_json::from_slice(&case_bytes).unwrap();
    assert_eq!(case["schema"], "sideeffect.investigation_case");
    assert_eq!(case["schema_version"], 1);
    assert_eq!(case["title"], "CLI case workflow integration");
    assert_eq!(case["sessions"].as_array().unwrap().len(), 1);
    assert_eq!(case["entries"].as_array().unwrap().len(), 0);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&case_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let second_init = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("init")
        .arg("--output")
        .arg(&case_path)
        .arg("--title")
        .arg("Should not replace existing case")
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(!second_init.status.success());
    assert_eq!(fs::read(&case_path).unwrap(), case_bytes);

    let resolved = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("resolve")
        .arg("--case")
        .arg(&case_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(
        resolved.status.success() || resolved.status.code() == Some(2),
        "case resolve failed: {}",
        String::from_utf8_lossy(&resolved.stderr)
    );
    let report: Value = serde_json::from_slice(&resolved.stdout).unwrap();
    assert_eq!(report["schema"], "sideeffect.resolved_investigation_case");
    assert_eq!(report["case_id"], case["case_id"]);
    assert_eq!(report["facts"].as_array().unwrap().len(), 0);
    assert_eq!(report["entries"].as_array().unwrap().len(), 0);
    assert_eq!(report["sessions"].as_array().unwrap().len(), 1);
    assert!(
        report["disclosure_note"]
            .as_str()
            .unwrap()
            .contains("not producer authenticity")
    );
}

#[test]
fn case_cli_rejects_unmatched_session_counts_and_oversized_case_files() {
    let directory = TestDirectory::new();
    let case_path = directory.0.join("oversized.case.json");
    fs::write(&case_path, vec![b' '; sideeffect::case::MAX_CASE_BYTES + 1]).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("resolve")
        .arg("--case")
        .arg(case_path)
        .arg("--session")
        .arg(directory.0.join("missing-session"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("case input exceeds"));
}
