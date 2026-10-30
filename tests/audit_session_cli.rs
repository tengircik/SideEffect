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

    for format in ["json", "text"] {
        let reviewed = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .arg("inspect")
            .arg("--format")
            .arg(format)
            .arg("--session")
            .arg(&output)
            .output()
            .unwrap();
        assert_eq!(reviewed.status.code(), Some(expected_exit));
        assert!(reviewed.stderr.is_empty());
        if format == "json" {
            let review: serde_json::Value = serde_json::from_slice(&reviewed.stdout).unwrap();
            assert_eq!(review["schema"], "sideeffect.audit_session_review");
            assert_eq!(review["schema_version"], 5);
            assert!(review["sources"][0]["collector"]["id"].is_string());
            assert_eq!(review["host_context"]["os_name"]["status"], "observed");
            assert!(review["host_context"]["privilege"].is_string());
            assert_eq!(review["authenticity"], "not_established");
            assert_eq!(review["sources"].as_array().unwrap().len(), 4);
            assert!(review["sources"][0]["coverage_status"].is_string());
            assert_eq!(
                review["sources"][0]["artifacts"][0]["integrity"],
                "length_and_sha256_match_local_bytes"
            );
            assert_eq!(
                review["sources"][0]["artifacts"][0]["provenance"],
                "manifest_reference_verified_against_local_bytes"
            );
        } else {
            assert!(reviewed.stdout.is_ascii());
            let text = String::from_utf8(reviewed.stdout).unwrap();
            assert!(text.contains("SideEffect audit session review"));
            assert!(text.contains("no atomic system snapshot is claimed"));
            assert!(text.contains("hashes do not authenticate the source"));
            assert!(
                text.contains("Artifact provenance (verified local bytes; not authenticated):")
            );
        }
    }

    fs::write(output.join("packages.json"), b"tampered").unwrap();
    fs::set_permissions(
        output.join("packages.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("inspect")
        .arg("--session")
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(1));
    assert!(rejected.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("audit session verification failed")
    );
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

#[test]
fn audit_cli_includes_bounded_runtime_bundle_and_preserves_argument_boundaries() {
    let directory = TestDirectory::new();
    let output = directory.0.join("runtime.session");
    let script = "import sys; raise SystemExit(0 if sys.argv[1:] == ['alpha beta', ''] else 9)";
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&output)
        .arg("--runtime-duration-seconds")
        .arg("10")
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(script)
        .arg("alpha beta")
        .arg("")
        .output()
        .unwrap();

    assert_eq!(
        result.status.code(),
        Some(2),
        "runtime completeness must remain unknown: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let manifest = parse_manifest(&fs::read(output.join("session.json")).unwrap()).unwrap();
    assert_eq!(
        manifest.status,
        sideeffect::audit_session::SessionStatus::Partial
    );
    let runtime = manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::Runtime)
        .unwrap();
    assert_eq!(runtime.status, SourceStatus::Partial);
    assert!(runtime.started_at_unix_ms <= runtime.ended_at_unix_ms);
    assert_eq!(
        runtime.requested_settings[0].code,
        "runtime_duration_seconds"
    );
    assert_eq!(runtime.requested_settings[0].value, 10);
    assert_eq!(
        runtime.loss.as_ref().unwrap().status,
        sideeffect::audit_session::LossStatus::Unknown
    );
    assert!(
        runtime
            .diagnostic_codes
            .contains(&"runtime_capture_completeness_unknown".to_owned())
    );
    assert_eq!(runtime.artifacts.len(), 2);

    let run: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("run.json")).unwrap()).unwrap();
    let trace = fs::read(output.join("trace.strace")).unwrap();
    assert_eq!(run["schema"], "sideeffect.run");
    assert_eq!(run["schema_version"], 2);
    assert_eq!(run["capture"]["completeness"], "unknown");
    assert_eq!(run["capture"]["stop_reason"], "tracer_exited");
    assert_eq!(
        run["capture"]["strace_reported_status"]["kind"],
        "exit_code"
    );
    assert_eq!(run["capture"]["strace_reported_status"]["value"], 0);
    assert!(String::from_utf8_lossy(&trace).contains("alpha beta"));
    assert_eq!(
        run["trace"]["sha256"],
        format!("{:x}", Sha256::digest(&trace))
    );

    let reviewed = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("inspect")
        .arg("--format")
        .arg("text")
        .arg("--session")
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(reviewed.status.code(), Some(2));
    let review = String::from_utf8(reviewed.stdout).unwrap();
    assert!(review.contains("runtime"));
    assert!(review.contains("runtime_capture_completeness_unknown"));
    assert!(review.contains("no atomic system snapshot is claimed"));
}

#[test]
fn audit_cli_preserves_unavailable_runtime_source_alongside_other_sources() {
    let directory = TestDirectory::new();
    let output = directory.0.join("partial.session");
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&output)
        .arg("--processes")
        .arg("--runtime-duration-seconds")
        .arg("1")
        .arg("--")
        .arg("python3")
        .env("PATH", &directory.0)
        .output()
        .unwrap();

    assert_eq!(result.status.code(), Some(2));
    let manifest = parse_manifest(&fs::read(output.join("session.json")).unwrap()).unwrap();
    let processes = manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::Processes)
        .unwrap();
    assert!(matches!(
        processes.status,
        SourceStatus::Complete | SourceStatus::Partial
    ));
    assert_eq!(processes.artifacts.len(), 1);
    let runtime = manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::Runtime)
        .unwrap();
    assert_eq!(runtime.status, SourceStatus::Unavailable);
    assert!(runtime.artifacts.is_empty());
    assert!(
        runtime
            .diagnostic_codes
            .contains(&"runtime_capture_unavailable".to_owned())
    );
    assert!(!output.join("run.json").exists());
    assert!(!output.join("trace.strace").exists());
}

#[test]
fn audit_cli_time_limited_runtime_is_explicitly_incomplete() {
    let directory = TestDirectory::new();
    let output = directory.0.join("timed.session");
    let script = "import time; time.sleep(5)";
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&output)
        .arg("--runtime-duration-seconds")
        .arg("1")
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();

    assert_eq!(result.status.code(), Some(2));
    let manifest = parse_manifest(&fs::read(output.join("session.json")).unwrap()).unwrap();
    let runtime = manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::Runtime)
        .unwrap();
    assert_eq!(runtime.status, SourceStatus::Partial);
    assert!(
        runtime
            .diagnostic_codes
            .contains(&"runtime_time_limit_reached".to_owned())
    );
    let run: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("run.json")).unwrap()).unwrap();
    assert_eq!(run["capture"]["time_limit_milliseconds"], 1000);
    assert_eq!(run["capture"]["stop_reason"], "time_limit_reached");
    assert_eq!(run["capture"]["completeness"], "unknown");
}
