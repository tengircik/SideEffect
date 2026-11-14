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
        .arg("--path-executables")
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
            "path-executables.json",
            "permissions.json",
            "processes.json",
            "session.json",
            "startup.json"
        ]
    );

    let manifest_bytes = fs::read(output.join("session.json")).unwrap();
    let manifest = parse_manifest(&manifest_bytes).unwrap();
    assert_eq!(manifest.platform, "linux");
    assert_eq!(manifest.sources.len(), 5);
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
            SourceRole::PathExecutables,
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
            assert_eq!(review["schema_version"], 7);
            assert!(review["sources"][0]["collector"]["id"].is_string());
            assert_eq!(review["host_context"]["os_name"]["status"], "observed");
            assert!(review["host_context"]["privilege"].is_string());
            assert_eq!(review["authenticity"], "not_established");
            assert_eq!(review["sources"].as_array().unwrap().len(), 5);
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
fn audit_sessions_capture_and_compare_one_selected_root_with_verified_evidence() {
    let directory = TestDirectory::new();
    let selected_root = directory.0.join("selected-root");
    fs::create_dir(&selected_root).unwrap();
    fs::write(selected_root.join("before.txt"), b"fixture").unwrap();
    let before = directory.0.join("before.session");
    let first = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["audit", "--output"])
        .arg(&before)
        .arg("--root")
        .arg(&selected_root)
        .output()
        .unwrap();
    assert!(
        matches!(first.status.code(), Some(0 | 2)),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let before_manifest = parse_manifest(&fs::read(before.join("session.json")).unwrap()).unwrap();
    assert_eq!(before_manifest.schema_version, 9);
    let root_source = before_manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::SelectedRoot)
        .unwrap();
    assert_eq!(root_source.artifacts[0].path, "root-snapshot.json");
    let before_snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(before.join("root-snapshot.json")).unwrap()).unwrap();
    assert_eq!(before_snapshot["schema_version"], 1);
    assert!(before_snapshot["content_hashing"].is_null());
    assert_eq!(before_snapshot["entries"].as_array().unwrap().len(), 1);
    assert!(
        before_snapshot["root"]["display_path"]
            .as_str()
            .unwrap()
            .contains("selected-root")
    );
    let review = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("inspect")
        .arg("--format")
        .arg("json")
        .arg("--session")
        .arg(&before)
        .output()
        .unwrap();
    assert!(matches!(review.status.code(), Some(0 | 2)));
    let review: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    assert_eq!(review["schema"], "sideeffect.audit_session_review");
    assert_eq!(review["schema_version"], 7);
    assert!(
        review["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["role"] == "selected_root")
    );

    fs::write(selected_root.join("after.txt"), b"second fixture").unwrap();
    let after = directory.0.join("after.session");
    let second = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["audit", "--output"])
        .arg(&after)
        .arg("--root")
        .arg(&selected_root)
        .output()
        .unwrap();
    assert!(
        matches!(second.status.code(), Some(0 | 2)),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );

    let comparison = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-sessions")
        .arg(&before)
        .arg(&after)
        .output()
        .unwrap();
    assert!(
        comparison.status.success(),
        "{}",
        String::from_utf8_lossy(&comparison.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&comparison.stdout).unwrap();
    assert_eq!(
        report["scope"],
        "metadata_and_item_level_inventory_runtime_and_selected_root_metadata"
    );
    let root_diff = report["source_diffs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["role"] == "selected_root")
        .unwrap();
    let after_snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(after.join("root-snapshot.json")).unwrap()).unwrap();
    let after_ordinal = after_snapshot["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["display_name"] == "after.txt")
        .unwrap()["ordinal"]
        .as_u64()
        .unwrap();
    assert_eq!(root_diff["status"], "compared");
    assert_eq!(root_diff["comparison"]["counts"]["additions"], 1);
    assert_eq!(
        root_diff["comparison"]["deltas"][0]["after"]["entry_ordinal"],
        after_ordinal
    );

    let duplicate = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["audit", "--output"])
        .arg(directory.0.join("duplicate.session"))
        .arg("--root")
        .arg(&selected_root)
        .arg("--root")
        .arg(&selected_root)
        .output()
        .unwrap();
    assert_eq!(duplicate.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("exactly one --root"));
}

#[test]
fn audit_sessions_opt_in_to_root_hashes_and_compare_content_with_verified_evidence() {
    let directory = TestDirectory::new();
    let selected_root = directory.0.join("selected-root-hashes");
    fs::create_dir(&selected_root).unwrap();
    let file = selected_root.join("payload.bin");
    fs::write(&file, b"before").unwrap();
    let before = directory.0.join("before-hashed.session");
    let first = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["audit", "--output"])
        .arg(&before)
        .arg("--root")
        .arg(&selected_root)
        .arg("--hash-regular-files")
        .output()
        .unwrap();
    assert!(
        matches!(first.status.code(), Some(0 | 2)),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let before_manifest = parse_manifest(&fs::read(before.join("session.json")).unwrap()).unwrap();
    assert_eq!(before_manifest.schema_version, 9);
    let before_root = before_manifest
        .sources
        .iter()
        .find(|s| s.role == SourceRole::SelectedRoot)
        .unwrap();
    assert_eq!(before_root.requested_settings[0].code, "hash_regular_files");
    let before_snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(before.join("root-snapshot.json")).unwrap()).unwrap();
    assert_eq!(before_snapshot["schema_version"], 2);
    assert!(
        before_snapshot["entries"][0]["content_sha256"]
            .as_str()
            .is_some()
    );

    fs::write(&file, b"after!").unwrap();
    let after = directory.0.join("after-hashed.session");
    let second = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["audit", "--output"])
        .arg(&after)
        .arg("--root")
        .arg(&selected_root)
        .arg("--hash-regular-files")
        .output()
        .unwrap();
    assert!(
        matches!(second.status.code(), Some(0 | 2)),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let comparison = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-sessions")
        .arg(&before)
        .arg(&after)
        .output()
        .unwrap();
    assert!(
        comparison.status.success(),
        "{}",
        String::from_utf8_lossy(&comparison.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&comparison.stdout).unwrap();
    let root_diff = report["source_diffs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["role"] == "selected_root")
        .unwrap();
    assert_eq!(root_diff["status"], "compared");
    assert_eq!(root_diff["comparison"]["counts"]["changes"], 1);
    assert!(
        root_diff["comparison"]["deltas"][0]["changed_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "content_sha256")
    );
    assert_eq!(
        root_diff["comparison"]["deltas"][0]["before"]["entry_ordinal"],
        0
    );
    assert_eq!(
        root_diff["comparison"]["deltas"][0]["after"]["evidence_source"],
        "selected_root_directory_entry"
    );

    let default_session = directory.0.join("default.session");
    let metadata_only = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["audit", "--output"])
        .arg(&default_session)
        .arg("--root")
        .arg(&selected_root)
        .output()
        .unwrap();
    assert!(matches!(metadata_only.status.code(), Some(0 | 2)));
    let default_manifest =
        parse_manifest(&fs::read(default_session.join("session.json")).unwrap()).unwrap();
    let default_ref = &default_manifest
        .sources
        .iter()
        .find(|s| s.role == SourceRole::SelectedRoot)
        .unwrap()
        .artifacts[0];
    assert_eq!(default_ref.schema_version, 1);

    let legacy_v7_session = directory.0.join("legacy-v7.session");
    fs::create_dir(&legacy_v7_session).unwrap();
    fs::set_permissions(&legacy_v7_session, fs::Permissions::from_mode(0o700)).unwrap();
    fs::copy(
        default_session.join("root-snapshot.json"),
        legacy_v7_session.join("root-snapshot.json"),
    )
    .unwrap();
    let mut legacy_manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(default_session.join("session.json")).unwrap()).unwrap();
    legacy_manifest["schema_version"] = serde_json::json!(7);
    let selected_root_source = legacy_manifest["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["role"] == "selected_root")
        .unwrap();
    selected_root_source["scope"] =
        serde_json::json!("one explicitly selected directory and direct-child metadata only");
    let legacy_manifest_path = legacy_v7_session.join("session.json");
    fs::write(
        &legacy_manifest_path,
        serde_json::to_vec(&legacy_manifest).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&legacy_manifest_path, fs::Permissions::from_mode(0o600)).unwrap();

    let v7_v8_metadata = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-sessions")
        .arg(&legacy_v7_session)
        .arg(&default_session)
        .output()
        .unwrap();
    assert!(
        matches!(v7_v8_metadata.status.code(), Some(0 | 2)),
        "{}",
        String::from_utf8_lossy(&v7_v8_metadata.stderr)
    );
    let v7_v8_metadata: serde_json::Value = serde_json::from_slice(&v7_v8_metadata.stdout).unwrap();
    assert_eq!(v7_v8_metadata["comparable"], true);
    let legacy_root_diff = v7_v8_metadata["source_diffs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["role"] == "selected_root")
        .unwrap();
    assert_eq!(legacy_root_diff["status"], "compared");

    let v7_hashed = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-sessions")
        .arg(&legacy_v7_session)
        .arg(&after)
        .output()
        .unwrap();
    assert!(
        matches!(v7_hashed.status.code(), Some(0 | 2)),
        "{}",
        String::from_utf8_lossy(&v7_hashed.stderr)
    );
    let v7_hashed: serde_json::Value = serde_json::from_slice(&v7_hashed.stdout).unwrap();
    let legacy_hashed_root = v7_hashed["source_diffs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["role"] == "selected_root")
        .unwrap();
    assert_eq!(legacy_hashed_root["status"], "partial");
    assert_eq!(
        legacy_hashed_root["comparison"]["deltas"][0]["unknown_fields"][0],
        "content_sha256"
    );

    let mixed = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-sessions")
        .arg(&default_session)
        .arg(&after)
        .output()
        .unwrap();
    assert!(
        matches!(mixed.status.code(), Some(0 | 2)),
        "{}",
        String::from_utf8_lossy(&mixed.stderr)
    );
    let mixed_report: serde_json::Value = serde_json::from_slice(&mixed.stdout).unwrap();
    let mixed_root = mixed_report["source_diffs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["role"] == "selected_root")
        .unwrap();
    assert_eq!(mixed_root["status"], "partial");
    assert_eq!(
        mixed_root["comparison"]["deltas"][0]["unknown_fields"][0],
        "content_sha256"
    );
}

#[test]
fn root_snapshot_does_not_capture_its_session_staging_or_final_directory() {
    let directory = TestDirectory::new();
    let selected_root = directory.0.join("selected-root");
    fs::create_dir(&selected_root).unwrap();
    fs::write(selected_root.join("input.txt"), b"synthetic fixture").unwrap();
    let output_path = selected_root.join("audit-session");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["audit", "--output"])
        .arg(&output_path)
        .arg("--root")
        .arg(&selected_root)
        .output()
        .unwrap();
    assert!(
        matches!(output.status.code(), Some(0 | 2)),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(output_path.join("root-snapshot.json")).unwrap()).unwrap();
    let names = snapshot["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["display_name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(names, ["input.txt"]);
    assert!(
        !names
            .iter()
            .any(|name| name.starts_with(".sideeffect-capture-"))
    );
    assert!(!names.contains(&"audit-session"));
}

#[test]
fn partial_path_source_forces_partial_session_and_has_fixed_provenance() {
    let directory = TestDirectory::new();
    let output = directory.0.join("path.session");
    let duplicate = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&output)
        .arg("--path-executables")
        .arg("--path-executables")
        .output()
        .unwrap();
    assert_eq!(duplicate.status.code(), Some(1));
    assert!(!output.exists());
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&output)
        .arg("--path-executables")
        .env_remove("PATH")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    let manifest = parse_manifest(&fs::read(output.join("session.json")).unwrap()).unwrap();
    assert_eq!(
        manifest.status,
        sideeffect::audit_session::SessionStatus::Partial
    );
    let source = manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::PathExecutables)
        .unwrap();
    assert_eq!(source.status, SourceStatus::Partial);
    assert_eq!(
        manifest
            .coverage_manifest
            .as_ref()
            .unwrap()
            .sources
            .iter()
            .find(|source| source.role == SourceRole::PathExecutables)
            .unwrap()
            .status,
        sideeffect::audit_session::CoverageStatus::Partial
    );
    assert_eq!(source.artifacts[0].path, "path-executables.json");
    assert_eq!(
        source.artifacts[0].schema,
        "sideeffect.path_executable_inventory"
    );
    assert_eq!(source.artifacts[0].schema_version, 1);
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
fn audit_observe_root_wraps_real_strace_and_compares_verified_snapshots() {
    let directory = TestDirectory::new();
    let observed_root = directory.0.join("observed");
    fs::create_dir(&observed_root).unwrap();
    let output = directory.0.join("observation.session");
    let created_file = observed_root.join("created-by-selected-command.txt");
    let transient_file = observed_root.join("transient-by-selected-command.txt");
    let script = "from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('fixture')\ntransient = Path(sys.argv[2])\ntransient.write_text('transient fixture')\ntransient.unlink()";
    let captured = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&output)
        .arg("--observe-root")
        .arg(&observed_root)
        .arg("--runtime-duration-seconds")
        .arg("10")
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(script)
        .arg(&created_file)
        .arg(&transient_file)
        .output()
        .unwrap();
    assert_eq!(
        captured.status.code(),
        Some(2),
        "runtime capture is partial by contract: {}",
        String::from_utf8_lossy(&captured.stderr)
    );
    assert!(created_file.exists());
    assert!(
        !transient_file.exists(),
        "the selected fixture command must remove its transient file"
    );
    let manifest = parse_manifest(&fs::read(output.join("session.json")).unwrap()).unwrap();
    assert_eq!(
        manifest.schema_version,
        sideeffect::audit_session::AUDIT_SESSION_V16_SCHEMA_VERSION
    );
    let root_source = manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::SelectedRoot)
        .unwrap();
    assert_eq!(root_source.artifacts.len(), 2);
    assert!(root_source.started_at_unix_ms < root_source.ended_at_unix_ms);
    let runtime = manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::Runtime)
        .unwrap();
    assert_eq!(runtime.status, SourceStatus::Partial);
    assert_eq!(runtime.artifacts.len(), 2);

    let compared = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-observation")
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(compared.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&compared.stdout).unwrap();
    assert_eq!(report["root_comparison_status"], "complete");
    assert_eq!(report["root_diff"]["counts"]["additions"], 1);
    let deltas = report["root_diff"]["deltas"].as_array().unwrap();
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0]["name"], "created-by-selected-command.txt");
    let transient_name = transient_file.file_name().unwrap().to_str().unwrap();
    assert!(
        deltas.iter().all(|delta| delta["name"] != transient_name),
        "a file created and removed inside the observation window must not appear in the before/after diff"
    );
    assert_eq!(report["runtime_artifacts"].as_array().unwrap().len(), 2);
    assert_eq!(report["runtime_source_status"], "partial");
    assert_eq!(report["runtime_capture_completeness"], "unknown");
    assert_eq!(
        report["root_runtime_association"]["claim"],
        "lexical_path_candidate_only_no_causation_or_process_identity"
    );
    assert_eq!(report["root_runtime_association"]["status"], "partial");
    assert_eq!(
        report["root_runtime_association"]["parse_comparison_status"],
        "complete"
    );
    assert_eq!(
        report["root_runtime_association"]["capture_completeness"],
        "unknown"
    );
    let associations = report["root_runtime_association"]["associations"]
        .as_array()
        .unwrap();
    assert_eq!(associations.len(), 1);
    assert_eq!(
        associations[0]["candidate_path"],
        created_file.to_string_lossy().as_ref()
    );
    assert_eq!(
        associations[0]["runtime_evidence"][0]["trace_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );

    // The trace remains the raw runtime evidence for the transient lifecycle.
    // Its openat path hint is source-derived, while the unlink success is read
    // from the observed syscall result rather than inferred from the absent file.
    let trace_path = output.join("trace.strace");
    let trace = String::from_utf8(fs::read(&trace_path).unwrap()).unwrap();
    let transient_trace_lines = trace
        .lines()
        .filter(|line| line.contains(transient_name))
        .collect::<Vec<_>>();
    assert!(
        !transient_trace_lines.is_empty(),
        "runtime trace must retain rows for the transient fixture file: {trace}"
    );
    assert!(
        transient_trace_lines.iter().any(|line| {
            let line = line.trim_end();
            (line.contains("unlink(") || line.contains("unlinkat("))
                && line
                    .rsplit_once(" = ")
                    .is_some_and(|(_, result)| result == "0")
        }),
        "runtime trace must retain the observed successful removal syscall: {transient_trace_lines:?}"
    );
    let events = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["events", "--trace"])
        .arg(&trace_path)
        .output()
        .unwrap();
    assert!(
        events.status.success(),
        "{}",
        String::from_utf8_lossy(&events.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&events.stdout).unwrap();
    assert!(
        envelope["events"].as_array().unwrap().iter().any(|event| {
            matches!(event["event_kind"].as_str(), Some("openat" | "openat2"))
                && event["path_observation"]["path"]
                    .as_str()
                    .is_some_and(|path| path.ends_with(transient_name))
                && event["operation"]["source_kind"] == "syscall_attempt"
                && event["operation"]["result"] == "success"
        }),
        "runtime evidence must retain the observed successful open of the transient file"
    );
}

#[test]
fn audit_observe_root_rename_race_yields_partial_unknown_comparison() {
    let directory = TestDirectory::new();
    let observed_root = directory.0.join("rename-during-capture");
    fs::create_dir(&observed_root).unwrap();
    fs::write(observed_root.join("present-before.txt"), "fixture").unwrap();
    let moved_root = directory.0.join("renamed-root");
    let output = directory.0.join("rename-race.session");
    let script = "from pathlib import Path\nimport os, sys\nos.rename(sys.argv[1], sys.argv[2])";
    let captured = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&output)
        .arg("--observe-root")
        .arg(&observed_root)
        .arg("--runtime-duration-seconds")
        .arg("10")
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(script)
        .arg(&observed_root)
        .arg(&moved_root)
        .output()
        .unwrap();
    assert_eq!(
        captured.status.code(),
        Some(2),
        "runtime capture is partial by contract: {}",
        String::from_utf8_lossy(&captured.stderr)
    );
    assert!(moved_root.join("present-before.txt").exists());
    assert!(!observed_root.exists());

    let manifest = parse_manifest(&fs::read(output.join("session.json")).unwrap()).unwrap();
    assert_eq!(manifest.platform, "linux");
    let root_source = manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::SelectedRoot)
        .unwrap();
    assert_eq!(root_source.status, SourceStatus::Partial);
    let after_snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("root-snapshot-after.json")).unwrap())
            .unwrap();
    assert!(after_snapshot["root"].is_null());
    assert_eq!(after_snapshot["entries"].as_array().unwrap().len(), 0);
    assert_eq!(after_snapshot["status"], "partial");

    let compared = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-observation")
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(compared.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&compared.stdout).unwrap();
    assert_eq!(report["status"], "partial");
    assert_eq!(report["root_comparison_status"], "partial");
    assert_eq!(
        report["root_comparison_diagnostic"],
        "selected_root_unavailable"
    );
    assert!(report["root_diff"].is_null());
    for artifact in ["before_artifact", "after_artifact"] {
        assert_eq!(report[artifact]["sha256"].as_str().unwrap().len(), 64);
    }
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
