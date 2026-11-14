#![cfg(any(target_os = "linux", windows))]

use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let root = std::env::temp_dir();
        for _ in 0..32 {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!(
                "sideeffect-baseline-cli-{}-{id}",
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
                Err(error) => panic!("could not create test directory: {error}"),
            }
        }
        panic!("could not allocate unique temporary directory");
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn packages_artifact(version: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema":"sideeffect.inventory",
        "schema_version":2,
        "platform":"linux",
        "scope":"available_package_manager_databases",
        "captured_at_unix_ms":1001,
        "status":"complete",
        "sources":[{"id":"dpkg_query","status":"complete","exit_code":0,"records_seen":1,"diagnostics":[]}],
        "packages":[{
            "source_id":"dpkg_query",
            "name":"synthetic-baseline-demo",
            "version":version,
            "architecture":"amd64",
            "status_abbrev":"ii ",
            "evidence":{
                "line":1,
                "byte_offset":0,
                "byte_length":8,
                "record_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "raw_record":null,
                "raw_record_hex":null
            },
            "diagnostic_code":null
        }]
    }))
    .unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

fn complete_manifest(session_id: &str, version: &str) -> (Value, Vec<u8>) {
    let artifact = packages_artifact(version);
    let manifest = json!({
        "schema":"sideeffect.audit_session",
        "schema_version":15,
        "session_id":session_id,
        "platform":"linux",
        "architecture":"x86_64",
        "started_at_unix_ms":1000,
        "ended_at_unix_ms":2000,
        "interval_semantics":"best_effort_non_atomic",
        "status":"complete",
        "sources":[{
            "role":"packages",
            "collector":{"id":"linux.debian_packages","version":"synthetic-test-collector"},
            "platform":"linux",
            "scope":"synthetic baseline fixture packages",
            "started_at_unix_ms":1000,
            "ended_at_unix_ms":2000,
            "status":"complete",
            "applied_limits":[],
            "requested_settings":[],
            "effective_settings":[],
            "diagnostic_codes":[],
            "artifacts":[{
                "kind":"packages",
                "path":"packages.json",
                "schema":"sideeffect.inventory",
                "schema_version":2,
                "byte_length":artifact.len(),
                "sha256":sha256_hex(&artifact)
            }]
        }],
        "host_context":{
            "os_name":{"status":"observed","value":"synthetic-linux"},
            "os_version":{"status":"observed","value":"fixture-1"},
            "privilege":"not_elevated"
        },
        "coverage_manifest":{"version":1,"sources":[{"role":"packages","status":"observed"}]}
    });
    (manifest, artifact)
}

fn unknown_manifest(session_id: &str) -> Value {
    json!({
        "schema":"sideeffect.audit_session",
        "schema_version":15,
        "session_id":session_id,
        "platform":"linux",
        "architecture":"x86_64",
        "started_at_unix_ms":1000,
        "ended_at_unix_ms":2000,
        "interval_semantics":"best_effort_non_atomic",
        "status":"partial",
        "sources":[{
            "role":"packages",
            "collector":{"id":"linux.debian_packages","version":"synthetic-test-collector"},
            "platform":"linux",
            "scope":"synthetic baseline fixture packages",
            "started_at_unix_ms":1000,
            "ended_at_unix_ms":2000,
            "status":"unknown",
            "applied_limits":[],
            "requested_settings":[],
            "effective_settings":[],
            "diagnostic_codes":[],
            "artifacts":[]
        }],
        "host_context":{
            "os_name":{"status":"observed","value":"synthetic-linux"},
            "os_version":{"status":"observed","value":"fixture-1"},
            "privilege":"not_elevated"
        },
        "coverage_manifest":{"version":1,"sources":[{"role":"packages","status":"unknown"}]}
    })
}

fn write_session(
    parent: &Path,
    name: &str,
    manifest: &Value,
    artifacts: &[(&str, &[u8])],
) -> PathBuf {
    let directory = parent.join(name);
    let manifest_bytes = serde_json::to_vec(manifest).unwrap();
    let mut files: Vec<(&str, &[u8])> = vec![("session.json", manifest_bytes.as_slice())];
    files.extend(artifacts.iter().copied());
    #[cfg(windows)]
    {
        sideeffect::record::publish_private_windows_directory(
            &directory,
            &files,
            sideeffect::audit_session::MAX_SESSION_TOTAL_ARTIFACT_BYTES as usize,
        )
        .unwrap();
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        for (file_name, bytes) in &files {
            let path = directory.join(file_name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    directory
}

fn run(arguments: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(arguments)
        .output()
        .expect("run sideeffect baseline command")
}

fn preview(label: &str, sessions: &[&Path]) -> (Value, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
    command.args(["baseline", "preview", "--label", label]);
    for session in sessions {
        command.arg("--session").arg(session);
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    (value.clone(), value["sha256"].as_str().unwrap().to_owned())
}

#[test]
fn digest_bound_creation_refuses_wrong_digest_and_never_replaces_a_profile() {
    let temp = TestDirectory::new();
    let (manifest, artifact) = complete_manifest("11111111111111111111111111111111", "1.0");
    let session = write_session(
        &temp.0,
        "baseline-a",
        &manifest,
        &[("packages.json", &artifact)],
    );
    let (_, digest) = preview("synthetic reviewed baseline", &[&session]);
    let profile = temp.0.join("profile.json");

    let output = run(&[
        "baseline".as_ref(),
        "create".as_ref(),
        "--profile".as_ref(),
        profile.as_os_str(),
        "--label".as_ref(),
        "synthetic reviewed baseline".as_ref(),
        "--confirm-sha256".as_ref(),
        "0".repeat(64).as_ref(),
        "--session".as_ref(),
        session.as_os_str(),
    ]);
    assert!(!output.status.success());
    assert!(!profile.exists());

    let create = || {
        run(&[
            "baseline".as_ref(),
            "create".as_ref(),
            "--profile".as_ref(),
            profile.as_os_str(),
            "--label".as_ref(),
            "synthetic reviewed baseline".as_ref(),
            "--confirm-sha256".as_ref(),
            digest.as_ref(),
            "--session".as_ref(),
            session.as_os_str(),
        ])
    };
    let output = create();
    assert!(output.status.success(), "{output:?}");
    let profile_value: Value = serde_json::from_slice(&fs::read(&profile).unwrap()).unwrap();
    assert_eq!(profile_value["preview"]["sha256"], digest);
    assert_eq!(profile_value["automatic_absorption"], false);
    assert_eq!(profile_value["software_identity"], "not_recorded");
    assert_eq!(profile_value["signer_identity"], "not_recorded");

    let output = create();
    assert!(
        !output.status.success(),
        "existing profile must not be replaced"
    );
}

#[test]
fn comparison_reports_evidence_linked_drift_and_refuses_contaminated_baselines() {
    let temp = TestDirectory::new();
    let (manifest, artifact) = complete_manifest("22222222222222222222222222222222", "1.0");
    let baseline = write_session(
        &temp.0,
        "baseline",
        &manifest,
        &[("packages.json", &artifact)],
    );
    let (candidate_manifest, candidate_artifact) =
        complete_manifest("33333333333333333333333333333333", "2.0");
    let candidate = write_session(
        &temp.0,
        "candidate",
        &candidate_manifest,
        &[("packages.json", &candidate_artifact)],
    );
    let (_, digest) = preview("synthetic drift baseline", &[&baseline]);
    let profile = temp.0.join("profile.json");
    let output = run(&[
        "baseline".as_ref(),
        "create".as_ref(),
        "--profile".as_ref(),
        profile.as_os_str(),
        "--label".as_ref(),
        "synthetic drift baseline".as_ref(),
        "--confirm-sha256".as_ref(),
        digest.as_ref(),
        "--session".as_ref(),
        baseline.as_os_str(),
    ]);
    assert!(output.status.success(), "{output:?}");

    let output = run(&[
        "baseline".as_ref(),
        "compare".as_ref(),
        "--profile".as_ref(),
        profile.as_os_str(),
        "--baseline-session".as_ref(),
        baseline.as_os_str(),
        "--session".as_ref(),
        candidate.as_os_str(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "sideeffect.baseline_comparison");
    assert_eq!(report["baseline_verification"], "verified");
    assert_eq!(report["automatic_absorption"], false);
    assert_eq!(report["deviation"], "different_from_reviewed_observations");
    assert_eq!(report["removal_claims_withheld"], false);
    let pair = &report["comparisons"][0];
    assert_eq!(pair["diff"]["source_diffs"][0]["status"], "compared");
    assert_eq!(
        pair["diff"]["source_diffs"][0]["before_artifacts"][0]["path"],
        "packages.json"
    );
    assert_eq!(
        pair["diff"]["source_diffs"][0]["comparison"]["counts"]["changes"],
        1
    );

    let mut incompatible_manifest = candidate_manifest.clone();
    incompatible_manifest["host_context"]["os_version"]["value"] = json!("different-fixture");
    let incompatible = write_session(
        &temp.0,
        "incompatible-candidate",
        &incompatible_manifest,
        &[("packages.json", &candidate_artifact)],
    );
    let output = run(&[
        "baseline".as_ref(),
        "compare".as_ref(),
        "--profile".as_ref(),
        profile.as_os_str(),
        "--baseline-session".as_ref(),
        baseline.as_os_str(),
        "--session".as_ref(),
        incompatible.as_os_str(),
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["deviation"], "not_assessed");

    let (other_manifest, other_artifact) =
        complete_manifest("44444444444444444444444444444444", "1.0");
    let other = write_session(
        &temp.0,
        "other",
        &other_manifest,
        &[("packages.json", &other_artifact)],
    );
    let output = run(&[
        "baseline".as_ref(),
        "compare".as_ref(),
        "--profile".as_ref(),
        profile.as_os_str(),
        "--baseline-session".as_ref(),
        other.as_os_str(),
        "--session".as_ref(),
        candidate.as_os_str(),
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "refused_contaminated_baseline");
    assert_eq!(report["baseline_verification"], "contaminated");
    assert_eq!(report["comparisons"].as_array().unwrap().len(), 0);
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["code"] == "baseline_manifest_changed" && item["severity"] == "error"
            })
    );
}

#[test]
fn compare_rejects_an_oversized_profile_before_session_reads() {
    let temp = TestDirectory::new();
    let (manifest, artifact) = complete_manifest("77777777777777777777777777777777", "1.0");
    let session = write_session(
        &temp.0,
        "session",
        &manifest,
        &[("packages.json", &artifact)],
    );
    let profile = temp.0.join("oversized-profile.json");
    fs::write(
        &profile,
        vec![b' '; sideeffect::baseline::MAX_BASELINE_PROFILE_BYTES + 1],
    )
    .unwrap();

    let output = run(&[
        "baseline".as_ref(),
        "compare".as_ref(),
        "--profile".as_ref(),
        profile.as_os_str(),
        "--baseline-session".as_ref(),
        session.as_os_str(),
        "--session".as_ref(),
        session.as_os_str(),
    ]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("baseline profile input exceeds"));
}

#[test]
fn create_refuses_aggregate_artifact_budget_without_publishing_profile() {
    let temp = TestDirectory::new();
    let mut large_artifact = packages_artifact("1.0");
    large_artifact.resize(
        sideeffect::baseline::MAX_BASELINE_SESSION_READ_BYTES as usize,
        b' ',
    );
    let (mut large_manifest, _) = complete_manifest("abababababababababababababababab", "1.0");
    large_manifest["sources"][0]["artifacts"][0]["byte_length"] = json!(large_artifact.len());
    large_manifest["sources"][0]["artifacts"][0]["sha256"] = json!(sha256_hex(&large_artifact));
    let first = write_session(
        &temp.0,
        "large-session",
        &large_manifest,
        &[("packages.json", &large_artifact)],
    );
    let (second_manifest, second_artifact) =
        complete_manifest("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "1.0");
    let second = write_session(
        &temp.0,
        "second-session",
        &second_manifest,
        &[("packages.json", &second_artifact)],
    );
    let profile = temp.0.join("must-not-be-published.json");

    let output = run(&[
        "baseline".as_ref(),
        "create".as_ref(),
        "--profile".as_ref(),
        profile.as_os_str(),
        "--label".as_ref(),
        "synthetic budget fixture".as_ref(),
        "--confirm-sha256".as_ref(),
        "0000000000000000000000000000000000000000000000000000000000000000".as_ref(),
        "--session".as_ref(),
        first.as_os_str(),
        "--session".as_ref(),
        second.as_os_str(),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("aggregate baseline read budget"));
    assert!(!profile.exists());
}

#[test]
fn partial_baseline_input_cannot_be_promoted() {
    let temp = TestDirectory::new();
    let session = write_session(
        &temp.0,
        "partial-baseline",
        &unknown_manifest("88888888888888888888888888888888"),
        &[],
    );
    let (preview_value, digest) = preview("synthetic partial baseline", &[&session]);
    assert_eq!(preview_value["promotion"]["allowed"], false);
    assert_eq!(preview_value["coverage"][0]["status"], "unknown");
    let profile = temp.0.join("profile.json");
    let output = run(&[
        "baseline".as_ref(),
        "create".as_ref(),
        "--profile".as_ref(),
        profile.as_os_str(),
        "--label".as_ref(),
        "synthetic partial baseline".as_ref(),
        "--confirm-sha256".as_ref(),
        digest.as_ref(),
        "--session".as_ref(),
        session.as_os_str(),
    ]);
    assert!(!output.status.success());
    assert!(!profile.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be promoted"));
}

#[test]
fn unknown_coverage_is_preserved_and_removal_claims_are_withheld() {
    let temp = TestDirectory::new();
    let (baseline_manifest, baseline_artifact) =
        complete_manifest("55555555555555555555555555555555", "1.0");
    let baseline = write_session(
        &temp.0,
        "baseline",
        &baseline_manifest,
        &[("packages.json", &baseline_artifact)],
    );
    let candidate = write_session(
        &temp.0,
        "unknown-candidate",
        &unknown_manifest("66666666666666666666666666666666"),
        &[],
    );
    let (preview_value, digest) = preview("synthetic unknown candidate", &[&baseline]);
    assert_eq!(preview_value["promotion"]["allowed"], true);
    let profile = temp.0.join("profile.json");
    let output = run(&[
        "baseline".as_ref(),
        "create".as_ref(),
        "--profile".as_ref(),
        profile.as_os_str(),
        "--label".as_ref(),
        "synthetic unknown candidate".as_ref(),
        "--confirm-sha256".as_ref(),
        digest.as_ref(),
        "--session".as_ref(),
        baseline.as_os_str(),
    ]);
    assert!(output.status.success(), "{output:?}");

    let output = run(&[
        "baseline".as_ref(),
        "compare".as_ref(),
        "--profile".as_ref(),
        profile.as_os_str(),
        "--baseline-session".as_ref(),
        baseline.as_os_str(),
        "--session".as_ref(),
        candidate.as_os_str(),
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["removal_claims_withheld"], true);
    assert_eq!(report["coverage_gaps"][0]["status"], "unknown");
    assert_eq!(
        report["coverage_gaps"][0]["session_id"],
        "66666666666666666666666666666666"
    );
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| { item["code"] == "incomplete_coverage_removal_withheld" })
    );
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| { item["code"] == "automatic_absorption_refused" })
    );
}
