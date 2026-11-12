use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let root = std::env::temp_dir();
        for _ in 0..32 {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!(
                "sideeffect-provenance-cli-{}-{id}",
                std::process::id()
            ));
            #[cfg(windows)]
            let created = sideeffect::record::publish_private_windows_directory(
                &path,
                &[("test-root", b"x")],
                128,
            )
            .map(|_| ());
            #[cfg(not(windows))]
            let created = fs::create_dir(&path);
            match created {
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
        panic!("could not allocate unique temporary directory")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn generate_pair(directory: &std::path::Path, name: &str) -> (PathBuf, PathBuf) {
    let private = directory.join(format!("{name}.pk8"));
    let public = directory.join(format!("{name}.hex"));
    sideeffect::provenance::generate_keypair(&private, &public).unwrap();
    (private, public)
}

fn key_check(private: &std::path::Path, public: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("key-check")
        .arg(private)
        .arg(public)
        .output()
        .unwrap()
}

fn output_contains_bytes(output: &Output, needle: &[u8]) -> bool {
    !needle.is_empty()
        && [output.stdout.as_slice(), output.stderr.as_slice()]
            .into_iter()
            .any(|stream| stream.windows(needle.len()).any(|window| window == needle))
}

const PACKAGES_ARTIFACT: &[u8] = br#"{"schema":"sideeffect.inventory","schema_version":2}"#;
const SCOPE_MARKER: &str = "synthetic-scope-marker-value";
const COLLECTOR_VERSION_MARKER: &str = "synthetic-collector-build-marker";
const DIAGNOSTIC_MARKER: &str = "synthetic_diagnostic_marker";
const HOST_NAME_MARKER: &str = "synthetic-host-name-marker";
const HOST_VERSION_MARKER: &str = "synthetic-host-version-marker";

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// Write a synthetic, private session directory. This is a test fixture, not a
/// real capture; it exercises the same reader contract used by the CLI.
fn write_private_session_directory(
    parent: &std::path::Path,
    name: &str,
    manifest: &serde_json::Value,
    artifacts: &[(&str, &[u8])],
) -> PathBuf {
    let directory = parent.join(name);
    let manifest_bytes = serde_json::to_vec(manifest).unwrap();
    let mut files: Vec<(&str, &[u8])> = vec![("session.json", manifest_bytes.as_slice())];
    files.extend(artifacts.iter().copied());
    #[cfg(windows)]
    {
        sideeffect::record::publish_private_windows_directory(&directory, &files, 1024 * 1024)
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

fn current_fixture_manifest() -> serde_json::Value {
    serde_json::json!({
        "schema": "sideeffect.audit_session",
        "schema_version": 15,
        "session_id": "0123456789abcdef0123456789abcdef",
        "platform": "linux",
        "architecture": "x86_64",
        "started_at_unix_ms": 1000,
        "ended_at_unix_ms": 2000,
        "interval_semantics": "best_effort_non_atomic",
        "status": "complete",
        "sources": [{
            "role": "packages",
            "collector": {
                "id": "linux.debian_packages",
                "version": COLLECTOR_VERSION_MARKER
            },
            "platform": "linux",
            "scope": SCOPE_MARKER,
            "started_at_unix_ms": 1000,
            "ended_at_unix_ms": 2000,
            "status": "complete",
            "applied_limits": [{"code": "max_files", "value": 10}],
            "requested_settings": [{"code": "include_paths", "value": 1}],
            "effective_settings": [{"code": "include_paths", "value": 1}],
            "diagnostic_codes": [DIAGNOSTIC_MARKER],
            "artifacts": [{
                "kind": "packages",
                "path": "packages.json",
                "schema": "sideeffect.inventory",
                "schema_version": 2,
                "byte_length": PACKAGES_ARTIFACT.len(),
                "sha256": sha256_hex(PACKAGES_ARTIFACT)
            }]
        }],
        "host_context": {
            "os_name": {"status": "observed", "value": HOST_NAME_MARKER},
            "os_version": {"status": "observed", "value": HOST_VERSION_MARKER},
            "privilege": "not_elevated"
        },
        "coverage_manifest": {
            "version": 2,
            "sources": [{"role": "packages", "status": "observed"}]
        }
    })
}

fn minimal_fixture_manifest() -> serde_json::Value {
    serde_json::json!({
        "schema": "sideeffect.audit_session",
        "schema_version": 3,
        "session_id": "fedcba9876543210fedcba9876543210",
        "platform": "linux",
        "architecture": "x86_64",
        "started_at_unix_ms": 3000,
        "ended_at_unix_ms": 4000,
        "interval_semantics": "best_effort_non_atomic",
        "status": "partial",
        "sources": [{
            "role": "startup",
            "platform": "linux",
            "scope": "minimal-synthetic-scope-marker",
            "started_at_unix_ms": 3000,
            "ended_at_unix_ms": 4000,
            "status": "unknown",
            "applied_limits": [],
            "diagnostic_codes": [],
            "artifacts": []
        }],
        "coverage_manifest": {
            "version": 1,
            "sources": [{"role": "startup", "status": "unknown"}]
        }
    })
}

fn preview_session(session: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["provenance", "preview-session"])
        .arg(session)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn sorted_keys(value: &serde_json::Value) -> Vec<&str> {
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("JSON object expected")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

#[test]
fn provenance_exports_only_the_public_key_and_never_replaces_a_file() {
    let temp = TestDirectory::new();
    let (private, public) = generate_pair(&temp.0, "original");
    let expected = fs::read(&public).unwrap();
    let original_private = fs::read(&private).unwrap();
    fs::remove_file(public).unwrap();
    let destination = temp.0.join("recovered.hex");
    let export = |destination: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .args(["provenance", "key-export-public"])
            .arg(&private)
            .arg(destination)
            .output()
            .unwrap()
    };
    let output = export(&destination);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected_fingerprint = sideeffect::provenance::public_key_id(&expected).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        expected_fingerprint
    );
    assert!(output.stderr.is_empty());
    assert_eq!(fs::read(&destination).unwrap(), expected);
    assert!(key_check(&private, &destination).status.success());

    fs::write(&destination, b"preserve existing output").unwrap();
    for path in [&destination, &private] {
        let output = export(path);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    assert_eq!(fs::read(&destination).unwrap(), b"preserve existing output");
    assert_eq!(fs::read(&private).unwrap(), original_private);
}

#[test]
fn provenance_key_check_cli_is_read_only_and_does_not_disclose_private_material() {
    let temp = TestDirectory::new();
    let (private, public) = generate_pair(&temp.0, "current");
    let (other_private, other_public) = generate_pair(&temp.0, "other");
    let original_private = fs::read(&private).unwrap();
    let original_public = fs::read(&public).unwrap();
    let trust_store = temp.0.join("explicit-trust-store");
    sideeffect::provenance::import_trusted_key_text(
        &trust_store,
        &original_public,
        "key check fixture",
    )
    .unwrap();
    let original_trusted_keys = sideeffect::provenance::list_trusted_keys(&trust_store).unwrap();
    let expected_fingerprint = sideeffect::provenance::public_key_id(&original_public).unwrap();

    let matched = key_check(&private, &public);
    assert!(
        matched.status.success(),
        "{}",
        String::from_utf8_lossy(&matched.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&matched.stdout).trim(),
        expected_fingerprint
    );
    assert!(matched.stderr.is_empty());
    assert!(!output_contains_bytes(&matched, &original_private));

    let help = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["help", "provenance", "key-check"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(
        String::from_utf8_lossy(&help.stdout)
            .contains("Usage: sideeffect provenance key-check PRIVATE_KEY.pk8 PUBLIC_KEY.hex")
    );
    assert!(String::from_utf8_lossy(&help.stdout).contains("pair consistency only"));

    let mismatch = key_check(&private, &other_public);
    assert_eq!(mismatch.status.code(), Some(1));
    assert!(mismatch.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&mismatch.stderr)
            .contains("private and public key do not form a pair")
    );
    assert!(!output_contains_bytes(&mismatch, &original_private));
    assert!(!output_contains_bytes(
        &mismatch,
        &fs::read(&other_private).unwrap()
    ));
    assert_eq!(fs::read(&private).unwrap(), original_private);
    assert_eq!(fs::read(&public).unwrap(), original_public);
    assert_eq!(
        sideeffect::provenance::list_trusted_keys(&trust_store).unwrap(),
        original_trusted_keys
    );

    let malformed_secret = b"PRIVATE_SECRET_MARKER_DO_NOT_ECHO";
    fs::write(&private, malformed_secret).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let malformed_bytes = fs::read(&private).unwrap();
    let malformed = key_check(&private, &public);
    assert_eq!(malformed.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&malformed.stderr)
            .contains("signing key is malformed or unsupported")
    );
    assert!(!output_contains_bytes(&malformed, malformed_secret));
    assert_eq!(fs::read(&private).unwrap(), malformed_bytes);
    fs::write(&private, &original_private).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o644)).unwrap();
        let insecure = key_check(&private, &public);
        assert_eq!(insecure.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&insecure.stderr).contains(
            "private key must be owned by the current user with no group or other access"
        ));
        assert!(!output_contains_bytes(&insecure, &original_private));
        fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let invalid_path = temp.0.join("not-a-key-file");
    fs::create_dir(&invalid_path).unwrap();
    let invalid_path_result = key_check(&invalid_path, &public);
    assert_eq!(invalid_path_result.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&invalid_path_result.stderr)
            .contains("private key must be a regular file, not a link or special file")
    );
    assert!(
        !String::from_utf8_lossy(&invalid_path_result.stderr)
            .contains(invalid_path.file_name().unwrap().to_string_lossy().as_ref())
    );

    assert_eq!(fs::read(&private).unwrap(), original_private);
    assert_eq!(fs::read(&public).unwrap(), original_public);
    assert_eq!(
        sideeffect::provenance::list_trusted_keys(&trust_store).unwrap(),
        original_trusted_keys
    );
}

#[test]
fn provenance_trust_rotation_requires_both_fingerprints_and_preserves_old_until_confirmed() {
    let temp = TestDirectory::new();
    let (old_private, old_public) = generate_pair(&temp.0, "rotation-old");
    let (new_private, new_public) = generate_pair(&temp.0, "rotation-new");
    let old_private_bytes = fs::read(&old_private).unwrap();
    let new_private_bytes = fs::read(&new_private).unwrap();
    let old_public_bytes = fs::read(&old_public).unwrap();
    let new_public_bytes = fs::read(&new_public).unwrap();
    let old_id = sideeffect::provenance::public_key_id(&old_public_bytes).unwrap();
    let new_id = sideeffect::provenance::public_key_id(&new_public_bytes).unwrap();
    let trust_store = temp.0.join("rotation-trust-store");
    sideeffect::provenance::import_trusted_key_text(
        &trust_store,
        &old_public_bytes,
        "prior signing key",
    )
    .unwrap();

    let invoke = |confirmation: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
        command
            .arg("provenance")
            .arg("trust")
            .arg("rotate")
            .arg(&old_id)
            .arg(&new_public)
            .arg("--trust-store")
            .arg(&trust_store)
            .arg("--label")
            .arg("replacement signing key")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(confirmation.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };

    let cancelled = invoke("no, keep the old key\n");
    assert_eq!(cancelled.status.code(), Some(1));
    let cancelled_text = String::from_utf8_lossy(&cancelled.stdout);
    assert!(cancelled_text.contains(&old_id));
    assert!(cancelled_text.contains(&new_id));
    assert!(cancelled_text.contains("Rotation cancelled; the prior trust store is unchanged."));
    assert_eq!(
        sideeffect::provenance::list_trusted_keys(&trust_store).unwrap(),
        vec![sideeffect::provenance::TrustedKey {
            key_id: old_id.clone(),
            label: "prior signing key".to_owned(),
        }]
    );

    let completed = invoke(&format!("rotate {old_id} to {new_id}\n"));
    assert!(
        completed.status.success(),
        "{}",
        String::from_utf8_lossy(&completed.stderr)
    );
    assert!(String::from_utf8_lossy(&completed.stdout).contains("Rotation complete"));
    assert!(String::from_utf8_lossy(&completed.stdout).contains(&old_id));
    assert!(String::from_utf8_lossy(&completed.stdout).contains(&new_id));
    assert_eq!(
        sideeffect::provenance::list_trusted_keys(&trust_store).unwrap(),
        vec![sideeffect::provenance::TrustedKey {
            key_id: new_id,
            label: "replacement signing key".to_owned(),
        }]
    );
    assert_eq!(fs::read(&old_private).unwrap(), old_private_bytes);
    assert_eq!(fs::read(&new_private).unwrap(), new_private_bytes);
    assert_eq!(fs::read(&old_public).unwrap(), old_public_bytes);

    let help = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["help", "provenance"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains(
        "provenance trust rotate OLD_KEY_ID NEW_PUBLIC_KEY.hex --trust-store DIR --label LABEL"
    ));
}

#[test]
fn provenance_trust_rotation_rejects_existing_replacement_without_mutation() {
    let temp = TestDirectory::new();
    let (_old_private, old_public) = generate_pair(&temp.0, "rotation-old-duplicate");
    let (_new_private, new_public) = generate_pair(&temp.0, "rotation-new-duplicate");
    let old_public_bytes = fs::read(&old_public).unwrap();
    let new_public_bytes = fs::read(&new_public).unwrap();
    let old_id = sideeffect::provenance::public_key_id(&old_public_bytes).unwrap();
    let trust_store = temp.0.join("rotation-duplicate-store");
    sideeffect::provenance::import_trusted_key_text(&trust_store, &old_public_bytes, "old")
        .unwrap();
    sideeffect::provenance::import_trusted_key_text(
        &trust_store,
        &new_public_bytes,
        "already trusted",
    )
    .unwrap();
    let before = sideeffect::provenance::list_trusted_keys(&trust_store).unwrap();

    let rejected = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("trust")
        .arg("rotate")
        .arg(&old_id)
        .arg(&new_public)
        .arg("--trust-store")
        .arg(&trust_store)
        .arg("--label")
        .arg("replacement")
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("replacement key is already present")
    );
    assert_eq!(
        sideeffect::provenance::list_trusted_keys(&trust_store).unwrap(),
        before
    );
}

#[test]
fn session_signature_cli_round_trip_and_detects_manifest_byte_changes() {
    let temp = TestDirectory::new();
    let session = temp.0.join("session");
    let audit = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&session)
        .arg("--path-executables")
        .output()
        .unwrap();
    assert!(
        audit.status.success() || audit.status.code() == Some(2),
        "audit failed: {}",
        String::from_utf8_lossy(&audit.stderr)
    );

    let private = temp.0.join("signing-key.pk8");
    let public = temp.0.join("verification-key.hex");
    let keygen = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("keygen")
        .arg(&private)
        .arg(&public)
        .output()
        .unwrap();
    assert!(
        keygen.status.success(),
        "{}",
        String::from_utf8_lossy(&keygen.stderr)
    );

    let signature = temp.0.join("session.signature.json");
    let mut sign = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("sign-session")
        .arg(&session)
        .arg("--private-key")
        .arg(&private)
        .arg("--output")
        .arg(&signature)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    sign.stdin.take().unwrap().write_all(b"sign\n").unwrap();
    let signed = sign.wait_with_output().unwrap();
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );

    let verify = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("verify-session")
        .arg(&session)
        .arg("--signature")
        .arg(&signature)
        .arg("--public-key")
        .arg(&public)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("Cryptographic signature valid"));
    assert!(String::from_utf8_lossy(&verify.stdout).contains("Key trust was not evaluated"));

    let trust_store = temp.0.join("explicit-trust-store");
    let public_text = fs::read(&public).unwrap();
    let key_id = sideeffect::provenance::public_key_id(&public_text).unwrap();
    let mut rejected_import = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("trust")
        .arg("import")
        .arg(&public)
        .arg("--trust-store")
        .arg(&trust_store)
        .arg("--label")
        .arg("review team")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    rejected_import
        .stdin
        .take()
        .unwrap()
        .write_all(b"trust 0000000000000000000000000000000000000000000000000000000000000000\n")
        .unwrap();
    let rejected_import = rejected_import.wait_with_output().unwrap();
    assert_eq!(rejected_import.status.code(), Some(1));
    assert!(
        !trust_store.exists(),
        "cancelled import must not create a trust store"
    );

    let mut oversized_confirmation = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("trust")
        .arg("import")
        .arg(&public)
        .arg("--trust-store")
        .arg(&trust_store)
        .arg("--label")
        .arg("review team")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    oversized_confirmation
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{}\n", "x".repeat(129)).as_bytes())
        .unwrap();
    let oversized_confirmation = oversized_confirmation.wait_with_output().unwrap();
    assert_eq!(oversized_confirmation.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&oversized_confirmation.stderr).contains("exceeds its size limit")
    );
    assert!(
        !trust_store.exists(),
        "oversized confirmation must not create a trust store"
    );

    let mut import = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("trust")
        .arg("import")
        .arg(&public)
        .arg("--trust-store")
        .arg(&trust_store)
        .arg("--label")
        .arg("review team")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    import
        .stdin
        .take()
        .unwrap()
        .write_all(format!("trust {key_id}\n").as_bytes())
        .unwrap();
    let imported = import.wait_with_output().unwrap();
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );

    let listed = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("trust")
        .arg("list")
        .arg("--trust-store")
        .arg(&trust_store)
        .output()
        .unwrap();
    assert!(listed.status.success());
    assert!(String::from_utf8_lossy(&listed.stdout).contains("review team"));

    let trusted_verify = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("verify-session")
        .arg(&session)
        .arg("--signature")
        .arg(&signature)
        .arg("--trust-store")
        .arg(&trust_store)
        .output()
        .unwrap();
    assert!(trusted_verify.status.success());
    assert!(
        String::from_utf8_lossy(&trusted_verify.stdout).contains("Cryptographic signature valid")
    );
    assert!(
        String::from_utf8_lossy(&trusted_verify.stdout)
            .contains("Matched locally trusted key label 'review team'")
    );
    assert!(
        String::from_utf8_lossy(&trusted_verify.stdout).contains("not verified signer identity")
    );

    let mut remove = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("trust")
        .arg("remove")
        .arg(&key_id)
        .arg("--trust-store")
        .arg(&trust_store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    remove
        .stdin
        .take()
        .unwrap()
        .write_all(format!("remove {key_id}\n").as_bytes())
        .unwrap();
    let removed = remove.wait_with_output().unwrap();
    assert!(removed.status.success());

    let valid_untrusted = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("verify-session")
        .arg(&session)
        .arg("--signature")
        .arg(&signature)
        .arg("--public-key")
        .arg(&public)
        .arg("--trust-store")
        .arg(&trust_store)
        .output()
        .unwrap();
    assert_eq!(valid_untrusted.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&valid_untrusted.stdout).contains("Cryptographic signature valid")
    );
    assert!(
        String::from_utf8_lossy(&valid_untrusted.stdout)
            .contains("not trusted in the selected local trust store")
    );

    let unknown_key = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("verify-session")
        .arg(&session)
        .arg("--signature")
        .arg(&signature)
        .arg("--trust-store")
        .arg(&trust_store)
        .output()
        .unwrap();
    assert_eq!(unknown_key.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&unknown_key.stdout)
            .contains("Cryptographic signature validity was not evaluated")
    );

    let manifest_path = session.join("session.json");
    let mut manifest = fs::read(&manifest_path).unwrap();
    manifest.push(b' ');
    fs::write(&manifest_path, manifest).unwrap();
    let tampered = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("verify-session")
        .arg(&session)
        .arg("--signature")
        .arg(&signature)
        .arg("--public-key")
        .arg(&public)
        .output()
        .unwrap();
    assert_eq!(tampered.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("signature verification failed"));
}

#[test]
fn provenance_commands_reject_malformed_and_unknown_session_manifests() {
    let temp = TestDirectory::new();
    let session = temp.0.join("session");
    let audit = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&session)
        .arg("--path-executables")
        .output()
        .unwrap();
    assert!(
        audit.status.success() || audit.status.code() == Some(2),
        "audit failed: {}",
        String::from_utf8_lossy(&audit.stderr)
    );

    let manifest_path = session.join("session.json");
    let original = fs::read(&manifest_path).unwrap();
    let signature = temp.0.join("signature.json");
    let public = temp.0.join("public.hex");

    fs::write(&manifest_path, b"{").unwrap();
    let malformed_sign = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("sign-session")
        .arg(&session)
        .arg("--private-key")
        .arg(temp.0.join("missing.pk8"))
        .arg("--output")
        .arg(&signature)
        .output()
        .unwrap();
    assert_eq!(malformed_sign.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&malformed_sign.stderr).contains("invalid audit-session manifest")
    );

    fs::write(&manifest_path, &original).unwrap();
    let mut unknown: serde_json::Value = serde_json::from_slice(&original).unwrap();
    unknown["unexpected_manifest_field"] = serde_json::json!(true);
    fs::write(&manifest_path, serde_json::to_vec(&unknown).unwrap()).unwrap();
    let unknown_verify = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("verify-session")
        .arg(&session)
        .arg("--signature")
        .arg(&signature)
        .arg("--public-key")
        .arg(&public)
        .output()
        .unwrap();
    assert_eq!(unknown_verify.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&unknown_verify.stderr).contains("invalid audit-session manifest")
    );

    let mut unsupported: serde_json::Value = serde_json::from_slice(&original).unwrap();
    unsupported["schema_version"] = serde_json::json!(999);
    fs::write(&manifest_path, serde_json::to_vec(&unsupported).unwrap()).unwrap();
    let unsupported_verify = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("provenance")
        .arg("verify-session")
        .arg(&session)
        .arg("--signature")
        .arg(&signature)
        .arg("--public-key")
        .arg(&public)
        .output()
        .unwrap();
    assert_eq!(unsupported_verify.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&unsupported_verify.stderr)
            .contains("invalid audit-session manifest")
    );
}

#[test]
fn provenance_preview_session_reports_digest_and_fixed_categories_without_prompting() {
    let temp = TestDirectory::new();
    let session = write_private_session_directory(
        &temp.0,
        "synthetic-complete-session",
        &current_fixture_manifest(),
        &[("packages.json", PACKAGES_ARTIFACT)],
    );

    // `output()` connects stdin to null: a command that prompted for a signing
    // confirmation would read EOF, cancel, and exit unsuccessfully.
    let preview = preview_session(&session);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    assert!(preview.stderr.is_empty());

    let text = String::from_utf8(preview.stdout).unwrap();
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        sorted_keys(&document),
        vec![
            "binds",
            "manifest_schema",
            "manifest_schema_version",
            "manifest_sha256",
            "schema",
            "schema_version",
            "signed_input",
        ]
    );
    assert_eq!(document["schema"], "sideeffect.provenance_signing_preview");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["manifest_schema"], "sideeffect.audit_session");
    assert_eq!(document["manifest_schema_version"], 15);
    assert_eq!(document["signed_input"], "exact_session_json_bytes");
    assert_eq!(
        document["manifest_sha256"],
        sha256_hex(&fs::read(session.join("session.json")).unwrap())
    );

    let binds = &document["binds"];
    assert_eq!(
        sorted_keys(binds),
        vec![
            "applied_limits_present",
            "artifact_count",
            "artifact_hashes_present",
            "collector_identity_present",
            "collector_provider_identity_present",
            "coverage_manifest_present",
            "diagnostics_present",
            "effective_settings_present",
            "exact_manifest_bytes",
            "host_context_present",
            "observed_os_metadata_present",
            "requested_settings_present",
            "runtime_loss_metadata_present",
            "session_identifier_present",
            "source_count",
        ]
    );
    for (field, expected) in [
        ("exact_manifest_bytes", serde_json::json!(true)),
        ("session_identifier_present", serde_json::json!(true)),
        ("host_context_present", serde_json::json!(true)),
        ("observed_os_metadata_present", serde_json::json!(true)),
        ("coverage_manifest_present", serde_json::json!(true)),
        ("collector_identity_present", serde_json::json!(true)),
        (
            "collector_provider_identity_present",
            serde_json::json!(false),
        ),
        ("requested_settings_present", serde_json::json!(true)),
        ("effective_settings_present", serde_json::json!(true)),
        ("applied_limits_present", serde_json::json!(true)),
        ("runtime_loss_metadata_present", serde_json::json!(false)),
        ("diagnostics_present", serde_json::json!(true)),
        ("artifact_hashes_present", serde_json::json!(true)),
        ("source_count", serde_json::json!(1)),
        ("artifact_count", serde_json::json!(1)),
    ] {
        assert_eq!(binds[field], expected, "unexpected value for {field}");
    }

    for omitted in [
        "0123456789abcdef0123456789abcdef",
        SCOPE_MARKER,
        COLLECTOR_VERSION_MARKER,
        DIAGNOSTIC_MARKER,
        HOST_NAME_MARKER,
        HOST_VERSION_MARKER,
        "packages.json",
        sha256_hex(PACKAGES_ARTIFACT).as_str(),
    ] {
        assert!(
            !text.contains(omitted),
            "preview must omit manifest value {omitted}"
        );
    }

    let help = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["help", "provenance", "preview-session"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(
        String::from_utf8_lossy(&help.stdout)
            .contains("Usage: sideeffect provenance preview-session SESSION_DIR")
    );
}

#[test]
fn provenance_preview_session_reports_absent_categories_for_minimal_manifest() {
    let temp = TestDirectory::new();
    let session = write_private_session_directory(
        &temp.0,
        "synthetic-minimal-session",
        &minimal_fixture_manifest(),
        &[],
    );
    let preview = preview_session(&session);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    assert!(preview.stderr.is_empty());

    let text = String::from_utf8(preview.stdout).unwrap();
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        document["manifest_sha256"],
        sha256_hex(&fs::read(session.join("session.json")).unwrap())
    );
    assert_eq!(document["manifest_schema_version"], 3);

    let binds = &document["binds"];
    for (field, expected) in [
        ("exact_manifest_bytes", serde_json::json!(true)),
        ("session_identifier_present", serde_json::json!(true)),
        ("host_context_present", serde_json::json!(false)),
        ("observed_os_metadata_present", serde_json::json!(false)),
        ("coverage_manifest_present", serde_json::json!(true)),
        ("collector_identity_present", serde_json::json!(false)),
        (
            "collector_provider_identity_present",
            serde_json::json!(false),
        ),
        ("requested_settings_present", serde_json::json!(false)),
        ("effective_settings_present", serde_json::json!(false)),
        ("applied_limits_present", serde_json::json!(false)),
        ("runtime_loss_metadata_present", serde_json::json!(false)),
        ("diagnostics_present", serde_json::json!(false)),
        ("artifact_hashes_present", serde_json::json!(false)),
        ("source_count", serde_json::json!(1)),
        ("artifact_count", serde_json::json!(0)),
    ] {
        assert_eq!(binds[field], expected, "unexpected value for {field}");
    }
    assert!(!text.contains("minimal-synthetic-scope-marker"));
    assert!(!text.contains("fedcba9876543210fedcba9876543210"));
}

#[test]
fn provenance_preview_session_rejects_tampered_evidence_without_json_output() {
    let temp = TestDirectory::new();
    let tampered_artifact_session = write_private_session_directory(
        &temp.0,
        "synthetic-tampered-artifact-session",
        &current_fixture_manifest(),
        &[("packages.json", PACKAGES_ARTIFACT)],
    );
    let artifact_path = tampered_artifact_session.join("packages.json");
    let mut tampered_artifact = fs::read(&artifact_path).unwrap();
    tampered_artifact[0] = b' ';
    fs::write(&artifact_path, &tampered_artifact).unwrap();
    let artifact_preview = preview_session(&tampered_artifact_session);
    assert_eq!(artifact_preview.status.code(), Some(1));
    assert!(artifact_preview.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&artifact_preview.stderr)
            .contains("does not match its declared SHA-256")
    );

    let malformed_manifest_session = write_private_session_directory(
        &temp.0,
        "synthetic-malformed-manifest-session",
        &current_fixture_manifest(),
        &[("packages.json", PACKAGES_ARTIFACT)],
    );
    fs::write(malformed_manifest_session.join("session.json"), b"{").unwrap();
    let manifest_preview = preview_session(&malformed_manifest_session);
    assert_eq!(manifest_preview.status.code(), Some(1));
    assert!(manifest_preview.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&manifest_preview.stderr)
            .contains("invalid audit-session manifest")
    );
}
