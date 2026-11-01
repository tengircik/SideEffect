use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
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
