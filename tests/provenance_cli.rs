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
