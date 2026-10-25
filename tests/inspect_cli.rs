use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempTrace(std::path::PathBuf);

impl TempTrace {
    fn with_contents(contents: &[u8]) -> Self {
        loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-inspect-cli-{}-{id}.trace",
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(contents).unwrap();
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create temporary trace: {error}"),
            }
        }
    }
}

impl Drop for TempTrace {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn inspect_defaults_to_versioned_json() {
    let trace = TempTrace::with_contents(
        b"123 1700000000.123456 openat(AT_FDCWD</tmp/work>, \"file.txt\", O_RDONLY) = 3\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("inspect")
        .arg(&trace.0)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schema_version"], 5);
    assert_eq!(document["source_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(document["parse_status"], "complete");
    assert_eq!(
        document["records"][0]["raw_arguments"],
        "AT_FDCWD</tmp/work>, \"file.txt\", O_RDONLY"
    );
    assert_eq!(
        document["records"][0]["lexical_path_hint"]["path"],
        "/tmp/work/file.txt"
    );
    assert_eq!(
        document["records"][0]["lexical_path_hint"]["basis"],
        "at_fdcwd_annotation"
    );
}

#[test]
fn inspect_json_links_conservative_outcome_to_raw_evidence() {
    let contents = concat!(
        "9 execve(\"/bin/tool\", [\"tool\"], 0x0) = 0\n",
        "9 openat(AT_FDCWD, \"/tmp/missing\", O_RDONLY) = -1 ENOENT (No such file or directory)\n",
        "9 connect(3, {sa_family=AF_INET}, 16) = -1 EINPROGRESS (Operation now in progress)\n",
        "9 socket(AF_INET, SOCK_STREAM, 0) = 3\n",
    );
    let trace = TempTrace::with_contents(contents.as_bytes());
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("inspect")
        .arg(&trace.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schema_version"], 5);
    assert_eq!(document["records"][0]["outcome"], "success");
    assert_eq!(document["records"][1]["outcome"], "failure");
    assert_eq!(document["records"][2]["outcome"], "in_progress");
    assert!(document["records"][3].get("outcome").is_none());
    assert_eq!(
        document["records"][1]["raw_result"],
        "-1 ENOENT (No such file or directory)"
    );
    assert_eq!(
        document["records"][1]["raw_line"],
        "9 openat(AT_FDCWD, \"/tmp/missing\", O_RDONLY) = -1 ENOENT (No such file or directory)"
    );
    assert_eq!(document["records"][1]["evidence"]["line_number"], 2);
    assert_eq!(document["records"][1]["evidence"]["byte_offset"], 41);
}

#[test]
fn inspect_text_discloses_the_basis_of_a_lexical_path_hint() {
    let trace = TempTrace::with_contents(
        b"123 1700000000.123456 openat(AT_FDCWD</tmp/work>, \"assets/icon.svg\", O_RDONLY) = 4\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inspect", "--format", "text"])
        .arg(&trace.0)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Lexical path hint: \"/tmp/work/assets/icon.svg\""));
    assert!(text.contains("Path hint basis: at_fdcwd_annotation"));
    assert!(text.contains("Outcome: success"));
}

#[test]
fn inspect_text_shows_partial_status_every_record_and_diagnostics_safely() {
    let trace = TempTrace::with_contents(
        "write(1, \"ansi-\u{1b}[31m-bidi-\u{202e}-é\", 16) = 16\nnot a strace record\n".as_bytes(),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inspect", "--format", "text"])
        .arg(&trace.0)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_ascii());
    assert!(!output.stdout.contains(&0x1b));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Parse status: partial"));
    assert!(text.contains("Kind: syscall"));
    assert!(text.contains("Arguments: \"1, \\\"ansi-\\u{1B}[31m-bidi-\\u{202E}-\\u{E9}\\\", 16\""));
    assert!(text.contains("Kind: unparsed"));
    assert!(text.contains("Raw line: \"not a strace record\""));
    assert!(text.contains("Diagnostics: 1"));
    assert!(text.contains("Code: \"unsupported_record\""));
}

#[test]
fn inspect_rejects_unknown_format_before_reading_a_path() {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inspect", "--format", "xml", "missing.trace"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("inspect format must be either"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("could not inspect trace input"));
}

#[cfg(target_os = "linux")]
struct TempBundle(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl TempBundle {
    fn new(trace: &[u8]) -> Self {
        use sha2::{Digest, Sha256};

        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "sideeffect-inspect-bundle-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(directory.join("trace.strace"), trace).unwrap();
        fs::set_permissions(
            directory.join("trace.strace"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let hash = format!("{:x}", Sha256::digest(trace));
        let manifest = format!(
            r#"{{"schema":"sideeffect.run","schema_version":1,"producer":{{"sideeffect_version":"0.1.0","operating_system":"linux","architecture":"x86_64"}},"capture":{{"tracer":{{"name":"strace","major":6,"minor":6}},"capture_profile":"linux_process_file_network_v1","strace_reported_status":{{"kind":"exit_code","value":0}},"command_outcome":"not_independently_verified","completeness":"unknown","command_stdout":"inherited_not_captured","command_stderr":"inherited_not_captured","tracer_diagnostics":"inherited_not_captured"}},"trace":{{"name":"trace.strace","format":"strace_text","byte_length":{},"sha256":"{}"}}}}"#,
            trace.len(),
            hash
        );
        fs::write(directory.join("run.json"), manifest).unwrap();
        fs::set_permissions(
            directory.join("run.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        Self(directory)
    }

    fn inspect(&self) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .args(["inspect", "--bundle"])
            .arg(&self.0)
            .output()
            .unwrap()
    }
}

#[cfg(target_os = "linux")]
impl Drop for TempBundle {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn inspect_bundle_matches_inspecting_its_trace_without_path_leak() {
    let trace = b"close(1) = 0\n";
    let bundle = TempBundle::new(trace);
    let output = bundle.inspect();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let trace_file = TempTrace::with_contents(trace);
    let raw = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inspect"])
        .arg(&trace_file.0)
        .output()
        .unwrap();
    let raw_document: serde_json::Value = serde_json::from_slice(&raw.stdout).unwrap();
    assert_eq!(document, raw_document);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(bundle.0.to_str().unwrap()));
}

#[cfg(target_os = "linux")]
#[test]
fn inspect_bundle_rejects_hash_and_length_mismatch() {
    let bundle = TempBundle::new(b"close(1) = 0\n");
    let manifest_path = bundle.0.join("run.json");
    let original = fs::read_to_string(&manifest_path).unwrap();
    let trace_path = bundle.0.join("trace.strace");
    fs::write(&trace_path, b"close(2) = 0\n").unwrap();
    fs::set_permissions(&trace_path, fs::Permissions::from_mode(0o600)).unwrap();
    let output = bundle.inspect();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("SHA-256"));

    fs::write(&trace_path, b"close(1) = 0\n").unwrap();
    fs::set_permissions(&trace_path, fs::Permissions::from_mode(0o600)).unwrap();
    let incorrect_length = original.replace("\"byte_length\":13", "\"byte_length\":12");
    fs::write(&manifest_path, incorrect_length).unwrap();
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
    let output = bundle.inspect();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("length"));
}

#[cfg(target_os = "linux")]
#[test]
fn inspect_bundle_rejects_extra_entries_and_symlinks() {
    let bundle = TempBundle::new(b"close(1) = 0\n");
    fs::write(bundle.0.join("unexpected"), b"x").unwrap();
    assert!(String::from_utf8_lossy(&bundle.inspect().stderr).contains("exactly"));
    fs::remove_file(bundle.0.join("unexpected")).unwrap();
    fs::remove_file(bundle.0.join("trace.strace")).unwrap();
    let outside = TempTrace::with_contents(b"close(1) = 0\n");
    std::os::unix::fs::symlink(&outside.0, bundle.0.join("trace.strace")).unwrap();
    assert!(String::from_utf8_lossy(&bundle.inspect().stderr).contains("without symlinks"));
}

#[cfg(target_os = "linux")]
#[test]
fn inspect_bundle_rejects_missing_or_symlinked_manifest() {
    let bundle = TempBundle::new(b"close(1) = 0\n");
    let manifest = bundle.0.join("run.json");
    let outside = TempTrace::with_contents(b"{}");
    fs::remove_file(&manifest).unwrap();
    assert!(String::from_utf8_lossy(&bundle.inspect().stderr).contains("exactly"));
    std::os::unix::fs::symlink(&outside.0, &manifest).unwrap();
    assert!(String::from_utf8_lossy(&bundle.inspect().stderr).contains("without symlinks"));
}

#[cfg(target_os = "linux")]
#[test]
fn inspect_bundle_rejects_insecure_modes_and_bundle_directory_symlink() {
    let bundle = TempBundle::new(b"close(1) = 0\n");
    fs::set_permissions(&bundle.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        String::from_utf8_lossy(&bundle.inspect().stderr).contains("owned by the current user")
    );
    fs::set_permissions(&bundle.0, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(
        bundle.0.join("trace.strace"),
        fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&bundle.inspect().stderr).contains("private regular files"));

    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let link = std::env::temp_dir().join(format!(
        "sideeffect-inspect-bundle-link-{}-{id}",
        std::process::id()
    ));
    std::os::unix::fs::symlink(&bundle.0, &link).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inspect", "--bundle"])
        .arg(&link)
        .output()
        .unwrap();
    let _ = fs::remove_file(link);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("without following symlinks"));
}

#[cfg(target_os = "linux")]
#[test]
fn inspect_bundle_rejects_unsupported_schema_and_malformed_manifest() {
    let bundle = TempBundle::new(b"close(1) = 0\n");
    let manifest_path = bundle.0.join("run.json");
    let valid = fs::read_to_string(&manifest_path).unwrap();
    fs::write(
        &manifest_path,
        valid.replace("\"schema_version\":1", "\"schema_version\":2"),
    )
    .unwrap();
    assert!(
        String::from_utf8_lossy(&bundle.inspect().stderr).contains("unsupported bundle schema")
    );
    fs::write(&manifest_path, b"{not-json").unwrap();
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(String::from_utf8_lossy(&bundle.inspect().stderr).contains("invalid JSON"));
}

#[cfg(target_os = "linux")]
#[test]
fn inspect_bundle_rejects_manifest_and_trace_over_limits() {
    let bundle = TempBundle::new(b"close(1) = 0\n");
    let manifest_path = bundle.0.join("run.json");
    fs::write(&manifest_path, vec![b' '; 16 * 1024 + 1]).unwrap();
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(String::from_utf8_lossy(&bundle.inspect().stderr).contains("limit"));

    let manifest = format!(
        r#"{{"schema":"sideeffect.run","schema_version":1,"producer":{{"sideeffect_version":"0.1.0","operating_system":"linux","architecture":"x86_64"}},"capture":{{"tracer":{{"name":"strace","major":6,"minor":6}},"capture_profile":"linux_process_file_network_v1","strace_reported_status":{{"kind":"exit_code","value":0}},"command_outcome":"not_independently_verified","completeness":"unknown","command_stdout":"inherited_not_captured","command_stderr":"inherited_not_captured","tracer_diagnostics":"inherited_not_captured"}},"trace":{{"name":"trace.strace","format":"strace_text","byte_length":{},"sha256":"{}"}}}}"#,
        32 * 1024 * 1024 + 1,
        "0".repeat(64)
    );
    fs::write(&manifest_path, manifest).unwrap();
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(String::from_utf8_lossy(&bundle.inspect().stderr).contains("trace exceeds"));

    let oversized_trace_bundle = TempBundle::new(b"close(1) = 0\n");
    let trace_path = oversized_trace_bundle.0.join("trace.strace");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&trace_path)
        .unwrap()
        .set_len((32 * 1024 * 1024 + 1) as u64)
        .unwrap();
    assert!(String::from_utf8_lossy(&oversized_trace_bundle.inspect().stderr).contains("limit"));
}
