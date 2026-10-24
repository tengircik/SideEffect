use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;

const BASELINE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/diff/baseline.synthetic.trace"
);
const UPDATED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/diff/updated.synthetic.trace"
);

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempTrace(std::path::PathBuf);

impl TempTrace {
    fn with_contents(contents: &[u8]) -> Self {
        loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-diff-cli-{}-{id}.trace",
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

#[cfg(target_os = "linux")]
struct TempBundle(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl TempBundle {
    fn with_contents(contents: &[u8]) -> Self {
        use sha2::{Digest, Sha256};

        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sideeffect-diff-bundle-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(path.join("trace.strace"), contents).unwrap();
        fs::set_permissions(path.join("trace.strace"), fs::Permissions::from_mode(0o600)).unwrap();
        let manifest = format!(
            r#"{{"schema":"sideeffect.run","schema_version":1,"producer":{{"sideeffect_version":"0.1.0","operating_system":"linux","architecture":"x86_64"}},"capture":{{"tracer":{{"name":"strace","major":6,"minor":6}},"capture_profile":"linux_process_file_network_v1","strace_reported_status":{{"kind":"exit_code","value":0}},"command_outcome":"not_independently_verified","completeness":"unknown","command_stdout":"inherited_not_captured","command_stderr":"inherited_not_captured","tracer_diagnostics":"inherited_not_captured"}},"trace":{{"name":"trace.strace","format":"strace_text","byte_length":{},"sha256":"{}"}}}}"#,
            contents.len(),
            format!("{:x}", Sha256::digest(contents))
        );
        fs::write(path.join("run.json"), manifest).unwrap();
        fs::set_permissions(path.join("run.json"), fs::Permissions::from_mode(0o600)).unwrap();
        Self(path)
    }
}

#[cfg(target_os = "linux")]
impl Drop for TempBundle {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn diff_command_emits_versioned_json_with_evidence_references() {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", BASELINE, UPDATED])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schema_version"], 3);
    assert_eq!(
        document["left_source_sha256"],
        "d75a97b3058387a94ca085ed28ab08826671f305be8c70e947df902de553ca9d"
    );
    assert_eq!(
        document["right_source_sha256"],
        "e75d32bc48eaa3577db14bbe3dc7f5e75bc83f28d575af8c0592e420aa866a91"
    );
    assert_eq!(document["capture_completeness"], "unknown");
    assert_eq!(document["matching_policy"]["multiplicity"], "multiset");
    assert_eq!(
        document["matching_policy"]["exact_fields"][3],
        "raw_arguments"
    );
    assert_eq!(
        document["matching_policy"]["display_only_fields"][0],
        "lexical_path_hint"
    );
    let changed_open = document["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["syscall"] == "openat" && change["kind"] == "changed")
        .unwrap();
    assert_eq!(
        changed_open["before_lexical_path_hint"]["path"],
        "/tmp/config.json"
    );
    assert_eq!(
        changed_open["after_lexical_path_hint"]["path"],
        "/tmp/config.json"
    );
    assert_eq!(document["changes"].as_array().unwrap().len(), 4);
    let changed_open = document["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["syscall"] == "openat" && change["kind"] == "changed")
        .unwrap();
    assert_eq!(changed_open["before"][0]["line_number"], 2);
    assert_eq!(changed_open["after"][0]["line_number"], 2);
}

#[test]
fn diff_command_emits_no_document_for_a_partial_parse() {
    let partial = TempTrace::with_contents(b"close(3) = 0\nnot a strace record\n");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff"])
        .arg(BASELINE)
        .arg(&partial.0)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not completely parsed"));
}

#[test]
fn text_format_escapes_terminal_controls_and_non_ascii_trace_data() {
    let trace =
        "1 1700000000.000001 write(1, \"ansi-\u{1b}[31m-bidi-\u{202e}-é\", 16) = 16\n".to_owned();
    let baseline = TempTrace::with_contents(trace.as_bytes());
    let candidate = TempTrace::with_contents(b"");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", "--format", "text"])
        .arg(&baseline.0)
        .arg(&candidate.0)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_ascii());
    assert!(!output.stdout.contains(&0x1b));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("\\u{1B}[31m"));
    assert!(text.contains("\\u{202E}"));
    assert!(text.contains("\\u{E9}"));
}

#[cfg(target_os = "linux")]
#[test]
fn diff_bundles_matches_raw_trace_json_and_text_without_leaking_bundle_paths() {
    let baseline = fs::read(BASELINE).unwrap();
    let updated = fs::read(UPDATED).unwrap();
    let left = TempBundle::with_contents(&baseline);
    let right = TempBundle::with_contents(&updated);

    let bundle_json = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", "--bundles"])
        .arg(&left.0)
        .arg(&right.0)
        .output()
        .unwrap();
    let raw_json = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", BASELINE, UPDATED])
        .output()
        .unwrap();
    assert!(bundle_json.status.success());
    assert!(raw_json.status.success());
    assert_eq!(bundle_json.stdout, raw_json.stdout);
    assert!(!String::from_utf8_lossy(&bundle_json.stdout).contains(left.0.to_str().unwrap()));
    assert!(!String::from_utf8_lossy(&bundle_json.stdout).contains(right.0.to_str().unwrap()));

    let bundle_text = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", "--bundles", "--format", "text"])
        .arg(&left.0)
        .arg(&right.0)
        .output()
        .unwrap();
    let raw_text = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", "--format", "text", BASELINE, UPDATED])
        .output()
        .unwrap();
    assert!(bundle_text.status.success());
    assert_eq!(bundle_text.stdout, raw_text.stdout);
}

#[cfg(target_os = "linux")]
#[test]
fn diff_bundles_rejects_manifest_mismatch_before_writing_comparison() {
    let left = TempBundle::with_contents(b"close(1) = 0\n");
    let right = TempBundle::with_contents(b"close(2) = 0\n");
    fs::write(left.0.join("trace.strace"), b"close(9) = 0\n").unwrap();
    fs::set_permissions(
        left.0.join("trace.strace"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", "--bundles"])
        .arg(&left.0)
        .arg(&right.0)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("SHA-256"));
    assert!(!stderr.contains(left.0.to_str().unwrap()));
}

#[cfg(target_os = "linux")]
#[test]
fn diff_bundles_rejects_partial_parses_without_writing_comparison() {
    let left = TempBundle::with_contents(b"close(1) = 0\n");
    let right = TempBundle::with_contents(b"close(3) = 0\nnot a strace record\n");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", "--bundles"])
        .arg(&left.0)
        .arg(&right.0)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not completely parsed"));
}

#[cfg(target_os = "linux")]
#[test]
fn diff_bundles_html_matches_raw_trace_report_without_bundle_paths() {
    let baseline = fs::read(BASELINE).unwrap();
    let updated = fs::read(UPDATED).unwrap();
    let left = TempBundle::with_contents(&baseline);
    let right = TempBundle::with_contents(&updated);
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let output_dir = std::env::temp_dir().join(format!(
        "sideeffect-diff-bundle-html-{}-{id}",
        std::process::id()
    ));
    fs::create_dir(&output_dir).unwrap();
    let bundle_report = output_dir.join("bundles.html");
    let raw_report = output_dir.join("raw.html");

    let bundle_output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", "--bundles", "--format", "html", "--output"])
        .arg(&bundle_report)
        .arg(&left.0)
        .arg(&right.0)
        .output()
        .unwrap();
    let raw_output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", "--format", "html", "--output"])
        .arg(&raw_report)
        .arg(BASELINE)
        .arg(UPDATED)
        .output()
        .unwrap();

    assert!(
        bundle_output.status.success(),
        "{}",
        String::from_utf8_lossy(&bundle_output.stderr)
    );
    assert!(raw_output.status.success());
    let bundle_html = fs::read_to_string(&bundle_report).unwrap();
    let raw_html = fs::read_to_string(&raw_report).unwrap();
    assert_eq!(bundle_html, raw_html);
    assert!(!bundle_html.contains(left.0.to_str().unwrap()));
    assert!(!bundle_html.contains(right.0.to_str().unwrap()));

    fs::remove_dir_all(output_dir).unwrap();
}
