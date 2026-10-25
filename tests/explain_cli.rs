use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempTrace(std::path::PathBuf);

impl TempTrace {
    fn with_contents(contents: &[u8]) -> Self {
        loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-explain-cli-{}-{id}.trace",
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

const BASELINE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/diff/baseline.synthetic.trace"
);
const CANDIDATE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/diff/updated.synthetic.trace"
);

#[test]
fn explain_trace_emits_bounded_summary_without_raw_trace_values() {
    let trace = TempTrace::with_contents(
        b"7 connect(3, {sa_family=AF_INET, secret=\"private-value\"}, 16) = -1 EINPROGRESS (Operation now in progress)\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("explain")
        .arg(&trace.0)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let explanation: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(explanation["parse_status"], "complete");
    assert_eq!(explanation["capture_completeness"], "unknown");
    assert_eq!(explanation["result_facts"][0]["syscall"], "connect");
    assert_eq!(explanation["result_facts"][0]["outcome"], "in_progress");
    assert_eq!(
        explanation["result_facts"][0]["meaning"],
        "connection_in_progress"
    );
    assert!(explanation["result_facts"][0]["evidence"]["byte_offset"].is_number());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("private-value"));
    assert!(!text.contains("EINPROGRESS"));
    assert!(!text.contains("raw_arguments"));
    assert!(!text.contains("source_sha256"));
}

#[test]
fn explain_partial_trace_emits_summary_and_partial_exit_status() {
    let trace = TempTrace::with_contents(b"close(3) = 0\nnot a strace record\n");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("explain")
        .arg(&trace.0)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let explanation: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(explanation["parse_status"], "partial");
    assert_eq!(explanation["parser_diagnostic_count"], 1);
    assert!(
        explanation["known_unknowns"]
            .as_array()
            .unwrap()
            .iter()
            .any(|unknown| unknown == "partial_parse")
    );
}

#[test]
fn explain_diff_emits_counts_and_evidence_without_raw_diff_fields() {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--diff", BASELINE, CANDIDATE])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let explanation: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(explanation["capture_completeness"], "unknown");
    assert!(explanation["scanned_change_count"].as_u64().unwrap() > 0);
    assert!(explanation["changes"][0]["category"].is_string());
    assert!(explanation["changes"][0]["before"].is_array());
    assert!(explanation["changes"][0]["after"].is_array());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("raw_arguments"));
    assert!(!text.contains("raw_result"));
    assert!(!text.contains("source_sha256"));
    assert!(!text.contains("\"syscall\":"));
}

#[test]
fn explain_diff_rejects_partial_trace_without_emitting_a_summary() {
    let partial = TempTrace::with_contents(b"close(3) = 0\nnot a strace record\n");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("explain")
        .arg("--diff")
        .arg(BASELINE)
        .arg(&partial.0)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not completely parsed"));
}
