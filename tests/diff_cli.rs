use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

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
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["capture_completeness"], "unknown");
    assert_eq!(document["matching_policy"]["multiplicity"], "multiset");
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
