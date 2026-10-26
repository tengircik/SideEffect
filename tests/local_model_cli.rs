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
                "sideeffect-model-preview-{}-{id}.trace",
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

fn run_preview(trace: &TempTrace) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args([
            "model-preview",
            "--question",
            "Which executable was observed?",
        ])
        .arg(&trace.0)
        .output()
        .unwrap()
}

#[test]
fn preview_digest_covers_only_the_bounded_typed_request() {
    let first = TempTrace::with_contents(
        b"100 execve(\"/usr/bin/printf\", [\"printf\", \"PRIVATE_ABC_117\"], 0x0) = 0\n",
    );
    let second = TempTrace::with_contents(
        b"100 execve(\"/usr/bin/printf\", [\"printf\", \"PRIVATE_XYZ_224\"], 0x0) = 0\n",
    );
    let first_output = run_preview(&first);
    let second_output = run_preview(&second);
    assert!(
        first_output.status.success(),
        "{}",
        String::from_utf8_lossy(&first_output.stderr)
    );
    assert!(second_output.status.success());

    let first_json: serde_json::Value = serde_json::from_slice(&first_output.stdout).unwrap();
    let second_json: serde_json::Value = serde_json::from_slice(&second_output.stdout).unwrap();
    assert_eq!(
        first_json["request_sha256"], second_json["request_sha256"],
        "raw arguments omitted from the reviewed request must not affect its digest"
    );
    assert_eq!(
        first_json["model_sha256"],
        sideeffect::local_model::MODEL_SHA256
    );
    assert_eq!(
        first_json["model_repository_revision"],
        sideeffect::local_model::MODEL_REPOSITORY_REVISION
    );
    assert_eq!(first_json["question"], "Which executable was observed?");
    assert!(first_json["prompt"].as_str().unwrap().contains("E001"));
    assert!(!String::from_utf8_lossy(&first_output.stdout).contains("PRIVATE_ABC_117"));
    assert!(!String::from_utf8_lossy(&second_output.stdout).contains("PRIVATE_XYZ_224"));
}

#[test]
fn partial_parse_is_visible_and_uses_partial_exit_status() {
    let trace =
        TempTrace::with_contents(b"100 execve(\"/usr/bin/printf\", [], 0x0) = 0\nmalformed row\n");
    let output = run_preview(&trace);
    assert_eq!(output.status.code(), Some(2));
    let preview: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(preview["evidence_summary"]["parse_status"], "partial");
}

#[test]
fn model_execution_rejects_unconfirmed_request_before_starting_runtime() {
    let trace = TempTrace::with_contents(
        b"100 execve(\"/usr/bin/printf\", [\"printf\", \"value\"], 0x0) = 0\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args([
            "model-analyze",
            "--question",
            "Which executable was observed?",
            "--runtime",
            "C:\\missing\\runtime.exe",
            "--model",
            "C:\\missing\\model.gguf",
            "--confirm-sha256",
            &"0".repeat(64),
        ])
        .arg(&trace.0)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("preview digest mismatch"));
}
