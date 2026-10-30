#[path = "common/model_store.rs"]
mod model_store;

use model_store::SelectedTestModel;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempTrace(std::path::PathBuf);

impl TempTrace {
    fn with_contents(contents: &[u8]) -> Self {
        loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-model-explain-preview-{}-{id}.trace",
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

fn run_preview(
    model: &SelectedTestModel,
    backend: &str,
    trace: &TempTrace,
) -> std::process::Output {
    run_preview_with_question(model, backend, trace, "What file access was observed?")
}

fn run_preview_with_question(
    model: &SelectedTestModel,
    backend: &str,
    trace: &TempTrace,
    question: &str,
) -> std::process::Output {
    model
        .command()
        .args([
            "model-explain-preview",
            "--question",
            question,
            "--backend",
            backend,
        ])
        .arg(&trace.0)
        .output()
        .unwrap()
}

#[test]
fn deterministic_scope_abstention_does_not_start_runtime() {
    let model = SelectedTestModel::new("explanation");
    let question = "Does this prove the program is safe to run?";
    let trace = TempTrace::with_contents(
        b"55 connect(7, {sa_family=AF_INET}, 16) = -1 ECONNREFUSED (Connection refused)\n",
    );
    let preview_output = run_preview_with_question(&model, "cpu", &trace, question);
    assert!(
        preview_output.status.success(),
        "{}",
        String::from_utf8_lossy(&preview_output.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&preview_output.stdout).unwrap();
    assert_eq!(preview["deterministic_abstain_reason"], "unsupported_scope");

    let output = model
        .command()
        .args([
            "model-explain",
            "--question",
            question,
            "--backend",
            "cpu",
            "--runtime",
            "missing-llama-runtime",
            "--confirm-sha256",
            preview["request_sha256"].as_str().unwrap(),
        ])
        .arg(&trace.0)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let analysis: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(analysis["backend_used"], "not_run");
    assert_eq!(analysis["backend_status"], "deterministic_scope_abstention");
    assert_eq!(analysis["interpretation"]["status"], "abstained");
    assert_eq!(
        analysis["interpretation"]["abstain_reason"],
        "unsupported_scope"
    );
}

#[test]
fn preview_shows_exact_bounded_evidence_and_coverage_for_confirmation() {
    let model = SelectedTestModel::new("explanation");
    let trace = TempTrace::with_contents(
        b"55 openat(AT_FDCWD, \"/tmp/sideeffect-explain-config.ini\", O_RDONLY) = -1 ENOENT (No such file or directory)\n",
    );
    let output = run_preview(&model, "auto", &trace);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        preview["schema"],
        "sideeffect.local_model_explanation_preview"
    );
    assert_eq!(preview["schema_version"], 2);
    assert_eq!(
        preview["deterministic_abstain_reason"],
        serde_json::Value::Null
    );
    assert_eq!(preview["backend_preference"], "auto");
    assert_eq!(preview["model_sha256"], model.sha256());
    assert_eq!(preview["model_id"], model.id());
    assert_eq!(preview["request_sha256"].as_str().unwrap().len(), 64);
    let prompt: serde_json::Value =
        serde_json::from_str(preview["prompt"].as_str().unwrap()).unwrap();
    assert_eq!(prompt["user_question"], "What file access was observed?");
    assert_eq!(prompt["coverage"]["parse_status"], "complete");
    assert_eq!(prompt["coverage"]["capture_completeness"], "unknown");
    assert!(
        prompt["observed_syscall_results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|fact| fact["lexical_path_hint"]["path"] == "/tmp/sideeffect-explain-config.ini")
    );
    assert!(
        preview["output_schema"]
            .to_string()
            .contains("evidence_ids")
    );
}

#[test]
fn preview_digest_binds_backend_choice_and_partial_input_is_explicit() {
    let model = SelectedTestModel::new("explanation");
    let complete =
        TempTrace::with_contents(b"55 execve(\"/usr/bin/example\", [\"example\"], 0x0) = 0\n");
    let auto = run_preview(&model, "auto", &complete);
    let cpu = run_preview(&model, "cpu", &complete);
    assert!(auto.status.success());
    assert!(cpu.status.success());
    let auto_json: serde_json::Value = serde_json::from_slice(&auto.stdout).unwrap();
    let cpu_json: serde_json::Value = serde_json::from_slice(&cpu.stdout).unwrap();
    assert_ne!(auto_json["request_sha256"], cpu_json["request_sha256"]);

    let partial = TempTrace::with_contents(
        b"55 execve(\"/usr/bin/example\", [\"example\"], 0x0) = 0\nnot a syscall row\n",
    );
    let partial_output = run_preview(&model, "auto", &partial);
    assert_eq!(partial_output.status.code(), Some(2));
    let partial_json: serde_json::Value = serde_json::from_slice(&partial_output.stdout).unwrap();
    assert_eq!(partial_json["evidence_summary"]["parse_status"], "partial");
}

#[test]
fn rejects_unknown_backend_without_attempting_model_execution() {
    let model = SelectedTestModel::new("explanation");
    let trace =
        TempTrace::with_contents(b"55 execve(\"/usr/bin/example\", [\"example\"], 0x0) = 0\n");
    let output = run_preview(&model, "mystery", &trace);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("backend must be auto, cpu, or cuda"));
}

#[test]
fn rejects_digest_mismatch_before_opening_runtime_or_model_paths() {
    let model = SelectedTestModel::new("explanation");
    let trace =
        TempTrace::with_contents(b"55 execve(\"/usr/bin/example\", [\"example\"], 0x0) = 0\n");
    let output = model
        .command()
        .args([
            "model-explain",
            "--question",
            "Which executable was observed?",
            "--backend",
            "cpu",
            "--runtime",
            "missing-llama-runtime",
            "--confirm-sha256",
            &"0".repeat(64),
        ])
        .arg(&trace.0)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("preview digest mismatch"));
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("could not resolve local runtime path")
    );
}
