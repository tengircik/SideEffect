#![cfg(target_os = "linux")]

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

fn run_preview(model: &SelectedTestModel, trace: &TempTrace) -> std::process::Output {
    run_preview_with_question(model, "Which executable was observed?", trace)
}

fn run_preview_with_question(
    model: &SelectedTestModel,
    question: &str,
    trace: &TempTrace,
) -> std::process::Output {
    model
        .command()
        .args(["model-preview", "--question", question])
        .arg(&trace.0)
        .output()
        .unwrap()
}

fn collect_evidence_ids(
    value: &serde_json::Value,
    output: &mut std::collections::BTreeSet<String>,
) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(id) = object
                .get("evidence_id")
                .and_then(serde_json::Value::as_str)
            {
                output.insert(id.to_owned());
            }
            for child in object.values() {
                collect_evidence_ids(child, output);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                collect_evidence_ids(child, output);
            }
        }
        _ => {}
    }
}

#[test]
fn preview_digest_covers_only_the_bounded_typed_request() {
    let model = SelectedTestModel::new("evidence");
    let first = TempTrace::with_contents(
        b"100 execve(\"/usr/bin/printf\", [\"printf\", \"PRIVATE_ABC_117\"], 0x0) = 0\n",
    );
    let second = TempTrace::with_contents(
        b"100 execve(\"/usr/bin/printf\", [\"printf\", \"PRIVATE_XYZ_224\"], 0x0) = 0\n",
    );
    let first_output = run_preview(&model, &first);
    let second_output = run_preview(&model, &second);
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
    assert_eq!(first_json["model_sha256"], model.sha256());
    assert_eq!(first_json["model_id"], model.id());
    assert_eq!(first_json["question"], "Which executable was observed?");
    assert!(first_json["prompt"].as_str().unwrap().contains("E001"));
    assert!(!String::from_utf8_lossy(&first_output.stdout).contains("PRIVATE_ABC_117"));
    assert!(!String::from_utf8_lossy(&second_output.stdout).contains("PRIVATE_XYZ_224"));
}

#[test]
fn partial_parse_is_visible_and_uses_partial_exit_status() {
    let model = SelectedTestModel::new("evidence");
    let trace =
        TempTrace::with_contents(b"100 execve(\"/usr/bin/printf\", [], 0x0) = 0\nmalformed row\n");
    let output = run_preview(&model, &trace);
    assert_eq!(output.status.code(), Some(2));
    let preview: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(preview["evidence_summary"]["parse_status"], "partial");
}

#[test]
fn preregistered_synthetic_corpus_keeps_all_evidence_available_to_the_model() {
    let model = SelectedTestModel::new("evidence");
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/local_model_synthetic");
    let corpus: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture_root.join("corpus.json")).unwrap()).unwrap();
    assert_eq!(corpus["schema"], "sideeffect.local_model_evaluation_corpus");

    for case in corpus["cases"].as_array().unwrap() {
        let trace_path = fixture_root.join(case["trace"].as_str().unwrap());
        let trace = TempTrace::with_contents(&fs::read(trace_path).unwrap());
        let question = case["question"].as_str().unwrap();
        let output = run_preview_with_question(&model, question, &trace);
        let expected_parse_status = case["expected_parse_status"].as_str().unwrap_or("complete");
        let expected_exit = if expected_parse_status == "partial" {
            Some(2)
        } else {
            Some(0)
        };
        assert_eq!(
            output.status.code(),
            expected_exit,
            "unexpected preview status for {}: {}",
            case["id"],
            String::from_utf8_lossy(&output.stderr)
        );
        let preview: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            preview["evidence_summary"]["parse_status"], expected_parse_status,
            "unexpected parse state for {}",
            case["id"]
        );
        let candidates = preview["output_schema"]["properties"]["evidence_ids"]["items"]["enum"]
            .as_array()
            .unwrap();
        let mut summary_ids = std::collections::BTreeSet::new();
        collect_evidence_ids(&preview["evidence_summary"], &mut summary_ids);
        let candidate_ids = candidates
            .iter()
            .map(|candidate| {
                candidate
                    .as_str()
                    .expect("candidate evidence ID is a string")
                    .to_owned()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            candidate_ids, summary_ids,
            "model schema must expose all bounded evidence for {}",
            case["id"]
        );
        for candidate in candidates {
            let id = candidate
                .as_str()
                .expect("candidate evidence ID is a string");
            assert!(
                summary_ids.contains(id),
                "unknown candidate {id} for {}",
                case["id"]
            );
        }
        if case["id"] == "ambiguous_duplicate_failures" {
            assert!(
                candidates.len() > 1,
                "ambiguous case must not be narrowed before inference"
            );
        }
    }
}

#[test]
fn model_execution_rejects_unconfirmed_request_before_starting_runtime() {
    let model = SelectedTestModel::new("evidence");
    let trace = TempTrace::with_contents(
        b"100 execve(\"/usr/bin/printf\", [\"printf\", \"value\"], 0x0) = 0\n",
    );
    let output = model
        .command()
        .args([
            "model-analyze",
            "--question",
            "Which executable was observed?",
            "--runtime",
            "C:\\missing\\runtime.exe",
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
