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

struct TempWindowsRuntime(std::path::PathBuf);

impl TempWindowsRuntime {
    fn synthetic() -> Self {
        use sha2::{Digest, Sha256};
        use sideeffect::windows_runtime::*;
        let mut capture = WindowsRuntimeCapture {
            schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
            schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
            platform: "windows".to_owned(),
            capture_profile: "synthetic_etw_fixture".to_owned(),
            collection_status: CollectionStatus::Complete,
            capture_completeness: "unknown".to_owned(),
            started_at_unix_ms: 1,
            ended_at_unix_ms: 2,
            requested_duration_seconds: 1,
            stop_reason: StopReason::TargetExited,
            target: TargetOutcome {
                process_id: 42,
                exit_code: Some(0),
                status_available: true,
            },
            session: SessionMetadata {
                name: "synthetic_fixture".to_owned(),
                provider: "synthetic".to_owned(),
                scope: "synthetic_fixture_only".to_owned(),
                buffer_size_kb_requested: 16,
                minimum_buffers_requested: 8,
                maximum_buffers_requested: 32,
                buffer_count_reported: 8,
                provider_process_id_header_semantics: "header PID/TID is event context only"
                    .to_owned(),
            },
            limits: AppliedLimits {
                maximum_duration_seconds: 60,
                maximum_events: MAX_WINDOWS_RUNTIME_EVENTS,
                maximum_total_payload_bytes: MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES,
                maximum_payload_bytes_per_event: MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
                maximum_document_bytes: MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
            },
            event_loss: EventLoss {
                events_lost: 0,
                log_buffers_lost: 0,
                real_time_buffers_lost: 0,
                loss_statistics_available: true,
                observation: "zero_reported".to_owned(),
                final_snapshot_available: true,
            },
            document_sha256: String::new(),
            events: vec![NativeRuntimeEvent {
                record_ordinal: 1,
                provider_guid: "3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c".to_owned(),
                event_id: 0,
                event_version: 2,
                opcode: 1,
                event_kind: "process_start".to_owned(),
                header_process_id: 8,
                header_thread_id: 9,
                header_flags: 0x0040,
                timestamp_qpc: 10,
                raw_payload_hex: "00000000".to_owned(),
                payload_decoding: Some(DecodedProcessPayload {
                    status: ProcessDecodeStatus::Decoded,
                    schema_name: Some("Process_V2_TypeGroup1".to_owned()),
                    schema_version: Some(2),
                    pointer_size_bytes: Some(8),
                    process_id: Some(42),
                    parent_process_id: Some(1),
                    image_file_name: Some("synthetic.exe".to_owned()),
                    diagnostic: None,
                }),
                observation_decoding: None,
            }],
            diagnostics: Vec::new(),
        };
        let canonical = serde_json::to_vec(&capture).unwrap();
        capture.document_sha256 = format!("{:x}", Sha256::digest(canonical));
        let bytes = serde_json::to_vec(&capture).unwrap();
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sideeffect-model-explain-etw-{}-{id}.json",
            std::process::id()
        ));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
}

impl Drop for TempWindowsRuntime {
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
        "stderr: {}; stdout: {}",
        String::from_utf8_lossy(&preview_output.stderr),
        String::from_utf8_lossy(&preview_output.stdout),
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
    assert_eq!(analysis["interpretation"]["selection_status"], "abstained");
    assert_eq!(
        analysis["interpretation"]["evidence_ids"],
        serde_json::json!([])
    );
    assert_eq!(
        analysis["interpretation"]["selected_facts"],
        serde_json::json!([])
    );
    assert_eq!(
        analysis["interpretation_label"],
        "local_model_selection_abstained"
    );
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
    assert_eq!(preview["schema_version"], 3);
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
    assert_eq!(
        preview["output_schema"]["required"],
        serde_json::json!(["evidence_ids"])
    );
    assert!(preview["output_schema"]["properties"].get("text").is_none());
    assert!(
        preview["output_schema"]["properties"]
            .get("status")
            .is_none()
    );
    let result_ids = prompt["observed_syscall_results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["evidence_id"].clone())
        .collect::<Vec<_>>();
    assert_eq!(
        preview["output_schema"]["properties"]["evidence_ids"]["items"]["enum"],
        serde_json::json!(result_ids)
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
fn preview_uses_the_registered_model_identity_without_reading_weights() {
    let model = SelectedTestModel::new("explanation");
    let mut changed_model = fs::read(model.model_path()).unwrap();
    changed_model[8] ^= 1;
    fs::write(model.model_path(), changed_model).unwrap();
    let trace =
        TempTrace::with_contents(b"55 execve(\"/usr/bin/example\", [\"example\"], 0x0) = 0\n");

    let output = run_preview(&model, "cpu", &trace);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(preview["model_sha256"], model.sha256());
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

#[test]
fn windows_runtime_preview_and_confirmed_selector_use_source_specific_contract() {
    let model = SelectedTestModel::new("explanation");
    let capture = TempWindowsRuntime::synthetic();
    let question = "Does this prove the program is safe to run?";
    let preview_output = model
        .command()
        .args([
            "model-explain-preview",
            "--question",
            question,
            "--backend",
            "cpu",
            "--windows-runtime",
        ])
        .arg(&capture.0)
        .output()
        .unwrap();
    assert_eq!(
        preview_output.status.code(),
        Some(2),
        "status {:?}, stderr: {}; stdout: {}",
        preview_output.status,
        String::from_utf8_lossy(&preview_output.stderr),
        String::from_utf8_lossy(&preview_output.stdout)
    );
    let preview: serde_json::Value = serde_json::from_slice(&preview_output.stdout).unwrap();
    assert_eq!(
        preview["schema"],
        "sideeffect.local_model_windows_runtime_explanation_preview"
    );
    assert_eq!(preview["schema_version"], 1);
    assert_eq!(preview["evidence_summary"]["source_status"], "complete");
    assert_eq!(preview["evidence_summary"]["parse_status"], "partial");
    assert_eq!(
        preview["evidence_summary"]["capture_completeness"],
        "unknown"
    );
    let digest = preview["request_sha256"].as_str().unwrap();

    let mismatch = model
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
            &"0".repeat(64),
            "--windows-runtime",
        ])
        .arg(&capture.0)
        .output()
        .unwrap();
    assert_eq!(mismatch.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&mismatch.stderr).contains("preview digest mismatch"),
        "status {:?}, stderr: {}; stdout: {}",
        mismatch.status,
        String::from_utf8_lossy(&mismatch.stderr),
        String::from_utf8_lossy(&mismatch.stdout)
    );

    let analysis_output = model
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
            digest,
            "--windows-runtime",
        ])
        .arg(&capture.0)
        .output()
        .unwrap();
    assert_eq!(analysis_output.status.code(), Some(2));
    let analysis: serde_json::Value = serde_json::from_slice(&analysis_output.stdout).unwrap();
    assert_eq!(
        analysis["schema"],
        "sideeffect.local_model_windows_runtime_explanation"
    );
    assert_eq!(analysis["schema_version"], 1);
    assert_eq!(analysis["backend_used"], "not_run");
    assert_eq!(analysis["interpretation"]["selection_status"], "abstained");
}

#[test]
fn pinned_synthetic_etw_corpus_fixture_passes_model_preview_parser() {
    let model = SelectedTestModel::new("explanation");
    let fixture_directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/local_model_windows_etw_explain_v1");
    for (fixture_name, expected_capture_sha, network_evidence_id) in [
        (
            "network-then-unknown.json",
            "6a319f7108bf702f29f8e2bf9aa27448a4d8ba752fccacaa483869f3a86af6c0",
            "W00001",
        ),
        (
            "unknown-then-network.json",
            "a8c56c3c81476afb8ea7086ae942df3162de616efeebf393bd283903eeebe80e",
            "W00002",
        ),
    ] {
        let output = model
            .command()
            .args([
                "model-explain-preview",
                "--question",
                "Which decoded network observation is present?",
                "--backend",
                "cpu",
                "--windows-runtime",
            ])
            .arg(fixture_directory.join(fixture_name))
            .output()
            .unwrap();

        assert!(
            matches!(output.status.code(), Some(0) | Some(2)),
            "fixture {fixture_name}, status {:?}, stderr: {}; stdout: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        let preview: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            preview["schema"],
            "sideeffect.local_model_windows_runtime_explanation_preview"
        );
        assert_eq!(
            preview["evidence_summary"]["capture_sha256"],
            expected_capture_sha
        );
        assert_eq!(preview["evidence_summary"]["event_count"], 2);
        let prompt: serde_json::Value =
            serde_json::from_str(preview["prompt"].as_str().unwrap()).unwrap();
        let rows = prompt["observed_windows_etw_events"].as_array().unwrap();
        let network = rows
            .iter()
            .find(|row| row["evidence_id"] == network_evidence_id)
            .unwrap();
        assert_eq!(
            network["payload_decode_status"],
            "decoded_and_sidecar_matched"
        );
        assert_eq!(
            network["payload_observation"]["observation"]["activity"]["observation"]["sequence_number"],
            99
        );
    }
}
