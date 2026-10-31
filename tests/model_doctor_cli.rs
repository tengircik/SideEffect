#[path = "common/model_store.rs"]
mod model_store;

use model_store::SelectedTestModel;
use std::path::PathBuf;

fn missing_runtime_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "sideeffect-doctor-missing-runtime-{}.exe",
        std::process::id()
    ))
}

struct EmptyModelStore(PathBuf);

impl EmptyModelStore {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-doctor-empty-store-{}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn command(&self) -> std::process::Command {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_sideeffect"));
        command
            .env("XDG_DATA_HOME", &self.0)
            .env("LOCALAPPDATA", &self.0);
        command
    }
}

impl Drop for EmptyModelStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn doctor_checks_model_registration_without_loading_weights_or_running_inference() {
    let model = SelectedTestModel::new("explanation");
    let output = model
        .command()
        .args(["model", "doctor", "--task", "explanation", "--runtime"])
        .arg(missing_runtime_path())
        .args(["--backend", "cpu"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "sideeffect.local_model_doctor");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["readiness"], "blocked_or_incomplete");
    assert_eq!(report["selected_model"]["status"], "verified");
    assert_eq!(report["selected_model"]["id"], model.id());
    assert_eq!(report["selected_model"]["sha256"], model.sha256());
    assert_eq!(report["runtime"]["executable_status"], "unavailable");
    assert_eq!(report["runtime"]["requested_backend"], "cpu");
    assert_eq!(
        report["runtime"]["cuda_device_status"],
        "not_checked_cpu_requested"
    );
    assert_eq!(report["runtime"]["gpu_inference_status"], "not_run");
    assert_eq!(report["inference"], "not_run");
    assert_eq!(report["model_weights_loaded_for_inference"], false);
}

#[test]
fn doctor_reports_missing_task_selection_and_still_checks_runtime_path() {
    let model_store = EmptyModelStore::new();
    let output = model_store
        .command()
        .args(["model", "doctor", "--task", "explanation", "--runtime"])
        .arg(missing_runtime_path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["selected_model"]["status"], "not_ready");
    assert!(
        report["selected_model"]["diagnostic"]
            .as_str()
            .unwrap()
            .contains("no model is selected")
    );
    assert_eq!(report["runtime"]["executable_status"], "unavailable");
    assert_eq!(report["runtime"]["gpu_inference_status"], "not_run");
}

#[test]
fn doctor_rejects_unknown_backend() {
    let model = SelectedTestModel::new("explanation");
    let output = model
        .command()
        .args([
            "model",
            "doctor",
            "--task",
            "explanation",
            "--runtime",
            "runtime.exe",
            "--backend",
            "metal",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("backend must be auto, cpu, or cuda"));
}
