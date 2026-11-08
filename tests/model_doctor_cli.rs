#[path = "common/model_store.rs"]
mod model_store;

use model_store::SelectedTestModel;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_STORE_ID: AtomicU64 = AtomicU64::new(0);
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static NEXT_RUNTIME_ID: AtomicU64 = AtomicU64::new(0);

fn missing_runtime_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "sideeffect-doctor-missing-runtime-{}.exe",
        std::process::id()
    ))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct FakeRuntime {
    directory: PathBuf,
    executable: PathBuf,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl FakeRuntime {
    fn reporting(version: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;

        let id = NEXT_RUNTIME_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "sideeffect-doctor-fake-runtime-dir-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let executable = directory.join("runtime");
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '%s\\n' '{version}'; exit 0; fi\nif [ \"$1\" = \"--list-devices\" ]; then printf 'CUDA0: synthetic test device\\n'; exit 0; fi\nexit 64\n"
        );
        std::fs::write(&executable, script).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            directory,
            executable,
        }
    }

    fn path(&self) -> &std::path::Path {
        &self.executable
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for FakeRuntime {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

struct EmptyModelStore(PathBuf);

impl EmptyModelStore {
    fn new() -> Self {
        loop {
            let id = NEXT_STORE_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-doctor-empty-store-{}-{id}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create isolated model store: {error}"),
            }
        }
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
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["task"], "explanation");
    assert_eq!(report["supported_here"], true);
    assert_eq!(report["readiness"], "blocked_or_incomplete");
    assert_eq!(report["selected_model"]["status"], "verified");
    assert_eq!(report["selected_model"]["id"], model.id());
    assert_eq!(report["selected_model"]["sha256"], model.sha256());
    assert_eq!(report["runtime"]["executable_status"], "unavailable");
    assert_eq!(
        report["runtime"]["expected_source_revision"],
        "19cce6919992fdffd92e0ac152caaf1e2b8f254e"
    );
    assert_eq!(
        report["runtime"]["expected_version_contract"],
        "pinned commit reported by --version"
    );
    assert_eq!(report["runtime"]["requested_backend"], "cpu");
    assert_eq!(
        report["runtime"]["device_check_status"],
        "not_applicable_cpu_requested"
    );
    assert_eq!(report["runtime"]["gpu_inference_status"], "not_run");
    assert_eq!(report["inference_not_run"], true);
    assert_eq!(report["weights_not_loaded"], true);
    assert_eq!(report["quality_assessment_performed_by_doctor"], false);
    assert!(report.get("quality_unassessed").is_none());
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
    assert_eq!(report["inference_not_run"], true);
    assert_eq!(report["weights_not_loaded"], true);
    assert_eq!(report["quality_assessment_performed_by_doctor"], false);
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn doctor_checks_evidence_prefix_and_query_exact_version_contracts() {
    use sideeffect::local_model::RUNTIME_VERSION_PREFIX;
    use sideeffect::local_query_plan::LOCAL_QUERY_PLAN_RUNTIME_VERSION;

    for (task, expected_version, version_contract, verified_status) in [
        (
            "evidence",
            format!("{RUNTIME_VERSION_PREFIX} (build 6000)"),
            RUNTIME_VERSION_PREFIX.to_owned(),
            "verified_version_prefix",
        ),
        (
            "query",
            LOCAL_QUERY_PLAN_RUNTIME_VERSION.to_owned(),
            LOCAL_QUERY_PLAN_RUNTIME_VERSION.to_owned(),
            "verified_exact_version",
        ),
    ] {
        let model = SelectedTestModel::new(task);
        let runtime = FakeRuntime::reporting(&expected_version);
        let output = model
            .command()
            .args(["model", "doctor", "--task", task, "--runtime"])
            .arg(runtime.path())
            .output()
            .unwrap();

        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["schema_version"], 2);
        assert_eq!(report["task"], task);
        assert_eq!(report["supported_here"], true);
        assert_eq!(
            report["readiness"],
            "registration_and_runtime_checks_passed"
        );
        assert_eq!(report["runtime"]["executable_status"], verified_status);
        assert_eq!(
            report["runtime"]["expected_version_contract"],
            version_contract
        );
        assert_eq!(report["runtime"]["device_check_status"], "not_applicable");
        assert_eq!(report["runtime"]["gpu_inference_status"], "not_run");
        assert_eq!(report["inference_not_run"], true);
        assert_eq!(report["weights_not_loaded"], true);
        assert_eq!(report["quality_assessment_performed_by_doctor"], false);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn doctor_rejects_nonmatching_evidence_and_query_runtime_versions() {
    for (task, wrong_version) in [
        ("evidence", "version: 5999 (4762ad731)"),
        ("query", "0.7.0-dev (build 11938, commit 19cce6919-extra)"),
    ] {
        let model = SelectedTestModel::new(task);
        let runtime = FakeRuntime::reporting(wrong_version);
        let output = model
            .command()
            .args(["model", "doctor", "--task", task, "--runtime"])
            .arg(runtime.path())
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(2));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["runtime"]["executable_status"],
            "version_check_failed"
        );
        assert_eq!(report["runtime"]["device_check_status"], "not_applicable");
        assert_eq!(report["readiness"], "blocked_or_incomplete");
    }
}

#[cfg(windows)]
#[test]
fn doctor_reports_evidence_and_query_as_unsupported_without_device_checks() {
    let model_store = EmptyModelStore::new();
    for task in ["evidence", "query"] {
        let output = model_store
            .command()
            .args([
                "model",
                "doctor",
                "--task",
                task,
                "--runtime",
                "unused-runtime.exe",
            ])
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(2));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["schema_version"], 2);
        assert_eq!(report["task"], task);
        assert_eq!(report["supported_here"], false);
        assert_eq!(
            report["runtime"]["executable_status"],
            "unsupported_platform"
        );
        let expected_contract = match task {
            "evidence" => "version: 6000 (4762ad731)",
            "query" => "0.7.0-dev (build 11938, commit 19cce6919)",
            _ => unreachable!(),
        };
        assert_eq!(
            report["runtime"]["expected_version_contract"],
            expected_contract
        );
        assert!(
            report["runtime"]["executable_diagnostic"]
                .as_str()
                .unwrap()
                .contains("Linux x86_64 only")
        );
        assert_eq!(report["runtime"]["device_check_status"], "not_applicable");
        assert_eq!(report["inference_not_run"], true);
        assert_eq!(report["weights_not_loaded"], true);
        assert_eq!(report["quality_assessment_performed_by_doctor"], false);
    }
}
