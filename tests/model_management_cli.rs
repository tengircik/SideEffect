#[path = "common/model_store.rs"]
mod model_store;

use model_store::SelectedTestModel;
use std::fs::File;
use std::path::Path;

const EXPLANATION_CATALOG_ID: &str = "explanation-qwen3.5-4b-q4-k-m";

fn run_setup(model: &SelectedTestModel, runtime_path: Option<&Path>) -> std::process::Output {
    let mut command = model.command();
    command.args(["model", "setup", EXPLANATION_CATALOG_ID]);
    if let Some(runtime_path) = runtime_path {
        command.arg("--runtime").arg(runtime_path);
    }
    command.output().unwrap()
}

#[test]
fn model_list_reports_platform_support_and_selection_for_catalog_and_custom_models() {
    let model = SelectedTestModel::new("explanation");
    let output = model.command().args(["model", "list"]).output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("platform: Linux x86_64 only ("));
    assert!(stdout.contains("supported here)"));
    assert!(stdout.contains("selected for task: no"));
    assert!(stdout.contains("explanation (supported here; selected)"));
    assert!(stdout.contains("license status: not provided"));
    assert!(stdout.contains("evaluation: not assessed; accuracy recommendation: none"));
}

#[test]
fn model_show_reports_catalog_platform_support_and_selection_as_json() {
    let model = SelectedTestModel::new("explanation");
    let output = model
        .command()
        .args(["model", "show", "evidence-qwen2.5-0.5b-q4-0"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["task_support"]["task"], "evidence");
    assert_eq!(
        value["task_support"]["supported_here"],
        cfg!(all(target_os = "linux", target_arch = "x86_64"))
    );
    assert_eq!(value["selected_for_task"], false);
    assert_eq!(value["recommended_for_accuracy"], false);
}

#[test]
fn model_show_reports_custom_model_task_selection_and_unverified_metadata() {
    let model = SelectedTestModel::new("explanation");
    let output = model
        .command()
        .args(["model", "show", model.id()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["id"], model.id());
    assert_eq!(value["sha256"], model.sha256());
    assert_eq!(value["task_support"][0]["task"], "explanation");
    assert_eq!(value["task_support"][0]["supported_here"], true);
    assert_eq!(value["task_support"][0]["selected"], true);
    assert_eq!(value["license_status"], "not provided");
    assert_eq!(value["evaluation_status"], "not assessed");
    assert_eq!(value["recommended_for_accuracy"], false);
}

#[test]
fn setup_runtime_path_is_validated_before_license_prompt_without_persisting_on_cancel() {
    let model = SelectedTestModel::new("explanation");
    let runtime_path = std::env::current_exe()
        .expect("test executable")
        .canonicalize()
        .expect("canonical test executable path");
    let output = run_setup(&model, Some(&runtime_path));
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("Existing runtime file:"), "{stdout}");
    assert!(
        stdout.contains("It will not be executed or downloaded"),
        "{stdout}"
    );
    assert!(stdout.contains("type ACCEPT Apache-2.0"), "{stdout}");
    assert!(
        stderr.contains("license acceptance was not confirmed"),
        "{stderr}"
    );

    // EOF at the license prompt cancels before the installer can issue a
    // request. Runtime configuration is persisted only after setup succeeds.
    let show = model
        .command()
        .args(["model", "runtime", "show", "explanation"])
        .output()
        .unwrap();
    assert!(show.status.success());
    assert!(String::from_utf8_lossy(&show.stdout).contains("not configured"));
}

#[test]
fn setup_rejects_missing_invalid_and_oversized_runtime_files_before_license_prompt() {
    let model = SelectedTestModel::new("explanation");
    let missing = model.data_root().join("missing-runtime.exe");
    let missing_output = run_setup(&model, Some(&missing));
    assert_eq!(missing_output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing_output.stderr).contains("existing local file"));
    assert!(!String::from_utf8_lossy(&missing_output.stdout).contains("type ACCEPT"));

    let directory_output = run_setup(&model, Some(model.data_root()));
    assert_eq!(directory_output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&directory_output.stderr).contains("plain regular file"));
    assert!(!String::from_utf8_lossy(&directory_output.stdout).contains("type ACCEPT"));

    let oversized = model.data_root().join("oversized-runtime.bin");
    File::create(&oversized)
        .expect("create sparse oversized runtime fixture")
        .set_len(sideeffect::model_manager::MAX_RUNTIME_FILE_BYTES + 1)
        .expect("extend sparse oversized runtime fixture");
    let oversized_output = run_setup(&model, Some(&oversized));
    assert_eq!(oversized_output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&oversized_output.stderr)
            .contains("exceeds the configured size limit")
    );
    assert!(!String::from_utf8_lossy(&oversized_output.stdout).contains("type ACCEPT"));

    let missing_argument = model
        .command()
        .args(["model", "setup", EXPLANATION_CATALOG_ID, "--runtime"])
        .output()
        .unwrap();
    assert_eq!(missing_argument.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&missing_argument.stderr)
            .contains("requires an existing runtime path")
    );
    assert!(!String::from_utf8_lossy(&missing_argument.stdout).contains("type ACCEPT"));
}

#[test]
fn setup_without_runtime_keeps_the_existing_license_prompt_flow() {
    let model = SelectedTestModel::new("explanation");
    let output = run_setup(&model, None);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("Evaluation note:"), "{stdout}");
    assert!(stdout.contains("type ACCEPT Apache-2.0"), "{stdout}");
    assert!(!stdout.contains("Existing runtime file:"), "{stdout}");
    assert!(
        stderr.contains("license acceptance was not confirmed"),
        "{stderr}"
    );

    let show = model
        .command()
        .args(["model", "runtime", "show", "explanation"])
        .output()
        .unwrap();
    assert!(show.status.success());
    assert!(String::from_utf8_lossy(&show.stdout).contains("not configured"));
}
