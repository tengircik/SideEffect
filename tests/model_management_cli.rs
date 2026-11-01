#[path = "common/model_store.rs"]
mod model_store;

use model_store::SelectedTestModel;

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
