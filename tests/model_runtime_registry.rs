use sideeffect::model_manager::{MAX_MODEL_PATH_BYTES, ModelRegistry, ModelTask};
use std::path::PathBuf;

#[test]
fn registry_migrates_v1_documents_without_runtime_configuration() {
    let old_registry = br#"{
        "schema":"sideeffect.local_model_registry",
        "schema_version":1,
        "accepted_licenses":[],
        "custom_models":[],
        "selected_by_task":{}
    }"#;

    let registry = ModelRegistry::from_json(old_registry).expect("read existing registry shape");
    assert_eq!(registry.schema_version, 2);
    assert!(registry.runtime_by_task.is_empty());
}

#[test]
fn registry_rejects_unknown_fields_and_future_versions() {
    let v1_with_unknown = br#"{
        "schema":"sideeffect.local_model_registry",
        "schema_version":1,
        "accepted_licenses":[],
        "custom_models":[],
        "selected_by_task":{},
        "unexpected":true
    }"#;
    assert!(
        ModelRegistry::from_json(v1_with_unknown)
            .unwrap_err()
            .contains("could not parse model registry v1")
    );

    let future_version = br#"{
        "schema":"sideeffect.local_model_registry",
        "schema_version":3,
        "accepted_licenses":[],
        "custom_models":[],
        "selected_by_task":{},
        "runtime_by_task":{}
    }"#;
    assert!(
        ModelRegistry::from_json(future_version)
            .unwrap_err()
            .contains("unsupported")
    );
}

#[test]
fn configured_runtime_path_is_canonicalized_persisted_and_clearable() {
    // The test executable is used only as an existing regular-file path. It is
    // never launched by these registry operations.
    let selected_path = std::env::current_exe().expect("test executable path");
    let canonical_path = selected_path.canonicalize().expect("canonical test path");
    let mut registry = ModelRegistry::default();

    let stored = registry
        .set_runtime(ModelTask::Explanation, &selected_path)
        .expect("configure existing file path");

    assert_eq!(stored.path, canonical_path);
    assert!(sideeffect::model_manager::verify_configured_runtime(&stored).is_ok());
    assert_eq!(
        registry.runtime_by_task.get(&ModelTask::Explanation),
        Some(&stored)
    );
    assert!(
        registry
            .clear_runtime(ModelTask::Explanation)
            .expect("clear runtime path")
    );
    assert!(
        !registry
            .runtime_by_task
            .contains_key(&ModelTask::Explanation)
    );
    assert!(
        !registry
            .clear_runtime(ModelTask::Explanation)
            .expect("clear absent runtime path")
    );
}

#[test]
fn configured_runtime_path_round_trips_through_bounded_registry_json() {
    let path = std::env::current_exe().expect("test executable path");
    let mut registry = ModelRegistry::default();
    registry
        .set_runtime(ModelTask::QueryPlan, &path)
        .expect("configure existing file path");

    let encoded = registry.to_json().expect("serialize registry");
    assert!(encoded.len() <= sideeffect::model_manager::MAX_REGISTRY_BYTES);
    let decoded = ModelRegistry::from_json(&encoded).expect("parse serialized registry");
    assert_eq!(decoded, registry);
}

#[test]
fn runtime_path_rejects_missing_files_directories_and_overlong_values() {
    let mut registry = ModelRegistry::default();
    let missing = PathBuf::from(format!(
        "{}.sideeffect-runtime-path-that-does-not-exist",
        std::env::current_exe()
            .expect("test executable path")
            .display()
    ));
    let error = registry
        .set_runtime(ModelTask::QueryPlan, &missing)
        .expect_err("missing path is rejected");
    assert!(error.contains("existing local file"));

    let directory = std::env::temp_dir();
    let error = registry
        .set_runtime(ModelTask::QueryPlan, &directory)
        .expect_err("directory path is rejected");
    assert!(error.contains("regular file"));

    let overlong = PathBuf::from("x".repeat(MAX_MODEL_PATH_BYTES + 1));
    let error = registry
        .set_runtime(ModelTask::QueryPlan, &overlong)
        .expect_err("overlong path is rejected before filesystem access");
    assert!(error.contains("path length limit"));
}

#[test]
fn registry_validation_rejects_relative_or_overlong_stored_runtime_paths() {
    let mut registry = ModelRegistry::default();
    registry.runtime_by_task.insert(
        ModelTask::Explanation,
        sideeffect::model_manager::ConfiguredRuntime {
            path: PathBuf::from("relative-runtime"),
            size_bytes: 1,
            sha256: "0".repeat(64),
        },
    );
    assert!(
        registry
            .validate()
            .unwrap_err()
            .contains("runtime metadata is invalid")
    );

    let executable_directory = std::env::current_exe()
        .expect("test executable path")
        .parent()
        .expect("test executable directory")
        .to_owned();
    registry.runtime_by_task.insert(
        ModelTask::Explanation,
        sideeffect::model_manager::ConfiguredRuntime {
            path: executable_directory.join("x".repeat(MAX_MODEL_PATH_BYTES + 1)),
            size_bytes: 1,
            sha256: "0".repeat(64),
        },
    );
    assert!(
        registry
            .validate()
            .unwrap_err()
            .contains("runtime metadata is invalid")
    );
}

#[test]
fn configured_runtime_detects_content_replacement_without_executing_it() {
    use std::fs;

    let path = std::env::temp_dir().join(format!(
        "sideeffect-inert-runtime-{}-{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    fs::write(&path, b"first inert file").expect("write initial inert file");
    let mut registry = ModelRegistry::default();
    let configured = registry
        .set_runtime(ModelTask::Explanation, &path)
        .expect("save runtime file identity");
    assert!(sideeffect::model_manager::verify_configured_runtime(&configured).is_ok());

    fs::write(&path, b"other inert file").expect("replace file with same-sized contents");
    let error = sideeffect::model_manager::verify_configured_runtime(&configured)
        .expect_err("modified runtime must not be silently accepted");
    assert!(error.contains("changed since it was saved"));
    fs::remove_file(path).expect("remove inert test file");
}
