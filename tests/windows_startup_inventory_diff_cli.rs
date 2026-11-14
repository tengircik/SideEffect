use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-windows-startup-diff-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create synthetic startup-diff test directory");
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn startup_state() -> Value {
    json!({
        "schema_version":1,
        "configured":"present",
        "effective":{"status":"unknown","context":null,"evidence":null},
        "observed":{"status":"unknown","capture_interval":null,"evidence":null}
    })
}

fn windows_v10() -> Value {
    let source_ids = [
        "current_user_run_native",
        "current_user_run_once_native",
        "current_user_run_32",
        "current_user_run_once_32",
        "local_machine_run_64",
        "local_machine_run_once_64",
        "local_machine_run_32",
        "local_machine_run_once_32",
        "user_startup",
        "common_startup",
        "service_start_configuration",
        "scheduled_task_triggers",
        "wmi_permanent_event_subscriptions",
    ];
    json!({
        "schema":"sideeffect.windows_startup_inventory",
        "schema_version":10,
        "platform":"windows",
        "scope":"current_user_and_accessible_machine_run_keys_startup_folders_services_with_delayed_auto_start_dependencies_load_order_group_and_trigger_configuration_and_current_token_visible_tasks_and_local_root_subscription_wmi_objects",
        "capture_started_at_unix_ms":1,
        "capture_ended_at_unix_ms":2,
        "status":"complete",
        "sources":source_ids.into_iter().map(|id| json!({
            "id":id,"status":"complete","entries_seen":0,"diagnostics":[]
        })).collect::<Vec<_>>(),
        "registry_entries":[],
        "folder_entries":[],
        "service_entries":[],
        "scheduled_task_entries":[],
        "scheduled_task_actions":[],
        "wmi_event_filters":[],
        "wmi_event_consumers":[],
        "wmi_filter_consumer_bindings":[]
    })
}

fn service(trigger_action: &str, state: &str, raw_state_code: u64) -> Value {
    json!({
        "service_name":"SyntheticService",
        "display_name":"Synthetic Service",
        "start_type":"automatic",
        "start_type_code":2,
        "account":null,
        "binary_path":"C:\\Synthetic\\service.exe",
        "startup_state":startup_state(),
        "service_observation":{"status":"known","state":state,"raw_state_code":raw_state_code},
        "delayed_auto_start":{"status":"observed","value":false},
        "dependencies":{"status":"observed","entries":[]},
        "load_order_group":{"status":"observed","value":null},
        "triggers":{"status":"observed","entries":[{
            "trigger_index":0,
            "trigger_type_code":1,
            "trigger_type":"device_interface_arrival",
            "action_code":if trigger_action == "service_start" { 1 } else { 2 },
            "action":trigger_action,
            "subtype_guid":"1234abcd-5678-9abc-def0-123456789abc",
            "data_items":[]
        }]},
        "evidence":{"source":"EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W","service_index":0}
    })
}

fn task(trigger_enabled: bool, action_path: &str) -> (Value, Value) {
    let task_path = "\\Synthetic\\Task";
    let task_row = json!({
        "task_path":task_path,
        "task_enabled":true,
        "trigger_type":"boot",
        "trigger_enabled":trigger_enabled,
        "logon_user":null,
        "startup_state":startup_state(),
        "evidence":{"source":"Task Scheduler IRegisteredTask/ITaskDefinition/ITrigger","task_index":0,"trigger_index":0}
    });
    let action_row = json!({
        "task_path":task_path,
        "action_index":0,
        "action_type":"exec",
        "action_type_code":0,
        "status":"observed",
        "executable_path":action_path,
        "arguments":null,
        "working_directory":null,
        "startup_state":startup_state(),
        "evidence":{"source":"Task Scheduler IActionCollection/IExecAction","task_index":0,"action_index":0}
    });
    (task_row, action_row)
}

fn with_entries(
    mut doc: Value,
    service_rows: Vec<Value>,
    task_enabled: bool,
    action_path: &str,
) -> Value {
    let (task_row, action_row) = task(task_enabled, action_path);
    doc["service_entries"] = json!(service_rows);
    doc["scheduled_task_entries"] = json!([task_row]);
    doc["scheduled_task_actions"] = json!([action_row]);
    doc["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["id"] == "service_start_configuration")
        .unwrap()["entries_seen"] = json!(service_rows.len());
    doc["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["id"] == "scheduled_task_triggers")
        .unwrap()["entries_seen"] = json!(2);
    doc
}

fn write_document(dir: &Path, name: &str, document: &Value) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, serde_json::to_vec(document).unwrap()).unwrap();
    path
}

fn compare(before: &Path, after: &Path) -> (Value, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(before)
        .arg(after)
        .output()
        .expect("run synthetic Windows startup inventory diff CLI");
    let code = output.status.code().expect("CLI exits with a status code");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "CLI output was not JSON ({error}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(report["schema"], "sideeffect.startup_inventory_diff");
    (report, code)
}

#[test]
fn windows_v10_service_and_task_lifecycle_diffs_keep_configuration_evidence() {
    let temp = TempDirectory::new();
    let empty = windows_v10();
    let installed = with_entries(
        windows_v10(),
        vec![service("service_start", "stopped", 1)],
        true,
        "C:\\Synthetic\\task.exe",
    );
    let changed = with_entries(
        windows_v10(),
        vec![service("service_stop", "stopped", 1)],
        false,
        "C:\\Synthetic\\task-updated.exe",
    );
    let empty_path = write_document(&temp.0, "empty.json", &empty);
    let installed_path = write_document(&temp.0, "installed.json", &installed);
    let changed_path = write_document(&temp.0, "changed.json", &changed);

    let (added, code) = compare(&empty_path, &installed_path);
    assert_eq!(code, 0);
    assert_eq!(added["counts"]["observed_after_only"], 3);
    let categories = added["deltas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|delta| delta["category"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(categories.contains(&"service_configuration"));
    assert!(categories.contains(&"scheduled_task_trigger"));
    assert!(categories.contains(&"scheduled_task_action_sequence"));
    assert!(added["deltas"].as_array().unwrap().iter().all(|delta| {
        delta["after"]["references"]
            .as_array()
            .is_some_and(|refs| !refs.is_empty())
    }));

    let (updated, code) = compare(&installed_path, &changed_path);
    assert_eq!(code, 0);
    assert_eq!(updated["counts"]["changed"], 3);
    let service_change = updated["deltas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|delta| delta["category"] == "service_configuration")
        .unwrap();
    assert_eq!(service_change["changed_fields"], json!(["triggers"]));
    assert_eq!(
        service_change["before"]["references"],
        json!(["/service_entries/0"])
    );
    assert_eq!(
        service_change["after"]["references"],
        json!(["/service_entries/0"])
    );
    let task_change = updated["deltas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|delta| delta["category"] == "scheduled_task_trigger")
        .unwrap();
    assert_eq!(task_change["changed_fields"], json!(["trigger_enabled"]));
    let action_change = updated["deltas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|delta| delta["category"] == "scheduled_task_action_sequence")
        .unwrap();
    assert_eq!(action_change["changed_fields"], json!(["action_sequence"]));

    let (removed, code) = compare(&changed_path, &empty_path);
    assert_eq!(code, 0);
    assert_eq!(removed["counts"]["observed_before_only"], 3);
    assert!(removed["deltas"].as_array().unwrap().iter().all(|delta| {
        delta["before"]["references"]
            .as_array()
            .is_some_and(|refs| !refs.is_empty())
            && delta["after"].is_null()
    }));
}

#[test]
fn windows_v10_inaccessible_source_suppresses_unmatched_service_and_task_presence() {
    let temp = TempDirectory::new();
    let before = with_entries(
        windows_v10(),
        vec![service("service_start", "stopped", 1)],
        true,
        "C:\\Synthetic\\task.exe",
    );
    let mut after = windows_v10();
    after["status"] = json!("partial");
    after["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["id"] == "service_start_configuration")
        .unwrap()["status"] = json!("inaccessible");
    after["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["id"] == "scheduled_task_triggers")
        .unwrap()["status"] = json!("inaccessible");
    let before_path = write_document(&temp.0, "before.json", &before);
    let after_path = write_document(&temp.0, "after.json", &after);
    let (report, code) = compare(&before_path, &after_path);
    assert_eq!(code, 2);
    assert_eq!(report["status"], "partial");
    assert_eq!(report["counts"]["observed_before_only"], 0);
    assert_eq!(
        report["counts"]["unmatched_rows_suppressed_for_incomplete_source"],
        3
    );
    assert!(report["deltas"].as_array().unwrap().is_empty());
}

#[test]
fn windows_v10_scm_state_is_separate_from_startup_configuration_and_observed_activity() {
    let temp = TempDirectory::new();
    let before = with_entries(
        windows_v10(),
        vec![service("service_start", "stopped", 1)],
        true,
        "C:\\Synthetic\\task.exe",
    );
    let after = with_entries(
        windows_v10(),
        vec![service("service_start", "running", 4)],
        true,
        "C:\\Synthetic\\task.exe",
    );
    let before_path = write_document(&temp.0, "state-before.json", &before);
    let after_path = write_document(&temp.0, "state-after.json", &after);
    let (report, code) = compare(&before_path, &after_path);
    assert_eq!(code, 0);
    assert_eq!(report["counts"]["changed"], 1);
    let delta = &report["deltas"][0];
    assert_eq!(delta["category"], "service_configuration");
    assert_eq!(delta["changed_fields"], json!(["service_observation"]));
    assert_eq!(
        before["service_entries"][0]["startup_state"]["observed"]["status"],
        "unknown"
    );
    assert_eq!(
        after["service_entries"][0]["startup_state"]["observed"]["status"],
        "unknown"
    );
    assert_eq!(
        before["scheduled_task_entries"][0]["startup_state"]["observed"]["status"],
        "unknown"
    );
    assert_eq!(
        before["scheduled_task_actions"][0]["startup_state"]["observed"]["status"],
        "unknown"
    );
}
