//! Conservative, evidence-linked comparison of Windows scheduled-task actions
//! with process-start rows in a saved ETW capture.

use crate::fingerprint::sha256_hex;
use crate::windows_runtime::{
    CollectionStatus, DecodedProcessPayload, ProcessDecodeStatus, WINDOWS_RUNTIME_CAPTURE_SCHEMA,
    WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION, inspect_windows_runtime_bytes,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

pub const WINDOWS_STARTUP_INVENTORY_SCHEMA: &str = "sideeffect.windows_startup_inventory";
pub const WINDOWS_STARTUP_INVENTORY_SCHEMA_VERSION: u32 = 4;
const MAX_STARTUP_DOCUMENT_BYTES: usize = crate::limits::MAX_REPORT_BYTES;
const MAX_TASK_ACTIONS: usize = 8_192;
const MAX_ACTION_METADATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_ACTION_FIELD_BYTES: usize = 65_536;
const MAX_JSON_VALUE_NODES: usize = 1_000_000;
const PROCESS_PROVIDER_GUID: &str = "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}";

#[derive(Clone, Debug, Serialize)]
pub struct WindowsAssociatedBehaviorSummary {
    pub schema: &'static str,
    pub schema_version: u32,
    pub algorithm: WindowsAssociationAlgorithm,
    pub platform_adapter: &'static str,
    pub capture_completeness: &'static str,
    pub status: &'static str,
    pub association_status: &'static str,
    pub inputs: WindowsAssociatedBehaviorInputs,
    pub summary: WindowsAssociatedBehaviorCounts,
    pub diagnostics: Vec<&'static str>,
    pub limitations: Vec<&'static str>,
    pub associations: Vec<WindowsAssociatedBehavior>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsAssociationAlgorithm {
    pub id: &'static str,
    pub version: u32,
    pub basis: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsAssociatedBehaviorInputs {
    pub startup_inventory: WindowsAssociatedInputIdentity,
    pub runtime_capture: WindowsAssociatedInputIdentity,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsAssociatedInputIdentity {
    pub source_format: &'static str,
    pub sha256: String,
    pub source_status: String,
    pub capture_completeness: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsAssociatedBehaviorCounts {
    pub scheduled_task_action_count: usize,
    pub supported_absolute_exec_action_count: usize,
    pub unsupported_or_incomplete_action_count: usize,
    pub process_start_event_count: usize,
    pub unsupported_process_start_event_count: usize,
    pub candidate_path_group_count: usize,
    pub candidate_action_reference_count: usize,
    pub candidate_process_event_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsAssociatedBehavior {
    pub status: &'static str,
    pub confidence: &'static str,
    pub basis: &'static str,
    pub executable_path: String,
    pub multiple_startup_references: bool,
    pub multiple_runtime_observations: bool,
    pub startup_evidence: Vec<WindowsStartupActionEvidenceReference>,
    pub runtime_evidence: Vec<WindowsProcessStartEvidenceReference>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsStartupActionEvidenceReference {
    pub source: String,
    pub task_index: usize,
    pub action_index: usize,
    pub task_path: Option<String>,
    pub executable_path: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsProcessStartEvidenceReference {
    pub capture_sha256: String,
    pub record_ordinal: u64,
    pub process_id: u32,
    pub image_file_name: String,
}

struct StartupInput {
    status: String,
    actions: Vec<StartupAction>,
}

struct StartupAction {
    task_path: Option<String>,
    action_index: usize,
    action_type: String,
    status: String,
    executable_path: Option<String>,
    evidence_source: String,
    task_index: usize,
    evidence_action_index: usize,
}

/// Compare only saved, bounded Windows startup and ETW documents.
///
/// The output is a candidate view. It never claims that a scheduled task ran or
/// caused an observed process to start.
pub fn summarize_windows_startup_behavior(
    startup_bytes: &[u8],
    runtime_bytes: &[u8],
) -> Result<WindowsAssociatedBehaviorSummary, String> {
    let startup = parse_startup_inventory(startup_bytes)?;
    let runtime = inspect_windows_runtime_bytes(runtime_bytes)?;
    if runtime.schema != WINDOWS_RUNTIME_CAPTURE_SCHEMA
        || runtime.schema_version != WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION
    {
        return Err("unsupported Windows runtime capture schema".to_owned());
    }

    let startup_sha256 = sha256_hex(startup_bytes);
    let capture_sha256 = sha256_hex(runtime_bytes);
    let scheduled_task_action_count = startup.actions.len();
    let startup_status = startup.status;
    let mut action_groups = BTreeMap::<String, Vec<WindowsStartupActionEvidenceReference>>::new();
    let mut supported_action_count = 0usize;
    let mut unsupported_action_count = 0usize;
    for action in startup.actions {
        if action.status != "observed"
            || action.action_type != "exec"
            || action.evidence_action_index != action.action_index
        {
            unsupported_action_count += 1;
            continue;
        }
        let Some(path) = action.executable_path else {
            unsupported_action_count += 1;
            continue;
        };
        if !is_drive_rooted_windows_path(&path) {
            unsupported_action_count += 1;
            continue;
        }
        supported_action_count += 1;
        action_groups.entry(path.clone()).or_default().push(
            WindowsStartupActionEvidenceReference {
                source: action.evidence_source,
                task_index: action.task_index,
                action_index: action.action_index,
                task_path: action.task_path,
                executable_path: path,
            },
        );
    }

    let mut process_groups = BTreeMap::<String, Vec<WindowsProcessStartEvidenceReference>>::new();
    let mut process_start_event_count = 0usize;
    let mut unsupported_process_start_event_count = 0usize;
    for event in &runtime.events {
        if event.event_kind != "process_start"
            || event.provider_guid != PROCESS_PROVIDER_GUID
            || event.event_id != 0
            || event.opcode != 1
        {
            continue;
        }
        process_start_event_count += 1;
        let Some(decoded) = event.payload_decoding.as_ref() else {
            unsupported_process_start_event_count += 1;
            continue;
        };
        if !is_supported_process_start(decoded, event.event_version) {
            unsupported_process_start_event_count += 1;
            continue;
        }
        let (Some(process_id), Some(image_file_name)) =
            (decoded.process_id, decoded.image_file_name.as_ref())
        else {
            unsupported_process_start_event_count += 1;
            continue;
        };
        if !is_drive_rooted_windows_path(image_file_name) {
            unsupported_process_start_event_count += 1;
            continue;
        }
        process_groups
            .entry(image_file_name.clone())
            .or_default()
            .push(WindowsProcessStartEvidenceReference {
                capture_sha256: capture_sha256.clone(),
                record_ordinal: event.record_ordinal,
                process_id,
                image_file_name: image_file_name.clone(),
            });
    }

    let mut associations = Vec::new();
    let mut action_reference_count = 0usize;
    let mut process_event_count = 0usize;
    for (path, startup_evidence) in action_groups {
        let Some(runtime_evidence) = process_groups.remove(&path) else {
            continue;
        };
        action_reference_count = action_reference_count.saturating_add(startup_evidence.len());
        process_event_count = process_event_count.saturating_add(runtime_evidence.len());
        associations.push(WindowsAssociatedBehavior {
            status: "candidate_match",
            confidence: "limited_candidate",
            basis: "exact_equality_of_drive_rooted_windows_path_strings",
            executable_path: path,
            multiple_startup_references: startup_evidence.len() > 1,
            multiple_runtime_observations: runtime_evidence.len() > 1,
            startup_evidence,
            runtime_evidence,
        });
    }

    let partial = startup_status != "complete"
        || runtime.collection_status != CollectionStatus::Complete
        || runtime.event_loss.events_lost > 0
        || runtime.event_loss.log_buffers_lost > 0
        || runtime.event_loss.real_time_buffers_lost > 0
        || !runtime.event_loss.loss_statistics_available
        || !runtime.event_loss.final_snapshot_available
        || !runtime.diagnostics.is_empty()
        || unsupported_action_count > 0
        || unsupported_process_start_event_count > 0;
    let mut diagnostics = Vec::new();
    if startup_status != "complete" {
        diagnostics.push("startup_inventory_is_not_complete");
    }
    if runtime.collection_status != CollectionStatus::Complete || !runtime.diagnostics.is_empty() {
        diagnostics.push("runtime_capture_is_partial_or_has_diagnostics");
    }
    if runtime.event_loss.events_lost > 0
        || runtime.event_loss.log_buffers_lost > 0
        || runtime.event_loss.real_time_buffers_lost > 0
    {
        diagnostics.push("etw_loss_was_reported");
    }
    if !runtime.event_loss.loss_statistics_available || !runtime.event_loss.final_snapshot_available
    {
        diagnostics.push("etw_loss_statistics_are_incomplete");
    }
    if unsupported_action_count > 0 {
        diagnostics.push("unsupported_or_incomplete_task_actions_were_excluded");
    }
    if unsupported_process_start_event_count > 0 {
        diagnostics.push("unsupported_process_start_payloads_or_paths_were_excluded");
    }
    if associations.is_empty() {
        diagnostics.push("no_exact_supported_path_pair_was_observed");
    }
    diagnostics.push("nonmatches_are_not_evidence_of_nonexecution");

    Ok(WindowsAssociatedBehaviorSummary {
        schema: "sideeffect.windows_associated_behavior_summary",
        schema_version: 1,
        algorithm: WindowsAssociationAlgorithm {
            id: "windows_task_action_process_image_exact_path",
            version: 1,
            basis: "exact_equality_of_drive_rooted_windows_path_strings",
        },
        platform_adapter: "windows_startup_inventory_v4_windows_runtime_capture_v3",
        capture_completeness: "unknown",
        status: if partial { "partial" } else { "complete" },
        association_status: if associations.is_empty() {
            "insufficient_evidence"
        } else {
            "candidate_match"
        },
        inputs: WindowsAssociatedBehaviorInputs {
            startup_inventory: WindowsAssociatedInputIdentity {
                source_format: "sideeffect.windows_startup_inventory_v4",
                sha256: startup_sha256,
                source_status: startup_status,
                capture_completeness: "unknown",
            },
            runtime_capture: WindowsAssociatedInputIdentity {
                source_format: "sideeffect.windows_runtime_capture_v3",
                sha256: capture_sha256,
                source_status: match runtime.collection_status {
                    CollectionStatus::Complete => "complete",
                    CollectionStatus::Partial => "partial",
                }
                .to_owned(),
                capture_completeness: "unknown",
            },
        },
        summary: WindowsAssociatedBehaviorCounts {
            scheduled_task_action_count,
            supported_absolute_exec_action_count: supported_action_count,
            unsupported_or_incomplete_action_count: unsupported_action_count,
            process_start_event_count,
            unsupported_process_start_event_count,
            candidate_path_group_count: associations.len(),
            candidate_action_reference_count: action_reference_count,
            candidate_process_event_count: process_event_count,
        },
        diagnostics,
        limitations: vec![
            "Only observed Exec scheduled-task actions with drive-rooted literal paths are considered.",
            "Only decoded process-start events with a drive-rooted ImageFileName string are considered; no basename matching, path normalization, environment expansion, or device-path conversion is performed.",
            "A candidate path match does not establish that a task ran, launched the observed process, or caused any behavior.",
            "The Windows ETW capture is system-wide for a bounded window; target and descendant attribution is not established.",
            "The two inputs are independent snapshots; missing matches do not establish absence or non-execution.",
            "Input fingerprints identify supplied bytes but do not authenticate their origin or contents.",
        ],
        associations,
    })
}

fn parse_startup_inventory(bytes: &[u8]) -> Result<StartupInput, String> {
    if bytes.len() > MAX_STARTUP_DOCUMENT_BYTES {
        return Err(format!(
            "Windows startup inventory exceeds the {MAX_STARTUP_DOCUMENT_BYTES} byte limit"
        ));
    }
    let value = crate::windows_runtime::parse_strict_json_value(bytes, MAX_JSON_VALUE_NODES)
        .map_err(|error| format!("invalid Windows startup inventory JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "Windows startup inventory must be a JSON object".to_owned())?;
    if object.get("schema").and_then(Value::as_str) != Some(WINDOWS_STARTUP_INVENTORY_SCHEMA)
        || object.get("schema_version").and_then(Value::as_u64)
            != Some(u64::from(WINDOWS_STARTUP_INVENTORY_SCHEMA_VERSION))
        || object.get("platform").and_then(Value::as_str) != Some("windows")
    {
        return Err("unsupported Windows startup inventory schema or platform".to_owned());
    }
    const REQUIRED_FIELDS: [&str; 13] = [
        "schema",
        "schema_version",
        "platform",
        "scope",
        "capture_started_at_unix_ms",
        "capture_ended_at_unix_ms",
        "status",
        "sources",
        "registry_entries",
        "folder_entries",
        "service_entries",
        "scheduled_task_entries",
        "scheduled_task_actions",
    ];
    if object.len() != REQUIRED_FIELDS.len()
        || object
            .keys()
            .any(|key| !REQUIRED_FIELDS.contains(&key.as_str()))
    {
        return Err(
            "Windows startup inventory v4 has missing or unknown top-level fields".to_owned(),
        );
    }
    bounded_string(object.get("scope"), MAX_ACTION_FIELD_BYTES, "scope")?;
    let capture_started = object
        .get("capture_started_at_unix_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Windows startup inventory has an invalid start timestamp".to_owned())?;
    let capture_ended = object
        .get("capture_ended_at_unix_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Windows startup inventory has an invalid end timestamp".to_owned())?;
    if capture_started > capture_ended {
        return Err("Windows startup inventory has an invalid capture interval".to_owned());
    }
    for (field, max_entries) in [
        ("sources", 64usize),
        ("registry_entries", 8192),
        ("folder_entries", 8192),
        ("service_entries", 8192),
        ("scheduled_task_entries", 8192),
    ] {
        let entries = object
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("Windows startup inventory {field} must be an array"))?;
        if entries.len() > max_entries {
            return Err(format!(
                "Windows startup inventory {field} exceeds the {max_entries} entry limit"
            ));
        }
        for (index, entry) in entries.iter().enumerate() {
            validate_inventory_row(field, index, entry)?;
        }
    }
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| "Windows startup inventory has no valid status".to_owned())?;
    if !matches!(
        status,
        "complete"
            | "partial"
            | "not_present"
            | "inaccessible"
            | "unavailable"
            | "unsupported"
            | "not_checked"
            | "error"
    ) {
        return Err("Windows startup inventory has an unsupported status".to_owned());
    }
    let actions = object
        .get("scheduled_task_actions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "Windows startup inventory has no scheduled_task_actions array".to_owned()
        })?;
    if actions.len() > MAX_TASK_ACTIONS {
        return Err(format!(
            "Windows scheduled-task action count exceeds the {MAX_TASK_ACTIONS} entry limit"
        ));
    }
    let mut aggregate_bytes = 0usize;
    let mut parsed_actions = Vec::with_capacity(actions.len());
    for (index, value) in actions.iter().enumerate() {
        let action = value
            .as_object()
            .ok_or_else(|| format!("scheduled-task action {index} must be an object"))?;
        validate_object_fields(
            action,
            &[
                "action_index",
                "action_type",
                "action_type_code",
                "status",
                "evidence",
            ],
            &[
                "task_path",
                "executable_path",
                "arguments",
                "working_directory",
            ],
            &format!("scheduled-task action {index}"),
        )?;
        let action_index = action
            .get("action_index")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| format!("scheduled-task action {index} has an invalid action_index"))?;
        let action_type = bounded_string(
            action.get("action_type"),
            MAX_ACTION_FIELD_BYTES,
            "action_type",
        )?;
        require_enum(
            action.get("action_type").unwrap(),
            &[
                "exec",
                "com_handler",
                "send_email",
                "show_message",
                "unknown",
            ],
            "action_type",
        )?;
        let action_status = bounded_string(action.get("status"), 32, "status")?;
        if !matches!(
            action_status.as_str(),
            "observed" | "unsupported" | "partial"
        ) {
            return Err(format!(
                "scheduled-task action {index} has an unsupported status"
            ));
        }
        let evidence = action
            .get("evidence")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("scheduled-task action {index} has no evidence object"))?;
        validate_object_fields(
            evidence,
            &["source", "task_index", "action_index"],
            &[],
            &format!("scheduled-task action {index} evidence"),
        )?;
        let evidence_source = bounded_string(
            evidence.get("source"),
            MAX_ACTION_FIELD_BYTES,
            "evidence.source",
        )?;
        let task_index = evidence
            .get("task_index")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| {
                format!("scheduled-task action {index} has an invalid evidence task_index")
            })?;
        let evidence_action_index = evidence
            .get("action_index")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| {
                format!("scheduled-task action {index} has an invalid evidence action_index")
            })?;
        let task_path =
            optional_bounded_string(action.get("task_path"), MAX_ACTION_FIELD_BYTES, "task_path")?;
        let executable_path = optional_bounded_string(
            action.get("executable_path"),
            MAX_ACTION_FIELD_BYTES,
            "executable_path",
        )?;
        let action_type_code = optional_i64(action.get("action_type_code"), "action_type_code")?;
        if action_type_code.is_some_and(|code| i32::try_from(code).is_err()) {
            return Err(format!(
                "scheduled-task action {index} has an invalid action_type_code"
            ));
        }
        let type_code_consistent = match (action_type.as_str(), action_type_code) {
            ("exec", Some(0)) => true,
            ("com_handler", Some(5)) => true,
            ("send_email", Some(6)) => true,
            ("show_message", Some(7)) => true,
            ("unknown", None) => true,
            ("unknown", Some(code)) => ![0, 5, 6, 7].contains(&code),
            _ => false,
        };
        let status_consistent = match action_type.as_str() {
            "exec" => matches!(action_status.as_str(), "observed" | "partial"),
            "unknown" if action_type_code.is_none() => action_status == "partial",
            _ => action_status == "unsupported",
        };
        if !type_code_consistent || !status_consistent {
            return Err(format!(
                "scheduled-task action {index} has inconsistent type, code, or status fields"
            ));
        }
        let arguments =
            optional_bounded_string(action.get("arguments"), MAX_ACTION_FIELD_BYTES, "arguments")?;
        let working_directory = optional_bounded_string(
            action.get("working_directory"),
            MAX_ACTION_FIELD_BYTES,
            "working_directory",
        )?;
        for field in [&action_type, &action_status, &evidence_source]
            .into_iter()
            .chain(task_path.iter())
            .chain(executable_path.iter())
            .chain(arguments.iter())
            .chain(working_directory.iter())
        {
            aggregate_bytes = aggregate_bytes
                .checked_add(field.len())
                .filter(|total| *total <= MAX_ACTION_METADATA_BYTES)
                .ok_or_else(|| {
                    "Windows startup metadata exceeds the 8 MiB copied-field budget".to_owned()
                })?;
        }
        parsed_actions.push(StartupAction {
            task_path,
            action_index,
            action_type,
            status: action_status,
            executable_path,
            evidence_source,
            task_index,
            evidence_action_index,
        });
    }
    Ok(StartupInput {
        status: status.to_owned(),
        actions: parsed_actions,
    })
}

fn bounded_string(value: Option<&Value>, max: usize, label: &str) -> Result<String, String> {
    let value = value
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Windows startup inventory {label} must be a string"))?;
    if value.len() > max {
        return Err(format!(
            "Windows startup inventory {label} exceeds the {max} byte limit"
        ));
    }
    Ok(value.to_owned())
}

fn optional_i64(value: Option<&Value>, label: &str) -> Result<Option<i64>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| format!("Windows startup inventory {label} must be an integer or null")),
    }
}

fn validate_object_fields(
    object: &serde_json::Map<String, Value>,
    required: &[&str],
    optional: &[&str],
    label: &str,
) -> Result<(), String> {
    if required.iter().any(|field| !object.contains_key(*field))
        || object
            .keys()
            .any(|field| !required.contains(&field.as_str()) && !optional.contains(&field.as_str()))
    {
        return Err(format!("{label} has missing or unknown fields"));
    }
    Ok(())
}

fn validate_inventory_row(field: &str, index: usize, value: &Value) -> Result<(), String> {
    let label = format!("Windows startup inventory {field}[{index}]");
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?;
    let (required, optional): (&[&str], &[&str]) = match field {
        "sources" => (
            &["id", "status", "entries_seen", "diagnostics"],
            &[
                "registry_hive",
                "registry_key",
                "registry_view",
                "location_path",
                "location_path_utf16_hex",
            ],
        ),
        "registry_entries" => (
            &[
                "registry_key",
                "hive",
                "registry_view",
                "trigger",
                "value_name",
                "value_type",
                "evidence",
            ],
            &["command", "command_utf16_hex"],
        ),
        "folder_entries" => (
            &[
                "folder_scope",
                "trigger",
                "display_path",
                "path_utf16_hex",
                "kind",
                "evidence",
            ],
            &[],
        ),
        "service_entries" => (
            &[
                "service_name",
                "display_name",
                "start_type",
                "start_type_code",
                "evidence",
            ],
            &["account", "binary_path"],
        ),
        "scheduled_task_entries" => (
            &[
                "task_path",
                "task_enabled",
                "trigger_type",
                "trigger_enabled",
                "evidence",
            ],
            &["logon_user"],
        ),
        _ => return Err("unsupported Windows inventory array".to_owned()),
    };
    validate_object_fields(object, required, optional, &label)?;
    match field {
        "sources" => {
            bounded_string(object.get("id"), MAX_ACTION_FIELD_BYTES, "source.id")?;
            valid_startup_status(object.get("status"), "source.status")?;
            unsigned_integer(object.get("entries_seen"), "source.entries_seen")?;
            for name in [
                "registry_hive",
                "registry_key",
                "registry_view",
                "location_path",
                "location_path_utf16_hex",
            ] {
                if object.contains_key(name) {
                    optional_bounded_string(object.get(name), MAX_ACTION_FIELD_BYTES, name)?;
                }
            }
            if let Some(view) = object.get("registry_view") {
                require_enum(
                    view,
                    &["native", "wow64_32", "wow64_64"],
                    "source.registry_view",
                )?;
            }
            if let Some(hive) = object.get("registry_hive") {
                require_enum(
                    hive,
                    &["HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE"],
                    "source.registry_hive",
                )?;
            }
            let diagnostics = object
                .get("diagnostics")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{label}.diagnostics must be an array"))?;
            if diagnostics.len() > 8192 {
                return Err(format!("{label}.diagnostics exceeds the entry limit"));
            }
            for (diagnostic_index, diagnostic) in diagnostics.iter().enumerate() {
                let diagnostic_label = format!("{label}.diagnostics[{diagnostic_index}]");
                let diagnostic = diagnostic
                    .as_object()
                    .ok_or_else(|| format!("{diagnostic_label} must be an object"))?;
                validate_object_fields(
                    diagnostic,
                    &["code", "message"],
                    &["item_index", "win32_error", "hresult"],
                    &diagnostic_label,
                )?;
                bounded_string(
                    diagnostic.get("code"),
                    MAX_ACTION_FIELD_BYTES,
                    "diagnostic.code",
                )?;
                bounded_string(
                    diagnostic.get("message"),
                    MAX_ACTION_FIELD_BYTES,
                    "diagnostic.message",
                )?;
                for number in ["item_index", "win32_error", "hresult"] {
                    if diagnostic.contains_key(number) {
                        optional_unsigned_integer(diagnostic.get(number), number)?;
                    }
                }
            }
        }
        "registry_entries" => {
            for name in [
                "registry_key",
                "hive",
                "registry_view",
                "trigger",
                "value_name",
                "value_type",
            ] {
                bounded_string(object.get(name), MAX_ACTION_FIELD_BYTES, name)?;
            }
            require_enum(
                object.get("registry_view").unwrap(),
                &["native", "wow64_32", "wow64_64"],
                "registry_view",
            )?;
            require_enum(
                object.get("hive").unwrap(),
                &["HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE"],
                "hive",
            )?;
            require_enum(
                object.get("trigger").unwrap(),
                &["user_logon", "user_logon_once"],
                "trigger",
            )?;
            require_enum(
                object.get("value_type").unwrap(),
                &["REG_SZ", "REG_EXPAND_SZ", "unsupported"],
                "value_type",
            )?;
            let evidence = object
                .get("evidence")
                .and_then(Value::as_object)
                .ok_or_else(|| format!("{label}.evidence must be an object"))?;
            require_enum(
                evidence
                    .get("registry_view")
                    .ok_or_else(|| format!("{label}.evidence is missing registry_view"))?,
                &["native", "wow64_32", "wow64_64"],
                "evidence.registry_view",
            )?;
            require_enum(
                evidence
                    .get("hive")
                    .ok_or_else(|| format!("{label}.evidence is missing hive"))?,
                &["HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE"],
                "evidence.hive",
            )?;
            for name in ["command", "command_utf16_hex"] {
                if object.contains_key(name) {
                    optional_bounded_string(object.get(name), MAX_ACTION_FIELD_BYTES, name)?;
                }
            }
            validate_evidence(
                object.get("evidence"),
                &[
                    "source",
                    "hive",
                    "registry_view",
                    "registry_key",
                    "value_index",
                    "value_name",
                    "registry_type",
                ],
                &[],
                &label,
            )?;
        }
        "folder_entries" => {
            for name in [
                "folder_scope",
                "trigger",
                "display_path",
                "path_utf16_hex",
                "kind",
            ] {
                bounded_string(object.get(name), MAX_ACTION_FIELD_BYTES, name)?;
            }
            require_enum(
                object.get("folder_scope").unwrap(),
                &["user_startup", "common_startup"],
                "folder_scope",
            )?;
            require_enum(object.get("trigger").unwrap(), &["user_logon"], "trigger")?;
            require_enum(
                object.get("kind").unwrap(),
                &["file", "directory", "unknown"],
                "kind",
            )?;
            validate_evidence(
                object.get("evidence"),
                &["source", "folder_scope", "display_path", "path_utf16_hex"],
                &[],
                &label,
            )?;
        }
        "service_entries" => {
            for name in ["service_name", "display_name", "start_type"] {
                bounded_string(object.get(name), MAX_ACTION_FIELD_BYTES, name)?;
            }
            require_enum(
                object.get("start_type").unwrap(),
                &[
                    "boot",
                    "system",
                    "automatic",
                    "manual",
                    "disabled",
                    "unknown",
                ],
                "start_type",
            )?;
            let start_type_code =
                unsigned_integer(object.get("start_type_code"), "start_type_code")?;
            if start_type_code > u64::from(u32::MAX) {
                return Err(format!("{label}.start_type_code is outside the u32 range"));
            }
            let expected_start_type = match start_type_code {
                0 => "boot",
                1 => "system",
                2 => "automatic",
                3 => "manual",
                4 => "disabled",
                _ => "unknown",
            };
            if object.get("start_type").and_then(Value::as_str) != Some(expected_start_type) {
                return Err(format!(
                    "{label} has inconsistent start_type and start_type_code"
                ));
            }
            for name in ["account", "binary_path"] {
                if object.contains_key(name) {
                    optional_bounded_string(object.get(name), MAX_ACTION_FIELD_BYTES, name)?;
                }
            }
            validate_evidence(
                object.get("evidence"),
                &["source", "service_index"],
                &[],
                &label,
            )?;
        }
        "scheduled_task_entries" => {
            bounded_string(object.get("task_path"), MAX_ACTION_FIELD_BYTES, "task_path")?;
            optional_boolean(object.get("task_enabled"), "task_enabled")?;
            bounded_string(
                object.get("trigger_type"),
                MAX_ACTION_FIELD_BYTES,
                "trigger_type",
            )?;
            require_enum(
                object.get("trigger_type").unwrap(),
                &["boot", "logon"],
                "trigger_type",
            )?;
            optional_boolean(object.get("trigger_enabled"), "trigger_enabled")?;
            if object.contains_key("logon_user") {
                optional_bounded_string(
                    object.get("logon_user"),
                    MAX_ACTION_FIELD_BYTES,
                    "logon_user",
                )?;
            }
            validate_evidence(
                object.get("evidence"),
                &["source", "task_index", "trigger_index"],
                &[],
                &label,
            )?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn validate_evidence(
    value: Option<&Value>,
    required: &[&str],
    optional: &[&str],
    label: &str,
) -> Result<(), String> {
    let evidence = value
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{label}.evidence must be an object"))?;
    validate_object_fields(evidence, required, optional, &format!("{label}.evidence"))?;
    for (key, value) in evidence {
        if key == "source"
            || key == "hive"
            || key == "registry_view"
            || key == "registry_key"
            || key == "value_name"
            || key == "folder_scope"
            || key == "display_path"
            || key == "path_utf16_hex"
        {
            bounded_string(Some(value), MAX_ACTION_FIELD_BYTES, key)?;
        } else {
            unsigned_integer(Some(value), key)?;
        }
    }
    Ok(())
}

fn unsigned_integer(value: Option<&Value>, label: &str) -> Result<u64, String> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("Windows startup inventory {label} must be an unsigned integer"))
}

fn optional_unsigned_integer(value: Option<&Value>, label: &str) -> Result<Option<u64>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => unsigned_integer(Some(value), label).map(Some),
    }
}

fn optional_boolean(value: Option<&Value>, label: &str) -> Result<Option<bool>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("Windows startup inventory {label} must be a boolean or null")),
    }
}

fn valid_startup_status(value: Option<&Value>, label: &str) -> Result<(), String> {
    let status = bounded_string(value, 32, label)?;
    if matches!(
        status.as_str(),
        "complete"
            | "partial"
            | "not_present"
            | "inaccessible"
            | "unavailable"
            | "unsupported"
            | "not_checked"
            | "error"
    ) {
        Ok(())
    } else {
        Err(format!("Windows startup inventory {label} is unsupported"))
    }
}

fn require_enum(value: &Value, allowed: &[&str], label: &str) -> Result<(), String> {
    let actual = bounded_string(Some(value), MAX_ACTION_FIELD_BYTES, label)?;
    if allowed.contains(&actual.as_str()) {
        Ok(())
    } else {
        Err(format!(
            "Windows startup inventory {label} has an unsupported value"
        ))
    }
}

fn optional_bounded_string(
    value: Option<&Value>,
    max: usize,
    label: &str,
) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => bounded_string(Some(value), max, label).map(Some),
    }
}

fn is_supported_process_start(decoded: &DecodedProcessPayload, event_version: u8) -> bool {
    decoded.status == ProcessDecodeStatus::Decoded
        && decoded.schema_name.as_deref() == Some("windows.kernel_process_typegroup1")
        && decoded.schema_version == Some(event_version)
        && event_version <= 3
}

fn is_drive_rooted_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !value.contains(['\0', '"', '%'])
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_runtime::{
        AppliedLimits, EventLoss, NativeRuntimeEvent, SessionMetadata, StopReason, TargetOutcome,
        WindowsRuntimeCapture,
    };

    fn startup_bytes(actions: Vec<Value>, status: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": WINDOWS_STARTUP_INVENTORY_SCHEMA,
            "schema_version": WINDOWS_STARTUP_INVENTORY_SCHEMA_VERSION,
            "platform": "windows",
            "scope": "synthetic_fixture_not_a_live_capture",
            "capture_started_at_unix_ms": 10,
            "capture_ended_at_unix_ms": 11,
            "status": status,
            "sources": [],
            "registry_entries": [],
            "folder_entries": [],
            "service_entries": [],
            "scheduled_task_entries": [],
            "scheduled_task_actions": actions,
        }))
        .unwrap()
    }

    fn action(path: Option<&str>, status: &str, action_index: usize) -> Value {
        serde_json::json!({
            "task_path": "\\Synthetic\\Task",
            "action_index": action_index,
            "action_type": "exec",
            "action_type_code": 0,
            "status": status,
            "executable_path": path,
            "arguments": null,
            "working_directory": null,
            "evidence": {
                "source": "synthetic fixture scheduled-task action",
                "task_index": 3,
                "action_index": action_index,
            }
        })
    }

    fn capture_bytes(
        events: Vec<NativeRuntimeEvent>,
        collection_status: CollectionStatus,
        lost: u32,
    ) -> Vec<u8> {
        let mut capture = WindowsRuntimeCapture {
            schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
            schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
            platform: "windows".to_owned(),
            capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
            collection_status,
            capture_completeness: "unknown".to_owned(),
            started_at_unix_ms: 10,
            ended_at_unix_ms: 20,
            requested_duration_seconds: 1,
            stop_reason: if lost == 0 {
                StopReason::TargetExited
            } else {
                StopReason::EtwLossReported
            },
            target: TargetOutcome {
                process_id: 77,
                exit_code: Some(0),
                status_available: true,
            },
            session: SessionMetadata {
                name: "NT Kernel Logger".to_owned(),
                provider: "synthetic ETW fixture".to_owned(),
                scope: "synthetic_fixture_not_a_live_capture".to_owned(),
                buffer_size_kb_requested: 16,
                minimum_buffers_requested: 8,
                maximum_buffers_requested: 32,
                buffer_count_reported: 8,
                provider_process_id_header_semantics: "header PID/TID is event context only"
                    .to_owned(),
            },
            limits: AppliedLimits {
                maximum_duration_seconds: 60,
                maximum_events: crate::windows_runtime::MAX_WINDOWS_RUNTIME_EVENTS,
                maximum_total_payload_bytes:
                    crate::windows_runtime::MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES,
                maximum_payload_bytes_per_event:
                    crate::windows_runtime::MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
                maximum_document_bytes: crate::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
            },
            event_loss: EventLoss {
                events_lost: lost,
                log_buffers_lost: 0,
                real_time_buffers_lost: 0,
                loss_statistics_available: true,
                observation: if lost == 0 {
                    "zero_reported"
                } else {
                    "loss_reported"
                }
                .to_owned(),
                final_snapshot_available: true,
            },
            document_sha256: String::new(),
            events,
            diagnostics: if collection_status == CollectionStatus::Partial || lost > 0 {
                vec!["synthetic_fixture_not_a_live_capture".to_owned()]
            } else {
                vec![]
            },
        };
        let canonical = serde_json::to_vec(&capture).unwrap();
        capture.document_sha256 = sha256_hex(&canonical);
        serde_json::to_vec(&capture).unwrap()
    }

    fn process_start(path: &str, ordinal: u64) -> NativeRuntimeEvent {
        NativeRuntimeEvent {
            record_ordinal: ordinal,
            provider_guid: PROCESS_PROVIDER_GUID.to_owned(),
            event_id: 0,
            event_version: 2,
            opcode: 1,
            event_kind: "process_start".to_owned(),
            header_process_id: 77,
            header_thread_id: 78,
            header_flags: 0,
            timestamp_qpc: 10,
            raw_payload_hex: "00".to_owned(),
            payload_decoding: Some(DecodedProcessPayload {
                status: ProcessDecodeStatus::Decoded,
                schema_name: Some("windows.kernel_process_typegroup1".to_owned()),
                schema_version: Some(2),
                pointer_size_bytes: Some(8),
                process_id: Some(77),
                parent_process_id: Some(1),
                image_file_name: Some(path.to_owned()),
                diagnostic: None,
            }),
            observation_decoding: None,
        }
    }

    #[test]
    fn exact_drive_rooted_path_match_keeps_both_source_references() {
        let startup = startup_bytes(
            vec![action(Some(r"C:\Apps\worker.exe"), "observed", 0)],
            "complete",
        );
        let runtime = capture_bytes(
            vec![process_start(r"C:\Apps\worker.exe", 1)],
            CollectionStatus::Partial,
            0,
        );
        let summary = summarize_windows_startup_behavior(&startup, &runtime).unwrap();

        assert_eq!(
            summary.schema,
            "sideeffect.windows_associated_behavior_summary"
        );
        assert_eq!(summary.association_status, "candidate_match");
        assert_eq!(summary.status, "partial");
        assert_eq!(summary.associations.len(), 1);
        assert_eq!(summary.associations[0].startup_evidence[0].task_index, 3);
        assert_eq!(summary.associations[0].startup_evidence[0].action_index, 0);
        assert_eq!(
            summary.associations[0].runtime_evidence[0].record_ordinal,
            1
        );
        assert_eq!(summary.associations[0].runtime_evidence[0].process_id, 77);
        assert_eq!(
            summary.inputs.runtime_capture.capture_completeness,
            "unknown"
        );
    }

    #[test]
    fn basename_mismatch_and_non_absolute_forms_remain_insufficient_evidence() {
        let startup = startup_bytes(
            vec![action(Some(r"C:\Apps\worker.exe"), "observed", 0)],
            "complete",
        );
        let runtime = capture_bytes(
            vec![
                process_start("worker.exe", 1),
                process_start(r"D:\Apps\worker.exe", 2),
            ],
            CollectionStatus::Complete,
            0,
        );
        let summary = summarize_windows_startup_behavior(&startup, &runtime).unwrap();
        assert_eq!(summary.association_status, "insufficient_evidence");
        assert!(summary.associations.is_empty());
        assert_eq!(summary.summary.unsupported_process_start_event_count, 1);
    }

    #[test]
    fn unsupported_actions_and_reported_etw_loss_are_partial_and_visible() {
        let mut unsupported_action = action(None, "unsupported", 1);
        unsupported_action["action_type"] = Value::String("com_handler".to_owned());
        unsupported_action["action_type_code"] = Value::from(5);
        let startup = startup_bytes(
            vec![
                action(Some(r"C:\Apps\worker.exe"), "observed", 0),
                unsupported_action,
            ],
            "partial",
        );
        let runtime = capture_bytes(
            vec![process_start(r"C:\Apps\worker.exe", 1)],
            CollectionStatus::Partial,
            3,
        );
        let summary = summarize_windows_startup_behavior(&startup, &runtime).unwrap();
        assert_eq!(summary.status, "partial");
        assert!(summary.diagnostics.contains(&"etw_loss_was_reported"));
        assert!(
            summary
                .diagnostics
                .contains(&"startup_inventory_is_not_complete")
        );
        assert_eq!(summary.summary.unsupported_or_incomplete_action_count, 1);
    }

    #[test]
    fn mismatched_process_descriptor_or_payload_version_is_not_matched() {
        let startup = startup_bytes(
            vec![action(Some(r"C:\Apps\worker.exe"), "observed", 0)],
            "complete",
        );
        let mut mismatched_event_id = process_start(r"C:\Apps\worker.exe", 1);
        mismatched_event_id.event_id = 1;
        let mut mismatched_payload_version = process_start(r"C:\Apps\worker.exe", 2);
        mismatched_payload_version
            .payload_decoding
            .as_mut()
            .unwrap()
            .schema_version = Some(1);
        let runtime = capture_bytes(
            vec![mismatched_event_id, mismatched_payload_version],
            CollectionStatus::Partial,
            0,
        );
        let summary = summarize_windows_startup_behavior(&startup, &runtime).unwrap();
        assert_eq!(summary.association_status, "insufficient_evidence");
        assert!(summary.associations.is_empty());
        assert_eq!(summary.summary.unsupported_process_start_event_count, 1);
    }

    #[test]
    fn unsupported_versions_malformed_fields_and_duplicate_keys_are_rejected() {
        let mut startup: Value =
            serde_json::from_slice(&startup_bytes(vec![], "complete")).unwrap();
        startup["schema_version"] = Value::from(5);
        assert!(
            summarize_windows_startup_behavior(
                &serde_json::to_vec(&startup).unwrap(),
                &capture_bytes(vec![], CollectionStatus::Complete, 0)
            )
            .is_err()
        );

        let mut incomplete =
            serde_json::from_slice::<Value>(&startup_bytes(vec![], "complete")).unwrap();
        incomplete
            .as_object_mut()
            .unwrap()
            .remove("service_entries");
        assert!(
            summarize_windows_startup_behavior(
                &serde_json::to_vec(&incomplete).unwrap(),
                &capture_bytes(vec![], CollectionStatus::Complete, 0)
            )
            .is_err()
        );

        let mut extended =
            serde_json::from_slice::<Value>(&startup_bytes(vec![], "complete")).unwrap();
        extended["future_field"] = Value::Bool(true);
        assert!(
            summarize_windows_startup_behavior(
                &serde_json::to_vec(&extended).unwrap(),
                &capture_bytes(vec![], CollectionStatus::Complete, 0)
            )
            .is_err()
        );

        let mut malformed =
            serde_json::from_slice::<Value>(&startup_bytes(vec![], "complete")).unwrap();
        malformed["scheduled_task_actions"] = Value::String("not-an-array".to_owned());
        assert!(
            summarize_windows_startup_behavior(
                &serde_json::to_vec(&malformed).unwrap(),
                &capture_bytes(vec![], CollectionStatus::Complete, 0)
            )
            .is_err()
        );

        assert!(summarize_windows_startup_behavior(
            br#"{"schema":"sideeffect.windows_startup_inventory","schema":"sideeffect.windows_startup_inventory","schema_version":4,"platform":"windows","status":"complete","scheduled_task_actions":[]}"#,
            &capture_bytes(vec![], CollectionStatus::Complete, 0)
        )
        .is_err());
    }

    #[test]
    fn malformed_inventory_rows_and_unknown_nested_fields_are_rejected() {
        let capture = capture_bytes(vec![], CollectionStatus::Complete, 0);

        let mut malformed_row: Value =
            serde_json::from_slice(&startup_bytes(vec![], "complete")).unwrap();
        malformed_row["registry_entries"] = serde_json::json!([123]);
        assert!(
            summarize_windows_startup_behavior(
                &serde_json::to_vec(&malformed_row).unwrap(),
                &capture
            )
            .is_err()
        );

        let mut malformed_nested: Value =
            serde_json::from_slice(&startup_bytes(vec![], "complete")).unwrap();
        malformed_nested["sources"] = serde_json::json!([{
            "id": "registry",
            "status": "complete",
            "entries_seen": 0,
            "diagnostics": [{ "code": "ok", "message": "ok", "unexpected": true }]
        }]);
        assert!(
            summarize_windows_startup_behavior(
                &serde_json::to_vec(&malformed_nested).unwrap(),
                &capture
            )
            .is_err()
        );

        let mut invalid_source_enum: Value =
            serde_json::from_slice(&startup_bytes(vec![], "complete")).unwrap();
        invalid_source_enum["sources"] = serde_json::json!([{
            "id": "registry",
            "status": "complete",
            "entries_seen": 0,
            "registry_hive": "bogus",
            "diagnostics": []
        }]);
        assert!(
            summarize_windows_startup_behavior(
                &serde_json::to_vec(&invalid_source_enum).unwrap(),
                &capture
            )
            .is_err()
        );

        let mut invalid_enum: Value =
            serde_json::from_slice(&startup_bytes(vec![], "complete")).unwrap();
        invalid_enum["folder_entries"] = serde_json::json!([{
            "folder_scope": "bogus",
            "trigger": "user_logon",
            "display_path": "C:\\Startup\\sample.lnk",
            "path_utf16_hex": "",
            "kind": "file",
            "evidence": {
                "source": "SHGetKnownFolderPath/FindFirstFileW",
                "folder_scope": "bogus",
                "display_path": "C:\\Startup\\sample.lnk",
                "path_utf16_hex": ""
            }
        }]);
        assert!(
            summarize_windows_startup_behavior(
                &serde_json::to_vec(&invalid_enum).unwrap(),
                &capture
            )
            .is_err()
        );

        let mut inconsistent_service: Value =
            serde_json::from_slice(&startup_bytes(vec![], "complete")).unwrap();
        inconsistent_service["service_entries"] = serde_json::json!([{
            "service_name": "SyntheticService",
            "display_name": "Synthetic Service",
            "start_type": "boot",
            "start_type_code": 4,
            "evidence": { "source": "synthetic", "service_index": 0 }
        }]);
        assert!(
            summarize_windows_startup_behavior(
                &serde_json::to_vec(&inconsistent_service).unwrap(),
                &capture
            )
            .is_err()
        );

        let mut malformed_action = action(Some(r"C:\Apps\worker.exe"), "observed", 0);
        malformed_action["evidence"]["untrusted_extension"] = Value::Bool(true);
        let startup = startup_bytes(vec![malformed_action], "complete");
        assert!(summarize_windows_startup_behavior(&startup, &capture).is_err());

        for (action_type, code, status) in [
            ("exec", 5, "observed"),
            ("exec", 0, "unsupported"),
            ("com_handler", 5, "observed"),
            ("unknown", 0, "unsupported"),
        ] {
            let mut inconsistent = action(Some(r"C:\Apps\worker.exe"), status, 0);
            inconsistent["action_type"] = Value::String(action_type.to_owned());
            inconsistent["action_type_code"] = Value::from(code);
            let startup = startup_bytes(vec![inconsistent], "complete");
            assert!(summarize_windows_startup_behavior(&startup, &capture).is_err());
        }
    }
}
