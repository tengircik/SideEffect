use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-associated-behavior-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn startup(exec_value: &str, status: &str) -> Value {
    json!({
        "schema":"sideeffect.startup_inventory", "schema_version":2,
        "platform":"linux", "scope":"curated_xdg_systemd_sysv_cron_sources",
        "capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":status,
        "xdg_autostart": {
            "schema":"sideeffect.xdg_autostart_inventory","schema_version":1,"platform":"linux",
            "scope":"xdg_autostart_directories","capture_started_at_unix_ms":1,
            "capture_ended_at_unix_ms":2,"status":status,"directories":[],
            "entries":[{
                "scope":"user","source_path":"/config/example.desktop","applicability":"not_evaluated",
                "keys":[{"key":"Exec","value":exec_value,"value_hex":null,
                    "line":4,"byte_offset":20,"byte_length":exec_value.len(),
                    "line_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
            }]
        },
        "systemd_units":{"schema":"sideeffect.systemd_units","schema_version":1,"platform":"linux",
            "scope":"systemd_unit_files","capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,
            "status":status,"directories":[],"records":[]},
        "legacy_sources":{"schema":"sideeffect.legacy_startup_inventory","schema_version":1,
            "platform":"linux","scope":"curated_sysv_cron_paths","capture_started_at_unix_ms":1,
            "capture_ended_at_unix_ms":2,"status":status,"sources":[],"entries":[]}
    })
}

fn run_cli(startup: &Value, trace_text: &[u8]) -> (std::process::Output, Value) {
    let temp = Temp::new();
    let startup_path = temp.0.join("startup.json");
    let trace_path = temp.0.join("trace.strace");
    fs::write(&startup_path, serde_json::to_vec(startup).unwrap()).unwrap();
    fs::write(&trace_path, trace_text).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("associated-behavior")
        .arg(&startup_path)
        .arg(&trace_path)
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    // Temp input files remain available until after stdout has been parsed.
    drop(temp);
    (output, report)
}

#[test]
fn cli_emits_candidate_association_with_all_evidence_and_disclaimers() {
    // Synthetic saved inputs; this test does not exercise a real startup event or capture.
    let (output, report) = run_cli(
        &startup("/usr/bin/example --version", "complete"),
        b"100 execve(\"/usr/bin/example\", [\"different-argv0\"], 0x0) = 0\n",
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(report["schema"], "sideeffect.associated_behavior_summary");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["algorithm"]["version"], 1);
    assert_eq!(
        report["platform_adapter"],
        "linux_startup_inventory_v2_strace_v1"
    );
    assert_eq!(report["capture_completeness"], "unknown");
    assert_eq!(report["association_status"], "candidate_match");
    assert_eq!(report["associations"][0]["status"], "candidate_match");
    assert_eq!(report["associations"][0]["startup_evidence"][0]["line"], 4);
    assert_eq!(
        report["associations"][0]["runtime_evidence"][0]["caller_task_id"],
        100
    );
    assert_eq!(
        report["associations"][0]["runtime_evidence"][0]["evidence"]["line_number"],
        1
    );
    assert!(
        report["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item
                .as_str()
                .unwrap()
                .contains("does not establish that a startup hook executed or caused"))
    );
}

#[test]
fn cli_reports_no_match_as_insufficient_evidence_without_partial_exit() {
    let (output, report) = run_cli(
        &startup("/usr/bin/configured", "complete"),
        b"100 execve(\"/usr/bin/other\", [], 0x0) = 0\n",
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(report["status"], "complete");
    assert_eq!(report["association_status"], "insufficient_evidence");
    assert!(report["associations"].as_array().unwrap().is_empty());
    assert_eq!(report["summary"]["unmatched_config_path_count"], 1);
    assert_eq!(report["summary"]["unmatched_runtime_path_count"], 1);
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "unmatched_paths_are_not_evidence_of_non_occurrence")
    );
}

#[test]
fn cli_marks_partial_sources_or_coverage_and_exits_two() {
    let (output, report) = run_cli(
        &startup("/usr/bin/example", "partial"),
        b"malformed trace row\n100 execve(\"/usr/bin/example\", [], 0x0) = 0\n",
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(report["status"], "partial");
    assert_eq!(report["association_status"], "candidate_match");
    assert_eq!(
        report["inputs"]["startup_inventory"]["source_status"],
        "partial"
    );
    assert_eq!(
        report["inputs"]["runtime_trace"]["source_status"],
        "partial"
    );
    assert!(!report["diagnostics"].as_array().unwrap().is_empty());
}

#[test]
fn cli_rejects_oversized_startup_input_before_json_parsing() {
    let temp = Temp::new();
    let startup_path = temp.0.join("oversized-startup.json");
    let trace_path = temp.0.join("trace.strace");
    fs::File::create(&startup_path)
        .unwrap()
        .set_len(sideeffect::limits::MAX_REPORT_BYTES as u64 + 1)
        .unwrap();
    fs::write(&trace_path, b"").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("associated-behavior")
        .arg(&startup_path)
        .arg(&trace_path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("startup inventory input exceeds"));
}

#[test]
fn cli_dispatches_windows_inputs_to_the_exact_path_candidate_adapter() {
    use sideeffect::windows_runtime::{
        AppliedLimits, CollectionStatus, DecodedProcessPayload, EventLoss, NativeRuntimeEvent,
        ProcessDecodeStatus, SessionMetadata, StopReason, TargetOutcome, WindowsRuntimeCapture,
    };

    let temp = Temp::new();
    let startup_path = temp.0.join("startup.windows.json");
    let runtime_path = temp.0.join("runtime.windows.json");
    let output = json!({
        "schema": "sideeffect.windows_startup_inventory",
        "schema_version": 4,
        "platform": "windows",
        "scope": "synthetic_fixture_not_a_live_capture",
        "capture_started_at_unix_ms": 10,
        "capture_ended_at_unix_ms": 11,
        "status": "complete",
        "sources": [],
        "registry_entries": [],
        "folder_entries": [],
        "service_entries": [],
        "scheduled_task_entries": [],
        "scheduled_task_actions": [{
            "task_path": "\\Synthetic\\Task",
            "action_index": 0,
            "action_type": "exec",
            "action_type_code": 0,
            "status": "observed",
            "executable_path": r"C:\Apps\worker.exe",
            "evidence": {
                "source": "synthetic_fixture_not_a_live_capture",
                "task_index": 4,
                "action_index": 0
            }
        }]
    });
    fs::write(&startup_path, serde_json::to_vec(&output).unwrap()).unwrap();

    let mut capture = WindowsRuntimeCapture {
        schema: sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
        schema_version: sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        platform: "windows".to_owned(),
        capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
        collection_status: CollectionStatus::Partial,
        capture_completeness: "unknown".to_owned(),
        started_at_unix_ms: 10,
        ended_at_unix_ms: 20,
        requested_duration_seconds: 1,
        stop_reason: StopReason::EtwStatisticsUnavailable,
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
            provider_process_id_header_semantics: "header PID/TID is event context only".to_owned(),
        },
        limits: AppliedLimits {
            maximum_duration_seconds: 60,
            maximum_events: sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_EVENTS,
            maximum_total_payload_bytes:
                sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES,
            maximum_payload_bytes_per_event:
                sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
            maximum_document_bytes: sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        },
        event_loss: EventLoss {
            events_lost: 0,
            log_buffers_lost: 0,
            real_time_buffers_lost: 0,
            loss_statistics_available: false,
            observation: "unavailable".to_owned(),
            final_snapshot_available: false,
        },
        document_sha256: String::new(),
        events: vec![NativeRuntimeEvent {
            record_ordinal: 1,
            provider_guid: "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}".to_owned(),
            event_id: 0,
            event_version: 2,
            opcode: 1,
            event_kind: "process_start".to_owned(),
            header_process_id: 77,
            header_thread_id: 78,
            header_flags: 0,
            timestamp_qpc: 100,
            raw_payload_hex: "00".to_owned(),
            payload_decoding: Some(DecodedProcessPayload {
                status: ProcessDecodeStatus::Decoded,
                schema_name: Some("windows.kernel_process_typegroup1".to_owned()),
                schema_version: Some(2),
                pointer_size_bytes: Some(8),
                process_id: Some(77),
                parent_process_id: Some(1),
                image_file_name: Some(r"C:\Apps\worker.exe".to_owned()),
                diagnostic: None,
            }),
            observation_decoding: None,
        }],
        diagnostics: vec!["synthetic_fixture_not_a_live_capture".to_owned()],
    };
    capture.document_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&capture).unwrap())
    );
    fs::write(&runtime_path, serde_json::to_vec(&capture).unwrap()).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("associated-behavior")
        .arg(&startup_path)
        .arg(&runtime_path)
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&result.stdout).unwrap_or_else(|error| {
        panic!(
            "Windows associated-behavior CLI returned no JSON: {error}; stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        )
    });
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        report["schema"],
        "sideeffect.windows_associated_behavior_summary"
    );
    assert_eq!(report["association_status"], "candidate_match");
    assert_eq!(report["status"], "partial");
    assert_eq!(
        report["associations"][0]["startup_evidence"][0]["task_index"],
        4
    );
    assert_eq!(
        report["associations"][0]["runtime_evidence"][0]["record_ordinal"],
        1
    );
    assert_eq!(
        report["inputs"]["runtime_capture"]["capture_completeness"],
        "unknown"
    );
    assert!(
        report["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item.as_str().unwrap().contains("no basename matching"))
    );
}
