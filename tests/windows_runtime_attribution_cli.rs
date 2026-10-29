use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sideeffect::windows_runtime::{
    AppliedLimits, CollectionStatus, DecodedProcessPayload, EventLoss,
    MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES, MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
    MAX_WINDOWS_RUNTIME_EVENTS, MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES, NativeRuntimeEvent,
    ProcessDecodeStatus, SessionMetadata, StopReason, TargetOutcome,
    WINDOWS_RUNTIME_CAPTURE_SCHEMA, WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION, WindowsRuntimeCapture,
};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-windows-attribution-{}-{}",
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

fn process_event(
    ordinal: u64,
    kind: &str,
    pid: u32,
    parent: u32,
    image: &str,
) -> NativeRuntimeEvent {
    let (opcode, event_kind) = match kind {
        "process_start" => (1, "process_start"),
        "process_end" => (2, "process_end"),
        _ => unreachable!(),
    };
    NativeRuntimeEvent {
        record_ordinal: ordinal,
        provider_guid: "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}".to_owned(),
        event_id: 0,
        event_version: 2,
        opcode,
        event_kind: event_kind.to_owned(),
        header_process_id: 1,
        header_thread_id: 2,
        header_flags: 0,
        timestamp_qpc: i64::try_from(ordinal).unwrap(),
        raw_payload_hex: "00".to_owned(),
        payload_decoding: Some(DecodedProcessPayload {
            status: ProcessDecodeStatus::Decoded,
            schema_name: Some("windows.kernel_process_typegroup1".to_owned()),
            schema_version: Some(2),
            pointer_size_bytes: Some(8),
            process_id: Some(pid),
            parent_process_id: Some(parent),
            image_file_name: Some(image.to_owned()),
            diagnostic: None,
        }),
        observation_decoding: None,
    }
}

fn observation_event(
    ordinal: u64,
    kind: &str,
    header_pid: u32,
    payload_pid: Option<u32>,
) -> NativeRuntimeEvent {
    let network = kind == "network_observation";
    let descriptor = if network {
        (
            "{9a280ac0-c8e0-11d1-84e2-00c04fb998a2}",
            12,
            "windows.kernel_tcp_ipv4_typegroup2",
            2,
            "network",
        )
    } else {
        (
            "{90cbdc39-4a3e-11d1-84f4-0000f80464e3}",
            67,
            "windows.kernel_file_io",
            2,
            "file",
        )
    };
    let mut observation = json!({
        "status":"decoded",
        "diagnostic":null,
        "observation":{
            "schema":descriptor.2,
            "schema_version":descriptor.3,
            "activity":{"kind":descriptor.4,"observation":{"operation":"fixture"}}
        }
    });
    if let Some(pid) = payload_pid {
        observation["observation"]["activity"]["observation"]["payload_process_id"] = json!(pid);
    }
    NativeRuntimeEvent {
        record_ordinal: ordinal,
        provider_guid: descriptor.0.to_owned(),
        event_id: 0,
        event_version: 2,
        opcode: descriptor.1,
        event_kind: kind.to_owned(),
        header_process_id: header_pid,
        header_thread_id: 2,
        header_flags: 0,
        timestamp_qpc: i64::try_from(ordinal).unwrap(),
        raw_payload_hex: "00".to_owned(),
        payload_decoding: None,
        observation_decoding: Some(observation),
    }
}

fn unsupported_process_event(ordinal: u64) -> NativeRuntimeEvent {
    let mut event = process_event(ordinal, "process_start", 0, 0, "");
    event.payload_decoding = Some(DecodedProcessPayload {
        status: ProcessDecodeStatus::UnsupportedVersion,
        schema_name: None,
        schema_version: None,
        pointer_size_bytes: None,
        process_id: None,
        parent_process_id: None,
        image_file_name: None,
        diagnostic: Some("fixture_unsupported".to_owned()),
    });
    event
}

fn capture(events: Vec<NativeRuntimeEvent>, lost: bool) -> Vec<u8> {
    let mut capture = WindowsRuntimeCapture {
        schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
        schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        platform: "windows".to_owned(),
        capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
        collection_status: if lost {
            CollectionStatus::Partial
        } else {
            CollectionStatus::Complete
        },
        capture_completeness: "unknown".to_owned(),
        started_at_unix_ms: 1,
        ended_at_unix_ms: 2,
        requested_duration_seconds: 1,
        stop_reason: if lost {
            StopReason::EtwLossReported
        } else {
            StopReason::TargetExited
        },
        target: TargetOutcome {
            process_id: 100,
            exit_code: Some(0),
            status_available: true,
        },
        session: SessionMetadata {
            name: "NT Kernel Logger".to_owned(),
            provider: "fixture provider".to_owned(),
            scope: "system_wide_capture".to_owned(),
            buffer_size_kb_requested: 16,
            minimum_buffers_requested: 8,
            maximum_buffers_requested: 32,
            buffer_count_reported: 8,
            provider_process_id_header_semantics: "header PID/TID is context".to_owned(),
        },
        limits: AppliedLimits {
            maximum_duration_seconds: 60,
            maximum_events: MAX_WINDOWS_RUNTIME_EVENTS,
            maximum_total_payload_bytes: MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES,
            maximum_payload_bytes_per_event: MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
            maximum_document_bytes: MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        },
        event_loss: EventLoss {
            events_lost: u32::from(lost),
            log_buffers_lost: 0,
            real_time_buffers_lost: 0,
            loss_statistics_available: true,
            observation: if lost {
                "loss_reported"
            } else {
                "zero_reported"
            }
            .to_owned(),
            final_snapshot_available: true,
        },
        document_sha256: String::new(),
        events,
        diagnostics: Vec::new(),
    };
    capture.document_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&capture).unwrap())
    );
    serde_json::to_vec(&capture).unwrap()
}

fn run(capture: &[u8]) -> Output {
    let temp = Temp::new();
    let path = temp.0.join("capture.json");
    fs::write(&path, capture).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["attribute", "--windows-runtime", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), capture);
    output
}

fn output_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn links_supported_descendant_and_network_payloads_but_keeps_header_pid_as_context() {
    let bytes = capture(
        vec![
            process_event(1, "process_start", 100, 5, "target.exe"),
            process_event(2, "process_start", 200, 100, "child.exe"),
            observation_event(3, "network_observation", 999, Some(100)),
            observation_event(4, "network_observation", 999, Some(200)),
            observation_event(5, "file_io_observation", 200, None),
            process_event(6, "process_end", 200, 100, "child.exe"),
            observation_event(7, "network_observation", 200, Some(200)),
        ],
        false,
    );
    let output = run(&bytes);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = output_json(&output);
    assert_eq!(summary["status"], "complete");
    assert_eq!(
        summary["capture"]["sha256"],
        format!("{:x}", Sha256::digest(&bytes))
    );
    assert_eq!(
        summary["summary"]["observed_descendant_process_instances"],
        1
    );
    assert_eq!(summary["summary"]["header_pid_context_candidates"], 1);
    assert_eq!(
        summary["event_attributions"][2]["attribution"],
        "target_network_payload_pid_match"
    );
    assert_eq!(
        summary["event_attributions"][3]["attribution"],
        "descendant_network_payload_pid_match"
    );
    assert_eq!(
        summary["event_attributions"][4]["attribution"],
        "descendant_header_pid_context_candidate"
    );
    assert_eq!(
        summary["event_attributions"][4]["basis"],
        "header_process_id_matches_active_target_tree_pid_but_remains_event_context_only"
    );
    assert_eq!(
        summary["unassigned_events"][0]["event"]["record_ordinal"],
        7
    );
    assert_eq!(
        summary["event_attributions"][1]["event"]["capture_sha256"],
        summary["capture"]["sha256"]
    );
}

#[test]
fn pid_reuse_after_end_does_not_extend_the_old_target_descendant_lifetime() {
    let bytes = capture(
        vec![
            process_event(1, "process_start", 100, 5, "target.exe"),
            process_event(2, "process_start", 200, 100, "child.exe"),
            process_event(3, "process_end", 200, 100, "child.exe"),
            process_event(4, "process_start", 200, 999, "unrelated.exe"),
            observation_event(5, "network_observation", 200, Some(200)),
        ],
        false,
    );
    let output = run(&bytes);
    assert!(output.status.success());
    let summary = output_json(&output);
    assert_eq!(
        summary["unassigned_events"][0]["event"]["record_ordinal"],
        4
    );
    assert_eq!(
        summary["unassigned_events"][1]["event"]["record_ordinal"],
        5
    );
    assert_eq!(
        summary["unassigned_events"][1]["reason"],
        "network_payload_process_id_is_outside_observed_target_tree"
    );
}

#[test]
fn overlapping_pid_lifecycle_is_reported_ambiguous_and_not_network_attributed() {
    let bytes = capture(
        vec![
            process_event(1, "process_start", 100, 5, "target.exe"),
            process_event(2, "process_start", 200, 100, "first.exe"),
            process_event(3, "process_start", 200, 100, "second.exe"),
            observation_event(4, "network_observation", 200, Some(200)),
        ],
        false,
    );
    let output = run(&bytes);
    assert_eq!(output.status.code(), Some(2));
    let summary = output_json(&output);
    assert_eq!(summary["summary"]["ambiguous_process_ids"], 1);
    assert_eq!(
        summary["processes"][1]["identity_status"],
        "ambiguous_pid_lifecycle"
    );
    assert_eq!(
        summary["unassigned_events"][0]["reason"],
        "overlapping_process_id_makes_instance_identity_ambiguous"
    );
    assert_eq!(
        summary["unassigned_events"][1]["reason"],
        "network_payload_process_id_is_ambiguous"
    );
}

#[test]
fn process_end_with_mismatched_start_identity_ends_attribution_as_ambiguous() {
    let bytes = capture(
        vec![
            process_event(1, "process_start", 100, 5, "target.exe"),
            process_event(2, "process_start", 200, 100, "child.exe"),
            process_event(3, "process_end", 200, 100, "other.exe"),
            observation_event(4, "network_observation", 200, Some(200)),
        ],
        true,
    );
    let output = run(&bytes);
    assert_eq!(output.status.code(), Some(2));
    let summary = output_json(&output);
    assert_eq!(summary["summary"]["ambiguous_process_ids"], 1);
    assert_eq!(
        summary["unassigned_events"][0]["reason"],
        "process_end_parent_or_image_does_not_match_active_start_payload"
    );
    assert_eq!(
        summary["unassigned_events"][1]["reason"],
        "network_payload_process_id_is_ambiguous"
    );
}

#[test]
fn missing_target_start_and_reported_loss_are_partial_without_absence_claims() {
    let bytes = capture(
        vec![observation_event(1, "network_observation", 100, Some(100))],
        true,
    );
    let output = run(&bytes);
    assert_eq!(output.status.code(), Some(2));
    let summary = output_json(&output);
    assert_eq!(summary["status"], "partial");
    assert_eq!(summary["target_start_status"], "not_observed");
    assert_eq!(summary["capture"]["event_loss_reported"], true);
    assert!(
        summary["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "target_process_start_was_not_observed")
    );
    assert_eq!(
        summary["unassigned_events"][0]["reason"],
        "network_payload_process_id_is_outside_observed_target_tree"
    );
}

#[test]
fn unsupported_process_lifecycle_is_preserved_as_unassigned_and_partial() {
    let bytes = capture(
        vec![
            process_event(1, "process_start", 100, 5, "target.exe"),
            unsupported_process_event(2),
        ],
        true,
    );
    let output = run(&bytes);
    assert_eq!(output.status.code(), Some(2));
    let summary = output_json(&output);
    assert_eq!(summary["status"], "partial");
    assert_eq!(
        summary["unassigned_events"][0]["event"]["record_ordinal"],
        2
    );
    assert_eq!(
        summary["unassigned_events"][0]["reason"],
        "process_start_payload_is_not_supported_and_validated"
    );
}
