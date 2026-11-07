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
    process_event_with_layout(ordinal, kind, pid, parent, image, 2, 8)
}

fn process_event_with_layout(
    ordinal: u64,
    kind: &str,
    pid: u32,
    parent: u32,
    image: &str,
    version: u8,
    pointer_size: usize,
) -> NativeRuntimeEvent {
    let (opcode, event_kind) = match kind {
        "process_start" => (1, "process_start"),
        "process_end" => (2, "process_end"),
        _ => unreachable!(),
    };
    let mut raw_process_payload = Vec::new();
    if version == 0 {
        if pointer_size == 4 {
            raw_process_payload.extend_from_slice(&pid.to_le_bytes());
            raw_process_payload.extend_from_slice(&parent.to_le_bytes());
        } else {
            raw_process_payload.extend_from_slice(&u64::from(pid).to_le_bytes());
            raw_process_payload.extend_from_slice(&u64::from(parent).to_le_bytes());
        }
    } else {
        raw_process_payload.resize(pointer_size, 0);
        raw_process_payload.extend_from_slice(&pid.to_le_bytes());
        raw_process_payload.extend_from_slice(&parent.to_le_bytes());
    }
    let raw_payload_hex = {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(raw_process_payload.len().saturating_mul(2));
        for byte in &raw_process_payload {
            write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        encoded
    };
    NativeRuntimeEvent {
        record_ordinal: ordinal,
        provider_guid: "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}".to_owned(),
        event_id: 0,
        event_version: version,
        opcode,
        event_kind: event_kind.to_owned(),
        header_process_id: 1,
        header_thread_id: 2,
        header_flags: if pointer_size == 4 { 0x0020 } else { 0x0040 },
        timestamp_qpc: i64::try_from(ordinal).unwrap(),
        raw_payload_hex,
        payload_decoding: Some(DecodedProcessPayload {
            status: ProcessDecodeStatus::Decoded,
            schema_name: Some("windows.kernel_process_typegroup1".to_owned()),
            schema_version: Some(version),
            pointer_size_bytes: Some(pointer_size as u8),
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
            11,
            "windows.kernel_tcp_ipv4_typegroup1",
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
    let (raw_payload_hex, observation) = if network {
        let payload_pid = payload_pid.unwrap_or_default();
        let mut raw_payload = Vec::new();
        raw_payload.extend_from_slice(&payload_pid.to_le_bytes());
        raw_payload.extend_from_slice(&12_u32.to_le_bytes());
        raw_payload.extend_from_slice(&[127, 0, 0, 1]);
        raw_payload.extend_from_slice(&[127, 0, 0, 1]);
        raw_payload.extend_from_slice(&443_u16.to_be_bytes());
        raw_payload.extend_from_slice(&50_000_u16.to_be_bytes());
        raw_payload.extend_from_slice(&99_u32.to_le_bytes());
        raw_payload.extend_from_slice(&0x7788_u64.to_le_bytes());
        let observation = json!({
            "status":"decoded",
            "diagnostic":null,
            "observation":{
                "schema":descriptor.2,
                "schema_version":descriptor.3,
                "activity":{"kind":"network","observation":{
                    "transport":"tcp",
                    "operation":"receive",
                    "payload_process_id":payload_pid,
                    "source_address":{"v4":[127,0,0,1]},
                    "destination_address":{"v4":[127,0,0,1]},
                    "source_port":50000,
                    "destination_port":443,
                    "packet_size":12,
                    "sequence_number":99,
                    "connection_id":30600
                }}
            }
        });
        let mut encoded = String::with_capacity(raw_payload.len().saturating_mul(2));
        use std::fmt::Write as _;
        for byte in &raw_payload {
            write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        (encoded, observation)
    } else {
        (
            "00".to_owned(),
            json!({
                "status":"decoded",
                "diagnostic":null,
                "observation":{
                    "schema":descriptor.2,
                    "schema_version":descriptor.3,
                    "activity":{"kind":descriptor.4,"observation":{"operation":"fixture"}}
                }
            }),
        )
    };
    NativeRuntimeEvent {
        record_ordinal: ordinal,
        provider_guid: descriptor.0.to_owned(),
        event_id: 0,
        event_version: 2,
        opcode: descriptor.1,
        event_kind: kind.to_owned(),
        header_process_id: header_pid,
        header_thread_id: 2,
        header_flags: if network { 0x0040 } else { 0 },
        timestamp_qpc: i64::try_from(ordinal).unwrap(),
        raw_payload_hex,
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
    assert_eq!(summary["schema_version"], 2);
    assert_eq!(summary["algorithm"]["version"], 2);
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
        summary["event_attributions"][3]["basis"],
        "raw_network_payload_pid_matches_serialized_sidecar_and_active_target_tree_instance"
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
fn process_end_with_mismatched_parent_ends_attribution_as_ambiguous() {
    let bytes = capture(
        vec![
            process_event(1, "process_start", 100, 5, "target.exe"),
            process_event(2, "process_start", 200, 100, "child.exe"),
            process_event(3, "process_end", 200, 101, "child.exe"),
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
        "process_end_parent_does_not_match_active_start_payload"
    );
    assert_eq!(
        summary["unassigned_events"][1]["reason"],
        "network_payload_process_id_is_ambiguous"
    );
}

#[test]
fn process_end_image_metadata_does_not_define_process_identity() {
    let bytes = capture(
        vec![
            process_event(1, "process_start", 100, 5, "target.exe"),
            process_event(2, "process_end", 100, 5, "different-untrusted-image.exe"),
        ],
        false,
    );
    let output = run(&bytes);
    assert!(output.status.success());
    let summary = output_json(&output);
    assert_eq!(summary["processes"][0]["end_event"]["record_ordinal"], 2);
    assert_eq!(
        summary["event_attributions"][1]["basis"],
        "raw_checked_process_end_pid_and_parent_match_active_process_start"
    );
}

#[test]
fn process_payload_raw_and_sidecar_must_match_for_pid_and_parent_id() {
    for mismatch_parent in [false, true] {
        let mut row = process_event(1, "process_start", 100, 5, "target.exe");
        let payload = row.payload_decoding.as_mut().unwrap();
        if mismatch_parent {
            payload.parent_process_id = Some(6);
        } else {
            payload.process_id = Some(101);
        }
        let bytes = capture(vec![row], false);
        let output = run(&bytes);
        assert_eq!(
            output.status.code(),
            Some(2),
            "network row result: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let summary = output_json(&output);
        assert_eq!(summary["status"], "partial");
        assert_eq!(summary["target_start_status"], "not_observed");
        assert!(summary["processes"].as_array().unwrap().is_empty());
        assert_eq!(
            summary["unassigned_events"][0]["reason"],
            "process_start_payload_is_not_supported_and_validated"
        );
        assert!(
            summary["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "process_payload_sidecar_mismatch")
        );
    }
}

#[test]
fn network_attribution_requires_raw_payload_sidecar_pid_match() {
    let mut forged = observation_event(2, "network_observation", 999, Some(100));
    forged.observation_decoding.as_mut().unwrap()["observation"]["activity"]["observation"]["payload_process_id"] =
        json!(101);
    let output = run(&capture(
        vec![
            process_event(1, "process_start", 100, 5, "target.exe"),
            forged,
        ],
        false,
    ));
    assert_eq!(output.status.code(), Some(2));
    let summary = output_json(&output);
    assert_eq!(summary["event_attributions"].as_array().unwrap().len(), 1);
    assert_eq!(
        summary["unassigned_events"][0]["event"]["record_ordinal"],
        2
    );
    assert_eq!(
        summary["unassigned_events"][0]["reason"],
        "network_payload_sidecar_does_not_match_raw_payload"
    );
    assert!(
        summary["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "network_decoder_metadata_mismatch")
    );
}

#[test]
fn malformed_and_unsupported_network_payloads_are_partial_and_unassigned() {
    let mut malformed = observation_event(2, "network_observation", 999, Some(100));
    malformed.raw_payload_hex = "00".to_owned();
    let mut unsupported = observation_event(3, "network_observation", 999, Some(100));
    unsupported.opcode = 99;
    for (mut row, expected_diagnostic) in [
        (malformed, "network_payload_malformed"),
        (unsupported, "network_payload_unsupported"),
    ] {
        row.record_ordinal = 2;
        let output = run(&capture(
            vec![process_event(1, "process_start", 100, 5, "target.exe"), row],
            false,
        ));
        assert_eq!(
            output.status.code(),
            Some(2),
            "network row result: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let summary = output_json(&output);
        assert_eq!(summary["status"], "partial");
        assert_eq!(summary["event_attributions"].as_array().unwrap().len(), 1);
        assert_eq!(
            summary["unassigned_events"][0]["event"]["record_ordinal"],
            2
        );
        assert!(
            summary["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == expected_diagnostic)
        );
    }
}

#[test]
fn malformed_or_unsupported_process_payloads_remain_unresolved() {
    let mut cases = Vec::new();
    let mut truncated = process_event(1, "process_start", 100, 5, "target.exe");
    truncated.raw_payload_hex = "00".to_owned();
    cases.push((truncated, "process_payload_malformed"));

    let mut missing_pointer_flags = process_event(1, "process_start", 100, 5, "target.exe");
    missing_pointer_flags.header_flags = 0;
    cases.push((missing_pointer_flags, "process_payload_unsupported"));

    let mut conflicting_pointer_flags = process_event(1, "process_start", 100, 5, "target.exe");
    conflicting_pointer_flags.header_flags = 0x0060;
    cases.push((conflicting_pointer_flags, "process_payload_unsupported"));

    let mut unsupported_version = process_event(1, "process_start", 100, 5, "target.exe");
    unsupported_version.event_version = 4;
    cases.push((unsupported_version, "process_payload_unsupported"));

    let mut wrong_provider = process_event(1, "process_start", 100, 5, "target.exe");
    wrong_provider.provider_guid = "00000000-0000-0000-0000-000000000000".to_owned();
    cases.push((wrong_provider, "process_payload_unsupported"));

    let mut wrong_event_id = process_event(1, "process_start", 100, 5, "target.exe");
    wrong_event_id.event_id = 1;
    cases.push((wrong_event_id, "process_payload_unsupported"));

    let mut wrong_opcode = process_event(1, "process_start", 100, 5, "target.exe");
    wrong_opcode.opcode = 9;
    cases.push((wrong_opcode, "process_payload_unsupported"));

    cases.push((
        process_event(1, "process_start", 0, 5, "target.exe"),
        "process_payload_invalid_process_id",
    ));

    for (row, expected_diagnostic) in cases {
        let bytes = capture(vec![row], false);
        let output = run(&bytes);
        assert_eq!(output.status.code(), Some(2));
        let summary = output_json(&output);
        assert_eq!(summary["status"], "partial");
        assert_eq!(summary["target_start_status"], "not_observed");
        assert!(summary["event_attributions"].as_array().unwrap().is_empty());
        assert!(
            summary["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == expected_diagnostic)
        );
    }
}

#[test]
fn malformed_child_start_invalidates_active_lifecycle_continuity() {
    let mut invalid_child = process_event(2, "process_start", 200, 100, "child.exe");
    invalid_child.raw_payload_hex = "00".to_owned();
    let bytes = capture(
        vec![
            process_event(1, "process_start", 100, 5, "target.exe"),
            invalid_child,
            observation_event(3, "network_observation", 100, Some(100)),
        ],
        false,
    );
    let output = run(&bytes);
    assert_eq!(output.status.code(), Some(2));
    let summary = output_json(&output);
    assert_eq!(
        summary["processes"][0]["identity_status"],
        "ambiguous_pid_lifecycle"
    );
    assert_eq!(
        summary["unassigned_events"][0]["event"]["record_ordinal"],
        2
    );
    assert_eq!(
        summary["unassigned_events"][1]["event"]["record_ordinal"],
        3
    );
    assert_eq!(
        summary["unassigned_events"][1]["reason"],
        "network_payload_process_id_is_ambiguous"
    );
}

#[test]
fn rehashed_process_end_with_wrong_kind_invalidates_lifecycle_before_network_rows() {
    for event_id in [0, 1] {
        let mut wrong_kind_end = process_event(2, "process_end", 100, 5, "target.exe");
        wrong_kind_end.event_id = event_id;
        wrong_kind_end.event_kind = "unsupported_or_malformed_provider_event".to_owned();
        let output = run(&capture(
            vec![
                process_event(1, "process_start", 100, 5, "target.exe"),
                wrong_kind_end,
                observation_event(3, "network_observation", 999, Some(100)),
            ],
            false,
        ));
        assert_eq!(output.status.code(), Some(2));
        let summary = output_json(&output);
        assert_eq!(
            summary["processes"][0]["identity_status"],
            "ambiguous_pid_lifecycle"
        );
        assert_eq!(
            summary["unassigned_events"][0]["event"]["record_ordinal"],
            2
        );
        assert_eq!(
            summary["unassigned_events"][1]["event"]["record_ordinal"],
            3
        );
        assert_eq!(
            summary["unassigned_events"][1]["reason"],
            "network_payload_process_id_is_ambiguous"
        );
        assert!(
            summary["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "process_payload_unsupported")
        );
    }
}

#[test]
fn rehashed_network_row_with_wrong_kind_is_checked_and_partial() {
    let mut wrong_kind_network = observation_event(2, "network_observation", 999, Some(100));
    wrong_kind_network.event_kind = "unsupported_or_malformed_provider_event".to_owned();
    let output = run(&capture(
        vec![
            process_event(1, "process_start", 100, 5, "target.exe"),
            wrong_kind_network,
        ],
        false,
    ));
    assert_eq!(output.status.code(), Some(2));
    let summary = output_json(&output);
    assert_eq!(summary["status"], "partial");
    assert_eq!(
        summary["unassigned_events"][0]["event"]["record_ordinal"],
        2
    );
    assert_eq!(
        summary["unassigned_events"][0]["reason"],
        "network_payload_sidecar_does_not_match_raw_payload"
    );
    assert!(
        summary["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "network_decoder_metadata_mismatch")
    );
}

#[test]
fn reviewed_process_layouts_validate_for_each_version_and_pointer_width() {
    for version in 0..=3 {
        for pointer_size in [4, 8] {
            let row = process_event_with_layout(
                1,
                "process_start",
                100,
                5,
                "target.exe",
                version,
                pointer_size,
            );
            let output = run(&capture(vec![row], false));
            assert!(
                output.status.success(),
                "version={version}, pointer_size={pointer_size}, status={:?}: stdout={} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let summary = output_json(&output);
            assert_eq!(summary["target_start_status"], "observed_once");
            assert_eq!(summary["summary"]["observed_target_process_instances"], 1);
        }
    }
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
