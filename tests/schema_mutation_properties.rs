//! Deterministic mutation exploration for accepted Windows schemas.
//!
//! These bounded synthetic cases are regression checks, not a coverage-guided
//! fuzzer and not evidence from a live Windows/ETW capture.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sideeffect::windows_runtime::{
    AppliedLimits, CollectionStatus, DecodedProcessPayload, EventLoss,
    MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES, MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
    MAX_WINDOWS_RUNTIME_EVENTS, MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES, NativeRuntimeEvent,
    ProcessDecodeStatus, SessionMetadata, StopReason, TargetOutcome,
    WINDOWS_RUNTIME_CAPTURE_SCHEMA, WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION, WindowsRuntimeCapture,
    inspect_windows_runtime_bytes,
};
use sideeffect::windows_startup_correlation::{
    WINDOWS_STARTUP_INVENTORY_SCHEMA, WINDOWS_STARTUP_INVENTORY_SCHEMA_VERSION,
    summarize_windows_startup_behavior,
};

const FIXTURE_SCOPE: &str = "synthetic_fixture_not_a_live_capture";

fn runtime_fixture() -> Vec<u8> {
    let mut capture = WindowsRuntimeCapture {
        schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
        schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        platform: "windows".to_owned(),
        capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
        collection_status: CollectionStatus::Complete,
        capture_completeness: "unknown".to_owned(),
        started_at_unix_ms: 10,
        ended_at_unix_ms: 20,
        requested_duration_seconds: 1,
        stop_reason: StopReason::TargetExited,
        target: TargetOutcome {
            process_id: 77,
            exit_code: Some(0),
            status_available: true,
        },
        session: SessionMetadata {
            name: "synthetic session".to_owned(),
            provider: "synthetic fixture provider".to_owned(),
            scope: FIXTURE_SCOPE.to_owned(),
            buffer_size_kb_requested: 16,
            minimum_buffers_requested: 8,
            maximum_buffers_requested: 32,
            buffer_count_reported: 8,
            provider_process_id_header_semantics: "header PID/TID is event context only".to_owned(),
        },
        limits: AppliedLimits {
            maximum_duration_seconds: 60,
            maximum_events: MAX_WINDOWS_RUNTIME_EVENTS,
            maximum_total_payload_bytes: MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES,
            maximum_payload_bytes_per_event: MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
            maximum_document_bytes: MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        },
        event_loss: EventLoss {
            events_lost: 0,
            log_buffers_lost: 0,
            real_time_buffers_lost: 0,
            loss_statistics_available: true,
            observation: "zero_reported".to_owned(),
            final_snapshot_available: true,
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
            timestamp_qpc: 10,
            raw_payload_hex: "00".to_owned(),
            payload_decoding: Some(DecodedProcessPayload {
                status: ProcessDecodeStatus::Decoded,
                schema_name: Some("windows.kernel_process_typegroup1".to_owned()),
                schema_version: Some(2),
                pointer_size_bytes: Some(8),
                process_id: Some(501),
                parent_process_id: Some(77),
                image_file_name: Some("C:\\Synthetic\\worker.exe".to_owned()),
                diagnostic: None,
            }),
            observation_decoding: None,
        }],
        diagnostics: vec![],
    };
    let canonical = serde_json::to_vec(&capture).expect("fixture serializes");
    capture.document_sha256 = hex(&Sha256::digest(canonical));
    serde_json::to_vec(&capture).expect("fixture serializes with fingerprint")
}

fn startup_fixture() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": WINDOWS_STARTUP_INVENTORY_SCHEMA,
        "schema_version": WINDOWS_STARTUP_INVENTORY_SCHEMA_VERSION,
        "platform": "windows",
        "scope": FIXTURE_SCOPE,
        "capture_started_at_unix_ms": 10,
        "capture_ended_at_unix_ms": 20,
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
            "executable_path": "C:\\Synthetic\\worker.exe",
            "arguments": null,
            "working_directory": null,
            "evidence": {
                "source": "synthetic fixture scheduled-task action",
                "task_index": 3,
                "action_index": 0
            }
        }]
    }))
    .expect("fixture serializes")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn mutation_corpus(seed: &[u8]) -> Vec<Vec<u8>> {
    let mut cases = Vec::with_capacity(seed.len() * 2 + 16);
    cases.push(seed.to_vec());
    for end in 0..seed.len() {
        cases.push(seed[..end].to_vec());
    }
    for index in 0..seed.len() {
        let mut changed = seed.to_vec();
        changed[index] ^= 0x80;
        cases.push(changed);
    }
    cases
}

fn assert_runtime_acceptance_invariants(bytes: &[u8]) {
    let capture =
        inspect_windows_runtime_bytes(bytes).expect("accepted input has valid fingerprint");
    assert_eq!(capture.schema, WINDOWS_RUNTIME_CAPTURE_SCHEMA);
    assert_eq!(
        capture.schema_version,
        WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION
    );
    assert_eq!(capture.capture_completeness, "unknown");
    assert!(capture.events.len() <= capture.limits.maximum_events);
    assert!(
        capture
            .events
            .iter()
            .enumerate()
            .all(|(index, event)| { event.record_ordinal == u64::try_from(index + 1).unwrap() })
    );

    let fingerprint = capture.document_sha256.clone();
    let mut canonical_capture = capture;
    canonical_capture.document_sha256.clear();
    let canonical = serde_json::to_vec(&canonical_capture).expect("accepted capture serializes");
    assert_eq!(fingerprint, sha256(&canonical));
    assert!(canonical.len() <= MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES);
}

#[test]
fn runtime_v3_seed_and_bounded_mutations_preserve_parser_invariants() {
    let seed = runtime_fixture();
    let mut cases = mutation_corpus(&seed);

    let mut unknown = serde_json::from_slice::<Value>(&seed).expect("valid fixture JSON");
    unknown["unexpected"] = Value::Bool(true);
    let unknown = serde_json::to_vec(&unknown).unwrap();
    cases.push(unknown.clone());

    let mut duplicate = seed.clone();
    duplicate.splice(
        1..1,
        br#""schema":"sideeffect.windows_runtime_capture","#
            .iter()
            .copied(),
    );
    cases.push(duplicate.clone());

    let mut unsupported_version =
        serde_json::from_slice::<Value>(&seed).expect("valid fixture JSON");
    unsupported_version["schema_version"] = Value::from(WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION + 1);
    let unsupported_version = serde_json::to_vec(&unsupported_version).unwrap();
    cases.push(unsupported_version.clone());

    let oversized = vec![b' '; MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES + 1];
    cases.push(oversized.clone());

    for invalid in [&unknown, &duplicate, &unsupported_version, &oversized] {
        assert!(inspect_windows_runtime_bytes(invalid).is_err());
    }

    for candidate in cases {
        let parsed = std::panic::catch_unwind(|| inspect_windows_runtime_bytes(&candidate));
        let result = parsed.expect("runtime parser must not panic on bounded mutation corpus");
        if result.is_ok() {
            assert_runtime_acceptance_invariants(&candidate);
        }
    }
}

#[test]
fn startup_v4_mutations_reject_or_preserve_exact_input_and_evidence_semantics() {
    let startup = startup_fixture();
    let runtime = runtime_fixture();
    let baseline = summarize_windows_startup_behavior(&startup, &runtime)
        .expect("synthetic schema seeds are accepted");
    assert_eq!(baseline.summary.candidate_action_reference_count, 1);
    assert_eq!(baseline.summary.candidate_process_event_count, 1);
    assert_eq!(baseline.associations.len(), 1);
    assert_eq!(baseline.associations[0].startup_evidence[0].task_index, 3);
    assert_eq!(
        baseline.associations[0].runtime_evidence[0].record_ordinal,
        1
    );

    let mut cases = mutation_corpus(&startup);

    let mut unknown = serde_json::from_slice::<Value>(&startup).expect("valid fixture JSON");
    unknown["unexpected"] = Value::Bool(true);
    let unknown = serde_json::to_vec(&unknown).unwrap();
    cases.push(unknown.clone());

    let mut malformed = serde_json::from_slice::<Value>(&startup).expect("valid fixture JSON");
    malformed["scheduled_task_actions"][0]["unexpected"] = Value::Null;
    let malformed = serde_json::to_vec(&malformed).unwrap();
    cases.push(malformed.clone());

    let duplicate = br#"{"schema":"sideeffect.windows_startup_inventory","schema":"sideeffect.windows_startup_inventory"}"#.to_vec();
    cases.push(duplicate.clone());
    let oversized = vec![b' '; sideeffect::limits::MAX_REPORT_BYTES + 1];
    cases.push(oversized.clone());
    for invalid in [&unknown, &malformed, &duplicate, &oversized] {
        assert!(summarize_windows_startup_behavior(invalid, &runtime).is_err());
    }

    for candidate in cases {
        let result =
            std::panic::catch_unwind(|| summarize_windows_startup_behavior(&candidate, &runtime))
                .expect("startup adapter must not panic on bounded mutation corpus");
        if let Ok(summary) = result {
            assert_eq!(summary.inputs.startup_inventory.sha256, sha256(&candidate));
            assert_eq!(summary.inputs.runtime_capture.sha256, sha256(&runtime));
            assert_eq!(summary.inputs.startup_inventory.source_status, "complete");
            assert!(summary.associations.iter().all(|association| {
                association.startup_evidence.iter().all(|evidence| {
                    evidence.task_index == 3
                        && evidence.action_index == 0
                        && evidence.executable_path == "C:\\Synthetic\\worker.exe"
                }) && association.runtime_evidence.iter().all(|evidence| {
                    evidence.capture_sha256 == sha256(&runtime)
                        && evidence.record_ordinal == 1
                        && evidence.image_file_name == "C:\\Synthetic\\worker.exe"
                })
            }));
            let rendered = serde_json::to_vec(&summary).expect("summary serializes");
            assert!(rendered.len() <= sideeffect::limits::MAX_REPORT_BYTES);
        }
    }
}
