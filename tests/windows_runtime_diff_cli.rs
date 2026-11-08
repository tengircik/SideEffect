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
            "sideeffect-windows-runtime-diff-{}-{}",
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

fn event(ordinal: u64, kind: &str) -> NativeRuntimeEvent {
    let io_descriptor = match kind {
        "file.create_name_a" | "file.create_name_b" => Some((
            "{90cbdc39-4a3e-11d1-84f4-0000f80464e3}",
            2,
            32,
            "file_io_observation",
            "windows.kernel_file_io",
            2,
            "file",
            json!({
                "operation":"create_name",
                "path":r"C:\Apps\worker.exe",
                "file_object": if kind.ends_with("_a") { 10 } else { 20 }
            }),
        )),
        "file.read_request" => Some((
            "{90cbdc39-4a3e-11d1-84f4-0000f80464e3}",
            2,
            67,
            "file_io_observation",
            "windows.kernel_file_io",
            2,
            "file",
            json!({"operation":"read_request"}),
        )),
        "file.write_request" => Some((
            "{90cbdc39-4a3e-11d1-84f4-0000f80464e3}",
            2,
            68,
            "file_io_observation",
            "windows.kernel_file_io",
            2,
            "file",
            json!({"operation":"write_request"}),
        )),
        "disk.read" => Some((
            "{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}",
            0,
            10,
            "disk_io_observation",
            "windows.kernel_disk_io",
            0,
            "disk",
            json!({"operation":"read"}),
        )),
        "network.tcp.connect" => Some((
            "{9a280ac0-c8e0-11d1-84e2-00c04fb998a2}",
            2,
            12,
            "network_observation",
            "windows.kernel_tcp_ipv4_typegroup2",
            2,
            "network",
            json!({"transport":"tcp","operation":"connect"}),
        )),
        _ => None,
    };
    let observation =
        io_descriptor
            .as_ref()
            .map(|(_, _, _, _, schema, schema_version, kind, payload)| {
                json!({"status":"decoded","diagnostic":null,"observation":{
                    "schema":schema,"schema_version":schema_version,
                    "activity":{"kind":kind,"observation":payload}
                }})
            });
    let process = (kind == "process.start").then(|| DecodedProcessPayload {
        status: ProcessDecodeStatus::Decoded,
        schema_name: Some("windows.kernel_process_typegroup1".to_owned()),
        schema_version: Some(2),
        pointer_size_bytes: Some(8),
        process_id: Some(42),
        parent_process_id: Some(1),
        image_file_name: Some("fixture.exe".to_owned()),
        diagnostic: None,
    });
    NativeRuntimeEvent {
        record_ordinal: ordinal,
        provider_guid: process
            .as_ref()
            .map(|_| "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}".to_owned())
            .or_else(|| {
                io_descriptor
                    .as_ref()
                    .map(|(provider, ..)| provider.to_string())
            })
            .unwrap_or_default(),
        event_id: 0,
        event_version: process
            .as_ref()
            .map(|_| 2)
            .or_else(|| io_descriptor.as_ref().map(|(_, version, ..)| *version))
            .unwrap_or(0),
        opcode: process
            .as_ref()
            .map(|_| 1)
            .or_else(|| io_descriptor.as_ref().map(|(_, _, opcode, ..)| *opcode))
            .unwrap_or(0),
        event_kind: process
            .as_ref()
            .map(|_| "process_start".to_owned())
            .or_else(|| {
                io_descriptor
                    .as_ref()
                    .map(|(_, _, _, event_kind, ..)| event_kind.to_string())
            })
            .unwrap_or_default(),
        header_process_id: 8,
        header_thread_id: 9,
        header_flags: 0,
        timestamp_qpc: i64::try_from(ordinal).unwrap(),
        raw_payload_hex: "00".to_owned(),
        payload_decoding: process,
        observation_decoding: observation,
    }
}

fn capture(status: CollectionStatus, kinds: &[&str]) -> Vec<u8> {
    let mut capture = WindowsRuntimeCapture {
        schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
        schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        platform: "windows".to_owned(),
        capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
        collection_status: status,
        capture_completeness: "unknown".to_owned(),
        started_at_unix_ms: 1,
        ended_at_unix_ms: 2,
        requested_duration_seconds: 1,
        stop_reason: StopReason::TargetExited,
        target: TargetOutcome {
            process_id: 42,
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
            events_lost: 0,
            log_buffers_lost: 0,
            real_time_buffers_lost: 0,
            loss_statistics_available: true,
            observation: "zero_reported".to_owned(),
            final_snapshot_available: true,
        },
        document_sha256: String::new(),
        events: kinds
            .iter()
            .enumerate()
            .map(|(index, kind)| event(index as u64 + 1, kind))
            .collect(),
        diagnostics: Vec::new(),
    };
    capture.document_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&capture).unwrap())
    );
    serde_json::to_vec(&capture).unwrap()
}

fn run_diff(before: &[u8], after: &[u8], extra: &[&str]) -> (Temp, Output) {
    let temp = Temp::new();
    let before_path = temp.0.join("before.json");
    let after_path = temp.0.join("after.json");
    fs::write(&before_path, before).unwrap();
    fs::write(&after_path, after).unwrap();
    let mut args = vec!["diff", "--windows-runtime"];
    args.extend_from_slice(extra);
    args.push(before_path.to_str().unwrap());
    args.push(after_path.to_str().unwrap());
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(args)
        .output()
        .unwrap();
    (temp, output)
}

fn category<'a>(document: &'a Value, key: &str) -> &'a Value {
    document["categories"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["category"] == key)
        .unwrap()
}

fn document_fingerprint(bytes: &[u8]) -> String {
    let capture: Value = serde_json::from_slice(bytes).unwrap();
    capture["document_sha256"].as_str().unwrap().to_owned()
}

fn refingerprint_capture(bytes: &[u8], schema_version: u32) -> Vec<u8> {
    let mut capture: WindowsRuntimeCapture = serde_json::from_slice(bytes).unwrap();
    capture.schema_version = schema_version;
    capture.document_sha256.clear();
    let fingerprint = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&capture).unwrap())
    );
    capture.document_sha256 = fingerprint;
    serde_json::to_vec(&capture).unwrap()
}

#[test]
fn json_compares_observed_category_counts_and_preserves_ordinals() {
    let before = capture(
        CollectionStatus::Complete,
        &["process.start", "file.read_request", "network.tcp.connect"],
    );
    let after = capture(
        CollectionStatus::Complete,
        &["process.start", "file.write_request", "disk.read"],
    );
    let (_temp, output) = run_diff(&before, &after, &[]);
    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "sideeffect.windows_runtime_diff_summary");
    assert_eq!(report["schema_version"], 3);
    assert_eq!(
        report["algorithm"]["id"],
        "windows_etw_exact_multiset_and_unique_candidate_diff"
    );
    assert_eq!(report["algorithm"]["version"], 2);
    assert_eq!(
        report["algorithm"]["basis"],
        "fixed_category_counts_plus_exact_record_multiset_and_unique_identity_candidates"
    );
    assert_eq!(report["comparison_status"], "complete");
    assert_eq!(report["capture_completeness"], "unknown");
    assert_eq!(
        report["before"]["document_sha256"],
        document_fingerprint(&before)
    );
    assert_eq!(
        report["after"]["document_sha256"],
        document_fingerprint(&after)
    );
    assert_eq!(report["before"]["producer_collection_status"], "complete");
    assert_eq!(report["after"]["producer_collection_status"], "complete");
    assert_eq!(report["before"]["observed_event_count"], 3);
    assert_eq!(report["after"]["observed_event_count"], 3);
    assert_eq!(report["normalization_ledger"].as_array().unwrap().len(), 2);
    assert_eq!(report["normalization_ledger"][1]["field"], "timestamp_qpc");
    assert_eq!(category(&report, "process.start")["before_count"], 1);
    assert_eq!(category(&report, "process.start")["after_count"], 1);
    assert_eq!(
        category(&report, "process.start")["observed_count_delta"],
        0
    );
    assert_eq!(
        category(&report, "process.start")["before_event_ordinals"],
        json!([1])
    );
    assert_eq!(
        category(&report, "process.start")["after_event_ordinals"],
        json!([1])
    );
    assert_eq!(
        category(&report, "file_io.read_request")["before_event_ordinals"][0],
        2
    );
    assert_eq!(category(&report, "file_io.read_request")["after_count"], 0);
    assert_eq!(
        category(&report, "file_io.write_request")["after_event_ordinals"][0],
        2
    );
    assert_eq!(
        category(&report, "disk_io.read")["after_event_ordinals"][0],
        3
    );
    assert_eq!(
        category(&report, "network.tcp.connect")["before_event_ordinals"][0],
        3
    );
    assert!(report["event_changes"].as_array().is_some());
    assert!(
        report["event_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|delta| {
                delta["status"] == "unchanged"
                    && delta["category"] == "process.start"
                    && delta["before"][0]["record_ordinal"] == 1
                    && delta["after"][0]["record_ordinal"] == 1
            })
    );
    assert!(
        report["event_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|delta| {
                delta["status"] == "observed_only_before"
                    && delta["category"] == "network.tcp.connect"
                    && delta["before"][0]["capture_sha256"] == report["before"]["document_sha256"]
            })
    );
    assert!(
        report["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item.as_str()
                    .unwrap()
                    .contains("exact normalized event records")
            })
    );
}

#[test]
fn exact_event_match_excludes_qpc_but_keeps_both_source_values() {
    let before = capture(CollectionStatus::Complete, &["process.start"]);
    let mut after_value: Value = serde_json::from_slice(&before).unwrap();
    after_value["events"][0]["timestamp_qpc"] = json!(99);
    let after = refingerprint_capture(
        &serde_json::to_vec(&after_value).unwrap(),
        WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
    );
    let (_temp, output) = run_diff(&before, &after, &[]);

    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["representation_comparison"]["same_validated_representation_fingerprint"],
        false
    );
    let unchanged = report["event_changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|delta| delta["status"] == "unchanged")
        .unwrap();
    assert_eq!(unchanged["before"][0]["timestamp_qpc"], 1);
    assert_eq!(unchanged["after"][0]["timestamp_qpc"], 99);
    assert_eq!(
        report["normalization_ledger"][1]["treatment"],
        "excluded_from_exact_event_equality"
    );
    assert_eq!(
        report["normalization_ledger"][1]["source_values_retained_as"],
        "before/after event references timestamp_qpc"
    );

    let (_temp, text_output) = run_diff(&before, &after, &["--format", "text"]);
    assert_eq!(text_output.status.code(), Some(0));
    let text = String::from_utf8(text_output.stdout).unwrap();
    assert!(text.contains("field=\"timestamp_qpc\""));
    assert!(text.contains("ordinal=1 timestamp_qpc=1"));
    assert!(text.contains("ordinal=1 timestamp_qpc=99"));
}

#[test]
fn identical_capture_reports_matching_validated_representation_fingerprint() {
    let capture = capture(CollectionStatus::Complete, &["process.start"]);
    let (_temp, output) = run_diff(&capture, &capture, &[]);
    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["representation_comparison"]["same_validated_representation_fingerprint"],
        true
    );
    assert_eq!(
        report["representation_comparison"]["basis"],
        "sha256_of_canonical_validated_capture_representation"
    );
}

#[test]
fn json_reports_unique_changed_identity_as_candidate_with_both_input_references() {
    let before = capture(CollectionStatus::Complete, &["file.create_name_a"]);
    let after = capture(CollectionStatus::Complete, &["file.create_name_b"]);
    let (_temp, output) = run_diff(&before, &after, &[]);
    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let candidate = report["event_changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|delta| delta["status"] == "candidate_changed")
        .unwrap();
    assert_eq!(candidate["basis"], "unique_file_operation_and_literal_path");
    assert_eq!(candidate["before"][0]["record_ordinal"], 1);
    assert_eq!(candidate["after"][0]["record_ordinal"], 1);
    assert_eq!(
        candidate["before"][0]["capture_sha256"],
        report["before"]["document_sha256"]
    );
    assert_eq!(
        candidate["after"][0]["capture_sha256"],
        report["after"]["document_sha256"]
    );
    assert!(
        candidate["diagnostic"]
            .as_str()
            .unwrap()
            .contains("does_not_prove_same_underlying_execution")
    );
}

#[test]
fn partial_capture_never_turns_unmatched_before_events_into_removals() {
    let before = capture(CollectionStatus::Complete, &["process.start"]);
    let after = capture(CollectionStatus::Partial, &[]);
    let (_temp, output) = run_diff(&before, &after, &[]);
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["event_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|delta| {
                delta["status"] == "observed_only_before"
                    && delta["diagnostic"]
                        .as_str()
                        .unwrap()
                        .contains("other_capture_is_incomplete")
            })
    );
    assert!(
        !report["event_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|delta| delta["status"] == "removed")
    );
}

#[test]
fn text_is_terminal_safe_and_partial_collection_exits_two() {
    let before = capture(CollectionStatus::Complete, &["process.start"]);
    let after = capture(CollectionStatus::Partial, &["process.start"]);
    let (_temp, output) = run_diff(&before, &after, &["--format", "text"]);
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Observed category count deltas"));
    assert!(text.contains("One-sided observations are not removals or additions"));
    assert!(text.contains("Capture completeness remains unknown"));
    assert!(text.contains("event absence, operation success, causation, or target attribution"));
    assert!(text.contains("Exact-match normalization ledger"));
    assert!(text.contains("field=\"timestamp_qpc\""));
}

#[test]
fn malformed_and_digest_mismatch_inputs_are_rejected_before_comparison() {
    let before = capture(CollectionStatus::Complete, &["process.start"]);
    let (_temp, malformed) = run_diff(&br#"{"schema":"wrong"}"#[..], &before, &[]);
    assert_eq!(malformed.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&malformed.stderr)
            .contains("before Windows runtime validation failed")
    );

    let mut changed: Value = serde_json::from_slice(&before).unwrap();
    changed["events"][0]["header_process_id"] = json!(77);
    let changed = serde_json::to_vec(&changed).unwrap();
    let (_temp, mismatch) = run_diff(&before, &changed, &[]);
    assert_eq!(mismatch.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&mismatch.stderr)
            .contains("after Windows runtime validation failed")
    );
}

#[test]
fn correctly_refingerprinted_unsupported_capture_version_is_rejected() {
    let before = capture(CollectionStatus::Complete, &["process.start"]);
    let unsupported = refingerprint_capture(&before, WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION + 1);

    let (_temp, output) = run_diff(&before, &unsupported, &[]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("after Windows runtime validation failed"));
    assert!(stderr.contains("unsupported Windows runtime schema version"));
}

#[test]
fn html_uses_static_csp_and_refuses_to_replace_existing_report() {
    let before = capture(CollectionStatus::Complete, &["process.start"]);
    let after = capture(
        CollectionStatus::Complete,
        &["process.start", "file.write_request"],
    );
    let temp = Temp::new();
    let before_path = temp.0.join("before.json");
    let after_path = temp.0.join("after.json");
    let report_path = temp.0.join("report.html");
    fs::write(&before_path, &before).unwrap();
    fs::write(&after_path, &after).unwrap();

    #[cfg(windows)]
    {
        let run = || {
            Command::new(env!("CARGO_BIN_EXE_sideeffect"))
                .args(["diff", "--format", "html", "--output"])
                .arg(&report_path)
                .arg("--windows-runtime")
                .arg(&before_path)
                .arg(&after_path)
                .output()
                .unwrap()
        };
        let first = run();
        assert_eq!(
            first.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        let html = fs::read_to_string(&report_path).unwrap();
        assert!(html.contains("default-src 'none'"));
        assert!(html.contains("connect-src 'none'"));
        assert!(html.contains("script-src 'none'"));
        assert!(html.contains("Exact-match normalization ledger"));
        assert!(html.contains("timestamp_qpc"));
        assert!(html.contains("QPC timestamp 1"));
        assert!(
            html.contains(
                "Category counts and one-sided observations do not establish event absence"
            )
        );
        assert!(!html.contains("<script"));
        let second = run();
        assert_eq!(second.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&second.stderr).contains("without replacing a file"));
        assert_eq!(fs::read_to_string(&report_path).unwrap(), html);
    }

    #[cfg(not(windows))]
    {
        let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .args(["diff", "--format", "html", "--output"])
            .arg(&report_path)
            .arg("--windows-runtime")
            .arg(&before_path)
            .arg(&after_path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("available only in native Windows builds")
        );
        assert!(!report_path.exists());
    }
}

#[test]
fn html_format_and_output_after_runtime_flag_are_supported_or_explicitly_rejected() {
    let before = capture(CollectionStatus::Complete, &["process.start"]);
    let after = capture(
        CollectionStatus::Complete,
        &["process.start", "file.write_request"],
    );
    let temp = Temp::new();
    let before_path = temp.0.join("before.json");
    let after_path = temp.0.join("after.json");
    let report_path = temp.0.join("report-after-runtime-flag.html");
    fs::write(&before_path, before).unwrap();
    fs::write(&after_path, after).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", "--windows-runtime", "--format", "html", "--output"])
        .arg(&report_path)
        .arg(&before_path)
        .arg(&after_path)
        .output()
        .unwrap();
    #[cfg(windows)]
    {
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            fs::read_to_string(&report_path)
                .unwrap()
                .contains("Category count deltas")
        );
    }
    #[cfg(not(windows))]
    {
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("available only in native Windows builds")
        );
        assert!(!report_path.exists());
    }
}
