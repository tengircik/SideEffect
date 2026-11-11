use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TempFiles(Vec<PathBuf>);

impl TempFiles {
    fn write(&mut self, suffix: &str, bytes: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-query-{}-{}.{suffix}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        self.0.push(path.clone());
        path
    }
}

impl Drop for TempFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

fn run(trace: &PathBuf, query: &PathBuf, format: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(query)
        .args(["--trace"])
        .arg(trace)
        .args(["--format", format])
        .output()
        .unwrap()
}

#[test]
fn cli_query_keeps_raw_evidence_and_emits_safe_text_or_json() {
    let mut files = TempFiles(Vec::new());
    let trace = files.write(
        "trace",
        b"123 1700000000.1 close(4) = 0\n123 1700000000.2 openat(AT_FDCWD, \"/tmp/x\", O_RDONLY) = 3\n",
    );
    let query = files.write(
        "json",
        br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"event_kind":"openat","operation_kind":"syscall_attempt"},"limit":5}"#,
    );
    let output = run(&trace, &query, "json");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema"], "sideeffect.event_query_result");
    assert_eq!(result["schema_version"], 3);
    assert_eq!(result["matched_count"], 1);
    assert_eq!(result["events"][0]["event_kind"], "openat");
    assert_eq!(result["events"][0]["evidence"]["kind"], "raw_trace_record");
    assert_eq!(result["events"][0]["evidence"]["line_number"], 2);
    assert_eq!(result["source_state"]["completeness"], "complete");

    let output = run(&trace, &query, "text");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("1 result(s)"));
    assert!(text.contains("raw_trace_record"));
}

#[test]
fn cli_query_v4_compares_decimal_timestamps_without_changing_evidence() {
    let mut files = TempFiles(Vec::new());
    let trace = files.write(
        "trace",
        b"123 9.99 close(3) = 0\n123 10.100 close(4) = 0\n123 010.19 close(5) = 0\n123 10.200 close(6) = 0\n123 10.201 close(7) = 0\n123 close(8) = 0\n",
    );
    let query = files.write(
        "json",
        br#"{"schema":"sideeffect.event_query","schema_version":4,"filters":{"event_kind":"close","timestamp":{"clock":"strace_decimal","from_inclusive":"10.1","to_inclusive":"10.20"}}}"#,
    );
    let output = run(&trace, &query, "json");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema_version"], 4);
    assert_eq!(result["matched_count"], 3);
    assert_eq!(result["events"][0]["source_timestamp"]["value"], "10.100");
    assert_eq!(result["events"][1]["source_timestamp"]["value"], "010.19");
    assert_eq!(result["events"][2]["source_timestamp"]["value"], "10.200");
    assert_eq!(result["events"][2]["evidence"]["line_number"], 4);
    let text = run(&trace, &query, "text");
    assert!(text.status.success());
    assert!(
        String::from_utf8_lossy(&text.stdout)
            .contains("timestamp=10.100 (strace_timestamp_decimal")
    );

    let wrong_clock = files.write(
        "json",
        br#"{"schema":"sideeffect.event_query","schema_version":4,"filters":{"timestamp":{"clock":"etw_qpc_ticks","from_inclusive":"10"}}}"#,
    );
    let output = run(&trace, &wrong_clock, "json");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("clock does not match"));
}

#[test]
fn cli_query_rejects_timestamp_filter_for_multiple_sessions_before_opening_them() {
    let mut files = TempFiles(Vec::new());
    let query = files.write(
        "json",
        br#"{"schema":"sideeffect.event_query","schema_version":4,"filters":{"timestamp":{"clock":"strace_decimal","to_inclusive":"10.0"}}}"#,
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(query)
        .args([
            "--session",
            "unused-1",
            "--session",
            "unused-2",
            "--source",
            "runtime",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("timestamp filters require one runtime source")
    );
}

#[test]
fn cli_query_v2_filters_exact_lexical_paths_and_displays_them_as_terminal_safe_text() {
    let mut files = TempFiles(Vec::new());
    let trace = files.write(
        "trace",
        b"123 1700000000.1 openat(AT_FDCWD</tmp>, \"<script>alert(1)</script>\", O_RDONLY) = 3\n123 1700000000.2 openat(AT_FDCWD</tmp>, \"<script>alert(1)</script>.bak\", O_RDONLY) = 4\n",
    );
    let query = files.write(
        "json",
        br#"{"schema":"sideeffect.event_query","schema_version":2,"filters":{"path_exact":"/tmp/<script>alert(1)</script>"},"limit":5}"#,
    );
    let output = run(&trace, &query, "json");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema_version"], 3);
    assert_eq!(result["matched_count"], 1);
    assert_eq!(
        result["events"][0]["path_observation"]["path"],
        "/tmp/<script>alert(1)</script>"
    );
    assert_eq!(
        result["events"][0]["path_observation"]["basis"]["kind"],
        "linux_strace_lexical_hint"
    );

    let output = run(&trace, &query, "text");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("path=/tmp/<script>alert(1)</script>"));
    assert!(!text.contains(".bak"));
    assert!(!text.contains("\u{1b}"));

    let prefix_query = files.write(
        "json",
        br#"{"schema":"sideeffect.event_query","schema_version":3,"filters":{"path_prefix":"/tmp/<script>alert(1)</script>"},"limit":5}"#,
    );
    let output = run(&trace, &prefix_query, "json");
    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema_version"], 3);
    assert_eq!(result["matched_count"], 2);
    assert_eq!(
        result["events"][1]["path_observation"]["path"],
        "/tmp/<script>alert(1)</script>.bak"
    );
}

#[test]
fn cli_query_preserves_partial_status_and_rejects_unsupported_filter_keys() {
    let mut files = TempFiles(Vec::new());
    let trace = files.write("trace", b"123 1700000000.1 close(4) = 0\nmalformed row\n");
    let query = files.write(
        "json",
        br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"event_kind":"close"}}"#,
    );
    let output = run(&trace, &query, "json");
    assert_eq!(output.status.code(), Some(2));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["source_state"]["completeness"], "partial");
    assert_eq!(result["events"].as_array().unwrap().len(), 1);
    assert_eq!(result["diagnostics"][0]["code"], "unsupported_source_row");

    let bad_query = files.write(
        "json",
        br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"path":"/tmp/x"}}"#,
    );
    let output = run(&trace, &bad_query, "json");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid event query JSON"));
}

#[test]
fn cli_query_filters_exact_raw_trace_evidence_and_keeps_full_input_status() {
    let mut files = TempFiles(Vec::new());
    let trace = files.write("trace", b"123 1700000000.1 close(4) = 0\nmalformed row\n");
    let broad_query = files.write(
        "json",
        br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"event_kind":"close"}}"#,
    );
    let baseline = run(&trace, &broad_query, "json");
    assert_eq!(baseline.status.code(), Some(2));
    let baseline: serde_json::Value = serde_json::from_slice(&baseline.stdout).unwrap();
    let evidence = baseline["events"][0]["evidence"].clone();
    let exact_query = files.write(
        "json",
        &serde_json::to_vec(&serde_json::json!({
            "schema": "sideeffect.event_query",
            "schema_version": 1,
            "filters": { "evidence": evidence }
        }))
        .unwrap(),
    );
    let exact = run(&trace, &exact_query, "json");
    assert_eq!(exact.status.code(), Some(2));
    let exact: serde_json::Value = serde_json::from_slice(&exact.stdout).unwrap();
    assert_eq!(exact["matched_count"], 1);
    assert_eq!(exact["source_state"], baseline["source_state"]);
    assert_eq!(exact["diagnostics"], baseline["diagnostics"]);

    let mut wrong_evidence = baseline["events"][0]["evidence"].clone();
    wrong_evidence["byte_offset"] =
        serde_json::json!(wrong_evidence["byte_offset"].as_u64().unwrap() + 1);
    let wrong_query = files.write(
        "json",
        &serde_json::to_vec(&serde_json::json!({
            "schema": "sideeffect.event_query",
            "schema_version": 1,
            "filters": { "evidence": wrong_evidence }
        }))
        .unwrap(),
    );
    let wrong = run(&trace, &wrong_query, "json");
    assert_eq!(wrong.status.code(), Some(2));
    let wrong: serde_json::Value = serde_json::from_slice(&wrong.stdout).unwrap();
    assert_eq!(wrong["matched_count"], 0);
    assert_eq!(wrong["source_state"], baseline["source_state"]);
    assert_eq!(wrong["diagnostics"], baseline["diagnostics"]);
}

#[cfg(windows)]
#[test]
fn cli_query_uses_native_windows_runtime_fixture_and_preserves_unknown_completeness() {
    use sha2::{Digest, Sha256};
    use sideeffect::windows_runtime::{
        AppliedLimits, CollectionStatus, DecodedProcessPayload, EventLoss,
        MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES, MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
        MAX_WINDOWS_RUNTIME_EVENTS, MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES, NativeRuntimeEvent,
        ProcessDecodeStatus, SessionMetadata, StopReason, TargetOutcome,
        WINDOWS_RUNTIME_CAPTURE_SCHEMA, WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        WindowsRuntimeCapture,
    };

    let mut capture = WindowsRuntimeCapture {
        schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
        schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        platform: "windows".to_owned(),
        capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
        collection_status: CollectionStatus::Complete,
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
            provider: "synthetic Windows ETW fixture".to_owned(),
            scope: "synthetic fixture only".to_owned(),
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
            header_process_id: 8,
            header_thread_id: 9,
            header_flags: 0x0040,
            timestamp_qpc: 10,
            raw_payload_hex: "00000000000000002a00000001000000".to_owned(),
            payload_decoding: Some(DecodedProcessPayload {
                status: ProcessDecodeStatus::Decoded,
                schema_name: Some("Process_V2_TypeGroup1".to_owned()),
                schema_version: Some(2),
                pointer_size_bytes: Some(8),
                process_id: Some(42),
                parent_process_id: Some(1),
                image_file_name: Some("synthetic.exe".to_owned()),
                diagnostic: None,
            }),
            observation_decoding: None,
        }],
        diagnostics: Vec::new(),
    };
    let canonical = serde_json::to_vec(&capture).unwrap();
    capture.document_sha256 = format!("{:x}", Sha256::digest(canonical));

    let mut files = TempFiles(Vec::new());
    let capture_path = files.write("json", &serde_json::to_vec(&capture).unwrap());
    let query_path = files.write(
        "query.json",
        br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"event_kind":"process_start","operation_kind":"native_observation"}}"#,
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(query_path)
        .args(["--windows-runtime"])
        .arg(&capture_path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["source"]["platform"], "windows");
    assert_eq!(result["source_state"]["completeness"], "unknown");
    assert_eq!(result["events"].as_array().unwrap().len(), 1);
    assert_eq!(result["events"][0]["event_kind"], "process_start");
    assert_eq!(
        result["events"][0]["evidence"]["kind"],
        "windows_etw_record"
    );

    let evidence = result["events"][0]["evidence"].clone();
    let exact_query = files.write(
        "query.json",
        &serde_json::to_vec(&serde_json::json!({
            "schema": "sideeffect.event_query",
            "schema_version": 1,
            "filters": {
                "event_kind": "process_start",
                "evidence": evidence
            }
        }))
        .unwrap(),
    );
    let exact = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(exact_query)
        .args(["--windows-runtime"])
        .arg(&capture_path)
        .output()
        .unwrap();
    assert_eq!(exact.status.code(), Some(2));
    let exact: serde_json::Value = serde_json::from_slice(&exact.stdout).unwrap();
    assert_eq!(exact["matched_count"], 1);
    assert_eq!(exact["source_state"]["completeness"], "unknown");

    let timestamp_query = files.write(
        "query.json",
        br#"{"schema":"sideeffect.event_query","schema_version":4,"filters":{"timestamp":{"clock":"etw_qpc_ticks","from_inclusive":"-2","to_inclusive":"10"}}}"#,
    );
    let timestamp = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(timestamp_query)
        .args(["--windows-runtime"])
        .arg(&capture_path)
        .output()
        .unwrap();
    assert_eq!(timestamp.status.code(), Some(2));
    let timestamp: serde_json::Value = serde_json::from_slice(&timestamp.stdout).unwrap();
    assert_eq!(timestamp["schema_version"], 4);
    assert_eq!(timestamp["matched_count"], 1);
    assert_eq!(timestamp["source_state"]["completeness"], "unknown");
    assert_eq!(timestamp["events"][0]["source_timestamp"]["value"], "10");
    assert_eq!(
        timestamp["events"][0]["evidence"],
        exact["events"][0]["evidence"]
    );
}
