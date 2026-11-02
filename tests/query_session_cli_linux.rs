#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sideeffect::audit_session::{
    AUDIT_SESSION_SCHEMA, AUDIT_SESSION_SCHEMA_VERSION, ArtifactKind, AuditSessionManifest,
    AuditSessionSource, CoverageManifest, IntervalSemantics, LossMetadata, SessionArtifactRef,
    SessionStatus, SourceRole, SourceStatus, collector_identity,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const TRACE: &[u8] = b"123 1700000000.1 openat(AT_FDCWD, \"/tmp/item\", O_RDONLY) = 3\n";
const QUERY: &[u8] = br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"event_kind":"openat"},"limit":5}"#;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-query-session-linux-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn run_manifest(
    trace: &[u8],
    mismatched_binding: bool,
    oversized: bool,
    malformed: bool,
) -> Vec<u8> {
    let trace_hash = if mismatched_binding {
        "0".repeat(64)
    } else {
        hash(trace)
    };
    let version = if oversized {
        "x".repeat(sideeffect::limits::MAX_BUNDLE_MANIFEST_BYTES + 1)
    } else {
        "0.1.0".to_owned()
    };
    let valid = serde_json::to_vec(&json!({
        "schema": "sideeffect.run",
        "schema_version": 2,
        "producer": {
            "sideeffect_version": version,
            "operating_system": "linux",
            "architecture": "x86_64"
        },
        "capture": {
            "tracer": {"name":"strace","major":6,"minor":8},
            "capture_profile":"linux_process_file_network_v1",
            "strace_reported_status":{"kind":"exit_code","value":0},
            "command_outcome":"not_independently_verified",
            "completeness":"unknown",
            "command_stdout":"inherited_not_captured",
            "command_stderr":"inherited_not_captured",
            "tracer_diagnostics":"inherited_not_captured",
            "time_limit_milliseconds":null,
            "stop_reason":"tracer_exited"
        },
        "trace": {
            "name":"trace.strace",
            "format":"strace_text",
            "byte_length":trace.len(),
            "sha256":trace_hash
        }
    }))
    .unwrap();
    if malformed {
        b"{\"schema\":\"sideeffect.run\"".to_vec()
    } else {
        valid
    }
}

fn write_session(path: &Path, runtime: Option<(&[u8], bool, bool, bool)>) {
    write_session_with_id(path, runtime, "0123456789abcdef0123456789abcdef");
}

fn write_session_with_id(
    path: &Path,
    runtime: Option<(&[u8], bool, bool, bool)>,
    session_id: &str,
) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    let mut artifacts = Vec::new();
    if let Some((trace, mismatched_binding, oversized_manifest, malformed_manifest)) = runtime {
        let run = run_manifest(
            trace,
            mismatched_binding,
            oversized_manifest,
            malformed_manifest,
        );
        artifacts = vec![
            SessionArtifactRef {
                kind: ArtifactKind::RuntimeManifest,
                path: "run.json".to_owned(),
                schema: "sideeffect.run".to_owned(),
                schema_version: 2,
                byte_length: run.len() as u64,
                sha256: hash(&run),
            },
            SessionArtifactRef {
                kind: ArtifactKind::RuntimeTrace,
                path: "trace.strace".to_owned(),
                schema: "strace_text".to_owned(),
                schema_version: 1,
                byte_length: trace.len() as u64,
                sha256: hash(trace),
            },
        ];
        write_private(path, "run.json", &run);
        write_private(path, "trace.strace", trace);
    }
    let source = AuditSessionSource {
        role: SourceRole::Runtime,
        collector: Some(collector_identity("linux", SourceRole::Runtime)),
        platform: "linux".to_owned(),
        scope: "synthetic fixture only; one selected command and traced children".to_owned(),
        started_at_unix_ms: 1_000,
        ended_at_unix_ms: 1_002,
        status: if artifacts.is_empty() {
            SourceStatus::Unavailable
        } else {
            SourceStatus::Partial
        },
        applied_limits: vec![],
        requested_settings: vec![],
        effective_settings: vec![],
        loss: Some(LossMetadata::unknown()),
        diagnostic_codes: if artifacts.is_empty() {
            vec!["runtime_capture_unavailable".to_owned()]
        } else {
            vec!["runtime_capture_completeness_unknown".to_owned()]
        },
        artifacts,
    };
    let manifest = AuditSessionManifest {
        schema: AUDIT_SESSION_SCHEMA.to_owned(),
        schema_version: AUDIT_SESSION_SCHEMA_VERSION,
        session_id: session_id.to_owned(),
        platform: "linux".to_owned(),
        architecture: "x86_64".to_owned(),
        started_at_unix_ms: 1_000,
        ended_at_unix_ms: 1_002,
        interval_semantics: IntervalSemantics::BestEffortNonAtomic,
        status: SessionStatus::Partial,
        sources: vec![source],
        host_context: Some(sideeffect::audit_session::HostContext {
            os_name: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some("Linux".to_owned()),
            },
            os_version: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some("synthetic fixture".to_owned()),
            },
            privilege: sideeffect::audit_session::PrivilegeContext::NotElevated,
        }),
        coverage_manifest: None,
    };
    let mut manifest = manifest;
    manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));
    manifest.validate().unwrap();
    write_private(
        path,
        "session.json",
        &serde_json::to_vec(&manifest).unwrap(),
    );
}

fn write_private(directory: &Path, name: &str, bytes: &[u8]) {
    let path = directory.join(name);
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn query(directory: &TestDirectory, session_name: &str) -> Output {
    let session = directory.0.join(session_name);
    let query = directory.0.join("query.json");
    fs::write(&query, QUERY).unwrap();
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(query)
        .args(["--session"])
        .arg(session)
        .args(["--source", "runtime"])
        .output()
        .unwrap()
}

fn multi_query(directory: &TestDirectory, session_names: &[&str], text: bool) -> Output {
    let query = directory.0.join("query.json");
    fs::write(&query, QUERY).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
    command.args(["query", "--query"]).arg(query);
    for name in session_names {
        command.args(["--session"]).arg(directory.0.join(name));
    }
    command.args(["--source", "runtime"]);
    if text {
        command.args(["--format", "text"]);
    }
    command.output().unwrap()
}

fn multi_query_with_filter(
    directory: &TestDirectory,
    session_names: &[&str],
    query_json: &[u8],
) -> Output {
    let query = directory.0.join("query.json");
    fs::write(&query, query_json).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
    command.args(["query", "--query"]).arg(query);
    for name in session_names {
        command.args(["--session"]).arg(directory.0.join(name));
    }
    command.args(["--source", "runtime"]);
    command.output().unwrap()
}

fn selected_root_document(version: u32, status: &str, display_name: &str) -> Vec<u8> {
    let mut entry = json!({
        "ordinal": 0,
        "display_name": display_name,
        "name_bytes_hex": "62696e617279ff",
        "object_type": "regular_file",
        "size_bytes": 12,
        "modified_at_unix_ms": 1700000000000i64,
        "device_or_volume_serial": 1,
        "inode_or_file_index": 2,
        "evidence": {"source":"selected_root_directory_entry", "entry_ordinal":0}
    });
    let mut document = json!({
        "schema":"sideeffect.selected_root_inventory",
        "schema_version":version,
        "platform":"linux",
        "scope":if version == 1 { "one_explicit_root_and_its_direct_children_metadata_only" } else { "one_explicit_root_and_its_direct_children_metadata_and_opt_in_sha256" },
        "captured_started_at_unix_ms":1700000000000u64,
        "captured_ended_at_unix_ms":1700000000001u64,
        "status":status,
        "root":{"display_path":"/synthetic/root","path_bytes_hex":"2f73796e7468657469632f726f6f74","object_type":"directory","device_or_volume_serial":1,"inode_or_file_index":3},
        "entries":[entry],
        "diagnostics":if status == "partial" { json!([{"code":"entry_metadata_failed","entry_ordinal":1,"native_error":5}]) } else { json!([]) },
        "limits":{"max_root_path_bytes_or_utf16_units":4095,"max_entries":10000,"max_name_bytes_or_utf16_units":32767,"max_aggregate_name_bytes":8388608,"deadline_seconds":5}
    });
    if version == 2 {
        entry["content_sha256"] = json!("a".repeat(64));
        entry["content_hash_status"] = json!("observed");
        document["entries"] = json!([entry]);
        document["content_hashing"] = json!({
            "requested":true,"algorithm":"sha256","max_file_bytes":16777216,
            "max_aggregate_bytes":67108864,"deadline_seconds":5
        });
    }
    serde_json::to_vec(&document).unwrap()
}

fn write_selected_root_session(
    path: &Path,
    session_id: &str,
    artifact_bytes: &[u8],
    source_status: SourceStatus,
    schema_version: u32,
) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    let artifact = SessionArtifactRef {
        kind: ArtifactKind::SelectedRoot,
        path: "root-snapshot.json".to_owned(),
        schema: "sideeffect.selected_root_inventory".to_owned(),
        schema_version,
        byte_length: artifact_bytes.len() as u64,
        sha256: hash(artifact_bytes),
    };
    let source = AuditSessionSource {
        role: SourceRole::SelectedRoot,
        collector: Some(collector_identity("linux", SourceRole::SelectedRoot)),
        platform: "linux".to_owned(),
        scope: "synthetic fixture only; one selected root".to_owned(),
        started_at_unix_ms: 1_000,
        ended_at_unix_ms: 1_002,
        status: source_status,
        applied_limits: vec![],
        requested_settings: vec![],
        effective_settings: vec![],
        loss: None,
        diagnostic_codes: if source_status == SourceStatus::Complete {
            vec![]
        } else {
            vec!["selected_root_partial".to_owned()]
        },
        artifacts: vec![artifact],
    };
    let session_status = if source_status == SourceStatus::Complete {
        SessionStatus::Complete
    } else {
        SessionStatus::Partial
    };
    let mut manifest = AuditSessionManifest {
        schema: AUDIT_SESSION_SCHEMA.to_owned(),
        schema_version: AUDIT_SESSION_SCHEMA_VERSION,
        session_id: session_id.to_owned(),
        platform: "linux".to_owned(),
        architecture: "x86_64".to_owned(),
        started_at_unix_ms: 1_000,
        ended_at_unix_ms: 1_002,
        interval_semantics: IntervalSemantics::BestEffortNonAtomic,
        status: session_status,
        sources: vec![source],
        host_context: Some(sideeffect::audit_session::HostContext {
            os_name: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some("Linux".to_owned()),
            },
            os_version: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some("synthetic fixture".to_owned()),
            },
            privilege: sideeffect::audit_session::PrivilegeContext::NotElevated,
        }),
        coverage_manifest: None,
    };
    manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));
    manifest.validate().unwrap();
    write_private(
        path,
        "session.json",
        &serde_json::to_vec(&manifest).unwrap(),
    );
    write_private(path, "root-snapshot.json", artifact_bytes);
}

fn selected_root_query(
    directory: &TestDirectory,
    names: &[&str],
    query_json: &[u8],
    text: bool,
) -> Output {
    let query = directory.0.join("inventory-query.json");
    fs::write(&query, query_json).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
    command.args(["query", "--query"]).arg(query);
    for name in names {
        command.args(["--session"]).arg(directory.0.join(name));
    }
    command.args(["--source", "selected_root"]);
    if text {
        command.args(["--format", "text"]);
    }
    command.output().unwrap()
}

#[test]
fn session_query_keeps_session_source_capture_and_parse_status_separate() {
    let directory = TestDirectory::new();
    let session = directory.0.join("valid-session");
    write_session(&session, Some((TRACE, false, false, false)));
    let output = query(&directory, "valid-session");
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema"], "sideeffect.session_event_query_result");
    assert_eq!(result["session"]["status"], "partial");
    assert_eq!(result["runtime_source"]["status"], "partial");
    assert_eq!(result["capture"]["completeness"], "unknown");
    assert_eq!(result["capture"]["stop_reason"], "tracer_exited");
    assert_eq!(
        result["event_query_result"]["source_state"]["completeness"],
        "complete"
    );
    assert_eq!(
        result["runtime_source"]["artifacts"][1]["sha256"],
        hash(TRACE)
    );
    assert_eq!(
        result["event_query_result"]["events"][0]["evidence"]["line_number"],
        1
    );
    assert_eq!(
        result["runtime_source"]["diagnostic_codes"][0],
        "runtime_capture_completeness_unknown"
    );
}

#[test]
fn multi_session_query_keeps_results_and_evidence_scoped_by_session() {
    let directory = TestDirectory::new();
    for (name, id) in [
        ("before", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ("after", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    ] {
        write_session_with_id(
            &directory.0.join(name),
            Some((TRACE, false, false, false)),
            id,
        );
    }
    let output = multi_query(&directory, &["before", "after"], false);
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["schema"],
        "sideeffect.multi_session_event_query_result"
    );
    assert_eq!(result["session_count"], 2);
    assert_eq!(result["matched_count"], 2);
    assert_eq!(result["complete"], false);
    assert_eq!(
        result["sessions"][0]["session"]["session_id"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        result["sessions"][1]["session"]["session_id"],
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    for session in result["sessions"].as_array().unwrap() {
        assert_eq!(
            session["event_query_result"]["events"][0]["event_kind"],
            "openat"
        );
        assert_eq!(
            session["event_query_result"]["events"][0]["evidence"]["line_number"],
            1
        );
    }
}

#[test]
fn multi_session_query_text_keeps_both_session_headings() {
    let directory = TestDirectory::new();
    for (name, id) in [
        ("one", "cccccccccccccccccccccccccccccccc"),
        ("two", "dddddddddddddddddddddddddddddddd"),
    ] {
        write_session_with_id(
            &directory.0.join(name),
            Some((TRACE, false, false, false)),
            id,
        );
    }
    let output = multi_query(&directory, &["one", "two"], true);
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("cccccccccccccccccccccccccccccccc"));
    assert!(text.contains("dddddddddddddddddddddddddddddddd"));
    assert_eq!(text.matches("Event query: linux").count(), 2);
}

#[test]
fn multi_session_query_rejects_duplicate_ids_and_source_local_filters() {
    let directory = TestDirectory::new();
    write_session(
        &directory.0.join("same"),
        Some((TRACE, false, false, false)),
    );
    let duplicate = multi_query(&directory, &["same", "same"], false);
    assert_eq!(duplicate.status.code(), Some(1));
    assert!(duplicate.stdout.is_empty());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("duplicate session IDs"));

    let local_id = multi_query_with_filter(
        &directory,
        &["missing-one", "missing-two"],
        br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"process_observation_id":1}}"#,
    );
    assert_eq!(local_id.status.code(), Some(1));
    assert!(local_id.stdout.is_empty());
    assert!(String::from_utf8_lossy(&local_id.stderr).contains("source-local"));
}

#[test]
fn session_query_rejects_unbound_malformed_and_oversized_run_manifests() {
    let directory = TestDirectory::new();
    for (name, mismatch, oversized, malformed, expected) in [
        (
            "mismatch",
            true,
            false,
            false,
            "runtime_manifest_trace_binding_mismatch",
        ),
        (
            "oversized",
            false,
            true,
            false,
            "runtime_manifest_limit_exceeded",
        ),
        ("malformed", false, false, true, "run.json"),
    ] {
        write_session(
            &directory.0.join(name),
            Some((TRACE, mismatch, oversized, malformed)),
        );
        let output = query(&directory, name);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
    }
}

#[test]
fn missing_runtime_is_an_error_instead_of_an_empty_successful_query() {
    let directory = TestDirectory::new();
    write_session(&directory.0.join("missing-runtime"), None);
    let output = query(&directory, "missing-runtime");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("runtime_artifact_missing"));
}

#[test]
fn session_query_rejects_malformed_cli_combinations() {
    let directory = TestDirectory::new();
    let query_file = directory.0.join("query.json");
    fs::write(&query_file, QUERY).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["query", "--query"])
        .arg(&query_file)
        .args([
            "--session",
            "missing",
            "--source",
            "runtime",
            "--trace",
            "other.trace",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot combine --session"));
}

#[test]
fn selected_root_query_multi_session_retains_v1_v2_status_and_entry_evidence() {
    let directory = TestDirectory::new();
    let v1 = selected_root_document(1, "complete", "binary�");
    let v2 = selected_root_document(2, "partial", "binary�");
    write_selected_root_session(
        &directory.0.join("v1"),
        "11111111111111111111111111111111",
        &v1,
        SourceStatus::Complete,
        1,
    );
    write_selected_root_session(
        &directory.0.join("v2"),
        "22222222222222222222222222222222",
        &v2,
        SourceStatus::Partial,
        2,
    );
    let query = br#"{"schema":"sideeffect.inventory_query","schema_version":1,"filters":{"root_path_hex":"2f73796e7468657469632f726f6f74","entry_name_hex":"62696e617279ff"},"limit":10}"#;
    let output = selected_root_query(&directory, &["v1", "v2"], query, false);
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema"], "sideeffect.inventory_query_result");
    assert_eq!(result["session_count"], 2);
    assert_eq!(result["matched_count"], 2);
    assert_eq!(result["complete"], false);
    assert_eq!(
        result["filter"]["root_path_hex"],
        "2f73796e7468657469632f726f6f74"
    );
    assert_eq!(result["filter"]["entry_name_hex"], "62696e617279ff");
    assert_eq!(result["limit"], 10);
    assert_eq!(
        result["sessions"][0]["session"]["session_id"],
        "11111111111111111111111111111111"
    );
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["artifact"]["schema_version"],
        1
    );
    assert_eq!(
        result["sessions"][1]["selected_root_source"]["artifact"]["schema_version"],
        2
    );
    assert_eq!(
        result["sessions"][1]["selected_root_source"]["status"],
        "partial"
    );
    assert_eq!(
        result["sessions"][1]["selected_root_source"]["inventory_diagnostics"][0]["code"],
        "entry_metadata_failed"
    );
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["entries"][0]["name_hex"],
        "62696e617279ff"
    );
    assert_eq!(
        result["sessions"][1]["selected_root_source"]["entries"][0]["content_hash_status"],
        "observed"
    );
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["entries"][0]["evidence"]["entry_ordinal"],
        0
    );
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["entries"][0]["evidence"]["artifact_path"],
        "root-snapshot.json"
    );
}

#[test]
fn selected_root_query_text_escapes_control_characters_and_duplicate_ids_fail_closed() {
    let directory = TestDirectory::new();
    let root = selected_root_document(1, "complete", "file\u{1b}[31m<script>");
    write_selected_root_session(
        &directory.0.join("one"),
        "33333333333333333333333333333333",
        &root,
        SourceStatus::Complete,
        1,
    );
    let query = br#"{"schema":"sideeffect.inventory_query","schema_version":1}"#;
    let text = selected_root_query(&directory, &["one"], query, true);
    assert_eq!(text.status.code(), Some(0));
    let rendered = String::from_utf8(text.stdout).unwrap();
    assert!(!rendered.contains('\u{1b}'));
    assert!(rendered.contains("\\u{1b}"));
    assert!(rendered.contains("root_path_hex: 2f73796e7468657469632f726f6f74"));

    let duplicate = selected_root_query(&directory, &["one", "one"], query, false);
    assert_eq!(duplicate.status.code(), Some(1));
    assert!(duplicate.stdout.is_empty());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("duplicate session IDs"));
}

#[test]
fn selected_root_query_rejects_unknown_duplicate_and_oversized_documents() {
    let directory = TestDirectory::new();
    let base = selected_root_document(1, "complete", "item");
    for (name, bytes) in [
        ("unknown", {
            let mut value: Value = serde_json::from_slice(&base).unwrap();
            value["unknown_field"] = json!(true);
            serde_json::to_vec(&value).unwrap()
        }),
        ("duplicate", {
            String::from_utf8(base.clone())
                .unwrap()
                .replace(
                    "\"status\":\"complete\"",
                    "\"status\":\"complete\",\"status\":\"complete\"",
                )
                .into_bytes()
        }),
        ("oversized", {
            let mut value: Value = serde_json::from_slice(&base).unwrap();
            let first = value["entries"][0].clone();
            value["entries"] = json!(
                (0..10_001)
                    .map(|ordinal| {
                        let mut entry = first.clone();
                        entry["ordinal"] = json!(ordinal);
                        entry["evidence"]["entry_ordinal"] = json!(ordinal);
                        entry
                    })
                    .collect::<Vec<_>>()
            );
            serde_json::to_vec(&value).unwrap()
        }),
    ] {
        let path = directory.0.join(name);
        write_selected_root_session(
            &path,
            "44444444444444444444444444444444",
            &bytes,
            SourceStatus::Complete,
            1,
        );
        let query = br#"{"schema":"sideeffect.inventory_query","schema_version":1}"#;
        let output = selected_root_query(&directory, &[name], query, false);
        assert_eq!(output.status.code(), Some(1), "{name}");
        assert!(output.stdout.is_empty(), "{name}");
    }
}

#[test]
fn selected_root_query_rejects_noncanonical_query_encoding() {
    let directory = TestDirectory::new();
    let root = selected_root_document(1, "complete", "item");
    write_selected_root_session(
        &directory.0.join("root"),
        "55555555555555555555555555555555",
        &root,
        SourceStatus::Complete,
        1,
    );
    let query = br#"{"schema":"sideeffect.inventory_query","schema_version":1,"filters":{"entry_name_hex":"62696E617279"}}"#;
    let output = selected_root_query(&directory, &["root"], query, false);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

#[test]
fn selected_root_query_preserves_partial_source_without_root_identity() {
    let directory = TestDirectory::new();
    let mut document: Value =
        serde_json::from_slice(&selected_root_document(1, "partial", "item")).unwrap();
    document["root"] = Value::Null;
    document["entries"] = json!([]);
    let bytes = serde_json::to_vec(&document).unwrap();
    write_selected_root_session(
        &directory.0.join("root-unknown"),
        "66666666666666666666666666666666",
        &bytes,
        SourceStatus::Partial,
        1,
    );
    let query = br#"{"schema":"sideeffect.inventory_query","schema_version":1}"#;
    let output = selected_root_query(&directory, &["root-unknown"], query, false);
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["inventory_status"],
        "partial"
    );
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["root_path_hex"],
        Value::Null
    );
    assert_eq!(
        result["sessions"][0]["selected_root_source"]["matched_count"],
        0
    );
}

#[test]
fn selected_root_query_rejects_aggregate_name_bytes_over_limit() {
    let directory = TestDirectory::new();
    let mut document: Value =
        serde_json::from_slice(&selected_root_document(1, "complete", "item")).unwrap();
    let first = document["entries"][0].clone();
    let large_name = "61".repeat(32_767);
    document["entries"] = json!(
        (0..257)
            .map(|ordinal| {
                let mut entry = first.clone();
                entry["ordinal"] = json!(ordinal);
                entry["name_bytes_hex"] = json!(large_name);
                entry["evidence"]["entry_ordinal"] = json!(ordinal);
                entry
            })
            .collect::<Vec<_>>()
    );
    let bytes = serde_json::to_vec(&document).unwrap();
    write_selected_root_session(
        &directory.0.join("large-names"),
        "77777777777777777777777777777777",
        &bytes,
        SourceStatus::Complete,
        1,
    );
    let query = br#"{"schema":"sideeffect.inventory_query","schema_version":1}"#;
    let output = selected_root_query(&directory, &["large-names"], query, false);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("aggregate names"));
}
