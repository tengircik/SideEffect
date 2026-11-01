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
        session_id: "0123456789abcdef0123456789abcdef".to_owned(),
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
