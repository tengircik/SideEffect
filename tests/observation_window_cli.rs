use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sideeffect::audit_session::{
    ArtifactKind, AuditSessionManifest, AuditSessionSource, CoverageManifest, HostContext,
    IntervalSemantics, LossMetadata, SessionArtifactRef, SessionStatus, SourceRole, SourceStatus,
};
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(target_os = "linux")]
fn root_snapshot(entries: Value, start: u128, end: u128) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema":"sideeffect.selected_root_inventory",
        "schema_version":1,
        "platform":"linux",
        "scope":"one_explicit_root_and_its_direct_children_metadata_only",
        "captured_started_at_unix_ms":start,
        "captured_ended_at_unix_ms":end,
        "status":"complete",
        "root":{
            "display_path":"/tmp/synthetic-observation-root",
            "path_bytes_hex":"2f746d702f73796e7468657469632d6f62736572766174696f6e2d726f6f74",
            "object_type":"directory",
            "device_or_volume_serial":1,
            "inode_or_file_index":2
        },
        "entries":entries,
        "diagnostics":[],
        "limits":{
            "max_root_path_bytes_or_utf16_units":4095,
            "max_entries":10000,
            "max_name_bytes_or_utf16_units":32767,
            "max_aggregate_name_bytes":8388608,
            "deadline_seconds":5
        }
    }))
    .unwrap()
}

#[cfg(windows)]
fn root_snapshot(entries: Value, start: u128, end: u128) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema":"sideeffect.selected_root_inventory",
        "schema_version":1,
        "platform":"windows",
        "scope":"one_explicit_root_and_its_direct_children_metadata_only",
        "captured_started_at_unix_ms":start,
        "captured_ended_at_unix_ms":end,
        "status":"complete",
        "root":{
            "display_path":"C:\\Synthetic\\ObservationRoot",
            "path_utf16le_hex":"43003a005c00530079006e007400680065007400690063005c004f00620073006500720076006100740069006f006e0052006f006f007400",
            "object_type":"directory",
            "device_or_volume_serial":1,
            "inode_or_file_index":2
        },
        "entries":entries,
        "diagnostics":[],
        "limits":{
            "max_root_path_bytes_or_utf16_units":32766,
            "max_entries":10000,
            "max_name_bytes_or_utf16_units":32767,
            "max_aggregate_name_bytes":8388608,
            "deadline_seconds":5
        }
    })).unwrap()
}

fn entry() -> Value {
    #[cfg(target_os = "linux")]
    let object_type = "regular_file";
    #[cfg(windows)]
    let object_type = "regular_or_other_file";
    #[cfg(target_os = "linux")]
    let identity = json!({"name_bytes_hex":"6e6577"});
    #[cfg(windows)]
    let identity = json!({"name_utf16le_hex":"6e0065007700"});
    json!({
        "ordinal":0,
        "display_name":"new",
        "object_type":object_type,
        "size_bytes":3,
        "modified_at_unix_ms":10,
        "device_or_volume_serial":1,
        "inode_or_file_index":12,
        "evidence":{"source":"selected_root_directory_entry","entry_ordinal":0}
    })
    .as_object()
    .map(|row| {
        let mut row = row.clone();
        row.extend(identity.as_object().unwrap().clone());
        Value::Object(row)
    })
    .unwrap()
}

fn observation_files() -> Vec<(&'static str, Vec<u8>)> {
    let before = root_snapshot(json!([]), 1000, 1001);
    let after = root_snapshot(json!([entry()]), 1002, 1003);
    let platform = if cfg!(windows) { "windows" } else { "linux" };
    let root_source = AuditSessionSource {
        role: SourceRole::SelectedRoot,
        collector: Some(sideeffect::audit_session::collector_identity(
            platform,
            SourceRole::SelectedRoot,
        )),
        platform: platform.to_owned(),
        scope: "same explicitly selected directory before and after bounded runtime capture"
            .to_owned(),
        started_at_unix_ms: 1000,
        ended_at_unix_ms: 1003,
        status: SourceStatus::Complete,
        applied_limits: vec![],
        requested_settings: vec![],
        effective_settings: vec![],
        loss: None,
        diagnostic_codes: vec![],
        artifacts: vec![
            SessionArtifactRef {
                kind: ArtifactKind::SelectedRoot,
                path: "root-snapshot.json".to_owned(),
                schema: "sideeffect.selected_root_inventory".to_owned(),
                schema_version: 1,
                byte_length: before.len() as u64,
                sha256: digest(&before),
            },
            SessionArtifactRef {
                kind: ArtifactKind::SelectedRootAfter,
                path: "root-snapshot-after.json".to_owned(),
                schema: "sideeffect.selected_root_inventory".to_owned(),
                schema_version: 1,
                byte_length: after.len() as u64,
                sha256: digest(&after),
            },
        ],
    };
    let runtime_source = AuditSessionSource {
        role: SourceRole::Runtime,
        collector: Some(sideeffect::audit_session::collector_identity(
            platform,
            SourceRole::Runtime,
        )),
        platform: platform.to_owned(),
        scope: "synthetic fixture runtime source; no live capture".to_owned(),
        started_at_unix_ms: 1001,
        ended_at_unix_ms: 1002,
        status: SourceStatus::Partial,
        applied_limits: vec![],
        requested_settings: vec![],
        effective_settings: vec![],
        loss: Some(LossMetadata::unknown()),
        diagnostic_codes: vec!["synthetic_fixture_not_a_live_capture".to_owned()],
        artifacts: vec![],
    };
    let sources = vec![root_source, runtime_source];
    let manifest = AuditSessionManifest {
        schema: sideeffect::audit_session::AUDIT_SESSION_SCHEMA.to_owned(),
        schema_version: sideeffect::audit_session::AUDIT_SESSION_V16_SCHEMA_VERSION,
        session_id: "0123456789abcdef0123456789abcdef".to_owned(),
        platform: platform.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        host_context: Some(HostContext {
            os_name: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some(if cfg!(windows) { "Windows" } else { "Linux" }.to_owned()),
            },
            os_version: sideeffect::audit_session::ContextFact {
                status: sideeffect::audit_session::ContextFactStatus::Observed,
                value: Some("synthetic-test".to_owned()),
            },
            privilege: sideeffect::audit_session::PrivilegeContext::NotElevated,
        }),
        started_at_unix_ms: 1000,
        ended_at_unix_ms: 1003,
        interval_semantics: IntervalSemantics::BestEffortNonAtomic,
        status: SessionStatus::Partial,
        coverage_manifest: Some(CoverageManifest::from_sources(&sources)),
        sources,
    };
    manifest.validate().unwrap();
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    vec![
        ("root-snapshot.json", before),
        ("root-snapshot-after.json", after),
        ("session.json", manifest_bytes),
    ]
}

fn publish_observation_session() -> std::path::PathBuf {
    publish_observation_files(observation_files())
}

fn publish_observation_files(files: Vec<(&'static str, Vec<u8>)>) -> std::path::PathBuf {
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "sideeffect-observation-cli-{}-{id}",
        std::process::id()
    ));
    let session = base.join("session");
    fs::create_dir_all(&base).unwrap();
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(&session).unwrap();
        fs::set_permissions(&session, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in files {
            let path = session.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    #[cfg(windows)]
    {
        let file_refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(name, bytes)| (*name, bytes.as_slice()))
            .collect();
        sideeffect::record::publish_private_windows_directory(
            &session,
            &file_refs,
            sideeffect::audit_session::MAX_SESSION_TOTAL_ARTIFACT_BYTES as usize,
        )
        .unwrap();
    }
    session
}

#[test]
fn compare_observation_verifies_artifacts_and_keeps_partial_runtime_separate() {
    let session = publish_observation_session();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-observation")
        .arg(&session)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "sideeffect.observation_window_diff");
    assert_eq!(report["status"], "partial");
    assert_eq!(report["root_comparison_status"], "complete");
    assert_eq!(report["runtime_source_status"], "partial");
    assert_eq!(report["root_diff"]["counts"]["additions"], 1);
    assert_eq!(
        report["before_artifact"]["sha256"].as_str().unwrap().len(),
        64
    );
    assert_eq!(report["after_artifact"]["path"], "root-snapshot-after.json");
    assert_eq!(report["runtime_artifacts"].as_array().unwrap().len(), 0);
    fs::remove_dir_all(session.parent().unwrap()).unwrap();
}

#[test]
fn compare_observation_reports_unavailable_selected_root_without_presence_claims() {
    let mut files = observation_files();
    let after_index = files
        .iter()
        .position(|(name, _)| *name == "root-snapshot-after.json")
        .unwrap();
    let mut after: Value = serde_json::from_slice(&files[after_index].1).unwrap();
    after["status"] = json!("partial");
    after["root"] = Value::Null;
    after["entries"] = json!([]);
    after["diagnostics"] =
        json!([{"code":"root_open_failed","entry_ordinal":null,"native_error":2}]);
    files[after_index].1 = serde_json::to_vec(&after).unwrap();
    let manifest_index = files
        .iter()
        .position(|(name, _)| *name == "session.json")
        .unwrap();
    let mut manifest: Value = serde_json::from_slice(&files[manifest_index].1).unwrap();
    let root_source = manifest["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["role"] == "selected_root")
        .unwrap();
    root_source["status"] = json!("partial");
    root_source["diagnostic_codes"] = json!(["root_open_failed"]);
    let artifact = root_source["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|artifact| artifact["path"] == "root-snapshot-after.json")
        .unwrap();
    artifact["byte_length"] = json!(files[after_index].1.len());
    artifact["sha256"] = json!(digest(&files[after_index].1));
    let sources: Vec<AuditSessionSource> =
        serde_json::from_value(manifest["sources"].clone()).unwrap();
    manifest["coverage_manifest"] =
        serde_json::to_value(CoverageManifest::from_sources(&sources)).unwrap();
    files[manifest_index].1 = serde_json::to_vec(&manifest).unwrap();
    let session = publish_observation_files(files);
    let base = session.parent().unwrap().to_path_buf();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-observation")
        .arg(&session)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["root_comparison_status"], "partial");
    assert_eq!(
        report["root_comparison_diagnostic"],
        "selected_root_unavailable"
    );
    assert!(report["root_diff"].is_null());
    assert_eq!(report["before_artifact"]["path"], "root-snapshot.json");
    assert_eq!(report["after_artifact"]["path"], "root-snapshot-after.json");
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn observation_reader_rejects_tampered_and_missing_after_artifacts() {
    let session = publish_observation_session();
    let after = session.join("root-snapshot-after.json");
    fs::write(&after, b"{}").unwrap();
    let tampered = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-observation")
        .arg(&session)
        .output()
        .unwrap();
    assert!(!tampered.status.success());
    let files = observation_files();
    fs::write(&after, &files[1].1).unwrap();
    fs::remove_file(&after).unwrap();
    let missing = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-observation")
        .arg(&session)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    fs::remove_dir_all(session.parent().unwrap()).unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn observe_root_rejects_output_under_scope_before_tracer_or_target_launch() {
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "sideeffect-observation-overlap-cli-{}-{id}",
        std::process::id()
    ));
    let root = base.join("root");
    fs::create_dir_all(&root).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["audit", "--output"])
        .arg(root.join("session"))
        .args(["--observe-root"])
        .arg(&root)
        .args([
            "--runtime-duration-seconds",
            "1",
            "--",
            "definitely-not-started",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("overlaps --observe-root"));
    assert!(!root.join("session").exists());
    fs::remove_dir_all(base).unwrap();
}

#[test]
#[cfg(windows)]
fn observe_root_rejects_output_under_scope_before_etw_or_target_launch() {
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "sideeffect-observation-overlap-cli-{}-{id}",
        std::process::id()
    ));
    let root = base.join("root");
    fs::create_dir_all(&root).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["audit", "--output"])
        .arg(root.join("session"))
        .args(["--observe-root"])
        .arg(&root)
        .args([
            "--runtime-source",
            "windows-etw",
            "--runtime-duration-seconds",
            "1",
            "--",
            "definitely-not-started.exe",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("overlaps --observe-root"));
    assert!(!root.join("session").exists());
    fs::remove_dir_all(base).unwrap();
}
