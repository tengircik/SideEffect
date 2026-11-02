//! Synthetic contract tests for resolving case locators against verified session views.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sideeffect::audit_session::{
    AUDIT_SESSION_SCHEMA, AUDIT_SESSION_SCHEMA_VERSION, ArtifactKind, AuditSessionManifest,
    AuditSessionSource, ContextFact, ContextFactStatus, CoverageManifest, HostContext,
    IntervalSemantics, LossMetadata, PrivilegeContext, SessionArtifactRef, SessionStatus,
    SourceRole, SourceStatus,
};
use sideeffect::case::{CASE_SCHEMA, CASE_SCHEMA_VERSION, InvestigationCase};
use sideeffect::case_evidence::{VerifiedArtifactView, VerifiedSessionView, resolve_case};
use sideeffect::windows_runtime::{
    AppliedLimits, CollectionStatus, DecodedProcessPayload, EventLoss, NativeRuntimeEvent,
    ProcessDecodeStatus, SessionMetadata, StopReason, TargetOutcome,
    WINDOWS_RUNTIME_CAPTURE_SCHEMA, WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION, WindowsRuntimeCapture,
};

const LINUX_ID: &str = "0123456789abcdef0123456789abcdef";
const WINDOWS_ID: &str = "abcdef0123456789abcdef0123456789";

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn source(
    platform: &str,
    role: SourceRole,
    artifacts: Vec<SessionArtifactRef>,
) -> AuditSessionSource {
    AuditSessionSource {
        role,
        collector: Some(sideeffect::audit_session::collector_identity(
            platform, role,
        )),
        platform: platform.to_owned(),
        scope: "synthetic fixture only".to_owned(),
        started_at_unix_ms: 10,
        ended_at_unix_ms: 11,
        status: SourceStatus::Partial,
        applied_limits: vec![],
        requested_settings: vec![],
        effective_settings: vec![],
        loss: (role == SourceRole::Runtime).then(LossMetadata::unknown),
        diagnostic_codes: vec!["synthetic_fixture_partial".to_owned()],
        artifacts,
    }
}

fn manifest(
    platform: &str,
    session_id: &str,
    source: AuditSessionSource,
) -> (AuditSessionManifest, Vec<u8>) {
    let mut manifest = AuditSessionManifest {
        schema: AUDIT_SESSION_SCHEMA.to_owned(),
        schema_version: AUDIT_SESSION_SCHEMA_VERSION,
        session_id: session_id.to_owned(),
        platform: platform.to_owned(),
        architecture: "synthetic".to_owned(),
        started_at_unix_ms: 10,
        ended_at_unix_ms: 11,
        interval_semantics: IntervalSemantics::BestEffortNonAtomic,
        status: SessionStatus::Partial,
        sources: vec![source],
        host_context: Some(HostContext {
            os_name: ContextFact {
                status: ContextFactStatus::Observed,
                value: Some(platform.to_owned()),
            },
            os_version: ContextFact {
                status: ContextFactStatus::Observed,
                value: Some("synthetic fixture".to_owned()),
            },
            privilege: PrivilegeContext::NotElevated,
        }),
        coverage_manifest: None,
    };
    manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));
    manifest.validate().unwrap();
    let bytes = serde_json::to_vec(&manifest).unwrap();
    (manifest, bytes)
}

fn artifact_ref(
    kind: ArtifactKind,
    path: &str,
    schema: &str,
    version: u32,
    bytes: &[u8],
) -> SessionArtifactRef {
    SessionArtifactRef {
        kind,
        path: path.to_owned(),
        schema: schema.to_owned(),
        schema_version: version,
        byte_length: bytes.len() as u64,
        sha256: sha256(bytes),
    }
}

fn make_case(
    session_id: &str,
    platform: &str,
    manifest_bytes: &[u8],
    locator: Value,
) -> InvestigationCase {
    let value = json!({
        "schema": CASE_SCHEMA,
        "schema_version": CASE_SCHEMA_VERSION,
        "case_id": "synthetic-case",
        "title": "Synthetic evidence review",
        "sessions": [{
            "session_id": session_id,
            "platform": platform,
            "manifest_schema_version": AUDIT_SESSION_SCHEMA_VERSION,
            "manifest_sha256": sha256(manifest_bytes)
        }],
        "entries": [{
            "id": "claim-1",
            "kind": "assertion",
            "authorship": "analyst_supplied_unverified",
            "text": "Synthetic assertion; not independently verified.",
            "severity": "low",
            "confidence": "low",
            "evidence": [locator]
        }]
    });
    InvestigationCase::from_json(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn trace_fixture() -> Vec<u8> {
    b"17 connect(3, {sa_family=AF_INET, sin_port=htons(9), sin_addr=inet_addr(\"127.0.0.1\")}, 16) = -1 ECONNREFUSED (Connection refused) <script>alert(1)</script>\nmalformed trace row\n".to_vec()
}

fn first_trace_line_length(trace: &[u8]) -> usize {
    trace
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(trace.len())
}

fn linux_session(trace: &[u8]) -> (AuditSessionManifest, Vec<u8>, SessionArtifactRef) {
    let trace_ref = artifact_ref(
        ArtifactKind::RuntimeTrace,
        "trace.strace",
        "strace_text",
        1,
        trace,
    );
    let run = br#"{"schema":"sideeffect.run","schema_version":2,"fixture":"synthetic-only"}"#;
    let run_ref = artifact_ref(
        ArtifactKind::RuntimeManifest,
        "run.json",
        "sideeffect.run",
        2,
        run,
    );
    let source = source(
        "linux",
        SourceRole::Runtime,
        vec![run_ref, trace_ref.clone()],
    );
    let (manifest, bytes) = manifest("linux", LINUX_ID, source);
    (manifest, bytes, trace_ref)
}

fn windows_capture() -> Vec<u8> {
    let mut capture = WindowsRuntimeCapture {
        schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
        schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        platform: "windows".to_owned(),
        capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
        collection_status: CollectionStatus::Partial,
        capture_completeness: "unknown".to_owned(),
        started_at_unix_ms: 10,
        ended_at_unix_ms: 11,
        requested_duration_seconds: 1,
        stop_reason: StopReason::TargetExited,
        target: TargetOutcome {
            process_id: 5,
            exit_code: Some(0),
            status_available: true,
        },
        session: SessionMetadata {
            name: "NT Kernel Logger".to_owned(),
            provider: "Synthetic fixture providers".to_owned(),
            scope: "synthetic fixture only".to_owned(),
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
            loss_statistics_available: true,
            observation: "zero_reported".to_owned(),
            final_snapshot_available: true,
        },
        document_sha256: String::new(),
        events: vec![NativeRuntimeEvent {
            record_ordinal: 1,
            provider_guid: "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}".to_owned(),
            event_id: 0,
            event_version: 0,
            opcode: 1,
            event_kind: "process_start".to_owned(),
            header_process_id: 5,
            header_thread_id: 6,
            header_flags: 0,
            timestamp_qpc: 7,
            raw_payload_hex: "00a1".to_owned(),
            payload_decoding: Some(DecodedProcessPayload {
                status: ProcessDecodeStatus::Decoded,
                schema_name: Some("Process_V2_TypeGroup1".to_owned()),
                schema_version: Some(2),
                pointer_size_bytes: Some(8),
                process_id: Some(5),
                parent_process_id: Some(1),
                image_file_name: Some("synthetic-fixture.exe".to_owned()),
                diagnostic: None,
            }),
            observation_decoding: None,
        }],
        diagnostics: vec!["synthetic fixture only".to_owned()],
    };
    let unsealed = serde_json::to_vec(&capture).unwrap();
    capture.document_sha256 = sha256(&unsealed);
    serde_json::to_vec(&capture).unwrap()
}

fn root_fixture(platform: &str) -> Vec<u8> {
    let names = if platform == "linux" {
        json!({"path_bytes_hex":"2f746d70", "name_bytes_hex":"6974656d"})
    } else {
        json!({"path_utf16le_hex":"43003a005c005c0074006d007000", "name_utf16le_hex":"6900740065006d00"})
    };
    let path_field = if platform == "linux" {
        "path_bytes_hex"
    } else {
        "path_utf16le_hex"
    };
    let name_field = if platform == "linux" {
        "name_bytes_hex"
    } else {
        "name_utf16le_hex"
    };
    let mut root = json!({
        "schema":"sideeffect.selected_root_inventory", "schema_version":1,
        "platform":platform,
        "scope":"one_explicit_root_and_its_direct_children_metadata_only",
        "captured_started_at_unix_ms":10, "captured_ended_at_unix_ms":11,
        "status":"partial",
        "root":{
            "display_path":"synthetic root",
            "object_type":"directory", "device_or_volume_serial":1, "inode_or_file_index":2
        },
        "entries":[{
            "ordinal":0, "display_name":"item",
            "object_type": if platform == "linux" {"regular_file"} else {"regular_or_other_file"},
            "size_bytes":1, "modified_at_unix_ms":10,
            "device_or_volume_serial":1, "inode_or_file_index":3,
            "evidence":{"source":"selected_root_directory_entry", "entry_ordinal":0}
        }],
        "diagnostics":[],
        "limits":{
            "max_root_path_bytes_or_utf16_units": if platform == "linux" {4095} else {32766},
            "max_entries":10000, "max_name_bytes_or_utf16_units":32767,
            "max_aggregate_name_bytes":8388608, "deadline_seconds":5
        }
    });
    root["root"][path_field] = names[path_field].clone();
    root["entries"][0][name_field] = names[name_field].clone();
    root.to_string().into_bytes()
}

fn locator_value(
    kind: &str,
    extra: Value,
    session_id: &str,
    manifest_bytes: &[u8],
    artifact: &SessionArtifactRef,
) -> Value {
    let mut value = json!({
        "kind":kind, "session_id":session_id,
        "manifest_sha256":sha256(manifest_bytes), "artifact_sha256":artifact.sha256
    });
    value
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    value
}

#[test]
fn resolves_synthetic_linux_trace_and_preserves_partial_diagnostics_and_untrusted_text() {
    let trace = trace_fixture();
    let (manifest, manifest_bytes, trace_ref) = linux_session(&trace);
    let locator = locator_value(
        "linux_trace_record",
        json!({
            "line_number":1, "byte_offset":0, "byte_length":first_trace_line_length(&trace) as u64
        }),
        LINUX_ID,
        &manifest_bytes,
        &trace_ref,
    );
    let case = make_case(LINUX_ID, "linux", &manifest_bytes, locator);
    let artifacts = [
        VerifiedArtifactView {
            kind: ArtifactKind::RuntimeManifest,
            path: "run.json",
            bytes: br#"{"schema":"sideeffect.run","schema_version":2,"fixture":"synthetic-only"}"#,
        },
        VerifiedArtifactView {
            kind: ArtifactKind::RuntimeTrace,
            path: "trace.strace",
            bytes: &trace,
        },
    ];
    let resolved = resolve_case(
        &case,
        &[VerifiedSessionView {
            manifest: &manifest,
            manifest_bytes: &manifest_bytes,
            artifacts: &artifacts,
        }],
    )
    .unwrap();
    assert_eq!(resolved.facts.len(), 1);
    let record = match &resolved.facts[0].fact {
        sideeffect::case_evidence::ResolvedEvidence::LinuxTraceRecord {
            record,
            parse_status,
        } => {
            assert_eq!(*parse_status, sideeffect::model::ParseCompleteness::Partial);
            record
        }
        _ => panic!("expected synthetic Linux trace evidence"),
    };
    assert!(record.raw_line.contains("<script>alert(1)</script>"));
    assert_eq!(resolved.sessions[0].status, SessionStatus::Partial);
    assert_eq!(
        resolved.sessions[0].sources[0].diagnostic_codes,
        ["synthetic_fixture_partial"]
    );
    assert!(matches!(
        resolved.sessions[0].sources[0].artifact_review,
        Some(sideeffect::case_evidence::ArtifactReview::LinuxTrace {
            parse_status: sideeffect::model::ParseCompleteness::Partial,
            ref diagnostics
        }) if !diagnostics.is_empty()
    ));
    assert!(
        resolved
            .disclosure_note
            .contains("not producer authenticity")
    );
}

#[test]
fn refuses_wrong_manifest_artifact_and_trace_source_tuples() {
    let trace = trace_fixture();
    let (manifest, manifest_bytes, trace_ref) = linux_session(&trace);
    let mut locator = locator_value(
        "linux_trace_record",
        json!({
            "line_number":1, "byte_offset":1, "byte_length":10
        }),
        LINUX_ID,
        &manifest_bytes,
        &trace_ref,
    );
    let case = make_case(LINUX_ID, "linux", &manifest_bytes, locator.clone());
    let artifacts = [
        VerifiedArtifactView {
            kind: ArtifactKind::RuntimeManifest,
            path: "run.json",
            bytes: br#"{"schema":"sideeffect.run","schema_version":2,"fixture":"synthetic-only"}"#,
        },
        VerifiedArtifactView {
            kind: ArtifactKind::RuntimeTrace,
            path: "trace.strace",
            bytes: &trace,
        },
    ];
    let view = VerifiedSessionView {
        manifest: &manifest,
        manifest_bytes: &manifest_bytes,
        artifacts: &artifacts,
    };
    assert!(resolve_case(&case, &[view]).is_err());

    locator["byte_offset"] = json!(0);
    locator["byte_length"] = json!(trace.len() - 1);
    locator["artifact_sha256"] = json!("f".repeat(64));
    let case = make_case(LINUX_ID, "linux", &manifest_bytes, locator);
    assert!(resolve_case(&case, &[view]).is_err());

    let case = make_case(
        LINUX_ID,
        "linux",
        &manifest_bytes,
        locator_value(
            "linux_trace_record",
            json!({"line_number":1,"byte_offset":0,"byte_length":first_trace_line_length(&trace) as u64}),
            LINUX_ID,
            &manifest_bytes,
            &trace_ref,
        ),
    );
    let mut changed_manifest_bytes = manifest_bytes.clone();
    changed_manifest_bytes.push(b' ');
    let changed_view = VerifiedSessionView {
        manifest: &manifest,
        manifest_bytes: &changed_manifest_bytes,
        artifacts: &artifacts,
    };
    assert!(resolve_case(&case, &[changed_view]).is_err());
}

#[test]
fn resolves_synthetic_windows_etw_record_with_capture_and_payload_digests() {
    let capture_bytes = windows_capture();
    let capture =
        sideeffect::windows_runtime::inspect_windows_runtime_bytes(&capture_bytes).unwrap();
    let capture_ref = artifact_ref(
        ArtifactKind::WindowsRuntimeCapture,
        "runtime.windows.json",
        WINDOWS_RUNTIME_CAPTURE_SCHEMA,
        WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        &capture_bytes,
    );
    let source_row = source("windows", SourceRole::Runtime, vec![capture_ref.clone()]);
    let (session_manifest, manifest_bytes) = manifest("windows", WINDOWS_ID, source_row);
    let locator = locator_value(
        "windows_etw_record",
        json!({
            "capture_sha256":capture.document_sha256,
            "record_ordinal":1, "json_pointer":"/events/0", "raw_payload_sha256":sha256(&[0,0xa1])
        }),
        WINDOWS_ID,
        &manifest_bytes,
        &capture_ref,
    );
    let case = make_case(WINDOWS_ID, "windows", &manifest_bytes, locator);
    let artifacts = [VerifiedArtifactView {
        kind: ArtifactKind::WindowsRuntimeCapture,
        path: "runtime.windows.json",
        bytes: &capture_bytes,
    }];
    let resolved = resolve_case(
        &case,
        &[VerifiedSessionView {
            manifest: &session_manifest,
            manifest_bytes: &manifest_bytes,
            artifacts: &artifacts,
        }],
    )
    .unwrap();
    assert_eq!(resolved.facts.len(), 1);
    assert_eq!(resolved.sessions[0].status, SessionStatus::Partial);
    assert!(matches!(
        resolved.facts[0].fact,
        sideeffect::case_evidence::ResolvedEvidence::WindowsEtwRecord { .. }
    ));
    assert!(matches!(
        resolved.sessions[0].sources[0].artifact_review,
        Some(sideeffect::case_evidence::ArtifactReview::WindowsEtw {
            ref capture_completeness,
            ..
        }) if capture_completeness == "unknown"
    ));
}

#[test]
fn rejects_malformed_windows_capture_and_bad_payload_digest() {
    let capture_bytes = windows_capture();
    let capture =
        sideeffect::windows_runtime::inspect_windows_runtime_bytes(&capture_bytes).unwrap();
    let capture_ref = artifact_ref(
        ArtifactKind::WindowsRuntimeCapture,
        "runtime.windows.json",
        WINDOWS_RUNTIME_CAPTURE_SCHEMA,
        WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        &capture_bytes,
    );
    let source_row = source("windows", SourceRole::Runtime, vec![capture_ref.clone()]);
    let (session_manifest, manifest_bytes) = manifest("windows", WINDOWS_ID, source_row);
    let locator = locator_value(
        "windows_etw_record",
        json!({
            "capture_sha256":capture.document_sha256, "record_ordinal":1,
            "json_pointer":"/events/0", "raw_payload_sha256":"0".repeat(64)
        }),
        WINDOWS_ID,
        &manifest_bytes,
        &capture_ref,
    );
    let artifacts = [VerifiedArtifactView {
        kind: ArtifactKind::WindowsRuntimeCapture,
        path: "runtime.windows.json",
        bytes: &capture_bytes,
    }];
    let view = VerifiedSessionView {
        manifest: &session_manifest,
        manifest_bytes: &manifest_bytes,
        artifacts: &artifacts,
    };
    let case = make_case(WINDOWS_ID, "windows", &manifest_bytes, locator);
    assert!(resolve_case(&case, &[view]).is_err());

    let malformed = b"{";
    let malformed_ref = artifact_ref(
        ArtifactKind::WindowsRuntimeCapture,
        "runtime.windows.json",
        WINDOWS_RUNTIME_CAPTURE_SCHEMA,
        WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        malformed,
    );
    let malformed_source = source("windows", SourceRole::Runtime, vec![malformed_ref]);
    // An invalid native document is intentionally paired with a structurally valid manifest view;
    // the locator still fails in the strict ETW parser.
    let (malformed_manifest, malformed_manifest_bytes) =
        manifest("windows", WINDOWS_ID, malformed_source);
    let malformed_case = make_case(
        WINDOWS_ID,
        "windows",
        &malformed_manifest_bytes,
        locator_value(
            "windows_etw_record",
            json!({
                "capture_sha256":capture.document_sha256, "record_ordinal":1,
                "json_pointer":"/events/0", "raw_payload_sha256":sha256(&[0, 0xa1])
            }),
            WINDOWS_ID,
            &malformed_manifest_bytes,
            &artifact_ref(
                ArtifactKind::WindowsRuntimeCapture,
                "runtime.windows.json",
                WINDOWS_RUNTIME_CAPTURE_SCHEMA,
                WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
                malformed,
            ),
        ),
    );
    let malformed_artifacts = [VerifiedArtifactView {
        kind: ArtifactKind::WindowsRuntimeCapture,
        path: "runtime.windows.json",
        bytes: malformed,
    }];
    assert!(
        resolve_case(
            &malformed_case,
            &[VerifiedSessionView {
                manifest: &malformed_manifest,
                manifest_bytes: &malformed_manifest_bytes,
                artifacts: &malformed_artifacts,
            }]
        )
        .is_err()
    );
}

#[test]
fn resolves_synthetic_selected_root_entry_through_strict_inventory_query_parser() {
    let platform = if cfg!(windows) { "windows" } else { "linux" };
    let root = root_fixture(platform);
    let root_ref = artifact_ref(
        ArtifactKind::SelectedRoot,
        "root-snapshot.json",
        "sideeffect.selected_root_inventory",
        1,
        &root,
    );
    let source = source(platform, SourceRole::SelectedRoot, vec![root_ref.clone()]);
    let (manifest, manifest_bytes) = manifest(platform, LINUX_ID, source);
    let case = make_case(
        LINUX_ID,
        platform,
        &manifest_bytes,
        locator_value(
            "selected_root_entry",
            json!({"entry_ordinal":0}),
            LINUX_ID,
            &manifest_bytes,
            &root_ref,
        ),
    );
    let artifacts = [VerifiedArtifactView {
        kind: ArtifactKind::SelectedRoot,
        path: "root-snapshot.json",
        bytes: &root,
    }];
    let resolved = resolve_case(
        &case,
        &[VerifiedSessionView {
            manifest: &manifest,
            manifest_bytes: &manifest_bytes,
            artifacts: &artifacts,
        }],
    )
    .unwrap();
    assert!(matches!(
        resolved.facts[0].fact,
        sideeffect::case_evidence::ResolvedEvidence::SelectedRootEntry { .. }
    ));
    assert_eq!(resolved.sessions[0].status, SessionStatus::Partial);
}

#[test]
fn resolves_synthetic_selected_root_entries_above_general_query_limit() {
    let platform = if cfg!(windows) { "windows" } else { "linux" };
    let mut root: Value = serde_json::from_slice(&root_fixture(platform)).unwrap();
    let entries = (0..sideeffect::query::MAX_ROOT_QUERY_ENTRIES)
        .map(|ordinal| {
            let name = format!("entry{ordinal}");
            let name_hex = if platform == "linux" {
                name.as_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            } else {
                name.encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            };
            let mut entry = json!({
                "ordinal":ordinal,
                "display_name":name,
                "object_type": if platform == "linux" {"regular_file"} else {"regular_or_other_file"},
                "size_bytes":1,
                "modified_at_unix_ms":10,
                "device_or_volume_serial":1,
                "inode_or_file_index":ordinal + 3,
                "evidence":{"source":"selected_root_directory_entry", "entry_ordinal":ordinal}
            });
            if platform == "linux" {
                entry["name_bytes_hex"] = json!(name_hex);
            } else {
                entry["name_utf16le_hex"] = json!(name_hex);
            }
            entry
        })
        .collect::<Vec<_>>();
    root["entries"] = json!(entries);
    let root_bytes = serde_json::to_vec(&root).unwrap();
    let root_ref = artifact_ref(
        ArtifactKind::SelectedRoot,
        "root-snapshot.json",
        "sideeffect.selected_root_inventory",
        1,
        &root_bytes,
    );
    let source = source(platform, SourceRole::SelectedRoot, vec![root_ref.clone()]);
    let (manifest, manifest_bytes) = manifest(platform, LINUX_ID, source);
    let case_value = json!({
        "schema": CASE_SCHEMA,
        "schema_version": CASE_SCHEMA_VERSION,
        "case_id":"synthetic-large-root-case",
        "title":"Synthetic selected-root ordinal boundary",
        "sessions":[{
            "session_id":LINUX_ID,
            "platform":platform,
            "manifest_schema_version":AUDIT_SESSION_SCHEMA_VERSION,
            "manifest_sha256":sha256(&manifest_bytes)
        }],
        "entries":[{
            "id":"claim-1",
            "kind":"assertion",
            "authorship":"analyst_supplied_unverified",
            "text":"Synthetic fixture boundary check.",
            "severity":"low",
            "confidence":"low",
            "evidence":[
                locator_value("selected_root_entry", json!({"entry_ordinal":9999}), LINUX_ID, &manifest_bytes, &root_ref),
                locator_value("selected_root_entry", json!({"entry_ordinal":0}), LINUX_ID, &manifest_bytes, &root_ref)
            ]
        }]
    });
    let case = InvestigationCase::from_json(&serde_json::to_vec(&case_value).unwrap()).unwrap();
    let artifacts = [VerifiedArtifactView {
        kind: ArtifactKind::SelectedRoot,
        path: "root-snapshot.json",
        bytes: &root_bytes,
    }];
    let resolved = resolve_case(
        &case,
        &[VerifiedSessionView {
            manifest: &manifest,
            manifest_bytes: &manifest_bytes,
            artifacts: &artifacts,
        }],
    )
    .unwrap();
    let ordinals = resolved
        .facts
        .iter()
        .map(|fact| match &fact.fact {
            sideeffect::case_evidence::ResolvedEvidence::SelectedRootEntry { entry, .. } => {
                entry.ordinal
            }
            _ => panic!("expected selected-root evidence"),
        })
        .collect::<Vec<_>>();
    assert_eq!(ordinals, vec![9999, 0]);
}

#[test]
fn rejects_oversized_case_and_malformed_or_oversized_trace_artifacts() {
    assert!(
        InvestigationCase::from_json(&vec![b' '; sideeffect::case::MAX_CASE_BYTES + 1]).is_err()
    );

    let oversized = vec![b'x'; sideeffect::limits::MAX_TRACE_BYTES + 1];
    let (manifest, manifest_bytes, trace_ref) = linux_session(&oversized);
    let case = make_case(
        LINUX_ID,
        "linux",
        &manifest_bytes,
        locator_value(
            "linux_trace_record",
            json!({"line_number":1,"byte_offset":0,"byte_length":1}),
            LINUX_ID,
            &manifest_bytes,
            &trace_ref,
        ),
    );
    let artifacts = [
        VerifiedArtifactView {
            kind: ArtifactKind::RuntimeManifest,
            path: "run.json",
            bytes: br#"{"schema":"sideeffect.run","schema_version":2,"fixture":"synthetic-only"}"#,
        },
        VerifiedArtifactView {
            kind: ArtifactKind::RuntimeTrace,
            path: "trace.strace",
            bytes: &oversized,
        },
    ];
    assert!(
        resolve_case(
            &case,
            &[VerifiedSessionView {
                manifest: &manifest,
                manifest_bytes: &manifest_bytes,
                artifacts: &artifacts,
            }]
        )
        .is_err()
    );

    let malformed = b"not a strace record\xff\n";
    let (manifest, manifest_bytes, trace_ref) = linux_session(malformed);
    let case = make_case(
        LINUX_ID,
        "linux",
        &manifest_bytes,
        locator_value(
            "linux_trace_record",
            json!({"line_number":1,"byte_offset":0,"byte_length":1}),
            LINUX_ID,
            &manifest_bytes,
            &trace_ref,
        ),
    );
    let artifacts = [
        VerifiedArtifactView {
            kind: ArtifactKind::RuntimeManifest,
            path: "run.json",
            bytes: br#"{"schema":"sideeffect.run","schema_version":2,"fixture":"synthetic-only"}"#,
        },
        VerifiedArtifactView {
            kind: ArtifactKind::RuntimeTrace,
            path: "trace.strace",
            bytes: malformed,
        },
    ];
    assert!(
        resolve_case(
            &case,
            &[VerifiedSessionView {
                manifest: &manifest,
                manifest_bytes: &manifest_bytes,
                artifacts: &artifacts,
            }]
        )
        .is_err()
    );
}

#[test]
fn rejects_root_snapshot_unknown_fields_and_bad_locator_ordinal() {
    let root = root_fixture("linux");
    let root_ref = artifact_ref(
        ArtifactKind::SelectedRoot,
        "root-snapshot.json",
        "sideeffect.selected_root_inventory",
        1,
        &root,
    );
    let source_row = source("linux", SourceRole::SelectedRoot, vec![root_ref.clone()]);
    let (session_manifest, manifest_bytes) = manifest("linux", LINUX_ID, source_row);
    let case = make_case(
        LINUX_ID,
        "linux",
        &manifest_bytes,
        locator_value(
            "selected_root_entry",
            json!({"entry_ordinal":1}),
            LINUX_ID,
            &manifest_bytes,
            &root_ref,
        ),
    );
    let artifacts = [VerifiedArtifactView {
        kind: ArtifactKind::SelectedRoot,
        path: "root-snapshot.json",
        bytes: &root,
    }];
    assert!(
        resolve_case(
            &case,
            &[VerifiedSessionView {
                manifest: &session_manifest,
                manifest_bytes: &manifest_bytes,
                artifacts: &artifacts
            }]
        )
        .is_err()
    );

    let mut malformed_value: Value = serde_json::from_slice(&root).unwrap();
    malformed_value["unexpected"] = json!(true);
    let malformed = serde_json::to_vec(&malformed_value).unwrap();
    // An unknown field must be rejected by the strict selected-root validator.
    let malformed_ref = artifact_ref(
        ArtifactKind::SelectedRoot,
        "root-snapshot.json",
        "sideeffect.selected_root_inventory",
        1,
        &malformed,
    );
    let malformed_source = source(
        "linux",
        SourceRole::SelectedRoot,
        vec![malformed_ref.clone()],
    );
    let (malformed_manifest, malformed_manifest_bytes) =
        manifest("linux", LINUX_ID, malformed_source);
    let malformed_case = make_case(
        LINUX_ID,
        "linux",
        &malformed_manifest_bytes,
        locator_value(
            "selected_root_entry",
            json!({"entry_ordinal":0}),
            LINUX_ID,
            &malformed_manifest_bytes,
            &malformed_ref,
        ),
    );
    let malformed_artifacts = [VerifiedArtifactView {
        kind: ArtifactKind::SelectedRoot,
        path: "root-snapshot.json",
        bytes: &malformed,
    }];
    assert!(
        resolve_case(
            &malformed_case,
            &[VerifiedSessionView {
                manifest: &malformed_manifest,
                manifest_bytes: &malformed_manifest_bytes,
                artifacts: &malformed_artifacts
            }]
        )
        .is_err()
    );
}

#[test]
fn rejects_cross_platform_session_identity_mismatch() {
    let trace = trace_fixture();
    let (manifest, manifest_bytes, trace_ref) = linux_session(&trace);
    let case = make_case(
        LINUX_ID,
        "windows",
        &manifest_bytes,
        locator_value(
            "windows_etw_record",
            json!({
                "capture_sha256":"a".repeat(64), "record_ordinal":1,
                "json_pointer":"/events/0", "raw_payload_sha256":"b".repeat(64)
            }),
            LINUX_ID,
            &manifest_bytes,
            &trace_ref,
        ),
    );
    let artifacts = [
        VerifiedArtifactView {
            kind: ArtifactKind::RuntimeManifest,
            path: "run.json",
            bytes: br#"{"schema":"sideeffect.run","schema_version":2,"fixture":"synthetic-only"}"#,
        },
        VerifiedArtifactView {
            kind: ArtifactKind::RuntimeTrace,
            path: "trace.strace",
            bytes: &trace,
        },
    ];
    assert!(
        resolve_case(
            &case,
            &[VerifiedSessionView {
                manifest: &manifest,
                manifest_bytes: &manifest_bytes,
                artifacts: &artifacts
            }]
        )
        .is_err()
    );
}
