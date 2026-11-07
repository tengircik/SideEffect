//! Bounded native Windows audit-session collection and private publication.

use crate::audit_session::{
    AUDIT_SESSION_SCHEMA, ArtifactKind, AuditSessionManifest, AuditSessionSource, ContextFact,
    ContextFactStatus, CoverageManifest, HostContext, IntervalSemantics, PrivilegeContext,
    RuntimeCoverageDetail, SessionArtifactRef, SessionStatus, SourceRole, SourceStatus,
    UnsupportedRuntimeCategoryCode,
};
use crate::fingerprint::sha256_hex;
use crate::inventory::{
    collect_path_executables, collect_windows_app_paths, collect_windows_msix,
    collect_windows_permissions, collect_windows_processes, collect_windows_software,
    collect_windows_startup_v5, collect_windows_startup_v6, collect_windows_startup_v7,
};
use crate::record::publish_private_windows_directory;
use serde::Serialize;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_WINDOWS_SESSION_BYTES: usize = 128 * 1024 * 1024;
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Default)]
pub struct WindowsAuditOptions {
    pub software: bool,
    pub msix: bool,
    pub app_paths: bool,
    pub processes: bool,
    pub startup: bool,
    pub path_executables: bool,
    pub root_path: Option<PathBuf>,
    pub hash_root_regular_files: bool,
    pub permission_paths: Vec<PathBuf>,
    pub include_runtime: bool,
    pub runtime_duration: Option<Duration>,
    pub runtime_program: Option<OsString>,
    pub runtime_arguments: Vec<OsString>,
}

#[derive(Clone, Debug)]
pub struct PublishedWindowsAuditSession {
    pub path: PathBuf,
    pub manifest: AuditSessionManifest,
}

struct Artifact {
    kind: ArtifactKind,
    file_name: &'static str,
    schema: &'static str,
    schema_version: u32,
    bytes: Vec<u8>,
}

pub fn collect_and_publish(
    destination: &Path,
    options: &WindowsAuditOptions,
) -> Result<PublishedWindowsAuditSession, String> {
    if !options.software
        && !options.msix
        && !options.app_paths
        && !options.processes
        && !options.startup
        && !options.path_executables
        && options.root_path.is_none()
        && !options.hash_root_regular_files
        && options.permission_paths.is_empty()
        && !options.include_runtime
    {
        return Err("select at least one source for the audit session".to_owned());
    }
    if options.hash_root_regular_files && options.root_path.is_none() {
        return Err("audit --hash-regular-files requires --root DIRECTORY".to_owned());
    }
    if options.permission_paths.len() > 256 {
        return Err("permission path count exceeds the 256 path limit".to_owned());
    }
    if options.include_runtime
        != (options.runtime_duration.is_some() && options.runtime_program.is_some())
        || (!options.include_runtime
            && (options.runtime_duration.is_some()
                || options.runtime_program.is_some()
                || !options.runtime_arguments.is_empty()))
    {
        return Err(
            "Windows runtime capture requires --runtime-source windows-etw, --runtime-duration-seconds, and -- PROGRAM [ARGS...]".to_owned(),
        );
    }
    if options.include_runtime {
        match std::fs::symlink_metadata(destination) {
            Ok(_) => {
                return Err(
                    "Windows audit-session output already exists; refusing to launch the runtime command"
                        .to_owned(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "could not check Windows audit-session destination before runtime launch: {error}"
                ));
            }
        }
    }
    let started = now_ms()?;
    let mut artifacts = Vec::new();
    let mut sources = Vec::new();
    let mut runtime_coverage_detail = None;

    if options.software {
        let doc = collect_windows_software();
        let (status, diagnostics) = status_from_serialized(&doc, "status");
        let value = serde_json::to_vec(&doc)
            .map_err(|e| format!("could not serialize software inventory: {e}"))?;
        sources.push(source(
            SourceRole::Packages,
            "bounded uninstall-registry registrations",
            doc.capture_started_at_unix_ms,
            doc.capture_ended_at_unix_ms,
            status,
            diagnostics,
            vec![("max_software_registrations", 8192)],
        ));
        artifacts.push(artifact(
            ArtifactKind::WindowsSoftware,
            "software.windows.json",
            "sideeffect.windows_software_inventory",
            1,
            value,
        ));
    }
    if options.msix {
        let doc = collect_windows_msix();
        let (status, diagnostics) = status_from_serialized(&doc, "status");
        let value = serde_json::to_vec(&doc)
            .map_err(|e| format!("could not serialize MSIX inventory: {e}"))?;
        sources.push(source(
            SourceRole::Msix,
            "bounded current-user MSIX package registrations",
            doc.capture_started_at_unix_ms,
            doc.capture_ended_at_unix_ms,
            status,
            diagnostics,
            vec![
                ("max_packages", 4096),
                ("max_string_utf16_units", 32768),
                ("max_aggregate_string_utf16_units", 1_048_576),
                ("max_diagnostics", 512),
                ("scan_deadline_ms", 10000),
            ],
        ));
        artifacts.push(artifact(
            ArtifactKind::WindowsMsix,
            "msix.windows.json",
            "sideeffect.windows_msix_inventory",
            1,
            value,
        ));
    }
    if options.app_paths {
        let doc = collect_windows_app_paths();
        let (status, diagnostics) = status_from_serialized(&doc, "status");
        let value = serde_json::to_vec(&doc)
            .map_err(|e| format!("could not serialize App Paths inventory: {e}"))?;
        sources.push(source(
            SourceRole::AppPaths,
            "selected current-user native and accessible machine 32-bit and 64-bit App Paths registry entries",
            doc.capture_started_at_unix_ms,
            doc.capture_ended_at_unix_ms,
            status,
            diagnostics,
            vec![
                ("max_entries", crate::inventory::APP_PATHS_MAX_ENTRIES as u64),
                ("max_name_utf16_units", crate::inventory::APP_PATHS_MAX_NAME_UNITS as u64),
                ("max_aggregate_name_utf16_units", crate::inventory::APP_PATHS_MAX_AGGREGATE_NAME_UNITS as u64),
                ("max_value_bytes", crate::inventory::APP_PATHS_MAX_VALUE_BYTES as u64),
                ("max_aggregate_value_bytes", crate::inventory::APP_PATHS_MAX_AGGREGATE_VALUE_BYTES as u64),
                ("scan_deadline_ms", crate::inventory::APP_PATHS_MAX_SCAN_DURATION_MS as u64),
            ],
        ));
        artifacts.push(artifact(
            ArtifactKind::WindowsAppPaths,
            "app-paths.windows.json",
            "sideeffect.windows_app_path_inventory",
            1,
            value,
        ));
    }
    if options.processes {
        let doc = collect_windows_processes();
        let status = if doc.status == crate::inventory::WindowsProcessInventoryStatus::Complete {
            SourceStatus::Complete
        } else {
            SourceStatus::Partial
        };
        let diagnostics = if status == SourceStatus::Complete {
            vec![]
        } else {
            vec!["process_snapshot_partial"]
        };
        let value = serde_json::to_vec(&doc)
            .map_err(|e| format!("could not serialize process inventory: {e}"))?;
        sources.push(source(
            SourceRole::Processes,
            "visible Tool Help process snapshot, permitted image paths, and token context",
            doc.capture_started_at_unix_ms,
            doc.capture_ended_at_unix_ms,
            status,
            diagnostics,
            vec![
                ("max_processes", 8192),
                ("deadline_ms", 10000),
                ("max_token_sid_utf16_code_units", 2 * 1024 * 1024),
            ],
        ));
        artifacts.push(artifact(
            ArtifactKind::WindowsProcesses,
            "processes.windows.json",
            "sideeffect.windows_process_inventory",
            4,
            value,
        ));
    }
    if !options.permission_paths.is_empty() {
        let doc = collect_windows_permissions(&options.permission_paths);
        let (status, diagnostics) = status_from_serialized(&doc, "status");
        let value = serde_json::to_vec(&doc)
            .map_err(|e| format!("could not serialize permission inventory: {e}"))?;
        sources.push(source(
            SourceRole::Permissions,
            "explicit caller-selected paths only; no recursion or effective-access evaluation",
            doc.capture_started_at_unix_ms,
            doc.capture_ended_at_unix_ms,
            status,
            diagnostics,
            vec![
                ("max_permission_paths", 256),
                ("max_descriptor_bytes", 65536),
            ],
        ));
        artifacts.push(artifact(
            ArtifactKind::WindowsPermissions,
            "permissions.windows.json",
            "sideeffect.windows_permission_inventory",
            1,
            value,
        ));
    }
    if options.startup {
        let doc = collect_windows_startup_for_session(
            crate::audit_session::AUDIT_SESSION_V13_SCHEMA_VERSION,
        )?;
        let (status, diagnostics) = status_from_serialized(&doc, "status");
        let value = serde_json::to_vec(&doc)
            .map_err(|e| format!("could not serialize startup inventory: {e}"))?;
        sources.push(source(SourceRole::Startup, "selected Run/RunOnce, Startup folders, services including read-only delayed-auto-start configuration, visible boot/logon scheduled tasks, and local ROOT\\subscription WMI permanent event subscriptions", doc.capture_started_at_unix_ms, doc.capture_ended_at_unix_ms, status, diagnostics, vec![("max_startup_entries", 8192), ("deadline_ms_between_calls", 10000)]));
        artifacts.push(artifact(
            ArtifactKind::WindowsStartup,
            "startup.windows.json",
            "sideeffect.windows_startup_inventory",
            doc.schema_version,
            value,
        ));
    }
    if options.path_executables {
        let source_started = now_ms()?;
        let doc = collect_path_executables();
        let source_ended = now_ms()?;
        let status = match doc.status {
            "complete" => SourceStatus::Complete,
            "partial" => SourceStatus::Partial,
            _ => SourceStatus::Unknown,
        };
        let diagnostics = doc
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect();
        let value = serde_json::to_vec(&doc)
            .map_err(|e| format!("could not serialize PATH executable inventory: {e}"))?;
        sources.push(source(
            SourceRole::PathExecutables,
            "one-level metadata snapshot of the current process PATH; candidate heuristics only, no execution or shell resolution",
            source_started,
            source_ended,
            status,
            diagnostics,
            vec![
                ("max_components", doc.limits.max_components as u64),
                ("max_component_path_bytes_or_units", doc.limits.max_component_path_bytes_or_units as u64),
                ("max_entries", doc.limits.max_entries as u64),
                ("max_aggregate_path_and_name_bytes_or_units", doc.limits.max_aggregate_path_and_name_bytes_or_units as u64),
                ("max_pathext_utf16_units", doc.limits.max_pathext_utf16_units as u64),
                ("max_pathext_extensions", doc.limits.max_pathext_extensions as u64),
                ("deadline_seconds", doc.limits.deadline_seconds),
            ],
        ));
        artifacts.push(artifact(
            ArtifactKind::PathExecutables,
            "path-executables.json",
            "sideeffect.path_executable_inventory",
            1,
            value,
        ));
    }
    if let Some(root_path) = &options.root_path {
        let doc = crate::inventory::collect_root_snapshot_with_hash(
            root_path,
            options.hash_root_regular_files,
        );
        let status = match doc.status {
            "complete" => SourceStatus::Complete,
            "partial" => SourceStatus::Partial,
            _ => SourceStatus::Unknown,
        };
        let diagnostics = doc.diagnostics.iter().map(|item| item.code).collect();
        let mut root_limits = vec![
            ("max_entries", doc.limits.max_entries as u64),
            (
                "max_root_path_bytes_or_utf16_units",
                doc.limits.max_root_path_bytes_or_utf16_units as u64,
            ),
            (
                "max_name_bytes_or_utf16_units",
                doc.limits.max_name_bytes_or_utf16_units as u64,
            ),
            (
                "max_aggregate_name_bytes",
                doc.limits.max_aggregate_name_bytes as u64,
            ),
            ("deadline_seconds", doc.limits.deadline_seconds),
        ];
        if options.hash_root_regular_files {
            root_limits.extend([
                (
                    "max_file_hash_bytes",
                    crate::inventory::MAX_ROOT_FILE_HASH_BYTES,
                ),
                (
                    "max_aggregate_hash_bytes",
                    crate::inventory::MAX_ROOT_AGGREGATE_HASH_BYTES,
                ),
                (
                    "hash_deadline_seconds",
                    crate::inventory::ROOT_HASH_DEADLINE.as_secs(),
                ),
            ]);
        }
        sources.push(source(
            SourceRole::SelectedRoot,
            if options.hash_root_regular_files {
                "one explicitly selected directory and direct-child metadata; optional regular-file content fingerprints"
            } else {
                "one explicitly selected directory and direct-child metadata only"
            },
            doc.captured_started_at_unix_ms,
            doc.captured_ended_at_unix_ms,
            status,
            diagnostics,
            root_limits,
        ));
        let value = serde_json::to_vec(&doc)
            .map_err(|error| format!("could not serialize selected-root inventory: {error}"))?;
        let root_artifact = artifact(
            ArtifactKind::SelectedRoot,
            "root-snapshot.json",
            "sideeffect.selected_root_inventory",
            doc.schema_version,
            value,
        );
        if options.hash_root_regular_files {
            if let Some(root_source) = sources.last_mut() {
                root_source
                    .requested_settings
                    .push(crate::audit_session::Setting {
                        code: "hash_regular_files".to_owned(),
                        value: 1,
                    });
            }
        }
        artifacts.push(root_artifact);
    }
    if options.include_runtime {
        let duration = options.runtime_duration.ok_or_else(|| {
            "Windows runtime capture requires --runtime-duration-seconds".to_owned()
        })?;
        let program = options
            .runtime_program
            .as_deref()
            .ok_or_else(|| "Windows runtime capture requires -- PROGRAM [ARGS...]".to_owned())?;
        let (capture, bytes) = crate::record::collect_windows_runtime_capture_before_launch(
            program,
            &options.runtime_arguments,
            duration,
            || ensure_runtime_destination_absent(destination),
        )?;
        runtime_coverage_detail = runtime_coverage_detail_from_event_diagnostics(
            capture
                .events
                .iter()
                .take(crate::windows_runtime::MAX_WINDOWS_RUNTIME_EVENTS)
                .map(|event| (event.event_kind, event.observation_decoding.as_ref())),
        );
        let mut diagnostics = vec!["capture_completeness_unknown"];
        if capture.collection_status == crate::record::WindowsRuntimeCollectionStatus::Partial {
            diagnostics.push("etw_collection_partial");
        }
        if capture.event_loss.events_lost > 0
            || capture.event_loss.log_buffers_lost > 0
            || capture.event_loss.real_time_buffers_lost > 0
        {
            diagnostics.push("etw_loss_reported");
        }
        if !capture.event_loss.loss_statistics_available
            || !capture.event_loss.final_snapshot_available
        {
            diagnostics.push("etw_loss_statistics_unavailable");
        }
        if capture.stop_reason == crate::record::WindowsRuntimeStopReason::DurationLimitReached {
            diagnostics.push("duration_limit_reached");
        }
        let mut source = source(
            SourceRole::Runtime,
            "system-wide NT Kernel Logger process, selected FileIo/DiskIo, and TCP/UDP observations during a bounded window; no event attribution or completeness claim",
            capture.started_at_unix_ms,
            capture.ended_at_unix_ms,
            SourceStatus::Partial,
            diagnostics,
            vec![
                (
                    "max_duration_seconds",
                    capture.limits.maximum_duration_seconds,
                ),
                ("max_events", capture.limits.maximum_events as u64),
                (
                    "max_total_payload_bytes",
                    capture.limits.maximum_total_payload_bytes as u64,
                ),
                (
                    "max_payload_bytes_per_event",
                    capture.limits.maximum_payload_bytes_per_event as u64,
                ),
                (
                    "max_document_bytes",
                    capture.limits.maximum_document_bytes as u64,
                ),
            ],
        );
        source
            .requested_settings
            .push(crate::audit_session::Setting {
                code: "runtime_duration_seconds".to_owned(),
                value: capture.requested_duration_seconds,
            });
        source.requested_settings.extend([
            crate::audit_session::Setting {
                code: "runtime_buffer_size_kb".to_owned(),
                value: capture.session.buffer_size_kb_requested as u64,
            },
            crate::audit_session::Setting {
                code: "runtime_minimum_buffers".to_owned(),
                value: capture.session.minimum_buffers_requested as u64,
            },
            crate::audit_session::Setting {
                code: "runtime_maximum_buffers".to_owned(),
                value: capture.session.maximum_buffers_requested as u64,
            },
        ]);
        source
            .effective_settings
            .push(crate::audit_session::Setting {
                code: "runtime_buffer_count_reported".to_owned(),
                value: capture.session.buffer_count_reported as u64,
            });
        let any_loss = capture.event_loss.events_lost > 0
            || capture.event_loss.log_buffers_lost > 0
            || capture.event_loss.real_time_buffers_lost > 0;
        let statistics_available = capture.event_loss.loss_statistics_available;
        let final_snapshot_available = capture.event_loss.final_snapshot_available;
        source.loss = Some(crate::audit_session::LossMetadata {
            status: if any_loss {
                crate::audit_session::LossStatus::Reported
            } else if statistics_available && final_snapshot_available {
                crate::audit_session::LossStatus::NoneReported
            } else {
                crate::audit_session::LossStatus::Unknown
            },
            statistics_available,
            final_snapshot_available,
            events_lost: statistics_available.then_some(capture.event_loss.events_lost as u64),
            log_buffers_lost: statistics_available
                .then_some(capture.event_loss.log_buffers_lost as u64),
            real_time_buffers_lost: statistics_available
                .then_some(capture.event_loss.real_time_buffers_lost as u64),
        });
        source.artifacts.push(SessionArtifactRef {
            kind: ArtifactKind::WindowsRuntimeCapture,
            path: "runtime.windows.json".to_owned(),
            schema: "sideeffect.windows_runtime_capture".to_owned(),
            schema_version: 3,
            byte_length: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        });
        sources.push(source);
        artifacts.push(artifact(
            ArtifactKind::WindowsRuntimeCapture,
            "runtime.windows.json",
            "sideeffect.windows_runtime_capture",
            3,
            bytes,
        ));
    }

    let context = host_context();
    let ended = now_ms()?;
    let mut files: Vec<(&str, &[u8])> = artifacts
        .iter()
        .map(|a| (a.file_name, a.bytes.as_slice()))
        .collect();
    let manifest = build_manifest(
        started,
        ended,
        context,
        sources,
        &artifacts,
        runtime_coverage_detail,
        session_schema_version(options),
    )?;
    let manifest_bytes = serde_json::to_vec(&manifest)
        .map_err(|e| format!("could not serialize audit manifest: {e}"))?;
    files.push(("session.json", manifest_bytes.as_slice()));
    let total = files
        .iter()
        .try_fold(0usize, |sum, (_, bytes)| sum.checked_add(bytes.len()))
        .ok_or_else(|| "audit session size overflowed".to_owned())?;
    if total > MAX_WINDOWS_SESSION_BYTES {
        return Err("audit session exceeds the 128 MiB total byte limit".to_owned());
    }
    let path = publish_private_windows_directory(destination, &files, MAX_WINDOWS_SESSION_BYTES)
        .map_err(|e| format!("could not publish private Windows audit session: {e}"))?;
    Ok(PublishedWindowsAuditSession { path, manifest })
}

fn status_from_serialized<T: Serialize>(value: &T, key: &str) -> (SourceStatus, Vec<&'static str>) {
    let Ok(value) = serde_json::to_value(value) else {
        return (SourceStatus::Unknown, vec!["source_status_unavailable"]);
    };
    match value.get(key).and_then(serde_json::Value::as_str) {
        Some("complete") => (SourceStatus::Complete, vec![]),
        Some("partial") | Some("limit_reached") => {
            (SourceStatus::Partial, vec!["source_reported_partial"])
        }
        Some("inaccessible") => (SourceStatus::AccessDenied, vec!["source_access_denied"]),
        Some("not_present") => (SourceStatus::NotApplicable, vec!["source_not_present"]),
        Some("unavailable") => (SourceStatus::Unavailable, vec!["source_unavailable"]),
        Some("unsupported") => (SourceStatus::Unsupported, vec!["source_unsupported"]),
        Some("not_checked") => (SourceStatus::NotChecked, vec!["source_not_checked"]),
        _ => (SourceStatus::Failed, vec!["source_failed"]),
    }
}

fn ensure_runtime_destination_absent(destination: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(destination) {
        Ok(_) => Err(
            "Windows audit-session output already exists; refusing to launch the runtime command"
                .to_owned(),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "could not check Windows audit-session destination before runtime launch: {error}"
        )),
    }
}

fn source(
    role: SourceRole,
    scope: &str,
    start: u128,
    end: u128,
    status: SourceStatus,
    diagnostics: Vec<&str>,
    limits: Vec<(&str, u64)>,
) -> AuditSessionSource {
    AuditSessionSource {
        role,
        collector: Some(crate::audit_session::collector_identity("windows", role)),
        platform: "windows".to_owned(),
        scope: scope.to_owned(),
        started_at_unix_ms: start,
        ended_at_unix_ms: end,
        status,
        applied_limits: limits
            .into_iter()
            .map(|(code, value)| crate::audit_session::AppliedLimit {
                code: code.to_owned(),
                value,
            })
            .collect(),
        requested_settings: vec![],
        effective_settings: vec![],
        loss: (role == SourceRole::Runtime).then(crate::audit_session::LossMetadata::unknown),
        diagnostic_codes: diagnostics.into_iter().map(str::to_owned).collect(),
        artifacts: vec![],
    }
}

fn artifact(
    kind: ArtifactKind,
    file_name: &'static str,
    schema: &'static str,
    schema_version: u32,
    bytes: Vec<u8>,
) -> Artifact {
    Artifact {
        kind,
        file_name,
        schema,
        schema_version,
        bytes,
    }
}

fn build_manifest(
    started: u128,
    ended: u128,
    host_context: HostContext,
    mut sources: Vec<AuditSessionSource>,
    artifacts: &[Artifact],
    runtime_coverage_detail: Option<RuntimeCoverageDetail>,
    schema_version: u32,
) -> Result<AuditSessionManifest, String> {
    for source in &mut sources {
        source.artifacts = artifacts
            .iter()
            .filter(|artifact| role_kind(source.role) == Some(artifact.kind))
            .map(|artifact| SessionArtifactRef {
                kind: artifact.kind,
                path: artifact.file_name.to_owned(),
                schema: artifact.schema.to_owned(),
                schema_version: artifact.schema_version,
                byte_length: artifact.bytes.len() as u64,
                sha256: sha256_hex(&artifact.bytes),
            })
            .collect();
    }
    let complete = sources.iter().all(|s| s.status == SourceStatus::Complete);
    let coverage_manifest = Some(CoverageManifest::from_sources_with_runtime_detail(
        &sources,
        runtime_coverage_detail,
    ));
    let manifest = AuditSessionManifest {
        schema: AUDIT_SESSION_SCHEMA.to_owned(),
        schema_version,
        session_id: format!(
            "{:016x}{:016x}",
            started as u64,
            NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed)
        ),
        platform: "windows".to_owned(),
        architecture: if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else {
            "unknown"
        }
        .to_owned(),
        host_context: Some(host_context),
        started_at_unix_ms: started,
        ended_at_unix_ms: ended,
        interval_semantics: IntervalSemantics::BestEffortNonAtomic,
        status: if complete {
            SessionStatus::Complete
        } else {
            SessionStatus::Partial
        },
        sources,
        coverage_manifest,
    };
    manifest
        .validate()
        .map_err(|e| format!("constructed audit session is invalid: {e:?}"))?;
    Ok(manifest)
}

fn runtime_coverage_detail_from_event_diagnostics<'a>(
    events: impl IntoIterator<Item = (&'a str, Option<&'a serde_json::Value>)>,
) -> Option<RuntimeCoverageDetail> {
    let mut malformed_payloads = 0_u64;
    let mut unsupported_events = 0_u64;
    let mut unsupported_providers = 0_u64;
    for (event_kind, decoding) in events {
        let Some(decoding) = decoding else {
            if event_kind == "unsupported_or_malformed_provider_event" {
                return None;
            }
            continue;
        };
        match decoding.get("status").and_then(serde_json::Value::as_str) {
            Some("decoded") => {}
            Some("unsupported_provider") => unsupported_providers += 1,
            Some("unsupported_event" | "unsupported_version" | "ambiguous_pointer_width") => {
                unsupported_events += 1;
            }
            Some("malformed_payload") => malformed_payloads += 1,
            _ => return None,
        }
    }
    Some(RuntimeCoverageDetail::from_counts([
        (
            UnsupportedRuntimeCategoryCode::WindowsMalformedEtwPayloads,
            malformed_payloads,
        ),
        (
            UnsupportedRuntimeCategoryCode::WindowsUnsupportedEtwEvents,
            unsupported_events,
        ),
        (
            UnsupportedRuntimeCategoryCode::WindowsUnsupportedEtwProviders,
            unsupported_providers,
        ),
    ]))
}

fn host_context() -> HostContext {
    let version = windows_version();
    let os_version = version.map_or(
        ContextFact {
            status: ContextFactStatus::Unknown,
            value: None,
        },
        |value| ContextFact {
            status: ContextFactStatus::Observed,
            value: Some(value),
        },
    );
    HostContext {
        os_name: ContextFact {
            status: ContextFactStatus::Observed,
            value: Some("Windows".to_owned()),
        },
        os_version,
        privilege: windows_privilege(),
    }
}

#[repr(C)]
struct OsVersionInfo {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    service_pack: [u16; 128],
}

fn windows_version() -> Option<String> {
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(info: *mut OsVersionInfo) -> i32;
    }
    let mut info = OsVersionInfo {
        size: std::mem::size_of::<OsVersionInfo>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform: 0,
        service_pack: [0; 128],
    };
    // RtlGetVersion reports the native OS version without the compatibility
    // version masking applied to some higher-level version APIs.
    (unsafe { RtlGetVersion(&mut info) } == 0)
        .then(|| format!("{}.{}.{}", info.major, info.minor, info.build))
}

fn windows_privilege() -> PrivilegeContext {
    use std::ffi::c_void;
    type Handle = *mut c_void;
    #[repr(C)]
    struct TokenElevation {
        elevated: u32,
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            info: *mut c_void,
            len: u32,
            needed: *mut u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
    }
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 0x0008, &mut token) } == 0 {
        return PrivilegeContext::Unknown;
    }
    struct Token(Handle);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let token = Token(token);
    let mut elevation = TokenElevation { elevated: 0 };
    let mut needed = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            20,
            (&mut elevation as *mut TokenElevation).cast(),
            std::mem::size_of::<TokenElevation>() as u32,
            &mut needed,
        )
    } == 0
    {
        PrivilegeContext::Unknown
    } else if elevation.elevated != 0 {
        PrivilegeContext::Elevated
    } else {
        PrivilegeContext::NotElevated
    }
}

fn role_kind(role: SourceRole) -> Option<ArtifactKind> {
    match role {
        SourceRole::Packages => Some(ArtifactKind::WindowsSoftware),
        SourceRole::Msix => Some(ArtifactKind::WindowsMsix),
        SourceRole::AppPaths => Some(ArtifactKind::WindowsAppPaths),
        SourceRole::Processes => Some(ArtifactKind::WindowsProcesses),
        SourceRole::Permissions => Some(ArtifactKind::WindowsPermissions),
        SourceRole::Startup => Some(ArtifactKind::WindowsStartup),
        SourceRole::PathExecutables => Some(ArtifactKind::PathExecutables),
        SourceRole::SelectedRoot => Some(ArtifactKind::SelectedRoot),
        SourceRole::Runtime => Some(ArtifactKind::WindowsRuntimeCapture),
    }
}

fn collect_windows_startup_for_session(
    schema_version: u32,
) -> Result<crate::inventory::WindowsStartupInventoryDocument, String> {
    match schema_version {
        crate::audit_session::AUDIT_SESSION_V9_SCHEMA_VERSION => Ok(collect_windows_startup_v5()),
        crate::audit_session::AUDIT_SESSION_V10_SCHEMA_VERSION => Ok(collect_windows_startup_v6()),
        crate::audit_session::AUDIT_SESSION_V11_SCHEMA_VERSION => Ok(collect_windows_startup_v6()),
        crate::audit_session::AUDIT_SESSION_V12_SCHEMA_VERSION => Ok(collect_windows_startup_v7()),
        crate::audit_session::AUDIT_SESSION_V13_SCHEMA_VERSION => {
            Ok(crate::inventory::collect_windows_startup())
        }
        _ => Err("unsupported Windows audit-session schema version".to_owned()),
    }
}

fn session_schema_version(options: &WindowsAuditOptions) -> u32 {
    if options.startup {
        crate::audit_session::AUDIT_SESSION_V13_SCHEMA_VERSION
    } else if options.app_paths {
        crate::audit_session::AUDIT_SESSION_V11_SCHEMA_VERSION
    } else {
        crate::audit_session::AUDIT_SESSION_V9_SCHEMA_VERSION
    }
}

fn now_ms() -> Result<u128, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .map_err(|_| "system clock is before the Unix epoch".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{WindowsAuditOptions, artifact, build_manifest, session_schema_version, source};
    use crate::audit_session::{
        ArtifactKind, ContextFact, ContextFactStatus, HostContext, PrivilegeContext, SessionStatus,
        SourceRole, SourceStatus,
    };

    #[test]
    fn producer_selects_v13_for_startup_and_v11_for_app_paths_only() {
        let startup_and_app_paths = WindowsAuditOptions {
            startup: true,
            app_paths: true,
            ..WindowsAuditOptions::default()
        };
        assert_eq!(
            session_schema_version(&startup_and_app_paths),
            crate::audit_session::AUDIT_SESSION_V13_SCHEMA_VERSION
        );

        let app_paths_only = WindowsAuditOptions {
            app_paths: true,
            ..WindowsAuditOptions::default()
        };
        assert_eq!(
            session_schema_version(&app_paths_only),
            crate::audit_session::AUDIT_SESSION_V11_SCHEMA_VERSION
        );
    }

    #[test]
    fn windows_runtime_coverage_counts_only_fixed_decoder_diagnostic_categories() {
        let provider = serde_json::json!({"status":"unsupported_provider"});
        let unsupported = serde_json::json!({"status":"unsupported_version"});
        let malformed = serde_json::json!({"status":"malformed_payload"});
        let decoded = serde_json::json!({"status":"decoded"});
        let detail = super::runtime_coverage_detail_from_event_diagnostics([
            ("unsupported_or_malformed_provider_event", Some(&provider)),
            (
                "unsupported_or_malformed_provider_event",
                Some(&unsupported),
            ),
            ("unsupported_or_malformed_provider_event", Some(&malformed)),
            ("network_observation", Some(&decoded)),
        ])
        .unwrap();
        assert_eq!(
            detail.unsupported_categories,
            vec![
                crate::audit_session::UnsupportedRuntimeCategory {
                    code: crate::audit_session::UnsupportedRuntimeCategoryCode::WindowsMalformedEtwPayloads,
                    count: 1,
                },
                crate::audit_session::UnsupportedRuntimeCategory {
                    code: crate::audit_session::UnsupportedRuntimeCategoryCode::WindowsUnsupportedEtwEvents,
                    count: 1,
                },
                crate::audit_session::UnsupportedRuntimeCategory {
                    code: crate::audit_session::UnsupportedRuntimeCategoryCode::WindowsUnsupportedEtwProviders,
                    count: 1,
                },
            ]
        );
        assert!(
            super::runtime_coverage_detail_from_event_diagnostics([(
                "unsupported_or_malformed_provider_event",
                None,
            )])
            .is_none()
        );
    }

    #[test]
    fn windows_runtime_source_manifest_binds_capture_bytes_and_stays_partial() {
        let bytes = br#"{"schema":"sideeffect.windows_runtime_capture","schema_version":3,"synthetic_fixture":true}"#.to_vec();
        let artifacts = [artifact(
            ArtifactKind::WindowsRuntimeCapture,
            "runtime.windows.json",
            "sideeffect.windows_runtime_capture",
            3,
            bytes.clone(),
        )];
        let runtime_source = source(
            SourceRole::Runtime,
            "synthetic bounded ETW fixture",
            1_001,
            1_002,
            SourceStatus::Partial,
            vec!["capture_completeness_unknown"],
            vec![("max_events", 50_000)],
        );

        let manifest = build_manifest(
            1_000,
            1_003,
            HostContext {
                os_name: ContextFact {
                    status: ContextFactStatus::Observed,
                    value: Some("Windows".to_owned()),
                },
                os_version: ContextFact {
                    status: ContextFactStatus::Unknown,
                    value: None,
                },
                privilege: PrivilegeContext::Unknown,
            },
            vec![runtime_source],
            &artifacts,
            None,
            crate::audit_session::AUDIT_SESSION_V10_SCHEMA_VERSION,
        )
        .unwrap();
        assert_eq!(manifest.status, SessionStatus::Partial);
        let reference = &manifest.sources[0].artifacts[0];
        assert_eq!(reference.kind, ArtifactKind::WindowsRuntimeCapture);
        assert_eq!(reference.path, "runtime.windows.json");
        assert_eq!(reference.byte_length, bytes.len() as u64);
        assert_eq!(reference.sha256, crate::fingerprint::sha256_hex(&bytes));
        assert_eq!(manifest.sources[0].status, SourceStatus::Partial);
        manifest.validate().unwrap();
    }
}
