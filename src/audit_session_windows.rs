//! Bounded native Windows audit-session collection and private publication.

use crate::audit_session::{
    AUDIT_SESSION_SCHEMA, AUDIT_SESSION_SCHEMA_VERSION, ArtifactKind, AuditSessionManifest,
    AuditSessionSource, ContextFact, ContextFactStatus, CoverageManifest, HostContext,
    IntervalSemantics, PrivilegeContext, SessionArtifactRef, SessionStatus, SourceRole,
    SourceStatus,
};
use crate::fingerprint::sha256_hex;
use crate::inventory::{
    collect_windows_permissions, collect_windows_processes, collect_windows_software,
    collect_windows_startup,
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
    pub processes: bool,
    pub startup: bool,
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
        && !options.processes
        && !options.startup
        && options.permission_paths.is_empty()
        && !options.include_runtime
    {
        return Err("select at least one source for the audit session".to_owned());
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
            "visible Tool Help process snapshot and permitted image paths",
            doc.capture_started_at_unix_ms,
            doc.capture_ended_at_unix_ms,
            status,
            diagnostics,
            vec![("max_processes", 8192), ("deadline_ms", 10000)],
        ));
        artifacts.push(artifact(
            ArtifactKind::WindowsProcesses,
            "processes.windows.json",
            "sideeffect.windows_process_inventory",
            2,
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
        let doc = collect_windows_startup();
        let (status, diagnostics) = status_from_serialized(&doc, "status");
        let value = serde_json::to_vec(&doc)
            .map_err(|e| format!("could not serialize startup inventory: {e}"))?;
        sources.push(source(SourceRole::Startup, "selected Run/RunOnce, Startup folders, services, and visible boot/logon scheduled tasks", doc.capture_started_at_unix_ms, doc.capture_ended_at_unix_ms, status, diagnostics, vec![("max_startup_entries", 8192), ("deadline_ms_between_calls", 10000)]));
        artifacts.push(artifact(
            ArtifactKind::WindowsStartup,
            "startup.windows.json",
            "sideeffect.windows_startup_inventory",
            4,
            value,
        ));
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
    let manifest = build_manifest(started, ended, context, sources, &artifacts)?;
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
    let coverage_manifest = Some(CoverageManifest::from_sources(&sources));
    let manifest = AuditSessionManifest {
        schema: AUDIT_SESSION_SCHEMA.to_owned(),
        schema_version: AUDIT_SESSION_SCHEMA_VERSION,
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
        SourceRole::Processes => Some(ArtifactKind::WindowsProcesses),
        SourceRole::Permissions => Some(ArtifactKind::WindowsPermissions),
        SourceRole::Startup => Some(ArtifactKind::WindowsStartup),
        SourceRole::Runtime => Some(ArtifactKind::WindowsRuntimeCapture),
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
    use super::{artifact, build_manifest, source};
    use crate::audit_session::{
        ArtifactKind, ContextFact, ContextFactStatus, HostContext, PrivilegeContext, SessionStatus,
        SourceRole, SourceStatus,
    };

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
