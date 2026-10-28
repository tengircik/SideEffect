//! Bounded native Windows audit-session collection and private publication.

use crate::audit_session::{
    AUDIT_SESSION_SCHEMA, AUDIT_SESSION_SCHEMA_VERSION, ArtifactKind, AuditSessionManifest,
    AuditSessionSource, IntervalSemantics, SessionArtifactRef, SessionStatus, SourceRole,
    SourceStatus,
};
use crate::fingerprint::sha256_hex;
use crate::inventory::{
    collect_windows_permissions, collect_windows_processes, collect_windows_software,
    collect_windows_startup,
};
use crate::record::publish_private_windows_directory;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_WINDOWS_SESSION_BYTES: usize = 128 * 1024 * 1024;
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Default)]
pub struct WindowsAuditOptions {
    pub software: bool,
    pub processes: bool,
    pub startup: bool,
    pub permission_paths: Vec<PathBuf>,
    pub include_runtime: bool,
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
            1,
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
        let when = now_ms()?;
        sources.push(source(SourceRole::Runtime, "native Windows runtime activity capture is unsupported by this audit-session path; experimental ETW process prototype is not evidence-complete", when, when, SourceStatus::Unsupported, vec!["windows_runtime_source_unsupported"], vec![]));
    }

    let ended = now_ms()?;
    let mut files: Vec<(&str, &[u8])> = artifacts
        .iter()
        .map(|a| (a.file_name, a.bytes.as_slice()))
        .collect();
    let manifest = build_manifest(started, ended, sources, &artifacts)?;
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
        started_at_unix_ms: started,
        ended_at_unix_ms: ended,
        interval_semantics: IntervalSemantics::BestEffortNonAtomic,
        status: if complete {
            SessionStatus::Complete
        } else {
            SessionStatus::Partial
        },
        sources,
    };
    manifest
        .validate()
        .map_err(|e| format!("constructed audit session is invalid: {e:?}"))?;
    Ok(manifest)
}

fn role_kind(role: SourceRole) -> Option<ArtifactKind> {
    match role {
        SourceRole::Packages => Some(ArtifactKind::WindowsSoftware),
        SourceRole::Processes => Some(ArtifactKind::WindowsProcesses),
        SourceRole::Permissions => Some(ArtifactKind::WindowsPermissions),
        SourceRole::Startup => Some(ArtifactKind::WindowsStartup),
        SourceRole::Runtime => None,
    }
}

fn now_ms() -> Result<u128, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .map_err(|_| "system clock is before the Unix epoch".to_owned())
}
