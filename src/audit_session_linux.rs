//! Linux-first collection and publication for bounded local audit sessions.

use crate::audit_session::{
    AUDIT_SESSION_SCHEMA, AUDIT_SESSION_SCHEMA_VERSION, AppliedLimit, ArtifactKind,
    AuditSessionManifest, AuditSessionSource, ContextFact, ContextFactStatus, CoverageManifest,
    HostContext, IntervalSemantics, MAX_SESSION_ARTIFACT_BYTES, MAX_SESSION_SOURCES,
    MAX_SESSION_TIMESTAMP_UNIX_MS, MAX_SESSION_TOTAL_ARTIFACT_BYTES, PrivilegeContext,
    SessionArtifactRef, SessionId, SessionStatus, SourceRole, SourceStatus,
};
use crate::fingerprint::sha256_hex;
use crate::inventory::{collect_packages, collect_permissions, collect_processes, collect_startup};
use crate::record::{SessionOutput, record_bundle_artifacts};
use serde::Serialize;
use serde_json::Value;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_DIAGNOSTICS: usize = 256;
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Default)]
pub struct AuditOptions {
    pub packages: bool,
    pub processes: bool,
    pub startup: bool,
    pub permission_paths: Vec<PathBuf>,
    pub runtime_program: Option<OsString>,
    pub runtime_arguments: Vec<OsString>,
    pub runtime_duration: Option<Duration>,
}

#[derive(Clone, Debug)]
pub struct PublishedAuditSession {
    pub path: PathBuf,
    pub parent_sync_confirmed: bool,
    pub manifest: AuditSessionManifest,
}

struct Artifact {
    file_name: &'static str,
    bytes: Vec<u8>,
}

/// Collect selected Linux inventory sources and atomically publish one private session directory.
pub fn collect_and_publish(
    destination: &Path,
    options: &AuditOptions,
) -> Result<PublishedAuditSession, String> {
    if !options.packages
        && !options.processes
        && !options.startup
        && options.permission_paths.is_empty()
        && options.runtime_program.is_none()
    {
        return Err("select at least one source for the audit session".to_owned());
    }
    if options.permission_paths.len() > crate::inventory::MAX_PERMISSION_PATHS {
        return Err(format!(
            "permission path count exceeds the {} path limit",
            crate::inventory::MAX_PERMISSION_PATHS
        ));
    }
    if options.runtime_program.is_some() != options.runtime_duration.is_some() {
        return Err("runtime audit requires both a command and a duration limit".to_owned());
    }
    if options
        .runtime_program
        .as_ref()
        .is_some_and(|program| program.is_empty())
    {
        return Err("runtime audit command must not be empty".to_owned());
    }
    if options.runtime_program.is_none() && !options.runtime_arguments.is_empty() {
        return Err("runtime audit arguments require a command".to_owned());
    }
    if options.runtime_duration.is_some_and(|duration| {
        duration.as_secs() == 0 || duration.as_secs() > 3600 || duration.subsec_nanos() != 0
    }) {
        return Err(
            "runtime audit duration must be a whole number of seconds from 1 to 3600".to_owned(),
        );
    }

    let mut output = SessionOutput::prepare(destination)
        .map_err(|error| format!("could not prepare private audit session: {error}"))?;
    let mut artifacts = Vec::new();
    let mut sources = Vec::new();
    let session_start = now_unix_ms()?;

    if options.packages {
        let started = now_unix_ms()?;
        let document = collect_packages();
        let ended = now_unix_ms()?;
        let value = serde_json::to_value(&document)
            .map_err(|error| format!("could not inspect package inventory metadata: {error}"))?;
        sources.push(build_source(
            SourceRole::Packages,
            &value,
            started,
            ended,
            vec![
                limit(
                    "max_inventory_rows",
                    crate::limits::MAX_INVENTORY_ROWS as u64,
                ),
                limit(
                    "max_adapter_stdout_bytes",
                    crate::limits::MAX_INVENTORY_STDOUT_BYTES as u64,
                ),
                limit(
                    "max_adapter_stderr_bytes",
                    crate::limits::MAX_INVENTORY_STDERR_BYTES as u64,
                ),
            ],
        )?);
        artifacts.push(artifact("packages.json", &document)?);
    }

    if options.processes {
        let document = collect_processes();
        let value = serde_json::to_value(&document)
            .map_err(|error| format!("could not inspect process inventory metadata: {error}"))?;
        sources.push(build_source(
            SourceRole::Processes,
            &value,
            document.capture_started_at_unix_ms,
            document.capture_ended_at_unix_ms,
            vec![
                limit(
                    "max_process_directories",
                    crate::inventory::MAX_PROCESS_DIRECTORIES as u64,
                ),
                limit(
                    "max_aggregate_status_bytes",
                    crate::inventory::MAX_AGGREGATE_STATUS_BYTES as u64,
                ),
            ],
        )?);
        artifacts.push(artifact("processes.json", &document)?);
    }

    if options.startup {
        let document = collect_startup();
        let value = serde_json::to_value(&document)
            .map_err(|error| format!("could not inspect startup inventory metadata: {error}"))?;
        sources.push(build_source(
            SourceRole::Startup,
            &value,
            document.capture_started_at_unix_ms,
            document.capture_ended_at_unix_ms,
            vec![
                limit(
                    "max_startup_files",
                    crate::inventory::MAX_STARTUP_FILES as u64,
                ),
                limit(
                    "max_startup_total_bytes",
                    crate::inventory::MAX_STARTUP_TOTAL_BYTES as u64,
                ),
                limit(
                    "max_startup_directories",
                    crate::inventory::MAX_STARTUP_DIRECTORIES as u64,
                ),
            ],
        )?);
        artifacts.push(artifact("startup.json", &document)?);
    }

    if !options.permission_paths.is_empty() {
        let started = now_unix_ms()?;
        let document = collect_permissions(&options.permission_paths);
        let ended = now_unix_ms()?;
        let value = serde_json::to_value(&document)
            .map_err(|error| format!("could not inspect permission inventory metadata: {error}"))?;
        sources.push(build_source(
            SourceRole::Permissions,
            &value,
            started,
            ended,
            vec![
                limit(
                    "max_permission_paths",
                    crate::inventory::MAX_PERMISSION_PATHS as u64,
                ),
                limit(
                    "max_total_acl_bytes",
                    crate::inventory::MAX_PERMISSION_TOTAL_ACL_BYTES as u64,
                ),
                limit(
                    "max_total_capability_bytes",
                    crate::inventory::MAX_PERMISSION_TOTAL_CAPABILITY_BYTES as u64,
                ),
            ],
        )?);
        artifacts.push(artifact("permissions.json", &document)?);
    }

    if let Some(program) = &options.runtime_program {
        let started = now_unix_ms()?;
        let duration = options
            .runtime_duration
            .expect("runtime options were validated above");
        let runtime_result =
            record_bundle_artifacts(destination, program, &options.runtime_arguments, duration);
        let ended = now_unix_ms()?;
        match runtime_result {
            Ok(bundle) => {
                let mut diagnostic_codes = vec!["runtime_capture_completeness_unknown".to_owned()];
                if bundle.time_limit_reached {
                    diagnostic_codes.push("runtime_time_limit_reached".to_owned());
                }
                sources.push(AuditSessionSource {
                    role: SourceRole::Runtime,
                    platform: "linux".to_owned(),
                    scope: "selected command and traced descendants; command arguments are not copied into the session manifest".to_owned(),
                    started_at_unix_ms: started,
                    ended_at_unix_ms: ended,
                    status: SourceStatus::Partial,
                    applied_limits: vec![
                        limit("max_trace_bytes", crate::limits::MAX_TRACE_BYTES as u64),
                    ],
                    requested_settings: vec![crate::audit_session::Setting {
                        code: "runtime_duration_seconds".to_owned(),
                        value: duration.as_secs(),
                    }],
                    effective_settings: Vec::new(),
                    loss: Some(crate::audit_session::LossMetadata::unknown()),
                    diagnostic_codes,
                    artifacts: Vec::new(),
                });
                artifacts.push(Artifact {
                    file_name: "run.json",
                    bytes: bundle.manifest_bytes,
                });
                artifacts.push(Artifact {
                    file_name: "trace.strace",
                    bytes: bundle.trace_bytes,
                });
            }
            Err(error) => {
                let target_may_have_run = error.target_may_have_run();
                sources.push(AuditSessionSource {
                    role: SourceRole::Runtime,
                    platform: "linux".to_owned(),
                    scope: "selected command and traced descendants; command arguments are not copied into the session manifest".to_owned(),
                    started_at_unix_ms: started,
                    ended_at_unix_ms: ended,
                    status: if target_may_have_run {
                        SourceStatus::Partial
                    } else {
                        SourceStatus::Unavailable
                    },
                    applied_limits: vec![
                        limit("max_trace_bytes", crate::limits::MAX_TRACE_BYTES as u64),
                    ],
                    requested_settings: vec![crate::audit_session::Setting {
                        code: "runtime_duration_seconds".to_owned(),
                        value: duration.as_secs(),
                    }],
                    effective_settings: Vec::new(),
                    loss: Some(crate::audit_session::LossMetadata::unknown()),
                    diagnostic_codes: if target_may_have_run {
                        vec![
                            "runtime_capture_failed".to_owned(),
                            "runtime_target_may_have_run".to_owned(),
                        ]
                    } else {
                        vec!["runtime_capture_unavailable".to_owned()]
                    },
                    artifacts: Vec::new(),
                });
            }
        }
    }

    let host_context = host_context();
    let session_end = now_unix_ms()?;
    if sources.is_empty() || sources.len() > MAX_SESSION_SOURCES {
        return Err("selected audit sources exceed the session source limit".to_owned());
    }
    let total_artifact_bytes = artifacts.iter().try_fold(0_u64, |total, artifact| {
        total.checked_add(artifact.bytes.len() as u64)
    });
    if total_artifact_bytes.is_none_or(|total| total > MAX_SESSION_TOTAL_ARTIFACT_BYTES) {
        return Err(format!(
            "selected audit artifacts exceed the {MAX_SESSION_TOTAL_ARTIFACT_BYTES} byte aggregate session limit"
        ));
    }
    let complete = sources
        .iter()
        .all(|source| source.status == SourceStatus::Complete);
    let session_id = new_session_id(session_start)?;
    for artifact in &artifacts {
        let (schema, schema_version) = artifact_schema(artifact.file_name, &artifact.bytes)?;
        let kind = artifact_kind(artifact.file_name)?;
        let role = match kind {
            ArtifactKind::Packages => SourceRole::Packages,
            ArtifactKind::Processes => SourceRole::Processes,
            ArtifactKind::Permissions => SourceRole::Permissions,
            ArtifactKind::Startup => SourceRole::Startup,
            ArtifactKind::WindowsSoftware
            | ArtifactKind::WindowsProcesses
            | ArtifactKind::WindowsPermissions
            | ArtifactKind::WindowsStartup
            | ArtifactKind::WindowsRuntimeCapture => {
                return Err(
                    "Windows artifacts are not supported in Linux audit collection".to_owned(),
                );
            }
            ArtifactKind::RuntimeManifest | ArtifactKind::RuntimeTrace => SourceRole::Runtime,
        };
        let source = sources
            .iter_mut()
            .find(|source| source.role == role)
            .ok_or_else(|| "audit artifact has no matching selected source".to_owned())?;
        source.artifacts.push(SessionArtifactRef {
            kind,
            path: artifact.file_name.to_owned(),
            schema,
            schema_version,
            byte_length: artifact.bytes.len() as u64,
            sha256: sha256_hex(&artifact.bytes),
        });
    }

    let coverage_manifest = Some(CoverageManifest::from_sources(&sources));
    let manifest = AuditSessionManifest {
        schema: AUDIT_SESSION_SCHEMA.to_owned(),
        schema_version: AUDIT_SESSION_SCHEMA_VERSION,
        session_id,
        platform: "linux".to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        host_context: Some(host_context),
        started_at_unix_ms: session_start,
        ended_at_unix_ms: session_end,
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
        .map_err(|error| format!("constructed audit session is invalid: {error:?}"))?;

    let manifest_bytes = serialize_bounded(&manifest, 512 * 1024, "session manifest")?;
    for artifact in &artifacts {
        output
            .write_artifact(artifact.file_name, &artifact.bytes)
            .map_err(|error| format!("could not stage private audit artifact: {error}"))?;
    }
    output
        .write_manifest(&manifest_bytes)
        .map_err(|error| format!("could not stage private audit manifest: {error}"))?;
    let (path, parent_sync_confirmed) = output
        .publish()
        .map_err(|error| format!("could not publish private audit session: {error}"))?;

    Ok(PublishedAuditSession {
        path,
        parent_sync_confirmed,
        manifest,
    })
}

fn host_context() -> HostContext {
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::uninit();
    let (os_name, os_version) = if unsafe { libc::uname(uts.as_mut_ptr()) } == 0 {
        let uts = unsafe { uts.assume_init() };
        let bounded = |field: &[libc::c_char]| {
            let bytes: Vec<u8> = field
                .iter()
                .take_while(|byte| **byte != 0)
                .map(|byte| *byte as u8)
                .take(128)
                .collect();
            let decoded = String::from_utf8_lossy(&bytes);
            let mut end = decoded.len().min(128);
            while !decoded.is_char_boundary(end) {
                end -= 1;
            }
            decoded[..end].to_owned()
        };
        (bounded(&uts.sysname), bounded(&uts.release))
    } else {
        (String::new(), String::new())
    };
    let fact = |value: String| {
        if value.is_empty() {
            ContextFact {
                status: ContextFactStatus::Unknown,
                value: None,
            }
        } else {
            ContextFact {
                status: ContextFactStatus::Observed,
                value: Some(value),
            }
        }
    };
    HostContext {
        os_name: fact(os_name),
        os_version: fact(os_version),
        // This reports the process effective-UID context; it is not a broad
        // statement about capabilities or access to every system resource.
        privilege: if unsafe { libc::geteuid() } == 0 {
            PrivilegeContext::Elevated
        } else {
            PrivilegeContext::NotElevated
        },
    }
}

fn build_source(
    role: SourceRole,
    document: &Value,
    started_at_unix_ms: u128,
    ended_at_unix_ms: u128,
    applied_limits: Vec<AppliedLimit>,
) -> Result<AuditSessionSource, String> {
    let status = match document.get("status").and_then(Value::as_str) {
        Some("complete") => SourceStatus::Complete,
        Some("partial") => SourceStatus::Partial,
        _ => SourceStatus::Unknown,
    };
    let platform = document
        .get("platform")
        .and_then(Value::as_str)
        .ok_or_else(|| "inventory artifact has no platform field".to_owned())?;
    let scope = document
        .get("scope")
        .and_then(Value::as_str)
        .ok_or_else(|| "inventory artifact has no scope field".to_owned())?;
    let diagnostic_codes = collect_codes(document);
    Ok(AuditSessionSource {
        role,
        platform: platform.to_owned(),
        scope: scope.to_owned(),
        started_at_unix_ms,
        ended_at_unix_ms,
        status,
        applied_limits,
        requested_settings: Vec::new(),
        effective_settings: Vec::new(),
        loss: None,
        diagnostic_codes,
        artifacts: Vec::new(),
    })
}

fn collect_codes(value: &Value) -> Vec<String> {
    fn visit(value: &Value, output: &mut Vec<String>) {
        if output.len() >= MAX_DIAGNOSTICS {
            return;
        }
        match value {
            Value::Object(object) => {
                if let Some(code) = object.get("code").and_then(Value::as_str) {
                    if code.len() <= crate::audit_session::MAX_CODE_BYTES
                        && !output.iter().any(|item| item == code)
                    {
                        output.push(code.to_owned());
                    }
                }
                for child in object.values() {
                    visit(child, output);
                }
            }
            Value::Array(items) => {
                for child in items {
                    visit(child, output);
                    if output.len() >= MAX_DIAGNOSTICS {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    let mut output = Vec::new();
    visit(value, &mut output);
    output
}

fn artifact<T: Serialize>(file_name: &'static str, document: &T) -> Result<Artifact, String> {
    let bytes = serialize_bounded(document, MAX_SESSION_ARTIFACT_BYTES as usize, file_name)?;
    Ok(Artifact { file_name, bytes })
}

fn serialize_bounded<T: Serialize>(value: &T, max: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut writer = CappedWriter::new(max);
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| format!("could not serialize {label} within {max} bytes: {error}"))?;
    Ok(writer.bytes)
}

fn artifact_schema(file_name: &str, bytes: &[u8]) -> Result<(String, u32), String> {
    if file_name == "trace.strace" {
        return Ok(("strace_text".to_owned(), 1));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("could not read serialized artifact schema: {error}"))?;
    let schema = value
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| "serialized inventory artifact has no schema".to_owned())?;
    let version = value
        .get("schema_version")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "serialized inventory artifact has an invalid schema version".to_owned())?;
    Ok((schema.to_owned(), version))
}

fn artifact_kind(file_name: &str) -> Result<ArtifactKind, String> {
    match file_name {
        "packages.json" => Ok(ArtifactKind::Packages),
        "processes.json" => Ok(ArtifactKind::Processes),
        "startup.json" => Ok(ArtifactKind::Startup),
        "permissions.json" => Ok(ArtifactKind::Permissions),
        "run.json" => Ok(ArtifactKind::RuntimeManifest),
        "trace.strace" => Ok(ArtifactKind::RuntimeTrace),
        "software.windows.json" => Ok(ArtifactKind::WindowsSoftware),
        "processes.windows.json" => Ok(ArtifactKind::WindowsProcesses),
        "permissions.windows.json" => Ok(ArtifactKind::WindowsPermissions),
        "startup.windows.json" => Ok(ArtifactKind::WindowsStartup),
        _ => Err("unknown audit artifact name".to_owned()),
    }
}

fn limit(code: &str, value: u64) -> AppliedLimit {
    AppliedLimit {
        code: code.to_owned(),
        value,
    }
}

fn now_unix_ms() -> Result<u128, String> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?
        .as_millis();
    if value == 0 || value > MAX_SESSION_TIMESTAMP_UNIX_MS {
        return Err("system clock is outside the supported session timestamp range".to_owned());
    }
    Ok(value)
}

fn new_session_id(timestamp_ms: u128) -> Result<SessionId, String> {
    let counter = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    let material = format!("{timestamp_ms}:{}:{counter}", std::process::id());
    let digest = sha256_hex(material.as_bytes());
    Ok(digest[..32].to_owned())
}

struct CappedWriter {
    bytes: Vec<u8>,
    max_bytes: usize,
}

impl CappedWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_bytes,
        }
    }
}

impl Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let new_len = self.bytes.len().checked_add(bytes.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized output length overflow",
            )
        })?;
        if new_len > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized output exceeds its configured limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
