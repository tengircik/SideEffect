//! Versioned, platform-neutral manifest for a best-effort local audit session.
//!
//! This envelope references source artifacts without normalizing their native
//! schemas. It describes a set of observations collected over an interval; it
//! does not claim that the sources were captured atomically.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const AUDIT_SESSION_SCHEMA: &str = "sideeffect.audit_session";
pub const AUDIT_SESSION_SCHEMA_VERSION: u32 = 1;
pub const MAX_AUDIT_SESSION_MANIFEST_BYTES: usize = 512 * 1024;
pub const MAX_SESSION_SOURCES: usize = 8;
pub const MAX_SESSION_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_SESSION_TOTAL_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_SESSION_TIMESTAMP_UNIX_MS: u128 = 253_402_300_799_999;
pub const MAX_PLATFORM_BYTES: usize = 64;
pub const MAX_SCOPE_BYTES: usize = 4 * 1024;
pub const MAX_LIMITS_PER_SOURCE: usize = 64;
pub const MAX_DIAGNOSTIC_CODES_PER_SOURCE: usize = 256;
pub const MAX_CODE_BYTES: usize = 128;

/// The session ID is an opaque stable identifier, not a secret or credential.
/// Producers should create it once and preserve it when the manifest is read.
pub type SessionId = String;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSessionManifest {
    pub schema: String,
    pub schema_version: u32,
    pub session_id: SessionId,
    pub platform: String,
    pub architecture: String,
    pub started_at_unix_ms: u128,
    pub ended_at_unix_ms: u128,
    pub interval_semantics: IntervalSemantics,
    pub status: SessionStatus,
    pub sources: Vec<AuditSessionSource>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntervalSemantics {
    /// Sources run sequentially or concurrently over a best-effort interval;
    /// the resulting artifacts are not a point-in-time atomic snapshot.
    BestEffortNonAtomic,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRole {
    Packages,
    Processes,
    Permissions,
    Startup,
    Runtime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    /// The selected collector produced all artifacts it declared for this
    /// source. This does not establish exhaustive system coverage.
    Complete,
    Partial,
    Unknown,
    NotChecked,
    Unsupported,
    NotApplicable,
    Unavailable,
    AccessDenied,
    Failed,
    TimedOut,
    OutputLimitExceeded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSessionSource {
    pub role: SourceRole,
    pub platform: String,
    pub scope: String,
    pub started_at_unix_ms: u128,
    pub ended_at_unix_ms: u128,
    pub status: SourceStatus,
    pub applied_limits: Vec<AppliedLimit>,
    pub diagnostic_codes: Vec<String>,
    pub artifacts: Vec<SessionArtifactRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedLimit {
    /// Stable snake_case code naming the limit, for example `max_files`.
    pub code: String,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Packages,
    Processes,
    Permissions,
    Startup,
    WindowsSoftware,
    WindowsProcesses,
    WindowsPermissions,
    WindowsStartup,
    RuntimeManifest,
    RuntimeTrace,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionArtifactRef {
    pub kind: ArtifactKind,
    /// Must exactly match the fixed filename assigned to `kind`.
    pub path: String,
    /// The native source schema. Raw trace text uses `strace_text` v1.
    pub schema: String,
    pub schema_version: u32,
    pub byte_length: u64,
    /// Lowercase hexadecimal SHA-256 of the referenced bytes.
    pub sha256: String,
}

/// Parse and validate a bounded session manifest. Artifact files must still be
/// opened with no-follow semantics and checked against these references by the
/// eventual session reader before their contents are consumed.
pub fn parse_manifest(bytes: &[u8]) -> Result<AuditSessionManifest, ValidationError> {
    if bytes.len() > MAX_AUDIT_SESSION_MANIFEST_BYTES {
        return Err(ValidationError::ManifestTooLarge);
    }
    let manifest: AuditSessionManifest =
        serde_json::from_slice(bytes).map_err(|_| ValidationError::InvalidManifestJson)?;
    manifest.validate()?;
    Ok(manifest)
}

impl AuditSessionManifest {
    /// Validate all envelope fields, source completeness semantics, and fixed
    /// artifact references before serializing, consuming, or publishing it.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != AUDIT_SESSION_SCHEMA
            || self.schema_version != AUDIT_SESSION_SCHEMA_VERSION
        {
            return Err(ValidationError::InvalidSchema);
        }
        if !is_session_id(&self.session_id) {
            return Err(ValidationError::InvalidSessionId);
        }
        validate_platform(&self.platform)?;
        validate_token(&self.architecture, MAX_PLATFORM_BYTES, "architecture")?;
        validate_interval(self.started_at_unix_ms, self.ended_at_unix_ms)?;
        if self.sources.is_empty() || self.sources.len() > MAX_SESSION_SOURCES {
            return Err(ValidationError::SourceCountOutOfBounds);
        }

        let mut roles = HashSet::new();
        let mut artifact_kinds = HashSet::new();
        let mut artifact_paths = HashSet::new();
        let mut total_bytes = 0_u64;
        let mut all_complete = true;

        for source in &self.sources {
            if !roles.insert(source.role) {
                return Err(ValidationError::DuplicateSourceRole);
            }
            validate_platform(&source.platform)?;
            if source.platform != self.platform {
                return Err(ValidationError::SourcePlatformMismatch);
            }
            validate_bounded_text(&source.scope, MAX_SCOPE_BYTES, "scope")?;
            validate_interval(source.started_at_unix_ms, source.ended_at_unix_ms)?;
            if source.started_at_unix_ms < self.started_at_unix_ms
                || source.ended_at_unix_ms > self.ended_at_unix_ms
            {
                return Err(ValidationError::SourceOutsideSessionInterval);
            }
            if source.applied_limits.len() > MAX_LIMITS_PER_SOURCE
                || source.diagnostic_codes.len() > MAX_DIAGNOSTIC_CODES_PER_SOURCE
            {
                return Err(ValidationError::MetadataCountOutOfBounds);
            }
            for limit in &source.applied_limits {
                validate_code(&limit.code)?;
            }
            for code in &source.diagnostic_codes {
                validate_code(code)?;
            }
            if source.role == SourceRole::Runtime && source.status == SourceStatus::Complete {
                return Err(ValidationError::RuntimeCompletenessNotEstablished);
            }

            let expected = expected_artifacts(source.role, &source.platform)?;
            if source.artifacts.len() > expected.len()
                || (source.status == SourceStatus::Complete
                    && source.artifacts.len() != expected.len())
            {
                return Err(ValidationError::ArtifactSetMismatch);
            }
            if source.role == SourceRole::Runtime
                && source.platform == "windows"
                && !source.artifacts.is_empty()
            {
                return Err(ValidationError::ArtifactSetMismatch);
            }
            let mut source_artifact_kinds = HashSet::new();
            for artifact in &source.artifacts {
                let (path, schema, version) = artifact_contract(artifact.kind)?;
                if !expected.contains(&artifact.kind)
                    || !source_artifact_kinds.insert(artifact.kind)
                    || artifact.path != path
                    || artifact.schema != schema
                    || artifact.schema_version != version
                {
                    return Err(ValidationError::ArtifactContractMismatch);
                }
                validate_artifact_path(&artifact.path)?;
                if !artifact_kinds.insert(artifact.kind) || !artifact_paths.insert(&artifact.path) {
                    return Err(ValidationError::DuplicateArtifact);
                }
                if artifact.byte_length == 0 || artifact.byte_length > MAX_SESSION_ARTIFACT_BYTES {
                    return Err(ValidationError::ArtifactSizeOutOfBounds);
                }
                total_bytes = total_bytes
                    .checked_add(artifact.byte_length)
                    .ok_or(ValidationError::AggregateSizeOutOfBounds)?;
                if total_bytes > MAX_SESSION_TOTAL_ARTIFACT_BYTES {
                    return Err(ValidationError::AggregateSizeOutOfBounds);
                }
                if !is_lower_hex(&artifact.sha256, 64) {
                    return Err(ValidationError::InvalidArtifactDigest);
                }
            }
            if source.status != SourceStatus::Complete {
                all_complete = false;
            }
        }
        if (self.status == SessionStatus::Complete) != all_complete {
            return Err(ValidationError::SessionStatusHidesIncompleteSource);
        }
        Ok(())
    }
}

fn expected_artifacts(
    role: SourceRole,
    platform: &str,
) -> Result<Vec<ArtifactKind>, ValidationError> {
    match platform {
        "linux" => Ok(match role {
            SourceRole::Packages => vec![ArtifactKind::Packages],
            SourceRole::Processes => vec![ArtifactKind::Processes],
            SourceRole::Permissions => vec![ArtifactKind::Permissions],
            SourceRole::Startup => vec![ArtifactKind::Startup],
            SourceRole::Runtime => vec![ArtifactKind::RuntimeManifest, ArtifactKind::RuntimeTrace],
        }),
        "windows" => Ok(match role {
            SourceRole::Packages => vec![ArtifactKind::WindowsSoftware],
            SourceRole::Processes => vec![ArtifactKind::WindowsProcesses],
            SourceRole::Permissions => vec![ArtifactKind::WindowsPermissions],
            SourceRole::Startup => vec![ArtifactKind::WindowsStartup],
            SourceRole::Runtime => Vec::new(),
        }),
        _ => Err(ValidationError::UnsupportedArtifactPlatform),
    }
}

fn artifact_contract(
    kind: ArtifactKind,
) -> Result<(&'static str, &'static str, u32), ValidationError> {
    Ok(match kind {
        ArtifactKind::Packages => ("packages.json", "sideeffect.inventory", 2),
        ArtifactKind::Processes => ("processes.json", "sideeffect.process_inventory", 1),
        ArtifactKind::Permissions => ("permissions.json", "sideeffect.permission_inventory", 1),
        ArtifactKind::Startup => ("startup.json", "sideeffect.startup_inventory", 2),
        ArtifactKind::WindowsSoftware => (
            "software.windows.json",
            "sideeffect.windows_software_inventory",
            1,
        ),
        ArtifactKind::WindowsProcesses => (
            "processes.windows.json",
            "sideeffect.windows_process_inventory",
            1,
        ),
        ArtifactKind::WindowsPermissions => (
            "permissions.windows.json",
            "sideeffect.windows_permission_inventory",
            1,
        ),
        ArtifactKind::WindowsStartup => (
            "startup.windows.json",
            "sideeffect.windows_startup_inventory",
            4,
        ),
        ArtifactKind::RuntimeManifest => ("run.json", "sideeffect.run", 2),
        ArtifactKind::RuntimeTrace => ("trace.strace", "strace_text", 1),
    })
}

fn validate_artifact_path(path: &str) -> Result<(), ValidationError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path.contains(':')
    {
        return Err(ValidationError::InvalidArtifactPath);
    }
    Ok(())
}

fn validate_platform(value: &str) -> Result<(), ValidationError> {
    validate_token(value, MAX_PLATFORM_BYTES, "platform")?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
    }) {
        return Err(ValidationError::InvalidPlatform);
    }
    Ok(())
}

fn validate_token(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ValidationError::InvalidMetadata(field));
    }
    Ok(())
}

fn validate_bounded_text(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ValidationError::InvalidMetadata(field));
    }
    Ok(())
}

fn validate_code(code: &str) -> Result<(), ValidationError> {
    if code.is_empty()
        || code.len() > MAX_CODE_BYTES
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ValidationError::InvalidCode);
    }
    Ok(())
}

fn validate_interval(start: u128, end: u128) -> Result<(), ValidationError> {
    if start == 0 || end < start || end > MAX_SESSION_TIMESTAMP_UNIX_MS {
        return Err(ValidationError::InvalidTimestampInterval);
    }
    Ok(())
}

fn is_session_id(value: &str) -> bool {
    value.len() == 32 && is_lower_hex(value, 32)
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    InvalidSchema,
    InvalidSessionId,
    InvalidMetadata(&'static str),
    InvalidPlatform,
    InvalidTimestampInterval,
    SourceCountOutOfBounds,
    DuplicateSourceRole,
    SourcePlatformMismatch,
    SourceOutsideSessionInterval,
    MetadataCountOutOfBounds,
    InvalidCode,
    UnsupportedArtifactPlatform,
    ArtifactSetMismatch,
    ArtifactContractMismatch,
    InvalidArtifactPath,
    DuplicateArtifact,
    ArtifactSizeOutOfBounds,
    AggregateSizeOutOfBounds,
    InvalidArtifactDigest,
    SessionStatusHidesIncompleteSource,
    RuntimeCompletenessNotEstablished,
    ManifestTooLarge,
    InvalidManifestJson,
}

#[cfg(test)]
mod tests {
    use super::{
        AUDIT_SESSION_SCHEMA, AUDIT_SESSION_SCHEMA_VERSION, AppliedLimit, ArtifactKind,
        AuditSessionManifest, AuditSessionSource, IntervalSemantics, SessionArtifactRef,
        SessionStatus, SourceRole, SourceStatus, ValidationError, parse_manifest,
    };

    fn valid_manifest() -> AuditSessionManifest {
        AuditSessionManifest {
            schema: AUDIT_SESSION_SCHEMA.to_owned(),
            schema_version: AUDIT_SESSION_SCHEMA_VERSION,
            session_id: "0123456789abcdef0123456789abcdef".to_owned(),
            platform: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            started_at_unix_ms: 1000,
            ended_at_unix_ms: 1002,
            interval_semantics: IntervalSemantics::BestEffortNonAtomic,
            status: SessionStatus::Complete,
            sources: vec![AuditSessionSource {
                role: SourceRole::Packages,
                platform: "linux".to_owned(),
                scope: "available package databases".to_owned(),
                started_at_unix_ms: 1000,
                ended_at_unix_ms: 1001,
                status: SourceStatus::Complete,
                applied_limits: vec![AppliedLimit {
                    code: "max_inventory_rows".to_owned(),
                    value: 200_000,
                }],
                diagnostic_codes: Vec::new(),
                artifacts: vec![SessionArtifactRef {
                    kind: ArtifactKind::Packages,
                    path: "packages.json".to_owned(),
                    schema: "sideeffect.inventory".to_owned(),
                    schema_version: 2,
                    byte_length: 1,
                    sha256: "0".repeat(64),
                }],
            }],
        }
    }

    #[test]
    fn parser_accepts_a_bounded_complete_manifest() {
        let bytes = serde_json::to_vec(&valid_manifest()).unwrap();
        let parsed = parse_manifest(&bytes).unwrap();
        assert_eq!(parsed.session_id, "0123456789abcdef0123456789abcdef");
        assert_eq!(parsed.sources[0].artifacts[0].path, "packages.json");
    }

    #[test]
    fn parser_rejects_unknown_schema_versions_and_unknown_fields() {
        let mut manifest = valid_manifest();
        manifest.schema_version += 1;
        assert_eq!(
            manifest.validate(),
            Err(super::ValidationError::InvalidSchema)
        );

        let bytes =
            br#"{"schema":"sideeffect.audit_session","schema_version":1,"unexpected":true}"#;
        assert_eq!(
            parse_manifest(bytes),
            Err(super::ValidationError::InvalidManifestJson)
        );
        assert_eq!(
            parse_manifest(b"{"),
            Err(super::ValidationError::InvalidManifestJson)
        );
    }

    #[test]
    fn incomplete_source_cannot_be_hidden_by_a_complete_session() {
        let mut manifest = valid_manifest();
        manifest.sources[0].status = SourceStatus::Partial;
        assert_eq!(
            manifest.validate(),
            Err(super::ValidationError::SessionStatusHidesIncompleteSource)
        );
        manifest.status = SessionStatus::Partial;
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn partial_session_can_preserve_an_unavailable_selected_source_without_artifact() {
        let mut manifest = valid_manifest();
        manifest.status = SessionStatus::Partial;
        manifest.sources.push(AuditSessionSource {
            role: SourceRole::Processes,
            platform: "linux".to_owned(),
            scope: "visible procfs entries".to_owned(),
            started_at_unix_ms: 1001,
            ended_at_unix_ms: 1002,
            status: SourceStatus::Unavailable,
            applied_limits: Vec::new(),
            diagnostic_codes: vec!["procfs_unavailable".to_owned()],
            artifacts: Vec::new(),
        });

        assert!(manifest.validate().is_ok());
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert_eq!(parse_manifest(&bytes).unwrap(), manifest);
    }

    #[test]
    fn source_intervals_must_fit_inside_the_non_atomic_session_window() {
        let mut manifest = valid_manifest();
        manifest.sources[0].ended_at_unix_ms = manifest.ended_at_unix_ms + 1;
        assert_eq!(
            manifest.validate(),
            Err(super::ValidationError::SourceOutsideSessionInterval)
        );
    }

    #[test]
    fn oversized_manifest_is_rejected_before_json_parsing() {
        let bytes = vec![b' '; super::MAX_AUDIT_SESSION_MANIFEST_BYTES + 1];
        assert_eq!(
            parse_manifest(&bytes),
            Err(super::ValidationError::ManifestTooLarge)
        );
    }

    #[test]
    fn windows_manifest_has_fixed_native_artifact_contracts_and_mixed_statuses() {
        let mut manifest = valid_manifest();
        manifest.platform = "windows".to_owned();
        manifest.architecture = "x86_64".to_owned();
        manifest.sources[0].platform = "windows".to_owned();
        manifest.sources[0].scope = "bounded native software registrations".to_owned();
        manifest.sources[0].artifacts = vec![SessionArtifactRef {
            kind: ArtifactKind::WindowsSoftware,
            path: "software.windows.json".to_owned(),
            schema: "sideeffect.windows_software_inventory".to_owned(),
            schema_version: 1,
            byte_length: 1,
            sha256: "0".repeat(64),
        }];
        manifest.sources.push(AuditSessionSource {
            role: SourceRole::Runtime,
            platform: "windows".to_owned(),
            scope: "native runtime capture unsupported".to_owned(),
            started_at_unix_ms: 1001,
            ended_at_unix_ms: 1002,
            status: SourceStatus::Unsupported,
            applied_limits: Vec::new(),
            diagnostic_codes: vec!["windows_runtime_source_unsupported".to_owned()],
            artifacts: Vec::new(),
        });
        manifest.status = SessionStatus::Partial;
        assert!(manifest.validate().is_ok());

        manifest.sources[0].artifacts[0].schema_version = 99;
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::ArtifactContractMismatch)
        );
    }

    #[test]
    fn one_session_preserves_complete_partial_and_unavailable_sources() {
        let mut manifest = valid_manifest();
        let processes = AuditSessionSource {
            role: SourceRole::Processes,
            platform: "linux".to_owned(),
            scope: "visible procfs entries".to_owned(),
            started_at_unix_ms: 1001,
            ended_at_unix_ms: 1002,
            status: SourceStatus::Partial,
            applied_limits: Vec::new(),
            diagnostic_codes: vec!["process_entry_inaccessible".to_owned()],
            artifacts: vec![SessionArtifactRef {
                kind: ArtifactKind::Processes,
                path: "processes.json".to_owned(),
                schema: "sideeffect.process_inventory".to_owned(),
                schema_version: 1,
                byte_length: 1,
                sha256: "1".repeat(64),
            }],
        };
        let unavailable = AuditSessionSource {
            role: SourceRole::Startup,
            platform: "linux".to_owned(),
            scope: "selected startup locations".to_owned(),
            started_at_unix_ms: 1002,
            ended_at_unix_ms: 1002,
            status: SourceStatus::Unavailable,
            applied_limits: Vec::new(),
            diagnostic_codes: vec!["startup_source_unavailable".to_owned()],
            artifacts: Vec::new(),
        };
        manifest.sources.push(processes);
        manifest.sources.push(unavailable);
        manifest.status = SessionStatus::Partial;

        assert!(manifest.validate().is_ok());
        assert_eq!(manifest.status, SessionStatus::Partial);
        assert_eq!(manifest.sources[0].status, SourceStatus::Complete);
        assert_eq!(manifest.sources[0].artifacts.len(), 1);
        assert_eq!(manifest.sources[1].status, SourceStatus::Partial);
        assert_eq!(manifest.sources[1].started_at_unix_ms, 1001);
        assert_eq!(manifest.sources[1].ended_at_unix_ms, 1002);
        assert_eq!(manifest.sources[1].artifacts[0].path, "processes.json");
        assert_eq!(manifest.sources[2].status, SourceStatus::Unavailable);
        assert_eq!(manifest.sources[2].started_at_unix_ms, 1002);
        assert!(manifest.sources[2].artifacts.is_empty());
    }

    #[test]
    fn manifest_rejects_source_and_metadata_counts_over_their_bounds() {
        let mut manifest = valid_manifest();
        manifest.sources = vec![manifest.sources[0].clone(); super::MAX_SESSION_SOURCES + 1];
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::SourceCountOutOfBounds)
        );

        let mut manifest = valid_manifest();
        manifest.sources[0].applied_limits = vec![
            AppliedLimit {
                code: "max_test_limit".to_owned(),
                value: 1,
            };
            super::MAX_LIMITS_PER_SOURCE + 1
        ];
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::MetadataCountOutOfBounds)
        );

        let mut manifest = valid_manifest();
        manifest.sources[0].diagnostic_codes =
            vec!["test_diagnostic".to_owned(); super::MAX_DIAGNOSTIC_CODES_PER_SOURCE + 1];
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::MetadataCountOutOfBounds)
        );
    }

    #[test]
    fn manifest_rejects_per_artifact_and_aggregate_size_overages() {
        let mut manifest = valid_manifest();
        manifest.sources[0].artifacts[0].byte_length = super::MAX_SESSION_ARTIFACT_BYTES + 1;
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::ArtifactSizeOutOfBounds)
        );

        let mut manifest = valid_manifest();
        manifest.status = SessionStatus::Partial;
        manifest.sources[0].status = SourceStatus::Partial;
        manifest.sources[0].artifacts[0].byte_length = super::MAX_SESSION_ARTIFACT_BYTES;
        let source = |role, kind, path: &str, schema: &str| AuditSessionSource {
            role,
            platform: "linux".to_owned(),
            scope: "bounded test source".to_owned(),
            started_at_unix_ms: 1000,
            ended_at_unix_ms: 1002,
            status: SourceStatus::Partial,
            applied_limits: Vec::new(),
            diagnostic_codes: Vec::new(),
            artifacts: vec![SessionArtifactRef {
                kind,
                path: path.to_owned(),
                schema: schema.to_owned(),
                schema_version: 1,
                byte_length: super::MAX_SESSION_ARTIFACT_BYTES,
                sha256: "0".repeat(64),
            }],
        };
        manifest.sources.push(source(
            SourceRole::Processes,
            ArtifactKind::Processes,
            "processes.json",
            "sideeffect.process_inventory",
        ));
        manifest.sources.push(source(
            SourceRole::Permissions,
            ArtifactKind::Permissions,
            "permissions.json",
            "sideeffect.permission_inventory",
        ));
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::AggregateSizeOutOfBounds)
        );
    }
}
