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

            let expected = expected_artifacts(source.role, &source.platform)?;
            if source.artifacts.len() > expected.len()
                || (source.status == SourceStatus::Complete
                    && source.artifacts.len() != expected.len())
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
    if platform != "linux" {
        return Err(ValidationError::UnsupportedArtifactPlatform);
    }
    Ok(match role {
        SourceRole::Packages => vec![ArtifactKind::Packages],
        SourceRole::Processes => vec![ArtifactKind::Processes],
        SourceRole::Permissions => vec![ArtifactKind::Permissions],
        SourceRole::Startup => vec![ArtifactKind::Startup],
        SourceRole::Runtime => vec![ArtifactKind::RuntimeManifest, ArtifactKind::RuntimeTrace],
    })
}

fn artifact_contract(
    kind: ArtifactKind,
) -> Result<(&'static str, &'static str, u32), ValidationError> {
    Ok(match kind {
        ArtifactKind::Packages => ("packages.json", "sideeffect.inventory", 2),
        ArtifactKind::Processes => ("processes.json", "sideeffect.process_inventory", 1),
        ArtifactKind::Permissions => ("permissions.json", "sideeffect.permission_inventory", 1),
        ArtifactKind::Startup => ("startup.json", "sideeffect.startup_inventory", 2),
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
    ManifestTooLarge,
    InvalidManifestJson,
}
