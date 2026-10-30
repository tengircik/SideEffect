//! Versioned, platform-neutral manifest for a best-effort local audit session.
//!
//! This envelope references source artifacts without normalizing their native
//! schemas. It describes a set of observations collected over an interval; it
//! does not claim that the sources were captured atomically.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const AUDIT_SESSION_SCHEMA: &str = "sideeffect.audit_session";
pub const AUDIT_SESSION_SCHEMA_VERSION: u32 = 5;
pub const AUDIT_SESSION_V1_SCHEMA_VERSION: u32 = 1;
pub const AUDIT_SESSION_V2_SCHEMA_VERSION: u32 = 2;
pub const AUDIT_SESSION_V3_SCHEMA_VERSION: u32 = 3;
pub const AUDIT_SESSION_V4_SCHEMA_VERSION: u32 = 4;
pub const COVERAGE_MANIFEST_VERSION: u32 = 1;
pub const MAX_AUDIT_SESSION_MANIFEST_BYTES: usize = 512 * 1024;
pub const MAX_SESSION_SOURCES: usize = 8;
pub const MAX_SESSION_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_SESSION_TOTAL_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_SESSION_TIMESTAMP_UNIX_MS: u128 = 253_402_300_799_999;
pub const MAX_PLATFORM_BYTES: usize = 64;
pub const MAX_SCOPE_BYTES: usize = 4 * 1024;
pub const MAX_LIMITS_PER_SOURCE: usize = 64;
pub const MAX_SETTINGS_PER_SOURCE: usize = 32;
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
    /// Host identity and caller privilege facts. Absent from v1-v3 manifests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_context: Option<HostContext>,
    /// Missing in v1 manifests; v2-v5 producers include an explicit bounded map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_manifest: Option<CoverageManifest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostContext {
    pub os_name: ContextFact,
    pub os_version: ContextFact,
    pub privilege: PrivilegeContext,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextFact {
    pub status: ContextFactStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextFactStatus {
    Observed,
    Unknown,
    NotChecked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeContext {
    Elevated,
    NotElevated,
    Unknown,
    NotChecked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageManifest {
    pub version: u32,
    pub sources: Vec<SourceCoverage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCoverage {
    pub role: SourceRole,
    pub status: CoverageStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Observed,
    Configured,
    NotObserved,
    NotChecked,
    Unsupported,
    Inaccessible,
    Partial,
    Unknown,
}

impl CoverageManifest {
    /// Summarize only the selected source's declared result. This is not an
    /// assertion that the source or operating system was exhaustively covered.
    pub fn from_sources(sources: &[AuditSessionSource]) -> Self {
        let sources = sources
            .iter()
            .map(|source| SourceCoverage {
                role: source.role,
                status: coverage_status_for_source(source),
            })
            .collect();
        Self {
            version: COVERAGE_MANIFEST_VERSION,
            sources,
        }
    }
}

fn coverage_status_for_source(source: &AuditSessionSource) -> CoverageStatus {
    match source.status {
        SourceStatus::Complete if source.role == SourceRole::Startup => CoverageStatus::Configured,
        // “Observed” means the selected inventory snapshot was read; it does
        // not mean runtime activity was observed.
        SourceStatus::Complete => CoverageStatus::Observed,
        SourceStatus::Partial => CoverageStatus::Partial,
        SourceStatus::NotChecked => CoverageStatus::NotChecked,
        SourceStatus::Unsupported => CoverageStatus::Unsupported,
        SourceStatus::AccessDenied => CoverageStatus::Inaccessible,
        SourceStatus::Unknown
        | SourceStatus::NotApplicable
        | SourceStatus::Unavailable
        | SourceStatus::Failed
        | SourceStatus::TimedOut
        | SourceStatus::OutputLimitExceeded => CoverageStatus::Unknown,
    }
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
    /// Collector implementation identity. Absent from v1-v4 manifests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector: Option<CollectorIdentity>,
    pub platform: String,
    pub scope: String,
    pub started_at_unix_ms: u128,
    pub ended_at_unix_ms: u128,
    pub status: SourceStatus,
    pub applied_limits: Vec<AppliedLimit>,
    /// Explicitly requested settings are kept separate from collector limits
    /// and from settings the source reports as effective.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_settings: Vec<Setting>,
    /// Settings reported by the source as effective; absent means unavailable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_settings: Vec<Setting>,
    /// Runtime loss facts, if this source reports them. Inventory sources omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss: Option<LossMetadata>,
    pub diagnostic_codes: Vec<String>,
    pub artifacts: Vec<SessionArtifactRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorIdentity {
    /// Stable platform+role implementation ID.
    pub id: String,
    /// SideEffect package version implementing the collector.
    pub version: String,
    /// Present only for a provider-backed Windows ETW runtime source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Setting {
    /// Stable snake_case code naming a requested or source-reported setting.
    pub code: String,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LossStatus {
    Reported,
    NoneReported,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LossMetadata {
    pub status: LossStatus,
    pub statistics_available: bool,
    pub final_snapshot_available: bool,
    pub events_lost: Option<u64>,
    pub log_buffers_lost: Option<u64>,
    pub real_time_buffers_lost: Option<u64>,
}

impl LossMetadata {
    pub fn unknown() -> Self {
        Self {
            status: LossStatus::Unknown,
            statistics_available: false,
            final_snapshot_available: false,
            events_lost: None,
            log_buffers_lost: None,
            real_time_buffers_lost: None,
        }
    }
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
    WindowsRuntimeCapture,
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
            || !matches!(
                self.schema_version,
                AUDIT_SESSION_V1_SCHEMA_VERSION..=AUDIT_SESSION_SCHEMA_VERSION
            )
        {
            return Err(ValidationError::InvalidSchema);
        }
        if !is_session_id(&self.session_id) {
            return Err(ValidationError::InvalidSessionId);
        }
        validate_platform(&self.platform)?;
        validate_token(&self.architecture, MAX_PLATFORM_BYTES, "architecture")?;
        match (&self.host_context, self.schema_version) {
            (None, 1..=3) => {}
            (Some(context), AUDIT_SESSION_V4_SCHEMA_VERSION | AUDIT_SESSION_SCHEMA_VERSION) => {
                for fact in [&context.os_name, &context.os_version] {
                    match (fact.status, &fact.value) {
                        (ContextFactStatus::Observed, Some(value)) => {
                            validate_bounded_text(value, 128, "host context value")?;
                        }
                        (ContextFactStatus::Unknown | ContextFactStatus::NotChecked, None) => {}
                        _ => return Err(ValidationError::InvalidHostContext),
                    }
                }
            }
            _ => return Err(ValidationError::InvalidHostContext),
        }
        validate_interval(self.started_at_unix_ms, self.ended_at_unix_ms)?;
        if self.sources.is_empty() || self.sources.len() > MAX_SESSION_SOURCES {
            return Err(ValidationError::SourceCountOutOfBounds);
        }
        match (&self.coverage_manifest, self.schema_version) {
            (None, AUDIT_SESSION_V1_SCHEMA_VERSION) => {}
            (
                Some(coverage),
                AUDIT_SESSION_V2_SCHEMA_VERSION
                | AUDIT_SESSION_V3_SCHEMA_VERSION
                | AUDIT_SESSION_V4_SCHEMA_VERSION
                | AUDIT_SESSION_SCHEMA_VERSION,
            ) => {
                if coverage.version != COVERAGE_MANIFEST_VERSION
                    || coverage.sources.len() != self.sources.len()
                    || coverage.sources.len() > MAX_SESSION_SOURCES
                {
                    return Err(ValidationError::InvalidCoverageManifest);
                }
                let mut coverage_roles = HashSet::new();
                for entry in &coverage.sources {
                    let Some(source) = self.sources.iter().find(|s| s.role == entry.role) else {
                        return Err(ValidationError::InvalidCoverageManifest);
                    };
                    if !coverage_roles.insert(entry.role)
                        || entry.status != coverage_status_for_source(source)
                    {
                        return Err(ValidationError::InvalidCoverageManifest);
                    }
                }
            }
            _ => return Err(ValidationError::InvalidCoverageManifest),
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
            match (&source.collector, self.schema_version) {
                (None, 1..=AUDIT_SESSION_V4_SCHEMA_VERSION) => {}
                (Some(identity), AUDIT_SESSION_SCHEMA_VERSION) => {
                    validate_collector_identity(identity, &source.platform, source.role)?;
                }
                _ => return Err(ValidationError::InvalidCollectorIdentity),
            }
            validate_interval(source.started_at_unix_ms, source.ended_at_unix_ms)?;
            if source.started_at_unix_ms < self.started_at_unix_ms
                || source.ended_at_unix_ms > self.ended_at_unix_ms
            {
                return Err(ValidationError::SourceOutsideSessionInterval);
            }
            if source.applied_limits.len() > MAX_LIMITS_PER_SOURCE
                || source.requested_settings.len() > MAX_SETTINGS_PER_SOURCE
                || source.effective_settings.len() > MAX_SETTINGS_PER_SOURCE
                || source.diagnostic_codes.len() > MAX_DIAGNOSTIC_CODES_PER_SOURCE
            {
                return Err(ValidationError::MetadataCountOutOfBounds);
            }
            for limit in &source.applied_limits {
                validate_code(&limit.code)?;
            }
            for setting in source
                .requested_settings
                .iter()
                .chain(&source.effective_settings)
            {
                validate_code(&setting.code)?;
            }
            if source.role == SourceRole::Runtime
                && self.schema_version >= AUDIT_SESSION_V3_SCHEMA_VERSION
            {
                if source.loss.is_none() {
                    return Err(ValidationError::InvalidLossMetadata);
                }
            } else if source.loss.is_some() {
                return Err(ValidationError::InvalidLossMetadata);
            }
            if self.schema_version < AUDIT_SESSION_V3_SCHEMA_VERSION
                && (!source.requested_settings.is_empty() || !source.effective_settings.is_empty())
            {
                return Err(ValidationError::InvalidSourceSettings);
            }
            if let Some(loss) = &source.loss {
                let counters = [
                    loss.events_lost,
                    loss.log_buffers_lost,
                    loss.real_time_buffers_lost,
                ];
                let reported = counters.iter().any(|count| count.is_some_and(|n| n > 0));
                let all_counters_available = counters.iter().all(Option::is_some);
                match loss.status {
                    LossStatus::Reported
                        if !reported || !loss.statistics_available || !all_counters_available =>
                    {
                        return Err(ValidationError::InvalidLossMetadata);
                    }
                    LossStatus::NoneReported
                        if reported
                            || !all_counters_available
                            || !loss.statistics_available
                            || !loss.final_snapshot_available =>
                    {
                        return Err(ValidationError::InvalidLossMetadata);
                    }
                    LossStatus::Unknown
                        if reported
                            || (loss.statistics_available && loss.final_snapshot_available) =>
                    {
                        return Err(ValidationError::InvalidLossMetadata);
                    }
                    _ => {}
                }
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
            let mut source_artifact_kinds = HashSet::new();
            for artifact in &source.artifacts {
                let (path, schema, version) = artifact_contract(artifact.kind)?;
                if !expected.contains(&artifact.kind)
                    || !source_artifact_kinds.insert(artifact.kind)
                    || artifact.path != path
                    || artifact.schema != schema
                    || !artifact_version_supported(artifact.kind, artifact.schema_version, version)
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

/// Result of the metadata-only audit-session comparability check.
///
/// A comparable result means the manifests describe matching declared
/// collection contexts. It does not establish complete capture, equal event
/// sets, or the absence of activity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComparabilityResult {
    pub comparable: bool,
    /// Stable, bounded reason codes. The list is ordered by comparison stage.
    pub reasons: Vec<ComparabilityReason>,
}

/// Stable reason codes returned by [`compare_sessions`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComparabilityReason {
    PlatformMismatch,
    ArchitectureMismatch,
    HostOsMismatch,
    HostOsUnknown,
    SourceRolesMismatch,
    SourcePlatformMismatch,
    SourceScopeMismatch,
    SourceStatusMismatch,
    PartialSource,
    UnknownSourceStatus,
    AppliedLimitsMismatch,
    RequestedSettingsMismatch,
    EffectiveSettingsMismatch,
    SourceSettingsUnknown,
    ArtifactSetMismatch,
    ArtifactContractMismatch,
    CollectorIdentityMismatch,
    CollectorIdentityUnknown,
    CoverageUnknown,
    CoverageMismatch,
    RuntimeLossMismatch,
    RuntimeLossReported,
    RuntimeLossUnknown,
}

impl ComparabilityReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::PlatformMismatch => "platform_mismatch",
            Self::ArchitectureMismatch => "architecture_mismatch",
            Self::HostOsMismatch => "host_os_mismatch",
            Self::HostOsUnknown => "host_os_unknown",
            Self::SourceRolesMismatch => "source_roles_mismatch",
            Self::SourcePlatformMismatch => "source_platform_mismatch",
            Self::SourceScopeMismatch => "source_scope_mismatch",
            Self::SourceStatusMismatch => "source_status_mismatch",
            Self::PartialSource => "partial_source",
            Self::UnknownSourceStatus => "unknown_source_status",
            Self::AppliedLimitsMismatch => "applied_limits_mismatch",
            Self::RequestedSettingsMismatch => "requested_settings_mismatch",
            Self::EffectiveSettingsMismatch => "effective_settings_mismatch",
            Self::SourceSettingsUnknown => "source_settings_unknown",
            Self::ArtifactSetMismatch => "artifact_set_mismatch",
            Self::ArtifactContractMismatch => "artifact_contract_mismatch",
            Self::CollectorIdentityMismatch => "collector_identity_mismatch",
            Self::CollectorIdentityUnknown => "collector_identity_unknown",
            Self::CoverageUnknown => "coverage_unknown",
            Self::CoverageMismatch => "coverage_mismatch",
            Self::RuntimeLossMismatch => "runtime_loss_mismatch",
            Self::RuntimeLossReported => "runtime_loss_reported",
            Self::RuntimeLossUnknown => "runtime_loss_unknown",
        }
    }
}

/// Compare two already-validated manifests using only their declared metadata.
/// Missing host context or v1-v2 source settings are treated as unknown, never
/// as evidence that the sessions used matching settings.
pub fn compare_sessions(
    left: &AuditSessionManifest,
    right: &AuditSessionManifest,
) -> ComparabilityResult {
    use ComparabilityReason as R;
    let mut reasons = Vec::new();
    let mut comparable = true;
    let mut add = |reason: R, makes_incomparable: bool| {
        if !reasons.contains(&reason) && reasons.len() < 32 {
            reasons.push(reason);
        }
        if makes_incomparable {
            comparable = false;
        }
    };

    if left.platform != right.platform {
        add(R::PlatformMismatch, true);
    }
    if left.architecture != right.architecture {
        add(R::ArchitectureMismatch, true);
    }
    match (&left.host_context, &right.host_context) {
        (Some(a), Some(b)) => {
            for (a, b) in [(&a.os_name, &b.os_name), (&a.os_version, &b.os_version)] {
                match (a.status, &a.value, b.status, &b.value) {
                    (
                        ContextFactStatus::Observed,
                        Some(av),
                        ContextFactStatus::Observed,
                        Some(bv),
                    ) => {
                        if av != bv {
                            add(R::HostOsMismatch, true);
                        }
                    }
                    _ => add(R::HostOsUnknown, true),
                }
            }
        }
        _ => add(R::HostOsUnknown, true),
    }

    if left.schema_version < AUDIT_SESSION_V4_SCHEMA_VERSION
        || right.schema_version < AUDIT_SESSION_V4_SCHEMA_VERSION
    {
        // Host context did not exist in those versions, even if deserialized
        // defaults happen to look alike.
        add(R::HostOsUnknown, true);
    }

    let mut left_sources: Vec<_> = left.sources.iter().collect();
    let mut right_sources: Vec<_> = right.sources.iter().collect();
    left_sources.sort_by_key(|s| s.role as u8);
    right_sources.sort_by_key(|s| s.role as u8);
    if left_sources
        .iter()
        .map(|s| s.role)
        .ne(right_sources.iter().map(|s| s.role))
    {
        add(R::SourceRolesMismatch, true);
    }

    if left.schema_version < AUDIT_SESSION_V3_SCHEMA_VERSION
        || right.schema_version < AUDIT_SESSION_V3_SCHEMA_VERSION
    {
        add(R::SourceSettingsUnknown, true);
    }
    if left.schema_version == AUDIT_SESSION_V1_SCHEMA_VERSION
        || right.schema_version == AUDIT_SESSION_V1_SCHEMA_VERSION
        || left.coverage_manifest.is_none()
        || right.coverage_manifest.is_none()
    {
        add(R::CoverageUnknown, true);
    } else if let (Some(a), Some(b)) = (&left.coverage_manifest, &right.coverage_manifest) {
        let mut a_coverage: Vec<_> = a.sources.iter().map(|s| (s.role, s.status)).collect();
        let mut b_coverage: Vec<_> = b.sources.iter().map(|s| (s.role, s.status)).collect();
        a_coverage.sort_unstable_by_key(|(role, _)| *role as u8);
        b_coverage.sort_unstable_by_key(|(role, _)| *role as u8);
        if a.version != b.version || a_coverage != b_coverage {
            add(R::CoverageMismatch, true);
        }
    }

    for a in &left_sources {
        let Some(b) = right.sources.iter().find(|s| s.role == a.role) else {
            continue;
        };
        if a.platform != b.platform {
            add(R::SourcePlatformMismatch, true);
        }
        match (&a.collector, &b.collector) {
            (Some(x), Some(y)) if x == y => {}
            (Some(_), Some(_)) => add(R::CollectorIdentityMismatch, true),
            _ => add(R::CollectorIdentityUnknown, true),
        }
        if a.scope != b.scope {
            add(R::SourceScopeMismatch, true);
        }
        if a.status != b.status {
            add(R::SourceStatusMismatch, true);
        }
        match a.status {
            SourceStatus::Partial => add(R::PartialSource, false),
            SourceStatus::Unknown
            | SourceStatus::NotChecked
            | SourceStatus::NotApplicable
            | SourceStatus::Unavailable
            | SourceStatus::AccessDenied
            | SourceStatus::Failed
            | SourceStatus::TimedOut
            | SourceStatus::OutputLimitExceeded => add(R::UnknownSourceStatus, true),
            SourceStatus::Complete | SourceStatus::Unsupported => {}
        }
        let mut a_limits: Vec<_> = a
            .applied_limits
            .iter()
            .map(|v| (&v.code, v.value))
            .collect();
        let mut b_limits: Vec<_> = b
            .applied_limits
            .iter()
            .map(|v| (&v.code, v.value))
            .collect();
        a_limits.sort_unstable();
        b_limits.sort_unstable();
        if a_limits != b_limits {
            add(R::AppliedLimitsMismatch, true);
        }
        let mut a_requested: Vec<_> = a
            .requested_settings
            .iter()
            .map(|v| (&v.code, v.value))
            .collect();
        let mut b_requested: Vec<_> = b
            .requested_settings
            .iter()
            .map(|v| (&v.code, v.value))
            .collect();
        a_requested.sort_unstable();
        b_requested.sort_unstable();
        if a_requested != b_requested {
            add(R::RequestedSettingsMismatch, true);
        }
        let mut a_effective: Vec<_> = a
            .effective_settings
            .iter()
            .map(|v| (&v.code, v.value))
            .collect();
        let mut b_effective: Vec<_> = b
            .effective_settings
            .iter()
            .map(|v| (&v.code, v.value))
            .collect();
        a_effective.sort_unstable();
        b_effective.sort_unstable();
        if a_effective != b_effective {
            add(R::EffectiveSettingsMismatch, true);
        }

        let mut aa: Vec<_> = a.artifacts.iter().collect();
        let mut ba: Vec<_> = b.artifacts.iter().collect();
        aa.sort_by_key(|x| (x.kind as u8, x.path.as_str()));
        ba.sort_by_key(|x| (x.kind as u8, x.path.as_str()));
        if aa.len() != ba.len()
            || aa
                .iter()
                .map(|x| (x.kind, x.path.as_str()))
                .ne(ba.iter().map(|x| (x.kind, x.path.as_str())))
        {
            add(R::ArtifactSetMismatch, true);
        } else if aa
            .iter()
            .zip(&ba)
            .any(|(x, y)| x.schema != y.schema || x.schema_version != y.schema_version)
        {
            add(R::ArtifactContractMismatch, true);
        }

        if a.role == SourceRole::Runtime {
            match (&a.loss, &b.loss) {
                (None, None) => add(R::RuntimeLossUnknown, true),
                (Some(x), Some(y)) => {
                    if x.status != y.status || x != y {
                        add(R::RuntimeLossMismatch, true);
                    }
                    match x.status {
                        LossStatus::Reported => add(R::RuntimeLossReported, true),
                        LossStatus::Unknown => add(R::RuntimeLossUnknown, true),
                        LossStatus::NoneReported => {}
                    }
                }
                _ => add(R::RuntimeLossMismatch, true),
            }
        }
    }

    ComparabilityResult {
        comparable,
        reasons,
    }
}

fn artifact_version_supported(kind: ArtifactKind, observed: u32, current: u32) -> bool {
    observed == current
        || (observed == 1
            && matches!(
                kind,
                ArtifactKind::Processes | ArtifactKind::WindowsProcesses
            ))
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
            SourceRole::Runtime => vec![ArtifactKind::WindowsRuntimeCapture],
        }),
        _ => Err(ValidationError::UnsupportedArtifactPlatform),
    }
}

fn artifact_contract(
    kind: ArtifactKind,
) -> Result<(&'static str, &'static str, u32), ValidationError> {
    Ok(match kind {
        ArtifactKind::Packages => ("packages.json", "sideeffect.inventory", 2),
        ArtifactKind::Processes => ("processes.json", "sideeffect.process_inventory", 2),
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
            2,
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
        ArtifactKind::WindowsRuntimeCapture => (
            "runtime.windows.json",
            "sideeffect.windows_runtime_capture",
            3,
        ),
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

pub fn collector_identity(platform: &str, role: SourceRole) -> CollectorIdentity {
    let id = match (platform, role) {
        ("linux", SourceRole::Packages) => "linux.debian_packages",
        ("linux", SourceRole::Processes) => "linux.procfs_processes",
        ("linux", SourceRole::Permissions) => "linux.selected_path_permissions",
        ("linux", SourceRole::Startup) => "linux.curated_startup_sources",
        ("linux", SourceRole::Runtime) => "linux.strace_runtime",
        ("windows", SourceRole::Packages) => "windows.software_registry",
        ("windows", SourceRole::Processes) => "windows.toolhelp_processes",
        ("windows", SourceRole::Permissions) => "windows.selected_path_permissions",
        ("windows", SourceRole::Startup) => "windows.curated_startup_sources",
        ("windows", SourceRole::Runtime) => "windows.etw_runtime",
        _ => "unknown",
    };
    CollectorIdentity {
        id: id.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        provider_id: (platform == "windows" && role == SourceRole::Runtime)
            .then(|| "nt_kernel_logger".to_owned()),
    }
}

fn validate_collector_identity(
    identity: &CollectorIdentity,
    platform: &str,
    role: SourceRole,
) -> Result<(), ValidationError> {
    let expected = collector_identity(platform, role);
    validate_token(&identity.id, 96, "collector id")?;
    validate_token(&identity.version, 64, "collector version")?;
    if !identity.id.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
    }) || identity.id != expected.id
        || identity.provider_id != expected.provider_id
    {
        return Err(ValidationError::InvalidCollectorIdentity);
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
    InvalidLossMetadata,
    InvalidHostContext,
    InvalidSourceSettings,
    InvalidCollectorIdentity,
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
    InvalidCoverageManifest,
}

#[cfg(test)]
mod tests {
    use super::{
        AUDIT_SESSION_SCHEMA, AUDIT_SESSION_SCHEMA_VERSION, AUDIT_SESSION_V1_SCHEMA_VERSION,
        AUDIT_SESSION_V2_SCHEMA_VERSION, AUDIT_SESSION_V3_SCHEMA_VERSION, AppliedLimit,
        ArtifactKind, AuditSessionManifest, AuditSessionSource, CoverageManifest,
        IntervalSemantics, SessionArtifactRef, SessionStatus, SourceRole, SourceStatus,
        ValidationError, compare_sessions, parse_manifest,
    };

    fn valid_manifest() -> AuditSessionManifest {
        AuditSessionManifest {
            schema: AUDIT_SESSION_SCHEMA.to_owned(),
            schema_version: AUDIT_SESSION_SCHEMA_VERSION,
            session_id: "0123456789abcdef0123456789abcdef".to_owned(),
            platform: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            host_context: Some(super::HostContext {
                os_name: super::ContextFact {
                    status: super::ContextFactStatus::Observed,
                    value: Some("Linux".to_owned()),
                },
                os_version: super::ContextFact {
                    status: super::ContextFactStatus::Observed,
                    value: Some("6.1".to_owned()),
                },
                privilege: super::PrivilegeContext::NotElevated,
            }),
            started_at_unix_ms: 1000,
            ended_at_unix_ms: 1002,
            interval_semantics: IntervalSemantics::BestEffortNonAtomic,
            status: SessionStatus::Complete,
            coverage_manifest: Some(CoverageManifest::from_sources(&[AuditSessionSource {
                role: SourceRole::Packages,
                collector: Some(crate::audit_session::collector_identity(
                    "linux",
                    SourceRole::Packages,
                )),
                platform: "linux".to_owned(),
                scope: "available package databases".to_owned(),
                started_at_unix_ms: 1000,
                ended_at_unix_ms: 1001,
                status: SourceStatus::Complete,
                applied_limits: vec![],
                requested_settings: vec![],
                effective_settings: vec![],
                loss: None,
                diagnostic_codes: vec![],
                artifacts: vec![],
            }])),
            sources: vec![AuditSessionSource {
                role: SourceRole::Packages,
                collector: Some(crate::audit_session::collector_identity(
                    "linux",
                    SourceRole::Packages,
                )),
                platform: "linux".to_owned(),
                scope: "available package databases".to_owned(),
                started_at_unix_ms: 1000,
                ended_at_unix_ms: 1001,
                status: SourceStatus::Complete,
                applied_limits: vec![AppliedLimit {
                    code: "max_inventory_rows".to_owned(),
                    value: 200_000,
                }],
                requested_settings: vec![],
                effective_settings: vec![],
                loss: None,
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
    fn comparability_accepts_equal_known_metadata() {
        let manifest = valid_manifest();
        let result = compare_sessions(&manifest, &manifest);
        assert!(result.comparable);
        assert!(result.reasons.is_empty());
    }

    #[test]
    fn legacy_collector_identity_is_incomparable_and_v5_identity_is_strict() {
        let current = valid_manifest();
        let mut legacy = current.clone();
        legacy.schema_version = super::AUDIT_SESSION_V4_SCHEMA_VERSION;
        legacy.host_context = Some(current.host_context.clone().unwrap());
        legacy.sources[0].collector = None;
        assert!(legacy.validate().is_ok());
        let result = compare_sessions(&current, &legacy);
        assert!(!result.comparable);
        assert!(
            result
                .reasons
                .iter()
                .any(|r| r.code() == "collector_identity_unknown")
        );

        let mut invalid_id = current.clone();
        invalid_id.sources[0].collector.as_mut().unwrap().id = "linux.unknown".to_owned();
        assert_eq!(
            invalid_id.validate(),
            Err(ValidationError::InvalidCollectorIdentity)
        );

        let mut invalid_provider = current;
        invalid_provider.sources[0]
            .collector
            .as_mut()
            .unwrap()
            .provider_id = Some("nt_kernel_logger".to_owned());
        assert_eq!(
            invalid_provider.validate(),
            Err(ValidationError::InvalidCollectorIdentity)
        );
    }

    #[test]
    fn comparability_reports_mismatch_categories() {
        let mut left = valid_manifest();
        left.sources[0].role = SourceRole::Processes;
        left.sources[0].collector = Some(super::collector_identity("linux", SourceRole::Processes));
        left.sources[0].artifacts[0] = SessionArtifactRef {
            kind: ArtifactKind::Processes,
            path: "processes.json".to_owned(),
            schema: "sideeffect.process_inventory".to_owned(),
            schema_version: 1,
            byte_length: 1,
            sha256: "0".repeat(64),
        };
        left.coverage_manifest = Some(CoverageManifest::from_sources(&left.sources));
        assert!(left.validate().is_ok());
        let mut right = left.clone();
        right.architecture = "aarch64".to_owned();
        right.host_context.as_mut().unwrap().os_version.value = Some("6.2".to_owned());
        right.sources[0].scope = "different package scope".to_owned();
        right.sources[0].applied_limits[0].value += 1;
        right.sources[0].artifacts[0].schema_version = 2;
        assert!(right.validate().is_ok());
        let result = compare_sessions(&left, &right);
        assert!(!result.comparable);
        let codes: Vec<_> = result.reasons.iter().map(|r| r.code()).collect();
        assert!(codes.contains(&"architecture_mismatch"));
        assert!(codes.contains(&"host_os_mismatch"));
        assert!(codes.contains(&"source_scope_mismatch"));
        assert!(codes.contains(&"applied_limits_mismatch"));
        assert!(codes.contains(&"artifact_contract_mismatch"));
    }

    #[test]
    fn comparability_checks_settings_roles_and_source_statuses() {
        let mut left = valid_manifest();
        let mut right = valid_manifest();
        left.sources[0].requested_settings.push(super::Setting {
            code: "requested_duration_seconds".to_owned(),
            value: 5,
        });
        right.sources[0].requested_settings.push(super::Setting {
            code: "requested_duration_seconds".to_owned(),
            value: 10,
        });
        left.sources[0].effective_settings.push(super::Setting {
            code: "effective_buffer_count".to_owned(),
            value: 16,
        });
        right.sources[0].effective_settings.push(super::Setting {
            code: "effective_buffer_count".to_owned(),
            value: 32,
        });
        left.sources[0].status = SourceStatus::Partial;
        left.status = SessionStatus::Partial;
        left.coverage_manifest = Some(CoverageManifest::from_sources(&left.sources));
        let status_and_settings = compare_sessions(&left, &right);
        let status_codes: Vec<_> = status_and_settings
            .reasons
            .iter()
            .map(|r| r.code())
            .collect();
        assert!(status_codes.contains(&"source_status_mismatch"));
        assert!(status_codes.contains(&"requested_settings_mismatch"));
        assert!(status_codes.contains(&"effective_settings_mismatch"));

        right.sources[0].role = SourceRole::Processes;
        right.sources[0].collector =
            Some(super::collector_identity("linux", SourceRole::Processes));
        right.sources[0].artifacts[0].kind = ArtifactKind::Processes;
        right.sources[0].artifacts[0].path = "processes.json".to_owned();
        right.sources[0].artifacts[0].schema = "sideeffect.process_inventory".to_owned();
        right.coverage_manifest = Some(CoverageManifest::from_sources(&right.sources));
        let result = compare_sessions(&left, &right);
        let codes: Vec<_> = result.reasons.iter().map(|r| r.code()).collect();
        assert!(!result.comparable);
        assert!(codes.contains(&"source_roles_mismatch"));
    }

    #[test]
    fn partial_sources_are_comparable_with_partial_reason_but_unknown_is_not() {
        let mut partial = valid_manifest();
        partial.sources[0].status = SourceStatus::Partial;
        partial.status = SessionStatus::Partial;
        partial.coverage_manifest = Some(CoverageManifest::from_sources(&partial.sources));
        let result = compare_sessions(&partial, &partial);
        assert!(result.comparable);
        assert!(result.reasons.iter().any(|r| r.code() == "partial_source"));

        let mut unknown = valid_manifest();
        unknown.sources[0].status = SourceStatus::Unknown;
        unknown.status = SessionStatus::Partial;
        unknown.coverage_manifest = Some(CoverageManifest::from_sources(&unknown.sources));
        let result = compare_sessions(&unknown, &unknown);
        assert!(!result.comparable);
        assert!(
            result
                .reasons
                .iter()
                .any(|r| r.code() == "unknown_source_status")
        );
    }

    #[test]
    fn runtime_loss_and_legacy_metadata_are_incomparable_when_unknown() {
        let mut runtime = valid_manifest();
        runtime.sources[0].role = SourceRole::Runtime;
        runtime.sources[0].collector =
            Some(super::collector_identity("linux", SourceRole::Runtime));
        runtime.sources[0].status = SourceStatus::Partial;
        runtime.status = SessionStatus::Partial;
        runtime.sources[0].loss = Some(super::LossMetadata::unknown());
        runtime.sources[0].artifacts = vec![
            SessionArtifactRef {
                kind: ArtifactKind::RuntimeManifest,
                path: "run.json".to_owned(),
                schema: "sideeffect.run".to_owned(),
                schema_version: 2,
                byte_length: 1,
                sha256: "0".repeat(64),
            },
            SessionArtifactRef {
                kind: ArtifactKind::RuntimeTrace,
                path: "trace.strace".to_owned(),
                schema: "strace_text".to_owned(),
                schema_version: 1,
                byte_length: 1,
                sha256: "0".repeat(64),
            },
        ];
        runtime.coverage_manifest = Some(CoverageManifest::from_sources(&runtime.sources));
        assert!(runtime.validate().is_ok());
        let result = compare_sessions(&runtime, &runtime);
        assert!(!result.comparable);
        assert!(
            result
                .reasons
                .iter()
                .any(|r| r.code() == "runtime_loss_unknown")
        );

        let mut lost = runtime.clone();
        lost.sources[0].loss = Some(super::LossMetadata {
            status: super::LossStatus::Reported,
            statistics_available: true,
            final_snapshot_available: true,
            events_lost: Some(1),
            log_buffers_lost: Some(0),
            real_time_buffers_lost: Some(0),
        });
        let result = compare_sessions(&lost, &lost);
        assert!(!result.comparable);
        assert!(
            result
                .reasons
                .iter()
                .any(|r| r.code() == "runtime_loss_reported")
        );

        for version in [
            AUDIT_SESSION_V1_SCHEMA_VERSION,
            AUDIT_SESSION_V2_SCHEMA_VERSION,
            AUDIT_SESSION_V3_SCHEMA_VERSION,
        ] {
            let mut legacy = valid_manifest();
            legacy.schema_version = version;
            if version == AUDIT_SESSION_V1_SCHEMA_VERSION {
                legacy.coverage_manifest = None;
            }
            if version < AUDIT_SESSION_V3_SCHEMA_VERSION {
                legacy.sources[0].requested_settings.clear();
                legacy.sources[0].effective_settings.clear();
            }
            if version < AUDIT_SESSION_SCHEMA_VERSION {
                legacy.host_context = None;
            }
            let result = compare_sessions(&legacy, &legacy);
            assert!(
                !result.comparable,
                "v{version} must not guess absent metadata equal"
            );
            assert!(result.reasons.iter().any(|r| r.code() == "host_os_unknown"));
            if version < AUDIT_SESSION_V3_SCHEMA_VERSION {
                assert!(
                    result
                        .reasons
                        .iter()
                        .any(|r| r.code() == "source_settings_unknown")
                );
            }
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
    fn v1_manifests_remain_readable_without_inventing_coverage() {
        let mut value = serde_json::to_value(valid_manifest()).unwrap();
        value["schema_version"] = serde_json::json!(AUDIT_SESSION_V1_SCHEMA_VERSION);
        value.as_object_mut().unwrap().remove("coverage_manifest");
        value.as_object_mut().unwrap().remove("host_context");
        value["sources"][0]
            .as_object_mut()
            .unwrap()
            .remove("collector");
        let parsed = parse_manifest(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(parsed.schema_version, AUDIT_SESSION_V1_SCHEMA_VERSION);
        assert_eq!(parsed.coverage_manifest, None);

        let mut v2 = valid_manifest();
        v2.coverage_manifest = None;
        assert_eq!(v2.validate(), Err(ValidationError::InvalidCoverageManifest));
        let mut v2_value = serde_json::to_value(valid_manifest()).unwrap();
        v2_value["schema_version"] = serde_json::json!(AUDIT_SESSION_V2_SCHEMA_VERSION);
        v2_value.as_object_mut().unwrap().remove("host_context");
        v2_value["sources"][0]
            .as_object_mut()
            .unwrap()
            .remove("collector");
        let parsed_v2 = parse_manifest(&serde_json::to_vec(&v2_value).unwrap()).unwrap();
        assert_eq!(parsed_v2.schema_version, AUDIT_SESSION_V2_SCHEMA_VERSION);
        v2_value["sources"][0]["requested_settings"] = serde_json::json!([{
            "code": "test_setting",
            "value": 1
        }]);
        assert_eq!(
            parse_manifest(&serde_json::to_vec(&v2_value).unwrap()),
            Err(ValidationError::InvalidSourceSettings)
        );
    }

    #[test]
    fn v3_manifests_remain_readable_without_host_context() {
        let mut value = serde_json::to_value(valid_manifest()).unwrap();
        value["schema_version"] = serde_json::json!(super::AUDIT_SESSION_V3_SCHEMA_VERSION);
        value.as_object_mut().unwrap().remove("host_context");
        value["sources"][0]
            .as_object_mut()
            .unwrap()
            .remove("collector");
        let parsed = parse_manifest(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            parsed.schema_version,
            super::AUDIT_SESSION_V3_SCHEMA_VERSION
        );
        assert_eq!(parsed.host_context, None);
    }

    #[test]
    fn host_context_accepts_known_and_unknown_facts_and_enforces_bounds() {
        let mut manifest = valid_manifest();
        manifest.host_context.as_mut().unwrap().os_version = super::ContextFact {
            status: super::ContextFactStatus::Unknown,
            value: None,
        };
        manifest.validate().unwrap();
        manifest.host_context.as_mut().unwrap().os_name = super::ContextFact {
            status: super::ContextFactStatus::NotChecked,
            value: None,
        };
        manifest.validate().unwrap();
        manifest.host_context.as_mut().unwrap().os_version.value = Some("x".repeat(129));
        manifest.host_context.as_mut().unwrap().os_version.status =
            super::ContextFactStatus::Observed;
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::InvalidMetadata("host context value"))
        );
        manifest.host_context.as_mut().unwrap().os_version.value = None;
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::InvalidHostContext)
        );
    }

    #[test]
    fn coverage_manifest_is_bounded_versioned_and_explicit() {
        let mut manifest = valid_manifest();
        let entry = &manifest.coverage_manifest.as_ref().unwrap().sources[0];
        assert_eq!(entry.status, super::CoverageStatus::Observed);
        manifest.coverage_manifest.as_mut().unwrap().sources[0].status =
            super::CoverageStatus::Configured;
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::InvalidCoverageManifest)
        );
        manifest.coverage_manifest.as_mut().unwrap().sources[0].status =
            super::CoverageStatus::Observed;
        manifest.coverage_manifest.as_mut().unwrap().version += 1;
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::InvalidCoverageManifest)
        );
        let startup = AuditSessionSource {
            role: SourceRole::Startup,
            collector: Some(crate::audit_session::collector_identity(
                "linux",
                SourceRole::Startup,
            )),
            platform: "linux".to_owned(),
            scope: "curated startup paths".to_owned(),
            started_at_unix_ms: 1000,
            ended_at_unix_ms: 1001,
            status: SourceStatus::Complete,
            applied_limits: vec![],
            requested_settings: vec![],
            effective_settings: vec![],
            loss: None,
            diagnostic_codes: vec![],
            artifacts: vec![],
        };
        assert_eq!(
            CoverageManifest::from_sources(&[startup]).sources[0].status,
            super::CoverageStatus::Configured
        );
        let inaccessible = AuditSessionSource {
            role: SourceRole::Processes,
            collector: Some(crate::audit_session::collector_identity(
                "linux",
                SourceRole::Processes,
            )),
            platform: "linux".to_owned(),
            scope: "visible procfs".to_owned(),
            started_at_unix_ms: 1000,
            ended_at_unix_ms: 1001,
            status: SourceStatus::AccessDenied,
            applied_limits: vec![],
            requested_settings: vec![],
            effective_settings: vec![],
            loss: None,
            diagnostic_codes: vec![],
            artifacts: vec![],
        };
        assert_eq!(
            CoverageManifest::from_sources(&[inaccessible]).sources[0].status,
            super::CoverageStatus::Inaccessible
        );
    }

    #[test]
    fn incomplete_source_cannot_be_hidden_by_a_complete_session() {
        let mut manifest = valid_manifest();
        manifest.sources[0].status = SourceStatus::Partial;
        manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));
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
            collector: Some(crate::audit_session::collector_identity(
                "linux",
                SourceRole::Processes,
            )),
            platform: "linux".to_owned(),
            scope: "visible procfs entries".to_owned(),
            started_at_unix_ms: 1001,
            ended_at_unix_ms: 1002,
            status: SourceStatus::Unavailable,
            applied_limits: Vec::new(),
            requested_settings: Vec::new(),
            effective_settings: Vec::new(),
            loss: None,
            diagnostic_codes: vec!["procfs_unavailable".to_owned()],
            artifacts: Vec::new(),
        });
        manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));

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
        manifest.sources[0].collector =
            Some(super::collector_identity("windows", SourceRole::Packages));
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
            collector: Some(crate::audit_session::collector_identity(
                "windows",
                SourceRole::Runtime,
            )),
            platform: "windows".to_owned(),
            scope: "bounded system-wide ETW observations; completeness unknown".to_owned(),
            started_at_unix_ms: 1001,
            ended_at_unix_ms: 1002,
            status: SourceStatus::Partial,
            applied_limits: vec![AppliedLimit {
                code: "max_events".to_owned(),
                value: 50_000,
            }],
            requested_settings: vec![],
            effective_settings: vec![],
            loss: Some(super::LossMetadata::unknown()),
            diagnostic_codes: vec!["capture_completeness_unknown".to_owned()],
            artifacts: vec![SessionArtifactRef {
                kind: ArtifactKind::WindowsRuntimeCapture,
                path: "runtime.windows.json".to_owned(),
                schema: "sideeffect.windows_runtime_capture".to_owned(),
                schema_version: 3,
                byte_length: 1,
                sha256: "1".repeat(64),
            }],
        });
        manifest.status = SessionStatus::Partial;
        manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));
        assert!(manifest.validate().is_ok());

        manifest.sources[1].status = SourceStatus::Complete;
        manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));
        manifest.status = SessionStatus::Partial;
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::RuntimeCompletenessNotEstablished)
        );
        manifest.sources[1].status = SourceStatus::Partial;
        manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));

        manifest.sources[0].artifacts[0].schema_version = 99;
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::ArtifactContractMismatch)
        );
    }

    #[test]
    fn process_artifact_contracts_accept_legacy_v1_and_current_v2() {
        for kind in [ArtifactKind::Processes, ArtifactKind::WindowsProcesses] {
            assert!(super::artifact_version_supported(kind, 1, 2));
            assert!(super::artifact_version_supported(kind, 2, 2));
            assert!(!super::artifact_version_supported(kind, 3, 2));
        }
        assert!(!super::artifact_version_supported(
            ArtifactKind::Packages,
            1,
            2
        ));
    }

    #[test]
    fn one_session_preserves_complete_partial_and_unavailable_sources() {
        let mut manifest = valid_manifest();
        let processes = AuditSessionSource {
            role: SourceRole::Processes,
            collector: Some(crate::audit_session::collector_identity(
                "linux",
                SourceRole::Processes,
            )),
            platform: "linux".to_owned(),
            scope: "visible procfs entries".to_owned(),
            started_at_unix_ms: 1001,
            ended_at_unix_ms: 1002,
            status: SourceStatus::Partial,
            applied_limits: Vec::new(),
            requested_settings: Vec::new(),
            effective_settings: Vec::new(),
            loss: None,
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
            collector: Some(crate::audit_session::collector_identity(
                "linux",
                SourceRole::Startup,
            )),
            platform: "linux".to_owned(),
            scope: "selected startup locations".to_owned(),
            started_at_unix_ms: 1002,
            ended_at_unix_ms: 1002,
            status: SourceStatus::Unavailable,
            applied_limits: Vec::new(),
            requested_settings: Vec::new(),
            effective_settings: Vec::new(),
            loss: None,
            diagnostic_codes: vec!["startup_source_unavailable".to_owned()],
            artifacts: Vec::new(),
        };
        manifest.sources.push(processes);
        manifest.sources.push(unavailable);
        manifest.status = SessionStatus::Partial;
        manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));

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
        manifest.sources[0].requested_settings = vec![
            super::Setting {
                code: "test_setting".to_owned(),
                value: 1
            };
            super::MAX_SETTINGS_PER_SOURCE + 1
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
    fn runtime_loss_metadata_preserves_unknown_and_rejects_false_no_loss_claims() {
        let mut manifest = valid_manifest();
        let mut source = manifest.sources[0].clone();
        source.role = SourceRole::Runtime;
        source.collector = Some(super::collector_identity("linux", SourceRole::Runtime));
        source.status = SourceStatus::Partial;
        source.artifacts = vec![
            SessionArtifactRef {
                kind: ArtifactKind::RuntimeManifest,
                path: "run.json".to_owned(),
                schema: "sideeffect.run".to_owned(),
                schema_version: 2,
                byte_length: 1,
                sha256: "0".repeat(64),
            },
            SessionArtifactRef {
                kind: ArtifactKind::RuntimeTrace,
                path: "trace.strace".to_owned(),
                schema: "strace_text".to_owned(),
                schema_version: 1,
                byte_length: 1,
                sha256: "1".repeat(64),
            },
        ];
        source.loss = Some(super::LossMetadata::unknown());
        manifest.sources = vec![source];
        manifest.status = SessionStatus::Partial;
        manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));
        assert!(manifest.validate().is_ok());

        manifest.sources[0].loss = Some(super::LossMetadata {
            status: super::LossStatus::NoneReported,
            statistics_available: true,
            final_snapshot_available: true,
            events_lost: Some(0),
            log_buffers_lost: Some(0),
            real_time_buffers_lost: Some(0),
        });
        assert!(manifest.validate().is_ok());
        manifest.sources[0]
            .loss
            .as_mut()
            .unwrap()
            .final_snapshot_available = false;
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::InvalidLossMetadata)
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
            collector: Some(super::collector_identity("linux", role)),
            platform: "linux".to_owned(),
            scope: "bounded test source".to_owned(),
            started_at_unix_ms: 1000,
            ended_at_unix_ms: 1002,
            status: SourceStatus::Partial,
            applied_limits: Vec::new(),
            requested_settings: Vec::new(),
            effective_settings: Vec::new(),
            loss: None,
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
        manifest.coverage_manifest = Some(CoverageManifest::from_sources(&manifest.sources));
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::AggregateSizeOutOfBounds)
        );
    }
}
