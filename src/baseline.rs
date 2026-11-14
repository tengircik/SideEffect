//! Reviewed behavioral baselines over verified audit sessions.
//!
//! A baseline is a bounded, explicitly reviewed set of session manifests. It
//! records exact manifest digests so a later comparison can detect a missing or
//! replaced session. Creating a profile requires the digest printed by a preview,
//! and a profile is never treated as a trusted reference merely because it was
//! read from disk: it must validate against its own preview digest.

use crate::audit_session::{
    AuditSessionManifest, CoverageStatus, LossStatus, MAX_AUDIT_SESSION_MANIFEST_BYTES,
    SessionStatus, SourceRole, SourceStatus, compare_sessions, parse_manifest,
};
use crate::fingerprint::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

pub const BASELINE_PROFILE_SCHEMA: &str = "sideeffect.behavioral_baseline";
pub const BASELINE_PROFILE_SCHEMA_VERSION: u32 = 1;
pub const BASELINE_PREVIEW_SCHEMA: &str = "sideeffect.baseline_preview";
pub const BASELINE_PREVIEW_SCHEMA_VERSION: u32 = 1;
pub const MAX_BASELINE_SESSIONS: usize = 16;
pub const MAX_BASELINE_LABEL_BYTES: usize = 128;
pub const MAX_BASELINE_PROFILE_BYTES: usize = 1024 * 1024;
pub const MAX_BASELINE_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
/// Aggregate verified artifact bytes opened by one baseline operation.
pub const MAX_BASELINE_SESSION_READ_BYTES: u64 = 64 * 1024 * 1024;
const BASELINE_DIGEST_DOMAIN: &str = "sideeffect.behavioral_baseline.preview.v1\n";
const REVIEW_APPROVAL_MODE: &str = "explicit_digest_confirmation";
const NOT_RECORDED: &str = "not_recorded";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineSession {
    pub session_id: String,
    /// Lowercase SHA-256 of the exact manifest bytes accepted by the session reader.
    pub manifest_sha256: String,
    pub platform: String,
    pub architecture: String,
    pub started_at_unix_ms: u128,
    pub ended_at_unix_ms: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineCoverage {
    pub role: SourceRole,
    pub status: CoverageStatus,
    pub session_id: String,
}

/// Deterministic, digest-bound description of the sessions a user is asked to approve.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselinePreview {
    pub schema: String,
    pub schema_version: u32,
    pub label: String,
    pub sessions: Vec<BaselineSession>,
    pub coverage: Vec<BaselineCoverage>,
    /// `comparable` means the reviewed sessions declare matching metadata
    /// contexts. It does not establish complete coverage or equal observations.
    pub comparability: BaselineComparability,
    /// Promotion is blocked for partial, incomplete, or loss-affected inputs.
    pub promotion: BaselinePromotion,
    /// Digest over the label, exact session manifest digests, declared coverage,
    /// comparability, and promotion decision.
    pub sha256: String,
    pub approval_required: bool,
    pub automatic_absorption: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineComparability {
    pub status: BaselineComparabilityStatus,
    pub reason_codes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselinePromotion {
    pub allowed: bool,
    pub blocking_reason_codes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineComparabilityStatus {
    Comparable,
    Incomparable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineApproval {
    pub mode: String,
    pub preview_sha256: String,
}

/// A protected local profile. It records behavioral observations, not software
/// authorship or signer identity, and never absorbs a candidate automatically.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineProfile {
    pub schema: String,
    pub schema_version: u32,
    pub profile_id: String,
    pub label: String,
    pub reviewed_at_unix_ms: u128,
    pub approval: BaselineApproval,
    pub preview: BaselinePreview,
    pub software_identity: String,
    pub signer_identity: String,
    pub automatic_absorption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BaselineError {
    InvalidLabel,
    TooManySessions,
    NoSessions,
    InvalidManifestSha256,
    DuplicateSession(String),
    InvalidManifest(String),
    TooLarge,
    InvalidProfile,
    ApprovalDigestMismatch,
    PromotionBlocked(Vec<String>),
}

impl fmt::Display for BaselineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLabel => write!(
                f,
                "baseline label must be 1-{MAX_BASELINE_LABEL_BYTES} printable UTF-8 bytes"
            ),
            Self::TooManySessions => write!(
                f,
                "a baseline may contain at most {MAX_BASELINE_SESSIONS} sessions"
            ),
            Self::NoSessions => f.write_str("a baseline requires at least one verified session"),
            Self::InvalidManifestSha256 => f.write_str(
                "each baseline session requires a lowercase 64-character manifest SHA-256",
            ),
            Self::DuplicateSession(id) => {
                write!(f, "baseline contains session {id} more than once")
            }
            Self::InvalidManifest(reason) => write!(f, "invalid audit session: {reason}"),
            Self::TooLarge => f.write_str("baseline profile exceeds its bounded size"),
            Self::InvalidProfile => f.write_str(
                "baseline profile is invalid or its preview digest does not match its contents",
            ),
            Self::ApprovalDigestMismatch => f.write_str(
                "approval digest does not match the preview; review and pass the exact preview sha256",
            ),
            Self::PromotionBlocked(codes) => write!(
                f,
                "baseline inputs cannot be promoted because verified evidence is partial, incomplete, or loss-affected: {}",
                codes.join(", ")
            ),
        }
    }
}

impl std::error::Error for BaselineError {}

/// One session manifest whose exact bytes and digest were verified by a reader.
#[derive(Clone, Copy)]
pub struct BaselineManifestInput<'a> {
    pub manifest: &'a AuditSessionManifest,
    /// Lowercase SHA-256 of the exact manifest bytes that were read.
    pub manifest_sha256: &'a str,
}

/// Build a bounded preview. The digest is computed only from deterministic
/// fields, so previewing the same verified inputs yields the same approval value.
pub fn preview_baseline(
    label: &str,
    inputs: &[BaselineManifestInput<'_>],
) -> Result<BaselinePreview, BaselineError> {
    validate_label(label)?;
    if inputs.is_empty() {
        return Err(BaselineError::NoSessions);
    }
    if inputs.len() > MAX_BASELINE_SESSIONS {
        return Err(BaselineError::TooManySessions);
    }

    let mut sessions = Vec::with_capacity(inputs.len());
    let mut coverage = Vec::new();
    let mut promotion_codes = Vec::new();
    let mut ids = HashSet::new();
    for input in inputs {
        if !is_sha256(input.manifest_sha256) {
            return Err(BaselineError::InvalidManifestSha256);
        }
        input
            .manifest
            .validate()
            .map_err(|e| BaselineError::InvalidManifest(format!("{e:?}")))?;
        let manifest = input.manifest;
        if !ids.insert(manifest.session_id.clone()) {
            return Err(BaselineError::DuplicateSession(manifest.session_id.clone()));
        }
        sessions.push(BaselineSession {
            session_id: manifest.session_id.clone(),
            manifest_sha256: input.manifest_sha256.to_ascii_lowercase(),
            platform: manifest.platform.clone(),
            architecture: manifest.architecture.clone(),
            started_at_unix_ms: manifest.started_at_unix_ms,
            ended_at_unix_ms: manifest.ended_at_unix_ms,
        });
        if manifest.status == SessionStatus::Partial {
            promotion_codes.push("session_partial".to_string());
        }
        for source in &manifest.sources {
            if source.status != SourceStatus::Complete {
                promotion_codes.push("source_incomplete".to_string());
            }
            if source.role == SourceRole::Runtime {
                match source.loss.as_ref().map(|loss| loss.status) {
                    Some(LossStatus::NoneReported) => {}
                    Some(LossStatus::Reported) => {
                        promotion_codes.push("runtime_loss_reported".to_string());
                    }
                    Some(LossStatus::Unknown) | None => {
                        promotion_codes.push("runtime_loss_unknown".to_string());
                    }
                }
            }
        }
        match &manifest.coverage_manifest {
            Some(manifest_coverage) => {
                for source in &manifest_coverage.sources {
                    coverage.push(BaselineCoverage {
                        role: source.role,
                        status: source.status,
                        session_id: manifest.session_id.clone(),
                    });
                }
            }
            None => {
                // A missing coverage declaration is unknown, never complete.
                for source in &manifest.sources {
                    coverage.push(BaselineCoverage {
                        role: source.role,
                        status: CoverageStatus::Unknown,
                        session_id: manifest.session_id.clone(),
                    });
                }
            }
        }
    }
    sessions.sort_by(|a, b| a.session_id.cmp(&b.session_id));
    coverage.sort_by(|a, b| {
        (&a.session_id, a.role as u8, coverage_status_order(a.status)).cmp(&(
            &b.session_id,
            b.role as u8,
            coverage_status_order(b.status),
        ))
    });

    let mut reason_codes = Vec::new();
    for left in 0..inputs.len() {
        for right in left + 1..inputs.len() {
            let result = compare_sessions(inputs[left].manifest, inputs[right].manifest);
            for reason in result.reasons {
                if !reason_codes.iter().any(|code| code == reason.code()) {
                    reason_codes.push(reason.code().to_string());
                }
            }
        }
    }
    reason_codes.sort();
    let comparability = BaselineComparability {
        status: if reason_codes.is_empty() {
            BaselineComparabilityStatus::Comparable
        } else {
            BaselineComparabilityStatus::Incomparable
        },
        reason_codes,
    };
    promotion_codes.sort();
    promotion_codes.dedup();
    let promotion = BaselinePromotion {
        allowed: promotion_codes.is_empty(),
        blocking_reason_codes: promotion_codes,
    };

    let mut preview = BaselinePreview {
        schema: BASELINE_PREVIEW_SCHEMA.to_string(),
        schema_version: BASELINE_PREVIEW_SCHEMA_VERSION,
        label: label.to_string(),
        sessions,
        coverage,
        comparability,
        promotion,
        sha256: String::new(),
        approval_required: true,
        automatic_absorption: false,
    };
    preview.sha256 = preview_digest(&preview)?;
    Ok(preview)
}

/// Recompute the digest from a preview's deterministic fields.
pub fn preview_digest(preview: &BaselinePreview) -> Result<String, BaselineError> {
    let document = PreviewDigestDocument {
        domain: BASELINE_DIGEST_DOMAIN,
        schema: BASELINE_PREVIEW_SCHEMA,
        schema_version: BASELINE_PREVIEW_SCHEMA_VERSION,
        label: &preview.label,
        sessions: &preview.sessions,
        coverage: &preview.coverage,
        comparability: &preview.comparability,
        promotion: &preview.promotion,
    };
    let bytes = serde_json::to_vec(&document).map_err(|_| BaselineError::InvalidProfile)?;
    Ok(sha256_hex(&bytes))
}

#[derive(Serialize)]
struct PreviewDigestDocument<'a> {
    domain: &'static str,
    schema: &'static str,
    schema_version: u32,
    label: &'a str,
    sessions: &'a [BaselineSession],
    coverage: &'a [BaselineCoverage],
    comparability: &'a BaselineComparability,
    promotion: &'a BaselinePromotion,
}

/// Create a profile only when the caller supplies the exact preview digest.
pub fn create_profile(
    preview: &BaselinePreview,
    confirm_sha256: &str,
    reviewed_at_unix_ms: u128,
) -> Result<BaselineProfile, BaselineError> {
    validate_preview(preview)?;
    if confirm_sha256 != preview.sha256 {
        return Err(BaselineError::ApprovalDigestMismatch);
    }
    if !preview.promotion.allowed {
        return Err(BaselineError::PromotionBlocked(
            preview.promotion.blocking_reason_codes.clone(),
        ));
    }
    if reviewed_at_unix_ms > crate::audit_session::MAX_SESSION_TIMESTAMP_UNIX_MS {
        return Err(BaselineError::InvalidProfile);
    }
    Ok(BaselineProfile {
        schema: BASELINE_PROFILE_SCHEMA.to_string(),
        schema_version: BASELINE_PROFILE_SCHEMA_VERSION,
        profile_id: sha256_hex(preview.sha256.as_bytes()),
        label: preview.label.clone(),
        reviewed_at_unix_ms,
        approval: BaselineApproval {
            mode: REVIEW_APPROVAL_MODE.to_string(),
            preview_sha256: preview.sha256.clone(),
        },
        preview: preview.clone(),
        software_identity: NOT_RECORDED.to_string(),
        signer_identity: NOT_RECORDED.to_string(),
        automatic_absorption: false,
    })
}

/// Parse a bounded profile and verify that it is internally consistent.
pub fn parse_profile(bytes: &[u8]) -> Result<BaselineProfile, BaselineError> {
    if bytes.len() > MAX_BASELINE_PROFILE_BYTES {
        return Err(BaselineError::TooLarge);
    }
    let profile: BaselineProfile =
        serde_json::from_slice(bytes).map_err(|_| BaselineError::InvalidProfile)?;
    validate_profile(&profile)?;
    Ok(profile)
}

pub fn validate_profile(profile: &BaselineProfile) -> Result<(), BaselineError> {
    if profile.schema != BASELINE_PROFILE_SCHEMA
        || profile.schema_version != BASELINE_PROFILE_SCHEMA_VERSION
        || profile.software_identity != NOT_RECORDED
        || profile.signer_identity != NOT_RECORDED
        || profile.automatic_absorption
        || profile.approval.mode != REVIEW_APPROVAL_MODE
        || profile.profile_id != sha256_hex(profile.preview.sha256.as_bytes())
    {
        return Err(BaselineError::InvalidProfile);
    }
    validate_label(&profile.label)?;
    if profile.label != profile.preview.label {
        return Err(BaselineError::InvalidProfile);
    }
    validate_preview(&profile.preview)?;
    if profile.approval.preview_sha256 != profile.preview.sha256
        || profile.reviewed_at_unix_ms > crate::audit_session::MAX_SESSION_TIMESTAMP_UNIX_MS
    {
        return Err(BaselineError::InvalidProfile);
    }
    Ok(())
}

fn validate_preview(preview: &BaselinePreview) -> Result<(), BaselineError> {
    if preview.schema != BASELINE_PREVIEW_SCHEMA
        || preview.schema_version != BASELINE_PREVIEW_SCHEMA_VERSION
        || !preview.approval_required
        || preview.automatic_absorption
    {
        return Err(BaselineError::InvalidProfile);
    }
    validate_label(&preview.label)?;
    if preview.sessions.is_empty() {
        return Err(BaselineError::NoSessions);
    }
    if preview.sessions.len() > MAX_BASELINE_SESSIONS {
        return Err(BaselineError::TooManySessions);
    }
    let mut ids = HashSet::new();
    for session in &preview.sessions {
        if !ids.insert(&session.session_id)
            || session.session_id.len() != 32
            || !session
                .session_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !is_sha256(&session.manifest_sha256)
        {
            return Err(BaselineError::InvalidProfile);
        }
    }
    if preview.promotion.allowed != preview.promotion.blocking_reason_codes.is_empty()
        || preview.promotion.blocking_reason_codes.len() > 8
    {
        return Err(BaselineError::InvalidProfile);
    }
    if !is_sha256(&preview.sha256) || preview.sha256 != preview_digest(preview)? {
        return Err(BaselineError::InvalidProfile);
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), BaselineError> {
    let bytes = label.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_BASELINE_LABEL_BYTES
        || label.chars().any(|c| c.is_control())
    {
        return Err(BaselineError::InvalidLabel);
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn coverage_status_order(status: CoverageStatus) -> u8 {
    match status {
        CoverageStatus::Observed => 0,
        CoverageStatus::Configured => 1,
        CoverageStatus::NotObserved => 2,
        CoverageStatus::NotChecked => 3,
        CoverageStatus::Unsupported => 4,
        CoverageStatus::Inaccessible => 5,
        CoverageStatus::Partial => 6,
        CoverageStatus::Unknown => 7,
    }
}

#[derive(Clone, Copy)]
pub struct BaselineComparisonSession<'a> {
    pub manifest: &'a AuditSessionManifest,
    pub manifest_sha256: &'a str,
    pub artifacts: &'a [crate::audit_session_diff::VerifiedArtifactBytes<'a>],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineDiagnostic {
    pub code: String,
    pub severity: BaselineSeverity,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Serialize)]
pub struct BaselineComparison {
    pub schema: String,
    pub schema_version: u32,
    /// `compared`, `partial`, `incomparable`, or `refused_contaminated_baseline`.
    pub status: BaselineComparisonStatus,
    pub profile_id: String,
    pub label: String,
    pub preview_sha256: String,
    pub reviewed_at_unix_ms: u128,
    pub baseline_verification: BaselineVerificationStatus,
    pub candidate_session_ids: Vec<String>,
    pub diagnostics: Vec<BaselineDiagnostic>,
    pub coverage_gaps: Vec<BaselineCoverageGap>,
    /// Removal claims are withheld whenever either side has incomplete or
    /// unknown declared coverage.
    pub removal_claims_withheld: bool,
    pub deviation: BaselineDeviationStatus,
    pub comparisons: Vec<BaselinePairComparison>,
    pub automatic_absorption: bool,
    pub limitations: [&'static str; 5],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineComparisonStatus {
    Compared,
    Partial,
    Incomparable,
    RefusedContaminatedBaseline,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineVerificationStatus {
    Verified,
    Contaminated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineDeviationStatus {
    NoItemDifferencesReported,
    DifferentFromReviewedObservations,
    NotAssessed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineCoverageGap {
    pub session_id: String,
    pub role: SourceRole,
    pub status: CoverageStatus,
}

#[derive(Clone, Debug, Serialize)]
pub struct BaselinePairComparison {
    pub baseline_session_id: String,
    pub candidate_session_id: String,
    pub diff: crate::audit_session_diff::AuditSessionDiff,
}

/// Compare candidates against a reviewed profile without absorbing them.
/// The exact baseline sessions must be supplied and must match the approved
/// manifest digests; otherwise the comparison refuses to produce item deltas.
pub fn compare_against_baseline(
    profile: &BaselineProfile,
    baselines: &[BaselineComparisonSession<'_>],
    candidates: &[BaselineComparisonSession<'_>],
) -> Result<BaselineComparison, BaselineError> {
    validate_profile(profile)?;
    if candidates.is_empty() {
        return Err(BaselineError::NoSessions);
    }
    if candidates.len() > MAX_BASELINE_SESSIONS || baselines.len() > MAX_BASELINE_SESSIONS {
        return Err(BaselineError::TooManySessions);
    }
    for input in baselines.iter().chain(candidates) {
        if !is_sha256(input.manifest_sha256) {
            return Err(BaselineError::InvalidManifestSha256);
        }
        input
            .manifest
            .validate()
            .map_err(|e| BaselineError::InvalidManifest(format!("{e:?}")))?;
    }

    let mut candidate_ids = HashSet::new();
    for candidate in candidates {
        if !candidate_ids.insert(candidate.manifest.session_id.as_str()) {
            return Err(BaselineError::DuplicateSession(
                candidate.manifest.session_id.clone(),
            ));
        }
    }
    let total_artifact_bytes = baselines
        .iter()
        .chain(candidates)
        .try_fold(0_u64, |total, input| {
            input.artifacts.iter().try_fold(total, |total, artifact| {
                total.checked_add(artifact.bytes.len() as u64)
            })
        })
        .ok_or(BaselineError::TooLarge)?;
    if total_artifact_bytes > crate::audit_session_diff::MAX_SESSION_DIFF_PAIR_BYTES as u64 {
        return Err(BaselineError::TooLarge);
    }

    let mut diagnostics = Vec::new();
    let mut contaminated = baselines.len() != profile.preview.sessions.len();
    let mut seen_baselines = HashSet::new();
    for approved in &profile.preview.sessions {
        let Some(provided) = baselines
            .iter()
            .find(|input| input.manifest.session_id == approved.session_id)
        else {
            contaminated = true;
            continue;
        };
        if !seen_baselines.insert(provided.manifest.session_id.as_str())
            || provided.manifest_sha256 != approved.manifest_sha256
        {
            contaminated = true;
        }
    }
    for provided in baselines {
        if !profile
            .preview
            .sessions
            .iter()
            .any(|approved| approved.session_id == provided.manifest.session_id)
        {
            contaminated = true;
        }
    }
    if contaminated {
        diagnostics.push(BaselineDiagnostic {
            code: "baseline_manifest_changed".to_string(),
            severity: BaselineSeverity::Error,
            message: "provided baseline sessions do not match the approved session set and manifest digests; no candidate comparison was performed".to_string(),
        });
        return Ok(BaselineComparison {
            schema: BASELINE_COMPARISON_SCHEMA.to_string(),
            schema_version: BASELINE_COMPARISON_SCHEMA_VERSION,
            status: BaselineComparisonStatus::RefusedContaminatedBaseline,
            profile_id: profile.profile_id.clone(),
            label: profile.label.clone(),
            preview_sha256: profile.preview.sha256.clone(),
            reviewed_at_unix_ms: profile.reviewed_at_unix_ms,
            baseline_verification: BaselineVerificationStatus::Contaminated,
            candidate_session_ids: candidates
                .iter()
                .map(|input| input.manifest.session_id.clone())
                .collect(),
            diagnostics,
            coverage_gaps: Vec::new(),
            removal_claims_withheld: true,
            deviation: BaselineDeviationStatus::NotAssessed,
            comparisons: Vec::new(),
            automatic_absorption: false,
            limitations: BASELINE_COMPARISON_LIMITATIONS,
        });
    }

    let mut coverage_gaps = Vec::new();
    for coverage in &profile.preview.coverage {
        if coverage_withholds_removal(coverage.status) {
            coverage_gaps.push(BaselineCoverageGap {
                session_id: coverage.session_id.clone(),
                role: coverage.role,
                status: coverage.status,
            });
        }
    }
    for candidate in candidates {
        match &candidate.manifest.coverage_manifest {
            Some(coverage) => {
                for source in &coverage.sources {
                    if coverage_withholds_removal(source.status) {
                        coverage_gaps.push(BaselineCoverageGap {
                            session_id: candidate.manifest.session_id.clone(),
                            role: source.role,
                            status: source.status,
                        });
                    }
                }
            }
            None => {
                for source in &candidate.manifest.sources {
                    coverage_gaps.push(BaselineCoverageGap {
                        session_id: candidate.manifest.session_id.clone(),
                        role: source.role,
                        status: CoverageStatus::Unknown,
                    });
                }
            }
        }
    }
    coverage_gaps.sort_by(|a, b| (&a.session_id, a.role as u8).cmp(&(&b.session_id, b.role as u8)));
    coverage_gaps.dedup();

    let mut comparable = true;
    for candidate in candidates {
        for baseline in baselines {
            let result = compare_sessions(baseline.manifest, candidate.manifest);
            for reason in result.reasons {
                let code = reason.code();
                if !diagnostics.iter().any(|item| item.code == code) {
                    diagnostics.push(BaselineDiagnostic {
                        code: code.to_string(),
                        severity: if result.comparable {
                            BaselineSeverity::Info
                        } else {
                            BaselineSeverity::Warning
                        },
                        message:
                            "candidate and reviewed session declare different comparison contexts"
                                .to_string(),
                    });
                }
            }
            comparable &= result.comparable;
        }
    }
    if !coverage_gaps.is_empty() {
        diagnostics.push(BaselineDiagnostic {
            code: "incomplete_coverage_removal_withheld".to_string(),
            severity: BaselineSeverity::Warning,
            message: "one or more reviewed or candidate sources are incomplete or unknown; removal and absence claims are withheld".to_string(),
        });
    }

    let mut comparisons = Vec::with_capacity(baselines.len() * candidates.len());
    let mut differences_reported = false;
    let mut assessment_performed = false;
    for baseline in baselines {
        for candidate in candidates {
            let pair_comparable =
                compare_sessions(baseline.manifest, candidate.manifest).comparable;
            let mut diff = crate::audit_session_diff::compare_audit_sessions(
                baseline.manifest,
                candidate.manifest,
                baseline.artifacts,
                candidate.artifacts,
            );
            for source in &mut diff.source_diffs {
                if role_has_coverage_gap(baseline.manifest, source.role)
                    || role_has_coverage_gap(candidate.manifest, source.role)
                {
                    if let Some(comparison) = &mut source.comparison {
                        suppress_nested_removals(source.role, comparison);
                    }
                }
            }
            if pair_comparable {
                for source in &diff.source_diffs {
                    let Some(comparison) = source.comparison.as_ref() else {
                        continue;
                    };
                    if source.status == "compared" && comparison_schema_is_supported(comparison) {
                        assessment_performed = true;
                        differences_reported |= comparison_reports_changes(comparison);
                    }
                }
            }
            comparisons.push(BaselinePairComparison {
                baseline_session_id: baseline.manifest.session_id.clone(),
                candidate_session_id: candidate.manifest.session_id.clone(),
                diff,
            });
        }
    }
    if differences_reported {
        diagnostics.push(BaselineDiagnostic {
            code: "candidate_drift_observed".to_string(),
            severity: BaselineSeverity::Info,
            message: "candidate evidence differs from at least one reviewed baseline; a difference is not evidence of unsafe behavior".to_string(),
        });
    }
    diagnostics.push(BaselineDiagnostic {
        code: "automatic_absorption_refused".to_string(),
        severity: BaselineSeverity::Info,
        message: "the candidate was compared only; it was not added to the reviewed baseline"
            .to_string(),
    });

    let status = if !comparable {
        BaselineComparisonStatus::Incomparable
    } else if coverage_gaps.is_empty()
        && comparisons
            .iter()
            .all(|pair| pair.diff.item_comparison_status == "complete")
    {
        BaselineComparisonStatus::Compared
    } else {
        BaselineComparisonStatus::Partial
    };
    Ok(BaselineComparison {
        schema: BASELINE_COMPARISON_SCHEMA.to_string(),
        schema_version: BASELINE_COMPARISON_SCHEMA_VERSION,
        status,
        profile_id: profile.profile_id.clone(),
        label: profile.label.clone(),
        preview_sha256: profile.preview.sha256.clone(),
        reviewed_at_unix_ms: profile.reviewed_at_unix_ms,
        baseline_verification: BaselineVerificationStatus::Verified,
        candidate_session_ids: candidates
            .iter()
            .map(|input| input.manifest.session_id.clone())
            .collect(),
        diagnostics,
        removal_claims_withheld: !coverage_gaps.is_empty(),
        coverage_gaps,
        deviation: if !assessment_performed {
            BaselineDeviationStatus::NotAssessed
        } else if differences_reported {
            BaselineDeviationStatus::DifferentFromReviewedObservations
        } else {
            BaselineDeviationStatus::NoItemDifferencesReported
        },
        comparisons,
        automatic_absorption: false,
        limitations: BASELINE_COMPARISON_LIMITATIONS,
    })
}

fn role_has_coverage_gap(manifest: &AuditSessionManifest, role: SourceRole) -> bool {
    match &manifest.coverage_manifest {
        Some(coverage) => coverage
            .sources
            .iter()
            .find(|source| source.role == role)
            .is_none_or(|source| coverage_withholds_removal(source.status)),
        None => manifest.sources.iter().any(|source| source.role == role),
    }
}

/// The native diff can contain one-sided rows even when the session-level
/// coverage manifest is weaker than the source artifact. Remove those nested
/// removal claims as well as their counters while retaining other changes.
fn suppress_nested_removals(role: SourceRole, comparison: &mut serde_json::Value) {
    let (kind, count) = match role {
        SourceRole::Packages
        | SourceRole::Msix
        | SourceRole::AppPaths
        | SourceRole::Permissions
        | SourceRole::SelectedRoot => ("removed", "removals"),
        SourceRole::Processes => ("removed", "removals"),
        SourceRole::Startup => ("observed_before_only", "observed_before_only"),
        SourceRole::PathExecutables => ("candidate_removed", "candidates_removed"),
        SourceRole::Runtime => return,
    };
    if let Some(deltas) = comparison
        .get_mut("deltas")
        .and_then(serde_json::Value::as_array_mut)
    {
        deltas.retain(|delta| delta.get("kind").and_then(serde_json::Value::as_str) != Some(kind));
    }
    if let Some(counts) = comparison
        .get_mut("counts")
        .and_then(serde_json::Value::as_object_mut)
    {
        if let Some(value) = counts.get_mut(count) {
            *value = serde_json::Value::from(0);
        }
    }
}

fn coverage_withholds_removal(status: CoverageStatus) -> bool {
    !matches!(
        status,
        CoverageStatus::Observed | CoverageStatus::Configured | CoverageStatus::NotObserved
    )
}

/// Report drift only for native comparison contracts this baseline layer knows.
/// Suppression, ambiguity, and unknown-row counters are diagnostics; they are
/// not evidence that a reviewed observation changed. Actual drift comes from
/// the documented delta count fields or a nonempty `deltas` collection.
fn comparison_reports_changes(value: &serde_json::Value) -> bool {
    let Some(schema) = value.get("schema").and_then(|schema| schema.as_str()) else {
        return false;
    };
    let Some(version) = value
        .get("schema_version")
        .and_then(|version| version.as_u64())
    else {
        return false;
    };
    let count_fields: &[&str] = match (schema, version) {
        ("sideeffect.package_inventory_diff", 1)
        | ("sideeffect.windows_software_inventory_diff", 1)
        | ("sideeffect.windows_msix_inventory_diff", 1)
        | ("sideeffect.windows_app_path_inventory_diff", 1)
        | ("sideeffect.permission_inventory_diff", 1) => &["additions", "removals", "changes"],
        ("sideeffect.process_inventory_diff", 3) => {
            &["additions", "removals", "changes", "candidate_changes"]
        }
        ("sideeffect.path_executable_inventory_diff", 1) => &[
            "candidates_added",
            "candidates_removed",
            "candidate_status_changes",
            "path_component_position_changes",
        ],
        ("sideeffect.selected_root_inventory_diff", 1) => &["additions", "removals", "changes"],
        ("sideeffect.startup_inventory_diff", 1) => {
            &["observed_before_only", "observed_after_only", "changed"]
        }
        _ => return false,
    };
    value
        .get("deltas")
        .and_then(|deltas| deltas.as_array())
        .is_some_and(|deltas| !deltas.is_empty())
        || value
            .get("counts")
            .and_then(|counts| counts.as_object())
            .is_some_and(|counts| {
                count_fields.iter().any(|field| {
                    counts
                        .get(*field)
                        .and_then(|count| count.as_u64())
                        .is_some_and(|count| count > 0)
                })
            })
}

fn comparison_schema_is_supported(value: &serde_json::Value) -> bool {
    let Some(schema) = value.get("schema").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let Some(version) = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
    else {
        return false;
    };
    matches!(
        (schema, version),
        ("sideeffect.package_inventory_diff", 1)
            | ("sideeffect.windows_software_inventory_diff", 1)
            | ("sideeffect.windows_msix_inventory_diff", 1)
            | ("sideeffect.windows_app_path_inventory_diff", 1)
            | ("sideeffect.permission_inventory_diff", 1)
            | ("sideeffect.process_inventory_diff", 3)
            | ("sideeffect.path_executable_inventory_diff", 1)
            | ("sideeffect.selected_root_inventory_diff", 1)
            | ("sideeffect.startup_inventory_diff", 1)
    )
}

pub const BASELINE_COMPARISON_SCHEMA: &str = "sideeffect.baseline_comparison";
pub const BASELINE_COMPARISON_SCHEMA_VERSION: u32 = 1;
const BASELINE_COMPARISON_LIMITATIONS: [&str; 5] = [
    "This comparison covers only explicitly selected verified audit sessions and their declared sources.",
    "A difference is not proof of unsafe behavior, causation, or a complete system change.",
    "Removal and absence claims are withheld when coverage is incomplete or unknown.",
    "The candidate is never absorbed into the reviewed baseline automatically.",
    "Baseline manifests preserve observations; they do not establish software or signer identity.",
];

/// Parse exactly one bounded manifest while preserving its exact bytes.
pub fn parse_verified_manifest(bytes: &[u8]) -> Result<AuditSessionManifest, BaselineError> {
    if bytes.len() > MAX_AUDIT_SESSION_MANIFEST_BYTES {
        return Err(BaselineError::TooLarge);
    }
    parse_manifest(bytes).map_err(|e| BaselineError::InvalidManifest(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(
        session_id: &str,
        version: &str,
        coverage: Option<&str>,
    ) -> (Vec<u8>, AuditSessionManifest) {
        manifest_with_host(session_id, Some(version), coverage)
    }

    fn manifest_with_host(
        session_id: &str,
        host_version: Option<&str>,
        coverage: Option<&str>,
    ) -> (Vec<u8>, AuditSessionManifest) {
        let host_version = match host_version {
            Some(version) => serde_json::json!({"status": "observed", "value": version}),
            None => serde_json::json!({"status": "unknown"}),
        };
        let mut value = serde_json::json!({
            "schema": "sideeffect.audit_session",
            "schema_version": 5,
            "session_id": session_id,
            "platform": "linux",
            "architecture": "x86_64",
            "started_at_unix_ms": 1000,
            "ended_at_unix_ms": 2000,
            "interval_semantics": "best_effort_non_atomic",
            "status": "complete",
            "sources": [{
                "role": "packages",
                "platform": "linux",
                "scope": "synthetic baseline test fixture",
                "started_at_unix_ms": 1000,
                "ended_at_unix_ms": 2000,
                "status": "complete",
                "applied_limits": [],
                "diagnostic_codes": [],
                "artifacts": [{
                    "kind": "packages",
                    "path": "packages.json",
                    "schema": "sideeffect.inventory",
                    "schema_version": 2,
                    "byte_length": 2,
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }]
            }],
            "host_context": {
                "os_name": {"status": "observed", "value": "synthetic-linux"},
                "os_version": host_version,
                "privilege": "not_elevated"
            }
        });
        if coverage.is_some() {
            value["coverage_manifest"] = serde_json::json!({
                "version": 1,
                "sources": [{"role": "packages", "status": "observed"}]
            });
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        let parsed = parse_manifest(&bytes).unwrap();
        (bytes, parsed)
    }

    fn preview_two() -> BaselinePreview {
        let (a_bytes, a) = manifest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1", Some("observed"));
        let (b_bytes, b) = manifest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "2", Some("observed"));
        preview_baseline(
            "synthetic reviewed baseline",
            &[
                BaselineManifestInput {
                    manifest: &a,
                    manifest_sha256: &sha256_hex(&a_bytes),
                },
                BaselineManifestInput {
                    manifest: &b,
                    manifest_sha256: &sha256_hex(&b_bytes),
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn preview_digest_is_deterministic_and_order_independent() {
        let (a_bytes, a) = manifest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1", Some("observed"));
        let (b_bytes, b) = manifest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "2", Some("observed"));
        let first = preview_baseline(
            "synthetic reviewed baseline",
            &[
                BaselineManifestInput {
                    manifest: &b,
                    manifest_sha256: &sha256_hex(&b_bytes),
                },
                BaselineManifestInput {
                    manifest: &a,
                    manifest_sha256: &sha256_hex(&a_bytes),
                },
            ],
        )
        .unwrap();
        let second = preview_two();
        assert_eq!(first, second);
        assert_eq!(first.coverage.len(), 2);
        assert!(!first.automatic_absorption);
        assert!(first.approval_required);
        assert_eq!(
            first.comparability.status,
            BaselineComparabilityStatus::Incomparable
        );
        assert_eq!(
            first.comparability.reason_codes,
            vec!["collector_identity_unknown", "host_os_mismatch"]
        );
    }

    #[test]
    fn comparability_reasons_do_not_depend_on_reviewed_input_order() {
        let (a_bytes, a) = manifest_with_host(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some("1"),
            Some("observed"),
        );
        let (b_bytes, b) =
            manifest_with_host("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", None, Some("observed"));
        let (c_bytes, c) = manifest_with_host(
            "cccccccccccccccccccccccccccccccc",
            Some("2"),
            Some("observed"),
        );
        let a_digest = sha256_hex(&a_bytes);
        let b_digest = sha256_hex(&b_bytes);
        let c_digest = sha256_hex(&c_bytes);
        let manifests = [&a, &b, &c];
        let digests = [&a_digest, &b_digest, &c_digest];
        let permutations = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        let previews: Vec<_> = permutations
            .into_iter()
            .map(|order| {
                let inputs: Vec<_> = order
                    .into_iter()
                    .map(|index| BaselineManifestInput {
                        manifest: manifests[index],
                        manifest_sha256: digests[index],
                    })
                    .collect();
                preview_baseline("synthetic comparability order", &inputs).unwrap()
            })
            .collect();
        for preview in &previews {
            assert_eq!(preview, &previews[0]);
        }
        assert_eq!(
            previews[0].comparability.reason_codes,
            vec![
                "collector_identity_unknown",
                "host_os_mismatch",
                "host_os_unknown"
            ]
        );
    }

    #[test]
    fn profile_creation_requires_the_exact_preview_digest() {
        let preview = preview_two();
        assert_eq!(
            create_profile(&preview, "0".repeat(64).as_str(), 10),
            Err(BaselineError::ApprovalDigestMismatch)
        );
        let profile = create_profile(&preview, &preview.sha256, 10).unwrap();
        assert_eq!(profile.approval.preview_sha256, preview.sha256);
        assert_eq!(profile.software_identity, "not_recorded");
        assert_eq!(profile.signer_identity, "not_recorded");
        assert!(!profile.automatic_absorption);
        assert_eq!(validate_profile(&profile), Ok(()));
    }

    #[test]
    fn profile_rejects_modified_preview_or_approval() {
        let preview = preview_two();
        let profile = create_profile(&preview, &preview.sha256, 10).unwrap();

        let mut modified = profile.clone();
        modified.preview.label = "different label".to_string();
        assert_eq!(
            validate_profile(&modified),
            Err(BaselineError::InvalidProfile)
        );

        let mut modified = profile.clone();
        modified.preview.sessions[0].manifest_sha256 = "c".repeat(64);
        assert_eq!(
            validate_profile(&modified),
            Err(BaselineError::InvalidProfile)
        );

        let mut modified = profile;
        modified.approval.mode = "implicit".to_string();
        assert_eq!(
            validate_profile(&modified),
            Err(BaselineError::InvalidProfile)
        );
    }

    #[test]
    fn missing_coverage_is_preserved_as_unknown() {
        let value = serde_json::json!({
            "schema": "sideeffect.audit_session",
            "schema_version": 1,
            "session_id": "cccccccccccccccccccccccccccccccc",
            "platform": "linux",
            "architecture": "x86_64",
            "started_at_unix_ms": 1000,
            "ended_at_unix_ms": 2000,
            "interval_semantics": "best_effort_non_atomic",
            "status": "complete",
            "sources": [{
                "role": "packages",
                "platform": "linux",
                "scope": "synthetic baseline test fixture",
                "started_at_unix_ms": 1000,
                "ended_at_unix_ms": 2000,
                "status": "complete",
                "applied_limits": [],
                "diagnostic_codes": [],
                "artifacts": [{
                    "kind": "packages",
                    "path": "packages.json",
                    "schema": "sideeffect.inventory",
                    "schema_version": 2,
                    "byte_length": 2,
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }]
            }]
        });
        let bytes = serde_json::to_vec(&value).unwrap();
        let manifest = parse_manifest(&bytes).unwrap();
        let preview = preview_baseline(
            "synthetic baseline without coverage",
            &[BaselineManifestInput {
                manifest: &manifest,
                manifest_sha256: &sha256_hex(&bytes),
            }],
        )
        .unwrap();
        assert_eq!(preview.coverage[0].status, CoverageStatus::Unknown);
    }

    #[test]
    fn partial_or_incomplete_inputs_cannot_become_a_profile() {
        let (bytes, _) = manifest("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "1", Some("observed"));
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["status"] = serde_json::json!("partial");
        value["sources"][0]["status"] = serde_json::json!("unknown");
        value["sources"][0]["artifacts"] = serde_json::json!([]);
        value["coverage_manifest"]["sources"][0]["status"] = serde_json::json!("unknown");
        let bytes = serde_json::to_vec(&value).unwrap();
        let manifest = parse_manifest(&bytes).unwrap();
        let digest = sha256_hex(&bytes);
        let preview = preview_baseline(
            "synthetic partial baseline",
            &[BaselineManifestInput {
                manifest: &manifest,
                manifest_sha256: &digest,
            }],
        )
        .unwrap();
        assert!(!preview.promotion.allowed);
        assert_eq!(
            preview.promotion.blocking_reason_codes,
            vec!["session_partial", "source_incomplete"]
        );
        assert_eq!(preview.coverage[0].status, CoverageStatus::Unknown);
        assert_eq!(
            create_profile(&preview, &preview.sha256, 10),
            Err(BaselineError::PromotionBlocked(vec![
                "session_partial".to_string(),
                "source_incomplete".to_string()
            ]))
        );
    }

    #[test]
    fn suppression_only_comparison_counts_are_not_drift() {
        let suppression_only = serde_json::json!({
            "schema": "sideeffect.package_inventory_diff",
            "schema_version": 1,
            "counts": {
                "additions": 0,
                "removals": 0,
                "changes": 0,
                "unmatched_rows_with_incomplete_source": 3,
                "invalid_identity_rows": 2,
                "ambiguous_identity_groups": 1
            },
            "deltas": []
        });
        assert!(!comparison_reports_changes(&suppression_only));

        let changed = serde_json::json!({
            "schema": "sideeffect.package_inventory_diff",
            "schema_version": 1,
            "counts": {"additions": 1, "removals": 0, "changes": 0},
            "deltas": [{"kind": "addition"}]
        });
        assert!(comparison_reports_changes(&changed));

        let unsupported_version = serde_json::json!({
            "schema": "sideeffect.package_inventory_diff",
            "schema_version": 2,
            "counts": {"additions": 1},
            "deltas": [{"kind": "addition"}]
        });
        assert!(!comparison_reports_changes(&unsupported_version));
        let unknown_schema = serde_json::json!({
            "schema": "sideeffect.synthetic_diff",
            "schema_version": 1,
            "counts": {"additions": 1},
            "deltas": [{"kind": "addition"}]
        });
        assert!(!comparison_reports_changes(&unknown_schema));
    }

    #[test]
    fn incomplete_coverage_removes_nested_removal_claims() {
        let mut nested = serde_json::json!({
            "counts": {"additions": 1, "removals": 2, "changes": 0},
            "deltas": [
                {"kind": "removed", "name": "synthetic-old-entry"},
                {"kind": "added", "name": "synthetic-new-entry"}
            ]
        });
        suppress_nested_removals(SourceRole::Packages, &mut nested);
        assert_eq!(nested["counts"]["removals"], 0);
        assert_eq!(nested["deltas"].as_array().unwrap().len(), 1);
        assert_eq!(nested["deltas"][0]["kind"], "added");
    }

    #[test]
    fn reported_runtime_loss_blocks_promotion() {
        let value = serde_json::json!({
            "schema": "sideeffect.audit_session",
            "schema_version": 5,
            "session_id": "ffffffffffffffffffffffffffffffff",
            "platform": "linux",
            "architecture": "x86_64",
            "started_at_unix_ms": 1000,
            "ended_at_unix_ms": 2000,
            "interval_semantics": "best_effort_non_atomic",
            "status": "partial",
            "sources": [{
                "role": "runtime",
                "platform": "linux",
                "scope": "synthetic bounded runtime fixture",
                "started_at_unix_ms": 1000,
                "ended_at_unix_ms": 2000,
                "status": "partial",
                "applied_limits": [],
                "diagnostic_codes": [],
                "loss": {
                    "status": "reported",
                    "statistics_available": true,
                    "final_snapshot_available": false,
                    "events_lost": 1,
                    "log_buffers_lost": 0,
                    "real_time_buffers_lost": 0
                },
                "artifacts": [
                    {
                        "kind": "runtime_manifest",
                        "path": "run.json",
                        "schema": "sideeffect.run",
                        "schema_version": 2,
                        "byte_length": 2,
                        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    },
                    {
                        "kind": "runtime_trace",
                        "path": "trace.strace",
                        "schema": "strace_text",
                        "schema_version": 1,
                        "byte_length": 2,
                        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    }
                ]
            }],
            "host_context": {
                "os_name": {"status": "observed", "value": "synthetic-linux"},
                "os_version": {"status": "observed", "value": "1"},
                "privilege": "not_elevated"
            },
            "coverage_manifest": {
                "version": 1,
                "sources": [{"role": "runtime", "status": "partial"}]
            }
        });
        let bytes = serde_json::to_vec(&value).unwrap();
        let manifest = parse_manifest(&bytes).unwrap();
        let digest = sha256_hex(&bytes);
        let preview = preview_baseline(
            "synthetic lossy baseline",
            &[BaselineManifestInput {
                manifest: &manifest,
                manifest_sha256: &digest,
            }],
        )
        .unwrap();
        assert!(!preview.promotion.allowed);
        assert_eq!(
            preview.promotion.blocking_reason_codes,
            vec![
                "runtime_loss_reported",
                "session_partial",
                "source_incomplete"
            ]
        );
        assert!(matches!(
            create_profile(&preview, &preview.sha256, 10),
            Err(BaselineError::PromotionBlocked(_))
        ));
    }

    #[test]
    fn preview_rejects_duplicate_sessions_and_invalid_approval_digest() {
        let (bytes, manifest) = manifest("dddddddddddddddddddddddddddddddd", "1", Some("observed"));
        let digest = sha256_hex(&bytes);
        let input = BaselineManifestInput {
            manifest: &manifest,
            manifest_sha256: &digest,
        };
        assert!(matches!(
            preview_baseline("duplicate", &[input, input]),
            Err(BaselineError::DuplicateSession(_))
        ));

        let preview = preview_baseline("valid", &[input]).unwrap();
        assert_eq!(
            create_profile(&preview, &preview.sha256.to_ascii_uppercase(), 1),
            Err(BaselineError::ApprovalDigestMismatch)
        );
    }

    #[test]
    fn bounded_parsing_rejects_oversized_or_unknown_profile_fields() {
        assert_eq!(
            parse_profile(&vec![b' '; MAX_BASELINE_PROFILE_BYTES + 1]),
            Err(BaselineError::TooLarge)
        );
        let preview = preview_two();
        let profile = create_profile(&preview, &preview.sha256, 10).unwrap();
        let mut value = serde_json::to_value(profile).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert_eq!(
            parse_profile(value.to_string().as_bytes()),
            Err(BaselineError::InvalidProfile)
        );
    }
}
