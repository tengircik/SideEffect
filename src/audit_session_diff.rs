//! Bounded item-level comparison of verified audit-session inventory artifacts.

use crate::audit_session::{
    ArtifactKind, AuditSessionManifest, SessionArtifactRef, SourceRole, SourceStatus,
    compare_sessions,
};
use crate::fingerprint::sha256_hex;
use crate::inventory::{
    compare_package_inventory_json, compare_permission_inventory_json,
    compare_process_inventory_json, compare_startup_inventory_json,
    compare_windows_software_inventory_json,
};
use serde::Serialize;
use serde_json::Value;

/// Existing inventory comparators accept at most this many bytes across a pair.
pub const MAX_SESSION_DIFF_PAIR_BYTES: usize = 64 * 1024 * 1024;
pub const AUDIT_SESSION_DIFF_SCHEMA: &str = "sideeffect.audit_session_diff";

#[derive(Clone, Copy, Debug)]
pub struct VerifiedArtifactBytes<'a> {
    pub kind: ArtifactKind,
    pub path: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditSessionDiff {
    pub schema: &'static str,
    pub schema_version: u32,
    /// Preserves the existing compare-sessions metadata readiness result.
    pub status: &'static str,
    pub comparable: bool,
    pub reason_codes: Vec<&'static str>,
    pub metadata_scope: &'static str,
    pub scope: &'static str,
    pub item_comparison_status: &'static str,
    pub native_pair_input_limit_bytes: usize,
    pub before_session_id: String,
    pub after_session_id: String,
    pub before_platform: String,
    pub after_platform: String,
    pub before_interval_unix_ms: [u128; 2],
    pub after_interval_unix_ms: [u128; 2],
    pub source_diffs: Vec<SessionSourceDiff>,
    pub limitations: [&'static str; 6],
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionSourceDiff {
    pub role: SourceRole,
    /// `compared`, `partial`, `not_compared`, or `incomparable`.
    pub status: &'static str,
    pub reason_code: Option<&'static str>,
    pub before_source_status: Option<SourceStatus>,
    pub after_source_status: Option<SourceStatus>,
    pub before_source_platform: Option<String>,
    pub after_source_platform: Option<String>,
    pub before_source_scope: Option<String>,
    pub after_source_scope: Option<String>,
    pub before_artifacts: Vec<ArtifactEvidence>,
    pub after_artifacts: Vec<ArtifactEvidence>,
    /// Native comparator result, including its item-level deltas and local evidence locators.
    pub comparison: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactEvidence {
    pub path: String,
    pub schema: String,
    pub schema_version: u32,
    pub sha256: String,
}

pub fn compare_audit_sessions(
    before: &AuditSessionManifest,
    after: &AuditSessionManifest,
    before_artifacts: &[VerifiedArtifactBytes<'_>],
    after_artifacts: &[VerifiedArtifactBytes<'_>],
) -> AuditSessionDiff {
    let context = compare_sessions(before, after);
    let roles = [
        SourceRole::Packages,
        SourceRole::Processes,
        SourceRole::Permissions,
        SourceRole::Startup,
        SourceRole::Runtime,
        SourceRole::PathExecutables,
    ];
    let source_diffs: Vec<_> = roles
        .into_iter()
        .filter(|role| {
            before.sources.iter().any(|source| source.role == *role)
                || after.sources.iter().any(|source| source.role == *role)
        })
        .map(|role| compare_source_role(role, before, after, before_artifacts, after_artifacts))
        .collect();

    let item_comparison_status =
        if !source_diffs.is_empty() && source_diffs.iter().all(|item| item.status == "compared") {
            "complete"
        } else if source_diffs.iter().any(|item| item.status == "partial") {
            "partial"
        } else {
            "not_complete"
        };
    AuditSessionDiff {
        schema: AUDIT_SESSION_DIFF_SCHEMA,
        schema_version: 1,
        status: if context.comparable {
            "comparable"
        } else {
            "incomparable"
        },
        comparable: context.comparable,
        reason_codes: context.reasons.iter().map(|reason| reason.code()).collect(),
        metadata_scope: "metadata_readiness_only",
        scope: "metadata_and_item_level_inventory_and_runtime",
        item_comparison_status,
        native_pair_input_limit_bytes: MAX_SESSION_DIFF_PAIR_BYTES,
        before_session_id: before.session_id.clone(),
        after_session_id: after.session_id.clone(),
        before_platform: before.platform.clone(),
        after_platform: after.platform.clone(),
        before_interval_unix_ms: [before.started_at_unix_ms, before.ended_at_unix_ms],
        after_interval_unix_ms: [after.started_at_unix_ms, after.ended_at_unix_ms],
        source_diffs,
        limitations: [
            "Metadata comparability describes declared collection context; it does not establish equal observations or complete system coverage.",
            "Each item reference is local to its verified artifact; the artifact SHA-256 links the locator to bytes but does not authenticate their producer.",
            "Unmatched rows are additions or removals only where the native comparator establishes complete source coverage and certain identity.",
            "Snapshots are non-atomic observations. Differences do not establish installation, execution history, causation, or safety.",
            "Caller privilege contexts are not comparability keys and may differ.",
            "PATH-executable artifacts are reported as not compared in this version.",
        ],
    }
}

fn compare_source_role(
    role: SourceRole,
    before: &AuditSessionManifest,
    after: &AuditSessionManifest,
    before_artifacts: &[VerifiedArtifactBytes<'_>],
    after_artifacts: &[VerifiedArtifactBytes<'_>],
) -> SessionSourceDiff {
    let left = before.sources.iter().find(|source| source.role == role);
    let right = after.sources.iter().find(|source| source.role == role);
    let left_status = left.map(|source| source.status);
    let right_status = right.map(|source| source.status);
    let left_platform = left.map(|source| source.platform.clone());
    let right_platform = right.map(|source| source.platform.clone());
    let left_scope = left.map(|source| source.scope.clone());
    let right_scope = right.map(|source| source.scope.clone());
    let left_references = left
        .map(|source| source.artifacts.as_slice())
        .unwrap_or_default();
    let right_references = right
        .map(|source| source.artifacts.as_slice())
        .unwrap_or_default();
    let left_reference = left_references.first();
    let right_reference = right_references.first();
    let mut result = SessionSourceDiff {
        role,
        status: "not_compared",
        reason_code: None,
        before_source_status: left_status,
        after_source_status: right_status,
        before_source_platform: left_platform,
        after_source_platform: right_platform,
        before_source_scope: left_scope,
        after_source_scope: right_scope,
        before_artifacts: left_references.iter().map(ArtifactEvidence::from).collect(),
        after_artifacts: right_references
            .iter()
            .map(ArtifactEvidence::from)
            .collect(),
        comparison: None,
    };

    if before.platform != after.platform {
        return result.incomparable("platform_mismatch");
    }
    let (Some(left), Some(right)) = (left, right) else {
        return result.not_compared(if left.is_none() {
            "source_missing_before"
        } else {
            "source_missing_after"
        });
    };
    if left.platform != right.platform {
        return result.incomparable("source_platform_mismatch");
    }
    if left.scope != right.scope {
        return result.incomparable("source_scope_mismatch");
    }
    let (Some(left_ref), Some(right_ref)) = (left_reference, right_reference) else {
        return result.not_compared(if left_reference.is_none() {
            "artifact_missing_before"
        } else {
            "artifact_missing_after"
        });
    };
    if left_ref.kind != right_ref.kind
        || left_ref.schema != right_ref.schema
        || left_ref.schema_version != right_ref.schema_version
    {
        return result.incomparable("artifact_contract_mismatch");
    }
    if !supported_role_kind(role, left_ref.kind) {
        return result.not_compared("role_not_supported_by_item_diff");
    }
    if left_ref
        .byte_length
        .checked_add(right_ref.byte_length)
        .is_none_or(|combined| combined > MAX_SESSION_DIFF_PAIR_BYTES as u64)
    {
        return result.not_compared("native_input_limit_exceeded");
    }
    let left_bytes = find_verified_bytes(left_ref, before_artifacts);
    let right_bytes = find_verified_bytes(right_ref, after_artifacts);
    let (Some(left_bytes), Some(right_bytes)) = (left_bytes, right_bytes) else {
        return result.incomparable("verified_artifact_reference_mismatch");
    };
    if left_bytes
        .bytes
        .len()
        .checked_add(right_bytes.bytes.len())
        .is_none_or(|combined| combined > MAX_SESSION_DIFF_PAIR_BYTES)
    {
        return result.not_compared("native_input_limit_exceeded");
    }
    match compare_native(role, left_ref.kind, left_bytes.bytes, right_bytes.bytes) {
        Ok((mut status, mut value)) => {
            if left.status != SourceStatus::Complete || right.status != SourceStatus::Complete {
                suppress_session_incomplete_presence(role, &mut value);
                status = "partial";
                result.reason_code = Some("session_source_incomplete");
            }
            result.status = status;
            result.comparison = Some(value);
            result
        }
        Err(NativeCompareError::InputLimit) => result.not_compared("native_input_limit_exceeded"),
        Err(NativeCompareError::Malformed) => result.incomparable("invalid_inventory_artifact"),
        Err(NativeCompareError::Unsupported) => result.not_compared("native_schema_not_supported"),
        Err(NativeCompareError::Incompatible) => result.incomparable("native_contract_mismatch"),
        Err(NativeCompareError::Limit) => result.not_compared("native_comparison_limit_exceeded"),
    }
}

/// A source-level session status is authoritative for unmatched-row claims, even if the
/// referenced artifact's own document claims complete coverage. Matched changes remain useful.
fn suppress_session_incomplete_presence(role: SourceRole, comparison: &mut Value) {
    let (before_only_kind, after_only_kind, before_count, after_count, suppressed_count) =
        match role {
            SourceRole::Packages => (
                "removed",
                "added",
                "removals",
                "additions",
                "unmatched_rows_with_incomplete_source",
            ),
            SourceRole::Processes => (
                "removed",
                "added",
                "removals",
                "additions",
                "unmatched_rows_suppressed_for_partial_source",
            ),
            SourceRole::Permissions => (
                "removed",
                "added",
                "removals",
                "additions",
                "unmatched_rows_suppressed_for_partial_source",
            ),
            SourceRole::Startup => (
                "observed_before_only",
                "observed_after_only",
                "observed_before_only",
                "observed_after_only",
                "unmatched_rows_suppressed_for_incomplete_source",
            ),
            SourceRole::Runtime | SourceRole::PathExecutables => return,
        };

    let Some(deltas) = comparison.get_mut("deltas").and_then(Value::as_array_mut) else {
        return;
    };
    let mut before_only = 0usize;
    let mut after_only = 0usize;
    deltas.retain(|delta| {
        let kind = delta.get("kind").and_then(Value::as_str);
        match kind {
            Some(kind) if kind == before_only_kind => {
                before_only = before_only.saturating_add(1);
                false
            }
            Some(kind) if kind == after_only_kind => {
                after_only = after_only.saturating_add(1);
                false
            }
            _ => true,
        }
    });
    let suppressed = before_only.saturating_add(after_only);
    if let Some(counts) = comparison.get_mut("counts").and_then(Value::as_object_mut) {
        subtract_count(counts, before_count, before_only);
        subtract_count(counts, after_count, after_only);
        add_count(counts, suppressed_count, suppressed);
    }
    if let Some(status) = comparison.get_mut("status") {
        *status = Value::String("partial".into());
    }
    if let Some(diagnostics) = comparison
        .get_mut("diagnostics")
        .and_then(Value::as_array_mut)
    {
        // Package diagnostics are a closed enum in Rust; use its existing equivalent.
        let diagnostic = if role == SourceRole::Packages {
            "source_incomplete"
        } else {
            "session_source_incomplete"
        };
        if !diagnostics
            .iter()
            .any(|item| item.as_str() == Some(diagnostic))
        {
            diagnostics.push(Value::String(diagnostic.into()));
        }
    }
}

fn subtract_count(counts: &mut serde_json::Map<String, Value>, key: &str, amount: usize) {
    if let Some(count) = counts.get(key).and_then(Value::as_u64) {
        *counts.get_mut(key).expect("count key was just read") =
            Value::from(count.saturating_sub(amount as u64));
    }
}

fn add_count(counts: &mut serde_json::Map<String, Value>, key: &str, amount: usize) {
    let current = counts.get(key).and_then(Value::as_u64).unwrap_or(0);
    counts.insert(
        key.into(),
        Value::from(current.saturating_add(amount as u64)),
    );
}

impl SessionSourceDiff {
    fn not_compared(mut self, reason: &'static str) -> Self {
        self.status = "not_compared";
        self.reason_code = Some(reason);
        self
    }
    fn incomparable(mut self, reason: &'static str) -> Self {
        self.status = "incomparable";
        self.reason_code = Some(reason);
        self
    }
}

impl AuditSessionDiff {
    pub fn refresh_item_comparison_status(&mut self) {
        self.item_comparison_status = if !self.source_diffs.is_empty()
            && self
                .source_diffs
                .iter()
                .all(|item| item.status == "compared")
        {
            "complete"
        } else if self
            .source_diffs
            .iter()
            .any(|item| item.status == "partial")
        {
            "partial"
        } else {
            "not_complete"
        };
    }
}

impl From<&SessionArtifactRef> for ArtifactEvidence {
    fn from(reference: &SessionArtifactRef) -> Self {
        Self {
            path: reference.path.clone(),
            schema: reference.schema.clone(),
            schema_version: reference.schema_version,
            sha256: reference.sha256.clone(),
        }
    }
}

fn find_verified_bytes<'a>(
    reference: &SessionArtifactRef,
    artifacts: &'a [VerifiedArtifactBytes<'a>],
) -> Option<&'a VerifiedArtifactBytes<'a>> {
    artifacts.iter().find(|artifact| {
        artifact.kind == reference.kind
            && artifact.path == reference.path
            && artifact.bytes.len() as u64 == reference.byte_length
            && sha256_hex(artifact.bytes) == reference.sha256
    })
}

fn supported_role_kind(role: SourceRole, kind: ArtifactKind) -> bool {
    matches!(
        (role, kind),
        (
            SourceRole::Packages,
            ArtifactKind::Packages | ArtifactKind::WindowsSoftware
        ) | (
            SourceRole::Processes,
            ArtifactKind::Processes | ArtifactKind::WindowsProcesses
        ) | (
            SourceRole::Permissions,
            ArtifactKind::Permissions | ArtifactKind::WindowsPermissions
        ) | (
            SourceRole::Startup,
            ArtifactKind::Startup | ArtifactKind::WindowsStartup
        )
    )
}

#[derive(Clone, Copy)]
enum NativeCompareError {
    InputLimit,
    Malformed,
    Unsupported,
    Incompatible,
    Limit,
}

fn compare_native(
    role: SourceRole,
    kind: ArtifactKind,
    left: &[u8],
    right: &[u8],
) -> Result<(&'static str, Value), NativeCompareError> {
    let value = match (role, kind) {
        (SourceRole::Packages, ArtifactKind::Packages) => {
            let result = compare_package_inventory_json(left, right).map_err(map_package_error)?;
            let status = if result.status == crate::inventory::PackageComparisonStatus::Complete {
                "compared"
            } else {
                "partial"
            };
            (
                status,
                serde_json::to_value(result).map_err(|_| NativeCompareError::Malformed)?,
            )
        }
        (SourceRole::Packages, ArtifactKind::WindowsSoftware) => {
            let result =
                compare_windows_software_inventory_json(left, right).map_err(map_software_error)?;
            let status =
                if result.status == crate::inventory::WindowsSoftwareComparisonStatus::Complete {
                    "compared"
                } else {
                    "partial"
                };
            (
                status,
                serde_json::to_value(result).map_err(|_| NativeCompareError::Malformed)?,
            )
        }
        (SourceRole::Processes, ArtifactKind::Processes | ArtifactKind::WindowsProcesses)
        | (SourceRole::Permissions, ArtifactKind::Permissions | ArtifactKind::WindowsPermissions)
        | (SourceRole::Startup, ArtifactKind::Startup | ArtifactKind::WindowsStartup) => match role
        {
            SourceRole::Processes => {
                let result =
                    compare_process_inventory_json(left, right).map_err(map_process_error)?;
                let status = if result.status == crate::inventory::ProcessDiffStatus::Complete {
                    "compared"
                } else {
                    "partial"
                };
                (
                    status,
                    serde_json::to_value(result).map_err(|_| NativeCompareError::Malformed)?,
                )
            }
            SourceRole::Permissions => {
                let result =
                    compare_permission_inventory_json(left, right).map_err(map_permission_error)?;
                let status = if result.status == crate::inventory::PermissionDiffStatus::Complete {
                    "compared"
                } else {
                    "partial"
                };
                (
                    status,
                    serde_json::to_value(result).map_err(|_| NativeCompareError::Malformed)?,
                )
            }
            SourceRole::Startup => {
                let result =
                    compare_startup_inventory_json(left, right).map_err(map_startup_error)?;
                let status = if result.status == crate::inventory::StartupDiffStatus::Complete {
                    "compared"
                } else {
                    "partial"
                };
                (
                    status,
                    serde_json::to_value(result).map_err(|_| NativeCompareError::Malformed)?,
                )
            }
            _ => return Err(NativeCompareError::Unsupported),
        },
        _ => return Err(NativeCompareError::Unsupported),
    };
    Ok(value)
}

fn map_process_error(error: crate::inventory::ProcessDiffError) -> NativeCompareError {
    use crate::inventory::ProcessDiffError as E;
    match error {
        E::MalformedInput => NativeCompareError::Malformed,
        E::InputTooLarge => NativeCompareError::InputLimit,
        E::UnsupportedSchema => NativeCompareError::Unsupported,
        E::SchemaMismatch | E::PlatformMismatch => NativeCompareError::Incompatible,
        E::LimitExceeded => NativeCompareError::Limit,
    }
}

fn map_permission_error(error: crate::inventory::PermissionDiffError) -> NativeCompareError {
    use crate::inventory::PermissionDiffError as E;
    match error {
        E::MalformedInput => NativeCompareError::Malformed,
        E::InputTooLarge => NativeCompareError::InputLimit,
        E::UnsupportedSchema => NativeCompareError::Unsupported,
        E::SchemaMismatch | E::PlatformMismatch => NativeCompareError::Incompatible,
        E::LimitExceeded => NativeCompareError::Limit,
    }
}

fn map_startup_error(error: crate::inventory::StartupDiffError) -> NativeCompareError {
    use crate::inventory::StartupDiffError as E;
    match error {
        E::MalformedInput => NativeCompareError::Malformed,
        E::InputTooLarge => NativeCompareError::InputLimit,
        E::UnsupportedSchema => NativeCompareError::Unsupported,
        E::SchemaMismatch | E::PlatformMismatch => NativeCompareError::Incompatible,
        E::LimitExceeded => NativeCompareError::Limit,
    }
}

fn map_package_error(error: crate::inventory::PackageComparisonError) -> NativeCompareError {
    use crate::inventory::PackageComparisonError as E;
    match error {
        E::MalformedInput => NativeCompareError::Malformed,
        E::InputTooLarge => NativeCompareError::InputLimit,
        E::UnsupportedSchema => NativeCompareError::Unsupported,
        E::SchemaMismatch | E::PlatformMismatch | E::ScopeMismatch => {
            NativeCompareError::Incompatible
        }
        E::UnsupportedSourceId
        | E::SourceLimitExceeded
        | E::PackageLimitExceeded
        | E::FieldLimitExceeded
        | E::DocumentTextLimitExceeded
        | E::DuplicateSourceId
        | E::DeltaLimitExceeded => NativeCompareError::Limit,
    }
}

fn map_software_error(
    error: crate::inventory::WindowsSoftwareComparisonError,
) -> NativeCompareError {
    use crate::inventory::WindowsSoftwareComparisonError as E;
    match error {
        E::MalformedInput => NativeCompareError::Malformed,
        E::InputTooLarge => NativeCompareError::InputLimit,
        E::UnsupportedSchema => NativeCompareError::Unsupported,
        E::PlatformMismatch | E::ScopeMismatch | E::InvalidSourceSet => {
            NativeCompareError::Incompatible
        }
        E::LimitExceeded => NativeCompareError::Limit,
    }
}

#[cfg(test)]
mod tests {
    use super::{VerifiedArtifactBytes, compare_audit_sessions};
    use crate::audit_session::{
        ArtifactKind, AuditSessionManifest, AuditSessionSource, IntervalSemantics,
        SessionArtifactRef, SessionStatus, SourceRole, SourceStatus,
    };
    use sha2::{Digest, Sha256};

    fn inventory(name: &str, version: &str, source_status: &str, global_status: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema":"sideeffect.inventory", "schema_version":2, "platform":"linux",
            "scope":"available_package_manager_databases", "captured_at_unix_ms":1001,
            "status":global_status,
            "sources":[{"id":"dpkg_query","status":source_status,"records_seen":1,"diagnostics":[]}],
            "packages":[{"source_id":"dpkg_query","name":name,"version":version,"architecture":"amd64","status_abbrev":"ii ","evidence":{"line":1,"byte_offset":0,"byte_length":8,"record_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","raw_record":null,"raw_record_hex":null},"diagnostic_code":null}]
        })).unwrap()
    }

    fn session(
        bytes: &[u8],
        id: &str,
        source_status: SourceStatus,
    ) -> (AuditSessionManifest, String) {
        session_for(
            bytes,
            id,
            SessionSpec {
                role: SourceRole::Packages,
                kind: ArtifactKind::Packages,
                schema: "sideeffect.inventory",
                schema_version: 2,
                scope: "available_package_manager_databases",
            },
            source_status,
        )
    }

    struct SessionSpec<'a> {
        role: SourceRole,
        kind: ArtifactKind,
        schema: &'a str,
        schema_version: u32,
        scope: &'a str,
    }

    fn session_for(
        bytes: &[u8],
        id: &str,
        spec: SessionSpec<'_>,
        source_status: SourceStatus,
    ) -> (AuditSessionManifest, String) {
        let digest = format!("{:x}", Sha256::digest(bytes));
        let reference = SessionArtifactRef {
            kind: spec.kind,
            path: match spec.kind {
                ArtifactKind::Permissions => "permissions.json",
                _ => "packages.json",
            }
            .into(),
            schema: spec.schema.into(),
            schema_version: spec.schema_version,
            byte_length: bytes.len() as u64,
            sha256: digest.clone(),
        };
        let source = AuditSessionSource {
            role: spec.role,
            collector: None,
            platform: "linux".into(),
            scope: spec.scope.into(),
            started_at_unix_ms: 1000,
            ended_at_unix_ms: 1001,
            status: source_status,
            applied_limits: vec![],
            requested_settings: vec![],
            effective_settings: vec![],
            loss: None,
            diagnostic_codes: vec![],
            artifacts: vec![reference],
        };
        (
            AuditSessionManifest {
                schema: "sideeffect.audit_session".into(),
                schema_version: 6,
                session_id: id.into(),
                platform: "linux".into(),
                architecture: "x86_64".into(),
                started_at_unix_ms: 1000,
                ended_at_unix_ms: 1002,
                interval_semantics: IntervalSemantics::BestEffortNonAtomic,
                status: if source_status == SourceStatus::Complete {
                    SessionStatus::Complete
                } else {
                    SessionStatus::Partial
                },
                sources: vec![source],
                host_context: None,
                coverage_manifest: None,
            },
            digest,
        )
    }

    #[test]
    fn emits_item_deltas_linked_to_both_verified_artifact_digests() {
        let before_bytes = inventory("demo", "1", "complete", "complete");
        let after_bytes = inventory("demo", "2", "complete", "complete");
        let (before, before_digest) = session(
            &before_bytes,
            "0123456789abcdef0123456789abcdef",
            SourceStatus::Complete,
        );
        let (after, after_digest) = session(
            &after_bytes,
            "1123456789abcdef0123456789abcdef",
            SourceStatus::Complete,
        );
        let left = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: &before_bytes,
        }];
        let right = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: &after_bytes,
        }];
        let report = compare_audit_sessions(&before, &after, &left, &right);
        assert_eq!(report.schema, "sideeffect.audit_session_diff");
        assert_eq!(report.source_diffs[0].status, "compared");
        assert_eq!(
            report.source_diffs[0].before_artifacts[0].sha256,
            before_digest
        );
        assert_eq!(
            report.source_diffs[0].after_artifacts[0].sha256,
            after_digest
        );
        assert_eq!(
            report.source_diffs[0].before_artifacts[0].path,
            "packages.json"
        );
        assert_eq!(
            report.source_diffs[0].comparison.as_ref().unwrap()["counts"]["changes"],
            1
        );
        assert_eq!(
            report.source_diffs[0].comparison.as_ref().unwrap()["deltas"][0]["before"]["evidence"]
                ["line"],
            1
        );
    }

    #[test]
    fn partial_and_ambiguous_native_rows_remain_partial_without_presence_claims() {
        let before_bytes = inventory("demo", "1", "partial", "partial");
        let after_bytes = inventory("demo", "2", "partial", "partial");
        let (before, _) = session(
            &before_bytes,
            "0123456789abcdef0123456789abcdef",
            SourceStatus::Partial,
        );
        let (after, _) = session(
            &after_bytes,
            "1123456789abcdef0123456789abcdef",
            SourceStatus::Partial,
        );
        let left = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: &before_bytes,
        }];
        let right = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: &after_bytes,
        }];
        let report = compare_audit_sessions(&before, &after, &left, &right);
        assert_eq!(report.source_diffs[0].status, "partial");
        let comparison = report.source_diffs[0].comparison.as_ref().unwrap();
        assert_eq!(comparison["counts"]["changes"], 1);
        assert_eq!(comparison["counts"]["additions"], 0);
        assert_eq!(comparison["counts"]["removals"], 0);
    }

    #[test]
    fn session_partial_status_suppresses_presence_deltas_from_complete_package_documents() {
        let with_unmatched = |version: &str, unmatched_name: &str| {
            let mut document: serde_json::Value =
                serde_json::from_slice(&inventory("demo", version, "complete", "complete"))
                    .unwrap();
            let mut unmatched = document["packages"][0].clone();
            unmatched["name"] = serde_json::Value::String(unmatched_name.into());
            document["packages"] = serde_json::json!([document["packages"][0].clone(), unmatched]);
            document["sources"][0]["records_seen"] = serde_json::json!(2);
            serde_json::to_vec(&document).unwrap()
        };
        let before_bytes = with_unmatched("1", "old-package");
        let after_bytes = with_unmatched("2", "new-package");
        let (before, before_digest) = session(
            &before_bytes,
            "0123456789abcdef0123456789abcdef",
            SourceStatus::Partial,
        );
        let (after, after_digest) = session(
            &after_bytes,
            "1123456789abcdef0123456789abcdef",
            SourceStatus::Complete,
        );
        let left = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: &before_bytes,
        }];
        let right = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: &after_bytes,
        }];

        let report = compare_audit_sessions(&before, &after, &left, &right);
        assert_eq!(report.item_comparison_status, "partial");
        let source = &report.source_diffs[0];
        assert_eq!(source.status, "partial");
        assert_eq!(source.reason_code, Some("session_source_incomplete"));
        let comparison = source.comparison.as_ref().unwrap();
        assert_eq!(comparison["status"], "partial");
        assert_eq!(comparison["counts"]["changes"], 1);
        assert_eq!(comparison["counts"]["additions"], 0);
        assert_eq!(comparison["counts"]["removals"], 0);
        assert_eq!(
            comparison["counts"]["unmatched_rows_with_incomplete_source"],
            2
        );
        assert_eq!(comparison["deltas"].as_array().unwrap().len(), 1);
        assert_eq!(comparison["deltas"][0]["kind"], "changed");
        assert!(
            comparison["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|diagnostic| diagnostic == "source_incomplete")
        );
        assert_eq!(source.before_artifacts[0].sha256, before_digest);
        assert_eq!(source.after_artifacts[0].sha256, after_digest);
    }

    #[test]
    fn duplicate_package_identities_are_reported_ambiguous_without_deltas() {
        let make_duplicates = |version: &str| {
            let mut value: serde_json::Value =
                serde_json::from_slice(&inventory("demo", version, "complete", "complete"))
                    .unwrap();
            let row = value["packages"][0].clone();
            value["packages"] = serde_json::json!([row.clone(), row]);
            value["sources"][0]["records_seen"] = serde_json::json!(2);
            serde_json::to_vec(&value).unwrap()
        };
        let before_bytes = make_duplicates("1");
        let after_bytes = make_duplicates("2");
        let (before, _) = session(
            &before_bytes,
            "0123456789abcdef0123456789abcdef",
            SourceStatus::Complete,
        );
        let (after, _) = session(
            &after_bytes,
            "1123456789abcdef0123456789abcdef",
            SourceStatus::Complete,
        );
        let left = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: &before_bytes,
        }];
        let right = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: &after_bytes,
        }];
        let report = compare_audit_sessions(&before, &after, &left, &right);
        assert_eq!(report.source_diffs[0].status, "partial");
        let comparison = report.source_diffs[0].comparison.as_ref().unwrap();
        assert!(
            comparison["counts"]["ambiguous_identity_groups"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert!(comparison["deltas"].as_array().unwrap().is_empty());
    }

    #[test]
    fn reports_missing_unsupported_and_invalid_artifacts_without_inventing_deltas() {
        let bytes = inventory("demo", "1", "complete", "complete");
        let (mut before, _) = session(
            &bytes,
            "0123456789abcdef0123456789abcdef",
            SourceStatus::Complete,
        );
        let (after, _) = session(
            &bytes,
            "1123456789abcdef0123456789abcdef",
            SourceStatus::Complete,
        );
        before.sources[0].artifacts.clear();
        let left: [VerifiedArtifactBytes<'_>; 0] = [];
        let right = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: &bytes,
        }];
        let missing = compare_audit_sessions(&before, &after, &left, &right);
        assert_eq!(
            missing.source_diffs[0].reason_code,
            Some("artifact_missing_before")
        );
        assert!(missing.source_diffs[0].comparison.is_none());

        let bad = b"{\"schema\":\"sideeffect.inventory\",\"schema_version\":2}";
        let (before, _) = session(
            bad,
            "0123456789abcdef0123456789abcdef",
            SourceStatus::Complete,
        );
        let (after, _) = session(
            bad,
            "1123456789abcdef0123456789abcdef",
            SourceStatus::Complete,
        );
        let left = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: bad,
        }];
        let right = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: bad,
        }];
        let invalid = compare_audit_sessions(&before, &after, &left, &right);
        assert_eq!(invalid.source_diffs[0].status, "incomparable");
        assert_eq!(
            invalid.source_diffs[0].reason_code,
            Some("invalid_inventory_artifact")
        );
        assert!(invalid.source_diffs[0].comparison.is_none());

        let (before, _) = session(
            &bytes,
            "0123456789abcdef0123456789abcdef",
            SourceStatus::Complete,
        );
        let (after, _) = session(
            &bytes,
            "1123456789abcdef0123456789abcdef",
            SourceStatus::Complete,
        );
        let mismatched = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: bad,
        }];
        let verified = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: &bytes,
        }];
        let report = compare_audit_sessions(&before, &after, &mismatched, &verified);
        assert_eq!(
            report.source_diffs[0].reason_code,
            Some("verified_artifact_reference_mismatch")
        );
        assert!(report.source_diffs[0].comparison.is_none());

        let mut same_length_tamper = bytes.clone();
        let last = same_length_tamper.len() - 1;
        same_length_tamper[last] ^= 1;
        let same_length_mismatch = [VerifiedArtifactBytes {
            kind: ArtifactKind::Packages,
            path: "packages.json",
            bytes: &same_length_tamper,
        }];
        let report = compare_audit_sessions(&before, &after, &same_length_mismatch, &verified);
        assert_eq!(
            report.source_diffs[0].reason_code,
            Some("verified_artifact_reference_mismatch")
        );
        assert!(report.source_diffs[0].comparison.is_none());

        let (mut before, _) = session(
            &bytes,
            "0123456789abcdef0123456789abcdef",
            SourceStatus::Complete,
        );
        let (mut after, _) = session(
            &bytes,
            "1123456789abcdef0123456789abcdef",
            SourceStatus::Complete,
        );
        before.sources[0].artifacts[0].byte_length = (32 * 1024 * 1024 + 1) as u64;
        after.sources[0].artifacts[0].byte_length = (32 * 1024 * 1024 + 1) as u64;
        let oversized = compare_audit_sessions(&before, &after, &verified, &verified);
        assert_eq!(oversized.source_diffs[0].status, "not_compared");
        assert_eq!(
            oversized.source_diffs[0].reason_code,
            Some("native_input_limit_exceeded")
        );
        assert!(oversized.source_diffs[0].comparison.is_none());
    }

    #[test]
    fn dispatches_permission_artifacts_through_the_existing_comparator() {
        fn permission(mode: u64) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "schema":"sideeffect.permission_inventory", "schema_version":1,
                "platform":"linux", "scope":"explicit_paths_metadata_posix_acl_file_capability",
                "captured_at_unix_ms":100, "status":"complete", "paths_requested":1,
                "acl_bytes_read":0, "capability_bytes_read":0,
                "objects":[{
                    "path":"/tmp/fixture", "path_bytes_hex":"2f746d702f66697874757265",
                    "status":"complete", "object_type":"regular_file", "uid":1000,
                    "gid":1000, "mode":mode, "device":1, "inode":2,
                    "access_acl":{"status":"absent","source":"fgetxattr/system.posix_acl_access"},
                    "default_acl":{"status":"not_applicable","source":"fgetxattr/system.posix_acl_default"},
                    "file_capability":{"status":"absent","source":"fgetxattr/security.capability"},
                    "diagnostics":[]
                }], "diagnostics":[]
            })).unwrap()
        }
        let before_bytes = permission(0o644);
        let after_bytes = permission(0o600);
        let (before, _) = session_for(
            &before_bytes,
            "0123456789abcdef0123456789abcdef",
            SessionSpec {
                role: SourceRole::Permissions,
                kind: ArtifactKind::Permissions,
                schema: "sideeffect.permission_inventory",
                schema_version: 1,
                scope: "selected explicit paths",
            },
            SourceStatus::Complete,
        );
        let (after, _) = session_for(
            &after_bytes,
            "1123456789abcdef0123456789abcdef",
            SessionSpec {
                role: SourceRole::Permissions,
                kind: ArtifactKind::Permissions,
                schema: "sideeffect.permission_inventory",
                schema_version: 1,
                scope: "selected explicit paths",
            },
            SourceStatus::Complete,
        );
        let left = [VerifiedArtifactBytes {
            kind: ArtifactKind::Permissions,
            path: "permissions.json",
            bytes: &before_bytes,
        }];
        let right = [VerifiedArtifactBytes {
            kind: ArtifactKind::Permissions,
            path: "permissions.json",
            bytes: &after_bytes,
        }];
        let report = compare_audit_sessions(&before, &after, &left, &right);
        assert_eq!(report.source_diffs[0].status, "compared");
        assert_eq!(
            report.source_diffs[0].comparison.as_ref().unwrap()["counts"]["changes"],
            1
        );
        assert_eq!(
            report.source_diffs[0].before_artifacts[0].path,
            "permissions.json"
        );
    }
}
