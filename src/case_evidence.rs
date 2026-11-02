//! Resolve case-file evidence references against already verified session bytes.
//!
//! The resolver performs no filesystem access. Callers must obtain session views from the
//! platform audit-session reader. Manifest and artifact hashes establish byte consistency with
//! the supplied manifest; they do not authenticate a producer or prove capture completeness.

use serde::Serialize;
use std::collections::{HashMap, HashSet};

use crate::audit_session::{
    self, ArtifactKind, AuditSessionManifest, AuditSessionSource, SessionStatus, SourceRole,
    SourceStatus,
};
use crate::case::{CaseEvidenceLocator, CasePlatform, InvestigationCase, MAX_CASE_SESSIONS};

pub const MAX_CASE_RESOLUTION_INPUT_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_CASE_RESOLVED_FACT_BYTES: usize = 32 * 1024 * 1024;

/// One manifest-listed artifact returned by a platform session reader.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedArtifactView<'a> {
    pub kind: ArtifactKind,
    pub path: &'a str,
    pub bytes: &'a [u8],
}

/// Borrowed view over bytes already opened and checked by the platform session reader.
///
/// Construct this from `read_verified_session` output. The resolver rechecks manifest and
/// artifact bindings, but it cannot check the original directory ACL, file identity, or producer.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedSessionView<'a> {
    pub manifest: &'a AuditSessionManifest,
    pub manifest_bytes: &'a [u8],
    pub artifacts: &'a [VerifiedArtifactView<'a>],
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolvedCase {
    pub schema: &'static str,
    pub schema_version: u32,
    pub disclosure_note: &'static str,
    pub case_id: String,
    pub title: String,
    /// Unique resolved facts; entry references point here by index to avoid duplicating raw data.
    pub facts: Vec<ResolvedEvidenceFact>,
    pub entries: Vec<ResolvedCaseEntry>,
    pub sessions: Vec<ResolvedSession>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolvedCaseEntry {
    pub id: String,
    pub kind: crate::case::CaseEntryKind,
    pub authorship: String,
    pub text: String,
    pub severity: Option<crate::case::Severity>,
    pub confidence: Option<crate::case::Confidence>,
    pub evidence_fact_indexes: Vec<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolvedEvidenceFact {
    pub locator: CaseEvidenceLocator,
    pub artifact_path: String,
    pub fact: ResolvedEvidence,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResolvedEvidence {
    LinuxTraceRecord {
        parse_status: crate::model::ParseCompleteness,
        record: crate::model::TraceRecord,
    },
    WindowsEtwRecord {
        collection_status: crate::windows_runtime::CollectionStatus,
        capture_completeness: String,
        event_loss: crate::windows_runtime::EventLoss,
        record: crate::windows_runtime::NativeRuntimeEvent,
    },
    SelectedRootEntry {
        inventory_status: String,
        entry: crate::query::RootQueryEntry,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolvedSession {
    pub session_id: String,
    pub platform: String,
    pub manifest_schema_version: u32,
    pub manifest_sha256: String,
    pub status: SessionStatus,
    pub sources: Vec<ResolvedSource>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolvedSource {
    pub role: SourceRole,
    pub status: SourceStatus,
    pub diagnostic_codes: Vec<String>,
    /// Diagnostics from the referenced native artifact, retained once per source.
    pub artifact_review: Option<ArtifactReview>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactReview {
    LinuxTrace {
        parse_status: crate::model::ParseCompleteness,
        diagnostics: Vec<crate::model::TraceDiagnostic>,
    },
    WindowsEtw {
        collection_status: crate::windows_runtime::CollectionStatus,
        capture_completeness: String,
        stop_reason: crate::windows_runtime::StopReason,
        event_loss: crate::windows_runtime::EventLoss,
        diagnostics: Vec<String>,
    },
    SelectedRoot {
        inventory_status: String,
        diagnostics: Vec<crate::query::RootQueryDiagnostic>,
    },
}

enum ParsedArtifact {
    LinuxTrace(crate::model::TraceDocument),
    WindowsEtw(crate::windows_runtime::WindowsRuntimeCapture),
    SelectedRoot(crate::query::SelectedRootQuerySource),
}

/// Resolve every case locator against exact, already verified artifact bytes.
pub fn resolve_case(
    case: &InvestigationCase,
    sessions: &[VerifiedSessionView<'_>],
) -> Result<ResolvedCase, String> {
    case.validate()?;
    if sessions.len() != case.sessions.len() || sessions.len() > MAX_CASE_SESSIONS {
        return Err("verified session count does not match the case session list".to_owned());
    }

    let mut by_id = HashMap::with_capacity(sessions.len());
    let mut total_bytes = 0u64;
    for session in sessions {
        let manifest = session.manifest;
        if session.manifest_bytes.len() > audit_session::MAX_AUDIT_SESSION_MANIFEST_BYTES {
            return Err("case session manifest exceeds its byte limit".to_owned());
        }
        total_bytes = total_bytes
            .checked_add(session.manifest_bytes.len() as u64)
            .ok_or_else(|| "case session input byte count overflow".to_owned())?;
        for artifact in session.artifacts {
            if artifact.bytes.len() as u64 > audit_session::MAX_SESSION_ARTIFACT_BYTES {
                return Err("case session artifact exceeds its byte limit".to_owned());
            }
            total_bytes = total_bytes
                .checked_add(artifact.bytes.len() as u64)
                .ok_or_else(|| "case session input byte count overflow".to_owned())?;
        }
        if total_bytes > MAX_CASE_RESOLUTION_INPUT_BYTES {
            return Err(format!(
                "case session input exceeds the {MAX_CASE_RESOLUTION_INPUT_BYTES}-byte aggregate limit"
            ));
        }
        verify_session_view(session)?;
        if by_id
            .insert(manifest.session_id.as_str(), session)
            .is_some()
        {
            return Err("verified sessions contain duplicate session IDs".to_owned());
        }
    }

    for identity in &case.sessions {
        let session = by_id
            .get(identity.session_id.as_str())
            .ok_or_else(|| "case references a session that was not supplied".to_owned())?;
        let manifest = session.manifest;
        if manifest.session_id != identity.session_id
            || manifest.schema_version != identity.manifest_schema_version
            || platform_from_manifest(&manifest.platform)? != identity.platform
            || crate::fingerprint::sha256_hex(session.manifest_bytes) != identity.manifest_sha256
        {
            return Err("verified session does not match the case manifest binding".to_owned());
        }
    }

    let mut selected_root_ordinals = HashMap::<String, HashSet<usize>>::new();
    for locator in case.entries.iter().flat_map(|entry| entry.evidence.iter()) {
        if let CaseEvidenceLocator::SelectedRootEntry {
            session_id,
            entry_ordinal,
            ..
        } = locator
        {
            let ordinal = usize::try_from(*entry_ordinal).map_err(|_| {
                "selected-root entry ordinal is outside the supported range".to_owned()
            })?;
            selected_root_ordinals
                .entry(session_id.clone())
                .or_default()
                .insert(ordinal);
        }
    }

    let mut facts = Vec::new();
    let mut fact_indexes = HashMap::<CaseEvidenceLocator, usize>::new();
    let mut source_reviews = HashMap::<(String, SourceRole), ArtifactReview>::new();
    let mut parsed_artifacts = HashMap::<(String, ArtifactKind), ParsedArtifact>::new();
    let mut entries = Vec::with_capacity(case.entries.len());
    let mut resolved_fact_bytes = 0usize;

    for entry in &case.entries {
        let mut evidence_fact_indexes = Vec::with_capacity(entry.evidence.len());
        for locator in &entry.evidence {
            if let Some(index) = fact_indexes.get(locator) {
                evidence_fact_indexes.push(*index);
                continue;
            }
            let session = by_id
                .get(locator_session_id(locator))
                .ok_or_else(|| "evidence locator session was not supplied".to_owned())?;
            let (role, artifact_kind) = locator_contract(locator);
            let source = unique_source(session.manifest, role)?;
            let artifact_ref = unique_artifact_ref(source, artifact_kind)?;
            let artifact = unique_verified_artifact(session, artifact_kind, &artifact_ref.path)?;
            if locator_artifact_sha256(locator) != artifact_ref.sha256 {
                return Err(
                    "evidence locator artifact digest does not match the manifest".to_owned(),
                );
            }
            let cache_key = (session.manifest.session_id.clone(), artifact_kind);
            if !parsed_artifacts.contains_key(&cache_key) {
                let root_ordinals = selected_root_ordinals
                    .get(&session.manifest.session_id)
                    .map(|ordinals| ordinals.iter().copied().collect::<Vec<_>>())
                    .unwrap_or_default();
                let parsed =
                    parse_artifact(locator, source, artifact_ref, artifact, &root_ordinals)?;
                parsed_artifacts.insert(cache_key.clone(), parsed);
            }
            let parsed = parsed_artifacts
                .get(&cache_key)
                .ok_or_else(|| "verified artifact parser did not retain its result".to_owned())?;
            let review_key = (session.manifest.session_id.clone(), role);
            source_reviews
                .entry(review_key)
                .or_insert_with(|| artifact_review(parsed));
            let fact = resolve_locator(locator, parsed)?;
            let fact_bytes = serde_json::to_vec(&fact)
                .map_err(|_| "could not size resolved evidence fact".to_owned())?
                .len();
            resolved_fact_bytes = resolved_fact_bytes
                .checked_add(fact_bytes)
                .ok_or_else(|| "resolved evidence byte count overflow".to_owned())?;
            if resolved_fact_bytes > MAX_CASE_RESOLVED_FACT_BYTES {
                return Err(format!(
                    "resolved evidence exceeds the {MAX_CASE_RESOLVED_FACT_BYTES}-byte aggregate limit"
                ));
            }
            let index = facts.len();
            facts.push(ResolvedEvidenceFact {
                locator: locator.clone(),
                artifact_path: artifact_ref.path.clone(),
                fact,
            });
            fact_indexes.insert(locator.clone(), index);
            evidence_fact_indexes.push(index);
        }
        entries.push(ResolvedCaseEntry {
            id: entry.id.clone(),
            kind: entry.kind,
            authorship: entry.authorship.clone(),
            text: entry.text.clone(),
            severity: entry.severity,
            confidence: entry.confidence,
            evidence_fact_indexes,
        });
    }

    let mut resolved_sessions = Vec::with_capacity(case.sessions.len());
    for identity in &case.sessions {
        let session = by_id[identity.session_id.as_str()];
        let manifest = session.manifest;
        let sources = manifest
            .sources
            .iter()
            .map(|source| ResolvedSource {
                role: source.role,
                status: source.status,
                diagnostic_codes: source.diagnostic_codes.clone(),
                artifact_review: source_reviews
                    .get(&(manifest.session_id.clone(), source.role))
                    .cloned(),
            })
            .collect();
        resolved_sessions.push(ResolvedSession {
            session_id: manifest.session_id.clone(),
            platform: manifest.platform.clone(),
            manifest_schema_version: manifest.schema_version,
            manifest_sha256: crate::fingerprint::sha256_hex(session.manifest_bytes),
            status: manifest.status,
            sources,
        });
    }

    Ok(ResolvedCase {
        schema: "sideeffect.resolved_investigation_case",
        schema_version: 1,
        disclosure_note: "Evidence values may be sensitive and untrusted. Hash checks establish consistency with the supplied manifest, not producer authenticity or capture completeness. Escape values when rendering and review before sharing.",
        case_id: case.case_id.clone(),
        title: case.title.clone(),
        facts,
        entries,
        sessions: resolved_sessions,
    })
}

fn verify_session_view(session: &VerifiedSessionView<'_>) -> Result<(), String> {
    let parsed = audit_session::parse_manifest(session.manifest_bytes)
        .map_err(|error| format!("invalid verified session manifest: {error:?}"))?;
    if &parsed != session.manifest {
        return Err("verified session manifest object does not match its bytes".to_owned());
    }
    let expected_count = session
        .manifest
        .sources
        .iter()
        .map(|source| source.artifacts.len())
        .sum::<usize>();
    if session.artifacts.len() != expected_count {
        return Err("verified session artifact set does not match its manifest".to_owned());
    }
    let mut seen = HashSet::with_capacity(expected_count);
    for source in &session.manifest.sources {
        for reference in &source.artifacts {
            if !seen.insert((reference.kind, reference.path.as_str())) {
                return Err("verified session manifest contains duplicate artifacts".to_owned());
            }
            let matches = session
                .artifacts
                .iter()
                .filter(|artifact| {
                    artifact.kind == reference.kind && artifact.path == reference.path
                })
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(
                    "verified session artifact reference is missing or ambiguous".to_owned(),
                );
            }
            verify_artifact_bytes(reference, matches[0])?;
        }
    }
    Ok(())
}

fn verify_artifact_bytes(
    reference: &audit_session::SessionArtifactRef,
    artifact: &VerifiedArtifactView<'_>,
) -> Result<(), String> {
    if artifact.kind != reference.kind
        || artifact.path != reference.path
        || artifact.bytes.len() as u64 != reference.byte_length
        || crate::fingerprint::sha256_hex(artifact.bytes) != reference.sha256
    {
        return Err("verified artifact bytes do not match their manifest reference".to_owned());
    }
    Ok(())
}

fn platform_from_manifest(platform: &str) -> Result<CasePlatform, String> {
    match platform {
        "linux" => Ok(CasePlatform::Linux),
        "windows" => Ok(CasePlatform::Windows),
        _ => Err("verified session platform is unsupported for case resolution".to_owned()),
    }
}

fn locator_session_id(locator: &CaseEvidenceLocator) -> &str {
    match locator {
        CaseEvidenceLocator::LinuxTraceRecord { session_id, .. }
        | CaseEvidenceLocator::WindowsEtwRecord { session_id, .. }
        | CaseEvidenceLocator::SelectedRootEntry { session_id, .. } => session_id,
    }
}

fn locator_contract(locator: &CaseEvidenceLocator) -> (SourceRole, ArtifactKind) {
    match locator {
        CaseEvidenceLocator::LinuxTraceRecord { .. } => {
            (SourceRole::Runtime, ArtifactKind::RuntimeTrace)
        }
        CaseEvidenceLocator::WindowsEtwRecord { .. } => {
            (SourceRole::Runtime, ArtifactKind::WindowsRuntimeCapture)
        }
        CaseEvidenceLocator::SelectedRootEntry { .. } => {
            (SourceRole::SelectedRoot, ArtifactKind::SelectedRoot)
        }
    }
}

fn unique_source(
    manifest: &AuditSessionManifest,
    role: SourceRole,
) -> Result<&AuditSessionSource, String> {
    let mut matches = manifest.sources.iter().filter(|source| source.role == role);
    let source = matches
        .next()
        .ok_or_else(|| format!("verified session has no {role:?} source"))?;
    if matches.next().is_some() {
        return Err(format!("verified session has duplicate {role:?} sources"));
    }
    Ok(source)
}

fn unique_artifact_ref(
    source: &AuditSessionSource,
    kind: ArtifactKind,
) -> Result<&audit_session::SessionArtifactRef, String> {
    let mut matches = source
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == kind);
    let reference = matches
        .next()
        .ok_or_else(|| format!("source has no {kind:?} artifact"))?;
    if matches.next().is_some() {
        return Err(format!("source has duplicate {kind:?} artifacts"));
    }
    Ok(reference)
}

fn unique_verified_artifact<'a>(
    session: &VerifiedSessionView<'a>,
    kind: ArtifactKind,
    path: &str,
) -> Result<&'a VerifiedArtifactView<'a>, String> {
    let mut matches = session
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == kind && artifact.path == path);
    let artifact = matches
        .next()
        .ok_or_else(|| format!("verified session is missing artifact {path}"))?;
    if matches.next().is_some() {
        return Err(format!(
            "verified session contains duplicate artifact {path}"
        ));
    }
    Ok(artifact)
}

fn parse_artifact(
    locator: &CaseEvidenceLocator,
    source: &AuditSessionSource,
    artifact_ref: &audit_session::SessionArtifactRef,
    artifact: &VerifiedArtifactView<'_>,
    selected_root_ordinals: &[usize],
) -> Result<ParsedArtifact, String> {
    if locator_artifact_sha256(locator) != artifact_ref.sha256 {
        return Err("evidence locator artifact digest does not match the manifest".to_owned());
    }
    match locator {
        CaseEvidenceLocator::LinuxTraceRecord { .. } => {
            if source.platform != "linux"
                || artifact_ref.path != "trace.strace"
                || artifact_ref.schema != "strace_text"
                || artifact_ref.schema_version != 1
            {
                return Err("Linux trace locator source contract mismatch".to_owned());
            }
            let document = crate::trace::strace::parse_trace_bytes(
                artifact.bytes,
                crate::limits::ParseLimits::default(),
            )
            .map_err(|error| format!("verified trace artifact could not be parsed: {error}"))?;
            Ok(ParsedArtifact::LinuxTrace(document))
        }
        CaseEvidenceLocator::WindowsEtwRecord {
            capture_sha256,
            record_ordinal,
            json_pointer,
            raw_payload_sha256,
            ..
        } => {
            if source.platform != "windows"
                || artifact_ref.path != "runtime.windows.json"
                || artifact_ref.schema != crate::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA
                || artifact_ref.schema_version
                    != crate::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION
            {
                return Err("Windows ETW locator source contract mismatch".to_owned());
            }
            let capture = crate::windows_runtime::inspect_windows_runtime_bytes(artifact.bytes)
                .map_err(|_| "verified ETW artifact could not be validated".to_owned())?;
            let _ = (
                capture_sha256,
                record_ordinal,
                json_pointer,
                raw_payload_sha256,
            );
            Ok(ParsedArtifact::WindowsEtw(capture))
        }
        CaseEvidenceLocator::SelectedRootEntry { .. } => {
            if artifact_ref.path != "root-snapshot.json"
                || artifact_ref.schema != "sideeffect.selected_root_inventory"
                || !matches!(artifact_ref.schema_version, 1 | 2)
            {
                return Err("selected-root locator source contract mismatch".to_owned());
            }
            let result = crate::query::query_verified_selected_root_entries_artifact(
                crate::query::SelectedRootQueryInput {
                    platform: &source.platform,
                    source_status: source.status,
                    scope: Some(source.scope.clone()),
                    started_at_unix_ms: Some(source.started_at_unix_ms),
                    ended_at_unix_ms: Some(source.ended_at_unix_ms),
                    collector: source.collector.clone(),
                    diagnostic_codes: source.diagnostic_codes.clone(),
                    artifact: Some(artifact_ref),
                    bytes: Some(artifact.bytes),
                },
                selected_root_ordinals,
            )?;
            Ok(ParsedArtifact::SelectedRoot(result))
        }
    }
}

fn resolve_locator(
    locator: &CaseEvidenceLocator,
    parsed: &ParsedArtifact,
) -> Result<ResolvedEvidence, String> {
    match (locator, parsed) {
        (
            CaseEvidenceLocator::LinuxTraceRecord {
                line_number,
                byte_offset,
                byte_length,
                ..
            },
            ParsedArtifact::LinuxTrace(document),
        ) => {
            let record = document
                .records
                .iter()
                .find(|record| {
                    record.evidence.line_number == *line_number
                        && record.evidence.byte_offset == *byte_offset
                        && record.evidence.byte_length == *byte_length
                })
                .ok_or_else(|| "Linux trace locator does not match a source record".to_owned())?
                .clone();
            Ok(ResolvedEvidence::LinuxTraceRecord {
                parse_status: document.parse_status,
                record,
            })
        }
        (
            CaseEvidenceLocator::WindowsEtwRecord {
                capture_sha256,
                record_ordinal,
                json_pointer,
                raw_payload_sha256,
                ..
            },
            ParsedArtifact::WindowsEtw(capture),
        ) => {
            if &capture.document_sha256 != capture_sha256 {
                return Err(
                    "ETW locator capture digest does not match the capture document".to_owned(),
                );
            }
            let index = usize::try_from(*record_ordinal - 1)
                .map_err(|_| "ETW locator ordinal is outside the supported range".to_owned())?;
            if json_pointer != &format!("/events/{index}") {
                return Err("ETW locator JSON pointer does not match its ordinal".to_owned());
            }
            let record = capture
                .events
                .get(index)
                .filter(|record| record.record_ordinal == *record_ordinal)
                .ok_or_else(|| {
                    "ETW locator ordinal does not identify a capture event".to_owned()
                })?;
            let raw_payload = decode_lower_hex(&record.raw_payload_hex)?;
            if crate::fingerprint::sha256_hex(&raw_payload) != *raw_payload_sha256 {
                return Err("ETW locator payload digest does not match the raw payload".to_owned());
            }
            Ok(ResolvedEvidence::WindowsEtwRecord {
                collection_status: capture.collection_status,
                capture_completeness: capture.capture_completeness.clone(),
                event_loss: capture.event_loss.clone(),
                record: record.clone(),
            })
        }
        (
            CaseEvidenceLocator::SelectedRootEntry { entry_ordinal, .. },
            ParsedArtifact::SelectedRoot(result),
        ) => {
            let entry = result
                .entries
                .iter()
                .find(|entry| entry.ordinal as u64 == *entry_ordinal)
                .ok_or_else(|| "selected-root locator does not match a validated entry".to_owned())?
                .clone();
            let inventory_status = result
                .inventory_status
                .clone()
                .ok_or_else(|| "selected-root artifact status is unavailable".to_owned())?;
            Ok(ResolvedEvidence::SelectedRootEntry {
                inventory_status,
                entry,
            })
        }
        _ => Err("evidence locator does not match its parsed artifact kind".to_owned()),
    }
}

fn artifact_review(parsed: &ParsedArtifact) -> ArtifactReview {
    match parsed {
        ParsedArtifact::LinuxTrace(document) => ArtifactReview::LinuxTrace {
            parse_status: document.parse_status,
            diagnostics: document.diagnostics.clone(),
        },
        ParsedArtifact::WindowsEtw(capture) => ArtifactReview::WindowsEtw {
            collection_status: capture.collection_status,
            capture_completeness: capture.capture_completeness.clone(),
            stop_reason: capture.stop_reason,
            event_loss: capture.event_loss.clone(),
            diagnostics: capture.diagnostics.clone(),
        },
        ParsedArtifact::SelectedRoot(result) => ArtifactReview::SelectedRoot {
            inventory_status: result
                .inventory_status
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
            diagnostics: result.inventory_diagnostics.clone(),
        },
    }
}

fn locator_artifact_sha256(locator: &CaseEvidenceLocator) -> &str {
    match locator {
        CaseEvidenceLocator::LinuxTraceRecord {
            artifact_sha256, ..
        }
        | CaseEvidenceLocator::WindowsEtwRecord {
            artifact_sha256, ..
        }
        | CaseEvidenceLocator::SelectedRootEntry {
            artifact_sha256, ..
        } => artifact_sha256,
    }
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("ETW raw payload is not bounded lowercase hexadecimal".to_owned());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_digit(pair[0]).ok_or_else(|| "invalid ETW payload hex".to_owned())?;
        let low = hex_digit(pair[1]).ok_or_else(|| "invalid ETW payload hex".to_owned())?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
