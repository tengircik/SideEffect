//! Bounded, read-only exact filters over the versioned common event envelope.
//!
//! Query results preserve source status, diagnostics, event evidence, and the
//! source-local process links needed to inspect the selected rows. This first
//! contract intentionally does not claim path, endpoint, or time filtering.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::audit_session::{
    AuditSessionManifest, AuditSessionSource, CollectorIdentity, LossMetadata, SessionArtifactRef,
    SessionStatus, SourceStatus,
};
use crate::event::{
    CommonEvent, CommonEventEnvelope, EventDiagnostic, EventProcessLink, OperationSemantics,
    ProcessObservation, ProcessRelationship, SourceCompleteness, SourceDescriptor, SourceState,
};
use crate::model::SyscallOutcome;

pub const QUERY_SCHEMA: &str = "sideeffect.event_query";
pub const QUERY_SCHEMA_VERSION: u32 = 1;
pub const QUERY_RESULT_SCHEMA: &str = "sideeffect.event_query_result";
pub const QUERY_RESULT_SCHEMA_VERSION: u32 = 1;
pub const SESSION_QUERY_RESULT_SCHEMA: &str = "sideeffect.session_event_query_result";
pub const SESSION_QUERY_RESULT_SCHEMA_VERSION: u32 = 1;
pub const MULTI_SESSION_QUERY_RESULT_SCHEMA: &str = "sideeffect.multi_session_event_query_result";
pub const MULTI_SESSION_QUERY_RESULT_SCHEMA_VERSION: u32 = 1;
pub const MAX_QUERY_SESSIONS: usize = 16;
pub const MAX_MULTI_SESSION_RESULTS: usize = MAX_QUERY_RESULTS;
pub const MAX_MULTI_SESSION_INPUT_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_MULTI_SESSION_ELAPSED: Duration = Duration::from_secs(10);
pub const MAX_QUERY_BYTES: usize = 16 * 1024;
pub const MAX_QUERY_RESULTS: usize = 5_000;
pub const MAX_QUERY_ELAPSED: Duration = Duration::from_secs(2);
pub const MAX_QUERY_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_FILTER_TEXT_BYTES: usize = 128;

#[derive(Hash, Eq, PartialEq)]
enum EvidenceKey {
    Trace(u64, u64, u64),
    Windows(u64, String, String),
}

fn evidence_key(evidence: &crate::event::EvidenceReference) -> EvidenceKey {
    match evidence {
        crate::event::EvidenceReference::RawTraceRecord {
            line_number,
            byte_offset,
            byte_length,
        } => EvidenceKey::Trace(*line_number, *byte_offset, *byte_length),
        crate::event::EvidenceReference::WindowsEtwRecord {
            record_ordinal,
            json_pointer,
            raw_payload_sha256,
        } => EvidenceKey::Windows(
            *record_ordinal,
            json_pointer.clone(),
            raw_payload_sha256.clone(),
        ),
    }
}

fn check_elapsed(started: Instant) -> Result<(), String> {
    if started.elapsed() > MAX_QUERY_ELAPSED {
        Err(format!(
            "query exceeded the {} ms execution limit",
            MAX_QUERY_ELAPSED.as_millis()
        ))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    SyscallAttempt,
    NativeObservation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeFilter {
    Success,
    Failure,
    InProgress,
    Unknown,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventQueryFilters {
    /// Exact normalized event-kind match, such as `openat` or `file_io`.
    pub event_kind: Option<String>,
    pub operation_kind: Option<OperationKind>,
    /// Matches only syscall attempts with the corresponding normalized result.
    pub outcome: Option<OutcomeFilter>,
    /// Source-local ProcessObservation ID, not an OS PID or cross-capture ID.
    pub process_observation_id: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventQuery {
    pub schema: String,
    pub schema_version: u32,
    #[serde(default)]
    pub filters: EventQueryFilters,
    /// Rejects the query if more rows match; results are never silently truncated.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    MAX_QUERY_RESULTS as u32
}

impl EventQuery {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_QUERY_BYTES {
            return Err(format!(
                "query input exceeds the {MAX_QUERY_BYTES}-byte limit"
            ));
        }
        let query: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid event query JSON: {error}"))?;
        query.validate()?;
        Ok(query)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != QUERY_SCHEMA || self.schema_version != QUERY_SCHEMA_VERSION {
            return Err(format!(
                "query schema must be {QUERY_SCHEMA} version {QUERY_SCHEMA_VERSION}"
            ));
        }
        if self.limit == 0 || self.limit as usize > MAX_QUERY_RESULTS {
            return Err(format!(
                "query limit must be between 1 and {MAX_QUERY_RESULTS}"
            ));
        }
        if let Some(kind) = &self.filters.event_kind {
            if kind.is_empty()
                || kind.len() > MAX_FILTER_TEXT_BYTES
                || kind.chars().any(char::is_control)
            {
                return Err(format!(
                    "event_kind must contain 1..{MAX_FILTER_TEXT_BYTES} printable UTF-8 bytes"
                ));
            }
        }
        if self.filters.process_observation_id == Some(0) {
            return Err("process_observation_id must be a positive source-local ID".to_owned());
        }
        if self.filters.outcome.is_some()
            && self.filters.operation_kind == Some(OperationKind::NativeObservation)
        {
            return Err("outcome cannot be combined with native_observation".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EventQueryResult {
    pub schema: &'static str,
    pub schema_version: u32,
    pub source: SourceDescriptor,
    /// Full input status is retained even when filters return no rows.
    pub source_state: SourceState,
    pub filter: EventQueryFilters,
    pub matched_count: usize,
    pub events: Vec<CommonEvent>,
    pub event_process_links: Vec<EventProcessLink>,
    pub process_observations: Vec<ProcessObservation>,
    pub process_relationships: Vec<ProcessRelationship>,
    /// Diagnostics for the full source input, not merely the returned rows.
    pub diagnostics: Vec<EventDiagnostic>,
}

/// One session-scoped runtime query. Manifest status and event parsing status
/// remain separate, and the artifact references bind event locators to bytes.
#[derive(Clone, Debug, Serialize)]
pub struct SessionEventQueryResult {
    pub schema: &'static str,
    pub schema_version: u32,
    pub session: SessionQueryIdentity,
    pub runtime_source: SessionRuntimeSource,
    pub capture: SessionCaptureStatus,
    pub event_query_result: EventQueryResult,
}

/// Results for an explicit set of verified sessions. Every event stays nested
/// under its own session identity because source-local ordinals and IDs reset.
#[derive(Clone, Debug, Serialize)]
pub struct MultiSessionEventQueryResult {
    pub schema: &'static str,
    pub schema_version: u32,
    pub session_count: usize,
    pub matched_count: usize,
    pub complete: bool,
    pub sessions: Vec<SessionEventQueryResult>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionQueryIdentity {
    pub session_id: String,
    pub manifest_schema_version: u32,
    pub platform: String,
    pub status: SessionStatus,
    pub started_at_unix_ms: u128,
    pub ended_at_unix_ms: u128,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionRuntimeSource {
    pub role: crate::audit_session::SourceRole,
    pub platform: String,
    pub scope: String,
    pub started_at_unix_ms: u128,
    pub ended_at_unix_ms: u128,
    pub status: SourceStatus,
    pub collector: Option<CollectorIdentity>,
    pub loss: Option<LossMetadata>,
    pub diagnostic_codes: Vec<String>,
    pub artifacts: Vec<SessionArtifactRef>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionCaptureStatus {
    /// The producer's bounded completeness statement; runtime sessions usually say unknown.
    pub completeness: String,
    /// Windows collection status is distinct from completeness. Linux has no counterpart.
    pub collection_status: Option<String>,
    pub stop_reason: Option<String>,
}

pub fn session_query_result(
    manifest: &AuditSessionManifest,
    source: &AuditSessionSource,
    capture: SessionCaptureStatus,
    event_query_result: EventQueryResult,
) -> SessionEventQueryResult {
    SessionEventQueryResult {
        schema: SESSION_QUERY_RESULT_SCHEMA,
        schema_version: SESSION_QUERY_RESULT_SCHEMA_VERSION,
        session: SessionQueryIdentity {
            session_id: manifest.session_id.clone(),
            manifest_schema_version: manifest.schema_version,
            platform: manifest.platform.clone(),
            status: manifest.status,
            started_at_unix_ms: manifest.started_at_unix_ms,
            ended_at_unix_ms: manifest.ended_at_unix_ms,
        },
        runtime_source: SessionRuntimeSource {
            role: source.role,
            platform: source.platform.clone(),
            scope: source.scope.clone(),
            started_at_unix_ms: source.started_at_unix_ms,
            ended_at_unix_ms: source.ended_at_unix_ms,
            status: source.status,
            collector: source.collector.clone(),
            loss: source.loss.clone(),
            diagnostic_codes: source.diagnostic_codes.clone(),
            artifacts: source.artifacts.clone(),
        },
        capture,
        event_query_result,
    }
}

pub fn session_source_is_complete(result: &SessionEventQueryResult) -> bool {
    result.session.status == SessionStatus::Complete
        && result.runtime_source.status == SourceStatus::Complete
        && result.capture.completeness == "complete"
        && result
            .capture
            .collection_status
            .as_deref()
            .is_none_or(|status| status == "complete")
        && source_is_complete(&result.event_query_result.source_state)
}

pub fn multi_session_query_result(
    sessions: Vec<SessionEventQueryResult>,
) -> Result<MultiSessionEventQueryResult, String> {
    use std::collections::HashSet;

    if !(2..=MAX_QUERY_SESSIONS).contains(&sessions.len()) {
        return Err(format!(
            "multi-session query result requires 2..={MAX_QUERY_SESSIONS} sessions"
        ));
    }
    let mut session_ids = HashSet::with_capacity(sessions.len());
    let mut matched_count = 0usize;
    for session in &sessions {
        if !session_ids.insert(session.session.session_id.as_str()) {
            return Err("multi-session query result contains duplicate session IDs".to_owned());
        }
        matched_count = matched_count
            .checked_add(session.event_query_result.matched_count)
            .ok_or_else(|| "multi-session query result count overflow".to_owned())?;
        if matched_count > MAX_MULTI_SESSION_RESULTS {
            return Err(format!(
                "multi-session query result exceeds the {MAX_MULTI_SESSION_RESULTS}-row limit"
            ));
        }
    }
    let complete = sessions.iter().all(session_source_is_complete);
    Ok(MultiSessionEventQueryResult {
        schema: MULTI_SESSION_QUERY_RESULT_SCHEMA,
        schema_version: MULTI_SESSION_QUERY_RESULT_SCHEMA_VERSION,
        session_count: sessions.len(),
        matched_count,
        complete,
        sessions,
    })
}

pub fn execute_query(
    envelope: &CommonEventEnvelope,
    query: &EventQuery,
) -> Result<EventQueryResult, String> {
    query.validate()?;
    if envelope.schema != crate::event::COMMON_EVENT_SCHEMA
        || envelope.schema_version != crate::event::COMMON_EVENT_SCHEMA_VERSION
    {
        return Err("query input has an unsupported common event envelope".to_owned());
    }

    let started = Instant::now();
    let process_evidence = if let Some(selected_id) = query.filters.process_observation_id {
        let mut evidence = HashSet::new();
        for link in &envelope.event_process_links {
            check_elapsed(started)?;
            if link.process_observation_id == Some(selected_id) {
                evidence.insert(evidence_key(&link.event));
            }
        }
        Some(evidence)
    } else {
        None
    };
    let mut matched = Vec::new();
    for event in &envelope.events {
        check_elapsed(started)?;
        if matches_event(event, process_evidence.as_ref(), &query.filters) {
            if matched.len() >= query.limit as usize {
                return Err(format!(
                    "query matched more than its {}-row limit; narrow the filters",
                    query.limit
                ));
            }
            matched.push(event.clone());
        }
    }

    let evidence_keys = matched
        .iter()
        .map(|event| evidence_key(&event.evidence))
        .collect::<HashSet<_>>();
    let mut links = Vec::new();
    for link in &envelope.event_process_links {
        check_elapsed(started)?;
        if evidence_keys.contains(&evidence_key(&link.event))
            && query
                .filters
                .process_observation_id
                .is_none_or(|selected| link.process_observation_id == Some(selected))
        {
            links.push(link.clone());
        }
    }
    let included_ids = links
        .iter()
        .filter_map(|link| link.process_observation_id)
        .collect::<HashSet<_>>();
    let mut process_observations = Vec::new();
    for observation in &envelope.process_observations {
        check_elapsed(started)?;
        if included_ids.contains(&observation.source_local_id) {
            process_observations.push(observation.clone());
        }
    }
    let mut process_relationships = Vec::new();
    for relation in &envelope.process_relationships {
        check_elapsed(started)?;
        if included_ids.contains(&relation.to_observation_id)
            || relation
                .from_observation_id
                .is_some_and(|id| included_ids.contains(&id))
        {
            process_relationships.push(relation.clone());
        }
    }
    let matched_count = matched.len();
    Ok(EventQueryResult {
        schema: QUERY_RESULT_SCHEMA,
        schema_version: QUERY_RESULT_SCHEMA_VERSION,
        source: envelope.source.clone(),
        source_state: envelope.source_state.clone(),
        filter: query.filters.clone(),
        matched_count,
        events: matched,
        event_process_links: links,
        process_observations,
        process_relationships,
        diagnostics: envelope.diagnostics.clone(),
    })
}

fn matches_event(
    event: &CommonEvent,
    process_evidence: Option<&HashSet<EvidenceKey>>,
    filters: &EventQueryFilters,
) -> bool {
    if filters
        .event_kind
        .as_ref()
        .is_some_and(|kind| event.event_kind != *kind)
    {
        return false;
    }
    if filters.operation_kind.is_some_and(|kind| {
        !matches!(
            (kind, &event.operation),
            (
                OperationKind::SyscallAttempt,
                OperationSemantics::SyscallAttempt { .. }
            ) | (
                OperationKind::NativeObservation,
                OperationSemantics::NativeObservation
            )
        )
    }) {
        return false;
    }
    if let Some(outcome) = filters.outcome {
        let OperationSemantics::SyscallAttempt { result } = &event.operation else {
            return false;
        };
        if !matches!(
            (outcome, result),
            (OutcomeFilter::Success, Some(SyscallOutcome::Success))
                | (OutcomeFilter::Failure, Some(SyscallOutcome::Failure))
                | (OutcomeFilter::InProgress, Some(SyscallOutcome::InProgress))
                | (OutcomeFilter::Unknown, Some(SyscallOutcome::Unknown) | None)
        ) {
            return false;
        }
    }
    process_evidence.is_none_or(|evidence| evidence.contains(&evidence_key(&event.evidence)))
}

/// Helps callers retain the source's partial/unknown exit status.
pub fn source_is_complete(state: &SourceState) -> bool {
    state.completeness == SourceCompleteness::Complete
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event;
    use crate::limits::ParseLimits;
    use crate::trace::strace::parse_trace_bytes;

    fn linux_envelope(bytes: &[u8]) -> CommonEventEnvelope {
        let trace = parse_trace_bytes(bytes, ParseLimits::default()).unwrap();
        event::from_linux_strace(&trace, bytes, "synthetic-query-fixture")
    }

    fn query(filters: EventQueryFilters, limit: u32) -> EventQuery {
        EventQuery {
            schema: QUERY_SCHEMA.to_owned(),
            schema_version: QUERY_SCHEMA_VERSION,
            filters,
            limit,
        }
    }

    fn complete_session_query_result(
        completeness: &str,
        collection_status: Option<&str>,
    ) -> SessionEventQueryResult {
        let envelope = linux_envelope(b"123 1700000000.1 close(1) = 0\n");
        let event_query_result =
            execute_query(&envelope, &query(EventQueryFilters::default(), 5)).unwrap();
        SessionEventQueryResult {
            schema: SESSION_QUERY_RESULT_SCHEMA,
            schema_version: SESSION_QUERY_RESULT_SCHEMA_VERSION,
            session: SessionQueryIdentity {
                session_id: "synthetic-session".to_owned(),
                manifest_schema_version: 7,
                platform: "linux".to_owned(),
                status: crate::audit_session::SessionStatus::Complete,
                started_at_unix_ms: 1,
                ended_at_unix_ms: 2,
            },
            runtime_source: SessionRuntimeSource {
                role: crate::audit_session::SourceRole::Runtime,
                platform: "linux".to_owned(),
                scope: "synthetic fixture".to_owned(),
                started_at_unix_ms: 1,
                ended_at_unix_ms: 2,
                status: crate::audit_session::SourceStatus::Complete,
                collector: None,
                loss: None,
                diagnostic_codes: Vec::new(),
                artifacts: Vec::new(),
            },
            capture: SessionCaptureStatus {
                completeness: completeness.to_owned(),
                collection_status: collection_status.map(str::to_owned),
                stop_reason: None,
            },
            event_query_result,
        }
    }

    #[test]
    fn session_query_exit_gate_requires_complete_capture_statuses() {
        assert!(!session_source_is_complete(&complete_session_query_result(
            "unknown", None
        )));
        assert!(!session_source_is_complete(&complete_session_query_result(
            "complete",
            Some("partial")
        )));
        assert!(session_source_is_complete(&complete_session_query_result(
            "complete", None
        )));
        assert!(session_source_is_complete(&complete_session_query_result(
            "complete",
            Some("complete")
        )));
    }

    #[test]
    fn multi_session_summary_aggregates_counts_and_never_promotes_partial_evidence() {
        let complete = complete_session_query_result("complete", None);
        let mut partial = complete_session_query_result("unknown", None);
        partial.session.session_id = "other-session".to_owned();
        partial.event_query_result.matched_count = 2;
        let result = multi_session_query_result(vec![complete, partial]).unwrap();
        assert_eq!(result.schema, MULTI_SESSION_QUERY_RESULT_SCHEMA);
        assert_eq!(result.session_count, 2);
        assert_eq!(result.matched_count, 3);
        assert!(!result.complete);
        assert_eq!(result.sessions[0].session.session_id, "synthetic-session");
        assert_eq!(result.sessions[1].session.session_id, "other-session");
    }

    #[test]
    fn multi_session_summary_rejects_duplicate_ids_and_out_of_range_counts() {
        let first = complete_session_query_result("complete", None);
        let second = complete_session_query_result("complete", None);
        assert!(multi_session_query_result(vec![first.clone()]).is_err());
        assert!(multi_session_query_result(vec![first.clone(), second]).is_err());
        let too_many =
            vec![complete_session_query_result("complete", None); MAX_QUERY_SESSIONS + 1];
        assert!(multi_session_query_result(too_many).is_err());
    }

    #[test]
    fn strict_query_contract_rejects_unknown_fields_and_unsupported_values() {
        assert!(EventQuery::from_json(
            br#"{"schema":"sideeffect.event_query","schema_version":1,"filters":{"path":"/tmp"}}"#
        )
        .is_err());
        assert!(
            EventQuery::from_json(
                br#"{"schema":"sideeffect.event_query","schema_version":1,"limit":5001}"#
            )
            .is_err()
        );
        assert!(EventQuery::from_json(&vec![b' '; MAX_QUERY_BYTES + 1]).is_err());
    }

    #[test]
    fn query_exact_filters_preserve_full_source_diagnostics_and_evidence() {
        let trace = b"1700000000.000001 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"127.0.0.1\")}, 16) = -1 ECONNREFUSED (Connection refused)\ninvalid row\n";
        let envelope = linux_envelope(trace);
        let result = execute_query(
            &envelope,
            &query(
                EventQueryFilters {
                    event_kind: Some("connect".to_owned()),
                    operation_kind: Some(OperationKind::SyscallAttempt),
                    outcome: Some(OutcomeFilter::Failure),
                    process_observation_id: None,
                },
                10,
            ),
        )
        .unwrap();
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].event_kind, "connect");
        assert_eq!(result.events[0].evidence, envelope.events[0].evidence);
        assert_eq!(
            result.source_state.completeness,
            SourceCompleteness::Partial
        );
        assert_eq!(result.diagnostics, envelope.diagnostics);
        assert!(
            result
                .source_state
                .diagnostics
                .contains(&"source_parse_partial".to_owned())
        );
    }

    #[test]
    fn overflow_is_an_error_and_never_silently_truncates_results() {
        let envelope =
            linux_envelope(b"123 1700000000.1 close(1) = 0\n123 1700000000.2 close(2) = 0\n");
        let error = execute_query(&envelope, &query(EventQueryFilters::default(), 1)).unwrap_err();
        assert!(error.contains("matched more than its 1-row limit"));
    }

    #[test]
    fn source_local_process_filter_keeps_exact_linked_observation() {
        let envelope = linux_envelope(b"123 1700000000.1 close(1) = 0\n");
        let result = execute_query(
            &envelope,
            &query(
                EventQueryFilters {
                    process_observation_id: Some(1),
                    ..EventQueryFilters::default()
                },
                5,
            ),
        )
        .unwrap();
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.event_process_links.len(), 1);
        assert_eq!(
            result.event_process_links[0].process_observation_id,
            Some(1)
        );
        assert_eq!(result.process_observations.len(), 1);
        assert_eq!(result.process_observations[0].source_local_id, 1);
    }

    #[test]
    fn synthetic_windows_normalized_event_uses_the_same_allowlisted_contract() {
        let mut envelope = linux_envelope(b"123 1700000000.1 close(1) = 0\n");
        envelope.source.platform = crate::event::SourcePlatform::Windows;
        envelope.source.schema = "sideeffect.windows_runtime_capture".to_owned();
        envelope.source.schema_version = 3;
        envelope.events[0].event_kind = "file_io".to_owned();
        envelope.events[0].operation = OperationSemantics::NativeObservation;
        envelope.events[0].evidence = crate::event::EvidenceReference::WindowsEtwRecord {
            record_ordinal: 7,
            json_pointer: "/events/6".to_owned(),
            raw_payload_sha256: "a".repeat(64),
        };
        envelope.event_process_links.clear();
        let result = execute_query(
            &envelope,
            &query(
                EventQueryFilters {
                    event_kind: Some("file_io".to_owned()),
                    operation_kind: Some(OperationKind::NativeObservation),
                    ..EventQueryFilters::default()
                },
                5,
            ),
        )
        .unwrap();
        assert_eq!(
            result.source.platform,
            crate::event::SourcePlatform::Windows
        );
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].evidence, envelope.events[0].evidence);
    }
}
