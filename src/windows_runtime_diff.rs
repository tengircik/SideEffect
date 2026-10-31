//! Bounded aggregate and event-level comparisons for validated Windows ETW captures.
//!
//! This module compares observed record counts by a fixed event category. It
//! never pairs individual ETW records or infers command attribution, absence,
//! causation, or capture completeness.

use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use crate::windows_runtime::{CollectionStatus, MAX_WINDOWS_RUNTIME_EVENTS, WindowsRuntimeCapture};

pub const WINDOWS_RUNTIME_DIFF_SUMMARY_SCHEMA: &str = "sideeffect.windows_runtime_diff_summary";
pub const WINDOWS_RUNTIME_DIFF_SUMMARY_SCHEMA_VERSION: u32 = 3;
const MAX_EVENT_DIFF_KEY_BYTES: usize = 128 * 1024 * 1024;
const MAX_EVENT_DIFF_ROWS: usize = MAX_WINDOWS_RUNTIME_EVENTS * 2;
const PROCESS_PROVIDER_GUID: &str = "3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c";
const PROCESS_TYPEGROUP1_SCHEMA: &str = "windows.kernel_process_typegroup1";
const FILE_IO_PROVIDER_GUID: &str = "90cbdc39-4a3e-11d1-84f4-0000f80464e3";
const TCP_IP_PROVIDER_GUID: &str = "9a280ac0-c8e0-11d1-84e2-00c04fb998a2";
const UDP_IP_PROVIDER_GUID: &str = "bf3a50c5-a9c9-4988-a005-2df0b7c80f80";
const DISK_IO_PROVIDER_GUID: &str = "3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonStatus {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRuntimeDiffSummary {
    pub schema: &'static str,
    pub schema_version: u32,
    pub algorithm: ComparisonAlgorithm,
    /// This describes processing of the two documents, not capture completeness.
    pub comparison_status: ComparisonStatus,
    pub capture_completeness: &'static str,
    pub before: CaptureSide,
    pub after: CaptureSide,
    pub representation_comparison: RepresentationComparison,
    pub categories: Vec<CategoryCountDelta>,
    /// Declares every source field omitted from exact event equality.
    pub normalization_ledger: Vec<NormalizationLedgerEntry>,
    /// Event-level differences. Exact records are multiset-compared; uncertain
    /// cross-capture identity is explicitly left unpaired or marked candidate.
    pub event_changes: Vec<EventDelta>,
    pub diagnostics: Vec<&'static str>,
    pub limitations: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RepresentationComparison {
    /// Equality of the validated, canonical capture representation fingerprints;
    /// this does not compare source JSON whitespace or authenticate a producer.
    pub same_validated_representation_fingerprint: bool,
    pub basis: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventDeltaStatus {
    Unchanged,
    CandidateChanged,
    ObservedOnlyBefore,
    ObservedOnlyAfter,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventDelta {
    pub status: EventDeltaStatus,
    pub confidence: &'static str,
    pub basis: &'static str,
    pub category: &'static str,
    pub before: Vec<EventEvidenceReference>,
    pub after: Vec<EventEvidenceReference>,
    /// Explains why a one-sided observation is not a removal or addition claim.
    pub diagnostic: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventEvidenceReference {
    pub capture_sha256: String,
    pub record_ordinal: u64,
    pub timestamp_qpc: i64,
    pub provider_guid: String,
    pub event_id: u16,
    pub event_version: u8,
    pub opcode: u8,
    pub event_kind: String,
    pub category: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct NormalizationLedgerEntry {
    pub field: &'static str,
    pub treatment: &'static str,
    pub reason: &'static str,
    pub source_values_retained_as: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ComparisonAlgorithm {
    pub id: &'static str,
    pub version: u32,
    pub basis: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct CaptureSide {
    pub document_sha256: String,
    pub producer_collection_status: CollectionStatus,
    pub capture_completeness: &'static str,
    pub observed_event_count: usize,
    pub event_loss: EventLossSummary,
    pub diagnostics_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventLossSummary {
    pub events_lost: u32,
    pub log_buffers_lost: u32,
    pub real_time_buffers_lost: u32,
    pub loss_statistics_available: bool,
    pub final_snapshot_available: bool,
    pub observation: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CategoryCountDelta {
    /// One of the fixed category identifiers documented by this schema.
    pub category: &'static str,
    pub before_count: usize,
    pub after_count: usize,
    /// `after_count - before_count`; this is a count delta, not an event match.
    pub observed_count_delta: i64,
    /// Ordinals in the before document; these are not ETW byte offsets.
    pub before_event_ordinals: Vec<u64>,
    /// Ordinals in the after document; these are not ETW byte offsets.
    pub after_event_ordinals: Vec<u64>,
}

/// Compare two already validated Windows runtime capture documents.
///
/// Category counts preserve the v1 aggregate contract. The v2 event view first
/// matches exact normalized record representations as multisets, excluding
/// only record ordinal and capture-local QPC timestamp. It then pairs a changed
/// row only when one supported identity key is unique in each complete input.
/// Missing records are never described as removals/additions; incomplete sides
/// instead produce explicitly one-sided observations with a diagnostic.
pub fn compare_windows_runtime_captures(
    before: &WindowsRuntimeCapture,
    after: &WindowsRuntimeCapture,
) -> Result<WindowsRuntimeDiffSummary, String> {
    validate_event_count(before, "before")?;
    validate_event_count(after, "after")?;

    let mut key_budget = MAX_EVENT_DIFF_KEY_BYTES;
    let before_index = index_capture(before, "before", &mut key_budget)?;
    let after_index = index_capture(after, "after", &mut key_budget)?;
    let mut categories = Vec::with_capacity(FIXED_CATEGORIES.len());
    for category in fixed_categories() {
        let before_event_ordinals = before_index
            .categories
            .get(category)
            .cloned()
            .unwrap_or_default();
        let after_event_ordinals = after_index
            .categories
            .get(category)
            .cloned()
            .unwrap_or_default();
        if before_event_ordinals.is_empty() && after_event_ordinals.is_empty() {
            continue;
        }
        let before_count = before_event_ordinals.len();
        let after_count = after_event_ordinals.len();
        let before_count_i64 = i64::try_from(before_count)
            .map_err(|_| "Windows runtime event count exceeds the supported range".to_owned())?;
        let after_count_i64 = i64::try_from(after_count)
            .map_err(|_| "Windows runtime event count exceeds the supported range".to_owned())?;
        categories.push(CategoryCountDelta {
            category,
            before_count,
            after_count,
            observed_count_delta: after_count_i64 - before_count_i64,
            before_event_ordinals,
            after_event_ordinals,
        });
    }

    let before_incomplete_reasons = capture_incomplete_reasons(before);
    let after_incomplete_reasons = capture_incomplete_reasons(after);
    let partial = !before_incomplete_reasons.is_empty() || !after_incomplete_reasons.is_empty();
    let mut diagnostics = Vec::new();
    if before.collection_status == CollectionStatus::Partial
        || after.collection_status == CollectionStatus::Partial
    {
        diagnostics.push("one_or_both_captures_report_partial_collection");
    }
    if before.event_loss.events_lost > 0
        || before.event_loss.log_buffers_lost > 0
        || before.event_loss.real_time_buffers_lost > 0
        || after.event_loss.events_lost > 0
        || after.event_loss.log_buffers_lost > 0
        || after.event_loss.real_time_buffers_lost > 0
    {
        diagnostics.push("one_or_both_captures_report_etw_event_loss");
    }
    if !before.event_loss.loss_statistics_available || !after.event_loss.loss_statistics_available {
        diagnostics.push("one_or_both_captures_lack_loss_statistics");
    }
    if !before.event_loss.final_snapshot_available || !after.event_loss.final_snapshot_available {
        diagnostics.push("one_or_both_captures_lack_a_final_loss_snapshot");
    }
    if !before.diagnostics.is_empty() || !after.diagnostics.is_empty() {
        diagnostics.push("one_or_both_captures_include_diagnostics");
    }

    let (event_changes, ambiguous_candidate_group_count) = compare_event_indices(
        before,
        after,
        &before_index,
        &after_index,
        !before_incomplete_reasons.is_empty(),
        !after_incomplete_reasons.is_empty(),
    )?;
    if ambiguous_candidate_group_count > 0 {
        diagnostics.push("ambiguous_candidate_identities_were_left_unpaired");
    }

    Ok(WindowsRuntimeDiffSummary {
        schema: WINDOWS_RUNTIME_DIFF_SUMMARY_SCHEMA,
        schema_version: WINDOWS_RUNTIME_DIFF_SUMMARY_SCHEMA_VERSION,
        algorithm: ComparisonAlgorithm {
            id: "windows_etw_exact_multiset_and_unique_candidate_diff",
            version: 2,
            basis: "fixed_category_counts_plus_exact_record_multiset_and_unique_identity_candidates",
        },
        comparison_status: if partial {
            ComparisonStatus::Partial
        } else {
            ComparisonStatus::Complete
        },
        capture_completeness: "unknown",
        before: capture_side(before),
        after: capture_side(after),
        representation_comparison: RepresentationComparison {
            same_validated_representation_fingerprint: before.document_sha256
                == after.document_sha256,
            basis: "sha256_of_canonical_validated_capture_representation",
        },
        categories,
        normalization_ledger: vec![
            NormalizationLedgerEntry {
                field: "record_ordinal",
                treatment: "excluded_from_exact_event_equality",
                reason: "record ordinals are source-local evidence locators and can differ between captures",
                source_values_retained_as: "before/after event references record_ordinal",
            },
            NormalizationLedgerEntry {
                field: "timestamp_qpc",
                treatment: "excluded_from_exact_event_equality",
                reason: "QPC ticks are capture-local timestamps and are not comparable across captures",
                source_values_retained_as: "before/after event references timestamp_qpc",
            },
        ],
        event_changes,
        diagnostics,
        limitations: vec![
            "The v1 fixed-category count and ordinal fields preserve their semantics; v2 additionally compares exact normalized event records as multisets.",
            "Exact event equality excludes only the capture-local record ordinal and QPC timestamp; provider, descriptor, header context, raw payload, and decode status/content remain part of identity.",
            "Candidate-changed rows use a unique same-file-operation/path or same-process-event/image-path identity and do not prove the same underlying execution.",
            "Ambiguous candidate identities are left unpaired; no event pair is inferred from category counts alone.",
            "One-sided observations are not removals or additions; partial collection, event loss, unavailable loss statistics, and capture diagnostics remain explicit.",
            "A difference does not establish that an operation was absent, completed, caused another event, or was attributable to the selected command.",
            "Producer collection statuses and loss evidence are preserved, but capture completeness remains unknown even when both inputs report complete collection.",
            "Event ordinals identify positions in each capture document, not ETW source byte offsets.",
            "SHA-256 values identify serialized representations and do not authenticate their origin.",
        ],
    })
}

fn capture_incomplete_reasons(capture: &WindowsRuntimeCapture) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if capture.collection_status == CollectionStatus::Partial {
        reasons.push("partial_collection");
    }
    if capture.event_loss.events_lost > 0
        || capture.event_loss.log_buffers_lost > 0
        || capture.event_loss.real_time_buffers_lost > 0
    {
        reasons.push("reported_event_loss");
    }
    if !capture.event_loss.loss_statistics_available {
        reasons.push("loss_statistics_unavailable");
    }
    if !capture.event_loss.final_snapshot_available {
        reasons.push("final_loss_snapshot_unavailable");
    }
    if !capture.diagnostics.is_empty() {
        reasons.push("capture_diagnostics_present");
    }
    reasons
}

#[derive(Serialize)]
struct NormalizedEvent<'a> {
    provider_guid: &'a str,
    event_id: u16,
    event_version: u8,
    opcode: u8,
    event_kind: &'a str,
    header_process_id: u32,
    header_thread_id: u32,
    header_flags: u16,
    raw_payload_hex: &'a str,
    payload_decoding: &'a Option<crate::windows_runtime::DecodedProcessPayload>,
    observation_decoding: &'a Option<Value>,
}

#[derive(Serialize)]
struct CandidateEventIdentity<'a> {
    identity_kind: &'static str,
    provider_guid: &'a str,
    event_id: u16,
    event_version: u8,
    opcode: u8,
    event_kind: &'a str,
    operation: &'a str,
    path: &'a str,
}

struct CandidateEventGroup {
    basis: &'static str,
    indices: Vec<usize>,
}

struct CaptureEventIndex {
    categories: BTreeMap<&'static str, Vec<u64>>,
    exact_records: BTreeMap<Vec<u8>, Vec<usize>>,
    candidate_records: BTreeMap<Vec<u8>, CandidateEventGroup>,
}

struct KeyWriter<'a> {
    bytes: Vec<u8>,
    remaining: &'a mut usize,
}

impl Write for KeyWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > *self.remaining {
            return Err(io::Error::other("event diff key byte budget exceeded"));
        }
        self.bytes
            .try_reserve(buffer.len())
            .map_err(|_| io::Error::other("could not reserve bounded event diff key"))?;
        self.bytes.extend_from_slice(buffer);
        *self.remaining -= buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialize_bounded_key<T: Serialize>(
    value: &T,
    remaining: &mut usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut writer = KeyWriter {
        bytes: Vec::new(),
        remaining,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| format!("could not serialize bounded Windows runtime {label}: {error}"))?;
    Ok(writer.bytes)
}

fn index_capture(
    capture: &WindowsRuntimeCapture,
    side: &str,
    key_budget: &mut usize,
) -> Result<CaptureEventIndex, String> {
    let mut categories = BTreeMap::<&'static str, Vec<u64>>::new();
    let mut exact_records = BTreeMap::<Vec<u8>, Vec<usize>>::new();
    let mut candidate_records = BTreeMap::<Vec<u8>, CandidateEventGroup>::new();
    for (index, event) in capture.events.iter().enumerate() {
        let expected_ordinal = u64::try_from(index + 1)
            .map_err(|_| "Windows runtime event ordinal exceeds the supported range".to_owned())?;
        if event.record_ordinal != expected_ordinal {
            return Err(format!(
                "{side} Windows runtime event ordinal mismatch at array entry {}",
                index + 1
            ));
        }
        let category = classify_event(event);
        let ordinals = categories.entry(category).or_default();
        ordinals.try_reserve(1).map_err(|_| {
            "could not reserve bounded Windows runtime category evidence".to_owned()
        })?;
        ordinals.push(event.record_ordinal);

        let exact_key = serialize_bounded_key(
            &NormalizedEvent {
                provider_guid: &event.provider_guid,
                event_id: event.event_id,
                event_version: event.event_version,
                opcode: event.opcode,
                event_kind: &event.event_kind,
                header_process_id: event.header_process_id,
                header_thread_id: event.header_thread_id,
                header_flags: event.header_flags,
                raw_payload_hex: &event.raw_payload_hex,
                payload_decoding: &event.payload_decoding,
                observation_decoding: &event.observation_decoding,
            },
            key_budget,
            "event identity",
        )?;
        let exact_group = exact_records.entry(exact_key).or_default();
        exact_group.try_reserve(1).map_err(|_| {
            "could not reserve bounded exact Windows runtime event references".to_owned()
        })?;
        exact_group.push(index);

        if let Some((identity_kind, operation, path, basis)) =
            candidate_event_identity(event, category)
        {
            let identity = CandidateEventIdentity {
                identity_kind,
                provider_guid: &event.provider_guid,
                event_id: event.event_id,
                event_version: event.event_version,
                opcode: event.opcode,
                event_kind: &event.event_kind,
                operation,
                path,
            };
            let key = serialize_bounded_key(&identity, key_budget, "candidate identity")?;
            let group = candidate_records
                .entry(key)
                .or_insert_with(|| CandidateEventGroup {
                    basis,
                    indices: Vec::new(),
                });
            group.indices.try_reserve(1).map_err(|_| {
                "could not reserve bounded candidate Windows runtime event references".to_owned()
            })?;
            group.indices.push(index);
        }
    }
    Ok(CaptureEventIndex {
        categories,
        exact_records,
        candidate_records,
    })
}

fn candidate_event_identity<'a>(
    event: &'a crate::windows_runtime::NativeRuntimeEvent,
    category: &'static str,
) -> Option<(&'static str, &'a str, &'a str, &'static str)> {
    if category.starts_with("process.") {
        let process = event.payload_decoding.as_ref()?;
        if process.status != crate::windows_runtime::ProcessDecodeStatus::Decoded {
            return None;
        }
        let path = process.image_file_name.as_deref()?;
        if path.is_empty() {
            return None;
        }
        return Some((
            "process_image",
            event.event_kind.as_str(),
            path,
            "unique_process_event_kind_and_exact_image_file_name",
        ));
    }
    if !category.starts_with("file_io.") {
        return None;
    }
    let decoding = event.observation_decoding.as_ref()?;
    if decoding.get("status").and_then(Value::as_str) != Some("decoded") {
        return None;
    }
    let activity = decoding.get("observation")?.get("activity")?.as_object()?;
    if activity.get("kind").and_then(Value::as_str) != Some("file") {
        return None;
    }
    let observation = activity.get("observation")?;
    let operation = observation.get("operation")?.as_str()?;
    let path = observation.get("path")?.as_str()?;
    if path.is_empty() {
        return None;
    }
    Some((
        "file_operation_path",
        operation,
        path,
        "unique_file_operation_and_literal_path",
    ))
}

fn compare_event_indices(
    before: &WindowsRuntimeCapture,
    after: &WindowsRuntimeCapture,
    before_index: &CaptureEventIndex,
    after_index: &CaptureEventIndex,
    before_incomplete: bool,
    after_incomplete: bool,
) -> Result<(Vec<EventDelta>, usize), String> {
    let mut before_unmatched = BTreeSet::new();
    let mut after_unmatched = BTreeSet::new();
    let mut deltas = Vec::new();
    let signatures: BTreeSet<&Vec<u8>> = before_index
        .exact_records
        .keys()
        .chain(after_index.exact_records.keys())
        .collect();
    for signature in signatures {
        let before_indices = before_index
            .exact_records
            .get(signature)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let after_indices = after_index
            .exact_records
            .get(signature)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let unchanged_count = before_indices.len().min(after_indices.len());
        if unchanged_count > 0 {
            push_event_delta(
                &mut deltas,
                EventDelta {
                    status: EventDeltaStatus::Unchanged,
                    confidence: "exact_record_representation",
                    basis: "exact_normalized_event_multiset_ignoring_ordinal_and_qpc_timestamp",
                    category: classify_event(&before.events[before_indices[0]]),
                    before: event_references(before, &before_indices[..unchanged_count]),
                    after: event_references(after, &after_indices[..unchanged_count]),
                    diagnostic: None,
                },
            )?;
        }
        before_unmatched.extend(before_indices[unchanged_count..].iter().copied());
        after_unmatched.extend(after_indices[unchanged_count..].iter().copied());
    }

    let candidate_keys: BTreeSet<&Vec<u8>> = before_index
        .candidate_records
        .keys()
        .chain(after_index.candidate_records.keys())
        .collect();
    let mut ambiguous_before = BTreeSet::new();
    let mut ambiguous_after = BTreeSet::new();
    let mut ambiguous_candidate_group_count = 0usize;
    for key in candidate_keys {
        let before_group = before_index.candidate_records.get(key);
        let after_group = after_index.candidate_records.get(key);
        let (Some(before_group), Some(after_group)) = (before_group, after_group) else {
            continue;
        };
        if !before_incomplete
            && !after_incomplete
            && before_group.indices.len() == 1
            && after_group.indices.len() == 1
            && before_unmatched.contains(&before_group.indices[0])
            && after_unmatched.contains(&after_group.indices[0])
        {
            let before_event = &before.events[before_group.indices[0]];
            let after_event = &after.events[after_group.indices[0]];
            let category = if classify_event(before_event) == classify_event(after_event) {
                classify_event(before_event)
            } else {
                "unclassified"
            };
            push_event_delta(
                &mut deltas,
                EventDelta {
                    status: EventDeltaStatus::CandidateChanged,
                    confidence: "limited_candidate",
                    basis: before_group.basis,
                    category,
                    before: event_references(before, &before_group.indices),
                    after: event_references(after, &after_group.indices),
                    diagnostic: Some(
                        "unique_identity_key_does_not_prove_same_underlying_execution",
                    ),
                },
            )?;
            before_unmatched.remove(&before_group.indices[0]);
            after_unmatched.remove(&after_group.indices[0]);
        } else if before_group.indices.len() > 1 || after_group.indices.len() > 1 {
            let has_unmatched = before_group
                .indices
                .iter()
                .any(|index| before_unmatched.contains(index))
                || after_group
                    .indices
                    .iter()
                    .any(|index| after_unmatched.contains(index));
            if has_unmatched {
                ambiguous_candidate_group_count = ambiguous_candidate_group_count.saturating_add(1);
                ambiguous_before.extend(
                    before_group
                        .indices
                        .iter()
                        .filter(|index| before_unmatched.contains(index))
                        .copied(),
                );
                ambiguous_after.extend(
                    after_group
                        .indices
                        .iter()
                        .filter(|index| after_unmatched.contains(index))
                        .copied(),
                );
            }
        }
    }

    append_one_sided_deltas(
        before,
        &before_unmatched,
        true,
        after_incomplete,
        before_incomplete,
        &ambiguous_before,
        &mut deltas,
    )?;
    append_one_sided_deltas(
        after,
        &after_unmatched,
        false,
        before_incomplete,
        after_incomplete,
        &ambiguous_after,
        &mut deltas,
    )?;
    Ok((deltas, ambiguous_candidate_group_count))
}

fn append_one_sided_deltas(
    observed_capture: &WindowsRuntimeCapture,
    indices: &BTreeSet<usize>,
    is_before: bool,
    other_incomplete: bool,
    observed_incomplete: bool,
    ambiguous: &BTreeSet<usize>,
    deltas: &mut Vec<EventDelta>,
) -> Result<(), String> {
    if indices.is_empty() {
        return Ok(());
    }
    let mut groups = BTreeMap::<Vec<u8>, Vec<usize>>::new();
    let mut key_budget = MAX_EVENT_DIFF_KEY_BYTES;
    for index in indices {
        let event = &observed_capture.events[*index];
        let key = serialize_bounded_key(
            &OneSidedGroupKey {
                category: classify_event(event),
                event_kind: &event.event_kind,
                provider_guid: &event.provider_guid,
                event_id: event.event_id,
                event_version: event.event_version,
                opcode: event.opcode,
            },
            &mut key_budget,
            "one-sided event group",
        )?;
        let group = groups.entry(key).or_default();
        group.try_reserve(1).map_err(|_| {
            "could not reserve bounded one-sided event evidence references".to_owned()
        })?;
        group.push(*index);
    }
    for (_, group) in groups {
        let event = &observed_capture.events[group[0]];
        let category = classify_event(event);
        let diagnostic = if group.iter().any(|index| ambiguous.contains(index)) {
            Some("candidate_identity_is_ambiguous_records_were_left_unpaired")
        } else if other_incomplete {
            Some("other_capture_is_incomplete_missing_records_are_unknown")
        } else if observed_incomplete {
            Some("observed_capture_is_incomplete")
        } else {
            Some("one_sided_observation_does_not_establish_system_level_addition_or_removal")
        };
        let mut delta = EventDelta {
            status: if is_before {
                EventDeltaStatus::ObservedOnlyBefore
            } else {
                EventDeltaStatus::ObservedOnlyAfter
            },
            confidence: "observed_on_one_input",
            basis: "no_exact_or_unambiguous_cross_capture_match",
            category,
            before: Vec::new(),
            after: Vec::new(),
            diagnostic,
        };
        if is_before {
            delta.before = event_references(observed_capture, &group);
        } else {
            delta.after = event_references(observed_capture, &group);
        }
        push_event_delta(deltas, delta)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct OneSidedGroupKey<'a> {
    category: &'static str,
    event_kind: &'a str,
    provider_guid: &'a str,
    event_id: u16,
    event_version: u8,
    opcode: u8,
}

fn event_references(
    capture: &WindowsRuntimeCapture,
    indices: &[usize],
) -> Vec<EventEvidenceReference> {
    indices
        .iter()
        .map(|index| {
            let event = &capture.events[*index];
            EventEvidenceReference {
                capture_sha256: capture.document_sha256.clone(),
                record_ordinal: event.record_ordinal,
                timestamp_qpc: event.timestamp_qpc,
                provider_guid: event.provider_guid.clone(),
                event_id: event.event_id,
                event_version: event.event_version,
                opcode: event.opcode,
                event_kind: event.event_kind.clone(),
                category: classify_event(event),
            }
        })
        .collect()
}

fn push_event_delta(deltas: &mut Vec<EventDelta>, delta: EventDelta) -> Result<(), String> {
    if deltas.len() >= MAX_EVENT_DIFF_ROWS {
        return Err("Windows runtime event diff exceeds the output row limit".to_owned());
    }
    deltas
        .try_reserve(1)
        .map_err(|_| "could not reserve bounded Windows runtime event diff output".to_owned())?;
    deltas.push(delta);
    Ok(())
}

fn validate_event_count(capture: &WindowsRuntimeCapture, side: &str) -> Result<(), String> {
    if capture.events.len() > MAX_WINDOWS_RUNTIME_EVENTS {
        return Err(format!(
            "{side} Windows runtime capture exceeds the {MAX_WINDOWS_RUNTIME_EVENTS} event limit"
        ));
    }
    Ok(())
}

fn capture_side(capture: &WindowsRuntimeCapture) -> CaptureSide {
    CaptureSide {
        document_sha256: capture.document_sha256.clone(),
        producer_collection_status: capture.collection_status,
        capture_completeness: "unknown",
        observed_event_count: capture.events.len(),
        event_loss: EventLossSummary {
            events_lost: capture.event_loss.events_lost,
            log_buffers_lost: capture.event_loss.log_buffers_lost,
            real_time_buffers_lost: capture.event_loss.real_time_buffers_lost,
            loss_statistics_available: capture.event_loss.loss_statistics_available,
            final_snapshot_available: capture.event_loss.final_snapshot_available,
            observation: capture.event_loss.observation.clone(),
        },
        diagnostics_count: capture.diagnostics.len(),
    }
}

#[cfg(test)]
fn group_event_ordinals(
    capture: &WindowsRuntimeCapture,
) -> Result<BTreeMap<&'static str, Vec<u64>>, String> {
    let mut groups: BTreeMap<&'static str, Vec<u64>> = BTreeMap::new();
    for (index, event) in capture.events.iter().enumerate() {
        let expected_ordinal = u64::try_from(index + 1)
            .map_err(|_| "Windows runtime event ordinal exceeds the supported range".to_owned())?;
        if event.record_ordinal != expected_ordinal {
            return Err(format!(
                "Windows runtime event ordinal mismatch at array entry {}",
                index + 1
            ));
        }
        let category = classify_event(event);
        let ordinals = groups.entry(category).or_default();
        ordinals.try_reserve(1).map_err(|_| {
            "could not reserve bounded Windows runtime category evidence".to_owned()
        })?;
        ordinals.push(event.record_ordinal);
    }
    Ok(groups)
}

fn classify_event(event: &crate::windows_runtime::NativeRuntimeEvent) -> &'static str {
    if let Some(process) = &event.payload_decoding {
        return classify_process_event(
            event,
            process.status,
            process.schema_name.as_deref(),
            process.schema_version,
        );
    }

    let Some(decoding) = &event.observation_decoding else {
        return "unclassified";
    };
    if decoding.get("status").and_then(Value::as_str) != Some("decoded") {
        return "unclassified";
    }
    let Some(observation_envelope) = decoding.get("observation") else {
        return "unclassified";
    };
    let schema = observation_envelope.get("schema").and_then(Value::as_str);
    let schema_version = observation_envelope
        .get("schema_version")
        .and_then(Value::as_u64);
    let Some(activity) = observation_envelope.get("activity") else {
        return "unclassified";
    };
    let Some(kind) = activity.get("kind").and_then(Value::as_str) else {
        return "unclassified";
    };
    let Some(observation) = activity.get("observation") else {
        return "unclassified";
    };

    match kind {
        "file" => classify_file_event(event, observation, schema, schema_version),
        "disk" => classify_disk_event(event, observation, schema, schema_version),
        "network" => classify_network_event(event, observation, schema, schema_version),
        _ => "unclassified",
    }
}

fn descriptor_matches_provider(
    event: &crate::windows_runtime::NativeRuntimeEvent,
    provider_guid: &str,
    version: u8,
    expected_event_kind: &str,
) -> bool {
    event
        .provider_guid
        .trim_matches(['{', '}'])
        .eq_ignore_ascii_case(provider_guid)
        && event.event_id == 0
        && event.event_version == version
        && event.event_kind == expected_event_kind
}

fn classify_process_event(
    event: &crate::windows_runtime::NativeRuntimeEvent,
    status: crate::windows_runtime::ProcessDecodeStatus,
    schema_name: Option<&str>,
    schema_version: Option<u8>,
) -> &'static str {
    if status != crate::windows_runtime::ProcessDecodeStatus::Decoded
        || !event
            .provider_guid
            .trim_matches(['{', '}'])
            .eq_ignore_ascii_case(PROCESS_PROVIDER_GUID)
        || event.event_id != 0
        || !(0..=3).contains(&event.event_version)
        || schema_name != Some(PROCESS_TYPEGROUP1_SCHEMA)
        || schema_version != Some(event.event_version)
    {
        return "unclassified";
    }

    match (event.opcode, event.event_kind.as_str()) {
        (1, "process_start") => "process.start",
        (2, "process_end") => "process.end",
        (3, "process_rundown_start") => "process.rundown_start",
        (4, "process_rundown_end") => "process.rundown_end",
        _ => "unclassified",
    }
}

fn classify_file_event(
    event: &crate::windows_runtime::NativeRuntimeEvent,
    observation: &Value,
    schema: Option<&str>,
    schema_version: Option<u64>,
) -> &'static str {
    if !descriptor_matches_provider(event, FILE_IO_PROVIDER_GUID, 2, "file_io_observation")
        || schema != Some("windows.kernel_file_io")
        || schema_version != Some(2)
    {
        return "unclassified";
    }
    let Some(operation) = observation.get("operation").and_then(Value::as_str) else {
        return "unclassified";
    };
    FILE_OPERATIONS
        .iter()
        .find_map(|(wire_operation, opcode, category)| {
            (*wire_operation == operation && *opcode == event.opcode).then_some(*category)
        })
        .unwrap_or("unclassified")
}

fn classify_disk_event(
    event: &crate::windows_runtime::NativeRuntimeEvent,
    observation: &Value,
    schema: Option<&str>,
    schema_version: Option<u64>,
) -> &'static str {
    if !descriptor_matches_provider(event, DISK_IO_PROVIDER_GUID, 0, "disk_io_observation")
        || schema != Some("windows.kernel_disk_io")
        || schema_version != Some(0)
    {
        return "unclassified";
    }
    let Some(operation) = observation.get("operation").and_then(Value::as_str) else {
        return "unclassified";
    };
    DISK_OPERATIONS
        .iter()
        .find_map(|(wire_operation, opcode, category)| {
            (*wire_operation == operation && *opcode == event.opcode).then_some(*category)
        })
        .unwrap_or("unclassified")
}

fn classify_network_event(
    event: &crate::windows_runtime::NativeRuntimeEvent,
    observation: &Value,
    schema: Option<&str>,
    schema_version: Option<u64>,
) -> &'static str {
    let Some(transport) = observation.get("transport").and_then(Value::as_str) else {
        return "unclassified";
    };
    let Some(operation) = observation.get("operation").and_then(Value::as_str) else {
        return "unclassified";
    };
    let provider_guid = match transport {
        "tcp" => TCP_IP_PROVIDER_GUID,
        "udp" => UDP_IP_PROVIDER_GUID,
        _ => return "unclassified",
    };
    if !descriptor_matches_provider(event, provider_guid, 2, "network_observation") {
        return "unclassified";
    }
    if schema_version != Some(2) {
        return "unclassified";
    }
    NETWORK_OPERATIONS
        .iter()
        .find_map(
            |(wire_transport, wire_operation, opcode, wire_schema, category)| {
                (*wire_transport == transport
                    && *wire_operation == operation
                    && *opcode == event.opcode
                    && Some(*wire_schema) == schema)
                    .then_some(*category)
            },
        )
        .unwrap_or("unclassified")
}

const FILE_OPERATIONS: &[(&str, u8, &str)] = &[
    ("name", 0, "file_io.name"),
    ("create_name", 32, "file_io.create_name"),
    ("delete_name", 35, "file_io.delete_name"),
    ("rundown_name", 36, "file_io.rundown_name"),
    ("create_request", 64, "file_io.create_request"),
    ("cleanup", 65, "file_io.cleanup"),
    ("close", 66, "file_io.close"),
    ("read_request", 67, "file_io.read_request"),
    ("write_request", 68, "file_io.write_request"),
    ("flush_request", 73, "file_io.flush_request"),
    (
        "set_information_request",
        69,
        "file_io.set_information_request",
    ),
    ("delete_request", 70, "file_io.delete_request"),
    ("rename_request", 71, "file_io.rename_request"),
    (
        "query_information_request",
        74,
        "file_io.query_information_request",
    ),
    (
        "file_system_control_request",
        75,
        "file_io.file_system_control_request",
    ),
];

const DISK_OPERATIONS: &[(&str, u8, &str)] = &[
    ("read", 10, "disk_io.read"),
    ("write", 11, "disk_io.write"),
    ("flush_buffers", 14, "disk_io.flush_buffers"),
];

const NETWORK_OPERATIONS: &[(&str, &str, u8, &str, &str)] = &[
    (
        "tcp",
        "send",
        10,
        "windows.kernel_tcp_ipv4_send",
        "network.tcp.send",
    ),
    (
        "tcp",
        "receive",
        11,
        "windows.kernel_tcp_ipv4_typegroup1",
        "network.tcp.receive",
    ),
    (
        "tcp",
        "connect",
        12,
        "windows.kernel_tcp_ipv4_typegroup2",
        "network.tcp.connect",
    ),
    (
        "tcp",
        "disconnect",
        13,
        "windows.kernel_tcp_ipv4_typegroup1",
        "network.tcp.disconnect",
    ),
    (
        "tcp",
        "retransmit",
        14,
        "windows.kernel_tcp_ipv4_typegroup1",
        "network.tcp.retransmit",
    ),
    (
        "tcp",
        "accept",
        15,
        "windows.kernel_tcp_ipv4_typegroup2",
        "network.tcp.accept",
    ),
    (
        "tcp",
        "reconnect",
        16,
        "windows.kernel_tcp_ipv4_typegroup1",
        "network.tcp.reconnect",
    ),
    (
        "tcp",
        "tcp_copy",
        18,
        "windows.kernel_tcp_ipv4_typegroup1",
        "network.tcp.tcp_copy",
    ),
    (
        "tcp",
        "send",
        26,
        "windows.kernel_tcp_ipv6_send",
        "network.tcp.send",
    ),
    (
        "tcp",
        "receive",
        27,
        "windows.kernel_tcp_ipv6_typegroup3",
        "network.tcp.receive",
    ),
    (
        "tcp",
        "connect",
        28,
        "windows.kernel_tcp_ipv6_typegroup4",
        "network.tcp.connect",
    ),
    (
        "tcp",
        "disconnect",
        29,
        "windows.kernel_tcp_ipv6_typegroup3",
        "network.tcp.disconnect",
    ),
    (
        "tcp",
        "retransmit",
        30,
        "windows.kernel_tcp_ipv6_typegroup3",
        "network.tcp.retransmit",
    ),
    (
        "tcp",
        "accept",
        31,
        "windows.kernel_tcp_ipv6_typegroup4",
        "network.tcp.accept",
    ),
    (
        "tcp",
        "reconnect",
        32,
        "windows.kernel_tcp_ipv6_typegroup3",
        "network.tcp.reconnect",
    ),
    (
        "tcp",
        "tcp_copy",
        34,
        "windows.kernel_tcp_ipv6_typegroup3",
        "network.tcp.tcp_copy",
    ),
    (
        "udp",
        "send",
        10,
        "windows.kernel_udp_ipv4_typegroup1",
        "network.udp.send",
    ),
    (
        "udp",
        "receive",
        11,
        "windows.kernel_udp_ipv4_typegroup1",
        "network.udp.receive",
    ),
    (
        "udp",
        "send",
        26,
        "windows.kernel_udp_ipv6_typegroup2",
        "network.udp.send",
    ),
    (
        "udp",
        "receive",
        27,
        "windows.kernel_udp_ipv6_typegroup2",
        "network.udp.receive",
    ),
];

const FIXED_CATEGORIES: &[&str] = &[
    "process.start",
    "process.end",
    "process.rundown_start",
    "process.rundown_end",
    "file_io.name",
    "file_io.create_name",
    "file_io.delete_name",
    "file_io.rundown_name",
    "file_io.create_request",
    "file_io.read_request",
    "file_io.write_request",
    "file_io.set_information_request",
    "file_io.delete_request",
    "file_io.rename_request",
    "file_io.query_information_request",
    "file_io.file_system_control_request",
    "file_io.cleanup",
    "file_io.close",
    "file_io.flush_request",
    "disk_io.read",
    "disk_io.write",
    "disk_io.flush_buffers",
    "network.tcp.connect",
    "network.tcp.accept",
    "network.tcp.disconnect",
    "network.tcp.send",
    "network.tcp.receive",
    "network.tcp.retransmit",
    "network.tcp.reconnect",
    "network.tcp.tcp_copy",
    "network.udp.send",
    "network.udp.receive",
    "unclassified",
];

fn fixed_categories() -> impl Iterator<Item = &'static str> {
    FIXED_CATEGORIES.iter().copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_runtime::{
        AppliedLimits, DecodedProcessPayload, EventLoss, NativeRuntimeEvent, ProcessDecodeStatus,
        SessionMetadata, StopReason, TargetOutcome,
    };

    fn capture(
        status: CollectionStatus,
        events: Vec<NativeRuntimeEvent>,
        hash: &str,
    ) -> WindowsRuntimeCapture {
        WindowsRuntimeCapture {
            schema: crate::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
            schema_version: crate::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
            platform: "windows".to_owned(),
            capture_profile: "test".to_owned(),
            collection_status: status,
            capture_completeness: "unknown".to_owned(),
            started_at_unix_ms: 1,
            ended_at_unix_ms: 2,
            requested_duration_seconds: 1,
            stop_reason: StopReason::TargetExited,
            target: TargetOutcome {
                process_id: 9,
                exit_code: Some(0),
                status_available: true,
            },
            session: SessionMetadata {
                name: "session".to_owned(),
                provider: "provider".to_owned(),
                scope: "scope".to_owned(),
                buffer_size_kb_requested: 1,
                minimum_buffers_requested: 1,
                maximum_buffers_requested: 1,
                buffer_count_reported: 1,
                provider_process_id_header_semantics: "context".to_owned(),
            },
            limits: AppliedLimits {
                maximum_duration_seconds: 60,
                maximum_events: MAX_WINDOWS_RUNTIME_EVENTS,
                maximum_total_payload_bytes:
                    crate::windows_runtime::MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES,
                maximum_payload_bytes_per_event:
                    crate::windows_runtime::MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
                maximum_document_bytes: crate::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
            },
            event_loss: EventLoss {
                events_lost: 0,
                log_buffers_lost: 0,
                real_time_buffers_lost: 0,
                loss_statistics_available: true,
                observation: "zero_reported".to_owned(),
                final_snapshot_available: true,
            },
            document_sha256: hash.to_owned(),
            events,
            diagnostics: Vec::new(),
        }
    }

    fn process_event(ordinal: u64, kind: &str, status: ProcessDecodeStatus) -> NativeRuntimeEvent {
        let opcode = match kind {
            "process_start" => 1,
            "process_end" => 2,
            "process_rundown_start" => 3,
            "process_rundown_end" => 4,
            _ => 99,
        };
        NativeRuntimeEvent {
            record_ordinal: ordinal,
            provider_guid: format!("{{{PROCESS_PROVIDER_GUID}}}"),
            event_id: 0,
            event_version: 2,
            opcode,
            event_kind: kind.to_owned(),
            header_process_id: 1,
            header_thread_id: 2,
            header_flags: 0,
            timestamp_qpc: i64::try_from(ordinal).unwrap(),
            raw_payload_hex: "00".to_owned(),
            payload_decoding: Some(DecodedProcessPayload {
                status,
                schema_name: Some(PROCESS_TYPEGROUP1_SCHEMA.to_owned()),
                schema_version: Some(2),
                pointer_size_bytes: Some(8),
                process_id: Some(10),
                parent_process_id: Some(1),
                image_file_name: Some("child.exe".to_owned()),
                diagnostic: None,
            }),
            observation_decoding: None,
        }
    }

    fn file_path_event(ordinal: u64, path: &str, file_object: u64) -> NativeRuntimeEvent {
        observed_event(
            ordinal,
            decoded_activity(
                "file",
                serde_json::json!({
                    "operation":"create_name",
                    "path":path,
                    "file_object":file_object,
                }),
            ),
            FILE_IO_PROVIDER_GUID,
            2,
            32,
            "file_io_observation",
        )
    }

    fn observation_event(ordinal: u64, value: Value) -> NativeRuntimeEvent {
        NativeRuntimeEvent {
            record_ordinal: ordinal,
            provider_guid: "observation-provider".to_owned(),
            event_id: 0,
            event_version: 2,
            opcode: 0,
            event_kind: "io_observation".to_owned(),
            header_process_id: 3,
            header_thread_id: 4,
            header_flags: 0,
            timestamp_qpc: i64::try_from(ordinal).unwrap(),
            raw_payload_hex: "01".to_owned(),
            payload_decoding: None,
            observation_decoding: Some(value),
        }
    }

    fn set_descriptor(
        event: &mut NativeRuntimeEvent,
        provider_guid: &str,
        version: u8,
        opcode: u8,
        event_kind: &str,
    ) {
        event.provider_guid = format!("{{{provider_guid}}}");
        event.event_id = 0;
        event.event_version = version;
        event.opcode = opcode;
        event.event_kind = event_kind.to_owned();
    }

    fn observed_event(
        ordinal: u64,
        value: Value,
        provider_guid: &str,
        version: u8,
        opcode: u8,
        event_kind: &str,
    ) -> NativeRuntimeEvent {
        let mut event = observation_event(ordinal, value);
        set_descriptor(&mut event, provider_guid, version, opcode, event_kind);
        event
    }

    fn decoded_activity(kind: &str, observation: Value) -> Value {
        let schema = match kind {
            "file" => "windows.kernel_file_io",
            "disk" => "windows.kernel_disk_io",
            "network" => match (
                observation["transport"].as_str(),
                observation["operation"].as_str(),
            ) {
                (Some("udp"), _) => "windows.kernel_udp_ipv4_typegroup1",
                (_, Some("connect" | "accept")) => "windows.kernel_tcp_ipv4_typegroup2",
                (_, Some("send")) => "windows.kernel_tcp_ipv4_send",
                _ => "windows.kernel_tcp_ipv4_typegroup1",
            },
            _ => "sideeffect.unsupported",
        };
        let schema_version = if kind == "disk" { 0 } else { 2 };
        serde_json::json!({
            "status":"decoded",
            "diagnostic":null,
            "observation":{
                "schema":schema,
                "schema_version":schema_version,
                "activity":{"kind":kind,"observation":observation}
            }
        })
    }

    #[test]
    fn compares_fixed_categories_with_counts_and_source_ordinals() {
        let before = capture(
            CollectionStatus::Complete,
            vec![
                process_event(1, "process_start", ProcessDecodeStatus::Decoded),
                observed_event(
                    2,
                    decoded_activity("file", serde_json::json!({"operation":"read_request"})),
                    FILE_IO_PROVIDER_GUID,
                    2,
                    67,
                    "file_io_observation",
                ),
                observed_event(
                    3,
                    decoded_activity(
                        "network",
                        serde_json::json!({"transport":"tcp","operation":"connect"}),
                    ),
                    TCP_IP_PROVIDER_GUID,
                    2,
                    12,
                    "network_observation",
                ),
                observation_event(4, serde_json::json!({"status":"unsupported_event"})),
            ],
            &"a".repeat(64),
        );
        let after = capture(
            CollectionStatus::Complete,
            vec![
                process_event(1, "process_end", ProcessDecodeStatus::Decoded),
                observed_event(
                    2,
                    decoded_activity("file", serde_json::json!({"operation":"read_request"})),
                    FILE_IO_PROVIDER_GUID,
                    2,
                    67,
                    "file_io_observation",
                ),
                observed_event(
                    3,
                    decoded_activity("file", serde_json::json!({"operation":"read_request"})),
                    FILE_IO_PROVIDER_GUID,
                    2,
                    67,
                    "file_io_observation",
                ),
                observed_event(
                    4,
                    decoded_activity("disk", serde_json::json!({"operation":"write"})),
                    DISK_IO_PROVIDER_GUID,
                    0,
                    11,
                    "disk_io_observation",
                ),
                observed_event(
                    5,
                    decoded_activity(
                        "network",
                        serde_json::json!({"transport":"udp","operation":"receive"}),
                    ),
                    UDP_IP_PROVIDER_GUID,
                    2,
                    11,
                    "network_observation",
                ),
            ],
            &"b".repeat(64),
        );
        let summary = compare_windows_runtime_captures(&before, &after).unwrap();
        let json = serde_json::to_value(&summary).unwrap();

        assert_eq!(summary.schema, WINDOWS_RUNTIME_DIFF_SUMMARY_SCHEMA);
        assert_eq!(summary.schema_version, 3);
        assert_eq!(summary.comparison_status, ComparisonStatus::Complete);
        assert_eq!(summary.capture_completeness, "unknown");
        assert!(
            !summary
                .representation_comparison
                .same_validated_representation_fingerprint
        );
        assert_eq!(summary.before.document_sha256, "a".repeat(64));
        assert_eq!(summary.after.document_sha256, "b".repeat(64));
        assert_eq!(
            json["algorithm"]["basis"],
            "fixed_category_counts_plus_exact_record_multiset_and_unique_identity_candidates"
        );

        let category = |name| {
            summary
                .categories
                .iter()
                .find(|entry| entry.category == name)
                .unwrap()
        };
        let reads = category("file_io.read_request");
        assert_eq!((reads.before_count, reads.after_count), (1, 2));
        assert_eq!(reads.observed_count_delta, 1);
        assert_eq!(reads.before_event_ordinals, [2]);
        assert_eq!(reads.after_event_ordinals, [2, 3]);
        let unknown = category("unclassified");
        assert_eq!(unknown.before_event_ordinals, [4]);
        assert_eq!(category("network.tcp.connect").after_count, 0);
        assert_eq!(category("network.udp.receive").after_event_ordinals, [5]);
        assert!(
            summary
                .limitations
                .iter()
                .any(|item| item.contains("unpaired"))
        );
        assert!(
            summary
                .limitations
                .iter()
                .any(|item| item.contains("does not establish"))
        );
    }

    #[test]
    fn event_diff_is_order_independent_preserves_multiplicity_and_source_references() {
        let before = capture(
            CollectionStatus::Complete,
            vec![
                process_event(1, "process_start", ProcessDecodeStatus::Decoded),
                process_event(2, "process_start", ProcessDecodeStatus::Decoded),
                file_path_event(3, r"C:\Apps\one.exe", 10),
            ],
            &"a".repeat(64),
        );
        let after = capture(
            CollectionStatus::Complete,
            vec![
                file_path_event(1, r"C:\Apps\one.exe", 10),
                process_event(2, "process_start", ProcessDecodeStatus::Decoded),
                process_event(3, "process_start", ProcessDecodeStatus::Decoded),
            ],
            &"b".repeat(64),
        );
        let summary = compare_windows_runtime_captures(&before, &after).unwrap();
        let unchanged = summary
            .event_changes
            .iter()
            .filter(|delta| delta.status == EventDeltaStatus::Unchanged)
            .collect::<Vec<_>>();
        assert_eq!(unchanged.len(), 2);
        let process = unchanged
            .iter()
            .find(|delta| delta.category == "process.start")
            .unwrap();
        assert_eq!(process.before.len(), 2);
        assert_eq!(process.after.len(), 2);
        assert_eq!(process.before[0].record_ordinal, 1);
        assert_eq!(process.before[1].record_ordinal, 2);
        assert_eq!(process.after[0].record_ordinal, 2);
        assert_eq!(process.after[1].record_ordinal, 3);
        assert!(
            process
                .before
                .iter()
                .all(|reference| reference.capture_sha256 == "a".repeat(64))
        );
        assert!(
            process
                .after
                .iter()
                .all(|reference| reference.capture_sha256 == "b".repeat(64))
        );
        assert!(summary.event_changes.iter().all(|delta| {
            !matches!(
                delta.status,
                EventDeltaStatus::ObservedOnlyBefore | EventDeltaStatus::ObservedOnlyAfter
            )
        }));
    }

    #[test]
    fn unique_file_identity_is_only_a_candidate_changed_pair() {
        let before = capture(
            CollectionStatus::Complete,
            vec![file_path_event(1, r"C:\Apps\one.exe", 10)],
            &"a".repeat(64),
        );
        let after = capture(
            CollectionStatus::Complete,
            vec![file_path_event(1, r"C:\Apps\one.exe", 20)],
            &"b".repeat(64),
        );
        let summary = compare_windows_runtime_captures(&before, &after).unwrap();
        let candidate = summary
            .event_changes
            .iter()
            .find(|delta| delta.status == EventDeltaStatus::CandidateChanged)
            .unwrap();
        assert_eq!(candidate.confidence, "limited_candidate");
        assert_eq!(candidate.basis, "unique_file_operation_and_literal_path");
        assert_eq!(candidate.before[0].record_ordinal, 1);
        assert_eq!(candidate.after[0].record_ordinal, 1);
        assert_eq!(candidate.before[0].capture_sha256, "a".repeat(64));
        assert_eq!(candidate.after[0].capture_sha256, "b".repeat(64));
        assert!(
            candidate
                .diagnostic
                .unwrap()
                .contains("does_not_prove_same_underlying_execution")
        );
    }

    #[test]
    fn ambiguous_identity_is_left_one_sided_and_partial_absence_is_not_a_removal() {
        let before = capture(
            CollectionStatus::Complete,
            vec![
                file_path_event(1, r"C:\Apps\one.exe", 10),
                file_path_event(2, r"C:\Apps\one.exe", 11),
            ],
            &"a".repeat(64),
        );
        let after = capture(
            CollectionStatus::Partial,
            vec![file_path_event(1, r"C:\Apps\one.exe", 20)],
            &"b".repeat(64),
        );
        let summary = compare_windows_runtime_captures(&before, &after).unwrap();
        assert_eq!(summary.comparison_status, ComparisonStatus::Partial);
        assert!(
            summary
                .diagnostics
                .contains(&"ambiguous_candidate_identities_were_left_unpaired")
        );
        assert!(
            summary
                .event_changes
                .iter()
                .all(|delta| { delta.status != EventDeltaStatus::CandidateChanged })
        );
        assert!(summary.event_changes.iter().any(|delta| {
            delta.status == EventDeltaStatus::ObservedOnlyBefore
                && delta.diagnostic
                    == Some("candidate_identity_is_ambiguous_records_were_left_unpaired")
        }));
        assert!(summary.event_changes.iter().any(|delta| {
            delta.status == EventDeltaStatus::ObservedOnlyAfter
                && delta.diagnostic
                    == Some("candidate_identity_is_ambiguous_records_were_left_unpaired")
        }));

        let only_before = capture(
            CollectionStatus::Complete,
            vec![file_path_event(1, r"C:\Apps\gone.exe", 50)],
            &"c".repeat(64),
        );
        let partial_after = capture(CollectionStatus::Partial, vec![], &"d".repeat(64));
        let partial = compare_windows_runtime_captures(&only_before, &partial_after).unwrap();
        assert!(partial.event_changes.iter().any(|delta| {
            delta.status == EventDeltaStatus::ObservedOnlyBefore
                && delta
                    .diagnostic
                    .is_some_and(|diagnostic| diagnostic.contains("missing_records_are_unknown"))
        }));
        assert!(partial.before.event_loss.loss_statistics_available);
        assert!(partial.after.event_loss.final_snapshot_available);
    }

    #[test]
    fn preserves_partial_status_and_never_claims_completeness() {
        let before = capture(CollectionStatus::Partial, vec![], "a");
        let after = capture(CollectionStatus::Complete, vec![], "b");
        let summary = compare_windows_runtime_captures(&before, &after).unwrap();
        assert_eq!(summary.comparison_status, ComparisonStatus::Partial);
        assert_eq!(summary.capture_completeness, "unknown");
        assert_eq!(
            summary.before.producer_collection_status,
            CollectionStatus::Partial
        );
        assert_eq!(
            summary.after.producer_collection_status,
            CollectionStatus::Complete
        );
        assert_eq!(
            summary.diagnostics,
            ["one_or_both_captures_report_partial_collection"]
        );
    }

    #[test]
    fn unknown_operations_and_undecoded_process_events_stay_unclassified() {
        let capture = capture(
            CollectionStatus::Partial,
            vec![
                observed_event(
                    1,
                    decoded_activity("file", serde_json::json!({"operation":"future_op"})),
                    FILE_IO_PROVIDER_GUID,
                    2,
                    67,
                    "file_io_observation",
                ),
                process_event(2, "process_start", ProcessDecodeStatus::MalformedPayload),
            ],
            "a",
        );
        let groups = group_event_ordinals(&capture).unwrap();
        assert_eq!(groups["unclassified"], [1, 2]);
        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn decoded_process_labels_require_matching_provider_descriptor_and_kind() {
        let mut wrong_provider = process_event(1, "process_start", ProcessDecodeStatus::Decoded);
        wrong_provider.provider_guid = "{00000000-0000-0000-0000-000000000000}".to_owned();
        let mut wrong_id = process_event(2, "process_start", ProcessDecodeStatus::Decoded);
        wrong_id.event_id = 1;
        let mut wrong_opcode = process_event(3, "process_start", ProcessDecodeStatus::Decoded);
        wrong_opcode.opcode = 2;
        let mut wrong_version = process_event(4, "process_start", ProcessDecodeStatus::Decoded);
        wrong_version.event_version = 4;
        let capture = capture(
            CollectionStatus::Complete,
            vec![wrong_provider, wrong_id, wrong_opcode, wrong_version],
            "a",
        );
        let groups = group_event_ordinals(&capture).unwrap();
        assert_eq!(groups["unclassified"], [1, 2, 3, 4]);
        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn decoded_io_labels_require_provider_descriptor_and_operation_mapping() {
        let file = observed_event(
            1,
            decoded_activity("file", serde_json::json!({"operation":"read_request"})),
            FILE_IO_PROVIDER_GUID,
            2,
            68,
            "file_io_observation",
        );
        let disk = observed_event(
            2,
            decoded_activity("disk", serde_json::json!({"operation":"write"})),
            DISK_IO_PROVIDER_GUID,
            0,
            10,
            "disk_io_observation",
        );
        let tcp = observed_event(
            3,
            decoded_activity(
                "network",
                serde_json::json!({"transport":"tcp","operation":"send"}),
            ),
            TCP_IP_PROVIDER_GUID,
            2,
            12,
            "network_observation",
        );
        let udp = observed_event(
            4,
            decoded_activity(
                "network",
                serde_json::json!({"transport":"udp","operation":"receive"}),
            ),
            UDP_IP_PROVIDER_GUID,
            2,
            10,
            "network_observation",
        );
        let wrong_file_provider = observed_event(
            5,
            decoded_activity("file", serde_json::json!({"operation":"read_request"})),
            TCP_IP_PROVIDER_GUID,
            2,
            67,
            "file_io_observation",
        );
        let mut wrong_disk_event_id = observed_event(
            6,
            decoded_activity("disk", serde_json::json!({"operation":"read"})),
            DISK_IO_PROVIDER_GUID,
            0,
            10,
            "disk_io_observation",
        );
        wrong_disk_event_id.event_id = 1;
        let wrong_tcp_version = observed_event(
            7,
            decoded_activity(
                "network",
                serde_json::json!({"transport":"tcp","operation":"connect"}),
            ),
            TCP_IP_PROVIDER_GUID,
            1,
            12,
            "network_observation",
        );
        let wrong_udp_version = observed_event(
            8,
            decoded_activity(
                "network",
                serde_json::json!({"transport":"udp","operation":"receive"}),
            ),
            UDP_IP_PROVIDER_GUID,
            1,
            11,
            "network_observation",
        );
        let capture = capture(
            CollectionStatus::Partial,
            vec![
                file,
                disk,
                tcp,
                udp,
                wrong_file_provider,
                wrong_disk_event_id,
                wrong_tcp_version,
                wrong_udp_version,
            ],
            "a",
        );
        let groups = group_event_ordinals(&capture).unwrap();
        assert_eq!(groups["unclassified"], [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn rejects_caller_constructed_input_over_event_bound() {
        let event = process_event(1, "process_start", ProcessDecodeStatus::Decoded);
        let before = capture(
            CollectionStatus::Complete,
            vec![event; MAX_WINDOWS_RUNTIME_EVENTS + 1],
            "a",
        );
        let after = capture(CollectionStatus::Complete, vec![], "b");
        assert!(
            compare_windows_runtime_captures(&before, &after)
                .unwrap_err()
                .contains("event limit")
        );
    }
}
