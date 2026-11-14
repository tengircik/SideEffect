//! Exact lexical candidate linking between Windows selected-root deltas and
//! raw-cross-checked ETW FileIo name records.
//!
//! Only drive-rooted paths with the same exact DOS drive spelling are compared.
//! NT device paths, UNC paths, verbatim paths, relative paths, and other drives
//! remain explicitly unresolved. A match is a path candidate only; it does not
//! establish success, ownership, mutation, or cause.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::record::windows_io_decode::{FilePathCrossCheck, FilePathInput, cross_check_file_path};
use crate::windows_runtime::{NativeRuntimeEvent, inspect_windows_runtime_bytes};

const MAX_ASSOCIATIONS: usize = 20_000;
const MAX_EVIDENCE_REFS: usize = 50_000;
const MAX_REFS_PER_ASSOCIATION: usize = 256;
const MAX_ASSOCIATION_REPORT_BYTES: usize = 1024 * 1024;
const MAX_PATH_UTF16_UNITS: usize = 32_766;
const MAX_NAME_UTF16_UNITS: usize = 32_767;

const CREATE_NAME_OPCODE: u8 = 32;
const DELETE_NAME_OPCODE: u8 = 35;

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRootRuntimeAssociationReport {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    /// The association output stays partial because capture completeness is unknown.
    pub status: &'static str,
    pub association_status: &'static str,
    pub capture_completeness: &'static str,
    pub claim: &'static str,
    pub root_diff_status: String,
    pub capture_artifact_sha256: String,
    pub capture_document_sha256: String,
    pub capture_claimed_collection_status: &'static str,
    pub root_dos_drive_prefix: Option<String>,
    pub summary: WindowsRootRuntimeAssociationSummary,
    pub associations_omitted_to_output_limit: usize,
    pub evidence_references_omitted_to_output_limit: usize,
    pub diagnostics: Vec<&'static str>,
    pub limitations: Vec<&'static str>,
    pub associations: Vec<WindowsRootRuntimeAssociation>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRootRuntimeAssociationSummary {
    pub delta_count: usize,
    pub name_bearing_file_event_count: usize,
    pub directional_file_name_event_count: usize,
    pub same_dos_drive_event_count: usize,
    pub nt_device_namespace_event_count: usize,
    pub unc_namespace_event_count: usize,
    pub verbatim_namespace_event_count: usize,
    pub relative_or_other_namespace_event_count: usize,
    pub different_dos_drive_event_count: usize,
    pub cross_check_rejected_event_count: usize,
    pub runtime_observation_rows_omitted_to_limit: usize,
    pub candidate_match_count: usize,
    pub ambiguous_candidate_count: usize,
    pub unmatched_delta_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRootRuntimeAssociation {
    pub status: &'static str,
    pub candidate_path: String,
    pub candidate_path_utf16le_hex: String,
    pub delta_kind: String,
    pub delta_name_identity_hex: String,
    pub etw_operation: &'static str,
    pub multiple_runtime_observations: bool,
    pub runtime_evidence: Vec<WindowsRootRuntimeEvidence>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRootRuntimeEvidence {
    /// Self-reported canonical document fingerprint used for capture lookup.
    pub capture_document_sha256: String,
    pub record_ordinal: u64,
    pub json_pointer: String,
    pub raw_payload_sha256: String,
    pub etw_operation: &'static str,
}

/// Compare an already validated selected-root delta with one verified Windows
/// ETW v3 capture. Every retained evidence row is re-decoded from its raw
/// payload and must exactly match its serialized observation sidecar.
pub fn associate_windows_root_runtime_diff(
    diff: &super::root_snapshot_diff::RootSnapshotDiff,
    capture_bytes: &[u8],
) -> Result<WindowsRootRuntimeAssociationReport, String> {
    if diff.platform != "windows" {
        return Err("root/runtime association requires a Windows selected-root diff".to_owned());
    }
    let capture = inspect_windows_runtime_bytes(capture_bytes)?;
    let capture_artifact_sha256 = sha256_hex(capture_bytes);
    let capture_document_sha256 = capture.document_sha256.clone();
    let root_units = decode_utf16le_hex(&diff.root_path_identity_hex, MAX_PATH_UTF16_UNITS)
        .ok_or_else(|| "selected-root exact UTF-16 path units are unavailable".to_owned())?;
    let root_drive = dos_drive_prefix(&root_units);

    let mut observed = BTreeMap::<Vec<u16>, Vec<WindowsRootRuntimeEvidence>>::new();
    let mut name_bearing_file_event_count = 0usize;
    let mut directional_file_name_event_count = 0usize;
    let mut same_dos_drive_event_count = 0usize;
    let mut nt_device_namespace_event_count = 0usize;
    let mut unc_namespace_event_count = 0usize;
    let mut verbatim_namespace_event_count = 0usize;
    let mut relative_or_other_namespace_event_count = 0usize;
    let mut different_dos_drive_event_count = 0usize;
    let mut cross_check_rejected_event_count = 0usize;
    let mut runtime_observation_rows_omitted_to_limit = 0usize;
    let mut retained_observation_count = 0usize;

    for (event_index, event) in capture.events.iter().enumerate() {
        let operation = match event.opcode {
            CREATE_NAME_OPCODE => "create_name",
            DELETE_NAME_OPCODE => "delete_name",
            _ => continue,
        };
        if event.event_kind != "file_io_observation" {
            continue;
        }
        name_bearing_file_event_count = name_bearing_file_event_count.saturating_add(1);
        directional_file_name_event_count = directional_file_name_event_count.saturating_add(1);
        let Some(payload) = decode_payload_hex(&event.raw_payload_hex) else {
            cross_check_rejected_event_count = cross_check_rejected_event_count.saturating_add(1);
            continue;
        };
        let path = match cross_check_file_path(file_path_input(event, &payload)) {
            FilePathCrossCheck::Matched(Some(path)) => path,
            FilePathCrossCheck::Matched(None)
            | FilePathCrossCheck::Mismatch
            | FilePathCrossCheck::Unsupported
            | FilePathCrossCheck::Malformed
            | FilePathCrossCheck::NotFileProvider => {
                cross_check_rejected_event_count =
                    cross_check_rejected_event_count.saturating_add(1);
                continue;
            }
        };
        let path_units = path.encode_utf16().collect::<Vec<_>>();
        match classify_path_units(&path_units) {
            PathNamespace::DosDrive => {}
            PathNamespace::NtDevice => {
                nt_device_namespace_event_count = nt_device_namespace_event_count.saturating_add(1);
                continue;
            }
            PathNamespace::Unc => {
                unc_namespace_event_count = unc_namespace_event_count.saturating_add(1);
                continue;
            }
            PathNamespace::Verbatim => {
                verbatim_namespace_event_count = verbatim_namespace_event_count.saturating_add(1);
                continue;
            }
            PathNamespace::RelativeOrOther => {
                relative_or_other_namespace_event_count =
                    relative_or_other_namespace_event_count.saturating_add(1);
                continue;
            }
        }
        let Some(root_drive) = root_drive else {
            continue;
        };
        if dos_drive_prefix(&path_units) != Some(root_drive) {
            different_dos_drive_event_count = different_dos_drive_event_count.saturating_add(1);
            continue;
        }
        same_dos_drive_event_count = same_dos_drive_event_count.saturating_add(1);
        if retained_observation_count >= MAX_EVIDENCE_REFS {
            runtime_observation_rows_omitted_to_limit =
                runtime_observation_rows_omitted_to_limit.saturating_add(1);
            continue;
        }
        retained_observation_count = retained_observation_count.saturating_add(1);
        observed
            .entry(path_units)
            .or_default()
            .push(WindowsRootRuntimeEvidence {
                capture_document_sha256: capture_document_sha256.clone(),
                record_ordinal: event.record_ordinal,
                json_pointer: format!("/events/{event_index}"),
                raw_payload_sha256: sha256_hex(&payload),
                etw_operation: operation,
            });
    }

    let mut associations = Vec::new();
    let mut delta_count = 0usize;
    let mut ambiguous_candidate_count = 0usize;
    let mut unmatched_delta_count = 0usize;
    let mut candidates_omitted_to_limit = 0usize;
    for delta in &diff.deltas {
        let operation = match delta.kind {
            "added" | "changed" => "create_name",
            "removed" => "delete_name",
            _ => continue,
        };
        delta_count = delta_count.saturating_add(1);
        let Some(candidate_path) =
            exact_child_path(&root_units, &delta.name_identity_hex, MAX_NAME_UTF16_UNITS)
        else {
            unmatched_delta_count = unmatched_delta_count.saturating_add(1);
            continue;
        };
        let Some(evidence) = observed.get(&candidate_path) else {
            unmatched_delta_count = unmatched_delta_count.saturating_add(1);
            continue;
        };
        if associations.len() >= MAX_ASSOCIATIONS {
            candidates_omitted_to_limit = candidates_omitted_to_limit.saturating_add(1);
            continue;
        }
        if evidence.iter().any(|row| row.etw_operation != operation) {
            unmatched_delta_count = unmatched_delta_count.saturating_add(1);
            continue;
        }
        if evidence.len() > 1 {
            ambiguous_candidate_count = ambiguous_candidate_count.saturating_add(1);
        }
        let candidate_path_text = String::from_utf16(&candidate_path)
            .map_err(|_| "selected-root candidate path is not valid UTF-16".to_owned())?;
        associations.push(WindowsRootRuntimeAssociation {
            status: if evidence.len() > 1 {
                "ambiguous_candidate_match"
            } else {
                "candidate_match"
            },
            candidate_path: candidate_path_text,
            candidate_path_utf16le_hex: utf16le_hex(&candidate_path),
            delta_kind: delta.kind.to_owned(),
            delta_name_identity_hex: delta.name_identity_hex.clone(),
            etw_operation: operation,
            multiple_runtime_observations: evidence.len() > 1,
            runtime_evidence: evidence.clone(),
        });
    }

    let mut report = WindowsRootRuntimeAssociationReport {
        schema: "sideeffect.windows_root_runtime_association",
        schema_version: 1,
        platform: "windows",
        status: "partial",
        association_status: if associations.is_empty() {
            "insufficient_evidence"
        } else {
            "candidate_match"
        },
        capture_completeness: "unknown",
        claim: "exact_lexical_dos_drive_path_candidate_only_no_success_ownership_or_causation",
        root_diff_status: diff.status.to_owned(),
        capture_artifact_sha256,
        capture_document_sha256,
        capture_claimed_collection_status: match capture.collection_status {
            crate::windows_runtime::CollectionStatus::Complete => "complete",
            crate::windows_runtime::CollectionStatus::Partial => "partial",
        },
        root_dos_drive_prefix: root_drive.map(drive_prefix_text),
        summary: WindowsRootRuntimeAssociationSummary {
            delta_count,
            name_bearing_file_event_count,
            directional_file_name_event_count,
            same_dos_drive_event_count,
            nt_device_namespace_event_count,
            unc_namespace_event_count,
            verbatim_namespace_event_count,
            relative_or_other_namespace_event_count,
            different_dos_drive_event_count,
            cross_check_rejected_event_count,
            runtime_observation_rows_omitted_to_limit,
            candidate_match_count: associations.len(),
            ambiguous_candidate_count,
            unmatched_delta_count,
        },
        associations_omitted_to_output_limit: candidates_omitted_to_limit,
        evidence_references_omitted_to_output_limit: 0,
        diagnostics: Vec::new(),
        limitations: vec![
            "Only added or changed selected-root rows are compared with create_name records, and only removed rows with delete_name records; other FileIo operations are not used for mutation direction.",
            "A path is compared only when both the selected-root candidate and the decoded FileIo path use the same exact DOS drive prefix and agree in native UTF-16 code units; no case folding, separators, aliases, or components are normalized.",
            "NT device, UNC, verbatim, relative, and other-drive paths remain explicitly unresolved and are never converted to or from a DOS drive path.",
            "Each FileIo row is retained only after its raw payload is re-decoded and its complete typed observation exactly matches the serialized sidecar; a cross-check failure is excluded and counted.",
            "A create_name or delete_name record does not establish that the operation succeeded or changed the selected-root entry.",
            "ETW header process IDs are not used; a candidate does not identify the process that performed the operation or establish causation.",
            "The capture is system-wide for a bounded window, and capture completeness remains unknown.",
            "Missing matches do not establish absence; unsupported, unresolved, ambiguous, or truncated observations remain unknown.",
        ],
        associations,
    };
    for association in &mut report.associations {
        if association.runtime_evidence.len() > MAX_REFS_PER_ASSOCIATION {
            report.evidence_references_omitted_to_output_limit = report
                .evidence_references_omitted_to_output_limit
                .saturating_add(association.runtime_evidence.len() - MAX_REFS_PER_ASSOCIATION);
            association
                .runtime_evidence
                .truncate(MAX_REFS_PER_ASSOCIATION);
        }
    }
    if report.summary.runtime_observation_rows_omitted_to_limit > 0 {
        report.diagnostics.push("runtime_observation_limit_reached");
    }
    if report.summary.nt_device_namespace_event_count > 0
        || report.summary.unc_namespace_event_count > 0
        || report.summary.verbatim_namespace_event_count > 0
        || report.summary.relative_or_other_namespace_event_count > 0
        || report.summary.different_dos_drive_event_count > 0
    {
        report
            .diagnostics
            .push("different_namespaces_remain_unresolved");
    }
    if report.summary.cross_check_rejected_event_count > 0 {
        report
            .diagnostics
            .push("raw_cross_check_rejected_file_name_events");
    }
    if report.root_dos_drive_prefix.is_none() {
        report
            .diagnostics
            .push("selected_root_is_not_a_dos_drive_path");
    }
    if report.association_status == "insufficient_evidence" {
        report
            .diagnostics
            .push("no_same_namespace_exact_path_candidate_was_observed");
    }
    report
        .diagnostics
        .push("runtime_capture_completeness_is_unknown");

    let all_associations = std::mem::take(&mut report.associations);
    let mut used = serde_json::to_vec(&report)
        .map_err(|_| "could not size Windows association report".to_owned())?
        .len()
        .saturating_add(128);
    for association in all_associations {
        let item_bytes = serde_json::to_vec(&association)
            .map_err(|_| "could not size Windows association row".to_owned())?
            .len();
        let added = item_bytes.saturating_add(usize::from(!report.associations.is_empty()));
        if used.saturating_add(added) > MAX_ASSOCIATION_REPORT_BYTES {
            report.associations_omitted_to_output_limit = report
                .associations_omitted_to_output_limit
                .saturating_add(1);
            report.evidence_references_omitted_to_output_limit = report
                .evidence_references_omitted_to_output_limit
                .saturating_add(association.runtime_evidence.len());
        } else {
            used = used.saturating_add(added);
            report.associations.push(association);
        }
    }
    if report.associations_omitted_to_output_limit > 0
        || report.evidence_references_omitted_to_output_limit > 0
    {
        report.status = "partial";
        report.diagnostics.push("association_output_limit_reached");
    }
    report.summary.candidate_match_count = report.associations.len();
    Ok(report)
}

fn file_path_input<'a>(event: &'a NativeRuntimeEvent, raw_payload: &'a [u8]) -> FilePathInput<'a> {
    FilePathInput {
        provider_guid: &event.provider_guid,
        event_id: event.event_id,
        event_version: event.event_version,
        opcode: event.opcode,
        header_flags: event.header_flags,
        event_kind: &event.event_kind,
        raw_payload,
        serialized_decoding: event.observation_decoding.as_ref(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathNamespace {
    DosDrive,
    NtDevice,
    Unc,
    Verbatim,
    RelativeOrOther,
}

fn classify_path_units(units: &[u16]) -> PathNamespace {
    if dos_drive_prefix(units).is_some() {
        return PathNamespace::DosDrive;
    }
    if starts_with_ascii_case_insensitive(units, r"\Device\")
        || starts_with_ascii_case_insensitive(units, r"\??\")
    {
        return PathNamespace::NtDevice;
    }
    if starts_with_ascii(units, r"\\?\") {
        return PathNamespace::Verbatim;
    }
    if starts_with_ascii(units, r"\\") {
        return PathNamespace::Unc;
    }
    PathNamespace::RelativeOrOther
}

fn dos_drive_prefix(units: &[u16]) -> Option<[u16; 2]> {
    if units.len() < 3
        || !u16_to_ascii(units[0]).is_some_and(|value| value.is_ascii_alphabetic())
        || units[1] != u16::from(b':')
        || units[2] != u16::from(b'\\')
    {
        return None;
    }
    Some([units[0], units[1]])
}

fn drive_prefix_text(prefix: [u16; 2]) -> String {
    let letter = u16_to_ascii(prefix[0]).unwrap_or(b'?') as char;
    format!("{letter}:\\")
}

fn exact_child_path(root: &[u16], name_hex: &str, max_name_units: usize) -> Option<Vec<u16>> {
    let name = decode_utf16le_hex(name_hex, max_name_units)?;
    if name.is_empty()
        || name.contains(&u16::from(b'\\'))
        || name.contains(&u16::from(b'/'))
        || name == [u16::from(b'.')]
        || name == [u16::from(b'.'), u16::from(b'.')]
        || name.iter().any(|unit| {
            u16_to_ascii(*unit).is_some_and(|value| {
                value == b'"'
                    || value == b'%'
                    || value == b'*'
                    || value == b'?'
                    || value == b'<'
                    || value == b'>'
                    || value == b'|'
                    || value < 0x20
            })
        })
        || name.contains(&0)
    {
        return None;
    }
    if dos_drive_prefix(root).is_none() || root.len() > MAX_PATH_UTF16_UNITS {
        return None;
    }
    let mut path = root.to_vec();
    if !path.ends_with(&[u16::from(b'\\')]) {
        path.push(u16::from(b'\\'));
    }
    path.extend_from_slice(&name);
    (path.len() <= MAX_PATH_UTF16_UNITS).then_some(path)
}

fn decode_utf16le_hex(value: &str, max_units: usize) -> Option<Vec<u16>> {
    if value.is_empty() || value.len() % 4 != 0 || value.len() > max_units.saturating_mul(4) {
        return None;
    }
    let mut units = Vec::with_capacity(value.len() / 4);
    for chunk in value.as_bytes().chunks_exact(4) {
        let low = decode_hex_byte(chunk[0], chunk[1])?;
        let high = decode_hex_byte(chunk[2], chunk[3])?;
        units.push(u16::from_le_bytes([low, high]));
    }
    Some(units)
}

fn decode_hex_byte(high: u8, low: u8) -> Option<u8> {
    let high = (high as char).to_digit(16)?;
    let low = (low as char).to_digit(16)?;
    Some(((high << 4) | low) as u8)
}

fn decode_payload_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 || value.len() > 2 * 1024 * 1024 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| decode_hex_byte(pair[0], pair[1]))
        .collect()
}

fn starts_with_ascii(units: &[u16], prefix: &str) -> bool {
    let prefix = prefix.encode_utf16().collect::<Vec<_>>();
    units.starts_with(&prefix)
}

fn starts_with_ascii_case_insensitive(units: &[u16], prefix: &str) -> bool {
    let prefix = prefix.encode_utf16().collect::<Vec<_>>();
    units.len() >= prefix.len()
        && units.iter().zip(prefix.iter()).all(|(left, right)| {
            u16_to_ascii(*left)
                .zip(u16_to_ascii(*right))
                .is_some_and(|(left, right)| left.eq_ignore_ascii_case(&right))
        })
}

fn u16_to_ascii(unit: u16) -> Option<u8> {
    u8::try_from(unit).ok().filter(|value| value.is_ascii())
}

fn utf16le_hex(units: &[u16]) -> String {
    let mut encoded = String::with_capacity(units.len().saturating_mul(4));
    for unit in units {
        for byte in unit.to_le_bytes() {
            write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
    }
    encoded
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod synthetic_tests {
    use super::*;
    use crate::inventory::root_snapshot_diff::{
        RootSnapshotDelta, RootSnapshotDiff, RootSnapshotDiffCounts,
    };
    use crate::record::windows_io_decode::{DecodeStatus, PointerWidth, decode_classic_event};
    use crate::windows_runtime::{
        AppliedLimits, CollectionStatus, EventLoss, SessionMetadata, StopReason, TargetOutcome,
        WindowsRuntimeCapture,
    };

    fn capture(path: &str, alter_sidecar: bool) -> Vec<u8> {
        let mut payload = vec![0; 8];
        for unit in path.encode_utf16().chain(std::iter::once(0)) {
            payload.extend_from_slice(&unit.to_le_bytes());
        }
        let decoded = decode_classic_event(
            "90cbdc39-4a3e-11d1-84f4-0000f80464e3",
            0,
            2,
            CREATE_NAME_OPCODE,
            Some(PointerWidth::Bits64),
            &payload,
        );
        assert_eq!(decoded.status, DecodeStatus::Decoded);
        let mut sidecar = serde_json::to_value(decoded).unwrap();
        if alter_sidecar {
            sidecar["observation"]["activity"]["observation"]["path"] =
                serde_json::json!("C:\\root\\different.txt");
        }
        let mut capture = WindowsRuntimeCapture {
            schema: crate::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
            schema_version: 3,
            platform: "windows".to_owned(),
            capture_profile: "synthetic_fixture".to_owned(),
            collection_status: CollectionStatus::Partial,
            capture_completeness: "unknown".to_owned(),
            started_at_unix_ms: 1,
            ended_at_unix_ms: 2,
            requested_duration_seconds: 1,
            stop_reason: StopReason::DurationLimitReached,
            target: TargetOutcome {
                process_id: 7,
                exit_code: None,
                status_available: false,
            },
            session: SessionMetadata {
                name: "synthetic".to_owned(),
                provider: "synthetic".to_owned(),
                scope: "synthetic_fixture_only".to_owned(),
                buffer_size_kb_requested: 16,
                minimum_buffers_requested: 1,
                maximum_buffers_requested: 1,
                buffer_count_reported: 0,
                provider_process_id_header_semantics: "context_only".to_owned(),
            },
            limits: AppliedLimits {
                maximum_duration_seconds: 60,
                maximum_events: 50_000,
                maximum_total_payload_bytes: 8 * 1024 * 1024,
                maximum_payload_bytes_per_event: 64 * 1024,
                maximum_document_bytes: 32 * 1024 * 1024,
            },
            event_loss: EventLoss {
                events_lost: 0,
                log_buffers_lost: 0,
                real_time_buffers_lost: 0,
                loss_statistics_available: true,
                observation: "zero_reported".to_owned(),
                final_snapshot_available: true,
            },
            document_sha256: String::new(),
            events: vec![NativeRuntimeEvent {
                record_ordinal: 1,
                provider_guid: "90cbdc39-4a3e-11d1-84f4-0000f80464e3".to_owned(),
                event_id: 0,
                event_version: 2,
                opcode: CREATE_NAME_OPCODE,
                event_kind: "file_io_observation".to_owned(),
                header_process_id: 7,
                header_thread_id: 9,
                header_flags: 0x0040,
                timestamp_qpc: 10,
                raw_payload_hex: hex(&payload),
                payload_decoding: None,
                observation_decoding: Some(sidecar),
            }],
            diagnostics: vec![],
        };
        capture.document_sha256.clear();
        capture.document_sha256 = sha256_hex(&serde_json::to_vec(&capture).unwrap());
        serde_json::to_vec(&capture).unwrap()
    }

    fn diff(root: &str) -> RootSnapshotDiff {
        let name = "new.txt";
        RootSnapshotDiff {
            schema: "sideeffect.selected_root_inventory_diff",
            schema_version: 1,
            platform: "windows",
            status: "complete",
            root_path_identity_hex: utf16le_hex(&root.encode_utf16().collect::<Vec<_>>()),
            root_path_encoding: "utf16le_hex",
            root_identity_hint_conflict: false,
            coverage_note: "synthetic fixture",
            counts: RootSnapshotDiffCounts::default(),
            diagnostics: vec![],
            deltas: vec![RootSnapshotDelta {
                kind: "added",
                name: name.to_owned(),
                name_identity_hex: utf16le_hex(&name.encode_utf16().collect::<Vec<_>>()),
                changed_fields: vec![],
                unknown_fields: vec![],
                before: None,
                after: None,
            }],
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn same_exact_dos_spelling_emits_candidate_with_capture_and_raw_row_references() {
        let bytes = capture("C:\\root\\new.txt", false);
        let artifact_digest = sha256_hex(&bytes);
        let report = associate_windows_root_runtime_diff(&diff("C:\\root"), &bytes).unwrap();
        assert_eq!(report.associations.len(), 1);
        assert_eq!(report.associations[0].candidate_path, "C:\\root\\new.txt");
        assert_eq!(report.associations[0].status, "candidate_match");
        let evidence = &report.associations[0].runtime_evidence[0];
        assert_eq!(evidence.json_pointer, "/events/0");
        assert_eq!(evidence.record_ordinal, 1);
        assert_eq!(
            evidence.capture_document_sha256,
            report.capture_document_sha256
        );
        assert_eq!(report.capture_artifact_sha256, artifact_digest);
        assert_eq!(evidence.raw_payload_sha256.len(), 64);
    }

    #[test]
    fn mismatched_sidecar_and_different_drive_spelling_remain_unresolved() {
        let mismatched = capture("C:\\root\\new.txt", true);
        let report = associate_windows_root_runtime_diff(&diff("C:\\root"), &mismatched).unwrap();
        assert!(report.associations.is_empty());
        assert_eq!(report.summary.cross_check_rejected_event_count, 1);

        let different_case = capture("c:\\root\\new.txt", false);
        let report =
            associate_windows_root_runtime_diff(&diff("C:\\root"), &different_case).unwrap();
        assert!(report.associations.is_empty());
        assert_eq!(report.summary.different_dos_drive_event_count, 1);
    }

    #[test]
    fn unsupported_namespaces_are_classified_without_mapping() {
        let device = r"\Device\HarddiskVolume1\root\new.txt"
            .encode_utf16()
            .collect::<Vec<_>>();
        let unc = r"\\server\share\new.txt".encode_utf16().collect::<Vec<_>>();
        let verbatim = r"\\?\C:\root\new.txt".encode_utf16().collect::<Vec<_>>();
        assert_eq!(classify_path_units(&device), PathNamespace::NtDevice);
        assert_eq!(classify_path_units(&unc), PathNamespace::Unc);
        assert_eq!(classify_path_units(&verbatim), PathNamespace::Verbatim);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_hex(value: &str) -> String {
        utf16le_hex(&value.encode_utf16().collect::<Vec<_>>())
    }

    #[test]
    fn exact_dos_drive_utf16_units_match_without_normalization() {
        let root = r"C:\Synthetic\ObservationRoot";
        let candidate = exact_child_path(
            &root.encode_utf16().collect::<Vec<_>>(),
            &utf16_hex("fixture.txt"),
            MAX_NAME_UTF16_UNITS,
        )
        .unwrap();
        assert_eq!(
            String::from_utf16(&candidate).unwrap(),
            r"C:\Synthetic\ObservationRoot\fixture.txt"
        );
        assert!(classify_path_units(&candidate) == PathNamespace::DosDrive);

        let lower_case = r"c:\synthetic\observationroot\fixture.txt"
            .encode_utf16()
            .collect::<Vec<_>>();
        assert_ne!(candidate, lower_case);
    }

    #[test]
    fn nt_device_unc_verbatim_and_relative_paths_are_unresolved() {
        let units = |value: &str| value.encode_utf16().collect::<Vec<_>>();
        assert_eq!(
            classify_path_units(&units(r"\Device\HarddiskVolume3\dir\a.txt")),
            PathNamespace::NtDevice
        );
        assert_eq!(
            classify_path_units(&units(r"\\server\share\a.txt")),
            PathNamespace::Unc
        );
        assert_eq!(
            classify_path_units(&units(r"\\?\C:\dir\a.txt")),
            PathNamespace::Verbatim
        );
        assert_eq!(
            classify_path_units(&units(r"relative\a.txt")),
            PathNamespace::RelativeOrOther
        );
    }

    #[test]
    fn different_dos_drive_spelling_is_not_the_same_namespace() {
        let candidate_root = r"C:\Synthetic".encode_utf16().collect::<Vec<_>>();
        let observe = |path: &str| {
            let units = path.encode_utf16().collect::<Vec<_>>();
            dos_drive_prefix(&units) == dos_drive_prefix(&candidate_root)
        };
        assert!(observe(r"C:\Synthetic\fixture.txt"));
        assert!(!observe(r"D:\Synthetic\fixture.txt"));
        assert!(!observe(r"c:\Synthetic\fixture.txt"));
    }

    #[test]
    fn malformed_or_unsafe_child_identities_are_rejected() {
        let root = r"C:\Synthetic".encode_utf16().collect::<Vec<_>>();
        assert!(exact_child_path(&root, "", MAX_NAME_UTF16_UNITS).is_none());
        assert!(exact_child_path(&root, "00", MAX_NAME_UTF16_UNITS).is_none());
        assert!(
            exact_child_path(&root, &utf16_hex(r"sub\file.txt"), MAX_NAME_UTF16_UNITS).is_none()
        );
        assert!(exact_child_path(&root, &utf16_hex(".."), MAX_NAME_UTF16_UNITS).is_none());
        assert!(
            exact_child_path(
                &root,
                &utf16_hex(&"a".repeat(MAX_NAME_UTF16_UNITS + 1)),
                MAX_NAME_UTF16_UNITS
            )
            .is_none()
        );
    }

    #[test]
    fn selected_root_must_be_a_dos_drive_path() {
        assert_eq!(
            dos_drive_prefix(
                &r"\Device\HarddiskVolume3"
                    .encode_utf16()
                    .collect::<Vec<_>>()
            ),
            None
        );
        assert_eq!(
            dos_drive_prefix(&r"C:/Synthetic".encode_utf16().collect::<Vec<_>>()),
            None
        );
        assert_eq!(
            dos_drive_prefix(&r"C:\".encode_utf16().collect::<Vec<_>>()),
            Some([u16::from(b'C'), u16::from(b':')])
        );
    }
}
