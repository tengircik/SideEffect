//! Exact lexical candidate linking between Windows selected-root deltas and
//! raw-cross-checked ETW FileIo name records.
//!
//! Legacy matching only compares drive-rooted paths with the same exact DOS
//! drive spelling. The separate v19 NT matcher requires a stable path and root
//! identity from the held root handles. Neither matcher establishes success,
//! ownership, mutation, or cause.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::inventory::windows_root_namespace::WindowsRootNamespaceDocument;
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

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRootNamespaceRuntimeAssociationReport {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub status: &'static str,
    pub association_status: &'static str,
    pub capture_completeness: &'static str,
    pub claim: &'static str,
    pub root_diff_status: String,
    pub root_namespace_artifact_sha256: String,
    pub before_root_artifact_sha256: String,
    pub after_root_artifact_sha256: String,
    pub capture_artifact_sha256: String,
    pub capture_document_sha256: String,
    pub summary: WindowsRootNamespaceRuntimeAssociationSummary,
    pub diagnostics: Vec<&'static str>,
    pub limitations: Vec<&'static str>,
    pub associations_omitted_to_output_limit: usize,
    pub evidence_references_omitted_to_output_limit: usize,
    pub associations: Vec<WindowsRootNamespaceRuntimeAssociation>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRootNamespaceRuntimeAssociationSummary {
    pub delta_count: usize,
    pub raw_checked_nt_device_event_count: usize,
    pub raw_cross_check_rejected_event_count: usize,
    pub opposite_direction_event_count: usize,
    pub runtime_observation_rows_omitted_to_limit: usize,
    pub candidate_match_count: usize,
    pub ambiguous_candidate_count: usize,
    pub unmatched_delta_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRootNamespaceRuntimeAssociation {
    pub status: &'static str,
    pub candidate_path_namespace: &'static str,
    pub candidate_path_utf16le_hex: String,
    pub delta_kind: String,
    pub delta_name_identity_hex: String,
    pub etw_operation: &'static str,
    pub multiple_runtime_observations: bool,
    pub evidence_truncated: bool,
    pub runtime_evidence: Vec<WindowsRootRuntimeEvidence>,
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

/// Find exact NT-device path candidates using a v19 pair of namespace records
/// tied to the verified before/after selected-root artifact digests.
#[allow(clippy::too_many_arguments)]
pub fn associate_windows_root_namespace_runtime_diff(
    diff: &super::root_snapshot_diff::RootSnapshotDiff,
    capture_bytes: &[u8],
    namespace: &WindowsRootNamespaceDocument,
    namespace_artifact_sha256: &str,
    before_root_bytes: &[u8],
    before_root_sha256: &str,
    after_root_bytes: &[u8],
    after_root_sha256: &str,
) -> Result<WindowsRootNamespaceRuntimeAssociationReport, String> {
    if diff.platform != "windows" {
        return Err("NT root/runtime association requires a Windows selected-root diff".to_owned());
    }
    let capture = inspect_windows_runtime_bytes(capture_bytes)?;
    let capture_artifact_sha256 = sha256_hex(capture_bytes);
    let capture_document_sha256 = capture.document_sha256.clone();
    let mut diagnostics = Vec::new();
    let before_root = root_namespace_snapshot_identity(before_root_bytes);
    let after_root = root_namespace_snapshot_identity(after_root_bytes);
    let before = &namespace.before;
    let after = &namespace.after;
    let namespace_linked = is_sha256(namespace_artifact_sha256)
        && before.root_snapshot_sha256 == before_root_sha256
        && after.root_snapshot_sha256 == after_root_sha256
        && before.root_path_utf16le_hex.as_deref() == Some(diff.root_path_identity_hex.as_str())
        && after.root_path_utf16le_hex.as_deref() == Some(diff.root_path_identity_hex.as_str())
        && before_root.as_ref().is_some_and(|identity| {
            Some(identity.path_hex.as_str()) == before.root_path_utf16le_hex.as_deref()
                && identity.volume_serial == before.volume_serial
                && identity.file_index == before.file_index
        })
        && after_root.as_ref().is_some_and(|identity| {
            Some(identity.path_hex.as_str()) == after.root_path_utf16le_hex.as_deref()
                && identity.volume_serial == after.volume_serial
                && identity.file_index == after.file_index
        });
    if !namespace_linked {
        diagnostics.push("root_namespace_artifact_reference_mismatch");
    }
    let root_stable = namespace.status == "complete"
        && before.status == "observed"
        && after.status == "observed"
        && before.nt_path_utf16le_hex.is_some()
        && before.nt_path_utf16le_hex == after.nt_path_utf16le_hex
        && before.volume_serial.is_some_and(|value| value != 0)
        && before.volume_serial == after.volume_serial
        && before.file_index.is_some_and(|value| value != 0)
        && before.file_index == after.file_index
        && !diff.root_identity_hint_conflict;
    if !root_stable {
        if diff.root_identity_hint_conflict
            || before.nt_path_utf16le_hex != after.nt_path_utf16le_hex
            || before.volume_serial != after.volume_serial
            || before.file_index != after.file_index
        {
            diagnostics.push("root_namespace_or_identity_changed");
        } else {
            diagnostics.push("root_namespace_identity_unavailable");
        }
    }
    let root_units = before
        .nt_path_utf16le_hex
        .as_deref()
        .and_then(|value| decode_utf16le_hex(value, MAX_PATH_UTF16_UNITS));
    let root_units = root_units.filter(|units| is_hard_device_path(units));
    if root_units.is_none() {
        diagnostics.push("root_nt_device_namespace_unsupported");
    }
    let can_match = namespace_linked && root_stable && root_units.is_some();

    let mut observed = BTreeMap::<Vec<u16>, Vec<WindowsRootRuntimeEvidence>>::new();
    let mut raw_checked_nt_device_event_count = 0usize;
    let mut raw_cross_check_rejected_event_count = 0usize;
    let mut opposite_direction_event_count = 0usize;
    let mut runtime_observation_rows_omitted_to_limit = 0usize;
    let mut retained_observation_count = 0usize;
    if can_match {
        for (event_index, event) in capture.events.iter().enumerate() {
            let operation = match event.opcode {
                CREATE_NAME_OPCODE => "create_name",
                DELETE_NAME_OPCODE => "delete_name",
                _ => continue,
            };
            if event.event_kind != "file_io_observation" {
                continue;
            }
            let Some(payload) = decode_payload_hex(&event.raw_payload_hex) else {
                raw_cross_check_rejected_event_count =
                    raw_cross_check_rejected_event_count.saturating_add(1);
                continue;
            };
            let path = match cross_check_file_path(file_path_input(event, &payload)) {
                FilePathCrossCheck::Matched(Some(path)) => path,
                FilePathCrossCheck::Matched(None)
                | FilePathCrossCheck::Mismatch
                | FilePathCrossCheck::Unsupported
                | FilePathCrossCheck::Malformed
                | FilePathCrossCheck::NotFileProvider => {
                    raw_cross_check_rejected_event_count =
                        raw_cross_check_rejected_event_count.saturating_add(1);
                    continue;
                }
            };
            let path_units = path.encode_utf16().collect::<Vec<_>>();
            if !is_hard_device_path(&path_units) {
                continue;
            }
            raw_checked_nt_device_event_count = raw_checked_nt_device_event_count.saturating_add(1);
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
    }

    let mut associations = Vec::new();
    let mut delta_count = 0usize;
    let mut ambiguous_candidate_count = 0usize;
    let mut unmatched_delta_count = 0usize;
    let mut associations_omitted_to_output_limit = 0usize;
    let mut evidence_references_omitted_to_output_limit = 0usize;
    let mut association_evidence_reference_count = 0usize;
    if can_match {
        for delta in &diff.deltas {
            let operation = match delta.kind {
                "added" | "changed" => "create_name",
                "removed" => "delete_name",
                _ => continue,
            };
            delta_count = delta_count.saturating_add(1);
            let Some(candidate_path) = root_units.as_deref().and_then(|root| {
                exact_nt_child_path(root, &delta.name_identity_hex, MAX_NAME_UTF16_UNITS)
            }) else {
                unmatched_delta_count = unmatched_delta_count.saturating_add(1);
                continue;
            };
            let Some(evidence) = observed.get(&candidate_path) else {
                unmatched_delta_count = unmatched_delta_count.saturating_add(1);
                continue;
            };
            let compatible_evidence = evidence
                .iter()
                .filter(|row| row.etw_operation == operation)
                .collect::<Vec<_>>();
            opposite_direction_event_count = opposite_direction_event_count
                .saturating_add(evidence.len().saturating_sub(compatible_evidence.len()));
            if compatible_evidence.is_empty() {
                unmatched_delta_count = unmatched_delta_count.saturating_add(1);
                continue;
            }
            if associations.len() >= MAX_ASSOCIATIONS {
                associations_omitted_to_output_limit =
                    associations_omitted_to_output_limit.saturating_add(1);
                evidence_references_omitted_to_output_limit =
                    evidence_references_omitted_to_output_limit.saturating_add(evidence.len());
                continue;
            }
            if association_evidence_reference_count >= MAX_EVIDENCE_REFS {
                associations_omitted_to_output_limit =
                    associations_omitted_to_output_limit.saturating_add(1);
                evidence_references_omitted_to_output_limit =
                    evidence_references_omitted_to_output_limit.saturating_add(evidence.len());
                continue;
            }
            if compatible_evidence.len() > 1 {
                ambiguous_candidate_count = ambiguous_candidate_count.saturating_add(1);
            }
            let evidence_truncated = runtime_observation_rows_omitted_to_limit > 0;
            let retained_evidence = compatible_evidence
                .len()
                .min(MAX_REFS_PER_ASSOCIATION)
                .min(MAX_EVIDENCE_REFS.saturating_sub(association_evidence_reference_count));
            evidence_references_omitted_to_output_limit =
                evidence_references_omitted_to_output_limit
                    .saturating_add(compatible_evidence.len().saturating_sub(retained_evidence));
            association_evidence_reference_count =
                association_evidence_reference_count.saturating_add(retained_evidence);
            associations.push(WindowsRootNamespaceRuntimeAssociation {
                status: if compatible_evidence.len() > 1 {
                    "ambiguous_candidate_match"
                } else if evidence_truncated {
                    "partial_candidate_match"
                } else {
                    "candidate_match"
                },
                candidate_path_namespace: "nt_device",
                candidate_path_utf16le_hex: utf16le_hex(&candidate_path),
                delta_kind: delta.kind.to_owned(),
                delta_name_identity_hex: delta.name_identity_hex.clone(),
                etw_operation: operation,
                multiple_runtime_observations: compatible_evidence.len() > 1 || evidence_truncated,
                evidence_truncated,
                runtime_evidence: compatible_evidence
                    .into_iter()
                    .take(retained_evidence)
                    .cloned()
                    .collect(),
            });
        }
    } else {
        delta_count = diff
            .deltas
            .iter()
            .filter(|delta| matches!(delta.kind, "added" | "changed" | "removed"))
            .count();
        unmatched_delta_count = delta_count;
    }

    let mut report = WindowsRootNamespaceRuntimeAssociationReport {
        schema: "sideeffect.windows_root_nt_runtime_association",
        schema_version: 1,
        platform: "windows",
        status: "partial",
        association_status: if associations.is_empty() {
            "insufficient_evidence"
        } else {
            "candidate_match"
        },
        capture_completeness: "unknown",
        claim: "exact_stable_held_handle_nt_device_path_candidate_only_no_success_ownership_or_causation",
        root_diff_status: diff.status.to_owned(),
        root_namespace_artifact_sha256: namespace_artifact_sha256.to_owned(),
        before_root_artifact_sha256: before_root_sha256.to_owned(),
        after_root_artifact_sha256: after_root_sha256.to_owned(),
        capture_artifact_sha256,
        capture_document_sha256,
        summary: WindowsRootNamespaceRuntimeAssociationSummary {
            delta_count,
            raw_checked_nt_device_event_count,
            raw_cross_check_rejected_event_count,
            opposite_direction_event_count,
            runtime_observation_rows_omitted_to_limit,
            candidate_match_count: 0,
            ambiguous_candidate_count,
            unmatched_delta_count,
        },
        diagnostics,
        limitations: vec![
            "This NT namespace comparison is emitted only for a v19 session and requires exact same-handle NT root paths and nonzero volume/file-index hints at both endpoints.",
            "Only raw-cross-checked NT device path code units are compared; DOS, volume-GUID, UNC, verbatim, and other namespaces are not translated or normalized.",
            "Added or changed selected-root rows compare only with create_name; removed rows compare only with delete_name. FileIo name observations do not establish success or mutation.",
            "A path candidate does not identify a process, establish ownership, or show that the runtime event caused the selected-root delta.",
            "Volume/file-index hints are point-in-time identities, not durable identities; the system-wide ETW capture remains incomplete or unknown.",
        ],
        associations_omitted_to_output_limit,
        evidence_references_omitted_to_output_limit,
        associations,
    };
    let candidates = std::mem::take(&mut report.associations);
    let mut used = serde_json::to_vec(&report)
        .map_err(|_| "could not size NT association report".to_owned())?
        .len()
        .saturating_add(128);
    for association in candidates {
        let added = serde_json::to_vec(&association)
            .map_err(|_| "could not size NT association row".to_owned())?
            .len()
            .saturating_add(usize::from(!report.associations.is_empty()));
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
        || runtime_observation_rows_omitted_to_limit > 0
    {
        report.diagnostics.push("association_output_limit_reached");
    }
    report.summary.candidate_match_count = report.associations.len();
    Ok(report)
}

struct RootNamespaceSnapshotIdentity {
    path_hex: String,
    volume_serial: Option<u64>,
    file_index: Option<u64>,
}

fn root_namespace_snapshot_identity(bytes: &[u8]) -> Option<RootNamespaceSnapshotIdentity> {
    if bytes.is_empty() || bytes.len() > 32 * 1024 * 1024 {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let root = value.get("root")?.as_object()?;
    Some(RootNamespaceSnapshotIdentity {
        path_hex: root.get("path_utf16le_hex")?.as_str()?.to_owned(),
        volume_serial: root.get("device_or_volume_serial")?.as_u64(),
        file_index: root.get("inode_or_file_index")?.as_u64(),
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_hard_device_path(units: &[u16]) -> bool {
    starts_with_ascii_case_insensitive(units, r"\Device\")
        && units.len() > r"\Device\".encode_utf16().count()
        && !units.contains(&u16::from(b'/'))
        && !units.contains(&0)
}

fn exact_nt_child_path(root: &[u16], name_hex: &str, max_name_units: usize) -> Option<Vec<u16>> {
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
        || !is_hard_device_path(root)
        || root.len() > MAX_PATH_UTF16_UNITS
    {
        return None;
    }
    let mut path = root.to_vec();
    if !path.ends_with(&[u16::from(b'\\')]) {
        path.push(u16::from(b'\\'));
    }
    path.extend_from_slice(&name);
    (path.len() <= MAX_PATH_UTF16_UNITS).then_some(path)
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
        capture_with_opcode(path, CREATE_NAME_OPCODE, alter_sidecar)
    }

    fn capture_with_opcode(path: &str, opcode: u8, alter_sidecar: bool) -> Vec<u8> {
        capture_with_opcodes(path, &[opcode], alter_sidecar)
    }

    fn capture_with_opcodes(path: &str, opcodes: &[u8], alter_sidecar: bool) -> Vec<u8> {
        let mut payload = vec![0; 8];
        for unit in path.encode_utf16().chain(std::iter::once(0)) {
            payload.extend_from_slice(&unit.to_le_bytes());
        }
        let events = opcodes
            .iter()
            .enumerate()
            .map(|(index, opcode)| {
                let decoded = decode_classic_event(
                    "90cbdc39-4a3e-11d1-84f4-0000f80464e3",
                    0,
                    2,
                    *opcode,
                    Some(PointerWidth::Bits64),
                    &payload,
                );
                assert_eq!(decoded.status, DecodeStatus::Decoded);
                let mut sidecar = serde_json::to_value(decoded).unwrap();
                if alter_sidecar {
                    sidecar["observation"]["activity"]["observation"]["path"] =
                        serde_json::json!("C:\\root\\different.txt");
                }
                NativeRuntimeEvent {
                    record_ordinal: index as u64 + 1,
                    provider_guid: "90cbdc39-4a3e-11d1-84f4-0000f80464e3".to_owned(),
                    event_id: 0,
                    event_version: 2,
                    opcode: *opcode,
                    event_kind: "file_io_observation".to_owned(),
                    header_process_id: 7,
                    header_thread_id: 9,
                    header_flags: 0x0040,
                    timestamp_qpc: 10 + index as i64,
                    raw_payload_hex: hex(&payload),
                    payload_decoding: None,
                    observation_decoding: Some(sidecar),
                }
            })
            .collect();
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
            events,
            diagnostics: vec![],
        };
        capture.document_sha256.clear();
        capture.document_sha256 = sha256_hex(&serde_json::to_vec(&capture).unwrap());
        serde_json::to_vec(&capture).unwrap()
    }

    fn diff(root: &str) -> RootSnapshotDiff {
        diff_kind(root, "added")
    }

    fn diff_kind(root: &str, kind: &'static str) -> RootSnapshotDiff {
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
                kind,
                name: name.to_owned(),
                name_identity_hex: utf16le_hex(&name.encode_utf16().collect::<Vec<_>>()),
                changed_fields: vec![],
                unknown_fields: vec![],
                before: None,
                after: None,
            }],
        }
    }

    fn root_snapshot(path_hex: &str, volume: u64, file_index: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "root": {
                "path_utf16le_hex": path_hex,
                "device_or_volume_serial": volume,
                "inode_or_file_index": file_index
            }
        }))
        .unwrap()
    }

    fn namespace_document(
        path: &str,
        before_sha: &str,
        after_sha: &str,
    ) -> WindowsRootNamespaceDocument {
        let root_path_hex = utf16le_hex(&"C:\\root".encode_utf16().collect::<Vec<_>>());
        let nt_path_hex = utf16le_hex(&path.encode_utf16().collect::<Vec<_>>());
        WindowsRootNamespaceDocument::new(
            crate::inventory::WindowsRootNamespaceSide {
                status: "observed".to_owned(),
                root_snapshot_sha256: before_sha.to_owned(),
                root_path_utf16le_hex: Some(root_path_hex.clone()),
                nt_path_utf16le_hex: Some(nt_path_hex.clone()),
                volume_serial: Some(7),
                file_index: Some(11),
            },
            crate::inventory::WindowsRootNamespaceSide {
                status: "observed".to_owned(),
                root_snapshot_sha256: after_sha.to_owned(),
                root_path_utf16le_hex: Some(root_path_hex),
                nt_path_utf16le_hex: Some(nt_path_hex),
                volume_serial: Some(7),
                file_index: Some(11),
            },
        )
    }

    fn associate_nt(
        diff: &RootSnapshotDiff,
        capture: &[u8],
        namespace: &WindowsRootNamespaceDocument,
        before_root: &[u8],
        after_root: &[u8],
    ) -> WindowsRootNamespaceRuntimeAssociationReport {
        let before_sha = sha256_hex(before_root);
        let after_sha = sha256_hex(after_root);
        associate_windows_root_namespace_runtime_diff(
            diff,
            capture,
            namespace,
            &"e".repeat(64),
            before_root,
            &before_sha,
            after_root,
            &after_sha,
        )
        .unwrap()
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

    #[test]
    fn v19_stable_held_handle_nt_path_emits_raw_evidence_candidate() {
        let root = r"\Device\HarddiskVolume3\dir";
        let before = root_snapshot(
            &utf16le_hex(&"C:\\root".encode_utf16().collect::<Vec<_>>()),
            7,
            11,
        );
        let after = root_snapshot(
            &utf16le_hex(&"C:\\root".encode_utf16().collect::<Vec<_>>()),
            7,
            11,
        );
        let namespace = namespace_document(root, &sha256_hex(&before), &sha256_hex(&after));
        let capture = capture_with_opcode(
            r"\Device\HarddiskVolume3\dir\new.txt",
            CREATE_NAME_OPCODE,
            false,
        );
        let report = associate_nt(&diff(r"C:\root"), &capture, &namespace, &before, &after);
        assert_eq!(report.status, "partial");
        assert_eq!(report.association_status, "candidate_match");
        assert_eq!(report.associations.len(), 1);
        assert_eq!(report.associations[0].candidate_path_namespace, "nt_device");
        assert_eq!(report.associations[0].etw_operation, "create_name");
        assert_eq!(
            report.associations[0].runtime_evidence[0].json_pointer,
            "/events/0"
        );
        assert_eq!(report.summary.raw_checked_nt_device_event_count, 1);
    }

    #[test]
    fn v19_changed_root_namespace_or_identity_and_wrong_direction_are_unmatched() {
        let root = r"\Device\HarddiskVolume3\dir";
        let before = root_snapshot(
            &utf16le_hex(&"C:\\root".encode_utf16().collect::<Vec<_>>()),
            7,
            11,
        );
        let after = root_snapshot(
            &utf16le_hex(&"C:\\root".encode_utf16().collect::<Vec<_>>()),
            7,
            12,
        );
        let mut changed = namespace_document(root, &sha256_hex(&before), &sha256_hex(&after));
        changed.after.file_index = Some(12);
        let bytes = capture_with_opcode(
            r"\Device\HarddiskVolume3\dir\new.txt",
            CREATE_NAME_OPCODE,
            false,
        );
        let report = associate_nt(&diff(r"C:\root"), &bytes, &changed, &before, &after);
        assert!(report.associations.is_empty());
        assert!(
            report
                .diagnostics
                .contains(&"root_namespace_or_identity_changed")
        );

        let before = root_snapshot(
            &utf16le_hex(&"C:\\root".encode_utf16().collect::<Vec<_>>()),
            7,
            11,
        );
        let after = root_snapshot(
            &utf16le_hex(&"C:\\root".encode_utf16().collect::<Vec<_>>()),
            7,
            11,
        );
        let namespace = namespace_document(root, &sha256_hex(&before), &sha256_hex(&after));
        let delete_capture = capture_with_opcode(
            r"\Device\HarddiskVolume3\dir\new.txt",
            DELETE_NAME_OPCODE,
            false,
        );
        let report = associate_nt(
            &diff_kind(r"C:\root", "added"),
            &delete_capture,
            &namespace,
            &before,
            &after,
        );
        assert!(report.associations.is_empty());
        assert_eq!(report.summary.unmatched_delta_count, 1);
    }

    #[test]
    fn v19_opposite_direction_rows_do_not_suppress_a_compatible_candidate() {
        let root = r"\Device\HarddiskVolume3\dir";
        let before = root_snapshot(
            &utf16le_hex(&"C:\\root".encode_utf16().collect::<Vec<_>>()),
            7,
            11,
        );
        let after = root_snapshot(
            &utf16le_hex(&"C:\\root".encode_utf16().collect::<Vec<_>>()),
            7,
            11,
        );
        let namespace = namespace_document(root, &sha256_hex(&before), &sha256_hex(&after));
        let capture = capture_with_opcodes(
            r"\Device\HarddiskVolume3\dir\new.txt",
            &[CREATE_NAME_OPCODE, DELETE_NAME_OPCODE],
            false,
        );
        let report = associate_nt(
            &diff_kind(r"C:\root", "added"),
            &capture,
            &namespace,
            &before,
            &after,
        );
        assert_eq!(report.associations.len(), 1);
        assert_eq!(report.associations[0].status, "candidate_match");
        assert_eq!(report.associations[0].runtime_evidence.len(), 1);
        assert_eq!(
            report.associations[0].runtime_evidence[0].etw_operation,
            "create_name"
        );
        assert_eq!(report.summary.opposite_direction_event_count, 1);
    }

    #[test]
    fn v19_namespace_artifact_digest_and_root_path_links_are_required() {
        let root = r"\Device\HarddiskVolume3\dir";
        let before = root_snapshot(
            &utf16le_hex(&"C:\\root".encode_utf16().collect::<Vec<_>>()),
            7,
            11,
        );
        let after = root_snapshot(
            &utf16le_hex(&"C:\\root".encode_utf16().collect::<Vec<_>>()),
            7,
            11,
        );
        let namespace = namespace_document(root, &sha256_hex(&before), &sha256_hex(&after));
        let bytes = capture(r"\Device\HarddiskVolume3\dir\new.txt", false);
        let mut wrong_link = namespace.clone();
        wrong_link.before.root_snapshot_sha256 = "0".repeat(64);
        let report = associate_nt(&diff(r"C:\root"), &bytes, &wrong_link, &before, &after);
        assert!(report.associations.is_empty());
        assert!(
            report
                .diagnostics
                .contains(&"root_namespace_artifact_reference_mismatch")
        );

        let mut wrong_input_path = namespace;
        wrong_input_path.after.root_path_utf16le_hex =
            Some(utf16le_hex(&"D:\\root".encode_utf16().collect::<Vec<_>>()));
        let report = associate_nt(
            &diff(r"C:\root"),
            &bytes,
            &wrong_input_path,
            &before,
            &after,
        );
        assert!(report.associations.is_empty());
        assert!(
            report
                .diagnostics
                .contains(&"root_namespace_artifact_reference_mismatch")
        );
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
