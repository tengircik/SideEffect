//! Conservative lexical comparison of selected-root deltas with traced writes.
//! A match is a path candidate only; it does not identify a process or establish cause.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::limits::ParseLimits;
use crate::model::{ParseCompleteness, SyscallOutcome, TraceRecordKind};
use crate::trace::strace::parse_trace_bytes;

const MAX_ASSOCIATIONS: usize = 20_000;
const MAX_EVIDENCE_REFS: usize = 50_000;
const MAX_ASSOCIATION_REPORT_BYTES: usize = 1024 * 1024;
const MAX_REFS_PER_ASSOCIATION: usize = 256;

#[derive(Clone, Debug, Serialize)]
pub struct RootRuntimeAssociationReport {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    /// The association output stays partial because capture completeness is unknown.
    pub status: &'static str,
    pub parse_comparison_status: &'static str,
    pub capture_completeness: &'static str,
    pub claim: &'static str,
    pub root_diff_status: String,
    pub trace_sha256: String,
    pub trace_parse_status: ParseCompleteness,
    pub trace_record_count: usize,
    pub summary: RootRuntimeAssociationSummary,
    pub associations_omitted_to_output_limit: usize,
    pub evidence_references_omitted_to_output_limit: usize,
    pub diagnostics: Vec<&'static str>,
    pub limitations: Vec<&'static str>,
    pub associations: Vec<RootRuntimeAssociation>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootRuntimeAssociationSummary {
    pub delta_count: usize,
    pub eligible_runtime_observation_count: usize,
    pub runtime_observation_rows_omitted_to_limit: usize,
    pub failed_or_unknown_write_intent_count: usize,
    pub candidate_match_count: usize,
    pub ambiguous_candidate_count: usize,
    pub unmatched_delta_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootRuntimeAssociation {
    pub status: &'static str,
    pub candidate_path: String,
    pub candidate_path_bytes_hex: String,
    pub delta_kind: String,
    pub delta_name_identity_hex: String,
    pub multiple_runtime_observations: bool,
    pub runtime_evidence: Vec<RootRuntimeEvidence>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootRuntimeEvidence {
    pub trace_sha256: String,
    pub syscall: String,
    /// `strace -f` prefix task/thread ID; it is not a stable process identity.
    pub caller_task_id: Option<u32>,
    pub line_number: u64,
    pub byte_offset: u64,
    pub byte_length: u64,
}

/// Compare an already validated selected-root delta with a bounded strace trace.
/// Only successful openat create/truncate operations with
/// parser-derived absolute lexical hints are eligible.
pub fn associate_root_runtime_diff(
    diff: &super::root_snapshot_diff::RootSnapshotDiff,
    trace_bytes: &[u8],
) -> Result<RootRuntimeAssociationReport, String> {
    if diff.platform != "linux" {
        return Err("root/runtime association supports Linux byte path namespaces only".to_owned());
    }
    let root_bytes = decode_hex(&diff.root_path_identity_hex)
        .ok_or_else(|| "selected-root exact path bytes are unavailable".to_owned())?;

    let trace = parse_trace_bytes(trace_bytes, ParseLimits::default())
        .map_err(|error| format!("trace parse failed: {error}"))?;
    let trace_hash = format!("{:x}", Sha256::digest(trace_bytes));
    let mut observed = BTreeMap::<Vec<u8>, Vec<RootRuntimeEvidence>>::new();
    let mut failed_or_unknown_write_intent_count = 0;
    let mut eligible_runtime_observation_count = 0usize;
    let mut runtime_observation_rows_omitted_to_limit = 0usize;
    for record in &trace.records {
        if record.kind != TraceRecordKind::Syscall {
            continue;
        }
        let syscall = match record.syscall.as_deref() {
            Some("openat") => "openat",
            _ => continue,
        };
        let Some(hint) = &record.lexical_path_hint else {
            continue;
        };
        let Some(args) = record.raw_arguments.as_deref().and_then(split_args) else {
            continue;
        };
        let Some(flags) = args.get(2) else { continue };
        let flag_tokens = flags.split('|').map(str::trim).collect::<Vec<_>>();
        if flag_tokens.contains(&"O_TMPFILE")
            || !flag_tokens
                .iter()
                .any(|flag| matches!(*flag, "O_CREAT" | "O_TRUNC"))
        {
            continue;
        }
        if record.outcome != Some(SyscallOutcome::Success) {
            failed_or_unknown_write_intent_count += 1;
            continue;
        }
        // The parser hint is usable here only when the source operand is an exact,
        // plain absolute spelling without path aliases or escapes.
        let Some(operand) = args.get(1) else {
            continue;
        };
        let Some(path) = operand.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
            continue;
        };
        if path != hint.path
            || !path.starts_with('/')
            || path.len() > 4095
            || path.contains('\\')
            || path.bytes().any(|b| !(0x20..=0x7e).contains(&b))
            || path.split('/').any(|part| part == "." || part == "..")
            || path.contains("//")
        {
            continue;
        }
        if eligible_runtime_observation_count >= MAX_EVIDENCE_REFS {
            runtime_observation_rows_omitted_to_limit += 1;
            continue;
        }
        eligible_runtime_observation_count += 1;
        observed
            .entry(hint.path.as_bytes().to_vec())
            .or_default()
            .push(RootRuntimeEvidence {
                trace_sha256: trace_hash.clone(),
                syscall: syscall.to_owned(),
                caller_task_id: record.process_id,
                line_number: record.evidence.line_number,
                byte_offset: record.evidence.byte_offset,
                byte_length: record.evidence.byte_length,
            });
    }
    let mut associations = Vec::new();
    let mut delta_count = 0;
    let mut unmatched = 0;
    let mut ambiguous = 0;
    let mut total_evidence_refs = 0usize;
    for delta in &diff.deltas {
        if !matches!(delta.kind, "added" | "changed") {
            continue;
        }
        delta_count += 1;
        let Some(name_bytes) = decode_hex(&delta.name_identity_hex) else {
            unmatched += 1;
            continue;
        };
        let mut full = root_bytes.clone();
        if !full.ends_with(b"/") {
            full.push(b'/');
        }
        full.extend_from_slice(&name_bytes);
        let Some(evidence) = observed.get(&full) else {
            unmatched += 1;
            continue;
        };
        if evidence.len() > 1 {
            ambiguous += 1;
        }
        total_evidence_refs = total_evidence_refs.saturating_add(evidence.len());
        if total_evidence_refs > MAX_EVIDENCE_REFS {
            return Err("runtime evidence reference limit exceeded".to_owned());
        }
        associations.push(RootRuntimeAssociation {
            status: if evidence.len() > 1 {
                "ambiguous_candidate_match"
            } else {
                "candidate_match"
            },
            candidate_path: String::from_utf8_lossy(&full).into_owned(),
            candidate_path_bytes_hex: hex(&full),
            delta_kind: delta.kind.to_owned(),
            delta_name_identity_hex: delta.name_identity_hex.clone(),
            multiple_runtime_observations: evidence.len() > 1,
            runtime_evidence: evidence.clone(),
        });
        if associations.len() > MAX_ASSOCIATIONS {
            return Err("association limit exceeded".to_owned());
        }
    }
    let partial = trace.parse_status != ParseCompleteness::Complete || diff.status != "complete";
    let mut report = RootRuntimeAssociationReport {
        schema: "sideeffect.root_runtime_association",
        schema_version: 1,
        platform: "linux",
        status: "partial",
        parse_comparison_status: if partial { "partial" } else { "complete" },
        capture_completeness: "unknown",
        claim: "lexical_path_candidate_only_no_causation_or_process_identity",
        root_diff_status: diff.status.to_owned(),
        trace_sha256: trace_hash,
        trace_parse_status: trace.parse_status,
        trace_record_count: trace.records.len(),
        summary: RootRuntimeAssociationSummary {
            delta_count,
            eligible_runtime_observation_count,
            runtime_observation_rows_omitted_to_limit,
            failed_or_unknown_write_intent_count,
            candidate_match_count: associations.len(),
            ambiguous_candidate_count: ambiguous,
            unmatched_delta_count: unmatched,
        },
        associations_omitted_to_output_limit: 0,
        evidence_references_omitted_to_output_limit: 0,
        diagnostics: {
            let mut diagnostics = Vec::new();
            if partial {
                diagnostics.push("one_or_more_inputs_are_partial_or_incomplete");
            }
            if runtime_observation_rows_omitted_to_limit > 0 {
                diagnostics.push("runtime_observation_limit_reached");
            }
            diagnostics.push("runtime_capture_completeness_is_unknown");
            diagnostics
        },
        limitations: vec![
            "Only exact absolute lexical paths in successful openat O_CREAT or O_TRUNC calls are considered; successful O_CREAT may open an existing file and does not prove a change.",
            "Failed or unknown write-intent outcomes are counted but never treated as mutations.",
            "Successful open calls are associated only with selected-root additions or changed rows; removals and unlink/rename operations are not supported.",
            "The strace task ID is not a stable process identity and does not establish which process caused a delta.",
            "A lexical candidate does not prove the filesystem operation changed the selected-root entry.",
            "Missing candidates do not establish absence; unsupported, failed, ambiguous, or non-comparable observations remain unknown.",
            "Windows path namespaces are not compared by this Linux adapter.",
        ],
        associations,
    };
    for association in &mut report.associations {
        if association.runtime_evidence.len() > MAX_REFS_PER_ASSOCIATION {
            report.evidence_references_omitted_to_output_limit +=
                association.runtime_evidence.len() - MAX_REFS_PER_ASSOCIATION;
            association
                .runtime_evidence
                .truncate(MAX_REFS_PER_ASSOCIATION);
        }
    }
    let all_associations = std::mem::take(&mut report.associations);
    let mut used = serde_json::to_vec(&report)
        .map_err(|_| "could not size association report".to_owned())?
        .len();
    // Reserve a small amount for the eventual omitted counts and diagnostic.
    used = used.saturating_add(128);
    for association in all_associations {
        let item_bytes = serde_json::to_vec(&association)
            .map_err(|_| "could not size association row".to_owned())?
            .len();
        let added = item_bytes.saturating_add(usize::from(!report.associations.is_empty()));
        if used.saturating_add(added) > MAX_ASSOCIATION_REPORT_BYTES {
            report.associations_omitted_to_output_limit += 1;
            report.evidence_references_omitted_to_output_limit +=
                association.runtime_evidence.len();
        } else {
            used += added;
            report.associations.push(association);
        }
    }
    if report.associations_omitted_to_output_limit > 0
        || report.evidence_references_omitted_to_output_limit > 0
    {
        report.status = "partial";
        report.diagnostics.push("association_output_limit_reached");
    }
    Ok(report)
}

fn split_args(input: &str) -> Option<Vec<&str>> {
    if input.len() > 64 * 1024 {
        return None;
    }
    let mut result = Vec::new();
    let (mut quoted, mut escape, mut depth, mut start) = (false, false, 0_i32, 0);
    for (i, c) in input.char_indices() {
        if quoted {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            ',' if depth == 0 => {
                result.push(input.get(start..i)?.trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    if quoted || escape || depth != 0 {
        return None;
    }
    result.push(input.get(start..)?.trim());
    Some(result)
}
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 || value.len() > 8190 {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(value.get(i..i + 2)?, 16).ok())
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::associate_root_runtime_diff;
    use serde_json::json;

    fn snapshot(rows: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema":"sideeffect.selected_root_inventory", "schema_version":1,
            "platform":"linux", "scope":"one_explicit_root_and_its_direct_children_metadata_only",
            "captured_started_at_unix_ms":1, "captured_ended_at_unix_ms":2, "status":"complete",
            "root":{"display_path":"/tmp/r5-root", "path_bytes_hex":"2f746d702f72352d726f6f74", "object_type":"directory", "device_or_volume_serial":1, "inode_or_file_index":2},
            "entries":rows, "diagnostics":[], "limits":{"max_root_path_bytes_or_utf16_units":4095,"max_entries":10000,"max_name_bytes_or_utf16_units":32767,"max_aggregate_name_bytes":8388608,"deadline_seconds":5}
        })).unwrap()
    }
    fn row(size: u64) -> serde_json::Value {
        json!({"ordinal":0,"display_name":"item","name_bytes_hex":"6974656d","object_type":"regular_file","size_bytes":size,"modified_at_unix_ms":2,"device_or_volume_serial":1,"inode_or_file_index":3,"evidence":{"source":"selected_root_directory_entry","entry_ordinal":0}})
    }
    #[test]
    fn associates_only_successful_exact_write_intent_path_with_raw_locator() {
        let before = snapshot(json!([]));
        let after = snapshot(json!([row(4)]));
        let trace = b"123.000001 openat(AT_FDCWD, \"/tmp/r5-root/item\", O_WRONLY|O_CREAT|O_CLOEXEC, 0600) = 3\n";
        let diff =
            super::super::root_snapshot_diff::compare_selected_root_inventory_json(&before, &after)
                .unwrap();
        let report = associate_root_runtime_diff(&diff, trace).unwrap();
        assert_eq!(report.associations.len(), 1);
        assert_eq!(report.associations[0].status, "candidate_match");
        assert_eq!(
            report.associations[0].candidate_path_bytes_hex,
            "2f746d702f72352d726f6f742f6974656d"
        );
        assert_eq!(report.associations[0].runtime_evidence[0].line_number, 1);
        assert_eq!(
            report.claim,
            "lexical_path_candidate_only_no_causation_or_process_identity"
        );
    }
    #[test]
    fn readonly_and_failed_write_intent_do_not_match() {
        let before = snapshot(json!([]));
        let after = snapshot(json!([row(4)]));
        let trace = b"openat(AT_FDCWD, \"/tmp/r5-root/item\", O_RDONLY) = 3\nopenat(AT_FDCWD, \"/tmp/r5-root/item\", O_WRONLY|O_CREAT, 0600) = -1 EACCES (Permission denied)\n";
        let diff =
            super::super::root_snapshot_diff::compare_selected_root_inventory_json(&before, &after)
                .unwrap();
        let report = associate_root_runtime_diff(&diff, trace).unwrap();
        assert!(report.associations.is_empty());
        assert_eq!(report.summary.failed_or_unknown_write_intent_count, 1);
    }

    #[test]
    fn ignores_removals_and_tmpfile_paths() {
        let before = snapshot(json!([row(4)]));
        let after = snapshot(json!([]));
        let diff =
            super::super::root_snapshot_diff::compare_selected_root_inventory_json(&before, &after)
                .unwrap();
        let report = associate_root_runtime_diff(
            &diff,
            b"openat(AT_FDCWD, \"/tmp/r5-root/item\", O_WRONLY|O_CREAT, 0600) = 3\n",
        )
        .unwrap();
        assert!(report.associations.is_empty());
        assert_eq!(report.summary.delta_count, 0);

        let before = snapshot(json!([]));
        let after = snapshot(json!([row(4)]));
        let diff =
            super::super::root_snapshot_diff::compare_selected_root_inventory_json(&before, &after)
                .unwrap();
        let report = associate_root_runtime_diff(
            &diff,
            b"openat(AT_FDCWD, \"/tmp/r5-root/item\", O_TMPFILE|O_DIRECTORY|O_RDWR, 0600) = 3\n",
        )
        .unwrap();
        assert!(report.associations.is_empty());
    }
}
