//! Conservative comparison of bounded PATH executable candidate inventories.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const SCHEMA: &str = "sideeffect.path_executable_inventory";
const SCHEMA_VERSION: u32 = 1;
const MAX_INPUT: usize = 64 * 1024 * 1024;
const MAX_COMPONENTS: usize = 256;
const MAX_DIRECTORIES: usize = 256;
const MAX_ENTRIES: usize = 20_000;
const MAX_PATH_UNITS: usize = 32_767;
const MAX_TEXT_BYTES: usize = 131_072;
const MAX_DIAGNOSTICS: usize = 20_000;
const MAX_OUTPUT_DELTAS: usize = MAX_ENTRIES * 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathExecutableDiffError {
    MalformedInput,
    InputTooLarge,
    UnsupportedSchema,
    PlatformMismatch,
    LimitExceeded,
}

#[derive(Debug, Serialize)]
pub struct PathExecutableDiff {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub status: &'static str,
    pub coverage_note: &'static str,
    pub counts: PathExecutableDiffCounts,
    pub diagnostics: Vec<&'static str>,
    pub deltas: Vec<PathExecutableDelta>,
}

#[derive(Debug, Default, Serialize)]
pub struct PathExecutableDiffCounts {
    pub candidates_added: usize,
    pub candidates_removed: usize,
    pub candidate_status_changes: usize,
    pub path_component_position_changes: usize,
    pub unmatched_candidates_suppressed_for_incomplete_or_changed_context: usize,
    pub candidate_status_changes_suppressed_for_changed_context: usize,
    pub ambiguous_identities_suppressed: usize,
    pub entries_with_unknown_candidate_status: usize,
}

#[derive(Debug, Serialize)]
pub struct PathExecutableDelta {
    pub kind: &'static str,
    /// Display text is for review; the source artifact retains the exact platform encoding.
    pub name: String,
    pub before: Option<PathEntryFacts>,
    pub after: Option<PathEntryFacts>,
}

#[derive(Debug, Serialize)]
pub struct PathEntryFacts {
    pub status: String,
    pub metadata_status: String,
    pub candidate_rule: Option<String>,
    pub component_ordinal: usize,
    pub directory_ordinal: usize,
    pub entry_ordinal: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactPath {
    pub display: String,
    pub exact: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_bytes_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utf16_code_units: Option<Vec<u16>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    schema_version: u32,
    platform: String,
    path_source: String,
    candidate_extensions: Vec<String>,
    candidate_extensions_status: String,
    status: String,
    components: Vec<Component>,
    directories: Vec<Directory>,
    diagnostics: Vec<Diagnostic>,
    limits: Limits,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Component {
    ordinal: usize,
    path: ExactPath,
    empty_component_mapped_to_cwd: bool,
    directory_ordinal: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Directory {
    ordinal: usize,
    component_ordinal: usize,
    path: ExactPath,
    status: String,
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    ordinal: usize,
    name: ExactPath,
    status: String,
    metadata_status: String,
    candidate_rule: Option<String>,
    evidence: EntryEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryEvidence {
    directory_ordinal: usize,
    entry_ordinal: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Diagnostic {
    code: String,
    component_ordinal: Option<usize>,
    directory_ordinal: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    max_components: usize,
    max_component_path_bytes_or_units: usize,
    max_entries: usize,
    max_aggregate_path_and_name_bytes_or_units: usize,
    max_pathext_utf16_units: usize,
    max_pathext_extensions: usize,
    deadline_seconds: u64,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum PathIdentity {
    Linux { directory: String, name: String },
    Windows { directory: Vec<u16>, name: Vec<u16> },
}

#[derive(Clone, Copy)]
struct EntryRef<'a> {
    directory: &'a Directory,
    entry: &'a Entry,
}

pub fn compare_path_executable_inventory_json(
    before: &[u8],
    after: &[u8],
) -> Result<PathExecutableDiff, PathExecutableDiffError> {
    if before.len().saturating_add(after.len()) > MAX_INPUT {
        return Err(PathExecutableDiffError::InputTooLarge);
    }
    let left: Document =
        serde_json::from_slice(before).map_err(|_| PathExecutableDiffError::MalformedInput)?;
    let right: Document =
        serde_json::from_slice(after).map_err(|_| PathExecutableDiffError::MalformedInput)?;
    if left.schema != SCHEMA
        || right.schema != SCHEMA
        || left.schema_version != SCHEMA_VERSION
        || right.schema_version != SCHEMA_VERSION
    {
        return Err(PathExecutableDiffError::UnsupportedSchema);
    }
    if left.platform != right.platform || !matches!(left.platform.as_str(), "linux" | "windows") {
        return Err(PathExecutableDiffError::PlatformMismatch);
    }
    validate(&left)?;
    validate(&right)?;
    compare(&left, &right)
}

fn validate(document: &Document) -> Result<(), PathExecutableDiffError> {
    if document.path_source != "current_process_environment_PATH"
        || !matches!(document.status.as_str(), "complete" | "partial")
        || !matches!(
            document.candidate_extensions_status.as_str(),
            "available" | "unavailable" | "partial" | "not_applicable"
        )
        || document.candidate_extensions.len() > 256
        || document.diagnostics.len() > MAX_DIAGNOSTICS
        || document.components.len() > MAX_COMPONENTS
        || document.directories.len() > MAX_DIRECTORIES
        || document
            .candidate_extensions
            .iter()
            .any(|value| value.len() > 128)
        || document
            .components
            .iter()
            .enumerate()
            .any(|(i, c)| c.ordinal != i)
        || document
            .directories
            .iter()
            .enumerate()
            .any(|(i, d)| d.ordinal != i)
        || document.limits.max_components > MAX_COMPONENTS
        || document.limits.max_entries > MAX_ENTRIES
        || document.limits.max_components == 0
        || document.limits.max_entries == 0
        || document.components.len() > document.limits.max_components
        || document.components.iter().any(|component| {
            path_units(&component.path, &document.platform)
                > document.limits.max_component_path_bytes_or_units
        })
        || (document.platform == "linux"
            && document.candidate_extensions_status != "not_applicable")
        || (document.platform == "windows"
            && document.candidate_extensions_status == "not_applicable")
    {
        return Err(PathExecutableDiffError::LimitExceeded);
    }
    let mut entries = 0usize;
    let mut encoded_units = 0usize;
    for component in &document.components {
        validate_path(&component.path, &document.platform)?;
        encoded_units =
            encoded_units.saturating_add(path_units(&component.path, &document.platform));
        let component_is_empty = match document.platform.as_str() {
            "linux" => component.path.exact && component.path.raw_bytes_hex.as_deref() == Some(""),
            "windows" => {
                component.path.exact && component.path.utf16_code_units.as_deref() == Some(&[])
            }
            _ => false,
        };
        if component.empty_component_mapped_to_cwd != component_is_empty {
            return Err(PathExecutableDiffError::MalformedInput);
        }
        if component
            .directory_ordinal
            .is_some_and(|i| i >= document.directories.len())
        {
            return Err(PathExecutableDiffError::MalformedInput);
        }
    }
    for directory in &document.directories {
        validate_path(&directory.path, &document.platform)?;
        encoded_units =
            encoded_units.saturating_add(path_units(&directory.path, &document.platform));
        if !matches!(
            directory.status.as_str(),
            "complete" | "partial" | "unknown"
        ) || directory.component_ordinal >= document.components.len()
            || document.components[directory.component_ordinal].directory_ordinal
                != Some(directory.ordinal)
        {
            return Err(PathExecutableDiffError::MalformedInput);
        }
        let component = &document.components[directory.component_ordinal];
        if !component.empty_component_mapped_to_cwd
            && (component.path.exact != directory.path.exact
                || component.path.raw_bytes_hex != directory.path.raw_bytes_hex
                || component.path.utf16_code_units != directory.path.utf16_code_units)
        {
            return Err(PathExecutableDiffError::MalformedInput);
        }
        entries = entries.saturating_add(directory.entries.len());
        if entries > MAX_ENTRIES
            || directory
                .entries
                .iter()
                .enumerate()
                .any(|(i, e)| e.ordinal != i)
        {
            return Err(PathExecutableDiffError::LimitExceeded);
        }
        for entry in &directory.entries {
            validate_path(&entry.name, &document.platform)?;
            encoded_units =
                encoded_units.saturating_add(path_units(&entry.name, &document.platform));
            if !matches!(
                entry.status.as_str(),
                "candidate" | "not_candidate" | "unknown"
            ) || entry.metadata_status.len() > 128
                || !matches!(
                    entry.metadata_status.as_str(),
                    "observed" | "unavailable" | "symlink_or_reparse_not_followed"
                )
                || entry.candidate_rule.as_ref().is_some_and(|r| {
                    r.len() > 128
                        || (r != "regular_file_with_execute_bit"
                            && r != "regular_file_with_captured_PATHEXT_suffix")
                })
                || entry.evidence.directory_ordinal != directory.ordinal
                || entry.evidence.entry_ordinal != entry.ordinal
            {
                return Err(PathExecutableDiffError::MalformedInput);
            }
            let expected_rule = if document.platform == "linux" {
                "regular_file_with_execute_bit"
            } else {
                "regular_file_with_captured_PATHEXT_suffix"
            };
            if (entry.status == "candidate"
                && (entry.metadata_status != "observed"
                    || entry.candidate_rule.as_deref() != Some(expected_rule)))
                || (entry.status == "not_candidate" && entry.metadata_status != "observed")
                || (entry.status != "candidate" && entry.candidate_rule.is_some())
            {
                return Err(PathExecutableDiffError::MalformedInput);
            }
        }
    }
    if encoded_units > 16 * 1024 * 1024
        || encoded_units > document.limits.max_aggregate_path_and_name_bytes_or_units
        || entries > document.limits.max_entries
        || document.candidate_extensions.len() > document.limits.max_pathext_extensions
    {
        return Err(PathExecutableDiffError::LimitExceeded);
    }
    for diagnostic in &document.diagnostics {
        if diagnostic.code.len() > 128
            || diagnostic
                .component_ordinal
                .is_some_and(|i| i >= document.components.len())
            || diagnostic
                .directory_ordinal
                .is_some_and(|i| i >= document.directories.len())
        {
            return Err(PathExecutableDiffError::MalformedInput);
        }
    }
    if document.limits.max_component_path_bytes_or_units > MAX_PATH_UNITS
        || document.limits.max_aggregate_path_and_name_bytes_or_units > 16 * 1024 * 1024
        || document.limits.max_pathext_utf16_units > 32_767
        || document.limits.max_pathext_extensions > 256
        || document.limits.deadline_seconds > 60
    {
        return Err(PathExecutableDiffError::LimitExceeded);
    }
    Ok(())
}

fn validate_path(path: &ExactPath, platform: &str) -> Result<(), PathExecutableDiffError> {
    if path.display.len() > MAX_TEXT_BYTES {
        return Err(PathExecutableDiffError::LimitExceeded);
    }
    match platform {
        "linux" => {
            if path.utf16_code_units.is_some()
                || path
                    .raw_bytes_hex
                    .as_ref()
                    .is_none_or(|v| v.len() > MAX_PATH_UNITS * 2 || !is_lower_hex(v))
                || path.exact && path.raw_bytes_hex.is_none()
                || !path.exact && path.raw_bytes_hex.as_ref().is_some_and(|v| !v.is_empty())
            {
                return Err(PathExecutableDiffError::MalformedInput);
            }
            if path.exact {
                let raw = decode_hex(path.raw_bytes_hex.as_deref().unwrap_or_default())
                    .ok_or(PathExecutableDiffError::MalformedInput)?;
                if String::from_utf8_lossy(&raw) != path.display {
                    return Err(PathExecutableDiffError::MalformedInput);
                }
            }
        }
        "windows" => {
            if path.raw_bytes_hex.is_some()
                || path
                    .utf16_code_units
                    .as_ref()
                    .is_none_or(|v| v.len() > MAX_PATH_UNITS)
                || !path.exact
                    && path
                        .utf16_code_units
                        .as_ref()
                        .is_some_and(|v| !v.is_empty())
            {
                return Err(PathExecutableDiffError::MalformedInput);
            }
            if path.exact
                && String::from_utf16_lossy(path.utf16_code_units.as_deref().unwrap_or_default())
                    != path.display
            {
                return Err(PathExecutableDiffError::MalformedInput);
            }
        }
        _ => return Err(PathExecutableDiffError::PlatformMismatch),
    }
    Ok(())
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn path_units(path: &ExactPath, platform: &str) -> usize {
    match platform {
        "linux" => path
            .raw_bytes_hex
            .as_ref()
            .map_or(0, |value| value.len() / 2),
        "windows" => path.utf16_code_units.as_ref().map_or(0, Vec::len),
        _ => 0,
    }
}

fn is_lower_hex(value: &str) -> bool {
    value.len() % 2 == 0
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn identity(directory: &ExactPath, name: &ExactPath, platform: &str) -> Option<PathIdentity> {
    if !directory.exact || !name.exact {
        return None;
    }
    match platform {
        "linux" => Some(PathIdentity::Linux {
            directory: directory.raw_bytes_hex.clone()?,
            name: name.raw_bytes_hex.clone()?,
        }),
        "windows" => Some(PathIdentity::Windows {
            directory: directory.utf16_code_units.clone()?,
            name: name.utf16_code_units.clone()?,
        }),
        _ => None,
    }
}

fn compare(
    left: &Document,
    right: &Document,
) -> Result<PathExecutableDiff, PathExecutableDiffError> {
    let mut counts = PathExecutableDiffCounts::default();
    let mut diagnostics = Vec::new();
    let left_entries = index(left, &mut counts)?;
    let right_entries = index(right, &mut counts)?;
    let left_coverage_complete = document_coverage_complete(left);
    let right_coverage_complete = document_coverage_complete(right);
    let candidate_context_equal = left.platform == "linux"
        || (left.candidate_extensions == right.candidate_extensions
            && left.candidate_extensions_status == right.candidate_extensions_status);
    let can_claim_presence =
        left_coverage_complete && right_coverage_complete && candidate_context_equal;
    let mut deltas = Vec::new();
    let mut identities = left_entries
        .keys()
        .chain(right_entries.keys())
        .cloned()
        .collect::<Vec<_>>();
    identities.sort();
    identities.dedup();
    for key in identities {
        let before = left_entries
            .get(&key)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let after = right_entries
            .get(&key)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if before.len() > 1 || after.len() > 1 {
            counts.ambiguous_identities_suppressed = counts
                .ambiguous_identities_suppressed
                .saturating_add(before.len().max(after.len()));
            continue;
        }
        match (before.first(), after.first()) {
            (Some(b), Some(a)) => {
                if b.entry.status == "unknown" || a.entry.status == "unknown" {
                    continue;
                }
                let mut changes = Vec::new();
                if b.entry.status != a.entry.status && candidate_context_equal {
                    changes.push(PathExecutableDelta {
                        kind: "candidate_status_changed",
                        name: a.entry.name.display.clone(),
                        before: Some(facts(b)),
                        after: Some(facts(a)),
                    });
                    counts.candidate_status_changes =
                        counts.candidate_status_changes.saturating_add(1);
                } else if b.entry.status != a.entry.status {
                    counts.candidate_status_changes_suppressed_for_changed_context = counts
                        .candidate_status_changes_suppressed_for_changed_context
                        .saturating_add(1);
                }
                if b.directory.component_ordinal != a.directory.component_ordinal {
                    changes.push(PathExecutableDelta {
                        kind: "path_component_position_changed",
                        name: a.entry.name.display.clone(),
                        before: Some(facts(b)),
                        after: Some(facts(a)),
                    });
                    counts.path_component_position_changes =
                        counts.path_component_position_changes.saturating_add(1);
                }
                if changes.len() > MAX_OUTPUT_DELTAS.saturating_sub(deltas.len()) {
                    return Err(PathExecutableDiffError::LimitExceeded);
                }
                deltas.extend(changes);
            }
            (Some(b), None) if b.entry.status == "candidate" => {
                if can_claim_presence {
                    counts.candidates_removed = counts.candidates_removed.saturating_add(1);
                    deltas.push(delta("candidate_removed", Some(b), None));
                } else {
                    counts.unmatched_candidates_suppressed_for_incomplete_or_changed_context =
                        counts
                            .unmatched_candidates_suppressed_for_incomplete_or_changed_context
                            .saturating_add(1);
                }
            }
            (None, Some(a)) if a.entry.status == "candidate" => {
                if can_claim_presence {
                    counts.candidates_added = counts.candidates_added.saturating_add(1);
                    deltas.push(delta("candidate_added", None, Some(a)));
                } else {
                    counts.unmatched_candidates_suppressed_for_incomplete_or_changed_context =
                        counts
                            .unmatched_candidates_suppressed_for_incomplete_or_changed_context
                            .saturating_add(1);
                }
            }
            _ => {}
        }
        if deltas.len() > MAX_OUTPUT_DELTAS {
            return Err(PathExecutableDiffError::LimitExceeded);
        }
    }
    if !left_coverage_complete || !right_coverage_complete {
        diagnostics.push("incomplete_or_unknown_source_coverage");
    }
    if counts.ambiguous_identities_suppressed > 0 {
        diagnostics.push("duplicate_or_ambiguous_path_identity");
    }
    if counts.entries_with_unknown_candidate_status > 0 {
        diagnostics.push("unknown_candidate_status");
    }
    if left.candidate_extensions != right.candidate_extensions
        || left.candidate_extensions_status != right.candidate_extensions_status
    {
        diagnostics.push("candidate_extension_context_changed");
    }
    if counts.candidate_status_changes_suppressed_for_changed_context > 0 {
        diagnostics.push("candidate_status_change_suppressed_for_changed_context");
    }
    Ok(PathExecutableDiff {
        schema: "sideeffect.path_executable_inventory_diff",
        schema_version: 1,
        platform: if left.platform == "linux" {
            "linux"
        } else {
            "windows"
        },
        status: if can_claim_presence && diagnostics.is_empty() {
            "complete"
        } else {
            "partial"
        },
        coverage_note: "Compares exact metadata candidate identities in two PATH snapshots; does not resolve shell commands or prove launchability, effective precedence, execution, or absence outside the captured sources.",
        counts,
        diagnostics,
        deltas,
    })
}

fn index<'a>(
    document: &'a Document,
    counts: &mut PathExecutableDiffCounts,
) -> Result<HashMap<PathIdentity, Vec<EntryRef<'a>>>, PathExecutableDiffError> {
    let mut map: HashMap<PathIdentity, Vec<EntryRef<'a>>> = HashMap::new();
    for directory in &document.directories {
        for entry in &directory.entries {
            let key = identity(&directory.path, &entry.name, &document.platform);
            if entry.status == "unknown" || key.is_none() {
                counts.entries_with_unknown_candidate_status = counts
                    .entries_with_unknown_candidate_status
                    .saturating_add(1);
            }
            let Some(key) = key else {
                continue;
            };
            map.entry(key)
                .or_default()
                .push(EntryRef { directory, entry });
        }
    }
    Ok(map)
}

fn document_coverage_complete(document: &Document) -> bool {
    document.status == "complete"
        && document.diagnostics.is_empty()
        && document.candidate_extensions_status != "unavailable"
        && document.candidate_extensions_status != "partial"
        && document
            .components
            .iter()
            .all(|c| c.directory_ordinal.is_some() && c.path.exact)
        && document
            .directories
            .iter()
            .all(|d| d.status == "complete" && d.path.exact)
        && document
            .directories
            .iter()
            .flat_map(|d| &d.entries)
            .all(|e| e.status != "unknown" && e.name.exact)
}

fn facts(reference: &EntryRef<'_>) -> PathEntryFacts {
    PathEntryFacts {
        status: reference.entry.status.clone(),
        metadata_status: reference.entry.metadata_status.clone(),
        candidate_rule: reference.entry.candidate_rule.clone(),
        component_ordinal: reference.directory.component_ordinal,
        directory_ordinal: reference.directory.ordinal,
        entry_ordinal: reference.entry.evidence.entry_ordinal,
    }
}

fn delta(
    kind: &'static str,
    before: Option<&EntryRef<'_>>,
    after: Option<&EntryRef<'_>>,
) -> PathExecutableDelta {
    let representative = before.or(after).expect("a delta has an evidence row");
    PathExecutableDelta {
        kind,
        name: representative.entry.name.display.clone(),
        before: before.map(facts),
        after: after.map(facts),
    }
}

#[cfg(test)]
mod tests {
    use super::{PathExecutableDiffError, compare_path_executable_inventory_json};
    use serde_json::{Value, json};

    fn exact_path(platform: &str, display: &str, encoded: &str) -> Value {
        if platform == "linux" {
            json!({"display": display, "exact": true, "raw_bytes_hex": encoded})
        } else {
            json!({
                "display": display,
                "exact": true,
                "utf16_code_units": encoded.encode_utf16().collect::<Vec<_>>()
            })
        }
    }

    fn document(platform: &str, rows: &[(&str, &str, &str)]) -> Vec<u8> {
        let directory_display = if platform == "linux" {
            "/tools"
        } else {
            "C:\\tools"
        };
        let directory_identity = if platform == "linux" {
            "2f746f6f6c73"
        } else {
            directory_display
        };
        let entries = rows.iter().enumerate().map(|(ordinal, (name, encoded, status))| {
            json!({
                "ordinal": ordinal,
                "name": exact_path(platform, name, encoded),
                "status": status,
                "metadata_status": "observed",
                "candidate_rule": if *status == "candidate" {
                    Some(if platform == "linux" { "regular_file_with_execute_bit" } else { "regular_file_with_captured_PATHEXT_suffix" })
                } else { None },
                "evidence": {"directory_ordinal": 0, "entry_ordinal": ordinal}
            })
        }).collect::<Vec<_>>();
        serde_json::to_vec(&json!({
            "schema": "sideeffect.path_executable_inventory",
            "schema_version": 1,
            "platform": platform,
            "path_source": "current_process_environment_PATH",
            "candidate_extensions": if platform == "windows" { vec![".exe"] } else { vec![] },
            "candidate_extensions_status": if platform == "windows" { "available" } else { "not_applicable" },
            "status": "complete",
            "components": [{
                "ordinal": 0,
                "path": exact_path(platform, directory_display, directory_identity),
                "empty_component_mapped_to_cwd": false,
                "directory_ordinal": 0
            }],
            "directories": [{
                "ordinal": 0,
                "component_ordinal": 0,
                "path": exact_path(platform, directory_display, directory_identity),
                "status": "complete",
                "entries": entries
            }],
            "diagnostics": [],
            "limits": {
                "max_components": 256,
                "max_component_path_bytes_or_units": if platform == "windows" { 32767 } else { 4096 },
                "max_entries": 20000,
                "max_aggregate_path_and_name_bytes_or_units": 16777216,
                "max_pathext_utf16_units": 32767,
                "max_pathext_extensions": 256,
                "deadline_seconds": 5
            }
        })).unwrap()
    }

    #[test]
    fn complete_pair_reports_candidate_changes_with_evidence_locators() {
        let before = document(
            "linux",
            &[
                ("tool", "746f6f6c", "candidate"),
                ("old", "6f6c64", "candidate"),
            ],
        );
        let after = document(
            "linux",
            &[
                ("tool", "746f6f6c", "not_candidate"),
                ("new", "6e6577", "candidate"),
            ],
        );
        let diff = compare_path_executable_inventory_json(&before, &after).unwrap();
        assert_eq!(diff.status, "complete");
        assert_eq!(diff.counts.candidates_added, 1);
        assert_eq!(diff.counts.candidates_removed, 1);
        assert_eq!(diff.counts.candidate_status_changes, 1);
        let added = diff
            .deltas
            .iter()
            .find(|item| item.kind == "candidate_added")
            .unwrap();
        assert_eq!(added.name, "new");
        assert!(added.before.is_none());
        assert_eq!(added.after.as_ref().unwrap().entry_ordinal, 1);
    }

    #[test]
    fn incomplete_pair_suppresses_one_sided_presence_but_keeps_matches() {
        let before = document(
            "linux",
            &[
                ("tool", "746f6f6c", "candidate"),
                ("old", "6f6c64", "candidate"),
            ],
        );
        let after = document(
            "linux",
            &[
                ("tool", "746f6f6c", "not_candidate"),
                ("new", "6e6577", "candidate"),
            ],
        );
        let mut left: Value = serde_json::from_slice(&before).unwrap();
        let mut right: Value = serde_json::from_slice(&after).unwrap();
        left["status"] = json!("partial");
        left["directories"][0]["status"] = json!("partial");
        right["status"] = json!("partial");
        right["directories"][0]["status"] = json!("partial");
        let diff = compare_path_executable_inventory_json(
            &serde_json::to_vec(&left).unwrap(),
            &serde_json::to_vec(&right).unwrap(),
        )
        .unwrap();
        assert_eq!(diff.status, "partial");
        assert_eq!(diff.counts.candidates_added, 0);
        assert_eq!(diff.counts.candidates_removed, 0);
        assert_eq!(
            diff.counts
                .unmatched_candidates_suppressed_for_incomplete_or_changed_context,
            2
        );
        assert_eq!(diff.counts.candidate_status_changes, 1);
        assert_eq!(diff.deltas.len(), 1);
        assert_eq!(diff.deltas[0].kind, "candidate_status_changed");
    }

    #[test]
    fn linux_matching_uses_raw_name_bytes_not_lossy_display() {
        let before = document("linux", &[("�", "ff", "candidate")]);
        let after = document("linux", &[("�", "fe", "candidate")]);
        let diff = compare_path_executable_inventory_json(&before, &after).unwrap();
        assert_eq!(diff.counts.candidates_added, 1);
        assert_eq!(diff.counts.candidates_removed, 1);
    }

    #[test]
    fn duplicate_candidates_are_ambiguous_and_not_counted_as_presence_changes() {
        let before = document(
            "linux",
            &[
                ("tool", "746f6f6c", "candidate"),
                ("tool", "746f6f6c", "candidate"),
            ],
        );
        let after = document("linux", &[]);
        let diff = compare_path_executable_inventory_json(&before, &after).unwrap();
        assert_eq!(diff.status, "partial");
        assert_eq!(diff.counts.candidates_removed, 0);
        assert_eq!(diff.counts.ambiguous_identities_suppressed, 2);
        assert!(diff.deltas.is_empty());
    }

    #[test]
    fn inexact_rows_prevent_complete_presence_claims() {
        let before = document("linux", &[("lost", "6c6f7374", "candidate")]);
        let after = document("linux", &[]);
        let mut left: Value = serde_json::from_slice(&before).unwrap();
        left["directories"][0]["entries"][0]["name"]["exact"] = json!(false);
        left["directories"][0]["entries"][0]["name"]["raw_bytes_hex"] = json!("");
        let diff =
            compare_path_executable_inventory_json(&serde_json::to_vec(&left).unwrap(), &after)
                .unwrap();
        assert_eq!(diff.status, "partial");
        assert_eq!(diff.counts.candidates_removed, 0);
        assert_eq!(
            diff.counts
                .unmatched_candidates_suppressed_for_incomplete_or_changed_context,
            0
        );
        assert_eq!(diff.counts.entries_with_unknown_candidate_status, 1);
    }

    #[test]
    fn changed_windows_pathext_suppresses_candidate_presence_and_status_claims() {
        let before = document("windows", &[("tool.exe", "tool.exe", "candidate")]);
        let after = document("windows", &[("tool.exe", "tool.exe", "not_candidate")]);
        let mut right: Value = serde_json::from_slice(&after).unwrap();
        right["candidate_extensions"] = json!([".cmd"]);
        let diff =
            compare_path_executable_inventory_json(&before, &serde_json::to_vec(&right).unwrap())
                .unwrap();
        assert_eq!(diff.status, "partial");
        assert_eq!(diff.counts.candidates_added, 0);
        assert_eq!(diff.counts.candidates_removed, 0);
        assert_eq!(diff.counts.candidate_status_changes, 0);
        assert_eq!(
            diff.counts
                .candidate_status_changes_suppressed_for_changed_context,
            1
        );
        assert!(diff.deltas.is_empty());
        assert!(
            diff.diagnostics
                .contains(&"candidate_extension_context_changed")
        );
    }

    #[test]
    fn rejects_unrecognized_fields_and_cross_platform_comparisons() {
        let linux = document("linux", &[]);
        let windows = document("windows", &[]);
        let mut value: Value = serde_json::from_slice(&linux).unwrap();
        value["unrecognized"] = json!(true);
        assert_eq!(
            compare_path_executable_inventory_json(&serde_json::to_vec(&value).unwrap(), &linux)
                .unwrap_err(),
            PathExecutableDiffError::MalformedInput
        );
        assert_eq!(
            compare_path_executable_inventory_json(&linux, &windows).unwrap_err(),
            PathExecutableDiffError::PlatformMismatch
        );
    }
}
