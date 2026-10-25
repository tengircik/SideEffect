//! Conservative, evidence-linked matching between saved startup configuration
//! and successful executable-path arguments in a saved strace trace.
//!
//! This module never interprets a command as shell input and never launches it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::limits::{MAX_RECORD_BYTES, MAX_REPORT_BYTES};
use crate::model::{EvidenceReference, ParseCompleteness, SyscallOutcome, TraceRecordKind};
use crate::trace::strace::parse_trace_bytes;

pub const MAX_STARTUP_CORRELATION_CONFIG_ROWS: usize = 50_000;
/// Aggregate bound for copied executable paths, evidence metadata, and source-context strings.
pub const MAX_STARTUP_CORRELATION_METADATA_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct StartupCorrelationDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub status: &'static str,
    pub coverage: &'static str,
    pub claim: &'static str,
    pub startup_inventory_sha256: String,
    pub startup_inventory_status: String,
    pub startup_capture_started_at_unix_ms: u128,
    pub startup_capture_ended_at_unix_ms: u128,
    pub xdg_status: String,
    pub systemd_status: String,
    pub legacy_status: String,
    pub startup_sources: Vec<StartupSourceContext>,
    pub trace_sha256: String,
    pub trace_parse_status: ParseCompleteness,
    pub trace_capture_completeness: &'static str,
    pub trace_diagnostic_count: usize,
    pub trace_record_count: usize,
    pub limitations: Vec<&'static str>,
    pub summary: CorrelationSummary,
    pub candidate_matches: Vec<CandidateMatch>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StartupSourceContext {
    pub source_family: String,
    pub scope: String,
    pub source_path: String,
    pub status: String,
    pub diagnostic_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct CorrelationSummary {
    pub candidate_match_path_count: usize,
    pub config_evidence_count: usize,
    pub runtime_evidence_count: usize,
    pub supported_config_reference_count: usize,
    pub supported_runtime_reference_count: usize,
    pub unmatched_config_path_count: usize,
    pub unmatched_runtime_path_count: usize,
    pub unsupported_xdg_exec_count: usize,
    pub unsupported_systemd_exec_count: usize,
    pub successful_exec_rows_without_supported_path_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct CandidateMatch {
    pub status: &'static str,
    pub match_basis: &'static str,
    pub executable_path: String,
    pub multiple_startup_references: bool,
    pub multiple_runtime_observations: bool,
    /// All matching configuration rows are retained; multiple rows are
    /// ambiguity, not a reason to select one.
    pub startup_evidence: Vec<StartupEvidenceReference>,
    /// All matching successful exec rows are retained; these are observations
    /// within the supplied trace, not proof of startup-manager execution.
    pub runtime_evidence: Vec<RuntimeEvidenceReference>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StartupEvidenceReference {
    pub source: &'static str,
    pub scope: String,
    pub source_path: String,
    pub key: String,
    pub line: u64,
    pub byte_offset: u64,
    pub byte_length: u64,
    pub source_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuntimeEvidenceReference {
    pub trace_sha256: String,
    pub syscall: String,
    /// `strace -f` row prefix task/thread identifier; this is not necessarily a process PID.
    pub caller_task_id: Option<u32>,
    pub evidence: EvidenceReference,
}

#[derive(Deserialize)]
struct StartupInput {
    schema: String,
    schema_version: u32,
    platform: String,
    status: String,
    capture_started_at_unix_ms: u128,
    capture_ended_at_unix_ms: u128,
    xdg_autostart: XdgInput,
    systemd_units: SystemdInput,
    legacy_sources: LegacyInput,
}

#[derive(Deserialize)]
struct XdgInput {
    status: String,
    directories: Vec<XdgDirectoryInput>,
    entries: Vec<XdgEntryInput>,
}

#[derive(Deserialize)]
struct XdgDirectoryInput {
    scope: String,
    path: String,
    status: String,
    diagnostics: Vec<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct XdgEntryInput {
    scope: String,
    source_path: String,
    keys: Vec<XdgKeyInput>,
}

#[derive(Deserialize)]
struct XdgKeyInput {
    key: String,
    value: Option<String>,
    line: usize,
    byte_offset: usize,
    byte_length: usize,
    line_sha256: String,
}

#[derive(Deserialize)]
struct SystemdInput {
    status: String,
    directories: Vec<SystemdDirectoryInput>,
    records: Vec<SystemdRecordInput>,
}

#[derive(Deserialize)]
struct SystemdDirectoryInput {
    scope: String,
    path: String,
    status: String,
    diagnostics: Vec<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct SystemdRecordInput {
    scope: String,
    source_path: String,
    record_type: String,
    directives: Vec<SystemdDirectiveInput>,
}

#[derive(Deserialize)]
struct SystemdDirectiveInput {
    section: String,
    key: String,
    value: Option<String>,
    line: usize,
    byte_offset: usize,
    byte_length: usize,
    line_sha256: String,
}

#[derive(Deserialize)]
struct LegacyInput {
    status: String,
    sources: Vec<LegacySourceInput>,
}

#[derive(Deserialize)]
struct LegacySourceInput {
    kind: String,
    path: String,
    state: String,
    diagnostics: Vec<serde::de::IgnoredAny>,
}

#[derive(Clone)]
struct ConfigCandidate {
    path: String,
    evidence: StartupEvidenceReference,
}

/// Correlate a saved schema-v2 Linux startup inventory with raw strace bytes.
/// Both inputs have already been bounded by the caller. Output data is bounded
/// by the fixed source/parser limits and must still be serialized with the
/// caller's capped writer.
pub fn correlate_startup_bytes(
    startup_bytes: &[u8],
    trace_bytes: &[u8],
) -> Result<StartupCorrelationDocument, String> {
    if startup_bytes.len() > MAX_REPORT_BYTES {
        return Err(format!(
            "startup inventory exceeds the {MAX_REPORT_BYTES} byte limit"
        ));
    }
    if trace_bytes.len() > crate::limits::MAX_TRACE_BYTES {
        return Err(format!(
            "trace input exceeds the {} byte limit",
            crate::limits::MAX_TRACE_BYTES
        ));
    }
    let startup: StartupInput = serde_json::from_slice(startup_bytes)
        .map_err(|_| "startup input is not a valid bounded JSON inventory".to_owned())?;
    if startup.schema != "sideeffect.startup_inventory"
        || startup.schema_version != 2
        || startup.platform != "linux"
    {
        return Err(
            "startup input must be a Linux sideeffect.startup_inventory schema v2 document"
                .to_owned(),
        );
    }
    if !matches!(startup.status.as_str(), "complete" | "partial")
        || !matches!(
            startup.xdg_autostart.status.as_str(),
            "complete" | "partial"
        )
        || !matches!(
            startup.systemd_units.status.as_str(),
            "complete" | "partial"
        )
        || !matches!(
            startup.legacy_sources.status.as_str(),
            "complete" | "partial"
        )
        || startup
            .xdg_autostart
            .directories
            .iter()
            .any(|source| !matches!(source.status.as_str(), "complete" | "partial"))
        || startup
            .systemd_units
            .directories
            .iter()
            .any(|source| !matches!(source.status.as_str(), "complete" | "partial"))
        || startup.legacy_sources.sources.iter().any(|source| {
            !matches!(
                source.state.as_str(),
                "complete" | "partial" | "not_present" | "unchecked"
            )
        })
    {
        return Err("startup inventory contains an unsupported status value".to_owned());
    }
    let directive_count = startup
        .systemd_units
        .records
        .iter()
        .try_fold(0usize, |total, record| {
            total.checked_add(record.directives.len())
        })
        .ok_or_else(|| "startup inventory directive count overflowed".to_owned())?;
    let xdg_key_count = startup
        .xdg_autostart
        .entries
        .iter()
        .try_fold(0usize, |total, entry| total.checked_add(entry.keys.len()))
        .ok_or_else(|| "startup inventory key count overflowed".to_owned())?;
    if startup.xdg_autostart.entries.len() > MAX_STARTUP_CORRELATION_CONFIG_ROWS
        || startup.systemd_units.records.len() > MAX_STARTUP_CORRELATION_CONFIG_ROWS
        || directive_count > MAX_STARTUP_CORRELATION_CONFIG_ROWS.saturating_mul(4)
        || xdg_key_count > MAX_STARTUP_CORRELATION_CONFIG_ROWS.saturating_mul(4)
        || startup.xdg_autostart.directories.len() > MAX_STARTUP_CORRELATION_CONFIG_ROWS
        || startup.systemd_units.directories.len() > MAX_STARTUP_CORRELATION_CONFIG_ROWS
        || startup.legacy_sources.sources.len() > MAX_STARTUP_CORRELATION_CONFIG_ROWS
    {
        return Err(format!(
            "startup inventory exceeds the bounded correlation row limit ({MAX_STARTUP_CORRELATION_CONFIG_ROWS})"
        ));
    }
    let mut config_candidates = Vec::new();
    let mut unsupported_xdg = 0usize;
    let mut unsupported_systemd = 0usize;
    let mut examined_config_rows = 0usize;
    let mut copied_metadata_bytes = 0usize;
    let mut startup_sources = Vec::new();
    for source in &startup.xdg_autostart.directories {
        push_startup_source_context(
            &mut startup_sources,
            &mut copied_metadata_bytes,
            "xdg_autostart",
            &source.scope,
            &source.path,
            &source.status,
            source.diagnostics.len(),
        )?;
    }
    for source in &startup.systemd_units.directories {
        push_startup_source_context(
            &mut startup_sources,
            &mut copied_metadata_bytes,
            "systemd",
            &source.scope,
            &source.path,
            &source.status,
            source.diagnostics.len(),
        )?;
    }
    for source in &startup.legacy_sources.sources {
        push_startup_source_context(
            &mut startup_sources,
            &mut copied_metadata_bytes,
            &source.kind,
            "linux_curated_source",
            &source.path,
            &source.state,
            source.diagnostics.len(),
        )?;
    }

    for entry in &startup.xdg_autostart.entries {
        for key in entry.keys.iter().filter(|key| key.key == "Exec") {
            examined_config_rows = examined_config_rows.saturating_add(1);
            ensure_config_row_limit(examined_config_rows)?;
            let Some(value) = key.value.as_deref() else {
                unsupported_xdg = unsupported_xdg.saturating_add(1);
                continue;
            };
            match literal_executable(value) {
                Some(path) => {
                    ensure_candidate_limit(config_candidates.len() + 1)?;
                    reserve_metadata_strings(
                        &mut copied_metadata_bytes,
                        std::mem::size_of::<ConfigCandidate>(),
                        [
                            path,
                            &entry.scope,
                            &entry.source_path,
                            "Exec",
                            &key.line_sha256,
                        ],
                    )?;
                    config_candidates.push(ConfigCandidate {
                        path: path.to_owned(),
                        evidence: StartupEvidenceReference {
                            source: "xdg_autostart",
                            scope: entry.scope.clone(),
                            source_path: entry.source_path.clone(),
                            key: "Exec".to_owned(),
                            line: key.line as u64,
                            byte_offset: key.byte_offset as u64,
                            byte_length: key.byte_length as u64,
                            source_sha256: key.line_sha256.clone(),
                        },
                    });
                }
                None => unsupported_xdg = unsupported_xdg.saturating_add(1),
            }
        }
    }

    for record in &startup.systemd_units.records {
        if !matches!(record.record_type.as_str(), "unit_file" | "drop_in_file") {
            continue;
        }
        for directive in record.directives.iter().filter(|directive| {
            directive.section == "Service" && systemd_exec_evidence_key(&directive.key).is_some()
        }) {
            examined_config_rows = examined_config_rows.saturating_add(1);
            ensure_config_row_limit(examined_config_rows)?;
            let Some(value) = directive.value.as_deref() else {
                unsupported_systemd = unsupported_systemd.saturating_add(1);
                continue;
            };
            let evidence_key = systemd_exec_evidence_key(&directive.key)
                .expect("filtered supported systemd command directive");
            match literal_executable(value) {
                Some(path) => {
                    ensure_candidate_limit(config_candidates.len() + 1)?;
                    reserve_metadata_strings(
                        &mut copied_metadata_bytes,
                        std::mem::size_of::<ConfigCandidate>(),
                        [
                            path,
                            &record.scope,
                            &record.source_path,
                            evidence_key,
                            &directive.line_sha256,
                        ],
                    )?;
                    config_candidates.push(ConfigCandidate {
                        path: path.to_owned(),
                        evidence: StartupEvidenceReference {
                            source: "systemd_unit",
                            scope: record.scope.clone(),
                            source_path: record.source_path.clone(),
                            key: evidence_key.to_owned(),
                            line: directive.line as u64,
                            byte_offset: directive.byte_offset as u64,
                            byte_length: directive.byte_length as u64,
                            source_sha256: directive.line_sha256.clone(),
                        },
                    });
                }
                None => unsupported_systemd = unsupported_systemd.saturating_add(1),
            }
        }
    }

    let trace = parse_trace_bytes(trace_bytes, Default::default())
        .map_err(|error| format!("trace parsing failed: {error}"))?;
    let trace_sha256 = trace.source_sha256.clone();
    let mut config_by_path: BTreeMap<String, Vec<StartupEvidenceReference>> = BTreeMap::new();
    for candidate in config_candidates {
        config_by_path
            .entry(candidate.path)
            .or_default()
            .push(candidate.evidence);
    }

    let mut runtime_by_path: BTreeMap<String, Vec<RuntimeEvidenceReference>> = BTreeMap::new();
    let mut unsupported_runtime = 0usize;
    for row in &trace.records {
        if row.kind != TraceRecordKind::Syscall
            || row.outcome != Some(SyscallOutcome::Success)
            || !matches!(row.syscall.as_deref(), Some("execve" | "execveat"))
        {
            continue;
        }
        let Some(syscall) = row.syscall.as_deref() else {
            continue;
        };
        let (argument_index, expected_arguments) =
            if syscall == "execve" { (0, 3) } else { (1, 5) };
        match strace_argument(
            row.raw_arguments.as_deref().unwrap_or_default(),
            argument_index,
            expected_arguments,
        ) {
            Some(raw_path) if literal_absolute_path(&raw_path) => {
                runtime_by_path.entry(raw_path.clone()).or_default().push(
                    RuntimeEvidenceReference {
                        trace_sha256: trace_sha256.clone(),
                        syscall: syscall.to_owned(),
                        caller_task_id: row.process_id,
                        evidence: row.evidence.clone(),
                    },
                );
            }
            _ => unsupported_runtime = unsupported_runtime.saturating_add(1),
        }
    }

    let mut candidate_matches = Vec::new();
    let mut config_evidence_count = 0usize;
    let mut runtime_evidence_count = 0usize;
    let supported_config_reference_count = config_by_path.values().map(Vec::len).sum();
    let supported_runtime_reference_count = runtime_by_path.values().map(Vec::len).sum();
    let mut unmatched_config_path_count = 0usize;
    for (path, startup_evidence) in config_by_path {
        if let Some(runtime_evidence) = runtime_by_path.remove(&path) {
            config_evidence_count = config_evidence_count.saturating_add(startup_evidence.len());
            runtime_evidence_count = runtime_evidence_count.saturating_add(runtime_evidence.len());
            candidate_matches.push(CandidateMatch {
                status: "candidate_match",
                match_basis: "exact_literal_absolute_executable_path",
                executable_path: path,
                multiple_startup_references: startup_evidence.len() > 1,
                multiple_runtime_observations: runtime_evidence.len() > 1,
                startup_evidence,
                runtime_evidence,
            });
        } else {
            unmatched_config_path_count = unmatched_config_path_count.saturating_add(1);
        }
    }
    let unmatched_runtime_path_count = runtime_by_path.len();
    candidate_matches.sort_by(|left, right| left.executable_path.cmp(&right.executable_path));
    let source_partial = startup_sources
        .iter()
        .any(|source| !matches!(source.status.as_str(), "complete" | "not_present"));
    let unsupported_coverage =
        unsupported_xdg > 0 || unsupported_systemd > 0 || unsupported_runtime > 0;
    let status = if startup.status == "complete"
        && startup.xdg_autostart.status == "complete"
        && startup.systemd_units.status == "complete"
        && startup.legacy_sources.status == "complete"
        && !source_partial
        && trace.parse_status == ParseCompleteness::Complete
        && !unsupported_coverage
    {
        "complete"
    } else {
        "partial"
    };

    Ok(StartupCorrelationDocument {
        schema: "sideeffect.startup_correlation",
        schema_version: 1,
        status,
        coverage: "narrow_supported_subset",
        claim: "A candidate match means only that a supported literal configured executable path exactly equals a successful execve/execveat filename argument in the supplied trace. It does not prove a startup hook ran, that the startup manager caused the process, or that unrelated activity is attributable.",
        startup_inventory_sha256: sha256_hex(startup_bytes),
        startup_inventory_status: startup.status,
        startup_capture_started_at_unix_ms: startup.capture_started_at_unix_ms,
        startup_capture_ended_at_unix_ms: startup.capture_ended_at_unix_ms,
        xdg_status: startup.xdg_autostart.status,
        systemd_status: startup.systemd_units.status,
        legacy_status: startup.legacy_sources.status,
        startup_sources,
        trace_sha256,
        trace_parse_status: trace.parse_status,
        trace_capture_completeness: "unknown_for_raw_trace_input",
        trace_diagnostic_count: trace.diagnostics.len(),
        trace_record_count: trace.records.len(),
        limitations: vec![
            "Only XDG Exec and systemd Service Exec* directives in a narrow literal-path subset are considered.",
            "Cron and SysV configuration, wrappers, PATH lookup, and argv[0] are not matched; symlink targets and canonicalized paths are not resolved. Exact literal path strings can refer to symlinks.",
            "A missing match is not evidence that a configured item did not execute or that no startup source exists.",
            "Inventory and trace are separate snapshots and are not an atomic view of system state.",
            "Startup source references are carried through from the supplied snapshot; source files are not re-read.",
            "Raw trace input does not establish capture completeness; parse completeness is reported separately.",
            "Fingerprints identify the supplied input bytes but do not authenticate their origin or contents.",
            "Trace rows and startup configuration are sensitive local data; review output before sharing.",
        ],
        summary: CorrelationSummary {
            candidate_match_path_count: candidate_matches.len(),
            config_evidence_count,
            runtime_evidence_count,
            supported_config_reference_count,
            supported_runtime_reference_count,
            unmatched_config_path_count,
            unmatched_runtime_path_count,
            unsupported_xdg_exec_count: unsupported_xdg,
            unsupported_systemd_exec_count: unsupported_systemd,
            successful_exec_rows_without_supported_path_count: unsupported_runtime,
        },
        candidate_matches,
    })
}

fn systemd_exec_evidence_key(key: &str) -> Option<&'static str> {
    Some(match key {
        "ExecStart" => "Service.ExecStart",
        "ExecStartPre" => "Service.ExecStartPre",
        "ExecStartPost" => "Service.ExecStartPost",
        "ExecCondition" => "Service.ExecCondition",
        "ExecStop" => "Service.ExecStop",
        "ExecStopPost" => "Service.ExecStopPost",
        "ExecReload" => "Service.ExecReload",
        _ => return None,
    })
}

fn ensure_candidate_limit(count: usize) -> Result<(), String> {
    if count > MAX_STARTUP_CORRELATION_CONFIG_ROWS {
        Err(format!(
            "startup inventory exceeds the {MAX_STARTUP_CORRELATION_CONFIG_ROWS} supported executable-reference limit"
        ))
    } else {
        Ok(())
    }
}

fn reserve_metadata_strings<'a>(
    used: &mut usize,
    fixed_bytes: usize,
    strings: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    let charge = strings
        .into_iter()
        .try_fold(fixed_bytes, |sum, value| sum.checked_add(value.len()))
        .ok_or_else(|| "startup correlation metadata size overflowed".to_owned())?;
    let total = used
        .checked_add(charge)
        .ok_or_else(|| "startup correlation metadata size overflowed".to_owned())?;
    if total > MAX_STARTUP_CORRELATION_METADATA_BYTES {
        return Err(format!(
            "startup correlation copied metadata exceeds the {MAX_STARTUP_CORRELATION_METADATA_BYTES} byte limit"
        ));
    }
    *used = total;
    Ok(())
}

fn push_startup_source_context(
    output: &mut Vec<StartupSourceContext>,
    metadata_bytes: &mut usize,
    source_family: &str,
    scope: &str,
    source_path: &str,
    status: &str,
    diagnostic_count: usize,
) -> Result<(), String> {
    reserve_metadata_strings(
        metadata_bytes,
        std::mem::size_of::<StartupSourceContext>(),
        [source_family, scope, source_path, status],
    )?;
    output.push(StartupSourceContext {
        source_family: source_family.to_owned(),
        scope: scope.to_owned(),
        source_path: source_path.to_owned(),
        status: status.to_owned(),
        diagnostic_count,
    });
    Ok(())
}

fn ensure_config_row_limit(count: usize) -> Result<(), String> {
    if count > MAX_STARTUP_CORRELATION_CONFIG_ROWS {
        Err(format!(
            "startup inventory exceeds the {MAX_STARTUP_CORRELATION_CONFIG_ROWS} executable-directive limit"
        ))
    } else {
        Ok(())
    }
}

/// Accept only an unquoted absolute first token. The command remainder is
/// deliberately not interpreted. Reject syntax which could make token
/// boundaries or the executable identity uncertain.
fn literal_executable(value: &str) -> Option<&str> {
    if value.len() > MAX_RECORD_BYTES || !value.is_ascii() {
        return None;
    }
    let token = value.split_ascii_whitespace().next()?;
    if !literal_absolute_path(token) {
        return None;
    }
    if value.bytes().any(|byte| {
        matches!(
            byte,
            b'\\' | b'"' | b'\'' | b'%' | b'`' | b'$' | b';' | b'|' | b'&'
        )
    }) {
        return None;
    }
    Some(token)
}

fn literal_absolute_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.is_empty()
        && path.len() <= MAX_RECORD_BYTES
        && path.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        && !path.contains([
            '\\', '"', '\'', '%', '`', '$', ';', '|', '&', '*', '?', '[', ']', '{', '}', '<', '>',
            '(', ')',
        ])
        && !path.contains("...")
}

/// Extract one strace argument using only bounded delimiter/quote tracking.
/// Quoted escapes are rejected by the later literal-path validator.
fn strace_argument(raw: &str, requested: usize, expected_count: usize) -> Option<String> {
    if raw.len() > MAX_RECORD_BYTES || expected_count > 8 || requested >= expected_count {
        return None;
    }
    let mut arguments = Vec::with_capacity(expected_count);
    let mut start = 0usize;
    let mut stack = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    for (offset, character) in raw.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            continue;
        }
        match character {
            '"' => quoted = true,
            '(' | '[' | '{' => {
                if stack.len() >= 64 {
                    return None;
                }
                stack.push(character);
            }
            ')' | ']' | '}' => {
                let expected = match character {
                    ')' => '(',
                    ']' => '[',
                    '}' => '{',
                    _ => unreachable!(),
                };
                if stack.pop() != Some(expected) {
                    return None;
                }
            }
            ',' if stack.is_empty() => {
                if arguments.len() + 1 >= expected_count {
                    return None;
                }
                let argument = raw.get(start..offset)?.trim();
                if argument.is_empty() {
                    return None;
                }
                arguments.push(argument);
                start = offset + character.len_utf8();
            }
            _ => {}
        }
    }
    if quoted || escaped || !stack.is_empty() {
        return None;
    }
    let argument = raw.get(start..)?.trim();
    if argument.is_empty() {
        return None;
    }
    arguments.push(argument);
    if arguments.len() != expected_count {
        return None;
    }
    decode_strace_string(arguments[requested])
}

fn decode_strace_string(value: &str) -> Option<String> {
    let inner = value.strip_prefix('"')?.strip_suffix('"')?;
    if inner.contains('"') || inner.contains('\\') || inner.contains("...") || !inner.is_ascii() {
        return None;
    }
    Some(inner.to_owned())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::MAX_STARTUP_CORRELATION_METADATA_BYTES;
    use super::{correlate_startup_bytes, literal_executable, strace_argument};
    use crate::limits::MAX_RECORD_BYTES;
    use crate::model::ParseCompleteness;
    use serde_json::json;

    fn startup(exec_values: &[(&str, &str)]) -> Vec<u8> {
        let xdg = exec_values
            .iter()
            .enumerate()
            .map(|(i, (scope, value))| {
                json!({
                    "scope": scope,
                    "source_path": format!("/config/{i}.desktop"),
                    "applicability": "not_evaluated",
                    "keys": [{
                        "key": "Exec", "value": value, "value_hex": null,
                        "line": 4, "byte_offset": 20, "byte_length": value.len(),
                        "line_sha256": format!("{i:064x}")
                    }]
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_vec(&json!({
            "schema": "sideeffect.startup_inventory", "schema_version": 2,
            "platform": "linux", "scope": "curated_xdg_systemd_sysv_cron_sources",
            "capture_started_at_unix_ms": 1, "capture_ended_at_unix_ms": 2,
            "status": "complete",
            "xdg_autostart": {"status":"complete", "directories":[], "entries":xdg},
            "systemd_units": {"status":"complete", "directories":[], "records":[]},
            "legacy_sources": {"status":"complete", "sources":[], "entries":[]}
        }))
        .unwrap()
    }

    #[test]
    fn accepts_only_simple_literal_absolute_executable_tokens() {
        assert_eq!(
            literal_executable("/usr/bin/example --version"),
            Some("/usr/bin/example")
        );
        for value in [
            "relative-tool",
            "\"/usr/bin/tool\"",
            "/usr/bin/tool%U",
            "/usr/bin/tool $(touch /tmp/sideeffect-injection)",
            "/usr/bin/tool\\ escaped",
            "/usr/bin/tool; /usr/bin/other",
        ] {
            assert_eq!(literal_executable(value), None, "{value}");
        }
    }

    #[test]
    fn parses_only_unescaped_quoted_filename_arguments() {
        assert_eq!(
            strace_argument("\"/usr/bin/a\", [\"x\"], []", 0, 3),
            Some("/usr/bin/a".to_owned())
        );
        assert_eq!(
            strace_argument("AT_FDCWD, \"/usr/bin/a\", [\"x\"], 0, 0", 1, 5),
            Some("/usr/bin/a".to_owned())
        );
        assert_eq!(
            strace_argument("\"/usr/bin/\u{005c}141\", [], []", 0, 3),
            None
        );
        assert_eq!(strace_argument("[\"/usr/bin/a\"], [], []", 0, 3), None);
        assert_eq!(strace_argument("\"/usr/bin/a\"", 0, 3), None);
        assert_eq!(strace_argument("\"/usr/bin/a\", , []", 0, 3), None);
    }

    #[test]
    fn reports_exact_candidate_match_with_both_evidence_references_and_ambiguity() {
        let inventory = startup(&[
            ("user", "/usr/bin/example --version"),
            ("system", "/usr/bin/example --other"),
            ("user", "$(touch /tmp/sideeffect-never-run)"),
        ]);
        let trace = b"100 execve(\"/usr/bin/example\", [\"example\"], 0x0) = 0\n";
        let report = correlate_startup_bytes(&inventory, trace).unwrap();
        assert_eq!(report.schema, "sideeffect.startup_correlation");
        assert_eq!(report.coverage, "narrow_supported_subset");
        assert_eq!(report.status, "partial");
        assert_eq!(report.trace_parse_status, ParseCompleteness::Complete);
        assert_eq!(report.summary.candidate_match_path_count, 1);
        assert_eq!(report.summary.config_evidence_count, 2);
        assert_eq!(report.summary.runtime_evidence_count, 1);
        let matched = &report.candidate_matches[0];
        assert_eq!(matched.status, "candidate_match");
        assert_eq!(matched.startup_evidence.len(), 2);
        assert!(matched.multiple_startup_references);
        assert_eq!(matched.runtime_evidence[0].evidence.line_number, 1);
        assert_eq!(
            matched.runtime_evidence[0].trace_sha256,
            report.trace_sha256
        );
        assert!(report.claim.contains("does not prove"));
    }

    #[test]
    fn unsupported_exec_path_forms_make_coverage_status_partial() {
        let inventory = startup(&[("user", "/usr/bin/example")]);
        let trace = b"100 execve(\"./example\", [\"example\"], 0x0) = 0\n";
        let report = correlate_startup_bytes(&inventory, trace).unwrap();
        assert_eq!(report.status, "partial");
        assert_eq!(
            report
                .summary
                .successful_exec_rows_without_supported_path_count,
            1
        );
    }

    #[test]
    fn failed_exec_calls_and_unsupported_forms_do_not_match() {
        let inventory = startup(&[("user", "/usr/bin/example")]);
        let trace = b"100 execve(\"/usr/bin/example\", [\"example\"], 0x0) = -1 ENOENT (No such file or directory)\n";
        let report = correlate_startup_bytes(&inventory, trace).unwrap();
        assert!(report.candidate_matches.is_empty());
        assert_eq!(report.summary.candidate_match_path_count, 0);
    }

    #[test]
    fn does_not_normalize_paths_or_match_legacy_cron_or_sysv_text() {
        let mut inventory: serde_json::Value =
            serde_json::from_slice(&startup(&[("user", "/usr/bin/./example")])).unwrap();
        inventory["legacy_sources"]["entries"] = json!([{
            "source_kind":"cron_system_file", "entry_kind":"inert_file", "path":"/etc/crontab",
            "path_bytes_hex":"", "lines":[{"line_number":1,"byte_offset":0,"byte_length":28,
            "line_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "raw_line":"* * * * * root /usr/bin/example"}]
        }]);
        let encoded = serde_json::to_vec(&inventory).unwrap();
        let trace = b"100 execve(\"/usr/bin/example\", [], []) = 0\n";
        let report = correlate_startup_bytes(&encoded, trace).unwrap();
        assert_eq!(report.status, "complete");
        assert!(report.candidate_matches.is_empty());
        assert_eq!(report.legacy_status, "complete");
        assert!(
            report
                .startup_sources
                .iter()
                .all(|source| source.source_family != "cron_system_file")
        );
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let mut inventory: serde_json::Value = serde_json::from_slice(&startup(&[])).unwrap();
        inventory["schema_version"] = json!(1);
        let bad = serde_json::to_vec(&inventory).unwrap();
        assert!(correlate_startup_bytes(&bad, b"").is_err());
    }

    #[test]
    fn enforces_the_supported_configuration_row_boundary() {
        assert!(super::ensure_config_row_limit(super::MAX_STARTUP_CORRELATION_CONFIG_ROWS).is_ok());
        assert!(
            super::ensure_config_row_limit(super::MAX_STARTUP_CORRELATION_CONFIG_ROWS + 1).is_err()
        );
    }

    #[test]
    fn rejects_oversized_copied_source_metadata_before_cloning_it() {
        let oversized_path = format!("/{}", "x".repeat(MAX_STARTUP_CORRELATION_METADATA_BYTES));

        let mut config_inventory: serde_json::Value =
            serde_json::from_slice(&startup(&[])).unwrap();
        config_inventory["xdg_autostart"]["entries"] = json!([{
            "scope":"user", "source_path":oversized_path, "applicability":"not_evaluated",
            "keys":[{"key":"Exec","value":"/usr/bin/example", "value_hex":null,
            "line":1,"byte_offset":0,"byte_length":20,
            "line_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
        }]);
        let encoded = serde_json::to_vec(&config_inventory).unwrap();
        let error =
            correlate_startup_bytes(&encoded, b"100 execve(\"/usr/bin/example\", [], []) = 0\n")
                .unwrap_err();
        assert!(error.contains("copied metadata exceeds"));

        let mut source_inventory: serde_json::Value =
            serde_json::from_slice(&startup(&[])).unwrap();
        source_inventory["xdg_autostart"]["directories"] = json!([{
            "scope":"user", "path":format!("/{}", "y".repeat(MAX_STARTUP_CORRELATION_METADATA_BYTES)),
            "status":"complete", "files_seen":0, "diagnostics":[]
        }]);
        let encoded = serde_json::to_vec(&source_inventory).unwrap();
        let error = correlate_startup_bytes(&encoded, b"").unwrap_err();
        assert!(error.contains("copied metadata exceeds"));
    }

    #[test]
    fn matches_systemd_execstart_filename_from_execveat_and_preserves_partial_trace_status() {
        let mut inventory: serde_json::Value = serde_json::from_slice(&startup(&[])).unwrap();
        inventory["status"] = json!("partial");
        inventory["systemd_units"]["status"] = json!("partial");
        inventory["systemd_units"]["directories"] = json!([]);
        inventory["systemd_units"]["records"] = json!([{
            "scope":"system", "source_path":"/etc/systemd/system/example.service",
            "record_type":"unit_file", "source_path_bytes_hex":"",
            "directives":[{
                "section":"Service", "key":"ExecStart", "value":"/usr/bin/example --safe",
                "value_hex":null, "line":9, "byte_offset":123, "byte_length":24,
                "line_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }]
        }]);
        let inventory = serde_json::to_vec(&inventory).unwrap();
        let trace = b"not a syscall row\n100 execveat(AT_FDCWD, \"/usr/bin/example\", [\"different-argv0\"], 0x0, 0) = 0\n101 execve(\"/usr/bin/example\", [\"another-argv0\"], 0x0) = 0\n";
        let report = correlate_startup_bytes(&inventory, trace).unwrap();
        assert_eq!(report.startup_inventory_status, "partial");
        assert_eq!(report.trace_parse_status, ParseCompleteness::Partial);
        assert_eq!(report.trace_diagnostic_count, 1);
        assert_eq!(report.candidate_matches.len(), 1);
        let evidence = &report.candidate_matches[0].startup_evidence[0];
        assert_eq!(evidence.source, "systemd_unit");
        assert_eq!(evidence.key, "Service.ExecStart");
        assert_eq!(report.candidate_matches[0].runtime_evidence.len(), 2);
        assert!(report.candidate_matches[0].multiple_runtime_observations);
        assert_eq!(
            report.candidate_matches[0].runtime_evidence[0].syscall,
            "execveat"
        );
    }

    #[test]
    fn refuses_oversized_and_shell_injected_configuration_values_without_execution() {
        let mut inventory: serde_json::Value = serde_json::from_slice(&startup(&[])).unwrap();
        inventory["xdg_autostart"]["entries"] = json!([{
            "scope":"user", "source_path":"/config/hostile.desktop", "applicability":"not_evaluated",
            "keys":[{
                "key":"Exec", "value":"/usr/bin/tool $(touch /tmp/sideeffect-should-not-exist)",
                "line":1,"byte_offset":0,"byte_length":12,"line_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }]
        }]);
        let encoded = serde_json::to_vec(&inventory).unwrap();
        let report =
            correlate_startup_bytes(&encoded, b"100 execve(\"/usr/bin/tool\", [], []) = 0\n")
                .unwrap();
        assert!(report.candidate_matches.is_empty());
        assert_eq!(report.summary.unsupported_xdg_exec_count, 1);
        let oversized = format!("/{}", "a".repeat(MAX_RECORD_BYTES));
        assert_eq!(literal_executable(&oversized), None);
    }
}
