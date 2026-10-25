use crate::fingerprint::sha256_hex;
use serde::Serialize;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_PROCESS_DIRECTORIES: usize = 8_192;
pub const MAX_STATUS_BYTES: usize = 64 * 1024;
pub const MAX_AGGREGATE_STATUS_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_PROCESS_SCAN_DURATION: Duration = Duration::from_secs(10);
pub const MAX_EXECUTABLE_LINK_BYTES: usize = 4 * 1024;
pub const MAX_AGGREGATE_EXECUTABLE_LINK_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessInventoryStatus {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessInventoryDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub capture_started_at_unix_ms: u128,
    pub capture_ended_at_unix_ms: u128,
    pub status: ProcessInventoryStatus,
    pub source: ProcessInventorySource,
    pub processes: Vec<ProcessRow>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessInventorySource {
    pub id: &'static str,
    pub status: ProcessInventoryStatus,
    pub directories_seen: usize,
    pub status_bytes_read: usize,
    pub diagnostics: Vec<ProcessDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessRow {
    pub pid: u32,
    pub executable_link: ProcessExecutableLink,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tgid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<[u32; 4]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<[u32; 4]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_inh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_prm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_eff: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_bnd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_amb: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_new_privs: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<u32>,
    pub evidence: Vec<ProcessEvidence>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessExecutableLink {
    pub status: ProcessExecutableLinkStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_bytes_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<ProcessExecutableEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessExecutableLinkStatus {
    Observed,
    Inaccessible,
    Vanished,
    OverLimit,
    Unsupported,
    Error,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessExecutableEvidence {
    pub source: String,
    pub byte_length: usize,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessEvidence {
    pub field: &'static str,
    pub line: usize,
    pub byte_offset: usize,
    pub byte_length: usize,
    pub line_sha256: String,
    pub raw_source_line: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_source_line_hex: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessDiagnostic {
    pub code: &'static str,
    pub pid: Option<u32>,
    pub field: Option<&'static str>,
    pub message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<ProcessEvidence>,
}

#[derive(Clone, Copy)]
struct Limits {
    directories: usize,
    status: usize,
    aggregate: usize,
}
const LIMITS: Limits = Limits {
    directories: MAX_PROCESS_DIRECTORIES,
    status: MAX_STATUS_BYTES,
    aggregate: MAX_AGGREGATE_STATUS_BYTES,
};

pub fn collect_processes() -> ProcessInventoryDocument {
    collect_processes_from(Path::new("/proc"))
}

/// Collects one bounded, non-atomic observation from an injectable procfs root.
pub fn collect_processes_from(proc_root: &Path) -> ProcessInventoryDocument {
    collect_with_limits(proc_root, LIMITS)
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn collect_with_limits(root: &Path, limits: Limits) -> ProcessInventoryDocument {
    let started_at = Instant::now();
    let started = now_ms();
    let mut rows = Vec::new();
    let mut diagnostics = Vec::new();
    let mut total_bytes = 0usize;
    let mut executable_bytes = 0usize;
    let mut directories_seen = 0usize;
    let mut partial = false;
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => {
            diagnostics.push(diag(
                "proc_root_unreadable",
                None,
                None,
                "Could not enumerate the procfs root.",
            ));
            return finish(started, rows, diagnostics, 0, 0, true);
        }
    };
    let mut pids = Vec::new();
    let mut enumeration_limited = false;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                partial = true;
                diagnostics.push(diag(
                    "directory_entry_unreadable",
                    None,
                    None,
                    "Could not read a procfs directory entry.",
                ));
                continue;
            }
        };
        let name = entry.file_name();
        let Some(text) = name.to_str() else { continue };
        if !text.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = text.parse::<u32>() else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        pids.push((pid, entry.path()));
        if pids.len() > limits.directories {
            enumeration_limited = true;
            break;
        }
    }
    pids.sort_by_key(|(pid, _)| *pid);
    if enumeration_limited {
        partial = true;
        pids.truncate(limits.directories);
        diagnostics.push(diag(
            "process_directory_limit_exceeded",
            None,
            None,
            "The process directory limit was reached; remaining entries were not checked.",
        ));
    }
    for (pid, directory) in pids {
        if started_at.elapsed() >= MAX_PROCESS_SCAN_DURATION {
            partial = true;
            diagnostics.push(diag(
                "process_scan_deadline_exceeded",
                Some(pid),
                None,
                "The process scan time limit was reached; remaining entries were not checked.",
            ));
            break;
        }
        directories_seen += 1;
        let path = directory.join("status");
        let remaining = limits.aggregate.saturating_sub(total_bytes);
        if remaining == 0 {
            partial = true;
            diagnostics.push(diag("aggregate_status_byte_limit_exceeded", Some(pid), None, "The aggregate status byte limit was reached; remaining processes were not checked."));
            break;
        }
        let cap = limits.status.min(remaining);
        let bytes = match read_bounded_status(&path, cap) {
            Ok(bytes) => bytes,
            Err(ReadStatusError::TooLarge(bytes_read)) => {
                total_bytes = total_bytes.saturating_add(bytes_read);
                partial = true;
                let code = if cap < limits.status {
                    "aggregate_status_byte_limit_exceeded"
                } else {
                    "status_file_limit_exceeded"
                };
                diagnostics.push(diag(
                    code,
                    Some(pid),
                    None,
                    "The status file exceeded the configured byte limit.",
                ));
                if cap < limits.status || total_bytes >= limits.aggregate {
                    break;
                }
                continue;
            }
            Err(ReadStatusError::Vanished) => {
                partial = true;
                diagnostics.push(diag(
                    "process_vanished",
                    Some(pid),
                    None,
                    "The process disappeared before its status file could be read.",
                ));
                continue;
            }
            Err(ReadStatusError::Unreadable(bytes_read)) => {
                total_bytes = total_bytes.saturating_add(bytes_read);
                partial = true;
                diagnostics.push(diag(
                    "status_unreadable",
                    Some(pid),
                    None,
                    "The process status file could not be read.",
                ));
                if total_bytes >= limits.aggregate {
                    break;
                }
                continue;
            }
        };
        total_bytes = total_bytes.saturating_add(bytes.len());
        let (mut row, mut row_diags) = parse_status(pid, &bytes);
        if !row_diags.is_empty() {
            partial = true;
        }
        let executable_limit = MAX_EXECUTABLE_LINK_BYTES
            .min(MAX_AGGREGATE_EXECUTABLE_LINK_BYTES.saturating_sub(executable_bytes));
        row.executable_link =
            match read_executable_link(&directory.join("exe"), pid, executable_limit) {
                Ok(identity) => {
                    executable_bytes =
                        executable_bytes.saturating_add(identity.byte_length.unwrap_or(0));
                    if identity.status != ProcessExecutableLinkStatus::Observed {
                        partial = true;
                        diagnostics.push(executable_link_diagnostic(pid, identity.status));
                    }
                    identity
                }
                Err(status) => {
                    partial = true;
                    diagnostics.push(executable_link_diagnostic(pid, status));
                    empty_executable_link(status)
                }
            };
        rows.push(row);
        diagnostics.append(&mut row_diags);
    }
    finish(
        started,
        rows,
        diagnostics,
        directories_seen,
        total_bytes,
        partial,
    )
}

fn finish(
    started: u128,
    processes: Vec<ProcessRow>,
    diagnostics: Vec<ProcessDiagnostic>,
    directories_seen: usize,
    status_bytes_read: usize,
    partial: bool,
) -> ProcessInventoryDocument {
    let status = if partial {
        ProcessInventoryStatus::Partial
    } else {
        ProcessInventoryStatus::Complete
    };
    ProcessInventoryDocument {
        schema: "sideeffect.process_inventory",
        schema_version: 1,
        platform: "linux",
        scope: "numeric_proc_status_entries",
        capture_started_at_unix_ms: started,
        capture_ended_at_unix_ms: now_ms(),
        status,
        source: ProcessInventorySource {
            id: "procfs_status",
            status,
            directories_seen,
            status_bytes_read,
            diagnostics,
        },
        processes,
    }
}

enum ReadStatusError {
    TooLarge(usize),
    Vanished,
    Unreadable(usize),
}
fn read_bounded_status(path: &Path, limit: usize) -> Result<Vec<u8>, ReadStatusError> {
    let file = fs::File::open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            ReadStatusError::Vanished
        } else {
            ReadStatusError::Unreadable(0)
        }
    })?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadStatusError::Unreadable(bytes.len()))?;
    if bytes.len() > limit {
        return Err(ReadStatusError::TooLarge(bytes.len()));
    }
    Ok(bytes)
}

fn diag(
    code: &'static str,
    pid: Option<u32>,
    field: Option<&'static str>,
    message: &'static str,
) -> ProcessDiagnostic {
    ProcessDiagnostic {
        code,
        pid,
        field,
        message,
        evidence: None,
    }
}

fn parse_status(pid: u32, bytes: &[u8]) -> (ProcessRow, Vec<ProcessDiagnostic>) {
    let mut row = ProcessRow {
        pid,
        executable_link: empty_executable_link(ProcessExecutableLinkStatus::Unsupported),
        name: None,
        tgid: None,
        ppid: None,
        state: None,
        uid: None,
        gid: None,
        cap_inh: None,
        cap_prm: None,
        cap_eff: None,
        cap_bnd: None,
        cap_amb: None,
        no_new_privs: None,
        seccomp: None,
        evidence: Vec::new(),
    };
    let mut diagnostics = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut offset = 0usize;
    for (line_index, raw) in bytes.split_inclusive(|b| *b == b'\n').enumerate() {
        let line_no = line_index + 1;
        let line = raw
            .strip_suffix(b"\n")
            .unwrap_or(raw)
            .strip_suffix(b"\r")
            .unwrap_or(raw.strip_suffix(b"\n").unwrap_or(raw));
        let line_end = offset + line.len();
        if let Some(colon) = line.iter().position(|b| *b == b':') {
            let key = &line[..colon];
            let field = match key {
                b"Name" => Some("Name"),
                b"Pid" => Some("Pid"),
                b"Tgid" => Some("Tgid"),
                b"PPid" => Some("PPid"),
                b"State" => Some("State"),
                b"Uid" => Some("Uid"),
                b"Gid" => Some("Gid"),
                b"CapInh" => Some("CapInh"),
                b"CapPrm" => Some("CapPrm"),
                b"CapEff" => Some("CapEff"),
                b"CapBnd" => Some("CapBnd"),
                b"CapAmb" => Some("CapAmb"),
                b"NoNewPrivs" => Some("NoNewPrivs"),
                b"Seccomp" => Some("Seccomp"),
                _ => None,
            };
            if let Some(field) = field {
                let evidence = ProcessEvidence {
                    field,
                    line: line_no,
                    byte_offset: offset,
                    byte_length: line.len(),
                    line_sha256: sha256_hex(line),
                    raw_source_line: String::from_utf8_lossy(line).into_owned(),
                    raw_source_line_hex: std::str::from_utf8(line)
                        .is_err()
                        .then(|| hex_bytes(line)),
                };
                if !seen.insert(field) {
                    if field == "Pid" {
                        row.pid = pid;
                    } else {
                        clear_field(&mut row, field);
                    }
                    diagnostics.push(ProcessDiagnostic { code: "duplicate_status_field", pid: Some(pid), field: Some(field), message: "A status field appeared more than once; the ambiguous value is omitted.", evidence: Some(evidence.clone()) });
                    row.evidence.push(evidence);
                } else {
                    let value = std::str::from_utf8(&line[colon + 1..]).ok().map(str::trim);
                    if value.is_none() || !set_field(&mut row, field, value.unwrap_or("")) {
                        diagnostics.push(ProcessDiagnostic {
                            code: "malformed_status_field",
                            pid: Some(pid),
                            field: Some(field),
                            message: "The status field value was malformed.",
                            evidence: Some(evidence.clone()),
                        });
                    }
                    row.evidence.push(evidence);
                }
            }
        }
        offset = line_end + (raw.len() - line.len());
    }
    for field in [
        "Name",
        "Pid",
        "Tgid",
        "PPid",
        "State",
        "Uid",
        "Gid",
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
        "Seccomp",
    ] {
        if !seen.contains(field) {
            diagnostics.push(diag(
                "missing_status_field",
                Some(pid),
                Some(field),
                "The expected status field was absent.",
            ));
        }
    }
    if row.pid != pid {
        diagnostics.push(diag(
            "pid_directory_mismatch",
            Some(pid),
            Some("Pid"),
            "The reported PID did not match the procfs directory name.",
        ));
    }
    (row, diagnostics)
}

fn empty_executable_link(status: ProcessExecutableLinkStatus) -> ProcessExecutableLink {
    ProcessExecutableLink {
        status,
        target_display: None,
        target_bytes_hex: None,
        byte_length: None,
        sha256: None,
        evidence: None,
    }
}

fn executable_link_diagnostic(pid: u32, status: ProcessExecutableLinkStatus) -> ProcessDiagnostic {
    let (code, message) = match status {
        ProcessExecutableLinkStatus::Inaccessible => (
            "process_executable_inaccessible",
            "The process executable link could not be read due to access restrictions.",
        ),
        ProcessExecutableLinkStatus::Vanished => (
            "process_executable_vanished",
            "The process executable link disappeared during collection.",
        ),
        ProcessExecutableLinkStatus::OverLimit => (
            "process_executable_link_limit_exceeded",
            "The process executable link exceeded the configured byte limit.",
        ),
        ProcessExecutableLinkStatus::Unsupported => (
            "process_executable_unsupported",
            "Executable link collection is unsupported for this process entry.",
        ),
        ProcessExecutableLinkStatus::Error => (
            "process_executable_error",
            "The process executable link could not be read due to an I/O error.",
        ),
        ProcessExecutableLinkStatus::Observed => (
            "process_executable_observed",
            "The process executable link was read.",
        ),
    };
    diag(code, Some(pid), Some("exe"), message)
}

/// Reads the procfs symlink itself with a fixed-size buffer; the target is never opened.
fn read_executable_link(
    path: &Path,
    pid: u32,
    limit: usize,
) -> Result<ProcessExecutableLink, ProcessExecutableLinkStatus> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| ProcessExecutableLinkStatus::Error)?;
    let mut buffer = vec![0u8; limit.saturating_add(1)];
    // SAFETY: path is NUL-terminated and buffer is writable for its declared length.
    let count = unsafe { libc::readlink(path.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len()) };
    if count < 0 {
        let error = io::Error::last_os_error();
        return Err(match error.kind() {
            io::ErrorKind::NotFound => match path_parent_state(&path) {
                ProcessExecutableLinkStatus::Observed => ProcessExecutableLinkStatus::Unsupported,
                state => state,
            },
            io::ErrorKind::PermissionDenied => ProcessExecutableLinkStatus::Inaccessible,
            _ => ProcessExecutableLinkStatus::Error,
        });
    }
    let count = count as usize;
    if count > limit {
        return Err(ProcessExecutableLinkStatus::OverLimit);
    }
    buffer.truncate(count);
    let hash = sha256_hex(&buffer);
    let source = format!("{pid}/exe");
    Ok(ProcessExecutableLink {
        status: ProcessExecutableLinkStatus::Observed,
        target_display: std::str::from_utf8(&buffer).ok().map(str::to_owned),
        target_bytes_hex: Some(hex_bytes(&buffer)),
        byte_length: Some(buffer.len()),
        sha256: Some(hash.clone()),
        evidence: Some(ProcessExecutableEvidence {
            source,
            byte_length: buffer.len(),
            sha256: hash,
        }),
    })
}

fn path_parent_state(path: &std::ffi::CStr) -> ProcessExecutableLinkStatus {
    use std::os::unix::ffi::OsStrExt;
    let Some(parent) = Path::new(std::ffi::OsStr::from_bytes(path.to_bytes())).parent() else {
        return ProcessExecutableLinkStatus::Error;
    };
    match fs::metadata(parent) {
        Ok(_) => ProcessExecutableLinkStatus::Observed,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            ProcessExecutableLinkStatus::Vanished
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            ProcessExecutableLinkStatus::Inaccessible
        }
        Err(_) => ProcessExecutableLinkStatus::Error,
    }
}

fn set_field(row: &mut ProcessRow, field: &str, value: &str) -> bool {
    match field {
        "Name" => {
            if value.is_empty() {
                false
            } else {
                row.name = Some(value.to_owned());
                true
            }
        }
        "Pid" => parse_num(value).map(|n| row.pid = n).is_some(),
        "Tgid" => set_num(value, &mut row.tgid),
        "PPid" => set_num(value, &mut row.ppid),
        "State" => {
            let mut parts = value.split_whitespace();
            let state = parts.next().unwrap_or("");
            if state.is_empty() {
                false
            } else {
                row.state = Some(value.to_owned());
                true
            }
        }
        "Uid" => set_four(value, &mut row.uid),
        "Gid" => set_four(value, &mut row.gid),
        "CapInh" => set_hex(value, &mut row.cap_inh),
        "CapPrm" => set_hex(value, &mut row.cap_prm),
        "CapEff" => set_hex(value, &mut row.cap_eff),
        "CapBnd" => set_hex(value, &mut row.cap_bnd),
        "CapAmb" => set_hex(value, &mut row.cap_amb),
        "NoNewPrivs" => set_num(value, &mut row.no_new_privs),
        "Seccomp" => set_num(value, &mut row.seccomp),
        _ => false,
    }
}

fn clear_field(row: &mut ProcessRow, field: &str) {
    match field {
        "Name" => row.name = None,
        "Pid" => {}
        "Tgid" => row.tgid = None,
        "PPid" => row.ppid = None,
        "State" => row.state = None,
        "Uid" => row.uid = None,
        "Gid" => row.gid = None,
        "CapInh" => row.cap_inh = None,
        "CapPrm" => row.cap_prm = None,
        "CapEff" => row.cap_eff = None,
        "CapBnd" => row.cap_bnd = None,
        "CapAmb" => row.cap_amb = None,
        "NoNewPrivs" => row.no_new_privs = None,
        "Seccomp" => row.seccomp = None,
        _ => {}
    }
}
fn parse_num(s: &str) -> Option<u32> {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse().ok()
    } else {
        None
    }
}
fn set_num(s: &str, out: &mut Option<u32>) -> bool {
    match parse_num(s) {
        Some(n) => {
            *out = Some(n);
            true
        }
        None => false,
    }
}
fn set_four(s: &str, out: &mut Option<[u32; 4]>) -> bool {
    let parts: Vec<_> = s.split_whitespace().collect();
    if parts.len() != 4 {
        return false;
    }
    let Some(a) = parse_num(parts[0]) else {
        return false;
    };
    let Some(b) = parse_num(parts[1]) else {
        return false;
    };
    let Some(c) = parse_num(parts[2]) else {
        return false;
    };
    let Some(d) = parse_num(parts[3]) else {
        return false;
    };
    *out = Some([a, b, c, d]);
    true
}
fn set_hex(s: &str, out: &mut Option<String>) -> bool {
    let v = s.trim();
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    *out = Some(v.to_owned());
    true
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "sideeffect-proc-fixture-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
        fn status(&self, pid: u32, bytes: &[u8]) {
            let d = self.0.join(pid.to_string());
            fs::create_dir(&d).unwrap();
            fs::write(d.join("status"), bytes).unwrap();
        }
        fn executable_link(&self, pid: u32, target: &[u8]) {
            let directory = self.0.join(pid.to_string());
            fs::create_dir_all(&directory).unwrap();
            symlink(std::ffi::OsStr::from_bytes(target), directory.join("exe")).unwrap();
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    const VALID:&[u8]=b"Name:\ttest\nUmask:\t0022\nState:\tR (running)\nTgid:\t42\nPid:\t42\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t2\n";
    #[test]
    fn parses_valid_status_and_exact_line_evidence() {
        let (row, d) = parse_status(42, VALID);
        assert!(d.is_empty());
        assert_eq!(row.name.as_deref(), Some("test"));
        assert_eq!(row.uid, Some([1000; 4]));
        assert_eq!(row.cap_eff.as_deref(), Some("0000000000000000"));
        let ev = row.evidence.iter().find(|e| e.field == "CapEff").unwrap();
        let line = b"CapEff:\t0000000000000000";
        assert_eq!(
            &VALID[ev.byte_offset..ev.byte_offset + ev.byte_length],
            line
        );
        assert_eq!(ev.raw_source_line, "CapEff:\t0000000000000000");
        assert_eq!(ev.line_sha256, sha256_hex(line));
    }
    #[test]
    fn malformed_and_missing_fields_are_diagnostics() {
        let bytes = b"Name:\tx\nPid:\tnope\nUid:\t1 2\n";
        let (r, d) = parse_status(7, bytes);
        assert!(r.tgid.is_none());
        assert!(
            d.iter()
                .any(|x| x.code == "malformed_status_field" && x.field == Some("Pid"))
        );
        assert!(
            d.iter()
                .any(|x| x.code == "missing_status_field" && x.field == Some("CapAmb"))
        );
    }
    #[test]
    fn invalid_utf8_in_selected_lines_retains_exact_hex_evidence() {
        let (row, diagnostics) = parse_status(7, b"Name:\tbad\xff\nPid:\t7\n");
        let evidence = row
            .evidence
            .iter()
            .find(|item| item.field == "Name")
            .unwrap();
        assert_eq!(evidence.raw_source_line, "Name:\tbad\u{fffd}");
        assert_eq!(
            evidence.raw_source_line_hex.as_deref(),
            Some("4e616d653a09626164ff")
        );
        assert_eq!(evidence.line_sha256, sha256_hex(b"Name:\tbad\xff"));
        assert!(
            diagnostics.iter().any(|item| {
                item.code == "malformed_status_field" && item.field == Some("Name")
            })
        );
    }
    #[test]
    fn duplicate_status_keys_are_omitted_as_ambiguous() {
        let bytes = b"Name:\tforged\nCapEff:\tffffffffffffffff\nUid:\t1 1 1 1\nCapEff:\t0000000000000000\nUid:\t1000 1000 1000 1000\nPid:\t7\n";
        let (row, diagnostics) = parse_status(7, bytes);
        assert_eq!(row.cap_eff, None);
        assert_eq!(row.uid, None);
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "duplicate_status_field" && item.field == Some("CapEff"))
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "duplicate_status_field" && item.field == Some("Uid"))
        );
    }
    #[test]
    fn executable_link_preserves_bytes_and_distinguishes_invalid_utf8() {
        let t = Temp::new();
        t.executable_link(42, b"/usr/bin/example");
        let observed = read_executable_link(&t.0.join("42/exe"), 42, 64).unwrap();
        assert_eq!(observed.status, ProcessExecutableLinkStatus::Observed);
        assert_eq!(observed.target_display.as_deref(), Some("/usr/bin/example"));
        assert_eq!(
            observed.target_bytes_hex.as_deref(),
            Some("2f7573722f62696e2f6578616d706c65")
        );
        assert_eq!(observed.byte_length, Some(16));
        assert_eq!(
            observed.sha256.as_deref(),
            Some(sha256_hex(b"/usr/bin/example").as_str())
        );
        assert_eq!(observed.evidence.as_ref().unwrap().byte_length, 16);

        t.executable_link(43, b"/bin/bad\xff");
        let invalid = read_executable_link(&t.0.join("43/exe"), 43, 64).unwrap();
        assert_eq!(invalid.target_display, None);
        assert_eq!(
            invalid.target_bytes_hex.as_deref(),
            Some("2f62696e2f626164ff")
        );
        assert_eq!(invalid.byte_length, Some(9));
    }
    #[test]
    fn executable_link_missing_error_and_over_limit_are_explicit() {
        let t = Temp::new();
        assert_eq!(
            read_executable_link(&t.0.join("missing/exe"), 7, 8).unwrap_err(),
            ProcessExecutableLinkStatus::Vanished
        );
        fs::create_dir(t.0.join("no-executable")).unwrap();
        assert_eq!(
            read_executable_link(&t.0.join("no-executable/exe"), 7, 8).unwrap_err(),
            ProcessExecutableLinkStatus::Unsupported
        );
        fs::create_dir(t.0.join("not-a-link")).unwrap();
        assert_eq!(
            read_executable_link(&t.0.join("not-a-link"), 7, 8).unwrap_err(),
            ProcessExecutableLinkStatus::Error
        );
        t.executable_link(42, b"/a/long/target");
        assert_eq!(
            read_executable_link(&t.0.join("42/exe"), 42, 4).unwrap_err(),
            ProcessExecutableLinkStatus::OverLimit
        );
    }
    #[test]
    fn missing_unreadable_and_vanished_rows_are_partial() {
        let t = Temp::new();
        t.status(1, b"Name:\tpartial\nPid:\t1\n");
        fs::create_dir(t.0.join("2")).unwrap();
        let d3 = t.0.join("3");
        fs::create_dir(&d3).unwrap();
        fs::create_dir(d3.join("status")).unwrap();
        let doc = collect_with_limits(
            &t.0,
            Limits {
                directories: 20,
                status: 1024,
                aggregate: 4096,
            },
        );
        assert_eq!(doc.status, ProcessInventoryStatus::Partial);
        assert!(
            doc.source
                .diagnostics
                .iter()
                .any(|d| d.code == "process_vanished")
        );
        assert!(
            doc.source
                .diagnostics
                .iter()
                .any(|d| d.code == "status_unreadable")
        );
        assert!(
            doc.source
                .diagnostics
                .iter()
                .any(|d| d.code == "missing_status_field")
        );
    }
    #[test]
    fn exact_status_limit_succeeds_and_limit_plus_one_is_partial() {
        let t = Temp::new();
        t.status(42, VALID);
        t.executable_link(42, b"/synthetic/not-opened");
        let doc = collect_with_limits(
            &t.0,
            Limits {
                directories: 1,
                status: VALID.len(),
                aggregate: VALID.len(),
            },
        );
        assert_eq!(doc.source.status, ProcessInventoryStatus::Complete);
        assert_eq!(doc.source.status_bytes_read, VALID.len());
        let t = Temp::new();
        t.status(1, b"12345");
        let doc = collect_with_limits(
            &t.0,
            Limits {
                directories: 1,
                status: 4,
                aggregate: 8,
            },
        );
        assert!(
            doc.source
                .diagnostics
                .iter()
                .any(|d| d.code == "status_file_limit_exceeded")
        );
    }
    #[test]
    fn aggregate_and_directory_limits_are_reported_separately() {
        let t = Temp::new();
        t.status(1, b"abc");
        t.status(2, b"def");
        let doc = collect_with_limits(
            &t.0,
            Limits {
                directories: 3,
                status: 3,
                aggregate: 3,
            },
        );
        assert!(
            doc.source
                .diagnostics
                .iter()
                .any(|d| d.code == "aggregate_status_byte_limit_exceeded")
        );
        let t = Temp::new();
        t.status(42, VALID);
        let doc = collect_with_limits(
            &t.0,
            Limits {
                directories: 1,
                status: VALID.len(),
                aggregate: VALID.len(),
            },
        );
        assert!(
            !doc.source
                .diagnostics
                .iter()
                .any(|d| d.code == "process_directory_limit_exceeded")
        );
        let t = Temp::new();
        t.status(1, b"a");
        t.status(2, b"b");
        let doc = collect_with_limits(
            &t.0,
            Limits {
                directories: 1,
                status: 3,
                aggregate: 10,
            },
        );
        assert!(
            doc.source
                .diagnostics
                .iter()
                .any(|d| d.code == "process_directory_limit_exceeded")
        );
    }
}
