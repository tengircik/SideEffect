//! Bounded, read-only discovery of systemd unit-file configuration.
//!
//! Unit directives and symlink targets are inert evidence. This module does not
//! execute or resolve `Exec*` values, inspect manager state, or determine whether
//! a unit is active, enabled in effective manager context, or applicable.
//! Directive values and paths can contain sensitive local configuration and are
//! retained without redaction; callers should handle the resulting document as
//! sensitive data.
#![cfg(target_os = "linux")]

use crate::fingerprint::sha256_hex;
use serde::Serialize;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_UNIT_DIRECTORIES: usize = 32;
pub const MAX_UNIT_FILES: usize = 4096;
pub const MAX_UNIT_DIRECTORY_ENTRIES: usize = 16_384;
pub const MAX_UNIT_FILE_BYTES: usize = 256 * 1024;
pub const MAX_UNIT_TOTAL_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_UNIT_RECORDS: usize = 10_000;
pub const MAX_UNIT_SCAN_TIME: Duration = Duration::from_secs(5);
pub const MAX_UNIT_LINE_BYTES: usize = 64 * 1024;
pub const MAX_SYMLINK_TARGET_BYTES: usize = 4096;
pub const MAX_TOTAL_SYMLINK_TARGET_BYTES: usize = 1024 * 1024;

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitDirectory {
    pub scope: &'static str,
    pub path: PathBuf,
}

/// Common vendor and administrator unit search paths. Missing optional paths are
/// represented as empty; callers should not interpret this list as exhaustive.
pub fn default_unit_directories(home: Option<&OsStr>) -> Vec<UnitDirectory> {
    let mut dirs = vec![
        UnitDirectory {
            scope: "system",
            path: "/etc/systemd/system".into(),
        },
        UnitDirectory {
            scope: "system",
            path: "/run/systemd/system".into(),
        },
        UnitDirectory {
            scope: "system",
            path: "/usr/local/lib/systemd/system".into(),
        },
        UnitDirectory {
            scope: "system",
            path: "/usr/lib/systemd/system".into(),
        },
        UnitDirectory {
            scope: "system",
            path: "/lib/systemd/system".into(),
        },
        UnitDirectory {
            scope: "global_user",
            path: "/etc/systemd/user".into(),
        },
        UnitDirectory {
            scope: "global_user",
            path: "/run/systemd/user".into(),
        },
        UnitDirectory {
            scope: "global_user",
            path: "/usr/local/lib/systemd/user".into(),
        },
        UnitDirectory {
            scope: "global_user",
            path: "/usr/lib/systemd/user".into(),
        },
        UnitDirectory {
            scope: "global_user",
            path: "/lib/systemd/user".into(),
        },
        UnitDirectory {
            scope: "global_user",
            path: "/usr/local/share/systemd/user".into(),
        },
        UnitDirectory {
            scope: "global_user",
            path: "/usr/share/systemd/user".into(),
        },
    ];
    if let Some(home) = home.filter(|h| !h.is_empty()) {
        let home = PathBuf::from(home);
        dirs.extend([
            UnitDirectory {
                scope: "user",
                path: home.join(".config/systemd/user"),
            },
            UnitDirectory {
                scope: "user",
                path: home.join(".local/share/systemd/user"),
            },
        ]);
    }
    let config_dirs = std::env::var_os("XDG_CONFIG_DIRS")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsStr::new("/etc/xdg").to_owned());
    append_configured_paths(&mut dirs, &config_dirs, "user_config_dir");
    let data_dirs = std::env::var_os("XDG_DATA_DIRS")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsStr::new("/usr/local/share:/usr/share").to_owned());
    append_configured_paths(&mut dirs, &data_dirs, "user_data_dir");
    dirs
}

fn append_configured_paths(dirs: &mut Vec<UnitDirectory>, paths: &OsStr, scope: &'static str) {
    let available = MAX_UNIT_DIRECTORIES.saturating_sub(dirs.len());
    let bounded = std::env::split_paths(paths)
        .take(available.saturating_add(1))
        .collect::<Vec<_>>();
    let exceeded = bounded.len() > available;
    dirs.extend(
        bounded
            .into_iter()
            .take(available)
            .map(|path| UnitDirectory {
                scope,
                path: path.join("systemd/user"),
            }),
    );
    if exceeded {
        dirs.push(UnitDirectory {
            scope,
            path: PathBuf::from("additional configured directories not checked"),
        });
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Serialize)]
pub struct UnitInventory {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub capture_started_at_unix_ms: u128,
    pub capture_ended_at_unix_ms: u128,
    pub status: Status,
    pub directories: Vec<DirectoryStatus>,
    pub records: Vec<UnitRecord>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DirectoryStatus {
    pub scope: &'static str,
    pub path: String,
    pub path_bytes_hex: String,
    pub status: Status,
    pub entries_seen: usize,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UnitRecord {
    pub scope: &'static str,
    pub source_path: String,
    pub source_path_bytes_hex: String,
    /// `unit_file`, `unit_symlink`, or a symlink inside a `*.wants`/`*.requires` directory.
    pub record_type: &'static str,
    pub symlink_target: Option<ValueEvidence>,
    pub directives: Vec<DirectiveEvidence>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValueEvidence {
    pub value: Option<String>,
    pub value_hex: Option<String>,
    pub byte_length: usize,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DirectiveEvidence {
    pub section: String,
    pub key: String,
    pub value: Option<String>,
    pub value_hex: Option<String>,
    pub line: usize,
    pub byte_offset: usize,
    pub byte_length: usize,
    pub line_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Diagnostic {
    pub code: &'static str,
    pub path: Option<String>,
    pub path_bytes_hex: Option<String>,
    pub line: Option<usize>,
    pub byte_offset: Option<usize>,
}

#[derive(Clone, Debug)]
struct Candidate {
    path: PathBuf,
    enabled_reference: bool,
    drop_in: bool,
}

pub fn collect_systemd_units() -> UnitInventory {
    collect_systemd_units_from(&default_unit_directories(
        std::env::var_os("HOME").as_deref(),
    ))
}

/// Injectable paths for deterministic callers and tests.
pub fn collect_systemd_units_from(dirs: &[UnitDirectory]) -> UnitInventory {
    collect_with_limits(
        dirs,
        MAX_UNIT_FILES,
        MAX_UNIT_FILE_BYTES,
        MAX_UNIT_TOTAL_BYTES,
        MAX_UNIT_SCAN_TIME,
        MAX_UNIT_RECORDS,
    )
}

fn collect_with_limits(
    dirs: &[UnitDirectory],
    max_files: usize,
    max_file: usize,
    max_total: usize,
    duration: Duration,
    max_records: usize,
) -> UnitInventory {
    collect_with_symlink_budget(
        dirs,
        max_files,
        max_file,
        max_total,
        duration,
        max_records,
        MAX_TOTAL_SYMLINK_TARGET_BYTES,
    )
}

fn collect_with_symlink_budget(
    dirs: &[UnitDirectory],
    max_files: usize,
    max_file: usize,
    max_total: usize,
    duration: Duration,
    max_records: usize,
    max_symlink_target_bytes: usize,
) -> UnitInventory {
    let started = Instant::now();
    let capture_started = now_ms();
    let mut directories = Vec::new();
    let mut records = Vec::new();
    let mut total_bytes = 0usize;
    let mut symlink_target_bytes = 0usize;
    let mut file_count = 0usize;
    let mut entries_total = 0usize;
    let mut lines_total = 0usize;
    let mut partial = false;

    for input in dirs.iter().take(MAX_UNIT_DIRECTORIES) {
        let mut row = DirectoryStatus {
            scope: input.scope,
            path: display_path(&input.path),
            path_bytes_hex: path_bytes_hex(&input.path),
            status: Status::Complete,
            entries_seen: 0,
            diagnostics: Vec::new(),
        };
        if started.elapsed() >= duration {
            add_diag(&mut row, "scan_deadline_exceeded", None, None, None);
            partial = true;
            row.status = Status::Partial;
            directories.push(row);
            continue;
        }
        if !input.path.is_absolute() {
            add_diag(&mut row, "directory_invalid", None, None, None);
            partial = true;
            row.status = Status::Partial;
            directories.push(row);
            continue;
        }
        match fs::symlink_metadata(&input.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                directories.push(row);
                continue;
            }
            Err(_) => {
                add_diag(&mut row, "directory_unreadable", None, None, None);
            }
            Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
                add_diag(&mut row, "directory_invalid", None, None, None);
            }
            Ok(_) => {
                let list = match fs::read_dir(&input.path) {
                    Ok(x) => x,
                    Err(_) => {
                        add_diag(&mut row, "directory_unreadable", None, None, None);
                        row.status = Status::Partial;
                        directories.push(row);
                        partial = true;
                        continue;
                    }
                };
                let mut paths: Vec<Candidate> = Vec::new();
                let mut limit_hit = false;
                for item in list {
                    entries_total = entries_total.saturating_add(1);
                    row.entries_seen = row.entries_seen.saturating_add(1);
                    if entries_total > MAX_UNIT_DIRECTORY_ENTRIES {
                        add_diag(&mut row, "directory_entry_limit_exceeded", None, None, None);
                        break;
                    }
                    if started.elapsed() >= duration {
                        add_diag(&mut row, "scan_deadline_exceeded", None, None, None);
                        break;
                    }
                    match item {
                        Err(_) => {
                            add_diag(&mut row, "directory_entry_unreadable", None, None, None)
                        }
                        Ok(entry) => {
                            let path = entry.path();
                            let name = entry.file_name();
                            let name_bytes = name.as_bytes();
                            let is_group = name_bytes.ends_with(b".wants")
                                || name_bytes.ends_with(b".requires");
                            if looks_like_unit_dropin_dir(&name) {
                                match fs::symlink_metadata(&path) {
                                    Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {
                                        match fs::read_dir(&path) {
                                            Ok(children) => {
                                                for child in children {
                                                    entries_total = entries_total.saturating_add(1);
                                                    row.entries_seen =
                                                        row.entries_seen.saturating_add(1);
                                                    if entries_total > MAX_UNIT_DIRECTORY_ENTRIES {
                                                        add_diag(
                                                            &mut row,
                                                            "directory_entry_limit_exceeded",
                                                            None,
                                                            None,
                                                            None,
                                                        );
                                                        limit_hit = true;
                                                        break;
                                                    }
                                                    if started.elapsed() >= duration {
                                                        add_diag(
                                                            &mut row,
                                                            "scan_deadline_exceeded",
                                                            None,
                                                            None,
                                                            None,
                                                        );
                                                        limit_hit = true;
                                                        break;
                                                    }
                                                    match child {
                                                        Ok(c)
                                                            if c.file_name()
                                                                .as_bytes()
                                                                .ends_with(b".conf") =>
                                                        {
                                                            paths.push(Candidate {
                                                                path: c.path(),
                                                                enabled_reference: false,
                                                                drop_in: true,
                                                            })
                                                        }
                                                        Ok(_) => {}
                                                        Err(_) => add_diag(
                                                            &mut row,
                                                            "directory_entry_unreadable",
                                                            None,
                                                            None,
                                                            None,
                                                        ),
                                                    }
                                                }
                                            }
                                            Err(_) => add_diag(
                                                &mut row,
                                                "directory_unreadable",
                                                Some(&path),
                                                None,
                                                None,
                                            ),
                                        }
                                    }
                                    Ok(m) if m.file_type().is_symlink() => add_diag(
                                        &mut row,
                                        "drop_in_directory_symlink",
                                        Some(&path),
                                        None,
                                        None,
                                    ),
                                    Ok(_) => add_diag(
                                        &mut row,
                                        "directory_invalid",
                                        Some(&path),
                                        None,
                                        None,
                                    ),
                                    Err(_) => add_diag(
                                        &mut row,
                                        "directory_unreadable",
                                        Some(&path),
                                        None,
                                        None,
                                    ),
                                }
                            } else if is_group {
                                match fs::symlink_metadata(&path) {
                                    Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {
                                        match fs::read_dir(&path) {
                                            Ok(children) => {
                                                for child in children {
                                                    entries_total = entries_total.saturating_add(1);
                                                    row.entries_seen =
                                                        row.entries_seen.saturating_add(1);
                                                    if entries_total > MAX_UNIT_DIRECTORY_ENTRIES {
                                                        add_diag(
                                                            &mut row,
                                                            "directory_entry_limit_exceeded",
                                                            None,
                                                            None,
                                                            None,
                                                        );
                                                        limit_hit = true;
                                                        break;
                                                    }
                                                    match child {
                                                        Ok(c)
                                                            if looks_like_unit(&c.file_name()) =>
                                                        {
                                                            paths.push(Candidate {
                                                                path: c.path(),
                                                                enabled_reference: true,
                                                                drop_in: false,
                                                            })
                                                        }
                                                        Ok(_) => {}
                                                        Err(_) => add_diag(
                                                            &mut row,
                                                            "directory_entry_unreadable",
                                                            None,
                                                            None,
                                                            None,
                                                        ),
                                                    }
                                                }
                                            }
                                            Err(_) => add_diag(
                                                &mut row,
                                                "directory_unreadable",
                                                Some(&path),
                                                None,
                                                None,
                                            ),
                                        }
                                    }
                                    Ok(_) => add_diag(
                                        &mut row,
                                        "directory_invalid",
                                        Some(&path),
                                        None,
                                        None,
                                    ),
                                    Err(_) => add_diag(
                                        &mut row,
                                        "directory_unreadable",
                                        Some(&path),
                                        None,
                                        None,
                                    ),
                                }
                            } else if looks_like_unit(&name) {
                                paths.push(Candidate {
                                    path,
                                    enabled_reference: false,
                                    drop_in: false,
                                });
                            }
                        }
                    }
                    if limit_hit {
                        break;
                    }
                }
                paths.sort_by(|a, b| a.path.cmp(&b.path));
                for candidate in paths {
                    let Candidate {
                        path,
                        enabled_reference: enabled_ref,
                        drop_in,
                    } = candidate;
                    if started.elapsed() >= duration {
                        add_diag(&mut row, "scan_deadline_exceeded", None, None, None);
                        break;
                    }
                    if file_count >= max_files {
                        add_diag(
                            &mut row,
                            "file_count_limit_exceeded",
                            Some(&path),
                            None,
                            None,
                        );
                        break;
                    }
                    if total_bytes >= max_total {
                        add_diag(
                            &mut row,
                            "aggregate_byte_limit_exceeded",
                            Some(&path),
                            None,
                            None,
                        );
                        break;
                    }
                    file_count += 1;
                    let sm = match fs::symlink_metadata(&path) {
                        Ok(m) => m,
                        Err(_) => {
                            add_diag(
                                &mut row,
                                "file_metadata_unavailable",
                                Some(&path),
                                None,
                                None,
                            );
                            continue;
                        }
                    };
                    if sm.file_type().is_symlink() {
                        if drop_in {
                            add_diag(&mut row, "drop_in_file_symlink", Some(&path), None, None);
                            continue;
                        }
                        let target = match fs::read_link(&path) {
                            Ok(target)
                                if target.as_os_str().as_bytes().len()
                                    > MAX_SYMLINK_TARGET_BYTES =>
                            {
                                add_diag(
                                    &mut row,
                                    "symlink_target_limit_exceeded",
                                    Some(&path),
                                    None,
                                    None,
                                );
                                None
                            }
                            Ok(target) => {
                                let target_bytes = target.as_os_str().as_bytes();
                                let remaining =
                                    max_symlink_target_bytes.saturating_sub(symlink_target_bytes);
                                if target_bytes.len() > remaining {
                                    add_diag(
                                        &mut row,
                                        "symlink_target_aggregate_limit_exceeded",
                                        Some(&path),
                                        None,
                                        None,
                                    );
                                    None
                                } else {
                                    symlink_target_bytes =
                                        symlink_target_bytes.saturating_add(target_bytes.len());
                                    Some(value_evidence(target_bytes))
                                }
                            }
                            Err(_) => {
                                add_diag(
                                    &mut row,
                                    "symlink_target_unavailable",
                                    Some(&path),
                                    None,
                                    None,
                                );
                                None
                            }
                        };
                        records.push(UnitRecord {
                            scope: input.scope,
                            source_path: display_path(&path),
                            source_path_bytes_hex: path_bytes_hex(&path),
                            record_type: if enabled_ref {
                                "enabled_reference_symlink"
                            } else {
                                "unit_symlink"
                            },
                            symlink_target: target,
                            directives: Vec::new(),
                        });
                        continue;
                    }
                    if !sm.is_file() {
                        add_diag(&mut row, "file_not_regular", Some(&path), None, None);
                        continue;
                    }
                    if enabled_ref {
                        add_diag(
                            &mut row,
                            "enabled_reference_not_symlink",
                            Some(&path),
                            None,
                            None,
                        );
                    }
                    let file = match OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                        .open(&path)
                    {
                        Ok(f) => f,
                        Err(_) => {
                            add_diag(&mut row, "file_unreadable", Some(&path), None, None);
                            continue;
                        }
                    };
                    let opened_metadata = match file.metadata() {
                        Ok(metadata) => metadata,
                        Err(_) => {
                            add_diag(
                                &mut row,
                                "file_metadata_unavailable",
                                Some(&path),
                                None,
                                None,
                            );
                            continue;
                        }
                    };
                    if !opened_metadata.is_file() {
                        add_diag(&mut row, "file_not_regular", Some(&path), None, None);
                        continue;
                    }
                    if !same_file_identity(&sm, &opened_metadata) {
                        add_diag(&mut row, "file_identity_changed", Some(&path), None, None);
                        continue;
                    }
                    let remaining = max_total.saturating_sub(total_bytes);
                    let limit = max_file.min(remaining);
                    let mut bytes = Vec::new();
                    if file.take(limit as u64 + 1).read_to_end(&mut bytes).is_err() {
                        total_bytes = total_bytes.saturating_add(bytes.len());
                        add_diag(&mut row, "file_read_failed", Some(&path), None, None);
                        continue;
                    }
                    total_bytes = total_bytes.saturating_add(bytes.len());
                    if bytes.len() > limit {
                        add_diag(
                            &mut row,
                            if bytes.len() > remaining {
                                "aggregate_byte_limit_exceeded"
                            } else {
                                "file_limit_exceeded"
                            },
                            Some(&path),
                            None,
                            None,
                        );
                        continue;
                    }
                    let parsed = parse_unit(&bytes, max_records.saturating_sub(lines_total));
                    lines_total = lines_total.saturating_add(parsed.lines_read);
                    for (code, line, offset) in parsed.diagnostics {
                        add_diag(&mut row, code, Some(&path), line, offset);
                    }
                    records.push(UnitRecord {
                        scope: input.scope,
                        source_path: display_path(&path),
                        source_path_bytes_hex: path_bytes_hex(&path),
                        record_type: if drop_in { "drop_in_file" } else { "unit_file" },
                        symlink_target: None,
                        directives: parsed.directives,
                    });
                }
            }
        }
        if !row.diagnostics.is_empty() {
            row.status = Status::Partial;
            partial = true;
        }
        directories.push(row);
    }
    if dirs.len() > MAX_UNIT_DIRECTORIES {
        let mut row = DirectoryStatus {
            scope: "system",
            path: "additional unit directories not checked".into(),
            path_bytes_hex: hex(b"additional unit directories not checked"),
            status: Status::Partial,
            entries_seen: 0,
            diagnostics: Vec::new(),
        };
        add_diag(&mut row, "directory_count_limit_exceeded", None, None, None);
        directories.push(row);
        partial = true;
    }
    UnitInventory {
        schema: "sideeffect.systemd_unit_inventory",
        schema_version: 1,
        platform: "linux",
        scope: "systemd_unit_files_and_enablement_symlink_references",
        capture_started_at_unix_ms: capture_started,
        capture_ended_at_unix_ms: now_ms(),
        status: if partial {
            Status::Partial
        } else {
            Status::Complete
        },
        directories,
        records,
    }
}

fn looks_like_unit(name: &OsStr) -> bool {
    let b = name.as_bytes();
    has_unit_suffix(b)
}

fn looks_like_unit_dropin_dir(name: &OsStr) -> bool {
    name.as_bytes()
        .strip_suffix(b".d")
        .is_some_and(has_unit_suffix)
}

fn has_unit_suffix(b: &[u8]) -> bool {
    [
        b".service".as_slice(),
        b".socket",
        b".target",
        b".device",
        b".timer",
        b".path",
        b".mount",
        b".automount",
        b".swap",
        b".slice",
        b".scope",
        b".busname",
    ]
    .iter()
    .any(|s| b.ends_with(s))
}
fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
fn path_bytes_hex(path: &Path) -> String {
    hex(path.as_os_str().as_bytes())
}
fn same_file_identity(before: &fs::Metadata, opened: &fs::Metadata) -> bool {
    before.dev() == opened.dev() && before.ino() == opened.ino()
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}
fn value_evidence(bytes: &[u8]) -> ValueEvidence {
    ValueEvidence {
        value: std::str::from_utf8(bytes).ok().map(str::to_owned),
        value_hex: std::str::from_utf8(bytes).is_err().then(|| hex(bytes)),
        byte_length: bytes.len(),
        sha256: sha256_hex(bytes),
    }
}
fn add_diag(
    row: &mut DirectoryStatus,
    code: &'static str,
    path: Option<&Path>,
    line: Option<usize>,
    offset: Option<usize>,
) {
    row.diagnostics.push(Diagnostic {
        code,
        path: path.map(display_path),
        path_bytes_hex: path.map(path_bytes_hex),
        line,
        byte_offset: offset,
    });
}

struct Parsed {
    directives: Vec<DirectiveEvidence>,
    diagnostics: Vec<(&'static str, Option<usize>, Option<usize>)>,
    lines_read: usize,
}
fn parse_unit(bytes: &[u8], max_lines: usize) -> Parsed {
    let mut out = Parsed {
        directives: Vec::new(),
        diagnostics: Vec::new(),
        lines_read: 0,
    };
    let mut section: Option<String> = None;
    let mut offset = 0usize;
    for (index, chunk) in bytes.split_inclusive(|b| *b == b'\n').enumerate() {
        if out.lines_read >= max_lines {
            out.diagnostics
                .push(("record_limit_exceeded", Some(index + 1), Some(offset)));
            break;
        }
        out.lines_read += 1;
        let content = chunk.strip_suffix(b"\n").unwrap_or(chunk);
        let content = content.strip_suffix(b"\r").unwrap_or(content);
        if content.len() > MAX_UNIT_LINE_BYTES {
            out.diagnostics
                .push(("line_limit_exceeded", Some(index + 1), Some(offset)));
            offset += chunk.len();
            continue;
        }
        let trimmed = trim_ascii(content);
        if trimmed.is_empty() || trimmed.starts_with(b"#") || trimmed.starts_with(b";") {
            offset += chunk.len();
            continue;
        }
        if trimmed.starts_with(b"[") && trimmed.ends_with(b"]") && trimmed.len() > 2 {
            match std::str::from_utf8(&trimmed[1..trimmed.len() - 1]) {
                Ok(s) if !s.chars().any(|c| matches!(c, '[' | ']' | '\n' | '\r')) => {
                    section = Some(s.to_owned())
                }
                _ => {
                    section = None;
                    out.diagnostics
                        .push(("malformed_section", Some(index + 1), Some(offset)));
                }
            }
            offset += chunk.len();
            continue;
        }
        let Some(eq) = content.iter().position(|b| *b == b'=') else {
            out.diagnostics
                .push(("malformed_directive", Some(index + 1), Some(offset)));
            offset += chunk.len();
            continue;
        };
        let key = trim_ascii(&content[..eq]);
        if key.is_empty()
            || key
                .iter()
                .any(|b| b.is_ascii_whitespace() || *b == b'[' || *b == b']')
        {
            out.diagnostics
                .push(("malformed_directive", Some(index + 1), Some(offset)));
            offset += chunk.len();
            continue;
        }
        let Some(section_name) = section.clone() else {
            out.diagnostics
                .push(("directive_outside_section", Some(index + 1), Some(offset)));
            offset += chunk.len();
            continue;
        };
        let value = &content[eq + 1..];
        let (text, raw_hex) = match std::str::from_utf8(value) {
            Ok(v) => (Some(v.to_owned()), None),
            Err(_) => (None, Some(hex(value))),
        };
        out.directives.push(DirectiveEvidence {
            section: section_name,
            key: String::from_utf8_lossy(key).into_owned(),
            value: text,
            value_hex: raw_hex,
            line: index + 1,
            byte_offset: offset,
            byte_length: content.len(),
            line_sha256: sha256_hex(content),
        });
        offset += chunk.len();
    }
    out
}
fn trim_ascii(mut b: &[u8]) -> &[u8] {
    while b.first().is_some_and(u8::is_ascii_whitespace) {
        b = &b[1..];
    }
    while b.last().is_some_and(u8::is_ascii_whitespace) {
        b = &b[..b.len() - 1];
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "systemd-units-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn parser_preserves_sections_duplicate_directives_and_exact_offsets() {
        let b = b"[Unit]\nDescription=hi\n[Service]\nExecStart=/bin/echo %n\nExecStart=again\n";
        let p = parse_unit(b, 100);
        assert!(p.diagnostics.is_empty());
        assert_eq!(
            p.directives.iter().filter(|d| d.key == "ExecStart").count(),
            2
        );
        let e = &p.directives[1];
        assert_eq!(
            (&e.section[..], &e.key[..], e.value.as_deref()),
            ("Service", "ExecStart", Some("/bin/echo %n"))
        );
        assert_eq!(
            e.byte_offset,
            b.windows(b"ExecStart=/bin".len())
                .position(|w| w == b"ExecStart=/bin")
                .unwrap()
        );
    }
    #[test]
    fn malformed_oversized_and_non_utf8_evidence_is_bounded_and_diagnostic() {
        let mut b = b"bad\n[Service]\nEnvironment=\xff\n".to_vec();
        b.extend(vec![b'x'; MAX_UNIT_LINE_BYTES + 1]);
        let p = parse_unit(&b, 10);
        assert!(p.diagnostics.iter().any(|x| x.0 == "malformed_directive"));
        assert!(p.diagnostics.iter().any(|x| x.0 == "line_limit_exceeded"));
        assert_eq!(p.directives[0].value_hex.as_deref(), Some("ff"));
    }
    #[test]
    fn collector_parses_regular_units_and_records_enablement_links_without_following() {
        let t = Temp::new();
        let root = t.0.join("units");
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("demo.service"),
            b"[Service]\nExecStart=/path/that/must/not/run\n",
        )
        .unwrap();
        let wants = root.join("multi-user.target.wants");
        fs::create_dir(&wants).unwrap();
        symlink("../demo.service", wants.join("demo.service")).unwrap();
        let d = collect_with_limits(
            &[UnitDirectory {
                scope: "system",
                path: root,
            }],
            10,
            4096,
            4096,
            Duration::from_secs(1),
            100,
        );
        assert_eq!(d.status, Status::Complete);
        assert_eq!(d.records.len(), 2);
        assert!(
            d.records
                .iter()
                .any(|r| r.record_type == "enabled_reference_symlink"
                    && r.symlink_target.as_ref().and_then(|v| v.value.as_deref())
                        == Some("../demo.service"))
        );
        assert!(
            d.records
                .iter()
                .flat_map(|r| &r.directives)
                .any(|x| x.key == "ExecStart")
        );
    }

    #[test]
    fn reads_drop_in_with_exact_source_reference_and_skips_symlinked_drop_in_paths() {
        let t = Temp::new();
        let root = t.0.join("units");
        fs::create_dir(&root).unwrap();
        let real_dropins = root.join("demo.service.d");
        fs::create_dir(&real_dropins).unwrap();
        let drop_in = real_dropins.join("20-local.conf");
        let contents = b"[Service]\nEnvironment=MODE=local\n";
        fs::write(&drop_in, contents).unwrap();

        let outside = t.0.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(
            outside.join("10-external.conf"),
            b"[Service]\nExecStart=/unsafe\n",
        )
        .unwrap();
        symlink(&outside, root.join("hidden.service.d")).unwrap();
        symlink(
            outside.join("10-external.conf"),
            real_dropins.join("10-linked.conf"),
        )
        .unwrap();

        let d = collect_with_limits(
            &[UnitDirectory {
                scope: "system",
                path: root.clone(),
            }],
            20,
            4096,
            8192,
            Duration::from_secs(1),
            100,
        );
        assert_eq!(d.status, Status::Partial);
        let records: Vec<_> = d
            .records
            .iter()
            .filter(|r| r.record_type == "drop_in_file")
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source_path, display_path(&drop_in));
        let evidence = records[0]
            .directives
            .iter()
            .find(|item| item.key == "Environment")
            .unwrap();
        assert_eq!(
            evidence.byte_offset,
            contents
                .windows(b"Environment=".len())
                .position(|w| w == b"Environment=")
                .unwrap()
        );
        assert_eq!(
            evidence.byte_offset + evidence.byte_length,
            contents.strip_suffix(b"\n").unwrap().len()
        );
        assert_eq!(evidence.line_sha256, sha256_hex(b"Environment=MODE=local"));
        assert!(
            !d.records
                .iter()
                .any(|r| r.source_path.contains("hidden.service.d"))
        );
        assert!(
            d.directories[0]
                .diagnostics
                .iter()
                .any(|diag| diag.code == "drop_in_directory_symlink")
        );
        assert!(
            d.directories[0]
                .diagnostics
                .iter()
                .any(|diag| diag.code == "drop_in_file_symlink")
        );
        assert!(
            records[0]
                .directives
                .iter()
                .all(|item| item.value.as_deref() != Some("/unsafe"))
        );
    }
    #[test]
    fn symlink_directory_and_size_limit_are_reported_partial() {
        let t = Temp::new();
        let actual = t.0.join("actual");
        fs::create_dir(&actual).unwrap();
        fs::write(actual.join("x.service"), b"[Unit]\nDescription=long\n").unwrap();
        let root = t.0.join("root");
        symlink(&actual, &root).unwrap();
        let invalid = collect_with_limits(
            &[UnitDirectory {
                scope: "system",
                path: root,
            }],
            10,
            100,
            100,
            Duration::from_secs(1),
            10,
        );
        assert_eq!(invalid.status, Status::Partial);
        let limited = collect_with_limits(
            &[UnitDirectory {
                scope: "system",
                path: actual,
            }],
            10,
            4,
            100,
            Duration::from_secs(1),
            10,
        );
        assert_eq!(limited.status, Status::Partial);
        assert!(
            limited.directories[0]
                .diagnostics
                .iter()
                .any(|x| x.code == "file_limit_exceeded")
        );
    }

    #[test]
    fn symlink_target_aggregate_budget_accepts_boundary_then_rejects_overflow() {
        let t = Temp::new();
        let root = t.0.join("units");
        fs::create_dir(&root).unwrap();
        symlink("1234", root.join("a.service")).unwrap();
        symlink("5678", root.join("b.service")).unwrap();
        symlink("x", root.join("c.service")).unwrap();

        let d = collect_with_symlink_budget(
            &[UnitDirectory {
                scope: "system",
                path: root,
            }],
            10,
            4096,
            4096,
            Duration::from_secs(1),
            100,
            8,
        );

        assert_eq!(d.status, Status::Partial);
        assert_eq!(d.records.len(), 3);
        let retained_bytes: usize = d
            .records
            .iter()
            .filter_map(|r| r.symlink_target.as_ref())
            .map(|target| target.byte_length)
            .sum();
        assert_eq!(retained_bytes, 8);
        assert!(d.records[0].symlink_target.is_some());
        assert!(d.records[1].symlink_target.is_some());
        assert!(d.records[2].symlink_target.is_none());
        assert!(d.directories[0].diagnostics.iter().any(|diag| diag.code
            == "symlink_target_aggregate_limit_exceeded"
            && diag.path.as_deref() == Some(d.records[2].source_path.as_str())));
    }

    #[test]
    fn missing_optional_directory_is_empty_complete() {
        let t = Temp::new();
        let d = collect_with_limits(
            &[UnitDirectory {
                scope: "user",
                path: t.0.join("missing"),
            }],
            10,
            100,
            100,
            Duration::from_secs(1),
            10,
        );
        assert_eq!(d.status, Status::Complete);
        assert!(d.records.is_empty());
    }

    #[test]
    fn opened_file_identity_matches_initial_no_follow_metadata() {
        let t = Temp::new();
        let first = t.0.join("first.service");
        let second = t.0.join("second.service");
        fs::write(&first, b"[Unit]\n").unwrap();
        fs::write(&second, b"[Unit]\n").unwrap();
        let first_before = fs::symlink_metadata(&first).unwrap();
        let first_opened = OpenOptions::new().read(true).open(&first).unwrap();
        let second_opened = OpenOptions::new().read(true).open(&second).unwrap();
        assert!(same_file_identity(
            &first_before,
            &first_opened.metadata().unwrap()
        ));
        assert!(!same_file_identity(
            &first_before,
            &second_opened.metadata().unwrap()
        ));
    }

    #[test]
    fn non_utf8_directory_and_unit_path_bytes_are_preserved_exactly() {
        let t = Temp::new();
        let root = t.0.join(OsString::from_vec(b"units-\xff".to_vec()));
        fs::create_dir(&root).unwrap();
        let file = root.join(OsString::from_vec(b"local-\xfe.service".to_vec()));
        fs::write(&file, b"[Unit]\nDescription=fixture\n").unwrap();
        let d = collect_with_limits(
            &[UnitDirectory {
                scope: "system",
                path: root.clone(),
            }],
            10,
            4096,
            4096,
            Duration::from_secs(1),
            100,
        );
        assert_eq!(d.status, Status::Complete);
        assert_eq!(
            d.directories[0].path_bytes_hex,
            hex(root.as_os_str().as_bytes())
        );
        let record = d
            .records
            .iter()
            .find(|r| r.record_type == "unit_file")
            .unwrap();
        assert_eq!(
            record.source_path_bytes_hex,
            hex(file.as_os_str().as_bytes())
        );
        assert!(record.source_path.contains('\u{fffd}'));
    }

    #[test]
    fn wants_directory_keeps_only_children_with_known_unit_suffixes() {
        let t = Temp::new();
        let root = t.0.join("units");
        fs::create_dir(&root).unwrap();
        let wants = root.join("multi-user.target.wants");
        fs::create_dir(&wants).unwrap();
        symlink("../demo.service", wants.join("demo.service")).unwrap();
        symlink("../ignored-file", wants.join("notes.txt")).unwrap();
        symlink("../ignored-extension", wants.join("custom.unknown")).unwrap();

        let d = collect_with_limits(
            &[UnitDirectory {
                scope: "system",
                path: root,
            }],
            10,
            4096,
            4096,
            Duration::from_secs(1),
            100,
        );
        let enabled: Vec<_> = d
            .records
            .iter()
            .filter(|r| r.record_type == "enabled_reference_symlink")
            .collect();
        assert_eq!(enabled.len(), 1);
        assert!(enabled[0].source_path.ends_with("demo.service"));
        assert!(
            !d.records
                .iter()
                .any(|r| r.source_path.ends_with("notes.txt"))
        );
        assert!(
            !d.records
                .iter()
                .any(|r| r.source_path.ends_with("custom.unknown"))
        );
        assert_eq!(d.status, Status::Complete);
    }
}
