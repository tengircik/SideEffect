//! Bounded discovery of legacy Linux startup configuration.
//!
//! This module records inert bytes from common SysV init/runlevel and cron
//! locations. It does not parse shell commands, cron schedules, or execution
//! applicability, and it never executes discovered content.

use crate::fingerprint::sha256_hex;
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_LEGACY_STARTUP_FILES: usize = 4096;
pub const MAX_LEGACY_STARTUP_FILE_BYTES: usize = 256 * 1024;
pub const MAX_LEGACY_STARTUP_TOTAL_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_LEGACY_STARTUP_LINES: usize = 10_000;
pub const MAX_LEGACY_STARTUP_ENTRIES: usize = 8_192;
pub const MAX_LEGACY_STARTUP_LINE_BYTES: usize = 64 * 1024;
pub const MAX_LEGACY_STARTUP_DIRECTORIES: usize = 64;
pub const MAX_LEGACY_STARTUP_SCAN_TIME: Duration = Duration::from_secs(5);
pub const MAX_LEGACY_SYMLINK_TARGET_BYTES: usize = 4096;
pub const MAX_LEGACY_SYMLINK_TARGET_TOTAL_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct LegacyStartupPaths {
    pub sysv_init_dir: PathBuf,
    pub sysv_runlevel_dirs: Vec<PathBuf>,
    pub cron_system_file: PathBuf,
    pub cron_config_dir: PathBuf,
    pub cron_periodic_dirs: Vec<PathBuf>,
    pub cron_user_spool_dirs: Vec<PathBuf>,
}

impl Default for LegacyStartupPaths {
    fn default() -> Self {
        Self {
            sysv_init_dir: PathBuf::from("/etc/init.d"),
            sysv_runlevel_dirs: (0..=6)
                .map(|n| PathBuf::from(format!("/etc/rc{n}.d")))
                .chain(std::iter::once(PathBuf::from("/etc/rcS.d")))
                .collect(),
            cron_system_file: PathBuf::from("/etc/crontab"),
            cron_config_dir: PathBuf::from("/etc/cron.d"),
            cron_periodic_dirs: ["hourly", "daily", "weekly", "monthly"]
                .into_iter()
                .map(|name| PathBuf::from(format!("/etc/cron.{name}")))
                .collect(),
            cron_user_spool_dirs: vec![PathBuf::from("/var/spool/cron/crontabs")],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LegacyStartupLimits {
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
    pub max_lines: usize,
    pub max_entries: usize,
    pub max_line_bytes: usize,
    pub max_directories: usize,
    pub scan_time: Duration,
    pub max_symlink_target_total_bytes: usize,
}

impl Default for LegacyStartupLimits {
    fn default() -> Self {
        Self {
            max_files: MAX_LEGACY_STARTUP_FILES,
            max_file_bytes: MAX_LEGACY_STARTUP_FILE_BYTES,
            max_total_bytes: MAX_LEGACY_STARTUP_TOTAL_BYTES,
            max_lines: MAX_LEGACY_STARTUP_LINES,
            max_entries: MAX_LEGACY_STARTUP_ENTRIES,
            max_line_bytes: MAX_LEGACY_STARTUP_LINE_BYTES,
            max_directories: MAX_LEGACY_STARTUP_DIRECTORIES,
            scan_time: MAX_LEGACY_STARTUP_SCAN_TIME,
            max_symlink_target_total_bytes: MAX_LEGACY_SYMLINK_TARGET_TOTAL_BYTES,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LegacyStartupDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub capture_started_at_unix_ms: u128,
    pub capture_ended_at_unix_ms: u128,
    pub status: ScanStatus,
    pub sources: Vec<SourceStatus>,
    pub entries: Vec<LegacyStartupEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    Complete,
    Partial,
    NotPresent,
    Unchecked,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceStatus {
    pub kind: SourceKind,
    pub path: String,
    pub path_bytes_hex: String,
    pub state: SourceState,
    pub files_seen: usize,
    pub diagnostics: Vec<LegacyStartupDiagnostic>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    SysvInitScripts,
    SysvRunlevelLinks,
    CronSystemFile,
    CronConfigDirectory,
    CronPeriodicDirectory,
    CronUserSpool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    InertFile,
    RunlevelLink,
    SysvInitScriptLink,
    CronSourceLink,
}

#[derive(Clone, Debug, Serialize)]
pub struct LegacyStartupEntry {
    pub source_kind: SourceKind,
    pub entry_kind: EntryKind,
    pub path: String,
    pub path_bytes_hex: String,
    /// Raw symlink target bytes. This is metadata, not a resolved path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target_sha256: Option<String>,
    pub lines: Vec<LegacyStartupLine>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LegacyStartupLine {
    pub line_number: usize,
    pub byte_offset: usize,
    pub byte_length: usize,
    pub line_sha256: String,
    pub raw_line: Option<String>,
    pub raw_line_hex: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LegacyStartupDiagnostic {
    pub code: &'static str,
    pub path: Option<String>,
    pub line: Option<usize>,
    pub byte_offset: Option<usize>,
}

#[derive(Clone, Debug)]
struct SourceSpec {
    kind: SourceKind,
    path: PathBuf,
    is_directory: bool,
    optional: bool,
}

pub fn collect_legacy_startup() -> LegacyStartupDocument {
    collect_legacy_startup_from(
        &LegacyStartupPaths::default(),
        LegacyStartupLimits::default(),
    )
}

/// Injectable paths and limits for deterministic tests and orchestration.
pub fn collect_legacy_startup_from(
    paths: &LegacyStartupPaths,
    limits: LegacyStartupLimits,
) -> LegacyStartupDocument {
    let started = Instant::now();
    let capture_started = now_ms();
    let mut specs = vec![SourceSpec {
        kind: SourceKind::SysvInitScripts,
        path: paths.sysv_init_dir.clone(),
        is_directory: true,
        optional: true,
    }];
    specs.extend(
        paths
            .sysv_runlevel_dirs
            .iter()
            .cloned()
            .map(|path| SourceSpec {
                kind: SourceKind::SysvRunlevelLinks,
                path,
                is_directory: true,
                optional: true,
            }),
    );
    specs.push(SourceSpec {
        kind: SourceKind::CronSystemFile,
        path: paths.cron_system_file.clone(),
        is_directory: false,
        optional: true,
    });
    specs.push(SourceSpec {
        kind: SourceKind::CronConfigDirectory,
        path: paths.cron_config_dir.clone(),
        is_directory: true,
        optional: true,
    });
    specs.extend(
        paths
            .cron_periodic_dirs
            .iter()
            .cloned()
            .map(|path| SourceSpec {
                kind: SourceKind::CronPeriodicDirectory,
                path,
                is_directory: true,
                optional: true,
            }),
    );
    specs.extend(
        paths
            .cron_user_spool_dirs
            .iter()
            .cloned()
            .map(|path| SourceSpec {
                kind: SourceKind::CronUserSpool,
                path,
                is_directory: true,
                optional: true,
            }),
    );

    let mut sources = Vec::new();
    let mut entries = Vec::new();
    let mut partial = false;
    let mut file_count = 0usize;
    let mut total_bytes = 0usize;
    let mut line_count = 0usize;
    let mut entry_count = 0usize;
    let mut symlink_target_bytes = 0usize;

    for (index, spec) in specs.iter().enumerate() {
        let mut source = SourceStatus {
            kind: spec.kind,
            path: display_path(&spec.path),
            path_bytes_hex: hex(spec.path.as_os_str().as_bytes()),
            state: SourceState::Complete,
            files_seen: 0,
            diagnostics: Vec::new(),
        };
        if index >= limits.max_directories || started.elapsed() >= limits.scan_time {
            source.state = SourceState::Unchecked;
            diag(
                &mut source,
                if index >= limits.max_directories {
                    "directory_limit_exceeded"
                } else {
                    "scan_deadline_exceeded"
                },
                None,
            );
            partial = true;
            sources.push(source);
            continue;
        }
        let meta = match fs::symlink_metadata(&spec.path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound && spec.optional => {
                source.state = SourceState::NotPresent;
                sources.push(source);
                continue;
            }
            Err(_) => {
                source.state = SourceState::Partial;
                diag(&mut source, "source_metadata_unavailable", None);
                partial = true;
                sources.push(source);
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            if spec.kind == SourceKind::CronSystemFile {
                if started.elapsed() >= limits.scan_time || entry_count >= limits.max_entries {
                    source.state = SourceState::Partial;
                    diag(
                        &mut source,
                        if started.elapsed() >= limits.scan_time {
                            "scan_deadline_exceeded"
                        } else {
                            "entry_limit_exceeded"
                        },
                        Some(&spec.path),
                    );
                    partial = true;
                } else {
                    entry_count += 1;
                    source.files_seen += 1;
                    if let Some(entry) = read_link_entry(
                        spec.kind,
                        &spec.path,
                        &mut source,
                        &mut symlink_target_bytes,
                        limits.max_symlink_target_total_bytes,
                    ) {
                        entries.push(entry);
                    } else {
                        source.state = SourceState::Partial;
                        partial = true;
                    }
                }
                sources.push(source);
                continue;
            }
            source.state = SourceState::Partial;
            diag(&mut source, "source_directory_is_symlink", None);
            partial = true;
            sources.push(source);
            continue;
        }
        if spec.is_directory && !meta.is_dir() {
            source.state = SourceState::Partial;
            diag(&mut source, "source_not_directory", None);
            partial = true;
            sources.push(source);
            continue;
        }
        if !spec.is_directory && !meta.is_file() {
            source.state = SourceState::Partial;
            diag(&mut source, "source_not_regular_file", None);
            partial = true;
            sources.push(source);
            continue;
        }

        if spec.is_directory {
            scan_directory(
                spec,
                &mut source,
                &mut entries,
                &mut file_count,
                &mut total_bytes,
                &mut line_count,
                &mut entry_count,
                &mut symlink_target_bytes,
                &mut partial,
                started,
                limits,
            );
        } else {
            scan_file(
                &spec.path,
                spec.kind,
                &mut source,
                &mut entries,
                &mut file_count,
                &mut total_bytes,
                &mut line_count,
                &mut entry_count,
                &mut partial,
                started,
                limits,
                true,
            );
        }
        if source.state == SourceState::Partial || source.state == SourceState::Unchecked {
            partial = true;
        }
        sources.push(source);
    }

    LegacyStartupDocument {
        schema: "sideeffect.legacy_startup_inventory",
        schema_version: 1,
        platform: "linux",
        scope: "common_sysv_cron_paths_only",
        capture_started_at_unix_ms: capture_started,
        capture_ended_at_unix_ms: now_ms(),
        status: if partial {
            ScanStatus::Partial
        } else {
            ScanStatus::Complete
        },
        sources,
        entries,
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_directory(
    spec: &SourceSpec,
    source: &mut SourceStatus,
    entries: &mut Vec<LegacyStartupEntry>,
    file_count: &mut usize,
    total_bytes: &mut usize,
    line_count: &mut usize,
    entry_count: &mut usize,
    symlink_target_bytes: &mut usize,
    partial: &mut bool,
    started: Instant,
    limits: LegacyStartupLimits,
) {
    let mut paths = Vec::new();
    let iterator = match fs::read_dir(&spec.path) {
        Ok(iterator) => iterator,
        Err(error) => {
            source.state = SourceState::Partial;
            diag(
                source,
                if error.kind() == io::ErrorKind::PermissionDenied {
                    "source_inaccessible"
                } else {
                    "directory_read_failed"
                },
                None,
            );
            *partial = true;
            return;
        }
    };
    for item in iterator {
        if started.elapsed() >= limits.scan_time {
            source.state = SourceState::Partial;
            diag(source, "scan_deadline_exceeded", None);
            *partial = true;
            break;
        }
        if paths.len() >= limits.max_entries {
            source.state = SourceState::Partial;
            diag(source, "directory_entry_limit_exceeded", None);
            *partial = true;
            break;
        }
        match item {
            Ok(entry) => paths.push(entry.path()),
            Err(_) => {
                source.state = SourceState::Partial;
                diag(source, "directory_entry_unreadable", None);
                *partial = true;
            }
        }
    }
    paths.sort();
    for path in paths {
        if started.elapsed() >= limits.scan_time {
            source.state = SourceState::Partial;
            diag_path(source, "scan_deadline_exceeded", &path);
            *partial = true;
            break;
        }
        if *entry_count >= limits.max_entries {
            source.state = SourceState::Partial;
            diag_path(source, "entry_limit_exceeded", &path);
            *partial = true;
            break;
        }
        *entry_count += 1;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                source.state = SourceState::Partial;
                diag_path(source, "entry_metadata_unavailable", &path);
                *partial = true;
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            if matches!(
                spec.kind,
                SourceKind::SysvRunlevelLinks
                    | SourceKind::SysvInitScripts
                    | SourceKind::CronConfigDirectory
                    | SourceKind::CronPeriodicDirectory
                    | SourceKind::CronUserSpool
            ) {
                if let Some(entry) = read_link_entry(
                    spec.kind,
                    &path,
                    source,
                    symlink_target_bytes,
                    limits.max_symlink_target_total_bytes,
                ) {
                    entries.push(entry);
                } else {
                    source.state = SourceState::Partial;
                    *partial = true;
                }
            } else {
                source.state = SourceState::Partial;
                diag_path(source, "symlink_entry_not_followed", &path);
                *partial = true;
            }
            continue;
        }
        if !metadata.is_file() {
            source.state = SourceState::Partial;
            diag_path(source, "unsupported_entry_type", &path);
            *partial = true;
            continue;
        }
        if spec.kind == SourceKind::SysvRunlevelLinks {
            source.state = SourceState::Partial;
            diag_path(source, "runlevel_entry_not_symlink", &path);
            *partial = true;
            continue;
        }
        scan_file(
            &path,
            spec.kind,
            source,
            entries,
            file_count,
            total_bytes,
            line_count,
            entry_count,
            partial,
            started,
            limits,
            false,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_file(
    path: &Path,
    kind: SourceKind,
    source: &mut SourceStatus,
    entries: &mut Vec<LegacyStartupEntry>,
    file_count: &mut usize,
    total_bytes: &mut usize,
    line_count: &mut usize,
    entry_count: &mut usize,
    partial: &mut bool,
    started: Instant,
    limits: LegacyStartupLimits,
    count_entry: bool,
) {
    if *file_count >= limits.max_files {
        source.state = SourceState::Partial;
        diag_path(source, "file_limit_exceeded", path);
        *partial = true;
        return;
    }
    if count_entry && *entry_count >= limits.max_entries {
        source.state = SourceState::Partial;
        diag_path(source, "entry_limit_exceeded", path);
        *partial = true;
        return;
    }
    if started.elapsed() >= limits.scan_time {
        source.state = SourceState::Partial;
        diag_path(source, "scan_deadline_exceeded", path);
        *partial = true;
        return;
    }
    *file_count += 1;
    if count_entry {
        *entry_count += 1;
    }
    source.files_seen += 1;
    let before = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => meta,
        _ => {
            source.state = SourceState::Partial;
            diag_path(source, "file_metadata_unavailable", path);
            *partial = true;
            return;
        }
    };
    let remaining = limits.max_total_bytes.saturating_sub(*total_bytes);
    let read_limit = limits.max_file_bytes.min(remaining);
    let file = match open_regular_nofollow(path) {
        Ok(file) => file,
        Err(error) => {
            source.state = SourceState::Partial;
            diag_path(
                source,
                if error.kind() == io::ErrorKind::PermissionDenied {
                    "file_inaccessible"
                } else {
                    "file_open_failed"
                },
                path,
            );
            *partial = true;
            return;
        }
    };
    let opened = match file.metadata() {
        Ok(meta) if meta.is_file() && meta.dev() == before.dev() && meta.ino() == before.ino() => {
            meta
        }
        _ => {
            source.state = SourceState::Partial;
            diag_path(source, "file_identity_changed", path);
            *partial = true;
            return;
        }
    };
    if opened.len() > read_limit as u64 {
        source.state = SourceState::Partial;
        diag_path(
            source,
            if remaining < limits.max_file_bytes {
                "aggregate_byte_limit_exceeded"
            } else {
                "file_byte_limit_exceeded"
            },
            path,
        );
        *partial = true;
        return;
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    if file
        .take(read_limit as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        source.state = SourceState::Partial;
        diag_path(source, "file_read_failed", path);
        *partial = true;
        return;
    }
    *total_bytes = total_bytes.saturating_add(bytes.len());
    if bytes.len() > read_limit {
        source.state = SourceState::Partial;
        diag_path(
            source,
            if remaining < limits.max_file_bytes {
                "aggregate_byte_limit_exceeded"
            } else {
                "file_byte_limit_exceeded"
            },
            path,
        );
        *partial = true;
        return;
    }
    let after = match fs::symlink_metadata(path) {
        Ok(meta) if meta.dev() == before.dev() && meta.ino() == before.ino() => meta,
        _ => {
            source.state = SourceState::Partial;
            diag_path(source, "file_identity_changed", path);
            *partial = true;
            return;
        }
    };
    if after.len() != opened.len() {
        source.state = SourceState::Partial;
        diag_path(source, "file_changed_during_read", path);
        *partial = true;
        return;
    }
    let (lines, issues, exhausted) = split_lines(&bytes, *line_count, limits);
    *line_count = line_count
        .saturating_add(lines.len())
        .saturating_add(issues.len());
    if exhausted {
        source.state = SourceState::Partial;
        diag_path(source, "line_limit_exceeded", path);
        *partial = true;
    }
    for (line, offset) in issues {
        source.state = SourceState::Partial;
        source.diagnostics.push(LegacyStartupDiagnostic {
            code: "line_byte_limit_exceeded",
            path: Some(display_path(path)),
            line: Some(line),
            byte_offset: Some(offset),
        });
        *partial = true;
    }
    for line in lines.iter().filter(|line| line.raw_line_hex.is_some()) {
        source.state = SourceState::Partial;
        source.diagnostics.push(LegacyStartupDiagnostic {
            code: "line_invalid_utf8",
            path: Some(display_path(path)),
            line: Some(line.line_number),
            byte_offset: Some(line.byte_offset),
        });
        *partial = true;
    }
    if kind != SourceKind::SysvInitScripts
        && kind != SourceKind::SysvRunlevelLinks
        && !bytes.is_empty()
        && !bytes.ends_with(b"\n")
    {
        source.state = SourceState::Partial;
        diag_path(source, "final_line_missing_newline", path);
        *partial = true;
    }
    entries.push(LegacyStartupEntry {
        source_kind: kind,
        entry_kind: EntryKind::InertFile,
        path: display_path(path),
        path_bytes_hex: hex(path.as_os_str().as_bytes()),
        symlink_target: None,
        symlink_target_hex: None,
        symlink_target_sha256: None,
        lines,
    });
}

fn read_link_entry(
    kind: SourceKind,
    path: &Path,
    source: &mut SourceStatus,
    symlink_target_bytes: &mut usize,
    max_total_bytes: usize,
) -> Option<LegacyStartupEntry> {
    let target = match fs::read_link(path) {
        Ok(target) => target,
        Err(_) => {
            diag_path(source, "symlink_target_unavailable", path);
            return None;
        }
    };
    let target_bytes = target.as_os_str().as_bytes();
    if target_bytes.len() > MAX_LEGACY_SYMLINK_TARGET_BYTES {
        diag_path(source, "symlink_target_limit_exceeded", path);
        return None;
    }
    let next_total = symlink_target_bytes.checked_add(target_bytes.len())?;
    if next_total > max_total_bytes {
        diag_path(source, "symlink_target_aggregate_limit_exceeded", path);
        return None;
    }
    *symlink_target_bytes = next_total;
    Some(LegacyStartupEntry {
        source_kind: kind,
        entry_kind: match kind {
            SourceKind::SysvRunlevelLinks => EntryKind::RunlevelLink,
            SourceKind::SysvInitScripts => EntryKind::SysvInitScriptLink,
            SourceKind::CronSystemFile
            | SourceKind::CronConfigDirectory
            | SourceKind::CronPeriodicDirectory
            | SourceKind::CronUserSpool => EntryKind::CronSourceLink,
        },
        path: display_path(path),
        path_bytes_hex: hex(path.as_os_str().as_bytes()),
        symlink_target: target.to_str().map(str::to_owned),
        symlink_target_hex: Some(hex(target_bytes)),
        symlink_target_sha256: Some(sha256_hex(target_bytes)),
        lines: Vec::new(),
    })
}

fn split_lines(
    bytes: &[u8],
    already_seen: usize,
    limits: LegacyStartupLimits,
) -> (Vec<LegacyStartupLine>, Vec<(usize, usize)>, bool) {
    let mut lines = Vec::new();
    let mut issues = Vec::new();
    let mut offset = 0usize;
    let mut exhausted = false;
    for (index, raw) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        if already_seen.saturating_add(index) >= limits.max_lines {
            exhausted = true;
            break;
        }
        let number = index + 1;
        if raw.len() > limits.max_line_bytes {
            issues.push((number, offset));
            offset += raw.len();
            continue;
        }
        let (raw_line, raw_line_hex) = match std::str::from_utf8(raw) {
            Ok(text) => (Some(text.to_owned()), None),
            Err(_) => (None, Some(hex(raw))),
        };
        lines.push(LegacyStartupLine {
            line_number: number,
            byte_offset: offset,
            byte_length: raw.len(),
            line_sha256: sha256_hex(raw),
            raw_line,
            raw_line_hex,
        });
        offset += raw.len();
    }
    (lines, issues, exhausted)
}

fn open_regular_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn diag(source: &mut SourceStatus, code: &'static str, path: Option<&Path>) {
    source.diagnostics.push(LegacyStartupDiagnostic {
        code,
        path: path.map(display_path),
        line: None,
        byte_offset: None,
    });
}

fn diag_path(source: &mut SourceStatus, code: &'static str, path: &Path) {
    diag(source, code, Some(path));
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sideeffect-legacy-startup-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_paths(root: &TempDir) -> LegacyStartupPaths {
        LegacyStartupPaths {
            sysv_init_dir: root.path("init.d"),
            sysv_runlevel_dirs: vec![root.path("rc2.d")],
            cron_system_file: root.path("crontab"),
            cron_config_dir: root.path("cron.d"),
            cron_periodic_dirs: vec![root.path("cron.daily")],
            cron_user_spool_dirs: vec![root.path("spool")],
        }
    }

    fn create_dirs(paths: &LegacyStartupPaths) {
        for path in [
            &paths.sysv_init_dir,
            &paths.sysv_runlevel_dirs[0],
            &paths.cron_config_dir,
            &paths.cron_periodic_dirs[0],
            &paths.cron_user_spool_dirs[0],
        ] {
            fs::create_dir_all(path).unwrap();
        }
    }

    #[test]
    fn discovers_init_cron_and_runlevel_entries_as_inert_evidence() {
        let root = TempDir::new();
        let paths = fixture_paths(&root);
        create_dirs(&paths);
        fs::write(
            paths.sysv_init_dir.join("demo"),
            b"#!/bin/sh\n# Provides: demo\nexit 0\n",
        )
        .unwrap();
        symlink(
            "../init.d/demo",
            paths.sysv_runlevel_dirs[0].join("S20demo"),
        )
        .unwrap();
        fs::write(
            &paths.cron_system_file,
            b"SHELL=/bin/sh\n* * * * * root echo inert\n",
        )
        .unwrap();
        fs::write(
            paths.cron_config_dir.join("demo"),
            b"17 * * * * root /bin/true\n",
        )
        .unwrap();
        fs::write(
            paths.cron_periodic_dirs[0].join("rotate"),
            b"#!/bin/sh\n# inert\n",
        )
        .unwrap();
        fs::write(
            paths.cron_user_spool_dirs[0].join("alice"),
            b"@reboot echo inert\n",
        )
        .unwrap();

        let document = collect_legacy_startup_from(&paths, LegacyStartupLimits::default());
        assert_eq!(document.status, ScanStatus::Complete);
        assert_eq!(document.entries.len(), 6);
        let script = document
            .entries
            .iter()
            .find(|entry| entry.path.ends_with("/init.d/demo"))
            .unwrap();
        assert_eq!(
            script.lines[1].raw_line.as_deref(),
            Some("# Provides: demo\n")
        );
        assert_eq!(script.lines[1].byte_offset, 10);
        assert_eq!(
            script.lines[1].line_sha256,
            sha256_hex(b"# Provides: demo\n")
        );
        let link = document
            .entries
            .iter()
            .find(|entry| entry.entry_kind == EntryKind::RunlevelLink)
            .unwrap();
        assert_eq!(link.symlink_target.as_deref(), Some("../init.d/demo"));
        assert!(
            document
                .entries
                .iter()
                .flat_map(|entry| &entry.lines)
                .any(|line| line.raw_line.as_deref() == Some("* * * * * root echo inert\n"))
        );
    }

    #[test]
    fn reports_limits_and_non_utf8_lines_without_silently_dropping_source() {
        let root = TempDir::new();
        let paths = fixture_paths(&root);
        create_dirs(&paths);
        fs::write(
            paths.cron_config_dir.join("bad"),
            [b"ok\n".as_slice(), b"\xff\n", b"long\n"].concat(),
        )
        .unwrap();
        let limits = LegacyStartupLimits {
            max_line_bytes: 3,
            ..LegacyStartupLimits::default()
        };
        let document = collect_legacy_startup_from(&paths, limits);
        assert_eq!(document.status, ScanStatus::Partial);
        let entry = document
            .entries
            .iter()
            .find(|entry| entry.path.ends_with("/cron.d/bad"))
            .unwrap();
        assert_eq!(entry.lines[0].raw_line.as_deref(), Some("ok\n"));
        assert_eq!(entry.lines[1].raw_line_hex.as_deref(), Some("ff0a"));
        assert!(
            document
                .sources
                .iter()
                .flat_map(|source| &source.diagnostics)
                .any(|diagnostic| diagnostic.code == "line_byte_limit_exceeded")
        );
    }

    #[test]
    fn refuses_symlink_directories_and_retains_cron_entry_symlink_evidence() {
        let root = TempDir::new();
        let paths = fixture_paths(&root);
        create_dirs(&paths);
        let target = root.path("target");
        fs::write(&target, b"secret schedule\n").unwrap();
        symlink(&target, paths.cron_config_dir.join("linked")).unwrap();
        let redirect = root.path("redirect");
        symlink(&paths.cron_config_dir, &redirect).unwrap();
        let mut custom = paths.clone();
        custom.cron_periodic_dirs = vec![redirect];

        let document = collect_legacy_startup_from(&custom, LegacyStartupLimits::default());
        let cron_link = document
            .entries
            .iter()
            .find(|entry| entry.path.ends_with("/cron.d/linked"))
            .unwrap();
        assert_eq!(cron_link.entry_kind, EntryKind::CronSourceLink);
        assert_eq!(cron_link.symlink_target.as_deref(), target.to_str());
        assert!(cron_link.lines.is_empty());
        assert!(
            !document
                .entries
                .iter()
                .any(|entry| entry.path.ends_with("/redirect/linked"))
        );
        assert!(
            !document
                .sources
                .iter()
                .flat_map(|source| &source.diagnostics)
                .any(|diagnostic| diagnostic.code == "symlink_entry_not_followed")
        );
        assert!(
            document
                .sources
                .iter()
                .flat_map(|source| &source.diagnostics)
                .any(|diagnostic| diagnostic.code == "source_directory_is_symlink")
        );
    }

    #[test]
    fn cron_periodic_symlink_is_retained_as_bounded_inert_target_evidence() {
        let root = TempDir::new();
        let paths = fixture_paths(&root);
        create_dirs(&paths);
        let target = root.path("outside-periodic-directory");
        fs::write(&target, b"# target contents must not be followed\n").unwrap();
        let link = paths.cron_periodic_dirs[0].join("linked-job");
        symlink(&target, &link).unwrap();

        let document = collect_legacy_startup_from(&paths, LegacyStartupLimits::default());
        assert_eq!(document.status, ScanStatus::Complete);
        let entry = document
            .entries
            .iter()
            .find(|entry| entry.path.ends_with("/cron.daily/linked-job"))
            .unwrap();
        assert_eq!(entry.source_kind, SourceKind::CronPeriodicDirectory);
        assert_eq!(entry.entry_kind, EntryKind::CronSourceLink);
        assert_eq!(entry.symlink_target.as_deref(), target.to_str());
        let expected_hex = hex(target.as_os_str().as_bytes());
        let expected_hash = sha256_hex(target.as_os_str().as_bytes());
        assert_eq!(
            entry.symlink_target_hex.as_deref(),
            Some(expected_hex.as_str())
        );
        assert_eq!(
            entry.symlink_target_sha256.as_deref(),
            Some(expected_hash.as_str())
        );
        assert!(entry.lines.is_empty());
        assert!(
            !document
                .entries
                .iter()
                .any(|candidate| candidate.path == display_path(&target))
        );
    }

    #[test]
    fn sysv_symlink_targets_share_an_explicit_aggregate_byte_budget() {
        let root = TempDir::new();
        let paths = fixture_paths(&root);
        create_dirs(&paths);
        symlink(
            Path::new("../init.d/one"),
            paths.sysv_runlevel_dirs[0].join("S01one"),
        )
        .unwrap();
        symlink(
            Path::new("../init.d/two"),
            paths.sysv_runlevel_dirs[0].join("S02two"),
        )
        .unwrap();
        let limits = LegacyStartupLimits {
            max_symlink_target_total_bytes: 13,
            ..LegacyStartupLimits::default()
        };
        let document = collect_legacy_startup_from(&paths, limits);
        assert_eq!(document.status, ScanStatus::Partial);
        assert_eq!(
            document
                .entries
                .iter()
                .filter(|entry| entry.symlink_target.is_some())
                .count(),
            1
        );
        assert!(document.sources.iter().any(|source| {
            source.kind == SourceKind::SysvRunlevelLinks
                && source
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == "symlink_target_aggregate_limit_exceeded")
        }));
    }

    #[test]
    fn missing_paths_are_reported_as_not_present_and_unreadable_source_is_partial() {
        let root = TempDir::new();
        let mut paths = fixture_paths(&root);
        create_dirs(&paths);
        paths.cron_config_dir = root.path("missing-cron.d");
        let document = collect_legacy_startup_from(&paths, LegacyStartupLimits::default());
        assert_eq!(
            document
                .sources
                .iter()
                .find(|source| source.kind == SourceKind::CronConfigDirectory)
                .unwrap()
                .state,
            SourceState::NotPresent
        );
        assert_eq!(
            document
                .sources
                .iter()
                .find(|source| source.kind == SourceKind::CronSystemFile)
                .unwrap()
                .state,
            SourceState::NotPresent
        );
    }
}
