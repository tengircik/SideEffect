//! Bounded discovery of XDG autostart desktop-entry files. Values are inert evidence.
use crate::fingerprint::sha256_hex;
use serde::Serialize;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_STARTUP_FILES: usize = 4096;
pub const MAX_STARTUP_FILE_BYTES: usize = 256 * 1024;
pub const MAX_STARTUP_TOTAL_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_STARTUP_SCAN_TIME: Duration = Duration::from_secs(5);
pub const MAX_STARTUP_DIRECTORIES: usize = 64;
pub const MAX_STARTUP_DIRECTORY_ENTRIES: usize = 16_384;
/// Maximum number of physical lines examined across the whole startup scan.
const MAX_STARTUP_RECORDS: usize = 10_000;
const KEYS: &[&str] = &[
    "Type",
    "Name",
    "Exec",
    "TryExec",
    "Hidden",
    "OnlyShowIn",
    "NotShowIn",
    "DBusActivatable",
];
const MAX_LINE_BYTES: usize = 64 * 1024;

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[derive(Clone, Debug, Serialize)]
pub struct StartupInventoryDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub capture_started_at_unix_ms: u128,
    pub capture_ended_at_unix_ms: u128,
    pub status: Status,
    pub xdg_autostart: XdgAutostartInventory,
    pub systemd_units: super::systemd_units::UnitInventory,
    pub legacy_sources: super::startup_legacy::LegacyStartupDocument,
}

#[derive(Clone, Debug, Serialize)]
pub struct XdgAutostartInventory {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub capture_started_at_unix_ms: u128,
    pub capture_ended_at_unix_ms: u128,
    pub status: Status,
    pub directories: Vec<Directory>,
    pub entries: Vec<Entry>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    Partial,
}
#[derive(Clone, Debug, Serialize)]
pub struct Directory {
    pub scope: &'static str,
    pub path: String,
    pub status: Status,
    pub files_seen: usize,
    pub diagnostics: Vec<Diagnostic>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub scope: &'static str,
    pub source_path: String,
    pub applicability: &'static str,
    pub keys: Vec<KeyEvidence>,
}
#[derive(Clone, Debug, Serialize)]
pub struct KeyEvidence {
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
    pub line: Option<usize>,
    pub byte_offset: Option<usize>,
}

pub fn collect_startup() -> StartupInventoryDocument {
    let started = now_ms();
    let dirs = resolve_xdg_paths(
        std::env::var_os("HOME").as_deref(),
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
        std::env::var_os("XDG_CONFIG_DIRS").as_deref(),
    );
    let xdg_autostart = collect_startup_from(&dirs);
    let systemd_units = super::systemd_units::collect_systemd_units();
    let legacy_sources = super::startup_legacy::collect_legacy_startup();
    let status = if xdg_autostart.status == Status::Complete
        && systemd_units.status == super::systemd_units::Status::Complete
        && legacy_sources.status == super::startup_legacy::ScanStatus::Complete
    {
        Status::Complete
    } else {
        Status::Partial
    };
    StartupInventoryDocument {
        schema: "sideeffect.startup_inventory",
        schema_version: 2,
        platform: "linux",
        scope: "curated_xdg_systemd_sysv_cron_sources",
        capture_started_at_unix_ms: started,
        capture_ended_at_unix_ms: now_ms(),
        status,
        xdg_autostart,
        systemd_units,
        legacy_sources,
    }
}

fn resolve_xdg_paths(
    home: Option<&OsStr>,
    config_home: Option<&OsStr>,
    config_dirs: Option<&OsStr>,
) -> Vec<(&'static str, PathBuf)> {
    let home = home.map(PathBuf::from).unwrap_or_default();
    let config = config_home
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let mut dirs = vec![("user", config.join("autostart"))];
    let system = config_dirs
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| OsStr::new("/etc/xdg"));
    let mut paths = std::env::split_paths(system);
    for _ in 1..MAX_STARTUP_DIRECTORIES {
        let Some(path) = paths.next() else { break };
        dirs.push(("system", path.join("autostart")));
    }
    if paths.next().is_some() {
        dirs.push((
            "system",
            PathBuf::from("additional configured directories not checked"),
        ));
    }
    dirs
}

/// Injectable directory roots and limits for deterministic tests.
pub fn collect_startup_from(dirs: &[(&'static str, PathBuf)]) -> XdgAutostartInventory {
    collect(
        dirs,
        MAX_STARTUP_FILES,
        MAX_STARTUP_FILE_BYTES,
        MAX_STARTUP_TOTAL_BYTES,
        MAX_STARTUP_SCAN_TIME,
    )
}
fn collect(
    dirs: &[(&'static str, PathBuf)],
    max_files: usize,
    max_file: usize,
    max_total: usize,
    duration: Duration,
) -> XdgAutostartInventory {
    collect_with_record_limit(
        dirs,
        max_files,
        max_file,
        max_total,
        duration,
        MAX_STARTUP_RECORDS,
    )
}

fn collect_with_record_limit(
    dirs: &[(&'static str, PathBuf)],
    max_files: usize,
    max_file: usize,
    max_total: usize,
    duration: Duration,
    max_records: usize,
) -> XdgAutostartInventory {
    let started = Instant::now();
    let capture_started = now_ms();
    let mut directory_rows = Vec::new();
    let mut entries = Vec::new();
    let mut total = 0usize;
    let mut count = 0usize;
    let mut examined = 0usize;
    let mut records_parsed = 0usize;
    let mut record_limit_reached = false;
    let mut partial = false;
    for (scope, root) in dirs.iter().take(MAX_STARTUP_DIRECTORIES) {
        let mut d = Directory {
            scope,
            path: display_path(root),
            status: Status::Complete,
            files_seen: 0,
            diagnostics: Vec::new(),
        };
        if record_limit_reached {
            diag(&mut d, "record_limit_exceeded", None);
            partial = true;
            d.status = Status::Partial;
            directory_rows.push(d);
            continue;
        }
        if started.elapsed() >= duration {
            diag(&mut d, "scan_deadline_exceeded", None);
            partial = true;
            d.status = Status::Partial;
            directory_rows.push(d);
            continue;
        }
        if !root.is_absolute() {
            diag(&mut d, "directory_invalid", None);
            partial = true;
            d.status = Status::Partial;
            directory_rows.push(d);
            continue;
        }
        let meta = match fs::symlink_metadata(root) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                directory_rows.push(d);
                continue;
            }
            Err(_) => {
                diag(&mut d, "directory_unreadable", None);
                partial = true;
                d.status = Status::Partial;
                directory_rows.push(d);
                continue;
            }
            Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
                diag(&mut d, "directory_invalid", None);
                partial = true;
                d.status = Status::Partial;
                directory_rows.push(d);
                continue;
            }
            Ok(m) => m,
        };
        let _ = meta;
        let list = match fs::read_dir(root) {
            Ok(x) => x,
            Err(_) => {
                diag(&mut d, "directory_unreadable", None);
                partial = true;
                d.status = Status::Partial;
                directory_rows.push(d);
                continue;
            }
        };
        let mut paths = Vec::new();
        let mut hit_code = None;
        for item in list {
            examined += 1;
            if examined > MAX_STARTUP_DIRECTORY_ENTRIES {
                hit_code = Some("directory_entry_limit_exceeded");
                break;
            }
            if started.elapsed() >= duration {
                hit_code = Some("scan_deadline_exceeded");
                break;
            }
            match item {
                Ok(e) => {
                    let p = e.path();
                    if p.extension() == Some(OsStr::new("desktop")) {
                        paths.push(p);
                        if paths.len() > max_files {
                            hit_code = Some("file_count_limit_exceeded");
                            break;
                        }
                    }
                }
                Err(_) => {
                    diag(&mut d, "directory_entry_unreadable", None);
                    partial = true;
                }
            }
        }
        paths.sort();
        if hit_code.is_some() {
            paths.truncate(max_files);
        }
        for path in paths {
            if started.elapsed() >= duration {
                hit_code = Some("scan_deadline_exceeded");
                break;
            }
            if count >= max_files {
                hit_code = Some("file_count_limit_exceeded");
                break;
            }
            if total >= max_total {
                hit_code = Some("aggregate_byte_limit_exceeded");
                partial = true;
                break;
            }
            count += 1;
            d.files_seen += 1;
            let sm = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => {
                    diag(&mut d, "file_metadata_unavailable", Some(&path));
                    partial = true;
                    continue;
                }
            };
            if sm.file_type().is_symlink() || !sm.is_file() {
                diag(&mut d, "file_not_regular", Some(&path));
                partial = true;
                continue;
            }
            let file = match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(&path)
            {
                Ok(f) => f,
                Err(_) => {
                    diag(&mut d, "file_unreadable", Some(&path));
                    partial = true;
                    continue;
                }
            };
            if file.metadata().map(|m| !m.is_file()).unwrap_or(true) {
                diag(&mut d, "file_not_regular", Some(&path));
                partial = true;
                continue;
            }
            let remaining = max_total.saturating_sub(total);
            let limit = max_file.min(remaining);
            let mut bytes = Vec::new();
            let read_result = file.take(limit as u64 + 1).read_to_end(&mut bytes);
            total = total.saturating_add(bytes.len());
            if read_result.is_err() {
                diag(&mut d, "file_read_failed", Some(&path));
                partial = true;
                continue;
            }
            if bytes.len() > limit {
                diag(
                    &mut d,
                    if bytes.len() > remaining {
                        "aggregate_byte_limit_exceeded"
                    } else {
                        "file_limit_exceeded"
                    },
                    Some(&path),
                );
                partial = true;
                continue;
            }
            let record_budget = max_records.saturating_sub(records_parsed);
            let parsed = parse_with_limit(&bytes, record_budget);
            records_parsed = records_parsed.saturating_add(parsed.records_read);
            for (line, byte_offset) in &parsed.issues {
                diag_at(&mut d, "malformed_line", Some(&path), *line, *byte_offset);
            }
            if let Some((line, byte_offset)) = parsed.limit_at {
                diag_at(
                    &mut d,
                    "record_limit_exceeded",
                    Some(&path),
                    line,
                    byte_offset,
                );
                partial = true;
                record_limit_reached = true;
            }
            if !parsed.issues.is_empty() || !parsed.has_desktop_entry {
                diag(&mut d, "malformed_desktop_entry", Some(&path));
                partial = true;
            }
            entries.push(Entry {
                scope,
                source_path: display_path(&path),
                applicability: "not_evaluated",
                keys: parsed.keys,
            });
            if record_limit_reached {
                break;
            }
        }
        if let Some(code) = hit_code {
            diag(&mut d, code, None);
            partial = true;
        }
        if !d.diagnostics.is_empty() {
            d.status = Status::Partial;
            partial = true;
        }
        directory_rows.push(d);
    }
    if dirs.len() > MAX_STARTUP_DIRECTORIES {
        let mut d = Directory {
            scope: "system",
            path: "additional configured directories not checked".to_owned(),
            status: Status::Partial,
            files_seen: 0,
            diagnostics: Vec::new(),
        };
        diag(&mut d, "directory_count_limit_exceeded", None);
        directory_rows.push(d);
        partial = true;
    }
    XdgAutostartInventory {
        schema: "sideeffect.xdg_autostart_inventory",
        schema_version: 1,
        platform: "linux",
        scope: "xdg_autostart_files_only",
        capture_started_at_unix_ms: capture_started,
        capture_ended_at_unix_ms: now_ms(),
        status: if partial {
            Status::Partial
        } else {
            Status::Complete
        },
        directories: directory_rows,
        entries,
    }
}
#[cfg(test)]
fn parse(bytes: &[u8]) -> (Vec<KeyEvidence>, Vec<(usize, usize)>, bool) {
    let parsed = parse_with_limit(bytes, MAX_STARTUP_RECORDS);
    (parsed.keys, parsed.issues, parsed.has_desktop_entry)
}

struct ParsedStartupFile {
    keys: Vec<KeyEvidence>,
    issues: Vec<(usize, usize)>,
    has_desktop_entry: bool,
    records_read: usize,
    limit_at: Option<(usize, usize)>,
}

fn parse_with_limit(bytes: &[u8], max_records: usize) -> ParsedStartupFile {
    let mut out = Vec::new();
    let mut issues = Vec::new();
    let mut section = false;
    let mut has_desktop_entry = false;
    let mut offset = 0usize;
    let mut records_read = 0usize;
    let mut limit_at = None;
    for (i, line0) in bytes.split_inclusive(|b| *b == b'\n').enumerate() {
        if records_read >= max_records {
            limit_at = Some((i + 1, offset));
            break;
        }
        records_read += 1;
        if line0.len() > MAX_LINE_BYTES {
            issues.push((i + 1, offset));
            offset += line0.len();
            continue;
        }
        let line = line0.strip_suffix(b"\n").unwrap_or(line0);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let trim = trim_ascii(line);
        if trim.starts_with(b"[") {
            section = trim == b"[Desktop Entry]";
            has_desktop_entry |= section;
            if trim.last() != Some(&b']') {
                issues.push((i + 1, offset));
            }
        } else if section && !trim.is_empty() && !trim.starts_with(b"#") {
            if let Some(eq) = line.iter().position(|b| *b == b'=') {
                let k = trim_ascii(&line[..eq]);
                if let Some(name) = KEYS.iter().find(|n| n.as_bytes() == k) {
                    let val = trim_ascii(&line[eq + 1..]);
                    let (value, value_hex) = match std::str::from_utf8(val) {
                        Ok(s) => (Some(s.to_owned()), None),
                        Err(_) => (None, Some(hex(val))),
                    };
                    out.push(KeyEvidence {
                        key: (*name).to_owned(),
                        value,
                        value_hex,
                        line: i + 1,
                        byte_offset: offset,
                        byte_length: line0.len(),
                        line_sha256: sha256_hex(line0),
                    });
                } else {
                    out.push(unparsed(line, i + 1, offset, line0));
                }
            } else {
                issues.push((i + 1, offset));
                out.push(unparsed(line, i + 1, offset, line0));
            }
        }
        offset += line0.len();
    }
    ParsedStartupFile {
        keys: out,
        issues,
        has_desktop_entry,
        records_read,
        limit_at,
    }
}
fn unparsed(line: &[u8], number: usize, offset: usize, raw_line: &[u8]) -> KeyEvidence {
    let (value, value_hex) = match std::str::from_utf8(line) {
        Ok(s) => (Some(s.to_owned()), None),
        Err(_) => (None, Some(hex(line))),
    };
    KeyEvidence {
        key: "unparsed".to_owned(),
        value,
        value_hex,
        line: number,
        byte_offset: offset,
        byte_length: raw_line.len(),
        line_sha256: sha256_hex(raw_line),
    }
}
fn trim_ascii(b: &[u8]) -> &[u8] {
    let a = b
        .iter()
        .position(|x| !x.is_ascii_whitespace())
        .unwrap_or(b.len());
    let z = b
        .iter()
        .rposition(|x| !x.is_ascii_whitespace())
        .map_or(a, |i| i + 1);
    &b[a..z]
}
fn hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(b.len().saturating_mul(2));
    for byte in b {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}
fn display_path(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
fn diag(d: &mut Directory, code: &'static str, p: Option<&Path>) {
    d.diagnostics.push(Diagnostic {
        code,
        path: p.map(display_path),
        line: None,
        byte_offset: None,
    });
}
fn diag_at(
    d: &mut Directory,
    code: &'static str,
    p: Option<&Path>,
    line: usize,
    byte_offset: usize,
) {
    d.diagnostics.push(Diagnostic {
        code,
        path: p.map(display_path),
        line: Some(line),
        byte_offset: Some(byte_offset),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_key_duplicates_and_invalid_utf8_preserved() {
        let (keys, issues, found_section) =
            parse(b"[Desktop Entry]\nName=one\nName=two\nExec=x\nExec=\xff\nOther=y\nBroken\n");
        assert_eq!(issues, vec![(7, 56)]);
        assert!(found_section);
        assert_eq!(keys.iter().filter(|k| k.key == "Name").count(), 2);
        let invalid = keys
            .iter()
            .find(|k| k.key == "Exec" && k.value_hex.is_some())
            .unwrap();
        assert_eq!(invalid.value_hex.as_deref(), Some("ff"));
        assert_eq!(invalid.line, 5);
        assert!(
            keys.iter()
                .any(|k| k.key == "unparsed" && k.value.as_deref() == Some("Broken"))
        );
        assert_eq!(keys[0].byte_offset, 16);
    }
    #[test]
    fn other_sections_are_ignored() {
        let (k, issues, found) = parse(b"[Other]\nExec=no\n[Desktop Entry]\nType=Application\n");
        assert!(issues.is_empty());
        assert!(found);
        assert_eq!(k.len(), 1);
        assert_eq!(k[0].key, "Type");
    }
    #[test]
    fn oversized_line_is_diagnostic_and_not_retained() {
        let mut b = b"[Desktop Entry]\nName=".to_vec();
        b.extend(vec![b'x'; MAX_LINE_BYTES]);
        let (k, issues, found) = parse(&b);
        assert_eq!(issues, vec![(2, 16)]);
        assert!(found);
        assert!(k.is_empty());
    }
    #[test]
    fn physical_line_record_limit_accepts_exact_boundary_and_reports_next_line() {
        let exact = b"[Desktop Entry]\nName=a\n";
        let parsed = parse_with_limit(exact, 2);
        assert_eq!(parsed.records_read, 2);
        assert!(parsed.limit_at.is_none());
        assert!(parsed.issues.is_empty());
        assert!(parsed.has_desktop_entry);
        assert_eq!(parsed.keys.len(), 1);

        let over = b"[Desktop Entry]\nName=a\nextra\n";
        let parsed = parse_with_limit(over, 2);
        assert_eq!(parsed.records_read, 2);
        assert_eq!(parsed.limit_at, Some((3, exact.len())));
        assert!(parsed.issues.is_empty());
        assert!(parsed.has_desktop_entry);
        assert_eq!(parsed.keys.len(), 1);
    }
    #[test]
    fn missing_desktop_entry_section_is_detected() {
        let (_, _, found) = parse(b"[Other]\nName=not-a-desktop-entry\n");
        assert!(!found);
    }
    #[test]
    fn xdg_empty_variables_use_specified_defaults() {
        let roots = resolve_xdg_paths(
            Some(OsStr::new("/home/test")),
            Some(OsStr::new("")),
            Some(OsStr::new("")),
        );
        assert_eq!(roots[0].1, PathBuf::from("/home/test/.config/autostart"));
        assert_eq!(roots[1].1, PathBuf::from("/etc/xdg/autostart"));
        let custom = resolve_xdg_paths(
            Some(OsStr::new("/home/test")),
            Some(OsStr::new("/custom/config")),
            Some(OsStr::new("/first:/second")),
        );
        assert_eq!(custom[0].1, PathBuf::from("/custom/config/autostart"));
        assert_eq!(custom[1].1, PathBuf::from("/first/autostart"));
        assert_eq!(custom[2].1, PathBuf::from("/second/autostart"));
    }
    #[cfg(unix)]
    #[test]
    fn symlink_file_is_reported_partial() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("se-startup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let target = root.join("target");
        fs::write(&target, b"[Desktop Entry]\nName=x\n").unwrap();
        symlink(&target, root.join("evil.desktop")).unwrap();
        let d = collect(
            &[("user", root.clone())],
            10,
            1000,
            1000,
            Duration::from_secs(1),
        );
        assert_eq!(d.status, Status::Partial);
        assert!(d.entries.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn missing_optional_directory_is_empty_complete() {
        let root = std::env::temp_dir().join(format!("se-startup-missing-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let d = collect(&[("user", root)], 10, 1000, 1000, Duration::from_secs(1));
        assert_eq!(d.status, Status::Complete);
        assert!(d.entries.is_empty());
    }
    #[test]
    fn invalid_configured_directory_is_partial() {
        let root = std::env::temp_dir().join(format!("se-startup-invalid-{}", std::process::id()));
        let _ = fs::remove_file(&root);
        fs::write(&root, b"not a directory").unwrap();
        let d = collect(
            &[("user", root.clone())],
            10,
            1000,
            1000,
            Duration::from_secs(1),
        );
        assert_eq!(d.status, Status::Partial);
        assert_eq!(d.directories[0].diagnostics[0].code, "directory_invalid");
        fs::remove_file(root).unwrap();
    }
    #[test]
    fn file_size_limit_and_deadline_are_partial() {
        let root = std::env::temp_dir().join(format!("se-startup-bounds-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("a.desktop"), b"[Desktop Entry]\nName=a\n").unwrap();
        let limited = collect(
            &[("user", root.clone())],
            10,
            2,
            1000,
            Duration::from_secs(1),
        );
        assert_eq!(limited.status, Status::Partial);
        assert!(
            limited.directories[0]
                .diagnostics
                .iter()
                .any(|d| d.code == "file_limit_exceeded")
        );
        let aggregate = collect(
            &[("user", root.clone())],
            10,
            1000,
            2,
            Duration::from_secs(1),
        );
        assert!(
            aggregate.directories[0]
                .diagnostics
                .iter()
                .any(|d| d.code == "aggregate_byte_limit_exceeded")
        );
        let expired = collect(&[("user", root.clone())], 10, 1000, 1000, Duration::ZERO);
        assert_eq!(expired.status, Status::Partial);
        assert_eq!(
            expired.directories[0].diagnostics[0].code,
            "scan_deadline_exceeded"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn limits_make_scan_partial() {
        let root = std::env::temp_dir().join(format!("se-startup-limit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("a.desktop"), b"[Desktop Entry]\nName=a\n").unwrap();
        fs::write(root.join("b.desktop"), b"[Desktop Entry]\nName=b\n").unwrap();
        let d = collect(
            &[("user", root.clone())],
            1,
            1000,
            1000,
            Duration::from_secs(1),
        );
        assert_eq!(d.status, Status::Partial);
        assert_eq!(d.entries.len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parsed_record_limit_is_global_across_files_and_reports_source_offset() {
        let root =
            std::env::temp_dir().join(format!("se-startup-record-limit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("a.desktop"), b"[Desktop Entry]\nName=a\n").unwrap();
        fs::write(root.join("b.desktop"), b"[Desktop Entry]\nName=b\n").unwrap();

        let d = collect_with_record_limit(
            &[("user", root.clone())],
            10,
            1024,
            4096,
            Duration::from_secs(1),
            3,
        );

        assert_eq!(d.status, Status::Partial);
        assert_eq!(d.entries.len(), 2);
        assert_eq!(d.entries[0].keys.len(), 1);
        assert!(d.entries[1].keys.is_empty());
        assert!(d.directories[0].diagnostics.iter().any(|diag| {
            diag.code == "record_limit_exceeded"
                && diag.path.as_deref() == Some(root.join("b.desktop").to_string_lossy().as_ref())
                && diag.line == Some(2)
                && diag.byte_offset == Some(b"[Desktop Entry]\n".len())
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_file_probe_bytes_consume_the_aggregate_budget() {
        let root =
            std::env::temp_dir().join(format!("se-startup-probe-budget-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("a.desktop"), b"12345").unwrap();
        fs::write(root.join("b.desktop"), b"67890").unwrap();

        let d = collect(&[("user", root.clone())], 10, 4, 5, Duration::from_secs(1));

        assert_eq!(d.status, Status::Partial);
        assert_eq!(d.directories[0].files_seen, 1);
        assert!(
            d.directories[0]
                .diagnostics
                .iter()
                .any(|diag| diag.code == "file_limit_exceeded")
        );
        assert!(
            d.directories[0]
                .diagnostics
                .iter()
                .any(|diag| diag.code == "aggregate_byte_limit_exceeded")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
