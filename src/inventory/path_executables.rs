//! Bounded discovery of executable-name candidates in the current process PATH.
//! Candidate selection is metadata-only; no discovered path is opened for execution.

use serde::Serialize;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub const PATH_EXECUTABLE_SCHEMA: &str = "sideeffect.path_executable_inventory";
pub const PATH_EXECUTABLE_SCHEMA_VERSION: u32 = 1;
pub const MAX_PATH_COMPONENTS: usize = 256;
pub const MAX_PATH_ENTRIES: usize = 20_000;
pub const MAX_PATH_DATA_BYTES_OR_UNITS: usize = 16 * 1024 * 1024;
pub const MAX_PATHEXT_UNITS: usize = 32_767;
pub const MAX_PATHEXT_EXTENSIONS: usize = 256;
pub const PATH_SCAN_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Serialize)]
pub struct ExactPath {
    pub display: String,
    pub exact: bool,
    #[cfg(unix)]
    pub raw_bytes_hex: String,
    #[cfg(windows)]
    pub utf16_code_units: Vec<u16>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PathEntry {
    pub ordinal: usize,
    pub name: ExactPath,
    pub status: &'static str,
    pub metadata_status: &'static str,
    pub candidate_rule: Option<&'static str>,
    pub evidence: PathEntryEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct PathEntryEvidence {
    pub directory_ordinal: usize,
    pub entry_ordinal: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct PathDirectory {
    pub ordinal: usize,
    pub component_ordinal: usize,
    pub path: ExactPath,
    pub status: &'static str,
    pub entries: Vec<PathEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PathComponent {
    pub ordinal: usize,
    pub path: ExactPath,
    pub empty_component_mapped_to_cwd: bool,
    pub directory_ordinal: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PathDiagnostic {
    pub code: &'static str,
    pub component_ordinal: Option<usize>,
    pub directory_ordinal: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PathExecutableInventory {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub path_source: &'static str,
    pub candidate_extensions: Vec<String>,
    pub candidate_extensions_status: &'static str,
    pub status: &'static str,
    pub components: Vec<PathComponent>,
    pub directories: Vec<PathDirectory>,
    pub diagnostics: Vec<PathDiagnostic>,
    pub limits: PathLimits,
}

#[derive(Clone, Debug, Serialize)]
pub struct PathLimits {
    pub max_components: usize,
    pub max_component_path_bytes_or_units: usize,
    pub max_entries: usize,
    pub max_aggregate_path_and_name_bytes_or_units: usize,
    pub max_pathext_utf16_units: usize,
    pub max_pathext_extensions: usize,
    pub deadline_seconds: u64,
}

pub fn collect_path_executables() -> PathExecutableInventory {
    let path = std::env::var_os("PATH");
    #[cfg(windows)]
    {
        let extensions = std::env::var_os("PATHEXT");
        collect_from_environment(path.as_deref(), extensions.as_deref(), || {
            std::env::current_dir().ok()
        })
    }
    #[cfg(not(windows))]
    {
        collect_from_environment(path.as_deref(), None, || std::env::current_dir().ok())
    }
}

fn collect_from_environment<F>(
    path: Option<&OsStr>,
    pathext: Option<&OsStr>,
    cwd: F,
) -> PathExecutableInventory
where
    F: FnOnce() -> Option<PathBuf>,
{
    if let Some(path) = path {
        return collect_from(path, pathext, cwd);
    }
    #[allow(unused_mut)]
    let mut diagnostics = vec![PathDiagnostic {
        code: "path_environment_unavailable",
        component_ordinal: None,
        directory_ordinal: None,
    }];
    #[cfg(windows)]
    if pathext.is_none() {
        diagnostics.push(PathDiagnostic {
            code: "pathext_unavailable",
            component_ordinal: None,
            directory_ordinal: None,
        });
    }
    #[cfg(windows)]
    if pathext.is_some_and(|value| path_size(value) > MAX_PATHEXT_UNITS) {
        diagnostics.push(PathDiagnostic {
            code: "pathext_limit_reached",
            component_ordinal: None,
            directory_ordinal: None,
        });
    }
    PathExecutableInventory {
        schema: PATH_EXECUTABLE_SCHEMA,
        schema_version: PATH_EXECUTABLE_SCHEMA_VERSION,
        platform: if cfg!(windows) { "windows" } else { "linux" },
        path_source: "current_process_environment_PATH",
        candidate_extensions: pathext.map(parse_extensions).unwrap_or_default(),
        candidate_extensions_status: pathext_status(pathext),
        status: "partial",
        components: Vec::new(),
        directories: Vec::new(),
        diagnostics,
        limits: path_limits(),
    }
}

fn collect_from<F>(path: &OsStr, pathext: Option<&OsStr>, cwd: F) -> PathExecutableInventory
where
    F: FnOnce() -> Option<PathBuf>,
{
    let start = Instant::now();
    let mut partial = false;
    let mut diagnostics = Vec::new();
    let mut components = Vec::new();
    let mut directories = Vec::new();
    let mut used = 0usize;
    let mut total_entries = 0usize;
    let cwd = cwd();
    let ext = pathext.map(parse_extensions).unwrap_or_default();
    #[cfg(windows)]
    if pathext.is_none() {
        partial = true;
        diagnostics.push(PathDiagnostic {
            code: "pathext_unavailable",
            component_ordinal: None,
            directory_ordinal: None,
        });
    }
    #[cfg(windows)]
    if pathext.is_some_and(|value| path_size(value) > MAX_PATHEXT_UNITS) {
        partial = true;
        diagnostics.push(PathDiagnostic {
            code: "pathext_limit_reached",
            component_ordinal: None,
            directory_ordinal: None,
        });
    }
    let mut parts = std::env::split_paths(path).peekable();
    while let Some(raw_component) = parts.next() {
        if components.len() >= MAX_PATH_COMPONENTS || start.elapsed() >= PATH_SCAN_DEADLINE {
            partial = true;
            diagnostics.push(PathDiagnostic {
                code: if components.len() >= MAX_PATH_COMPONENTS {
                    "component_limit_reached"
                } else {
                    "scan_deadline_exceeded"
                },
                component_ordinal: None,
                directory_ordinal: None,
            });
            break;
        }
        let component_ordinal = components.len();
        let empty = raw_component.as_os_str().is_empty();
        let directory = if empty {
            cwd.clone()
        } else {
            Some(raw_component.clone())
        };
        let encoded = exact_path(raw_component.as_os_str());
        let component_size = path_size(raw_component.as_os_str());
        used = used.saturating_add(component_size);
        if component_size > component_limit() || used > MAX_PATH_DATA_BYTES_OR_UNITS {
            partial = true;
            diagnostics.push(PathDiagnostic {
                code: "path_data_limit_reached",
                component_ordinal: Some(component_ordinal),
                directory_ordinal: None,
            });
            components.push(PathComponent {
                ordinal: component_ordinal,
                path: encoded,
                empty_component_mapped_to_cwd: empty,
                directory_ordinal: None,
            });
            for remaining in parts {
                let i = components.len();
                if i < MAX_PATH_COMPONENTS {
                    let s = path_size(remaining.as_os_str());
                    used = used.saturating_add(s);
                    components.push(PathComponent {
                        ordinal: i,
                        path: exact_path(remaining.as_os_str()),
                        empty_component_mapped_to_cwd: remaining.as_os_str().is_empty(),
                        directory_ordinal: None,
                    });
                }
            }
            break;
        }
        if empty && directory.is_none() {
            partial = true;
            diagnostics.push(PathDiagnostic {
                code: "current_directory_unavailable",
                component_ordinal: Some(component_ordinal),
                directory_ordinal: None,
            });
            components.push(PathComponent {
                ordinal: component_ordinal,
                path: encoded,
                empty_component_mapped_to_cwd: true,
                directory_ordinal: None,
            });
            continue;
        }
        let dir_path = directory.unwrap();
        let directory_ordinal = directories.len();
        components.push(PathComponent {
            ordinal: component_ordinal,
            path: exact_path(raw_component.as_os_str()),
            empty_component_mapped_to_cwd: empty,
            directory_ordinal: Some(directory_ordinal),
        });
        let mut dir_record = PathDirectory {
            ordinal: directory_ordinal,
            component_ordinal,
            path: exact_path(dir_path.as_os_str()),
            status: "complete",
            entries: Vec::new(),
        };
        used = used.saturating_add(path_size(dir_path.as_os_str()));
        if used > MAX_PATH_DATA_BYTES_OR_UNITS {
            dir_record.status = "unknown";
            partial = true;
            diagnostics.push(PathDiagnostic {
                code: "path_data_limit_reached",
                component_ordinal: Some(component_ordinal),
                directory_ordinal: Some(directory_ordinal),
            });
            directories.push(dir_record);
            continue;
        }
        match fs::symlink_metadata(&dir_path) {
            Ok(meta) if is_reparse_or_symlink(&meta) => {
                dir_record.status = "unknown";
                partial = true;
                diagnostics.push(PathDiagnostic {
                    code: "directory_symlink_or_reparse_not_followed",
                    component_ordinal: Some(component_ordinal),
                    directory_ordinal: Some(directory_ordinal),
                });
            }
            Ok(meta) if !meta.is_dir() => {
                dir_record.status = "unknown";
                partial = true;
                diagnostics.push(PathDiagnostic {
                    code: "component_not_directory",
                    component_ordinal: Some(component_ordinal),
                    directory_ordinal: Some(directory_ordinal),
                });
            }
            Ok(_) => match fs::read_dir(&dir_path) {
                Err(_) => {
                    dir_record.status = "unknown";
                    partial = true;
                    diagnostics.push(PathDiagnostic {
                        code: "directory_unreadable",
                        component_ordinal: Some(component_ordinal),
                        directory_ordinal: Some(directory_ordinal),
                    });
                }
                Ok(iter) => {
                    let mut reported_link = false;
                    for (entry_ordinal, item) in iter.enumerate() {
                        if start.elapsed() >= PATH_SCAN_DEADLINE {
                            dir_record.status = "partial";
                            partial = true;
                            diagnostics.push(PathDiagnostic {
                                code: "scan_deadline_exceeded",
                                component_ordinal: Some(component_ordinal),
                                directory_ordinal: Some(directory_ordinal),
                            });
                            break;
                        }
                        if total_entries >= MAX_PATH_ENTRIES {
                            dir_record.status = "partial";
                            partial = true;
                            diagnostics.push(PathDiagnostic {
                                code: "entry_limit_reached",
                                component_ordinal: Some(component_ordinal),
                                directory_ordinal: Some(directory_ordinal),
                            });
                            break;
                        }
                        let entry = match item {
                            Ok(v) => v,
                            Err(_) => {
                                partial = true;
                                dir_record.status = "partial";
                                diagnostics.push(PathDiagnostic {
                                    code: "directory_entry_unreadable",
                                    component_ordinal: Some(component_ordinal),
                                    directory_ordinal: Some(directory_ordinal),
                                });
                                continue;
                            }
                        };
                        let name = entry.file_name();
                        total_entries += 1;
                        let name_bytes = path_size(&name);
                        used = used.saturating_add(name_bytes);
                        if used > MAX_PATH_DATA_BYTES_OR_UNITS {
                            partial = true;
                            dir_record.status = "partial";
                            diagnostics.push(PathDiagnostic {
                                code: "path_data_limit_reached",
                                component_ordinal: Some(component_ordinal),
                                directory_ordinal: Some(directory_ordinal),
                            });
                            break;
                        }
                        let metadata = match fs::symlink_metadata(entry.path()) {
                            Ok(m) => m,
                            Err(_) => {
                                partial = true;
                                dir_record.status = "partial";
                                diagnostics.push(PathDiagnostic {
                                    code: "entry_metadata_unavailable",
                                    component_ordinal: Some(component_ordinal),
                                    directory_ordinal: Some(directory_ordinal),
                                });
                                dir_record.entries.push(PathEntry {
                                    ordinal: dir_record.entries.len(),
                                    name: exact_path(&name),
                                    status: "unknown",
                                    metadata_status: "unavailable",
                                    candidate_rule: None,
                                    evidence: PathEntryEvidence {
                                        directory_ordinal,
                                        entry_ordinal,
                                    },
                                });
                                continue;
                            }
                        };
                        if is_reparse_or_symlink(&metadata) {
                            partial = true;
                            dir_record.status = "partial";
                            if !reported_link {
                                diagnostics.push(PathDiagnostic {
                                    code: "child_symlink_or_reparse_not_followed",
                                    component_ordinal: Some(component_ordinal),
                                    directory_ordinal: Some(directory_ordinal),
                                });
                                reported_link = true;
                            }
                            dir_record.entries.push(PathEntry {
                                ordinal: dir_record.entries.len(),
                                name: exact_path(&name),
                                status: "unknown",
                                metadata_status: "symlink_or_reparse_not_followed",
                                candidate_rule: None,
                                evidence: PathEntryEvidence {
                                    directory_ordinal,
                                    entry_ordinal,
                                },
                            });
                            continue;
                        }
                        let is_candidate = candidate(
                            &name,
                            &metadata,
                            &ext,
                            pathext_status(pathext) == "available",
                        );
                        if is_candidate.is_none() {
                            partial = true;
                            dir_record.status = "partial";
                        }
                        dir_record.entries.push(PathEntry {
                            ordinal: dir_record.entries.len(),
                            name: exact_path(&name),
                            status: match is_candidate {
                                Some(true) => "candidate",
                                Some(false) => "not_candidate",
                                None => "unknown",
                            },
                            metadata_status: "observed",
                            candidate_rule: is_candidate
                                .and_then(|value| value.then_some(candidate_rule())),
                            evidence: PathEntryEvidence {
                                directory_ordinal,
                                entry_ordinal,
                            },
                        });
                    }
                }
            },
            Err(_) => {
                dir_record.status = "unknown";
                partial = true;
                diagnostics.push(PathDiagnostic {
                    code: "directory_unavailable",
                    component_ordinal: Some(component_ordinal),
                    directory_ordinal: Some(directory_ordinal),
                });
            }
        }
        directories.push(dir_record);
    }
    PathExecutableInventory {
        schema: PATH_EXECUTABLE_SCHEMA,
        schema_version: PATH_EXECUTABLE_SCHEMA_VERSION,
        platform: if cfg!(windows) { "windows" } else { "linux" },
        path_source: "current_process_environment_PATH",
        candidate_extensions: ext,
        candidate_extensions_status: pathext_status(pathext),
        status: if partial { "partial" } else { "complete" },
        components,
        directories,
        diagnostics,
        limits: path_limits(),
    }
}

#[cfg(unix)]
fn component_limit() -> usize {
    4096
}
#[cfg(windows)]
fn component_limit() -> usize {
    32767
}
fn path_limits() -> PathLimits {
    PathLimits {
        max_components: MAX_PATH_COMPONENTS,
        max_component_path_bytes_or_units: component_limit(),
        max_entries: MAX_PATH_ENTRIES,
        max_aggregate_path_and_name_bytes_or_units: MAX_PATH_DATA_BYTES_OR_UNITS,
        max_pathext_utf16_units: MAX_PATHEXT_UNITS,
        max_pathext_extensions: MAX_PATHEXT_EXTENSIONS,
        deadline_seconds: PATH_SCAN_DEADLINE.as_secs(),
    }
}
#[cfg(windows)]
fn pathext_status(value: Option<&OsStr>) -> &'static str {
    match value {
        None => "unavailable",
        Some(value) if path_size(value) > MAX_PATHEXT_UNITS => "partial",
        Some(_) => "available",
    }
}
#[cfg(not(windows))]
fn pathext_status(_: Option<&OsStr>) -> &'static str {
    "not_applicable"
}
#[cfg(unix)]
fn path_size(path: &OsStr) -> usize {
    use std::os::unix::ffi::OsStrExt;
    path.as_bytes().len()
}
#[cfg(windows)]
fn path_size(path: &OsStr) -> usize {
    use std::os::windows::ffi::OsStrExt;
    path.encode_wide().count()
}
#[cfg(unix)]
fn exact_path(path: &OsStr) -> ExactPath {
    use std::os::unix::ffi::OsStrExt;
    if path_size(path) > component_limit() {
        return ExactPath {
            display: "<omitted: component path exceeds limit>".to_owned(),
            exact: false,
            raw_bytes_hex: String::new(),
        };
    }
    let bytes = path.as_bytes();
    ExactPath {
        display: path.to_string_lossy().into_owned(),
        exact: true,
        raw_bytes_hex: bytes.iter().map(|b| format!("{b:02x}")).collect(),
    }
}
#[cfg(windows)]
fn exact_path(path: &OsStr) -> ExactPath {
    use std::os::windows::ffi::OsStrExt;
    if path_size(path) > component_limit() {
        return ExactPath {
            display: "<omitted: component path exceeds limit>".to_owned(),
            exact: false,
            utf16_code_units: Vec::new(),
        };
    }
    ExactPath {
        display: path.to_string_lossy().into_owned(),
        exact: true,
        utf16_code_units: path.encode_wide().collect(),
    }
}
#[cfg(unix)]
fn is_reparse_or_symlink(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}
#[cfg(windows)]
fn is_reparse_or_symlink(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_type().is_symlink() || meta.file_attributes() & 0x400 != 0
}
#[cfg(unix)]
fn candidate(name: &OsStr, meta: &fs::Metadata, _: &[String], _: bool) -> Option<bool> {
    use std::os::unix::fs::PermissionsExt;
    let _ = name;
    Some(meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}
#[cfg(windows)]
fn candidate(
    name: &OsStr,
    meta: &fs::Metadata,
    extensions: &[String],
    extension_available: bool,
) -> Option<bool> {
    if !meta.is_file() {
        return Some(false);
    }
    if !extension_available {
        return None;
    }
    Some(
        extensions
            .iter()
            .any(|ext| name.to_string_lossy().to_ascii_lowercase().ends_with(ext)),
    )
}
#[cfg(unix)]
fn candidate_rule() -> &'static str {
    "regular_file_with_execute_bit"
}
#[cfg(windows)]
fn candidate_rule() -> &'static str {
    "regular_file_with_captured_PATHEXT_suffix"
}
#[cfg(windows)]
fn parse_extensions(value: &OsStr) -> Vec<String> {
    use std::os::windows::ffi::OsStrExt;
    String::from_utf16_lossy(
        &value
            .encode_wide()
            .take(MAX_PATHEXT_UNITS)
            .collect::<Vec<_>>(),
    )
    .split(';')
    .filter(|s| !s.is_empty())
    .take(MAX_PATHEXT_EXTENSIONS)
    .map(str::to_ascii_lowercase)
    .collect()
}
#[cfg(not(windows))]
fn parse_extensions(_: &OsStr) -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn unique_test_directory(label: &str) -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        for _ in 0..100 {
            let attempt = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-path-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create unique test directory: {error}"),
            }
        }
        panic!("could not allocate unique test directory after 100 attempts")
    }

    #[test]
    fn schema_roundtrip_preserves_exact_path_and_order() {
        let root = unique_test_directory("schema");
        fs::create_dir_all(root.join("a")).unwrap();
        fs::create_dir_all(root.join("b")).unwrap();
        #[cfg(windows)]
        let file = root.join("a/tool.exe");
        #[cfg(not(windows))]
        let file = root.join("a/tool");
        fs::write(&file, b"").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = std::env::join_paths([root.join("a"), root.join("b"), root.join("a")]).unwrap();
        #[cfg(windows)]
        let doc = collect_from(&path, Some(OsStr::new(".EXE")), || None);
        #[cfg(not(windows))]
        let doc = collect_from(&path, None, || None);
        assert_eq!(doc.status, "complete", "diagnostics: {:?}", doc.diagnostics);
        assert_eq!(doc.components.len(), 3);
        assert_eq!(
            doc.directories[2].path.display,
            doc.directories[0].path.display
        );
        #[cfg(windows)]
        assert_eq!(doc.directories[0].entries[0].name.display, "tool.exe");
        #[cfg(not(windows))]
        assert_eq!(doc.directories[0].entries[0].name.display, "tool");
        assert_eq!(doc.directories[0].entries[0].evidence.directory_ordinal, 0);
        let bytes = serde_json::to_vec(&doc).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["schema_version"], 1);
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn missing_path_is_partial_and_does_not_consult_or_scan_cwd() {
        let mut cwd_consulted = false;
        let d = collect_from_environment(None, None, || {
            cwd_consulted = true;
            Some(PathBuf::from("."))
        });
        assert!(!cwd_consulted);
        assert!(d.components.is_empty());
        assert!(d.directories.is_empty());
        assert_eq!(d.status, "partial");
        assert!(
            d.diagnostics
                .iter()
                .any(|x| x.code == "path_environment_unavailable")
        );
    }
    #[cfg(unix)]
    #[test]
    fn non_utf8_names_are_retained_and_symlinks_are_not_followed() {
        use std::ffi::OsString;
        use std::os::unix::{ffi::OsStringExt, fs::PermissionsExt};
        let root = unique_test_directory("link");
        let odd = OsString::from_vec(b"bad-\xff".to_vec());
        let f = root.join(&odd);
        fs::write(&f, b"").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&f, root.join("alias")).unwrap();
        let p = std::env::join_paths([&root]).unwrap();
        let d = collect_from(&p, None, || None);
        assert_eq!(d.status, "partial");
        assert!(
            d.directories[0]
                .entries
                .iter()
                .any(|e| e.name.raw_bytes_hex == "6261642dff")
        );
        assert!(
            d.directories[0]
                .entries
                .iter()
                .any(|e| e.name.display == "alias"
                    && e.status == "unknown"
                    && e.metadata_status == "symlink_or_reparse_not_followed")
        );
        assert!(
            d.diagnostics
                .iter()
                .any(|x| x.code == "child_symlink_or_reparse_not_followed")
        );
        let _ = fs::remove_dir_all(root);
    }
    #[cfg(unix)]
    #[test]
    fn symlink_path_directory_is_unknown_without_enumerating_target() {
        let parent = unique_test_directory("directory-link");
        let target = parent.join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("hidden-candidate"), b"not inspected").unwrap();
        let link = parent.join("path-component");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let path = std::env::join_paths([&link]).unwrap();
        let d = collect_from(&path, None, || None);
        assert_eq!(d.status, "partial");
        assert_eq!(d.directories[0].status, "unknown");
        assert!(d.directories[0].entries.is_empty());
        assert!(
            d.diagnostics
                .iter()
                .any(|x| x.code == "directory_symlink_or_reparse_not_followed")
        );
        let _ = fs::remove_dir_all(parent);
    }
    #[test]
    fn component_limit_retains_partial_document() {
        let parts = (0..=MAX_PATH_COMPONENTS)
            .map(|n| PathBuf::from(format!("unavailable-component-{n}")))
            .collect::<Vec<_>>();
        let p = std::env::join_paths(parts).unwrap();
        let d = collect_from(&p, None, || None);
        assert_eq!(d.status, "partial");
        assert!(d.components.len() <= MAX_PATH_COMPONENTS);
        assert!(
            d.diagnostics
                .iter()
                .any(|x| x.code == "component_limit_reached")
        );
    }

    #[cfg(unix)]
    #[test]
    fn oversized_non_utf8_component_is_reported_without_serializing_its_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let oversized = OsString::from_vec(vec![b'x'; 4097]);
        let d = collect_from(&oversized, None, || None);
        assert_eq!(d.status, "partial");
        assert!(!d.components[0].path.exact);
        assert_eq!(d.components[0].path.raw_bytes_hex, "");
        assert!(
            d.diagnostics
                .iter()
                .any(|x| x.code == "path_data_limit_reached")
        );
    }

    #[cfg(unix)]
    #[test]
    fn empty_components_map_to_cwd_and_keep_duplicate_order() {
        let root = unique_test_directory("cwd");
        let file = root.join("from-cwd");
        fs::write(&file, b"").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
        let d = collect_from(OsStr::new(":"), None, || Some(root.clone()));
        assert_eq!(d.components.len(), 2);
        assert!(d.components.iter().all(|c| c.empty_component_mapped_to_cwd));
        assert_eq!(d.directories[0].entries[0].name.display, "from-cwd");
        assert_eq!(d.directories[0].path.display, d.directories[1].path.display);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn missing_pathext_keeps_regular_rows_unknown() {
        let root = unique_test_directory("ext");
        fs::write(root.join("tool.exe"), b"synthetic fixture; never executed").unwrap();
        let path = std::env::join_paths([root.clone()]).unwrap();
        let d = collect_from(&path, None, || None);
        assert_eq!(d.status, "partial");
        assert_eq!(d.directories[0].entries[0].status, "unknown");
        assert_eq!(d.directories[0].entries[0].metadata_status, "observed");
        let _ = fs::remove_dir_all(root);
    }
}
