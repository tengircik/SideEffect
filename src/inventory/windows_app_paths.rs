//! Bounded, read-only inventory of selected Windows App Paths registrations.
//!
//! These records show registry configuration only. They do not prove that a
//! registered executable exists, is installed, or can be launched. Registry
//! strings are retained as inert literal data; environment strings are never
//! expanded and no command text is parsed or executed.

use serde::Serialize;
use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_MORE_DATA: u32 = 234;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const KEY_READ: u32 = 0x0002_0019;
const KEY_WOW64_64KEY: u32 = 0x0100;
const KEY_WOW64_32KEY: u32 = 0x0200;

pub const MAX_ENTRIES: usize = 4_096;
const MAX_ENTRIES_PER_SOURCE: usize = MAX_ENTRIES;
const MAX_NAME_UNITS: usize = 1_024;
const MAX_VALUE_BYTES: usize = 64 * 1024;
const MAX_AGGREGATE_NAME_UNITS: usize = 1024 * 1024;
const MAX_AGGREGATE_VALUE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SCAN_DURATION_MS: u128 = 10_000;

const HKEY_CURRENT_USER: isize = -2_147_483_647;
const HKEY_LOCAL_MACHINE: isize = -2_147_483_646;
const APP_PATHS_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths";

type Handle = *mut c_void;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(
        key: Handle,
        subkey: *const u16,
        options: u32,
        desired: u32,
        result: *mut Handle,
    ) -> i32;
    fn RegQueryInfoKeyW(
        key: Handle,
        class: *mut u16,
        class_length: *mut u32,
        reserved: *mut u32,
        subkeys: *mut u32,
        max_subkey_length: *mut u32,
        max_class_length: *mut u32,
        values: *mut u32,
        max_value_name_length: *mut u32,
        max_value_data_length: *mut u32,
        security_descriptor_size: *mut u32,
        last_write_time: *mut c_void,
    ) -> i32;
    fn RegEnumKeyExW(
        key: Handle,
        index: u32,
        name: *mut u16,
        name_length: *mut u32,
        reserved: *mut u32,
        class: *mut u16,
        class_length: *mut u32,
        last_write_time: *mut c_void,
    ) -> i32;
    fn RegQueryValueExW(
        key: Handle,
        value_name: *const u16,
        reserved: *mut u32,
        value_type: *mut u32,
        data: *mut u8,
        data_length: *mut u32,
    ) -> i32;
    fn RegCloseKey(key: Handle) -> i32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppPathStatus {
    Complete,
    Partial,
    NotPresent,
    Inaccessible,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppPathRegistryView {
    Native,
    Wow64_32,
    Wow64_64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AppPathValue {
    pub name: &'static str,
    pub registry_type: u32,
    pub type_name: &'static str,
    pub text: Option<String>,
    /// Exact bytes returned by the registry, encoded as lowercase hex.
    pub raw_data_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AppPathEntry {
    /// Registry subkey name; this is a registration label, not an executable proof.
    pub registered_name: String,
    pub registered_name_utf16_hex: String,
    /// Default value, conventionally a registered executable path.
    pub executable_path: Option<AppPathValue>,
    /// Optional `Path` value, retained literally and not interpreted as a command.
    pub search_path: Option<AppPathValue>,
    /// True when the same registry subkey label appeared in an earlier selected view.
    pub duplicate_registration_name: bool,
    pub evidence: AppPathEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct AppPathEvidence {
    pub source: &'static str,
    pub hive: &'static str,
    pub registry_view: AppPathRegistryView,
    pub registry_key: &'static str,
    pub entry_index: usize,
    pub registry_subkey: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AppPathDiagnostic {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_name: Option<&'static str>,
    pub message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub win32_error: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AppPathSource {
    pub id: &'static str,
    pub status: AppPathStatus,
    pub entries_seen: usize,
    pub hive: &'static str,
    pub registry_key: &'static str,
    pub registry_view: AppPathRegistryView,
    pub diagnostics: Vec<AppPathDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsAppPathInventoryDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub capture_started_at_unix_ms: u128,
    pub capture_ended_at_unix_ms: u128,
    pub status: AppPathStatus,
    pub sources: Vec<AppPathSource>,
    pub entries: Vec<AppPathEntry>,
    pub duplicate_registration_names: usize,
}

#[derive(Clone, Copy, Debug)]
struct RegistrySource {
    id: &'static str,
    hive: &'static str,
    root: isize,
    view: AppPathRegistryView,
    flag: u32,
}

const SOURCES: [RegistrySource; 3] = [
    RegistrySource {
        id: "current_user_native_app_paths",
        hive: "HKEY_CURRENT_USER",
        root: HKEY_CURRENT_USER,
        view: AppPathRegistryView::Native,
        flag: 0,
    },
    RegistrySource {
        id: "local_machine_64_app_paths",
        hive: "HKEY_LOCAL_MACHINE",
        root: HKEY_LOCAL_MACHINE,
        view: AppPathRegistryView::Wow64_64,
        flag: KEY_WOW64_64KEY,
    },
    RegistrySource {
        id: "local_machine_32_app_paths",
        hive: "HKEY_LOCAL_MACHINE",
        root: HKEY_LOCAL_MACHINE,
        view: AppPathRegistryView::Wow64_32,
        flag: KEY_WOW64_32KEY,
    },
];

struct RegistryKey(Handle);
impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

trait AppPathsRegistryApi {
    type Key;
    fn open_root(&mut self, source: RegistrySource) -> Result<Self::Key, u32>;
    fn query_subkey_info(&mut self, key: &Self::Key) -> Result<(u32, u32), u32>;
    fn enumerate(&mut self, key: &Self::Key, index: u32, name: &mut [u16], length: &mut u32)
    -> u32;
    fn open_entry(&mut self, source: RegistrySource, name: &[u16]) -> Result<Self::Key, u32>;
    fn read_value(
        &mut self,
        key: &Self::Key,
        name: &'static str,
        aggregate_remaining: usize,
    ) -> Result<Option<(u32, Vec<u8>)>, u32>;
}

struct NativeRegistryApi;
impl AppPathsRegistryApi for NativeRegistryApi {
    type Key = RegistryKey;
    fn open_root(&mut self, source: RegistrySource) -> Result<Self::Key, u32> {
        open_key(source, APP_PATHS_KEY)
    }
    fn query_subkey_info(&mut self, key: &Self::Key) -> Result<(u32, u32), u32> {
        let (mut count, mut max_name) = (0u32, 0u32);
        let result = unsafe {
            RegQueryInfoKeyW(
                key.0,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut count,
                &mut max_name,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        } as u32;
        if result == 0 {
            Ok((count, max_name))
        } else {
            Err(result)
        }
    }
    fn enumerate(
        &mut self,
        key: &Self::Key,
        index: u32,
        name: &mut [u16],
        length: &mut u32,
    ) -> u32 {
        unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                name.as_mut_ptr(),
                length,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            ) as u32
        }
    }
    fn open_entry(&mut self, source: RegistrySource, name: &[u16]) -> Result<Self::Key, u32> {
        let mut path = APP_PATHS_KEY.encode_utf16().collect::<Vec<_>>();
        path.push(b'\\' as u16);
        path.extend_from_slice(name);
        path.push(0);
        let mut key = null_mut();
        let result = unsafe {
            RegOpenKeyExW(
                source.root as Handle,
                path.as_ptr(),
                0,
                KEY_READ | source.flag,
                &mut key,
            )
        } as u32;
        if result == 0 {
            Ok(RegistryKey(key))
        } else {
            Err(result)
        }
    }
    fn read_value(
        &mut self,
        key: &Self::Key,
        name: &'static str,
        aggregate_remaining: usize,
    ) -> Result<Option<(u32, Vec<u8>)>, u32> {
        read_value(key.0, name, aggregate_remaining)
    }
}

fn open_key(source: RegistrySource, path: &str) -> Result<RegistryKey, u32> {
    let path = wide_z(OsStr::new(path));
    let mut key = null_mut();
    let result = unsafe {
        RegOpenKeyExW(
            source.root as Handle,
            path.as_ptr(),
            0,
            KEY_READ | source.flag,
            &mut key,
        )
    } as u32;
    if result == 0 {
        Ok(RegistryKey(key))
    } else {
        Err(result)
    }
}

pub fn collect_windows_app_paths() -> WindowsAppPathInventoryDocument {
    collect_with_api(&mut NativeRegistryApi)
}

fn collect_with_api<A: AppPathsRegistryApi>(api: &mut A) -> WindowsAppPathInventoryDocument {
    let started_at = now_ms();
    let started = Instant::now();
    let mut sources = Vec::with_capacity(SOURCES.len());
    let mut entries = Vec::new();
    let mut name_units = 0usize;
    let mut value_bytes = 0usize;
    let mut entries_examined = 0usize;
    let mut seen_names = std::collections::HashSet::<String>::new();
    let mut duplicates = 0usize;
    for source in SOURCES {
        let (result, mut rows, names, bytes, duplicate_count, examined) = collect_source(
            api,
            source,
            started,
            MAX_ENTRIES
                .saturating_sub(entries_examined)
                .min(MAX_ENTRIES_PER_SOURCE),
            MAX_AGGREGATE_NAME_UNITS.saturating_sub(name_units),
            MAX_AGGREGATE_VALUE_BYTES.saturating_sub(value_bytes),
            &mut seen_names,
        );
        name_units = name_units.saturating_add(names);
        value_bytes = value_bytes.saturating_add(bytes);
        entries_examined = entries_examined.saturating_add(examined);
        duplicates = duplicates.saturating_add(duplicate_count);
        sources.push(result);
        entries.append(&mut rows);
    }
    let status = if sources.iter().all(|s| {
        matches!(
            s.status,
            AppPathStatus::Complete | AppPathStatus::NotPresent
        )
    }) {
        AppPathStatus::Complete
    } else {
        AppPathStatus::Partial
    };
    WindowsAppPathInventoryDocument {
        schema: "sideeffect.windows_app_path_inventory",
        schema_version: 1,
        platform: "windows",
        scope: "selected_current_user_native_and_accessible_machine_32_bit_and_64_bit_app_paths_registry_entries",
        capture_started_at_unix_ms: started_at,
        capture_ended_at_unix_ms: now_ms(),
        status,
        sources,
        entries,
        duplicate_registration_names: duplicates,
    }
}

fn collect_source<A: AppPathsRegistryApi>(
    api: &mut A,
    source: RegistrySource,
    started: Instant,
    entry_limit: usize,
    names_remaining: usize,
    values_remaining: usize,
    seen_names: &mut std::collections::HashSet<String>,
) -> (AppPathSource, Vec<AppPathEntry>, usize, usize, usize, usize) {
    if started.elapsed().as_millis() >= MAX_SCAN_DURATION_MS {
        return (
            source_result(
                source,
                AppPathStatus::Partial,
                0,
                vec![diag(
                    "scan_deadline_exceeded",
                    None,
                    None,
                    "The App Paths inventory time limit was reached before this registry view was checked.",
                    None,
                )],
            ),
            vec![],
            0,
            0,
            0,
            0,
        );
    }
    let key = match api.open_root(source) {
        Ok(key) => key,
        Err(e) => {
            let status = open_status(e);
            let diagnostics = if status == AppPathStatus::NotPresent {
                vec![]
            } else {
                vec![diag(
                    "app_paths_key_unavailable",
                    None,
                    None,
                    "Windows could not open this selected App Paths registry view.",
                    Some(e),
                )]
            };
            return (
                source_result(source, status, 0, diagnostics),
                vec![],
                0,
                0,
                0,
                0,
            );
        }
    };
    let (count, max_name) = match api.query_subkey_info(&key) {
        Ok(info) => info,
        Err(e) => {
            return (
                source_result(
                    source,
                    error_status(e),
                    0,
                    vec![diag(
                        "app_paths_metadata_failed",
                        None,
                        None,
                        "Windows could not query this App Paths registry view.",
                        Some(e),
                    )],
                ),
                vec![],
                0,
                0,
                0,
                0,
            );
        }
    };
    let name_capacity = (max_name as usize)
        .min(MAX_NAME_UNITS)
        .saturating_add(1)
        .min(MAX_NAME_UNITS + 1);
    let mut buffer = vec![0u16; name_capacity];
    let mut status = AppPathStatus::Complete;
    let mut diagnostics = Vec::new();
    let mut rows = Vec::new();
    let mut names_used = 0usize;
    let mut values_used = 0usize;
    let mut duplicate_count = 0usize;
    let mut seen = 0usize;
    let mut examined = 0usize;
    for index in 0..count {
        if started.elapsed().as_millis() >= MAX_SCAN_DURATION_MS {
            status = AppPathStatus::Partial;
            diagnostics.push(diag(
                "scan_deadline_exceeded",
                Some(index as usize),
                None,
                "The inventory time limit was reached while enumerating App Paths.",
                None,
            ));
            break;
        }
        if examined >= entry_limit {
            status = AppPathStatus::Partial;
            diagnostics.push(diag(
                "entry_limit_exceeded",
                Some(index as usize),
                None,
                "The bounded App Paths entry limit was reached; later entries were not read.",
                None,
            ));
            break;
        }
        examined = examined.saturating_add(1);
        let mut length = buffer.len() as u32;
        let result = api.enumerate(&key, index, &mut buffer, &mut length);
        if result != 0 {
            status = AppPathStatus::Partial;
            diagnostics.push(diag(
                if result == ERROR_MORE_DATA {
                    "entry_name_limit_exceeded"
                } else {
                    "entry_enumeration_failed"
                },
                Some(index as usize),
                None,
                "Windows could not read this App Paths subkey name within the configured bound.",
                Some(result),
            ));
            if result == ERROR_ACCESS_DENIED {
                break;
            }
            continue;
        }
        let length = length as usize;
        if length > MAX_NAME_UNITS
            || length > buffer.len()
            || length > names_remaining.saturating_sub(names_used)
        {
            status = AppPathStatus::Partial;
            diagnostics.push(diag("entry_name_limit_exceeded", Some(index as usize), None, "An App Paths subkey name exceeded an individual or aggregate bound and was omitted.", None));
            continue;
        }
        names_used = names_used.saturating_add(length);
        seen += 1;
        let raw_name = &buffer[..length];
        let display_name = match String::from_utf16(raw_name) {
            Ok(value) => value,
            Err(_) => {
                status = AppPathStatus::Partial;
                diagnostics.push(diag("entry_name_malformed_utf16", Some(index as usize), None, "An App Paths subkey name contained invalid UTF-16; exact name bytes are retained and its values were not read.", None));
                rows.push(make_entry(
                    source,
                    index as usize,
                    String::from_utf16_lossy(raw_name),
                    raw_name,
                    None,
                    None,
                    false,
                ));
                continue;
            }
        };
        let folded = display_name.to_lowercase();
        let duplicate = !seen_names.insert(folded);
        if duplicate {
            duplicate_count += 1;
        }
        let entry_key = match api.open_entry(source, raw_name) {
            Ok(key) => key,
            Err(e) => {
                status = if e == ERROR_ACCESS_DENIED {
                    AppPathStatus::Inaccessible
                } else {
                    AppPathStatus::Partial
                };
                diagnostics.push(diag("entry_disappeared_or_inaccessible", Some(index as usize), None, "Windows could not reopen this App Paths subkey after enumeration; its values are unknown.", Some(e)));
                continue;
            }
        };
        let mut read = |value_name| {
            if started.elapsed().as_millis() >= MAX_SCAN_DURATION_MS {
                return Err(ERROR_MORE_DATA);
            }
            api.read_value(
                &entry_key,
                value_name,
                values_remaining.saturating_sub(values_used),
            )
        };
        let decode = |name,
                      value: Result<Option<(u32, Vec<u8>)>, u32>,
                      diagnostics: &mut Vec<AppPathDiagnostic>,
                      status: &mut AppPathStatus,
                      values_used: &mut usize|
         -> Option<AppPathValue> {
            match value {
                Ok(None) => None,
                Ok(Some((kind, data))) => {
                    *values_used = values_used.saturating_add(data.len());
                    let (value, issue) = decode_value(name, kind, &data);
                    if let Some(code) = issue {
                        *status = AppPathStatus::Partial;
                        diagnostics.push(diag(code, Some(index as usize), Some(name), "The registry value is unsupported or malformed; exact bytes remain available without a guessed interpretation.", None));
                    }
                    Some(value)
                }
                Err(e) => {
                    *status = AppPathStatus::Partial;
                    diagnostics.push(diag(if e == ERROR_MORE_DATA { "value_limit_or_deadline_exceeded" } else { "value_read_failed" }, Some(index as usize), Some(name), "Windows could not read this selected App Paths value within the configured bounds.", Some(e)));
                    None
                }
            }
        };
        let default_value = read("");
        let executable = decode(
            "(Default)",
            default_value,
            &mut diagnostics,
            &mut status,
            &mut values_used,
        );
        let path_value = read("Path");
        let search = decode(
            "Path",
            path_value,
            &mut diagnostics,
            &mut status,
            &mut values_used,
        );
        if executable
            .as_ref()
            .and_then(|v| v.text.as_ref())
            .is_none_or(|v| v.trim().is_empty())
        {
            status = AppPathStatus::Partial;
            diagnostics.push(diag("default_executable_value_missing_or_unusable", Some(index as usize), Some("(Default)"), "This registry entry has no usable string default value; registration does not establish an executable path.", None));
        }
        rows.push(make_entry(
            source,
            index as usize,
            display_name,
            raw_name,
            executable,
            search,
            duplicate,
        ));
    }
    if count as usize > entry_limit && !diagnostics.iter().any(|d| d.code == "entry_limit_exceeded")
    {
        status = AppPathStatus::Partial;
        diagnostics.push(diag(
            "entry_limit_exceeded",
            None,
            None,
            "The bounded App Paths entry limit was lower than the registry-reported entry count.",
            None,
        ));
    }
    (
        source_result(source, status, seen, diagnostics),
        rows,
        names_used,
        values_used,
        duplicate_count,
        examined,
    )
}

fn make_entry(
    source: RegistrySource,
    index: usize,
    name: String,
    raw_name: &[u16],
    executable_path: Option<AppPathValue>,
    search_path: Option<AppPathValue>,
    duplicate_registration_name: bool,
) -> AppPathEntry {
    AppPathEntry {
        registered_name: name.clone(),
        registered_name_utf16_hex: utf16_hex(raw_name),
        executable_path,
        search_path,
        duplicate_registration_name,
        evidence: AppPathEvidence {
            source: "RegEnumKeyExW/RegQueryValueExW",
            hive: source.hive,
            registry_view: source.view,
            registry_key: APP_PATHS_KEY,
            entry_index: index,
            registry_subkey: name,
        },
    }
}

fn read_value(
    key: Handle,
    name: &'static str,
    remaining: usize,
) -> Result<Option<(u32, Vec<u8>)>, u32> {
    let name_wide = if name.is_empty() {
        vec![0]
    } else {
        wide_z(OsStr::new(name))
    };
    let name_ptr = if name.is_empty() {
        null_mut()
    } else {
        name_wide.as_ptr() as *mut u16
    };
    let mut kind = 0u32;
    let mut size = 0u32;
    let result =
        unsafe { RegQueryValueExW(key, name_ptr, null_mut(), &mut kind, null_mut(), &mut size) }
            as u32;
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if result != 0 && result != ERROR_MORE_DATA {
        return Err(result);
    }
    let size = size as usize;
    if size > MAX_VALUE_BYTES || size > remaining {
        return Err(ERROR_MORE_DATA);
    }
    let mut data = vec![0u8; size];
    let mut actual = data.len() as u32;
    let result = unsafe {
        RegQueryValueExW(
            key,
            name_ptr,
            null_mut(),
            &mut kind,
            if data.is_empty() {
                null_mut()
            } else {
                data.as_mut_ptr()
            },
            &mut actual,
        )
    } as u32;
    if result != 0 {
        return Err(result);
    }
    if actual as usize > data.len() {
        return Err(ERROR_MORE_DATA);
    }
    data.truncate(actual as usize);
    Ok(Some((kind, data)))
}

fn decode_value(
    name: &'static str,
    kind: u32,
    data: &[u8],
) -> (AppPathValue, Option<&'static str>) {
    let type_name = match kind {
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        _ => "unsupported",
    };
    let text = if matches!(kind, REG_SZ | REG_EXPAND_SZ) && data.len() % 2 == 0 {
        let units = data
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect::<Vec<_>>();
        let end = units.iter().rposition(|u| *u != 0).map_or(0, |i| i + 1);
        String::from_utf16(&units[..end]).ok()
    } else {
        None
    };
    let issue = if type_name == "unsupported" {
        Some("app_path_value_type_unsupported")
    } else if data.len() % 2 != 0 {
        Some("app_path_value_malformed_length")
    } else if text.is_none() {
        Some("app_path_value_malformed_utf16")
    } else {
        None
    };
    (
        AppPathValue {
            name,
            registry_type: kind,
            type_name,
            text,
            raw_data_hex: bytes_hex(data),
        },
        issue,
    )
}

fn source_result(
    source: RegistrySource,
    status: AppPathStatus,
    entries_seen: usize,
    diagnostics: Vec<AppPathDiagnostic>,
) -> AppPathSource {
    AppPathSource {
        id: source.id,
        status,
        entries_seen,
        hive: source.hive,
        registry_key: APP_PATHS_KEY,
        registry_view: source.view,
        diagnostics,
    }
}
fn diag(
    code: &'static str,
    entry_index: Option<usize>,
    value_name: Option<&'static str>,
    message: &'static str,
    win32_error: Option<u32>,
) -> AppPathDiagnostic {
    AppPathDiagnostic {
        code,
        entry_index,
        value_name,
        message,
        win32_error,
    }
}
fn open_status(error: u32) -> AppPathStatus {
    match error {
        ERROR_FILE_NOT_FOUND => AppPathStatus::NotPresent,
        ERROR_ACCESS_DENIED => AppPathStatus::Inaccessible,
        _ => AppPathStatus::Error,
    }
}
fn error_status(error: u32) -> AppPathStatus {
    if error == ERROR_ACCESS_DENIED {
        AppPathStatus::Inaccessible
    } else {
        AppPathStatus::Error
    }
}
fn wide_z(value: impl AsRef<OsStr>) -> Vec<u16> {
    let mut wide = value.as_ref().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    wide
}
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
fn utf16_hex(units: &[u16]) -> String {
    let mut out = String::with_capacity(units.len().saturating_mul(4));
    for unit in units {
        for shift in [12, 8, 4, 0] {
            out.push(b"0123456789abcdef"[((unit >> shift) & 15) as usize] as char);
        }
    }
    out
}
fn bytes_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.push(b"0123456789abcdef"[(b >> 4) as usize] as char);
        out.push(b"0123456789abcdef"[(b & 15) as usize] as char);
    }
    out
}
