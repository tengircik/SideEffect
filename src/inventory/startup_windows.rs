//! Bounded native Windows startup configuration snapshot.
//!
//! Registry commands and startup-folder paths are data only. This module never
//! expands environment strings, parses command lines, or launches entries.

use serde::Serialize;
use std::ffi::{OsStr, c_void};
use std::fs;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::ptr::null_mut;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const KEY_READ: u32 = 0x0002_0019;
const KEY_WOW64_64KEY: u32 = 0x0100;
const KEY_WOW64_32KEY: u32 = 0x0200;
const MAX_VALUE_NAME_UNITS: usize = 16_384;
const MAX_VALUE_DATA_BYTES: usize = 64 * 1024;
const MAX_AGGREGATE_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_AGGREGATE_REGISTRY_NAME_UNITS: usize = 1024 * 1024;
const MAX_STARTUP_ENTRIES: usize = 8_192;
const MAX_PATH_UNITS: usize = 32_768;
const MAX_AGGREGATE_PATH_UNITS: usize = 4 * 1024 * 1024;
const MAX_SCAN_DURATION_MS: u128 = 10_000;
const KF_FLAG_DONT_VERIFY: u32 = 0x0000_4000;
const REGISTRY_ROOT_CURRENT_USER: isize = -2_147_483_647;
const REGISTRY_ROOT_LOCAL_MACHINE: isize = -2_147_483_646;

type Handle = *mut c_void;

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

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
        value_count: *mut u32,
        max_value_name_length: *mut u32,
        max_value_data_length: *mut u32,
        security_descriptor_size: *mut u32,
        last_write_time: *mut c_void,
    ) -> i32;
    fn RegEnumValueW(
        key: Handle,
        index: u32,
        value_name: *mut u16,
        value_name_length: *mut u32,
        reserved: *mut u32,
        value_type: *mut u32,
        data: *mut u8,
        data_length: *mut u32,
    ) -> i32;
    fn RegCloseKey(key: Handle) -> i32;
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(
        folder_id: *const Guid,
        flags: u32,
        token: Handle,
        path: *mut *mut u16,
    ) -> i32;
}

#[link(name = "ole32")]
unsafe extern "system" {
    fn CoTaskMemFree(memory: *mut c_void);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsStartupStatus {
    Complete,
    Partial,
    NotPresent,
    Inaccessible,
    Unavailable,
    Unsupported,
    NotChecked,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsRegistryView {
    Native,
    Wow64_32,
    Wow64_64,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsStartupDiagnostic {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_index: Option<usize>,
    pub message: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRegistryStartupEntry {
    pub registry_key: &'static str,
    pub hive: &'static str,
    pub registry_view: WindowsRegistryView,
    pub trigger: &'static str,
    pub value_name: String,
    pub value_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_utf16_hex: Option<String>,
    pub evidence: WindowsRegistryStartupEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRegistryStartupEvidence {
    pub source: &'static str,
    pub hive: &'static str,
    pub registry_view: WindowsRegistryView,
    pub registry_key: &'static str,
    pub value_index: usize,
    pub value_name: String,
    pub registry_type: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsStartupFolderEntry {
    pub folder_scope: &'static str,
    pub trigger: &'static str,
    pub display_path: String,
    pub path_utf16_hex: String,
    pub kind: &'static str,
    pub evidence: WindowsStartupFolderEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsStartupFolderEvidence {
    pub source: &'static str,
    pub folder_scope: &'static str,
    pub display_path: String,
    pub path_utf16_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsStartupSource {
    pub id: &'static str,
    pub status: WindowsStartupStatus,
    pub entries_seen: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hive: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_key: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_view: Option<WindowsRegistryView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_path_utf16_hex: Option<String>,
    pub diagnostics: Vec<WindowsStartupDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsStartupInventoryDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub capture_started_at_unix_ms: u128,
    pub capture_ended_at_unix_ms: u128,
    pub status: WindowsStartupStatus,
    pub sources: Vec<WindowsStartupSource>,
    pub registry_entries: Vec<WindowsRegistryStartupEntry>,
    pub folder_entries: Vec<WindowsStartupFolderEntry>,
}

#[derive(Clone, Copy)]
struct RegistrySource {
    id: &'static str,
    hive: &'static str,
    root: isize,
    key: &'static str,
    trigger: &'static str,
    view: WindowsRegistryView,
    wow64_flag: u32,
}

const REGISTRY_SOURCES: [RegistrySource; 8] = [
    RegistrySource {
        id: "current_user_run_native",
        hive: "HKEY_CURRENT_USER",
        root: REGISTRY_ROOT_CURRENT_USER,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        trigger: "user_logon",
        view: WindowsRegistryView::Native,
        wow64_flag: 0,
    },
    RegistrySource {
        id: "current_user_run_once_native",
        hive: "HKEY_CURRENT_USER",
        root: REGISTRY_ROOT_CURRENT_USER,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        trigger: "user_logon_once",
        view: WindowsRegistryView::Native,
        wow64_flag: 0,
    },
    RegistrySource {
        id: "current_user_run_32",
        hive: "HKEY_CURRENT_USER",
        root: REGISTRY_ROOT_CURRENT_USER,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        trigger: "user_logon",
        view: WindowsRegistryView::Wow64_32,
        wow64_flag: KEY_WOW64_32KEY,
    },
    RegistrySource {
        id: "current_user_run_once_32",
        hive: "HKEY_CURRENT_USER",
        root: REGISTRY_ROOT_CURRENT_USER,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        trigger: "user_logon_once",
        view: WindowsRegistryView::Wow64_32,
        wow64_flag: KEY_WOW64_32KEY,
    },
    RegistrySource {
        id: "local_machine_run_64",
        hive: "HKEY_LOCAL_MACHINE",
        root: REGISTRY_ROOT_LOCAL_MACHINE,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        trigger: "user_logon",
        view: WindowsRegistryView::Wow64_64,
        wow64_flag: KEY_WOW64_64KEY,
    },
    RegistrySource {
        id: "local_machine_run_once_64",
        hive: "HKEY_LOCAL_MACHINE",
        root: REGISTRY_ROOT_LOCAL_MACHINE,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        trigger: "user_logon_once",
        view: WindowsRegistryView::Wow64_64,
        wow64_flag: KEY_WOW64_64KEY,
    },
    RegistrySource {
        id: "local_machine_run_32",
        hive: "HKEY_LOCAL_MACHINE",
        root: REGISTRY_ROOT_LOCAL_MACHINE,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        trigger: "user_logon",
        view: WindowsRegistryView::Wow64_32,
        wow64_flag: KEY_WOW64_32KEY,
    },
    RegistrySource {
        id: "local_machine_run_once_32",
        hive: "HKEY_LOCAL_MACHINE",
        root: REGISTRY_ROOT_LOCAL_MACHINE,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        trigger: "user_logon_once",
        view: WindowsRegistryView::Wow64_32,
        wow64_flag: KEY_WOW64_32KEY,
    },
];

const FOLDER_IDS: [(&str, Guid); 2] = [
    (
        "user_startup",
        Guid {
            data1: 0xb97d20bb,
            data2: 0xf46a,
            data3: 0x4c97,
            data4: [0xba, 0x10, 0x5e, 0x36, 0x08, 0x43, 0x08, 0x54],
        },
    ),
    (
        "common_startup",
        Guid {
            data1: 0x82a5ea35,
            data2: 0xd9cd,
            data3: 0x47c5,
            data4: [0x96, 0x29, 0xe1, 0x5d, 0x2f, 0x71, 0x4e, 0x6e],
        },
    ),
];

struct RegistryKey(Handle);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

struct KnownFolderPath(*mut u16);

impl Drop for KnownFolderPath {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(self.0.cast()) };
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn collect_windows_startup() -> WindowsStartupInventoryDocument {
    let started_at = now_ms();
    let started = Instant::now();
    let mut sources = Vec::new();
    let mut registry_entries = Vec::new();
    let mut folder_entries = Vec::new();
    let mut aggregate_registry_bytes = 0usize;
    let mut aggregate_registry_names = 0usize;
    let mut registry_values_checked = 0usize;
    let mut aggregate_path_units = 0usize;
    let mut folder_entries_checked = 0usize;
    for source in REGISTRY_SOURCES {
        if elapsed(started) {
            let mut result = source_result(
                source.id,
                WindowsStartupStatus::Partial,
                0,
                vec![diagnostic(
                    "scan_deadline_exceeded",
                    None,
                    "The startup inventory time limit was reached before this source was checked.",
                )],
            );
            result.registry_hive = Some(source.hive);
            result.registry_key = Some(source.key);
            result.registry_view = Some(source.view);
            sources.push(result);
            continue;
        }
        let remaining_entries = (MAX_STARTUP_ENTRIES / 2).saturating_sub(registry_values_checked);
        let (mut result, entries, bytes, checked, names) = collect_registry_source(
            source,
            started,
            MAX_AGGREGATE_REGISTRY_BYTES.saturating_sub(aggregate_registry_bytes),
            MAX_AGGREGATE_REGISTRY_NAME_UNITS.saturating_sub(aggregate_registry_names),
            remaining_entries,
        );
        result.registry_hive = Some(source.hive);
        result.registry_key = Some(source.key);
        result.registry_view = Some(source.view);
        aggregate_registry_bytes = aggregate_registry_bytes.saturating_add(bytes);
        aggregate_registry_names = aggregate_registry_names.saturating_add(names);
        registry_values_checked = registry_values_checked.saturating_add(checked);
        registry_entries.extend(entries);
        sources.push(result);
    }

    for (folder_scope, folder_id) in &FOLDER_IDS {
        if elapsed(started) {
            sources.push(source_result(
                folder_scope,
                WindowsStartupStatus::Partial,
                0,
                vec![diagnostic(
                    "scan_deadline_exceeded",
                    None,
                    "The startup inventory time limit was reached before this folder was checked.",
                )],
            ));
            continue;
        }
        let remaining_entries = (MAX_STARTUP_ENTRIES / 2).saturating_sub(folder_entries_checked);
        let (result, entries, units, checked) = collect_startup_folder(
            folder_scope,
            folder_id,
            MAX_AGGREGATE_PATH_UNITS.saturating_sub(aggregate_path_units),
            remaining_entries,
            started,
        );
        aggregate_path_units = aggregate_path_units.saturating_add(units);
        folder_entries_checked = folder_entries_checked.saturating_add(checked);
        folder_entries.extend(entries);
        sources.push(result);
    }

    sources.push(source_result(
        "service_start_configuration",
        WindowsStartupStatus::NotChecked,
        0,
        vec![diagnostic(
            "service_sources_not_implemented",
            None,
            "Windows service start configuration is not checked by this adapter.",
        )],
    ));
    sources.push(source_result(
        "scheduled_task_triggers",
        WindowsStartupStatus::NotChecked,
        0,
        vec![diagnostic(
            "scheduled_task_sources_not_implemented",
            None,
            "Windows scheduled-task boot/logon triggers are not checked by this adapter.",
        )],
    ));
    let status = if sources.iter().any(|source| {
        !matches!(
            source.status,
            WindowsStartupStatus::Complete | WindowsStartupStatus::NotPresent
        )
    }) {
        WindowsStartupStatus::Partial
    } else {
        WindowsStartupStatus::Complete
    };
    WindowsStartupInventoryDocument {
        schema: "sideeffect.windows_startup_inventory",
        schema_version: 1,
        platform: "windows",
        scope: "current_user_and_accessible_machine_run_keys_and_startup_folders",
        capture_started_at_unix_ms: started_at,
        capture_ended_at_unix_ms: now_ms(),
        status,
        sources,
        registry_entries,
        folder_entries,
    }
}

fn elapsed(started: Instant) -> bool {
    started.elapsed().as_millis() >= MAX_SCAN_DURATION_MS
}

fn collect_registry_source(
    source: RegistrySource,
    started: Instant,
    aggregate_remaining: usize,
    aggregate_name_remaining: usize,
    entry_remaining: usize,
) -> (
    WindowsStartupSource,
    Vec<WindowsRegistryStartupEntry>,
    usize,
    usize,
    usize,
) {
    let subkey = wide_z(OsStr::new(source.key));
    let mut key = null_mut();
    let code = unsafe {
        RegOpenKeyExW(
            source.root as Handle,
            subkey.as_ptr(),
            0,
            KEY_READ | source.wow64_flag,
            &mut key,
        )
    } as u32;
    if code != 0 {
        let status = match code {
            ERROR_FILE_NOT_FOUND => WindowsStartupStatus::NotPresent,
            ERROR_ACCESS_DENIED => WindowsStartupStatus::Inaccessible,
            _ => WindowsStartupStatus::Error,
        };
        let diagnostics = if status == WindowsStartupStatus::NotPresent {
            Vec::new()
        } else {
            vec![diagnostic(
                "registry_key_unavailable",
                None,
                "Windows could not open this startup registry key in the requested view.",
            )]
        };
        return (
            source_result(source.id, status, 0, diagnostics),
            Vec::new(),
            0,
            0,
            0,
        );
    }
    let key = RegistryKey(key);
    let mut value_count = 0u32;
    let mut max_name = 0u32;
    let mut max_data = 0u32;
    let query_code = unsafe {
        RegQueryInfoKeyW(
            key.0,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut value_count,
            &mut max_name,
            &mut max_data,
            null_mut(),
            null_mut(),
        )
    } as u32;
    if query_code != 0 {
        return (
            source_result(
                source.id,
                WindowsStartupStatus::Error,
                0,
                vec![diagnostic(
                    "registry_metadata_failed",
                    None,
                    "Windows could not read startup registry key metadata.",
                )],
            ),
            Vec::new(),
            0,
            0,
            0,
        );
    }
    let mut diagnostics = Vec::new();
    let mut status = WindowsStartupStatus::Complete;
    let name_capacity = (max_name as usize + 1).min(MAX_VALUE_NAME_UNITS + 1);
    if max_name as usize > MAX_VALUE_NAME_UNITS {
        status = WindowsStartupStatus::Partial;
        diagnostics.push(diagnostic(
            "registry_value_name_limit_exceeded",
            None,
            "At least one registry value name exceeds the supported UTF-16 length.",
        ));
    }
    if max_data as usize > MAX_VALUE_DATA_BYTES {
        status = WindowsStartupStatus::Partial;
        diagnostics.push(diagnostic(
            "registry_value_data_limit_exceeded",
            None,
            "At least one registry value exceeds the per-value data limit.",
        ));
    }
    let max_values = entry_remaining.min(value_count as usize);
    if value_count as usize > entry_remaining {
        status = WindowsStartupStatus::Partial;
        diagnostics.push(diagnostic(
            "registry_value_count_limit_exceeded",
            None,
            "The registry value count exceeds the per-source limit; remaining values were not checked.",
        ));
    }
    let mut entries = Vec::with_capacity(max_values.min(512));
    let mut bytes_read = 0usize;
    let mut values_checked = 0usize;
    let mut name_units_read = 0usize;
    for index in 0..max_values {
        if elapsed(started) {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "scan_deadline_exceeded",
                Some(index),
                "The startup inventory time limit was reached while enumerating this key.",
            ));
            break;
        }
        let mut name = vec![0u16; name_capacity.max(1)];
        let mut name_len = name.len() as u32;
        let mut value_type = 0u32;
        let available = MAX_VALUE_DATA_BYTES.min(aggregate_remaining.saturating_sub(bytes_read));
        let mut data = vec![0u8; available];
        let mut data_len = data.len() as u32;
        let result = unsafe {
            RegEnumValueW(
                key.0,
                index as u32,
                name.as_mut_ptr(),
                &mut name_len,
                null_mut(),
                &mut value_type,
                if data.is_empty() {
                    null_mut()
                } else {
                    data.as_mut_ptr()
                },
                &mut data_len,
            )
        } as u32;
        if result == ERROR_NO_MORE_ITEMS {
            break;
        }
        values_checked = values_checked.saturating_add(1);
        if result == ERROR_MORE_DATA {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "registry_value_over_limit_or_changed",
                Some(index),
                "A registry value exceeded the read buffer or changed during collection; its data was not retained.",
            ));
            continue;
        }
        if result != 0 {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "registry_value_read_failed",
                Some(index),
                "Windows could not read a startup registry value.",
            ));
            continue;
        }
        let name_len = name_len as usize;
        if name_len > MAX_VALUE_NAME_UNITS || name_len > name.len() {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "registry_value_name_limit_exceeded",
                Some(index),
                "A registry value name exceeded the supported UTF-16 length and was omitted.",
            ));
            continue;
        }
        if name_len > aggregate_name_remaining.saturating_sub(name_units_read) {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "registry_name_budget_exceeded",
                Some(index),
                "The aggregate registry value-name budget was exhausted; this value was omitted.",
            ));
            continue;
        }
        name_units_read = name_units_read.saturating_add(name_len);
        let value_name = match String::from_utf16(&name[..name_len]) {
            Ok(name) => name,
            Err(_) => {
                status = WindowsStartupStatus::Partial;
                diagnostics.push(diagnostic(
                    "registry_value_name_malformed_utf16",
                    Some(index),
                    "A registry value name contained invalid UTF-16 and was displayed lossily.",
                ));
                String::from_utf16_lossy(&name[..name_len])
            }
        };
        let data_len = data_len as usize;
        if data_len > data.len() {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "registry_value_read_failed",
                Some(index),
                "Windows reported a registry value length beyond the supplied read buffer.",
            ));
            continue;
        }
        bytes_read = bytes_read.saturating_add(data_len);
        let (type_name, command, raw_hex) = match decode_registry_text(
            value_type,
            &data[..data_len],
        ) {
            Ok((type_name, display, raw_hex, malformed_utf16)) => {
                if malformed_utf16 {
                    status = WindowsStartupStatus::Partial;
                    diagnostics.push(diagnostic(
                        "registry_command_malformed_utf16",
                        Some(index),
                        "A registry startup value contained invalid UTF-16; its display contains replacement characters.",
                    ));
                }
                (type_name, Some(display), Some(raw_hex))
            }
            Err(RegistryDecodeError::OddLength) => {
                status = WindowsStartupStatus::Partial;
                diagnostics.push(diagnostic(
                    "registry_command_malformed_length",
                    Some(index),
                    "A registry string had an odd byte length and was omitted.",
                ));
                (
                    if value_type == REG_SZ {
                        "REG_SZ"
                    } else {
                        "REG_EXPAND_SZ"
                    },
                    None,
                    None,
                )
            }
            Err(RegistryDecodeError::OverLimit) => {
                status = WindowsStartupStatus::Partial;
                diagnostics.push(diagnostic(
                    "registry_value_data_limit_exceeded",
                    Some(index),
                    "A registry startup value exceeded the supported data limit and was omitted.",
                ));
                (
                    if value_type == REG_SZ {
                        "REG_SZ"
                    } else {
                        "REG_EXPAND_SZ"
                    },
                    None,
                    None,
                )
            }
            Err(RegistryDecodeError::UnsupportedType) => {
                status = WindowsStartupStatus::Partial;
                diagnostics.push(diagnostic(
                    "registry_value_type_unsupported",
                    Some(index),
                    "A startup registry value had an unsupported type; its raw data was omitted.",
                ));
                ("unsupported", None, None)
            }
        };
        entries.push(WindowsRegistryStartupEntry {
            registry_key: source.key,
            hive: source.hive,
            registry_view: source.view,
            trigger: source.trigger,
            value_name: value_name.clone(),
            value_type: type_name,
            command,
            command_utf16_hex: raw_hex,
            evidence: WindowsRegistryStartupEvidence {
                source: "RegEnumValueW",
                hive: source.hive,
                registry_view: source.view,
                registry_key: source.key,
                value_index: index,
                value_name,
                registry_type: value_type,
            },
        });
    }
    (
        source_result(source.id, status, entries.len(), diagnostics),
        entries,
        bytes_read,
        values_checked,
        name_units_read,
    )
}

#[derive(Debug)]
enum RegistryDecodeError {
    OddLength,
    OverLimit,
    UnsupportedType,
}

fn decode_registry_text(
    value_type: u32,
    data: &[u8],
) -> Result<(&'static str, String, String, bool), RegistryDecodeError> {
    let type_name = match value_type {
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        _ => return Err(RegistryDecodeError::UnsupportedType),
    };
    if data.len() > MAX_VALUE_DATA_BYTES {
        return Err(RegistryDecodeError::OverLimit);
    }
    if data.len() % 2 != 0 {
        return Err(RegistryDecodeError::OddLength);
    }
    let units = data
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    let end = units
        .iter()
        .rposition(|unit| *unit != 0)
        .map_or(0, |i| i + 1);
    let (display, malformed_utf16) = match String::from_utf16(&units[..end]) {
        Ok(value) => (value, false),
        Err(_) => (String::from_utf16_lossy(&units[..end]), true),
    };
    Ok((type_name, display, utf16_hex(&units), malformed_utf16))
}

fn collect_startup_folder(
    folder_scope: &'static str,
    folder_id: &Guid,
    aggregate_remaining: usize,
    entry_remaining: usize,
    started: Instant,
) -> (
    WindowsStartupSource,
    Vec<WindowsStartupFolderEntry>,
    usize,
    usize,
) {
    let mut path = null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(folder_id, KF_FLAG_DONT_VERIFY, null_mut(), &mut path) };
    if result < 0 || path.is_null() {
        return (
            source_result(
                folder_scope,
                WindowsStartupStatus::Unavailable,
                0,
                vec![diagnostic(
                    "startup_folder_unavailable",
                    None,
                    "Windows could not resolve this known startup folder.",
                )],
            ),
            Vec::new(),
            0,
            0,
        );
    }
    let path = KnownFolderPath(path);
    let mut len = 0usize;
    unsafe {
        while len < MAX_PATH_UNITS && *path.0.add(len) != 0 {
            len += 1;
        }
    }
    if len == 0 || len >= MAX_PATH_UNITS {
        return (
            source_result(
                folder_scope,
                WindowsStartupStatus::Partial,
                0,
                vec![diagnostic(
                    "startup_folder_path_invalid_or_over_limit",
                    None,
                    "The known startup folder path was empty, malformed, or over the path limit.",
                )],
            ),
            Vec::new(),
            0,
            0,
        );
    }
    let wide = unsafe { std::slice::from_raw_parts(path.0, len) };
    let folder = PathBuf::from(std::ffi::OsString::from_wide(wide));
    let path_units = len;
    let display_folder = String::from_utf16_lossy(wide);
    let folder_hex = utf16_hex(wide);
    if path_units > aggregate_remaining {
        return (
            source_result_with_location(
                folder_scope,
                WindowsStartupStatus::Partial,
                0,
                vec![diagnostic(
                    "startup_path_budget_exceeded",
                    None,
                    "The aggregate startup path budget was exhausted before this folder was checked.",
                )],
                display_folder,
                folder_hex,
            ),
            Vec::new(),
            0,
            0,
        );
    }
    let read_dir = match fs::read_dir(&folder) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (
                source_result_with_location(
                    folder_scope,
                    WindowsStartupStatus::NotPresent,
                    0,
                    Vec::new(),
                    display_folder.clone(),
                    folder_hex.clone(),
                ),
                Vec::new(),
                path_units,
                0,
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return (
                source_result_with_location(
                    folder_scope,
                    WindowsStartupStatus::Inaccessible,
                    0,
                    vec![diagnostic(
                        "startup_folder_inaccessible",
                        None,
                        "Windows denied access to this startup folder.",
                    )],
                    display_folder.clone(),
                    folder_hex.clone(),
                ),
                Vec::new(),
                path_units,
                0,
            );
        }
        Err(_) => {
            return (
                source_result_with_location(
                    folder_scope,
                    WindowsStartupStatus::Error,
                    0,
                    vec![diagnostic(
                        "startup_folder_read_failed",
                        None,
                        "Windows could not enumerate this startup folder.",
                    )],
                    display_folder.clone(),
                    folder_hex.clone(),
                ),
                Vec::new(),
                path_units,
                0,
            );
        }
    };
    let mut entries = Vec::new();
    let mut diagnostics = Vec::new();
    let mut status = WindowsStartupStatus::Complete;
    let mut aggregate_used = path_units;
    let mut entries_checked = 0usize;
    for (index, item) in read_dir.enumerate() {
        if elapsed(started) {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "scan_deadline_exceeded",
                Some(index),
                "The startup inventory time limit was reached while enumerating this folder.",
            ));
            break;
        }
        if index >= entry_remaining {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "startup_folder_entry_limit_exceeded",
                Some(index),
                "The startup-folder entry limit was reached; remaining entries were not checked.",
            ));
            break;
        }
        entries_checked = entries_checked.saturating_add(1);
        let item = match item {
            Ok(item) => item,
            Err(_) => {
                status = WindowsStartupStatus::Partial;
                diagnostics.push(diagnostic(
                    "startup_folder_entry_read_failed",
                    Some(index),
                    "Windows could not read a startup-folder entry.",
                ));
                continue;
            }
        };
        let path = item.path();
        let wide_path = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if wide_path.len() > MAX_PATH_UNITS
            || wide_path.len() > aggregate_remaining.saturating_sub(aggregate_used)
        {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "startup_path_budget_exceeded",
                Some(index),
                "A startup path exceeded the per-path or aggregate path budget and was omitted.",
            ));
            continue;
        }
        aggregate_used = aggregate_used.saturating_add(wide_path.len());
        let display_path = String::from_utf16_lossy(&wide_path);
        let kind = match item.file_type() {
            Ok(kind) if kind.is_symlink() => "reparse_or_symlink_entry",
            Ok(kind) if kind.is_dir() => "directory",
            Ok(_) => "file",
            Err(_) => {
                status = WindowsStartupStatus::Partial;
                diagnostics.push(diagnostic(
                    "startup_folder_entry_metadata_failed",
                    Some(index),
                    "Windows could not determine a startup-folder entry's type.",
                ));
                "unknown"
            }
        };
        let hex = utf16_hex(&wide_path);
        entries.push(WindowsStartupFolderEntry {
            folder_scope,
            trigger: "user_logon",
            display_path: display_path.clone(),
            path_utf16_hex: hex.clone(),
            kind,
            evidence: WindowsStartupFolderEvidence {
                source: "SHGetKnownFolderPath/FindFirstFileW",
                folder_scope,
                display_path,
                path_utf16_hex: hex,
            },
        });
    }
    (
        source_result_with_location(
            folder_scope,
            status,
            entries.len(),
            diagnostics,
            display_folder,
            folder_hex,
        ),
        entries,
        aggregate_used,
        entries_checked,
    )
}

fn source_result(
    id: &'static str,
    status: WindowsStartupStatus,
    entries_seen: usize,
    diagnostics: Vec<WindowsStartupDiagnostic>,
) -> WindowsStartupSource {
    WindowsStartupSource {
        id,
        status,
        entries_seen,
        registry_hive: None,
        registry_key: None,
        registry_view: None,
        location_path: None,
        location_path_utf16_hex: None,
        diagnostics,
    }
}

fn source_result_with_location(
    id: &'static str,
    status: WindowsStartupStatus,
    entries_seen: usize,
    diagnostics: Vec<WindowsStartupDiagnostic>,
    location_path: String,
    location_path_utf16_hex: String,
) -> WindowsStartupSource {
    WindowsStartupSource {
        id,
        status,
        entries_seen,
        registry_hive: None,
        registry_key: None,
        registry_view: None,
        location_path: Some(location_path),
        location_path_utf16_hex: Some(location_path_utf16_hex),
        diagnostics,
    }
}

fn diagnostic(
    code: &'static str,
    value_index: Option<usize>,
    message: &'static str,
) -> WindowsStartupDiagnostic {
    WindowsStartupDiagnostic {
        code,
        value_index,
        message,
    }
}

fn wide_z(value: impl AsRef<OsStr>) -> Vec<u16> {
    let mut wide = value.as_ref().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    wide
}

fn utf16_hex(units: &[u16]) -> String {
    units.iter().map(|unit| format!("{unit:04x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_registry_text(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn registry_expand_strings_remain_literal_and_keep_raw_utf16_evidence() {
        let source = "%USERPROFILE%\\Tools\\agent.exe\0";
        let data = encode_registry_text(source);
        let (kind, display, raw, malformed) = decode_registry_text(REG_EXPAND_SZ, &data).unwrap();
        assert_eq!(kind, "REG_EXPAND_SZ");
        assert_eq!(display, source.trim_end_matches('\0'));
        assert!(!malformed);
        assert_eq!(raw.len(), source.encode_utf16().count() * 4);
        assert!(raw.starts_with("0025"));
    }

    #[test]
    fn malformed_or_unsupported_registry_data_is_reported_instead_of_guessed() {
        assert!(matches!(
            decode_registry_text(REG_SZ, &[0x41]),
            Err(RegistryDecodeError::OddLength)
        ));
        assert!(matches!(
            decode_registry_text(REG_SZ, &vec![0; MAX_VALUE_DATA_BYTES + 2]),
            Err(RegistryDecodeError::OverLimit)
        ));
        assert!(matches!(
            decode_registry_text(3, &[0, 0]),
            Err(RegistryDecodeError::UnsupportedType)
        ));
        let malformed = decode_registry_text(REG_SZ, &[0x00, 0xd8]).unwrap();
        assert!(malformed.3);
        assert_eq!(malformed.1, "�");
        assert_eq!(malformed.2, "d800");
    }

    #[test]
    fn startup_scope_lists_only_the_curated_sources() {
        assert_eq!(REGISTRY_SOURCES.len(), 8);
        assert_eq!(FOLDER_IDS.len(), 2);
        assert!(
            REGISTRY_SOURCES.iter().all(|source| {
                source.key.ends_with("\\Run") || source.key.ends_with("\\RunOnce")
            })
        );
        assert_eq!(FOLDER_IDS[0].0, "user_startup");
        assert_eq!(FOLDER_IDS[1].0, "common_startup");
    }
}
