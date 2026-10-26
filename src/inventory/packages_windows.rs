//! Bounded Windows software registration inventory from uninstall registry keys.
//!
//! Registry values are retained as inert data. This module never launches an
//! uninstall command, expands environment strings, or queries Win32_Product.

use serde::Serialize;
use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::OsStrExt;
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

const MAX_REGISTRATIONS: usize = 8_192;
const MAX_REGISTRATIONS_PER_SOURCE: usize = MAX_REGISTRATIONS / 4;
const MAX_SUBKEY_NAME_UNITS: usize = 16_384;
const MAX_VALUE_DATA_BYTES: usize = 64 * 1024;
const MAX_AGGREGATE_VALUE_BYTES: usize = 4 * 1024 * 1024;
const MAX_AGGREGATE_NAME_UNITS: usize = 1024 * 1024;
const MAX_SCAN_DURATION_MS: u128 = 10_000;

const REGISTRY_ROOT_CURRENT_USER: isize = -2_147_483_647;
const REGISTRY_ROOT_LOCAL_MACHINE: isize = -2_147_483_646;
const UNINSTALL_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

const SELECTED_VALUES: [&str; 8] = [
    "DisplayName",
    "DisplayVersion",
    "Publisher",
    "InstallLocation",
    "InstallDate",
    "UninstallString",
    "QuietUninstallString",
    "DisplayIcon",
];

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
pub enum WindowsSoftwareStatus {
    Complete,
    Partial,
    NotPresent,
    Inaccessible,
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
pub struct WindowsSoftwareDiagnostic {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_name: Option<&'static str>,
    pub message: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRegistryValue {
    pub name: &'static str,
    pub registry_type: u32,
    pub type_name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Exact returned registry bytes, represented as lowercase hexadecimal.
    pub raw_data_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsSoftwareRegistration {
    pub registry_subkey: String,
    pub registry_subkey_utf16_hex: String,
    pub display_name: Option<String>,
    pub values: Vec<WindowsRegistryValue>,
    pub evidence: WindowsSoftwareEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsSoftwareEvidence {
    pub source: &'static str,
    pub hive: &'static str,
    pub registry_view: WindowsRegistryView,
    pub registry_key: &'static str,
    pub registration_index: usize,
    pub registry_subkey: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsSoftwareSource {
    pub id: &'static str,
    pub status: WindowsSoftwareStatus,
    pub registrations_seen: usize,
    pub hive: &'static str,
    pub registry_key: &'static str,
    pub registry_view: WindowsRegistryView,
    pub diagnostics: Vec<WindowsSoftwareDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsSoftwareInventoryDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub capture_started_at_unix_ms: u128,
    pub capture_ended_at_unix_ms: u128,
    pub status: WindowsSoftwareStatus,
    pub sources: Vec<WindowsSoftwareSource>,
    pub registrations: Vec<WindowsSoftwareRegistration>,
}

#[derive(Clone, Copy)]
struct RegistrySource {
    id: &'static str,
    hive: &'static str,
    root: isize,
    view: WindowsRegistryView,
    view_flag: u32,
}

const REGISTRY_SOURCES: [RegistrySource; 4] = [
    RegistrySource {
        id: "current_user_native_uninstall",
        hive: "HKEY_CURRENT_USER",
        root: REGISTRY_ROOT_CURRENT_USER,
        view: WindowsRegistryView::Native,
        view_flag: 0,
    },
    RegistrySource {
        id: "current_user_32_uninstall",
        hive: "HKEY_CURRENT_USER",
        root: REGISTRY_ROOT_CURRENT_USER,
        view: WindowsRegistryView::Wow64_32,
        view_flag: KEY_WOW64_32KEY,
    },
    RegistrySource {
        id: "local_machine_64_uninstall",
        hive: "HKEY_LOCAL_MACHINE",
        root: REGISTRY_ROOT_LOCAL_MACHINE,
        view: WindowsRegistryView::Wow64_64,
        view_flag: KEY_WOW64_64KEY,
    },
    RegistrySource {
        id: "local_machine_32_uninstall",
        hive: "HKEY_LOCAL_MACHINE",
        root: REGISTRY_ROOT_LOCAL_MACHINE,
        view: WindowsRegistryView::Wow64_32,
        view_flag: KEY_WOW64_32KEY,
    },
];

struct RegistryKey(Handle);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns a valid handle returned by RegOpenKeyExW.
        unsafe { RegCloseKey(self.0) };
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn collect_windows_software() -> WindowsSoftwareInventoryDocument {
    let started_at = now_ms();
    let started = Instant::now();
    let mut sources = Vec::with_capacity(REGISTRY_SOURCES.len());
    let mut registrations = Vec::new();
    let mut aggregate_data_bytes = 0usize;
    let mut aggregate_name_units = 0usize;
    let mut registrations_seen = 0usize;

    for source in REGISTRY_SOURCES {
        let remaining = MAX_REGISTRATIONS.saturating_sub(registrations_seen);
        let (source_document, mut rows, data_bytes, name_units, seen) = collect_source(
            source,
            started,
            MAX_AGGREGATE_VALUE_BYTES.saturating_sub(aggregate_data_bytes),
            MAX_AGGREGATE_NAME_UNITS.saturating_sub(aggregate_name_units),
            remaining.min(MAX_REGISTRATIONS_PER_SOURCE),
        );
        aggregate_data_bytes = aggregate_data_bytes.saturating_add(data_bytes);
        aggregate_name_units = aggregate_name_units.saturating_add(name_units);
        registrations_seen = registrations_seen.saturating_add(seen);
        registrations.append(&mut rows);
        sources.push(source_document);
    }

    let status = if sources.iter().any(|source| {
        !matches!(
            source.status,
            WindowsSoftwareStatus::Complete | WindowsSoftwareStatus::NotPresent
        )
    }) {
        WindowsSoftwareStatus::Partial
    } else {
        WindowsSoftwareStatus::Complete
    };

    WindowsSoftwareInventoryDocument {
        schema: "sideeffect.windows_software_inventory",
        schema_version: 1,
        platform: "windows",
        scope: "current_user_and_accessible_machine_uninstall_registry_entries",
        capture_started_at_unix_ms: started_at,
        capture_ended_at_unix_ms: now_ms(),
        status,
        sources,
        registrations,
    }
}

fn collect_source(
    source: RegistrySource,
    started: Instant,
    aggregate_data_remaining: usize,
    aggregate_names_remaining: usize,
    registration_remaining: usize,
) -> (
    WindowsSoftwareSource,
    Vec<WindowsSoftwareRegistration>,
    usize,
    usize,
    usize,
) {
    if started.elapsed().as_millis() >= MAX_SCAN_DURATION_MS {
        return (
            source_result(
                source,
                WindowsSoftwareStatus::Partial,
                0,
                vec![diagnostic(
                    "scan_deadline_exceeded",
                    None,
                    None,
                    "The software inventory time limit was reached before this registry view was checked.",
                )],
            ),
            Vec::new(),
            0,
            0,
            0,
        );
    }
    let subkey = wide_z(OsStr::new(UNINSTALL_KEY));
    let mut key = null_mut();
    let open_result = unsafe {
        RegOpenKeyExW(
            source.root as Handle,
            subkey.as_ptr(),
            0,
            KEY_READ | source.view_flag,
            &mut key,
        )
    } as u32;
    if open_result != 0 {
        let status = source_open_status(open_result);
        let diagnostics = if status == WindowsSoftwareStatus::NotPresent {
            Vec::new()
        } else {
            vec![diagnostic(
                "uninstall_key_unavailable",
                None,
                None,
                "Windows could not open this uninstall registry view.",
            )]
        };
        return (
            source_result(source, status, 0, diagnostics),
            Vec::new(),
            0,
            0,
            0,
        );
    }
    let key = RegistryKey(key);

    let mut subkey_count = 0u32;
    let mut max_subkey_name = 0u32;
    let query_result = unsafe {
        RegQueryInfoKeyW(
            key.0,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut subkey_count,
            &mut max_subkey_name,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
        )
    } as u32;
    if query_result != 0 {
        return (
            source_result(
                source,
                WindowsSoftwareStatus::Error,
                0,
                vec![diagnostic(
                    "uninstall_key_metadata_failed",
                    None,
                    None,
                    "Windows could not read uninstall registry key metadata.",
                )],
            ),
            Vec::new(),
            0,
            0,
            0,
        );
    }

    let mut status = WindowsSoftwareStatus::Complete;
    let mut diagnostics = Vec::new();
    let max_registrations = registration_remaining.min(subkey_count as usize);
    if subkey_count as usize > registration_remaining {
        status = WindowsSoftwareStatus::Partial;
        diagnostics.push(diagnostic(
            "registration_count_limit_exceeded",
            None,
            None,
            "The global software-registration limit was reached; remaining keys were not checked.",
        ));
    }
    if max_subkey_name as usize > MAX_SUBKEY_NAME_UNITS {
        status = WindowsSoftwareStatus::Partial;
        diagnostics.push(diagnostic(
            "registration_name_limit_exceeded",
            None,
            None,
            "At least one registration subkey name exceeds the supported UTF-16 length.",
        ));
    }
    let name_capacity = (max_subkey_name as usize + 1).min(MAX_SUBKEY_NAME_UNITS + 1);
    let mut rows = Vec::with_capacity(max_registrations.min(512));
    let mut data_bytes = 0usize;
    let mut name_units = 0usize;
    let mut registrations_seen = 0usize;
    for index in 0..max_registrations {
        if started.elapsed().as_millis() >= MAX_SCAN_DURATION_MS {
            status = WindowsSoftwareStatus::Partial;
            diagnostics.push(diagnostic(
                "scan_deadline_exceeded",
                Some(index),
                None,
                "The software inventory time limit was reached; remaining keys were not checked.",
            ));
            break;
        }
        let mut name = vec![0u16; name_capacity.max(1)];
        let mut name_length = name.len() as u32;
        let result = unsafe {
            RegEnumKeyExW(
                key.0,
                index as u32,
                name.as_mut_ptr(),
                &mut name_length,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        } as u32;
        if result == ERROR_NO_MORE_ITEMS {
            break;
        }
        registrations_seen = registrations_seen.saturating_add(1);
        if result != 0 {
            status = WindowsSoftwareStatus::Partial;
            diagnostics.push(diagnostic(
                "registration_key_read_failed",
                Some(index),
                None,
                "Windows could not read a software-registration key name.",
            ));
            continue;
        }
        let name_length = name_length as usize;
        if name_length > MAX_SUBKEY_NAME_UNITS || name_length > name.len() {
            status = WindowsSoftwareStatus::Partial;
            diagnostics.push(diagnostic(
                "registration_name_limit_exceeded",
                Some(index),
                None,
                "A registration subkey name exceeded its bound and was omitted.",
            ));
            continue;
        }
        if name_length > aggregate_names_remaining.saturating_sub(name_units) {
            status = WindowsSoftwareStatus::Partial;
            diagnostics.push(diagnostic(
                "registration_name_budget_exceeded",
                Some(index),
                None,
                "The aggregate registration-name budget was exhausted; this key was omitted.",
            ));
            continue;
        }
        name_units = name_units.saturating_add(name_length);
        let raw_name = &name[..name_length];
        let (display_name, malformed_name) = match String::from_utf16(raw_name) {
            Ok(name) => (name, false),
            Err(_) => {
                status = WindowsSoftwareStatus::Partial;
                diagnostics.push(diagnostic(
                    "registration_name_malformed_utf16",
                    Some(index),
                    None,
                    "A registration key name contained invalid UTF-16; its display is lossy.",
                ));
                (String::from_utf16_lossy(raw_name), true)
            }
        };
        if malformed_name {
            rows.push(WindowsSoftwareRegistration {
                registry_subkey: display_name.clone(),
                registry_subkey_utf16_hex: utf16_hex(raw_name),
                display_name: None,
                values: Vec::new(),
                evidence: WindowsSoftwareEvidence {
                    source: "RegEnumKeyExW/RegQueryValueExW",
                    hive: source.hive,
                    registry_view: source.view,
                    registry_key: UNINSTALL_KEY,
                    registration_index: index,
                    registry_subkey: display_name,
                },
            });
            continue;
        }
        let key_path = format!("{UNINSTALL_KEY}\\{display_name}");
        let mut registration_key = null_mut();
        let key_wide = wide_z(OsStr::new(&key_path));
        let open_result = unsafe {
            RegOpenKeyExW(
                source.root as Handle,
                key_wide.as_ptr(),
                0,
                KEY_READ | source.view_flag,
                &mut registration_key,
            )
        } as u32;
        if open_result != 0 {
            status = WindowsSoftwareStatus::Partial;
            diagnostics.push(diagnostic(
                "registration_disappeared_or_inaccessible",
                Some(index),
                None,
                "Windows could not reopen this registration after enumeration; its values are unknown.",
            ));
            continue;
        }
        let registration_key = RegistryKey(registration_key);
        let (values, value_diagnostics, bytes) = read_values(
            registration_key.0,
            index,
            MAX_VALUE_DATA_BYTES,
            aggregate_data_remaining.saturating_sub(data_bytes),
            started,
        );
        if !value_diagnostics.is_empty() {
            status = WindowsSoftwareStatus::Partial;
            diagnostics.extend(value_diagnostics);
        }
        data_bytes = data_bytes.saturating_add(bytes);
        let display_name_value = values
            .iter()
            .find(|value| value.name == "DisplayName")
            .and_then(|value| value.text.clone())
            .filter(|value| !value.trim().is_empty());
        if display_name_value.is_none() {
            status = WindowsSoftwareStatus::Partial;
            diagnostics.push(diagnostic(
                "registration_display_name_missing",
                Some(index),
                Some("DisplayName"),
                "This uninstall key has no usable DisplayName value; the registration may not identify an application.",
            ));
        }
        rows.push(WindowsSoftwareRegistration {
            registry_subkey: display_name.clone(),
            registry_subkey_utf16_hex: utf16_hex(raw_name),
            display_name: display_name_value,
            values,
            evidence: WindowsSoftwareEvidence {
                source: "RegEnumKeyExW/RegQueryValueExW",
                hive: source.hive,
                registry_view: source.view,
                registry_key: UNINSTALL_KEY,
                registration_index: index,
                registry_subkey: display_name,
            },
        });
    }
    (
        source_result(source, status, registrations_seen, diagnostics),
        rows,
        data_bytes,
        name_units,
        registrations_seen,
    )
}

fn read_values(
    key: Handle,
    registration_index: usize,
    per_value_limit: usize,
    aggregate_remaining: usize,
    started: Instant,
) -> (
    Vec<WindowsRegistryValue>,
    Vec<WindowsSoftwareDiagnostic>,
    usize,
) {
    let mut values = Vec::new();
    let mut diagnostics = Vec::new();
    let mut bytes_read = 0usize;
    for name in SELECTED_VALUES {
        if started.elapsed().as_millis() >= MAX_SCAN_DURATION_MS {
            diagnostics.push(diagnostic(
                "scan_deadline_exceeded",
                Some(registration_index),
                None,
                "The software inventory time limit was reached while reading this registration.",
            ));
            break;
        }
        let wide_name = wide_z(OsStr::new(name));
        let mut value_type = 0u32;
        let mut size = 0u32;
        let query = unsafe {
            RegQueryValueExW(
                key,
                wide_name.as_ptr(),
                null_mut(),
                &mut value_type,
                null_mut(),
                &mut size,
            )
        } as u32;
        if query == ERROR_FILE_NOT_FOUND {
            continue;
        }
        if query != 0 && query != ERROR_MORE_DATA {
            diagnostics.push(diagnostic(
                "registration_value_query_failed",
                Some(registration_index),
                Some(name),
                "Windows could not query a selected registration value.",
            ));
            continue;
        }
        let size = size as usize;
        let remaining = aggregate_remaining.saturating_sub(bytes_read);
        if size > per_value_limit || size > remaining {
            diagnostics.push(diagnostic(
                "registration_value_data_limit_exceeded",
                Some(registration_index),
                Some(name),
                "A selected registry value exceeded the per-value or aggregate data limit and was omitted.",
            ));
            continue;
        }
        let mut data = vec![0u8; size];
        let mut actual_size = data.len() as u32;
        let result = unsafe {
            RegQueryValueExW(
                key,
                wide_name.as_ptr(),
                null_mut(),
                &mut value_type,
                if data.is_empty() {
                    null_mut()
                } else {
                    data.as_mut_ptr()
                },
                &mut actual_size,
            )
        } as u32;
        if result != 0 {
            diagnostics.push(diagnostic(
                if result == ERROR_MORE_DATA {
                    "registration_value_changed_or_over_limit"
                } else {
                    "registration_value_read_failed"
                },
                Some(registration_index),
                Some(name),
                "Windows could not read a selected registry value within its measured size.",
            ));
            continue;
        }
        let actual_size = actual_size as usize;
        if actual_size > data.len() {
            diagnostics.push(diagnostic(
                "registration_value_read_failed",
                Some(registration_index),
                Some(name),
                "Windows reported a value length beyond the supplied buffer.",
            ));
            continue;
        }
        data.truncate(actual_size);
        bytes_read = bytes_read.saturating_add(actual_size);
        let (type_name, text) = decode_value_text(value_type, &data);
        if type_name == "unsupported" {
            diagnostics.push(diagnostic(
                "registration_value_type_unsupported",
                Some(registration_index),
                Some(name),
                "A selected registration value had a non-string type; exact bytes were retained without interpretation.",
            ));
        } else if matches!(value_type, REG_SZ | REG_EXPAND_SZ) && data.len() % 2 != 0 {
            diagnostics.push(diagnostic(
                "registration_value_malformed_length",
                Some(registration_index),
                Some(name),
                "A selected string registry value had an odd byte length; exact bytes were retained without a display string.",
            ));
        } else if text.is_none() && matches!(value_type, REG_SZ | REG_EXPAND_SZ) {
            diagnostics.push(diagnostic(
                "registration_value_malformed_utf16",
                Some(registration_index),
                Some(name),
                "A selected string registry value contained invalid UTF-16; exact bytes were retained without a display string.",
            ));
        }
        values.push(WindowsRegistryValue {
            name,
            registry_type: value_type,
            type_name,
            text,
            raw_data_hex: bytes_hex(&data),
        });
    }
    (values, diagnostics, bytes_read)
}

fn decode_value_text(value_type: u32, data: &[u8]) -> (&'static str, Option<String>) {
    let type_name = match value_type {
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        _ => return ("unsupported", None),
    };
    if data.len() % 2 != 0 {
        return (type_name, None);
    }
    let units = data
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    let end = units
        .iter()
        .rposition(|unit| *unit != 0)
        .map_or(0, |index| index + 1);
    (type_name, String::from_utf16(&units[..end]).ok())
}

fn source_result(
    source: RegistrySource,
    status: WindowsSoftwareStatus,
    registrations_seen: usize,
    diagnostics: Vec<WindowsSoftwareDiagnostic>,
) -> WindowsSoftwareSource {
    WindowsSoftwareSource {
        id: source.id,
        status,
        registrations_seen,
        hive: source.hive,
        registry_key: UNINSTALL_KEY,
        registry_view: source.view,
        diagnostics,
    }
}

fn source_open_status(error: u32) -> WindowsSoftwareStatus {
    match error {
        ERROR_FILE_NOT_FOUND => WindowsSoftwareStatus::NotPresent,
        ERROR_ACCESS_DENIED => WindowsSoftwareStatus::Inaccessible,
        _ => WindowsSoftwareStatus::Error,
    }
}

fn diagnostic(
    code: &'static str,
    registration_index: Option<usize>,
    value_name: Option<&'static str>,
    message: &'static str,
) -> WindowsSoftwareDiagnostic {
    WindowsSoftwareDiagnostic {
        code,
        registration_index,
        value_name,
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

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_bytes(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn decodes_string_and_expand_string_literally_without_expansion() {
        for value_type in [REG_SZ, REG_EXPAND_SZ] {
            let bytes = utf16_bytes("%USERPROFILE%\\Apps\\tool.exe\0");
            let (kind, text) = decode_value_text(value_type, &bytes);
            assert_eq!(
                kind,
                if value_type == REG_SZ {
                    "REG_SZ"
                } else {
                    "REG_EXPAND_SZ"
                }
            );
            assert_eq!(text.as_deref(), Some("%USERPROFILE%\\Apps\\tool.exe"));
        }
    }

    #[test]
    fn malformed_and_non_string_values_are_not_guessed() {
        assert_eq!(decode_value_text(REG_SZ, &[0x41]), ("REG_SZ", None));
        assert_eq!(decode_value_text(REG_SZ, &[0x00, 0xd8]), ("REG_SZ", None));
        assert_eq!(decode_value_text(4, &[1, 2, 3, 4]), ("unsupported", None));
        assert_eq!(bytes_hex(&[0, 255]), "00ff");
        assert_eq!(utf16_hex(&[0xd800]), "d800");
    }

    #[test]
    fn bounds_and_sources_are_fixed_and_explicit() {
        assert_eq!(REGISTRY_SOURCES.len(), 4);
        assert_eq!(
            MAX_REGISTRATIONS_PER_SOURCE * REGISTRY_SOURCES.len(),
            MAX_REGISTRATIONS
        );
        assert!(SELECTED_VALUES.contains(&"UninstallString"));
        assert!(SELECTED_VALUES.contains(&"QuietUninstallString"));
        assert!(
            REGISTRY_SOURCES
                .iter()
                .all(|source| source.id.contains("uninstall"))
        );
    }

    #[test]
    fn inaccessible_and_missing_views_remain_distinct() {
        assert_eq!(
            source_open_status(ERROR_ACCESS_DENIED),
            WindowsSoftwareStatus::Inaccessible
        );
        assert_eq!(
            source_open_status(ERROR_FILE_NOT_FOUND),
            WindowsSoftwareStatus::NotPresent
        );
        assert_eq!(source_open_status(1234), WindowsSoftwareStatus::Error);
    }
}
