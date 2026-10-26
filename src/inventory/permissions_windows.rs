//! Bounded, selected-path Windows security descriptor inventory.
//!
//! The collector opens only caller-supplied paths, does not follow the final
//! reparse point, requests no SACL, and never computes effective access.

use crate::fingerprint::sha256_hex;
use serde::Serialize;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const GENERIC_READ_CONTROL: u32 = 0x0002_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_SHARE_ALL: u32 = 0x0000_0007;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_TYPE_DISK: u32 = 1;
const INVALID_HANDLE_VALUE: isize = -1;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const SE_FILE_OBJECT: u32 = 1;
const OWNER_SECURITY_INFORMATION: u32 = 0x1;
const GROUP_SECURITY_INFORMATION: u32 = 0x2;
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const MAX_PATHS: usize = 256;
const MAX_PATH_UNITS: usize = 32_767;
const MAX_TOTAL_PATH_UNITS: usize = 1_048_576;
const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;
const MAX_ACES: usize = 1024;
const MAX_AGGREGATE_DESCRIPTOR_BYTES: usize = 8 * 1024 * 1024;
const MAX_SCAN_MS: u128 = 5_000;

type Handle = *mut c_void;

#[repr(C)]
#[derive(Default)]
struct ByHandleFileInformation {
    attributes: u32,
    creation_time: [u32; 2],
    last_access_time: [u32; 2],
    last_write_time: [u32; 2],
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *const c_void,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn GetFileInformationByHandle(handle: Handle, info: *mut ByHandleFileInformation) -> i32;
    fn GetFileType(handle: Handle) -> u32;
    fn GetLastError() -> u32;
    fn LocalFree(memory: Handle) -> Handle;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetSecurityInfo(
        handle: Handle,
        object_type: u32,
        information: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn GetSecurityDescriptorLength(descriptor: *const c_void) -> u32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPermissionStatus {
    Complete,
    Partial,
    Inaccessible,
    NotPresent,
    LimitReached,
    Error,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsPermissionDiagnostic {
    pub code: &'static str,
    pub path_index: Option<usize>,
    pub message: &'static str,
    pub win32_error: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsPermissionInventoryDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub capture_started_at_unix_ms: u128,
    pub capture_ended_at_unix_ms: u128,
    pub status: WindowsPermissionStatus,
    pub objects: Vec<WindowsPermissionObject>,
    pub diagnostics: Vec<WindowsPermissionDiagnostic>,
    pub limits: WindowsPermissionLimits,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsPermissionLimits {
    pub max_paths: usize,
    pub max_utf16_units_per_path: usize,
    pub max_total_path_utf16_units: usize,
    pub max_descriptor_bytes: usize,
    pub max_aces_per_descriptor: usize,
    pub max_aggregate_descriptor_bytes: usize,
    pub deadline_ms_between_paths: u128,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsPermissionObject {
    pub path: Option<String>,
    pub path_utf16_hex: String,
    pub status: WindowsPermissionStatus,
    pub metadata: Option<WindowsPermissionMetadata>,
    pub security: Option<WindowsSecurityDescriptorEvidence>,
    pub diagnostic: Option<WindowsPermissionDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsPermissionMetadata {
    pub attributes: u32,
    pub is_directory: bool,
    pub is_reparse_point: bool,
    pub volume_serial_number: u32,
    pub file_index: u64,
    pub size_bytes: u64,
    pub last_write_filetime: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsSecurityDescriptorEvidence {
    pub descriptor_length: usize,
    pub descriptor_sha256: String,
    pub descriptor_raw_hex: String,
    pub control: u16,
    pub owner_sid_raw_hex: Option<String>,
    pub group_sid_raw_hex: Option<String>,
    pub dacl_state: &'static str,
    pub dacl_protected: bool,
    pub dacl_auto_inherited: bool,
    pub aces: Vec<WindowsAceEvidence>,
    pub parse_diagnostic: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsAceEvidence {
    pub index: usize,
    pub ace_type: u8,
    pub type_name: &'static str,
    pub flags: u8,
    pub inherited: bool,
    pub inherit_only: bool,
    pub ace_size: usize,
    pub access_mask: Option<u32>,
    pub trustee_sid_raw_hex: Option<String>,
    pub raw_hex: String,
    pub recognized: bool,
}

struct OwnedHandle(Handle);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CloseHandle(handle: Handle) -> i32;
}

struct OwnedDescriptor(Handle);
impl Drop for OwnedDescriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

pub fn collect_windows_permissions(paths: &[PathBuf]) -> WindowsPermissionInventoryDocument {
    let started = unix_ms();
    let timer = Instant::now();
    let mut objects = Vec::new();
    let mut diagnostics = Vec::new();
    let mut status = WindowsPermissionStatus::Complete;
    let mut aggregate_path_units = 0usize;
    let mut aggregate_descriptor_bytes = 0usize;
    for (index, path) in paths.iter().enumerate() {
        if index >= MAX_PATHS || timer.elapsed().as_millis() >= MAX_SCAN_MS {
            status = WindowsPermissionStatus::LimitReached;
            diagnostics.push(diag(
                "limit_reached",
                None,
                "Path count or between-path deadline limit reached.",
                None,
            ));
            break;
        }
        let wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        aggregate_path_units = aggregate_path_units.saturating_add(wide.len());
        if wide.is_empty()
            || wide.contains(&0)
            || wide.len() > MAX_PATH_UNITS
            || aggregate_path_units > MAX_TOTAL_PATH_UNITS
        {
            let (code, message) = if wide.contains(&0) {
                (
                    "path_contains_nul",
                    "Path contains a NUL code unit and cannot be passed to a Windows path API safely.",
                )
            } else {
                (
                    "path_limit",
                    "Path is empty or exceeds a configured UTF-16 path limit.",
                )
            };
            let object = failed_object(
                &wide,
                index,
                if wide.contains(&0) {
                    WindowsPermissionStatus::Partial
                } else {
                    WindowsPermissionStatus::LimitReached
                },
                code,
                message,
                None,
            );
            objects.push(object.0);
            diagnostics.push(object.1);
            status = WindowsPermissionStatus::Partial;
            continue;
        }
        match collect_one(&wide, index, &mut aggregate_descriptor_bytes) {
            Ok(object) => {
                if object.status != WindowsPermissionStatus::Complete {
                    status = WindowsPermissionStatus::Partial;
                    if let Some(diagnostic) = &object.diagnostic {
                        diagnostics.push(diagnostic.clone());
                    }
                }
                objects.push(object);
            }
            Err((item_status, diagnostic)) => {
                objects.push(WindowsPermissionObject {
                    path: Some(String::from_utf16_lossy(&wide)),
                    path_utf16_hex: u16_hex(&wide),
                    status: item_status,
                    metadata: None,
                    security: None,
                    diagnostic: Some(diagnostic.clone()),
                });
                diagnostics.push(diagnostic);
                if status == WindowsPermissionStatus::Complete {
                    status = item_status;
                } else if status != WindowsPermissionStatus::LimitReached {
                    status = WindowsPermissionStatus::Partial;
                }
            }
        }
    }
    if paths.len() > MAX_PATHS && status == WindowsPermissionStatus::Complete {
        status = WindowsPermissionStatus::LimitReached;
        diagnostics.push(diag(
            "path_count_limit",
            None,
            "Only the first 256 explicitly supplied paths were considered.",
            None,
        ));
    }
    WindowsPermissionInventoryDocument {
        schema: "sideeffect.windows_permission_inventory",
        schema_version: 1,
        platform: "windows",
        scope: "explicit_paths_only; final_reparse_points_opened_without_following; no_sacl; no_effective_access_calculation",
        capture_started_at_unix_ms: started,
        capture_ended_at_unix_ms: unix_ms(),
        status,
        objects,
        diagnostics,
        limits: WindowsPermissionLimits {
            max_paths: MAX_PATHS,
            max_utf16_units_per_path: MAX_PATH_UNITS,
            max_total_path_utf16_units: MAX_TOTAL_PATH_UNITS,
            max_descriptor_bytes: MAX_DESCRIPTOR_BYTES,
            max_aces_per_descriptor: MAX_ACES,
            max_aggregate_descriptor_bytes: MAX_AGGREGATE_DESCRIPTOR_BYTES,
            deadline_ms_between_paths: MAX_SCAN_MS,
        },
    }
}

fn collect_one(
    wide: &[u16],
    index: usize,
    aggregate: &mut usize,
) -> Result<WindowsPermissionObject, (WindowsPermissionStatus, WindowsPermissionDiagnostic)> {
    let mut terminated = wide.to_vec();
    terminated.push(0);
    let raw = unsafe {
        CreateFileW(
            terminated.as_ptr(),
            GENERIC_READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_ALL,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if raw as isize == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        let state = if error == ERROR_ACCESS_DENIED {
            WindowsPermissionStatus::Inaccessible
        } else if error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND {
            WindowsPermissionStatus::NotPresent
        } else {
            WindowsPermissionStatus::Error
        };
        return Err((
            state,
            diag(
                "open_failed",
                Some(index),
                "Could not open the selected path with read-control and file-attribute access.",
                Some(error),
            ),
        ));
    }
    let handle = OwnedHandle(raw);
    let mut info = ByHandleFileInformation::default();
    if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0 {
        let error = unsafe { GetLastError() };
        return Err((
            WindowsPermissionStatus::Error,
            diag(
                "metadata_failed",
                Some(index),
                "Could not read metadata from the opened path handle.",
                Some(error),
            ),
        ));
    }
    let metadata = WindowsPermissionMetadata {
        attributes: info.attributes,
        is_directory: info.attributes & 0x10 != 0,
        is_reparse_point: info.attributes & 0x400 != 0,
        volume_serial_number: info.volume_serial_number,
        file_index: (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low),
        size_bytes: (u64::from(info.file_size_high) << 32) | u64::from(info.file_size_low),
        last_write_filetime: (u64::from(info.last_write_time[1]) << 32)
            | u64::from(info.last_write_time[0]),
    };
    if unsafe { GetFileType(handle.0) } != FILE_TYPE_DISK {
        return Err((
            WindowsPermissionStatus::Partial,
            diag(
                "unsupported_object_type",
                Some(index),
                "The selected path did not resolve to a disk file or directory.",
                None,
            ),
        ));
    }
    let mut descriptor = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 || descriptor.is_null() {
        return Err((
            if result == ERROR_ACCESS_DENIED {
                WindowsPermissionStatus::Inaccessible
            } else {
                WindowsPermissionStatus::Error
            },
            diag(
                "security_descriptor_failed",
                Some(index),
                "Could not read owner, group, and DACL from the opened path handle; no SACL was requested.",
                Some(result),
            ),
        ));
    }
    let descriptor = OwnedDescriptor(descriptor);
    let length = unsafe { GetSecurityDescriptorLength(descriptor.0.cast_const()) } as usize;
    if !(20..=MAX_DESCRIPTOR_BYTES).contains(&length)
        || aggregate.saturating_add(length) > MAX_AGGREGATE_DESCRIPTOR_BYTES
    {
        return Err((
            WindowsPermissionStatus::LimitReached,
            diag(
                "descriptor_limit",
                Some(index),
                "Security descriptor size exceeds a configured per-object or aggregate bound.",
                None,
            ),
        ));
    }
    *aggregate += length;
    let bytes = unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), length) };
    let (security, parse_diagnostic) = match parse_descriptor(bytes) {
        Ok(security) => (security, None),
        Err(code) => (
            WindowsSecurityDescriptorEvidence {
                descriptor_length: bytes.len(),
                descriptor_sha256: sha256_hex(bytes),
                descriptor_raw_hex: hex(bytes),
                control: le16(bytes, 2).unwrap_or_default(),
                owner_sid_raw_hex: None,
                group_sid_raw_hex: None,
                dacl_state: "malformed_or_unsupported",
                dacl_protected: false,
                dacl_auto_inherited: false,
                aces: Vec::new(),
                parse_diagnostic: Some(code),
            },
            Some(code),
        ),
    };
    let unsupported_ace = security.aces.iter().any(|ace| !ace.recognized);
    let partial_code = parse_diagnostic.or(unsupported_ace.then_some("unsupported_ace_type"));
    Ok(WindowsPermissionObject {
        path: Some(String::from_utf16_lossy(wide)),
        path_utf16_hex: u16_hex(wide),
        status: if partial_code.is_some() { WindowsPermissionStatus::Partial } else { WindowsPermissionStatus::Complete },
        metadata: Some(metadata),
        security: Some(security),
        diagnostic: partial_code.map(|code| diag(code, Some(index), "Raw security descriptor evidence is retained; one or more descriptor or ACE fields could not be safely decoded.", None)),
    })
}

fn parse_descriptor(bytes: &[u8]) -> Result<WindowsSecurityDescriptorEvidence, &'static str> {
    if bytes.len() < 20 || bytes[0] != 1 {
        return Err("malformed_descriptor_header");
    }
    let control = le16(bytes, 2).ok_or("malformed_descriptor_header")?;
    if control & 0x8000 == 0 {
        return Err("unsupported_absolute_descriptor");
    }
    let owner = le32(bytes, 4).ok_or("malformed_descriptor_header")? as usize;
    let group = le32(bytes, 8).ok_or("malformed_descriptor_header")? as usize;
    let dacl_offset = le32(bytes, 16).ok_or("malformed_descriptor_header")? as usize;
    let dacl_present = control & 0x0004 != 0;
    let owner_sid_raw_hex = if owner == 0 {
        None
    } else {
        Some(sid_at(bytes, owner)?.to_owned())
    };
    let group_sid_raw_hex = if group == 0 {
        None
    } else {
        Some(sid_at(bytes, group)?.to_owned())
    };
    let (dacl_state, aces) = if !dacl_present {
        ("absent", Vec::new())
    } else if dacl_offset == 0 {
        ("null", Vec::new())
    } else {
        let aces = parse_acl(bytes, dacl_offset)?;
        (if aces.is_empty() { "empty" } else { "present" }, aces)
    };
    Ok(WindowsSecurityDescriptorEvidence {
        descriptor_length: bytes.len(),
        descriptor_sha256: sha256_hex(bytes),
        descriptor_raw_hex: hex(bytes),
        control,
        owner_sid_raw_hex,
        group_sid_raw_hex,
        dacl_state,
        dacl_protected: control & 0x1000 != 0,
        dacl_auto_inherited: control & 0x0400 != 0,
        aces,
        parse_diagnostic: None,
    })
}

fn parse_acl(bytes: &[u8], offset: usize) -> Result<Vec<WindowsAceEvidence>, &'static str> {
    if offset < 20 || offset.checked_add(8).is_none_or(|end| end > bytes.len()) {
        return Err("malformed_acl_offset");
    }
    if !matches!(bytes[offset], 2 | 4) {
        return Err("unsupported_acl_revision");
    }
    let size = le16(bytes, offset + 2).ok_or("malformed_acl_header")? as usize;
    let count = le16(bytes, offset + 4).ok_or("malformed_acl_header")? as usize;
    let end = offset.checked_add(size).ok_or("malformed_acl_size")?;
    if size < 8 || end > bytes.len() {
        return Err("malformed_acl_size");
    }
    if count > MAX_ACES {
        return Err("ace_count_limit");
    }
    let mut cursor = offset + 8;
    let mut aces = Vec::with_capacity(count);
    for index in 0..count {
        if cursor.checked_add(4).is_none_or(|next| next > end) {
            return Err("truncated_ace_header");
        }
        let ace_type = bytes[cursor];
        let flags = bytes[cursor + 1];
        let ace_size = le16(bytes, cursor + 2).ok_or("truncated_ace_header")? as usize;
        let ace_end = cursor.checked_add(ace_size).ok_or("malformed_ace_size")?;
        if ace_size < 4 || ace_size % 4 != 0 || ace_end > end {
            return Err("malformed_ace_size");
        }
        let (access_mask, trustee_sid_raw_hex, recognized) = if matches!(ace_type, 0..=2) {
            let mask = le32(bytes, cursor + 4).ok_or("malformed_basic_ace")?;
            let sid = sid_at(&bytes[cursor..ace_end], 8)?.to_owned();
            (Some(mask), Some(sid), true)
        } else {
            (None, None, false)
        };
        aces.push(WindowsAceEvidence {
            index,
            ace_type,
            type_name: ace_name(ace_type),
            flags,
            inherited: flags & 0x10 != 0,
            inherit_only: flags & 0x08 != 0,
            ace_size,
            access_mask,
            trustee_sid_raw_hex,
            raw_hex: hex(&bytes[cursor..ace_end]),
            recognized,
        });
        cursor = ace_end;
    }
    if cursor > end {
        return Err("malformed_acl_trailing_data");
    }
    Ok(aces)
}

fn sid_at(bytes: &[u8], offset: usize) -> Result<String, &'static str> {
    if offset.checked_add(8).is_none_or(|end| end > bytes.len()) {
        return Err("malformed_sid_offset");
    }
    let subauth = bytes[offset + 1] as usize;
    let length = 8usize
        .checked_add(subauth.checked_mul(4).ok_or("malformed_sid_length")?)
        .ok_or("malformed_sid_length")?;
    let end = offset.checked_add(length).ok_or("malformed_sid_length")?;
    if bytes[offset] != 1 || end > bytes.len() {
        return Err("malformed_sid");
    }
    Ok(hex(&bytes[offset..end]))
}

fn ace_name(kind: u8) -> &'static str {
    match kind {
        0 => "access_allowed",
        1 => "access_denied",
        2 => "system_audit",
        5 => "access_allowed_object",
        6 => "access_denied_object",
        7 => "system_audit_object",
        9 => "access_allowed_callback",
        10 => "access_denied_callback",
        11 => "access_allowed_callback_object",
        12 => "access_denied_callback_object",
        17 => "mandatory_label",
        _ => "unknown",
    }
}
fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}
fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}
fn u16_hex(units: &[u16]) -> String {
    let mut bytes = Vec::with_capacity(units.len() * 2);
    for unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    hex(&bytes)
}
fn diag(
    code: &'static str,
    path_index: Option<usize>,
    message: &'static str,
    win32_error: Option<u32>,
) -> WindowsPermissionDiagnostic {
    WindowsPermissionDiagnostic {
        code,
        path_index,
        message,
        win32_error,
    }
}
fn failed_object(
    wide: &[u16],
    index: usize,
    status: WindowsPermissionStatus,
    code: &'static str,
    message: &'static str,
    win32_error: Option<u32>,
) -> (WindowsPermissionObject, WindowsPermissionDiagnostic) {
    let diagnostic = diag(code, Some(index), message, win32_error);
    (
        WindowsPermissionObject {
            path: Some(String::from_utf16_lossy(wide)),
            path_utf16_hex: u16_hex(wide),
            status,
            metadata: None,
            security: None,
            diagnostic: Some(diagnostic.clone()),
        },
        diagnostic,
    )
}
fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStringExt;

    fn fixture(control: u16, dacl_offset: u32, acl: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 20];
        bytes[0] = 1;
        bytes[2..4].copy_from_slice(&control.to_le_bytes());
        bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
        if !acl.is_empty() {
            bytes.extend_from_slice(acl);
        }
        bytes
    }
    fn acl(aces: &[u8], count: u16) -> Vec<u8> {
        let mut a = vec![2, 0, 0, 0, 0, 0, 0, 0];
        let size = 8 + aces.len();
        a[2..4].copy_from_slice(&(size as u16).to_le_bytes());
        a[4..6].copy_from_slice(&count.to_le_bytes());
        a.extend_from_slice(aces);
        a
    }
    fn basic_ace(kind: u8, flags: u8, mask: u32) -> Vec<u8> {
        let mut a = vec![kind, flags, 20, 0];
        a.extend_from_slice(&mask.to_le_bytes());
        a.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]);
        a
    }

    #[test]
    fn preserves_ace_order_and_inherited_flags_and_raw_bytes() {
        let mut body = basic_ace(0, 0x10, 0x0012_0089);
        body.extend(basic_ace(1, 0x08, 0x1));
        let bytes = fixture(0x8004 | 0x1000, 20, &acl(&body, 2));
        let parsed = parse_descriptor(&bytes).unwrap();
        assert_eq!(parsed.aces.len(), 2);
        assert_eq!(parsed.aces[0].index, 0);
        assert!(parsed.aces[0].inherited);
        assert!(parsed.aces[1].inherit_only);
        assert_eq!(parsed.aces[1].ace_type, 1);
        assert_eq!(parsed.dacl_state, "present");
        assert!(parsed.dacl_protected);
        assert!(!parsed.aces[0].raw_hex.is_empty());
    }

    #[test]
    fn distinguishes_absent_null_and_empty_dacl() {
        assert_eq!(
            parse_descriptor(&fixture(0x8000, 0, &[]))
                .unwrap()
                .dacl_state,
            "absent"
        );
        assert_eq!(
            parse_descriptor(&fixture(0x8004, 0, &[]))
                .unwrap()
                .dacl_state,
            "null"
        );
        assert_eq!(
            parse_descriptor(&fixture(0x8004, 20, &acl(&[], 0)))
                .unwrap()
                .dacl_state,
            "empty"
        );
    }

    #[test]
    fn malformed_and_unknown_aces_are_not_guessed() {
        let unknown = vec![0xfe, 0, 8, 0, 1, 2, 3, 4];
        let parsed = parse_descriptor(&fixture(0x8004, 20, &acl(&unknown, 1))).unwrap();
        assert!(!parsed.aces[0].recognized);
        assert_eq!(parsed.aces[0].raw_hex, "fe00080001020304");
        let bad = fixture(0x8004, 0xffff_fff0, &[]);
        assert_eq!(parse_descriptor(&bad).unwrap_err(), "malformed_acl_offset");
        let malformed = fixture(0x8004, 20, &acl(&[0, 0, 3, 0], 1));
        assert_eq!(
            parse_descriptor(&malformed).unwrap_err(),
            "malformed_ace_size"
        );
    }

    #[test]
    fn rejects_embedded_nul_before_calling_windows_path_apis() {
        let path = PathBuf::from(std::ffi::OsString::from_wide(&[
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            b'x' as u16,
            0,
            b'y' as u16,
        ]));
        let document = collect_windows_permissions(&[path]);
        assert_eq!(document.status, WindowsPermissionStatus::Partial);
        assert_eq!(document.objects[0].status, WindowsPermissionStatus::Partial);
        assert_eq!(
            document.objects[0].diagnostic.as_ref().unwrap().code,
            "path_contains_nul"
        );
        assert!(document.objects[0].metadata.is_none());
    }
}
