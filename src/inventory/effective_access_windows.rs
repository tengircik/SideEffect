//! Bounded, experimental Windows DACL evaluation for one process token and one
//! selected file-system object.
//!
//! This is deliberately not an effective path-access verdict. It reports the
//! Authz DACL result for the selected process token and the selected final
//! object, then keeps the overall conclusion conditional because ancestor
//! traversal, reparse resolution, mandatory integrity labels, central access
//! policy, remote share policy, and other controls are not evaluated here.

use crate::fingerprint::sha256_hex;
use serde::Serialize;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    AUTHZ_ACCESS_REPLY, AUTHZ_ACCESS_REQUEST, AUTHZ_CLIENT_CONTEXT_HANDLE,
    AUTHZ_RESOURCE_MANAGER_HANDLE, AUTHZ_RM_FLAG_NO_AUDIT, AuthzAccessCheck, AuthzFreeContext,
    AuthzFreeResourceManager, AuthzInitializeContextFromToken, AuthzInitializeResourceManager,
    GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
    IsValidSecurityDescriptor, OWNER_SECURITY_INFORMATION, TOKEN_QUERY, TokenIsAppContainer,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

const MAX_PATH_UTF16_UNITS: usize = 32_767;
const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_DATA: u32 = 13;
const ERROR_INVALID_DRIVE: u32 = 15;
const DRIVE_REMOTE: u32 = 4;
const READ_CONTROL: u32 = 0x0002_0000;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_EXECUTE: u32 = 0x0020;

/// A narrowly defined requested operation. These map to file-object DACL bits;
/// they do not simulate opening, writing, or executing the object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAccessOperation {
    ReadData,
    WriteData,
    Execute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAccessConclusion {
    Conditional,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDaclDecision {
    GrantedByDacl,
    DeniedByDacl,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAccessStatus {
    Evaluated,
    Conditional,
    Inaccessible,
    Unsupported,
    IdentityChanged,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAccessControlStatus {
    Evaluated,
    NotEvaluated,
    Unsupported,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsAccessControlEvidence {
    pub control: &'static str,
    pub status: WindowsAccessControlStatus,
    pub detail: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsDaclEvaluationResult {
    pub schema: &'static str,
    pub schema_version: u32,
    pub status: WindowsAccessStatus,
    /// Always `conditional` for this DACL-only implementation; it never emits
    /// a definitive effective-access allow or deny.
    pub conclusion: WindowsAccessConclusion,
    pub process_id: u32,
    pub expected_creation_time_filetime_100ns: u64,
    pub observed_creation_time_filetime_100ns: Option<u64>,
    pub path: Option<String>,
    pub path_utf16_hex: String,
    pub operation: &'static str,
    pub requested_access_mask: Option<u32>,
    pub granted_access_mask: Option<u32>,
    pub dacl_decision: WindowsDaclDecision,
    pub object_volume_serial_number: Option<u32>,
    pub object_file_index: Option<u64>,
    /// Length and digest refer to the exact bounded self-relative descriptor
    /// returned by `GetSecurityInfo`; they establish byte identity only.
    pub security_descriptor_length: Option<usize>,
    pub security_descriptor_sha256: Option<String>,
    pub controls: Vec<WindowsAccessControlEvidence>,
    pub diagnostic_code: Option<&'static str>,
    pub win32_error: Option<u32>,
}

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct OwnedSecurityDescriptor(*mut core::ffi::c_void);
impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

struct OwnedResourceManager(AUTHZ_RESOURCE_MANAGER_HANDLE);
impl Drop for OwnedResourceManager {
    fn drop(&mut self) {
        unsafe { AuthzFreeResourceManager(self.0) };
    }
}

struct OwnedAuthzContext(AUTHZ_CLIENT_CONTEXT_HANDLE);
impl Drop for OwnedAuthzContext {
    fn drop(&mut self) {
        unsafe { AuthzFreeContext(self.0) };
    }
}

/// Evaluate the selected file object's DACL against the selected live process
/// token. PID reuse is rejected by requiring the caller's observed creation
/// FILETIME. The API does not elevate, impersonate, enable privileges, mutate
/// the file, follow the final reparse point, or make a definitive path verdict.
pub fn evaluate_windows_dacl_for_process(
    process_id: u32,
    expected_creation_time_filetime_100ns: u64,
    path: &Path,
    operation: WindowsAccessOperation,
) -> WindowsDaclEvaluationResult {
    let operation_name = operation.name();
    let requested_access = operation.access_mask();
    let mut result = empty_result(
        process_id,
        expected_creation_time_filetime_100ns,
        path,
        operation_name,
        requested_access,
    );

    if process_id == 0 || expected_creation_time_filetime_100ns == 0 {
        result.diagnostic_code = Some("invalid_process_identity");
        return result;
    }
    let wide_path = match bounded_path(path) {
        Ok(value) => value,
        Err(code) => {
            result.status = WindowsAccessStatus::Unsupported;
            result.diagnostic_code = Some(code);
            return result;
        }
    };
    if is_network_or_device_path(&wide_path) {
        result.status = WindowsAccessStatus::Unsupported;
        result.diagnostic_code = Some("network_or_device_path_not_supported");
        set_control(
            &mut result,
            control(
                "remote_share_and_server_policy",
                WindowsAccessControlStatus::Unsupported,
                "UNC and device namespace paths are rejected before opening or querying the selected object.",
            ),
        );
        return result;
    }
    match volume_is_remote(&wide_path) {
        Ok(true) => {
            result.status = WindowsAccessStatus::Unsupported;
            result.diagnostic_code = Some("remote_filesystem_not_supported");
            set_control(
                &mut result,
                control(
                    "remote_share_and_server_policy",
                    WindowsAccessControlStatus::Unsupported,
                    "Mapped remote drives and UNC shares are outside this selected-object DACL check.",
                ),
            );
            return result;
        }
        Ok(false) => {}
        Err(error) => return fail(result, "volume_type_unavailable", error),
    }

    let process = match open_process(process_id) {
        Ok(value) => value,
        Err(error) => return fail(result, "process_open_failed", error),
    };
    let observed_creation = match process_creation_time(process.0) {
        Ok(value) => value,
        Err(error) => return fail(result, "process_creation_time_unavailable", error),
    };
    result.observed_creation_time_filetime_100ns = Some(observed_creation);
    if observed_creation != expected_creation_time_filetime_100ns {
        result.status = WindowsAccessStatus::IdentityChanged;
        result.diagnostic_code = Some("process_identity_changed");
        set_control(
            &mut result,
            control(
                "process_primary_token",
                WindowsAccessControlStatus::Unknown,
                "The PID now refers to a process with a different creation FILETIME.",
            ),
        );
        return result;
    }

    let token = match process_token(process.0) {
        Ok(value) => value,
        Err(error) => return fail(result, "process_token_unavailable", error),
    };
    match is_app_container(token.0) {
        Ok(true) => {
            result.status = WindowsAccessStatus::Unsupported;
            result.diagnostic_code = Some("appcontainer_token_not_supported");
            set_control(
                &mut result,
                control(
                    "process_primary_token",
                    WindowsAccessControlStatus::Unsupported,
                    "AppContainer capability and package policy are not evaluated by this slice.",
                ),
            );
            return result;
        }
        Ok(false) => set_control(
            &mut result,
            control(
                "process_primary_token",
                WindowsAccessControlStatus::Evaluated,
                "Authz is initialized from the selected process token after a creation-time identity check.",
            ),
        ),
        Err(error) => return fail(result, "token_context_unavailable", error),
    }

    let file = match open_object(&wide_path) {
        Ok(value) => value,
        Err(error) => return fail(result, "selected_object_open_failed", error),
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.0, &mut info) } == 0 {
        return fail(result, "selected_object_metadata_failed", unsafe {
            GetLastError()
        });
    }
    result.object_volume_serial_number = Some(info.dwVolumeSerialNumber);
    result.object_file_index =
        Some((u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow));
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        result.status = WindowsAccessStatus::Unsupported;
        result.diagnostic_code = Some("selected_object_is_directory");
        set_control(
            &mut result,
            control(
                "selected_object_dacl",
                WindowsAccessControlStatus::Unsupported,
                "This operation vocabulary is limited to files; directory-list and traversal rights are not inferred.",
            ),
        );
        return result;
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        result.status = WindowsAccessStatus::Unsupported;
        result.diagnostic_code = Some("selected_object_is_reparse_point");
        set_control(
            &mut result,
            control(
                "final_reparse_resolution",
                WindowsAccessControlStatus::Unsupported,
                "The selected final reparse point is not followed; target access is not evaluated.",
            ),
        );
        return result;
    }

    let descriptor = match security_descriptor(file.0) {
        Ok(value) => value,
        Err(error) => return fail(result, "security_descriptor_unavailable", error),
    };
    let descriptor_len =
        unsafe { windows_sys::Win32::Security::GetSecurityDescriptorLength(descriptor.0) } as usize;
    result.security_descriptor_length = Some(descriptor_len);
    if descriptor_len == 0 || descriptor_len > MAX_DESCRIPTOR_BYTES {
        result.status = WindowsAccessStatus::Unsupported;
        result.diagnostic_code = Some("security_descriptor_over_limit");
        set_control(
            &mut result,
            control(
                "selected_object_dacl",
                WindowsAccessControlStatus::Unknown,
                "The descriptor is empty or exceeds the 64 KiB evaluation limit.",
            ),
        );
        return result;
    }
    if unsafe { IsValidSecurityDescriptor(descriptor.0) } == 0 {
        result.status = WindowsAccessStatus::Unknown;
        result.diagnostic_code = Some("security_descriptor_malformed");
        return result;
    }
    let descriptor_bytes =
        unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), descriptor_len) };
    result.security_descriptor_sha256 = Some(sha256_hex(descriptor_bytes));
    if let Some(reason) = dacl_unsupported_reason(descriptor.0, descriptor_len) {
        result.status = WindowsAccessStatus::Unsupported;
        result.diagnostic_code = Some(reason);
        set_control(
            &mut result,
            control(
                "selected_object_dacl",
                WindowsAccessControlStatus::Unsupported,
                if reason == "owner_rights_ace_not_supported" {
                    "An OWNER RIGHTS ACE is present; this evaluator does not implement its special owner semantics."
                } else {
                    "Object, callback, conditional, audit, malformed, or unsupported ACE semantics are not evaluated."
                },
            ),
        );
        return result;
    }

    let dacl = match authz_dacl_check(token.0, descriptor.0, requested_access) {
        Ok(mask) => mask,
        Err(error) => return fail(result, "authz_access_check_failed", error),
    };
    result.granted_access_mask = Some(dacl.granted_mask);
    result.dacl_decision = dacl_decision(dacl, requested_access);
    set_control(
        &mut result,
        control(
            "selected_object_dacl",
            WindowsAccessControlStatus::Evaluated,
            "Authz evaluated the requested file rights against this object's DACL and selected process token.",
        ),
    );
    set_control(
        &mut result,
        control(
            "collector_path_open",
            WindowsAccessControlStatus::Evaluated,
            "The collector opened the selected object to read its descriptor; this does not prove the selected process can resolve or open the path.",
        ),
    );
    set_control(
        &mut result,
        control(
            "thread_impersonation_token",
            WindowsAccessControlStatus::NotEvaluated,
            "The process primary token is checked; a thread may use a different impersonation token.",
        ),
    );
    set_control(
        &mut result,
        control(
            "mandatory_integrity_label",
            WindowsAccessControlStatus::NotEvaluated,
            "SACL labels are not requested; mandatory integrity effects are not included.",
        ),
    );
    set_control(
        &mut result,
        control(
            "ancestor_traversal_and_selected_identity_path_resolution",
            WindowsAccessControlStatus::NotEvaluated,
            "The selected object was opened under the collector token; ancestor traversal and path resolution under the selected process token are not checked.",
        ),
    );
    set_control(
        &mut result,
        control(
            "central_access_policy_and_resource_attributes",
            WindowsAccessControlStatus::NotEvaluated,
            "Central access policy and resource attributes are outside this DACL check.",
        ),
    );
    result.controls.push(control(
        "remote_share_and_server_policy",
        WindowsAccessControlStatus::NotEvaluated,
        "Remote share and server-side policy are not evaluated.",
    ));
    result.status = WindowsAccessStatus::Conditional;
    result.conclusion = WindowsAccessConclusion::Conditional;
    result.diagnostic_code = Some("dacl_only_result_is_conditional");
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthzDecision {
    granted_mask: u32,
    error: u32,
}

fn authz_dacl_check(
    token: HANDLE,
    descriptor: *mut core::ffi::c_void,
    desired: u32,
) -> Result<AuthzDecision, u32> {
    let mut manager: AUTHZ_RESOURCE_MANAGER_HANDLE = null_mut();
    if unsafe {
        AuthzInitializeResourceManager(
            AUTHZ_RM_FLAG_NO_AUDIT,
            None,
            None,
            None,
            null(),
            &mut manager,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    let manager = OwnedResourceManager(manager);
    let mut context: AUTHZ_CLIENT_CONTEXT_HANDLE = null_mut();
    if unsafe {
        AuthzInitializeContextFromToken(
            0,
            token,
            manager.0,
            null(),
            windows_sys::Win32::Foundation::LUID::default(),
            null(),
            &mut context,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    let context = OwnedAuthzContext(context);
    let request = AUTHZ_ACCESS_REQUEST {
        DesiredAccess: desired,
        ..Default::default()
    };
    let mut granted_mask = 0u32;
    let mut error = 0u32;
    let mut reply = AUTHZ_ACCESS_REPLY {
        ResultListLength: 1,
        GrantedAccessMask: &mut granted_mask,
        Error: &mut error,
        ..Default::default()
    };
    if unsafe {
        AuthzAccessCheck(
            0,
            context.0,
            &request,
            null_mut(),
            descriptor,
            null(),
            0,
            &mut reply,
            null_mut(),
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    Ok(AuthzDecision {
        granted_mask,
        error,
    })
}

fn security_descriptor(file: HANDLE) -> Result<OwnedSecurityDescriptor, u32> {
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        Err(status)
    } else if descriptor.is_null() {
        Err(ERROR_INVALID_DATA)
    } else {
        Ok(OwnedSecurityDescriptor(descriptor))
    }
}

fn dacl_unsupported_reason(
    descriptor: *mut core::ffi::c_void,
    descriptor_len: usize,
) -> Option<&'static str> {
    let mut present = 0;
    let mut dacl = null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Some("malformed_dacl");
    }
    if present == 0 || dacl.is_null() {
        return None;
    }
    let descriptor_start = descriptor as usize;
    let descriptor_end = match descriptor_start.checked_add(descriptor_len) {
        Some(value) => value,
        None => return Some("malformed_dacl"),
    };
    let acl_address = dacl as usize;
    let acl_header_end =
        match acl_address.checked_add(std::mem::size_of::<windows_sys::Win32::Security::ACL>()) {
            Some(value) => value,
            None => return Some("malformed_dacl"),
        };
    if acl_address < descriptor_start || acl_header_end > descriptor_end {
        return Some("malformed_dacl");
    }
    let acl = unsafe { &*(dacl.cast::<windows_sys::Win32::Security::ACL>()) };
    let acl_len = usize::from(acl.AclSize);
    let acl_end = match acl_address.checked_add(acl_len) {
        Some(value) => value,
        None => return Some("malformed_dacl"),
    };
    if acl_len < std::mem::size_of::<windows_sys::Win32::Security::ACL>()
        || acl_len > MAX_DESCRIPTOR_BYTES
        || acl_end > descriptor_end
    {
        return Some("malformed_dacl");
    }
    if usize::from(acl.AceCount) > 1_024 {
        return Some("malformed_dacl");
    }
    for index in 0..u32::from(acl.AceCount) {
        let mut ace = null_mut();
        if unsafe { windows_sys::Win32::Security::GetAce(dacl, index, &mut ace) } == 0
            || ace.is_null()
        {
            return Some("malformed_dacl");
        }
        let ace_address = ace as usize;
        let ace_header_end = match ace_address.checked_add(4) {
            Some(value) => value,
            None => return Some("malformed_dacl"),
        };
        if ace_address < acl_header_end || ace_header_end > acl_end {
            return Some("malformed_dacl");
        }
        let ace_bytes = unsafe {
            std::slice::from_raw_parts(ace.cast::<u8>(), acl_end.saturating_sub(ace_address))
        };
        let ace_size = usize::from(u16::from_ne_bytes([ace_bytes[2], ace_bytes[3]]));
        if ace_size < 4 || ace_size > ace_bytes.len() {
            return Some("malformed_dacl");
        }
        let ace_type = ace_bytes[0];
        if let Some(reason) = dacl_ace_unsupported_reason(ace_type, &ace_bytes[..ace_size]) {
            return Some(reason);
        }
    }
    None
}

fn dacl_ace_unsupported_reason(ace_type: u8, ace: &[u8]) -> Option<&'static str> {
    // Only ordinary allow/deny ACEs are supported. Object, callback,
    // conditional and audit ACEs require authorization semantics not provided
    // by this selected-object DACL slice.
    if ace_type != 0 && ace_type != 1 {
        return Some("unsupported_dacl_ace");
    }
    match basic_ace_sid(ace) {
        Err(()) => Some("malformed_dacl"),
        Ok(sid) if is_owner_rights_sid(sid) => Some("owner_rights_ace_not_supported"),
        Ok(_) => None,
    }
}

fn basic_ace_sid(ace: &[u8]) -> Result<&[u8], ()> {
    const ACE_PREFIX_BYTES: usize = 8;
    const SID_HEADER_BYTES: usize = 8;
    if ace.len() < ACE_PREFIX_BYTES + SID_HEADER_BYTES {
        return Err(());
    }
    let sid = &ace[ACE_PREFIX_BYTES..];
    if sid[0] != 1 || sid[1] > 15 {
        return Err(());
    }
    let expected_sid_length = SID_HEADER_BYTES
        .checked_add(usize::from(sid[1]).checked_mul(4).ok_or(())?)
        .ok_or(())?;
    if sid.len() != expected_sid_length {
        return Err(());
    }
    Ok(sid)
}

fn is_owner_rights_sid(sid: &[u8]) -> bool {
    if sid.len() != 12 || sid[0] != 1 || sid[1] != 1 || sid[2..8] != [0, 0, 0, 0, 0, 3] {
        return false;
    }
    u32::from_le_bytes([sid[8], sid[9], sid[10], sid[11]]) == 4
}

fn is_app_container(token: HANDLE) -> Result<bool, u32> {
    let mut value = 0u32;
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token,
            TokenIsAppContainer,
            (&mut value as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    if returned != std::mem::size_of::<u32>() as u32 || value > 1 {
        return Err(ERROR_INVALID_DATA);
    }
    Ok(value != 0)
}

fn open_process(process_id: u32) -> Result<OwnedHandle, u32> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        Err(unsafe { GetLastError() })
    } else {
        Ok(OwnedHandle(handle))
    }
}

fn process_creation_time(process: HANDLE) -> Result<u64, u32> {
    let mut creation = windows_sys::Win32::Foundation::FILETIME::default();
    let mut exit = windows_sys::Win32::Foundation::FILETIME::default();
    let mut kernel = windows_sys::Win32::Foundation::FILETIME::default();
    let mut user = windows_sys::Win32::Foundation::FILETIME::default();
    if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn process_token(process: HANDLE) -> Result<OwnedHandle, u32> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        Err(unsafe { GetLastError() })
    } else if token.is_null() {
        Err(ERROR_INVALID_DATA)
    } else {
        Ok(OwnedHandle(token))
    }
}

fn open_object(path: &[u16]) -> Result<OwnedHandle, u32> {
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(unsafe { GetLastError() })
    } else {
        Ok(OwnedHandle(handle))
    }
}

fn volume_is_remote(path: &[u16]) -> Result<bool, u32> {
    let mut volume_path = vec![0u16; MAX_PATH_UTF16_UNITS + 1];
    if unsafe {
        windows_sys::Win32::Storage::FileSystem::GetVolumePathNameW(
            path.as_ptr(),
            volume_path.as_mut_ptr(),
            volume_path.len() as u32,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    let drive_type =
        unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(volume_path.as_ptr()) };
    if drive_type == DRIVE_REMOTE {
        Ok(true)
    } else if drive_type <= 1 {
        Err(ERROR_INVALID_DRIVE)
    } else {
        Ok(false)
    }
}

fn bounded_path(path: &Path) -> Result<Vec<u16>, &'static str> {
    if !path.is_absolute() {
        return Err("path_must_be_absolute");
    }
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .take(MAX_PATH_UTF16_UNITS + 1)
        .collect();
    if wide.is_empty() {
        return Err("empty_path");
    }
    if wide.len() > MAX_PATH_UTF16_UNITS {
        return Err("path_over_limit");
    }
    if wide.contains(&0) {
        return Err("path_contains_nul");
    }
    let mut terminated = wide;
    terminated.push(0);
    Ok(terminated)
}

fn is_network_or_device_path(path: &[u16]) -> bool {
    if path.len() < 2 || path[0] != b'\\' as u16 || path[1] != b'\\' as u16 {
        return false;
    }
    // Permit a local extended path (`\\?\C:\...`) but reject UNC and other
    // device namespaces before volume lookup or file opening.
    if path.len() >= 4 && path[2] == b'?' as u16 && path[3] == b'\\' as u16 {
        let prefix = [b'U' as u16, b'N' as u16, b'C' as u16, b'\\' as u16];
        return path.get(4..8).is_some_and(|candidate| {
            candidate.iter().zip(prefix).all(|(left, right)| {
                let upper = if (b'a' as u16..=b'z' as u16).contains(left) {
                    *left - 32
                } else {
                    *left
                };
                upper == right
            })
        });
    }
    true
}

fn empty_result(
    process_id: u32,
    expected_creation: u64,
    path: &Path,
    operation: &'static str,
    requested: u32,
) -> WindowsDaclEvaluationResult {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .take(MAX_PATH_UTF16_UNITS + 1)
        .collect();
    let path_text = (wide.len() <= MAX_PATH_UTF16_UNITS)
        .then(|| path.to_str().map(str::to_owned))
        .flatten();
    WindowsDaclEvaluationResult {
        schema: "sideeffect.windows_dacl_evaluation",
        schema_version: 1,
        status: WindowsAccessStatus::Unknown,
        conclusion: WindowsAccessConclusion::Unknown,
        process_id,
        expected_creation_time_filetime_100ns: expected_creation,
        observed_creation_time_filetime_100ns: None,
        path: path_text,
        path_utf16_hex: utf16_hex(&wide),
        operation,
        requested_access_mask: Some(requested),
        granted_access_mask: None,
        dacl_decision: WindowsDaclDecision::Unknown,
        object_volume_serial_number: None,
        object_file_index: None,
        security_descriptor_length: None,
        security_descriptor_sha256: None,
        controls: vec![
            control(
                "process_primary_token",
                WindowsAccessControlStatus::Unknown,
                "Not evaluated.",
            ),
            control(
                "selected_object_dacl",
                WindowsAccessControlStatus::Unknown,
                "Not evaluated.",
            ),
            control(
                "thread_impersonation_token",
                WindowsAccessControlStatus::NotEvaluated,
                "A process thread may use a different impersonation token.",
            ),
            control(
                "collector_path_open",
                WindowsAccessControlStatus::NotEvaluated,
                "The selected object has not been opened by the collector.",
            ),
            control(
                "mandatory_integrity_label",
                WindowsAccessControlStatus::NotEvaluated,
                "SACL is not requested.",
            ),
            control(
                "ancestor_traversal_and_selected_identity_path_resolution",
                WindowsAccessControlStatus::NotEvaluated,
                "Not evaluated.",
            ),
        ],
        diagnostic_code: None,
        win32_error: None,
    }
}

fn fail(
    mut result: WindowsDaclEvaluationResult,
    code: &'static str,
    error: u32,
) -> WindowsDaclEvaluationResult {
    result.conclusion = WindowsAccessConclusion::Unknown;
    result.status = if error == ERROR_ACCESS_DENIED {
        WindowsAccessStatus::Inaccessible
    } else {
        WindowsAccessStatus::Unknown
    };
    result.diagnostic_code = Some(code);
    result.win32_error = Some(error);
    result
}

fn control(
    name: &'static str,
    status: WindowsAccessControlStatus,
    detail: &'static str,
) -> WindowsAccessControlEvidence {
    WindowsAccessControlEvidence {
        control: name,
        status,
        detail,
    }
}

fn set_control(result: &mut WindowsDaclEvaluationResult, evidence: WindowsAccessControlEvidence) {
    if let Some(existing) = result
        .controls
        .iter_mut()
        .find(|existing| existing.control == evidence.control)
    {
        *existing = evidence;
    } else {
        result.controls.push(evidence);
    }
}

fn utf16_hex(value: &[u16]) -> String {
    let mut output = String::with_capacity(value.len().saturating_mul(4));
    for unit in value {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{unit:04x}");
    }
    output
}

impl WindowsAccessOperation {
    fn name(self) -> &'static str {
        match self {
            Self::ReadData => "read_data",
            Self::WriteData => "write_data",
            Self::Execute => "execute",
        }
    }

    fn access_mask(self) -> u32 {
        match self {
            Self::ReadData => FILE_READ_DATA,
            Self::WriteData => FILE_WRITE_DATA,
            Self::Execute => FILE_EXECUTE,
        }
    }
}

fn dacl_decision(decision: AuthzDecision, requested_access: u32) -> WindowsDaclDecision {
    if decision.error == 0 && decision.granted_mask & requested_access == requested_access {
        WindowsDaclDecision::GrantedByDacl
    } else if decision.error == 0 || decision.error == ERROR_ACCESS_DENIED {
        WindowsDaclDecision::DeniedByDacl
    } else {
        WindowsDaclDecision::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_masks_are_narrow_and_do_not_request_generic_all_access() {
        assert_eq!(
            WindowsAccessOperation::ReadData.access_mask(),
            FILE_READ_DATA
        );
        assert_eq!(
            WindowsAccessOperation::WriteData.access_mask(),
            FILE_WRITE_DATA
        );
        assert_eq!(WindowsAccessOperation::Execute.access_mask(), FILE_EXECUTE);
        assert_ne!(WindowsAccessOperation::ReadData.access_mask(), 0x001f_01ff);
    }

    #[test]
    fn every_result_starts_unknown_and_does_not_assert_effective_access() {
        let result = empty_result(
            11,
            22,
            Path::new("C:\\temp\\item.txt"),
            "read_data",
            FILE_READ_DATA,
        );
        assert_eq!(result.status, WindowsAccessStatus::Unknown);
        assert_eq!(result.conclusion, WindowsAccessConclusion::Unknown);
        assert_eq!(result.dacl_decision, WindowsDaclDecision::Unknown);
        assert!(
            result
                .controls
                .iter()
                .any(|item| item.control == "mandatory_integrity_label"
                    && item.status == WindowsAccessControlStatus::NotEvaluated)
        );
    }

    #[test]
    fn access_check_decision_requires_the_entire_requested_mask() {
        let requested = FILE_READ_DATA | READ_CONTROL;
        let partial = AuthzDecision {
            granted_mask: FILE_READ_DATA,
            error: 0,
        };
        assert_eq!(
            dacl_decision(partial, requested),
            WindowsDaclDecision::DeniedByDacl
        );
        let complete = AuthzDecision {
            granted_mask: requested,
            error: 0,
        };
        assert_eq!(
            dacl_decision(complete, requested),
            WindowsDaclDecision::GrantedByDacl
        );
        let failed = AuthzDecision {
            granted_mask: requested,
            error: ERROR_ACCESS_DENIED,
        };
        assert_eq!(
            dacl_decision(failed, requested),
            WindowsDaclDecision::DeniedByDacl
        );
        let unexpected_error = AuthzDecision {
            granted_mask: 0,
            error: ERROR_INVALID_DATA,
        };
        assert_eq!(
            dacl_decision(unexpected_error, requested),
            WindowsDaclDecision::Unknown
        );
    }

    #[test]
    fn network_namespace_paths_are_rejected_but_extended_local_paths_are_allowed() {
        assert!(is_network_or_device_path(
            &"\\\\server\\share\\item".encode_utf16().collect::<Vec<_>>()
        ));
        assert!(is_network_or_device_path(
            &"\\\\.\\device".encode_utf16().collect::<Vec<_>>()
        ));
        assert!(!is_network_or_device_path(
            &"\\\\?\\C:\\folder\\item".encode_utf16().collect::<Vec<_>>()
        ));
        assert!(is_network_or_device_path(
            &"\\\\?\\UNC\\server\\share"
                .encode_utf16()
                .collect::<Vec<_>>()
        ));
    }

    #[test]
    fn owner_rights_ace_is_unsupported_until_special_semantics_are_implemented() {
        let mut ace = vec![0u8; 20];
        ace[0] = 0; // ACCESS_ALLOWED_ACE_TYPE
        ace[2..4].copy_from_slice(&20u16.to_ne_bytes());
        ace[4..8].copy_from_slice(&FILE_READ_DATA.to_ne_bytes());
        ace[8] = 1; // SID revision
        ace[9] = 1; // one subauthority
        ace[10..16].copy_from_slice(&[0, 0, 0, 0, 0, 3]); // SECURITY_CREATOR_AUTHORITY
        ace[16..20].copy_from_slice(&4u32.to_le_bytes()); // OWNER RIGHTS (S-1-3-4)

        assert_eq!(
            dacl_ace_unsupported_reason(ace[0], &ace),
            Some("owner_rights_ace_not_supported")
        );

        let mut ordinary = ace.clone();
        ordinary[10..16].copy_from_slice(&[0, 0, 0, 0, 0, 5]); // SECURITY_NT_AUTHORITY
        ordinary[16..20].copy_from_slice(&18u32.to_le_bytes()); // Local System
        assert_eq!(dacl_ace_unsupported_reason(ordinary[0], &ordinary), None);

        assert_eq!(
            dacl_ace_unsupported_reason(0, &ace[..19]),
            Some("malformed_dacl")
        );
    }
}
