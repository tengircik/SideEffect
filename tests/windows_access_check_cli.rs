#![cfg(windows)]

use serde_json::Value;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::ACL_REVISION;
use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AccessCheck, AddAccessAllowedAceEx, AddAccessDeniedAceEx, DACL_SECURITY_INFORMATION,
    DuplicateTokenEx, GENERIC_MAPPING, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorLength,
    GetTokenInformation, InitializeAcl, IsValidSecurityDescriptor, IsValidSid,
    OWNER_SECURITY_INFORMATION, PRIVILEGE_SET, PROTECTED_DACL_SECURITY_INFORMATION,
    SecurityImpersonation, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER, TokenImpersonation, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ALL_ACCESS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_DATA, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_READ_ATTRIBUTES, SYNCHRONIZE, WRITE_DAC};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const MAX_ORACLE_DESCRIPTOR_BYTES: usize = 64 * 1024;
const INITIAL_PRIVILEGE_BUFFER_BYTES: usize = 1024;
const MAX_PRIVILEGE_BUFFER_BYTES: usize = 64 * 1024;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        loop {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-windows-access-check-{}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create synthetic fixture directory: {error}"),
            }
        }
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn access_check_uses_process_snapshot_identity_and_reports_conditional_dacl_result() {
    let directory = TempDirectory::new();
    let selected = directory.0.join("synthetic-file.txt");
    let original_contents = b"synthetic Windows DACL fixture";
    fs::write(&selected, original_contents).expect("create synthetic selected file");
    let before_modified = fs::metadata(&selected)
        .expect("read fixture metadata before check")
        .modified()
        .expect("read fixture modification time");
    let process_inventory = directory.0.join("processes.json");
    let snapshot = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "processes", "--output"])
        .arg(&process_inventory)
        .output()
        .expect("start Windows process inventory CLI");
    assert!(
        snapshot.status.success() || snapshot.status.code() == Some(2),
        "unexpected process inventory result: {}",
        String::from_utf8_lossy(&snapshot.stderr)
    );
    let inventory: Value = serde_json::from_slice(
        &fs::read(&process_inventory).expect("process inventory output exists"),
    )
    .expect("process inventory output is JSON");
    assert_eq!(inventory["schema"], "sideeffect.windows_process_inventory");
    assert_eq!(inventory["schema_version"], 3);
    let current_pid = std::process::id();
    let current_process = inventory["processes"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["process_id"] == current_pid));
    let Some(current_process) = current_process else {
        eprintln!(
            "SKIP: host process snapshot did not include this test process (PID {current_pid}); Windows access-check requires a snapshot identity."
        );
        return;
    };
    assert_eq!(
        current_process["evidence"]["snapshot_source"],
        "ToolHelp32Snapshot/PROCESSENTRY32W"
    );
    if current_process["creation_time"]["status"] != "observed" {
        eprintln!(
            "SKIP: host process snapshot could not observe this test process creation FILETIME; Windows access-check requires that generation identity."
        );
        return;
    }
    let Some(creation_time) = current_process["creation_time"]["filetime_100ns"].as_u64() else {
        eprintln!(
            "SKIP: host process snapshot omitted this test process creation FILETIME; Windows access-check requires that generation identity."
        );
        return;
    };
    assert_eq!(
        current_process["creation_time"]["source"],
        "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)/GetProcessTimes"
    );

    let output = directory.0.join("access-check.json");
    let pid_text = current_pid.to_string();
    let creation_time_text = creation_time.to_string();
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "access-check", "--pid"])
        .arg(pid_text)
        .args(["--creation-time-filetime"])
        .arg(creation_time_text)
        .args(["--operation", "read", "--output"])
        .arg(&output)
        .arg(&selected)
        .output()
        .expect("start Windows access-check CLI");
    assert_eq!(
        result.status.code(),
        Some(2),
        "expected a published partial/conditional DACL result: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    let document: Value =
        serde_json::from_slice(&fs::read(&output).expect("access-check output exists"))
            .expect("access-check output is JSON");

    if document["diagnostic_code"] == "appcontainer_token_not_supported" {
        eprintln!(
            "SKIP: host test process uses an AppContainer token, which this DACL check does not support."
        );
        return;
    }
    if document["diagnostic_code"] == "unsupported_dacl_ace"
        || document["diagnostic_code"] == "owner_rights_ace_not_supported"
    {
        eprintln!(
            "SKIP: host temporary-file DACL contains ACE semantics outside the supported basic allow/deny test prerequisite."
        );
        return;
    }
    if document["diagnostic_code"] == "remote_filesystem_not_supported"
        || document["diagnostic_code"] == "network_or_device_path_not_supported"
    {
        eprintln!("SKIP: host temporary directory is not on a supported local filesystem.");
        return;
    }

    assert_eq!(document["schema"], "sideeffect.windows_dacl_evaluation");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["status"], "conditional", "result: {document:#}");
    assert_eq!(
        document["conclusion"], "conditional",
        "result: {document:#}"
    );
    assert_eq!(document["process_id"], current_pid);
    assert_eq!(
        document["expected_creation_time_filetime_100ns"],
        creation_time
    );
    assert_eq!(
        document["observed_creation_time_filetime_100ns"],
        creation_time
    );
    assert_eq!(document["path"], selected.to_str().unwrap());
    assert_eq!(document["operation"], "read_data");
    assert!(matches!(
        document["dacl_decision"].as_str(),
        Some("granted_by_dacl" | "denied_by_dacl")
    ));
    assert!(document["requested_access_mask"].is_u64());
    assert!(document["granted_access_mask"].is_u64());
    assert_eq!(
        document["diagnostic_code"],
        "dacl_only_result_is_conditional"
    );
    let dacl_control = document["controls"]
        .as_array()
        .and_then(|controls| {
            controls
                .iter()
                .find(|control| control["control"] == "selected_object_dacl")
        })
        .expect("DACL control is present");
    assert_eq!(dacl_control["status"], "evaluated", "result: {document:#}");

    let oracle = match access_check_oracle(&selected, FILE_READ_DATA) {
        Ok(value) => value,
        Err(error) if error.starts_with("UNSUPPORTED:") => {
            eprintln!("SKIP: independent AccessCheck oracle prerequisite unsupported: {error}");
            return;
        }
        Err(error) => panic!("AccessCheck oracle failed: {error}"),
    };
    assert_eq!(
        document["object_volume_serial_number"].as_u64(),
        Some(u64::from(oracle.volume_serial_number)),
        "CLI and oracle must inspect the same volume: {document:#}"
    );
    assert_eq!(
        document["object_file_index"].as_u64(),
        Some(oracle.file_index),
        "CLI and oracle must inspect the same file object: {document:#}"
    );
    if oracle.privileges_used != 0 {
        eprintln!(
            "SKIP: AccessCheck used {} token privilege(s); this run cannot serve as a DACL-only oracle.",
            oracle.privileges_used
        );
        return;
    }
    assert_eq!(
        document["dacl_decision"],
        if oracle.granted {
            "granted_by_dacl"
        } else {
            "denied_by_dacl"
        },
        "Authz and independent AccessCheck results differ: {document:#}"
    );

    let allow_fixture = directory.0.join("explicit-allow.txt");
    let deny_fixture = directory.0.join("explicit-deny.txt");
    fs::write(&allow_fixture, b"synthetic explicit-allow fixture")
        .expect("create explicit-allow fixture");
    fs::write(&deny_fixture, b"synthetic explicit-deny fixture")
        .expect("create explicit-deny fixture");
    for (fixture, deny_read_data) in [(&allow_fixture, false), (&deny_fixture, true)] {
        match set_current_user_fixture_dacl(fixture, deny_read_data) {
            Ok(()) => {}
            Err(FixtureDaclError::Unsupported(reason)) => {
                eprintln!(
                    "SKIP: cannot construct a private synthetic DACL oracle fixture: {reason}"
                );
                return;
            }
            Err(FixtureDaclError::Failure(reason)) => {
                panic!("failed to construct a private synthetic DACL oracle fixture: {reason}");
            }
        }
    }
    for (fixture, output_name, expected) in [
        (&allow_fixture, "explicit-allow.json", "granted_by_dacl"),
        (&deny_fixture, "explicit-deny.json", "denied_by_dacl"),
    ] {
        if !assert_cli_matches_access_check_oracle(
            fixture,
            &directory.0.join(output_name),
            current_pid,
            creation_time,
            expected,
        ) {
            return;
        }
    }

    let after_metadata = fs::metadata(&selected).expect("read fixture metadata after check");
    assert_eq!(
        fs::read(&selected).expect("DACL check leaves file contents unchanged"),
        original_contents
    );
    assert_eq!(after_metadata.len(), original_contents.len() as u64);
    assert_eq!(
        after_metadata
            .modified()
            .expect("read fixture modification time after check"),
        before_modified
    );
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

struct AccessCheckOracleResult {
    granted: bool,
    privileges_used: u32,
    volume_serial_number: u32,
    file_index: u64,
}

fn access_check_oracle(
    path: &std::path::Path,
    desired_access: u32,
) -> Result<AccessCheckOracleResult, String> {
    let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide_path.contains(&0) {
        return Err("synthetic fixture path unexpectedly contains a NUL".to_owned());
    }
    wide_path.push(0);
    let file = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if file == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        if error == 5 || error == 50 {
            return Err(format!(
                "UNSUPPORTED: fixture cannot be opened for READ_CONTROL (Win32 {error})"
            ));
        }
        return Err(format!(
            "could not open the existing fixture for READ_CONTROL (Win32 {})",
            error
        ));
    }
    let file = OwnedHandle(file);
    let mut file_info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.0, &mut file_info) } == 0 {
        return Err(format!(
            "could not identify the oracle file handle (Win32 {})",
            unsafe { GetLastError() }
        ));
    }

    let mut descriptor = null_mut();
    let security_status = unsafe {
        GetSecurityInfo(
            file.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if security_status != 0 {
        if security_status == 5 || security_status == 50 {
            return Err(format!(
                "UNSUPPORTED: fixture owner/group/DACL cannot be read (Win32 {security_status})"
            ));
        }
        return Err(format!(
            "GetSecurityInfo failed for the fixture (Win32 {security_status})"
        ));
    }
    if descriptor.is_null() {
        return Err("GetSecurityInfo returned a null security descriptor".to_owned());
    }
    let descriptor = OwnedSecurityDescriptor(descriptor);
    let descriptor_length = unsafe { GetSecurityDescriptorLength(descriptor.0) } as usize;
    if descriptor_length == 0 || descriptor_length > MAX_ORACLE_DESCRIPTOR_BYTES {
        return Err(format!(
            "UNSUPPORTED: fixture security descriptor length {descriptor_length} is outside the oracle bound"
        ));
    }
    if unsafe { IsValidSecurityDescriptor(descriptor.0) } == 0 {
        return Err("UNSUPPORTED: AccessCheck cannot safely use the fixture descriptor".to_owned());
    }

    let mut primary_token = null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut primary_token,
        )
    } == 0
    {
        let error = unsafe { GetLastError() };
        if error == 5 || error == 50 {
            return Err(format!(
                "UNSUPPORTED: test process token cannot be queried/duplicated (Win32 {error})"
            ));
        }
        return Err(format!(
            "could not query/duplicate the test process primary token (Win32 {error})"
        ));
    }
    if primary_token.is_null() {
        return Err("OpenProcessToken returned a null token handle".to_owned());
    }
    let primary_token = OwnedHandle(primary_token);
    let mut impersonation_token = null_mut();
    if unsafe {
        DuplicateTokenEx(
            primary_token.0,
            TOKEN_QUERY,
            null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut impersonation_token,
        )
    } == 0
    {
        let error = unsafe { GetLastError() };
        if error == 5 || error == 50 {
            return Err(format!(
                "UNSUPPORTED: test token cannot be duplicated as an impersonation token (Win32 {error})"
            ));
        }
        return Err(format!(
            "could not create a query-only impersonation token for AccessCheck (Win32 {error})"
        ));
    }
    if impersonation_token.is_null() {
        return Err("DuplicateTokenEx returned a null token handle".to_owned());
    }
    let impersonation_token = OwnedHandle(impersonation_token);

    let generic_mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    let (granted, privileges_used) = access_check_with_bounded_privilege_buffer(
        descriptor.0,
        impersonation_token.0,
        desired_access,
        &generic_mapping,
    )?;

    Ok(AccessCheckOracleResult {
        granted,
        privileges_used,
        volume_serial_number: file_info.dwVolumeSerialNumber,
        file_index: (u64::from(file_info.nFileIndexHigh) << 32)
            | u64::from(file_info.nFileIndexLow),
    })
}

fn access_check_with_bounded_privilege_buffer(
    descriptor: *mut core::ffi::c_void,
    token: HANDLE,
    desired_access: u32,
    generic_mapping: &GENERIC_MAPPING,
) -> Result<(bool, u32), String> {
    let mut buffer = privilege_buffer(INITIAL_PRIVILEGE_BUFFER_BYTES);
    let mut buffer_length = u32::try_from(buffer.len() * std::mem::size_of::<usize>())
        .map_err(|_| "initial privilege buffer length overflowed u32".to_owned())?;

    for attempt in 0..2 {
        let mut granted_access = 0u32;
        let mut access_status = 0;
        let success = unsafe {
            AccessCheck(
                descriptor,
                token,
                desired_access,
                generic_mapping,
                buffer.as_mut_ptr().cast::<PRIVILEGE_SET>(),
                &mut buffer_length,
                &mut granted_access,
                &mut access_status,
            )
        };
        if success != 0 {
            let privilege_set = unsafe { &*buffer.as_ptr().cast::<PRIVILEGE_SET>() };
            let privilege_array_offset = std::mem::offset_of!(PRIVILEGE_SET, Privilege);
            let buffer_bytes = buffer.len() * std::mem::size_of::<usize>();
            let privilege_capacity = buffer_bytes.saturating_sub(privilege_array_offset)
                / std::mem::size_of::<windows_sys::Win32::Security::LUID_AND_ATTRIBUTES>();
            if privilege_set.PrivilegeCount as usize > privilege_capacity {
                return Err("AccessCheck returned an out-of-bounds privilege count".to_owned());
            }
            return Ok((access_status != 0, privilege_set.PrivilegeCount));
        }

        let error = unsafe { GetLastError() };
        if error == windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER && attempt == 0 {
            let required = usize::try_from(buffer_length).map_err(|_| {
                "AccessCheck returned an invalid privilege buffer length".to_owned()
            })?;
            if required <= buffer.len() * std::mem::size_of::<usize>()
                || required > MAX_PRIVILEGE_BUFFER_BYTES
            {
                return Err(format!(
                    "UNSUPPORTED: AccessCheck requested an invalid or over-limit privilege buffer size ({required} bytes)"
                ));
            }
            buffer = privilege_buffer(required);
            buffer_length = u32::try_from(buffer.len() * std::mem::size_of::<usize>())
                .map_err(|_| "required privilege buffer length overflowed u32".to_owned())?;
            continue;
        }
        if error == 50 || error == 1338 {
            return Err(format!(
                "UNSUPPORTED: AccessCheck cannot evaluate this descriptor/token combination (Win32 {error})"
            ));
        }
        return Err(format!(
            "AccessCheck failed (Win32 {error}, privilege-buffer attempt {attempt})"
        ));
    }

    Err("AccessCheck exhausted its bounded privilege-buffer retry".to_owned())
}

fn privilege_buffer(minimum_bytes: usize) -> Vec<usize> {
    let word_bytes = std::mem::size_of::<usize>();
    vec![0; minimum_bytes.div_ceil(word_bytes)]
}

enum FixtureDaclError {
    Unsupported(String),
    Failure(String),
}

fn set_current_user_fixture_dacl(
    path: &std::path::Path,
    deny_read_data: bool,
) -> Result<(), FixtureDaclError> {
    let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide_path.contains(&0) {
        return Err(FixtureDaclError::Failure(
            "synthetic fixture path unexpectedly contains a NUL".to_owned(),
        ));
    }
    wide_path.push(0);
    let file = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if file == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        if error == 5 || error == 50 {
            return Err(FixtureDaclError::Unsupported(format!(
                "fixture cannot be opened with WRITE_DAC (Win32 {error})"
            )));
        }
        return Err(FixtureDaclError::Failure(format!(
            "could not open fixture with WRITE_DAC (Win32 {error})"
        )));
    }
    let file = OwnedHandle(file);

    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        let error = unsafe { GetLastError() };
        if error == 5 || error == 50 {
            return Err(FixtureDaclError::Unsupported(format!(
                "test process token cannot be queried (Win32 {error})"
            )));
        }
        return Err(FixtureDaclError::Failure(format!(
            "could not query test process token (Win32 {error})"
        )));
    }
    if token.is_null() {
        return Err(FixtureDaclError::Failure(
            "OpenProcessToken returned a null token handle".to_owned(),
        ));
    }
    let token = OwnedHandle(token);
    let mut required = 0u32;
    let sized = unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required) };
    if sized != 0 || unsafe { GetLastError() } != 122 {
        let error = unsafe { GetLastError() };
        return Err(FixtureDaclError::Failure(format!(
            "could not size TokenUser information (Win32 {error})"
        )));
    }
    let required = required as usize;
    if required < std::mem::size_of::<TOKEN_USER>() || required > 4096 {
        return Err(FixtureDaclError::Unsupported(format!(
            "TokenUser size {required} is outside the bounded fixture limit"
        )));
    }
    let word_bytes = std::mem::size_of::<usize>();
    let mut token_user_buffer = vec![0usize; required.div_ceil(word_bytes)];
    let buffer_bytes = token_user_buffer.len() * word_bytes;
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            token_user_buffer.as_mut_ptr().cast(),
            u32::try_from(buffer_bytes).map_err(|_| {
                FixtureDaclError::Failure("TokenUser buffer length overflowed u32".to_owned())
            })?,
            &mut returned,
        )
    } == 0
    {
        let error = unsafe { GetLastError() };
        if error == 5 || error == 50 {
            return Err(FixtureDaclError::Unsupported(format!(
                "TokenUser information is unavailable (Win32 {error})"
            )));
        }
        return Err(FixtureDaclError::Failure(format!(
            "could not read TokenUser information (Win32 {error})"
        )));
    }
    let returned = returned as usize;
    if returned < std::mem::size_of::<TOKEN_USER>() || returned > buffer_bytes {
        return Err(FixtureDaclError::Failure(
            "TokenUser returned a length outside its allocated buffer".to_owned(),
        ));
    }
    let token_user = unsafe { &*token_user_buffer.as_ptr().cast::<TOKEN_USER>() };
    let sid = token_user.User.Sid;
    if sid.is_null() {
        return Err(FixtureDaclError::Failure(
            "TokenUser returned a null SID".to_owned(),
        ));
    }
    let buffer_start = token_user_buffer.as_ptr() as usize;
    let buffer_end = buffer_start
        .checked_add(returned)
        .ok_or_else(|| FixtureDaclError::Failure("TokenUser address overflow".to_owned()))?;
    let sid_start = sid as usize;
    let sid_header_end = sid_start
        .checked_add(8)
        .ok_or_else(|| FixtureDaclError::Failure("SID address overflow".to_owned()))?;
    if sid_start < buffer_start || sid_header_end > buffer_end {
        return Err(FixtureDaclError::Failure(
            "TokenUser SID header lies outside its returned buffer".to_owned(),
        ));
    }
    let sid_bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), 8) };
    let subauthority_count = usize::from(sid_bytes[1]);
    if subauthority_count > 15 {
        return Err(FixtureDaclError::Failure(
            "TokenUser SID has an invalid subauthority count".to_owned(),
        ));
    }
    let sid_length = 8 + subauthority_count * 4;
    let sid_end = sid_start
        .checked_add(sid_length)
        .ok_or_else(|| FixtureDaclError::Failure("SID address overflow".to_owned()))?;
    if sid_end > buffer_end || unsafe { IsValidSid(sid) } == 0 {
        return Err(FixtureDaclError::Failure(
            "TokenUser SID is invalid or exceeds its returned buffer".to_owned(),
        ));
    }

    const ACL_BUFFER_BYTES: usize = 1024;
    let mut acl_buffer = vec![0usize; ACL_BUFFER_BYTES.div_ceil(word_bytes)];
    let acl_length = u32::try_from(acl_buffer.len() * word_bytes)
        .map_err(|_| FixtureDaclError::Failure("ACL buffer length overflow".to_owned()))?;
    let acl = acl_buffer.as_mut_ptr().cast::<ACL>();
    if unsafe { InitializeAcl(acl, acl_length, ACL_REVISION) } == 0 {
        return Err(FixtureDaclError::Failure(format!(
            "InitializeAcl failed (Win32 {})",
            unsafe { GetLastError() }
        )));
    }
    if deny_read_data
        && unsafe { AddAccessDeniedAceEx(acl, ACL_REVISION, 0, FILE_READ_DATA, sid) } == 0
    {
        return Err(FixtureDaclError::Failure(format!(
            "AddAccessDeniedAceEx failed (Win32 {})",
            unsafe { GetLastError() }
        )));
    }
    let allow_mask = FILE_READ_ATTRIBUTES
        | READ_CONTROL
        | SYNCHRONIZE
        | if deny_read_data { 0 } else { FILE_READ_DATA };
    if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, 0, allow_mask, sid) } == 0 {
        return Err(FixtureDaclError::Failure(format!(
            "AddAccessAllowedAceEx failed (Win32 {})",
            unsafe { GetLastError() }
        )));
    }
    let status = unsafe {
        SetSecurityInfo(
            file.0,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null_mut(),
        )
    };
    if status != 0 {
        if status == 5 || status == 50 {
            return Err(FixtureDaclError::Unsupported(format!(
                "DACL cannot be set on the private fixture (Win32 {status})"
            )));
        }
        return Err(FixtureDaclError::Failure(format!(
            "SetSecurityInfo failed (Win32 {status})"
        )));
    }
    Ok(())
}

fn assert_cli_matches_access_check_oracle(
    path: &std::path::Path,
    output: &std::path::Path,
    process_id: u32,
    creation_time: u64,
    expected_decision: &str,
) -> bool {
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "access-check", "--pid"])
        .arg(process_id.to_string())
        .args(["--creation-time-filetime"])
        .arg(creation_time.to_string())
        .args(["--operation", "read", "--output"])
        .arg(output)
        .arg(path)
        .output()
        .expect("start Windows access-check CLI for explicit DACL fixture");
    assert_eq!(
        result.status.code(),
        Some(2),
        "expected conditional result for {}: {}",
        path.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    let document: Value = serde_json::from_slice(
        &fs::read(output).expect("explicit DACL access-check output exists"),
    )
    .expect("explicit DACL access-check output is JSON");
    assert_eq!(document["schema"], "sideeffect.windows_dacl_evaluation");
    assert_eq!(document["status"], "conditional", "result: {document:#}");
    assert_eq!(
        document["dacl_decision"], expected_decision,
        "result: {document:#}"
    );
    assert_eq!(
        document["diagnostic_code"],
        "dacl_only_result_is_conditional"
    );

    let oracle = match access_check_oracle(path, FILE_READ_DATA) {
        Ok(value) => value,
        Err(error) if error.starts_with("UNSUPPORTED:") => {
            eprintln!("SKIP: independent AccessCheck oracle prerequisite unsupported: {error}");
            return false;
        }
        Err(error) => panic!("AccessCheck oracle failed: {error}"),
    };
    assert_eq!(
        document["object_volume_serial_number"].as_u64(),
        Some(u64::from(oracle.volume_serial_number))
    );
    assert_eq!(
        document["object_file_index"].as_u64(),
        Some(oracle.file_index)
    );
    if oracle.privileges_used != 0 {
        eprintln!(
            "SKIP: AccessCheck used {} token privilege(s); this run cannot serve as a DACL-only oracle.",
            oracle.privileges_used
        );
        return false;
    }
    assert_eq!(
        oracle.granted,
        expected_decision == "granted_by_dacl",
        "native AccessCheck disagrees with the explicit fixture ACL: {document:#}"
    );
    true
}
