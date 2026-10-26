//! Windows private, no-clobber output publication.

use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io::{self, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU64, Ordering};

type Handle = *mut c_void;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_USER_CLASS: u32 = 1;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_ALREADY_EXISTS: i32 = 183;
const GENERIC_WRITE: u32 = 0x4000_0000;
const CREATE_NEW: u32 = 1;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
static NEXT_STAGE_ID: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    security_descriptor: *mut c_void,
    inherit_handle: i32,
}

#[repr(C)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}

#[repr(C)]
struct TokenUser {
    user: SidAndAttributes,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn LocalFree(memory: Handle) -> Handle;
    fn GetCurrentProcessId() -> u32;
    fn CreateDirectoryW(path: *const u16, attributes: *const SecurityAttributes) -> i32;
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        attributes: *const SecurityAttributes,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn MoveFileExW(source: *const u16, destination: *const u16, flags: u32) -> i32;
    fn DeleteFileW(path: *const u16) -> i32;
    fn RemoveDirectoryW(path: *const u16) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        information: *mut c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, string_sid: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_security_descriptor: *const u16,
        revision: u32,
        security_descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
}

struct LocalAllocation(Handle);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: LocalAllocation owns a buffer returned by a Windows LocalAlloc API.
            unsafe { LocalFree(self.0) };
        }
    }
}

struct Token(Handle);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: Token owns a handle returned by OpenProcessToken.
        unsafe { CloseHandle(self.0) };
    }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CloseHandle(handle: Handle) -> i32;
}

struct Stage {
    directory: PathBuf,
    payload: PathBuf,
}

impl Drop for Stage {
    fn drop(&mut self) {
        if let Ok(path) = wide_z(&self.payload) {
            // SAFETY: cleanup only targets the unique private staging entry created below.
            unsafe { DeleteFileW(path.as_ptr()) };
        }
        if let Ok(path) = wide_z(&self.directory) {
            // SAFETY: cleanup only targets the unique private staging directory created below.
            unsafe { RemoveDirectoryW(path.as_ptr()) };
        }
    }
}

/// Publishes bytes through an owner-only sibling staging directory and never replaces a file.
pub fn publish_private_file(
    destination: &Path,
    bytes: &[u8],
    max_bytes: usize,
) -> io::Result<PathBuf> {
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("private output exceeds the {max_bytes} byte limit"),
        ));
    }
    let file_name = destination
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "output path has no file name")
        })?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = parent.canonicalize()?;
    let destination = parent.join(file_name);
    let descriptor = current_user_security_descriptor()?;
    let attributes = SecurityAttributes {
        length: size_of::<SecurityAttributes>() as u32,
        security_descriptor: descriptor.0,
        inherit_handle: 0,
    };
    let stage = create_stage(&parent, &attributes)?;
    let payload_name = wide_z(&stage.payload)?;
    let handle = unsafe {
        CreateFileW(
            payload_name.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a new valid, exclusively opened handle.
    let mut file = unsafe { File::from_raw_handle(handle) };
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);

    let source = wide_z(&stage.payload)?;
    let target = wide_z(&destination)?;
    if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = destination;
    drop(stage);
    Ok(result)
}

fn create_stage(parent: &Path, attributes: &SecurityAttributes) -> io::Result<Stage> {
    for _ in 0..32 {
        let id = NEXT_STAGE_ID.fetch_add(1, Ordering::Relaxed);
        let name = format!(".sideeffect-private-{}-{id}", unsafe {
            GetCurrentProcessId()
        });
        let directory = parent.join(name);
        let wide = wide_z(&directory)?;
        if unsafe { CreateDirectoryW(wide.as_ptr(), attributes) } != 0 {
            let payload = directory.join("inventory.json");
            return Ok(Stage { directory, payload });
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS) {
            return Err(error);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique private staging directory",
    ))
}

fn current_user_security_descriptor() -> io::Result<LocalAllocation> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Token(token);
    let mut needed = 0u32;
    let ok = unsafe { GetTokenInformation(token.0, TOKEN_USER_CLASS, null_mut(), 0, &mut needed) };
    if ok != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token.0,
            TOKEN_USER_CLASS,
            storage.as_mut_ptr().cast(),
            needed,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned < size_of::<TokenUser>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a truncated user token record",
        ));
    }
    // SAFETY: GetTokenInformation initialized a correctly sized TOKEN_USER buffer.
    let token_user = unsafe { &*storage.as_ptr().cast::<TokenUser>() };
    let mut sid_text = null_mut();
    if unsafe { ConvertSidToStringSidW(token_user.user.sid, &mut sid_text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid_text = LocalAllocation(sid_text.cast());
    let mut sid_len = 0usize;
    while unsafe { *sid_text.0.cast::<u16>().add(sid_len) } != 0 {
        sid_len += 1;
        if sid_len > 184 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned an oversized SID",
            ));
        }
    }
    // SAFETY: SID string is NUL-terminated and bounded above.
    let sid = String::from_utf16(unsafe {
        std::slice::from_raw_parts(sid_text.0.cast::<u16>(), sid_len)
    })
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid SID string",
        )
    })?;
    let sddl = format!("D:P(A;;GA;;;{sid})");
    let sddl = wide_z(OsStr::new(&sddl))?;
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    drop(sid_text);
    Ok(LocalAllocation(descriptor))
}

fn wide_z(value: impl AsRef<OsStr>) -> io::Result<Vec<u16>> {
    let mut wide: Vec<_> = value.as_ref().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains a NUL code unit",
        ));
    }
    wide.push(0);
    Ok(wide)
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
}

#[cfg(test)]
#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetFileSecurityW(
        file_name: *const u16,
        requested_information: u32,
        security_descriptor: *mut c_void,
        length: u32,
        length_needed: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorControl(
        security_descriptor: *const c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        security_descriptor: *const c_void,
        dacl_present: *mut i32,
        dacl: *mut *mut c_void,
        dacl_defaulted: *mut i32,
    ) -> i32;
    fn GetAclInformation(
        acl: *mut c_void,
        information: *mut c_void,
        information_length: u32,
        information_class: u32,
    ) -> i32;
    fn GetAce(acl: *mut c_void, ace_index: u32, ace: *mut *mut c_void) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-private-output-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn publishes_owner_private_file_without_replacing_existing_destination() {
        let directory = temp_dir();
        let output = directory.join("inventory.json");
        let path = publish_private_file(&output, b"{\"safe\":true}", 1024).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"{\"safe\":true}");
        assert_owner_only_dacl(&path);
        let error = publish_private_file(&output, b"replacement", 1024).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"{\"safe\":true}");
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    fn assert_owner_only_dacl(path: &Path) {
        const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
        const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
        const SE_DACL_PROTECTED: u16 = 0x1000;
        const ACL_SIZE_INFORMATION: u32 = 2;
        #[repr(C)]
        struct AclSizeInformation {
            ace_count: u32,
            bytes_in_use: u32,
            bytes_free: u32,
        }
        #[repr(C)]
        struct AceHeader {
            ace_type: u8,
            ace_flags: u8,
            ace_size: u16,
        }

        let path = wide_z(path).unwrap();
        let mut needed = 0u32;
        let ok = unsafe {
            GetFileSecurityW(
                path.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                0,
                &mut needed,
            )
        };
        assert_eq!(ok, 0);
        assert!(needed > 0);
        let mut storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        assert_ne!(
            unsafe {
                GetFileSecurityW(
                    path.as_ptr(),
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    storage.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            },
            0
        );
        let descriptor = storage.as_mut_ptr().cast::<c_void>();
        let mut control = 0u16;
        let mut revision = 0u32;
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
            0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0);
        let mut present = 0;
        let mut dacl = null_mut();
        let mut defaulted = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
            },
            0
        );
        assert_ne!(present, 0);
        assert!(!dacl.is_null());
        let mut acl_size = AclSizeInformation {
            ace_count: 0,
            bytes_in_use: 0,
            bytes_free: 0,
        };
        assert_ne!(
            unsafe {
                GetAclInformation(
                    dacl,
                    (&mut acl_size as *mut AclSizeInformation).cast(),
                    size_of::<AclSizeInformation>() as u32,
                    ACL_SIZE_INFORMATION,
                )
            },
            0
        );
        assert_eq!(acl_size.ace_count, 1);
        let mut ace = null_mut();
        assert_ne!(unsafe { GetAce(dacl, 0, &mut ace) }, 0);
        assert_eq!(unsafe { (*ace.cast::<AceHeader>()).ace_type }, 0);
    }

    #[test]
    fn rejects_output_over_limit_before_creating_a_file() {
        let directory = temp_dir();
        let output = directory.join("inventory.json");
        let error = publish_private_file(&output, b"too long", 3).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!output.exists());
        fs::remove_dir(directory).unwrap();
    }
}
