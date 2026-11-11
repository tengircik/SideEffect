//! Windows private, no-clobber output publication.

use std::ffi::{OsStr, c_void};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformation, NtCreateFile,
    NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    GENERIC_WRITE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FileDispositionInfo, SYNCHRONIZE,
    SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

type Handle = *mut c_void;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_USER_CLASS: u32 = 1;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const MAX_PRIVATE_DIRECTORY_FILES: usize = 8;
static NEXT_STAGE_ID: AtomicU64 = AtomicU64::new(0);

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

struct StagedOutput<'a> {
    object: File,
    children: Vec<&'a str>,
    cleanup_pending: bool,
}

impl Drop for StagedOutput<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Publishes bytes through an owner-only sibling file and never replaces a file.
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
    let (parent, destination, name) = open_output_parent(destination)?;
    let descriptor = current_user_security_descriptor()?;
    let mut stage = create_stage(&parent, &descriptor, false)?;
    let result =
        write_payload(&mut stage.object, bytes).and_then(|()| stage.publish(&parent, &name));
    stage.finish(result)?;
    Ok(destination)
}

/// Atomically publishes a private, fixed-name directory without replacing an existing path.
///
/// The directory and files receive a protected current-user-only DACL before publication.
/// Names are restricted to flat ASCII filenames so callers cannot escape the staging root.
pub fn publish_private_directory(
    destination: &Path,
    files: &[(&str, &[u8])],
    max_total_bytes: usize,
) -> io::Result<PathBuf> {
    if files.is_empty() || files.len() > MAX_PRIVATE_DIRECTORY_FILES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private output directory has an invalid file count",
        ));
    }
    let mut total_bytes = 0usize;
    for (index, (name, bytes)) in files.iter().enumerate() {
        validate_flat_file_name(name)?;
        if files[..index].iter().any(|(existing, _)| existing == name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private output directory contains duplicate file names",
            ));
        }
        total_bytes = total_bytes.checked_add(bytes.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "private output directory size overflowed",
            )
        })?;
        if total_bytes > max_total_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("private output directory exceeds the {max_total_bytes} byte limit"),
            ));
        }
    }

    let (parent, destination, name) = open_output_parent(destination)?;
    let descriptor = current_user_security_descriptor()?;
    let mut stage = create_stage(&parent, &descriptor, true)?;
    let result = (|| {
        for (name, bytes) in files {
            let mut file = open_child(&stage.object, OsStr::new(name), false, Some(&descriptor))?;
            stage.children.push(name);
            write_payload(&mut file, bytes)?;
            // Windows requires child files to be closed before renaming the directory.
        }
        stage.publish(&parent, &name)
    })();
    stage.finish(result)?;
    Ok(destination)
}

fn write_payload(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()
}

fn open_output_parent(destination: &Path) -> io::Result<(File, PathBuf, Vec<u16>)> {
    let name = destination.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "output path has no file name")
    })?;
    let name_utf16 = component_utf16(name)?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let handle = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | FILE_TRAVERSE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&parent)?;
    let metadata = handle.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output parent is not an ordinary directory",
        ));
    }
    Ok((handle, parent.join(name), name_utf16))
}

impl StagedOutput<'_> {
    fn publish(&mut self, parent: &File, name: &[u16]) -> io::Result<()> {
        let name_bytes = std::mem::size_of_val(name);
        let filename_offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
        let length = size_of::<FILE_RENAME_INFORMATION>() + name_bytes;
        let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
        let buffer = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: Storage is zeroed and pointer-aligned, and has room for the header and name.
        // Parent and source handles remain open for the call. The zeroed replace flag forbids clobbering.
        let status = unsafe {
            (*buffer).RootDirectory = parent.as_raw_handle();
            (*buffer).FileNameLength = name_bytes as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                storage
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(filename_offset)
                    .cast::<u16>(),
                name.len(),
            );
            NtSetInformationFile(
                self.object.as_raw_handle(),
                &mut status_block,
                buffer.cast(),
                length as u32,
                FileRenameInformation,
            )
        };
        if status < 0 {
            // SAFETY: The value is the NTSTATUS returned by NtSetInformationFile.
            return Err(io::Error::from_raw_os_error(
                unsafe { RtlNtStatusToDosError(status) } as i32,
            ));
        }
        self.cleanup_pending = false;
        Ok(())
    }

    fn finish(&mut self, result: io::Result<()>) -> io::Result<()> {
        let Err(error) = result else { return Ok(()) };
        match self.cleanup() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(io::Error::other(format!(
                "{error}. Staging cleanup also failed ({cleanup})"
            ))),
        }
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if !self.cleanup_pending {
            return Ok(());
        }
        self.cleanup_pending = false;
        let mut result = Ok(());
        for name in &self.children {
            // The staging directory is still held, private, and opened without delete sharing.
            let child = open_child(&self.object, OsStr::new(name), false, None)
                .and_then(|child| discard(&child));
            result = result.and(child);
        }
        result.and(discard(&self.object))
    }
}

fn discard(file: &File) -> io::Result<()> {
    let information = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: This requests deletion of the opened object when its handle closes.
    let marked = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&information as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if marked == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn component_utf16(name: &OsStr) -> io::Result<Vec<u16>> {
    let units: Vec<_> = name.encode_wide().take(256).collect();
    if units.is_empty()
        || units.len() > 255
        || units == [b'.' as u16]
        || units == [b'.' as u16, b'.' as u16]
        || units.iter().any(|&unit| {
            unit < 32 || u8::try_from(unit).is_ok_and(|byte| b"<>:\"/\\|?*".contains(&byte))
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output file name is not a valid single Windows component",
        ));
    }
    Ok(units)
}

fn open_child(
    parent: &File,
    name: &OsStr,
    directory: bool,
    descriptor: Option<&LocalAllocation>,
) -> io::Result<File> {
    let mut units = component_utf16(name)?;
    let length = (units.len() * size_of::<u16>()) as u16;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: descriptor.map_or(null(), |value| value.0.cast_const().cast()),
        SecurityQualityOfService: null(),
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle = null_mut();
    let options = FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        };
    let access = DELETE
        | SYNCHRONIZE
        | if descriptor.is_some() {
            GENERIC_WRITE
        } else {
            0
        };
    // SAFETY: The parent handle, descriptor, name, and output pointers remain valid for the synchronous call.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status_block,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            0,
            if descriptor.is_some() {
                FILE_CREATE
            } else {
                FILE_OPEN
            },
            options,
            null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: The value is the NTSTATUS returned by NtCreateFile.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    // SAFETY: A successful NtCreateFile returned a handle owned by this caller.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn validate_flat_file_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private output file name is not a bounded flat ASCII name",
        ));
    }
    Ok(())
}

fn create_stage<'a>(
    parent: &File,
    descriptor: &LocalAllocation,
    directory: bool,
) -> io::Result<StagedOutput<'a>> {
    for _ in 0..32 {
        let id = NEXT_STAGE_ID.fetch_add(1, Ordering::Relaxed);
        // SAFETY: GetCurrentProcessId takes no arguments.
        let name = format!(".sideeffect-private-{}-{id}", unsafe {
            GetCurrentProcessId()
        });
        match open_child(parent, OsStr::new(&name), directory, Some(descriptor)) {
            Ok(object) => {
                return Ok(StagedOutput {
                    object,
                    children: Vec::new(),
                    cleanup_pending: true,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique private staging object",
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
    // Pin the object owner to the token's user SID. Elevated runners may have a
    // different default owner (for example the Administrators group); the
    // private DACL alone does not guarantee that the creator's user SID owns it.
    let sddl = format!("O:{sid}D:P(A;;GA;;;{sid})");
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

    #[test]
    fn publishes_owner_private_directory_without_replacing_existing_destination() {
        let parent = temp_dir();
        let destination = parent.join("audit-session");
        let files = [
            ("session.json", b"{\"schema_version\":1}".as_slice()),
            ("processes.json", b"{\"schema_version\":1}".as_slice()),
        ];
        let published = publish_private_directory(&destination, &files, 1024).unwrap();

        assert_eq!(
            fs::read(published.join("session.json")).unwrap(),
            files[0].1
        );
        assert_eq!(
            fs::read(published.join("processes.json")).unwrap(),
            files[1].1
        );
        assert_owner_only_dacl(&published);
        assert_owner_only_dacl(&published.join("session.json"));
        assert_owner_only_dacl(&published.join("processes.json"));

        let error = publish_private_directory(&destination, &files, 1024).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(published.join("session.json")).unwrap(),
            files[0].1
        );

        fs::remove_file(published.join("session.json")).unwrap();
        fs::remove_file(published.join("processes.json")).unwrap();
        fs::remove_dir(published).unwrap();
        fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn private_directory_rejects_unsafe_names_and_total_size_before_staging() {
        let parent = temp_dir();
        let destination = parent.join("session");
        let traversal = [("../outside", b"x".as_slice())];
        assert_eq!(
            publish_private_directory(&destination, &traversal, 10)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let oversized = [("session.json", b"1234".as_slice())];
        assert_eq!(
            publish_private_directory(&destination, &oversized, 3)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!destination.exists());
        let entries = fs::read_dir(&parent).unwrap().count();
        assert_eq!(entries, 0);
        fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn stage_directory_remains_pinned_until_cleanup() {
        let root = temp_dir();
        let (parent, _, _) = open_output_parent(&root.join("audit")).unwrap();
        let descriptor = current_user_security_descriptor().unwrap();
        let mut stage = create_stage(&parent, &descriptor, true).unwrap();
        let name = "session.json";
        let child = open_child(&stage.object, OsStr::new(name), false, Some(&descriptor)).unwrap();
        stage.children.push(name);
        drop(child);

        let stage_path = fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
        assert!(fs::rename(&stage_path, root.join("other")).is_err());
        drop(stage);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        drop(parent);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn publication_error_reports_incomplete_staging_cleanup() {
        let root = temp_dir();
        let destination = root.join("audit");
        fs::create_dir(&destination).unwrap();
        let (parent, _, name) = open_output_parent(&destination).unwrap();
        let descriptor = current_user_security_descriptor().unwrap();
        let mut stage = create_stage(&parent, &descriptor, true).unwrap();
        let extra = OsStr::new("extra.json");
        drop(open_child(&stage.object, extra, false, Some(&descriptor)).unwrap());
        let stage_path = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path != &destination)
            .unwrap();

        let publication = stage.publish(&parent, &name);
        assert_eq!(
            publication.as_ref().unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let error = stage.finish(publication).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("Staging cleanup also failed"));
        drop(stage);
        assert!(destination.is_dir());
        fs::remove_file(stage_path.join(extra)).unwrap();
        fs::remove_dir(stage_path).unwrap();
        fs::remove_dir(destination).unwrap();
        drop(parent);
        fs::remove_dir(root).unwrap();
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
