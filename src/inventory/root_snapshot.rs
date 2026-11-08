//! Bounded snapshots of one explicitly selected directory level.
//!
//! The default collector reads metadata only. Explicit hashing reads bounded direct-child
//! regular-file contents. Neither mode descends into child directories.

use serde::Serialize;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const ROOT_SNAPSHOT_SCHEMA: &str = "sideeffect.selected_root_inventory";
pub const ROOT_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
pub const ROOT_SNAPSHOT_HASH_SCHEMA_VERSION: u32 = 2;
pub const MAX_ROOT_FILE_HASH_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_ROOT_AGGREGATE_HASH_BYTES: u64 = 64 * 1024 * 1024;
pub const ROOT_HASH_DEADLINE: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
pub const MAX_ROOT_PATH_BYTES_OR_UTF16_UNITS: usize = 4_095;
#[cfg(windows)]
pub const MAX_ROOT_PATH_BYTES_OR_UTF16_UNITS: usize = 32_766;
#[cfg(not(any(target_os = "linux", windows)))]
pub const MAX_ROOT_PATH_BYTES_OR_UTF16_UNITS: usize = 4_095;
pub const MAX_ROOT_ENTRIES: usize = 10_000;
pub const MAX_ROOT_NAME_BYTES_OR_UNITS: usize = 32_767;
pub const MAX_ROOT_AGGREGATE_NAME_BYTES: usize = 8 * 1024 * 1024;
pub const ROOT_SCAN_DEADLINE: Duration = Duration::from_secs(5);
const MAX_DIAGNOSTICS: usize = 256;

fn exceeds_limit(current: usize, addition: usize, maximum: usize) -> bool {
    addition > maximum
        || current
            .checked_add(addition)
            .is_none_or(|total| total > maximum)
}

fn entry_limit_reached(ordinal: usize) -> bool {
    ordinal >= MAX_ROOT_ENTRIES
}

#[derive(Clone, Debug, Serialize)]
pub struct RootSnapshot {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub captured_started_at_unix_ms: u128,
    pub captured_ended_at_unix_ms: u128,
    pub status: &'static str,
    pub root: Option<RootIdentity>,
    pub entries: Vec<RootEntry>,
    pub diagnostics: Vec<RootDiagnostic>,
    pub limits: RootSnapshotLimits,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hashing: Option<RootContentHashing>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootContentHashing {
    pub requested: bool,
    pub algorithm: &'static str,
    pub max_file_bytes: u64,
    pub max_aggregate_bytes: u64,
    pub deadline_seconds: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootIdentity {
    pub display_path: String,
    #[cfg(unix)]
    pub path_bytes_hex: String,
    #[cfg(windows)]
    pub path_utf16le_hex: String,
    pub object_type: &'static str,
    pub device_or_volume_serial: Option<u64>,
    pub inode_or_file_index: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootEntry {
    pub ordinal: usize,
    pub display_name: String,
    #[cfg(unix)]
    pub name_bytes_hex: String,
    #[cfg(windows)]
    pub name_utf16le_hex: String,
    pub object_type: &'static str,
    pub size_bytes: Option<u64>,
    pub modified_at_unix_ms: Option<i128>,
    /// File IDs are only point-in-time matching hints; they are not persistent identities.
    pub device_or_volume_serial: Option<u64>,
    /// File IDs are only point-in-time matching hints; they are not persistent identities.
    pub inode_or_file_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash_status: Option<&'static str>,
    pub evidence: RootEntryEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootEntryEvidence {
    pub source: &'static str,
    pub entry_ordinal: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootDiagnostic {
    pub code: &'static str,
    pub entry_ordinal: Option<usize>,
    pub native_error: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootSnapshotLimits {
    pub max_root_path_bytes_or_utf16_units: usize,
    pub max_entries: usize,
    pub max_name_bytes_or_utf16_units: usize,
    pub max_aggregate_name_bytes: usize,
    pub deadline_seconds: u64,
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn empty_snapshot(platform: &'static str, started: u128) -> RootSnapshot {
    RootSnapshot {
        schema: ROOT_SNAPSHOT_SCHEMA,
        schema_version: ROOT_SNAPSHOT_SCHEMA_VERSION,
        platform,
        scope: "one_explicit_root_and_its_direct_children_metadata_only",
        captured_started_at_unix_ms: started,
        captured_ended_at_unix_ms: now_unix_ms(),
        status: "partial",
        root: None,
        entries: Vec::new(),
        diagnostics: Vec::new(),
        limits: RootSnapshotLimits {
            max_root_path_bytes_or_utf16_units: MAX_ROOT_PATH_BYTES_OR_UTF16_UNITS,
            max_entries: MAX_ROOT_ENTRIES,
            max_name_bytes_or_utf16_units: MAX_ROOT_NAME_BYTES_OR_UNITS,
            max_aggregate_name_bytes: MAX_ROOT_AGGREGATE_NAME_BYTES,
            deadline_seconds: ROOT_SCAN_DEADLINE.as_secs(),
        },
        content_hashing: None,
    }
}

fn add_diagnostic(
    snapshot: &mut RootSnapshot,
    code: &'static str,
    ordinal: Option<usize>,
    error: Option<u32>,
) {
    if snapshot.diagnostics.len() < MAX_DIAGNOSTICS {
        snapshot.diagnostics.push(RootDiagnostic {
            code,
            entry_ordinal: ordinal,
            native_error: error,
        });
    } else if snapshot
        .diagnostics
        .last()
        .is_some_and(|item| item.code != "diagnostic_limit_reached")
    {
        if let Some(last) = snapshot.diagnostics.last_mut() {
            *last = RootDiagnostic {
                code: "diagnostic_limit_reached",
                entry_ordinal: None,
                native_error: None,
            };
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
    }

    fn exact_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            result.push(HEX[(byte >> 4) as usize] as char);
            result.push(HEX[(byte & 0x0f) as usize] as char);
        }
        result
    }

    fn object_type(mode: u32) -> &'static str {
        match mode & libc::S_IFMT {
            libc::S_IFREG => "regular_file",
            libc::S_IFDIR => "directory",
            libc::S_IFLNK => "symbolic_link",
            libc::S_IFIFO => "fifo",
            libc::S_IFSOCK => "socket",
            libc::S_IFCHR => "character_device",
            libc::S_IFBLK => "block_device",
            _ => "unknown",
        }
    }

    fn modified_ms(stat: &libc::stat) -> Option<i128> {
        i128::from(stat.st_mtime)
            .checked_mul(1_000)?
            .checked_add(i128::from(stat.st_mtime_nsec / 1_000_000))
    }

    pub fn collect(root_path: &Path, hash_regular_files: bool) -> RootSnapshot {
        let started = now_unix_ms();
        let start = Instant::now();
        let mut out = empty_snapshot("linux", started);
        configure_hashing(&mut out, hash_regular_files);
        let raw_path = root_path.as_os_str().as_bytes();
        if raw_path.is_empty()
            || exceeds_limit(0, raw_path.len(), MAX_ROOT_PATH_BYTES_OR_UTF16_UNITS)
            || raw_path.contains(&0)
        {
            add_diagnostic(&mut out, "root_path_invalid_or_over_limit", None, None);
            return finish(out);
        }
        let c_path = match CString::new(raw_path) {
            Ok(value) => value,
            Err(_) => {
                add_diagnostic(&mut out, "root_path_invalid_or_over_limit", None, None);
                return finish(out);
            }
        };
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            add_diagnostic(&mut out, "root_open_failed", None, Some(errno()));
            return finish(out);
        }
        let root_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut root_stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(root_fd.as_raw_fd(), &mut root_stat) } != 0 {
            add_diagnostic(&mut out, "root_metadata_failed", None, Some(errno()));
            return finish(out);
        }
        out.root = Some(RootIdentity {
            display_path: root_path.to_string_lossy().into_owned(),
            path_bytes_hex: exact_hex(raw_path),
            object_type: "directory",
            device_or_volume_serial: Some(root_stat.st_dev),
            inode_or_file_index: (root_stat.st_ino != 0).then_some(root_stat.st_ino),
        });
        let dup_fd = unsafe { libc::fcntl(root_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if dup_fd < 0 {
            add_diagnostic(&mut out, "root_enumeration_failed", None, Some(errno()));
            return finish(out);
        }
        let dir = Directory(unsafe { libc::fdopendir(dup_fd) });
        if dir.0.is_null() {
            unsafe {
                libc::close(dup_fd);
            }
            add_diagnostic(&mut out, "root_enumeration_failed", None, Some(errno()));
            return finish(out);
        }
        let mut aggregate = 0usize;
        let mut actual_hash_bytes = 0u64;
        let mut ordinal = 0usize;
        let mut complete = true;
        loop {
            if start.elapsed() >= ROOT_SCAN_DEADLINE {
                add_diagnostic(&mut out, "scan_deadline_exceeded", None, None);
                complete = false;
                break;
            }
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(dir.0) };
            if entry.is_null() {
                if errno() != 0 {
                    add_diagnostic(&mut out, "root_enumeration_failed", None, Some(errno()));
                    complete = false;
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let current_ordinal = ordinal;
            ordinal = ordinal.saturating_add(1);
            if entry_limit_reached(current_ordinal) {
                add_diagnostic(&mut out, "entry_limit_reached", Some(current_ordinal), None);
                complete = false;
                break;
            }
            if exceeds_limit(0, name.len(), MAX_ROOT_NAME_BYTES_OR_UNITS)
                || exceeds_limit(aggregate, name.len(), MAX_ROOT_AGGREGATE_NAME_BYTES)
            {
                add_diagnostic(
                    &mut out,
                    "name_data_limit_reached",
                    Some(current_ordinal),
                    None,
                );
                complete = false;
                break;
            }
            aggregate += name.len();
            let c_name = match CString::new(name) {
                Ok(value) => value,
                Err(_) => {
                    add_diagnostic(&mut out, "entry_name_invalid", Some(current_ordinal), None);
                    complete = false;
                    continue;
                }
            };
            let item_fd = unsafe {
                libc::openat(
                    root_fd.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if item_fd < 0 {
                add_diagnostic(
                    &mut out,
                    "entry_metadata_failed",
                    Some(current_ordinal),
                    Some(errno()),
                );
                if hash_regular_files {
                    add_diagnostic(
                        &mut out,
                        "content_hash_unavailable",
                        Some(current_ordinal),
                        Some(errno()),
                    );
                }
                complete = false;
                continue;
            }
            let item_fd = unsafe { OwnedFd::from_raw_fd(item_fd) };
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(item_fd.as_raw_fd(), &mut stat) } != 0 {
                add_diagnostic(
                    &mut out,
                    "entry_metadata_failed",
                    Some(current_ordinal),
                    Some(errno()),
                );
                if hash_regular_files {
                    add_diagnostic(
                        &mut out,
                        "content_hash_unavailable",
                        Some(current_ordinal),
                        Some(errno()),
                    );
                }
                complete = false;
                continue;
            }
            let name_os = std::ffi::OsString::from_vec(name.to_vec());
            let (content_sha256, content_hash_status) = if hash_regular_files {
                hash_file_at(
                    root_fd.as_raw_fd(),
                    c_name.as_ptr(),
                    &stat,
                    &mut RootFileHashContext {
                        ordinal: current_ordinal,
                        scan_start: start,
                        actual_bytes: &mut actual_hash_bytes,
                        out: &mut out,
                    },
                )
            } else {
                (None, None)
            };
            if content_hash_status == Some("unavailable") {
                complete = false;
            }
            out.entries.push(RootEntry {
                ordinal: current_ordinal,
                display_name: name_os.to_string_lossy().into_owned(),
                name_bytes_hex: exact_hex(name),
                object_type: object_type(stat.st_mode),
                size_bytes: u64::try_from(stat.st_size).ok(),
                modified_at_unix_ms: modified_ms(&stat),
                device_or_volume_serial: Some(stat.st_dev),
                inode_or_file_index: Some(stat.st_ino),
                content_sha256,
                content_hash_status,
                evidence: RootEntryEvidence {
                    source: "selected_root_directory_entry",
                    entry_ordinal: current_ordinal,
                },
            });
        }
        out.status = if complete { "complete" } else { "partial" };
        finish(out)
    }

    struct RootFileHashContext<'a> {
        ordinal: usize,
        scan_start: Instant,
        actual_bytes: &'a mut u64,
        out: &'a mut RootSnapshot,
    }

    impl RootFileHashContext<'_> {
        fn unavailable(&mut self, code: &'static str) -> (Option<String>, Option<&'static str>) {
            add_diagnostic(self.out, code, Some(self.ordinal), None);
            (None, Some("unavailable"))
        }
    }

    fn hash_file_at(
        root_fd: std::os::fd::RawFd,
        name: *const libc::c_char,
        listed: &libc::stat,
        context: &mut RootFileHashContext<'_>,
    ) -> (Option<String>, Option<&'static str>) {
        if listed.st_mode & libc::S_IFMT != libc::S_IFREG {
            return (None, Some("not_applicable"));
        }
        let size = match u64::try_from(listed.st_size) {
            Ok(value) => value,
            Err(_) => return context.unavailable("content_hash_metadata_invalid"),
        };
        if size > MAX_ROOT_FILE_HASH_BYTES {
            return context.unavailable("content_hash_file_limit_exceeded");
        }
        if context.scan_start.elapsed() >= ROOT_SCAN_DEADLINE
            || context.scan_start.elapsed() >= ROOT_HASH_DEADLINE
        {
            return context.unavailable("content_hash_deadline_exceeded");
        }
        let fd = unsafe {
            libc::openat(
                root_fd,
                name,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return context.unavailable("content_hash_open_failed");
        }
        let file = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut before: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut before) } != 0
            || before.st_mode & libc::S_IFMT != libc::S_IFREG
            || before.st_dev != listed.st_dev
            || before.st_ino != listed.st_ino
            || before.st_size != listed.st_size
            || before.st_mtime != listed.st_mtime
            || before.st_mtime_nsec != listed.st_mtime_nsec
            || before.st_ctime != listed.st_ctime
            || before.st_ctime_nsec != listed.st_ctime_nsec
        {
            return context.unavailable("content_hash_identity_changed");
        }
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut read_bytes = 0u64;
        loop {
            if context.scan_start.elapsed() >= ROOT_HASH_DEADLINE
                || context.scan_start.elapsed() >= ROOT_SCAN_DEADLINE
            {
                return context.unavailable("content_hash_deadline_exceeded");
            }
            if read_bytes == size {
                break;
            }
            let allowed = size
                .saturating_sub(read_bytes)
                .min(MAX_ROOT_FILE_HASH_BYTES.saturating_sub(read_bytes))
                .min(MAX_ROOT_AGGREGATE_HASH_BYTES.saturating_sub(*context.actual_bytes))
                .min(buffer.len() as u64) as usize;
            if allowed == 0 {
                let code = if *context.actual_bytes >= MAX_ROOT_AGGREGATE_HASH_BYTES {
                    "content_hash_aggregate_limit_exceeded"
                } else {
                    "content_hash_file_limit_exceeded"
                };
                return context.unavailable(code);
            }
            let count =
                unsafe { libc::read(file.as_raw_fd(), buffer.as_mut_ptr().cast(), allowed) };
            if count < 0 {
                if errno() == libc::EINTR as u32 {
                    continue;
                }
                return context.unavailable("content_hash_read_failed");
            }
            if count == 0 {
                break;
            }
            let count = count as usize;
            *context.actual_bytes += count as u64;
            read_bytes = match read_bytes.checked_add(count as u64) {
                Some(v) if v <= MAX_ROOT_FILE_HASH_BYTES => v,
                _ => return context.unavailable("content_hash_file_limit_exceeded"),
            };
            hasher.update(&buffer[..count]);
            if read_bytes == size {
                break;
            }
        }
        let mut after: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut after) } != 0
            || after.st_dev != before.st_dev
            || after.st_ino != before.st_ino
            || after.st_size != before.st_size
            || after.st_mtime != before.st_mtime
            || after.st_mtime_nsec != before.st_mtime_nsec
            || after.st_ctime != before.st_ctime
            || after.st_ctime_nsec != before.st_ctime_nsec
            || read_bytes != size
        {
            return context.unavailable("content_hash_identity_changed");
        }
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write;
            let _ = write!(hex, "{byte:02x}");
        }
        (Some(hex), Some("observed"))
    }

    fn errno() -> u32 {
        unsafe { *libc::__errno_location() as u32 }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_BOTH_DIR_INFO,
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TYPE_DISK, FileAttributeTagInfo, FileBasicInfo,
        FileIdBothDirectoryInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        GetFileType, OPEN_EXISTING,
    };

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn exact_utf16le_hex(units: &[u16]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(units.len().saturating_mul(4));
        for unit in units {
            for byte in unit.to_le_bytes() {
                result.push(HEX[(byte >> 4) as usize] as char);
                result.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
        result
    }
    fn filetime_unix_ms(ticks: i64) -> Option<i128> {
        i128::from(ticks)
            .checked_sub(116_444_736_000_000_000)?
            .checked_div(10_000)
    }

    struct RootFileHashContext<'a> {
        expected_volume: u32,
        ordinal: usize,
        scan_start: Instant,
        actual_bytes: &'a mut u64,
        out: &'a mut RootSnapshot,
    }

    impl RootFileHashContext<'_> {
        fn unavailable(&mut self, code: &'static str) -> (Option<String>, Option<&'static str>) {
            add_diagnostic(self.out, code, Some(self.ordinal), None);
            (None, Some("unavailable"))
        }
    }

    fn hash_file_at(
        root: &[u16],
        name: &[u16],
        listed: FILE_ID_BOTH_DIR_INFO,
        context: &mut RootFileHashContext<'_>,
    ) -> (Option<String>, Option<&'static str>) {
        use std::io::Read;
        use std::os::windows::io::FromRawHandle;
        let size = match u64::try_from(listed.EndOfFile) {
            Ok(value) => value,
            Err(_) => return context.unavailable("content_hash_metadata_invalid"),
        };
        if size > MAX_ROOT_FILE_HASH_BYTES {
            return context.unavailable("content_hash_file_limit_exceeded");
        }
        if context.scan_start.elapsed() >= ROOT_HASH_DEADLINE
            || context.scan_start.elapsed() >= ROOT_SCAN_DEADLINE
        {
            return context.unavailable("content_hash_deadline_exceeded");
        }
        let mut path = root.to_vec();
        if path
            .last()
            .is_some_and(|c| *c != b'\\' as u16 && *c != b'/' as u16)
        {
            path.push(b'\\' as u16);
        }
        path.extend_from_slice(name);
        path.push(0);
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                0x8000_0000 | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return context.unavailable("content_hash_open_failed");
        }
        if unsafe { GetFileType(raw) } != FILE_TYPE_DISK {
            unsafe {
                CloseHandle(raw);
            }
            return context.unavailable("content_hash_not_regular_file");
        }
        let mut before = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(raw, &mut before) } == 0 {
            unsafe {
                CloseHandle(raw);
            }
            return context.unavailable("content_hash_metadata_failed");
        }
        let id = (u64::from(before.nFileIndexHigh) << 32) | u64::from(before.nFileIndexLow);
        let listed_write = listed.LastWriteTime as u64;
        let before_write = ((before.ftLastWriteTime.dwHighDateTime as u64) << 32)
            | before.ftLastWriteTime.dwLowDateTime as u64;
        let before_size = (u64::from(before.nFileSizeHigh) << 32) | u64::from(before.nFileSizeLow);
        if before.dwFileAttributes
            & (FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
            || before.dwVolumeSerialNumber != context.expected_volume
            || id != listed.FileId as u64
            || before_size != size
            || before_write != listed_write
        {
            unsafe {
                CloseHandle(raw);
            }
            return context.unavailable("content_hash_identity_changed");
        }
        let mut basic_before = FILE_BASIC_INFO::default();
        if unsafe {
            GetFileInformationByHandleEx(
                raw,
                FileBasicInfo,
                (&mut basic_before as *mut FILE_BASIC_INFO).cast::<c_void>(),
                std::mem::size_of_val(&basic_before) as u32,
            )
        } == 0
        {
            unsafe {
                CloseHandle(raw);
            }
            return context.unavailable("content_hash_metadata_failed");
        }
        let mut file = unsafe { std::fs::File::from_raw_handle(raw as _) };
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut read_bytes = 0u64;
        loop {
            if context.scan_start.elapsed() >= ROOT_HASH_DEADLINE
                || context.scan_start.elapsed() >= ROOT_SCAN_DEADLINE
            {
                return context.unavailable("content_hash_deadline_exceeded");
            }
            if read_bytes == size {
                break;
            }
            let allowed = size
                .saturating_sub(read_bytes)
                .min(MAX_ROOT_FILE_HASH_BYTES.saturating_sub(read_bytes))
                .min(MAX_ROOT_AGGREGATE_HASH_BYTES.saturating_sub(*context.actual_bytes))
                .min(buffer.len() as u64) as usize;
            if allowed == 0 {
                let code = if *context.actual_bytes >= MAX_ROOT_AGGREGATE_HASH_BYTES {
                    "content_hash_aggregate_limit_exceeded"
                } else {
                    "content_hash_file_limit_exceeded"
                };
                return context.unavailable(code);
            }
            let count = match file.read(&mut buffer[..allowed]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => return context.unavailable("content_hash_read_failed"),
            };
            *context.actual_bytes += count as u64;
            read_bytes = match read_bytes.checked_add(count as u64) {
                Some(v) if v <= MAX_ROOT_FILE_HASH_BYTES => v,
                _ => return context.unavailable("content_hash_file_limit_exceeded"),
            };
            hasher.update(&buffer[..count]);
            if read_bytes == size {
                break;
            }
        }
        let mut after = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(raw, &mut after) } == 0 {
            return context.unavailable("content_hash_metadata_failed");
        }
        let mut basic_after = FILE_BASIC_INFO::default();
        if unsafe {
            GetFileInformationByHandleEx(
                raw,
                FileBasicInfo,
                (&mut basic_after as *mut FILE_BASIC_INFO).cast::<c_void>(),
                std::mem::size_of_val(&basic_after) as u32,
            )
        } == 0
        {
            return context.unavailable("content_hash_metadata_failed");
        }
        let after_id = (u64::from(after.nFileIndexHigh) << 32) | u64::from(after.nFileIndexLow);
        let after_write = ((after.ftLastWriteTime.dwHighDateTime as u64) << 32)
            | after.ftLastWriteTime.dwLowDateTime as u64;
        let after_size = (u64::from(after.nFileSizeHigh) << 32) | u64::from(after.nFileSizeLow);
        if after_id != id
            || after_size != before_size
            || after_write != before_write
            || basic_after.ChangeTime != basic_before.ChangeTime
            || read_bytes != size
        {
            return context.unavailable("content_hash_identity_changed");
        }
        let mut hex = String::with_capacity(64);
        for byte in hasher.finalize() {
            use std::fmt::Write;
            let _ = write!(hex, "{byte:02x}");
        }
        (Some(hex), Some("observed"))
    }

    pub fn collect(root_path: &Path, hash_regular_files: bool) -> RootSnapshot {
        let started = now_unix_ms();
        let start = Instant::now();
        let mut out = empty_snapshot("windows", started);
        configure_hashing(&mut out, hash_regular_files);
        let units = root_path.as_os_str().encode_wide().collect::<Vec<_>>();
        if units.is_empty()
            || exceeds_limit(0, units.len(), MAX_ROOT_PATH_BYTES_OR_UTF16_UNITS)
            || units.contains(&0)
        {
            add_diagnostic(&mut out, "root_path_invalid_or_over_limit", None, None);
            return finish(out);
        }
        let mut nul_path = units.clone();
        nul_path.push(0);
        let raw = unsafe {
            CreateFileW(
                nul_path.as_ptr(),
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            add_diagnostic(
                &mut out,
                "root_open_failed",
                None,
                Some(unsafe { GetLastError() }),
            );
            return finish(out);
        }
        let root = HandleGuard(raw);
        if unsafe { GetFileType(raw) } != FILE_TYPE_DISK {
            add_diagnostic(&mut out, "root_not_directory", None, None);
            return finish(out);
        }
        let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
        if unsafe {
            GetFileInformationByHandleEx(
                raw,
                FileAttributeTagInfo,
                (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast::<c_void>(),
                std::mem::size_of_val(&tag) as u32,
            )
        } == 0
        {
            add_diagnostic(
                &mut out,
                "root_metadata_failed",
                None,
                Some(unsafe { GetLastError() }),
            );
            return finish(out);
        }
        if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        {
            add_diagnostic(&mut out, "root_reparse_or_not_directory", None, None);
            return finish(out);
        }
        let mut root_info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(raw, &mut root_info) } == 0 {
            add_diagnostic(
                &mut out,
                "root_metadata_failed",
                None,
                Some(unsafe { GetLastError() }),
            );
            return finish(out);
        }
        out.root = Some(RootIdentity {
            display_path: root_path.to_string_lossy().into_owned(),
            path_utf16le_hex: exact_utf16le_hex(&units),
            object_type: "directory",
            device_or_volume_serial: (root_info.dwVolumeSerialNumber != 0)
                .then_some(u64::from(root_info.dwVolumeSerialNumber)),
            inode_or_file_index: {
                let id = (u64::from(root_info.nFileIndexHigh) << 32)
                    | u64::from(root_info.nFileIndexLow);
                (id != 0).then_some(id)
            },
        });
        let mut aggregate = 0usize;
        let mut ordinal = 0usize;
        let mut actual_hash_bytes = 0u64;
        let mut complete = true;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            if start.elapsed() >= ROOT_SCAN_DEADLINE {
                add_diagnostic(&mut out, "scan_deadline_exceeded", None, None);
                complete = false;
                break;
            }
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    raw,
                    FileIdBothDirectoryInfo,
                    buffer.as_mut_ptr().cast::<c_void>(),
                    buffer.len() as u32,
                )
            };
            if ok == 0 {
                let error = unsafe { GetLastError() };
                if error != 18 {
                    add_diagnostic(&mut out, "root_enumeration_failed", None, Some(error));
                    complete = false;
                }
                break;
            }
            let mut offset = 0usize;
            loop {
                let header_len = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
                if offset
                    .checked_add(header_len)
                    .is_none_or(|end| end > buffer.len())
                {
                    add_diagnostic(&mut out, "directory_record_malformed", Some(ordinal), None);
                    complete = false;
                    break;
                }
                let row = unsafe {
                    ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<FILE_ID_BOTH_DIR_INFO>())
                };
                let name_len = row.FileNameLength as usize;
                let _record_end = match offset
                    .checked_add(header_len)
                    .and_then(|start| start.checked_add(name_len))
                {
                    Some(end) if name_len % 2 == 0 && end <= buffer.len() => end,
                    _ => {
                        add_diagnostic(&mut out, "directory_record_malformed", Some(ordinal), None);
                        complete = false;
                        break;
                    }
                };
                let name = unsafe {
                    std::slice::from_raw_parts(
                        buffer.as_ptr().add(offset + header_len).cast::<u16>(),
                        name_len / 2,
                    )
                };
                if name.contains(&0) {
                    add_diagnostic(&mut out, "directory_record_malformed", Some(ordinal), None);
                    complete = false;
                    break;
                }
                if name != [46] && name != [46, 46] {
                    let current = ordinal;
                    ordinal = ordinal.saturating_add(1);
                    let name_units = name_len / 2;
                    if entry_limit_reached(current) {
                        add_diagnostic(&mut out, "entry_limit_reached", Some(current), None);
                        complete = false;
                        break;
                    }
                    if exceeds_limit(0, name_units, MAX_ROOT_NAME_BYTES_OR_UNITS)
                        || exceeds_limit(aggregate, name_len, MAX_ROOT_AGGREGATE_NAME_BYTES)
                    {
                        add_diagnostic(&mut out, "name_data_limit_reached", Some(current), None);
                        complete = false;
                        break;
                    }
                    aggregate += name_len;
                    let entry_file_id = row.FileId as u64;
                    let kind = if row.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                        "reparse_point"
                    } else if row.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                        "directory"
                    } else {
                        "regular_or_other_file"
                    };
                    let (content_sha256, content_hash_status) = if hash_regular_files
                        && kind == "regular_or_other_file"
                        && row.FileAttributes & FILE_ATTRIBUTE_DEVICE == 0
                    {
                        hash_file_at(
                            &units,
                            name,
                            row,
                            &mut RootFileHashContext {
                                expected_volume: root_info.dwVolumeSerialNumber,
                                ordinal: current,
                                scan_start: start,
                                actual_bytes: &mut actual_hash_bytes,
                                out: &mut out,
                            },
                        )
                    } else if hash_regular_files {
                        (None, Some("not_applicable"))
                    } else {
                        (None, None)
                    };
                    if content_hash_status == Some("unavailable") {
                        complete = false;
                    }
                    out.entries.push(RootEntry {
                        ordinal: current,
                        display_name: String::from_utf16_lossy(name),
                        name_utf16le_hex: exact_utf16le_hex(name),
                        object_type: kind,
                        size_bytes: u64::try_from(row.EndOfFile).ok(),
                        modified_at_unix_ms: filetime_unix_ms(row.LastWriteTime),
                        device_or_volume_serial: (root_info.dwVolumeSerialNumber != 0)
                            .then_some(u64::from(root_info.dwVolumeSerialNumber)),
                        inode_or_file_index: (entry_file_id != 0).then_some(entry_file_id),
                        content_sha256,
                        content_hash_status,
                        evidence: RootEntryEvidence {
                            source: "selected_root_directory_entry",
                            entry_ordinal: current,
                        },
                    });
                }
                if row.NextEntryOffset == 0 {
                    break;
                }
                let next = row.NextEntryOffset as usize;
                if next < header_len.saturating_add(name_len)
                    || offset.checked_add(next).is_none_or(|v| v >= buffer.len())
                {
                    add_diagnostic(&mut out, "directory_record_malformed", Some(ordinal), None);
                    complete = false;
                    break;
                }
                offset += next;
            }
            if !complete {
                break;
            }
            // A successful batch is followed by another query; Windows advances the handle cursor.
        }
        out.status = if complete { "complete" } else { "partial" };
        drop(root);
        finish(out)
    }

    #[cfg(test)]
    mod tests {
        use super::exact_utf16le_hex;

        #[test]
        fn exact_utf16_encoding_preserves_unpaired_surrogate_units() {
            assert_eq!(exact_utf16le_hex(&[0xd800, b'A' as u16]), "00d84100");
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::*;
    pub fn collect(_root_path: &Path, hash_regular_files: bool) -> RootSnapshot {
        let mut out = empty_snapshot("unsupported", now_unix_ms());
        configure_hashing(&mut out, hash_regular_files);
        add_diagnostic(&mut out, "platform_unsupported", None, None);
        finish(out)
    }
}

pub fn collect_root_snapshot(root_path: &Path) -> RootSnapshot {
    collect_root_snapshot_with_hash(root_path, false)
}

pub fn collect_root_snapshot_with_hash(root_path: &Path, hash_regular_files: bool) -> RootSnapshot {
    platform::collect(root_path, hash_regular_files)
}

fn configure_hashing(snapshot: &mut RootSnapshot, requested: bool) {
    if requested {
        snapshot.schema_version = ROOT_SNAPSHOT_HASH_SCHEMA_VERSION;
        snapshot.scope = "one_explicit_root_and_its_direct_children_metadata_and_opt_in_sha256";
        snapshot.content_hashing = Some(RootContentHashing {
            requested: true,
            algorithm: "sha256",
            max_file_bytes: MAX_ROOT_FILE_HASH_BYTES,
            max_aggregate_bytes: MAX_ROOT_AGGREGATE_HASH_BYTES,
            deadline_seconds: ROOT_HASH_DEADLINE.as_secs(),
        });
    }
}

fn finish(mut output: RootSnapshot) -> RootSnapshot {
    output.captured_ended_at_unix_ms = now_unix_ms();
    output
}

#[cfg(test)]
mod tests {
    use super::{entry_limit_reached, exceeds_limit, *};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture_dir(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sideeffect-root-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn bounds_accept_exact_limit_and_reject_overflow_or_one_over() {
        assert!(!exceeds_limit(2, 1, 3));
        assert!(exceeds_limit(2, 2, 3));
        assert!(exceeds_limit(usize::MAX, 1, usize::MAX));
        assert!(!entry_limit_reached(MAX_ROOT_ENTRIES - 1));
        assert!(entry_limit_reached(MAX_ROOT_ENTRIES));
    }

    #[test]
    fn empty_and_oversized_root_paths_are_partial_before_filesystem_access() {
        let empty = collect_root_snapshot(Path::new(""));
        assert_eq!(empty.status, "partial");
        assert_eq!(empty.diagnostics[0].code, "root_path_invalid_or_over_limit");

        #[cfg(target_os = "linux")]
        let oversized = {
            use std::os::unix::ffi::OsStringExt;
            Path::new(&std::ffi::OsString::from_vec(vec![
                b'x';
                MAX_ROOT_PATH_BYTES_OR_UTF16_UNITS
                    + 1
            ]))
            .to_path_buf()
        };
        #[cfg(windows)]
        let oversized = {
            use std::os::windows::ffi::OsStringExt;
            Path::new(&std::ffi::OsString::from_wide(&vec![
                b'x' as u16;
                MAX_ROOT_PATH_BYTES_OR_UTF16_UNITS
                    + 1
            ]))
            .to_path_buf()
        };
        let over = collect_root_snapshot(&oversized);
        assert_eq!(over.status, "partial");
        assert_eq!(over.diagnostics[0].code, "root_path_invalid_or_over_limit");
    }

    #[test]
    fn snapshots_only_direct_children_and_preserves_evidence_ordinals() {
        let root = fixture_dir("children");
        fs::write(root.join("one.txt"), b"contents are never read").unwrap();
        fs::create_dir(root.join("nested")).unwrap();
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::symlink;
            let outside = fixture_dir("outside");
            fs::write(outside.join("must-not-appear"), b"fixture").unwrap();
            symlink(&outside, root.join("link-out")).unwrap();
            let output = collect_root_snapshot(&root);
            assert_eq!(output.status, "complete");
            assert!(
                output
                    .entries
                    .iter()
                    .any(|item| item.object_type == "symbolic_link")
            );
            assert!(
                !output
                    .entries
                    .iter()
                    .any(|item| item.display_name == "must-not-appear")
            );
            fs::remove_dir_all(outside).unwrap();
        }
        let output = collect_root_snapshot(&root);
        assert_eq!(output.status, "complete");
        #[cfg(target_os = "linux")]
        assert_eq!(output.entries.len(), 3);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(output.entries.len(), 2);
        assert!(
            output
                .entries
                .iter()
                .all(|item| item.evidence.entry_ordinal == item.ordinal)
        );
        assert!(
            output
                .entries
                .iter()
                .any(|item| item.object_type == "directory")
        );
        assert!(
            !output
                .entries
                .iter()
                .any(|item| item.display_name == "contents are never read")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preserves_exact_non_utf8_entry_name_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let root = fixture_dir("non-utf8");
        let name = OsString::from_vec(vec![0xff, b'x']);
        fs::write(root.join(name), b"fixture").unwrap();
        let output = collect_root_snapshot(&root);
        assert_eq!(output.status, "complete");
        assert_eq!(output.entries.len(), 1);
        assert_eq!(output.entries[0].name_bytes_hex, "ff78");
        assert!(!output.entries[0].display_name.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inaccessible_selected_root_is_partial_with_access_denied_diagnostic() {
        use std::os::unix::fs::PermissionsExt;

        // Permission checks are bypassed for root, so this fixture is meaningful only
        // when the test process runs with an ordinary user token.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping permission-denial fixture because the test process is root");
            return;
        }

        let root = fixture_dir("denied-root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o0)).unwrap();
        let output = collect_root_snapshot(&root);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(output.status, "partial");
        assert!(output.root.is_none());
        assert!(output.entries.is_empty());
        assert_eq!(output.diagnostics.len(), 1);
        assert_eq!(output.diagnostics[0].code, "root_open_failed");
        assert_eq!(
            output.diagnostics[0].native_error,
            Some(libc::EACCES as u32)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_metadata_denial_keeps_root_and_reports_partial_entry() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping permission-denial fixture because the test process is root");
            return;
        }

        let root = fixture_dir("denied-child-metadata");
        fs::write(root.join("inaccessible-child"), b"synthetic fixture").unwrap();
        // Read permission allows readdir; missing search permission makes the
        // subsequent handle-relative openat for each child fail with EACCES.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o400)).unwrap();
        let output = collect_root_snapshot(&root);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(output.status, "partial");
        assert!(output.root.is_some());
        assert!(output.entries.is_empty());
        assert_eq!(output.diagnostics.len(), 1);
        assert_eq!(output.diagnostics[0].code, "entry_metadata_failed");
        assert_eq!(output.diagnostics[0].entry_ordinal, Some(0));
        assert_eq!(
            output.diagnostics[0].native_error,
            Some(libc::EACCES as u32)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn root_reparse_points_are_rejected_when_symlink_fixtures_are_available() {
        use std::os::windows::fs::symlink_dir;
        let parent = fixture_dir("reparse-parent");
        let target = fixture_dir("reparse-target");
        fs::write(target.join("must-not-appear"), b"synthetic fixture").unwrap();
        let selected = parent.join("selected");
        fs::create_dir(&selected).unwrap();
        let child_link = selected.join("child-reparse");
        if symlink_dir(&target, &child_link).is_err() {
            eprintln!("reparse fixture unavailable: creating a directory symlink was denied");
            let _ = fs::remove_dir_all(target);
            let _ = fs::remove_dir_all(parent);
            return;
        }
        let child_output = collect_root_snapshot(&selected);
        assert_eq!(child_output.status, "complete");
        assert!(child_output.entries.iter().any(|entry| {
            entry.display_name == "child-reparse" && entry.object_type == "reparse_point"
        }));
        assert!(
            !child_output
                .entries
                .iter()
                .any(|entry| entry.display_name == "must-not-appear")
        );

        let link = parent.join("root-link");
        symlink_dir(&target, &link).unwrap();
        let output = collect_root_snapshot(&link);
        assert_eq!(output.status, "partial");
        assert!(output.root.is_none());
        assert_eq!(output.diagnostics[0].code, "root_reparse_or_not_directory");
        fs::remove_dir(link).unwrap();
        fs::remove_dir(child_link).unwrap();
        fs::remove_dir(selected).unwrap();
        fs::remove_dir_all(target).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn empty_selected_root_is_complete_and_final_symlink_is_not_followed() {
        let root = fixture_dir("empty");
        let output = collect_root_snapshot(&root);
        assert_eq!(output.status, "complete");
        assert!(output.entries.is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = root.with_extension("link");
            symlink(&root, &link).unwrap();
            let linked = collect_root_snapshot(&link);
            assert_eq!(linked.status, "partial");
            assert!(linked.root.is_none());
            let _ = fs::remove_file(link);
        }
        fs::remove_dir_all(root).unwrap();
    }
}
