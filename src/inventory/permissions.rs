//! Bounded, explicit-path Linux file metadata and POSIX ACL inventory.

use crate::fingerprint::sha256_hex;
use serde::Serialize;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_PERMISSION_PATHS: usize = 256;
pub const MAX_PERMISSION_PATH_BYTES: usize = 4096;
pub const MAX_ACL_XATTR_BYTES: usize = 64 * 1024;
pub const MAX_PERMISSION_TOTAL_ACL_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PERMISSION_SCAN_DURATION: Duration = Duration::from_secs(5);

const ACL_XATTR_ACCESS: &[u8] = b"system.posix_acl_access\0";
const ACL_XATTR_DEFAULT: &[u8] = b"system.posix_acl_default\0";
const ACL_XATTR_VERSION: u32 = 0x0002;
const ACL_UNDEFINED_ID: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionInventoryStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionObjectStatus {
    Complete,
    Partial,
    Unavailable,
    AccessDenied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AclStatus {
    Present,
    Absent,
    NotApplicable,
    Inaccessible,
    Unsupported,
    Malformed,
    LimitExceeded,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct PermissionInventoryDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub captured_at_unix_ms: u128,
    pub status: PermissionInventoryStatus,
    pub paths_requested: usize,
    pub acl_bytes_read: usize,
    pub objects: Vec<PermissionObject>,
    pub diagnostics: Vec<PermissionDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PermissionObject {
    /// UTF-8 path for display; exact Unix path bytes are always retained separately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub path_bytes_hex: String,
    pub status: PermissionObjectStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inode: Option<u64>,
    pub access_acl: AclObservation,
    pub default_acl: AclObservation,
    pub diagnostics: Vec<PermissionDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AclObservation {
    pub status: AclStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<AclEntry>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AclTag {
    UserObject,
    User,
    GroupObject,
    Group,
    Mask,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AclDecodeError {
    InvalidFormat,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AclEntry {
    pub tag: AclTag,
    pub permissions: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PermissionDiagnostic {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_index: Option<usize>,
    pub source: Option<&'static str>,
    pub message: &'static str,
}

#[derive(Clone, Copy)]
struct Limits {
    paths: usize,
    path_bytes: usize,
    acl_bytes: usize,
    total_acl_bytes: usize,
    scan_duration: Duration,
}

const LIMITS: Limits = Limits {
    paths: MAX_PERMISSION_PATHS,
    path_bytes: MAX_PERMISSION_PATH_BYTES,
    acl_bytes: MAX_ACL_XATTR_BYTES,
    total_acl_bytes: MAX_PERMISSION_TOTAL_ACL_BYTES,
    scan_duration: MAX_PERMISSION_SCAN_DURATION,
};

pub fn collect_permissions(paths: &[PathBuf]) -> PermissionInventoryDocument {
    collect_with_limits(paths, LIMITS)
}

fn collect_with_limits(paths: &[PathBuf], limits: Limits) -> PermissionInventoryDocument {
    let captured_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let mut objects = Vec::new();
    let mut diagnostics = Vec::new();
    let mut acl_bytes_read = 0usize;
    let mut partial = false;
    let count = paths.len().min(limits.paths);
    let started = Instant::now();
    for (index, path) in paths.iter().take(count).enumerate() {
        // This is a between-path deadline: a blocked kernel/filesystem syscall cannot be safely
        // canceled here and may extend wall-clock time beyond the configured interval.
        if started.elapsed() >= limits.scan_duration {
            partial = true;
            diagnostics.push(PermissionDiagnostic {
                code: "scan_deadline_exceeded",
                path_index: Some(index),
                source: None,
                message: "The permission scan time limit was reached; remaining paths were not checked.",
            });
            break;
        }
        if path.as_os_str().as_bytes().len() > limits.path_bytes {
            partial = true;
            diagnostics.push(PermissionDiagnostic {
                code: "path_limit_exceeded",
                path_index: Some(index),
                source: None,
                message: "The selected path exceeded the path byte limit and was not checked.",
            });
            continue;
        }
        let (object, read, has_partial) = collect_one(path, index, acl_bytes_read, limits);
        acl_bytes_read = acl_bytes_read.saturating_add(read);
        partial |= has_partial;
        objects.push(object);
    }
    if paths.len() > limits.paths {
        partial = true;
        diagnostics.push(PermissionDiagnostic {
            code: "path_count_limit_exceeded",
            path_index: Some(limits.paths),
            source: None,
            message: "The selected path count limit was reached; remaining paths were not checked.",
        });
    }
    PermissionInventoryDocument {
        schema: "sideeffect.permission_inventory",
        schema_version: 1,
        platform: "linux",
        scope: "explicit_paths_metadata_posix_acl",
        captured_at_unix_ms,
        status: if partial {
            PermissionInventoryStatus::Partial
        } else {
            PermissionInventoryStatus::Complete
        },
        paths_requested: paths.len(),
        acl_bytes_read,
        objects,
        diagnostics,
    }
}

fn collect_one(
    path: &Path,
    index: usize,
    total_read: usize,
    limits: Limits,
) -> (PermissionObject, usize, bool) {
    let path_bytes = path.as_os_str().as_bytes();
    let mut row = PermissionObject {
        path: path.to_str().map(str::to_owned),
        path_bytes_hex: hex(path_bytes),
        status: PermissionObjectStatus::Complete,
        object_type: None,
        uid: None,
        gid: None,
        mode: None,
        device: None,
        inode: None,
        access_acl: acl_initial(AclStatus::Failed, "system.posix_acl_access"),
        default_acl: acl_initial(AclStatus::NotApplicable, "system.posix_acl_default"),
        diagnostics: Vec::new(),
    };
    let c_path = match std::ffi::CString::new(path_bytes) {
        Ok(path) => path,
        Err(_) => {
            row.status = PermissionObjectStatus::Partial;
            row.default_acl.status = AclStatus::Failed;
            row.diagnostics.push(PermissionDiagnostic {
                code: "path_invalid",
                path_index: Some(index),
                source: None,
                message: "The selected path contains a NUL byte and was not checked.",
            });
            return (row, 0, true);
        }
    };
    // Pin the final path component first without opening a device or following a final symlink.
    // ACL reads use a read-only descriptor reopened through this pinned descriptor via procfs.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        let (status, code, message) = if error.kind() == io::ErrorKind::PermissionDenied {
            (
                PermissionObjectStatus::AccessDenied,
                "path_access_denied",
                "The selected path could not be opened with current-user permissions.",
            )
        } else if error.kind() == io::ErrorKind::NotFound {
            (
                PermissionObjectStatus::Unavailable,
                "path_unavailable",
                "The selected path was unavailable when checked.",
            )
        } else if error.raw_os_error() == Some(libc::ELOOP) {
            (
                PermissionObjectStatus::Partial,
                "final_symlink_not_followed",
                "The final path component is a symlink and was not followed.",
            )
        } else {
            (
                PermissionObjectStatus::Partial,
                "path_open_failed",
                "The selected path could not be opened and was not fully checked.",
            )
        };
        row.status = status;
        row.access_acl.status = AclStatus::Inaccessible;
        row.default_acl.status = AclStatus::Inaccessible;
        row.diagnostics.push(PermissionDiagnostic {
            code,
            path_index: Some(index),
            source: None,
            message,
        });
        return (row, 0, true);
    }
    // SAFETY: open returned a new owned file descriptor.
    let pinned = unsafe { File::from_raw_fd(fd) };
    let stat = match stat_fd(pinned.as_raw_fd()) {
        Ok(stat) => stat,
        Err(_) => {
            row.status = PermissionObjectStatus::Partial;
            row.access_acl.status = AclStatus::Failed;
            row.default_acl.status = AclStatus::Failed;
            row.diagnostics.push(PermissionDiagnostic {
                code: "metadata_unavailable",
                path_index: Some(index),
                source: Some("fstat"),
                message: "File metadata could not be read from the pinned object.",
            });
            return (row, 0, true);
        }
    };
    let kind = stat.st_mode & libc::S_IFMT;
    row.object_type = match kind {
        libc::S_IFREG => Some("regular_file"),
        libc::S_IFDIR => Some("directory"),
        libc::S_IFLNK => Some("symlink"),
        _ => Some("other"),
    };
    row.uid = Some(stat.st_uid);
    row.gid = Some(stat.st_gid);
    row.mode = Some(stat.st_mode as u32 & 0o7777);
    row.device = Some(stat.st_dev as u64);
    row.inode = Some(stat.st_ino as u64);
    if kind == libc::S_IFLNK {
        row.status = PermissionObjectStatus::Partial;
        row.access_acl.status = AclStatus::Unsupported;
        row.default_acl.status = AclStatus::NotApplicable;
        row.diagnostics.push(PermissionDiagnostic {
            code: "final_symlink_not_followed",
            path_index: Some(index),
            source: Some("fstat"),
            message: "The final path component is a symlink; its target was not followed and ACLs were not read.",
        });
        return (row, 0, true);
    }
    if kind != libc::S_IFREG && kind != libc::S_IFDIR {
        row.status = PermissionObjectStatus::Partial;
        row.access_acl.status = AclStatus::Unsupported;
        row.default_acl.status = AclStatus::NotApplicable;
        row.diagnostics.push(PermissionDiagnostic {
            code: "object_type_unsupported",
            path_index: Some(index),
            source: Some("fstat"),
            message: "Only regular files and directories are supported; no ACL was read.",
        });
        return (row, 0, true);
    }
    let readable_fd = match reopen_pinned_readonly(pinned.as_raw_fd(), &stat) {
        Ok(file) => file,
        Err(error) => {
            let code = if error.kind() == io::ErrorKind::PermissionDenied {
                "acl_access_denied"
            } else {
                "acl_descriptor_unavailable"
            };
            row.status = PermissionObjectStatus::Partial;
            row.access_acl.status = AclStatus::Inaccessible;
            row.default_acl.status = if kind == libc::S_IFDIR {
                AclStatus::Inaccessible
            } else {
                AclStatus::NotApplicable
            };
            row.diagnostics.push(PermissionDiagnostic {
                code,
                path_index: Some(index),
                source: Some("fgetxattr"),
                message: "ACL data could not be read using current-user permissions.",
            });
            return (row, 0, true);
        }
    };
    let mut read = 0usize;
    let mut partial = false;
    row.access_acl = read_acl(
        readable_fd.as_raw_fd(),
        ACL_XATTR_ACCESS,
        "system.posix_acl_access",
        index,
        total_read,
        limits,
        &mut read,
        &mut row.diagnostics,
    );
    if row.access_acl.status != AclStatus::Present && row.access_acl.status != AclStatus::Absent {
        partial = true;
    }
    if kind == libc::S_IFDIR {
        row.default_acl = read_acl(
            readable_fd.as_raw_fd(),
            ACL_XATTR_DEFAULT,
            "system.posix_acl_default",
            index,
            total_read.saturating_add(read),
            limits,
            &mut read,
            &mut row.diagnostics,
        );
        if row.default_acl.status != AclStatus::Present
            && row.default_acl.status != AclStatus::Absent
        {
            partial = true;
        }
    }
    if partial {
        row.status = PermissionObjectStatus::Partial;
    }
    (row, read, partial)
}

fn stat_fd(fd: i32) -> io::Result<libc::stat> {
    // SAFETY: stat is initialized by fstat on success.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn reopen_pinned_readonly(fd: i32, original: &libc::stat) -> io::Result<File> {
    let proc_path = CString::new(format!("/proc/self/fd/{fd}")).expect("fixed descriptor path");
    let reopened = unsafe {
        libc::open(
            proc_path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if reopened < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a new owned file descriptor.
    let file = unsafe { File::from_raw_fd(reopened) };
    let stat = stat_fd(file.as_raw_fd())?;
    if stat.st_dev != original.st_dev
        || stat.st_ino != original.st_ino
        || stat.st_mode & libc::S_IFMT != original.st_mode & libc::S_IFMT
    {
        return Err(io::Error::other("pinned object identity changed"));
    }
    Ok(file)
}

#[allow(clippy::too_many_arguments)]
fn read_acl(
    fd: i32,
    name: &'static [u8],
    source: &'static str,
    index: usize,
    total_read: usize,
    limits: Limits,
    read: &mut usize,
    diagnostics: &mut Vec<PermissionDiagnostic>,
) -> AclObservation {
    let name_ptr = name.as_ptr().cast::<libc::c_char>();
    let size = unsafe { libc::fgetxattr(fd, name_ptr, std::ptr::null_mut(), 0) };
    if size < 0 {
        let error = io::Error::last_os_error();
        let status = if error.raw_os_error() == Some(libc::ENODATA) {
            AclStatus::Absent
        } else if error.kind() == io::ErrorKind::PermissionDenied {
            AclStatus::Inaccessible
        } else if error.raw_os_error() == Some(libc::EOPNOTSUPP) {
            AclStatus::Unsupported
        } else {
            AclStatus::Failed
        };
        if status != AclStatus::Absent {
            diagnostics.push(PermissionDiagnostic {
                code: acl_diagnostic_code(status),
                path_index: Some(index),
                source: Some(source),
                message: acl_diagnostic_message(status),
            });
        }
        return acl_initial(status, source);
    }
    let size = size as usize;
    let aggregate_remaining = limits.total_acl_bytes.saturating_sub(total_read);
    if size > limits.acl_bytes || size > aggregate_remaining {
        diagnostics.push(PermissionDiagnostic {
            code: "acl_byte_limit_exceeded",
            path_index: Some(index),
            source: Some(source),
            message: "ACL xattr exceeded a configured byte limit and was not retained.",
        });
        return acl_initial(AclStatus::LimitExceeded, source);
    }
    let mut bytes = vec![0u8; size];
    let actual = unsafe { libc::fgetxattr(fd, name_ptr, bytes.as_mut_ptr().cast(), bytes.len()) };
    if actual < 0 {
        let error = io::Error::last_os_error();
        let status = if error.kind() == io::ErrorKind::PermissionDenied {
            AclStatus::Inaccessible
        } else if error.raw_os_error() == Some(libc::EOPNOTSUPP) {
            AclStatus::Unsupported
        } else {
            AclStatus::Failed
        };
        diagnostics.push(PermissionDiagnostic {
            code: acl_diagnostic_code(status),
            path_index: Some(index),
            source: Some(source),
            message: "ACL xattr changed or could not be read after its bounded size probe.",
        });
        return acl_initial(status, source);
    }
    let actual = actual as usize;
    bytes.truncate(actual);
    *read = read.saturating_add(actual);
    if actual != size {
        diagnostics.push(PermissionDiagnostic {
            code: "acl_changed_during_read",
            path_index: Some(index),
            source: Some(source),
            message: "ACL xattr size changed between the bounded size probe and read; raw bytes were retained but not decoded.",
        });
        return AclObservation {
            status: AclStatus::Failed,
            source: Some(source),
            byte_length: Some(actual),
            bytes_hex: Some(hex(&bytes)),
            sha256: Some(sha256_hex(&bytes)),
            entries: None,
        };
    }
    let decoded = decode_posix_acl(&bytes);
    let (status, entries) = match decoded {
        Ok(entries) => (AclStatus::Present, Some(entries)),
        Err(AclDecodeError::InvalidFormat) => {
            diagnostics.push(PermissionDiagnostic {
                code: "acl_malformed",
                path_index: Some(index),
                source: Some(source),
                message: "ACL xattr bytes did not match the supported POSIX ACL format; raw bytes were retained.",
            });
            (AclStatus::Malformed, None)
        }
    };
    AclObservation {
        status,
        source: Some(source),
        byte_length: Some(actual),
        bytes_hex: Some(hex(&bytes)),
        sha256: Some(sha256_hex(&bytes)),
        entries,
    }
}

fn acl_initial(status: AclStatus, source: &'static str) -> AclObservation {
    AclObservation {
        status,
        source: Some(source),
        byte_length: None,
        bytes_hex: None,
        sha256: None,
        entries: None,
    }
}

fn acl_diagnostic_code(status: AclStatus) -> &'static str {
    match status {
        AclStatus::Inaccessible => "acl_inaccessible",
        AclStatus::Unsupported => "acl_unsupported",
        _ => "acl_read_failed",
    }
}

fn acl_diagnostic_message(status: AclStatus) -> &'static str {
    match status {
        AclStatus::Inaccessible => "ACL xattr could not be read with current-user permissions.",
        AclStatus::Unsupported => "The filesystem or object does not support this ACL xattr.",
        _ => "ACL xattr could not be read.",
    }
}

fn decode_posix_acl(bytes: &[u8]) -> Result<Vec<AclEntry>, AclDecodeError> {
    if bytes.len() < 4 || (bytes.len() - 4) % 8 != 0 || read_u32(&bytes[..4]) != ACL_XATTR_VERSION {
        return Err(AclDecodeError::InvalidFormat);
    }
    let mut entries = Vec::with_capacity((bytes.len() - 4) / 8);
    for chunk in bytes[4..].chunks_exact(8) {
        let tag = u16::from_le_bytes([chunk[0], chunk[1]]);
        let permissions = u16::from_le_bytes([chunk[2], chunk[3]]);
        if permissions > 7 {
            return Err(AclDecodeError::InvalidFormat);
        }
        let raw_id = read_u32(&chunk[4..8]);
        let (tag, id) = match tag {
            0x01 if raw_id == ACL_UNDEFINED_ID => (AclTag::UserObject, None),
            0x02 if raw_id != ACL_UNDEFINED_ID => (AclTag::User, Some(raw_id)),
            0x04 if raw_id == ACL_UNDEFINED_ID => (AclTag::GroupObject, None),
            0x08 if raw_id != ACL_UNDEFINED_ID => (AclTag::Group, Some(raw_id)),
            0x10 if raw_id == ACL_UNDEFINED_ID => (AclTag::Mask, None),
            0x20 if raw_id == ACL_UNDEFINED_ID => (AclTag::Other, None),
            _ => return Err(AclDecodeError::InvalidFormat),
        };
        entries.push(AclEntry {
            tag,
            permissions: permissions as u8,
            id,
        });
    }
    if !valid_acl_order(&entries) {
        return Err(AclDecodeError::InvalidFormat);
    }
    Ok(entries)
}

fn valid_acl_order(entries: &[AclEntry]) -> bool {
    if entries.len() < 3
        || entries.first().map(|e| &e.tag) != Some(&AclTag::UserObject)
        || entries.last().map(|e| &e.tag) != Some(&AclTag::Other)
    {
        return false;
    }
    let mut phase = 0u8;
    let mut previous_user = None;
    let mut previous_group = None;
    let mut named = false;
    let mut mask = false;
    let mut seen_group_obj = false;
    for entry in entries.iter().skip(1).take(entries.len() - 2) {
        match entry.tag {
            AclTag::User if phase <= 1 => {
                phase = 1;
                let Some(id) = entry.id else { return false };
                if previous_user.is_some_and(|prior| prior >= id) {
                    return false;
                }
                previous_user = Some(id);
                named = true;
            }
            AclTag::GroupObject if phase <= 2 && !seen_group_obj => {
                phase = 2;
                seen_group_obj = true;
            }
            AclTag::Group if phase <= 3 => {
                phase = 3;
                let Some(id) = entry.id else { return false };
                if previous_group.is_some_and(|prior| prior >= id) {
                    return false;
                }
                previous_group = Some(id);
                named = true;
            }
            AclTag::Mask if phase <= 4 && !mask => {
                phase = 4;
                mask = true;
            }
            _ => return false,
        }
    }
    seen_group_obj && (!named || mask)
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn acl_fixture(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut bytes = ACL_XATTR_VERSION.to_le_bytes().to_vec();
        for (tag, perms, id) in entries {
            bytes.extend(tag.to_le_bytes());
            bytes.extend(perms.to_le_bytes());
            bytes.extend(id.to_le_bytes());
        }
        bytes
    }

    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-permissions-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn decodes_base_and_named_acl_entries() {
        let bytes = acl_fixture(&[
            (0x01, 7, ACL_UNDEFINED_ID),
            (0x02, 4, 1001),
            (0x04, 5, ACL_UNDEFINED_ID),
            (0x08, 4, 1002),
            (0x10, 5, ACL_UNDEFINED_ID),
            (0x20, 1, ACL_UNDEFINED_ID),
        ]);
        let entries = decode_posix_acl(&bytes).unwrap();
        assert_eq!(entries.len(), 6);
        assert_eq!(entries[1].id, Some(1001));
        assert_eq!(entries[3].tag, AclTag::Group);
    }

    #[test]
    fn rejects_bad_acl_versions_shapes_order_and_permissions() {
        assert!(decode_posix_acl(&[]).is_err());
        assert!(decode_posix_acl(&[3, 0, 0, 0]).is_err());
        assert!(decode_posix_acl(&[2, 0, 0, 0, 1]).is_err());
        let no_mask = acl_fixture(&[
            (0x01, 7, ACL_UNDEFINED_ID),
            (0x02, 4, 1),
            (0x04, 5, ACL_UNDEFINED_ID),
            (0x20, 1, ACL_UNDEFINED_ID),
        ]);
        assert!(decode_posix_acl(&no_mask).is_err());
        let bad_permissions = acl_fixture(&[
            (0x01, 8, ACL_UNDEFINED_ID),
            (0x04, 5, ACL_UNDEFINED_ID),
            (0x20, 1, ACL_UNDEFINED_ID),
        ]);
        assert!(decode_posix_acl(&bad_permissions).is_err());
    }

    #[test]
    fn inventories_selected_regular_file_without_following_final_symlink() {
        use std::os::unix::fs::symlink;
        let root = temp_dir();
        let file = root.join("sample");
        std::fs::write(&file, b"synthetic permission fixture").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        let link = root.join("link");
        symlink(&file, &link).unwrap();
        let document = collect_permissions(&[file.clone(), link]);
        assert_eq!(document.status, PermissionInventoryStatus::Partial);
        assert_eq!(document.objects[0].object_type, Some("regular_file"));
        assert_eq!(document.objects[0].mode.unwrap() & 0o777, 0o640);
        assert_eq!(document.objects[1].object_type, Some("symlink"));
        assert_eq!(
            document.objects[1].access_acl.status,
            AclStatus::Unsupported
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preserves_non_utf8_path_bytes_and_reports_absent_acl() {
        let root = temp_dir();
        let mut name = b"file-".to_vec();
        name.push(0xff);
        let path = root.join(std::ffi::OsString::from_vec(name));
        std::fs::write(&path, b"fixture").unwrap();
        let document = collect_permissions(std::slice::from_ref(&path));
        let row = &document.objects[0];
        assert!(row.path.is_none());
        assert!(row.path_bytes_hex.ends_with("ff"));
        assert!(matches!(
            row.access_acl.status,
            AclStatus::Absent | AclStatus::Unsupported
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reads_supported_access_and_default_acl_xattrs_from_pinned_descriptors() {
        let root = temp_dir();
        let file = root.join("acl-file");
        std::fs::write(&file, b"synthetic ACL fixture").unwrap();
        let bytes = acl_fixture(&[
            (0x01, 7, ACL_UNDEFINED_ID),
            (0x02, 4, 12345),
            (0x04, 5, ACL_UNDEFINED_ID),
            (0x10, 5, ACL_UNDEFINED_ID),
            (0x20, 1, ACL_UNDEFINED_ID),
        ]);
        let c_path = CString::new(file.as_os_str().as_bytes()).unwrap();
        let set_result = unsafe {
            libc::setxattr(
                c_path.as_ptr(),
                ACL_XATTR_ACCESS.as_ptr().cast(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
            )
        };
        if set_result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EOPNOTSUPP)
                || error.raw_os_error() == Some(libc::EPERM)
            {
                std::fs::remove_dir_all(root).unwrap();
                return;
            }
            panic!("could not install synthetic ACL xattr fixture: {error}");
        }
        let default_bytes = acl_fixture(&[
            (0x01, 7, ACL_UNDEFINED_ID),
            (0x04, 5, ACL_UNDEFINED_ID),
            (0x08, 4, 12346),
            (0x10, 5, ACL_UNDEFINED_ID),
            (0x20, 1, ACL_UNDEFINED_ID),
        ]);
        let c_root = CString::new(root.as_os_str().as_bytes()).unwrap();
        let set_default_result = unsafe {
            libc::setxattr(
                c_root.as_ptr(),
                ACL_XATTR_DEFAULT.as_ptr().cast(),
                default_bytes.as_ptr().cast(),
                default_bytes.len(),
                0,
            )
        };
        if set_default_result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EOPNOTSUPP)
                || error.raw_os_error() == Some(libc::EPERM)
            {
                std::fs::remove_dir_all(root).unwrap();
                return;
            }
            panic!("could not install synthetic default ACL fixture: {error}");
        }
        let exact = collect_with_limits(
            std::slice::from_ref(&file),
            Limits {
                paths: 2,
                path_bytes: 4096,
                acl_bytes: bytes.len(),
                total_acl_bytes: bytes.len(),
                scan_duration: Duration::from_secs(5),
            },
        );
        assert_eq!(exact.status, PermissionInventoryStatus::Complete);
        assert_eq!(exact.acl_bytes_read, bytes.len());
        assert_eq!(exact.objects[0].access_acl.status, AclStatus::Present);
        let limited = collect_with_limits(
            std::slice::from_ref(&file),
            Limits {
                paths: 2,
                path_bytes: 4096,
                acl_bytes: bytes.len() - 1,
                total_acl_bytes: 8 * 1024 * 1024,
                scan_duration: Duration::from_secs(5),
            },
        );
        assert_eq!(limited.status, PermissionInventoryStatus::Partial);
        assert_eq!(
            limited.objects[0].access_acl.status,
            AclStatus::LimitExceeded
        );
        let aggregate_limited = collect_with_limits(
            &[file.clone(), root.clone()],
            Limits {
                paths: 2,
                path_bytes: 4096,
                acl_bytes: 64 * 1024,
                total_acl_bytes: bytes.len(),
                scan_duration: Duration::from_secs(5),
            },
        );
        assert_eq!(aggregate_limited.status, PermissionInventoryStatus::Partial);
        assert_eq!(aggregate_limited.acl_bytes_read, bytes.len());
        assert_eq!(
            aggregate_limited.objects[1].default_acl.status,
            AclStatus::LimitExceeded
        );
        let document = collect_permissions(&[file, root.clone()]);
        assert_eq!(document.status, PermissionInventoryStatus::Complete);
        let access = &document.objects[0].access_acl;
        assert_eq!(access.status, AclStatus::Present);
        assert_eq!(access.entries.as_ref().unwrap()[1].id, Some(12345));
        assert_eq!(access.bytes_hex.as_deref(), Some(hex(&bytes).as_str()));
        let default = &document.objects[1].default_acl;
        assert_eq!(default.status, AclStatus::Present);
        assert_eq!(default.entries.as_ref().unwrap()[2].id, Some(12346));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn path_count_and_path_byte_limits_mark_partial() {
        let accepted = collect_with_limits(
            &[PathBuf::from("/")],
            Limits {
                paths: 1,
                path_bytes: 1,
                acl_bytes: 64 * 1024,
                total_acl_bytes: 8 * 1024 * 1024,
                scan_duration: Duration::from_secs(5),
            },
        );
        assert_eq!(accepted.paths_requested, 1);
        assert_eq!(accepted.objects.len(), 1);
        assert!(
            !accepted
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "path_count_limit_exceeded")
        );
        assert!(
            !accepted
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "path_limit_exceeded")
        );
        let paths = vec![PathBuf::from("/"), PathBuf::from("/tmp")];
        let limited = collect_with_limits(
            &paths,
            Limits {
                paths: 1,
                path_bytes: 4096,
                acl_bytes: 64 * 1024,
                total_acl_bytes: 8 * 1024 * 1024,
                scan_duration: Duration::from_secs(5),
            },
        );
        assert_eq!(limited.status, PermissionInventoryStatus::Partial);
        assert_eq!(limited.objects.len(), 1);
        assert_eq!(limited.diagnostics[0].code, "path_count_limit_exceeded");
        let path_limited = collect_with_limits(
            &[PathBuf::from("/tmp/long")],
            Limits {
                paths: 4,
                path_bytes: 3,
                acl_bytes: 64 * 1024,
                total_acl_bytes: 8 * 1024 * 1024,
                scan_duration: Duration::from_secs(5),
            },
        );
        assert_eq!(path_limited.status, PermissionInventoryStatus::Partial);
        assert!(path_limited.objects.is_empty());
        assert_eq!(path_limited.diagnostics[0].code, "path_limit_exceeded");
        let deadline_limited = collect_with_limits(
            &[PathBuf::from("/"), PathBuf::from("/tmp")],
            Limits {
                paths: 4,
                path_bytes: 4096,
                acl_bytes: 64 * 1024,
                total_acl_bytes: 8 * 1024 * 1024,
                scan_duration: Duration::ZERO,
            },
        );
        assert_eq!(deadline_limited.status, PermissionInventoryStatus::Partial);
        assert!(deadline_limited.objects.is_empty());
        assert_eq!(
            deadline_limited.diagnostics[0].code,
            "scan_deadline_exceeded"
        );
    }

    #[test]
    fn invalid_path_does_not_claim_default_acl_is_not_applicable() {
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"/invalid\0path".to_vec()));
        let document = collect_permissions(&[path]);
        assert_eq!(document.status, PermissionInventoryStatus::Partial);
        assert_eq!(document.objects[0].default_acl.status, AclStatus::Failed);
    }
}
