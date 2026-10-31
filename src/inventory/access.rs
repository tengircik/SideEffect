//! Bounded Linux access probes under the calling thread's current credentials.
//!
//! This module deliberately does not switch identities or predict access for
//! another process. A successful kernel probe is not a guarantee that a later
//! operation will succeed. The configured-policy conclusion remains unknown
//! until the missing policy inputs are collected and validated.

use serde::Serialize;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub const MAX_ACCESS_PATH_BYTES: usize = 4 * 1024;
pub const MAX_ACCESS_GROUPS: usize = 256;
pub const MAX_THREAD_STATUS_BYTES: usize = 64 * 1024;
pub const ACCESS_ANALYSIS_SCHEMA: &str = "sideeffect.linux_access_analysis";
pub const ACCESS_ANALYSIS_SCHEMA_VERSION: u32 = 1;

const MAX_PATH_HEX_BYTES: usize = MAX_ACCESS_PATH_BYTES * 2;
const ACCESS_PROBE_FLAGS: libc::c_int = libc::AT_EMPTY_PATH | libc::AT_EACCESS;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessOperation {
    Read,
    Write,
    Execute,
}

impl AccessOperation {
    /// Parse the deliberately small public operation vocabulary.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "execute" => Ok(Self::Execute),
            _ => Err("operation must be exactly read, write, or execute"),
        }
    }

    fn mode(self) -> libc::c_int {
        match self {
            Self::Read => libc::R_OK,
            Self::Write => libc::W_OK,
            Self::Execute => libc::X_OK,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessConclusion {
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelProbeStatus {
    AllowedByKernelProbe,
    RejectedByKernelProbe,
    Unavailable,
    NotAttempted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FactStatus {
    Observed,
    Unknown,
    Unsupported,
    LimitExceeded,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccessAnalysisDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub status: &'static str,
    pub operation: AccessOperation,
    pub selected_path: SelectedPath,
    pub identity: CallingThreadIdentity,
    /// No runtime operation was observed by this read-only query.
    pub observed_attempt: Option<ObservedAttempt>,
    /// Only object metadata is captured here. ACLs, file capabilities, and
    /// non-DAC policies are not represented as evaluated configured facts.
    pub configured_facts: ConfiguredFacts,
    /// The kernel's non-mutating faccessat2 result, separate from a later I/O
    /// operation and from the product's still-unknown policy conclusion.
    pub observed_kernel_check: KernelCheck,
    pub calculated_conclusion: AccessConclusion,
    pub controls: Vec<ControlState>,
    pub diagnostics: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SelectedPath {
    pub path_byte_length: usize,
    pub path_bytes_hex: String,
    pub path_bytes_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_display: Option<String>,
    pub resolution_status: FactStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inode: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_type: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CallingThreadIdentity {
    pub identity_scope: &'static str,
    pub effective_uid: FactValue<u32>,
    pub effective_gid: FactValue<u32>,
    /// Linux's filesystem IDs are reported separately because VFS permission
    /// checks use them; a mismatch is not silently normalized away.
    pub filesystem_uid: FactValue<u32>,
    pub filesystem_gid: FactValue<u32>,
    pub effective_filesystem_ids_match: Option<bool>,
    pub supplementary_groups: FactValue<Vec<u32>>,
    pub effective_capabilities_hex: FactValue<String>,
    pub seccomp_mode: FactValue<u32>,
    pub user_namespace: FactValue<String>,
    pub mount_namespace: FactValue<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FactValue<T> {
    pub status: FactStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<T>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObservedAttempt {
    pub status: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConfiguredFacts {
    pub status: FactStatus,
    pub source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    pub omitted: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct KernelCheck {
    pub status: KernelProbeStatus,
    pub api: &'static str,
    pub path_resolution: &'static str,
    pub flags: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_errno: Option<i32>,
    pub explanation: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ControlState {
    pub control: &'static str,
    pub status: FactStatus,
    pub note: &'static str,
}

/// Query one absolute, bounded path under the calling thread's current
/// effective credentials. It reports `geteuid()`/`getegid()` and the separate
/// Linux filesystem IDs read from `/proc/thread-self/status`; any mismatch is
/// explicit. This never changes credentials, mutates the target,
/// or launches a program. The exact kernel probe is kept separate from the
/// conservative calculated conclusion, which is always `unknown` in v1.
pub fn analyze_current_process_access(
    path: &Path,
    operation: AccessOperation,
) -> AccessAnalysisDocument {
    let path_bytes = path.as_os_str().as_bytes();
    let selected_path = selected_path_unresolved(path_bytes);
    if path_bytes.len() > MAX_ACCESS_PATH_BYTES {
        return unavailable_document(
            operation,
            selected_path,
            "The selected path exceeds the configured byte limit; no kernel probe was attempted.",
            KernelProbeStatus::NotAttempted,
            None,
        );
    }
    if !path.is_absolute() {
        return unavailable_document(
            operation,
            selected_path,
            "Only absolute paths are accepted so the query does not depend on an unreported working directory.",
            KernelProbeStatus::NotAttempted,
            None,
        );
    }
    let path_c = match CString::new(path_bytes) {
        Ok(value) => value,
        Err(_) => {
            return unavailable_document(
                operation,
                selected_path,
                "The selected path contains an interior NUL byte and cannot be passed to the kernel.",
                KernelProbeStatus::NotAttempted,
                None,
            );
        }
    };

    // O_PATH follows symlinks and resolves ancestors in the calling thread's
    // current namespace. The descriptor pins the final object across the
    // subsequent permission probe; it does not preserve the path's symlink
    // chain or establish that a future pathname lookup will resolve the same.
    // SAFETY: path_c is NUL terminated and flags are fixed; the returned fd is
    // immediately checked and wrapped in an owning File on success.
    let descriptor = unsafe { libc::open(path_c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        return unavailable_document(
            operation,
            selected_path,
            "The kernel could not resolve the selected path to an object descriptor; this is not an effective-access denial result.",
            KernelProbeStatus::Unavailable,
            error.raw_os_error(),
        );
    }
    // SAFETY: open returned a new descriptor owned by this function.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata().ok();
    let selected_path = selected_path_resolved(path_bytes, metadata.as_ref());
    let credentials = calling_thread_identity();
    let empty_path = c"";
    // SAFETY: the file descriptor is live, empty_path is NUL terminated, and
    // mode/flags are fixed constants selected from the closed operation enum.
    let result = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            file.as_raw_fd(),
            empty_path.as_ptr(),
            operation.mode(),
            ACCESS_PROBE_FLAGS,
        )
    };
    let raw_errno = (result != 0)
        .then(|| io::Error::last_os_error().raw_os_error())
        .flatten();
    let probe_status = classify_probe_result(result, raw_errno);
    let explanation = if result == 0 {
        "The kernel permission probe returned success for the pinned object and current calling-thread credentials; this does not guarantee a later operation."
    } else {
        "The kernel permission probe did not return success; the errno is preserved without attributing it to DAC, MAC, seccomp, or another policy."
    };
    AccessAnalysisDocument {
        schema: ACCESS_ANALYSIS_SCHEMA,
        schema_version: ACCESS_ANALYSIS_SCHEMA_VERSION,
        platform: "linux",
        scope: "single_absolute_path_current_calling_thread_non_mutating_permission_probe",
        status: "partial",
        operation,
        selected_path,
        identity: credentials,
        observed_attempt: None,
        configured_facts: configured_metadata(metadata.as_ref()),
        observed_kernel_check: KernelCheck {
            status: probe_status,
            api: "faccessat2",
            path_resolution: "kernel_resolved_to_pinned_object_by_open_o_path; ancestors_and_symlink_chain_not_retained",
            flags: vec!["AT_EMPTY_PATH", "AT_EACCESS"],
            raw_errno,
            explanation,
        },
        calculated_conclusion: AccessConclusion::Unknown,
        controls: controls_after_probe(),
        diagnostics: vec![
            "This check uses the calling thread's current credentials only; it does not evaluate another process identity.",
            "A permission preflight is not proof that a later open, write, or execution will succeed.",
            "Configured ACLs and file capabilities are not decoded by this module.",
            "MAC policy, seccomp filter contents, mount flags, and complete ancestor/symlink evidence are not evaluated; calculated access remains unknown.",
        ],
    }
}

fn classify_probe_result(result: libc::c_long, errno: Option<i32>) -> KernelProbeStatus {
    if result == 0 {
        KernelProbeStatus::AllowedByKernelProbe
    } else if matches!(errno, Some(libc::EACCES | libc::EPERM)) {
        KernelProbeStatus::RejectedByKernelProbe
    } else {
        // In particular, ENOSYS/EINVAL/ENOTSUP are unavailable API results,
        // never access denials.
        KernelProbeStatus::Unavailable
    }
}

fn selected_path_unresolved(path_bytes: &[u8]) -> SelectedPath {
    let path_bytes_truncated = path_bytes.len() > MAX_ACCESS_PATH_BYTES;
    SelectedPath {
        path_byte_length: path_bytes.len(),
        path_bytes_hex: hex(path_bytes),
        path_bytes_truncated,
        path_display: (!path_bytes_truncated)
            .then(|| std::str::from_utf8(path_bytes).ok())
            .flatten()
            .map(ToOwned::to_owned),
        resolution_status: FactStatus::Unknown,
        device: None,
        inode: None,
        object_type: None,
    }
}

fn selected_path_resolved(path_bytes: &[u8], metadata: Option<&fs::Metadata>) -> SelectedPath {
    let mut selected = selected_path_unresolved(path_bytes);
    if let Some(metadata) = metadata {
        selected.resolution_status = FactStatus::Observed;
        selected.device = Some(metadata.dev());
        selected.inode = Some(metadata.ino());
        selected.object_type = Some(if metadata.is_file() {
            "regular_file"
        } else if metadata.is_dir() {
            "directory"
        } else {
            "other"
        });
    }
    selected
}

fn configured_metadata(metadata: Option<&fs::Metadata>) -> ConfiguredFacts {
    let mut facts = ConfiguredFacts {
        status: FactStatus::Unknown,
        source: "fstat_on_pinned_o_path_descriptor",
        uid: None,
        gid: None,
        mode: None,
        omitted: vec![
            "access_acl",
            "file_capabilities",
            "mount_flags",
            "selinux_policy",
            "apparmor_policy",
            "seccomp_filter_contents",
        ],
    };
    if let Some(metadata) = metadata {
        facts.status = FactStatus::Observed;
        facts.uid = Some(metadata.uid());
        facts.gid = Some(metadata.gid());
        facts.mode = Some(metadata.mode());
    }
    facts
}

fn calling_thread_identity() -> CallingThreadIdentity {
    let groups = supplementary_groups();
    let status = read_thread_status();
    // SAFETY: these credential queries take no pointers and have no
    // preconditions; they inspect the calling thread's current IDs.
    let effective_uid = observed(unsafe { libc::geteuid() });
    let effective_gid = observed(unsafe { libc::getegid() });
    let (filesystem_uid, filesystem_gid, effective_capabilities_hex, seccomp_mode) = match status {
        Ok(value) => (
            value.uid_filesystem.map_or_else(unknown, observed),
            value.gid_filesystem.map_or_else(unknown, observed),
            value.cap_effective_hex.map_or_else(unknown, observed),
            value.seccomp_mode.map_or_else(unknown, observed),
        ),
        Err(status) => (
            unknown_with_status(status),
            unknown_with_status(status),
            unknown_with_status(status),
            unknown_with_status(status),
        ),
    };
    let effective_filesystem_ids_match = match (
        effective_uid.value,
        effective_gid.value,
        filesystem_uid.value,
        filesystem_gid.value,
    ) {
        (Some(effective_uid), Some(effective_gid), Some(filesystem_uid), Some(filesystem_gid)) => {
            Some(effective_uid == filesystem_uid && effective_gid == filesystem_gid)
        }
        _ => None,
    };
    CallingThreadIdentity {
        identity_scope: "calling_thread_at_query_time; effective and filesystem IDs reported separately",
        effective_uid,
        effective_gid,
        filesystem_uid,
        filesystem_gid,
        effective_filesystem_ids_match,
        supplementary_groups: groups,
        effective_capabilities_hex,
        seccomp_mode,
        user_namespace: namespace_identity("user"),
        mount_namespace: namespace_identity("mnt"),
    }
}

fn supplementary_groups() -> FactValue<Vec<u32>> {
    // SAFETY: getgroups with size zero only queries the count.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        return FactValue {
            status: FactStatus::Unknown,
            value: None,
        };
    }
    let count = count as usize;
    if count > MAX_ACCESS_GROUPS {
        return FactValue {
            status: FactStatus::LimitExceeded,
            value: None,
        };
    }
    let mut groups = vec![0 as libc::gid_t; count];
    // SAFETY: the vector has exactly `count` valid slots; zero count permits
    // a dangling non-null vector pointer as documented by getgroups(2).
    let read = unsafe { libc::getgroups(count as libc::c_int, groups.as_mut_ptr()) };
    if read < 0 || read as usize != count {
        return FactValue {
            status: FactStatus::Unknown,
            value: None,
        };
    }
    FactValue {
        status: FactStatus::Observed,
        value: Some(groups.into_iter().collect()),
    }
}

struct ThreadStatusFields {
    uid_filesystem: Option<u32>,
    gid_filesystem: Option<u32>,
    cap_effective_hex: Option<String>,
    seccomp_mode: Option<u32>,
}

fn read_thread_status() -> Result<ThreadStatusFields, FactStatus> {
    let file = File::open("/proc/thread-self/status").map_err(|_| FactStatus::Unknown)?;
    let mut bytes = Vec::new();
    file.take((MAX_THREAD_STATUS_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| FactStatus::Unknown)?;
    if bytes.len() > MAX_THREAD_STATUS_BYTES {
        return Err(FactStatus::LimitExceeded);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| FactStatus::Unknown)?;
    let mut fields = ThreadStatusFields {
        uid_filesystem: None,
        gid_filesystem: None,
        cap_effective_hex: None,
        seccomp_mode: None,
    };
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            match key {
                "Uid" => fields.uid_filesystem = parse_four_ids(value).map(|ids| ids[3]),
                "Gid" => fields.gid_filesystem = parse_four_ids(value).map(|ids| ids[3]),
                "CapEff" => fields.cap_effective_hex = parse_capability_hex(value.trim()),
                "Seccomp" => fields.seccomp_mode = value.trim().parse::<u32>().ok(),
                _ => {}
            }
        }
    }
    Ok(fields)
}

fn parse_four_ids(value: &str) -> Option<[u32; 4]> {
    let mut fields = value.split_ascii_whitespace();
    let ids = [
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
    ];
    fields.next().is_none().then_some(ids)
}

fn parse_capability_hex(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn namespace_identity(name: &str) -> FactValue<String> {
    let path = format!("/proc/thread-self/ns/{name}");
    match fs::read_link(path) {
        Ok(target) => {
            let text = target.to_string_lossy();
            if text.len() <= 128 && text.starts_with(&format!("{name}:[")) && text.ends_with(']') {
                FactValue {
                    status: FactStatus::Observed,
                    value: Some(text.into_owned()),
                }
            } else {
                FactValue {
                    status: FactStatus::Unknown,
                    value: None,
                }
            }
        }
        Err(_) => FactValue {
            status: FactStatus::Unknown,
            value: None,
        },
    }
}

fn observed<T>(value: T) -> FactValue<T> {
    FactValue {
        status: FactStatus::Observed,
        value: Some(value),
    }
}

fn unknown<T>() -> FactValue<T> {
    unknown_with_status(FactStatus::Unknown)
}

fn unknown_with_status<T>(status: FactStatus) -> FactValue<T> {
    FactValue {
        status,
        value: None,
    }
}

fn controls_after_probe() -> Vec<ControlState> {
    vec![
        ControlState {
            control: "calling_thread_effective_credentials",
            status: FactStatus::Observed,
            note: "UID/GID and supplementary groups are queried for the calling thread context; capability and namespace data may be unknown individually.",
        },
        ControlState {
            control: "kernel_vfs_permission_probe",
            status: FactStatus::Observed,
            note: "Only the pinned final object is checked by faccessat2(AT_EMPTY_PATH | AT_EACCESS); no future I/O is attempted.",
        },
        ControlState {
            control: "posix_acl_and_file_capabilities",
            status: FactStatus::Unsupported,
            note: "Not separately collected or decoded by this first slice.",
        },
        ControlState {
            control: "mac_seccomp_and_mount_policy",
            status: FactStatus::Unknown,
            note: "Policy details and mount flags are not fully enumerated; a negative errno is not attributed to one control.",
        },
        ControlState {
            control: "ancestor_and_symlink_resolution_context",
            status: FactStatus::Unknown,
            note: "The kernel resolves the path during O_PATH open, but the ancestor chain and symlink transitions are not retained as stable evidence.",
        },
        ControlState {
            control: "time_of_check_to_use",
            status: FactStatus::Unknown,
            note: "The probe is a point-in-time preflight and says nothing about later changes or operations.",
        },
    ]
}

fn unavailable_document(
    operation: AccessOperation,
    selected_path: SelectedPath,
    reason: &'static str,
    probe_status: KernelProbeStatus,
    raw_errno: Option<i32>,
) -> AccessAnalysisDocument {
    AccessAnalysisDocument {
        schema: ACCESS_ANALYSIS_SCHEMA,
        schema_version: ACCESS_ANALYSIS_SCHEMA_VERSION,
        platform: "linux",
        scope: "single_absolute_path_current_calling_thread_non_mutating_permission_probe",
        status: "partial",
        operation,
        selected_path,
        identity: calling_thread_identity(),
        observed_attempt: None,
        configured_facts: configured_metadata(None),
        observed_kernel_check: KernelCheck {
            status: probe_status,
            api: "open_o_path_then_faccessat2",
            path_resolution: "not_fully_observed",
            flags: vec!["O_PATH", "O_CLOEXEC", "AT_EMPTY_PATH", "AT_EACCESS"],
            raw_errno,
            explanation: reason,
        },
        calculated_conclusion: AccessConclusion::Unknown,
        controls: vec![ControlState {
            control: "effective_access",
            status: FactStatus::Unknown,
            note: "No complete configured-policy conclusion is produced by this first slice.",
        }],
        diagnostics: vec![reason],
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(
        bytes
            .len()
            .min(MAX_ACCESS_PATH_BYTES)
            .saturating_mul(2)
            .min(MAX_PATH_HEX_BYTES),
    );
    for byte in bytes.iter().take(MAX_ACCESS_PATH_BYTES) {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn operation_parser_accepts_only_the_closed_vocabulary() {
        assert_eq!(AccessOperation::parse("read"), Ok(AccessOperation::Read));
        assert_eq!(AccessOperation::parse("write"), Ok(AccessOperation::Write));
        assert_eq!(
            AccessOperation::parse("execute"),
            Ok(AccessOperation::Execute)
        );
        for invalid in ["", "READ", "delete", "read ", "shell"] {
            assert!(AccessOperation::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn oversized_and_relative_paths_do_not_reach_the_kernel_probe() {
        let overlong = PathBuf::from(format!("/{}", "x".repeat(MAX_ACCESS_PATH_BYTES)));
        let overlong_result = analyze_current_process_access(&overlong, AccessOperation::Read);
        assert_eq!(
            overlong_result.observed_kernel_check.status,
            KernelProbeStatus::NotAttempted
        );
        assert_eq!(
            overlong_result.calculated_conclusion,
            AccessConclusion::Unknown
        );
        assert!(overlong_result.selected_path.path_bytes_hex.len() <= MAX_PATH_HEX_BYTES);
        assert_eq!(
            overlong_result.selected_path.path_byte_length,
            MAX_ACCESS_PATH_BYTES + 1
        );
        assert!(overlong_result.selected_path.path_bytes_truncated);
        assert_eq!(overlong_result.selected_path.path_display, None);

        let relative =
            analyze_current_process_access(Path::new("relative-target"), AccessOperation::Read);
        assert_eq!(
            relative.observed_kernel_check.status,
            KernelProbeStatus::NotAttempted
        );
        assert_eq!(
            relative.selected_path.resolution_status,
            FactStatus::Unknown
        );
    }

    #[test]
    fn permission_probe_is_read_only_and_never_claims_a_calculated_allow() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sideeffect-access-probe-{unique}"));
        fs::write(&path, b"synthetic fixture").expect("create synthetic permission-probe fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("set synthetic fixture permissions");

        let result = analyze_current_process_access(&path, AccessOperation::Read);

        assert_eq!(result.schema, ACCESS_ANALYSIS_SCHEMA);
        assert_eq!(result.status, "partial");
        assert_eq!(result.calculated_conclusion, AccessConclusion::Unknown);
        assert!(result.observed_attempt.is_none());
        assert_eq!(result.selected_path.resolution_status, FactStatus::Observed);
        assert_eq!(result.observed_kernel_check.api, "faccessat2");
        assert!(matches!(
            result.observed_kernel_check.status,
            KernelProbeStatus::AllowedByKernelProbe | KernelProbeStatus::RejectedByKernelProbe
        ));
        assert_eq!(
            fs::read(&path).expect("probe must not modify target"),
            b"synthetic fixture"
        );

        fs::remove_file(path).expect("remove synthetic permission-probe fixture");
    }

    #[test]
    fn proc_status_uid_and_gid_fields_require_exactly_four_values() {
        assert_eq!(
            parse_four_ids("\t1000\t1001\t1002\t1003"),
            Some([1000, 1001, 1002, 1003])
        );
        assert_eq!(parse_four_ids("1000 1001 1002"), None);
        assert_eq!(parse_four_ids("1000 1001 1002 1003 extra"), None);
        assert_eq!(parse_four_ids("1000 1001 malformed 1003"), None);
    }

    #[test]
    fn unsupported_probe_errors_are_not_reported_as_access_rejections() {
        assert_eq!(
            classify_probe_result(-1, Some(libc::ENOSYS)),
            KernelProbeStatus::Unavailable
        );
        assert_eq!(
            classify_probe_result(-1, Some(libc::EINVAL)),
            KernelProbeStatus::Unavailable
        );
        assert_eq!(
            classify_probe_result(-1, Some(libc::EACCES)),
            KernelProbeStatus::RejectedByKernelProbe
        );
        assert_eq!(
            classify_probe_result(-1, Some(libc::EPERM)),
            KernelProbeStatus::RejectedByKernelProbe
        );
    }
}
