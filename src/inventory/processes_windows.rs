//! Bounded native Windows process snapshot using Tool Help APIs.

use serde::Serialize;
use std::collections::HashSet;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const MAX_PROCESSES: usize = 8_192;
const MAX_IMAGE_PATH_UTF16_UNITS: usize = 32_768;
const MAX_AGGREGATE_IMAGE_PATH_UTF16_UNITS: usize = 4 * 1024 * 1024;
const MAX_TOKEN_INFO_BYTES: usize = 64 * 1024;
const MAX_PROCESS_TOKEN_SID_UTF16_UNITS: usize = 256;
pub const MAX_AGGREGATE_TOKEN_SID_UTF16_UNITS: usize = 2 * 1024 * 1024;
const MAX_SCAN_DURATION: Duration = Duration::from_secs(10);
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NO_MORE_FILES: u32 = 18;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NOT_FOUND: u32 = 1168;

type Handle = *mut c_void;

#[derive(Clone, Copy)]
#[repr(C)]
struct ProcessEntry32W {
    size: u32,
    usage_count: u32,
    process_id: u32,
    default_heap_id: usize,
    module_id: u32,
    thread_count: u32,
    parent_process_id: u32,
    base_priority: i32,
    flags: u32,
    executable_name: [u16; 260],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct FileTime {
    low: u32,
    high: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
    fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
    fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
    fn QueryFullProcessImageNameW(
        process: Handle,
        flags: u32,
        name: *mut u16,
        size: *mut u32,
    ) -> i32;
    fn GetProcessTimes(
        process: Handle,
        creation: *mut FileTime,
        exit: *mut FileTime,
        kernel: *mut FileTime,
        user: *mut FileTime,
    ) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsProcessInventoryStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsProcessImageStatus {
    Observed,
    Inaccessible,
    Vanished,
    OverLimit,
    MalformedUtf16,
    Error,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsProcessImage {
    pub status: WindowsProcessImageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utf16_code_units: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsProcessRow {
    pub process_id: u32,
    pub parent_process_id: u32,
    pub thread_count: u32,
    pub executable_name: String,
    pub creation_time: WindowsProcessCreationTime,
    pub image: WindowsProcessImage,
    pub token_context: WindowsProcessTokenContext,
    pub evidence: WindowsProcessEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsProcessTokenContextStatus {
    Observed,
    IdentityUnverified,
    ChangedDuringRead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsProcessTokenFieldStatus {
    Observed,
    Inaccessible,
    Vanished,
    Malformed,
    OverLimit,
    IdentityUnverified,
    Error,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsProcessTokenField<T> {
    pub status: WindowsProcessTokenFieldStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<T>,
    pub source: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsProcessTokenContext {
    pub identity_status: WindowsProcessTokenContextStatus,
    pub process_creation_time_filetime_100ns: Option<u64>,
    pub user_sid: WindowsProcessTokenField<String>,
    pub integrity_level_rid: WindowsProcessTokenField<u32>,
    pub session_id: WindowsProcessTokenField<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsProcessCreationTimeStatus {
    Observed,
    Inaccessible,
    Vanished,
    Error,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsProcessCreationTime {
    pub status: WindowsProcessCreationTimeStatus,
    /// Raw Windows FILETIME ticks (100 ns units since 1601-01-01 UTC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filetime_100ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsProcessEvidence {
    pub snapshot_source: &'static str,
    pub snapshot_index: usize,
    pub process_id: u32,
    pub parent_process_id: u32,
    pub thread_count: u32,
    pub executable_name: String,
    pub image_source: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsProcessDiagnostic {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
    pub message: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsProcessInventorySource {
    pub id: &'static str,
    pub status: WindowsProcessInventoryStatus,
    pub entries_seen: usize,
    pub image_path_utf16_code_units: usize,
    pub token_sid_utf16_code_units: usize,
    pub diagnostics: Vec<WindowsProcessDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsProcessInventoryDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub capture_started_at_unix_ms: u128,
    pub capture_ended_at_unix_ms: u128,
    pub status: WindowsProcessInventoryStatus,
    pub source: WindowsProcessInventorySource,
    pub processes: Vec<WindowsProcessRow>,
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

struct OwnedHandle(Handle);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper only owns valid handles returned by the APIs below.
        unsafe { CloseHandle(self.0) };
    }
}

trait WindowsProcessApi {
    type Snapshot;

    fn create_snapshot(&mut self) -> Result<Self::Snapshot, u32>;
    fn first_process(
        &mut self,
        snapshot: &mut Self::Snapshot,
    ) -> Result<Option<ProcessEntry32W>, u32>;
    fn next_process(
        &mut self,
        snapshot: &mut Self::Snapshot,
    ) -> Result<Option<ProcessEntry32W>, u32>;
    fn read_image_path(
        &mut self,
        process_id: u32,
        aggregate_remaining: usize,
    ) -> WindowsProcessImage;
    fn read_creation_time(&mut self, process_id: u32) -> WindowsProcessCreationTime;
    fn read_token_context(
        &mut self,
        process_id: u32,
        aggregate_sid_remaining: usize,
    ) -> WindowsProcessTokenContext;
}

struct NativeWindowsProcessApi;

impl WindowsProcessApi for NativeWindowsProcessApi {
    type Snapshot = OwnedHandle;

    fn create_snapshot(&mut self) -> Result<Self::Snapshot, u32> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot as isize == -1 {
            Err(unsafe { GetLastError() })
        } else {
            Ok(OwnedHandle(snapshot))
        }
    }

    fn first_process(
        &mut self,
        snapshot: &mut Self::Snapshot,
    ) -> Result<Option<ProcessEntry32W>, u32> {
        let mut entry: ProcessEntry32W = unsafe { zeroed() };
        entry.size = size_of::<ProcessEntry32W>() as u32;
        if unsafe { Process32FirstW(snapshot.0, &mut entry) } != 0 {
            Ok(Some(entry))
        } else {
            let error = unsafe { GetLastError() };
            if error == ERROR_NO_MORE_FILES {
                Ok(None)
            } else {
                Err(error)
            }
        }
    }

    fn next_process(
        &mut self,
        snapshot: &mut Self::Snapshot,
    ) -> Result<Option<ProcessEntry32W>, u32> {
        let mut entry: ProcessEntry32W = unsafe { zeroed() };
        entry.size = size_of::<ProcessEntry32W>() as u32;
        if unsafe { Process32NextW(snapshot.0, &mut entry) } != 0 {
            Ok(Some(entry))
        } else {
            let error = unsafe { GetLastError() };
            if error == ERROR_NO_MORE_FILES {
                Ok(None)
            } else {
                Err(error)
            }
        }
    }

    fn read_image_path(
        &mut self,
        process_id: u32,
        aggregate_remaining: usize,
    ) -> WindowsProcessImage {
        read_image_path_native(process_id, aggregate_remaining)
    }

    fn read_creation_time(&mut self, process_id: u32) -> WindowsProcessCreationTime {
        read_creation_time_native(process_id)
    }

    fn read_token_context(
        &mut self,
        process_id: u32,
        aggregate_sid_remaining: usize,
    ) -> WindowsProcessTokenContext {
        read_token_context_native(process_id, aggregate_sid_remaining)
    }
}

struct RawEntry(ProcessEntry32W);

pub fn collect_windows_processes() -> WindowsProcessInventoryDocument {
    collect_windows_processes_with_api(&mut NativeWindowsProcessApi)
}

fn collect_windows_processes_with_api<A: WindowsProcessApi>(
    api: &mut A,
) -> WindowsProcessInventoryDocument {
    let started_at = now_ms();
    let started = Instant::now();
    let mut diagnostics = Vec::new();
    let mut snapshot = match api.create_snapshot() {
        Ok(snapshot) => snapshot,
        Err(_) => {
            diagnostics.push(diagnostic(
                "snapshot_unavailable",
                None,
                "Windows could not create a process snapshot.",
            ));
            return finish(started_at, Vec::new(), diagnostics, 0, 0, 0, true);
        }
    };
    let mut entries = Vec::with_capacity(MAX_PROCESSES.min(512));
    let mut truncated = false;
    let mut process_limit_reached = false;
    let mut current_entry = match api.first_process(&mut snapshot) {
        Ok(entry) => entry,
        Err(_) => {
            diagnostics.push(diagnostic(
                "snapshot_enumeration_failed",
                None,
                "Windows could not read the first process snapshot entry.",
            ));
            truncated = true;
            None
        }
    };
    while let Some(entry) = current_entry {
        entries.push(RawEntry(entry));
        if trim_to_process_limit(&mut entries) {
            truncated = true;
            process_limit_reached = true;
            diagnostics.push(diagnostic(
                "process_limit_exceeded",
                None,
                "The process-count limit was reached; remaining entries were not checked.",
            ));
            break;
        }
        if started.elapsed() >= MAX_SCAN_DURATION {
            truncated = true;
            diagnostics.push(diagnostic(
                "scan_deadline_exceeded",
                None,
                "The process inventory time limit was reached; remaining snapshot entries were not checked.",
            ));
            break;
        }
        current_entry = match api.next_process(&mut snapshot) {
            Ok(entry) => entry,
            Err(_) => {
                diagnostics.push(diagnostic(
                    "snapshot_enumeration_failed",
                    None,
                    "Windows stopped enumerating the process snapshot unexpectedly.",
                ));
                truncated = true;
                None
            }
        };
    }
    drop(snapshot);

    if trim_to_process_limit(&mut entries) {
        truncated = true;
        process_limit_reached = true;
    }
    let mut seen = HashSet::with_capacity(entries.len());
    let mut rows = Vec::with_capacity(entries.len());
    let mut image_total = 0usize;
    let mut token_sid_total = 0usize;
    for (index, raw) in entries.into_iter().enumerate() {
        if started.elapsed() >= MAX_SCAN_DURATION {
            truncated = true;
            diagnostics.push(diagnostic(
                "scan_deadline_exceeded",
                None,
                "The process inventory time limit was reached; remaining entries were not checked.",
            ));
            break;
        }
        let entry = raw.0;
        if entry.process_id == 0 {
            truncated = true;
            diagnostics.push(diagnostic(
                "invalid_process_id",
                None,
                "A snapshot row had a zero process identifier and was omitted.",
            ));
            continue;
        }
        if !accept_process_id(&mut seen, entry.process_id) {
            truncated = true;
            diagnostics.push(diagnostic(
                "duplicate_process_id",
                Some(entry.process_id),
                "A duplicate process identifier was omitted.",
            ));
            continue;
        }
        let (name, invalid_name) = decode_executable_name(&entry.executable_name);
        if invalid_name {
            truncated = true;
            diagnostics.push(diagnostic(
                "invalid_executable_name_utf16",
                Some(entry.process_id),
                "The executable name contained invalid UTF-16 and was displayed lossily.",
            ));
        }
        let available = MAX_AGGREGATE_IMAGE_PATH_UTF16_UNITS.saturating_sub(image_total);
        let image = if available == 0 {
            truncated = true;
            WindowsProcessImage {
                status: WindowsProcessImageStatus::OverLimit,
                path: None,
                utf16_code_units: None,
            }
        } else {
            let image = api.read_image_path(entry.process_id, available);
            if let Some(count) = image.utf16_code_units {
                image_total = image_total.saturating_add(count);
            }
            if image.status != WindowsProcessImageStatus::Observed {
                truncated = true;
                diagnostics.push(image_diagnostic(entry.process_id, image.status));
            }
            image
        };
        let creation_time = api.read_creation_time(entry.process_id);
        if creation_time.status != WindowsProcessCreationTimeStatus::Observed {
            truncated = true;
            diagnostics.push(creation_time_diagnostic(
                entry.process_id,
                creation_time.status,
            ));
        }
        let sid_remaining = MAX_AGGREGATE_TOKEN_SID_UTF16_UNITS.saturating_sub(token_sid_total);
        let mut token_context = api.read_token_context(entry.process_id, sid_remaining);
        if let Some(sid) = token_context.user_sid.value.as_ref() {
            token_sid_total = token_sid_total.saturating_add(sid.encode_utf16().count());
        }
        validate_token_context_identity(&mut token_context, &creation_time);
        if token_context.identity_status != WindowsProcessTokenContextStatus::Observed {
            truncated = true;
            diagnostics.push(diagnostic(
                "process_token_identity_unverified",
                Some(entry.process_id),
                "Token facts could not be tied to the process generation in the snapshot.",
            ));
        }
        for (field, status) in [
            ("user_sid", token_context.user_sid.status),
            ("integrity_level", token_context.integrity_level_rid.status),
            ("session_id", token_context.session_id.status),
        ] {
            if status != WindowsProcessTokenFieldStatus::Observed {
                truncated = true;
                diagnostics.push(token_field_diagnostic(entry.process_id, field, status));
            }
        }
        rows.push(WindowsProcessRow {
            process_id: entry.process_id,
            parent_process_id: entry.parent_process_id,
            thread_count: entry.thread_count,
            executable_name: name.clone(),
            image,
            creation_time,
            token_context,
            evidence: WindowsProcessEvidence {
                snapshot_source: "ToolHelp32Snapshot/PROCESSENTRY32W",
                snapshot_index: index,
                process_id: entry.process_id,
                parent_process_id: entry.parent_process_id,
                thread_count: entry.thread_count,
                executable_name: name,
                image_source: "QueryFullProcessImageNameW",
            },
        });
    }
    rows.sort_by_key(|row| row.process_id);
    if process_limit_reached
        && !diagnostics
            .iter()
            .any(|item| item.code == "process_limit_exceeded")
    {
        diagnostics.push(diagnostic(
            "process_limit_exceeded",
            None,
            "The process-count limit was reached; remaining entries were not checked.",
        ));
    }
    finish(
        started_at,
        rows,
        diagnostics,
        seen.len(),
        image_total,
        token_sid_total,
        truncated,
    )
}

fn accept_process_id(seen: &mut HashSet<u32>, process_id: u32) -> bool {
    process_id != 0 && seen.insert(process_id)
}

fn trim_to_process_limit(entries: &mut Vec<RawEntry>) -> bool {
    if entries.len() <= MAX_PROCESSES {
        return false;
    }
    entries.truncate(MAX_PROCESSES);
    true
}

fn decode_executable_name(name: &[u16; 260]) -> (String, bool) {
    let Some(end) = name.iter().position(|unit| *unit == 0) else {
        return (String::from_utf16_lossy(name), true);
    };
    if end == 0 {
        return (String::new(), true);
    }
    match String::from_utf16(&name[..end]) {
        Ok(value) => (value, false),
        Err(_) => (String::from_utf16_lossy(&name[..end]), true),
    }
}

fn read_image_path_native(process_id: u32, aggregate_remaining: usize) -> WindowsProcessImage {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        return empty_image(image_status(unsafe { GetLastError() }));
    }
    let handle = OwnedHandle(handle);
    let mut buffer = vec![0u16; MAX_IMAGE_PATH_UTF16_UNITS];
    let mut length = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle.0, 0, buffer.as_mut_ptr(), &mut length) } == 0 {
        return empty_image(image_status(unsafe { GetLastError() }));
    }
    let length = length as usize;
    if length > aggregate_remaining {
        return WindowsProcessImage {
            status: WindowsProcessImageStatus::OverLimit,
            path: None,
            utf16_code_units: None,
        };
    }
    decode_image_path(&buffer[..length])
}

fn read_creation_time_native(process_id: u32) -> WindowsProcessCreationTime {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        return empty_creation_time(creation_time_status(unsafe { GetLastError() }));
    }
    let handle = OwnedHandle(handle);
    let mut creation = FileTime { low: 0, high: 0 };
    let mut exit = FileTime { low: 0, high: 0 };
    let mut kernel = FileTime { low: 0, high: 0 };
    let mut user = FileTime { low: 0, high: 0 };
    if unsafe { GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return empty_creation_time(creation_time_status(unsafe { GetLastError() }));
    }
    WindowsProcessCreationTime {
        status: WindowsProcessCreationTimeStatus::Observed,
        filetime_100ns: Some(((creation.high as u64) << 32) | creation.low as u64),
        source: Some("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)/GetProcessTimes"),
    }
}

fn validate_token_context_identity(
    context: &mut WindowsProcessTokenContext,
    row_creation_time: &WindowsProcessCreationTime,
) {
    match row_creation_time
        .filetime_100ns
        .zip(context.process_creation_time_filetime_100ns)
    {
        Some((row, token)) if row == token => {
            context.identity_status = WindowsProcessTokenContextStatus::Observed;
        }
        Some(_) => {
            context.identity_status = WindowsProcessTokenContextStatus::ChangedDuringRead;
            clear_token_context_values(context);
        }
        None => {
            context.identity_status = WindowsProcessTokenContextStatus::IdentityUnverified;
            clear_token_context_values(context);
        }
    }
}

fn clear_token_context_values(context: &mut WindowsProcessTokenContext) {
    context.user_sid.status = WindowsProcessTokenFieldStatus::IdentityUnverified;
    context.user_sid.value = None;
    context.integrity_level_rid.status = WindowsProcessTokenFieldStatus::IdentityUnverified;
    context.integrity_level_rid.value = None;
    context.session_id.status = WindowsProcessTokenFieldStatus::IdentityUnverified;
    context.session_id.value = None;
}

fn token_field_diagnostic(
    process_id: u32,
    field: &'static str,
    status: WindowsProcessTokenFieldStatus,
) -> WindowsProcessDiagnostic {
    let (code, message) = match status {
        WindowsProcessTokenFieldStatus::Observed => unreachable!(),
        WindowsProcessTokenFieldStatus::Inaccessible => (
            "process_token_field_inaccessible",
            "Windows denied access to a process token field.",
        ),
        WindowsProcessTokenFieldStatus::Vanished => (
            "process_token_field_vanished",
            "The process or token disappeared during collection.",
        ),
        WindowsProcessTokenFieldStatus::Malformed => (
            "process_token_field_malformed",
            "Windows returned a malformed process token field.",
        ),
        WindowsProcessTokenFieldStatus::OverLimit => (
            "process_token_context_limit_exceeded",
            "The process token field exceeded its configured bound.",
        ),
        WindowsProcessTokenFieldStatus::IdentityUnverified => (
            "process_token_identity_unverified",
            "The token field could not be tied to a verified process generation.",
        ),
        WindowsProcessTokenFieldStatus::Error => (
            "process_token_field_query_failed",
            "Windows could not query a process token field.",
        ),
    };
    diagnostic(code, Some(process_id), message).with_field(field)
}

#[repr(C)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}

#[repr(C)]
struct TokenUserInfo {
    user: SidAndAttributes,
}

#[repr(C)]
struct TokenMandatoryLabelInfo {
    label: SidAndAttributes,
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
    fn IsValidSid(sid: *mut c_void) -> i32;
    fn GetSidSubAuthorityCount(sid: *mut c_void) -> *mut u8;
    fn GetSidSubAuthority(sid: *mut c_void, index: u32) -> *mut u32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: Handle) -> Handle;
}

struct OwnedToken(Handle);
impl Drop for OwnedToken {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns a token handle returned by OpenProcessToken.
        unsafe { CloseHandle(self.0) };
    }
}

struct LocalString(*mut u16);
impl Drop for LocalString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this pointer was returned by ConvertSidToStringSidW.
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

fn read_token_context_native(
    process_id: u32,
    aggregate_sid_remaining: usize,
) -> WindowsProcessTokenContext {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        let status = token_field_status(unsafe { GetLastError() });
        return token_context_for_process_error(status);
    }
    let process = OwnedHandle(process);
    let generation = read_creation_time_from_handle(&process);
    let Some(generation) = generation else {
        return token_context_for_process_error(WindowsProcessTokenFieldStatus::IdentityUnverified);
    };
    let mut token_handle = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process.0, 0x0008, &mut token_handle) } == 0 {
        return token_context_with_generation(
            generation,
            token_fields_with_status(token_field_status(unsafe { GetLastError() })),
        );
    }
    let token = OwnedToken(token_handle);
    let sid_budget = aggregate_sid_remaining.min(MAX_PROCESS_TOKEN_SID_UTF16_UNITS);
    let user_sid = if sid_budget == 0 {
        token_field(
            WindowsProcessTokenFieldStatus::OverLimit,
            None,
            "GetTokenInformation/TokenUser",
        )
    } else {
        read_user_sid(&token, sid_budget)
    };
    let integrity_level_rid = read_integrity_level(&token);
    let session_id = read_session_id(&token);
    token_context_with_generation(generation, (user_sid, integrity_level_rid, session_id))
}

fn read_creation_time_from_handle(process: &OwnedHandle) -> Option<u64> {
    let mut creation = FileTime { low: 0, high: 0 };
    let mut exit = FileTime { low: 0, high: 0 };
    let mut kernel = FileTime { low: 0, high: 0 };
    let mut user = FileTime { low: 0, high: 0 };
    (unsafe { GetProcessTimes(process.0, &mut creation, &mut exit, &mut kernel, &mut user) } != 0)
        .then_some(((creation.high as u64) << 32) | creation.low as u64)
}

fn read_user_sid(token: &OwnedToken, sid_budget: usize) -> WindowsProcessTokenField<String> {
    let buffer = match token_information(token, 1) {
        Ok(buffer) => buffer,
        Err(status) => return token_field(status, None, "GetTokenInformation/TokenUser"),
    };
    if buffer.len() < size_of::<TokenUserInfo>() {
        return token_field(
            WindowsProcessTokenFieldStatus::Malformed,
            None,
            "GetTokenInformation/TokenUser",
        );
    }
    let info = buffer.as_ptr().cast::<TokenUserInfo>();
    // SAFETY: the buffer is initialized by GetTokenInformation and large enough for TokenUserInfo.
    let sid = unsafe { (*info).user.sid };
    match sid_to_string(sid, sid_budget) {
        Ok(value) => token_field(
            WindowsProcessTokenFieldStatus::Observed,
            Some(value),
            "GetTokenInformation/TokenUser",
        ),
        Err(status) => token_field(status, None, "GetTokenInformation/TokenUser"),
    }
}

fn read_integrity_level(token: &OwnedToken) -> WindowsProcessTokenField<u32> {
    let buffer = match token_information(token, 25) {
        Ok(buffer) => buffer,
        Err(status) => return token_field(status, None, "GetTokenInformation/TokenIntegrityLevel"),
    };
    if buffer.len() < size_of::<TokenMandatoryLabelInfo>() {
        return token_field(
            WindowsProcessTokenFieldStatus::Malformed,
            None,
            "GetTokenInformation/TokenIntegrityLevel",
        );
    }
    // SAFETY: the buffer is initialized by GetTokenInformation and large enough for this header.
    let sid = unsafe {
        (*buffer.as_ptr().cast::<TokenMandatoryLabelInfo>())
            .label
            .sid
    };
    // SAFETY: the SID pointer is returned as part of the validated token information buffer.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return token_field(
            WindowsProcessTokenFieldStatus::Malformed,
            None,
            "GetTokenInformation/TokenIntegrityLevel",
        );
    }
    // SAFETY: IsValidSid succeeded and the SID subauthority count is addressable.
    let count = unsafe { GetSidSubAuthorityCount(sid) };
    if count.is_null() || unsafe { *count } == 0 {
        return token_field(
            WindowsProcessTokenFieldStatus::Malformed,
            None,
            "GetTokenInformation/TokenIntegrityLevel",
        );
    }
    // SAFETY: the index is the last subauthority advertised by the valid SID.
    let rid = unsafe { GetSidSubAuthority(sid, (*count - 1) as u32) };
    if rid.is_null() {
        return token_field(
            WindowsProcessTokenFieldStatus::Malformed,
            None,
            "GetTokenInformation/TokenIntegrityLevel",
        );
    }
    token_field(
        WindowsProcessTokenFieldStatus::Observed,
        Some(unsafe { *rid }),
        "GetTokenInformation/TokenIntegrityLevel",
    )
}

fn read_session_id(token: &OwnedToken) -> WindowsProcessTokenField<u32> {
    let mut value = 0_u32;
    let mut needed = 0_u32;
    if unsafe {
        GetTokenInformation(
            token.0,
            12,
            (&mut value as *mut u32).cast(),
            size_of::<u32>() as u32,
            &mut needed,
        )
    } == 0
    {
        return token_field(
            token_field_status(unsafe { GetLastError() }),
            None,
            "GetTokenInformation/TokenSessionId",
        );
    }
    if needed as usize != size_of::<u32>() {
        return token_field(
            WindowsProcessTokenFieldStatus::Malformed,
            None,
            "GetTokenInformation/TokenSessionId",
        );
    }
    token_field(
        WindowsProcessTokenFieldStatus::Observed,
        Some(value),
        "GetTokenInformation/TokenSessionId",
    )
}

fn token_information(
    token: &OwnedToken,
    class: u32,
) -> Result<Vec<usize>, WindowsProcessTokenFieldStatus> {
    let mut needed = 0_u32;
    unsafe { GetTokenInformation(token.0, class, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 || needed as usize > MAX_TOKEN_INFO_BYTES {
        return Err(if needed as usize > MAX_TOKEN_INFO_BYTES {
            WindowsProcessTokenFieldStatus::OverLimit
        } else {
            token_field_status(unsafe { GetLastError() })
        });
    }
    let mut storage = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            class,
            storage.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(token_field_status(unsafe { GetLastError() }));
    }
    if needed as usize > MAX_TOKEN_INFO_BYTES
        || needed as usize > storage.len() * size_of::<usize>()
    {
        return Err(WindowsProcessTokenFieldStatus::OverLimit);
    }
    Ok(storage)
}

fn sid_to_string(
    sid: *mut c_void,
    sid_budget: usize,
) -> Result<String, WindowsProcessTokenFieldStatus> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(WindowsProcessTokenFieldStatus::Malformed);
    }
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(token_field_status(unsafe { GetLastError() }));
    }
    let text = LocalString(text);
    let mut len = 0usize;
    while len <= MAX_PROCESS_TOKEN_SID_UTF16_UNITS && unsafe { *text.0.add(len) } != 0 {
        len += 1;
    }
    if len == 0 {
        return Err(WindowsProcessTokenFieldStatus::Malformed);
    }
    if len > MAX_PROCESS_TOKEN_SID_UTF16_UNITS || len > sid_budget {
        return Err(WindowsProcessTokenFieldStatus::OverLimit);
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text.0, len) })
        .map_err(|_| WindowsProcessTokenFieldStatus::Malformed)
}

fn token_field<T>(
    status: WindowsProcessTokenFieldStatus,
    value: Option<T>,
    source: &'static str,
) -> WindowsProcessTokenField<T> {
    WindowsProcessTokenField {
        status,
        value,
        source,
    }
}

fn token_field_status(error: u32) -> WindowsProcessTokenFieldStatus {
    match error {
        ERROR_ACCESS_DENIED => WindowsProcessTokenFieldStatus::Inaccessible,
        ERROR_INVALID_HANDLE | ERROR_INVALID_PARAMETER | ERROR_NOT_FOUND => {
            WindowsProcessTokenFieldStatus::Vanished
        }
        ERROR_INSUFFICIENT_BUFFER => WindowsProcessTokenFieldStatus::OverLimit,
        _ => WindowsProcessTokenFieldStatus::Error,
    }
}

fn token_fields_with_status(
    status: WindowsProcessTokenFieldStatus,
) -> (
    WindowsProcessTokenField<String>,
    WindowsProcessTokenField<u32>,
    WindowsProcessTokenField<u32>,
) {
    (
        token_field(status, None, "GetTokenInformation/TokenUser"),
        token_field(status, None, "GetTokenInformation/TokenIntegrityLevel"),
        token_field(status, None, "GetTokenInformation/TokenSessionId"),
    )
}

fn token_context_with_generation(
    generation: u64,
    fields: (
        WindowsProcessTokenField<String>,
        WindowsProcessTokenField<u32>,
        WindowsProcessTokenField<u32>,
    ),
) -> WindowsProcessTokenContext {
    WindowsProcessTokenContext {
        identity_status: WindowsProcessTokenContextStatus::IdentityUnverified,
        process_creation_time_filetime_100ns: Some(generation),
        user_sid: fields.0,
        integrity_level_rid: fields.1,
        session_id: fields.2,
    }
}

fn token_context_for_process_error(
    status: WindowsProcessTokenFieldStatus,
) -> WindowsProcessTokenContext {
    WindowsProcessTokenContext {
        identity_status: WindowsProcessTokenContextStatus::IdentityUnverified,
        process_creation_time_filetime_100ns: None,
        user_sid: token_field(status, None, "GetTokenInformation/TokenUser"),
        integrity_level_rid: token_field(status, None, "GetTokenInformation/TokenIntegrityLevel"),
        session_id: token_field(status, None, "GetTokenInformation/TokenSessionId"),
    }
}

fn creation_time_status(error: u32) -> WindowsProcessCreationTimeStatus {
    match error {
        ERROR_ACCESS_DENIED => WindowsProcessCreationTimeStatus::Inaccessible,
        ERROR_INVALID_HANDLE | ERROR_INVALID_PARAMETER | ERROR_NOT_FOUND => {
            WindowsProcessCreationTimeStatus::Vanished
        }
        _ => WindowsProcessCreationTimeStatus::Error,
    }
}

fn empty_creation_time(status: WindowsProcessCreationTimeStatus) -> WindowsProcessCreationTime {
    WindowsProcessCreationTime {
        status,
        filetime_100ns: None,
        source: None,
    }
}

fn creation_time_diagnostic(
    process_id: u32,
    status: WindowsProcessCreationTimeStatus,
) -> WindowsProcessDiagnostic {
    let (code, message) = match status {
        WindowsProcessCreationTimeStatus::Inaccessible => (
            "process_creation_time_inaccessible",
            "Windows denied access to this process creation time.",
        ),
        WindowsProcessCreationTimeStatus::Vanished => (
            "process_creation_time_vanished",
            "The process disappeared before its creation time could be read.",
        ),
        WindowsProcessCreationTimeStatus::Error => (
            "process_creation_time_query_failed",
            "Windows could not query this process creation time.",
        ),
        WindowsProcessCreationTimeStatus::Observed => (
            "unexpected_creation_time_status",
            "An unexpected process creation time status was returned.",
        ),
    };
    diagnostic(code, Some(process_id), message)
}

fn decode_image_path(units: &[u16]) -> WindowsProcessImage {
    let (path, status) = match String::from_utf16(units) {
        Ok(path) => (path, WindowsProcessImageStatus::Observed),
        Err(_) => (
            String::from_utf16_lossy(units),
            WindowsProcessImageStatus::MalformedUtf16,
        ),
    };
    WindowsProcessImage {
        status,
        path: Some(path),
        utf16_code_units: Some(units.len()),
    }
}

fn image_status(error: u32) -> WindowsProcessImageStatus {
    match error {
        ERROR_INSUFFICIENT_BUFFER => WindowsProcessImageStatus::OverLimit,
        ERROR_ACCESS_DENIED => WindowsProcessImageStatus::Inaccessible,
        ERROR_INVALID_HANDLE | ERROR_INVALID_PARAMETER | ERROR_NOT_FOUND => {
            WindowsProcessImageStatus::Vanished
        }
        _ => WindowsProcessImageStatus::Error,
    }
}

fn empty_image(status: WindowsProcessImageStatus) -> WindowsProcessImage {
    WindowsProcessImage {
        status,
        path: None,
        utf16_code_units: None,
    }
}

fn image_diagnostic(pid: u32, status: WindowsProcessImageStatus) -> WindowsProcessDiagnostic {
    match status {
        WindowsProcessImageStatus::Inaccessible => diagnostic(
            "process_image_inaccessible",
            Some(pid),
            "Windows denied access to this process image path.",
        ),
        WindowsProcessImageStatus::Vanished => diagnostic(
            "process_vanished",
            Some(pid),
            "The process disappeared before its image path could be read.",
        ),
        WindowsProcessImageStatus::OverLimit => diagnostic(
            "image_path_limit_exceeded",
            Some(pid),
            "The per-process or aggregate image path limit was reached.",
        ),
        WindowsProcessImageStatus::MalformedUtf16 => diagnostic(
            "malformed_image_path_utf16",
            Some(pid),
            "Windows returned an image path with invalid UTF-16; its display contains replacement characters.",
        ),
        WindowsProcessImageStatus::Error => diagnostic(
            "process_image_query_failed",
            Some(pid),
            "Windows could not query this process image path.",
        ),
        WindowsProcessImageStatus::Observed => diagnostic(
            "unexpected_image_status",
            Some(pid),
            "An unexpected image query status was returned.",
        ),
    }
}

fn diagnostic(
    code: &'static str,
    process_id: Option<u32>,
    message: &'static str,
) -> WindowsProcessDiagnostic {
    WindowsProcessDiagnostic {
        code,
        process_id,
        field: None,
        message,
    }
}

impl WindowsProcessDiagnostic {
    fn with_field(mut self, field: &'static str) -> Self {
        self.field = Some(field);
        self
    }
}

fn finish(
    started_at: u128,
    processes: Vec<WindowsProcessRow>,
    diagnostics: Vec<WindowsProcessDiagnostic>,
    entries_seen: usize,
    image_path_utf16_code_units: usize,
    token_sid_utf16_code_units: usize,
    partial: bool,
) -> WindowsProcessInventoryDocument {
    let status = if partial || !diagnostics.is_empty() {
        WindowsProcessInventoryStatus::Partial
    } else {
        WindowsProcessInventoryStatus::Complete
    };
    WindowsProcessInventoryDocument {
        schema: "sideeffect.windows_process_inventory",
        schema_version: 3,
        platform: "windows",
        scope: "toolhelp_process_snapshot_image_paths_and_token_context",
        capture_started_at_unix_ms: started_at,
        capture_ended_at_unix_ms: now_ms(),
        status,
        source: WindowsProcessInventorySource {
            id: "toolhelp_process_snapshot",
            status,
            entries_seen,
            image_path_utf16_code_units,
            token_sid_utf16_code_units,
            diagnostics,
        },
        processes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeProcessApi {
        snapshot_error: Option<u32>,
        first_error: Option<u32>,
        enumeration_error_at: Option<usize>,
        entries: Vec<ProcessEntry32W>,
        next_index: usize,
        images: HashMap<u32, WindowsProcessImage>,
        creation_times: HashMap<u32, WindowsProcessCreationTime>,
        token_contexts: HashMap<u32, WindowsProcessTokenContext>,
    }

    impl FakeProcessApi {
        fn with_entries(entries: Vec<ProcessEntry32W>) -> Self {
            Self {
                snapshot_error: None,
                first_error: None,
                enumeration_error_at: None,
                entries,
                next_index: 0,
                images: HashMap::new(),
                creation_times: HashMap::new(),
                token_contexts: HashMap::new(),
            }
        }
    }

    impl WindowsProcessApi for FakeProcessApi {
        type Snapshot = ();

        fn create_snapshot(&mut self) -> Result<Self::Snapshot, u32> {
            self.snapshot_error.map_or(Ok(()), Err)
        }

        fn first_process(
            &mut self,
            _snapshot: &mut Self::Snapshot,
        ) -> Result<Option<ProcessEntry32W>, u32> {
            if let Some(error) = self.first_error {
                return Err(error);
            }
            self.next_index = 0;
            let first = self.entries.get(self.next_index).copied();
            if first.is_some() {
                self.next_index += 1;
            }
            Ok(first)
        }

        fn next_process(
            &mut self,
            _snapshot: &mut Self::Snapshot,
        ) -> Result<Option<ProcessEntry32W>, u32> {
            if self.enumeration_error_at == Some(self.next_index) {
                return Err(ERROR_ACCESS_DENIED);
            }
            let next = self.entries.get(self.next_index).copied();
            if next.is_some() {
                self.next_index += 1;
            }
            Ok(next)
        }

        fn read_image_path(
            &mut self,
            process_id: u32,
            _aggregate_remaining: usize,
        ) -> WindowsProcessImage {
            self.images
                .get(&process_id)
                .cloned()
                .unwrap_or_else(|| empty_image(WindowsProcessImageStatus::Error))
        }

        fn read_creation_time(&mut self, process_id: u32) -> WindowsProcessCreationTime {
            self.creation_times
                .get(&process_id)
                .cloned()
                .unwrap_or_else(|| empty_creation_time(WindowsProcessCreationTimeStatus::Error))
        }

        fn read_token_context(
            &mut self,
            process_id: u32,
            _aggregate_sid_remaining: usize,
        ) -> WindowsProcessTokenContext {
            if let Some(context) = self.token_contexts.get(&process_id) {
                return context.clone();
            }
            match self
                .creation_times
                .get(&process_id)
                .and_then(|time| time.filetime_100ns)
            {
                Some(generation) => WindowsProcessTokenContext {
                    identity_status: WindowsProcessTokenContextStatus::IdentityUnverified,
                    process_creation_time_filetime_100ns: Some(generation),
                    user_sid: token_field(
                        WindowsProcessTokenFieldStatus::Observed,
                        Some("S-1-5-18".to_owned()),
                        "synthetic TokenUser",
                    ),
                    integrity_level_rid: token_field(
                        WindowsProcessTokenFieldStatus::Observed,
                        Some(0x2000),
                        "synthetic TokenIntegrityLevel",
                    ),
                    session_id: token_field(
                        WindowsProcessTokenFieldStatus::Observed,
                        Some(1),
                        "synthetic TokenSessionId",
                    ),
                },
                None => token_context_for_process_error(WindowsProcessTokenFieldStatus::Error),
            }
        }
    }

    fn entry(name: &[u16], process_id: u32) -> ProcessEntry32W {
        let mut value: ProcessEntry32W = unsafe { zeroed() };
        value.process_id = process_id;
        value.parent_process_id = 1;
        value.thread_count = 2;
        let len = name.len().min(value.executable_name.len() - 1);
        value.executable_name[..len].copy_from_slice(&name[..len]);
        value.executable_name[len] = 0;
        value
    }

    fn observed_image(path: &str) -> WindowsProcessImage {
        WindowsProcessImage {
            status: WindowsProcessImageStatus::Observed,
            path: Some(path.to_owned()),
            utf16_code_units: Some(path.encode_utf16().count()),
        }
    }

    fn observed_creation_time(filetime_100ns: u64) -> WindowsProcessCreationTime {
        WindowsProcessCreationTime {
            status: WindowsProcessCreationTimeStatus::Observed,
            filetime_100ns: Some(filetime_100ns),
            source: Some("synthetic GetProcessTimes result"),
        }
    }

    #[test]
    fn decodes_toolhelp_names_and_reports_malformed_utf16_or_unterminated_values() {
        let valid = entry(&"safe.exe".encode_utf16().collect::<Vec<_>>(), 10);
        assert_eq!(
            decode_executable_name(&valid.executable_name),
            ("safe.exe".to_owned(), false)
        );
        let invalid = entry(&[0xd800], 11);
        assert!(decode_executable_name(&invalid.executable_name).1);
        let mut unterminated = [b'x' as u16; 260];
        assert!(decode_executable_name(&unterminated).1);
        unterminated[0] = 0;
        assert_eq!(decode_executable_name(&unterminated), (String::new(), true));
    }

    #[test]
    fn process_limit_and_duplicate_rows_are_bounded_and_partial() {
        let mut seen = HashSet::new();
        assert!(accept_process_id(&mut seen, 41));
        assert!(!accept_process_id(&mut seen, 41));
        assert!(!accept_process_id(&mut seen, 0));
        let mut entries = (1..=MAX_PROCESSES + 1)
            .map(|pid| {
                RawEntry(entry(
                    &"synthetic.exe".encode_utf16().collect::<Vec<_>>(),
                    pid as u32,
                ))
            })
            .collect::<Vec<_>>();
        assert!(trim_to_process_limit(&mut entries));
        assert_eq!(entries.len(), MAX_PROCESSES);
        let diagnostics = vec![diagnostic(
            "process_limit_exceeded",
            None,
            "The process-count limit was reached; remaining entries were not checked.",
        )];
        let doc = finish(now_ms(), Vec::new(), diagnostics, entries.len(), 0, 0, true);
        assert_eq!(doc.status, WindowsProcessInventoryStatus::Partial);
        assert_eq!(doc.source.entries_seen, MAX_PROCESSES);
        assert_eq!(doc.source.diagnostics[0].code, "process_limit_exceeded");
    }

    #[test]
    fn image_path_statuses_preserve_access_and_process_race_uncertainty() {
        assert_eq!(
            image_status(ERROR_ACCESS_DENIED),
            WindowsProcessImageStatus::Inaccessible
        );
        assert_eq!(
            image_status(ERROR_INVALID_PARAMETER),
            WindowsProcessImageStatus::Vanished
        );
        assert_eq!(
            image_status(ERROR_INSUFFICIENT_BUFFER),
            WindowsProcessImageStatus::OverLimit
        );
        assert_eq!(image_status(1234), WindowsProcessImageStatus::Error);
        assert_eq!(
            empty_image(WindowsProcessImageStatus::Inaccessible).path,
            None
        );
        let malformed = decode_image_path(&[0xd800]);
        assert_eq!(malformed.status, WindowsProcessImageStatus::MalformedUtf16);
        assert_eq!(malformed.path.as_deref(), Some("�"));
    }

    #[test]
    fn token_context_requires_matching_process_generation() {
        let mut context = WindowsProcessTokenContext {
            identity_status: WindowsProcessTokenContextStatus::IdentityUnverified,
            process_creation_time_filetime_100ns: Some(123),
            user_sid: token_field(
                WindowsProcessTokenFieldStatus::Observed,
                Some("S-1-5-18".to_owned()),
                "fixture",
            ),
            integrity_level_rid: token_field(
                WindowsProcessTokenFieldStatus::Observed,
                Some(8192),
                "fixture",
            ),
            session_id: token_field(WindowsProcessTokenFieldStatus::Observed, Some(1), "fixture"),
        };
        validate_token_context_identity(&mut context, &observed_creation_time(124));
        assert_eq!(
            context.identity_status,
            WindowsProcessTokenContextStatus::ChangedDuringRead
        );
        assert_eq!(context.user_sid.value, None);
        assert_eq!(
            context.user_sid.status,
            WindowsProcessTokenFieldStatus::IdentityUnverified
        );

        validate_token_context_identity(
            &mut context,
            &empty_creation_time(WindowsProcessCreationTimeStatus::Inaccessible),
        );
        assert_eq!(
            context.identity_status,
            WindowsProcessTokenContextStatus::IdentityUnverified
        );
        assert_eq!(context.session_id.value, None);
    }

    #[test]
    fn snapshot_failure_is_partial_and_has_no_process_rows() {
        let mut api = FakeProcessApi::with_entries(Vec::new());
        api.snapshot_error = Some(ERROR_ACCESS_DENIED);

        let document = collect_windows_processes_with_api(&mut api);

        assert_eq!(document.status, WindowsProcessInventoryStatus::Partial);
        assert!(document.processes.is_empty());
        assert_eq!(document.source.diagnostics.len(), 1);
        assert_eq!(document.source.diagnostics[0].code, "snapshot_unavailable");
    }

    #[test]
    fn snapshot_enumeration_failure_keeps_rows_already_observed() {
        let mut api = FakeProcessApi::with_entries(vec![entry(
            &"first.exe".encode_utf16().collect::<Vec<_>>(),
            10,
        )]);
        api.enumeration_error_at = Some(1);
        api.images
            .insert(10, observed_image(r"C:\Program Files\first.exe"));
        api.creation_times.insert(10, observed_creation_time(1234));

        let document = collect_windows_processes_with_api(&mut api);

        assert_eq!(document.status, WindowsProcessInventoryStatus::Partial);
        assert_eq!(document.processes.len(), 1);
        assert_eq!(document.processes[0].process_id, 10);
        assert_eq!(
            document.processes[0].image.status,
            WindowsProcessImageStatus::Observed
        );
        assert_eq!(
            document.processes[0].creation_time.filetime_100ns,
            Some(1234)
        );
        assert!(
            document
                .source
                .diagnostics
                .iter()
                .any(|item| item.code == "snapshot_enumeration_failed")
        );
    }

    #[test]
    fn inaccessible_and_vanished_image_queries_keep_process_rows_and_mark_partial() {
        let mut api = FakeProcessApi::with_entries(vec![
            entry(&"observed.exe".encode_utf16().collect::<Vec<_>>(), 10),
            entry(&"inaccessible.exe".encode_utf16().collect::<Vec<_>>(), 11),
            entry(&"vanished.exe".encode_utf16().collect::<Vec<_>>(), 12),
        ]);
        api.images
            .insert(10, observed_image(r"C:\Program Files\observed.exe"));
        api.images
            .insert(11, empty_image(WindowsProcessImageStatus::Inaccessible));
        api.images
            .insert(12, empty_image(WindowsProcessImageStatus::Vanished));

        let document = collect_windows_processes_with_api(&mut api);

        assert_eq!(document.status, WindowsProcessInventoryStatus::Partial);
        assert_eq!(document.processes.len(), 3);
        assert_eq!(document.processes[0].process_id, 10);
        assert_eq!(
            document.processes[1].image.status,
            WindowsProcessImageStatus::Inaccessible
        );
        assert_eq!(
            document.processes[2].image.status,
            WindowsProcessImageStatus::Vanished
        );
        assert!(document.source.diagnostics.iter().any(|item| {
            item.code == "process_image_inaccessible" && item.process_id == Some(11)
        }));
        assert!(
            document
                .source
                .diagnostics
                .iter()
                .any(|item| { item.code == "process_vanished" && item.process_id == Some(12) })
        );
    }

    #[test]
    fn unavailable_creation_time_is_preserved_and_makes_inventory_partial() {
        let mut api = FakeProcessApi::with_entries(vec![entry(
            &"restricted.exe".encode_utf16().collect::<Vec<_>>(),
            19,
        )]);
        api.images.insert(19, observed_image(r"C:\restricted.exe"));
        api.creation_times.insert(
            19,
            empty_creation_time(WindowsProcessCreationTimeStatus::Inaccessible),
        );

        let document = collect_windows_processes_with_api(&mut api);

        assert_eq!(document.status, WindowsProcessInventoryStatus::Partial);
        assert_eq!(
            document.processes[0].creation_time.status,
            WindowsProcessCreationTimeStatus::Inaccessible
        );
        assert_eq!(document.processes[0].creation_time.filetime_100ns, None);
        assert!(document.source.diagnostics.iter().any(|item| {
            item.code == "process_creation_time_inaccessible" && item.process_id == Some(19)
        }));
    }
}
