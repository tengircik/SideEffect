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
const MAX_SCAN_DURATION: Duration = Duration::from_secs(10);
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NO_MORE_FILES: u32 = 18;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NOT_FOUND: u32 = 1168;

type Handle = *mut c_void;

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
    pub image: WindowsProcessImage,
    pub evidence: WindowsProcessEvidence,
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
    pub message: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsProcessInventorySource {
    pub id: &'static str,
    pub status: WindowsProcessInventoryStatus,
    pub entries_seen: usize,
    pub image_path_utf16_code_units: usize,
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

struct RawEntry(ProcessEntry32W);

pub fn collect_windows_processes() -> WindowsProcessInventoryDocument {
    let started_at = now_ms();
    let started = Instant::now();
    let mut diagnostics = Vec::new();
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot as isize == -1 {
        diagnostics.push(diagnostic(
            "snapshot_unavailable",
            None,
            "Windows could not create a process snapshot.",
        ));
        return finish(started_at, Vec::new(), diagnostics, 0, 0, true);
    }
    let snapshot = OwnedHandle(snapshot);
    let mut entries = Vec::with_capacity(MAX_PROCESSES.min(512));
    let mut entry: ProcessEntry32W = unsafe { zeroed() };
    entry.size = size_of::<ProcessEntry32W>() as u32;
    let first = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    let mut truncated = false;
    let mut process_limit_reached = false;
    if first != 0 {
        loop {
            entries.push(RawEntry(copy_entry(&entry)));
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
            entry.size = size_of::<ProcessEntry32W>() as u32;
            if unsafe { Process32NextW(snapshot.0, &mut entry) } == 0 {
                let error = unsafe { GetLastError() };
                if error != ERROR_NO_MORE_FILES {
                    diagnostics.push(diagnostic(
                        "snapshot_enumeration_failed",
                        None,
                        "Windows stopped enumerating the process snapshot unexpectedly.",
                    ));
                    truncated = true;
                }
                break;
            }
        }
    } else {
        let error = unsafe { GetLastError() };
        if error != ERROR_NO_MORE_FILES {
            diagnostics.push(diagnostic(
                "snapshot_enumeration_failed",
                None,
                "Windows could not read the first process snapshot entry.",
            ));
            truncated = true;
        }
    }
    drop(snapshot);

    if trim_to_process_limit(&mut entries) {
        truncated = true;
        process_limit_reached = true;
    }
    let mut seen = HashSet::with_capacity(entries.len());
    let mut rows = Vec::with_capacity(entries.len());
    let mut image_total = 0usize;
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
            let image = read_image_path(entry.process_id, available);
            if let Some(count) = image.utf16_code_units {
                image_total = image_total.saturating_add(count);
            }
            if image.status != WindowsProcessImageStatus::Observed {
                truncated = true;
                diagnostics.push(image_diagnostic(entry.process_id, image.status));
            }
            image
        };
        rows.push(WindowsProcessRow {
            process_id: entry.process_id,
            parent_process_id: entry.parent_process_id,
            thread_count: entry.thread_count,
            executable_name: name.clone(),
            image,
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
        truncated,
    )
}

fn copy_entry(entry: &ProcessEntry32W) -> ProcessEntry32W {
    let mut copy: ProcessEntry32W = unsafe { zeroed() };
    copy.size = entry.size;
    copy.usage_count = entry.usage_count;
    copy.process_id = entry.process_id;
    copy.default_heap_id = entry.default_heap_id;
    copy.module_id = entry.module_id;
    copy.thread_count = entry.thread_count;
    copy.parent_process_id = entry.parent_process_id;
    copy.base_priority = entry.base_priority;
    copy.flags = entry.flags;
    copy.executable_name = entry.executable_name;
    copy
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

fn read_image_path(process_id: u32, aggregate_remaining: usize) -> WindowsProcessImage {
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
        message,
    }
}

fn finish(
    started_at: u128,
    processes: Vec<WindowsProcessRow>,
    diagnostics: Vec<WindowsProcessDiagnostic>,
    entries_seen: usize,
    image_path_utf16_code_units: usize,
    partial: bool,
) -> WindowsProcessInventoryDocument {
    let status = if partial || !diagnostics.is_empty() {
        WindowsProcessInventoryStatus::Partial
    } else {
        WindowsProcessInventoryStatus::Complete
    };
    WindowsProcessInventoryDocument {
        schema: "sideeffect.windows_process_inventory",
        schema_version: 1,
        platform: "windows",
        scope: "toolhelp_process_snapshot_and_queryable_image_paths",
        capture_started_at_unix_ms: started_at,
        capture_ended_at_unix_ms: now_ms(),
        status,
        source: WindowsProcessInventorySource {
            id: "toolhelp_process_snapshot",
            status,
            entries_seen,
            image_path_utf16_code_units,
            diagnostics,
        },
        processes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let doc = finish(now_ms(), Vec::new(), diagnostics, entries.len(), 0, true);
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
}
