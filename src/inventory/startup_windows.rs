//! Bounded native Windows startup configuration snapshot.
//!
//! Registry commands, service image paths, and startup-folder paths are data only.
//! This module never expands environment strings, parses command lines, or
//! launches entries.

use serde::Serialize;
use std::ffi::{OsStr, c_void};
use std::fs;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::ptr::null_mut;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::TaskScheduler::{
    IExecAction, ILogonTrigger, ITaskService, TASK_ACTION_COM_HANDLER, TASK_ACTION_EXEC,
    TASK_ACTION_SEND_EMAIL, TASK_ACTION_SHOW_MESSAGE, TASK_ACTION_TYPE, TASK_ENUM_HIDDEN,
    TASK_TRIGGER_BOOT, TASK_TRIGGER_LOGON, TASK_TRIGGER_TYPE2, TaskScheduler,
};
use windows::Win32::System::Variant::{VARIANT, VARIANT_0, VARIANT_0_0, VARIANT_0_0_0, VT_I4};
use windows::core::{BSTR, HRESULT, Interface};

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
const ERROR_PROC_NOT_FOUND: u32 = 127;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const KEY_READ: u32 = 0x0002_0019;
const KEY_WOW64_64KEY: u32 = 0x0100;
const KEY_WOW64_32KEY: u32 = 0x0200;
const MAX_VALUE_NAME_UNITS: usize = 16_384;
const MAX_VALUE_DATA_BYTES: usize = 64 * 1024;
const MAX_AGGREGATE_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_AGGREGATE_REGISTRY_NAME_UNITS: usize = 1024 * 1024;
const MAX_STARTUP_ENTRIES: usize = 8_192;
const MAX_PATH_UNITS: usize = 32_768;
const MAX_AGGREGATE_PATH_UNITS: usize = 4 * 1024 * 1024;
const MAX_SCAN_DURATION_MS: u128 = 10_000;
const MAX_SERVICE_ENUM_BYTES: usize = 256 * 1024;
const MAX_SERVICE_CONFIG_BYTES: usize = 64 * 1024;
const MAX_AGGREGATE_SERVICE_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_SERVICE_ENTRIES: usize = 8_192;
const MAX_SERVICE_STRING_UNITS: usize = 32_768;
const MAX_AGGREGATE_SERVICE_STRING_UNITS: usize = 4 * 1024 * 1024;
const MAX_SERVICE_DIAGNOSTICS: usize = 256;
const MAX_TASK_FOLDER_DEPTH: usize = 16;
const MAX_TASK_FOLDERS: usize = 1_024;
const MAX_SCHEDULED_TASKS: usize = 8_192;
const MAX_SCHEDULED_TASK_TRIGGERS: usize = 8_192;
const MAX_TRIGGERS_PER_TASK: usize = 256;
const MAX_SCHEDULED_TASK_ACTIONS: usize = 8_192;
const MAX_ACTIONS_PER_TASK: usize = 256;
const MAX_TASK_STRING_UNITS: usize = 32_768;
const MAX_AGGREGATE_TASK_STRING_UNITS: usize = 4 * 1024 * 1024;
const MAX_TASK_DIAGNOSTICS: usize = 256;
const SC_MANAGER_CONNECT: u32 = 0x0001;
const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
const SERVICE_QUERY_CONFIG: u32 = 0x0001;
const SC_ENUM_PROCESS_INFO: u32 = 0;
const SERVICE_DRIVER: u32 = 0x0000_000b;
const SERVICE_WIN32: u32 = 0x0000_0030;
const SERVICE_TYPE_ALL: u32 = SERVICE_DRIVER | SERVICE_WIN32;
const SERVICE_STATE_ALL: u32 = 0x0000_0003;
const SERVICE_BOOT_START: u32 = 0;
const SERVICE_SYSTEM_START: u32 = 1;
const SERVICE_AUTO_START: u32 = 2;
const SERVICE_DEMAND_START: u32 = 3;
const SERVICE_DISABLED: u32 = 4;
const KF_FLAG_DONT_VERIFY: u32 = 0x0000_4000;
const REGISTRY_ROOT_CURRENT_USER: isize = -2_147_483_647;
const REGISTRY_ROOT_LOCAL_MACHINE: isize = -2_147_483_646;

type Handle = *mut c_void;

#[repr(C)]
struct ServiceStatusProcess {
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_specific_exit_code: u32,
    check_point: u32,
    wait_hint: u32,
    process_id: u32,
    service_flags: u32,
}

#[repr(C)]
struct EnumServiceStatusProcessW {
    service_name: *mut u16,
    display_name: *mut u16,
    status: ServiceStatusProcess,
}

#[repr(C)]
struct QueryServiceConfigW {
    service_type: u32,
    start_type: u32,
    error_control: u32,
    binary_path_name: *mut u16,
    load_order_group: *mut u16,
    tag_id: u32,
    dependencies: *mut u16,
    service_start_name: *mut u16,
    display_name: *mut u16,
}

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(
        key: Handle,
        subkey: *const u16,
        options: u32,
        desired: u32,
        result: *mut Handle,
    ) -> i32;
    fn RegQueryInfoKeyW(
        key: Handle,
        class: *mut u16,
        class_length: *mut u32,
        reserved: *mut u32,
        subkeys: *mut u32,
        max_subkey_length: *mut u32,
        max_class_length: *mut u32,
        value_count: *mut u32,
        max_value_name_length: *mut u32,
        max_value_data_length: *mut u32,
        security_descriptor_size: *mut u32,
        last_write_time: *mut c_void,
    ) -> i32;
    fn RegEnumValueW(
        key: Handle,
        index: u32,
        value_name: *mut u16,
        value_name_length: *mut u32,
        reserved: *mut u32,
        value_type: *mut u32,
        data: *mut u8,
        data_length: *mut u32,
    ) -> i32;
    fn RegCloseKey(key: Handle) -> i32;
    fn OpenSCManagerW(
        machine_name: *const u16,
        database_name: *const u16,
        desired_access: u32,
    ) -> Handle;
    fn EnumServicesStatusExW(
        manager: Handle,
        info_level: u32,
        service_type: u32,
        service_state: u32,
        buffer: *mut u8,
        buffer_size: u32,
        bytes_needed: *mut u32,
        services_returned: *mut u32,
        resume_handle: *mut u32,
        group_name: *const u16,
    ) -> i32;
    fn OpenServiceW(manager: Handle, service_name: *const u16, desired_access: u32) -> Handle;
    fn QueryServiceConfigW(
        service: Handle,
        config: *mut QueryServiceConfigW,
        buffer_size: u32,
        bytes_needed: *mut u32,
    ) -> i32;
    fn CloseServiceHandle(service: Handle) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(
        folder_id: *const Guid,
        flags: u32,
        token: Handle,
        path: *mut *mut u16,
    ) -> i32;
}

#[link(name = "ole32")]
unsafe extern "system" {
    fn CoTaskMemFree(memory: *mut c_void);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsStartupStatus {
    Complete,
    Partial,
    NotPresent,
    Inaccessible,
    Unavailable,
    Unsupported,
    NotChecked,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupFailureClass {
    Missing,
    AccessDenied,
    Unsupported,
    ApiFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupFailureContext {
    RegistryKey,
    StartupFolder,
    KnownFolder,
    ServiceManager,
    ServiceApi,
    TaskSchedulerSetup,
    TaskSchedulerScan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StartupFailureMapping {
    status: WindowsStartupStatus,
    diagnostic_code: Option<&'static str>,
}

fn classify_win32_failure(code: u32) -> StartupFailureClass {
    match code {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => StartupFailureClass::Missing,
        ERROR_ACCESS_DENIED => StartupFailureClass::AccessDenied,
        ERROR_NOT_SUPPORTED | ERROR_CALL_NOT_IMPLEMENTED | ERROR_PROC_NOT_FOUND => {
            StartupFailureClass::Unsupported
        }
        _ => StartupFailureClass::ApiFailure,
    }
}

fn classify_hresult_failure(hresult: i32) -> StartupFailureClass {
    let raw = hresult as u32;
    if raw == 0x8000_4001 {
        return StartupFailureClass::Unsupported;
    }
    if raw & 0xffff_0000 == 0x8007_0000 {
        return classify_win32_failure(raw & 0x0000_ffff);
    }
    StartupFailureClass::ApiFailure
}

fn classify_io_failure(error: &std::io::Error) -> StartupFailureClass {
    if let Some(code) = error.raw_os_error() {
        return classify_win32_failure(code as u32);
    }
    match error.kind() {
        std::io::ErrorKind::NotFound => StartupFailureClass::Missing,
        std::io::ErrorKind::PermissionDenied => StartupFailureClass::AccessDenied,
        std::io::ErrorKind::Unsupported => StartupFailureClass::Unsupported,
        _ => StartupFailureClass::ApiFailure,
    }
}

fn map_startup_failure(
    context: StartupFailureContext,
    class: StartupFailureClass,
) -> StartupFailureMapping {
    use StartupFailureClass::{AccessDenied, ApiFailure, Missing, Unsupported};
    let (status, diagnostic_code) = match (context, class) {
        (StartupFailureContext::RegistryKey | StartupFailureContext::StartupFolder, Missing) => {
            (WindowsStartupStatus::NotPresent, None)
        }
        (StartupFailureContext::RegistryKey, AccessDenied) => (
            WindowsStartupStatus::Inaccessible,
            Some("registry_key_unavailable"),
        ),
        (StartupFailureContext::StartupFolder, AccessDenied) => (
            WindowsStartupStatus::Inaccessible,
            Some("startup_folder_inaccessible"),
        ),
        (StartupFailureContext::RegistryKey, Unsupported) => (
            WindowsStartupStatus::Unsupported,
            Some("registry_key_unsupported"),
        ),
        (StartupFailureContext::StartupFolder, Unsupported) => (
            WindowsStartupStatus::Unsupported,
            Some("startup_folder_unsupported"),
        ),
        (StartupFailureContext::RegistryKey, ApiFailure) => (
            WindowsStartupStatus::Error,
            Some("registry_key_unavailable"),
        ),
        (StartupFailureContext::StartupFolder, ApiFailure) => (
            WindowsStartupStatus::Error,
            Some("startup_folder_read_failed"),
        ),
        (StartupFailureContext::KnownFolder, Missing) => (WindowsStartupStatus::NotPresent, None),
        (StartupFailureContext::KnownFolder, AccessDenied) => (
            WindowsStartupStatus::Inaccessible,
            Some("startup_folder_inaccessible"),
        ),
        (StartupFailureContext::KnownFolder, Unsupported) => (
            WindowsStartupStatus::Unsupported,
            Some("startup_folder_unsupported"),
        ),
        (StartupFailureContext::KnownFolder, ApiFailure) => (
            WindowsStartupStatus::Unavailable,
            Some("startup_folder_unavailable"),
        ),
        (StartupFailureContext::ServiceManager, AccessDenied) => (
            WindowsStartupStatus::Inaccessible,
            Some("service_manager_access_denied"),
        ),
        (StartupFailureContext::ServiceManager, Unsupported) => (
            WindowsStartupStatus::Unsupported,
            Some("service_manager_unsupported"),
        ),
        (StartupFailureContext::ServiceManager, Missing | ApiFailure) => (
            WindowsStartupStatus::Unavailable,
            Some("service_manager_unavailable"),
        ),
        (StartupFailureContext::ServiceApi, Unsupported) => (
            WindowsStartupStatus::Partial,
            Some("service_api_unsupported"),
        ),
        (StartupFailureContext::ServiceApi, Missing | AccessDenied | ApiFailure) => {
            (WindowsStartupStatus::Partial, Some("service_api_failed"))
        }
        (StartupFailureContext::TaskSchedulerSetup, AccessDenied) => (
            WindowsStartupStatus::Inaccessible,
            Some("task_scheduler_inaccessible"),
        ),
        (StartupFailureContext::TaskSchedulerSetup, Unsupported) => (
            WindowsStartupStatus::Unsupported,
            Some("task_scheduler_unsupported"),
        ),
        (StartupFailureContext::TaskSchedulerSetup, Missing | ApiFailure) => (
            WindowsStartupStatus::Unavailable,
            Some("task_scheduler_unavailable"),
        ),
        (StartupFailureContext::TaskSchedulerScan, Unsupported) => (
            WindowsStartupStatus::Partial,
            Some("task_scheduler_scan_unsupported"),
        ),
        (StartupFailureContext::TaskSchedulerScan, Missing | AccessDenied | ApiFailure) => (
            WindowsStartupStatus::Partial,
            Some("task_scheduler_scan_incomplete"),
        ),
    };
    StartupFailureMapping {
        status,
        diagnostic_code,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsRegistryView {
    Native,
    Wow64_32,
    Wow64_64,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsStartupDiagnostic {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_index: Option<usize>,
    pub message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub win32_error: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hresult: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRegistryStartupEntry {
    pub registry_key: &'static str,
    pub hive: &'static str,
    pub registry_view: WindowsRegistryView,
    pub trigger: &'static str,
    pub value_name: String,
    pub value_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_utf16_hex: Option<String>,
    pub evidence: WindowsRegistryStartupEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRegistryStartupEvidence {
    pub source: &'static str,
    pub hive: &'static str,
    pub registry_view: WindowsRegistryView,
    pub registry_key: &'static str,
    pub value_index: usize,
    pub value_name: String,
    pub registry_type: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsStartupFolderEntry {
    pub folder_scope: &'static str,
    pub trigger: &'static str,
    pub display_path: String,
    pub path_utf16_hex: String,
    pub kind: &'static str,
    pub evidence: WindowsStartupFolderEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsStartupFolderEvidence {
    pub source: &'static str,
    pub folder_scope: &'static str,
    pub display_path: String,
    pub path_utf16_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsServiceStartupEntry {
    pub service_name: String,
    pub display_name: String,
    pub start_type: &'static str,
    pub start_type_code: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    pub evidence: WindowsServiceStartupEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsServiceStartupEvidence {
    pub source: &'static str,
    pub service_index: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsScheduledTaskStartupEntry {
    pub task_path: String,
    pub task_enabled: Option<bool>,
    pub trigger_type: &'static str,
    pub trigger_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logon_user: Option<String>,
    pub evidence: WindowsScheduledTaskStartupEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsScheduledTaskStartupEvidence {
    pub source: &'static str,
    pub task_index: usize,
    pub trigger_index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsScheduledTaskActionStatus {
    Observed,
    Unsupported,
    Partial,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsScheduledTaskAction {
    pub task_path: Option<String>,
    pub action_index: usize,
    pub action_type: &'static str,
    pub action_type_code: Option<i32>,
    pub status: WindowsScheduledTaskActionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    pub evidence: WindowsScheduledTaskActionEvidence,
}

#[derive(Clone, Copy)]
enum ExecActionField {
    Path,
    Arguments,
    WorkingDirectory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecActionTextError {
    Com(HRESULT),
    Invalid(TaskStringError),
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsScheduledTaskActionEvidence {
    pub source: &'static str,
    pub task_index: usize,
    pub action_index: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsStartupSource {
    pub id: &'static str,
    pub status: WindowsStartupStatus,
    pub entries_seen: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hive: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_key: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_view: Option<WindowsRegistryView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_path_utf16_hex: Option<String>,
    pub diagnostics: Vec<WindowsStartupDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsStartupInventoryDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub capture_started_at_unix_ms: u128,
    pub capture_ended_at_unix_ms: u128,
    pub status: WindowsStartupStatus,
    pub sources: Vec<WindowsStartupSource>,
    pub registry_entries: Vec<WindowsRegistryStartupEntry>,
    pub folder_entries: Vec<WindowsStartupFolderEntry>,
    pub service_entries: Vec<WindowsServiceStartupEntry>,
    pub scheduled_task_entries: Vec<WindowsScheduledTaskStartupEntry>,
    pub scheduled_task_actions: Vec<WindowsScheduledTaskAction>,
}

#[derive(Clone, Copy)]
struct RegistrySource {
    id: &'static str,
    hive: &'static str,
    root: isize,
    key: &'static str,
    trigger: &'static str,
    view: WindowsRegistryView,
    wow64_flag: u32,
}

const REGISTRY_SOURCES: [RegistrySource; 8] = [
    RegistrySource {
        id: "current_user_run_native",
        hive: "HKEY_CURRENT_USER",
        root: REGISTRY_ROOT_CURRENT_USER,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        trigger: "user_logon",
        view: WindowsRegistryView::Native,
        wow64_flag: 0,
    },
    RegistrySource {
        id: "current_user_run_once_native",
        hive: "HKEY_CURRENT_USER",
        root: REGISTRY_ROOT_CURRENT_USER,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        trigger: "user_logon_once",
        view: WindowsRegistryView::Native,
        wow64_flag: 0,
    },
    RegistrySource {
        id: "current_user_run_32",
        hive: "HKEY_CURRENT_USER",
        root: REGISTRY_ROOT_CURRENT_USER,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        trigger: "user_logon",
        view: WindowsRegistryView::Wow64_32,
        wow64_flag: KEY_WOW64_32KEY,
    },
    RegistrySource {
        id: "current_user_run_once_32",
        hive: "HKEY_CURRENT_USER",
        root: REGISTRY_ROOT_CURRENT_USER,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        trigger: "user_logon_once",
        view: WindowsRegistryView::Wow64_32,
        wow64_flag: KEY_WOW64_32KEY,
    },
    RegistrySource {
        id: "local_machine_run_64",
        hive: "HKEY_LOCAL_MACHINE",
        root: REGISTRY_ROOT_LOCAL_MACHINE,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        trigger: "user_logon",
        view: WindowsRegistryView::Wow64_64,
        wow64_flag: KEY_WOW64_64KEY,
    },
    RegistrySource {
        id: "local_machine_run_once_64",
        hive: "HKEY_LOCAL_MACHINE",
        root: REGISTRY_ROOT_LOCAL_MACHINE,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        trigger: "user_logon_once",
        view: WindowsRegistryView::Wow64_64,
        wow64_flag: KEY_WOW64_64KEY,
    },
    RegistrySource {
        id: "local_machine_run_32",
        hive: "HKEY_LOCAL_MACHINE",
        root: REGISTRY_ROOT_LOCAL_MACHINE,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        trigger: "user_logon",
        view: WindowsRegistryView::Wow64_32,
        wow64_flag: KEY_WOW64_32KEY,
    },
    RegistrySource {
        id: "local_machine_run_once_32",
        hive: "HKEY_LOCAL_MACHINE",
        root: REGISTRY_ROOT_LOCAL_MACHINE,
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        trigger: "user_logon_once",
        view: WindowsRegistryView::Wow64_32,
        wow64_flag: KEY_WOW64_32KEY,
    },
];

const FOLDER_IDS: [(&str, Guid); 2] = [
    (
        "user_startup",
        Guid {
            data1: 0xb97d20bb,
            data2: 0xf46a,
            data3: 0x4c97,
            data4: [0xba, 0x10, 0x5e, 0x36, 0x08, 0x43, 0x08, 0x54],
        },
    ),
    (
        "common_startup",
        Guid {
            data1: 0x82a5ea35,
            data2: 0xd9cd,
            data3: 0x47c5,
            data4: [0x96, 0x29, 0xe1, 0x5d, 0x2f, 0x71, 0x4e, 0x6e],
        },
    ),
];

struct RegistryKey(Handle);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

trait StartupRegistryApi {
    type Key;

    fn open(&mut self, source: RegistrySource) -> Result<Self::Key, u32>;
    fn query_value_info(&mut self, key: &Self::Key) -> Result<(u32, u32, u32), u32>;
    fn enumerate_value(
        &mut self,
        key: &Self::Key,
        index: u32,
        buffer: &mut StartupRegistryValueBuffer,
    ) -> u32;
}

struct StartupRegistryValueBuffer {
    name: Vec<u16>,
    name_length: u32,
    value_type: u32,
    data: Vec<u8>,
    data_length: u32,
}

struct NativeStartupRegistryApi;

impl StartupRegistryApi for NativeStartupRegistryApi {
    type Key = RegistryKey;

    fn open(&mut self, source: RegistrySource) -> Result<Self::Key, u32> {
        let subkey = wide_z(OsStr::new(source.key));
        let mut key = null_mut();
        let code = unsafe {
            RegOpenKeyExW(
                source.root as Handle,
                subkey.as_ptr(),
                0,
                KEY_READ | source.wow64_flag,
                &mut key,
            )
        } as u32;
        if code == 0 {
            Ok(RegistryKey(key))
        } else {
            Err(code)
        }
    }

    fn query_value_info(&mut self, key: &Self::Key) -> Result<(u32, u32, u32), u32> {
        let mut value_count = 0u32;
        let mut max_name = 0u32;
        let mut max_data = 0u32;
        let code = unsafe {
            RegQueryInfoKeyW(
                key.0,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut value_count,
                &mut max_name,
                &mut max_data,
                null_mut(),
                null_mut(),
            )
        } as u32;
        if code == 0 {
            Ok((value_count, max_name, max_data))
        } else {
            Err(code)
        }
    }

    fn enumerate_value(
        &mut self,
        key: &Self::Key,
        index: u32,
        buffer: &mut StartupRegistryValueBuffer,
    ) -> u32 {
        (unsafe {
            RegEnumValueW(
                key.0,
                index,
                buffer.name.as_mut_ptr(),
                &mut buffer.name_length,
                null_mut(),
                &mut buffer.value_type,
                if buffer.data.is_empty() {
                    null_mut()
                } else {
                    buffer.data.as_mut_ptr()
                },
                &mut buffer.data_length,
            )
        }) as u32
    }
}

struct KnownFolderPath(*mut u16);

impl Drop for KnownFolderPath {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(self.0.cast()) };
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn collect_windows_startup() -> WindowsStartupInventoryDocument {
    let started_at = now_ms();
    let started = Instant::now();
    let mut sources = Vec::new();
    let mut registry_entries = Vec::new();
    let mut folder_entries = Vec::new();
    let mut service_entries = Vec::new();
    let mut scheduled_task_entries = Vec::new();
    let mut aggregate_registry_bytes = 0usize;
    let mut aggregate_registry_names = 0usize;
    let mut registry_values_checked = 0usize;
    let mut aggregate_path_units = 0usize;
    let mut folder_entries_checked = 0usize;
    for source in REGISTRY_SOURCES {
        if elapsed(started) {
            let mut result = source_result(
                source.id,
                WindowsStartupStatus::Partial,
                0,
                vec![diagnostic(
                    "scan_deadline_exceeded",
                    None,
                    "The startup inventory time limit was reached before this source was checked.",
                )],
            );
            result.registry_hive = Some(source.hive);
            result.registry_key = Some(source.key);
            result.registry_view = Some(source.view);
            sources.push(result);
            continue;
        }
        let remaining_entries = (MAX_STARTUP_ENTRIES / 2).saturating_sub(registry_values_checked);
        let (mut result, entries, bytes, checked, names) = collect_registry_source(
            source,
            started,
            MAX_AGGREGATE_REGISTRY_BYTES.saturating_sub(aggregate_registry_bytes),
            MAX_AGGREGATE_REGISTRY_NAME_UNITS.saturating_sub(aggregate_registry_names),
            remaining_entries,
        );
        result.registry_hive = Some(source.hive);
        result.registry_key = Some(source.key);
        result.registry_view = Some(source.view);
        aggregate_registry_bytes = aggregate_registry_bytes.saturating_add(bytes);
        aggregate_registry_names = aggregate_registry_names.saturating_add(names);
        registry_values_checked = registry_values_checked.saturating_add(checked);
        registry_entries.extend(entries);
        sources.push(result);
    }

    for (folder_scope, folder_id) in &FOLDER_IDS {
        if elapsed(started) {
            sources.push(source_result(
                folder_scope,
                WindowsStartupStatus::Partial,
                0,
                vec![diagnostic(
                    "scan_deadline_exceeded",
                    None,
                    "The startup inventory time limit was reached before this folder was checked.",
                )],
            ));
            continue;
        }
        let remaining_entries = (MAX_STARTUP_ENTRIES / 2).saturating_sub(folder_entries_checked);
        let (result, entries, units, checked) = collect_startup_folder(
            folder_scope,
            folder_id,
            MAX_AGGREGATE_PATH_UNITS.saturating_sub(aggregate_path_units),
            remaining_entries,
            started,
        );
        aggregate_path_units = aggregate_path_units.saturating_add(units);
        folder_entries_checked = folder_entries_checked.saturating_add(checked);
        folder_entries.extend(entries);
        sources.push(result);
    }

    let (service_source, services) = collect_service_start_configuration(started);
    sources.push(service_source);
    service_entries.extend(services);
    let (task_source, tasks, task_actions) = collect_scheduled_task_triggers(started);
    sources.push(task_source);
    scheduled_task_entries.extend(tasks);
    let scheduled_task_actions = task_actions;
    let status = if sources.iter().any(|source| {
        !matches!(
            source.status,
            WindowsStartupStatus::Complete | WindowsStartupStatus::NotPresent
        )
    }) {
        WindowsStartupStatus::Partial
    } else {
        WindowsStartupStatus::Complete
    };
    WindowsStartupInventoryDocument {
        schema: "sideeffect.windows_startup_inventory",
        schema_version: 4,
        platform: "windows",
        scope: "current_user_and_accessible_machine_run_keys_startup_folders_services_and_current_token_visible_tasks",
        capture_started_at_unix_ms: started_at,
        capture_ended_at_unix_ms: now_ms(),
        status,
        sources,
        registry_entries,
        folder_entries,
        service_entries,
        scheduled_task_entries,
        scheduled_task_actions,
    }
}

struct ServiceHandle(Handle);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceStringError {
    Missing,
    OutsideBuffer,
    Misaligned,
    Unterminated,
    OverLimit,
    MalformedUtf16,
}

fn collect_service_start_configuration(
    started: Instant,
) -> (WindowsStartupSource, Vec<WindowsServiceStartupEntry>) {
    let mut diagnostics = Vec::new();
    let mut entries = Vec::new();
    let mut status = WindowsStartupStatus::Complete;
    let mut aggregate_config_bytes = 0usize;
    let mut aggregate_string_units = 0usize;
    let mut enumerated = 0usize;
    let manager = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        )
    };
    if manager.is_null() {
        let error = unsafe { GetLastError() };
        let mapping = map_startup_failure(
            StartupFailureContext::ServiceManager,
            classify_win32_failure(error),
        );
        return (
            source_result(
                "service_start_configuration",
                mapping.status,
                0,
                vec![diagnostic_win32(
                    mapping
                        .diagnostic_code
                        .unwrap_or("service_manager_unavailable"),
                    None,
                    "Windows could not open the Service Control Manager with read-only enumeration access.",
                    error,
                )],
            ),
            entries,
        );
    }
    let manager = ServiceHandle(manager);
    let enum_words = MAX_SERVICE_ENUM_BYTES.div_ceil(std::mem::size_of::<u64>());
    let mut resume = 0u32;
    let mut previous_resume = u32::MAX;
    let mut enumeration_finished = false;
    while !enumeration_finished && enumerated < MAX_SERVICE_ENTRIES {
        if elapsed(started) {
            status = WindowsStartupStatus::Partial;
            push_service_diagnostic(
                &mut diagnostics,
                diagnostic(
                    "service_scan_deadline_exceeded",
                    None,
                    "The startup inventory time limit was reached during service enumeration.",
                ),
            );
            break;
        }
        let mut buffer = vec![0u64; enum_words];
        let buffer_bytes = buffer.len() * std::mem::size_of::<u64>();
        let mut bytes_needed = 0u32;
        let mut returned = 0u32;
        let prior_resume = resume;
        let success = unsafe {
            EnumServicesStatusExW(
                manager.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_TYPE_ALL,
                SERVICE_STATE_ALL,
                buffer.as_mut_ptr().cast(),
                buffer_bytes as u32,
                &mut bytes_needed,
                &mut returned,
                &mut resume,
                std::ptr::null(),
            )
        } != 0;
        let error = if success {
            0
        } else {
            unsafe { GetLastError() }
        };
        if !success && error != ERROR_MORE_DATA {
            let mapping = map_startup_failure(
                StartupFailureContext::ServiceApi,
                classify_win32_failure(error),
            );
            status = mapping.status;
            push_service_diagnostic(
                &mut diagnostics,
                diagnostic_win32(
                    mapping
                        .diagnostic_code
                        .unwrap_or("service_enumeration_failed"),
                    None,
                    "Windows could not enumerate all service configurations visible to this user.",
                    error,
                ),
            );
            break;
        }
        let item_size = std::mem::size_of::<EnumServiceStatusProcessW>();
        let capacity = buffer_bytes / item_size;
        if returned as usize > capacity {
            status = WindowsStartupStatus::Partial;
            push_service_diagnostic(
                &mut diagnostics,
                diagnostic(
                    "service_enumeration_result_malformed",
                    None,
                    "Windows returned a service count that exceeded the bounded enumeration buffer.",
                ),
            );
            break;
        }
        let base = buffer.as_ptr().cast::<u8>();
        for index in 0..returned as usize {
            if elapsed(started) {
                status = WindowsStartupStatus::Partial;
                push_service_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "service_scan_deadline_exceeded",
                        Some(enumerated),
                        "The startup inventory time limit was reached while querying services.",
                    ),
                );
                enumeration_finished = true;
                break;
            }
            let item_ptr = unsafe {
                base.add(index * item_size)
                    .cast::<EnumServiceStatusProcessW>()
            };
            let item = unsafe { &*item_ptr };
            let name = bounded_wide_in_buffer(
                base,
                buffer_bytes,
                item.service_name,
                MAX_SERVICE_STRING_UNITS,
            );
            let display = bounded_wide_in_buffer(
                base,
                buffer_bytes,
                item.display_name,
                MAX_SERVICE_STRING_UNITS,
            );
            let (Ok(name), Ok(display)) = (name, display) else {
                status = WindowsStartupStatus::Partial;
                push_service_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "service_enumeration_string_invalid",
                        Some(enumerated),
                        "Windows returned a malformed or over-limit service name or display name; that row was omitted.",
                    ),
                );
                enumerated += 1;
                continue;
            };
            let row_units = name
                .encode_utf16()
                .count()
                .saturating_add(display.encode_utf16().count());
            if aggregate_string_units.saturating_add(row_units) > MAX_AGGREGATE_SERVICE_STRING_UNITS
            {
                status = WindowsStartupStatus::Partial;
                push_service_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "service_string_budget_exceeded",
                        Some(enumerated),
                        "The aggregate service-string limit was reached; remaining services were not checked.",
                    ),
                );
                enumeration_finished = true;
                break;
            }
            aggregate_string_units += row_units;
            let service_name_wide = wide_z(name.as_str());
            let service = unsafe {
                OpenServiceW(manager.0, service_name_wide.as_ptr(), SERVICE_QUERY_CONFIG)
            };
            if service.is_null() {
                let error = unsafe { GetLastError() };
                let mapping = map_startup_failure(
                    StartupFailureContext::ServiceApi,
                    classify_win32_failure(error),
                );
                status = mapping.status;
                push_service_diagnostic(
                    &mut diagnostics,
                    diagnostic_win32(
                        mapping.diagnostic_code.unwrap_or("service_open_failed"),
                        Some(enumerated),
                        "Windows denied or failed opening this service for configuration query; the service row is unknown.",
                        error,
                    ),
                );
                enumerated += 1;
                continue;
            }
            let service = ServiceHandle(service);
            let mut required_bytes = 0u32;
            let first_result = unsafe {
                QueryServiceConfigW(service.0, std::ptr::null_mut(), 0, &mut required_bytes)
            };
            let first_error = if first_result == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            if first_result != 0 || first_error != ERROR_INSUFFICIENT_BUFFER {
                let mapping = map_startup_failure(
                    StartupFailureContext::ServiceApi,
                    classify_win32_failure(first_error),
                );
                status = mapping.status;
                push_service_diagnostic(
                    &mut diagnostics,
                    diagnostic_win32(
                        mapping
                            .diagnostic_code
                            .unwrap_or("service_configuration_query_failed"),
                        Some(enumerated),
                        "Windows could not determine the bounded service-configuration buffer size.",
                        first_error,
                    ),
                );
                enumerated += 1;
                continue;
            }
            let config_bytes = required_bytes as usize;
            if config_bytes < std::mem::size_of::<QueryServiceConfigW>()
                || config_bytes > MAX_SERVICE_CONFIG_BYTES
                || aggregate_config_bytes.saturating_add(config_bytes)
                    > MAX_AGGREGATE_SERVICE_CONFIG_BYTES
            {
                status = WindowsStartupStatus::Partial;
                push_service_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "service_configuration_budget_exceeded",
                        Some(enumerated),
                        "The service configuration was malformed or exceeded a per-entry or aggregate byte limit; it was omitted.",
                    ),
                );
                enumerated += 1;
                continue;
            }
            let word_count = config_bytes.div_ceil(std::mem::size_of::<u64>());
            let mut config_buffer = vec![0u64; word_count];
            let mut actual_bytes = 0u32;
            let query_success = unsafe {
                QueryServiceConfigW(
                    service.0,
                    config_buffer.as_mut_ptr().cast(),
                    config_bytes as u32,
                    &mut actual_bytes,
                )
            } != 0;
            if !query_success {
                let error = unsafe { GetLastError() };
                let mapping = map_startup_failure(
                    StartupFailureContext::ServiceApi,
                    classify_win32_failure(error),
                );
                status = mapping.status;
                push_service_diagnostic(
                    &mut diagnostics,
                    diagnostic_win32(
                        mapping
                            .diagnostic_code
                            .unwrap_or("service_configuration_query_failed"),
                        Some(enumerated),
                        "Windows could not read this service's configuration; its row is unknown.",
                        error,
                    ),
                );
                enumerated += 1;
                continue;
            }
            aggregate_config_bytes += config_bytes;
            let config_base = config_buffer.as_ptr().cast::<u8>();
            let config = unsafe { &*config_buffer.as_ptr().cast::<QueryServiceConfigW>() };
            let account = bounded_optional_wide_in_buffer(
                config_base,
                config_bytes,
                config.service_start_name,
                MAX_SERVICE_STRING_UNITS,
            );
            let binary_path = bounded_optional_wide_in_buffer(
                config_base,
                config_bytes,
                config.binary_path_name,
                MAX_SERVICE_STRING_UNITS,
            );
            let (Ok(account), Ok(binary_path)) = (account, binary_path) else {
                status = WindowsStartupStatus::Partial;
                push_service_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "service_configuration_string_invalid",
                        Some(enumerated),
                        "A service account or binary path was malformed or over limit; the service row was omitted.",
                    ),
                );
                enumerated += 1;
                continue;
            };
            let extra_units = account
                .as_ref()
                .map_or(0, |value| value.encode_utf16().count())
                + binary_path
                    .as_ref()
                    .map_or(0, |value| value.encode_utf16().count());
            if aggregate_string_units.saturating_add(extra_units)
                > MAX_AGGREGATE_SERVICE_STRING_UNITS
            {
                status = WindowsStartupStatus::Partial;
                push_service_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "service_string_budget_exceeded",
                        Some(enumerated),
                        "The aggregate service-string limit was reached; remaining services were not checked.",
                    ),
                );
                enumeration_finished = true;
                break;
            }
            aggregate_string_units += extra_units;
            entries.push(WindowsServiceStartupEntry {
                service_name: name,
                display_name: display,
                start_type: service_start_type(config.start_type),
                start_type_code: config.start_type,
                account,
                binary_path,
                evidence: WindowsServiceStartupEvidence {
                    source: "EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW",
                    service_index: enumerated,
                },
            });
            enumerated += 1;
        }
        if enumeration_finished {
            break;
        }
        if !success {
            if returned == 0 || resume == prior_resume || resume == previous_resume {
                status = WindowsStartupStatus::Partial;
                push_service_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "service_enumeration_buffer_insufficient",
                        None,
                        "The bounded SCM enumeration buffer could not advance; remaining services were not checked.",
                    ),
                );
                break;
            }
            previous_resume = prior_resume;
        } else {
            enumeration_finished = true;
        }
        if enumerated >= MAX_SERVICE_ENTRIES {
            status = WindowsStartupStatus::Partial;
            push_service_diagnostic(
                &mut diagnostics,
                diagnostic(
                    "service_entry_limit_exceeded",
                    None,
                    "The service-entry limit was reached; remaining services were not checked.",
                ),
            );
        }
    }
    (
        source_result(
            "service_start_configuration",
            status,
            entries.len(),
            diagnostics,
        ),
        entries,
    )
}

struct ComApartment;

impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaskStringError {
    OverLimit,
    MalformedUtf16,
    AggregateLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaskCountError {
    Negative,
}

fn collect_scheduled_task_triggers(
    started: Instant,
) -> (
    WindowsStartupSource,
    Vec<WindowsScheduledTaskStartupEntry>,
    Vec<WindowsScheduledTaskAction>,
) {
    let mut diagnostics = Vec::new();
    let mut entries = Vec::new();
    let mut actions = Vec::new();
    let mut status = WindowsStartupStatus::Complete;
    let mut tasks_seen = 0usize;
    let mut folders_seen = 0usize;
    let mut aggregate_string_units = 0usize;
    let mut trigger_row_limit_hit = false;

    let init_result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    if init_result.is_err() {
        return (
            source_result(
                "scheduled_task_triggers",
                WindowsStartupStatus::Unavailable,
                0,
                vec![diagnostic_hresult(
                    "task_scheduler_com_initialization_failed",
                    None,
                    "COM could not initialize the local Task Scheduler query apartment.",
                    init_result,
                )],
            ),
            entries,
            actions,
        );
    }
    let _apartment = ComApartment;
    let service = match unsafe {
        CoCreateInstance::<_, ITaskService>(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
    } {
        Ok(service) => service,
        Err(error) => {
            let mapping = task_error_mapping(&error, StartupFailureContext::TaskSchedulerSetup);
            return (
                source_result(
                    "scheduled_task_triggers",
                    mapping.status,
                    0,
                    vec![diagnostic_hresult(
                        mapping
                            .diagnostic_code
                            .unwrap_or("task_scheduler_service_unavailable"),
                        None,
                        "Windows could not create the local Task Scheduler COM service object.",
                        error.code(),
                    )],
                ),
                entries,
                actions,
            );
        }
    };
    let empty = VARIANT::default();
    if let Err(error) = unsafe { service.Connect(&empty, &empty, &empty, &empty) } {
        let mapping = task_error_mapping(&error, StartupFailureContext::TaskSchedulerSetup);
        return (
            source_result(
                "scheduled_task_triggers",
                mapping.status,
                0,
                vec![diagnostic_hresult(
                    mapping
                        .diagnostic_code
                        .unwrap_or("task_scheduler_connection_failed"),
                    None,
                    "Windows denied or failed connecting to the local Task Scheduler with the current user's token.",
                    error.code(),
                )],
            ),
            entries,
            actions,
        );
    }
    let root_path = BSTR::from("\\");
    let root = match unsafe { service.GetFolder(&root_path) } {
        Ok(root) => root,
        Err(error) => {
            let mapping = task_error_mapping(&error, StartupFailureContext::TaskSchedulerSetup);
            return (
                source_result(
                    "scheduled_task_triggers",
                    mapping.status,
                    0,
                    vec![diagnostic_hresult(
                        mapping
                            .diagnostic_code
                            .unwrap_or("task_scheduler_root_folder_unavailable"),
                        None,
                        "Windows denied or failed opening the root folder of tasks visible to the current user.",
                        error.code(),
                    )],
                ),
                entries,
                actions,
            );
        }
    };

    let mut pending_folders = vec![(root, 0usize)];
    while let Some((folder, depth)) = pending_folders.pop() {
        if elapsed(started) {
            status = WindowsStartupStatus::Partial;
            push_task_diagnostic(
                &mut diagnostics,
                diagnostic(
                    "task_scheduler_scan_deadline_exceeded",
                    None,
                    "The shared startup inventory time limit was reached during scheduled-task enumeration.",
                ),
            );
            break;
        }
        folders_seen += 1;
        let tasks = match unsafe { folder.GetTasks(TASK_ENUM_HIDDEN.0) } {
            Ok(tasks) => tasks,
            Err(error) => {
                let mapping = task_error_mapping(&error, StartupFailureContext::TaskSchedulerScan);
                status = mapping.status;
                push_task_diagnostic(
                    &mut diagnostics,
                    diagnostic_hresult(
                        mapping
                            .diagnostic_code
                            .unwrap_or("task_folder_enumeration_failed"),
                        Some(folders_seen - 1),
                        "Windows denied or failed enumerating tasks in a visible folder; that folder remains unknown.",
                        error.code(),
                    ),
                );
                continue;
            }
        };
        let task_count = match unsafe { tasks.Count() } {
            Ok(count) => count,
            Err(error) => {
                status = WindowsStartupStatus::Partial;
                push_task_diagnostic(
                    &mut diagnostics,
                    diagnostic_hresult(
                        "task_folder_count_failed",
                        Some(folders_seen - 1),
                        "Windows could not determine the number of tasks in a visible folder.",
                        error.code(),
                    ),
                );
                continue;
            }
        };
        let remaining_tasks = MAX_SCHEDULED_TASKS.saturating_sub(tasks_seen);
        let (tasks_to_read, task_limit_hit) = match bounded_task_count(task_count, remaining_tasks)
        {
            Ok(bound) => bound,
            Err(_) => {
                status = WindowsStartupStatus::Partial;
                push_task_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "task_folder_count_malformed",
                        Some(folders_seen - 1),
                        "Windows returned a negative task count; that folder was not enumerated.",
                    ),
                );
                continue;
            }
        };
        for task_number in 1..=tasks_to_read {
            if elapsed(started) {
                status = WindowsStartupStatus::Partial;
                push_task_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "task_scheduler_scan_deadline_exceeded",
                        Some(tasks_seen),
                        "The shared startup inventory time limit was reached while reading tasks.",
                    ),
                );
                break;
            }
            let task_index = tasks_seen;
            tasks_seen += 1;
            let task_variant = one_based_task_index(task_number as i32);
            let task = match unsafe { tasks.get_Item(&task_variant) } {
                Ok(task) => task,
                Err(error) => {
                    status = WindowsStartupStatus::Partial;
                    push_task_diagnostic(
                        &mut diagnostics,
                        diagnostic_hresult(
                            if task_error_is_access_denied(&error) {
                                "task_access_denied"
                            } else {
                                "task_read_failed"
                            },
                            Some(task_index),
                            "Windows denied or failed reading a task visible in the folder count.",
                            error.code(),
                        ),
                    );
                    continue;
                }
            };
            let definition = match unsafe { task.Definition() } {
                Ok(definition) => definition,
                Err(error) => {
                    status = WindowsStartupStatus::Partial;
                    push_task_diagnostic(
                        &mut diagnostics,
                        diagnostic_hresult(
                            "task_definition_read_failed",
                            Some(task_index),
                            "Windows could not read a task definition; its startup triggers remain unknown.",
                            error.code(),
                        ),
                    );
                    continue;
                }
            };
            let triggers = match unsafe { definition.Triggers() } {
                Ok(triggers) => triggers,
                Err(error) => {
                    status = WindowsStartupStatus::Partial;
                    push_task_diagnostic(
                        &mut diagnostics,
                        diagnostic_hresult(
                            "task_trigger_collection_read_failed",
                            Some(task_index),
                            "Windows could not read a task's trigger collection.",
                            error.code(),
                        ),
                    );
                    continue;
                }
            };
            let mut trigger_count = 0i32;
            if let Err(error) = unsafe { triggers.Count(&mut trigger_count) } {
                status = WindowsStartupStatus::Partial;
                push_task_diagnostic(
                    &mut diagnostics,
                    diagnostic_hresult(
                        "task_trigger_count_failed",
                        Some(task_index),
                        "Windows could not determine a task's trigger count.",
                        error.code(),
                    ),
                );
                continue;
            }
            let (triggers_to_read, trigger_limit_hit) = match bounded_task_count(
                trigger_count,
                MAX_TRIGGERS_PER_TASK,
            ) {
                Ok(bound) => bound,
                Err(_) => {
                    status = WindowsStartupStatus::Partial;
                    push_task_diagnostic(
                        &mut diagnostics,
                        diagnostic(
                            "task_trigger_count_malformed",
                            Some(task_index),
                            "Windows returned a negative trigger count; that task's triggers remain unknown.",
                        ),
                    );
                    continue;
                }
            };
            if trigger_limit_hit {
                status = WindowsStartupStatus::Partial;
                push_task_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "task_trigger_limit_exceeded",
                        Some(task_index),
                        "The per-task trigger limit was reached; remaining triggers were not checked.",
                    ),
                );
            }
            let mut task_actions_collected = false;
            for trigger_number in 1..=triggers_to_read {
                if elapsed(started) {
                    status = WindowsStartupStatus::Partial;
                    push_task_diagnostic(
                        &mut diagnostics,
                        diagnostic(
                            "task_scheduler_scan_deadline_exceeded",
                            Some(task_index),
                            "The shared startup inventory time limit was reached while reading triggers.",
                        ),
                    );
                    break;
                }
                let trigger_index = trigger_number - 1;
                let trigger = match unsafe { triggers.get_Item(trigger_number as i32) } {
                    Ok(trigger) => trigger,
                    Err(error) => {
                        status = WindowsStartupStatus::Partial;
                        push_task_diagnostic(
                            &mut diagnostics,
                            diagnostic_hresult(
                                if task_error_is_access_denied(&error) {
                                    "task_trigger_access_denied"
                                } else {
                                    "task_trigger_read_failed"
                                },
                                Some(task_index),
                                "Windows denied or failed reading a task trigger.",
                                error.code(),
                            ),
                        );
                        continue;
                    }
                };
                let mut trigger_type = TASK_TRIGGER_TYPE2(0);
                if let Err(error) = unsafe { trigger.Type(&mut trigger_type) } {
                    status = WindowsStartupStatus::Partial;
                    push_task_diagnostic(
                        &mut diagnostics,
                        diagnostic_hresult(
                            "task_trigger_type_read_failed",
                            Some(task_index),
                            "Windows could not identify a trigger type; that trigger was omitted.",
                            error.code(),
                        ),
                    );
                    continue;
                }
                let Some(trigger_name) = scheduled_trigger_name(trigger_type) else {
                    continue;
                };
                if entries.len() >= MAX_SCHEDULED_TASK_TRIGGERS {
                    status = WindowsStartupStatus::Partial;
                    trigger_row_limit_hit = true;
                    push_task_diagnostic(
                        &mut diagnostics,
                        diagnostic(
                            "task_trigger_row_limit_exceeded",
                            Some(task_index),
                            "The scheduled-task startup-row limit was reached; remaining triggers were not checked.",
                        ),
                    );
                    break;
                }
                let task_path_bstr = match unsafe { task.Path() } {
                    Ok(path) => path,
                    Err(error) => {
                        status = WindowsStartupStatus::Partial;
                        push_task_diagnostic(
                            &mut diagnostics,
                            diagnostic_hresult(
                                "task_path_read_failed",
                                Some(task_index),
                                "Windows could not read the registered task path; its trigger row was omitted.",
                                error.code(),
                            ),
                        );
                        continue;
                    }
                };
                let task_path = match bounded_bstr_to_string(&task_path_bstr) {
                    Ok(path) => path,
                    Err(_) => {
                        status = WindowsStartupStatus::Partial;
                        push_task_diagnostic(
                            &mut diagnostics,
                            diagnostic(
                                "task_path_invalid_or_over_limit",
                                Some(task_index),
                                "A registered task path was malformed or over limit; its trigger row was omitted.",
                            ),
                        );
                        continue;
                    }
                };
                if !task_actions_collected {
                    let task_action_collection = match unsafe { definition.Actions() } {
                        Ok(collection) => Some(collection),
                        Err(error) => {
                            status = WindowsStartupStatus::Partial;
                            push_task_diagnostic(
                                &mut diagnostics,
                                diagnostic_hresult(
                                    "task_action_collection_read_failed",
                                    Some(task_index),
                                    "Windows could not read a task's action collection; its configured action remains unknown.",
                                    error.code(),
                                ),
                            );
                            None
                        }
                    };
                    if let Some(collection) = task_action_collection {
                        collect_task_actions(
                            &collection,
                            &task_path,
                            task_index,
                            &mut actions,
                            &mut aggregate_string_units,
                            &mut status,
                            &mut diagnostics,
                        );
                    }
                    task_actions_collected = true;
                }
                let task_enabled = match unsafe { task.Enabled() } {
                    Ok(enabled) => Some(enabled.0 != 0),
                    Err(error) => {
                        status = WindowsStartupStatus::Partial;
                        push_task_diagnostic(
                            &mut diagnostics,
                            diagnostic_hresult(
                                "task_enabled_state_unknown",
                                Some(task_index),
                                "Windows could not read the task's enabled state; it is unknown.",
                                error.code(),
                            ),
                        );
                        None
                    }
                };
                let mut trigger_enabled_value = windows::Win32::Foundation::VARIANT_BOOL(0);
                let trigger_enabled = match unsafe { trigger.Enabled(&mut trigger_enabled_value) } {
                    Ok(()) => Some(trigger_enabled_value.0 != 0),
                    Err(error) => {
                        status = WindowsStartupStatus::Partial;
                        push_task_diagnostic(
                            &mut diagnostics,
                            diagnostic_hresult(
                                "task_trigger_enabled_state_unknown",
                                Some(task_index),
                                "Windows could not read the trigger's enabled state; it is unknown.",
                                error.code(),
                            ),
                        );
                        None
                    }
                };
                let logon_user = if trigger_name == "logon" {
                    match trigger.cast::<ILogonTrigger>() {
                        Ok(logon_trigger) => {
                            let mut user = BSTR::default();
                            match unsafe { logon_trigger.UserId(&mut user) } {
                                Ok(()) => match bounded_bstr_to_string(&user) {
                                    Ok(user) => Some(user),
                                    Err(_) => {
                                        status = WindowsStartupStatus::Partial;
                                        push_task_diagnostic(
                                            &mut diagnostics,
                                            diagnostic(
                                                "task_logon_user_invalid_or_over_limit",
                                                Some(task_index),
                                                "A logon trigger user identifier was malformed or over limit; its value is unknown.",
                                            ),
                                        );
                                        None
                                    }
                                },
                                Err(error) => {
                                    status = WindowsStartupStatus::Partial;
                                    push_task_diagnostic(
                                        &mut diagnostics,
                                        diagnostic_hresult(
                                            "task_logon_user_read_failed",
                                            Some(task_index),
                                            "Windows could not read a logon trigger's optional user identifier.",
                                            error.code(),
                                        ),
                                    );
                                    None
                                }
                            }
                        }
                        Err(error) => {
                            status = WindowsStartupStatus::Partial;
                            push_task_diagnostic(
                                &mut diagnostics,
                                diagnostic_hresult(
                                    "task_logon_trigger_interface_unavailable",
                                    Some(task_index),
                                    "Windows could not query the logon-trigger interface; its user identifier is unknown.",
                                    error.code(),
                                ),
                            );
                            None
                        }
                    }
                } else {
                    None
                };
                let row_string_units = task_path.encode_utf16().count()
                    + logon_user
                        .as_ref()
                        .map_or(0, |user| user.encode_utf16().count());
                if aggregate_string_units.saturating_add(row_string_units)
                    > MAX_AGGREGATE_TASK_STRING_UNITS
                {
                    status = WindowsStartupStatus::Partial;
                    push_task_diagnostic(
                        &mut diagnostics,
                        diagnostic(
                            "task_string_budget_exceeded",
                            Some(task_index),
                            "The aggregate scheduled-task string budget was reached; remaining triggers were not checked.",
                        ),
                    );
                    break;
                }
                aggregate_string_units += row_string_units;
                entries.push(WindowsScheduledTaskStartupEntry {
                    task_path,
                    task_enabled,
                    trigger_type: trigger_name,
                    trigger_enabled,
                    logon_user,
                    evidence: WindowsScheduledTaskStartupEvidence {
                        source: "Task Scheduler IRegisteredTask/ITaskDefinition/ITrigger",
                        task_index,
                        trigger_index,
                    },
                });
            }
            if trigger_row_limit_hit {
                break;
            }
        }
        if trigger_row_limit_hit {
            break;
        }
        if task_limit_hit || tasks_seen >= MAX_SCHEDULED_TASKS {
            status = WindowsStartupStatus::Partial;
            push_task_diagnostic(
                &mut diagnostics,
                diagnostic(
                    "task_entry_limit_exceeded",
                    None,
                    "The scheduled-task entry limit was reached; remaining tasks and folders were not checked.",
                ),
            );
            break;
        }
        if elapsed(started) {
            status = WindowsStartupStatus::Partial;
            push_task_diagnostic(
                &mut diagnostics,
                diagnostic(
                    "task_scheduler_scan_deadline_exceeded",
                    Some(folders_seen - 1),
                    "The shared startup inventory time limit was reached before this folder's subfolders were checked.",
                ),
            );
            break;
        }
        let child_folders = match unsafe { folder.GetFolders(0) } {
            Ok(folders) => folders,
            Err(error) => {
                status = WindowsStartupStatus::Partial;
                push_task_diagnostic(
                    &mut diagnostics,
                    diagnostic_hresult(
                        if task_error_is_access_denied(&error) {
                            "task_subfolder_access_denied"
                        } else {
                            "task_subfolder_enumeration_failed"
                        },
                        Some(folders_seen - 1),
                        "Windows denied or failed enumerating subfolders; nested tasks remain unknown.",
                        error.code(),
                    ),
                );
                continue;
            }
        };
        let child_count = match unsafe { child_folders.Count() } {
            Ok(count) => count,
            Err(error) => {
                status = WindowsStartupStatus::Partial;
                push_task_diagnostic(
                    &mut diagnostics,
                    diagnostic_hresult(
                        "task_subfolder_count_failed",
                        Some(folders_seen - 1),
                        "Windows could not determine the number of subfolders.",
                        error.code(),
                    ),
                );
                continue;
            }
        };
        let remaining_folders = MAX_TASK_FOLDERS
            .saturating_sub(folders_seen)
            .saturating_sub(pending_folders.len());
        let (folders_to_read, folder_limit_hit) = match bounded_task_count(
            child_count,
            remaining_folders,
        ) {
            Ok(bound) => bound,
            Err(_) => {
                status = WindowsStartupStatus::Partial;
                push_task_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "task_subfolder_count_malformed",
                        Some(folders_seen - 1),
                        "Windows returned a negative subfolder count; nested tasks remain unknown.",
                    ),
                );
                continue;
            }
        };
        if depth >= MAX_TASK_FOLDER_DEPTH && folders_to_read > 0 {
            status = WindowsStartupStatus::Partial;
            push_task_diagnostic(
                &mut diagnostics,
                diagnostic(
                    "task_folder_depth_limit_exceeded",
                    Some(folders_seen - 1),
                    "The scheduled-task folder depth limit was reached; nested folders were not checked.",
                ),
            );
            continue;
        }
        for child_number in 1..=folders_to_read {
            if elapsed(started) {
                status = WindowsStartupStatus::Partial;
                push_task_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "task_scheduler_scan_deadline_exceeded",
                        Some(folders_seen - 1),
                        "The shared startup inventory time limit was reached while reading task subfolders.",
                    ),
                );
                break;
            }
            let child_variant = one_based_task_index(child_number as i32);
            match unsafe { child_folders.get_Item(&child_variant) } {
                Ok(child) => pending_folders.push((child, depth + 1)),
                Err(error) => {
                    status = WindowsStartupStatus::Partial;
                    push_task_diagnostic(
                        &mut diagnostics,
                        diagnostic_hresult(
                            if task_error_is_access_denied(&error) {
                                "task_subfolder_access_denied"
                            } else {
                                "task_subfolder_read_failed"
                            },
                            Some(folders_seen - 1),
                            "Windows denied or failed reading a visible task subfolder.",
                            error.code(),
                        ),
                    );
                }
            }
        }
        if folder_limit_hit {
            status = WindowsStartupStatus::Partial;
            push_task_diagnostic(
                &mut diagnostics,
                diagnostic(
                    "task_folder_limit_exceeded",
                    Some(folders_seen - 1),
                    "The scheduled-task folder limit was reached; remaining folders were not checked.",
                ),
            );
        }
    }
    (
        source_result(
            "scheduled_task_triggers",
            status,
            entries.len(),
            diagnostics,
        ),
        entries,
        actions,
    )
}

fn scheduled_trigger_name(trigger_type: TASK_TRIGGER_TYPE2) -> Option<&'static str> {
    match trigger_type {
        TASK_TRIGGER_BOOT => Some("boot"),
        TASK_TRIGGER_LOGON => Some("logon"),
        _ => None,
    }
}

fn collect_task_actions(
    collection: &windows::Win32::System::TaskScheduler::IActionCollection,
    task_path: &str,
    task_index: usize,
    actions: &mut Vec<WindowsScheduledTaskAction>,
    aggregate_string_units: &mut usize,
    status: &mut WindowsStartupStatus,
    diagnostics: &mut Vec<WindowsStartupDiagnostic>,
) {
    let mut count = 0i32;
    if let Err(error) = unsafe { collection.Count(&mut count) } {
        *status = WindowsStartupStatus::Partial;
        push_task_diagnostic(
            diagnostics,
            diagnostic_hresult(
                "task_action_count_failed",
                Some(task_index),
                "Windows could not determine a task's action count; its actions remain unknown.",
                error.code(),
            ),
        );
        return;
    }
    let remaining = MAX_SCHEDULED_TASK_ACTIONS.saturating_sub(actions.len());
    let (actions_to_read, count_limit_hit) = match bounded_task_count(count, MAX_ACTIONS_PER_TASK) {
        Ok((bounded, per_task_limit_hit)) => {
            let globally_bounded = bounded.min(remaining);
            (globally_bounded, per_task_limit_hit || bounded > remaining)
        }
        Err(_) => {
            *status = WindowsStartupStatus::Partial;
            push_task_diagnostic(
                diagnostics,
                diagnostic(
                    "task_action_count_malformed",
                    Some(task_index),
                    "Windows returned a negative action count; the task's actions remain unknown.",
                ),
            );
            return;
        }
    };
    if count_limit_hit {
        *status = WindowsStartupStatus::Partial;
        push_task_diagnostic(
            diagnostics,
            diagnostic(
                if actions.len() >= MAX_SCHEDULED_TASK_ACTIONS {
                    "task_action_row_limit_exceeded"
                } else {
                    "task_action_limit_exceeded"
                },
                Some(task_index),
                "A scheduled-task action count limit was reached; remaining actions were not checked.",
            ),
        );
    }

    for action_number in 1..=actions_to_read {
        let action_index = action_number - 1;
        let action = match unsafe { collection.get_Item(action_number as i32) } {
            Ok(action) => action,
            Err(error) => {
                *status = WindowsStartupStatus::Partial;
                push_task_diagnostic(
                    diagnostics,
                    diagnostic_hresult(
                        if task_error_is_access_denied(&error) {
                            "task_action_access_denied"
                        } else {
                            "task_action_read_failed"
                        },
                        Some(task_index),
                        "Windows denied or failed reading a scheduled-task action; that action remains unknown.",
                        error.code(),
                    ),
                );
                continue;
            }
        };
        let mut action_type = TASK_ACTION_TYPE(0);
        if let Err(error) = unsafe { action.Type(&mut action_type) } {
            *status = WindowsStartupStatus::Partial;
            push_task_diagnostic(
                diagnostics,
                diagnostic_hresult(
                    "task_action_type_read_failed",
                    Some(task_index),
                    "Windows could not identify a scheduled-task action type; the action remains unknown.",
                    error.code(),
                ),
            );
            actions.push(WindowsScheduledTaskAction {
                task_path: retain_action_task_path(
                    task_path,
                    aggregate_string_units,
                    status,
                    diagnostics,
                    task_index,
                ),
                action_index,
                action_type: "unknown",
                action_type_code: None,
                status: WindowsScheduledTaskActionStatus::Partial,
                executable_path: None,
                arguments: None,
                working_directory: None,
                evidence: WindowsScheduledTaskActionEvidence {
                    source: "Task Scheduler IActionCollection/IAction",
                    task_index,
                    action_index,
                },
            });
            continue;
        }
        let type_name = scheduled_action_name(action_type);
        let mapped_status = scheduled_action_status(action_type);
        if mapped_status == WindowsScheduledTaskActionStatus::Unsupported {
            *status = WindowsStartupStatus::Partial;
            push_task_diagnostic(
                diagnostics,
                diagnostic(
                    "task_action_type_unsupported",
                    Some(task_index),
                    "A scheduled-task action type is recorded but not interpreted; its action-specific fields are unknown.",
                ),
            );
            actions.push(WindowsScheduledTaskAction {
                task_path: retain_action_task_path(
                    task_path,
                    aggregate_string_units,
                    status,
                    diagnostics,
                    task_index,
                ),
                action_index,
                action_type: type_name,
                action_type_code: Some(action_type.0),
                status: WindowsScheduledTaskActionStatus::Unsupported,
                executable_path: None,
                arguments: None,
                working_directory: None,
                evidence: WindowsScheduledTaskActionEvidence {
                    source: "Task Scheduler IActionCollection/IAction",
                    task_index,
                    action_index,
                },
            });
            continue;
        }
        let exec = match action.cast::<IExecAction>() {
            Ok(exec) => exec,
            Err(error) => {
                *status = WindowsStartupStatus::Partial;
                push_task_diagnostic(
                    diagnostics,
                    diagnostic_hresult(
                        "task_exec_action_interface_unavailable",
                        Some(task_index),
                        "Windows could not read the typed Exec action interface; action fields remain unknown.",
                        error.code(),
                    ),
                );
                actions.push(WindowsScheduledTaskAction {
                    task_path: retain_action_task_path(
                        task_path,
                        aggregate_string_units,
                        status,
                        diagnostics,
                        task_index,
                    ),
                    action_index,
                    action_type: type_name,
                    action_type_code: Some(action_type.0),
                    status: WindowsScheduledTaskActionStatus::Partial,
                    executable_path: None,
                    arguments: None,
                    working_directory: None,
                    evidence: WindowsScheduledTaskActionEvidence {
                        source: "Task Scheduler IActionCollection/IExecAction",
                        task_index,
                        action_index,
                    },
                });
                continue;
            }
        };
        let mut row_partial = false;
        let (executable_path, arguments, working_directory) = {
            let mut read_field = |field: ExecActionField| match read_exec_action_text(&exec, field)
            {
                Ok(value) => match reserve_task_string(&value, aggregate_string_units) {
                    Ok(()) => Some(value),
                    Err(TaskStringError::AggregateLimit) => {
                        row_partial = true;
                        *status = WindowsStartupStatus::Partial;
                        push_task_diagnostic(
                            diagnostics,
                            diagnostic(
                                "task_action_string_budget_exceeded",
                                Some(task_index),
                                "The aggregate scheduled-task action string budget was reached; this and remaining action fields are omitted.",
                            ),
                        );
                        None
                    }
                    Err(_) => unreachable!("BSTR was validated before aggregate accounting"),
                },
                Err(error) => {
                    row_partial = true;
                    *status = WindowsStartupStatus::Partial;
                    match error {
                        ExecActionTextError::Com(code) => push_task_diagnostic(
                            diagnostics,
                            diagnostic_hresult(
                                "task_action_field_read_failed",
                                Some(task_index),
                                "Windows could not read an Exec action field; that field remains unknown.",
                                code,
                            ),
                        ),
                        ExecActionTextError::Invalid(TaskStringError::OverLimit) => {
                            push_task_diagnostic(
                                diagnostics,
                                diagnostic(
                                    "task_action_field_limit_exceeded",
                                    Some(task_index),
                                    "An Exec action field exceeded its UTF-16 length limit and was omitted.",
                                ),
                            )
                        }
                        ExecActionTextError::Invalid(TaskStringError::MalformedUtf16) => {
                            push_task_diagnostic(
                                diagnostics,
                                diagnostic(
                                    "task_action_field_malformed_utf16",
                                    Some(task_index),
                                    "An Exec action field contained malformed UTF-16 and was omitted.",
                                ),
                            )
                        }
                        ExecActionTextError::Invalid(TaskStringError::AggregateLimit) => {
                            unreachable!("aggregate limits are applied after BSTR conversion")
                        }
                    }
                    None
                }
            };
            (
                read_field(ExecActionField::Path),
                read_field(ExecActionField::Arguments),
                read_field(ExecActionField::WorkingDirectory),
            )
        };
        actions.push(WindowsScheduledTaskAction {
            task_path: retain_action_task_path(
                task_path,
                aggregate_string_units,
                status,
                diagnostics,
                task_index,
            ),
            action_index,
            action_type: type_name,
            action_type_code: Some(action_type.0),
            status: if row_partial {
                WindowsScheduledTaskActionStatus::Partial
            } else {
                WindowsScheduledTaskActionStatus::Observed
            },
            executable_path,
            arguments,
            working_directory,
            evidence: WindowsScheduledTaskActionEvidence {
                source: "Task Scheduler IActionCollection/IExecAction",
                task_index,
                action_index,
            },
        });
    }
}

fn retain_action_task_path(
    task_path: &str,
    aggregate_units: &mut usize,
    status: &mut WindowsStartupStatus,
    diagnostics: &mut Vec<WindowsStartupDiagnostic>,
    task_index: usize,
) -> Option<String> {
    if reserve_task_string(task_path, aggregate_units).is_ok() {
        Some(task_path.to_owned())
    } else {
        *status = WindowsStartupStatus::Partial;
        push_task_diagnostic(
            diagnostics,
            diagnostic(
                "task_action_string_budget_exceeded",
                Some(task_index),
                "The aggregate scheduled-task action string budget was reached; this action's task path is omitted.",
            ),
        );
        None
    }
}

fn scheduled_action_name(action_type: TASK_ACTION_TYPE) -> &'static str {
    match action_type {
        TASK_ACTION_EXEC => "exec",
        TASK_ACTION_COM_HANDLER => "com_handler",
        TASK_ACTION_SEND_EMAIL => "send_email",
        TASK_ACTION_SHOW_MESSAGE => "show_message",
        _ => "unknown",
    }
}

fn scheduled_action_status(action_type: TASK_ACTION_TYPE) -> WindowsScheduledTaskActionStatus {
    if action_type == TASK_ACTION_EXEC {
        WindowsScheduledTaskActionStatus::Observed
    } else {
        WindowsScheduledTaskActionStatus::Unsupported
    }
}

fn reserve_task_string(value: &str, aggregate_units: &mut usize) -> Result<(), TaskStringError> {
    let units = value.encode_utf16().count();
    let total = aggregate_units
        .checked_add(units)
        .ok_or(TaskStringError::AggregateLimit)?;
    if total > MAX_AGGREGATE_TASK_STRING_UNITS {
        return Err(TaskStringError::AggregateLimit);
    }
    *aggregate_units = total;
    Ok(())
}

fn read_exec_action_text(
    action: &IExecAction,
    field: ExecActionField,
) -> Result<String, ExecActionTextError> {
    let mut value = BSTR::default();
    let result = unsafe {
        match field {
            ExecActionField::Path => action.Path(&mut value),
            ExecActionField::Arguments => action.Arguments(&mut value),
            ExecActionField::WorkingDirectory => action.WorkingDirectory(&mut value),
        }
    };
    result.map_err(|error| ExecActionTextError::Com(error.code()))?;
    bounded_bstr_to_string(&value).map_err(ExecActionTextError::Invalid)
}

fn bounded_task_count(count: i32, limit: usize) -> Result<(usize, bool), TaskCountError> {
    if count < 0 {
        return Err(TaskCountError::Negative);
    }
    let count = count as usize;
    Ok((count.min(limit), count > limit))
}

fn bounded_bstr_to_string(value: &BSTR) -> Result<String, TaskStringError> {
    if value.len() > MAX_TASK_STRING_UNITS {
        return Err(TaskStringError::OverLimit);
    }
    String::from_utf16(value).map_err(|_| TaskStringError::MalformedUtf16)
}

fn one_based_task_index(index: i32) -> VARIANT {
    let mut variant = VARIANT::default();
    let inner = VARIANT_0_0 {
        vt: VT_I4,
        wReserved1: 0,
        wReserved2: 0,
        wReserved3: 0,
        Anonymous: VARIANT_0_0_0 { lVal: index },
    };
    unsafe {
        std::ptr::write(
            std::ptr::addr_of_mut!(variant.Anonymous),
            VARIANT_0 {
                Anonymous: std::mem::ManuallyDrop::new(inner),
            },
        );
    }
    variant
}

fn task_error_is_access_denied(error: &windows::core::Error) -> bool {
    classify_hresult_failure(error.code().0) == StartupFailureClass::AccessDenied
}

fn task_error_mapping(
    error: &windows::core::Error,
    context: StartupFailureContext,
) -> StartupFailureMapping {
    map_startup_failure(context, classify_hresult_failure(error.code().0))
}

fn push_task_diagnostic(
    diagnostics: &mut Vec<WindowsStartupDiagnostic>,
    item: WindowsStartupDiagnostic,
) {
    if diagnostics.len() < MAX_TASK_DIAGNOSTICS {
        diagnostics.push(item);
    } else if diagnostics
        .last()
        .is_some_and(|last| last.code != "task_diagnostics_limit_exceeded")
    {
        *diagnostics.last_mut().expect("diagnostic count is nonzero") = diagnostic(
            "task_diagnostics_limit_exceeded",
            None,
            "Additional Task Scheduler diagnostics were omitted after the bounded diagnostic limit.",
        );
    }
}

fn push_service_diagnostic(
    diagnostics: &mut Vec<WindowsStartupDiagnostic>,
    item: WindowsStartupDiagnostic,
) {
    if diagnostics.len() < MAX_SERVICE_DIAGNOSTICS {
        diagnostics.push(item);
    } else if diagnostics
        .last()
        .is_some_and(|last| last.code != "service_diagnostics_limit_exceeded")
    {
        *diagnostics.last_mut().expect("diagnostic count is nonzero") = diagnostic(
            "service_diagnostics_limit_exceeded",
            None,
            "Additional service diagnostics were omitted after the bounded diagnostic limit.",
        );
    }
}

fn service_start_type(code: u32) -> &'static str {
    match code {
        SERVICE_BOOT_START => "boot",
        SERVICE_SYSTEM_START => "system",
        SERVICE_AUTO_START => "automatic",
        SERVICE_DEMAND_START => "manual",
        SERVICE_DISABLED => "disabled",
        _ => "unknown",
    }
}

fn bounded_wide_in_buffer(
    base: *const u8,
    buffer_bytes: usize,
    value: *const u16,
    maximum_units: usize,
) -> Result<String, ServiceStringError> {
    bounded_optional_wide_in_buffer(base, buffer_bytes, value, maximum_units)?
        .ok_or(ServiceStringError::Missing)
}

fn bounded_optional_wide_in_buffer(
    base: *const u8,
    buffer_bytes: usize,
    value: *const u16,
    maximum_units: usize,
) -> Result<Option<String>, ServiceStringError> {
    if value.is_null() {
        return Ok(None);
    }
    let base_address = base as usize;
    let address = value as usize;
    let Some(offset) = address.checked_sub(base_address) else {
        return Err(ServiceStringError::OutsideBuffer);
    };
    if offset >= buffer_bytes {
        return Err(ServiceStringError::OutsideBuffer);
    }
    if offset % std::mem::align_of::<u16>() != 0 {
        return Err(ServiceStringError::Misaligned);
    }
    let available_units = (buffer_bytes - offset) / 2;
    let units_to_check = available_units.min(maximum_units.saturating_add(1));
    let mut units = Vec::with_capacity(units_to_check.min(maximum_units));
    for index in 0..units_to_check {
        let unit = unsafe { std::ptr::read_unaligned(value.add(index)) };
        if unit == 0 {
            return String::from_utf16(&units)
                .map(Some)
                .map_err(|_| ServiceStringError::MalformedUtf16);
        }
        if index == maximum_units {
            return Err(ServiceStringError::OverLimit);
        }
        units.push(unit);
    }
    if available_units > maximum_units {
        Err(ServiceStringError::OverLimit)
    } else {
        Err(ServiceStringError::Unterminated)
    }
}

fn elapsed(started: Instant) -> bool {
    started.elapsed().as_millis() >= MAX_SCAN_DURATION_MS
}

fn collect_registry_source(
    source: RegistrySource,
    started: Instant,
    aggregate_remaining: usize,
    aggregate_name_remaining: usize,
    entry_remaining: usize,
) -> (
    WindowsStartupSource,
    Vec<WindowsRegistryStartupEntry>,
    usize,
    usize,
    usize,
) {
    collect_registry_source_with_api(
        &mut NativeStartupRegistryApi,
        source,
        started,
        aggregate_remaining,
        aggregate_name_remaining,
        entry_remaining,
    )
}

fn collect_registry_source_with_api<A: StartupRegistryApi>(
    api: &mut A,
    source: RegistrySource,
    started: Instant,
    aggregate_remaining: usize,
    aggregate_name_remaining: usize,
    entry_remaining: usize,
) -> (
    WindowsStartupSource,
    Vec<WindowsRegistryStartupEntry>,
    usize,
    usize,
    usize,
) {
    let key = match api.open(source) {
        Ok(key) => key,
        Err(code) => {
            let mapping = map_startup_failure(
                StartupFailureContext::RegistryKey,
                classify_win32_failure(code),
            );
            let diagnostics = mapping
                .diagnostic_code
                .map_or_else(Vec::new, |diagnostic_code| {
                    vec![diagnostic_win32(
                        diagnostic_code,
                        None,
                        "Windows could not open this startup registry key in the requested view.",
                        code,
                    )]
                });
            return (
                source_result(source.id, mapping.status, 0, diagnostics),
                Vec::new(),
                0,
                0,
                0,
            );
        }
    };
    let (value_count, max_name, max_data) = match api.query_value_info(&key) {
        Ok(info) => info,
        Err(query_code) => {
            let status = if query_code == ERROR_ACCESS_DENIED {
                WindowsStartupStatus::Inaccessible
            } else {
                WindowsStartupStatus::Error
            };
            return (
                source_result(
                    source.id,
                    status,
                    0,
                    vec![diagnostic_win32(
                        "registry_metadata_failed",
                        None,
                        "Windows could not read startup registry key metadata.",
                        query_code,
                    )],
                ),
                Vec::new(),
                0,
                0,
                0,
            );
        }
    };
    let mut diagnostics = Vec::new();
    let mut status = WindowsStartupStatus::Complete;
    let name_capacity = (max_name as usize + 1).min(MAX_VALUE_NAME_UNITS + 1);
    if max_name as usize > MAX_VALUE_NAME_UNITS {
        status = WindowsStartupStatus::Partial;
        diagnostics.push(diagnostic(
            "registry_value_name_limit_exceeded",
            None,
            "At least one registry value name exceeds the supported UTF-16 length.",
        ));
    }
    if max_data as usize > MAX_VALUE_DATA_BYTES {
        status = WindowsStartupStatus::Partial;
        diagnostics.push(diagnostic(
            "registry_value_data_limit_exceeded",
            None,
            "At least one registry value exceeds the per-value data limit.",
        ));
    }
    let max_values = entry_remaining.min(value_count as usize);
    if value_count as usize > entry_remaining {
        status = WindowsStartupStatus::Partial;
        diagnostics.push(diagnostic(
            "registry_value_count_limit_exceeded",
            None,
            "The registry value count exceeds the per-source limit; remaining values were not checked.",
        ));
    }
    let mut entries = Vec::with_capacity(max_values.min(512));
    let mut bytes_read = 0usize;
    let mut values_checked = 0usize;
    let mut name_units_read = 0usize;
    for index in 0..max_values {
        if elapsed(started) {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "scan_deadline_exceeded",
                Some(index),
                "The startup inventory time limit was reached while enumerating this key.",
            ));
            break;
        }
        let available = MAX_VALUE_DATA_BYTES.min(aggregate_remaining.saturating_sub(bytes_read));
        let mut value_buffer = StartupRegistryValueBuffer {
            name: vec![0u16; name_capacity.max(1)],
            name_length: 0,
            value_type: 0,
            data: vec![0u8; available],
            data_length: 0,
        };
        value_buffer.name_length = value_buffer.name.len() as u32;
        value_buffer.data_length = value_buffer.data.len() as u32;
        let result = api.enumerate_value(&key, index as u32, &mut value_buffer);
        if result == ERROR_NO_MORE_ITEMS {
            break;
        }
        values_checked = values_checked.saturating_add(1);
        if result == ERROR_MORE_DATA {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "registry_value_over_limit_or_changed",
                Some(index),
                "A registry value exceeded the read buffer or changed during collection; its data was not retained.",
            ));
            continue;
        }
        if result != 0 {
            let inaccessible = result == ERROR_ACCESS_DENIED;
            status = if inaccessible {
                WindowsStartupStatus::Inaccessible
            } else {
                WindowsStartupStatus::Partial
            };
            diagnostics.push(diagnostic_win32(
                if inaccessible {
                    "registry_value_inaccessible"
                } else {
                    "registry_value_read_failed"
                },
                Some(index),
                "Windows could not read a startup registry value.",
                result,
            ));
            if inaccessible {
                break;
            }
            continue;
        }
        let name_len = value_buffer.name_length as usize;
        if name_len > MAX_VALUE_NAME_UNITS || name_len > value_buffer.name.len() {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "registry_value_name_limit_exceeded",
                Some(index),
                "A registry value name exceeded the supported UTF-16 length and was omitted.",
            ));
            continue;
        }
        if name_len > aggregate_name_remaining.saturating_sub(name_units_read) {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "registry_name_budget_exceeded",
                Some(index),
                "The aggregate registry value-name budget was exhausted; this value was omitted.",
            ));
            continue;
        }
        name_units_read = name_units_read.saturating_add(name_len);
        let value_name = match String::from_utf16(&value_buffer.name[..name_len]) {
            Ok(name) => name,
            Err(_) => {
                status = WindowsStartupStatus::Partial;
                diagnostics.push(diagnostic(
                    "registry_value_name_malformed_utf16",
                    Some(index),
                    "A registry value name contained invalid UTF-16 and was displayed lossily.",
                ));
                String::from_utf16_lossy(&value_buffer.name[..name_len])
            }
        };
        let data_len = value_buffer.data_length as usize;
        if data_len > value_buffer.data.len() {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "registry_value_read_failed",
                Some(index),
                "Windows reported a registry value length beyond the supplied read buffer.",
            ));
            continue;
        }
        bytes_read = bytes_read.saturating_add(data_len);
        let (type_name, command, raw_hex) = match decode_registry_text(
            value_buffer.value_type,
            &value_buffer.data[..data_len],
        ) {
            Ok((type_name, display, raw_hex, malformed_utf16)) => {
                if malformed_utf16 {
                    status = WindowsStartupStatus::Partial;
                    diagnostics.push(diagnostic(
                        "registry_command_malformed_utf16",
                        Some(index),
                        "A registry startup value contained invalid UTF-16; its display contains replacement characters.",
                    ));
                }
                (type_name, Some(display), Some(raw_hex))
            }
            Err(RegistryDecodeError::OddLength) => {
                status = WindowsStartupStatus::Partial;
                diagnostics.push(diagnostic(
                    "registry_command_malformed_length",
                    Some(index),
                    "A registry string had an odd byte length and was omitted.",
                ));
                (
                    if value_buffer.value_type == REG_SZ {
                        "REG_SZ"
                    } else {
                        "REG_EXPAND_SZ"
                    },
                    None,
                    None,
                )
            }
            Err(RegistryDecodeError::OverLimit) => {
                status = WindowsStartupStatus::Partial;
                diagnostics.push(diagnostic(
                    "registry_value_data_limit_exceeded",
                    Some(index),
                    "A registry startup value exceeded the supported data limit and was omitted.",
                ));
                (
                    if value_buffer.value_type == REG_SZ {
                        "REG_SZ"
                    } else {
                        "REG_EXPAND_SZ"
                    },
                    None,
                    None,
                )
            }
            Err(RegistryDecodeError::UnsupportedType) => {
                status = WindowsStartupStatus::Partial;
                diagnostics.push(diagnostic(
                    "registry_value_type_unsupported",
                    Some(index),
                    "A startup registry value had an unsupported type; its raw data was omitted.",
                ));
                ("unsupported", None, None)
            }
        };
        entries.push(WindowsRegistryStartupEntry {
            registry_key: source.key,
            hive: source.hive,
            registry_view: source.view,
            trigger: source.trigger,
            value_name: value_name.clone(),
            value_type: type_name,
            command,
            command_utf16_hex: raw_hex,
            evidence: WindowsRegistryStartupEvidence {
                source: "RegEnumValueW",
                hive: source.hive,
                registry_view: source.view,
                registry_key: source.key,
                value_index: index,
                value_name,
                registry_type: value_buffer.value_type,
            },
        });
    }
    (
        source_result(source.id, status, entries.len(), diagnostics),
        entries,
        bytes_read,
        values_checked,
        name_units_read,
    )
}

#[derive(Debug)]
enum RegistryDecodeError {
    OddLength,
    OverLimit,
    UnsupportedType,
}

fn decode_registry_text(
    value_type: u32,
    data: &[u8],
) -> Result<(&'static str, String, String, bool), RegistryDecodeError> {
    let type_name = match value_type {
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        _ => return Err(RegistryDecodeError::UnsupportedType),
    };
    if data.len() > MAX_VALUE_DATA_BYTES {
        return Err(RegistryDecodeError::OverLimit);
    }
    if data.len() % 2 != 0 {
        return Err(RegistryDecodeError::OddLength);
    }
    let units = data
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    let end = units
        .iter()
        .rposition(|unit| *unit != 0)
        .map_or(0, |i| i + 1);
    let (display, malformed_utf16) = match String::from_utf16(&units[..end]) {
        Ok(value) => (value, false),
        Err(_) => (String::from_utf16_lossy(&units[..end]), true),
    };
    Ok((type_name, display, utf16_hex(&units), malformed_utf16))
}

fn collect_startup_folder(
    folder_scope: &'static str,
    folder_id: &Guid,
    aggregate_remaining: usize,
    entry_remaining: usize,
    started: Instant,
) -> (
    WindowsStartupSource,
    Vec<WindowsStartupFolderEntry>,
    usize,
    usize,
) {
    let mut path = null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(folder_id, KF_FLAG_DONT_VERIFY, null_mut(), &mut path) };
    if result < 0 || path.is_null() {
        let class = if result < 0 {
            classify_hresult_failure(result)
        } else {
            StartupFailureClass::ApiFailure
        };
        let mapping = map_startup_failure(StartupFailureContext::KnownFolder, class);
        let failure_hresult = if result < 0 {
            result
        } else {
            0x8000_4005u32 as i32
        };
        return (
            source_result(
                folder_scope,
                mapping.status,
                0,
                vec![diagnostic_hresult(
                    mapping
                        .diagnostic_code
                        .unwrap_or("startup_folder_unavailable"),
                    None,
                    "Windows could not resolve this known startup folder.",
                    HRESULT(failure_hresult),
                )],
            ),
            Vec::new(),
            0,
            0,
        );
    }
    let path = KnownFolderPath(path);
    let mut len = 0usize;
    unsafe {
        while len < MAX_PATH_UNITS && *path.0.add(len) != 0 {
            len += 1;
        }
    }
    if len == 0 || len >= MAX_PATH_UNITS {
        return (
            source_result(
                folder_scope,
                WindowsStartupStatus::Partial,
                0,
                vec![diagnostic(
                    "startup_folder_path_invalid_or_over_limit",
                    None,
                    "The known startup folder path was empty, malformed, or over the path limit.",
                )],
            ),
            Vec::new(),
            0,
            0,
        );
    }
    let wide = unsafe { std::slice::from_raw_parts(path.0, len) };
    let folder = PathBuf::from(std::ffi::OsString::from_wide(wide));
    let path_units = len;
    let display_folder = String::from_utf16_lossy(wide);
    let folder_hex = utf16_hex(wide);
    if path_units > aggregate_remaining {
        return (
            source_result_with_location(
                folder_scope,
                WindowsStartupStatus::Partial,
                0,
                vec![diagnostic(
                    "startup_path_budget_exceeded",
                    None,
                    "The aggregate startup path budget was exhausted before this folder was checked.",
                )],
                display_folder,
                folder_hex,
            ),
            Vec::new(),
            0,
            0,
        );
    }
    let read_dir = match fs::read_dir(&folder) {
        Ok(entries) => entries,
        Err(error) if classify_io_failure(&error) == StartupFailureClass::Missing => {
            let mapping = map_startup_failure(
                StartupFailureContext::StartupFolder,
                StartupFailureClass::Missing,
            );
            return (
                source_result_with_location(
                    folder_scope,
                    mapping.status,
                    0,
                    Vec::new(),
                    display_folder.clone(),
                    folder_hex.clone(),
                ),
                Vec::new(),
                path_units,
                0,
            );
        }
        Err(error) if classify_io_failure(&error) == StartupFailureClass::AccessDenied => {
            let mapping = map_startup_failure(
                StartupFailureContext::StartupFolder,
                StartupFailureClass::AccessDenied,
            );
            return (
                source_result_with_location(
                    folder_scope,
                    mapping.status,
                    0,
                    vec![diagnostic(
                        mapping
                            .diagnostic_code
                            .unwrap_or("startup_folder_inaccessible"),
                        None,
                        "Windows denied access to this startup folder.",
                    )],
                    display_folder.clone(),
                    folder_hex.clone(),
                ),
                Vec::new(),
                path_units,
                0,
            );
        }
        Err(error) => {
            let mapping = map_startup_failure(
                StartupFailureContext::StartupFolder,
                classify_io_failure(&error),
            );
            return (
                source_result_with_location(
                    folder_scope,
                    mapping.status,
                    0,
                    vec![diagnostic(
                        mapping
                            .diagnostic_code
                            .unwrap_or("startup_folder_read_failed"),
                        None,
                        "Windows could not enumerate this startup folder.",
                    )],
                    display_folder.clone(),
                    folder_hex.clone(),
                ),
                Vec::new(),
                path_units,
                0,
            );
        }
    };
    let mut entries = Vec::new();
    let mut diagnostics = Vec::new();
    let mut status = WindowsStartupStatus::Complete;
    let mut aggregate_used = path_units;
    let mut entries_checked = 0usize;
    for (index, item) in read_dir.enumerate() {
        if elapsed(started) {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "scan_deadline_exceeded",
                Some(index),
                "The startup inventory time limit was reached while enumerating this folder.",
            ));
            break;
        }
        if index >= entry_remaining {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "startup_folder_entry_limit_exceeded",
                Some(index),
                "The startup-folder entry limit was reached; remaining entries were not checked.",
            ));
            break;
        }
        entries_checked = entries_checked.saturating_add(1);
        let item = match item {
            Ok(item) => item,
            Err(_) => {
                status = WindowsStartupStatus::Partial;
                diagnostics.push(diagnostic(
                    "startup_folder_entry_read_failed",
                    Some(index),
                    "Windows could not read a startup-folder entry.",
                ));
                continue;
            }
        };
        let path = item.path();
        let wide_path = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if wide_path.len() > MAX_PATH_UNITS
            || wide_path.len() > aggregate_remaining.saturating_sub(aggregate_used)
        {
            status = WindowsStartupStatus::Partial;
            diagnostics.push(diagnostic(
                "startup_path_budget_exceeded",
                Some(index),
                "A startup path exceeded the per-path or aggregate path budget and was omitted.",
            ));
            continue;
        }
        aggregate_used = aggregate_used.saturating_add(wide_path.len());
        let display_path = String::from_utf16_lossy(&wide_path);
        let kind = match item.file_type() {
            Ok(kind) if kind.is_symlink() => "reparse_or_symlink_entry",
            Ok(kind) if kind.is_dir() => "directory",
            Ok(_) => "file",
            Err(_) => {
                status = WindowsStartupStatus::Partial;
                diagnostics.push(diagnostic(
                    "startup_folder_entry_metadata_failed",
                    Some(index),
                    "Windows could not determine a startup-folder entry's type.",
                ));
                "unknown"
            }
        };
        let hex = utf16_hex(&wide_path);
        entries.push(WindowsStartupFolderEntry {
            folder_scope,
            trigger: "user_logon",
            display_path: display_path.clone(),
            path_utf16_hex: hex.clone(),
            kind,
            evidence: WindowsStartupFolderEvidence {
                source: "SHGetKnownFolderPath/FindFirstFileW",
                folder_scope,
                display_path,
                path_utf16_hex: hex,
            },
        });
    }
    (
        source_result_with_location(
            folder_scope,
            status,
            entries.len(),
            diagnostics,
            display_folder,
            folder_hex,
        ),
        entries,
        aggregate_used,
        entries_checked,
    )
}

fn source_result(
    id: &'static str,
    status: WindowsStartupStatus,
    entries_seen: usize,
    diagnostics: Vec<WindowsStartupDiagnostic>,
) -> WindowsStartupSource {
    WindowsStartupSource {
        id,
        status,
        entries_seen,
        registry_hive: None,
        registry_key: None,
        registry_view: None,
        location_path: None,
        location_path_utf16_hex: None,
        diagnostics,
    }
}

fn source_result_with_location(
    id: &'static str,
    status: WindowsStartupStatus,
    entries_seen: usize,
    diagnostics: Vec<WindowsStartupDiagnostic>,
    location_path: String,
    location_path_utf16_hex: String,
) -> WindowsStartupSource {
    WindowsStartupSource {
        id,
        status,
        entries_seen,
        registry_hive: None,
        registry_key: None,
        registry_view: None,
        location_path: Some(location_path),
        location_path_utf16_hex: Some(location_path_utf16_hex),
        diagnostics,
    }
}

fn diagnostic(
    code: &'static str,
    item_index: Option<usize>,
    message: &'static str,
) -> WindowsStartupDiagnostic {
    WindowsStartupDiagnostic {
        code,
        item_index,
        message,
        win32_error: None,
        hresult: None,
    }
}

fn diagnostic_win32(
    code: &'static str,
    item_index: Option<usize>,
    message: &'static str,
    win32_error: u32,
) -> WindowsStartupDiagnostic {
    WindowsStartupDiagnostic {
        code,
        item_index,
        message,
        win32_error: Some(win32_error),
        hresult: None,
    }
}

fn diagnostic_hresult(
    code: &'static str,
    item_index: Option<usize>,
    message: &'static str,
    hresult: HRESULT,
) -> WindowsStartupDiagnostic {
    WindowsStartupDiagnostic {
        code,
        item_index,
        message,
        win32_error: None,
        hresult: Some(hresult.0 as u32),
    }
}

fn wide_z(value: impl AsRef<OsStr>) -> Vec<u16> {
    let mut wide = value.as_ref().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    wide
}

fn utf16_hex(units: &[u16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(units.len().saturating_mul(4));
    for unit in units {
        for shift in [12, 8, 4, 0] {
            output.push(HEX[((unit >> shift) & 0x0f) as usize] as char);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    enum FakeRegistryValue {
        Value {
            name: Vec<u16>,
            value_type: u32,
            data: Vec<u8>,
        },
        Error(u32),
    }

    struct FakeStartupRegistryApi {
        metadata: Result<(u32, u32, u32), u32>,
        values: VecDeque<FakeRegistryValue>,
    }

    impl FakeStartupRegistryApi {
        fn with_values(values: Vec<FakeRegistryValue>) -> Self {
            let metadata = Ok((values.len() as u32, 16, 256));
            Self {
                metadata,
                values: values.into(),
            }
        }
    }

    impl StartupRegistryApi for FakeStartupRegistryApi {
        type Key = ();

        fn open(&mut self, _source: RegistrySource) -> Result<Self::Key, u32> {
            Ok(())
        }

        fn query_value_info(&mut self, _key: &Self::Key) -> Result<(u32, u32, u32), u32> {
            self.metadata
        }

        fn enumerate_value(
            &mut self,
            _key: &Self::Key,
            _index: u32,
            buffer: &mut StartupRegistryValueBuffer,
        ) -> u32 {
            match self
                .values
                .pop_front()
                .unwrap_or(FakeRegistryValue::Error(ERROR_NO_MORE_ITEMS))
            {
                FakeRegistryValue::Value {
                    name: value_name,
                    value_type: kind,
                    data: value_data,
                } => {
                    if value_name.len() > buffer.name.len() || value_data.len() > buffer.data.len()
                    {
                        return ERROR_MORE_DATA;
                    }
                    buffer.name[..value_name.len()].copy_from_slice(&value_name);
                    buffer.data[..value_data.len()].copy_from_slice(&value_data);
                    buffer.name_length = value_name.len() as u32;
                    buffer.value_type = kind;
                    buffer.data_length = value_data.len() as u32;
                    0
                }
                FakeRegistryValue::Error(error) => error,
            }
        }
    }

    fn encode_registry_text(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn registry_test_value(name: &str, text: &str) -> FakeRegistryValue {
        FakeRegistryValue::Value {
            name: name.encode_utf16().collect(),
            value_type: REG_SZ,
            data: encode_registry_text(text),
        }
    }

    #[test]
    fn registry_metadata_access_denied_is_inaccessible_with_native_code() {
        let mut api = FakeStartupRegistryApi::with_values(Vec::new());
        api.metadata = Err(ERROR_ACCESS_DENIED);

        let (source, entries, _, _, _) = collect_registry_source_with_api(
            &mut api,
            REGISTRY_SOURCES[0],
            Instant::now(),
            MAX_AGGREGATE_REGISTRY_BYTES,
            MAX_AGGREGATE_REGISTRY_NAME_UNITS,
            MAX_STARTUP_ENTRIES,
        );

        assert_eq!(source.status, WindowsStartupStatus::Inaccessible);
        assert!(entries.is_empty());
        let diagnostic = &source.diagnostics[0];
        assert_eq!(diagnostic.code, "registry_metadata_failed");
        assert_eq!(diagnostic.win32_error, Some(ERROR_ACCESS_DENIED));
    }

    #[test]
    fn registry_metadata_generic_failure_remains_error_with_native_code() {
        let mut api = FakeStartupRegistryApi::with_values(Vec::new());
        api.metadata = Err(1234);

        let (source, entries, _, _, _) = collect_registry_source_with_api(
            &mut api,
            REGISTRY_SOURCES[0],
            Instant::now(),
            MAX_AGGREGATE_REGISTRY_BYTES,
            MAX_AGGREGATE_REGISTRY_NAME_UNITS,
            MAX_STARTUP_ENTRIES,
        );

        assert_eq!(source.status, WindowsStartupStatus::Error);
        assert!(entries.is_empty());
        assert_eq!(source.diagnostics[0].win32_error, Some(1234));
    }

    #[test]
    fn registry_value_access_denied_retains_observed_entries_and_error_code() {
        let mut api = FakeStartupRegistryApi::with_values(vec![
            registry_test_value("Observed", "literal.exe"),
            FakeRegistryValue::Error(ERROR_ACCESS_DENIED),
        ]);
        api.metadata = Ok((2, 16, 256));

        let (source, entries, _, checked, _) = collect_registry_source_with_api(
            &mut api,
            REGISTRY_SOURCES[0],
            Instant::now(),
            MAX_AGGREGATE_REGISTRY_BYTES,
            MAX_AGGREGATE_REGISTRY_NAME_UNITS,
            MAX_STARTUP_ENTRIES,
        );

        assert_eq!(source.status, WindowsStartupStatus::Inaccessible);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value_name, "Observed");
        assert_eq!(entries[0].command.as_deref(), Some("literal.exe"));
        assert_eq!(checked, 2);
        assert_eq!(source.diagnostics[0].code, "registry_value_inaccessible");
        assert_eq!(source.diagnostics[0].item_index, Some(1));
        assert_eq!(source.diagnostics[0].win32_error, Some(ERROR_ACCESS_DENIED));
    }

    #[test]
    fn registry_value_generic_failure_remains_partial_with_native_code() {
        let mut api = FakeStartupRegistryApi::with_values(vec![
            registry_test_value("Observed", "literal.exe"),
            FakeRegistryValue::Error(1234),
        ]);
        api.metadata = Ok((2, 16, 256));

        let (source, entries, _, checked, _) = collect_registry_source_with_api(
            &mut api,
            REGISTRY_SOURCES[0],
            Instant::now(),
            MAX_AGGREGATE_REGISTRY_BYTES,
            MAX_AGGREGATE_REGISTRY_NAME_UNITS,
            MAX_STARTUP_ENTRIES,
        );

        assert_eq!(source.status, WindowsStartupStatus::Partial);
        assert_eq!(entries.len(), 1);
        assert_eq!(checked, 2);
        assert_eq!(source.diagnostics[0].code, "registry_value_read_failed");
        assert_eq!(source.diagnostics[0].win32_error, Some(1234));
    }

    #[test]
    fn registry_expand_strings_remain_literal_and_keep_raw_utf16_evidence() {
        let source = "%USERPROFILE%\\Tools\\agent.exe\0";
        let data = encode_registry_text(source);
        let (kind, display, raw, malformed) = decode_registry_text(REG_EXPAND_SZ, &data).unwrap();
        assert_eq!(kind, "REG_EXPAND_SZ");
        assert_eq!(display, source.trim_end_matches('\0'));
        assert!(!malformed);
        assert_eq!(raw.len(), source.encode_utf16().count() * 4);
        assert!(raw.starts_with("0025"));
    }

    #[test]
    fn malformed_or_unsupported_registry_data_is_reported_instead_of_guessed() {
        assert!(matches!(
            decode_registry_text(REG_SZ, &[0x41]),
            Err(RegistryDecodeError::OddLength)
        ));
        assert!(matches!(
            decode_registry_text(REG_SZ, &vec![0; MAX_VALUE_DATA_BYTES + 2]),
            Err(RegistryDecodeError::OverLimit)
        ));
        assert!(matches!(
            decode_registry_text(3, &[0, 0]),
            Err(RegistryDecodeError::UnsupportedType)
        ));
        let malformed = decode_registry_text(REG_SZ, &[0x00, 0xd8]).unwrap();
        assert!(malformed.3);
        assert_eq!(malformed.1, "�");
        assert_eq!(malformed.2, "d800");
    }

    #[test]
    fn startup_scope_lists_only_the_curated_sources() {
        assert_eq!(REGISTRY_SOURCES.len(), 8);
        assert_eq!(FOLDER_IDS.len(), 2);
        assert!(
            REGISTRY_SOURCES.iter().all(|source| {
                source.key.ends_with("\\Run") || source.key.ends_with("\\RunOnce")
            })
        );
        assert_eq!(FOLDER_IDS[0].0, "user_startup");
        assert_eq!(FOLDER_IDS[1].0, "common_startup");
    }

    #[test]
    fn service_start_type_mapping_preserves_unknown_values() {
        assert_eq!(service_start_type(SERVICE_BOOT_START), "boot");
        assert_eq!(service_start_type(SERVICE_SYSTEM_START), "system");
        assert_eq!(service_start_type(SERVICE_AUTO_START), "automatic");
        assert_eq!(service_start_type(SERVICE_DEMAND_START), "manual");
        assert_eq!(service_start_type(SERVICE_DISABLED), "disabled");
        assert_eq!(service_start_type(99), "unknown");
    }

    #[test]
    fn startup_source_failure_mapping_keeps_source_specific_statuses() {
        let cases = [
            (
                StartupFailureContext::RegistryKey,
                ERROR_FILE_NOT_FOUND,
                WindowsStartupStatus::NotPresent,
                None,
            ),
            (
                StartupFailureContext::RegistryKey,
                ERROR_ACCESS_DENIED,
                WindowsStartupStatus::Inaccessible,
                Some("registry_key_unavailable"),
            ),
            (
                StartupFailureContext::RegistryKey,
                ERROR_NOT_SUPPORTED,
                WindowsStartupStatus::Unsupported,
                Some("registry_key_unsupported"),
            ),
            (
                StartupFailureContext::RegistryKey,
                1234,
                WindowsStartupStatus::Error,
                Some("registry_key_unavailable"),
            ),
            (
                StartupFailureContext::StartupFolder,
                ERROR_PATH_NOT_FOUND,
                WindowsStartupStatus::NotPresent,
                None,
            ),
            (
                StartupFailureContext::StartupFolder,
                ERROR_ACCESS_DENIED,
                WindowsStartupStatus::Inaccessible,
                Some("startup_folder_inaccessible"),
            ),
            (
                StartupFailureContext::StartupFolder,
                ERROR_CALL_NOT_IMPLEMENTED,
                WindowsStartupStatus::Unsupported,
                Some("startup_folder_unsupported"),
            ),
            (
                StartupFailureContext::StartupFolder,
                1234,
                WindowsStartupStatus::Error,
                Some("startup_folder_read_failed"),
            ),
        ];
        for (context, win32, expected_status, expected_diagnostic) in cases {
            let mapping = map_startup_failure(context, classify_win32_failure(win32));
            assert_eq!(
                mapping.status, expected_status,
                "context={context:?} code={win32}"
            );
            assert_eq!(mapping.diagnostic_code, expected_diagnostic);
        }
    }

    #[test]
    fn scm_and_scheduler_failures_preserve_inaccessible_unsupported_and_partial_states() {
        assert_eq!(
            map_startup_failure(
                StartupFailureContext::ServiceManager,
                classify_win32_failure(ERROR_ACCESS_DENIED)
            )
            .status,
            WindowsStartupStatus::Inaccessible
        );
        assert_eq!(
            map_startup_failure(
                StartupFailureContext::ServiceManager,
                classify_win32_failure(ERROR_NOT_SUPPORTED)
            )
            .status,
            WindowsStartupStatus::Unsupported
        );
        assert_eq!(
            map_startup_failure(
                StartupFailureContext::ServiceManager,
                classify_win32_failure(1234)
            )
            .status,
            WindowsStartupStatus::Unavailable
        );
        for class in [
            StartupFailureClass::Missing,
            StartupFailureClass::AccessDenied,
            StartupFailureClass::ApiFailure,
        ] {
            assert_eq!(
                map_startup_failure(StartupFailureContext::ServiceApi, class).status,
                WindowsStartupStatus::Partial
            );
        }
        assert_eq!(
            map_startup_failure(
                StartupFailureContext::ServiceApi,
                StartupFailureClass::Unsupported
            ),
            StartupFailureMapping {
                status: WindowsStartupStatus::Partial,
                diagnostic_code: Some("service_api_unsupported"),
            }
        );
        assert_eq!(
            classify_hresult_failure(0x8007_0005u32 as i32),
            StartupFailureClass::AccessDenied
        );
        assert_eq!(
            classify_hresult_failure(0x8007_0078u32 as i32),
            StartupFailureClass::Unsupported
        );
        assert_eq!(
            classify_hresult_failure(0x8000_4001u32 as i32),
            StartupFailureClass::Unsupported
        );
        assert_eq!(
            map_startup_failure(
                StartupFailureContext::TaskSchedulerSetup,
                classify_hresult_failure(0x8007_0005u32 as i32)
            )
            .status,
            WindowsStartupStatus::Inaccessible
        );
        assert_eq!(
            map_startup_failure(
                StartupFailureContext::TaskSchedulerSetup,
                classify_hresult_failure(0x8000_4001u32 as i32)
            )
            .status,
            WindowsStartupStatus::Unsupported
        );
        assert_eq!(
            map_startup_failure(
                StartupFailureContext::TaskSchedulerSetup,
                classify_hresult_failure(0x8000_4005u32 as i32)
            )
            .status,
            WindowsStartupStatus::Unavailable
        );
        assert_eq!(
            map_startup_failure(
                StartupFailureContext::TaskSchedulerScan,
                StartupFailureClass::Unsupported
            ),
            StartupFailureMapping {
                status: WindowsStartupStatus::Partial,
                diagnostic_code: Some("task_scheduler_scan_unsupported"),
            }
        );
    }

    #[test]
    fn source_limit_failures_are_not_mapped_to_complete() {
        let (bounded, limit_hit) = bounded_task_count(257, MAX_ACTIONS_PER_TASK).unwrap();
        assert_eq!(bounded, MAX_ACTIONS_PER_TASK);
        assert!(limit_hit);
        let service_api_failure = map_startup_failure(
            StartupFailureContext::ServiceApi,
            StartupFailureClass::ApiFailure,
        );
        assert_eq!(service_api_failure.status, WindowsStartupStatus::Partial);
        assert_eq!(
            map_startup_failure(
                StartupFailureContext::TaskSchedulerScan,
                StartupFailureClass::ApiFailure
            )
            .status,
            WindowsStartupStatus::Partial
        );
    }

    #[test]
    fn service_strings_must_be_terminated_inside_the_bounded_buffer() {
        let mut bytes = [0u8; 16];
        bytes[2..8].copy_from_slice(&[b'A', 0, b'B', 0, 0, 0]);
        let value = unsafe { bytes.as_ptr().add(2).cast::<u16>() };
        assert_eq!(
            bounded_wide_in_buffer(bytes.as_ptr(), bytes.len(), value, 4).unwrap(),
            "AB"
        );
        assert_eq!(
            bounded_wide_in_buffer(bytes.as_ptr(), bytes.len(), value, 1),
            Err(ServiceStringError::OverLimit)
        );
        assert_eq!(
            bounded_optional_wide_in_buffer(bytes.as_ptr(), bytes.len(), std::ptr::null(), 4)
                .unwrap(),
            None
        );
        let outside = unsafe { bytes.as_ptr().add(bytes.len()).cast::<u16>() };
        assert_eq!(
            bounded_wide_in_buffer(bytes.as_ptr(), bytes.len(), outside, 4),
            Err(ServiceStringError::OutsideBuffer)
        );
        let malformed = [0x00, 0xd8, 0x00, 0x00];
        assert_eq!(
            bounded_wide_in_buffer(
                malformed.as_ptr(),
                malformed.len(),
                malformed.as_ptr().cast(),
                4,
            ),
            Err(ServiceStringError::MalformedUtf16)
        );
    }

    #[test]
    fn service_limits_are_finite_and_diagnostics_bounded() {
        assert_eq!(MAX_SERVICE_ENTRIES, 8_192);
        assert_eq!(MAX_SERVICE_DIAGNOSTICS, 256);
        let mut diagnostics = (0..MAX_SERVICE_DIAGNOSTICS)
            .map(|_| diagnostic("service_open_failed", None, "failed"))
            .collect::<Vec<_>>();
        push_service_diagnostic(
            &mut diagnostics,
            diagnostic("service_query_failed", None, "failed"),
        );
        assert_eq!(diagnostics.len(), MAX_SERVICE_DIAGNOSTICS);
        assert_eq!(
            diagnostics.last().unwrap().code,
            "service_diagnostics_limit_exceeded"
        );
    }

    #[test]
    fn scheduled_trigger_normalization_keeps_only_boot_and_logon() {
        assert_eq!(scheduled_trigger_name(TASK_TRIGGER_BOOT), Some("boot"));
        assert_eq!(scheduled_trigger_name(TASK_TRIGGER_LOGON), Some("logon"));
        assert_eq!(scheduled_trigger_name(TASK_TRIGGER_TYPE2(0)), None);
        assert_eq!(scheduled_trigger_name(TASK_TRIGGER_TYPE2(7)), None);
    }

    #[test]
    fn scheduled_action_mapping_only_interprets_exec_actions() {
        assert_eq!(scheduled_action_name(TASK_ACTION_EXEC), "exec");
        assert_eq!(
            scheduled_action_status(TASK_ACTION_EXEC),
            WindowsScheduledTaskActionStatus::Observed
        );
        for (action, name) in [
            (TASK_ACTION_COM_HANDLER, "com_handler"),
            (TASK_ACTION_SEND_EMAIL, "send_email"),
            (TASK_ACTION_SHOW_MESSAGE, "show_message"),
            (TASK_ACTION_TYPE(91), "unknown"),
        ] {
            assert_eq!(scheduled_action_name(action), name);
            assert_eq!(
                scheduled_action_status(action),
                WindowsScheduledTaskActionStatus::Unsupported
            );
        }
    }

    #[test]
    fn exec_action_text_is_serialized_inertly_without_interpretation() {
        let action = WindowsScheduledTaskAction {
            task_path: Some("\\Example\\Literal".to_owned()),
            action_index: 2,
            action_type: "exec",
            action_type_code: Some(TASK_ACTION_EXEC.0),
            status: WindowsScheduledTaskActionStatus::Observed,
            executable_path: Some(r"%TEMP%\worker.exe".to_owned()),
            arguments: Some(r#"--name "value"; $(not-run)"#.to_owned()),
            working_directory: Some(r"C:\Work".to_owned()),
            evidence: WindowsScheduledTaskActionEvidence {
                source: "synthetic unit-test value",
                task_index: 4,
                action_index: 2,
            },
        };
        let value = serde_json::to_value(action).unwrap();
        assert_eq!(value["executable_path"], r"%TEMP%\worker.exe");
        assert_eq!(value["arguments"], r#"--name "value"; $(not-run)"#);
        assert_eq!(value["working_directory"], r"C:\Work");
        assert_eq!(value["evidence"]["task_index"], 4);
        assert_eq!(value["evidence"]["action_index"], 2);
    }

    #[test]
    fn task_collection_counts_are_clamped_and_negative_values_rejected() {
        assert_eq!(bounded_task_count(3, 5), Ok((3, false)));
        assert_eq!(bounded_task_count(8, 5), Ok((5, true)));
        assert_eq!(bounded_task_count(0, 0), Ok((0, false)));
        assert_eq!(bounded_task_count(-1, 5), Err(TaskCountError::Negative));
    }

    #[test]
    fn scheduled_task_action_limits_are_bounded_and_string_budget_is_checked() {
        assert_eq!(MAX_SCHEDULED_TASK_ACTIONS, 8_192);
        assert_eq!(MAX_ACTIONS_PER_TASK, 256);
        assert_eq!(
            bounded_task_count(257, MAX_ACTIONS_PER_TASK),
            Ok((256, true))
        );
        let mut used = MAX_AGGREGATE_TASK_STRING_UNITS - 2;
        assert_eq!(reserve_task_string("ab", &mut used), Ok(()));
        assert_eq!(used, MAX_AGGREGATE_TASK_STRING_UNITS);
        assert_eq!(
            reserve_task_string("x", &mut used),
            Err(TaskStringError::AggregateLimit)
        );
    }

    #[test]
    fn task_strings_are_strict_and_bounded() {
        assert_eq!(
            bounded_bstr_to_string(&BSTR::from("\\Root\\Example")),
            Ok("\\Root\\Example".to_string())
        );
        let malformed = BSTR::from_wide(&[0xd800]);
        assert_eq!(
            bounded_bstr_to_string(&malformed),
            Err(TaskStringError::MalformedUtf16)
        );
        let oversized_units = vec![b'X' as u16; MAX_TASK_STRING_UNITS + 1];
        let oversized = BSTR::from_wide(&oversized_units);
        assert_eq!(
            bounded_bstr_to_string(&oversized),
            Err(TaskStringError::OverLimit)
        );
    }

    #[test]
    fn task_collection_indices_use_one_based_i4_variants() {
        let variant = one_based_task_index(4);
        unsafe {
            let value = &*variant.Anonymous.Anonymous;
            assert_eq!(value.vt, VT_I4);
            assert_eq!(value.Anonymous.lVal, 4);
        }
    }
}
