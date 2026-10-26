//! Bounded Windows process-lifecycle observations from the NT Kernel Logger.
//!
//! The kernel logger is system-wide. This first prototype does not attribute
//! process events to the selected command or claim that a parent caused a child.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, EVENT_RECORD, EVENT_TRACE_CONTROL_QUERY,
    EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_TYPE_END, EVENT_TRACE_TYPE_START, EventTraceGuid,
    OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace,
    StartTraceW, StopTraceW, SystemTraceControlGuid, WNODE_FLAG_TRACED_GUID,
};

pub const WINDOWS_RUNTIME_CAPTURE_SCHEMA: &str = "sideeffect.windows_runtime_capture";
pub const WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION: u32 = 1;
pub const MAX_WINDOWS_RUNTIME_DURATION_SECONDS: u64 = 60;
const MAX_EVENT_RECORDS: usize = 50_000;
const MAX_EVENT_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const MAX_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;
const MAX_EVENT_PAYLOAD_LENGTH: usize = 64 * 1024;
const BUFFER_SIZE_KB: u32 = 16;
const MINIMUM_BUFFERS: u32 = 8;
const MAXIMUM_BUFFERS: u32 = 32;
// SystemTraceControlGuid identifies the reserved NT Kernel Logger. Windows
// requires its well-known name; this session is shared with other software.
const SESSION_NAME: &str = "NT Kernel Logger";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WindowsRuntimeCapture {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub capture_profile: &'static str,
    pub collection_status: CollectionStatus,
    pub capture_completeness: &'static str,
    pub started_at_unix_ms: u128,
    pub ended_at_unix_ms: u128,
    pub requested_duration_seconds: u64,
    pub stop_reason: StopReason,
    pub target: TargetOutcome,
    pub session: SessionMetadata,
    pub limits: AppliedLimits,
    pub event_loss: EventLoss,
    pub document_sha256: String,
    pub events: Vec<NativeProcessEvent>,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    TargetExited,
    DurationLimitReached,
    EventLimitReached,
    EtwLossReported,
    EtwStatisticsUnavailable,
}

#[derive(Clone, Debug, Serialize)]
pub struct TargetOutcome {
    pub process_id: u32,
    pub exit_code: Option<i32>,
    pub status_available: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionMetadata {
    pub name: &'static str,
    pub provider: &'static str,
    pub scope: &'static str,
    pub buffer_size_kb_requested: u32,
    pub minimum_buffers_requested: u32,
    pub maximum_buffers_requested: u32,
    pub buffer_count_reported: u32,
    pub provider_process_id_header_semantics: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct AppliedLimits {
    pub maximum_duration_seconds: u64,
    pub maximum_events: usize,
    pub maximum_total_payload_bytes: usize,
    pub maximum_payload_bytes_per_event: usize,
    pub maximum_document_bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventLoss {
    pub events_lost: u32,
    pub log_buffers_lost: u32,
    pub real_time_buffers_lost: u32,
    pub loss_statistics_available: bool,
    pub observation: &'static str,
    pub final_snapshot_available: bool,
}

impl Default for EventLoss {
    fn default() -> Self {
        Self {
            events_lost: 0,
            log_buffers_lost: 0,
            real_time_buffers_lost: 0,
            loss_statistics_available: false,
            observation: "unavailable",
            final_snapshot_available: false,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct NativeProcessEvent {
    pub record_ordinal: u64,
    pub provider_guid: String,
    pub event_id: u16,
    pub event_version: u8,
    pub opcode: u8,
    pub event_kind: &'static str,
    /// ETW header context only. For process create events this may describe
    /// the parent execution context, not the newly created process.
    pub header_process_id: u32,
    pub header_thread_id: u32,
    /// ETW QPC timestamp ticks. No wall-clock conversion is claimed here.
    pub timestamp_qpc: i64,
    /// Exact bytes from EVENT_RECORD.UserData for this source event.
    pub raw_payload_hex: String,
}

#[derive(Default)]
struct Collector {
    events: Vec<NativeProcessEventBytes>,
    payload_bytes: usize,
    limit_reached: bool,
    malformed: bool,
    unsupported_provider_events: usize,
}

#[derive(Clone)]
struct NativeProcessEventBytes {
    provider_guid: String,
    event_id: u16,
    event_version: u8,
    opcode: u8,
    event_kind: &'static str,
    header_process_id: u32,
    header_thread_id: u32,
    timestamp_qpc: i64,
    raw_payload: Vec<u8>,
}

/// Run a selected command while collecting process start/end ETW records.
/// Session creation must succeed before the command is launched.
pub fn record_windows_process_capture(
    destination: &Path,
    program: &OsStr,
    args: &[std::ffi::OsString],
    duration_limit: Duration,
) -> Result<WindowsRuntimeCapture, String> {
    let seconds = duration_limit.as_secs();
    if duration_limit.subsec_nanos() != 0
        || !(1..=MAX_WINDOWS_RUNTIME_DURATION_SECONDS).contains(&seconds)
    {
        return Err(format!(
            "Windows ETW duration must be a whole number of seconds from 1 to {MAX_WINDOWS_RUNTIME_DURATION_SECONDS}"
        ));
    }
    if destination.exists() {
        return Err("Windows runtime output already exists; refusing to overwrite".to_owned());
    }

    let collector = Arc::new(Mutex::new(Collector::default()));
    let mut session = EtwSession::start(collector.clone())?;
    let start_unix_ms = session.started_at_unix_ms;
    // Session setup is outside the requested runtime budget. The deadline
    // starts after the real-time ETW consumer reports ready and before spawn.
    let runtime_started = Instant::now();
    let mut command = build_target_command(program, args);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = session.stop();
            return Err(format!("could not start selected program: {error}"));
        }
    };
    let target_pid = child.id();
    let mut timed_out = false;
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if runtime_started.elapsed() < duration_limit => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                timed_out = true;
                child.kill().map_err(|error| {
                    format!("could not stop selected process at duration limit: {error}")
                })?;
                break child.wait().ok();
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = session.stop();
                return Err(format!("could not wait for selected process: {error}"));
            }
        }
    };

    let stopped = session.stop();
    let end_unix_ms = now_unix_ms()?;
    let mut diagnostics = Vec::new();
    if let Err(error) = stopped {
        diagnostics.push(format!("etw_stop_failed:{error}"));
    }
    let collector = collector
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let loss = session.loss.clone().unwrap_or_default();
    let event_limit = collector.limit_reached;
    let malformed = collector.malformed;
    let unsupported_provider_events = collector.unsupported_provider_events;
    let mut events = Vec::with_capacity(collector.events.len());
    for (index, event) in collector.events.iter().enumerate() {
        events.push(NativeProcessEvent {
            record_ordinal: (index + 1) as u64,
            provider_guid: event.provider_guid.clone(),
            event_id: event.event_id,
            event_version: event.event_version,
            opcode: event.opcode,
            event_kind: event.event_kind,
            header_process_id: event.header_process_id,
            header_thread_id: event.header_thread_id,
            timestamp_qpc: event.timestamp_qpc,
            raw_payload_hex: hex(&event.raw_payload),
        });
    }
    drop(collector);
    let status = collection_status(
        timed_out,
        event_limit,
        malformed,
        loss.is_complete_and_loss_free(),
        !diagnostics.is_empty(),
    );
    if event_limit {
        diagnostics.push("event_or_payload_limit_reached".to_owned());
    }
    if malformed {
        diagnostics.push("invalid_or_unsupported_etw_record_seen".to_owned());
    }
    if unsupported_provider_events > 0 {
        diagnostics.push(format!(
            "unexpected_provider_events:{unsupported_provider_events}"
        ));
    }
    if loss.has_losses() {
        diagnostics.push("etw_reported_event_loss".to_owned());
    }
    if !loss.loss_statistics_available {
        diagnostics.push("etw_loss_statistics_unavailable".to_owned());
    }
    if !loss.final_snapshot_available {
        diagnostics.push("etw_final_loss_statistics_unavailable".to_owned());
    }
    if timed_out {
        diagnostics.push("duration_limit_reached; only the selected process was stopped; descendants may continue outside this capture".to_owned());
    }
    let stop_reason = if timed_out {
        StopReason::DurationLimitReached
    } else if event_limit {
        StopReason::EventLimitReached
    } else if loss.has_losses() {
        StopReason::EtwLossReported
    } else if !loss.loss_statistics_available || !loss.final_snapshot_available {
        StopReason::EtwStatisticsUnavailable
    } else {
        StopReason::TargetExited
    };
    let target = TargetOutcome {
        process_id: target_pid,
        exit_code: exit_status.as_ref().and_then(ExitStatus::code),
        status_available: exit_status.is_some(),
    };
    let mut document = WindowsRuntimeCapture {
        schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA,
        schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
        platform: "windows",
        capture_profile: "windows_nt_kernel_process_lifecycle_v1",
        collection_status: status,
        capture_completeness: "unknown",
        started_at_unix_ms: start_unix_ms,
        ended_at_unix_ms: end_unix_ms,
        requested_duration_seconds: seconds,
        stop_reason,
        target,
        session: SessionMetadata {
            name: SESSION_NAME,
            provider: "NT Kernel Logger Process provider",
            scope: "system_wide_process_lifecycle_during_capture_window",
            buffer_size_kb_requested: BUFFER_SIZE_KB,
            minimum_buffers_requested: MINIMUM_BUFFERS,
            maximum_buffers_requested: MAXIMUM_BUFFERS,
            buffer_count_reported: session.buffer_count,
            provider_process_id_header_semantics: "header PID/TID is event context and may not identify the process described by a process-start payload",
        },
        limits: AppliedLimits {
            maximum_duration_seconds: MAX_WINDOWS_RUNTIME_DURATION_SECONDS,
            maximum_events: MAX_EVENT_RECORDS,
            maximum_total_payload_bytes: MAX_EVENT_PAYLOAD_BYTES,
            maximum_payload_bytes_per_event: MAX_EVENT_PAYLOAD_LENGTH,
            maximum_document_bytes: MAX_DOCUMENT_BYTES,
        },
        event_loss: loss,
        document_sha256: String::new(),
        events,
        diagnostics,
    };
    let payload = serde_json::to_vec(&document)
        .map_err(|error| format!("could not serialize Windows runtime capture: {error}"))?;
    if payload.len() > MAX_DOCUMENT_BYTES {
        return Err(format!(
            "Windows runtime capture exceeds the {MAX_DOCUMENT_BYTES} byte document limit; no output was published"
        ));
    }
    document.document_sha256 = format!("{:x}", Sha256::digest(&payload));
    let output = serde_json::to_vec(&document)
        .map_err(|error| format!("could not serialize Windows runtime capture: {error}"))?;
    if output.len() > MAX_DOCUMENT_BYTES {
        return Err(format!(
            "Windows runtime capture exceeds the {MAX_DOCUMENT_BYTES} byte document limit; no output was published"
        ));
    }
    super::publish_private_windows_file(destination, &output, MAX_DOCUMENT_BYTES)
        .map_err(|error| format!("could not publish private Windows runtime capture without replacing an existing path: {error}"))?;
    Ok(document)
}

fn build_target_command(program: &OsStr, args: &[std::ffi::OsString]) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    command
}

impl EventLoss {
    fn has_losses(&self) -> bool {
        self.events_lost > 0 || self.log_buffers_lost > 0 || self.real_time_buffers_lost > 0
    }

    fn is_complete_and_loss_free(&self) -> bool {
        self.loss_statistics_available && self.final_snapshot_available && !self.has_losses()
    }
}

fn collection_status(
    timed_out: bool,
    event_limit: bool,
    malformed: bool,
    loss_free: bool,
    stop_failed: bool,
) -> CollectionStatus {
    if timed_out || event_limit || malformed || !loss_free || stop_failed {
        CollectionStatus::Partial
    } else {
        CollectionStatus::Complete
    }
}

struct EtwSession {
    handle: CONTROLTRACE_HANDLE,
    consumer: Option<thread::JoinHandle<u32>>,
    name: Vec<u16>,
    loss: Option<EventLoss>,
    buffer_count: u32,
    started_at_unix_ms: u128,
    stopped: bool,
}

impl EtwSession {
    fn start(collector: Arc<Mutex<Collector>>) -> Result<Self, String> {
        let name = wide_z(SESSION_NAME);
        let properties_size = size_of::<EVENT_TRACE_PROPERTIES>();
        let name_bytes = name.len() * size_of::<u16>();
        let total_size = properties_size + name_bytes;
        let mut words = vec![0_u64; total_size.div_ceil(size_of::<u64>())];
        let props = words.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
        unsafe {
            (*props).Wnode.BufferSize = total_size as u32;
            (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props).Wnode.ClientContext = 1;
            (*props).Wnode.Guid = SystemTraceControlGuid;
            (*props).BufferSize = BUFFER_SIZE_KB;
            (*props).MinimumBuffers = MINIMUM_BUFFERS;
            (*props).MaximumBuffers = MAXIMUM_BUFFERS;
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).EnableFlags = EVENT_TRACE_FLAG_PROCESS;
            (*props).LoggerNameOffset = properties_size as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                words
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(properties_size)
                    .cast::<u16>(),
                name.len(),
            );
        }
        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let result = unsafe { StartTraceW(&mut handle, name.as_ptr(), props) };
        if result != ERROR_SUCCESS {
            return Err(etw_start_error(result));
        }
        let started_at_unix_ms = match now_unix_ms() {
            Ok(timestamp) => timestamp,
            Err(error) => {
                unsafe { StopTraceW(handle, name.as_ptr(), props) };
                return Err(error);
            }
        };
        let (ready_tx, ready_rx) = mpsc::channel();
        let consumer_name = name.clone();
        let consumer_state = collector.clone();
        let consumer =
            thread::spawn(move || consume_session(consumer_name, consumer_state, ready_tx));
        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(Self {
                handle,
                consumer: Some(consumer),
                name,
                loss: None,
                buffer_count: 0,
                started_at_unix_ms,
                stopped: false,
            }),
            Ok(Err(code)) => {
                unsafe { StopTraceW(handle, name.as_ptr(), props) };
                let _ = consumer.join();
                Err(etw_start_error(code))
            }
            Err(_) => {
                unsafe { StopTraceW(handle, name.as_ptr(), props) };
                let _ = consumer.join();
                Err("ETW real-time consumer did not become ready within 5 seconds; command was not started".to_owned())
            }
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        if self.stopped {
            return Ok(());
        }
        let mut properties =
            vec![0_u64; size_of::<EVENT_TRACE_PROPERTIES>().div_ceil(size_of::<u64>())];
        let props = properties.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
        unsafe {
            (*props).Wnode.BufferSize = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props).Wnode.Guid = SystemTraceControlGuid;
            (*props).LogFileNameOffset = 0;
            (*props).LoggerNameOffset = 0;
        }
        let query = unsafe {
            windows_sys::Win32::System::Diagnostics::Etw::ControlTraceW(
                self.handle,
                self.name.as_ptr(),
                props,
                EVENT_TRACE_CONTROL_QUERY,
            )
        };
        if query == ERROR_SUCCESS {
            self.buffer_count = unsafe { (*props).NumberOfBuffers };
            self.loss = Some(EventLoss {
                events_lost: unsafe { (*props).EventsLost },
                log_buffers_lost: unsafe { (*props).LogBuffersLost },
                real_time_buffers_lost: unsafe { (*props).RealTimeBuffersLost },
                loss_statistics_available: true,
                observation: "pre_stop_query",
                final_snapshot_available: false,
            });
        }
        let stopped = unsafe { StopTraceW(self.handle, self.name.as_ptr(), props) };
        if stopped != ERROR_SUCCESS {
            return Err(format!(
                "ControlTrace(STOP) failed with Windows error {stopped}"
            ));
        }
        self.stopped = true;
        self.loss = Some(EventLoss {
            events_lost: unsafe { (*props).EventsLost },
            log_buffers_lost: unsafe { (*props).LogBuffersLost },
            real_time_buffers_lost: unsafe { (*props).RealTimeBuffersLost },
            loss_statistics_available: true,
            observation: "stop_response",
            final_snapshot_available: true,
        });
        if let Some(consumer) = self.consumer.take() {
            let result = consumer
                .join()
                .map_err(|_| "ETW consumer thread panicked".to_owned())?;
            validate_process_trace_result(result)?;
        }
        // STOP succeeded and supplied final counters. QUERY failure is
        // therefore not fatal to this final loss snapshot.
        let _ = query;
        Ok(())
    }
}

fn validate_process_trace_result(result: u32) -> Result<(), String> {
    if result == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "ProcessTrace returned Windows error {result} after the session stopped"
        ))
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.stop();
        }
    }
}

fn consume_session(
    name: Vec<u16>,
    collector: Arc<Mutex<Collector>>,
    ready: mpsc::Sender<Result<(), u32>>,
) -> u32 {
    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { zeroed() };
    logfile.LoggerName = name.as_ptr() as *mut u16;
    logfile.Context = Arc::as_ptr(&collector) as *mut _;
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
    logfile.Anonymous2.EventRecordCallback = Some(event_callback);
    let trace = unsafe { OpenTraceW(&mut logfile) };
    if trace.Value == u64::MAX {
        let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(1) as u32;
        let _ = ready.send(Err(error));
        return error;
    }
    let _ = ready.send(Ok(()));
    let result = unsafe { ProcessTrace(&trace, 1, std::ptr::null(), std::ptr::null()) };
    unsafe { CloseTrace(trace) };
    result
}

unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let event = unsafe { &*record };
    let header = &event.EventHeader;
    let guid = header.ProviderId;
    // ProcessGuid identifies the classic kernel process event class. Only its
    // documented Start/End opcodes are labeled; unknown opcodes stay visible.
    let process_guid = windows_sys::Win32::System::Diagnostics::Etw::ProcessGuid;
    if !guid_equal(guid, process_guid) {
        if !guid_equal(guid, EventTraceGuid) && !event.UserContext.is_null() {
            let state = unsafe { &*event.UserContext.cast::<Mutex<Collector>>() };
            let mut state = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.unsupported_provider_events = state.unsupported_provider_events.saturating_add(1);
            state.malformed = true;
        }
        return;
    }
    let opcode = header.EventDescriptor.Opcode;
    let event_kind = classify_process_opcode(opcode);
    let length = usize::from(event.UserDataLength);
    if length > MAX_EVENT_PAYLOAD_LENGTH || (length > 0 && event.UserData.is_null()) {
        if !event.UserContext.is_null() {
            unsafe { &*event.UserContext.cast::<Mutex<Collector>>() }
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .malformed = true;
        }
        return;
    }
    if event.UserContext.is_null() {
        return;
    }
    let mut payload = Vec::new();
    if payload.try_reserve_exact(length).is_err() {
        unsafe { &*event.UserContext.cast::<Mutex<Collector>>() }
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .limit_reached = true;
        return;
    }
    if length > 0 {
        let bytes = unsafe { std::slice::from_raw_parts(event.UserData.cast::<u8>(), length) };
        payload.extend_from_slice(bytes);
    }
    let state = unsafe { &*event.UserContext.cast::<Mutex<Collector>>() };
    let mut state = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    append_event(
        &mut state,
        NativeProcessEventBytes {
            provider_guid: format_guid(guid),
            event_id: header.EventDescriptor.Id,
            event_version: header.EventDescriptor.Version,
            opcode,
            event_kind,
            header_process_id: header.ProcessId,
            header_thread_id: header.ThreadId,
            timestamp_qpc: header.TimeStamp,
            raw_payload: payload,
        },
    );
}

fn append_event(state: &mut Collector, event: NativeProcessEventBytes) -> bool {
    let payload_len = event.raw_payload.len();
    if payload_len > MAX_EVENT_PAYLOAD_LENGTH {
        state.malformed = true;
        return false;
    }
    if state.events.len() >= MAX_EVENT_RECORDS
        || state.payload_bytes.saturating_add(payload_len) > MAX_EVENT_PAYLOAD_BYTES
    {
        state.limit_reached = true;
        return false;
    }
    if event.event_kind == "unsupported_process_event" {
        state.malformed = true;
    }
    if state.events.try_reserve(1).is_err() {
        state.limit_reached = true;
        return false;
    }
    state.payload_bytes += payload_len;
    state.events.push(event);
    true
}

fn etw_start_error(code: u32) -> String {
    if code == ERROR_ACCESS_DENIED {
        "NT Kernel Logger control was denied; this capture requires administrative privileges. No elevation was requested and the command was not started.".to_owned()
    } else if code == 183 {
        "the NT Kernel Logger session is already in use; no session was changed and the command was not started".to_owned()
    } else {
        format!(
            "could not start or consume the NT Kernel Logger session (Windows error {code}); the command was not started"
        )
    }
}

fn now_unix_ms() -> Result<u128, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|_| "system clock is earlier than Unix epoch".to_owned())
}

fn wide_z(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

fn format_guid(guid: windows_sys::core::GUID) -> String {
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7]
    )
}

fn guid_equal(left: windows_sys::core::GUID, right: windows_sys::core::GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

fn classify_process_opcode(opcode: u8) -> &'static str {
    match u32::from(opcode) {
        EVENT_TRACE_TYPE_START => "process_start",
        EVENT_TRACE_TYPE_END => "process_end",
        _ => "unsupported_process_event",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_event_opcodes_are_classified_only_for_known_class() {
        assert_eq!(
            classify_process_opcode(EVENT_TRACE_TYPE_START as u8),
            "process_start"
        );
        assert_eq!(
            classify_process_opcode(EVENT_TRACE_TYPE_END as u8),
            "process_end"
        );
        assert_eq!(classify_process_opcode(99), "unsupported_process_event");
    }

    #[test]
    fn hex_preserves_raw_payload_and_has_bounded_expansion() {
        assert_eq!(hex(&[0, 1, 127, 255]), "00017fff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn unknown_loss_statistics_make_collection_partial() {
        let unknown = EventLoss::default();
        let zero = EventLoss {
            loss_statistics_available: true,
            observation: "stop_response",
            final_snapshot_available: true,
            ..EventLoss::default()
        };
        let lost = EventLoss {
            loss_statistics_available: true,
            events_lost: 1,
            observation: "stop_response",
            final_snapshot_available: true,
            ..EventLoss::default()
        };
        let pre_stop = EventLoss {
            loss_statistics_available: true,
            observation: "pre_stop_query",
            ..EventLoss::default()
        };
        assert!(!unknown.is_complete_and_loss_free());
        assert!(zero.is_complete_and_loss_free());
        assert!(!lost.is_complete_and_loss_free());
        assert!(!pre_stop.is_complete_and_loss_free());
    }

    #[test]
    fn process_trace_non_success_status_is_not_treated_as_complete() {
        assert!(validate_process_trace_result(ERROR_SUCCESS).is_ok());
        assert!(validate_process_trace_result(1).is_err());
    }

    #[test]
    fn event_and_payload_limits_reject_the_first_over_limit_record() {
        let event = |raw_payload: Vec<u8>| NativeProcessEventBytes {
            provider_guid: "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}".to_owned(),
            event_id: 1,
            event_version: 0,
            opcode: EVENT_TRACE_TYPE_START as u8,
            event_kind: "process_start",
            header_process_id: 0,
            header_thread_id: 0,
            timestamp_qpc: 0,
            raw_payload,
        };
        let mut state = Collector::default();
        for _ in 0..(MAX_EVENT_PAYLOAD_BYTES / MAX_EVENT_PAYLOAD_LENGTH) {
            assert!(append_event(
                &mut state,
                event(vec![7; MAX_EVENT_PAYLOAD_LENGTH])
            ));
        }
        assert!(!append_event(&mut state, event(vec![8])));
        assert!(state.limit_reached);
        assert_eq!(
            state.events.len(),
            MAX_EVENT_PAYLOAD_BYTES / MAX_EVENT_PAYLOAD_LENGTH
        );

        let mut state = Collector::default();
        assert!(!append_event(
            &mut state,
            event(vec![0; MAX_EVENT_PAYLOAD_LENGTH + 1])
        ));
        assert!(state.malformed);
    }

    #[test]
    fn partial_status_covers_timeout_loss_unknown_stats_and_decoder_gaps() {
        assert_eq!(
            collection_status(false, false, false, true, false),
            CollectionStatus::Complete
        );
        for inputs in [
            (true, false, false, true, false),
            (false, true, false, true, false),
            (false, false, true, true, false),
            (false, false, false, false, false),
            (false, false, false, true, true),
        ] {
            assert_eq!(
                collection_status(inputs.0, inputs.1, inputs.2, inputs.3, inputs.4),
                CollectionStatus::Partial
            );
        }
    }

    #[test]
    fn target_argv_is_forwarded_as_distinct_operating_system_arguments() {
        use std::ffi::OsString;
        let arguments = vec![OsString::from("two words"), OsString::from("; literal")];
        let command = build_target_command(OsStr::new("program name.exe"), &arguments);
        assert_eq!(command.get_program(), OsStr::new("program name.exe"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            arguments
                .iter()
                .map(OsString::as_os_str)
                .collect::<Vec<_>>()
        );
    }
}
