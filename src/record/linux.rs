use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::limits::MAX_TRACE_BYTES;

const READ_BUFFER_BYTES: usize = 64 * 1024;
const POLL_INTERVAL_MS: i32 = 50;
const MIN_STRACE_VERSION: (u64, u64) = (6, 8);
const MAX_VERSION_OUTPUT_BYTES: usize = 4096;
const VERSION_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
static CANCELLATION_SIGNAL: AtomicI32 = AtomicI32::new(0);
static SIGNAL_GUARD_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug)]
pub struct RecordOutcome {
    /// The raw status returned by strace. It is not interpreted as a tracer
    /// success indicator or as a separately verified command exit status.
    pub strace_status: ExitStatus,
    pub trace_path: PathBuf,
    pub trace_bytes: usize,
    /// True when the caller-requested wall-clock limit stopped the capture.
    pub time_limit_reached: bool,
}

#[derive(Debug)]
pub struct RunBundleOutcome {
    pub strace_status: ExitStatus,
    pub bundle_path: PathBuf,
    pub trace_bytes: usize,
    pub parent_directory_sync_confirmed: bool,
    /// True when the caller-requested wall-clock limit stopped the capture.
    pub time_limit_reached: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StraceVersion {
    major: u64,
    minor: u64,
}

#[derive(Serialize)]
struct RunManifest<'a> {
    schema: &'static str,
    schema_version: u32,
    producer: Producer,
    capture: Capture,
    trace: TraceFile<'a>,
}

#[derive(Serialize)]
struct Producer {
    sideeffect_version: &'static str,
    operating_system: &'static str,
    architecture: &'static str,
}

#[derive(Serialize)]
struct Capture {
    tracer: Tracer,
    capture_profile: &'static str,
    strace_reported_status: ReportedStatus,
    command_outcome: &'static str,
    completeness: &'static str,
    command_stdout: &'static str,
    command_stderr: &'static str,
    tracer_diagnostics: &'static str,
    time_limit_milliseconds: Option<u64>,
    stop_reason: &'static str,
}

#[derive(Serialize)]
struct Tracer {
    name: &'static str,
    major: u64,
    minor: u64,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ReportedStatus {
    ExitCode { value: i32 },
    Signal { value: i32 },
    Unavailable,
}

#[derive(Serialize)]
struct TraceFile<'a> {
    name: &'static str,
    format: &'static str,
    byte_length: usize,
    sha256: &'a str,
}

struct CaptureStage {
    output: super::AnchoredOutput,
    status: ExitStatus,
    bytes: usize,
    version: StraceVersion,
    trace_file: File,
    time_limit_reached: bool,
}

#[derive(Debug)]
pub struct RecordError {
    message: String,
    target_may_have_run: bool,
}

impl RecordError {
    fn before_launch(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            target_may_have_run: false,
        }
    }

    fn after_launch(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            target_may_have_run: true,
        }
    }
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)?;
        if self.target_may_have_run {
            write!(
                formatter,
                "; the command may have started or been terminated"
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for RecordError {}

/// Run a command under strace and publish its bounded raw trace without
/// replacing an existing destination.
pub fn record_trace(
    destination: &Path,
    program: &OsStr,
    args: &[OsString],
) -> Result<RecordOutcome, RecordError> {
    record_trace_with_duration(destination, program, args, None)
}

/// Record until the target exits or the optional wall-clock limit is reached.
pub fn record_trace_with_duration(
    destination: &Path,
    program: &OsStr,
    args: &[OsString],
    duration_limit: Option<Duration>,
) -> Result<RecordOutcome, RecordError> {
    let mut captured = record_capture_bounded(
        destination,
        OsStr::new("strace"),
        program,
        args,
        MAX_TRACE_BYTES,
        false,
        duration_limit,
    )?;
    let final_path = captured.output.publish_trace().map_err(|error| {
        RecordError::after_launch(format!(
            "could not publish trace without replacing an existing path: {error}"
        ))
    })?;
    Ok(RecordOutcome {
        strace_status: captured.status,
        trace_path: final_path,
        trace_bytes: captured.bytes,
        time_limit_reached: captured.time_limit_reached,
    })
}

/// Record a bounded run and atomically publish a privacy-minimized versioned bundle.
pub fn record_bundle(
    destination: &Path,
    program: &OsStr,
    args: &[OsString],
) -> Result<RunBundleOutcome, RecordError> {
    record_bundle_with_duration(destination, program, args, None)
}

/// Record until the target exits or the optional wall-clock limit is reached.
pub fn record_bundle_with_duration(
    destination: &Path,
    program: &OsStr,
    args: &[OsString],
    duration_limit: Option<Duration>,
) -> Result<RunBundleOutcome, RecordError> {
    record_bundle_bounded(
        destination,
        OsStr::new("strace"),
        program,
        args,
        MAX_TRACE_BYTES,
        duration_limit,
    )
}

fn record_bundle_bounded(
    destination: &Path,
    tracer: &OsStr,
    program: &OsStr,
    args: &[OsString],
    max_trace_bytes: usize,
    duration_limit: Option<Duration>,
) -> Result<RunBundleOutcome, RecordError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(RecordError::before_launch(
            "versioned run bundles currently require Linux x86_64; the command was not started",
        ));
    }
    let mut capture = record_capture_bounded(
        destination,
        tracer,
        program,
        args,
        max_trace_bytes,
        true,
        duration_limit,
    )?;
    let (sha256, byte_length) = hash_exact_trace(&mut capture.trace_file, capture.bytes)?;
    let manifest = RunManifest {
        schema: "sideeffect.run",
        schema_version: 2,
        producer: Producer {
            sideeffect_version: env!("CARGO_PKG_VERSION"),
            operating_system: "linux",
            architecture: "x86_64",
        },
        capture: Capture {
            tracer: Tracer {
                name: "strace",
                major: capture.version.major,
                minor: capture.version.minor,
            },
            capture_profile: "linux_process_file_network_v1",
            strace_reported_status: reported_status(capture.status),
            command_outcome: "not_independently_verified",
            completeness: "unknown",
            command_stdout: "inherited_not_captured",
            command_stderr: "inherited_not_captured",
            tracer_diagnostics: "inherited_not_captured",
            time_limit_milliseconds: duration_limit.map(|value| value.as_millis() as u64),
            stop_reason: if capture.time_limit_reached {
                "time_limit_reached"
            } else {
                "tracer_exited"
            },
        },
        trace: TraceFile {
            name: "trace.strace",
            format: "strace_text",
            byte_length,
            sha256: &sha256,
        },
    };
    let mut manifest_file = capture.output.create_manifest_file().map_err(|error| {
        RecordError::after_launch(format!("could not create bundle manifest: {error}"))
    })?;
    serde_json::to_writer(&mut manifest_file, &manifest).map_err(|error| {
        RecordError::after_launch(format!("could not serialize bundle manifest: {error}"))
    })?;
    manifest_file
        .write_all(b"\n")
        .and_then(|()| manifest_file.flush())
        .and_then(|()| manifest_file.sync_all())
        .map_err(|error| {
            RecordError::after_launch(format!("could not finalize bundle manifest: {error}"))
        })?;
    drop(manifest_file);
    drop(capture.trace_file);
    capture.output.remove_fifo().map_err(|error| {
        RecordError::after_launch(format!(
            "could not remove staging FIFO before bundle publication: {error}"
        ))
    })?;
    let (bundle_path, parent_directory_sync_confirmed) =
        capture.output.publish_bundle().map_err(|error| {
            RecordError::after_launch(format!(
                "could not atomically publish bundle without replacing an existing path: {error}"
            ))
        })?;
    Ok(RunBundleOutcome {
        strace_status: capture.status,
        bundle_path,
        trace_bytes: capture.bytes,
        parent_directory_sync_confirmed,
        time_limit_reached: capture.time_limit_reached,
    })
}

fn reported_status(status: ExitStatus) -> ReportedStatus {
    if let Some(code) = status.code() {
        ReportedStatus::ExitCode { value: code }
    } else if let Some(signal) = status.signal() {
        ReportedStatus::Signal { value: signal }
    } else {
        ReportedStatus::Unavailable
    }
}

fn hash_exact_trace(
    file: &mut File,
    expected_bytes: usize,
) -> Result<(String, usize), RecordError> {
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        RecordError::after_launch(format!("could not seek staged trace for hashing: {error}"))
    })?;
    let mut digest = Sha256::new();
    let mut total = 0usize;
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            RecordError::after_launch(format!("could not read staged trace for hashing: {error}"))
        })?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count)
            .ok_or_else(|| RecordError::after_launch("trace byte count overflow while hashing"))?;
        if total > expected_bytes {
            return Err(RecordError::after_launch(
                "staged trace grew while hashing; bundle was discarded",
            ));
        }
        digest.update(&buffer[..count]);
    }
    if total != expected_bytes {
        return Err(RecordError::after_launch(
            "staged trace length changed before hashing; bundle was discarded",
        ));
    }
    let mut encoded = String::with_capacity(64);
    for byte in digest.finalize() {
        encoded.push(b"0123456789abcdef"[(byte >> 4) as usize] as char);
        encoded.push(b"0123456789abcdef"[(byte & 0x0f) as usize] as char);
    }
    Ok((encoded, total))
}

#[cfg(test)]
fn record_trace_bounded(
    destination: &Path,
    tracer: &OsStr,
    program: &OsStr,
    args: &[OsString],
    max_trace_bytes: usize,
) -> Result<RecordOutcome, RecordError> {
    let mut capture = record_capture_bounded(
        destination,
        tracer,
        program,
        args,
        max_trace_bytes,
        false,
        None,
    )?;
    let final_path = capture.output.publish_trace().map_err(|error| {
        RecordError::after_launch(format!(
            "could not publish trace without replacing an existing path: {error}"
        ))
    })?;
    Ok(RecordOutcome {
        strace_status: capture.status,
        trace_path: final_path,
        trace_bytes: capture.bytes,
        time_limit_reached: capture.time_limit_reached,
    })
}

fn record_capture_bounded(
    destination: &Path,
    tracer: &OsStr,
    program: &OsStr,
    args: &[OsString],
    max_trace_bytes: usize,
    bundle: bool,
    duration_limit: Option<Duration>,
) -> Result<CaptureStage, RecordError> {
    let version = verify_strace_version(tracer)?;
    let mut output = (if bundle {
        super::AnchoredOutput::prepare_bundle(destination)
    } else {
        super::AnchoredOutput::prepare(destination)
    })
    .map_err(|error| {
        RecordError::before_launch(format!("could not prepare safe trace output: {error}"))
    })?;
    output.create_fifo().map_err(|error| {
        RecordError::before_launch(format!("could not create private trace FIFO: {error}"))
    })?;
    let fifo_path = PathBuf::from(output.fifo_path_for_child());
    let fifo_anchor = open_fifo_anchor(&fifo_path)?;
    let mut staged_trace = output.create_trace_file().map_err(|error| {
        RecordError::before_launch(format!(
            "could not create private trace staging file: {error}"
        ))
    })?;
    let _signal_guard = SignalGuard::install().map_err(|error| {
        RecordError::before_launch(format!(
            "could not install capture cancellation handlers: {error}"
        ))
    })?;

    let parent_pid = std::process::id() as libc::pid_t;
    let mut command = super::build_strace_command_for(tracer, &fifo_path, program, args);
    // SAFETY: this child-side hook uses only prctl/getppid and a raw OS error
    // to ensure that abrupt parent death cannot leave the tracer running.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let child = command
        .spawn()
        .map_err(|error| RecordError::before_launch(format!("could not start strace: {error}")))?;
    let mut child = TracerChild::new(child);

    let mut total = 0usize;
    let capture_started = Instant::now();
    let mut buffer = vec![0u8; READ_BUFFER_BYTES.min(max_trace_bytes.saturating_add(1))];
    let mut overflow = false;
    let mut time_limit_reached = false;
    let mut sink_error = None;
    let status = loop {
        let signal = CANCELLATION_SIGNAL.load(Ordering::Relaxed);
        if signal != 0 {
            let _ = child.kill_and_wait();
            return Err(RecordError::after_launch(format!(
                "capture interrupted by signal {signal}; the partial trace was discarded"
            )));
        }
        if duration_limit.is_some_and(|limit| capture_started.elapsed() >= limit) {
            time_limit_reached = true;
            break child.kill_and_wait().map_err(|error| {
                RecordError::after_launch(format!(
                    "could not stop strace after the capture time limit: {error}"
                ))
            })?;
        }
        let mut descriptor = libc::pollfd {
            fd: fifo_anchor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd for the duration of poll.
        let poll_result = unsafe { libc::poll(&mut descriptor, 1, POLL_INTERVAL_MS) };
        if poll_result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                let _ = child.kill_and_wait();
                return Err(RecordError::after_launch(format!(
                    "could not poll trace FIFO: {error}"
                )));
            }
        }

        match drain_available(
            fifo_anchor.as_raw_fd(),
            &mut staged_trace,
            &mut total,
            &mut buffer,
            max_trace_bytes,
        ) {
            Ok(DrainResult::Idle) => {}
            Ok(DrainResult::Overflow) => {
                overflow = true;
                break child.kill_and_wait().map_err(|error| {
                    RecordError::after_launch(format!(
                        "could not reap strace after trace limit: {error}"
                    ))
                })?;
            }
            Err(error) => {
                sink_error = Some(error);
                break child.kill_and_wait().map_err(|error| {
                    RecordError::after_launch(format!(
                        "could not reap strace after trace write failure: {error}"
                    ))
                })?;
            }
        }

        if let Some(status) = child.try_wait().map_err(|error| {
            let _ = child.kill_and_wait();
            RecordError::after_launch(format!("could not inspect strace status: {error}"))
        })? {
            // Drain records already queued when strace exited. No writer other
            // than strace has the FIFO path; our O_RDWR anchor makes EAGAIN the
            // normal drained state rather than depending on EOF timing.
            loop {
                match drain_available(
                    fifo_anchor.as_raw_fd(),
                    &mut staged_trace,
                    &mut total,
                    &mut buffer,
                    max_trace_bytes,
                ) {
                    Ok(DrainResult::Idle) => break,
                    Ok(DrainResult::Overflow) => overflow = true,
                    Err(error) => {
                        sink_error = Some(error);
                        break;
                    }
                }
            }
            break status;
        }
    };
    if time_limit_reached {
        loop {
            match drain_available(
                fifo_anchor.as_raw_fd(),
                &mut staged_trace,
                &mut total,
                &mut buffer,
                max_trace_bytes,
            ) {
                Ok(DrainResult::Idle) => break,
                Ok(DrainResult::Overflow) => overflow = true,
                Err(error) => {
                    sink_error = Some(error);
                    break;
                }
            }
        }
    }
    drop(fifo_anchor);

    if overflow {
        return Err(RecordError::after_launch(format!(
            "trace exceeded the {max_trace_bytes} byte limit; the capture was discarded and the tracer was terminated"
        )));
    }
    let signal = CANCELLATION_SIGNAL.load(Ordering::Relaxed);
    if signal != 0 {
        return Err(RecordError::after_launch(format!(
            "capture interrupted by signal {signal}; the partial trace was discarded"
        )));
    }
    if let Some(error) = sink_error {
        return Err(RecordError::after_launch(format!(
            "could not write bounded trace: {error}"
        )));
    }
    if total == 0 {
        return Err(RecordError::after_launch(format!(
            "strace produced no trace bytes (raw exit status: {}); it may be too old for --kill-on-exit, unsupported by this kernel, or unable to start tracing; no trace was published",
            status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string())
        )));
    }

    staged_trace
        .flush()
        .and_then(|()| staged_trace.sync_all())
        .map_err(|error| {
            RecordError::after_launch(format!("could not finalize staged trace: {error}"))
        })?;
    Ok(CaptureStage {
        output,
        status,
        bytes: total,
        version,
        trace_file: staged_trace,
        time_limit_reached,
    })
}

fn verify_strace_version(tracer: &OsStr) -> Result<StraceVersion, RecordError> {
    verify_strace_version_with_timeout(tracer, VERSION_QUERY_TIMEOUT)
}

fn verify_strace_version_with_timeout(
    tracer: &OsStr,
    query_timeout: Duration,
) -> Result<StraceVersion, RecordError> {
    let parent_pid = std::process::id() as libc::pid_t;
    let mut version_command = Command::new(tracer);
    version_command
        .arg("-V")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: use the same narrow parent-death guard as the tracing process;
    // the version query does not launch the user's target.
    unsafe {
        version_command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let deadline = Instant::now() + query_timeout;
    let mut child = loop {
        match version_command.spawn() {
            Ok(child) => break child,
            Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(RecordError::before_launch(format!(
                        "strace version check timed out after {query_timeout:?} while the executable remained busy; the command was not started"
                    )));
                }
                std::thread::sleep(
                    Duration::from_millis(POLL_INTERVAL_MS as u64).min(deadline - now),
                );
            }
            Err(error) => {
                return Err(RecordError::before_launch(format!(
                    "could not query strace version: {error}; the command was not started"
                )));
            }
        }
    };
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(RecordError::before_launch(
            "could not read strace version output; the command was not started",
        ));
    };
    let mut output = Vec::with_capacity(128);
    let mut buffer = [0u8; 512];
    let mut eof = false;
    let mut status = None;

    while !eof || status.is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RecordError::before_launch(format!(
                "strace version check timed out after {query_timeout:?}; the command was not started"
            )));
        }

        let poll_result = if eof {
            std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS as u64));
            0
        } else {
            let mut descriptor = libc::pollfd {
                fd: stdout.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: descriptor points to one initialized pollfd for the duration of poll.
            unsafe { libc::poll(&mut descriptor, 1, POLL_INTERVAL_MS) }
        };
        if poll_result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err(RecordError::before_launch(format!(
                "could not read strace version output: {error}"
            )));
        }

        if poll_result > 0 {
            let remaining = MAX_VERSION_OUTPUT_BYTES
                .saturating_add(1)
                .saturating_sub(output.len());
            let read_len = buffer.len().min(remaining.max(1));
            let count =
                std::io::Read::read(&mut stdout, &mut buffer[..read_len]).map_err(|error| {
                    let _ = child.kill();
                    let _ = child.wait();
                    RecordError::before_launch(format!(
                        "could not read strace version output: {error}; the command was not started"
                    ))
                })?;
            if count == 0 {
                eof = true;
            } else {
                output.extend_from_slice(&buffer[..count]);
                if output.len() > MAX_VERSION_OUTPUT_BYTES {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(RecordError::before_launch(format!(
                        "strace version output exceeds {MAX_VERSION_OUTPUT_BYTES} bytes; the command was not started"
                    )));
                }
            }
        }

        if status.is_none() {
            status = child.try_wait().map_err(|error| {
                let _ = child.kill();
                let _ = child.wait();
                RecordError::before_launch(format!(
                    "could not inspect strace version-check status: {error}"
                ))
            })?;
        }
    }

    let status = status.expect("loop exits only after the version process exits");
    if !status.success() {
        return Err(RecordError::before_launch(format!(
            "strace version check failed with status {}; the command was not started",
            status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string())
        )));
    }

    let version = parse_strace_version(&output).ok_or_else(|| {
        RecordError::before_launch(
            "could not recognize `strace -V` output; the command was not started",
        )
    })?;
    if version < MIN_STRACE_VERSION {
        return Err(RecordError::before_launch(format!(
            "SideEffect requires strace {}.{} or newer; found {}.{}; the command was not started",
            MIN_STRACE_VERSION.0, MIN_STRACE_VERSION.1, version.0, version.1
        )));
    }
    Ok(StraceVersion {
        major: version.0,
        minor: version.1,
    })
}

fn parse_strace_version(output: &[u8]) -> Option<(u64, u64)> {
    let text = std::str::from_utf8(output).ok()?;
    let version = text
        .lines()
        .find_map(|line| line.strip_prefix("strace -- version "))?;
    let mut components = version.trim().split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next()?.parse().ok()?;
    if components.any(|component| component.parse::<u64>().is_err()) {
        return None;
    }
    Some((major, minor))
}

enum DrainResult {
    Idle,
    Overflow,
}

fn drain_available(
    fifo_fd: i32,
    output: &mut File,
    total: &mut usize,
    buffer: &mut [u8],
    max_trace_bytes: usize,
) -> io::Result<DrainResult> {
    loop {
        // SAFETY: buffer is writable for its full length and fifo_fd is open.
        let count = unsafe { libc::read(fifo_fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(DrainResult::Idle);
            }
            return Err(error);
        }
        if count == 0 {
            return Ok(DrainResult::Idle);
        }
        let count = count as usize;
        let remaining = max_trace_bytes.saturating_sub(*total);
        let accepted = count.min(remaining);
        if accepted > 0 {
            output.write_all(&buffer[..accepted])?;
            *total = total
                .checked_add(accepted)
                .ok_or_else(|| io::Error::other("trace byte count overflow"))?;
        }
        if count > accepted {
            return Ok(DrainResult::Overflow);
        }
    }
}

fn open_fifo_anchor(path: &Path) -> Result<OwnedFd, RecordError> {
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| RecordError::before_launch("generated FIFO path contains a NUL byte"))?;
    // Linux permits an O_RDWR FIFO open without a peer. O_CLOEXEC prevents
    // the target command from inheriting the anchor and keeping the FIFO open.
    // SAFETY: path_c is NUL-terminated; returned fd is owned on success.
    let fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(RecordError::before_launch(format!(
            "could not open private trace FIFO: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: open returned a fresh descriptor owned by this function.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

struct TracerChild {
    child: Child,
    armed: bool,
}

impl TracerChild {
    fn new(child: Child) -> Self {
        Self { child, armed: true }
    }

    fn kill_and_wait(&mut self) -> io::Result<ExitStatus> {
        let _ = self.child.kill();
        let status = self.child.wait()?;
        self.armed = false;
        Ok(status)
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.armed = false;
        }
        Ok(status)
    }
}

impl Drop for TracerChild {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

extern "C" fn capture_signal_handler(signal: libc::c_int) {
    CANCELLATION_SIGNAL.store(signal, Ordering::Relaxed);
}

struct SignalGuard {
    old_actions: Vec<(libc::c_int, libc::sigaction)>,
    _lock: MutexGuard<'static, ()>,
}

impl SignalGuard {
    fn install() -> io::Result<Self> {
        let lock = SIGNAL_GUARD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        CANCELLATION_SIGNAL.store(0, Ordering::Relaxed);
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = capture_signal_handler as *const () as usize;
        action.sa_flags = 0;
        // SAFETY: action is initialized and sigemptyset mutates only its mask.
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let signals = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];
        let mut old_actions = Vec::with_capacity(signals.len());
        for signal in signals {
            let mut old_action: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: both action structures remain valid for this call.
            if unsafe { libc::sigaction(signal, &action, &mut old_action) } != 0 {
                for (installed_signal, previous) in old_actions.iter().rev() {
                    // SAFETY: restore the saved action for each successfully installed signal.
                    unsafe { libc::sigaction(*installed_signal, previous, std::ptr::null_mut()) };
                }
                return Err(io::Error::last_os_error());
            }
            old_actions.push((signal, old_action));
        }
        Ok(Self {
            old_actions,
            _lock: lock,
        })
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for (signal, old_action) in self.old_actions.iter().rev() {
            // SAFETY: restore the process's previous signal disposition.
            unsafe { libc::sigaction(*signal, old_action, std::ptr::null_mut()) };
        }
        CANCELLATION_SIGNAL.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_VERSION_OUTPUT_BYTES, RecordError, record_bundle_bounded, record_trace_bounded,
        verify_strace_version_with_timeout,
    };
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            loop {
                let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "sideeffect-record-test-{}-{id}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create test directory: {error}"),
                }
            }
        }

        fn fake_tracer(&self, script_body: &str) -> PathBuf {
            self.fake_tracer_version(script_body, "6.8")
        }

        fn fake_tracer_version(&self, script_body: &str, version: &str) -> PathBuf {
            self.fake_tracer_script(&format!(
                "#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then printf '%s\\n' 'strace -- version {version}'; exit 0; fi\n{script_body}\n"
            ))
        }

        fn fake_tracer_script(&self, script: &str) -> PathBuf {
            let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path = self.0.join(format!("fake-strace-{id}"));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .expect("create fake tracer");
            file.write_all(script.as_bytes())
                .expect("write fake tracer");
            let mut permissions = file.metadata().unwrap().permissions();
            permissions.set_mode(0o700);
            file.set_permissions(permissions)
                .expect("chmod fake tracer");
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn run_fake(
        directory: &TestDirectory,
        script_body: &str,
        output_name: &str,
        limit: usize,
    ) -> Result<super::RecordOutcome, RecordError> {
        run_fake_with_version(directory, script_body, output_name, limit, "6.8")
    }

    fn run_fake_with_version(
        directory: &TestDirectory,
        script_body: &str,
        output_name: &str,
        limit: usize,
        version: &str,
    ) -> Result<super::RecordOutcome, RecordError> {
        let tracer = directory.fake_tracer_version(script_body, version);
        record_trace_bounded(
            &directory.0.join(output_name),
            tracer.as_os_str(),
            OsStr::new("target-must-not-be-run-by-fake-tracer"),
            &[OsString::from("literal target arg")],
            limit,
        )
    }

    fn run_fake_with_duration(
        directory: &TestDirectory,
        script_body: &str,
        output_name: &str,
        limit: usize,
        duration: Duration,
    ) -> Result<super::RecordOutcome, RecordError> {
        let tracer = directory.fake_tracer(script_body);
        let mut capture = super::record_capture_bounded(
            &directory.0.join(output_name),
            tracer.as_os_str(),
            OsStr::new("target-must-not-be-run-by-fake-tracer"),
            &[],
            limit,
            false,
            Some(duration),
        )?;
        let final_path = capture.output.publish_trace().map_err(|error| {
            RecordError::after_launch(format!(
                "could not publish trace without replacing an existing path: {error}"
            ))
        })?;
        Ok(super::RecordOutcome {
            strace_status: capture.status,
            trace_path: final_path,
            trace_bytes: capture.bytes,
            time_limit_reached: capture.time_limit_reached,
        })
    }

    fn run_fake_bundle(
        directory: &TestDirectory,
        script_body: &str,
        output_name: &str,
        limit: usize,
    ) -> Result<super::RunBundleOutcome, RecordError> {
        let tracer = directory.fake_tracer(script_body);
        record_bundle_bounded(
            &directory.0.join(output_name),
            tracer.as_os_str(),
            OsStr::new("private-program-name"),
            &[OsString::from("private-argument-value")],
            limit,
            None,
        )
    }

    fn run_fake_bundle_with_duration(
        directory: &TestDirectory,
        script_body: &str,
        output_name: &str,
        limit: usize,
        duration: Duration,
    ) -> Result<super::RunBundleOutcome, RecordError> {
        let tracer = directory.fake_tracer(script_body);
        record_bundle_bounded(
            &directory.0.join(output_name),
            tracer.as_os_str(),
            OsStr::new("private-program-name"),
            &[OsString::from("private-argument-value")],
            limit,
            Some(duration),
        )
    }

    fn write_trace_script(bytes: &str) -> String {
        format!(
            "while [ \"$1\" != \"-o\" ]; do shift; done\nfifo=$2\nprintf '%b' '{}' > \"$fifo\"",
            bytes.replace('\'', "'\\''")
        )
    }

    #[test]
    fn publishes_exact_bounded_trace_with_private_permissions() {
        let directory = TestDirectory::new();
        let outcome = run_fake(
            &directory,
            &write_trace_script("close(1) = 0\\n"),
            "result.trace",
            64,
        )
        .unwrap();
        assert_eq!(outcome.trace_bytes, 13);
        assert_eq!(fs::read(&outcome.trace_path).unwrap(), b"close(1) = 0\n");
        assert_eq!(
            fs::metadata(&outcome.trace_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(outcome.strace_status.success());
    }

    #[test]
    fn duration_limit_publishes_partial_trace_and_reports_timeout() {
        let directory = TestDirectory::new();
        let started = Instant::now();
        let outcome = run_fake_with_duration(
            &directory,
            &format!("{}\nexec sleep 10", write_trace_script("close(1) = 0\\n")),
            "timed.trace",
            64,
            Duration::from_millis(100),
        )
        .unwrap();

        assert!(outcome.time_limit_reached);
        assert_eq!(outcome.strace_status.signal(), Some(libc::SIGKILL));
        assert_eq!(fs::read(&outcome.trace_path).unwrap(), b"close(1) = 0\n");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    }

    #[test]
    fn bundle_manifest_records_fixed_privacy_minimized_schema_hash_size_and_exit_code() {
        let directory = TestDirectory::new();
        let trace = b"close(1) = 0\n";
        let outcome = run_fake_bundle(
            &directory,
            &format!("{}\nexit 37", write_trace_script("close(1) = 0\\n")),
            "bundle.run",
            64,
        )
        .unwrap();
        assert_eq!(outcome.strace_status.code(), Some(37));
        let bundle = outcome.bundle_path;
        assert_eq!(fs::read_dir(&bundle).unwrap().count(), 2);
        assert_eq!(fs::read(bundle.join("trace.strace")).unwrap(), trace);
        let manifest_bytes = fs::read(bundle.join("run.json")).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(manifest["schema"], "sideeffect.run");
        assert_eq!(manifest["schema_version"], 2);
        assert_eq!(
            manifest["producer"]["sideeffect_version"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(manifest["producer"]["operating_system"], "linux");
        assert_eq!(manifest["producer"]["architecture"], "x86_64");
        assert_eq!(manifest["capture"]["tracer"]["name"], "strace");
        assert_eq!(manifest["capture"]["tracer"]["major"], 6);
        assert_eq!(manifest["capture"]["tracer"]["minor"], 8);
        assert_eq!(
            manifest["capture"]["capture_profile"],
            "linux_process_file_network_v1"
        );
        assert_eq!(
            manifest["capture"]["strace_reported_status"]["kind"],
            "exit_code"
        );
        assert_eq!(manifest["capture"]["strace_reported_status"]["value"], 37);
        assert_eq!(
            manifest["capture"]["command_outcome"],
            "not_independently_verified"
        );
        assert_eq!(manifest["capture"]["completeness"], "unknown");
        assert_eq!(
            manifest["capture"]["time_limit_milliseconds"],
            serde_json::Value::Null
        );
        assert_eq!(manifest["capture"]["stop_reason"], "tracer_exited");
        assert_eq!(
            manifest["capture"]["command_stdout"],
            "inherited_not_captured"
        );
        assert_eq!(
            manifest["capture"]["command_stderr"],
            "inherited_not_captured"
        );
        assert_eq!(
            manifest["capture"]["tracer_diagnostics"],
            "inherited_not_captured"
        );
        assert_eq!(manifest["trace"]["name"], "trace.strace");
        assert_eq!(manifest["trace"]["format"], "strace_text");
        assert_eq!(manifest["trace"]["byte_length"], trace.len());
        assert_eq!(
            manifest["trace"]["sha256"],
            crate::fingerprint::sha256_hex(trace)
        );
        let text = String::from_utf8(manifest_bytes).unwrap();
        for forbidden in [
            "private-program-name",
            "private-argument-value",
            "argv",
            "environment",
            "cwd",
            "username",
            "trace.raw",
        ] {
            assert!(!text.contains(forbidden), "manifest leaked {forbidden}");
        }
        assert_eq!(
            fs::metadata(&bundle).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(bundle.join("run.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(bundle.join("trace.strace"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn timed_bundle_marks_partial_capture_without_leaking_command_arguments() {
        let directory = TestDirectory::new();
        let outcome = run_fake_bundle_with_duration(
            &directory,
            &format!("{}\nexec sleep 10", write_trace_script("close(1) = 0\\n")),
            "timed.run",
            64,
            Duration::from_millis(100),
        )
        .unwrap();
        assert!(outcome.time_limit_reached);
        assert_eq!(outcome.strace_status.signal(), Some(libc::SIGKILL));
        let manifest_bytes = fs::read(outcome.bundle_path.join("run.json")).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(manifest["schema_version"], 2);
        assert_eq!(manifest["capture"]["time_limit_milliseconds"], 100);
        assert_eq!(manifest["capture"]["stop_reason"], "time_limit_reached");
        assert_eq!(manifest["capture"]["completeness"], "unknown");
        let text = String::from_utf8(manifest_bytes).unwrap();
        assert!(!text.contains("private-program-name"));
        assert!(!text.contains("private-argument-value"));
    }

    #[test]
    fn bundle_manifest_records_signal_status_and_overflow_discards_staging() {
        let directory = TestDirectory::new();
        let signal_script = format!("{}\nkill -TERM $$", write_trace_script("close(1) = 0\\n"));
        let outcome = run_fake_bundle(&directory, &signal_script, "signal.run", 64).unwrap();
        assert_eq!(outcome.strace_status.signal(), Some(libc::SIGTERM));
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(outcome.bundle_path.join("run.json")).unwrap())
                .unwrap();
        assert_eq!(
            manifest["capture"]["strace_reported_status"]["kind"],
            "signal"
        );
        assert_eq!(
            manifest["capture"]["strace_reported_status"]["value"],
            libc::SIGTERM
        );

        let error = run_fake_bundle(
            &directory,
            &write_trace_script("0123456789"),
            "overflow.run",
            4,
        )
        .unwrap_err();
        assert!(error.to_string().contains("exceeded the 4 byte limit"));
        assert!(!directory.0.join("overflow.run").exists());
        assert_eq!(
            fs::read_dir(&directory.0)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".sideeffect-capture-"))
                .count(),
            0
        );
    }

    #[test]
    fn exact_limit_succeeds_and_limit_plus_one_discards_output() {
        let exact = TestDirectory::new();
        let outcome = run_fake(&exact, &write_trace_script("12345678"), "exact.trace", 8).unwrap();
        assert_eq!(outcome.trace_bytes, 8);

        let over = TestDirectory::new();
        let error = run_fake(&over, &write_trace_script("123456789"), "over.trace", 8).unwrap_err();
        assert!(
            error.to_string().contains("exceeded the 8 byte limit"),
            "unexpected recorder error: {error}"
        );
        assert!(!over.0.join("over.trace").exists());
        assert_eq!(
            std::fs::read_dir(&over.0).unwrap().count(),
            1,
            "only the fake tracer remains; private staging is removed"
        );
    }

    #[test]
    fn existing_destination_and_symlink_are_never_replaced() {
        let directory = TestDirectory::new();
        let existing = directory.0.join("existing.trace");
        fs::write(&existing, b"keep me").unwrap();
        let error = run_fake(
            &directory,
            &write_trace_script("new data"),
            "existing.trace",
            64,
        )
        .unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(fs::read(&existing).unwrap(), b"keep me");

        let target = directory.0.join("symlink-target");
        fs::write(&target, b"symlink target stays").unwrap();
        let link = directory.0.join("linked.trace");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = run_fake(
            &directory,
            &write_trace_script("new data"),
            "linked.trace",
            64,
        )
        .unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(fs::read(&target).unwrap(), b"symlink target stays");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn destination_created_during_capture_is_not_overwritten() {
        let directory = TestDirectory::new();
        let destination = directory.0.join("raced.trace");
        let script = format!(
            "while [ \"$1\" != \"-o\" ]; do shift; done\nfifo=$2\nprintf 'concurrent writer' > '{}'\nprintf 'captured\\n' > \"$fifo\"",
            destination.display()
        );
        let error = run_fake(&directory, &script, "raced.trace", 64).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("without replacing an existing path"),
            "unexpected recorder error: {error}"
        );
        assert_eq!(fs::read(&destination).unwrap(), b"concurrent writer");
        assert_eq!(
            fs::read_dir(&directory.0).unwrap().count(),
            2,
            "fake tracer and concurrent destination remain; private staging is removed"
        );
    }

    #[test]
    fn missing_tracer_does_not_publish_or_leave_staging_directory() {
        let directory = TestDirectory::new();
        let error = record_trace_bounded(
            &directory.0.join("missing.trace"),
            Path::new("/path/with/no/strace").as_os_str(),
            OsStr::new("not-run"),
            &[],
            64,
        )
        .unwrap_err();
        assert!(error.to_string().contains("could not query strace version"));
        assert!(error.to_string().contains("the command was not started"));
        assert!(!directory.0.join("missing.trace").exists());
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
    }

    #[test]
    fn older_strace_is_rejected_before_output_staging_or_target_launch() {
        let directory = TestDirectory::new();
        let target_marker = directory.0.join("target-was-started");
        let escaped_marker = target_marker.to_string_lossy().replace('\'', "'\\''");
        let error = run_fake_with_version(
            &directory,
            &format!("touch '{escaped_marker}'"),
            "old.trace",
            64,
            "6.7",
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("SideEffect requires strace 6.8 or newer")
        );
        assert!(error.to_string().contains("the command was not started"));
        assert!(!directory.0.join("old.trace").exists());
        assert!(!directory.0.join("target-was-started").exists());
        assert_eq!(
            fs::read_dir(&directory.0).unwrap().count(),
            1,
            "only the fake tracer remains; output staging was not created"
        );
    }

    #[test]
    fn strace_version_parser_rejects_unknown_and_accepts_numeric_versions() {
        assert_eq!(
            super::parse_strace_version(b"strace -- version 6.8\n"),
            Some((6, 8))
        );
        assert_eq!(
            super::parse_strace_version(b"strace -- version 7.0.1\n"),
            Some((7, 0))
        );
        assert_eq!(
            super::parse_strace_version(b"strace version unknown\n"),
            None
        );
        assert_eq!(
            super::parse_strace_version(b"strace -- version 6.x\n"),
            None
        );
    }

    #[test]
    fn unrecognized_successful_version_is_rejected_before_target_launch() {
        let directory = TestDirectory::new();
        let target_marker = directory.0.join("target-was-started");
        let escaped_marker = target_marker.to_string_lossy().replace('\'', "'\\''");
        let error = run_fake_with_version(
            &directory,
            &format!("touch '{escaped_marker}'"),
            "unknown.trace",
            64,
            "unknown",
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("could not recognize `strace -V` output"),
            "unexpected recorder error: {error}"
        );
        assert!(
            error.to_string().contains("the command was not started"),
            "unexpected recorder error: {error}"
        );
        assert!(!target_marker.exists());
        assert!(!directory.0.join("unknown.trace").exists());
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    fn oversized_version_output_is_rejected_before_target_launch() {
        let directory = TestDirectory::new();
        let target_marker = directory.0.join("target-was-started");
        let escaped_marker = target_marker.to_string_lossy().replace('\'', "'\\''");
        let oversized = format!("6.8.{}", "0".repeat(MAX_VERSION_OUTPUT_BYTES));
        let error = run_fake_with_version(
            &directory,
            &format!("touch '{escaped_marker}'"),
            "oversized.trace",
            64,
            &oversized,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("strace version output exceeds 4096 bytes")
        );
        assert!(error.to_string().contains("the command was not started"));
        assert!(!target_marker.exists());
        assert!(!directory.0.join("oversized.trace").exists());
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    fn version_query_eof_waits_until_bounded_timeout() {
        let directory = TestDirectory::new();
        let tracer = directory.fake_tracer_script(
            "#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then exec 1>&-; exec /bin/sleep 10; fi\nexit 1\n",
        );
        let started = Instant::now();
        let error =
            verify_strace_version_with_timeout(tracer.as_os_str(), Duration::from_millis(150))
                .unwrap_err();

        assert!(error.to_string().contains("version check timed out"));
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn version_query_retries_while_tracer_executable_is_write_locked() {
        let directory = TestDirectory::new();
        let tracer = directory.fake_tracer_script(
            "#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then printf '%s\\n' 'strace -- version 6.8'; exit 0; fi\nexit 1\n",
        );
        let writer = OpenOptions::new()
            .write(true)
            .open(&tracer)
            .expect("hold tracer open for writing");
        let release_writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(125));
            drop(writer);
        });

        let started = Instant::now();
        let version =
            verify_strace_version_with_timeout(tracer.as_os_str(), Duration::from_secs(2))
                .expect("version query retries until the transient write lock is released");
        release_writer.join().unwrap();

        assert_eq!((version.major, version.minor), (6, 8));
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn signal_cancellation_reaps_tracer_and_discards_staging() {
        let directory = TestDirectory::new();
        let marker = directory.0.join("tracer.pid");
        let script = format!(
            "while [ \"$1\" != \"-o\" ]; do shift; done\nfifo=$2\nprintf 'close(1) = 0\\n' > \"$fifo\"\nprintf '%s\\n' \"$$\" > '{}'\nexec /bin/sleep 30",
            marker.display()
        );
        let tracer = directory.fake_tracer(&script);
        let helper = std::env::current_exe().expect("test executable");
        let mut child = Command::new(helper)
            .arg("--exact")
            .arg("record::linux::tests::signal_cancel_helper_process")
            .arg("--nocapture")
            .env("SIDE_EFFECT_CANCEL_TEST_DIR", &directory.0)
            .env("SIDE_EFFECT_CANCEL_TEST_TRACER", &tracer)
            .spawn()
            .expect("spawn isolated cancellation test process");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !marker.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(marker.exists(), "fake tracer did not start in time");
        let tracer_pid: libc::pid_t = fs::read_to_string(&marker).unwrap().trim().parse().unwrap();
        // SAFETY: send SIGTERM only to the isolated helper process created above.
        assert_eq!(
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
            0
        );
        let status = child
            .wait()
            .expect("wait for isolated cancellation process");
        assert!(status.success(), "cancellation helper failed with {status}");
        // SAFETY: signal 0 only checks whether the recorded fake-tracer PID remains alive.
        assert_eq!(
            unsafe { libc::kill(tracer_pid, 0) },
            -1,
            "fake tracer survived cancellation"
        );
        assert!(!directory.0.join("cancel.run").exists());
        assert_eq!(
            fs::read_dir(&directory.0).unwrap().count(),
            2,
            "fake tracer and marker remain; private staging was cleaned"
        );
    }

    #[test]
    fn signal_cancel_helper_process() {
        let (Ok(directory), Ok(tracer)) = (
            std::env::var("SIDE_EFFECT_CANCEL_TEST_DIR"),
            std::env::var("SIDE_EFFECT_CANCEL_TEST_TRACER"),
        ) else {
            return;
        };
        let error = record_bundle_bounded(
            &Path::new(&directory).join("cancel.run"),
            OsStr::new(&tracer),
            OsStr::new("must-not-be-run-by-fake-tracer"),
            &[],
            64,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("capture interrupted by signal"));
        assert!(!Path::new(&directory).join("cancel.trace").exists());
    }
}
