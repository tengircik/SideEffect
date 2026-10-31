mod command;
#[cfg(target_os = "linux")]
mod paths;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod windows_etw;
#[cfg(windows)]
mod windows_io_decode;

#[cfg(target_os = "linux")]
mod linux;

pub use command::build_strace_command;
#[cfg(target_os = "linux")]
pub(crate) use command::build_strace_command_for;
#[cfg(target_os = "linux")]
pub use paths::{AnchoredOutput, SessionOutput, publish_private_file};
#[cfg(windows)]
pub use windows::publish_private_directory as publish_private_windows_directory;
#[cfg(windows)]
pub use windows::publish_private_file as publish_private_windows_file;
#[cfg(windows)]
pub(crate) use windows_etw::collect_windows_runtime_capture_before_launch;
#[cfg(windows)]
pub use windows_etw::{
    CollectionStatus as WindowsRuntimeCollectionStatus, DecodeStatus as WindowsRuntimeDecodeStatus,
    DecodedProcessPayload as WindowsDecodedProcessPayload, StopReason as WindowsRuntimeStopReason,
    WindowsRuntimeCapture, record_windows_runtime_capture,
};
#[cfg(windows)]
pub(crate) use windows_etw::{
    NetworkPayloadCrossCheck, NetworkPayloadInput, cross_check_network_payload,
};

#[cfg(target_os = "linux")]
pub use linux::{
    RecordError, RecordOutcome, RunBundleArtifacts, RunBundleOutcome, record_bundle,
    record_bundle_artifacts, record_bundle_with_duration, record_trace, record_trace_with_duration,
};
