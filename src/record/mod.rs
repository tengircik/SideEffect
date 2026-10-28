mod command;
#[cfg(target_os = "linux")]
mod paths;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod windows_etw;

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
pub use windows_etw::{
    CollectionStatus as WindowsRuntimeCollectionStatus, DecodeStatus as WindowsRuntimeDecodeStatus,
    DecodedProcessPayload as WindowsDecodedProcessPayload, WindowsRuntimeCapture,
    record_windows_process_capture,
};

#[cfg(target_os = "linux")]
pub use linux::{
    RecordError, RecordOutcome, RunBundleArtifacts, RunBundleOutcome, record_bundle,
    record_bundle_artifacts, record_bundle_with_duration, record_trace, record_trace_with_duration,
};
