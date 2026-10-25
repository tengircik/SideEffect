mod command;
#[cfg(target_os = "linux")]
mod paths;

#[cfg(target_os = "linux")]
mod linux;

pub use command::build_strace_command;
#[cfg(target_os = "linux")]
pub(crate) use command::build_strace_command_for;
#[cfg(target_os = "linux")]
pub use paths::{AnchoredOutput, publish_private_file};

#[cfg(target_os = "linux")]
pub use linux::{RecordError, RecordOutcome, RunBundleOutcome, record_bundle, record_trace};
