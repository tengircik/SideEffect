//! Narrow bounded runtime-version probing for the local-model doctor.
//!
//! This API never accepts caller-supplied arguments: it executes only the
//! selected runtime's `--version` command on Linux x86_64 and returns bounded
//! output for task-specific parsing by the caller.

/// Bounded result from the fixed runtime `--version` invocation.
///
/// Output bytes are untrusted runtime-provided text. Each stream is capped at
/// 16 KiB. Callers should parse only the expected version contract and should
/// not display or execute returned text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedVersionOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr: Vec<u8>,
    pub stderr_truncated: bool,
}

/// Run only `<runtime> --version` with a 10-second timeout and 16 KiB output
/// limit per stream. The runtime is executable code running as the current
/// user; this API does not sandbox it or authenticate its publisher.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn check_runtime_version(
    runtime_path: &std::path::Path,
) -> Result<BoundedVersionOutput, String> {
    use std::ffi::OsString;

    let canonical = runtime_path
        .canonicalize()
        .map_err(|_| "runtime path is missing or inaccessible".to_owned())?;
    if !std::fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_file()) {
        return Err("runtime path is not a regular file".to_owned());
    }

    let output = crate::local_model_runtime::run_bounded(
        &canonical,
        &[OsString::from("--version")],
        None,
        10,
        16 * 1024,
    )
    .map_err(|_| {
        "runtime --version check could not complete within the bounded runner".to_owned()
    })?;

    Ok(BoundedVersionOutput {
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout: output.stdout.bytes,
        stdout_truncated: output.stdout.truncated,
        stderr: output.stderr.bytes,
        stderr_truncated: output.stderr.truncated,
    })
}
