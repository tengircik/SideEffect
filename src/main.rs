use std::env;
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

#[cfg(target_os = "linux")]
use serde::Deserialize;
use serde::Serialize;
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use sideeffect::diff::compare_traces;
use sideeffect::explain::{explain_diff, explain_trace};
#[cfg(target_os = "linux")]
use sideeffect::format::write_html_diff;
#[cfg(target_os = "linux")]
use sideeffect::format::write_html_summary;
use sideeffect::format::{
    RedactedDiffSummary, summarize_diff, write_text_diff, write_trace_evidence_text,
};
#[cfg(target_os = "linux")]
use sideeffect::inventory::{InventoryStatus, collect_packages};
use sideeffect::inventory::{PackageComparisonStatus, compare_package_inventory_json};
#[cfg(target_os = "linux")]
use sideeffect::inventory::{PermissionInventoryStatus, collect_permissions};
#[cfg(target_os = "linux")]
use sideeffect::inventory::{ProcessInventoryStatus, collect_processes};
#[cfg(target_os = "linux")]
use sideeffect::inventory::{StartupInventoryStatus, collect_startup};
#[cfg(windows)]
use sideeffect::inventory::{WindowsProcessInventoryStatus, collect_windows_processes};
#[cfg(windows)]
use sideeffect::inventory::{WindowsStartupStatus, collect_windows_startup};
#[cfg(target_os = "linux")]
use sideeffect::limits::MAX_BUNDLE_MANIFEST_BYTES;
use sideeffect::limits::{MAX_REPORT_BYTES, MAX_TRACE_BYTES, ParseLimits};
use sideeffect::model::{BundleCaptureContext, ParseCompleteness, TraceDiff, TraceRecordKind};
#[cfg(target_os = "linux")]
use sideeffect::record::AnchoredOutput;
#[cfg(target_os = "linux")]
use sideeffect::record::publish_private_file;
#[cfg(windows)]
use sideeffect::record::publish_private_windows_file;
use sideeffect::startup_correlation::correlate_startup_bytes;
use sideeffect::trace::strace::parse_trace_bytes;

const USAGE: &str = "Usage: sideeffect inspect [--format json|text] <strace-trace-file>\n       sideeffect inspect [--format json|text] --bundle <run-bundle-directory>\n       sideeffect evidence <strace-trace-file> <sha256> <line> <byte-offset> <byte-length>\n       sideeffect diff [--format json|text] <baseline-trace> <candidate-trace>\n       sideeffect diff --format html --output <report.html> <baseline-trace> <candidate-trace>\n       sideeffect diff --bundles [--format json|text] <baseline-bundle> <candidate-bundle>\n       sideeffect diff --bundles --format html --output <report.html> <baseline-bundle> <candidate-bundle>\n       sideeffect diff-summary [--format json] <baseline-trace> <candidate-trace>\n       sideeffect diff-summary --format html --output <summary.html> <baseline-trace> <candidate-trace>\n       sideeffect inventory packages --output <new-inventory.json>\n\
       sideeffect explain <strace-trace-file>\n\
       sideeffect explain --diff <baseline-trace> <candidate-trace>\n\
       sideeffect explain --inventory-diff <before.json> <after.json>\n\
       sideeffect model-preview --question <question> <strace-trace-file>\n\
       sideeffect model-analyze --question <question> --runtime <llama-cli> --model <model.gguf> --confirm-sha256 <preview-digest> <strace-trace-file>\n\
       sideeffect correlate-startup <startup-inventory.json> <strace-trace-file>\n\
       sideeffect inventory processes --output <new-inventory.json>\n\
       sideeffect inventory startup --output <new-inventory.json>\n\
       sideeffect inventory permissions --output <new-inventory.json> <path>...\n\
       sideeffect record --trace <new-trace-file> -- <program> [args...]\n       sideeffect record --bundle <new-bundle-directory> -- <program> [args...]\n       sideeffect record --trace <new-trace-file> --duration-seconds <1..3600> -- <program> [args...]\n       sideeffect record --bundle <new-bundle-directory> --duration-seconds <1..3600> -- <program> [args...]\n       sideeffect help [command [subcommand]]\n       sideeffect version\n       sideeffect --help\n       sideeffect --version\n\nInspect reads one bounded strace text file or a validated local run bundle and writes JSON evidence by default, or terminal-safe text with --format text. Evidence verifies the supplied SHA-256 fingerprint, then checks an exact line/byte/length tuple against one parsed row. The fingerprint identifies bytes but does not authenticate them or prove capture completeness. Diff compares two complete parsed traces, or validates two local run bundles with --bundles, and writes observed syscall-row differences to stdout (JSON by default), or a local offline HTML report on Linux. Diff-summary creates a separate aggregate-only export and omits event strings, hashes, and evidence references; counts/category patterns can still be sensitive, and this is not a safe-to-share verdict. Inventory packages reads available local dpkg, RPM, pacman, and APK databases and saves a private JSON snapshot; unsupported, unavailable, or incomplete sources remain visible, and unregistered software may be missed. On Linux, inventory processes reads bounded numeric /proc status entries and executable-link identities; on Windows, it reads a Tool Help snapshot and queries accessible image paths. Neither adapter reads command lines or promises atomic or exhaustive coverage. On Linux, inventory startup discovers curated sources; on Windows, it inventories selected Run/RunOnce values and Startup folder entries while marking service/task sources not checked. Neither platform establishes that a configured entry ran. Inventory permissions inspects only explicit Linux paths and records ownership/type/mode, supported POSIX ACLs, and Linux file-capability xattrs; it never follows the final path symlink or calculates effective access. Record follows a selected command's traced descendants and may enforce a requested wall-clock limit; this is observation, not isolation or a safety check.";

fn main() -> ExitCode {
    match run(env::args_os().skip(1).collect()) {
        Ok(code) => code,
        Err(message) => {
            let _ = writeln!(io::stderr().lock(), "sideeffect: {message}");
            ExitCode::from(1)
        }
    }
}

fn run(arguments: Vec<OsString>) -> Result<ExitCode, String> {
    match arguments.as_slice() {
        [flag] if flag == "--help" || flag == "-h" => {
            println!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        [flag] if flag == "--version" => {
            print_version();
            Ok(ExitCode::SUCCESS)
        }
        [command] if command == "version" => {
            print_version();
            Ok(ExitCode::SUCCESS)
        }
        [command] if command == "help" => command_help(&[]),
        [command, topic] if command == "help" => command_help(std::slice::from_ref(topic)),
        [command, topic, subtopic] if command == "help" => {
            command_help(&[topic.clone(), subtopic.clone()])
        }
        [command, flag] if flag == "--help" || flag == "-h" => {
            command_help(std::slice::from_ref(command))
        }
        [command, subcommand, flag] if flag == "--help" || flag == "-h" => {
            command_help(&[command.clone(), subcommand.clone()])
        }
        [command, path] if command == "inspect" => inspect(path),
        [command, path] if command == "explain" => explain_trace_file(path),
        [command, question_flag, question, path]
            if command == "model-preview" && question_flag == "--question" =>
        {
            model_preview_file(question, path)
        }
        [
            command,
            question_flag,
            question,
            runtime_flag,
            runtime,
            model_flag,
            model,
            confirm_flag,
            digest,
            trace,
        ] if command == "model-analyze"
            && question_flag == "--question"
            && runtime_flag == "--runtime"
            && model_flag == "--model"
            && confirm_flag == "--confirm-sha256" =>
        {
            model_analyze_file(question, runtime, model, digest, trace)
        }
        [command, diff_flag, left, right] if command == "explain" && diff_flag == "--diff" => {
            explain_diff_files(left, right)
        }
        [command, diff_flag, before, after]
            if command == "explain" && diff_flag == "--inventory-diff" =>
        {
            explain_inventory_diff_files(before, after)
        }
        [command, startup_path, trace_path] if command == "correlate-startup" => {
            correlate_startup(startup_path, trace_path)
        }
        [command, subcommand, option, output]
            if command == "inventory" && subcommand == "packages" && option == "--output" =>
        {
            inventory_packages(output)
        }
        [command, subcommand, option, output]
            if command == "inventory" && subcommand == "processes" && option == "--output" =>
        {
            inventory_processes(output)
        }
        [command, subcommand, option, output]
            if command == "inventory" && subcommand == "startup" && option == "--output" =>
        {
            inventory_startup(output)
        }
        [command, subcommand, option, output, paths @ ..]
            if command == "inventory"
                && subcommand == "permissions"
                && option == "--output"
                && !paths.is_empty() =>
        {
            inventory_permissions(output, paths)
        }
        [command, flag, path] if command == "inspect" && flag == "--bundle" => {
            inspect_bundle_with_format(&OsString::from("json"), path)
        }
        [command, flag, format, path] if command == "inspect" && flag == "--format" => {
            inspect_with_format(format, path)
        }
        [command, format_flag, format, bundle_flag, path]
            if command == "inspect" && format_flag == "--format" && bundle_flag == "--bundle" =>
        {
            inspect_bundle_with_format(format, path)
        }
        [command, path, digest, line, byte_offset, byte_length] if command == "evidence" => {
            evidence(path, digest, line, byte_offset, byte_length)
        }
        [command, left, right] if command == "diff" => diff(left, right),
        [command, bundles_flag, left, right]
            if command == "diff" && bundles_flag == "--bundles" =>
        {
            diff_bundles(left, right)
        }
        [command, left, right] if command == "diff-summary" => diff_summary_json(left, right),
        [command, format_flag, format, left, right]
            if command == "diff-summary" && format_flag == "--format" && format == "json" =>
        {
            diff_summary_json(left, right)
        }
        [
            command,
            format_flag,
            format,
            output_flag,
            output,
            left,
            right,
        ] if command == "diff-summary"
            && format_flag == "--format"
            && format == "html"
            && output_flag == "--output" =>
        {
            diff_summary_html(output, left, right)
        }
        [command, flag, format, left, right] if command == "diff" && flag == "--format" => {
            diff_with_format(format, left, right)
        }
        [command, bundles_flag, flag, format, left, right]
            if command == "diff" && bundles_flag == "--bundles" && flag == "--format" =>
        {
            diff_bundles_with_format(format, left, right)
        }
        [
            command,
            format_flag,
            format,
            output_flag,
            output,
            left,
            right,
        ] if command == "diff"
            && format_flag == "--format"
            && format == "html"
            && output_flag == "--output" =>
        {
            diff_html(output, left, right)
        }
        [
            command,
            bundles_flag,
            format_flag,
            format,
            output_flag,
            output,
            left,
            right,
        ] if command == "diff"
            && bundles_flag == "--bundles"
            && format_flag == "--format"
            && format == "html"
            && output_flag == "--output" =>
        {
            diff_bundles_html(output, left, right)
        }
        [
            command,
            option,
            output,
            duration_flag,
            duration,
            separator,
            program,
            target_args @ ..,
        ] if command == "record"
            && option == "--trace"
            && duration_flag == "--duration-seconds"
            && separator == "--" =>
        {
            let duration = parse_duration_seconds(duration)?;
            record_with_duration(output, program, target_args, Some(duration))
        }
        [
            command,
            option,
            output,
            duration_flag,
            duration,
            separator,
            program,
            target_args @ ..,
        ] if command == "record"
            && option == "--bundle"
            && duration_flag == "--duration-seconds"
            && separator == "--" =>
        {
            let duration = parse_duration_seconds(duration)?;
            record_bundle_with_duration_command(output, program, target_args, Some(duration))
        }
        [
            command,
            option,
            output,
            separator,
            program,
            target_args @ ..,
        ] if command == "record" && option == "--trace" && separator == "--" => {
            record_with_duration(output, program, target_args, None)
        }
        [
            command,
            option,
            output,
            separator,
            program,
            target_args @ ..,
        ] if command == "record" && option == "--bundle" && separator == "--" => {
            record_bundle_with_duration_command(output, program, target_args, None)
        }
        [command, ..] if command == "record" => Err(USAGE.to_owned()),
        [command, ..] if command == "inventory" => Err(USAGE.to_owned()),
        _ => Err(USAGE.to_owned()),
    }
}

fn inventory_packages(output: &OsString) -> Result<ExitCode, String> {
    #[cfg(target_os = "linux")]
    {
        let document = collect_packages();
        let complete = document.status == InventoryStatus::Complete;
        let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
        serde_json::to_writer(&mut json, &document).map_err(|error| {
            format!(
                "could not serialize inventory within the {MAX_REPORT_BYTES} byte limit: {error}"
            )
        })?;
        let published = publish_private_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
            .map_err(|error| format!("could not publish private inventory: {error}"))?;
        if complete {
            eprintln!(
                "Saved a complete snapshot of detected, applicable package-manager databases to {}. This is a point-in-time source inventory, not a complete list of software on the computer.",
                terminal_safe_path(&published)
            );
            Ok(ExitCode::SUCCESS)
        } else {
            eprintln!(
                "Saved a partial package-manager snapshot to {}. Check its source status and diagnostics; unavailable or incomplete package data must be treated as unknown.",
                terminal_safe_path(&published)
            );
            Ok(ExitCode::from(2))
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = output;
        Err("inventory packages requires Linux package-manager sources".to_owned())
    }
}

fn inventory_processes(output: &OsString) -> Result<ExitCode, String> {
    #[cfg(target_os = "linux")]
    {
        let document = collect_processes();
        let complete = document.status == ProcessInventoryStatus::Complete;
        let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
        serde_json::to_writer(&mut json, &document).map_err(|error| format!("could not serialize process inventory within the {MAX_REPORT_BYTES} byte limit: {error}"))?;
        let published = publish_private_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
            .map_err(|error| format!("could not publish private process inventory: {error}"))?;
        if complete {
            eprintln!(
                "Saved a complete /proc status snapshot to {}. This is a non-atomic point-in-time observation, not exhaustive system coverage.",
                terminal_safe_path(&published)
            );
            Ok(ExitCode::SUCCESS)
        } else {
            eprintln!(
                "Saved a partial /proc status snapshot to {}. Check its diagnostics; unreadable or unobserved process data is unknown.",
                terminal_safe_path(&published)
            );
            Ok(ExitCode::from(2))
        }
    }
    #[cfg(windows)]
    {
        let document = collect_windows_processes();
        let complete = document.status == WindowsProcessInventoryStatus::Complete;
        let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
        serde_json::to_writer(&mut json, &document).map_err(|error| {
            format!("could not serialize Windows process inventory within the {MAX_REPORT_BYTES} byte limit: {error}")
        })?;
        let published =
            publish_private_windows_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
                .map_err(|error| {
                    format!("could not publish private Windows process inventory: {error}")
                })?;
        if complete {
            eprintln!(
                "Saved a Windows Tool Help process snapshot to {}. Process paths may be inaccessible, and the snapshot is non-atomic and not exhaustive.",
                terminal_safe_path(&published)
            );
            Ok(ExitCode::SUCCESS)
        } else {
            eprintln!(
                "Saved a partial Windows process snapshot to {}. Check its diagnostics; inaccessible or unobserved process data is unknown.",
                terminal_safe_path(&published)
            );
            Ok(ExitCode::from(2))
        }
    }
    #[cfg(not(target_os = "linux"))]
    #[cfg(not(windows))]
    {
        let _ = output;
        Err("inventory processes is not supported on this platform".to_owned())
    }
}

fn inventory_startup(output: &OsString) -> Result<ExitCode, String> {
    #[cfg(target_os = "linux")]
    {
        let document = collect_startup();
        let complete = document.status == StartupInventoryStatus::Complete;
        let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
        serde_json::to_writer(&mut json, &document)
            .map_err(|e| format!("could not serialize startup inventory: {e}"))?;
        let path = publish_private_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
            .map_err(|e| format!("could not publish private startup inventory: {e}"))?;
        eprintln!(
            "Saved a {} curated startup-configuration snapshot to {}. It includes bounded XDG, systemd, SysV, and cron sources; commands are inert evidence, applicability and execution are not inferred, and unobserved sources remain unknown.",
            if complete { "complete" } else { "partial" },
            terminal_safe_path(&path)
        );
        Ok(if complete {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        })
    }
    #[cfg(not(target_os = "linux"))]
    #[cfg(not(windows))]
    {
        let _ = output;
        Err("inventory startup is not supported on this platform".to_owned())
    }
    #[cfg(windows)]
    {
        let document = collect_windows_startup();
        let complete = document.status == WindowsStartupStatus::Complete;
        let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
        serde_json::to_writer(&mut json, &document).map_err(|error| {
            format!("could not serialize Windows startup inventory within the {MAX_REPORT_BYTES} byte limit: {error}")
        })?;
        let path = publish_private_windows_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
            .map_err(|error| {
            format!("could not publish private Windows startup inventory: {error}")
        })?;
        eprintln!(
            "Saved a {} Windows startup-configuration snapshot to {}. It covers current-user and accessible machine Run/RunOnce keys plus current/common Startup folders; commands are inert, and service/task sources remain not checked.",
            if complete { "complete" } else { "partial" },
            terminal_safe_path(&path)
        );
        Ok(if complete {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        })
    }
}

fn inventory_permissions(output: &OsString, paths: &[OsString]) -> Result<ExitCode, String> {
    #[cfg(target_os = "linux")]
    {
        let paths = paths
            .iter()
            .map(Path::new)
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        let document = collect_permissions(&paths);
        let complete = document.status == PermissionInventoryStatus::Complete;
        let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
        serde_json::to_writer(&mut json, &document).map_err(|error| {
            format!("could not serialize permission inventory within the {MAX_REPORT_BYTES} byte limit: {error}")
        })?;
        let published = publish_private_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
            .map_err(|error| format!("could not publish private permission inventory: {error}"))?;
        eprintln!(
            "Saved a {} explicit-path permission snapshot to {}. It records metadata and supported POSIX ACLs; effective access was not evaluated.",
            if complete { "complete" } else { "partial" },
            terminal_safe_path(&published)
        );
        Ok(if complete {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (output, paths);
        Err("inventory permissions currently supports Linux paths only".to_owned())
    }
}

fn parse_duration_seconds(value: &OsString) -> Result<Duration, String> {
    let Some(text) = value.to_str() else {
        return Err("capture duration must be an ASCII integer from 1 to 3600 seconds".to_owned());
    };
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("capture duration must be an ASCII integer from 1 to 3600 seconds".to_owned());
    }
    let seconds = text
        .parse::<u64>()
        .map_err(|_| "capture duration must be an ASCII integer from 1 to 3600 seconds")?;
    if !(1..=3600).contains(&seconds) {
        return Err("capture duration must be from 1 to 3600 seconds".to_owned());
    }
    Ok(Duration::from_secs(seconds))
}

fn record_with_duration(
    output: &OsString,
    program: &OsString,
    args: &[OsString],
    duration: Option<Duration>,
) -> Result<ExitCode, String> {
    #[cfg(target_os = "linux")]
    {
        let outcome = sideeffect::record::record_trace_with_duration(
            Path::new(output),
            program,
            args,
            duration,
        )
        .map_err(|error| error.to_string())?;
        if outcome.time_limit_reached {
            eprintln!(
                "Capture time limit reached after {} seconds. A bounded partial trace was published to {}; target outcome and capture completeness are unknown.",
                duration.map_or(0, |value| value.as_secs()),
                terminal_safe_path(&outcome.trace_path)
            );
            return Ok(ExitCode::from(2));
        }
        let status = outcome.strace_status;
        if let Some(code) = status.code() {
            eprintln!(
                "Recorded {} bytes to {}. strace-reported and propagated exit status: {} (strace normally mirrors the wrapped command; this does not prove tracer success or capture completeness).",
                outcome.trace_bytes,
                terminal_safe_path(&outcome.trace_path),
                code
            );
            Ok(ExitCode::from(code as u8))
        } else if let Some(signal) = status.signal() {
            eprintln!(
                "Recorded {} bytes to {}. strace-reported termination by signal {} is being propagated (strace normally mirrors the wrapped command; this does not prove tracer success or capture completeness).",
                outcome.trace_bytes,
                terminal_safe_path(&outcome.trace_path),
                signal
            );
            Ok(propagate_signal(signal))
        } else {
            eprintln!(
                "Recorded {} bytes to {}. strace returned an unavailable exit status; using failure status 1.",
                outcome.trace_bytes,
                terminal_safe_path(&outcome.trace_path)
            );
            Ok(ExitCode::from(1))
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (output, program, args, duration);
        Err("record is available only on Linux with an external strace executable".to_owned())
    }
}

fn record_bundle_with_duration_command(
    output: &OsString,
    program: &OsString,
    args: &[OsString],
    duration: Option<Duration>,
) -> Result<ExitCode, String> {
    #[cfg(target_os = "linux")]
    {
        let outcome = sideeffect::record::record_bundle_with_duration(
            Path::new(output),
            program,
            args,
            duration,
        )
        .map_err(|error| error.to_string())?;
        if !outcome.parent_directory_sync_confirmed {
            eprintln!(
                "Warning: bundle {} was atomically published, but syncing its parent directory failed; persistence across sudden power loss is uncertain.",
                terminal_safe_path(&outcome.bundle_path)
            );
        }
        if outcome.time_limit_reached {
            eprintln!(
                "Capture time limit reached after {} seconds. Published partial evidence in {}; target outcome and capture completeness are unknown.",
                duration.map_or(0, |value| value.as_secs()),
                terminal_safe_path(&outcome.bundle_path)
            );
            return Ok(ExitCode::from(2));
        }
        let status = outcome.strace_status;
        if let Some(code) = status.code() {
            eprintln!(
                "Recorded {} bytes in bundle {}. strace-reported and propagated exit status: {} (command outcome is not independently verified; capture completeness is unknown).",
                outcome.trace_bytes,
                terminal_safe_path(&outcome.bundle_path),
                code
            );
            Ok(ExitCode::from(code as u8))
        } else if let Some(signal) = status.signal() {
            eprintln!(
                "Recorded {} bytes in bundle {}. strace-reported termination by signal {} is being propagated (command outcome is not independently verified; capture completeness is unknown).",
                outcome.trace_bytes,
                terminal_safe_path(&outcome.bundle_path),
                signal
            );
            Ok(propagate_signal(signal))
        } else {
            eprintln!(
                "Recorded {} bytes in bundle {}. strace returned an unavailable exit status; using failure status 1.",
                outcome.trace_bytes,
                terminal_safe_path(&outcome.bundle_path)
            );
            Ok(ExitCode::from(1))
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (output, program, args, duration);
        Err(
            "record --bundle is available only on Linux with an external strace executable"
                .to_owned(),
        )
    }
}

#[cfg(target_os = "linux")]
fn propagate_signal(signal: i32) -> ExitCode {
    // `record_trace` has returned, so its cancellation handlers have been restored and
    // the trace has already been published. Re-raise with the default disposition to
    // preserve the wrapped command's signal outcome at the process boundary.
    // SAFETY: signal is supplied by ExitStatusExt from wait status. The calls only
    // update this process's signal disposition/mask and raise that signal in this process.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut action.sa_mask);
        let reset = libc::sigaction(signal, &action, std::ptr::null_mut()) == 0;
        // SIGKILL cannot have its disposition changed, but its disposition is already
        // unconditionally terminating, so it can still be raised below.
        if reset || signal == libc::SIGKILL {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, signal);
            if libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) == 0 {
                libc::raise(signal);
            }
        }
    }
    ExitCode::from(128u8.saturating_add(signal.clamp(0, 127) as u8))
}

#[cfg(target_os = "linux")]
fn terminal_safe_path(path: &Path) -> String {
    use std::fmt::Write as _;
    use std::os::unix::ffi::OsStrExt;

    let mut escaped = String::new();
    for byte in path.as_os_str().as_bytes() {
        if (0x20..=0x7e).contains(byte) && *byte != b'\\' {
            escaped.push(char::from(*byte));
        } else if *byte == b'\\' {
            escaped.push_str("\\\\");
        } else {
            let _ = write!(escaped, "\\x{byte:02x}");
        }
    }
    escaped
}

#[cfg(windows)]
fn terminal_safe_path(path: &Path) -> String {
    use std::fmt::Write as _;

    let mut escaped = String::new();
    for character in path.to_string_lossy().chars() {
        if character.is_control() {
            let _ = write!(escaped, "\\u{{{:x}}}", character as u32);
        } else {
            escaped.push(character);
        }
    }
    escaped
}

fn print_version() {
    println!("sideeffect {}", env!("CARGO_PKG_VERSION"));
}

fn command_help(topics: &[OsString]) -> Result<ExitCode, String> {
    let topic = topics
        .iter()
        .map(|part| {
            part.to_str()
                .ok_or_else(|| "help topics must be valid UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?
        .join(" ");
    if topic.is_empty() {
        println!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }

    let text = match topic.as_str() {
        "inspect" => {
            "Usage: sideeffect inspect [--format json|text] TRACE\n       sideeffect inspect [--format json|text] --bundle DIR\nReads bounded local strace evidence. It never runs the represented command. JSON is the default; text output escapes terminal controls. Partial parses are labeled and exit with status 2."
        }
        "diff" => {
            "Usage: sideeffect diff [--format json|text] LEFT RIGHT\n       sideeffect diff --format html --output REPORT.html LEFT RIGHT\n       sideeffect diff --bundles [--format json|text] LEFT_DIR RIGHT_DIR\nCompares complete parsed observations. HTML reports are available on Linux and are static, offline, and private. Trace values may be sensitive."
        }
        "diff-summary" => {
            "Usage: sideeffect diff-summary [--format json] LEFT RIGHT\n       sideeffect diff-summary --format html --output REPORT.html LEFT RIGHT\nWrites aggregate change counts without event strings or evidence references. Counts may still be sensitive; the output is not a safe-to-share verdict."
        }
        "explain" => {
            "Usage: sideeffect explain TRACE\n       sideeffect explain --diff LEFT RIGHT\n       sideeffect explain --inventory-diff BEFORE.json AFTER.json\nCreates bounded deterministic summaries. It does not use a language model."
        }
        "evidence" => {
            "Usage: sideeffect evidence TRACE SHA256 LINE BYTE_OFFSET BYTE_LENGTH\nVerifies an exact parsed-row reference against the supplied fingerprint. A hash identifies bytes but does not authenticate them or prove capture completeness."
        }
        "record" => {
            "Usage: sideeffect record --trace OUTPUT -- PROGRAM [ARGS...]\n       sideeffect record --bundle DIR -- PROGRAM [ARGS...]\n       sideeffect record --trace OUTPUT --duration-seconds 1..3600 -- PROGRAM [ARGS...]\nRuns the selected program with the current user's permissions under external strace. This is observation, not isolation or a safety check. Available on Linux."
        }
        "inventory" => {
            "Usage: sideeffect inventory packages|processes|startup|permissions --output FILE [PATH...]\nCollects bounded, local Linux snapshots. Sources are curated and coverage can be partial; inspect output and diagnostics before drawing conclusions."
        }
        "inventory startup" => {
            #[cfg(target_os = "linux")]
            {
                "Usage: sideeffect inventory startup --output FILE\nDiscovers supported Linux XDG, systemd, SysV, and cron startup configuration. It does not execute commands or establish that a configured entry ran."
            }
            #[cfg(windows)]
            {
                "Usage: sideeffect inventory startup --output FILE\nReads current-user and accessible machine Run/RunOnce registry values plus current/common Startup folders. Values remain inert; services and scheduled tasks are reported as not checked. It does not establish that a configured entry ran."
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            {
                "Usage: sideeffect inventory startup --output FILE\nStartup inventory is not supported on this platform."
            }
        }
        "inventory packages" => {
            "Usage: sideeffect inventory packages --output FILE\nReads available dpkg, RPM, pacman, and APK package databases at fixed Linux paths. Unregistered software and unsupported sources may be missing."
        }
        "inventory processes" => {
            #[cfg(target_os = "linux")]
            {
                "Usage: sideeffect inventory processes --output FILE\nReads bounded /proc status fields and executable-link text. It does not read command lines or open executable targets."
            }
            #[cfg(windows)]
            {
                "Usage: sideeffect inventory processes --output FILE\nReads a bounded Tool Help snapshot and queries accessible image paths. It does not read command lines, inspect process memory, or request elevation."
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            {
                "Usage: sideeffect inventory processes --output FILE\nProcess inventory is not supported on this platform."
            }
        }
        "inventory permissions" => {
            "Usage: sideeffect inventory permissions --output FILE PATH...\nInspects only explicit Linux paths for metadata, supported POSIX ACLs, and file capabilities. It does not recurse or calculate effective access."
        }
        "correlate-startup" => {
            "Usage: sideeffect correlate-startup STARTUP_INVENTORY.json TRACE\nFinds narrow exact-path candidate matches between supported saved startup configuration and successful exec evidence. A match does not prove that a hook caused or initiated execution."
        }
        "model" | "model-preview" => {
            "Usage: sideeffect model-preview --question QUESTION TRACE\nPreviews the bounded typed facts, question, JSON schema, and request digest. Review this exact request before confirming local analysis. Partial parsing is visible and exits with status 2."
        }
        "model-analyze" => {
            "Usage: sideeffect model-analyze --question QUESTION --runtime LLAMA_CLI --model MODEL.gguf --confirm-sha256 REQUEST_SHA256 TRACE\nRuns the pinned optional local model on Linux x86_64 after explicit digest confirmation. It does not download weights or upload evidence. The model may select at most one source evidence ID as an unverified hint; it can be wrong and is not a finding. See docs/LOCAL_MODEL_EVALUATION.md."
        }
        _ => return Err(format!("unknown help topic: {topic}\n\n{USAGE}")),
    };
    println!("{text}");
    Ok(ExitCode::SUCCESS)
}

fn inspect(path: &OsString) -> Result<ExitCode, String> {
    inspect_with_format(&OsString::from("json"), path)
}

fn correlate_startup(startup_path: &OsString, trace_path: &OsString) -> Result<ExitCode, String> {
    let startup_bytes = read_input_file(
        Path::new(startup_path),
        MAX_REPORT_BYTES,
        "startup inventory",
    )?;
    let trace_bytes = read_input_file(Path::new(trace_path), MAX_TRACE_BYTES, "trace")?;
    let report = correlate_startup_bytes(&startup_bytes, &trace_bytes)?;
    let complete = report.status == "complete";
    let match_count = report.summary.candidate_match_path_count;
    let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
    serde_json::to_writer(&mut json, &report).map_err(|error| {
        format!("startup correlation exceeds the {MAX_REPORT_BYTES} byte output limit: {error}")
    })?;
    json.write_all(b"\n").map_err(|_| {
        format!("startup correlation exceeds the {MAX_REPORT_BYTES} byte output limit")
    })?;
    write_buffer(&json, "startup correlation")?;
    if complete {
        eprintln!(
            "Compared the supplied snapshots and found {match_count} candidate path-match group(s). Candidate matches do not prove startup-hook execution or causation."
        );
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!(
            "Saved partial startup-correlation results with {match_count} candidate path-match group(s). Check input statuses and diagnostics; missing matches remain unknown."
        );
        Ok(ExitCode::from(2))
    }
}

fn evidence(
    path: &OsString,
    digest: &OsString,
    line: &OsString,
    byte_offset: &OsString,
    byte_length: &OsString,
) -> Result<ExitCode, String> {
    let expected_digest = parse_sha256_digest(digest)?;
    let line_number = parse_reference_number(line, "line number")?;
    let expected_offset = parse_reference_number(byte_offset, "byte offset")?;
    let expected_length = parse_reference_number(byte_length, "byte length")?;
    if line_number == 0 || expected_length == 0 {
        return Err("line number and byte length must be greater than zero".to_owned());
    }

    let document = read_and_parse(path)?;
    if document.source_sha256 != expected_digest {
        return Err(format!(
            "source SHA-256 mismatch: supplied {}, file is {}",
            expected_digest, document.source_sha256
        ));
    }
    let record = document
        .records
        .iter()
        .find(|record| record.evidence.line_number == line_number)
        .ok_or_else(|| format!("no trace record exists at line {line_number}"))?;

    match record.kind {
        TraceRecordKind::Syscall
        | TraceRecordKind::UnfinishedSyscall
        | TraceRecordKind::ResumedSyscall => {}
        TraceRecordKind::Control => {
            return Err(format!(
                "line {line_number} is a control record, not syscall evidence"
            ));
        }
        TraceRecordKind::Unparsed => {
            return Err(format!(
                "line {line_number} is unparsed; no unambiguous syscall evidence is available"
            ));
        }
    }
    if record.syscall.is_none() || record.raw_arguments.is_none() {
        return Err(format!(
            "line {line_number} has incomplete parsed fields; no unambiguous syscall evidence is available"
        ));
    }
    if record.evidence.byte_offset != expected_offset
        || record.evidence.byte_length != expected_length
    {
        return Err(format!(
            "reference mismatch at line {line_number}: supplied byte={expected_offset} length={expected_length}, file has byte={} length={}",
            record.evidence.byte_offset, record.evidence.byte_length
        ));
    }

    let partial = document.parse_status == ParseCompleteness::Partial;
    let mut text = CappedBuffer::new(MAX_REPORT_BYTES);
    write_trace_evidence_text(
        record,
        document.parse_status,
        &document.source_sha256,
        &mut text,
    )
    .map_err(|error| {
        if text.exceeded {
            format!("evidence output exceeds the {MAX_REPORT_BYTES} byte output limit")
        } else {
            format!("could not render evidence: {error}")
        }
    })?;
    write_buffer(&text, "evidence output")?;
    if partial {
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn parse_sha256_digest(value: &OsString) -> Result<String, String> {
    let Some(text) = value.to_str() else {
        return Err("SHA-256 must be 64 lowercase hexadecimal characters".to_owned());
    };
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("SHA-256 must be 64 lowercase hexadecimal characters".to_owned());
    }
    Ok(text.to_owned())
}

fn parse_reference_number(value: &OsString, label: &str) -> Result<u64, String> {
    let Some(text) = value.to_str() else {
        return Err(format!("{label} must be an ASCII decimal number"));
    };
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{label} must be an ASCII decimal number"));
    }
    text.parse::<u64>()
        .map_err(|_| format!("{label} exceeds the supported numeric range"))
}

fn inspect_with_format(format: &OsString, path: &OsString) -> Result<ExitCode, String> {
    if !matches!(format.to_str(), Some("json" | "text")) {
        return Err("inspect format must be either 'json' or 'text'".to_owned());
    }
    inspect_bytes_with_format(format, read_bounded(path)?)
}

fn explain_trace_file(path: &OsString) -> Result<ExitCode, String> {
    let document = read_and_parse(path)?;
    let partial = document.parse_status == ParseCompleteness::Partial;
    let explanation = explain_trace(&document);
    write_json(&explanation, "JSON trace explanation")?;
    if partial {
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn explain_diff_files(
    baseline_path: &OsString,
    candidate_path: &OsString,
) -> Result<ExitCode, String> {
    let baseline = read_and_parse(baseline_path)?;
    let candidate = read_and_parse(candidate_path)?;
    let diff = compare_traces(&baseline, &candidate)
        .map_err(|error| format!("could not compare traces: {error}"))?;
    let explanation = explain_diff(&diff);
    write_json(&explanation, "JSON diff explanation")?;
    Ok(ExitCode::SUCCESS)
}

fn explain_inventory_diff_files(
    before_path: &OsString,
    after_path: &OsString,
) -> Result<ExitCode, String> {
    let before = read_input_file(
        Path::new(before_path),
        MAX_REPORT_BYTES,
        "package inventory",
    )?;
    let after = read_input_file(
        Path::new(after_path),
        MAX_REPORT_BYTES.saturating_sub(before.len()),
        "package inventory",
    )?;
    let comparison = compare_package_inventory_json(&before, &after)
        .map_err(|error| format!("package inventory comparison failed: {error:?}"))?;
    let partial = comparison.status == PackageComparisonStatus::Partial;
    write_json(&comparison, "JSON package inventory comparison")?;
    if partial {
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn model_preview_file(question: &OsString, path: &OsString) -> Result<ExitCode, String> {
    let question = question
        .to_str()
        .ok_or("local model question must be valid UTF-8")?;
    let bytes = read_bounded(path)?;
    let preview = sideeffect::local_model::preview_trace_bytes(&bytes, question)?;
    let partial = preview.evidence_summary["parse_status"] == "partial";
    write_json(&preview, "local model request preview")?;
    Ok(if partial {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn model_analyze_file(
    question: &OsString,
    runtime: &OsString,
    model: &OsString,
    digest: &OsString,
    trace: &OsString,
) -> Result<ExitCode, String> {
    let question = question
        .to_str()
        .ok_or("local model question must be valid UTF-8")?;
    let Some(digest) = digest.to_str() else {
        return Err("preview digest must be 64 lowercase hexadecimal characters".to_owned());
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("preview digest must be 64 lowercase hexadecimal characters".to_owned());
    }
    let bytes = read_bounded(trace)?;
    let analysis = sideeffect::local_model::analyze_trace_bytes(
        &bytes,
        question,
        Path::new(runtime),
        Path::new(model),
        digest,
    )?;
    let partial = analysis.evidence_summary["parse_status"] == "partial";
    write_json(&analysis, "local model evidence selection")?;
    Ok(if partial {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn inspect_bundle_with_format(format: &OsString, path: &OsString) -> Result<ExitCode, String> {
    if !matches!(format.to_str(), Some("json" | "text")) {
        return Err("inspect format must be either 'json' or 'text'".to_owned());
    }
    let bundle = read_run_bundle(Path::new(path))?;
    let partial_capture = bundle.stop_reason == "time_limit_reached";
    let status = inspect_bytes_with_capture(format, bundle.trace_bytes, bundle.capture_context)?;
    if partial_capture {
        eprintln!(
            "Warning: this bundle stopped at its requested time limit. Absence from the trace is not evidence that an event did not occur."
        );
        Ok(ExitCode::from(2))
    } else {
        Ok(status)
    }
}

fn inspect_bytes_with_format(format: &OsString, bytes: Vec<u8>) -> Result<ExitCode, String> {
    inspect_bytes_with_capture(format, bytes, None)
}

fn inspect_bytes_with_capture(
    format: &OsString,
    bytes: Vec<u8>,
    capture_context: Option<BundleCaptureContext>,
) -> Result<ExitCode, String> {
    let format = match format.to_str() {
        Some("json") => DiffOutputFormat::Json,
        Some("text") => DiffOutputFormat::Text,
        _ => return Err("inspect format must be either 'json' or 'text'".to_owned()),
    };
    let mut document = parse_trace_bytes(&bytes, ParseLimits::default())
        .map_err(|error| format!("trace inspection failed: {error}"))?;
    document.bundle_capture = capture_context;
    let partial = document.parse_status == ParseCompleteness::Partial;
    match format {
        DiffOutputFormat::Json => write_json(&document, "JSON evidence document")?,
        DiffOutputFormat::Text => write_trace_text_bounded(&document)?,
    }

    if partial {
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn write_trace_text_bounded(document: &sideeffect::model::TraceDocument) -> Result<(), String> {
    let mut text = CappedBuffer::new(MAX_REPORT_BYTES);
    sideeffect::format::write_trace_text(document, &mut text).map_err(|error| {
        if text.exceeded {
            format!("text evidence exceeds the {MAX_REPORT_BYTES} byte output limit")
        } else {
            format!("could not render text evidence: {error}")
        }
    })?;
    write_buffer(&text, "text evidence")
}

fn diff(left_path: &OsString, right_path: &OsString) -> Result<ExitCode, String> {
    diff_with_output_format(left_path, right_path, DiffOutputFormat::Json)
}

fn diff_summary_json(left_path: &OsString, right_path: &OsString) -> Result<ExitCode, String> {
    let summary = read_summary(left_path, right_path)?;
    write_json(&summary, "JSON redacted diff summary")?;
    Ok(ExitCode::SUCCESS)
}

fn diff_summary_html(
    output_path: &OsString,
    left_path: &OsString,
    right_path: &OsString,
) -> Result<ExitCode, String> {
    #[cfg(target_os = "linux")]
    {
        let mut output = AnchoredOutput::prepare(Path::new(output_path))
            .map_err(|error| format!("could not prepare safe summary output: {error}"))?;
        let summary = read_summary(left_path, right_path)?;
        let report_path = publish_summary_html(&mut output, &summary, MAX_REPORT_BYTES)?;
        eprintln!(
            "Aggregate diff summary written to {}. Remaining category/count metadata may be sensitive; this export is not a safe-to-share verdict.",
            terminal_safe_path(&report_path)
        );
        Ok(ExitCode::SUCCESS)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (output_path, left_path, right_path);
        Err("HTML summary file export is currently supported on Linux only".to_owned())
    }
}

fn read_summary(
    left_path: &OsString,
    right_path: &OsString,
) -> Result<RedactedDiffSummary, String> {
    let left = read_and_parse(left_path)?;
    let right = read_and_parse(right_path)?;
    let diff = compare_traces(&left, &right)
        .map_err(|error| format!("could not compare traces: {error}"))?;
    Ok(summarize_diff(&diff))
}

#[cfg(target_os = "linux")]
fn publish_summary_html(
    output: &mut AnchoredOutput,
    summary: &RedactedDiffSummary,
    output_limit: usize,
) -> Result<std::path::PathBuf, String> {
    let mut html = CappedBuffer::new(output_limit);
    write_html_summary(summary, &mut html).map_err(|error| {
        if html.exceeded {
            format!("HTML summary exceeds the {output_limit} byte output limit")
        } else {
            format!("could not render HTML summary: {error}")
        }
    })?;
    let mut report = output
        .create_report_file()
        .map_err(|error| format!("could not create private summary staging file: {error}"))?;
    report
        .write_all(&html.bytes)
        .and_then(|()| report.flush())
        .and_then(|()| report.sync_all())
        .map_err(|error| format!("could not write complete HTML summary: {error}"))?;
    output
        .publish_report()
        .map_err(|error| format!("could not publish summary without replacing a file: {error}"))
}

fn diff_with_format(
    format: &OsString,
    left_path: &OsString,
    right_path: &OsString,
) -> Result<ExitCode, String> {
    let output_format = match format.to_str() {
        Some("json") => DiffOutputFormat::Json,
        Some("text") => DiffOutputFormat::Text,
        _ => return Err("diff format must be either 'json' or 'text'".to_owned()),
    };
    diff_with_output_format(left_path, right_path, output_format)
}

fn diff_bundles(left_path: &OsString, right_path: &OsString) -> Result<ExitCode, String> {
    diff_bundles_with_output_format(left_path, right_path, DiffOutputFormat::Json)
}

fn diff_bundles_with_format(
    format: &OsString,
    left_path: &OsString,
    right_path: &OsString,
) -> Result<ExitCode, String> {
    let output_format = match format.to_str() {
        Some("json") => DiffOutputFormat::Json,
        Some("text") => DiffOutputFormat::Text,
        _ => return Err("diff format must be either 'json' or 'text'".to_owned()),
    };
    diff_bundles_with_output_format(left_path, right_path, output_format)
}

fn diff_bundles_with_output_format(
    left_path: &OsString,
    right_path: &OsString,
    output_format: DiffOutputFormat,
) -> Result<ExitCode, String> {
    let (left, right) = read_and_parse_bundles(left_path, right_path)?;
    let result = compare_traces(&left, &right)
        .map_err(|error| format!("could not compare traces: {error}"))?;
    match output_format {
        DiffOutputFormat::Json => write_json(&result, "JSON comparison document")?,
        DiffOutputFormat::Text => write_text(&result)?,
    }
    Ok(ExitCode::SUCCESS)
}

fn read_and_parse_bundles(
    left_path: &OsString,
    right_path: &OsString,
) -> Result<
    (
        sideeffect::model::TraceDocument,
        sideeffect::model::TraceDocument,
    ),
    String,
> {
    let left_bundle = read_run_bundle(Path::new(left_path))?;
    let right_bundle = read_run_bundle(Path::new(right_path))?;
    if left_bundle.stop_reason == "time_limit_reached"
        || right_bundle.stop_reason == "time_limit_reached"
    {
        return Err("cannot compare a bundle stopped at its requested time limit; its event set is known to be incomplete".to_owned());
    }
    let left = parse_trace_bytes(&left_bundle.trace_bytes, ParseLimits::default())
        .map_err(|error| format!("trace inspection failed: {error}"))?;
    let right = parse_trace_bytes(&right_bundle.trace_bytes, ParseLimits::default())
        .map_err(|error| format!("trace inspection failed: {error}"))?;
    Ok((left, right))
}

fn diff_bundles_html(
    output_path: &OsString,
    left_path: &OsString,
    right_path: &OsString,
) -> Result<ExitCode, String> {
    #[cfg(target_os = "linux")]
    {
        let mut output = AnchoredOutput::prepare(Path::new(output_path))
            .map_err(|error| format!("could not prepare safe HTML report output: {error}"))?;
        let (left, right) = read_and_parse_bundles(left_path, right_path)?;
        let diff = compare_traces(&left, &right)
            .map_err(|error| format!("could not compare traces: {error}"))?;
        let report_path = publish_html_report(&mut output, &diff, MAX_REPORT_BYTES)?;
        eprintln!(
            "Offline HTML report written to {}. It may contain sensitive paths, arguments, or endpoint data; review before sharing.",
            terminal_safe_path(&report_path)
        );
        Ok(ExitCode::SUCCESS)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (output_path, left_path, right_path);
        Err(
            "bundle comparison and HTML report export are currently supported on Linux only"
                .to_owned(),
        )
    }
}

fn diff_html(
    output_path: &OsString,
    left_path: &OsString,
    right_path: &OsString,
) -> Result<ExitCode, String> {
    #[cfg(target_os = "linux")]
    {
        let mut output = AnchoredOutput::prepare(Path::new(output_path))
            .map_err(|error| format!("could not prepare safe HTML report output: {error}"))?;
        let left = read_and_parse(left_path)?;
        let right = read_and_parse(right_path)?;
        let diff = compare_traces(&left, &right)
            .map_err(|error| format!("could not compare traces: {error}"))?;
        let report_path = publish_html_report(&mut output, &diff, MAX_REPORT_BYTES)?;
        eprintln!(
            "Offline HTML report written to {}. It may contain sensitive paths, arguments, or endpoint data; review before sharing.",
            terminal_safe_path(&report_path)
        );
        Ok(ExitCode::SUCCESS)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (output_path, left_path, right_path);
        Err("HTML report file export is currently supported on Linux only".to_owned())
    }
}

#[cfg(target_os = "linux")]
fn publish_html_report(
    output: &mut AnchoredOutput,
    diff: &TraceDiff<'_>,
    output_limit: usize,
) -> Result<std::path::PathBuf, String> {
    let mut html = CappedBuffer::new(output_limit);
    write_html_diff(diff, &mut html).map_err(|error| {
        if html.exceeded {
            format!("HTML report exceeds the {output_limit} byte output limit")
        } else {
            format!("could not render HTML report: {error}")
        }
    })?;
    let mut report = output
        .create_report_file()
        .map_err(|error| format!("could not create private HTML staging file: {error}"))?;
    report
        .write_all(&html.bytes)
        .and_then(|()| report.flush())
        .and_then(|()| report.sync_all())
        .map_err(|error| format!("could not write complete HTML report: {error}"))?;
    output
        .publish_report()
        .map_err(|error| format!("could not publish HTML report without replacing a file: {error}"))
}

#[derive(Clone, Copy)]
enum DiffOutputFormat {
    Json,
    Text,
}

fn diff_with_output_format(
    left_path: &OsString,
    right_path: &OsString,
    output_format: DiffOutputFormat,
) -> Result<ExitCode, String> {
    let left = read_and_parse(left_path)?;
    let right = read_and_parse(right_path)?;
    let result = compare_traces(&left, &right)
        .map_err(|error| format!("could not compare traces: {error}"))?;
    match output_format {
        DiffOutputFormat::Json => write_json(&result, "JSON comparison document")?,
        DiffOutputFormat::Text => write_text(&result)?,
    }
    Ok(ExitCode::SUCCESS)
}

fn read_and_parse(path: &OsString) -> Result<sideeffect::model::TraceDocument, String> {
    let bytes = read_bounded(path)?;
    parse_trace_bytes(&bytes, ParseLimits::default())
        .map_err(|error| format!("trace inspection failed: {error}"))
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct RunManifest {
    schema: String,
    schema_version: u32,
    producer: BundleProducer,
    capture: BundleCapture,
    trace: BundleTrace,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct BundleProducer {
    sideeffect_version: String,
    operating_system: String,
    architecture: String,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct BundleCapture {
    tracer: BundleTracer,
    capture_profile: String,
    strace_reported_status: BundleStatus,
    command_outcome: String,
    completeness: String,
    command_stdout: String,
    command_stderr: String,
    tracer_diagnostics: String,
    #[serde(default)]
    time_limit_milliseconds: Option<u64>,
    #[serde(default)]
    stop_reason: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct BundleTracer {
    name: String,
    major: u64,
    minor: u64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[allow(dead_code)]
enum BundleStatus {
    ExitCode { value: i32 },
    Signal { value: i32 },
    Unavailable,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct BundleTrace {
    name: String,
    format: String,
    byte_length: u64,
    sha256: String,
}

struct RunBundleData {
    trace_bytes: Vec<u8>,
    stop_reason: &'static str,
    capture_context: Option<BundleCaptureContext>,
}

fn read_run_bundle(path: &Path) -> Result<RunBundleData, String> {
    #[cfg(target_os = "linux")]
    {
        read_run_bundle_linux(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err("bundle inspection is currently supported on Linux only".to_owned())
    }
}

#[cfg(target_os = "linux")]
fn read_run_bundle_linux(path: &Path) -> Result<RunBundleData, String> {
    use std::ffi::CStr;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| "bundle path contains a NUL byte".to_owned())?;
    // O_NOFOLLOW ensures the selected bundle directory itself is not a symlink.
    // SAFETY: c_path is NUL-terminated and the returned descriptor is owned below.
    let dir_fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if dir_fd < 0 {
        return Err("could not open bundle directory without following symlinks".to_owned());
    }
    // SAFETY: open returned a new owned descriptor.
    let dir = unsafe { File::from_raw_fd(dir_fd) };
    let metadata = dir
        .metadata()
        .map_err(|_| "could not inspect bundle directory".to_owned())?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(
            "bundle directory must be owned by the current user and inaccessible to group/other"
                .to_owned(),
        );
    }

    // Enumerate through a duplicated descriptor so a replaced path cannot redirect the read.
    // SAFETY: dup creates an owned descriptor; fdopendir takes ownership on success.
    let duplicate = unsafe { libc::dup(dir.as_raw_fd()) };
    if duplicate < 0 {
        return Err("could not enumerate bundle directory".to_owned());
    }
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        unsafe { libc::close(duplicate) };
        return Err("could not enumerate bundle directory".to_owned());
    }
    let mut names = Vec::new();
    let mut enumeration_failed = false;
    loop {
        // SAFETY: this Linux thread-local errno pointer is valid for the current thread.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: directory remains open until closed below; readdir returns storage owned by it.
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            // SAFETY: errno is thread-local and valid for this thread.
            enumeration_failed = unsafe { *libc::__errno_location() != 0 };
            break;
        }
        // SAFETY: d_name is a NUL-terminated byte array supplied by readdir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
            if names.len() > 2 {
                break;
            }
        }
    }
    // SAFETY: directory was returned by fdopendir and has not been closed.
    unsafe { libc::closedir(directory) };
    if enumeration_failed {
        return Err("could not enumerate bundle directory".to_owned());
    }
    names.sort();
    if names != [b"run.json".to_vec(), b"trace.strace".to_vec()] {
        return Err("bundle must contain exactly run.json and trace.strace".to_owned());
    }

    let manifest_bytes = read_bundle_file(dir.as_raw_fd(), b"run.json", MAX_BUNDLE_MANIFEST_BYTES)?;
    let manifest: RunManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| "bundle manifest is invalid JSON or has an unsupported schema".to_owned())?;
    validate_bundle_manifest(&manifest)?;
    let trace_len = usize::try_from(manifest.trace.byte_length)
        .map_err(|_| "bundle trace length exceeds the supported range".to_owned())?;
    if trace_len > MAX_TRACE_BYTES {
        return Err(format!(
            "bundle trace exceeds the {MAX_TRACE_BYTES} byte limit"
        ));
    }
    let trace = read_bundle_file(dir.as_raw_fd(), b"trace.strace", MAX_TRACE_BYTES)?;
    if trace.len() != trace_len {
        return Err("bundle trace length does not match the manifest".to_owned());
    }
    let actual_hash = format!("{:x}", Sha256::digest(&trace));
    if actual_hash != manifest.trace.sha256 {
        return Err("bundle trace SHA-256 does not match the manifest".to_owned());
    }
    Ok(RunBundleData {
        trace_bytes: trace,
        stop_reason: if manifest.capture.stop_reason.as_deref() == Some("time_limit_reached") {
            "time_limit_reached"
        } else {
            "tracer_exited"
        },
        capture_context: (manifest.schema_version >= 2).then(|| BundleCaptureContext {
            stop_reason: manifest
                .capture
                .stop_reason
                .clone()
                .unwrap_or_else(|| "tracer_exited".to_owned()),
            time_limit_milliseconds: manifest.capture.time_limit_milliseconds,
        }),
    })
}

#[cfg(target_os = "linux")]
fn read_bundle_file(dir_fd: i32, name: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::MetadataExt;

    let name_c = std::ffi::CString::new(name).expect("fixed file name has no NUL");
    // SAFETY: dir_fd is an open directory and name_c is a fixed single path component.
    let fd = unsafe {
        libc::openat(
            dir_fd,
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err("bundle entries must be regular files without symlinks".to_owned());
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .map_err(|_| "could not inspect bundle file".to_owned())?;
    let expected_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err("bundle entries must be current-user-owned private regular files".to_owned());
    }
    read_limited(file, limit)
        .map_err(|error| format!("could not read bounded bundle entry: {error}"))
}

#[cfg(target_os = "linux")]
fn validate_bundle_manifest(manifest: &RunManifest) -> Result<(), String> {
    let valid_reported_status = match manifest.capture.strace_reported_status {
        BundleStatus::ExitCode { value } => value >= 0,
        BundleStatus::Signal { value } => (1..=64).contains(&value),
        BundleStatus::Unavailable => true,
    };
    let versioned_capture_valid = match manifest.schema_version {
        1 => {
            manifest.capture.time_limit_milliseconds.is_none()
                && manifest.capture.stop_reason.is_none()
        }
        2 => match manifest.capture.stop_reason.as_deref() {
            Some("tracer_exited") => manifest
                .capture
                .time_limit_milliseconds
                .is_none_or(|milliseconds| (1..=3_600_000).contains(&milliseconds)),
            Some("time_limit_reached") => manifest
                .capture
                .time_limit_milliseconds
                .is_some_and(|milliseconds| (1..=3_600_000).contains(&milliseconds)),
            _ => false,
        },
        _ => false,
    };
    if manifest.schema != "sideeffect.run" || !versioned_capture_valid {
        return Err("unsupported bundle schema or schema version".to_owned());
    }
    if manifest.producer.operating_system != "linux"
        || manifest.producer.architecture != "x86_64"
        || manifest.capture.tracer.name != "strace"
        || manifest.capture.capture_profile != "linux_process_file_network_v1"
        || manifest.capture.command_outcome != "not_independently_verified"
        || manifest.capture.completeness != "unknown"
        || manifest.capture.command_stdout != "inherited_not_captured"
        || manifest.capture.command_stderr != "inherited_not_captured"
        || manifest.capture.tracer_diagnostics != "inherited_not_captured"
        || !valid_reported_status
        || manifest.trace.name != "trace.strace"
        || manifest.trace.format != "strace_text"
        || manifest.trace.byte_length == 0
        || manifest.trace.sha256.len() != 64
        || !manifest
            .trace
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || manifest.producer.sideeffect_version.is_empty()
        || manifest.capture.tracer.major == 0
    {
        return Err("bundle manifest contains invalid or unsupported fields".to_owned());
    }
    Ok(())
}

fn write_json<T: Serialize>(value: &T, description: &str) -> Result<(), String> {
    let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
    serde_json::to_writer_pretty(&mut json, value).map_err(|error| {
        if json.exceeded {
            format!(
                "{description} exceeds the {} byte output limit",
                MAX_REPORT_BYTES
            )
        } else {
            format!("could not serialize {description}: {error}")
        }
    })?;
    json.write_all(b"\n").map_err(|_| {
        format!(
            "{description} exceeds the {} byte output limit",
            MAX_REPORT_BYTES
        )
    })?;

    write_buffer(&json, description)
}

fn write_text(diff: &TraceDiff<'_>) -> Result<(), String> {
    let mut text = CappedBuffer::new(MAX_REPORT_BYTES);
    write_text_diff(diff, &mut text).map_err(|error| {
        if text.exceeded {
            format!("text comparison exceeds the {MAX_REPORT_BYTES} byte output limit")
        } else {
            format!("could not render text comparison: {error}")
        }
    })?;
    text.write_all(b"\n")
        .map_err(|_| format!("text comparison exceeds the {MAX_REPORT_BYTES} byte output limit"))?;
    write_buffer(&text, "text comparison")
}

fn write_buffer(buffer: &CappedBuffer, description: &str) -> Result<(), String> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&buffer.bytes)
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("could not write {description} to stdout: {error}"))
}

fn read_bounded(path: &OsString) -> Result<Vec<u8>, String> {
    read_trace_file(Path::new(path), MAX_TRACE_BYTES)
}

fn read_trace_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    read_input_file(path, limit, "trace")
}

fn read_input_file(path: &Path, limit: usize, description: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("could not inspect {description} input: {error}"))?;
    if !metadata.is_file() {
        return Err(format!(
            "{description} input must be a regular file; pipes and devices are not accepted"
        ));
    }
    let length = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if length > limit {
        return Err(format!(
            "{description} input exceeds the {limit} byte limit"
        ));
    }
    let file = open_trace_file(path)
        .map_err(|error| format!("could not open {description} input: {error}"))?;
    if !file
        .metadata()
        .map_err(|error| format!("could not inspect opened {description} input: {error}"))?
        .is_file()
    {
        return Err(format!("opened {description} input is not a regular file"));
    }
    read_limited(file, limit)
        .map_err(|error| error.replace("trace input", &format!("{description} input")))
}

#[cfg(target_os = "linux")]
fn open_trace_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_trace_file(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn read_limited<R: Read>(reader: R, limit: usize) -> Result<Vec<u8>, String> {
    let max_plus_one = u64::try_from(limit)
        .map_err(|_| "configured trace byte limit exceeds u64".to_owned())?
        .saturating_add(1);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(limit.min(8 * 1024))
        .map_err(|_| "could not allocate the bounded trace input buffer".to_owned())?;
    reader
        .take(max_plus_one)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read trace input: {error}"))?;
    if bytes.len() > limit {
        return Err(format!("trace input exceeds the {limit} byte limit"));
    }
    Ok(bytes)
}

struct CappedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl CappedBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl Write for CappedBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let new_len = self.bytes.len().checked_add(buffer.len()).ok_or_else(|| {
            self.exceeded = true;
            io::Error::other("output size overflow")
        })?;
        if new_len > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("output limit exceeded"));
        }
        self.bytes
            .try_reserve(buffer.len())
            .map_err(|_| io::Error::other("could not allocate bounded JSON output"))?;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::{
        AnchoredOutput, ParseLimits, compare_traces, parse_trace_bytes, publish_html_report,
    };
    use super::{CappedBuffer, MAX_REPORT_BYTES, read_limited, read_trace_file};
    use std::fs::{self, OpenOptions};
    use std::io::{self, Cursor, Write};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    struct TempTrace(PathBuf);

    impl TempTrace {
        fn with_contents(contents: &[u8]) -> Self {
            loop {
                let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("sideeffect-test-{}-{id}.trace", std::process::id()));
                match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(mut file) => {
                        file.write_all(contents).unwrap();
                        return Self(path);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create test trace: {error}"),
                }
            }
        }
    }

    impl Drop for TempTrace {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn capped_buffer_accepts_exact_limit() {
        let mut buffer = CappedBuffer::new(3);
        buffer.write_all(b"abc").unwrap();
        assert_eq!(buffer.bytes, b"abc");
        assert!(!buffer.exceeded);
    }

    #[test]
    fn capped_buffer_rejects_limit_plus_one_without_appending() {
        let mut buffer = CappedBuffer::new(3);
        buffer.write_all(b"abc").unwrap();
        assert!(buffer.write_all(b"d").is_err());
        assert_eq!(buffer.bytes, b"abc");
        assert!(buffer.exceeded);
    }

    #[test]
    fn capped_buffer_enforces_production_report_limit_at_boundary() {
        let mut buffer = CappedBuffer::new(MAX_REPORT_BYTES);
        buffer.bytes.resize(MAX_REPORT_BYTES - 1, 0);
        buffer.write_all(b"x").unwrap();
        assert_eq!(buffer.bytes.len(), MAX_REPORT_BYTES);
        assert!(!buffer.exceeded);

        assert!(buffer.write_all(b"y").is_err());
        assert_eq!(buffer.bytes.len(), MAX_REPORT_BYTES);
        assert!(buffer.exceeded);
    }

    #[test]
    fn bounded_reader_accepts_exact_limit() {
        let bytes = read_limited(Cursor::new(b"abcd"), 4).unwrap();
        assert_eq!(bytes, b"abcd");
    }

    #[test]
    fn bounded_reader_rejects_limit_plus_one() {
        let error = read_limited(Cursor::new(b"abcde"), 4).unwrap_err();
        assert!(error.contains("limit"));
    }

    #[test]
    fn production_path_reader_accepts_exact_file_limit() {
        let trace = TempTrace::with_contents(b"abcd");
        assert_eq!(read_trace_file(&trace.0, 4).unwrap(), b"abcd");
    }

    #[test]
    fn production_path_reader_rejects_file_limit_plus_one() {
        let trace = TempTrace::with_contents(b"abcde");
        assert!(read_trace_file(&trace.0, 4).unwrap_err().contains("limit"));
    }

    #[test]
    fn production_path_reader_rejects_non_regular_input() {
        let error = read_trace_file(&std::env::temp_dir(), 4).unwrap_err();
        assert!(error.contains("regular file"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oversized_html_render_does_not_create_a_report_or_leave_staging() {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "sideeffect-html-cap-test-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let report_path = directory.join("too-large.html");
        let mut output = AnchoredOutput::prepare(&report_path).unwrap();
        let baseline = parse_trace_bytes(b"close(1) = 0\n", ParseLimits::default()).unwrap();
        let candidate = parse_trace_bytes(b"", ParseLimits::default()).unwrap();
        let diff = compare_traces(&baseline, &candidate).unwrap();

        let error = publish_html_report(&mut output, &diff, 16).unwrap_err();
        assert!(error.contains("HTML report exceeds the 16 byte output limit"));
        assert!(!report_path.exists());
        drop(output);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        fs::remove_dir(&directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn html_publish_race_cleans_staging_and_preserves_source_evidence() {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "sideeffect-html-race-test-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let baseline_path = directory.join("baseline.trace");
        let candidate_path = directory.join("candidate.trace");
        let report_path = directory.join("race.html");
        fs::write(&baseline_path, b"close(1) = 0\n").unwrap();
        fs::write(&candidate_path, b"").unwrap();
        let baseline_evidence = fs::read(&baseline_path).unwrap();
        let candidate_evidence = fs::read(&candidate_path).unwrap();

        let baseline = parse_trace_bytes(&baseline_evidence, ParseLimits::default()).unwrap();
        let candidate = parse_trace_bytes(&candidate_evidence, ParseLimits::default()).unwrap();
        let diff = compare_traces(&baseline, &candidate).unwrap();
        let mut output = AnchoredOutput::prepare(&report_path).unwrap();
        fs::write(&report_path, b"concurrent writer").unwrap();

        let error = publish_html_report(&mut output, &diff, MAX_REPORT_BYTES).unwrap_err();
        assert!(error.contains("without replacing a file"));
        drop(output);

        assert_eq!(fs::read(&report_path).unwrap(), b"concurrent writer");
        assert_eq!(fs::read(&baseline_path).unwrap(), baseline_evidence);
        assert_eq!(fs::read(&candidate_path).unwrap(), candidate_evidence);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 3);
        fs::remove_dir_all(&directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn record_output_paths_escape_terminal_control_bytes() {
        let path = std::path::Path::new("safe\n\u{1b}[31m");
        assert_eq!(super::terminal_safe_path(path), "safe\\x0a\\x1b[31m");
    }
}
