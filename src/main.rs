use std::env;
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, BufRead, Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

#[cfg(target_os = "linux")]
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use sideeffect::audit_session_linux::{AuditOptions, collect_and_publish};
#[cfg(windows)]
use sideeffect::audit_session_windows::{
    WindowsAuditOptions, collect_and_publish as collect_windows_audit_and_publish,
};
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
use sideeffect::inventory::{WindowsPermissionStatus, collect_windows_permissions};
#[cfg(windows)]
use sideeffect::inventory::{WindowsProcessInventoryStatus, collect_windows_processes};
#[cfg(windows)]
use sideeffect::inventory::{WindowsSoftwareStatus, collect_windows_software};
#[cfg(windows)]
use sideeffect::inventory::{WindowsStartupStatus, collect_windows_startup};
#[cfg(target_os = "linux")]
use sideeffect::limits::MAX_BUNDLE_MANIFEST_BYTES;
use sideeffect::limits::{MAX_REPORT_BYTES, MAX_TRACE_BYTES, ParseLimits};
use sideeffect::model::{BundleCaptureContext, ParseCompleteness, TraceDiff, TraceRecordKind};
use sideeffect::model_manager::{EvaluationStatus, ModelTask, ResolvedModel};
#[cfg(target_os = "linux")]
use sideeffect::record::AnchoredOutput;
#[cfg(target_os = "linux")]
use sideeffect::record::publish_private_file;
#[cfg(windows)]
use sideeffect::record::publish_private_windows_file;
use sideeffect::startup_correlation::correlate_startup_bytes;
use sideeffect::trace::strace::parse_trace_bytes;

const USAGE: &str = "Usage: sideeffect inspect [--format json|text] <strace-trace-file>\n       sideeffect inspect [--format json|text] --bundle <run-bundle-directory>\n       sideeffect inspect [--format json|text] --session <audit-session-directory>\n       sideeffect inspect [--format json|text] --windows-runtime <capture.json>\n       sideeffect evidence <strace-trace-file> <sha256> <line> <byte-offset> <byte-length>\n       sideeffect diff [--format json|text] <baseline-trace> <candidate-trace>\n       sideeffect diff --format html --output <report.html> <baseline-trace> <candidate-trace>\n       sideeffect diff --bundles [--format json|text] <baseline-bundle> <candidate-bundle>\n       sideeffect diff --bundles --format html --output <report.html> <baseline-bundle> <candidate-bundle>\n       sideeffect diff-summary [--format json] <baseline-trace> <candidate-trace>\n       sideeffect diff-summary --format html --output <summary.html> <baseline-trace> <candidate-trace>\n       sideeffect inventory packages --output <new-inventory.json>\n\
       sideeffect explain <strace-trace-file>\n\
       sideeffect explain --diff <baseline-trace> <candidate-trace>\n\
       sideeffect explain --inventory-diff <before.json> <after.json>\n\
       sideeffect model-preview --question <question> <strace-trace-file>\n\
       sideeffect model-analyze --question <question> --runtime <llama-cli> --confirm-sha256 <preview-digest> <strace-trace-file>\n\
       sideeffect model-explain-preview --question <question> --backend auto|cpu|cuda <strace-trace-file>\n\
       sideeffect model-explain --question <question> --backend auto|cpu|cuda --runtime <llama-completion> --confirm-sha256 <preview-digest> <strace-trace-file>\n\
       sideeffect model-query-preview --question <question> <strace-trace-file>\n\
       sideeffect model-query --question <question> --runtime <llama-completion> --confirm-sha256 <preview-digest> <strace-trace-file>\n\
       sideeffect model list | show <id> | install <id> | setup <id> | add | select <task> <id> | remove <id>\n\
       sideeffect correlate-startup <startup-inventory.json> <strace-trace-file>\n\
       sideeffect inventory processes --output <new-inventory.json>\n\
       sideeffect inventory startup --output <new-inventory.json>\n\
       sideeffect inventory permissions --output <new-inventory.json> <path>...\n\
       sideeffect audit --output <new-session-directory> [--packages] [--processes] [--startup] [--permission <path>]... [--runtime-duration-seconds <1..3600> -- <program> [args...]]\n\
       sideeffect record --trace <new-trace-file> -- <program> [args...]\n       sideeffect record --bundle <new-bundle-directory> -- <program> [args...]\n       sideeffect record --trace <new-trace-file> --duration-seconds <1..3600> -- <program> [args...]\n       sideeffect record --bundle <new-bundle-directory> --duration-seconds <1..3600> -- <program> [args...]\n       sideeffect help [command [subcommand]]\n       sideeffect version\n       sideeffect --help\n       sideeffect --version\n\nInspect reads one bounded strace text file or a validated local run bundle and writes JSON evidence by default, or terminal-safe text with --format text. Evidence verifies the supplied SHA-256 fingerprint, then checks an exact line/byte/length tuple against one parsed row. The fingerprint identifies bytes but does not authenticate them or prove capture completeness. Diff compares two complete parsed traces, or validates two local run bundles with --bundles, and writes observed syscall-row differences to stdout (JSON by default), or a local offline HTML report on Linux. Diff-summary creates a separate aggregate-only export and omits event strings, hashes, and evidence references; counts/category patterns can still be sensitive, and this is not a safe-to-share verdict. On Linux, inventory packages reads available local dpkg, RPM, pacman, and APK databases; on Windows, it reads selected current-user and machine-wide Uninstall registry entries. Both are bounded source snapshots and can miss unregistered software. Windows does not use Win32_Product or launch uninstall commands. On Linux, inventory processes reads bounded numeric /proc status entries and executable-link identities; on Windows, it reads a Tool Help snapshot and queries accessible image paths. Neither adapter reads command lines or promises atomic or exhaustive coverage. On Linux, inventory startup discovers curated sources; on Windows, it inventories selected Run/RunOnce values, Startup folders, and visible service configuration and boot/logon triggers in tasks visible to the current token. For tasks, bounded Exec-action executable paths, arguments, and working directories are recorded as inert text; other action types remain unsupported with unknown action-specific fields. Neither platform establishes that a configured entry ran. Inventory permissions inspects only explicit Linux paths and records ownership/type/mode, supported POSIX ACLs, and Linux file-capability xattrs; it never follows the final path symlink or calculates effective access. Record follows a selected command's traced descendants and may enforce a requested wall-clock limit; this is observation, not isolation or a safety check.";

fn main() -> ExitCode {
    match run(env::args_os().skip(1).collect()) {
        Ok(code) => code,
        Err(message) => {
            let _ = writeln!(io::stderr().lock(), "sideeffect: {message}");
            ExitCode::from(1)
        }
    }
}

const MAX_MODEL_CONFIRMATION_BYTES: usize = 256;

fn read_model_confirmation() -> Result<String, String> {
    let stdin = io::stdin();
    let mut bytes = Vec::with_capacity(128);
    let mut limited = Read::take(stdin.lock(), (MAX_MODEL_CONFIRMATION_BYTES + 1) as u64);
    limited
        .read_until(b'\n', &mut bytes)
        .map_err(|error| format!("could not read model confirmation: {error}"))?;
    if bytes.len() > MAX_MODEL_CONFIRMATION_BYTES {
        return Err(format!(
            "model confirmation exceeds the {MAX_MODEL_CONFIRMATION_BYTES}-byte limit"
        ));
    }
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    String::from_utf8(bytes).map_err(|_| "model confirmation must be valid UTF-8".to_owned())
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
        [command, operation] if command == "model" && operation == "list" => model_list(),
        [command, operation, id] if command == "model" && operation == "show" => model_show(id),
        [command, operation, id] if command == "model" && operation == "install" => {
            model_install(id, false)
        }
        [command, operation, id] if command == "model" && operation == "setup" => {
            model_install(id, true)
        }
        [command, operation, task, id] if command == "model" && operation == "select" => {
            model_select(task, id)
        }
        [command, operation, id] if command == "model" && operation == "remove" => model_remove(id),
        [command, operation, arguments @ ..] if command == "model" && operation == "add" => {
            model_add(arguments)
        }
        [command, flag, path] if command == "inspect" && flag == "--session" => {
            inspect_session_with_format(&OsString::from("json"), path)
        }
        [command, format_flag, format, session_flag, path]
            if command == "inspect" && format_flag == "--format" && session_flag == "--session" =>
        {
            inspect_session_with_format(format, path)
        }
        [command, flag, path] if command == "inspect" && flag == "--windows-runtime" => {
            inspect_windows_runtime_with_format(&OsString::from("json"), path)
        }
        [command, format_flag, format, windows_flag, path]
            if command == "inspect"
                && format_flag == "--format"
                && windows_flag == "--windows-runtime" =>
        {
            inspect_windows_runtime_with_format(format, path)
        }
        [command, path] if command == "inspect" => inspect(path),
        [command, path] if command == "explain" => explain_trace_file(path),
        [command, question_flag, question, path]
            if command == "model-preview" && question_flag == "--question" =>
        {
            model_preview_file(question, path)
        }
        [command, question_flag, question, path]
            if command == "model-query-preview" && question_flag == "--question" =>
        {
            model_query_preview_file(question, path)
        }
        [
            command,
            question_flag,
            question,
            backend_flag,
            backend,
            path,
        ] if command == "model-explain-preview"
            && question_flag == "--question"
            && backend_flag == "--backend" =>
        {
            model_explanation_preview_file(question, backend, path)
        }
        [
            command,
            question_flag,
            question,
            backend_flag,
            backend,
            runtime_flag,
            runtime,
            confirm_flag,
            digest,
            trace,
        ] if command == "model-explain"
            && question_flag == "--question"
            && backend_flag == "--backend"
            && runtime_flag == "--runtime"
            && confirm_flag == "--confirm-sha256" =>
        {
            model_explanation_file(question, backend, runtime, digest, trace)
        }
        [
            command,
            question_flag,
            question,
            runtime_flag,
            runtime,
            confirm_flag,
            digest,
            trace,
        ] if command == "model-analyze"
            && question_flag == "--question"
            && runtime_flag == "--runtime"
            && confirm_flag == "--confirm-sha256" =>
        {
            model_analyze_file(question, runtime, digest, trace)
        }
        [
            command,
            question_flag,
            question,
            runtime_flag,
            runtime,
            confirm_flag,
            digest,
            trace,
        ] if command == "model-query"
            && question_flag == "--question"
            && runtime_flag == "--runtime"
            && confirm_flag == "--confirm-sha256" =>
        {
            model_query_file(question, runtime, digest, trace)
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
            && option == "--windows-etw"
            && duration_flag == "--duration-seconds"
            && separator == "--" =>
        {
            let duration = parse_windows_duration_seconds(duration)?;
            record_windows_etw(output, program, target_args, duration)
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
        [command, args @ ..] if command == "audit" => audit_command(args),
        [command, ..] if command == "inventory" => Err(USAGE.to_owned()),
        _ => Err(USAGE.to_owned()),
    }
}

fn audit_command(arguments: &[OsString]) -> Result<ExitCode, String> {
    #[cfg(target_os = "linux")]
    {
        let mut destination: Option<&OsString> = None;
        let mut options = AuditOptions::default();
        let mut selected = std::collections::HashSet::new();
        let mut index = 0;
        while index < arguments.len() {
            let argument = &arguments[index];
            if argument == "--" {
                if options.runtime_duration.is_none() {
                    return Err(
                        "audit runtime command requires --runtime-duration-seconds before --"
                            .to_owned(),
                    );
                }
                let Some(program) = arguments.get(index + 1) else {
                    return Err("audit runtime command is missing after --".to_owned());
                };
                options.runtime_program = Some(program.clone());
                options.runtime_arguments = arguments[index + 2..].to_vec();
                break;
            }
            if argument == "--output" {
                if destination.is_some() || index + 1 >= arguments.len() {
                    return Err("audit requires exactly one --output DIRECTORY".to_owned());
                }
                destination = Some(&arguments[index + 1]);
                index += 2;
                continue;
            }
            if argument == "--packages" {
                if !selected.insert("packages") {
                    return Err("audit source --packages was specified more than once".to_owned());
                }
                options.packages = true;
                index += 1;
                continue;
            }
            if argument == "--processes" {
                if !selected.insert("processes") {
                    return Err("audit source --processes was specified more than once".to_owned());
                }
                options.processes = true;
                index += 1;
                continue;
            }
            if argument == "--startup" {
                if !selected.insert("startup") {
                    return Err("audit source --startup was specified more than once".to_owned());
                }
                options.startup = true;
                index += 1;
                continue;
            }
            if argument == "--permission" {
                let Some(path) = arguments.get(index + 1) else {
                    return Err("audit --permission requires a path".to_owned());
                };
                options.permission_paths.push(Path::new(path).to_path_buf());
                index += 2;
                continue;
            }
            if argument == "--runtime-duration-seconds" {
                if options.runtime_duration.is_some() || index + 1 >= arguments.len() {
                    return Err(
                        "audit requires exactly one --runtime-duration-seconds value".to_owned(),
                    );
                }
                options.runtime_duration = Some(parse_duration_seconds(&arguments[index + 1])?);
                index += 2;
                continue;
            }
            return Err(format!(
                "unsupported audit argument: {}",
                terminal_safe_path(Path::new(argument))
            ));
        }
        if options.runtime_duration.is_some() && options.runtime_program.is_none() {
            return Err(
                "audit --runtime-duration-seconds must be followed by -- <program> [args...]"
                    .to_owned(),
            );
        }
        let destination =
            destination.ok_or_else(|| "audit requires --output DIRECTORY".to_owned())?;
        let result = collect_and_publish(Path::new(destination), &options)?;
        let state = match result.manifest.status {
            sideeffect::audit_session::SessionStatus::Complete => "complete",
            sideeffect::audit_session::SessionStatus::Partial => "partial",
        };
        eprintln!(
            "Published a {state} best-effort Linux audit session to {} ({} sources, {}–{} Unix milliseconds). Each source was collected in its own interval; this is not an atomic snapshot. Review the local artifacts before sharing.",
            terminal_safe_path(&result.path),
            result.manifest.sources.len(),
            result.manifest.started_at_unix_ms,
            result.manifest.ended_at_unix_ms
        );
        if !result.parent_sync_confirmed {
            eprintln!(
                "Warning: the session directory was published, but syncing its parent directory failed; persistence across sudden power loss is uncertain."
            );
        }
        Ok(
            if result.manifest.status == sideeffect::audit_session::SessionStatus::Complete {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            },
        )
    }
    #[cfg(windows)]
    {
        let mut destination: Option<&OsString> = None;
        let mut options = WindowsAuditOptions::default();
        let mut selected = std::collections::HashSet::new();
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].to_str() {
                Some("--output") if destination.is_none() && index + 1 < arguments.len() => {
                    destination = Some(&arguments[index + 1]);
                    index += 2;
                }
                Some("--packages") if selected.insert("packages") => {
                    options.software = true;
                    index += 1;
                }
                Some("--processes") if selected.insert("processes") => {
                    options.processes = true;
                    index += 1;
                }
                Some("--startup") if selected.insert("startup") => {
                    options.startup = true;
                    index += 1;
                }
                Some("--runtime-source") if selected.insert("runtime") => {
                    options.include_runtime = true;
                    index += 1;
                }
                Some("--permission") if index + 1 < arguments.len() => {
                    options
                        .permission_paths
                        .push(Path::new(&arguments[index + 1]).to_path_buf());
                    index += 2;
                }
                _ => {
                    return Err(format!(
                        "unsupported audit argument: {}",
                        terminal_safe_path(Path::new(&arguments[index]))
                    ));
                }
            }
        }
        let destination =
            destination.ok_or_else(|| "audit requires --output DIRECTORY".to_owned())?;
        let result = collect_windows_audit_and_publish(Path::new(destination), &options)?;
        let state = if result.manifest.status == sideeffect::audit_session::SessionStatus::Complete
        {
            "complete"
        } else {
            "partial"
        };
        eprintln!(
            "Published a {state} best-effort Windows audit session to {} ({} sources, {}–{} Unix milliseconds). Each source was collected in its own interval; this is not an atomic snapshot. Review the local artifacts before sharing.",
            terminal_safe_path(&result.path),
            result.manifest.sources.len(),
            result.manifest.started_at_unix_ms,
            result.manifest.ended_at_unix_ms
        );
        Ok(
            if result.manifest.status == sideeffect::audit_session::SessionStatus::Complete {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            },
        )
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = arguments;
        Err("audit sessions are not supported on this platform".to_owned())
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
    #[cfg(windows)]
    {
        let document = collect_windows_software();
        let complete = document.status == WindowsSoftwareStatus::Complete;
        let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
        serde_json::to_writer(&mut json, &document).map_err(|error| {
            format!("could not serialize Windows software inventory within the {MAX_REPORT_BYTES} byte limit: {error}")
        })?;
        let published =
            publish_private_windows_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
                .map_err(|error| {
                    format!("could not publish private Windows software inventory: {error}")
                })?;
        if complete {
            eprintln!(
                "Saved a complete snapshot of accessible Windows uninstall registry entries to {}. This does not include portable or unregistered software or establish complete software coverage.",
                terminal_safe_path(&published)
            );
            Ok(ExitCode::SUCCESS)
        } else {
            eprintln!(
                "Saved a partial Windows software-registration snapshot to {}. Check its source status and diagnostics; inaccessible or incomplete registrations remain unknown.",
                terminal_safe_path(&published)
            );
            Ok(ExitCode::from(2))
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = output;
        Err("inventory packages is not supported on this platform".to_owned())
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
            "Saved a {} Windows startup-configuration snapshot to {}. It covers selected current-user and accessible machine Run/RunOnce keys, current/common Startup folders, visible service configuration, and boot/logon triggers in tasks visible to the current token; command text remains inert.",
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
    #[cfg(all(not(target_os = "linux"), not(windows)))]
    {
        let _ = (output, paths);
        Err("inventory permissions is not supported on this platform".to_owned())
    }
    #[cfg(windows)]
    {
        let paths = paths
            .iter()
            .map(Path::new)
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        let document = collect_windows_permissions(&paths);
        let complete = document.status == WindowsPermissionStatus::Complete;
        let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
        serde_json::to_writer(&mut json, &document).map_err(|error| {
            format!("could not serialize Windows permission inventory within the {MAX_REPORT_BYTES} byte limit: {error}")
        })?;
        let published =
            publish_private_windows_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
                .map_err(|error| {
                    format!("could not publish private Windows permission inventory: {error}")
                })?;
        eprintln!(
            "Saved a {} Windows explicit-path permission snapshot to {}. It retains the opened object's owner, group, DACL, and ACE evidence; the final reparse point is not followed, no SACL is requested, and effective access is not calculated.",
            if complete { "complete" } else { "partial" },
            terminal_safe_path(&published)
        );
        Ok(if complete {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        })
    }
}

fn parse_windows_duration_seconds(value: &OsString) -> Result<Duration, String> {
    let Some(text) = value.to_str() else {
        return Err(
            "Windows ETW duration must be an ASCII integer from 1 to 60 seconds".to_owned(),
        );
    };
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(
            "Windows ETW duration must be an ASCII integer from 1 to 60 seconds".to_owned(),
        );
    }
    let seconds = text
        .parse::<u64>()
        .map_err(|_| "Windows ETW duration must be an ASCII integer from 1 to 60 seconds")?;
    if !(1..=60).contains(&seconds) {
        return Err("Windows ETW duration must be from 1 to 60 seconds".to_owned());
    }
    Ok(Duration::from_secs(seconds))
}

fn record_windows_etw(
    output: &OsString,
    program: &OsString,
    args: &[OsString],
    duration: Duration,
) -> Result<ExitCode, String> {
    #[cfg(windows)]
    {
        let capture = sideeffect::record::record_windows_runtime_capture(
            Path::new(output),
            program,
            args,
            duration,
        )?;
        eprintln!(
            "Saved {} Windows process/file/network ETW records to {} (collection: {:?}; capture completeness: unknown; ETW loss stats available: {}, final snapshot: {}, observation: {}).",
            capture.events.len(),
            terminal_safe_path(Path::new(output)),
            capture.collection_status,
            capture.event_loss.loss_statistics_available,
            capture.event_loss.final_snapshot_available,
            capture.event_loss.observation,
        );
        if capture.collection_status == sideeffect::record::WindowsRuntimeCollectionStatus::Partial
        {
            return Ok(ExitCode::from(2));
        }
        match capture.target.exit_code {
            None => Ok(ExitCode::SUCCESS),
            Some(code) => match windows_child_exit_code(code) {
                Some(code) => Ok(ExitCode::from(code)),
                None => {
                    eprintln!(
                        "Windows target exit code {code} is outside the 0–255 range representable by this CLI; returning failure."
                    );
                    Ok(ExitCode::FAILURE)
                }
            },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (output, program, args, duration);
        Err("record --windows-etw is available only on native Windows".to_owned())
    }
}

#[cfg(any(windows, test))]
fn windows_child_exit_code(code: i32) -> Option<u8> {
    u8::try_from(code).ok()
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
        "audit" => {
            #[cfg(target_os = "linux")]
            {
                "Usage: sideeffect audit --output NEW_DIRECTORY [--packages] [--processes] [--startup] [--permission PATH]... [--runtime-duration-seconds 1..3600 -- PROGRAM [ARGS...]]
Collects explicitly selected Linux inventory sources and an optional bounded command capture into one local, private session directory. Runtime command arguments stay separate and are passed without a shell. The session stores the native run manifest and raw trace, which may contain sensitive arguments and paths. Each source has its own interval; the session is not an atomic snapshot. Runtime completeness remains unknown, so runtime sources and sessions containing runtime are partial. Partial and unavailable selected sources are preserved and cause exit status 2. Native Windows builds group their separately versioned inventory artifacts; Windows runtime capture remains unsupported."
            }
            #[cfg(windows)]
            {
                "Usage: sideeffect audit --output NEW_DIRECTORY [--packages] [--processes] [--startup] [--permission PATH]... [--runtime-source]\nCollects selected bounded native Windows inventories into one current-user-private session directory. --permission inspects explicitly selected paths only. --runtime-source records that native Windows runtime capture is unsupported; it does not claim an ETW capture. Sessions are non-atomic, and partial/unsupported sources cause exit status 2."
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            {
                "Audit sessions are not supported on this platform."
            }
        }
        "inspect" => {
            "Usage: sideeffect inspect [--format json|text] TRACE\n       sideeffect inspect [--format json|text] --bundle DIR\n       sideeffect inspect [--format json|text] --session DIR\n       sideeffect inspect [--format json|text] --windows-runtime FILE\nReads bounded local strace evidence, a validated run bundle, a verified audit session, or a Windows ETW capture. It never runs represented commands. JSON is the default; text output escapes terminal controls and user-influenced fields. Windows runtime inspection accepts schema v3, validates its document fingerprint and bounds, and does not authenticate authorship or establish capture completeness. Partial input is labeled and exits with status 2."
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
            #[cfg(windows)]
            {
                "Usage: sideeffect record --windows-etw OUTPUT.json --duration-seconds 1..60 -- PROGRAM [ARGS...]\nStarts a bounded native ETW capture for process lifecycle, selected file activity, and TCP/UDP observations. The NT Kernel Logger observes system-wide events during the capture window; this prototype does not attribute every file event to the selected command or its descendants. File records describe observed requests/operations, not guaranteed success. Controlling the NT Kernel Logger requires administrative privileges. No automatic elevation is requested. This is observation, not isolation or a safety check."
            }
            #[cfg(not(windows))]
            {
                "Usage: sideeffect record --trace OUTPUT -- PROGRAM [ARGS...]\n       sideeffect record --bundle DIR -- PROGRAM [ARGS...]\n       sideeffect record --trace OUTPUT --duration-seconds 1..3600 -- PROGRAM [ARGS...]\nRuns the selected program with the current user's permissions under external strace. This is observation, not isolation or a safety check. Available on Linux."
            }
        }
        "inventory" => {
            "Usage: sideeffect inventory packages|processes|startup|permissions --output FILE [PATH...]\nCollects bounded, local snapshots from sources supported on this platform. Sources are curated and coverage can be partial; inspect output and diagnostics before drawing conclusions."
        }
        "inventory startup" => {
            #[cfg(target_os = "linux")]
            {
                "Usage: sideeffect inventory startup --output FILE\nDiscovers supported Linux XDG, systemd, SysV, and cron startup configuration. It does not execute commands or establish that a configured entry ran."
            }
            #[cfg(windows)]
            {
                "Usage: sideeffect inventory startup --output FILE\nReads current-user and accessible machine Run/RunOnce registry values, current/common Startup folders, service configuration, and boot/logon triggers in tasks visible to the current token. It records bounded Exec-action executable paths, arguments, and working directories as inert text; unsupported action types remain labeled unsupported with unknown action-specific fields. Values and paths are not executed or interpreted. It does not establish that a configured entry ran."
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            {
                "Usage: sideeffect inventory startup --output FILE\nStartup inventory is not supported on this platform."
            }
        }
        "inventory packages" => {
            #[cfg(target_os = "linux")]
            {
                "Usage: sideeffect inventory packages --output FILE\nReads available dpkg, RPM, pacman, and APK package databases at fixed Linux paths. Unregistered software and unsupported sources may be missing."
            }
            #[cfg(windows)]
            {
                "Usage: sideeffect inventory packages --output FILE\nReads selected current-user and machine-wide Uninstall registry entries in native and WOW64 views. It does not use Win32_Product or run uninstall commands. Portable or unregistered software may be missing."
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            {
                "Usage: sideeffect inventory packages --output FILE\nPackage inventory is not supported on this platform."
            }
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
            #[cfg(target_os = "linux")]
            {
                "Usage: sideeffect inventory permissions --output FILE PATH...\nInspects only explicit Linux paths for metadata, supported POSIX ACLs, and file capabilities. It does not recurse or calculate effective access."
            }
            #[cfg(windows)]
            {
                "Usage: sideeffect inventory permissions --output FILE PATH...\nInspects only explicit Windows paths. It reads owner, group, DACL, ordered ACEs, and metadata from the same handle, does not follow the final reparse point, does not request SACLs, and does not calculate effective access. No elevation is requested."
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            {
                "Usage: sideeffect inventory permissions --output FILE PATH...\nPermission inventory is not supported on this platform."
            }
        }
        "correlate-startup" => {
            "Usage: sideeffect correlate-startup STARTUP_INVENTORY.json TRACE\nFinds narrow exact-path candidate matches between supported saved startup configuration and successful exec evidence. A match does not prove that a hook caused or initiated execution."
        }
        "model" => {
            "Usage: sideeffect model list\n       sideeffect model show ID\n       sideeffect model install ID\n       sideeffect model setup ID\n       sideeffect model add --name NAME --path FILE --for evidence|explanation|query [--license ID]\n       sideeffect model select evidence|explanation|query ID\n       sideeffect model remove ID\n\nLists pinned catalog candidates and user-provided models. Catalog evaluation status is shown separately from runtime compatibility. Installing a catalog model requires explicit license acceptance; analysis never downloads weights implicitly. The setup command installs and selects the catalog model for its declared task. Registering a local model records its size and SHA-256, but does not verify task compatibility, licensing, or quality. Removing a custom registration leaves the model file untouched. Select a model for its task before running a model preview."
        }
        "model setup" => {
            "Usage: sideeffect model setup MODEL_ID\nShows the catalog license and model evaluation status, downloads the exact pinned file after explicit typed acceptance, verifies its size and SHA-256, then selects it for its declared task. The local inference runtime is installed or built separately and its path is still supplied to analysis commands."
        }
        "model list" => {
            "Usage: sideeffect model list\nLists pinned catalog candidates, installation status, task, license, exact size, evaluation status, and selected model per task. Every listed model's SHA-256 is rechecked before use."
        }
        "model add" => {
            "Usage: sideeffect model add --name NAME --path FILE --for evidence|explanation|query[,TASK...] [--license ID]\nRegisters an existing local GGUF by bounded size and SHA-256. The path and optional license ID are user-provided metadata; task compatibility and answer quality are not verified. The model remains opt-in and unreviewed until selected."
        }
        "model select" => {
            "Usage: sideeffect model select evidence|explanation|query MODEL_ID\nSelects a registered or installed model for one analysis task. The exact model identity is included in each preview digest and checked again before inference."
        }
        "model remove" => {
            "Usage: sideeffect model remove MODEL_ID\nFor a catalog model, requires typing the exact ID and removes only that verified catalog file plus task selections. For a user-provided model, removes only its registration; the original file is left untouched."
        }
        "model-preview" => {
            "Usage: sideeffect model-preview --question QUESTION TRACE\nPreviews the bounded typed facts, selected evidence model identity, JSON schema, and request digest. Select and install a model first with the model commands. Review this exact request before confirming local analysis. Partial parsing is visible and exits with status 2."
        }
        "model-analyze" => {
            "Usage: sideeffect model-analyze --question QUESTION --runtime LLAMA_CLI --confirm-sha256 REQUEST_SHA256 TRACE\nRuns the selected local evidence model on Linux x86_64 after explicit digest confirmation. The model may select at most one source evidence ID as an unverified hint; it can be wrong and is not a finding. SideEffect does not upload evidence. See docs/LOCAL_MODEL_EVALUATION.md."
        }
        "model-explain-preview" => {
            "Usage: sideeffect model-explain-preview --question QUESTION --backend auto|cpu|cuda TRACE\nPreviews the bounded typed evidence, coverage, and selected explanation model identity. Review the exact prompt and digest before inference. 'auto' prefers a supported GPU and otherwise reports CPU use; it does not silently fall back after a GPU failure. This command does not run a model."
        }
        "model-explain" => {
            "Usage: sideeffect model-explain --question QUESTION --backend auto|cpu|cuda --runtime LLAMA_COMPLETION --confirm-sha256 REQUEST_SHA256 TRACE\nRuns the selected local explanation model after confirmation of the exact evidence preview. The model receives bounded typed evidence and coverage; every generated statement must cite a source evidence ID and remains unverified. 'auto' prefers CUDA when the pinned runtime reports a device; CUDA errors do not silently fall back to CPU. SideEffect does not upload data or auto-download a model during analysis. The selected runtime is executable code that must be trusted separately; see docs/LOCAL_MODEL_EXPLANATION_EVALUATION.md."
        }
        "model-query-preview" => {
            "Usage: sideeffect model-query-preview --question QUESTION TRACE\nPreviews the bounded local query request, selected model identity, and typed evidence facts. Queryable facts are shown for review but are not sent to the model. Review this exact question, scope, and digest before optional local inference. Partial input exits with status 2."
        }
        "model-query" => {
            "Usage: sideeffect model-query --question QUESTION --runtime LLAMA_COMPLETION --confirm-sha256 REQUEST_SHA256 TRACE\nRuns the selected optional local query model on Linux x86_64 only after explicit preview-digest confirmation. It executes only validated exact-match AND filters over observed typed facts, never commands or model-authored expressions. No model is downloaded during analysis or evidence uploaded. Model results are unverified review aids. See docs/LOCAL_QUERY_PLAN_EVALUATION.md."
        }
        _ => return Err(format!("unknown help topic: {topic}\n\n{USAGE}")),
    };
    println!("{text}");
    Ok(ExitCode::SUCCESS)
}

fn inspect(path: &OsString) -> Result<ExitCode, String> {
    inspect_with_format(&OsString::from("json"), path)
}

fn inspect_session_with_format(format: &OsString, path: &OsString) -> Result<ExitCode, String> {
    if !matches!(format.to_str(), Some("json" | "text")) {
        return Err("inspect format must be either 'json' or 'text'".to_owned());
    }
    #[cfg(target_os = "linux")]
    {
        let session =
            sideeffect::audit_session_reader_linux::read_verified_session(Path::new(path))
                .map_err(|error| format!("audit session verification failed: {error}"))?;
        let partial =
            session.manifest().status == sideeffect::audit_session::SessionStatus::Partial;
        match format.to_str() {
            Some("json") => {
                let mut output = CappedBuffer::new(MAX_REPORT_BYTES);
                sideeffect::format::write_audit_session_json(session.manifest(), &mut output)
                    .map_err(|error| {
                        if output.exceeded {
                            format!("audit session review exceeds the {MAX_REPORT_BYTES} byte output limit")
                        } else {
                            format!("could not serialize audit session review: {error}")
                        }
                    })?;
                output.write_all(b"\n").map_err(|_| {
                    format!("audit session review exceeds the {MAX_REPORT_BYTES} byte output limit")
                })?;
                write_buffer(&output, "audit session review")?;
            }
            Some("text") => {
                let mut output = CappedBuffer::new(MAX_REPORT_BYTES);
                sideeffect::format::write_audit_session_text(session.manifest(), &mut output)
                    .map_err(|error| {
                        if output.exceeded {
                            format!("audit session review exceeds the {MAX_REPORT_BYTES} byte output limit")
                        } else {
                            format!("could not render audit session review: {error}")
                        }
                    })?;
                output.write_all(b"\n").map_err(|_| {
                    format!("audit session review exceeds the {MAX_REPORT_BYTES} byte output limit")
                })?;
                write_buffer(&output, "audit session review")?;
            }
            _ => unreachable!("format was checked above"),
        }
        Ok(if partial {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        })
    }
    #[cfg(windows)]
    {
        let session =
            sideeffect::audit_session_reader_windows::read_verified_session(Path::new(path))
                .map_err(|error| format!("audit session verification failed: {error}"))?;
        let partial =
            session.manifest().status == sideeffect::audit_session::SessionStatus::Partial;
        match format.to_str() {
            Some("json") => {
                let mut output = CappedBuffer::new(MAX_REPORT_BYTES);
                sideeffect::format::write_audit_session_json(session.manifest(), &mut output)
                    .map_err(|error| {
                        format!("could not serialize audit session review: {error}")
                    })?;
                output
                    .write_all(b"\n")
                    .map_err(|_| "audit session review output limit exceeded".to_owned())?;
                write_buffer(&output, "audit session review")?;
            }
            Some("text") => {
                let mut output = CappedBuffer::new(MAX_REPORT_BYTES);
                sideeffect::format::write_audit_session_text(session.manifest(), &mut output)
                    .map_err(|error| format!("could not render audit session review: {error}"))?;
                output
                    .write_all(b"\n")
                    .map_err(|_| "audit session review output limit exceeded".to_owned())?;
                write_buffer(&output, "audit session review")?;
            }
            _ => unreachable!("format was checked above"),
        }
        Ok(if partial {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        })
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = path;
        Err("audit-session inspection is not supported on this platform".to_owned())
    }
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

fn inspect_windows_runtime_with_format(
    format: &OsString,
    path: &OsString,
) -> Result<ExitCode, String> {
    if !matches!(format.to_str(), Some("json" | "text")) {
        return Err("inspect format must be either 'json' or 'text'".to_owned());
    }
    let bytes = read_input_file(
        Path::new(path),
        sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        "Windows runtime capture",
    )?;
    let source_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let capture = sideeffect::windows_runtime::inspect_windows_runtime_bytes(&bytes)?;
    let partial =
        capture.collection_status == sideeffect::windows_runtime::CollectionStatus::Partial;
    match format.to_str() {
        Some("json") => {
            let inspection = sideeffect::windows_runtime::WindowsRuntimeInspection {
                schema: sideeffect::windows_runtime::WINDOWS_RUNTIME_INSPECTION_SCHEMA,
                schema_version:
                    sideeffect::windows_runtime::WINDOWS_RUNTIME_INSPECTION_SCHEMA_VERSION,
                validation_status: "validated_untrusted_document",
                source_sha256: &source_sha256,
                representation_fingerprint_verified: true,
                authenticity: "not_verified",
                capture_completeness: &capture.capture_completeness,
                capture_claimed_status: capture.collection_status,
                capture: &capture,
            };
            write_json(&inspection, "Windows runtime inspection")?;
        }
        Some("text") => {
            let mut output = CappedBuffer::new(MAX_REPORT_BYTES);
            sideeffect::format::write_windows_runtime_text(&capture, &mut output).map_err(
                |error| {
                    if output.exceeded {
                        format!(
                            "Windows runtime text exceeds the {MAX_REPORT_BYTES} byte output limit"
                        )
                    } else {
                        format!("could not render Windows runtime inspection: {error}")
                    }
                },
            )?;
            output.write_all(b"Source file SHA-256: ").map_err(|_| {
                format!("Windows runtime text exceeds the {MAX_REPORT_BYTES} byte output limit")
            })?;
            output.write_all(source_sha256.as_bytes()).map_err(|_| {
                format!("Windows runtime text exceeds the {MAX_REPORT_BYTES} byte output limit")
            })?;
            output.write_all(b"\n").map_err(|_| {
                format!("Windows runtime text exceeds the {MAX_REPORT_BYTES} byte output limit")
            })?;
            write_buffer(&output, "Windows runtime inspection")?;
        }
        _ => unreachable!("format was checked above"),
    }
    Ok(if partial {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
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
    let model = selected_model(ModelTask::EvidenceSelection)?;
    let preview = sideeffect::local_model::preview_trace_bytes_for_model(&bytes, question, &model)?;
    let partial = preview.evidence_summary["parse_status"] == "partial";
    write_json(&preview, "local model request preview")?;
    Ok(if partial {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn model_query_preview_file(question: &OsString, path: &OsString) -> Result<ExitCode, String> {
    let question = question
        .to_str()
        .ok_or("local query question must be valid UTF-8")?;
    let bytes = read_bounded(path)?;
    let model = selected_model(ModelTask::QueryPlan)?;
    let preview =
        sideeffect::local_query_plan::preview_query_plan_bytes_for_model(&bytes, question, &model)?;
    let partial = preview.evidence_summary["parse_status"] == "partial";
    write_json(&preview, "local query-plan preview")?;
    Ok(if partial {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn model_explanation_preview_file(
    question: &OsString,
    backend: &OsString,
    path: &OsString,
) -> Result<ExitCode, String> {
    let question = question
        .to_str()
        .ok_or("local model question must be valid UTF-8")?;
    let backend = match backend.to_str() {
        Some("auto") => sideeffect::local_model_explanation::ExplanationBackendPreference::Auto,
        Some("cpu") => sideeffect::local_model_explanation::ExplanationBackendPreference::Cpu,
        Some("cuda") => sideeffect::local_model_explanation::ExplanationBackendPreference::Cuda,
        _ => return Err("model explanation backend must be auto, cpu, or cuda".to_owned()),
    };
    let bytes = read_bounded(path)?;
    let model = selected_model(ModelTask::Explanation)?;
    let preview = sideeffect::local_model_explanation::preview_model_explanation_bytes_for_model(
        &bytes, question, backend, &model,
    )?;
    let partial = preview.evidence_summary["parse_status"] == "partial";
    write_json(
        &preview,
        "local evidence-grounded model explanation preview",
    )?;
    Ok(if partial {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn model_query_file(
    question: &OsString,
    runtime: &OsString,
    digest: &OsString,
    trace: &OsString,
) -> Result<ExitCode, String> {
    let question = question
        .to_str()
        .ok_or("local query question must be valid UTF-8")?;
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
    let model = selected_model(ModelTask::QueryPlan)?;
    let analysis = sideeffect::local_query_plan::analyze_query_plan_bytes_for_model(
        &bytes,
        question,
        Path::new(runtime),
        &model,
        digest,
    )?;
    let partial = analysis.coverage["parse_status"] == "partial";
    write_json(&analysis, "local query-plan analysis")?;
    Ok(if partial {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn model_explanation_file(
    question: &OsString,
    backend: &OsString,
    runtime: &OsString,
    digest: &OsString,
    trace: &OsString,
) -> Result<ExitCode, String> {
    let question = question
        .to_str()
        .ok_or("local model question must be valid UTF-8")?;
    let backend = match backend.to_str() {
        Some("auto") => sideeffect::local_model_explanation::ExplanationBackendPreference::Auto,
        Some("cpu") => sideeffect::local_model_explanation::ExplanationBackendPreference::Cpu,
        Some("cuda") => sideeffect::local_model_explanation::ExplanationBackendPreference::Cuda,
        _ => return Err("model explanation backend must be auto, cpu, or cuda".to_owned()),
    };
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
    let model = selected_model(ModelTask::Explanation)?;
    let analysis =
        sideeffect::local_model_explanation_runtime::analyze_model_explanation_bytes_for_model(
            &bytes,
            question,
            backend,
            Path::new(runtime),
            &model,
            digest,
        )?;
    let partial = analysis.evidence_summary["parse_status"] == "partial"
        || analysis.interpretation.status
            != sideeffect::local_model_explanation::ExplanationStatus::Answered;
    write_json(&analysis, "local evidence-grounded model explanation")?;
    Ok(if partial {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn model_analyze_file(
    question: &OsString,
    runtime: &OsString,
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
    let model = selected_model(ModelTask::EvidenceSelection)?;
    let analysis = sideeffect::local_model::analyze_trace_bytes_for_model(
        &bytes,
        question,
        Path::new(runtime),
        &model,
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

fn selected_model(task: ModelTask) -> Result<ResolvedModel, String> {
    if !model_task_supported_here(task) {
        return Err(format!(
            "local model task '{}' is not supported on this platform",
            model_task_label(task)
        ));
    }
    sideeffect::model_manager::load_registry()?.selected(task)
}

fn model_list() -> Result<ExitCode, String> {
    use sideeffect::model_manager::{CATALOG, model_store_directory};

    let registry = sideeffect::model_manager::load_registry()?;
    println!("Pinned catalog (runtime compatibility is separate from model quality):");
    let model_directory = model_store_directory()?.join("models");
    for model in CATALOG {
        let path = model_directory.join(model.filename);
        let installed = match fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.is_file()
                    && metadata.len() == model.size_bytes
                    && !metadata.file_type().is_symlink() =>
            {
                "installed; SHA-256 is rechecked before use"
            }
            Ok(_) => "present but does not match the pinned file metadata",
            Err(error) if error.kind() == io::ErrorKind::NotFound => "not installed",
            Err(_) => "installation status unavailable",
        };
        let selected = registry
            .selected_by_task
            .get(&model.task)
            .is_some_and(|id| id == model.id);
        let license_accepted = registry.accepted_licenses.iter().any(|accepted| {
            accepted.model_id == model.id
                && accepted.revision == model.revision
                && accepted.license_id == model.license_id
                && accepted.license_url == model.license_url
        });
        println!(
            "- {} — {}\n  task: {}; platform: {}; size: {}; license: {} ({})\n  evaluation: {}; source: {} @ {}\n  license accepted: {}; status: {}{}",
            model.id,
            terminal_safe_text(model.name),
            model_task_label(model.task),
            model_task_platform(model.task),
            human_file_size(model.size_bytes),
            model.license_id,
            model.license_url,
            evaluation_status_label(model.evaluation),
            model.repository,
            model.revision,
            license_accepted,
            installed,
            if selected { "; selected" } else { "" }
        );
    }
    if registry.custom_models.is_empty() {
        println!("No user-provided models are registered.");
    } else {
        println!("User-provided models (unreviewed):");
        for model in &registry.custom_models {
            let tasks = model
                .tasks
                .iter()
                .map(|task| model_task_label(*task))
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "- {} — {}\n  tasks: {}; size: {}; SHA-256: {}\n  license: {}; evaluation: not assessed{}",
                model.id,
                terminal_safe_text(&model.name),
                tasks,
                human_file_size(model.size_bytes),
                model.sha256,
                model
                    .license_id
                    .as_deref()
                    .map(terminal_safe_text)
                    .unwrap_or_else(|| "not provided".to_owned()),
                if model.path.exists() {
                    ""
                } else {
                    " (registered file is missing; selection will fail)"
                }
            );
        }
    }
    for task in [
        ModelTask::EvidenceSelection,
        ModelTask::Explanation,
        ModelTask::QueryPlan,
    ] {
        println!(
            "Selected for {}: {}",
            model_task_label(task),
            registry
                .selected_by_task
                .get(&task)
                .map(String::as_str)
                .unwrap_or("none")
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn model_show(id: &OsString) -> Result<ExitCode, String> {
    let id = id.to_str().ok_or("model ID must be valid UTF-8")?;
    let registry = sideeffect::model_manager::load_registry()?;
    if let Some(model) = sideeffect::model_manager::catalog_model(id) {
        let path = sideeffect::model_manager::model_store_directory()?
            .join("models")
            .join(model.filename);
        let installation = match fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() == model.size_bytes =>
            {
                "file size matches catalog; SHA-256 is rechecked before use"
            }
            Ok(_) => "present but not the pinned size or file type",
            Err(error) if error.kind() == io::ErrorKind::NotFound => "not installed",
            Err(_) => "installation status unavailable",
        };
        let value = serde_json::json!({
            "catalog_entry": model,
            "installation_status": installation,
            "license_terms_url": model.license_url,
            "recommended_for_accuracy": false,
        });
        write_json(&value, "model catalog entry")?;
        return Ok(ExitCode::SUCCESS);
    }
    let model = registry
        .custom_models
        .iter()
        .find(|model| model.id == id)
        .ok_or_else(|| "model ID is not present in the catalog or user registry".to_owned())?;
    write_json(model, "registered user-provided model")?;
    Ok(ExitCode::SUCCESS)
}

fn model_install(id: &OsString, select_after_install: bool) -> Result<ExitCode, String> {
    let id = id.to_str().ok_or("model ID must be valid UTF-8")?;
    let model = sideeffect::model_manager::catalog_model(id).ok_or_else(|| {
        "model ID is not in the pinned catalog; install accepts catalog IDs only".to_owned()
    })?;
    println!("Model: {}", terminal_safe_text(model.name));
    println!(
        "Source: {} at revision {}",
        model.repository, model.revision
    );
    println!(
        "File: {} ({})",
        model.filename,
        human_file_size(model.size_bytes)
    );
    println!("License: {}", model.license_id);
    println!("Review license terms at: {}", model.license_url);
    println!("Platform support: {}", model_task_platform(model.task));
    println!("Evaluation: {}", evaluation_status_label(model.evaluation));
    println!(
        "Evaluation note: {}",
        terminal_safe_text(model.evaluation_note)
    );
    if !model_task_supported_here(model.task) {
        return Err("this model task is not supported on the current platform".to_owned());
    }
    println!(
        "This download sends no trace or prompt data. It contacts Hugging Face hosts only to fetch the pinned model file."
    );
    print!(
        "After reviewing the linked terms, type ACCEPT {} to continue: ",
        model.license_id
    );
    io::stdout()
        .flush()
        .map_err(|error| format!("could not display license confirmation prompt: {error}"))?;
    let answer = read_model_confirmation()?;
    if answer.trim() != format!("ACCEPT {}", model.license_id) {
        return Err("model download cancelled; license acceptance was not confirmed".to_owned());
    }
    let mut last_reported = 0_u64;
    let receipt = sideeffect::model_installer::install_catalog_model(
        id,
        model.license_id,
        model.license_url,
        true,
        |progress| {
            if progress.received_bytes == progress.expected_bytes
                || progress.received_bytes.saturating_sub(last_reported) >= 64 * 1024 * 1024
            {
                last_reported = progress.received_bytes;
                print!(
                    "\rDownloaded {} of {}",
                    human_file_size(progress.received_bytes),
                    human_file_size(progress.expected_bytes)
                );
                io::stdout().flush().is_ok()
            } else {
                true
            }
        },
    )?;
    if select_after_install {
        sideeffect::model_manager::update_registry(|registry| {
            registry.resolve(id, model.task)?;
            registry.select(model.task, id)
        })?;
        println!(
            "\nInstalled and selected {} for {} ({} bytes, SHA-256 {}).",
            receipt.id,
            model_task_label(model.task),
            receipt.size_bytes,
            receipt.sha256
        );
    } else {
        println!(
            "\nInstalled {} ({} bytes, SHA-256 {}). Select it with `sideeffect model select {} {}` before analysis.",
            receipt.id,
            receipt.size_bytes,
            receipt.sha256,
            match model.task {
                ModelTask::EvidenceSelection => "evidence",
                ModelTask::Explanation => "explanation",
                ModelTask::QueryPlan => "query",
            },
            receipt.id
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn model_add(arguments: &[OsString]) -> Result<ExitCode, String> {
    let mut name = None;
    let mut path = None;
    let mut tasks = Vec::new();
    let mut license = None;
    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index]
            .to_str()
            .ok_or("model registration option must be valid UTF-8")?;
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("missing value for model registration option {option}"))?;
        match option {
            "--name" => {
                name = Some(
                    value
                        .to_str()
                        .ok_or("model name must be valid UTF-8")?
                        .to_owned(),
                );
            }
            "--path" => path = Some(Path::new(value).to_path_buf()),
            "--for" => {
                let value = value
                    .to_str()
                    .ok_or("model task list must be valid UTF-8")?;
                for task in value.split(',') {
                    let task = parse_model_task(task)?;
                    if !tasks.contains(&task) {
                        tasks.push(task);
                    }
                }
            }
            "--license" => {
                license = Some(
                    value
                        .to_str()
                        .ok_or("model license ID must be valid UTF-8")?
                        .to_owned(),
                );
            }
            _ => return Err(format!("unknown model registration option: {option}")),
        }
        index += 2;
    }
    let name = name.ok_or("model add requires --name NAME")?;
    let path = path.ok_or("model add requires --path FILE")?;
    if tasks.iter().any(|task| !model_task_supported_here(*task)) {
        return Err(
            "one or more requested model tasks are not supported on this platform".to_owned(),
        );
    }
    let id = sideeffect::model_manager::update_registry(|registry| {
        registry.register_custom(&name, &path, license.as_deref(), tasks)
    })?;
    println!(
        "Registered {} as {}. It is user-provided and unreviewed; its SHA-256 will be rechecked before use.",
        terminal_safe_path(&path),
        id
    );
    Ok(ExitCode::SUCCESS)
}

fn model_select(task: &OsString, id: &OsString) -> Result<ExitCode, String> {
    let task = parse_model_task(task.to_str().ok_or("model task must be valid UTF-8")?)?;
    if !model_task_supported_here(task) {
        return Err(format!(
            "local model task '{}' is not supported on this platform",
            model_task_label(task)
        ));
    }
    let id = id.to_str().ok_or("model ID must be valid UTF-8")?;
    let model = sideeffect::model_manager::update_registry(|registry| {
        // Resolve before changing persistent selection. This checks installation,
        // current file bounds, and its digest for catalog and custom models.
        let model = registry.resolve(id, task)?;
        registry.select(task, id)?;
        Ok(model)
    })?;
    println!(
        "Selected {} for {}. Evaluation status: {}; this does not certify answer quality.",
        model.id,
        model_task_label(task),
        evaluation_status_label(model.evaluation)
    );
    Ok(ExitCode::SUCCESS)
}

fn model_remove(id: &OsString) -> Result<ExitCode, String> {
    let id = id.to_str().ok_or("model ID must be valid UTF-8")?;
    if sideeffect::model_manager::catalog_model(id).is_some() {
        println!("This will delete the installed, hash-verified catalog model file for {id}.");
        print!("Type DELETE {id} to confirm: ");
        io::stdout()
            .flush()
            .map_err(|error| format!("could not display model removal prompt: {error}"))?;
        let answer = read_model_confirmation()?;
        if answer.trim() != format!("DELETE {id}") {
            return Err("model removal cancelled".to_owned());
        }
        let path = sideeffect::model_installer::remove_catalog_model(id, true)?;
        println!(
            "Removed verified catalog model {}.",
            terminal_safe_path(&path)
        );
        return Ok(ExitCode::SUCCESS);
    }
    sideeffect::model_manager::update_registry(|registry| registry.unregister(id))?;
    println!("Unregistered {id}. The model file was left untouched.");
    Ok(ExitCode::SUCCESS)
}

fn parse_model_task(task: &str) -> Result<ModelTask, String> {
    match task {
        "evidence" | "evidence-selection" => Ok(ModelTask::EvidenceSelection),
        "explanation" => Ok(ModelTask::Explanation),
        "query" | "query-plan" => Ok(ModelTask::QueryPlan),
        _ => Err("model task must be evidence, explanation, or query".to_owned()),
    }
}

fn model_task_label(task: ModelTask) -> &'static str {
    match task {
        ModelTask::EvidenceSelection => "evidence selection",
        ModelTask::Explanation => "explanation",
        ModelTask::QueryPlan => "query plan",
    }
}

fn model_task_platform(task: ModelTask) -> &'static str {
    match task {
        ModelTask::EvidenceSelection | ModelTask::QueryPlan => "Linux x86_64 only",
        ModelTask::Explanation => "Linux x86_64 and native Windows",
    }
}

fn model_task_supported_here(task: ModelTask) -> bool {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let _ = task;
        true
    }
    #[cfg(windows)]
    {
        task == ModelTask::Explanation
    }
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64"), windows)))]
    {
        let _ = task;
        false
    }
}

fn evaluation_status_label(status: EvaluationStatus) -> &'static str {
    match status {
        EvaluationStatus::FailedTriage => "failed a triage check; not recommended",
        EvaluationStatus::FailedFrozenGate => "failed the frozen evaluation gate; not recommended",
        EvaluationStatus::FailedDevelopmentCheck => "failed a development check; not recommended",
        EvaluationStatus::NotAssessed => "not assessed; not recommended",
    }
}

fn human_file_size(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    format!("{} MiB ({bytes} bytes)", bytes.div_ceil(MIB))
}

fn terminal_safe_text(value: &str) -> String {
    use std::fmt::Write as _;
    let mut escaped = String::new();
    for character in value.chars() {
        if character.is_ascii() && !character.is_control() && character != '\\' {
            escaped.push(character);
        } else {
            let _ = write!(escaped, "\\u{{{:x}}}", character as u32);
        }
    }
    escaped
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
    fn windows_child_exit_code_does_not_wrap_out_of_range_values() {
        assert_eq!(super::windows_child_exit_code(0), Some(0));
        assert_eq!(super::windows_child_exit_code(255), Some(255));
        assert_eq!(super::windows_child_exit_code(256), None);
        assert_eq!(super::windows_child_exit_code(-1), None);
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
