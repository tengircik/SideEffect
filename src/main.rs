use std::env;
use std::ffi::{OsStr, OsString};
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, BufRead, Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

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
use sideeffect::inventory::{AccessOperation, analyze_current_process_access};
#[cfg(windows)]
use sideeffect::inventory::{AppPathStatus, collect_windows_app_paths};
#[cfg(target_os = "linux")]
use sideeffect::inventory::{InventoryStatus, collect_packages};
use sideeffect::inventory::{
    PackageComparisonStatus, PermissionDiffStatus, ProcessDiffStatus, StartupDiffStatus,
    WindowsSoftwareComparisonStatus, compare_package_inventory_json,
    compare_permission_inventory_json, compare_process_inventory_json,
    compare_selected_root_inventory_json, compare_startup_inventory_json,
    compare_windows_software_inventory_json, is_permission_inventory_json,
    is_process_inventory_json, is_selected_root_inventory_json, is_startup_inventory_json,
    is_windows_software_inventory_json,
};
use sideeffect::inventory::{PathExecutableInventory, collect_path_executables};
#[cfg(target_os = "linux")]
use sideeffect::inventory::{PermissionInventoryStatus, collect_permissions};
#[cfg(target_os = "linux")]
use sideeffect::inventory::{ProcessInventoryStatus, collect_processes};
use sideeffect::inventory::{RootSnapshot, collect_root_snapshot, collect_root_snapshot_with_hash};
#[cfg(target_os = "linux")]
use sideeffect::inventory::{StartupInventoryStatus, collect_startup};
#[cfg(windows)]
use sideeffect::inventory::{
    WindowsAccessOperation, WindowsAccessStatus, evaluate_windows_dacl_for_process,
};
#[cfg(windows)]
use sideeffect::inventory::{WindowsMsixStatus, collect_windows_msix};
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
use sideeffect::model_manager::{
    ConfiguredRuntime, EvaluationStatus, ModelRegistry, ModelTask, ResolvedModel,
};
#[cfg(target_os = "linux")]
use sideeffect::record::AnchoredOutput;
#[cfg(target_os = "linux")]
use sideeffect::record::publish_private_file;
#[cfg(windows)]
use sideeffect::record::publish_private_windows_file;
use sideeffect::startup_correlation::correlate_startup_bytes;
use sideeffect::trace::strace::parse_trace_bytes;

const USAGE: &str = "Usage: sideeffect inspect [--format json|text] <strace-trace-file>\n       sideeffect inspect [--format json|text] --bundle <run-bundle-directory>\n       sideeffect inspect [--format json|text] --session <audit-session-directory>\n       sideeffect inspect [--format json|text] --windows-runtime <capture.json>\n       sideeffect inspect --format html --output <report.html> --windows-runtime <capture.json>\n       sideeffect evidence <strace-trace-file> <sha256> <line> <byte-offset> <byte-length>\n       sideeffect evidence --windows-runtime <capture.json> <capture-sha256> <record-ordinal> <payload-sha256> (native Windows)\n       sideeffect diff [--format json|text] <baseline-trace> <candidate-trace>\n       sideeffect diff --format html --output <report.html> <baseline-trace> <candidate-trace>\n       sideeffect diff --bundles [--format json|text] <baseline-bundle> <candidate-bundle>\n       sideeffect diff --bundles --format html --output <report.html> <baseline-bundle> <candidate-bundle>\n       sideeffect diff --windows-runtime [--format json|text] <before-capture.json> <after-capture.json>\n       sideeffect diff --format html --output <report.html> --windows-runtime <before-capture.json> <after-capture.json> (native Windows)\n       sideeffect diff-summary [--format json] <baseline-trace> <candidate-trace>\n       sideeffect diff-summary --format html --output <summary.html> <baseline-trace> <candidate-trace>\n       sideeffect inventory packages --output <new-inventory.json>\n\
       sideeffect explain <strace-trace-file>\n\
       sideeffect explain --diff <baseline-trace> <candidate-trace>\n\
       sideeffect explain --inventory-diff <before.json> <after.json>\n\
       sideeffect compare-sessions <before-session-directory> <after-session-directory>\n\
       sideeffect case init --output <new-case.json> --title <title> --session <session-directory>...\n\
       sideeffect case migrate --case <v1.json> --status draft|open --output <v2.json> --session <session-directory>...\n\
       sideeffect case set-status --case <v2.json> --status <status> --output <new-v2.json> --session <session-directory>...\n\
       sideeffect case add-entry --case <v2.json> --entry <entry.json> --output <new-v2.json> --session <session-directory>...\n\
       sideeffect case add-note --case <v2.json> --id <entry-id> --text-file <note.txt> --output <new-v2.json> --session <session-directory>...\n\
       sideeffect case add-evidence --case <v2.json> --id <entry-id> --kind note|assertion --text-file <text.txt> --evidence-file <locators.json> --output <new-v2.json> --session <session-directory>...\n\
       sideeffect case show --case <case.json> [--format json|text]\n\
       sideeffect case resolve [--format json|text|html] [--redact case-text|artifact-paths|source-records|evidence-identifiers]... [--preview-redaction | --output <new-report.html>] --case <case.json> --session <session-directory>...\n\
       sideeffect model-preview --question <question> <strace-trace-file>\n\
       sideeffect model-analyze --question <question> [--runtime <llama-cli>] --confirm-sha256 <preview-digest> <strace-trace-file>\n\
       sideeffect model-explain-preview --question <question> --backend auto|cpu|cuda <strace-trace-file>\n\
       sideeffect model-explain-preview --question <question> --backend auto|cpu|cuda --windows-runtime <capture.json>\n\
       sideeffect model-explain --question <question> --backend auto|cpu|cuda [--runtime <llama-completion>] --confirm-sha256 <preview-digest> <strace-trace-file>\n\
       sideeffect model-explain --question <question> --backend auto|cpu|cuda [--runtime <llama-completion>] --confirm-sha256 <preview-digest> --windows-runtime <capture.json>\n\
       sideeffect model-query-preview --question <question> <strace-trace-file>\n\
       sideeffect model-query --question <question> [--runtime <llama-completion>] --confirm-sha256 <preview-digest> <strace-trace-file>\n\
       sideeffect query --query <query.json> --trace <trace> | --windows-runtime <capture.json>\n\
       sideeffect query --query <query.json> --session <session-directory> --source runtime|selected_root\n\
       sideeffect model list | show <id> | install <id> | setup <id> [--runtime <existing-file>] | add | select <task> <id> | remove <id>\n\
       sideeffect model runtime set <task> <existing-file> | show [task] | clear <task>\n\
       sideeffect model doctor --task evidence|explanation|query [--runtime <task-runtime>] [--backend auto|cpu|cuda]\n\
       sideeffect correlate-startup <startup-inventory.json> <strace-trace-file>\n\
       sideeffect associated-behavior <startup-inventory.json> <runtime-evidence-file>\n\
       sideeffect attribute --windows-runtime <capture.json>\n\
       sideeffect inventory processes --output <new-inventory.json>\n\
       sideeffect inventory startup --output <new-inventory.json>\n\
       sideeffect inventory path-executables --output <new-inventory.json>\n\
       sideeffect inventory app-paths --output <new-inventory.json> (native Windows)\n\
       sideeffect inventory msix --output <new-inventory.json> (native Windows)\n\
       sideeffect inventory root --output <new-inventory.json> <selected-directory>\n\
       sideeffect inventory permissions --output <new-inventory.json> <path>...\n\
       sideeffect inventory access-check --operation read|write|execute --output <new-result.json> <absolute-path> (Linux; current credentials)\n\
       sideeffect inventory access-check --pid <pid> --creation-time-filetime <100ns-value> --operation read|write|execute --output <new-result.json> <absolute-path> (Windows)\n\
       sideeffect audit --output <new-session-directory> [--packages] [--msix (native Windows)] [--app-paths (native Windows)] [--processes] [--startup] [--path-executables] [--root <directory> [--hash-regular-files]] [--permission <path>]... [--runtime-duration-seconds <1..3600> -- <program> [args...]]\n\
       sideeffect record --trace <new-trace-file> -- <program> [args...]\n       sideeffect record --bundle <new-bundle-directory> -- <program> [args...]\n       sideeffect record --trace <new-trace-file> --duration-seconds <1..3600> -- <program> [args...]\n       sideeffect record --bundle <new-bundle-directory> --duration-seconds <1..3600> -- <program> [args...]\n       sideeffect help [command [subcommand]]\n       sideeffect version\n       sideeffect --help\n       sideeffect --version\n\nInspect reads one bounded strace text file or a validated local run bundle and writes JSON evidence by default, or terminal-safe text with --format text. Evidence verifies the supplied SHA-256 fingerprint, then checks an exact line/byte/length tuple against one parsed row. The fingerprint identifies bytes but does not authenticate them or prove capture completeness. Diff compares two complete parsed traces, or validates two local run bundles with --bundles, and writes observed syscall-row differences to stdout (JSON by default), or a local offline HTML report on Linux. Diff-summary creates a separate aggregate-only export and omits event strings, hashes, and evidence references; counts/category patterns can still be sensitive, and this is not a safe-to-share verdict. On Linux, inventory packages reads available local dpkg, RPM, pacman, and APK databases plus optional fixed-path Flatpak installed references; on Windows, it reads selected current-user and machine-wide Uninstall registry entries. Both are bounded source snapshots and can miss unregistered software. Windows does not use Win32_Product or launch uninstall commands. Windows `inventory app-paths` separately reads selected App Paths registry registrations; it does not expand, parse, execute, or validate their referenced paths. Windows `inventory msix` separately reads current-user package registrations and does not activate packages or inspect package files. On Linux, inventory processes reads bounded numeric /proc status entries and executable-link identities; on Windows, it reads a Tool Help snapshot and queries accessible image paths. Neither adapter reads command lines or promises atomic or exhaustive coverage. On Linux, inventory startup discovers curated sources; on Windows, it inventories selected Run/RunOnce values, Startup folders, and visible service configuration and boot/logon triggers in tasks visible to the current token. For tasks, bounded Exec-action executable paths, arguments, and working directories are recorded as inert text; other action types remain unsupported with unknown action-specific fields. Neither platform establishes that a configured entry ran. Inventory permissions inspects only explicit Linux paths and records ownership/type/mode, supported POSIX ACLs, and Linux file-capability xattrs; it never follows the final path symlink or calculates effective access. Record follows a selected command's traced descendants and may enforce a requested wall-clock limit; this is observation, not isolation or a safety check.";

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
            print_usage();
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
        [command, operation, private_path, public_path]
            if command == "provenance" && operation == "key-check" =>
        {
            provenance_key_check(private_path, public_path)
        }
        [command, operation, private_path, public_path]
            if command == "provenance" && operation == "keygen" =>
        {
            provenance_keygen(private_path, public_path)
        }
        [
            command,
            trust,
            operation,
            public_path,
            store_flag,
            store_path,
            label_flag,
            label,
        ] if command == "provenance"
            && trust == "trust"
            && operation == "import"
            && store_flag == "--trust-store"
            && label_flag == "--label" =>
        {
            provenance_trust_import(public_path, store_path, label)
        }
        [
            command,
            trust,
            operation,
            old_key_id,
            public_path,
            store_flag,
            store_path,
            label_flag,
            label,
        ] if command == "provenance"
            && trust == "trust"
            && operation == "rotate"
            && store_flag == "--trust-store"
            && label_flag == "--label" =>
        {
            provenance_trust_rotate(old_key_id, public_path, store_path, label)
        }
        [command, trust, operation, store_flag, store_path]
            if command == "provenance"
                && trust == "trust"
                && operation == "list"
                && store_flag == "--trust-store" =>
        {
            provenance_trust_list(store_path)
        }
        [command, trust, operation, key_id, store_flag, store_path]
            if command == "provenance"
                && trust == "trust"
                && operation == "remove"
                && store_flag == "--trust-store" =>
        {
            provenance_trust_remove(key_id, store_path)
        }
        [
            command,
            operation,
            session,
            key_flag,
            key_path,
            output_flag,
            output_path,
        ] if command == "provenance"
            && operation == "sign-session"
            && key_flag == "--private-key"
            && output_flag == "--output" =>
        {
            provenance_sign_session(session, key_path, output_path)
        }
        [
            command,
            operation,
            session,
            signature_flag,
            signature_path,
            key_flag,
            key_path,
        ] if command == "provenance"
            && operation == "verify-session"
            && signature_flag == "--signature"
            && key_flag == "--public-key" =>
        {
            provenance_verify_session(session, signature_path, key_path)
        }
        [
            command,
            operation,
            session,
            signature_flag,
            signature_path,
            trust_flag,
            store_path,
        ] if command == "provenance"
            && operation == "verify-session"
            && signature_flag == "--signature"
            && trust_flag == "--trust-store" =>
        {
            provenance_verify_session_with_store(session, signature_path, store_path, None)
        }
        [
            command,
            operation,
            session,
            signature_flag,
            signature_path,
            key_flag,
            key_path,
            trust_flag,
            store_path,
        ] if command == "provenance"
            && operation == "verify-session"
            && signature_flag == "--signature"
            && key_flag == "--public-key"
            && trust_flag == "--trust-store" =>
        {
            provenance_verify_session_with_store(
                session,
                signature_path,
                store_path,
                Some(key_path),
            )
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
            model_install(id, false, None)
        }
        [command, operation, id] if command == "model" && operation == "setup" => {
            model_install(id, true, None)
        }
        [command, operation, id, runtime_flag, runtime_path]
            if command == "model" && operation == "setup" && runtime_flag == "--runtime" =>
        {
            model_install(id, true, Some(runtime_path))
        }
        [command, operation, _id, runtime_flag]
            if command == "model" && operation == "setup" && runtime_flag == "--runtime" =>
        {
            Err("model setup --runtime requires an existing runtime path".to_owned())
        }
        [command, operation, task, id] if command == "model" && operation == "select" => {
            model_select(task, id)
        }
        [command, operation, action, task, path]
            if command == "model" && operation == "runtime" && action == "set" =>
        {
            model_runtime_set(task, path)
        }
        [command, operation, action, task]
            if command == "model" && operation == "runtime" && action == "show" =>
        {
            model_runtime_show(Some(task))
        }
        [command, operation, action]
            if command == "model" && operation == "runtime" && action == "show" =>
        {
            model_runtime_show(None)
        }
        [command, operation, action, task]
            if command == "model" && operation == "runtime" && action == "clear" =>
        {
            model_runtime_clear(task)
        }
        [command, operation, task_flag, task]
            if command == "model" && operation == "doctor" && task_flag == "--task" =>
        {
            model_doctor(task, None, None)
        }
        [command, operation, task_flag, task, runtime_flag, runtime]
            if command == "model"
                && operation == "doctor"
                && task_flag == "--task"
                && runtime_flag == "--runtime" =>
        {
            model_doctor(task, Some(runtime), None)
        }
        [
            command,
            operation,
            task_flag,
            task,
            runtime_flag,
            runtime,
            backend_flag,
            backend,
        ] if command == "model"
            && operation == "doctor"
            && task_flag == "--task"
            && runtime_flag == "--runtime"
            && backend_flag == "--backend" =>
        {
            model_doctor(task, Some(runtime), Some(backend))
        }
        [command, operation, task_flag, task, backend_flag, backend]
            if command == "model"
                && operation == "doctor"
                && task_flag == "--task"
                && backend_flag == "--backend" =>
        {
            model_doctor(task, None, Some(backend))
        }
        [command, operation, id] if command == "model" && operation == "remove" => model_remove(id),
        [command, operation, arguments @ ..] if command == "model" && operation == "add" => {
            model_add(arguments)
        }
        [command, flag, path] if command == "inspect" && flag == "--session" => {
            inspect_session_with_format(&OsString::from("json"), path)
        }
        [command, before, after] if command == "compare-sessions" => {
            compare_audit_sessions(before, after)
        }
        [command, operation, arguments @ ..] if command == "case" => {
            case_command(operation, arguments)
        }
        [command, format_flag, format, session_flag, path]
            if command == "inspect" && format_flag == "--format" && session_flag == "--session" =>
        {
            inspect_session_with_format(format, path)
        }
        [command, flag, path] if command == "inspect" && flag == "--windows-runtime" => {
            inspect_windows_runtime_with_format(&OsString::from("json"), path)
        }
        [command, flag, path] if command == "events" && flag == "--trace" => events_trace(path),
        [command, arguments @ ..] if command == "query" => query_command(arguments),
        [command, flag, path, filters @ ..] if command == "graph" && flag == "--trace" => {
            graph_trace_with_filters(path, filters)
        }
        [command, flag, path, filters @ ..]
            if command == "graph" && flag == "--windows-runtime" =>
        {
            graph_windows_runtime_with_filters(path, filters)
        }
        [command, flag, path, filters @ ..] if command == "timeline" && flag == "--trace" => {
            timeline_trace_with_filters(path, filters)
        }
        [command, flag, path, filters @ ..]
            if command == "timeline" && flag == "--windows-runtime" =>
        {
            timeline_windows_runtime_with_filters(path, filters)
        }
        #[cfg(windows)]
        [command, flag, path] if command == "events" && flag == "--windows-runtime" => {
            events_windows_runtime(path)
        }
        #[cfg(not(windows))]
        [command, flag, path] if command == "events" && flag == "--windows-runtime" => {
            events_windows_runtime(path)
        }
        [command, flag, path] if command == "attribute" && flag == "--windows-runtime" => {
            attribute_windows_runtime(path)
        }
        [command, format_flag, format, windows_flag, path]
            if command == "inspect"
                && format_flag == "--format"
                && windows_flag == "--windows-runtime" =>
        {
            inspect_windows_runtime_with_format(format, path)
        }
        [
            command,
            format_flag,
            format,
            output_flag,
            output,
            windows_flag,
            capture,
        ] if command == "inspect"
            && format_flag == "--format"
            && format == "html"
            && output_flag == "--output"
            && windows_flag == "--windows-runtime" =>
        {
            inspect_windows_runtime_html(output, capture)
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
            windows_flag,
            path,
        ] if command == "model-explain-preview"
            && question_flag == "--question"
            && backend_flag == "--backend"
            && windows_flag == "--windows-runtime" =>
        {
            model_windows_runtime_explanation_preview_file(question, backend, path)
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
            model_explanation_file(question, backend, Some(runtime), digest, trace)
        }
        [
            command,
            question_flag,
            question,
            backend_flag,
            backend,
            confirm_flag,
            digest,
            windows_flag,
            capture,
        ] if command == "model-explain"
            && question_flag == "--question"
            && backend_flag == "--backend"
            && confirm_flag == "--confirm-sha256"
            && windows_flag == "--windows-runtime" =>
        {
            model_windows_runtime_explanation_file(question, backend, None, digest, capture)
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
            windows_flag,
            capture,
        ] if command == "model-explain"
            && question_flag == "--question"
            && backend_flag == "--backend"
            && runtime_flag == "--runtime"
            && confirm_flag == "--confirm-sha256"
            && windows_flag == "--windows-runtime" =>
        {
            model_windows_runtime_explanation_file(
                question,
                backend,
                Some(runtime),
                digest,
                capture,
            )
        }
        [
            command,
            question_flag,
            question,
            backend_flag,
            backend,
            confirm_flag,
            digest,
            trace,
        ] if command == "model-explain"
            && question_flag == "--question"
            && backend_flag == "--backend"
            && confirm_flag == "--confirm-sha256" =>
        {
            model_explanation_file(question, backend, None, digest, trace)
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
            model_analyze_file(question, Some(runtime), digest, trace)
        }
        [
            command,
            question_flag,
            question,
            confirm_flag,
            digest,
            trace,
        ] if command == "model-analyze"
            && question_flag == "--question"
            && confirm_flag == "--confirm-sha256" =>
        {
            model_analyze_file(question, None, digest, trace)
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
            model_query_file(question, Some(runtime), digest, trace)
        }
        [
            command,
            question_flag,
            question,
            confirm_flag,
            digest,
            trace,
        ] if command == "model-query"
            && question_flag == "--question"
            && confirm_flag == "--confirm-sha256" =>
        {
            model_query_file(question, None, digest, trace)
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
        [command, startup_path, trace_path] if command == "associated-behavior" => {
            associated_behavior(startup_path, trace_path)
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
        [command, subcommand, option, output]
            if command == "inventory"
                && subcommand == "path-executables"
                && option == "--output" =>
        {
            inventory_path_executables(output)
        }
        [command, subcommand, option, output]
            if command == "inventory" && subcommand == "app-paths" && option == "--output" =>
        {
            inventory_app_paths(output)
        }
        [command, subcommand, option, output]
            if command == "inventory" && subcommand == "msix" && option == "--output" =>
        {
            inventory_msix(output)
        }
        [command, subcommand, option, output, root]
            if command == "inventory" && subcommand == "root" && option == "--output" =>
        {
            inventory_root(output, root, false)
        }
        [command, subcommand, option, output, hash_flag, root]
            if command == "inventory"
                && subcommand == "root"
                && option == "--output"
                && hash_flag == "--hash-regular-files" =>
        {
            inventory_root(output, root, true)
        }
        [command, subcommand, hash_flag, option, output, root]
            if command == "inventory"
                && subcommand == "root"
                && hash_flag == "--hash-regular-files"
                && option == "--output" =>
        {
            inventory_root(output, root, true)
        }
        [command, subcommand, option, output, paths @ ..]
            if command == "inventory"
                && subcommand == "permissions"
                && option == "--output"
                && !paths.is_empty() =>
        {
            inventory_permissions(output, paths)
        }
        [
            command,
            subcommand,
            operation_flag,
            operation,
            output_flag,
            output,
            path,
        ] if command == "inventory"
            && subcommand == "access-check"
            && operation_flag == "--operation"
            && output_flag == "--output" =>
        {
            inventory_access_check(operation, output, path, None)
        }
        [
            command,
            subcommand,
            pid_flag,
            pid,
            creation_flag,
            creation_time,
            operation_flag,
            operation,
            output_flag,
            output,
            path,
        ] if command == "inventory"
            && subcommand == "access-check"
            && pid_flag == "--pid"
            && creation_flag == "--creation-time-filetime"
            && operation_flag == "--operation"
            && output_flag == "--output" =>
        {
            let pid = parse_positive_u32(pid, "process ID")?;
            let creation_time = parse_positive_u64(creation_time, "process creation FILETIME")?;
            inventory_access_check(operation, output, path, Some((pid, creation_time)))
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
        [command, flag, path, digest, ordinal, payload_digest]
            if command == "evidence" && flag == "--windows-runtime" =>
        {
            evidence_windows_runtime(path, digest, ordinal, payload_digest)
        }
        [command, path, digest, line, byte_offset, byte_length] if command == "evidence" => {
            evidence(path, digest, line, byte_offset, byte_length)
        }
        [command, left, right] if command == "diff" => diff(left, right),
        [command, runtime_flag, before, after]
            if command == "diff" && runtime_flag == "--windows-runtime" =>
        {
            diff_windows_runtime_with_format(&OsString::from("json"), before, after, None)
        }
        [command, runtime_flag, format_flag, format, before, after]
            if command == "diff"
                && runtime_flag == "--windows-runtime"
                && format_flag == "--format" =>
        {
            diff_windows_runtime_with_format(format, before, after, None)
        }
        [command, format_flag, format, runtime_flag, before, after]
            if command == "diff"
                && format_flag == "--format"
                && runtime_flag == "--windows-runtime" =>
        {
            diff_windows_runtime_with_format(format, before, after, None)
        }
        [
            command,
            runtime_flag,
            format_flag,
            format,
            output_flag,
            output,
            before,
            after,
        ] if command == "diff"
            && runtime_flag == "--windows-runtime"
            && format_flag == "--format"
            && format == "html"
            && output_flag == "--output" =>
        {
            diff_windows_runtime_with_format(format, before, after, Some(output))
        }
        [
            command,
            format_flag,
            format,
            output_flag,
            output,
            runtime_flag,
            before,
            after,
        ] if command == "diff"
            && format_flag == "--format"
            && format == "html"
            && output_flag == "--output"
            && runtime_flag == "--windows-runtime" =>
        {
            diff_windows_runtime_with_format(format, before, after, Some(output))
        }
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
            if argument == "--path-executables" {
                if !selected.insert("path-executables") {
                    return Err(
                        "audit source --path-executables was specified more than once".to_owned(),
                    );
                }
                options.path_executables = true;
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
            if argument == "--root" {
                if !selected.insert("root") || index + 1 >= arguments.len() {
                    return Err("audit requires exactly one --root DIRECTORY".to_owned());
                }
                options.root_path = Some(Path::new(&arguments[index + 1]).to_path_buf());
                index += 2;
                continue;
            }
            if argument == "--hash-regular-files" {
                if !selected.insert("hash-regular-files") {
                    return Err(
                        "audit option --hash-regular-files was specified more than once".to_owned(),
                    );
                }
                options.hash_root_regular_files = true;
                index += 1;
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
                Some("--msix") if selected.insert("msix") => {
                    options.msix = true;
                    index += 1;
                }
                Some("--msix") => {
                    return Err("audit source --msix was specified more than once".to_owned());
                }
                Some("--app-paths") if selected.insert("app-paths") => {
                    options.app_paths = true;
                    index += 1;
                }
                Some("--app-paths") => {
                    return Err("audit source --app-paths was specified more than once".to_owned());
                }
                Some("--processes") if selected.insert("processes") => {
                    options.processes = true;
                    index += 1;
                }
                Some("--startup") if selected.insert("startup") => {
                    options.startup = true;
                    index += 1;
                }
                Some("--path-executables") if selected.insert("path-executables") => {
                    options.path_executables = true;
                    index += 1;
                }
                Some("--path-executables") => {
                    return Err(
                        "audit source --path-executables was specified more than once".to_owned(),
                    );
                }
                Some("--root") if selected.insert("root") && index + 1 < arguments.len() => {
                    options.root_path = Some(Path::new(&arguments[index + 1]).to_path_buf());
                    index += 2;
                }
                Some("--root") => {
                    return Err("audit requires exactly one --root DIRECTORY".to_owned());
                }
                Some("--hash-regular-files") if selected.insert("hash-regular-files") => {
                    options.hash_root_regular_files = true;
                    index += 1;
                }
                Some("--hash-regular-files") => {
                    return Err(
                        "audit option --hash-regular-files was specified more than once".to_owned(),
                    );
                }
                Some("--runtime-source")
                    if selected.insert("runtime")
                        && arguments
                            .get(index + 1)
                            .is_some_and(|value| value == "windows-etw") =>
                {
                    options.include_runtime = true;
                    index += 2;
                }
                Some("--runtime-duration-seconds")
                    if options.runtime_duration.is_none() && index + 1 < arguments.len() =>
                {
                    options.runtime_duration =
                        Some(parse_windows_duration_seconds(&arguments[index + 1])?);
                    index += 2;
                }
                Some("--") if options.include_runtime => {
                    let Some(program) = arguments.get(index + 1) else {
                        return Err("Windows runtime command is missing after --".to_owned());
                    };
                    options.runtime_program = Some(program.clone());
                    options.runtime_arguments = arguments[index + 2..].to_vec();
                    break;
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
        if options.include_runtime
            && (options.runtime_duration.is_none() || options.runtime_program.is_none())
        {
            return Err("Windows runtime capture requires --runtime-duration-seconds 1..60 -- PROGRAM [ARGS...]".to_owned());
        }
        if options.runtime_duration.is_some() && !options.include_runtime {
            return Err(
                "Windows --runtime-duration-seconds requires --runtime-source windows-etw"
                    .to_owned(),
            );
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

fn inventory_app_paths(output: &OsString) -> Result<ExitCode, String> {
    #[cfg(windows)]
    {
        let document = collect_windows_app_paths();
        let complete = document.status == AppPathStatus::Complete;
        let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
        serde_json::to_writer(&mut json, &document).map_err(|error| {
            format!("could not serialize Windows App Paths inventory within the {MAX_REPORT_BYTES} byte limit: {error}")
        })?;
        let published =
            publish_private_windows_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
                .map_err(|error| {
                    format!("could not publish private Windows App Paths inventory: {error}")
                })?;
        if complete {
            eprintln!(
                "Saved a complete snapshot of selected Windows App Paths registry entries to {}. Registrations do not establish that their targets exist or can be launched.",
                terminal_safe_path(&published)
            );
            Ok(ExitCode::SUCCESS)
        } else {
            eprintln!(
                "Saved a partial Windows App Paths registration snapshot to {}. Check source status and diagnostics; unavailable or incomplete registrations remain unknown.",
                terminal_safe_path(&published)
            );
            Ok(ExitCode::from(2))
        }
    }
    #[cfg(not(windows))]
    {
        let _ = output;
        Err("inventory app-paths is supported only on native Windows".to_owned())
    }
}

fn inventory_msix(output: &OsString) -> Result<ExitCode, String> {
    #[cfg(windows)]
    {
        let document = collect_windows_msix();
        let complete = document.status == WindowsMsixStatus::Complete;
        let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
        serde_json::to_writer(&mut json, &document).map_err(|error| {
            format!("could not serialize Windows AppX/MSIX inventory within the {MAX_REPORT_BYTES} byte limit: {error}")
        })?;
        let published =
            publish_private_windows_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
                .map_err(|error| {
                    format!("could not publish private Windows AppX/MSIX inventory: {error}")
                })?;
        if complete {
            eprintln!(
                "Saved a complete snapshot of current-user AppX/MSIX package registrations to {}. Registration does not establish that a package is available, launchable, or has run.",
                terminal_safe_path(&published)
            );
            Ok(ExitCode::SUCCESS)
        } else {
            eprintln!(
                "Saved a partial current-user AppX/MSIX registration snapshot to {}. Check source status and diagnostics; unavailable or incomplete package data remains unknown.",
                terminal_safe_path(&published)
            );
            Ok(ExitCode::from(2))
        }
    }
    #[cfg(not(windows))]
    {
        let _ = output;
        Err("inventory msix is supported only on native Windows".to_owned())
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
            "Saved a {} Windows startup-configuration snapshot to {}. It covers selected current-user and accessible machine Run/RunOnce keys, Startup folders, services including read-only delayed-auto-start configuration, current-token-visible tasks, and local ROOT\\subscription WMI objects; the delayed bit gives no exact start time or execution evidence, and command/script text remains inert.",
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

fn inventory_path_executables(output: &OsString) -> Result<ExitCode, String> {
    let document: PathExecutableInventory = collect_path_executables();
    let complete = document.status == "complete";
    let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
    serde_json::to_writer(&mut json, &document).map_err(|error| format!("could not serialize PATH executable inventory within the {MAX_REPORT_BYTES} byte limit: {error}"))?;
    #[cfg(target_os = "linux")]
    let published = publish_private_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
        .map_err(|error| format!("could not publish private PATH executable inventory: {error}"))?;
    #[cfg(windows)]
    let published = publish_private_windows_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
        .map_err(|error| format!("could not publish private PATH executable inventory: {error}"))?;
    eprintln!(
        "Saved a {} current-process PATH executable-candidate snapshot to {}. Candidate rows are metadata heuristics, commands were not run, and PATH coverage may be partial.",
        if complete { "complete" } else { "partial" },
        terminal_safe_path(&published)
    );
    Ok(if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn inventory_root(
    output: &OsString,
    root: &OsString,
    hash_regular_files: bool,
) -> Result<ExitCode, String> {
    let document: RootSnapshot = if hash_regular_files {
        collect_root_snapshot_with_hash(Path::new(root), true)
    } else {
        collect_root_snapshot(Path::new(root))
    };
    let complete = document.status == "complete";
    let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
    serde_json::to_writer(&mut json, &document).map_err(|error| {
        format!("could not serialize selected-root inventory within the {MAX_REPORT_BYTES} byte limit: {error}")
    })?;
    #[cfg(target_os = "linux")]
    let published = publish_private_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
        .map_err(|error| format!("could not publish private selected-root inventory: {error}"))?;
    #[cfg(windows)]
    let published = publish_private_windows_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
        .map_err(|error| format!("could not publish private selected-root inventory: {error}"))?;
    eprintln!(
        "Saved a {} {} snapshot of the selected directory and its direct children to {}. It does not recurse; enumeration is non-atomic and file identities are local hints. Content hashes are sensitive equality fingerprints, not authenticity evidence.",
        if complete { "complete" } else { "partial" },
        if hash_regular_files {
            "SHA-256"
        } else {
            "metadata-only"
        },
        terminal_safe_path(&published)
    );
    Ok(if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
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

fn print_usage() {
    println!(
        "{USAGE}\n\nEvents:\n       sideeffect events --trace <strace-trace-file>\n       sideeffect events --windows-runtime <capture.json> (native Windows)\n       sideeffect query --query <query.json> --trace <trace> [--format json|text]\n       sideeffect query --query <query.json> --windows-runtime <capture.json> [--format json|text] (native Windows)\n       sideeffect query --query <query.json> --session <session-dir> --source runtime|selected_root [--format json|text]\n       sideeffect graph --trace <strace-trace-file> [--format json|text|html] [--output <new-report.html>] [--event-kind <kind> | --process-observation <id>]\n       sideeffect graph --windows-runtime <capture.json> [--format json|text|html] [--output <new-report.html>] [--event-kind <kind> | --process-observation <id>] (native Windows)\n       sideeffect timeline --trace <strace-trace-file> [--format json|text] [--event-kind <kind>] [--process-observation <id>]\n       sideeffect timeline --windows-runtime <capture.json> [--format json|text] [--event-kind <kind>] [--process-observation <id>] (native Windows)\n\nProvenance:\n       sideeffect provenance keygen <private-key.pk8> <public-key.hex>\n       sideeffect provenance key-check <private-key.pk8> <public-key.hex>\n       sideeffect provenance sign-session <session-dir> --private-key <private-key.pk8> --output <signature.json>\n       sideeffect provenance verify-session <session-dir> --signature <signature.json> --public-key <public-key.hex>"
    );
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
        print_usage();
        return Ok(ExitCode::SUCCESS);
    }

    let text = match topic.as_str() {
        "audit" => {
            #[cfg(target_os = "linux")]
            {
                "Usage: sideeffect audit --output NEW_DIRECTORY [--packages] [--processes] [--startup] [--path-executables] [--root DIRECTORY [--hash-regular-files]] [--permission PATH]... [--runtime-duration-seconds 1..3600 -- PROGRAM [ARGS...]]\nCollects explicitly selected Linux inventory sources and an optional bounded command capture into one local, private session directory. --root snapshots one selected directory and its direct children; it reads metadata only by default. --hash-regular-files opts into bounded SHA-256 reads of direct-child regular files and requires --root. Hashes are sensitive equality fingerprints, not authenticity evidence. Collection does not recurse. Review root paths and names before sharing a session. --path-executables snapshots current-process PATH metadata heuristically and never runs files or resolves commands through a shell. Linux runtime uses external strace. Runtime command arguments stay separate and are passed without a shell. The session stores the native run manifest and raw trace, which may contain sensitive arguments and paths. Each source has its own interval; the session is not an atomic snapshot. Runtime completeness remains unknown, so runtime sources and sessions containing runtime are partial. Partial and unavailable selected sources are preserved and cause exit status 2."
            }
            #[cfg(windows)]
            {
                "Usage: sideeffect audit --output NEW_DIRECTORY [--packages] [--msix] [--app-paths] [--processes] [--startup] [--path-executables] [--root DIRECTORY [--hash-regular-files]] [--permission PATH]... [--runtime-source windows-etw --runtime-duration-seconds 1..60 -- PROGRAM [ARGS...]]\nCollects selected bounded native Windows inventories and optional system-wide ETW observations into one current-user-private session directory. --packages reads bounded Uninstall registry registrations; --msix separately reads bounded current-user MSIX package registrations and does not activate packages or inspect package files. --app-paths adds selected current-user and accessible machine App Paths registrations without checking or launching registered paths; App-Paths-only sessions emit envelope v11. --startup includes bounded local ROOT\\subscription WMI rows and emits envelope v13 with startup artifact v8, including read-only service delayed-auto-start configuration; selecting --app-paths as well retains the App Paths source in v13. The delayed bit is ignored unless the service is configured for automatic start and does not state an exact start time or prove execution. WMI query, command, and script text is inert evidence. Session v10/v11 startup artifacts remain v6; v12 remains readable with startup v7. --root snapshots one selected directory and its direct children; it reads metadata only by default. --hash-regular-files opts into bounded SHA-256 reads of direct-child regular files and requires --root. Hashes are sensitive equality fingerprints, not authenticity evidence. Collection does not recurse. Review root paths and names before sharing a session. --path-executables snapshots current-process PATH metadata heuristically and never runs files or resolves commands through a shell. --permission inspects explicitly selected paths only. ETW requires permission to control the shared NT Kernel Logger; SideEffect never elevates. The command is passed as separate arguments and is not started unless ETW setup succeeds. Capture completeness is unknown, so runtime-containing sessions are partial."
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            {
                "Audit sessions are not supported on this platform."
            }
        }
        "inspect" => {
            "Usage: sideeffect inspect [--format json|text] TRACE\n       sideeffect inspect [--format json|text] --bundle DIR\n       sideeffect inspect [--format json|text] --session DIR\n       sideeffect inspect [--format json|text] --windows-runtime FILE\n       sideeffect inspect --format html --output NEW_REPORT.html --windows-runtime FILE (native Windows)\nReads bounded local strace evidence, a validated run bundle, a verified audit session, or a Windows ETW capture. It never runs represented commands. JSON is the default; text output escapes terminal controls and user-influenced fields. Windows runtime inspection accepts schema v3, validates its document fingerprint and bounds, and does not authenticate authorship or establish capture completeness. HTML file export uses the protected current-user publisher and is available only on native Windows. Partial input is labeled and exits with status 2."
        }
        "events" => {
            "Usage: sideeffect events --trace TRACE\n       sideeffect events --windows-runtime CAPTURE.json (native Windows)\nAdapts one local runtime source into a versioned common event envelope and writes JSON only. Source-local order and timestamps are preserved; no cross-platform ordering, parentage, ownership, or causation is inferred. Partial or unknown source status exits with status 2. Windows runtime input is strictly bounded and schema-validated before adaptation."
        }
        "query" => {
            "Usage: sideeffect query --query QUERY.json --trace TRACE [--format json|text]\n       sideeffect query --query QUERY.json --windows-runtime CAPTURE.json [--format json|text] (native Windows)\n       sideeffect query --query QUERY.json --session SESSION_DIR --source runtime|selected_root [--format json|text]\n       sideeffect query --query QUERY.json --session SESSION_DIR --session SESSION_DIR --source runtime|selected_root [--format json|text] (2..16 sessions)\nRuns a versioned, read-only exact-filter query over runtime evidence or selected-root inventory artifacts in explicitly selected verified sessions. Event query schema v2 adds path_exact (exact equality); v3 adds path_prefix (case-sensitive literal string starts_with). Both apply only to observed Linux lexical hints or raw-payload-validated Windows ETW FileIo names. Prefix matching can match sibling spellings such as /tmp/a and /tmp/abc; it does not mean directory containment. Neither filter normalizes, case-folds, resolves, or globs paths; unsupported/pathless rows cannot match, and zero matches do not establish absence. Query schemas v1/v2 remain accepted for their original filters. Other event filters are exact event_kind, operation_kind, syscall outcome, and source-local evidence locators; process_observation_id is supported for one runtime source only. Evidence locators match the complete source-native tuple and are rejected across sessions. Inventory query schema v1 accepts exact native-encoding root_path_hex and entry_name_hex filters; Linux values encode bytes and Windows values encode UTF-16LE. Query JSON is capped at 16 KiB, each path filter at 8 KiB, matching rows at 5,000, multi-session verified artifact bytes at 256 MiB, total work at 10 seconds checked between sessions, and serialized output at 8 MiB. Selected-root v1/v2 documents are strictly validated with 10,000-entry and 8 MiB aggregate encoded-name caps. Results retain session/source status, diagnostics, artifact digests, and direct-child entry ordinals. Missing and partial sources remain not checked or partial. Invalid sessions or malformed documents fail the request. Partial or unknown evidence exits with status 2."
        }
        "graph" => {
            "Usage: sideeffect graph --trace TRACE [--format json|text|html] [--output REPORT.html] [--event-kind KIND | --process-observation ID]\n       sideeffect graph --windows-runtime CAPTURE.json [--format json|text|html] [--output REPORT.html] [--event-kind KIND | --process-observation ID] (native Windows)\nBuilds a bounded source-local graph of event rows, process observations, reported PID context, and evidence-linked relationships. JSON remains the default; --format text writes an 8 MiB-bounded ASCII-only terminal summary to stdout. --format html requires --output and writes a bounded static offline HTML report without replacing existing files. The report uses a restrictive CSP, has no scripts or external assets, and escapes source values. --event-kind selects exact event-kind matches. --process-observation selects a source-local ProcessObservation ID (not a PID or cross-capture ID) and retains events linked to that observation plus its direct process relationships. Retained links preserve their status and basis; diagnostics and source status remain for the full input. An empty event selection is not evidence of absence. PID-only context nodes are kept separate and never merged into process instances. Edges do not establish ownership, causation, or a complete process tree. Partial or unknown source status exits with status 2."
        }
        "timeline" => {
            "Usage: sideeffect timeline --trace TRACE [--format json|text] [--event-kind KIND] [--process-observation ID]\n       sideeffect timeline --windows-runtime CAPTURE.json [--format json|text] [--event-kind KIND] [--process-observation ID] (native Windows)\nBuilds a source-local timeline from bounded Linux strace or strictly validated Windows ETW v3 evidence. Items keep their source ordinal, original timestamp representation, and exact raw-record evidence reference; timestamps do not establish causal order. JSON remains the default; --format text writes a bounded ASCII-only terminal summary to stdout, escaping controls, line breaks, and non-ASCII source strings. --event-kind matches an exact event kind. --process-observation selects an emitted source-local ProcessObservation.source_local_id (not a PID or cross-capture ID), retains directly linked items and all their source-native links, and includes the selected observation with its evidence and end_evidence even if no item matches. For Linux task observations, evidence is the first observed row, not proof of task start, and end_evidence is an exact prefixed termination row when available. For Linux returned-child-PID observations, evidence is only the caller's syscall result row; no child-start event is asserted. When both filters are supplied, displayed items must match both. Link roles, statuses and bases remain visible. Filters may appear in either order; duplicates or missing values are errors. An empty result or missing link does not prove absence. Unsupported rows remain in diagnostics. Partial or unknown source status exits with status 2."
        }
        "provenance key-check" => {
            "Usage: sideeffect provenance key-check PRIVATE_KEY.pk8 PUBLIC_KEY.hex\nChecks that a protected Ed25519 private key derives the supplied public key. On a match, prints only that public key's SHA-256 fingerprint. This read-only check establishes pair consistency only; it does not recover keys or verify backup completeness or authenticity."
        }
        "provenance" => {
            "Usage: sideeffect provenance keygen PRIVATE_KEY.pk8 PUBLIC_KEY.hex\n       sideeffect provenance key-check PRIVATE_KEY.pk8 PUBLIC_KEY.hex\n       sideeffect provenance sign-session SESSION_DIR --private-key PRIVATE_KEY.pk8 --output SIGNATURE.json\n       sideeffect provenance verify-session SESSION_DIR --signature SIGNATURE.json --public-key PUBLIC_KEY.hex [--trust-store DIR]\n       sideeffect provenance verify-session SESSION_DIR --signature SIGNATURE.json --trust-store DIR\n       sideeffect provenance trust import PUBLIC_KEY.hex --trust-store DIR --label LABEL\n       sideeffect provenance trust rotate OLD_KEY_ID NEW_PUBLIC_KEY.hex --trust-store DIR --label LABEL\n       sideeffect provenance trust list --trust-store DIR\n       sideeffect provenance trust remove KEY_ID --trust-store DIR\nCreates Ed25519 keys explicitly, checks a supplied private/public key pair without changing either file, signs the exact validated session.json bytes into a detached envelope, or verifies cryptographic validity offline. Trust is an explicit local user decision about a public key; a local label is not verified signer identity. Imports require typing the displayed key fingerprint. Rotation requires exact confirmation naming both fingerprints, adds the replacement before retiring the prior local trust decision, and never changes private-key files. Trust stores are selected explicitly and are protected for the current user. Signatures do not establish collector honesty or capture completeness."
        }
        "diff" => {
            "Usage: sideeffect diff [--format json|text] LEFT RIGHT\n       sideeffect diff --format html --output REPORT.html LEFT RIGHT\n       sideeffect diff --bundles [--format json|text] LEFT_DIR RIGHT_DIR\n       sideeffect diff --windows-runtime [--format json|text] BEFORE.json AFTER.json\n       sideeffect diff --format html --output REPORT.html --windows-runtime BEFORE.json AFTER.json (native Windows)\nCompares complete parsed strace observations or validated Windows ETW captures. Windows summary v2 preserves category counts, compares exact normalized record multisets, and labels unique supported changed identities as candidates with source references. One-sided observations are not removals or additions; capture completeness remains unknown, and no causal or system-level absence claims are made. Windows HTML uses the protected current-user publisher and a static offline report. Input and report data may be sensitive."
        }
        "diff-summary" => {
            "Usage: sideeffect diff-summary [--format json] LEFT RIGHT\n       sideeffect diff-summary --format html --output REPORT.html LEFT RIGHT\nWrites aggregate change counts without event strings or evidence references. Counts may still be sensitive; the output is not a safe-to-share verdict."
        }
        "compare-sessions" => {
            "Usage: sideeffect compare-sessions BEFORE_SESSION_DIR AFTER_SESSION_DIR\nVerifies both local audit sessions, reports metadata comparability, and compares bounded item-level inventory and runtime evidence from verified artifacts. Per-source status and evidence references remain visible; missing, partial, unsupported, or incompatible sources do not become empty results. This is not an exhaustive history or coverage claim, and it does not establish causation or event absence. Incomparable or partial results exit with status 2 and include stable reason codes."
        }
        "case" => {
            "Usage: sideeffect case init --output NEW_CASE.json --title TITLE --session SESSION_DIR [--session SESSION_DIR...]\n       sideeffect case migrate --case V1_CASE.json --status draft|open --output NEW_CASE.json --session SESSION_DIR [--session SESSION_DIR...]\n       sideeffect case set-status --case V2_CASE.json --status draft|open|in_review|closed|cancelled --output NEW_CASE.json --session SESSION_DIR [--session SESSION_DIR...]\n       sideeffect case add-entry --case V2_CASE.json --entry ENTRY.json --output NEW_CASE.json --session SESSION_DIR [--session SESSION_DIR...]\n       sideeffect case add-note --case V2_CASE.json --id ENTRY_ID --text-file NOTE.txt --output NEW_CASE.json --session SESSION_DIR [--session SESSION_DIR...]\n       sideeffect case add-evidence --case V2_CASE.json --id ENTRY_ID --kind note|assertion --text-file TEXT.txt --evidence-file LOCATORS.json --output NEW_CASE.json --session SESSION_DIR [--session SESSION_DIR...]\n       sideeffect case show --case CASE.json [--format json|text]\n       sideeffect case resolve [--format json|text|html] [--output NEW_REPORT.html] [--redact GROUP...] [--preview-redaction] --case CASE.json --session SESSION_DIR [--session SESSION_DIR...]\nReads a bounded case summary with `case show` without sessions; it omits analyst text and raw evidence rows and marks all evidence not_resolved. Other operations create a private schema-v2 draft, explicitly migrate a schema-v1 case with a user-selected initial status, applies validated lifecycle transitions, appends analyst-authored entries or bounded text-file note/assertion conveniences with optional source locators to a draft/open v2 case, or resolves evidence against supplied verified sessions. Note text is labeled analyst_supplied_unverified. Each update writes a new private file and never replaces an existing file. Closed and cancelled cases are terminal. Case-authored assertions remain unverified; lifecycle status is an analyst workflow label. Hash checks establish byte consistency, not producer authenticity or capture completeness. JSON output may contain sensitive local evidence. HTML redaction groups are explicit whole-field omissions; preview reports omission counts plus renderer-known retained/omitted field and record counts for four fixed groups, without scanning content or writing a report. Retained source records may contain arbitrary strings, arguments, or payloads; this is not a secret scan and does not make sharing safe. Incomplete, partial, or unknown source status remains visible and exits with status 2."
        }
        "case show" => {
            "Usage: sideeffect case show --case CASE.json [--format json|text]\nReads one regular case file bounded to 2 MiB and validates its strict v1/v2 schema. No session directories are required. JSON is the default and uses the sideeffect.investigation_case_summary v1 contract; text is ASCII-safe for terminal display. Shows case-declared bindings and metadata, but never note/assertion text or raw evidence rows. Evidence is always marked not_resolved: the case schema checks locator structure and internal bindings, but this command does not open sessions or resolve locators against artifacts. It makes no authenticity or analyst-claim assessment and performs no writes."
        }
        "case init" => {
            "Usage: sideeffect case init --output NEW_CASE.json --title TITLE --session SESSION_DIR [--session SESSION_DIR...]\nCreates an empty schema-v2 draft bound to the exact manifests of supplied verified sessions. It does not add findings or evidence locators. Revision 1 has no parent digest. The output is private and never overwrites an existing file."
        }
        "case migrate" => {
            "Usage: sideeffect case migrate --case V1_CASE.json --status draft|open --output NEW_CASE.json --session SESSION_DIR [--session SESSION_DIR...]\nExplicitly converts one schema-v1 case to schema v2, preserving its case ID, entries, session identities, and evidence locators. The initial status is required because v1 did not record one. Revision 2 links the exact input bytes with previous_case_sha256; the source is unchanged and the output never overwrites an existing file."
        }
        "case set-status" => {
            "Usage: sideeffect case set-status --case V2_CASE.json --status draft|open|in_review|closed|cancelled --output NEW_CASE.json --session SESSION_DIR [--session SESSION_DIR...]\nApplies one allowed status transition after strict verification of all bound sessions and evidence locators. Each output increments the branch-local revision and hashes the exact input case bytes. Closed and cancelled are terminal. The output is private and no-clobber; status is an analyst workflow label, not evidence quality or completeness."
        }
        "case add-entry" => {
            "Usage: sideeffect case add-entry --case V2_CASE.json --entry ENTRY.json --output NEW_CASE.json --session SESSION_DIR [--session SESSION_DIR...]\nValidates one bounded note/assertion JSON object and appends it only to a draft/open schema-v2 case after strict verification of all bound sessions and evidence locators. The source case is unchanged; output increments the branch-local revision and never overwrites an existing file. Schema-v1 cases require explicit migration first. Assertions require evidence locators and remain analyst_supplied_unverified."
        }
        "case add-note" => {
            "Usage: sideeffect case add-note --case V2_CASE.json --id ENTRY_ID --text-file NOTE.txt --output NEW_CASE.json --session SESSION_DIR [--session SESSION_DIR...]\nReads one regular UTF-8 text file up to 16 KiB; empty, invalid UTF-8, NUL-containing, or oversized input is rejected. The text file is never echoed in errors or progress output. Adds one note with authorship analyst_supplied_unverified and no evidence locators to a draft/open v2 case after strict verification of every bound session. The source case is unchanged; the output increments the branch-local revision and is private and no-clobber. Schema-v1 cases require explicit migration first."
        }
        "case add-evidence" => {
            "Usage: sideeffect case add-evidence --case V2_CASE.json --id ENTRY_ID --kind note|assertion --text-file TEXT.txt --evidence-file LOCATORS.json --output NEW_CASE.json --session SESSION_DIR [--session SESSION_DIR...]\nReads non-empty UTF-8 text without NUL from a regular file capped at 16 KiB; text is never echoed. LOCATORS.json must be a strict JSON array of at most 64 exact case evidence locators and is capped at 64 KiB; unknown fields/tags and malformed or oversized input are rejected. Assertions require at least one locator. Every locator must resolve against supplied verified sessions before a private no-clobber revision is published. A locator is only a source reference and does not validate the analyst's interpretation. Notes and assertions use authorship analyst_supplied_unverified. The source case is unchanged; revision and parent digest advance. Partial or unknown source state remains visible with exit status 2. Schema-v1 cases require explicit migration first."
        }
        "case resolve" => {
            "Usage: sideeffect case resolve [--format json|text|html] [--redact case-text|artifact-paths|source-records|evidence-identifiers]... [--preview-redaction | --output NEW_REPORT.html] --case CASE.json --session SESSION_DIR [--session SESSION_DIR...]\nVerifies supplied sessions and resolves each case locator to its exact source record or selected-root entry. Text writes a bounded ASCII-only terminal summary to stdout; controls, line breaks, and non-ASCII are escaped. Text has no --output option. JSON remains the default. HTML is static, offline, bounded, private, and no-clobber. Repeat --redact with exact field groups; --preview-redaction preserves the selected groups' omission counts and adds counts of renderer-known retained/omitted field occurrences for case-text, artifact-paths, source-records, and evidence-identifiers. Counts describe fixed renderer fields/record blocks only, not a scan or taxonomy of content; preview writes no report. Retained source records can contain arbitrary strings, arguments, or payloads. This is not a secret scan and does not make sharing safe; inspect the full output. The artifact-paths group matches the exact structured key artifact_path, not path, display_name, or substrings. Group redaction does not detect paths, usernames, secrets, or other substrings in remaining free text. The source case and evidence are unchanged. Session and artifact hashes establish consistency with the supplied manifest, not authenticity. Author-written assertions remain unverified; runtime completeness may remain unknown. Reports can contain sensitive paths, arguments, and raw payloads. Review before sharing."
        }
        "explain" => {
            "Usage: sideeffect explain TRACE\n       sideeffect explain --diff LEFT RIGHT\n       sideeffect explain --inventory-diff BEFORE.json AFTER.json\nCreates bounded deterministic summaries. It does not use a language model."
        }
        "evidence" => {
            "Usage: sideeffect evidence TRACE SHA256 LINE BYTE_OFFSET BYTE_LENGTH\n       sideeffect evidence --windows-runtime CAPTURE.json CAPTURE_SHA256 RECORD_ORDINAL PAYLOAD_SHA256 (native Windows)\nVerifies the exact source row identified by a capture fingerprint, ordinal, and raw-payload fingerprint. Windows lookup validates the bounded capture before resolving the event; serialized decode metadata and producer authenticity are not verified. Unknown capture completeness remains visible and exits with status 2."
        }
        "record" => {
            #[cfg(windows)]
            {
                "Usage: sideeffect record --windows-etw OUTPUT.json --duration-seconds 1..60 -- PROGRAM [ARGS...]\nStarts a bounded native ETW capture for process lifecycle, selected file activity, and TCP/UDP observations. The NT Kernel Logger observes system-wide events during the capture window. A separate attribute command provides only candidate process lineage and network PID associations; file/disk header PIDs remain event-context candidates. File records describe observed requests/operations, not guaranteed success. Controlling the NT Kernel Logger requires administrative privileges. No automatic elevation is requested. This is observation, not isolation or a safety check."
            }
            #[cfg(not(windows))]
            {
                "Usage: sideeffect record --trace OUTPUT -- PROGRAM [ARGS...]\n       sideeffect record --bundle DIR -- PROGRAM [ARGS...]\n       sideeffect record --trace OUTPUT --duration-seconds 1..3600 -- PROGRAM [ARGS...]\nRuns the selected program with the current user's permissions under external strace. This is observation, not isolation or a safety check. Available on Linux."
            }
        }
        "inventory" => {
            "Usage: sideeffect inventory packages|processes|startup|path-executables|app-paths|msix|root|permissions|access-check ...\nCollects bounded, local snapshots from sources supported on this platform. Sources are curated and coverage can be partial; inspect output and diagnostics before drawing conclusions."
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
        "inventory app-paths" => {
            #[cfg(windows)]
            {
                "Usage: sideeffect inventory app-paths --output FILE\nReads selected current-user and accessible machine App Paths registrations in native and WOW64 views. Values remain literal and inert. This does not scan the filesystem or establish that a registered executable exists or can be launched."
            }
            #[cfg(not(windows))]
            {
                "Usage: sideeffect inventory app-paths --output FILE\nApp Paths inventory is supported only on native Windows."
            }
        }
        "inventory msix" => {
            #[cfg(windows)]
            {
                "Usage: sideeffect inventory msix --output FILE\nReads current-user registered AppX/MSIX package metadata using the Windows package query API. It does not query other users, activate packages, inspect package files, or establish that a package is available, launchable, or has run."
            }
            #[cfg(not(windows))]
            {
                "Usage: sideeffect inventory msix --output FILE\nAppX/MSIX inventory is supported only on native Windows."
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
        "inventory path-executables" => {
            "Usage: sideeffect inventory path-executables --output FILE\nSnapshots the current process PATH and checks one directory level using platform metadata heuristics. It never executes candidates; symlinks/reparse points and limits make results partial."
        }
        "inventory root" => {
            "Usage: sideeffect inventory root [--hash-regular-files] --output NEW_FILE SELECTED_DIRECTORY\nOpens one explicitly selected directory and inventories only its direct children. By default it reads metadata only. --hash-regular-files opts into bounded SHA-256 reads of direct-child regular files; symlinks/reparse points and nonregular files are not followed or hashed. Hashes can reveal file equality and are sensitive; they do not authenticate content. The snapshot does not recurse or claim atomicity. Partial results exit with status 2."
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
        "inventory access-check" => {
            #[cfg(target_os = "linux")]
            {
                "Usage: sideeffect inventory access-check --operation read|write|execute --output FILE ABSOLUTE_PATH\nRuns a non-mutating faccessat2 permission preflight under the current calling thread's credentials and records the observed kernel result. `execute` requests X_OK; on a directory, that checks search/traversal permission, and it does not prove execve will succeed. The probe does not evaluate another process identity or prove that a later file operation succeeds; the calculated effective-access conclusion remains unknown. A partial result is written with exit status 2."
            }
            #[cfg(windows)]
            {
                "Usage: sideeffect inventory access-check --pid PID --creation-time-filetime FILETIME_100NS --operation read|write|execute --output FILE ABSOLUTE_PATH\nUses the selected process's primary token (PID plus creation time from a process snapshot) to evaluate only a local file object's DACL with Authz. After opening the selected path, it validates the final handle path is on a recognized local HarddiskVolume before DACL evaluation. Ancestor traversal under the selected token, reparse targets, integrity labels, thread impersonation, and other policy are not evaluated. Overall access is conditional, never a definitive allow/deny. No elevation is requested."
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            {
                "Usage: sideeffect inventory access-check ...\nAccess checks are not supported on this platform."
            }
        }
        "correlate-startup" => {
            "Usage: sideeffect correlate-startup STARTUP_INVENTORY.json TRACE\nFinds narrow exact-path candidate matches between supported saved startup configuration and successful exec evidence. A match does not prove that a hook caused or initiated execution."
        }
        "associated-behavior" => {
            "Usage: sideeffect associated-behavior STARTUP_INVENTORY.json RUNTIME_EVIDENCE\nWrites a versioned, evidence-linked candidate summary. Linux accepts startup inventory v2 plus raw strace text. Windows accepts startup inventory v4-v7 plus a validated ETW capture v3. It compares decoded process-start image paths with observed scheduled-task Exec paths, exact REG_SZ Run/RunOnce command strings whose raw UTF-16 sidecars strictly decode to the same display text, and SCM service binary_path strings only when the complete raw strings are identical drive-rooted paths. Missing, malformed, or inconsistent registry sidecars exclude that row and make the summary partial. It does not parse commands, strip arguments or quotes, expand variables, normalize or case-fold paths, match basenames, or convert device paths; those forms remain unmatched. Output retains startup-row and ETW ordinal evidence and duplicate/ambiguity flags. Candidate matches do not prove startup execution or causation. They do not establish that a matched task, registry entry, or service launched the observed process. No match is insufficient evidence, not a negative finding. Partial input or coverage exits with status 2."
        }
        "attribute" => {
            "Usage: sideeffect attribute --windows-runtime CAPTURE.json\nWrites a separate evidence-linked candidate view over a validated Windows ETW v3 capture. Descendant process links require supported process-start payloads and observed active parent IDs. Network association uses the decoded payload process ID. File and disk header PIDs remain context candidates, not ownership. Capture bytes are unchanged. Missing lifecycle data, ambiguity, unsupported records, or reported/unavailable loss is surfaced as partial or unassigned evidence; no causal or absence claims are made."
        }
        "model" => {
            "Usage: sideeffect model list\n       sideeffect model show ID\n       sideeffect model install ID\n       sideeffect model setup ID [--runtime EXISTING_FILE]\n       sideeffect model add --name NAME --path FILE --for evidence|explanation|query [--license ID]\n       sideeffect model select evidence|explanation|query ID\n       sideeffect model remove ID\n       sideeffect model runtime set evidence|explanation|query EXISTING_FILE\n       sideeffect model runtime show [evidence|explanation|query]\n       sideeffect model runtime clear evidence|explanation|query\n       sideeffect model doctor --task evidence|explanation|query [--runtime TASK_RUNTIME] [--backend auto|cpu|cuda]\n\nLists pinned catalog candidates and user-provided models. Catalog evaluation status is shown separately from runtime compatibility. Installing a catalog model requires explicit license acceptance; analysis never downloads weights implicitly. The setup command installs and selects the model for its declared task. An optional --runtime path records an existing runtime for that task without executing or downloading it; model doctor checks the task-specific runtime contract. Runtime configuration stores a per-task path without executing the file; runtime revision checks happen only when doctor or analysis is run. Evidence and query runtime checks are supported on Linux x86_64; explanation checks are supported on Linux x86_64 and native Windows. Device enumeration applies only to explanation. Doctor does not run inference, load weights, or assess answer quality. Catalog models still carry their task-specific evaluation warnings, and no model is approved for answer quality. Registering a local model records its size and SHA-256, but does not verify task compatibility, licensing, or quality. Removing a custom registration leaves the model file untouched. Select a model for its task before running a model preview."
        }
        "model doctor" => {
            "Usage: sideeffect model doctor --task evidence|explanation|query [--runtime TASK_RUNTIME] [--backend auto|cpu|cuda]\nUses --runtime when supplied, otherwise the configured runtime for that task. It checks the selected model registration and SHA-256, then runs the task's bounded runtime version check. Evidence requires the llama.cpp b6000 version prefix; query requires the exact pinned 0.7.0-dev build/commit version; explanation checks the pinned commit and may enumerate devices. Evidence and query are supported only on Linux x86_64. --backend applies only to explanation. The JSON schema v2 report states that inference was not run, weights were not loaded, and this doctor did not assess model quality; catalog evaluation metadata is reported separately. A reported CUDA device is not proof of successful GPU inference. Doctor executes the selected runtime as code; trust it separately."
        }
        "model setup" => {
            "Usage: sideeffect model setup MODEL_ID [--runtime EXISTING_FILE]\nShows the catalog license and model evaluation status, downloads the exact pinned file after explicit typed acceptance, verifies its size and SHA-256, then selects it for its declared task. Optional --runtime records an already obtained runtime path for that task after setup succeeds; it does not download or execute the runtime. Run 'sideeffect model doctor --task TASK' to check the configured task runtime."
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
        "model runtime" => {
            "Usage: sideeffect model runtime set evidence|explanation|query EXISTING_FILE\n       sideeffect model runtime show [evidence|explanation|query]\n       sideeffect model runtime clear evidence|explanation|query\nSet accepts an existing regular file and stores its canonical path in the private per-user registry. Set, show, and clear do not execute the path. Show marks missing or changed entries; reset them with set. Explicit --runtime paths override the configured path. The runtime and its libraries are executable dependencies; use only files you trust."
        }
        "model-preview" => {
            "Usage: sideeffect model-preview --question QUESTION TRACE\nPreviews the bounded typed facts, selected evidence model identity, JSON schema, and request digest. Select and install a model first with the model commands. Review this exact request before confirming local analysis. Partial parsing is visible and exits with status 2."
        }
        "model-analyze" => {
            "Usage: sideeffect model-analyze --question QUESTION [--runtime LLAMA_CLI] --confirm-sha256 REQUEST_SHA256 TRACE\nRuns the selected local evidence model on Linux x86_64 after explicit digest confirmation, using --runtime when supplied or the configured evidence runtime. The model may select at most one source evidence ID as an unverified hint; it can be wrong and is not a finding. SideEffect does not upload evidence. See docs/LOCAL_MODEL_EVALUATION.md."
        }
        "model-explain-preview" => {
            "Usage: sideeffect model-explain-preview --question QUESTION --backend auto|cpu|cuda TRACE | --windows-runtime CAPTURE.json\nPreviews bounded Linux syscall evidence or, with --windows-runtime, validated Windows ETW v3 events under a separate source-specific schema. ETW decoded observations appear only when bounded raw-payload re-decoding exactly matches the serialized sidecar; process payload fields remain unknown when live TDH metadata is required. Review the exact prompt and digest before inference. 'auto' prefers a supported GPU and otherwise reports CPU use; it does not silently fall back after a GPU failure. This command does not run a model."
        }
        "model-explain" => {
            "Usage: sideeffect model-explain --question QUESTION --backend auto|cpu|cuda [--runtime LLAMA_COMPLETION] --confirm-sha256 REQUEST_SHA256 TRACE | --windows-runtime CAPTURE.json\nRuns the selected local model after confirmation of the exact evidence preview. The Linux selector can select up to five syscall-result evidence IDs; --windows-runtime selects IDs from a source-specific Windows ETW v3 preview, with decoded payload observations included only after raw-payload/sidecar agreement. SideEffect returns only the exact matching preview rows. Unsupported event-kind labels remain marked as unverified capture metadata; the representation fingerprint does not authenticate the capture. This is an unverified evidence-selection aid, not an answer or finding. ETW event-header PID/TID values are context only. 'auto' prefers CUDA when the pinned runtime reports a device; CUDA errors do not silently fall back to CPU. SideEffect does not upload data or auto-download a model during analysis. The selected runtime is executable code that must be trusted separately; see docs/LOCAL_MODEL_EXPLANATION_EVALUATION.md."
        }
        "model-query-preview" => {
            "Usage: sideeffect model-query-preview --question QUESTION TRACE\nPreviews the bounded local query request, selected model identity, and typed evidence facts. Queryable facts are shown for review but are not sent to the model. Review this exact question, scope, and digest before optional local inference. Partial input exits with status 2."
        }
        "model-query" => {
            "Usage: sideeffect model-query --question QUESTION [--runtime LLAMA_COMPLETION] --confirm-sha256 REQUEST_SHA256 TRACE\nRuns the selected optional local query model on Linux x86_64 only after explicit preview-digest confirmation, using --runtime when supplied or the configured query runtime. It executes only validated exact-match AND filters over observed typed facts, never commands or model-authored expressions. No model is downloaded during analysis or evidence uploaded. Model results are unverified review aids. See docs/LOCAL_QUERY_PLAN_EVALUATION.md."
        }
        _ => return Err(format!("unknown help topic: {topic}\n\n{USAGE}")),
    };
    println!("{text}");
    Ok(ExitCode::SUCCESS)
}

fn inspect(path: &OsString) -> Result<ExitCode, String> {
    inspect_with_format(&OsString::from("json"), path)
}

fn inventory_access_check(
    operation: &OsString,
    output: &OsString,
    path: &OsString,
    process_identity: Option<(u32, u64)>,
) -> Result<ExitCode, String> {
    let operation = operation
        .to_str()
        .ok_or_else(|| "access-check operation must be valid ASCII".to_owned())?;
    #[cfg(target_os = "linux")]
    {
        if process_identity.is_some() {
            return Err(
                "Linux access-check supports only the calling thread's current credentials; it does not switch to another process identity"
                    .to_owned(),
            );
        }
        let operation = AccessOperation::parse(operation).map_err(str::to_owned)?;
        let document = analyze_current_process_access(Path::new(path), operation);
        let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
        serde_json::to_writer(&mut json, &document).map_err(|error| {
            format!("could not serialize access-check result within the {MAX_REPORT_BYTES}-byte limit: {error}")
        })?;
        let published = publish_private_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
            .map_err(|error| format!("could not publish private access-check result: {error}"))?;
        eprintln!(
            "Saved a partial Linux permission-probe result to {}. Kernel probe status: {:?}; the calculated effective-access conclusion remains unknown.",
            terminal_safe_path(&published),
            document.observed_kernel_check.status,
        );
        Ok(ExitCode::from(2))
    }
    #[cfg(windows)]
    {
        let (process_id, creation_time) = process_identity.ok_or_else(|| {
            "Windows access-check requires --pid and --creation-time-filetime from a process snapshot"
                .to_owned()
        })?;
        let operation = match operation {
            "read" => WindowsAccessOperation::ReadData,
            "write" => WindowsAccessOperation::WriteData,
            "execute" => WindowsAccessOperation::Execute,
            _ => return Err("operation must be exactly read, write, or execute".to_owned()),
        };
        let document = evaluate_windows_dacl_for_process(
            process_id,
            creation_time,
            Path::new(path),
            operation,
        );
        let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
        serde_json::to_writer(&mut json, &document).map_err(|error| {
            format!("could not serialize Windows access-check result within the {MAX_REPORT_BYTES}-byte limit: {error}")
        })?;
        let published =
            publish_private_windows_file(Path::new(output), &json.bytes, MAX_REPORT_BYTES)
                .map_err(|error| {
                    format!("could not publish private Windows access-check result: {error}")
                })?;
        eprintln!(
            "Saved a {} Windows DACL evaluation to {}. DACL result: {:?}; overall access remains {:?} because other controls are not evaluated.",
            if document.status == WindowsAccessStatus::Conditional {
                "conditional"
            } else {
                "partial"
            },
            terminal_safe_path(&published),
            document.dacl_decision,
            document.conclusion,
        );
        Ok(ExitCode::from(2))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (operation, output, path, process_identity);
        Err("inventory access-check is not supported on this platform".to_owned())
    }
}

fn provenance_keygen(private_path: &OsString, public_path: &OsString) -> Result<ExitCode, String> {
    sideeffect::provenance::generate_keypair(Path::new(private_path), Path::new(public_path))
        .map_err(|error| format!("could not create provenance keypair: {error}"))?;
    println!("Created private signing key and public verification key.");
    Ok(ExitCode::SUCCESS)
}

fn provenance_key_check(
    private_path: &OsString,
    public_path: &OsString,
) -> Result<ExitCode, String> {
    let fingerprint =
        sideeffect::provenance::check_keypair(Path::new(private_path), Path::new(public_path))
            .map_err(|error| format!("could not check provenance keypair: {error}"))?;
    println!("{fingerprint}");
    Ok(ExitCode::SUCCESS)
}

fn provenance_sign_session(
    session_path: &OsString,
    key_path: &OsString,
    output_path: &OsString,
) -> Result<ExitCode, String> {
    let session = read_verified_audit_session(Path::new(session_path))?;
    let manifest = session.manifest();
    println!("Session: {}", manifest.session_id);
    println!(
        "Platform: {} / {}",
        manifest.platform, manifest.architecture
    );
    println!("Sources: {}", manifest.sources.len());
    println!(
        "Artifacts: {}",
        manifest
            .sources
            .iter()
            .map(|source| source.artifacts.len())
            .sum::<usize>()
    );
    println!(
        "Signing binds the exact session.json bytes and its declared artifact hashes. The signature does not establish signer identity or capture completeness."
    );
    print!("Type 'sign' to continue: ");
    io::stdout()
        .flush()
        .map_err(|error| format!("could not write signing confirmation: {error}"))?;
    let mut confirmation = String::new();
    io::stdin()
        .read_line(&mut confirmation)
        .map_err(|error| format!("could not read signing confirmation: {error}"))?;
    if confirmation.trim() != "sign" {
        return Err("session signing cancelled".to_owned());
    }
    let private = sideeffect::provenance::load_private_key(Path::new(key_path))
        .map_err(|error| format!("could not read private key: {error}"))?;
    let signed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?
        .as_millis();
    let signed_at =
        u64::try_from(signed_at).map_err(|_| "signing timestamp is out of range".to_owned())?;
    let envelope =
        sideeffect::provenance::sign_manifest(session.manifest_bytes(), &private, signed_at)
            .map_err(|error| format!("could not sign session manifest: {error}"))?;
    sideeffect::provenance::publish_envelope(Path::new(output_path), &envelope)
        .map_err(|error| format!("could not publish signature envelope: {error}"))?;
    println!("Signature created. The recorded local clock time is not a trusted timestamp.");
    Ok(ExitCode::SUCCESS)
}

fn provenance_verify_session(
    session_path: &OsString,
    signature_path: &OsString,
    key_path: &OsString,
) -> Result<ExitCode, String> {
    let session = read_verified_audit_session(Path::new(session_path))?;
    let envelope = sideeffect::provenance::read_envelope(Path::new(signature_path))
        .map_err(|error| format!("could not read signature envelope: {error}"))?;
    let public = sideeffect::provenance::load_public_key(Path::new(key_path))
        .map_err(|error| format!("could not read public key: {error}"))?;
    match sideeffect::provenance::verify_manifest(session.manifest_bytes(), &envelope, &public)
        .map_err(|error| format!("signature verification failed: {error}"))?
    {
        sideeffect::provenance::Verification::Valid { key_id } => {
            println!("Cryptographic signature valid for key {key_id}.");
            println!(
                "Key trust was not evaluated. This does not establish signer identity, collector honesty, or capture completeness."
            );
            Ok(ExitCode::SUCCESS)
        }
        sideeffect::provenance::Verification::ValidTrusted { .. }
        | sideeffect::provenance::Verification::ValidUntrusted { .. }
        | sideeffect::provenance::Verification::UnknownTrustedKey { .. } => {
            unreachable!("public-key verification does not evaluate trust")
        }
    }
}

fn provenance_trust_import(
    public_path: &OsString,
    store_path: &OsString,
    label: &OsString,
) -> Result<ExitCode, String> {
    let label = label
        .to_str()
        .ok_or_else(|| "trust label must be valid UTF-8".to_owned())?;
    sideeffect::provenance::validate_trust_label(label)
        .map_err(|error| format!("invalid trust label: {error}"))?;
    let public = sideeffect::provenance::load_public_key(Path::new(public_path))
        .map_err(|error| format!("could not read public key: {error}"))?;
    let key_id = sideeffect::provenance::public_key_id(&public)
        .map_err(|error| format!("could not identify public key: {error}"))?;
    println!("Public-key fingerprint: {key_id}");
    println!("Local trust label: {label}");
    println!("This trusts the key locally; the label does not verify signer identity.");
    confirm_provenance_action(&format!("trust {key_id}"), "trust import cancelled")?;
    let trusted =
        sideeffect::provenance::import_trusted_key_text(Path::new(store_path), &public, label)
            .map_err(|error| format!("could not import trusted key: {error}"))?;
    println!(
        "Imported trusted public key {} as local label '{}'.",
        trusted.key_id, trusted.label
    );
    Ok(ExitCode::SUCCESS)
}

fn provenance_trust_rotate(
    old_key_id: &OsString,
    replacement_public_path: &OsString,
    store_path: &OsString,
    label: &OsString,
) -> Result<ExitCode, String> {
    let old_key_id = old_key_id
        .to_str()
        .ok_or_else(|| "prior key ID must be valid UTF-8".to_owned())?;
    sideeffect::provenance::validate_trusted_key_id(old_key_id)
        .map_err(|error| format!("invalid prior key ID: {error}"))?;
    let label = label
        .to_str()
        .ok_or_else(|| "trust label must be valid UTF-8".to_owned())?;
    sideeffect::provenance::validate_trust_label(label)
        .map_err(|error| format!("invalid trust label: {error}"))?;
    let replacement_public =
        sideeffect::provenance::load_public_key(Path::new(replacement_public_path))
            .map_err(|error| format!("could not read replacement public key: {error}"))?;
    let replacement_key_id = sideeffect::provenance::public_key_id(&replacement_public)
        .map_err(|error| format!("could not identify replacement public key: {error}"))?;
    let trusted_keys = sideeffect::provenance::list_trusted_keys(Path::new(store_path))
        .map_err(|error| format!("could not read trust store: {error}"))?;
    if !trusted_keys.iter().any(|key| key.key_id == old_key_id) {
        return Err(format!(
            "prior key {old_key_id} is not in the selected trust store"
        ));
    }
    if replacement_key_id == old_key_id {
        return Err("replacement key must differ from the prior key".to_owned());
    }
    if trusted_keys
        .iter()
        .any(|key| key.key_id == replacement_key_id)
    {
        return Err("replacement key is already present in the trust store".to_owned());
    }
    println!("Prior key fingerprint: {old_key_id}");
    println!("Replacement key fingerprint: {replacement_key_id}");
    println!("The replacement will be trusted before the prior local trust is removed.");
    if let Err(error) = confirm_provenance_action_with_limit(
        &format!("rotate {old_key_id} to {replacement_key_id}"),
        "trust rotation cancelled",
        160,
    ) {
        if error == "trust rotation cancelled" {
            println!("Rotation cancelled; the prior trust store is unchanged.");
            return Err("trust rotation cancelled".to_owned());
        }
        return Err(error);
    }

    match sideeffect::provenance::rotate_trusted_key(
        Path::new(store_path),
        old_key_id,
        &replacement_public,
        label,
    )
    .map_err(|error| format!("could not rotate provenance trust: {error}"))?
    {
        sideeffect::provenance::TrustRotationOutcome::Completed {
            old_key_id,
            replacement,
        } => {
            println!(
                "Rotation complete: replacement {} is trusted as '{}'; prior key {} is no longer trusted in this store.",
                replacement.key_id, replacement.label, old_key_id
            );
            Ok(ExitCode::SUCCESS)
        }
        sideeffect::provenance::TrustRotationOutcome::ReplacementTrustedPriorRetained {
            old_key_id,
            replacement,
        } => {
            println!(
                "Rotation incomplete: replacement {} is trusted as '{}', but prior key {} could not be retired; both keys remain trusted.",
                replacement.key_id, replacement.label, old_key_id
            );
            Ok(ExitCode::from(2))
        }
        sideeffect::provenance::TrustRotationOutcome::ReplacementTrustedPriorStateUnknown {
            old_key_id,
            replacement,
        } => {
            println!(
                "Rotation state uncertain: replacement {} is trusted as '{}', but the prior key {} could not be checked after retirement failed. Inspect the selected trust store before retrying.",
                replacement.key_id, replacement.label, old_key_id
            );
            Ok(ExitCode::from(2))
        }
    }
}

fn provenance_trust_list(store_path: &OsString) -> Result<ExitCode, String> {
    let keys = sideeffect::provenance::list_trusted_keys(Path::new(store_path))
        .map_err(|error| format!("could not read trust store: {error}"))?;
    if keys.is_empty() {
        println!("No trusted public keys in this local trust store.");
    } else {
        for key in keys {
            println!("{}  {}", key.key_id, key.label);
        }
        println!("Labels are local annotations and do not verify signer identity.");
    }
    Ok(ExitCode::SUCCESS)
}

fn provenance_trust_remove(key_id: &OsString, store_path: &OsString) -> Result<ExitCode, String> {
    let key_id = key_id
        .to_str()
        .ok_or_else(|| "key ID must be valid UTF-8".to_owned())?;
    sideeffect::provenance::validate_trusted_key_id(key_id)
        .map_err(|error| format!("invalid key ID: {error}"))?;
    confirm_provenance_action(&format!("remove {key_id}"), "trust removal cancelled")?;
    sideeffect::provenance::remove_trusted_key(Path::new(store_path), key_id)
        .map_err(|error| format!("could not remove trusted key: {error}"))?;
    println!("Removed local trust for key {key_id}.");
    Ok(ExitCode::SUCCESS)
}

fn confirm_provenance_action(expected: &str, cancelled: &str) -> Result<(), String> {
    confirm_provenance_action_with_limit(expected, cancelled, 128)
}

fn confirm_provenance_action_with_limit(
    expected: &str,
    cancelled: &str,
    max_confirmation_bytes: usize,
) -> Result<(), String> {
    print!("Type '{expected}' to continue: ");
    io::stdout()
        .flush()
        .map_err(|error| format!("could not write confirmation prompt: {error}"))?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut bytes = Vec::with_capacity(max_confirmation_bytes);
    loop {
        let (consumed, newline) = {
            let buffer = input
                .fill_buf()
                .map_err(|error| format!("could not read confirmation: {error}"))?;
            if buffer.is_empty() {
                return Err("confirmation must end with a newline".to_owned());
            }
            let remaining = max_confirmation_bytes
                .saturating_add(1)
                .saturating_sub(bytes.len());
            let inspected = buffer.len().min(remaining);
            match buffer[..inspected].iter().position(|byte| *byte == b'\n') {
                Some(position) => (position + 1, Some(position)),
                None => (inspected, None),
            }
        };
        if bytes.len().saturating_add(consumed) > max_confirmation_bytes + 1 {
            return Err(format!(
                "confirmation line exceeds its size limit ({max_confirmation_bytes} bytes)"
            ));
        }
        let buffer = input
            .fill_buf()
            .map_err(|error| format!("could not read confirmation: {error}"))?;
        if let Some(position) = newline {
            if bytes.len().saturating_add(position) > max_confirmation_bytes {
                return Err(format!(
                    "confirmation line exceeds its size limit ({max_confirmation_bytes} bytes)"
                ));
            }
            bytes.extend_from_slice(&buffer[..position]);
            input.consume(consumed);
            break;
        }
        bytes.extend_from_slice(&buffer[..consumed]);
        input.consume(consumed);
        if bytes.len() > max_confirmation_bytes {
            return Err(format!(
                "confirmation line exceeds its size limit ({max_confirmation_bytes} bytes)"
            ));
        }
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    let confirmation =
        String::from_utf8(bytes).map_err(|_| "confirmation must be valid UTF-8".to_owned())?;
    if confirmation != expected {
        return Err(cancelled.to_owned());
    }
    Ok(())
}

fn provenance_verify_session_with_store(
    session_path: &OsString,
    signature_path: &OsString,
    store_path: &OsString,
    public_path: Option<&OsString>,
) -> Result<ExitCode, String> {
    let session = read_verified_audit_session(Path::new(session_path))?;
    let envelope = sideeffect::provenance::read_envelope(Path::new(signature_path))
        .map_err(|error| format!("could not read signature envelope: {error}"))?;
    let result = if let Some(public_path) = public_path {
        let public = sideeffect::provenance::load_public_key(Path::new(public_path))
            .map_err(|error| format!("could not read public key: {error}"))?;
        sideeffect::provenance::verify_manifest_with_public_key_and_trust_store(
            session.manifest_bytes(),
            &envelope,
            &public,
            Path::new(store_path),
        )
    } else {
        sideeffect::provenance::verify_manifest_with_trust_store(
            session.manifest_bytes(),
            &envelope,
            Path::new(store_path),
        )
    }
    .map_err(|error| format!("signature verification failed: {error}"))?;
    match result {
        sideeffect::provenance::Verification::ValidTrusted { key_id, label } => {
            println!("Cryptographic signature valid for key {key_id}.");
            println!(
                "Matched locally trusted key label '{label}'. The label is not verified signer identity."
            );
            println!(
                "This does not establish collector honesty, host integrity, or capture completeness."
            );
            Ok(ExitCode::SUCCESS)
        }
        sideeffect::provenance::Verification::ValidUntrusted { key_id } => {
            println!("Cryptographic signature valid for key {key_id}.");
            println!("This key is not trusted in the selected local trust store.");
            Ok(ExitCode::from(2))
        }
        sideeffect::provenance::Verification::UnknownTrustedKey { key_id } => {
            println!("Key {key_id} is not in the selected local trust store.");
            println!("Cryptographic signature validity was not evaluated.");
            Ok(ExitCode::from(2))
        }
        sideeffect::provenance::Verification::Valid { .. } => {
            unreachable!("trust-aware verification must report trust status")
        }
    }
}

#[cfg(target_os = "linux")]
fn read_verified_audit_session(
    path: &Path,
) -> Result<sideeffect::audit_session_reader_linux::VerifiedAuditSession, String> {
    sideeffect::audit_session_reader_linux::read_verified_session(path)
        .map_err(|error| format!("could not verify audit session: {error}"))
}

#[cfg(windows)]
fn read_verified_audit_session(
    path: &Path,
) -> Result<sideeffect::audit_session_reader_windows::VerifiedAuditSession, String> {
    sideeffect::audit_session_reader_windows::read_verified_session(path)
        .map_err(|error| format!("could not verify audit session: {error}"))
}

#[cfg(target_os = "linux")]
type CaseVerifiedSession = sideeffect::audit_session_reader_linux::VerifiedAuditSession;
#[cfg(windows)]
type CaseVerifiedSession = sideeffect::audit_session_reader_windows::VerifiedAuditSession;

fn case_command(operation: &OsString, arguments: &[OsString]) -> Result<ExitCode, String> {
    match operation.to_str() {
        Some("init") => case_init_command(arguments),
        Some("migrate") => case_migrate_command(arguments),
        Some("set-status") => case_set_status_command(arguments),
        Some("add-entry") => case_add_entry_command(arguments),
        Some("add-note") => case_add_note_command(arguments),
        Some("add-evidence") => case_add_evidence_command(arguments),
        Some("show") => case_show_command(arguments),
        Some("resolve") => case_resolve_command(arguments),
        _ => Err(
            "case command must be 'init', 'migrate', 'set-status', 'add-entry', 'add-note', 'add-evidence', 'show', or 'resolve'"
                .to_owned(),
        ),
    }
}

#[derive(Serialize)]
struct CaseSummaryDocument<'a> {
    schema: &'static str,
    schema_version: u32,
    case_schema_version: u32,
    case_id: &'a str,
    title: &'a str,
    status: &'static str,
    revision: Option<u64>,
    parent_case_digest_present: Option<bool>,
    session_bindings: Vec<CaseSummaryBinding<'a>>,
    entries: Vec<CaseSummaryEntry<'a>>,
    evidence_state: &'static str,
    disclosure: &'static str,
}

#[derive(Serialize)]
struct CaseSummaryBinding<'a> {
    session_id: &'a str,
    platform: &'static str,
    manifest_schema_version: u32,
    manifest_sha256: &'a str,
}

#[derive(Serialize)]
struct CaseSummaryEntry<'a> {
    id: &'a str,
    kind: &'static str,
    authorship: &'a str,
    text_bytes: usize,
    evidence_locator_count: usize,
    evidence_state: &'static str,
}

fn case_show_command(arguments: &[OsString]) -> Result<ExitCode, String> {
    let mut case_path: Option<&OsString> = None;
    let mut output_format = "json";
    let mut format_seen = false;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments.get(index + 1).ok_or_else(|| {
            format!(
                "case show option {} requires a value",
                terminal_safe_text(&flag.to_string_lossy())
            )
        })?;
        match flag.to_str() {
            Some("--case") if case_path.replace(value).is_none() => {}
            Some("--case") => return Err("duplicate case show --case option".to_owned()),
            Some("--format") if !format_seen => {
                output_format = value
                    .to_str()
                    .ok_or("case show --format must be json or text")?;
                if !matches!(output_format, "json" | "text") {
                    return Err("case show --format must be json or text".to_owned());
                }
                format_seen = true;
            }
            Some("--format") => return Err("duplicate case show --format option".to_owned()),
            _ => {
                return Err(format!(
                    "unknown case show option {}",
                    terminal_safe_text(&flag.to_string_lossy())
                ));
            }
        }
        index += 2;
    }

    let case_path = case_path.ok_or("case show requires --case CASE.json")?;
    let case_bytes = read_input_file(
        Path::new(case_path),
        sideeffect::case::MAX_CASE_BYTES,
        "case",
    )?;
    let case = sideeffect::case::InvestigationCase::from_json(&case_bytes)?;
    let (status, revision, parent_case_digest_present) = match &case.lifecycle {
        Some(lifecycle) => (
            lifecycle.status.as_str(),
            Some(lifecycle.revision),
            Some(lifecycle.previous_case_sha256.is_some()),
        ),
        None => ("untracked", None, None),
    };
    let summary = CaseSummaryDocument {
        schema: "sideeffect.investigation_case_summary",
        schema_version: 1,
        case_schema_version: case.schema_version,
        case_id: &case.case_id,
        title: &case.title,
        status,
        revision,
        parent_case_digest_present,
        session_bindings: case
            .sessions
            .iter()
            .map(|session| CaseSummaryBinding {
                session_id: &session.session_id,
                platform: match session.platform {
                    sideeffect::case::CasePlatform::Linux => "linux",
                    sideeffect::case::CasePlatform::Windows => "windows",
                },
                manifest_schema_version: session.manifest_schema_version,
                manifest_sha256: &session.manifest_sha256,
            })
            .collect(),
        entries: case
            .entries
            .iter()
            .map(|entry| CaseSummaryEntry {
                id: &entry.id,
                kind: match entry.kind {
                    sideeffect::case::CaseEntryKind::Note => "note",
                    sideeffect::case::CaseEntryKind::Assertion => "assertion",
                },
                authorship: &entry.authorship,
                text_bytes: entry.text.len(),
                evidence_locator_count: entry.evidence.len(),
                evidence_state: "not_resolved",
            })
            .collect(),
        evidence_state: "not_resolved",
        disclosure: "Case-declared bindings and locator structure are validated within the case document, but sessions are not opened and locators are not resolved against artifacts; authorship and assertions are not authenticated or assessed.",
    };

    if output_format == "json" {
        write_json(&summary, "investigation case summary")?;
    } else {
        let mut text = CappedBuffer::new(MAX_REPORT_BYTES);
        render_case_summary_text(&summary, &mut text).map_err(|_| {
            format!("case summary text exceeds the {MAX_REPORT_BYTES} byte output limit")
        })?;
        text.write_all(b"\n").map_err(|_| {
            format!("case summary text exceeds the {MAX_REPORT_BYTES} byte output limit")
        })?;
        write_buffer(&text, "investigation case summary text")?;
    }
    Ok(ExitCode::SUCCESS)
}

fn render_case_summary_text(
    summary: &CaseSummaryDocument<'_>,
    output: &mut impl Write,
) -> io::Result<()> {
    writeln!(
        output,
        "Investigation case summary (v{})",
        summary.schema_version
    )?;
    writeln!(
        output,
        "Case schema version: {}",
        summary.case_schema_version
    )?;
    writeln!(output, "Case ID: {}", terminal_safe_text(summary.case_id))?;
    writeln!(output, "Title: {}", terminal_safe_text(summary.title))?;
    writeln!(output, "Status: {}", summary.status)?;
    match summary.revision {
        Some(revision) => writeln!(output, "Revision: {revision}")?,
        None => writeln!(output, "Revision: not recorded (schema v1)")?,
    }
    match summary.parent_case_digest_present {
        Some(present) => writeln!(output, "Parent case digest present: {present}")?,
        None => writeln!(
            output,
            "Parent case digest presence: not recorded (schema v1)"
        )?,
    }
    writeln!(output, "Evidence state: not_resolved")?;
    writeln!(output, "Session bindings (case-declared; not verified):")?;
    for binding in &summary.session_bindings {
        writeln!(
            output,
            "- session={} platform={} manifest_schema_version={} manifest_sha256={}",
            terminal_safe_text(binding.session_id),
            binding.platform,
            binding.manifest_schema_version,
            terminal_safe_text(binding.manifest_sha256)
        )?;
    }
    writeln!(output, "Entries:")?;
    if summary.entries.is_empty() {
        writeln!(output, "- (none)")?;
    }
    for entry in &summary.entries {
        writeln!(
            output,
            "- id={} kind={} authorship={} text_bytes={} evidence_locator_count={} evidence_state=not_resolved",
            terminal_safe_text(entry.id),
            entry.kind,
            terminal_safe_text(entry.authorship),
            entry.text_bytes,
            entry.evidence_locator_count
        )?;
    }
    writeln!(output, "{}", summary.disclosure)
}

fn case_add_entry_command(arguments: &[OsString]) -> Result<ExitCode, String> {
    let mut case_path: Option<&OsString> = None;
    let mut entry_path: Option<&OsString> = None;
    let mut output: Option<&OsString> = None;
    let mut session_paths: Vec<&OsString> = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments.get(index + 1).ok_or_else(|| {
            format!(
                "case add-entry option {} requires a value",
                terminal_safe_text(&flag.to_string_lossy())
            )
        })?;
        match flag.to_str() {
            Some("--case") if case_path.replace(value).is_none() => {}
            Some("--entry") if entry_path.replace(value).is_none() => {}
            Some("--output") if output.replace(value).is_none() => {}
            Some("--session") => session_paths.push(value),
            Some("--case") => return Err("duplicate case add-entry --case option".to_owned()),
            Some("--entry") => return Err("duplicate case add-entry --entry option".to_owned()),
            Some("--output") => return Err("duplicate case add-entry --output option".to_owned()),
            _ => {
                return Err(format!(
                    "unknown case add-entry option {}",
                    terminal_safe_text(&flag.to_string_lossy())
                ));
            }
        }
        index += 2;
    }

    let case_path = case_path.ok_or("case add-entry requires --case CASE.json")?;
    let entry_path = entry_path.ok_or("case add-entry requires --entry ENTRY.json")?;
    let output = output.ok_or("case add-entry requires --output NEW_CASE.json")?;
    if session_paths.is_empty() || session_paths.len() > sideeffect::case::MAX_CASE_SESSIONS {
        return Err(format!(
            "case add-entry requires 1..={} --session directories",
            sideeffect::case::MAX_CASE_SESSIONS
        ));
    }
    let case_bytes = read_input_file(
        Path::new(case_path),
        sideeffect::case::MAX_CASE_BYTES,
        "case",
    )?;
    let entry_bytes = read_input_file(
        Path::new(entry_path),
        sideeffect::case::MAX_CASE_BYTES,
        "case entry",
    )?;
    let mut case = sideeffect::case::InvestigationCase::from_json(&case_bytes)?;
    if case.schema_version != sideeffect::case::CASE_SCHEMA_VERSION {
        return Err("case add-entry requires schema version 2; migrate the version 1 case with an explicit initial status first".to_owned());
    }
    let lifecycle = case.lifecycle.as_ref().expect("validated v2 lifecycle");
    if !lifecycle.permits_entry() {
        return Err(format!(
            "case status {} does not permit entry changes; transition to open first if allowed",
            lifecycle.status.as_str()
        ));
    }
    let entry: sideeffect::case::CaseEntry = serde_json::from_slice(&entry_bytes)
        .map_err(|_| "case entry JSON is malformed or has unsupported fields".to_owned())?;
    case.entries.push(entry);
    advance_case_revision(&mut case, &case_bytes)?;
    case.validate()?;
    let session_paths: Vec<OsString> = session_paths.iter().map(|path| (*path).clone()).collect();
    let resolved_case = verify_case_against_sessions(&case, &session_paths)?;
    let incomplete = resolved_case_is_incomplete(&resolved_case);

    let mut encoded = CappedBuffer::new(sideeffect::case::MAX_CASE_BYTES);
    serde_json::to_writer_pretty(&mut encoded, &case).map_err(|error| {
        if encoded.exceeded {
            "updated case file exceeds its byte limit".to_owned()
        } else {
            format!("could not serialize updated case file: {error}")
        }
    })?;
    encoded
        .write_all(b"\n")
        .map_err(|_| "updated case file exceeds its byte limit".to_owned())?;
    #[cfg(target_os = "linux")]
    let published = publish_private_file(
        Path::new(output),
        &encoded.bytes,
        sideeffect::case::MAX_CASE_BYTES,
    )
    .map_err(|error| format!("could not publish updated private case: {error}"))?;
    #[cfg(windows)]
    let published = publish_private_windows_file(
        Path::new(output),
        &encoded.bytes,
        sideeffect::case::MAX_CASE_BYTES,
    )
    .map_err(|error| format!("could not publish updated private case: {error}"))?;
    #[cfg(not(any(target_os = "linux", windows)))]
    let published = {
        let _ = output;
        return Err("case workflows are not supported on this platform".to_owned());
    };
    eprintln!(
        "Saved case revision {} with one validated analyst entry to {}. Assertions remain unverified; review sensitive content before sharing.",
        case.lifecycle
            .as_ref()
            .map(|value| value.revision)
            .unwrap_or_default(),
        terminal_safe_path(&published)
    );
    if incomplete {
        eprintln!(
            "Supplied sessions or referenced sources remain partial or unknown; that state was preserved."
        );
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn case_add_note_command(arguments: &[OsString]) -> Result<ExitCode, String> {
    let mut case_path: Option<&OsString> = None;
    let mut entry_id: Option<String> = None;
    let mut text_path: Option<&OsString> = None;
    let mut output: Option<&OsString> = None;
    let mut session_paths: Vec<OsString> = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments.get(index + 1).ok_or_else(|| {
            format!(
                "case add-note option {} requires a value",
                terminal_safe_text(&flag.to_string_lossy())
            )
        })?;
        match flag.to_str() {
            Some("--case") if case_path.replace(value).is_none() => {}
            Some("--id") if entry_id.is_none() => {
                entry_id = Some(
                    value
                        .to_str()
                        .ok_or("case add-note --id must be valid UTF-8")?
                        .to_owned(),
                );
            }
            Some("--text-file") if text_path.replace(value).is_none() => {}
            Some("--output") if output.replace(value).is_none() => {}
            Some("--session") => session_paths.push(value.clone()),
            Some("--case") => return Err("duplicate case add-note --case option".to_owned()),
            Some("--id") => return Err("duplicate case add-note --id option".to_owned()),
            Some("--text-file") => {
                return Err("duplicate case add-note --text-file option".to_owned());
            }
            Some("--output") => return Err("duplicate case add-note --output option".to_owned()),
            _ => {
                return Err(format!(
                    "unknown case add-note option {}",
                    terminal_safe_text(&flag.to_string_lossy())
                ));
            }
        }
        index += 2;
    }

    let case_path = case_path.ok_or("case add-note requires --case CASE.json")?;
    let entry_id = entry_id.ok_or("case add-note requires --id ENTRY_ID")?;
    let text_path = text_path.ok_or("case add-note requires --text-file NOTE.txt")?;
    let output = output.ok_or("case add-note requires --output NEW_CASE.json")?;
    validate_case_session_count("case add-note", session_paths.len())?;

    let case_bytes = read_input_file(
        Path::new(case_path),
        sideeffect::case::MAX_CASE_BYTES,
        "case",
    )?;
    let mut case = sideeffect::case::InvestigationCase::from_json(&case_bytes)?;
    if case.schema_version != sideeffect::case::CASE_SCHEMA_VERSION {
        return Err("case add-note requires schema version 2; migrate the version 1 case with an explicit initial status first".to_owned());
    }
    let lifecycle = case.lifecycle.as_ref().expect("validated v2 lifecycle");
    if !lifecycle.permits_entry() {
        return Err(format!(
            "case status {} does not permit entry changes; transition to open first if allowed",
            lifecycle.status.as_str()
        ));
    }

    let note_bytes = read_input_file(
        Path::new(text_path),
        sideeffect::case::MAX_ENTRY_TEXT_BYTES,
        "case note",
    )?;
    if note_bytes.is_empty() {
        return Err("case note file must contain non-empty UTF-8 text without NUL".to_owned());
    }
    let note_text = String::from_utf8(note_bytes)
        .map_err(|_| "case note file must contain valid UTF-8".to_owned())?;
    if note_text.trim().is_empty() || note_text.contains('\0') {
        return Err("case note file must contain non-empty UTF-8 text without NUL".to_owned());
    }

    case.entries.push(sideeffect::case::CaseEntry {
        id: entry_id,
        kind: sideeffect::case::CaseEntryKind::Note,
        authorship: "analyst_supplied_unverified".to_owned(),
        text: note_text,
        severity: None,
        confidence: None,
        evidence: Vec::new(),
    });
    advance_case_revision(&mut case, &case_bytes)?;
    case.validate()?;
    let resolved_case = verify_case_against_sessions(&case, &session_paths)?;
    let incomplete = resolved_case_is_incomplete(&resolved_case);
    let published = publish_case_file(Path::new(output), &case)?;
    eprintln!(
        "Saved case revision {} with one analyst-authored unverified note to {}. Review sensitive content before sharing.",
        case.lifecycle
            .as_ref()
            .map(|value| value.revision)
            .unwrap_or_default(),
        terminal_safe_path(&published)
    );
    if incomplete {
        eprintln!(
            "Supplied sessions or referenced sources remain partial or unknown; that state was preserved."
        );
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn case_add_evidence_command(arguments: &[OsString]) -> Result<ExitCode, String> {
    let mut case_path: Option<&OsString> = None;
    let mut entry_id: Option<String> = None;
    let mut entry_kind: Option<sideeffect::case::CaseEntryKind> = None;
    let mut text_path: Option<&OsString> = None;
    let mut evidence_path: Option<&OsString> = None;
    let mut output: Option<&OsString> = None;
    let mut session_paths: Vec<OsString> = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments.get(index + 1).ok_or_else(|| {
            format!(
                "case add-evidence option {} requires a value",
                terminal_safe_text(&flag.to_string_lossy())
            )
        })?;
        match flag.to_str() {
            Some("--case") if case_path.replace(value).is_none() => {}
            Some("--id") if entry_id.is_none() => {
                entry_id = Some(
                    value
                        .to_str()
                        .ok_or("case add-evidence --id must be valid UTF-8")?
                        .to_owned(),
                );
            }
            Some("--kind") if entry_kind.is_none() => {
                entry_kind = Some(match value.to_str() {
                    Some("note") => sideeffect::case::CaseEntryKind::Note,
                    Some("assertion") => sideeffect::case::CaseEntryKind::Assertion,
                    _ => {
                        return Err("case add-evidence --kind must be note or assertion".to_owned());
                    }
                });
            }
            Some("--text-file") if text_path.replace(value).is_none() => {}
            Some("--evidence-file") if evidence_path.replace(value).is_none() => {}
            Some("--output") if output.replace(value).is_none() => {}
            Some("--session") => session_paths.push(value.clone()),
            Some("--case") => return Err("duplicate case add-evidence --case option".to_owned()),
            Some("--id") => return Err("duplicate case add-evidence --id option".to_owned()),
            Some("--kind") => return Err("duplicate case add-evidence --kind option".to_owned()),
            Some("--text-file") => {
                return Err("duplicate case add-evidence --text-file option".to_owned());
            }
            Some("--evidence-file") => {
                return Err("duplicate case add-evidence --evidence-file option".to_owned());
            }
            Some("--output") => {
                return Err("duplicate case add-evidence --output option".to_owned());
            }
            _ => {
                return Err(format!(
                    "unknown case add-evidence option {}",
                    terminal_safe_text(&flag.to_string_lossy())
                ));
            }
        }
        index += 2;
    }

    let case_path = case_path.ok_or("case add-evidence requires --case CASE.json")?;
    let entry_id = entry_id.ok_or("case add-evidence requires --id ENTRY_ID")?;
    let entry_kind = entry_kind.ok_or("case add-evidence requires --kind note|assertion")?;
    let text_path = text_path.ok_or("case add-evidence requires --text-file TEXT.txt")?;
    let evidence_path =
        evidence_path.ok_or("case add-evidence requires --evidence-file LOCATORS.json")?;
    let output = output.ok_or("case add-evidence requires --output NEW_CASE.json")?;
    validate_case_session_count("case add-evidence", session_paths.len())?;

    let case_bytes = read_input_file(
        Path::new(case_path),
        sideeffect::case::MAX_CASE_BYTES,
        "case",
    )?;
    let mut case = sideeffect::case::InvestigationCase::from_json(&case_bytes)?;
    if case.schema_version != sideeffect::case::CASE_SCHEMA_VERSION {
        return Err("case add-evidence requires schema version 2; migrate the version 1 case with an explicit initial status first".to_owned());
    }
    let lifecycle = case.lifecycle.as_ref().expect("validated v2 lifecycle");
    if !lifecycle.permits_entry() {
        return Err(format!(
            "case status {} does not permit entry changes; transition to open first if allowed",
            lifecycle.status.as_str()
        ));
    }

    let text_bytes = read_input_file(
        Path::new(text_path),
        sideeffect::case::MAX_ENTRY_TEXT_BYTES,
        "case entry text",
    )?;
    if text_bytes.is_empty() {
        return Err(
            "case entry text file must contain non-empty UTF-8 text without NUL".to_owned(),
        );
    }
    let text = String::from_utf8(text_bytes)
        .map_err(|_| "case entry text file must contain valid UTF-8".to_owned())?;
    if text.trim().is_empty() || text.contains('\0') {
        return Err(
            "case entry text file must contain non-empty UTF-8 text without NUL".to_owned(),
        );
    }

    let evidence_bytes = read_input_file(
        Path::new(evidence_path),
        sideeffect::case::MAX_ENTRY_EVIDENCE_FILE_BYTES,
        "case evidence locator list",
    )?;
    let evidence: Vec<sideeffect::case::CaseEvidenceLocator> =
        serde_json::from_slice(&evidence_bytes).map_err(|_| {
            "case evidence locator JSON is malformed or contains unsupported fields".to_owned()
        })?;
    if evidence.len() > sideeffect::case::MAX_ENTRY_EVIDENCE {
        return Err(format!(
            "case evidence locator list exceeds {} entries",
            sideeffect::case::MAX_ENTRY_EVIDENCE
        ));
    }
    if entry_kind == sideeffect::case::CaseEntryKind::Assertion && evidence.is_empty() {
        return Err(
            "case add-evidence assertion requires at least one evidence locator".to_owned(),
        );
    }
    let evidence_count = evidence.len();

    case.entries.push(sideeffect::case::CaseEntry {
        id: entry_id,
        kind: entry_kind,
        authorship: "analyst_supplied_unverified".to_owned(),
        text,
        severity: None,
        confidence: None,
        evidence,
    });
    advance_case_revision(&mut case, &case_bytes)?;
    case.validate()?;
    let resolved_case = verify_case_against_sessions(&case, &session_paths)?;
    let incomplete = resolved_case_is_incomplete(&resolved_case);
    let published = publish_case_file(Path::new(output), &case)?;
    let kind_label = match entry_kind {
        sideeffect::case::CaseEntryKind::Note => "note",
        sideeffect::case::CaseEntryKind::Assertion => "assertion",
    };
    let reference_label = if evidence_count == 1 {
        "reference"
    } else {
        "references"
    };
    let revision = case
        .lifecycle
        .as_ref()
        .map(|value| value.revision)
        .unwrap_or_default();
    if evidence_count == 0 {
        eprintln!(
            "Saved case revision {revision} with one analyst-authored unverified {kind_label} without source locators to {}. Review sensitive content before sharing.",
            terminal_safe_path(&published)
        );
    } else {
        eprintln!(
            "Saved case revision {revision} with one analyst-authored unverified {kind_label} and {evidence_count} resolved source {reference_label} to {}. Source references do not validate the interpretation; review sensitive content before sharing.",
            terminal_safe_path(&published)
        );
    }
    if incomplete {
        eprintln!(
            "Supplied sessions or referenced sources remain partial or unknown; that state was preserved."
        );
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn case_init_command(arguments: &[OsString]) -> Result<ExitCode, String> {
    let mut output: Option<&OsString> = None;
    let mut title: Option<&OsString> = None;
    let mut session_paths = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments.get(index + 1).ok_or_else(|| {
            format!(
                "case init option {} requires a value",
                terminal_safe_text(&flag.to_string_lossy())
            )
        })?;
        match flag.to_str() {
            Some("--output") if output.replace(value).is_none() => {}
            Some("--title") if title.replace(value).is_none() => {}
            Some("--session") => session_paths.push(value),
            Some("--output") => return Err("duplicate case init --output option".to_owned()),
            Some("--title") => return Err("duplicate case init --title option".to_owned()),
            _ => {
                return Err(format!(
                    "unknown case init option {}",
                    terminal_safe_text(&flag.to_string_lossy())
                ));
            }
        }
        index += 2;
    }

    let output = output.ok_or("case init requires --output NEW_CASE.json")?;
    let title = title
        .and_then(|value| value.to_str())
        .ok_or("case init requires a UTF-8 --title value")?;
    if session_paths.is_empty() || session_paths.len() > sideeffect::case::MAX_CASE_SESSIONS {
        return Err(format!(
            "case init requires 1..={} --session directories",
            sideeffect::case::MAX_CASE_SESSIONS
        ));
    }

    #[cfg(any(target_os = "linux", windows))]
    {
        let mut identities = Vec::with_capacity(session_paths.len());
        for path in session_paths {
            let session = read_verified_audit_session(Path::new(path))?;
            let manifest = session.manifest();
            let platform = match manifest.platform.as_str() {
                "linux" => sideeffect::case::CasePlatform::Linux,
                "windows" => sideeffect::case::CasePlatform::Windows,
                _ => return Err("audit-session platform is unsupported by case files".to_owned()),
            };
            let manifest_sha256 = format!("{:x}", Sha256::digest(session.manifest_bytes()));
            identities.push(sideeffect::case::CaseSessionIdentity {
                session_id: manifest.session_id.clone(),
                platform,
                manifest_schema_version: manifest.schema_version,
                manifest_sha256,
            });
        }
        let first_digest = identities
            .first()
            .map(|identity| &identity.manifest_sha256)
            .ok_or("case init requires at least one verified session")?;
        let case = sideeffect::case::InvestigationCase {
            schema: sideeffect::case::CASE_SCHEMA.to_owned(),
            schema_version: sideeffect::case::CASE_SCHEMA_VERSION,
            case_id: format!("case-{}", &first_digest[..24]),
            title: title.to_owned(),
            sessions: identities,
            entries: Vec::new(),
            lifecycle: Some(sideeffect::case::CaseLifecycle {
                status: sideeffect::case::CaseStatus::Draft,
                revision: 1,
                previous_case_sha256: None,
            }),
        };
        case.validate()?;
        let mut encoded = CappedBuffer::new(sideeffect::case::MAX_CASE_BYTES);
        serde_json::to_writer_pretty(&mut encoded, &case).map_err(|error| {
            if encoded.exceeded {
                "new case file exceeds its byte limit".to_owned()
            } else {
                format!("could not serialize case file: {error}")
            }
        })?;
        encoded
            .write_all(b"\n")
            .map_err(|_| "new case file exceeds its byte limit".to_owned())?;
        #[cfg(target_os = "linux")]
        let published = publish_private_file(
            Path::new(output),
            &encoded.bytes,
            sideeffect::case::MAX_CASE_BYTES,
        )
        .map_err(|error| format!("could not publish private case file: {error}"))?;
        #[cfg(windows)]
        let published = publish_private_windows_file(
            Path::new(output),
            &encoded.bytes,
            sideeffect::case::MAX_CASE_BYTES,
        )
        .map_err(|error| format!("could not publish private case file: {error}"))?;
        eprintln!(
            "Created private empty case draft at {}. Add analyst-labeled entries and evidence locators before resolving it.",
            terminal_safe_path(&published)
        );
        Ok(ExitCode::SUCCESS)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (output, title, session_paths);
        Err("case workflows are not supported on this platform".to_owned())
    }
}

fn case_migrate_command(arguments: &[OsString]) -> Result<ExitCode, String> {
    let mut case_path: Option<&OsString> = None;
    let mut output: Option<&OsString> = None;
    let mut status: Option<sideeffect::case::CaseStatus> = None;
    let mut session_paths: Vec<OsString> = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments.get(index + 1).ok_or_else(|| {
            format!(
                "case migrate option {} requires a value",
                terminal_safe_text(&flag.to_string_lossy())
            )
        })?;
        match flag.to_str() {
            Some("--case") if case_path.replace(value).is_none() => {}
            Some("--output") if output.replace(value).is_none() => {}
            Some("--status") if status.is_none() => status = Some(parse_case_status(value)?),
            Some("--session") => session_paths.push(value.clone()),
            Some("--case") => return Err("duplicate case migrate --case option".to_owned()),
            Some("--output") => return Err("duplicate case migrate --output option".to_owned()),
            Some("--status") => return Err("duplicate case migrate --status option".to_owned()),
            _ => {
                return Err(format!(
                    "unknown case migrate option {}",
                    terminal_safe_text(&flag.to_string_lossy())
                ));
            }
        }
        index += 2;
    }
    let case_path = case_path.ok_or("case migrate requires --case CASE.json")?;
    let output = output.ok_or("case migrate requires --output NEW_CASE.json")?;
    let status = status.ok_or("case migrate requires an explicit --status draft|open")?;
    if !matches!(
        status,
        sideeffect::case::CaseStatus::Draft | sideeffect::case::CaseStatus::Open
    ) {
        return Err("case migrate initial status must be draft or open".to_owned());
    }
    validate_case_session_count("case migrate", session_paths.len())?;
    let case_bytes = read_input_file(
        Path::new(case_path),
        sideeffect::case::MAX_CASE_BYTES,
        "case",
    )?;
    let mut case = sideeffect::case::InvestigationCase::from_json(&case_bytes)?;
    if case.schema_version != sideeffect::case::CASE_SCHEMA_V1 {
        return Err("case migrate accepts only schema version 1".to_owned());
    }
    case.schema_version = sideeffect::case::CASE_SCHEMA_VERSION;
    case.lifecycle = Some(sideeffect::case::CaseLifecycle {
        status,
        // V1 has no revision counter. Treat it as the parent revision and record its exact bytes.
        revision: 2,
        previous_case_sha256: Some(format!("{:x}", Sha256::digest(&case_bytes))),
    });
    case.validate()?;
    let resolved_case = verify_case_against_sessions(&case, &session_paths)?;
    let incomplete = resolved_case_is_incomplete(&resolved_case);
    let published = publish_case_file(Path::new(output), &case)?;
    eprintln!(
        "Migrated schema v1 case to schema v2 at {} (revision 2, status {}). The source file remains unchanged.",
        terminal_safe_path(&published),
        status.as_str()
    );
    if incomplete {
        eprintln!(
            "Supplied sessions or referenced sources remain partial or unknown; that state was preserved."
        );
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn case_set_status_command(arguments: &[OsString]) -> Result<ExitCode, String> {
    let mut case_path: Option<&OsString> = None;
    let mut output: Option<&OsString> = None;
    let mut status: Option<sideeffect::case::CaseStatus> = None;
    let mut session_paths: Vec<OsString> = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments.get(index + 1).ok_or_else(|| {
            format!(
                "case set-status option {} requires a value",
                terminal_safe_text(&flag.to_string_lossy())
            )
        })?;
        match flag.to_str() {
            Some("--case") if case_path.replace(value).is_none() => {}
            Some("--output") if output.replace(value).is_none() => {}
            Some("--status") if status.is_none() => status = Some(parse_case_status(value)?),
            Some("--session") => session_paths.push(value.clone()),
            Some("--case") => return Err("duplicate case set-status --case option".to_owned()),
            Some("--output") => return Err("duplicate case set-status --output option".to_owned()),
            Some("--status") => return Err("duplicate case set-status --status option".to_owned()),
            _ => {
                return Err(format!(
                    "unknown case set-status option {}",
                    terminal_safe_text(&flag.to_string_lossy())
                ));
            }
        }
        index += 2;
    }
    let case_path = case_path.ok_or("case set-status requires --case CASE.json")?;
    let output = output.ok_or("case set-status requires --output NEW_CASE.json")?;
    let next_status = status.ok_or("case set-status requires --status STATUS")?;
    validate_case_session_count("case set-status", session_paths.len())?;
    let case_bytes = read_input_file(
        Path::new(case_path),
        sideeffect::case::MAX_CASE_BYTES,
        "case",
    )?;
    let mut case = sideeffect::case::InvestigationCase::from_json(&case_bytes)?;
    let lifecycle = case.lifecycle.as_mut().ok_or("case set-status requires schema version 2; migrate the version 1 case with an explicit initial status first")?;
    if !lifecycle.permits_transition(next_status) {
        return Err(format!(
            "case status transition from {} to {} is not allowed",
            lifecycle.status.as_str(),
            next_status.as_str()
        ));
    }
    lifecycle.status = next_status;
    advance_case_revision(&mut case, &case_bytes)?;
    case.validate()?;
    let resolved_case = verify_case_against_sessions(&case, &session_paths)?;
    let incomplete = resolved_case_is_incomplete(&resolved_case);
    let published = publish_case_file(Path::new(output), &case)?;
    eprintln!(
        "Saved case revision {} with status {} to {}. This is an analyst workflow label, not an evidence-quality or completeness claim.",
        case.lifecycle.as_ref().unwrap().revision,
        next_status.as_str(),
        terminal_safe_path(&published)
    );
    if incomplete {
        eprintln!(
            "Supplied sessions or referenced sources remain partial or unknown; that state was preserved."
        );
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn parse_case_status(value: &OsString) -> Result<sideeffect::case::CaseStatus, String> {
    match value.to_str() {
        Some("draft") => Ok(sideeffect::case::CaseStatus::Draft),
        Some("open") => Ok(sideeffect::case::CaseStatus::Open),
        Some("in_review") => Ok(sideeffect::case::CaseStatus::InReview),
        Some("closed") => Ok(sideeffect::case::CaseStatus::Closed),
        Some("cancelled") => Ok(sideeffect::case::CaseStatus::Cancelled),
        _ => Err("case status must be draft, open, in_review, closed, or cancelled".to_owned()),
    }
}

fn validate_case_session_count(command: &str, count: usize) -> Result<(), String> {
    if count == 0 || count > sideeffect::case::MAX_CASE_SESSIONS {
        return Err(format!(
            "{command} requires 1..={} --session directories",
            sideeffect::case::MAX_CASE_SESSIONS
        ));
    }
    Ok(())
}

fn advance_case_revision(
    case: &mut sideeffect::case::InvestigationCase,
    previous_bytes: &[u8],
) -> Result<(), String> {
    let lifecycle = case
        .lifecycle
        .as_mut()
        .ok_or("case lifecycle requires schema version 2")?;
    lifecycle.revision = lifecycle
        .revision
        .checked_add(1)
        .ok_or("case revision overflow")?;
    lifecycle.previous_case_sha256 = Some(format!("{:x}", Sha256::digest(previous_bytes)));
    Ok(())
}

fn publish_case_file(
    output: &Path,
    case: &sideeffect::case::InvestigationCase,
) -> Result<PathBuf, String> {
    case.validate()?;
    let mut encoded = CappedBuffer::new(sideeffect::case::MAX_CASE_BYTES);
    serde_json::to_writer_pretty(&mut encoded, case).map_err(|error| {
        if encoded.exceeded {
            "case file exceeds its byte limit".to_owned()
        } else {
            format!("could not serialize case file: {error}")
        }
    })?;
    encoded
        .write_all(b"\n")
        .map_err(|_| "case file exceeds its byte limit".to_owned())?;
    #[cfg(target_os = "linux")]
    let published = publish_private_file(output, &encoded.bytes, sideeffect::case::MAX_CASE_BYTES)
        .map_err(|error| format!("could not publish private case file: {error}"))?;
    #[cfg(windows)]
    let published =
        publish_private_windows_file(output, &encoded.bytes, sideeffect::case::MAX_CASE_BYTES)
            .map_err(|error| format!("could not publish private case file: {error}"))?;
    #[cfg(not(any(target_os = "linux", windows)))]
    let published = return Err("case workflows are not supported on this platform".to_owned());
    Ok(published)
}

#[cfg(any(target_os = "linux", windows))]
fn verify_case_against_sessions(
    case: &sideeffect::case::InvestigationCase,
    session_paths: &[OsString],
) -> Result<sideeffect::case_evidence::ResolvedCase, String> {
    validate_case_session_count("case operation", session_paths.len())?;
    let mut verified_sessions: Vec<CaseVerifiedSession> = Vec::with_capacity(session_paths.len());
    for path in session_paths {
        verified_sessions.push(read_verified_audit_session(Path::new(path))?);
    }
    let artifact_views = verified_sessions
        .iter()
        .map(|session| {
            session
                .artifacts()
                .iter()
                .map(|artifact| sideeffect::case_evidence::VerifiedArtifactView {
                    kind: artifact.kind(),
                    path: artifact.path(),
                    bytes: artifact.bytes(),
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let session_views = verified_sessions
        .iter()
        .zip(&artifact_views)
        .map(
            |(session, artifacts)| sideeffect::case_evidence::VerifiedSessionView {
                manifest: session.manifest(),
                manifest_bytes: session.manifest_bytes(),
                artifacts,
            },
        )
        .collect::<Vec<_>>();
    sideeffect::case_evidence::resolve_case(case, &session_views)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn verify_case_against_sessions(
    _case: &sideeffect::case::InvestigationCase,
    _session_paths: &[OsString],
) -> Result<sideeffect::case_evidence::ResolvedCase, String> {
    Err("case workflows are not supported on this platform".to_owned())
}

fn resolved_case_is_incomplete(case: &sideeffect::case_evidence::ResolvedCase) -> bool {
    case.sessions.iter().any(|session| {
        session.status != sideeffect::audit_session::SessionStatus::Complete
            || session
                .sources
                .iter()
                .any(|source| source.status != sideeffect::audit_session::SourceStatus::Complete)
    }) || case.facts.iter().any(|fact| match &fact.fact {
        sideeffect::case_evidence::ResolvedEvidence::LinuxTraceRecord { parse_status, .. } => {
            *parse_status == sideeffect::model::ParseCompleteness::Partial
        }
        sideeffect::case_evidence::ResolvedEvidence::WindowsEtwRecord {
            collection_status,
            capture_completeness,
            ..
        } => {
            *collection_status == sideeffect::windows_runtime::CollectionStatus::Partial
                || capture_completeness != "complete"
        }
        sideeffect::case_evidence::ResolvedEvidence::SelectedRootEntry {
            inventory_status, ..
        } => inventory_status != "complete",
    })
}

fn case_resolve_command(arguments: &[OsString]) -> Result<ExitCode, String> {
    let mut case_path: Option<&OsString> = None;
    let mut session_paths = Vec::new();
    let mut output_path: Option<&OsString> = None;
    let mut output_format = "json";
    let mut format_seen = false;
    let mut redaction_preview = false;
    let mut redactions = sideeffect::format::CaseHtmlRedactionPolicy::default();
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        if flag.to_str() == Some("--preview-redaction") {
            if redaction_preview {
                return Err("duplicate case resolve --preview-redaction option".to_owned());
            }
            redaction_preview = true;
            index += 1;
            continue;
        }
        let value = arguments.get(index + 1).ok_or_else(|| {
            format!(
                "case resolve option {} requires a value",
                terminal_safe_text(&flag.to_string_lossy())
            )
        })?;
        match flag.to_str() {
            Some("--case") if case_path.replace(value).is_none() => {}
            Some("--session") => session_paths.push(value),
            Some("--format") if !format_seen => {
                output_format = value
                    .to_str()
                    .ok_or("case resolve format must be json, text, or html")?;
                if !matches!(output_format, "json" | "text" | "html") {
                    return Err("case resolve format must be json, text, or html".to_owned());
                }
                format_seen = true;
            }
            Some("--format") => return Err("duplicate case resolve --format option".to_owned()),
            Some("--redact") => {
                let group = value
                    .to_str()
                    .ok_or("case resolve redaction group must be valid ASCII")?;
                let selected = match group {
                    "case-text" => &mut redactions.case_text,
                    "artifact-paths" => &mut redactions.artifact_paths,
                    "source-records" => &mut redactions.source_records,
                    "evidence-identifiers" => &mut redactions.evidence_identifiers,
                    _ => {
                        return Err("case resolve --redact must be case-text, artifact-paths, source-records, or evidence-identifiers".to_owned());
                    }
                };
                if std::mem::replace(selected, true) {
                    return Err(format!("duplicate case resolve redaction group {group}"));
                }
            }
            Some("--output") if output_path.replace(value).is_none() => {}
            Some("--output") => return Err("duplicate case resolve --output option".to_owned()),
            Some("--case") => return Err("duplicate case resolve --case option".to_owned()),
            _ => {
                return Err(format!(
                    "unknown case resolve option {}",
                    terminal_safe_text(&flag.to_string_lossy())
                ));
            }
        }
        index += 2;
    }
    let case_path = case_path.ok_or("case resolve requires --case CASE.json")?;
    let any_redactions = redactions.case_text
        || redactions.artifact_paths
        || redactions.source_records
        || redactions.evidence_identifiers;
    if (any_redactions || redaction_preview) && output_format != "html" {
        return Err("case resolve redaction options require --format html".to_owned());
    }
    if redaction_preview && !any_redactions {
        return Err(
            "case resolve --preview-redaction requires at least one --redact group".to_owned(),
        );
    }
    if redaction_preview && output_path.is_some() {
        return Err("case resolve --preview-redaction cannot be combined with --output".to_owned());
    }
    if output_format == "html" && output_path.is_none() && !redaction_preview {
        return Err("case resolve --format html requires --output NEW_REPORT.html".to_owned());
    }
    if matches!(output_format, "json" | "text") && output_path.is_some() {
        return Err("case resolve --output is supported only with --format html".to_owned());
    }
    if session_paths.is_empty() || session_paths.len() > sideeffect::case::MAX_CASE_SESSIONS {
        return Err(format!(
            "case resolve requires 1..={} --session directories",
            sideeffect::case::MAX_CASE_SESSIONS
        ));
    }
    let case_bytes = read_input_file(
        Path::new(case_path),
        sideeffect::case::MAX_CASE_BYTES,
        "case",
    )?;
    let case = sideeffect::case::InvestigationCase::from_json(&case_bytes)?;
    if session_paths.len() != case.sessions.len() {
        return Err("supplied --session count does not match the case session list".to_owned());
    }

    #[cfg(any(target_os = "linux", windows))]
    {
        let mut verified_sessions: Vec<CaseVerifiedSession> =
            Vec::with_capacity(session_paths.len());
        let mut total_input_bytes = case_bytes.len() as u64;
        for path in session_paths {
            let session = read_verified_audit_session(Path::new(path))?;
            total_input_bytes = total_input_bytes
                .checked_add(session.manifest_bytes().len() as u64)
                .ok_or_else(|| "case resolution input byte count overflow".to_owned())?;
            for artifact in session.artifacts() {
                total_input_bytes = total_input_bytes
                    .checked_add(artifact.bytes().len() as u64)
                    .ok_or_else(|| "case resolution input byte count overflow".to_owned())?;
            }
            if total_input_bytes > sideeffect::case_evidence::MAX_CASE_RESOLUTION_INPUT_BYTES {
                return Err(format!(
                    "case resolution inputs exceed the {}-byte aggregate limit",
                    sideeffect::case_evidence::MAX_CASE_RESOLUTION_INPUT_BYTES
                ));
            }
            verified_sessions.push(session);
        }
        let artifact_views = verified_sessions
            .iter()
            .map(|session| {
                session
                    .artifacts()
                    .iter()
                    .map(|artifact| sideeffect::case_evidence::VerifiedArtifactView {
                        kind: artifact.kind(),
                        path: artifact.path(),
                        bytes: artifact.bytes(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let session_views = verified_sessions
            .iter()
            .zip(&artifact_views)
            .map(
                |(session, artifacts)| sideeffect::case_evidence::VerifiedSessionView {
                    manifest: session.manifest(),
                    manifest_bytes: session.manifest_bytes(),
                    artifacts,
                },
            )
            .collect::<Vec<_>>();
        let resolved = sideeffect::case_evidence::resolve_case(&case, &session_views)?;
        let incomplete = resolved.sessions.iter().any(|session| {
            session.status != sideeffect::audit_session::SessionStatus::Complete
                || session.sources.iter().any(|source| {
                    source.status != sideeffect::audit_session::SourceStatus::Complete
                })
        }) || resolved.facts.iter().any(|fact| match &fact.fact {
            sideeffect::case_evidence::ResolvedEvidence::LinuxTraceRecord {
                parse_status: sideeffect::model::ParseCompleteness::Partial,
                ..
            } => true,
            sideeffect::case_evidence::ResolvedEvidence::WindowsEtwRecord {
                collection_status: sideeffect::windows_runtime::CollectionStatus::Partial,
                ..
            } => true,
            sideeffect::case_evidence::ResolvedEvidence::WindowsEtwRecord {
                capture_completeness,
                ..
            } => capture_completeness != "complete",
            sideeffect::case_evidence::ResolvedEvidence::SelectedRootEntry {
                inventory_status,
                ..
            } => inventory_status != "complete",
            _ => false,
        });
        if redaction_preview {
            println!("Redaction preview for the resolved case HTML report:");
            let preview =
                sideeffect::format::preview_case_html_redactions(&resolved, redactions)
                    .map_err(|error| format!("could not preview case HTML redactions: {error}"))?;
            for item in preview.iter().filter(|item| item.selected_for_redaction) {
                println!(
                    "  {}: {} field occurrence(s) would be omitted",
                    item.field_group, item.affected_field_occurrences
                );
            }
            println!(
                "Known rendered-field occurrence counts under selected policy (not a content scan):"
            );
            for item in &preview {
                let unit = if item.field_group == "source-records" {
                    "source-record block(s)"
                } else {
                    "field occurrence(s)"
                };
                println!(
                    "  {}: {} retained / {} known renderer {}; {} omitted",
                    item.field_group,
                    item.retained_rendered_occurrences,
                    item.known_rendered_occurrences,
                    unit,
                    item.omitted_rendered_occurrences
                );
            }
            if !redactions.source_records {
                println!(
                    "Source records remain and can contain arbitrary strings, arguments, or payload. This is not a secret scan and does not make sharing safe."
                );
            }
            println!(
                "No report was written. The preview contains counts only; inspect the redacted report before sharing. Selected redaction groups omit exact renderer fields; substrings in retained text are not detected."
            );
        } else if output_format == "text" {
            let mut text = CappedBuffer::new(sideeffect::format::MAX_CASE_TEXT_BYTES);
            sideeffect::format::write_case_text(&resolved, &mut text)
                .map_err(|_| "case text output exceeds its bounded output limit".to_owned())?;
            std::io::stdout()
                .write_all(&text.bytes)
                .map_err(|_| "could not write bounded case text to stdout".to_owned())?;
        } else if output_format == "json" {
            write_json(&resolved, "resolved investigation case")?;
        } else {
            let mut html = CappedBuffer::new(MAX_REPORT_BYTES);
            sideeffect::format::write_case_html_with_redactions(&resolved, &mut html, redactions)
                .map_err(|error| {
                if html.exceeded {
                    format!("case HTML report exceeds the {MAX_REPORT_BYTES} byte output limit")
                } else {
                    format!("could not render case HTML report: {error}")
                }
            })?;
            let output = output_path.expect("HTML output path was validated above");
            #[cfg(target_os = "linux")]
            let published = publish_private_file(Path::new(output), &html.bytes, MAX_REPORT_BYTES)
                .map_err(|error| format!("could not publish private case HTML report: {error}"))?;
            #[cfg(windows)]
            let published =
                publish_private_windows_file(Path::new(output), &html.bytes, MAX_REPORT_BYTES)
                    .map_err(|error| {
                        format!("could not publish private case HTML report: {error}")
                    })?;
            #[cfg(not(any(target_os = "linux", windows)))]
            let published = {
                let _ = output;
                return Err("case workflows are not supported on this platform".to_owned());
            };
            if any_redactions {
                eprintln!(
                    "Redacted offline case HTML report written to {}. Only selected structured fields were omitted; this is not a safe-to-share guarantee. Review the entire report before sharing.",
                    terminal_safe_path(&published)
                );
            } else {
                eprintln!(
                    "Offline case HTML report written to {}. It contains sensitive local evidence; review before sharing.",
                    terminal_safe_path(&published)
                );
            }
        }
        Ok(if incomplete {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        })
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (case, session_paths);
        Err("case workflows are not supported on this platform".to_owned())
    }
}

fn events_trace(path: &OsString) -> Result<ExitCode, String> {
    let bytes = read_bounded(path)?;
    let trace = parse_trace_bytes(&bytes, ParseLimits::default())
        .map_err(|error| format!("trace event adaptation failed: {error}"))?;
    let envelope = sideeffect::event::from_linux_strace(&trace, &bytes, "trace");
    let complete =
        envelope.source_state.completeness == sideeffect::event::SourceCompleteness::Complete;
    write_json(&envelope, "common event envelope")?;
    Ok(if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn query_command(arguments: &[OsString]) -> Result<ExitCode, String> {
    let mut query_path: Option<&OsString> = None;
    let mut source: Option<(&str, &OsString)> = None;
    let mut session_paths: Vec<&OsString> = Vec::new();
    let mut session_source: Option<&str> = None;
    let mut output_format = "json";
    let mut format_seen = false;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments.get(index + 1).ok_or_else(|| {
            format!(
                "query option {} requires a value",
                terminal_safe_text(&flag.to_string_lossy())
            )
        })?;
        if value.to_string_lossy().starts_with("--") {
            return Err(format!(
                "query option {} requires a value",
                terminal_safe_text(&flag.to_string_lossy())
            ));
        }
        if flag == "--query" {
            if query_path.replace(value).is_some() {
                return Err("duplicate query --query option".to_owned());
            }
        } else if flag == "--trace" || flag == "--windows-runtime" {
            if source
                .replace((
                    if flag == "--trace" {
                        "trace"
                    } else {
                        "windows-runtime"
                    },
                    value,
                ))
                .is_some()
            {
                return Err("query accepts exactly one source input".to_owned());
            }
        } else if flag == "--session" {
            if session_paths.len() >= sideeffect::query::MAX_QUERY_SESSIONS {
                return Err(format!(
                    "query accepts at most {} --session inputs",
                    sideeffect::query::MAX_QUERY_SESSIONS
                ));
            }
            session_paths.push(value);
        } else if flag == "--source" {
            if session_source.is_some() {
                return Err("duplicate query --source option".to_owned());
            }
            if value != "runtime" && value != "selected_root" {
                return Err("query --source supports only 'runtime' or 'selected_root'".to_owned());
            }
            session_source = Some(if value == "runtime" {
                "runtime"
            } else {
                "selected_root"
            });
        } else if flag == "--format" {
            if format_seen {
                return Err("duplicate query --format option".to_owned());
            }
            if value != "json" && value != "text" {
                return Err("query format must be either 'json' or 'text'".to_owned());
            }
            format_seen = true;
            output_format = value
                .to_str()
                .ok_or_else(|| "query format must be UTF-8".to_owned())?;
        } else {
            return Err(format!(
                "unknown query option {}; use --query, --trace, --windows-runtime, --session, --source, or --format",
                terminal_safe_text(&flag.to_string_lossy())
            ));
        }
        index += 2;
    }
    let query_path = query_path.ok_or_else(|| "query requires --query FILE".to_owned())?;
    let query_bytes = read_input_file(
        Path::new(query_path),
        sideeffect::query::MAX_QUERY_BYTES,
        if session_source == Some("selected_root") {
            "inventory query"
        } else {
            "event query"
        },
    )?;
    if session_source == Some("selected_root") {
        if source.is_some() {
            return Err(
                "selected-root inventory queries require verified --session inputs".to_owned(),
            );
        }
        let query = sideeffect::query::InventoryQuery::from_json(&query_bytes)?;
        let result = query_verified_session_selected_roots(&session_paths, &query)?;
        let complete = result.complete;
        write_inventory_query_result(&result, output_format)?;
        return Ok(if complete {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        });
    }
    let query = sideeffect::query::EventQuery::from_json(&query_bytes)?;
    if !session_paths.is_empty() {
        if source.is_some() {
            return Err(
                "query cannot combine --session with --trace or --windows-runtime".to_owned(),
            );
        }
        if session_source != Some("runtime") {
            return Err("session query requires --source runtime".to_owned());
        }
        if session_paths.len() == 1 {
            let result = query_verified_session_runtime(session_paths[0], &query)?;
            let complete = sideeffect::query::session_source_is_complete(&result);
            write_session_query_result(&result, output_format)?;
            return Ok(if complete {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            });
        }
        if query.filters.process_observation_id.is_some() || query.filters.evidence.is_some() {
            return Err(
                "process-observation and evidence filters are source-local and cannot be used across sessions"
                    .to_owned(),
            );
        }
        let result = query_verified_session_runtimes(&session_paths, &query)?;
        let complete = result.complete;
        write_multi_session_query_result(&result, output_format)?;
        return Ok(if complete {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        });
    }
    if session_source.is_some() {
        return Err("query --source requires --session DIR".to_owned());
    }
    let (source_kind, source_path) = source.ok_or_else(|| {
        "query requires --trace FILE, --windows-runtime FILE, or --session DIR --source runtime"
            .to_owned()
    })?;
    let envelope = match source_kind {
        "trace" => {
            let bytes = read_bounded(source_path)?;
            let trace = parse_trace_bytes(&bytes, ParseLimits::default())
                .map_err(|error| format!("query trace adaptation failed: {error}"))?;
            sideeffect::event::from_linux_strace(&trace, &bytes, "trace")
        }
        "windows-runtime" => read_windows_query_envelope(source_path)?,
        _ => return Err("invalid internal query source selector".to_owned()),
    };
    let result = sideeffect::query::execute_query(&envelope, &query)?;
    if output_format == "json" {
        let mut output = CappedBuffer::new(sideeffect::query::MAX_QUERY_OUTPUT_BYTES);
        serde_json::to_writer_pretty(&mut output, &result).map_err(|error| {
            if output.exceeded {
                format!(
                    "event query output exceeds the {}-byte limit",
                    sideeffect::query::MAX_QUERY_OUTPUT_BYTES
                )
            } else {
                format!("could not serialize event query result: {error}")
            }
        })?;
        output.write_all(b"\n").map_err(|_| {
            format!(
                "event query output exceeds the {}-byte limit",
                sideeffect::query::MAX_QUERY_OUTPUT_BYTES
            )
        })?;
        write_buffer(&output, "event query result")?;
    } else {
        write_event_query_text(&result)?;
    }
    Ok(
        if sideeffect::query::source_is_complete(&result.source_state) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        },
    )
}

fn session_runtime_source(
    manifest: &sideeffect::audit_session::AuditSessionManifest,
) -> Result<&sideeffect::audit_session::AuditSessionSource, String> {
    manifest
        .sources
        .iter()
        .find(|source| source.role == sideeffect::audit_session::SourceRole::Runtime)
        .ok_or_else(|| "runtime_source_missing: session has no selected runtime source".to_owned())
}

fn session_runtime_artifact_ref(
    source: &sideeffect::audit_session::AuditSessionSource,
    kind: sideeffect::audit_session::ArtifactKind,
) -> Result<&sideeffect::audit_session::SessionArtifactRef, String> {
    source
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == kind)
        .ok_or_else(|| {
            format!(
                "runtime_artifact_missing: session source has no verified {:?} artifact",
                kind
            )
        })
}

fn query_verified_session_runtimes(
    session_paths: &[&OsString],
    query: &sideeffect::query::EventQuery,
) -> Result<sideeffect::query::MultiSessionEventQueryResult, String> {
    use std::collections::HashSet;

    if !(2..=sideeffect::query::MAX_QUERY_SESSIONS).contains(&session_paths.len()) {
        return Err(format!(
            "multi-session query requires 2..={} sessions",
            sideeffect::query::MAX_QUERY_SESSIONS
        ));
    }
    let started = Instant::now();
    let mut sessions = Vec::with_capacity(session_paths.len());
    let mut session_ids = HashSet::with_capacity(session_paths.len());
    let mut aggregate_input_bytes = 0u64;
    let mut aggregate_results = 0usize;
    for session_path in session_paths {
        // Reading and parsing one verified source is bounded but not cancellable;
        // the total-work deadline is therefore cooperative between sessions.
        if started.elapsed() > sideeffect::query::MAX_MULTI_SESSION_ELAPSED {
            return Err(format!(
                "multi-session query exceeded the {} ms total execution limit",
                sideeffect::query::MAX_MULTI_SESSION_ELAPSED.as_millis()
            ));
        }
        let result = query_verified_session_runtime(session_path, query)?;
        if !session_ids.insert(result.session.session_id.clone()) {
            return Err("multi-session query contains duplicate session IDs".to_owned());
        }
        aggregate_input_bytes = result
            .runtime_source
            .artifacts
            .iter()
            .try_fold(aggregate_input_bytes, |total, artifact| {
                total.checked_add(artifact.byte_length)
            })
            .ok_or_else(|| "multi-session query input byte count overflow".to_owned())?;
        if aggregate_input_bytes > sideeffect::query::MAX_MULTI_SESSION_INPUT_BYTES {
            return Err(format!(
                "multi-session query input exceeds the {}-byte aggregate limit",
                sideeffect::query::MAX_MULTI_SESSION_INPUT_BYTES
            ));
        }
        aggregate_results = aggregate_results
            .checked_add(result.event_query_result.matched_count)
            .ok_or_else(|| "multi-session query result count overflow".to_owned())?;
        if aggregate_results > sideeffect::query::MAX_MULTI_SESSION_RESULTS {
            return Err(format!(
                "multi-session query matched more than its {}-row aggregate limit; narrow the filters",
                sideeffect::query::MAX_MULTI_SESSION_RESULTS
            ));
        }
        sessions.push(result);
    }
    if started.elapsed() > sideeffect::query::MAX_MULTI_SESSION_ELAPSED {
        return Err(format!(
            "multi-session query exceeded the {} ms total execution limit",
            sideeffect::query::MAX_MULTI_SESSION_ELAPSED.as_millis()
        ));
    }
    sideeffect::query::multi_session_query_result(sessions)
}

fn query_verified_session_selected_roots(
    session_paths: &[&OsString],
    query: &sideeffect::query::InventoryQuery,
) -> Result<sideeffect::query::MultiSessionInventoryQueryResult, String> {
    use std::collections::HashSet;

    if !(1..=sideeffect::query::MAX_QUERY_SESSIONS).contains(&session_paths.len()) {
        return Err(format!(
            "selected-root inventory query requires 1..={} sessions",
            sideeffect::query::MAX_QUERY_SESSIONS
        ));
    }
    let started = Instant::now();
    let mut sessions = Vec::with_capacity(session_paths.len());
    let mut session_ids = HashSet::with_capacity(session_paths.len());
    let mut aggregate_input_bytes = 0u64;
    let mut aggregate_matches = 0usize;
    for session_path in session_paths {
        if started.elapsed() > sideeffect::query::MAX_MULTI_SESSION_ELAPSED {
            return Err(format!(
                "selected-root inventory query exceeded the {} ms total execution limit",
                sideeffect::query::MAX_MULTI_SESSION_ELAPSED.as_millis()
            ));
        }
        let verified = read_verified_audit_session(Path::new(session_path))?;
        let manifest = verified.manifest();
        if manifest.platform != native_query_platform() {
            return Err(
                "selected-root query platform does not match this native reader".to_owned(),
            );
        }
        if !session_ids.insert(manifest.session_id.clone()) {
            return Err("inventory query contains duplicate session IDs".to_owned());
        }
        let source = manifest
            .sources
            .iter()
            .find(|source| source.role == sideeffect::audit_session::SourceRole::SelectedRoot);
        let artifact = source.and_then(|source| {
            source.artifacts.iter().find(|reference| {
                reference.kind == sideeffect::audit_session::ArtifactKind::SelectedRoot
            })
        });
        let artifact_bytes = artifact.and_then(|reference| {
            verified
                .artifacts()
                .iter()
                .find(|item| item.kind() == reference.kind)
                .map(|item| item.bytes())
        });
        if let Some(artifact) = artifact {
            aggregate_input_bytes = aggregate_input_bytes
                .checked_add(artifact.byte_length)
                .ok_or_else(|| "inventory query input byte count overflow".to_owned())?;
        }
        if aggregate_input_bytes > sideeffect::query::MAX_MULTI_SESSION_INPUT_BYTES {
            return Err(format!(
                "inventory query input exceeds the {}-byte aggregate limit",
                sideeffect::query::MAX_MULTI_SESSION_INPUT_BYTES
            ));
        }
        let selected_root_source = sideeffect::query::query_selected_root_artifact(
            sideeffect::query::SelectedRootQueryInput {
                platform: &manifest.platform,
                source_status: source.map_or(
                    sideeffect::audit_session::SourceStatus::NotChecked,
                    |item| item.status,
                ),
                scope: source.map(|item| item.scope.clone()),
                started_at_unix_ms: source.map(|item| item.started_at_unix_ms),
                ended_at_unix_ms: source.map(|item| item.ended_at_unix_ms),
                collector: source.and_then(|item| item.collector.clone()),
                diagnostic_codes: source
                    .map_or_else(Vec::new, |item| item.diagnostic_codes.clone()),
                artifact,
                bytes: artifact_bytes,
            },
            query,
        )?;
        aggregate_matches = aggregate_matches
            .checked_add(selected_root_source.matched_count)
            .ok_or_else(|| "inventory query result count overflow".to_owned())?;
        if aggregate_matches > sideeffect::query::MAX_MULTI_SESSION_RESULTS {
            return Err(format!(
                "inventory query matched more than its {}-row aggregate limit; narrow the filters",
                sideeffect::query::MAX_MULTI_SESSION_RESULTS
            ));
        }
        sessions.push(sideeffect::query::SessionInventoryQueryResult {
            session: sideeffect::query::SessionQueryIdentity {
                session_id: manifest.session_id.clone(),
                manifest_schema_version: manifest.schema_version,
                platform: manifest.platform.clone(),
                status: manifest.status,
                started_at_unix_ms: manifest.started_at_unix_ms,
                ended_at_unix_ms: manifest.ended_at_unix_ms,
            },
            selected_root_source,
        });
    }
    if started.elapsed() > sideeffect::query::MAX_MULTI_SESSION_ELAPSED {
        return Err(format!(
            "selected-root inventory query exceeded the {} ms total execution limit",
            sideeffect::query::MAX_MULTI_SESSION_ELAPSED.as_millis()
        ));
    }
    sideeffect::query::multi_session_inventory_query_result(sessions, query)
}

#[cfg(target_os = "linux")]
fn native_query_platform() -> &'static str {
    "linux"
}

#[cfg(windows)]
fn native_query_platform() -> &'static str {
    "windows"
}

#[cfg(not(any(target_os = "linux", windows)))]
fn native_query_platform() -> &'static str {
    "unsupported"
}

fn write_inventory_query_result(
    result: &sideeffect::query::MultiSessionInventoryQueryResult,
    output_format: &str,
) -> Result<(), String> {
    if output_format == "json" {
        let mut output = CappedBuffer::new(sideeffect::query::MAX_QUERY_OUTPUT_BYTES);
        serde_json::to_writer_pretty(&mut output, result).map_err(|error| {
            if output.exceeded {
                format!(
                    "inventory query output exceeds the {}-byte limit",
                    sideeffect::query::MAX_QUERY_OUTPUT_BYTES
                )
            } else {
                format!("could not serialize inventory query result: {error}")
            }
        })?;
        output
            .write_all(b"\n")
            .map_err(|_| "inventory query output limit exceeded".to_owned())?;
        write_buffer(&output, "inventory query result")
    } else {
        use std::fmt::Write as _;
        let mut text = String::new();
        writeln!(
            text,
            "Selected-root inventory query: sessions={} matches={} completeness={}",
            result.session_count,
            result.matched_count,
            if result.complete {
                "complete"
            } else {
                "partial or unknown"
            }
        )
        .map_err(|_| "could not format inventory query text".to_owned())?;
        writeln!(
            text,
            "Filter: root_path_hex={}; entry_name_hex={}; limit={}",
            result.filter.root_path_hex.as_deref().unwrap_or("*"),
            result.filter.entry_name_hex.as_deref().unwrap_or("*"),
            result.limit
        )
        .map_err(|_| "could not format inventory query text".to_owned())?;
        for session in &result.sessions {
            writeln!(
                text,
                "Session {} ({}, {:?})",
                terminal_safe_text(&session.session.session_id),
                terminal_safe_text(&session.session.platform),
                session.session.status
            )
            .map_err(|_| "could not format inventory query text".to_owned())?;
            let source = &session.selected_root_source;
            writeln!(
                text,
                "  selected_root: {:?}; inventory status: {}; scope: {}",
                source.status,
                source
                    .inventory_status
                    .as_deref()
                    .unwrap_or("not available"),
                source
                    .scope
                    .as_deref()
                    .map(terminal_safe_text)
                    .unwrap_or_else(|| "not checked".to_owned())
            )
            .map_err(|_| "could not format inventory query text".to_owned())?;
            writeln!(
                text,
                "  root_path_hex: {}",
                source.root_path_hex.as_deref().unwrap_or("not recorded")
            )
            .map_err(|_| "could not format inventory query text".to_owned())?;
            writeln!(
                text,
                "  root_path_hex: {}",
                source.root_path_hex.as_deref().unwrap_or("not recorded")
            )
            .map_err(|_| "could not format inventory query text".to_owned())?;
            for code in &source.diagnostic_codes {
                writeln!(text, "  source diagnostic: {}", terminal_safe_text(code))
                    .map_err(|_| "could not format inventory query text".to_owned())?;
            }
            for diagnostic in &source.inventory_diagnostics {
                writeln!(
                    text,
                    "  inventory diagnostic: {} entry={:?} native_error={:?}",
                    terminal_safe_text(&diagnostic.code),
                    diagnostic.entry_ordinal,
                    diagnostic.native_error
                )
                .map_err(|_| "could not format inventory query text".to_owned())?;
            }
            if let Some(artifact) = &source.artifact {
                writeln!(
                    text,
                    "  artifact: {} schema={} v{} bytes={} sha256={}",
                    terminal_safe_text(&artifact.path),
                    terminal_safe_text(&artifact.schema),
                    artifact.schema_version,
                    artifact.byte_length,
                    artifact.sha256
                )
                .map_err(|_| "could not format inventory query text".to_owned())?;
            }
            for entry in &source.entries {
                writeln!(
                    text,
                    "  - ordinal={} name={} display={} evidence={}[{}] source={}",
                    entry.ordinal,
                    entry.name_hex,
                    terminal_safe_text(&entry.display_name),
                    terminal_safe_text(&entry.evidence.artifact_path),
                    entry.evidence.entry_ordinal,
                    terminal_safe_text(&entry.evidence.source)
                )
                .map_err(|_| "could not format inventory query text".to_owned())?;
                if text.len() > sideeffect::query::MAX_QUERY_OUTPUT_BYTES {
                    return Err(format!(
                        "inventory query text exceeds the {}-byte output limit",
                        sideeffect::query::MAX_QUERY_OUTPUT_BYTES
                    ));
                }
            }
        }
        let mut output = CappedBuffer::new(sideeffect::query::MAX_QUERY_OUTPUT_BYTES);
        output
            .write_all(text.as_bytes())
            .map_err(|_| "inventory query text output limit exceeded".to_owned())?;
        write_buffer(&output, "inventory query text result")
    }
}

fn write_multi_session_query_result(
    result: &sideeffect::query::MultiSessionEventQueryResult,
    output_format: &str,
) -> Result<(), String> {
    if output_format == "json" {
        let mut output = CappedBuffer::new(sideeffect::query::MAX_QUERY_OUTPUT_BYTES);
        serde_json::to_writer_pretty(&mut output, result).map_err(|error| {
            if output.exceeded {
                format!(
                    "multi-session event query output exceeds the {}-byte limit",
                    sideeffect::query::MAX_QUERY_OUTPUT_BYTES
                )
            } else {
                format!("could not serialize multi-session event query result: {error}")
            }
        })?;
        output.write_all(b"\n").map_err(|_| {
            format!(
                "multi-session event query output exceeds the {}-byte limit",
                sideeffect::query::MAX_QUERY_OUTPUT_BYTES
            )
        })?;
        write_buffer(&output, "multi-session event query result")
    } else {
        let mut text = String::new();
        for session in &result.sessions {
            let session_text = format_session_query_text(session)?;
            if text.len().saturating_add(session_text.len())
                > sideeffect::query::MAX_QUERY_OUTPUT_BYTES
            {
                return Err(format!(
                    "multi-session event query text exceeds the {}-byte limit",
                    sideeffect::query::MAX_QUERY_OUTPUT_BYTES
                ));
            }
            text.push_str(&session_text);
            text.push('\n');
        }
        let mut output = CappedBuffer::new(sideeffect::query::MAX_QUERY_OUTPUT_BYTES);
        output
            .write_all(text.as_bytes())
            .map_err(|_| "multi-session event query text output limit exceeded".to_owned())?;
        write_buffer(&output, "multi-session event query text result")
    }
}

fn write_session_query_result(
    result: &sideeffect::query::SessionEventQueryResult,
    output_format: &str,
) -> Result<(), String> {
    if output_format == "json" {
        let mut output = CappedBuffer::new(sideeffect::query::MAX_QUERY_OUTPUT_BYTES);
        serde_json::to_writer_pretty(&mut output, result).map_err(|error| {
            if output.exceeded {
                format!(
                    "session event query output exceeds the {}-byte limit",
                    sideeffect::query::MAX_QUERY_OUTPUT_BYTES
                )
            } else {
                format!("could not serialize session event query result: {error}")
            }
        })?;
        output.write_all(b"\n").map_err(|_| {
            format!(
                "session event query output exceeds the {}-byte limit",
                sideeffect::query::MAX_QUERY_OUTPUT_BYTES
            )
        })?;
        write_buffer(&output, "session event query result")
    } else {
        write_session_query_text(result)
    }
}

#[cfg(target_os = "linux")]
fn query_verified_session_runtime(
    session_path: &OsString,
    query: &sideeffect::query::EventQuery,
) -> Result<sideeffect::query::SessionEventQueryResult, String> {
    use sideeffect::audit_session::ArtifactKind;

    let verified = read_verified_audit_session(Path::new(session_path))?;
    let manifest = verified.manifest();
    if manifest.platform != "linux" {
        return Err("session runtime query platform does not match this native reader".to_owned());
    }
    let source = session_runtime_source(manifest)?;
    let run_ref = session_runtime_artifact_ref(source, ArtifactKind::RuntimeManifest)?;
    let trace_ref = session_runtime_artifact_ref(source, ArtifactKind::RuntimeTrace)?;
    let run_bytes = verified
        .artifacts()
        .iter()
        .find(|artifact| artifact.kind() == ArtifactKind::RuntimeManifest)
        .ok_or_else(|| {
            "runtime_artifact_missing: verified run.json bytes are unavailable".to_owned()
        })?
        .bytes();
    let trace_bytes = verified
        .artifacts()
        .iter()
        .find(|artifact| artifact.kind() == ArtifactKind::RuntimeTrace)
        .ok_or_else(|| {
            "runtime_artifact_missing: verified trace.strace bytes are unavailable".to_owned()
        })?
        .bytes();
    if run_ref.schema != "sideeffect.run"
        || run_ref.schema_version != 2
        || run_ref.path != "run.json"
        || trace_ref.schema != "strace_text"
        || trace_ref.schema_version != 1
        || trace_ref.path != "trace.strace"
    {
        return Err(
            "runtime_artifact_contract_mismatch: unsupported Linux runtime artifact contract"
                .to_owned(),
        );
    }
    if run_bytes.len() > sideeffect::limits::MAX_BUNDLE_MANIFEST_BYTES {
        return Err(format!(
            "runtime_manifest_limit_exceeded: run.json exceeds the {}-byte limit",
            sideeffect::limits::MAX_BUNDLE_MANIFEST_BYTES
        ));
    }
    if trace_bytes.len() > sideeffect::limits::MAX_TRACE_BYTES {
        return Err(format!(
            "runtime_trace_limit_exceeded: trace.strace exceeds the {}-byte limit",
            sideeffect::limits::MAX_TRACE_BYTES
        ));
    }
    let run_manifest: RunManifest = serde_json::from_slice(run_bytes).map_err(|_| {
        "runtime_manifest_invalid: run.json is not a strict supported manifest".to_owned()
    })?;
    validate_bundle_manifest(&run_manifest).map_err(|_| {
        "runtime_manifest_invalid: run.json has invalid or unsupported fields".to_owned()
    })?;
    if run_manifest.schema_version != run_ref.schema_version
        || run_manifest.trace.name != trace_ref.path
        || run_manifest.trace.format != trace_ref.schema
        || run_manifest.trace.byte_length != trace_ref.byte_length
        || run_manifest.trace.byte_length != trace_bytes.len() as u64
        || run_manifest.trace.sha256 != trace_ref.sha256
        || format!("{:x}", Sha256::digest(trace_bytes)) != run_manifest.trace.sha256
    {
        return Err("runtime_manifest_trace_binding_mismatch: run.json does not bind the verified trace.strace artifact".to_owned());
    }
    let trace = parse_trace_bytes(trace_bytes, ParseLimits::default())
        .map_err(|error| format!("session runtime trace parsing failed: {error}"))?;
    let envelope = sideeffect::event::from_linux_strace(&trace, trace_bytes, "trace.strace");
    let events = sideeffect::query::execute_query(&envelope, query)?;
    Ok(sideeffect::query::session_query_result(
        manifest,
        source,
        sideeffect::query::SessionCaptureStatus {
            completeness: run_manifest.capture.completeness,
            collection_status: None,
            stop_reason: run_manifest.capture.stop_reason,
        },
        events,
    ))
}

#[cfg(windows)]
fn query_verified_session_runtime(
    session_path: &OsString,
    query: &sideeffect::query::EventQuery,
) -> Result<sideeffect::query::SessionEventQueryResult, String> {
    use sideeffect::audit_session::ArtifactKind;

    let verified = read_verified_audit_session(Path::new(session_path))?;
    let manifest = verified.manifest();
    if manifest.platform != "windows" {
        return Err("session runtime query platform does not match this native reader".to_owned());
    }
    let source = session_runtime_source(manifest)?;
    let capture_ref = session_runtime_artifact_ref(source, ArtifactKind::WindowsRuntimeCapture)?;
    let capture_bytes = verified
        .artifacts()
        .iter()
        .find(|artifact| artifact.kind() == ArtifactKind::WindowsRuntimeCapture)
        .ok_or_else(|| {
            "runtime_artifact_missing: verified runtime.windows.json bytes are unavailable"
                .to_owned()
        })?
        .bytes();
    if capture_ref.schema != sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA
        || capture_ref.schema_version
            != sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION
        || capture_ref.path != "runtime.windows.json"
        || capture_bytes.len() > sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES
    {
        return Err(
            "runtime_artifact_contract_mismatch: unsupported Windows runtime artifact contract"
                .to_owned(),
        );
    }
    let capture = sideeffect::windows_runtime::inspect_windows_runtime_bytes(capture_bytes)
        .map_err(|error| format!("Windows session runtime capture validation failed: {error}"))?;
    let envelope = sideeffect::event::from_windows_runtime_capture(&capture);
    let events = sideeffect::query::execute_query(&envelope, query)?;
    let completeness = capture.capture_completeness.clone();
    let collection_status = Some(match capture.collection_status {
        sideeffect::windows_runtime::CollectionStatus::Complete => "complete".to_owned(),
        sideeffect::windows_runtime::CollectionStatus::Partial => "partial".to_owned(),
    });
    let stop_reason = Some(
        match capture.stop_reason {
            sideeffect::windows_runtime::StopReason::TargetExited => "target_exited",
            sideeffect::windows_runtime::StopReason::DurationLimitReached => {
                "duration_limit_reached"
            }
            sideeffect::windows_runtime::StopReason::EventLimitReached => "event_limit_reached",
            sideeffect::windows_runtime::StopReason::EtwLossReported => "etw_loss_reported",
            sideeffect::windows_runtime::StopReason::EtwStatisticsUnavailable => {
                "etw_statistics_unavailable"
            }
        }
        .to_owned(),
    );
    Ok(sideeffect::query::session_query_result(
        manifest,
        source,
        sideeffect::query::SessionCaptureStatus {
            completeness,
            collection_status,
            stop_reason,
        },
        events,
    ))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn query_verified_session_runtime(
    _session_path: &OsString,
    _query: &sideeffect::query::EventQuery,
) -> Result<sideeffect::query::SessionEventQueryResult, String> {
    Err("session runtime query is supported only on Linux and native Windows".to_owned())
}

#[cfg(windows)]
fn read_windows_query_envelope(
    path: &OsString,
) -> Result<sideeffect::event::CommonEventEnvelope, String> {
    let bytes = read_input_file(
        Path::new(path),
        sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        "Windows runtime capture",
    )?;
    let capture = sideeffect::windows_runtime::inspect_windows_runtime_bytes(&bytes)
        .map_err(|error| format!("Windows runtime query adaptation failed: {error}"))?;
    Ok(sideeffect::event::from_windows_runtime_capture(&capture))
}

#[cfg(not(windows))]
fn read_windows_query_envelope(
    _path: &OsString,
) -> Result<sideeffect::event::CommonEventEnvelope, String> {
    Err("query --windows-runtime is supported only in native Windows builds".to_owned())
}

fn write_event_query_text(result: &sideeffect::query::EventQueryResult) -> Result<(), String> {
    let text = format_event_query_text(result)?;
    let mut output = CappedBuffer::new(sideeffect::query::MAX_QUERY_OUTPUT_BYTES);
    output
        .write_all(text.as_bytes())
        .map_err(|_| "event query text output limit exceeded".to_owned())?;
    write_buffer(&output, "event query text result")
}

fn write_session_query_text(
    result: &sideeffect::query::SessionEventQueryResult,
) -> Result<(), String> {
    let text = format_session_query_text(result)?;
    let mut output = CappedBuffer::new(sideeffect::query::MAX_QUERY_OUTPUT_BYTES);
    output
        .write_all(text.as_bytes())
        .map_err(|_| "session event query text output limit exceeded".to_owned())?;
    write_buffer(&output, "session event query text result")
}

fn format_session_query_text(
    result: &sideeffect::query::SessionEventQueryResult,
) -> Result<String, String> {
    use std::fmt::Write as _;
    let mut text = String::new();
    writeln!(
        text,
        "Session query: {} (manifest v{}, {})",
        terminal_safe_text(&result.session.session_id),
        result.session.manifest_schema_version,
        match result.session.status {
            sideeffect::audit_session::SessionStatus::Complete => "complete",
            sideeffect::audit_session::SessionStatus::Partial => "partial",
        }
    )
    .map_err(|_| "could not format session query text".to_owned())?;
    check_event_query_text_limit(&text)?;
    writeln!(
        text,
        "Runtime source: {} ({}) {}..{}",
        match result.runtime_source.status {
            sideeffect::audit_session::SourceStatus::Complete => "complete",
            sideeffect::audit_session::SourceStatus::Partial => "partial",
            sideeffect::audit_session::SourceStatus::Unknown => "unknown",
            sideeffect::audit_session::SourceStatus::NotChecked => "not_checked",
            sideeffect::audit_session::SourceStatus::Unsupported => "unsupported",
            sideeffect::audit_session::SourceStatus::NotApplicable => "not_applicable",
            sideeffect::audit_session::SourceStatus::Unavailable => "unavailable",
            sideeffect::audit_session::SourceStatus::AccessDenied => "access_denied",
            sideeffect::audit_session::SourceStatus::Failed => "failed",
            sideeffect::audit_session::SourceStatus::TimedOut => "timed_out",
            sideeffect::audit_session::SourceStatus::OutputLimitExceeded => "output_limit_exceeded",
        },
        terminal_safe_text(&result.runtime_source.scope),
        result.runtime_source.started_at_unix_ms,
        result.runtime_source.ended_at_unix_ms
    )
    .map_err(|_| "could not format session query text".to_owned())?;
    check_event_query_text_limit(&text)?;
    writeln!(
        text,
        "Capture completeness: {}; event parse/adaptation: {:?}",
        terminal_safe_text(&result.capture.completeness),
        result.event_query_result.source_state.completeness
    )
    .map_err(|_| "could not format session query text".to_owned())?;
    check_event_query_text_limit(&text)?;
    for code in &result.runtime_source.diagnostic_codes {
        writeln!(
            text,
            "- session source diagnostic: {}",
            terminal_safe_text(code)
        )
        .map_err(|_| "could not format session query text".to_owned())?;
        check_event_query_text_limit(&text)?;
    }
    let events_text = format_event_query_text(&result.event_query_result)?;
    if text.len().saturating_add(events_text.len()) > sideeffect::query::MAX_QUERY_OUTPUT_BYTES {
        return Err(format!(
            "session event query text exceeds the {}-byte output limit",
            sideeffect::query::MAX_QUERY_OUTPUT_BYTES
        ));
    }
    text.push_str(&events_text);
    Ok(text)
}

fn format_event_query_text(result: &sideeffect::query::EventQueryResult) -> Result<String, String> {
    use std::fmt::Write as _;
    let mut text = String::new();
    let platform = match result.source.platform {
        sideeffect::event::SourcePlatform::Linux => "linux",
        sideeffect::event::SourcePlatform::Windows => "windows",
    };
    let completeness = match result.source_state.completeness {
        sideeffect::event::SourceCompleteness::Complete => "complete",
        sideeffect::event::SourceCompleteness::Partial => "partial",
        sideeffect::event::SourceCompleteness::Unknown => "unknown",
    };
    writeln!(
        text,
        "Event query: {} ({}), {} result(s)",
        platform, completeness, result.matched_count
    )
    .map_err(|_| "could not format event query text".to_owned())?;
    check_event_query_text_limit(&text)?;
    writeln!(text, "Full-input diagnostics: {}", result.diagnostics.len())
        .map_err(|_| "could not format event query text".to_owned())?;
    check_event_query_text_limit(&text)?;
    for diagnostic in &result.source_state.diagnostics {
        writeln!(text, "- source: {}", terminal_safe_text(diagnostic))
            .map_err(|_| "could not format event query text".to_owned())?;
        check_event_query_text_limit(&text)?;
    }
    for diagnostic in &result.diagnostics {
        writeln!(
            text,
            "- event {}: {} ({})",
            diagnostic
                .source_local_ordinal
                .map_or_else(|| "?".to_owned(), |ordinal| ordinal.to_string()),
            terminal_safe_text(&diagnostic.code),
            terminal_safe_text(&diagnostic.message)
        )
        .map_err(|_| "could not format event query text".to_owned())?;
        check_event_query_text_limit(&text)?;
    }
    for event in &result.events {
        let evidence = serde_json::to_string(&event.evidence)
            .map_err(|error| format!("could not format event evidence: {error}"))?;
        let path = event
            .path_observation
            .as_ref()
            .map(|observation| format!(" path={}", terminal_safe_text(&observation.path)))
            .unwrap_or_default();
        writeln!(
            text,
            "- #{} {} [{}] evidence={}{}",
            event.source_local_ordinal,
            terminal_safe_text(&event.event_kind),
            match &event.operation {
                sideeffect::event::OperationSemantics::SyscallAttempt { .. } => "syscall_attempt",
                sideeffect::event::OperationSemantics::NativeObservation => "native_observation",
            },
            evidence,
            path
        )
        .map_err(|_| "could not format event query text".to_owned())?;
        check_event_query_text_limit(&text)?;
    }
    Ok(text)
}

fn check_event_query_text_limit(text: &str) -> Result<(), String> {
    if text.len() > sideeffect::query::MAX_QUERY_OUTPUT_BYTES {
        Err(format!(
            "event query text exceeds the {}-byte output limit",
            sideeffect::query::MAX_QUERY_OUTPUT_BYTES
        ))
    } else {
        Ok(())
    }
}

fn graph_trace(
    path: &OsString,
    event_kind: Option<&OsString>,
    process_observation_id: Option<&OsString>,
    output_format: &str,
    output_path: Option<&OsString>,
) -> Result<ExitCode, String> {
    let event_kind = parse_event_kind_filter(event_kind)?;
    let process_observation_id = parse_process_observation_filter(process_observation_id)?;
    let bytes = read_bounded(path)?;
    let trace = parse_trace_bytes(&bytes, ParseLimits::default())
        .map_err(|error| format!("trace graph adaptation failed: {error}"))?;
    let envelope = sideeffect::event::from_linux_strace(&trace, &bytes, "trace");
    write_event_graph(
        &envelope,
        event_kind,
        process_observation_id,
        output_format,
        output_path,
    )
}

fn graph_trace_with_filters(path: &OsString, arguments: &[OsString]) -> Result<ExitCode, String> {
    let options = parse_graph_filters(arguments)?;
    graph_trace(
        path,
        options.event_kind.as_ref(),
        options.process_observation_id.as_ref(),
        options.output_format,
        options.output_path.as_ref(),
    )
}

struct GraphCliOptions {
    event_kind: Option<OsString>,
    process_observation_id: Option<OsString>,
    output_format: &'static str,
    output_path: Option<OsString>,
}

fn parse_graph_filters(arguments: &[OsString]) -> Result<GraphCliOptions, String> {
    let mut event_kind = None;
    let mut process_observation_id = None;
    let mut output_format = "json";
    let mut format_seen = false;
    let mut output_path = None;
    let mut filter_seen = false;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        if flag == "--format" {
            if format_seen {
                return Err("duplicate graph option --format".to_owned());
            }
            let value = arguments
                .get(index + 1)
                .ok_or("graph option --format requires a value")?;
            if value.to_string_lossy().starts_with("--") {
                return Err("graph option --format requires a value".to_owned());
            }
            output_format = match value.to_str() {
                Some("json") => "json",
                Some("text") => "text",
                Some("html") => "html",
                _ => return Err("graph format must be json, text, or html".to_owned()),
            };
            format_seen = true;
            index += 2;
            continue;
        }
        if flag == "--output" {
            if output_path.is_some() {
                return Err("duplicate graph option --output".to_owned());
            }
            let value = arguments
                .get(index + 1)
                .ok_or("graph option --output requires a value")?;
            if value.to_string_lossy().starts_with("--") {
                return Err("graph option --output requires a value".to_owned());
            }
            output_path = Some(value.clone());
            index += 2;
            continue;
        }
        let destination = if flag == "--event-kind" {
            &mut event_kind
        } else if flag == "--process-observation" {
            &mut process_observation_id
        } else {
            return Err(format!(
                "unknown graph option {}",
                terminal_safe_text(&flag.to_string_lossy())
            ));
        };
        if destination.is_some() {
            return Err(format!(
                "duplicate graph option {}",
                terminal_safe_text(&flag.to_string_lossy())
            ));
        }
        if filter_seen {
            return Err("graph accepts one filter at a time".to_owned());
        }
        let value = arguments.get(index + 1).ok_or_else(|| {
            format!(
                "graph option {} requires a value",
                terminal_safe_text(&flag.to_string_lossy())
            )
        })?;
        if value.to_string_lossy().starts_with("--") {
            return Err(format!(
                "graph option {} requires a value",
                terminal_safe_text(&flag.to_string_lossy())
            ));
        }
        *destination = Some(value.clone());
        filter_seen = true;
        index += 2;
    }
    if output_path.is_some() && output_format != "html" {
        return Err("graph --output is valid only with --format html".to_owned());
    }
    if output_format == "html" && output_path.is_none() {
        return Err("graph --format html requires --output <new-report.html>".to_owned());
    }
    Ok(GraphCliOptions {
        event_kind,
        process_observation_id,
        output_format,
        output_path,
    })
}

#[cfg(windows)]
fn graph_windows_runtime(
    path: &OsString,
    event_kind: Option<&OsString>,
    process_observation_id: Option<&OsString>,
    output_format: &str,
    output_path: Option<&OsString>,
) -> Result<ExitCode, String> {
    let event_kind = parse_event_kind_filter(event_kind)?;
    let process_observation_id = parse_process_observation_filter(process_observation_id)?;
    let bytes = read_input_file(
        Path::new(path),
        sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        "Windows runtime capture",
    )?;
    let capture = sideeffect::windows_runtime::inspect_windows_runtime_bytes(&bytes)
        .map_err(|error| format!("Windows runtime graph adaptation failed: {error}"))?;
    let envelope = sideeffect::event::from_windows_runtime_capture(&capture);
    write_event_graph(
        &envelope,
        event_kind,
        process_observation_id,
        output_format,
        output_path,
    )
}

#[cfg(windows)]
fn graph_windows_runtime_with_filters(
    path: &OsString,
    arguments: &[OsString],
) -> Result<ExitCode, String> {
    let options = parse_graph_filters(arguments)?;
    graph_windows_runtime(
        path,
        options.event_kind.as_ref(),
        options.process_observation_id.as_ref(),
        options.output_format,
        options.output_path.as_ref(),
    )
}

#[cfg(not(windows))]
fn graph_windows_runtime(
    _path: &OsString,
    _event_kind: Option<&OsString>,
    _process_observation_id: Option<&OsString>,
    _output_format: &str,
    _output_path: Option<&OsString>,
) -> Result<ExitCode, String> {
    Err("graph --windows-runtime is supported only in native Windows builds".to_owned())
}

#[cfg(not(windows))]
fn graph_windows_runtime_with_filters(
    path: &OsString,
    arguments: &[OsString],
) -> Result<ExitCode, String> {
    let options = parse_graph_filters(arguments)?;
    graph_windows_runtime(
        path,
        None,
        None,
        options.output_format,
        options.output_path.as_ref(),
    )
}

fn write_event_graph(
    envelope: &sideeffect::event::CommonEventEnvelope,
    event_kind: Option<&str>,
    process_observation_id: Option<u64>,
    output_format: &str,
    output_path: Option<&OsString>,
) -> Result<ExitCode, String> {
    let complete =
        envelope.source_state.completeness == sideeffect::event::SourceCompleteness::Complete;
    let graph = sideeffect::event::graph(envelope, event_kind, process_observation_id)?;
    match output_format {
        "json" => write_json(&graph, "event graph")?,
        "text" => {
            let mut output = CappedBuffer::new(sideeffect::format::MAX_EVENT_GRAPH_TEXT_BYTES);
            sideeffect::format::write_event_graph_text(&graph, &mut output)
                .map_err(|_| "event graph text exceeds its bounded output limit".to_owned())?;
            std::io::stdout()
                .write_all(&output.bytes)
                .map_err(|_| "could not write bounded event graph text to stdout".to_owned())?;
        }
        "html" => {
            let output_path = output_path.ok_or("graph HTML output requires --output")?;
            let mut html = CappedBuffer::new(MAX_REPORT_BYTES);
            sideeffect::format::write_event_graph_html(&graph, &mut html).map_err(|_| {
                if html.exceeded {
                    format!("event graph HTML exceeds the {MAX_REPORT_BYTES} byte output limit")
                } else {
                    "could not render bounded event graph HTML".to_owned()
                }
            })?;
            let report = publish_graph_html(Path::new(output_path), &html.bytes)?;
            eprintln!(
                "Offline event graph HTML report written to {}. It may contain sensitive local evidence; review before sharing.",
                terminal_safe_path(&report)
            );
        }
        _ => return Err("graph output format is unsupported".to_owned()),
    }
    Ok(if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn publish_graph_html(path: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    #[cfg(target_os = "linux")]
    {
        publish_private_file(path, bytes, MAX_REPORT_BYTES).map_err(|_| {
            "could not publish event graph HTML without replacing an existing file".to_owned()
        })
    }
    #[cfg(windows)]
    {
        publish_private_windows_file(path, bytes, MAX_REPORT_BYTES).map_err(|_| {
            "could not publish event graph HTML without replacing an existing file".to_owned()
        })
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (path, bytes);
        Err("event graph HTML export is supported on Linux and native Windows builds".to_owned())
    }
}

fn timeline_trace(
    path: &OsString,
    event_kind: Option<&OsString>,
    process_observation_id: Option<&OsString>,
    output_format: &str,
) -> Result<ExitCode, String> {
    let kind = parse_event_kind_filter(event_kind)?;
    let process_observation_id = parse_process_observation_filter(process_observation_id)?;
    let bytes = read_bounded(path)?;
    let trace = parse_trace_bytes(&bytes, ParseLimits::default())
        .map_err(|error| format!("trace timeline adaptation failed: {error}"))?;
    let envelope = sideeffect::event::from_linux_strace(&trace, &bytes, "trace");
    let complete =
        envelope.source_state.completeness == sideeffect::event::SourceCompleteness::Complete;
    let timeline = sideeffect::event::timeline(&envelope, kind, process_observation_id)?;
    write_event_timeline(&timeline, output_format)?;
    Ok(if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn timeline_trace_with_filters(
    path: &OsString,
    arguments: &[OsString],
) -> Result<ExitCode, String> {
    let (event_kind, process_observation_id, output_format) = parse_timeline_filters(arguments)?;
    timeline_trace(
        path,
        event_kind.as_ref(),
        process_observation_id.as_ref(),
        output_format,
    )
}

fn parse_timeline_filters(
    arguments: &[OsString],
) -> Result<(Option<OsString>, Option<OsString>, &'static str), String> {
    let mut event_kind = None;
    let mut process_observation_id = None;
    let mut output_format = "json";
    let mut format_seen = false;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        if flag == "--format" {
            if format_seen {
                return Err("duplicate timeline option --format".to_owned());
            }
            let value = arguments
                .get(index + 1)
                .ok_or("timeline option --format requires a value")?;
            if value.to_string_lossy().starts_with("--") {
                return Err("timeline option --format requires a value".to_owned());
            }
            output_format = match value.to_str() {
                Some("json") => "json",
                Some("text") => "text",
                _ => return Err("timeline format must be json or text".to_owned()),
            };
            format_seen = true;
            index += 2;
            continue;
        }
        let destination = if flag == "--event-kind" {
            &mut event_kind
        } else if flag == "--process-observation" {
            &mut process_observation_id
        } else {
            return Err(format!(
                "unknown timeline option {}; expected --event-kind or --process-observation",
                terminal_safe_text(&flag.to_string_lossy())
            ));
        };
        if destination.is_some() {
            return Err(format!(
                "duplicate timeline option {}",
                flag.to_string_lossy()
            ));
        }
        let value = arguments.get(index + 1).ok_or_else(|| {
            format!(
                "timeline option {} requires a value",
                flag.to_string_lossy()
            )
        })?;
        if value.to_string_lossy().starts_with("--") {
            return Err(format!(
                "timeline option {} requires a value",
                flag.to_string_lossy()
            ));
        }
        *destination = Some(value.clone());
        index += 2;
    }
    Ok((event_kind, process_observation_id, output_format))
}

fn write_event_timeline(
    timeline: &sideeffect::event::EventTimeline,
    output_format: &str,
) -> Result<(), String> {
    if output_format == "json" {
        return write_json(timeline, "event timeline");
    }
    let mut output = CappedBuffer::new(sideeffect::format::MAX_TIMELINE_TEXT_BYTES);
    sideeffect::format::write_timeline_text(timeline, &mut output)
        .map_err(|_| "timeline text exceeds its bounded output limit".to_owned())?;
    std::io::stdout()
        .write_all(&output.bytes)
        .map_err(|_| "could not write bounded timeline text to stdout".to_owned())
}

#[cfg(windows)]
fn timeline_windows_runtime(
    path: &OsString,
    event_kind: Option<&OsString>,
    process_observation_id: Option<&OsString>,
    output_format: &str,
) -> Result<ExitCode, String> {
    let kind = parse_event_kind_filter(event_kind)?;
    let process_observation_id = parse_process_observation_filter(process_observation_id)?;
    let bytes = read_input_file(
        Path::new(path),
        sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        "Windows runtime capture",
    )?;
    let capture = sideeffect::windows_runtime::inspect_windows_runtime_bytes(&bytes)
        .map_err(|error| format!("Windows runtime timeline adaptation failed: {error}"))?;
    let envelope = sideeffect::event::from_windows_runtime_capture(&capture);
    let complete =
        envelope.source_state.completeness == sideeffect::event::SourceCompleteness::Complete;
    let timeline = sideeffect::event::timeline(&envelope, kind, process_observation_id)?;
    write_event_timeline(&timeline, output_format)?;
    Ok(if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn timeline_windows_runtime_with_filters(
    path: &OsString,
    arguments: &[OsString],
) -> Result<ExitCode, String> {
    let (event_kind, process_observation_id, output_format) = parse_timeline_filters(arguments)?;
    timeline_windows_runtime(
        path,
        event_kind.as_ref(),
        process_observation_id.as_ref(),
        output_format,
    )
}

#[cfg(not(windows))]
fn timeline_windows_runtime(
    _path: &OsString,
    _event_kind: Option<&OsString>,
    _process_observation_id: Option<&OsString>,
    _output_format: &str,
) -> Result<ExitCode, String> {
    Err("timeline --windows-runtime is supported only in native Windows builds".to_owned())
}

fn parse_event_kind_filter(event_kind: Option<&OsString>) -> Result<Option<&str>, String> {
    event_kind
        .map(|value| {
            let kind = value
                .to_str()
                .ok_or_else(|| "event kind filter must be valid UTF-8".to_owned())?;
            if kind.is_empty() || kind.len() > 128 || kind.chars().any(char::is_control) {
                return Err("event kind filter must be 1..128 printable UTF-8 bytes".to_owned());
            }
            Ok(kind)
        })
        .transpose()
}

fn parse_process_observation_filter(
    process_observation_id: Option<&OsString>,
) -> Result<Option<u64>, String> {
    process_observation_id
        .map(|value| parse_positive_u64(value, "process observation ID"))
        .transpose()
}

#[cfg(windows)]
fn events_windows_runtime(path: &OsString) -> Result<ExitCode, String> {
    let bytes = read_input_file(
        Path::new(path),
        sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        "Windows runtime capture",
    )?;
    let capture = sideeffect::windows_runtime::inspect_windows_runtime_bytes(&bytes)
        .map_err(|error| format!("Windows runtime event adaptation failed: {error}"))?;
    let envelope = sideeffect::event::from_windows_runtime_capture(&capture);
    let complete =
        envelope.source_state.completeness == sideeffect::event::SourceCompleteness::Complete;
    write_json(&envelope, "common event envelope")?;
    Ok(if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

#[cfg(not(windows))]
fn events_windows_runtime(_path: &OsString) -> Result<ExitCode, String> {
    Err("events --windows-runtime is supported only in native Windows builds".to_owned())
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

fn compare_audit_sessions(
    before_path: &OsString,
    after_path: &OsString,
) -> Result<ExitCode, String> {
    let before = read_verified_audit_session(Path::new(before_path))?;
    let after = read_verified_audit_session(Path::new(after_path))?;
    #[cfg(target_os = "linux")]
    let report = {
        let before_artifacts: Vec<_> = before
            .artifacts()
            .iter()
            .map(
                |artifact| sideeffect::audit_session_diff::VerifiedArtifactBytes {
                    kind: artifact.kind(),
                    path: artifact.path(),
                    bytes: artifact.bytes(),
                },
            )
            .collect();
        let after_artifacts: Vec<_> = after
            .artifacts()
            .iter()
            .map(
                |artifact| sideeffect::audit_session_diff::VerifiedArtifactBytes {
                    kind: artifact.kind(),
                    path: artifact.path(),
                    bytes: artifact.bytes(),
                },
            )
            .collect();
        let mut report = sideeffect::audit_session_diff::compare_audit_sessions(
            before.manifest(),
            after.manifest(),
            &before_artifacts,
            &after_artifacts,
        );
        compare_linux_session_runtime(
            &mut report,
            before.manifest(),
            after.manifest(),
            &before_artifacts,
            &after_artifacts,
        );
        report.refresh_item_comparison_status();
        report
    };
    #[cfg(windows)]
    let report = {
        let before_artifacts: Vec<_> = before
            .artifacts()
            .iter()
            .map(
                |artifact| sideeffect::audit_session_diff::VerifiedArtifactBytes {
                    kind: artifact.kind(),
                    path: artifact.path(),
                    bytes: artifact.bytes(),
                },
            )
            .collect();
        let after_artifacts: Vec<_> = after
            .artifacts()
            .iter()
            .map(
                |artifact| sideeffect::audit_session_diff::VerifiedArtifactBytes {
                    kind: artifact.kind(),
                    path: artifact.path(),
                    bytes: artifact.bytes(),
                },
            )
            .collect();
        let mut report = sideeffect::audit_session_diff::compare_audit_sessions(
            before.manifest(),
            after.manifest(),
            &before_artifacts,
            &after_artifacts,
        );
        compare_windows_session_runtime(
            &mut report,
            before.manifest(),
            after.manifest(),
            &before_artifacts,
            &after_artifacts,
        );
        report.refresh_item_comparison_status();
        report
    };
    let comparable = report.comparable;
    write_json(&report, "audit-session diff report")?;
    Ok(if comparable {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn verified_runtime_artifact<'manifest, 'bytes>(
    manifest: &'manifest sideeffect::audit_session::AuditSessionManifest,
    artifacts: &'bytes [sideeffect::audit_session_diff::VerifiedArtifactBytes<'bytes>],
    kind: sideeffect::audit_session::ArtifactKind,
    expected_path: &str,
    expected_schema: &str,
    expected_version: u32,
) -> Result<
    (
        &'manifest sideeffect::audit_session::SessionArtifactRef,
        &'bytes [u8],
    ),
    &'static str,
> {
    use sideeffect::audit_session::SourceRole;
    let source = manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::Runtime)
        .ok_or("runtime_source_missing")?;
    let reference = source
        .artifacts
        .iter()
        .find(|reference| reference.kind == kind)
        .ok_or("runtime_artifact_missing")?;
    if reference.path != expected_path
        || reference.schema != expected_schema
        || reference.schema_version != expected_version
    {
        return Err("runtime_artifact_contract_mismatch");
    }
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact.kind == kind && artifact.path == reference.path)
        .ok_or("runtime_artifact_reference_mismatch")?;
    if artifact.bytes.len() as u64 != reference.byte_length
        || format!("{:x}", Sha256::digest(artifact.bytes)) != reference.sha256
    {
        return Err("runtime_artifact_reference_mismatch");
    }
    Ok((reference, artifact.bytes))
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
struct LinuxSessionRunMetadata {
    schema_version: u32,
    tracer_name: String,
    tracer_major: u64,
    tracer_minor: u64,
    capture_profile: String,
    strace_reported_status: String,
    command_outcome: String,
    capture_completeness: String,
    time_limit_milliseconds: Option<u64>,
    stop_reason: Option<String>,
    trace_byte_length: u64,
    trace_sha256: String,
}

#[cfg(target_os = "linux")]
fn compare_linux_session_runtime(
    report: &mut sideeffect::audit_session_diff::AuditSessionDiff,
    before: &sideeffect::audit_session::AuditSessionManifest,
    after: &sideeffect::audit_session::AuditSessionManifest,
    before_artifacts: &[sideeffect::audit_session_diff::VerifiedArtifactBytes<'_>],
    after_artifacts: &[sideeffect::audit_session_diff::VerifiedArtifactBytes<'_>],
) {
    let Some(entry) = report
        .source_diffs
        .iter_mut()
        .find(|source| source.role == sideeffect::audit_session::SourceRole::Runtime)
    else {
        return;
    };
    if entry.reason_code != Some("role_not_supported_by_item_diff") {
        return;
    }

    let result = compare_linux_runtime_pair(before, after, before_artifacts, after_artifacts);
    match result {
        Ok((metadata_before, metadata_after, trace_diff)) => {
            entry.status = "partial";
            entry.reason_code = Some("runtime_capture_completeness_unknown");
            entry.comparison = Some(serde_json::json!({
                "runtime_kind":"linux_strace",
                "run_metadata":{"before":metadata_before,"after":metadata_after},
                "trace_diff":trace_diff,
                "capture_completeness":"unknown"
            }));
        }
        Err(RuntimePairIssue::Partial(reason, detail)) => {
            entry.status = "partial";
            entry.reason_code = Some(reason);
            entry.comparison = detail;
        }
        Err(RuntimePairIssue::NotCompared(reason)) => {
            entry.status = "not_compared";
            entry.reason_code = Some(reason);
        }
        Err(RuntimePairIssue::Incomparable(reason)) => {
            entry.status = "incomparable";
            entry.reason_code = Some(reason);
        }
    }
}

#[cfg(target_os = "linux")]
enum RuntimePairIssue {
    Partial(&'static str, Option<serde_json::Value>),
    NotCompared(&'static str),
    Incomparable(&'static str),
}

#[cfg(target_os = "linux")]
fn runtime_issue(reason: &'static str) -> RuntimePairIssue {
    match reason {
        "runtime_source_missing" | "runtime_artifact_missing" => {
            RuntimePairIssue::NotCompared(reason)
        }
        "runtime_artifact_input_limit_exceeded" => RuntimePairIssue::NotCompared(reason),
        "runtime_artifact_contract_mismatch" | "runtime_artifact_reference_mismatch" => {
            RuntimePairIssue::Incomparable(reason)
        }
        _ => RuntimePairIssue::Incomparable(reason),
    }
}

#[cfg(target_os = "linux")]
fn compare_linux_runtime_pair(
    before: &sideeffect::audit_session::AuditSessionManifest,
    after: &sideeffect::audit_session::AuditSessionManifest,
    before_artifacts: &[sideeffect::audit_session_diff::VerifiedArtifactBytes<'_>],
    after_artifacts: &[sideeffect::audit_session_diff::VerifiedArtifactBytes<'_>],
) -> Result<
    (
        LinuxSessionRunMetadata,
        LinuxSessionRunMetadata,
        serde_json::Value,
    ),
    RuntimePairIssue,
> {
    use sideeffect::audit_session::ArtifactKind;
    let side =
        |manifest: &sideeffect::audit_session::AuditSessionManifest,
         artifacts: &[sideeffect::audit_session_diff::VerifiedArtifactBytes<'_>]| {
            let (run_ref, run_bytes) = verified_runtime_artifact(
                manifest,
                artifacts,
                ArtifactKind::RuntimeManifest,
                "run.json",
                "sideeffect.run",
                2,
            )
            .map_err(runtime_issue)?;
            let (trace_ref, trace_bytes) = verified_runtime_artifact(
                manifest,
                artifacts,
                ArtifactKind::RuntimeTrace,
                "trace.strace",
                "strace_text",
                1,
            )
            .map_err(runtime_issue)?;
            if run_bytes.len() > sideeffect::limits::MAX_BUNDLE_MANIFEST_BYTES
                || trace_bytes.len() > sideeffect::limits::MAX_TRACE_BYTES
            {
                return Err(RuntimePairIssue::NotCompared(
                    "runtime_artifact_input_limit_exceeded",
                ));
            }
            let manifest: RunManifest = serde_json::from_slice(run_bytes)
                .map_err(|_| RuntimePairIssue::Incomparable("runtime_manifest_invalid"))?;
            validate_bundle_manifest(&manifest)
                .map_err(|_| RuntimePairIssue::Incomparable("runtime_manifest_invalid"))?;
            if manifest.schema_version != run_ref.schema_version
                || manifest.trace.name != trace_ref.path
                || manifest.trace.format != trace_ref.schema
                || manifest.trace.byte_length != trace_ref.byte_length
                || manifest.trace.byte_length != trace_bytes.len() as u64
                || manifest.trace.sha256 != trace_ref.sha256
                || format!("{:x}", Sha256::digest(trace_bytes)) != manifest.trace.sha256
            {
                return Err(RuntimePairIssue::Incomparable(
                    "runtime_manifest_trace_contract_mismatch",
                ));
            }
            let run_metadata = LinuxSessionRunMetadata {
                schema_version: manifest.schema_version,
                tracer_name: manifest.capture.tracer.name.clone(),
                tracer_major: manifest.capture.tracer.major,
                tracer_minor: manifest.capture.tracer.minor,
                capture_profile: manifest.capture.capture_profile.clone(),
                strace_reported_status: match manifest.capture.strace_reported_status {
                    BundleStatus::ExitCode { value } => format!("exit_code:{value}"),
                    BundleStatus::Signal { value } => format!("signal:{value}"),
                    BundleStatus::Unavailable => "unavailable".to_owned(),
                },
                command_outcome: manifest.capture.command_outcome.clone(),
                capture_completeness: manifest.capture.completeness.clone(),
                time_limit_milliseconds: manifest.capture.time_limit_milliseconds,
                stop_reason: manifest.capture.stop_reason.clone(),
                trace_byte_length: manifest.trace.byte_length,
                trace_sha256: manifest.trace.sha256.clone(),
            };
            let trace = parse_trace_bytes(trace_bytes, ParseLimits::default()).map_err(
                |error| match error {
                    sideeffect::trace::strace::ParseError::InputTooLarge { .. }
                    | sideeffect::trace::strace::ParseError::RecordTooLarge { .. }
                    | sideeffect::trace::strace::ParseError::TooManyRecords { .. } => {
                        RuntimePairIssue::NotCompared("runtime_trace_parse_limit_exceeded")
                    }
                    sideeffect::trace::strace::ParseError::InvalidUtf8 { .. } => {
                        RuntimePairIssue::Incomparable("runtime_trace_encoding_invalid")
                    }
                },
            )?;
            Ok((run_metadata, trace))
        };

    let (metadata_before, trace_before) = side(before, before_artifacts)?;
    let (metadata_after, trace_after) = side(after, after_artifacts)?;
    if trace_before.parse_status != ParseCompleteness::Complete
        || trace_after.parse_status != ParseCompleteness::Complete
    {
        return Err(RuntimePairIssue::Partial(
            "runtime_trace_parse_incomplete",
            Some(serde_json::json!({
                "runtime_kind":"linux_strace",
                "before_parse_status":trace_before.parse_status,
                "before_diagnostic_count":trace_before.diagnostics.len(),
                "after_parse_status":trace_after.parse_status,
                "after_diagnostic_count":trace_after.diagnostics.len()
            })),
        ));
    }
    let diff =
        sideeffect::diff::compare_traces(&trace_before, &trace_after).map_err(
            |error| match error {
                sideeffect::diff::DiffError::PartialParse { .. } => {
                    RuntimePairIssue::Partial("runtime_trace_parse_incomplete", None)
                }
                sideeffect::diff::DiffError::InputTooLarge { .. }
                | sideeffect::diff::DiffError::TooManyRecords { .. }
                | sideeffect::diff::DiffError::AllocationFailed { .. } => {
                    RuntimePairIssue::NotCompared("runtime_comparison_limit_exceeded")
                }
                sideeffect::diff::DiffError::InconsistentDocument { .. } => {
                    RuntimePairIssue::Incomparable("runtime_trace_document_inconsistent")
                }
            },
        )?;
    let diff = serde_json::to_value(diff)
        .map_err(|_| RuntimePairIssue::Incomparable("runtime_diff_serialization_failed"))?;
    Ok((metadata_before, metadata_after, diff))
}

#[cfg(windows)]
fn compare_windows_session_runtime(
    report: &mut sideeffect::audit_session_diff::AuditSessionDiff,
    before: &sideeffect::audit_session::AuditSessionManifest,
    after: &sideeffect::audit_session::AuditSessionManifest,
    before_artifacts: &[sideeffect::audit_session_diff::VerifiedArtifactBytes<'_>],
    after_artifacts: &[sideeffect::audit_session_diff::VerifiedArtifactBytes<'_>],
) {
    use sideeffect::audit_session::{ArtifactKind, SourceRole};
    let Some(entry) = report
        .source_diffs
        .iter_mut()
        .find(|source| source.role == SourceRole::Runtime)
    else {
        return;
    };
    if entry.reason_code != Some("role_not_supported_by_item_diff") {
        return;
    }
    let compare_side =
        |manifest: &sideeffect::audit_session::AuditSessionManifest,
         artifacts: &[sideeffect::audit_session_diff::VerifiedArtifactBytes<'_>]| {
            let (_, bytes) = verified_runtime_artifact(
                manifest,
                artifacts,
                ArtifactKind::WindowsRuntimeCapture,
                "runtime.windows.json",
                sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA,
                sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
            )?;
            if bytes.len() > sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES {
                return Err("runtime_artifact_input_limit_exceeded");
            }
            sideeffect::windows_runtime::inspect_windows_runtime_bytes(bytes)
                .map_err(|_| "runtime_capture_invalid")
        };
    let result = (|| {
        let left = compare_side(before, before_artifacts)?;
        let right = compare_side(after, after_artifacts)?;
        let summary =
            sideeffect::windows_runtime_diff::compare_windows_runtime_captures(&left, &right)
                .map_err(|_| "runtime_comparison_limit_exceeded")?;
        serde_json::to_value(summary).map_err(|_| "runtime_diff_serialization_failed")
    })();
    match result {
        Ok(comparison) => {
            entry.status = "partial";
            entry.reason_code = Some("runtime_capture_completeness_unknown");
            entry.comparison = Some(comparison);
        }
        Err(reason) => {
            entry.status = if reason == "runtime_artifact_input_limit_exceeded"
                || reason == "runtime_comparison_limit_exceeded"
            {
                "not_compared"
            } else {
                "incomparable"
            };
            entry.reason_code = Some(reason);
            entry.comparison = None;
        }
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

fn associated_behavior(startup_path: &OsString, trace_path: &OsString) -> Result<ExitCode, String> {
    let startup_bytes = read_input_file(
        Path::new(startup_path),
        MAX_REPORT_BYTES,
        "startup inventory",
    )?;
    let runtime_bytes =
        read_input_file(Path::new(trace_path), MAX_TRACE_BYTES, "runtime evidence")?;
    let startup_schema = serde_json::from_slice::<serde_json::Value>(&startup_bytes)
        .ok()
        .and_then(|value| {
            value
                .get("schema")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    if startup_schema.as_deref()
        == Some(sideeffect::windows_startup_correlation::WINDOWS_STARTUP_INVENTORY_SCHEMA)
    {
        let report = sideeffect::windows_startup_correlation::summarize_windows_startup_behavior(
            &startup_bytes,
            &runtime_bytes,
        )?;
        let partial = report.status == "partial";
        let candidate_count = report.summary.candidate_path_group_count;
        let association_status = report.association_status;
        return write_associated_behavior_report(
            &report,
            partial,
            candidate_count,
            association_status,
        );
    }
    let report = sideeffect::startup_correlation::summarize_associated_startup_behavior(
        &startup_bytes,
        &runtime_bytes,
    )?;
    let partial = report.status == "partial";
    let candidate_count = report.summary.candidate_match_count;
    let association_status = report.association_status;
    write_associated_behavior_report(&report, partial, candidate_count, association_status)
}

fn write_associated_behavior_report<T: Serialize>(
    report: &T,
    partial: bool,
    candidate_count: usize,
    association_status: &str,
) -> Result<ExitCode, String> {
    let mut json = CappedBuffer::new(MAX_REPORT_BYTES);
    serde_json::to_writer(&mut json, &report).map_err(|error| {
        format!("associated-behavior output exceeds the {MAX_REPORT_BYTES} byte limit: {error}")
    })?;
    json.write_all(b"\n").map_err(|_| {
        format!("associated-behavior output exceeds the {MAX_REPORT_BYTES} byte limit")
    })?;
    write_buffer(&json, "associated-behavior summary")?;
    if partial {
        eprintln!(
            "Saved partial associated-behavior results with {candidate_count} candidate match(es); check diagnostics and source status."
        );
        Ok(ExitCode::from(2))
    } else {
        eprintln!(
            "Processed the supported associated-behavior subset: {candidate_count} candidate match(es), association status {association_status}. Capture completeness remains unknown."
        );
        Ok(ExitCode::SUCCESS)
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

#[cfg(windows)]
#[derive(Serialize)]
struct WindowsRuntimeEventEvidence<'a> {
    schema: &'static str,
    schema_version: u32,
    validation_status: &'static str,
    authenticity: &'static str,
    source_file_sha256: String,
    capture_sha256: &'a str,
    capture_status: sideeffect::windows_runtime::CollectionStatus,
    capture_completeness: &'a str,
    event_loss: &'a sideeffect::windows_runtime::EventLoss,
    record_ordinal: u64,
    json_pointer: String,
    raw_payload_sha256: String,
    decode_metadata_status: &'static str,
    event: &'a sideeffect::windows_runtime::NativeRuntimeEvent,
    diagnostics: &'a [String],
}

#[cfg(windows)]
fn evidence_windows_runtime(
    path: &OsString,
    digest: &OsString,
    ordinal: &OsString,
    payload_digest: &OsString,
) -> Result<ExitCode, String> {
    let expected_capture_digest = parse_sha256_digest(digest)?;
    let expected_payload_digest = parse_sha256_digest(payload_digest)?;
    let expected_ordinal = parse_reference_number(ordinal, "record ordinal")?;
    if expected_ordinal == 0 {
        return Err("record ordinal must be greater than zero".to_owned());
    }
    let bytes = read_input_file(
        Path::new(path),
        sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        "Windows runtime capture",
    )?;
    let capture = sideeffect::windows_runtime::inspect_windows_runtime_bytes(&bytes)
        .map_err(|error| format!("Windows runtime evidence validation failed: {error}"))?;
    if capture.document_sha256 != expected_capture_digest {
        return Err(format!(
            "capture SHA-256 mismatch: supplied {expected_capture_digest}, validated capture is {}",
            capture.document_sha256
        ));
    }
    let (index, event) = capture
        .events
        .iter()
        .enumerate()
        .find(|(_, event)| event.record_ordinal == expected_ordinal)
        .ok_or_else(|| format!("no Windows runtime event exists at ordinal {expected_ordinal}"))?;
    let payload = decode_validated_runtime_payload(&event.raw_payload_hex)?;
    let actual_payload_digest = format!("{:x}", Sha256::digest(&payload));
    if actual_payload_digest != expected_payload_digest {
        return Err(format!(
            "raw payload SHA-256 mismatch at ordinal {expected_ordinal}: supplied {expected_payload_digest}, event is {actual_payload_digest}"
        ));
    }

    let partial = capture.collection_status
        == sideeffect::windows_runtime::CollectionStatus::Partial
        || capture.capture_completeness != "complete";
    let report = WindowsRuntimeEventEvidence {
        schema: "sideeffect.windows_runtime_event_evidence",
        schema_version: 1,
        validation_status: "bounded_schema_and_capture_fingerprint_verified",
        authenticity: "not_verified",
        source_file_sha256: format!("{:x}", Sha256::digest(&bytes)),
        capture_sha256: &capture.document_sha256,
        capture_status: capture.collection_status,
        capture_completeness: &capture.capture_completeness,
        event_loss: &capture.event_loss,
        record_ordinal: event.record_ordinal,
        json_pointer: format!("/events/{index}"),
        raw_payload_sha256: actual_payload_digest,
        decode_metadata_status: "serialized_metadata_not_independently_verified",
        event,
        diagnostics: &capture.diagnostics,
    };
    write_json(&report, "Windows runtime event evidence")?;
    Ok(if partial {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(not(windows))]
fn evidence_windows_runtime(
    _path: &OsString,
    _digest: &OsString,
    _ordinal: &OsString,
    _payload_digest: &OsString,
) -> Result<ExitCode, String> {
    Err("evidence --windows-runtime is available only in native Windows builds".to_owned())
}

#[cfg(windows)]
fn decode_validated_runtime_payload(hex: &str) -> Result<Vec<u8>, String> {
    let source = hex.as_bytes();
    if source.len() % 2 != 0
        || source.len() > sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES * 2
    {
        return Err(
            "validated Windows runtime payload has an invalid bounded hex length".to_owned(),
        );
    }
    let mut decoded = Vec::with_capacity(source.len() / 2);
    for pair in source.chunks_exact(2) {
        let high = lower_hex_nibble(pair[0]).ok_or_else(|| {
            "validated Windows runtime payload is not lowercase hexadecimal".to_owned()
        })?;
        let low = lower_hex_nibble(pair[1]).ok_or_else(|| {
            "validated Windows runtime payload is not lowercase hexadecimal".to_owned()
        })?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

#[cfg(windows)]
fn lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
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

fn parse_positive_u32(value: &OsString, label: &str) -> Result<u32, String> {
    let value = parse_reference_number(value, label)?;
    if value == 0 {
        return Err(format!("{label} must be greater than zero"));
    }
    u32::try_from(value).map_err(|_| format!("{label} exceeds the supported numeric range"))
}

fn parse_positive_u64(value: &OsString, label: &str) -> Result<u64, String> {
    let value = parse_reference_number(value, label)?;
    if value == 0 {
        return Err(format!("{label} must be greater than zero"));
    }
    Ok(value)
}

fn inspect_with_format(format: &OsString, path: &OsString) -> Result<ExitCode, String> {
    if !matches!(format.to_str(), Some("json" | "text")) {
        return Err("inspect format must be either 'json' or 'text'".to_owned());
    }
    inspect_bytes_with_format(format, read_bounded(path)?)
}

fn attribute_windows_runtime(path: &OsString) -> Result<ExitCode, String> {
    let bytes = read_input_file(
        Path::new(path),
        sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        "Windows runtime capture",
    )?;
    let summary =
        sideeffect::windows_runtime_attribution::summarize_windows_runtime_attribution(&bytes)
            .map_err(|error| format!("Windows runtime attribution failed: {error}"))?;
    let partial = summary.status == "partial";
    write_json(&summary, "Windows runtime attribution summary")?;
    Ok(if partial {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
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

fn inspect_windows_runtime_html(
    output_path: &OsString,
    capture_path: &OsString,
) -> Result<ExitCode, String> {
    #[cfg(windows)]
    {
        let output_path = Path::new(output_path);
        match fs::symlink_metadata(output_path) {
            Ok(_) => {
                return Err(
                    "HTML report destination already exists; refusing to replace it".to_owned(),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "could not inspect HTML report destination: {error}"
                ));
            }
        }
        let bytes = read_input_file(
            Path::new(capture_path),
            sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
            "Windows runtime capture",
        )?;
        let source_sha256 = format!("{:x}", Sha256::digest(&bytes));
        let capture = sideeffect::windows_runtime::inspect_windows_runtime_bytes(&bytes)?;
        let partial =
            capture.collection_status == sideeffect::windows_runtime::CollectionStatus::Partial;
        let mut html = CappedBuffer::new(MAX_REPORT_BYTES);
        sideeffect::format::write_windows_runtime_html(&capture, &source_sha256, &mut html)
            .map_err(|error| {
                if html.exceeded {
                    format!("Windows runtime HTML report exceeds the {MAX_REPORT_BYTES} byte output limit")
                } else {
                    format!("could not render Windows runtime HTML report: {error}")
                }
            })?;
        let published = publish_private_windows_file(output_path, &html.bytes, MAX_REPORT_BYTES)
            .map_err(|error| {
                format!("could not publish HTML report without replacing a file: {error}")
            })?;
        eprintln!(
            "Offline Windows runtime HTML report written to {}. Capture data may be sensitive; review before sharing. This is one capture review, not a comparison.",
            terminal_safe_path(&published)
        );
        Ok(if partial {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (output_path, capture_path);
        Err(
            "Windows runtime HTML file export is available only in native Windows builds"
                .to_owned(),
        )
    }
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
        "inventory comparison input",
    )?;
    let after = read_input_file(
        Path::new(after_path),
        MAX_REPORT_BYTES.saturating_sub(before.len()),
        "inventory comparison input",
    )?;
    if is_selected_root_inventory_json(&before) || is_selected_root_inventory_json(&after) {
        let comparison = compare_selected_root_inventory_json(&before, &after)
            .map_err(|error| format!("selected-root inventory comparison failed: {error:?}"))?;
        let partial = comparison.status == "partial";
        write_json(&comparison, "JSON selected-root inventory comparison")?;
        return Ok(if partial {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        });
    }
    if is_permission_inventory_json(&before) || is_permission_inventory_json(&after) {
        let comparison = compare_permission_inventory_json(&before, &after)
            .map_err(|error| format!("permission inventory comparison failed: {error:?}"))?;
        let partial = comparison.status == PermissionDiffStatus::Partial;
        write_json(&comparison, "JSON permission inventory comparison")?;
        return Ok(if partial {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        });
    }
    if is_startup_inventory_json(&before) || is_startup_inventory_json(&after) {
        let comparison = compare_startup_inventory_json(&before, &after)
            .map_err(|error| format!("startup inventory comparison failed: {error:?}"))?;
        let partial = comparison.status == StartupDiffStatus::Partial;
        write_json(&comparison, "JSON startup inventory comparison")?;
        return Ok(if partial {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        });
    }
    if is_process_inventory_json(&before) || is_process_inventory_json(&after) {
        let comparison = compare_process_inventory_json(&before, &after)
            .map_err(|error| format!("process inventory comparison failed: {error:?}"))?;
        let partial = comparison.status == ProcessDiffStatus::Partial;
        write_json(&comparison, "JSON process inventory comparison")?;
        return Ok(if partial {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        });
    }
    if is_windows_software_inventory_json(&before) || is_windows_software_inventory_json(&after) {
        let comparison = compare_windows_software_inventory_json(&before, &after)
            .map_err(|error| format!("Windows software inventory comparison failed: {error:?}"))?;
        let partial = comparison.status == WindowsSoftwareComparisonStatus::Partial;
        write_json(&comparison, "JSON Windows software inventory comparison")?;
        if partial {
            Ok(ExitCode::from(2))
        } else {
            Ok(ExitCode::SUCCESS)
        }
    } else {
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
}

fn model_preview_file(question: &OsString, path: &OsString) -> Result<ExitCode, String> {
    let question = question
        .to_str()
        .ok_or("local model question must be valid UTF-8")?;
    let bytes = read_bounded(path)?;
    let model = selected_model_identity(ModelTask::EvidenceSelection)?;
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
    let model = selected_model_identity(ModelTask::QueryPlan)?;
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
    let model = selected_model_identity(ModelTask::Explanation)?;
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

fn model_windows_runtime_explanation_preview_file(
    question: &OsString,
    backend: &OsString,
    path: &OsString,
) -> Result<ExitCode, String> {
    let question = question
        .to_str()
        .ok_or("local model question must be valid UTF-8")?;
    let backend = parse_explanation_backend(backend)?;
    let bytes = read_bounded(path)?;
    let model = selected_model_identity(ModelTask::Explanation)?;
    let preview =
        sideeffect::local_model_explanation::preview_windows_runtime_explanation_bytes_for_model(
            &bytes, question, backend, &model,
        )?;
    let partial = preview.evidence_summary["parse_status"] == "partial";
    write_json(&preview, "local Windows ETW evidence explanation preview")?;
    Ok(if partial {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn parse_explanation_backend(
    backend: &OsStr,
) -> Result<sideeffect::local_model_explanation::ExplanationBackendPreference, String> {
    match backend.to_str() {
        Some("auto") => Ok(sideeffect::local_model_explanation::ExplanationBackendPreference::Auto),
        Some("cpu") => Ok(sideeffect::local_model_explanation::ExplanationBackendPreference::Cpu),
        Some("cuda") => Ok(sideeffect::local_model_explanation::ExplanationBackendPreference::Cuda),
        _ => Err("model explanation backend must be auto, cpu, or cuda".to_owned()),
    }
}

fn model_query_file(
    question: &OsString,
    runtime: Option<&OsString>,
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
    let model = selected_model_identity(ModelTask::QueryPlan)?;
    let runtime = resolve_runtime_path(ModelTask::QueryPlan, runtime)?;
    let analysis = sideeffect::local_query_plan::analyze_query_plan_bytes_for_model(
        &bytes, question, &runtime, &model, digest,
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
    runtime: Option<&OsString>,
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
    let model = selected_model_identity(ModelTask::Explanation)?;
    let runtime = resolve_runtime_path(ModelTask::Explanation, runtime)?;
    let analysis =
        sideeffect::local_model_explanation_runtime::analyze_model_explanation_bytes_for_model(
            &bytes, question, backend, &runtime, &model, digest,
        )?;
    let selected = analysis.interpretation.selection_status
        == sideeffect::local_model_explanation::ExplanationSelectionStatus::Selected;
    write_json(&analysis, "local model evidence selection")?;
    Ok(if selected {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn model_windows_runtime_explanation_file(
    question: &OsString,
    backend: &OsString,
    runtime: Option<&OsString>,
    digest: &OsString,
    capture_path: &OsString,
) -> Result<ExitCode, String> {
    let question = question
        .to_str()
        .ok_or("local model question must be valid UTF-8")?;
    let backend = parse_explanation_backend(backend)?;
    let digest = digest
        .to_str()
        .ok_or("preview digest must be 64 lowercase hexadecimal characters")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("preview digest must be 64 lowercase hexadecimal characters".to_owned());
    }
    let bytes = read_bounded(capture_path)?;
    let model = selected_model_identity(ModelTask::Explanation)?;
    let runtime = resolve_runtime_path(ModelTask::Explanation, runtime)?;
    let analysis = sideeffect::local_model_explanation_runtime::analyze_windows_runtime_explanation_bytes_for_model(
        &bytes, question, backend, &runtime, &model, digest,
    )?;
    let selected = analysis.interpretation.selection_status
        == sideeffect::local_model_explanation::ExplanationSelectionStatus::Selected;
    write_json(&analysis, "local Windows ETW evidence selection")?;
    Ok(if selected {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn model_analyze_file(
    question: &OsString,
    runtime: Option<&OsString>,
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
    let model = selected_model_identity(ModelTask::EvidenceSelection)?;
    let runtime = resolve_runtime_path(ModelTask::EvidenceSelection, runtime)?;
    let analysis = sideeffect::local_model::analyze_trace_bytes_for_model(
        &bytes, question, &runtime, &model, digest,
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

fn selected_model_identity(task: ModelTask) -> Result<ResolvedModel, String> {
    if !model_task_supported_here(task) {
        return Err(format!(
            "local model task '{}' is not supported on this platform",
            model_task_label(task)
        ));
    }
    sideeffect::model_manager::load_registry()?.selected_identity(task)
}

fn resolve_runtime_path(task: ModelTask, explicit: Option<&OsString>) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        if path.is_empty()
            || path.to_string_lossy().len() > sideeffect::model_manager::MAX_MODEL_PATH_BYTES
        {
            return Err("runtime path is empty or exceeds the path length limit".to_owned());
        }
        return Ok(PathBuf::from(path));
    }

    let configured = sideeffect::model_manager::load_registry()?
        .runtime_by_task
        .get(&task)
        .cloned()
        .ok_or_else(|| {
            format!(
                "no runtime is configured for {}; run 'sideeffect model runtime set {} PATH' or pass --runtime PATH",
                model_task_label(task),
                model_task_cli_name(task)
            )
        })?;
    revalidate_configured_runtime_path(task, &configured).map(|runtime| runtime.path)
}

fn revalidate_configured_runtime_path(
    task: ModelTask,
    runtime: &sideeffect::model_manager::ConfiguredRuntime,
) -> Result<sideeffect::model_manager::ConfiguredRuntime, String> {
    let canonical = runtime.path.canonicalize().map_err(|_| {
        format!(
            "configured runtime for {} is missing or inaccessible; run 'sideeffect model runtime set {} PATH' again or pass --runtime PATH",
            model_task_label(task),
            model_task_cli_name(task)
        )
    })?;
    if canonical != runtime.path {
        return Err(format!(
            "configured runtime for {} changed since it was saved; run 'sideeffect model runtime set {} PATH' again",
            model_task_label(task),
            model_task_cli_name(task)
        ));
    }
    sideeffect::model_manager::verify_configured_runtime(runtime).map_err(|_| {
        format!(
            "configured runtime for {} is missing, changed, or invalid; run 'sideeffect model runtime set {} PATH' again or pass --runtime PATH",
            model_task_label(task), model_task_cli_name(task)
        )
    })?;
    Ok(runtime.clone())
}

fn model_doctor(
    task: &OsString,
    runtime_path: Option<&OsString>,
    backend: Option<&OsString>,
) -> Result<ExitCode, String> {
    let task_name = task
        .to_str()
        .ok_or_else(|| "model task must be valid UTF-8".to_owned())?;
    let model_task = parse_model_task(task_name)?;
    let backend_name = match backend {
        None => Some("auto"),
        Some(value) => value.to_str(),
    }
    .ok_or_else(|| "backend must be valid UTF-8".to_owned())?;
    if model_task != ModelTask::Explanation && backend.is_some() {
        return Err("--backend is supported only for --task explanation".to_owned());
    }
    let backend = match backend_name {
        "auto" => sideeffect::local_model_explanation::ExplanationBackendPreference::Auto,
        "cpu" => sideeffect::local_model_explanation::ExplanationBackendPreference::Cpu,
        "cuda" => sideeffect::local_model_explanation::ExplanationBackendPreference::Cuda,
        _ => return Err("backend must be auto, cpu, or cuda".to_owned()),
    };

    let model = match selected_model(model_task) {
        Ok(model) => serde_json::json!({
            "status": "verified",
            "id": model.id,
            "name": model.name,
            "size_bytes": model.size_bytes,
            "sha256": model.sha256,
            "source": model.source,
            "license_id": model.license_id,
            "evaluation_status": model.evaluation,
            "recommended": model.recommended,
            "note": "File identity and registration match; compatibility and answer quality are not established."
        }),
        Err(error) => serde_json::json!({
            "status": "not_ready",
            "diagnostic": error
        }),
    };
    let expected_revision = match model_task {
        ModelTask::EvidenceSelection => sideeffect::local_model::RUNTIME_REVISION,
        ModelTask::Explanation => sideeffect::local_model_explanation::EXPLANATION_RUNTIME_REVISION,
        ModelTask::QueryPlan => sideeffect::local_query_plan::LOCAL_QUERY_PLAN_RUNTIME_REVISION,
    };
    let expected_version = match model_task {
        ModelTask::EvidenceSelection => sideeffect::local_model::RUNTIME_VERSION_PREFIX,
        ModelTask::Explanation => "pinned commit reported by --version",
        ModelTask::QueryPlan => sideeffect::local_query_plan::LOCAL_QUERY_PLAN_RUNTIME_VERSION,
    };
    let supported_here = model_task_supported_here(model_task);
    let runtime = if !supported_here {
        serde_json::json!({
            "runtime_path": null,
            "expected_source_revision": expected_revision,
            "expected_version_contract": expected_version,
            "executable_status": "unsupported_platform",
            "executable_diagnostic": format!("{} runtime doctor checks are supported on {} only", model_task_label(model_task), model_task_platform(model_task)),
            "device_check_status": "not_applicable",
            "device_diagnostic": null,
            "backend_readiness": "blocked_unsupported_platform",
            "gpu_inference_status": "not_run"
        })
    } else {
        match resolve_runtime_path(model_task, runtime_path) {
            Ok(path) => doctor_task_runtime(model_task, &path, backend),
            Err(error) => serde_json::json!({
                "runtime_path": null,
                "expected_source_revision": expected_revision,
                "expected_version_contract": expected_version,
                "executable_status": "not_configured_or_unavailable",
                "executable_diagnostic": error,
                "device_check_status": if model_task == ModelTask::Explanation && backend != sideeffect::local_model_explanation::ExplanationBackendPreference::Cpu { "not_checked" } else { "not_applicable" },
                "device_diagnostic": null,
                "backend_readiness": "blocked_runtime_unavailable",
                "gpu_inference_status": "not_run"
            }),
        }
    };
    let runtime_ready = runtime["executable_status"] == "verified_revision_prefix"
        || runtime["executable_status"] == "verified_version_prefix"
        || runtime["executable_status"] == "verified_exact_version";
    let ready = supported_here
        && model["status"] == "verified"
        && runtime_ready
        && runtime["backend_readiness"]
            .as_str()
            .is_some_and(|status| status.starts_with("ready_"));
    let report = serde_json::json!({
        "schema": "sideeffect.local_model_doctor",
        "schema_version": 2,
        "task": model_task_cli_name(model_task),
        "supported_here": supported_here,
        "readiness": if ready { "registration_and_runtime_checks_passed" } else { "blocked_or_incomplete" },
        "selected_model": model,
        "runtime": runtime,
        "inference_not_run": true,
        "weights_not_loaded": true,
        "quality_assessment_performed_by_doctor": false,
        "limitations": [
            "Runtime output identifies only a reported version or commit string; it does not authenticate the executable or its loaded libraries.",
            "Device enumeration is performed only for explanation and does not prove successful GPU inference or measure GPU memory.",
            "Model registration and hash checks do not establish runtime compatibility or answer quality. Doctor does not load weights or run inference."
        ]
    });
    write_json(&report, "local model doctor report")?;
    Ok(if ready {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn doctor_task_runtime(
    task: ModelTask,
    runtime_path: &std::path::Path,
    backend: sideeffect::local_model_explanation::ExplanationBackendPreference,
) -> serde_json::Value {
    match task {
        ModelTask::Explanation => {
            let runtime = sideeffect::local_model_explanation_runtime::doctor_explanation_runtime(
                runtime_path,
                backend,
            );
            let device_check_status = if backend
                == sideeffect::local_model_explanation::ExplanationBackendPreference::Cpu
            {
                "not_applicable_cpu_requested"
            } else {
                runtime.cuda_device_status
            };
            serde_json::json!({
                "runtime_path": runtime.runtime_path,
                "expected_source_revision": runtime.expected_source_revision,
                "expected_version_contract": "pinned commit reported by --version",
                "executable_status": runtime.executable_status,
                "executable_diagnostic": runtime.executable_diagnostic,
                "requested_backend": runtime.requested_backend,
                "device_check_status": device_check_status,
                "device_diagnostic": runtime.device_diagnostic,
                "backend_readiness": runtime.backend_readiness,
                "gpu_inference_status": runtime.gpu_inference_status
            })
        }
        ModelTask::EvidenceSelection => doctor_pinned_version_runtime(task, runtime_path),
        ModelTask::QueryPlan => doctor_pinned_version_runtime(task, runtime_path),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn doctor_pinned_version_runtime(
    task: ModelTask,
    runtime_path: &std::path::Path,
) -> serde_json::Value {
    let expected_revision = match task {
        ModelTask::EvidenceSelection => sideeffect::local_model::RUNTIME_REVISION,
        ModelTask::QueryPlan => sideeffect::local_query_plan::LOCAL_QUERY_PLAN_RUNTIME_REVISION,
        ModelTask::Explanation => unreachable!("explanation has its own runtime doctor"),
    };
    let expected_version = match task {
        ModelTask::EvidenceSelection => sideeffect::local_model::RUNTIME_VERSION_PREFIX,
        ModelTask::QueryPlan => sideeffect::local_query_plan::LOCAL_QUERY_PLAN_RUNTIME_VERSION,
        ModelTask::Explanation => unreachable!("explanation has its own runtime doctor"),
    };
    let canonical = match runtime_path.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            return serde_json::json!({
                "runtime_path": runtime_path.to_string_lossy(),
                "expected_source_revision": expected_revision,
                "expected_version_contract": expected_version,
                "executable_status": "unavailable",
                "executable_diagnostic": "runtime path is missing or inaccessible",
                "device_check_status": "not_applicable",
                "device_diagnostic": null,
                "backend_readiness": "blocked_runtime_unavailable",
                "gpu_inference_status": "not_run"
            });
        }
    };
    if !std::fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_file()) {
        return serde_json::json!({
            "runtime_path": canonical.to_string_lossy(),
            "expected_source_revision": expected_revision,
            "expected_version_contract": expected_version,
            "executable_status": "unavailable",
            "executable_diagnostic": "runtime path is not a regular file",
            "device_check_status": "not_applicable",
            "device_diagnostic": null,
            "backend_readiness": "blocked_runtime_unavailable",
            "gpu_inference_status": "not_run"
        });
    }

    let output = sideeffect::local_model_doctor::check_runtime_version(&canonical);
    let (status, diagnostic) = match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let reported = stdout.lines().chain(stderr.lines()).any(|line| match task {
                ModelTask::EvidenceSelection => line.starts_with(expected_version),
                ModelTask::QueryPlan => {
                    line.trim().strip_prefix("version: ").unwrap_or(line.trim()) == expected_version
                }
                ModelTask::Explanation => false,
            });
            let status = match task {
                ModelTask::EvidenceSelection => "verified_version_prefix",
                ModelTask::QueryPlan => "verified_exact_version",
                ModelTask::Explanation => unreachable!("explanation has its own runtime doctor"),
            };
            if output.success && !output.stdout_truncated && !output.stderr_truncated && reported {
                (status, None)
            } else {
                (
                    "version_check_failed",
                    Some(format!(
                        "runtime version check failed (successful exit {}, stdout truncated {}, stderr truncated {}, expected contract reported {})",
                        output.success, output.stdout_truncated, output.stderr_truncated, reported
                    )),
                )
            }
        }
        Err(error) => ("version_check_failed", Some(error)),
    };
    let verified = status == "verified_version_prefix" || status == "verified_exact_version";
    serde_json::json!({
        "runtime_path": canonical.to_string_lossy(),
        "expected_source_revision": expected_revision,
        "expected_version_contract": expected_version,
        "executable_status": status,
        "executable_diagnostic": diagnostic,
        "device_check_status": "not_applicable",
        "device_diagnostic": null,
        "backend_readiness": if verified {
            "ready_runtime_version_verified"
        } else {
            "blocked_runtime_check_failed"
        },
        "gpu_inference_status": "not_run"
    })
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn doctor_pinned_version_runtime(
    task: ModelTask,
    runtime_path: &std::path::Path,
) -> serde_json::Value {
    let (expected_revision, expected_version) = match task {
        ModelTask::EvidenceSelection => (
            sideeffect::local_model::RUNTIME_REVISION,
            sideeffect::local_model::RUNTIME_VERSION_PREFIX,
        ),
        ModelTask::QueryPlan => (
            sideeffect::local_query_plan::LOCAL_QUERY_PLAN_RUNTIME_REVISION,
            sideeffect::local_query_plan::LOCAL_QUERY_PLAN_RUNTIME_VERSION,
        ),
        ModelTask::Explanation => unreachable!("explanation has its own runtime doctor"),
    };
    serde_json::json!({
        "runtime_path": runtime_path.to_string_lossy(),
        "expected_source_revision": expected_revision,
        "expected_version_contract": expected_version,
        "executable_status": "unsupported_platform",
        "executable_diagnostic": "runtime check is supported on Linux x86_64 only",
        "device_check_status": "not_applicable",
        "device_diagnostic": null,
        "backend_readiness": "blocked_unsupported_platform",
        "gpu_inference_status": "not_run"
    })
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
            "- {} — {}\n  task: {}; platform: {} ({}); size: {}; license: {} ({})\n  evaluation: {}; source: {} @ {}\n  selected for task: {}; license accepted: {}; status: {}",
            model.id,
            terminal_safe_text(model.name),
            model_task_label(model.task),
            model_task_platform(model.task),
            platform_support_label(model_task_supported_here(model.task)),
            human_file_size(model.size_bytes),
            model.license_id,
            model.license_url,
            evaluation_status_label(model.evaluation),
            model.repository,
            model.revision,
            if selected { "yes" } else { "no" },
            license_accepted,
            installed
        );
    }
    if registry.custom_models.is_empty() {
        println!("No user-provided models are registered.");
    } else {
        println!("User-provided models (unreviewed):");
        for model in &registry.custom_models {
            let (license, license_status) = match model.license_id.as_deref() {
                Some(license) => (terminal_safe_text(license), "user-provided and unverified"),
                None => ("not provided".to_owned(), "not provided"),
            };
            let tasks = model
                .tasks
                .iter()
                .map(|task| {
                    format!(
                        "{} ({}; {})",
                        model_task_label(*task),
                        platform_support_label(model_task_supported_here(*task)),
                        if registry
                            .selected_by_task
                            .get(task)
                            .is_some_and(|id| id == &model.id)
                        {
                            "selected"
                        } else {
                            "not selected"
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "- {} — {}\n  tasks: {}; size: {}; SHA-256: {}\n  license: {}; license status: {}; evaluation: not assessed; accuracy recommendation: none{}",
                model.id,
                terminal_safe_text(&model.name),
                tasks,
                human_file_size(model.size_bytes),
                model.sha256,
                license,
                license_status,
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
            "task_support": {
                "task": model_task_cli_name(model.task),
                "platform_scope": model_task_platform(model.task),
                "supported_here": model_task_supported_here(model.task),
            },
            "selected_for_task": registry
                .selected_by_task
                .get(&model.task)
                .is_some_and(|selected| selected == model.id),
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
    let task_support = model
        .tasks
        .iter()
        .map(|task| {
            serde_json::json!({
                "task": model_task_cli_name(*task),
                "supported_here": model_task_supported_here(*task),
                "selected": registry
                    .selected_by_task
                    .get(task)
                    .is_some_and(|selected| selected == &model.id),
            })
        })
        .collect::<Vec<_>>();
    let mut value = serde_json::to_value(model)
        .map_err(|_| "could not serialize registered user-provided model".to_owned())?;
    let object = value.as_object_mut().ok_or_else(|| {
        "registered user-provided model did not serialize as an object".to_owned()
    })?;
    object.insert("task_support".to_owned(), serde_json::json!(task_support));
    object.insert(
        "license_status".to_owned(),
        serde_json::json!(if model.license_id.is_some() {
            "user-provided and unverified"
        } else {
            "not provided"
        }),
    );
    object.insert(
        "evaluation_status".to_owned(),
        serde_json::json!("not assessed"),
    );
    object.insert(
        "recommended_for_accuracy".to_owned(),
        serde_json::json!(false),
    );
    write_json(&value, "registered user-provided model")?;
    Ok(ExitCode::SUCCESS)
}

fn model_install(
    id: &OsString,
    select_after_install: bool,
    runtime_path: Option<&OsString>,
) -> Result<ExitCode, String> {
    let id = id.to_str().ok_or("model ID must be valid UTF-8")?;
    let model = sideeffect::model_manager::catalog_model(id).ok_or_else(|| {
        "model ID is not in the pinned catalog; install accepts catalog IDs only".to_owned()
    })?;
    if runtime_path.is_some() && !select_after_install {
        return Err("--runtime is available only with model setup".to_owned());
    }
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
    let prevalidated_runtime = runtime_path
        .map(|path| validate_setup_runtime(model.task, path))
        .transpose()?;
    if let Some(runtime) = &prevalidated_runtime {
        println!(
            "Existing runtime file: {} ({} bytes; SHA-256 {}). It will not be executed or downloaded by this command.",
            terminal_safe_path(&runtime.path),
            runtime.size_bytes,
            runtime.sha256
        );
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
        let configured_runtime = sideeffect::model_manager::update_registry(|registry| {
            complete_model_setup_in_registry(
                registry,
                id,
                model.task,
                runtime_path,
                prevalidated_runtime.as_ref(),
            )
        })?;
        println!(
            "\nInstalled and selected {} for {} ({} bytes, SHA-256 {}).",
            receipt.id,
            model_task_label(model.task),
            receipt.size_bytes,
            receipt.sha256
        );
        if let Some(runtime) = configured_runtime {
            println!(
                "Configured runtime path for {}: {} ({} bytes; SHA-256 {}). This command did not execute the runtime.",
                model_task_label(model.task),
                terminal_safe_path(&runtime.path),
                runtime.size_bytes,
                runtime.sha256
            );
            println!(
                "Run `sideeffect model doctor --task {}` to check its reported runtime contract and readiness.",
                model_task_cli_name(model.task)
            );
        }
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

fn validate_setup_runtime(task: ModelTask, path: &OsStr) -> Result<ConfiguredRuntime, String> {
    let mut registry = ModelRegistry::default();
    registry.set_runtime(task, Path::new(path))
}

fn complete_model_setup_in_registry(
    registry: &mut ModelRegistry,
    model_id: &str,
    task: ModelTask,
    runtime_path: Option<&OsString>,
    preflight_runtime: Option<&ConfiguredRuntime>,
) -> Result<Option<ConfiguredRuntime>, String> {
    let mut updated = registry.clone();
    updated.resolve(model_id, task)?;
    updated.select(task, model_id)?;
    let runtime = runtime_path
        .map(|path| updated.set_runtime(task, Path::new(path)))
        .transpose()?;
    match (runtime.as_ref(), preflight_runtime) {
        (Some(runtime), Some(preflight))
            if runtime.path == preflight.path
                && runtime.size_bytes == preflight.size_bytes
                && runtime.sha256 == preflight.sha256 => {}
        (None, None) => {}
        (Some(_), Some(_)) => {
            return Err(
                "runtime file changed after setup preflight; model setup was not completed"
                    .to_owned(),
            );
        }
        _ => {
            return Err("runtime setup preflight state is inconsistent".to_owned());
        }
    }
    *registry = updated;
    Ok(runtime)
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

fn model_runtime_set(task: &OsString, path: &OsString) -> Result<ExitCode, String> {
    let task = parse_model_task(task.to_str().ok_or("model task must be valid UTF-8")?)?;
    if !model_task_supported_here(task) {
        return Err(format!(
            "local model task '{}' is not supported on this platform",
            model_task_label(task)
        ));
    }
    let resolved = sideeffect::model_manager::update_registry(|registry| {
        registry.set_runtime(task, Path::new(path))
    })?;
    println!(
        "Configured runtime path for {}: {}. This command did not execute the file; runtime compatibility is checked when you run doctor or analysis.",
        model_task_label(task),
        terminal_safe_path(&resolved.path)
    );
    Ok(ExitCode::SUCCESS)
}

fn model_runtime_show(task: Option<&OsString>) -> Result<ExitCode, String> {
    let registry = sideeffect::model_manager::load_registry()?;
    let tasks = if let Some(task) = task {
        vec![parse_model_task(
            task.to_str().ok_or("model task must be valid UTF-8")?,
        )?]
    } else {
        vec![
            ModelTask::EvidenceSelection,
            ModelTask::Explanation,
            ModelTask::QueryPlan,
        ]
    };
    println!("Configured runtime paths (not executed by this command):");
    for task in tasks {
        match registry.runtime_by_task.get(&task) {
            Some(runtime) => {
                let status = if revalidate_configured_runtime_path(task, runtime).is_ok() {
                    "available regular file"
                } else {
                    "missing, changed, or invalid; reconfigure before use"
                };
                println!(
                    "- {}: {} ({status}; {} bytes; SHA-256 {})",
                    model_task_cli_name(task),
                    terminal_safe_path(&runtime.path),
                    runtime.size_bytes,
                    runtime.sha256
                );
            }
            None => println!("- {}: not configured", model_task_cli_name(task)),
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn model_runtime_clear(task: &OsString) -> Result<ExitCode, String> {
    let task = parse_model_task(task.to_str().ok_or("model task must be valid UTF-8")?)?;
    let cleared =
        sideeffect::model_manager::update_registry(|registry| registry.clear_runtime(task))?;
    if cleared {
        println!(
            "Cleared the configured runtime path for {}.",
            model_task_label(task)
        );
    } else {
        println!(
            "No runtime path was configured for {}.",
            model_task_label(task)
        );
    }
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

fn model_task_cli_name(task: ModelTask) -> &'static str {
    match task {
        ModelTask::EvidenceSelection => "evidence",
        ModelTask::Explanation => "explanation",
        ModelTask::QueryPlan => "query",
    }
}

fn model_task_platform(task: ModelTask) -> &'static str {
    match task {
        ModelTask::EvidenceSelection | ModelTask::QueryPlan => "Linux x86_64 only",
        ModelTask::Explanation => "Linux x86_64 and native Windows",
    }
}

fn platform_support_label(supported: bool) -> &'static str {
    if supported {
        "supported here"
    } else {
        "not supported here"
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

fn diff_windows_runtime_with_format(
    format: &OsString,
    before_path: &OsString,
    after_path: &OsString,
    output_path: Option<&OsString>,
) -> Result<ExitCode, String> {
    let format = format
        .to_str()
        .ok_or("Windows runtime diff format must be valid UTF-8")?;
    if !matches!(format, "json" | "text" | "html") {
        return Err("Windows runtime diff format must be json, text, or html".to_owned());
    }
    match (format, output_path) {
        ("html", None) => {
            return Err("Windows runtime HTML diff requires --output REPORT.html".to_owned());
        }
        ("json" | "text", Some(_)) => {
            return Err("--output is supported only for Windows runtime HTML diff".to_owned());
        }
        ("html", Some(_)) if !cfg!(windows) => {
            return Err(
                "Windows runtime HTML diff is available only in native Windows builds".to_owned(),
            );
        }
        _ => {}
    }

    let before_bytes = read_input_file(
        Path::new(before_path),
        sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        "before Windows runtime capture",
    )?;
    let after_bytes = read_input_file(
        Path::new(after_path),
        sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
        "after Windows runtime capture",
    )?;
    let before = sideeffect::windows_runtime::inspect_windows_runtime_bytes(&before_bytes)
        .map_err(|error| format!("before Windows runtime validation failed: {error}"))?;
    let after = sideeffect::windows_runtime::inspect_windows_runtime_bytes(&after_bytes)
        .map_err(|error| format!("after Windows runtime validation failed: {error}"))?;
    let summary =
        sideeffect::windows_runtime_diff::compare_windows_runtime_captures(&before, &after)?;
    let partial =
        summary.comparison_status == sideeffect::windows_runtime_diff::ComparisonStatus::Partial;

    match format {
        "json" => write_json(&summary, "Windows runtime comparison")?,
        "text" => {
            let mut text = CappedBuffer::new(MAX_REPORT_BYTES);
            sideeffect::format::write_windows_runtime_diff_text(
                &summary, &before, &after, &mut text,
            )
            .map_err(|error| {
                if text.exceeded {
                    format!(
                        "Windows runtime diff text exceeds the {MAX_REPORT_BYTES} byte output limit"
                    )
                } else {
                    format!("could not render Windows runtime diff text: {error}")
                }
            })?;
            text.write_all(b"\n").map_err(|_| {
                format!(
                    "Windows runtime diff text exceeds the {MAX_REPORT_BYTES} byte output limit"
                )
            })?;
            write_buffer(&text, "Windows runtime comparison")?;
        }
        "html" => {
            #[cfg(windows)]
            {
                let mut html = CappedBuffer::new(MAX_REPORT_BYTES);
                sideeffect::format::write_windows_runtime_diff_html(&summary, &mut html)
                    .map_err(|error| {
                        if html.exceeded {
                            format!("Windows runtime diff HTML exceeds the {MAX_REPORT_BYTES} byte output limit")
                        } else {
                            format!("could not render Windows runtime diff HTML: {error}")
                        }
                    })?;
                let output = output_path.expect("HTML output path was validated above");
                let published = publish_private_windows_file(
                    Path::new(output),
                    &html.bytes,
                    MAX_REPORT_BYTES,
                )
                .map_err(|error| {
                    format!(
                        "could not publish Windows runtime diff without replacing a file: {error}"
                    )
                })?;
                eprintln!(
                    "Offline Windows runtime comparison written to {}. The report contains sensitive capture fingerprints, event details, and source references; review before sharing.",
                    terminal_safe_path(&published)
                );
            }
            #[cfg(not(windows))]
            unreachable!("unsupported HTML diff was rejected above");
        }
        _ => unreachable!("format was validated above"),
    }

    Ok(if partial {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
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
    use super::{
        CappedBuffer, MAX_REPORT_BYTES, read_limited, read_trace_file, write_event_query_text,
    };
    #[cfg(windows)]
    use sha2::{Digest, Sha256};
    #[cfg(target_os = "linux")]
    use sha2::{Digest, Sha256};
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
    fn event_query_text_stops_at_the_output_cap_while_appending_rows() {
        let result = sideeffect::query::EventQueryResult {
            schema: sideeffect::query::QUERY_RESULT_SCHEMA,
            schema_version: sideeffect::query::QUERY_RESULT_SCHEMA_VERSION,
            source: sideeffect::event::SourceDescriptor {
                platform: sideeffect::event::SourcePlatform::Linux,
                schema: "synthetic_fixture".to_owned(),
                schema_version: 1,
                artifact: "synthetic-query-fixture".to_owned(),
                sha256: None,
            },
            source_state: sideeffect::event::SourceState {
                completeness: sideeffect::event::SourceCompleteness::Complete,
                diagnostics: Vec::new(),
                loss: None,
                identity_ambiguity_present: false,
            },
            filter: sideeffect::query::EventQueryFilters::default(),
            matched_count: 1,
            events: vec![sideeffect::event::CommonEvent {
                source_local_ordinal: 1,
                source_timestamp: None,
                event_kind: "x".repeat(sideeffect::query::MAX_QUERY_OUTPUT_BYTES + 1),
                operation: sideeffect::event::OperationSemantics::NativeObservation,
                evidence: sideeffect::event::EvidenceReference::RawTraceRecord {
                    line_number: 1,
                    byte_offset: 0,
                    byte_length: 1,
                },
                identity_context: Vec::new(),
                path_observation: None,
            }],
            event_process_links: Vec::new(),
            process_observations: Vec::new(),
            process_relationships: Vec::new(),
            diagnostics: Vec::new(),
        };
        let error = write_event_query_text(&result).unwrap_err();
        assert!(error.contains("event query text exceeds the 8388608-byte output limit"));
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

    #[cfg(windows)]
    #[test]
    fn session_runtime_diff_uses_verified_etw_bytes_and_preserves_loss_refs() {
        use sideeffect::audit_session::{
            ArtifactKind, AuditSessionManifest, AuditSessionSource, IntervalSemantics,
            LossMetadata, SessionArtifactRef, SessionStatus, SourceRole, SourceStatus,
        };
        use sideeffect::windows_runtime::{
            AppliedLimits, CollectionStatus, EventLoss, NativeRuntimeEvent, SessionMetadata,
            StopReason, TargetOutcome, WindowsRuntimeCapture,
        };
        let make_capture = |payload: &str, events_lost: u32| {
            let mut capture = WindowsRuntimeCapture {
                schema: sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
                schema_version: sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
                platform: "windows".to_owned(),
                capture_profile: "synthetic_session_diff_test".to_owned(),
                collection_status: CollectionStatus::Partial,
                capture_completeness: "unknown".to_owned(),
                started_at_unix_ms: 100,
                ended_at_unix_ms: 101,
                requested_duration_seconds: 1,
                stop_reason: StopReason::EtwLossReported,
                target: TargetOutcome {
                    process_id: 10,
                    exit_code: Some(0),
                    status_available: true,
                },
                session: SessionMetadata {
                    name: "NT Kernel Logger".to_owned(),
                    provider: "synthetic fixture".to_owned(),
                    scope: "system_wide_process_file_and_network_events_during_capture_window"
                        .to_owned(),
                    buffer_size_kb_requested: 16,
                    minimum_buffers_requested: 8,
                    maximum_buffers_requested: 32,
                    buffer_count_reported: 8,
                    provider_process_id_header_semantics: "header PID/TID is event context only"
                        .to_owned(),
                },
                limits: AppliedLimits {
                    maximum_duration_seconds: 60,
                    maximum_events: sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_EVENTS,
                    maximum_total_payload_bytes:
                        sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES,
                    maximum_payload_bytes_per_event:
                        sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
                    maximum_document_bytes:
                        sideeffect::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
                },
                event_loss: EventLoss {
                    events_lost,
                    log_buffers_lost: 0,
                    real_time_buffers_lost: 0,
                    loss_statistics_available: true,
                    observation: "synthetic_loss_fixture".to_owned(),
                    final_snapshot_available: true,
                },
                document_sha256: String::new(),
                events: vec![NativeRuntimeEvent {
                    record_ordinal: 1,
                    provider_guid: "synthetic-provider".to_owned(),
                    event_id: 99,
                    event_version: 0,
                    opcode: 0,
                    event_kind: "synthetic_event".to_owned(),
                    header_process_id: 10,
                    header_thread_id: 11,
                    header_flags: 0,
                    timestamp_qpc: 1,
                    raw_payload_hex: payload.to_owned(),
                    payload_decoding: None,
                    observation_decoding: Some(serde_json::json!({"status":"unsupported_event"})),
                }],
                diagnostics: vec!["synthetic_fixture_not_a_live_capture".to_owned()],
            };
            capture.document_sha256 = format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&capture).unwrap())
            );
            serde_json::to_vec(&capture).unwrap()
        };
        let make_manifest = |bytes: &[u8], id: &str| {
            let reference = SessionArtifactRef {
                kind: ArtifactKind::WindowsRuntimeCapture,
                path: "runtime.windows.json".to_owned(),
                schema: sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
                schema_version: sideeffect::windows_runtime::WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
                byte_length: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(bytes)),
            };
            AuditSessionManifest {
                schema: sideeffect::audit_session::AUDIT_SESSION_SCHEMA.to_owned(),
                schema_version: sideeffect::audit_session::AUDIT_SESSION_SCHEMA_VERSION,
                session_id: id.to_owned(),
                platform: "windows".to_owned(),
                architecture: "x86_64".to_owned(),
                started_at_unix_ms: 100,
                ended_at_unix_ms: 102,
                interval_semantics: IntervalSemantics::BestEffortNonAtomic,
                status: SessionStatus::Partial,
                sources: vec![AuditSessionSource {
                    role: SourceRole::Runtime,
                    collector: None,
                    platform: "windows".to_owned(),
                    scope: "synthetic bounded ETW capture".to_owned(),
                    started_at_unix_ms: 100,
                    ended_at_unix_ms: 101,
                    status: SourceStatus::Partial,
                    applied_limits: vec![],
                    requested_settings: vec![],
                    effective_settings: vec![],
                    loss: Some(LossMetadata::unknown()),
                    diagnostic_codes: vec!["synthetic_fixture_not_a_live_capture".to_owned()],
                    artifacts: vec![reference],
                }],
                host_context: None,
                coverage_manifest: None,
            }
        };
        let before_bytes = make_capture("00", 1);
        let after_bytes = make_capture("01", 2);
        let before = make_manifest(&before_bytes, "0123456789abcdef0123456789abcdef");
        let after = make_manifest(&after_bytes, "1123456789abcdef0123456789abcdef");
        let before_artifacts = [sideeffect::audit_session_diff::VerifiedArtifactBytes {
            kind: ArtifactKind::WindowsRuntimeCapture,
            path: "runtime.windows.json",
            bytes: &before_bytes,
        }];
        let after_artifacts = [sideeffect::audit_session_diff::VerifiedArtifactBytes {
            kind: ArtifactKind::WindowsRuntimeCapture,
            path: "runtime.windows.json",
            bytes: &after_bytes,
        }];
        let mut report = sideeffect::audit_session_diff::compare_audit_sessions(
            &before,
            &after,
            &before_artifacts,
            &after_artifacts,
        );
        super::compare_windows_session_runtime(
            &mut report,
            &before,
            &after,
            &before_artifacts,
            &after_artifacts,
        );
        report.refresh_item_comparison_status();
        let runtime = &report.source_diffs[0];
        assert_eq!(runtime.status, "partial");
        assert_eq!(
            runtime.reason_code,
            Some("runtime_capture_completeness_unknown")
        );
        assert_eq!(runtime.before_artifacts[0].path, "runtime.windows.json");
        assert_eq!(
            runtime.before_artifacts[0].sha256,
            format!("{:x}", Sha256::digest(&before_bytes))
        );
        assert_eq!(
            runtime.comparison.as_ref().unwrap()["schema"],
            "sideeffect.windows_runtime_diff_summary"
        );
        assert_eq!(
            runtime.comparison.as_ref().unwrap()["capture_completeness"],
            "unknown"
        );
        assert_eq!(
            runtime.comparison.as_ref().unwrap()["before"]["event_loss"]["events_lost"],
            1
        );
        assert_eq!(report.item_comparison_status, "partial");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn session_runtime_diff_checks_run_manifest_trace_binding_and_keeps_both_artifact_refs() {
        use sideeffect::audit_session::{
            ArtifactKind, AuditSessionManifest, AuditSessionSource, IntervalSemantics,
            LossMetadata, SessionArtifactRef, SessionStatus, SourceRole, SourceStatus,
        };
        let make_run = |trace: &[u8]| {
            serde_json::to_vec(&serde_json::json!({
                "schema":"sideeffect.run", "schema_version":2,
                "producer":{"sideeffect_version":env!("CARGO_PKG_VERSION"),"operating_system":"linux","architecture":"x86_64"},
                "capture":{
                    "tracer":{"name":"strace","major":6,"minor":1},
                    "capture_profile":"linux_process_file_network_v1",
                    "strace_reported_status":{"kind":"exit_code","value":0},
                    "command_outcome":"not_independently_verified",
                    "completeness":"unknown",
                    "command_stdout":"inherited_not_captured",
                    "command_stderr":"inherited_not_captured",
                    "tracer_diagnostics":"inherited_not_captured",
                    "time_limit_milliseconds":1000,
                    "stop_reason":"time_limit_reached"
                },
                "trace":{"name":"trace.strace","format":"strace_text","byte_length":trace.len(),"sha256":format!("{:x}",Sha256::digest(trace))}
            })).unwrap()
        };
        let make_manifest = |run: &[u8], trace: &[u8], id: &str| {
            let refs = vec![
                SessionArtifactRef {
                    kind: ArtifactKind::RuntimeManifest,
                    path: "run.json".to_owned(),
                    schema: "sideeffect.run".to_owned(),
                    schema_version: 2,
                    byte_length: run.len() as u64,
                    sha256: format!("{:x}", Sha256::digest(run)),
                },
                SessionArtifactRef {
                    kind: ArtifactKind::RuntimeTrace,
                    path: "trace.strace".to_owned(),
                    schema: "strace_text".to_owned(),
                    schema_version: 1,
                    byte_length: trace.len() as u64,
                    sha256: format!("{:x}", Sha256::digest(trace)),
                },
            ];
            AuditSessionManifest {
                schema: sideeffect::audit_session::AUDIT_SESSION_SCHEMA.to_owned(),
                schema_version: sideeffect::audit_session::AUDIT_SESSION_SCHEMA_VERSION,
                session_id: id.to_owned(),
                platform: "linux".to_owned(),
                architecture: "x86_64".to_owned(),
                started_at_unix_ms: 100,
                ended_at_unix_ms: 102,
                interval_semantics: IntervalSemantics::BestEffortNonAtomic,
                status: SessionStatus::Partial,
                sources: vec![AuditSessionSource {
                    role: SourceRole::Runtime,
                    collector: None,
                    platform: "linux".to_owned(),
                    scope: "synthetic bounded strace capture".to_owned(),
                    started_at_unix_ms: 100,
                    ended_at_unix_ms: 101,
                    status: SourceStatus::Partial,
                    applied_limits: vec![],
                    requested_settings: vec![],
                    effective_settings: vec![],
                    loss: Some(LossMetadata::unknown()),
                    diagnostic_codes: vec!["synthetic_fixture_not_a_live_capture".to_owned()],
                    artifacts: refs,
                }],
                host_context: None,
                coverage_manifest: None,
            }
        };
        let before_trace = b"close(1) = 0\n";
        let after_trace = b"openat(AT_FDCWD, \"/tmp/demo\", O_RDONLY) = 3\n";
        let before_run = make_run(before_trace);
        let after_run = make_run(after_trace);
        let before = make_manifest(
            &before_run,
            before_trace,
            "0123456789abcdef0123456789abcdef",
        );
        let after = make_manifest(&after_run, after_trace, "1123456789abcdef0123456789abcdef");
        let before_artifacts = [
            sideeffect::audit_session_diff::VerifiedArtifactBytes {
                kind: ArtifactKind::RuntimeManifest,
                path: "run.json",
                bytes: &before_run,
            },
            sideeffect::audit_session_diff::VerifiedArtifactBytes {
                kind: ArtifactKind::RuntimeTrace,
                path: "trace.strace",
                bytes: before_trace,
            },
        ];
        let after_artifacts = [
            sideeffect::audit_session_diff::VerifiedArtifactBytes {
                kind: ArtifactKind::RuntimeManifest,
                path: "run.json",
                bytes: &after_run,
            },
            sideeffect::audit_session_diff::VerifiedArtifactBytes {
                kind: ArtifactKind::RuntimeTrace,
                path: "trace.strace",
                bytes: after_trace,
            },
        ];
        let mut report = sideeffect::audit_session_diff::compare_audit_sessions(
            &before,
            &after,
            &before_artifacts,
            &after_artifacts,
        );
        super::compare_linux_session_runtime(
            &mut report,
            &before,
            &after,
            &before_artifacts,
            &after_artifacts,
        );
        report.refresh_item_comparison_status();
        let runtime = &report.source_diffs[0];
        assert_eq!(runtime.status, "partial");
        assert_eq!(
            runtime.reason_code,
            Some("runtime_capture_completeness_unknown")
        );
        assert_eq!(runtime.before_artifacts.len(), 2);
        assert_eq!(runtime.before_artifacts[0].path, "run.json");
        assert_eq!(runtime.before_artifacts[1].path, "trace.strace");
        assert_eq!(
            runtime.before_artifacts[1].sha256,
            format!("{:x}", Sha256::digest(before_trace))
        );
        assert_eq!(
            runtime.comparison.as_ref().unwrap()["runtime_kind"],
            "linux_strace"
        );
        assert_eq!(
            runtime.comparison.as_ref().unwrap()["trace_diff"]["capture_completeness"],
            "unknown"
        );
        assert_eq!(report.item_comparison_status, "partial");

        let mut mismatched = after.clone();
        let mut bad_run: serde_json::Value = serde_json::from_slice(&after_run).unwrap();
        bad_run["trace"]["sha256"] = serde_json::json!("0".repeat(64));
        let bad_run = serde_json::to_vec(&bad_run).unwrap();
        mismatched.sources[0].artifacts[0].byte_length = bad_run.len() as u64;
        mismatched.sources[0].artifacts[0].sha256 = format!("{:x}", Sha256::digest(&bad_run));
        let bad_artifacts = [
            sideeffect::audit_session_diff::VerifiedArtifactBytes {
                kind: ArtifactKind::RuntimeManifest,
                path: "run.json",
                bytes: &bad_run,
            },
            sideeffect::audit_session_diff::VerifiedArtifactBytes {
                kind: ArtifactKind::RuntimeTrace,
                path: "trace.strace",
                bytes: after_trace,
            },
        ];
        let mut invalid = sideeffect::audit_session_diff::compare_audit_sessions(
            &before,
            &mismatched,
            &before_artifacts,
            &bad_artifacts,
        );
        super::compare_linux_session_runtime(
            &mut invalid,
            &before,
            &mismatched,
            &before_artifacts,
            &bad_artifacts,
        );
        assert_eq!(invalid.source_diffs[0].status, "incomparable");
        assert_eq!(
            invalid.source_diffs[0].reason_code,
            Some("runtime_manifest_trace_contract_mismatch")
        );
        assert!(invalid.source_diffs[0].comparison.is_none());
    }
}

#[cfg(test)]
mod model_setup_tests {
    use super::complete_model_setup_in_registry;
    use sha2::{Digest, Sha256};
    use sideeffect::model_manager::{ModelRegistry, ModelTask};
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_SETUP_DIR_ID: AtomicU64 = AtomicU64::new(0);

    struct TempSetupDir(PathBuf);

    impl TempSetupDir {
        fn new() -> Self {
            loop {
                let id = NEXT_SETUP_DIR_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "sideeffect-model-setup-test-{}-{id}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create model-setup test directory: {error}"),
                }
            }
        }
    }

    impl Drop for TempSetupDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn assert_setup_rejects_runtime_mismatch(
        temp: &TempSetupDir,
        final_runtime_path: &std::path::Path,
        preflight_runtime: &sideeffect::model_manager::ConfiguredRuntime,
    ) {
        let old_model_path = temp.0.join("previous.gguf");
        fs::write(&old_model_path, b"GGUF\x03\0\0\0previous model").unwrap();
        let setup_model_path = temp.0.join("setup.gguf");
        fs::write(&setup_model_path, b"GGUF\x03\0\0\0setup model").unwrap();
        let old_runtime_path = temp.0.join("previous-runtime.bin");
        fs::write(&old_runtime_path, b"previous runtime bytes").unwrap();

        let mut registry = ModelRegistry::default();
        let old_model_id = registry
            .register_custom(
                "Previous model",
                &old_model_path,
                None,
                vec![ModelTask::Explanation],
            )
            .unwrap();
        let setup_model_id = registry
            .register_custom(
                "Setup model",
                &setup_model_path,
                None,
                vec![ModelTask::Explanation],
            )
            .unwrap();
        registry
            .select(ModelTask::Explanation, &old_model_id)
            .unwrap();
        registry
            .set_runtime(ModelTask::Explanation, &old_runtime_path)
            .unwrap();
        let before = registry.clone();

        let final_runtime_path_os = OsString::from(final_runtime_path);
        let error = complete_model_setup_in_registry(
            &mut registry,
            &setup_model_id,
            ModelTask::Explanation,
            Some(&final_runtime_path_os),
            Some(preflight_runtime),
        )
        .unwrap_err();

        assert!(error.contains("runtime file changed after setup preflight"));
        assert_eq!(registry, before);
    }

    #[test]
    fn successful_setup_finalization_selects_model_and_hash_registers_runtime_for_same_task() {
        let temp = TempSetupDir::new();
        let model_path = temp.0.join("synthetic.gguf");
        fs::write(&model_path, b"GGUF\x03\0\0\0synthetic setup model").unwrap();
        let runtime_path = temp.0.join("inert-runtime-file.bin");
        let runtime_bytes = b"inert test fixture; never execute";
        fs::write(&runtime_path, runtime_bytes).unwrap();

        let mut registry = ModelRegistry::default();
        let model_id = registry
            .register_custom(
                "Synthetic setup model",
                &model_path,
                None,
                vec![ModelTask::Explanation],
            )
            .unwrap();
        let runtime_path_os = OsString::from(&runtime_path);
        let preflight_runtime = ModelRegistry::default()
            .set_runtime(ModelTask::Explanation, &runtime_path)
            .unwrap();
        let configured = complete_model_setup_in_registry(
            &mut registry,
            &model_id,
            ModelTask::Explanation,
            Some(&runtime_path_os),
            Some(&preflight_runtime),
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            registry.selected_by_task.get(&ModelTask::Explanation),
            Some(&model_id)
        );
        assert_eq!(
            registry.runtime_by_task.get(&ModelTask::Explanation),
            Some(&configured)
        );
        assert!(!registry.runtime_by_task.contains_key(&ModelTask::QueryPlan));
        assert_eq!(configured.path, runtime_path.canonicalize().unwrap());
        assert_eq!(configured.size_bytes, runtime_bytes.len() as u64);
        assert_eq!(
            configured.sha256,
            format!("{:x}", Sha256::digest(runtime_bytes))
        );
    }

    #[test]
    fn setup_finalization_without_runtime_preserves_model_only_behavior() {
        let temp = TempSetupDir::new();
        let model_path = temp.0.join("synthetic.gguf");
        fs::write(&model_path, b"GGUF\x03\0\0\0synthetic setup model").unwrap();

        let mut registry = ModelRegistry::default();
        let model_id = registry
            .register_custom(
                "Synthetic setup model",
                &model_path,
                None,
                vec![ModelTask::Explanation],
            )
            .unwrap();
        assert!(
            complete_model_setup_in_registry(
                &mut registry,
                &model_id,
                ModelTask::Explanation,
                None,
                None,
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            registry.selected_by_task.get(&ModelTask::Explanation),
            Some(&model_id)
        );
        assert!(registry.runtime_by_task.is_empty());
    }

    #[test]
    fn setup_finalization_rejects_runtime_change_without_partial_registry_mutation() {
        let temp = TempSetupDir::new();
        let model_path = temp.0.join("synthetic.gguf");
        fs::write(&model_path, b"GGUF\x03\0\0\0synthetic setup model").unwrap();
        let mut registry = ModelRegistry::default();
        let model_id = registry
            .register_custom(
                "Synthetic setup model",
                &model_path,
                None,
                vec![ModelTask::Explanation],
            )
            .unwrap();
        let missing_runtime = OsString::from(temp.0.join("missing-runtime.exe"));

        assert!(
            complete_model_setup_in_registry(
                &mut registry,
                &model_id,
                ModelTask::Explanation,
                Some(&missing_runtime),
                None,
            )
            .is_err()
        );
        assert!(registry.selected_by_task.is_empty());
        assert!(registry.runtime_by_task.is_empty());
    }

    #[test]
    fn setup_finalization_rejects_changed_runtime_bytes_without_registry_mutation() {
        let temp = TempSetupDir::new();
        let runtime_path = temp.0.join("runtime.bin");
        let original_bytes = b"runtime fixture bytes";
        let changed_bytes = b"runtime altered bytes";
        assert_eq!(original_bytes.len(), changed_bytes.len());
        fs::write(&runtime_path, original_bytes).unwrap();
        let preflight_runtime = ModelRegistry::default()
            .set_runtime(ModelTask::Explanation, &runtime_path)
            .unwrap();
        fs::write(&runtime_path, changed_bytes).unwrap();

        assert_setup_rejects_runtime_mismatch(&temp, &runtime_path, &preflight_runtime);
    }

    #[test]
    fn setup_finalization_rejects_changed_runtime_size_without_registry_mutation() {
        let temp = TempSetupDir::new();
        let runtime_path = temp.0.join("runtime.bin");
        fs::write(&runtime_path, b"runtime").unwrap();
        let preflight_runtime = ModelRegistry::default()
            .set_runtime(ModelTask::Explanation, &runtime_path)
            .unwrap();
        fs::write(&runtime_path, b"runtime changed to a larger file").unwrap();

        assert_setup_rejects_runtime_mismatch(&temp, &runtime_path, &preflight_runtime);
    }

    #[test]
    fn setup_finalization_rejects_changed_runtime_canonical_path_without_registry_mutation() {
        let temp = TempSetupDir::new();
        let preflight_path = temp.0.join("runtime-before.bin");
        let final_path = temp.0.join("runtime-after.bin");
        let same_bytes = b"same runtime bytes at a different path";
        fs::write(&preflight_path, same_bytes).unwrap();
        fs::write(&final_path, same_bytes).unwrap();
        let preflight_runtime = ModelRegistry::default()
            .set_runtime(ModelTask::Explanation, &preflight_path)
            .unwrap();

        assert_setup_rejects_runtime_mismatch(&temp, &final_path, &preflight_runtime);
    }
}
