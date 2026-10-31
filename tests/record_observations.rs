#![cfg(target_os = "linux")]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder};
use std::net::TcpListener;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct PrivateTempDirectory(PathBuf);

impl PrivateTempDirectory {
    fn new() -> Self {
        loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-real-record-{}-{id}",
                std::process::id()
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    let directory = Self(path);
                    let mode = fs::metadata(&directory.0)
                        .expect("inspect private test directory")
                        .permissions()
                        .mode();
                    assert_eq!(mode & 0o777, 0o700, "test directory must be private");
                    return directory;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create private test directory: {error}"),
            }
        }
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateTempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn require_tool(name: &str, version_args: &[&str]) {
    let output = Command::new(name)
        .args(version_args)
        .output()
        .unwrap_or_else(|error| {
            panic!("required integration-test tool {name} is unavailable: {error}")
        });
    assert!(
        output.status.success(),
        "required integration-test tool {name} failed its version probe (status: {:?}; stderr: {})",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_record(
    trace_path: &Path,
    file_path: &Path,
    connect_loopback: bool,
    spawn_child: bool,
) -> Output {
    const SCRIPT: &str = r#"
import socket
import os
import subprocess
import sys

path = sys.argv[1]
os.chdir(sys.argv[2])
with open(path, "wb") as output:
    output.write(b"SideEffect loopback integration test")
with open(path, "rb") as source:
    source.read()

if sys.argv[3] == "connect":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(server.getsockname())
    accepted, _ = server.accept()
    accepted.close()
    client.close()
    server.close()

if sys.argv[4] == "spawn-child":
    subprocess.run(
        [sys.executable, "-c", "pass", "sideeffect-child-process-marker"],
        check=True,
    )
"#;

    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["record", "--trace"])
        .arg(trace_path)
        .args(["--", "python3", "-c", SCRIPT])
        .arg(file_path.file_name().expect("test filename"))
        .arg(file_path.parent().expect("test directory"))
        .arg(if connect_loopback {
            "connect"
        } else {
            "file-only"
        })
        .arg(if spawn_child {
            "spawn-child"
        } else {
            "no-child"
        })
        .arg("sideeffect-parent-process-marker")
        .output()
        .expect("launch SideEffect record command")
}

fn assert_record_output_does_not_leak_capture(output: &Output) {
    assert!(
        output.stdout.is_empty(),
        "record target unexpectedly wrote stdout"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for sentinel in [
        "SideEffect loopback integration test",
        "sideeffect-parent-process-marker",
        "sideeffect-child-process-marker",
        "\"records\"",
        "\"schema_version\"",
    ] {
        assert!(!stdout.contains(sentinel), "stdout leaked {sentinel}");
        assert!(!stderr.contains(sentinel), "stderr leaked {sentinel}");
    }
}

fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed (status: {:?}; stderr: {})",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_record_target_status(trace_path: &Path, script: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["record", "--trace"])
        .arg(trace_path)
        .args(["--", "python3", "-c", script])
        .output()
        .expect("launch SideEffect record status target")
}

fn assert_published_nonempty_trace(path: &Path) {
    let metadata = fs::metadata(path).expect("record should publish the trace");
    assert!(metadata.is_file());
    assert!(metadata.len() > 0, "published trace must be nonempty");
}

#[test]
fn fake_strace_diagnostic_trace_and_reported_status_follow_milestone_one_contract() {
    use std::os::unix::fs::PermissionsExt;

    const TRACE_ROW: &str =
        "123 1700000000.000001 openat(AT_FDCWD, \"/synthetic/fake-tracer\", O_RDONLY) = 3";
    const FAKE_DIAGNOSTIC: &str = "fake strace runtime diagnostic marker";

    let directory = PrivateTempDirectory::new();
    let fake_bin = directory.path().join("fake-bin");
    fs::create_dir(&fake_bin).expect("create private fake tracer directory");
    let fake_strace = fake_bin.join("strace");
    let script = format!(
        r##"#!/bin/sh
if [ "$#" -eq 1 ] && [ "$1" = "-V" ]; then
    printf '%s\n' 'strace -- version 6.8'
    exit 0
fi
trace=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) trace=$2; shift 2 ;;
        --) shift; break ;;
        *) shift ;;
    esac
done
[ "$trace" != "" ] || exit 90
[ "$#" -eq 4 ] || exit 91
[ "$1" = "/fake target/program" ] || exit 92
[ "$2" = "two words stay together" ] || exit 93
[ "$3" = "; literal shell text" ] || exit 94
[ "$4" = '$(not-a-shell)' ] || exit 95
printf '%s\n' '{TRACE_ROW}' > "$trace" || exit 96
printf '%s\n' '{FAKE_DIAGNOSTIC}' >&2
exit 37
"##
    );
    fs::write(&fake_strace, script).expect("write fake strace executable");
    fs::set_permissions(&fake_strace, fs::Permissions::from_mode(0o700))
        .expect("make fake strace executable");

    let trace_path = directory.path().join("fake-capture.trace");
    let inherited_path = std::env::var_os("PATH").unwrap_or_default();
    let mut path_entries = vec![fake_bin];
    path_entries.extend(std::env::split_paths(&inherited_path));
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["record", "--trace"])
        .arg(&trace_path)
        .args(["--", "/fake target/program", "two words stay together"])
        .args(["; literal shell text", "$(not-a-shell)"])
        .env(
            "PATH",
            std::env::join_paths(path_entries).expect("join PATH entries"),
        )
        .output()
        .expect("launch SideEffect against fake strace");

    assert_eq!(
        output.status.code(),
        Some(37),
        "the CLI should propagate only the fake tracer's reported status; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(FAKE_DIAGNOSTIC), "stderr: {stderr}");
    assert!(
        stderr.contains("strace-reported and propagated exit status: 37"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("strace normally mirrors the wrapped command")
            && stderr.contains("does not prove tracer success or capture completeness"),
        "the status caveat should remain explicit; stderr: {stderr}"
    );
    assert!(!stderr.contains("target exited"), "stderr: {stderr}");

    assert_published_nonempty_trace(&trace_path);
    assert_eq!(
        fs::read_to_string(&trace_path).unwrap(),
        format!("{TRACE_ROW}\n")
    );
    let inspected = inspect_trace(&trace_path);
    assert_eq!(inspected["parse_status"], "complete");
    assert!(
        inspected["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| { record["kind"] == "syscall" && record["raw_line"] == TRACE_ROW })
    );
}

#[test]
fn record_propagates_nonzero_target_exit_after_publishing_trace() {
    require_tool("strace", &["--version"]);
    require_tool("python3", &["--version"]);

    let directory = PrivateTempDirectory::new();
    let trace_path = directory.path().join("exit-37.trace");
    let output = run_record_target_status(&trace_path, "import os; os._exit(37)");

    assert_eq!(
        output.status.code(),
        Some(37),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_published_nonempty_trace(&trace_path);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Recorded "), "stderr: {stderr}");
    assert!(
        stderr.contains("strace-reported and propagated exit status: 37"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("does not prove tracer success or capture completeness"),
        "stderr: {stderr}"
    );
}

#[test]
fn record_propagates_target_signal_after_publishing_trace() {
    require_tool("strace", &["--version"]);
    require_tool("python3", &["--version"]);

    let directory = PrivateTempDirectory::new();
    let trace_path = directory.path().join("sigterm.trace");
    let output = run_record_target_status(
        &trace_path,
        "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
    );

    assert_eq!(
        output.status.signal(),
        Some(libc::SIGTERM),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_published_nonempty_trace(&trace_path);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Recorded "), "stderr: {stderr}");
    assert!(
        stderr.contains("strace-reported termination by signal 15 is being propagated"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("does not prove tracer success or capture completeness"),
        "stderr: {stderr}"
    );
}

#[test]
fn record_inherits_target_output_and_publishes_failed_exec_evidence() {
    require_tool("strace", &["--version"]);
    require_tool("python3", &["--version"]);

    let directory = PrivateTempDirectory::new();
    let output_trace = directory.path().join("output.trace");
    let output = run_record_target_status(
        &output_trace,
        "import os; os.write(1, b'SideEffect inherited stdout\\n'); os.write(2, b'SideEffect inherited stderr\\n')",
    );
    assert_success(&output, "record target output capture");
    assert_eq!(output.stdout, b"SideEffect inherited stdout\n");
    assert!(
        output.stderr.starts_with(b"SideEffect inherited stderr\n"),
        "target stderr should be inherited before SideEffect's record summary; got: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_published_nonempty_trace(&output_trace);

    let failed_program = directory.path().join("program-that-does-not-exist");
    let failure_trace = directory.path().join("failed-exec.trace");
    let failure = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["record", "--trace"])
        .arg(&failure_trace)
        .args([
            "--",
            "python3",
            "-c",
            "import os, sys; os.execv(sys.argv[1], [sys.argv[1]])",
        ])
        .arg(&failed_program)
        .output()
        .expect("launch SideEffect record command for failed exec");
    assert!(!failure.status.success(), "a failed target exec must fail");
    assert!(
        String::from_utf8_lossy(&failure.stderr).contains("Recorded "),
        "SideEffect should report the published trace: {}",
        String::from_utf8_lossy(&failure.stderr)
    );
    assert_published_nonempty_trace(&failure_trace);

    let trace = inspect_trace(&failure_trace);
    let failed_exec = trace["records"]
        .as_array()
        .expect("inspect records array")
        .iter()
        .find(|record| {
            record["kind"] == "syscall"
                && record["syscall"] == "execve"
                && record["raw_arguments"]
                    .as_str()
                    .is_some_and(|arguments| arguments.contains("program-that-does-not-exist"))
                && record["raw_result"]
                    .as_str()
                    .is_some_and(|result| result.starts_with("-1 ENOENT"))
        })
        .expect("real strace trace should retain the failed execve attempt");
    assert!(
        failed_exec["raw_result"]
            .as_str()
            .unwrap()
            .starts_with("-1 ENOENT")
    );
    assert_eq!(failed_exec["outcome"], "failure");
    assert!(failed_exec["evidence"]["line_number"].as_u64().is_some());
    assert!(failed_exec["evidence"]["byte_offset"].as_u64().is_some());
    assert!(failed_exec["evidence"]["byte_length"].as_u64().is_some());
}

#[test]
fn record_bundle_publishes_manifest_and_exact_trace_for_nonzero_target() {
    require_tool("strace", &["--version"]);
    require_tool("python3", &["--version"]);

    let directory = PrivateTempDirectory::new();
    let bundle = directory.path().join("exit-37.run");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["record", "--bundle"])
        .arg(&bundle)
        .args([
            "--",
            "python3",
            "-c",
            "import os,sys; os._exit(37)",
            "private-bundle-argv-marker",
        ])
        .output()
        .expect("launch SideEffect record bundle command");

    assert_eq!(
        output.status.code(),
        Some(37),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let entries = fs::read_dir(&bundle)
        .expect("bundle directory should be published")
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().any(|name| name == "run.json"));
    assert!(entries.iter().any(|name| name == "trace.strace"));
    assert_eq!(
        fs::metadata(&bundle).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for name in ["run.json", "trace.strace"] {
        assert_eq!(
            fs::metadata(bundle.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "bundle file {name} must be private"
        );
    }

    let trace = fs::read(bundle.join("trace.strace")).unwrap();
    let manifest_bytes = fs::read(bundle.join("run.json")).unwrap();
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest["schema"], "sideeffect.run");
    assert_eq!(manifest["schema_version"], 2);
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
    assert_eq!(manifest["trace"]["name"], "trace.strace");
    assert_eq!(manifest["trace"]["byte_length"], trace.len());
    let expected_hash = format!("{:x}", Sha256::digest(&trace));
    assert_eq!(manifest["trace"]["sha256"], expected_hash);
    let manifest_text = String::from_utf8(manifest_bytes).unwrap();
    assert!(!manifest_text.contains("private-bundle-argv-marker"));
    assert!(!manifest_text.contains("python3"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("strace-reported and propagated exit status: 37"));
}

fn inspect_trace(path: &Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("inspect")
        .arg(path)
        .output()
        .expect("launch SideEffect inspect command");
    let document: Value = serde_json::from_slice(&output.stdout).expect("parse inspect JSON");
    if !output.status.success() {
        let diagnostics = document["diagnostics"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|diagnostic| {
                let line_number = diagnostic["line_number"].as_u64().unwrap_or_default();
                let syscall_name = document["records"]
                    .as_array()
                    .and_then(|records| records.get(line_number.saturating_sub(1) as usize))
                    .and_then(|record| record["raw_line"].as_str())
                    .and_then(|raw_line| raw_line.find('(').map(|open| &raw_line[..open]))
                    .and_then(|prefix| prefix.split_whitespace().last())
                    .unwrap_or("unknown");
                (
                    line_number,
                    diagnostic["code"].as_str().unwrap_or("unknown"),
                    syscall_name,
                    diagnostic["message"].as_str().unwrap_or("unknown"),
                )
            })
            .collect::<Vec<_>>();
        panic!(
            "inspect failed (status: {:?}; diagnostic summary: {diagnostics:?})",
            output.status.code()
        );
    }
    document
}

fn assert_successful_syscall<'a>(
    document: &'a Value,
    syscall_name: &str,
    argument_fragment: &str,
) -> &'a Value {
    assert_eq!(document["parse_status"], "complete");
    let record = document["records"]
        .as_array()
        .expect("inspect records array")
        .iter()
        .find(|record| {
            record["kind"] == "syscall"
                && record["syscall"] == syscall_name
                && record["raw_arguments"]
                    .as_str()
                    .is_some_and(|args| args.contains(argument_fragment))
                && record["raw_result"]
                    .as_str()
                    .is_some_and(|result| !result.starts_with("-1"))
        })
        .unwrap_or_else(|| {
            panic!(
                "inspect output lacks successful {syscall_name} evidence matching argument marker {argument_fragment}"
            )
        });
    assert!(
        record["evidence"]["line_number"]
            .as_u64()
            .is_some_and(|line| line > 0)
    );
    assert!(record["evidence"]["byte_offset"].as_u64().is_some());
    assert!(
        record["evidence"]["byte_length"]
            .as_u64()
            .is_some_and(|length| length > 0)
    );
    record
}

#[test]
fn real_strace_capture_inspect_and_diff_observe_file_and_loopback_events() {
    require_tool("strace", &["--version"]);
    require_tool("python3", &["--version"]);

    let directory = PrivateTempDirectory::new();
    let temporary_root = directory.path().to_path_buf();
    let baseline_path = directory.path().join("baseline.trace");
    let candidate_path = directory.path().join("candidate.trace");
    let baseline_file = directory.path().join(format!(
        "baseline-file-{}-{}.bin",
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let candidate_file = directory.path().join(format!(
        "candidate-file-{}-{}.bin",
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));

    for (trace, file, connect_loopback, spawn_child) in [
        (
            baseline_path.as_path(),
            baseline_file.as_path(),
            true,
            false,
        ),
        (
            candidate_path.as_path(),
            candidate_file.as_path(),
            false,
            true,
        ),
    ] {
        let output = run_record(trace, file, connect_loopback, spawn_child);
        assert_record_output_does_not_leak_capture(&output);
        assert_success(&output, "record real strace capture");
        assert!(trace.is_file(), "record should publish its trace file");
        assert_eq!(
            fs::metadata(trace).unwrap().permissions().mode() & 0o777,
            0o600,
            "recorded traces should remain private"
        );
        assert!(
            file.is_file(),
            "Python target should create its unique file"
        );
    }

    let baseline = inspect_trace(&baseline_path);
    let candidate = inspect_trace(&candidate_path);
    let baseline_file_open = assert_successful_syscall(
        &baseline,
        "openat",
        baseline_file
            .file_name()
            .unwrap()
            .to_str()
            .expect("UTF-8 test filename"),
    );
    let timeline_output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["timeline", "--trace"])
        .arg(&baseline_path)
        .args(["--event-kind", "openat"])
        .output()
        .expect("launch timeline over the real strace capture");
    assert!(
        matches!(timeline_output.status.code(), Some(0 | 2)),
        "timeline real strace capture failed (status: {:?}; stderr: {})",
        timeline_output.status.code(),
        String::from_utf8_lossy(&timeline_output.stderr)
    );
    let timeline: Value =
        serde_json::from_slice(&timeline_output.stdout).expect("parse real-capture timeline JSON");
    assert_eq!(timeline["schema"], "sideeffect.event_timeline");
    let expected_exit = if timeline["source_state"]["completeness"] == "complete" {
        0
    } else {
        2
    };
    assert_eq!(timeline_output.status.code(), Some(expected_exit));
    assert_eq!(timeline["filter"]["event_kind"], "openat");
    let timeline_file_event = timeline["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| {
            event["event_kind"] == "openat"
                && event["evidence"]["line_number"] == baseline_file_open["evidence"]["line_number"]
                && event["evidence"]["byte_offset"] == baseline_file_open["evidence"]["byte_offset"]
                && event["evidence"]["byte_length"] == baseline_file_open["evidence"]["byte_length"]
        })
        .expect("timeline should link to the observed real file-open row");
    assert_eq!(timeline_file_event["evidence"]["kind"], "raw_trace_record");
    let raw_trace = fs::read(&baseline_path).unwrap();
    let start = timeline_file_event["evidence"]["byte_offset"]
        .as_u64()
        .unwrap() as usize;
    let length = timeline_file_event["evidence"]["byte_length"]
        .as_u64()
        .unwrap() as usize;
    assert!(
        start
            .checked_add(length)
            .is_some_and(|end| end <= raw_trace.len())
    );
    assert!(
        String::from_utf8_lossy(&raw_trace[start..start + length])
            .contains(baseline_file.file_name().unwrap().to_str().unwrap())
    );
    let graph_output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&baseline_path)
        .output()
        .expect("launch graph over the real strace capture");
    assert!(
        matches!(graph_output.status.code(), Some(0 | 2)),
        "graph real strace capture failed (status: {:?}; stderr: {})",
        graph_output.status.code(),
        String::from_utf8_lossy(&graph_output.stderr)
    );
    let graph: Value =
        serde_json::from_slice(&graph_output.stdout).expect("parse real-capture graph JSON");
    assert_eq!(graph["schema"], "sideeffect.event_graph");
    assert_eq!(graph["source_state"], timeline["source_state"]);
    let graph_file_event = graph["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| {
            node["kind"] == "event"
                && node["event"]["event_kind"] == "openat"
                && node["evidence"]["line_number"] == baseline_file_open["evidence"]["line_number"]
                && node["evidence"]["byte_offset"] == baseline_file_open["evidence"]["byte_offset"]
        })
        .expect("graph should include the observed real file-open event");
    assert!(graph["edges"].as_array().unwrap().iter().any(|edge| {
        edge["kind"] == "event_process_link"
            && edge["event_link_status"] == "observed"
            && edge["from_node_id"] == graph_file_event["id"]
    }));
    assert_eq!(
        baseline_file_open["lexical_path_hint"]["path"],
        baseline_file.to_str().unwrap()
    );
    assert_eq!(
        baseline_file_open["lexical_path_hint"]["basis"],
        "at_fdcwd_annotation"
    );
    let candidate_file_open = assert_successful_syscall(
        &candidate,
        "openat",
        candidate_file
            .file_name()
            .unwrap()
            .to_str()
            .expect("UTF-8 test filename"),
    );
    assert_eq!(
        candidate_file_open["lexical_path_hint"]["path"],
        candidate_file.to_str().unwrap()
    );
    let loopback_connect = assert_successful_syscall(&baseline, "connect", "127.0.0.1");
    assert_eq!(loopback_connect["raw_result"], "0");
    let parent_exec =
        assert_successful_syscall(&candidate, "execve", "sideeffect-parent-process-marker");
    let child_exec = candidate["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| {
            (record["kind"] == "syscall" || record["kind"] == "unfinished_syscall")
                && record["syscall"] == "execve"
                && record["raw_arguments"]
                    .as_str()
                    .is_some_and(|args| args.contains("sideeffect-child-process-marker"))
        })
        .expect("candidate trace should preserve the child's execve evidence row");
    let child_pid = child_exec["process_id"]
        .as_u64()
        .expect("child execve row PID");
    let parent_pid = parent_exec["process_id"]
        .as_u64()
        .expect("parent execve row PID");
    assert!(
        candidate["process_lineage"]["relations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|relation| {
                relation["caller_task_id"] == parent_pid
                    && relation["child_pid"] == child_pid
                    && relation["evidence"]["line_number"].as_u64().is_some()
            }),
        "the child PID must be linked to the observed caller task only by a supported process-creation evidence row; caller_task_id={parent_pid}, child={child_pid}, lineage={}, creation_rows={:?}",
        candidate["process_lineage"],
        candidate["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|record| matches!(
                record["syscall"].as_str(),
                Some("fork" | "vfork" | "clone" | "clone3")
            ))
            .collect::<Vec<_>>()
    );
    let child_exec_resume = match child_exec["kind"].as_str() {
        Some("syscall") => {
            assert_eq!(child_exec["raw_result"], "0");
            None
        }
        Some("unfinished_syscall") => Some(
            candidate["records"]
                .as_array()
                .unwrap()
                .iter()
                .find(|record| {
                    record["kind"] == "resumed_syscall"
                        && record["syscall"] == "execve"
                        && record["process_id"] == child_pid
                        && record["raw_result"] == "0"
                })
                .expect("split child execve should have a matching successful resume"),
        ),
        _ => panic!("child execve should be a complete or unfinished syscall record"),
    };
    assert_ne!(
        parent_exec["process_id"], child_exec["process_id"],
        "child execve evidence must identify a PID distinct from the target process"
    );
    assert!(child_exec["evidence"]["line_number"].as_u64().is_some());
    assert!(child_exec["evidence"]["byte_offset"].as_u64().is_some());
    assert!(child_exec["evidence"]["byte_length"].as_u64().is_some());
    if let Some(child_exec_resume) = child_exec_resume {
        assert!(
            child_exec_resume["evidence"]["line_number"]
                .as_u64()
                .is_some()
        );
        assert!(
            child_exec_resume["evidence"]["byte_offset"]
                .as_u64()
                .is_some()
        );
        assert!(
            child_exec_resume["evidence"]["byte_length"]
                .as_u64()
                .is_some()
        );
    }
    assert!(
        !baseline["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| {
                record["syscall"] == "execve"
                    && record["raw_arguments"]
                        .as_str()
                        .is_some_and(|args| args.contains("sideeffect-child-process-marker"))
            }),
        "baseline target should not spawn the child"
    );
    assert!(
        !candidate["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| {
                record["kind"] == "syscall"
                    && record["syscall"] == "connect"
                    && record["raw_arguments"]
                        .as_str()
                        .is_some_and(|args| args.contains("127.0.0.1"))
            }),
        "file-only candidate should not connect to the loopback listener"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", "--format", "json"])
        .arg(&baseline_path)
        .arg(&candidate_path)
        .output()
        .expect("launch SideEffect diff command");
    assert_success(&output, "diff real captures");
    let diff: Value = serde_json::from_slice(&output.stdout).expect("parse diff JSON");
    let changes = diff["changes"].as_array().expect("diff changes array");
    let baseline_file_name = baseline_file.file_name().unwrap().to_str().unwrap();
    let candidate_file_name = candidate_file.file_name().unwrap().to_str().unwrap();
    assert!(
        changes.iter().any(|change| {
            change["kind"] == "removed"
                && change["category"] == "file"
                && change["syscall"] == "openat"
                && change["raw_arguments"]
                    .as_str()
                    .is_some_and(|args| args.contains(baseline_file_name))
                && change["before_result"]
                    .as_str()
                    .is_some_and(|result| !result.starts_with("-1"))
                && change["after_result"].is_null()
        }),
        "diff should report the baseline file open as removed"
    );
    assert!(
        changes.iter().any(|change| {
            change["kind"] == "added"
                && change["category"] == "file"
                && change["syscall"] == "openat"
                && change["raw_arguments"]
                    .as_str()
                    .is_some_and(|args| args.contains(candidate_file_name))
                && change["before_result"].is_null()
                && change["after_result"]
                    .as_str()
                    .is_some_and(|result| !result.starts_with("-1"))
        }),
        "diff should report the candidate file open as added"
    );
    assert!(
        changes.iter().any(|change| {
            change["kind"] == "removed"
                && change["before_result"] == "0"
                && change["after_result"].is_null()
                && change["category"] == "network"
                && change["syscall"] == "connect"
                && change["raw_arguments"]
                    .as_str()
                    .is_some_and(|args| args.contains("127.0.0.1"))
        }),
        "diff should contain a loopback connect delta"
    );
    assert!(
        changes.iter().any(|change| {
            change["kind"] == "added"
                && change["category"] == "process"
                && change["record_kind"] == child_exec["kind"]
                && change["syscall"] == "execve"
                && change["raw_arguments"]
                    .as_str()
                    .is_some_and(|args| args.contains("sideeffect-child-process-marker"))
                && change["before"].as_array().is_some_and(Vec::is_empty)
                && change["after"].as_array().is_some_and(|references| {
                    references.iter().any(|reference| {
                        reference["line_number"] == child_exec["evidence"]["line_number"]
                            && reference["byte_offset"] == child_exec["evidence"]["byte_offset"]
                            && reference["byte_length"] == child_exec["evidence"]["byte_length"]
                    })
                })
        }),
        "diff should report the child's observed execve row as an added process observation with evidence"
    );

    drop(directory);
    assert!(
        !temporary_root.exists(),
        "temporary traces and target files must be removed after the test"
    );
}

#[test]
fn real_strace_capture_reports_refused_loopback_connection_as_failed_attempt() {
    require_tool("strace", &["--version"]);
    require_tool("python3", &["--version"]);

    let directory = PrivateTempDirectory::new();
    let trace_path = directory.path().join("refused-loopback.trace");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve loopback port");
    let port = listener.local_addr().expect("read loopback port").port();
    drop(listener);

    const SCRIPT: &str = r#"
import errno
import socket
import sys

port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    result = client.connect_ex(("127.0.0.1", port))
if result != errno.ECONNREFUSED:
    sys.exit(1)
"#;
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["record", "--trace"])
        .arg(&trace_path)
        .args(["--", "python3", "-c", SCRIPT])
        .arg(port.to_string())
        .output()
        .expect("launch SideEffect real strace capture");
    assert_record_output_does_not_leak_capture(&output);
    assert_success(&output, "record refused loopback connection");
    assert!(trace_path.is_file(), "record should publish its real trace");

    let document = inspect_trace(&trace_path);
    assert_eq!(document["parse_status"], "complete");
    let port_marker = format!("htons({port})");
    let records = document["records"]
        .as_array()
        .expect("inspect records array");
    let failed_connect = records
        .iter()
        .find(|record| {
            record["kind"] == "syscall"
                && record["syscall"] == "connect"
                && record["raw_arguments"]
                    .as_str()
                    .is_some_and(|args| args.contains(&port_marker) && args.contains("127.0.0.1"))
        })
        .expect("real trace should retain the selected loopback connect attempt");
    assert_eq!(failed_connect["outcome"], "failure");
    assert!(
        failed_connect["raw_result"]
            .as_str()
            .is_some_and(|result| result.starts_with("-1 ECONNREFUSED"))
    );
    assert!(
        !records.iter().any(|record| {
            record["kind"] == "syscall"
                && record["syscall"] == "connect"
                && record["raw_arguments"]
                    .as_str()
                    .is_some_and(|args| args.contains(&port_marker) && args.contains("127.0.0.1"))
                && record["outcome"] == "success"
        }),
        "the refused connection must not appear as a successful network effect"
    );

    let evidence = &failed_connect["evidence"];
    let byte_offset = evidence["byte_offset"]
        .as_u64()
        .expect("failed connect byte offset") as usize;
    let byte_length = evidence["byte_length"]
        .as_u64()
        .expect("failed connect byte length") as usize;
    let trace = fs::read(&trace_path).expect("read real trace bytes");
    let evidence_end = byte_offset
        .checked_add(byte_length)
        .expect("evidence span must not overflow");
    let evidence_bytes = trace
        .get(byte_offset..evidence_end)
        .expect("failed connect evidence span must be in the real trace");
    assert_eq!(
        evidence_bytes,
        failed_connect["raw_line"].as_str().unwrap().as_bytes()
    );
    assert!(
        evidence["line_number"]
            .as_u64()
            .is_some_and(|line| line > 0)
    );
}

#[test]
fn bounded_duration_capture_publishes_partial_bundle_with_explicit_limit_status() {
    let temp = PrivateTempDirectory::new();
    let bundle = temp.0.join("timed.run");
    let marker = temp.0.join("descendant-finished-after-timeout");
    let started = std::time::Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["record", "--bundle"])
        .arg(&bundle)
        .args(["--duration-seconds", "1", "--", "python3", "-c"])
        .arg(format!(
            "import os,time; child=os.fork(); (time.sleep(2),open({:?},'w').write('alive'),os._exit(0)) if child==0 else time.sleep(10)",
            marker
        ))
        .output()
        .expect("launch bounded SideEffect capture");
    let elapsed = started.elapsed();
    assert_eq!(output.status.code(), Some(2));
    assert!(elapsed < std::time::Duration::from_secs(5));
    assert_record_output_does_not_leak_capture(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("Capture time limit reached"));
    assert!(bundle.is_dir());
    let manifest: Value = serde_json::from_slice(&fs::read(bundle.join("run.json")).unwrap())
        .expect("read bounded run metadata");
    assert_eq!(manifest["schema_version"], 2);
    assert_eq!(manifest["capture"]["time_limit_milliseconds"], 1000);
    assert_eq!(manifest["capture"]["stop_reason"], "time_limit_reached");
    assert_eq!(manifest["capture"]["completeness"], "unknown");
    assert!(fs::metadata(bundle.join("trace.strace")).unwrap().len() > 0);

    let inspected = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inspect", "--bundle"])
        .arg(&bundle)
        .output()
        .expect("inspect bounded partial bundle");
    assert_eq!(inspected.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&inspected.stderr)
            .contains("Absence from the trace is not evidence that an event did not occur")
    );
    let trace: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(trace["schema_version"], 7);
    assert_eq!(trace["bundle_capture"]["stop_reason"], "time_limit_reached");
    assert_eq!(trace["bundle_capture"]["time_limit_milliseconds"], 1000);
    assert!(
        trace["records"]
            .as_array()
            .is_some_and(|records| !records.is_empty())
    );

    let compared = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", "--bundles"])
        .arg(&bundle)
        .arg(&bundle)
        .output()
        .expect("reject comparison of a time-limited bundle");
    assert_eq!(compared.status.code(), Some(1));
    assert!(compared.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&compared.stderr).contains("event set is known to be incomplete")
    );
    std::thread::sleep(std::time::Duration::from_millis(1200));
    assert!(
        !marker.exists(),
        "traced descendant continued running after the time-limited capture returned"
    );
}

#[test]
fn real_strace_capture_cancellation_discards_partial_trace_and_reaps_tracee() {
    // Prerequisites: Linux x86_64, external strace >= 6.8, and python3.
    require_tool("strace", &["--version"]);
    require_tool("python3", &["--version"]);

    let temp = PrivateTempDirectory::new();
    let trace_path = temp.path().join("cancelled.trace");
    let ready_path = temp.path().join("target-ready.pid");
    let script = format!(
        "import os,time; open({:?}, 'w').write(str(os.getpid())); time.sleep(30)",
        ready_path
    );
    let mut recorder = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["record", "--trace"])
        .arg(&trace_path)
        .args(["--", "python3", "-c", &script])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("launch SideEffect real strace capture");

    let ready_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let target_pid = loop {
        if let Ok(contents) = fs::read_to_string(&ready_path) {
            if let Ok(pid) = contents.parse::<libc::pid_t>() {
                break pid;
            }
        }
        if let Some(status) = recorder.try_wait().expect("check recorder startup") {
            panic!("real capture exited before target readiness: {status}");
        }
        if std::time::Instant::now() >= ready_deadline {
            let _ = recorder.kill();
            let _ = recorder.wait();
            panic!("real strace target did not signal readiness within 10 seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };

    // SAFETY: send SIGTERM only to the isolated SideEffect recorder process
    // started by this test after its traced target has written the ready file.
    let signal_result = unsafe { libc::kill(recorder.id() as libc::pid_t, libc::SIGTERM) };
    if signal_result != 0 {
        let _ = recorder.kill();
        let _ = recorder.wait();
        panic!(
            "could not interrupt isolated real capture: {}",
            std::io::Error::last_os_error()
        );
    }

    let stop_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = recorder.try_wait().expect("wait for interrupted recorder") {
            break status;
        }
        if std::time::Instant::now() >= stop_deadline {
            let _ = recorder.kill();
            let _ = recorder.wait();
            // SAFETY: target_pid came from the test's own isolated Python target.
            unsafe { libc::kill(target_pid, libc::SIGKILL) };
            panic!("recorder did not stop after SIGTERM within 5 seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let output = recorder
        .wait_with_output()
        .expect("collect interrupted recorder output");
    assert_eq!(status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("capture interrupted by signal 15; the partial trace was discarded"),
        "unexpected cancellation diagnostic: {stderr}"
    );
    assert!(
        !trace_path.exists(),
        "interrupted capture must not publish a partial trace"
    );

    // --kill-on-exit is expected to stop the real traced target when SideEffect
    // terminates strace. Give the kernel a short bounded interval to reap it.
    let reap_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let target_reaped = loop {
        // SAFETY: signal 0 only checks the recorded test target PID.
        let result = unsafe { libc::kill(target_pid, 0) };
        if result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            break true;
        }
        if std::time::Instant::now() >= reap_deadline {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    if !target_reaped {
        // SAFETY: target_pid is the Python process created by this test.
        unsafe { libc::kill(target_pid, libc::SIGKILL) };
        panic!("traced Python target survived real strace cancellation");
    }
    assert_eq!(
        fs::read_dir(temp.path()).unwrap().count(),
        1,
        "cancellation should clean the private staging output and leave only the readiness marker"
    );
}
