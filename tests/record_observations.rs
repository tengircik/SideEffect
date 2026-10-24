#![cfg(target_os = "linux")]

use serde_json::Value;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
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
