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

fn run_record(trace_path: &Path, file_path: &Path, connect_loopback: bool) -> Output {
    const SCRIPT: &str = r#"
import socket
import sys

path = sys.argv[1]
with open(path, "wb") as output:
    output.write(b"SideEffect loopback integration test")
with open(path, "rb") as source:
    source.read()

if sys.argv[2] == "connect":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(server.getsockname())
    accepted, _ = server.accept()
    accepted.close()
    client.close()
    server.close()
"#;

    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["record", "--trace"])
        .arg(trace_path)
        .args(["--", "python3", "-c", SCRIPT])
        .arg(file_path)
        .arg(if connect_loopback {
            "connect"
        } else {
            "file-only"
        })
        .output()
        .expect("launch SideEffect record command")
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
                "inspect output lacks successful {syscall_name} evidence matching the expected argument"
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

    for (trace, file, connect_loopback) in [
        (baseline_path.as_path(), baseline_file.as_path(), true),
        (candidate_path.as_path(), candidate_file.as_path(), false),
    ] {
        let output = run_record(trace, file, connect_loopback);
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
    assert_successful_syscall(
        &baseline,
        "openat",
        baseline_file.to_str().expect("UTF-8 test path"),
    );
    assert_successful_syscall(
        &candidate,
        "openat",
        candidate_file.to_str().expect("UTF-8 test path"),
    );
    let loopback_connect = assert_successful_syscall(&baseline, "connect", "127.0.0.1");
    assert_eq!(loopback_connect["raw_result"], "0");
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
    assert!(
        changes.iter().any(|change| {
            change["kind"] == "removed"
                && change["category"] == "file"
                && change["syscall"] == "openat"
                && change["raw_arguments"]
                    .as_str()
                    .is_some_and(|args| args.contains(baseline_file.to_str().unwrap()))
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
                    .is_some_and(|args| args.contains(candidate_file.to_str().unwrap()))
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
}
