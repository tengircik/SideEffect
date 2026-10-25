#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-startup-correlation-strace-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn find_python() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join("python3"))
        .find(|path| path.is_file())
}

#[test]
fn real_strace_capture_can_match_a_synthetic_literal_startup_row() {
    // Prerequisites: Linux x86_64, external strace >= 6.8, and python3.
    let version = Command::new("strace").arg("--version").output();
    assert!(
        version.as_ref().is_ok_and(|output| output.status.success()),
        "real-tracer test requires external strace >= 6.8"
    );
    let python = find_python().expect("real-tracer test requires python3 on PATH");
    assert!(
        Command::new(&python)
            .arg("--version")
            .status()
            .unwrap()
            .success()
    );

    let temp = Temp::new();
    let startup = temp.0.join("synthetic-startup.json");
    let trace = temp.0.join("real-capture.trace");
    let config_path = python
        .to_str()
        .expect("real-tracer test path must be UTF-8")
        .to_owned();
    let inventory = serde_json::json!({
        "schema":"sideeffect.startup_inventory", "schema_version":2, "platform":"linux",
        "scope":"curated_xdg_systemd_sysv_cron_sources", "status":"complete",
        "capture_started_at_unix_ms":1, "capture_ended_at_unix_ms":2,
        "xdg_autostart":{"status":"complete", "directories":[], "entries":[{
            "scope":"synthetic_fixture", "source_path":"/synthetic/example.desktop",
            "applicability":"not_evaluated", "keys":[{
                "key":"Exec", "value":config_path, "value_hex":null, "line":1,
                "byte_offset":0, "byte_length":config_path.len(),
                "line_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }]
        }]},
        "systemd_units":{"status":"complete", "directories":[], "records":[]},
        "legacy_sources":{"status":"complete", "sources":[], "entries":[]}
    });
    fs::write(&startup, serde_json::to_vec(&inventory).unwrap()).unwrap();

    let capture = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["record", "--trace"])
        .arg(&trace)
        .arg("--")
        .arg(&python)
        .args(["-c", "pass"])
        .output()
        .unwrap();
    assert!(
        capture.status.success(),
        "record stderr: {}",
        String::from_utf8_lossy(&capture.stderr)
    );

    let correlation = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("correlate-startup")
        .arg(&startup)
        .arg(&trace)
        .output()
        .unwrap();
    assert!(
        correlation.status.success(),
        "correlation stderr: {}",
        String::from_utf8_lossy(&correlation.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&correlation.stdout).unwrap();
    assert_eq!(result["candidate_matches"].as_array().unwrap().len(), 1);
    assert_eq!(result["candidate_matches"][0]["status"], "candidate_match");
    assert_eq!(
        result["candidate_matches"][0]["executable_path"],
        config_path
    );
    assert_eq!(
        result["candidate_matches"][0]["runtime_evidence"][0]["syscall"],
        "execve"
    );
    assert!(
        result["candidate_matches"][0]["runtime_evidence"][0]
            .get("caller_task_id")
            .is_some()
    );
    assert_eq!(
        result["trace_capture_completeness"],
        "unknown_for_raw_trace_input"
    );
    assert!(Path::new(&trace).is_file());
}
