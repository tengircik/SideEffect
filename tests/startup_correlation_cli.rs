use sideeffect::limits::MAX_REPORT_BYTES;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-startup-correlation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn cli_correlates_synthetic_saved_inputs_without_claiming_startup_causation() {
    let temp = Temp::new();
    let inventory = temp.0.join("startup.json");
    let trace = temp.0.join("capture.trace");
    let payload = temp.0.join("should-not-be-created");
    let startup = serde_json::json!({
        "schema":"sideeffect.startup_inventory", "schema_version":2,
        "platform":"linux", "scope":"curated_xdg_systemd_sysv_cron_sources",
        "capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":"complete",
        "xdg_autostart": {
            "schema":"sideeffect.xdg_autostart_inventory","schema_version":1,"platform":"linux",
            "scope":"xdg_autostart_directories","capture_started_at_unix_ms":1,
            "capture_ended_at_unix_ms":2,"status":"complete","directories":[],
            "entries":[{
                "scope":"user","source_path":"/config/example.desktop","applicability":"not_evaluated",
                "keys":[
                    {"key":"Exec","value":"/usr/bin/example --safe","value_hex":null,
                     "line":4,"byte_offset":20,"byte_length":24,"line_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                    {"key":"Exec","value":format!("$(touch {})", payload.display()),"value_hex":null,
                     "line":5,"byte_offset":45,"byte_length":20,"line_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
                ]
            }]
        },
        "systemd_units":{"schema":"sideeffect.systemd_units","schema_version":1,"platform":"linux",
            "scope":"systemd_unit_files","capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,
            "status":"complete","directories":[],"records":[]},
        "legacy_sources":{"schema":"sideeffect.legacy_startup_inventory","schema_version":1,
            "platform":"linux","scope":"curated_sysv_cron_paths","capture_started_at_unix_ms":1,
            "capture_ended_at_unix_ms":2,"status":"complete","sources":[],"entries":[]}
    });
    fs::write(&inventory, serde_json::to_vec(&startup).unwrap()).unwrap();
    // Both inputs are synthetic fixtures; this does not exercise a real capture.
    fs::write(
        &trace,
        b"100 execve(\"/usr/bin/example\", [\"different-argv0\"], 0x0) = 0\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("correlate-startup")
        .arg(&inventory)
        .arg(&trace)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "sideeffect.startup_correlation");
    assert_eq!(report["status"], "partial");
    assert_eq!(report["candidate_matches"][0]["status"], "candidate_match");
    assert_eq!(
        report["candidate_matches"][0]["runtime_evidence"][0]["caller_task_id"],
        100
    );
    assert!(
        report["candidate_matches"][0]["runtime_evidence"][0]
            .get("process_id")
            .is_none()
    );
    assert_eq!(report["summary"]["unsupported_xdg_exec_count"], 1);
    assert_eq!(
        report["trace_capture_completeness"],
        "unknown_for_raw_trace_input"
    );
    assert!(report["claim"].as_str().unwrap().contains("does not prove"));
    assert!(!payload.exists());
}

#[test]
fn cli_rejects_non_startup_schema_input() {
    let temp = Temp::new();
    let inventory = temp.0.join("wrong.json");
    let trace = temp.0.join("empty.trace");
    fs::write(
        &inventory,
        br#"{"schema":"wrong","schema_version":2,"platform":"linux"}"#,
    )
    .unwrap();
    fs::write(&trace, b"").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("correlate-startup")
        .arg(&inventory)
        .arg(&trace)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("startup input"));
}

#[test]
fn cli_rejects_oversized_startup_inventory_before_reading_it() {
    let temp = Temp::new();
    let inventory = temp.0.join("oversized.json");
    let trace = temp.0.join("empty.trace");
    fs::File::create(&inventory)
        .unwrap()
        .set_len(MAX_REPORT_BYTES as u64 + 1)
        .unwrap();
    fs::write(&trace, b"").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("correlate-startup")
        .arg(&inventory)
        .arg(&trace)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("startup inventory input exceeds"));
}

#[test]
fn cli_marks_partial_parse_in_json_and_exit_status() {
    let temp = Temp::new();
    let inventory = temp.0.join("startup.json");
    let trace = temp.0.join("partial.trace");
    let startup = serde_json::json!({
        "schema":"sideeffect.startup_inventory", "schema_version":2,
        "platform":"linux", "capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,
        "scope":"curated_xdg_systemd_sysv_cron_sources", "status":"complete",
        "xdg_autostart":{"status":"complete", "directories":[], "entries":[]},
        "systemd_units":{"status":"complete", "directories":[], "records":[]},
        "legacy_sources":{"status":"complete", "sources":[], "entries":[]}
    });
    fs::write(&inventory, serde_json::to_vec(&startup).unwrap()).unwrap();
    fs::write(&trace, b"malformed trace input\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("correlate-startup")
        .arg(&inventory)
        .arg(&trace)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "partial");
    assert_eq!(report["trace_parse_status"], "partial");
}
