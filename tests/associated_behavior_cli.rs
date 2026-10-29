use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-associated-behavior-{}-{}",
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

fn startup(exec_value: &str, status: &str) -> Value {
    json!({
        "schema":"sideeffect.startup_inventory", "schema_version":2,
        "platform":"linux", "scope":"curated_xdg_systemd_sysv_cron_sources",
        "capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":status,
        "xdg_autostart": {
            "schema":"sideeffect.xdg_autostart_inventory","schema_version":1,"platform":"linux",
            "scope":"xdg_autostart_directories","capture_started_at_unix_ms":1,
            "capture_ended_at_unix_ms":2,"status":status,"directories":[],
            "entries":[{
                "scope":"user","source_path":"/config/example.desktop","applicability":"not_evaluated",
                "keys":[{"key":"Exec","value":exec_value,"value_hex":null,
                    "line":4,"byte_offset":20,"byte_length":exec_value.len(),
                    "line_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
            }]
        },
        "systemd_units":{"schema":"sideeffect.systemd_units","schema_version":1,"platform":"linux",
            "scope":"systemd_unit_files","capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,
            "status":status,"directories":[],"records":[]},
        "legacy_sources":{"schema":"sideeffect.legacy_startup_inventory","schema_version":1,
            "platform":"linux","scope":"curated_sysv_cron_paths","capture_started_at_unix_ms":1,
            "capture_ended_at_unix_ms":2,"status":status,"sources":[],"entries":[]}
    })
}

fn run_cli(startup: &Value, trace_text: &[u8]) -> (std::process::Output, Value) {
    let temp = Temp::new();
    let startup_path = temp.0.join("startup.json");
    let trace_path = temp.0.join("trace.strace");
    fs::write(&startup_path, serde_json::to_vec(startup).unwrap()).unwrap();
    fs::write(&trace_path, trace_text).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("associated-behavior")
        .arg(&startup_path)
        .arg(&trace_path)
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    // Temp input files remain available until after stdout has been parsed.
    drop(temp);
    (output, report)
}

#[test]
fn cli_emits_candidate_association_with_all_evidence_and_disclaimers() {
    // Synthetic saved inputs; this test does not exercise a real startup event or capture.
    let (output, report) = run_cli(
        &startup("/usr/bin/example --version", "complete"),
        b"100 execve(\"/usr/bin/example\", [\"different-argv0\"], 0x0) = 0\n",
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(report["schema"], "sideeffect.associated_behavior_summary");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["algorithm"]["version"], 1);
    assert_eq!(
        report["platform_adapter"],
        "linux_startup_inventory_v2_strace_v1"
    );
    assert_eq!(report["capture_completeness"], "unknown");
    assert_eq!(report["association_status"], "candidate_match");
    assert_eq!(report["associations"][0]["status"], "candidate_match");
    assert_eq!(report["associations"][0]["startup_evidence"][0]["line"], 4);
    assert_eq!(
        report["associations"][0]["runtime_evidence"][0]["caller_task_id"],
        100
    );
    assert_eq!(
        report["associations"][0]["runtime_evidence"][0]["evidence"]["line_number"],
        1
    );
    assert!(
        report["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item
                .as_str()
                .unwrap()
                .contains("does not establish that a startup hook executed or caused"))
    );
}

#[test]
fn cli_reports_no_match_as_insufficient_evidence_without_partial_exit() {
    let (output, report) = run_cli(
        &startup("/usr/bin/configured", "complete"),
        b"100 execve(\"/usr/bin/other\", [], 0x0) = 0\n",
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(report["status"], "complete");
    assert_eq!(report["association_status"], "insufficient_evidence");
    assert!(report["associations"].as_array().unwrap().is_empty());
    assert_eq!(report["summary"]["unmatched_config_path_count"], 1);
    assert_eq!(report["summary"]["unmatched_runtime_path_count"], 1);
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "unmatched_paths_are_not_evidence_of_non_occurrence")
    );
}

#[test]
fn cli_marks_partial_sources_or_coverage_and_exits_two() {
    let (output, report) = run_cli(
        &startup("/usr/bin/example", "partial"),
        b"malformed trace row\n100 execve(\"/usr/bin/example\", [], 0x0) = 0\n",
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(report["status"], "partial");
    assert_eq!(report["association_status"], "candidate_match");
    assert_eq!(
        report["inputs"]["startup_inventory"]["source_status"],
        "partial"
    );
    assert_eq!(
        report["inputs"]["runtime_trace"]["source_status"],
        "partial"
    );
    assert!(!report["diagnostics"].as_array().unwrap().is_empty());
}

#[test]
fn cli_rejects_oversized_startup_input_before_json_parsing() {
    let temp = Temp::new();
    let startup_path = temp.0.join("oversized-startup.json");
    let trace_path = temp.0.join("trace.strace");
    fs::File::create(&startup_path)
        .unwrap()
        .set_len(sideeffect::limits::MAX_REPORT_BYTES as u64 + 1)
        .unwrap();
    fs::write(&trace_path, b"").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("associated-behavior")
        .arg(&startup_path)
        .arg(&trace_path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("startup inventory input exceeds"));
}
