use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TempTrace(std::path::PathBuf);

impl TempTrace {
    fn with_contents(bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-events-cli-{}-{}.trace",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        Self(path)
    }
}

impl Drop for TempTrace {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn events_trace_writes_versioned_json_in_source_order() {
    let trace = TempTrace::with_contents(
        b"123 1700000000.123456 openat(AT_FDCWD, \"/tmp/item\", O_RDONLY) = 4\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["events", "--trace"])
        .arg(&trace.0)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema"], "sideeffect.common_event_envelope");
    assert_eq!(envelope["schema_version"], 2);
    assert_eq!(envelope["source_state"]["completeness"], "complete");
    assert_eq!(envelope["events"].as_array().unwrap().len(), 1);
    assert_eq!(envelope["events"][0]["source_local_ordinal"], 1);
    assert_eq!(envelope["events"][0]["event_kind"], "openat");
    assert_eq!(
        envelope["events"][0]["source_timestamp"]["value"],
        "1700000000.123456"
    );
    assert_eq!(envelope["events"][0]["evidence"]["line_number"], 1);
    assert_eq!(
        envelope["process_observations"].as_array().unwrap().len(),
        1
    );
    assert!(
        envelope["process_relationships"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn timeline_filters_exact_kind_and_retains_raw_evidence_and_diagnostics() {
    let trace = TempTrace::with_contents(
        b"1700000000.000001 openat(AT_FDCWD, \"/tmp/item\", O_RDONLY) = 4\nnot a recognized trace row\n1700000000.000003 close(4) = 0\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["timeline", "--trace"])
        .arg(&trace.0)
        .args(["--event-kind", "close"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let timeline: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(timeline["schema"], "sideeffect.event_timeline");
    assert_eq!(timeline["schema_version"], 1);
    assert_eq!(timeline["source_state"]["completeness"], "partial");
    assert_eq!(timeline["filter"]["event_kind"], "close");
    assert!(
        timeline["ordering"]
            .as_str()
            .unwrap()
            .contains("do not establish causal order")
    );
    assert_eq!(timeline["items"].as_array().unwrap().len(), 1);
    assert_eq!(timeline["items"][0]["source_local_ordinal"], 3);
    assert_eq!(
        timeline["items"][0]["source_timestamp"]["value"],
        "1700000000.000003"
    );
    assert_eq!(timeline["items"][0]["evidence"]["kind"], "raw_trace_record");
    assert_eq!(timeline["items"][0]["evidence"]["line_number"], 3);
    assert_eq!(timeline["diagnostics"][0]["code"], "unsupported_source_row");
    assert_eq!(timeline["diagnostics"][0]["source_local_ordinal"], 2);
}

#[test]
fn timeline_rejects_invalid_filter_before_reading_trace() {
    let trace = TempTrace::with_contents(b"1700000000.000001 close(3) = 0\n");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["timeline", "--trace"])
        .arg(&trace.0)
        .args(["--event-kind", ""])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("1..128 printable UTF-8 bytes"));
}

#[test]
fn events_trace_preserves_partial_diagnostics_and_uses_exit_two() {
    let trace = TempTrace::with_contents(b"not a recognized trace row\n");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["events", "--trace"])
        .arg(&trace.0)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["source_state"]["completeness"], "partial");
    assert_eq!(envelope["events"].as_array().unwrap().len(), 0);
    assert_eq!(envelope["diagnostics"][0]["code"], "unsupported_source_row");
    assert_eq!(envelope["diagnostics"][0]["source_local_ordinal"], 1);
}

#[cfg(not(windows))]
#[test]
fn windows_runtime_events_are_native_windows_only() {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["events", "--windows-runtime", "capture.json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("supported only in native Windows builds")
    );
}
