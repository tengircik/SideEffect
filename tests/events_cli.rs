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
    assert_eq!(timeline["schema_version"], 2);
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
    assert!(
        timeline["event_process_links"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(timeline["diagnostics"][0]["code"], "unsupported_source_row");
    assert_eq!(timeline["diagnostics"][0]["source_local_ordinal"], 2);
}

#[test]
fn timeline_process_observation_filters_by_local_link_and_preserves_evidence() {
    let trace = TempTrace::with_contents(
        b"[pid 123] 1700000000.000001 openat(AT_FDCWD, \"/tmp/one\", O_RDONLY) = 3\nnot a recognized trace row\n[pid 456] 1700000000.000003 close(4) = 0\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["timeline", "--trace"])
        .arg(&trace.0)
        .args(["--process-observation", "1"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let timeline: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(timeline["schema_version"], 2);
    assert_eq!(timeline["filter"]["process_observation_id"], 1);
    assert_eq!(timeline["source_state"]["completeness"], "partial");
    assert_eq!(timeline["items"].as_array().unwrap().len(), 1);
    assert_eq!(timeline["items"][0]["source_local_ordinal"], 1);
    assert_eq!(timeline["items"][0]["evidence"]["line_number"], 1);
    assert_eq!(
        timeline["selected_process_observation"]["source_local_id"],
        1
    );
    assert_eq!(
        timeline["selected_process_observation"]["evidence"]["line_number"],
        1
    );
    assert_eq!(timeline["event_process_links"].as_array().unwrap().len(), 1);
    assert_eq!(
        timeline["event_process_links"][0]["process_observation_id"],
        1
    );
    assert_eq!(
        timeline["event_process_links"][0]["role"],
        "linux_trace_caller_task_context"
    );
    assert_eq!(timeline["event_process_links"][0]["status"], "observed");
    assert_eq!(timeline["diagnostics"][0]["code"], "unsupported_source_row");
    assert!(
        timeline["semantics"]
            .as_str()
            .unwrap()
            .contains("does not prove activity was absent")
    );
}

#[test]
fn timeline_process_observation_rejects_invalid_and_unemitted_ids() {
    let trace = TempTrace::with_contents(b"123 1700000000.000001 close(4) = 0\n");
    for id in ["0", "invalid", "99", "18446744073709551616"] {
        let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .args(["timeline", "--trace"])
            .arg(&trace.0)
            .args(["--process-observation", id])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "ID was {id}");
        assert!(output.stdout.is_empty(), "ID was {id}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("process observation ID"));
    }
}

#[test]
fn timeline_rejects_combined_filters() {
    let trace = TempTrace::with_contents(b"123 1700000000.000001 close(4) = 0\n");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["timeline", "--trace"])
        .arg(&trace.0)
        .args(["--process-observation", "1", "--event-kind", "close"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be combined"));
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
fn graph_trace_keeps_event_process_link_and_source_evidence() {
    let trace = TempTrace::with_contents(
        b"123 1700000000.000001 openat(AT_FDCWD, \"/tmp/item\", O_RDONLY) = 4\nnot a recognized trace row\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let graph: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(graph["schema"], "sideeffect.event_graph");
    assert_eq!(graph["schema_version"], 2);
    assert_eq!(graph["source_state"]["completeness"], "partial");
    assert!(
        graph["semantics"]
            .as_str()
            .unwrap()
            .contains("do not establish ownership, causation")
    );
    assert_eq!(graph["nodes"].as_array().unwrap().len(), 2);
    let event = graph["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["kind"] == "event")
        .unwrap();
    let process = graph["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["kind"] == "process_observation")
        .unwrap();
    assert_eq!(event["event"]["event_kind"], "openat");
    assert_eq!(event["evidence"]["line_number"], 1);
    assert_eq!(process["process_observation"]["identity"]["task_id"], 123);
    assert_eq!(graph["edges"].as_array().unwrap().len(), 1);
    assert_eq!(graph["edges"][0]["kind"], "event_process_link");
    assert_eq!(graph["edges"][0]["event_link_status"], "observed");
    assert_eq!(graph["edges"][0]["from_node_id"], event["id"]);
    assert_eq!(graph["edges"][0]["to_node_id"], process["id"]);
    assert_eq!(graph["edges"][0]["evidence"][0]["line_number"], 1);
    assert_eq!(graph["diagnostics"][0]["code"], "unsupported_source_row");
}

#[test]
fn graph_event_kind_filter_keeps_related_evidence_and_all_diagnostics() {
    let trace = TempTrace::with_contents(
        b"123 1700000000.000001 openat(AT_FDCWD, \"/tmp/item\", O_RDONLY) = 4\n456 1700000000.000002 close(4) = 0\nnot a recognized trace row\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .args(["--event-kind", "openat"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let graph: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(graph["filter"]["event_kind"], "openat");
    assert_eq!(graph["source_state"]["completeness"], "partial");
    assert_eq!(graph["diagnostics"].as_array().unwrap().len(), 1);
    assert_eq!(graph["nodes"].as_array().unwrap().len(), 2);
    assert!(graph["nodes"].as_array().unwrap().iter().any(|node| {
        node["kind"] == "event"
            && node["event"]["event_kind"] == "openat"
            && node["evidence"]["line_number"] == 1
    }));
    assert!(
        !graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["event"]["event_kind"] == "close")
    );
    assert_eq!(graph["edges"].as_array().unwrap().len(), 1);
    assert_eq!(graph["edges"][0]["kind"], "event_process_link");
}

#[test]
fn graph_process_observation_filter_selects_source_local_context_and_links() {
    let trace = TempTrace::with_contents(
        b"[pid 123] 1700000000.000001 openat(AT_FDCWD, \"/tmp/one\", O_RDONLY) = 3\n[pid 456] 1700000000.000002 close(4) = 0\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .args(["--process-observation", "1"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let graph: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(graph["schema_version"], 2);
    assert_eq!(graph["filter"]["event_kind"], serde_json::Value::Null);
    assert_eq!(graph["filter"]["process_observation_id"], 1);
    assert!(
        graph["semantics"]
            .as_str()
            .unwrap()
            .contains("not proof of absence")
    );
    let nodes = graph["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 2);
    let event = nodes.iter().find(|node| node["kind"] == "event").unwrap();
    let process = nodes
        .iter()
        .find(|node| node["kind"] == "process_observation")
        .unwrap();
    assert_eq!(event["event"]["event_kind"], "openat");
    assert_eq!(event["evidence"]["line_number"], 1);
    assert_eq!(process["process_observation"]["source_local_id"], 1);
    assert_eq!(
        process["process_observation"]["identity"]["kind"],
        "linux_trace_task_context"
    );
    assert_eq!(process["process_observation"]["identity"]["task_id"], 123);
    assert_eq!(graph["edges"].as_array().unwrap().len(), 1);
    assert_eq!(graph["edges"][0]["event_link_status"], "observed");
    assert_eq!(
        graph["edges"][0]["event_link_role"],
        "linux_trace_caller_task_context"
    );
}

#[test]
fn graph_process_observation_filter_rejects_invalid_or_unemitted_ids() {
    let trace = TempTrace::with_contents(b"123 1700000000.000001 close(4) = 0\n");
    for id in ["0", "invalid", "18446744073709551616"] {
        let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .args(["graph", "--trace"])
            .arg(&trace.0)
            .args(["--process-observation", id])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "ID was {id}");
        assert!(output.stdout.is_empty(), "ID was {id}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("process observation ID"));
    }

    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .args(["--process-observation", "99"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("no source-local process observation ID 99 was emitted")
    );
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

#[cfg(not(windows))]
#[test]
fn windows_runtime_timeline_is_native_windows_only() {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["timeline", "--windows-runtime", "capture.json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("supported only in native Windows builds")
    );
}

#[cfg(not(windows))]
#[test]
fn windows_runtime_graph_is_native_windows_only() {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--windows-runtime", "capture.json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("supported only in native Windows builds")
    );
}
