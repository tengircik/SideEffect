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
    assert_eq!(envelope["schema_version"], 5);
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
    assert_eq!(timeline["schema_version"], 5);
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
    assert_eq!(timeline["schema_version"], 5);
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
fn timeline_text_is_terminal_safe_preserves_source_references_and_keeps_json_default() {
    let malicious_trace =
        "123 1700000000.000001 openat(AT_FDCWD, \"/tmp/\x1b[31m\\u202e\", O_RDONLY) = 4\n"
            .to_string();
    let trace = TempTrace::with_contents(malicious_trace.as_bytes());
    let json_default = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["timeline", "--trace"])
        .arg(&trace.0)
        .output()
        .unwrap();
    assert!(json_default.status.success() || json_default.status.code() == Some(2));
    let json: serde_json::Value = serde_json::from_slice(&json_default.stdout).unwrap();
    assert_eq!(json["schema"], "sideeffect.event_timeline");
    let explicit_json = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["timeline", "--trace"])
        .arg(&trace.0)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(explicit_json.status.code(), json_default.status.code());
    assert_eq!(explicit_json.stdout, json_default.stdout);

    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["timeline", "--trace"])
        .arg(&trace.0)
        .args(["--event-kind", "openat", "--format", "text"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), json_default.status.code());
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.is_ascii());
    assert!(text.contains("ordinal=1 timestamp=1700000000.000001"));
    assert!(text.contains("raw_trace_record(line=1,byte="));
    assert!(text.contains("timestamps do not establish causality"));
    assert!(!text.contains('\u{001b}'));
    assert!(!text.contains('\u{202e}'));
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
fn timeline_combined_filters_intersect_in_either_argument_order() {
    let trace = TempTrace::with_contents(
        b"123 1700000000.000001 openat(AT_FDCWD, \"/tmp/item\", O_RDONLY) = 4\n",
    );
    for filters in [
        ["--event-kind", "openat", "--process-observation", "1"],
        ["--process-observation", "1", "--event-kind", "openat"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .args(["timeline", "--trace"])
            .arg(&trace.0)
            .args(filters)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let timeline: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(timeline["filter"]["event_kind"], "openat");
        assert_eq!(timeline["filter"]["process_observation_id"], 1);
        assert_eq!(timeline["items"].as_array().unwrap().len(), 1);
        assert_eq!(timeline["items"][0]["event_kind"], "openat");
        assert_eq!(timeline["items"][0]["evidence"]["line_number"], 1);
        assert_eq!(
            timeline["selected_process_observation"]["source_local_id"],
            1
        );
        assert_eq!(timeline["event_process_links"].as_array().unwrap().len(), 1);
    }

    let no_match = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["timeline", "--trace"])
        .arg(&trace.0)
        .args(["--process-observation", "1", "--event-kind", "close"])
        .output()
        .unwrap();
    assert!(no_match.status.success());
    let timeline: serde_json::Value = serde_json::from_slice(&no_match.stdout).unwrap();
    assert!(timeline["items"].as_array().unwrap().is_empty());
    assert_eq!(
        timeline["selected_process_observation"]["source_local_id"],
        1
    );
    assert_eq!(
        timeline["selected_process_observation"]["evidence"]["line_number"],
        1
    );
    assert!(
        timeline["event_process_links"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn timeline_rejects_duplicate_and_malformed_filter_options() {
    let trace = TempTrace::with_contents(b"123 1700000000.000001 close(4) = 0\n");
    for (arguments, expected) in [
        (
            vec!["--event-kind", "close", "--event-kind", "openat"],
            "duplicate timeline option --event-kind",
        ),
        (
            vec!["--event-kind"],
            "timeline option --event-kind requires a value",
        ),
        (
            vec!["--unexpected", "value"],
            "unknown timeline option --unexpected",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
            .args(["timeline", "--trace"])
            .arg(&trace.0)
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
    }
}

#[test]
fn timeline_unknown_option_escapes_terminal_control_characters() {
    let trace = TempTrace::with_contents(b"123 1700000000.000001 close(4) = 0\n");
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["timeline", "--trace"])
        .arg(&trace.0)
        .arg("--unexpected\x1b[2J")
        .arg("value")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--unexpected\\u{1b}[2J"));
    assert!(!stderr.contains('\x1b'));
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
    assert_eq!(graph["schema_version"], 5);
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
fn graph_text_preserves_selected_context_and_json_default() {
    let trace = TempTrace::with_contents(
        b"[pid 123] 1700000000.000001 openat(AT_FDCWD, \"/tmp/item\", O_RDONLY) = 3\nnot a recognized trace row\n",
    );
    let default_json = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .output()
        .unwrap();
    assert_eq!(default_json.status.code(), Some(2));
    let default_value: serde_json::Value = serde_json::from_slice(&default_json.stdout).unwrap();
    assert_eq!(default_value["schema"], "sideeffect.event_graph");
    let explicit_json = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(explicit_json.status.code(), default_json.status.code());
    assert_eq!(explicit_json.stdout, default_json.stdout);

    let text = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .args(["--process-observation", "1", "--format", "text"])
        .output()
        .unwrap();
    assert_eq!(text.status.code(), Some(2));
    assert!(text.stderr.is_empty());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.is_ascii());
    assert!(text.contains("Completeness: partial"));
    assert!(text.contains("process_observation_id=1"));
    assert!(text.contains("process observation (source-local, not a PID key): source_local_id=1"));
    assert!(text.contains("raw_trace_record(line=1,byte=0,length="));
    assert!(text.contains("role=linux_trace_caller_task_context status=observed"));
    assert!(text.contains("unsupported_source_row"));
    assert!(text.contains("Empty selections do not prove absence"));

    let empty = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .args(["--event-kind", "not-present", "--format", "text"])
        .output()
        .unwrap();
    assert_eq!(empty.status.code(), Some(2));
    let empty = String::from_utf8(empty.stdout).unwrap();
    assert!(empty.contains("none selected; this does not establish absence"));
}

#[test]
fn graph_html_is_offline_bounded_private_and_no_clobber() {
    let trace = TempTrace::with_contents(
        b"1700000000.000001 openat(AT_FDCWD, \"/tmp/<graph>\", O_RDONLY) = 3\nnot a recognized trace row\n",
    );
    let report = std::env::temp_dir().join(format!(
        "sideeffect-events-graph-html-{}-{}.html",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .args(["--format", "html", "--output"])
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Offline event graph HTML report written")
    );
    let html = fs::read_to_string(&report).unwrap();
    assert!(html.contains("Content-Security-Policy"));
    assert!(html.contains("default-src 'none'"));
    assert!(html.contains("script-src 'none'"));
    assert!(html.contains("Skip to report content"));
    assert!(html.contains("Source completeness"));
    assert!(html.contains("unsupported_source_row"));
    assert!(html.contains("partial"));
    assert!(html.contains("raw_trace_record"));
    assert!(html.contains("&lt;graph&gt;"));
    assert!(!html.contains("<script"));
    assert!(!html.contains("https://"));

    let existing = b"preserve-existing-report";
    fs::write(&report, existing).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .args(["--format", "html", "--output"])
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(1));
    assert!(rejected.stdout.is_empty());
    assert_eq!(fs::read(&report).unwrap(), existing);
    fs::remove_file(report).unwrap();

    let empty_report = std::env::temp_dir().join(format!(
        "sideeffect-events-graph-html-empty-{}-{}.html",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let empty = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .args([
            "--event-kind",
            "not-present",
            "--format",
            "html",
            "--output",
        ])
        .arg(&empty_report)
        .output()
        .unwrap();
    assert_eq!(empty.status.code(), Some(2));
    let empty_html = fs::read_to_string(&empty_report).unwrap();
    assert!(empty_html.contains("No nodes were selected by these filters"));
    assert!(empty_html.contains("does not establish absence"));
    fs::remove_file(empty_report).unwrap();

    let missing_output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .args(["--format", "html"])
        .output()
        .unwrap();
    assert_eq!(missing_output.status.code(), Some(1));
    let invalid_output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .args(["--format", "text", "--output", "ignored.html"])
        .output()
        .unwrap();
    assert_eq!(invalid_output.status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn graph_html_rejects_symlink_destination_without_changing_target() {
    let trace = TempTrace::with_contents(b"1700000000.000001 close(3) = 0\n");
    let target = std::env::temp_dir().join(format!(
        "sideeffect-events-graph-link-target-{}-{}.html",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let link = target.with_extension("link.html");
    fs::write(&target, b"protected target").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--trace"])
        .arg(&trace.0)
        .args(["--format", "html", "--output"])
        .arg(&link)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(&target).unwrap(), b"protected target");
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    fs::remove_file(link).unwrap();
    fs::remove_file(target).unwrap();
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
    assert_eq!(graph["schema_version"], 5);
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
