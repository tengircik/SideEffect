#![cfg(windows)]

use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Opt-in acceptance test. This needs permission to control the NT Kernel
/// Logger and is explicitly run on privileged GitHub-hosted Windows CI runners.
/// Its child fixture creates and reads one temporary file, then connects to a
/// loopback TCP listener. The fixture is this test executable itself so the
/// acceptance run does not depend on PowerShell startup or command parsing.
#[test]
#[ignore = "requires administrative access to the NT Kernel Logger; run explicitly"]
fn captures_process_file_and_loopback_network_observations_and_reports_loss_state() {
    let directory = std::env::temp_dir().join(format!(
        "sideeffect-windows-etw-integration-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&directory).unwrap();
    let output = directory.join("capture.json");
    let fixture_name = format!("sideeffect-etw-fixture-{}.txt", std::process::id());
    let fixture_file = directory.join(&fixture_name);
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop_server = Arc::new(AtomicBool::new(false));
    let server_stop = stop_server.clone();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut buffer = [0_u8; 16];
                    let _ = stream.read(&mut buffer);
                    return true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if server_stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return false,
            }
        }
    });
    let fixture_executable = std::env::current_exe().unwrap();
    let record_started = Instant::now();
    let command = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["record", "--windows-etw", output.to_str().unwrap()])
        .args([
            "--duration-seconds",
            "10",
            "--",
            fixture_executable.to_str().unwrap(),
            "--ignored",
            "--exact",
            "etw_fixture_child",
            "--nocapture",
        ])
        .env("SIDEEFFECT_ETW_FIXTURE_FILE", &fixture_file)
        .env("SIDEEFFECT_ETW_FIXTURE_PORT", port.to_string())
        .output()
        .unwrap();
    let record_command_elapsed_ms = record_started.elapsed().as_millis();
    stop_server.store(true, Ordering::Relaxed);
    assert!(
        server.join().unwrap(),
        "loopback fixture did not accept the connection; recorder exit: {:?}; stderr: {}; stdout: {}",
        command.status,
        String::from_utf8_lossy(&command.stderr),
        String::from_utf8_lossy(&command.stdout)
    );
    assert!(
        matches!(command.status.code(), Some(0 | 2)),
        "ETW acceptance failed (this host may lack permission to control NT Kernel Logger): {}",
        String::from_utf8_lossy(&command.stderr)
    );
    let capture_bytes = fs::read(&output).unwrap();
    let document: Value = serde_json::from_slice(&capture_bytes).unwrap();
    assert_eq!(document["schema"], "sideeffect.windows_runtime_capture");
    assert_eq!(document["schema_version"], 3);
    assert_eq!(document["capture_completeness"], "unknown");
    assert_eq!(document["event_loss"]["loss_statistics_available"], true);
    let events = document["events"].as_array().unwrap();
    assert!(events.iter().any(|event| {
        event["event_kind"] == "process_start" || event["event_kind"] == "process_end"
    }));
    assert!(document["target"]["process_id"].as_u64().unwrap() > 0);
    let target_pid = document["target"]["process_id"].as_u64().unwrap();
    let target_process_start_seen = events.iter().any(|event| {
        event["event_kind"] == "process_start"
            && event["payload_decoding"]["status"] == "decoded"
            && event["payload_decoding"]["process_id"] == target_pid
    });
    let process_observations = events
        .iter()
        .filter(|event| event["payload_decoding"].is_object())
        .map(|event| {
            serde_json::json!({
                "event_id": event["event_id"],
                "event_version": event["event_version"],
                "opcode": event["opcode"],
                "event_kind": event["event_kind"],
                "payload_decoding": {
                    "status": event["payload_decoding"]["status"],
                    "diagnostic": event["payload_decoding"]["diagnostic"],
                    "process_id": event["payload_decoding"]["process_id"]
                }
            })
        })
        .collect::<Vec<_>>();
    assert!(
        target_process_start_seen,
        "target process start was not decoded; target PID {target_pid}; process observations: {}",
        serde_json::to_string(&process_observations).unwrap()
    );
    let envelope_output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["events", "--windows-runtime"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        matches!(envelope_output.status.code(), Some(0 | 2)),
        "common event adapter failed on its real ETW capture: {}",
        String::from_utf8_lossy(&envelope_output.stderr)
    );
    let envelope: Value = serde_json::from_slice(&envelope_output.stdout).unwrap();
    assert_eq!(envelope["schema"], "sideeffect.common_event_envelope");
    assert_eq!(envelope["schema_version"], 5);
    let target_version = events
        .iter()
        .find(|event| {
            event["event_kind"] == "process_start"
                && event["payload_decoding"]["process_id"] == target_pid
        })
        .and_then(|event| event["event_version"].as_u64())
        .unwrap();
    let loss_free = document["event_loss"]["events_lost"] == 0
        && document["event_loss"]["log_buffers_lost"] == 0
        && document["event_loss"]["real_time_buffers_lost"] == 0
        && document["event_loss"]["loss_statistics_available"] == true
        && document["event_loss"]["final_snapshot_available"] == true;
    let target_identity_status = envelope["process_observations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|process| process["identity"]["process_id"] == target_pid)
        .map(|process| process["identity"]["identity_status"].as_str().unwrap());
    if target_version <= 3 && loss_free {
        assert_eq!(target_identity_status, Some("observed_start"));
        assert!(
            envelope["event_process_links"]
                .as_array()
                .unwrap()
                .iter()
                .any(|link| {
                    link["role"] == "windows_process_start_payload"
                        && link["status"] == "observed"
                        && link["process_observation_id"].is_number()
                })
        );
    } else {
        assert_ne!(target_identity_status, Some("observed_start"));
    }
    let attribution_output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["attribute", "--windows-runtime"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        matches!(attribution_output.status.code(), Some(0 | 2)),
        "attribution adapter failed on its real ETW capture: {}",
        String::from_utf8_lossy(&attribution_output.stderr)
    );
    let attribution: Value = serde_json::from_slice(&attribution_output.stdout).unwrap();
    assert_eq!(
        attribution["schema"],
        "sideeffect.windows_runtime_attribution"
    );
    assert_eq!(attribution["schema_version"], 2);
    assert_eq!(attribution["target_process_id"], target_pid);
    if target_version <= 3 {
        assert_eq!(
            attribution["target_start_status"],
            "observed_once",
            "supported target process-start version {target_version} was not raw-checked into attribution: {}",
            serde_json::to_string(&attribution).unwrap()
        );
        let target_processes = attribution["processes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|process| process["role"] == "target")
            .collect::<Vec<_>>();
        assert_eq!(target_processes.len(), 1);
        assert_eq!(target_processes[0]["process_id"], target_pid);
        assert_eq!(
            target_processes[0]["identity_status"],
            "recorder_target_pid_matches_observed_process_start"
        );
        assert_eq!(
            target_processes[0]["start_event"]["record_ordinal"],
            events
                .iter()
                .find(|event| {
                    event["event_kind"] == "process_start"
                        && event["payload_decoding"]["process_id"] == target_pid
                })
                .unwrap()["record_ordinal"]
        );
    } else {
        assert_eq!(attribution["status"], "partial");
        assert_eq!(attribution["target_start_status"], "not_observed");
        assert!(
            attribution["processes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|process| process["role"] != "target")
        );
    }
    assert!(
        events.iter().any(|event| {
            event["observation_decoding"]["status"] == "decoded"
                && event["observation_decoding"]["observation"]["activity"]["kind"] == "file"
                && event["observation_decoding"]["observation"]["activity"]["observation"]["path"]
                    .as_str()
                    .is_some_and(|path| path.ends_with(&fixture_name))
        }),
        "capture did not include the fixture's file-name event"
    );
    let loopback_network_seen = events.iter().any(|event| {
        event["observation_decoding"]["status"] == "decoded"
            && event["observation_decoding"]["observation"]["activity"]["kind"] == "network"
            && event["observation_decoding"]["observation"]["activity"]["observation"]["payload_process_id"] == target_pid
            && event["observation_decoding"]["observation"]["activity"]["observation"]["destination_address"]["v4"] == serde_json::json!([127, 0, 0, 1])
            && event["observation_decoding"]["observation"]["activity"]["observation"]["destination_port"] == port
    });
    let network_event_summaries = events
        .iter()
        .filter(|event| {
            event["provider_guid"]
                .as_str()
                .is_some_and(|guid| guid.contains("9a280ac0") || guid.contains("bf3a50c5"))
        })
        .take(64)
        .map(|event| {
            serde_json::json!({
                "event_id": event["event_id"],
                "event_version": event["event_version"],
                "opcode": event["opcode"],
                "header_flags": event["header_flags"],
                "payload_length": event["raw_payload_hex"].as_str().map(|value| value.len() / 2),
                "status": event["observation_decoding"]["status"],
                "diagnostic": event["observation_decoding"]["diagnostic"]
            })
        })
        .collect::<Vec<_>>();
    assert!(
        loopback_network_seen,
        "capture did not include the fixture's loopback network event with payload PID; network event summaries: {}",
        serde_json::to_string(&network_event_summaries).unwrap()
    );
    let events = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["events", "--windows-runtime"])
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(events.status.code(), Some(2));
    let events: Value = serde_json::from_slice(&events.stdout).unwrap();
    let timeline = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["timeline", "--windows-runtime"])
        .arg(&output)
        .args(["--event-kind", "file_io_observation"])
        .output()
        .unwrap();
    assert_eq!(
        timeline.status.code(),
        Some(2),
        "the live ETW capture has unknown completeness; timeline should preserve that state: {}",
        String::from_utf8_lossy(&timeline.stderr)
    );
    let timeline: Value = serde_json::from_slice(&timeline.stdout).unwrap();
    assert_eq!(timeline["schema"], "sideeffect.event_timeline");
    assert_eq!(timeline["source_state"], events["source_state"]);
    assert!(matches!(
        timeline["source_state"]["completeness"].as_str(),
        Some("partial" | "unknown")
    ));
    assert_eq!(timeline["filter"]["event_kind"], "file_io_observation");
    assert!(
        timeline["items"].as_array().unwrap().iter().any(|event| {
            event["event_kind"] == "file_io_observation"
                && event["evidence"]["kind"] == "windows_etw_record"
                && event["evidence"]["json_pointer"]
                    .as_str()
                    .is_some_and(|pointer| pointer.starts_with("/events/"))
                && event["evidence"]["raw_payload_sha256"]
                    .as_str()
                    .is_some_and(|digest| digest.len() == 64)
        }),
        "live ETW timeline should retain a filtered file event with exact source evidence"
    );
    let graph = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["graph", "--windows-runtime"])
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(graph.status.code(), Some(2));
    let graph: Value = serde_json::from_slice(&graph.stdout).unwrap();
    assert_eq!(graph["schema"], "sideeffect.event_graph");
    assert_eq!(graph["source_state"], events["source_state"]);
    assert!(graph["nodes"].as_array().unwrap().iter().any(|node| {
        node["kind"] == "event"
            && node["event"]["event_kind"] == "file_io_observation"
            && node["evidence"]["json_pointer"]
                .as_str()
                .is_some_and(|pointer| pointer.starts_with("/events/"))
    }));
    let graph_edges = graph["edges"].as_array().unwrap();
    let event_process_links = events["event_process_links"].as_array().unwrap();
    assert!(
        !event_process_links.is_empty(),
        "the live process/file/network capture should yield event-process links"
    );
    for link in event_process_links {
        assert!(graph_edges.iter().any(|edge| {
            edge["kind"] == "event_process_link"
                && edge["event_link_status"] == link["status"]
                && edge["event_link_role"] == link["role"]
                && edge["basis"] == link["basis"]
                && edge["evidence"][0] == link["event"]
        }));
    }
    if std::env::var("SIDEEFFECT_ETW_DIAGNOSTIC_SAMPLE")
        .is_ok_and(|value| value == "windows_server_hosted_ci")
    {
        let loss = &document["event_loss"];
        let capture_window_ms = document["ended_at_unix_ms"]
            .as_u64()
            .expect("capture end timestamp is an unsigned millisecond count")
            .saturating_sub(
                document["started_at_unix_ms"]
                    .as_u64()
                    .expect("capture start timestamp is an unsigned millisecond count"),
            );
        let diagnostic_sample = serde_json::json!({
            "scope": "windows_server_2022_2025_hosted_ci",
            "sample": "single_synthetic_live_etw_fixture",
            "record_command_elapsed_ms": record_command_elapsed_ms,
            "capture_window_ms": capture_window_ms,
            "retained_event_count": events.len(),
            "serialized_capture_size_bytes": capture_bytes.len(),
            "events_lost": loss["events_lost"]
                .as_u64()
                .expect("ETW events-lost counter is present"),
            "log_buffers_lost": loss["log_buffers_lost"]
                .as_u64()
                .expect("ETW log-buffer loss counter is present"),
            "real_time_buffers_lost": loss["real_time_buffers_lost"]
                .as_u64()
                .expect("ETW real-time buffer loss counter is present"),
        });
        eprintln!(
            "SIDEEFFECT_ETW_DIAGNOSTIC_SAMPLE {}",
            serde_json::to_string(&diagnostic_sample).unwrap()
        );
    }
    fs::remove_file(fixture_file).unwrap();
    fs::remove_file(output).unwrap();
    fs::remove_dir(directory).unwrap();
}

/// Launched only by the live ETW acceptance test above.
#[test]
#[ignore = "launched as a child fixture by the live ETW acceptance test"]
fn etw_fixture_child() {
    let path = std::env::var_os("SIDEEFFECT_ETW_FIXTURE_FILE")
        .expect("ETW fixture file path must be supplied by the parent acceptance test");
    let port = std::env::var("SIDEEFFECT_ETW_FIXTURE_PORT")
        .expect("ETW fixture port must be supplied by the parent acceptance test")
        .parse::<u16>()
        .expect("ETW fixture port must be a valid TCP port");

    fs::write(&path, b"fixture").expect("ETW fixture should write its temporary file");
    assert_eq!(
        fs::read(&path).expect("ETW fixture should read its temporary file"),
        b"fixture"
    );
    let mut connection = TcpStream::connect(("127.0.0.1", port))
        .expect("ETW fixture should connect to its local listener");
    connection
        .write_all(b"fixture")
        .expect("ETW fixture should send bytes to its local listener");
}
