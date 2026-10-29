#![cfg(windows)]

use serde_json::Value;
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Opt-in acceptance test. This needs permission to control the NT Kernel
/// Logger and is explicitly run on privileged GitHub-hosted Windows CI runners.
/// Its child fixture creates and reads one temporary file, then connects to a
/// loopback TCP listener.
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
        let deadline = Instant::now() + Duration::from_secs(15);
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
    let escaped_path = fixture_file.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$ErrorActionPreference='Stop'; [System.IO.File]::WriteAllText('{escaped_path}','fixture'); [System.IO.File]::ReadAllText('{escaped_path}') | Out-Null; $client=[System.Net.Sockets.TcpClient]::new(); $client.Connect('127.0.0.1',{port}); $client.Close()"
    );
    let command = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["record", "--windows-etw", output.to_str().unwrap()])
        .args([
            "--duration-seconds",
            "10",
            "--",
            "powershell.exe",
            "-NoProfile",
            "-Command",
            &script,
        ])
        .output()
        .unwrap();
    stop_server.store(true, Ordering::Relaxed);
    assert!(
        server.join().unwrap(),
        "loopback fixture did not accept the connection"
    );
    assert!(
        matches!(command.status.code(), Some(0 | 2)),
        "ETW acceptance failed (this host may lack permission to control NT Kernel Logger): {}",
        String::from_utf8_lossy(&command.stderr)
    );
    let document: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
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
    assert!(events.iter().any(|event| {
        event["event_kind"] == "process_start"
            && event["payload_decoding"]["status"] == "decoded"
            && event["payload_decoding"]["process_id"] == target_pid
    }));
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
    assert!(events.iter().any(|event| {
        event["observation_decoding"]["status"] == "decoded"
            && event["observation_decoding"]["observation"]["activity"]["kind"] == "network"
            && event["observation_decoding"]["observation"]["activity"]["observation"]["payload_process_id"] == target_pid
            && event["observation_decoding"]["observation"]["activity"]["observation"]["destination_address"]["v4"] == serde_json::json!([127, 0, 0, 1])
            && event["observation_decoding"]["observation"]["activity"]["observation"]["destination_port"] == port
    }), "capture did not include the fixture's loopback network event with payload PID");
    fs::remove_file(fixture_file).unwrap();
    fs::remove_file(output).unwrap();
    fs::remove_dir(directory).unwrap();
}
