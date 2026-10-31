use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TempJson(std::path::PathBuf);
impl TempJson {
    fn new(value: &serde_json::Value) -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sideeffect-permission-diff-{}-{id}.json",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create synthetic permission inventory");
        file.write_all(value.to_string().as_bytes())
            .expect("write synthetic permission inventory");
        Self(path)
    }
}
impl Drop for TempJson {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn run(before: &serde_json::Value, after: &serde_json::Value) -> Output {
    let before = TempJson::new(before);
    let after = TempJson::new(after);
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(&before.0)
        .arg(&after.0)
        .output()
        .expect("run permission inventory diff")
}

fn linux_row(mode: u32) -> serde_json::Value {
    serde_json::json!({
        "path":"/tmp/permission-fixture", "path_bytes_hex":"2f746d702f7065726d697373696f6e2d66697874757265",
        "status":"complete", "object_type":"regular_file", "uid":1000, "gid":1000,
        "mode":mode, "device":1, "inode":2,
        "access_acl":{"status":"absent","source":"fgetxattr/system.posix_acl_access"},
        "default_acl":{"status":"not_applicable","source":"fgetxattr/system.posix_acl_default"},
        "file_capability":{"status":"absent","source":"fgetxattr/security.capability"}, "diagnostics":[]
    })
}
fn linux(mode: u32) -> serde_json::Value {
    serde_json::json!({
        "schema":"sideeffect.permission_inventory","schema_version":1,"platform":"linux",
        "scope":"explicit_paths_metadata_posix_acl_file_capability","captured_at_unix_ms":100,
        "status":"complete","paths_requested":1,"acl_bytes_read":0,"capability_bytes_read":0,
        "objects":[linux_row(mode)],"diagnostics":[]
    })
}

fn windows_row(size: u64) -> serde_json::Value {
    let mut descriptor = [0_u8; 20];
    descriptor[0] = 1;
    descriptor[3] = 0x80;
    let digest = Sha256::digest(descriptor);
    let digest_hex = lower_hex(&digest);
    serde_json::json!({
        "path":"C:\\permission-fixture.txt","path_utf16_hex":"43003a005c007000650072006d0069007300730069006f006e002d0066006900780074007500720065002e00740078007400",
        "status":"complete",
        "metadata":{"attributes":32,"is_directory":false,"is_reparse_point":false,"volume_serial_number":1,"file_index":2,"size_bytes":size,"last_write_filetime":100},
        "security":{"descriptor_length":20,"descriptor_sha256":digest_hex,"descriptor_raw_hex":"0100008000000000000000000000000000000000","control":32768,"owner_sid_raw_hex":null,"group_sid_raw_hex":null,"dacl_state":"absent","dacl_protected":false,"dacl_auto_inherited":false,"aces":[],"parse_diagnostic":null},
        "diagnostic":null
    })
}
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0xf) as usize] as char);
    }
    output
}
fn windows(size: u64) -> serde_json::Value {
    serde_json::json!({
        "schema":"sideeffect.windows_permission_inventory","schema_version":1,"platform":"windows",
        "scope":"explicit_paths_only; final_reparse_points_opened_without_following; no_sacl; no_effective_access_calculation",
        "capture_started_at_unix_ms":100,"capture_ended_at_unix_ms":101,"status":"complete",
        "objects":[windows_row(size)],"diagnostics":[],
        "limits":{"max_paths":256,"max_utf16_units_per_path":32767,"max_total_path_utf16_units":1048576,"max_descriptor_bytes":65536,"max_aces_per_descriptor":1024,"max_aggregate_descriptor_bytes":8388608,"deadline_ms_between_paths":5000}
    })
}

#[test]
fn linux_selected_path_permission_change_routes_through_cli() {
    let output = run(&linux(0o640), &linux(0o600));
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "sideeffect.permission_inventory_diff");
    assert_eq!(report["platform"], "linux");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["counts"]["changes"], 1);
    assert_eq!(report["deltas"][0]["changed_fields"][0], "mode");
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .find("\"bytes_hex\"")
            .is_none()
    );
}

#[test]
fn windows_selected_path_permission_change_routes_through_cli_without_raw_descriptor() {
    let output = run(&windows(10), &windows(11));
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "sideeffect.permission_inventory_diff");
    assert_eq!(report["platform"], "windows");
    assert_eq!(report["counts"]["changes"], 1);
    assert_eq!(report["deltas"][0]["changed_fields"][0], "metadata");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("\"descriptor_raw_hex\""));
    assert!(!stdout.contains("\"raw_hex\""));
}
