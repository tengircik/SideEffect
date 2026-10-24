use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempFile(std::path::PathBuf);

impl TempFile {
    fn with_contents(suffix: &str, contents: &[u8]) -> Self {
        loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-summary-{}-{id}.{suffix}",
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(contents).unwrap();
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create temporary test file: {error}"),
            }
        }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn input_pair() -> (TempFile, TempFile) {
    let before = TempFile::with_contents(
        "before.trace",
        b"1 1700000000.000001 openat(AT_FDCWD, \"/private/sentinel/path\", O_RDONLY) = 3\n1 1700000000.000002 write(1, \"sentinel-secret-arg\", 19) = 19 (sentinel-result-token)\n",
    );
    let after = TempFile::with_contents(
        "after.trace",
        b"2 1700000001.000001 openat(AT_FDCWD, \"/private/sentinel/path\", O_WRONLY) = 4\n2 1700000001.000002 write(1, \"sentinel-secret-arg\", 19) = 18 (sentinel-result-token)\n",
    );
    (before, after)
}

fn summary_json(before: &TempFile, after: &TempFile) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff-summary", "--format", "json"])
        .arg(&before.0)
        .arg(&after.0)
        .output()
        .unwrap()
}

#[test]
fn summary_json_excludes_raw_strings_hashes_and_source_references() {
    let (before, after) = input_pair();
    let output = summary_json(&before, &after);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["schema"], "sideeffect_redacted_diff_summary");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["parse_status"], "complete");
    assert_eq!(json["capture_completeness"], "unknown");
    assert_eq!(json["disclosure"]["mode"], "category_group_counts_only");
    assert!(
        json["disclosure"]["warning"]
            .as_str()
            .unwrap()
            .contains("not a safe-to-share verdict")
    );

    let serialized = String::from_utf8(output.stdout).unwrap();
    for sentinel in [
        "sentinel-secret-arg",
        "/private/sentinel/path",
        "sentinel-result-token",
        before.0.to_str().unwrap(),
        after.0.to_str().unwrap(),
        "raw_arguments\":\"",
        "line_number",
        "byte_offset",
        "source_sha256\":\"",
    ] {
        assert!(!serialized.contains(sentinel), "summary leaked {sentinel}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn html_summary_is_bounded_private_and_does_not_clobber_existing_output() {
    use std::os::unix::fs::PermissionsExt;

    let (before, after) = input_pair();
    let report = TempFile::with_contents("summary.html", b"existing report");
    let original = fs::read(&report.0).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff-summary", "--format", "html", "--output"])
        .arg(&report.0)
        .arg(&before.0)
        .arg(&after.0)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(&report.0).unwrap(), original);

    let report = TempFile::with_contents("fresh.html", b"");
    fs::remove_file(&report.0).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff-summary", "--format", "html", "--output"])
        .arg(&report.0)
        .arg(&before.0)
        .arg(&after.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let permissions = fs::metadata(&report.0).unwrap().permissions();
    assert_eq!(permissions.mode() & 0o777, 0o600);
    let html = fs::read_to_string(&report.0).unwrap();
    assert!(html.contains("sideeffect_redacted_diff_summary"));
    assert!(html.contains("default-src 'none'"));
    assert!(html.contains("script-src 'none'"));
    assert!(html.contains("not a safe-to-share verdict"));
    for sentinel in [
        "sentinel-secret-arg",
        "/private/sentinel/path",
        "sentinel-result-token",
        before.0.to_str().unwrap(),
        after.0.to_str().unwrap(),
    ] {
        assert!(!html.contains(sentinel), "summary leaked {sentinel}");
    }
}
