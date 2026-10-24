use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempTrace(std::path::PathBuf);

impl TempTrace {
    fn with_contents(contents: &[u8]) -> Self {
        loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-inspect-cli-{}-{id}.trace",
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(contents).unwrap();
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create temporary trace: {error}"),
            }
        }
    }
}

impl Drop for TempTrace {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn inspect_defaults_to_versioned_json() {
    let trace = TempTrace::with_contents(
        b"123 1700000000.123456 openat(AT_FDCWD</tmp/work>, \"file.txt\", O_RDONLY) = 3\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("inspect")
        .arg(&trace.0)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schema_version"], 2);
    assert_eq!(document["parse_status"], "complete");
    assert_eq!(
        document["records"][0]["raw_arguments"],
        "AT_FDCWD</tmp/work>, \"file.txt\", O_RDONLY"
    );
    assert_eq!(
        document["records"][0]["lexical_path_hint"]["path"],
        "/tmp/work/file.txt"
    );
    assert_eq!(
        document["records"][0]["lexical_path_hint"]["basis"],
        "at_fdcwd_annotation"
    );
}

#[test]
fn inspect_text_discloses_the_basis_of_a_lexical_path_hint() {
    let trace = TempTrace::with_contents(
        b"123 1700000000.123456 openat(AT_FDCWD</tmp/work>, \"assets/icon.svg\", O_RDONLY) = 4\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inspect", "--format", "text"])
        .arg(&trace.0)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Lexical path hint: \"/tmp/work/assets/icon.svg\""));
    assert!(text.contains("Path hint basis: at_fdcwd_annotation"));
}

#[test]
fn inspect_text_shows_partial_status_every_record_and_diagnostics_safely() {
    let trace = TempTrace::with_contents(
        "write(1, \"ansi-\u{1b}[31m-bidi-\u{202e}-é\", 16) = 16\nnot a strace record\n".as_bytes(),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inspect", "--format", "text"])
        .arg(&trace.0)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_ascii());
    assert!(!output.stdout.contains(&0x1b));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Parse status: partial"));
    assert!(text.contains("Kind: syscall"));
    assert!(text.contains("Arguments: \"1, \\\"ansi-\\u{1B}[31m-bidi-\\u{202E}-\\u{E9}\\\", 16\""));
    assert!(text.contains("Kind: unparsed"));
    assert!(text.contains("Raw line: \"not a strace record\""));
    assert!(text.contains("Diagnostics: 1"));
    assert!(text.contains("Code: \"unsupported_record\""));
}

#[test]
fn inspect_rejects_unknown_format_before_reading_a_path() {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inspect", "--format", "xml", "missing.trace"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("inspect format must be either"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("could not inspect trace input"));
}
