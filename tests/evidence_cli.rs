use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use sideeffect::limits::{MAX_TRACE_BYTES, ParseLimits};
use sideeffect::trace::strace::parse_trace_bytes;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempTrace(std::path::PathBuf);

impl TempTrace {
    fn with_contents(contents: &[u8]) -> Self {
        loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-evidence-cli-{}-{id}.trace",
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

    fn oversized() -> Self {
        loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-evidence-cli-{}-{id}.trace",
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    file.set_len((MAX_TRACE_BYTES as u64) + 1).unwrap();
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create oversized temporary trace: {error}"),
            }
        }
    }
}

impl Drop for TempTrace {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn run_evidence(
    path: &std::path::Path,
    line: &str,
    byte_offset: &str,
    byte_length: &str,
) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["evidence"])
        .arg(path)
        .args([line, byte_offset, byte_length])
        .output()
        .unwrap()
}

fn first_reference(contents: &[u8]) -> sideeffect::model::EvidenceReference {
    parse_trace_bytes(contents, ParseLimits::default())
        .unwrap()
        .records[0]
        .evidence
        .clone()
}

#[test]
fn resolves_a_diff_reference_to_one_parsed_row() {
    let contents = b"7 1700000000.000001 openat(AT_FDCWD</tmp>, \"item.txt\", O_RDONLY) = 3\n";
    let trace = TempTrace::with_contents(contents);
    let reference = first_reference(contents);
    let output = run_evidence(
        &trace.0,
        &reference.line_number.to_string(),
        &reference.byte_offset.to_string(),
        &reference.byte_length.to_string(),
    );

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_ascii());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("SideEffect evidence lookup\nParse status: complete"));
    assert!(text.contains(&format!(
        "Reference: line={} byte={} length={}",
        reference.line_number, reference.byte_offset, reference.byte_length
    )));
    assert!(text.contains("Kind: syscall"));
    assert!(text.contains("Syscall: \"openat\""));
    assert!(text.contains("Raw line: \"7 1700000000.000001 openat("));
    assert!(text.contains("no content hash or capture completeness is established"));
}

#[test]
fn rejects_a_reference_whose_offset_or_length_does_not_match() {
    let contents = b"1 1700000000.000001 close(3) = 0\n";
    let trace = TempTrace::with_contents(contents);
    let reference = first_reference(contents);
    let output = run_evidence(
        &trace.0,
        &reference.line_number.to_string(),
        &(reference.byte_offset + 1).to_string(),
        &reference.byte_length.to_string(),
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("reference mismatch"));
}

#[test]
fn rejects_out_of_range_control_and_unparsed_references() {
    let trace = TempTrace::with_contents(b"+++ exited with 0 +++\nnot a syscall record\n");
    let document = parse_trace_bytes(
        b"+++ exited with 0 +++\nnot a syscall record\n",
        ParseLimits::default(),
    )
    .unwrap();
    let control = &document.records[0].evidence;
    let output = run_evidence(
        &trace.0,
        &control.line_number.to_string(),
        &control.byte_offset.to_string(),
        &control.byte_length.to_string(),
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("control record"));

    let unparsed = &document.records[1].evidence;
    let output = run_evidence(
        &trace.0,
        &unparsed.line_number.to_string(),
        &unparsed.byte_offset.to_string(),
        &unparsed.byte_length.to_string(),
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("is unparsed"));

    let output = run_evidence(&trace.0, "99", "0", "1");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no trace record exists at line 99"));
}

#[test]
fn partial_input_labels_the_lookup_and_escapes_terminal_controls() {
    let contents =
        b"1 1700000000.000001 write(1, \"ansi-\x1b[31m\", 8) = 8\nnot a syscall record\n";
    let trace = TempTrace::with_contents(contents);
    let reference = first_reference(contents);
    let output = run_evidence(
        &trace.0,
        &reference.line_number.to_string(),
        &reference.byte_offset.to_string(),
        &reference.byte_length.to_string(),
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_ascii());
    assert!(!output.stdout.contains(&0x1b));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Parse status: partial"));
    assert!(text.contains("positional match in the supplied file"));
    assert!(text.contains("\\u{1B}[31m"));
}

#[test]
fn rejects_oversized_trace_before_producing_output() {
    let trace = TempTrace::oversized();
    let output = run_evidence(&trace.0, "1", "0", "1");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("trace input exceeds"));
}

#[test]
fn rejects_non_decimal_reference_fields() {
    let trace = TempTrace::with_contents(b"1 1700000000.000001 close(3) = 0\n");
    let output = run_evidence(&trace.0, "1", "0", "1x");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("byte length must be an ASCII decimal number")
    );
}
