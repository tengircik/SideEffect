use super::model::{
    INVENTORY_SCHEMA, INVENTORY_SCHEMA_VERSION, InventoryDiagnostic, InventoryDocument,
    InventoryEvidence, InventoryPackage, InventorySource, InventorySourceStatus, InventoryStatus,
};
use crate::fingerprint::sha256_hex;
use crate::limits::{
    MAX_INVENTORY_ROW_BYTES, MAX_INVENTORY_ROWS, MAX_INVENTORY_STDERR_BYTES,
    MAX_INVENTORY_STDOUT_BYTES,
};
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DPKG_QUERY_PATH: &str = "/usr/bin/dpkg-query";
const DPKG_QUERY_FORMAT: &str =
    "${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\n";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Run the fixed, read-only dpkg query and return a bounded point-in-time snapshot.
/// No user input is passed to the child process and no privilege escalation is attempted.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn collect_debian_packages() -> InventoryDocument {
    let captured_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let mut document = empty_document(captured_at_unix_ms);

    let mut command = Command::new(DPKG_QUERY_PATH);
    command
        .arg("-W")
        .arg("-f")
        .arg(DPKG_QUERY_FORMAT)
        // Clear dpkg and shell-related redirection variables (including DPKG_ADMINDIR,
        // DPKG_ROOT, DPKG_PAGER, PAGER, and SHELL) before invoking the fixed binary.
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let (status, code) = if error.kind() == io::ErrorKind::NotFound {
                (InventorySourceStatus::Unavailable, "source_unavailable")
            } else if error.kind() == io::ErrorKind::PermissionDenied {
                (InventorySourceStatus::AccessDenied, "source_access_denied")
            } else {
                (InventorySourceStatus::Failed, "source_start_failed")
            };
            set_source_failure(&mut document, status, code);
            return document;
        }
    };

    let Some(stdout) = child.stdout.take() else {
        set_source_failure(
            &mut document,
            InventorySourceStatus::Failed,
            "stdout_unavailable",
        );
        let _ = child.kill();
        let _ = child.wait();
        return document;
    };
    let Some(stderr) = child.stderr.take() else {
        set_source_failure(
            &mut document,
            InventorySourceStatus::Failed,
            "stderr_unavailable",
        );
        let _ = child.kill();
        let _ = child.wait();
        return document;
    };

    let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
    let stdout_thread = thread::spawn(move || {
        let result = read_capped(stdout, MAX_INVENTORY_STDOUT_BYTES);
        let _ = stdout_tx.send(result);
    });
    let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
    let stderr_thread = thread::spawn(move || {
        let result = read_capped(stderr, MAX_INVENTORY_STDERR_BYTES);
        let _ = stderr_tx.send(result);
    });

    let started = Instant::now();
    let mut status = None;
    let mut timed_out = false;
    let mut output_exceeded = false;
    let mut stderr_exceeded = false;
    let mut stdout_read_failed = false;
    let mut stderr_read_failed = false;
    let mut stdout_result = None;
    let mut stderr_result = None;
    while status.is_none() {
        if let Ok(result) = stdout_rx.try_recv() {
            output_exceeded = result.exceeded;
            stdout_read_failed = result.read_failed;
            stdout_result = Some(result);
        }
        if let Ok(result) = stderr_rx.try_recv() {
            stderr_exceeded = result.exceeded;
            stderr_read_failed = result.read_failed;
            stderr_result = Some(result);
        }
        if started.elapsed() >= COMMAND_TIMEOUT {
            timed_out = true;
            let _ = child.kill();
            status = child.wait().ok();
            break;
        }
        if output_exceeded || stderr_exceeded || stdout_read_failed || stderr_read_failed {
            let _ = child.kill();
        }
        match child.try_wait() {
            Ok(Some(exit_status)) => status = Some(exit_status),
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(_) => {
                let _ = child.kill();
                status = child.wait().ok();
                break;
            }
        }
    }
    if status.is_none() {
        let _ = child.kill();
        status = child.wait().ok();
    }

    let stdout_result = stdout_result.unwrap_or_else(|| {
        stdout_rx.recv().unwrap_or(ReadCapped {
            bytes: Vec::new(),
            exceeded: false,
            read_failed: true,
        })
    });
    let stderr_result = stderr_result.unwrap_or_else(|| {
        stderr_rx.recv().unwrap_or(ReadCapped {
            bytes: Vec::new(),
            exceeded: false,
            read_failed: true,
        })
    });
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();
    let stdout_bytes = stdout_result.bytes;
    let stderr_exceeded = stderr_result.exceeded;
    let stdout_exceeded = stdout_result.exceeded;
    stdout_read_failed |= stdout_result.read_failed;
    stderr_read_failed |= stderr_result.read_failed;

    let parsed = parse_dpkg_query_output(&stdout_bytes, captured_at_unix_ms);
    document = parsed;
    let exit_code = status.as_ref().and_then(|exit| exit.code());
    finalize_child_result(
        &mut document,
        ChildResult {
            exit_code,
            wait_completed: status.is_some(),
            timed_out,
            stdout_exceeded,
            stderr_exceeded,
            stdout_read_failed,
            stderr_read_failed,
        },
    );
    document
}

/// Parse bounded output from a synthetic fixture or a completed dpkg-query invocation.
/// Every captured source row is represented as a package record or a diagnostic record.
pub fn parse_dpkg_query_output(bytes: &[u8], captured_at_unix_ms: u128) -> InventoryDocument {
    let mut document = empty_document(captured_at_unix_ms);
    let source = &mut document.sources[0];
    let bounded_bytes = &bytes[..bytes.len().min(MAX_INVENTORY_STDOUT_BYTES)];
    let mut offset = 0usize;
    let mut line = 1usize;
    while offset < bounded_bytes.len() {
        if source.records_seen >= MAX_INVENTORY_ROWS {
            let remainder = &bounded_bytes[offset..];
            source.diagnostics.push(InventoryDiagnostic {
                code: "row_count_limit_exceeded",
                line: Some(line),
                byte_offset: Some(offset),
                byte_length: Some(remainder.len()),
                record_sha256: Some(sha256_hex(remainder)),
            });
            source.status = InventorySourceStatus::Partial;
            break;
        }

        let rest = &bounded_bytes[offset..];
        let newline = rest.iter().position(|byte| *byte == b'\n');
        let terminated = newline.is_some();
        let raw = &rest[..newline.unwrap_or(rest.len())];
        let record_offset = offset;
        let next_offset = offset + raw.len() + usize::from(terminated);
        source.records_seen += 1;

        if raw.len() > MAX_INVENTORY_ROW_BYTES {
            let package = malformed_row(raw, line, record_offset, "row_length_limit_exceeded");
            add_row_diagnostic(source, &package);
            document.packages.push(package);
            source.status = InventorySourceStatus::Partial;
        } else if !terminated {
            let package = malformed_row(raw, line, record_offset, "missing_line_terminator");
            add_row_diagnostic(source, &package);
            document.packages.push(package);
            source.status = InventorySourceStatus::Partial;
        } else if let Some((name, version, architecture, status_abbrev)) = parse_row(raw) {
            document.packages.push(InventoryPackage {
                name: Some(name),
                version: Some(version),
                architecture: Some(architecture),
                status_abbrev: Some(status_abbrev),
                evidence: evidence(raw, line, record_offset, true),
                diagnostic_code: None,
            });
        } else {
            let package = malformed_row(raw, line, record_offset, "malformed_source_row");
            add_row_diagnostic(source, &package);
            document.packages.push(package);
            source.status = InventorySourceStatus::Partial;
        }

        offset = next_offset;
        line += 1;
    }

    if bytes.len() > MAX_INVENTORY_STDOUT_BYTES {
        source.status = InventorySourceStatus::OutputLimitExceeded;
        source.diagnostics.push(InventoryDiagnostic {
            code: "stdout_limit_exceeded",
            line: None,
            byte_offset: Some(MAX_INVENTORY_STDOUT_BYTES),
            byte_length: Some(bytes.len() - MAX_INVENTORY_STDOUT_BYTES),
            record_sha256: None,
        });
    }

    if source.status == InventorySourceStatus::Complete {
        document.status = InventoryStatus::Complete;
    } else {
        document.status = InventoryStatus::Partial;
    }
    document
}

fn parse_row(raw: &[u8]) -> Option<(String, String, String, String)> {
    let fields = raw.split(|byte| *byte == b'\t').collect::<Vec<_>>();
    if fields.len() != 4
        || fields[0].is_empty()
        || fields[0].iter().any(|byte| !is_field_byte(*byte))
        || fields[1].iter().any(|byte| !is_field_byte(*byte))
        || fields[2].iter().any(|byte| !is_field_byte(*byte))
        || fields[3].len() != 3
        || fields[3]
            .iter()
            .any(|byte| !byte.is_ascii() || (*byte != b' ' && byte.is_ascii_control()))
    {
        return None;
    }
    Some((
        String::from_utf8(fields[0].to_vec()).ok()?,
        String::from_utf8(fields[1].to_vec()).ok()?,
        String::from_utf8(fields[2].to_vec()).ok()?,
        String::from_utf8(fields[3].to_vec()).ok()?,
    ))
}

fn is_field_byte(byte: u8) -> bool {
    byte.is_ascii() && !byte.is_ascii_control()
}

fn malformed_row(
    raw: &[u8],
    line: usize,
    byte_offset: usize,
    code: &'static str,
) -> InventoryPackage {
    InventoryPackage {
        name: None,
        version: None,
        architecture: None,
        status_abbrev: None,
        evidence: evidence(raw, line, byte_offset, false),
        diagnostic_code: Some(code),
    }
}

fn evidence(raw: &[u8], line: usize, byte_offset: usize, valid_row: bool) -> InventoryEvidence {
    InventoryEvidence {
        line,
        byte_offset,
        byte_length: raw.len(),
        record_sha256: sha256_hex(raw),
        raw_record: valid_row
            .then(|| String::from_utf8(raw.to_vec()).expect("validated ASCII row")),
        raw_record_hex: (!valid_row).then(|| encode_hex(raw)),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    encoded
}

fn empty_document(captured_at_unix_ms: u128) -> InventoryDocument {
    InventoryDocument {
        schema: INVENTORY_SCHEMA,
        schema_version: INVENTORY_SCHEMA_VERSION,
        platform: "linux",
        scope: "debian_package_database",
        captured_at_unix_ms,
        status: InventoryStatus::Partial,
        sources: vec![InventorySource {
            id: "dpkg_query",
            status: InventorySourceStatus::Complete,
            exit_code: None,
            records_seen: 0,
            diagnostics: Vec::new(),
        }],
        packages: Vec::new(),
    }
}

fn diagnostic(code: &'static str) -> InventoryDiagnostic {
    InventoryDiagnostic {
        code,
        line: None,
        byte_offset: None,
        byte_length: None,
        record_sha256: None,
    }
}

fn add_row_diagnostic(source: &mut InventorySource, package: &InventoryPackage) {
    source.diagnostics.push(InventoryDiagnostic {
        code: package.diagnostic_code.expect("row diagnostic code"),
        line: Some(package.evidence.line),
        byte_offset: Some(package.evidence.byte_offset),
        byte_length: Some(package.evidence.byte_length),
        record_sha256: Some(package.evidence.record_sha256.clone()),
    });
}

fn set_source_failure(
    document: &mut InventoryDocument,
    status: InventorySourceStatus,
    code: &'static str,
) {
    document.sources[0].status = status;
    document.sources[0].diagnostics.push(diagnostic(code));
    document.status = InventoryStatus::Partial;
}

struct ChildResult {
    exit_code: Option<i32>,
    wait_completed: bool,
    timed_out: bool,
    stdout_exceeded: bool,
    stderr_exceeded: bool,
    stdout_read_failed: bool,
    stderr_read_failed: bool,
}

fn finalize_child_result(document: &mut InventoryDocument, result: ChildResult) {
    let source = &mut document.sources[0];
    source.exit_code = result.exit_code;
    if result.timed_out {
        source.status = InventorySourceStatus::TimedOut;
        source.diagnostics.push(diagnostic("source_timed_out"));
    }
    if result.stdout_exceeded || result.stderr_exceeded {
        source.status = InventorySourceStatus::OutputLimitExceeded;
        if result.stdout_exceeded {
            source.diagnostics.push(diagnostic("stdout_limit_exceeded"));
        }
        if result.stderr_exceeded {
            source.diagnostics.push(diagnostic("stderr_limit_exceeded"));
        }
    }
    if result.stdout_read_failed || result.stderr_read_failed {
        source.status = InventorySourceStatus::Failed;
        if result.stdout_read_failed {
            source.diagnostics.push(diagnostic("stdout_read_failed"));
        }
        if result.stderr_read_failed {
            source.diagnostics.push(diagnostic("stderr_read_failed"));
        }
    }
    if !result.timed_out && !result.wait_completed {
        source.status = InventorySourceStatus::Failed;
        source.diagnostics.push(diagnostic("child_wait_failed"));
    } else if !result.timed_out && result.wait_completed && result.exit_code != Some(0) {
        if source.status == InventorySourceStatus::Complete {
            source.status = InventorySourceStatus::Partial;
        }
        let code = if result.exit_code.is_none() {
            "source_signal_exit"
        } else {
            "source_nonzero_exit"
        };
        source.diagnostics.push(diagnostic(code));
    }
    if source.status == InventorySourceStatus::Complete
        && source.diagnostics.is_empty()
        && result.exit_code == Some(0)
        && result.wait_completed
    {
        document.status = InventoryStatus::Complete;
    } else {
        document.status = InventoryStatus::Partial;
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ReadCapped {
    bytes: Vec<u8>,
    exceeded: bool,
    read_failed: bool,
}

fn read_capped<R: Read>(reader: R, limit: usize) -> ReadCapped {
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    let mut reader = reader.take(limit.saturating_add(1) as u64);
    let read_result = reader.read_to_end(&mut bytes);
    let exceeded = bytes.len() > limit;
    bytes.truncate(limit);
    ReadCapped {
        bytes,
        exceeded,
        read_failed: read_result.is_err(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{InventorySourceStatus, InventoryStatus};
    use super::{
        ChildResult, ReadCapped, finalize_child_result, parse_dpkg_query_output, read_capped,
    };
    use std::io::{self, Cursor, Read};

    #[test]
    fn capped_reader_accepts_exact_limit_and_detects_limit_plus_one() {
        assert_eq!(
            read_capped(Cursor::new(b"12345"), 5),
            ReadCapped {
                bytes: b"12345".to_vec(),
                exceeded: false,
                read_failed: false,
            }
        );
        assert_eq!(
            read_capped(Cursor::new(b"123456"), 5),
            ReadCapped {
                bytes: b"12345".to_vec(),
                exceeded: true,
                read_failed: false,
            }
        );
    }

    #[test]
    fn capped_reader_reports_read_errors_separately_from_limit_exceeded() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("synthetic read failure"))
            }
        }

        let result = read_capped(FailingReader, 5);
        assert!(result.read_failed);
        assert!(!result.exceeded);
        assert!(result.bytes.is_empty());
    }

    #[test]
    fn unsuccessful_exit_signal_and_wait_failure_never_report_complete_source() {
        let mut nonzero = parse_dpkg_query_output(b"pkg\t1\tall\tii \n", 1);
        finalize_child_result(
            &mut nonzero,
            ChildResult {
                exit_code: Some(23),
                wait_completed: true,
                timed_out: false,
                stdout_exceeded: false,
                stderr_exceeded: false,
                stdout_read_failed: false,
                stderr_read_failed: false,
            },
        );
        assert_eq!(nonzero.sources[0].status, InventorySourceStatus::Partial);
        assert_eq!(nonzero.status, InventoryStatus::Partial);
        assert_eq!(nonzero.packages.len(), 1);

        let mut signaled = parse_dpkg_query_output(b"pkg\t1\tall\tii \n", 1);
        finalize_child_result(
            &mut signaled,
            ChildResult {
                exit_code: None,
                wait_completed: true,
                timed_out: false,
                stdout_exceeded: false,
                stderr_exceeded: false,
                stdout_read_failed: false,
                stderr_read_failed: false,
            },
        );
        assert_eq!(signaled.sources[0].status, InventorySourceStatus::Partial);
        assert_eq!(signaled.status, InventoryStatus::Partial);
        assert_eq!(
            signaled.sources[0].diagnostics[0].code,
            "source_signal_exit"
        );

        let mut wait_failed = parse_dpkg_query_output(b"pkg\t1\tall\tii \n", 1);
        finalize_child_result(
            &mut wait_failed,
            ChildResult {
                exit_code: None,
                wait_completed: false,
                timed_out: false,
                stdout_exceeded: false,
                stderr_exceeded: false,
                stdout_read_failed: false,
                stderr_read_failed: false,
            },
        );
        assert_eq!(wait_failed.sources[0].status, InventorySourceStatus::Failed);
        assert_eq!(wait_failed.status, InventoryStatus::Partial);
        assert_eq!(wait_failed.packages.len(), 1);

        let mut read_failed = parse_dpkg_query_output(b"pkg\t1\tall\tii \n", 1);
        finalize_child_result(
            &mut read_failed,
            ChildResult {
                exit_code: Some(0),
                wait_completed: true,
                timed_out: false,
                stdout_exceeded: false,
                stderr_exceeded: false,
                stdout_read_failed: true,
                stderr_read_failed: false,
            },
        );
        assert_eq!(read_failed.sources[0].status, InventorySourceStatus::Failed);
        assert_eq!(read_failed.status, InventoryStatus::Partial);
        assert_eq!(
            read_failed.sources[0].diagnostics[0].code,
            "stdout_read_failed"
        );
    }
}
