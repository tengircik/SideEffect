use super::model::{
    INVENTORY_SCHEMA, INVENTORY_SCHEMA_VERSION, InventoryDiagnostic, InventoryDocument,
    InventoryEvidence, InventoryPackage, InventorySource, InventorySourceStatus, InventoryStatus,
};
use crate::fingerprint::sha256_hex;
use crate::limits::{
    MAX_INVENTORY_ROW_BYTES, MAX_INVENTORY_ROWS, MAX_INVENTORY_STDERR_BYTES,
    MAX_INVENTORY_STDOUT_BYTES,
};
use std::collections::HashMap;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum PackageSourceKind {
    Dpkg,
    Rpm,
    Pacman,
    Apk,
    Flatpak,
}

pub(crate) struct PackageSourceRun {
    pub(crate) document: InventoryDocument,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) stdout_bytes: usize,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) stderr_bytes: usize,
}

pub(crate) struct PackageSourceConfig {
    pub(crate) id: &'static str,
    pub(crate) executable: &'static str,
    pub(crate) args: &'static [&'static str],
    pub(crate) kind: PackageSourceKind,
    pub(crate) stdout_limit: usize,
    pub(crate) stderr_limit: usize,
    pub(crate) row_limit: usize,
    pub(crate) timeout: Duration,
}

pub(crate) fn current_time_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// Run the fixed, read-only dpkg query and return a bounded point-in-time snapshot.
/// No user input is passed to the child process and no privilege escalation is attempted.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn collect_debian_packages() -> InventoryDocument {
    collect_package_source(
        PackageSourceConfig {
            id: "dpkg_query",
            executable: "/usr/bin/dpkg-query",
            args: &[
                "-W",
                "-f",
                "${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\n",
            ],
            kind: PackageSourceKind::Dpkg,
            stdout_limit: MAX_INVENTORY_STDOUT_BYTES,
            stderr_limit: MAX_INVENTORY_STDERR_BYTES,
            row_limit: MAX_INVENTORY_ROWS,
            timeout: COMMAND_TIMEOUT,
        },
        current_time_unix_ms(),
    )
    .document
}

pub(crate) fn collect_package_source(
    config: PackageSourceConfig,
    captured_at_unix_ms: u128,
) -> PackageSourceRun {
    let PackageSourceConfig {
        id: source_id,
        executable,
        args,
        kind,
        stdout_limit,
        stderr_limit,
        row_limit,
        timeout: command_timeout,
    } = config;
    let mut document = empty_document(source_id, captured_at_unix_ms);

    let mut command = Command::new(executable);
    command
        .args(args)
        // Clear dpkg and shell-related redirection variables (including DPKG_ADMINDIR,
        // DPKG_ROOT, DPKG_PAGER, PAGER, and SHELL) before invoking fixed package tools.
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
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
            return PackageSourceRun {
                document,
                stdout_bytes: 0,
                stderr_bytes: 0,
            };
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
        return PackageSourceRun {
            document,
            stdout_bytes: 0,
            stderr_bytes: 0,
        };
    };
    let Some(stderr) = child.stderr.take() else {
        set_source_failure(
            &mut document,
            InventorySourceStatus::Failed,
            "stderr_unavailable",
        );
        let _ = child.kill();
        let _ = child.wait();
        return PackageSourceRun {
            document,
            stdout_bytes: 0,
            stderr_bytes: 0,
        };
    };

    let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
    let stdout_thread = thread::spawn(move || {
        let result = read_capped(stdout, stdout_limit);
        let _ = stdout_tx.send(result);
    });
    let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
    let stderr_thread = thread::spawn(move || {
        let result = read_capped(stderr, stderr_limit);
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
        if started.elapsed() >= command_timeout {
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
    let stderr_bytes_read = stderr_result.bytes.len();
    let stderr_exceeded = stderr_result.exceeded;
    let stdout_exceeded = stdout_result.exceeded;
    stdout_read_failed |= stdout_result.read_failed;
    stderr_read_failed |= stderr_result.read_failed;

    let stdout_bytes_read = stdout_bytes.len();
    let parsed = parse_package_source_output(
        source_id,
        kind,
        &stdout_bytes,
        captured_at_unix_ms,
        stdout_limit,
        row_limit,
    );
    document = parsed;
    let exit_code = status.as_ref().and_then(|exit| exit.code());
    finalize_child_result(
        &mut document,
        ChildResult {
            exit_code,
            wait_completed: status.is_some(),
            timed_out,
            stdout_exceeded,
            stderr_bytes_read,
            stderr_exceeded,
            stdout_read_failed,
            stderr_read_failed,
        },
    );
    PackageSourceRun {
        document,
        stdout_bytes: stdout_bytes_read,
        stderr_bytes: stderr_bytes_read,
    }
}

/// Parse bounded output from a synthetic fixture or a completed dpkg-query invocation.
/// Every captured source row is represented as a package record or a diagnostic record.
pub fn parse_dpkg_query_output(bytes: &[u8], captured_at_unix_ms: u128) -> InventoryDocument {
    parse_package_source_output(
        "dpkg_query",
        PackageSourceKind::Dpkg,
        bytes,
        captured_at_unix_ms,
        MAX_INVENTORY_STDOUT_BYTES,
        MAX_INVENTORY_ROWS,
    )
}

pub(crate) fn parse_package_source_output(
    source_id: &'static str,
    kind: PackageSourceKind,
    bytes: &[u8],
    captured_at_unix_ms: u128,
    stdout_limit: usize,
    row_limit: usize,
) -> InventoryDocument {
    if kind == PackageSourceKind::Flatpak {
        return parse_flatpak_refs(
            source_id,
            bytes,
            captured_at_unix_ms,
            stdout_limit,
            row_limit,
        );
    }
    let mut document = empty_document(source_id, captured_at_unix_ms);
    let source = &mut document.sources[0];
    let bounded_bytes = &bytes[..bytes.len().min(stdout_limit)];
    let mut offset = 0usize;
    let mut line = 1usize;
    while offset < bounded_bytes.len() {
        if source.records_seen >= row_limit {
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
            let package = malformed_row(
                source_id,
                raw,
                line,
                record_offset,
                "row_length_limit_exceeded",
            );
            add_row_diagnostic(source, &package);
            document.packages.push(package);
            source.status = InventorySourceStatus::Partial;
        } else if !terminated {
            let package = malformed_row(
                source_id,
                raw,
                line,
                record_offset,
                "missing_line_terminator",
            );
            add_row_diagnostic(source, &package);
            document.packages.push(package);
            source.status = InventorySourceStatus::Partial;
        } else if let Some((name, version, architecture, status_abbrev)) = parse_row(kind, raw) {
            document.packages.push(InventoryPackage {
                source_id,
                name: Some(name),
                version: Some(version),
                architecture,
                status_abbrev,
                evidence: evidence(raw, line, record_offset, true),
                diagnostic_code: None,
            });
        } else {
            let package =
                malformed_row(source_id, raw, line, record_offset, "malformed_source_row");
            add_row_diagnostic(source, &package);
            document.packages.push(package);
            source.status = InventorySourceStatus::Partial;
        }

        offset = next_offset;
        line += 1;
    }

    if bytes.len() > stdout_limit {
        source.status = InventorySourceStatus::OutputLimitExceeded;
        source.diagnostics.push(InventoryDiagnostic {
            code: "stdout_limit_exceeded",
            line: None,
            byte_offset: Some(stdout_limit),
            byte_length: Some(bytes.len() - stdout_limit),
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

/// Parse the documented single-column `flatpak list --columns=ref` output.
/// The header and every reference are checked strictly; repeated refs remain as separate,
/// ambiguous rows because this output does not identify their installation.
fn parse_flatpak_refs(
    source_id: &'static str,
    bytes: &[u8],
    captured_at_unix_ms: u128,
    stdout_limit: usize,
    row_limit: usize,
) -> InventoryDocument {
    let mut document = empty_document(source_id, captured_at_unix_ms);
    let source = &mut document.sources[0];
    let bounded_bytes = &bytes[..bytes.len().min(stdout_limit)];
    let mut offset = 0usize;
    let mut line = 1usize;
    let mut header_seen = false;
    let mut first_ref_rows = HashMap::<String, usize>::new();

    while offset < bounded_bytes.len() {
        let rest = &bounded_bytes[offset..];
        let newline = rest.iter().position(|byte| *byte == b'\n');
        let terminated = newline.is_some();
        let raw = &rest[..newline.unwrap_or(rest.len())];
        let record_offset = offset;
        let next_offset = offset + raw.len() + usize::from(terminated);

        if !header_seen {
            header_seen = true;
            if raw == b"Ref" && terminated {
                offset = next_offset;
                line += 1;
                continue;
            }
            source.diagnostics.push(InventoryDiagnostic {
                code: "flatpak_header_missing_or_malformed",
                line: Some(line),
                byte_offset: Some(record_offset),
                byte_length: Some(raw.len()),
                record_sha256: Some(sha256_hex(raw)),
            });
            source.status = InventorySourceStatus::Partial;
        }

        if source.records_seen >= row_limit {
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
        source.records_seen += 1;

        if raw.len() > MAX_INVENTORY_ROW_BYTES {
            let package = malformed_row(
                source_id,
                raw,
                line,
                record_offset,
                "row_length_limit_exceeded",
            );
            add_row_diagnostic(source, &package);
            document.packages.push(package);
            source.status = InventorySourceStatus::Partial;
        } else if !terminated {
            let package = malformed_row(
                source_id,
                raw,
                line,
                record_offset,
                "missing_line_terminator",
            );
            add_row_diagnostic(source, &package);
            document.packages.push(package);
            source.status = InventorySourceStatus::Partial;
        } else if let Some(reference) = parse_flatpak_ref(raw) {
            let mut package = InventoryPackage {
                source_id,
                name: Some(reference.clone()),
                version: None,
                architecture: None,
                status_abbrev: None,
                evidence: evidence(raw, line, record_offset, true),
                diagnostic_code: None,
            };
            if let Some(first_index) = first_ref_rows.get(&reference).copied() {
                let first = &mut document.packages[first_index];
                if first.diagnostic_code.is_none() {
                    first.diagnostic_code = Some("duplicate_ref_ambiguous");
                    add_row_diagnostic(source, first);
                }
                package.diagnostic_code = Some("duplicate_ref_ambiguous");
                add_row_diagnostic(source, &package);
                source.status = InventorySourceStatus::Partial;
            } else {
                first_ref_rows.insert(reference, document.packages.len());
            }
            document.packages.push(package);
        } else {
            let package =
                malformed_row(source_id, raw, line, record_offset, "malformed_flatpak_ref");
            add_row_diagnostic(source, &package);
            document.packages.push(package);
            source.status = InventorySourceStatus::Partial;
        }

        offset = next_offset;
        line += 1;
    }

    if !header_seen {
        source.status = InventorySourceStatus::Partial;
        source.diagnostics.push(diagnostic("flatpak_output_empty"));
    }
    if bytes.len() > stdout_limit {
        source.status = InventorySourceStatus::OutputLimitExceeded;
        source.diagnostics.push(InventoryDiagnostic {
            code: "stdout_limit_exceeded",
            line: None,
            byte_offset: Some(stdout_limit),
            byte_length: Some(bytes.len() - stdout_limit),
            record_sha256: None,
        });
    }
    document.status = if source.status == InventorySourceStatus::Complete {
        InventoryStatus::Complete
    } else {
        InventoryStatus::Partial
    };
    document
}

fn parse_flatpak_ref(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || !raw.is_ascii() || raw.iter().any(|byte| !byte.is_ascii_graphic()) {
        return None;
    }
    let reference = std::str::from_utf8(raw).ok()?;
    let mut parts = reference.split('/');
    let kind = parts.next()?;
    let app_id = parts.next()?;
    let arch = parts.next()?;
    let branch = parts.next()?;
    if !matches!(kind, "app" | "runtime")
        || !valid_ref_component(app_id)
        || !valid_ref_component(arch)
        || !valid_ref_component(branch)
        || parts.next().is_some()
    {
        return None;
    }
    Some(reference.to_owned())
}

fn valid_ref_component(component: &str) -> bool {
    !component.is_empty()
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

fn parse_row(
    kind: PackageSourceKind,
    raw: &[u8],
) -> Option<(String, String, Option<String>, Option<String>)> {
    match kind {
        PackageSourceKind::Dpkg => {
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
                utf8(fields[0])?,
                utf8(fields[1])?,
                Some(utf8(fields[2])?),
                Some(utf8(fields[3])?),
            ))
        }
        PackageSourceKind::Rpm => {
            let fields = raw.split(|byte| *byte == b'\t').collect::<Vec<_>>();
            if fields.len() != 4
                || fields[0].is_empty()
                || fields[1].is_empty()
                || fields[2].is_empty()
                || fields[3] != b"installed"
                || fields[..3]
                    .iter()
                    .any(|field| field.iter().any(|byte| !is_field_byte(*byte)))
            {
                return None;
            }
            Some((
                utf8(fields[0])?,
                utf8(fields[1])?,
                Some(utf8(fields[2])?),
                None,
            ))
        }
        PackageSourceKind::Pacman => {
            let separator = raw.iter().position(|byte| *byte == b' ')?;
            let (name, version_with_separator) = raw.split_at(separator);
            let version = &version_with_separator[1..];
            if name.is_empty()
                || version.is_empty()
                || version.contains(&b' ')
                || name.iter().chain(version).any(|byte| !is_field_byte(*byte))
            {
                return None;
            }
            Some((utf8(name)?, utf8(version)?, None, None))
        }
        PackageSourceKind::Apk => {
            let split = raw
                .windows(2)
                .rposition(|pair| pair[0] == b'-' && pair[1].is_ascii_digit())?;
            let name = &raw[..split];
            let version = &raw[split + 1..];
            if name.is_empty()
                || version.is_empty()
                || !version[0].is_ascii_digit()
                || !name[0].is_ascii_alphanumeric()
                || name.iter().any(|byte| {
                    !byte.is_ascii_alphanumeric() && !matches!(*byte, b'.' | b'_' | b'+' | b'-')
                })
                || version.iter().any(|byte| {
                    !byte.is_ascii_alphanumeric()
                        && !matches!(*byte, b'.' | b'_' | b'~' | b'-' | b'+')
                })
            {
                return None;
            }
            Some((utf8(name)?, utf8(version)?, None, None))
        }
        PackageSourceKind::Flatpak => None,
    }
}

fn utf8(bytes: &[u8]) -> Option<String> {
    String::from_utf8(bytes.to_vec()).ok()
}

fn is_field_byte(byte: u8) -> bool {
    byte.is_ascii() && !byte.is_ascii_control()
}

fn malformed_row(
    source_id: &'static str,
    raw: &[u8],
    line: usize,
    byte_offset: usize,
    code: &'static str,
) -> InventoryPackage {
    InventoryPackage {
        source_id,
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

fn empty_document(source_id: &'static str, captured_at_unix_ms: u128) -> InventoryDocument {
    InventoryDocument {
        schema: INVENTORY_SCHEMA,
        schema_version: INVENTORY_SCHEMA_VERSION,
        platform: "linux",
        scope: "available_package_manager_databases",
        captured_at_unix_ms,
        status: InventoryStatus::Partial,
        sources: vec![InventorySource {
            id: source_id,
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
    stderr_bytes_read: usize,
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
    if result.stderr_bytes_read > 0 && !result.stderr_exceeded {
        source.status = InventorySourceStatus::Partial;
        source
            .diagnostics
            .push(diagnostic("source_stderr_nonempty"));
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
                stderr_bytes_read: 0,
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
                stderr_bytes_read: 0,
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
                stderr_bytes_read: 0,
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
                stderr_bytes_read: 0,
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
