//! Bounded snapshots from locally available Linux package-manager databases.

use super::debian::{
    PackageSourceConfig, PackageSourceKind, PackageSourceRun, collect_package_source,
    current_time_unix_ms,
};
use super::model::{
    INVENTORY_SCHEMA, INVENTORY_SCHEMA_VERSION, InventoryDiagnostic, InventoryDocument,
    InventorySource, InventorySourceStatus, InventoryStatus,
};
use crate::limits::{MAX_INVENTORY_ROWS, MAX_INVENTORY_STDOUT_BYTES};
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

const TOTAL_PACKAGE_SCAN_TIMEOUT: Duration = Duration::from_secs(20);

const UNSUPPORTED_ADAPTERS: [(&str, &[&str]); 5] = [
    ("xbps_query", &["/usr/bin/xbps-query", "/bin/xbps-query"]),
    (
        "nix",
        &[
            "/usr/bin/nix",
            "/bin/nix",
            "/nix/var/nix/profiles/default/bin/nix",
            "/run/current-system/sw/bin/nix",
        ],
    ),
    (
        "guix",
        &[
            "/usr/bin/guix",
            "/bin/guix",
            "/run/current-system/profile/bin/guix",
            "/var/guix/profiles/per-user/root/guix-profile/bin/guix",
        ],
    ),
    ("snap", &["/usr/bin/snap", "/bin/snap"]),
    ("flatpak", &["/usr/bin/flatpak", "/bin/flatpak"]),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageAdapter {
    id: &'static str,
    executable: &'static str,
    args: &'static [&'static str],
    kind: PackageSourceKind,
}

const ADAPTERS: [PackageAdapter; 4] = [
    PackageAdapter {
        id: "dpkg_query",
        executable: "/usr/bin/dpkg-query",
        args: &[
            "-W",
            "-f",
            "${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\n",
        ],
        kind: PackageSourceKind::Dpkg,
    },
    PackageAdapter {
        id: "rpm_query",
        executable: "/usr/bin/rpm",
        args: &[
            "-qa",
            "--queryformat",
            "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\tinstalled\\n",
        ],
        kind: PackageSourceKind::Rpm,
    },
    PackageAdapter {
        id: "pacman_query",
        executable: "/usr/bin/pacman",
        args: &["-Q"],
        kind: PackageSourceKind::Pacman,
    },
    PackageAdapter {
        id: "apk_info",
        executable: "/sbin/apk",
        // One verbose level prints package-version rows; `-vv` also prints descriptions.
        args: &["--network=no", "info", "-v"],
        kind: PackageSourceKind::Apk,
    },
];

/// Query each supported package-manager executable found at its fixed Linux path.
/// Missing tools are explicit `unavailable` sources, not empty successful snapshots.
pub fn collect_packages() -> InventoryDocument {
    let availability = ADAPTERS.map(|adapter| Path::new(adapter.executable).is_file());
    let unsupported =
        UNSUPPORTED_ADAPTERS.map(|(_, paths)| paths.iter().any(|path| Path::new(path).is_file()));
    let applicable = expected_package_managers(read_os_release());
    collect_packages_with(
        availability,
        unsupported,
        applicable,
        TOTAL_PACKAGE_SCAN_TIMEOUT,
        current_time_unix_ms(),
        |adapter, captured_at, bytes, stderr, rows, timeout| {
            collect_package_source(
                PackageSourceConfig {
                    id: adapter.id,
                    executable: adapter.executable,
                    args: adapter.args,
                    kind: adapter.kind,
                    stdout_limit: bytes,
                    stderr_limit: stderr,
                    row_limit: rows,
                    timeout,
                },
                captured_at,
            )
        },
    )
}

fn collect_packages_with<F>(
    availability: [bool; 4],
    unsupported_availability: [bool; 5],
    applicable: Option<[bool; 4]>,
    total_timeout: Duration,
    captured_at_unix_ms: u128,
    mut run: F,
) -> InventoryDocument
where
    F: FnMut(PackageAdapter, u128, usize, usize, usize, Duration) -> PackageSourceRun,
{
    let mut sources = Vec::with_capacity(ADAPTERS.len() + UNSUPPORTED_ADAPTERS.len());
    let mut packages = Vec::new();
    let mut bytes_remaining = MAX_INVENTORY_STDOUT_BYTES;
    let mut stderr_remaining = crate::limits::MAX_INVENTORY_STDERR_BYTES;
    let mut rows_remaining = MAX_INVENTORY_ROWS;
    let started = Instant::now();
    let mut available_count = 0usize;
    let mut available_sources_complete = true;
    let mut unsupported_found = false;

    for (unsupported_index, (id, _paths)) in UNSUPPORTED_ADAPTERS.iter().enumerate() {
        if unsupported_availability[unsupported_index] {
            unsupported_found = true;
            sources.push(InventorySource {
                id,
                status: InventorySourceStatus::Unsupported,
                exit_code: None,
                records_seen: 0,
                diagnostics: vec![InventoryDiagnostic {
                    code: "package_manager_adapter_unsupported",
                    line: None,
                    byte_offset: None,
                    byte_length: None,
                    record_sha256: None,
                }],
            });
        }
    }

    for (index, adapter) in ADAPTERS.iter().copied().enumerate() {
        if !availability[index] {
            sources.push(InventorySource {
                id: adapter.id,
                status: if applicable.is_some_and(|expected| !expected[index]) {
                    InventorySourceStatus::NotApplicable
                } else {
                    InventorySourceStatus::Unavailable
                },
                exit_code: None,
                records_seen: 0,
                diagnostics: vec![InventoryDiagnostic {
                    code: if applicable.is_some_and(|expected| !expected[index]) {
                        "package_manager_not_applicable_for_distribution"
                    } else {
                        "package_manager_executable_unavailable"
                    },
                    line: None,
                    byte_offset: None,
                    byte_length: None,
                    record_sha256: None,
                }],
            });
            if applicable.is_none_or(|expected| expected[index]) {
                available_sources_complete = false;
            }
            continue;
        }

        available_count += 1;
        let timeout_remaining = total_timeout.saturating_sub(started.elapsed());
        if bytes_remaining == 0 || rows_remaining == 0 || timeout_remaining.is_zero() {
            let (status, code) = if bytes_remaining == 0 || rows_remaining == 0 {
                (
                    InventorySourceStatus::NotChecked,
                    "not_checked_due_to_aggregate_inventory_limit",
                )
            } else {
                (
                    InventorySourceStatus::NotChecked,
                    "not_checked_due_to_aggregate_scan_deadline",
                )
            };
            sources.push(InventorySource {
                id: adapter.id,
                status,
                exit_code: None,
                records_seen: 0,
                diagnostics: vec![InventoryDiagnostic {
                    code,
                    line: None,
                    byte_offset: None,
                    byte_length: None,
                    record_sha256: None,
                }],
            });
            available_sources_complete = false;
            continue;
        }

        let run_result = run(
            adapter,
            captured_at_unix_ms,
            bytes_remaining,
            stderr_remaining,
            rows_remaining,
            timeout_remaining,
        );
        bytes_remaining = bytes_remaining.saturating_sub(run_result.stdout_bytes);
        stderr_remaining = stderr_remaining.saturating_sub(run_result.stderr_bytes);
        let source = run_result
            .document
            .sources
            .into_iter()
            .next()
            .unwrap_or(InventorySource {
                id: adapter.id,
                status: InventorySourceStatus::Failed,
                exit_code: None,
                records_seen: 0,
                diagnostics: vec![InventoryDiagnostic {
                    code: "package_source_result_missing",
                    line: None,
                    byte_offset: None,
                    byte_length: None,
                    record_sha256: None,
                }],
            });
        rows_remaining = rows_remaining.saturating_sub(source.records_seen);
        if source.status != InventorySourceStatus::Complete {
            available_sources_complete = false;
        }
        sources.push(source);
        packages.extend(run_result.document.packages);
    }

    InventoryDocument {
        schema: INVENTORY_SCHEMA,
        schema_version: INVENTORY_SCHEMA_VERSION,
        platform: "linux",
        scope: "available_package_manager_databases",
        captured_at_unix_ms,
        status: if available_count > 0 && available_sources_complete && !unsupported_found {
            InventoryStatus::Complete
        } else {
            InventoryStatus::Partial
        },
        sources,
        packages,
    }
}

/// Return a primary supported package ecosystem only for well-known distributions.
/// Unknown distributions stay conservative: absent tools remain unavailable and keep the
/// aggregate partial instead of implying that an unrecognized database was not applicable.
fn expected_package_managers(os_release: Option<Vec<String>>) -> Option<[bool; 4]> {
    let ids = os_release?;
    let mut expected = [false; 4]; // dpkg, rpm, pacman, apk
    for id in ids {
        match id.as_str() {
            "debian" | "ubuntu" | "linuxmint" | "pop" | "kali" | "raspbian" => expected[0] = true,
            "fedora"
            | "rhel"
            | "centos"
            | "rocky"
            | "almalinux"
            | "opensuse"
            | "opensuse-leap"
            | "opensuse-tumbleweed" => expected[1] = true,
            "arch" | "manjaro" | "endeavouros" => expected[2] = true,
            "alpine" => expected[3] = true,
            _ => {}
        }
    }
    expected
        .iter()
        .any(|is_expected| *is_expected)
        .then_some(expected)
}

fn read_os_release() -> Option<Vec<String>> {
    const MAX_OS_RELEASE_BYTES: usize = 16 * 1024;
    let file = std::fs::File::open("/etc/os-release").ok()?;
    let mut bytes = Vec::new();
    file.take((MAX_OS_RELEASE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_OS_RELEASE_BYTES || !bytes.is_ascii() {
        return None;
    }
    let mut ids = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        let Some(separator) = line.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let (key, value_with_separator) = line.split_at(separator);
        let value = &value_with_separator[1..];
        if key != b"ID" && key != b"ID_LIKE" {
            continue;
        }
        let value = value
            .strip_prefix(b"\"")
            .and_then(|v| v.strip_suffix(b"\""))
            .or_else(|| value.strip_prefix(b"'").and_then(|v| v.strip_suffix(b"'")))
            .unwrap_or(value);
        if value.iter().any(|byte| {
            !byte.is_ascii_alphanumeric()
                && *byte != b' '
                && *byte != b'-'
                && *byte != b'_'
                && *byte != b'.'
        }) {
            return None;
        }
        ids.extend(
            value
                .split(|byte| *byte == b' ' || *byte == b'_' || *byte == b'.')
                .filter(|part| !part.is_empty())
                .filter_map(|part| {
                    std::str::from_utf8(part)
                        .ok()
                        .map(|value| value.to_ascii_lowercase())
                }),
        );
    }
    Some(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::debian::{PackageSourceKind, parse_package_source_output};

    fn fixture_run(
        adapter: PackageAdapter,
        captured_at: u128,
        output: &[u8],
        status: InventorySourceStatus,
    ) -> PackageSourceRun {
        let mut document = parse_package_source_output(
            adapter.id,
            adapter.kind,
            output,
            captured_at,
            MAX_INVENTORY_STDOUT_BYTES,
            MAX_INVENTORY_ROWS,
        );
        document.sources[0].status = status;
        if status != InventorySourceStatus::Complete {
            document.status = InventoryStatus::Partial;
        }
        PackageSourceRun {
            document,
            stdout_bytes: output.len(),
            stderr_bytes: 0,
        }
    }

    #[test]
    fn only_available_sources_are_run_and_rows_keep_source_identity() {
        let availability = [true, false, true, false];
        let mut invoked = Vec::new();
        let document = collect_packages_with(
            availability,
            [false; 5],
            Some([true, false, true, false]),
            TOTAL_PACKAGE_SCAN_TIMEOUT,
            44,
            |adapter, at, _, _, _, _| {
                invoked.push(adapter.id);
                let output = match adapter.kind {
                    PackageSourceKind::Dpkg => b"one\t1\tall\tii \n".as_slice(),
                    PackageSourceKind::Pacman => b"two 2-1\n".as_slice(),
                    PackageSourceKind::Rpm | PackageSourceKind::Apk => unreachable!(),
                };
                fixture_run(adapter, at, output, InventorySourceStatus::Complete)
            },
        );

        assert_eq!(invoked, ["dpkg_query", "pacman_query"]);
        assert_eq!(document.status, InventoryStatus::Complete);
        assert_eq!(document.sources.len(), 4);
        assert_eq!(document.sources[0].status, InventorySourceStatus::Complete);
        assert_eq!(
            document.sources[1].status,
            InventorySourceStatus::NotApplicable
        );
        assert_eq!(
            document.sources[3].status,
            InventorySourceStatus::NotApplicable
        );
        assert_eq!(document.packages.len(), 2);
        assert_eq!(document.packages[0].source_id, "dpkg_query");
        assert_eq!(document.packages[1].source_id, "pacman_query");
        assert_eq!(document.packages[1].name.as_deref(), Some("two"));
    }

    #[test]
    fn no_available_package_manager_is_partial_and_never_an_empty_complete_result() {
        let document = collect_packages_with(
            [false; 4],
            [false; 5],
            None,
            TOTAL_PACKAGE_SCAN_TIMEOUT,
            10,
            |_, _, _, _, _, _| unreachable!(),
        );
        assert_eq!(document.status, InventoryStatus::Partial);
        assert!(document.packages.is_empty());
        assert_eq!(document.sources.len(), 4);
        assert!(
            document
                .sources
                .iter()
                .all(|source| source.status == InventorySourceStatus::Unavailable)
        );
    }

    #[test]
    fn failed_available_source_keeps_rows_but_marks_inventory_partial() {
        let document = collect_packages_with(
            [false, true, false, false],
            [false; 5],
            Some([false, true, false, false]),
            TOTAL_PACKAGE_SCAN_TIMEOUT,
            11,
            |adapter, at, _, _, _, _| {
                fixture_run(
                    adapter,
                    at,
                    b"alpha\t0:1.2-3\tx86_64\tinstalled\n",
                    InventorySourceStatus::Failed,
                )
            },
        );
        assert_eq!(document.status, InventoryStatus::Partial);
        assert_eq!(document.sources[1].status, InventorySourceStatus::Failed);
        assert_eq!(document.packages.len(), 1);
        assert_eq!(document.packages[0].source_id, "rpm_query");
    }

    #[test]
    fn detected_unsupported_manager_is_reported_even_when_no_supported_binary_exists() {
        let mut unsupported = [false; 5];
        unsupported[0] = true;
        let document = collect_packages_with(
            [false; 4],
            unsupported,
            None,
            TOTAL_PACKAGE_SCAN_TIMEOUT,
            12,
            |_, _, _, _, _, _| unreachable!(),
        );
        assert_eq!(document.status, InventoryStatus::Partial);
        assert!(
            document
                .sources
                .iter()
                .any(|source| source.id == "xbps_query"
                    && source.status == InventorySourceStatus::Unsupported)
        );
        assert!(
            document
                .sources
                .iter()
                .any(|source| source.id == "dpkg_query"
                    && source.status == InventorySourceStatus::Unavailable)
        );
    }

    #[test]
    fn known_distribution_marks_absent_alternative_managers_not_applicable() {
        let document = collect_packages_with(
            [true, false, false, false],
            [false; 5],
            Some([true, false, false, false]),
            TOTAL_PACKAGE_SCAN_TIMEOUT,
            13,
            |adapter, at, _, _, _, _| {
                fixture_run(
                    adapter,
                    at,
                    b"one\t1\tall\tii \n",
                    InventorySourceStatus::Complete,
                )
            },
        );
        assert_eq!(document.status, InventoryStatus::Complete);
        assert!(
            document
                .sources
                .iter()
                .filter(|source| source.id != "dpkg_query")
                .all(|source| source.status == InventorySourceStatus::NotApplicable)
        );
    }

    #[test]
    fn unknown_distribution_with_missing_alternatives_remains_partial() {
        let document = collect_packages_with(
            [true, false, false, false],
            [false; 5],
            None,
            TOTAL_PACKAGE_SCAN_TIMEOUT,
            14,
            |adapter, at, _, _, _, _| {
                fixture_run(
                    adapter,
                    at,
                    b"one\t1\tall\tii \n",
                    InventorySourceStatus::Complete,
                )
            },
        );
        assert_eq!(document.status, InventoryStatus::Partial);
        assert!(
            document
                .sources
                .iter()
                .filter(|source| source.id != "dpkg_query")
                .all(|source| source.status == InventorySourceStatus::Unavailable)
        );
    }

    #[test]
    fn aggregate_stdout_budget_exhaustion_leaves_later_manager_not_checked() {
        let document = collect_packages_with(
            [true; 4],
            [false; 5],
            Some([true; 4]),
            TOTAL_PACKAGE_SCAN_TIMEOUT,
            15,
            |adapter, at, stdout, _, rows, _| {
                assert_eq!(stdout, MAX_INVENTORY_STDOUT_BYTES);
                let output = b"one\t1\tall\tii \n";
                let mut run = fixture_run(adapter, at, output, InventorySourceStatus::Complete);
                run.stdout_bytes = MAX_INVENTORY_STDOUT_BYTES;
                run.document.sources[0].records_seen = rows;
                run
            },
        );
        assert_eq!(document.status, InventoryStatus::Partial);
        assert_eq!(
            document.sources[1].status,
            InventorySourceStatus::NotChecked
        );
    }

    #[test]
    fn aggregate_stderr_budget_is_shared_across_adapters() {
        let mut calls = 0usize;
        let document = collect_packages_with(
            [true; 4],
            [false; 5],
            Some([true; 4]),
            TOTAL_PACKAGE_SCAN_TIMEOUT,
            17,
            |adapter, at, _, stderr, _, _| {
                if calls == 0 {
                    assert_eq!(stderr, crate::limits::MAX_INVENTORY_STDERR_BYTES);
                } else {
                    assert_eq!(stderr, 0);
                }
                calls += 1;
                let mut run = fixture_run(
                    adapter,
                    at,
                    b"one\t1\tall\tii \n",
                    InventorySourceStatus::Complete,
                );
                if calls == 1 {
                    run.stderr_bytes = crate::limits::MAX_INVENTORY_STDERR_BYTES;
                }
                run
            },
        );
        assert_eq!(calls, 4);
        assert_eq!(document.status, InventoryStatus::Complete);
    }

    #[test]
    fn os_release_identifiers_map_only_known_package_families() {
        assert_eq!(
            expected_package_managers(Some(vec!["ubuntu".to_owned()])),
            Some([true, false, false, false])
        );
        assert_eq!(
            expected_package_managers(Some(vec!["opensuse-leap".to_owned()])),
            Some([false, true, false, false])
        );
        assert_eq!(
            expected_package_managers(Some(vec!["unknown".to_owned()])),
            None
        );
        assert_eq!(expected_package_managers(None), None);
    }

    #[test]
    fn aggregate_deadline_marks_later_sources_not_checked() {
        let document = collect_packages_with(
            [true; 4],
            [false; 5],
            Some([true; 4]),
            Duration::from_millis(1),
            16,
            |adapter, at, _, _, _, timeout| {
                assert!(!timeout.is_zero());
                let run = fixture_run(
                    adapter,
                    at,
                    b"one\t1\tall\tii \n",
                    InventorySourceStatus::Complete,
                );
                std::thread::sleep(Duration::from_millis(2));
                run
            },
        );
        assert_eq!(document.status, InventoryStatus::Partial);
        assert!(
            document
                .sources
                .iter()
                .any(|source| source.status == InventorySourceStatus::NotChecked)
        );
    }

    #[test]
    fn package_adapters_parse_strict_synthetic_rows_for_all_supported_formats() {
        let cases = [
            (
                "rpm_query",
                PackageSourceKind::Rpm,
                b"alpha\t0:1.2-3\tx86_64\tinstalled\n".as_slice(),
                "alpha",
                "0:1.2-3",
                Some("x86_64"),
            ),
            (
                "pacman_query",
                PackageSourceKind::Pacman,
                b"alpha 1.2-3\n".as_slice(),
                "alpha",
                "1.2-3",
                None,
            ),
            (
                "apk_info",
                PackageSourceKind::Apk,
                b"alpha-2-addon-1.2-r3\n".as_slice(),
                "alpha-2-addon",
                "1.2-r3",
                None,
            ),
        ];
        for (id, kind, fixture, name, version, architecture) in cases {
            let document = parse_package_source_output(
                id,
                kind,
                fixture,
                0,
                MAX_INVENTORY_STDOUT_BYTES,
                MAX_INVENTORY_ROWS,
            );
            assert_eq!(document.status, InventoryStatus::Complete, "{id}");
            let package = &document.packages[0];
            assert_eq!(package.source_id, id);
            assert_eq!(package.name.as_deref(), Some(name));
            assert_eq!(package.version.as_deref(), Some(version));
            assert_eq!(package.architecture.as_deref(), architecture);
            assert!(package.status_abbrev.is_none());
        }

        for (kind, fixture) in [
            (PackageSourceKind::Rpm, b"malformed\n".as_slice()),
            (PackageSourceKind::Pacman, b"alpha 1 extra\n".as_slice()),
            (
                PackageSourceKind::Apk,
                b"name-without-valid-version\n".as_slice(),
            ),
        ] {
            let document = parse_package_source_output(
                "synthetic",
                kind,
                fixture,
                0,
                MAX_INVENTORY_STDOUT_BYTES,
                MAX_INVENTORY_ROWS,
            );
            assert_eq!(document.status, InventoryStatus::Partial);
            assert_eq!(
                document.packages[0].diagnostic_code,
                Some("malformed_source_row")
            );
            assert_eq!(document.packages[0].evidence.raw_record, None);
        }
    }
}
