//! Bounded, read-only snapshot of current-user AppX/MSIX package registrations.
//!
//! Package registration records do not establish that an app is available,
//! launchable, or has run. This collector queries only the calling user's
//! package registrations and never activates a package or reads its files.

use serde::Serialize;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use windows::Management::Deployment::PackageManager;
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
use windows::core::HSTRING;

const MAX_ROWS: usize = 4_096;
const MAX_STRING_UNITS: usize = 32_768;
const MAX_AGGREGATE_STRING_UNITS: usize = 1024 * 1024;
const MAX_DIAGNOSTICS: usize = 512;
const MAX_SCAN_DURATION_MS: u128 = 10_000;
const E_ACCESSDENIED: i32 = 0x8007_0005u32 as i32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsMsixStatus {
    Complete,
    Partial,
    Inaccessible,
    Unavailable,
    Error,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsMsixStringEvidence {
    /// A display form. `utf16_hex` preserves exact UTF-16 code units when the
    /// display form needs replacement characters.
    pub text: String,
    /// Exact UTF-16 code units, represented as lowercase hexadecimal.
    pub utf16_hex: String,
    pub display_replaced_invalid_utf16: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsMsixPackageVersion {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsMsixPackage {
    pub ordinal: usize,
    pub name: Option<WindowsMsixStringEvidence>,
    pub publisher: Option<WindowsMsixStringEvidence>,
    pub full_name: Option<WindowsMsixStringEvidence>,
    pub family_name: Option<WindowsMsixStringEvidence>,
    pub install_location: Option<WindowsMsixStringEvidence>,
    pub version: Option<WindowsMsixPackageVersion>,
    pub is_framework: Option<bool>,
    pub is_resource_package: Option<bool>,
    pub is_bundle: Option<bool>,
    pub is_development_mode: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsMsixDiagnostic {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_ordinal: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
    pub message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hresult: Option<i32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsMsixSource {
    pub id: &'static str,
    pub status: WindowsMsixStatus,
    pub packages_seen: usize,
    pub scope: &'static str,
    pub diagnostics: Vec<WindowsMsixDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsMsixInventoryDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub platform: &'static str,
    pub scope: &'static str,
    pub capture_started_at_unix_ms: u128,
    pub capture_ended_at_unix_ms: u128,
    pub status: WindowsMsixStatus,
    pub sources: Vec<WindowsMsixSource>,
    pub packages: Vec<WindowsMsixPackage>,
}

struct WinRtApartment;

impl Drop for WinRtApartment {
    fn drop(&mut self) {
        // SAFETY: construction follows a successful RoInitialize call on this thread.
        unsafe { RoUninitialize() };
    }
}

struct StringBudget {
    used_units: usize,
}

impl StringBudget {
    fn new() -> Self {
        Self { used_units: 0 }
    }

    fn retain(&mut self, value: HSTRING) -> Result<WindowsMsixStringEvidence, StringEvidenceError> {
        let units: &[u16] = &value;
        if units.len() > MAX_STRING_UNITS {
            return Err(StringEvidenceError::IndividualLimit);
        }
        let next_used = self
            .used_units
            .checked_add(units.len())
            .ok_or(StringEvidenceError::AggregateLimit)?;
        if next_used > MAX_AGGREGATE_STRING_UNITS {
            return Err(StringEvidenceError::AggregateLimit);
        }
        self.used_units = next_used;

        let display_replaced_invalid_utf16 = String::from_utf16(units).is_err();
        let text = String::from_utf16_lossy(units);
        let mut utf16_hex = String::with_capacity(units.len().saturating_mul(4));
        use std::fmt::Write as _;
        for unit in units {
            let _ = write!(utf16_hex, "{unit:04x}");
        }
        Ok(WindowsMsixStringEvidence {
            text,
            utf16_hex,
            display_replaced_invalid_utf16,
        })
    }
}

#[derive(Clone, Copy)]
enum StringEvidenceError {
    IndividualLimit,
    AggregateLimit,
}

pub fn collect_windows_msix() -> WindowsMsixInventoryDocument {
    let capture_started_at_unix_ms = now_ms();
    let started = Instant::now();
    let mut diagnostics = Vec::new();
    let mut packages = Vec::new();
    let mut status = WindowsMsixStatus::Complete;

    let init = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
    if let Err(error) = init {
        status = if error.code().0 == E_ACCESSDENIED {
            WindowsMsixStatus::Inaccessible
        } else {
            WindowsMsixStatus::Unavailable
        };
        push_diagnostic(
            &mut diagnostics,
            WindowsMsixDiagnostic {
                code: "winrt_apartment_initialization_failed",
                package_ordinal: None,
                field: None,
                message: "Windows could not initialize the Windows Runtime apartment for package inventory.",
                hresult: Some(error.code().0),
            },
        );
        return document(capture_started_at_unix_ms, status, diagnostics, packages);
    }
    let _apartment = WinRtApartment;

    let manager = match PackageManager::new() {
        Ok(manager) => manager,
        Err(error) => {
            status = if error.code().0 == E_ACCESSDENIED {
                WindowsMsixStatus::Inaccessible
            } else {
                WindowsMsixStatus::Unavailable
            };
            push_diagnostic(
                &mut diagnostics,
                WindowsMsixDiagnostic {
                    code: "package_manager_activation_failed",
                    package_ordinal: None,
                    field: None,
                    message: "Windows could not activate the read-only package query API.",
                    hresult: Some(error.code().0),
                },
            );
            return document(capture_started_at_unix_ms, status, diagnostics, packages);
        }
    };

    if deadline_reached(started) {
        status = WindowsMsixStatus::Partial;
        push_diagnostic(
            &mut diagnostics,
            WindowsMsixDiagnostic {
                code: "scan_deadline_exceeded",
                package_ordinal: None,
                field: None,
                message: "The package inventory time limit was reached before enumeration began.",
                hresult: None,
            },
        );
        return document(capture_started_at_unix_ms, status, diagnostics, packages);
    }

    // An empty user SID explicitly selects the calling user's packages. Never query
    // another user or enumerate packages for all users.
    let current_user_sid = HSTRING::new();
    let iterable = match manager.FindPackagesByUserSecurityId(&current_user_sid) {
        Ok(iterable) => iterable,
        Err(error) => {
            status = if error.code().0 == E_ACCESSDENIED {
                WindowsMsixStatus::Inaccessible
            } else {
                WindowsMsixStatus::Error
            };
            push_diagnostic(
                &mut diagnostics,
                WindowsMsixDiagnostic {
                    code: "current_user_package_query_failed",
                    package_ordinal: None,
                    field: None,
                    message: "Windows could not enumerate package registrations for the current user.",
                    hresult: Some(error.code().0),
                },
            );
            return document(capture_started_at_unix_ms, status, diagnostics, packages);
        }
    };

    if deadline_reached(started) {
        status = WindowsMsixStatus::Partial;
        push_diagnostic(
            &mut diagnostics,
            WindowsMsixDiagnostic {
                code: "scan_deadline_exceeded",
                package_ordinal: None,
                field: None,
                message: "The package inventory time limit was reached after the query was prepared.",
                hresult: None,
            },
        );
        return document(capture_started_at_unix_ms, status, diagnostics, packages);
    }

    let iterator = match iterable.First() {
        Ok(iterator) => iterator,
        Err(error) => {
            status = WindowsMsixStatus::Error;
            push_diagnostic(
                &mut diagnostics,
                WindowsMsixDiagnostic {
                    code: "package_iterator_creation_failed",
                    package_ordinal: None,
                    field: None,
                    message: "Windows could not create an iterator over current-user package registrations.",
                    hresult: Some(error.code().0),
                },
            );
            return document(capture_started_at_unix_ms, status, diagnostics, packages);
        }
    };

    let mut string_budget = StringBudget::new();
    loop {
        if deadline_reached(started) {
            status = WindowsMsixStatus::Partial;
            push_diagnostic(
                &mut diagnostics,
                WindowsMsixDiagnostic {
                    code: "scan_deadline_exceeded",
                    package_ordinal: None,
                    field: None,
                    message: "The package inventory time limit was reached during enumeration.",
                    hresult: None,
                },
            );
            break;
        }
        let has_current = match iterator.HasCurrent() {
            Ok(has_current) => has_current,
            Err(error) => {
                status = WindowsMsixStatus::Partial;
                push_diagnostic(
                    &mut diagnostics,
                    WindowsMsixDiagnostic {
                        code: "package_iterator_status_failed",
                        package_ordinal: None,
                        field: None,
                        message: "Windows could not determine whether another package record was available.",
                        hresult: Some(error.code().0),
                    },
                );
                break;
            }
        };
        if !has_current {
            break;
        }
        if packages.len() >= MAX_ROWS {
            status = WindowsMsixStatus::Partial;
            push_diagnostic(
                &mut diagnostics,
                WindowsMsixDiagnostic {
                    code: "package_row_limit_exceeded",
                    package_ordinal: Some(packages.len()),
                    field: None,
                    message: "The package row limit was reached; later registrations were not enumerated.",
                    hresult: None,
                },
            );
            break;
        }
        if deadline_reached(started) {
            status = WindowsMsixStatus::Partial;
            push_diagnostic(
                &mut diagnostics,
                WindowsMsixDiagnostic {
                    code: "scan_deadline_exceeded",
                    package_ordinal: Some(packages.len()),
                    field: None,
                    message: "The package inventory time limit was reached before this record was read.",
                    hresult: None,
                },
            );
            break;
        }
        let package = match iterator.Current() {
            Ok(package) => package,
            Err(error) => {
                status = WindowsMsixStatus::Partial;
                push_diagnostic(
                    &mut diagnostics,
                    WindowsMsixDiagnostic {
                        code: "package_iterator_current_failed",
                        package_ordinal: Some(packages.len()),
                        field: None,
                        message: "Windows could not read the current package record.",
                        hresult: Some(error.code().0),
                    },
                );
                break;
            }
        };
        let ordinal = packages.len();
        let row = collect_package(
            &package,
            ordinal,
            started,
            &mut string_budget,
            &mut diagnostics,
            &mut status,
        );
        packages.push(row);
        if diagnostics.len() >= MAX_DIAGNOSTICS {
            status = WindowsMsixStatus::Partial;
            break;
        }
        if deadline_reached(started) {
            status = WindowsMsixStatus::Partial;
            push_diagnostic(
                &mut diagnostics,
                WindowsMsixDiagnostic {
                    code: "scan_deadline_exceeded",
                    package_ordinal: Some(ordinal),
                    field: None,
                    message: "The package inventory time limit was reached while reading this record.",
                    hresult: None,
                },
            );
            break;
        }
        if let Err(error) = iterator.MoveNext() {
            status = WindowsMsixStatus::Partial;
            push_diagnostic(
                &mut diagnostics,
                WindowsMsixDiagnostic {
                    code: "package_iterator_advance_failed",
                    package_ordinal: Some(ordinal),
                    field: None,
                    message: "Windows could not advance to the next package registration.",
                    hresult: Some(error.code().0),
                },
            );
            break;
        }
    }

    document(capture_started_at_unix_ms, status, diagnostics, packages)
}

fn collect_package(
    package: &windows::ApplicationModel::Package,
    ordinal: usize,
    started: Instant,
    string_budget: &mut StringBudget,
    diagnostics: &mut Vec<WindowsMsixDiagnostic>,
    status: &mut WindowsMsixStatus,
) -> WindowsMsixPackage {
    let mut row = WindowsMsixPackage {
        ordinal,
        name: None,
        publisher: None,
        full_name: None,
        family_name: None,
        install_location: None,
        version: None,
        is_framework: None,
        is_resource_package: None,
        is_bundle: None,
        is_development_mode: None,
    };
    if deadline_reached(started) {
        *status = WindowsMsixStatus::Partial;
        push_diagnostic(
            diagnostics,
            field_diagnostic(
                "scan_deadline_exceeded",
                ordinal,
                None,
                "The package inventory time limit was reached before this record was read.",
                None,
            ),
        );
        return row;
    }
    let id = match package.Id() {
        Ok(id) => id,
        Err(error) => {
            *status = WindowsMsixStatus::Partial;
            push_diagnostic(
                diagnostics,
                field_diagnostic(
                    "package_identity_read_failed",
                    ordinal,
                    Some("id"),
                    "Windows could not read this package's identity object.",
                    Some(error.code().0),
                ),
            );
            return row;
        }
    };

    read_string_field(
        "name",
        ordinal,
        started,
        diagnostics,
        status,
        string_budget,
        &mut row.name,
        || id.Name(),
    );
    read_string_field(
        "publisher",
        ordinal,
        started,
        diagnostics,
        status,
        string_budget,
        &mut row.publisher,
        || id.Publisher(),
    );
    read_string_field(
        "full_name",
        ordinal,
        started,
        diagnostics,
        status,
        string_budget,
        &mut row.full_name,
        || id.FullName(),
    );
    read_string_field(
        "family_name",
        ordinal,
        started,
        diagnostics,
        status,
        string_budget,
        &mut row.family_name,
        || id.FamilyName(),
    );
    read_field(
        "version",
        ordinal,
        started,
        diagnostics,
        status,
        &mut row.version,
        || {
            id.Version().map(|v| WindowsMsixPackageVersion {
                major: v.Major,
                minor: v.Minor,
                build: v.Build,
                revision: v.Revision,
            })
        },
    );
    read_install_location(
        ordinal,
        started,
        diagnostics,
        status,
        string_budget,
        &mut row.install_location,
        package,
    );
    read_field(
        "is_framework",
        ordinal,
        started,
        diagnostics,
        status,
        &mut row.is_framework,
        || package.IsFramework(),
    );
    read_field(
        "is_resource_package",
        ordinal,
        started,
        diagnostics,
        status,
        &mut row.is_resource_package,
        || package.IsResourcePackage(),
    );
    read_field(
        "is_bundle",
        ordinal,
        started,
        diagnostics,
        status,
        &mut row.is_bundle,
        || package.IsBundle(),
    );
    read_field(
        "is_development_mode",
        ordinal,
        started,
        diagnostics,
        status,
        &mut row.is_development_mode,
        || package.IsDevelopmentMode(),
    );
    row
}

#[allow(clippy::too_many_arguments)] // Each field read shares the same bounds, status, and evidence budget.
fn read_string_field<F>(
    field: &'static str,
    ordinal: usize,
    started: Instant,
    diagnostics: &mut Vec<WindowsMsixDiagnostic>,
    status: &mut WindowsMsixStatus,
    budget: &mut StringBudget,
    target: &mut Option<WindowsMsixStringEvidence>,
    getter: F,
) where
    F: FnOnce() -> windows::core::Result<HSTRING>,
{
    if deadline_reached(started) {
        *status = WindowsMsixStatus::Partial;
        push_diagnostic(
            diagnostics,
            field_diagnostic(
                "scan_deadline_exceeded",
                ordinal,
                Some(field),
                "The package inventory time limit was reached before this field was read.",
                None,
            ),
        );
        return;
    }
    match getter() {
        Ok(value) => match budget.retain(value) {
            Ok(evidence) => *target = Some(evidence),
            Err(issue) => {
                *status = WindowsMsixStatus::Partial;
                let (code, message) = match issue {
                    StringEvidenceError::IndividualLimit => (
                        "package_string_limit_exceeded",
                        "This package string exceeded its individual size bound; the field remains unknown.",
                    ),
                    StringEvidenceError::AggregateLimit => (
                        "package_text_budget_exceeded",
                        "The aggregate package text bound was reached; this field remains unknown and later fields are subject to the remaining budget.",
                    ),
                };
                push_diagnostic(
                    diagnostics,
                    field_diagnostic(code, ordinal, Some(field), message, None),
                );
            }
        },
        Err(error) => {
            *status = WindowsMsixStatus::Partial;
            push_diagnostic(
                diagnostics,
                field_diagnostic(
                    "package_field_read_failed",
                    ordinal,
                    Some(field),
                    "Windows could not read this package field; the field remains unknown.",
                    Some(error.code().0),
                ),
            );
        }
    }
}

fn read_install_location(
    ordinal: usize,
    started: Instant,
    diagnostics: &mut Vec<WindowsMsixDiagnostic>,
    status: &mut WindowsMsixStatus,
    budget: &mut StringBudget,
    target: &mut Option<WindowsMsixStringEvidence>,
    package: &windows::ApplicationModel::Package,
) {
    if deadline_reached(started) {
        *status = WindowsMsixStatus::Partial;
        push_diagnostic(
            diagnostics,
            field_diagnostic(
                "scan_deadline_exceeded",
                ordinal,
                Some("install_location"),
                "The package inventory time limit was reached before this field was read.",
                None,
            ),
        );
        return;
    }
    let folder = match package.InstalledLocation() {
        Ok(folder) => folder,
        Err(error) => {
            *status = WindowsMsixStatus::Partial;
            push_diagnostic(
                diagnostics,
                field_diagnostic(
                    "package_field_read_failed",
                    ordinal,
                    Some("install_location"),
                    "Windows could not read this package field; the field remains unknown.",
                    Some(error.code().0),
                ),
            );
            return;
        }
    };
    read_string_field(
        "install_location",
        ordinal,
        started,
        diagnostics,
        status,
        budget,
        target,
        || folder.Path(),
    );
}

fn read_field<T, F>(
    field: &'static str,
    ordinal: usize,
    started: Instant,
    diagnostics: &mut Vec<WindowsMsixDiagnostic>,
    status: &mut WindowsMsixStatus,
    target: &mut Option<T>,
    getter: F,
) where
    F: FnOnce() -> windows::core::Result<T>,
{
    if deadline_reached(started) {
        *status = WindowsMsixStatus::Partial;
        push_diagnostic(
            diagnostics,
            field_diagnostic(
                "scan_deadline_exceeded",
                ordinal,
                Some(field),
                "The package inventory time limit was reached before this field was read.",
                None,
            ),
        );
        return;
    }
    match getter() {
        Ok(value) => *target = Some(value),
        Err(error) => {
            *status = WindowsMsixStatus::Partial;
            push_diagnostic(
                diagnostics,
                field_diagnostic(
                    "package_field_read_failed",
                    ordinal,
                    Some(field),
                    "Windows could not read this package field; the field remains unknown.",
                    Some(error.code().0),
                ),
            );
        }
    }
}

fn field_diagnostic(
    code: &'static str,
    package_ordinal: usize,
    field: Option<&'static str>,
    message: &'static str,
    hresult: Option<i32>,
) -> WindowsMsixDiagnostic {
    WindowsMsixDiagnostic {
        code,
        package_ordinal: Some(package_ordinal),
        field,
        message,
        hresult,
    }
}

fn push_diagnostic(
    diagnostics: &mut Vec<WindowsMsixDiagnostic>,
    diagnostic: WindowsMsixDiagnostic,
) {
    if diagnostics.len() < MAX_DIAGNOSTICS {
        diagnostics.push(diagnostic);
    }
}

fn document(
    capture_started_at_unix_ms: u128,
    status: WindowsMsixStatus,
    diagnostics: Vec<WindowsMsixDiagnostic>,
    packages: Vec<WindowsMsixPackage>,
) -> WindowsMsixInventoryDocument {
    let source_status = status;
    WindowsMsixInventoryDocument {
        schema: "sideeffect.windows_msix_inventory",
        schema_version: 1,
        platform: "windows",
        scope: "current_user_registered_appx_and_msix_packages_only",
        capture_started_at_unix_ms,
        capture_ended_at_unix_ms: now_ms(),
        status,
        sources: vec![WindowsMsixSource {
            id: "current_user_appx_msix_packages",
            status: source_status,
            packages_seen: packages.len(),
            scope: "calling_user_only",
            diagnostics,
        }],
        packages,
    }
}

fn deadline_reached(started: Instant) -> bool {
    started.elapsed().as_millis() >= MAX_SCAN_DURATION_MS
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
