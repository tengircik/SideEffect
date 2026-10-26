//! Read-only, on-demand system inventory sources.

mod debian;
mod model;
mod package_diff;
#[cfg(target_os = "linux")]
mod packages;
#[cfg(target_os = "linux")]
mod permissions;
#[cfg(target_os = "linux")]
mod processes;
#[cfg(windows)]
mod processes_windows;
#[cfg(target_os = "linux")]
mod startup;
#[cfg(target_os = "linux")]
mod startup_legacy;
#[cfg(windows)]
mod startup_windows;
#[cfg(target_os = "linux")]
mod systemd_units;

pub use model::{
    INVENTORY_SCHEMA, INVENTORY_SCHEMA_VERSION, InventoryDiagnostic, InventoryDocument,
    InventoryEvidence, InventoryPackage, InventorySource, InventorySourceStatus, InventoryStatus,
};
pub use package_diff::{
    PackageChangeKind, PackageComparisonCounts, PackageComparisonDiagnostic,
    PackageComparisonError, PackageComparisonStatus, PackageEvidenceReference, PackageFacts,
    PackageIdentity, PackageInventoryComparison, PackageInventoryDelta, PackageSourceComparison,
    compare_package_inventories, compare_package_inventory_json,
};

#[cfg(target_os = "linux")]
pub use debian::collect_debian_packages;
pub use debian::parse_dpkg_query_output;
#[cfg(target_os = "linux")]
pub use packages::collect_packages;
#[cfg(target_os = "linux")]
pub use permissions::{
    AclEntry, AclObservation, AclStatus, AclTag, PermissionDiagnostic, PermissionInventoryDocument,
    PermissionInventoryStatus, PermissionObject, PermissionObjectStatus, collect_permissions,
};
#[cfg(target_os = "linux")]
pub use processes::{
    ProcessDiagnostic, ProcessEvidence, ProcessExecutableEvidence, ProcessExecutableLink,
    ProcessExecutableLinkStatus, ProcessInventoryDocument, ProcessInventorySource,
    ProcessInventoryStatus, ProcessRow, collect_processes, collect_processes_from,
};
#[cfg(windows)]
pub use processes_windows::{
    WindowsProcessDiagnostic, WindowsProcessImage, WindowsProcessImageStatus,
    WindowsProcessInventoryDocument, WindowsProcessInventoryStatus, WindowsProcessRow,
    collect_windows_processes,
};
#[cfg(target_os = "linux")]
pub use startup::{
    Directory as StartupDirectory, Entry as XdgStartupEntry, KeyEvidence as StartupKeyEvidence,
    StartupInventoryDocument, Status as StartupInventoryStatus, XdgAutostartInventory,
    collect_startup, collect_startup_from,
};
#[cfg(target_os = "linux")]
pub use startup_legacy::{
    LegacyStartupDocument, LegacyStartupEntry, LegacyStartupPaths,
    ScanStatus as LegacyStartupStatus, collect_legacy_startup,
};
#[cfg(windows)]
pub use startup_windows::{
    WindowsRegistryStartupEntry, WindowsRegistryStartupEvidence, WindowsRegistryView,
    WindowsStartupDiagnostic, WindowsStartupFolderEntry, WindowsStartupFolderEvidence,
    WindowsStartupInventoryDocument, WindowsStartupSource, WindowsStartupStatus,
    collect_windows_startup,
};
#[cfg(target_os = "linux")]
pub use systemd_units::{UnitInventory as SystemdUnitInventory, UnitRecord as SystemdUnitRecord};
