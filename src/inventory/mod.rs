//! Read-only, on-demand system inventory sources.

mod debian;
mod model;
mod package_diff;
#[cfg(target_os = "linux")]
mod packages;
#[cfg(windows)]
mod packages_windows;
mod path_executables;
#[cfg(target_os = "linux")]
mod permissions;
#[cfg(windows)]
mod permissions_windows;
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
pub use path_executables::{PathExecutableInventory, collect_path_executables};

#[cfg(target_os = "linux")]
pub use debian::collect_debian_packages;
pub use debian::parse_dpkg_query_output;
#[cfg(target_os = "linux")]
pub use packages::collect_packages;
#[cfg(windows)]
pub use packages_windows::{
    WindowsRegistryValue, WindowsSoftwareDiagnostic, WindowsSoftwareInventoryDocument,
    WindowsSoftwareRegistration, WindowsSoftwareSource, WindowsSoftwareStatus,
    collect_windows_software,
};
#[cfg(target_os = "linux")]
pub use permissions::{
    AclEntry, AclObservation, AclStatus, AclTag, MAX_ACL_XATTR_BYTES, MAX_CAPABILITY_XATTR_BYTES,
    MAX_PERMISSION_PATHS, MAX_PERMISSION_TOTAL_ACL_BYTES, MAX_PERMISSION_TOTAL_CAPABILITY_BYTES,
    PermissionDiagnostic, PermissionInventoryDocument, PermissionInventoryStatus, PermissionObject,
    PermissionObjectStatus, collect_permissions,
};
#[cfg(windows)]
pub use permissions_windows::{
    WindowsAceEvidence, WindowsPermissionDiagnostic, WindowsPermissionInventoryDocument,
    WindowsPermissionLimits, WindowsPermissionMetadata, WindowsPermissionObject,
    WindowsPermissionStatus, WindowsSecurityDescriptorEvidence, collect_windows_permissions,
};
#[cfg(target_os = "linux")]
pub use processes::{
    MAX_AGGREGATE_NAMESPACE_LINK_BYTES, MAX_AGGREGATE_STATUS_BYTES, MAX_NAMESPACE_LINK_BYTES,
    MAX_PROCESS_DIRECTORIES, MAX_PROCESS_STAT_BYTES, NamespacePidEvidence, NamespacePidStatus,
    PROCESS_NAMESPACES, ProcessDiagnostic, ProcessEvidence, ProcessExecutableEvidence,
    ProcessExecutableLink, ProcessExecutableLinkStatus, ProcessInventoryDocument,
    ProcessInventorySource, ProcessInventoryStatus, ProcessNamespace, ProcessNamespaceEvidence,
    ProcessNamespaceStatus, ProcessRow, ProcessStartTime, ProcessStartTimeEvidence,
    ProcessStartTimeStatus, collect_processes, collect_processes_from,
};
#[cfg(windows)]
pub use processes_windows::{
    MAX_AGGREGATE_TOKEN_SID_UTF16_UNITS, WindowsProcessCreationTime,
    WindowsProcessCreationTimeStatus, WindowsProcessDiagnostic, WindowsProcessImage,
    WindowsProcessImageStatus, WindowsProcessInventoryDocument, WindowsProcessInventoryStatus,
    WindowsProcessRow, WindowsProcessTokenContext, WindowsProcessTokenContextStatus,
    WindowsProcessTokenField, WindowsProcessTokenFieldStatus, collect_windows_processes,
};
#[cfg(target_os = "linux")]
pub use startup::{
    Directory as StartupDirectory, Entry as XdgStartupEntry, KeyEvidence as StartupKeyEvidence,
    MAX_STARTUP_DIRECTORIES, MAX_STARTUP_FILES, MAX_STARTUP_TOTAL_BYTES, StartupInventoryDocument,
    Status as StartupInventoryStatus, XdgAutostartInventory, collect_startup, collect_startup_from,
};
#[cfg(target_os = "linux")]
pub use startup_legacy::{
    LegacyStartupDocument, LegacyStartupEntry, LegacyStartupPaths,
    ScanStatus as LegacyStartupStatus, collect_legacy_startup,
};
#[cfg(windows)]
pub use startup_windows::{
    WindowsRegistryStartupEntry, WindowsRegistryStartupEvidence, WindowsRegistryView,
    WindowsScheduledTaskStartupEntry, WindowsScheduledTaskStartupEvidence,
    WindowsServiceStartupEntry, WindowsServiceStartupEvidence, WindowsStartupDiagnostic,
    WindowsStartupFolderEntry, WindowsStartupFolderEvidence, WindowsStartupInventoryDocument,
    WindowsStartupSource, WindowsStartupStatus, collect_windows_startup,
};
#[cfg(target_os = "linux")]
pub use systemd_units::{UnitInventory as SystemdUnitInventory, UnitRecord as SystemdUnitRecord};
