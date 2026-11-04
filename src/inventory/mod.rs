//! Read-only, on-demand system inventory sources.

#[cfg(target_os = "linux")]
mod access;
mod debian;
#[cfg(windows)]
mod effective_access_windows;
mod model;
mod package_diff;
#[cfg(target_os = "linux")]
mod packages;
#[cfg(windows)]
mod packages_windows;
mod path_executable_diff;
mod path_executables;
mod permission_diff;
#[cfg(target_os = "linux")]
mod permissions;
#[cfg(windows)]
mod permissions_windows;
mod process_diff;
#[cfg(target_os = "linux")]
mod processes;
#[cfg(windows)]
mod processes_windows;
mod root_snapshot;
mod root_snapshot_diff;
#[cfg(target_os = "linux")]
mod startup;
mod startup_diff;
#[cfg(target_os = "linux")]
mod startup_legacy;
mod startup_state;
#[cfg(windows)]
mod startup_windows;
#[cfg(windows)]
mod startup_wmi;
#[cfg(target_os = "linux")]
mod systemd_units;
#[cfg(windows)]
mod windows_app_paths;
#[cfg(windows)]
mod windows_msix;
mod windows_msix_diff;
mod windows_software_diff;

#[cfg(target_os = "linux")]
pub use access::{
    ACCESS_ANALYSIS_SCHEMA, ACCESS_ANALYSIS_SCHEMA_VERSION, AccessAnalysisDocument,
    AccessConclusion, AccessOperation, FactStatus, KernelProbeStatus,
    analyze_current_process_access,
};
#[cfg(windows)]
pub use effective_access_windows::{
    WindowsAccessConclusion, WindowsAccessControlEvidence, WindowsAccessControlStatus,
    WindowsAccessOperation, WindowsAccessStatus, WindowsDaclDecision, WindowsDaclEvaluationResult,
    evaluate_windows_dacl_for_process,
};
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
pub use path_executable_diff::{
    PathEntryFacts, PathExecutableDelta, PathExecutableDiff, PathExecutableDiffCounts,
    PathExecutableDiffError, compare_path_executable_inventory_json,
};
pub use path_executables::{PathExecutableInventory, collect_path_executables};
pub use permission_diff::{
    PermissionDelta, PermissionDiff, PermissionDiffCounts, PermissionDiffError,
    PermissionDiffStatus, PermissionEvidenceRef, PermissionSide, compare_permission_inventory_json,
    is_permission_inventory_json,
};
pub use process_diff::{
    ProcessDelta, ProcessDiff, ProcessDiffCounts, ProcessDiffError, ProcessDiffStatus,
    ProcessEvidenceRef, ProcessSide, compare_process_inventory_json, is_process_inventory_json,
};
pub use startup_diff::{
    StartupDelta, StartupDiffCounts, StartupDiffError, StartupDiffStatus, StartupEvidenceSide,
    StartupInventoryDiff, compare_startup_inventory_json, is_startup_inventory_json,
};
pub use windows_msix_diff::{
    WindowsMsixChangeKind, WindowsMsixComparisonDiagnostic, WindowsMsixComparisonError,
    WindowsMsixComparisonStatus, WindowsMsixCounts, WindowsMsixDelta, WindowsMsixEvidenceReference,
    WindowsMsixFacts, WindowsMsixIdentity, WindowsMsixInventoryComparison,
    compare_windows_msix_inventory_json,
};
pub use windows_software_diff::{
    WindowsSoftwareChangeKind, WindowsSoftwareComparisonCounts,
    WindowsSoftwareComparisonDiagnostic, WindowsSoftwareComparisonError,
    WindowsSoftwareComparisonStatus, WindowsSoftwareDelta, WindowsSoftwareEvidenceReference,
    WindowsSoftwareFacts, WindowsSoftwareIdentity, WindowsSoftwareInventoryComparison,
    WindowsSoftwareSourceComparison, WindowsSoftwareSourceStatus,
    compare_windows_software_inventory_json, is_windows_software_inventory_json,
};

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
    PROCESS_NAMESPACES, PidNamespaceIdentityEvidence, ProcessDiagnostic, ProcessEvidence,
    ProcessExecutableEvidence, ProcessExecutableLink, ProcessExecutableLinkStatus,
    ProcessIdentityDomain, ProcessIdentityDomainStatus, ProcessInventoryDocument,
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
pub use root_snapshot::{
    MAX_ROOT_AGGREGATE_HASH_BYTES, MAX_ROOT_ENTRIES, MAX_ROOT_FILE_HASH_BYTES, ROOT_HASH_DEADLINE,
    ROOT_SNAPSHOT_HASH_SCHEMA_VERSION, ROOT_SNAPSHOT_SCHEMA, ROOT_SNAPSHOT_SCHEMA_VERSION,
    RootContentHashing, RootDiagnostic, RootEntry, RootEntryEvidence, RootIdentity, RootSnapshot,
    RootSnapshotLimits, collect_root_snapshot, collect_root_snapshot_with_hash,
};
pub use root_snapshot_diff::{
    RootSnapshotDelta, RootSnapshotDiff, RootSnapshotDiffCounts, RootSnapshotDiffError,
    RootSnapshotSide, compare_selected_root_inventory_json, is_selected_root_inventory_json,
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
pub(crate) use startup_windows::collect_windows_startup_v5;
#[cfg(windows)]
pub use startup_windows::{
    WindowsRegistryStartupEntry, WindowsRegistryStartupEvidence, WindowsRegistryView,
    WindowsScheduledTaskStartupEntry, WindowsScheduledTaskStartupEvidence,
    WindowsServiceStartupEntry, WindowsServiceStartupEvidence, WindowsStartupDiagnostic,
    WindowsStartupFolderEntry, WindowsStartupFolderEvidence, WindowsStartupInventoryDocument,
    WindowsStartupSource, WindowsStartupStatus, collect_windows_startup,
};
#[cfg(windows)]
pub use startup_wmi::{
    WmiConsumerStatus, WmiEventConsumer, WmiEventFilter, WmiFilterConsumerBinding,
    WmiReferenceStatus, WmiSubscriptionEvidence,
};
#[cfg(target_os = "linux")]
pub use systemd_units::{UnitInventory as SystemdUnitInventory, UnitRecord as SystemdUnitRecord};
#[cfg(windows)]
pub use windows_app_paths::{
    AppPathDiagnostic, AppPathEntry, AppPathEvidence, AppPathRegistryView, AppPathSource,
    AppPathStatus, AppPathValue, WindowsAppPathInventoryDocument, collect_windows_app_paths,
};
#[cfg(windows)]
pub use windows_msix::{WindowsMsixInventoryDocument, WindowsMsixStatus, collect_windows_msix};
