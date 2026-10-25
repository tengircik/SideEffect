//! Read-only, on-demand system inventory sources.

mod debian;
mod model;
#[cfg(target_os = "linux")]
mod packages;
#[cfg(target_os = "linux")]
mod permissions;
#[cfg(target_os = "linux")]
mod processes;
#[cfg(target_os = "linux")]
mod startup;

pub use model::{
    INVENTORY_SCHEMA, INVENTORY_SCHEMA_VERSION, InventoryDiagnostic, InventoryDocument,
    InventoryEvidence, InventoryPackage, InventorySource, InventorySourceStatus, InventoryStatus,
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
#[cfg(target_os = "linux")]
pub use startup::{
    StartupInventoryDocument, Status as StartupInventoryStatus, collect_startup,
    collect_startup_from,
};
