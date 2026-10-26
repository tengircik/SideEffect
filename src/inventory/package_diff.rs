//! Deterministic, bounded comparison of two package inventory snapshots.

use super::model::{
    INVENTORY_SCHEMA, INVENTORY_SCHEMA_VERSION, InventoryDocument, InventoryEvidence,
    InventoryPackage, InventorySource, InventorySourceStatus, InventoryStatus,
};
use serde::{Deserialize, Serialize, de};
use std::collections::{BTreeMap, BTreeSet};

const MAX_SOURCES: usize = 256;
const MAX_PACKAGES_PER_DOCUMENT: usize = 200_000;
const MAX_DIAGNOSTICS_PER_DOCUMENT: usize = 200_000;
const MAX_DELTAS: usize = 100_000;
const MAX_FIELD_BYTES: usize = 2_048;
const MAX_DOCUMENT_TEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_PACKAGE_INVENTORY_INPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageComparisonStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PackageIdentity {
    pub source_id: String,
    pub name: String,
    pub architecture: Option<String>,
}

/// An evidence locator keeps the package row's source tuple without copying its raw row or
/// fingerprint into a human-readable comparison.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PackageEvidenceReference {
    pub line: usize,
    pub byte_offset: usize,
    pub byte_length: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PackageFacts {
    pub version: Option<String>,
    pub status_abbrev: Option<String>,
    pub evidence: PackageEvidenceReference,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PackageInventoryDelta {
    pub kind: PackageChangeKind,
    pub identity: PackageIdentity,
    pub before: Option<PackageFacts>,
    pub after: Option<PackageFacts>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PackageSourceComparison {
    pub source_id: String,
    pub before_status: Option<InventorySourceStatus>,
    pub after_status: Option<InventorySourceStatus>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageComparisonDiagnostic {
    SourceMissingOnOneSide,
    SourceApplicabilityDiffers,
    SourceIncomplete,
    InvalidPackageIdentity,
    DuplicatePackageIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PackageComparisonCounts {
    pub additions: usize,
    pub removals: usize,
    pub changes: usize,
    pub unmatched_rows_with_incomplete_source: usize,
    pub invalid_identity_rows: usize,
    pub ambiguous_identity_groups: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PackageInventoryComparison {
    pub schema: &'static str,
    pub schema_version: u32,
    pub before_captured_at_unix_ms: u128,
    pub after_captured_at_unix_ms: u128,
    pub status: PackageComparisonStatus,
    pub coverage_note: &'static str,
    pub sources: Vec<PackageSourceComparison>,
    pub counts: PackageComparisonCounts,
    pub diagnostics: Vec<PackageComparisonDiagnostic>,
    pub deltas: Vec<PackageInventoryDelta>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageComparisonError {
    MalformedInput,
    InputTooLarge,
    UnsupportedSourceId,
    UnsupportedSchema,
    SchemaMismatch,
    PlatformMismatch,
    ScopeMismatch,
    SourceLimitExceeded,
    PackageLimitExceeded,
    FieldLimitExceeded,
    DocumentTextLimitExceeded,
    DuplicateSourceId,
    DeltaLimitExceeded,
}

/// Deserialize and compare two saved package inventory JSON documents. The accepted JSON
/// shape is strict schema `sideeffect.inventory` v2; unknown fields and source IDs are rejected.
pub fn compare_package_inventory_json(
    before_json: &[u8],
    after_json: &[u8],
) -> Result<PackageInventoryComparison, PackageComparisonError> {
    if before_json.len().saturating_add(after_json.len()) > MAX_PACKAGE_INVENTORY_INPUT_BYTES {
        return Err(PackageComparisonError::InputTooLarge);
    }
    let before: PackageInventoryInput =
        serde_json::from_slice(before_json).map_err(|_| PackageComparisonError::MalformedInput)?;
    let after: PackageInventoryInput =
        serde_json::from_slice(after_json).map_err(|_| PackageComparisonError::MalformedInput)?;
    compare_package_inventories(&before.into_document()?, &after.into_document()?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageInventoryInput {
    schema: String,
    schema_version: u32,
    platform: String,
    scope: String,
    captured_at_unix_ms: u128,
    status: InventoryStatusInput,
    #[serde(deserialize_with = "deserialize_sources")]
    sources: Vec<PackageSourceInput>,
    #[serde(deserialize_with = "deserialize_packages")]
    packages: Vec<PackageInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageSourceInput {
    id: String,
    status: InventorySourceStatusInput,
    exit_code: Option<i32>,
    records_seen: usize,
    #[serde(default, deserialize_with = "deserialize_diagnostics")]
    diagnostics: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum InventoryStatusInput {
    Complete,
    Partial,
}

impl From<InventoryStatusInput> for InventoryStatus {
    fn from(value: InventoryStatusInput) -> Self {
        match value {
            InventoryStatusInput::Complete => Self::Complete,
            InventoryStatusInput::Partial => Self::Partial,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum InventorySourceStatusInput {
    Complete,
    Partial,
    NotChecked,
    Unsupported,
    NotApplicable,
    Unavailable,
    AccessDenied,
    Failed,
    TimedOut,
    OutputLimitExceeded,
}

impl From<InventorySourceStatusInput> for InventorySourceStatus {
    fn from(value: InventorySourceStatusInput) -> Self {
        match value {
            InventorySourceStatusInput::Complete => Self::Complete,
            InventorySourceStatusInput::Partial => Self::Partial,
            InventorySourceStatusInput::NotChecked => Self::NotChecked,
            InventorySourceStatusInput::Unsupported => Self::Unsupported,
            InventorySourceStatusInput::NotApplicable => Self::NotApplicable,
            InventorySourceStatusInput::Unavailable => Self::Unavailable,
            InventorySourceStatusInput::AccessDenied => Self::AccessDenied,
            InventorySourceStatusInput::Failed => Self::Failed,
            InventorySourceStatusInput::TimedOut => Self::TimedOut,
            InventorySourceStatusInput::OutputLimitExceeded => Self::OutputLimitExceeded,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageDiagnosticInput {
    #[serde(rename = "code")]
    _code: String,
    #[serde(rename = "line")]
    _line: Option<usize>,
    #[serde(rename = "byte_offset")]
    _byte_offset: Option<usize>,
    #[serde(rename = "byte_length")]
    _byte_length: Option<usize>,
    #[serde(rename = "record_sha256")]
    _record_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageInput {
    source_id: String,
    name: Option<String>,
    version: Option<String>,
    architecture: Option<String>,
    status_abbrev: Option<String>,
    evidence: PackageEvidenceInput,
    #[serde(rename = "diagnostic_code")]
    _diagnostic_code: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageEvidenceInput {
    line: usize,
    byte_offset: usize,
    byte_length: usize,
    record_sha256: String,
    raw_record: Option<String>,
    raw_record_hex: Option<String>,
}

impl PackageInventoryInput {
    fn into_document(self) -> Result<InventoryDocument, PackageComparisonError> {
        if self.schema != INVENTORY_SCHEMA || self.schema_version != INVENTORY_SCHEMA_VERSION {
            return Err(PackageComparisonError::UnsupportedSchema);
        }
        let sources = self
            .sources
            .into_iter()
            .map(|source| {
                let id = supported_source_id(&source.id)
                    .ok_or(PackageComparisonError::UnsupportedSourceId)?;
                // Diagnostic text and fingerprints are validated by the strict input shape but
                // deliberately discarded; comparison output does not propagate either.
                let _discarded_diagnostic_count = source.diagnostics;
                Ok(InventorySource {
                    id,
                    status: source.status.into(),
                    exit_code: source.exit_code,
                    records_seen: source.records_seen,
                    diagnostics: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>, PackageComparisonError>>()?;
        let packages = self
            .packages
            .into_iter()
            .map(|package| {
                Ok(InventoryPackage {
                    source_id: supported_source_id(&package.source_id)
                        .ok_or(PackageComparisonError::UnsupportedSourceId)?,
                    name: package.name,
                    version: package.version,
                    architecture: package.architecture,
                    status_abbrev: package.status_abbrev,
                    evidence: InventoryEvidence {
                        line: package.evidence.line,
                        byte_offset: package.evidence.byte_offset,
                        byte_length: package.evidence.byte_length,
                        record_sha256: package.evidence.record_sha256,
                        raw_record: package.evidence.raw_record,
                        raw_record_hex: package.evidence.raw_record_hex,
                    },
                    diagnostic_code: None,
                })
            })
            .collect::<Result<Vec<_>, PackageComparisonError>>()?;
        let platform = match self.platform.as_str() {
            "linux" => "linux",
            _ => return Err(PackageComparisonError::PlatformMismatch),
        };
        let scope = match self.scope.as_str() {
            "available_package_manager_databases" => "available_package_manager_databases",
            _ => return Err(PackageComparisonError::ScopeMismatch),
        };
        Ok(InventoryDocument {
            schema: INVENTORY_SCHEMA,
            schema_version: INVENTORY_SCHEMA_VERSION,
            platform,
            scope,
            captured_at_unix_ms: self.captured_at_unix_ms,
            status: self.status.into(),
            sources,
            packages,
        })
    }
}

fn supported_source_id(value: &str) -> Option<&'static str> {
    match value {
        "dpkg_query" => Some("dpkg_query"),
        "rpm_query" => Some("rpm_query"),
        "pacman_query" => Some("pacman_query"),
        "apk_info" => Some("apk_info"),
        "xbps_query" => Some("xbps_query"),
        "nix" => Some("nix"),
        "guix" => Some("guix"),
        "snap" => Some("snap"),
        "flatpak" => Some("flatpak"),
        _ => None,
    }
}

fn deserialize_sources<'de, D>(deserializer: D) -> Result<Vec<PackageSourceInput>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct PackageSourcesVisitor;
    impl<'de> serde::de::Visitor<'de> for PackageSourcesVisitor {
        type Value = Vec<PackageSourceInput>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a sequence with at most {MAX_SOURCES} sources")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut sources = Vec::new();
            let mut diagnostic_count = 0usize;
            while let Some(source) = sequence.next_element::<PackageSourceInput>()? {
                if sources.len() >= MAX_SOURCES {
                    return Err(de::Error::custom("source limit exceeded"));
                }
                diagnostic_count = diagnostic_count
                    .checked_add(source.diagnostics)
                    .ok_or_else(|| de::Error::custom("diagnostic count overflow"))?;
                if diagnostic_count > MAX_DIAGNOSTICS_PER_DOCUMENT {
                    return Err(de::Error::custom("document diagnostic limit exceeded"));
                }
                sources.push(source);
            }
            Ok(sources)
        }
    }
    deserializer.deserialize_seq(PackageSourcesVisitor)
}

fn deserialize_packages<'de, D>(deserializer: D) -> Result<Vec<PackageInput>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_vec::<_, _, MAX_PACKAGES_PER_DOCUMENT>(deserializer)
}

fn deserialize_diagnostics<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct DiagnosticCountVisitor;
    impl<'de> serde::de::Visitor<'de> for DiagnosticCountVisitor {
        type Value = usize;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "a sequence with at most {MAX_DIAGNOSTICS_PER_DOCUMENT} diagnostics"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut count = 0usize;
            while sequence.next_element::<PackageDiagnosticInput>()?.is_some() {
                count += 1;
                if count > MAX_DIAGNOSTICS_PER_DOCUMENT {
                    return Err(de::Error::custom("diagnostic limit exceeded"));
                }
            }
            Ok(count)
        }
    }
    deserializer.deserialize_seq(DiagnosticCountVisitor)
}

fn deserialize_bounded_vec<'de, D, T, const LIMIT: usize>(
    deserializer: D,
) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T, const LIMIT: usize>(std::marker::PhantomData<T>);
    impl<'de, T, const LIMIT: usize> serde::de::Visitor<'de> for BoundedVecVisitor<T, LIMIT>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a sequence with at most {LIMIT} entries")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element()? {
                if values.len() >= LIMIT {
                    return Err(de::Error::custom("sequence limit exceeded"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(BoundedVecVisitor::<T, LIMIT>(std::marker::PhantomData))
}

/// Compare two package snapshots using `(source_id, name, architecture)` identity.
///
/// The operation is bounded and deterministic. Unmatched identities become additions or
/// removals only when the corresponding source is complete on both sides and applicable on
/// both sides. Matched identities can still report observed version/status changes when a
/// source is partial; the result remains partial in that case.
pub fn compare_package_inventories(
    before: &InventoryDocument,
    after: &InventoryDocument,
) -> Result<PackageInventoryComparison, PackageComparisonError> {
    validate_document(before)?;
    validate_document(after)?;
    if before.platform != after.platform {
        return Err(PackageComparisonError::PlatformMismatch);
    }
    if before.scope != after.scope {
        return Err(PackageComparisonError::ScopeMismatch);
    }

    let before_sources = source_map(before)?;
    let after_sources = source_map(after)?;
    let source_ids: BTreeSet<&str> = before_sources
        .keys()
        .chain(after_sources.keys())
        .copied()
        .collect();

    let mut source_comparisons = Vec::with_capacity(source_ids.len());
    let mut source_can_diff = BTreeMap::<&str, bool>::new();
    let mut diagnostics = BTreeSet::new();
    let mut complete = true;
    if before.status != super::model::InventoryStatus::Complete
        || after.status != super::model::InventoryStatus::Complete
    {
        diagnostics.insert(PackageComparisonDiagnostic::SourceIncomplete);
        complete = false;
    }

    for id in source_ids {
        let left = before_sources.get(id).copied();
        let right = after_sources.get(id).copied();
        source_comparisons.push(PackageSourceComparison {
            source_id: id.to_owned(),
            before_status: left.map(|source| source.status),
            after_status: right.map(|source| source.status),
        });
        let can_compare = match (left, right) {
            (Some(left), Some(right)) => {
                if is_not_applicable(left.status) != is_not_applicable(right.status) {
                    diagnostics.insert(PackageComparisonDiagnostic::SourceApplicabilityDiffers);
                    complete = false;
                    false
                } else if is_not_applicable(left.status) {
                    false
                } else {
                    if left.status != InventorySourceStatus::Complete
                        || right.status != InventorySourceStatus::Complete
                    {
                        diagnostics.insert(PackageComparisonDiagnostic::SourceIncomplete);
                        complete = false;
                    }
                    true
                }
            }
            _ => {
                diagnostics.insert(PackageComparisonDiagnostic::SourceMissingOnOneSide);
                complete = false;
                false
            }
        };
        source_can_diff.insert(id, can_compare);
    }

    let mut left = grouped_packages(before, &before_sources)?;
    let mut right = grouped_packages(after, &after_sources)?;
    let mut deltas = Vec::new();
    let mut counts = PackageComparisonCounts {
        additions: 0,
        removals: 0,
        changes: 0,
        unmatched_rows_with_incomplete_source: 0,
        invalid_identity_rows: 0,
        ambiguous_identity_groups: 0,
    };
    counts.invalid_identity_rows = left.invalid_rows + right.invalid_rows;
    if counts.invalid_identity_rows > 0 {
        diagnostics.insert(PackageComparisonDiagnostic::InvalidPackageIdentity);
        complete = false;
    }
    counts.ambiguous_identity_groups = left.duplicates.len() + right.duplicates.len();
    if counts.ambiguous_identity_groups > 0 {
        diagnostics.insert(PackageComparisonDiagnostic::DuplicatePackageIdentity);
        complete = false;
        for key in &left.duplicates {
            left.rows.remove(key);
            right.rows.remove(key);
        }
        for key in &right.duplicates {
            left.rows.remove(key);
            right.rows.remove(key);
        }
    }

    if left.unknown_source_rows + right.unknown_source_rows > 0 {
        diagnostics.insert(PackageComparisonDiagnostic::SourceMissingOnOneSide);
        complete = false;
    }

    let keys: BTreeSet<PackageIdentity> =
        left.rows.keys().chain(right.rows.keys()).cloned().collect();
    for identity in keys {
        let before_row = left.rows.get(&identity);
        let after_row = right.rows.get(&identity);
        match (before_row, after_row) {
            (Some(a), Some(b)) => {
                if a.version != b.version || a.status_abbrev != b.status_abbrev {
                    push_delta(
                        &mut deltas,
                        PackageInventoryDelta {
                            kind: PackageChangeKind::Changed,
                            identity,
                            before: Some(package_facts(a)),
                            after: Some(package_facts(b)),
                        },
                    )?;
                    counts.changes += 1;
                }
            }
            (Some(a), None) | (None, Some(a)) => {
                let source_complete = source_can_diff
                    .get(identity.source_id.as_str())
                    .copied()
                    .unwrap_or(false)
                    && !left.invalid_sources.contains(identity.source_id.as_str())
                    && !right.invalid_sources.contains(identity.source_id.as_str())
                    && before_sources
                        .get(identity.source_id.as_str())
                        .is_some_and(|source| source.status == InventorySourceStatus::Complete)
                    && after_sources
                        .get(identity.source_id.as_str())
                        .is_some_and(|source| source.status == InventorySourceStatus::Complete);
                if !source_complete {
                    counts.unmatched_rows_with_incomplete_source += 1;
                    complete = false;
                } else if before_row.is_some() {
                    push_delta(
                        &mut deltas,
                        PackageInventoryDelta {
                            kind: PackageChangeKind::Removed,
                            identity,
                            before: Some(package_facts(a)),
                            after: None,
                        },
                    )?;
                    counts.removals += 1;
                } else {
                    push_delta(
                        &mut deltas,
                        PackageInventoryDelta {
                            kind: PackageChangeKind::Added,
                            identity,
                            before: None,
                            after: Some(package_facts(a)),
                        },
                    )?;
                    counts.additions += 1;
                }
            }
            (None, None) => unreachable!("identity came from one of the maps"),
        }
    }

    if counts.unmatched_rows_with_incomplete_source > 0 {
        diagnostics.insert(PackageComparisonDiagnostic::SourceIncomplete);
    }
    Ok(PackageInventoryComparison {
        schema: "sideeffect.package_inventory_diff",
        schema_version: 1,
        before_captured_at_unix_ms: before.captured_at_unix_ms,
        after_captured_at_unix_ms: after.captured_at_unix_ms,
        status: if complete {
            PackageComparisonStatus::Complete
        } else {
            PackageComparisonStatus::Partial
        },
        coverage_note: "Comparison is limited to these snapshots and their listed sources; it does not establish exhaustive software coverage.",
        sources: source_comparisons,
        counts,
        diagnostics: diagnostics.into_iter().collect(),
        deltas,
    })
}

fn validate_document(document: &InventoryDocument) -> Result<(), PackageComparisonError> {
    if document.schema != INVENTORY_SCHEMA || document.schema_version != INVENTORY_SCHEMA_VERSION {
        return Err(PackageComparisonError::UnsupportedSchema);
    }
    if document.sources.len() > MAX_SOURCES {
        return Err(PackageComparisonError::SourceLimitExceeded);
    }
    if document.packages.len() > MAX_PACKAGES_PER_DOCUMENT {
        return Err(PackageComparisonError::PackageLimitExceeded);
    }
    let mut text_bytes = 0usize;
    for source in &document.sources {
        if source.id.len() > MAX_FIELD_BYTES {
            return Err(PackageComparisonError::FieldLimitExceeded);
        }
        text_bytes = text_bytes.saturating_add(source.id.len());
    }
    for package in &document.packages {
        for field in [
            Some(package.source_id),
            package.name.as_deref(),
            package.architecture.as_deref(),
            package.version.as_deref(),
            package.status_abbrev.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if field.len() > MAX_FIELD_BYTES {
                return Err(PackageComparisonError::FieldLimitExceeded);
            }
            text_bytes = text_bytes.saturating_add(field.len());
        }
    }
    if text_bytes > MAX_DOCUMENT_TEXT_BYTES {
        return Err(PackageComparisonError::DocumentTextLimitExceeded);
    }
    Ok(())
}

fn source_map(
    document: &InventoryDocument,
) -> Result<BTreeMap<&str, &super::model::InventorySource>, PackageComparisonError> {
    let mut result = BTreeMap::new();
    for source in &document.sources {
        if result.insert(source.id, source).is_some() {
            return Err(PackageComparisonError::DuplicateSourceId);
        }
    }
    Ok(result)
}

struct GroupedPackages<'a> {
    rows: BTreeMap<PackageIdentity, &'a InventoryPackage>,
    duplicates: BTreeSet<PackageIdentity>,
    invalid_rows: usize,
    invalid_sources: BTreeSet<String>,
    unknown_source_rows: usize,
}

fn grouped_packages<'a>(
    document: &'a InventoryDocument,
    sources: &BTreeMap<&str, &super::model::InventorySource>,
) -> Result<GroupedPackages<'a>, PackageComparisonError> {
    let mut grouped = GroupedPackages {
        rows: BTreeMap::new(),
        duplicates: BTreeSet::new(),
        invalid_rows: 0,
        invalid_sources: BTreeSet::new(),
        unknown_source_rows: 0,
    };
    for package in &document.packages {
        let Some(name) = package.name.as_deref().filter(|name| !name.is_empty()) else {
            grouped.invalid_rows += 1;
            grouped.invalid_sources.insert(package.source_id.to_owned());
            continue;
        };
        let identity = PackageIdentity {
            source_id: package.source_id.to_owned(),
            name: name.to_owned(),
            architecture: package.architecture.clone(),
        };
        if grouped.rows.insert(identity.clone(), package).is_some() {
            grouped.duplicates.insert(identity);
        }
    }
    // Rows from unknown source IDs cannot support absence claims. Exclude them while retaining
    // an explicit signal that this comparison has an unknown source.
    grouped.rows.retain(|identity, _| {
        let known = sources.contains_key(identity.source_id.as_str());
        if !known {
            grouped.unknown_source_rows += 1;
        }
        known
    });
    Ok(grouped)
}

fn package_facts(package: &InventoryPackage) -> PackageFacts {
    PackageFacts {
        version: package.version.clone(),
        status_abbrev: package.status_abbrev.clone(),
        evidence: evidence_reference(&package.evidence),
    }
}

fn evidence_reference(evidence: &InventoryEvidence) -> PackageEvidenceReference {
    PackageEvidenceReference {
        line: evidence.line,
        byte_offset: evidence.byte_offset,
        byte_length: evidence.byte_length,
    }
}

fn is_not_applicable(status: InventorySourceStatus) -> bool {
    status == InventorySourceStatus::NotApplicable
}

fn push_delta(
    deltas: &mut Vec<PackageInventoryDelta>,
    delta: PackageInventoryDelta,
) -> Result<(), PackageComparisonError> {
    if deltas.len() >= MAX_DELTAS {
        return Err(PackageComparisonError::DeltaLimitExceeded);
    }
    deltas.push(delta);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::model::{
        InventoryDiagnostic, InventoryEvidence, InventoryPackage, InventorySource, InventoryStatus,
    };

    fn document(
        status: InventorySourceStatus,
        packages: Vec<InventoryPackage>,
    ) -> InventoryDocument {
        InventoryDocument {
            schema: INVENTORY_SCHEMA,
            schema_version: INVENTORY_SCHEMA_VERSION,
            platform: "linux",
            scope: "available_package_manager_databases",
            captured_at_unix_ms: 10,
            status: if status == InventorySourceStatus::Complete {
                InventoryStatus::Complete
            } else {
                InventoryStatus::Partial
            },
            sources: vec![InventorySource {
                id: "dpkg_query",
                status,
                exit_code: Some(0),
                records_seen: packages.len(),
                diagnostics: Vec::<InventoryDiagnostic>::new(),
            }],
            packages,
        }
    }

    fn package(name: &str, version: &str, status: &str, line: usize) -> InventoryPackage {
        InventoryPackage {
            source_id: "dpkg_query",
            name: Some(name.into()),
            version: Some(version.into()),
            architecture: Some("amd64".into()),
            status_abbrev: Some(status.into()),
            evidence: InventoryEvidence {
                line,
                byte_offset: line * 10,
                byte_length: 8,
                record_sha256: "do-not-copy-this-fingerprint".into(),
                raw_record: Some("do-not-copy-raw".into()),
                raw_record_hex: None,
            },
            diagnostic_code: None,
        }
    }

    #[test]
    fn emits_sorted_add_remove_and_changed_deltas_with_evidence_tuple_only() {
        let before = document(
            InventorySourceStatus::Complete,
            vec![
                package("zeta", "1", "ii ", 1),
                package("alpha", "1", "ii ", 2),
            ],
        );
        let after = document(
            InventorySourceStatus::Complete,
            vec![
                package("alpha", "2", "ii ", 3),
                package("beta", "1", "ii ", 4),
            ],
        );
        let result = compare_package_inventories(&before, &after).unwrap();
        assert_eq!(result.status, PackageComparisonStatus::Complete);
        assert_eq!(result.counts.additions, 1);
        assert_eq!(result.counts.removals, 1);
        assert_eq!(result.counts.changes, 1);
        assert_eq!(result.deltas[0].identity.name, "alpha");
        assert_eq!(result.deltas[1].identity.name, "beta");
        assert_eq!(result.deltas[2].identity.name, "zeta");
        assert_eq!(
            result.deltas[0]
                .before
                .as_ref()
                .unwrap()
                .evidence
                .byte_offset,
            20
        );
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("do-not-copy"));
        assert!(!json.contains("record_sha256"));
        assert!(!json.contains("raw_record"));
    }

    #[test]
    fn incomplete_source_suppresses_additions_and_removals_but_keeps_observed_changes() {
        let before = document(
            InventorySourceStatus::Partial,
            vec![
                package("old", "1", "ii ", 1),
                package("same", "1", "ii ", 2),
            ],
        );
        let after = document(
            InventorySourceStatus::Complete,
            vec![
                package("new", "1", "ii ", 3),
                package("same", "2", "ii ", 4),
            ],
        );
        let result = compare_package_inventories(&before, &after).unwrap();
        assert_eq!(result.status, PackageComparisonStatus::Partial);
        assert_eq!(result.counts.additions, 0);
        assert_eq!(result.counts.removals, 0);
        assert_eq!(result.counts.changes, 1);
        assert_eq!(result.counts.unmatched_rows_with_incomplete_source, 2);
    }

    #[test]
    fn applicability_mismatch_suppresses_unmatched_claims() {
        let before = document(InventorySourceStatus::NotApplicable, vec![]);
        let after = document(
            InventorySourceStatus::Complete,
            vec![package("new", "1", "ii ", 1)],
        );
        let result = compare_package_inventories(&before, &after).unwrap();
        assert_eq!(result.status, PackageComparisonStatus::Partial);
        assert_eq!(result.counts.additions, 0);
        assert!(
            result
                .diagnostics
                .contains(&PackageComparisonDiagnostic::SourceApplicabilityDiffers)
        );
    }

    #[test]
    fn rejects_scope_and_oversized_fields() {
        let before = document(InventorySourceStatus::Complete, vec![]);
        let mut other_scope = before.clone();
        other_scope.scope = "different_scope";
        assert_eq!(
            compare_package_inventories(&before, &other_scope),
            Err(PackageComparisonError::ScopeMismatch)
        );
        let huge = "x".repeat(MAX_FIELD_BYTES + 1);
        let oversized = document(
            InventorySourceStatus::Complete,
            vec![package(&huge, "1", "ii ", 1)],
        );
        assert_eq!(
            compare_package_inventories(&before, &oversized),
            Err(PackageComparisonError::FieldLimitExceeded)
        );
    }

    #[test]
    fn rejects_oversized_document_text_budget() {
        let before = document(InventorySourceStatus::Complete, vec![]);
        let oversized = document(
            InventorySourceStatus::Complete,
            (0..9_000)
                .map(|index| package(&"x".repeat(MAX_FIELD_BYTES), "version", "ii ", index))
                .collect(),
        );
        assert_eq!(
            compare_package_inventories(&before, &oversized),
            Err(PackageComparisonError::DocumentTextLimitExceeded)
        );
    }

    #[test]
    fn duplicate_identity_is_ambiguous_and_not_emitted_as_delta() {
        let before = document(
            InventorySourceStatus::Complete,
            vec![
                package("same", "1", "ii ", 1),
                package("same", "2", "ii ", 2),
            ],
        );
        let after = document(InventorySourceStatus::Complete, vec![]);
        let result = compare_package_inventories(&before, &after).unwrap();
        assert_eq!(result.status, PackageComparisonStatus::Partial);
        assert_eq!(result.counts.removals, 0);
        assert_eq!(result.counts.ambiguous_identity_groups, 1);
        assert!(result.deltas.is_empty());
    }
}
