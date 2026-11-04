//! Conservative comparison of current-user Windows AppX/MSIX registrations.

use serde::{Deserialize, Serialize, de};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};

const SCHEMA: &str = "sideeffect.windows_msix_inventory";
const SCOPE: &str = "current_user_registered_appx_and_msix_packages_only";
const SOURCE: &str = "current_user_appx_msix_packages";
const MAX_PAIR_BYTES: usize = 64 * 1024 * 1024;
const MAX_ROWS: usize = 4_096;
const MAX_DIAGNOSTICS: usize = 512;
const MAX_STRING_UNITS: usize = 32_768;
const MAX_DELTAS: usize = 8_192;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsMsixComparisonStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsMsixChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsMsixComparisonDiagnostic {
    SourceIncomplete,
    InvalidIdentity,
    DuplicateIdentity,
    MatchedMetadataIncomplete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsMsixIdentity {
    pub family_name_utf16_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsMsixEvidenceReference {
    pub source_id: String,
    pub package_ordinal: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsMsixFacts {
    pub name_utf16_sha256: Option<String>,
    pub publisher_utf16_sha256: Option<String>,
    pub full_name_utf16_sha256: Option<String>,
    pub install_location_utf16_sha256: Option<String>,
    pub version: Option<Version>,
    pub is_framework: Option<bool>,
    pub is_resource_package: Option<bool>,
    pub is_bundle: Option<bool>,
    pub is_development_mode: Option<bool>,
    pub evidence: WindowsMsixEvidenceReference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsMsixDelta {
    pub kind: WindowsMsixChangeKind,
    pub identity: WindowsMsixIdentity,
    pub changed_fields: Vec<String>,
    pub before: Option<WindowsMsixFacts>,
    pub after: Option<WindowsMsixFacts>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsMsixCounts {
    pub additions: usize,
    pub removals: usize,
    pub changes: usize,
    pub unmatched_rows_with_incomplete_source: usize,
    pub invalid_identity_rows: usize,
    pub ambiguous_identity_groups: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsMsixInventoryComparison {
    pub schema: &'static str,
    pub schema_version: u32,
    pub before_captured_at_unix_ms: u128,
    pub after_captured_at_unix_ms: u128,
    pub status: WindowsMsixComparisonStatus,
    pub coverage_note: &'static str,
    pub counts: WindowsMsixCounts,
    pub diagnostics: Vec<WindowsMsixComparisonDiagnostic>,
    pub deltas: Vec<WindowsMsixDelta>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsMsixComparisonError {
    MalformedInput,
    InputTooLarge,
    UnsupportedSchema,
    Incompatible,
    LimitExceeded,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    schema_version: u32,
    platform: String,
    scope: String,
    capture_started_at_unix_ms: u128,
    capture_ended_at_unix_ms: u128,
    status: Status,
    #[serde(deserialize_with = "bounded_sources")]
    sources: Vec<SourceRecord>,
    #[serde(deserialize_with = "bounded_packages")]
    packages: Vec<Package>,
}
#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Complete,
    Partial,
    Inaccessible,
    Unavailable,
    Error,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRecord {
    id: String,
    status: Status,
    packages_seen: usize,
    scope: String,
    #[serde(deserialize_with = "bounded_diagnostics")]
    diagnostics: Vec<Diagnostic>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Diagnostic {
    code: String,
    package_ordinal: Option<usize>,
    field: Option<String>,
    message: String,
    #[serde(rename = "hresult")]
    _hresult: Option<i32>,
}
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct StringEvidence {
    text: String,
    utf16_hex: String,
    display_replaced_invalid_utf16: bool,
}
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Package {
    ordinal: usize,
    name: Option<StringEvidence>,
    publisher: Option<StringEvidence>,
    full_name: Option<StringEvidence>,
    family_name: Option<StringEvidence>,
    install_location: Option<StringEvidence>,
    version: Option<Version>,
    is_framework: Option<bool>,
    is_resource_package: Option<bool>,
    is_bundle: Option<bool>,
    is_development_mode: Option<bool>,
}

pub fn compare_windows_msix_inventory_json(
    left: &[u8],
    right: &[u8],
) -> Result<WindowsMsixInventoryComparison, WindowsMsixComparisonError> {
    if left.len().saturating_add(right.len()) > MAX_PAIR_BYTES {
        return Err(WindowsMsixComparisonError::InputTooLarge);
    }
    let before: Document =
        serde_json::from_slice(left).map_err(|_| WindowsMsixComparisonError::MalformedInput)?;
    let after: Document =
        serde_json::from_slice(right).map_err(|_| WindowsMsixComparisonError::MalformedInput)?;
    compare_documents(before, after)
}

fn compare_documents(
    before: Document,
    after: Document,
) -> Result<WindowsMsixInventoryComparison, WindowsMsixComparisonError> {
    for doc in [&before, &after] {
        if doc.schema != SCHEMA || doc.schema_version != 1 {
            return Err(WindowsMsixComparisonError::UnsupportedSchema);
        }
        if doc.platform != "windows" || doc.scope != SCOPE {
            return Err(WindowsMsixComparisonError::Incompatible);
        }
        if doc.capture_ended_at_unix_ms < doc.capture_started_at_unix_ms
            || doc.sources.len() != 1
            || doc.sources[0].id != SOURCE
            || doc.sources[0].scope != "calling_user_only"
            || doc.packages.len() > MAX_ROWS
            || doc.sources[0].packages_seen > MAX_ROWS
            || doc.sources[0].diagnostics.len() > MAX_DIAGNOSTICS
        {
            return Err(WindowsMsixComparisonError::MalformedInput);
        }
        if doc.status != doc.sources[0].status
            || (doc.status == Status::Complete && !doc.sources[0].diagnostics.is_empty())
        {
            return Err(WindowsMsixComparisonError::MalformedInput);
        }
        if doc.sources[0].packages_seen < doc.packages.len() {
            return Err(WindowsMsixComparisonError::MalformedInput);
        }
        for (index, row) in doc.packages.iter().enumerate() {
            if row.ordinal >= MAX_ROWS
                || row.ordinal >= doc.sources[0].packages_seen
                || row.ordinal != index
            {
                return Err(WindowsMsixComparisonError::MalformedInput);
            }
            for field in [
                &row.name,
                &row.publisher,
                &row.full_name,
                &row.family_name,
                &row.install_location,
            ]
            .into_iter()
            .flatten()
            {
                if !valid_string(field) {
                    return Err(WindowsMsixComparisonError::MalformedInput);
                }
            }
        }
        for diag in &doc.sources[0].diagnostics {
            if diag.code.len() > 256
                || diag.message.len() > 4096
                || diag.field.as_ref().is_some_and(|s| s.len() > 128)
                || diag.package_ordinal.is_some_and(|i| i >= MAX_ROWS)
            {
                return Err(WindowsMsixComparisonError::MalformedInput);
            }
        }
    }
    let mut counts = WindowsMsixCounts {
        additions: 0,
        removals: 0,
        changes: 0,
        unmatched_rows_with_incomplete_source: 0,
        invalid_identity_rows: 0,
        ambiguous_identity_groups: 0,
    };
    let mut diagnostics = BTreeSet::new();
    let left_complete = before.status == Status::Complete
        && before.sources[0].status == Status::Complete
        && before.sources[0].packages_seen == before.packages.len();
    let right_complete = after.status == Status::Complete
        && after.sources[0].status == Status::Complete
        && after.sources[0].packages_seen == after.packages.len();
    if !left_complete || !right_complete {
        diagnostics.insert(WindowsMsixComparisonDiagnostic::SourceIncomplete);
    }
    let (left_map, left_ambiguous) = index(&before.packages, &mut counts);
    let (right_map, right_ambiguous) = index(&after.packages, &mut counts);
    let presence_safe = left_complete && right_complete && counts.invalid_identity_rows == 0;
    let ambiguous: BTreeSet<_> = left_ambiguous.union(&right_ambiguous).cloned().collect();
    counts.ambiguous_identity_groups = ambiguous.len();
    if counts.invalid_identity_rows > 0 {
        diagnostics.insert(WindowsMsixComparisonDiagnostic::InvalidIdentity);
    }
    if counts.ambiguous_identity_groups > 0 {
        diagnostics.insert(WindowsMsixComparisonDiagnostic::DuplicateIdentity);
    }
    let mut deltas = Vec::new();
    let identities: BTreeSet<_> = left_map.keys().chain(right_map.keys()).cloned().collect();
    for id in identities {
        if ambiguous.contains(&id) {
            continue;
        }
        match (left_map.get(&id), right_map.get(&id)) {
            (Some(a), Some(b)) => {
                if !complete_facts(a) || !complete_facts(b) {
                    diagnostics.insert(WindowsMsixComparisonDiagnostic::MatchedMetadataIncomplete);
                }
                let af = facts(a);
                let bf = facts(b);
                let fields = changed_fields(&af, &bf);
                if !fields.is_empty() {
                    deltas.push(WindowsMsixDelta {
                        kind: WindowsMsixChangeKind::Changed,
                        identity: identity(&id),
                        changed_fields: fields,
                        before: Some(af),
                        after: Some(bf),
                    });
                    counts.changes += 1;
                }
            }
            (Some(a), None) if presence_safe => {
                deltas.push(WindowsMsixDelta {
                    kind: WindowsMsixChangeKind::Removed,
                    identity: identity(&id),
                    changed_fields: vec![],
                    before: Some(facts(a)),
                    after: None,
                });
                counts.removals += 1;
            }
            (None, Some(b)) if presence_safe => {
                deltas.push(WindowsMsixDelta {
                    kind: WindowsMsixChangeKind::Added,
                    identity: identity(&id),
                    changed_fields: vec![],
                    before: None,
                    after: Some(facts(b)),
                });
                counts.additions += 1;
            }
            (Some(_), None) | (None, Some(_)) => counts.unmatched_rows_with_incomplete_source += 1,
            (None, None) => {}
        }
        if deltas.len() > MAX_DELTAS {
            return Err(WindowsMsixComparisonError::LimitExceeded);
        }
    }
    Ok(WindowsMsixInventoryComparison {
        schema: "sideeffect.windows_msix_inventory_diff",
        schema_version: 1,
        before_captured_at_unix_ms: before.capture_started_at_unix_ms,
        after_captured_at_unix_ms: after.capture_started_at_unix_ms,
        status: if diagnostics.is_empty() {
            WindowsMsixComparisonStatus::Complete
        } else {
            WindowsMsixComparisonStatus::Partial
        },
        coverage_note: "Compares current-user package registrations by exact valid family-name UTF-16 identity; registration does not establish availability, launchability, health, or execution.",
        counts,
        diagnostics: diagnostics.into_iter().collect(),
        deltas,
    })
}

fn valid_string(value: &StringEvidence) -> bool {
    if value.text.len() > MAX_STRING_UNITS * 4
        || value.utf16_hex.len() > MAX_STRING_UNITS * 4
        || value.utf16_hex.len() % 4 != 0
        || !value.utf16_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return false;
    }
    let units: Vec<u16> = value
        .utf16_hex
        .as_bytes()
        .chunks_exact(4)
        .map(|c| u16::from_str_radix(std::str::from_utf8(c).unwrap_or(""), 16).unwrap_or(0))
        .collect();
    if units.len() > MAX_STRING_UNITS {
        return false;
    }
    let decoded = String::from_utf16(&units);
    match decoded {
        Ok(text) => !value.display_replaced_invalid_utf16 && value.text == text,
        Err(_) => {
            value.display_replaced_invalid_utf16 && value.text == String::from_utf16_lossy(&units)
        }
    }
}
fn key(row: &Package) -> Option<String> {
    let evidence = row.family_name.as_ref()?;
    if evidence.display_replaced_invalid_utf16 || evidence.utf16_hex.is_empty() {
        return None;
    };
    Some(evidence.utf16_hex.to_ascii_lowercase())
}
fn complete_facts(row: &Package) -> bool {
    row.name.is_some()
        && row.publisher.is_some()
        && row.full_name.is_some()
        && row.install_location.is_some()
        && row.version.is_some()
        && row.is_framework.is_some()
        && row.is_resource_package.is_some()
        && row.is_bundle.is_some()
        && row.is_development_mode.is_some()
}
fn index<'a>(
    rows: &'a [Package],
    counts: &mut WindowsMsixCounts,
) -> (BTreeMap<String, &'a Package>, BTreeSet<String>) {
    let mut groups: BTreeMap<String, Vec<&Package>> = BTreeMap::new();
    for row in rows {
        if let Some(key) = key(row) {
            groups.entry(key).or_default().push(row)
        } else {
            counts.invalid_identity_rows += 1;
        }
    }
    let mut indexed = BTreeMap::new();
    let mut ambiguous = BTreeSet::new();
    for (key, rows) in groups {
        if rows.len() == 1 {
            indexed.insert(key, rows[0]);
        } else {
            ambiguous.insert(key);
        }
    }
    (indexed, ambiguous)
}
fn hash(value: Option<&StringEvidence>) -> Option<String> {
    value.map(|v| {
        format!(
            "{:x}",
            sha2::Sha256::digest(v.utf16_hex.to_ascii_lowercase().as_bytes())
        )
    })
}
fn identity(key: &str) -> WindowsMsixIdentity {
    WindowsMsixIdentity {
        family_name_utf16_sha256: format!("{:x}", sha2::Sha256::digest(key.as_bytes())),
    }
}
fn facts(row: &Package) -> WindowsMsixFacts {
    WindowsMsixFacts {
        name_utf16_sha256: hash(row.name.as_ref()),
        publisher_utf16_sha256: hash(row.publisher.as_ref()),
        full_name_utf16_sha256: hash(row.full_name.as_ref()),
        install_location_utf16_sha256: hash(row.install_location.as_ref()),
        version: row.version.clone(),
        is_framework: row.is_framework,
        is_resource_package: row.is_resource_package,
        is_bundle: row.is_bundle,
        is_development_mode: row.is_development_mode,
        evidence: WindowsMsixEvidenceReference {
            source_id: SOURCE.into(),
            package_ordinal: row.ordinal,
        },
    }
}
fn changed_fields(a: &WindowsMsixFacts, b: &WindowsMsixFacts) -> Vec<String> {
    let mut fields = Vec::new();
    macro_rules! field {
        ($name:literal,$left:expr,$right:expr) => {
            if $left.is_some() && $right.is_some() && $left != $right {
                fields.push($name.into())
            }
        };
    }
    field!("name", a.name_utf16_sha256, b.name_utf16_sha256);
    field!(
        "publisher",
        a.publisher_utf16_sha256,
        b.publisher_utf16_sha256
    );
    field!(
        "full_name",
        a.full_name_utf16_sha256,
        b.full_name_utf16_sha256
    );
    field!(
        "install_location",
        a.install_location_utf16_sha256,
        b.install_location_utf16_sha256
    );
    field!("version", a.version, b.version);
    field!("is_framework", a.is_framework, b.is_framework);
    field!(
        "is_resource_package",
        a.is_resource_package,
        b.is_resource_package
    );
    field!("is_bundle", a.is_bundle, b.is_bundle);
    field!(
        "is_development_mode",
        a.is_development_mode,
        b.is_development_mode
    );
    fields
}
fn bounded_sources<'de, D>(d: D) -> Result<Vec<SourceRecord>, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserialize_bounded::<_, _, 1>(d)
}
fn bounded_packages<'de, D>(d: D) -> Result<Vec<Package>, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserialize_bounded::<_, _, MAX_ROWS>(d)
}
fn bounded_diagnostics<'de, D>(d: D) -> Result<Vec<Diagnostic>, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserialize_bounded::<_, _, MAX_DIAGNOSTICS>(d)
}
fn deserialize_bounded<'de, D, T, const MAX: usize>(d: D) -> Result<Vec<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T, const N: usize>(std::marker::PhantomData<T>);
    impl<'de, T, const N: usize> de::Visitor<'de> for Visitor<T, N>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "a sequence with at most {N} entries")
        }
        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<T>, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(N));
            while let Some(item) = seq.next_element()? {
                if out.len() >= N {
                    return Err(de::Error::custom("sequence limit exceeded"));
                }
                out.push(item)
            }
            Ok(out)
        }
    }
    d.deserialize_seq(Visitor::<T, MAX>(std::marker::PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::fmt::Write as _;
    fn str_ev(text: &str, hex: &str) -> Value {
        json!({"text":text,"utf16_hex":hex,"display_replaced_invalid_utf16":false})
    }
    fn hex(text: &str) -> String {
        let mut output = String::with_capacity(text.encode_utf16().count() * 4);
        for unit in text.encode_utf16() {
            write!(&mut output, "{unit:04x}").unwrap();
        }
        output
    }
    fn row(ordinal: usize, version: u16) -> Value {
        let full_name = format!("Demo_{}_neutral__pub", version);
        let install_location = "C:\\Apps\\Demo";
        json!({"ordinal":ordinal,"name":str_ev("Demo",&hex("Demo")),"publisher":str_ev("Publisher",&hex("Publisher")),"full_name":str_ev(&full_name,&hex(&full_name)),"family_name":str_ev("Demo_pub",&hex("Demo_pub")),"install_location":str_ev(install_location,&hex(install_location)),"version":{"major":version,"minor":0,"build":0,"revision":0},"is_framework":false,"is_resource_package":false,"is_bundle":false,"is_development_mode":false})
    }
    fn doc(rows: Vec<Value>, status: &str, seen: usize) -> Vec<u8> {
        serde_json::to_vec(&json!({"schema":SCHEMA,"schema_version":1,"platform":"windows","scope":SCOPE,"capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":status,"sources":[{"id":SOURCE,"status":status,"packages_seen":seen,"scope":"calling_user_only","diagnostics":[]}],"packages":rows})).unwrap()
    }
    #[test]
    fn compares_version_and_metadata_by_exact_family_utf16_with_both_evidence_refs() {
        let a = doc(vec![row(0, 1)], "complete", 1);
        let b = doc(vec![row(0, 2)], "complete", 1);
        let parsed: Document = serde_json::from_slice(&a).unwrap();
        assert!(valid_string(parsed.packages[0].name.as_ref().unwrap()));
        assert!(valid_string(parsed.packages[0].publisher.as_ref().unwrap()));
        assert!(valid_string(parsed.packages[0].full_name.as_ref().unwrap()));
        assert!(valid_string(
            parsed.packages[0].family_name.as_ref().unwrap()
        ));
        assert!(valid_string(
            parsed.packages[0].install_location.as_ref().unwrap()
        ));
        let result = compare_windows_msix_inventory_json(&a, &b).unwrap();
        assert_eq!(result.status, WindowsMsixComparisonStatus::Complete);
        assert_eq!(result.counts.changes, 1);
        assert!(result.deltas[0].changed_fields.contains(&"version".into()));
        assert_eq!(
            result.deltas[0]
                .before
                .as_ref()
                .unwrap()
                .evidence
                .package_ordinal,
            0
        );
        assert_eq!(
            result.deltas[0].after.as_ref().unwrap().evidence.source_id,
            SOURCE
        );
    }
    #[test]
    fn complete_sources_report_add_remove_but_duplicates_and_missing_identity_suppress() {
        let before = doc(vec![row(0, 1)], "complete", 1);
        let after = doc(vec![], "complete", 0);
        let removed = compare_windows_msix_inventory_json(&before, &after).unwrap();
        assert_eq!(removed.counts.removals, 1);
        let added = compare_windows_msix_inventory_json(&after, &before).unwrap();
        assert_eq!(added.counts.additions, 1);
        let duplicate = doc(vec![row(0, 1), row(1, 2)], "complete", 2);
        let suppressed = compare_windows_msix_inventory_json(&duplicate, &after).unwrap();
        assert_eq!(suppressed.counts.removals, 0);
        assert_eq!(suppressed.counts.ambiguous_identity_groups, 1);
        let mut missing: Value = serde_json::from_slice(&before).unwrap();
        missing["packages"][0]["family_name"] = Value::Null;
        let missing = serde_json::to_vec(&missing).unwrap();
        let suppressed = compare_windows_msix_inventory_json(&missing, &after).unwrap();
        assert_eq!(suppressed.counts.removals, 0);
        assert_eq!(suppressed.counts.invalid_identity_rows, 1);
        let mut empty: Value = serde_json::from_slice(&before).unwrap();
        empty["packages"][0]["family_name"] = str_ev("", "");
        let empty = serde_json::to_vec(&empty).unwrap();
        let suppressed = compare_windows_msix_inventory_json(&empty, &after).unwrap();
        assert_eq!(suppressed.counts.removals, 0);
        assert_eq!(suppressed.counts.invalid_identity_rows, 1);
        let suppressed = compare_windows_msix_inventory_json(&empty, &before).unwrap();
        assert_eq!(suppressed.counts.additions, 0);
        assert_eq!(suppressed.counts.unmatched_rows_with_incomplete_source, 1);
    }
    #[test]
    fn partial_sources_suppress_presence_and_malformed_or_oversized_inputs_fail_closed() {
        let a = doc(vec![row(0, 1)], "partial", 1);
        let b = doc(vec![], "complete", 0);
        let partial = compare_windows_msix_inventory_json(&a, &b).unwrap();
        assert_eq!(partial.status, WindowsMsixComparisonStatus::Partial);
        assert_eq!(partial.counts.unmatched_rows_with_incomplete_source, 1);
        let partial_add = compare_windows_msix_inventory_json(&b, &a).unwrap();
        assert_eq!(partial_add.counts.additions, 0);
        assert_eq!(partial_add.counts.unmatched_rows_with_incomplete_source, 1);
        assert!(matches!(
            compare_windows_msix_inventory_json(b"{", b"{}"),
            Err(WindowsMsixComparisonError::MalformedInput)
        ));
        let diagnostics: Value = serde_json::from_slice(&doc(vec![], "complete", 0)).unwrap();
        let mut inconsistent = diagnostics;
        inconsistent["sources"][0]["diagnostics"] =
            json!([{"code":"unexpected","message":"source claims complete despite a diagnostic"}]);
        let inconsistent = serde_json::to_vec(&inconsistent).unwrap();
        assert!(matches!(
            compare_windows_msix_inventory_json(&inconsistent, &inconsistent),
            Err(WindowsMsixComparisonError::MalformedInput)
        ));
        let valid = String::from_utf8(doc(vec![], "complete", 0)).unwrap();
        let duplicate_key = valid.replacen(
            "\"schema\":\"sideeffect.windows_msix_inventory\"",
            "\"schema\":\"sideeffect.windows_msix_inventory\",\"schema\":\"sideeffect.windows_msix_inventory\"",
            1,
        );
        assert!(matches!(
            compare_windows_msix_inventory_json(duplicate_key.as_bytes(), b"{}"),
            Err(WindowsMsixComparisonError::MalformedInput)
        ));
        assert!(matches!(
            compare_windows_msix_inventory_json(&vec![b' '; MAX_PAIR_BYTES + 1], b""),
            Err(WindowsMsixComparisonError::InputTooLarge)
        ));
    }
}
