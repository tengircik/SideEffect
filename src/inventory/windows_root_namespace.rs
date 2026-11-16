//! Exact, bounded Windows selected-root namespace metadata for observation sessions.

use serde::{Deserialize, Serialize};

pub const WINDOWS_ROOT_NAMESPACE_SCHEMA: &str = "sideeffect.windows_root_namespace_identity";
pub const WINDOWS_ROOT_NAMESPACE_SCHEMA_VERSION: u32 = 1;
pub const WINDOWS_ROOT_NAMESPACE_MAX_BYTES: usize = 1024 * 1024;
pub const WINDOWS_ROOT_NAMESPACE_MAX_PATH_UTF16_UNITS: usize = 32_766;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRootNamespaceDocument {
    pub schema: String,
    pub schema_version: u32,
    pub platform: String,
    pub status: String,
    pub before: WindowsRootNamespaceSide,
    pub after: WindowsRootNamespaceSide,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRootNamespaceSide {
    pub status: String,
    pub root_snapshot_sha256: String,
    pub root_path_utf16le_hex: Option<String>,
    pub nt_path_utf16le_hex: Option<String>,
    pub volume_serial: Option<u64>,
    pub file_index: Option<u64>,
}

impl WindowsRootNamespaceDocument {
    pub fn new(before: WindowsRootNamespaceSide, after: WindowsRootNamespaceSide) -> Self {
        let mut diagnostics = Vec::new();
        if before.nt_path_utf16le_hex.is_none() {
            diagnostics.push("before_nt_root_path_unavailable".to_owned());
        }
        if after.nt_path_utf16le_hex.is_none() {
            diagnostics.push("after_nt_root_path_unavailable".to_owned());
        }
        if before.volume_serial.is_none_or(|value| value == 0)
            || before.file_index.is_none_or(|value| value == 0)
        {
            diagnostics.push("before_root_identity_hint_unavailable".to_owned());
        }
        if after.volume_serial.is_none_or(|value| value == 0)
            || after.file_index.is_none_or(|value| value == 0)
        {
            diagnostics.push("after_root_identity_hint_unavailable".to_owned());
        }
        let status = if diagnostics.is_empty()
            && before.status == "observed"
            && after.status == "observed"
        {
            "complete"
        } else {
            "partial"
        };
        Self {
            schema: WINDOWS_ROOT_NAMESPACE_SCHEMA.to_owned(),
            schema_version: WINDOWS_ROOT_NAMESPACE_SCHEMA_VERSION,
            platform: "windows".to_owned(),
            status: status.to_owned(),
            before,
            after,
            diagnostics,
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > WINDOWS_ROOT_NAMESPACE_MAX_BYTES {
            return Err("root_namespace_artifact_size_invalid");
        }
        let document: Self =
            serde_json::from_slice(bytes).map_err(|_| "root_namespace_artifact_malformed")?;
        if document.schema != WINDOWS_ROOT_NAMESPACE_SCHEMA
            || document.schema_version != WINDOWS_ROOT_NAMESPACE_SCHEMA_VERSION
            || document.platform != "windows"
            || !matches!(document.status.as_str(), "complete" | "partial")
            || document.diagnostics.len() > 8
            || document
                .diagnostics
                .iter()
                .any(|code| code.len() > 128 || !is_diagnostic_code(code))
            || !valid_side(&document.before)
            || !valid_side(&document.after)
        {
            return Err("root_namespace_artifact_invalid");
        }
        let expected = Self::new(document.before.clone(), document.after.clone());
        if document.status != expected.status || document.diagnostics != expected.diagnostics {
            return Err("root_namespace_artifact_status_invalid");
        }
        Ok(document)
    }
}

fn valid_side(side: &WindowsRootNamespaceSide) -> bool {
    matches!(side.status.as_str(), "observed" | "unavailable")
        && is_sha256(&side.root_snapshot_sha256)
        && side
            .root_path_utf16le_hex
            .as_deref()
            .is_none_or(|path| valid_utf16le_hex(path, WINDOWS_ROOT_NAMESPACE_MAX_PATH_UTF16_UNITS))
        && side
            .nt_path_utf16le_hex
            .as_deref()
            .is_none_or(|path| valid_utf16le_hex(path, WINDOWS_ROOT_NAMESPACE_MAX_PATH_UTF16_UNITS))
        && (side.nt_path_utf16le_hex.is_none() || side.status == "observed")
        && (side.root_path_utf16le_hex.is_some()
            || (side.nt_path_utf16le_hex.is_none()
                && side.volume_serial.is_none()
                && side.file_index.is_none()
                && side.status == "unavailable"))
        && side.volume_serial.is_none_or(|value| value != 0)
        && side.file_index.is_none_or(|value| value != 0)
}

fn valid_utf16le_hex(value: &str, max_units: usize) -> bool {
    !value.is_empty()
        && value.len() % 4 == 0
        && value.len() / 4 <= max_units
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && !value.as_bytes().chunks_exact(4).any(|unit| unit == b"0000")
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_diagnostic_code(value: &str) -> bool {
    matches!(
        value,
        "before_nt_root_path_unavailable"
            | "after_nt_root_path_unavailable"
            | "before_root_identity_hint_unavailable"
            | "after_root_identity_hint_unavailable"
    )
}

#[cfg(test)]
fn utf16le_hex(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(value.encode_utf16().count().saturating_mul(4));
    for unit in value.encode_utf16() {
        for byte in unit.to_le_bytes() {
            result.push(HEX[(byte >> 4) as usize] as char);
            result.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn side(path: &str, file_index: u64) -> WindowsRootNamespaceSide {
        WindowsRootNamespaceSide {
            status: "observed".to_owned(),
            root_snapshot_sha256: "a".repeat(64),
            root_path_utf16le_hex: Some(path.to_owned()),
            nt_path_utf16le_hex: Some(utf16le_hex("\\Device\\HarddiskVolume3\\dir")),
            volume_serial: Some(7),
            file_index: Some(file_index),
        }
    }

    #[test]
    fn namespace_document_round_trips_bounded_exact_handles() {
        let document = WindowsRootNamespaceDocument::new(
            side("43003a005c0072006f006f007400", 11),
            side("43003a005c0072006f006f007400", 11),
        );
        let bytes = serde_json::to_vec(&document).unwrap();
        assert_eq!(
            WindowsRootNamespaceDocument::parse(&bytes).unwrap(),
            document
        );
    }

    #[test]
    fn missing_nt_path_or_identity_is_explicitly_partial() {
        let mut before = side("43003a005c0072006f006f007400", 11);
        before.nt_path_utf16le_hex = None;
        before.status = "unavailable".to_owned();
        let document =
            WindowsRootNamespaceDocument::new(before, side("43003a005c0072006f006f007400", 11));
        assert_eq!(document.status, "partial");
        assert!(
            document
                .diagnostics
                .contains(&"before_nt_root_path_unavailable".to_owned())
        );
    }

    #[test]
    fn namespace_document_rejects_unbounded_paths_unknown_codes_and_digest_errors() {
        let mut document = WindowsRootNamespaceDocument::new(
            side("43003a005c0072006f006f007400", 11),
            side("43003a005c0072006f006f007400", 11),
        );
        document.before.nt_path_utf16le_hex =
            Some("5c00".repeat(WINDOWS_ROOT_NAMESPACE_MAX_PATH_UTF16_UNITS + 1));
        assert_eq!(
            WindowsRootNamespaceDocument::parse(&serde_json::to_vec(&document).unwrap()),
            Err("root_namespace_artifact_invalid")
        );

        let mut document = WindowsRootNamespaceDocument::new(
            side("43003a005c0072006f006f007400", 11),
            side("43003a005c0072006f006f007400", 11),
        );
        document.diagnostics.push("arbitrary free text".to_owned());
        assert_eq!(
            WindowsRootNamespaceDocument::parse(&serde_json::to_vec(&document).unwrap()),
            Err("root_namespace_artifact_invalid")
        );

        let mut document = WindowsRootNamespaceDocument::new(
            side("43003a005c0072006f006f007400", 11),
            side("43003a005c0072006f006f007400", 11),
        );
        document.after.root_snapshot_sha256 = "z".repeat(64);
        assert_eq!(
            WindowsRootNamespaceDocument::parse(&serde_json::to_vec(&document).unwrap()),
            Err("root_namespace_artifact_invalid")
        );
    }
}
