//! Strict, bounded case-file model for analyst-authored material.
//!
//! This module validates the shape and internal references in a case file. It
//! does not open audit sessions, verify artifact hashes, resolve evidence
//! locators, authenticate a producer, or establish that an assertion is true.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::audit_session::AUDIT_SESSION_SCHEMA_VERSION;

pub const CASE_SCHEMA: &str = "sideeffect.investigation_case";
pub const CASE_SCHEMA_V1: u32 = 1;
pub const CASE_SCHEMA_VERSION: u32 = 2;

pub const MAX_CASE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CASE_SESSIONS: usize = 16;
pub const MAX_CASE_ENTRIES: usize = 1_000;
pub const MAX_ENTRY_EVIDENCE: usize = 64;
pub const MAX_CASE_ID_BYTES: usize = 64;
pub const MAX_SESSION_ID_BYTES: usize = 32;
pub const MAX_TITLE_BYTES: usize = 512;
pub const MAX_ENTRY_TEXT_BYTES: usize = 16 * 1024;
pub const MAX_JSON_POINTER_BYTES: usize = 256;

/// A user-selected session identity. `manifest_sha256` binds this reference to
/// the exact manifest bytes later checked by a session reader; it is not a
/// signature or proof of who produced the session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSessionIdentity {
    pub session_id: String,
    pub platform: CasePlatform,
    pub manifest_schema_version: u32,
    pub manifest_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CasePlatform {
    Linux,
    Windows,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseEntryKind {
    Note,
    Assertion,
}

/// User-managed case workflow status. This does not describe evidence quality or truth.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Draft,
    Open,
    InReview,
    Closed,
    Cancelled,
}

impl CaseStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::InReview => "in_review",
            Self::Closed => "closed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Branch-local immutable revision metadata. The digest identifies exact prior file bytes; it
/// does not authenticate their author or prevent a case history from being forked or rewritten.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseLifecycle {
    pub status: CaseStatus,
    pub revision: u64,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub previous_case_sha256: Option<String>,
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl CaseLifecycle {
    pub fn validate(&self) -> Result<(), String> {
        if self.revision == 0 {
            return Err("case lifecycle revision must be positive".to_owned());
        }
        match (self.revision, self.previous_case_sha256.as_deref()) {
            (1, None) => Ok(()),
            (1, Some(_)) => Err("revision 1 must not have a previous case digest".to_owned()),
            (_, None) => Err("case revision after 1 requires previous_case_sha256".to_owned()),
            (_, Some(digest)) => validate_sha256("previous_case_sha256", digest),
        }
    }

    pub fn permits_transition(&self, next: CaseStatus) -> bool {
        matches!(
            (self.status, next),
            (CaseStatus::Draft, CaseStatus::Open | CaseStatus::Cancelled)
                | (
                    CaseStatus::Open,
                    CaseStatus::InReview | CaseStatus::Closed | CaseStatus::Cancelled
                )
                | (
                    CaseStatus::InReview,
                    CaseStatus::Open | CaseStatus::Closed | CaseStatus::Cancelled
                )
        )
    }

    pub fn permits_entry(&self) -> bool {
        matches!(self.status, CaseStatus::Draft | CaseStatus::Open)
    }
}

/// This is an author's severity assessment, not a system-derived risk rating.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// Confidence is kept independent from severity and is supplied by the author.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseEntry {
    pub id: String,
    pub kind: CaseEntryKind,
    /// Must be the literal `analyst_supplied_unverified` for every entry.
    pub authorship: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    #[serde(default)]
    pub evidence: Vec<CaseEvidenceLocator>,
}

/// Evidence locators point to source-native records or rows. They are
/// references only: the case parser validates field shape and platform
/// compatibility, while a caller must resolve them against verified artifacts.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaseEvidenceLocator {
    LinuxTraceRecord {
        session_id: String,
        manifest_sha256: String,
        artifact_sha256: String,
        line_number: u64,
        byte_offset: u64,
        byte_length: u64,
    },
    WindowsEtwRecord {
        session_id: String,
        manifest_sha256: String,
        artifact_sha256: String,
        capture_sha256: String,
        record_ordinal: u64,
        json_pointer: String,
        raw_payload_sha256: String,
    },
    SelectedRootEntry {
        session_id: String,
        manifest_sha256: String,
        artifact_sha256: String,
        entry_ordinal: u64,
    },
}

impl CaseEvidenceLocator {
    fn session_binding(&self) -> (&str, &str) {
        match self {
            Self::LinuxTraceRecord {
                session_id,
                manifest_sha256,
                ..
            }
            | Self::WindowsEtwRecord {
                session_id,
                manifest_sha256,
                ..
            }
            | Self::SelectedRootEntry {
                session_id,
                manifest_sha256,
                ..
            } => (session_id, manifest_sha256),
        }
    }

    fn validate(&self) -> Result<(), String> {
        match self {
            Self::LinuxTraceRecord {
                artifact_sha256,
                manifest_sha256,
                line_number,
                byte_offset,
                byte_length,
                ..
            } => {
                validate_sha256("manifest_sha256", manifest_sha256)?;
                validate_sha256("artifact_sha256", artifact_sha256)?;
                if *line_number == 0
                    || *line_number > crate::limits::MAX_TRACE_BYTES as u64
                    || *byte_length == 0
                    || byte_offset
                        .checked_add(*byte_length)
                        .is_none_or(|end| end > crate::limits::MAX_TRACE_BYTES as u64)
                {
                    return Err(
                        "linux_trace_record locator has an invalid line or byte range".to_owned(),
                    );
                }
            }
            Self::WindowsEtwRecord {
                artifact_sha256,
                manifest_sha256,
                capture_sha256,
                record_ordinal,
                json_pointer,
                raw_payload_sha256,
                ..
            } => {
                validate_sha256("manifest_sha256", manifest_sha256)?;
                validate_sha256("artifact_sha256", artifact_sha256)?;
                validate_sha256("capture_sha256", capture_sha256)?;
                validate_sha256("raw_payload_sha256", raw_payload_sha256)?;
                if *record_ordinal == 0
                    || *record_ordinal > crate::windows_runtime::MAX_WINDOWS_RUNTIME_EVENTS as u64
                    || json_pointer.is_empty()
                    || json_pointer.len() > MAX_JSON_POINTER_BYTES
                    || !json_pointer.starts_with('/')
                    || json_pointer.chars().any(char::is_control)
                    || json_pointer.as_str() != format!("/events/{}", record_ordinal - 1)
                {
                    return Err(
                        "windows_etw_record locator has an invalid ordinal or JSON pointer"
                            .to_owned(),
                    );
                }
            }
            Self::SelectedRootEntry {
                artifact_sha256,
                manifest_sha256,
                entry_ordinal,
                ..
            } => {
                validate_sha256("manifest_sha256", manifest_sha256)?;
                validate_sha256("artifact_sha256", artifact_sha256)?;
                if *entry_ordinal >= crate::inventory::MAX_ROOT_ENTRIES as u64 {
                    return Err(format!(
                        "selected_root_entry ordinal must be less than {}",
                        crate::inventory::MAX_ROOT_ENTRIES,
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationCase {
    pub schema: String,
    pub schema_version: u32,
    pub case_id: String,
    pub title: String,
    pub sessions: Vec<CaseSessionIdentity>,
    pub entries: Vec<CaseEntry>,
    /// Absent only in schema v1. V2 requires this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<CaseLifecycle>,
}

impl InvestigationCase {
    /// Parse one bounded JSON case document and validate its internal contract.
    /// Session and artifact verification must be done by the caller.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_CASE_BYTES {
            return Err(format!(
                "case input exceeds the {MAX_CASE_BYTES}-byte limit"
            ));
        }
        let case: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid case JSON".to_owned())?;
        case.validate()?;
        Ok(case)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CASE_SCHEMA
            || !matches!(self.schema_version, CASE_SCHEMA_V1 | CASE_SCHEMA_VERSION)
        {
            return Err(format!(
                "case schema must be {CASE_SCHEMA} version {CASE_SCHEMA_V1} or {CASE_SCHEMA_VERSION}"
            ));
        }
        match (self.schema_version, &self.lifecycle) {
            (CASE_SCHEMA_V1, None) => {}
            (CASE_SCHEMA_V1, Some(_)) => {
                return Err("case schema version 1 must not contain lifecycle".to_owned());
            }
            (CASE_SCHEMA_VERSION, Some(lifecycle)) => lifecycle.validate()?,
            (CASE_SCHEMA_VERSION, None) => {
                return Err("case schema version 2 requires lifecycle".to_owned());
            }
            _ => unreachable!("schema version was checked above"),
        }
        validate_identifier("case_id", &self.case_id, MAX_CASE_ID_BYTES)?;
        validate_text("title", &self.title, MAX_TITLE_BYTES)?;
        if self.sessions.is_empty() || self.sessions.len() > MAX_CASE_SESSIONS {
            return Err(format!(
                "case must reference 1..={MAX_CASE_SESSIONS} sessions"
            ));
        }
        if self.entries.len() > MAX_CASE_ENTRIES {
            return Err(format!(
                "case contains more than {MAX_CASE_ENTRIES} entries"
            ));
        }

        let platform = self.sessions[0].platform;
        let mut sessions = HashSet::with_capacity(self.sessions.len());
        let mut session_ids = HashSet::with_capacity(self.sessions.len());
        for session in &self.sessions {
            if !valid_session_id(&session.session_id) {
                return Err("session_id must be 32 lowercase hexadecimal characters".to_owned());
            }
            if !session_ids.insert(session.session_id.as_str()) {
                return Err("case contains duplicate session IDs".to_owned());
            }
            sessions.insert((
                session.session_id.as_str(),
                session.manifest_sha256.as_str(),
            ));
            if session.platform != platform {
                return Err("case sessions must use one native platform".to_owned());
            }
            if !(1..=AUDIT_SESSION_SCHEMA_VERSION).contains(&session.manifest_schema_version) {
                return Err(format!(
                    "manifest_schema_version must be between 1 and {AUDIT_SESSION_SCHEMA_VERSION}"
                ));
            }
            validate_sha256("manifest_sha256", &session.manifest_sha256)?;
        }

        let mut entry_ids = HashSet::with_capacity(self.entries.len());
        for entry in &self.entries {
            validate_identifier("entry id", &entry.id, MAX_CASE_ID_BYTES)?;
            if !entry_ids.insert(entry.id.as_str()) {
                return Err("case contains duplicate entry IDs".to_owned());
            }
            if entry.authorship != "analyst_supplied_unverified" {
                return Err("entry authorship must be analyst_supplied_unverified".to_owned());
            }
            validate_text("entry text", &entry.text, MAX_ENTRY_TEXT_BYTES)?;
            if entry.evidence.len() > MAX_ENTRY_EVIDENCE {
                return Err(format!(
                    "entry {} contains more than {MAX_ENTRY_EVIDENCE} evidence references",
                    entry.id
                ));
            }
            if entry.kind == CaseEntryKind::Assertion && entry.evidence.is_empty() {
                return Err(format!(
                    "assertion {} must contain at least one evidence reference",
                    entry.id
                ));
            }
            let mut locators = HashSet::with_capacity(entry.evidence.len());
            for locator in &entry.evidence {
                locator.validate()?;
                if !sessions.contains(&locator.session_binding()) {
                    return Err(format!(
                        "entry {} evidence references a session not listed in the case",
                        entry.id
                    ));
                }
                let locator_platform = match locator {
                    CaseEvidenceLocator::LinuxTraceRecord { .. } => CasePlatform::Linux,
                    CaseEvidenceLocator::WindowsEtwRecord { .. } => CasePlatform::Windows,
                    CaseEvidenceLocator::SelectedRootEntry { .. } => platform,
                };
                if locator_platform != platform {
                    return Err(format!(
                        "entry {} evidence locator does not match the case platform",
                        entry.id
                    ));
                }
                if !locators.insert(locator) {
                    return Err(format!(
                        "entry {} contains a duplicate evidence reference",
                        entry.id
                    ));
                }
            }
        }
        Ok(())
    }
}

fn validate_identifier(label: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(format!(
            "{label} must contain 1..={max_bytes} ASCII letters, digits, '_' or '-'"
        ));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(|ch| ch == '\0') {
        return Err(format!(
            "{label} must be non-empty, at most {max_bytes} UTF-8 bytes, and contain no NUL"
        ));
    }
    Ok(())
}

fn validate_session_id(value: &str) -> Result<(), String> {
    if value.len() != MAX_SESSION_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("session_id must be 32 lowercase hexadecimal characters".to_owned());
    }
    Ok(())
}

fn valid_session_id(value: &str) -> bool {
    validate_session_id(value).is_ok()
}

fn validate_sha256(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}
