//! Additive state contract shared by native startup inventory rows.
//!
//! Current collectors prove that each emitted row is configured. They do not
//! establish applicability under a live manager context or directly link a
//! runtime event to the configured row, so the other state dimensions stay
//! explicitly unknown.

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct StartupRowState {
    pub schema_version: u32,
    pub configured: ConfiguredStatus,
    pub effective: EffectiveState,
    pub observed: ObservedState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfiguredStatus {
    Present,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveStatus {
    Unknown,
    Effective,
    NotEffective,
}

#[derive(Clone, Debug, Serialize)]
pub struct EffectiveState {
    pub status: EffectiveStatus,
    /// Required when status is known; identifies the bounded policy context.
    pub context: Option<String>,
    /// Source artifact locator supporting a known result.
    pub evidence: Option<StartupStateEvidenceReference>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedStatus {
    Unknown,
    Observed,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObservedState {
    pub status: ObservedStatus,
    /// Bounded runtime capture interval containing the linked event.
    pub capture_interval: Option<StartupStateCaptureInterval>,
    /// Direct runtime evidence; candidate correlations are not sufficient.
    pub evidence: Option<StartupStateEvidenceReference>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StartupStateCaptureInterval {
    pub started_at_unix_ms: u128,
    pub ended_at_unix_ms: u128,
}

#[derive(Clone, Debug, Serialize)]
pub struct StartupStateEvidenceReference {
    pub artifact_path: String,
    pub artifact_schema: String,
    pub artifact_schema_version: u32,
    /// Source-local exact record locator (for example a line or event ordinal).
    pub record_locator: String,
}

impl StartupRowState {
    pub fn configured_present() -> Self {
        Self {
            schema_version: 1,
            configured: ConfiguredStatus::Present,
            effective: EffectiveState {
                status: EffectiveStatus::Unknown,
                context: None,
                evidence: None,
            },
            observed: ObservedState {
                status: ObservedStatus::Unknown,
                capture_interval: None,
                evidence: None,
            },
        }
    }
}
