//! Bounded offline validation for the experimental Windows ETW capture schema.
//!
//! Validation checks the serialized representation and its self-reported
//! fingerprint. It does not authenticate who created the document or prove
//! that ETW observed every event.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

pub const WINDOWS_RUNTIME_CAPTURE_SCHEMA: &str = "sideeffect.windows_runtime_capture";
pub const WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION: u32 = 3;
pub const WINDOWS_RUNTIME_INSPECTION_SCHEMA: &str = "sideeffect.windows_runtime_inspection";
pub const WINDOWS_RUNTIME_INSPECTION_SCHEMA_VERSION: u32 = 1;
pub const MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_WINDOWS_RUNTIME_EVENTS: usize = 50_000;
pub const MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_WINDOWS_RUNTIME_DURATION_SECONDS: u64 = 60;
const MAX_JSON_ARRAY_ENTRIES: usize = MAX_WINDOWS_RUNTIME_EVENTS * 4;
const MAX_JSON_OBJECT_ENTRIES: usize = 4096;
const MAX_JSON_VALUE_NODES: usize = 4_000_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct WindowsRuntimeCapture {
    pub schema: String,
    pub schema_version: u32,
    pub platform: String,
    pub capture_profile: String,
    pub collection_status: CollectionStatus,
    pub capture_completeness: String,
    pub started_at_unix_ms: u128,
    pub ended_at_unix_ms: u128,
    pub requested_duration_seconds: u64,
    pub stop_reason: StopReason,
    pub target: TargetOutcome,
    pub session: SessionMetadata,
    pub limits: AppliedLimits,
    pub event_loss: EventLoss,
    pub document_sha256: String,
    pub events: Vec<NativeRuntimeEvent>,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CollectionStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    TargetExited,
    DurationLimitReached,
    EventLimitReached,
    EtwLossReported,
    EtwStatisticsUnavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct TargetOutcome {
    pub process_id: u32,
    pub exit_code: Option<i32>,
    pub status_available: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMetadata {
    pub name: String,
    pub provider: String,
    pub scope: String,
    pub buffer_size_kb_requested: u32,
    pub minimum_buffers_requested: u32,
    pub maximum_buffers_requested: u32,
    pub buffer_count_reported: u32,
    pub provider_process_id_header_semantics: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedLimits {
    pub maximum_duration_seconds: u64,
    pub maximum_events: usize,
    pub maximum_total_payload_bytes: usize,
    pub maximum_payload_bytes_per_event: usize,
    pub maximum_document_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventLoss {
    pub events_lost: u32,
    pub log_buffers_lost: u32,
    pub real_time_buffers_lost: u32,
    pub loss_statistics_available: bool,
    pub observation: String,
    pub final_snapshot_available: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRuntimeEvent {
    pub record_ordinal: u64,
    pub provider_guid: String,
    pub event_id: u16,
    pub event_version: u8,
    pub opcode: u8,
    pub event_kind: String,
    pub header_process_id: u32,
    pub header_thread_id: u32,
    pub header_flags: u16,
    pub timestamp_qpc: i64,
    pub raw_payload_hex: String,
    pub payload_decoding: Option<DecodedProcessPayload>,
    pub observation_decoding: Option<Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessDecodeStatus {
    Decoded,
    UnsupportedVersion,
    UnsupportedOpcode,
    AmbiguousPointerSize,
    SchemaUnavailable,
    SchemaMismatch,
    MalformedPayload,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DecodedProcessPayload {
    pub status: ProcessDecodeStatus,
    pub schema_name: Option<String>,
    pub schema_version: Option<u8>,
    pub pointer_size_bytes: Option<u8>,
    pub process_id: Option<u32>,
    pub parent_process_id: Option<u32>,
    pub image_file_name: Option<String>,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRuntimeInspection<'a> {
    pub schema: &'static str,
    pub schema_version: u32,
    pub validation_status: &'static str,
    pub source_sha256: &'a str,
    pub representation_fingerprint_verified: bool,
    pub authenticity: &'static str,
    pub capture_completeness: &'a str,
    pub capture_claimed_status: CollectionStatus,
    pub capture: &'a WindowsRuntimeCapture,
}

/// Parse and validate one bounded Windows runtime capture document.
pub fn inspect_windows_runtime_bytes(bytes: &[u8]) -> Result<WindowsRuntimeCapture, String> {
    if bytes.len() > MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES {
        return Err(format!(
            "Windows runtime document exceeds the {MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES} byte limit"
        ));
    }
    let value = parse_strict_json_with_budget(bytes, MAX_JSON_VALUE_NODES)
        .map_err(|error| format!("invalid Windows runtime JSON: {error}"))?;
    let value = value.into_value();
    let mut capture: WindowsRuntimeCapture = serde_json::from_value(value)
        .map_err(|error| format!("invalid Windows runtime schema: {error}"))?;
    if bytes.len() > capture.limits.maximum_document_bytes {
        return Err(
            "Windows runtime input exceeds the document limit declared by the producer".to_owned(),
        );
    }
    validate_capture(&mut capture)?;
    Ok(capture)
}

fn validate_capture(capture: &mut WindowsRuntimeCapture) -> Result<(), String> {
    if capture.schema != WINDOWS_RUNTIME_CAPTURE_SCHEMA {
        return Err("unsupported Windows runtime document schema".to_owned());
    }
    if capture.schema_version != WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported Windows runtime schema version: {}",
            capture.schema_version
        ));
    }
    if capture.platform != "windows" {
        return Err("Windows runtime document has an unexpected platform".to_owned());
    }
    if capture.capture_completeness != "unknown" {
        return Err("Windows runtime capture completeness must remain unknown".to_owned());
    }
    if capture.started_at_unix_ms > capture.ended_at_unix_ms {
        return Err("Windows runtime capture interval is invalid".to_owned());
    }
    if !(1..=MAX_WINDOWS_RUNTIME_DURATION_SECONDS).contains(&capture.requested_duration_seconds) {
        return Err("Windows runtime requested duration is outside the supported range".to_owned());
    }
    validate_limits(&capture.limits)?;
    if capture.requested_duration_seconds > capture.limits.maximum_duration_seconds {
        return Err("Windows runtime requested duration exceeds its declared limit".to_owned());
    }
    if capture.events.len() > MAX_WINDOWS_RUNTIME_EVENTS {
        return Err(format!(
            "Windows runtime event count exceeds the {MAX_WINDOWS_RUNTIME_EVENTS} event limit"
        ));
    }
    if capture.events.len() > capture.limits.maximum_events {
        return Err("Windows runtime event count exceeds its declared limit".to_owned());
    }
    if capture.diagnostics.len() > 1024 {
        return Err("Windows runtime diagnostic count exceeds the 1024 entry limit".to_owned());
    }
    let mut payload_bytes = 0usize;
    let mut decoder_gaps = false;
    for (index, event) in capture.events.iter().enumerate() {
        let expected = u64::try_from(index + 1).map_err(|_| "event ordinal overflow")?;
        if event.record_ordinal != expected {
            return Err(format!(
                "Windows runtime event ordinal mismatch at array entry {}",
                index + 1
            ));
        }
        let event_payload_bytes = validate_payload_hex(&event.raw_payload_hex)?;
        if event_payload_bytes > MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES {
            return Err(format!(
                "Windows runtime event {} exceeds the {MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES} byte payload limit",
                event.record_ordinal
            ));
        }
        if event_payload_bytes > capture.limits.maximum_payload_bytes_per_event {
            return Err(format!(
                "Windows runtime event {} exceeds its declared payload limit",
                event.record_ordinal
            ));
        }
        payload_bytes = payload_bytes
            .checked_add(event_payload_bytes)
            .ok_or_else(|| "Windows runtime payload byte count overflow".to_owned())?;
        if payload_bytes > MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES {
            return Err(format!(
                "Windows runtime payloads exceed the {MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES} byte aggregate limit"
            ));
        }
        if payload_bytes > capture.limits.maximum_total_payload_bytes {
            return Err(
                "Windows runtime payloads exceed the aggregate limit declared by the producer"
                    .to_owned(),
            );
        }
        if event.provider_guid.len() > 64 || event.event_kind.len() > 128 {
            return Err(format!(
                "Windows runtime event {} has an oversized identity field",
                event.record_ordinal
            ));
        }
        if event.payload_decoding.is_some() == event.observation_decoding.is_some() {
            return Err(format!(
                "Windows runtime event {} must contain exactly one decoder result",
                event.record_ordinal
            ));
        }
        if event
            .payload_decoding
            .as_ref()
            .is_some_and(|decoded| decoded.status != ProcessDecodeStatus::Decoded)
        {
            decoder_gaps = true;
        }
        if let Some(observation) = &event.observation_decoding {
            match observation.get("status").and_then(Value::as_str) {
                Some("decoded") => {}
                Some(_) => decoder_gaps = true,
                None => {
                    return Err(format!(
                        "Windows runtime event {} has no observation decoder status",
                        event.record_ordinal
                    ));
                }
            }
        }
    }
    if capture.collection_status == CollectionStatus::Complete
        && (capture.stop_reason != StopReason::TargetExited
            || !capture.event_loss.loss_statistics_available
            || !capture.event_loss.final_snapshot_available
            || capture.event_loss.events_lost > 0
            || capture.event_loss.log_buffers_lost > 0
            || capture.event_loss.real_time_buffers_lost > 0
            || !capture.diagnostics.is_empty()
            || decoder_gaps)
    {
        return Err("Windows runtime complete status conflicts with its stop, loss, decoder, or diagnostic metadata".to_owned());
    }
    let expected_digest = parse_digest(&capture.document_sha256)?;
    let supplied_digest = capture.document_sha256.clone();
    capture.document_sha256.clear();
    let canonical = serde_json::to_vec(capture)
        .map_err(|error| format!("could not canonicalize Windows runtime document: {error}"))?;
    capture.document_sha256 = supplied_digest;
    let actual_digest = hex(&Sha256::digest(canonical));
    if actual_digest != expected_digest {
        return Err("Windows runtime document SHA-256 mismatch".to_owned());
    }
    Ok(())
}

fn validate_limits(limits: &AppliedLimits) -> Result<(), String> {
    if limits.maximum_duration_seconds == 0
        || limits.maximum_duration_seconds > MAX_WINDOWS_RUNTIME_DURATION_SECONDS
        || limits.maximum_events == 0
        || limits.maximum_events > MAX_WINDOWS_RUNTIME_EVENTS
        || limits.maximum_total_payload_bytes == 0
        || limits.maximum_total_payload_bytes > MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES
        || limits.maximum_payload_bytes_per_event == 0
        || limits.maximum_payload_bytes_per_event > MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES
        || limits.maximum_document_bytes == 0
        || limits.maximum_document_bytes > MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES
    {
        return Err("Windows runtime declared limits exceed supported bounds".to_owned());
    }
    Ok(())
}

fn validate_payload_hex(value: &str) -> Result<usize, String> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Windows runtime raw payload must be lowercase hexadecimal".to_owned());
    }
    Ok(value.len() / 2)
}

fn parse_digest(value: &str) -> Result<String, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "Windows runtime document SHA-256 must be 64 lowercase hexadecimal characters"
                .to_owned(),
        );
    }
    Ok(value.to_owned())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Debug)]
enum StrictValue {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(Map<String, Value>),
}

impl StrictValue {
    fn into_value(self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Bool(value) => Value::Bool(value),
            Self::Number(value) => Value::Number(value),
            Self::String(value) => Value::String(value),
            Self::Array(value) => Value::Array(value),
            Self::Object(value) => Value::Object(value),
        }
    }
}

struct StrictValueSeed {
    remaining_nodes: Rc<Cell<usize>>,
}

impl StrictValueSeed {
    fn new(max_nodes: usize) -> Self {
        Self {
            remaining_nodes: Rc::new(Cell::new(max_nodes)),
        }
    }
}

impl<'de> serde::de::DeserializeSeed<'de> for StrictValueSeed {
    type Value = StrictValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let remaining = self.remaining_nodes.get();
        if remaining == 0 {
            return Err(serde::de::Error::custom(
                "aggregate JSON value-node budget exceeded",
            ));
        }
        self.remaining_nodes.set(remaining - 1);
        deserializer.deserialize_any(StrictVisitor {
            remaining_nodes: self.remaining_nodes,
        })
    }
}

struct StrictVisitor {
    remaining_nodes: Rc<Cell<usize>>,
}

impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue::Null)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue::Null)
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue::Bool(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue::Number(Number::from(value)))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue::Number(Number::from(value)))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(StrictValue::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue::String(value.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue::String(value))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed {
            remaining_nodes: self.remaining_nodes.clone(),
        })? {
            if values.len() >= MAX_JSON_ARRAY_ENTRIES {
                return Err(serde::de::Error::custom("JSON array entry limit exceeded"));
            }
            values.push(value.into_value());
        }
        Ok(StrictValue::Array(values))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = Map::new();
        let mut seen = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.len() >= MAX_JSON_OBJECT_ENTRIES {
                return Err(serde::de::Error::custom("JSON object entry limit exceeded"));
            }
            if seen.insert(key.clone(), ()).is_some() {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value_seed(StrictValueSeed {
                remaining_nodes: self.remaining_nodes.clone(),
            })?;
            values.insert(key, value.into_value());
        }
        Ok(StrictValue::Object(values))
    }
}

fn parse_strict_json_with_budget(
    bytes: &[u8],
    max_nodes: usize,
) -> Result<StrictValue, serde_json::Error> {
    use serde::de::DeserializeSeed;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValueSeed::new(max_nodes).deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> WindowsRuntimeCapture {
        WindowsRuntimeCapture {
            schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.to_owned(),
            schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
            platform: "windows".to_owned(),
            capture_profile: "windows_nt_kernel_process_file_network_v1".to_owned(),
            collection_status: CollectionStatus::Complete,
            capture_completeness: "unknown".to_owned(),
            started_at_unix_ms: 10,
            ended_at_unix_ms: 11,
            requested_duration_seconds: 1,
            stop_reason: StopReason::TargetExited,
            target: TargetOutcome {
                process_id: 123,
                exit_code: Some(0),
                status_available: true,
            },
            session: SessionMetadata {
                name: "NT Kernel Logger".to_owned(),
                provider: "NT Kernel Logger process, FileIo, DiskIo, TcpIp, and UdpIp providers"
                    .to_owned(),
                scope: "system_wide_process_file_and_network_events_during_capture_window"
                    .to_owned(),
                buffer_size_kb_requested: 16,
                minimum_buffers_requested: 8,
                maximum_buffers_requested: 32,
                buffer_count_reported: 8,
                provider_process_id_header_semantics: "header PID/TID is event context only"
                    .to_owned(),
            },
            limits: AppliedLimits {
                maximum_duration_seconds: 60,
                maximum_events: MAX_WINDOWS_RUNTIME_EVENTS,
                maximum_total_payload_bytes: MAX_WINDOWS_RUNTIME_PAYLOAD_BYTES,
                maximum_payload_bytes_per_event: MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES,
                maximum_document_bytes: MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES,
            },
            event_loss: EventLoss {
                events_lost: 0,
                log_buffers_lost: 0,
                real_time_buffers_lost: 0,
                loss_statistics_available: true,
                observation: "zero_reported".to_owned(),
                final_snapshot_available: true,
            },
            document_sha256: String::new(),
            events: vec![NativeRuntimeEvent {
                record_ordinal: 1,
                provider_guid: "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}".to_owned(),
                event_id: 0,
                event_version: 0,
                opcode: 1,
                event_kind: "process_start".to_owned(),
                header_process_id: 99,
                header_thread_id: 101,
                header_flags: 0,
                timestamp_qpc: 77,
                raw_payload_hex: "00a1".to_owned(),
                payload_decoding: Some(DecodedProcessPayload {
                    status: ProcessDecodeStatus::Decoded,
                    schema_name: Some("Process_V2_TypeGroup1".to_owned()),
                    schema_version: Some(2),
                    pointer_size_bytes: Some(8),
                    process_id: Some(123),
                    parent_process_id: Some(1),
                    image_file_name: Some("fixture.exe".to_owned()),
                    diagnostic: None,
                }),
                observation_decoding: None,
            }],
            diagnostics: vec![],
        }
    }

    fn encoded(mut capture: WindowsRuntimeCapture) -> Vec<u8> {
        capture.document_sha256.clear();
        let bytes = serde_json::to_vec(&capture).unwrap();
        capture.document_sha256 = hex(&Sha256::digest(&bytes));
        serde_json::to_vec(&capture).unwrap()
    }

    #[test]
    fn validates_schema_bounds_ordinals_and_representation_digest() {
        let bytes = encoded(fixture());
        let result = inspect_windows_runtime_bytes(&bytes).unwrap();
        assert_eq!(result.events[0].record_ordinal, 1);
        assert_eq!(result.document_sha256.len(), 64);
    }

    #[test]
    fn rejects_duplicate_keys_even_inside_untyped_observation_json() {
        let bytes = encoded(fixture());
        let text = String::from_utf8(bytes).unwrap();
        let duplicated = text.replace(
            "\"observation_decoding\":null",
            "\"observation_decoding\":{\"status\":\"decoded\",\"status\":\"partial\"}",
        );
        // The fixture process event normally has null observation; replacing it adds duplicate keys.
        assert!(inspect_windows_runtime_bytes(duplicated.as_bytes()).is_err());
    }

    #[test]
    fn rejects_aggregate_json_value_nodes_beyond_shared_budget() {
        // The root and nested arrays are each far below their per-container cap;
        // rejection must therefore come from the shared recursive node counter.
        let error = parse_strict_json_with_budget(b"[1,[2,3]]", 4)
            .unwrap_err()
            .to_string();
        assert!(error.contains("aggregate JSON value-node budget exceeded"));
    }

    #[test]
    fn rejects_wrong_schema_and_digest_mismatch() {
        let bytes = encoded(fixture());
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["schema"] = Value::String("sideeffect.other".to_owned());
        let wrong_schema = serde_json::to_vec(&value).unwrap();
        assert!(inspect_windows_runtime_bytes(&wrong_schema).is_err());

        let mut capture = fixture();
        capture.document_sha256 = "0".repeat(64);
        let digest_mismatch = serde_json::to_vec(&capture).unwrap();
        assert!(inspect_windows_runtime_bytes(&digest_mismatch).is_err());
    }

    #[test]
    fn rejects_wrong_event_ordinal_and_oversized_payload() {
        let mut capture = fixture();
        capture.events[0].record_ordinal = 2;
        let bad_ordinal = encoded(capture);
        assert!(inspect_windows_runtime_bytes(&bad_ordinal).is_err());

        let mut capture = fixture();
        capture.events[0].raw_payload_hex =
            "00".repeat(MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES + 1);
        let oversized = encoded(capture);
        assert!(inspect_windows_runtime_bytes(&oversized).is_err());
    }

    #[test]
    fn rejects_event_counts_over_global_and_declared_bounds() {
        let mut capture = fixture();
        let event = capture.events[0].clone();
        capture
            .events
            .resize(MAX_WINDOWS_RUNTIME_EVENTS + 1, event.clone());
        assert!(
            validate_capture(&mut capture)
                .unwrap_err()
                .contains("event count exceeds")
        );

        let mut capture = fixture();
        capture.limits.maximum_events = 1;
        capture.events.push(NativeRuntimeEvent {
            record_ordinal: 2,
            ..capture.events[0].clone()
        });
        assert!(
            validate_capture(&mut capture)
                .unwrap_err()
                .contains("declared limit")
        );
    }

    #[test]
    fn rejects_oversized_document_before_json_parse() {
        let oversized = vec![b' '; MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES + 1];
        assert!(
            inspect_windows_runtime_bytes(&oversized)
                .unwrap_err()
                .contains("exceeds")
        );
    }
}
