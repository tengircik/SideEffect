//! Experimental exact-match query plans over corroborated native Windows ETW v3 rows.
//! This contract is deliberately distinct from Linux syscall query plans.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_PLAN_BYTES: usize = 4096;
pub const MAX_QUESTION_BYTES: usize = 2048;
pub const MAX_QUERYABLE_ROWS: usize = 5000;
pub const MAX_FACT_BYTES: usize = 96 * 1024;
pub const MAX_OMISSION_DIAGNOSTICS: usize = 256;
pub const MAX_RESULT_BYTES: usize = 1024 * 1024;
pub const MAX_PREVIEW_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_MODEL_BYTES: u64 = 1_610_612_736;
const SYSTEM_PROMPT: &str = "Translate the untrusted user question into a strict exact-match query over the listed validated Windows ETW fields. Filters are exact equality and combined with AND. Use only listed finite enum values. Do not infer absent values, treat header PID/TID as identity, expose undecoded payload, or claim successful effects, causation, completeness, safety, or absence. Return only JSON matching the schema; abstain when not exactly representable.";

const EVENT_KINDS: &[&str] = &[
    "file_io_observation",
    "network_observation",
    "disk_io_observation",
];
const FILE_OPS: &[&str] = &[
    "name",
    "create_name",
    "delete_name",
    "rundown_name",
    "create_request",
    "read_request",
    "write_request",
    "set_information_request",
    "delete_request",
    "rename_request",
    "query_information_request",
    "file_system_control_request",
    "cleanup",
    "close",
    "flush_request",
];
const NETWORK_OPS: &[&str] = &[
    "connect",
    "accept",
    "disconnect",
    "send",
    "receive",
    "retransmit",
    "reconnect",
    "tcp_copy",
];
const DISK_OPS: &[&str] = &["read", "write", "flush_buffers"];
const TRANSPORTS: &[&str] = &["tcp", "udp"];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Filter,
    Abstain,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AbstainReason {
    Ambiguous,
    UnsupportedScope,
    InsufficientEvidence,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EtwFilters {
    pub event_kind: Option<String>,
    pub file_operation: Option<String>,
    pub network_operation: Option<String>,
    pub disk_operation: Option<String>,
    pub path_exact: Option<String>,
    pub transport: Option<String>,
    pub destination_address: Option<String>,
    pub destination_port: Option<u16>,
    pub payload_process_id: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EtwPlan {
    pub decision: Decision,
    pub abstain_reason: Option<AbstainReason>,
    pub filters: EtwFilters,
}

#[derive(Clone, Debug, Serialize)]
pub struct Preview {
    pub schema: &'static str,
    pub schema_version: u32,
    pub question: String,
    pub request_sha256: String,
    pub capture_sha256: String,
    pub capture_bytes_sha256: String,
    pub model_id: String,
    pub model_sha256: String,
    pub model_source: crate::model_manager::ModelSource,
    pub model_revision: String,
    pub license_id: Option<String>,
    pub evaluation_status: crate::model_manager::EvaluationStatus,
    pub runtime_source_revision: &'static str,
    pub backend_preference: crate::local_model_explanation::ExplanationBackendPreference,
    pub system_prompt: &'static str,
    pub prompt: String,
    pub output_schema: Value,
    pub queryable_events: Vec<Value>,
    pub coverage: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResultDocument {
    pub schema: &'static str,
    pub schema_version: u32,
    pub request_sha256: String,
    pub capture_sha256: String,
    pub capture_bytes_sha256: String,
    pub model_id: String,
    pub model_sha256: String,
    pub model_source: crate::model_manager::ModelSource,
    pub model_revision: String,
    pub license_id: Option<String>,
    pub evaluation_status: crate::model_manager::EvaluationStatus,
    pub runtime_source_revision: &'static str,
    pub backend_preference: crate::local_model_explanation::ExplanationBackendPreference,
    pub backend_used: &'static str,
    pub backend_status: &'static str,
    pub execution_status: &'static str,
    pub plan: EtwPlan,
    pub matched_events: Vec<Value>,
    pub capture_completeness: String,
    pub collection_status: crate::windows_runtime::CollectionStatus,
    pub event_loss: crate::windows_runtime::EventLoss,
    pub diagnostics: Vec<String>,
    pub coverage: Value,
    pub result_status: &'static str,
}

fn schema() -> Value {
    fn nullable_enum(values: &[&str]) -> Value {
        json!({"anyOf":[{"type":"string","enum":values},{"type":"null"}]})
    }
    let mut filters = serde_json::Map::new();
    for name in [
        "event_kind",
        "file_operation",
        "network_operation",
        "disk_operation",
        "path_exact",
        "transport",
        "destination_address",
        "destination_port",
        "payload_process_id",
    ] {
        let value = match name {
            "event_kind" => nullable_enum(EVENT_KINDS),
            "file_operation" => nullable_enum(FILE_OPS),
            "network_operation" => nullable_enum(NETWORK_OPS),
            "disk_operation" => nullable_enum(DISK_OPS),
            "transport" => nullable_enum(TRANSPORTS),
            "path_exact" => {
                json!({"anyOf":[{"type":"string","minLength":1,"maxLength":4096},{"type":"null"}]})
            }
            "destination_address" => {
                json!({"anyOf":[{"type":"string","maxLength":64},{"type":"null"}]})
            }
            "destination_port" => {
                json!({"anyOf":[{"type":"integer","minimum":0,"maximum":65535},{"type":"null"}]})
            }
            "payload_process_id" => {
                json!({"anyOf":[{"type":"integer","minimum":1,"maximum":u32::MAX},{"type":"null"}]})
            }
            _ => unreachable!(),
        };
        filters.insert(name.to_owned(), value);
    }
    json!({"anyOf":[
        {"type":"object","additionalProperties":false,"required":["decision","abstain_reason","filters"],"properties":{"decision":{"const":"abstain"},"abstain_reason":{"enum":["ambiguous","unsupported_scope","insufficient_evidence"]},"filters":{"type":"object","additionalProperties":false,"required":filters.keys().collect::<Vec<_>>(),"properties":filters.iter().map(|(k,_)|(k.clone(),json!({"const":null}))).collect::<serde_json::Map<_,_>>()}}},
        {"type":"object","additionalProperties":false,"required":["decision","abstain_reason","filters"],"properties":{"decision":{"const":"filter"},"abstain_reason":{"type":"null"},"filters":{"type":"object","additionalProperties":false,"required":filters.keys().collect::<Vec<_>>(),"properties":filters}}}
    ]})
}

fn validate_plan_value(plan: &EtwPlan) -> Result<(), String> {
    let f = &plan.filters;
    let strings = [
        &f.event_kind,
        &f.file_operation,
        &f.network_operation,
        &f.disk_operation,
        &f.path_exact,
        &f.transport,
        &f.destination_address,
    ];
    let populated = strings.iter().filter(|v| v.is_some()).count()
        + usize::from(f.destination_port.is_some())
        + usize::from(f.payload_process_id.is_some());
    if plan.decision == Decision::Abstain {
        if plan.abstain_reason.is_none() || populated != 0 {
            return Err("ETW abstention requires a reason and null filters".into());
        }
        return Ok(());
    }
    if plan.abstain_reason.is_some() || populated == 0 || populated > 4 {
        return Err(
            "ETW filter plan has invalid decision, abstention state, or filter count".into(),
        );
    }
    for (value, allowed) in [
        (&f.event_kind, EVENT_KINDS),
        (&f.file_operation, FILE_OPS),
        (&f.network_operation, NETWORK_OPS),
        (&f.disk_operation, DISK_OPS),
        (&f.transport, TRANSPORTS),
    ] {
        if value.as_deref().is_some_and(|v| !allowed.contains(&v)) {
            return Err("ETW plan contains an unsupported enum value".into());
        }
    }
    if f.path_exact
        .as_ref()
        .is_some_and(|v| v.is_empty() || v.len() > 4096 || v.contains('\0'))
    {
        return Err("ETW path filter is empty or exceeds its bound".into());
    }
    if f.destination_address
        .as_ref()
        .is_some_and(|v| v.len() > 64 || v.parse::<std::net::IpAddr>().is_err())
    {
        return Err("ETW destination address must be a literal IP address".into());
    }
    if f.payload_process_id == Some(0) {
        return Err("ETW payload process ID must be positive".into());
    }
    if f.event_kind.as_deref().is_some_and(|kind| match kind {
        "file_io_observation" => {
            f.network_operation.is_some()
                || f.disk_operation.is_some()
                || f.transport.is_some()
                || f.destination_address.is_some()
                || f.destination_port.is_some()
                || f.payload_process_id.is_some()
        }
        "network_observation" => {
            f.file_operation.is_some() || f.disk_operation.is_some() || f.path_exact.is_some()
        }
        "disk_io_observation" => {
            f.file_operation.is_some()
                || f.network_operation.is_some()
                || f.path_exact.is_some()
                || f.transport.is_some()
                || f.destination_address.is_some()
                || f.destination_port.is_some()
                || f.payload_process_id.is_some()
        }
        _ => true,
    }) {
        return Err("ETW filters combine fields from incompatible event kinds".into());
    }
    if (f.file_operation.is_some() || f.path_exact.is_some())
        && f.event_kind.as_deref() != Some("file_io_observation")
        || f.network_operation.is_some() && f.event_kind.as_deref() != Some("network_observation")
        || f.disk_operation.is_some() && f.event_kind.as_deref() != Some("disk_io_observation")
        || (f.transport.is_some()
            || f.destination_address.is_some()
            || f.destination_port.is_some()
            || f.payload_process_id.is_some())
            && f.event_kind.as_deref() != Some("network_observation")
    {
        return Err("ETW operation and payload fields require their exact event_kind".into());
    }
    Ok(())
}

pub fn validate_plan(bytes: &[u8]) -> Result<EtwPlan, String> {
    if bytes.is_empty() || bytes.len() > MAX_PLAN_BYTES {
        return Err("ETW query plan is empty or exceeds its byte limit".into());
    }
    let value = crate::windows_runtime::parse_strict_json_value(bytes, 256)
        .map_err(|_| "ETW query plan has duplicate keys or malformed JSON".to_owned())?;
    let expected = ["decision", "abstain_reason", "filters"];
    if value.as_object().is_none_or(|object| {
        object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key))
    }) {
        return Err("ETW query plan must contain exactly its required fields".to_owned());
    }
    let filter_keys = [
        "event_kind",
        "file_operation",
        "network_operation",
        "disk_operation",
        "path_exact",
        "transport",
        "destination_address",
        "destination_port",
        "payload_process_id",
    ];
    if value
        .get("filters")
        .and_then(Value::as_object)
        .is_none_or(|object| {
            object.len() != filter_keys.len()
                || filter_keys.iter().any(|key| !object.contains_key(*key))
        })
    {
        return Err("ETW query filters must contain every nullable field exactly once".to_owned());
    }
    let plan: EtwPlan = serde_json::from_value(value)
        .map_err(|_| "ETW query plan has an unsupported schema".to_owned())?;
    validate_plan_value(&plan)?;
    Ok(plan)
}

fn corroboration(
    event: &crate::windows_runtime::NativeRuntimeEvent,
) -> Result<(Option<Value>, Option<&'static str>), String> {
    use crate::record::windows_io_decode::{DecodeStatus, PointerWidth, decode_classic_event};
    if event.payload_decoding.is_some() {
        return Ok((None, Some("process_payload_not_redecoded_offline")));
    }
    let Some(sidecar) = event.observation_decoding.as_ref() else {
        return Ok((None, Some("observation_decoder_unavailable")));
    };
    let payload = decode_lower_hex_payload(&event.raw_payload_hex)?;
    let width = match event.header_flags {
        f if f & 0x20 != 0 && f & 0x40 == 0 => Some(PointerWidth::Bits32),
        f if f & 0x40 != 0 && f & 0x20 == 0 => Some(PointerWidth::Bits64),
        _ => None,
    };
    let decoded = decode_classic_event(
        &event.provider_guid,
        event.event_id,
        event.event_version,
        event.opcode,
        width,
        &payload,
    );
    let kind = decoded.observation.as_ref().map(|v| match &v.activity {
        crate::record::windows_io_decode::Activity::File(_) => "file_io_observation",
        crate::record::windows_io_decode::Activity::Network(_) => "network_observation",
        crate::record::windows_io_decode::Activity::Disk(_) => "disk_io_observation",
    });
    if decoded.status != DecodeStatus::Decoded || kind != Some(event.event_kind.as_str()) {
        return Ok((None, Some("raw_payload_unsupported_or_kind_mismatch")));
    }
    let reproduced = serde_json::to_value(&decoded)
        .map_err(|_| "could not serialize corroborated ETW observation")?;
    if &reproduced != sidecar {
        return Ok((None, Some("payload_sidecar_mismatch")));
    }
    match reproduced.get("observation").cloned() {
        Some(observation) => Ok((Some(observation), None)),
        None => Ok((None, Some("observation_missing_after_redecode"))),
    }
}

fn decode_lower_hex_payload(value: &str) -> Result<Vec<u8>, String> {
    let byte_len = value.len() / 2;
    if value.len() % 2 != 0
        || byte_len > crate::windows_runtime::MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES
    {
        return Err("validated ETW payload hex has an invalid or oversized length".to_owned());
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(byte_len)
        .map_err(|_| "could not allocate the bounded ETW payload buffer".to_owned())?;
    for pair in value.as_bytes().chunks_exact(2) {
        let high = lower_hex_nibble(pair[0]).ok_or("validated ETW payload hex is invalid")?;
        let low = lower_hex_nibble(pair[1]).ok_or("validated ETW payload hex is invalid")?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
fn encode_lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn corroborated_decoded(
    event: &crate::windows_runtime::NativeRuntimeEvent,
) -> Result<Option<Value>, String> {
    Ok(corroboration(event)?.0)
}

fn normalized_event(
    event: &crate::windows_runtime::NativeRuntimeEvent,
    activity: &Value,
    digest: &str,
) -> Value {
    let detail = activity
        .get("activity")
        .and_then(|a| a.get("observation"))
        .cloned()
        .unwrap_or(Value::Null);
    let kind = activity
        .pointer("/activity/kind")
        .cloned()
        .unwrap_or(Value::Null);
    let op = detail.get("operation").cloned().unwrap_or(Value::Null);
    let address = detail.get("destination_address").and_then(|v| {
        if let Some(a) = v.get("v4").and_then(Value::as_array) {
            let bytes: Option<Vec<u8>> = a
                .iter()
                .map(|n| n.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            bytes
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(|b| std::net::Ipv4Addr::from(b).to_string())
        } else {
            let bytes: Option<Vec<u8>> = v
                .get("v6")
                .and_then(Value::as_array)?
                .iter()
                .map(|n| n.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            bytes
                .and_then(|b| <[u8; 16]>::try_from(b).ok())
                .map(|b| std::net::Ipv6Addr::from(b).to_string())
        }
    });
    json!({"event_kind":event.event_kind,"activity_kind":kind,"operation":op,"path":detail.get("path"),"transport":detail.get("transport"),"destination_address":address,"destination_port":detail.get("destination_port"),"payload_process_id":detail.get("payload_process_id"),"evidence_id":format!("W{:05}",event.record_ordinal),"evidence":{"capture_sha256":digest,"record_ordinal":event.record_ordinal,"json_pointer":format!("/events/{}",event.record_ordinal-1)}})
}

#[derive(Serialize)]
struct DigestMaterial<'a> {
    schema: &'static str,
    version: u32,
    capture_sha256: &'a str,
    capture_bytes_sha256: &'a str,
    question: &'a str,
    system_prompt: &'static str,
    prompt: &'a str,
    schema_value: &'a Value,
    model_id: &'a str,
    model_sha256: &'a str,
    model_source: &'a crate::model_manager::ModelSource,
    model_revision: &'a str,
    license_id: &'a Option<String>,
    evaluation_status: crate::model_manager::EvaluationStatus,
    runtime_revision: &'static str,
    backend: crate::local_model_explanation::ExplanationBackendPreference,
}

pub fn preview_bytes(
    bytes: &[u8],
    question: &str,
    model: &crate::model_manager::ResolvedModel,
    backend: crate::local_model_explanation::ExplanationBackendPreference,
) -> Result<Preview, String> {
    if bytes.len() > crate::windows_runtime::MAX_WINDOWS_RUNTIME_DOCUMENT_BYTES {
        return Err("ETW capture exceeds its document byte limit".into());
    }
    let question = crate::local_model::validate_question(question)?;
    if question.len() > MAX_QUESTION_BYTES {
        return Err("ETW query question exceeds its byte limit".into());
    }
    crate::local_model::validate_resolved_model(model, MAX_MODEL_BYTES)?;
    let capture = crate::windows_runtime::inspect_windows_runtime_bytes(bytes)?;
    let mut events = Vec::new();
    let mut omitted = 0usize;
    let mut fact_bytes = 0usize;
    let mut omission_diagnostics = Vec::new();
    let mut omission_diagnostics_truncated = false;
    for event in &capture.events {
        let (activity, omission_reason) = corroboration(event)?;
        let Some(activity) = activity else {
            omitted += 1;
            if omission_diagnostics.len() < MAX_OMISSION_DIAGNOSTICS {
                omission_diagnostics.push(json!({
                    "record_ordinal": event.record_ordinal,
                    "json_pointer": format!("/events/{}", event.record_ordinal - 1),
                    "diagnostic_code": omission_reason.unwrap_or("observation_not_queryable")
                }));
            } else {
                omission_diagnostics_truncated = true;
            }
            continue;
        };
        let row = normalized_event(event, &activity, &capture.document_sha256);
        let size = serde_json::to_vec(&row)
            .map_err(|_| "could not size ETW query fact")?
            .len();
        if events.len() == MAX_QUERYABLE_ROWS || fact_bytes.saturating_add(size) > MAX_FACT_BYTES {
            omitted += 1;
            if omission_diagnostics.len() < MAX_OMISSION_DIAGNOSTICS {
                omission_diagnostics.push(json!({
                    "record_ordinal": event.record_ordinal,
                    "json_pointer": format!("/events/{}", event.record_ordinal - 1),
                    "diagnostic_code": "query_fact_limit_reached"
                }));
            } else {
                omission_diagnostics_truncated = true;
            }
            continue;
        }
        fact_bytes += size;
        events.push(row);
    }
    let scope = json!({"source":"validated_windows_etw_v3","fields":["event_kind","file_operation","network_operation","disk_operation","path_exact","transport","destination_address","destination_port","payload_process_id"]});
    let prompt =
        serde_json::to_string(&json!({"user_question":question,"supported_query_scope":scope}))
            .map_err(|_| "could not encode ETW query prompt")?;
    let schema_value = schema();
    let (revision, _) = match &model.source {
        crate::model_manager::ModelSource::Catalog {
            revision, filename, ..
        } => (revision.clone(), filename.clone()),
        crate::model_manager::ModelSource::UserProvided => {
            ("user-provided".to_owned(), "user-provided".to_owned())
        }
    };
    let capture_bytes_sha256 = crate::local_model::sha256_hex(bytes);
    let material = serde_json::to_vec(&DigestMaterial {
        schema: "sideeffect.windows_etw_query_preview",
        version: SCHEMA_VERSION,
        capture_sha256: &capture.document_sha256,
        capture_bytes_sha256: &capture_bytes_sha256,
        question,
        system_prompt: SYSTEM_PROMPT,
        prompt: &prompt,
        schema_value: &schema_value,
        model_id: &model.id,
        model_sha256: &model.sha256,
        model_source: &model.source,
        model_revision: &revision,
        license_id: &model.license_id,
        evaluation_status: model.evaluation,
        runtime_revision: crate::local_model_explanation::EXPLANATION_RUNTIME_REVISION,
        backend,
    })
    .map_err(|_| "could not bind ETW query preview")?;
    let request_sha256 = crate::local_model::sha256_hex(&material);
    let partial = capture.collection_status != crate::windows_runtime::CollectionStatus::Complete
        || !capture.diagnostics.is_empty()
        || capture.event_loss.events_lost > 0
        || capture.event_loss.log_buffers_lost > 0
        || capture.event_loss.real_time_buffers_lost > 0
        || !capture.event_loss.loss_statistics_available
        || !capture.event_loss.final_snapshot_available
        || omitted > 0;
    let coverage = json!({"collection_status":capture.collection_status,"capture_completeness":capture.capture_completeness,"stop_reason":capture.stop_reason,"event_loss":capture.event_loss,"applied_limits":capture.limits,"diagnostics":capture.diagnostics,"omitted_unvalidated_or_limited_event_count":omitted,"omission_diagnostics":omission_diagnostics,"omission_diagnostics_truncated":omission_diagnostics_truncated,"queryable_event_count":events.len(),"query_status":if partial || capture.capture_completeness != "complete" {"partial_or_unknown"} else {"bounded_source_complete"}});
    let preview = Preview {
        schema: "sideeffect.windows_etw_query_preview",
        schema_version: SCHEMA_VERSION,
        question: question.to_owned(),
        request_sha256,
        capture_sha256: capture.document_sha256,
        capture_bytes_sha256,
        model_id: model.id.clone(),
        model_sha256: model.sha256.clone(),
        model_source: model.source.clone(),
        model_revision: revision,
        license_id: model.license_id.clone(),
        evaluation_status: model.evaluation,
        runtime_source_revision: crate::local_model_explanation::EXPLANATION_RUNTIME_REVISION,
        backend_preference: backend,
        system_prompt: SYSTEM_PROMPT,
        prompt,
        output_schema: schema_value,
        queryable_events: events,
        coverage,
    };
    if serde_json::to_vec(&preview)
        .map_err(|_| "could not serialize ETW query preview")?
        .len()
        > MAX_PREVIEW_BYTES
    {
        return Err("ETW query preview exceeds its output byte limit".into());
    }
    Ok(preview)
}

fn matches(row: &Value, f: &EtwFilters) -> bool {
    let str_eq = |expected: &Option<String>, key: &str| {
        expected
            .as_ref()
            .is_none_or(|v| row.get(key).and_then(Value::as_str) == Some(v.as_str()))
    };
    str_eq(&f.event_kind, "event_kind")
        && str_eq(&f.file_operation, "operation")
        && str_eq(&f.network_operation, "operation")
        && str_eq(&f.disk_operation, "operation")
        && str_eq(&f.path_exact, "path")
        && str_eq(&f.transport, "transport")
        && str_eq(&f.destination_address, "destination_address")
        && f.destination_port.is_none_or(|v| {
            row.get("destination_port").and_then(Value::as_u64) == Some(u64::from(v))
        })
        && f.payload_process_id.is_none_or(|v| {
            row.get("payload_process_id").and_then(Value::as_u64) == Some(u64::from(v))
        })
}

fn strip_runtime_suffix(output: &[u8]) -> &[u8] {
    let Ok(text) = std::str::from_utf8(output) else {
        return output;
    };
    let trimmed = text.trim_end();
    if let Some(index) = trimmed.rfind("[end of text]") {
        if trimmed[index + "[end of text]".len()..].trim().is_empty() {
            return trimmed[..index].trim_end().as_bytes();
        }
    }
    output
}

fn result_from_preview(
    preview: Preview,
    capture: crate::windows_runtime::WindowsRuntimeCapture,
    plan: EtwPlan,
    backend_used: &'static str,
    backend_status: &'static str,
) -> Result<ResultDocument, String> {
    validate_plan_value(&plan)?;
    let rows = if plan.decision == Decision::Filter {
        preview
            .queryable_events
            .iter()
            .filter(|row| matches(row, &plan.filters))
            .cloned()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let status = if capture.collection_status == crate::windows_runtime::CollectionStatus::Complete
        && capture.diagnostics.is_empty()
        && preview.coverage["omitted_unvalidated_or_limited_event_count"] == 0
        && capture.event_loss.events_lost == 0
        && capture.event_loss.log_buffers_lost == 0
        && capture.event_loss.real_time_buffers_lost == 0
        && capture.event_loss.loss_statistics_available
        && capture.event_loss.final_snapshot_available
    {
        "capture_completeness_unknown"
    } else {
        "partial_or_unknown"
    };
    let result = ResultDocument {
        schema: "sideeffect.windows_etw_query_result",
        schema_version: SCHEMA_VERSION,
        request_sha256: preview.request_sha256,
        capture_sha256: preview.capture_sha256,
        capture_bytes_sha256: preview.capture_bytes_sha256,
        model_id: preview.model_id,
        model_sha256: preview.model_sha256,
        model_source: preview.model_source,
        model_revision: preview.model_revision,
        license_id: preview.license_id,
        evaluation_status: preview.evaluation_status,
        runtime_source_revision: preview.runtime_source_revision,
        backend_preference: preview.backend_preference,
        backend_used,
        backend_status,
        execution_status: if plan.decision == Decision::Filter {
            "executed"
        } else {
            "not_executed"
        },
        plan,
        matched_events: rows,
        capture_completeness: capture.capture_completeness,
        collection_status: capture.collection_status,
        event_loss: capture.event_loss,
        diagnostics: capture.diagnostics,
        coverage: preview.coverage,
        result_status: status,
    };
    if serde_json::to_vec(&result)
        .map_err(|_| "could not serialize ETW query result")?
        .len()
        > MAX_RESULT_BYTES
    {
        return Err("ETW query result exceeds its output byte limit".into());
    }
    Ok(result)
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub fn analyze_bytes(
    bytes: &[u8],
    question: &str,
    backend: crate::local_model_explanation::ExplanationBackendPreference,
    runtime: &std::path::Path,
    model: &crate::model_manager::ResolvedModel,
    confirmed: &str,
) -> Result<ResultDocument, String> {
    let preview = preview_bytes(bytes, question, model, backend)?;
    if preview.request_sha256 != confirmed {
        return Err(format!(
            "preview digest mismatch; review model-etw-query-preview and confirm request_sha256 ({})",
            preview.request_sha256
        ));
    }
    let capture = crate::windows_runtime::inspect_windows_runtime_bytes(bytes)?;
    let (raw, used, status) = crate::local_model_explanation_runtime::run_windows_constrained_json(
        &preview.prompt,
        preview.system_prompt,
        &preview.output_schema,
        backend,
        runtime,
        model,
        MAX_MODEL_BYTES,
    )?;
    let plan = validate_plan(strip_runtime_suffix(&raw))?;
    result_from_preview(preview, capture, plan, used, status)
}

#[cfg(test)]
mod tests {
    use super::*;
    const NULL_FILTERS: &str = r#""event_kind":null,"file_operation":null,"network_operation":null,"disk_operation":null,"path_exact":null,"transport":null,"destination_address":null,"destination_port":null,"payload_process_id":null"#;

    fn empty_capture_bytes(status: crate::windows_runtime::CollectionStatus) -> Vec<u8> {
        use crate::windows_runtime::*;
        let mut capture = WindowsRuntimeCapture {
            schema: WINDOWS_RUNTIME_CAPTURE_SCHEMA.into(),
            schema_version: WINDOWS_RUNTIME_CAPTURE_SCHEMA_VERSION,
            platform: "windows".into(),
            capture_profile: "synthetic_fixture_only".into(),
            collection_status: status,
            capture_completeness: "unknown".into(),
            started_at_unix_ms: 1,
            ended_at_unix_ms: 2,
            requested_duration_seconds: 1,
            stop_reason: StopReason::TargetExited,
            target: TargetOutcome {
                process_id: 42,
                exit_code: Some(0),
                status_available: true,
            },
            session: SessionMetadata {
                name: "synthetic fixture".into(),
                provider: "synthetic fixture".into(),
                scope: "synthetic fixture only".into(),
                buffer_size_kb_requested: 64,
                minimum_buffers_requested: 2,
                maximum_buffers_requested: 4,
                buffer_count_reported: 2,
                provider_process_id_header_semantics: "context only".into(),
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
                observation: "none_reported".into(),
                final_snapshot_available: true,
            },
            document_sha256: String::new(),
            events: Vec::new(),
            diagnostics: Vec::new(),
        };
        let canonical = serde_json::to_vec(&capture).unwrap();
        capture.document_sha256 = crate::local_model::sha256_hex(&canonical);
        serde_json::to_vec(&capture).unwrap()
    }

    fn synthetic_query_model() -> crate::model_manager::ResolvedModel {
        crate::model_manager::ResolvedModel {
            id: "custom-synthetic".into(),
            name: "Synthetic fixture model".into(),
            path: std::path::PathBuf::new(),
            size_bytes: 1,
            sha256: "a".repeat(64),
            source: crate::model_manager::ModelSource::UserProvided,
            license_id: None,
            evaluation: crate::model_manager::EvaluationStatus::NotAssessed,
            recommended: false,
        }
    }

    #[test]
    fn bounded_lowercase_hex_decoder_accepts_only_bounded_lowercase_pairs() {
        let bytes = [0x00, 0x09, 0x7f, 0xa0, 0xff];
        let encoded = encode_lower_hex(&bytes);
        assert_eq!(decode_lower_hex_payload(&encoded).unwrap(), bytes.to_vec());
        assert!(decode_lower_hex_payload("0A").is_err());
        assert!(decode_lower_hex_payload("0").is_err());
        assert!(
            decode_lower_hex_payload(
                &"00".repeat(crate::windows_runtime::MAX_WINDOWS_RUNTIME_EVENT_PAYLOAD_BYTES + 1)
            )
            .is_err()
        );
    }

    fn synthetic_network_event() -> crate::windows_runtime::NativeRuntimeEvent {
        use crate::record::windows_io_decode::{PointerWidth, decode_classic_event};
        let mut payload = Vec::new();
        payload.extend_from_slice(&4242_u32.to_le_bytes());
        payload.extend_from_slice(&64_u32.to_le_bytes());
        payload.extend_from_slice(&[203, 0, 113, 8]);
        payload.extend_from_slice(&[192, 0, 2, 4]);
        payload.extend_from_slice(&443_u16.to_be_bytes());
        payload.extend_from_slice(&51_234_u16.to_be_bytes());
        for value in [1460_u16, 1, 1, 1] {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        payload.extend_from_slice(&4096_u32.to_le_bytes());
        payload.extend_from_slice(&1_i16.to_le_bytes());
        payload.extend_from_slice(&1_i16.to_le_bytes());
        payload.extend_from_slice(&9_u32.to_le_bytes());
        payload.extend_from_slice(&10_u64.to_le_bytes());
        let decoded = decode_classic_event(
            "9a280ac0-c8e0-11d1-84e2-00c04fb998a2",
            0,
            2,
            12,
            Some(PointerWidth::Bits64),
            &payload,
        );
        crate::windows_runtime::NativeRuntimeEvent {
            record_ordinal: 1,
            provider_guid: "9a280ac0-c8e0-11d1-84e2-00c04fb998a2".into(),
            event_id: 0,
            event_version: 2,
            opcode: 12,
            event_kind: "network_observation".into(),
            header_process_id: 777,
            header_thread_id: 888,
            header_flags: 0x0040,
            timestamp_qpc: 123,
            raw_payload_hex: encode_lower_hex(&payload),
            payload_decoding: None,
            observation_decoding: Some(serde_json::to_value(decoded).unwrap()),
        }
    }
    #[test]
    fn schema_rejects_unknown_and_malformed_fields() {
        assert!(validate_plan(format!(r#"{{"decision":"filter","abstain_reason":null,"filters":{{{NULL_FILTERS},"header_process_id":2}}}}"#).as_bytes()).is_err());
        assert!(validate_plan(format!(r#"{{"decision":"filter","abstain_reason":null,"filters":{{"event_kind":"process_start",{NULL_FILTERS}}}}}"#).as_bytes()).is_err());
        assert!(validate_plan(&vec![b' '; MAX_PLAN_BYTES + 1]).is_err());
        assert!(validate_plan(br#"{"decision":"abstain","decision":"filter","abstain_reason":"ambiguous","filters":{"event_kind":null,"file_operation":null,"network_operation":null,"disk_operation":null,"path_exact":null,"transport":null,"destination_address":null,"destination_port":null,"payload_process_id":null}}"#).is_err());
    }
    #[test]
    fn rejects_non_literal_ip_and_incompatible_filter_group() {
        assert!(validate_plan(br#"{"decision":"filter","abstain_reason":null,"filters":{"event_kind":"network_observation","file_operation":null,"network_operation":"connect","disk_operation":null,"path_exact":null,"transport":"tcp","destination_address":"host.test","destination_port":443,"payload_process_id":null}}"#).is_err());
        assert!(validate_plan(br#"{"decision":"filter","abstain_reason":null,"filters":{"event_kind":"file_io_observation","file_operation":"read_request","network_operation":"connect","disk_operation":null,"path_exact":null,"transport":null,"destination_address":null,"destination_port":null,"payload_process_id":null}}"#).is_err());
    }

    #[test]
    fn strips_only_a_trailing_runtime_end_marker() {
        let plan = format!(
            r#"{{"decision":"abstain","abstain_reason":"unsupported_scope","filters":{{{NULL_FILTERS}}}}}"#
        );
        assert_eq!(
            strip_runtime_suffix(format!("{plan}\n[end of text]\n").as_bytes()),
            plan.as_bytes()
        );
        assert_eq!(
            strip_runtime_suffix(b"not [end of text] content"),
            b"not [end of text] content"
        );
    }
    #[test]
    fn abstention_requires_reason_and_no_filters() {
        assert!(validate_plan(format!(r#"{{"decision":"abstain","abstain_reason":"unsupported_scope","filters":{{{NULL_FILTERS}}}}}"#).as_bytes()).is_ok());
        assert!(
            validate_plan(
                format!(
                    r#"{{"decision":"abstain","abstain_reason":null,"filters":{{{NULL_FILTERS}}}}}"#
                )
                .as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn selects_exact_payload_fields_and_returns_capture_local_w_evidence() {
        let event = synthetic_network_event();
        let activity = corroborated_decoded(&event).unwrap().unwrap();
        let row = normalized_event(&event, &activity, &"a".repeat(64));
        assert_eq!(row["payload_process_id"], 4242);
        assert_eq!(row["destination_port"], 443);
        assert_eq!(row["evidence_id"], "W00001");
        assert_eq!(row["evidence"]["json_pointer"], "/events/0");
        assert_eq!(row["evidence"]["capture_sha256"], "a".repeat(64));
        assert!(row.get("header_process_id").is_none());
        assert!(row.get("header_thread_id").is_none());
        let filters = EtwFilters {
            event_kind: Some("network_observation".into()),
            network_operation: Some("connect".into()),
            transport: Some("tcp".into()),
            destination_port: Some(443),
            ..EtwFilters::default()
        };
        assert!(matches(&row, &filters));
        let wrong = EtwFilters {
            destination_port: Some(80),
            ..filters
        };
        assert!(!matches(&row, &wrong));
        assert_ne!(row["payload_process_id"], event.header_process_id);
        assert_ne!(row["payload_process_id"], event.header_thread_id);
    }

    #[test]
    fn refuses_mismatched_payload_sidecar_and_does_not_query_header_ids() {
        let mut event = synthetic_network_event();
        event.observation_decoding.as_mut().unwrap()["observation"]["activity"]["observation"]["destination_port"] =
            json!(80);
        assert!(corroborated_decoded(&event).unwrap().is_none());
        assert_eq!(
            corroboration(&event).unwrap().1,
            Some("payload_sidecar_mismatch")
        );
        assert!(validate_plan(br#"{"decision":"filter","abstain_reason":null,"filters":{"event_kind":"network_observation","file_operation":null,"network_operation":null,"disk_operation":null,"path_exact":null,"transport":null,"destination_address":null,"destination_port":null,"payload_process_id":null,"header_process_id":777}}"#).is_err());
    }

    #[test]
    fn omits_process_payloads_that_cannot_be_redecoded_without_live_tdh_schema() {
        let mut event = synthetic_network_event();
        event.event_kind = "process_start".into();
        event.payload_decoding = Some(crate::windows_runtime::DecodedProcessPayload {
            status: crate::windows_runtime::ProcessDecodeStatus::SchemaUnavailable,
            schema_name: None,
            schema_version: None,
            pointer_size_bytes: None,
            process_id: Some(123),
            parent_process_id: Some(7),
            image_file_name: None,
            diagnostic: None,
        });
        event.observation_decoding = None;
        assert!(corroborated_decoded(&event).unwrap().is_none());
        assert_eq!(
            corroboration(&event).unwrap().1,
            Some("process_payload_not_redecoded_offline")
        );
    }

    #[test]
    fn preview_digest_binds_exact_bytes_question_schema_model_and_backend() {
        use crate::local_model_explanation::ExplanationBackendPreference as Backend;
        let bytes = empty_capture_bytes(crate::windows_runtime::CollectionStatus::Complete);
        let model = synthetic_query_model();
        let first = preview_bytes(&bytes, "List TCP observations.", &model, Backend::Cpu).unwrap();
        let mut whitespace_variant = bytes.clone();
        whitespace_variant.push(b' ');
        let second = preview_bytes(
            &whitespace_variant,
            "List TCP observations.",
            &model,
            Backend::Cpu,
        )
        .unwrap();
        let other_question =
            preview_bytes(&bytes, "List UDP observations.", &model, Backend::Cpu).unwrap();
        let other_backend =
            preview_bytes(&bytes, "List TCP observations.", &model, Backend::Cuda).unwrap();
        assert_ne!(first.request_sha256, second.request_sha256);
        assert_ne!(first.capture_bytes_sha256, second.capture_bytes_sha256);
        assert_ne!(first.request_sha256, other_question.request_sha256);
        assert_ne!(first.request_sha256, other_backend.request_sha256);
        assert_eq!(first.coverage["capture_completeness"], "unknown");
        assert_eq!(first.coverage["query_status"], "partial_or_unknown");
    }

    #[test]
    fn rejects_oversized_question_before_capture_processing() {
        let error = preview_bytes(
            b"not a capture",
            &"q".repeat(MAX_QUESTION_BYTES + 1),
            &synthetic_query_model(),
            crate::local_model_explanation::ExplanationBackendPreference::Cpu,
        )
        .unwrap_err();
        assert!(error.contains("question exceeds"));
    }

    #[test]
    fn partial_capture_preview_preserves_loss_and_diagnostics() {
        use crate::local_model_explanation::ExplanationBackendPreference;
        let bytes = empty_capture_bytes(crate::windows_runtime::CollectionStatus::Partial);
        let model = synthetic_query_model();
        let preview = preview_bytes(
            &bytes,
            "Find network events.",
            &model,
            ExplanationBackendPreference::Cpu,
        )
        .unwrap();
        assert_eq!(preview.coverage["collection_status"], "partial");
        assert_eq!(preview.coverage["capture_completeness"], "unknown");
        assert_eq!(
            preview.coverage["event_loss"]["loss_statistics_available"],
            true
        );
        assert_eq!(preview.coverage["query_status"], "partial_or_unknown");
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn stale_confirmation_is_rejected_before_runtime_start() {
        use crate::local_model_explanation::ExplanationBackendPreference;
        let bytes = empty_capture_bytes(crate::windows_runtime::CollectionStatus::Complete);
        let model = synthetic_query_model();
        let result = analyze_bytes(
            &bytes,
            "Find network events.",
            ExplanationBackendPreference::Cpu,
            std::path::Path::new("missing-runtime.exe"),
            &model,
            &"0".repeat(64),
        );
        assert!(result.unwrap_err().contains("preview digest mismatch"));
    }
}
