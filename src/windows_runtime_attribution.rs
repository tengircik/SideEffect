//! Conservative offline process-lineage and event-context view for Windows ETW v3.
//!
//! Process-start payloads supply the only lineage edges. Network observations
//! use their documented payload PID. File and disk header PIDs are exposed as
//! context candidates only, never as confirmed ownership.

use crate::fingerprint::sha256_hex;
use crate::windows_runtime::{
    DecodedProcessPayload, NativeRuntimeEvent, ProcessDecodeStatus, WindowsRuntimeCapture,
    inspect_windows_runtime_bytes,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const PROCESS_PROVIDER_GUID: &str = "3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c";
const FILE_PROVIDER_GUID: &str = "90cbdc39-4a3e-11d1-84f4-0000f80464e3";
const TCP_PROVIDER_GUID: &str = "9a280ac0-c8e0-11d1-84e2-00c04fb998a2";
const UDP_PROVIDER_GUID: &str = "bf3a50c5-a9c9-4988-a005-2df0b7c80f80";
const DISK_PROVIDER_GUID: &str = "3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c";
const MAX_ATTRIBUTION_EVENTS: usize = crate::windows_runtime::MAX_WINDOWS_RUNTIME_EVENTS;

#[derive(Clone, Debug, Serialize)]
pub struct WindowsRuntimeAttributionSummary {
    pub schema: &'static str,
    pub schema_version: u32,
    pub algorithm: AttributionAlgorithm,
    pub status: &'static str,
    pub attribution_status: &'static str,
    pub capture: CaptureIdentity,
    pub target_process_id: u32,
    pub target_start_status: &'static str,
    pub summary: AttributionCounts,
    pub processes: Vec<AttributedProcess>,
    pub event_attributions: Vec<EventAttribution>,
    pub unassigned_events: Vec<UnassignedEvent>,
    pub diagnostics: Vec<&'static str>,
    pub limitations: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AttributionAlgorithm {
    pub id: &'static str,
    pub version: u32,
    pub process_lineage_basis: &'static str,
    pub network_basis: &'static str,
    pub file_disk_basis: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct CaptureIdentity {
    pub source_format: &'static str,
    pub sha256: String,
    pub claimed_status: String,
    pub capture_completeness: &'static str,
    pub event_loss_reported: bool,
    pub loss_statistics_available: bool,
    pub final_loss_snapshot_available: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AttributionCounts {
    pub observed_target_process_instances: usize,
    pub observed_descendant_process_instances: usize,
    pub payload_pid_attributed_events: usize,
    pub header_pid_context_candidates: usize,
    pub unassigned_events: usize,
    pub ambiguous_process_ids: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct AttributedProcess {
    pub role: &'static str,
    pub process_id: u32,
    pub image_file_name: String,
    pub start_event: EventReference,
    pub parent_process_id: Option<u32>,
    pub parent_start_event: Option<EventReference>,
    pub end_event: Option<EventReference>,
    pub identity_status: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventAttribution {
    pub event: EventReference,
    pub event_kind: String,
    pub attribution: &'static str,
    pub process_start_event: EventReference,
    pub basis: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct UnassignedEvent {
    pub event: EventReference,
    pub event_kind: String,
    pub reason: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventReference {
    pub capture_sha256: String,
    pub record_ordinal: u64,
}

struct ProcessInstance {
    role: &'static str,
    process_id: u32,
    image_file_name: String,
    start_ordinal: u64,
    parent_process_id: Option<u32>,
    parent_start_ordinal: Option<u64>,
    end_ordinal: Option<u64>,
    identity_ambiguous: bool,
}

/// Build a separate, bounded attribution view without changing the capture.
pub fn summarize_windows_runtime_attribution(
    capture_bytes: &[u8],
) -> Result<WindowsRuntimeAttributionSummary, String> {
    let capture = inspect_windows_runtime_bytes(capture_bytes)?;
    summarize_capture(capture_bytes, &capture)
}

fn summarize_capture(
    capture_bytes: &[u8],
    capture: &WindowsRuntimeCapture,
) -> Result<WindowsRuntimeAttributionSummary, String> {
    if capture.events.len() > MAX_ATTRIBUTION_EVENTS {
        return Err("Windows runtime attribution exceeds the supported event limit".to_owned());
    }
    let capture_sha256 = sha256_hex(capture_bytes);
    let target_pid = capture.target.process_id;
    let target_starts = capture
        .events
        .iter()
        .filter_map(|event| process_event(event, "process_start"))
        .filter(|(decoded, _)| decoded.process_id == Some(target_pid))
        .count();

    let target_start_ordinal = (target_starts == 1)
        .then(|| {
            capture
                .events
                .iter()
                .find(|event| {
                    process_event(event, "process_start")
                        .is_some_and(|(decoded, _)| decoded.process_id == Some(target_pid))
                })
                .map(|event| event.record_ordinal)
        })
        .flatten();

    let mut instances = Vec::<ProcessInstance>::new();
    let mut active = BTreeMap::<u32, usize>::new();
    let mut ambiguous_pids = BTreeSet::<u32>::new();
    let mut event_attributions = Vec::new();
    let mut unassigned_events = Vec::new();
    let mut diagnostics = Vec::new();

    for event in &capture.events {
        if event_attributions
            .len()
            .saturating_add(unassigned_events.len())
            >= MAX_ATTRIBUTION_EVENTS
        {
            return Err("Windows runtime attribution output exceeds the event limit".to_owned());
        }
        let ordinal = event.record_ordinal;
        if Some(ordinal) == target_start_ordinal {
            let Some((decoded, image)) = process_event(event, "process_start") else {
                return Err("validated target process event became unavailable".to_owned());
            };
            let process_id = decoded.process_id.expect("validated process ID");
            let image_file_name = image.to_owned();
            let instance_index = instances.len();
            instances.push(ProcessInstance {
                role: "target",
                process_id,
                image_file_name,
                start_ordinal: ordinal,
                parent_process_id: decoded.parent_process_id,
                parent_start_ordinal: None,
                end_ordinal: None,
                identity_ambiguous: false,
            });
            active.insert(process_id, instance_index);
            event_attributions.push(EventAttribution {
                event: event_reference(&capture_sha256, event),
                event_kind: event.event_kind.clone(),
                attribution: "target_process_payload",
                process_start_event: event_reference(&capture_sha256, event),
                basis: "validated_process_start_payload_process_id_matches_recorder_target_pid",
            });
            continue;
        }

        if event.event_kind == "process_start" {
            if let Some((decoded, image)) = process_event(event, "process_start") {
                let process_id = decoded.process_id.expect("validated process ID");
                let parent_pid = decoded
                    .parent_process_id
                    .expect("validated parent process ID");
                if ambiguous_pids.contains(&process_id) {
                    unassigned_events.push(unassigned(
                        &capture_sha256,
                        event,
                        "process_id_was_ambiguous_earlier_in_capture",
                    ));
                    continue;
                }
                if active.contains_key(&process_id) {
                    if let Some(existing_index) = active.remove(&process_id) {
                        instances[existing_index].identity_ambiguous = true;
                    }
                    ambiguous_pids.insert(process_id);
                    diagnostics.push("overlapping_process_start_reused_an_active_pid");
                    unassigned_events.push(unassigned(
                        &capture_sha256,
                        event,
                        "overlapping_process_id_makes_instance_identity_ambiguous",
                    ));
                    continue;
                }
                let parent_index = active.get(&parent_pid).copied();
                if let Some(parent_index) = parent_index {
                    let parent = &instances[parent_index];
                    let instance_index = instances.len();
                    instances.push(ProcessInstance {
                        role: "descendant",
                        process_id,
                        image_file_name: image.to_owned(),
                        start_ordinal: ordinal,
                        parent_process_id: Some(parent_pid),
                        parent_start_ordinal: Some(parent.start_ordinal),
                        end_ordinal: None,
                        identity_ambiguous: false,
                    });
                    active.insert(process_id, instance_index);
                    event_attributions.push(EventAttribution {
                        event: event_reference(&capture_sha256, event),
                        event_kind: event.event_kind.clone(),
                        attribution: "descendant_process_payload_candidate",
                        process_start_event: event_reference(&capture_sha256, event),
                        basis: "validated_parent_id_matches_one_active_target_tree_process",
                    });
                } else {
                    unassigned_events.push(unassigned(
                        &capture_sha256,
                        event,
                        "parent_process_id_does_not_match_one_active_target_tree_process",
                    ));
                }
            } else {
                diagnostics
                    .push("unsupported_or_malformed_process_start_prevents_complete_lineage");
                unassigned_events.push(unassigned(
                    &capture_sha256,
                    event,
                    "process_start_payload_is_not_supported_and_validated",
                ));
            }
            continue;
        }

        if event.event_kind == "process_end" {
            if let Some((decoded, image)) = process_event(event, "process_end") {
                let process_id = decoded.process_id.expect("validated process ID");
                if let Some(instance_index) = active.remove(&process_id) {
                    let instance = &mut instances[instance_index];
                    if decoded.parent_process_id == instance.parent_process_id
                        && image == instance.image_file_name
                    {
                        instance.end_ordinal = Some(ordinal);
                        event_attributions.push(EventAttribution {
                            event: event_reference(&capture_sha256, event),
                            event_kind: event.event_kind.clone(),
                            attribution: if instance.role == "target" {
                                "target_process_payload"
                            } else {
                                "descendant_process_payload_candidate"
                            },
                            process_start_event: event_reference(
                                &capture_sha256,
                                capture
                                    .events
                                    .get(usize::try_from(instance.start_ordinal - 1).unwrap_or(usize::MAX))
                                    .ok_or_else(|| "process start evidence reference is unavailable".to_owned())?,
                            ),
                            basis: "validated_process_end_pid_parent_and_image_match_active_process_start_payload",
                        });
                    } else {
                        instance.identity_ambiguous = true;
                        ambiguous_pids.insert(process_id);
                        diagnostics
                            .push("process_end_identity_does_not_match_active_process_start");
                        unassigned_events.push(unassigned(
                            &capture_sha256,
                            event,
                            "process_end_parent_or_image_does_not_match_active_start_payload",
                        ));
                    }
                } else {
                    unassigned_events.push(unassigned(
                        &capture_sha256,
                        event,
                        if ambiguous_pids.contains(&process_id) {
                            "process_id_is_ambiguous"
                        } else {
                            "process_end_has_no_active_target_tree_instance"
                        },
                    ));
                }
            } else {
                diagnostics.push("unsupported_or_malformed_process_end_may_hide_pid_reuse");
                for instance in active.values().copied().collect::<Vec<_>>() {
                    ambiguous_pids.insert(instances[instance].process_id);
                    instances[instance].identity_ambiguous = true;
                }
                active.clear();
                unassigned_events.push(unassigned(
                    &capture_sha256,
                    event,
                    "process_end_payload_is_not_supported_and_may_hide_pid_reuse",
                ));
            }
            continue;
        }

        if is_network_observation(event) {
            if let Some(pid) = payload_pid(event) {
                if let Some(instance_index) = active.get(&pid).copied() {
                    let instance = &instances[instance_index];
                    event_attributions.push(EventAttribution {
                        event: event_reference(&capture_sha256, event),
                        event_kind: event.event_kind.clone(),
                        attribution: if instance.role == "target" {
                            "target_network_payload_pid_match"
                        } else {
                            "descendant_network_payload_pid_match"
                        },
                        process_start_event: event_reference(
                            &capture_sha256,
                            capture
                                .events
                                .get(usize::try_from(instance.start_ordinal - 1).unwrap_or(usize::MAX))
                                .ok_or_else(|| "process start evidence reference is unavailable".to_owned())?,
                        ),
                        basis: "documented_network_provider_payload_process_id_matches_active_target_tree_instance",
                    });
                } else {
                    unassigned_events.push(unassigned(
                        &capture_sha256,
                        event,
                        if ambiguous_pids.contains(&pid) {
                            "network_payload_process_id_is_ambiguous"
                        } else {
                            "network_payload_process_id_is_outside_observed_target_tree"
                        },
                    ));
                }
            } else {
                unassigned_events.push(unassigned(
                    &capture_sha256,
                    event,
                    "decoded_network_observation_has_no_valid_payload_process_id",
                ));
            }
            continue;
        }

        if is_file_or_disk_observation(event) {
            let pid = event.header_process_id;
            if let Some(instance_index) = active.get(&pid).copied() {
                let instance = &instances[instance_index];
                event_attributions.push(EventAttribution {
                    event: event_reference(&capture_sha256, event),
                    event_kind: event.event_kind.clone(),
                    attribution: if instance.role == "target" {
                        "target_header_pid_context_candidate"
                    } else {
                        "descendant_header_pid_context_candidate"
                    },
                    process_start_event: event_reference(
                        &capture_sha256,
                        capture
                            .events
                            .get(usize::try_from(instance.start_ordinal - 1).unwrap_or(usize::MAX))
                            .ok_or_else(|| "process start evidence reference is unavailable".to_owned())?,
                    ),
                    basis: "header_process_id_matches_active_target_tree_pid_but_remains_event_context_only",
                });
            } else {
                unassigned_events.push(unassigned(
                    &capture_sha256,
                    event,
                    if ambiguous_pids.contains(&pid) {
                        "header_process_id_is_ambiguous"
                    } else {
                        "header_process_id_is_not_in_the_observed_target_tree"
                    },
                ));
            }
            continue;
        }

        unassigned_events.push(unassigned(
            &capture_sha256,
            event,
            "event_kind_is_outside_the_supported_attribution_rules",
        ));
    }

    if target_starts == 0 {
        diagnostics.push("target_process_start_was_not_observed");
    } else if target_starts > 1 {
        diagnostics.push("target_pid_has_multiple_process_start_rows_and_is_ambiguous");
    }
    if capture.collection_status != crate::windows_runtime::CollectionStatus::Complete
        || capture.event_loss.events_lost > 0
        || capture.event_loss.log_buffers_lost > 0
        || capture.event_loss.real_time_buffers_lost > 0
        || !capture.event_loss.loss_statistics_available
        || !capture.event_loss.final_snapshot_available
        || !capture.diagnostics.is_empty()
    {
        diagnostics.push("capture_or_loss_metadata_is_partial_or_unavailable");
    }
    if !ambiguous_pids.is_empty() {
        diagnostics.push("one_or_more_process_ids_could_not_be_resolved_to_one_instance");
    }
    let has_gaps = !diagnostics.is_empty();
    let attribution_status = if target_starts != 1 {
        "insufficient_evidence"
    } else if !ambiguous_pids.is_empty() {
        "partial_candidate_lineage"
    } else {
        "candidate_lineage_observed"
    };
    let payload_pid_attributed_events = event_attributions
        .iter()
        .filter(|event| {
            event.attribution.contains("network_payload_pid_match")
                || event.attribution.contains("process_payload")
        })
        .count();
    let header_pid_context_candidates = event_attributions
        .iter()
        .filter(|event| event.attribution.contains("header_pid_context_candidate"))
        .count();
    let observed_target_process_instances = instances
        .iter()
        .filter(|instance| instance.role == "target")
        .count();
    let observed_descendant_process_instances = instances
        .iter()
        .filter(|instance| instance.role == "descendant")
        .count();
    let processes = instances
        .into_iter()
        .map(|instance| AttributedProcess {
            role: instance.role,
            process_id: instance.process_id,
            image_file_name: instance.image_file_name,
            start_event: event_reference_by_ordinal(&capture_sha256, instance.start_ordinal),
            parent_process_id: if instance.role == "target" {
                None
            } else {
                instance.parent_process_id
            },
            parent_start_event: instance
                .parent_start_ordinal
                .map(|ordinal| event_reference_by_ordinal(&capture_sha256, ordinal)),
            end_event: instance
                .end_ordinal
                .map(|ordinal| event_reference_by_ordinal(&capture_sha256, ordinal)),
            identity_status: if instance.identity_ambiguous {
                "ambiguous_pid_lifecycle"
            } else if instance.role == "target" {
                "recorder_target_pid_matches_observed_process_start"
            } else {
                "observed_pid_and_parent_id_candidate"
            },
        })
        .collect();

    Ok(WindowsRuntimeAttributionSummary {
        schema: "sideeffect.windows_runtime_attribution",
        schema_version: 1,
        algorithm: AttributionAlgorithm {
            id: "windows_etw_process_lineage_payload_pid_context_pid_v1",
            version: 1,
            process_lineage_basis: "validated_process_start_payload_parent_id_chain_with_capture_order_lifetimes",
            network_basis: "documented_network_payload_process_id_exact_match",
            file_disk_basis: "header_pid_context_candidate_only_never_confirmed_ownership",
        },
        status: if has_gaps { "partial" } else { "complete" },
        attribution_status,
        capture: CaptureIdentity {
            source_format: "sideeffect.windows_runtime_capture_v3",
            sha256: capture_sha256.clone(),
            claimed_status: match capture.collection_status {
                crate::windows_runtime::CollectionStatus::Complete => "complete",
                crate::windows_runtime::CollectionStatus::Partial => "partial",
            }
            .to_owned(),
            capture_completeness: "unknown",
            event_loss_reported: capture.event_loss.events_lost > 0
                || capture.event_loss.log_buffers_lost > 0
                || capture.event_loss.real_time_buffers_lost > 0,
            loss_statistics_available: capture.event_loss.loss_statistics_available,
            final_loss_snapshot_available: capture.event_loss.final_snapshot_available,
        },
        target_process_id: target_pid,
        target_start_status: match target_starts {
            0 => "not_observed",
            1 => "observed_once",
            _ => "ambiguous_multiple_rows",
        },
        summary: AttributionCounts {
            observed_target_process_instances,
            observed_descendant_process_instances,
            payload_pid_attributed_events,
            header_pid_context_candidates,
            unassigned_events: unassigned_events.len(),
            ambiguous_process_ids: ambiguous_pids.len(),
        },
        processes,
        event_attributions,
        unassigned_events,
        diagnostics,
        limitations: vec![
            "This is a derived candidate view over the supplied capture; its SHA-256 does not authenticate the capture or its collector.",
            "Descendant links require one supported process-start payload whose parent ID matches one active observed target-tree process; they do not establish application-level causation.",
            "Network association uses the decoded provider payload process ID and the observed process-ID lifetime; it does not identify remote hosts or prove operation success.",
            "File and disk header process IDs are event-context candidates only. They do not establish that the selected process performed the represented operation.",
            "Unassigned records remain in the raw capture and are listed by source ordinal; no match does not establish absence or non-execution.",
            "Process-ID reuse, missing lifecycle rows, decoder gaps, or event loss reduce or prevent attribution; capture completeness remains unknown.",
        ],
    })
}

fn process_event<'a>(
    event: &'a NativeRuntimeEvent,
    expected_kind: &str,
) -> Option<(&'a DecodedProcessPayload, &'a str)> {
    if !provider_matches(&event.provider_guid)
        || event.event_id != 0
        || event.event_kind != expected_kind
        || match expected_kind {
            "process_start" => event.opcode != 1,
            "process_end" => event.opcode != 2,
            _ => true,
        }
    {
        return None;
    }
    let payload = event.payload_decoding.as_ref()?;
    let process_id = payload.process_id?;
    let parent_id = payload.parent_process_id?;
    let image = payload.image_file_name.as_deref()?;
    if payload.status != ProcessDecodeStatus::Decoded
        || payload.schema_name.as_deref() != Some("windows.kernel_process_typegroup1")
        || payload.schema_version != Some(event.event_version)
        || event.event_version > 3
        || !matches!(payload.pointer_size_bytes, Some(4 | 8))
        || process_id == 0
        || image.is_empty()
    {
        return None;
    }
    let _ = parent_id;
    Some((payload, image))
}

fn provider_matches(value: &str) -> bool {
    normalized_guid(value).as_deref() == Some(PROCESS_PROVIDER_GUID)
}

fn normalized_guid(value: &str) -> Option<String> {
    let value = value.trim();
    let value = value
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(value);
    (value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        }))
    .then(|| value.to_ascii_lowercase())
}

fn is_network_observation(event: &NativeRuntimeEvent) -> bool {
    let Some(value) = event.observation_decoding.as_ref() else {
        return false;
    };
    if value.get("status").and_then(Value::as_str) != Some("decoded")
        || value
            .pointer("/observation/activity/kind")
            .and_then(Value::as_str)
            != Some("network")
        || value
            .pointer("/observation/schema_version")
            .and_then(Value::as_u64)
            != Some(2)
        || event.event_kind != "network_observation"
        || event.event_id != 0
        || event.event_version != 2
    {
        return false;
    }
    let Some(schema) = value.pointer("/observation/schema").and_then(Value::as_str) else {
        return false;
    };
    match normalized_guid(&event.provider_guid).as_deref() {
        Some(TCP_PROVIDER_GUID) => match event.opcode {
            10 => schema == "windows.kernel_tcp_ipv4_send",
            11 | 13 | 14 | 16 | 18 => schema == "windows.kernel_tcp_ipv4_typegroup1",
            12 | 15 => schema == "windows.kernel_tcp_ipv4_typegroup2",
            26 => schema == "windows.kernel_tcp_ipv6_send",
            27 | 29 | 30 | 32 | 34 => schema == "windows.kernel_tcp_ipv6_typegroup3",
            28 | 31 => schema == "windows.kernel_tcp_ipv6_typegroup4",
            _ => false,
        },
        Some(UDP_PROVIDER_GUID) => match event.opcode {
            10 | 11 => schema == "windows.kernel_udp_ipv4_typegroup1",
            26 | 27 => schema == "windows.kernel_udp_ipv6_typegroup2",
            _ => false,
        },
        _ => false,
    }
}

fn is_file_or_disk_observation(event: &NativeRuntimeEvent) -> bool {
    let Some(value) = event.observation_decoding.as_ref() else {
        return false;
    };
    if value.get("status").and_then(Value::as_str) != Some("decoded") {
        return false;
    }
    match (
        normalized_guid(&event.provider_guid).as_deref(),
        value
            .pointer("/observation/activity/kind")
            .and_then(Value::as_str),
        value.pointer("/observation/schema").and_then(Value::as_str),
        value
            .pointer("/observation/schema_version")
            .and_then(Value::as_u64),
        event.event_id,
        event.event_version,
        event.opcode,
    ) {
        (
            Some(FILE_PROVIDER_GUID),
            Some("file"),
            Some("windows.kernel_file_io"),
            Some(2),
            0,
            2,
            0 | 32 | 35 | 36 | 64 | 65 | 66 | 67 | 68 | 69 | 70 | 71 | 73 | 74 | 75,
        ) => event.event_kind == "file_io_observation",
        (
            Some(DISK_PROVIDER_GUID),
            Some("disk"),
            Some("windows.kernel_disk_io"),
            Some(0),
            0,
            0,
            10 | 11 | 14,
        ) => event.event_kind == "disk_io_observation",
        _ => false,
    }
}

fn payload_pid(event: &NativeRuntimeEvent) -> Option<u32> {
    event
        .observation_decoding
        .as_ref()?
        .pointer("/observation/activity/observation/payload_process_id")?
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
}

fn event_reference(capture_sha256: &str, event: &NativeRuntimeEvent) -> EventReference {
    event_reference_by_ordinal(capture_sha256, event.record_ordinal)
}

fn event_reference_by_ordinal(capture_sha256: &str, ordinal: u64) -> EventReference {
    EventReference {
        capture_sha256: capture_sha256.to_owned(),
        record_ordinal: ordinal,
    }
}

fn unassigned(
    capture_sha256: &str,
    event: &NativeRuntimeEvent,
    reason: &'static str,
) -> UnassignedEvent {
    UnassignedEvent {
        event: event_reference(capture_sha256, event),
        event_kind: event.event_kind.clone(),
        reason,
    }
}
