use sideeffect::event::*;
use sideeffect::format::{MAX_TIMELINE_HTML_BYTES, write_event_timeline_html};
use sideeffect::limits::MAX_REPORT_BYTES;

fn timeline() -> EventTimeline {
    EventTimeline {
        schema: EVENT_TIMELINE_SCHEMA,
        schema_version: EVENT_TIMELINE_SCHEMA_VERSION,
        source: SourceDescriptor {
            platform: SourcePlatform::Linux,
            schema: "synthetic.capture".into(),
            schema_version: 3,
            artifact: "synthetic-fixture-only".into(),
            sha256: None,
        },
        source_state: SourceState {
            completeness: SourceCompleteness::Partial,
            diagnostics: vec!["fixture partial".into()],
            loss: None,
            identity_ambiguity_present: false,
        },
        ordering: "source ordinal",
        semantics: "source-local listing",
        filter: EventTimelineFilter {
            event_kind: None,
            process_observation_id: None,
        },
        selected_process_observation: None,
        items: vec![CommonEvent {
            source_local_ordinal: 7,
            source_timestamp: Some(SourceTimestamp {
                value: "123".into(),
                clock_unit: "ticks".into(),
            }),
            event_kind: "openat".into(),
            operation: OperationSemantics::SyscallAttempt {
                result: Some(sideeffect::model::SyscallOutcome::Success),
            },
            evidence: EvidenceReference::RawTraceRecord {
                line_number: 7,
                byte_offset: 80,
                byte_length: 12,
            },
            identity_context: vec![],
            network_endpoints: None,
            path_observation: None,
        }],
        event_process_links: vec![EventProcessLink {
            event: EvidenceReference::RawTraceRecord {
                line_number: 7,
                byte_offset: 80,
                byte_length: 12,
            },
            process_observation_id: Some(2),
            reported_process_id: Some(444),
            role: EventProcessLinkRole::LinuxTraceCallerTaskContext,
            status: EventProcessLinkStatus::ContextCandidate,
            basis: "source-row context".into(),
        }],
        diagnostics: vec![],
    }
}

#[test]
fn static_offline_html_escapes_values_and_retains_partial_status_and_evidence() {
    let mut t = timeline();
    let obs_evidence = EvidenceReference::RawTraceRecord {
        line_number: 2,
        byte_offset: 12,
        byte_length: 8,
    };
    t.selected_process_observation = Some(ProcessObservation {
        source_local_id: 2,
        identity: ProcessIdentity::LinuxReturnedChildPid {
            process_id: 444,
            identity_status: ProcessIdentityStatus::ReturnedChildPidOnly,
        },
        evidence: obs_evidence.clone(),
        end_evidence: Some(obs_evidence),
    });
    t.items[0].event_kind = "</title><script>alert(1)</script>\x1b\u{202e}".into();
    let mut html = Vec::new();
    write_event_timeline_html(&t, &mut html).unwrap();
    let html = String::from_utf8(html).unwrap();
    assert!(html.contains("default-src 'none'"));
    assert!(html.contains("script-src 'none'"));
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(html.contains("&lt;/title&gt;&lt;script&gt;"));
    assert!(html.contains("&amp;#x1B;"));
    assert!(html.contains("&amp;#x202E;"));
    assert!(html.contains("raw_trace_record line=7 byte_offset=80 byte_length=12"));
    assert!(html.contains("context_candidate"));
    assert!(html.contains("source-row context"));
    assert!(html.contains("End evidence"));
    assert!(html.contains("returned_child_pid_only"));
    assert!(html.contains("partial"));
    assert!(!html.contains("https://"));
    assert!(!html.contains("<script"));
    assert!(!html.contains("<iframe"));
}

#[test]
fn empty_selection_is_explicit_and_output_cap_is_fail_closed() {
    let mut t = timeline();
    t.items.clear();
    t.event_process_links.clear();
    let mut html = Vec::new();
    write_event_timeline_html(&t, &mut html).unwrap();
    assert!(
        String::from_utf8(html)
            .unwrap()
            .contains("does not establish absence")
    );
    let mut oversized = timeline();
    oversized.source.artifact = "x".repeat(MAX_TIMELINE_HTML_BYTES + 1);
    let mut destination = Vec::new();
    assert!(write_event_timeline_html(&oversized, &mut destination).is_err());
    assert!(destination.is_empty());
    assert_eq!(MAX_TIMELINE_HTML_BYTES, MAX_REPORT_BYTES);
}
