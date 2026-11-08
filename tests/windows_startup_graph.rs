use sideeffect::event::{
    CommonEvent, EVENT_GRAPH_SCHEMA, EVENT_GRAPH_SCHEMA_VERSION, EventDiagnostic, EventGraph,
    EventGraphFilter, EventGraphNode, EventGraphNodeKind, EvidenceReference, OperationSemantics,
    SourceCompleteness, SourceDescriptor, SourcePlatform, SourceState,
    graph_with_windows_startup_candidates,
};
use sideeffect::format::{write_event_graph_html, write_event_graph_text};
use sideeffect::windows_startup_correlation::{
    WindowsAssociatedBehavior, WindowsAssociatedBehaviorCounts, WindowsAssociatedBehaviorInputs,
    WindowsAssociatedBehaviorSummary, WindowsAssociatedInputIdentity, WindowsAssociationAlgorithm,
    WindowsProcessStartEvidenceReference, WindowsServiceStartupEvidenceReference,
};

const EXECUTABLE: &str = r"C:\Program Files\Example\worker.exe";
const STARTUP_SHA: &str = "a5";
const RUNTIME_SHA: &str = "b6";

fn graph() -> EventGraph {
    let evidence = EvidenceReference::WindowsEtwRecord {
        record_ordinal: 7,
        json_pointer: "/events/6".to_owned(),
        raw_payload_sha256: "c3".repeat(32),
    };
    EventGraph {
        schema: EVENT_GRAPH_SCHEMA,
        schema_version: EVENT_GRAPH_SCHEMA_VERSION,
        filter: EventGraphFilter {
            event_kind: None,
            process_observation_id: None,
        },
        source: SourceDescriptor {
            platform: SourcePlatform::Windows,
            schema: "sideeffect.windows_runtime_capture".to_owned(),
            schema_version: 3,
            artifact: "windows-runtime".to_owned(),
            sha256: Some("d4".repeat(32)),
        },
        source_state: SourceState {
            completeness: SourceCompleteness::Unknown,
            diagnostics: vec!["capture_completeness_unknown".to_owned()],
            loss: None,
            identity_ambiguity_present: false,
        },
        supplemental_sources: Vec::new(),
        semantics: "source-local graph",
        nodes: vec![EventGraphNode {
            id: "event:7".to_owned(),
            kind: EventGraphNodeKind::Event,
            source_local_ordinal: Some(7),
            evidence: Some(evidence.clone()),
            event: Some(CommonEvent {
                source_local_ordinal: 7,
                source_timestamp: None,
                event_kind: "process_start".to_owned(),
                operation: OperationSemantics::NativeObservation,
                evidence,
                identity_context: Vec::new(),
                path_observation: None,
            }),
            process_observation: None,
            reported_process_id: None,
            context_note: None,
            supplemental_evidence: None,
            service_startup_configuration: None,
        }],
        edges: Vec::new(),
        diagnostics: Vec::<EventDiagnostic>::new(),
    }
}

fn summary(status: &'static str) -> WindowsAssociatedBehaviorSummary {
    WindowsAssociatedBehaviorSummary {
        schema: "sideeffect.windows_associated_behavior_summary",
        schema_version: 2,
        algorithm: WindowsAssociationAlgorithm {
            id: "windows_startup_source_process_image_exact_path",
            version: 2,
            basis: "exact_equality_of_drive_rooted_windows_path_strings",
        },
        platform_adapter: "windows_startup_inventory_v10_windows_runtime_capture_v3",
        capture_completeness: "unknown",
        status,
        association_status: "candidate_match",
        inputs: WindowsAssociatedBehaviorInputs {
            startup_inventory: WindowsAssociatedInputIdentity {
                source_format: "sideeffect.windows_startup_inventory_v10".to_owned(),
                sha256: STARTUP_SHA.repeat(32),
                source_status: if status == "complete" {
                    "complete"
                } else {
                    "partial"
                }
                .to_owned(),
                capture_completeness: "unknown",
            },
            runtime_capture: WindowsAssociatedInputIdentity {
                source_format: "sideeffect.windows_runtime_capture_v3".to_owned(),
                sha256: RUNTIME_SHA.repeat(32),
                source_status: if status == "complete" {
                    "complete".to_owned()
                } else {
                    "partial".to_owned()
                },
                capture_completeness: "unknown",
            },
        },
        summary: WindowsAssociatedBehaviorCounts {
            scheduled_task_action_count: 0,
            supported_absolute_exec_action_count: 0,
            unsupported_or_incomplete_action_count: 0,
            registry_entry_count: 0,
            supported_absolute_registry_command_count: 0,
            unsupported_or_incomplete_registry_command_count: 0,
            service_entry_count: 2,
            supported_absolute_service_binary_path_count: 2,
            unsupported_or_incomplete_service_binary_path_count: 0,
            process_start_event_count: 1,
            unsupported_process_start_event_count: 0,
            candidate_path_group_count: 1,
            candidate_action_reference_count: 0,
            candidate_registry_reference_count: 0,
            candidate_service_reference_count: 2,
            candidate_process_event_count: 1,
        },
        diagnostics: Vec::new(),
        limitations: Vec::new(),
        associations: vec![WindowsAssociatedBehavior {
            status: "candidate_match",
            confidence: "limited_candidate",
            basis: "exact_equality_of_drive_rooted_windows_path_strings",
            executable_path: EXECUTABLE.to_owned(),
            multiple_startup_references: true,
            multiple_runtime_observations: false,
            startup_evidence: Vec::new(),
            registry_evidence: Vec::new(),
            service_evidence: vec![
                WindowsServiceStartupEvidenceReference {
                    source: "Windows SCM service configuration".to_owned(),
                    service_index: 2,
                    service_name: "ExampleSvc<script>".to_owned(),
                    executable_path: EXECUTABLE.to_owned(),
                },
                WindowsServiceStartupEvidenceReference {
                    source: "Windows SCM service configuration".to_owned(),
                    service_index: 3,
                    service_name: "ExampleSvcBackup".to_owned(),
                    executable_path: EXECUTABLE.to_owned(),
                },
            ],
            runtime_evidence: vec![WindowsProcessStartEvidenceReference {
                capture_sha256: RUNTIME_SHA.repeat(32),
                record_ordinal: 7,
                process_id: 81,
                image_file_name: EXECUTABLE.to_owned(),
            }],
        }],
    }
}

#[test]
fn service_startup_candidates_preserve_duplicate_rows_and_both_evidence_sources() {
    let graph = graph_with_windows_startup_candidates(graph(), &summary("complete")).unwrap();
    assert_eq!(graph.supplemental_sources.len(), 1);
    assert_eq!(graph.supplemental_sources[0].schema_version, 10);
    assert_eq!(graph.edges.len(), 2);
    assert_eq!(
        graph
            .nodes
            .iter()
            .filter(|node| node.kind == EventGraphNodeKind::ServiceStartupConfiguration)
            .count(),
        2
    );
    for edge in &graph.edges {
        assert_eq!(edge.kind, "startup_process_candidate");
        assert!(edge.basis.contains("candidate only"));
        assert_eq!(edge.evidence.len(), 1);
        assert_eq!(
            edge.supplemental_evidence[0].json_pointer,
            if edge.from_node_id == "startup_service:2" {
                "/service_entries/2"
            } else {
                "/service_entries/3"
            }
        );
    }

    let value = serde_json::to_value(&graph).unwrap();
    assert_eq!(value["schema_version"], 6);
    assert_eq!(
        value["edges"][0]["supplemental_evidence"][0]["artifact_sha256"],
        STARTUP_SHA.repeat(32)
    );

    let mut text = Vec::new();
    write_event_graph_text(&graph, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("startup_process_candidate"));
    assert!(text.contains("/service_entries/2"));
    assert!(text.contains("does not show that a service launched"));

    let mut html = Vec::new();
    write_event_graph_html(&graph, &mut html).unwrap();
    let html = String::from_utf8(html).unwrap();
    assert!(html.contains("/service_entries/2"));
    assert!(html.contains("&lt;script&gt;"));
    assert!(!html.contains("ExampleSvc<script>"));
    assert!(html.contains("does not prove the service launched"));
}

#[test]
fn partial_startup_or_runtime_inputs_mark_graph_diagnostics() {
    let graph = graph_with_windows_startup_candidates(graph(), &summary("partial")).unwrap();
    assert!(
        graph
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "startup_candidate_input_partial" })
    );
}

#[test]
fn unsupported_summary_relationships_are_rejected() {
    let mut summary = summary("complete");
    summary.associations[0].confidence = "high";
    assert!(graph_with_windows_startup_candidates(graph(), &summary).is_err());
}
