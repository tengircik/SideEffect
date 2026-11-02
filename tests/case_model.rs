use serde_json::{Value, json};
use sideeffect::case::{
    CASE_SCHEMA, CASE_SCHEMA_VERSION, CasePlatform, Confidence, InvestigationCase, MAX_CASE_BYTES,
    MAX_CASE_ENTRIES, MAX_CASE_SESSIONS, Severity,
};

const LINUX_SESSION: &str = "0123456789abcdef0123456789abcdef";
const WINDOWS_SESSION: &str = "abcdef0123456789abcdef0123456789";
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn valid_case() -> Value {
    json!({
        "schema": CASE_SCHEMA,
        "schema_version": CASE_SCHEMA_VERSION,
        "case_id": "case-1",
        "title": "Review selected runtime evidence",
        "sessions": [{
            "session_id": LINUX_SESSION,
            "platform": "linux",
            "manifest_schema_version": 8,
            "manifest_sha256": HASH
        }],
        "entries": [{
            "id": "assertion-1",
            "kind": "assertion",
            "authorship": "analyst_supplied_unverified",
            "text": "The selected trace contains an observed failed connection attempt.",
            "severity": "medium",
            "confidence": "low",
            "evidence": [{
                "kind": "linux_trace_record",
                "session_id": LINUX_SESSION,
                "manifest_sha256": HASH,
                "artifact_sha256": HASH,
                "line_number": 3,
                "byte_offset": 40,
                "byte_length": 24
            }]
        }]
    })
}

fn parse(value: &Value) -> Result<InvestigationCase, String> {
    InvestigationCase::from_json(&serde_json::to_vec(value).unwrap())
}

#[test]
fn case_model_accepts_analyst_text_and_keeps_severity_separate_from_confidence() {
    let parsed = parse(&valid_case()).unwrap();
    assert_eq!(parsed.entries[0].authorship, "analyst_supplied_unverified");
    assert_eq!(parsed.entries[0].severity, Some(Severity::Medium));
    assert_eq!(parsed.entries[0].confidence, Some(Confidence::Low));
    assert_eq!(parsed.sessions[0].platform, CasePlatform::Linux);
}

#[test]
fn case_model_rejects_unknown_fields_and_wrong_schema() {
    let mut value = valid_case();
    value["unexpected"] = json!(true);
    assert!(parse(&value).unwrap_err().contains("invalid case JSON"));

    let mut value = valid_case();
    value["entries"][0]["unsupported"] = json!("ignored fields are unsafe");
    assert!(parse(&value).unwrap_err().contains("invalid case JSON"));

    let mut value = valid_case();
    value["schema_version"] = json!(99);
    assert!(parse(&value).unwrap_err().contains("case schema must be"));
}

#[test]
fn case_model_rejects_oversized_documents_and_collection_counts() {
    let bytes = vec![b' '; MAX_CASE_BYTES + 1];
    assert!(
        InvestigationCase::from_json(&bytes)
            .unwrap_err()
            .contains("input exceeds")
    );

    let mut too_many_sessions = valid_case();
    too_many_sessions["sessions"] = json!(
        (0..=MAX_CASE_SESSIONS)
            .map(|index| {
                json!({
                    "session_id": format!("{index:032x}"),
                    "platform": "linux",
                    "manifest_schema_version": 8,
                    "manifest_sha256": HASH
                })
            })
            .collect::<Vec<_>>()
    );
    assert!(
        parse(&too_many_sessions)
            .unwrap_err()
            .contains("must reference 1..=")
    );

    let mut too_many_entries = valid_case();
    too_many_entries["entries"] = json!(
        (0..=MAX_CASE_ENTRIES)
            .map(|index| {
                json!({
                    "id": format!("entry-{index}"),
                    "kind": "note",
                    "authorship": "analyst_supplied_unverified",
                    "text": "bounded note",
                    "severity": null,
                    "confidence": null,
                    "evidence": []
                })
            })
            .collect::<Vec<_>>()
    );
    assert!(parse(&too_many_entries).unwrap_err().contains("more than"));
}

#[test]
fn case_model_rejects_duplicate_case_session_and_entry_ids() {
    let mut duplicate_session = valid_case();
    let session = duplicate_session["sessions"][0].clone();
    duplicate_session["sessions"] = json!([session.clone(), session]);
    assert!(
        parse(&duplicate_session)
            .unwrap_err()
            .contains("duplicate session IDs")
    );

    let mut same_id_different_manifest = valid_case();
    let mut changed_session = same_id_different_manifest["sessions"][0].clone();
    changed_session["manifest_sha256"] =
        json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    same_id_different_manifest["sessions"] = json!([
        same_id_different_manifest["sessions"][0].clone(),
        changed_session
    ]);
    assert!(
        parse(&same_id_different_manifest)
            .unwrap_err()
            .contains("duplicate session IDs")
    );

    let mut duplicate_entry = valid_case();
    let entry = duplicate_entry["entries"][0].clone();
    duplicate_entry["entries"]
        .as_array_mut()
        .unwrap()
        .push(entry);
    assert!(
        parse(&duplicate_entry)
            .unwrap_err()
            .contains("duplicate entry IDs")
    );

    let mut duplicate_evidence = valid_case();
    let locator = duplicate_evidence["entries"][0]["evidence"][0].clone();
    duplicate_evidence["entries"][0]["evidence"]
        .as_array_mut()
        .unwrap()
        .push(locator);
    assert!(
        parse(&duplicate_evidence)
            .unwrap_err()
            .contains("duplicate evidence reference")
    );
}

#[test]
fn case_model_rejects_unlisted_sessions_and_cross_platform_locators() {
    let mut unlisted_session = valid_case();
    unlisted_session["entries"][0]["evidence"][0]["session_id"] = json!(WINDOWS_SESSION);
    assert!(
        parse(&unlisted_session)
            .unwrap_err()
            .contains("session not listed")
    );

    let mut changed_manifest_binding = valid_case();
    changed_manifest_binding["entries"][0]["evidence"][0]["manifest_sha256"] =
        json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert!(
        parse(&changed_manifest_binding)
            .unwrap_err()
            .contains("session not listed")
    );

    let mut mixed_sessions = valid_case();
    mixed_sessions["sessions"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "session_id": WINDOWS_SESSION,
            "platform": "windows",
            "manifest_schema_version": 8,
            "manifest_sha256": HASH
        }));
    assert!(
        parse(&mixed_sessions)
            .unwrap_err()
            .contains("one native platform")
    );

    let mut wrong_locator = valid_case();
    wrong_locator["entries"][0]["evidence"][0] = json!({
        "kind": "windows_etw_record",
        "session_id": LINUX_SESSION,
        "manifest_sha256": HASH,
        "artifact_sha256": HASH,
        "capture_sha256": HASH,
        "record_ordinal": 1,
        "json_pointer": "/events/0",
        "raw_payload_sha256": HASH
    });
    assert!(
        parse(&wrong_locator)
            .unwrap_err()
            .contains("does not match the case platform")
    );
}

#[test]
fn case_model_validates_platform_specific_locator_shapes() {
    let mut linux_root_case = valid_case();
    linux_root_case["entries"][0]["evidence"][0] = json!({
        "kind": "selected_root_entry",
        "session_id": LINUX_SESSION,
        "manifest_sha256": HASH,
        "artifact_sha256": HASH,
        "entry_ordinal": 0
    });
    assert!(parse(&linux_root_case).is_ok());

    let mut windows_case = valid_case();
    windows_case["sessions"][0] = json!({
        "session_id": WINDOWS_SESSION,
        "platform": "windows",
        "manifest_schema_version": 8,
        "manifest_sha256": HASH
    });
    windows_case["entries"][0]["evidence"][0] = json!({
        "kind": "windows_etw_record",
        "session_id": WINDOWS_SESSION,
        "manifest_sha256": HASH,
        "artifact_sha256": HASH,
        "capture_sha256": HASH,
        "record_ordinal": 2,
        "json_pointer": "/events/1",
        "raw_payload_sha256": HASH
    });
    assert!(parse(&windows_case).is_ok());

    let mut windows_root_case = windows_case.clone();
    windows_root_case["entries"][0]["evidence"][0] = json!({
        "kind": "selected_root_entry",
        "session_id": WINDOWS_SESSION,
        "manifest_sha256": HASH,
        "artifact_sha256": HASH,
        "entry_ordinal": 0
    });
    assert!(parse(&windows_root_case).is_ok());

    let mut malformed = valid_case();
    malformed["entries"][0]["evidence"][0]["artifact_sha256"] = json!("not-a-digest");
    assert!(
        parse(&malformed)
            .unwrap_err()
            .contains("artifact_sha256 must be")
    );

    let mut malformed = windows_case;
    malformed["entries"][0]["evidence"][0]["json_pointer"] = json!("events/1");
    assert!(parse(&malformed).unwrap_err().contains("JSON pointer"));
}

#[test]
fn case_model_rejects_authored_assertions_without_evidence_or_unverified_label() {
    let mut no_evidence = valid_case();
    no_evidence["entries"][0]["evidence"] = json!([]);
    assert!(
        parse(&no_evidence)
            .unwrap_err()
            .contains("must contain at least one evidence")
    );

    let mut unlabeled = valid_case();
    unlabeled["entries"][0]["authorship"] = json!("verified_finding");
    assert!(
        parse(&unlabeled)
            .unwrap_err()
            .contains("analyst_supplied_unverified")
    );
}

#[test]
fn case_model_rejects_oversized_evidence_lists_and_invalid_trace_ranges() {
    let mut too_many_locators = valid_case();
    let locator = too_many_locators["entries"][0]["evidence"][0].clone();
    too_many_locators["entries"][0]["evidence"] = json!(
        (0..=sideeffect::case::MAX_ENTRY_EVIDENCE)
            .map(|_| locator.clone())
            .collect::<Vec<_>>()
    );
    assert!(parse(&too_many_locators).unwrap_err().contains("more than"));

    let mut overflow = valid_case();
    overflow["entries"][0]["evidence"][0]["byte_offset"] = json!(u64::MAX);
    assert!(parse(&overflow).unwrap_err().contains("byte range"));

    let mut invalid_root_ordinal = valid_case();
    invalid_root_ordinal["entries"][0]["evidence"][0] = json!({
        "kind": "selected_root_entry",
        "session_id": LINUX_SESSION,
        "manifest_sha256": HASH,
        "artifact_sha256": HASH,
        "entry_ordinal": sideeffect::inventory::MAX_ROOT_ENTRIES as u64
    });
    assert!(
        parse(&invalid_root_ordinal)
            .unwrap_err()
            .contains("selected_root_entry ordinal")
    );

    let mut last_valid_root_ordinal = valid_case();
    last_valid_root_ordinal["entries"][0]["evidence"][0] = json!({
        "kind": "selected_root_entry",
        "session_id": LINUX_SESSION,
        "manifest_sha256": HASH,
        "artifact_sha256": HASH,
        "entry_ordinal": sideeffect::inventory::MAX_ROOT_ENTRIES as u64 - 1
    });
    assert!(parse(&last_valid_root_ordinal).is_ok());
}
