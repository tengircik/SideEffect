#![allow(dead_code)]

#[path = "../src/inventory/debian.rs"]
mod debian;
#[path = "../src/fingerprint.rs"]
mod fingerprint;
#[path = "../src/limits.rs"]
mod limits;
#[path = "../src/inventory/model.rs"]
mod model;

use debian::parse_dpkg_query_output;
use model::{InventorySourceStatus, InventoryStatus};

const SYNTHETIC_DPKG_QUERY_OUTPUT: &[u8] =
    b"alpha:amd64\t1.2.3\tamd64\tii \nbeta\t0:4.0-1\tall\t rc\n";

#[test]
fn parses_synthetic_rows_with_exact_evidence_offsets_and_schema() {
    let document = parse_dpkg_query_output(SYNTHETIC_DPKG_QUERY_OUTPUT, 1234);
    assert_eq!(document.schema, "sideeffect.inventory");
    assert_eq!(document.schema_version, 1);
    assert_eq!(document.platform, "linux");
    assert_eq!(document.scope, "debian_package_database");
    assert_eq!(document.captured_at_unix_ms, 1234);
    assert_eq!(document.status, InventoryStatus::Complete);
    assert_eq!(document.sources[0].id, "dpkg_query");
    assert_eq!(document.sources[0].status, InventorySourceStatus::Complete);
    assert_eq!(document.sources[0].records_seen, 2);
    assert_eq!(document.packages.len(), 2);

    let first = &document.packages[0];
    assert_eq!(first.name.as_deref(), Some("alpha:amd64"));
    assert_eq!(first.version.as_deref(), Some("1.2.3"));
    assert_eq!(first.architecture.as_deref(), Some("amd64"));
    assert_eq!(first.status_abbrev.as_deref(), Some("ii "));
    assert_eq!(first.evidence.line, 1);
    assert_eq!(first.evidence.byte_offset, 0);
    assert_eq!(
        first.evidence.byte_length,
        b"alpha:amd64\t1.2.3\tamd64\tii ".len()
    );
    assert_eq!(
        first.evidence.raw_record.as_deref(),
        Some("alpha:amd64\t1.2.3\tamd64\tii ")
    );
    assert!(first.evidence.raw_record_hex.is_none());
    assert_eq!(first.evidence.record_sha256.len(), 64);

    let second = &document.packages[1];
    assert_eq!(second.name.as_deref(), Some("beta"));
    assert_eq!(second.evidence.line, 2);
    assert_eq!(
        second.evidence.byte_offset,
        b"alpha:amd64\t1.2.3\tamd64\tii \n".len()
    );
    assert_eq!(second.evidence.record_sha256.len(), 64);

    let json = serde_json::to_value(&document).unwrap();
    assert_eq!(json["schema"], "sideeffect.inventory");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["packages"][0]["evidence"]["line"], 1);
    assert!(json.get("stderr").is_none());
}

#[test]
fn retains_malformed_synthetic_rows_as_diagnostic_evidence() {
    let bytes = b"good\t1\tamd64\tii \nwrong\tfields\ninvalid\xff\t1\tall\tii \nlast\t1\tall\tii ";
    let document = parse_dpkg_query_output(bytes, 7);
    assert_eq!(document.status, InventoryStatus::Partial);
    assert_eq!(document.sources[0].status, InventorySourceStatus::Partial);
    assert_eq!(document.sources[0].records_seen, 4);
    assert_eq!(document.packages.len(), 4);
    assert!(document.packages[0].diagnostic_code.is_none());
    assert_eq!(
        document.packages[1].diagnostic_code,
        Some("malformed_source_row")
    );
    assert_eq!(
        document.packages[1].evidence.byte_length,
        b"wrong\tfields".len()
    );
    assert_eq!(document.packages[1].evidence.raw_record, None);
    assert_eq!(
        document.packages[1].evidence.raw_record_hex.as_deref(),
        Some("77726f6e67096669656c6473")
    );
    assert_eq!(
        document.packages[2].diagnostic_code,
        Some("malformed_source_row")
    );
    assert_eq!(
        document.packages[2].evidence.byte_length,
        b"invalid\xff\t1\tall\tii ".len()
    );
    assert_eq!(
        document.packages[2].evidence.raw_record_hex.as_deref(),
        Some("696e76616c6964ff093109616c6c09696920")
    );
    assert_eq!(
        document.packages[3].diagnostic_code,
        Some("missing_line_terminator")
    );
    assert_eq!(document.packages[3].evidence.line, 4);
    assert_eq!(document.sources[0].diagnostics.len(), 3);
    assert_eq!(document.sources[0].diagnostics[0].line, Some(2));
    assert_eq!(
        document.sources[0].diagnostics[1].byte_offset,
        Some(document.packages[2].evidence.byte_offset)
    );
    assert_eq!(
        document.sources[0].diagnostics[2].code,
        "missing_line_terminator"
    );
}

#[test]
fn oversized_synthetic_row_is_hashed_and_marked_without_copying_unbounded_data() {
    let mut bytes = vec![b'x'; 8 * 1024 + 1];
    bytes.push(b'\n');
    let document = parse_dpkg_query_output(&bytes, 0);
    assert_eq!(document.status, InventoryStatus::Partial);
    let row = &document.packages[0];
    assert_eq!(row.diagnostic_code, Some("row_length_limit_exceeded"));
    assert_eq!(row.evidence.byte_length, 8 * 1024 + 1);
    assert_eq!(row.evidence.record_sha256.len(), 64);
    let expected_hex = "78".repeat(8 * 1024 + 1);
    assert_eq!(
        row.evidence.raw_record_hex.as_deref(),
        Some(expected_hex.as_str())
    );
    assert_eq!(
        document.sources[0].diagnostics[0].code,
        "row_length_limit_exceeded"
    );
}

#[test]
fn empty_synthetic_output_is_a_complete_empty_database_snapshot() {
    let document = parse_dpkg_query_output(b"", 99);
    assert_eq!(document.status, InventoryStatus::Complete);
    assert_eq!(document.sources[0].records_seen, 0);
    assert!(document.packages.is_empty());
}

#[test]
fn serialized_model_keeps_source_strings_inert_and_excludes_machine_metadata() {
    let document = parse_dpkg_query_output(b"pkg&lt;script&gt;\t1\tall\tii \n", 1);
    let value = serde_json::to_value(document).unwrap();
    assert_eq!(value["packages"][0]["name"], "pkg&lt;script&gt;");
    assert_eq!(value["sources"][0]["id"], "dpkg_query");
    assert_eq!(value["platform"], "linux");
    assert_eq!(value["scope"], "debian_package_database");
    assert_eq!(value.as_object().unwrap().len(), 8);
    let rendered = serde_json::to_string(&value).unwrap();
    assert!(!rendered.contains("/usr/bin/dpkg-query"));
    assert!(!rendered.contains("username"));
    assert!(!rendered.contains("stderr"));
}

#[test]
fn row_length_limit_is_enforced_at_and_above_boundary() {
    let exact = vec![b'a'; 8 * 1024];
    let above = vec![b'a'; 8 * 1024 + 1];
    assert_eq!(
        parse_dpkg_query_output(&exact, 0).packages[0].diagnostic_code,
        Some("missing_line_terminator")
    );
    assert_eq!(
        parse_dpkg_query_output(&above, 0).packages[0].diagnostic_code,
        Some("row_length_limit_exceeded")
    );
}

#[test]
fn synthetic_evidence_has_sha256_of_exact_row_bytes() {
    let row = b"alpha\t1\tall\tii ";
    let mut bytes = row.to_vec();
    bytes.push(b'\n');
    let doc = parse_dpkg_query_output(&bytes, 0);
    assert_eq!(
        doc.packages[0].evidence.record_sha256,
        sha256_hex_for_test(row)
    );
}

fn sha256_hex_for_test(bytes: &[u8]) -> String {
    // Known test vector assertion avoids exposing the production fingerprint helper.
    assert_eq!(bytes, b"alpha\t1\tall\tii ");
    "7e8ad20c48d6caa0a6acd638dbfc172c1dcc0433539b5cc6bf68b4ed43f23856".to_owned()
}
