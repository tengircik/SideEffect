#![cfg(windows)]

use serde_json::{Value, json};
use sha2::Digest;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sideeffect-session-comparability-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn audit(root: &Path, name: &str) -> PathBuf {
    let output_path = root.join(name);
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&output_path)
        .arg("--packages")
        .output()
        .unwrap();
    assert!(
        matches!(output.status.code(), Some(0 | 2)),
        "audit fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output_path
}

fn audit_msix(root: &Path, name: &str) -> PathBuf {
    let output_path = root.join(name);
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&output_path)
        .arg("--msix")
        .output()
        .unwrap();
    assert!(
        matches!(output.status.code(), Some(0 | 2)),
        "MSIX audit fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output_path
}

fn audit_app_paths(root: &Path, name: &str) -> PathBuf {
    let output_path = root.join(name);
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&output_path)
        .arg("--app-paths")
        .output()
        .unwrap();
    assert!(
        matches!(output.status.code(), Some(0 | 2)),
        "App Paths audit fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output_path
}

fn compare(before: &Path, after: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-sessions")
        .arg(before)
        .arg(after)
        .output()
        .unwrap()
}

fn manifest(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path.join("session.json")).unwrap()).unwrap()
}

fn write_manifest(path: &Path, value: &Value) {
    fs::write(
        path.join("session.json"),
        serde_json::to_vec_pretty(value).unwrap(),
    )
    .unwrap();
}

fn msix_document(packages: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema":"sideeffect.windows_msix_inventory","schema_version":1,
        "platform":"windows","scope":"current_user_registered_appx_and_msix_packages_only",
        "capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":"complete",
        "sources":[{"id":"current_user_appx_msix_packages","status":"complete","packages_seen":packages.as_array().unwrap().len(),"scope":"calling_user_only","diagnostics":[]}],
        "packages":packages
    })).unwrap()
}

fn write_msix_artifact(session: &Path, bytes: &[u8]) {
    fs::write(session.join("msix.windows.json"), bytes).unwrap();
    let mut value = manifest(session);
    let source = value["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["role"] == "msix")
        .unwrap();
    source["status"] = json!("complete");
    source["artifacts"][0]["byte_length"] = json!(bytes.len());
    source["artifacts"][0]["sha256"] = json!(format!("{:x}", sha2::Sha256::digest(bytes)));
    value["status"] = json!("complete");
    write_manifest(session, &value);
}

fn software_document(subkey: &str, display_name: &str, version: &str, publisher: &str) -> Vec<u8> {
    fn utf16_units_hex(text: &str) -> String {
        let mut output = String::with_capacity(text.encode_utf16().count() * 4);
        for unit in text.encode_utf16() {
            write!(&mut output, "{unit:04x}").unwrap();
        }
        output
    }
    fn utf16le_hex(text: &str) -> String {
        let mut output = String::with_capacity(text.encode_utf16().count() * 4);
        for unit in text.encode_utf16() {
            for byte in unit.to_le_bytes() {
                write!(&mut output, "{byte:02x}").unwrap();
            }
        }
        output
    }

    let registry_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    serde_json::to_vec(&json!({
        "schema":"sideeffect.windows_software_inventory","schema_version":1,
        "platform":"windows","scope":"current_user_and_accessible_machine_uninstall_registry_entries",
        "capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":"complete",
        "sources":[
            {"id":"current_user_native_uninstall","status":"complete","registrations_seen":1,
                "hive":"HKEY_CURRENT_USER","registry_key":registry_key,"registry_view":"native","diagnostics":[]},
            {"id":"current_user_32_uninstall","status":"complete","registrations_seen":0,
                "hive":"HKEY_CURRENT_USER","registry_key":registry_key,"registry_view":"wow64_32","diagnostics":[]},
            {"id":"local_machine_64_uninstall","status":"complete","registrations_seen":0,
                "hive":"HKEY_LOCAL_MACHINE","registry_key":registry_key,"registry_view":"wow64_64","diagnostics":[]},
            {"id":"local_machine_32_uninstall","status":"complete","registrations_seen":0,
                "hive":"HKEY_LOCAL_MACHINE","registry_key":registry_key,"registry_view":"wow64_32","diagnostics":[]}
        ],
        "registrations":[{
            "registry_subkey":subkey,"registry_subkey_utf16_hex":utf16_units_hex(subkey),
            "display_name":display_name,"values":[
                {"name":"DisplayName","registry_type":1,"type_name":"REG_SZ","text":display_name,"raw_data_hex":utf16le_hex(display_name)},
                {"name":"DisplayVersion","registry_type":1,"type_name":"REG_SZ","text":version,"raw_data_hex":utf16le_hex(version)},
                {"name":"Publisher","registry_type":1,"type_name":"REG_SZ","text":publisher,"raw_data_hex":utf16le_hex(publisher)},
                {"name":"UninstallString","registry_type":1,"type_name":"REG_SZ",
                    "text":"C:\\Users\\PrivateUser\\AppData\\Local\\Programs\\SensitiveSuite\\uninstall.exe --token private-value",
                    "raw_data_hex":utf16le_hex("C:\\Users\\PrivateUser\\AppData\\Local\\Programs\\SensitiveSuite\\uninstall.exe --token private-value")}
            ],
            "evidence":{"source":"RegEnumKeyExW/RegQueryValueExW","hive":"HKEY_CURRENT_USER",
                "registry_view":"native","registry_key":registry_key,"registration_index":0,"registry_subkey":subkey}
        }]
    })).unwrap()
}

fn write_software_artifact(session: &Path, bytes: &[u8]) {
    fs::write(session.join("software.windows.json"), bytes).unwrap();
    let mut value = manifest(session);
    let source = value["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["role"] == "packages")
        .unwrap();
    source["status"] = json!("complete");
    source["artifacts"][0]["byte_length"] = json!(bytes.len());
    source["artifacts"][0]["sha256"] = json!(format!("{:x}", sha2::Sha256::digest(bytes)));
    let coverage_source = value["coverage_manifest"]["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["role"] == "packages")
        .unwrap();
    coverage_source["status"] = json!("observed");
    value["status"] = json!("complete");
    write_manifest(session, &value);
}

fn msix_row(ordinal: usize, version: u16) -> Value {
    fn exact(text: &str) -> Value {
        let mut utf16_hex = String::with_capacity(text.encode_utf16().count() * 4);
        for unit in text.encode_utf16() {
            write!(&mut utf16_hex, "{unit:04x}").unwrap();
        }
        json!({"text":text,"utf16_hex":utf16_hex,"display_replaced_invalid_utf16":false})
    }
    let full_name = format!("Demo_{version}_neutral__publisher");
    let family_name = if ordinal == 0 {
        "Demo_publisher"
    } else {
        "Other_publisher"
    };
    json!({"ordinal":ordinal,"name":exact("Demo"),"publisher":exact("Publisher"),
        "full_name":exact(&full_name),"family_name":exact(family_name),
        "install_location":exact("C:\\Apps\\Demo"),"version":{"major":version,"minor":0,"build":0,"revision":0},
        "is_framework":false,"is_resource_package":false,"is_bundle":false,"is_development_mode":false})
}

fn app_paths_document(name: &str, executable_path: &str) -> Vec<u8> {
    fn utf16_hex(text: &str) -> String {
        let mut output = String::with_capacity(text.encode_utf16().count() * 4);
        for unit in text.encode_utf16() {
            write!(&mut output, "{unit:04x}").unwrap();
        }
        output
    }
    fn raw_utf16_hex(text: &str) -> String {
        let mut output = String::with_capacity((text.encode_utf16().count() + 1) * 4);
        for unit in text.encode_utf16().chain(std::iter::once(0)) {
            write!(&mut output, "{:02x}{:02x}", unit as u8, (unit >> 8) as u8).unwrap();
        }
        output
    }
    let mut sources = Vec::new();
    for (id, hive, registry_view) in [
        (
            "current_user_native_app_paths",
            "HKEY_CURRENT_USER",
            "native",
        ),
        (
            "local_machine_64_app_paths",
            "HKEY_LOCAL_MACHINE",
            "wow64_64",
        ),
        (
            "local_machine_32_app_paths",
            "HKEY_LOCAL_MACHINE",
            "wow64_32",
        ),
    ] {
        let contains_row = id == "current_user_native_app_paths";
        sources.push(json!({
            "id":id,"status":"complete","entries_seen":usize::from(contains_row),
            "hive":hive,"registry_key":"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths",
            "registry_view":registry_view,"diagnostics":[]
        }));
    }
    let entries = json!([{
        "registered_name":name,"registered_name_utf16_hex":utf16_hex(name),
        "executable_path":{"name":"(Default)","registry_type":2,"type_name":"REG_EXPAND_SZ",
            "text":executable_path,"raw_data_hex":raw_utf16_hex(executable_path)},
        "search_path":null,"duplicate_registration_name":false,
        "evidence":{"source":"RegEnumKeyExW/RegQueryValueExW","hive":"HKEY_CURRENT_USER",
            "registry_view":"native","registry_key":"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths",
            "entry_index":0,"registry_subkey":name}
    }]);
    serde_json::to_vec(&json!({
        "schema":"sideeffect.windows_app_path_inventory","schema_version":1,"platform":"windows",
        "scope":"selected_current_user_native_and_accessible_machine_32_bit_and_64_bit_app_paths_registry_entries",
        "capture_started_at_unix_ms":1,"capture_ended_at_unix_ms":2,"status":"complete",
        "sources":sources,"entries":entries,"duplicate_registration_names":0
    })).unwrap()
}

fn write_app_paths_artifact(session: &Path, bytes: &[u8]) {
    fs::write(session.join("app-paths.windows.json"), bytes).unwrap();
    let mut value = manifest(session);
    let source = value["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["role"] == "app_paths")
        .unwrap();
    source["status"] = json!("complete");
    source["artifacts"][0]["byte_length"] = json!(bytes.len());
    source["artifacts"][0]["sha256"] = json!(format!("{:x}", sha2::Sha256::digest(bytes)));
    let coverage_source = value["coverage_manifest"]["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["role"] == "app_paths")
        .unwrap();
    coverage_source["status"] = json!("observed");
    value["status"] = json!("complete");
    write_manifest(session, &value);
}

#[test]
fn compare_sessions_emits_private_app_paths_change_evidence_and_v11_contract() {
    let root = TestDirectory::new();
    let before_bytes =
        app_paths_document("SensitiveProgram.exe", "%LOCALAPPDATA%\\Old\\program.exe");
    let after_bytes =
        app_paths_document("SensitiveProgram.exe", "%LOCALAPPDATA%\\New\\program.exe");
    let direct = sideeffect::inventory::compare_windows_app_paths_inventory_json(
        &before_bytes,
        &after_bytes,
    );
    assert!(
        direct.is_ok(),
        "direct comparator error: {:?}",
        direct.err()
    );
    let before = audit_app_paths(&root.0, "app-paths-before");
    let after = audit_app_paths(&root.0, "app-paths-after");
    assert_eq!(manifest(&before)["schema_version"], 11);
    assert_eq!(
        manifest(&before)["sources"][0]["artifacts"][0]["path"],
        "app-paths.windows.json"
    );
    write_app_paths_artifact(&before, &before_bytes);
    write_app_paths_artifact(&after, &after_bytes);
    let output = compare(&before, &after);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let serialized = String::from_utf8_lossy(&output.stdout);
    assert!(!serialized.contains("SensitiveProgram.exe"));
    assert!(!serialized.contains("LOCALAPPDATA"));
    let value = report(&output);
    let source = value["source_diffs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["role"] == "app_paths")
        .unwrap();
    assert_eq!(
        source["status"], "compared",
        "reason: {}",
        source["reason_code"]
    );
    let delta = &source["comparison"]["deltas"][0];
    assert_eq!(delta["kind"], "changed");
    assert_eq!(delta["changed_fields"], json!(["executable_path"]));
    assert_eq!(
        delta["before"]["evidence"]["source_id"],
        "current_user_native_app_paths"
    );
}

#[test]
fn compare_sessions_compares_verified_windows_software_registration_facts() {
    let root = TestDirectory::new();
    let before = audit(&root.0, "software-before");
    let after = audit(&root.0, "software-after");
    let subkey = "Vendor\\SensitiveSuite_InstallRegistration";
    let before_bytes = software_document(subkey, "Sensitive Suite", "1.0.0", "Example Vendor");
    let after_bytes = software_document(
        subkey,
        "Sensitive Suite Pro",
        "2.0.0",
        "Example Vendor Ltd.",
    );
    write_software_artifact(&before, &before_bytes);
    write_software_artifact(&after, &after_bytes);

    for (session, bytes) in [(&before, &before_bytes), (&after, &after_bytes)] {
        let artifact = &manifest(session)["sources"][0]["artifacts"][0];
        assert_eq!(artifact["path"], "software.windows.json");
        assert_eq!(artifact["schema"], "sideeffect.windows_software_inventory");
        assert_eq!(artifact["schema_version"], 1);
        assert_eq!(artifact["byte_length"], bytes.len());
        assert_eq!(
            artifact["sha256"],
            format!("{:x}", sha2::Sha256::digest(bytes))
        );
    }

    let output = compare(&before, &after);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let serialized = String::from_utf8_lossy(&output.stdout);
    assert!(serialized.contains("Sensitive Suite"));
    assert!(serialized.contains("2.0.0"));
    assert!(serialized.contains("Example Vendor Ltd."));
    assert!(!serialized.contains("PrivateUser"));
    assert!(!serialized.contains("uninstall.exe"));
    assert!(!serialized.contains("private-value"));
    assert!(!serialized.contains("raw_data_hex"));

    let value = report(&output);
    let source = value["source_diffs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["role"] == "packages")
        .unwrap();
    assert_eq!(source["status"], "compared");
    assert_eq!(
        source["before_artifacts"][0]["path"],
        "software.windows.json"
    );
    assert_eq!(
        source["before_artifacts"][0]["sha256"],
        format!("{:x}", sha2::Sha256::digest(&before_bytes))
    );
    assert_eq!(
        source["after_artifacts"][0]["sha256"],
        format!("{:x}", sha2::Sha256::digest(&after_bytes))
    );
    let delta = &source["comparison"]["deltas"][0];
    assert_eq!(delta["kind"], "changed");
    assert_eq!(
        delta["changed_fields"],
        json!(["display_name", "display_version", "publisher"])
    );
    assert_eq!(delta["identity"]["registry_subkey"], subkey);
    assert_eq!(delta["before"]["display_name"], "Sensitive Suite");
    assert_eq!(delta["before"]["display_version"], "1.0.0");
    assert_eq!(delta["before"]["publisher"], "Example Vendor");
    assert_eq!(delta["after"]["display_name"], "Sensitive Suite Pro");
    assert_eq!(delta["after"]["display_version"], "2.0.0");
    assert_eq!(delta["after"]["publisher"], "Example Vendor Ltd.");
    assert_eq!(
        delta["before"]["evidence"]["source_id"],
        "current_user_native_uninstall"
    );
    assert_eq!(delta["before"]["evidence"]["registration_index"], 0);
    assert_eq!(
        delta["after"]["evidence"]["source_id"],
        "current_user_native_uninstall"
    );
    assert_eq!(delta["after"]["evidence"]["registration_index"], 0);
}

#[test]
fn compare_sessions_emits_msix_item_changes_and_evidence() {
    let root = TestDirectory::new();
    let before = audit_msix(&root.0, "msix-before");
    let after = audit_msix(&root.0, "msix-after");
    write_msix_artifact(&before, &msix_document(json!([msix_row(0, 1)])));
    write_msix_artifact(
        &after,
        &msix_document(json!([msix_row(0, 2), msix_row(1, 1)])),
    );

    let output = compare(&before, &after);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = report(&output);
    let source = value["source_diffs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["role"] == "msix")
        .unwrap();
    assert_eq!(source["status"], "compared");
    assert_eq!(source["comparison"]["counts"]["changes"], 1);
    assert_eq!(source["comparison"]["counts"]["additions"], 1);
    let changed = source["comparison"]["deltas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|delta| delta["kind"] == "changed")
        .unwrap();
    assert_eq!(changed["before"]["evidence"]["package_ordinal"], 0);
    assert_eq!(changed["after"]["evidence"]["package_ordinal"], 0);
}

fn report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_code(output: &Output, expected: &str) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "unexpected status; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = report(output);
    assert_eq!(value["schema"], "sideeffect.audit_session_diff");
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["status"], "incomparable");
    assert!(
        value["reason_codes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|code| code == expected)
    );
}

fn assert_reason(output: &Output, expected: &str) {
    let value = report(output);
    assert!(
        value["reason_codes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|code| code == expected)
    );
}

fn make_linux_peer(path: &Path) {
    let mut value = manifest(path);
    let old_artifact = path.join("software.windows.json");
    let new_artifact = path.join("packages.json");
    let bytes = br#"{"schema":"sideeffect.inventory","schema_version":2}"#;
    fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&old_artifact)
        .unwrap()
        .write_all(bytes)
        .unwrap();
    fs::rename(old_artifact, &new_artifact).unwrap();
    value["platform"] = json!("linux");
    value["host_context"]["os_name"]["value"] = json!("Linux");
    let source = &mut value["sources"][0];
    source["platform"] = json!("linux");
    source["collector"]["id"] = json!("linux.debian_packages");
    source["scope"] = json!("selected package databases");
    source["artifacts"][0] = json!({
        "kind": "packages",
        "path": "packages.json",
        "schema": "sideeffect.inventory",
        "schema_version": 2,
        "byte_length": bytes.len(),
        "sha256": format!("{:x}", sha2::Sha256::digest(bytes)),
    });
    write_manifest(path, &value);
}

#[test]
fn windows_session_comparability_cli_preserves_metadata_only_and_reader_boundaries() {
    let root = TestDirectory::new();
    let before = audit(&root.0, "before");
    let after = audit(&root.0, "after");

    let compatible = compare(&before, &after);
    assert_eq!(compatible.status.code(), Some(0));
    let compatible_report = report(&compatible);
    assert_eq!(compatible_report["schema"], "sideeffect.audit_session_diff");
    assert_eq!(compatible_report["status"], "comparable");
    assert_eq!(
        compatible_report["metadata_scope"],
        "metadata_readiness_only"
    );
    assert_eq!(
        compatible_report["scope"],
        "metadata_and_item_level_inventory_runtime_and_selected_root_metadata"
    );
    assert!(compatible_report["comparable"].as_bool().unwrap());
    assert_reason(&compatible, "partial_source");
    assert!(
        compatible_report["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item
                == "Caller privilege contexts are not comparability keys and may differ.")
    );
    assert!(compatible_report["source_diffs"].is_array());
    assert_eq!(compatible_report["item_comparison_status"], "partial");

    let mut changed = manifest(&after);
    changed["sources"][0]["scope"] = json!("changed bounded scope");
    write_manifest(&after, &changed);
    assert_code(&compare(&before, &after), "source_scope_mismatch");

    changed["sources"][0]["scope"] = manifest(&before)["sources"][0]["scope"].clone();
    changed["sources"][0]["requested_settings"] = json!([{"code":"fixture_setting","value":1}]);
    write_manifest(&after, &changed);
    assert_code(&compare(&before, &after), "requested_settings_mismatch");

    changed["sources"][0]["requested_settings"] = json!([]);
    changed["status"] = json!("partial");
    changed["sources"][0]["status"] = json!("unknown");
    changed["coverage_manifest"]["sources"][0]["status"] = json!("unknown");
    write_manifest(&after, &changed);
    let partial = compare(&before, &after);
    assert_code(&partial, "coverage_mismatch");
    assert!(
        report(&partial)["reason_codes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "partial_source")
    );

    make_linux_peer(&after);
    assert_code(&compare(&before, &after), "platform_mismatch");

    let mut legacy = manifest(&before);
    legacy["schema_version"] = json!(1);
    legacy.as_object_mut().unwrap().remove("host_context");
    legacy.as_object_mut().unwrap().remove("coverage_manifest");
    legacy["sources"][0]
        .as_object_mut()
        .unwrap()
        .remove("collector");
    legacy["sources"][0]
        .as_object_mut()
        .unwrap()
        .remove("requested_settings");
    legacy["sources"][0]
        .as_object_mut()
        .unwrap()
        .remove("effective_settings");
    let legacy_path = before.clone();
    write_manifest(&legacy_path, &legacy);
    let legacy_result = compare(&legacy_path, &after);
    assert_eq!(
        legacy_result.status.code(),
        Some(2),
        "legacy metadata mismatch; stderr: {}",
        String::from_utf8_lossy(&legacy_result.stderr)
    );
    let legacy_report = report(&legacy_result);
    for reason in [
        "host_os_unknown",
        "source_settings_unknown",
        "coverage_unknown",
    ] {
        assert!(
            legacy_report["reason_codes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|code| code == reason)
        );
    }

    fs::write(before.join("software.windows.json"), b"tampered artifact").unwrap();
    let rejected = compare(&before, &before);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(
        {
            let error = String::from_utf8_lossy(&rejected.stderr);
            error.contains("hash") || error.contains("byte length")
        },
        "unexpected rejection: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );

    let malformed_artifact = audit(&root.0, "malformed-artifact");
    fs::write(malformed_artifact.join("software.windows.json"), b"{").unwrap();
    let mut malformed_artifact_manifest = manifest(&malformed_artifact);
    malformed_artifact_manifest["sources"][0]["artifacts"][0]["byte_length"] = json!(1);
    malformed_artifact_manifest["sources"][0]["artifacts"][0]["sha256"] =
        json!(format!("{:x}", sha2::Sha256::digest(b"{")));
    write_manifest(&malformed_artifact, &malformed_artifact_manifest);
    let rejected = compare(&malformed_artifact, &malformed_artifact);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("bounded JSON"));

    let malformed = audit(&root.0, "malformed");
    fs::write(malformed.join("session.json"), b"{").unwrap();
    let rejected = compare(&malformed, &malformed);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("manifest"));
}

#[test]
fn msix_source_selection_changes_comparability_and_reader_rejects_bad_artifacts() {
    let root = TestDirectory::new();
    let with_msix = audit_msix(&root.0, "with-msix");
    let without_msix = audit(&root.0, "without-msix");
    assert_code(&compare(&with_msix, &without_msix), "source_roles_mismatch");

    let msix_manifest = manifest(&with_msix);
    let msix_source = msix_manifest["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["role"] == "msix")
        .unwrap();
    assert_eq!(msix_source["artifacts"][0]["path"], "msix.windows.json");

    let missing = audit_msix(&root.0, "missing-msix-artifact");
    fs::remove_file(missing.join("msix.windows.json")).unwrap();
    let rejected = compare(&missing, &missing);
    assert_eq!(rejected.status.code(), Some(1));

    let extra = audit_msix(&root.0, "extra-msix-entry");
    fs::write(extra.join("unexpected.txt"), b"unexpected").unwrap();
    let rejected = compare(&extra, &extra);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("not listed"));

    let malformed = audit_msix(&root.0, "malformed-msix-artifact");
    let malformed_bytes = b"{";
    fs::write(malformed.join("msix.windows.json"), malformed_bytes).unwrap();
    let mut malformed_manifest = manifest(&malformed);
    let source = malformed_manifest["sources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|source| source["role"] == "msix")
        .unwrap();
    source["artifacts"][0]["byte_length"] = json!(malformed_bytes.len());
    source["artifacts"][0]["sha256"] =
        json!(format!("{:x}", sha2::Sha256::digest(malformed_bytes)));
    write_manifest(&malformed, &malformed_manifest);
    let rejected = compare(&malformed, &malformed);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("bounded JSON"));
}
