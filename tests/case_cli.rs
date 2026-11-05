use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let root = std::env::temp_dir();
        for _ in 0..32 {
            let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!(
                "sideeffect-case-cli-test-{}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                    }
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create case test directory: {error}"),
            }
        }
        panic!("could not allocate a unique case test directory")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn case_help_describes_the_partial_workflow_and_integrity_boundary() {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("help")
        .arg("case")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("sideeffect case init"));
    assert!(help.contains("sideeffect case migrate"));
    assert!(help.contains("sideeffect case set-status"));
    assert!(help.contains("sideeffect case add-entry"));
    assert!(help.contains("sideeffect case add-note"));
    assert!(help.contains("sideeffect case resolve"));
    assert!(help.contains("not producer authenticity"));
    assert!(help.contains("sensitive local evidence"));

    let note_help = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("help")
        .arg("case")
        .arg("add-note")
        .output()
        .unwrap();
    assert!(note_help.status.success());
    let note_help = String::from_utf8(note_help.stdout).unwrap();
    assert!(note_help.contains("--text-file NOTE.txt"));
    assert!(note_help.contains("analyst_supplied_unverified"));
}

fn run_case_add_note(
    case_path: &PathBuf,
    note_path: &PathBuf,
    output_path: &PathBuf,
    sessions: &[PathBuf],
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
    command
        .arg("case")
        .arg("add-note")
        .arg("--case")
        .arg(case_path)
        .arg("--id")
        .arg("N001")
        .arg("--text-file")
        .arg(note_path)
        .arg("--output")
        .arg(output_path);
    for session in sessions {
        command.arg("--session").arg(session);
    }
    command.output().unwrap()
}

#[test]
fn case_add_note_reads_bounded_text_and_publishes_verified_private_revision() {
    let directory = TestDirectory::new();
    let session = directory.0.join("session");
    let audit = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&session)
        .arg("--packages")
        .output()
        .unwrap();
    assert!(audit.status.success() || audit.status.code() == Some(2));

    let other_session = directory.0.join("other-session");
    let other_audit = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&other_session)
        .arg("--packages")
        .output()
        .unwrap();
    assert!(other_audit.status.success() || other_audit.status.code() == Some(2));

    let case_path = directory.0.join("review.case.json");
    let init = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("init")
        .arg("--output")
        .arg(&case_path)
        .arg("--title")
        .arg("Case note CLI test")
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(init.status.success() || init.status.code() == Some(2));
    let original_case = fs::read(&case_path).unwrap();

    let note_text = "Analyst note: <script>alert('inert')</script>";
    let note_path = directory.0.join("note.txt");
    fs::write(&note_path, note_text.as_bytes()).unwrap();
    let updated_path = directory.0.join("review-with-note.case.json");
    let added = run_case_add_note(
        &case_path,
        &note_path,
        &updated_path,
        std::slice::from_ref(&session),
    );
    assert!(
        added.status.success() || added.status.code() == Some(2),
        "case add-note failed: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert!(!String::from_utf8_lossy(&added.stderr).contains(note_text));
    let inline_output = directory.0.join("inline-note.case.json");
    let inline = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("add-note")
        .arg("--case")
        .arg(&case_path)
        .arg("--id")
        .arg("N002")
        .arg("--text")
        .arg(note_text)
        .arg("--output")
        .arg(&inline_output)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(!inline.status.success());
    assert!(!String::from_utf8_lossy(&inline.stderr).contains(note_text));
    assert!(!inline_output.exists());
    assert_eq!(fs::read(&case_path).unwrap(), original_case);

    let updated_bytes = fs::read(&updated_path).unwrap();
    let updated: Value = serde_json::from_slice(&updated_bytes).unwrap();
    assert_eq!(updated["schema_version"], 2);
    assert_eq!(updated["lifecycle"]["revision"], 2);
    assert_eq!(
        updated["lifecycle"]["previous_case_sha256"],
        format!("{:x}", Sha256::digest(&original_case))
    );
    assert_eq!(updated["entries"].as_array().unwrap().len(), 1);
    assert_eq!(updated["entries"][0]["id"], "N001");
    assert_eq!(updated["entries"][0]["kind"], "note");
    assert_eq!(
        updated["entries"][0]["authorship"],
        "analyst_supplied_unverified"
    );
    assert_eq!(updated["entries"][0]["text"], note_text);
    assert_eq!(updated["entries"][0]["evidence"], serde_json::json!([]));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&updated_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let duplicate_path = directory.0.join("duplicate.case.json");
    let duplicate = run_case_add_note(
        &updated_path,
        &note_path,
        &duplicate_path,
        std::slice::from_ref(&session),
    );
    assert!(!duplicate.status.success());
    assert!(!duplicate_path.exists());

    let existing_path = directory.0.join("existing.case.json");
    let sentinel = b"existing destination must remain untouched";
    fs::write(&existing_path, sentinel).unwrap();
    let existing = run_case_add_note(
        &case_path,
        &note_path,
        &existing_path,
        std::slice::from_ref(&session),
    );
    assert!(!existing.status.success());
    assert_eq!(fs::read(&existing_path).unwrap(), sentinel);

    let mut v1_case: Value = serde_json::from_slice(&original_case).unwrap();
    v1_case["schema_version"] = serde_json::json!(1);
    v1_case.as_object_mut().unwrap().remove("lifecycle");
    let v1_path = directory.0.join("legacy.case.json");
    let v1_bytes = serde_json::to_vec(&v1_case).unwrap();
    fs::write(&v1_path, &v1_bytes).unwrap();
    let v1_output = directory.0.join("v1-output.case.json");
    let v1_result = run_case_add_note(
        &v1_path,
        &note_path,
        &v1_output,
        std::slice::from_ref(&session),
    );
    assert!(!v1_result.status.success());
    assert_eq!(fs::read(&v1_path).unwrap(), v1_bytes);
    assert!(!v1_output.exists());

    let cancelled_path = directory.0.join("cancelled.case.json");
    let cancelled = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("set-status")
        .arg("--case")
        .arg(&case_path)
        .arg("--status")
        .arg("cancelled")
        .arg("--output")
        .arg(&cancelled_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(cancelled.status.success() || cancelled.status.code() == Some(2));
    let terminal_output = directory.0.join("terminal-output.case.json");
    let terminal = run_case_add_note(
        &cancelled_path,
        &note_path,
        &terminal_output,
        std::slice::from_ref(&session),
    );
    assert!(!terminal.status.success());
    assert!(!terminal_output.exists());

    let missing_session_output = directory.0.join("missing-session.case.json");
    let missing_session = run_case_add_note(&case_path, &note_path, &missing_session_output, &[]);
    assert!(!missing_session.status.success());
    assert!(!missing_session_output.exists());

    let mismatched_output = directory.0.join("mismatched-session.case.json");
    let mismatched = run_case_add_note(
        &case_path,
        &note_path,
        &mismatched_output,
        std::slice::from_ref(&other_session),
    );
    assert!(!mismatched.status.success());
    assert!(!mismatched_output.exists());

    for (label, bytes) in [
        ("invalid-utf8", vec![0xff, 0xfe]),
        ("nul", b"note\0text".to_vec()),
        ("empty", Vec::new()),
        ("whitespace", b" \n\t".to_vec()),
        (
            "oversized",
            vec![b'x'; sideeffect::case::MAX_ENTRY_TEXT_BYTES + 1],
        ),
    ] {
        let invalid_note = directory.0.join(format!("{label}.txt"));
        fs::write(&invalid_note, &bytes).unwrap();
        let invalid_output = directory.0.join(format!("{label}.case.json"));
        let result = run_case_add_note(
            &case_path,
            &invalid_note,
            &invalid_output,
            std::slice::from_ref(&session),
        );
        assert!(!result.status.success(), "{label} note input was accepted");
        if !bytes.is_empty() {
            let rejected_text = String::from_utf8_lossy(&bytes);
            assert!(!String::from_utf8_lossy(&result.stderr).contains(rejected_text.as_ref()));
        }
        assert!(
            !invalid_output.exists(),
            "{label} input created an output case"
        );
    }

    let resolved_html = directory.0.join("note.html");
    let html_result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("resolve")
        .arg("--format")
        .arg("html")
        .arg("--output")
        .arg(&resolved_html)
        .arg("--case")
        .arg(&updated_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(html_result.status.success() || html_result.status.code() == Some(2));
    let html = String::from_utf8(fs::read(&resolved_html).unwrap()).unwrap();
    assert!(html.contains("Analyst note: &lt;script&gt;alert(&#39;inert&#39;)&lt;/script&gt;"));
    assert!(!html.contains("Analyst note: <script>"));
}

#[test]
fn case_cli_initializes_and_resolves_against_a_verified_session_without_overwriting() {
    let directory = TestDirectory::new();
    let session = directory.0.join("session");
    let audit = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("audit")
        .arg("--output")
        .arg(&session)
        .arg("--packages")
        .output()
        .unwrap();
    assert!(
        audit.status.success() || audit.status.code() == Some(2),
        "audit fixture setup failed: {}",
        String::from_utf8_lossy(&audit.stderr)
    );

    let case_path = directory.0.join("review.case.json");
    let init = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("init")
        .arg("--output")
        .arg(&case_path)
        .arg("--title")
        .arg("CLI case workflow integration")
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "case init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let case_bytes = fs::read(&case_path).unwrap();
    let case: Value = serde_json::from_slice(&case_bytes).unwrap();
    assert_eq!(case["schema"], "sideeffect.investigation_case");
    assert_eq!(case["schema_version"], 2);
    assert_eq!(case["lifecycle"]["status"], "draft");
    assert_eq!(case["lifecycle"]["revision"], 1);
    assert!(case["lifecycle"]["previous_case_sha256"].is_null());
    assert_eq!(case["title"], "CLI case workflow integration");
    assert_eq!(case["sessions"].as_array().unwrap().len(), 1);
    assert_eq!(case["entries"].as_array().unwrap().len(), 0);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&case_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let second_init = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("init")
        .arg("--output")
        .arg(&case_path)
        .arg("--title")
        .arg("Should not replace existing case")
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(!second_init.status.success());
    assert_eq!(fs::read(&case_path).unwrap(), case_bytes);

    let mut legacy_value = case.clone();
    legacy_value["schema_version"] = serde_json::json!(1);
    legacy_value.as_object_mut().unwrap().remove("lifecycle");
    let legacy_bytes = serde_json::to_vec(&legacy_value).unwrap();
    let legacy_path = directory.0.join("legacy-v1.case.json");
    fs::write(&legacy_path, &legacy_bytes).unwrap();
    let legacy_resolve = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("resolve")
        .arg("--case")
        .arg(&legacy_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(legacy_resolve.status.success() || legacy_resolve.status.code() == Some(2));
    let legacy_report: Value = serde_json::from_slice(&legacy_resolve.stdout).unwrap();
    assert_eq!(legacy_report["schema_version"], 2);
    assert!(legacy_report.get("lifecycle").is_none());
    let migrated_path = directory.0.join("migrated.case.json");
    let migrated = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("migrate")
        .arg("--case")
        .arg(&legacy_path)
        .arg("--status")
        .arg("open")
        .arg("--output")
        .arg(&migrated_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(
        migrated.status.success() || migrated.status.code() == Some(2),
        "migration failed: {}",
        String::from_utf8_lossy(&migrated.stderr)
    );
    let migrated_bytes = fs::read(&migrated_path).unwrap();
    let migrated_value: Value = serde_json::from_slice(&migrated_bytes).unwrap();
    assert_eq!(migrated_value["schema_version"], 2);
    assert_eq!(migrated_value["lifecycle"]["status"], "open");
    assert_eq!(migrated_value["lifecycle"]["revision"], 2);
    assert_eq!(
        migrated_value["lifecycle"]["previous_case_sha256"],
        format!("{:x}", Sha256::digest(&legacy_bytes))
    );
    assert_eq!(fs::read(&legacy_path).unwrap(), legacy_bytes);

    let review_path = directory.0.join("in-review.case.json");
    let to_review = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("set-status")
        .arg("--case")
        .arg(&migrated_path)
        .arg("--status")
        .arg("in_review")
        .arg("--output")
        .arg(&review_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(
        to_review.status.success() || to_review.status.code() == Some(2),
        "status transition failed: {}",
        String::from_utf8_lossy(&to_review.stderr)
    );
    let review_bytes = fs::read(&review_path).unwrap();
    let review_value: Value = serde_json::from_slice(&review_bytes).unwrap();
    assert_eq!(review_value["lifecycle"]["revision"], 3);
    assert_eq!(
        review_value["lifecycle"]["previous_case_sha256"],
        format!("{:x}", Sha256::digest(&migrated_bytes))
    );
    assert_eq!(fs::read(&migrated_path).unwrap(), migrated_bytes);

    let repeated_transition = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("set-status")
        .arg("--case")
        .arg(&migrated_path)
        .arg("--status")
        .arg("in_review")
        .arg("--output")
        .arg(&review_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(!repeated_transition.status.success());
    assert_eq!(fs::read(&review_path).unwrap(), review_bytes);

    let entry_path = directory.0.join("note.json");
    fs::write(&entry_path, br#"{"id":"N001","kind":"note","authorship":"analyst_supplied_unverified","text":"bounded note"}"#).unwrap();
    let blocked_entry = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("add-entry")
        .arg("--case")
        .arg(&review_path)
        .arg("--entry")
        .arg(directory.0.join("note.json"))
        .arg("--output")
        .arg(directory.0.join("blocked-entry.case.json"))
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(!blocked_entry.status.success());

    let reopened_path = directory.0.join("reopened.case.json");
    let reopen = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("set-status")
        .arg("--case")
        .arg(&review_path)
        .arg("--status")
        .arg("open")
        .arg("--output")
        .arg(&reopened_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(reopen.status.success() || reopen.status.code() == Some(2));
    let closed_path = directory.0.join("closed.case.json");
    let close = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("set-status")
        .arg("--case")
        .arg(&reopened_path)
        .arg("--status")
        .arg("closed")
        .arg("--output")
        .arg(&closed_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(close.status.success() || close.status.code() == Some(2));
    let closed_entry = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("add-entry")
        .arg("--case")
        .arg(&closed_path)
        .arg("--entry")
        .arg(&entry_path)
        .arg("--output")
        .arg(directory.0.join("closed-entry.case.json"))
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(!closed_entry.status.success());
    let terminal = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("set-status")
        .arg("--case")
        .arg(&closed_path)
        .arg("--status")
        .arg("open")
        .arg("--output")
        .arg(directory.0.join("reopened-terminal.case.json"))
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(!terminal.status.success());

    fs::write(
        &entry_path,
        br#"{"id":"N001","kind":"note","authorship":"analyst_supplied_unverified","text":"<script>alert(1)</script>\u202e"}"#,
    )
    .unwrap();
    let updated_case_path = directory.0.join("review-with-note.case.json");
    let add_entry = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("add-entry")
        .arg("--case")
        .arg(&case_path)
        .arg("--entry")
        .arg(&entry_path)
        .arg("--session")
        .arg(&session)
        .arg("--output")
        .arg(&updated_case_path)
        .output()
        .unwrap();
    assert!(
        add_entry.status.success() || add_entry.status.code() == Some(2),
        "case add-entry failed: {}",
        String::from_utf8_lossy(&add_entry.stderr)
    );
    assert_eq!(fs::read(&case_path).unwrap(), case_bytes);
    let updated_case_bytes = fs::read(&updated_case_path).unwrap();
    let updated_case: Value = serde_json::from_slice(&updated_case_bytes).unwrap();
    assert_eq!(updated_case["entries"].as_array().unwrap().len(), 1);
    assert_eq!(updated_case["entries"][0]["id"], "N001");

    let duplicate_output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("add-entry")
        .arg("--case")
        .arg(&case_path)
        .arg("--entry")
        .arg(&entry_path)
        .arg("--session")
        .arg(&session)
        .arg("--output")
        .arg(&updated_case_path)
        .output()
        .unwrap();
    assert!(!duplicate_output.status.success());
    assert_eq!(fs::read(&updated_case_path).unwrap(), updated_case_bytes);

    let duplicate_id_output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("add-entry")
        .arg("--case")
        .arg(&updated_case_path)
        .arg("--entry")
        .arg(&entry_path)
        .arg("--session")
        .arg(&session)
        .arg("--output")
        .arg(directory.0.join("duplicate-id.case.json"))
        .output()
        .unwrap();
    assert!(!duplicate_id_output.status.success());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&updated_case_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let invalid_assertion_path = directory.0.join("assertion-without-evidence.json");
    fs::write(
        &invalid_assertion_path,
        br#"{"id":"A001","kind":"assertion","authorship":"analyst_supplied_unverified","text":"Unsupported assertion"}"#,
    )
    .unwrap();
    let invalid_assertion = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("add-entry")
        .arg("--case")
        .arg(&case_path)
        .arg("--entry")
        .arg(&invalid_assertion_path)
        .arg("--session")
        .arg(&session)
        .arg("--output")
        .arg(directory.0.join("invalid.case.json"))
        .output()
        .unwrap();
    assert!(!invalid_assertion.status.success());

    let resolved = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("resolve")
        .arg("--case")
        .arg(&updated_case_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(
        resolved.status.success() || resolved.status.code() == Some(2),
        "case resolve failed: {}",
        String::from_utf8_lossy(&resolved.stderr)
    );
    let report: Value = serde_json::from_slice(&resolved.stdout).unwrap();
    assert_eq!(report["schema"], "sideeffect.resolved_investigation_case");
    assert_eq!(report["case_id"], case["case_id"]);
    assert_eq!(report["facts"].as_array().unwrap().len(), 0);
    assert_eq!(report["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["entries"][0]["text"],
        "<script>alert(1)</script>\u{202e}"
    );
    assert_eq!(report["sessions"].as_array().unwrap().len(), 1);
    assert!(
        report["disclosure_note"]
            .as_str()
            .unwrap()
            .contains("not producer authenticity")
    );

    let html_path = directory.0.join("review.html");
    let html = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("resolve")
        .arg("--format")
        .arg("html")
        .arg("--output")
        .arg(&html_path)
        .arg("--case")
        .arg(&updated_case_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(
        html.status.success() || html.status.code() == Some(2),
        "case HTML resolve failed: {}",
        String::from_utf8_lossy(&html.stderr)
    );
    let html_bytes = fs::read(&html_path).unwrap();
    let html = String::from_utf8(html_bytes.clone()).unwrap();
    assert!(html.contains("Content-Security-Policy"));
    assert!(html.contains("default-src 'none'"));
    assert!(html.contains("script-src 'none'"));
    assert!(!html.contains("Redaction receipt"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&amp;#x202E;"));
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(!html.contains("https://"));

    let redacted_path = directory.0.join("review-redacted.html");
    let redaction_preview = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("resolve")
        .arg("--format")
        .arg("html")
        .arg("--redact")
        .arg("case-text")
        .arg("--preview-redaction")
        .arg("--case")
        .arg(&updated_case_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(
        redaction_preview.status.success() || redaction_preview.status.code() == Some(2),
        "redaction preview failed: {}",
        String::from_utf8_lossy(&redaction_preview.stderr)
    );
    let preview_text = String::from_utf8(redaction_preview.stdout).unwrap();
    assert!(preview_text.contains("case-text: 2 field occurrence(s) would be omitted"));
    assert!(preview_text.contains(
        "Known rendered-field occurrence counts under selected policy (not a content scan):"
    ));
    assert!(
        preview_text
            .contains("case-text: 0 retained / 2 known renderer field occurrence(s); 2 omitted")
    );
    assert!(preview_text.contains("artifact-paths: "));
    assert!(preview_text.contains("evidence-identifiers: "));
    assert!(preview_text.contains("source-records: "));
    assert!(preview_text.contains(
        "Source records remain and can contain arbitrary strings, arguments, or payload. This is not a secret scan and does not make sharing safe."
    ));
    assert!(preview_text.contains("No report was written."));
    assert!(!redacted_path.exists());
    assert!(!preview_text.contains("alert(1)"));
    assert!(!preview_text.contains("<script>"));

    let redacted = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("resolve")
        .arg("--format")
        .arg("html")
        .arg("--redact")
        .arg("case-text")
        .arg("--output")
        .arg(&redacted_path)
        .arg("--case")
        .arg(&updated_case_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(
        redacted.status.success() || redacted.status.code() == Some(2),
        "redacted case HTML resolve failed: {}",
        String::from_utf8_lossy(&redacted.stderr)
    );
    let redacted_html = fs::read_to_string(&redacted_path).unwrap();
    assert!(redacted_html.contains("Redacted export"));
    assert!(redacted_html.contains("[OMITTED: case text]"));
    let receipt_start = redacted_html
        .find("<h2 id=\"redaction-receipt-heading\">")
        .expect("redacted report should include its receipt");
    let receipt_end = receipt_start + redacted_html[receipt_start..].find("</section>").unwrap();
    let receipt = &redacted_html[receipt_start..receipt_end];
    assert!(receipt.contains("Redaction receipt"));
    assert!(
        receipt.contains("case-text: 0 retained / 2 known renderer field occurrence(s); 2 omitted")
    );
    assert!(!receipt.contains("artifact-paths:"));
    assert!(!receipt.contains("source-records:"));
    assert!(!receipt.contains("evidence-identifiers:"));
    assert!(receipt.contains("no content or secret scan was performed"));
    assert!(receipt.contains("does not make this report safe to share"));
    assert!(!receipt.contains("alert(1)"));
    assert!(!receipt.contains("<script>"));
    assert!(!redacted_html.contains("alert(1)"));
    assert_eq!(fs::read(&updated_case_path).unwrap(), updated_case_bytes);

    let html_overwrite = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("resolve")
        .arg("--format")
        .arg("html")
        .arg("--output")
        .arg(&html_path)
        .arg("--case")
        .arg(&updated_case_path)
        .arg("--session")
        .arg(&session)
        .output()
        .unwrap();
    assert!(!html_overwrite.status.success());
    assert_eq!(fs::read(&html_path).unwrap(), html_bytes);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&html_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn case_cli_rejects_unmatched_session_counts_and_oversized_case_files() {
    let directory = TestDirectory::new();
    let case_path = directory.0.join("oversized.case.json");
    fs::write(&case_path, vec![b' '; sideeffect::case::MAX_CASE_BYTES + 1]).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("case")
        .arg("resolve")
        .arg("--case")
        .arg(case_path)
        .arg("--session")
        .arg(directory.0.join("missing-session"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("case input exceeds"));
}
