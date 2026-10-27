use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempTrace(std::path::PathBuf);

impl TempTrace {
    fn with_contents(contents: &[u8]) -> Self {
        loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-query-preview-{}-{id}.trace",
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(contents).unwrap();
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create temporary trace: {error}"),
            }
        }
    }
}

impl Drop for TempTrace {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn run_preview(question: &str, trace: &TempTrace) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["model-query-preview", "--question", question])
        .arg(&trace.0)
        .output()
        .unwrap()
}

#[test]
fn query_preview_keeps_trace_facts_out_of_model_prompt_and_links_sources() {
    let trace = TempTrace::with_contents(
        b"44 openat(AT_FDCWD, \"/tmp/sideeffect-private.sock\", O_RDONLY) = -1 ENOENT (No such file or directory)\n",
    );
    let output = run_preview("Which operation returned ENOENT?", &trace);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(preview["schema"], "sideeffect.local_query_plan_preview");
    assert_eq!(preview["schema_version"], 1);
    assert_eq!(preview["model_repository"], "ggml-org/Qwen3.5-0.8B-GGUF");
    assert_eq!(preview["trace_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(preview["request_sha256"].as_str().unwrap().len(), 64);
    let prompt: serde_json::Value =
        serde_json::from_str(preview["prompt"].as_str().unwrap()).unwrap();
    assert_eq!(prompt["user_question"], "Which operation returned ENOENT?");
    assert!(prompt["supported_query_scope"].is_object());
    assert!(
        !preview["prompt"]
            .as_str()
            .unwrap()
            .contains("/tmp/sideeffect-private.sock")
    );
    assert!(
        preview["queryable_facts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|fact| {
                fact["filters"]["lexical_path_exact"] == "/tmp/sideeffect-private.sock"
                    && fact["evidence"]["line_number"] == 1
            })
    );
    assert_eq!(preview["coverage"], preview["evidence_summary"]);
}

#[test]
fn query_preview_marks_partial_trace_with_exit_status_two() {
    let trace = TempTrace::with_contents(
        b"44 execve(\"/usr/bin/tool\", [\"tool\"], 0x0) = 0\nmalformed trace row\n",
    );
    let output = run_preview("Which executable succeeded?", &trace);
    assert_eq!(output.status.code(), Some(2));
    let preview: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(preview["evidence_summary"]["parse_status"], "partial");
}
