#[path = "common/model_store.rs"]
mod model_store;

use model_store::SelectedTestModel;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TRACE_ID: AtomicU64 = AtomicU64::new(0);

struct TempTrace(PathBuf);

impl TempTrace {
    fn new(directory: &Path) -> Self {
        loop {
            let id = NEXT_TRACE_ID.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(
                "runtime-config-trace-{}-{id}.trace",
                std::process::id()
            ));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    file.write_all(
                        b"44 execve(\"/usr/bin/tool\", [\"tool\"], 0x0) = 0\n44 openat(AT_FDCWD, \"/tmp/example\", O_RDONLY) = -1 ENOENT (No such file or directory)\n",
                    )
                    .expect("write synthetic trace");
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

fn successful(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn runtime_path_set_show_and_clear_do_not_execute_the_selected_file() {
    let model = SelectedTestModel::new("explanation");
    let runtime_path = std::env::current_exe()
        .expect("test executable")
        .canonicalize()
        .expect("canonical test executable path");

    let set = model
        .command()
        .args(["model", "runtime", "set", "explanation"])
        .arg(&runtime_path)
        .output()
        .expect("run inert runtime-path configuration command");
    successful(&set);
    assert!(stderr(&set).is_empty());
    assert!(String::from_utf8_lossy(&set.stdout).contains("did not execute the file"));

    let model_show = model
        .command()
        .args(["model", "show", model.id()])
        .output()
        .expect("confirm runtime configuration leaves model selection intact");
    successful(&model_show);
    assert!(String::from_utf8_lossy(&model_show.stdout).contains(model.sha256()));

    let show = model
        .command()
        .args(["model", "runtime", "show", "explanation"])
        .output()
        .expect("run inert runtime-path display command");
    successful(&show);
    let shown = String::from_utf8_lossy(&show.stdout);
    assert!(shown.contains(&runtime_path.to_string_lossy().to_string()));
    assert!(shown.contains("available regular file"));

    let clear = model
        .command()
        .args(["model", "runtime", "clear", "explanation"])
        .output()
        .expect("run inert runtime-path removal command");
    successful(&clear);
    assert!(String::from_utf8_lossy(&clear.stdout).contains("Cleared"));

    let show_cleared = model
        .command()
        .args(["model", "runtime", "show", "explanation"])
        .output()
        .expect("show cleared runtime configuration");
    successful(&show_cleared);
    assert!(String::from_utf8_lossy(&show_cleared.stdout).contains("not configured"));
}

#[test]
fn runtime_path_configuration_rejects_missing_and_non_file_paths() {
    let model = SelectedTestModel::new("explanation");
    let missing = model.data_root().join("missing-runtime.exe");
    let missing_result = model
        .command()
        .args(["model", "runtime", "set", "explanation"])
        .arg(missing)
        .output()
        .expect("reject missing runtime path");
    assert_eq!(missing_result.status.code(), Some(1));
    assert!(stderr(&missing_result).contains("existing local file"));

    let directory_result = model
        .command()
        .args(["model", "runtime", "set", "explanation"])
        .arg(model.data_root())
        .output()
        .expect("reject directory as runtime path");
    assert_eq!(directory_result.status.code(), Some(1));
    assert!(stderr(&directory_result).contains("regular file"));
}

#[test]
fn configured_runtime_fallback_and_explicit_override_stop_before_runtime_launch() {
    let model = SelectedTestModel::new("explanation");
    let trace = TempTrace::new(model.data_root());
    let configured = model.data_root().join("configured-runtime.bin");
    fs::write(&configured, b"test-only regular file; not a runtime").expect("create inert file");

    let set = model
        .command()
        .args(["model", "runtime", "set", "explanation"])
        .arg(&configured)
        .output()
        .expect("configure inert test file");
    successful(&set);

    // A deliberately incorrect digest must fail after resolving the saved
    // path but before the runtime subprocess can be started.
    let fallback = model
        .command()
        .args([
            "model-explain",
            "--question",
            "Which executable was observed to start successfully?",
            "--backend",
            "cpu",
            "--confirm-sha256",
        ])
        .arg("0".repeat(64))
        .arg(&trace.0)
        .output()
        .expect("exercise saved runtime fallback without inference");
    assert_eq!(fallback.status.code(), Some(1));
    assert!(stderr(&fallback).contains("preview digest mismatch"));

    fs::write(&configured, b"same-size altered file contents").expect("modify runtime bytes");
    let changed_show = model
        .command()
        .args(["model", "runtime", "show", "explanation"])
        .output()
        .expect("show detects changed runtime bytes");
    successful(&changed_show);
    assert!(String::from_utf8_lossy(&changed_show.stdout).contains("missing, changed, or invalid"));

    fs::remove_file(&configured).expect("remove configured test file");
    let doctor = model
        .command()
        .args(["model", "doctor", "--task", "explanation"])
        .output()
        .expect("check stale saved runtime path without launching it");
    assert_eq!(doctor.status.code(), Some(1));
    assert!(stderr(&doctor).contains("missing or inaccessible"));

    // The explicit path overrides the stale saved path. The digest mismatch
    // again guarantees that the selected file is not started.
    let explicit_path = std::env::current_exe()
        .expect("test executable")
        .canonicalize()
        .expect("canonical test executable path");
    let explicit = model
        .command()
        .args([
            "model-explain",
            "--question",
            "Which executable was observed to start successfully?",
            "--backend",
            "cpu",
            "--runtime",
        ])
        .arg(explicit_path)
        .args([
            "--confirm-sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .arg(&trace.0)
        .output()
        .expect("exercise explicit runtime override without inference");
    assert_eq!(explicit.status.code(), Some(1));
    assert!(stderr(&explicit).contains("preview digest mismatch"));
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn evidence_and_query_commands_use_configured_runtimes_without_launching_them() {
    for (task, command_name, question) in [
        ("evidence", "model-analyze", "Which syscall failed?"),
        ("query", "model-query", "Which operation returned ENOENT?"),
    ] {
        let model = SelectedTestModel::new(task);
        let trace = TempTrace::new(model.data_root());
        let unconfigured = model
            .command()
            .args([command_name, "--question", question, "--confirm-sha256"])
            .arg("0".repeat(64))
            .arg(&trace.0)
            .output()
            .expect("report missing configured runtime");
        assert_eq!(unconfigured.status.code(), Some(1));
        assert!(stderr(&unconfigured).contains("no runtime is configured"));

        let inert_file = std::env::current_exe().expect("test executable");
        let set = model
            .command()
            .args(["model", "runtime", "set", task])
            .arg(&inert_file)
            .output()
            .expect("configure test executable path without launching it");
        successful(&set);

        let fallback = model
            .command()
            .args([command_name, "--question", question, "--confirm-sha256"])
            .arg("0".repeat(64))
            .arg(&trace.0)
            .output()
            .expect("resolve configured runtime without inference");
        assert_eq!(fallback.status.code(), Some(1));
        assert!(stderr(&fallback).contains("preview digest mismatch"));

        let explicit_override = model
            .command()
            .args([command_name, "--question", question, "--runtime"])
            .arg(&inert_file)
            .args([
                "--confirm-sha256",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ])
            .arg(&trace.0)
            .output()
            .expect("resolve explicit runtime override without inference");
        assert_eq!(explicit_override.status.code(), Some(1));
        assert!(stderr(&explicit_override).contains("preview digest mismatch"));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn runtime_paths_are_escaped_before_terminal_display() {
    use std::os::unix::ffi::OsStrExt;

    let model = SelectedTestModel::new("explanation");
    let path = model.data_root().join("runtime\nwith-control");
    fs::write(&path, b"not a runtime").expect("create inert test file");
    let set = model
        .command()
        .args(["model", "runtime", "set", "explanation"])
        .arg(&path)
        .output()
        .expect("set path containing a control character");
    successful(&set);

    let show = model
        .command()
        .args(["model", "runtime", "show", "explanation"])
        .output()
        .expect("show escaped runtime path");
    successful(&show);
    let shown = String::from_utf8_lossy(&show.stdout);
    assert!(shown.contains("runtime\\x0awith-control"));
    assert!(!show.stdout.windows(2).any(|window| window == b"\n\n"));
    assert!(path.as_os_str().as_bytes().contains(&b'\n'));
}
