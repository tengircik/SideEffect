use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

fn unique_test_directory() -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    for _ in 0..100 {
        let attempt = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "sideeffect-path-cli-{}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&root) {
            Ok(()) => return root,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("could not create unique test directory: {error}"),
        }
    }
    panic!("could not allocate unique test directory after 100 attempts")
}

#[test]
fn cli_writes_versioned_path_inventory_without_overwriting() {
    let root = unique_test_directory();
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    #[cfg(windows)]
    let candidate = bin.join("fixture.exe");
    #[cfg(not(windows))]
    let candidate = bin.join("fixture");
    fs::write(&candidate, b"synthetic fixture; never executed").unwrap();
    let ordinary = bin.join("ordinary-data");
    fs::write(&ordinary, b"synthetic non-candidate").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let output = root.join("inventory.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
    command
        .args(["inventory", "path-executables", "--output"])
        .arg(&output)
        .env("PATH", &bin);
    #[cfg(windows)]
    command.env("PATHEXT", ".EXE;.CMD");
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(value["schema"], "sideeffect.path_executable_inventory");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["path_source"], "current_process_environment_PATH");
    assert_eq!(value["status"], "complete");
    assert!(
        value["directories"][0]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["name"]["display"]
                == candidate.file_name().unwrap().to_string_lossy().as_ref()
                && row["status"] == "candidate")
    );
    assert!(
        value["directories"][0]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |row| row["name"]["display"] == "ordinary-data" && row["status"] == "not_candidate"
            )
    );

    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "path-executables", "--output"])
        .arg(&output)
        .env("PATH", &bin)
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "existing output must not be replaced"
    );
    let _ = fs::remove_dir_all(root);
}
