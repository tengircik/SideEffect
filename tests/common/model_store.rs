use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

pub struct SelectedTestModel {
    data_root: PathBuf,
    id: String,
    sha256: String,
}

impl SelectedTestModel {
    pub fn new(task: &str) -> Self {
        let data_root = loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-model-registry-fixture-{}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create model registry fixture: {error}"),
            }
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&data_root, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let model_path = data_root.join("synthetic-test-model.gguf");
        let model_bytes = b"GGUF\x03\0\0\0synthetic local model fixture";
        fs::write(&model_path, model_bytes).unwrap();
        let sha256 = format!("{:x}", Sha256::digest(model_bytes));

        let registration = run_in_data_root(
            &data_root,
            [
                "model",
                "add",
                "--name",
                "Synthetic test model",
                "--path",
                model_path.to_str().unwrap(),
                "--for",
                task,
            ],
        );
        assert!(
            registration.status.success(),
            "{}",
            String::from_utf8_lossy(&registration.stderr)
        );
        let stdout = String::from_utf8(registration.stdout).unwrap();
        let id = stdout
            .split(" as ")
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
            .expect("model registration prints its ID")
            .trim_end_matches('.')
            .to_owned();
        let selection = run_in_data_root(&data_root, ["model", "select", task, &id]);
        assert!(
            selection.status.success(),
            "{}",
            String::from_utf8_lossy(&selection.stderr)
        );

        Self {
            data_root,
            id,
            sha256,
        }
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
        command
            .env("XDG_DATA_HOME", &self.data_root)
            .env("LOCALAPPDATA", &self.data_root);
        command
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

impl Drop for SelectedTestModel {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.data_root);
    }
}

fn run_in_data_root<'a>(
    data_root: &std::path::Path,
    arguments: impl IntoIterator<Item = &'a str>,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
    command
        .env("XDG_DATA_HOME", data_root)
        .env("LOCALAPPDATA", data_root)
        .args(arguments)
        .output()
        .unwrap()
}
