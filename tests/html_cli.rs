#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(std::path::PathBuf);

impl TempDirectory {
    fn new() -> Self {
        loop {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("sideeffect-html-cli-{}-{id}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create HTML test directory: {error}"),
            }
        }
    }

    fn traces(&self) -> (std::path::PathBuf, std::path::PathBuf) {
        let baseline = self.0.join("baseline.trace");
        let candidate = self.0.join("candidate.trace");
        fs::write(
            &baseline,
            b"101 1700000000.000001 openat(AT_FDCWD, \"private-config.ini\", O_RDONLY) = 3\n",
        )
        .unwrap();
        fs::write(
            &candidate,
            b"202 1700000001.000001 openat(AT_FDCWD, \"private-config.ini\", O_RDONLY) = -1 ENOENT (No such file or directory)\n",
        )
        .unwrap();
        (baseline, candidate)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_html(
    output: &std::path::Path,
    left: &std::path::Path,
    right: &std::path::Path,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["diff", "--format", "html", "--output"])
        .arg(output)
        .arg(left)
        .arg(right)
        .output()
        .unwrap()
}

#[test]
fn html_command_publishes_private_offline_escaped_report_without_input_paths() {
    let directory = TempDirectory::new();
    let (baseline, candidate) = directory.traces();
    let report_path = directory.0.join("comparison.html");
    let output = run_html(&report_path, &baseline, &candidate);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let metadata = fs::metadata(&report_path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    let report = fs::read_to_string(&report_path).unwrap();
    assert!(report.contains("<h3>Changed</h3>"));
    assert!(report.contains("private-config.ini"));
    assert!(report.contains("unknown (not established by parsing)"));
    assert!(report.contains("line=1"));
    assert!(report.contains("default-src &#39;none&#39;") || report.contains("default-src 'none'"));
    assert!(!report.contains(&directory.0.display().to_string()));
    assert!(!report.contains("<script"));
    assert!(!report.contains("src=\"http"));
    assert!(!report.contains("href=\"http"));
}

#[test]
fn existing_file_and_symlink_destinations_are_left_untouched() {
    let directory = TempDirectory::new();
    let (baseline, candidate) = directory.traces();
    let existing = directory.0.join("existing.html");
    fs::write(&existing, b"keep existing report").unwrap();
    let output = run_html(&existing, &baseline, &candidate);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
    assert_eq!(fs::read(&existing).unwrap(), b"keep existing report");

    let target = directory.0.join("symlink-target.html");
    fs::write(&target, b"keep symlink target").unwrap();
    let link = directory.0.join("linked.html");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let output = run_html(&link, &baseline, &candidate);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
    assert_eq!(fs::read(&target).unwrap(), b"keep symlink target");
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}
