#![cfg(target_os = "linux")]

use serde_json::Value;
use sideeffect::audit_session::{
    ArtifactKind, SessionArtifactRef, SourceRole, SourceStatus, parse_manifest,
};
use sideeffect::inventory::parse_dpkg_query_output;
use sideeffect::limits::ParseLimits;
use sideeffect::model::{SyscallOutcome, TraceRecord, TraceRecordKind};
use sideeffect::trace::strace::parse_trace_bytes;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const PACKAGE_NAME: &str = "sideeffect-r5-synthetic-lifecycle";
const PACKAGE_DIRECTORY: &str = "usr/lib/sideeffect-r5-synthetic-lifecycle";
const STARTUP_HOME_DIRECTORY: &str = "home/sideeffect-r5-synthetic";
const STARTUP_SERVICE_NAME: &str = "sideeffect-r5-synthetic.service";
const STARTUP_TIMER_NAME: &str = "sideeffect-r5-synthetic.timer";
const PAYLOAD_NAME: &str = "payload.bin";
const ANCHOR_NAME: &str = "fixture-owned-anchor.txt";
const ANCHOR_CONTENT: &[u8] = b"fixture-owned directory anchor\n";
const DPKG: &str = "/usr/bin/dpkg";
const DPKG_DEB: &str = "/usr/bin/dpkg-deb";
const DPKG_QUERY: &str = "/usr/bin/dpkg-query";
const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

struct PrivateStartupEnvironment {
    home: PathBuf,
    config_home: PathBuf,
    config_dirs: PathBuf,
    data_dirs: PathBuf,
    runtime_dir: PathBuf,
}

impl PrivateStartupEnvironment {
    fn new(root: &Path, parent: &Path) -> Self {
        let home = root.join(STARTUP_HOME_DIRECTORY);
        let config_home = home.join(".config");
        let config_dirs = parent.join("xdg-config");
        let data_dirs = parent.join("xdg-data");
        let runtime_dir = parent.join("xdg-runtime");
        fs::create_dir_all(home.join(".config/systemd/user")).unwrap();
        fs::create_dir_all(config_dirs.join("autostart")).unwrap();
        fs::create_dir_all(&data_dirs).unwrap();
        fs::create_dir_all(&runtime_dir).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            home: home.canonicalize().unwrap(),
            config_home: config_home.canonicalize().unwrap(),
            config_dirs: config_dirs.canonicalize().unwrap(),
            data_dirs: data_dirs.canonicalize().unwrap(),
            runtime_dir: runtime_dir.canonicalize().unwrap(),
        }
    }

    fn apply(&self, command: &mut Command) {
        command
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_CONFIG_DIRS", &self.config_dirs)
            .env("XDG_DATA_DIRS", &self.data_dirs)
            .env("XDG_RUNTIME_DIR", &self.runtime_dir);
    }

    fn fixture_unit_dir(&self) -> PathBuf {
        self.home.join(".config/systemd/user")
    }
}

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn successful_split_removal_pairs<'a>(
    records: &'a [TraceRecord],
    basename: &str,
) -> Vec<(&'a TraceRecord, &'a TraceRecord)> {
    let mut pairs = Vec::new();
    let mut pending: std::collections::BTreeMap<(u32, String), Vec<&TraceRecord>> =
        std::collections::BTreeMap::new();
    for record in records {
        let (Some(process_id), Some(syscall)) = (record.process_id, record.syscall.as_ref()) else {
            continue;
        };
        if !matches!(syscall.as_str(), "unlink" | "unlinkat") {
            continue;
        }
        let key = (process_id, syscall.clone());
        match record.kind {
            TraceRecordKind::UnfinishedSyscall => {
                pending.entry(key).or_default().push(record);
            }
            TraceRecordKind::ResumedSyscall => {
                let Some(queue) = pending.get_mut(&key) else {
                    continue;
                };
                if queue.len() == 1 {
                    let unfinished = queue.remove(0);
                    if unfinished.raw_line.contains(basename)
                        && record.raw_result.as_deref() == Some("0")
                    {
                        pairs.push((unfinished, record));
                    }
                }
            }
            _ => {}
        }
    }
    pairs
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        for _ in 0..32 {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is after Unix epoch")
                .as_nanos();
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sideeffect-dpkg-root-lifecycle-{}-{nonce}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .expect("make the fixture parent private");
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create private temporary directory: {error}"),
            }
        }
        panic!("could not allocate a unique private temporary directory")
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn package_tool(program: &str) -> Command {
    assert!(Path::new(program).is_absolute());
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LC_ALL", "C");
    command
}

fn require_tool(program: &str) {
    assert!(
        Path::new(program).is_file(),
        "required tool {program} is missing"
    );
    let output = package_tool(program)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| {
            panic!("required lifecycle test tool {program} is unavailable: {error}")
        });
    assert!(
        output.status.success(),
        "{program} --version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn build_scriptless_deb(parent: &Path, version: &str, payload: &[u8]) -> PathBuf {
    let package_tree = parent.join(format!("package-{version}"));
    let control_dir = package_tree.join("DEBIAN");
    let payload_dir = package_tree.join(PACKAGE_DIRECTORY);
    let user_unit_dir = package_tree
        .join(STARTUP_HOME_DIRECTORY)
        .join(".config/systemd/user");
    fs::create_dir_all(&control_dir).unwrap();
    fs::create_dir_all(&payload_dir).unwrap();
    fs::create_dir_all(&user_unit_dir).unwrap();
    fs::write(
        control_dir.join("control"),
        format!(
            "Package: {PACKAGE_NAME}\nVersion: {version}\nArchitecture: all\nMaintainer: SideEffect Test <test@example.invalid>\nDescription: Scriptless synthetic lifecycle fixture\n"
        ),
    )
    .unwrap();
    fs::write(payload_dir.join(PAYLOAD_NAME), payload).unwrap();
    let never_run_command = parent.join("fixture-command-never-executed");
    assert!(
        !never_run_command.exists(),
        "private fixture command must remain absent and inert"
    );
    let revision = if version == "1.0-1" { "v1" } else { "v2" };
    fs::write(
        user_unit_dir.join(STARTUP_SERVICE_NAME),
        format!(
            "[Unit]\nDescription=SideEffect private service fixture {revision}\n[Service]\nType=oneshot\nExecStart={}\n",
            never_run_command.display()
        ),
    )
    .unwrap();
    fs::write(
        user_unit_dir.join(STARTUP_TIMER_NAME),
        format!(
            "[Unit]\nDescription=SideEffect private timer fixture {revision}\n[Timer]\nOnBootSec=1h\nUnit={STARTUP_SERVICE_NAME}\n"
        ),
    )
    .unwrap();
    let control_entries: Vec<_> = fs::read_dir(&control_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(control_entries, vec![std::ffi::OsString::from("control")]);

    let deb = parent.join(format!("{PACKAGE_NAME}_{version}_all.deb"));
    let output = package_tool(DPKG_DEB)
        .args(["--build"])
        .arg(&package_tree)
        .arg(&deb)
        .env("TMPDIR", parent)
        .output()
        .expect("launch dpkg-deb --build");
    assert!(
        output.status.success(),
        "dpkg-deb failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    deb
}

fn isolated_dpkg_command(
    root: &Path,
    private_parent: &Path,
    startup_environment: &PrivateStartupEnvironment,
) -> Command {
    let root = root
        .canonicalize()
        .expect("canonicalize isolated dpkg root");
    let parent = private_parent
        .canonicalize()
        .expect("canonicalize private fixture parent");
    assert!(
        root.starts_with(&parent),
        "dpkg root escaped fixture directory"
    );
    assert_ne!(root, Path::new("/"), "refusing to target the host root");

    let admin = root.join("var/lib/dpkg");
    let log = parent.join("dpkg.log");
    assert!(
        admin.starts_with(&root),
        "dpkg admin path escaped private root"
    );
    assert!(
        log.starts_with(&parent),
        "dpkg log path escaped fixture directory"
    );

    let mut command = package_tool(DPKG);
    command
        .arg(format!("--root={}", root.display()))
        .arg(format!("--admindir={}", admin.display()))
        .arg(format!("--instdir={}", root.display()))
        .arg(format!("--log={}", log.display()))
        .args(["--force-not-root", "--no-triggers"])
        .env("TMPDIR", private_parent);
    startup_environment.apply(&mut command);
    command
}

fn dpkg_install_command(
    root: &Path,
    private_parent: &Path,
    startup_environment: &PrivateStartupEnvironment,
    deb: &Path,
    downgrade: bool,
) -> Command {
    let mut command = isolated_dpkg_command(root, private_parent, startup_environment);
    if downgrade {
        command.arg("--force-downgrade");
    }
    command.arg("--install").arg(deb);
    command
}

fn dpkg_install(
    root: &Path,
    private_parent: &Path,
    startup_environment: &PrivateStartupEnvironment,
    deb: &Path,
    downgrade: bool,
) {
    let output = dpkg_install_command(root, private_parent, startup_environment, deb, downgrade)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated dpkg install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn audit_dpkg_install(
    root: &Path,
    private_parent: &Path,
    startup_environment: &PrivateStartupEnvironment,
    observed_root: &Path,
    deb: &Path,
    session_path: &Path,
) {
    let dpkg = dpkg_install_command(root, private_parent, startup_environment, deb, false);
    audit_dpkg_command(
        root,
        private_parent,
        observed_root,
        session_path,
        dpkg,
        startup_environment,
        &["--install".to_owned(), deb.to_string_lossy().into_owned()],
    );
}

fn audit_dpkg_purge(
    root: &Path,
    private_parent: &Path,
    startup_environment: &PrivateStartupEnvironment,
    observed_root: &Path,
    session_path: &Path,
) {
    let mut dpkg = isolated_dpkg_command(root, private_parent, startup_environment);
    dpkg.args(["--purge", PACKAGE_NAME]);
    audit_dpkg_command(
        root,
        private_parent,
        observed_root,
        session_path,
        dpkg,
        startup_environment,
        &["--purge".to_owned(), PACKAGE_NAME.to_owned()],
    );
}

fn audit_dpkg_command(
    root: &Path,
    private_parent: &Path,
    observed_root: &Path,
    session_path: &Path,
    dpkg: Command,
    startup_environment: &PrivateStartupEnvironment,
    operation_arguments: &[String],
) {
    let program = dpkg.get_program().to_owned();
    let arguments = dpkg.get_args().map(OsString::from).collect::<Vec<_>>();
    let mut expected_arguments = vec![
        format!("--root={}", root.canonicalize().unwrap().display()),
        format!(
            "--admindir={}",
            root.canonicalize().unwrap().join("var/lib/dpkg").display()
        ),
        format!("--instdir={}", root.canonicalize().unwrap().display()),
        format!(
            "--log={}",
            private_parent
                .canonicalize()
                .unwrap()
                .join("dpkg.log")
                .display()
        ),
        "--force-not-root".to_owned(),
        "--no-triggers".to_owned(),
    ];
    expected_arguments.extend_from_slice(operation_arguments);
    assert_eq!(
        arguments
            .iter()
            .map(|argument| argument.to_str().expect("fixture argv is UTF-8"))
            .collect::<Vec<_>>(),
        expected_arguments
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        "the observed child must preserve the isolated dpkg argument vector exactly"
    );
    let environment = dpkg
        .get_envs()
        .map(|(key, value)| (OsString::from(key), value.map(OsString::from)))
        .collect::<Vec<_>>();
    assert_eq!(program, DPKG);
    assert_eq!(
        environment.len(),
        8,
        "isolated dpkg must receive only its fixed PATH, locale, private TMPDIR, and private startup/XDG settings"
    );
    assert!(
        environment
            .iter()
            .any(|(key, value)| { key == "PATH" && value.as_deref() == Some(SAFE_PATH.as_ref()) })
    );
    assert!(
        environment
            .iter()
            .any(|(key, value)| { key == "LC_ALL" && value.as_deref() == Some(OsStr::new("C")) })
    );
    assert!(environment.iter().any(|(key, value)| {
        key == "TMPDIR" && value.as_deref() == Some(private_parent.as_os_str())
    }));
    for (key, expected) in [
        ("HOME", startup_environment.home.as_os_str()),
        (
            "XDG_CONFIG_HOME",
            startup_environment.config_home.as_os_str(),
        ),
        (
            "XDG_CONFIG_DIRS",
            startup_environment.config_dirs.as_os_str(),
        ),
        ("XDG_DATA_DIRS", startup_environment.data_dirs.as_os_str()),
        (
            "XDG_RUNTIME_DIR",
            startup_environment.runtime_dir.as_os_str(),
        ),
    ] {
        assert!(environment.iter().any(|(actual_key, value)| {
            actual_key == key && value.as_deref() == Some(expected)
        }));
    }

    let mut audit = Command::new(env!("CARGO_BIN_EXE_sideeffect"));
    audit
        .env_clear()
        .arg("audit")
        .arg("--output")
        .arg(session_path)
        .arg("--observe-root")
        .arg(observed_root)
        .arg("--hash-regular-files")
        .arg("--startup")
        .arg("--packages")
        .arg("--dpkg-admindir")
        .arg(root.join("var/lib/dpkg"))
        .arg("--runtime-duration-seconds")
        .arg("30")
        .arg("--")
        .arg(program)
        .args(arguments);
    for (key, value) in environment {
        audit.env(
            key,
            value.expect("the fixture dpkg environment contains only fixed values"),
        );
    }
    startup_environment.apply(&mut audit);
    let output = audit
        .output()
        .expect("launch observed isolated dpkg transaction");
    assert_eq!(
        output.status.code(),
        Some(2),
        "runtime-containing audit sessions are partial by contract: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn dpkg_query_inventory(root: &Path, private_parent: &Path, output_path: &Path) -> Value {
    let root = root.canonicalize().unwrap();
    let parent = private_parent.canonicalize().unwrap();
    assert!(root.starts_with(&parent));
    let admin = root.join("var/lib/dpkg");
    assert!(admin.starts_with(&root));
    let showformat =
        "--showformat=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\\n";
    let output = package_tool(DPKG_QUERY)
        .arg(format!("--admindir={}", admin.display()))
        .arg("--show")
        .arg(showformat)
        .env("TMPDIR", private_parent)
        .output()
        .expect("launch bounded dpkg-query with private admin directory");
    assert!(
        output.status.success(),
        "private dpkg-query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.len() <= 8 * 1024,
        "private dpkg-query output exceeded the fixture bound"
    );
    let document = parse_dpkg_query_output(&output.stdout, 0);
    assert_eq!(
        document.status,
        sideeffect::inventory::InventoryStatus::Complete
    );
    assert_eq!(document.sources.len(), 1);
    assert_eq!(document.sources[0].id, "dpkg_query");
    assert_eq!(document.sources[0].records_seen, document.packages.len());
    assert!(
        document
            .packages
            .iter()
            .all(|package| package.evidence.line > 0)
    );
    fs::write(output_path, serde_json::to_vec(&document).unwrap()).unwrap();
    serde_json::from_slice(&fs::read(output_path).unwrap()).unwrap()
}

fn assert_package_version(document: &Value, expected_version: Option<&str>) {
    assert_eq!(document["schema"], "sideeffect.inventory");
    assert_eq!(document["schema_version"], 2);
    assert_eq!(document["status"], "complete");
    let matching = document["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|package| package["name"] == PACKAGE_NAME)
        .collect::<Vec<_>>();
    match expected_version {
        Some(version) => {
            assert_eq!(matching.len(), 1);
            assert_eq!(matching[0]["version"], version);
            assert_eq!(matching[0]["source_id"], "dpkg_query");
            assert_eq!(matching[0]["evidence"]["line"], 1);
            assert_eq!(matching[0]["evidence"]["byte_offset"], 0);
            assert!(
                matching[0]["evidence"]["raw_record"]
                    .as_str()
                    .unwrap()
                    .starts_with(PACKAGE_NAME)
            );
        }
        None => assert!(
            matching.is_empty(),
            "purged package remains in parsed private dpkg state"
        ),
    }
}

fn package_diff(before: &Path, after: &Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(before)
        .arg(after)
        .output()
        .expect("launch SideEffect package inventory diff");
    assert_eq!(
        output.status.code(),
        Some(0),
        "SideEffect package inventory diff failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_package_delta_evidence(
    diff: &Value,
    kind: &str,
    before_line: Option<u64>,
    after_line: Option<u64>,
) {
    assert_eq!(diff["schema"], "sideeffect.package_inventory_diff");
    assert_eq!(diff["status"], "complete");
    assert_eq!(diff["deltas"].as_array().unwrap().len(), 1);
    let delta = &diff["deltas"][0];
    assert_eq!(delta["kind"], kind);
    assert_eq!(delta["identity"]["source_id"], "dpkg_query");
    assert_eq!(delta["identity"]["name"], PACKAGE_NAME);
    for (side, expected_line) in [("before", before_line), ("after", after_line)] {
        match expected_line {
            Some(line) => {
                assert_eq!(delta[side]["evidence"]["line"], line);
                assert!(delta[side]["evidence"]["byte_length"].as_u64().unwrap() > 0);
            }
            None => assert!(delta[side].is_null()),
        }
    }
}

fn snapshot(root: &Path, output_path: &Path) -> Value {
    let result = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["inventory", "root", "--hash-regular-files", "--output"])
        .arg(output_path)
        .arg(root)
        .output()
        .expect("launch SideEffect selected-root inventory");
    assert!(
        result.status.success(),
        "SideEffect selected-root snapshot failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&fs::read(output_path).unwrap()).unwrap()
}

fn snapshot_payload_hash(document: &Value, expected_payload: &[u8]) -> usize {
    assert_eq!(document["schema"], "sideeffect.selected_root_inventory");
    assert_eq!(document["schema_version"], 2);
    assert_eq!(document["status"], "complete");
    let entries = document["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let anchor = entries
        .iter()
        .find(|entry| entry["display_name"] == ANCHOR_NAME)
        .expect("fixture-owned anchor keeps the selected directory present");
    assert_eq!(anchor["content_hash_status"], "observed");
    assert_eq!(anchor["content_sha256"], sha256_hex(ANCHOR_CONTENT));
    let entry = entries
        .iter()
        .find(|entry| entry["display_name"] == PAYLOAD_NAME)
        .expect("package payload is present");
    assert_eq!(entry["content_hash_status"], "observed");
    assert_eq!(entry["content_sha256"], sha256_hex(expected_payload));
    assert_eq!(entry["evidence"]["source"], "selected_root_directory_entry");
    assert_eq!(entry["evidence"]["entry_ordinal"], entry["ordinal"]);
    entry["ordinal"].as_u64().unwrap() as usize
}

fn snapshot_entry<'a>(document: &'a Value, name: &str) -> &'a Value {
    document["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["display_name"] == name)
        .unwrap_or_else(|| panic!("snapshot is missing expected entry {name}"))
}

fn snapshot_diff(before: &Path, after: &Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(["explain", "--inventory-diff"])
        .arg(before)
        .arg(after)
        .output()
        .expect("launch SideEffect selected-root diff");
    assert!(
        output.status.success(),
        "SideEffect selected-root diff failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn path_bytes_hex(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = path.as_os_str().as_bytes();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn assert_selected_dpkg_version(document: &Value, admindir: &Path, version: Option<&str>) {
    assert_eq!(document["schema"], "sideeffect.inventory");
    assert_eq!(document["schema_version"], 3);
    assert_eq!(document["scope"], "selected_dpkg_admindir");
    assert_eq!(document["source_selection"]["kind"], "dpkg_admindir");
    assert_eq!(
        document["source_selection"]["path_bytes_hex"],
        path_bytes_hex(admindir)
    );
    let matching = document["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|package| package["name"] == PACKAGE_NAME)
        .collect::<Vec<_>>();
    match version {
        Some(version) => {
            assert_eq!(matching.len(), 1);
            assert_eq!(matching[0]["version"], version);
            assert_eq!(matching[0]["source_id"], "dpkg_query");
            assert!(matching[0]["evidence"]["line"].as_u64().unwrap() > 0);
            assert!(matching[0]["evidence"]["byte_length"].as_u64().unwrap() > 0);
        }
        None => assert!(matching.is_empty()),
    }
}

fn assert_startup_fixture_units(
    document: &Value,
    startup_environment: &PrivateStartupEnvironment,
    version: Option<&str>,
    never_run_command: &Path,
) -> Vec<(String, usize)> {
    assert_eq!(document["schema"], "sideeffect.startup_inventory");
    assert_eq!(document["schema_version"], 3);
    assert_eq!(document["platform"], "linux");
    let revision = version.map(|version| if version == "1.0-1" { "v1" } else { "v2" });
    let mut result = Vec::new();
    for (unit_name, description) in [
        (
            STARTUP_SERVICE_NAME,
            revision.map(|revision| format!("SideEffect private service fixture {revision}")),
        ),
        (
            STARTUP_TIMER_NAME,
            revision.map(|revision| format!("SideEffect private timer fixture {revision}")),
        ),
    ] {
        let path = startup_environment.fixture_unit_dir().join(unit_name);
        let matches = document["systemd_units"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .filter(|(_, record)| {
                record["scope"] == "user"
                    && record["record_type"] == "unit_file"
                    && record["source_path"] == path.to_string_lossy().as_ref()
            })
            .collect::<Vec<_>>();
        match description {
            Some(description) => {
                assert_eq!(matches.len(), 1, "expected exact private fixture unit row");
                let (index, record) = matches[0];
                assert_eq!(record["source_path_bytes_hex"], path_bytes_hex(&path));
                assert_eq!(record["startup_state"]["configured"], "present");
                assert_eq!(record["startup_state"]["effective"]["status"], "unknown");
                assert_eq!(record["startup_state"]["observed"]["status"], "unknown");
                let directives = record["directives"].as_array().unwrap();
                let directive_value = |section: &str, key: &str| {
                    directives
                        .iter()
                        .find(|directive| {
                            directive["section"] == section && directive["key"] == key
                        })
                        .and_then(|directive| directive["value"].as_str())
                };
                assert_eq!(
                    directive_value("Unit", "Description"),
                    Some(description.as_str()),
                    "synthetic fixture directives did not preserve Unit/Description: {:?}; fixture file text: {:?}",
                    directives
                        .iter()
                        .map(|directive| (
                            directive["section"].as_str(),
                            directive["key"].as_str(),
                            directive["value"].as_str()
                        ))
                        .collect::<Vec<_>>(),
                    fs::read_to_string(&path).ok()
                );
                if unit_name == STARTUP_SERVICE_NAME {
                    assert_eq!(
                        directive_value("Service", "ExecStart"),
                        Some(never_run_command.to_string_lossy().as_ref())
                    );
                } else {
                    assert_eq!(directive_value("Timer", "Unit"), Some(STARTUP_SERVICE_NAME));
                    assert_eq!(directive_value("Timer", "OnBootSec"), Some("1h"));
                }
                result.push((path.to_string_lossy().into_owned(), index));
            }
            None => assert!(matches.is_empty(), "unit row unexpectedly present"),
        }
    }
    result
}

fn source_status_name(status: SourceStatus) -> &'static str {
    match status {
        SourceStatus::Complete => "complete",
        SourceStatus::Partial => "partial",
        SourceStatus::Unknown => "unknown",
        SourceStatus::NotChecked => "not_checked",
        SourceStatus::Unsupported => "unsupported",
        SourceStatus::NotApplicable => "not_applicable",
        SourceStatus::Unavailable => "unavailable",
        SourceStatus::AccessDenied => "access_denied",
        SourceStatus::Failed => "failed",
        SourceStatus::TimedOut => "timed_out",
        SourceStatus::OutputLimitExceeded => "output_limit_exceeded",
    }
}

fn assert_observed_dpkg_transition(
    session_path: &Path,
    observed_root: &Path,
    startup_environment: &PrivateStartupEnvironment,
    payload_before: Option<&[u8]>,
    payload_after: Option<&[u8]>,
    package_before: Option<&str>,
    package_after: Option<&str>,
) {
    let manifest_path = session_path.join("session.json");
    let manifest_bytes = fs::read(&manifest_path).unwrap();
    let manifest = parse_manifest(&manifest_bytes).expect("validate observation session manifest");
    assert_eq!(
        manifest.schema_version,
        sideeffect::audit_session::AUDIT_SESSION_V20_SCHEMA_VERSION
    );
    assert_eq!(manifest.platform, "linux");
    assert_eq!(
        manifest.status,
        sideeffect::audit_session::SessionStatus::Partial,
        "runtime completeness remains unknown by contract"
    );
    let root_source = manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::SelectedRoot)
        .expect("selected-root source");
    assert_eq!(root_source.status, SourceStatus::Complete);
    assert_eq!(root_source.artifacts.len(), 2);
    assert!(
        root_source
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == ArtifactKind::SelectedRoot)
    );
    assert!(
        root_source
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == ArtifactKind::SelectedRootAfter)
    );
    let packages = manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::Packages)
        .expect("selected package source");
    assert_eq!(packages.artifacts.len(), 2);
    let package_before_ref = packages
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == ArtifactKind::Packages)
        .unwrap();
    let package_after_ref = packages
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == ArtifactKind::PackagesAfter)
        .unwrap();
    assert_eq!(package_before_ref.path, "packages.json");
    assert_eq!(package_after_ref.path, "packages-after.json");
    let startup = manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::Startup)
        .expect("selected startup source");
    assert_eq!(startup.artifacts.len(), 2);
    let startup_before_ref = startup
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == ArtifactKind::Startup)
        .unwrap();
    let startup_after_ref = startup
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == ArtifactKind::StartupAfter)
        .unwrap();
    assert_eq!(startup_before_ref.path, "startup.json");
    assert_eq!(startup_after_ref.path, "startup-after.json");

    let runtime = manifest
        .sources
        .iter()
        .find(|source| source.role == SourceRole::Runtime)
        .expect("runtime source");
    assert_eq!(runtime.status, SourceStatus::Partial);
    assert_eq!(
        runtime.scope,
        "selected command and traced descendants; command arguments are not copied into the session manifest"
    );
    assert_eq!(runtime.artifacts.len(), 2);
    let run_ref = runtime
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == ArtifactKind::RuntimeManifest)
        .unwrap();
    let trace_ref = runtime
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == ArtifactKind::RuntimeTrace)
        .unwrap();
    assert_eq!(run_ref.path, "run.json");
    assert_eq!(trace_ref.path, "trace.strace");

    assert_session_artifacts_verified(
        session_path,
        root_source
            .artifacts
            .iter()
            .chain(&runtime.artifacts)
            .chain(&packages.artifacts)
            .chain(&startup.artifacts),
    );

    let admindir = session_path
        .parent()
        .expect("session fixture parent")
        .join("root/var/lib/dpkg")
        .canonicalize()
        .expect("canonical selected dpkg admin directory");
    let packages_before_document: Value = serde_json::from_slice(
        &fs::read(session_path.join(package_before_ref.path.as_str())).unwrap(),
    )
    .expect("verified package before inventory JSON");
    let packages_after_document: Value = serde_json::from_slice(
        &fs::read(session_path.join(package_after_ref.path.as_str())).unwrap(),
    )
    .expect("verified package after inventory JSON");
    assert_selected_dpkg_version(&packages_before_document, &admindir, package_before);
    assert_selected_dpkg_version(&packages_after_document, &admindir, package_after);
    let startup_before_document: Value = serde_json::from_slice(
        &fs::read(session_path.join(startup_before_ref.path.as_str())).unwrap(),
    )
    .expect("verified startup before inventory JSON");
    let startup_after_document: Value = serde_json::from_slice(
        &fs::read(session_path.join(startup_after_ref.path.as_str())).unwrap(),
    )
    .expect("verified startup after inventory JSON");
    let never_run_command = session_path
        .parent()
        .expect("session fixture parent")
        .join("fixture-command-never-executed");
    assert!(!never_run_command.exists());
    let startup_before_rows = assert_startup_fixture_units(
        &startup_before_document,
        startup_environment,
        package_before,
        &never_run_command,
    );
    let startup_after_rows = assert_startup_fixture_units(
        &startup_after_document,
        startup_environment,
        package_after,
        &never_run_command,
    );

    let before_ref = root_source
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == ArtifactKind::SelectedRoot)
        .unwrap();
    let after_ref = root_source
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == ArtifactKind::SelectedRootAfter)
        .unwrap();
    let before_snapshot: Value =
        serde_json::from_slice(&fs::read(session_path.join(before_ref.path.as_str())).unwrap())
            .expect("transition before snapshot JSON");
    let after_snapshot: Value =
        serde_json::from_slice(&fs::read(session_path.join(after_ref.path.as_str())).unwrap())
            .expect("transition after snapshot JSON");
    for snapshot in [&before_snapshot, &after_snapshot] {
        assert_eq!(snapshot["schema"], "sideeffect.selected_root_inventory");
        assert_eq!(snapshot["schema_version"], 2);
        assert_eq!(snapshot["status"], "complete");
        let anchor = snapshot_entry(snapshot, ANCHOR_NAME);
        assert_eq!(anchor["content_hash_status"], "observed");
        assert_eq!(anchor["content_sha256"], sha256_hex(ANCHOR_CONTENT));
    }
    let before_entries = before_snapshot["entries"].as_array().unwrap();
    assert_eq!(
        before_entries.len(),
        1 + usize::from(payload_before.is_some())
    );
    assert_eq!(
        after_snapshot["entries"].as_array().unwrap().len(),
        1 + usize::from(payload_after.is_some())
    );
    let before_payload = before_entries
        .iter()
        .find(|entry| entry["display_name"] == PAYLOAD_NAME);
    match (payload_before, before_payload) {
        (Some(expected), Some(entry)) => {
            assert_eq!(entry["content_hash_status"], "observed");
            assert_eq!(entry["content_sha256"], sha256_hex(expected));
            assert_eq!(entry["evidence"]["source"], "selected_root_directory_entry");
            assert_eq!(entry["evidence"]["entry_ordinal"], entry["ordinal"]);
        }
        (None, None) => assert_eq!(before_entries.len(), 1),
        _ => panic!("before snapshot payload presence did not match the expected transition"),
    }
    let after_entries = after_snapshot["entries"].as_array().unwrap();
    let after_payload = after_entries
        .iter()
        .find(|entry| entry["display_name"] == PAYLOAD_NAME);
    match (payload_after, after_payload) {
        (Some(expected), Some(entry)) => {
            assert_eq!(entry["content_hash_status"], "observed");
            assert_eq!(entry["content_sha256"], sha256_hex(expected));
            assert_eq!(entry["evidence"]["source"], "selected_root_directory_entry");
            assert_eq!(entry["evidence"]["entry_ordinal"], entry["ordinal"]);
        }
        (None, None) => assert_eq!(after_entries.len(), 1),
        _ => panic!("after snapshot payload presence did not match the expected transition"),
    }
    match (payload_before, payload_after) {
        (Some(before), Some(after)) => {
            assert_ne!(before, after);
            assert_ne!(
                snapshot_entry(&before_snapshot, PAYLOAD_NAME)["content_sha256"],
                snapshot_entry(&after_snapshot, PAYLOAD_NAME)["content_sha256"],
                "the verified session snapshots must show the observed fixture content change"
            );
        }
        (Some(_), None) | (None, Some(_)) => {}
        (None, None) => {
            panic!("an observed lifecycle transition must change payload presence or content")
        }
    }

    let run: Value = serde_json::from_slice(&fs::read(session_path.join("run.json")).unwrap())
        .expect("runtime bundle manifest JSON");
    assert_eq!(run["schema"], "sideeffect.run");
    assert_eq!(run["schema_version"], 2);
    assert_eq!(run["capture"]["completeness"], "unknown");
    assert_eq!(run["capture"]["stop_reason"], "tracer_exited");
    assert_eq!(
        run["capture"]["strace_reported_status"]["kind"],
        "exit_code"
    );
    assert_eq!(run["capture"]["strace_reported_status"]["value"], 0);

    let trace_bytes = fs::read(session_path.join("trace.strace")).unwrap();
    let trace = parse_trace_bytes(&trace_bytes, ParseLimits::default()).unwrap();
    assert_eq!(
        trace.parse_status,
        sideeffect::model::ParseCompleteness::Complete
    );
    let compared = Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .arg("compare-observation")
        .arg(session_path)
        .output()
        .expect("launch SideEffect observation comparison");
    assert_eq!(
        compared.status.code(),
        Some(2),
        "runtime-containing comparison remains partial by contract: {}",
        String::from_utf8_lossy(&compared.stderr)
    );
    let report: Value = serde_json::from_slice(&compared.stdout).unwrap();
    assert_eq!(report["root_comparison_status"], "complete");
    assert_eq!(
        report["package_before_artifact"]["path"],
        package_before_ref.path
    );
    assert_eq!(
        report["package_after_artifact"]["path"],
        package_after_ref.path
    );
    assert_eq!(
        report["package_before_artifact"]["sha256"],
        package_before_ref.sha256
    );
    assert_eq!(
        report["package_after_artifact"]["sha256"],
        package_after_ref.sha256
    );
    assert_eq!(
        report["package_source_status"],
        source_status_name(packages.status)
    );
    assert_eq!(
        report["startup_before_artifact"]["path"],
        startup_before_ref.path
    );
    assert_eq!(
        report["startup_after_artifact"]["path"],
        startup_after_ref.path
    );
    assert_eq!(
        report["startup_before_artifact"]["sha256"],
        startup_before_ref.sha256
    );
    assert_eq!(
        report["startup_after_artifact"]["sha256"],
        startup_after_ref.sha256
    );
    assert_eq!(
        report["startup_source_status"],
        source_status_name(startup.status)
    );
    assert_eq!(
        report["startup_before_document_status"],
        startup_before_document["status"]
    );
    assert_eq!(
        report["startup_after_document_status"],
        startup_after_document["status"]
    );
    let package_delta_kind = match (package_before, package_after) {
        (None, Some(_)) => "added",
        (Some(_), Some(_)) if package_before != package_after => "changed",
        (Some(_), None) => "removed",
        _ => panic!("package transition must change the selected package version"),
    };
    if packages.status == SourceStatus::Complete {
        assert_eq!(report["package_comparison_status"], "complete");
        let package_diff = &report["package_diff"];
        assert_eq!(package_diff["status"], "complete");
        assert_eq!(package_diff["deltas"].as_array().unwrap().len(), 1);
        let package_delta = &package_diff["deltas"][0];
        assert_eq!(package_delta["kind"], package_delta_kind);
        assert_eq!(package_delta["identity"]["source_id"], "dpkg_query");
        assert_eq!(package_delta["identity"]["name"], PACKAGE_NAME);
    } else {
        assert_eq!(report["package_comparison_status"], "partial");
        assert_eq!(
            report["package_comparison_diagnostic"],
            "package_source_incomplete"
        );
        assert!(report["package_diff"].is_null());
    }

    let startup_diff = &report["startup_diff"];
    assert_eq!(startup_diff["schema"], "sideeffect.startup_inventory_diff");
    assert_eq!(startup_diff["platform"], "linux");
    let startup_is_complete = startup.status == SourceStatus::Complete
        && startup_before_document["status"] == "complete"
        && startup_after_document["status"] == "complete"
        && startup_diff["status"] == "complete";
    assert_eq!(
        report["startup_comparison_status"],
        if startup_is_complete {
            "complete"
        } else {
            "partial"
        }
    );
    let startup_deltas = startup_diff["deltas"].as_array().unwrap();
    match (package_before, package_after) {
        (Some(_), Some(_)) => {
            assert_eq!(startup_before_rows.len(), 2);
            assert_eq!(startup_after_rows.len(), 2);
            assert_eq!(startup_diff["counts"]["changed"], 2);
            assert_eq!(startup_deltas.len(), 2);
            for ((before_path, before_index), (after_path, after_index)) in
                startup_before_rows.iter().zip(&startup_after_rows)
            {
                assert_eq!(before_path, after_path);
                let before_pointer = format!("/systemd_units/records/{before_index}");
                let after_pointer = format!("/systemd_units/records/{after_index}");
                let matching = startup_deltas
                    .iter()
                    .filter(|delta| {
                        delta["category"] == "systemd_units"
                            && delta["kind"] == "changed"
                            && delta["before"]["references"]
                                .as_array()
                                .is_some_and(|refs| {
                                    refs.iter().any(|value| value == &before_pointer)
                                })
                            && delta["after"]["references"].as_array().is_some_and(|refs| {
                                refs.iter().any(|value| value == &after_pointer)
                            })
                    })
                    .collect::<Vec<_>>();
                assert_eq!(matching.len(), 1);
                assert!(
                    matching[0]["changed_fields"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|field| field == "directives")
                );
            }
        }
        (None, Some(_)) | (Some(_), None) => {
            if startup_is_complete {
                assert_eq!(startup_deltas.len(), 2);
                let expected_kind = if package_before.is_none() {
                    "observed_after_only"
                } else {
                    "observed_before_only"
                };
                assert!(
                    startup_deltas
                        .iter()
                        .all(|delta| delta["kind"] == expected_kind
                            && delta["category"] == "systemd_units")
                );
                let expected_rows = if package_before.is_none() {
                    &startup_after_rows
                } else {
                    &startup_before_rows
                };
                for (_, index) in expected_rows {
                    let pointer = format!("/systemd_units/records/{index}");
                    assert!(startup_deltas.iter().any(|delta| {
                        let side = if package_before.is_none() {
                            &delta["after"]
                        } else {
                            &delta["before"]
                        };
                        delta["category"] == "systemd_units"
                            && side["references"]
                                .as_array()
                                .is_some_and(|refs| refs.iter().any(|value| value == &pointer))
                    }));
                }
            } else {
                assert!(
                    startup_deltas
                        .iter()
                        .all(|delta| delta["kind"] == "changed")
                );
                assert!(
                    startup_diff["counts"]["unmatched_rows_suppressed_for_incomplete_source"]
                        .as_u64()
                        .unwrap()
                        >= 2
                );
            }
        }
        _ => unreachable!("validated package transition"),
    }
    let expected_delta_kind = match (payload_before.is_some(), payload_after.is_some()) {
        (false, true) => "added",
        (true, true) => "changed",
        (true, false) => "removed",
        (false, false) => unreachable!("validated above"),
    };
    assert_eq!(
        report["root_diff"]["counts"]["additions"],
        usize::from(expected_delta_kind == "added")
    );
    assert_eq!(
        report["root_diff"]["counts"]["removals"],
        usize::from(expected_delta_kind == "removed")
    );
    assert_eq!(
        report["root_diff"]["counts"]["changes"],
        usize::from(expected_delta_kind == "changed")
    );
    let delta = &report["root_diff"]["deltas"][0];
    assert_eq!(delta["kind"], expected_delta_kind);
    assert_eq!(delta["name"], PAYLOAD_NAME);
    assert_eq!(report["runtime_source_status"], "partial");
    assert_eq!(report["runtime_capture_completeness"], "unknown");

    let association = &report["root_runtime_association"];
    assert_eq!(
        association["claim"],
        "lexical_path_candidate_only_no_causation_or_process_identity"
    );
    assert_eq!(association["status"], "partial");
    assert_eq!(association["capture_completeness"], "unknown");
    assert_eq!(association["trace_sha256"], trace_ref.sha256);
    let payload_path = observed_root.join(PAYLOAD_NAME);
    let payload_path = payload_path.to_string_lossy();
    let staged_payload_path = observed_root.join(format!("{PAYLOAD_NAME}.dpkg-new"));
    let staged_payload_path = staged_payload_path.to_string_lossy();
    assert_eq!(
        trace.source_sha256,
        sha256_hex(&trace_bytes),
        "parsed runtime rows must retain the exact trace fingerprint"
    );

    // The observed successful mutation supplies a candidate only on the delta's
    // supported side: rename destination for add/change, unlink or rename source
    // for removal. The staging path is not a snapshot delta.
    assert_eq!(association["summary"]["delta_count"], 1);
    let associations = association["associations"].as_array().unwrap();
    let candidate_count = association["summary"]["candidate_match_count"]
        .as_u64()
        .expect("candidate count is numeric");
    assert!(
        candidate_count <= 1,
        "unexpected duplicate candidate: {association}"
    );
    assert_eq!(
        association["summary"]["unmatched_delta_count"],
        u64::from(candidate_count == 0)
    );
    if expected_delta_kind == "changed" {
        assert!(
            delta["changed_fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| { field == "content_sha256" })
        );
        assert_eq!(
            delta["before"]["entry_ordinal"],
            snapshot_entry(&before_snapshot, PAYLOAD_NAME)["ordinal"]
        );
        assert_eq!(
            delta["after"]["entry_ordinal"],
            snapshot_entry(&after_snapshot, PAYLOAD_NAME)["ordinal"]
        );
    } else if expected_delta_kind == "removed" {
        assert_eq!(
            delta["before"]["entry_ordinal"],
            snapshot_entry(&before_snapshot, PAYLOAD_NAME)["ordinal"]
        );
        assert!(delta["after"].is_null());
    }
    if candidate_count == 1 {
        assert_eq!(associations.len(), 1);
        assert_eq!(associations[0]["delta_kind"], expected_delta_kind);
        assert_eq!(associations[0]["status"], "candidate_match");
        assert_eq!(associations[0]["candidate_path"], payload_path.as_ref());
        assert!(
            !associations[0]["multiple_runtime_observations"]
                .as_bool()
                .unwrap()
        );
        let evidence = associations[0]["runtime_evidence"].as_array().unwrap();
        assert_eq!(evidence.len(), 1);
        let runtime_mutation = trace
            .records
            .iter()
            .find(|record| {
                record.evidence.line_number == evidence[0]["line_number"]
                    && record.evidence.byte_offset == evidence[0]["byte_offset"]
                    && record.evidence.byte_length == evidence[0]["byte_length"]
            })
            .expect("association locator must resolve to one parsed raw trace row");
        assert_eq!(
            evidence[0]["syscall"],
            runtime_mutation.syscall.as_deref().unwrap()
        );
        assert_eq!(evidence[0]["trace_sha256"], trace_ref.sha256);
        assert_eq!(runtime_mutation.kind, TraceRecordKind::Syscall);
        assert_eq!(runtime_mutation.raw_result.as_deref(), Some("0"));
        match expected_delta_kind {
            "added" | "changed" => {
                assert!(matches!(
                    runtime_mutation.syscall.as_deref(),
                    Some("rename" | "renameat" | "renameat2")
                ));
                let arguments = runtime_mutation.raw_arguments.as_deref().unwrap();
                assert!(arguments.contains(staged_payload_path.as_ref()));
                assert!(arguments.contains(payload_path.as_ref()));
                assert_eq!(runtime_mutation.outcome, None);
            }
            "removed" => match runtime_mutation.syscall.as_deref() {
                Some("unlink") => assert_eq!(
                    runtime_mutation.raw_arguments.as_deref(),
                    Some(format!("\"{payload_path}\"").as_str())
                ),
                Some("unlinkat") => {
                    let arguments = runtime_mutation.raw_arguments.as_deref().unwrap();
                    let parts = arguments.split(',').map(str::trim).collect::<Vec<_>>();
                    assert_eq!(parts.len(), 3);
                    assert!(parts[0].starts_with("AT_FDCWD"));
                    assert_eq!(parts[1], format!("\"{payload_path}\""));
                    assert_eq!(parts[2], "0");
                }
                Some("rename" | "renameat" | "renameat2") => {
                    let arguments = runtime_mutation.raw_arguments.as_deref().unwrap();
                    assert!(arguments.starts_with(&format!("\"{payload_path}\",")));
                }
                other => panic!("unexpected syscall for a removal association: {other:?}"),
            },
            _ => unreachable!("transition kind was established above"),
        }
        let start = runtime_mutation.evidence.byte_offset as usize;
        let end = start
            .checked_add(runtime_mutation.evidence.byte_length as usize)
            .expect("runtime mutation evidence range does not overflow");
        assert_eq!(
            &trace_bytes[start..end],
            runtime_mutation.raw_line.as_bytes()
        );
        assert!(runtime_mutation.raw_line.ends_with(" = 0"));
    } else {
        assert_eq!(expected_delta_kind, "removed");
        assert!(associations.is_empty());
        let removal_rows = trace
            .records
            .iter()
            .filter(|record| {
                matches!(
                    record.syscall.as_deref(),
                    Some("unlink" | "unlinkat" | "rename" | "renameat" | "renameat2")
                ) && record.raw_result.as_deref() == Some("0")
                    && record.raw_line.contains(PAYLOAD_NAME)
            })
            .collect::<Vec<_>>();
        let split_pairs = successful_split_removal_pairs(&trace.records, PAYLOAD_NAME);
        if removal_rows.is_empty() && split_pairs.is_empty() {
            let rows = trace
                .records
                .iter()
                .filter(|record| {
                    matches!(
                        record.syscall.as_deref(),
                        Some("unlink" | "unlinkat" | "rename" | "renameat" | "renameat2")
                    )
                })
                .take(8)
                .map(|record| {
                    let mut line = record.raw_line.chars().take(384).collect::<String>();
                    if record.raw_line.chars().count() > 384 {
                        line.push('…');
                    }
                    format!("{}: {line}", record.evidence.line_number)
                })
                .collect::<Vec<_>>();
            panic!(
                "purge delta is explicitly unmatched and no successful complete removal or uniquely paired split removal mentions payload basename; bounded raw rows: {}",
                if rows.is_empty() {
                    "none parsed".to_owned()
                } else {
                    rows.join(" | ")
                }
            );
        }
        for record in &removal_rows {
            let start = usize::try_from(record.evidence.byte_offset)
                .expect("trace byte offset fits the host address size");
            let end = start
                .checked_add(record.evidence.byte_length as usize)
                .expect("trace evidence range does not overflow");
            assert_eq!(
                trace_bytes.get(start..end),
                Some(record.raw_line.as_bytes()),
                "unmatched removal evidence locator must resolve to its raw trace row"
            );
        }
        for (unfinished, resumed) in &split_pairs {
            for record in [unfinished, resumed] {
                let start = usize::try_from(record.evidence.byte_offset)
                    .expect("trace byte offset fits the host address size");
                let end = start
                    .checked_add(record.evidence.byte_length as usize)
                    .expect("trace evidence range does not overflow");
                assert_eq!(
                    trace_bytes.get(start..end),
                    Some(record.raw_line.as_bytes()),
                    "split removal evidence locator must resolve to its raw trace row"
                );
            }
        }
        let mut diagnostic_rows = removal_rows
            .iter()
            .take(8)
            .map(|record| {
                format!(
                    "{}: {}",
                    record.evidence.line_number,
                    record.raw_line.chars().take(384).collect::<String>()
                )
            })
            .collect::<Vec<_>>();
        for (unfinished, resumed) in split_pairs.iter().take(4) {
            diagnostic_rows.push(format!(
                "{} + {} (same PID/syscall unique pair): {} || {}",
                unfinished.evidence.line_number,
                resumed.evidence.line_number,
                unfinished.raw_line.chars().take(384).collect::<String>(),
                resumed.raw_line.chars().take(384).collect::<String>()
            ));
        }
        eprintln!(
            "purge delta explicitly unmatched by absolute lexical path; validated bounded runtime evidence (no path identity inferred): {}",
            diagnostic_rows.join(" | ")
        );
    }

    if payload_after.is_some() {
        let staged_create = trace
            .records
            .iter()
            .find(|record| {
                matches!(record.syscall.as_deref(), Some("openat" | "openat2"))
                    && record.outcome == Some(SyscallOutcome::Success)
                    && record
                        .raw_arguments
                        .as_ref()
                        .is_some_and(|arguments| arguments.contains("O_CREAT"))
                    && record
                        .lexical_path_hint
                        .as_ref()
                        .is_some_and(|hint| hint.path == staged_payload_path.as_ref())
            })
            .expect("raw trace must retain a successful create of the dpkg staging path");
        let start = staged_create.evidence.byte_offset as usize;
        let end = start
            .checked_add(staged_create.evidence.byte_length as usize)
            .expect("staging create evidence range does not overflow");
        assert_eq!(&trace_bytes[start..end], staged_create.raw_line.as_bytes());
    }
}

fn assert_session_artifacts_verified<'a>(
    session_path: &Path,
    artifacts: impl Iterator<Item = &'a SessionArtifactRef>,
) {
    for artifact in artifacts {
        let path = session_path.join(&artifact.path);
        let metadata = fs::symlink_metadata(&path).expect("session artifact exists");
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let bytes = fs::read(path).unwrap();
        assert_eq!(artifact.byte_length, bytes.len() as u64);
        assert_eq!(artifact.sha256, sha256_hex(&bytes));
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn split_purge_removal_evidence_pairs_only_unique_pid_and_syscall_rows() {
    let prefix = b"7539 1794733592.063025 unlink(\"/tmp/private/root/usr/lib/pkg/payload.bin\" <unfinished ...>\n7539 1794733592.063214 <... unlink resumed>) = 0\n";
    let parsed = parse_trace_bytes(prefix, ParseLimits::default()).unwrap();
    let pairs = successful_split_removal_pairs(&parsed.records, PAYLOAD_NAME);
    assert_eq!(pairs.len(), 1);
    let (unfinished, resumed) = pairs[0];
    assert_eq!(unfinished.kind, TraceRecordKind::UnfinishedSyscall);
    assert_eq!(resumed.kind, TraceRecordKind::ResumedSyscall);
    assert_eq!(unfinished.process_id, Some(7539));
    assert_eq!(resumed.process_id, Some(7539));
    assert_eq!(unfinished.syscall.as_deref(), Some("unlink"));
    assert_eq!(resumed.syscall.as_deref(), Some("unlink"));
    assert_eq!(resumed.raw_result.as_deref(), Some("0"));
    for record in [unfinished, resumed] {
        let start = record.evidence.byte_offset as usize;
        let end = start + record.evidence.byte_length as usize;
        assert_eq!(
            &prefix[start..end],
            record.raw_line.as_bytes(),
            "each paired locator must resolve to its own raw row"
        );
    }

    let ambiguous = b"7539 1794733592.063025 unlink(\"/tmp/private/root/payload.bin\" <unfinished ...>\n7539 1794733592.063026 unlink(\"/tmp/private/root/other.bin\" <unfinished ...>\n7539 1794733592.063214 <... unlink resumed>) = 0\n";
    let parsed = parse_trace_bytes(ambiguous, ParseLimits::default()).unwrap();
    assert!(successful_split_removal_pairs(&parsed.records, PAYLOAD_NAME).is_empty());

    let wrong_pid = b"7539 1794733592.063025 unlink(\"/tmp/private/root/payload.bin\" <unfinished ...>\n7540 1794733592.063214 <... unlink resumed>) = 0\n";
    let parsed = parse_trace_bytes(wrong_pid, ParseLimits::default()).unwrap();
    assert!(successful_split_removal_pairs(&parsed.records, PAYLOAD_NAME).is_empty());

    let out_of_order = b"7539 1794733592.063025 <... unlink resumed>) = 0\n7539 1794733592.063214 unlink(\"/tmp/private/root/payload.bin\" <unfinished ...>\n";
    let parsed = parse_trace_bytes(out_of_order, ParseLimits::default()).unwrap();
    assert!(successful_split_removal_pairs(&parsed.records, PAYLOAD_NAME).is_empty());

    let failed = b"7539 1794733592.063025 unlink(\"/tmp/private/root/payload.bin\" <unfinished ...>\n7539 1794733592.063214 <... unlink resumed>) = -1 ENOENT (No such file or directory)\n";
    let parsed = parse_trace_bytes(failed, ParseLimits::default()).unwrap();
    assert!(successful_split_removal_pairs(&parsed.records, PAYLOAD_NAME).is_empty());

    let sequential = b"7539 1794733592.063025 unlink(\"/tmp/private/root/payload.bin\" <unfinished ...>\n7539 1794733592.063214 <... unlink resumed>) = 0\n7539 1794733592.064025 unlink(\"/tmp/private/root/payload.bin\" <unfinished ...>\n7539 1794733592.064214 <... unlink resumed>) = 0\n";
    let parsed = parse_trace_bytes(sequential, ParseLimits::default()).unwrap();
    assert_eq!(
        successful_split_removal_pairs(&parsed.records, PAYLOAD_NAME).len(),
        2
    );
}

#[test]
fn private_dpkg_install_update_downgrade_purge_has_selected_root_evidence() {
    for tool in [DPKG, DPKG_DEB, DPKG_QUERY] {
        require_tool(tool);
    }

    let temporary = TempDirectory::new();
    let private_parent = &temporary.0;
    let private_root = private_parent.join("root");
    fs::create_dir(&private_root).unwrap();
    fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700)).unwrap();
    let startup_environment = PrivateStartupEnvironment::new(&private_root, private_parent);
    let admindir = private_root.join("var/lib/dpkg");
    fs::create_dir_all(&admindir).unwrap();
    fs::write(admindir.join("status"), b"").unwrap();
    let install_root = private_root.join(PACKAGE_DIRECTORY);
    fs::create_dir_all(&install_root).unwrap();
    fs::write(install_root.join(ANCHOR_NAME), ANCHOR_CONTENT).unwrap();
    let payload_v1 = b"synthetic benign dpkg fixture revision A\n";
    let payload_v2 = b"synthetic benign dpkg fixture revision B\n";
    let deb_v1 = build_scriptless_deb(private_parent, "1.0-1", payload_v1);
    let deb_v2 = build_scriptless_deb(private_parent, "2.0-1", payload_v2);
    assert!(deb_v1.starts_with(private_parent));
    assert!(deb_v2.starts_with(private_parent));

    let package_before_install_path = private_parent.join("packages-before-install.json");
    let package_before_install =
        dpkg_query_inventory(&private_root, private_parent, &package_before_install_path);
    assert_package_version(&package_before_install, None);

    let before_install_path = private_parent.join("before-install.json");
    let before_install = snapshot(&install_root, &before_install_path);
    assert_eq!(before_install["status"], "complete");
    let before_entries = before_install["entries"].as_array().unwrap();
    assert_eq!(before_entries.len(), 1);
    assert_eq!(before_entries[0]["display_name"], ANCHOR_NAME);
    assert_eq!(
        before_entries[0]["content_sha256"],
        sha256_hex(ANCHOR_CONTENT)
    );

    let observed_v1_session = private_parent.join("observed-install-v1.session");
    audit_dpkg_install(
        &private_root,
        private_parent,
        &startup_environment,
        &install_root,
        &deb_v1,
        &observed_v1_session,
    );
    assert_observed_dpkg_transition(
        &observed_v1_session,
        &install_root,
        &startup_environment,
        None,
        Some(payload_v1),
        None,
        Some("1.0-1"),
    );
    let packages_v1_path = private_parent.join("packages-installed-v1.json");
    let packages_v1 = dpkg_query_inventory(&private_root, private_parent, &packages_v1_path);
    assert_package_version(&packages_v1, Some("1.0-1"));
    let package_install_diff = package_diff(&package_before_install_path, &packages_v1_path);
    assert_eq!(package_install_diff["counts"]["additions"], 1);
    assert_package_delta_evidence(&package_install_diff, "added", None, Some(1));
    let v1_snapshot_path = private_parent.join("installed-v1.json");
    let v1_snapshot = snapshot(&install_root, &v1_snapshot_path);
    let v1_ordinal = snapshot_payload_hash(&v1_snapshot, payload_v1);
    let install_diff = snapshot_diff(&before_install_path, &v1_snapshot_path);
    assert_eq!(install_diff["counts"]["additions"], 1);
    assert_eq!(install_diff["deltas"][0]["kind"], "added");
    assert_eq!(
        install_diff["deltas"][0]["after"]["entry_ordinal"],
        v1_ordinal
    );
    assert_eq!(
        install_diff["deltas"][0]["after"]["evidence_source"],
        "selected_root_directory_entry"
    );

    let observed_v2_session = private_parent.join("observed-upgrade-v2.session");
    audit_dpkg_install(
        &private_root,
        private_parent,
        &startup_environment,
        &install_root,
        &deb_v2,
        &observed_v2_session,
    );
    assert_observed_dpkg_transition(
        &observed_v2_session,
        &install_root,
        &startup_environment,
        Some(payload_v1),
        Some(payload_v2),
        Some("1.0-1"),
        Some("2.0-1"),
    );
    let packages_v2_path = private_parent.join("packages-installed-v2.json");
    let packages_v2 = dpkg_query_inventory(&private_root, private_parent, &packages_v2_path);
    assert_package_version(&packages_v2, Some("2.0-1"));
    let package_update_diff = package_diff(&packages_v1_path, &packages_v2_path);
    assert_eq!(package_update_diff["counts"]["changes"], 1);
    assert_package_delta_evidence(&package_update_diff, "changed", Some(1), Some(1));
    let v2_snapshot_path = private_parent.join("installed-v2.json");
    let v2_snapshot = snapshot(&install_root, &v2_snapshot_path);
    let v2_ordinal = snapshot_payload_hash(&v2_snapshot, payload_v2);
    assert_ne!(
        snapshot_entry(&v1_snapshot, PAYLOAD_NAME)["content_sha256"],
        snapshot_entry(&v2_snapshot, PAYLOAD_NAME)["content_sha256"]
    );
    let update_diff = snapshot_diff(&v1_snapshot_path, &v2_snapshot_path);
    assert_eq!(update_diff["counts"]["changes"], 1);
    assert!(
        update_diff["deltas"][0]["changed_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "content_sha256")
    );
    assert_eq!(
        update_diff["deltas"][0]["before"]["entry_ordinal"],
        v1_ordinal
    );
    assert_eq!(
        update_diff["deltas"][0]["after"]["entry_ordinal"],
        v2_ordinal
    );

    dpkg_install(
        &private_root,
        private_parent,
        &startup_environment,
        &deb_v1,
        true,
    );
    let packages_downgraded_path = private_parent.join("packages-downgraded-v1.json");
    let packages_downgraded =
        dpkg_query_inventory(&private_root, private_parent, &packages_downgraded_path);
    assert_package_version(&packages_downgraded, Some("1.0-1"));
    let package_downgrade_diff = package_diff(&packages_v2_path, &packages_downgraded_path);
    assert_eq!(package_downgrade_diff["counts"]["changes"], 1);
    assert_package_delta_evidence(&package_downgrade_diff, "changed", Some(1), Some(1));
    let downgraded_snapshot_path = private_parent.join("downgraded-v1.json");
    let downgraded_snapshot = snapshot(&install_root, &downgraded_snapshot_path);
    let downgraded_ordinal = snapshot_payload_hash(&downgraded_snapshot, payload_v1);
    assert_eq!(
        snapshot_entry(&downgraded_snapshot, PAYLOAD_NAME)["content_sha256"],
        snapshot_entry(&v1_snapshot, PAYLOAD_NAME)["content_sha256"]
    );
    let downgrade_diff = snapshot_diff(&v2_snapshot_path, &downgraded_snapshot_path);
    assert_eq!(downgrade_diff["counts"]["changes"], 1);
    assert!(
        downgrade_diff["deltas"][0]["changed_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "content_sha256")
    );
    assert_eq!(
        downgrade_diff["deltas"][0]["before"]["entry_ordinal"],
        v2_ordinal
    );
    assert_eq!(
        downgrade_diff["deltas"][0]["after"]["entry_ordinal"],
        downgraded_ordinal
    );

    let observed_purge_session = private_parent.join("observed-purge-v1.session");
    audit_dpkg_purge(
        &private_root,
        private_parent,
        &startup_environment,
        &install_root,
        &observed_purge_session,
    );
    assert_observed_dpkg_transition(
        &observed_purge_session,
        &install_root,
        &startup_environment,
        Some(payload_v1),
        None,
        Some("1.0-1"),
        None,
    );
    let packages_purged_path = private_parent.join("packages-purged.json");
    let packages_purged =
        dpkg_query_inventory(&private_root, private_parent, &packages_purged_path);
    assert_package_version(&packages_purged, None);
    let package_purge_diff = package_diff(&packages_downgraded_path, &packages_purged_path);
    assert_eq!(package_purge_diff["counts"]["removals"], 1);
    assert_package_delta_evidence(&package_purge_diff, "removed", Some(1), None);
    let purged_snapshot_path = private_parent.join("purged.json");
    let purged_snapshot = snapshot(&install_root, &purged_snapshot_path);
    assert_eq!(purged_snapshot["status"], "complete");
    let purged_entries = purged_snapshot["entries"].as_array().unwrap();
    assert_eq!(purged_entries.len(), 1);
    assert_eq!(purged_entries[0]["display_name"], ANCHOR_NAME);
    let purge_diff = snapshot_diff(&downgraded_snapshot_path, &purged_snapshot_path);
    assert_eq!(purge_diff["counts"]["removals"], 1);
    assert_eq!(purge_diff["deltas"][0]["kind"], "removed");
    assert_eq!(
        purge_diff["deltas"][0]["before"]["entry_ordinal"],
        downgraded_ordinal
    );
    assert_eq!(
        purge_diff["deltas"][0]["before"]["evidence_source"],
        "selected_root_directory_entry"
    );
    assert!(purge_diff["deltas"][0]["after"].is_null());

    assert!(private_root.starts_with(private_parent));
    let admin = private_root.join("var/lib/dpkg");
    assert!(admin.starts_with(&private_root));
    let log = private_parent.join("dpkg.log");
    assert!(log.starts_with(private_parent));
    assert!(log.is_file());
}
