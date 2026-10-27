//! Linux subprocess limits and private temporary storage for local inference.

#[cfg(target_os = "linux")]
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::{Command, ExitStatus, Stdio};

#[cfg(target_os = "linux")]
const DEFAULT_ADDRESS_SPACE_LIMIT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_ADDRESS_SPACE_LIMIT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[cfg(target_os = "linux")]
pub struct BoundedPipe {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

#[cfg(target_os = "linux")]
pub struct BoundedCommandOutput {
    pub status: ExitStatus,
    pub stdout: BoundedPipe,
    pub stderr: BoundedPipe,
}

#[cfg(target_os = "linux")]
pub struct TempDirectory(pub PathBuf);

#[cfg(target_os = "linux")]
impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(target_os = "linux")]
pub fn create_private_temp_dir() -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    for _ in 0..128 {
        let nonce = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sideeffect-local-model-{}-{epoch:x}-{nonce:x}",
            std::process::id()
        ));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!("could not create private model workspace: {error}"));
            }
        }
    }
    Err("could not allocate a unique private model workspace".to_owned())
}

#[cfg(target_os = "linux")]
fn set_pipe_nonblocking(fd: std::os::fd::RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn drain_pipe<R: Read>(
    reader: &mut R,
    pipe: &mut BoundedPipe,
    limit: usize,
    closed: &mut bool,
    deadline: std::time::Instant,
) -> io::Result<()> {
    let mut buffer = [0_u8; 4096];
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local runtime exceeded its wall-clock limit",
            ));
        }
        match reader.read(&mut buffer) {
            Ok(0) => {
                *closed = true;
                return Ok(());
            }
            Ok(read) => {
                let remaining = limit.saturating_sub(pipe.bytes.len());
                let retained = read.min(remaining);
                if retained > 0 {
                    pipe.bytes
                        .try_reserve(retained)
                        .map_err(|_| io::Error::other("bounded output allocation failed"))?;
                    pipe.bytes.extend_from_slice(&buffer[..retained]);
                }
                pipe.truncated |= retained < read;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
pub fn run_bounded(
    program: &Path,
    arguments: &[std::ffi::OsString],
    working_directory: Option<&Path>,
    timeout_seconds: u64,
    output_limit: usize,
) -> Result<BoundedCommandOutput, String> {
    run_bounded_with_address_space_limit(
        program,
        arguments,
        working_directory,
        timeout_seconds,
        output_limit,
        DEFAULT_ADDRESS_SPACE_LIMIT_BYTES,
    )
}

/// Run a subprocess with the same restrictions as [`run_bounded`], allowing
/// only the address-space ceiling to be selected up to the reviewed 4 GiB cap.
#[cfg(target_os = "linux")]
pub fn run_bounded_with_address_space_limit(
    program: &Path,
    arguments: &[std::ffi::OsString],
    working_directory: Option<&Path>,
    timeout_seconds: u64,
    output_limit: usize,
    address_space_limit_bytes: u64,
) -> Result<BoundedCommandOutput, String> {
    if address_space_limit_bytes == 0 || address_space_limit_bytes > MAX_ADDRESS_SPACE_LIMIT_BYTES {
        return Err(format!(
            "local runtime address-space limit must be between 1 and {MAX_ADDRESS_SPACE_LIMIT_BYTES} bytes"
        ));
    }
    let mut command = Command::new(program);
    command
        .env_clear()
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(directory) = working_directory {
        command.current_dir(directory);
    }
    if address_space_limit_bytes == DEFAULT_ADDRESS_SPACE_LIMIT_BYTES {
        set_child_limits(&mut command)?;
    } else {
        set_child_limits_with_address_space_limit(&mut command, address_space_limit_bytes)?;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_seconds);
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start the selected local runtime: {error}"))?;
    let mut stdout = child.stdout.take().expect("piped runtime stdout");
    let mut stderr = child.stderr.take().expect("piped runtime stderr");
    if let Err(error) = set_pipe_nonblocking(std::os::fd::AsRawFd::as_raw_fd(&stdout))
        .and_then(|()| set_pipe_nonblocking(std::os::fd::AsRawFd::as_raw_fd(&stderr)))
    {
        kill_process_group(child.id());
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "could not configure bounded runtime output pipes: {error}"
        ));
    }
    let mut stdout_pipe = BoundedPipe {
        bytes: Vec::new(),
        truncated: false,
    };
    let mut stderr_pipe = BoundedPipe {
        bytes: Vec::new(),
        truncated: false,
    };
    let mut stdout_closed = false;
    let mut stderr_closed = false;
    let mut status = None;
    loop {
        if !stdout_closed {
            drain_pipe(
                &mut stdout,
                &mut stdout_pipe,
                output_limit,
                &mut stdout_closed,
                deadline,
            )
            .map_err(|error| {
                kill_process_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                format!("could not read local runtime output: {error}")
            })?;
        }
        if !stderr_closed {
            drain_pipe(
                &mut stderr,
                &mut stderr_pipe,
                16 * 1024,
                &mut stderr_closed,
                deadline,
            )
            .map_err(|error| {
                kill_process_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                format!("could not read local runtime diagnostics: {error}")
            })?;
        }
        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    kill_process_group(child.id());
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("could not wait for local runtime: {error}"));
                }
            };
        }
        if status.is_some() && stdout_closed && stderr_closed {
            break;
        }
        if std::time::Instant::now() >= deadline {
            kill_process_group(child.id());
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "local runtime exceeded the {timeout_seconds} second time limit"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok(BoundedCommandOutput {
        status: status.expect("runtime status was observed before output pipes closed"),
        stdout: stdout_pipe,
        stderr: stderr_pipe,
    })
}

#[cfg(target_os = "linux")]
pub fn set_child_limits(command: &mut Command) -> Result<(), String> {
    set_child_limits_with_address_space_limit(command, DEFAULT_ADDRESS_SPACE_LIMIT_BYTES)
}

#[cfg(target_os = "linux")]
fn set_child_limits_with_address_space_limit(
    command: &mut Command,
    address_space_limit_bytes: u64,
) -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    if address_space_limit_bytes == 0 || address_space_limit_bytes > MAX_ADDRESS_SPACE_LIMIT_BYTES {
        return Err(format!(
            "local runtime address-space limit must be between 1 and {MAX_ADDRESS_SPACE_LIMIT_BYTES} bytes"
        ));
    }
    let address_space_limit = libc::rlim_t::try_from(address_space_limit_bytes).map_err(|_| {
        "requested address-space limit is not representable by this platform".to_owned()
    })?;

    // This is defense in depth for the pinned local runtime, not a sandbox.
    // The runtime inherits these limits and a seccomp filter that denies network
    // sockets, io_uring, privilege changes, and unneeded persistence channels.
    unsafe {
        command.process_group(0);
        command.pre_exec(move || {
            let limits = [
                (libc::RLIMIT_CPU, 120 as libc::rlim_t),
                (libc::RLIMIT_AS, address_space_limit),
                (libc::RLIMIT_FSIZE, 0 as libc::rlim_t),
                (libc::RLIMIT_CORE, 0 as libc::rlim_t),
                (libc::RLIMIT_NOFILE, 64 as libc::rlim_t),
            ];
            for (resource, value) in limits {
                let limit = libc::rlimit {
                    rlim_cur: value,
                    rlim_max: value,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            install_network_deny_filter()
        });
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn install_network_deny_filter() -> io::Result<()> {
    use libc::{
        BPF_ABS, BPF_JEQ, BPF_JMP, BPF_JSET, BPF_K, BPF_LD, BPF_RET, BPF_W, PR_SET_SECCOMP,
        SECCOMP_MODE_FILTER, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
        sock_filter, sock_fprog,
    };

    const fn test_syscall(number: libc::c_long) -> sock_filter {
        sock_filter {
            code: (BPF_JMP | BPF_JEQ | BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: number as u32,
        }
    }
    const fn deny() -> sock_filter {
        sock_filter {
            code: (BPF_RET | BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | libc::EPERM as u32,
        }
    }

    // Reject non-x86_64 and x32 syscall ABIs so callers cannot bypass the
    // network syscall list with a different syscall-number namespace.
    const FILTER: [sock_filter; 41] = [
        sock_filter {
            code: (BPF_LD | BPF_W | BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 4,
        },
        sock_filter {
            code: (BPF_JMP | BPF_JEQ | BPF_K) as u16,
            jt: 1,
            jf: 0,
            k: 0xc000_003e,
        },
        sock_filter {
            code: (BPF_RET | BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        },
        sock_filter {
            code: (BPF_LD | BPF_W | BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        sock_filter {
            code: (BPF_JMP | BPF_JSET | BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: 0x4000_0000,
        },
        sock_filter {
            code: (BPF_RET | BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        },
        test_syscall(libc::SYS_socket),
        deny(),
        test_syscall(libc::SYS_socketpair),
        deny(),
        test_syscall(libc::SYS_connect),
        deny(),
        test_syscall(libc::SYS_bind),
        deny(),
        test_syscall(libc::SYS_listen),
        deny(),
        test_syscall(libc::SYS_accept),
        deny(),
        test_syscall(libc::SYS_accept4),
        deny(),
        test_syscall(libc::SYS_sendto),
        deny(),
        test_syscall(libc::SYS_recvfrom),
        deny(),
        test_syscall(libc::SYS_sendmsg),
        deny(),
        test_syscall(libc::SYS_recvmsg),
        deny(),
        test_syscall(libc::SYS_shutdown),
        deny(),
        test_syscall(libc::SYS_setsockopt),
        deny(),
        test_syscall(libc::SYS_getsockopt),
        deny(),
        test_syscall(libc::SYS_getsockname),
        deny(),
        test_syscall(libc::SYS_getpeername),
        deny(),
        test_syscall(libc::SYS_io_uring_setup),
        deny(),
        sock_filter {
            code: (BPF_RET | BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ];
    let program = sock_fprog {
        len: FILTER.len() as u16,
        filter: FILTER.as_ptr() as *mut sock_filter,
    };
    // SAFETY: FILTER is a static, validated BPF program that reads only the
    // syscall architecture and number and denies known network entry points.
    if unsafe { libc::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
unsafe fn install_network_deny_filter() -> io::Result<()> {
    Err(io::Error::other(
        "local model analysis is currently supported only on Linux x86_64",
    ))
}

#[cfg(target_os = "linux")]
fn kill_process_group(child_id: u32) {
    // The runtime is placed in its own process group before exec. This best-effort
    // cleanup also covers children that inherited the stdout/stderr pipe handles.
    unsafe {
        libc::kill(-(child_id as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(target_os = "linux")]
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("could not create private model schema: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("could not write private model schema: {error}"))
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use super::{run_bounded, run_bounded_with_address_space_limit};
    use std::ffi::OsString;
    use std::path::Path;

    fn python() -> &'static Path {
        let python = Path::new("/usr/bin/python3");
        assert!(
            python.is_file(),
            "Linux CI installs python3 for runtime checks"
        );
        python
    }

    #[test]
    fn existing_bounded_api_keeps_the_two_gibibyte_address_space_limit() {
        let script = "import resource\nprint(resource.getrlimit(resource.RLIMIT_AS)[0])";
        let arguments = [OsString::from("-c"), OsString::from(script)];
        let output = run_bounded(python(), &arguments, None, 10, 1024).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout.bytes, b"2147483648\n");
    }

    #[test]
    fn requested_four_gibibyte_limit_keeps_seccomp_network_denial() {
        let script = "import resource,socket\nprint(resource.getrlimit(resource.RLIMIT_AS)[0])\ntry:\n socket.socket(socket.AF_INET,socket.SOCK_STREAM)\nexcept PermissionError:\n print('network-blocked')\nelse:\n raise SystemExit(17)";
        let arguments = [OsString::from("-c"), OsString::from(script)];
        let output = run_bounded_with_address_space_limit(
            python(),
            &arguments,
            None,
            10,
            1024,
            4 * 1024 * 1024 * 1024,
        )
        .unwrap();
        assert!(output.status.success());
        assert!(!output.stdout.truncated);
        assert_eq!(output.stdout.bytes, b"4294967296\nnetwork-blocked\n");
    }

    #[test]
    fn configurable_address_space_limit_rejects_values_above_four_gibibytes() {
        let arguments: [OsString; 0] = [];
        let error = run_bounded_with_address_space_limit(
            python(),
            &arguments,
            None,
            10,
            1024,
            4 * 1024 * 1024 * 1024 + 1,
        )
        .err()
        .expect("a limit above the cap must be rejected before spawn");
        assert!(error.contains("address-space limit"));
    }

    #[test]
    fn seccomp_denies_inet_and_unix_socket_creation() {
        let script = "import socket\nfor family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):\n try:\n  socket.socket(family, socket.SOCK_STREAM)\n except PermissionError:\n  continue\n else:\n  raise SystemExit(17)\nprint('blocked')";
        let arguments = [OsString::from("-c"), OsString::from(script)];
        let output = run_bounded(python(), &arguments, None, 10, 1024).unwrap();
        assert!(output.status.success());
        assert!(!output.stdout.truncated);
        assert_eq!(output.stdout.bytes, b"blocked\n");
    }
}

#[cfg(target_os = "windows")]
use std::io::{self, Read, Write};
#[cfg(target_os = "windows")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::process::{Command, ExitStatus, Stdio};

#[cfg(target_os = "windows")]
const WINDOWS_MAX_PROCESS_MEMORY_BYTES: u64 = 6 * 1024 * 1024 * 1024;
#[cfg(target_os = "windows")]
const WINDOWS_MAX_RUNTIME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
#[cfg(target_os = "windows")]
const WINDOWS_MAX_RUNTIME_OUTPUT_BYTES: usize = 64 * 1024;

#[cfg(target_os = "windows")]
pub struct BoundedPipe {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

#[cfg(target_os = "windows")]
pub struct BoundedCommandOutputWindows {
    pub status: ExitStatus,
    pub stdout: BoundedPipe,
    pub stderr: BoundedPipe,
    /// Job Objects bound host process resources only; they do not limit CUDA VRAM or deny network access.
    pub containment_note: &'static str,
}

/// Owns a private workspace and removes only that workspace when dropped.
#[cfg(target_os = "windows")]
pub struct TempDirectoryWindows {
    path: PathBuf,
}

#[cfg(target_os = "windows")]
impl Drop for TempDirectoryWindows {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(target_os = "windows")]
impl TempDirectoryWindows {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(target_os = "windows")]
pub fn create_private_temp_dir_windows() -> Result<TempDirectoryWindows, String> {
    use std::os::windows::fs::MetadataExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
    use windows_sys::Win32::Storage::FileSystem::{CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let base = std::env::temp_dir()
        .canonicalize()
        .map_err(|error| format!("could not resolve the Windows temporary directory: {error}"))?;
    let base_metadata = std::fs::symlink_metadata(&base)
        .map_err(|error| format!("could not inspect the Windows temporary directory: {error}"))?;
    if !base_metadata.is_dir()
        || base_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err("the Windows temporary directory is not a plain directory".to_owned());
    }
    let security = WindowsCurrentUserSecurity::new()?;
    let attributes = security.attributes();
    for _ in 0..128 {
        let nonce = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = base.join(format!(
            "sideeffect-local-model-{}-{epoch:x}-{nonce:x}",
            std::process::id()
        ));
        let path_wide = windows_wide_path(path.as_os_str());
        // SAFETY: the path and security descriptor remain alive during the call.
        if unsafe { CreateDirectoryW(path_wide.as_ptr(), &attributes) } != 0 {
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                let _ = std::fs::remove_dir(&path);
                format!("could not verify the private Windows model workspace: {error}")
            })?;
            if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                let _ = std::fs::remove_dir(&path);
                return Err(
                    "the private Windows model workspace is not a plain directory".to_owned(),
                );
            }
            return Ok(TempDirectoryWindows { path });
        }
        // SAFETY: GetLastError has no preconditions.
        let error = unsafe { GetLastError() };
        if error != ERROR_ALREADY_EXISTS {
            return Err(format!(
                "could not create a current-user-only Windows model workspace (Win32 error {error})"
            ));
        }
    }
    Err("could not allocate a unique private Windows model workspace".to_owned())
}

#[cfg(target_os = "windows")]
pub fn write_private_file_windows(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let security = WindowsCurrentUserSecurity::new()?;
    let attributes = security.attributes();
    let path_wide = windows_wide_path(path.as_os_str());
    // SAFETY: pointers refer to valid NUL-terminated path and live security attributes.
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "could not create an exclusive private Windows model file: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: handle is a new, exclusively-created file handle owned by this function.
    let mut file = unsafe { std::fs::File::from_raw_handle(handle.cast()) };
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("could not write private Windows model file: {error}"));
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

#[cfg(target_os = "windows")]
pub fn copy_verified_model_windows(
    source: &Path,
    destination: &Path,
    expected_sha256: &str,
    limit: u64,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };

    if limit == 0 || expected_sha256.len() != 64 {
        return Err(
            "verified model copy requires a positive limit and a SHA-256 digest".to_owned(),
        );
    }
    if !expected_sha256
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("verified model copy requires a lowercase SHA-256 digest".to_owned());
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut input = options
        .open(source)
        .map_err(|error| format!("could not open selected local model file: {error}"))?;
    let metadata = input
        .metadata()
        .map_err(|error| format!("could not inspect selected local model file: {error}"))?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("selected local model path must be a plain regular file".to_owned());
    }
    if metadata.len() > limit {
        return Err(format!(
            "selected local model exceeds the {limit} byte limit"
        ));
    }
    let mut output = create_private_windows_file(destination)?;
    let result = (|| {
        let mut hasher = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = input
                .read(&mut buffer)
                .map_err(|error| format!("could not read selected local model file: {error}"))?;
            if read == 0 {
                break;
            }
            copied = copied.saturating_add(read as u64);
            if copied > limit {
                return Err(format!(
                    "selected local model exceeds the {limit} byte limit"
                ));
            }
            hasher.update(&buffer[..read]);
            output
                .write_all(&buffer[..read])
                .map_err(|error| format!("could not stage verified local model: {error}"))?;
        }
        let digest = hasher.finalize();
        let mut text = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
        }
        if text != expected_sha256 {
            return Err(format!(
                "selected local model hash does not match the reviewed model ({expected_sha256})"
            ));
        }
        output
            .sync_all()
            .map_err(|error| format!("could not flush verified local model: {error}"))?;
        Ok(())
    })();
    drop(output);
    if result.is_err() {
        let _ = std::fs::remove_file(destination);
    }
    result
}

#[cfg(target_os = "windows")]
pub fn run_bounded_windows(
    program: &Path,
    arguments: &[std::ffi::OsString],
    working_directory: Option<&Path>,
    timeout: std::time::Duration,
    output_limit: usize,
    process_memory_limit_bytes: u64,
) -> Result<BoundedCommandOutputWindows, String> {
    use std::os::windows::process::CommandExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

    if timeout.is_zero() || timeout > WINDOWS_MAX_RUNTIME_TIMEOUT {
        return Err(format!(
            "local runtime timeout must be between 1 ms and {} seconds",
            WINDOWS_MAX_RUNTIME_TIMEOUT.as_secs()
        ));
    }
    if output_limit == 0 || output_limit > WINDOWS_MAX_RUNTIME_OUTPUT_BYTES {
        return Err(format!(
            "local runtime output limit must be between 1 and {WINDOWS_MAX_RUNTIME_OUTPUT_BYTES} bytes per stream"
        ));
    }
    if process_memory_limit_bytes == 0
        || process_memory_limit_bytes > WINDOWS_MAX_PROCESS_MEMORY_BYTES
    {
        return Err(format!(
            "local runtime process-memory limit must be between 1 and {WINDOWS_MAX_PROCESS_MEMORY_BYTES} bytes"
        ));
    }
    let deadline = std::time::Instant::now() + timeout;
    let mut command = Command::new(program);
    command
        .env_clear()
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_SUSPENDED);
    if let Some(directory) = working_directory {
        command.current_dir(directory);
        // CUDA dependencies should be colocated with the selected runtime or resolve via the
        // Windows loader's system locations; do not inherit an arbitrary user PATH.
        command.env("TEMP", directory).env("TMP", directory);
    }
    let system_directory = windows_system_directory()?;
    let system_root = system_directory
        .parent()
        .ok_or_else(|| "could not determine the Windows system root".to_owned())?;
    let program_files = windows_program_files_directory()?;
    let cuda_directories = discover_cuda_dll_directories(&program_files)?;
    let runtime_directory = program
        .parent()
        .ok_or_else(|| "selected local runtime has no containing directory".to_owned())?;
    let dll_search_path = build_windows_dll_search_path(
        &system_directory,
        runtime_directory,
        &program_files,
        &cuda_directories,
    )?;
    command
        .env("SystemRoot", system_root)
        .env("WINDIR", system_root)
        .env("PATH", dll_search_path);
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start the selected local runtime: {error}"))?;
    let job = match WindowsJob::new(process_memory_limit_bytes, timeout) {
        Ok(job) => job,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    if let Err(error) = job.assign(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    if let Err(error) = resume_suspended_process(child.id()) {
        job.terminate();
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let stdout = child.stdout.take().expect("piped runtime stdout");
    let stderr = child.stderr.take().expect("piped runtime stderr");
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout_overflow = Arc::clone(&overflow);
    let stderr_overflow = Arc::clone(&overflow);
    let stdout_reader =
        std::thread::spawn(move || drain_windows_pipe(stdout, output_limit, stdout_overflow));
    let stderr_reader =
        std::thread::spawn(move || drain_windows_pipe(stderr, output_limit, stderr_overflow));
    let mut status = None;
    let mut overflow_terminated = false;
    loop {
        if overflow.load(Ordering::Acquire) && !overflow_terminated {
            job.terminate();
            overflow_terminated = true;
        }
        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    job.terminate();
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = join_pipe_reader(stdout_reader);
                    let _ = join_pipe_reader(stderr_reader);
                    return Err(format!("could not wait for local runtime: {error}"));
                }
            };
        }
        if status.is_some() && stdout_reader.is_finished() && stderr_reader.is_finished() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            job.terminate();
            let _ = child.kill();
            let _ = child.wait();
            let _ = join_pipe_reader(stdout_reader);
            let _ = join_pipe_reader(stderr_reader);
            return Err(format!(
                "local runtime exceeded its {} millisecond time limit",
                timeout.as_millis()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let stdout = join_pipe_reader(stdout_reader)?;
    let stderr = join_pipe_reader(stderr_reader)?;
    Ok(BoundedCommandOutputWindows {
        status: status.expect("runtime process status is observed before its pipes close"),
        stdout,
        stderr,
        containment_note: "Windows Job Objects bound host process resources only; CUDA VRAM and network access are not limited or denied.",
    })
}

#[cfg(target_os = "windows")]
fn windows_system_directory() -> Result<PathBuf, String> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: buffer is writable and its length fits the API's u32 capacity argument.
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(format!(
            "could not resolve the Windows system directory: {}",
            io::Error::last_os_error()
        ));
    }
    let path = PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length]));
    canonical_plain_windows_directory(&path)
        .ok_or_else(|| "Windows system directory is not a plain directory".to_owned())
}

#[cfg(target_os = "windows")]
fn windows_program_files_directory() -> Result<PathBuf, String> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };

    let mut path = std::ptr::null_mut();
    // SAFETY: known-folder ID and writable output pointer are valid; null token requests current machine's known folder.
    let result = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramFiles,
            KF_FLAG_DEFAULT as u32,
            std::ptr::null_mut(),
            &mut path,
        )
    };
    if result < 0 || path.is_null() {
        return Err(format!(
            "could not resolve the Windows Program Files directory (HRESULT 0x{:08x})",
            result as u32
        ));
    }
    let allocation = WindowsComAllocation(path.cast());
    let length = unsafe { windows_wide_path_length(path) };
    if length == 0 || length >= 32_768 {
        return Err("Windows Program Files path is empty or oversized".to_owned());
    }
    let path = PathBuf::from(std::ffi::OsString::from_wide(unsafe {
        std::slice::from_raw_parts(path, length)
    }));
    drop(allocation);
    canonical_plain_windows_directory(&path)
        .ok_or_else(|| "Windows Program Files is not a plain directory".to_owned())
}

#[cfg(target_os = "windows")]
fn discover_cuda_dll_directories(program_files: &Path) -> Result<Vec<PathBuf>, String> {
    let program_files = canonical_plain_windows_directory(program_files)
        .ok_or_else(|| "Windows Program Files is not a plain directory".to_owned())?;
    let Some(cuda_root) = validated_child_directory(
        &program_files,
        &program_files
            .join("NVIDIA GPU Computing Toolkit")
            .join("CUDA"),
    )?
    else {
        return Ok(Vec::new());
    };

    let entries = std::fs::read_dir(&cuda_root)
        .map_err(|error| format!("could not enumerate NVIDIA CUDA toolkit versions: {error}"))?;
    let mut versions = Vec::new();
    let mut inspected = 0_usize;
    for entry in entries {
        inspected += 1;
        if inspected > 32 {
            return Err("too many NVIDIA CUDA toolkit entries to inspect safely".to_owned());
        }
        let entry = entry.map_err(|error| {
            format!("could not read NVIDIA CUDA toolkit directory entry: {error}")
        })?;
        if let Some(version) = parse_cuda_version_directory(&entry.file_name()) {
            versions.push((version, entry.path()));
        }
    }
    versions.sort_by(|left, right| right.0.cmp(&left.0));

    let mut directories = Vec::new();
    for (_, version_directory) in versions {
        // Some CUDA toolkit releases place DLLs in bin\x64; current 64-bit
        // installers may place them directly in bin. Both remain beneath the
        // validated Program Files toolkit tree.
        for candidate in [
            version_directory.join("bin").join("x64"),
            version_directory.join("bin"),
        ] {
            if let Some(directory) = validated_child_directory(&cuda_root, &candidate)? {
                directories.push(directory);
            }
        }
    }
    Ok(directories)
}

#[cfg(target_os = "windows")]
fn parse_cuda_version_directory(name: &std::ffi::OsStr) -> Option<Vec<u32>> {
    let name = name.to_str()?;
    let version = name.strip_prefix('v')?;
    if version.is_empty() || version.len() > 15 {
        return None;
    }
    let parts = version.split('.').collect::<Vec<_>>();
    if parts.is_empty()
        || parts.len() > 4
        || parts.iter().any(|part| part.is_empty() || part.len() > 3)
    {
        return None;
    }
    parts
        .into_iter()
        .map(|part| {
            if !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            part.parse::<u32>().ok()
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn validated_child_directory(root: &Path, candidate: &Path) -> Result<Option<PathBuf>, String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let relative = match candidate.strip_prefix(root) {
        Ok(relative) => relative,
        Err(_) => return Ok(None),
    };
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Ok(None);
        };
        current.push(name);
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!("could not inspect NVIDIA CUDA directory: {error}"));
            }
        };
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Ok(None);
        }
    }
    let canonical = match current.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not resolve NVIDIA CUDA directory: {error}")),
    };
    if !canonical.starts_with(root) {
        return Ok(None);
    }
    Ok(Some(canonical))
}

#[cfg(target_os = "windows")]
fn canonical_plain_windows_directory(path: &Path) -> Option<PathBuf> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return None;
    }
    path.canonicalize().ok()
}

#[cfg(target_os = "windows")]
fn build_windows_dll_search_path(
    system_directory: &Path,
    runtime_directory: &Path,
    program_files: &Path,
    cuda_directories: &[PathBuf],
) -> Result<std::ffi::OsString, String> {
    let program_files = canonical_plain_windows_directory(program_files)
        .ok_or_else(|| "Windows Program Files is not a plain directory".to_owned())?;
    let mut directories = Vec::with_capacity(2 + cuda_directories.len());
    directories.push(
        canonical_plain_windows_directory(system_directory)
            .ok_or_else(|| "Windows system directory is not a plain directory".to_owned())?,
    );
    directories.push(
        canonical_plain_windows_directory(runtime_directory)
            .ok_or_else(|| "selected runtime directory is not a plain directory".to_owned())?,
    );
    for directory in cuda_directories {
        let canonical = canonical_plain_windows_directory(directory)
            .ok_or_else(|| "a selected CUDA DLL directory is not a plain directory".to_owned())?;
        if !canonical.starts_with(&program_files) {
            return Err("a selected CUDA DLL directory escapes Program Files".to_owned());
        }
        if !directories.iter().any(|known| {
            known
                .to_string_lossy()
                .eq_ignore_ascii_case(&canonical.to_string_lossy())
        }) {
            directories.push(canonical);
        }
    }
    let joined = std::env::join_paths(&directories).map_err(|_| {
        "a Windows DLL search directory contains an invalid PATH separator".to_owned()
    })?;
    use std::os::windows::ffi::OsStrExt;
    if joined.encode_wide().count() > 16_000 {
        return Err(
            "bounded Windows DLL search path exceeds its 16,000 character limit".to_owned(),
        );
    }
    Ok(joined)
}

#[cfg(target_os = "windows")]
struct WindowsComAllocation(*mut std::ffi::c_void);

#[cfg(target_os = "windows")]
impl Drop for WindowsComAllocation {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Com::CoTaskMemFree;
        // SAFETY: SHGetKnownFolderPath allocated this buffer with the COM task allocator.
        unsafe { CoTaskMemFree(self.0) };
    }
}

#[cfg(target_os = "windows")]
unsafe fn windows_wide_path_length(value: *const u16) -> usize {
    if value.is_null() {
        return 0;
    }
    let mut length = 0_usize;
    while length < 32_768 && unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    length
}

#[cfg(target_os = "windows")]
fn create_private_windows_file(path: &Path) -> Result<std::fs::File, String> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let security = WindowsCurrentUserSecurity::new()?;
    let attributes = security.attributes();
    let path_wide = windows_wide_path(path.as_os_str());
    // SAFETY: pointers refer to a valid path and a live security descriptor.
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "could not create an exclusive private Windows model file: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: this is a newly-created file handle with exclusive ownership.
    Ok(unsafe { std::fs::File::from_raw_handle(handle.cast()) })
}

#[cfg(target_os = "windows")]
fn windows_wide_path(value: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
struct WindowsCurrentUserSecurity {
    descriptor: *mut std::ffi::c_void,
}

#[cfg(target_os = "windows")]
impl WindowsCurrentUserSecurity {
    fn new() -> Result<Self, String> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{
            GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle and token is writable.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(format!(
                "could not open the current user's token: {}",
                io::Error::last_os_error()
            ));
        }
        let token_guard = WindowsHandle(token);
        let mut needed = 0_u32;
        // SAFETY: the null buffer with zero length is the documented size query.
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        }
        if needed == 0 || needed as usize > 64 * 1024 {
            return Err("could not determine the current user's token size".to_owned());
        }
        let word_count = (needed as usize).div_ceil(std::mem::size_of::<usize>());
        let mut token_buffer = vec![0_usize; word_count];
        // SAFETY: token_buffer is large enough and aligned for TOKEN_USER.
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                token_buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(format!(
                "could not read the current user's token: {}",
                io::Error::last_os_error()
            ));
        }
        let token_user = token_buffer.as_ptr().cast::<TOKEN_USER>();
        let mut sid_string = std::ptr::null_mut();
        // SAFETY: TOKEN_USER came from GetTokenInformation and contains a valid SID pointer.
        if unsafe { ConvertSidToStringSidW((*token_user).User.Sid, &mut sid_string) } == 0 {
            return Err(format!(
                "could not encode the current user's SID: {}",
                io::Error::last_os_error()
            ));
        }
        let sid_string_guard = WindowsLocalAllocation(sid_string.cast());
        let sid_length = unsafe { windows_wide_length(sid_string) };
        if sid_length == 0 || sid_length > 256 {
            return Err("the current user's SID string is empty or oversized".to_owned());
        }
        // SAFETY: the SID string is NUL-terminated and bounded above.
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_string, sid_length) })
            .map_err(|_| "the current user's SID was not valid UTF-16".to_owned())?;
        let sddl = format!("D:P(A;;FA;;;{sid})");
        let sddl_wide = sddl
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: SDDL is valid NUL-terminated UTF-16 and descriptor is writable.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(format!(
                "could not create current-user-only model workspace permissions: {}",
                io::Error::last_os_error()
            ));
        }
        drop(sid_string_guard);
        drop(token_guard);
        Ok(Self { descriptor })
    }

    fn attributes(&self) -> windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: self.descriptor,
            bInheritHandle: 0,
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsCurrentUserSecurity {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;
        // SAFETY: descriptor came from ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            LocalFree(self.descriptor);
        }
    }
}

#[cfg(target_os = "windows")]
struct WindowsHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(target_os = "windows")]
impl Drop for WindowsHandle {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        // SAFETY: this wrapper owns the handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[cfg(target_os = "windows")]
struct WindowsLocalAllocation(windows_sys::Win32::Foundation::HLOCAL);

#[cfg(target_os = "windows")]
impl Drop for WindowsLocalAllocation {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;
        // SAFETY: pointer came from ConvertSidToStringSidW.
        unsafe {
            LocalFree(self.0);
        }
    }
}

#[cfg(target_os = "windows")]
unsafe fn windows_wide_length(value: *const u16) -> usize {
    if value.is_null() {
        return 0;
    }
    let mut length = 0_usize;
    while length < 256 && unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    length
}

#[cfg(target_os = "windows")]
struct WindowsJob(WindowsHandle);

#[cfg(target_os = "windows")]
impl WindowsJob {
    fn new(process_memory_limit_bytes: u64, timeout: std::time::Duration) -> Result<Self, String> {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_PROCESS_TIME,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let process_memory_limit = usize::try_from(process_memory_limit_bytes)
            .map_err(|_| "requested process-memory limit is not representable".to_owned())?;
        let timeout_100ns = i64::try_from(timeout.as_nanos() / 100)
            .map_err(|_| "requested runtime timeout is not representable".to_owned())?;
        // SAFETY: null attributes/name request a new unnamed job with default non-inheritable security.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "could not create the local runtime Job Object: {}",
                io::Error::last_os_error()
            ));
        }
        let job = Self(WindowsHandle(handle));
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_PROCESS_TIME;
        information.BasicLimitInformation.ActiveProcessLimit = 1;
        information.BasicLimitInformation.PerProcessUserTimeLimit = timeout_100ns;
        information.ProcessMemoryLimit = process_memory_limit;
        // SAFETY: information is a fully initialized extended limit structure.
        if unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&information as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            let error = unsafe { GetLastError() };
            // SAFETY: handle was created above and remains owned by this scope.
            unsafe {
                CloseHandle(handle);
            }
            std::mem::forget(job);
            return Err(format!(
                "could not set local runtime Job Object limits (Win32 error {error})"
            ));
        }
        Ok(job)
    }

    fn assign(&self, child: &std::process::Child) -> Result<(), String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        // SAFETY: Child's raw handle is valid for the lifetime of child and the job handle is live.
        if unsafe { AssignProcessToJobObject(self.0.0, child.as_raw_handle().cast()) } == 0 {
            return Err(format!(
                "could not assign the suspended local runtime to its Job Object: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn terminate(&self) {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        // SAFETY: the handle is a live Job Object owned by self.
        unsafe {
            TerminateJobObject(self.0.0, 1);
        }
    }
}

#[cfg(target_os = "windows")]
fn resume_suspended_process(process_id: u32) -> Result<(), String> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    // SAFETY: thread enumeration flags are valid and use the current process snapshot.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
        return Err(format!(
            "could not locate the suspended local runtime thread: {}",
            io::Error::last_os_error()
        ));
    }
    let snapshot_guard = WindowsHandle(snapshot);
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    // SAFETY: entry has its documented size and is writable.
    if unsafe { Thread32First(snapshot, &mut entry) } == 0 {
        return Err(format!(
            "could not enumerate the suspended local runtime thread: {}",
            io::Error::last_os_error()
        ));
    }
    loop {
        if entry.th32OwnerProcessID == process_id {
            // SAFETY: thread ID was obtained from a live system thread snapshot.
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if thread.is_null() {
                return Err(format!(
                    "could not open the suspended local runtime thread: {}",
                    io::Error::last_os_error()
                ));
            }
            let thread_guard = WindowsHandle(thread);
            // SAFETY: thread_guard refers to the suspended primary thread we just opened.
            let previous_suspend_count = unsafe { ResumeThread(thread) };
            if previous_suspend_count != 1 {
                return Err(if previous_suspend_count == u32::MAX {
                    format!(
                        "could not resume the suspended local runtime thread: {}",
                        io::Error::last_os_error()
                    )
                } else {
                    "local runtime thread did not have the expected suspended state".to_owned()
                });
            }
            drop(thread_guard);
            drop(snapshot_guard);
            return Ok(());
        }
        // SAFETY: entry remains a valid output structure for enumeration.
        if unsafe { Thread32Next(snapshot, &mut entry) } == 0 {
            break;
        }
    }
    Err("could not find a thread belonging to the suspended local runtime".to_owned())
}

#[cfg(target_os = "windows")]
fn drain_windows_pipe<R: Read>(
    mut reader: R,
    limit: usize,
    overflow: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> io::Result<BoundedPipe> {
    let mut pipe = BoundedPipe {
        bytes: Vec::new(),
        truncated: false,
    };
    let mut buffer = [0_u8; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(pipe),
            Ok(read) => {
                let remaining = limit.saturating_sub(pipe.bytes.len());
                let retained = read.min(remaining);
                if retained > 0 {
                    pipe.bytes
                        .try_reserve(retained)
                        .map_err(|_| io::Error::other("bounded output allocation failed"))?;
                    pipe.bytes.extend_from_slice(&buffer[..retained]);
                }
                if retained < read {
                    pipe.truncated = true;
                    overflow.store(true, std::sync::atomic::Ordering::Release);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "windows")]
fn join_pipe_reader(
    reader: std::thread::JoinHandle<io::Result<BoundedPipe>>,
) -> Result<BoundedPipe, String> {
    reader
        .join()
        .map_err(|_| "local runtime output reader panicked".to_owned())?
        .map_err(|error| format!("could not read bounded local runtime output: {error}"))
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::{
        build_windows_dll_search_path, copy_verified_model_windows,
        create_private_temp_dir_windows, discover_cuda_dll_directories,
        parse_cuda_version_directory, run_bounded_windows, validated_child_directory,
        write_private_file_windows,
    };
    use std::ffi::OsString;
    use std::path::Path;
    use std::time::Duration;

    #[test]
    fn private_workspace_guard_removes_only_its_workspace() {
        let guard = create_private_temp_dir_windows().expect("create private workspace");
        let path = guard.path().to_path_buf();
        let source = path.join("source.bin");
        let staged = path.join("staged.bin");
        write_private_file_windows(&source, b"abc").expect("write source fixture");
        assert!(write_private_file_windows(&source, b"replace").is_err());
        copy_verified_model_windows(
            &source,
            &staged,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            3,
        )
        .expect("copy and verify fixture");
        assert_eq!(std::fs::read(&staged).expect("read staged fixture"), b"abc");
        drop(guard);
        assert!(!path.exists());
    }

    #[test]
    fn verified_copy_removes_partial_destination_on_hash_mismatch() {
        let guard = create_private_temp_dir_windows().expect("create private workspace");
        let path = guard.path().to_path_buf();
        let source = path.join("source.bin");
        let staged = path.join("staged.bin");
        write_private_file_windows(&source, b"abc").expect("write source fixture");
        assert!(copy_verified_model_windows(&source, &staged, &"0".repeat(64), 3).is_err());
        assert!(!staged.exists());
        drop(guard);
    }

    #[test]
    fn bounded_runner_executes_direct_argv_and_returns_capped_output() {
        let current_test_executable = std::env::current_exe().expect("locate test executable");
        let arguments = [OsString::from("--list")];
        let output = run_bounded_windows(
            &current_test_executable,
            &arguments,
            None,
            Duration::from_secs(10),
            16 * 1024,
            1024 * 1024 * 1024,
        )
        .expect("run bounded child process");
        assert!(output.status.success());
        assert!(!output.stdout.truncated);
        assert!(!output.stderr.truncated);
        assert!(!output.stdout.bytes.is_empty());
        assert!(output.containment_note.contains("not limited or denied"));
    }

    #[test]
    fn cuda_search_discovery_accepts_only_versioned_program_files_bin_x64() {
        let guard = create_private_temp_dir_windows().expect("create private fixture root");
        let root = guard.path().to_path_buf();
        let cuda_root = root.join("NVIDIA GPU Computing Toolkit").join("CUDA");
        let expected = cuda_root.join("v12.8").join("bin").join("x64");
        let standard_bin = cuda_root.join("v12.8").join("bin");
        let older = cuda_root.join("v11.7").join("bin").join("x64");
        let invalid = cuda_root.join("v12.bad").join("bin").join("x64");
        std::fs::create_dir_all(&expected).expect("create current toolkit fixture");
        std::fs::create_dir_all(&older).expect("create older toolkit fixture");
        std::fs::create_dir_all(&invalid).expect("create invalid toolkit fixture");
        let selected = discover_cuda_dll_directories(&root).expect("discover toolkit dirs");
        assert_eq!(selected.len(), 4);
        assert!(selected[0].ends_with(Path::new("v12.8\\bin\\x64")));
        assert!(selected[1].ends_with(Path::new("v12.8\\bin")));
        assert!(selected[2].ends_with(Path::new("v11.7\\bin\\x64")));
        assert!(selected[3].ends_with(Path::new("v11.7\\bin")));
        assert!(
            !selected
                .iter()
                .any(|path| path.ends_with("v12.bad\\bin\\x64"))
        );
        assert!(standard_bin.is_dir());
        drop(guard);
    }

    #[test]
    fn cuda_search_rejects_malformed_versions_and_directories_outside_root() {
        assert_eq!(
            parse_cuda_version_directory(std::ffi::OsStr::new("v12.8")),
            Some(vec![12, 8])
        );
        assert_eq!(
            parse_cuda_version_directory(std::ffi::OsStr::new("v12.8.1")),
            Some(vec![12, 8, 1])
        );
        for invalid in ["12.8", "v12..8", "v12.8;evil", "v9999.8", "v1.2.3.4.5"] {
            assert!(parse_cuda_version_directory(std::ffi::OsStr::new(invalid)).is_none());
        }
        let guard = create_private_temp_dir_windows().expect("create private fixture root");
        let root = guard.path().to_path_buf();
        let outside = root.with_extension("outside");
        std::fs::create_dir(&outside).expect("create outside fixture");
        assert_eq!(validated_child_directory(&root, &outside).unwrap(), None);
        let system = root.join("system32");
        let runtime = root.join("runtime");
        let cuda = root.join("NVIDIA GPU Computing Toolkit").join("CUDA");
        let cuda_bin = cuda.join("v12.8").join("bin").join("x64");
        std::fs::create_dir(&system).expect("create system path fixture");
        std::fs::create_dir(&runtime).expect("create runtime path fixture");
        std::fs::create_dir_all(&cuda_bin).expect("create CUDA path fixture");
        let path = build_windows_dll_search_path(
            &system,
            &runtime,
            &root,
            std::slice::from_ref(&cuda_bin),
        )
        .expect("build validated DLL search path");
        let path = path.to_string_lossy();
        assert!(path.contains(&system.to_string_lossy().to_string()));
        assert!(path.contains(&runtime.to_string_lossy().to_string()));
        assert!(path.contains(&cuda_bin.to_string_lossy().to_string()));
        assert!(
            build_windows_dll_search_path(&system, &runtime, &root, std::slice::from_ref(&outside))
                .is_err()
        );
        let _ = std::fs::remove_dir(&outside);
        drop(guard);
    }
}
