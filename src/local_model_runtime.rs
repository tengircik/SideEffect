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
