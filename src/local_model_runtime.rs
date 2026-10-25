//! Linux subprocess limits and private temporary storage for local inference.

#[cfg(target_os = "linux")]
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::{Command, ExitStatus, Stdio};

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
pub fn read_capped_pipe<R: Read>(mut reader: R, limit: usize) -> io::Result<BoundedPipe> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 4096];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        let retained = read.min(remaining);
        if retained > 0 {
            bytes
                .try_reserve(retained)
                .map_err(|_| io::Error::other("bounded output allocation failed"))?;
            bytes.extend_from_slice(&buffer[..retained]);
        }
        truncated |= retained < read;
    }
    Ok(BoundedPipe { bytes, truncated })
}

#[cfg(target_os = "linux")]
pub fn run_bounded(
    program: &Path,
    arguments: &[std::ffi::OsString],
    working_directory: Option<&Path>,
    timeout_seconds: u64,
    output_limit: usize,
) -> Result<BoundedCommandOutput, String> {
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
    set_child_limits(&mut command)?;
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start the selected local runtime: {error}"))?;
    let stdout = child.stdout.take().expect("piped runtime stdout");
    let stderr = child.stderr.take().expect("piped runtime stderr");
    let stdout_reader = std::thread::spawn(move || read_capped_pipe(stdout, output_limit));
    let stderr_reader = std::thread::spawn(move || read_capped_pipe(stderr, 16 * 1024));
    let status = wait_for_child(&mut child, timeout_seconds)?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| "local runtime stdout reader stopped unexpectedly".to_owned())?
        .map_err(|error| format!("could not read local runtime output: {error}"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "local runtime stderr reader stopped unexpectedly".to_owned())?
        .map_err(|error| format!("could not read local runtime diagnostics: {error}"))?;
    Ok(BoundedCommandOutput {
        status,
        stdout,
        stderr,
    })
}

#[cfg(target_os = "linux")]
pub fn set_child_limits(command: &mut Command) -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    // This is defense in depth for the pinned local runtime, not a sandbox.
    // The runtime inherits these limits and a seccomp filter that denies network
    // sockets, io_uring, privilege changes, and unneeded persistence channels.
    unsafe {
        command.process_group(0);
        command.pre_exec(|| {
            let limits = [
                (libc::RLIMIT_CPU, 120 as libc::rlim_t),
                (
                    libc::RLIMIT_AS,
                    (2_u64 * 1024 * 1024 * 1024) as libc::rlim_t,
                ),
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
fn wait_for_child(
    child: &mut std::process::Child,
    timeout_seconds: u64,
) -> Result<ExitStatus, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_seconds);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("could not wait for local runtime: {error}"))?
        {
            return Ok(status);
        }
        if std::time::Instant::now() >= deadline {
            // The selected runtime is expected to be the pinned direct CLI. Kill
            // its process group too so an unexpected child cannot hold pipes open.
            unsafe {
                libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "local runtime exceeded the {timeout_seconds} second time limit"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
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
    use super::run_bounded;
    use std::ffi::OsString;
    use std::path::Path;

    #[test]
    fn seccomp_denies_inet_and_unix_socket_creation() {
        let python = Path::new("/usr/bin/python3");
        assert!(
            python.is_file(),
            "Linux CI installs python3 for runtime checks"
        );
        let script = "import socket\nfor family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):\n try:\n  socket.socket(family, socket.SOCK_STREAM)\n except PermissionError:\n  continue\n else:\n  raise SystemExit(17)\nprint('blocked')";
        let arguments = [OsString::from("-c"), OsString::from(script)];
        let output = run_bounded(python, &arguments, None, 10, 1024).unwrap();
        assert!(output.status.success());
        assert!(!output.stdout.truncated);
        assert_eq!(output.stdout.bytes, b"blocked\n");
    }
}
