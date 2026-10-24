use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::Command;

/// Build the fixed `strace` invocation used for one bounded trace capture.
///
/// `fifo_path` must be an absolute path generated inside SideEffect's private
/// capture directory. Arguments are appended as distinct OS strings; this
/// function never invokes a shell or rewrites the target command's argv.
pub fn build_strace_command(fifo_path: &Path, program: &OsStr, args: &[OsString]) -> Command {
    build_strace_command_for(OsStr::new("strace"), fifo_path, program, args)
}

pub fn build_strace_command_for(
    tracer: &OsStr,
    fifo_path: &Path,
    program: &OsStr,
    args: &[OsString],
) -> Command {
    debug_assert!(fifo_path.is_absolute(), "strace FIFO path must be absolute");

    let mut command = Command::new(tracer);
    command
        .arg("-f")
        .arg("-ttt")
        .arg("-yy")
        .arg("-s")
        .arg("256")
        .arg("-e")
        .arg("trace=%process,%file,%network")
        .arg("--kill-on-exit")
        .arg("-o")
        .arg(fifo_path.as_os_str())
        .arg("--")
        .arg(program)
        .args(args);
    command
}

#[cfg(test)]
mod tests {
    use super::build_strace_command;
    use std::ffi::{OsStr, OsString};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn absolute_fifo_path() -> PathBuf {
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\sideeffect-private\capture fifo")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/tmp/sideeffect-private/capture fifo")
        }
    }

    fn argv(command: &Command) -> Vec<OsString> {
        command.get_args().map(OsString::from).collect()
    }

    #[test]
    fn emits_exact_fixed_options_in_required_order() {
        let fifo = absolute_fifo_path();
        let command = build_strace_command(&fifo, OsStr::new("/usr/bin/example"), &[]);

        assert_eq!(command.get_program(), OsStr::new("strace"));
        assert_eq!(
            argv(&command),
            vec![
                "-f",
                "-ttt",
                "-yy",
                "-s",
                "256",
                "-e",
                "trace=%process,%file,%network",
                "--kill-on-exit",
                "-o",
            ]
            .into_iter()
            .map(OsString::from)
            .chain([
                fifo.into_os_string(),
                OsString::from("--"),
                OsString::from("/usr/bin/example")
            ])
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn separator_keeps_leading_dash_program_out_of_strace_options() {
        let fifo = absolute_fifo_path();
        let command = build_strace_command(&fifo, OsStr::new("-target"), &[]);
        let args = argv(&command);
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(args[separator + 1], "-target");
    }

    #[test]
    fn spaces_and_shell_metacharacters_remain_individual_literal_arguments() {
        let fifo = absolute_fifo_path();
        let program = OsString::from("/tmp/program with spaces");
        let target_args = vec![
            OsString::from("two words stay together"),
            OsString::from("; touch /tmp/should-not-exist"),
            OsString::from("$(not-a-shell) && `literal` \"quoted\""),
        ];
        let command = build_strace_command(&fifo, &program, &target_args);
        let argv = argv(&command);
        let separator = argv.iter().position(|arg| arg == "--").unwrap();

        assert_eq!(argv[separator + 1], program);
        assert_eq!(&argv[separator + 2..], target_args.as_slice());
        assert_eq!(
            argv[argv.iter().position(|arg| arg == "-o").unwrap() + 1],
            fifo.as_os_str()
        );
        assert_eq!(
            Path::new(&argv[argv.iter().position(|arg| arg == "-o").unwrap() + 1]),
            fifo
        );
    }
}
