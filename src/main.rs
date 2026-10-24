use std::env;
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use serde::Serialize;
use sideeffect::diff::compare_traces;
use sideeffect::format::write_text_diff;
use sideeffect::limits::{MAX_JSON_BYTES, MAX_TRACE_BYTES, ParseLimits};
use sideeffect::model::{ParseCompleteness, TraceDiff};
use sideeffect::trace::strace::parse_trace_bytes;

const USAGE: &str = "Usage: sideeffect inspect <strace-trace-file>\n       sideeffect diff [--format json|text] <baseline-trace> <candidate-trace>\n       sideeffect --help\n       sideeffect --version\n\nInspect reads one bounded strace text file and writes JSON evidence to stdout. Diff compares two complete parsed traces and writes observed syscall-row differences to stdout (JSON by default). Neither command executes the represented command.";

fn main() -> ExitCode {
    match run(env::args_os().skip(1).collect()) {
        Ok(code) => code,
        Err(message) => {
            let _ = writeln!(io::stderr().lock(), "sideeffect: {message}");
            ExitCode::from(1)
        }
    }
}

fn run(arguments: Vec<OsString>) -> Result<ExitCode, String> {
    match arguments.as_slice() {
        [flag] if flag == "--help" || flag == "-h" => {
            println!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        [flag] if flag == "--version" => {
            println!("sideeffect {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        [command, path] if command == "inspect" => inspect(path),
        [command, left, right] if command == "diff" => diff(left, right),
        [command, flag, format, left, right] if command == "diff" && flag == "--format" => {
            diff_with_format(format, left, right)
        }
        _ => Err(USAGE.to_owned()),
    }
}

fn inspect(path: &OsString) -> Result<ExitCode, String> {
    let document = read_and_parse(path)?;
    let partial = document.parse_status == ParseCompleteness::Partial;
    write_json(&document, "JSON evidence document")?;

    if partial {
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn diff(left_path: &OsString, right_path: &OsString) -> Result<ExitCode, String> {
    diff_with_output_format(left_path, right_path, DiffOutputFormat::Json)
}

fn diff_with_format(
    format: &OsString,
    left_path: &OsString,
    right_path: &OsString,
) -> Result<ExitCode, String> {
    let output_format = match format.to_str() {
        Some("json") => DiffOutputFormat::Json,
        Some("text") => DiffOutputFormat::Text,
        _ => return Err("diff format must be either 'json' or 'text'".to_owned()),
    };
    diff_with_output_format(left_path, right_path, output_format)
}

#[derive(Clone, Copy)]
enum DiffOutputFormat {
    Json,
    Text,
}

fn diff_with_output_format(
    left_path: &OsString,
    right_path: &OsString,
    output_format: DiffOutputFormat,
) -> Result<ExitCode, String> {
    let left = read_and_parse(left_path)?;
    let right = read_and_parse(right_path)?;
    let result = compare_traces(&left, &right)
        .map_err(|error| format!("could not compare traces: {error}"))?;
    match output_format {
        DiffOutputFormat::Json => write_json(&result, "JSON comparison document")?,
        DiffOutputFormat::Text => write_text(&result)?,
    }
    Ok(ExitCode::SUCCESS)
}

fn read_and_parse(path: &OsString) -> Result<sideeffect::model::TraceDocument, String> {
    let bytes = read_bounded(path)?;
    parse_trace_bytes(&bytes, ParseLimits::default())
        .map_err(|error| format!("trace inspection failed: {error}"))
}

fn write_json<T: Serialize>(value: &T, description: &str) -> Result<(), String> {
    let mut json = CappedBuffer::new(MAX_JSON_BYTES);
    serde_json::to_writer_pretty(&mut json, value).map_err(|error| {
        if json.exceeded {
            format!(
                "{description} exceeds the {} byte output limit",
                MAX_JSON_BYTES
            )
        } else {
            format!("could not serialize {description}: {error}")
        }
    })?;
    json.write_all(b"\n").map_err(|_| {
        format!(
            "{description} exceeds the {} byte output limit",
            MAX_JSON_BYTES
        )
    })?;

    write_buffer(&json, description)
}

fn write_text(diff: &TraceDiff<'_>) -> Result<(), String> {
    let mut text = CappedBuffer::new(MAX_JSON_BYTES);
    write_text_diff(diff, &mut text).map_err(|error| {
        if text.exceeded {
            format!("text comparison exceeds the {MAX_JSON_BYTES} byte output limit")
        } else {
            format!("could not render text comparison: {error}")
        }
    })?;
    text.write_all(b"\n")
        .map_err(|_| format!("text comparison exceeds the {MAX_JSON_BYTES} byte output limit"))?;
    write_buffer(&text, "text comparison")
}

fn write_buffer(buffer: &CappedBuffer, description: &str) -> Result<(), String> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&buffer.bytes)
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("could not write {description} to stdout: {error}"))
}

fn read_bounded(path: &OsString) -> Result<Vec<u8>, String> {
    read_trace_file(Path::new(path), MAX_TRACE_BYTES)
}

fn read_trace_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("could not inspect trace input: {error}"))?;
    if !metadata.is_file() {
        return Err(
            "trace input must be a regular file; pipes and devices are not accepted".to_owned(),
        );
    }
    let length = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if length > limit {
        return Err(format!("trace input exceeds the {limit} byte limit"));
    }
    let file =
        open_trace_file(path).map_err(|error| format!("could not open trace input: {error}"))?;
    if !file
        .metadata()
        .map_err(|error| format!("could not inspect opened trace input: {error}"))?
        .is_file()
    {
        return Err("opened trace input is not a regular file".to_owned());
    }
    read_limited(file, limit)
}

#[cfg(target_os = "linux")]
fn open_trace_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_trace_file(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn read_limited<R: Read>(reader: R, limit: usize) -> Result<Vec<u8>, String> {
    let max_plus_one = u64::try_from(limit)
        .map_err(|_| "configured trace byte limit exceeds u64".to_owned())?
        .saturating_add(1);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(limit.min(8 * 1024))
        .map_err(|_| "could not allocate the bounded trace input buffer".to_owned())?;
    reader
        .take(max_plus_one)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read trace input: {error}"))?;
    if bytes.len() > limit {
        return Err(format!("trace input exceeds the {limit} byte limit"));
    }
    Ok(bytes)
}

struct CappedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl CappedBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl Write for CappedBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let new_len = self.bytes.len().checked_add(buffer.len()).ok_or_else(|| {
            self.exceeded = true;
            io::Error::other("output size overflow")
        })?;
        if new_len > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("output limit exceeded"));
        }
        self.bytes
            .try_reserve(buffer.len())
            .map_err(|_| io::Error::other("could not allocate bounded JSON output"))?;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CappedBuffer, read_limited, read_trace_file};
    use std::fs::{self, OpenOptions};
    use std::io::{self, Cursor, Write};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    struct TempTrace(PathBuf);

    impl TempTrace {
        fn with_contents(contents: &[u8]) -> Self {
            loop {
                let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("sideeffect-test-{}-{id}.trace", std::process::id()));
                match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(mut file) => {
                        file.write_all(contents).unwrap();
                        return Self(path);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create test trace: {error}"),
                }
            }
        }
    }

    impl Drop for TempTrace {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn capped_buffer_accepts_exact_limit() {
        let mut buffer = CappedBuffer::new(3);
        buffer.write_all(b"abc").unwrap();
        assert_eq!(buffer.bytes, b"abc");
        assert!(!buffer.exceeded);
    }

    #[test]
    fn capped_buffer_rejects_limit_plus_one_without_appending() {
        let mut buffer = CappedBuffer::new(3);
        buffer.write_all(b"abc").unwrap();
        assert!(buffer.write_all(b"d").is_err());
        assert_eq!(buffer.bytes, b"abc");
        assert!(buffer.exceeded);
    }

    #[test]
    fn bounded_reader_accepts_exact_limit() {
        let bytes = read_limited(Cursor::new(b"abcd"), 4).unwrap();
        assert_eq!(bytes, b"abcd");
    }

    #[test]
    fn bounded_reader_rejects_limit_plus_one() {
        let error = read_limited(Cursor::new(b"abcde"), 4).unwrap_err();
        assert!(error.contains("limit"));
    }

    #[test]
    fn production_path_reader_accepts_exact_file_limit() {
        let trace = TempTrace::with_contents(b"abcd");
        assert_eq!(read_trace_file(&trace.0, 4).unwrap(), b"abcd");
    }

    #[test]
    fn production_path_reader_rejects_file_limit_plus_one() {
        let trace = TempTrace::with_contents(b"abcde");
        assert!(read_trace_file(&trace.0, 4).unwrap_err().contains("limit"));
    }

    #[test]
    fn production_path_reader_rejects_non_regular_input() {
        let error = read_trace_file(&std::env::temp_dir(), 4).unwrap_err();
        assert!(error.contains("regular file"));
    }
}
