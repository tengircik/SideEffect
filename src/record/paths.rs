use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const FIFO_NAME: &[u8] = b"trace.fifo";
const TRACE_NAME: &[u8] = b"trace.raw";
const REPORT_NAME: &[u8] = b"report.html";
const STAGE_PREFIX: &[u8] = b".sideeffect-capture-";
static NEXT_STAGE_ID: AtomicU64 = AtomicU64::new(0);

/// Holds directory descriptors for race-resistant private staging and no-clobber publication.
///
/// All temporary entries are addressed relative to the held staging directory descriptor. The
/// output parent is likewise held open, so renaming the selected parent does not redirect capture
/// or publication into a different directory.
#[derive(Debug)]
pub struct AnchoredOutput {
    parent_dir: File,
    parent_path_at_prepare: PathBuf,
    destination_name: OsString,
    stage_dir: File,
    stage_name: OsString,
    stage_device: libc::dev_t,
    stage_inode: libc::ino_t,
    fifo_identity: Option<(libc::dev_t, libc::ino_t)>,
    trace_identity: Option<(libc::dev_t, libc::ino_t)>,
    report_identity: Option<(libc::dev_t, libc::ino_t)>,
    published: bool,
}

impl AnchoredOutput {
    /// Resolve and hold the destination parent, then create a private staging directory in it.
    pub fn prepare(destination: &Path) -> io::Result<Self> {
        let destination_name = destination
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "destination must name a file")
            })?
            .to_os_string();
        let parent_request = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent_path = fs::canonicalize(parent_request)?;
        let parent_dir = open_directory(&parent_path)?;
        ensure_destination_absent(parent_dir.as_raw_fd(), &destination_name)?;

        let (stage_name, stage_dir, stage_stat) = create_stage_directory(&parent_dir)?;

        Ok(Self {
            parent_dir,
            parent_path_at_prepare: parent_path,
            destination_name,
            stage_dir,
            stage_name,
            stage_device: stage_stat.st_dev,
            stage_inode: stage_stat.st_ino,
            fifo_identity: None,
            trace_identity: None,
            report_identity: None,
            published: false,
        })
    }

    /// Return a child-visible path pinned through this process's held stage directory descriptor.
    pub fn fifo_path_for_child(&self) -> OsString {
        let mut path = format!(
            "/proc/{}/fd/{}/",
            std::process::id(),
            self.stage_dir.as_raw_fd()
        )
        .into_bytes();
        path.extend_from_slice(FIFO_NAME);
        OsString::from_vec(path)
    }

    /// Create the FIFO at a fixed name relative to the held staging directory descriptor.
    pub fn create_fifo(&mut self) -> io::Result<()> {
        let name = c_name(FIFO_NAME)?;
        // SAFETY: stage_dir is an open directory; name is a fixed NUL-terminated relative name.
        if unsafe { libc::mkfifoat(self.stage_dir.as_raw_fd(), name.as_ptr(), 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = stat_named_entry(self.stage_dir.as_raw_fd(), FIFO_NAME)?;
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFIFO {
            return Err(io::Error::other("created trace FIFO was replaced"));
        }
        self.fifo_identity = Some((stat.st_dev, stat.st_ino));
        Ok(())
    }

    /// Create a new private regular trace file relative to the held staging directory descriptor.
    pub fn create_trace_file(&mut self) -> io::Result<File> {
        let name = c_name(TRACE_NAME)?;
        // SAFETY: stage_dir is an open directory; name is fixed and flags prevent following or
        // replacing an existing entry. The returned descriptor is owned by `from_raw_fd`.
        let fd = unsafe {
            libc::openat(
                self.stage_dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        let stat = stat_fd(file.as_raw_fd())?;
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(io::Error::other(
                "created trace staging entry is not a regular file",
            ));
        }
        self.trace_identity = Some((stat.st_dev, stat.st_ino));
        Ok(file)
    }

    /// Publish the staged trace as a new destination entry without replacing anything.
    pub fn publish_trace(&mut self) -> io::Result<PathBuf> {
        if self.trace_identity.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "trace staging file has not been created",
            ));
        }
        if self.published {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "trace has already been published",
            ));
        }

        let source = c_name(TRACE_NAME)?;
        let destination = c_name(self.destination_name.as_os_str().as_bytes())?;
        // SAFETY: both dirfds are held open directories; names are NUL-terminated single
        // components; linkat without AT_SYMLINK_FOLLOW does not follow a source symlink.
        if unsafe {
            libc::linkat(
                self.stage_dir.as_raw_fd(),
                source.as_ptr(),
                self.parent_dir.as_raw_fd(),
                destination.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        self.published = true;

        let current_parent = read_fd_path(self.parent_dir.as_raw_fd())
            .unwrap_or_else(|_| self.parent_path_at_prepare.clone());
        Ok(current_parent.join(&self.destination_name))
    }

    /// Create a new private HTML report staging file relative to the held directory descriptor.
    pub fn create_report_file(&mut self) -> io::Result<File> {
        let file = self.create_private_staged_file(REPORT_NAME)?;
        let stat = stat_fd(file.as_raw_fd())?;
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(io::Error::other(
                "created HTML report staging entry is not a regular file",
            ));
        }
        self.report_identity = Some((stat.st_dev, stat.st_ino));
        Ok(file)
    }

    /// Publish the staged report without replacing an existing destination.
    pub fn publish_report(&mut self) -> io::Result<PathBuf> {
        if self.report_identity.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTML report staging file has not been created",
            ));
        }
        if self.published {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "output has already been published",
            ));
        }
        let source = c_name(REPORT_NAME)?;
        let destination = c_name(self.destination_name.as_os_str().as_bytes())?;
        // SAFETY: both dirfds are held open; names are NUL-terminated single components.
        if unsafe {
            libc::linkat(
                self.stage_dir.as_raw_fd(),
                source.as_ptr(),
                self.parent_dir.as_raw_fd(),
                destination.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        self.published = true;
        let current_parent = read_fd_path(self.parent_dir.as_raw_fd())
            .unwrap_or_else(|_| self.parent_path_at_prepare.clone());
        Ok(current_parent.join(&self.destination_name))
    }

    fn create_private_staged_file(&self, filename: &[u8]) -> io::Result<File> {
        let name = c_name(filename)?;
        // SAFETY: stage_dir is a held directory; flags reject symlinks and existing entries.
        let fd = unsafe {
            libc::openat(
                self.stage_dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    #[cfg(test)]
    fn stage_path_for_test(&self) -> PathBuf {
        self.parent_path_at_prepare.join(&self.stage_name)
    }
}

impl Drop for AnchoredOutput {
    fn drop(&mut self) {
        if let Some((device, inode)) = self.fifo_identity {
            let fifo = c_name(FIFO_NAME).expect("fixed FIFO name contains no NUL");
            if named_entry_matches(self.stage_dir.as_raw_fd(), FIFO_NAME, device, inode) {
                // SAFETY: fixed name is relative to the held stage dirfd; unlink removes the
                // entry itself and never follows a replacement symlink.
                unsafe {
                    libc::unlinkat(self.stage_dir.as_raw_fd(), fifo.as_ptr(), 0);
                }
            }
        }
        if let Some((device, inode)) = self.trace_identity {
            let trace = c_name(TRACE_NAME).expect("fixed trace name contains no NUL");
            if named_entry_matches(self.stage_dir.as_raw_fd(), TRACE_NAME, device, inode) {
                // SAFETY: fixed name is relative to the held stage dirfd; unlink removes the
                // entry itself and never follows a replacement symlink.
                unsafe {
                    libc::unlinkat(self.stage_dir.as_raw_fd(), trace.as_ptr(), 0);
                }
            }
        }
        if let Some((device, inode)) = self.report_identity {
            let report = c_name(REPORT_NAME).expect("fixed report name contains no NUL");
            if named_entry_matches(self.stage_dir.as_raw_fd(), REPORT_NAME, device, inode) {
                // SAFETY: fixed name is relative to held stage dirfd; unlink doesn't follow it.
                unsafe {
                    libc::unlinkat(self.stage_dir.as_raw_fd(), report.as_ptr(), 0);
                }
            }
        }

        if verify_named_directory(
            self.parent_dir.as_raw_fd(),
            &self.stage_name,
            self.stage_device,
            self.stage_inode,
        )
        .is_ok()
        {
            let stage_name = match c_name(self.stage_name.as_os_str().as_bytes()) {
                Ok(name) => name,
                Err(_) => return,
            };
            // SAFETY: the entry was just checked to identify the held stage inode. This
            // removes only an empty directory and never recursively follows entries.
            unsafe {
                libc::unlinkat(
                    self.parent_dir.as_raw_fd(),
                    stage_name.as_ptr(),
                    libc::AT_REMOVEDIR,
                );
            }
        }
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

fn ensure_destination_absent(parent_fd: i32, destination_name: &OsStr) -> io::Result<()> {
    let name = c_name(destination_name.as_bytes())?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: stat is writable and name is one directory entry. Do not follow symlinks: a
    // dangling final symlink still occupies the requested destination name.
    let result = unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "trace destination already exists",
        ));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}

fn create_stage_directory(parent: &File) -> io::Result<(OsString, File, libc::stat)> {
    create_stage_directory_with_hook(parent, |_, _| {})
}

fn create_stage_directory_with_hook<F>(
    parent: &File,
    mut after_create: F,
) -> io::Result<(OsString, File, libc::stat)>
where
    F: FnMut(&File, &OsStr),
{
    for _ in 0..64 {
        let name = stage_name();
        let c_name = c_name(name.as_os_str().as_bytes())?;
        // SAFETY: parent is an open directory and c_name is a single relative component.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o700) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(error);
        }

        let created_stat = match stat_named_entry(parent.as_raw_fd(), name.as_os_str().as_bytes()) {
            Ok(stat) if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR => stat,
            Ok(_) => {
                return Err(io::Error::other(
                    "new staging name was replaced before it could be verified",
                ));
            }
            Err(error) => return Err(error),
        };
        after_create(parent, &name);

        // SAFETY: parent is an open directory; the just-created entry is opened without following
        // symlinks and with close-on-exec. O_PATH keeps the directory usable as a dirfd even under
        // a restrictive umask without granting read access to the staged contents.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            remove_directory_if_same(
                parent.as_raw_fd(),
                &name,
                created_stat.st_dev,
                created_stat.st_ino,
            );
            return Err(error);
        }
        // SAFETY: openat returned a new owned descriptor.
        let directory = unsafe { File::from_raw_fd(fd) };
        let stat = match stat_fd(directory.as_raw_fd()) {
            Ok(stat) => stat,
            Err(error) => {
                drop(directory);
                // The descriptor remains authoritative. Without a usable inode identity, leave
                // the empty private directory in place rather than risk removing a replacement.
                return Err(error);
            }
        };
        let validation = verify_opened_stage(parent.as_raw_fd(), &name, &stat, &created_stat);
        if let Err(error) = validation {
            drop(directory);
            remove_directory_if_same(
                parent.as_raw_fd(),
                &name,
                created_stat.st_dev,
                created_stat.st_ino,
            );
            return Err(error);
        }
        return Ok((name, directory, stat));
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique private staging directory",
    ))
}

fn verify_opened_stage(
    parent_fd: i32,
    name: &OsStr,
    opened: &libc::stat,
    created: &libc::stat,
) -> io::Result<()> {
    if (opened.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(io::Error::other("opened staging entry is not a directory"));
    }
    if opened.st_uid != unsafe { libc::geteuid() } {
        return Err(io::Error::other(
            "opened staging directory is not owned by the current user",
        ));
    }
    if (opened.st_mode & 0o077) != 0 {
        return Err(io::Error::other(
            "opened staging directory is accessible to group or other users",
        ));
    }
    if opened.st_dev != created.st_dev || opened.st_ino != created.st_ino {
        return Err(io::Error::other(
            "staging name changed between creation and opening",
        ));
    }
    verify_named_directory(parent_fd, name, opened.st_dev, opened.st_ino)
}

fn remove_directory_if_same(parent_fd: i32, name: &OsStr, device: libc::dev_t, inode: libc::ino_t) {
    if verify_named_directory(parent_fd, name, device, inode).is_ok()
        && let Ok(name) = c_name(name.as_bytes())
    {
        // SAFETY: the entry was checked against the held directory inode and removal is
        // restricted to an empty directory.
        unsafe {
            libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR);
        }
    }
}

fn stage_name() -> OsString {
    let mut bytes = STAGE_PREFIX.to_vec();
    let mut random = [0u8; 16];
    let mut filled = 0usize;
    while filled < random.len() {
        // SAFETY: random is writable for its full length and getrandom writes at most that length.
        let result = unsafe {
            libc::getrandom(
                random[filled..].as_mut_ptr().cast(),
                random.len() - filled,
                0,
            )
        };
        if result > 0 {
            filled += result as usize;
            continue;
        }
        if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        let fallback = NEXT_STAGE_ID.fetch_add(1, Ordering::Relaxed);
        bytes.extend_from_slice(std::process::id().to_string().as_bytes());
        bytes.push(b'-');
        bytes.extend_from_slice(fallback.to_string().as_bytes());
        return OsString::from_vec(bytes);
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in random {
        bytes.push(HEX[(byte >> 4) as usize]);
        bytes.push(HEX[(byte & 0x0f) as usize]);
    }
    OsString::from_vec(bytes)
}

fn verify_named_directory(
    parent_fd: i32,
    name: &OsStr,
    expected_device: libc::dev_t,
    expected_inode: libc::ino_t,
) -> io::Result<()> {
    let name = c_name(name.as_bytes())?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: stat is writable; name is a single relative component and AT_SYMLINK_NOFOLLOW
    // prevents following a replaced symbolic link.
    if unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if stat.st_dev != expected_device || stat.st_ino != expected_inode {
        return Err(io::Error::other(
            "staging path no longer identifies the held directory",
        ));
    }
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(io::Error::other("staging path is no longer a directory"));
    }
    Ok(())
}

fn stat_named_entry(dir_fd: i32, name: &[u8]) -> io::Result<libc::stat> {
    let name = c_name(name)?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: stat is writable and the fixed name is relative to a held directory descriptor.
    if unsafe { libc::fstatat(dir_fd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn named_entry_matches(dir_fd: i32, name: &[u8], device: libc::dev_t, inode: libc::ino_t) -> bool {
    stat_named_entry(dir_fd, name)
        .map(|stat| stat.st_dev == device && stat.st_ino == inode)
        .unwrap_or(false)
}

fn stat_fd(fd: i32) -> io::Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: stat is writable and fd is a held descriptor.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn read_fd_path(fd: i32) -> io::Result<PathBuf> {
    fs::read_link(format!("/proc/self/fd/{fd}"))
}

fn c_name(name: &[u8]) -> io::Result<CString> {
    CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
}

#[cfg(test)]
mod tests {
    use super::AnchoredOutput;
    use std::fs;
    use std::io::{self, Write};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            loop {
                let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("sideeffect-paths-test-{}-{id}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create test directory: {error}"),
                }
            }
        }

        fn prepare(&self, name: &str) -> AnchoredOutput {
            AnchoredOutput::prepare(&self.0.join(name)).expect("prepare anchored output")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_staged(output: &mut AnchoredOutput, contents: &[u8]) {
        let mut trace = output.create_trace_file().expect("create trace file");
        trace.write_all(contents).expect("write staged trace");
        trace.sync_all().expect("sync staged trace");
    }

    #[test]
    fn staging_and_entries_have_private_modes_and_are_cleaned() {
        let directory = TestDirectory::new();
        let mut output = directory.prepare("result.trace");
        let stage_path = output.stage_path_for_test();
        output.create_fifo().unwrap();
        let trace = output.create_trace_file().unwrap();
        let stage_mode = fs::metadata(&stage_path).unwrap().permissions().mode() & 0o777;
        let trace_mode = trace.metadata().unwrap().permissions().mode() & 0o777;
        let fifo_path = PathBuf::from(output.fifo_path_for_child());
        let fifo_mode = fs::metadata(&fifo_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(stage_mode & 0o077, 0);
        assert_eq!(trace_mode & 0o077, 0);
        assert_eq!(fifo_mode & 0o077, 0);
        drop(trace);
        drop(output);
        assert!(!stage_path.exists());
    }

    #[test]
    fn publication_refuses_existing_files_symlinks_and_races() {
        let directory = TestDirectory::new();
        let existing = directory.0.join("existing.trace");
        fs::write(&existing, b"keep file").unwrap();
        let error = AnchoredOutput::prepare(&existing).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&existing).unwrap(), b"keep file");

        let target = directory.0.join("target");
        fs::write(&target, b"keep target").unwrap();
        let symlink = directory.0.join("symlink.trace");
        std::os::unix::fs::symlink(&target, &symlink).unwrap();
        assert_eq!(
            AnchoredOutput::prepare(&symlink).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&target).unwrap(), b"keep target");
        assert!(
            fs::symlink_metadata(&symlink)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let raced = directory.0.join("raced.trace");
        let mut output = directory.prepare("raced.trace");
        write_staged(&mut output, b"staged");
        fs::write(&raced, b"concurrent writer").unwrap();
        assert_eq!(
            output.publish_trace().unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&raced).unwrap(), b"concurrent writer");
    }

    #[test]
    fn html_report_uses_private_staging_and_no_clobber_publication() {
        let directory = TestDirectory::new();
        let destination = directory.0.join("report.html");
        let mut output = directory.prepare("report.html");
        let mut report = output.create_report_file().unwrap();
        assert_eq!(report.metadata().unwrap().permissions().mode() & 0o077, 0);
        report.write_all(b"<!doctype html><p>safe</p>").unwrap();
        report.sync_all().unwrap();
        fs::write(&destination, b"concurrent writer").unwrap();
        assert_eq!(
            output.publish_report().unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&destination).unwrap(), b"concurrent writer");
        drop(report);
        drop(output);
    }

    #[test]
    fn parent_rename_does_not_redirect_fifo_or_publication() {
        let directory = TestDirectory::new();
        let original_parent = directory.0.join("parent");
        fs::create_dir(&original_parent).unwrap();
        let moved_parent = directory.0.join("renamed-parent");
        let mut output = AnchoredOutput::prepare(&original_parent.join("result.trace")).unwrap();
        output.create_fifo().unwrap();
        let fifo_path = PathBuf::from(output.fifo_path_for_child());
        assert!(fs::metadata(&fifo_path).unwrap().file_type().is_fifo());
        write_staged(&mut output, b"after rename");

        fs::rename(&original_parent, &moved_parent).unwrap();
        let published = output.publish_trace().unwrap();
        assert_eq!(published, moved_parent.join("result.trace"));
        assert_eq!(fs::read(published).unwrap(), b"after rename");
    }

    #[test]
    fn cleanup_never_removes_replacement_at_staging_name() {
        let directory = TestDirectory::new();
        let mut output = directory.prepare("result.trace");
        output.create_fifo().unwrap();
        write_staged(&mut output, b"private bytes");
        let stage_path = output.stage_path_for_test();
        let held_stage_path = directory.0.join("renamed-original-stage");
        fs::rename(&stage_path, &held_stage_path).unwrap();
        fs::create_dir(&stage_path).unwrap();
        let marker = stage_path.join("belongs-to-replacement");
        fs::write(&marker, b"preserve").unwrap();

        drop(output);
        assert_eq!(fs::read(&marker).unwrap(), b"preserve");
        assert!(held_stage_path.exists());
        assert_eq!(fs::read_dir(&held_stage_path).unwrap().count(), 0);
    }

    #[test]
    fn rejects_directory_substitution_between_mkdir_and_open_without_deleting_it() {
        let directory = TestDirectory::new();
        let parent = super::open_directory(&directory.0).unwrap();
        let moved_original = directory.0.join("moved-original-stage");
        let mut replacement_path = None;
        let result = super::create_stage_directory_with_hook(&parent, |_, stage_name| {
            let stage_path = directory.0.join(stage_name);
            fs::rename(&stage_path, &moved_original).unwrap();
            fs::create_dir(&stage_path).unwrap();
            fs::set_permissions(&stage_path, fs::Permissions::from_mode(0o770)).unwrap();
            fs::write(&stage_path.join("marker"), b"replacement data").unwrap();
            replacement_path = Some(stage_path);
        });

        assert!(result.is_err());
        let replacement = replacement_path.unwrap();
        assert_eq!(
            fs::read(replacement.join("marker")).unwrap(),
            b"replacement data"
        );
        assert!(moved_original.exists());
        assert_eq!(fs::read_dir(&moved_original).unwrap().count(), 0);
    }

    #[test]
    fn fifo_child_path_is_absolute_and_uses_the_held_directory_descriptor() {
        let directory = TestDirectory::new();
        let mut output = directory.prepare("result.trace");
        output.create_fifo().unwrap();
        let path = output.fifo_path_for_child();
        assert!(Path::new(&path).is_absolute());
        let metadata = fs::metadata(&path).unwrap();
        assert!(metadata.file_type().is_fifo());
        assert!(metadata.ino() > 0);
    }
}
