//! Strict, read-only validation for published Linux audit-session directories.
//!
//! SHA-256 checks establish byte consistency with the supplied manifest; they do not
//! authenticate who created either the manifest or its artifacts.

use crate::audit_session::{
    ArtifactKind, AuditSessionManifest, MAX_AUDIT_SESSION_MANIFEST_BYTES,
    MAX_SESSION_ARTIFACT_BYTES, MAX_SESSION_TOTAL_ARTIFACT_BYTES, SessionArtifactRef,
    ValidationError, parse_manifest,
};
use crate::fingerprint::sha256_hex;
use serde::Deserializer;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use std::ffi::{CStr, CString};
use std::fmt::{self, Formatter};
use std::fs::File;
use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const MANIFEST_NAME: &[u8] = b"session.json";
const PRIVATE_BITS: libc::mode_t = 0o077;
const DIRECTORY_OPEN_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
const FILE_OPEN_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;

/// A session whose bounded artifacts were opened and checked against its manifest.
#[derive(Debug)]
pub struct VerifiedAuditSession {
    manifest: AuditSessionManifest,
    artifacts: Vec<VerifiedAuditArtifact>,
}

impl VerifiedAuditSession {
    pub fn manifest(&self) -> &AuditSessionManifest {
        &self.manifest
    }

    pub fn artifacts(&self) -> &[VerifiedAuditArtifact] {
        &self.artifacts
    }
}

/// Exact bytes from one manifest-listed native artifact.
#[derive(Debug)]
pub struct VerifiedAuditArtifact {
    kind: ArtifactKind,
    path: String,
    bytes: Vec<u8>,
}

impl VerifiedAuditArtifact {
    pub fn kind(&self) -> ArtifactKind {
        self.kind
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug)]
pub enum SessionReadError {
    Io(io::Error),
    Manifest(ValidationError),
    InvalidSessionDirectory,
    InvalidPrivateEntry(&'static str),
    EntryTooLarge(&'static str),
    EntryChanged(&'static str),
    UnexpectedEntries,
    ArtifactLengthMismatch(&'static str),
    ArtifactHashMismatch(&'static str),
    ArtifactSchemaMismatch(&'static str),
    ArtifactJsonInvalid(&'static str),
}

impl fmt::Display for SessionReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "could not read audit session: {error}"),
            Self::Manifest(error) => write!(formatter, "invalid audit-session manifest: {error:?}"),
            Self::InvalidSessionDirectory => formatter.write_str(
                "audit session must be a current-user-owned private directory, not a symbolic link",
            ),
            Self::InvalidPrivateEntry(name) => {
                write!(
                    formatter,
                    "session entry {name} is not a private current-user regular file"
                )
            }
            Self::EntryTooLarge(name) => {
                write!(formatter, "session entry {name} exceeds its size limit")
            }
            Self::EntryChanged(name) => {
                write!(formatter, "session entry {name} changed while being read")
            }
            Self::UnexpectedEntries => formatter
                .write_str("audit session contains entries that are not listed by its manifest"),
            Self::ArtifactLengthMismatch(name) => {
                write!(
                    formatter,
                    "session artifact {name} has an unexpected byte length"
                )
            }
            Self::ArtifactHashMismatch(name) => {
                write!(
                    formatter,
                    "session artifact {name} does not match its declared SHA-256"
                )
            }
            Self::ArtifactSchemaMismatch(name) => {
                write!(
                    formatter,
                    "session artifact {name} does not match its declared schema"
                )
            }
            Self::ArtifactJsonInvalid(name) => {
                write!(
                    formatter,
                    "session artifact {name} is not valid bounded JSON"
                )
            }
        }
    }
}

impl std::error::Error for SessionReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for SessionReadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Open a published session without following the final directory or artifact symlink.
///
/// The session directory and files must be owned by the current effective user and must not
/// grant group/other permissions. All listed artifacts must exactly match the manifest's
/// lengths, digests, and native JSON schema/version where applicable. This is integrity
/// checking against an untrusted manifest, not origin authentication or a safety verdict.
pub fn read_verified_session(path: &Path) -> Result<VerifiedAuditSession, SessionReadError> {
    let directory = open_session_directory(path)?;
    let directory_stat = stat_fd(directory.as_raw_fd())?;
    if !private_directory(&directory_stat) {
        return Err(SessionReadError::InvalidSessionDirectory);
    }

    let manifest_read = read_named_file(
        directory.as_raw_fd(),
        MANIFEST_NAME,
        MAX_AUDIT_SESSION_MANIFEST_BYTES,
    )?;
    let manifest = parse_manifest(&manifest_read.bytes).map_err(SessionReadError::Manifest)?;
    let expected = expected_names(&manifest);
    verify_exact_entry_names(directory.as_raw_fd(), &expected)?;

    let mut artifacts = Vec::with_capacity(expected.len().saturating_sub(1));
    let mut opened = Vec::with_capacity(expected.len());
    opened.push((MANIFEST_NAME, manifest_read.identity));
    let mut total_bytes = manifest_read.bytes.len() as u64;
    for source in &manifest.sources {
        for reference in &source.artifacts {
            total_bytes = total_bytes
                .checked_add(reference.byte_length)
                .ok_or(SessionReadError::EntryTooLarge("session"))?;
            if total_bytes > MAX_SESSION_TOTAL_ARTIFACT_BYTES {
                return Err(SessionReadError::EntryTooLarge("session"));
            }
            let name = reference.path.as_bytes();
            let read = read_named_file(
                directory.as_raw_fd(),
                name,
                usize::try_from(MAX_SESSION_ARTIFACT_BYTES)
                    .expect("64 MiB fits in usize on supported Linux x86_64"),
            )?;
            if read.bytes.len() as u64 != reference.byte_length {
                return Err(SessionReadError::ArtifactLengthMismatch(fixed_label(
                    reference,
                )));
            }
            if sha256_hex(&read.bytes) != reference.sha256 {
                return Err(SessionReadError::ArtifactHashMismatch(fixed_label(
                    reference,
                )));
            }
            verify_artifact_schema(reference, &read.bytes)?;
            opened.push((name, read.identity));
            artifacts.push(VerifiedAuditArtifact {
                kind: reference.kind,
                path: reference.path.clone(),
                bytes: read.bytes,
            });
        }
    }

    if !private_directory(&stat_fd(directory.as_raw_fd())?) {
        return Err(SessionReadError::InvalidSessionDirectory);
    }
    verify_exact_entry_names(directory.as_raw_fd(), &expected)?;
    for (name, identity) in &opened {
        if !named_entry_matches(directory.as_raw_fd(), name, *identity)? {
            return Err(SessionReadError::EntryChanged(fixed_entry_label(name)));
        }
    }

    Ok(VerifiedAuditSession {
        manifest,
        artifacts,
    })
}

struct ReadEntry {
    bytes: Vec<u8>,
    identity: (libc::dev_t, libc::ino_t),
}

fn open_session_directory(path: &Path) -> Result<File, SessionReadError> {
    let path_bytes = path.as_os_str().as_bytes();
    let mut trimmed = path_bytes;
    while trimmed.len() > 1 && trimmed.ends_with(b"/") {
        trimmed = &trimmed[..trimmed.len() - 1];
    }
    let name = CString::new(trimmed).map_err(|_| {
        SessionReadError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session path contains a NUL byte",
        ))
    })?;
    // SAFETY: `name` is a NUL-terminated path and the returned descriptor is immediately owned.
    let fd = unsafe { libc::open(name.as_ptr(), DIRECTORY_OPEN_FLAGS) };
    if fd < 0 {
        return Err(SessionReadError::Io(io::Error::last_os_error()));
    }
    // SAFETY: open returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_named_file(
    dir_fd: RawFd,
    name: &[u8],
    max_bytes: usize,
) -> Result<ReadEntry, SessionReadError> {
    let c_name = CString::new(name).map_err(|_| {
        SessionReadError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in fixed entry name",
        ))
    })?;
    // SAFETY: dir_fd is a held directory; manifest validation restricts artifact names to fixed
    // single components. O_NOFOLLOW rejects symlinks and O_NONBLOCK avoids hanging on a FIFO.
    let fd = unsafe { libc::openat(dir_fd, c_name.as_ptr(), FILE_OPEN_FLAGS) };
    if fd < 0 {
        return Err(SessionReadError::Io(io::Error::last_os_error()));
    }
    // SAFETY: openat returned a new owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = stat_fd(file.as_raw_fd())?;
    if !private_regular_file(&before) {
        return Err(SessionReadError::InvalidPrivateEntry(fixed_entry_label(
            name,
        )));
    }
    let before_size = usize::try_from(before.st_size)
        .map_err(|_| SessionReadError::EntryTooLarge(fixed_entry_label(name)))?;
    if before_size > max_bytes {
        return Err(SessionReadError::EntryTooLarge(fixed_entry_label(name)));
    }
    let mut bytes = Vec::with_capacity(before_size);
    let mut limited = (&mut file).take(max_bytes as u64 + 1);
    limited.read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(SessionReadError::EntryTooLarge(fixed_entry_label(name)));
    }
    let after = stat_fd(file.as_raw_fd())?;
    if !private_regular_file(&after)
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || after.st_size < 0
        || usize::try_from(after.st_size).ok() != Some(bytes.len())
        || !named_entry_matches(dir_fd, name, (after.st_dev, after.st_ino))?
    {
        return Err(SessionReadError::EntryChanged(fixed_entry_label(name)));
    }
    Ok(ReadEntry {
        bytes,
        identity: (after.st_dev, after.st_ino),
    })
}

fn private_directory(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR
        && stat.st_uid == unsafe { libc::geteuid() }
        && stat.st_mode & PRIVATE_BITS == 0
        && stat.st_mode & 0o700 == 0o700
}

fn private_regular_file(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFREG
        && stat.st_uid == unsafe { libc::geteuid() }
        && stat.st_mode & PRIVATE_BITS == 0
        && stat.st_mode & 0o400 != 0
        && stat.st_mode & 0o111 == 0
}

fn expected_names(manifest: &AuditSessionManifest) -> Vec<&[u8]> {
    let mut names = Vec::with_capacity(1 + manifest.sources.len().saturating_mul(2));
    names.push(MANIFEST_NAME);
    for source in &manifest.sources {
        for artifact in &source.artifacts {
            names.push(artifact.path.as_bytes());
        }
    }
    names
}

fn verify_exact_entry_names(dir_fd: RawFd, expected: &[&[u8]]) -> Result<(), SessionReadError> {
    let dot = CString::new(".").expect("literal contains no NUL");
    // openat(".") creates an independent open-file description so readdir calls do not share
    // directory offsets with the held session descriptor or with subsequent checks.
    let fd = unsafe {
        libc::openat(
            dir_fd,
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(SessionReadError::Io(io::Error::last_os_error()));
    }
    // SAFETY: openat returned a new owned descriptor.
    let _directory = unsafe { File::from_raw_fd(fd) };
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(SessionReadError::Io(io::Error::last_os_error()));
    }
    // SAFETY: duplicate is a valid directory descriptor owned by fdopendir after success.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(SessionReadError::Io(error));
    }
    let mut seen = vec![false; expected.len()];
    let result = loop {
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: stream is a live DIR* and remains owned until closed below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = unsafe { *libc::__errno_location() };
            if error != 0 {
                break Err(SessionReadError::Io(io::Error::from_raw_os_error(error)));
            }
            if seen.iter().all(|present| *present) {
                break Ok(());
            }
            break Err(SessionReadError::UnexpectedEntries);
        }
        // SAFETY: readdir returns a NUL-terminated d_name valid until the next call.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let Some(index) = expected.iter().position(|candidate| *candidate == name) else {
            break Err(SessionReadError::UnexpectedEntries);
        };
        if std::mem::replace(&mut seen[index], true) {
            break Err(SessionReadError::UnexpectedEntries);
        }
    };
    // SAFETY: stream is the DIR* created above.
    unsafe { libc::closedir(stream) };
    result
}

fn named_entry_matches(
    dir_fd: RawFd,
    name: &[u8],
    identity: (libc::dev_t, libc::ino_t),
) -> Result<bool, SessionReadError> {
    let name = CString::new(name).map_err(|_| {
        SessionReadError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in fixed entry name",
        ))
    })?;
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to writable storage and AT_SYMLINK_NOFOLLOW reports a symlink itself.
    let result = unsafe {
        libc::fstatat(
            dir_fd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Ok(false);
    }
    // SAFETY: successful fstatat initialized the stat structure.
    let stat = unsafe { stat.assume_init() };
    Ok(stat.st_dev == identity.0 && stat.st_ino == identity.1 && private_regular_file(&stat))
}

fn stat_fd(fd: RawFd) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to writable storage and fd is a held descriptor.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstat initialized the stat structure.
    Ok(unsafe { stat.assume_init() })
}

fn verify_artifact_schema(
    reference: &SessionArtifactRef,
    bytes: &[u8],
) -> Result<(), SessionReadError> {
    if reference.kind == ArtifactKind::RuntimeTrace {
        // strace_text has a fixed schema/version contract but is not a JSON document.
        return Ok(());
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let header = (HeaderSeed {
        expected_schema: &reference.schema,
        expected_version: reference.schema_version,
    })
    .deserialize(&mut deserializer)
    .and_then(|header| deserializer.end().map(|()| header))
    .map_err(|_| SessionReadError::ArtifactJsonInvalid(fixed_label(reference)))?;
    if header.schema_matches && header.version_matches {
        Ok(())
    } else {
        Err(SessionReadError::ArtifactSchemaMismatch(fixed_label(
            reference,
        )))
    }
}

struct HeaderSeed<'a> {
    expected_schema: &'a str,
    expected_version: u32,
}

struct HeaderVisitor<'a> {
    expected_schema: &'a str,
    expected_version: u32,
}

struct HeaderMatch {
    schema_matches: bool,
    version_matches: bool,
}

impl<'de> DeserializeSeed<'de> for HeaderSeed<'_> {
    type Value = HeaderMatch;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(HeaderVisitor {
            expected_schema: self.expected_schema,
            expected_version: self.expected_version,
        })
    }
}

impl<'de> Visitor<'de> for HeaderVisitor<'_> {
    type Value = HeaderMatch;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object with schema and schema_version fields")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut schema = None;
        let mut version = None;
        while let Some(key) = map.next_key::<&str>()? {
            match key {
                "schema" => {
                    if schema.is_some() {
                        return Err(serde::de::Error::duplicate_field("schema"));
                    }
                    schema = Some(map.next_value::<&str>()? == self.expected_schema);
                }
                "schema_version" => {
                    if version.is_some() {
                        return Err(serde::de::Error::duplicate_field("schema_version"));
                    }
                    let found = map.next_value::<u64>()?;
                    version = Some(u32::try_from(found).ok() == Some(self.expected_version));
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }
        let Some(schema_matches) = schema else {
            return Err(serde::de::Error::missing_field("schema"));
        };
        let Some(version_matches) = version else {
            return Err(serde::de::Error::missing_field("schema_version"));
        };
        Ok(HeaderMatch {
            schema_matches,
            version_matches,
        })
    }
}

fn fixed_label(reference: &SessionArtifactRef) -> &'static str {
    fixed_entry_label(reference.path.as_bytes())
}

fn fixed_entry_label(name: &[u8]) -> &'static str {
    match name {
        b"session.json" => "session.json",
        b"packages.json" => "packages.json",
        b"processes.json" => "processes.json",
        b"startup.json" => "startup.json",
        b"path-executables.json" => "path-executables.json",
        b"software.windows.json" => "software.windows.json",
        b"processes.windows.json" => "processes.windows.json",
        b"permissions.windows.json" => "permissions.windows.json",
        b"startup.windows.json" => "startup.windows.json",
        b"permissions.json" => "permissions.json",
        b"run.json" => "run.json",
        b"trace.strace" => "trace.strace",
        _ => "unknown entry",
    }
}

#[cfg(test)]
mod tests {
    use super::{ArtifactKind, AuditSessionManifest, SessionArtifactRef, read_verified_session};
    use crate::audit_session::{
        AUDIT_SESSION_SCHEMA, AUDIT_SESSION_SCHEMA_VERSION, AuditSessionSource, IntervalSemantics,
        SessionStatus, SourceRole, SourceStatus,
    };
    use crate::fingerprint::sha256_hex;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let root = std::env::temp_dir();
            for _ in 0..32 {
                let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
                let path = root.join(format!(
                    "sideeffect-session-reader-test-{}-{id}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                        return Self(path);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create test directory: {error}"),
                }
            }
            panic!("could not allocate a unique session-reader test directory")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn write_fixture(directory: &Path, artifact_bytes: &[u8]) {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        let artifact_path = directory.join("packages.json");
        fs::write(&artifact_path, artifact_bytes).unwrap();
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o600)).unwrap();
        let manifest = AuditSessionManifest {
            schema: AUDIT_SESSION_SCHEMA.to_owned(),
            schema_version: AUDIT_SESSION_SCHEMA_VERSION,
            session_id: "0123456789abcdef0123456789abcdef".to_owned(),
            platform: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            host_context: Some(crate::audit_session::HostContext {
                os_name: crate::audit_session::ContextFact {
                    status: crate::audit_session::ContextFactStatus::Observed,
                    value: Some("Linux".to_owned()),
                },
                os_version: crate::audit_session::ContextFact {
                    status: crate::audit_session::ContextFactStatus::Observed,
                    value: Some("6.1".to_owned()),
                },
                privilege: crate::audit_session::PrivilegeContext::NotElevated,
            }),
            started_at_unix_ms: 100,
            ended_at_unix_ms: 101,
            interval_semantics: IntervalSemantics::BestEffortNonAtomic,
            status: SessionStatus::Complete,
            coverage_manifest: Some(crate::audit_session::CoverageManifest {
                version: crate::audit_session::COVERAGE_MANIFEST_VERSION,
                sources: vec![crate::audit_session::SourceCoverage {
                    role: SourceRole::Packages,
                    status: crate::audit_session::CoverageStatus::Observed,
                    runtime_detail: None,
                }],
            }),
            sources: vec![AuditSessionSource {
                role: SourceRole::Packages,
                collector: Some(crate::audit_session::collector_identity(
                    "linux",
                    SourceRole::Packages,
                )),
                platform: "linux".to_owned(),
                scope: "fixture source".to_owned(),
                started_at_unix_ms: 100,
                ended_at_unix_ms: 101,
                status: SourceStatus::Complete,
                applied_limits: Vec::new(),
                requested_settings: Vec::new(),
                effective_settings: Vec::new(),
                loss: None,
                diagnostic_codes: Vec::new(),
                artifacts: vec![SessionArtifactRef {
                    kind: ArtifactKind::Packages,
                    path: "packages.json".to_owned(),
                    schema: "sideeffect.inventory".to_owned(),
                    schema_version: 2,
                    byte_length: artifact_bytes.len() as u64,
                    sha256: sha256_hex(artifact_bytes),
                }],
            }],
        };
        let manifest_path = directory.join("session.json");
        fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::set_permissions(
            directory.join("session.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }

    const VALID_PACKAGE: &[u8] = br#"{"schema":"sideeffect.inventory","schema_version":2}"#;

    #[test]
    fn reader_returns_only_manifest_verified_private_artifacts() {
        let temporary = TestDirectory::new();
        let session = temporary.0.join("session");
        write_fixture(&session, VALID_PACKAGE);

        let loaded = read_verified_session(&session).unwrap();
        assert_eq!(loaded.manifest.status, SessionStatus::Complete);
        assert_eq!(loaded.artifacts.len(), 1);
        assert_eq!(loaded.artifacts[0].kind, ArtifactKind::Packages);
        assert_eq!(loaded.artifacts[0].path, "packages.json");
        assert_eq!(loaded.artifacts[0].bytes, VALID_PACKAGE);
    }

    #[test]
    fn reader_rejects_changed_artifact_bytes() {
        let temporary = TestDirectory::new();
        let session = temporary.0.join("session");
        write_fixture(&session, VALID_PACKAGE);
        fs::write(
            session.join("packages.json"),
            b"{\"schema\":\"sideeffect.inventory\",\"schema_version\":3}",
        )
        .unwrap();
        fs::set_permissions(
            session.join("packages.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        assert!(matches!(
            read_verified_session(&session),
            Err(super::SessionReadError::ArtifactLengthMismatch(
                "packages.json"
            )) | Err(super::SessionReadError::ArtifactHashMismatch(
                "packages.json"
            ))
        ));
    }

    #[test]
    fn reader_rejects_symlinks_and_unlisted_entries() {
        let temporary = TestDirectory::new();
        let session = temporary.0.join("session");
        write_fixture(&session, VALID_PACKAGE);
        let external = temporary.0.join("outside.json");
        fs::write(&external, VALID_PACKAGE).unwrap();
        fs::remove_file(session.join("packages.json")).unwrap();
        symlink(&external, session.join("packages.json")).unwrap();
        assert!(read_verified_session(&session).is_err());

        fs::remove_file(session.join("packages.json")).unwrap();
        fs::copy(&external, session.join("packages.json")).unwrap();
        fs::set_permissions(
            session.join("packages.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(session.join("unlisted.txt"), b"extra").unwrap();
        fs::set_permissions(
            session.join("unlisted.txt"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(matches!(
            read_verified_session(&session),
            Err(super::SessionReadError::UnexpectedEntries)
        ));
    }

    #[test]
    fn reader_requires_private_directory_and_artifacts() {
        let temporary = TestDirectory::new();
        let session = temporary.0.join("session");
        write_fixture(&session, VALID_PACKAGE);
        fs::set_permissions(&session, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            read_verified_session(&session),
            Err(super::SessionReadError::InvalidSessionDirectory)
        ));
        fs::set_permissions(&session, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            session.join("packages.json"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(matches!(
            read_verified_session(&session),
            Err(super::SessionReadError::InvalidPrivateEntry(
                "packages.json"
            ))
        ));
    }

    #[test]
    fn reader_rejects_an_untrusted_final_directory_symlink() {
        let temporary = TestDirectory::new();
        let session = temporary.0.join("session");
        write_fixture(&session, VALID_PACKAGE);
        let link = temporary.0.join("session-link");
        symlink(&session, &link).unwrap();
        assert!(read_verified_session(&link).is_err());
    }
}
