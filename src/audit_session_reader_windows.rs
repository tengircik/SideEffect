//! Bounded Windows reader for private, manifest-verified audit sessions.

use crate::audit_session::{
    ArtifactKind, AuditSessionManifest, MAX_AUDIT_SESSION_MANIFEST_BYTES,
    MAX_SESSION_ARTIFACT_BYTES, MAX_SESSION_TOTAL_ARTIFACT_BYTES, ValidationError, parse_manifest,
};
use crate::fingerprint::sha256_hex;
use serde::Deserializer;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const MAX_ENTRIES: usize = 9;

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "could not read audit session: {e}"),
            Self::Manifest(e) => write!(f, "invalid audit-session manifest: {e:?}"),
            Self::InvalidSessionDirectory => f.write_str(
                "audit session must be a private current-user directory without reparse points",
            ),
            Self::InvalidPrivateEntry(n) => {
                write!(f, "session entry {n} is not a private regular file")
            }
            Self::EntryTooLarge(n) => write!(f, "session entry {n} exceeds its size limit"),
            Self::EntryChanged(n) => write!(f, "session entry {n} changed while being read"),
            Self::UnexpectedEntries => {
                f.write_str("audit session contains entries not listed by its manifest")
            }
            Self::ArtifactLengthMismatch(n) => {
                write!(f, "session artifact {n} has an unexpected byte length")
            }
            Self::ArtifactHashMismatch(n) => write!(
                f,
                "session artifact {n} does not match its declared SHA-256"
            ),
            Self::ArtifactSchemaMismatch(n) => {
                write!(f, "session artifact {n} does not match its declared schema")
            }
            Self::ArtifactJsonInvalid(n) => {
                write!(f, "session artifact {n} is not valid bounded JSON")
            }
        }
    }
}
impl std::error::Error for SessionReadError {}
impl From<io::Error> for SessionReadError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<ValidationError> for SessionReadError {
    fn from(error: ValidationError) -> Self {
        Self::Manifest(error)
    }
}

pub fn read_verified_session(path: &Path) -> Result<VerifiedAuditSession, SessionReadError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !owner_only_acl(path)?
    {
        return Err(SessionReadError::InvalidSessionDirectory);
    }
    let directory_lock = OpenOptions::new()
        .read(true)
        .share_mode(0x0000_0003)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let held_metadata = directory_lock.metadata()?;
    if !held_metadata.is_dir()
        || held_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(SessionReadError::InvalidSessionDirectory);
    }
    let canonical = path.canonicalize()?;
    if !owner_only_acl(&canonical)? {
        return Err(SessionReadError::InvalidSessionDirectory);
    }
    let entries = fs::read_dir(&canonical)?;
    let mut names = Vec::new();
    for entry in entries {
        if names.len() >= MAX_ENTRIES {
            return Err(SessionReadError::UnexpectedEntries);
        }
        let entry = entry?;
        names.push(entry.file_name());
    }
    let manifest_file = read_named(
        &canonical,
        "session.json",
        MAX_AUDIT_SESSION_MANIFEST_BYTES,
        true,
    )?;
    let manifest = parse_manifest(&manifest_file)?;
    let mut expected: Vec<String> = vec!["session.json".to_owned()];
    let mut total = 0u64;
    let mut artifacts = Vec::new();
    for source in &manifest.sources {
        for reference in &source.artifacts {
            total = total
                .checked_add(reference.byte_length)
                .ok_or(SessionReadError::EntryTooLarge("aggregate"))?;
            if total > MAX_SESSION_TOTAL_ARTIFACT_BYTES {
                return Err(SessionReadError::EntryTooLarge("aggregate"));
            }
            expected.push(reference.path.clone());
            let bytes = read_named(
                &canonical,
                &reference.path,
                MAX_SESSION_ARTIFACT_BYTES as usize,
                false,
            )?;
            if bytes.len() as u64 != reference.byte_length {
                return Err(SessionReadError::ArtifactLengthMismatch(label(
                    &reference.path,
                )));
            }
            if sha256_hex(&bytes) != reference.sha256 {
                return Err(SessionReadError::ArtifactHashMismatch(label(
                    &reference.path,
                )));
            }
            verify_schema(reference, &bytes)?;
            artifacts.push(VerifiedAuditArtifact {
                kind: reference.kind,
                path: reference.path.clone(),
                bytes,
            });
        }
    }
    let actual: Vec<String> = names
        .into_iter()
        .map(|name| {
            name.into_string()
                .map_err(|_| SessionReadError::UnexpectedEntries)
        })
        .collect::<Result<_, _>>()?;
    if actual.len() != expected.len() || actual.iter().any(|name| !expected.contains(name)) {
        return Err(SessionReadError::UnexpectedEntries);
    }
    let after = fs::symlink_metadata(path)?;
    if !after.is_dir()
        || after.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !owner_only_acl(path)?
    {
        return Err(SessionReadError::EntryChanged("session directory"));
    }
    drop(directory_lock);
    Ok(VerifiedAuditSession {
        manifest,
        artifacts,
    })
}

fn read_named(
    directory: &Path,
    name: &str,
    max: usize,
    manifest: bool,
) -> Result<Vec<u8>, SessionReadError> {
    let path = directory.join(name);
    let before = fs::symlink_metadata(&path).map_err(SessionReadError::Io)?;
    if !before.is_file()
        || before.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !owner_only_acl(&path)?
    {
        return Err(SessionReadError::InvalidPrivateEntry(label(name)));
    }
    if usize::try_from(before.len()).unwrap_or(usize::MAX) > max {
        return Err(SessionReadError::EntryTooLarge(label(name)));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)?;
    let opened = file.metadata()?;
    if !opened.is_file()
        || opened.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || opened.len() != before.len()
    {
        return Err(SessionReadError::EntryChanged(label(name)));
    }
    let limit = if manifest {
        MAX_AUDIT_SESSION_MANIFEST_BYTES
    } else {
        max
    };
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(SessionReadError::EntryTooLarge(label(name)));
    }
    let after = file.metadata()?;
    let named_after = fs::symlink_metadata(&path)?;
    if after.len() != before.len()
        || named_after.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || named_after.len() != before.len()
    {
        return Err(SessionReadError::EntryChanged(label(name)));
    }
    Ok(bytes)
}

fn verify_schema(
    reference: &crate::audit_session::SessionArtifactRef,
    bytes: &[u8],
) -> Result<(), SessionReadError> {
    if reference.kind == ArtifactKind::RuntimeTrace {
        return Ok(());
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let matches = (HeaderSeed {
        schema: &reference.schema,
        version: reference.schema_version,
    })
    .deserialize(&mut deserializer)
    .and_then(|value| deserializer.end().map(|()| value))
    .map_err(|_| SessionReadError::ArtifactJsonInvalid(label(&reference.path)))?;
    if !matches {
        return Err(SessionReadError::ArtifactSchemaMismatch(label(
            &reference.path,
        )));
    }
    Ok(())
}

struct HeaderSeed<'a> {
    schema: &'a str,
    version: u32,
}
impl<'de> DeserializeSeed<'de> for HeaderSeed<'_> {
    type Value = bool;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(HeaderVisitor {
            schema: self.schema,
            version: self.version,
        })
    }
}
struct HeaderVisitor<'a> {
    schema: &'a str,
    version: u32,
}
impl<'de> Visitor<'de> for HeaderVisitor<'_> {
    type Value = bool;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object with schema and schema_version")
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
                    schema = Some(map.next_value::<&str>()? == self.schema);
                }
                "schema_version" => {
                    if version.is_some() {
                        return Err(serde::de::Error::duplicate_field("schema_version"));
                    }
                    version = Some(map.next_value::<u64>()? == self.version as u64);
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }
        match (schema, version) {
            (Some(schema), Some(version)) => Ok(schema && version),
            _ => Err(serde::de::Error::custom("missing schema header field")),
        }
    }
}

fn label(path: &str) -> &'static str {
    match path {
        "session.json" => "session.json",
        "packages.json" => "packages.json",
        "processes.json" => "processes.json",
        "permissions.json" => "permissions.json",
        "startup.json" => "startup.json",
        "software.windows.json" => "software.windows.json",
        "processes.windows.json" => "processes.windows.json",
        "permissions.windows.json" => "permissions.windows.json",
        "startup.windows.json" => "startup.windows.json",
        "run.json" => "run.json",
        "trace.strace" => "trace.strace",
        _ => "unknown entry",
    }
}

// Windows publication creates a protected DACL. The reader accepts only an explicit
// non-inheriting DACL with a single allow ACE for the current user SID.
fn owner_only_acl(path: &Path) -> io::Result<bool> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    type Handle = *mut c_void;
    #[repr(C)]
    struct AclSize {
        ace_count: u32,
        bytes_in_use: u32,
        bytes_free: u32,
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetNamedSecurityInfoW(
            name: *mut u16,
            object_type: u32,
            information: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            descriptor: *mut *mut c_void,
        ) -> u32;
        fn GetSecurityDescriptorDacl(
            descriptor: *const c_void,
            present: *mut i32,
            dacl: *mut *mut c_void,
            defaulted: *mut i32,
        ) -> i32;
        fn GetSecurityDescriptorControl(
            descriptor: *const c_void,
            control: *mut u16,
            revision: *mut u32,
        ) -> i32;
        fn GetAclInformation(acl: *mut c_void, info: *mut c_void, length: u32, class: u32) -> i32;
        fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
        fn EqualSid(a: *mut c_void, b: *mut c_void) -> i32;
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            info: *mut c_void,
            len: u32,
            needed: *mut u32,
        ) -> i32;
        fn LocalFree(memory: Handle) -> Handle;
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
    }
    #[repr(C)]
    struct AceHeader {
        ace_type: u8,
        ace_flags: u8,
        ace_size: u16,
    }
    #[repr(C)]
    struct AllowAce {
        header: AceHeader,
        mask: u32,
        sid_start: u32,
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut sd = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr() as *mut _,
            1,
            0x1 | 0x4,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    struct Local(Handle);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let _sd = Local(sd);
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0
        || control & 0x1000 == 0
    {
        return Ok(false);
    }
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 0x8, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    struct Token(Handle);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let token = Token(token);
    let mut needed = 0;
    unsafe {
        GetTokenInformation(token.0, 1, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 || needed > 65536 {
        return Ok(false);
    }
    let mut storage = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe { GetTokenInformation(token.0, 1, storage.as_mut_ptr().cast(), needed, &mut needed) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    let user_sid = unsafe { *(storage.as_ptr().cast::<*mut c_void>()) };
    if owner.is_null() || unsafe { EqualSid(owner, user_sid) } == 0 {
        return Ok(false);
    }
    let mut present = 0;
    let mut dacl_from_sd = std::ptr::null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl_from_sd, &mut defaulted) }
        == 0
        || present == 0
        || dacl_from_sd.is_null()
        || dacl_from_sd != dacl
    {
        return Ok(false);
    }
    let mut info = AclSize {
        ace_count: 0,
        bytes_in_use: 0,
        bytes_free: 0,
    };
    if unsafe {
        GetAclInformation(
            dacl_from_sd,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<AclSize>() as u32,
            2,
        )
    } == 0
        || info.ace_count != 1
    {
        return Ok(false);
    }
    let mut ace = std::ptr::null_mut();
    if unsafe { GetAce(dacl_from_sd, 0, &mut ace) } == 0 || ace.is_null() {
        return Ok(false);
    }
    let allow = unsafe { &*ace.cast::<AllowAce>() };
    Ok(owner_only_acl_contract(
        control & 0x1000 != 0,
        !owner.is_null() && unsafe { EqualSid(owner, user_sid) } != 0,
        present != 0,
        info.ace_count,
        allow.header.ace_type,
        allow.header.ace_flags,
        unsafe { EqualSid((&allow.sid_start as *const u32).cast_mut().cast(), user_sid) } != 0,
    ))
}

fn owner_only_acl_contract(
    protected: bool,
    owner_matches_current_user: bool,
    dacl_present: bool,
    ace_count: u32,
    ace_type: u8,
    ace_flags: u8,
    ace_sid_matches_current_user: bool,
) -> bool {
    protected
        && owner_matches_current_user
        && dacl_present
        && ace_count == 1
        && ace_type == 0
        && ace_flags == 0
        && ace_sid_matches_current_user
}

#[cfg(test)]
mod tests {
    use super::{SessionReadError, owner_only_acl, owner_only_acl_contract, verify_schema};
    use crate::audit_session::{ArtifactKind, SessionArtifactRef};

    #[test]
    fn reader_accepts_the_publisher_dacl() {
        let root =
            std::env::temp_dir().join(format!("sideeffect-session-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let destination = root.join("session");
        let files = [("session.json", b"fixture".as_slice())];
        crate::record::publish_private_windows_directory(&destination, &files, 1024).unwrap();
        assert!(owner_only_acl(&destination).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn acl_contract_rejects_inheritance_extra_principals_and_wrong_owner() {
        let valid = (true, true, true, 1, 0, 0, true);
        assert!(owner_only_acl_contract(
            valid.0, valid.1, valid.2, valid.3, valid.4, valid.5, valid.6
        ));
        for invalid in [
            (false, true, true, 1, 0, 0, true),
            (true, false, true, 1, 0, 0, true),
            (true, true, false, 1, 0, 0, true),
            (true, true, true, 2, 0, 0, true),
            (true, true, true, 1, 1, 0, true),
            (true, true, true, 1, 0, 1, true),
            (true, true, true, 1, 0, 0, false),
        ] {
            assert!(!owner_only_acl_contract(
                invalid.0, invalid.1, invalid.2, invalid.3, invalid.4, invalid.5, invalid.6
            ));
        }
    }

    #[test]
    fn artifact_schema_check_rejects_duplicate_and_unknown_versions() {
        let reference = SessionArtifactRef {
            kind: ArtifactKind::WindowsSoftware,
            path: "software.windows.json".to_owned(),
            schema: "sideeffect.windows_software_inventory".to_owned(),
            schema_version: 1,
            byte_length: 1,
            sha256: "0".repeat(64),
        };
        assert!(matches!(verify_schema(&reference, br#"{"schema":"sideeffect.windows_software_inventory","schema":"sideeffect.windows_software_inventory","schema_version":1}"#), Err(SessionReadError::ArtifactJsonInvalid("software.windows.json"))));
        assert!(matches!(
            verify_schema(
                &reference,
                br#"{"schema":"sideeffect.windows_software_inventory","schema_version":9}"#
            ),
            Err(SessionReadError::ArtifactSchemaMismatch(
                "software.windows.json"
            ))
        ));
    }
}
