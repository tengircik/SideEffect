//! Detached Ed25519 signatures for exact audit-session manifest bytes.
//!
//! A valid signature proves only that the corresponding private key signed the
//! manifest digest. It does not establish key ownership, collector honesty, or
//! capture completeness.

use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub const SIGNATURE_SCHEMA: &str = "sideeffect.provenance_signature";
pub const SIGNATURE_VERSION: u32 = 1;
pub const MAX_SIGNATURE_BYTES: usize = 4 * 1024;
pub const MAX_KEY_FILE_BYTES: usize = 4 * 1024;
pub const MAX_TRUSTED_KEYS: usize = 256;
const MAX_TRUST_RECORD_BYTES: usize = 4 * 1024;
const TRUST_STORE_SCHEMA: &str = "sideeffect.provenance_trust_store";
const TRUSTED_KEY_SCHEMA: &str = "sideeffect.trusted_provenance_key";
const TRUST_STORE_VERSION: u32 = 1;
const SIGNATURE_DOMAIN: &[u8] = b"sideeffect.audit_session.signature.v1\0";
const ALGORITHM: &str = "ed25519";
const TRUST_STORE_MARKER: &str = "store.json";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub schema: String,
    pub schema_version: u32,
    pub algorithm: String,
    pub key_id: String,
    pub manifest_sha256: String,
    pub signed_at_unix_ms: u64,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verification {
    Valid { key_id: String },
    ValidTrusted { key_id: String, label: String },
    ValidUntrusted { key_id: String },
    UnknownTrustedKey { key_id: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub key_id: String,
    pub label: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustStoreMarker {
    schema: String,
    schema_version: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedKeyRecord {
    schema: String,
    schema_version: u32,
    key_id: String,
    public_key: String,
    label: String,
}

#[derive(Debug)]
pub enum ProvenanceError {
    Io(io::Error),
    InvalidInput(&'static str),
    InvalidEnvelope,
    InvalidKey,
    PublicKeyMismatch,
    ManifestDigestMismatch,
    InvalidSignature,
    UnknownTrustedKey(String),
    InvalidStore,
}

impl std::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::InvalidInput(message) => f.write_str(message),
            Self::InvalidEnvelope => f.write_str("signature envelope is malformed or unsupported"),
            Self::InvalidKey => f.write_str("signing key is malformed or unsupported"),
            Self::PublicKeyMismatch => f.write_str("public key does not match the envelope key ID"),
            Self::ManifestDigestMismatch => {
                f.write_str("session manifest bytes do not match the signed digest")
            }
            Self::InvalidSignature => f.write_str("Ed25519 signature is invalid"),
            Self::UnknownTrustedKey(key_id) => {
                write!(f, "key {key_id} is not in the selected local trust store")
            }
            Self::InvalidStore => {
                f.write_str("local provenance trust store is malformed or unsafe")
            }
        }
    }
}

impl std::error::Error for ProvenanceError {}

impl From<io::Error> for ProvenanceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Create a PKCS#8 Ed25519 private key and a lowercase-hex raw public key.
/// Both destinations are published privately and without replacement.
pub fn generate_keypair(private_path: &Path, public_path: &Path) -> Result<(), ProvenanceError> {
    if private_path == public_path {
        return Err(ProvenanceError::InvalidInput(
            "private and public key paths must differ",
        ));
    }
    for destination in [public_path, private_path] {
        match fs::symlink_metadata(destination) {
            Ok(_) => {
                return Err(ProvenanceError::InvalidInput(
                    "key output path already exists",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(ProvenanceError::Io(error)),
        }
    }
    let rng = SystemRandom::new();
    let private = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| ProvenanceError::InvalidKey)?;
    let key =
        Ed25519KeyPair::from_pkcs8(private.as_ref()).map_err(|_| ProvenanceError::InvalidKey)?;
    let public = key.public_key().as_ref();
    let public_hex = encode_hex(public);
    // Publish the non-secret public key first. If the private destination
    // collides concurrently, failure can leave only this public file behind.
    publish_private(public_path, public_hex.as_bytes())?;
    publish_private(private_path, private.as_ref())?;
    Ok(())
}

/// Sign the exact manifest bytes already accepted by the bounded session reader.
pub fn sign_manifest(
    manifest_bytes: &[u8],
    private_key_bytes: &[u8],
    signed_at_unix_ms: u64,
) -> Result<SignatureEnvelope, ProvenanceError> {
    check_manifest_size(manifest_bytes)?;
    if private_key_bytes.is_empty() || private_key_bytes.len() > MAX_KEY_FILE_BYTES {
        return Err(ProvenanceError::InvalidKey);
    }
    let key =
        Ed25519KeyPair::from_pkcs8(private_key_bytes).map_err(|_| ProvenanceError::InvalidKey)?;
    let manifest_sha256 = encode_hex(&Sha256::digest(manifest_bytes));
    let public_key = key.public_key().as_ref();
    let key_id = encode_hex(&Sha256::digest(public_key));
    let message = signature_message(&key_id, &manifest_sha256, signed_at_unix_ms)?;
    let signature = key.sign(&message);
    Ok(SignatureEnvelope {
        schema: SIGNATURE_SCHEMA.to_owned(),
        schema_version: SIGNATURE_VERSION,
        algorithm: ALGORITHM.to_owned(),
        key_id,
        manifest_sha256,
        signed_at_unix_ms,
        signature: encode_hex(signature.as_ref()),
    })
}

/// Verify a detached envelope using an explicitly supplied public key.
/// This function evaluates cryptographic validity only; it has no trust store.
pub fn verify_manifest(
    manifest_bytes: &[u8],
    envelope_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<Verification, ProvenanceError> {
    check_manifest_size(manifest_bytes)?;
    if envelope_bytes.is_empty() || envelope_bytes.len() > MAX_SIGNATURE_BYTES {
        return Err(ProvenanceError::InvalidEnvelope);
    }
    let envelope: SignatureEnvelope =
        serde_json::from_slice(envelope_bytes).map_err(|_| ProvenanceError::InvalidEnvelope)?;
    validate_envelope(&envelope)?;

    let public_key = decode_hex(public_key_bytes, 32).ok_or(ProvenanceError::InvalidKey)?;
    let key_id = encode_hex(&Sha256::digest(&public_key));
    if envelope.key_id != key_id {
        return Err(ProvenanceError::PublicKeyMismatch);
    }
    let digest = encode_hex(&Sha256::digest(manifest_bytes));
    if envelope.manifest_sha256 != digest {
        return Err(ProvenanceError::ManifestDigestMismatch);
    }
    let signature =
        decode_hex(envelope.signature.as_bytes(), 64).ok_or(ProvenanceError::InvalidEnvelope)?;
    let message = signature_message(
        &envelope.key_id,
        &envelope.manifest_sha256,
        envelope.signed_at_unix_ms,
    )?;
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(&message, &signature)
        .map_err(|_| ProvenanceError::InvalidSignature)?;
    Ok(Verification::Valid { key_id })
}

pub fn serialize_envelope(envelope: &SignatureEnvelope) -> Result<Vec<u8>, ProvenanceError> {
    let mut bytes = serde_json::to_vec(envelope).map_err(|_| ProvenanceError::InvalidEnvelope)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_SIGNATURE_BYTES {
        return Err(ProvenanceError::InvalidEnvelope);
    }
    Ok(bytes)
}

pub fn publish_envelope(
    path: &Path,
    envelope: &SignatureEnvelope,
) -> Result<PathBuf, ProvenanceError> {
    publish_private(path, &serialize_envelope(envelope)?)
}

pub fn load_private_key(path: &Path) -> Result<Vec<u8>, ProvenanceError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(ProvenanceError::InvalidInput(
            "private key must be a regular file, not a link or special file",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and does not mutate memory.
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid || metadata.mode() & 0o077 != 0 {
            return Err(ProvenanceError::InvalidInput(
                "private key must be owned by the current user with no group or other access",
            ));
        }
    }
    #[cfg(windows)]
    if !crate::audit_session_reader_windows::owner_only_acl(path)? {
        return Err(ProvenanceError::InvalidInput(
            "private key must have a protected current-user-only DACL",
        ));
    }
    let bytes = read_limited(path, MAX_KEY_FILE_BYTES, "private key")?;
    Ed25519KeyPair::from_pkcs8(&bytes).map_err(|_| ProvenanceError::InvalidKey)?;
    Ok(bytes)
}

pub fn load_public_key(path: &Path) -> Result<Vec<u8>, ProvenanceError> {
    let bytes = read_limited(path, 64, "public key")?;
    decode_hex(&bytes, 32).ok_or(ProvenanceError::InvalidKey)?;
    Ok(bytes)
}

/// Add a public key to a user-selected, current-user-private trust store.
/// `public_key_bytes` must contain the raw 32-byte Ed25519 public key.
pub fn import_trusted_key(
    store: &Path,
    public_key_bytes: &[u8],
    label: &str,
) -> Result<TrustedKey, ProvenanceError> {
    if public_key_bytes.len() != 32 || !valid_trust_label(label) {
        return Err(ProvenanceError::InvalidInput(
            "public key or trust label is invalid",
        ));
    }
    ensure_trust_store(store)?;
    if list_trusted_keys(store)?.len() >= MAX_TRUSTED_KEYS {
        return Err(ProvenanceError::InvalidInput("trust store is full"));
    }
    let key_id = encode_hex(&Sha256::digest(public_key_bytes));
    let filename = trust_record_filename(&key_id);
    let path = store.join(filename);
    let record = TrustedKeyRecord {
        schema: TRUSTED_KEY_SCHEMA.to_owned(),
        schema_version: TRUST_STORE_VERSION,
        key_id: key_id.clone(),
        public_key: encode_hex(public_key_bytes),
        label: label.to_owned(),
    };
    let mut bytes = serde_json::to_vec(&record).map_err(|_| ProvenanceError::InvalidStore)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_TRUST_RECORD_BYTES {
        return Err(ProvenanceError::InvalidStore);
    }
    publish_private(&path, &bytes).map_err(|error| match error {
        ProvenanceError::Io(ref io_error) if io_error.kind() == io::ErrorKind::AlreadyExists => {
            ProvenanceError::InvalidInput("key is already present in the trust store")
        }
        other => other,
    })?;
    Ok(TrustedKey {
        key_id,
        label: label.to_owned(),
    })
}

/// Import a public key from the existing lowercase-hex public-key file format.
pub fn import_trusted_key_text(
    store: &Path,
    public_key_text: &[u8],
    label: &str,
) -> Result<TrustedKey, ProvenanceError> {
    let public_key = decode_hex(public_key_text, 32).ok_or(ProvenanceError::InvalidKey)?;
    import_trusted_key(store, &public_key, label)
}

pub fn public_key_id(public_key_text: &[u8]) -> Result<String, ProvenanceError> {
    let public_key = decode_hex(public_key_text, 32).ok_or(ProvenanceError::InvalidKey)?;
    Ok(encode_hex(&Sha256::digest(public_key)))
}

pub fn validate_trust_label(label: &str) -> Result<(), ProvenanceError> {
    if valid_trust_label(label) {
        Ok(())
    } else {
        Err(ProvenanceError::InvalidInput(
            "trust label must be 1 to 64 ASCII letters, digits, spaces, periods, underscores, @, or hyphens; edge spaces are not allowed",
        ))
    }
}

pub fn validate_trusted_key_id(key_id: &str) -> Result<(), ProvenanceError> {
    if decode_hex(key_id.as_bytes(), 32).is_some() {
        Ok(())
    } else {
        Err(ProvenanceError::InvalidInput(
            "key ID must be lowercase SHA-256 hex",
        ))
    }
}

/// List keys from a strictly validated local trust store.
pub fn list_trusted_keys(store: &Path) -> Result<Vec<TrustedKey>, ProvenanceError> {
    validate_trust_store(store)?;
    let mut keys = Vec::new();
    let entries = fs::read_dir(store)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if name == TRUST_STORE_MARKER {
            continue;
        }
        if keys.len() == MAX_TRUSTED_KEYS {
            return Err(ProvenanceError::InvalidStore);
        }
        let name = name.to_str().ok_or(ProvenanceError::InvalidStore)?;
        let key_id = name
            .strip_prefix("key-")
            .and_then(|name| name.strip_suffix(".json"))
            .ok_or(ProvenanceError::InvalidStore)?;
        if decode_hex(key_id.as_bytes(), 32).is_none() {
            return Err(ProvenanceError::InvalidStore);
        }
        let record = read_trust_record(&entry.path())?;
        if record.key_id != key_id {
            return Err(ProvenanceError::InvalidStore);
        }
        keys.push(TrustedKey {
            key_id: record.key_id,
            label: record.label,
        });
    }
    keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));
    Ok(keys)
}

/// Remove a key from a local trust store. The caller should obtain explicit
/// confirmation before invoking this operation.
pub fn remove_trusted_key(store: &Path, key_id: &str) -> Result<(), ProvenanceError> {
    if decode_hex(key_id.as_bytes(), 32).is_none() {
        return Err(ProvenanceError::InvalidInput(
            "key ID must be lowercase SHA-256 hex",
        ));
    }
    validate_trust_store(store)?;
    let _ = list_trusted_keys(store)?;
    let path = store.join(trust_record_filename(key_id));
    let record = read_trust_record(&path)?;
    if record.key_id != key_id {
        return Err(ProvenanceError::InvalidStore);
    }
    fs::remove_file(path)?;
    Ok(())
}

/// Verify using a key selected from the trust store. An absent key is reported
/// as unknown without claiming that its signature was cryptographically checked.
pub fn verify_manifest_with_trust_store(
    manifest_bytes: &[u8],
    envelope_bytes: &[u8],
    store: &Path,
) -> Result<Verification, ProvenanceError> {
    check_manifest_size(manifest_bytes)?;
    if envelope_bytes.is_empty() || envelope_bytes.len() > MAX_SIGNATURE_BYTES {
        return Err(ProvenanceError::InvalidEnvelope);
    }
    let envelope: SignatureEnvelope =
        serde_json::from_slice(envelope_bytes).map_err(|_| ProvenanceError::InvalidEnvelope)?;
    validate_envelope(&envelope)?;
    let Some(record) = find_trusted_key(store, &envelope.key_id)? else {
        return Ok(Verification::UnknownTrustedKey {
            key_id: envelope.key_id,
        });
    };
    match verify_manifest(manifest_bytes, envelope_bytes, record.public_key.as_bytes())? {
        Verification::Valid { key_id } => Ok(Verification::ValidTrusted {
            key_id,
            label: record.label,
        }),
        _ => unreachable!("verify_manifest only returns cryptographic validity"),
    }
}

/// Verify with an explicitly supplied public key, then report whether that key
/// is also trusted in the selected store.
pub fn verify_manifest_with_public_key_and_trust_store(
    manifest_bytes: &[u8],
    envelope_bytes: &[u8],
    public_key_text: &[u8],
    store: &Path,
) -> Result<Verification, ProvenanceError> {
    let valid = verify_manifest(manifest_bytes, envelope_bytes, public_key_text)?;
    let Verification::Valid { key_id } = valid else {
        unreachable!("verify_manifest only returns cryptographic validity")
    };
    let Some(record) = find_trusted_key(store, &key_id)? else {
        return Ok(Verification::ValidUntrusted { key_id });
    };
    if record.public_key.as_bytes() != public_key_text {
        return Err(ProvenanceError::InvalidStore);
    }
    Ok(Verification::ValidTrusted {
        key_id,
        label: record.label,
    })
}

pub fn read_manifest(path: &Path) -> Result<Vec<u8>, ProvenanceError> {
    read_limited(
        path,
        crate::audit_session::MAX_AUDIT_SESSION_MANIFEST_BYTES,
        "session manifest",
    )
}

pub fn read_envelope(path: &Path) -> Result<Vec<u8>, ProvenanceError> {
    read_limited(path, MAX_SIGNATURE_BYTES, "signature envelope")
}

fn ensure_trust_store(store: &Path) -> Result<(), ProvenanceError> {
    match fs::symlink_metadata(store) {
        Ok(_) => return validate_trust_store(store),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(ProvenanceError::Io(error)),
    }
    let parent = store
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    validate_trust_store_parent(parent)?;
    let marker = TrustStoreMarker {
        schema: TRUST_STORE_SCHEMA.to_owned(),
        schema_version: TRUST_STORE_VERSION,
    };
    let mut bytes = serde_json::to_vec(&marker).map_err(|_| ProvenanceError::InvalidStore)?;
    bytes.push(b'\n');
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(store) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return validate_trust_store(store);
            }
            Err(error) => return Err(ProvenanceError::Io(error)),
        }
        validate_trust_store_directory(store)?;
        publish_private(&store.join(TRUST_STORE_MARKER), &bytes)?;
    }
    #[cfg(windows)]
    {
        match crate::record::publish_private_windows_directory(
            store,
            &[(TRUST_STORE_MARKER, bytes.as_slice())],
            MAX_TRUST_RECORD_BYTES,
        ) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return validate_trust_store(store);
            }
            Err(error) => return Err(ProvenanceError::Io(error)),
        }
    }
    validate_trust_store(store)
}

fn validate_trust_store_parent(parent: &Path) -> Result<(), ProvenanceError> {
    let metadata = fs::metadata(parent)?;
    if !metadata.is_dir() {
        return Err(ProvenanceError::InvalidStore);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        // Permit a sticky shared temporary directory, where other users cannot
        // remove entries owned by this user. Reject other writable parents.
        if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
            return Err(ProvenanceError::InvalidStore);
        }
    }
    // On Windows, the private-directory publisher applies the protected DACL
    // atomically to the new store; ordinary profile parents may have inherited
    // read-only ACEs that do not permit tampering with that private child.
    Ok(())
}

fn validate_trust_store(store: &Path) -> Result<(), ProvenanceError> {
    let parent = store
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    validate_trust_store_parent(parent)?;
    validate_trust_store_directory(store)?;
    let marker_path = store.join(TRUST_STORE_MARKER);
    validate_trust_store_file(&marker_path)?;
    let bytes = read_limited(&marker_path, MAX_TRUST_RECORD_BYTES, "trust-store marker")?;
    let marker: TrustStoreMarker =
        serde_json::from_slice(&bytes).map_err(|_| ProvenanceError::InvalidStore)?;
    if marker.schema != TRUST_STORE_SCHEMA || marker.schema_version != TRUST_STORE_VERSION {
        return Err(ProvenanceError::InvalidStore);
    }
    Ok(())
}

fn validate_trust_store_directory(store: &Path) -> Result<(), ProvenanceError> {
    let metadata = fs::symlink_metadata(store)?;
    if !metadata.file_type().is_dir() {
        return Err(ProvenanceError::InvalidStore);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and does not mutate memory.
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid || metadata.mode() & 0o077 != 0 {
            return Err(ProvenanceError::InvalidStore);
        }
    }
    #[cfg(windows)]
    if !crate::audit_session_reader_windows::owner_only_acl(store)? {
        return Err(ProvenanceError::InvalidStore);
    }
    Ok(())
}

fn validate_trust_store_file(path: &Path) -> Result<(), ProvenanceError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(ProvenanceError::InvalidStore);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and does not mutate memory.
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid || metadata.mode() & 0o077 != 0 {
            return Err(ProvenanceError::InvalidStore);
        }
    }
    #[cfg(windows)]
    if !crate::audit_session_reader_windows::owner_only_acl(path)? {
        return Err(ProvenanceError::InvalidStore);
    }
    Ok(())
}

fn read_trust_record(path: &Path) -> Result<TrustedKeyRecord, ProvenanceError> {
    validate_trust_store_file(path)?;
    let bytes = read_limited(path, MAX_TRUST_RECORD_BYTES, "trusted key record")?;
    let record: TrustedKeyRecord =
        serde_json::from_slice(&bytes).map_err(|_| ProvenanceError::InvalidStore)?;
    let public_key =
        decode_hex(record.public_key.as_bytes(), 32).ok_or(ProvenanceError::InvalidStore)?;
    if record.schema != TRUSTED_KEY_SCHEMA
        || record.schema_version != TRUST_STORE_VERSION
        || record.key_id != encode_hex(&Sha256::digest(&public_key))
        || !valid_trust_label(&record.label)
    {
        return Err(ProvenanceError::InvalidStore);
    }
    Ok(record)
}

fn find_trusted_key(
    store: &Path,
    key_id: &str,
) -> Result<Option<TrustedKeyRecord>, ProvenanceError> {
    let keys = list_trusted_keys(store)?;
    if !keys.iter().any(|key| key.key_id == key_id) {
        return Ok(None);
    }
    let record = read_trust_record(&store.join(trust_record_filename(key_id)))?;
    Ok(Some(record))
}

fn trust_record_filename(key_id: &str) -> String {
    format!("key-{key_id}.json")
}

fn valid_trust_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && label.trim() == label
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b" ._@-".contains(&byte))
}

fn read_limited(path: &Path, limit: usize, description: &str) -> Result<Vec<u8>, ProvenanceError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > limit as u64 {
        return Err(ProvenanceError::InvalidInput(
            "input must be a bounded regular file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let mut file = options.open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(ProvenanceError::InvalidInput(
            "input must be a regular file, not a link or special file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if opened_metadata.file_attributes() & 0x400 != 0 {
            return Err(ProvenanceError::InvalidInput(
                "input must not be a reparse point",
            ));
        }
    }
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(limit));
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(ProvenanceError::InvalidInput(
            "input exceeds its size limit",
        ));
    }
    if bytes.is_empty() {
        return Err(ProvenanceError::InvalidInput("input file is empty"));
    }
    let _ = description;
    Ok(bytes)
}

fn publish_private(path: &Path, bytes: &[u8]) -> Result<PathBuf, ProvenanceError> {
    #[cfg(target_os = "linux")]
    let published = crate::record::publish_private_file(path, bytes, MAX_KEY_FILE_BYTES)?;
    #[cfg(windows)]
    let published = crate::record::publish_private_windows_file(path, bytes, MAX_KEY_FILE_BYTES)?;
    Ok(published)
}

fn check_manifest_size(bytes: &[u8]) -> Result<(), ProvenanceError> {
    if bytes.is_empty() || bytes.len() > crate::audit_session::MAX_AUDIT_SESSION_MANIFEST_BYTES {
        return Err(ProvenanceError::InvalidInput(
            "session manifest is empty or exceeds its size limit",
        ));
    }
    Ok(())
}

fn validate_envelope(envelope: &SignatureEnvelope) -> Result<(), ProvenanceError> {
    if envelope.schema != SIGNATURE_SCHEMA
        || envelope.schema_version != SIGNATURE_VERSION
        || envelope.algorithm != ALGORITHM
        || decode_hex(envelope.key_id.as_bytes(), 32).is_none()
        || decode_hex(envelope.manifest_sha256.as_bytes(), 32).is_none()
        || decode_hex(envelope.signature.as_bytes(), 64).is_none()
        || envelope.signed_at_unix_ms > crate::audit_session::MAX_SESSION_TIMESTAMP_UNIX_MS as u64
    {
        return Err(ProvenanceError::InvalidEnvelope);
    }
    Ok(())
}

fn signature_message(
    key_id: &str,
    manifest_digest: &str,
    signed_at: u64,
) -> Result<Vec<u8>, ProvenanceError> {
    let key = decode_hex(key_id.as_bytes(), 32).ok_or(ProvenanceError::InvalidEnvelope)?;
    let digest =
        decode_hex(manifest_digest.as_bytes(), 32).ok_or(ProvenanceError::InvalidEnvelope)?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32 + 32 + 8);
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&key);
    message.extend_from_slice(&digest);
    message.extend_from_slice(&signed_at.to_be_bytes());
    Ok(message)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}

fn decode_hex(bytes: &[u8], expected: usize) -> Option<Vec<u8>> {
    if bytes.len() != expected.checked_mul(2)? {
        return None;
    }
    let mut output = Vec::with_capacity(expected);
    for pair in bytes.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output.push((high << 4) | low);
    }
    Some(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Ed25519KeyPair, SignatureEnvelope, SystemRandom, generate_keypair, import_trusted_key,
        list_trusted_keys, remove_trusted_key, sign_manifest, verify_manifest,
        verify_manifest_with_public_key_and_trust_store, verify_manifest_with_trust_store,
    };
    use ring::signature::KeyPair;
    use sha2::Digest;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_STORE_ID: AtomicU64 = AtomicU64::new(0);

    fn test_key() -> (Vec<u8>, Vec<u8>) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        (pkcs8.as_ref().to_vec(), key.public_key().as_ref().to_vec())
    }

    fn public_text(raw: &[u8]) -> Vec<u8> {
        raw.iter()
            .flat_map(|byte| {
                [
                    b"0123456789abcdef"[(byte >> 4) as usize],
                    b"0123456789abcdef"[(byte & 0xf) as usize],
                ]
            })
            .collect()
    }

    fn temporary_root() -> std::path::PathBuf {
        let id = NEXT_STORE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "sideeffect-provenance-unit-{}-{id}",
            std::process::id()
        ));
        #[cfg(windows)]
        crate::record::publish_private_windows_directory(&root, &[("test-root", b"x")], 128)
            .unwrap();
        #[cfg(not(windows))]
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }

    #[test]
    fn detached_signature_round_trips_and_binds_exact_bytes() {
        let (private, public) = test_key();
        let manifest = br#"{"schema":"sideeffect.audit_session","schema_version":6}"#;
        let envelope = sign_manifest(manifest, &private, 1234).unwrap();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        assert!(matches!(
            verify_manifest(manifest, &bytes, &public_text(&public)).unwrap(),
            super::Verification::Valid { .. }
        ));
        assert!(
            verify_manifest(
                b"{\"schema\":\"sideeffect.audit_session\",\"schema_version\":6} ",
                &bytes,
                &public_text(&public)
            )
            .is_err()
        );
    }

    #[test]
    fn a_different_public_key_and_modified_signature_are_rejected() {
        let (private, public) = test_key();
        let (wrong_private, wrong_public) = test_key();
        let manifest = b"fixed manifest bytes";
        let envelope = sign_manifest(manifest, &private, 1234).unwrap();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        assert!(verify_manifest(manifest, &bytes, &public_text(&wrong_public)).is_err());

        let mut changed = sign_manifest(manifest, &private, 1234).unwrap();
        let replacement = if changed.signature.starts_with('0') {
            "1"
        } else {
            "0"
        };
        changed.signature.replace_range(0..1, replacement);
        let changed = serde_json::to_vec(&changed).unwrap();
        assert!(verify_manifest(manifest, &changed, &public_text(&public)).is_err());
        assert!(sign_manifest(manifest, &wrong_private, 1234).is_ok());
    }

    #[test]
    fn envelope_rejects_unknown_fields_and_unsupported_algorithms() {
        let (private, _) = test_key();
        let envelope = sign_manifest(b"manifest", &private, 1).unwrap();
        let mut value = serde_json::to_value(envelope).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SignatureEnvelope>(value).is_err());
        let mut envelope = sign_manifest(b"manifest", &private, 1).unwrap();
        envelope.algorithm = "unknown".into();
        assert!(super::validate_envelope(&envelope).is_err());
    }

    #[test]
    fn malformed_or_oversized_envelopes_are_rejected() {
        let (_, public) = test_key();
        assert!(verify_manifest(b"m", b"{}", &public_text(&public)).is_err());
        assert!(
            verify_manifest(
                b"m",
                &vec![b' '; super::MAX_SIGNATURE_BYTES + 1],
                &public_text(&public)
            )
            .is_err()
        );
    }

    #[test]
    fn trust_store_import_verify_and_remove_keep_crypto_and_trust_distinct() {
        let root = temporary_root();
        let store = root.join("trusted-keys");
        let (trusted_private, trusted_public) = test_key();
        let (untrusted_private, untrusted_public) = test_key();
        let trusted = import_trusted_key(&store, &trusted_public, "review team").unwrap();
        assert_eq!(
            trusted.key_id,
            super::encode_hex(&sha2::Sha256::digest(&trusted_public))
        );
        assert_eq!(list_trusted_keys(&store).unwrap(), vec![trusted.clone()]);

        let manifest = b"validated test manifest bytes";
        let trusted_envelope = sign_manifest(manifest, &trusted_private, 1234).unwrap();
        let trusted_envelope = serde_json::to_vec(&trusted_envelope).unwrap();
        assert_eq!(
            verify_manifest_with_trust_store(manifest, &trusted_envelope, &store).unwrap(),
            super::Verification::ValidTrusted {
                key_id: trusted.key_id.clone(),
                label: "review team".to_owned(),
            }
        );
        let mut tampered: super::SignatureEnvelope =
            serde_json::from_slice(&trusted_envelope).unwrap();
        let replacement = if tampered.signature.starts_with('0') {
            "1"
        } else {
            "0"
        };
        tampered.signature.replace_range(0..1, replacement);
        let tampered = serde_json::to_vec(&tampered).unwrap();
        assert!(verify_manifest_with_trust_store(manifest, &tampered, &store).is_err());

        let untrusted_envelope = sign_manifest(manifest, &untrusted_private, 1234).unwrap();
        let untrusted_envelope = serde_json::to_vec(&untrusted_envelope).unwrap();
        let untrusted_public = public_text(&untrusted_public);
        let untrusted_id = super::public_key_id(&untrusted_public).unwrap();
        assert_eq!(
            verify_manifest_with_trust_store(manifest, &untrusted_envelope, &store).unwrap(),
            super::Verification::UnknownTrustedKey {
                key_id: untrusted_id.clone(),
            }
        );
        assert_eq!(
            verify_manifest_with_public_key_and_trust_store(
                manifest,
                &untrusted_envelope,
                &untrusted_public,
                &store,
            )
            .unwrap(),
            super::Verification::ValidUntrusted {
                key_id: untrusted_id,
            }
        );
        #[cfg(windows)]
        assert!(
            crate::audit_session_reader_windows::owner_only_acl(
                &store.join(super::trust_record_filename(&trusted.key_id))
            )
            .unwrap()
        );

        remove_trusted_key(&store, &trusted.key_id).unwrap();
        assert!(list_trusted_keys(&store).unwrap().is_empty());
        assert!(remove_trusted_key(&store, &trusted.key_id).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&store).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(store.join(super::TRUST_STORE_MARKER))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        #[cfg(windows)]
        assert!(crate::audit_session_reader_windows::owner_only_acl(&store).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn trust_store_rejects_duplicate_invalid_label_unknown_record_fields_and_links() {
        let root = temporary_root();
        let store = root.join("trusted-keys");
        let (_, public) = test_key();
        let trusted = import_trusted_key(&store, &public, "known key").unwrap();
        assert!(import_trusted_key(&store, &public, "known key").is_err());
        assert!(import_trusted_key(&store, &public, "bad\nlabel").is_err());

        let record_path = store.join(super::trust_record_filename(&trusted.key_id));
        let valid_record = std::fs::read(&record_path).unwrap();
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
        record["unexpected"] = serde_json::json!(true);
        std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(list_trusted_keys(&store).is_err());

        let mut record: serde_json::Value = serde_json::from_slice(&valid_record).unwrap();
        record["key_id"] =
            serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");
        std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(list_trusted_keys(&store).is_err());

        let record: super::TrustedKeyRecord = serde_json::from_slice(&valid_record).unwrap();
        let duplicate_key_id = format!(
            "{{\"schema\":\"{}\",\"schema_version\":{},\"key_id\":\"{}\",\"key_id\":\"{}\",\"public_key\":\"{}\",\"label\":\"{}\"}}",
            record.schema,
            record.schema_version,
            record.key_id,
            record.key_id,
            record.public_key,
            record.label,
        );
        std::fs::write(&record_path, duplicate_key_id).unwrap();
        assert!(list_trusted_keys(&store).is_err());

        std::fs::write(&record_path, vec![b' '; super::MAX_TRUST_RECORD_BYTES + 1]).unwrap();
        assert!(list_trusted_keys(&store).is_err());
        std::fs::write(&record_path, &valid_record).unwrap();

        #[cfg(unix)]
        {
            let link = store
                .join("key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json");
            std::os::unix::fs::symlink(&record_path, &link).unwrap();
            assert!(list_trusted_keys(&store).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generated_key_files_are_private_and_do_not_replace() {
        let root =
            std::env::temp_dir().join(format!("sideeffect-provenance-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let private = root.join("private.pk8");
        let public = root.join("public.hex");
        generate_keypair(&private, &public).unwrap();
        assert!(generate_keypair(&private, &public).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&private).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        #[cfg(windows)]
        {
            assert!(
                crate::audit_session_reader_windows::owner_only_acl(&private).unwrap(),
                "generated private key must have a protected current-user-only DACL"
            );
            assert!(
                crate::audit_session_reader_windows::owner_only_acl(&public).unwrap(),
                "generated public key must have a protected current-user-only DACL"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
