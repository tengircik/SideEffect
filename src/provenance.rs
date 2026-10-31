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
const SIGNATURE_DOMAIN: &[u8] = b"sideeffect.audit_session.signature.v1\0";
const ALGORITHM: &str = "ed25519";

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
        Ed25519KeyPair, SignatureEnvelope, SystemRandom, generate_keypair, sign_manifest,
        verify_manifest,
    };
    use ring::signature::KeyPair;

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
