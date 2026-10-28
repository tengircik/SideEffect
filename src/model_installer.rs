//! Explicit installation of models from the immutable built-in catalog.
//!
//! This module has no API for arbitrary download URLs. A caller must display
//! the exact license notice and pass a positive acknowledgement before this
//! module persists that acknowledgement or makes a network request.

use reqwest::blocking::{Client, Response};
use reqwest::{Proxy, Url};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::model_manager::{
    CatalogModel, catalog_model, create_model_stage, ensure_private_model_directory, lock_registry,
    update_registry, verify_model_stage_acl,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const PROGRESS_GRANULARITY: u64 = 1024 * 1024;
const ALLOWED_REDIRECTS: usize = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallProgress {
    pub received_bytes: u64,
    pub expected_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallReceipt {
    pub id: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
}

/// Install a pinned built-in model after exact affirmative license consent.
///
/// The callback returns false to cancel. It is called after each approximately
/// 1 MiB received. Downloads are unauthenticated HTTPS requests; no model or
/// prompt data is sent. Only credential-free HTTPS_PROXY/ALL_PROXY settings
/// are used. HTTP proxy variables with user-info are rejected; NO_PROXY and
/// platform-specific proxy stores are not currently honored.
pub fn install_catalog_model<F>(
    model_id: &str,
    displayed_license_id: &str,
    displayed_license_url: &str,
    affirmative_acceptance: bool,
    mut progress: F,
) -> Result<InstallReceipt, String>
where
    F: FnMut(InstallProgress) -> bool,
{
    let catalog = catalog_model(model_id)
        .ok_or_else(|| "model ID is not in the built-in catalog".to_owned())?;
    if !affirmative_acceptance {
        return Err("model installation requires explicit license acceptance".to_owned());
    }
    if displayed_license_id != catalog.license_id || displayed_license_url != catalog.license_url {
        return Err("displayed license does not match the pinned catalog entry".to_owned());
    }

    let directory = ensure_private_model_directory()?;
    let destination = directory.join(catalog.filename);
    // Persist before the first request; acceptance remains recorded if the
    // subsequent transfer fails or is cancelled.
    update_registry(|registry| {
        registry.accept_catalog_license(
            catalog.id,
            catalog.revision,
            catalog.license_id,
            catalog.license_url,
            true,
        )
    })?;

    if destination.exists() {
        let transaction = lock_registry()?;
        let registry = transaction.load()?;
        let verified = registry.resolve(catalog.id, catalog.task)?;
        return Ok(receipt(catalog, verified.path));
    }

    let url = catalog_url(catalog)?;
    let client = build_client()?;
    let response = client.get(url).send().map_err(|_| {
        "model download request failed; check network and proxy settings".to_owned()
    })?;
    let mut response = response
        .error_for_status()
        .map_err(|_| "model source returned an unsuccessful HTTP status".to_owned())?;
    validate_final_url(response.url())?;
    if response
        .content_length()
        .is_some_and(|length| length != catalog.size_bytes)
    {
        return Err("model source size does not match the pinned catalog size".to_owned());
    }

    let (staged, mut output) = create_staging_file(&directory, catalog.id)?;
    let mut stage_guard = StagingFile::new(staged.clone());
    stream_and_verify(&mut response, &mut output, catalog, &mut progress)?;
    output
        .sync_all()
        .map_err(|_| "could not flush downloaded model staging file".to_owned())?;
    drop(output);
    verify_model_stage_acl(&staged)?;

    // Serialize publication with catalog removal and selection changes while
    // avoiding holding the registry lock during network transfer.
    let transaction = lock_registry()?;
    let registry = transaction.load()?;
    if destination.exists() {
        let verified = registry.resolve(catalog.id, catalog.task)?;
        return Ok(receipt(catalog, verified.path));
    }

    // A hard link is an atomic same-directory publish that fails if the
    // destination exists; it never replaces another model file.
    fs::hard_link(&staged, &destination)
        .map_err(|_| "could not publish model without replacing an existing file".to_owned())?;
    if fs::remove_file(&staged).is_ok() {
        stage_guard.disarm();
    }

    let verified = registry.resolve(catalog.id, catalog.task)?;
    Ok(receipt(catalog, verified.path))
}

/// Remove only an installed built-in catalog model after an exact pinned
/// size/hash check. Custom model files are never removed by this operation.
/// The caller should require the user to type the model ID before setting the
/// explicit confirmation flag.
pub fn remove_catalog_model(
    model_id: &str,
    affirmative_confirmation: bool,
) -> Result<PathBuf, String> {
    if !affirmative_confirmation {
        return Err("catalog model removal requires explicit confirmation".to_owned());
    }
    let catalog = catalog_model(model_id)
        .ok_or_else(|| "model ID is not in the built-in catalog".to_owned())?;
    let directory = ensure_private_model_directory()?;
    let transaction = lock_registry()?;
    let mut registry = transaction.load()?;
    let resolved = registry.resolve(catalog.id, catalog.task)?;
    let expected = directory.join(catalog.filename);
    if resolved.path != expected {
        return Err("verified catalog model resolved outside its private store path".to_owned());
    }
    registry
        .selected_by_task
        .retain(|_, selected| selected != catalog.id);
    transaction.save(&registry)?;
    fs::remove_file(&expected)
        .map_err(|_| "could not remove the verified catalog model file".to_owned())?;
    Ok(expected)
}

fn receipt(catalog: &CatalogModel, path: PathBuf) -> InstallReceipt {
    InstallReceipt {
        id: catalog.id.to_owned(),
        path,
        size_bytes: catalog.size_bytes,
        sha256: catalog.sha256.to_owned(),
    }
}

fn catalog_url(catalog: &CatalogModel) -> Result<Url, String> {
    // Every interpolated component is from the static catalog and is checked
    // here to guard future entries from accidentally adding URL syntax.
    for component in [catalog.repository, catalog.revision, catalog.filename] {
        if component.is_empty()
            || !component.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.')
            })
        {
            return Err("built-in model source metadata is invalid".to_owned());
        }
    }
    let raw = format!(
        "https://huggingface.co/{}/resolve/{}/{}?download=true",
        catalog.repository, catalog.revision, catalog.filename
    );
    let url = Url::parse(&raw).map_err(|_| "built-in model URL is invalid".to_owned())?;
    validate_final_url(&url)?;
    Ok(url)
}

fn validate_final_url(url: &Url) -> Result<(), String> {
    let host = url
        .host_str()
        .ok_or_else(|| "model source URL has no host".to_owned())?;
    let allowed_host = host == "huggingface.co"
        || host.ends_with(".huggingface.co")
        || host == "hf.co"
        || host.ends_with(".hf.co");
    if url.scheme() != "https"
        || !allowed_host
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("model source or redirect is not an approved HTTPS host".to_owned());
    }
    Ok(())
}

fn build_client() -> Result<Client, String> {
    let mut builder = Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= ALLOWED_REDIRECTS {
                return attempt.error("too many model download redirects");
            }
            if validate_final_url(attempt.url()).is_err() {
                return attempt.error("model download redirect is not approved");
            }
            attempt.follow()
        }))
        .user_agent(concat!("SideEffect/", env!("CARGO_PKG_VERSION")))
        // reqwest's automatic proxy discovery could forward proxy credentials
        // from environment variables. Configure only explicitly inspected,
        // credential-free HTTPS/ALL proxy URLs instead.
        .no_proxy();

    if let Some(proxy) = configured_proxy()? {
        let proxy =
            Proxy::all(proxy.as_str()).map_err(|_| "configured proxy URL is invalid".to_owned())?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|_| "could not initialize secure model download client".to_owned())
}

fn configured_proxy() -> Result<Option<Url>, String> {
    let raw = ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()));
    let Some(raw) = raw else {
        return Ok(None);
    };
    let proxy = Url::parse(&raw).map_err(|_| "configured proxy URL is invalid".to_owned())?;
    if !matches!(proxy.scheme(), "http" | "https")
        || proxy.host_str().is_none()
        || !proxy.username().is_empty()
        || proxy.password().is_some()
        || proxy.query().is_some()
        || proxy.fragment().is_some()
    {
        return Err(
            "configured proxy must be HTTP(S) and contain no credentials or query data".to_owned(),
        );
    }
    Ok(Some(proxy))
}

fn create_staging_file(directory: &Path, model_id: &str) -> Result<(PathBuf, File), String> {
    for attempt in 0..16_u8 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_owned())?
            .as_nanos();
        let path = directory.join(format!(
            ".{model_id}-{}-{nonce:x}-{attempt:x}.part",
            std::process::id()
        ));
        match create_model_stage(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("could not create private model staging file".to_owned()),
        }
    }
    Err("could not allocate a unique model staging file".to_owned())
}

fn stream_and_verify<F>(
    response: &mut Response,
    output: &mut File,
    catalog: &CatalogModel,
    progress: &mut F,
) -> Result<(), String>
where
    F: FnMut(InstallProgress) -> bool,
{
    let mut hasher = Sha256::new();
    let mut received = 0_u64;
    let mut last_reported = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = response
            .read(&mut buffer)
            .map_err(|_| "model download was interrupted or timed out".to_owned())?;
        if count == 0 {
            break;
        }
        received = received.saturating_add(count as u64);
        if received > catalog.size_bytes {
            return Err("model response exceeds the pinned catalog size".to_owned());
        }
        hasher.update(&buffer[..count]);
        output
            .write_all(&buffer[..count])
            .map_err(|_| "could not write model staging file".to_owned())?;
        if received.saturating_sub(last_reported) >= PROGRESS_GRANULARITY {
            if !progress(InstallProgress {
                received_bytes: received,
                expected_bytes: catalog.size_bytes,
            }) {
                return Err("model download was cancelled".to_owned());
            }
            last_reported = received;
        }
    }
    if received != catalog.size_bytes {
        return Err("model response ended before the pinned catalog size".to_owned());
    }
    let digest = hex_digest(hasher.finalize().as_slice());
    if digest != catalog.sha256 {
        return Err("downloaded model SHA-256 does not match the pinned catalog".to_owned());
    }
    if last_reported != received
        && !progress(InstallProgress {
            received_bytes: received,
            expected_bytes: catalog.size_bytes,
        })
    {
        return Err("model download was cancelled".to_owned());
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

struct StagingFile {
    path: PathBuf,
    armed: bool,
}

impl StagingFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}
