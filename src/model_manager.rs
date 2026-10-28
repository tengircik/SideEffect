//! Local model catalog metadata and bounded per-user model selection state.
//!
//! Catalog entries are provenance records, not quality recommendations. A
//! model's current evaluation status is shown independently from its ability
//! to load in the configured local runtime.

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const REGISTRY_SCHEMA: &str = "sideeffect.local_model_registry";
pub const REGISTRY_SCHEMA_VERSION: u32 = 1;
pub const MAX_REGISTRY_BYTES: usize = 64 * 1024;
pub const MAX_REGISTERED_MODELS: usize = 32;
pub const MAX_MODEL_NAME_BYTES: usize = 128;
pub const MAX_MODEL_PATH_BYTES: usize = 32 * 1024;
/// The largest model file currently supported by any one local analysis path.
/// Task-specific limits are enforced below before registration and use.
pub const MAX_MODEL_FILE_BYTES: u64 = 3 * 1024 * 1024 * 1024;

pub fn model_file_size_limit(task: ModelTask) -> u64 {
    max_bytes_for_task(task)
}

/// Product operations with distinct request schemas and evaluation contracts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelTask {
    EvidenceSelection,
    Explanation,
    QueryPlan,
}

/// Evidence from repo evaluations is deliberately not collapsed to a single
/// boolean "supported" flag.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationStatus {
    FailedTriage,
    FailedFrozenGate,
    FailedDevelopmentCheck,
    NotAssessed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CatalogModel {
    pub id: &'static str,
    pub name: &'static str,
    pub task: ModelTask,
    pub repository: &'static str,
    pub revision: &'static str,
    pub filename: &'static str,
    pub size_bytes: u64,
    pub sha256: &'static str,
    pub license_id: &'static str,
    pub license_url: &'static str,
    pub evaluation: EvaluationStatus,
    pub evaluation_note: &'static str,
    pub evaluation_document: &'static str,
}

/// Pinned local candidates documented in the repository. Every current entry
/// failed a task-specific quality check and is never marked recommended.
pub const CATALOG: &[CatalogModel] = &[
    CatalogModel {
        id: "evidence-qwen2.5-0.5b-q4-0",
        name: "Qwen2.5 0.5B Q4_0 (experimental; failed frozen gate)",
        task: ModelTask::EvidenceSelection,
        repository: "Qwen/Qwen2.5-0.5B-Instruct-GGUF",
        revision: "9217f5db79a29953eb74d5343926648285ec7e67",
        filename: "Qwen2.5-0.5B-Instruct-Q4_0.gguf",
        size_bytes: 428_730_208,
        sha256: "7671c0c304e6ce5a7fc577bcb12aba01e2c155cc2efd29b2213c95b18edaf6ed",
        license_id: "Apache-2.0",
        license_url: "https://www.apache.org/licenses/LICENSE-2.0",
        evaluation: EvaluationStatus::FailedFrozenGate,
        evaluation_note: "Scored 9/39 answerable selections and false-selected all 12 unanswerable cases; not recommended.",
        evaluation_document: "docs/LOCAL_MODEL_EVALUATION.md",
    },
    CatalogModel {
        id: "explanation-qwen3.5-4b-q4-k-m",
        name: "Qwen3.5 4B Q4_K_M (experimental; failed development check)",
        task: ModelTask::Explanation,
        repository: "gguf/Qwen3.5-4B-GGUF",
        revision: "76e05555d64c8d045dd4b9c9f1ebaef1e35d99f7",
        filename: "qwen3.5-4b-Q4_K_M.gguf",
        size_bytes: 2_783_446_368,
        sha256: "c3c2cf023efdbd913c2363a14d5c7266db5e05c4602f1c0790eaed567d8aff23",
        license_id: "Apache-2.0",
        license_url: "https://www.apache.org/licenses/LICENSE-2.0",
        evaluation: EvaluationStatus::FailedDevelopmentCheck,
        evaluation_note: "Answered only 4 of 26 synthetic development questions; not recommended for decisions.",
        evaluation_document: "docs/LOCAL_MODEL_EXPLANATION_EVALUATION.md",
    },
    CatalogModel {
        id: "query-qwen3-1.7b-q4-k-m",
        name: "Qwen3 1.7B Q4_K_M (experimental; failed triage)",
        task: ModelTask::QueryPlan,
        repository: "bartowski/Qwen_Qwen3-1.7B-GGUF",
        revision: "dcb19155b962dbb6389f4691a982043a8e651022",
        filename: "Qwen_Qwen3-1.7B-Q4_K_M.gguf",
        size_bytes: 1_282_439_584,
        sha256: "72c5c3cb38fa32d5256e2fe30d03e7a64c6c79e668ad84057e3bd66e250b24fb",
        license_id: "Apache-2.0",
        license_url: "https://www.apache.org/licenses/LICENSE-2.0",
        evaluation: EvaluationStatus::FailedTriage,
        evaluation_note: "Returned unsupported_scope for a clearly supported query; not recommended.",
        evaluation_document: "docs/LOCAL_QUERY_PLAN_EVALUATION.md",
    },
    CatalogModel {
        id: "query-smollm3-3b-q3-k-m",
        name: "SmolLM3 3B Q3_K_M (experimental; failed triage)",
        task: ModelTask::QueryPlan,
        repository: "bartowski/HuggingFaceTB_SmolLM3-3B-GGUF",
        revision: "86b3536ed1ca0dcb4716745642db4e6804bf3d32",
        filename: "HuggingFaceTB_SmolLM3-3B-Q3_K_M.gguf",
        size_bytes: 1_571_069_760,
        sha256: "5e5c70fdc3429023ed88ead8af2a70684047e2628258b650bdb729c8437639d0",
        license_id: "Apache-2.0",
        license_url: "https://www.apache.org/licenses/LICENSE-2.0",
        evaluation: EvaluationStatus::FailedTriage,
        evaluation_note: "Returned unsupported_scope for a clearly supported query; not recommended.",
        evaluation_document: "docs/LOCAL_QUERY_PLAN_EVALUATION.md",
    },
    CatalogModel {
        id: "query-phi-3-5-mini-q2-k",
        name: "Phi-3.5 Mini Q2_K (experimental; failed independent confirmation)",
        task: ModelTask::QueryPlan,
        repository: "microsoft/Phi-3.5-mini-instruct-GGUF",
        revision: "6d70da17e749a471ccb62ade694486011a75cda3",
        filename: "Phi-3.5-mini-instruct-Q2_K.gguf",
        size_bytes: 1_416_204_576,
        sha256: "7425cb5fec0d2673151c95d1418f5e11bdf102edd0d8b22986d17210adb05bbd",
        license_id: "MIT",
        license_url: "https://opensource.org/license/mit",
        evaluation: EvaluationStatus::FailedFrozenGate,
        evaluation_note: "Independent confirmation failed plan and abstention criteria; not recommended.",
        evaluation_document: "docs/LOCAL_QUERY_PLAN_EVALUATION.md",
    },
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredModel {
    /// Stable local identifier, generated by SideEffect and never interpreted
    /// as a path or URL.
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
    /// Custom model licenses are user-provided metadata and are not verified.
    pub license_id: Option<String>,
    pub tasks: Vec<ModelTask>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRegistry {
    pub schema: String,
    pub schema_version: u32,
    #[serde(default)]
    pub accepted_licenses: Vec<AcceptedModelLicense>,
    pub custom_models: Vec<RegisteredModel>,
    pub selected_by_task: BTreeMap<ModelTask, String>,
}

/// Holds the cross-process exclusive lock for one registry read-modify-write
/// transaction. Keep the guard short-lived; never hold it while downloading.
pub struct RegistryTransaction {
    _lock_file: File,
}

impl RegistryTransaction {
    pub fn load(&self) -> Result<ModelRegistry, String> {
        load_registry_unlocked()
    }

    pub fn save(&self, registry: &ModelRegistry) -> Result<(), String> {
        save_registry_unlocked(registry)
    }
}

pub fn lock_registry() -> Result<RegistryTransaction, String> {
    let path = registry_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| "model registry path has no parent directory".to_owned())?;
    ensure_private_store_directory(parent)?;
    let lock_path = parent.join(".model-registry.lock");
    let lock_file = open_registry_lock(&lock_path)
        .map_err(|error| format!("could not open private model registry lock: {error}"))?;
    FileExt::lock_exclusive(&lock_file)
        .map_err(|error| format!("could not lock model registry: {error}"))?;
    Ok(RegistryTransaction {
        _lock_file: lock_file,
    })
}

/// Apply one registry mutation while holding the cross-process lock. The
/// closure must remain local and bounded; network work belongs outside it.
pub fn update_registry<T>(
    update: impl FnOnce(&mut ModelRegistry) -> Result<T, String>,
) -> Result<T, String> {
    let transaction = lock_registry()?;
    let mut registry = transaction.load()?;
    let result = update(&mut registry)?;
    transaction.save(&registry)?;
    Ok(result)
}

/// A license acceptance explicitly confirmed by the user before an installer
/// sends a network request. The exact catalog identity is retained for audit.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedModelLicense {
    pub model_id: String,
    pub revision: String,
    pub license_id: String,
    pub license_url: String,
}

impl Default for ModelRegistry {
    fn default() -> Self {
        Self {
            schema: REGISTRY_SCHEMA.to_owned(),
            schema_version: REGISTRY_SCHEMA_VERSION,
            accepted_licenses: Vec::new(),
            custom_models: Vec::new(),
            selected_by_task: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedModel {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
    pub source: ModelSource,
    pub license_id: Option<String>,
    pub evaluation: EvaluationStatus,
    pub recommended: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModelSource {
    Catalog {
        repository: String,
        revision: String,
        filename: String,
    },
    UserProvided,
}

impl ModelRegistry {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(format!("model registry exceeds {MAX_REGISTRY_BYTES} bytes"));
        }
        let registry: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("could not parse model registry: {error}"))?;
        registry.validate()?;
        Ok(registry)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| format!("could not serialize model registry: {error}"))?;
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(format!("model registry exceeds {MAX_REGISTRY_BYTES} bytes"));
        }
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != REGISTRY_SCHEMA || self.schema_version != REGISTRY_SCHEMA_VERSION {
            return Err("model registry schema or version is unsupported".to_owned());
        }
        if self.custom_models.len() > MAX_REGISTERED_MODELS {
            return Err(format!(
                "model registry exceeds the {MAX_REGISTERED_MODELS} custom-model limit"
            ));
        }
        if self.accepted_licenses.len() > CATALOG.len() {
            return Err("model registry contains too many license acceptances".to_owned());
        }
        let mut accepted = std::collections::BTreeSet::new();
        for item in &self.accepted_licenses {
            let catalog = catalog_model(&item.model_id).ok_or_else(|| {
                "model registry contains an unknown license acceptance".to_owned()
            })?;
            if item.revision != catalog.revision
                || item.license_id != catalog.license_id
                || item.license_url != catalog.license_url
                || !accepted.insert(item.model_id.as_str())
            {
                return Err(
                    "model registry contains an invalid or duplicate license acceptance".to_owned(),
                );
            }
        }
        let mut ids = std::collections::BTreeSet::new();
        for model in &self.custom_models {
            validate_custom_model(model)?;
            if !ids.insert(model.id.as_str()) || catalog_model(&model.id).is_some() {
                return Err("model registry contains a duplicate or reserved model ID".to_owned());
            }
        }
        for (task, id) in &self.selected_by_task {
            if id.len() > 96 || !is_safe_id(id) || !model_supports(task, id, &self.custom_models) {
                return Err("selected model ID is invalid or unsupported for its task".to_owned());
            }
        }
        Ok(())
    }

    /// Register a user-provided local GGUF. This validates only file identity
    /// and size; it does not establish compatibility, license, or quality.
    pub fn register_custom(
        &mut self,
        name: &str,
        path: &Path,
        license_id: Option<&str>,
        tasks: Vec<ModelTask>,
    ) -> Result<String, String> {
        validate_name(name)?;
        if tasks.is_empty() || tasks.len() > 3 {
            return Err("a custom model must be assigned at least one supported task".to_owned());
        }
        if let Some(license) = license_id {
            validate_name(license)?;
        }
        let (canonical_path, size_bytes, sha256) = inspect_model_file(path, &tasks)?;
        if self.custom_models.len() >= MAX_REGISTERED_MODELS {
            return Err(format!(
                "model registry already has {MAX_REGISTERED_MODELS} custom models"
            ));
        }
        let id = custom_model_id(&sha256);
        if self.custom_models.iter().any(|model| model.id == id) {
            return Err("this custom model is already registered".to_owned());
        }
        let mut normalized_tasks = tasks;
        normalized_tasks.sort();
        normalized_tasks.dedup();
        self.custom_models.push(RegisteredModel {
            id: id.clone(),
            name: name.to_owned(),
            path: canonical_path,
            size_bytes,
            sha256,
            license_id: license_id.map(str::to_owned),
            tasks: normalized_tasks,
        });
        self.validate()?;
        Ok(id)
    }

    pub fn select(&mut self, task: ModelTask, id: &str) -> Result<(), String> {
        if !model_supports(&task, id, &self.custom_models) {
            return Err("model is unknown or is not registered for this task".to_owned());
        }
        self.selected_by_task.insert(task, id.to_owned());
        Ok(())
    }

    /// Record the exact catalog license only after an explicit positive answer.
    /// Callers must persist this before making the first request.
    pub fn accept_catalog_license(
        &mut self,
        model_id: &str,
        revision: &str,
        license_id: &str,
        license_url: &str,
        affirmative: bool,
    ) -> Result<(), String> {
        if !affirmative {
            return Err("model installation requires explicit license acceptance".to_owned());
        }
        let catalog = catalog_model(model_id)
            .ok_or_else(|| "model ID is not in the built-in catalog".to_owned())?;
        if catalog.revision != revision
            || catalog.license_id != license_id
            || catalog.license_url != license_url
        {
            return Err("license acceptance does not match the pinned catalog entry".to_owned());
        }
        if self.accepted_licenses.iter().any(|accepted| {
            accepted.model_id == model_id
                && accepted.revision == revision
                && accepted.license_id == license_id
                && accepted.license_url == license_url
        }) {
            return Ok(());
        }
        if self.accepted_licenses.len() >= CATALOG.len() {
            return Err("model registry license acceptance limit reached".to_owned());
        }
        self.accepted_licenses.push(AcceptedModelLicense {
            model_id: model_id.to_owned(),
            revision: revision.to_owned(),
            license_id: license_id.to_owned(),
            license_url: license_url.to_owned(),
        });
        self.accepted_licenses.sort();
        self.validate()
    }

    /// Unregister a custom model. A catalog model is immutable and cannot be
    /// removed; selected references are cleared, but the file is left alone.
    pub fn unregister(&mut self, id: &str) -> Result<(), String> {
        let before = self.custom_models.len();
        self.custom_models.retain(|model| model.id != id);
        if before == self.custom_models.len() {
            return Err("custom model ID was not registered".to_owned());
        }
        self.selected_by_task.retain(|_, selected| selected != id);
        Ok(())
    }

    pub fn selected(&self, task: ModelTask) -> Result<ResolvedModel, String> {
        let id = self
            .selected_by_task
            .get(&task)
            .ok_or_else(|| "no model is selected for this task".to_owned())?;
        self.resolve(id, task)
    }

    pub fn resolve(&self, id: &str, task: ModelTask) -> Result<ResolvedModel, String> {
        if let Some(catalog) = catalog_model(id) {
            if catalog.task != task {
                return Err("catalog model is not registered for this task".to_owned());
            }
            let path = ensure_private_model_directory()?.join(catalog.filename);
            let (path, size_bytes, sha256) = inspect_model_file(&path, &[task])?;
            if size_bytes != catalog.size_bytes || sha256 != catalog.sha256 {
                return Err("catalog model file failed its pinned size or SHA-256 check".to_owned());
            }
            return Ok(ResolvedModel {
                id: catalog.id.to_owned(),
                name: catalog.name.to_owned(),
                path,
                size_bytes,
                sha256,
                source: ModelSource::Catalog {
                    repository: catalog.repository.to_owned(),
                    revision: catalog.revision.to_owned(),
                    filename: catalog.filename.to_owned(),
                },
                license_id: Some(catalog.license_id.to_owned()),
                evaluation: catalog.evaluation,
                recommended: false,
            });
        }
        let model = self
            .custom_models
            .iter()
            .find(|model| model.id == id)
            .ok_or_else(|| "model ID is not known".to_owned())?;
        if !model.tasks.contains(&task) {
            return Err("custom model is not registered for this task".to_owned());
        }
        let (path, size_bytes, sha256) = inspect_model_file(&model.path, &model.tasks)?;
        if size_bytes != model.size_bytes || sha256 != model.sha256 {
            return Err("registered custom model changed since it was added".to_owned());
        }
        Ok(ResolvedModel {
            id: model.id.clone(),
            name: model.name.clone(),
            path,
            size_bytes,
            sha256,
            source: ModelSource::UserProvided,
            license_id: model.license_id.clone(),
            evaluation: EvaluationStatus::NotAssessed,
            recommended: false,
        })
    }
}

pub fn catalog_model(id: &str) -> Option<&'static CatalogModel> {
    CATALOG.iter().find(|model| model.id == id)
}

pub fn model_store_directory() -> Result<PathBuf, String> {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "LOCALAPPDATA is unavailable; cannot locate the model store".to_owned())?;

    #[cfg(not(windows))]
    let base = match std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        Some(value) => PathBuf::from(value),
        None => std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| "HOME is unavailable; cannot locate the model store".to_owned())?
            .join(".local")
            .join("share"),
    };
    if !base.is_absolute() {
        return Err("user data directory must be an absolute path".to_owned());
    }
    Ok(base.join("SideEffect"))
}

pub fn registry_path() -> Result<PathBuf, String> {
    Ok(model_store_directory()?.join("model-registry.json"))
}

/// Return the model weights directory after creating it with private access
/// controls. Download code must use this location and still publish files
/// with exclusive/no-clobber semantics after digest verification.
pub fn ensure_private_model_directory() -> Result<PathBuf, String> {
    let path = model_store_directory()?.join("models");
    ensure_private_store_directory(&path)?;
    Ok(path)
}

/// Create an exclusive staging file in the private model directory.
pub(crate) fn create_model_stage(path: &Path) -> std::io::Result<File> {
    create_registry_stage(path)
}

/// Verify inherited Windows ACLs on a staged model before publication.
pub(crate) fn verify_model_stage_acl(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    apply_and_verify_current_user_acl(path, false)?;
    let _ = path;
    Ok(())
}

/// Load the per-user selection file with strict schema and byte bounds.
/// Missing configuration is an empty registry; malformed or inaccessible
/// existing files are errors and are never silently overwritten.
pub fn load_registry() -> Result<ModelRegistry, String> {
    let path = registry_path()?;
    ensure_private_store_directory(
        path.parent()
            .ok_or_else(|| "model registry path has no parent directory".to_owned())?,
    )?;
    load_registry_unlocked()
}

fn load_registry_unlocked() -> Result<ModelRegistry, String> {
    let path = registry_path()?;
    let mut file = match open_registry_read(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ModelRegistry::default());
        }
        Err(error) => return Err(format!("could not open model registry: {error}")),
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_REGISTRY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read model registry: {error}"))?;
    ModelRegistry::from_json(&bytes)
}

/// Save the per-user registry through an exclusive sibling staging file and
/// same-directory rename. Call only while a RegistryTransaction is held.
fn save_registry_unlocked(registry: &ModelRegistry) -> Result<(), String> {
    let bytes = registry.to_json()?;
    let path = registry_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| "model registry path has no parent directory".to_owned())?;
    ensure_private_store_directory(parent)?;
    validate_registry_destination(&path)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?
        .as_nanos();
    let staged = parent.join(format!(
        ".model-registry-{}-{nonce:x}.tmp",
        std::process::id()
    ));
    let mut file = create_registry_stage(&staged).map_err(|error| {
        format!("could not create private model registry staging file: {error}")
    })?;
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|error| format!("could not write model registry: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("could not flush model registry: {error}"))?;
        drop(file);
        #[cfg(windows)]
        apply_and_verify_current_user_acl(&staged, false)?;
        publish_registry(&staged, &path)
            .map_err(|error| format!("could not publish model registry: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

fn validate_custom_model(model: &RegisteredModel) -> Result<(), String> {
    if !is_safe_id(&model.id) || !model.id.starts_with("custom-") {
        return Err("custom model ID is invalid".to_owned());
    }
    validate_name(&model.name)?;
    if model.path.as_os_str().to_string_lossy().len() > MAX_MODEL_PATH_BYTES
        || !model.path.is_absolute()
    {
        return Err("custom model path is invalid or too long".to_owned());
    }
    if model.size_bytes == 0
        || model.size_bytes > MAX_MODEL_FILE_BYTES
        || model
            .tasks
            .iter()
            .any(|task| model.size_bytes > max_bytes_for_task(*task))
    {
        return Err("custom model size is outside the supported file limit".to_owned());
    }
    if !is_sha256(&model.sha256) || model.tasks.is_empty() || model.tasks.len() > 3 {
        return Err("custom model hash or task list is invalid".to_owned());
    }
    if let Some(license) = &model.license_id {
        validate_name(license)?;
    }
    let mut unique_tasks = model.tasks.clone();
    unique_tasks.sort();
    unique_tasks.dedup();
    if unique_tasks.len() != model.tasks.len() {
        return Err("custom model task list contains duplicates".to_owned());
    }
    Ok(())
}

fn validate_name(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_MODEL_NAME_BYTES || value.chars().any(char::is_control)
    {
        return Err(
            "model name or license ID is empty, oversized, or contains control characters"
                .to_owned(),
        );
    }
    Ok(())
}

fn is_safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn custom_model_id(sha256: &str) -> String {
    format!("custom-{}", &sha256[..16])
}

fn model_supports(task: &ModelTask, id: &str, custom: &[RegisteredModel]) -> bool {
    if let Some(model) = catalog_model(id) {
        return &model.task == task;
    }
    custom
        .iter()
        .any(|model| model.id == id && model.tasks.contains(task))
}

fn max_bytes_for_task(task: ModelTask) -> u64 {
    match task {
        ModelTask::EvidenceSelection => 512 * 1024 * 1024,
        ModelTask::Explanation => 3 * 1024 * 1024 * 1024,
        ModelTask::QueryPlan => 1_610_612_736,
    }
}

fn inspect_model_file(path: &Path, tasks: &[ModelTask]) -> Result<(PathBuf, u64, String), String> {
    if tasks.is_empty() || tasks.len() > 3 {
        return Err("model task list is empty or oversized".to_owned());
    }
    let task_limit = tasks
        .iter()
        .map(|task| max_bytes_for_task(*task))
        .min()
        .unwrap();
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect local model path: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("model path must identify a plain regular file, not a symlink".to_owned());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("model path must not be a Windows reparse point".to_owned());
        }
    }
    if metadata.len() == 0 || metadata.len() > task_limit {
        return Err(format!(
            "model file must be between 1 and {task_limit} bytes for the selected task"
        ));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("could not resolve local model path: {error}"))?;
    if canonical.as_os_str().to_string_lossy().len() > MAX_MODEL_PATH_BYTES {
        return Err("model path exceeds its maximum length".to_owned());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        };
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options
            .open(&canonical)
            .map_err(|error| format!("could not open local model file: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("could not inspect open local model file: {error}"))?;
        use std::os::windows::fs::MetadataExt;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("model path resolves to a reparse point or non-file".to_owned());
        }
        hash_model_file(file, canonical, metadata.len(), task_limit)
    }
    #[cfg(not(windows))]
    {
        let file = options
            .open(&canonical)
            .map_err(|error| format!("could not open local model file: {error}"))?;
        let opened_metadata = file
            .metadata()
            .map_err(|error| format!("could not inspect open local model file: {error}"))?;
        if !opened_metadata.is_file() || opened_metadata.len() > task_limit {
            return Err("opened model is not a bounded regular file".to_owned());
        }
        hash_model_file(file, canonical, opened_metadata.len(), task_limit)
    }
}

fn hash_model_file(
    mut file: File,
    canonical: PathBuf,
    initial_size: u64,
    task_limit: u64,
) -> Result<(PathBuf, u64, String), String> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    let mut header_checked = false;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("could not read local model file: {error}"))?;
        if read == 0 {
            break;
        }
        if !header_checked {
            if read < 8
                || &buffer[..4] != b"GGUF"
                || !matches!(
                    u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                    2 | 3
                )
            {
                return Err("model file does not have a supported GGUF v2/v3 header".to_owned());
            }
            header_checked = true;
        }
        total = total.saturating_add(read as u64);
        if total > task_limit {
            return Err(
                "model file exceeded the task-specific file limit while hashing".to_owned(),
            );
        }
        hasher.update(&buffer[..read]);
    }
    if total == 0 || total != initial_size {
        return Err("model file changed size while it was being hashed".to_owned());
    }
    Ok((canonical, total, hex_digest(hasher.finalize().as_slice())))
}

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

#[cfg(target_os = "linux")]
fn ensure_private_store_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let parent = path
        .parent()
        .ok_or_else(|| "model store directory has no parent".to_owned())?;
    ensure_private_store_parent_directory(parent)?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("could not inspect model store parent directory: {error}"))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(
            "model store parent must be a current-user-owned directory not writable by other users"
                .to_owned(),
        );
    }
    fs::create_dir_all(path)
        .map_err(|error| format!("could not create model store directory: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect model store directory: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err("model store must be a current-user-owned plain directory".to_owned());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("could not restrict model store directory: {error}"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("could not verify model store parent directory: {error}"))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(
            "model store parent directory changed or is writable by other users".to_owned(),
        );
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not verify model store directory: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err("model store directory is not private to the current user".to_owned());
    }
    Ok(())
}

/// Safely prepare missing per-user data directories without following a
/// symlink or accepting a writable shared ancestor. Existing root-owned
/// ancestors are allowed when they are not writable by other users; sticky
/// root-owned temporary directories are also safe parents for a private user
/// directory.
#[cfg(target_os = "linux")]
fn ensure_private_store_parent_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err("model store path must not contain dot segments".to_owned());
    }

    let current_uid = unsafe { libc::geteuid() };
    let mut missing = Vec::new();
    let mut cursor = path.to_path_buf();
    loop {
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) => {
                let root_sticky_directory = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || (metadata.uid() != current_uid && metadata.uid() != 0)
                    || (metadata.mode() & 0o022 != 0 && !root_sticky_directory)
                {
                    return Err(
                        "model store path contains an unsafe or writable shared directory"
                            .to_owned(),
                    );
                }
                if !cursor.pop() {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.clone());
                if !cursor.pop() {
                    return Err("model store path has no existing ancestor".to_owned());
                }
            }
            Err(error) => {
                return Err(format!("could not inspect model store path: {error}"));
            }
        }
    }

    for directory in missing.iter().rev() {
        match fs::create_dir(directory) {
            Ok(()) => fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("could not restrict model data directory: {error}"))?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!("could not create model data directory: {error}"));
            }
        }
        let metadata = fs::symlink_metadata(directory)
            .map_err(|error| format!("could not inspect model data directory: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != current_uid
            || metadata.mode() & 0o077 != 0
        {
            return Err("new model data directory is not private to the current user".to_owned());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_private_store_directory(path: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    fs::create_dir_all(path)
        .map_err(|error| format!("could not create model store directory: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect model store directory: {error}"))?;
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.is_dir()
    {
        return Err("model store must be a plain directory, not a reparse point".to_owned());
    }
    apply_and_verify_current_user_acl(path, true)
}

#[cfg(target_os = "linux")]
fn validate_registry_destination(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0 =>
        {
            Err("model registry destination must be a private current-user regular file".to_owned())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "could not inspect model registry destination: {error}"
        )),
    }
}

#[cfg(windows)]
fn apply_and_verify_current_user_acl(path: &Path, is_directory: bool) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE,
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetTokenInformation, OBJECT_INHERIT_ACE,
        PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct LocalGuard(*mut std::ffi::c_void);
    impl Drop for LocalGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: this pointer was returned by a LocalAlloc-backed API.
                unsafe { LocalFree(self.0) };
            }
        }
    }
    struct TokenGuard(HANDLE);
    impl Drop for TokenGuard {
        fn drop(&mut self) {
            // SAFETY: OpenProcessToken returned this owned handle.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }

    let mut token = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; token is an output pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(format!(
            "could not open the current user's token for model-store ACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    let token_guard = TokenGuard(token);
    let mut needed = 0_u32;
    // SAFETY: the null buffer/zero length call is the documented size query.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 || needed as usize > 64 * 1024 {
        return Err("could not determine the current user's token size".to_owned());
    }
    let mut token_buffer = vec![0_usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: the aligned buffer is large enough for the requested token record.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            token_buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(format!(
            "could not read the current user's SID for model-store ACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    let token_user = token_buffer.as_ptr().cast::<TOKEN_USER>();
    let mut sid_text = std::ptr::null_mut();
    // SAFETY: token_user is initialized by GetTokenInformation above.
    if unsafe { ConvertSidToStringSidW((*token_user).User.Sid, &mut sid_text) } == 0 {
        return Err(format!(
            "could not encode the current user's SID: {}",
            std::io::Error::last_os_error()
        ));
    }
    let sid_guard = LocalGuard(sid_text.cast());
    let mut sid_len = 0_usize;
    while sid_len < 256 && unsafe { *sid_text.add(sid_len) } != 0 {
        sid_len += 1;
    }
    if sid_len == 0 || sid_len >= 256 {
        return Err("the current user's SID string is empty or oversized".to_owned());
    }
    // SAFETY: SID text is nul-terminated and bounded above.
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, sid_len) })
        .map_err(|_| "the current user's SID string is invalid UTF-16".to_owned())?;
    let sddl = if is_directory {
        format!("D:P(A;OICI;FA;;;{sid})")
    } else {
        format!("D:P(A;;FA;;;{sid})")
    };
    let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: sddl_wide is a valid nul-terminated SDDL descriptor string.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(format!(
            "could not build current-user-only model-store ACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    let descriptor_guard = LocalGuard(descriptor.cast());
    let mut dacl_present = 0;
    let mut dacl = std::ptr::null_mut::<ACL>();
    let mut dacl_defaulted = 0;
    // SAFETY: descriptor was created by ConvertStringSecurityDescriptorToSecurityDescriptorW.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || dacl.is_null()
    {
        return Err("could not extract the current-user model-store DACL".to_owned());
    }
    let path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: path_wide and the self-relative descriptor remain valid during the call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(format!(
            "could not restrict the model-store directory to the current user: {}",
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }

    let mut actual_dacl = std::ptr::null_mut::<ACL>();
    let mut actual_descriptor = std::ptr::null_mut();
    // SAFETY: GetNamedSecurityInfoW fills output pointers; requested data is bounded ACL metadata.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut actual_dacl,
            std::ptr::null_mut(),
            &mut actual_descriptor,
        )
    };
    if status != 0 || actual_descriptor.is_null() || actual_dacl.is_null() {
        return Err(format!(
            "could not verify the model-store directory ACL: {}",
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    let actual_guard = LocalGuard(actual_descriptor.cast());
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: actual_descriptor was allocated and populated by GetNamedSecurityInfoW.
    if unsafe { GetSecurityDescriptorControl(actual_descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err("model-store DACL is not protected from parent inheritance".to_owned());
    }
    let mut acl_info = ACL_SIZE_INFORMATION::default();
    // SAFETY: actual_dacl is owned by actual_descriptor and ACL_SIZE_INFORMATION is writable.
    if unsafe {
        GetAclInformation(
            actual_dacl,
            (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            2,
        )
    } == 0
        || acl_info.AceCount != 1
    {
        return Err("model-store DACL must contain exactly one current-user ACE".to_owned());
    }
    let mut ace = std::ptr::null_mut();
    // SAFETY: index 0 exists because AceCount was verified as 1.
    if unsafe { GetAce(actual_dacl, 0, &mut ace) } == 0 || ace.is_null() {
        return Err("could not inspect the model-store DACL entry".to_owned());
    }
    let ace_header = unsafe { &*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
    let allowed_ace_type = 0_u8; // ACCESS_ALLOWED_ACE_TYPE
    let expected_inheritance_flags = if is_directory {
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
    } else {
        0
    };
    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    let ace_sid = (&allowed.SidStart as *const u32).cast_mut().cast();
    // SAFETY: ACE was returned by GetAce from a verified ACL; its SID begins at SidStart.
    let sid_matches =
        unsafe { windows_sys::Win32::Security::EqualSid((*token_user).User.Sid, ace_sid) } != 0;
    if ace_header.AceType != allowed_ace_type
        || ace_header.AceFlags != expected_inheritance_flags
        || allowed.Mask != FILE_ALL_ACCESS
        || !sid_matches
    {
        return Err("model-store DACL is not restricted to the current user".to_owned());
    }
    drop(actual_guard);
    drop(descriptor_guard);
    drop(sid_guard);
    drop(token_guard);
    Ok(())
}

#[cfg(windows)]
fn validate_registry_destination(path: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || !metadata.is_file() =>
        {
            Err("model registry destination must be a plain regular file".to_owned())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "could not inspect model registry destination: {error}"
        )),
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn validate_registry_destination(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err("model registry destination must be a plain regular file".to_owned())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "could not inspect model registry destination: {error}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn open_registry_read(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(std::io::Error::other(
            "model registry is not a private current-user regular file",
        ));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_registry_lock(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(std::io::Error::other(
            "model registry lock is not a private current-user regular file",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn open_registry_read(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other(
            "model registry is not a plain regular file",
        ));
    }
    apply_and_verify_current_user_acl(path, false).map_err(std::io::Error::other)?;
    Ok(file)
}

#[cfg(windows)]
fn open_registry_lock(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other(
            "model registry lock is not a plain regular file",
        ));
    }
    apply_and_verify_current_user_acl(path, false).map_err(std::io::Error::other)?;
    Ok(file)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn open_registry_read(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn open_registry_lock(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
}

#[cfg(target_os = "linux")]
fn create_registry_stage(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(windows)]
fn create_registry_stage(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn create_registry_stage(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(not(windows))]
fn publish_registry(staged: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(staged, destination)
}

#[cfg(windows)]
fn publish_registry(staged: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let staged_wide: Vec<u16> = staged.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both nul-terminated paths live for the duration of the call.
    if unsafe {
        MoveFileExW(
            staged_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod private_store_parent_tests {
    use super::ensure_private_store_parent_directory;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            loop {
                let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "sideeffect-private-model-parent-{}-{id}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                        return Self(path);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create temporary test directory: {error}"),
                }
            }
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn creates_missing_private_data_directory_components() {
        let root = TempDirectory::new();
        let parent = root.0.join(".local").join("share");
        ensure_private_store_parent_directory(&parent).unwrap();
        for directory in [root.0.join(".local"), parent] {
            let metadata = fs::symlink_metadata(directory).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }
    }

    #[test]
    fn rejects_a_symlink_in_the_model_store_path() {
        let root = TempDirectory::new();
        let target = root.0.join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let link = root.0.join("link");
        symlink(&target, &link).unwrap();
        assert!(ensure_private_store_parent_directory(&link.join("share")).is_err());
        assert!(!target.join("share").exists());
    }

    #[test]
    fn rejects_dot_segments_in_the_model_store_path() {
        let root = TempDirectory::new();
        let path = root.0.join("..").join("outside");
        assert!(ensure_private_store_parent_directory(&path).is_err());
    }
}
