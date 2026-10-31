//! Pinned, bounded subprocess execution for local evidence explanations.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use crate::local_model_explanation::{
    EXPLANATION_MODEL_FILENAME, EXPLANATION_MODEL_SHA256, EXPLANATION_MODEL_SIZE_BYTES,
    EXPLANATION_RUNTIME_REVISION, ExplanationBackendPreference, LocalModelExplanation,
    LocalModelExplanationPreview,
};

const MAX_RUNTIME_DIAGNOSTIC_BYTES: usize = 16 * 1024;
const MAX_RUNTIME_OUTPUT_BYTES: usize = 64 * 1024;
const MODEL_TIMEOUT_SECONDS: u64 = 120;
const MODEL_CONTEXT_TOKENS: &str = "8192";
const MODEL_OUTPUT_TOKENS: &str = "512";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const MODEL_PROCESS_MEMORY_LIMIT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
#[cfg(windows)]
const MODEL_PROCESS_MEMORY_LIMIT_BYTES: u64 = 6 * 1024 * 1024 * 1024;

/// A bounded explanation-runtime readiness report. This checks the selected
/// executable and, unless CPU was requested, asks the runtime to enumerate
/// devices. It never opens model weights or runs inference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExplanationRuntimeDoctorReport {
    pub runtime_path: String,
    pub expected_source_revision: &'static str,
    pub executable_status: &'static str,
    pub executable_diagnostic: Option<String>,
    pub requested_backend: ExplanationBackendPreference,
    pub cuda_device_status: &'static str,
    pub device_diagnostic: Option<String>,
    pub backend_readiness: &'static str,
    /// Device enumeration is not proof that a model successfully ran on CUDA.
    pub gpu_inference_status: &'static str,
}

pub fn doctor_explanation_runtime(
    runtime_path: &Path,
    backend: ExplanationBackendPreference,
) -> ExplanationRuntimeDoctorReport {
    let path_text = runtime_path.to_string_lossy().into_owned();
    let mut report = ExplanationRuntimeDoctorReport {
        runtime_path: path_text,
        expected_source_revision: EXPLANATION_RUNTIME_REVISION,
        executable_status: "not_checked",
        executable_diagnostic: None,
        requested_backend: backend,
        cuda_device_status: if backend == ExplanationBackendPreference::Cpu {
            "not_checked_cpu_requested"
        } else {
            "not_checked"
        },
        device_diagnostic: None,
        backend_readiness: "blocked_runtime_not_checked",
        gpu_inference_status: "not_run",
    };

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let runtime = match crate::local_model::canonical_regular_file(runtime_path, "runtime") {
        Ok(path) => path,
        Err(error) => {
            report.executable_status = "unavailable";
            report.executable_diagnostic = Some(error);
            return report;
        }
    };
    #[cfg(windows)]
    let runtime = match canonical_regular_file(runtime_path, "runtime") {
        Ok(path) => path,
        Err(error) => {
            report.executable_status = "unavailable";
            report.executable_diagnostic = Some(error);
            return report;
        }
    };
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64"), windows)))]
    let runtime = {
        report.executable_status = "unsupported_platform";
        report.executable_diagnostic = Some(
            "local explanation runtime checks support Linux x86_64 and native Windows only"
                .to_owned(),
        );
        return report;
        #[allow(unreachable_code)]
        std::path::PathBuf::new()
    };

    report.runtime_path = runtime.to_string_lossy().into_owned();

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let version_check = verify_runtime(&runtime, |arguments| {
        crate::local_model_runtime::run_bounded(
            &runtime,
            arguments,
            None,
            10,
            MAX_RUNTIME_DIAGNOSTIC_BYTES,
        )
    });
    #[cfg(windows)]
    let version_check = verify_runtime(&runtime, |arguments| {
        crate::local_model_runtime::run_bounded_windows(
            &runtime,
            arguments,
            None,
            std::time::Duration::from_secs(10),
            MAX_RUNTIME_DIAGNOSTIC_BYTES,
            1024 * 1024 * 1024,
        )
    });
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64"), windows)))]
    let version_check: Result<(), String> = unreachable!();

    if let Err(error) = version_check {
        report.executable_status = "revision_or_version_check_failed";
        report.executable_diagnostic = Some(error);
        report.backend_readiness = "blocked_runtime_check_failed";
        return report;
    }

    report.executable_status = "verified_revision_prefix";
    if backend == ExplanationBackendPreference::Cpu {
        report.backend_readiness = "ready_cpu_requested";
        return report;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let device_check = list_cuda_devices(
        &runtime,
        |arguments| {
            crate::local_model_runtime::run_bounded(
                &runtime,
                arguments,
                None,
                10,
                MAX_RUNTIME_DIAGNOSTIC_BYTES,
            )
        },
        ExplanationBackendPreference::Auto,
    );
    #[cfg(windows)]
    let device_check = list_cuda_devices(
        &runtime,
        |arguments| {
            crate::local_model_runtime::run_bounded_windows(
                &runtime,
                arguments,
                None,
                std::time::Duration::from_secs(10),
                MAX_RUNTIME_DIAGNOSTIC_BYTES,
                1024 * 1024 * 1024,
            )
        },
        ExplanationBackendPreference::Auto,
    );
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64"), windows)))]
    let device_check: Result<bool, String> = unreachable!();

    match device_check {
        Ok(true) => {
            report.cuda_device_status = "reported_available";
            report.backend_readiness = "ready_cuda_device_reported_inference_not_run";
        }
        Ok(false) if backend == ExplanationBackendPreference::Auto => {
            report.cuda_device_status = "not_reported";
            report.backend_readiness = "ready_cpu_auto_selected_without_cuda_device";
        }
        Ok(false) => {
            report.cuda_device_status = "not_reported";
            report.backend_readiness = "blocked_cuda_device_not_reported";
        }
        Err(error) => {
            report.cuda_device_status = "enumeration_failed";
            report.backend_readiness = "blocked_device_enumeration_failed";
            report.device_diagnostic = Some(error);
        }
    }

    report
}

pub fn analyze_model_explanation_bytes(
    trace_bytes: &[u8],
    question: &str,
    backend_preference: ExplanationBackendPreference,
    runtime_path: &Path,
    model_path: &Path,
    confirmed_request_sha256: &str,
) -> Result<LocalModelExplanation, String> {
    let selected = crate::model_manager::ResolvedModel {
        id: "pinned-evidence-explanation".to_owned(),
        name: "Pinned evidence explanation model".to_owned(),
        path: model_path.to_path_buf(),
        size_bytes: EXPLANATION_MODEL_SIZE_BYTES,
        sha256: EXPLANATION_MODEL_SHA256.to_owned(),
        source: crate::model_manager::ModelSource::Catalog {
            repository: crate::local_model_explanation::EXPLANATION_MODEL_REPOSITORY.to_owned(),
            revision: crate::local_model_explanation::EXPLANATION_MODEL_REVISION.to_owned(),
            filename: crate::local_model_explanation::EXPLANATION_MODEL_FILENAME.to_owned(),
        },
        license_id: Some("Apache-2.0".to_owned()),
        evaluation: crate::model_manager::EvaluationStatus::NotAssessed,
        recommended: false,
    };
    analyze_model_explanation_bytes_with_model(
        trace_bytes,
        question,
        backend_preference,
        runtime_path,
        model_path,
        &selected,
        confirmed_request_sha256,
    )
}

pub fn analyze_model_explanation_bytes_for_model(
    trace_bytes: &[u8],
    question: &str,
    backend_preference: ExplanationBackendPreference,
    runtime_path: &Path,
    model: &crate::model_manager::ResolvedModel,
    confirmed_request_sha256: &str,
) -> Result<LocalModelExplanation, String> {
    analyze_model_explanation_bytes_with_model(
        trace_bytes,
        question,
        backend_preference,
        runtime_path,
        &model.path,
        model,
        confirmed_request_sha256,
    )
}

fn analyze_model_explanation_bytes_with_model(
    trace_bytes: &[u8],
    question: &str,
    backend_preference: ExplanationBackendPreference,
    runtime_path: &Path,
    model_path: &Path,
    model: &crate::model_manager::ResolvedModel,
    confirmed_request_sha256: &str,
) -> Result<LocalModelExplanation, String> {
    let preview = crate::local_model_explanation::preview_model_explanation_bytes_for_model(
        trace_bytes,
        question,
        backend_preference,
        model,
    )?;
    if confirmed_request_sha256 != preview.request_sha256 {
        return Err(format!(
            "preview digest mismatch; review model-explain-preview and confirm its request_sha256 ({})",
            preview.request_sha256
        ));
    }

    if let Some(reason) = preview.deterministic_abstain_reason {
        let interpretation = crate::local_model_explanation::derive_selected_facts(
            Vec::new(),
            &preview.prompt,
            &preview.evidence_summary,
            Some(reason),
        )?;
        return Ok(LocalModelExplanation {
            schema: "sideeffect.local_model_explanation",
            schema_version: crate::local_model_explanation::LOCAL_MODEL_EXPLANATION_SCHEMA_VERSION,
            interpretation_label: "local_model_selection_abstained",
            request_sha256: preview.request_sha256,
            backend_used: "not_run",
            backend_status: "deterministic_scope_abstention",
            runtime_containment_note: "No model runtime was started for this deterministic scope abstention.",
            model_id: preview.model_id,
            model_sha256: preview.model_sha256,
            model_source: preview.model_source,
            license_id: preview.license_id,
            license_status: preview.license_status,
            evaluation_status: preview.evaluation_status,
            model_revision: preview.model_revision,
            runtime_source_revision: preview.runtime_source_revision,
            runtime_version: preview.runtime_version,
            backend: preview.backend,
            evidence_summary: preview.evidence_summary,
            interpretation,
        });
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        run_linux(preview, runtime_path, model_path)
    }
    #[cfg(windows)]
    {
        run_windows(preview, runtime_path, model_path)
    }
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64"), windows)))]
    {
        let _ = (runtime_path, model_path);
        Err("local model explanation supports Linux x86_64 and native Windows only".to_owned())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_linux(
    preview: LocalModelExplanationPreview,
    runtime_path: &Path,
    model_path: &Path,
) -> Result<LocalModelExplanation, String> {
    use crate::local_model::{canonical_regular_file, copy_verified_model};
    use crate::local_model_runtime::{
        TempDirectory, create_private_temp_dir, run_bounded, run_bounded_with_address_space_limit,
        write_private_file,
    };
    let runtime = canonical_regular_file(runtime_path, "runtime")?;
    let model = canonical_regular_file(model_path, "model")?;
    verify_runtime(&runtime, |arguments| {
        run_bounded(&runtime, arguments, None, 10, MAX_RUNTIME_DIAGNOSTIC_BYTES)
    })?;
    let cuda_available = list_cuda_devices(
        &runtime,
        |arguments| run_bounded(&runtime, arguments, None, 10, MAX_RUNTIME_DIAGNOSTIC_BYTES),
        preview.backend_preference,
    )?;
    let (use_cuda, backend_status) = choose_backend(preview.backend_preference, cuda_available)?;

    let temporary = create_private_temp_dir()?;
    let _temporary_guard = TempDirectory(temporary.clone());
    let staged_model = temporary.join(EXPLANATION_MODEL_FILENAME);
    copy_verified_model(
        &model,
        &staged_model,
        &preview.model_sha256,
        preview.model_size_bytes,
    )?;
    verify_staged_model_size(&staged_model)?;
    let (prompt_path, system_prompt_path, schema_path) =
        stage_prompt_files(&temporary, &preview, |path, bytes| {
            write_private_file(path, bytes)
        })?;
    let arguments = runtime_arguments(
        &staged_model,
        &prompt_path,
        &system_prompt_path,
        &schema_path,
        use_cuda,
    )?;
    let result = run_bounded_with_address_space_limit(
        &runtime,
        &arguments,
        Some(&temporary),
        MODEL_TIMEOUT_SECONDS,
        MAX_RUNTIME_OUTPUT_BYTES,
        MODEL_PROCESS_MEMORY_LIMIT_BYTES,
    )?;
    finish_inference(preview, result, use_cuda, backend_status)
}

#[cfg(windows)]
fn run_windows(
    preview: LocalModelExplanationPreview,
    runtime_path: &Path,
    model_path: &Path,
) -> Result<LocalModelExplanation, String> {
    use crate::local_model_runtime::{
        copy_verified_model_windows, create_private_temp_dir_windows, run_bounded_windows,
        write_private_file_windows,
    };
    use std::time::Duration;

    let runtime = canonical_regular_file(runtime_path, "runtime")?;
    let model = canonical_regular_file(model_path, "model")?;
    verify_runtime(&runtime, |arguments| {
        run_bounded_windows(
            &runtime,
            arguments,
            None,
            Duration::from_secs(10),
            MAX_RUNTIME_DIAGNOSTIC_BYTES,
            1024 * 1024 * 1024,
        )
    })?;
    let cuda_available = list_cuda_devices(
        &runtime,
        |arguments| {
            run_bounded_windows(
                &runtime,
                arguments,
                None,
                Duration::from_secs(10),
                MAX_RUNTIME_DIAGNOSTIC_BYTES,
                1024 * 1024 * 1024,
            )
        },
        preview.backend_preference,
    )?;
    let (use_cuda, backend_status) = choose_backend(preview.backend_preference, cuda_available)?;

    let temporary_guard = create_private_temp_dir_windows()?;
    let temporary = temporary_guard.path();
    let staged_model = temporary.join(EXPLANATION_MODEL_FILENAME);
    copy_verified_model_windows(
        &model,
        &staged_model,
        &preview.model_sha256,
        preview.model_size_bytes,
    )?;
    verify_staged_model_size(&staged_model)?;
    let (prompt_path, system_prompt_path, schema_path) =
        stage_prompt_files(temporary, &preview, |path, bytes| {
            write_private_file_windows(path, bytes)
        })?;
    let arguments = runtime_arguments(
        &staged_model,
        &prompt_path,
        &system_prompt_path,
        &schema_path,
        use_cuda,
    )?;
    let result = run_bounded_windows(
        &runtime,
        &arguments,
        Some(temporary),
        Duration::from_secs(MODEL_TIMEOUT_SECONDS),
        MAX_RUNTIME_OUTPUT_BYTES,
        MODEL_PROCESS_MEMORY_LIMIT_BYTES,
    )?;
    finish_inference(preview, result, use_cuda, backend_status)
}

fn verify_runtime<F, O>(runtime: &Path, mut run: F) -> Result<(), String>
where
    F: FnMut(&[std::ffi::OsString]) -> Result<O, String>,
    O: RuntimeOutputView,
{
    let output = run(&[std::ffi::OsString::from("--version")])?;
    let stdout = std::str::from_utf8(output.stdout_bytes())
        .map_err(|_| "selected local runtime version output is not UTF-8".to_owned())?;
    let stderr = std::str::from_utf8(output.stderr_bytes())
        .map_err(|_| "selected local runtime diagnostic output is not UTF-8".to_owned())?;
    let expected_commit = EXPLANATION_RUNTIME_REVISION.get(..9).unwrap_or("");
    let revision_reported = stdout
        .lines()
        .chain(stderr.lines())
        .any(|line| line.contains(expected_commit));
    if !output.success()
        || output.stdout_truncated()
        || output.stderr_truncated()
        || !revision_reported
    {
        return Err(format!(
            "selected local runtime failed the pinned llama.cpp version check (expected revision {}, successful exit {}, stdout truncated {}, stderr truncated {}, revision reported {})",
            EXPLANATION_RUNTIME_REVISION,
            output.success(),
            output.stdout_truncated(),
            output.stderr_truncated(),
            revision_reported,
        ));
    }
    let _ = runtime;
    Ok(())
}

fn list_cuda_devices<F, O>(
    runtime: &Path,
    mut run: F,
    preference: ExplanationBackendPreference,
) -> Result<bool, String>
where
    F: FnMut(&[std::ffi::OsString]) -> Result<O, String>,
    O: RuntimeOutputView,
{
    if preference == ExplanationBackendPreference::Cpu {
        return Ok(false);
    }
    let output = run(&[std::ffi::OsString::from("--list-devices")])?;
    if !output.success() || output.stdout_truncated() || output.stderr_truncated() {
        return Err("could not reliably enumerate local model devices".to_owned());
    }
    let stdout = String::from_utf8_lossy(output.stdout_bytes());
    let stderr = String::from_utf8_lossy(output.stderr_bytes());
    let available = stdout
        .lines()
        .chain(stderr.lines())
        .any(|line| line.trim_start().starts_with("CUDA0:"));
    if preference == ExplanationBackendPreference::Cuda && !available {
        return Err(
            "CUDA was requested, but the pinned local runtime reports no CUDA0 device".to_owned(),
        );
    }
    let _ = runtime;
    Ok(available)
}

fn choose_backend(
    preference: ExplanationBackendPreference,
    cuda_available: bool,
) -> Result<(bool, &'static str), String> {
    match preference {
        ExplanationBackendPreference::Cpu => Ok((false, "cpu_explicitly_selected")),
        ExplanationBackendPreference::Cuda if cuda_available => {
            Ok((true, "cuda_requested_device_available"))
        }
        ExplanationBackendPreference::Cuda => Err(
            "CUDA was requested, but the pinned local runtime reports no CUDA0 device".to_owned(),
        ),
        ExplanationBackendPreference::Auto if cuda_available => {
            Ok((true, "cuda_preferred_device_available"))
        }
        ExplanationBackendPreference::Auto => Ok((false, "cpu_used_no_cuda_device_available")),
    }
}

fn stage_prompt_files<F>(
    temporary: &Path,
    preview: &LocalModelExplanationPreview,
    mut write: F,
) -> Result<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf), String>
where
    F: FnMut(&Path, &[u8]) -> Result<(), String>,
{
    let prompt = temporary.join("model-prompt.json");
    let system_prompt = temporary.join("system-prompt.txt");
    let output_schema = temporary.join("output-schema.json");
    write(&prompt, preview.prompt.as_bytes())?;
    write(&system_prompt, preview.system_prompt.as_bytes())?;
    let schema_bytes = serde_json::to_vec(&preview.output_schema)
        .map_err(|_| "could not encode local explanation output schema".to_owned())?;
    write(&output_schema, &schema_bytes)?;
    Ok((prompt, system_prompt, output_schema))
}

fn runtime_arguments(
    staged_model: &Path,
    prompt: &Path,
    system_prompt: &Path,
    schema: &Path,
    use_cuda: bool,
) -> Result<Vec<std::ffi::OsString>, String> {
    let mut arguments = vec![
        std::ffi::OsString::from("--model"),
        path_argument(staged_model),
        "--offline".into(),
        "--simple-io".into(),
        "--single-turn".into(),
        "--no-display-prompt".into(),
        "--threads".into(),
        "2".into(),
        "--ctx-size".into(),
        MODEL_CONTEXT_TOKENS.into(),
        "--n-predict".into(),
        MODEL_OUTPUT_TOKENS.into(),
        "--reasoning-budget".into(),
        "0".into(),
        "--seed".into(),
        "1".into(),
        "--temp".into(),
        "0".into(),
        "--system-prompt-file".into(),
        path_argument(system_prompt),
        "--file".into(),
        path_argument(prompt),
        "--json-schema-file".into(),
        path_argument(schema),
        "--color".into(),
        "off".into(),
        "--log-colors".into(),
        "off".into(),
        "--verbosity".into(),
        "4".into(),
    ];
    if use_cuda {
        arguments.extend([
            "--device".into(),
            "CUDA0".into(),
            "--gpu-layers".into(),
            "99".into(),
        ]);
    } else {
        arguments.extend(["--gpu-layers".into(), "0".into()]);
    }
    Ok(arguments)
}

fn path_argument(path: &Path) -> std::ffi::OsString {
    path.as_os_str().to_owned()
}

fn verify_staged_model_size(path: &Path) -> Result<(), String> {
    let size = std::fs::metadata(path)
        .map_err(|error| format!("could not verify staged model size: {error}"))?
        .len();
    if size == 0 || size > EXPLANATION_MODEL_SIZE_BYTES {
        return Err("selected model exceeds the existing model size limit".to_owned());
    }
    Ok(())
}

trait RuntimeOutputView {
    fn success(&self) -> bool;
    fn exit_code(&self) -> Option<i32>;
    fn stdout_bytes(&self) -> &[u8];
    fn stderr_bytes(&self) -> &[u8];
    fn stdout_truncated(&self) -> bool;
    fn stderr_truncated(&self) -> bool;
    fn containment_note(&self) -> &'static str;
}

fn finish_inference<O: RuntimeOutputView>(
    preview: LocalModelExplanationPreview,
    result: O,
    use_cuda: bool,
    backend_status: &'static str,
) -> Result<LocalModelExplanation, String> {
    if result.stdout_truncated() || result.stderr_truncated() {
        return Err("local model exceeded its bounded output limit".to_owned());
    }
    if !result.success() {
        let excerpt = runtime_diagnostic_excerpt(result.stderr_bytes());
        let diagnostic_suffix = if excerpt.is_empty() {
            String::new()
        } else {
            format!("; escaped runtime diagnostic excerpt: {excerpt}")
        };
        return Err(if use_cuda {
            format!(
                "CUDA model inference failed with exit code {:?}; output was discarded and no CPU fallback was attempted{diagnostic_suffix}",
                result.exit_code(),
            )
        } else {
            format!(
                "CPU model inference failed with exit code {:?}; output was discarded{diagnostic_suffix}",
                result.exit_code(),
            )
        });
    }
    let diagnostics = String::from_utf8_lossy(result.stderr_bytes());
    if use_cuda && !cuda_offload_confirmed(&diagnostics) {
        return Err("runtime completed without verifiable CUDA layer-offload evidence; output was discarded".to_owned());
    }
    let allowed = preview_evidence_ids(&preview)?;
    let evidence_ids = crate::local_model_explanation::validate_model_explanation_output(
        result.stdout_bytes(),
        &allowed,
    )?;
    let interpretation = crate::local_model_explanation::derive_selected_facts(
        evidence_ids,
        &preview.prompt,
        &preview.evidence_summary,
        None,
    )?;
    Ok(LocalModelExplanation {
        schema: "sideeffect.local_model_explanation",
        schema_version: crate::local_model_explanation::LOCAL_MODEL_EXPLANATION_SCHEMA_VERSION,
        interpretation_label: match interpretation.selection_status {
            crate::local_model_explanation::ExplanationSelectionStatus::Selected => {
                "local_model_selected_preview_evidence"
            }
            crate::local_model_explanation::ExplanationSelectionStatus::PartialSelection => {
                "local_model_partial_selection_from_partial_parse"
            }
            crate::local_model_explanation::ExplanationSelectionStatus::Abstained => {
                "local_model_selection_abstained"
            }
        },
        request_sha256: preview.request_sha256,
        backend_used: if use_cuda { "cuda" } else { "cpu" },
        backend_status,
        runtime_containment_note: result.containment_note(),
        model_id: preview.model_id,
        model_sha256: preview.model_sha256,
        model_source: preview.model_source,
        license_id: preview.license_id,
        license_status: preview.license_status,
        evaluation_status: preview.evaluation_status,
        model_revision: preview.model_revision,
        runtime_source_revision: EXPLANATION_RUNTIME_REVISION,
        runtime_version: preview.runtime_version,
        backend: preview.backend,
        evidence_summary: preview.evidence_summary,
        interpretation,
    })
}

fn runtime_diagnostic_excerpt(bytes: &[u8]) -> String {
    let source = String::from_utf8_lossy(bytes);
    let mut reverse_excerpt = Vec::new();
    let mut encoded_bytes = 0_usize;
    for character in source.chars().rev() {
        let escaped = character.escape_default().to_string();
        if encoded_bytes.saturating_add(escaped.len()) > 512 {
            break;
        }
        encoded_bytes += escaped.len();
        reverse_excerpt.push(escaped);
    }
    reverse_excerpt.into_iter().rev().collect()
}

fn preview_evidence_ids(
    preview: &LocalModelExplanationPreview,
) -> Result<BTreeSet<String>, String> {
    preview
        .output_schema
        .pointer("/properties/evidence_ids/items/enum")
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .ok_or_else(|| "local explanation preview has no bounded evidence ID schema".to_owned())
}

fn cuda_offload_confirmed(diagnostics: &str) -> bool {
    diagnostics.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("offloading") || !lower.contains("repeating layers to gpu") {
            return false;
        }
        lower
            .split("offloading")
            .nth(1)
            .and_then(|tail| tail.split_whitespace().next())
            .and_then(|count| count.parse::<u32>().ok())
            .is_some_and(|count| count > 0)
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl RuntimeOutputView for crate::local_model_runtime::BoundedCommandOutput {
    fn success(&self) -> bool {
        self.status.success()
    }
    fn exit_code(&self) -> Option<i32> {
        self.status.code()
    }
    fn stdout_bytes(&self) -> &[u8] {
        &self.stdout.bytes
    }
    fn stderr_bytes(&self) -> &[u8] {
        &self.stderr.bytes
    }
    fn stdout_truncated(&self) -> bool {
        self.stdout.truncated
    }
    fn stderr_truncated(&self) -> bool {
        self.stderr.truncated
    }
    fn containment_note(&self) -> &'static str {
        "Linux process resource limits and network-syscall filtering are defense in depth; the runtime is not a security sandbox."
    }
}

#[cfg(windows)]
impl RuntimeOutputView for crate::local_model_runtime::BoundedCommandOutputWindows {
    fn success(&self) -> bool {
        self.status.success()
    }
    fn exit_code(&self) -> Option<i32> {
        self.status.code()
    }
    fn stdout_bytes(&self) -> &[u8] {
        &self.stdout.bytes
    }
    fn stderr_bytes(&self) -> &[u8] {
        &self.stderr.bytes
    }
    fn stdout_truncated(&self) -> bool {
        self.stdout.truncated
    }
    fn stderr_truncated(&self) -> bool {
        self.stderr.truncated
    }
    fn containment_note(&self) -> &'static str {
        self.containment_note
    }
}

#[cfg(windows)]
fn canonical_regular_file(path: &Path, description: &str) -> Result<std::path::PathBuf, String> {
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("could not resolve local {description} path: {error}"))?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|error| format!("could not inspect local {description} file: {error}"))?;
    if !metadata.is_file() {
        return Err(format!("local {description} path must be a regular file"));
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_explanation_address_space_limit_is_accepted_by_shared_runner() {
        use std::ffi::OsString;
        use std::path::Path;

        use crate::local_model_runtime::run_bounded_with_address_space_limit;

        let script = "import resource; print(resource.getrlimit(resource.RLIMIT_AS)[0])";
        let arguments = [OsString::from("-c"), OsString::from(script)];
        let output = run_bounded_with_address_space_limit(
            Path::new("/usr/bin/python3"),
            &arguments,
            None,
            10,
            1024,
            super::MODEL_PROCESS_MEMORY_LIMIT_BYTES,
        )
        .expect("the explanation limit must be accepted by the shared Linux runner");

        assert!(output.status.success());
        assert_eq!(output.stdout.bytes, b"4294967296\n");
    }

    #[cfg(windows)]
    #[test]
    fn windows_explanation_process_limit_is_accepted_by_job_object_runner() {
        use std::ffi::OsString;
        use std::time::Duration;

        let executable = std::env::current_exe().expect("locate test executable");
        let arguments = [OsString::from("--list")];
        let output = crate::local_model_runtime::run_bounded_windows(
            &executable,
            &arguments,
            None,
            Duration::from_secs(10),
            32 * 1024,
            super::MODEL_PROCESS_MEMORY_LIMIT_BYTES,
        )
        .expect("the explanation limit must be accepted by the Windows Job Object runner");

        assert!(output.status.success());
        assert!(!output.stdout.truncated);
        assert!(output.containment_note.contains("Job Objects"));
    }
}
