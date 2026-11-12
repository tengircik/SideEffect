# Windows local explanation model setup

**Status:** optional experimental workflow. No model is approved for answer quality, and this guide does not certify a runtime as safe. SideEffect's inventory, capture, inspection, comparison, and deterministic explanation commands work without a local model.

This guide primarily describes the existing native Windows explanation path. The same pinned llama.cpp runtime contract and bounded runner are used by the separate experimental ETW query workflow on native Windows x86_64. The SideEffect CLI does not install llama.cpp or run a model during setup. You may obtain the source and build it yourself, or use the optional repository helper below to download one pinned upstream package after explicit confirmation. Model weights are installed separately. Treat the runtime and its libraries as executable code that runs with your Windows user's permissions.

## Runtime build

The Windows explanation and x86_64 ETW-query commands expect llama.cpp's `llama-completion` executable built from [source revision `19cce6919992fdffd92e0ac152caaf1e2b8f254e`](https://github.com/ggml-org/llama.cpp/tree/19cce6919992fdffd92e0ac152caaf1e2b8f254e) with CUDA enabled. The repository's evaluation record identifies this revision and the build option; it does not provide a Windows driver/Toolkit support matrix or authenticate any binary. Check the current NVIDIA and llama.cpp requirements for your GPU, Windows version, compiler, CUDA Toolkit, and driver before building. SideEffect does not install or update those prerequisites.

### Optional pinned Windows runtime download

The repository includes [`scripts/install_sideeffect_llama_runtime_windows.ps1`](../scripts/install_sideeffect_llama_runtime_windows.ps1) for users who prefer the upstream prebuilt Windows x64 package over building from source. It offers only the pinned `b11938` release, whose signed source commit matches the explanation runtime check (`19cce6919992fdffd92e0ac152caaf1e2b8f254e`). The script downloads from the [official llama.cpp release](https://github.com/ggml-org/llama.cpp/releases/tag/b11938), verifies exact archive sizes and SHA-256 digests, applies bounded ZIP extraction under the current user's `%LOCALAPPDATA%`, refuses existing destinations, and prints the command to register the extracted `llama-completion.exe`. New installs include a bounded local manifest listing the published files and hashes. `-Action inspect` compares the current files with that manifest; `-Action remove` requires an exact typed confirmation and removes a fully matching, reparse-free install at the fixed release/backend path. Install and removal refuse elevated sessions because the target is under the writable user profile; concurrent same-user filesystem changes are not isolated. These hashes detect local changes; they do not authenticate the publisher. The helper never executes extracted files, changes the SideEffect model registry, or requests administrator access. Upstream lists [build provenance attestations](https://github.com/ggml-org/llama.cpp/attestations/60617910), but this helper does not verify them. The pinned archive hashes verify bytes; they do not by themselves authenticate who built the binary.

The CPU package downloads 24,260,998 bytes (about 24 MB). CUDA downloads two separate official assets—the 279,447,765-byte llama.cpp CUDA build and the 391,443,627-byte CUDA runtime-library bundle—for 670,891,392 bytes total (about 671 MB); aggregate archive extraction and the merged runtime files are capped at 2 GiB. CUDA DLLs are placed beside the runtime executable, while any bundled license/notice files are retained under `third-party-notices\cuda-runtime`. The CUDA package includes NVIDIA runtime libraries, so review both the [llama.cpp MIT license](https://github.com/ggml-org/llama.cpp/blob/b11938/LICENSE) and the versioned [NVIDIA CUDA 12.4.0 EULA](https://docs.nvidia.com/cuda/archive/12.4.0/eula/index.html) before choosing it. The bundle does not install a display driver. CUDA availability, runtime compatibility, VRAM sufficiency, and inference success still require separate checks. SideEffect's `model runtime set` records a hash of `llama-completion.exe`; it does not reverify adjacent DLL hashes before inference, so keep the entire extracted directory under your control.

From the repository root, choose exactly one backend. The script shows the pinned source, digests, download size, and license links before asking for a backend-specific confirmation; declining or entering different text makes no request.

```powershell
# CPU (about 24 MB):
powershell.exe -NoProfile -File .\scripts\install_sideeffect_llama_runtime_windows.ps1 -Backend cpu

# Or CUDA (about 671 MB; includes NVIDIA runtime libraries):
powershell.exe -NoProfile -File .\scripts\install_sideeffect_llama_runtime_windows.ps1 -Backend cuda
```

After it completes, review and copy the exact `sideeffect model runtime set explanation ...` command printed by the script. For the separate Windows ETW query task, register the same executable with `sideeffect model runtime set query PATH`. Then, if you trust the runtime and choose to execute it, run `sideeffect.exe model doctor --task explanation --backend auto` or `--task query --backend auto` to check the reported revision and device listing. The doctor executes the selected runtime; it does not load model weights or assess answer quality. The script will not overwrite an existing pinned install.

Inspect or remove the managed install with the same script and backend:

```powershell
powershell.exe -NoProfile -File .\scripts\install_sideeffect_llama_runtime_windows.ps1 -Backend cuda -Action inspect
```

Before removal, run `sideeffect.exe model runtime show explanation` and `sideeffect.exe model runtime show query`. Clear a task only if its configured path points to this exact runtime: `sideeffect.exe model runtime clear explanation` or `sideeffect.exe model runtime clear query`. Then run:

```powershell
powershell.exe -NoProfile -File .\scripts\install_sideeffect_llama_runtime_windows.ps1 -Backend cuda -Action remove
```

The helper refuses removal if the manifest is missing, a file was changed, an unexpected file/directory exists, or a reparse point is present. Installations created before the manifest was added are not eligible for managed removal; inspect the exact directory and its contents manually before removing them. Inspection output includes the local install path and filenames; review it before sharing. Runtime removal does not delete model weights and does not change SideEffect's registry. The helper manages only its current pinned release; a future pinned release uses a separate versioned directory and must be validated before changing the task's registered path.

### Hosted runtime lifecycle acceptance (maintainers)

The repository workflow [`.github/workflows/windows-runtime-lifecycle-acceptance.yml`](../.github/workflows/windows-runtime-lifecycle-acceptance.yml) runs this helper end to end on hosted Windows runners, as one job per allowlisted backend (`cpu` and `cuda`). A disposable standard local account performs the install, the hash-backed `verified` inspect, the removal, and a final inspect that must report `not_installed`; the workflow checks the install manifest fields, the inspected file count and byte total, an independently recomputed manifest SHA-256, and the absence of the runtime directory after removal. The typed install/removal confirmations and the expected install path are derived from the backend selector rather than hardcoded. The jobs never start the downloaded executable, remove the disposable account and its profile afterwards, and have read-only repository permissions. They are started manually with `workflow_dispatch`, or by a pull request that changes the workflow file itself and targets `main` or `codex/windows-runtime-lifecycle`; the jobs only run for same-repository pull requests and never use `pull_request_target` or repository secrets. This covers package download, manifest verification, and managed removal for two backends on one hosted runner image. It does not show that CUDA is usable on a GPU, that the runtime initializes, or that inference succeeds, and it covers no other Windows version, interactive user session, or publisher authentication; the checks it runs are limited to what those runs observed.

[GitHub run 43211118225](https://github.com/tengircik/sideeffect/actions/runs/43211118225) at head `0a96a830d4a90d4afcc66f49974bf3e0f12812ce` passed CPU and CUDA install, hash-verified inspect, removal, and the final `not_installed` check under disposable standard users on a hosted Windows Server 2025 image. That run tested lifecycle and manifest handling only; no runtime execution or inference was tested.

If you choose to build the runtime, obtain the llama.cpp source using your usual reviewed process, check out the pinned commit, verify the checkout, and build the `llama-completion` target. These commands fetch source and build the executable locally only when you choose to run them; SideEffect does not run them:

```powershell
git clone https://github.com/ggml-org/llama.cpp.git
Set-Location .\llama.cpp
git config core.longpaths true
git checkout --detach 19cce6919992fdffd92e0ac152caaf1e2b8f254e
git rev-parse HEAD
cmake -B build -DGGML_CUDA=ON -DLLAMA_BUILD_COMMIT=19cce6919992fdffd92e0ac152caaf1e2b8f254e
cmake --build build --config Release --target llama-completion
```

Confirm that `git rev-parse HEAD` prints exactly `19cce6919992fdffd92e0ac152caaf1e2b8f254e`. Pass the full revision through `LLAMA_BUILD_COMMIT`: llama.cpp's default version string reports only a seven-character short hash, which is too short for SideEffect's pinned revision check. Locate the resulting `llama-completion.exe` in the build output. The exact output subdirectory can depend on the generator and build configuration. Keep track of the source, build tools, CUDA Toolkit, and binary you chose. You can record the executable's local hash with:

```powershell
Get-FileHash -Algorithm SHA256 .\path\to\llama-completion.exe
```

The source revision and local hash help identify the source checkout and binary bytes. They do not establish who built the executable, authenticate the build environment, or prove that the executable or its loaded libraries are safe. SideEffect's runtime check only requires the executable's `--version` output to report the pinned revision prefix; that check does not verify a binary signature or full executable hash.

## NVIDIA and Windows runtime behavior

Building the CUDA-enabled runtime requires the CUDA Toolkit and compatible compiler/build dependencies used by the pinned llama.cpp revision. A supported NVIDIA GPU and compatible installed driver are needed to initialize and run CUDA inference; they are not prerequisites for compiling the CUDA-enabled executable. The repository does not prescribe exact driver or Toolkit versions. A successful build alone does not show that the runtime can initialize CUDA on this computer.

For inference, SideEffect clears the inherited environment and supplies a bounded DLL search path. It includes the selected runtime directory, Windows system directories, and versioned CUDA Toolkit directories discovered under the standard `%ProgramFiles%\NVIDIA GPU Computing Toolkit\CUDA` location (including `bin` and `bin\x64` layouts). A Toolkit installed in a custom location may not be discovered. Required CUDA DLLs colocated with the runtime can also be found. SideEffect does not search an arbitrary user `PATH`; missing or incompatible DLLs can prevent startup. Do not copy DLLs from unrelated installations to work around a loader error. Check the selected runtime, build configuration, installed driver/Toolkit, and required libraries together.

The `cpu`, `cuda`, and `auto` backend choices apply to explanation and native Windows x86_64 ETW-query inference. `auto` uses CUDA when the selected runtime lists `CUDA0`; otherwise it uses CPU. `cuda` fails if the runtime does not list `CUDA0`. A CUDA initialization or inference failure is an error; SideEffect does not retry on CPU. When CUDA is requested, SideEffect accepts output only when runtime diagnostics report positive GPU layer offload. A listed device alone does not prove that inference completed on the GPU.

Windows Job Objects limit host process memory to 6 GiB and bound the runtime process and its output. They do not impose a hard CUDA VRAM limit, and SideEffect does not measure process-isolated peak VRAM. GPU allocations can fail if available VRAM is insufficient. The runtime receives `--offline`, but this is a llama.cpp option, not a Windows network-isolation boundary; SideEffect does not block the runtime's network access. Do not use a runtime you do not trust with sensitive evidence.

## Select and review model weights

The catalog's Windows explanation model is `explanation-qwen3.5-4b-q4-k-m`. It is an experimental 2,783,446,368-byte GGUF with Apache-2.0 terms. It failed its development check (4 of 26 synthetic questions answered) and is not recommended for decisions. No catalog model has passed its applicable quality gate.

The catalog also includes `explanation-qwen3.5-0.8b-q4-0`, a smaller experimental workflow-test candidate. Its pinned file is [`Qwen3.5-0.8B-Q4_0.gguf`](https://huggingface.co/ggml-org/Qwen3.5-0.8B-GGUF/blob/9447f74101aeb4e93621884dfa36ee8effb8831b/Qwen3.5-0.8B-Q4_0.gguf), from `ggml-org/Qwen3.5-0.8B-GGUF` revision `9447f74101aeb4e93621884dfa36ee8effb8831b`, with size 563,036,064 bytes and SHA-256 `57d1997790d1744fba5b40a7317df71ea5e2acee28c47e78f0cce39c0703f8cf`. The source model is `Qwen/Qwen3.5-0.8B`; its pinned Apache-2.0 license file is [here](https://huggingface.co/Qwen/Qwen3.5-0.8B/blob/95ab6d408b035a1ca532ca6ec09f21071fbf4b22/LICENSE). Use `model show` to inspect the entry, or choose `model setup` to download the pinned file after typing the exact license acceptance:

```powershell
sideeffect.exe model show explanation-qwen3.5-0.8b-q4-0
sideeffect.exe model setup explanation-qwen3.5-0.8b-q4-0
```

This entry is `not_assessed`, experimental, unqualified, and not recommended or approved. It has not passed any answer-quality evaluation. The existing runtime pin is unchanged: llama.cpp revision `19cce6919992fdffd92e0ac152caaf1e2b8f254e`. That revision contains the upstream [`qwen35.cpp` model implementation](https://github.com/ggml-org/llama.cpp/blob/19cce6919992fdffd92e0ac152caaf1e2b8f254e/src/models/qwen35.cpp), and SideEffect's explanation path is supported on Linux x86_64 and native Windows. Source-code support is not evidence of successful inference, compatibility with every build, performance, or answer quality. The runtime remains separately user-obtained and is never downloaded by `model setup`.

Inspect the entry and its evaluation note before deciding whether to install it:

```powershell
sideeffect.exe model list
sideeffect.exe model show explanation-qwen3.5-4b-q4-k-m
```

If you choose to install the pinned catalog weights, `setup` downloads that model file and selects it for explanation after displaying its source, license, platform, and evaluation status and receiving the exact `ACCEPT Apache-2.0` confirmation. You can include `--runtime EXISTING_FILE` if you have already obtained a llama.cpp executable:

```powershell
# Without registering a runtime during setup:
sideeffect.exe model setup explanation-qwen3.5-4b-q4-k-m

# With an already-obtained runtime (replace this path with your executable):
sideeffect.exe model setup explanation-qwen3.5-4b-q4-k-m --runtime .\path\to\llama-completion.exe
```

When supplied, the runtime path is resolved to a canonical regular file and its bounded size and SHA-256 are checked before the catalog license prompt. The runtime must already have been obtained by you; setup neither downloads nor executes it. After the pinned weights install successfully, setup selects the model and saves that runtime for the selected task. Run `sideeffect.exe model doctor --task explanation --backend auto` or `--task query --backend auto` to check the reported explanation-runtime commit and device readiness. On native Windows, evidence and Linux syscall-query runtime checks remain unsupported; only Windows x86_64 query selects the separate ETW query task/runtime contract. Without `--runtime`, configure an existing runtime separately with `model runtime set explanation PATH` or `model runtime set query PATH` for ETW query.

This action contacts the pinned Hugging Face file hosts and verifies the catalog model size and SHA-256. It does not download or install llama.cpp, execute model weights, or send a trace or prompt. You can instead register an existing local GGUF with `model add`; that records a file and hash, but does not verify its license, quality, or compatibility with llama.cpp. Registration is not a recommendation. Select a registered model explicitly before analysis:

```powershell
sideeffect.exe model add --name "My local GGUF" --path .\model.gguf --for explanation
sideeffect.exe model list
sideeffect.exe model select explanation MODEL_ID
```

Use the ID printed by `model add` in place of `MODEL_ID`. SideEffect checks the file's bounded GGUF header, size, and hash. Previews use this registered identity without rereading model weights; before inference, SideEffect stages the selected file and verifies the staged bytes against the registered size and hash. If model bytes change after registration, inference fails this check without making large previews reread the weights. These checks do not establish model quality or runtime compatibility. Review the model's source and license separately.

## Preview, then explicitly run inference

Previewing parses the selected trace and shows the exact bounded request, selected model identity, backend preference, and digest. It does not start the runtime. Review the complete preview because evidence labels and path hints can be sensitive:

```powershell
$preview = sideeffect.exe model-explain-preview `
  --question "What happened to the observed connection?" `
  --backend cuda .\capture.strace | ConvertFrom-Json
$preview | ConvertTo-Json -Depth 100
```

If you decide to run inference, use the exact request digest from that preview and the path to the runtime you obtained and reviewed:

```powershell
sideeffect.exe model-explain `
  --question "What happened to the observed connection?" `
  --backend cuda `
  --runtime .\path\to\llama-completion.exe `
  --confirm-sha256 $preview.request_sha256 `
  .\capture.strace
```

When the preview has no deterministic scope-abstention reason, an inference run executes the selected runtime after checking its reported revision and backend availability. A deterministic abstention returns without starting the runtime. A model output is an unverified aid, not a finding; citation validation confirms only that the cited evidence was in the preview. The runtime and loaded libraries are not sandboxed from the user's account. Do not use generated statements for safety, security, permission, or operational decisions. See the [explanation evaluation and quality results](LOCAL_MODEL_EXPLANATION_EVALUATION.md) for the current limitations and release gate.

If CUDA setup fails, try `--backend cpu` only if you choose to run on CPU; `auto` does not fall back after detecting a CUDA device and then encountering an error. A CPU attempt still executes the selected runtime. Keep deterministic CLI workflows available independently of all local-model setup.
