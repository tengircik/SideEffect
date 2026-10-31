# Windows local explanation model setup

**Status:** optional experimental workflow. No model is approved for answer quality, and this guide does not certify a runtime as safe. SideEffect's inventory, capture, inspection, comparison, and deterministic explanation commands work without a local model.

This guide describes the existing native Windows explanation path. SideEffect does not install llama.cpp or run a model during setup. You choose whether to obtain the source, build the executable, and install model weights. Treat the runtime and its libraries as executable code that runs with your Windows user's permissions.

## Runtime build

The explanation command expects llama.cpp's `llama-completion` executable built from [source revision `19cce6919992fdffd92e0ac152caaf1e2b8f254e`](https://github.com/ggml-org/llama.cpp/tree/19cce6919992fdffd92e0ac152caaf1e2b8f254e) with CUDA enabled. The repository's evaluation record identifies this revision and the build option; it does not provide a Windows driver/Toolkit support matrix or authenticate any binary. Check the current NVIDIA and llama.cpp requirements for your GPU, Windows version, compiler, CUDA Toolkit, and driver before building. SideEffect does not install or update those prerequisites.

If you choose to build the runtime, obtain the llama.cpp source using your usual reviewed process, check out the pinned commit, verify the checkout, and build the `llama-completion` target. These commands fetch source and build the executable locally only when you choose to run them; SideEffect does not run them:

```powershell
git clone https://github.com/ggml-org/llama.cpp.git
Set-Location .\llama.cpp
git checkout --detach 19cce6919992fdffd92e0ac152caaf1e2b8f254e
git rev-parse HEAD
cmake -B build -DGGML_CUDA=ON
cmake --build build --config Release --target llama-completion
```

Confirm that `git rev-parse HEAD` prints exactly `19cce6919992fdffd92e0ac152caaf1e2b8f254e`. Locate the resulting `llama-completion.exe` in the build output. The exact output subdirectory can depend on the generator and build configuration. Keep track of the source, build tools, CUDA Toolkit, and binary you chose. You can record the executable's local hash with:

```powershell
Get-FileHash -Algorithm SHA256 .\path\to\llama-completion.exe
```

The source revision and local hash help identify the source checkout and binary bytes. They do not establish who built the executable, authenticate the build environment, or prove that the executable or its loaded libraries are safe. SideEffect's runtime check only requires the executable's `--version` output to report the pinned revision prefix; that check does not verify a binary signature or full executable hash.

## NVIDIA and Windows runtime behavior

The CUDA build requires a supported NVIDIA GPU, a compatible installed driver, and the CUDA build dependencies used when compiling llama.cpp. The repository does not prescribe exact driver or Toolkit versions. A successful build alone does not show that the runtime can initialize CUDA on this computer.

For inference, SideEffect clears the inherited environment and supplies a bounded DLL search path. It includes the selected runtime directory, Windows system directories, and versioned CUDA Toolkit directories discovered under the standard `%ProgramFiles%\NVIDIA GPU Computing Toolkit\CUDA` location (including `bin` and `bin\x64` layouts). A Toolkit installed in a custom location may not be discovered. Required CUDA DLLs colocated with the runtime can also be found. SideEffect does not search an arbitrary user `PATH`; missing or incompatible DLLs can prevent startup. Do not copy DLLs from unrelated installations to work around a loader error. Check the selected runtime, build configuration, installed driver/Toolkit, and required libraries together.

The `cpu`, `cuda`, and `auto` backend choices apply only to the explanation commands. `auto` uses CUDA when the selected runtime lists `CUDA0`; otherwise it uses CPU. `cuda` fails if the runtime does not list `CUDA0`. A CUDA initialization or inference failure is an error; SideEffect does not retry on CPU. When CUDA is requested, SideEffect accepts output only when runtime diagnostics report positive GPU layer offload. A listed device alone does not prove that inference completed on the GPU.

Windows Job Objects limit host process memory to 6 GiB and bound the runtime process and its output. They do not impose a hard CUDA VRAM limit, and SideEffect does not measure process-isolated peak VRAM. GPU allocations can fail if available VRAM is insufficient. The runtime receives `--offline`, but this is a llama.cpp option, not a Windows network-isolation boundary; SideEffect does not block the runtime's network access. Do not use a runtime you do not trust with sensitive evidence.

## Select and review model weights

The catalog's Windows explanation model is `explanation-qwen3.5-4b-q4-k-m`. It is an experimental 2,783,446,368-byte GGUF with Apache-2.0 terms. It failed its development check (4 of 26 synthetic questions answered) and is not recommended for decisions. No catalog model has passed its applicable quality gate.

Inspect the entry and its evaluation note before deciding whether to install it:

```powershell
sideeffect.exe model list
sideeffect.exe model show explanation-qwen3.5-4b-q4-k-m
```

If you choose to install the pinned catalog weights, `setup` downloads that model file and selects it for explanation after displaying its source, license, platform, and evaluation status and receiving the exact `ACCEPT Apache-2.0` confirmation:

```powershell
sideeffect.exe model setup explanation-qwen3.5-4b-q4-k-m
```

This action contacts the pinned Hugging Face file hosts and verifies the catalog size and SHA-256. It does not download or install llama.cpp, execute model weights, or send a trace or prompt. You can instead register an existing local GGUF with `model add`; that records a file and hash, but does not verify its license, quality, or compatibility with llama.cpp. Registration is not a recommendation. Select a registered model explicitly before analysis:

```powershell
sideeffect.exe model add --name "My local GGUF" --path .\model.gguf --for explanation
sideeffect.exe model list
sideeffect.exe model select explanation MODEL_ID
```

Use the ID printed by `model add` in place of `MODEL_ID`. SideEffect checks the file's bounded GGUF header, size, and hash, then checks its hash again before use. These checks do not establish model quality or runtime compatibility. Review the model's source and license separately.

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

The inference command executes the selected runtime after checking its reported revision and backend availability. A model output is an unverified aid, not a finding; citation validation confirms only that the cited evidence was in the preview. The runtime and loaded libraries are not sandboxed from the user's account. Do not use generated statements for safety, security, permission, or operational decisions. See the [explanation evaluation and quality results](LOCAL_MODEL_EXPLANATION_EVALUATION.md) for the current limitations and release gate.

If CUDA setup fails, try `--backend cpu` only if you choose to run on CPU; `auto` does not fall back after detecting a CUDA device and then encountering an error. A CPU attempt still executes the selected runtime. Keep deterministic CLI workflows available independently of all local-model setup.
