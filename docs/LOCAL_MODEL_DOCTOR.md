# Local explanation model readiness check

`sideeffect model doctor` checks whether an explanation model is selected and its registered file still matches its recorded size and SHA-256. It also checks a user-supplied llama.cpp runtime path against SideEffect's pinned explanation runtime revision. The command does not read a trace, stage model weights for inference, or run inference. Hash validation reads the selected model file to verify its bytes.

Configure an existing local runtime once for a task, inspect the saved paths and hashes, or clear one. Configuration hashes a bounded regular file without executing it; it does not install the selected file:

```sh
sideeffect model runtime set explanation /path/to/llama-completion
sideeffect model runtime show [explanation]
sideeffect model runtime clear explanation
```

Use `evidence` and `query` for their respective Linux x86_64 commands. `explanation` is available on Linux x86_64 and native Windows. `show` prints the configured path as terminal-safe text and marks files that have gone missing or changed. `clear` removes only the stored path; it leaves the file untouched. Runtime paths can reveal local account or project names.

Run the readiness check before preparing a trace preview:

```powershell
sideeffect.exe model runtime set explanation .\path\to\llama-completion.exe
sideeffect.exe model doctor --task explanation --backend auto
```

The same commands are available on Linux x86_64. `model doctor --task explanation` uses the configured runtime path; an explicit `--runtime PATH` overrides it for that command without changing saved configuration. `--backend` may be `auto`, `cpu`, or `cuda`; it defaults to `auto`. CPU mode skips GPU device enumeration. `auto` and `cuda` run the runtime's bounded `--list-devices` check after its version check. The doctor uses the same 10-second timeout and bounded diagnostic output as inference startup checks.

The runtime is executable code. Doctor runs it with `--version` and, except in CPU mode, `--list-devices`; use only a runtime you trust. A reported version prefix is not binary authentication. Before an analysis command uses a configured path, SideEffect rechecks that it still resolves to the saved canonical path and is an existing regular file. The runtime's pinned version check still happens during startup. A reported CUDA device is separate from successful GPU inference. `gpu_inference_status` is always `not_run`, because doctor does not load model weights into the inference runtime. Device presence does not prove that inference will initialize, complete, or fit in available GPU memory.

`model-analyze`, `model-explain`, and `model-query` use the configured per-task path when `--runtime` is omitted. Before use, SideEffect re-hashes that runtime (up to 1 GiB) and rejects a missing, changed, or invalid file. Passing `--runtime PATH` keeps working and overrides the saved path for that invocation. Each command still requires the exact `--confirm-sha256` from its reviewed preview before runtime inference starts. No path setting or analysis command downloads a runtime or model implicitly. Runtime setup remains user-managed, and the selected runtime and its libraries run with the user's permissions. A hash binds the saved configuration to bytes observed at verification time; it is not a signature or proof of publisher identity.

The JSON report has schema `sideeffect.local_model_doctor` v1. Exit status `0` means the selected model file, runtime revision check, and requested backend readiness checks passed. Exit status `2` means one or more prerequisites are missing or unverified. Other command/configuration errors exit `1`. A ready report does not establish model/runtime compatibility or answer quality; all current catalog models remain experimental and not recommended. Continue with `model-explain-preview`, review the exact bounded request, and only then explicitly run inference with the matching digest. See [the Windows explanation setup](LOCAL_MODEL_WINDOWS_SETUP.md) for GPU/runtime limitations and [the evaluation record](LOCAL_MODEL_EXPLANATION_EVALUATION.md) for quality status.
