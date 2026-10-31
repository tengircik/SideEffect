# Local explanation model readiness check

`sideeffect model doctor` checks whether an explanation model is selected and its registered file still matches its recorded size and SHA-256. It also checks a user-supplied llama.cpp runtime path against SideEffect's pinned explanation runtime revision. The command does not read a trace, stage model weights for inference, or run inference. Hash validation reads the selected model file to verify its bytes.

Run the readiness check before preparing a trace preview:

```powershell
sideeffect.exe model doctor --task explanation --runtime .\path\to\llama-completion.exe --backend auto
```

The same command is available on Linux x86_64. `--backend` may be `auto`, `cpu`, or `cuda`; it defaults to `auto`. CPU mode skips GPU device enumeration. `auto` and `cuda` run the runtime's bounded `--list-devices` check after its version check. The doctor uses the same 10-second timeout and bounded diagnostic output as inference startup checks.

The runtime is executable code. Doctor runs it with `--version` and, except in CPU mode, `--list-devices`; use only a runtime you trust. A reported version prefix is not binary authentication. The report distinguishes a CUDA device reported by the runtime from successful GPU inference. `gpu_inference_status` is always `not_run`, because this command does not load model weights into the inference runtime. Device presence does not prove that inference will initialize, complete, or fit in available GPU memory.

The JSON report has schema `sideeffect.local_model_doctor` v1. Exit status `0` means the selected model file, runtime revision check, and requested backend readiness checks passed. Exit status `2` means one or more prerequisites are missing or unverified. Other command/configuration errors exit `1`. A ready report does not establish model/runtime compatibility or answer quality; all current catalog models remain experimental and not recommended. Continue with `model-explain-preview`, review the exact bounded request, and only then explicitly run inference with the matching digest. See [the Windows explanation setup](LOCAL_MODEL_WINDOWS_SETUP.md) for GPU/runtime limitations and [the evaluation record](LOCAL_MODEL_EXPLANATION_EVALUATION.md) for quality status.
