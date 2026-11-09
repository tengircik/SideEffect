# Local model runtime readiness checks

`sideeffect model doctor --task TASK` checks a selected model registration and the runtime contract for `evidence`, `explanation`, or `query`. The report uses `sideeffect.local_model_doctor` schema v2. A successful report uses `readiness: registration_and_runtime_checks_passed`; this means only that the model registration/hash and required runtime checks passed. It does not test model/runtime compatibility or run inference. `inference_not_run`, `weights_not_loaded`, and `quality_assessment_performed_by_doctor: false` remain explicit in every report. The selected-model section may include catalog evaluation metadata; that metadata is not an assessment performed by doctor. A successful status does not establish compatibility, useful answers, or safe behavior.

The task contracts are intentionally separate:

| Task | Supported platform | Runtime check | Device check |
|---|---|---|---|
| `evidence` | Linux x86_64 | Successful bounded `--version`; a reported line must start with `version: 6000 (4762ad731)` | `not_applicable` |
| `explanation` | Linux x86_64 and native Windows | Successful bounded `--version` output must report the pinned commit `19cce6919` | `--list-devices` is checked for `auto`/`cuda`; CPU mode skips enumeration |
| `query` (Linux syscall plan) | Linux x86_64 | Successful bounded `--version`; after optional `version: ` prefix removal, a line must exactly equal `0.7.0-dev (build 11938, commit 19cce6919)` | `not_applicable` |
| `query` (Windows ETW plan) | Native Windows x86_64 | Explanation runtime check: bounded `--version` must report pinned llama.cpp commit `19cce6919` | `--list-devices` for `auto`/`cuda`; CPU skips enumeration |

Evidence and Linux syscall-query runtime output are checked only on Linux x86_64. Native Windows x86_64 `query` readiness uses the explanation runtime contract for the separate ETW query workflow; other Windows architectures do not enable that query task. The report does not execute any analysis command, download or build a runtime, install anything, or inspect a trace. Each runtime check is limited to a 10-second subprocess timeout and bounded output. The report records only whether the pinned contract was reported; it does not authenticate the binary, its libraries, or its build environment.

Configure an existing runtime path without executing it, then run the task doctor:

```sh
sideeffect model runtime set evidence /path/to/llama-cli
sideeffect model doctor --task evidence

sideeffect model runtime set query /path/to/llama-completion
sideeffect model doctor --task query
```

```powershell
sideeffect.exe model runtime set explanation .\path\to\llama-completion.exe
sideeffect.exe model doctor --task explanation --backend auto
```

`--runtime PATH` overrides the configured path for that doctor call without changing saved configuration. `--backend auto|cpu|cuda` is accepted for explanation and native Windows x86_64 ETW query and defaults to `auto`. Device enumeration may report a CUDA device, but that does not prove that weights load, GPU inference succeeds, GPU memory is sufficient, or output quality is acceptable. `device_check_status` is `not_applicable` for evidence and Linux syscall query; no GPU detection or offload claim is made for those tasks.

The doctor verifies the selected model file against its registered size and SHA-256, which requires reading the local model bytes. Missing selections, paths, unsupported platforms, version mismatches, and failed device checks produce a blocked/incomplete JSON report and exit status `2`. Invalid CLI arguments or report-writing errors exit `1`; exit status `0` means only that registration and required runtime checks passed. A configured runtime path is revalidated against its saved path/hash before use. An explicit override is not bound to a saved runtime hash. The JSON report includes the supplied runtime path, canonicalized when it resolves successfully; it may reveal a username or project directory, so review it before sharing. In either case the doctor executes the selected runtime as the current user; use only a runtime you trust. Hashes are byte-integrity checks, not signatures or proof of publisher identity.

Model acquisition remains user-managed. `setup` may accept a runtime you already obtained and validate its file metadata without executing it; setup does not download or build runtimes. Analysis commands separately require a reviewed preview digest before inference. All candidate models remain experimental and unqualified. See [model setup](INSTALL.md#optional-local-model-setup), [the evidence evaluation](LOCAL_MODEL_EVALUATION.md), [the explanation evaluation](LOCAL_MODEL_EXPLANATION_EVALUATION.md), and [the query-plan evaluation](LOCAL_QUERY_PLAN_EVALUATION.md).
