# Windows local-model GPU memory sampling

`scripts/measure_windows_local_model_gpu.py` samples NVIDIA-SMI counters while it launches one actual SideEffect CLI command. The harness is for bounded development measurements; it does not enforce a VRAM limit and does not establish an unsampled allocation peak.

The harness launches argv directly without a shell and leaves stdout/stderr attached to the current console. It does not save the command, question, trace path, model path, or runtime path. The output is local JSON containing timestamps, sampled GPU memory, the SideEffect CLI PID, and (when confirmed) runtime PIDs and their sampled process-parent chains. Review and protect the report as local machine metadata. A new report path is required; output creation is exclusive and never replaces an existing file.

Example, using the already reviewed preview digest and locally registered runtime/model:

```powershell
py -3 scripts\measure_windows_local_model_gpu.py `
  --duration-seconds 120 `
  --interval-ms 500 `
  --runtime-process-name llama-completion.exe `
  --output C:\Users\you\Documents\sideeffect-gpu-sample.json `
  -- sideeffect.exe model-explain `
    --question "Which executable was observed to start successfully?" `
    --backend cuda `
    --runtime C:\LocalTools\llama-completion.exe `
    --confirm-sha256 REVIEWED_PREVIEW_SHA256 `
    C:\LocalData\trace.strace
```

The runtime name must be the executable basename configured for the run. A process-isolated sample is reported only when NVIDIA-SMI reports that PID and a bounded Windows Tool Help snapshot links the exact PID to the launched SideEffect process tree, with the requested runtime basename. The report retains those PID parent chains as evidence for the match. NVIDIA-SMI can report a valid process PID/GPU UUID with `used_memory=[N/A]` under Windows WDDM. Such rows retain the identity match but set `memory_used_mib` to JSON `null` and `memory_status` to `unsupported_driver_reported_n_a`; the report's `per_process_memory_status` is `unsupported_driver_reported_n_a`, and process-isolated memory remains unknown, never zero. If other matched rows in the same run have numeric values, only those contribute to the sampled peak and the status is `sampled_with_unsupported_rows`. When there is no matched runtime PID row, the report states `unknown_no_runtime_pid_memory`. Global counters include other GPU workloads and are not attributable to SideEffect.

The sampling interval is 250–10,000 ms, the requested window is 1–600 seconds, and the sample count is capped at 600. Each NVIDIA-SMI call has a five-second timeout, tool output is bounded to 64 KiB, the Windows process snapshot is bounded to 8,192 entries, NVIDIA-SMI compute-process rows are bounded to 256, and the JSON report is capped at 2 MiB. If the sampling bound expires while SideEffect is still running, the harness reports that fact and does not terminate the command. Sampling can miss short-lived allocations between polls. CUDA usage, global memory, per-process memory, and model quality are separate observations. The measurement harness itself makes no network requests and does not download or modify models or change SideEffect's resource limits; the launched SideEffect command and configured runtime retain their normal network behavior.
