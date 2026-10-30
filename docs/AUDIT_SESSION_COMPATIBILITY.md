# Audit session compatibility

The `sideeffect.audit_session` v3 manifest is a platform-neutral envelope. Readers also accept v1 and v2 manifests; v1 has no `coverage_manifest`, so its coverage status is rendered as `unknown`. Native inventory and runtime artifacts keep their own schemas. A reader accepts only the exact combinations below; it does not migrate artifact versions or treat an unknown source as complete. Unknown platform strings and artifact contracts are rejected.

V2 includes a bounded `coverage_manifest` with version 1 and one status per selected source role. Status is one of `observed`, `configured`, `not_observed`, `not_checked`, `unsupported`, `inaccessible`, `partial`, or `unknown`. The current producers report `configured` for a complete startup source, `observed` for a complete selected inventory snapshot, preserve partial/not-checked/unsupported/access-denied as `partial`/`not_checked`/`unsupported`/`inaccessible`, and use `unknown` for other incomplete states. Here `observed` means the selected inventory was read; it does not claim runtime activity. Runtime capture remains partial today. These values describe the selected collector result only; they do not assert exhaustive OS coverage.

V3 retains that coverage map and adds bounded per-source requested settings, source-reported effective settings, and runtime loss metadata. A requested setting is kept separate from applied collector limits and source-reported effective settings. An empty setting list means no values were recorded; it does not mean the OS default or effective state is known. Runtime loss is `reported` when any loss counter is positive, `none_reported` only when both statistics and the final snapshot are available and counters are zero, and otherwise `unknown`. Linux `strace` sessions currently report runtime loss as unknown. Windows ETW settings/counters are copied from the validated capture artifact; the reported session buffer count is not a guarantee of complete capture. Inventory sources omit runtime loss metadata. Every source's artifact references continue to provide provenance links by fixed path, native schema/version, byte length, and SHA-256; those hashes establish local byte consistency only, not authorship. OS build and privilege state are not inferred or added.

| Platform | Source role | Fixed artifact | Native schema | Version |
| --- | --- | --- | --- | ---: |
| Linux | packages | `packages.json` | `sideeffect.inventory` | 2 |
| Linux | processes | `processes.json` | `sideeffect.process_inventory` | 1 |
| Linux | permissions | `permissions.json` | `sideeffect.permission_inventory` | 1 |
| Linux | startup | `startup.json` | `sideeffect.startup_inventory` | 2 |
| Linux | runtime | `run.json` | `sideeffect.run` | 2 |
| Linux | runtime | `trace.strace` | `strace_text` | 1 |
| Windows | packages/software registrations | `software.windows.json` | `sideeffect.windows_software_inventory` | 1 |
| Windows | processes | `processes.windows.json` | `sideeffect.windows_process_inventory` | 1 |
| Windows | permissions | `permissions.windows.json` | `sideeffect.windows_permission_inventory` | 1 |
| Windows | startup | `startup.windows.json` | `sideeffect.windows_startup_inventory` | 4 |
| Windows | runtime | `runtime.windows.json` | `sideeffect.windows_runtime_capture` | 3 |

Windows runtime capture is selected explicitly with `--runtime-source windows-etw --runtime-duration-seconds 1..60 -- PROGRAM [ARGS...]`. ETW setup must succeed before the target launches. The target's arguments remain separate argv values. The NT Kernel Logger is shared and system-wide for the bounded capture window; controlling it requires permission, and SideEffect never elevates. The captured v3 JSON document is included as the fixed runtime artifact in the one atomically published session directory. It retains bounded raw ETW payloads, capture interval, target outcome, loss metadata, and diagnostics. The session source is always `partial` because capture completeness is unknown. Setup, launch, or capture errors fail the audit before session publication; they are not represented as an empty successful artifact. No target/descendant event attribution or causal inference is made.

`complete` means the selected collector produced its declared artifact set. It does not mean exhaustive system coverage. `partial`, `unsupported`, `unavailable`, `access_denied`, and other non-complete states remain visible and force the enclosing session to `partial`. Runtime can never be marked complete in this session version because capture completeness is not established.

Each artifact reference has a fixed basename, exact native schema/version, positive bounded byte length, and lowercase SHA-256 digest. Readers reject unknown fields in the manifest, duplicate roles/artifacts, extra directory entries, unexpected artifact versions, oversized data, and mismatching hashes. The manifest digest is an integrity consistency check only; it does not authenticate who produced the manifest or artifacts. Readers render source metadata and do not claim full semantic validation of native inventory documents.

The envelope version changes when fields or status/completeness semantics change. V2 added the versioned coverage manifest; v3 adds bounded source details. Current readers accept v1, v2, and v3, leaving v1 coverage unknown and v1/v2 source details absent. Older binaries safely reject newer envelopes. A native artifact format change requires its own artifact schema-version change and explicit reader support.
