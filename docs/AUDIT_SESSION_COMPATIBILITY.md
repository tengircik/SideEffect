# Audit session compatibility

The `sideeffect.audit_session` v1 manifest is a platform-neutral envelope. Native inventory and runtime artifacts keep their own schemas. A reader accepts only the exact combinations below; it does not migrate older artifact versions, infer missing fields, or treat an unknown source as complete. Unknown platform strings and artifact contracts are rejected.

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

The Windows runtime role currently has no artifact contract. An explicitly selected Windows runtime source is recorded as `unsupported` with a diagnostic and no artifact. The experimental ETW process/file/network capture output is not represented as a completed runtime source.

`complete` means the selected collector produced its declared artifact set. It does not mean exhaustive system coverage. `partial`, `unsupported`, `unavailable`, `access_denied`, and other non-complete states remain visible and force the enclosing session to `partial`. Runtime can never be marked complete in this session version because capture completeness is not established.

Each artifact reference has a fixed basename, exact native schema/version, positive bounded byte length, and lowercase SHA-256 digest. Readers reject unknown fields in the manifest, duplicate roles/artifacts, extra directory entries, unexpected artifact versions, oversized data, and mismatching hashes. The manifest digest is an integrity consistency check only; it does not authenticate who produced the manifest or artifacts. Readers render source metadata and do not claim full semantic validation of native inventory documents.

The envelope version stays at 1 when a new platform contract is added because its serialized envelope fields and semantics do not change. Older binaries safely reject newly added platform/artifact combinations. A change to envelope fields or status/completeness semantics requires a manifest schema-version change; a native artifact format change requires its own artifact schema-version change and explicit reader support.
