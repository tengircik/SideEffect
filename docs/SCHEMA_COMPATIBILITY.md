# Schema compatibility

This document describes the versioned formats currently emitted by SideEffect and the formats that current commands accept as input. A schema version identifies a serialized contract; it does not promise that every consumer understands every field, nor that a document is authentic or complete.

## Current schema inventory

| Format | Schema / version | Produced by | Input support |
| --- | --- | --- | --- |
| Trace inspection JSON | No `schema` name field; `schema_version` 7 | `inspect TRACE`, `inspect --bundle DIR` | Not imported as JSON. `inspect` and `diff` read bounded raw `strace` text. |
| Trace diff JSON | No `schema` name field; `schema_version` 3 | `diff` and `diff --bundles` | Not imported as JSON by current commands. |
| Linux package inventory | `sideeffect.inventory` v2 | Linux `inventory packages` | Package inventory comparison accepts v2 only. Session inspection checks the declared header/version and hash, not every inventory field. |
| Linux process inventory | `sideeffect.process_inventory` v1 | Linux `inventory processes` | No standalone semantic importer. Session inspection checks the declared header/version and hash. |
| Linux permission inventory | `sideeffect.permission_inventory` v1 | Linux `inventory permissions` | No standalone semantic importer. Session inspection checks the declared header/version and hash. |
| Linux aggregate startup inventory | `sideeffect.startup_inventory` v2 | Linux `inventory startup` | `correlate-startup` accepts v2 as saved input; session inspection checks its declared header/version and hash. |
| Linux XDG startup component | `sideeffect.xdg_autostart_inventory` v1 | Nested in the Linux aggregate startup inventory | No standalone importer. |
| Linux systemd component | `sideeffect.systemd_unit_inventory` v1 | Nested in the Linux aggregate startup inventory | No standalone importer. |
| Linux legacy startup component | `sideeffect.legacy_startup_inventory` v1 | Nested in the Linux aggregate startup inventory | No standalone importer. |
| Windows software inventory | `sideeffect.windows_software_inventory` v1 | Windows `inventory packages` | No standalone semantic importer. Session inspection checks the declared header/version and hash. |
| Windows process inventory | `sideeffect.windows_process_inventory` v1 | Windows `inventory processes` | No standalone semantic importer. Session inspection checks the declared header/version and hash. |
| Windows permission inventory | `sideeffect.windows_permission_inventory` v1 | Windows `inventory permissions` | No standalone semantic importer. Session inspection checks the declared header/version and hash. |
| Windows startup inventory | `sideeffect.windows_startup_inventory` v4 | Windows `inventory startup` | No standalone semantic importer. Session inspection checks the declared header/version and hash. |
| Linux run bundle manifest | `sideeffect.run` v2 | Linux `record --bundle` | Linux `inspect --bundle` and `diff --bundles` accept v1 and v2. |
| Bundle trace entry | `strace_text` v1; raw `trace.strace` bytes | Linux `record --bundle` | Parsed as raw `strace` text after bundle validation. |
| Audit session envelope | `sideeffect.audit_session` v1 | Linux and Windows `audit` | `inspect --session` accepts v1 with the exact platform/artifact contracts below. |
| Audit session review JSON | `sideeffect.audit_session_review` v1 | `inspect --session --format json` | Output-only; not accepted as a session manifest. |
| Windows ETW capture | `sideeffect.windows_runtime_capture` v2 | Experimental Windows `record --windows-etw` | Output-only. It is not accepted by `inspect`, `diff`, bundle inspection, or the Windows session runtime contract. |
| Package inventory comparison | `sideeffect.package_inventory_diff` v1 | `explain --inventory-diff` | Reads Linux `sideeffect.inventory` v2 documents only. |
| Startup correlation | `sideeffect.startup_correlation` v1 | `correlate-startup` | Reads Linux `sideeffect.startup_inventory` v2 and raw `strace` text; output is not an input format. |
| Trace explanation JSON | Shape version 1 (no schema-name field) | `explain TRACE` | Output-only. Input is raw `strace` text. |
| Diff explanation JSON | Shape version 1 (no schema-name field) | `explain --diff` | Output-only. Input is raw `strace` text on each side. |
| Aggregate diff summary | `sideeffect_redacted_diff_summary` v1 | `diff-summary` | Output-only; it is not a detailed diff or an input format. |
| Offline HTML diff report | No separate report schema; renders trace diff v3 | Linux `diff --format html` and `diff --bundles --format html` | Output-only. It contains the comparison fields and evidence references, but is not imported by SideEffect. |
| Local model registry | `sideeffect.local_model_registry` v1 | `model` commands persist per-user registry state | Read and written by the model manager; unknown versions and fields are rejected rather than migrated. |
| Evidence-selection model preview and analysis | `sideeffect.local_model_preview` v5; `sideeffect.local_model_analysis` v5 | `model-query-preview` and `model-query` | Output-only; the preview is a reviewed request contract, not an import format. |
| Query-plan model artifacts | `sideeffect.local_queryable_facts` v2; `sideeffect.local_query_plan_preview` v2; `sideeffect.local_query_plan_analysis` v2; `sideeffect.local_query_result` v2 | `model-query-plan-preview`, `model-query-plan`, and their deterministic query execution | Output-only; model-generated plans are validated against the fixed schema and are not general-purpose query input. |
| Model-explanation artifacts | `sideeffect.local_model_explanation_preview` v1; `sideeffect.local_model_explanation` v1 | `model-explain-preview` and `model-explain` | Output-only; generated statements are unverified and citations are checked only against the preview's evidence IDs. |

The table lists current product command formats, not every development or local-model evaluation artifact in the repository. Text renderings of inspect, diff, evidence, and session review are human-readable output and do not declare a JSON schema version.

### Session artifact contracts

The v1 session envelope is platform-neutral. Its current exact artifact contracts are:

| Platform | Role | Fixed artifact | Artifact schema / version |
| --- | --- | --- | --- |
| Linux | Packages | `packages.json` | `sideeffect.inventory` v2 |
| Linux | Processes | `processes.json` | `sideeffect.process_inventory` v1 |
| Linux | Permissions | `permissions.json` | `sideeffect.permission_inventory` v1 |
| Linux | Startup | `startup.json` | `sideeffect.startup_inventory` v2 |
| Linux | Runtime | `run.json` | `sideeffect.run` v2 |
| Linux | Runtime | `trace.strace` | `strace_text` v1 |
| Windows | Packages/software registrations | `software.windows.json` | `sideeffect.windows_software_inventory` v1 |
| Windows | Processes | `processes.windows.json` | `sideeffect.windows_process_inventory` v1 |
| Windows | Permissions | `permissions.windows.json` | `sideeffect.windows_permission_inventory` v1 |
| Windows | Startup | `startup.windows.json` | `sideeffect.windows_startup_inventory` v4 |

Windows runtime has no session artifact contract. A selected Windows runtime source is recorded as unsupported with a diagnostic; the process-only ETW prototype is not a completed session artifact. Session inspection checks envelope rules, fixed names, schema/version headers, byte lengths, and SHA-256 values, then renders metadata. It does not fully validate the semantic contents of each native inventory artifact.

## Accepted inputs and unsupported versions

- `inspect` and `evidence` accept bounded raw `strace` text, not prior SideEffect trace JSON. `diff` accepts two completely parsed raw `strace` inputs. Bundle variants of inspect and diff accept Linux `sideeffect.run` v1 or v2, verify the fixed private bundle layout and trace hash, and then parse the trace text. A v2 bundle may include stop reason and time-limit metadata; v1 does not. Other manifest versions, unknown fields, invalid version-specific capture metadata, wrong fixed entries, and integrity mismatches fail visibly. Bundle output currently uses v2.
- Current trace and diff JSON schemas (v7 and v3) are produced, not JSON import formats. Trace JSON versions v1-v5 and diff JSON versions v1-v2 were standalone exports and are not imported or migrated. Trace schema v6 was not published. This document makes no compatibility or round-trip claim for those historical exports.
- Package inventory comparison requires the Linux package schema `sideeffect.inventory` v2. Unsupported schema versions or malformed documents are rejected; it does not convert older versions. Startup correlation requires a saved Linux aggregate startup inventory with schema `sideeffect.startup_inventory` v2 and raw trace text. It does not upgrade older startup documents.
- Session readers accept only the v1 envelope and the exact artifact combinations in the table above. Unknown platform/source/artifact combinations, unexpected versions, unknown manifest fields, duplicate or extra artifacts, oversized files, and digest mismatches are rejected. Windows runtime artifacts are unsupported in sessions. A session's `complete` status means the selected collectors produced their declared artifacts, not exhaustive coverage.
- The Windows ETW v2 capture is a prototype output only; no current command imports it. The explanation JSON, aggregate summary, audit-session review, and HTML report are likewise output-only.
- Local-model previews and analyses are versioned outputs, not persisted capture evidence or general import formats. The local model registry is persisted per user and accepts only its current exact schema version; no registry migration is promised. Model runtime compatibility and schema validation do not establish answer quality.
- Unsupported or malformed raw trace rows are represented by parser diagnostics/partial status where possible; this is separate from accepting an unsupported SideEffect JSON schema. Diff refuses partial parsed traces rather than treating unparsed rows as absent events.

No automatic schema migration is currently provided. A reader that supports only an exact version must reject unsupported versions visibly rather than infer fields or silently reinterpret values. An output that has no schema-name field (the deterministic explanation shapes) is still versioned by its `schema_version` field, but is not a general import contract.

## Integrity and semantic limits

SHA-256 fields bind a reference to particular bytes for equality and consistency checks. A successful hash check does not authenticate a producer, prove when or how the bytes were collected, prove capture completeness, establish that an operation succeeded beyond the recorded syscall result, or make the data safe to share. Hashes may reveal equality and can be guessable for low-entropy inputs.

For trace inspection, `source_sha256` is computed over the exact bounded byte buffer parsed, and evidence references identify line number, byte offset, and byte length within those bytes. The evidence command verifies that tuple against the supplied raw trace. Diff references carry separate left/right fingerprints and source tuples. Bundle and session hashes check artifact consistency against local bytes; session inspection's schema-header check is not full semantic validation. Windows ETW's `document_sha256` identifies its serialized representation and is not authentication. Inventory evidence hashes, where present, have the same integrity-only limitation.

## Versioning and compatibility policy

- Keep source evidence, uncertainty, diagnostics, and partial/unsupported states explicit. A derived field or summary must not replace its underlying evidence or overstate what the source establishes.
- Increment the relevant schema version when a serialized contract's fields, meanings, requiredness, or interpretation change incompatibly. Do not reuse an unpublished version number as if a format had shipped; trace v6 is intentionally noted as unpublished.
- A new artifact contract can be added to the session platform matrix without changing the session envelope version only when envelope fields and status/completeness semantics remain unchanged. Changing those envelope semantics requires a new envelope version. A native artifact's format changes require that artifact's own version change and explicit reader support.
- Add reader support for each accepted version deliberately. Document whether it is parsed, validated, rejected, or migrated. If a migration is introduced, preserve raw source evidence and uncertainty, describe the conversion, and test that supported input versions round-trip without silent semantic loss. No migration is promised by the current formats.
- Document tested and untested operating systems, architectures, toolchains, tracer versions, and trace sources in the compatibility matrix and release notes. Current tested scope is summarized in [INSTALL.md](INSTALL.md#compatibility-and-observation-matrix); it is bounded evidence, not broad OS or trace-source compatibility.

For current run-bundle details, see [ARCHITECTURE.md](ARCHITECTURE.md#versioned-run-record). For the exact session reader contract, see [AUDIT_SESSION_COMPATIBILITY.md](AUDIT_SESSION_COMPATIBILITY.md).
