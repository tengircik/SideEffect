# SideEffect

SideEffect's product goal is an on-demand, local audit that helps people understand software on their computer: available permissions and startup hooks/scripts, plus observed runtime activity, all tied to evidence. It does not continuously monitor the computer.

Use `sideeffect --help` or `sideeffect help` for the command list, `sideeffect help <command>` for focused examples, and `sideeffect version` to see the installed version. Most commands also accept `--help`.

> **Status: early implementation; the full product goal is not yet implemented.** The current Linux x86_64 CLI includes bounded snapshots from available dpkg, RPM, pacman, and APK package databases; visible `/proc` process status and executable-link identity; selected-path metadata, POSIX ACL, and Linux file-capability snapshots; curated XDG, systemd, SysV, and cron configuration discovery; local `strace` text and bundle inspection; complete-trace comparison; exact evidence lookup; and recording of one selected command with its traced children. These sources do not establish complete software, process, permission, or effective startup configuration. Package-manager support is source-specific, and unregistered applications and unsupported managers can be missed. Permission inspection is limited to selected paths and does not calculate effective access. A narrow Linux integration test records temporary-file and loopback TCP activity plus a child process, then verifies inspect and diff evidence; it has passed in WSL against extracted Ubuntu strace 6.8 and 6.19 packages and in Ubuntu 24.04 CI. These runs do not verify every supported kernel or trace event. Recording is not a sandbox.

Linux is the first implemented platform. Native Windows support is a core product requirement: Windows users should be able to inspect software, processes, selected-path permissions, startup configuration, and bounded process/file/network activity with evidence-linked comparisons using native Windows sources. Windows currently has uninstall-registry software registrations, a Tool Help process snapshot, bounded Run/RunOnce + Startup-folder + SCM-service + Task Scheduler startup configuration, explicit-path owner/group/DACL inspection, and an experimental ETW process/FileIo/DiskIo/TCP/UDP capture prototype. Windows runtime evidence has a bounded offline `inspect --windows-runtime` path, but no target/descendant attribution, session integration, diff/report workflow, or live file/network acceptance. WSL2 does not satisfy native Windows coverage. A Linux-only preview must be labeled as such; the cross-platform 1.0 gate requires useful native Windows workflows and real Windows validation. Platform reports will describe their different source and event coverage.

## Take an installed-package snapshot (Linux)

```sh
sideeffect inventory packages --output ./inventory.json
```

This runs fixed, read-only local queries for supported package databases present at their standard system paths: dpkg, RPM, pacman, and APK. Package-manager rows keep their source IDs, and output is shared under bounded byte, row, and time budgets. Unsupported managers are reported when detected at checked paths; missing or unsupported sources remain visible rather than being presented as empty successful results. Unknown distribution metadata leaves applicability unresolved and the aggregate partial. The output path must not already exist; SideEffect publishes the file privately (mode `0600`) and does not overwrite an existing file. A complete set of applicable, checked sources exits with status `0`; a partial, unavailable, unsupported, or otherwise incomplete read still writes its status and diagnostics and exits with status `2`. Check the status and diagnostics before relying on the listed rows.

This is not a complete software inventory. Manually copied or otherwise unregistered programs, unrecognized database formats, unsupported package managers, and custom manager installations outside checked locations may not be represented. This command does not take a process snapshot or inspect permissions, startup hooks, scripts, or runtime activity. It does not request elevated privileges or query package repositories. Package names, versions, architecture, and raw database rows can reveal installed software and system details, so treat the output as sensitive, choose a private destination, review it before sharing, and delete it when no longer needed. SideEffect does not upload or automatically delete the file.

## Snapshot Windows software registrations

```powershell
.\target\release\sideeffect.exe inventory packages --output .\software.json
```

On Windows, `inventory packages` reads selected values from current-user and accessible machine-wide Uninstall registry entries in the native and 32-bit registry views. It records registry hive/key/view references and exact selected value bytes as hexadecimal. `REG_SZ` and `REG_EXPAND_SZ` display strings are kept literal; environment variables are not expanded and uninstall commands are never launched or shell-parsed. Output uses a current-user-only Windows DACL and no-clobber publication. This covers registered uninstall entries only; portable or unregistered programs, per-user package formats, and other software registrations may be absent. The output can reveal installed applications, paths, and uninstall commands, so review before sharing.

## Inspect selected file permissions, ACLs, and capabilities (Linux)

```sh
sideeffect inventory permissions --output ./permissions.json ./some/file ./some/directory
```

On Windows, the same command accepts only explicitly selected paths and writes `sideeffect.windows_permission_inventory` v1. It reads file attributes and owner/group/DACL evidence from the same handle, opens the final reparse point itself, retains descriptor and ordered ACE bytes, and never requests SACL data or calculates effective access. Access to protected objects can be unavailable without elevation; SideEffect does not elevate. The inventory does not recurse and does not claim system-wide coverage.

This checks only the paths you name; it does not recurse. The `sideeffect.permission_inventory` v1 JSON records observed file type, owner/group IDs, mode bits, supported POSIX access ACLs (plus default ACLs on directories), and Linux `security.capability` file-capability xattrs. Raw ACL and capability bytes are retained as bounded hex with SHA-256 fingerprints; validated ACL entries and Linux VFS capability revisions 1–3 are decoded. Final-component symlinks are not followed; intermediate components use normal Linux path resolution. Only regular files and directories are supported. Permission denial, unsupported filesystems/xattrs, malformed data, I/O errors, and limits are reported, make the snapshot partial, and produce exit status `2`; the partial JSON is still published. Limits are 256 paths, 4 KiB per path, 64 KiB per xattr, 8 MiB aggregate ACL bytes, 8 MiB aggregate capability bytes, a 5-second between-path deadline, and the common 64 MiB serialized output cap. The deadline cannot cancel a filesystem syscall already in progress, so one may take longer. No elevated privileges are requested.

This records selected metadata, ACL, and file-capability configuration; it does not calculate whether a particular user can access a file and does not constitute complete permission or system inventory. The mode-0600 output is sensitive because it contains paths, account IDs, modes, and raw xattr data. Choose a private destination, review before sharing, and delete it when no longer needed. SideEffect does not upload or automatically delete the file.

## Take a Linux process status snapshot

```sh
sideeffect inventory processes --output ./processes.json
```

This reads one `/proc/<pid>/status` file and the `/proc/<pid>/exe` link for each numeric procfs entry visible during the walk. It emits the `sideeffect.process_inventory` v1 schema with the capture start/end timestamps, selected process identity, executable-link target bytes and fingerprint when readable, state, UID/GID values, capability masks, `NoNewPrivs` and `Seccomp`, and byte-offset/length/SHA-256 evidence. The executable target is read as link text; SideEffect does not open or execute it. The walk is an interval, not an atomic snapshot; processes can appear, exit, or change while it runs. It covers only entries visible through the current procfs view and does not claim exhaustive system coverage. Unreadable, vanished, malformed, missing, ambiguous, or omitted data and reached limits are recorded as diagnostics, make the result partial, and produce exit status `2` while still publishing the file.

The collector does not read command lines or other procfs files, and does not request elevated privileges. It is bounded to 8,192 numeric process directories, 64 KiB per status file, 32 MiB of aggregate status bytes, 4 KiB per executable link, 4 MiB aggregate executable-link bytes, a 10-second scan deadline, and 64 MiB of serialized JSON. Output is private (mode `0600`) and no-clobber. Process names, executable paths, IDs, credentials, capability masks, and security mode values are sensitive system information; the output is not redacted or uploaded. Review it before sharing and delete it when no longer needed.

## Take a Windows process snapshot

```powershell
.\target\release\sideeffect.exe inventory processes --output .\processes.json
```

The first native Windows inventory uses one Tool Help process snapshot and queries image paths only when Windows grants limited query access. It does not read command lines, inspect process memory, run processes, or request elevation. The process snapshot and image-path lookups are separate observations; processes may exit or a process ID may be reused between them. Inaccessible image paths remain unknown and make the document partial. Collection is bounded to 8,192 entries, 10 seconds, 32,768 UTF-16 code units per path, 4 Mi aggregate path code units, and 64 MiB of JSON. Output uses a current-user-only Windows DACL and no-clobber publication. Names and paths may be sensitive. This command does not complete Windows package, permission, startup, or runtime auditing.

## Discover Linux startup configuration

```sh
sideeffect inventory startup --output ./startup.json
```

This writes the aggregate `sideeffect.startup_inventory` v2 schema. It combines bounded XDG autostart `.desktop` discovery, systemd unit files/drop-ins and enablement-link references, common SysV init scripts and runlevel links, and common cron configuration and periodic directories. Each component retains its own scope, source statuses, diagnostics, and source-linked configuration evidence. Inert file lines include the source path, line number, byte offset/length, and SHA-256; symlink targets are recorded as inert references without resolving or executing them. Unreadable, unsupported, malformed, and limit-affected sources remain partial; missing optional locations are recorded as not present. The command publishes its private output and exits `2` for a partial snapshot.

All discovered commands, scripts, and directives are inert values. SideEffect does not execute or shell-parse them, resolve their runtime effects, evaluate startup applicability, or establish that an entry is active or will run. A systemd unit file or enablement symlink is not proof of runtime activation; cron content is not proof that cron is running or a job executed; SysV files and links do not establish that SysV init is active. These are curated common locations, not exhaustive startup inventory. Component scans use bounded directories, entries, files, per-file/aggregate bytes, lines, line length, and time; any inaccessible, unsupported, malformed, or limit-affected source is marked partial. Non-UTF-8 source path bytes are preserved alongside display paths where supported.

## Collect a Linux audit session

```sh
sideeffect audit --output ./audit-session \
  --packages --processes --startup \
  --permission ./some/file --permission ./some/directory
```

This runs only the selected, read-only Linux inventory sources and stores their existing JSON schemas as `packages.json`, `processes.json`, `startup.json`, and/or `permissions.json`, alongside `session.json`. The manifest records each source's scope, interval, status, selected key limits, diagnostic codes, artifact size, schema version, and SHA-256. The directory is staged privately and published atomically without replacing an existing destination. Session directories use mode `0700`; files use mode `0600`. Partial sources remain in the session and make the command exit with status `2`.

To include a bounded runtime observation, add `--runtime-duration-seconds` and a `--` separator before the command:

```sh
sideeffect audit --output ./audit-session \
  --processes --runtime-duration-seconds 60 -- \
  python3 -c 'print("inspect this selected command")'
```

SideEffect passes the program and each argument directly without a shell. Runtime sessions contain `run.json` and raw `trace.strace`; the trace may expose command arguments, paths, and network endpoints, so review it before sharing. The runtime source is always marked partial because capture completeness is unknown; a reached time limit is recorded explicitly. If strace is unavailable or runtime capture fails, the selected source remains unavailable/partial in the session without runtime artifacts. Partial or unavailable selected sources make the command exit with status `2`.

Review a session after verifying its manifest and artifact files:

```sh
sideeffect inspect --format text --session ./audit-session
```

Session review reports source scopes, statuses, time windows, selected limits, diagnostics, and verified artifact metadata without printing inventory rows. JSON is available with `--format json` and uses the `sideeffect.audit_session_review` v1 schema. The reader rejects symlinks, unexpected entries, unsupported artifact schema/version headers, changed bytes, and directories or files that grant group/other access. It checks JSON syntax and the declared schema/version header; this is not full semantic validation of each inventory schema. SHA-256 matching checks consistency with the local manifest; it does not authenticate who produced the session.

Sources run as separate observations across a best-effort time window. This is not an atomic snapshot, and a `complete` session means only that each selected inventory collector produced its declared artifact; it does not mean exhaustive system coverage. Linux runtime sources remain partial because capture completeness is unknown. Native Windows sessions can group selected software registration, process, startup, and explicit-path permission inventories. For example:

```powershell
.\target\release\sideeffect.exe audit --output .\audit-session --packages --processes --startup --permission 'C:\Program Files\Example\app.exe'
.\target\release\sideeffect.exe inspect --format text --session .\audit-session
```

Windows `--runtime-source` currently records runtime capture as unsupported; the experimental process/FileIo/DiskIo/TCP/UDP ETW prototype is not treated as complete runtime evidence or included in sessions. Session files can contain sensitive command arguments, paths, network endpoints, software names, account and process data, and configuration evidence. Review the local artifacts before sharing; SideEffect does not redact, upload, or automatically delete them. Platform-specific schemas and compatibility rules are documented in [AUDIT_SESSION_COMPATIBILITY.md](docs/AUDIT_SESSION_COMPATIBILITY.md).

## Discover a bounded set of Windows startup entries

```powershell
.\target\release\sideeffect.exe inventory startup --output .\startup.json
```

The native Windows adapter writes `sideeffect.windows_startup_inventory` v4. It checks current-user Run/RunOnce registry keys, accessible machine-wide Run/RunOnce keys in the 32-bit and 64-bit registry views, current-user/common Startup folders, service start configuration visible through the Service Control Manager, and boot/logon triggers in tasks visible to the current token through the local Task Scheduler. Service rows contain the service name, display name, start type, configured account, and configured binary path. Task rows contain task path, task/trigger enabled states, trigger kind, and a logon user when exposed by the trigger definition; hidden tasks are included. For matching boot/logon tasks, action rows preserve the task/action indexes and action type; Exec actions include the configured executable path, arguments, and working directory as inert strings. Other action types and unreadable or over-limit fields are reported as unsupported or partial with diagnostics. No task action is launched, expanded, or shell-parsed, and task XML is not collected. Registry values, service paths, and task metadata stay inert: environment variables are never expanded, and command text is never parsed or executed. Startup-folder entries are listed by path and type; shortcut contents are not inspected. COM enumeration is local and uses the current token without alternate credentials or automatic elevation. Folder/task/trigger/action counts, string sizes, diagnostics, and elapsed time are bounded. This curated snapshot does not prove that any entry applies or ran; inaccessible folders/tasks and limit hits are reported as incomplete, and the scheduler call's visible task set is not an all-users guarantee.

Schema v2 added service rows; v3 added Task Scheduler trigger rows; v4 adds indexed Task Scheduler action rows and inert fields for Exec actions. Service collection uses only local SCM enumeration and `SERVICE_QUERY_CONFIG`, never requests elevation, and marks access failures or limits partial/inaccessible. It includes Win32 and driver service types and is bounded to 8,192 services, a 256 KiB SCM enumeration buffer, 64 KiB per service configuration and 4 MiB aggregate configuration bytes, 32,768 UTF-16 code units per returned service string and 4 Mi aggregate service-string units, the shared 10-second inventory deadline, 256 retained service diagnostics, and the shared 64 MiB JSON output limit. Services not visible or queryable under the current token remain unknown. The current slice records the base start type only; delayed-auto-start and service-trigger details are not queried. Start type is configuration only, not evidence that a service started or is running.

## Compare startup paths with a saved trace

```sh
sideeffect correlate-startup ./startup.json ./capture.trace
```

This read-only operation accepts a saved Linux `sideeffect.startup_inventory` v2 JSON file and a saved raw `strace` text file, and writes a bounded `sideeffect.startup_correlation` v1 JSON document to stdout. It reports candidate matches only when a simple literal absolute executable path from an XDG `Exec` value or systemd `Service.Exec*` directive exactly equals the filename argument of a successful `execve` or `execveat` row. Each candidate includes the startup source line/hash and trace fingerprint plus exact line/byte reference. Duplicate configuration rows and runtime rows remain grouped, preserving ambiguity.

The operation never runs, shell-parses, or expands startup command text. It does not parse cron or SysV, perform `PATH` lookup, match `argv[0]`, or resolve symlink targets or canonical paths; exact literal path strings are compared as written, so a literal path may itself name a symlink. Values outside the narrow literal subset are counted as unsupported and make the result partial. Inventory input is capped at 64 MiB, raw trace input at 32 MiB, supported configuration rows at 50,000, copied configuration/source metadata at 8 MiB, parsed trace rows at 100,000, and JSON output at 64 MiB. Startup source references are carried through from the supplied inventory and source files are not re-read. Complete means only that inputs and rows in this narrow supported subset were processed without partial or unsupported items; it does not mean the full startup/runtime relationship was covered. Partial inputs or unsupported relevant rows publish status and exit `2`; invalid inputs exit `1`. Runtime evidence names the `strace -f` row-prefix identifier `caller_task_id`, which may be a task/thread ID and is not necessarily a process or parent PID. A candidate does not prove that a startup hook ran, that a startup manager caused the process, or that unrelated activity is attributable. The inventory and trace are separate snapshots; raw-trace capture completeness remains unknown, and no match is not evidence of non-execution. Treat the output as sensitive local evidence and review it before sharing.

## Try the current command

From the repository root, run:

```sh
cargo run -- inspect tests/fixtures/strace/synthetic-minimal.trace
```

This prints a schema-v7 JSON document containing parsed records, raw trace lines, source byte offsets, diagnostics, optional `lexical_path_hint` values, conservative `outcome` summaries for selected syscalls, evidence-linked process-creation relations from caller task IDs to returned child PIDs, and the SHA-256 fingerprint of the exact bytes parsed. When inspecting a schema-v2 bundle, the document also includes its `bundle_capture` stop reason and optional requested time limit; raw trace inputs and legacy schema-v1 bundles have no bundle context. The fixture is synthetic; it is not a real system capture. A fingerprint identifies bytes but does not authenticate them or establish capture completeness. For a readable, terminal-safe view of every parsed and unparsed record, run:

```sh
cargo run -- inspect --format text tests/fixtures/strace/synthetic-minimal.trace
```

Exit status `0` means every input record was classified and continuation records were reconciled; `2` means JSON or text was produced with a partial parse; `1` means the input or output could not be processed. Text output retains raw values and is not redacted. **Parse status says nothing about whether the original OS capture observed every event.**

For `openat` and `openat2`, records may also include a `lexical_path_hint` when the path argument is unambiguously printable and either absolute or paired with an absolute `-yy` directory annotation. It preserves `.` and `..` segments and is not a canonical or filesystem-resolved path; symlinks, descriptor reuse, resolution flags, and trace truncation can make it differ from the path the kernel ultimately used. Raw arguments remain the evidence source.

Inspection text shows an `Outcome` line for complete `execve`/`execveat`, `openat`/`openat2`, and `connect` records. It is a conservative summary of the syscall result only; unfinished/resumed rows and other syscall names have no outcome.

`inspect` and ordinary `diff` consume raw `strace` text; `inspect --bundle DIR` reads validated `sideeffect.run` v1 or v2 recording bundles, and `record --bundle` writes v2. `diff --bundles LEFT_DIR RIGHT_DIR` validates both bundles and compares their contained traces with the same JSON, text, or Linux HTML output as raw trace comparison. Bundle validation checks fixed entries, ownership and private modes, symlink and size rules, supported manifest fields, and exact trace length and SHA-256 before parsing; manifest status fields do not establish capture completeness or command success. Earlier schema-v1 through v5 trace exports and schema-v1/v2 diff exports remain standalone; the current CLI does not import or migrate them. Trace inspection uses schema v7, while diff output remains schema v3. Schema-v2 bundle inspection adds `bundle_capture` metadata to JSON and text; raw traces and legacy schema-v1 bundles omit it. Timed bundles include the stop reason and requested time limit, return status 2 with an incompleteness warning, and remain ineligible for `diff --bundles`. A SHA-256 fingerprint is identity metadata, not a signature, authenticity proof, redaction, or completeness signal. Because traces may be sensitive, fingerprints are sensitive metadata too; low-entropy traces may be guessed, and exact trace bytes never leave the local machine through these commands.

Schema v5 introduced evidence-linked process-creation relations supported by complete successful `fork`, `vfork`, or qualifying `clone`/`clone3` rows. Schema v7 names the source field `caller_task_id`: with `strace -f`, the line prefix identifies the calling task/thread ID, which is not necessarily the Linux parent process PID when a non-leader thread creates a process. Current relations link that caller task ID to the child PID returned by the syscall; they do not claim an OS parent-child relationship. Each relation refers to its exact result row and, for split `clone3`, its unfinished-arguments row. Thread clones, `CLONE_PARENT` calls, ambiguous child-PID claims, unsupported clone flags, and unpaired/incomplete calls do not produce guessed links. A unique unfinished/resumed `clone3` relation carries evidence references to both rows. This is not a complete process tree, does not establish PID generations or a capture root, and does not infer causation from configured startup entries. `correlate-startup` can report only narrow exact-path candidate matches between saved configuration and successful exec rows.

Published traces, bundles, and report files stay at the output paths you choose until you delete them. SideEffect does not upload, rotate, or automatically delete published data. Handled failures and cancellation clean up private staging; a machine crash can leave a private staging directory behind.

## What the parser accepts

The parser handles bounded outer syntax for line-oriented `strace` text, including syscall records, common control lines, and `-yy` file-descriptor annotations; it preserves raw arguments and results rather than fully decoding each syscall. `record` uses `-f -ttt -yy -s 256 -e trace=%process,%file,%network --kill-on-exit` and a generated FIFO output path; `inspect` does not verify how an input was produced. See the [`strace(1)` manual](https://man7.org/linux/man-pages/man1/strace.1.html). Narrow real-tracer checks have exercised strace 6.8 in Ubuntu 24.04 CI and WSL, and 6.19 in WSL; they do not validate all records or events. See the [compatibility and observation matrix](docs/INSTALL.md#compatibility-and-observation-matrix).

Input is limited to 32 MiB, each physical record to 64 KiB, and the document to 100,000 records. JSON and text output are limited to 64 MiB. Oversized or invalid UTF-8 input fails without emitting an inspection document. Unrecognized, malformed, or unpaired continuation lines remain visible as raw records with diagnostics.

## Compare two traces

```sh
cargo run -- diff tests/fixtures/diff/baseline.synthetic.trace tests/fixtures/diff/updated.synthetic.trace
```

`diff` emits schema-v3 observed syscall-row additions, removals, and uniquely paired result changes with source line/byte references and separate SHA-256 fingerprints for the exact baseline and candidate bytes. `matching_policy.exact_fields` names the compared row/result fields, while `matching_policy.display_only_fields` identifies lexical hints that never participate in matching. References use the baseline input for `before` and candidate input for `after`, in command argument order. Optional side-specific lexical path hints are display-only; matching uses exact raw arguments and results, never the hints. Fingerprints identify each input but do not authenticate it or establish capture completeness. The fixture pair is synthetic and is not a real capture. A comparison requires both inputs to parse completely; parser status still cannot prove capture completeness. The initial matcher treats records as a multiset, ignores only the parsed PID and timestamp prefixes for matching, and keeps exact arguments/results (including path and file-descriptor text). When multiple same-signature result records remain and no pairing is justified, they remain separate additions/removals instead of an invented changed-event pair. Paired unfinished/resumed rows are compared as separate trace rows, not merged into a reconstructed call. Control rows are outside the initial comparison and their counts are reported. The process/file/network labels are syscall-name buckets; they do not claim that an operation succeeded or caused another event.

For complete `execve`/`execveat`, `openat`/`openat2`, and `connect` records, inspection may include an `outcome` of `success`, `failure`, `in_progress`, or `unknown`. The summary is derived only from strict result spellings (`connect`'s `EINPROGRESS` is in progress); unsupported or malformed result forms are `unknown`. It does not describe a higher-level effect. The exact `raw_result`, `raw_line`, and sibling evidence reference remain available. Other syscalls and unfinished/resumed rows have no outcome field.

## Explain bounded observations

Create a deterministic explanation without installing a model:

```sh
sideeffect explain TRACE
sideeffect explain --diff BASELINE CANDIDATE
sideeffect explain --inventory-diff BEFORE.json AFTER.json
```

Trace explanations summarize selected syscall result classifications, direct evidence-linked process relations, parse and capture limitations, and known unknowns. Diff explanations summarize observed syscall-row changes. Package inventory explanations compare saved `sideeffect.inventory` v2 snapshots for additions, removals, and changed package versions/statuses. An unmatched package is reported as added or removed only when the relevant source is complete on both sides; otherwise it stays unresolved. All three commands emit bounded JSON, preserve evidence locations, and omit raw syscall arguments/results, raw package rows, diagnostic text, and source fingerprints. Inventory comparison covers only the listed supported package sources; it does not provide an exhaustive software inventory.

Trace explanations return status `2` when parsing is partial while still emitting the bounded summary. Trace diffs require complete parses. Package inventory comparisons return status `2` when source coverage is partial and reject malformed, oversized, unsupported, or unknown-field input. These deterministic commands do not use a language model.

### Optional local model setup

Model management is opt-in. Use `sideeffect model list` to inspect the pinned catalog, installation state, task/platform scope, license, size, evaluation status, user-provided GGUF registrations, and the selected model for each task. `sideeffect model show ID` prints one catalog or registered-model record as JSON. No model has a positive quality recommendation; catalog installation and runtime compatibility do not imply useful or accurate answers.

```sh
sideeffect model list
sideeffect model show query-qwen3-1.7b-q4-k-m
sideeffect model setup query-qwen3-1.7b-q4-k-m
# Review the displayed terms, then type the exact ACCEPT <license-id> prompt.
sideeffect model-query-preview --question "Find failed connect calls." TRACE
sideeffect model-query --question "Find failed connect calls." \
  --runtime /path/to/llama-completion \
  --confirm-sha256 REVIEWED_PREVIEW_SHA256 TRACE
```

The downloadable catalog contains evidence-selection and query-plan candidates for Linux x86_64, plus an explanation candidate for Linux x86_64 and native Windows. Every catalog model has failed a task-specific quality check and is not recommended. Evidence selection and query-plan analysis remain Linux x86_64 only; explanations have a separate Linux x86_64 and native Windows path. `sideeffect model setup ID` is the shortest catalog flow: it shows the license and evaluation status, downloads the pinned file after typed license acceptance, verifies it, then selects it for its declared task. It does not install the inference runtime. On supported platforms, `sideeffect model add --name NAME --path FILE --for TASK[,TASK...] [--license ID]` registers an existing local GGUF by size and SHA-256. The supplied license label is unverified metadata. Registration does not establish model format compatibility or answer quality. `sideeffect model select TASK ID` persists a selection independently for each supported task. `sideeffect model remove ID` unregisters a user-provided model without deleting its source file; removing a catalog model requires typing `DELETE ID` and removes only its verified catalog file and selections.

Catalog downloads are explicit. Before a request, SideEffect displays the source, immutable revision, file size, license ID/terms, platform scope, and evaluation note, then requires the exact typed `ACCEPT <license-id>` response. It persists acceptance for that model/revision/license before network access. The downloader uses pinned HTTPS sources and approved HTTPS redirects, enforces the catalog size and SHA-256, stages privately, and publishes without replacing an existing file. The per-user registry and model store live under `%LOCALAPPDATA%\SideEffect` on Windows or `$XDG_DATA_HOME/SideEffect` (default `$HOME/.local/share/SideEffect`) on Linux with restrictive user-only access. Analysis never downloads weights. Runtime binaries are separate user-provided executable dependencies and are not downloaded or installed by these commands.

Each preview digest binds the selected model ID and SHA-256, catalog source/revision or the user-provided marker, license/evaluation status, and the task's pinned runtime/backend metadata. Changing the selection requires a fresh preview and confirmation. Trace evidence and prompts are not uploaded. A selected runtime remains trusted executable code; offline mode and platform-specific resource/network controls are defense in depth, not a sandbox.

### Experimental local analysis limits

Local question-focused evidence selection, typed query plans, and evidence-grounded model explanations are experimental and not approved for release or decision-making. The selected model's output is unverified and remains separate from deterministic source evidence. The evidence-selection and query-plan commands are Linux x86_64 only; the query-plan model prompt contains only the question and fixed scope while bounded queryable facts stay outside the prompt. Explanation has a separate Linux x86_64/native Windows path; Windows supports CPU/CUDA selection and does not silently fall back after CUDA failure. Citation validity does not establish that a generated statement is true. See the [evidence-selection setup and evaluation record](docs/LOCAL_MODEL_EVALUATION.md), [query-plan contract](docs/LOCAL_QUERY_PLAN_EVALUATION.md), and [explanation limits](docs/LOCAL_MODEL_EXPLANATION_EVALUATION.md). No model has passed its applicable semantic quality gate.

## Create an aggregate diff summary

For an export that omits event-level values, run:

```sh
sideeffect diff-summary BASELINE CANDIDATE
```

This emits a separate `sideeffect_redacted_diff_summary` schema containing only added/changed/removed diff-group counts by fixed category. It omits syscall names, raw arguments/results, lexical path hints, source hashes, evidence references, and local input paths. This is field omission, not secret detection: categories and counts may still be sensitive, so the summary is not a safe-to-share verdict.

On Linux, write the same aggregate as a local static HTML report with:

```sh
sideeffect diff-summary --format html --output SUMMARY.html BASELINE CANDIDATE
```

The HTML output is bounded, mode `0600`, no-clobber, offline, and contains no scripts or remote assets. JSON goes to stdout; neither command uploads data. This summary is a distinct aggregate export, not a redacted detailed diff, and it contains no event-level references.

To look up a diff reference from the baseline fixture, use its `before` tuple (`line=2 byte=65 length=72`) and source hash:

```sh
sideeffect evidence tests/fixtures/diff/baseline.synthetic.trace d75a97b3058387a94ca085ed28ab08826671f305be8c70e947df902de553ca9d 2 65 72
```

The command first verifies that the supplied lowercase SHA-256 fingerprint matches the exact bounded bytes parsed, then requires an exact line, byte-offset, and byte-length match to one parsed syscall row. It rejects malformed or mismatched fingerprints and control, unparsed, out-of-range, or mismatched references. If the trace has a partial parse, it prints a warning and exits with status `2`. A successful lookup establishes byte identity relative to the supplied fingerprint and a positional match within those bytes; it does not establish authenticity or capture completeness. Fingerprints are not redaction and can reveal equality or be guessed for low-entropy inputs.

Each input remains bounded by the parser limits above (64 MiB combined maximum); a diff has at most 200,000 grouped delta rows and JSON/text output is capped at 64 MiB before stdout is written. The comparison keeps argument/result strings borrowed from parsed input and emits source references rather than copies of entire raw lines. Review reports before sharing: they may contain sensitive paths, arguments, and endpoint details.

On Linux, create a self-contained static report with:

```sh
sideeffect diff --format html --output REPORT.html BASELINE CANDIDATE
```

The report is capped at 64 MiB, mode 0600, and never replaces an existing destination. It uses no scripts, external assets, or network requests; trace-derived markup is escaped, and control/bidi formatting characters are shown as visible spellings. Local input paths are omitted, but raw arguments, paths, and endpoint details may remain. HTML file export is not available in the native Windows build; Windows users with WSL2 can run the Linux build there. Review the report before sharing it.

For a readable terminal view of the same comparison, use:

```sh
cargo run -- diff --format text tests/fixtures/diff/baseline.synthetic.trace tests/fixtures/diff/updated.synthetic.trace
```

Text output is ASCII-only: quotes, control characters, terminal escapes, and non-ASCII scalars in trace values are escaped, so imported content cannot inject ANSI terminal control sequences. The output remains sensitive and is not sanitized for sharing.

## Record one command (Linux only)

To compare two existing validated run bundles directly, use `sideeffect diff --bundles BASELINE_DIR CANDIDATE_DIR`. Add `--format text` for terminal-safe text or, on Linux, `--format html --output REPORT.html` for the bounded offline report. Bundle paths are not included in comparison output. The strict reader verifies each manifest and trace before parsing; manifest status fields do not prove successful execution or complete capture, and partial traces are rejected before diff output.

```sh
sideeffect record --trace ./run.trace -- /usr/bin/printf 'hello\n'
```

This requires Linux and an external `strace` version 6.8 or newer. Although `--kill-on-exit` exists in strace 6.6, 6.8 is the lowest release exercised by SideEffect's real-tracer integration checks. SideEffect passes the program and each argument separately, without a shell; the command runs with the invoking user's permissions. Its stdout and stderr remain attached to the terminal. The trace is written with mode `0600`, capped at 32 MiB, and published only if that destination does not already exist. Once SideEffect has finalized and published a nonempty trace, it propagates the `strace`-reported exit code; if `strace` reports signal termination, SideEffect terminates with that signal. The `strace(1)` manual says the tracer normally mirrors the wrapped command's exit status or signal. SideEffect capture errors take precedence and are reported as errors. The propagated status is not an independent verification of command outcome, tracer success, or capture completeness.

If the trace exceeds the limit, SideEffect terminates its `strace` process and discards the partial trace. `--kill-on-exit` asks supported strace/kernel combinations to kill tracees when the tracer exits, but descendants that escape tracing (for example, through `CLONE_UNTRACED`) may survive. This feature does not constrain the command: it can modify files, access the network, and perform other actions available to the user. Tracing can also change timing or behavior. Do not use it as a sandbox or run untrusted programs without separate OS isolation. Raw traces can contain arguments, paths, socket addresses, and other sensitive values.

To retain a minimal local run manifest beside the raw evidence, use:

```sh
sideeffect record --bundle ./run.sideeffect -- /usr/bin/printf 'hello\n'
```

To bound a capture by wall-clock time, add `--duration-seconds <seconds>` before `--`, where `<seconds>` is an integer from 1 to 3600. When the limit is reached, SideEffect terminates its direct tracer and publishes the available nonempty partial trace or bundle; the command exits with status `2`, and target outcome and capture completeness remain unknown. Bundle v2 records the requested duration and whether capture stopped at the time limit or when strace exited. Inspecting a timed bundle exits `2` with a warning that absence from the trace is not evidence of non-occurrence; `diff --bundles` refuses timed bundles because the event set is incomplete.

The bundle directory contains exactly `run.json` and `trace.strace`. It is staged beside the requested destination and published with one no-clobber directory rename; the directory is mode `0700` and both files are mode `0600`. Bundle creation rejects destination parents writable by other users unless the sticky bit protects entries (as in `/tmp`). Processes running as the same user are within the trusted local-user boundary and can still alter files they own. The schema `sideeffect.run` version 2 records SideEffect and strace versions, the fixed capture profile, raw strace-reported exit code or signal, the exact trace byte length and SHA-256, explicit unknown/unverified status fields, optional wall-clock limit in milliseconds, and stop reason. It deliberately omits program/argument strings, environment, working directory, user identity, absolute paths, command output, tracer diagnostics, and parsed event copies. The raw trace itself may contain arguments, paths, and endpoint values. Hashes can reveal equality and are not authenticity proofs. Files and the staging directory are synced before publication; if syncing the parent directory fails after the atomic rename, the complete bundle is visible and the CLI warns that persistence across sudden power loss is uncertain while still propagating the strace-reported status. Bundle creation and inspection are Linux-only. `sideeffect inspect --bundle DIR` validates the supported v1 or v2 schema and files, then emits trace evidence without including the bundle path. Schema-v2 bundles add `bundle_capture` with stop reason and optional requested time limit; raw traces and v1 bundles omit this context.

## Planned product

The broader product goal is a user-triggered, local audit on Linux and Windows. Both platforms should support useful software/process/selected-path-permission/startup inventories and bounded runtime evidence that can be inspected and compared. M10 is complete for its documented bounded native Windows inventory scope: selected software registrations, visible processes, explicit-path permissions, Run/RunOnce and Startup folders, SCM service configuration, and current-token-visible Task Scheduler boot/logon triggers with bounded action evidence. Deterministic adapter tests, real Windows inventory/session smoke tests, and the hosted Windows Server 2022/2025 jobs passed. These sources are curated and do not establish exhaustive system coverage. M9 provides shared audit sessions with per-source timestamps and status; it will not treat separate collections as an atomic snapshot. Windows runtime sessions explicitly report unsupported. The experimental ETW JSON can now be reviewed separately with `inspect --windows-runtime`, which validates its v3 representation but does not authenticate capture authorship or completeness. Milestone 11 now has an experimental ETW process/file/network decoder and capture path, but no live file/network acceptance, target/descendant attribution, session integration, or Windows diff/report workflow. The OS adapters use native sources and document their distinct coverage. WSL2 does not count as Windows support. The narrow Linux `correlate-startup` candidate match does not establish hook execution or causation. Effective-access analysis and exhaustive source coverage remain future work. SideEffect does not continuously monitor the computer. Static HTML export exists on Linux; browser compatibility beyond renderer tests remains unverified.

## Limits and privacy

`inspect` and `diff` read local files and write JSON or escaped terminal text to stdout. `record` executes the selected command under `strace` and writes a local raw trace. No command uploads data or uses telemetry. Traces and output retain arguments, paths, network endpoints, or other sensitive values. Review them before sharing.

The current capture feature is an observation aid, not a sandbox, malware detector, exhaustive computer audit, or safety verdict. A syscall attempt does not necessarily mean it succeeded, and event proximity does not prove causation. See [SECURITY.md](SECURITY.md).

### Data retention and deletion

SideEffect publishes persistent artifacts only at the output path you select. Traces, bundles, inventories, sessions, and reports remain there after the command exits until you delete them; SideEffect does not automatically redact or delete them. Review each artifact before sharing because it may contain paths, software names, process data, arguments, endpoints, or configuration evidence. Private file permissions do not encrypt the contents.

Delete an individual file through your file manager or a command-line tool using its exact path. For example, on Linux use `rm -- ./run.trace`; on Windows PowerShell use `Remove-Item -LiteralPath .\run.trace`. To delete a bundle or session directory, select that exact directory in your file manager. Ordinary deletion does not guarantee secure erasure: filesystem snapshots, backups, or storage-device behavior may retain recoverable copies.

## Documentation

- [Build and install from source](docs/INSTALL.md)
- [Product brief](docs/PRODUCT.md)
- [Architecture plan](docs/ARCHITECTURE.md)
- [Delivery plan](docs/PLAN.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE)
