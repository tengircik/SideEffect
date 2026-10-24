# Security Policy

**Project status:** early implementation. `sideeffect inspect TRACE` reads one local regular file, parses bounded `strace`-style text, and writes JSON to stdout. `sideeffect diff LEFT RIGHT` parses two local trace files and writes a bounded JSON comparison or ASCII-only terminal-safe text view only when both parses are complete. Neither command starts a command or invokes `strace`; HTML rendering is not implemented. The safeguards below distinguish current behavior from requirements for future features.

## System, scope, and threat model

The current inspector reads user-selected trace text and emits a JSON document containing raw lines and parsed fields. The current diff reads two such files and emits event deltas with source offsets; it ignores only parsed PID/timestamp prefixes for matching, keeps arguments/results exact, reports control-row counts, and states capture completeness is unknown. Its text formatter escapes controls and non-ASCII characters to prevent terminal-control injection, but does not redact secrets. Future capture may start a user-selected command under `strace`, retain a local evidence bundle, and render offline HTML. The main assets are the user's machine and files, input traces and their potentially sensitive data, and (for future capture) the command's execution context and raw trace/output bundles.

The operator is trusted to select a trace file and, in a future capture mode, choose a command and decide whether to run it. The selected file's contents, trace strings, command arguments, future capture output, and report values are untrusted. The current inspector does not execute trace content or launch the traced command. For future capture, the external `strace` binary, the kernel, and selected syscall set form part of the observation boundary. Repository vulnerabilities are reportable when a realistic input or action crosses that boundary and causes impact beyond the documented behavior.

## Security invariants

SideEffect is planned as a local observation and comparison tool. It is not a sandbox, malware detector, vulnerability scanner, or security verdict. The current `inspect` command does not run the represented command. Future tracing will not constrain a command: it will execute with the permissions of the user who starts it and may change files, start child processes, access the network, or perform any other action available to that account.

Only run commands and inputs you trust. Use least privilege. If you choose to run an untrusted command, arrange operating-system isolation separately before running it; SideEffect itself does not provide that isolation. Do not run it as an administrator or root user unless the target command genuinely requires those privileges.

The planned v0 target is Linux x86_64 with an external `strace` executable. An existing WSL2 installation may provide a Linux environment for Windows users; native Windows tracing is not supported or promised. Capture completeness depends on the kernel, tracer version and configuration, permissions, and supported syscall set. A successful trace does not prove that every relevant interaction was observed.

Temporal order and process ancestry can help a human investigate a behavior change, but they do not prove that one event caused another. Failed syscalls represent observed attempts, not successful effects. Reports must preserve uncertainty and capture limitations.

## Data handling and privacy

The current inspector and diff have no telemetry, hosted service, or automatic report upload. They read locally and write JSON or escaped terminal text to stdout. Future capture and reporting are also planned to remain local by default. This does not make trace data safe to share:

- Raw traces can contain command-line arguments, file paths, IP addresses and ports, and other values passed to traced syscalls. Arguments can contain credentials or tokens. Paths and output can reveal usernames, project names, customer data, or internal infrastructure.
- Command stdout and stderr may also contain sensitive information.
- The product does not plan to deliberately collect environment variables in v0, but that does not make a trace secret-free. The exact information captured depends on the command, selected syscalls, tracer behavior, and platform.
- No automatic redaction or guarantee that an export is safe to publish is planned. If redaction is added later, it must be described as best-effort unless it can be proven otherwise. Users must inspect traces and reports before sharing them.

Keep evidence bundles in a directory whose access you control. Do not attach real traces, command output, or report exports to public issues or pull requests. Use synthetic fixtures or carefully reviewed, sanitized examples instead. Do not assume that replacing a username or one apparent token removes all sensitive data.

## Planned implementation safeguards

The following safeguards are partly implemented for `inspect` and `diff` and remain requirements for future capture and rendering:

- Treat the current input trace, future command arguments/capture output, and report values as untrusted input.
- Preserve argument boundaries when starting a command; never construct a shell command by interpolating user-supplied text.
- Each diff input is limited to 32 MiB (64 MiB combined); each parser limits physical records to 64 KiB and total records to 100,000. Diff rows are limited to 200,000, and JSON serialization is capped at 64 MiB before stdout is written. The diff holds parsed inputs and bounded references/keys rather than copying raw lines into every delta. Keep limits explicit for future capture/rendering, and reject or clearly flag malformed, oversized, truncated, and unsupported input rather than silently treating it as complete.
- Handle output paths conservatively. Avoid following attacker-controlled symlinks or overwriting unrelated files when creating evidence bundles.
- Render every trace-derived value as inert text in offline HTML. Escape it in the correct output context, do not evaluate it as markup or script, and do not load remote assets or make network requests from a report.
- Keep raw evidence local and distinguish exact evidence from normalized or derived comparison fields.

These requirements should be covered by implementation tests before the related features ship: process arguments must retain their boundaries without shell parsing; malformed and oversized trace fixtures must hit explicit parser limits; diff tests must preserve source references and reject partial inputs; report fixtures containing HTML/script-like strings must display as inert text; report generation must work without network access; and capture must not elevate privileges or write outside its selected evidence location through path or symlink confusion.

Trace text is already an untrusted input to `inspect`. Any new import format, such as structured JSON bundles, requires a separate security review before release.

## Reportable findings and severity context

Report security issues that demonstrate a concrete violation of a documented or planned invariant, for example:

- Report rendering executes trace-derived content or initiates a network request; or SideEffect itself makes an outbound request unrelated to the wrapped command and without user request.
- A crafted command argument, path, trace, or report value causes SideEffect to execute an unintended command, overwrite unrelated files, escape its selected output directory, or disclose local data to another party.
- An input bypasses parser or renderer resource limits and can cause a reproducible denial of service beyond the documented per-run limits.
- A vulnerability in the evidence handling path exposes command output, arguments, paths, or trace data outside the local user's intended access.

Severity depends on reachability and impact. The fact that the user intentionally ran a command does not make a separate SideEffect vulnerability acceptable; conversely, that command's expected actions under the user's permissions are not a SideEffect security finding by themselves.

## Out of scope and known limitations

SideEffect is not intended to prevent the chosen command from modifying files or accessing the network, identify malware, establish that a command is safe, capture every system interaction, or prove causation. These are product limitations, not vulnerabilities, provided the implementation does not make contrary claims or violate the invariants above. Sensitive values appearing in a local trace as a result of the selected capture are an acknowledged privacy risk; unexpected external disclosure or unsafe rendering is reportable.

The current comparison is a conservative parser-row diff, not a capture-completeness check or logical syscall reconstruction. It has no real-tracer integration evidence. HTML rendering and capture risks have not been validated because those features do not exist yet. The parser/diff tests use synthetic input; real `strace` compatibility and capture completeness remain unverified. The Linux/`strace` scope, incomplete observation possibilities, local raw-data exposure, absence of automatic redaction, and non-causal nature of event comparison are known product limitations that must remain visible in user-facing documentation.

## Reporting a vulnerability

**Availability of private reporting has not yet been verified.** Before the first public code release, maintainers must verify that GitHub private vulnerability reporting is enabled for this repository and publish its working report path here. No security email address or other private channel is designated in this document.

Until a private channel is verified, do not post exploit details, sensitive traces, or unpublished vulnerability information in a public issue. There is currently no confirmed private disclosure route; maintainers must configure one before the first public executable release.

When a verified channel is available, please include the affected commit or release, operating system and architecture, required tracer version, reproduction steps, and the impact you observed. Do not include real secrets or personal data in a report unless they are essential and you have arranged a private channel.

## Release security review

Before each public release, maintainers should verify the supported platform and `strace` range, parser limits and failure behavior, path handling, HTML escaping and offline behavior, data-retention guidance, and the private vulnerability reporting route. Release notes must distinguish implemented and tested behavior from known limitations and planned work.
