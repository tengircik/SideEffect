# Security Policy

**Project status:** early implementation. `sideeffect inspect TRACE` reads one local regular file, parses bounded `strace`-style text, and writes JSON by default; `inspect --format text` emits an ASCII-only terminal-safe view of all parser rows and diagnostics. `sideeffect diff LEFT RIGHT` parses two local trace files and writes a bounded JSON comparison or ASCII-only terminal-safe text view only when both parses are complete. Linux also supports `diff --format html --output REPORT LEFT RIGHT` for a bounded static offline report. Linux `sideeffect record --trace OUTPUT -- PROGRAM [ARGS...]` runs a command under external strace and writes a capped raw trace through a private FIFO. A narrow Linux integration test records temporary file operations and loopback TCP activity, then checks inspect/diff evidence; it passed in WSL with extracted strace 6.19. Broad real-tracer compatibility and event coverage remain unverified. The HTML renderer has focused tests but has not received broad browser compatibility or accessibility review. The safeguards below distinguish current behavior from requirements for future features.

## System, scope, and threat model

The current inspector reads user-selected trace text and emits a JSON document containing raw lines and parsed fields; for a small `openat`/`openat2` subset it may add a printable-ASCII lexical path hint based on the argument spelling and a `-yy` annotation. The hint does not query or canonicalize filesystem state and can be wrong around symlinks, descriptor reuse, resolution flags, or incomplete traces; raw arguments remain authoritative. Its text view shows each row and diagnostic. The `evidence` command accepts an explicit source tuple, rejects unparsed/control/mismatched rows, and emits the selected parsed row using the terminal-safe formatter within the regular-file and output limits. For partial traces it labels the result partial; the tuple is only positional in the supplied file and is not authenticated by a content hash. Both text formatters escape controls and non-ASCII characters to prevent terminal-control injection, but do not redact secrets. The current diff reads two such files and emits schema-v2 event deltas with source offsets; it ignores only parsed PID/timestamp prefixes for matching, keeps raw arguments/results exact, reports control-row counts, and states capture completeness is unknown. The JSON `matching_policy.exact_fields` documents exact comparison fields, while side-specific lexical hints are listed in `display_only_fields` and never affect matching. Text and HTML repeat this boundary next to each hint. The HTML formatter emits static markup and CSS, applies a restrictive CSP, escapes trace values into text nodes, and includes no scripts or remote assets; it omits the local input paths. Current capture runs the selected command under `strace` and stages a bounded raw trace locally; it does not retain a structured run bundle. The main assets are the user's machine and files, input traces, command execution context, and potentially sensitive raw trace data.

The operator is trusted to select a trace file or choose a command and decide whether to run it. The selected file's contents, trace strings, command arguments, capture output, and future report values are untrusted. The inspector does not execute trace content. The recorder invokes the external `strace` binary and runs the selected command with the invoking user's permissions. The kernel, tracer, and selected syscall set form part of the observation boundary. Repository vulnerabilities are reportable when a realistic input or action crosses that boundary and causes impact beyond the documented behavior.

## Security invariants

SideEffect is a local observation and comparison tool. It is not a sandbox, malware detector, vulnerability scanner, or security verdict. `inspect` does not run the represented command. `record` runs the chosen command with the permissions of the user who starts it; it may change files, start child processes, access the network, or perform any other action available to that account.

Only run commands and inputs you trust. Use least privilege. If you choose to run an untrusted command, arrange operating-system isolation separately before running it; SideEffect itself does not provide that isolation. Do not run it as an administrator or root user unless the target command genuinely requires those privileges.

The planned v0 target is Linux x86_64 with an external `strace` executable. An existing WSL2 installation may provide a Linux environment for Windows users; native Windows tracing is not supported or promised. Capture completeness depends on the kernel, tracer version and configuration, permissions, and supported syscall set. A successful trace does not prove that every relevant interaction was observed.

Temporal order and process ancestry can help a human investigate a behavior change, but they do not prove that one event caused another. Failed syscalls represent observed attempts, not successful effects. Reports must preserve uncertainty and capture limitations.

## Data handling and privacy

The current commands have no telemetry, hosted service, or automatic report upload. `inspect` and JSON/text `diff` read local files and write to stdout; HTML `diff` writes a mode-0600 report locally; `record` writes a raw trace locally. This does not make trace data safe to share:

- Raw traces can contain command-line arguments, file paths, IP addresses and ports, and other values passed to traced syscalls. Arguments can contain credentials or tokens. Paths and output can reveal usernames, project names, customer data, or internal infrastructure.
- Command stdout and stderr may also contain sensitive information.
- The product does not plan to deliberately collect environment variables in v0, but that does not make a trace secret-free. The exact information captured depends on the command, selected syscalls, tracer behavior, and platform.
- No automatic redaction or guarantee that an export is safe to publish is planned. If redaction is added later, it must be described as best-effort unless it can be proven otherwise. Users must inspect traces and reports before sharing them.

Keep evidence bundles in a directory whose access you control. Do not attach real traces, command output, or report exports to public issues or pull requests. Use synthetic fixtures or carefully reviewed, sanitized examples instead. Do not assume that replacing a username or one apparent token removes all sensitive data.

## Implemented and planned safeguards

The following safeguards are implemented in part across `inspect`, `diff`, and `record`; remaining capture and rendering requirements are listed explicitly:

- Treat input traces, command arguments/capture output, and future report values as untrusted input.
- Preserve argument boundaries when starting a command; never construct a shell command by interpolating user-supplied text. The current record command does this and uses a generated FIFO path rather than the user-selected output path as strace's `-o` value.
- Recorded and inspected trace inputs are limited to 32 MiB; each parser limits physical records to 64 KiB and total records to 100,000. Each diff input is limited to 32 MiB (64 MiB combined); diff rows are limited to 200,000, and JSON/text/HTML serialization is capped at 64 MiB before stdout or report publication. The diff holds parsed inputs and bounded references/keys rather than copying raw lines into every delta. Reject or clearly flag malformed, oversized, truncated, and unsupported input rather than silently treating it as complete.
- The current recorder rejects an existing destination (including symlinks), stages trace data with mode 0600 in a mode-0700 directory, and uses directory descriptors plus same-directory `linkat` for no-replace publication. It discards oversized captures after terminating its direct strace process. It handles SIGINT, SIGTERM, SIGHUP, and SIGQUIT by terminating and reaping that child; parent death requests SIGKILL for strace. Traced descendants can still escape via `CLONE_UNTRACED`, and a system crash can leave a private staging directory behind. The destination parent is the canonicalized directory object opened at capture start; subsequent operations remain anchored to that object even if it is renamed.
- Render every trace-derived value as inert text in offline HTML. The current renderer escapes values into text nodes and uses a restrictive CSP with no script or remote assets; keep context-aware escaping, do not evaluate values as markup or script, and do not add network requests from a report.
- Keep raw evidence local and distinguish exact evidence from normalized or derived comparison fields.

Fake-tracer tests exercise argument construction, bounded FIFO recording, output collisions, symlink safety, and staging cleanup for pre-launch failures. A separate Linux integration test exercises real strace with two fixed Python targets, temporary files, and a loopback-only TCP connection; it requires `strace` and `python3` and stores no traces as artifacts. HTML renderer and Linux CLI tests cover injection strings, control/bidi visibility, no remote assets, output limits, mode 0600, and no-clobber behavior. Before release, broader real-tracer testing must verify additional options, target status semantics, selected observations, output limits, and cleanup behavior; HTML still needs broader browser and accessibility review.

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

The current comparison is a conservative parser-row diff, not a capture-completeness check or logical syscall reconstruction. One Linux real-tracer integration case observes a temporary file operation and a loopback connection, and a separate smoke test used `/usr/bin/true` and `/usr/bin/false`; lifecycle tests also use controlled fake executables, and parser/diff fixtures remain synthetic. HTML output is static and offline, but broad browser compatibility and accessibility remain unreviewed. Real `strace` compatibility beyond these narrow cases, other file/network-event coverage, and capture completeness remain unverified. The Linux/`strace` scope, incomplete observation possibilities, local raw-data exposure, absence of automatic redaction, and non-causal nature of event comparison are known product limitations that must remain visible in user-facing documentation.

## Reporting a vulnerability

**Availability of private reporting has not yet been verified.** Before the first public code release, maintainers must verify that GitHub private vulnerability reporting is enabled for this repository and publish its working report path here. No security email address or other private channel is designated in this document.

Until a private channel is verified, do not post exploit details, sensitive traces, or unpublished vulnerability information in a public issue. There is currently no confirmed private disclosure route; maintainers must configure one before the first public executable release.

When a verified channel is available, please include the affected commit or release, operating system and architecture, required tracer version, reproduction steps, and the impact you observed. Do not include real secrets or personal data in a report unless they are essential and you have arranged a private channel.

## Release security review

Before each public release, maintainers should verify the supported platform and `strace` range, parser limits and failure behavior, path handling, HTML escaping and offline behavior, data-retention guidance, and the private vulnerability reporting route. Release notes must distinguish implemented and tested behavior from known limitations and planned work.
