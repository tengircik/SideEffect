# Repository guidance

This file applies to the entire repository. Check for more specific `AGENTS.md` files in a subdirectory before changing files there.

## Project scope

- SideEffect is planned as a local-first Rust CLI for Linux x86_64. The initial capture backend uses an external `strace` executable.
- WSL2 is an optional environment for users who already have it. Do not describe the product as a native Windows tracer or imply that WSL2 is installed automatically.
- The core workflow is a paired comparison of observed process, file, and network-related events, with event-level references to raw evidence.
- Preserve the distinction between an observed fact, a derived comparison, an uncertainty, and an unsupported inference. Do not claim root cause, complete coverage, or safety.
- Do not add cloud upload, telemetry, automatic privilege escalation, or an LLM dependency without an explicit product/security review.

## Language and coordination

- Write product documentation, user-facing strings, code comments, and examples in English.
- Delegated implementation and documentation work must use `gpt-6-luna` with reasoning effort no higher than `high`. The orchestrator coordinates assignments; do not spawn additional agents unless explicitly assigned.
- Keep changes scoped to the assigned files. Read relevant product, architecture, security, and contribution documents before changing behavior or documenting guarantees.
- Use `rg` to locate relevant files and references before broad edits. Do not overwrite existing user files or secrets.

## Evidence and capture boundaries

- Keep the raw trace as evidence and make every parsed or derived event traceable to its source record. Do not silently drop unsupported or malformed records; surface diagnostics and partial/incomplete status.
- Distinguish syscall attempts from successful operations using the observed result. Do not convert IP addresses into hostnames or infer a DNS identity unless it was independently observed.
- Treat captures, imported traces, command output, paths, arguments, and metadata as untrusted and potentially sensitive. Distinguish a synthetic fixture from a real capture in names, docs, and UI.
- Local-by-default means no automatic network upload or telemetry. It does not mean capture data is nonsensitive or safe to publish.

## Security and resource handling

- Never execute trace-provided text as code, shell input, HTML, or a template. Preserve argument boundaries when launching commands; do not interpolate user arguments into a shell command string.
- Parse input strictly and with explicit bounds for file size, record length, nesting/collection growth, and rendered output. Reject or report unsupported forms rather than guessing. Handle large or malformed input without unbounded allocation or silent truncation.
- Escape all trace-derived strings in HTML and insert them as inert text. Reports must work offline and must not load remote assets or make network requests.
- Do not automatically request elevated privileges. If a supported capture needs privileges, fail with an explanatory message and document the requirement; privilege design requires explicit review.
- Keep raw captures, generated reports, credentials, private keys, tokens, and environment files out of commits. Inspect staged files before committing.

## Tests and claims

- Add meaningful tests for parsers, normalization, event matching, capture status, evidence references, and renderers, using deterministic fixtures. Include malformed and oversized-input cases and HTML-injection strings where relevant.
- Keep synthetic fixtures clearly separate from real capture examples. Never label a fixture, stub, or mocked result as a successful real capture.
- Do not add empty, tautological, or fake tests, and do not invent test commands, benchmark results, coverage numbers, or feature claims. Run and report only commands that exist and were actually executed.
- A capture integration test must exercise the real supported tracer and clearly state external prerequisites; a parser fixture alone does not validate runtime capture.

## Git workflow

- Use the repository-local identity `tengircik <192506011+tengircik@users.noreply.github.com>`; do not change global Git identity.
- Review `git status` and the diff before staging. Stage explicit paths, never the entire working tree by default.
- Make an isolated commit for each meaningful, reviewed change and push it after validation. Do not force-push, reset user work, or rewrite published history.
- Do not commit raw user captures, reports containing user data, local secrets, or machine-specific configuration.
