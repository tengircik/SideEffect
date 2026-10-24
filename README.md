# SideEffect

SideEffect is a proposed local-first CLI for capturing selected process, file, and network-related operating-system events from a command, comparing two runs, and producing an evidence-linked report.

> **Project status: planning only.** This repository currently contains documentation, not an executable implementation. No capture command, installer, report generator, or security guarantee is available yet. The workflow below describes the intended product.

## Why it exists

When a command behaves differently after a dependency, build, or environment change, raw system-call traces are difficult to compare. SideEffect is intended to turn a pair of captures into a compact review: what was observed in each run, what differs, and which raw trace records support each difference.

For example, a maintainer could compare the same CLI before and after an update and inspect whether the newer run attempted an extra child-process launch, file operation, or connection. A report describes observations; it does not infer root cause or decide whether software is safe.

## Proposed demo

The intended short demo uses a fixed, harmless sample command and two prepared captures. A local HTML report highlights one added event group and links it to the source records from both runs. This demo does not exist yet; no sample report is presented as real tool output.

## Planned v0

- Linux x86_64, using an externally installed `strace` executable.
- Record a command run and its capture metadata, then compare it with a second run.
- Preserve raw trace evidence and link each parsed or compared event back to that evidence.
- Export versioned JSON and a self-contained, offline HTML report.
- Keep captures and reports on the user's machine by default; no hosted service or telemetry is planned for v0.

Windows is not a native v0 target. A user who already has WSL2 installed may use its Linux environment; SideEffect will not install WSL2 or promise identical Windows behavior.

## Limits and privacy

SideEffect is an observation and comparison aid, not a sandbox, malware detector, complete audit, or proof that a command is safe. Tracer, kernel, permissions, and parser limitations may leave behavior unobserved. An attempted syscall does not necessarily mean the operation succeeded, and event proximity does not prove causation.

Raw traces, command output, paths, and arguments can contain secrets or personal data. Local storage does not make them safe to share. Reports are not automatically sanitized; inspect exports before sharing them.

## Documentation

- [Product brief](docs/PRODUCT.md)
- [Architecture plan](docs/ARCHITECTURE.md)
- [Delivery plan](docs/PLAN.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE)

The product, architecture, and delivery documents are proposals. The security and contribution documents describe requirements for future work; they do not imply that those safeguards or any executable features are implemented.
