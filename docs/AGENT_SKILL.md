# Install SideEffect for an AI coding agent

SideEffect ships a portable [Agent Skills](https://agentskills.io/specification) package. It teaches a compatible agent to use the local SideEffect CLI for user-requested, evidence-linked audits. The agent uses its own selected model; the SideEffect local-model experiments are not required.

## Requirements

- Install SideEffect itself by following [Build and run SideEffect](INSTALL.md). The skill contains instructions, not the CLI executable.
- Install Node.js 22.20 or later to use the community `skills` installer.
- Review the skill source before installing it: [SKILL.md](../.agents/skills/sideeffect-audit/SKILL.md).

## Codex, Claude Code, OpenCode, and other supported agents

The `skills` CLI detects installed agents, lets you choose one or more destinations, and installs the selected skill in each agent's native location. Install globally for your user:

```sh
DISABLE_TELEMETRY=1 npx skills add tengircik/SideEffect --skill sideeffect-audit -g
```

To select destinations explicitly:

```sh
DISABLE_TELEMETRY=1 npx skills add tengircik/SideEffect --skill sideeffect-audit -a codex -a claude-code -a opencode -g --copy
```

The installer is maintained by Vercel and is separate from SideEffect. Its anonymous telemetry is disabled in the commands above. Use the installer's interactive choice or consult its current [CLI reference](https://github.com/vercel-labs/skills) and [supported-agent list](https://github.com/vercel-labs/skills/blob/main/docs/agents.md) for additional clients. The installer may change supported agent IDs and options over time.

For a project-only installation, omit `-g` and run the command from the project directory. That writes the skill into project configuration paths; review the proposed files before sharing that project.

## Oh My Pi (OMP)

Oh My Pi has a native project skill directory. Copy the reviewed folder into `.omp/skills/sideeffect-audit/` in the project, or into the user-level skills directory documented by your installed OMP version. The resulting file must be `SKILL.md` directly inside `sideeffect-audit`.

```powershell
New-Item -ItemType Directory -Force .omp\skills\sideeffect-audit | Out-Null
Copy-Item .agents\skills\sideeffect-audit\SKILL.md .omp\skills\sideeffect-audit\SKILL.md
Copy-Item .agents\skills\sideeffect-audit\references .omp\skills\sideeffect-audit\references -Recurse -Force
```

On macOS/Linux, from a clone of SideEffect:

```sh
mkdir -p .omp/skills/sideeffect-audit
cp .agents/skills/sideeffect-audit/SKILL.md .omp/skills/sideeffect-audit/SKILL.md
cp -R .agents/skills/sideeffect-audit/references .omp/skills/sideeffect-audit/references
```

Oh My Pi's skill paths are documented in its [skills guide](https://github.com/can1357/oh-my-pi/blob/main/docs/skills.md). Restart or refresh the agent session if a newly copied skill does not appear.

## Verify installation and try it

Start a new agent session, ask it to list its available skills, and invoke `sideeffect-audit`. The skill first checks `sideeffect version` and the installed CLI help. Try a narrow inventory request such as “Show the startup entries visible to this account.” The agent should select `inventory startup`, explain its output path, run only that collector, and summarize the returned status and diagnostics.

Runtime capture requires a separate confirmation of the exact command, duration, capture scope, and destination. Linux uses external `strace` 6.8 or later. Windows ETW requires an already-administrative token and uses the shared NT Kernel Logger. The skill never asks SideEffect to elevate.

## Update and remove

Update an installation with `npx skills update` following that tool's current CLI guidance. To remove it, use `npx skills remove sideeffect-audit` and review the selected destinations before confirming. For OMP, delete only the `sideeffect-audit` folder from the chosen OMP skills directory. Do not remove neighboring skills or agent settings.

## Privacy and evidence handling

SideEffect keeps its own audit data local. The agent provider is a separate data path: evidence content returned to an agent may be processed according to that provider's model and privacy settings. Review the skill and choose provider-approved data before asking an agent to inspect raw traces, paths, or inventories. The `skills` CLI is third-party software; this repository does not control its installation behavior or telemetry implementation.
