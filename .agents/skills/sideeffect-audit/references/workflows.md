# SideEffect task reference

Use the platform-native CLI already installed by the user. Run `sideeffect <command> --help` when syntax differs from these examples. All evidence files may contain sensitive local data.

## Linux x86_64

### Bounded inventory

```sh
sideeffect inventory packages --output /private/path/packages.json
sideeffect inventory processes --output /private/path/processes.json
sideeffect inventory startup --output /private/path/startup.json
sideeffect inventory permissions --output /private/path/permissions.json /user/selected/path
```

Use a new, private output path. The command does not overwrite an existing path. The permission collector only reads paths explicitly named by the user.

### Selected audit session

```sh
sideeffect audit --output /private/path/session --packages --processes --startup
```

Add `--permission PATH` only for paths the user selected. Review with:

```sh
sideeffect inspect --format text --session /private/path/session
```

### Runtime capture

For a user-selected command, use Linux `record` or the audit runtime option only after showing the complete argv, duration, trace destination, and expected evidence. The selected command runs with the caller's permissions; capture is not a sandbox. Linux runtime requires external `strace` 6.8 or later.

```sh
sideeffect record --trace /private/path/capture.trace -- PROGRAM ARGUMENTS
sideeffect explain /private/path/capture.trace
```

Do not substitute shell text or a discovered startup command for `PROGRAM ARGUMENTS`.

## Native Windows

### Bounded inventory

```powershell
sideeffect.exe inventory packages --output C:\private\packages.json
sideeffect.exe inventory processes --output C:\private\processes.json
sideeffect.exe inventory startup --output C:\private\startup.json
sideeffect.exe inventory permissions --output C:\private\permissions.json C:\user\selected\path
```

Use a new output path with user-only access. Windows source visibility depends on the current token and selected native sources.

### Runtime evidence

Windows ETW capture uses the shared NT Kernel Logger for the requested bounded window and requires an already-administrative token. It does not elevate. Explain the system-wide capture scope, duration, selected command, and destination before asking the user to confirm.

```powershell
sideeffect.exe audit --output C:\private\session --runtime-source windows-etw --runtime-duration-seconds 10 -- PROGRAM ARGUMENTS
sideeffect.exe inspect --format text --session C:\private\session
```

Do not launch the command if the requested scope or administrative context is unclear. Windows ETW records may include events from processes other than the selected command; distinguish capture-window observations from target-specific associations.

## Reviewing and comparing evidence

- Use `explain TRACE` for a deterministic, bounded summary before requesting raw trace details.
- Use `inspect --format text TRACE` for raw row review only when the user has approved exposing those fields to the agent provider.
- Use `diff LEFT RIGHT` for two complete Linux trace inputs; Windows ETW evidence uses the platform-specific `--windows-runtime` option shown by installed help.
- Use `evidence` with the exact fingerprint and source tuple from the output to retrieve a referenced source record.
- Preserve exit status `2` and partial diagnostics in the answer. A successful parser status does not prove that capture observed every system event.

## Output handling

Choose a directory the user controls, restrict access to that user, and avoid shared folders. SideEffect uses no-clobber publication and leaves completed outputs at the chosen destination. Ask before deleting or moving user evidence. Do not attach raw outputs to issues, commits, pull requests, or external services.
