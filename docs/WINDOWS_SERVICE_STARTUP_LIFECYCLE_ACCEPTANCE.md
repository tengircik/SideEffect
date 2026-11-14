# Windows SCM startup lifecycle acceptance

The Windows hosted CI matrix runs
`scripts/test_windows_service_startup_lifecycle.ps1` on disposable GitHub-hosted
Windows Server runners after building the SideEffect CLI. The script refuses to
run without both hosted-runner markers and an already-administrative token. It
does not elevate and must not be run against a developer or self-hosted machine.

The fixture uses one generated service name and one unique temporary directory
under `RUNNER_TEMP`. Before creating the service it checks that the exact
generated SCM registry key and inert image path are absent. The service's image
path points to a nonexistent file inside that temporary directory, its startup
type is `disabled`, and it has no trigger configuration. The fixture is never
started. Its only change is a static display-name update while it remains
disabled. The script uses SCM create/config/delete operations only and removes
the exact generated service in both normal and failure cleanup. Inventory JSON
is bounded, kept in the fixture directory, and removed during cleanup.

For the baseline, added, changed, and removed states, the script runs the real
`inventory startup` CLI. Each snapshot must have a complete
`service_start_configuration` source; unrelated startup sources may make the
aggregate inventory partial. The real `explain --inventory-diff` CLI reports
the display-name change for the matched fixture service, linked to the exact
before and after `service_entries` evidence rows. When aggregate inputs are
complete it must also report add/remove deltas. If either aggregate input is
partial, the comparison must remain partial and suppress the unmatched
add/remove presence claim; the test then verifies the service's source rows
directly in each inventory and does not promote that snapshot difference into
a comparative presence result. If the SCM source itself is incomplete, the
test reports only its bounded status and diagnostic codes and fails the
lifecycle claim as unknown. The observed SCM row must retain its native
`EnumServicesStatusExW/OpenServiceW/QueryServiceConfigW/QueryServiceConfig2W`
evidence and report `configured=present`, `effective=unknown`, and
`observed=unknown`.

This exercises one disabled service's bounded SCM configuration lifecycle on
the named hosted runner images. It does not start a service, validate a real
service executable, exercise scheduled tasks or trigger firing, prove that a
configuration change caused runtime behavior, or establish exhaustive startup
coverage. Incomplete host sources leave the lifecycle result unknown and fail
the acceptance instead of producing an unsupported presence claim.
