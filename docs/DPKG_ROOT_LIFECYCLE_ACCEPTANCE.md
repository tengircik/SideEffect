# Isolated dpkg package lifecycle acceptance

`tests/dpkg_root_lifecycle_linux.rs::private_dpkg_install_update_downgrade_purge_has_selected_root_evidence`
builds two local, scriptless Debian packages for one synthetic fixture package
(versions `1.0-1` and `2.0-1`). It installs v1, updates to v2, downgrades back
to v1, and purges the package. Every dpkg transaction supplies explicit
`--root`, `--admindir`, `--instdir`, `--log`, and `TMPDIR` paths under a fresh
private temporary directory, enables `--force-not-root`, and disables trigger
runs. Its `DEBIAN` directory contains only `control`; no maintainer hooks are
present. The test calls the fixed `/usr/bin` dpkg tools with a cleared
environment, including all inherited `DPKG_*` variables, and a fixed system
tool `PATH`. It does not use `sudo` and never points dpkg at the host package
database.

The same fixed `/usr/bin/dpkg-query` invocation emits bounded tabular rows from
that private admin directory at each lifecycle state. The test passes those
exact bytes through SideEffect's existing `parse_dpkg_query_output` parser,
writes the resulting package inventory artifacts only inside the fixture, and
runs the real `explain --inventory-diff` CLI across install, update, downgrade,
and purge. It checks package version facts and each comparison's source ID,
package identity, change kind, and evidence line/byte locator against the
parsed source row. This parser/diff acceptance is separate from
`inventory packages`, which reads its normal fixed package-manager database
locations; it does not use or alter the host package database.

The packages also contain a synthetic user systemd service and timer under the
private root's `home/sideeffect-r5-synthetic/.config/systemd/user` directory.
The audit process and dpkg child receive an explicitly cleared environment
with private `HOME`, `XDG_CONFIG_HOME`, `XDG_CONFIG_DIRS`, `XDG_DATA_DIRS`,
`XDG_RUNTIME_DIR`, and `TMPDIR`, plus fixed `PATH` and `LC_ALL`. The XDG
directories and runtime directory are private to the fixture. The service's
`ExecStart` names a unique nonexistent command inside the fixture; the test
checks that it remains absent and never starts the service or timer. v1 and v2
change only the units' inert `Description` directives, giving the startup
comparator a deterministic changed-configuration case.

For each observed install, update, and purge, the test runs the real
`audit --observe-root --startup --packages --dpkg-admindir ... -- <isolated dpkg
argv>` command under the existing real `strace` capture. It verifies the exact
child argument vector and environment, selected private dpkg package state,
before/after package and startup artifact references and hashes, selected-root
snapshots, and raw runtime trace locators. The package artifacts identify the
synthetic package version from the selected dpkg database. The startup
artifacts identify the exact private service and timer paths, their source
bytes, and expected directive evidence. The v1-to-v2 comparison must link both
changed startup rows to their before and after JSON-pointer evidence; the
changed field is the comparator's digest of the directives, not a claim about
unit activation or execution.

For the selected root, the test invokes the actual SideEffect
`inventory root --hash-regular-files` CLI on the package's direct-child
install directory and compares adjacent snapshots with
`explain --inventory-diff`. It checks fixture-content SHA-256 fingerprints,
changed-content fields, addition/removal counts, and evidence source/ordinal
references back to snapshot rows. A fixture-owned anchor file keeps the
selected directory present throughout the lifecycle, so the final snapshot
confirms the payload is absent after purge while the anchor remains.

The install, update, and purge audit sessions verify the session-manifest
artifact digests, before/after selected-root snapshot hashes, and exact raw
`trace.strace` evidence locators. Installation shows one added payload; update
shows one changed payload with different before/after hashes; purge checks the
payload hash in the before snapshot and the removed delta. Install and update
traces must retain a successful create of `payload.bin.dpkg-new` and a
`rename` return value of zero to the final payload path. The runtime
association links that final path to the successful rename as a lexical
candidate. It treats strict absolute byte-faithful rename operands as a
removal candidate at the source path and an addition or change candidate at
the destination path. The staging name appears in neither snapshot, so it
produces no selected-root delta; only the destination supports one candidate
for install and update.

For purge, the test checks an exact locator when a strict absolute lexical
candidate exists for the removed payload from a successful supported
`unlink`, `unlinkat`, or rename-source row. If the real purge uses an
unsupported or relative spelling, or strace splits an operation over
unfinished/resumed rows, the delta stays explicitly unmatched. For a split
removal, the test pairs a resumed row only with the unique earlier pending row
for the same PID and syscall; sequential pairs are allowed, overlapping
ambiguous rows are not. It checks both raw byte locators and requires a
successful resumed result. It also reports bounded trace evidence containing
the payload basename without claiming absolute path identity. For `unlinkat`,
a bare `AT_FDCWD` or an absolute `-yy` annotation is accepted only with flags
`0` and an exact absolute operand; the annotation is display context, not a
path-resolution fallback. Install and update have no unmatched selected-root
delta; purge may remain unmatched.

The startup collector scans fixed system and legacy locations that the private
fixture cannot isolate. The test therefore preserves each startup document
and source status and does not require complete machine-wide startup coverage.
When that source is partial, install/purge additions or removals may be
suppressed by the comparison; the test checks the paired snapshots and reports
suppression as partial/unknown instead of treating a missing row as proof of
absence. Runtime capture completeness remains unknown, so the overall
observation session remains partial. The selected-root runtime association
remains `lexical_path_candidate_only_no_causation_or_process_identity`; it does
not establish causation, process identity, or broad `strace` coverage.

The test requires Linux x86_64, Rust/Cargo, `strace`, `dpkg`, `dpkg-deb`, and
`dpkg-query`. CI installs `strace` and `dpkg`; no package installation or
elevation is required on the CI host. Package trees, archives, private dpkg
state/logs, home/XDG directories, installed files, and session artifacts live
under the fixture's private temporary directory and are removed on exit or
unwind.

Run it directly with:

```sh
cargo test --locked --test dpkg_root_lifecycle_linux private_dpkg_install_update_downgrade_purge_has_selected_root_evidence
```

This exercises Debian package-state transitions and same-session startup,
package, selected-root, and real runtime evidence using local synthetic
packages. It does not test upstream package hooks, dependency resolution, a
host installation, or a released SideEffect archive. Temporal comparisons do
not infer that the package operation caused an observed configuration or file
change. The package version comes from the isolated dpkg database and the file
fingerprint comes from the selected-root artifact; neither is an authenticity
claim.
