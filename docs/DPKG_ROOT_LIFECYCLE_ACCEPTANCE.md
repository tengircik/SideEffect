# Isolated dpkg package lifecycle acceptance

`tests/dpkg_root_lifecycle_linux.rs::private_dpkg_install_update_downgrade_purge_has_selected_root_evidence`
builds two local, scriptless Debian packages for one synthetic fixture package
(versions `1.0-1` and `2.0-1`). It installs v1, updates to v2, downgrades back
to v1, and purges the package. Every `dpkg` transaction supplies explicit
`--root`, `--admindir`, `--instdir`, `--log`, and `TMPDIR` paths under a fresh
private temporary directory, enables `--force-not-root`, and disables trigger runs.
It calls the fixed `/usr/bin` dpkg tools with a cleared environment, including
all inherited `DPKG_*` variables, and a fixed system-tool `PATH`. The test does
not use `sudo`; it does not point dpkg at the host package database. It
verifies each installed version with `dpkg-query` using the private admin
directory.

The same fixed `/usr/bin/dpkg-query` invocation also emits its bounded tabular
rows from that private admin directory at each lifecycle state. The test passes
those exact output bytes through SideEffect's existing
`parse_dpkg_query_output` parser, writes the resulting package inventory
artifacts only inside the fixture, and runs the real
`explain --inventory-diff` CLI across install, update, downgrade, and purge.
It checks package version facts and each comparison's source ID, package
identity, change kind, and evidence line/byte locator against the parsed source
row. The package parser/diff acceptance is separate from
`inventory packages`: that standalone command intentionally reads fixed host
package-manager database paths and does not accept a caller-selected dpkg
admin directory. This fixture therefore exercises the real parser and
comparison CLI over isolated dpkg output, not the standalone host collector.

For each package state, the test invokes the actual SideEffect
`inventory root --hash-regular-files` CLI on the package's direct-child install
directory and compares adjacent snapshots with `explain --inventory-diff`.
It checks fixture-content SHA-256 fingerprints, changed-content fields,
addition/removal counts, and evidence source/ordinal references back to the
snapshot rows. A fixture-owned anchor file keeps the selected directory
present throughout the lifecycle, so the final snapshot can directly confirm
that the package payload is absent after purge while the anchor remains.

The v1 install phase is also launched through the real
`audit --observe-root --hash-regular-files` CLI. The test builds that CLI's
argument vector from the same fixed `/usr/bin/dpkg` command and private-root
arguments used by the unobserved lifecycle phases, preserving argument
boundaries. It clears the audit process environment and copies only the
fixture dpkg command's fixed `PATH`, `LC_ALL`, and private `TMPDIR` overrides;
the package command itself still targets only the canonicalized fixture root,
admin directory, and log under the private temporary parent. The resulting
session is compared with `compare-observation`: the selected-root diff must
show the added payload. The runtime association must leave the final payload
without a candidate link because dpkg commits it from a staging path with
`rename`. The test verifies each referenced runtime line locator against the
raw `trace.strace` bytes and parsed successful syscall result, plus the
session-manifest artifact digests. The trace must retain both a successful
create of `payload.bin.dpkg-new` and a `rename` return value of zero to the final
payload path. Since the current association adapter does not interpret
`rename`, it leaves the added root delta unmatched; the test makes no candidate
link for that final path. The remaining update, downgrade, and purge
transitions use the same direct private-root dpkg helper and are checked with
package/root snapshots, but are not individually wrapped in `audit`. The
association remains explicitly
`lexical_path_candidate_only_no_causation_or_process_identity`, and capture
completeness remains unknown. This does not prove the package command caused
the file state or establish broad `strace` coverage.

The test requires Linux x86_64, Rust/Cargo, `strace`, `dpkg`, `dpkg-deb`, and
`dpkg-query`. CI installs `strace` and `dpkg` explicitly. The
normal Linux `cargo test --locked --all-targets` job runs it; no package
installation or elevation is required on the CI host. All package trees,
archives, dpkg state/logs, installed files, and snapshots are created in the
private temporary fixture and removed when the test exits or unwinds.

Run it directly with:

```sh
cargo test --locked --test dpkg_root_lifecycle_linux private_dpkg_install_update_downgrade_purge_has_selected_root_evidence
```

This exercises Debian package-state transitions against local synthetic
packages in a private root. It does not test an upstream package, maintainer
script behavior, dependency resolution, a host installation, or a released
SideEffect archive. SideEffect's snapshot diff reports the observed selected
directory difference; it does not infer that a particular package operation
caused a change. The package version comes from the isolated dpkg database and
the file fingerprint comes from the selected-root artifact; neither is an
authenticity claim.
