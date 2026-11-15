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

The v1 install, v2 upgrade, and final purge phases are launched through the real
`audit --observe-root --hash-regular-files` CLI. They use the same parameterized
assertion helper, which verifies the session-manifest artifact digests,
before/after selected-root snapshot content hashes, and exact raw `trace.strace`
evidence locators. Installation shows one added payload; upgrade shows one
changed payload with different before/after hashes; purge verifies the payload
hash in the before snapshot and one removed delta with no after row. Install
and upgrade traces must retain a successful create of
`payload.bin.dpkg-new` and a `rename` return value of zero to the final payload
path. The runtime association links that final path to the successful rename as
a lexical candidate. The association interprets strict absolute byte-faithful
rename operands as a removal candidate at the source path and an addition or
change candidate at the destination path. The staging name appears in neither
snapshot, so it produces no selected-root delta; only the destination supports
one candidate for install and upgrade. For purge, the test requires one
candidate for the removed payload from the exact successful supported
`unlink`, `unlinkat`, or rename-source row selected by the association. For
`unlinkat`, a bare `AT_FDCWD` or an absolute `-yy` annotation is accepted only
with flags `0` and an exact absolute operand; the annotation is display context,
not a path-resolution fallback. It
checks that locator against the raw trace bytes and observed result. Each
observed transition has no unmatched selected-root delta. Downgrade still uses
the direct private-root dpkg helper and package/root snapshots, but is not
individually wrapped in `audit`. The association remains explicitly
`lexical_path_candidate_only_no_causation_or_process_identity`, and capture
completeness remains unknown. A candidate link does not prove the package
command caused the file state, that the runtime operation and selected-root
delta describe the same object identity, or establish broad `strace` coverage.

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
