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

For each package state, the test invokes the actual SideEffect
`inventory root --hash-regular-files` CLI on the package's direct-child install
directory and compares adjacent snapshots with `explain --inventory-diff`.
It checks fixture-content SHA-256 fingerprints, changed-content fields,
addition/removal counts, and evidence source/ordinal references back to the
snapshot rows. A fixture-owned anchor file keeps the selected directory
present throughout the lifecycle, so the final snapshot can directly confirm
that the package payload is absent after purge while the anchor remains.

The test requires Linux, Rust/Cargo, `dpkg`, `dpkg-deb`, and `dpkg-query`. The
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
