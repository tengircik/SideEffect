# Synthetic selected-root lifecycle evidence

`tests/root_snapshot_inventory_cli.rs::synthetic_selected_root_install_update_rollback_uninstall_tracks_content_and_evidence`
drives the built SideEffect CLI through a synthetic four-step file lifecycle in
a temporary selected directory:

1. Add a fixture file and compare the empty and populated root snapshots.
2. Replace its bytes with a second fixture version and compare the snapshots.
3. Restore the original fixture bytes and compare the snapshots.
4. Remove the fixture file and compare the snapshots.

Each snapshot is produced by `inventory root --hash-regular-files`; each pair is
compared by `explain --inventory-diff`. The test checks the CLI's schema and
complete status, verifies each observed content SHA-256 against the known
fixture bytes, checks the changed-content field for update and rollback, and
checks the selected-root entry evidence source and ordinal on emitted deltas.
The final removal is linked to the prior snapshot's entry evidence.

This is deterministic synthetic evidence for the selected-root collector and
comparator. The test directly changes fixture files; it does not execute an
installer, exercise a package manager, or prove that software was installed,
updated, rolled back, or uninstalled on a host. A removal delta means only
that a direct child present in the earlier selected-root snapshot was not
present in the later snapshot. It does not identify who removed the file, why
it changed, or whether a software lifecycle operation caused the difference.
Content hashes are equality fingerprints for the fixture bytes, not
authenticity evidence. Enumeration is non-atomic and covers only the explicitly
selected root and its direct children.

Run the test with:

```sh
cargo test --locked --test root_snapshot_inventory_cli synthetic_selected_root_install_update_rollback_uninstall_tracks_content_and_evidence
```

This test requires a working Rust toolchain and the repository's selected-root
CLI implementation. It does not require `strace`, elevated privileges, or a
system installation.
