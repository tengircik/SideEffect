# Release installation acceptance

This record captures only the release-install checks actually performed. CI build and Cargo-install smoke checks do not substitute for installation from a published archive or an update test.

## v0.1.0 archive checks (2026-11-02)

| Platform and asset | Checksum | Attestation | Extraction and invocation | Status |
| --- | --- | --- | --- | --- |
| Native Windows x64, `sideeffect-v0.1.0-windows-x86_64.zip` | Matched `SHA256SUMS`: `721b8a1593f4f473ce7ad03341f4e7d2a6d76c55cf9625492368b68d74fdc75e` | `gh attestation verify --repo tengircik/SideEffect` passed | Inspected all 7 archive entries for unsafe paths, extracted to a fresh temporary directory, and invoked the executable by full path; it reported `sideeffect 0.1.0`. No persistent PATH change was made. | Fresh archive installation passed on the tested native Windows host. |
| Linux x86_64, `sideeffect-v0.1.0-linux-x86_64.tar.gz` | Matched `SHA256SUMS`: `626f231728bb2a90d37c01afcdd6c773f79648cd27053fa7dbd1c81adbab007a` | Verification did not complete. GitHub CLI reported that the public-good verifier was unavailable. | The archive was not extracted or executed. WSL2 and native Linux installation acceptance were not performed. | Unverified; rerun attestation verification and archive installation in a native Linux environment. |

This is a fresh-install check only. It does not validate changing PATH entries, updating between distinct released versions, rollback, uninstall, or every supported Windows environment. The v0.1.0 Linux archive remains unexecuted in this acceptance record. Do not treat a checksum match alone as provenance verification.
