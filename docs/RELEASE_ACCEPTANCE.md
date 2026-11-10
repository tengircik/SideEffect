# Release installation acceptance

This record captures only the release-install checks actually performed. CI build and Cargo-install smoke checks do not substitute for installation from a published archive or an update test.

## v0.1.0 archive checks

| Platform and asset | Checksum | Attestation | Extraction and invocation | Status |
| --- | --- | --- | --- | --- |
| Native Windows x64, `sideeffect-v0.1.0-windows-x86_64.zip` | Matched `SHA256SUMS`: `721b8a1593f4f473ce7ad03341f4e7d2a6d76c55cf9625492368b68d74fdc75e` | `gh attestation verify --repo tengircik/SideEffect` passed on 2026-11-02 | Inspected all 7 archive entries for unsafe paths, extracted to a fresh temporary directory, and invoked the executable by full path; it reported `sideeffect 0.1.0`. On 2026-11-05, downloaded and hash-checked the same asset again, extracted it to a fresh temporary directory, prepended that directory to only the current PowerShell process's `PATH`, changed to `%TEMP%`, and confirmed the first `Get-Command sideeffect.exe` application match resolved to the extracted executable and `sideeffect.exe version` reported `sideeffect 0.1.0`. The process `PATH` was restored and the User `Path` value was unchanged. | Fresh archive installation and process-scoped PATH resolution passed on the tested native Windows host. |
| Linux x86_64, `sideeffect-v0.1.0-linux-x86_64.tar.gz` | Matched `SHA256SUMS`: `626f231728bb2a90d37c01afcdd6c773f79648cd27053fa7dbd1c81adbab007a` | GitHub CLI 2.103.2 verified one attestation on 2026-11-10. Verification required tag `refs/tags/v0.1.0`, source commit `dfff59ffa6ea01995bf121c6c59de9a52ba8ac4c`, signer `.github/workflows/release.yml` in `tengircik/SideEffect`, and a GitHub-hosted signer. | After attestation verification, `scripts/smoke_linux_release_archive.py` checked the member set, extracted into a fresh directory and ran `--help` and `version` under WSL2 Ubuntu. The executable reported `sideeffect 0.1.0`. A [hosted Ubuntu 24.04 run](https://github.com/tengircik/SideEffect/actions/runs/42851145005) independently downloaded the same published asset, verified checksum and attestation, and passed the extraction and invocation smoke check. | Provenance and fresh extraction/invocation passed on hosted Ubuntu 24.04 and WSL2 Ubuntu. |

These checks cover fresh extraction and invocation in the named environments. Updating between distinct released versions, rollback, uninstall, and persistent PATH configuration remain untested.

The 2026-11-05 repeat `gh attestation verify` attempt for the Windows archive could not initialize the public-good verifier. The 2026-11-06 `gh attestation trusted-root` retry failed with the same Sigstore trusted-root TLS error. The locally computed archive digest matched `SHA256SUMS` and the digest recorded for the Windows archive whose attestation had passed on 2026-11-02; no new attestation verification is claimed for the follow-up.

The November 4 and 6 Linux attestation attempts failed while fetching the Sigstore trusted root. The November 10 verification used the same published Linux asset digest and completed after the trusted-root request succeeded.

The release build workflow checks the assembled Linux archive before signing. The separate **Published Linux archive acceptance** workflow downloads a published asset and verifies its checksum and attestation before extracting and invoking it on a hosted Ubuntu runner. Run it for a specific published tag to obtain a separate installation record.
