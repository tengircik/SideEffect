# Signed provenance format

## Current v1 contract

The implemented `sideeffect.provenance_signature` v1 sidecar signs the SHA-256 digest of the exact bytes in a validated `session.json`. Its Ed25519 input is the following byte transcript, with the digest and key ID decoded from lowercase hexadecimal and the timestamp encoded as an unsigned 64-bit big-endian integer:

```text
"sideeffect.audit_session.signature.v1\0"
|| raw_key_id_sha256[32]
|| raw_manifest_sha256[32]
|| signed_at_unix_ms_be[8]
```

The JSON envelope fields are `schema`, `schema_version`, `algorithm`, `key_id`, `manifest_sha256`, `signed_at_unix_ms`, and `signature`. The algorithm is `ed25519`; key ID is SHA-256 of the raw 32-byte public key; digest and signature are lowercase hexadecimal. The envelope rejects unknown fields and unsupported schema versions or algorithms. The signed timestamp is the signer's local clock reading, not a trusted timestamp.

V1 is exact-byte compatible: do not normalize, parse-and-reserialize, or otherwise rewrite a v1 manifest before hashing. A whitespace-only change therefore invalidates its signature. The CLI validates the session manifest and all declared artifact hashes before signing or verifying. The low-level v1 signing primitive accepts bounded bytes and does not itself parse a session; callers that need the CLI's validation guarantee must use the session reader first. Existing v1 envelopes and `sideeffect.audit_session` session formats v1-v10 remain signed over their exact bytes; the signature format does not migrate or rewrite session manifests.

## Signing preview

`sideeffect provenance preview-session SESSION_DIR` is a read-only preview of what `sign-session` would bind. It uses the same verified native session reader and the same exact `session.json` bytes: it validates the manifest, every declared artifact length and SHA-256, and each JSON artifact's declared schema/version before writing anything. It does not read a key, prompt for confirmation, publish a file, or create a signature.

On success it writes one JSON document to stdout and exits 0:

```json
{
  "schema": "sideeffect.provenance_signing_preview",
  "schema_version": 1,
  "manifest_schema": "sideeffect.audit_session",
  "manifest_schema_version": 15,
  "manifest_sha256": "<lowercase hex of the exact session.json bytes>",
  "signed_input": "exact_session_json_bytes",
  "binds": {
    "exact_manifest_bytes": true,
    "session_identifier_present": true,
    "host_context_present": true,
    "observed_os_metadata_present": true,
    "coverage_manifest_present": true,
    "collector_identity_present": true,
    "collector_provider_identity_present": false,
    "requested_settings_present": false,
    "effective_settings_present": false,
    "applied_limits_present": false,
    "runtime_loss_metadata_present": false,
    "diagnostics_present": false,
    "artifact_hashes_present": true,
    "source_count": 2,
    "artifact_count": 3
  }
}
```

The document is fixed and bounded: `binds` has only the presence flags and counts shown above. `observed_os_metadata_present` is true only when the manifest's `host_context` includes an observed OS name or OS version value. The counts are declared manifest counts, not proof that the session covered those sources or artifacts. The artifact count is a count of declared references whose bytes and hashes were checked; artifact digest values are not copied into the summary.

The preview intentionally omits session identifiers, host and collector values, scope and path text, command text, setting and limit values, diagnostic codes, artifact digests, and all other free text. It reports only that those categories are present or absent. It does not authenticate the session or its creator, does not establish collector honesty or capture completeness, and does not verify signer identity or trust. The shown digest identifies the exact bytes a signature would cover; it is not a safety verdict and may reveal equality across repeated captures.

A failed verification exits 1 with no JSON on stdout. Malformed, unsupported, enlarged, or digest-mismatched sessions are reported as errors rather than summarized.

## Local public-key trust store

Use `sideeffect provenance key-export-public PRIVATE_KEY.pk8 NEW_PUBLIC_KEY.hex` to recreate a missing public verification file from its protected Ed25519 private key. The command writes the same lowercase-hex public format as `keygen` to a new file and prints its SHA-256 fingerprint. The private key stays in its original file. An existing output path causes the command to fail.

The implemented trust-store commands are explicit and offline:

```text
sideeffect provenance trust import PUBLIC_KEY.hex --trust-store DIR --label LABEL
sideeffect provenance trust rotate OLD_KEY_ID NEW_PUBLIC_KEY.hex --trust-store DIR --label LABEL
sideeffect provenance trust list --trust-store DIR
sideeffect provenance trust remove KEY_ID --trust-store DIR
sideeffect provenance verify-session SESSION_DIR --signature SIGNATURE.json --trust-store DIR
sideeffect provenance verify-session SESSION_DIR --signature SIGNATURE.json --public-key PUBLIC_KEY.hex --trust-store DIR
```

There is no default or global trust store. Import reads only the public-key file, computes the key ID as SHA-256 of the decoded raw Ed25519 public key, displays that fingerprint, and requires the user to type `trust <fingerprint>` before changing the store. Labels are local annotations restricted to 1–64 ASCII letters, digits, spaces, periods, underscores, `@`, and hyphens, with no edge spaces. Removal requires typing `remove <fingerprint>`. Import never overwrites an existing fingerprint entry. Listing and verification reject malformed or unexpected store contents.

The store contains a strict `sideeffect.provenance_trust_store` v1 marker and one strict `sideeffect.trusted_provenance_key` v1 record named `key-<key_id>.json` per key. It is capped at 256 key records and 4 KiB per marker or record. Records contain the public key in lowercase hexadecimal, its key ID, and the local label; they contain no private key material. Reads are bounded and reject links/reparse points. Store directories and records must be owned/protected for the current user: Linux uses mode `0700` directories and `0600` files and rejects non-sticky writable parents; Windows requires a protected current-user-only DACL. New record publication is no-overwrite. Confirmation lines are newline-terminated UTF-8 and bounded to 128 bytes for other trust actions and 160 bytes for rotation's two-fingerprint confirmation. The user-selected store path is the only store used by these commands.

`verify-session --trust-store DIR` verifies only when the envelope key ID matches a key in that store. It reports a matching key as cryptographically valid and locally trusted. An absent key is reported as unknown without claiming that signature validity was checked. When a public key is also supplied, the command can report a cryptographically valid signature as locally untrusted if the key is absent from the selected store. Unknown and valid-but-untrusted results exit with status 2; malformed inputs and invalid signatures fail. Without `--trust-store`, the existing `--public-key` path remains cryptographic-only and says trust was not evaluated. A local label does not establish signer identity. Removing a key changes only the local trust decision; it is not a published revocation and cannot invalidate previous signatures.

### Rotation and key loss

`provenance trust rotate OLD_KEY_ID NEW_PUBLIC_KEY.hex --trust-store DIR --label LABEL` performs an explicit local trust-store rotation. Generate and protect the replacement key pair separately, then run this command with its public-key file. The command verifies that the prior key is trusted, the replacement differs and is not already present, and the label is valid. It prints both fingerprints and requires the exact confirmation `rotate <old-key-id> to <new-key-id>`. Cancellation exits with status 1 and leaves the trust store unchanged.

After confirmation, rotation imports the replacement public key using the existing strict no-overwrite trust-record contract, then removes the prior key's trust record. A successful rotation reports that the replacement is trusted and the prior key is no longer trusted in this selected store. If retiring the prior record fails after the replacement was imported, the command exits with status 2. It reports both keys remain trusted when that state can be verified; if the selected store cannot be read back safely, it reports the prior-key state as uncertain and asks the user to inspect the store before retrying. The replacement is never rolled back. A full 256-key store cannot stage another key, so rotation fails before changing trust. The operation never reads, changes, deletes, exports, or backs up private-key files. It modifies only the explicitly selected local trust store. It does not publish revocation to other stores or invalidate old signatures cryptographically.

After a successful rotation, old signatures remain cryptographically verifiable when the old public key is retained and supplied explicitly; store-only verification reports the old key as unknown. Keep old public keys and signature envelopes with the sessions they verify. This process does not prove who controlled either key or when a rotation occurred. A local trust label remains only an annotation.

Use `sideeffect provenance key-check PRIVATE_KEY.pk8 PUBLIC_KEY.hex` as a read-only preflight before using a newly generated or user-restored key pair. The command checks ownership and access on the same open file it reads, then compares its derived public key with the supplied bounded public-key file, and prints only the matching public-key fingerprint. The library API is `provenance::check_keypair(private_path, public_path)`. This checks pair consistency only: it does not verify backup completeness or authenticity, recover a lost private key, create a backup, alter a trust store, or publish revocation.

The private PKCS#8 key is required to create future signatures. If it is lost, the public key and existing signature envelopes cannot reconstruct it; generate a replacement key and treat it as a new trust decision. Existing signatures remain cryptographically verifiable when their matching public key is retained. Key generation does not create a backup or encrypted export, so users who choose to back up private key material must arrange and protect that backup themselves. Do not treat a public-key copy or trust-store entry as a private-key recovery mechanism.

## Proposed canonical contract for a future v2

V2 is a format proposal, not an implemented or accepted signature version. It must be introduced additively and must never reinterpret a v1 sidecar. The proposed v2 envelope keeps schema `sideeffect.provenance_signature`, uses `schema_version: 2`, and has exactly these fields:

| Field | Meaning |
| --- | --- |
| `schema` | Literal `sideeffect.provenance_signature` |
| `schema_version` | Integer `2` |
| `algorithm` | Literal `ed25519` |
| `canonicalization` | Literal `RFC8785` |
| `manifest_schema` | Literal `sideeffect.audit_session` |
| `manifest_version` | Supported audit-session schema version |
| `key_id` | Lowercase hexadecimal SHA-256 of the raw Ed25519 public key |
| `manifest_sha256` | Lowercase hexadecimal SHA-256 of canonical manifest UTF-8 bytes |
| `signed_at_unix_ms` | Bounded nonnegative signer-local clock time; not trusted time |
| `signature` | Lowercase hexadecimal 64-byte Ed25519 signature |

The v2 signed message is the UTF-8 domain string `sideeffect.audit_session.signature.v2\0`, followed by the 32 raw key-ID bytes, 32 raw manifest-digest bytes, the 8-byte big-endian timestamp, and the UTF-8 bytes of `RFC8785`. This binds both the canonicalization identifier and the data digest into the signature transcript. Verification must validate the manifest, confirm that the envelope's manifest schema/version match it, canonicalize the validated manifest as specified below, compare the digest, and then verify the signature. Unknown versions, fields, algorithms, or canonicalization identifiers are errors; a verifier must not guess or fall back between versions.

For v2, canonical bytes are RFC 8785 JSON Canonicalization Scheme output from the validated JSON object parsed from `session.json`, without schema migration or insertion of defaulted fields. Input must be UTF-8 JSON with no duplicate object member names, no unknown fields at any level, and no non-finite or floating-point values. Integer fields must stay within the exact interoperable range `[-(2^53)+1, (2^53)-1]`; the supported manifest schema must define bounded integers and string constraints compatible with RFC 8785. Canonicalization preserves Unicode code points and does not perform Unicode normalization. Producers serialize canonical bytes for the session manifest. Verifiers independently canonicalize parsed input and require the supplied `session.json` bytes to equal those canonical bytes before accepting the signature. Requiring byte equality prevents multiple raw representations from being presented as the same canonical v2 manifest. Any future session fields that affect evidence, scope, diagnostics, or completeness must be covered by the canonical object and versioned compatibility rules.

This canonical contract does not expand what a signature proves. A valid signature establishes that the corresponding private key signed the canonical manifest digest and that the checked bytes match it. Without a separately verified key binding, it does not identify a person. It does not prove collector honesty, host integrity, event truth, exhaustive capture, or trusted signing time. Hashes and session identifiers may expose equality across repeated captures. V2 still requires implementation, independent interoperability vectors, malformed/duplicate/unknown-field tests, and explicit privacy review before it can be used.
