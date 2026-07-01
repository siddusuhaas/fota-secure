# fota-secure Binary Update Format (v1)

This document defines the on-disk / on-wire format for a fota-secure update
package. Both `packager` (host-side, Python) and `consumer` (device-side, C)
must implement this spec exactly for interoperability.

## Design Goals

- **Confidentiality**: firmware contents are not readable in transit or at rest
  without the device's private key.
- **Integrity + Authenticity**: any tampering with the package is detectable;
  only holders of the offline signing private key can produce a package the
  device will accept.
- **No shared long-term secrets**: the device never needs to know a symmetric
  key in advance. Keys are generated fresh per build and delivered via
  envelope encryption.
- **No static IV/key reuse**: every field that must be unique per build, is.

## High-Level Layout

```
[ fixed_header : 51 bytes ]
[ wrapped_key  : variable, RSA-OAEP ciphertext of a fresh AES-256 key ]
[ signature    : 256 bytes, RSA-2048 PKCS#1v1.5 SHA-256 ]
[ payload      : AES-256-CBC ciphertext of the firmware tarball ]
```

Total size = 51 + wrapped_key_len + 256 + payload_len.

## Fixed Header (51 bytes, packed, big-endian for multi-byte ints)

| Offset | Size | Field              | Description                                                   |
|--------|------|---------------------|----------------------------------------------------------------|
| 0      | 4    | `magic`             | ASCII `"FOTS"` — identifies a fota-secure package               |
| 4      | 1    | `format_version`    | Format spec version, currently `0x01`                          |
| 5      | 16   | `platform_tag`      | ASCII, NUL-padded, e.g. `"GENERIC"` — target platform identifier |
| 21     | 12   | `fw_version`        | ASCII, NUL-padded, 4-part semver string e.g. `"1.0.0.0"`        |
| 33     | 2    | `wrapped_key_len`   | uint16, length in bytes of the `wrapped_key` section that follows |
| 35     | 16   | `iv`                | AES-CBC initialization vector, generated fresh per build (never zero, never reused) |

Note: fields are packed back-to-back with no implicit padding (use explicit
struct packing / `struct.pack` with `!` or `<` format strings, not
compiler-default alignment) — 4 + 1 + 16 + 12 + 2 + 16 = 51 bytes total,
matching the offsets above.

## Wrapped Key Section (variable length)

- The packager generates a fresh random AES-256 key for every build.
- That key is encrypted with **RSA-OAEP** (SHA-256) using the **device's RSA
  public key** (a separate keypair from the signing key — see
  `THREAT_MODEL.md`).
- Length is stored in the header (`wrapped_key_len`) since RSA-OAEP ciphertext
  length depends on key size.
- This is what makes the scheme "envelope encryption": the device uses its own
  private key to unwrap the one-time AES key, then uses that key to decrypt
  the payload.

## Signature Section (256 bytes)

- RSA-2048, PKCS#1 v1.5 padding, SHA-256 digest.
- Computed over: `fixed_header || wrapped_key || plaintext_tarball_sha256_placeholder`

  Concretely: the signature is computed over the SHA-256 digest of
  `fixed_header || wrapped_key || ciphertext_payload`, i.e. it signs the
  **entire package minus the signature field itself**. This binds the header,
  the wrapped key, and the ciphertext together — an attacker cannot swap the
  wrapped key or header from one legitimate package into another.
- Signed with a **separate, offline-only signing private key**. This key is
  never present on the device and never present in the packager's runtime
  environment except at signing time (see `THREAT_MODEL.md` for the
  provisioning story).
- Verified on-device using the corresponding public key, which is baked in at
  provisioning time (not user-suppliable).

## Payload Section (remainder)

- AES-256-CBC encryption of a `.tar.gz` of the firmware file tree.
- PKCS#7 padding (standard CBC padding).
- Decrypted only after signature verification succeeds (verify-then-decrypt,
  see `THREAT_MODEL.md` for why this ordering matters).

## Manifest (inside the tarball, not the outer format)

A `manifest.json` file is included at the root of the tarball before
compression:

```json
{
  "platform": "GENERIC",
  "fw_version": "1.0.0.0",
  "build_date_utc": "2026-07-01T12:00:00Z",
  "git_commit": "a1b2c3d",
  "files": [
    {"path": "kernel.bin", "sha256": "..."},
    {"path": "rootfs.img", "sha256": "..."}
  ]
}
```

Per-file SHA-256 (not `cksum`) hashes give integrity checking at the
individual-file level after extraction, independent of the outer package
signature.

## Version Comparison

`fw_version` is a 4-part dotted integer tuple, e.g. `"1.2.3.4"`, compared
lexicographically component-by-component. A missing/unreadable installed
version file is treated as `0.0.0.0`.

## Exit Codes (consumer)

| Code | Meaning                              |
|------|----------------------------------------|
| 0    | Success                                |
| 1    | Generic failure                        |
| 2    | Already up to date (no-op)             |
| 3    | Invalid magic / malformed header       |
| 4    | Platform mismatch                      |
| 5    | Signature verification failed          |
| 6    | Downgrade blocked                      |
| 7    | Insufficient disk space                |
| 8    | Decryption failed (bad key unwrap or corrupt ciphertext) |

## Explicit Extension Point: Multi-Platform Support

v1 targets a single hardcoded platform (`GENERIC`) end to end. To extend:

1. Replace the single `PLATFORM_TAG` constant in `consumer/src/config.h` with
   a small table of supported tags and their install behavior (extraction
   path, post-install hook).
2. In the packager, `platform` becomes a required CLI argument validated
   against the same table (kept in a shared `platforms.json` both sides can
   read, to avoid drift).
3. The header format does **not** need to change — `platform_tag` is already
   a free-form 16-byte string field for exactly this reason.

This is intentionally left as a documented extension point rather than
implemented, to keep v1 focused and fully testable on one target.
