# fota-secure Threat Model

This document explains the security assumptions, the attacks fota-secure
defends against, and specific design decisions made in response to common
mistakes seen in real-world OTA implementations.

## Assets

1. **Firmware confidentiality** — update contents shouldn't be trivially
   readable by anyone who intercepts or downloads a package.
2. **Firmware authenticity/integrity** — a device must never install firmware
   that wasn't produced by a trusted party, unmodified.
3. **Signing key secrecy** — the private key used to authorize updates is the
   root of trust for the whole system. If it leaks, the scheme is broken.
4. **Device availability** — a malicious or malformed update should not be
   able to brick the device or force an unwanted downgrade.

## Threat Actors

- **Network attacker**: can observe/intercept the update package in transit
  (e.g. MITM on a download link), but does not have the signing key.
- **Local attacker with device access**: can read files on the device
  filesystem, potentially including the device's own keypair.
- **Insider/repo-access attacker**: has access to the packaging pipeline or
  its source repository, but not necessarily the offline signing key if it's
  kept out of the repo (see below).

## Key Design Decisions and What They Defend Against

### 1. Two separate keypairs: signing vs. encryption

A single RSA keypair is not reused for both encrypting the AES key
(confidentiality) and signing the package (authenticity). Mixing these roles
is a known anti-pattern — it couples two different security properties to one
key's lifecycle and makes key rotation/compromise response harder to reason
about. fota-secure uses:

- **Device encryption keypair**: public key wraps the AES key; private key
  lives only on the device.
- **Signing keypair**: private key signs packages, lives only with whoever is
  authorized to release firmware; public key is baked into the device at
  provisioning time.

### 2. Signing key is never committed to source control

The signing private key must be generated once via `keygen/` and stored
outside the repository — a secrets manager, an HSM, or at minimum an
encrypted, access-controlled location. `.gitignore` explicitly excludes
`*.pem` private key files, and `keygen/README.md` documents this requirement
in bold. A committed private key means the security of every device in the
field depends on the access-control history of a git repository forever,
which is not a defensible position.

### 3. Fresh AES key per build, delivered via envelope encryption

No symmetric key is ever hardcoded or reused across builds. Each build
generates a random AES-256 key, which is immediately wrapped (RSA-OAEP) with
the device's public key and shipped alongside the package. Only a device
holding the matching private key can recover the AES key. This means:

- Compromising one package's ciphertext doesn't help decrypt any other
  package (no static key reuse across the fleet/timeline).
- There's no long-term shared secret that needs distributing, rotating, or
  protecting on the build server beyond the RSA keypair itself.

### 4. Random IV per build, never zero, never reused

AES-CBC with a static or all-zero IV leaks information: identical plaintext
blocks (common in firmware images — padding, repeated headers, zeroed
regions) produce identical ciphertext blocks, which can leak structural
information about the plaintext and, depending on how IVs are managed
elsewhere, weaken the scheme against chosen-plaintext-style analysis. A fresh
CSPRNG-generated IV is produced per build and transmitted in the header
in the clear (IVs are not secret, only unique).

### 5. Verify-then-decrypt ordering

The signature is checked **before** decryption is attempted. This avoids
performing decryption on attacker-controlled ciphertext of unknown
provenance (avoiding a class of "decrypt first" issues where a device does
non-trivial cryptographic or parsing work on unauthenticated input). If
signature verification fails, the device exits immediately without touching
the payload.

### 6. Signature covers the whole package, not just the tarball

The signature is computed over `header || wrapped_key || ciphertext`, not
just the plaintext tarball. This prevents a class of attacks where an
attacker mixes and matches components from two otherwise-legitimate packages
(e.g. swapping in a wrapped key from a different, attacker-accessible
package while keeping a validly-signed payload) — binding everything under
one signature closes that gap.

### 7. Downgrade protection is a deliberate-override design, not a hard block

Downgrades are blocked by default (comparing the 4-part version tuple), with
an explicit override path gated behind a secret. The secret itself should
be treated as sensitive operational material (not hardcoded per-device;
provisioned similarly to the signing key), so that legitimate recovery
scenarios (rolling back a bad release) remain possible without making
downgrade attacks trivial.

### 8. No shelling out to CLI tools for cryptographic operations

Both the packager (Python, using the `cryptography` library) and the
consumer (C, linking libcrypto directly) perform crypto operations via
library calls, not by invoking an external `openssl` binary via subprocess.
Shelling out adds a dependency on the invoked binary's presence/version on
the target, complicates error handling (parsing exit codes/stderr instead of
checking library return values), and is generally discouraged for
production cryptographic code.

## Explicitly Out of Scope for v1

- **Transport security** (TLS, etc.) for however the package is delivered to
  the device — this format is designed to be safe over an untrusted
  transport, but a real deployment should still use TLS as defense in depth.
- **Secure boot / chain of trust below the OS** — this project assumes the
  device's OS and this updater binary are themselves trustworthy; it doesn't
  address bootloader-level attacks.
- **Per-device unique keys / fleet key management at scale** — v1 uses one
  device keypair for simplicity and demonstrability. A production fleet
  would want per-device or per-group keys; this is a documented extension
  point, not implemented.
- **Rollback of a partially-applied update** — the installer assumes
  extraction either fully succeeds or the exit code signals failure clearly
  enough for an external orchestrator to react; atomic A/B partition
  switching is a real-world pattern worth layering on top but is out of
  scope here.
