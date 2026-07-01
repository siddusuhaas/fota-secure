# fota-secure

![CI](https://github.com/siddusuhaas/fota-secure/actions/workflows/ci.yml/badge.svg)

`fota-secure` is a from-scratch, original implementation of a secure
over-the-air (OTA) firmware update system for embedded Linux devices. It
demonstrates the core security mechanisms a real OTA pipeline needs —
signature verification, envelope encryption, downgrade protection — and
defends against several concrete attack classes seen in real-world
firmware-update implementations: ciphertext tampering, package
mix-and-match attacks, path traversal during extraction, and
decompression-bomb resource exhaustion. It has two independent
components, a Python packager and a C consumer, that agree on nothing
except a documented binary format.

## Security design highlights

Full rationale for all of this lives in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — this is a summary of the parts most worth reading first.

- **Envelope encryption.** Every build generates a fresh random AES-256
  key. That key is wrapped with RSA-OAEP using the device's public key,
  and only the device's private key can recover it. No symmetric key is
  ever hardcoded, reused across builds, or shared in advance — there's no
  long-term secret to distribute or rotate beyond the RSA keypairs
  themselves.

- **Verify-then-decrypt, and why it actually matters here.** The
  consumer checks the RSA signature over the *entire* package
  (`header || wrapped_key || ciphertext`) before attempting any
  decryption. This isn't just defense-in-depth — testing `fcrypto`
  directly proved *why* the ordering is load-bearing: AES-CBC has no
  built-in integrity check. Flipping a single byte in the ciphertext
  doesn't break decryption or raise an error — it decrypts "successfully"
  into silently-wrong plaintext (that ciphertext block decodes to
  garbage, and because of CBC's chaining, the same bit position in the
  *next* block's plaintext flips too). A device that decrypted first and
  checked integrity after would have no reliable signal that anything
  was wrong. Verifying the signature first closes that gap entirely:
  tampering is caught before a single byte of ciphertext is touched.

- **The mix-and-match defense.** The signature covers the header and the
  wrapped key, not just the encrypted payload. This was verified directly
  by building two independently-valid, legitimately-signed packages and
  splicing one's wrapped key into the other while keeping its original
  header and signature — the forged combination fails signature
  verification, even though every individual piece came from a validly
  signed package. Binding everything under one signature closes off an
  entire class of component-swapping attacks.

- **Path traversal and decompression-bomb defenses in the installer.** A
  validly signed package still contains an attacker-shaped tar archive
  once decrypted — trusting the signature doesn't mean trusting every
  filename inside it. Every tar entry's path is checked for `..`
  components or an absolute path before extraction, and symlink entries
  are rejected outright and unconditionally (this project's own packager
  never produces them, so there's no "safe symlink" case to carve out).
  Decompression is capped at a fixed maximum output size, so a small
  ciphertext can't inflate into something that exhausts device storage
  before the installer even gets to look at file contents. Nothing is
  written to disk unless the whole package — paths, entry types, and
  every file's SHA-256 against the manifest — validates first.

- **Downgrade protection with a deliberate override.** Downgrades are
  blocked by default by comparing the firmware version tuple, but a
  legitimate rollback path exists, gated behind a secret whose SHA-256
  hash (not the secret itself) is what's stored on the device, compared
  in constant time.

## Quickstart

Consumer development happens inside Docker (`ubuntu:22.04`), since it's
a C binary linked against `libcrypto`/`zlib`, built/tested on macOS
without a native Linux toolchain — see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#build--test-environment-mac-friendly).
Run everything below inside:

```
docker run -it --rm -v $(pwd):/app -w /app ubuntu:22.04 bash
apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    zlib1g-dev \
    python3 \
    python3-venv
```

**1. Set up the packager** (pulls in `cryptography`, needed by both
keygen and the packager itself):

```
python3 -m venv .venv
.venv/bin/pip install -e "packager[dev]"
```

**2. Generate keys** (signing keypair + device encryption keypair):

```
.venv/bin/python3 keygen/generate_keys.py --output-dir ./keys
```

**3. Package a sample firmware directory:**

```
mkdir -p /tmp/firmware
echo "demo kernel" > /tmp/firmware/kernel.bin

.venv/bin/fota-secure-pack \
    --input-dir /tmp/firmware \
    --platform GENERIC \
    --fw-version 1.0.0.0 \
    --signing-key ./keys/signing_private.pem \
    --device-pubkey ./keys/device_public.pem \
    --output /tmp/update.bin
```

**4. Build the consumer:**

```
cmake -S consumer -B consumer/build -DCMAKE_BUILD_TYPE=Release
cmake --build consumer/build
```

**5. Provision device state and install the update** (the consumer's
paths — signing public key, device private key, version file, install
directory — are baked in at `consumer/src/config.h`, not runtime flags,
by design; see the Security design highlights above):

```
mkdir -p /etc/fota-secure /opt/fota-secure/install
cp ./keys/signing_public.pem /etc/fota-secure/signing_public.pem
cp ./keys/device_private.pem /etc/fota-secure/device_private.pem

./consumer/build/fota-secure-consumer /tmp/update.bin
echo "exit code: $?"
cat /opt/fota-secure/install/kernel.bin
```

Exit code `0` means the update installed; `kernel.bin` should now exist
under `/opt/fota-secure/install` with the demo content written above.

For the full picture — including every negative case (tampered
signature, wrong platform, downgrade blocked, path traversal,
decompression bomb) run against a real compiled binary — see
[`tests/integration_test.sh`](tests/integration_test.sh).

## Architecture

`packager` (Python) and `consumer` (C) share no code and no runtime
coupling — they agree only on the binary format in
[`docs/FORMAT_SPEC.md`](docs/FORMAT_SPEC.md). The packager stages
firmware files plus a manifest into a tarball, encrypts it, wraps the
AES key, and signs the result; the consumer verifies, decrypts, and
extracts it. Full module layout and data flow for both sides is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Explicitly out of scope for v1

These are documented, deliberate boundaries, not missed cases — see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#whats-deliberately-not-built-for-v1)
and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md#explicitly-out-of-scope-for-v1)
for the full reasoning:

- **Multi-platform support** — v1 targets one hardcoded platform end to
  end; the wire format already reserves room for this (`platform_tag`),
  documented as an explicit extension point in `docs/FORMAT_SPEC.md`.
- **Transport security** (TLS, etc.) for however the package is
  delivered to the device — this format is designed to be safe over an
  untrusted transport, but a real deployment should still layer TLS on
  top as defense in depth.
- **Secure boot / chain of trust below the OS** — this project assumes
  the device's OS and the updater binary itself are trustworthy.
- **Per-device key management at fleet scale** — v1 uses one shared
  device keypair for simplicity and demonstrability.

## CI

[![CI](https://github.com/siddusuhaas/fota-secure/actions/workflows/ci.yml/badge.svg)](https://github.com/siddusuhaas/fota-secure/actions/workflows/ci.yml)

Every push runs the packager's own unit tests, builds the consumer via
CMake on a clean Linux runner, and runs the full end-to-end integration
test — real signed packages, fed through the real compiled binary,
checking exit codes for both the successful path and every documented
failure case.

## License

MIT — see [`LICENSE`](LICENSE).
