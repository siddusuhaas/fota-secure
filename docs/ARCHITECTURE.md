# fota-secure Architecture

## Overview

fota-secure is a two-part system for securely delivering firmware updates to
an embedded Linux device:

1. **`packager`** — a Python CLI tool that runs on a build/release host. It
   takes a directory of firmware files, packages them, and produces a signed,
   encrypted update blob.
2. **`consumer`** — a C binary that runs on the target device. It reads an
   update blob (via stdin or a file path), verifies it, decrypts it, and
   installs it.

They communicate purely through the binary format defined in
`docs/FORMAT_SPEC.md` — there is no other coupling between them. This
separation is intentional: the packager never runs on the device, and the
consumer never needs Python or any host-side tooling.

```
   ┌─────────────────────┐                      ┌──────────────────────┐
   │   Build/Release Host  │                      │   Embedded Device      │
   │                      │                      │                       │
   │  firmware files/  ───▶│  packager (Python)  │──▶  update.bin  ──────▶│  consumer (C)         │
   │                      │   - tar + manifest   │      (FORMAT_SPEC)    │   - verify signature  │
   │                      │   - gen AES key       │                       │   - unwrap AES key    │
   │                      │   - wrap key (RSA)     │                       │   - decrypt payload   │
   │                      │   - sign (RSA)         │                       │   - extract + install  │
   │                      │   - encrypt (AES)      │                       │                       │
   └─────────────────────┘                      └──────────────────────┘
```

## `packager` (Python)

### Module Layout

```
packager/
├── pyproject.toml
└── fota_secure/
    ├── __init__.py
    ├── cli.py           # argparse entrypoint
    ├── manifest.py       # builds manifest.json, computes per-file SHA-256
    ├── tarball.py        # stages files + manifest, produces .tar.gz
    ├── crypto.py         # AES key gen, RSA-OAEP wrap, RSA sign, AES-CBC encrypt
    └── blob.py           # assembles the final header+key+sig+payload blob
```

### CLI Interface

```
fota-secure-pack \
  --input-dir ./firmware_files \
  --platform GENERIC \
  --fw-version 1.0.0.0 \
  --signing-key ./keys/signing_private.pem \
  --device-pubkey ./keys/device_public.pem \
  --output ./release/update.bin
```

Design choice: explicit flags, no auto-detection of platform or implicit env
vars. This keeps the tool runnable identically on any machine (including
CI) without relying on a specific build system's directory conventions —
deliberately more portable than being wired into any one host's layout.

### Flow (`cli.py` orchestrates)

1. Parse args, validate paths exist.
2. `manifest.build_manifest(input_dir, platform, fw_version)` → walks
   `input_dir`, computes SHA-256 per file, embeds git commit hash (via
   `git rev-parse --short HEAD`, best-effort, falls back to `"unknown"`) and
   UTC build timestamp.
3. `tarball.stage_and_compress(input_dir, manifest)` → copies files + writes
   `manifest.json` into a staging dir, tars+gzips it.
4. `crypto.generate_aes_key()` → fresh random 32-byte key via CSPRNG.
5. `crypto.generate_iv()` → fresh random 16-byte IV.
6. `crypto.encrypt_payload(tarball_bytes, key, iv)` → AES-256-CBC ciphertext.
7. `crypto.wrap_key(aes_key, device_pubkey)` → RSA-OAEP ciphertext of the key.
8. `blob.build_header(platform, fw_version, iv, wrapped_key_len)` → 51-byte
   header per spec.
9. `crypto.sign(header + wrapped_key + ciphertext, signing_privkey)` →
   256-byte signature.
10. `blob.assemble(header, wrapped_key, signature, ciphertext)` → write final
    file to `--output`.

### Key Dependency

`cryptography` (pyca/cryptography) for all RSA/AES operations — no
shelling out to the `openssl` CLI. This is a deliberate deviation from
common bash-script packaging patterns, see `THREAT_MODEL.md` item 8.

## `consumer` (C)

### Module Layout

```
consumer/
├── CMakeLists.txt
└── src/
    ├── main.c           # entrypoint, arg parsing, orchestration
    ├── config.h          # platform tag, install paths — single edit point for v1
    ├── header.c/h        # parse + validate the 51-byte fixed header
    ├── fcrypto.c/h        # RSA-OAEP unwrap, RSA verify, AES-CBC decrypt (libcrypto)
    ├── installer.c/h      # extract tarball, verify per-file manifest hashes, install
    └── version.c/h        # version file read + comparison + downgrade secret check
```

Note: `fcrypto` (not `crypto`) to avoid filename collision with system/library
headers on some toolchains.

### Flow (`main.c` orchestrates)

1. Parse CLI args (input path or stdin).
2. `header_parse()` → validate magic, format_version, platform_tag.
3. `version_compare()` against `/etc/fota-secure/version` (or configured
   path) → handle up-to-date / downgrade-blocked cases.
4. Disk space pre-check on the target install path.
5. Read `wrapped_key` (length from header) + `signature` (256 bytes).
6. `fcrypto_verify_signature()` over `header || wrapped_key || ciphertext`
   using the baked-in public signing key — **exit on failure before touching
   ciphertext**.
7. `fcrypto_unwrap_key()` — RSA-OAEP decrypt the wrapped AES key using the
   device's private key (path configured, not hardcoded).
8. `fcrypto_decrypt_payload()` — AES-256-CBC decrypt using the unwrapped key
   + IV from header.
9. `installer_extract()` — untar, verify each file's SHA-256 against
   `manifest.json` inside the tarball, then move into place.
10. Platform-specific post-install hook (single function, `config.h`-gated,
    for the one supported platform in v1 — this is the documented extension
    point for adding more).
11. Exit with appropriate code per `FORMAT_SPEC.md`.

### Key Dependency

OpenSSL's `libcrypto` (linked directly, `-lcrypto`), or `mbedTLS` as an
alternative if a smaller footprint is desired for real constrained targets —
document both build options in `README.md`, default to OpenSSL for local
dev/testing since it's trivially available in the Docker dev environment.

## Build & Test Environment (Mac-friendly)

Both parts are built and tested inside Docker (Ubuntu base image) since
development happens on macOS without a native Linux toolchain:

```
docker run -it --rm -v $(pwd):/app -w /app ubuntu:22.04 bash
```

- `consumer` compiles with CMake + gcc + libcrypto-dev inside the container.
- `packager` runs directly (Python 3 + `cryptography`, installable via pip
  inside the same container, or natively on macOS since it's pure Python
  with no OS-specific dependencies).
- `tests/integration_test.sh` runs an end-to-end round trip: generate a
  throwaway keypair → package a dummy firmware dir → feed the blob into the
  consumer binary → assert exit code 0 and that files landed in the expected
  install path.
- `.github/workflows/ci.yml` runs the same round trip on every push using a
  Linux GitHub Actions runner — this is also the "real" Linux test
  environment, not just Docker-on-Mac, giving CI results that mean something
  beyond local dev.

## What's Deliberately Not Built for v1

See `FORMAT_SPEC.md`'s "Explicit Extension Point" section for multi-platform
support, and `THREAT_MODEL.md`'s "Out of Scope" section for security-related
scope boundaries (transport security, secure boot, per-device keys, atomic
A/B rollback). These are documented, not hidden gaps — called out explicitly
so a reviewer understands they were considered and deferred, not missed.
