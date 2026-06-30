# TASKS.md — Incremental Build Plan

Suggested order, structured so each step is independently testable and maps
to a natural commit (or small handful of commits). This is a plan, not a
strict script — adjust as needed, but keep steps small and each one working
before moving to the next.

## Phase 0 — Scaffolding

- [ ] Repo skeleton: directories per `docs/ARCHITECTURE.md` module layout.
- [ ] `.gitignore`: exclude `*.pem`, `*.key`, `__pycache__/`, `build/`,
      any generated test keys or blobs.
- [ ] `keygen/generate_keys.sh` (or `.py`) — generates two RSA-2048 keypairs
      (signing pair, device encryption pair) into a local `keys/` dir that's
      gitignored. `keygen/README.md` explains what each keypair is for and
      that private keys must never be committed (link `docs/THREAT_MODEL.md`).

  **Commit**: `Initial repo scaffold + keygen`

## Phase 1 — Packager (Python), standalone-testable

- [ ] `packager/fota_secure/manifest.py`: build manifest dict (platform,
      version, build date, git commit, per-file SHA-256). Unit test with a
      small fixture directory.
- [ ] `packager/fota_secure/tarball.py`: stage files + manifest.json, produce
      `.tar.gz` bytes. Unit test: round-trip (build tarball, extract, compare
      contents).
- [ ] `packager/fota_secure/crypto.py`: AES key gen, IV gen, AES-256-CBC
      encrypt, RSA-OAEP wrap, RSA sign. Unit test each function against known
      test vectors or simple round-trips (encrypt then decrypt with the same
      key gives back the original bytes, etc).
- [ ] `packager/fota_secure/blob.py`: header packing per `FORMAT_SPEC.md`,
      full blob assembly. Unit test: pack header, unpack it, fields match.
- [ ] `packager/fota_secure/cli.py`: wire it all together behind argparse.
      Manual test: run against a dummy firmware directory, confirm a
      plausible-looking output file is produced (right size, magic bytes
      correct when inspected with `xxd`/`hexdump`).

  **Commit(s)**: can be one per module, e.g. `Add manifest builder`,
  `Add tarball staging`, `Add crypto primitives (AES/RSA)`,
  `Add blob assembly`, `Add packager CLI`

## Phase 2 — Consumer (C), buildable and unit-testable independently

- [ ] `consumer/src/header.c/h`: parse + validate the 40-byte header. Unit
      test with a hand-crafted valid header and a few malformed ones (bad
      magic, truncated).
- [ ] `consumer/src/fcrypto.c/h`: libcrypto wrappers — RSA-OAEP unwrap,
      RSA signature verify, AES-256-CBC decrypt. Unit test against
      known-good test vectors (can generate these using the packager's
      crypto.py against a test keypair, then hardcode the *test* vectors,
      not real keys, into a test fixture).
- [ ] `consumer/src/version.c/h`: version file read, tuple comparison,
      downgrade secret check. Unit test various comparison cases.
- [ ] `consumer/src/installer.c/h`: tarball extraction, per-file manifest
      hash verification, install-path placement. Test against a known-good
      tarball fixture.
- [ ] `consumer/src/main.c`: orchestrate the full flow per
      `docs/ARCHITECTURE.md`'s consumer flow section. Wire exit codes per
      `FORMAT_SPEC.md`.
- [ ] `consumer/CMakeLists.txt`: build target, link `-lcrypto`.

  **Commit(s)**: one per module roughly matches Phase 1's granularity —
  `Add header parsing + validation`, `Add crypto verify/decrypt (libcrypto)`,
  `Add version comparison + downgrade protection`, `Add tarball installer`,
  `Add consumer main + CLI orchestration`, `Add CMake build`

## Phase 3 — Integration

- [ ] `tests/integration_test.sh`: generate throwaway keypairs → package a
      dummy firmware dir with `packager` → feed the blob into the built
      `consumer` binary → assert exit code 0, assert files landed in the
      expected install path with correct contents.
- [ ] Negative test cases in the same script or a sibling one: tampered
      signature → expect exit 5; wrong platform tag → expect exit 4;
      downgrade attempt without secret → expect exit 6; truncated/corrupt
      blob → expect exit 3 or 8 as appropriate.

  **Commit**: `Add end-to-end integration test with positive + negative cases`

## Phase 4 — CI

- [ ] `.github/workflows/ci.yml`: Linux runner, install build deps
      (libssl-dev, cmake, python3), build consumer, install packager deps,
      run `tests/integration_test.sh`.

  **Commit**: `Add CI pipeline`

## Phase 5 — Docs & Polish

- [ ] Top-level `README.md`: what this is, quickstart (keygen → package →
      install a demo update), links to `docs/ARCHITECTURE.md`,
      `docs/THREAT_MODEL.md`, `docs/FORMAT_SPEC.md`. Include the "why this
      exists / what it demonstrates" framing, and optionally a short
      design-evolution note (fixed a static-IV / hardcoded-key issue found in
      earlier exploratory work — described generally, not tied to any
      specific employer or codebase).
- [ ] Double-check no stray hardcoded test keys, sample keys, or real keys
      anywhere in the final commit history before making the repo public —
      `git log -p | grep -i "BEGIN.*PRIVATE KEY"` as a final sanity check.

  **Commit**: `Add README and finalize docs`

## Definition of Done (v1)

- Packager produces a valid blob from a sample firmware directory.
- Consumer, given that blob and matching keys, verifies + decrypts +
  installs successfully (exit 0).
- All negative test cases produce their documented exit codes.
- CI is green on a fresh clone.
- No secrets of any kind in git history.
