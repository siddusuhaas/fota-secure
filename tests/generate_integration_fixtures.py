"""Generate full end-to-end packages for tests/integration_test.sh.

Everything here goes through the real packager pipeline (manifest.py,
tarball.py, crypto.py, blob.py) and real keygen output - these are
genuine packages the consumer binary must handle correctly, not
hand-rolled approximations of the format. The one exception is the
path-traversal package, which substitutes a maliciously-named tar entry
for the payload before it's encrypted+signed through the same real
pipeline - it's still validly signed, since the point is to prove the
installer's own defenses catch it even when the signature checks out.

Dev/test tooling only - never part of the consumer binary itself.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

from fota_secure import blob, crypto


REPO_ROOT = Path(__file__).resolve().parents[1]
KEYGEN_SCRIPT = REPO_ROOT / "keygen" / "generate_keys.py"


def _files_for_version(fw_version: str) -> dict:
    # Content embeds fw_version so an upgrade/downgrade's effect on disk
    # is directly verifiable, not just the exit code.
    return {
        "kernel.bin": f"kernel bytes for {fw_version}".encode("utf-8"),
        "rootfs.img": (f"rootfs bytes for {fw_version} " * 20).encode("utf-8"),
    }


def _build_package(platform: str, fw_version: str, iv: bytes, aes_key: bytes,
                    tarball_bytes: bytes, signing_private, device_public) -> bytes:
    ciphertext = crypto.encrypt_payload(tarball_bytes, aes_key, iv)
    wrapped_key = crypto.wrap_key(aes_key, device_public)
    header = blob.build_header(
        platform_tag=platform, fw_version=fw_version, iv=iv,
        wrapped_key_len=len(wrapped_key),
    )
    signature = crypto.sign(header + wrapped_key + ciphertext, signing_private)
    return blob.assemble(header, wrapped_key, signature, ciphertext)


def _real_tarball(fw_version: str, platform: str) -> bytes:
    files = _files_for_version(fw_version)
    files_manifest = {
        "platform": platform,
        "fw_version": fw_version,
        "build_date_utc": "2026-07-01T00:00:00Z",
        "git_commit": "unknown",
        "files": [
            {"path": path, "sha256": hashlib.sha256(data).hexdigest()}
            for path, data in files.items()
        ],
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for path, data in files.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        manifest_bytes = json.dumps(files_manifest, indent=2).encode("utf-8")
        info = tarfile.TarInfo(name="manifest.json")
        info.size = len(manifest_bytes)
        tar.addfile(info, io.BytesIO(manifest_bytes))
    return buf.getvalue()


def _malicious_traversal_tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        data = b"pwned"
        info = tarfile.TarInfo(name="../../../tmp/evil.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    out: Path = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    keys_dir = out / "keys"

    subprocess.run(
        [sys.executable, str(KEYGEN_SCRIPT), "--output-dir", str(keys_dir)],
        check=True, capture_output=True, text=True,
    )
    # A second, unrelated device keypair - never provisioned onto the
    # "device" in integration_test.sh - used only to build
    # wrong_device_key.bin below.
    other_keys_dir = out / "other_keys"
    subprocess.run(
        [sys.executable, str(KEYGEN_SCRIPT), "--output-dir", str(other_keys_dir)],
        check=True, capture_output=True, text=True,
    )

    signing_private = crypto.load_private_key(keys_dir / "signing_private.pem")
    device_public = crypto.load_public_key(keys_dir / "device_public.pem")
    other_device_public = crypto.load_public_key(other_keys_dir / "device_public.pem")

    # --- valid_v1.bin: platform=GENERIC, fw_version=1.0.0.0 ---
    tar_v1 = _real_tarball("1.0.0.0", "GENERIC")
    valid_v1 = _build_package(
        "GENERIC", "1.0.0.0", crypto.generate_iv(), crypto.generate_aes_key(),
        tar_v1, signing_private, device_public,
    )
    (out / "valid_v1.bin").write_bytes(valid_v1)

    # --- valid_v2.bin: platform=GENERIC, fw_version=2.0.0.0 ---
    tar_v2 = _real_tarball("2.0.0.0", "GENERIC")
    valid_v2 = _build_package(
        "GENERIC", "2.0.0.0", crypto.generate_iv(), crypto.generate_aes_key(),
        tar_v2, signing_private, device_public,
    )
    (out / "valid_v2.bin").write_bytes(valid_v2)

    # --- bad_signature.bin: valid_v1.bin with one signature byte flipped ---
    parsed_v1 = blob.parse_blob(valid_v1)
    tampered_signature = bytearray(parsed_v1.signature)
    tampered_signature[0] ^= 0xFF
    bad_signature = blob.assemble(
        valid_v1[: blob.HEADER_SIZE], parsed_v1.wrapped_key,
        bytes(tampered_signature), parsed_v1.payload,
    )
    (out / "bad_signature.bin").write_bytes(bad_signature)

    # --- tampered_ciphertext.bin: valid_v1.bin with one payload byte
    # flipped, original (now-mismatched) signature kept - demonstrates
    # verify-then-decrypt: this must be caught by signature verification,
    # not by decryption ---
    tampered_payload = bytearray(parsed_v1.payload)
    tampered_payload[0] ^= 0xFF
    tampered_ciphertext = blob.assemble(
        valid_v1[: blob.HEADER_SIZE], parsed_v1.wrapped_key,
        parsed_v1.signature, bytes(tampered_payload),
    )
    (out / "tampered_ciphertext.bin").write_bytes(tampered_ciphertext)

    # --- wrong_platform.bin: platform=OTHERPLAT ---
    tar_wrong_platform = _real_tarball("1.0.0.0", "OTHERPLAT")
    wrong_platform = _build_package(
        "OTHERPLAT", "1.0.0.0", crypto.generate_iv(), crypto.generate_aes_key(),
        tar_wrong_platform, signing_private, device_public,
    )
    (out / "wrong_platform.bin").write_bytes(wrong_platform)

    # --- path_traversal.bin: validly signed, malicious tar entry inside ---
    malicious_tar = _malicious_traversal_tarball()
    path_traversal = _build_package(
        "GENERIC", "1.0.0.0", crypto.generate_iv(), crypto.generate_aes_key(),
        malicious_tar, signing_private, device_public,
    )
    (out / "path_traversal.bin").write_bytes(path_traversal)

    # --- wrong_device_key.bin: genuinely valid signature and wrapped key,
    # but wrapped for a *different* device's public key - the signing
    # side did nothing wrong, this device's private key just isn't the
    # one this package was ever meant for. Exercises exit 8 (decryption
    # failed) without needing to forge anything - real signature, real
    # wrap, just the wrong recipient. ---
    wrong_device_key = _build_package(
        "GENERIC", "1.0.0.0", crypto.generate_iv(), crypto.generate_aes_key(),
        tar_v1, signing_private, other_device_public,
    )
    (out / "wrong_device_key.bin").write_bytes(wrong_device_key)

    print(f"fixtures written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
