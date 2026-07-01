"""Generate real cross-language crypto fixtures for test_fcrypto.c.

Produces the wrapped key, signature, and AES-CBC ciphertext using the
Python packager's actual crypto.py/blob.py, so the C consumer's fcrypto
tests exercise genuine interop (packager output -> consumer parsing),
not just C's own crypto self-consistency.

Requires the packager package installed (pip install -e ./packager).
Dev/test tooling only - never part of the consumer binary itself.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from fota_secure import blob, crypto

REPO_ROOT = Path(__file__).resolve().parents[2]
KEYGEN_SCRIPT = REPO_ROOT / "keygen" / "generate_keys.py"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    out: Path = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    keys_dir = out / "keys"

    subprocess.run(
        [sys.executable, str(KEYGEN_SCRIPT), "--output-dir", str(keys_dir)],
        check=True,
        capture_output=True,
        text=True,
    )

    device_public = crypto.load_public_key(keys_dir / "device_public.pem")
    device_private = crypto.load_private_key(keys_dir / "device_private.pem")
    signing_private = crypto.load_private_key(keys_dir / "signing_private.pem")
    signing_public = crypto.load_public_key(keys_dir / "signing_public.pem")

    aes_key = crypto.generate_aes_key()
    iv = crypto.generate_iv()
    plaintext = b"this is a fake firmware tarball payload for interop testing" * 10
    ciphertext = crypto.encrypt_payload(plaintext, aes_key, iv)
    wrapped_key = crypto.wrap_key(aes_key, device_public)

    header = blob.build_header(
        platform_tag="GENERIC",
        fw_version="1.0.0.0",
        iv=iv,
        wrapped_key_len=len(wrapped_key),
    )
    signed_data = header + wrapped_key + ciphertext
    signature = crypto.sign(signed_data, signing_private)

    # Sanity check before writing anything out: fixtures must validate
    # under the same crypto library that produced them, or the C side
    # would be testing against a broken fixture, not its own logic.
    assert crypto.unwrap_key(wrapped_key, device_private) == aes_key
    assert crypto.verify_signature(signed_data, signature, signing_public)

    (out / "header.bin").write_bytes(header)
    (out / "wrapped_key.bin").write_bytes(wrapped_key)
    (out / "signature.bin").write_bytes(signature)
    (out / "ciphertext.bin").write_bytes(ciphertext)
    (out / "aes_key.bin").write_bytes(aes_key)
    (out / "iv.bin").write_bytes(iv)
    (out / "plaintext.bin").write_bytes(plaintext)

    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF
    (out / "tampered_ciphertext.bin").write_bytes(bytes(tampered_ciphertext))

    tampered_signature = bytearray(signature)
    tampered_signature[0] ^= 0xFF
    (out / "tampered_signature.bin").write_bytes(bytes(tampered_signature))

    print(f"fixtures written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
