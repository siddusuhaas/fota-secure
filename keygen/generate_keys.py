#!/usr/bin/env python3
"""Generate the two RSA-2048 keypairs fota-secure needs: a signing pair and
a device encryption pair. See keygen/README.md and docs/THREAT_MODEL.md
(items 1-2) for why these are kept separate and why private keys must never
be committed to source control.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537

KEYPAIRS = ("signing", "device")


def generate_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE
    )


def write_private_key(private_key: rsa.RSAPrivateKey, path: Path) -> None:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # 0600 before writing content: private key material should never be
    # briefly world-readable on disk (docs/THREAT_MODEL.md #2).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def write_public_key(private_key: rsa.RSAPrivateKey, path: Path) -> None:
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("keys"),
        help="directory to write generated keypairs into (default: ./keys, gitignored)",
    )
    args = parser.parse_args()

    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    for name in KEYPAIRS:
        private_key = generate_keypair()
        write_private_key(private_key, output_dir / f"{name}_private.pem")
        write_public_key(private_key, output_dir / f"{name}_public.pem")
        print(f"Generated {name} keypair -> {output_dir}/{name}_private.pem (+public)")

    print(
        f"\nDone. Private keys are in {output_dir}/ — this directory is gitignored, "
        "but double-check before committing anything. See keygen/README.md."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
