"""argparse entrypoint wiring manifest, tarball, crypto, and blob together
into the packaging pipeline described in docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from fota_secure import blob, crypto, manifest, tarball


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fota-secure-pack",
        description="Package, sign, and encrypt a firmware update.",
    )
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--fw-version", required=True)
    parser.add_argument("--signing-key", required=True, type=Path)
    parser.add_argument("--device-pubkey", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def pack(
    input_dir: Path,
    platform: str,
    fw_version: str,
    signing_key_path: Path,
    device_pubkey_path: Path,
    output_path: Path,
) -> None:
    """Run the full packaging pipeline and write the signed+encrypted blob
    to output_path. See docs/ARCHITECTURE.md's packager flow section."""
    if not input_dir.is_dir():
        raise FileNotFoundError(f"input directory not found: {input_dir}")
    if not signing_key_path.is_file():
        raise FileNotFoundError(f"signing key not found: {signing_key_path}")
    if not device_pubkey_path.is_file():
        raise FileNotFoundError(f"device public key not found: {device_pubkey_path}")

    signing_private_key = crypto.load_private_key(signing_key_path)
    device_public_key = crypto.load_public_key(device_pubkey_path)

    manifest_dict = manifest.build_manifest(input_dir, platform, fw_version)
    tarball_bytes = tarball.stage_and_compress(input_dir, manifest_dict)

    aes_key = crypto.generate_aes_key()
    iv = crypto.generate_iv()
    ciphertext = crypto.encrypt_payload(tarball_bytes, aes_key, iv)
    wrapped_key = crypto.wrap_key(aes_key, device_public_key)

    header = blob.build_header(
        platform_tag=platform,
        fw_version=fw_version,
        iv=iv,
        wrapped_key_len=len(wrapped_key),
    )
    # Signed over header || wrapped_key || ciphertext - see
    # docs/FORMAT_SPEC.md's Signature Section and docs/THREAT_MODEL.md
    # item 6 for why the whole package is bound under one signature.
    signature = crypto.sign(header + wrapped_key + ciphertext, signing_private_key)
    final_blob = blob.assemble(header, wrapped_key, signature, ciphertext)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(final_blob)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        pack(
            input_dir=args.input_dir,
            platform=args.platform,
            fw_version=args.fw_version,
            signing_key_path=args.signing_key,
            device_pubkey_path=args.device_pubkey,
            output_path=args.output,
        )
    except (FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
