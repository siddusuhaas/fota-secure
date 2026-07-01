"""Generate tarball fixtures for test_installer.c.

valid.tar.gz is genuine output from this project's own
tarball.py/manifest.py (real interop, not hand-rolled in C). The
malicious/malformed fixtures are deliberately hand-crafted with Python's
stdlib tarfile module - these exercise attacks the C installer must
reject (path traversal, symlinks, manifest/content mismatches) that our
own packager would never produce on its own.

Dev/test tooling only - never part of the consumer binary itself.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import tarfile
from pathlib import Path

from fota_secure import manifest as manifest_mod
from fota_secure import tarball as tarball_mod

FILES = {
    "kernel.bin": b"fake kernel bytes for installer testing",
    "rootfs.img": b"fake rootfs bytes" * 20,
    "config/settings.ini": b"key=value\n",
}


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes,
                tar_type: int = tarfile.REGTYPE, linkname: str = "") -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data) if tar_type == tarfile.REGTYPE else 0
    info.type = tar_type
    if linkname:
        info.linkname = linkname
    tar.addfile(info, io.BytesIO(data) if tar_type == tarfile.REGTYPE else None)


def _build_tar_gz_with_manifest(files: dict, manifest_dict: dict) -> bytes:
    """Hand-built (not via tarball.py) so the manifest/content can be
    deliberately made inconsistent with each other for negative tests."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, data in files.items():
            _add_bytes(tar, path, data)
        manifest_bytes = json.dumps(manifest_dict, indent=2).encode("utf-8")
        _add_bytes(tar, "manifest.json", manifest_bytes)
    return buf.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    out: Path = args.output_dir
    out.mkdir(parents=True, exist_ok=True)

    # --- valid.tar.gz: genuine packager output, driven by real files on
    # disk through the real manifest.py/tarball.py modules ---
    input_dir = out / "firmware_files"
    for rel_path, data in FILES.items():
        file_path = input_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(data)

    real_manifest = manifest_mod.build_manifest(
        input_dir, platform="GENERIC", fw_version="1.0.0.0"
    )
    valid_tar_gz = tarball_mod.stage_and_compress(input_dir, real_manifest)
    (out / "valid.tar.gz").write_bytes(valid_tar_gz)

    # --- traversal.tar.gz: entry name attempts path traversal ---
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        _add_bytes(tar, "../../../tmp/evil.txt", b"pwned")
    (out / "traversal.tar.gz").write_bytes(buf.getvalue())

    # --- symlink.tar.gz: symlink entry pointing outside the install dir ---
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        _add_bytes(tar, "evil_symlink", b"", tar_type=tarfile.SYMTYPE,
                   linkname="/etc/passwd")
    (out / "symlink.tar.gz").write_bytes(buf.getvalue())

    # --- manifest_missing_file.tar.gz: manifest lists a file absent from
    # the tarball ---
    missing_file_manifest = json.loads(json.dumps(real_manifest))
    missing_file_manifest["files"].append(
        {"path": "ghost.bin", "sha256": "0" * 64}
    )
    (out / "manifest_missing_file.tar.gz").write_bytes(
        _build_tar_gz_with_manifest(FILES, missing_file_manifest)
    )

    # --- extra_unlisted_file.tar.gz: tarball has a file the manifest
    # never mentions ---
    extra_files = dict(FILES)
    extra_files["unlisted.bin"] = b"this file is not in the manifest"
    (out / "extra_unlisted_file.tar.gz").write_bytes(
        _build_tar_gz_with_manifest(extra_files, real_manifest)
    )

    # --- hash_mismatch.tar.gz: manifest sha256 doesn't match real content ---
    tampered_manifest = json.loads(json.dumps(real_manifest))
    tampered_manifest["files"][0]["sha256"] = "f" * 64
    (out / "hash_mismatch.tar.gz").write_bytes(
        _build_tar_gz_with_manifest(FILES, tampered_manifest)
    )

    print(f"fixtures written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
