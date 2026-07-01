import io
import json
import tarfile
from pathlib import Path

from fota_secure.manifest import build_manifest
from fota_secure.tarball import stage_and_compress


def test_stage_and_compress_round_trip(tmp_path: Path) -> None:
    (tmp_path / "kernel.bin").write_bytes(b"kernel-bytes")
    (tmp_path / "rootfs.img").write_bytes(b"rootfs-bytes")

    manifest = build_manifest(tmp_path, platform="GENERIC", fw_version="1.0.0.0")
    tar_bytes = stage_and_compress(tmp_path, manifest)

    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        names = tar.getnames()
        assert "manifest.json" in names
        assert "kernel.bin" in names
        assert "rootfs.img" in names

        manifest_member = tar.extractfile("manifest.json")
        assert manifest_member is not None
        assert json.loads(manifest_member.read()) == manifest

        kernel_member = tar.extractfile("kernel.bin")
        assert kernel_member is not None
        assert kernel_member.read() == b"kernel-bytes"

        rootfs_member = tar.extractfile("rootfs.img")
        assert rootfs_member is not None
        assert rootfs_member.read() == b"rootfs-bytes"


def test_stage_and_compress_nested_dirs(tmp_path: Path) -> None:
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "extra.bin").write_bytes(b"extra")

    manifest = build_manifest(tmp_path, platform="GENERIC", fw_version="1.0.0.0")
    tar_bytes = stage_and_compress(tmp_path, manifest)

    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        assert "sub/extra.bin" in tar.getnames()


def test_stage_and_compress_empty_dir(tmp_path: Path) -> None:
    manifest = build_manifest(tmp_path, platform="GENERIC", fw_version="1.0.0.0")
    tar_bytes = stage_and_compress(tmp_path, manifest)

    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        assert tar.getnames() == ["manifest.json"]
