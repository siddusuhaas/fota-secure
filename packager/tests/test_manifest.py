import hashlib
from pathlib import Path

from fota_secure.manifest import build_manifest


def test_build_manifest_basic(tmp_path: Path) -> None:
    (tmp_path / "kernel.bin").write_bytes(b"kernel-bytes")
    (tmp_path / "rootfs.img").write_bytes(b"rootfs-bytes")

    manifest = build_manifest(tmp_path, platform="GENERIC", fw_version="1.0.0.0")

    assert manifest["platform"] == "GENERIC"
    assert manifest["fw_version"] == "1.0.0.0"
    assert manifest["build_date_utc"].endswith("Z")
    assert isinstance(manifest["git_commit"], str)
    assert manifest["git_commit"] != ""

    files_by_path = {f["path"]: f["sha256"] for f in manifest["files"]}
    assert set(files_by_path) == {"kernel.bin", "rootfs.img"}
    assert files_by_path["kernel.bin"] == hashlib.sha256(b"kernel-bytes").hexdigest()
    assert files_by_path["rootfs.img"] == hashlib.sha256(b"rootfs-bytes").hexdigest()


def test_build_manifest_nested_dirs(tmp_path: Path) -> None:
    nested = tmp_path / "sub" / "dir"
    nested.mkdir(parents=True)
    (nested / "extra.bin").write_bytes(b"extra")

    manifest = build_manifest(tmp_path, platform="GENERIC", fw_version="2.0.0.0")

    paths = [f["path"] for f in manifest["files"]]
    assert "sub/dir/extra.bin" in paths


def test_build_manifest_empty_dir(tmp_path: Path) -> None:
    manifest = build_manifest(tmp_path, platform="GENERIC", fw_version="1.0.0.0")
    assert manifest["files"] == []
