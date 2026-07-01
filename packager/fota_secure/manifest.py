"""Build the manifest embedded inside the firmware tarball.

See docs/FORMAT_SPEC.md's "Manifest" section for the on-disk schema. This
manifest gives integrity checking at the individual-file level after
extraction, independent of the outer package signature.
"""

from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_HASH_CHUNK_SIZE = 1024 * 1024


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return result.stdout.strip()
    except (
        subprocess.CalledProcessError,
        FileNotFoundError,
        subprocess.TimeoutExpired,
    ):
        return "unknown"


def build_manifest(input_dir: Path, platform: str, fw_version: str) -> dict[str, Any]:
    """Walk input_dir, hash each file, and return the manifest dict.

    File paths in the manifest are relative to input_dir and use forward
    slashes regardless of host OS, so the manifest is portable between the
    packaging host (which may be macOS/Windows) and the embedded device.
    """
    input_dir = Path(input_dir)
    files = []
    for path in sorted(input_dir.rglob("*")):
        if path.is_file():
            rel_path = path.relative_to(input_dir).as_posix()
            files.append({"path": rel_path, "sha256": _sha256_file(path)})

    return {
        "platform": platform,
        "fw_version": fw_version,
        "build_date_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": _git_commit(),
        "files": files,
    }
