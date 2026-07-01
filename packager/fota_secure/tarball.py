"""Stage firmware files plus manifest.json into a .tar.gz payload.

See docs/FORMAT_SPEC.md's high-level layout: the payload section is the
AES-256-CBC ciphertext of this tarball.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any


def stage_and_compress(input_dir: Path, manifest: dict[str, Any]) -> bytes:
    """Build a .tar.gz containing input_dir's files plus manifest.json at
    the tarball root, and return its raw bytes.
    """
    input_dir = Path(input_dir)
    buf = io.BytesIO()
    # Explicit USTAR format: tarfile's default (PAX) emits a "./@PaxHeader"
    # extended-header entry before each file whenever mtimes have
    # sub-second precision, which is always for freshly-written firmware
    # files. The consumer's C-side tar parser only needs to understand
    # plain ustar headers - PAX support isn't needed for our short
    # filenames/small sizes, and not implementing it keeps that
    # security-critical parser narrower in scope.
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for path in sorted(input_dir.rglob("*")):
            if path.is_file():
                arcname = path.relative_to(input_dir).as_posix()
                tar.add(path, arcname=arcname)

        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        manifest_info = tarfile.TarInfo(name="manifest.json")
        manifest_info.size = len(manifest_bytes)
        tar.addfile(manifest_info, io.BytesIO(manifest_bytes))

    return buf.getvalue()
