import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
KEYGEN_SCRIPT = REPO_ROOT / "keygen" / "generate_keys.py"


@pytest.fixture
def real_keypairs(tmp_path: Path) -> Path:
    """Generate real signing + device keypairs via keygen/generate_keys.py
    (not ad hoc test keys built inline) so wrap/unwrap and sign/verify
    tests exercise the actual key-generation path fota-secure ships.
    """
    keys_dir = tmp_path / "keys"
    subprocess.run(
        [sys.executable, str(KEYGEN_SCRIPT), "--output-dir", str(keys_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    return keys_dir
