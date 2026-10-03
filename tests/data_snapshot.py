"""The package's data/ directory, file by file (register N9). Imports nothing from WARDEN, so conftest.py can take
the first snapshot before any test runs."""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib

DATA = pathlib.Path(importlib.util.find_spec("warden").origin).parent / "data"


def snapshot(root: pathlib.Path = DATA) -> dict[str, str]:
    """Every file under `root` and its sha256: a file added, removed or changed shows."""
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}
