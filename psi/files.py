"""File helpers for writing sensitive data safely."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_bytes_secure(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write bytes atomically with restrictive permissions from creation time."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path_str = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp_path = Path(tmp_path_str)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            os.fchmod(f.fileno(), mode)
        os.replace(tmp_path, path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise


def write_text_secure(
    path: Path,
    data: str,
    mode: int = 0o600,
    encoding: str = "utf-8",
) -> None:
    """Write text atomically with restrictive permissions from creation time."""
    write_bytes_secure(path, data.encode(encoding), mode=mode)
