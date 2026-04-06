"""Tests for secure file writing helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from psi.files import write_bytes_secure, write_text_secure

if TYPE_CHECKING:
    from pathlib import Path


class TestWriteTextSecure:
    def test_writes_text(self, tmp_path: Path) -> None:
        path = tmp_path / "secret.txt"
        write_text_secure(path, "top-secret")
        assert path.read_text() == "top-secret"

    def test_uses_requested_mode(self, tmp_path: Path) -> None:
        path = tmp_path / "secret.txt"
        write_text_secure(path, "top-secret", mode=0o640)
        assert oct(path.stat().st_mode & 0o777) == "0o640"

    def test_replaces_existing_file(self, tmp_path: Path) -> None:
        path = tmp_path / "secret.txt"
        path.write_text("old")
        write_text_secure(path, "new")
        assert path.read_text() == "new"


class TestWriteBytesSecure:
    def test_writes_bytes(self, tmp_path: Path) -> None:
        path = tmp_path / "secret.bin"
        write_bytes_secure(path, b"\x00\x01")
        assert path.read_bytes() == b"\x00\x01"

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        path = tmp_path / "deep" / "secret.bin"
        write_bytes_secure(path, b"data")
        assert path.exists()
