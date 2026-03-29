"""Tests for psi.secret — shell driver and secret status."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from psi.models import SecretSource, WorkloadConfig
from psi.secret import (
    _fail,
    _require_secret_id,
    delete,
    get_secret_status,
    list_secrets,
    store,
)

if TYPE_CHECKING:
    from pathlib import Path


def _mock_settings(tmp_path: Path, workloads: dict | None = None) -> MagicMock:
    settings = MagicMock()
    settings.state_dir = tmp_path
    settings.workloads = workloads or {}
    settings.projects = {}
    return settings


class TestStore:
    def test_writes_mapping(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECRET_ID", "myapp--DB_HOST")
        import io
        import sys

        monkeypatch.setattr(sys, "stdin", MagicMock(buffer=io.BytesIO(b"proj:/app:DB_HOST")))
        settings = _mock_settings(tmp_path)
        store(settings)

        mapping_file = tmp_path / "myapp--DB_HOST"
        assert mapping_file.exists()
        assert mapping_file.read_text() == "proj:/app:DB_HOST"
        assert oct(mapping_file.stat().st_mode & 0o777) == "0o600"

    def test_creates_state_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        state = tmp_path / "new" / "dir"
        monkeypatch.setenv("SECRET_ID", "test")
        import io
        import sys

        monkeypatch.setattr(sys, "stdin", MagicMock(buffer=io.BytesIO(b"data")))
        settings = _mock_settings(tmp_path)
        settings.state_dir = state
        store(settings)
        assert state.exists()


class TestDelete:
    def test_removes_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        mapping = tmp_path / "myapp--DB_HOST"
        mapping.write_text("proj:/app:DB_HOST")
        monkeypatch.setenv("SECRET_ID", "myapp--DB_HOST")
        delete(_mock_settings(tmp_path))
        assert not mapping.exists()

    def test_missing_file_ok(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECRET_ID", "nonexistent")
        delete(_mock_settings(tmp_path))  # Should not raise


class TestListSecrets:
    def test_lists_files(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        (tmp_path / "app--KEY_A").write_text("data")
        (tmp_path / "app--KEY_B").write_text("data")
        (tmp_path / ".token.abc.json").write_text("{}")
        list_secrets(_mock_settings(tmp_path))
        output = capsys.readouterr().out
        assert "app--KEY_A" in output
        assert "app--KEY_B" in output
        assert ".token" not in output

    def test_empty_dir(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        list_secrets(_mock_settings(tmp_path))
        assert capsys.readouterr().out == ""

    def test_missing_dir(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        settings = _mock_settings(tmp_path)
        settings.state_dir = tmp_path / "nonexistent"
        list_secrets(settings)
        assert capsys.readouterr().out == ""


class TestRequireSecretId:
    def test_returns_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECRET_ID", "test-id")
        assert _require_secret_id() == "test-id"

    def test_exits_when_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SECRET_ID", raising=False)
        with pytest.raises(SystemExit):
            _require_secret_id()

    def test_exits_when_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECRET_ID", "")
        with pytest.raises(SystemExit):
            _require_secret_id()


class TestFail:
    def test_exits_with_message(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc_info:
            _fail("something broke")
        assert exc_info.value.code == 1
        assert "something broke" in capsys.readouterr().err


class TestGetSecretStatus:
    def test_workload_with_secrets(self, tmp_path: Path) -> None:
        (tmp_path / "myapp--DB_HOST").write_text("proj:/app:DB_HOST")
        (tmp_path / "myapp--DB_PORT").write_text("proj:/app:DB_PORT")
        settings = _mock_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(secrets=[SecretSource(project="proj", path="/app")]),
            },
        )
        result = get_secret_status(settings)
        assert len(result) == 1
        assert result[0].workload == "myapp"
        assert len(result[0].secrets) == 2
        names = {s.name for s in result[0].secrets}
        assert names == {"DB_HOST", "DB_PORT"}
        assert all(s.registered for s in result[0].secrets)

    def test_workload_no_secrets(self, tmp_path: Path) -> None:
        settings = _mock_settings(
            tmp_path,
            workloads={
                "empty": WorkloadConfig(secrets=[SecretSource(project="proj", path="/app")]),
            },
        )
        result = get_secret_status(settings)
        assert len(result) == 1
        assert result[0].secrets == []

    def test_corrupt_mapping(self, tmp_path: Path) -> None:
        (tmp_path / "myapp--BAD").write_text("not-valid")
        settings = _mock_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(secrets=[SecretSource(project="proj", path="/app")]),
            },
        )
        result = get_secret_status(settings)
        assert len(result[0].secrets) == 1
        assert result[0].secrets[0].registered is False
        assert result[0].secrets[0].project == "?"
