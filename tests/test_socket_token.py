"""Tests for psi.token — socket auth token resolution."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from psi.errors import ConfigError
from psi.token import _validate, resolve_socket_token

if TYPE_CHECKING:
    from pathlib import Path


def _settings(token: str | None = None) -> MagicMock:
    s = MagicMock()
    s.socket_token = token
    return s


class TestResolveSocketToken:
    def test_returns_none_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        monkeypatch.delenv("PSI_SOCKET_TOKEN", raising=False)
        assert resolve_socket_token(_settings()) is None

    def test_from_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        monkeypatch.delenv("PSI_SOCKET_TOKEN", raising=False)
        assert resolve_socket_token(_settings("abcdefgh12345678")) == "abcdefgh12345678"

    def test_from_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        monkeypatch.setenv("PSI_SOCKET_TOKEN", "env-token-value123")
        assert resolve_socket_token(_settings()) == "env-token-value123"

    def test_from_credentials_directory(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        creds = tmp_path / "creds"
        creds.mkdir()
        (creds / "psi-socket-token").write_text("cred-token-value\n")
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
        monkeypatch.delenv("PSI_SOCKET_TOKEN", raising=False)

        assert resolve_socket_token(_settings("config-token-1234")) == "cred-token-value"

    def test_credentials_trumps_config(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        creds = tmp_path / "creds"
        creds.mkdir()
        (creds / "psi-socket-token").write_text("from-credentials")
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))

        assert resolve_socket_token(_settings("from-config-123")) == "from-credentials"

    def test_config_trumps_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        monkeypatch.setenv("PSI_SOCKET_TOKEN", "from-env-value")

        assert resolve_socket_token(_settings("from-config-123")) == "from-config-123"


class TestValidate:
    def test_accepts_standard_token(self) -> None:
        assert _validate("abcdefgh1234567890") == "abcdefgh1234567890"

    def test_accepts_base64_chars(self) -> None:
        token = "AbCdEfGh+/=._~-" + "abcdefgh"
        assert _validate(token) == token

    def test_rejects_short_token(self) -> None:
        with pytest.raises(ConfigError, match="at least 8"):
            _validate("short")

    def test_rejects_shell_metachars(self) -> None:
        with pytest.raises(ConfigError, match="only"):
            _validate("token'; rm -rf /")

    def test_rejects_spaces(self) -> None:
        with pytest.raises(ConfigError, match="only"):
            _validate("token with spaces 12")

    def test_rejects_quote(self) -> None:
        with pytest.raises(ConfigError, match="only"):
            _validate('token"injection')
