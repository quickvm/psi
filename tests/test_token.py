"""Tests for psi.token."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from psi.providers.infisical.models import AuthConfig, AuthMethod
from psi.providers.infisical.token import read_cached_token, write_token_cache

if TYPE_CHECKING:
    from pathlib import Path


def _auth() -> AuthConfig:
    return AuthConfig(method=AuthMethod.AWS_IAM, identity_id="test-id")


class TestWriteTokenCache:
    def test_writes_file(self, tmp_path: Path) -> None:
        write_token_cache(tmp_path, _auth(), "tok123", 3600)
        files = list(tmp_path.glob(".token.*.json"))
        assert len(files) == 1

    def test_file_permissions(self, tmp_path: Path) -> None:
        write_token_cache(tmp_path, _auth(), "tok123", 3600)
        files = list(tmp_path.glob(".token.*.json"))
        assert oct(files[0].stat().st_mode & 0o777) == "0o600"

    def test_ttl_cap(self, tmp_path: Path) -> None:
        write_token_cache(tmp_path, _auth(), "tok123", 7200, ttl_cap=300)
        files = list(tmp_path.glob(".token.*.json"))
        data = json.loads(files[0].read_text())
        # expires_at should be ~now + 300, not now + 7200
        import time

        assert data["expires_at"] < time.time() + 400
        assert data["expires_at"] > time.time() + 200

    def test_no_ttl_cap(self, tmp_path: Path) -> None:
        write_token_cache(tmp_path, _auth(), "tok123", 7200)
        files = list(tmp_path.glob(".token.*.json"))
        data = json.loads(files[0].read_text())
        import time

        assert data["expires_at"] > time.time() + 7000


class TestReadCachedToken:
    def test_returns_none_when_missing(self, tmp_path: Path) -> None:
        assert read_cached_token(tmp_path, _auth()) is None

    def test_returns_token_when_valid(self, tmp_path: Path) -> None:
        write_token_cache(tmp_path, _auth(), "mytoken", 3600)
        assert read_cached_token(tmp_path, _auth()) == "mytoken"

    def test_returns_none_when_expired(self, tmp_path: Path) -> None:
        write_token_cache(tmp_path, _auth(), "old", 0, ttl_cap=0)
        # TTL of 0 means already expired
        assert read_cached_token(tmp_path, _auth()) is None

    def test_different_auth_different_cache(self, tmp_path: Path) -> None:
        auth_a = AuthConfig(method=AuthMethod.AWS_IAM, identity_id="a")
        auth_b = AuthConfig(method=AuthMethod.AWS_IAM, identity_id="b")
        write_token_cache(tmp_path, auth_a, "tok_a", 3600)
        assert read_cached_token(tmp_path, auth_a) == "tok_a"
        assert read_cached_token(tmp_path, auth_b) is None
