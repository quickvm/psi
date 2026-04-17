"""Offline integration test: cached lookups succeed while the provider is down.

This is the regression test for the 2026-04-08 incident on homelab.inf7.dev
where an Infisical outage caused every PSI-backed container to fail to start.
"""

from __future__ import annotations

import io
import json
import os
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from psi.cache import Cache
from psi.cache_backends import TPM_BACKEND_TAG
from psi.errors import ProviderError
from psi.serve import _make_handler

if TYPE_CHECKING:
    from pathlib import Path


class _FakeBackend:
    """Fixed-key backend used in tests to bypass TPM/HSM provisioning."""

    tag = TPM_BACKEND_TAG

    def __init__(self, key: bytes = bytes(range(32))) -> None:
        self._key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(self._key).encrypt(nonce, plaintext, None)

    def decrypt(self, payload: bytes) -> bytes:
        nonce, ciphertext = payload[:12], payload[12:]
        return AESGCM(self._key).decrypt(nonce, ciphertext, None)

    def close(self) -> None:
        pass


class _FakeRequest:
    def __init__(self, path: str, headers: dict[str, str], body: bytes = b"") -> None:
        self.path = path
        self.headers = headers
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self._status: int | None = None
        self._response_headers: dict[str, str] = {}

    def send_response(self, code: int) -> None:
        self._status = code

    def send_header(self, key: str, value: str) -> None:
        self._response_headers[key] = value

    def end_headers(self) -> None:
        pass


def _make_settings(tmp_path: Path) -> MagicMock:
    s = MagicMock()
    s.state_dir = tmp_path
    return s


def _build_handler(
    tmp_path: Path,
    providers: dict,
    cache: Cache | None,
) -> type:
    handler_cls = _make_handler(_make_settings(tmp_path), providers, None, cache)

    class TestHandler(_FakeRequest, handler_cls):  # ty: ignore[unsupported-base]
        def __init__(self, path: str, headers: dict[str, str], body: bytes = b"") -> None:
            _FakeRequest.__init__(self, path, headers, body)

    return TestHandler


_DB_URL_MAPPING = '{"provider":"infisical","project":"p","path":"/","key":"DATABASE_URL"}'


def _cache_key_for(cache: Cache, mapping_json: str) -> str:
    """Compute the HMAC cache key the same way serve does at lookup time."""
    from psi.provider import mapping_cache_bytes, parse_mapping

    return cache.cache_key(mapping_cache_bytes(parse_mapping(mapping_json)))


@pytest.fixture
def populated_cache(tmp_path: Path) -> Cache:
    cache = Cache(tmp_path / "cache.enc", _FakeBackend())
    cache.set(_cache_key_for(cache, _DB_URL_MAPPING), b"postgres://prod/db")
    cache.save()
    fresh = Cache(tmp_path / "cache.enc", _FakeBackend())
    fresh.load()
    return fresh


class TestServeWhileProviderDown:
    def test_cached_lookup_succeeds_when_provider_raises(
        self,
        tmp_path: Path,
        populated_cache: Cache,
    ) -> None:
        (tmp_path / "myapp--DATABASE_URL").write_text(_DB_URL_MAPPING)
        provider = MagicMock()
        provider.lookup.side_effect = ProviderError(
            "Cannot reach Infisical API",
            provider_name="infisical",
        )

        handler_cls = _build_handler(tmp_path, {"infisical": provider}, populated_cache)
        h = handler_cls("/lookup/myapp--DATABASE_URL", headers={})
        h.do_GET()

        assert h._status == 200
        assert h.wfile.getvalue() == b"postgres://prod/db"
        # Provider must NOT have been called — the cache short-circuits it.
        provider.lookup.assert_not_called()

    def test_cache_miss_falls_through_to_provider(
        self,
        tmp_path: Path,
        populated_cache: Cache,
    ) -> None:
        new_mapping = '{"provider":"infisical","project":"p","path":"/","key":"NEW_KEY"}'
        (tmp_path / "myapp--NEW_KEY").write_text(new_mapping)
        provider = MagicMock()
        provider.lookup.return_value = b"fresh-value"

        handler_cls = _build_handler(tmp_path, {"infisical": provider}, populated_cache)
        h = handler_cls("/lookup/myapp--NEW_KEY", headers={})
        h.do_GET()

        assert h._status == 200
        assert h.wfile.getvalue() == b"fresh-value"
        provider.lookup.assert_called_once()
        assert populated_cache.get(_cache_key_for(populated_cache, new_mapping)) == b"fresh-value"

    def test_provider_error_without_cache_entry_returns_502(
        self,
        tmp_path: Path,
        populated_cache: Cache,
    ) -> None:
        (tmp_path / "myapp--MISSING").write_text(
            '{"provider":"infisical","project":"p","path":"/","key":"MISSING"}'
        )
        provider = MagicMock()
        provider.lookup.side_effect = ProviderError("down", provider_name="infisical")

        handler_cls = _build_handler(tmp_path, {"infisical": provider}, populated_cache)
        h = handler_cls("/lookup/myapp--MISSING", headers={})
        h.do_GET()

        assert h._status == 502
        body = json.loads(h.wfile.getvalue())
        assert body["error"] == "provider_error"
