"""Tests for psi.providers.infisical.auth error wrapping."""

from __future__ import annotations

import httpx
import pytest

from psi.errors import ProviderError
from psi.providers.infisical.auth import _parse_token_response


def _response(status_code: int, body: bytes = b"") -> httpx.Response:
    request = httpx.Request("POST", "http://test/api/v1/auth/universal-auth/login")
    return httpx.Response(status_code, request=request, content=body)


class TestParseTokenResponse:
    def test_success_returns_token_and_ttl(self) -> None:
        resp = _response(200, b'{"accessToken": "tok", "expiresIn": 3600}')
        assert _parse_token_response(resp) == ("tok", 3600)

    def test_502_raises_provider_error_with_cause(self) -> None:
        resp = _response(502, b"Bad Gateway")
        with pytest.raises(ProviderError) as excinfo:
            _parse_token_response(resp)
        assert "HTTP 502" in str(excinfo.value)
        assert excinfo.value.provider_name == "infisical"
        assert isinstance(excinfo.value.__cause__, httpx.HTTPStatusError)

    def test_401_raises_provider_error_with_body_snippet(self) -> None:
        resp = _response(401, b'{"error": "invalid credentials"}')
        with pytest.raises(ProviderError, match="invalid credentials"):
            _parse_token_response(resp)
