"""Tests for psi.serve — HTTP handler auth enforcement."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

from psi.serve import _make_handler

if TYPE_CHECKING:
    from pathlib import Path


def _settings(tmp_path: Path) -> MagicMock:
    s = MagicMock()
    s.state_dir = tmp_path
    return s


class _FakeRequest:
    """Minimal BaseHTTPRequestHandler stub.

    We construct Handler instances without a real socket by overriding
    __init__; the handler methods we test only touch self.path,
    self.headers, self.rfile, self.wfile, and the _respond helpers.
    """

    def __init__(self, path: str, headers: dict[str, str], body: bytes = b"") -> None:
        import io

        self.path = path
        self.headers = headers
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self._status: int | None = None
        self._response_headers: dict[str, str] = {}
        self._body: bytes = b""

    def send_response(self, code: int) -> None:
        self._status = code

    def send_header(self, key: str, value: str) -> None:
        self._response_headers[key] = value

    def end_headers(self) -> None:
        pass


def _make_test_handler(
    tmp_path: Path,
    token: str | None,
    providers: dict | None = None,
    cache: object | None = None,
) -> type:
    """Build a Handler class with a stubbed base."""
    handler_cls = _make_handler(
        _settings(tmp_path),
        providers or {},
        token,
        cache,  # ty: ignore[invalid-argument-type]
    )

    class TestHandler(_FakeRequest, handler_cls):  # ty: ignore[unsupported-base]
        def __init__(self, path: str, headers: dict[str, str], body: bytes = b"") -> None:
            _FakeRequest.__init__(self, path, headers, body)

    return TestHandler


class TestAuthDisabled:
    def test_lookup_works_without_token_when_auth_disabled(self, tmp_path: Path) -> None:
        mapping = tmp_path / "my-secret"
        mapping.write_text('{"provider":"fake","key":"k"}')
        provider = MagicMock()
        provider.lookup.return_value = b"the-value"

        handler_cls = _make_test_handler(tmp_path, token=None, providers={"fake": provider})
        h = handler_cls("/lookup/my-secret", headers={})
        h.do_GET()

        assert h._status == 200
        assert h.wfile.getvalue() == b"the-value"

    def test_healthz_always_works(self, tmp_path: Path) -> None:
        handler_cls = _make_test_handler(tmp_path, token=None)
        h = handler_cls("/healthz", headers={})
        h.do_GET()
        assert h._status == 200

    def test_lookup_rejects_path_traversal_secret_id(self, tmp_path: Path) -> None:
        handler_cls = _make_test_handler(tmp_path, token=None)
        h = handler_cls("/lookup/../outside", headers={})
        h.do_GET()

        assert h._status == 400
        body = json.loads(h.wfile.getvalue())
        assert body["error"] == "invalid_secret_id"

    def test_store_rejects_path_traversal_secret_id(self, tmp_path: Path) -> None:
        outside = tmp_path.parent / "outside"
        handler_cls = _make_test_handler(tmp_path, token=None)
        h = handler_cls(
            "/store/../outside",
            headers={"Content-Length": "4"},
            body=b"data",
        )
        h.do_POST()

        assert h._status == 400
        assert not outside.exists()


class TestAuthEnabled:
    TOKEN = "abcdefgh1234567890"

    def test_lookup_without_token_returns_401(self, tmp_path: Path) -> None:
        handler_cls = _make_test_handler(tmp_path, token=self.TOKEN)
        h = handler_cls("/lookup/anything", headers={})
        h.do_GET()

        assert h._status == 401
        body = json.loads(h.wfile.getvalue())
        assert body["error"] == "unauthorized"

    def test_lookup_with_wrong_token_returns_401(self, tmp_path: Path) -> None:
        handler_cls = _make_test_handler(tmp_path, token=self.TOKEN)
        h = handler_cls(
            "/lookup/anything",
            headers={"Authorization": "Bearer wrong-token-value"},
        )
        h.do_GET()

        assert h._status == 401

    def test_lookup_with_correct_token_is_authorized(self, tmp_path: Path) -> None:
        mapping = tmp_path / "my-secret"
        mapping.write_text('{"provider":"fake","key":"k"}')
        provider = MagicMock()
        provider.lookup.return_value = b"the-value"

        handler_cls = _make_test_handler(tmp_path, token=self.TOKEN, providers={"fake": provider})
        h = handler_cls(
            "/lookup/my-secret",
            headers={"Authorization": f"Bearer {self.TOKEN}"},
        )
        h.do_GET()

        assert h._status == 200
        assert h.wfile.getvalue() == b"the-value"

    def test_healthz_exempt_from_auth(self, tmp_path: Path) -> None:
        handler_cls = _make_test_handler(tmp_path, token=self.TOKEN)
        h = handler_cls("/healthz", headers={})
        h.do_GET()
        assert h._status == 200

    def test_store_without_token_returns_401(self, tmp_path: Path) -> None:
        handler_cls = _make_test_handler(tmp_path, token=self.TOKEN)
        h = handler_cls(
            "/store/my-secret",
            headers={"Content-Length": "4"},
            body=b"data",
        )
        h.do_POST()
        assert h._status == 401

    def test_delete_without_token_returns_401(self, tmp_path: Path) -> None:
        handler_cls = _make_test_handler(tmp_path, token=self.TOKEN)
        h = handler_cls("/delete/my-secret", headers={})
        h.do_DELETE()
        assert h._status == 401

    def test_list_without_token_returns_401(self, tmp_path: Path) -> None:
        handler_cls = _make_test_handler(tmp_path, token=self.TOKEN)
        h = handler_cls("/list", headers={})
        h.do_GET()
        assert h._status == 401

    def test_timing_safe_comparison_used(self, tmp_path: Path) -> None:
        """Slight variations should still compare as unequal."""
        handler_cls = _make_test_handler(tmp_path, token=self.TOKEN)
        h = handler_cls(
            "/lookup/x",
            headers={"Authorization": f"Bearer {self.TOKEN}x"},
        )
        h.do_GET()
        assert h._status == 401


class _BrokenWriter:
    """wfile stand-in that fails on every write, like a disconnected peer."""

    def __init__(self, exc: type[OSError]) -> None:
        self._exc = exc

    def write(self, _data: bytes) -> None:
        raise self._exc(32, "peer gone")


class TestClientHangup:
    def test_respond_error_swallows_broken_pipe(self, tmp_path: Path) -> None:
        """A 401 to a disconnected curl must not escape as BrokenPipeError."""
        handler_cls = _make_test_handler(tmp_path, token="abcdefgh1234")
        h = handler_cls("/list", headers={})
        h.wfile = _BrokenWriter(BrokenPipeError)  # type: ignore[assignment]

        h.do_GET()

        assert h._status == 401

    def test_respond_success_swallows_connection_reset(self, tmp_path: Path) -> None:
        """A 200 response raced by peer reset must also be swallowed."""
        handler_cls = _make_test_handler(tmp_path, token=None)
        h = handler_cls("/healthz", headers={})
        h.wfile = _BrokenWriter(ConnectionResetError)  # type: ignore[assignment]

        h.do_GET()

        assert h._status == 200
