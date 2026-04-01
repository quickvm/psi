"""HTTP server for secret lookups over a Unix socket."""

from __future__ import annotations

import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import UnixStreamServer
from typing import TYPE_CHECKING

from psi.provider import close_all_providers, open_all_providers, parse_mapping

if TYPE_CHECKING:
    from psi.settings import PsiSettings


class _UnixHTTPServer(UnixStreamServer, HTTPServer):
    """HTTP server that listens on a Unix socket."""

    def server_bind(self) -> None:
        """Bind using UnixStreamServer, not HTTPServer."""
        UnixStreamServer.server_bind(self)


def run_serve(settings: PsiSettings, socket_path: str) -> None:
    """Start the lookup service on a Unix socket."""
    providers = open_all_providers(settings)
    try:
        handler = _make_handler(settings, providers)

        if os.path.exists(socket_path):
            os.unlink(socket_path)

        os.makedirs(os.path.dirname(socket_path), exist_ok=True)
        server = _UnixHTTPServer(socket_path, handler)
        os.chmod(socket_path, 0o600)

        print(f"Listening on {socket_path}", file=sys.stderr)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
            if os.path.exists(socket_path):
                os.unlink(socket_path)
    finally:
        close_all_providers(providers)


def _make_handler(
    settings: PsiSettings,
    providers: dict,
) -> type[BaseHTTPRequestHandler]:
    """Create a request handler with access to settings and providers."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = self.path.rstrip("/")

            if path == "/healthz":
                self._respond(200, b"ok")
                return

            if path.startswith("/lookup/"):
                self._handle_lookup(path[len("/lookup/") :])
                return

            if path == "/list":
                self._handle_list()
                return

            self._respond(404, b"not found")

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.rstrip("/")

            if path.startswith("/store/"):
                self._handle_store(path[len("/store/") :])
                return

            self._respond(404, b"not found")

        def do_DELETE(self) -> None:  # noqa: N802
            path = self.path.rstrip("/")

            if path.startswith("/delete/"):
                self._handle_delete(path[len("/delete/") :])
                return

            self._respond(404, b"not found")

        def _handle_lookup(self, secret_id: str) -> None:
            if not secret_id:
                self._respond(400, b"SECRET_ID not set")
                return

            mapping_path = settings.state_dir / secret_id
            if not mapping_path.exists():
                self._respond(404, f"no mapping: {secret_id}".encode())
                return

            raw = mapping_path.read_text().strip()
            try:
                mapping_data = parse_mapping(raw)
            except ValueError:
                self._respond(500, f"corrupt mapping: {secret_id}".encode())
                return

            provider_name = mapping_data.get("provider", "")
            provider = providers.get(provider_name)
            if not provider:
                self._respond(
                    500,
                    f"unknown provider: {provider_name}".encode(),
                )
                return

            try:
                value = provider.lookup(mapping_data)
                self._respond(200, value)
            except Exception as e:
                self._respond(502, str(e).encode())

        def _handle_store(self, secret_id: str) -> None:
            if not secret_id:
                self._respond(400, b"secret_id required")
                return

            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length)

            settings.state_dir.mkdir(parents=True, exist_ok=True)
            mapping_path = settings.state_dir / secret_id
            mapping_path.write_bytes(data)
            mapping_path.chmod(0o600)
            self._respond(200, b"ok")

        def _handle_delete(self, secret_id: str) -> None:
            if not secret_id:
                self._respond(400, b"secret_id required")
                return

            mapping_path = settings.state_dir / secret_id
            mapping_path.unlink(missing_ok=True)
            self._respond(200, b"ok")

        def _handle_list(self) -> None:
            if not settings.state_dir.exists():
                self._respond(200, b"")
                return

            names = sorted(
                e.name
                for e in settings.state_dir.iterdir()
                if not e.name.startswith(".") and e.is_file()
            )
            self._respond(200, "\n".join(names).encode())

        def _respond(self, code: int, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            """Suppress per-request logging."""

    return Handler
