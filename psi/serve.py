"""HTTP server for secret lookups over a Unix socket."""

from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import UnixStreamServer
from typing import TYPE_CHECKING

from loguru import logger

from psi.errors import PsiError
from psi.files import write_bytes_secure
from psi.provider import close_all_providers, open_all_providers, parse_mapping
from psi.secret import validate_secret_id
from psi.token import resolve_socket_token

if TYPE_CHECKING:
    from psi.cache import Cache
    from psi.settings import PsiSettings


class _UnixHTTPServer(UnixStreamServer, HTTPServer):
    """HTTP server that listens on a Unix socket."""

    def server_bind(self) -> None:
        """Bind using UnixStreamServer, not HTTPServer."""
        UnixStreamServer.server_bind(self)


def run_serve(settings: PsiSettings, socket_path: str) -> None:
    """Start the lookup service on a Unix socket."""
    providers = open_all_providers(settings)
    cache = _open_cache(settings)
    token = resolve_socket_token(settings)
    if token:
        logger.info("Socket auth enabled")
    else:
        logger.info("Socket auth disabled — no token configured")
    try:
        handler = _make_handler(settings, providers, token, cache)

        if os.path.exists(socket_path):
            os.unlink(socket_path)

        os.makedirs(os.path.dirname(socket_path), exist_ok=True)
        server = _UnixHTTPServer(socket_path, handler)
        os.chmod(socket_path, 0o600)

        logger.info("Listening on {}", socket_path)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
            if os.path.exists(socket_path):
                os.unlink(socket_path)
    finally:
        if cache is not None:
            cache.close()
        close_all_providers(providers)


def _open_cache(settings: PsiSettings) -> Cache | None:
    """Construct, open, and load the secret cache.

    Returns None (and logs a warning) on any failure — PSI continues to serve
    live lookups so a missing cache key does not take down the fleet.
    """
    if not settings.cache.enabled:
        logger.info("Secret cache disabled by config")
        return None
    if settings.cache.backend is None:
        logger.warning(
            "Secret cache is enabled but no backend is configured. "
            "Run 'psi cache init --backend {tpm,hsm}' to provision one. "
            "Falling back to live provider lookups."
        )
        return None

    from psi.cache import Cache
    from psi.cache_backends import make_backend

    try:
        backend = make_backend(settings.cache.backend, settings)
        open_method = getattr(backend, "open", None)
        if callable(open_method):
            open_method()
    except Exception as e:
        logger.warning(
            "Secret cache backend {} failed to open: {}. Falling back to live provider lookups.",
            settings.cache.backend,
            e,
        )
        return None

    cache = Cache(settings.cache.resolve_path(settings.state_dir), backend)
    try:
        cache.load()
    except Exception as e:
        logger.warning(
            "Secret cache at {} failed to load: {}. Falling back to live provider lookups.",
            cache.path,
            e,
        )
        cache.close()
        return None
    logger.info("Secret cache ready: {} entries from {}", len(cache), cache.path)
    return cache


def _make_handler(
    settings: PsiSettings,
    providers: dict,
    token: str | None,
    cache: Cache | None,
) -> type[BaseHTTPRequestHandler]:
    """Create a request handler with access to settings and providers."""

    class Handler(BaseHTTPRequestHandler):
        def _check_auth(self) -> bool:
            """Validate the Authorization header against the configured token.

            Returns True if auth is not configured, or if the token matches.
            """
            if not token:
                return True
            provided = self.headers.get("Authorization", "")
            expected = f"Bearer {token}"
            return hmac.compare_digest(provided, expected)

        def _unauthorized(self) -> None:
            logger.bind(
                event="socket.auth",
                outcome="error",
                path=self.path,
            ).warning("unauthorized request")
            self._respond_error(401, "unauthorized", "invalid or missing token")

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.rstrip("/")

            if path == "/healthz":
                self._respond(200, b"ok")
                return

            if not self._check_auth():
                self._unauthorized()
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

            if not self._check_auth():
                self._unauthorized()
                return

            if path.startswith("/store/"):
                self._handle_store(path[len("/store/") :])
                return

            self._respond(404, b"not found")

        def do_DELETE(self) -> None:  # noqa: N802
            path = self.path.rstrip("/")

            if not self._check_auth():
                self._unauthorized()
                return

            if path.startswith("/delete/"):
                self._handle_delete(path[len("/delete/") :])
                return

            self._respond(404, b"not found")

        def _handle_lookup(self, secret_id: str) -> None:
            if not secret_id:
                self._respond_error(400, "missing_secret_id", "SECRET_ID not set")
                return
            try:
                secret_id = validate_secret_id(secret_id)
            except ValueError as e:
                self._respond_error(400, "invalid_secret_id", str(e))
                return

            mapping_path = settings.state_dir / secret_id
            if not mapping_path.exists():
                self._respond_error(404, "not_found", f"No mapping for secret: {secret_id}")
                return

            raw = mapping_path.read_text().strip()
            try:
                mapping_data = parse_mapping(raw)
            except ValueError:
                self._respond_error(500, "corrupt_mapping", f"Corrupt mapping for {secret_id}")
                return

            provider_name = mapping_data.get("provider", "")
            provider = providers.get(provider_name)
            if not provider:
                self._respond_error(
                    500,
                    "unknown_provider",
                    f"Provider '{provider_name}' not configured",
                )
                return

            audit = logger.bind(
                event="secret.lookup",
                secret_id=secret_id,
                provider=provider_name,
            )

            if cache is not None:
                cached = cache.get(secret_id)
                if cached is not None:
                    self._respond(200, cached)
                    audit.bind(outcome="success", source="cache").debug("lookup")
                    return

            try:
                value = provider.lookup(mapping_data)
            except PsiError as e:
                audit.bind(outcome="error", error=str(e)).warning("lookup")
                self._respond_error(502, "provider_error", str(e))
                return
            except Exception as e:
                audit.bind(outcome="error", error=str(e)).error("lookup")
                self._respond_error(502, "internal_error", str(e))
                return

            if cache is not None:
                cache.set(secret_id, value)

            self._respond(200, value)
            audit.bind(outcome="success", source="provider").info("lookup")

        def _handle_store(self, secret_id: str) -> None:
            if not secret_id:
                self._respond(400, b"secret_id required")
                return
            try:
                secret_id = validate_secret_id(secret_id)
            except ValueError as e:
                self._respond_error(400, "invalid_secret_id", str(e))
                return

            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length)

            settings.state_dir.mkdir(parents=True, exist_ok=True)
            mapping_path = settings.state_dir / secret_id
            write_bytes_secure(mapping_path, data)
            logger.bind(
                event="secret.store",
                secret_id=secret_id,
                outcome="success",
            ).info("store")
            self._respond(200, b"ok")

        def _handle_delete(self, secret_id: str) -> None:
            if not secret_id:
                self._respond(400, b"secret_id required")
                return
            try:
                secret_id = validate_secret_id(secret_id)
            except ValueError as e:
                self._respond_error(400, "invalid_secret_id", str(e))
                return

            mapping_path = settings.state_dir / secret_id
            mapping_path.unlink(missing_ok=True)
            logger.bind(
                event="secret.delete",
                secret_id=secret_id,
                outcome="success",
            ).info("delete")
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
            self._write_response(code, [], body)

        def _respond_error(self, code: int, error: str, detail: str) -> None:
            body = json.dumps({"error": error, "detail": detail}).encode()
            self._write_response(code, [("Content-Type", "application/json")], body)

        def _write_response(
            self,
            code: int,
            headers: list[tuple[str, str]],
            body: bytes,
        ) -> None:
            """Write a full HTTP response, swallowing client-hangup errors.

            Podman's shell driver uses ``curl -sf`` which closes the socket
            as soon as it sees a non-2xx status, so the server routinely
            races the client on error responses. ``BrokenPipeError`` and
            ``ConnectionResetError`` from the peer are normal conditions
            for any HTTP server and must not escape as tracebacks.
            """
            self.send_response(code)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            try:
                self.end_headers()
                self.wfile.write(body)
            except BrokenPipeError, ConnectionResetError:
                pass

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            """Suppress per-request logging."""

    return Handler
