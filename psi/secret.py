"""Podman shell secret driver commands.

These functions implement the store/lookup/delete/list interface that
Podman calls when using the shell secret driver. No Rich output —
pure stdin/stdout/stderr protocol.
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, NoReturn

from loguru import logger

from psi.errors import PsiError
from psi.files import write_bytes_secure
from psi.provider import get_provider, parse_mapping

if TYPE_CHECKING:
    from psi.settings import PsiSettings


def store(settings: PsiSettings) -> None:
    """Store a secret mapping. Called by Podman with SECRET_ID env var."""
    secret_id = _require_secret_id()
    mapping_data = sys.stdin.buffer.read()
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    mapping_path = settings.state_dir / secret_id
    write_bytes_secure(mapping_path, mapping_data)
    logger.bind(
        event="secret.store",
        secret_id=secret_id,
        outcome="success",
    ).info("store")


def lookup(settings: PsiSettings) -> None:
    """Fetch a secret value via the appropriate provider."""
    secret_id = ""
    provider_name = ""
    try:
        secret_id = _require_secret_id()
        mapping_path = settings.state_dir / secret_id

        if not mapping_path.exists():
            _fail(f"No mapping for secret: {secret_id}")

        raw = mapping_path.read_text().strip()
        try:
            mapping_data = parse_mapping(raw)
        except ValueError as e:
            _fail(f"Corrupt mapping for {secret_id}: {e}")

        provider_name = mapping_data["provider"]
        provider = get_provider(provider_name, settings)
        provider.open()
        try:
            value = provider.lookup(mapping_data)
        finally:
            provider.close()

        sys.stdout.buffer.write(value)
        logger.bind(
            event="secret.lookup",
            secret_id=secret_id,
            provider=provider_name,
            outcome="success",
        ).info("lookup")
    except SystemExit, KeyboardInterrupt:
        raise
    except PsiError as e:
        logger.bind(
            event="secret.lookup",
            secret_id=secret_id,
            provider=provider_name,
            outcome="error",
            error=str(e),
        ).warning("lookup")
        _fail(str(e))


def delete(settings: PsiSettings) -> None:
    """Remove a secret mapping. Called by Podman on secret removal."""
    secret_id = _require_secret_id()
    mapping_path = settings.state_dir / secret_id
    mapping_path.unlink(missing_ok=True)
    logger.bind(
        event="secret.delete",
        secret_id=secret_id,
        outcome="success",
    ).info("delete")


def list_secrets(settings: PsiSettings) -> None:
    """List all registered secret IDs. Called by Podman."""
    if not settings.state_dir.exists():
        return
    for entry in sorted(settings.state_dir.iterdir()):
        if not entry.name.startswith(".") and entry.is_file():
            print(entry.name)


def _require_secret_id() -> str:
    """Read SECRET_ID from environment, fail if missing or empty."""
    secret_id = os.environ.get("SECRET_ID", "")
    if not secret_id:
        _fail("SECRET_ID environment variable not set")
    try:
        return validate_secret_id(secret_id)
    except ValueError as e:
        _fail(str(e))


def validate_secret_id(secret_id: str) -> str:
    """Validate that a secret ID is safe to use as a state-dir filename."""
    if secret_id in ("", ".", ".."):
        msg = "Invalid secret ID"
        raise ValueError(msg)
    if "/" in secret_id or "\\" in secret_id:
        msg = "Invalid secret ID: path separators are not allowed"
        raise ValueError(msg)
    return secret_id


def _fail(message: str) -> NoReturn:
    """Print error to stderr and exit."""
    print(message, file=sys.stderr)
    raise SystemExit(1)
