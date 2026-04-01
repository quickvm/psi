"""Podman shell secret driver commands.

These functions implement the store/lookup/delete/list interface that
Podman calls when using the shell secret driver. No Rich output —
pure stdin/stdout/stderr protocol.
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, NoReturn

from psi.provider import get_provider, parse_mapping

if TYPE_CHECKING:
    from psi.settings import PsiSettings


def store(settings: PsiSettings) -> None:
    """Store a secret mapping. Called by Podman with SECRET_ID env var."""
    secret_id = _require_secret_id()
    mapping_data = sys.stdin.buffer.read()
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    mapping_path = settings.state_dir / secret_id
    mapping_path.write_bytes(mapping_data)
    mapping_path.chmod(0o600)


def lookup(settings: PsiSettings) -> None:
    """Fetch a secret value via the appropriate provider."""
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


def delete(settings: PsiSettings) -> None:
    """Remove a secret mapping. Called by Podman on secret removal."""
    secret_id = _require_secret_id()
    mapping_path = settings.state_dir / secret_id
    mapping_path.unlink(missing_ok=True)


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
    return secret_id


def _fail(message: str) -> NoReturn:
    """Print error to stderr and exit."""
    print(message, file=sys.stderr)
    raise SystemExit(1)
