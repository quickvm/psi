"""Socket authentication token resolution.

Resolution order (matches nitrokeyhsm pin.py pattern):
1. $CREDENTIALS_DIRECTORY/psi-socket-token (systemd-creds / TPM)
2. Config 'socket_token' field
3. PSI_SOCKET_TOKEN env var

Returns None if no token source is configured — auth is then disabled.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from psi.settings import PsiSettings

_VALID_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{8,}$")


def resolve_socket_token(settings: PsiSettings) -> str | None:
    """Resolve the socket auth token from credentials, config, or environment.

    Returns:
        The token string, or None if auth is not configured.

    Raises:
        ConfigError: If the resolved token contains invalid characters.
    """
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if creds_dir:
        token_path = Path(creds_dir) / "psi-socket-token"
        if token_path.exists():
            return _validate(token_path.read_text().strip())

    if settings.socket_token:
        return _validate(settings.socket_token)

    env_token = os.environ.get("PSI_SOCKET_TOKEN")
    if env_token:
        return _validate(env_token)

    return None


def _validate(token: str) -> str:
    """Validate token format — prevents shell injection in curl commands."""
    if not _VALID_TOKEN_RE.match(token):
        from psi.errors import ConfigError

        msg = (
            "Invalid socket token format. Must be at least 8 characters "
            "and contain only [A-Za-z0-9._~+/=-]."
        )
        raise ConfigError(msg)
    return token
