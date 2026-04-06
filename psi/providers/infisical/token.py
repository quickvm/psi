"""File-based token cache with per-auth-config keying."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from psi.files import write_text_secure
from psi.providers.infisical.models import AuthConfig, TokenCache

if TYPE_CHECKING:
    from pathlib import Path


def _cache_path(state_dir: Path, auth: AuthConfig) -> Path:
    """Token cache file path, unique per auth configuration."""
    return state_dir / f".token.{auth.cache_key()}.json"


def read_cached_token(state_dir: Path, auth: AuthConfig) -> str | None:
    """Return cached token if still valid, else None."""
    path = _cache_path(state_dir, auth)
    if not path.exists():
        return None
    cache = TokenCache.model_validate_json(path.read_text())
    if time.time() >= cache.expires_at:
        return None
    return cache.access_token


def write_token_cache(
    state_dir: Path,
    auth: AuthConfig,
    access_token: str,
    expires_in: int,
    ttl_cap: int | None = None,
) -> None:
    """Cache token to file. TTL is min(expires_in, ttl_cap) if cap given."""
    effective_ttl = min(expires_in, ttl_cap) if ttl_cap else expires_in
    cache = TokenCache(
        access_token=access_token,
        expires_at=time.time() + effective_ttl,
    )
    path = _cache_path(state_dir, auth)
    write_text_secure(path, cache.model_dump_json())
