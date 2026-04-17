"""Provider protocol and registry for secret backends."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from psi.settings import PsiSettings


@runtime_checkable
class SecretProvider(Protocol):
    """A pluggable backend for secret storage and retrieval."""

    name: str

    def open(self) -> None:
        """Acquire long-lived resources (PKCS#11 session, HTTP client)."""
        ...

    def close(self) -> None:
        """Release resources."""
        ...

    def lookup(self, mapping_data: dict) -> bytes:
        """Resolve a secret mapping to its plaintext value."""
        ...


def parse_mapping(raw: str) -> dict:
    """Parse a JSON secret mapping from state_dir.

    Returns:
        Dict with at least a 'provider' key.

    Raises:
        ValueError: If the data is not valid JSON or missing 'provider'.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        msg = f"Invalid mapping (not JSON): {raw[:80]!r}"
        raise ValueError(msg) from e
    if "provider" not in data:
        msg = f"Mapping missing 'provider' key: {raw[:80]!r}"
        raise ValueError(msg)
    return data


def mapping_cache_bytes(mapping_data: dict) -> bytes:
    """Canonical byte representation of a parsed mapping for cache keying.

    Both the setup writer and the serve reader compute the cache key from
    this canonical form, so any trailing whitespace or key-order differences
    in the on-disk mapping file do not produce spurious cache misses.
    """
    return json.dumps(mapping_data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def get_provider(name: str, settings: PsiSettings) -> SecretProvider:
    """Instantiate a provider by name from settings."""
    from psi.providers import create_provider

    return create_provider(name, settings)


def open_all_providers(settings: PsiSettings) -> dict[str, SecretProvider]:
    """Create and open all configured providers.

    Providers that fail to open are skipped with a warning — they
    may not be needed for the secrets currently registered.
    """
    from loguru import logger

    providers: dict[str, SecretProvider] = {}
    for name in settings.providers:
        provider = get_provider(name, settings)
        try:
            provider.open()
            providers[name] = provider
            logger.bind(
                event="provider.open",
                provider=name,
                outcome="success",
            ).info("provider opened")
        except Exception as e:
            logger.bind(
                event="provider.open",
                provider=name,
                outcome="error",
                error=str(e),
            ).warning("provider '{}' failed to open: {}", name, e)
    return providers


def close_all_providers(providers: dict[str, SecretProvider]) -> None:
    """Close all open providers."""
    for provider in providers.values():
        provider.close()
