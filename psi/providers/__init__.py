"""Provider registry for PSI secret backends."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from psi.provider import SecretProvider
    from psi.settings import PsiSettings


def create_provider(name: str, settings: PsiSettings) -> SecretProvider:
    """Create a provider instance by name."""
    if name == "infisical":
        from psi.providers.infisical import InfisicalProvider

        return InfisicalProvider(settings)
    if name == "nitrokeyhsm":
        from psi.providers.nitrokeyhsm import NitrokeyHSMProvider

        return NitrokeyHSMProvider(settings)
    msg = f"Unknown provider: {name!r}. Available: infisical, nitrokeyhsm"
    raise ValueError(msg)
