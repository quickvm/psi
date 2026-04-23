"""PSI exception hierarchy for user-facing errors."""

from __future__ import annotations


class PsiError(Exception):
    """Base for all PSI user-facing errors."""


class ConfigError(PsiError):
    """Invalid or missing configuration."""


class ProviderError(PsiError):
    """Provider failed to initialize or perform an operation."""

    def __init__(self, message: str, *, provider_name: str = "") -> None:
        self.provider_name = provider_name
        super().__init__(message)


class SecretNotFoundError(PsiError):
    """Secret mapping not found in state directory."""


class DriftDetectedError(PsiError):
    """Podman secret state diverged from the fetch — drop-ins are incomplete."""
