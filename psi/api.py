"""Infisical REST API client using sync httpx."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from psi.auth import authenticate
from psi.token import read_cached_token, write_token_cache

if TYPE_CHECKING:
    from psi.models import AuthConfig

_TIMEOUT = 30.0


class InfisicalClient:
    """Synchronous client for the Infisical secrets API."""

    def __init__(
        self,
        api_url: str,
        state_dir: Any,
        token_ttl: int,
        verify_ssl: bool = True,
    ) -> None:
        self.api_url = api_url
        self.state_dir = state_dir
        self.token_ttl = token_ttl
        self._client = httpx.Client(timeout=_TIMEOUT, verify=verify_ssl)

    def close(self) -> None:
        self._client.close()

    @classmethod
    def from_settings(cls, settings: Any) -> InfisicalClient:
        """Create a client from PsiSettings."""
        return cls(
            settings.api_url,
            settings.state_dir,
            settings.token.ttl,
            getattr(settings, "verify_ssl", True),
        )

    def __enter__(self) -> InfisicalClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def ensure_token(self, auth: AuthConfig) -> str:
        """Get a valid token, authenticating if cache is expired."""
        cached = read_cached_token(self.state_dir, auth)
        if cached:
            return cached
        token, expires_in = authenticate(self._client, self.api_url, auth)
        write_token_cache(self.state_dir, auth, token, expires_in, self.token_ttl)
        return token

    def list_secrets(
        self,
        token: str,
        project_id: str,
        environment: str,
        secret_path: str,
    ) -> list[dict[str, Any]]:
        """List all secrets at a path, recursively.

        Returns:
            List of secret objects with secretKey, secretValue, secretPath, etc.
        """
        resp = self._client.get(
            f"{self.api_url}/api/v4/secrets",
            params={
                "projectId": project_id,
                "environment": environment,
                "secretPath": secret_path,
                "recursive": "true",
                "viewSecretValue": "true",
                "expandSecretReferences": "true",
                "includeImports": "true",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        return resp.json()["secrets"]

    def get_secret(
        self,
        token: str,
        project_id: str,
        environment: str,
        secret_path: str,
        secret_name: str,
    ) -> str:
        """Fetch a single secret's value by name and path.

        Returns:
            The secret value as a string.
        """
        resp = self._client.get(
            f"{self.api_url}/api/v4/secrets/{secret_name}",
            params={
                "projectId": project_id,
                "environment": environment,
                "secretPath": secret_path,
                "viewSecretValue": "true",
                "expandSecretReferences": "true",
                "includeImports": "true",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        return resp.json()["secret"]["secretValue"]

    # --- TLS certificate methods ---

    def issue_certificate(
        self,
        token: str,
        profile_id: str,
        common_name: str,
        alt_names: list[dict[str, str]] | None = None,
        ttl: str | None = None,
        key_algorithm: str | None = None,
    ) -> dict[str, Any]:
        """Issue a new certificate from an Infisical PKI profile.

        Returns:
            Certificate object with certificate, privateKey,
            certificateChain, issuingCaCertificate, serialNumber,
            certificateId.
        """
        attributes: dict[str, Any] = {"commonName": common_name}
        if alt_names:
            attributes["altNames"] = alt_names
        if ttl:
            attributes["ttl"] = ttl
        if key_algorithm:
            attributes["keyAlgorithm"] = key_algorithm

        resp = self._client.post(
            f"{self.api_url}/api/v1/cert-manager/certificates",
            json={"profileId": profile_id, "attributes": attributes},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        return resp.json()["certificate"]

    def renew_certificate(
        self,
        token: str,
        certificate_id: str,
    ) -> dict[str, Any]:
        """Renew an existing certificate by ID.

        Returns:
            Renewed certificate object (same structure as issue).
        """
        resp = self._client.post(
            f"{self.api_url}/api/v1/cert-manager/certificates/{certificate_id}/renew",
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        return resp.json()["certificate"]
