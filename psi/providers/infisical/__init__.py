"""Infisical provider — fetches secrets from Infisical at lookup time."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from psi.providers.infisical.api import InfisicalClient
from psi.providers.infisical.models import InfisicalConfig, resolve_auth

if TYPE_CHECKING:
    from psi.settings import PsiSettings


class InfisicalProvider:
    """Secret provider that fetches values from Infisical."""

    name = "infisical"

    def __init__(self, settings: PsiSettings) -> None:
        raw = settings.providers.get("infisical", {})
        self.config = InfisicalConfig.model_validate(raw)
        self.state_dir = settings.state_dir
        self._client: InfisicalClient | None = None

    def open(self) -> None:
        self._client = InfisicalClient(
            api_url=self.config.api_url,
            state_dir=self.state_dir,
            token_ttl=self.config.token.ttl,
            verify_ssl=self.config.verify_ssl,
        )

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def lookup(self, mapping_data: dict) -> bytes:
        """Fetch secret value from Infisical using the mapping coordinate.

        Args:
            mapping_data: Dict with keys: project, path, key.

        Returns:
            Secret value as bytes.
        """
        if not self._client:
            msg = "InfisicalProvider not open"
            raise RuntimeError(msg)

        project_alias = mapping_data["project"]
        secret_path = mapping_data["path"]
        secret_name = mapping_data["key"]

        project = self.config.projects.get(project_alias)
        if not project:
            msg = f"Unknown project '{project_alias}'"
            raise ValueError(msg)

        auth = resolve_auth(project, self.config)
        token = self._client.ensure_token(auth)
        value = self._client.get_secret(
            token,
            project.id,
            project.environment,
            secret_path,
            secret_name,
        )
        return value.encode()

    @staticmethod
    def make_mapping(
        project_alias: str,
        secret_path: str,
        secret_name: str,
    ) -> str:
        """Create a JSON mapping string for an Infisical secret."""
        return json.dumps(
            {
                "provider": "infisical",
                "project": project_alias,
                "path": secret_path,
                "key": secret_name,
            }
        )
