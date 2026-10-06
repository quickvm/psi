"""Infisical's API, through Infisical's own Python SDK.

The client keeps PSI's interface, where each call takes a token from PSI's token file cache,
and the SDK makes the requests, retries them and raises their errors. What the SDK does not
cover (batch creates, certificates, GCP and Azure logins) goes through its request layer too
(``InfisicalSDKClient.api``), so every call to Infisical shares one session. That session gets
what the SDK leaves unset: a timeout on every request, and the CA bundle PSI is given.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

import requests
from infisical_sdk import BaseSecret, InfisicalError, InfisicalSDKClient
from infisical_sdk.infisical_requests import APIError
from requests.adapters import HTTPAdapter

from psi.errors import ProviderError
from psi.providers.infisical.auth import login
from psi.providers.infisical.token import read_cached_token, write_token_cache

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence
    from pathlib import Path

    from infisical_sdk.api_types import Import

    from psi.providers.infisical.models import AuthConfig, InfisicalConfig

_TIMEOUT = 30.0


class InfisicalAPIError(ProviderError):
    """Infisical refused a request, or could not be reached (``status_code`` None)."""

    def __init__(self, message: str, status_code: int | None) -> None:
        super().__init__(message, provider_name="infisical")
        self.status_code = status_code


class _Timeout(HTTPAdapter):
    """Gives every request a timeout, which the SDK leaves unset."""

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: bool | str = True,
        cert: Any = None,
        proxies: Mapping[str, str] | None = None,
    ) -> requests.Response:
        return _deliver(
            self,
            request,
            stream=stream,
            timeout=timeout or _TIMEOUT,
            verify=verify,
            cert=cert,
            proxies=proxies,
        )


def _deliver(adapter: HTTPAdapter, request: requests.PreparedRequest, **kwargs: Any) -> Any:
    """Send ``request`` over the network; the tests stand an Infisical in here."""
    return HTTPAdapter.send(adapter, request, **kwargs)


def _imported(imports: Sequence[Import], own: set[str], folder: str) -> list[dict[str, Any]]:
    """The secrets ``imports`` give ``folder`` besides its ``own`` keys, under its path.

    The last import wins, as Infisical's own CLI merges them.
    """
    added: dict[str, dict[str, Any]] = {}
    for imported in reversed(imports):
        for secret in imported.secrets:
            entry = _as_dict(secret)
            key = entry["secretKey"]
            if key not in own and key not in added:
                added[key] = entry | {"secretPath": folder}
    return list(added.values())


def _as_dict(secret: BaseSecret | Mapping[str, Any]) -> dict[str, Any]:
    """A listed secret as a dict.

    The SDK parses a folder's own secrets into ``BaseSecret`` but leaves an import's as the
    dicts the API sent (1.0.17's ``Import`` does not convert them), so both shapes are read.
    """
    return secret.to_dict() if isinstance(secret, BaseSecret) else dict(secret)


def _trust(verify_ssl: bool, ca_cert: Path | None) -> bool | str:
    """What requests verifies Infisical's certificate with.

    requests ignores ``SSL_CERT_FILE``, which PSI's container units set to the CA bundle
    they mount (``ca_cert`` in PSI's config), so it is passed on here.
    """
    if not verify_ssl:
        return False
    if ca_cert is not None:
        return str(ca_cert)
    return os.environ.get("SSL_CERT_FILE") or True


class _Raw:
    """Leaves a response the SDK has no model for as the JSON it was."""

    @staticmethod
    def from_dict(data: dict[str, Any]) -> dict[str, Any]:
        return data


class InfisicalClient:
    """Synchronous client for the Infisical secrets API."""

    def __init__(
        self,
        api_url: str,
        state_dir: Path,
        token_ttl: int,
        verify_ssl: bool = True,
        ca_cert: Path | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.state_dir = state_dir
        self.token_ttl = token_ttl
        # cache_ttl=0: PSI's encrypted cache is the only copy of a value.
        self._sdk = InfisicalSDKClient(host=self.api_url, cache_ttl=0)
        session = self._sdk.api.session
        session.mount("https://", _Timeout())
        session.mount("http://", _Timeout())
        session.verify = _trust(verify_ssl, ca_cert)

    @classmethod
    def for_config(cls, config: InfisicalConfig, state_dir: Path) -> InfisicalClient:
        """A client for the instance ``config`` names, caching tokens in ``state_dir``."""
        return cls(config.api_url, state_dir, config.token.ttl, config.verify_ssl, config.ca_cert)

    def close(self) -> None:
        self._sdk.close()
        self._sdk.api.session.close()

    def __enter__(self) -> InfisicalClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @contextmanager
    def _calling(self, what: str, token: str | None = None) -> Iterator[None]:
        """Run an SDK call, as ``token`` when given, raising :class:`InfisicalAPIError`."""
        if token is not None:
            self._sdk.set_token(token)
        try:
            yield
        except APIError as e:
            said = e.response.get("message") if isinstance(e.response, dict) else None
            detail = f": {said}" if said else ""
            msg = f"Infisical refused to {what} (HTTP {e.status_code}){detail}"
            raise InfisicalAPIError(msg, e.status_code) from e
        except (InfisicalError, requests.RequestException) as e:
            msg = f"Cannot reach Infisical at {self.api_url} to {what}: {e}"
            raise InfisicalAPIError(msg, None) from e

    def ensure_token(self, auth: AuthConfig) -> str:
        """Get a valid token, authenticating if cache is expired."""
        cached = read_cached_token(self.state_dir, auth)
        if cached:
            return cached
        with self._calling(f"log in with {auth.method}"):
            token, expires_in = login(self._sdk, auth)
        write_token_cache(self.state_dir, auth, token, expires_in, self.token_ttl)
        return token

    def list_secrets(
        self,
        token: str,
        project_id: str,
        environment: str,
        secret_path: str,
        *,
        recursive: bool = False,
        imports: bool = False,
    ) -> list[dict[str, Any]]:
        """List secrets at a path.

        Args:
            recursive: If True, include secrets from subfolders.
            imports: If True, also the secrets the folder imports, as Infisical resolves them:
                the folder's own win, and among its imports the last. Each takes the folder's
                path, so a lookup there finds it through the import, as the listing did.

        Returns:
            List of secret objects with secretKey, secretValue, secretPath, etc.

        Raises:
            ValueError: Both ``recursive`` and ``imports``: a recursive listing's imports do
                not say which folder imports each.
        """
        if recursive and imports:
            msg = "a recursive listing cannot take imports: they do not say which folder imports"
            raise ValueError(msg)
        with self._calling(f"list {secret_path}", token):
            listing = self._sdk.secrets.list_secrets(
                environment_slug=environment,
                secret_path=secret_path,
                project_id=project_id,
                expand_secret_references=True,
                view_secret_value=True,
                recursive=recursive,
                include_imports=True,
            )
        own = [secret.to_dict() for secret in listing.secrets]
        if not imports:
            return own
        return own + _imported(listing.imports, {s["secretKey"] for s in own}, secret_path)

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
        with self._calling(f"read {secret_name} at {secret_path}", token):
            secret = self._sdk.secrets.get_secret_by_name(
                secret_name=secret_name,
                environment_slug=environment,
                secret_path=secret_path,
                project_id=project_id,
                expand_secret_references=True,
                include_imports=True,
                view_secret_value=True,
            )
        return secret.secretValue

    # --- Folder methods ---

    def ensure_folder(
        self,
        token: str,
        project_id: str,
        environment: str,
        folder_path: str,
    ) -> None:
        """Create a folder if it does not already exist.

        Splits the path into segments and creates each level.
        For example, /atuin creates folder 'atuin' at path '/'.
        """
        segments = [s for s in folder_path.strip("/").split("/") if s]
        current = "/"
        for segment in segments:
            try:
                with self._calling(f"create folder {segment} in {current}", token):
                    self._sdk.folders.create_folder(
                        name=segment,
                        environment_slug=environment,
                        project_id=project_id,
                        path=current,
                    )
            except InfisicalAPIError as e:
                if e.status_code not in (400, 409):  # 400 and 409: it exists already
                    raise
            current = f"{current}{segment}/" if current.endswith("/") else f"{current}/{segment}/"

    # --- Secret write methods ---

    def create_secret(
        self,
        token: str,
        project_id: str,
        environment: str,
        secret_path: str,
        secret_name: str,
        secret_value: str,
    ) -> dict[str, Any]:
        """Create a single secret in Infisical.

        Returns:
            The created secret object.
        """
        with self._calling(f"create {secret_name} in {secret_path}", token):
            created = self._sdk.secrets.create_secret_by_name(
                secret_name=secret_name,
                secret_path=secret_path,
                environment_slug=environment,
                project_id=project_id,
                secret_value=secret_value,
            )
        return created.to_dict()

    def create_secrets_batch(
        self,
        token: str,
        project_id: str,
        environment: str,
        secret_path: str,
        secrets: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Create multiple secrets in a single request.

        Args:
            secrets: List of dicts with 'secretKey' and 'secretValue'.

        Returns:
            The API response with created secrets.
        """
        body = {
            "projectId": project_id,
            "environment": environment,
            "secretPath": secret_path,
            "secrets": secrets,
        }
        with self._calling(f"create {len(secrets)} secrets in {secret_path}", token):
            return self._sdk.api.post(path="/api/v4/secrets/batch", json=body, model=_Raw).data

    def update_secret(
        self,
        token: str,
        project_id: str,
        environment: str,
        secret_path: str,
        secret_name: str,
        secret_value: str,
    ) -> dict[str, Any]:
        """Update an existing secret's value in Infisical.

        Returns:
            The updated secret object.
        """
        with self._calling(f"update {secret_name} in {secret_path}", token):
            updated = self._sdk.secrets.update_secret_by_name(
                current_secret_name=secret_name,
                project_id=project_id,
                secret_path=secret_path,
                environment_slug=environment,
                secret_value=secret_value,
            )
        return updated.to_dict()

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
        body = {"profileId": profile_id, "attributes": attributes}
        with self._calling(f"issue a certificate for {common_name}", token):
            issued = self._sdk.api.post(
                path="/api/v1/cert-manager/certificates", json=body, model=_Raw
            )
        return issued.data["certificate"]

    def renew_certificate(
        self,
        token: str,
        certificate_id: str,
    ) -> dict[str, Any]:
        """Renew an existing certificate by ID.

        Returns:
            Renewed certificate object (same structure as issue).
        """
        path = f"/api/v1/cert-manager/certificates/{certificate_id}/renew"
        with self._calling(f"renew certificate {certificate_id}", token):
            renewed = self._sdk.api.post(path=path, json=None, model=_Raw)
        return renewed.data["certificate"]
