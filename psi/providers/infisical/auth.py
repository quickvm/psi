"""Infisical authentication methods.

Universal auth and AWS IAM go through Infisical's SDK. The SDK has no GCP or Azure login, so
for those PSI fetches the instance's identity token from the cloud's metadata service and
posts it to Infisical's login through the SDK's request layer. Each returns
``(access_token, expires_in_seconds)``.

The SDK signs AWS logins for the region's STS endpoint (``sts.<region>.amazonaws.com``, the
region from ``AWS_REGION`` or the instance metadata), so an AWS identity in Infisical must name
that endpoint as its STS endpoint.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from infisical_sdk.api_types import MachineIdentityLoginResponse

from psi.errors import ProviderError
from psi.providers.infisical.models import AuthConfig, AuthMethod

if TYPE_CHECKING:
    from infisical_sdk import InfisicalSDKClient

# GCP metadata server for identity tokens
_GCP_METADATA_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
)

# Azure IMDS for managed identity tokens
_AZURE_IMDS_URL = "http://169.254.169.254/metadata/identity/oauth2/token"

_METADATA_TIMEOUT = 10.0


def login(sdk: InfisicalSDKClient, auth: AuthConfig) -> tuple[str, int]:
    """Log ``sdk`` in with ``auth``.

    Returns:
        Tuple of (access_token, expires_in_seconds).
    """
    match auth.method:
        case AuthMethod.UNIVERSAL:
            assert auth.client_id is not None and auth.client_secret is not None
            response = sdk.auth.universal_auth.login(
                client_id=auth.client_id, client_secret=auth.client_secret
            )
        case AuthMethod.AWS_IAM:
            assert auth.identity_id is not None
            _require_aws_credentials()
            response = sdk.auth.aws_auth.login(identity_id=auth.identity_id)
        case AuthMethod.GCP:
            response = _metadata_login(sdk, "gcp-auth", auth, _gcp_identity_token(auth))
        case AuthMethod.AZURE:
            response = _metadata_login(sdk, "azure-auth", auth, _azure_identity_token())
    return response.accessToken, int(response.expiresIn)


def _require_aws_credentials() -> None:
    """Fail clearly when AWS has no credentials for the instance.

    Checked before the SDK's login, which (1.0.17) raises botocore's NoCredentialsError with
    a message it does not take, so a missing role surfaces as a TypeError.
    """
    import boto3

    if boto3.Session().get_credentials() is None:
        msg = (
            "No AWS credentials found for aws-iam login. "
            "Ensure the instance has an IAM role or credentials are configured."
        )
        raise ProviderError(msg, provider_name="infisical")


def _metadata_login(
    sdk: InfisicalSDKClient, method: str, auth: AuthConfig, jwt: str
) -> MachineIdentityLoginResponse:
    result = sdk.api.post(
        path=f"/api/v1/auth/{method}/login",
        json={"identityId": auth.identity_id, "jwt": jwt},
        model=MachineIdentityLoginResponse,
    )
    sdk.set_token(result.data.accessToken)
    return result.data


def _metadata(
    url: str, cloud: str, params: dict[str, str], headers: dict[str, str]
) -> httpx.Response:
    """GET ``url`` from a cloud's metadata service, as ProviderError when it fails."""
    try:
        response = httpx.get(url, params=params, headers=headers, timeout=_METADATA_TIMEOUT)
        response.raise_for_status()
    except httpx.HTTPError as e:
        msg = f"Cannot get an identity token from {cloud}'s metadata service at {url}: {e}"
        raise ProviderError(msg, provider_name="infisical") from e
    return response


def _gcp_identity_token(auth: AuthConfig) -> str:
    """The instance's GCP identity token, for Infisical's identity as the audience."""
    assert auth.identity_id is not None
    response = _metadata(
        _GCP_METADATA_URL,
        "GCP",
        params={"audience": auth.identity_id},
        headers={"Metadata-Flavor": "Google"},
    )
    return response.text


def _azure_identity_token() -> str:
    """The instance's Azure managed identity token."""
    response = _metadata(
        _AZURE_IMDS_URL,
        "Azure",
        params={"api-version": "2018-02-01", "resource": "https://management.azure.com/"},
        headers={"Metadata": "true"},
    )
    return response.json()["access_token"]
