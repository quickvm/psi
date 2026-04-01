"""Infisical authentication methods.

Each method hits POST /api/v1/auth/{method}/login and returns
(access_token, expires_in_seconds).
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

from psi.providers.infisical.models import AuthConfig, AuthMethod

if TYPE_CHECKING:
    import httpx

# STS endpoint for AWS IAM auth — global endpoint works from any region
_AWS_STS_ENDPOINT = "https://sts.amazonaws.com"
_AWS_STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15"

# GCP metadata server for identity tokens
_GCP_METADATA_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
)

# Azure IMDS for managed identity tokens
_AZURE_IMDS_URL = "http://169.254.169.254/metadata/identity/oauth2/token"


def authenticate(
    client: httpx.Client,
    api_url: str,
    auth: AuthConfig,
) -> tuple[str, int]:
    """Dispatch to the correct auth method.

    Returns:
        Tuple of (access_token, expires_in_seconds).
    """
    match auth.method:
        case AuthMethod.UNIVERSAL:
            return _universal_login(client, api_url, auth)
        case AuthMethod.AWS_IAM:
            return _aws_iam_login(client, api_url, auth)
        case AuthMethod.GCP:
            return _gcp_login(client, api_url, auth)
        case AuthMethod.AZURE:
            return _azure_login(client, api_url, auth)


def _parse_token_response(response: httpx.Response) -> tuple[str, int]:
    """Extract access token and expiry from Infisical auth response."""
    response.raise_for_status()
    data = response.json()
    return data["accessToken"], int(data["expiresIn"])


def _universal_login(
    client: httpx.Client,
    api_url: str,
    auth: AuthConfig,
) -> tuple[str, int]:
    resp = client.post(
        f"{api_url}/api/v1/auth/universal-auth/login",
        json={
            "clientId": auth.client_id,
            "clientSecret": auth.client_secret,
        },
    )
    return _parse_token_response(resp)


def _aws_iam_login(
    client: httpx.Client,
    api_url: str,
    auth: AuthConfig,
) -> tuple[str, int]:
    """Sign an STS GetCallerIdentity request and send to Infisical."""
    from botocore.auth import (
        SigV4Auth,
    )
    from botocore.awsrequest import AWSRequest
    from botocore.session import Session

    session = Session()
    credentials = session.get_credentials()
    if credentials is None:
        msg = (
            "No AWS credentials found. "
            "Ensure the instance has an IAM role or credentials are configured."
        )
        raise RuntimeError(msg)
    credentials = credentials.get_frozen_credentials()

    request = AWSRequest(
        method="POST",
        url=_AWS_STS_ENDPOINT,
        data=_AWS_STS_BODY,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "sts.amazonaws.com",
        },
    )
    SigV4Auth(credentials, "sts", "us-east-1").add_auth(request)

    encoded_headers = base64.b64encode(json.dumps(dict(request.headers)).encode()).decode()
    encoded_body = base64.b64encode(_AWS_STS_BODY.encode()).decode()

    resp = client.post(
        f"{api_url}/api/v1/auth/aws-auth/login",
        json={
            "identityId": auth.identity_id,
            "iamHttpRequestMethod": "POST",
            "iamRequestUrl": base64.b64encode(_AWS_STS_ENDPOINT.encode()).decode(),
            "iamRequestBody": encoded_body,
            "iamRequestHeaders": encoded_headers,
        },
    )
    return _parse_token_response(resp)


def _gcp_login(
    client: httpx.Client,
    api_url: str,
    auth: AuthConfig,
) -> tuple[str, int]:
    """Fetch a GCP identity token from the metadata server."""
    jwt_resp = client.get(
        _GCP_METADATA_URL,
        params={"audience": auth.identity_id},
        headers={"Metadata-Flavor": "Google"},
    )
    jwt_resp.raise_for_status()
    jwt_token = jwt_resp.text

    resp = client.post(
        f"{api_url}/api/v1/auth/gcp-auth/login",
        json={
            "identityId": auth.identity_id,
            "jwt": jwt_token,
        },
    )
    return _parse_token_response(resp)


def _azure_login(
    client: httpx.Client,
    api_url: str,
    auth: AuthConfig,
) -> tuple[str, int]:
    """Fetch an Azure managed identity token from IMDS."""
    jwt_resp = client.get(
        _AZURE_IMDS_URL,
        params={
            "api-version": "2018-02-01",
            "resource": "https://management.azure.com/",
        },
        headers={"Metadata": "true"},
    )
    jwt_resp.raise_for_status()
    jwt_token = jwt_resp.json()["access_token"]

    resp = client.post(
        f"{api_url}/api/v1/auth/azure-auth/login",
        json={
            "identityId": auth.identity_id,
            "jwt": jwt_token,
        },
    )
    return _parse_token_response(resp)
