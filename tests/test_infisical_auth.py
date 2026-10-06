"""Tests for psi.providers.infisical.auth — every login, through the client."""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

import httpx
import pytest

from psi.errors import ProviderError
from psi.providers.infisical import auth as auth_module
from psi.providers.infisical.api import InfisicalAPIError, InfisicalClient
from psi.providers.infisical.models import AuthConfig, AuthMethod

if TYPE_CHECKING:
    from pathlib import Path

    from tests.fake_infisical import FakeInfisical


def _client(tmp_path: Path) -> InfisicalClient:
    return InfisicalClient("https://infisical.test", tmp_path, token_ttl=300)


class TestUniversalAuth:
    def test_returns_the_token(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        auth = AuthConfig(
            method=AuthMethod.UNIVERSAL, client_id="test-client", client_secret="test-secret"
        )
        with _client(tmp_path) as client:
            assert client.ensure_token(auth) == "access-token-1"


class TestClientSecretFile:
    def test_the_file_logs_in_as_the_secret_would(
        self, tmp_path: Path, infisical: FakeInfisical
    ) -> None:
        (tmp_path / "client-secret").write_text("test-secret\n")
        auth = AuthConfig(
            method=AuthMethod.UNIVERSAL,
            client_id="test-client",
            client_secret_file=tmp_path / "client-secret",
        )
        with _client(tmp_path) as client:
            assert client.ensure_token(auth) == "access-token-1"
        assert infisical.sent[0].body == {"clientId": "test-client", "clientSecret": "test-secret"}


class TestAwsIam:
    def test_signs_for_the_regions_sts_endpoint(
        self, tmp_path: Path, infisical: FakeInfisical, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "not-a-real-secret")
        monkeypatch.setenv("AWS_REGION", "us-east-2")
        auth = AuthConfig(method=AuthMethod.AWS_IAM, identity_id="test-identity")
        with _client(tmp_path) as client:
            assert client.ensure_token(auth) == "access-token-1"
        (login,) = infisical.sent
        assert login.path == "/api/v1/auth/aws-auth/login"
        headers = json.loads(base64.b64decode(login.body["iamRequestHeaders"]))
        assert headers["Host"] == "sts.us-east-2.amazonaws.com"
        assert "Authorization" in headers

    def test_no_aws_credentials_is_a_provider_error(
        self, tmp_path: Path, infisical: FakeInfisical, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv("AWS_PROFILE", raising=False)
        monkeypatch.setenv("AWS_REGION", "us-east-2")
        monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
        monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "none"))
        monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
        auth = AuthConfig(method=AuthMethod.AWS_IAM, identity_id="test-identity")
        with _client(tmp_path) as client, pytest.raises(ProviderError, match="credentials"):
            client.ensure_token(auth)
        assert infisical.sent == []


def _metadata(monkeypatch: pytest.MonkeyPatch, response: httpx.Response) -> list[httpx.Request]:
    """Answer the cloud metadata service's GET with ``response``, recording the requests."""
    asked: list[httpx.Request] = []

    def get(
        url: str, *, params: dict[str, str], headers: dict[str, str], timeout: float
    ) -> httpx.Response:
        request = httpx.Request("GET", url, params=params, headers=headers)
        asked.append(request)
        response.request = request
        return response

    monkeypatch.setattr(auth_module.httpx, "get", get)
    return asked


class TestGcp:
    def test_sends_the_metadata_token_to_infisical(
        self, tmp_path: Path, infisical: FakeInfisical, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = _metadata(monkeypatch, httpx.Response(200, text="gcp-jwt"))
        auth = AuthConfig(method=AuthMethod.GCP, identity_id="test-identity")
        with _client(tmp_path) as client:
            assert client.ensure_token(auth) == "access-token-1"
        (request,) = asked
        assert request.url.params["audience"] == "test-identity"
        assert request.headers["Metadata-Flavor"] == "Google"
        (login,) = infisical.sent
        assert login.path == "/api/v1/auth/gcp-auth/login"
        assert login.body == {"identityId": "test-identity", "jwt": "gcp-jwt"}

    def test_a_failing_metadata_service_is_a_provider_error(
        self, tmp_path: Path, infisical: FakeInfisical, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _metadata(monkeypatch, httpx.Response(503, text="unavailable"))
        auth = AuthConfig(method=AuthMethod.GCP, identity_id="test-identity")
        with (
            _client(tmp_path) as client,
            pytest.raises(ProviderError, match="from GCP's metadata service"),
        ):
            client.ensure_token(auth)
        assert infisical.sent == []


class TestAzure:
    def test_sends_the_managed_identity_token_to_infisical(
        self, tmp_path: Path, infisical: FakeInfisical, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = _metadata(monkeypatch, httpx.Response(200, json={"access_token": "azure-jwt"}))
        auth = AuthConfig(method=AuthMethod.AZURE, identity_id="test-identity")
        with _client(tmp_path) as client:
            assert client.ensure_token(auth) == "access-token-1"
        assert asked[0].headers["Metadata"] == "true"
        assert infisical.sent[0].body == {"identityId": "test-identity", "jwt": "azure-jwt"}

    def test_an_identity_infisical_does_not_know_is_refused(
        self, tmp_path: Path, infisical: FakeInfisical, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _metadata(monkeypatch, httpx.Response(200, json={"access_token": "azure-jwt"}))
        auth = AuthConfig(method=AuthMethod.AZURE, identity_id="someone-else")
        with _client(tmp_path) as client, pytest.raises(InfisicalAPIError) as caught:
            client.ensure_token(auth)
        assert caught.value.status_code == 401
