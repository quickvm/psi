"""Tests for psi.providers.infisical.api — InfisicalClient, through Infisical's SDK."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import requests

from psi.providers.infisical import api
from psi.providers.infisical.api import InfisicalAPIError, InfisicalClient
from psi.providers.infisical.models import AuthConfig, AuthMethod, InfisicalConfig
from tests.fake_infisical import reply

if TYPE_CHECKING:
    from pathlib import Path

    from tests.fake_infisical import FakeInfisical

URL = "https://infisical.test"
APP = ("proj", "prod", "/app")


def _client(tmp_path: Path, *, verify_ssl: bool = True) -> InfisicalClient:
    return InfisicalClient(URL, tmp_path, token_ttl=300, verify_ssl=verify_ssl)


def _universal() -> AuthConfig:
    return AuthConfig(
        method=AuthMethod.UNIVERSAL, client_id="test-client", client_secret="test-secret"
    )


class TestInfisicalClientContext:
    def test_context_manager(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            assert client is not None

    def test_for_config_takes_the_instance_and_its_trust(self, tmp_path: Path) -> None:
        config = InfisicalConfig(api_url=f"{URL}/", ca_cert=tmp_path / "ca.pem")
        with InfisicalClient.for_config(config, tmp_path) as client:
            assert client.api_url == URL
            assert client._sdk.api.session.verify == str(tmp_path / "ca.pem")


class TestTrust:
    def test_verify_ssl_false_turns_verification_off(self, tmp_path: Path) -> None:
        with _client(tmp_path, verify_ssl=False) as client:
            assert client._sdk.api.session.verify is False

    def test_the_container_ca_bundle_is_honoured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSL_CERT_FILE", "/etc/pki/psi/ca.pem")
        with _client(tmp_path) as client:
            assert client._sdk.api.session.verify == "/etc/pki/psi/ca.pem"

    def test_default_is_requests_own_verification(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        with _client(tmp_path) as client:
            assert client._sdk.api.session.verify is True


class TestEnsureToken:
    def test_logs_in_once_and_caches_the_token(
        self, tmp_path: Path, infisical: FakeInfisical
    ) -> None:
        with _client(tmp_path) as client:
            assert client.ensure_token(_universal()) == "access-token-1"
        with _client(tmp_path) as client:
            assert client.ensure_token(_universal()) == "access-token-1"
        logins = [s for s in infisical.sent if s.path.endswith("/universal-auth/login")]
        assert len(logins) == 1
        assert logins[0].body == {"clientId": "test-client", "clientSecret": "test-secret"}

    def test_a_refused_login_says_so_with_its_status(
        self, tmp_path: Path, infisical: FakeInfisical
    ) -> None:
        infisical.client_secret = "rotated"
        with _client(tmp_path) as client, pytest.raises(InfisicalAPIError) as caught:
            client.ensure_token(_universal())
        assert caught.value.status_code == 401
        assert "Infisical refused to log in with universal-auth (HTTP 401)" in str(caught.value)
        assert "test-secret" not in str(caught.value)


class TestListSecrets:
    def test_returns_secrets(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        infisical.folders[APP] = {"DB_HOST": "localhost", "DB_PORT": "5432"}
        with _client(tmp_path) as client:
            secrets = client.list_secrets("access-token-1", *APP)
        assert [(s["secretKey"], s["secretValue"], s["secretPath"]) for s in secrets] == [
            ("DB_HOST", "localhost", "/app"),
            ("DB_PORT", "5432", "/app"),
        ]
        (listing,) = infisical.sent
        assert listing.headers["Authorization"] == "Bearer access-token-1"
        assert listing.params["workspaceId"] == "proj"
        assert listing.params["recursive"] == "false"
        assert listing.params["expandSecretReferences"] == "true"

    def test_recursive_lists_subfolders_with_their_paths(
        self, tmp_path: Path, infisical: FakeInfisical
    ) -> None:
        infisical.folders[APP] = {"A": "1"}
        infisical.folders[("proj", "prod", "/app/db")] = {"B": "2"}
        with _client(tmp_path) as client:
            secrets = client.list_secrets("access-token-1", *APP, recursive=True)
        assert {(s["secretKey"], s["secretPath"]) for s in secrets} == {
            ("A", "/app"),
            ("B", "/app/db"),
        }
        assert infisical.sent[0].params["recursive"] == "true"

    def test_raises_on_error(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        with _client(tmp_path) as client, pytest.raises(InfisicalAPIError) as caught:
            client.list_secrets("access-token-1", *APP)
        assert caught.value.status_code == 404
        assert "Folder not found" in str(caught.value)

    def test_every_request_gets_a_timeout(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        infisical.folders[APP] = {}
        with _client(tmp_path) as client:
            client.list_secrets("access-token-1", *APP)
        assert infisical.sent[0].kwargs["timeout"] == api._TIMEOUT


class TestUnreachable:
    def test_a_connection_error_is_retried_then_reported_without_a_status(
        self, tmp_path: Path, infisical: FakeInfisical, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("infisical_sdk.infisical_requests.time.sleep", lambda _: None)

        def refused(request: requests.PreparedRequest) -> requests.Response:
            raise requests.ConnectionError("connection refused")

        infisical.answers[("GET", "/api/v3/secrets/raw")] = refused
        with _client(tmp_path) as client, pytest.raises(InfisicalAPIError) as caught:
            client.list_secrets("access-token-1", *APP)
        assert caught.value.status_code is None
        assert str(caught.value).startswith(f"Cannot reach Infisical at {URL} to list /app")
        assert len(infisical.sent) > 1


class TestGetSecret:
    def test_returns_value(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        infisical.folders[APP] = {"DB_HOST": "localhost"}
        with _client(tmp_path) as client:
            assert client.get_secret("access-token-1", *APP, "DB_HOST") == "localhost"
        assert infisical.sent[0].path == "/api/v3/secrets/raw/DB_HOST"

    def test_a_missing_secret_is_a_404(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        infisical.folders[APP] = {}
        with _client(tmp_path) as client, pytest.raises(InfisicalAPIError) as caught:
            client.get_secret("access-token-1", *APP, "NOPE")
        assert caught.value.status_code == 404


class TestEnsureFolder:
    def test_creates_each_level_and_skips_the_ones_that_exist(
        self, tmp_path: Path, infisical: FakeInfisical
    ) -> None:
        infisical.folders[("proj", "prod", "/apps")] = {}
        with _client(tmp_path) as client:
            client.ensure_folder("access-token-1", "proj", "prod", "/apps/web")
        assert [(s.body["name"], s.body["path"]) for s in infisical.sent] == [
            ("apps", "/"),
            ("web", "/apps/"),
        ]
        assert ("proj", "prod", "/apps/web") in infisical.folders

    def test_the_root_needs_nothing(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        with _client(tmp_path) as client:
            client.ensure_folder("access-token-1", "proj", "prod", "/")
        assert infisical.sent == []

    def test_other_refusals_are_raised(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        infisical.answers[("POST", "/api/v2/folders")] = lambda request: reply(
            request, 403, {"message": "Forbidden"}
        )
        with _client(tmp_path) as client, pytest.raises(InfisicalAPIError) as caught:
            client.ensure_folder("access-token-1", "proj", "prod", "/apps")
        assert caught.value.status_code == 403


class TestIssueCertificate:
    def test_returns_cert_data(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        with _client(tmp_path) as client:
            cert = client.issue_certificate("access-token-1", "profile-1", "web.internal")
        assert cert["certificateId"] == "cert-1"
        (sent,) = infisical.sent
        assert sent.path == "/api/v1/cert-manager/certificates"
        assert sent.body == {"profileId": "profile-1", "attributes": {"commonName": "web.internal"}}

    def test_with_optional_params(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        alt_names = [{"type": "dns", "value": "www.internal"}]
        with _client(tmp_path) as client:
            client.issue_certificate(
                "access-token-1",
                "profile-1",
                "web.internal",
                alt_names=alt_names,
                ttl="30d",
                key_algorithm="EC_prime256v1",
            )
        assert infisical.sent[0].body["attributes"] == {
            "commonName": "web.internal",
            "altNames": alt_names,
            "ttl": "30d",
            "keyAlgorithm": "EC_prime256v1",
        }


class TestRenewCertificate:
    def test_returns_renewed(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        with _client(tmp_path) as client:
            cert = client.renew_certificate("access-token-1", "cert-9")
        assert cert["certificateId"] == "cert-9"
        assert infisical.sent[0].path == "/api/v1/cert-manager/certificates/cert-9/renew"
