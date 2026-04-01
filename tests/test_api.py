"""Tests for psi.api — InfisicalClient."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import httpx
import pytest

from psi.providers.infisical.api import InfisicalClient

if TYPE_CHECKING:
    from pathlib import Path


def _client(tmp_path: Path) -> InfisicalClient:
    return InfisicalClient("https://infisical.test", tmp_path, token_ttl=300)


class TestInfisicalClientContext:
    def test_context_manager(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            assert client is not None


class TestListSecrets:
    def test_returns_secrets(self, tmp_path: Path) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "secrets": [
                {"secretKey": "DB_HOST", "secretValue": "localhost", "secretPath": "/"},
                {"secretKey": "DB_PORT", "secretValue": "5432", "secretPath": "/"},
            ]
        }
        mock_resp.raise_for_status = MagicMock()

        with _client(tmp_path) as client:
            with patch.object(client._client, "get", return_value=mock_resp):
                secrets = client.list_secrets("tok", "proj", "prod", "/")

        assert len(secrets) == 2
        assert secrets[0]["secretKey"] == "DB_HOST"

    def test_default_non_recursive(self, tmp_path: Path) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"secrets": []}
        mock_resp.raise_for_status = MagicMock()

        with _client(tmp_path) as client:
            with patch.object(client._client, "get", return_value=mock_resp) as mock_get:
                client.list_secrets("tok", "proj", "prod", "/app")

        params = mock_get.call_args.kwargs["params"]
        assert params["recursive"] == "false"

    def test_recursive_true(self, tmp_path: Path) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"secrets": []}
        mock_resp.raise_for_status = MagicMock()

        with _client(tmp_path) as client:
            with patch.object(client._client, "get", return_value=mock_resp) as mock_get:
                client.list_secrets("tok", "proj", "prod", "/app", recursive=True)

        params = mock_get.call_args.kwargs["params"]
        assert params["recursive"] == "true"

    def test_raises_on_error(self, tmp_path: Path) -> None:
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401", request=MagicMock(), response=MagicMock()
        )

        with _client(tmp_path) as client:
            with patch.object(client._client, "get", return_value=mock_resp):
                with pytest.raises(httpx.HTTPStatusError):
                    client.list_secrets("bad-tok", "proj", "prod", "/")


class TestGetSecret:
    def test_returns_value(self, tmp_path: Path) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"secret": {"secretValue": "my-password"}}
        mock_resp.raise_for_status = MagicMock()

        with _client(tmp_path) as client:
            with patch.object(client._client, "get", return_value=mock_resp):
                value = client.get_secret("tok", "proj", "prod", "/", "DB_PASS")

        assert value == "my-password"


class TestIssueCertificate:
    def test_returns_cert_data(self, tmp_path: Path) -> None:
        cert_data = {
            "certificate": "---CERT---",
            "privateKey": "---KEY---",
            "certificateChain": "---CHAIN---",
            "certificateId": "cert-uuid",
            "serialNumber": "AABB",
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"certificate": cert_data}
        mock_resp.raise_for_status = MagicMock()

        with _client(tmp_path) as client:
            with patch.object(client._client, "post", return_value=mock_resp):
                result = client.issue_certificate("tok", "profile", "cn.example.com")

        assert result["certificateId"] == "cert-uuid"
        assert result["privateKey"] == "---KEY---"

    def test_with_optional_params(self, tmp_path: Path) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"certificate": {"certificateId": "c"}}
        mock_resp.raise_for_status = MagicMock()

        with _client(tmp_path) as client:
            with patch.object(client._client, "post", return_value=mock_resp) as mock_post:
                client.issue_certificate(
                    "tok",
                    "profile",
                    "cn",
                    alt_names=[{"type": "dns_name", "value": "*.example.com"}],
                    ttl="90d",
                    key_algorithm="EC_prime256v1",
                )

        call_json = mock_post.call_args.kwargs["json"]
        expected_alt = [{"type": "dns_name", "value": "*.example.com"}]
        assert call_json["attributes"]["altNames"] == expected_alt
        assert call_json["attributes"]["ttl"] == "90d"
        assert call_json["attributes"]["keyAlgorithm"] == "EC_prime256v1"


class TestRenewCertificate:
    def test_returns_renewed(self, tmp_path: Path) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "certificate": {"certificateId": "new-cert", "serialNumber": "EEFF"}
        }
        mock_resp.raise_for_status = MagicMock()

        with _client(tmp_path) as client:
            with patch.object(client._client, "post", return_value=mock_resp) as mock_post:
                result = client.renew_certificate("tok", "old-cert-id")

        assert result["certificateId"] == "new-cert"
        assert "old-cert-id" in mock_post.call_args.kwargs.get("url", "") or "old-cert-id" in str(
            mock_post.call_args
        )
