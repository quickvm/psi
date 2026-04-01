"""Tests for InfisicalClient write methods (create, batch, update)."""

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


class TestCreateSecret:
    def test_posts_correct_payload(self, tmp_path: Path) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"secret": {"secretKey": "DB_HOST"}}
        mock_resp.raise_for_status = MagicMock()

        with _client(tmp_path) as client:
            with patch.object(client._client, "post", return_value=mock_resp) as mock_post:
                client.create_secret("tok", "proj", "prod", "/app", "DB_HOST", "localhost")

        call_json = mock_post.call_args.kwargs["json"]
        assert call_json["projectId"] == "proj"
        assert call_json["environment"] == "prod"
        assert call_json["secretPath"] == "/app"
        assert call_json["secretValue"] == "localhost"
        assert call_json["type"] == "shared"
        assert "/api/v4/secrets/DB_HOST" in str(mock_post.call_args)

    def test_raises_on_error(self, tmp_path: Path) -> None:
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "409", request=MagicMock(), response=MagicMock()
        )

        with _client(tmp_path) as client:
            with patch.object(client._client, "post", return_value=mock_resp):
                with pytest.raises(httpx.HTTPStatusError):
                    client.create_secret("tok", "proj", "prod", "/", "X", "val")


class TestCreateSecretsBatch:
    def test_posts_batch(self, tmp_path: Path) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"secrets": []}
        mock_resp.raise_for_status = MagicMock()

        secrets = [
            {"secretKey": "A", "secretValue": "1"},
            {"secretKey": "B", "secretValue": "2"},
        ]

        with _client(tmp_path) as client:
            with patch.object(client._client, "post", return_value=mock_resp) as mock_post:
                client.create_secrets_batch("tok", "proj", "prod", "/", secrets)

        call_json = mock_post.call_args.kwargs["json"]
        assert call_json["secrets"] == secrets
        assert "/api/v4/secrets/batch" in str(mock_post.call_args)


class TestUpdateSecret:
    def test_patches_correct_payload(self, tmp_path: Path) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"secret": {"secretKey": "DB_HOST"}}
        mock_resp.raise_for_status = MagicMock()

        with _client(tmp_path) as client:
            with patch.object(client._client, "patch", return_value=mock_resp) as mock_patch:
                client.update_secret("tok", "proj", "prod", "/app", "DB_HOST", "new-host")

        call_json = mock_patch.call_args.kwargs["json"]
        assert call_json["secretValue"] == "new-host"
        assert call_json["projectId"] == "proj"
        assert "/api/v4/secrets/DB_HOST" in str(mock_patch.call_args)
