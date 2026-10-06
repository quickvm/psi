"""Tests for InfisicalClient's writes, through Infisical's SDK."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from psi.providers.infisical.api import InfisicalAPIError, InfisicalClient

if TYPE_CHECKING:
    from pathlib import Path

    from tests.fake_infisical import FakeInfisical

APP = ("proj", "prod", "/app")


def _client(tmp_path: Path) -> InfisicalClient:
    return InfisicalClient("https://infisical.test", tmp_path, token_ttl=300)


class TestCreateSecret:
    def test_creates_the_secret(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        with _client(tmp_path) as client:
            created = client.create_secret("access-token-1", *APP, "DB_HOST", "localhost")
        assert created["secretKey"] == "DB_HOST"
        assert infisical.folders[APP] == {"DB_HOST": "localhost"}
        (sent,) = infisical.sent
        assert (sent.method, sent.path) == ("POST", "/api/v3/secrets/raw/DB_HOST")
        assert sent.body["workspaceId"] == "proj"
        assert sent.body["type"] == "shared"

    def test_raises_on_error(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        with _client(tmp_path) as client, pytest.raises(InfisicalAPIError) as caught:
            client.create_secret("a-stale-token", *APP, "DB_HOST", "localhost")
        assert caught.value.status_code == 401


class TestCreateSecretsBatch:
    def test_posts_batch(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        batch = [
            {"secretKey": "A", "secretValue": "1"},
            {"secretKey": "B", "secretValue": "2"},
        ]
        with _client(tmp_path) as client:
            result = client.create_secrets_batch("access-token-1", *APP, batch)
        assert [s["secretKey"] for s in result["secrets"]] == ["A", "B"]
        assert infisical.folders[APP] == {"A": "1", "B": "2"}
        (sent,) = infisical.sent
        assert sent.path == "/api/v4/secrets/batch"
        assert sent.body == {
            "projectId": "proj",
            "environment": "prod",
            "secretPath": "/app",
            "secrets": batch,
        }


class TestUpdateSecret:
    def test_updates_the_value(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        infisical.folders[APP] = {"DB_HOST": "old-host"}
        with _client(tmp_path) as client:
            client.update_secret("access-token-1", *APP, "DB_HOST", "new-host")
        assert infisical.folders[APP] == {"DB_HOST": "new-host"}
        assert (infisical.sent[0].method, infisical.sent[0].path) == (
            "PATCH",
            "/api/v3/secrets/raw/DB_HOST",
        )

    def test_a_missing_secret_is_a_404(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        infisical.folders[APP] = {}
        with _client(tmp_path) as client, pytest.raises(InfisicalAPIError) as caught:
            client.update_secret("access-token-1", *APP, "DB_HOST", "new-host")
        assert caught.value.status_code == 404
