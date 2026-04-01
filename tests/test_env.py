"""Tests for the psi infisical env command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from psi.cli import app

runner = CliRunner()


def _fake_settings():
    """Build a minimal mock PsiSettings."""
    settings = MagicMock()
    settings.state_dir = "/tmp/psi-test"
    settings.providers = {
        "infisical": {
            "api_url": "https://infisical.test",
            "auth": {
                "method": "universal-auth",
                "client_id": "cid",
                "client_secret": "csec",
            },
            "token": {"ttl": 300},
            "projects": {
                "myproject": {"id": "proj-uuid", "environment": "prod"},
            },
        },
    }
    return settings


@pytest.fixture
def mock_infisical():
    """Patch load_settings and InfisicalClient for env command tests."""
    with (
        patch(
            "psi.providers.infisical.cli.load_settings",
        ) as mock_load,
        patch(
            "psi.providers.infisical.api.InfisicalClient",
            autospec=False,
        ) as mock_client_cls,
    ):
        settings = _fake_settings()
        mock_load.return_value = settings

        client_instance = MagicMock()
        client_instance.ensure_token.return_value = "fake-token"
        mock_client_cls.return_value = client_instance

        yield settings, client_instance


class TestEnvExportFormat:
    def test_basic_secrets(self, mock_infisical):
        _, client = mock_infisical
        client.list_secrets.return_value = [
            {"secretKey": "DB_HOST", "secretValue": "localhost"},
            {"secretKey": "DB_PORT", "secretValue": "5432"},
        ]

        result = runner.invoke(
            app,
            ["infisical", "env", "--project", "myproject"],
        )

        assert result.exit_code == 0
        assert "export DB_HOST='localhost'" in result.output
        assert "export DB_PORT='5432'" in result.output

    def test_single_quote_escaping(self, mock_infisical):
        _, client = mock_infisical
        client.list_secrets.return_value = [
            {"secretKey": "PASSWD", "secretValue": "it's a test"},
        ]

        result = runner.invoke(
            app,
            ["infisical", "env", "--project", "myproject"],
        )

        assert result.exit_code == 0
        assert "export PASSWD='it'\\''s a test'" in result.output


class TestEnvEnvFormat:
    def test_basic_secrets(self, mock_infisical):
        _, client = mock_infisical
        client.list_secrets.return_value = [
            {"secretKey": "TOKEN", "secretValue": "abc123"},
        ]

        result = runner.invoke(
            app,
            ["infisical", "env", "--project", "myproject", "--format", "env"],
        )

        assert result.exit_code == 0
        assert "TOKEN=abc123" in result.output
        assert "export" not in result.output


class TestEnvEdgeCases:
    def test_empty_secrets(self, mock_infisical):
        _, client = mock_infisical
        client.list_secrets.return_value = []

        result = runner.invoke(
            app,
            ["infisical", "env", "--project", "myproject"],
        )

        assert result.exit_code == 0
        assert result.output.strip() == ""

    def test_unknown_project(self, mock_infisical):
        result = runner.invoke(
            app,
            ["infisical", "env", "--project", "nonexistent"],
        )

        assert result.exit_code == 1
        assert "Unknown project" in result.output
