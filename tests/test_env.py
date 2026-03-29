"""Tests for the psi env command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from psi.cli import app

runner = CliRunner()


def _fake_settings(projects: dict | None = None):
    """Build a minimal mock PsiSettings."""
    settings = MagicMock()
    settings.api_url = "https://infisical.test"
    settings.state_dir = "/tmp/psi-test"
    settings.token.ttl = 300
    settings.auth = MagicMock()

    if projects is None:
        proj = MagicMock()
        proj.id = "proj-uuid"
        proj.environment = "prod"
        proj.auth = None
        projects = {"myproject": proj}

    settings.projects = projects
    return settings


@pytest.fixture
def mock_infisical():
    """Patch load_settings and InfisicalClient for env command tests."""
    with (
        patch("psi.cli.load_settings") as mock_load,
        patch("psi.api.InfisicalClient", autospec=False) as mock_client_cls,
    ):
        settings = _fake_settings()
        mock_load.return_value = settings

        client_instance = MagicMock()
        client_instance.ensure_token.return_value = "fake-token"
        mock_client_cls.from_settings.return_value = client_instance
        client_instance.__enter__ = MagicMock(return_value=client_instance)
        client_instance.__exit__ = MagicMock(return_value=False)

        yield settings, client_instance


class TestEnvExportFormat:
    """Tests for export format output."""

    def test_basic_secrets(self, mock_infisical):
        _, client = mock_infisical
        client.list_secrets.return_value = [
            {"secretKey": "DB_HOST", "secretValue": "localhost"},
            {"secretKey": "DB_PORT", "secretValue": "5432"},
        ]

        result = runner.invoke(app, ["env", "--project", "myproject"])

        assert result.exit_code == 0
        assert "export DB_HOST='localhost'" in result.output
        assert "export DB_PORT='5432'" in result.output

    def test_single_quote_escaping(self, mock_infisical):
        _, client = mock_infisical
        client.list_secrets.return_value = [
            {"secretKey": "PASSWD", "secretValue": "it's a test"},
        ]

        result = runner.invoke(app, ["env", "--project", "myproject"])

        assert result.exit_code == 0
        assert "export PASSWD='it'\\''s a test'" in result.output

    def test_special_characters(self, mock_infisical):
        _, client = mock_infisical
        client.list_secrets.return_value = [
            {
                "secretKey": "COMPLEX",
                "secretValue": 'has $dollar `backtick` "quotes" & more!',
            },
        ]

        result = runner.invoke(app, ["env", "--project", "myproject"])

        assert result.exit_code == 0
        line = result.output.strip()
        assert line.startswith("export COMPLEX='")
        assert line.endswith("'")
        assert "$dollar" in line
        assert "`backtick`" in line


class TestEnvEnvFormat:
    """Tests for env (KEY=VALUE) format output."""

    def test_basic_secrets(self, mock_infisical):
        _, client = mock_infisical
        client.list_secrets.return_value = [
            {"secretKey": "TOKEN", "secretValue": "abc123"},
        ]

        result = runner.invoke(app, ["env", "--project", "myproject", "--format", "env"])

        assert result.exit_code == 0
        assert "TOKEN=abc123" in result.output
        assert "export" not in result.output


class TestEnvEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_secrets(self, mock_infisical):
        _, client = mock_infisical
        client.list_secrets.return_value = []

        result = runner.invoke(app, ["env", "--project", "myproject"])

        assert result.exit_code == 0
        assert result.output.strip() == ""

    def test_unknown_project(self, mock_infisical):
        result = runner.invoke(app, ["env", "--project", "nonexistent"])

        assert result.exit_code == 1
        assert "Unknown project" in result.output

    def test_environment_override(self, mock_infisical):
        settings, client = mock_infisical
        client.list_secrets.return_value = []

        runner.invoke(
            app,
            [
                "env",
                "--project",
                "myproject",
                "--environment",
                "staging",
            ],
        )

        client.list_secrets.assert_called_once()
        call_args = client.list_secrets.call_args
        assert call_args[0][2] == "staging"

    def test_custom_path(self, mock_infisical):
        _, client = mock_infisical
        client.list_secrets.return_value = []

        runner.invoke(
            app,
            [
                "env",
                "--project",
                "myproject",
                "--path",
                "/pipelines/my-app",
            ],
        )

        client.list_secrets.assert_called_once()
        call_args = client.list_secrets.call_args
        assert call_args[0][3] == "/pipelines/my-app"
