"""Tests for psi.importer — source readers and import orchestration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

from psi.providers.infisical.importer import (
    read_env_file,
    read_podman_secrets,
    read_quadlet,
    run_import,
)
from psi.providers.infisical.models import ConflictPolicy, ImportOutcome

if TYPE_CHECKING:
    from pathlib import Path


def _mock_podman_api_get(responses: dict[str, Any]) -> Any:
    """Create a mock for _podman_api_get that returns different responses per path."""

    def _get(path: str, params: dict[str, str] | None = None) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.json.return_value = responses.get(path, [])
        return mock_resp

    return _get


class TestReadEnvFile:
    def test_basic_parsing(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("DB_HOST=localhost\nDB_PORT=5432\n")
        secrets = read_env_file(env_file)
        assert len(secrets) == 2
        assert secrets[0].key == "DB_HOST"
        assert secrets[0].value == "localhost"
        assert secrets[1].key == "DB_PORT"
        assert secrets[1].value == "5432"

    def test_skips_comments_and_blanks(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("# comment\n\nDB_HOST=localhost\n  \n")
        secrets = read_env_file(env_file)
        assert len(secrets) == 1
        assert secrets[0].key == "DB_HOST"

    def test_strips_quotes(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("A='single'\nB=\"double\"\nC=none\n")
        secrets = read_env_file(env_file)
        assert secrets[0].value == "single"
        assert secrets[1].value == "double"
        assert secrets[2].value == "none"

    def test_handles_export_prefix(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("export KEY=value\n")
        secrets = read_env_file(env_file)
        assert len(secrets) == 1
        assert secrets[0].key == "KEY"
        assert secrets[0].value == "value"

    def test_equals_in_value(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("URL=postgres://host:5432/db?ssl=true\n")
        secrets = read_env_file(env_file)
        assert secrets[0].value == "postgres://host:5432/db?ssl=true"

    def test_empty_value(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("EMPTY=\n")
        secrets = read_env_file(env_file)
        assert secrets[0].value == ""

    def test_skips_lines_without_equals(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("NOEQUALSSIGN\nGOOD=val\n")
        secrets = read_env_file(env_file)
        assert len(secrets) == 1
        assert secrets[0].key == "GOOD"


class TestReadPodmanSecrets:
    def test_reads_specific_secrets(self) -> None:
        mock_get = _mock_podman_api_get(
            {
                "/libpod/secrets/DB_PASS/json": {"SecretData": "my-password"},
            }
        )
        with patch("psi.providers.infisical.importer._podman_api_get", side_effect=mock_get):
            secrets = read_podman_secrets(["DB_PASS"])

        assert len(secrets) == 1
        assert secrets[0].key == "DB_PASS"
        assert secrets[0].value == "my-password"

    def test_reads_all_secrets(self) -> None:
        mock_get = _mock_podman_api_get(
            {
                "/libpod/secrets/json": [
                    {"Spec": {"Name": "SECRET_A"}},
                    {"Spec": {"Name": "SECRET_B"}},
                ],
                "/libpod/secrets/SECRET_A/json": {"SecretData": "val-a"},
                "/libpod/secrets/SECRET_B/json": {"SecretData": "val-b"},
            }
        )
        with patch("psi.providers.infisical.importer._podman_api_get", side_effect=mock_get):
            secrets = read_podman_secrets(None)

        assert len(secrets) == 2
        assert secrets[0].key == "SECRET_A"
        assert secrets[1].key == "SECRET_B"


class TestReadQuadlet:
    def test_parses_environment_directive(self, tmp_path: Path) -> None:
        container = tmp_path / "app.container"
        container.write_text("[Container]\nEnvironment=DB_HOST=localhost DB_PORT=5432\n")
        secrets = read_quadlet([container])
        assert len(secrets) == 2
        assert secrets[0].key == "DB_HOST"
        assert secrets[0].value == "localhost"

    def test_parses_quoted_environment(self, tmp_path: Path) -> None:
        container = tmp_path / "app.container"
        container.write_text('[Container]\nEnvironment=DB_HOST=localhost "DB_NAME=my database"\n')
        secrets = read_quadlet([container])
        assert len(secrets) == 2
        assert secrets[1].key == "DB_NAME"
        assert secrets[1].value == "my database"

    def test_skips_secret_refs_by_default(self, tmp_path: Path) -> None:
        container = tmp_path / "app.container"
        container.write_text("[Container]\nSecret=DB_PASS,type=env,target=DATABASE_PASSWORD\n")
        secrets = read_quadlet([container])
        assert len(secrets) == 0

    def test_resolves_secret_refs(self, tmp_path: Path) -> None:
        container = tmp_path / "app.container"
        container.write_text("[Container]\nSecret=DB_PASS,type=env,target=DATABASE_PASSWORD\n")
        mock_get = _mock_podman_api_get(
            {
                "/libpod/secrets/DB_PASS/json": {"SecretData": "s3cret"},
            }
        )
        with patch("psi.providers.infisical.importer._podman_api_get", side_effect=mock_get):
            secrets = read_quadlet([container], resolve_secrets=True)

        assert len(secrets) == 1
        assert secrets[0].key == "DATABASE_PASSWORD"
        assert secrets[0].value == "s3cret"

    def test_multiple_files(self, tmp_path: Path) -> None:
        f1 = tmp_path / "a.container"
        f1.write_text("[Container]\nEnvironment=A=1\n")
        f2 = tmp_path / "b.container"
        f2.write_text("[Container]\nEnvironment=B=2\n")
        secrets = read_quadlet([f1, f2])
        assert len(secrets) == 2
        keys = {s.key for s in secrets}
        assert keys == {"A", "B"}

    def test_deduplicates_across_files(self, tmp_path: Path) -> None:
        f1 = tmp_path / "app.container"
        f1.write_text("[Container]\nEnvironment=DB_HOST=localhost\n")
        f2 = tmp_path / "worker.container"
        f2.write_text("[Container]\nEnvironment=DB_HOST=localhost\n")
        secrets = read_quadlet([f1, f2])
        assert len(secrets) == 1
        assert secrets[0].key == "DB_HOST"

    def test_deduplicates_resolved_secrets(self, tmp_path: Path) -> None:
        f1 = tmp_path / "app.container"
        f1.write_text("[Container]\nSecret=DB_PASS,type=env,target=PASSWORD\n")
        f2 = tmp_path / "worker.container"
        f2.write_text("[Container]\nSecret=DB_PASS,type=env,target=PASSWORD\n")
        mock_get = _mock_podman_api_get(
            {
                "/libpod/secrets/DB_PASS/json": {"SecretData": "s3cret"},
            }
        )
        with patch("psi.providers.infisical.importer._podman_api_get", side_effect=mock_get):
            secrets = read_quadlet([f1, f2], resolve_secrets=True)
        assert len(secrets) == 1
        assert secrets[0].key == "PASSWORD"


def _mock_client() -> Any:
    """Create a mock InfisicalClient."""
    client = MagicMock()
    client.list_secrets.return_value = []
    client.create_secrets_batch.return_value = {"secrets": []}
    return client


class TestRunImport:
    def test_dry_run_all_new(self) -> None:
        from psi.providers.infisical.models import ImportSecret

        secrets = [ImportSecret(key="A", value="1"), ImportSecret(key="B", value="2")]
        result = run_import(
            _mock_client(),
            "tok",
            "proj",
            "prod",
            "/",
            secrets,
            dry_run=True,
        )
        assert result.total == 2
        assert result.created == 2
        assert all(s.outcome == ImportOutcome.DRY_RUN for s in result.secrets)
        assert all("would create" in s.detail for s in result.secrets)

    def test_dry_run_with_existing(self) -> None:
        from psi.providers.infisical.models import ImportSecret

        client = _mock_client()
        client.list_secrets.return_value = [{"secretKey": "A"}]
        secrets = [ImportSecret(key="A", value="1"), ImportSecret(key="B", value="2")]
        result = run_import(
            client,
            "tok",
            "proj",
            "prod",
            "/",
            secrets,
            conflict=ConflictPolicy.SKIP,
            dry_run=True,
        )
        assert result.total == 2
        assert result.created == 1
        assert result.skipped == 1
        details = {s.key: s.detail for s in result.secrets}
        assert "would create" in details["B"]
        assert "would skip" in details["A"]

    def test_creates_new_secrets(self) -> None:
        from psi.providers.infisical.models import ImportSecret

        client = _mock_client()
        secrets = [ImportSecret(key="NEW", value="val")]
        result = run_import(client, "tok", "proj", "prod", "/", secrets)
        assert result.created == 1
        client.create_secrets_batch.assert_called_once()

    def test_conflict_skip(self) -> None:
        from psi.providers.infisical.models import ImportSecret

        client = _mock_client()
        client.list_secrets.return_value = [{"secretKey": "EXISTING"}]
        secrets = [ImportSecret(key="EXISTING", value="new")]
        result = run_import(
            client,
            "tok",
            "proj",
            "prod",
            "/",
            secrets,
            conflict=ConflictPolicy.SKIP,
        )
        assert result.skipped == 1
        assert result.created == 0

    def test_conflict_fail(self) -> None:
        from psi.providers.infisical.models import ImportSecret

        client = _mock_client()
        client.list_secrets.return_value = [{"secretKey": "EXISTING"}]
        secrets = [ImportSecret(key="EXISTING", value="new")]
        result = run_import(
            client,
            "tok",
            "proj",
            "prod",
            "/",
            secrets,
            conflict=ConflictPolicy.FAIL,
        )
        assert result.failed == 1

    def test_conflict_overwrite(self) -> None:
        from psi.providers.infisical.models import ImportSecret

        client = _mock_client()
        client.list_secrets.return_value = [{"secretKey": "EXISTING"}]
        secrets = [ImportSecret(key="EXISTING", value="updated")]
        result = run_import(
            client,
            "tok",
            "proj",
            "prod",
            "/",
            secrets,
            conflict=ConflictPolicy.OVERWRITE,
        )
        assert result.overwritten == 1
        client.update_secret.assert_called_once_with(
            "tok",
            "proj",
            "prod",
            "/",
            "EXISTING",
            "updated",
        )

    def test_mixed_new_and_existing(self) -> None:
        from psi.providers.infisical.models import ImportSecret

        client = _mock_client()
        client.list_secrets.return_value = [{"secretKey": "OLD"}]
        secrets = [
            ImportSecret(key="OLD", value="updated"),
            ImportSecret(key="NEW", value="fresh"),
        ]
        result = run_import(
            client,
            "tok",
            "proj",
            "prod",
            "/",
            secrets,
            conflict=ConflictPolicy.SKIP,
        )
        assert result.created == 1
        assert result.skipped == 1
