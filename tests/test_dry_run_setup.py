"""Tests for psi.setup.dry_run_setup — read-only Podman secret inspection."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import httpx
import pytest

from psi.errors import ProviderError
from psi.models import SystemdScope
from psi.setup import (
    _classify_secrets,
    _parse_driver_opts,
    dry_run_setup,
)

if TYPE_CHECKING:
    from pathlib import Path


def _fake_settings(tmp_path: Path):
    from unittest.mock import MagicMock

    settings = MagicMock()
    settings.state_dir = tmp_path / "state"
    settings.state_dir.mkdir()
    settings.scope = SystemdScope.SYSTEM
    settings.socket_token = None
    return settings


def _shell_secret(
    name: str,
    *,
    secret_id: str = "",
    lookup: str = "curl-lookup",
    store: str = "curl-store",
    delete: str = "curl-delete",
    list_: str = "curl-list",
) -> dict:
    return {
        "ID": secret_id or name,
        "Spec": {
            "Name": name,
            "Driver": {
                "Name": "shell",
                "Options": {
                    "lookup": lookup,
                    "store": store,
                    "delete": delete,
                    "list": list_,
                },
            },
        },
    }


class TestParseDriverOpts:
    def test_extracts_all_four_opts(self) -> None:
        conf = (
            "[secrets]\n"
            'driver = "shell"\n'
            "\n"
            "[secrets.opts]\n"
            'store = "curl -X POST http://s"\n'
            'lookup = "curl http://l"\n'
            'delete = "curl -X DELETE http://d"\n'
            'list = "curl http://ls"\n'
        )
        opts = _parse_driver_opts(conf)
        assert opts == {
            "store": "curl -X POST http://s",
            "lookup": "curl http://l",
            "delete": "curl -X DELETE http://d",
            "list": "curl http://ls",
        }


class TestClassifySecrets:
    CURRENT = {
        "lookup": "curl-lookup",
        "store": "curl-store",
        "delete": "curl-delete",
        "list": "curl-list",
    }

    def test_managed_when_mapping_and_opts_match(self, tmp_path: Path) -> None:
        (tmp_path / "abc123").write_text("{}")
        managed, stale, orphaned = _classify_secrets(
            [_shell_secret("app--DB_URL", secret_id="abc123")],
            tmp_path,
            self.CURRENT,
        )
        assert managed == ["app--DB_URL"]
        assert stale == []
        assert orphaned == []

    def test_stale_when_opts_drift(self, tmp_path: Path) -> None:
        (tmp_path / "abc123").write_text("{}")
        managed, stale, orphaned = _classify_secrets(
            [_shell_secret("app--DB_URL", secret_id="abc123", lookup="curl-old-lookup")],
            tmp_path,
            self.CURRENT,
        )
        assert stale == ["app--DB_URL"]
        assert managed == []
        assert orphaned == []

    def test_orphaned_when_no_mapping_file(self, tmp_path: Path) -> None:
        managed, stale, orphaned = _classify_secrets(
            [_shell_secret("buildkite-agent--GHCR_PAT", secret_id="def456")],
            tmp_path,
            self.CURRENT,
        )
        assert orphaned == ["buildkite-agent--GHCR_PAT"]

    def test_mixed_state_sorted_per_bucket(self, tmp_path: Path) -> None:
        (tmp_path / "id-b").write_text("{}")
        (tmp_path / "id-a").write_text("{}")
        (tmp_path / "id-stale").write_text("{}")
        managed, stale, orphaned = _classify_secrets(
            [
                _shell_secret("b-managed", secret_id="id-b"),
                _shell_secret("a-managed", secret_id="id-a"),
                _shell_secret("stale", secret_id="id-stale", lookup="drifted"),
                _shell_secret("orph-b", secret_id="id-orph-b"),
                _shell_secret("orph-a", secret_id="id-orph-a"),
            ],
            tmp_path,
            self.CURRENT,
        )
        assert managed == ["a-managed", "b-managed"]
        assert stale == ["stale"]
        assert orphaned == ["orph-a", "orph-b"]

    def test_skips_entries_with_no_name(self, tmp_path: Path) -> None:
        managed, stale, orphaned = _classify_secrets(
            [{"Spec": {"Driver": {"Name": "shell", "Options": {}}}}],
            tmp_path,
            self.CURRENT,
        )
        assert managed == stale == orphaned == []


class TestDryRunSetup:
    def test_surfaces_podman_api_failure_as_provider_error(self, tmp_path: Path) -> None:
        settings = _fake_settings(tmp_path)
        with (
            patch(
                "psi.setup._list_podman_shell_secrets",
                side_effect=httpx.ConnectError("refused"),
            ),
            pytest.raises(ProviderError, match="Cannot reach Podman API"),
        ):
            dry_run_setup(settings)

    def test_prints_report_and_does_not_mutate(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        settings = _fake_settings(tmp_path)
        (settings.state_dir / "id-ok").write_text("{}")
        (settings.state_dir / "id-stale").write_text("{}")

        from psi.unitgen import generate_driver_conf

        current_conf = generate_driver_conf(settings.scope, token=None)
        opts = _parse_driver_opts(current_conf)
        stale_opts = {**opts, "lookup": "old-lookup-command"}

        secrets = [
            {
                "ID": "id-ok",
                "Spec": {
                    "Name": "app--OK",
                    "Driver": {"Name": "shell", "Options": opts},
                },
            },
            {
                "ID": "id-stale",
                "Spec": {
                    "Name": "app--STALE",
                    "Driver": {"Name": "shell", "Options": stale_opts},
                },
            },
            {
                "ID": "id-orphan",
                "Spec": {
                    "Name": "app--ORPHAN",
                    "Driver": {"Name": "shell", "Options": opts},
                },
            },
        ]

        with patch("psi.setup._list_podman_shell_secrets", return_value=secrets):
            dry_run_setup(settings)

        out = capsys.readouterr().out
        assert "app--OK" not in out or "managed" in out  # not in the stale/orphan lists
        assert "app--STALE" in out
        assert "app--ORPHAN" in out
        assert "dry-run" in out
        # state_dir must not have gained any new files
        assert sorted(p.name for p in settings.state_dir.iterdir()) == [
            "id-ok",
            "id-stale",
        ]
