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
    _parse_dropin_secret_targets,
    _workload_dropin_drift,
    dry_run_setup,
)

if TYPE_CHECKING:
    from pathlib import Path


def _fake_settings(tmp_path: Path):
    from unittest.mock import MagicMock

    settings = MagicMock()
    settings.state_dir = tmp_path / "state"
    settings.state_dir.mkdir()
    settings.systemd_dir = tmp_path / "systemd"
    settings.systemd_dir.mkdir()
    settings.scope = SystemdScope.SYSTEM
    settings.socket_token = None
    settings.workloads = {}
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


class TestParseDropinSecretTargets:
    def test_returns_empty_set_when_file_missing(self, tmp_path: Path) -> None:
        assert _parse_dropin_secret_targets(tmp_path / "missing.conf") == set()

    def test_parses_simple_secret_lines(self, tmp_path: Path) -> None:
        conf = tmp_path / "50-secrets.conf"
        conf.write_text(
            "[Container]\n"
            "Secret=myapp--DB_URL,type=env,target=DB_URL\n"
            "Secret=myapp--API_KEY,type=env,target=API_KEY\n"
        )
        assert _parse_dropin_secret_targets(conf) == {
            "myapp--DB_URL",
            "myapp--API_KEY",
        }

    def test_ignores_non_secret_lines(self, tmp_path: Path) -> None:
        conf = tmp_path / "50-secrets.conf"
        conf.write_text(
            "[Unit]\n"
            "After=psi-secrets-setup.service\n"
            "Wants=psi-secrets-setup.service\n"
            "\n"
            "[Container]\n"
            "Secret=myapp--DB_URL,type=env,target=DB_URL\n"
        )
        assert _parse_dropin_secret_targets(conf) == {"myapp--DB_URL"}

    def test_handles_template_unit_names(self, tmp_path: Path) -> None:
        conf = tmp_path / "50-secrets.conf"
        conf.write_text("Secret=windmill-worker@--DB_HOST,type=env,target=DB_HOST\n")
        assert _parse_dropin_secret_targets(conf) == {"windmill-worker@--DB_HOST"}

    def test_empty_file_returns_empty_set(self, tmp_path: Path) -> None:
        conf = tmp_path / "50-secrets.conf"
        conf.write_text("")
        assert _parse_dropin_secret_targets(conf) == set()


def _write_dropin(settings_obj, workload_name: str, names: list[str]) -> None:
    path = settings_obj.systemd_dir / f"{workload_name}.container.d"
    path.mkdir(parents=True, exist_ok=True)
    lines = ["[Container]"]
    for n in names:
        target = n.split("--", 1)[1]
        lines.append(f"Secret={n},type=env,target={target}")
    (path / "50-secrets.conf").write_text("\n".join(lines) + "\n")


class TestWorkloadDropinDrift:
    def test_no_drift_when_dropin_matches_podman(self, tmp_path: Path) -> None:
        settings = _fake_settings(tmp_path)
        settings.workloads = {"myapp": None}
        _write_dropin(settings, "myapp", ["myapp--DB_URL", "myapp--API_KEY"])
        secrets = [
            _shell_secret("myapp--DB_URL"),
            _shell_secret("myapp--API_KEY"),
        ]
        assert _workload_dropin_drift(settings, secrets) == {}

    def test_detects_podman_secret_missing_from_dropin(self, tmp_path: Path) -> None:
        settings = _fake_settings(tmp_path)
        settings.workloads = {"myapp": None}
        _write_dropin(settings, "myapp", ["myapp--DB_URL"])
        secrets = [
            _shell_secret("myapp--DB_URL"),
            _shell_secret("myapp--MODE"),
            _shell_secret("myapp--NUM_WORKERS"),
        ]
        drift = _workload_dropin_drift(settings, secrets)
        assert drift == {
            "myapp": {
                "in_podman_not_in_dropin": ["myapp--MODE", "myapp--NUM_WORKERS"],
                "in_dropin_not_in_podman": [],
            }
        }

    def test_detects_dangling_dropin_reference(self, tmp_path: Path) -> None:
        settings = _fake_settings(tmp_path)
        settings.workloads = {"myapp": None}
        _write_dropin(settings, "myapp", ["myapp--DB_URL", "myapp--GHOST"])
        secrets = [_shell_secret("myapp--DB_URL")]
        drift = _workload_dropin_drift(settings, secrets)
        assert drift == {
            "myapp": {
                "in_podman_not_in_dropin": [],
                "in_dropin_not_in_podman": ["myapp--GHOST"],
            }
        }

    def test_both_directions_reported(self, tmp_path: Path) -> None:
        settings = _fake_settings(tmp_path)
        settings.workloads = {"myapp": None}
        _write_dropin(settings, "myapp", ["myapp--DB_URL", "myapp--GHOST"])
        secrets = [
            _shell_secret("myapp--DB_URL"),
            _shell_secret("myapp--MODE"),
        ]
        drift = _workload_dropin_drift(settings, secrets)
        assert drift == {
            "myapp": {
                "in_podman_not_in_dropin": ["myapp--MODE"],
                "in_dropin_not_in_podman": ["myapp--GHOST"],
            }
        }

    def test_workloads_without_drift_omitted(self, tmp_path: Path) -> None:
        settings = _fake_settings(tmp_path)
        settings.workloads = {"clean": None, "dirty": None}
        _write_dropin(settings, "clean", ["clean--OK"])
        _write_dropin(settings, "dirty", ["dirty--ONLY_IN_DROPIN"])
        secrets = [
            _shell_secret("clean--OK"),
            _shell_secret("dirty--ONLY_IN_PODMAN"),
        ]
        drift = _workload_dropin_drift(settings, secrets)
        assert list(drift.keys()) == ["dirty"]

    def test_no_dropin_but_podman_has_secrets(self, tmp_path: Path) -> None:
        settings = _fake_settings(tmp_path)
        settings.workloads = {"myapp": None}
        secrets = [_shell_secret("myapp--DB_URL")]
        drift = _workload_dropin_drift(settings, secrets)
        assert drift == {
            "myapp": {
                "in_podman_not_in_dropin": ["myapp--DB_URL"],
                "in_dropin_not_in_podman": [],
            }
        }


class TestDryRunDriftSection:
    def test_drift_section_printed_with_per_workload_details(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        settings = _fake_settings(tmp_path)
        settings.workloads = {"myapp": None}
        _write_dropin(settings, "myapp", ["myapp--DB_URL"])

        from psi.unitgen import generate_driver_conf

        opts = _parse_driver_opts(generate_driver_conf(settings.scope, token=None))
        (settings.state_dir / "id-1").write_text("{}")
        (settings.state_dir / "id-2").write_text("{}")

        secrets = [
            {
                "ID": "id-1",
                "Spec": {
                    "Name": "myapp--DB_URL",
                    "Driver": {"Name": "shell", "Options": opts},
                },
            },
            {
                "ID": "id-2",
                "Spec": {
                    "Name": "myapp--MODE",
                    "Driver": {"Name": "shell", "Options": opts},
                },
            },
        ]

        with patch("psi.setup._list_podman_shell_secrets", return_value=secrets):
            dry_run_setup(settings)

        out = capsys.readouterr().out
        assert "Workload drift" in out
        assert "myapp" in out
        assert "myapp--MODE" in out
        assert "in Podman, not in drop-in" in out

    def test_no_drift_section_when_clean(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        settings = _fake_settings(tmp_path)
        settings.workloads = {"myapp": None}
        _write_dropin(settings, "myapp", ["myapp--DB_URL"])

        from psi.unitgen import generate_driver_conf

        opts = _parse_driver_opts(generate_driver_conf(settings.scope, token=None))
        (settings.state_dir / "id-1").write_text("{}")

        secrets = [
            {
                "ID": "id-1",
                "Spec": {
                    "Name": "myapp--DB_URL",
                    "Driver": {"Name": "shell", "Options": opts},
                },
            },
        ]

        with patch("psi.setup._list_podman_shell_secrets", return_value=secrets):
            dry_run_setup(settings)

        out = capsys.readouterr().out
        assert "All secrets are managed" in out
