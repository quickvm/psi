"""Tests for psi.installer — systemd unit installation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from psi.installer import (
    _containers_conf_dir,
    _find_psi_path,
    _systemd_unit_dir,
    install_driver_conf,
)
from psi.models import SystemdScope


def _mock_settings(
    tmp_path: Path,
    scope: SystemdScope = SystemdScope.SYSTEM,
) -> MagicMock:
    settings = MagicMock()
    settings.state_dir = tmp_path / "state"
    settings.systemd_dir = tmp_path / "systemd"
    settings.scope = scope
    settings.tls = None
    return settings


class TestFindPsiPath:
    def test_found(self) -> None:
        with patch("psi.installer.shutil.which", return_value="/usr/bin/psi"):
            assert _find_psi_path() == "/usr/bin/psi"

    def test_not_found(self) -> None:
        with (
            patch("psi.installer.shutil.which", return_value=None),
            pytest.raises(RuntimeError, match="psi not found"),
        ):
            _find_psi_path()


class TestInstallDriverConf:
    def test_writes_curl_based_conf(self, tmp_path: Path) -> None:
        conf_dir = tmp_path / "containers.conf.d"
        with patch("psi.installer._containers_conf_dir", return_value=conf_dir):
            settings = _mock_settings(tmp_path)
            install_driver_conf(settings)

        conf = (conf_dir / "psi.conf").read_text()
        assert 'driver = "shell"' in conf
        assert "curl -sf --unix-socket" in conf
        assert "/lookup" in conf

    def test_creates_state_dir(self, tmp_path: Path) -> None:
        conf_dir = tmp_path / "containers.conf.d"
        state_dir = tmp_path / "state"
        with patch("psi.installer._containers_conf_dir", return_value=conf_dir):
            settings = _mock_settings(tmp_path)
            settings.state_dir = state_dir
            install_driver_conf(settings)

        assert state_dir.exists()


class TestScopeAwarePaths:
    def test_systemd_unit_dir_system(self) -> None:
        assert _systemd_unit_dir(SystemdScope.SYSTEM) == Path("/etc/systemd/system")

    def test_systemd_unit_dir_user(self) -> None:
        expected = Path.home() / ".config/systemd/user"
        assert _systemd_unit_dir(SystemdScope.USER) == expected

    def test_containers_conf_dir_system(self) -> None:
        expected = Path("/etc/containers/containers.conf.d")
        assert _containers_conf_dir(SystemdScope.SYSTEM) == expected

    def test_containers_conf_dir_user(self) -> None:
        expected = Path.home() / ".config/containers/containers.conf.d"
        assert _containers_conf_dir(SystemdScope.USER) == expected
