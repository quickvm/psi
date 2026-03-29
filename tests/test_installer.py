"""Tests for psi.installer — systemd unit installation."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from psi.installer import _find_psi_path, install_driver_conf
from psi.models import DeployMode

if TYPE_CHECKING:
    from pathlib import Path


def _mock_settings(tmp_path: Path) -> MagicMock:
    settings = MagicMock()
    settings.state_dir = tmp_path / "state"
    settings.systemd_dir = tmp_path / "systemd"
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
    def test_native_mode(self, tmp_path: Path) -> None:
        conf_dir = tmp_path / "containers.conf.d"
        with patch("psi.installer._CONTAINERS_CONF_DIR", conf_dir):
            settings = _mock_settings(tmp_path)
            install_driver_conf(settings, DeployMode.NATIVE, image=None)

        conf = (conf_dir / "psi.conf").read_text()
        assert 'driver = "shell"' in conf
        assert 'store = "psi secret store"' in conf

    def test_container_mode(self, tmp_path: Path) -> None:
        conf_dir = tmp_path / "containers.conf.d"
        with patch("psi.installer._CONTAINERS_CONF_DIR", conf_dir):
            settings = _mock_settings(tmp_path)
            install_driver_conf(settings, DeployMode.CONTAINER, image="psi:latest")

        conf = (conf_dir / "psi.conf").read_text()
        assert "podman run --rm" in conf
        assert "psi:latest" in conf

    def test_creates_state_dir(self, tmp_path: Path) -> None:
        conf_dir = tmp_path / "containers.conf.d"
        state_dir = tmp_path / "state"
        with patch("psi.installer._CONTAINERS_CONF_DIR", conf_dir):
            settings = _mock_settings(tmp_path)
            settings.state_dir = state_dir
            install_driver_conf(settings, DeployMode.NATIVE, image=None)

        assert state_dir.exists()
