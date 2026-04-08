"""Tests for psi.installer — systemd unit installation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from psi.installer import (
    _containers_conf_dir,
    _find_psi_path,
    _systemd_unit_dir,
    _write_provider_setup_units_container,
    _write_provider_setup_units_native,
    _write_refresh_timers,
    install_driver_conf,
)
from psi.models import SystemdScope


def _mock_settings(
    tmp_path: Path,
    scope: SystemdScope = SystemdScope.SYSTEM,
    providers: dict | None = None,
    cache_backend: str | None = None,
    cache_enabled: bool = True,
    refresh_interval: str = "1h",
    refresh_randomized_delay: str = "5m",
) -> MagicMock:
    settings = MagicMock()
    settings.state_dir = tmp_path / "state"
    settings.systemd_dir = tmp_path / "systemd"
    settings.scope = scope
    settings.tls = None
    settings.ca_cert = None
    settings.socket_token = None
    settings.providers = providers or {}
    if scope == SystemdScope.USER:
        settings.config_dir = Path.home() / ".config/psi"
    else:
        settings.config_dir = Path("/etc/psi")
    settings.cache.enabled = cache_enabled
    settings.cache.backend = cache_backend
    settings.cache.refresh_interval = refresh_interval
    settings.cache.refresh_randomized_delay = refresh_randomized_delay
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

    def test_uses_restrictive_mode_when_token_present(self, tmp_path: Path) -> None:
        conf_dir = tmp_path / "containers.conf.d"
        with patch("psi.installer._containers_conf_dir", return_value=conf_dir):
            settings = _mock_settings(tmp_path)
            settings.socket_token = "mytoken12345"
            install_driver_conf(settings)

        conf_path = conf_dir / "psi.conf"
        assert oct(conf_path.stat().st_mode & 0o777) == "0o600"

    def test_uses_default_mode_without_token(self, tmp_path: Path) -> None:
        conf_dir = tmp_path / "containers.conf.d"
        with patch("psi.installer._containers_conf_dir", return_value=conf_dir):
            settings = _mock_settings(tmp_path)
            install_driver_conf(settings)

        conf_path = conf_dir / "psi.conf"
        assert oct(conf_path.stat().st_mode & 0o777) == "0o644"


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


class TestPerProviderSetupUnits:
    def test_native_both_providers(self, tmp_path: Path) -> None:
        settings = _mock_settings(
            tmp_path,
            providers={"infisical": {}, "nitrokeyhsm": {}},
        )
        unit_dir = tmp_path / "units"
        unit_dir.mkdir()
        units = _write_provider_setup_units_native(
            settings,
            "/usr/bin/psi",
            unit_dir,
        )
        assert "psi-infisical-setup.service" in units
        assert "psi-nitrokeyhsm-setup.service" in units
        assert (unit_dir / "psi-infisical-setup.service").exists()
        assert (unit_dir / "psi-nitrokeyhsm-setup.service").exists()

    def test_native_single_provider(self, tmp_path: Path) -> None:
        settings = _mock_settings(
            tmp_path,
            providers={"infisical": {}},
        )
        unit_dir = tmp_path / "units"
        unit_dir.mkdir()
        units = _write_provider_setup_units_native(
            settings,
            "/usr/bin/psi",
            unit_dir,
        )
        assert units == ["psi-infisical-setup.service"]
        assert not (unit_dir / "psi-nitrokeyhsm-setup.service").exists()

    def test_container_both_providers(self, tmp_path: Path) -> None:
        settings = _mock_settings(
            tmp_path,
            providers={"infisical": {}, "nitrokeyhsm": {}},
        )
        quadlet_dir = tmp_path / "quadlets"
        quadlet_dir.mkdir()
        units = _write_provider_setup_units_container(
            settings,
            "psi:latest",
            quadlet_dir,
        )
        assert "psi-infisical-setup.service" in units
        assert "psi-nitrokeyhsm-setup.service" in units
        assert (quadlet_dir / "psi-infisical-setup.container").exists()
        assert (quadlet_dir / "psi-nitrokeyhsm-setup.container").exists()

    def test_container_infisical_content(self, tmp_path: Path) -> None:
        settings = _mock_settings(
            tmp_path,
            providers={"infisical": {}},
        )
        quadlet_dir = tmp_path / "quadlets"
        quadlet_dir.mkdir()
        _write_provider_setup_units_container(
            settings,
            "psi:latest",
            quadlet_dir,
        )
        content = (quadlet_dir / "psi-infisical-setup.container").read_text()
        assert "Exec=setup --provider infisical" in content
        assert "network-online.target" in content


class TestWriteRefreshTimers:
    def test_infisical_timer_written_when_cache_enabled_with_backend(
        self,
        tmp_path: Path,
    ) -> None:
        settings = _mock_settings(
            tmp_path,
            providers={"infisical": {}, "nitrokeyhsm": {}},
            cache_backend="hsm",
        )
        unit_dir = tmp_path / "units"
        unit_dir.mkdir()
        timers = _write_refresh_timers(settings, unit_dir)
        assert timers == ["psi-infisical-setup.timer"]
        assert (unit_dir / "psi-infisical-setup.timer").exists()
        content = (unit_dir / "psi-infisical-setup.timer").read_text()
        assert "Unit=psi-infisical-setup.service" in content
        assert "OnUnitActiveSec=1h" in content

    def test_no_timer_when_cache_disabled(self, tmp_path: Path) -> None:
        settings = _mock_settings(
            tmp_path,
            providers={"infisical": {}},
            cache_backend="hsm",
            cache_enabled=False,
        )
        unit_dir = tmp_path / "units"
        unit_dir.mkdir()
        timers = _write_refresh_timers(settings, unit_dir)
        assert timers == []
        assert not (unit_dir / "psi-infisical-setup.timer").exists()

    def test_no_timer_when_no_backend(self, tmp_path: Path) -> None:
        settings = _mock_settings(
            tmp_path,
            providers={"infisical": {}},
            cache_backend=None,
        )
        unit_dir = tmp_path / "units"
        unit_dir.mkdir()
        timers = _write_refresh_timers(settings, unit_dir)
        assert timers == []

    def test_no_timer_for_nitrokeyhsm_provider(self, tmp_path: Path) -> None:
        """HSM is local-only — nothing to periodically re-fetch."""
        settings = _mock_settings(
            tmp_path,
            providers={"nitrokeyhsm": {}},
            cache_backend="hsm",
        )
        unit_dir = tmp_path / "units"
        unit_dir.mkdir()
        timers = _write_refresh_timers(settings, unit_dir)
        assert timers == []
        assert not (unit_dir / "psi-nitrokeyhsm-setup.timer").exists()

    def test_custom_interval_is_honored(self, tmp_path: Path) -> None:
        settings = _mock_settings(
            tmp_path,
            providers={"infisical": {}},
            cache_backend="tpm",
            refresh_interval="15m",
            refresh_randomized_delay="1m",
        )
        unit_dir = tmp_path / "units"
        unit_dir.mkdir()
        _write_refresh_timers(settings, unit_dir)
        content = (unit_dir / "psi-infisical-setup.timer").read_text()
        assert "OnUnitActiveSec=15m" in content
        assert "RandomizedDelaySec=1m" in content
