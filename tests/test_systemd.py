"""Tests for psi.systemd — systemctl query helpers."""

from __future__ import annotations

import unittest.mock
from unittest.mock import patch

from psi.models import SystemdScope
from psi.systemd import (
    _systemctl_show,
    _usec_to_iso,
    daemon_reload,
    get_timer_info,
    get_unit_state,
)


class TestUsecToIso:
    def test_valid_timestamp(self) -> None:
        # 1700000000 seconds = 2023-11-14T22:13:20Z
        usec = str(1700000000 * 1_000_000)
        result = _usec_to_iso(usec)
        assert result == "2023-11-14T22:13:20Z"

    def test_zero(self) -> None:
        assert _usec_to_iso("0") is None

    def test_na(self) -> None:
        assert _usec_to_iso("n/a") is None

    def test_none(self) -> None:
        assert _usec_to_iso(None) is None

    def test_invalid(self) -> None:
        assert _usec_to_iso("not-a-number") is None


class TestGetTimerInfo:
    def test_active_timer(self) -> None:
        with patch("psi.systemd._systemctl_show") as mock:
            mock.return_value = {
                "ActiveState": "active",
                "LastTriggerUSec": "1700000000000000",
                "NextElapseUSecRealtime": "1700086400000000",
            }
            info = get_timer_info("test.timer")
        assert info is not None
        assert info.active_state == "active"
        assert info.last_trigger is not None
        assert info.next_elapse is not None

    def test_returns_none_when_unavailable(self) -> None:
        with patch("psi.systemd._systemctl_show", return_value=None):
            assert get_timer_info("test.timer") is None

    def test_returns_none_for_inactive_never_triggered(self) -> None:
        with patch("psi.systemd._systemctl_show") as mock:
            mock.return_value = {
                "ActiveState": "inactive",
                "LastTriggerUSec": "n/a",
                "NextElapseUSecRealtime": "0",
            }
            assert get_timer_info("test.timer") is None


class TestGetUnitState:
    def test_returns_state(self) -> None:
        with patch("psi.systemd._systemctl_show") as mock:
            mock.return_value = {"ActiveState": "active"}
            assert get_unit_state("test.service") == "active"

    def test_returns_none_when_unavailable(self) -> None:
        with patch("psi.systemd._systemctl_show", return_value=None):
            assert get_unit_state("test.service") is None


class TestUserMode:
    def test_timer_info_passes_user_mode(self) -> None:
        with patch("psi.systemd._systemctl_show") as mock:
            mock.return_value = {
                "ActiveState": "active",
                "LastTriggerUSec": "1700000000000000",
                "NextElapseUSecRealtime": "1700086400000000",
            }
            get_timer_info("test.timer", user_mode=True)
            mock.assert_called_once_with(
                "test.timer",
                ["ActiveState", "LastTriggerUSec", "NextElapseUSecRealtime"],
                user_mode=True,
            )

    def test_unit_state_passes_user_mode(self) -> None:
        with patch("psi.systemd._systemctl_show") as mock:
            mock.return_value = {"ActiveState": "active"}
            get_unit_state("test.service", user_mode=True)
            mock.assert_called_once_with(
                "test.service",
                ["ActiveState"],
                user_mode=True,
            )

    def test_systemctl_show_includes_user_flag(self) -> None:
        with patch("psi.systemd.subprocess.run") as mock:
            mock.return_value = unittest.mock.MagicMock(
                returncode=0,
                stdout="ActiveState=active\n",
            )
            _systemctl_show("test.service", ["ActiveState"], user_mode=True)
            cmd = mock.call_args[0][0]
            assert cmd[0] == "systemctl"
            assert cmd[1] == "--user"
            assert "show" in cmd

    def test_systemctl_show_no_user_flag_by_default(self) -> None:
        with patch("psi.systemd.subprocess.run") as mock:
            mock.return_value = unittest.mock.MagicMock(
                returncode=0,
                stdout="ActiveState=active\n",
            )
            _systemctl_show("test.service", ["ActiveState"])
            cmd = mock.call_args[0][0]
            assert "--user" not in cmd


class TestDaemonReload:
    def test_dbus_success_skips_subprocess(self) -> None:
        with (
            patch("psi.systemd._dbus_daemon_reload") as mock_dbus,
            patch("psi.systemd.subprocess.run") as mock_run,
        ):
            daemon_reload(SystemdScope.SYSTEM)
        mock_dbus.assert_called_once()
        mock_run.assert_not_called()

    def test_dbus_failure_falls_back_to_subprocess(self) -> None:
        with (
            patch(
                "psi.systemd._dbus_daemon_reload",
                side_effect=RuntimeError("bus not found"),
            ),
            patch("psi.systemd.subprocess.run") as mock_run,
        ):
            daemon_reload(SystemdScope.SYSTEM)
        mock_run.assert_called_once_with(["systemctl", "daemon-reload"], check=True)

    def test_dbus_import_error_falls_back(self) -> None:
        with (
            patch("psi.systemd._dbus_daemon_reload", side_effect=ImportError("no dbus")),
            patch("psi.systemd.subprocess.run") as mock_run,
        ):
            daemon_reload(SystemdScope.SYSTEM)
        mock_run.assert_called_once_with(["systemctl", "daemon-reload"], check=True)

    def test_user_scope_uses_user_flag_in_fallback(self) -> None:
        with (
            patch("psi.systemd._dbus_daemon_reload", side_effect=ImportError("no dbus")),
            patch("psi.systemd.subprocess.run") as mock_run,
        ):
            daemon_reload(SystemdScope.USER)
        mock_run.assert_called_once_with(["systemctl", "--user", "daemon-reload"], check=True)

    def test_missing_systemctl_is_skipped_with_warning(self) -> None:
        """When neither D-Bus nor systemctl is available, log and skip rather than raise."""
        with (
            patch("psi.systemd._dbus_daemon_reload", side_effect=ImportError("no dbus")),
            patch(
                "psi.systemd.subprocess.run",
                side_effect=FileNotFoundError(2, "No such file", "systemctl"),
            ),
        ):
            daemon_reload(SystemdScope.SYSTEM)

    def test_systemctl_error_is_skipped_with_warning(self) -> None:
        """CalledProcessError from systemctl is downgraded to a warning (not raised).

        This is the regression test for the container-mode installer crash: inside
        a psi container, `systemctl` exits with 'System has not been booted with
        systemd' and CalledProcessError — installer must not abort.
        """
        import subprocess

        with (
            patch("psi.systemd._dbus_daemon_reload", side_effect=ImportError("no dbus")),
            patch(
                "psi.systemd.subprocess.run",
                side_effect=subprocess.CalledProcessError(1, "systemctl"),
            ),
        ):
            daemon_reload(SystemdScope.SYSTEM)
