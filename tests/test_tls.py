"""Tests for psi.tls — duration parsing, renewal logic, cert file writing."""

from __future__ import annotations

import subprocess
import time
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from psi.providers.infisical.models import CertState, CertStatusInfo
from psi.providers.infisical.tls import (
    _needs_renewal,
    _parse_duration_seconds,
    _run_hooks,
    _write_cert_files,
    build_tls_status_table,
)

if TYPE_CHECKING:
    from pathlib import Path


class TestParseDurationSeconds:
    def test_seconds(self) -> None:
        assert _parse_duration_seconds("60s") == 60

    def test_minutes(self) -> None:
        assert _parse_duration_seconds("5m") == 300

    def test_hours(self) -> None:
        assert _parse_duration_seconds("24h") == 86400

    def test_days(self) -> None:
        assert _parse_duration_seconds("90d") == 90 * 86400

    def test_years(self) -> None:
        assert _parse_duration_seconds("1y") == 365 * 86400

    def test_large_number(self) -> None:
        assert _parse_duration_seconds("365d") == 365 * 86400

    def test_strips_whitespace(self) -> None:
        assert _parse_duration_seconds("  30d  ") == 30 * 86400

    def test_invalid_unit(self) -> None:
        with pytest.raises(ValueError, match="Invalid duration"):
            _parse_duration_seconds("90x")

    def test_no_number(self) -> None:
        with pytest.raises(ValueError, match="Invalid duration"):
            _parse_duration_seconds("d")

    def test_empty_string(self) -> None:
        with pytest.raises(ValueError, match="Invalid duration"):
            _parse_duration_seconds("")

    def test_just_a_number(self) -> None:
        with pytest.raises(ValueError, match="Invalid duration"):
            _parse_duration_seconds("90")


class TestNeedsRenewal:
    def test_expired(self) -> None:
        state = CertState(
            certificate_id="c",
            serial_number="s",
            common_name="cn",
            issued_at=0,
            expires_at=time.time() - 100,
            profile_id="p",
        )
        assert _needs_renewal(state, 86400) is True

    def test_within_window(self) -> None:
        state = CertState(
            certificate_id="c",
            serial_number="s",
            common_name="cn",
            issued_at=0,
            expires_at=time.time() + 3600,
            profile_id="p",
        )
        assert _needs_renewal(state, 86400) is True

    def test_not_due(self) -> None:
        state = CertState(
            certificate_id="c",
            serial_number="s",
            common_name="cn",
            issued_at=0,
            expires_at=time.time() + 90 * 86400,
            profile_id="p",
        )
        assert _needs_renewal(state, 30 * 86400) is False


class TestWriteCertFiles:
    def test_writes_all_files(self, tmp_path: Path, tls_config) -> None:
        cert_config = tls_config.certificates["web"]
        cert_data = {
            "certificate": "---CERT---",
            "privateKey": "---KEY---",
            "certificateChain": "---CHAIN---",
        }
        _write_cert_files(cert_config, cert_data)

        assert cert_config.output.cert.read_text() == "---CERT---"
        assert cert_config.output.key.read_text() == "---KEY---"
        assert cert_config.output.chain.read_text() == "---CHAIN---"

    def test_key_file_permissions(self, tmp_path: Path, tls_config) -> None:
        cert_config = tls_config.certificates["web"]
        cert_data = {
            "certificate": "c",
            "privateKey": "k",
            "certificateChain": "ch",
        }
        _write_cert_files(cert_config, cert_data)
        assert oct(cert_config.output.key.stat().st_mode & 0o777) == "0o600"

    def test_non_key_files_use_configured_mode(self, tmp_path: Path, tls_config) -> None:
        cert_config = tls_config.certificates["web"]
        cert_data = {
            "certificate": "c",
            "privateKey": "k",
            "certificateChain": "ch",
        }
        _write_cert_files(cert_config, cert_data)
        assert oct(cert_config.output.cert.stat().st_mode & 0o777) == "0o640"
        assert oct(cert_config.output.chain.stat().st_mode & 0o777) == "0o640"

    def test_writes_ca_when_configured(self, tmp_path: Path) -> None:
        from psi.providers.infisical.models import CertificateConfig, CertOutput

        config = CertificateConfig(
            project="p",
            profile_id="pid",
            common_name="cn",
            output=CertOutput(
                cert=tmp_path / "cert.pem",
                key=tmp_path / "key.pem",
                chain=tmp_path / "chain.pem",
                ca=tmp_path / "ca.pem",
            ),
        )
        cert_data = {
            "certificate": "c",
            "privateKey": "k",
            "certificateChain": "ch",
            "issuingCaCertificate": "---CA---",
        }
        _write_cert_files(config, cert_data)
        assert config.output.ca is not None
        assert config.output.ca.read_text() == "---CA---"

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        from psi.providers.infisical.models import CertificateConfig, CertOutput

        nested = tmp_path / "deep" / "nested"
        config = CertificateConfig(
            project="p",
            profile_id="pid",
            common_name="cn",
            output=CertOutput(
                cert=nested / "cert.pem",
                key=nested / "key.pem",
                chain=nested / "chain.pem",
            ),
        )
        cert_data = {
            "certificate": "c",
            "privateKey": "k",
            "certificateChain": "ch",
        }
        _write_cert_files(config, cert_data)
        assert nested.exists()


class TestBuildTlsStatusTable:
    def test_empty_list(self) -> None:
        table = build_tls_status_table([])
        assert table.row_count == 0

    def test_valid_cert(self) -> None:
        certs = [
            CertStatusInfo(
                name="web",
                common_name="web.example.com",
                serial_number="AABB",
                issued="2026-01-01",
                expires="2026-04-01",
                days_left=60,
                status="valid",
            ),
        ]
        table = build_tls_status_table(certs)
        assert table.row_count == 1


class TestRunHooks:
    def test_runs_without_shell(self) -> None:
        with patch("psi.providers.infisical.tls.subprocess.run") as mock_run:
            assert _run_hooks(["systemctl reload traefik.service"], "web") is True

        mock_run.assert_called_once_with(
            ["systemctl", "reload", "traefik.service"],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_reports_parse_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert _run_hooks(['echo "unterminated'], "web") is False
        assert "parse error" in capsys.readouterr().out

    def test_reports_empty_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert _run_hooks(["   "], "web") is False
        assert "empty command" in capsys.readouterr().out

    def test_reports_command_failure(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch(
            "psi.providers.infisical.tls.subprocess.run",
            side_effect=subprocess.CalledProcessError(
                1,
                ["systemctl", "reload", "traefik.service"],
                stderr="failed",
            ),
        ):
            assert _run_hooks(["systemctl reload traefik.service"], "web") is False

        assert "stderr: failed" in capsys.readouterr().out

    def test_not_issued_shows_dash_for_days(self) -> None:
        certs = [
            CertStatusInfo(
                name="web",
                common_name="—",
                serial_number="—",
                issued="—",
                expires="—",
                days_left=0,
                status="not_issued",
            ),
        ]
        table = build_tls_status_table(certs)
        assert table.row_count == 1
