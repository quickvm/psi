"""Tests for psi.unitgen — systemd unit content generators."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from psi.models import SystemdScope
from psi.providers.infisical.models import CertificateConfig, CertOutput, TlsConfig
from psi.unitgen import (
    collect_tls_volume_dirs,
    generate_container_provider_setup_quadlet,
    generate_container_tls_renew_quadlet,
    generate_driver_conf,
    generate_native_provider_setup_service,
    generate_native_tls_renew_service,
    generate_tls_renew_timer,
)


def _mock_settings(
    tmp_path: Path,
    tls: TlsConfig | None = None,
    scope: SystemdScope = SystemdScope.SYSTEM,
) -> MagicMock:
    settings = MagicMock()
    settings.state_dir = tmp_path / "state"
    settings.systemd_dir = tmp_path / "systemd"
    settings.ca_cert = None
    settings.scope = scope
    if tls:
        settings.providers = {
            "infisical": {"tls": tls.model_dump()},
        }
    else:
        settings.providers = {}
    if scope == SystemdScope.USER:
        settings.config_dir = Path.home() / ".config/psi"
    else:
        settings.config_dir = Path("/etc/psi")
    return settings


class TestNativeServiceGenerators:
    def test_infisical_setup_service(self) -> None:
        content = generate_native_provider_setup_service("/usr/bin/psi", "infisical")
        assert "ExecStart=/usr/bin/psi setup --provider infisical" in content
        assert "Type=oneshot" in content
        assert "RemainAfterExit=yes" in content
        assert "WantedBy=multi-user.target" in content
        assert "After=network-online.target psi-secrets.service" in content
        assert "Wants=network-online.target" in content
        assert "Description=PSI infisical secrets setup" in content

    def test_nitrokeyhsm_setup_service(self) -> None:
        content = generate_native_provider_setup_service(
            "/usr/bin/psi",
            "nitrokeyhsm",
        )
        assert "ExecStart=/usr/bin/psi setup --provider nitrokeyhsm" in content
        assert "After=psi-secrets.service" in content
        assert "network-online.target" not in content
        assert "Wants=" not in content
        assert "Description=PSI nitrokeyhsm secrets setup" in content

    def test_tls_renew_service(self) -> None:
        content = generate_native_tls_renew_service("/usr/bin/psi")
        assert "ExecStart=/usr/bin/psi tls renew" in content
        assert "Type=oneshot" in content

    def test_custom_psi_path(self) -> None:
        content = generate_native_provider_setup_service(
            "/home/user/.local/bin/psi",
            "infisical",
        )
        assert "/home/user/.local/bin/psi setup --provider infisical" in content


class TestTimerGenerator:
    def test_timer_content(self) -> None:
        content = generate_tls_renew_timer()
        assert "OnCalendar=daily" in content
        assert "RandomizedDelaySec=1h" in content
        assert "Persistent=true" in content
        assert "WantedBy=timers.target" in content


class TestContainerQuadletGenerators:
    def test_infisical_setup_quadlet(self, tmp_path: Path) -> None:
        settings = _mock_settings(tmp_path)
        content = generate_container_provider_setup_quadlet(
            "psi:latest",
            settings,
            "infisical",
        )
        assert "Image=psi:latest" in content
        assert "Exec=setup --provider infisical" in content
        assert "Network=host" in content
        assert "/etc/psi:/etc/psi:ro" in content
        assert "Type=oneshot" in content
        assert "/run/dbus/system_bus_socket" in content
        assert "After=network-online.target psi-secrets.service" in content
        assert "Wants=network-online.target" in content

    def test_nitrokeyhsm_setup_quadlet(self, tmp_path: Path) -> None:
        settings = _mock_settings(tmp_path)
        content = generate_container_provider_setup_quadlet(
            "psi:latest",
            settings,
            "nitrokeyhsm",
        )
        assert "Exec=setup --provider nitrokeyhsm" in content
        assert "After=psi-secrets.service" in content
        assert "network-online.target" not in content

    def test_setup_quadlet_uses_settings_paths(self, tmp_path: Path) -> None:
        settings = _mock_settings(tmp_path)
        content = generate_container_provider_setup_quadlet(
            "img:v1",
            settings,
            "infisical",
        )
        state = str(settings.state_dir)
        assert f"Volume={state}:{state}:Z" in content

    def test_tls_renew_quadlet_no_tls(self, tmp_path: Path) -> None:
        settings = _mock_settings(tmp_path, tls=None)
        content = generate_container_tls_renew_quadlet("img:v1", settings)
        assert "Exec=tls renew" in content

    def test_tls_renew_quadlet_with_cert_dirs(self, tmp_path: Path) -> None:
        tls = TlsConfig(
            certificates={
                "web": CertificateConfig(
                    project="p",
                    profile_id="pid",
                    common_name="cn",
                    output=CertOutput(
                        cert=Path("/etc/traefik/tls/cert.pem"),
                        key=Path("/etc/traefik/tls/key.pem"),
                        chain=Path("/etc/traefik/tls/chain.pem"),
                    ),
                ),
            }
        )
        settings = _mock_settings(tmp_path, tls=tls)
        content = generate_container_tls_renew_quadlet("img:v1", settings)
        assert "Volume=/etc/traefik/tls:/etc/traefik/tls:Z" in content


class TestDriverConfGenerator:
    def test_system_scope(self) -> None:
        content = generate_driver_conf(SystemdScope.SYSTEM)
        assert 'driver = "shell"' in content
        assert "curl -sf --unix-socket /run/psi/psi.sock" in content
        assert "/lookup" in content
        assert "/store" in content

    def test_user_scope(self) -> None:
        content = generate_driver_conf(SystemdScope.USER)
        assert 'driver = "shell"' in content
        assert "psi.sock" in content
        assert "/lookup" in content

    def test_no_auth_header_without_token(self) -> None:
        content = generate_driver_conf(SystemdScope.SYSTEM)
        assert "Authorization" not in content

    def test_auth_header_with_token(self) -> None:
        content = generate_driver_conf(SystemdScope.SYSTEM, token="mytoken12345")
        assert "-H 'Authorization: Bearer mytoken12345'" in content
        # Still has all four command lines
        assert "/lookup" in content
        assert "/store" in content
        assert "/delete" in content
        assert "/list" in content


class TestCollectTlsVolumeDirs:
    def test_no_tls(self, tmp_path: Path) -> None:
        settings = _mock_settings(tmp_path, tls=None)
        assert collect_tls_volume_dirs(settings) == set()

    def test_single_cert(self, tmp_path: Path) -> None:
        tls = TlsConfig(
            certificates={
                "web": CertificateConfig(
                    project="p",
                    profile_id="pid",
                    common_name="cn",
                    output=CertOutput(
                        cert=Path("/tls/cert.pem"),
                        key=Path("/tls/key.pem"),
                        chain=Path("/tls/chain.pem"),
                    ),
                ),
            }
        )
        settings = _mock_settings(tmp_path, tls=tls)
        dirs = collect_tls_volume_dirs(settings)
        assert dirs == {Path("/tls")}

    def test_multiple_certs_deduplicates(self, tmp_path: Path) -> None:
        tls = TlsConfig(
            certificates={
                "a": CertificateConfig(
                    project="p",
                    profile_id="pid",
                    common_name="a",
                    output=CertOutput(
                        cert=Path("/tls/a/cert.pem"),
                        key=Path("/tls/a/key.pem"),
                        chain=Path("/tls/a/chain.pem"),
                    ),
                ),
                "b": CertificateConfig(
                    project="p",
                    profile_id="pid",
                    common_name="b",
                    output=CertOutput(
                        cert=Path("/tls/b/cert.pem"),
                        key=Path("/tls/b/key.pem"),
                        chain=Path("/tls/a/chain.pem"),  # shared dir with a
                    ),
                ),
            }
        )
        settings = _mock_settings(tmp_path, tls=tls)
        dirs = collect_tls_volume_dirs(settings)
        assert dirs == {Path("/tls/a"), Path("/tls/b")}

    def test_with_ca_path(self, tmp_path: Path) -> None:
        tls = TlsConfig(
            certificates={
                "web": CertificateConfig(
                    project="p",
                    profile_id="pid",
                    common_name="cn",
                    output=CertOutput(
                        cert=Path("/tls/cert.pem"),
                        key=Path("/tls/key.pem"),
                        chain=Path("/tls/chain.pem"),
                        ca=Path("/ca/ca.pem"),
                    ),
                ),
            }
        )
        settings = _mock_settings(tmp_path, tls=tls)
        dirs = collect_tls_volume_dirs(settings)
        assert Path("/ca") in dirs
        assert Path("/tls") in dirs


class TestUserScopeGenerators:
    def test_native_setup_service_user_scope(self) -> None:
        content = generate_native_provider_setup_service(
            "/usr/bin/psi",
            "infisical",
            SystemdScope.USER,
        )
        assert "WantedBy=default.target" in content
        assert "multi-user.target" not in content

    def test_native_setup_service_system_scope(self) -> None:
        content = generate_native_provider_setup_service(
            "/usr/bin/psi",
            "infisical",
            SystemdScope.SYSTEM,
        )
        assert "WantedBy=multi-user.target" in content

    def test_container_quadlet_user_scope(self, tmp_path: Path) -> None:
        settings = _mock_settings(tmp_path, scope=SystemdScope.USER)
        content = generate_container_provider_setup_quadlet(
            "psi:latest",
            settings,
            "infisical",
        )
        home = str(Path.home())
        assert f"{home}/.config/psi" in content
        assert "WantedBy=default.target" in content
        assert "multi-user.target" not in content
        assert "/run/dbus/system_bus_socket" not in content

    def test_container_quadlet_system_scope(self, tmp_path: Path) -> None:
        settings = _mock_settings(tmp_path, scope=SystemdScope.SYSTEM)
        content = generate_container_provider_setup_quadlet(
            "psi:latest",
            settings,
            "infisical",
        )
        assert "/etc/psi:/etc/psi:ro" in content
        assert "WantedBy=multi-user.target" in content
        assert "/run/dbus/system_bus_socket" in content

    def test_driver_conf_user_scope(self) -> None:
        content = generate_driver_conf(SystemdScope.USER)
        assert "psi.sock" in content
        assert "/run/psi/" not in content
