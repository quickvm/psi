"""Tests for psi.setup drop-in generation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from psi.models import SecretSource, SystemdScope, WorkloadConfig
from psi.providers.infisical import InfisicalProvider
from psi.settings import PsiSettings
from psi.setup import _generate_drop_in

if TYPE_CHECKING:
    from pathlib import Path


def _make_settings(
    tmp_path: Path,
    workloads: dict[str, WorkloadConfig],
) -> PsiSettings:
    """Build a minimal settings object for _generate_drop_in."""
    return PsiSettings(
        state_dir=tmp_path / "state",
        systemd_dir=tmp_path / "systemd",
        providers={
            "infisical": {
                "api_url": "https://infisical.test",
                "auth": {
                    "method": "universal-auth",
                    "client_id": "cid",
                    "client_secret": "csec",
                },
                "projects": {
                    "myproject": {"id": "proj-uuid", "environment": "prod"},
                },
            },
        },
        workloads=workloads,
        scope=SystemdScope.SYSTEM,
    )


def _sample_secrets() -> dict[str, str]:
    """Return sample mapping JSON strings keyed by secret name."""
    return {
        "DB_PASSWORD": InfisicalProvider.make_mapping(
            "myproject",
            "/app",
            "DB_PASSWORD",
        ),
        "API_KEY": InfisicalProvider.make_mapping(
            "myproject",
            "/app",
            "API_KEY",
        ),
    }


class TestGenerateDropIn:
    def test_dropin_without_depends_on(self, tmp_path: Path) -> None:
        workload = WorkloadConfig(
            provider="infisical",
            secrets=[SecretSource(project="myproject", path="/app")],
        )
        settings = _make_settings(tmp_path, {"myapp": workload})
        _generate_drop_in(settings, "myapp", _sample_secrets())

        dropin = tmp_path / "systemd" / "myapp.container.d" / "50-secrets.conf"
        content = dropin.read_text()

        assert content.startswith("[Container]\n")
        assert "[Unit]" not in content
        assert "Secret=myapp--API_KEY,type=env,target=API_KEY\n" in content
        assert "Secret=myapp--DB_PASSWORD,type=env,target=DB_PASSWORD\n" in content

    def test_dropin_with_depends_on(self, tmp_path: Path) -> None:
        workload = WorkloadConfig(
            provider="infisical",
            secrets=[SecretSource(project="myproject", path="/app")],
            depends_on=["psi-secrets-setup.service"],
        )
        settings = _make_settings(tmp_path, {"myapp": workload})
        _generate_drop_in(settings, "myapp", _sample_secrets())

        dropin = tmp_path / "systemd" / "myapp.container.d" / "50-secrets.conf"
        content = dropin.read_text()

        assert content.startswith("[Unit]\n")
        assert "After=psi-secrets-setup.service\n" in content
        assert "Wants=psi-secrets-setup.service\n" in content
        assert "[Container]\n" in content

    def test_dropin_secrets_sorted(self, tmp_path: Path) -> None:
        workload = WorkloadConfig(
            provider="infisical",
            secrets=[SecretSource(project="myproject", path="/app")],
        )
        settings = _make_settings(tmp_path, {"myapp": workload})
        _generate_drop_in(settings, "myapp", _sample_secrets())

        dropin = tmp_path / "systemd" / "myapp.container.d" / "50-secrets.conf"
        lines = dropin.read_text().strip().splitlines()
        secret_lines = [line for line in lines if line.startswith("Secret=")]
        assert secret_lines[0].startswith("Secret=myapp--API_KEY")
        assert secret_lines[1].startswith("Secret=myapp--DB_PASSWORD")


class TestTemplateUnitDropIn:
    """Template unit workloads use @ in the name (e.g. windmill-worker@).

    Secrets are shared across all instances. The drop-in goes to
    {name}@.container.d/ so all instances inherit the same Secret= lines.
    """

    def _template_secrets(self) -> dict[str, str]:
        return {
            "DB_HOST": InfisicalProvider.make_mapping("myproject", "/app", "DB_HOST"),
            "REDIS_URL": InfisicalProvider.make_mapping("myproject", "/app", "REDIS_URL"),
        }

    def test_template_dropin_directory(self, tmp_path: Path) -> None:
        workload = WorkloadConfig(
            provider="infisical",
            secrets=[SecretSource(project="myproject", path="/app")],
        )
        settings = _make_settings(tmp_path, {"windmill-worker@": workload})
        _generate_drop_in(settings, "windmill-worker@", self._template_secrets())

        dropin = tmp_path / "systemd" / "windmill-worker@.container.d" / "50-secrets.conf"
        assert dropin.exists()

    def test_template_secret_names(self, tmp_path: Path) -> None:
        workload = WorkloadConfig(
            provider="infisical",
            secrets=[SecretSource(project="myproject", path="/app")],
        )
        settings = _make_settings(tmp_path, {"windmill-worker@": workload})
        _generate_drop_in(settings, "windmill-worker@", self._template_secrets())

        dropin = tmp_path / "systemd" / "windmill-worker@.container.d" / "50-secrets.conf"
        content = dropin.read_text()

        assert "Secret=windmill-worker@--DB_HOST,type=env,target=DB_HOST\n" in content
        assert "Secret=windmill-worker@--REDIS_URL,type=env,target=REDIS_URL\n" in content

    def test_template_with_depends_on(self, tmp_path: Path) -> None:
        workload = WorkloadConfig(
            provider="infisical",
            secrets=[SecretSource(project="myproject", path="/app")],
            depends_on=["psi-secrets-setup.service"],
        )
        settings = _make_settings(tmp_path, {"windmill-worker@": workload})
        _generate_drop_in(settings, "windmill-worker@", self._template_secrets())

        dropin = tmp_path / "systemd" / "windmill-worker@.container.d" / "50-secrets.conf"
        content = dropin.read_text()

        assert "After=psi-secrets-setup.service\n" in content
        assert "Wants=psi-secrets-setup.service\n" in content
        assert "Secret=windmill-worker@--DB_HOST" in content
