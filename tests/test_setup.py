"""Tests for psi.setup drop-in generation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from psi.models import (
    AuthConfig,
    AuthMethod,
    ProjectConfig,
    SecretMapping,
    SecretSource,
    SystemdScope,
    WorkloadConfig,
)
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
        api_url="https://infisical.test",
        auth=AuthConfig(
            method=AuthMethod.UNIVERSAL,
            client_id="cid",
            client_secret="csec",
        ),
        state_dir=tmp_path / "state",
        systemd_dir=tmp_path / "systemd",
        projects={
            "myproject": ProjectConfig(id="proj-uuid", environment="prod"),
        },
        workloads=workloads,
        scope=SystemdScope.SYSTEM,
    )


def _sample_secrets() -> dict[str, SecretMapping]:
    return {
        "DB_PASSWORD": SecretMapping(
            project_alias="myproject",
            secret_path="/app",
            secret_name="DB_PASSWORD",
        ),
        "API_KEY": SecretMapping(
            project_alias="myproject",
            secret_path="/app",
            secret_name="API_KEY",
        ),
    }


class TestGenerateDropIn:
    def test_dropin_without_depends_on(self, tmp_path: Path) -> None:
        workload = WorkloadConfig(
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
            secrets=[SecretSource(project="myproject", path="/app")],
            depends_on=["psi-secrets-setup.service"],
        )
        settings = _make_settings(tmp_path, {"myapp": workload})
        _generate_drop_in(settings, "myapp", _sample_secrets())

        dropin = tmp_path / "systemd" / "myapp.container.d" / "50-secrets.conf"
        content = dropin.read_text()

        assert content.startswith("[Unit]\n")
        assert "After=psi-secrets-setup.service\n" in content
        assert "Requires=psi-secrets-setup.service\n" in content
        assert "[Container]\n" in content

    def test_dropin_with_multiple_depends_on(self, tmp_path: Path) -> None:
        workload = WorkloadConfig(
            secrets=[SecretSource(project="myproject", path="/app")],
            depends_on=[
                "psi-secrets-setup.service",
                "network-online.target",
            ],
        )
        settings = _make_settings(tmp_path, {"myapp": workload})
        _generate_drop_in(settings, "myapp", _sample_secrets())

        dropin = tmp_path / "systemd" / "myapp.container.d" / "50-secrets.conf"
        content = dropin.read_text()

        expected_deps = "psi-secrets-setup.service network-online.target"
        assert f"After={expected_deps}\n" in content
        assert f"Requires={expected_deps}\n" in content

    def test_dropin_secrets_sorted(self, tmp_path: Path) -> None:
        workload = WorkloadConfig(
            secrets=[SecretSource(project="myproject", path="/app")],
        )
        settings = _make_settings(tmp_path, {"myapp": workload})
        _generate_drop_in(settings, "myapp", _sample_secrets())

        dropin = tmp_path / "systemd" / "myapp.container.d" / "50-secrets.conf"
        lines = dropin.read_text().strip().splitlines()
        secret_lines = [line for line in lines if line.startswith("Secret=")]
        assert secret_lines[0].startswith("Secret=myapp--API_KEY")
        assert secret_lines[1].startswith("Secret=myapp--DB_PASSWORD")
