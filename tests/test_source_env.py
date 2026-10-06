"""Tests for a source's env: the keys a workload gets, under the variables it names."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from psi.errors import ProviderError
from psi.models import SecretSource, SystemdScope, WorkloadConfig
from psi.settings import PsiSettings
from psi.setup import _fetch_and_register_infisical

if TYPE_CHECKING:
    from pathlib import Path

    from tests.fake_infisical import FakeInfisical

FOLDER = ("proj-uuid", "prod", "/web")


def _settings(tmp_path: Path, source: SecretSource) -> PsiSettings:
    return PsiSettings(
        state_dir=tmp_path / "state",
        systemd_dir=tmp_path / "systemd",
        providers={
            "infisical": {
                "api_url": "https://infisical.test",
                "auth": {
                    "method": "universal-auth",
                    "client_id": "test-client",
                    "client_secret": "test-secret",
                },
                "projects": {"web": {"id": "proj-uuid", "environment": "prod"}},
            },
        },
        workloads={"tailscale": WorkloadConfig(provider="infisical", secrets=[source])},
        scope=SystemdScope.SYSTEM,
    )


def _fetch(tmp_path: Path, source: SecretSource) -> tuple[dict[str, str], dict[bytes, bytes]]:
    """Run setup's fetch for the workload, returning what it registered and cached."""
    registered: dict[str, str] = {}
    values: dict[bytes, bytes] = {}
    settings = _settings(tmp_path, source)
    with (
        patch("psi.setup._register_secrets", lambda s, w, merged: registered.update(merged)),
        patch("psi.setup._check_workload_drift", return_value=[]),
    ):
        _fetch_and_register_infisical(settings, "tailscale", values, [])
    return registered, values


class TestEnvMapping:
    def test_only_the_mapped_keys_reach_the_workload_under_their_names(
        self, tmp_path: Path, infisical: FakeInfisical
    ) -> None:
        infisical.folders[FOLDER] = {"TAILSCALE_AUTHKEY": "tskey-1", "OTHER": "not for it"}
        source = SecretSource(project="web", path="/web", env={"TS_AUTHKEY": "TAILSCALE_AUTHKEY"})
        registered, values = _fetch(tmp_path, source)
        assert list(registered) == ["TS_AUTHKEY"]
        assert json.loads(registered["TS_AUTHKEY"]) == {
            "provider": "infisical",
            "project": "web",
            "path": "/web",
            "key": "TAILSCALE_AUTHKEY",
        }
        assert list(values.values()) == [b"tskey-1"]
        dropin = tmp_path / "systemd" / "tailscale.container.d" / "50-secrets.conf"
        assert "Secret=tailscale--TS_AUTHKEY,type=env,target=TS_AUTHKEY" in dropin.read_text()
        assert "OTHER" not in dropin.read_text()

    def test_one_key_may_fill_two_variables(self, tmp_path: Path, infisical: FakeInfisical) -> None:
        infisical.folders[FOLDER] = {"TOKEN": "t"}
        source = SecretSource(project="web", path="/web", env={"A": "TOKEN", "B": "TOKEN"})
        registered, _ = _fetch(tmp_path, source)
        assert sorted(registered) == ["A", "B"]
        assert {json.loads(m)["key"] for m in registered.values()} == {"TOKEN"}

    def test_a_key_the_folder_lacks_fails_setup_and_registers_nothing(
        self, tmp_path: Path, infisical: FakeInfisical
    ) -> None:
        infisical.folders[FOLDER] = {"OTHER": "x"}
        source = SecretSource(project="web", path="/web", env={"TS_AUTHKEY": "TAILSCALE_AUTHKEY"})
        with pytest.raises(ProviderError) as caught:
            _fetch(tmp_path, source)
        assert str(caught.value) == (
            "workload tailscale: /web in project web has no TAILSCALE_AUTHKEY; add them there "
            "or drop them from the source's env"
        )

    def test_without_env_every_key_is_a_variable(
        self, tmp_path: Path, infisical: FakeInfisical
    ) -> None:
        infisical.folders[FOLDER] = {"A": "1", "B": "2"}
        registered, _ = _fetch(tmp_path, SecretSource(project="web", path="/web"))
        assert sorted(registered) == ["A", "B"]


class TestEnvValidation:
    def test_env_and_recursive_do_not_mix(self) -> None:
        with pytest.raises(ValidationError, match="cannot be combined with recursive"):
            SecretSource(project="web", recursive=True, env={"A": "A"})

    @pytest.mark.parametrize("name", ["1A", "A-B", "", "A B"])
    def test_env_names_are_environment_variable_names(self, name: str) -> None:
        with pytest.raises(ValidationError, match="not environment variable names"):
            SecretSource(project="web", env={name: "KEY"})

    def test_every_variable_names_a_key(self) -> None:
        with pytest.raises(ValidationError, match="needs a key"):
            SecretSource(project="web", env={"A": ""})
