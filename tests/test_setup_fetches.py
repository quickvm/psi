"""Tests for what one setup run's Infisical workloads share: a session, listings, a pace."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import ValidationError

from psi.models import SecretSource, SystemdScope, WorkloadConfig
from psi.providers.infisical import InfisicalProvider
from psi.providers.infisical.api import InfisicalAPIError
from psi.providers.infisical.models import InfisicalConfig
from psi.settings import PsiSettings
from psi.setup import run_setup
from tests.fake_infisical import reply

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    import requests

    from tests.fake_infisical import FakeInfisical

LISTING = ("GET", "/api/v3/secrets/raw")


def _settings(tmp_path: Path, folders: dict[str, str], **infisical: Any) -> PsiSettings:
    """A workload per entry of ``folders`` (its name, the folder it reads)."""
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
                "projects": {"app": {"id": "proj-uuid", "environment": "prod"}},
                **infisical,
            },
        },
        workloads={
            name: WorkloadConfig(
                provider="infisical", secrets=[SecretSource(project="app", path=p)]
            )
            for name, p in folders.items()
        },
        scope=SystemdScope.SYSTEM,
    )


@pytest.fixture
def podman() -> Iterator[None]:
    """Setup's work on this machine, with nothing registered and nothing to reload."""
    with (
        patch("psi.setup._register_secrets"),
        patch("psi.setup._check_workload_drift", return_value=[]),
        patch("psi.setup._check_orphans", return_value=[]),
        patch("psi.setup.daemon_reload"),
    ):
        yield


def _listed(infisical: FakeInfisical) -> list[str]:
    """The folders setup asked Infisical to list, in order."""
    return [s.params["secretPath"] for s in infisical.sent if (s.method, s.path) == LISTING]


@pytest.mark.usefixtures("podman")
def test_workloads_that_read_one_folder_list_it_once(
    tmp_path: Path, infisical: FakeInfisical
) -> None:
    infisical.folders[("proj-uuid", "prod", "/web")] = {"A": "1"}
    infisical.folders[("proj-uuid", "prod", "/db")] = {"B": "2"}
    run_setup(_settings(tmp_path, {"web": "/web", "worker": "/web", "db": "/db"}))
    assert _listed(infisical) == ["/web", "/db"]


@pytest.mark.usefixtures("podman")
def test_a_listing_is_reused_only_for_the_identity_that_made_it(
    tmp_path: Path, infisical: FakeInfisical
) -> None:
    infisical.folders[("proj-uuid", "prod", "/web")] = {"A": "1"}
    settings = _settings(tmp_path, {"web": "/web"})
    other = {
        "id": "proj-uuid",
        "environment": "prod",
        "auth": {"method": "gcp", "identity_id": infisical.identity_id},
    }
    settings.providers["infisical"]["projects"]["also-app"] = other
    reader = SecretSource(project="also-app", path="/web")
    settings.workloads["reader"] = WorkloadConfig(provider="infisical", secrets=[reader])
    with patch("psi.providers.infisical.auth._gcp_identity_token", return_value="gcp-jwt"):
        run_setup(settings)
    assert _listed(infisical) == ["/web", "/web"]


@pytest.mark.usefixtures("podman")
def test_a_retry_lists_again_only_the_folder_that_failed(
    tmp_path: Path, infisical: FakeInfisical
) -> None:
    infisical.folders[("proj-uuid", "prod", "/web")] = {"A": "1"}
    infisical.folders[("proj-uuid", "prod", "/db")] = {"B": "2"}
    busy = ["/db"]

    def once_busy(request: requests.PreparedRequest) -> requests.Response:
        (path,) = parse_qs(urlsplit(request.url or "").query)["secretPath"]
        if path in busy:
            busy.remove(path)
            return reply(request, 503, {"message": "busy"})
        return infisical._route(request, infisical.sent[-1])

    infisical.answers[LISTING] = once_busy
    settings = _settings(tmp_path, {})
    sources = [SecretSource(project="app", path="/web"), SecretSource(project="app", path="/db")]
    settings.workloads["app"] = WorkloadConfig(provider="infisical", secrets=sources)
    with patch("psi.setup.time.sleep"):
        run_setup(settings)
    assert _listed(infisical) == ["/web", "/db", "/db"]


@pytest.mark.usefixtures("podman")
def test_a_delay_paces_only_the_listings_that_reach_infisical(
    tmp_path: Path, infisical: FakeInfisical
) -> None:
    infisical.folders[("proj-uuid", "prod", "/web")] = {"A": "1"}
    infisical.folders[("proj-uuid", "prod", "/db")] = {"B": "2"}
    settings = _settings(
        tmp_path, {"web": "/web", "worker": "/web", "db": "/db"}, fetch_delay_ms=250
    )
    with patch("psi.setup.time.sleep") as slept:
        run_setup(settings)
    assert [call.args for call in slept.call_args_list] == [(0.25,)]


@pytest.mark.usefixtures("podman")
def test_without_a_delay_setup_never_pauses(tmp_path: Path, infisical: FakeInfisical) -> None:
    infisical.folders[("proj-uuid", "prod", "/web")] = {"A": "1"}
    infisical.folders[("proj-uuid", "prod", "/db")] = {"B": "2"}
    with patch("psi.setup.time.sleep") as slept:
        run_setup(_settings(tmp_path, {"web": "/web", "db": "/db"}))
    assert not slept.called


@pytest.mark.usefixtures("podman")
def test_the_runs_session_closes_when_a_workload_fails(
    tmp_path: Path, infisical: FakeInfisical
) -> None:
    infisical.client_secret = "rotated"
    closed: list[InfisicalProvider] = []
    real_close = InfisicalProvider.close

    def close(provider: InfisicalProvider) -> None:
        closed.append(provider)
        real_close(provider)

    with (
        patch.object(InfisicalProvider, "close", close),
        pytest.raises(InfisicalAPIError, match="HTTP 401"),
    ):
        run_setup(_settings(tmp_path, {"web": "/web", "db": "/db"}))
    assert len(closed) == 1


def test_a_negative_delay_is_refused() -> None:
    with pytest.raises(ValidationError, match="greater than or equal to 0"):
        InfisicalConfig.model_validate({"fetch_delay_ms": -1})
