"""Tests for psi.setup drop-in generation and provider filtering."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import httpx
import pytest

from psi.errors import ProviderError
from psi.models import SecretSource, SystemdScope, WorkloadConfig
from psi.providers.infisical import InfisicalProvider
from psi.settings import PsiSettings
from psi.setup import (
    _RETRY_DELAYS,
    _generate_drop_in,
    _is_retryable,
    _prune_stale_cache_entries,
    _register_secrets,
    _setup_infisical_workload,
)

if TYPE_CHECKING:
    from pathlib import Path


def _make_settings(
    tmp_path: Path,
    workloads: dict[str, WorkloadConfig] | None = None,
    providers: dict | None = None,
) -> PsiSettings:
    """Build a minimal settings object."""
    if providers is None:
        providers = {
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
        }
    return PsiSettings(
        state_dir=tmp_path / "state",
        systemd_dir=tmp_path / "systemd",
        providers=providers,
        workloads=workloads or {},
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


class TestIsRetryable:
    def test_connect_error_is_retryable(self) -> None:
        assert _is_retryable(httpx.ConnectError("refused"))

    def test_502_is_retryable(self) -> None:
        request = httpx.Request("GET", "http://test")
        response = httpx.Response(502, request=request)
        exc = httpx.HTTPStatusError("bad gateway", request=request, response=response)
        assert _is_retryable(exc)

    def test_503_is_retryable(self) -> None:
        request = httpx.Request("GET", "http://test")
        response = httpx.Response(503, request=request)
        exc = httpx.HTTPStatusError("unavailable", request=request, response=response)
        assert _is_retryable(exc)

    def test_404_is_retryable(self) -> None:
        request = httpx.Request("GET", "http://test")
        response = httpx.Response(404, request=request)
        exc = httpx.HTTPStatusError("not found", request=request, response=response)
        assert _is_retryable(exc)

    def test_401_is_not_retryable(self) -> None:
        request = httpx.Request("GET", "http://test")
        response = httpx.Response(401, request=request)
        exc = httpx.HTTPStatusError("unauthorized", request=request, response=response)
        assert not _is_retryable(exc)

    def test_other_exception_is_not_retryable(self) -> None:
        assert not _is_retryable(ValueError("nope"))


class TestSetupRetry:
    def test_retries_on_connect_error_then_succeeds(self, tmp_path: Path) -> None:
        call_count = 0

        def mock_fetch(settings, workload_name, cache_updates):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.ConnectError("refused")

        settings = _make_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/app")],
                ),
            },
        )

        with (
            patch("psi.setup._fetch_and_register_infisical", side_effect=mock_fetch),
            patch("psi.setup.time.sleep"),
        ):
            _setup_infisical_workload(settings, "myapp", {})

        assert call_count == 3

    def test_raises_after_all_retries_exhausted(self, tmp_path: Path) -> None:
        settings = _make_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/app")],
                ),
            },
        )

        with (
            patch(
                "psi.setup._fetch_and_register_infisical",
                side_effect=httpx.ConnectError("refused"),
            ),
            patch("psi.setup.time.sleep"),
            pytest.raises(httpx.ConnectError, match="refused"),
        ):
            _setup_infisical_workload(settings, "myapp", {})

    def test_non_retryable_error_raises_immediately(self, tmp_path: Path) -> None:
        request = httpx.Request("GET", "http://test")
        response = httpx.Response(401, request=request)
        exc = httpx.HTTPStatusError("unauthorized", request=request, response=response)

        settings = _make_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/app")],
                ),
            },
        )

        with (
            patch(
                "psi.setup._fetch_and_register_infisical",
                side_effect=exc,
            ),
            pytest.raises(httpx.HTTPStatusError, match="unauthorized"),
        ):
            _setup_infisical_workload(settings, "myapp", {})

    def test_auth_502_retries_then_raises_provider_error(self, tmp_path: Path) -> None:
        """Auth endpoint 502 wrapped as ProviderError is retried via __cause__."""
        request = httpx.Request("POST", "http://test/api/v1/auth/universal-auth/login")
        response = httpx.Response(502, request=request)
        call_count = 0

        def mock_fetch(settings, workload_name, cache_updates):
            nonlocal call_count
            call_count += 1
            http_err = httpx.HTTPStatusError("502", request=request, response=response)
            raise ProviderError(
                "Infisical authentication failed (HTTP 502): ...",
                provider_name="infisical",
            ) from http_err

        settings = _make_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/app")],
                ),
            },
        )

        with (
            patch("psi.setup._fetch_and_register_infisical", side_effect=mock_fetch),
            patch("psi.setup.time.sleep"),
            pytest.raises(ProviderError, match="authentication failed"),
        ):
            _setup_infisical_workload(settings, "myapp", {})

        assert call_count == len(_RETRY_DELAYS) + 1

    def test_auth_401_wrapped_as_provider_error_not_retried(self, tmp_path: Path) -> None:
        """Auth 401 wrapped as ProviderError is non-retryable — fails immediately."""
        request = httpx.Request("POST", "http://test/api/v1/auth/universal-auth/login")
        response = httpx.Response(401, request=request)
        call_count = 0

        def mock_fetch(settings, workload_name, cache_updates):
            nonlocal call_count
            call_count += 1
            http_err = httpx.HTTPStatusError("401", request=request, response=response)
            raise ProviderError(
                "Infisical authentication failed (HTTP 401): invalid credentials",
                provider_name="infisical",
            ) from http_err

        settings = _make_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/app")],
                ),
            },
        )

        with (
            patch("psi.setup._fetch_and_register_infisical", side_effect=mock_fetch),
            pytest.raises(ProviderError, match="invalid credentials"),
        ):
            _setup_infisical_workload(settings, "myapp", {})

        assert call_count == 1


class TestRegisterSecretsIdMap:
    def test_returns_secret_id_from_podman_api(self, tmp_path: Path) -> None:
        """_register_secrets returns {key: hex_id} for cache keying."""
        delete_resp = httpx.Response(204, request=httpx.Request("DELETE", "http://x"))
        create_resp = httpx.Response(
            200,
            json={"ID": "abc123hex"},
            request=httpx.Request("POST", "http://x"),
        )

        def mock_request(method, url, **kwargs):
            if method == "DELETE":
                return delete_resp
            return create_resp

        settings = _make_settings(tmp_path)

        with patch("psi.setup.httpx.Client") as mock_client_cls:
            client = mock_client_cls.return_value.__enter__.return_value
            client.delete.return_value = delete_resp
            client.post.return_value = create_resp

            id_map = _register_secrets(settings, "myapp", {"DB_URL": "{}"})

        assert id_map == {"DB_URL": "abc123hex"}


class TestPruneStaleCacheEntries:
    def test_drops_entries_not_in_active_podman_ids(self) -> None:
        """Orphaned cache entries from prior setup runs are pruned."""
        from unittest.mock import MagicMock

        cache = MagicMock()
        cache.entry_ids.return_value = ["active1", "stale-old", "active2", "stale-older"]

        podman_secrets = [
            {"ID": "active1", "Spec": {"Name": "x", "Driver": {"Name": "shell"}}},
            {"ID": "active2", "Spec": {"Name": "y", "Driver": {"Name": "shell"}}},
        ]

        with patch("psi.setup._list_podman_shell_secrets", return_value=podman_secrets):
            _prune_stale_cache_entries(cache)

        invalidated = [call.args[0] for call in cache.invalidate.call_args_list]
        assert sorted(invalidated) == ["stale-old", "stale-older"]

    def test_keeps_cache_intact_if_podman_api_unreachable(self) -> None:
        """A Podman API failure should not drop any entries."""
        from unittest.mock import MagicMock

        cache = MagicMock()
        cache.entry_ids.return_value = ["keep1", "keep2"]

        with patch(
            "psi.setup._list_podman_shell_secrets",
            side_effect=httpx.ConnectError("refused"),
        ):
            _prune_stale_cache_entries(cache)

        cache.invalidate.assert_not_called()

    def test_no_op_when_cache_is_already_clean(self) -> None:
        """No invalidate calls when every entry is already in Podman."""
        from unittest.mock import MagicMock

        cache = MagicMock()
        cache.entry_ids.return_value = ["abc", "def"]

        with patch(
            "psi.setup._list_podman_shell_secrets",
            return_value=[
                {"ID": "abc", "Spec": {"Name": "x", "Driver": {"Name": "shell"}}},
                {"ID": "def", "Spec": {"Name": "y", "Driver": {"Name": "shell"}}},
            ],
        ):
            _prune_stale_cache_entries(cache)

        cache.invalidate.assert_not_called()
