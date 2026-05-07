"""Tests for psi.setup drop-in generation and provider filtering."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import httpx
import pytest

from psi.errors import ProviderError
from psi.models import SecretSource, SystemdScope, WorkloadConfig
from psi.providers.infisical import InfisicalProvider
from psi.settings import PsiSettings
from psi.setup import (
    _RETRY_DELAYS,
    _check_orphans,
    _check_workload_drift,
    _fetch_and_register_infisical,
    _generate_drop_in,
    _is_retryable,
    _list_secrets_cached,
    _register_secrets,
    _setup_infisical_workload,
    run_setup,
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

        def mock_fetch(settings, workload_name, cache_updates, drift, **kwargs):
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
            _setup_infisical_workload(
                settings,
                "myapp",
                {},
                [],
                provider=MagicMock(),
                list_cache={},
            )

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
            _setup_infisical_workload(
                settings,
                "myapp",
                {},
                [],
                provider=MagicMock(),
                list_cache={},
            )

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
            _setup_infisical_workload(
                settings,
                "myapp",
                {},
                [],
                provider=MagicMock(),
                list_cache={},
            )

    def test_auth_502_retries_then_raises_provider_error(self, tmp_path: Path) -> None:
        """Auth endpoint 502 wrapped as ProviderError is retried via __cause__."""
        request = httpx.Request("POST", "http://test/api/v1/auth/universal-auth/login")
        response = httpx.Response(502, request=request)
        call_count = 0

        def mock_fetch(settings, workload_name, cache_updates, drift, **kwargs):
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
            _setup_infisical_workload(
                settings,
                "myapp",
                {},
                [],
                provider=MagicMock(),
                list_cache={},
            )

        assert call_count == len(_RETRY_DELAYS) + 1

    def test_auth_401_wrapped_as_provider_error_not_retried(self, tmp_path: Path) -> None:
        """Auth 401 wrapped as ProviderError is non-retryable — fails immediately."""
        request = httpx.Request("POST", "http://test/api/v1/auth/universal-auth/login")
        response = httpx.Response(401, request=request)
        call_count = 0

        def mock_fetch(settings, workload_name, cache_updates, drift, **kwargs):
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
            _setup_infisical_workload(
                settings,
                "myapp",
                {},
                [],
                provider=MagicMock(),
                list_cache={},
            )

        assert call_count == 1


class TestRegisterSecrets:
    def test_calls_podman_api_with_delete_then_create_per_secret(self, tmp_path: Path) -> None:
        """_register_secrets issues delete+create for each mapping."""
        delete_resp = httpx.Response(204, request=httpx.Request("DELETE", "http://x"))
        create_resp = httpx.Response(
            200,
            json={"ID": "ignored"},
            request=httpx.Request("POST", "http://x"),
        )

        settings = _make_settings(tmp_path)

        with patch("psi.setup.httpx.Client") as mock_client_cls:
            client = mock_client_cls.return_value.__enter__.return_value
            client.delete.return_value = delete_resp
            client.post.return_value = create_resp

            _register_secrets(settings, "myapp", {"DB_URL": "{}", "API_KEY": "{}"})

        assert client.delete.call_count == 2
        assert client.post.call_count == 2
        assert (
            "myapp--DB_URL" in client.delete.call_args_list[0].args[0]
            or "myapp--DB_URL" in client.delete.call_args_list[1].args[0]
        )


def _shell_secret_stub(name: str) -> dict:
    return {
        "ID": name,
        "Spec": {
            "Name": name,
            "Driver": {"Name": "shell", "Options": {}},
        },
    }


class TestCheckWorkloadDrift:
    def test_empty_when_podman_matches_fetch(self) -> None:
        merged = {"DB_URL": "{}", "API_KEY": "{}"}
        podman_secrets = [
            _shell_secret_stub("myapp--DB_URL"),
            _shell_secret_stub("myapp--API_KEY"),
        ]
        with patch("psi.setup._list_podman_shell_secrets", return_value=podman_secrets):
            assert _check_workload_drift("myapp", merged) == []

    def test_returns_stale_podman_secrets_sorted(self) -> None:
        merged = {"DB_URL": "{}"}
        podman_secrets = [
            _shell_secret_stub("myapp--DB_URL"),
            _shell_secret_stub("myapp--NUM_WORKERS"),
            _shell_secret_stub("myapp--MODE"),
        ]
        with patch("psi.setup._list_podman_shell_secrets", return_value=podman_secrets):
            drift = _check_workload_drift("myapp", merged)
        assert drift == ["myapp--MODE", "myapp--NUM_WORKERS"]

    def test_ignores_secrets_in_other_workload_namespaces(self) -> None:
        merged = {"DB_URL": "{}"}
        podman_secrets = [
            _shell_secret_stub("myapp--DB_URL"),
            _shell_secret_stub("other-workload--MODE"),
            _shell_secret_stub("myapp-extra--DB_URL"),
        ]
        with patch("psi.setup._list_podman_shell_secrets", return_value=podman_secrets):
            assert _check_workload_drift("myapp", merged) == []

    def test_template_workload_prefix_handled(self) -> None:
        merged = {"DB_HOST": "{}"}
        podman_secrets = [
            _shell_secret_stub("windmill-worker@--DB_HOST"),
            _shell_secret_stub("windmill-worker@--STALE_KEY"),
        ]
        with patch("psi.setup._list_podman_shell_secrets", return_value=podman_secrets):
            drift = _check_workload_drift("windmill-worker@", merged)
        assert drift == ["windmill-worker@--STALE_KEY"]

    def test_podman_api_error_returns_empty(self) -> None:
        with patch(
            "psi.setup._list_podman_shell_secrets",
            side_effect=httpx.ConnectError("refused"),
        ):
            assert _check_workload_drift("myapp", {"DB_URL": "{}"}) == []


class TestRunSetupDriftExit:
    def test_raises_drift_detected_error_when_drift_accumulates(self, tmp_path: Path) -> None:
        from psi.errors import DriftDetectedError

        settings = _make_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/app")],
                ),
            },
        )

        def mock_fetch(settings, workload_name, values_by_mapping, drift, **kwargs):
            drift.append(f"{workload_name}--STALE_KEY")

        with (
            patch("psi.setup._fetch_and_register_infisical", side_effect=mock_fetch),
            patch("psi.setup.daemon_reload"),
            pytest.raises(DriftDetectedError, match="1 Podman secret"),
        ):
            run_setup(settings)

    def test_no_raise_when_drift_is_empty(self, tmp_path: Path) -> None:
        settings = _make_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/app")],
                ),
            },
        )

        def mock_fetch(settings, workload_name, values_by_mapping, drift, **kwargs):
            pass

        with (
            patch("psi.setup._fetch_and_register_infisical", side_effect=mock_fetch),
            patch("psi.setup.daemon_reload"),
        ):
            run_setup(settings)

    def test_aggregates_drift_across_workloads(self, tmp_path: Path) -> None:
        from psi.errors import DriftDetectedError

        settings = _make_settings(
            tmp_path,
            workloads={
                "a": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/a")],
                ),
                "b": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/b")],
                ),
            },
        )

        def mock_fetch(settings, workload_name, values_by_mapping, drift, **kwargs):
            drift.append(f"{workload_name}--STALE")

        with (
            patch("psi.setup._fetch_and_register_infisical", side_effect=mock_fetch),
            patch("psi.setup.daemon_reload"),
            pytest.raises(DriftDetectedError, match="2 Podman secret"),
        ):
            run_setup(settings)

    def test_daemon_reload_runs_before_raise(self, tmp_path: Path) -> None:
        """Drift is reported at the end — drop-ins and systemd reload happen first."""
        from psi.errors import DriftDetectedError

        settings = _make_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/app")],
                ),
            },
        )

        def mock_fetch(settings, workload_name, values_by_mapping, drift, **kwargs):
            drift.append("myapp--STALE")

        with (
            patch("psi.setup._fetch_and_register_infisical", side_effect=mock_fetch),
            patch("psi.setup.daemon_reload") as mock_reload,
            pytest.raises(DriftDetectedError),
        ):
            run_setup(settings)

        mock_reload.assert_called_once()


class TestCheckOrphans:
    """Detection of Podman shell secrets with no backing mapping file."""

    def test_no_orphans_when_all_have_mappings(self, tmp_path: Path) -> None:
        settings = _make_settings(tmp_path)
        settings.state_dir.mkdir(parents=True)
        (settings.state_dir / "abc123").write_text("{}")
        podman_secrets = [
            {"ID": "abc123", "Spec": {"Name": "myapp--K"}},
        ]
        with patch("psi.setup._list_podman_shell_secrets", return_value=podman_secrets):
            assert _check_orphans(settings) == []

    def test_returns_names_for_secrets_without_mappings(self, tmp_path: Path) -> None:
        settings = _make_settings(tmp_path)
        settings.state_dir.mkdir(parents=True)
        (settings.state_dir / "have-mapping").write_text("{}")
        podman_secrets = [
            {"ID": "have-mapping", "Spec": {"Name": "myapp--PRESENT"}},
            {"ID": "missing-id-1", "Spec": {"Name": "INFISICAL_ENCRYPTION_KEY"}},
            {"ID": "missing-id-2", "Spec": {"Name": "INFISICAL_AUTH_SECRET"}},
        ]
        with patch("psi.setup._list_podman_shell_secrets", return_value=podman_secrets):
            assert _check_orphans(settings) == [
                "INFISICAL_AUTH_SECRET",
                "INFISICAL_ENCRYPTION_KEY",
            ]

    def test_returns_empty_when_podman_unreachable(self, tmp_path: Path) -> None:
        settings = _make_settings(tmp_path)
        with patch(
            "psi.setup._list_podman_shell_secrets",
            side_effect=httpx.ConnectError("connection refused"),
        ):
            assert _check_orphans(settings) == []


class TestRunSetupOrphanExit:
    def test_raises_orphaned_secrets_error_when_orphan_present(self, tmp_path: Path) -> None:
        from psi.errors import OrphanedSecretsError

        settings = _make_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/app")],
                ),
            },
        )

        def mock_fetch(settings, workload_name, values_by_mapping, drift, **kwargs):
            pass

        with (
            patch("psi.setup._fetch_and_register_infisical", side_effect=mock_fetch),
            patch("psi.setup.daemon_reload"),
            patch("psi.setup._check_orphans", return_value=["INFISICAL_ENCRYPTION_KEY"]),
            pytest.raises(OrphanedSecretsError, match="1 Podman shell"),
        ):
            run_setup(settings)

    def test_orphan_takes_precedence_over_drift(self, tmp_path: Path) -> None:
        from psi.errors import OrphanedSecretsError

        settings = _make_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/app")],
                ),
            },
        )

        def mock_fetch(settings, workload_name, values_by_mapping, drift, **kwargs):
            drift.append("myapp--STALE")

        with (
            patch("psi.setup._fetch_and_register_infisical", side_effect=mock_fetch),
            patch("psi.setup.daemon_reload"),
            patch("psi.setup._check_orphans", return_value=["INFISICAL_ENCRYPTION_KEY"]),
            pytest.raises(OrphanedSecretsError, match="1 drift"),
        ):
            run_setup(settings)

    def test_no_raise_when_orphans_empty(self, tmp_path: Path) -> None:
        settings = _make_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/app")],
                ),
            },
        )

        def mock_fetch(settings, workload_name, values_by_mapping, drift, **kwargs):
            pass

        with (
            patch("psi.setup._fetch_and_register_infisical", side_effect=mock_fetch),
            patch("psi.setup.daemon_reload"),
            patch("psi.setup._check_orphans", return_value=[]),
        ):
            run_setup(settings)


class TestListSecretsCached:
    """Memoization helper: two calls with the same key share one fetch."""

    def _fetch(
        self,
        client: MagicMock,
        memo: dict,
        *,
        path: str = "/app",
        recursive: bool = False,
        expand_references: bool = False,
        include_imports: bool = False,
    ) -> list[dict]:
        return _list_secrets_cached(
            client,
            "tok",
            "proj",
            "prod",
            path,
            recursive=recursive,
            expand_references=expand_references,
            include_imports=include_imports,
            memo=memo,
        )

    def test_first_call_hits_client(self) -> None:
        client = MagicMock()
        client.list_secrets.return_value = [{"secretKey": "K", "secretValue": "v"}]
        memo: dict = {}

        result = self._fetch(client, memo)

        assert result == [{"secretKey": "K", "secretValue": "v"}]
        assert client.list_secrets.call_count == 1

    def test_repeat_call_serves_from_memo(self) -> None:
        client = MagicMock()
        client.list_secrets.return_value = [{"secretKey": "K"}]
        memo: dict = {}

        for _ in range(3):
            self._fetch(client, memo)

        assert client.list_secrets.call_count == 1

    def test_distinct_path_distinct_entry(self) -> None:
        client = MagicMock()
        client.list_secrets.return_value = []
        memo: dict = {}

        self._fetch(client, memo, path="/a")
        self._fetch(client, memo, path="/b")

        assert client.list_secrets.call_count == 2

    def test_distinct_recursive_distinct_entry(self) -> None:
        client = MagicMock()
        client.list_secrets.return_value = []
        memo: dict = {}

        self._fetch(client, memo, recursive=False)
        self._fetch(client, memo, recursive=True)

        assert client.list_secrets.call_count == 2

    def test_distinct_expand_references_distinct_entry(self) -> None:
        client = MagicMock()
        client.list_secrets.return_value = []
        memo: dict = {}

        self._fetch(client, memo, expand_references=False)
        self._fetch(client, memo, expand_references=True)

        assert client.list_secrets.call_count == 2


class TestFetchAndRegisterFlagPassthrough:
    """SecretSource flags reach InfisicalClient.list_secrets unchanged."""

    def _mock_provider(self) -> MagicMock:
        mock_client = MagicMock()
        mock_client.ensure_token.return_value = "tok"
        mock_client.list_secrets.return_value = []
        provider = MagicMock()
        provider._client = mock_client
        return provider

    def test_default_source_sends_false_false(self, tmp_path: Path) -> None:
        provider = self._mock_provider()
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
            patch("psi.setup._register_secrets"),
            patch("psi.setup._generate_drop_in"),
            patch("psi.setup._check_workload_drift", return_value=[]),
        ):
            _fetch_and_register_infisical(
                settings,
                "myapp",
                {},
                [],
                provider=provider,
                list_cache={},
            )

        kwargs = provider._client.list_secrets.call_args.kwargs
        assert kwargs["expand_references"] is False
        assert kwargs["include_imports"] is False

    def test_opted_in_source_sends_true_true(self, tmp_path: Path) -> None:
        provider = self._mock_provider()
        settings = _make_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(
                    provider="infisical",
                    secrets=[
                        SecretSource(
                            project="myproject",
                            path="/app",
                            expand_references=True,
                            include_imports=True,
                        ),
                    ],
                ),
            },
        )

        with (
            patch("psi.setup._register_secrets"),
            patch("psi.setup._generate_drop_in"),
            patch("psi.setup._check_workload_drift", return_value=[]),
        ):
            _fetch_and_register_infisical(
                settings,
                "myapp",
                {},
                [],
                provider=provider,
                list_cache={},
            )

        kwargs = provider._client.list_secrets.call_args.kwargs
        assert kwargs["expand_references"] is True
        assert kwargs["include_imports"] is True

    def test_shared_memo_dedupes_across_workloads(self, tmp_path: Path) -> None:
        """Two workloads with the same source share one list_secrets call."""
        provider = self._mock_provider()
        settings = _make_settings(
            tmp_path,
            workloads={
                "a": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/shared")],
                ),
                "b": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/shared")],
                ),
            },
        )
        list_cache: dict = {}

        with (
            patch("psi.setup._register_secrets"),
            patch("psi.setup._generate_drop_in"),
            patch("psi.setup._check_workload_drift", return_value=[]),
        ):
            _fetch_and_register_infisical(
                settings,
                "a",
                {},
                [],
                provider=provider,
                list_cache=list_cache,
            )
            _fetch_and_register_infisical(
                settings,
                "b",
                {},
                [],
                provider=provider,
                list_cache=list_cache,
            )

        assert provider._client.list_secrets.call_count == 1


class TestSetupRetryReusesMemo:
    """Workload-level retry replays through the memo, not the network."""

    def test_retry_does_not_re_call_list_secrets(self, tmp_path: Path) -> None:
        mock_client = MagicMock()
        mock_client.ensure_token.return_value = "tok"
        mock_client.list_secrets.return_value = []
        provider = MagicMock()
        provider._client = mock_client

        settings = _make_settings(
            tmp_path,
            workloads={
                "myapp": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/app")],
                ),
            },
        )

        attempts = 0
        original = _register_secrets

        def flaky_register(s, w, secrets):
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise httpx.ConnectError("transient")
            return original(s, w, secrets)

        with (
            patch("psi.setup._register_secrets", side_effect=flaky_register),
            patch("psi.setup._generate_drop_in"),
            patch("psi.setup._check_workload_drift", return_value=[]),
            patch("psi.setup.time.sleep"),
        ):
            _setup_infisical_workload(
                settings,
                "myapp",
                {},
                [],
                provider=provider,
                list_cache={},
            )

        assert attempts == 2
        assert mock_client.list_secrets.call_count == 1


class TestRunSetupProviderLifecycle:
    """One InfisicalProvider opened/closed per run, not per workload."""

    def test_provider_opened_once_across_workloads(self, tmp_path: Path) -> None:
        settings = _make_settings(
            tmp_path,
            workloads={
                "a": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/a")],
                ),
                "b": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/b")],
                ),
            },
        )

        mock_provider_instance = MagicMock()
        mock_provider_class = MagicMock(return_value=mock_provider_instance)

        def noop_fetch(s, w, vbm, drift, **kwargs):
            pass

        with (
            patch("psi.providers.infisical.InfisicalProvider", mock_provider_class),
            patch("psi.setup._fetch_and_register_infisical", side_effect=noop_fetch),
            patch("psi.setup.daemon_reload"),
            patch("psi.setup._check_orphans", return_value=[]),
        ):
            run_setup(settings)

        assert mock_provider_class.call_count == 1
        assert mock_provider_instance.open.call_count == 1
        assert mock_provider_instance.close.call_count == 1

    def test_provider_not_opened_for_hsm_only(self, tmp_path: Path) -> None:
        settings = _make_settings(
            tmp_path,
            workloads={
                "vault": WorkloadConfig(provider="nitrokeyhsm"),
            },
            providers={"nitrokeyhsm": {}},
        )

        mock_provider_class = MagicMock()

        with (
            patch("psi.providers.infisical.InfisicalProvider", mock_provider_class),
            patch("psi.setup.daemon_reload"),
            patch("psi.setup._check_orphans", return_value=[]),
        ):
            run_setup(settings)

        assert mock_provider_class.call_count == 0


class TestRunSetupPacing:
    """fetch_delay_ms inserts time.sleep between consecutive Infisical fetches."""

    def _settings_two_infisical(self, tmp_path: Path, fetch_delay_ms: int) -> PsiSettings:
        return _make_settings(
            tmp_path,
            workloads={
                "a": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/a")],
                ),
                "b": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/b")],
                ),
            },
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
                    "fetch_delay_ms": fetch_delay_ms,
                },
            },
        )

    def _run(self, settings: PsiSettings) -> MagicMock:
        mock_sleep = MagicMock()
        with (
            patch("psi.providers.infisical.InfisicalProvider", MagicMock()),
            patch("psi.setup._fetch_and_register_infisical", side_effect=lambda *a, **k: None),
            patch("psi.setup.daemon_reload"),
            patch("psi.setup._check_orphans", return_value=[]),
            patch("psi.setup.time.sleep", mock_sleep),
        ):
            run_setup(settings)
        return mock_sleep

    def test_no_sleep_when_delay_zero(self, tmp_path: Path) -> None:
        mock_sleep = self._run(self._settings_two_infisical(tmp_path, fetch_delay_ms=0))
        assert mock_sleep.call_count == 0

    def test_sleep_between_two_infisical_workloads(self, tmp_path: Path) -> None:
        mock_sleep = self._run(self._settings_two_infisical(tmp_path, fetch_delay_ms=250))
        assert mock_sleep.call_args_list == [((0.25,), {})]

    def test_no_sleep_for_single_workload(self, tmp_path: Path) -> None:
        settings = _make_settings(
            tmp_path,
            workloads={
                "only": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/x")],
                ),
            },
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
                    "fetch_delay_ms": 500,
                },
            },
        )
        mock_sleep = self._run(settings)
        assert mock_sleep.call_count == 0

    def test_no_sleep_when_hsm_intervenes(self, tmp_path: Path) -> None:
        """HSM workload between two Infisical workloads breaks the consecutive run."""
        settings = _make_settings(
            tmp_path,
            workloads={
                "a": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/a")],
                ),
                "vault": WorkloadConfig(provider="nitrokeyhsm"),
                "b": WorkloadConfig(
                    provider="infisical",
                    secrets=[SecretSource(project="myproject", path="/b")],
                ),
            },
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
                    "fetch_delay_ms": 250,
                },
                "nitrokeyhsm": {},
            },
        )
        mock_sleep = self._run(settings)
        assert mock_sleep.call_count == 0
