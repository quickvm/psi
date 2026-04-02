"""Tests for psi.models and psi.providers.infisical.models."""

from __future__ import annotations

import json
import unittest.mock

import pytest

from psi.models import DeployMode, SecretSource, SystemdScope, WorkloadConfig, detect_scope
from psi.provider import parse_mapping
from psi.providers.infisical.models import (
    AuthConfig,
    AuthMethod,
)


class TestAuthConfig:
    def test_universal_valid(self) -> None:
        auth = AuthConfig(
            method=AuthMethod.UNIVERSAL,
            client_id="cid",
            client_secret="csec",
        )
        assert auth.method == AuthMethod.UNIVERSAL

    def test_universal_missing_client_id(self) -> None:
        with pytest.raises(ValueError, match="client_id and client_secret"):
            AuthConfig(method=AuthMethod.UNIVERSAL, client_secret="csec")

    def test_universal_missing_client_secret(self) -> None:
        with pytest.raises(ValueError, match="client_id and client_secret"):
            AuthConfig(method=AuthMethod.UNIVERSAL, client_id="cid")

    def test_aws_iam_valid(self) -> None:
        auth = AuthConfig(method=AuthMethod.AWS_IAM, identity_id="id123")
        assert auth.identity_id == "id123"

    def test_aws_iam_missing_identity(self) -> None:
        with pytest.raises(ValueError, match="requires identity_id"):
            AuthConfig(method=AuthMethod.AWS_IAM)

    def test_gcp_missing_identity(self) -> None:
        with pytest.raises(ValueError, match="requires identity_id"):
            AuthConfig(method=AuthMethod.GCP)

    def test_azure_missing_identity(self) -> None:
        with pytest.raises(ValueError, match="requires identity_id"):
            AuthConfig(method=AuthMethod.AZURE)

    def test_cache_key_deterministic(self) -> None:
        auth = AuthConfig(method=AuthMethod.AWS_IAM, identity_id="id123")
        assert auth.cache_key() == auth.cache_key()
        assert len(auth.cache_key()) == 12

    def test_cache_key_differs_by_method(self) -> None:
        a = AuthConfig(method=AuthMethod.AWS_IAM, identity_id="id123")
        b = AuthConfig(method=AuthMethod.GCP, identity_id="id123")
        assert a.cache_key() != b.cache_key()

    def test_cache_key_differs_by_identity(self) -> None:
        a = AuthConfig(method=AuthMethod.AWS_IAM, identity_id="id1")
        b = AuthConfig(method=AuthMethod.AWS_IAM, identity_id="id2")
        assert a.cache_key() != b.cache_key()


class TestParseMapping:
    def test_infisical_mapping(self) -> None:
        raw = json.dumps(
            {
                "provider": "infisical",
                "project": "myproj",
                "path": "/app",
                "key": "DB_HOST",
            }
        )
        data = parse_mapping(raw)
        assert data["provider"] == "infisical"
        assert data["project"] == "myproj"

    def test_nitrokeyhsm_mapping(self) -> None:
        raw = json.dumps({"provider": "nitrokeyhsm", "blob": "base64data"})
        data = parse_mapping(raw)
        assert data["provider"] == "nitrokeyhsm"

    def test_invalid_json(self) -> None:
        with pytest.raises(ValueError, match="not JSON"):
            parse_mapping("not-json")

    def test_missing_provider(self) -> None:
        with pytest.raises(ValueError, match="missing 'provider'"):
            parse_mapping('{"key": "value"}')


class TestWorkloadConfigTemplateUnit:
    """Template unit workloads use @ in the config key."""

    def test_template_workload_name(self) -> None:
        wl = WorkloadConfig(
            provider="infisical",
            secrets=[SecretSource(project="myproject", path="/app")],
        )
        workloads = {"windmill-worker@": wl}
        assert "windmill-worker@" in workloads

    def test_template_workload_in_dict(self) -> None:
        wl = WorkloadConfig(
            provider="infisical",
            secrets=[
                SecretSource(project="homelab", path="/windmill"),
                SecretSource(project="homelab", path="/windmill/worker"),
            ],
        )
        assert len(wl.secrets) == 2
        assert wl.secrets[0].path == "/windmill"
        assert wl.secrets[1].path == "/windmill/worker"


class TestDeployMode:
    def test_values(self) -> None:
        assert DeployMode.NATIVE == "native"
        assert DeployMode.CONTAINER == "container"


class TestSystemdScope:
    def test_values(self) -> None:
        assert SystemdScope.SYSTEM == "system"
        assert SystemdScope.USER == "user"

    def test_detect_scope_root(self) -> None:
        with unittest.mock.patch("os.getuid", return_value=0):
            assert detect_scope() == SystemdScope.SYSTEM

    def test_detect_scope_non_root(self) -> None:
        with unittest.mock.patch("os.getuid", return_value=1000):
            assert detect_scope() == SystemdScope.USER
