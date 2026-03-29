"""Tests for psi.models."""

from __future__ import annotations

import pytest

from psi.models import (
    AuthConfig,
    AuthMethod,
    DeployMode,
    SecretMapping,
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


class TestSecretMapping:
    def test_serialize(self) -> None:
        m = SecretMapping(
            project_alias="infra",
            secret_path="/app",
            secret_name="DB_HOST",
        )
        assert m.serialize() == "infra:/app:DB_HOST"

    def test_deserialize(self) -> None:
        m = SecretMapping.deserialize("infra:/app:DB_HOST")
        assert m.project_alias == "infra"
        assert m.secret_path == "/app"
        assert m.secret_name == "DB_HOST"

    def test_roundtrip(self) -> None:
        original = SecretMapping(
            project_alias="proj",
            secret_path="/deep/path",
            secret_name="KEY",
        )
        restored = SecretMapping.deserialize(original.serialize())
        assert restored == original

    def test_deserialize_with_colons_in_path(self) -> None:
        m = SecretMapping.deserialize("proj:/path:SECRET:WITH:COLONS")
        assert m.project_alias == "proj"
        assert m.secret_path == "/path"
        assert m.secret_name == "SECRET:WITH:COLONS"

    def test_deserialize_invalid_no_colons(self) -> None:
        with pytest.raises(ValueError, match="Invalid mapping format"):
            SecretMapping.deserialize("no-colons-here")

    def test_deserialize_invalid_one_colon(self) -> None:
        with pytest.raises(ValueError, match="Invalid mapping format"):
            SecretMapping.deserialize("only:one")

    def test_deserialize_strips_whitespace(self) -> None:
        m = SecretMapping.deserialize("  proj:/path:KEY  \n")
        assert m.project_alias == "proj"
        assert m.secret_name == "KEY"


class TestDeployMode:
    def test_values(self) -> None:
        assert DeployMode.NATIVE == "native"
        assert DeployMode.CONTAINER == "container"
