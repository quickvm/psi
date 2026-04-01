"""Shared test fixtures."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from psi.models import SecretSource, WorkloadConfig
from psi.providers.infisical.models import (
    AuthConfig,
    AuthMethod,
    CertificateConfig,
    CertOutput,
    CertState,
    ProjectConfig,
    TlsConfig,
    TokenSettings,
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def auth_aws() -> AuthConfig:
    return AuthConfig(method=AuthMethod.AWS_IAM, identity_id="test-identity")


@pytest.fixture
def auth_universal() -> AuthConfig:
    return AuthConfig(
        method=AuthMethod.UNIVERSAL,
        client_id="test-client",
        client_secret="test-secret",
    )


@pytest.fixture
def project_config() -> ProjectConfig:
    return ProjectConfig(id="proj-uuid-123", environment="prod")


@pytest.fixture
def workload_config() -> WorkloadConfig:
    return WorkloadConfig(
        secrets=[
            SecretSource(project="myproject", path="/app"),
            SecretSource(project="myproject", path="/shared"),
        ]
    )


@pytest.fixture
def tls_config(tmp_path: Path) -> TlsConfig:
    return TlsConfig(
        certificates={
            "web": CertificateConfig(
                project="myproject",
                profile_id="profile-uuid",
                common_name="web.example.com",
                ttl="90d",
                renew_before="30d",
                output=CertOutput(
                    cert=tmp_path / "tls" / "cert.pem",
                    key=tmp_path / "tls" / "key.pem",
                    chain=tmp_path / "tls" / "chain.pem",
                ),
            ),
        }
    )


@pytest.fixture
def cert_state() -> CertState:
    return CertState(
        certificate_id="cert-uuid-123",
        serial_number="AABBCCDD",
        common_name="web.example.com",
        issued_at=1700000000.0,
        expires_at=1707776000.0,
        profile_id="profile-uuid",
    )


@pytest.fixture
def sample_settings_dict(tmp_path: Path) -> dict:
    """Minimal config dict for constructing PsiSettings (new provider format)."""
    return {
        "state_dir": str(tmp_path / "state"),
        "systemd_dir": str(tmp_path / "systemd"),
        "providers": {
            "infisical": {
                "api_url": "https://infisical.test",
                "auth": {
                    "method": "universal-auth",
                    "client_id": "cid",
                    "client_secret": "csec",
                },
                "token": {"ttl": 60},
                "projects": {
                    "myproject": {"id": "proj-uuid-123", "environment": "prod"},
                },
            },
        },
        "workloads": {
            "myapp": {
                "provider": "infisical",
                "secrets": [{"project": "myproject", "path": "/app"}],
            },
        },
    }


@pytest.fixture
def token_settings() -> TokenSettings:
    return TokenSettings(ttl=60)
