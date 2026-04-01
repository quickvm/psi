"""Infisical provider models — auth, projects, TLS, import."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from pathlib import Path  # noqa: TCH003 — Pydantic needs Path at runtime

from pydantic import BaseModel, model_validator


class AuthMethod(StrEnum):
    """Supported Infisical authentication methods."""

    AWS_IAM = "aws-iam"
    UNIVERSAL = "universal-auth"
    GCP = "gcp"
    AZURE = "azure"


class AuthConfig(BaseModel):
    """Authentication configuration for Infisical."""

    method: AuthMethod
    identity_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None

    @model_validator(mode="after")
    def validate_auth_fields(self) -> AuthConfig:
        match self.method:
            case AuthMethod.UNIVERSAL:
                if not self.client_id or not self.client_secret:
                    msg = "universal-auth requires client_id and client_secret"
                    raise ValueError(msg)
            case AuthMethod.AWS_IAM | AuthMethod.GCP | AuthMethod.AZURE:
                if not self.identity_id:
                    msg = f"{self.method} requires identity_id"
                    raise ValueError(msg)
        return self

    def cache_key(self) -> str:
        """Unique hash for token cache file keying."""
        raw = f"{self.method}:{self.identity_id or ''}:{self.client_id or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]


class TokenSettings(BaseModel):
    """Token cache configuration."""

    ttl: int = 300


class TokenCache(BaseModel):
    """Cached authentication token."""

    access_token: str
    expires_at: float


class ProjectConfig(BaseModel):
    """An Infisical project with optional auth override."""

    id: str
    environment: str = "prod"
    auth: AuthConfig | None = None


class SecretSource(BaseModel):
    """A source of secrets: a project + folder path."""

    project: str
    path: str = "/"


class InfisicalConfig(BaseModel):
    """Configuration for the Infisical provider."""

    api_url: str = "https://app.infisical.com"
    auth: AuthConfig | None = None
    verify_ssl: bool = True
    ca_cert: Path | None = None
    token: TokenSettings = TokenSettings()
    projects: dict[str, ProjectConfig] = {}
    tls: TlsConfig | None = None

    @model_validator(mode="after")
    def validate_auth_coverage(self) -> InfisicalConfig:
        """Ensure every project has auth (own or global fallback)."""
        if self.auth:
            return self
        missing = [name for name, proj in self.projects.items() if not proj.auth]
        if missing:
            msg = (
                f"No global auth and no per-project auth for: "
                f"{', '.join(missing)}. Either set top-level 'auth' "
                f"or add 'auth' to each project."
            )
            raise ValueError(msg)
        return self


def resolve_auth(
    project: ProjectConfig,
    config: InfisicalConfig,
) -> AuthConfig:
    """Resolve auth for a project: project-level auth wins, then global."""
    auth = project.auth or config.auth
    if not auth:
        msg = f"No auth configured for project '{project.id}'"
        raise ValueError(msg)
    return auth


# --- TLS certificate models ---


class AltNameType(StrEnum):
    """Subject alternative name types for TLS certificates."""

    DNS_NAME = "dns_name"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    URI = "uri"


class KeyAlgorithm(StrEnum):
    """Key algorithms for TLS certificate issuance."""

    RSA_2048 = "RSA_2048"
    RSA_4096 = "RSA_4096"
    EC_PRIME256V1 = "EC_prime256v1"
    EC_SECP384R1 = "EC_secp384r1"


class AltName(BaseModel):
    """A subject alternative name entry."""

    type: AltNameType
    value: str


class CertOutput(BaseModel):
    """Output paths for certificate PEM files."""

    cert: Path
    key: Path
    chain: Path
    ca: Path | None = None
    mode: str = "0640"


class CertificateConfig(BaseModel):
    """Configuration for a single TLS certificate."""

    project: str
    profile_id: str
    common_name: str
    alt_names: list[AltName] = []
    ttl: str = "90d"
    key_algorithm: KeyAlgorithm | None = None
    output: CertOutput
    renew_before: str = "30d"
    hooks: list[str] = []


class TlsConfig(BaseModel):
    """TLS certificate management configuration."""

    certificates: dict[str, CertificateConfig]


class CertState(BaseModel):
    """Persisted state for an issued certificate."""

    certificate_id: str
    serial_number: str
    common_name: str
    issued_at: float
    expires_at: float
    profile_id: str


class CertStatusInfo(BaseModel):
    """Status of a single TLS certificate."""

    name: str
    common_name: str
    serial_number: str
    issued: str
    expires: str
    days_left: int
    status: str


# --- Import models ---


class ConflictPolicy(StrEnum):
    """How to handle secrets that already exist in Infisical."""

    SKIP = "skip"
    OVERWRITE = "overwrite"
    FAIL = "fail"


class ImportSecret(BaseModel):
    """A secret key-value pair read from an import source."""

    key: str
    value: str
    source: str = ""


class ImportOutcome(StrEnum):
    """Result of importing a single secret."""

    CREATED = "created"
    SKIPPED = "skipped"
    OVERWRITTEN = "overwritten"
    FAILED = "failed"
    DRY_RUN = "dry_run"


class ImportSecretResult(BaseModel):
    """Result of importing a single secret."""

    key: str
    outcome: ImportOutcome
    detail: str = ""


class ImportResult(BaseModel):
    """Summary of an import operation."""

    total: int
    created: int
    skipped: int
    overwritten: int
    failed: int
    secrets: list[ImportSecretResult]
