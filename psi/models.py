"""Pydantic models for psi configuration and runtime state."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from pathlib import Path  # noqa: TCH003 — Pydantic needs Path at runtime for validation

from pydantic import BaseModel, model_validator


class AuthMethod(StrEnum):
    """Supported Infisical authentication methods."""

    AWS_IAM = "aws-iam"
    UNIVERSAL = "universal-auth"
    GCP = "gcp"
    AZURE = "azure"


class DeployMode(StrEnum):
    """Deployment mode for systemd unit generation."""

    NATIVE = "native"
    CONTAINER = "container"


class SystemdScope(StrEnum):
    """System vs user-level systemd scope, detected from UID."""

    SYSTEM = "system"
    USER = "user"


def detect_scope() -> SystemdScope:
    """Detect systemd scope from the running UID."""
    import os

    if os.getuid() == 0:
        return SystemdScope.SYSTEM
    return SystemdScope.USER


def socket_path(scope: SystemdScope) -> Path:
    """Return the PSI Unix socket path for the given scope."""
    import os

    if scope == SystemdScope.USER:
        xdg = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        return Path(xdg) / "psi/psi.sock"
    return Path("/run/psi/psi.sock")


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


class ProjectConfig(BaseModel):
    """An Infisical project with optional auth override."""

    id: str
    environment: str = "prod"
    auth: AuthConfig | None = None


class SecretSource(BaseModel):
    """A source of secrets: a project + folder path."""

    project: str
    path: str = "/"


class WorkloadConfig(BaseModel):
    """Secrets configuration for a container workload."""

    unit: str | None = None
    secrets: list[SecretSource]


class SecretMapping(BaseModel):
    """Coordinate mapping stored by the shell driver.

    Format: `project_alias:secret_path:secret_name`
    The actual secret value is never stored — only where to fetch it.
    """

    project_alias: str
    secret_path: str
    secret_name: str

    def serialize(self) -> str:
        return f"{self.project_alias}:{self.secret_path}:{self.secret_name}"

    @classmethod
    def deserialize(cls, raw: str) -> SecretMapping:
        parts = raw.strip().split(":", 2)
        if len(parts) != 3:
            msg = f"Invalid mapping format: {raw!r}"
            raise ValueError(msg)
        return cls(
            project_alias=parts[0],
            secret_path=parts[1],
            secret_name=parts[2],
        )


class TokenCache(BaseModel):
    """Cached authentication token."""

    access_token: str
    expires_at: float


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


# --- Status output models ---


class SecretStatus(BaseModel):
    """Status of a single registered secret."""

    name: str
    project: str
    path: str
    registered: bool


class WorkloadStatus(BaseModel):
    """Status of a workload's secrets."""

    workload: str
    secrets: list[SecretStatus]


class CertStatusInfo(BaseModel):
    """Status of a single TLS certificate."""

    name: str
    common_name: str
    serial_number: str
    issued: str
    expires: str
    days_left: int
    status: str


class TimerInfo(BaseModel):
    """Systemd timer status."""

    active_state: str
    last_trigger: str | None = None
    next_elapse: str | None = None
