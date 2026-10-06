"""Generic models for PSI — shared across all providers."""

from __future__ import annotations

import os
import re
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, model_validator

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


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
    if os.getuid() == 0:
        return SystemdScope.SYSTEM
    return SystemdScope.USER


def socket_path(scope: SystemdScope) -> Path:
    """Return the PSI Unix socket path for the given scope."""
    if scope == SystemdScope.USER:
        xdg = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        return Path(xdg) / "psi/psi.sock"
    return Path("/run/psi/psi.sock")


class SecretSource(BaseModel):
    """A source of secrets: a project + folder path (Infisical workloads).

    Without ``env``, the container gets every secret in the folder, each as the environment
    variable its key names. With it, only the keys it maps, each as the variable it names
    (``{"TS_AUTHKEY": "TAILSCALE_AUTHKEY"}``), and setup fails when the folder lacks one.
    """

    project: str
    path: str = "/"
    recursive: bool = False
    env: dict[str, str] | None = None

    @model_validator(mode="after")
    def validate_env(self) -> SecretSource:
        if self.env is None:
            return self
        if self.recursive:
            msg = "env picks keys from one folder; it cannot be combined with recursive"
            raise ValueError(msg)
        bad = [name for name in self.env if not _ENV_NAME.fullmatch(name)]
        if bad:
            msg = f"not environment variable names: {', '.join(bad)}"
            raise ValueError(msg)
        if not all(self.env.values()):
            msg = "every environment variable in env needs a key to take its value from"
            raise ValueError(msg)
        return self


class WorkloadConfig(BaseModel):
    """Secrets configuration for a container workload."""

    provider: str = "infisical"
    unit: str | None = None
    secrets: list[SecretSource] = []
    depends_on: list[str] = []


class SecretStatus(BaseModel):
    """Status of a single registered secret."""

    name: str
    provider: str
    detail: str
    registered: bool


class WorkloadStatus(BaseModel):
    """Status of a workload's secrets."""

    workload: str
    secrets: list[SecretStatus]


class TimerInfo(BaseModel):
    """Systemd timer status."""

    active_state: str
    last_trigger: str | None = None
    next_elapse: str | None = None
