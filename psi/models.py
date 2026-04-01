"""Generic models for PSI — shared across all providers."""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel


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
    """A source of secrets: a project + folder path (Infisical workloads)."""

    project: str
    path: str = "/"
    recursive: bool = False


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
