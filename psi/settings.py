"""Configuration loading via pydantic-settings with YAML support."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ValidationError, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from psi.errors import ConfigError
from psi.models import SystemdScope, WorkloadConfig


class CacheConfig(BaseModel):
    """Configuration for the encrypted secret cache.

    When ``enabled`` is True and ``backend`` is set, ``psi serve`` loads
    ``cache.enc`` at startup and serves matching lookups from memory. If the
    backend cannot be opened (e.g. TPM credential missing), PSI logs a warning
    and falls back to live provider lookups.
    """

    enabled: bool = True
    backend: Literal["tpm", "hsm"] | None = None
    path: Path | None = None
    refresh_interval: str = "1h"
    refresh_randomized_delay: str = "5m"

    def resolve_path(self, state_dir: Path) -> Path:
        """Return the cache file path, defaulting to ``state_dir/cache.enc``."""
        return self.path if self.path is not None else state_dir / "cache.enc"


_SYSTEM_CONFIG = Path("/etc/psi/config.yaml")
_SYSTEM_STATE_DIR = Path("/var/lib/psi")
_SYSTEM_SYSTEMD_DIR = Path("/etc/containers/systemd")


def default_config_path(scope: SystemdScope = SystemdScope.SYSTEM) -> Path:
    """Return the default config file path for the given scope."""
    if scope == SystemdScope.USER:
        return Path.home() / ".config/psi/config.yaml"
    return _SYSTEM_CONFIG


class PsiSettings(BaseSettings):
    """Main configuration loaded from YAML, env vars, and CLI overrides."""

    model_config = SettingsConfigDict(
        yaml_file=str(_SYSTEM_CONFIG),
        yaml_file_encoding="utf-8",
        env_prefix="PSI_",
    )

    scope: SystemdScope = SystemdScope.SYSTEM
    state_dir: Path = _SYSTEM_STATE_DIR
    systemd_dir: Path = _SYSTEM_SYSTEMD_DIR
    ca_cert: Path | None = None
    socket_token: str | None = None
    providers: dict[str, Any] = {}
    workloads: dict[str, WorkloadConfig] = {}
    cache: CacheConfig = CacheConfig()

    @property
    def config_dir(self) -> Path:
        """Return the config directory for this scope."""
        if self.scope == SystemdScope.USER:
            return Path.home() / ".config/psi"
        return Path("/etc/psi")

    @model_validator(mode="after")
    def apply_user_scope_defaults(self) -> PsiSettings:
        """Override default paths for user scope when not explicitly set."""
        if self.scope != SystemdScope.USER:
            return self
        if self.state_dir == _SYSTEM_STATE_DIR:
            self.state_dir = Path.home() / ".local/share/psi"
        if self.systemd_dir == _SYSTEM_SYSTEMD_DIR:
            self.systemd_dir = Path.home() / ".config/containers/systemd"
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            YamlConfigSettingsSource(settings_cls),
        )

    @model_validator(mode="after")
    def validate_workload_providers(self) -> PsiSettings:
        """Ensure workloads reference configured providers."""
        for workload_name, workload in self.workloads.items():
            if workload.provider not in self.providers:
                available = ", ".join(self.providers) or "(none)"
                msg = (
                    f"Workload '{workload_name}' uses provider "
                    f"'{workload.provider}', but it is not configured. "
                    f"Available: {available}"
                )
                raise ConfigError(msg)
        return self


def load_settings(
    config_path: Path | None = None,
    scope: SystemdScope = SystemdScope.SYSTEM,
) -> PsiSettings:
    """Load settings from YAML config file with env var overrides."""
    yaml_file = str(config_path or default_config_path(scope))

    class _Settings(PsiSettings):
        model_config = SettingsConfigDict(
            yaml_file=yaml_file,
            yaml_file_encoding="utf-8",
            env_prefix="PSI_",
        )

    yaml_path = Path(yaml_file)
    if not yaml_path.exists():
        msg = f"Config file not found: {yaml_path}"
        raise ConfigError(msg)

    try:
        return _Settings(scope=scope)
    except ValidationError as e:
        lines = [f"Configuration error in {yaml_path}:"]
        for err in e.errors():
            loc = " → ".join(str(p) for p in err["loc"])
            lines.append(f"  - {loc}: {err['msg']}")
        raise ConfigError("\n".join(lines)) from e
    except Exception as e:
        if "yaml" in type(e).__module__.lower():
            msg = f"Invalid YAML in {yaml_path}: {e}"
            raise ConfigError(msg) from e
        raise
