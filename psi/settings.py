"""Configuration loading via pydantic-settings with YAML support."""

from __future__ import annotations

from pathlib import Path

from pydantic import model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from psi.models import (
    AuthConfig,
    ProjectConfig,
    SystemdScope,
    TlsConfig,
    TokenSettings,
    WorkloadConfig,
)

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
    api_url: str = "https://app.infisical.com"
    auth: AuthConfig | None = None
    verify_ssl: bool = True
    state_dir: Path = _SYSTEM_STATE_DIR
    systemd_dir: Path = _SYSTEM_SYSTEMD_DIR
    token: TokenSettings = TokenSettings()
    projects: dict[str, ProjectConfig]
    workloads: dict[str, WorkloadConfig] = {}
    tls: TlsConfig | None = None

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
    def validate_auth_coverage(self) -> PsiSettings:
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

    @model_validator(mode="after")
    def validate_project_references(self) -> PsiSettings:
        """Ensure workloads and TLS certs reference existing projects."""
        available = ", ".join(self.projects)
        for workload_name, workload in self.workloads.items():
            for source in workload.secrets:
                if source.project not in self.projects:
                    msg = (
                        f"Workload '{workload_name}' references unknown "
                        f"project '{source.project}'. "
                        f"Available: {available}"
                    )
                    raise ValueError(msg)
        if self.tls:
            for cert_name, cert in self.tls.certificates.items():
                if cert.project not in self.projects:
                    msg = (
                        f"Certificate '{cert_name}' references unknown "
                        f"project '{cert.project}'. "
                        f"Available: {available}"
                    )
                    raise ValueError(msg)
        return self


def resolve_auth(project: ProjectConfig, settings: PsiSettings) -> AuthConfig:
    """Resolve auth for a project: project-level auth wins, then global."""
    auth = project.auth or settings.auth
    if not auth:
        msg = f"No auth configured for project '{project.id}'"
        raise ValueError(msg)
    return auth


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

    return _Settings(scope=scope)  # ty: ignore[missing-argument]  # pydantic-settings loads from YAML
