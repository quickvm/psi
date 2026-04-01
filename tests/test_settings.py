"""Tests for psi.settings — config loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from psi.models import SystemdScope
from psi.providers.infisical.models import InfisicalConfig, resolve_auth
from psi.settings import default_config_path, load_settings


def _write_config(tmp_path: Path, config: dict) -> Path:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump(config))
    return config_file


class TestLoadSettings:
    def test_loads_minimal_config(
        self,
        tmp_path: Path,
        sample_settings_dict: dict,
    ) -> None:
        config_file = _write_config(tmp_path, sample_settings_dict)
        settings = load_settings(config_file)
        assert "infisical" in settings.providers
        assert "myapp" in settings.workloads

    def test_defaults(
        self,
        tmp_path: Path,
        sample_settings_dict: dict,
    ) -> None:
        config_file = _write_config(tmp_path, sample_settings_dict)
        settings = load_settings(config_file)
        inf = InfisicalConfig.model_validate(settings.providers["infisical"])
        assert inf.token.ttl == 60

    def test_workloads_optional(self, tmp_path: Path) -> None:
        config = {
            "providers": {
                "infisical": {
                    "auth": {"method": "aws-iam", "identity_id": "id"},
                    "projects": {"p": {"id": "uuid"}},
                },
            },
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file)
        assert settings.workloads == {}

    def test_empty_providers(self, tmp_path: Path) -> None:
        config: dict = {"providers": {}}
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file)
        assert settings.providers == {}


class TestWorkloadProviderValidation:
    def test_invalid_workload_provider(self, tmp_path: Path) -> None:
        config = {
            "providers": {"infisical": {"projects": {}}},
            "workloads": {
                "app": {
                    "provider": "nonexistent",
                    "secrets": [],
                },
            },
        }
        config_file = _write_config(tmp_path, config)
        with pytest.raises(Exception, match="nonexistent"):
            load_settings(config_file)

    def test_valid_provider_reference(self, tmp_path: Path) -> None:
        config = {
            "providers": {
                "infisical": {
                    "auth": {"method": "aws-iam", "identity_id": "id"},
                    "projects": {"infra": {"id": "uuid"}},
                },
            },
            "workloads": {
                "app": {
                    "provider": "infisical",
                    "secrets": [{"project": "infra", "path": "/"}],
                },
            },
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file)
        assert "app" in settings.workloads


class TestTemplateUnitWorkloadValidation:
    def test_template_workload_passes_validation(self, tmp_path: Path) -> None:
        config = {
            "providers": {
                "infisical": {
                    "auth": {"method": "aws-iam", "identity_id": "id"},
                    "projects": {"homelab": {"id": "uuid"}},
                },
            },
            "workloads": {
                "windmill-worker@": {
                    "provider": "infisical",
                    "secrets": [
                        {"project": "homelab", "path": "/windmill"},
                        {"project": "homelab", "path": "/windmill/worker"},
                    ],
                },
            },
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file)
        assert "windmill-worker@" in settings.workloads
        assert len(settings.workloads["windmill-worker@"].secrets) == 2

    def test_template_alongside_regular_workload(self, tmp_path: Path) -> None:
        config = {
            "providers": {
                "infisical": {
                    "auth": {"method": "aws-iam", "identity_id": "id"},
                    "projects": {"homelab": {"id": "uuid"}},
                },
            },
            "workloads": {
                "windmill-server": {
                    "provider": "infisical",
                    "secrets": [{"project": "homelab", "path": "/windmill/server"}],
                },
                "windmill-worker@": {
                    "provider": "infisical",
                    "secrets": [{"project": "homelab", "path": "/windmill/worker"}],
                },
            },
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file)
        assert "windmill-server" in settings.workloads
        assert "windmill-worker@" in settings.workloads


class TestInfisicalAuthCoverage:
    def test_global_auth_covers_all_projects(self, tmp_path: Path) -> None:
        inf_config = InfisicalConfig.model_validate(
            {
                "auth": {"method": "aws-iam", "identity_id": "id"},
                "projects": {
                    "a": {"id": "uuid-a"},
                    "b": {"id": "uuid-b"},
                },
            }
        )
        assert inf_config.auth is not None

    def test_per_project_auth_no_global(self, tmp_path: Path) -> None:
        inf_config = InfisicalConfig.model_validate(
            {
                "projects": {
                    "a": {
                        "id": "uuid-a",
                        "auth": {"method": "aws-iam", "identity_id": "id-a"},
                    },
                    "b": {
                        "id": "uuid-b",
                        "auth": {
                            "method": "universal-auth",
                            "client_id": "cid",
                            "client_secret": "csec",
                        },
                    },
                },
            }
        )
        assert inf_config.auth is None
        assert inf_config.projects["a"].auth is not None

    def test_missing_auth_on_project_without_global(self) -> None:
        with pytest.raises(Exception, match="no_auth"):
            InfisicalConfig.model_validate(
                {
                    "projects": {
                        "has_auth": {
                            "id": "uuid-a",
                            "auth": {"method": "aws-iam", "identity_id": "id"},
                        },
                        "no_auth": {"id": "uuid-b"},
                    },
                }
            )

    def test_no_auth_anywhere(self) -> None:
        with pytest.raises(Exception, match="lonely"):
            InfisicalConfig.model_validate(
                {
                    "projects": {"lonely": {"id": "uuid"}},
                }
            )


class TestResolveAuth:
    def test_project_auth_wins(self) -> None:
        inf_config = InfisicalConfig.model_validate(
            {
                "auth": {"method": "aws-iam", "identity_id": "global"},
                "projects": {
                    "p": {
                        "id": "uuid",
                        "auth": {"method": "gcp", "identity_id": "project-gcp"},
                    },
                },
            }
        )
        auth = resolve_auth(inf_config.projects["p"], inf_config)
        assert auth.method.value == "gcp"
        assert auth.identity_id == "project-gcp"

    def test_falls_back_to_global(self) -> None:
        inf_config = InfisicalConfig.model_validate(
            {
                "auth": {"method": "aws-iam", "identity_id": "global"},
                "projects": {"p": {"id": "uuid"}},
            }
        )
        auth = resolve_auth(inf_config.projects["p"], inf_config)
        assert auth.method.value == "aws-iam"
        assert auth.identity_id == "global"


class TestUserScope:
    def test_user_scope_resolves_default_paths(self, tmp_path: Path) -> None:
        config = {
            "providers": {
                "infisical": {
                    "auth": {"method": "aws-iam", "identity_id": "id"},
                    "projects": {"p": {"id": "uuid"}},
                },
            },
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file, scope=SystemdScope.USER)
        home = Path.home()
        assert settings.state_dir == home / ".local/share/psi"
        assert settings.systemd_dir == home / ".config/containers/systemd"

    def test_user_scope_preserves_explicit_paths(self, tmp_path: Path) -> None:
        config = {
            "providers": {
                "infisical": {
                    "auth": {"method": "aws-iam", "identity_id": "id"},
                    "projects": {"p": {"id": "uuid"}},
                },
            },
            "state_dir": str(tmp_path / "custom"),
            "systemd_dir": str(tmp_path / "custom-systemd"),
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file, scope=SystemdScope.USER)
        assert settings.state_dir == tmp_path / "custom"
        assert settings.systemd_dir == tmp_path / "custom-systemd"

    def test_default_config_path_system(self) -> None:
        assert default_config_path(SystemdScope.SYSTEM) == Path("/etc/psi/config.yaml")

    def test_default_config_path_user(self) -> None:
        expected = Path.home() / ".config/psi/config.yaml"
        assert default_config_path(SystemdScope.USER) == expected
