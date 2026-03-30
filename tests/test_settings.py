"""Tests for psi.settings — config loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from psi.models import SystemdScope
from psi.settings import default_config_path, load_settings, resolve_auth


def _write_config(tmp_path: Path, config: dict) -> Path:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump(config))
    return config_file


class TestLoadSettings:
    def test_loads_minimal_config(self, tmp_path: Path, sample_settings_dict: dict) -> None:
        config_file = _write_config(tmp_path, sample_settings_dict)
        settings = load_settings(config_file)
        assert settings.api_url == "https://infisical.test"
        assert "myproject" in settings.projects
        assert "myapp" in settings.workloads

    def test_defaults(self, tmp_path: Path, sample_settings_dict: dict) -> None:
        config_file = _write_config(tmp_path, sample_settings_dict)
        settings = load_settings(config_file)
        assert settings.token.ttl == 60

    def test_workloads_optional(self, tmp_path: Path) -> None:
        config = {
            "api_url": "https://test",
            "auth": {"method": "aws-iam", "identity_id": "id"},
            "projects": {"p": {"id": "uuid"}},
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file)
        assert settings.workloads == {}

    def test_tls_optional(self, tmp_path: Path, sample_settings_dict: dict) -> None:
        config_file = _write_config(tmp_path, sample_settings_dict)
        settings = load_settings(config_file)
        assert settings.tls is None


class TestProjectReferenceValidation:
    def test_invalid_workload_project(self, tmp_path: Path) -> None:
        config = {
            "api_url": "https://test",
            "auth": {"method": "aws-iam", "identity_id": "id"},
            "projects": {"real": {"id": "uuid"}},
            "workloads": {
                "app": {"secrets": [{"project": "nonexistent", "path": "/"}]},
            },
        }
        config_file = _write_config(tmp_path, config)
        with pytest.raises(Exception, match="nonexistent"):
            load_settings(config_file)

    def test_invalid_tls_project(self, tmp_path: Path) -> None:
        config = {
            "api_url": "https://test",
            "auth": {"method": "aws-iam", "identity_id": "id"},
            "projects": {"real": {"id": "uuid"}},
            "tls": {
                "certificates": {
                    "web": {
                        "project": "ghost",
                        "profile_id": "pid",
                        "common_name": "cn",
                        "output": {
                            "cert": "/c",
                            "key": "/k",
                            "chain": "/ch",
                        },
                    },
                },
            },
        }
        config_file = _write_config(tmp_path, config)
        with pytest.raises(Exception, match="ghost"):
            load_settings(config_file)

    def test_valid_references_pass(self, tmp_path: Path) -> None:
        config = {
            "api_url": "https://test",
            "auth": {"method": "aws-iam", "identity_id": "id"},
            "projects": {"infra": {"id": "uuid"}},
            "workloads": {
                "app": {"secrets": [{"project": "infra", "path": "/"}]},
            },
            "tls": {
                "certificates": {
                    "web": {
                        "project": "infra",
                        "profile_id": "pid",
                        "common_name": "cn",
                        "output": {
                            "cert": "/c",
                            "key": "/k",
                            "chain": "/ch",
                        },
                    },
                },
            },
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file)
        assert "infra" in settings.projects


class TestAuthCoverage:
    def test_global_auth_covers_all_projects(self, tmp_path: Path) -> None:
        config = {
            "auth": {"method": "aws-iam", "identity_id": "id"},
            "projects": {
                "a": {"id": "uuid-a"},
                "b": {"id": "uuid-b"},
            },
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file)
        assert settings.auth is not None

    def test_per_project_auth_no_global(self, tmp_path: Path) -> None:
        config = {
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
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file)
        assert settings.auth is None
        assert settings.projects["a"].auth is not None
        assert settings.projects["b"].auth is not None

    def test_missing_auth_on_project_without_global(self, tmp_path: Path) -> None:
        config = {
            "projects": {
                "has_auth": {
                    "id": "uuid-a",
                    "auth": {"method": "aws-iam", "identity_id": "id"},
                },
                "no_auth": {"id": "uuid-b"},
            },
        }
        config_file = _write_config(tmp_path, config)
        with pytest.raises(Exception, match="no_auth"):
            load_settings(config_file)

    def test_no_auth_anywhere(self, tmp_path: Path) -> None:
        config = {
            "projects": {"lonely": {"id": "uuid"}},
        }
        config_file = _write_config(tmp_path, config)
        with pytest.raises(Exception, match="lonely"):
            load_settings(config_file)

    def test_mixed_auth_global_fills_gaps(self, tmp_path: Path) -> None:
        config = {
            "auth": {"method": "aws-iam", "identity_id": "global-id"},
            "projects": {
                "with_own": {
                    "id": "uuid-a",
                    "auth": {"method": "gcp", "identity_id": "gcp-id"},
                },
                "uses_global": {"id": "uuid-b"},
            },
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file)
        assert settings.projects["with_own"].auth is not None
        assert settings.projects["uses_global"].auth is None
        assert settings.auth is not None


class TestResolveAuth:
    def test_project_auth_wins(self, tmp_path: Path) -> None:
        config = {
            "auth": {"method": "aws-iam", "identity_id": "global"},
            "projects": {
                "p": {
                    "id": "uuid",
                    "auth": {"method": "gcp", "identity_id": "project-gcp"},
                },
            },
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file)
        auth = resolve_auth(settings.projects["p"], settings)
        assert auth.method.value == "gcp"
        assert auth.identity_id == "project-gcp"

    def test_falls_back_to_global(self, tmp_path: Path) -> None:
        config = {
            "auth": {"method": "aws-iam", "identity_id": "global"},
            "projects": {"p": {"id": "uuid"}},
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file)
        auth = resolve_auth(settings.projects["p"], settings)
        assert auth.method.value == "aws-iam"
        assert auth.identity_id == "global"


class TestUserScope:
    def test_user_scope_resolves_default_paths(self, tmp_path: Path) -> None:
        config = {
            "auth": {"method": "aws-iam", "identity_id": "id"},
            "projects": {"p": {"id": "uuid"}},
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file, scope=SystemdScope.USER)
        home = Path.home()
        assert settings.state_dir == home / ".local/share/psi"
        assert settings.systemd_dir == home / ".config/containers/systemd"

    def test_user_scope_preserves_explicit_paths(self, tmp_path: Path) -> None:
        config = {
            "auth": {"method": "aws-iam", "identity_id": "id"},
            "projects": {"p": {"id": "uuid"}},
            "state_dir": str(tmp_path / "custom"),
            "systemd_dir": str(tmp_path / "custom-systemd"),
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file, scope=SystemdScope.USER)
        assert settings.state_dir == tmp_path / "custom"
        assert settings.systemd_dir == tmp_path / "custom-systemd"

    def test_user_scope_config_dir(
        self, tmp_path: Path, sample_settings_dict: dict,
    ) -> None:
        config_file = _write_config(tmp_path, sample_settings_dict)
        settings = load_settings(config_file, scope=SystemdScope.USER)
        assert settings.config_dir == Path.home() / ".config/psi"

    def test_system_scope_config_dir(
        self, tmp_path: Path, sample_settings_dict: dict,
    ) -> None:
        config_file = _write_config(tmp_path, sample_settings_dict)
        settings = load_settings(config_file, scope=SystemdScope.SYSTEM)
        assert settings.config_dir == Path("/etc/psi")

    def test_default_config_path_system(self) -> None:
        assert default_config_path(SystemdScope.SYSTEM) == Path("/etc/psi/config.yaml")

    def test_default_config_path_user(self) -> None:
        expected = Path.home() / ".config/psi/config.yaml"
        assert default_config_path(SystemdScope.USER) == expected

    def test_explicit_state_dir_preserved_in_user_scope(self, tmp_path: Path) -> None:
        config = {
            "auth": {"method": "aws-iam", "identity_id": "id"},
            "projects": {"p": {"id": "uuid"}},
            "state_dir": str(tmp_path / "custom-state"),
        }
        config_file = _write_config(tmp_path, config)
        settings = load_settings(config_file, scope=SystemdScope.USER)
        assert settings.state_dir == tmp_path / "custom-state"
