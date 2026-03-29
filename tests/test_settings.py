"""Tests for psi.settings — config loading and validation."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import yaml

from psi.settings import load_settings

if TYPE_CHECKING:
    from pathlib import Path


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
