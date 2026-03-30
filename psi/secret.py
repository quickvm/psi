"""Podman shell secret driver commands.

These functions implement the store/lookup/delete/list interface that
Podman calls when using the shell secret driver. No Rich output —
pure stdin/stdout/stderr protocol.
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, NoReturn

from psi.api import InfisicalClient
from psi.models import SecretMapping, SecretStatus, WorkloadStatus

if TYPE_CHECKING:
    from psi.settings import PsiSettings

from psi.settings import resolve_auth


def store(settings: PsiSettings) -> None:
    """Store a secret mapping. Called by Podman with SECRET_ID env var."""
    secret_id = _require_secret_id()
    mapping_data = sys.stdin.buffer.read()
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    mapping_path = settings.state_dir / secret_id
    mapping_path.write_bytes(mapping_data)
    mapping_path.chmod(0o600)


def lookup(settings: PsiSettings) -> None:
    """Fetch a secret value from Infisical. Called by Podman at container start."""
    secret_id = _require_secret_id()
    mapping_path = settings.state_dir / secret_id

    if not mapping_path.exists():
        _fail(f"No mapping for secret: {secret_id}")

    raw = mapping_path.read_text().strip()
    try:
        mapping = SecretMapping.deserialize(raw)
    except ValueError as e:
        _fail(f"Corrupt mapping for {secret_id}: {e}")

    project = settings.projects.get(mapping.project_alias)
    if not project:
        _fail(f"Secret {secret_id} references unknown project '{mapping.project_alias}'")

    auth = resolve_auth(project, settings)

    with InfisicalClient.from_settings(settings) as client:
        token = client.ensure_token(auth)
        value = client.get_secret(
            token,
            project.id,
            project.environment,
            mapping.secret_path,
            mapping.secret_name,
        )

    sys.stdout.buffer.write(value.encode())


def delete(settings: PsiSettings) -> None:
    """Remove a secret mapping. Called by Podman on secret removal."""
    secret_id = _require_secret_id()
    mapping_path = settings.state_dir / secret_id
    mapping_path.unlink(missing_ok=True)


def list_secrets(settings: PsiSettings) -> None:
    """List all registered secret IDs. Called by Podman."""
    if not settings.state_dir.exists():
        return
    for entry in sorted(settings.state_dir.iterdir()):
        if not entry.name.startswith(".") and entry.is_file():
            print(entry.name)


def get_secret_status(settings: PsiSettings) -> list[WorkloadStatus]:
    """Build status for all workloads from config and registered secrets."""
    from psi.importer import _podman_api_get

    all_secrets = _podman_api_get("/libpod/secrets/json").json()
    secret_map: dict[str, str] = {}
    for s in all_secrets:
        secret_map[s["Spec"]["Name"]] = s["ID"]

    results: list[WorkloadStatus] = []

    for workload_name in settings.workloads:
        secrets: list[SecretStatus] = []
        prefix = f"{workload_name}--"

        for name, secret_id in sorted(secret_map.items()):
            if not name.startswith(prefix):
                continue
            secret_key = name[len(prefix) :]
            mapping_path = settings.state_dir / secret_id
            if mapping_path.exists():
                try:
                    mapping = SecretMapping.deserialize(mapping_path.read_text().strip())
                    secrets.append(
                        SecretStatus(
                            name=secret_key,
                            project=mapping.project_alias,
                            path=mapping.secret_path,
                            registered=True,
                        )
                    )
                except ValueError, OSError:
                    secrets.append(
                        SecretStatus(
                            name=secret_key,
                            project="?",
                            path="?",
                            registered=False,
                        )
                    )
            else:
                secrets.append(
                    SecretStatus(
                        name=secret_key,
                        project="?",
                        path="?",
                        registered=False,
                    )
                )

        results.append(WorkloadStatus(workload=workload_name, secrets=secrets))

    return results


def _require_secret_id() -> str:
    """Read SECRET_ID from environment, fail if missing or empty."""
    secret_id = os.environ.get("SECRET_ID", "")
    if not secret_id:
        _fail("SECRET_ID environment variable not set")
    return secret_id


def _fail(message: str) -> NoReturn:
    """Print error to stderr and exit."""
    print(message, file=sys.stderr)
    raise SystemExit(1)
