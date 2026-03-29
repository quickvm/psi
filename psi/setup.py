"""Boot-time setup: discover secrets, register with Podman, generate drop-ins."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from rich.console import Console

from psi.api import InfisicalClient
from psi.models import SecretMapping
from psi.settings import resolve_auth

if TYPE_CHECKING:
    from psi.settings import PsiSettings

console = Console()


def run_setup(settings: PsiSettings) -> None:
    """Discover secrets for all workloads, register, and generate drop-ins."""
    settings.state_dir.mkdir(parents=True, exist_ok=True)

    with InfisicalClient(settings.api_url, settings.state_dir, settings.token.ttl) as client:
        for workload_name, _workload in settings.workloads.items():
            console.print(f"\n[bold]Workload: {workload_name}[/bold]")
            merged = _discover_workload_secrets(client, settings, workload_name)
            _register_secrets(settings, workload_name, merged)
            _generate_drop_in(settings, workload_name, merged)

    console.print("\n[bold]Reloading systemd...[/bold]")
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    console.print("[green]Setup complete.[/green]")


def _discover_workload_secrets(
    client: InfisicalClient,
    settings: PsiSettings,
    workload_name: str,
) -> dict[str, SecretMapping]:
    """Fetch and merge secrets for a workload. Later sources win."""
    workload = settings.workloads[workload_name]
    merged: dict[str, SecretMapping] = {}

    for source in workload.secrets:
        project = settings.projects[source.project]
        auth = resolve_auth(project, settings)
        token = client.ensure_token(auth)

        console.print(f"  Fetching [cyan]{source.project}[/cyan] path=[cyan]{source.path}[/cyan]")

        secrets = client.list_secrets(token, project.id, project.environment, source.path)

        for secret in secrets:
            key = secret["secretKey"]
            actual_path = secret.get("secretPath", source.path)
            merged[key] = SecretMapping(
                project_alias=source.project,
                secret_path=actual_path,
                secret_name=key,
            )

        console.print(f"    Found {len(secrets)} secrets")

    console.print(f"  [green]Merged: {len(merged)} unique secrets[/green]")
    return merged


def _register_secrets(
    settings: PsiSettings,
    workload_name: str,
    secrets: dict[str, SecretMapping],
) -> None:
    """Create namespaced Podman secrets with coordinate mappings."""
    for secret_name, mapping in secrets.items():
        podman_name = f"{workload_name}--{secret_name}"

        # Remove existing (idempotent re-registration)
        subprocess.run(
            ["podman", "secret", "rm", podman_name],
            capture_output=True,
        )

        subprocess.run(
            ["podman", "secret", "create", podman_name, "-"],
            input=mapping.serialize().encode(),
            check=True,
            capture_output=True,
        )

    console.print(f"  Registered {len(secrets)} secrets with Podman")


def _generate_drop_in(
    settings: PsiSettings,
    workload_name: str,
    secrets: dict[str, SecretMapping],
) -> None:
    """Write a systemd drop-in mapping namespaced secrets to env vars."""
    drop_in_dir = settings.systemd_dir / f"{workload_name}.container.d"
    drop_in_dir.mkdir(parents=True, exist_ok=True)
    drop_in_path = drop_in_dir / "50-secrets.conf"

    lines = ["[Container]"]
    for secret_name in sorted(secrets):
        podman_name = f"{workload_name}--{secret_name}"
        lines.append(f"Secret={podman_name},type=env,target={secret_name}")

    drop_in_path.write_text("\n".join(lines) + "\n")
    console.print(f"  Wrote drop-in: {drop_in_path}")
