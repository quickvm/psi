"""Boot-time setup: discover secrets, register with Podman, generate drop-ins."""

from __future__ import annotations

import os
import subprocess
from typing import TYPE_CHECKING

import httpx
from rich.console import Console

from psi.models import SystemdScope

if TYPE_CHECKING:
    from psi.settings import PsiSettings

console = Console()

_PODMAN_API_VERSION = "v5.0.0"


def _podman_socket_url() -> str:
    """Return the Podman API Unix socket path."""
    uid = os.getuid()
    if uid == 0:
        return "/run/podman/podman.sock"
    return f"/run/user/{uid}/podman/podman.sock"


def run_setup(settings: PsiSettings) -> None:
    """Discover secrets for all workloads, register, and generate drop-ins."""
    settings.state_dir.mkdir(parents=True, exist_ok=True)

    for workload_name, workload in settings.workloads.items():
        console.print(f"\n[bold]Workload: {workload_name}[/bold]")

        if workload.provider == "infisical":
            _setup_infisical_workload(settings, workload_name)
        elif workload.provider == "nitrokeyhsm":
            console.print(
                "  [dim]Nitrokey HSM workload — secrets created via 'psi nitrokeyhsm store'[/dim]"
            )
        else:
            console.print(f"  [yellow]Unknown provider '{workload.provider}', skipping[/yellow]")

    console.print("\n[bold]Reloading systemd...[/bold]")
    _systemd_daemon_reload(settings.scope)
    console.print("[green]Setup complete.[/green]")


def _setup_infisical_workload(
    settings: PsiSettings,
    workload_name: str,
) -> None:
    """Run Infisical-specific setup for a workload."""
    from psi.providers.infisical import InfisicalProvider
    from psi.providers.infisical.models import InfisicalConfig, resolve_auth

    infisical_config = InfisicalConfig.model_validate(settings.providers.get("infisical", {}))
    workload = settings.workloads[workload_name]
    provider = InfisicalProvider(settings)
    provider.open()

    try:
        merged: dict[str, str] = {}
        for source in workload.secrets:
            project = infisical_config.projects[source.project]
            auth = resolve_auth(project, infisical_config)
            assert provider._client is not None
            token = provider._client.ensure_token(auth)

            console.print(
                f"  Fetching [cyan]{source.project}[/cyan] path=[cyan]{source.path}[/cyan]"
            )

            secrets = provider._client.list_secrets(
                token,
                project.id,
                project.environment,
                source.path,
            )

            for secret in secrets:
                key = secret["secretKey"]
                actual_path = secret.get("secretPath", source.path)
                merged[key] = InfisicalProvider.make_mapping(
                    source.project,
                    actual_path,
                    key,
                )

            console.print(f"    Found {len(secrets)} secrets")

        console.print(f"  [green]Merged: {len(merged)} unique secrets[/green]")
        _register_secrets(settings, workload_name, merged)
        _generate_drop_in(settings, workload_name, merged)
    finally:
        provider.close()


def _systemd_daemon_reload(scope: SystemdScope) -> None:
    """Reload systemd via D-Bus, falling back to systemctl."""
    try:
        import dbus

        bus = dbus.SessionBus() if scope == SystemdScope.USER else dbus.SystemBus()
        systemd = bus.get_object(
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
        )
        manager = dbus.Interface(
            systemd,
            "org.freedesktop.systemd1.Manager",
        )
        manager.Reload()
    except ImportError:
        cmd = ["systemctl"]
        if scope == SystemdScope.USER:
            cmd.append("--user")
        cmd.append("daemon-reload")
        subprocess.run(cmd, check=True)


def _register_secrets(
    settings: PsiSettings,
    workload_name: str,
    secrets: dict[str, str],
) -> None:
    """Create namespaced Podman secrets with mapping data."""
    transport = httpx.HTTPTransport(uds=_podman_socket_url())
    base = f"http://localhost/{_PODMAN_API_VERSION}"

    with httpx.Client(transport=transport, timeout=30.0) as client:
        for secret_name, mapping_json in secrets.items():
            podman_name = f"{workload_name}--{secret_name}"
            client.delete(f"{base}/libpod/secrets/{podman_name}")
            resp = client.post(
                f"{base}/libpod/secrets/create",
                params={"name": podman_name, "driver": "shell"},
                content=mapping_json.encode(),
            )
            resp.raise_for_status()

    console.print(f"  Registered {len(secrets)} secrets with Podman")


def _generate_drop_in(
    settings: PsiSettings,
    workload_name: str,
    secrets: dict[str, str],
) -> None:
    """Write a systemd drop-in mapping namespaced secrets to env vars."""
    workload = settings.workloads[workload_name]
    drop_in_dir = settings.systemd_dir / f"{workload_name}.container.d"
    drop_in_dir.mkdir(parents=True, exist_ok=True)
    drop_in_path = drop_in_dir / "50-secrets.conf"

    lines: list[str] = []

    if workload.depends_on:
        deps = " ".join(workload.depends_on)
        lines.append("[Unit]")
        lines.append(f"After={deps}")
        lines.append(f"Wants={deps}")
        lines.append("")

    lines.append("[Container]")
    for secret_name in sorted(secrets):
        podman_name = f"{workload_name}--{secret_name}"
        lines.append(f"Secret={podman_name},type=env,target={secret_name}")

    drop_in_path.write_text("\n".join(lines) + "\n")
    console.print(f"  Wrote drop-in: {drop_in_path}")
