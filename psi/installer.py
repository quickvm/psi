"""Orchestrate systemd unit installation."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from psi.models import DeployMode, SystemdScope
from psi.unitgen import (
    generate_container_driver_conf,
    generate_container_setup_quadlet,
    generate_container_tls_renew_quadlet,
    generate_native_driver_conf,
    generate_native_setup_service,
    generate_native_tls_renew_service,
    generate_tls_renew_timer,
)

if TYPE_CHECKING:
    from psi.settings import PsiSettings

console = Console()


def _systemd_unit_dir(scope: SystemdScope) -> Path:
    """Return the systemd unit directory for the given scope."""
    if scope == SystemdScope.USER:
        return Path.home() / ".config/systemd/user"
    return Path("/etc/systemd/system")


def _containers_conf_dir(scope: SystemdScope) -> Path:
    """Return the containers.conf.d directory for the given scope."""
    if scope == SystemdScope.USER:
        return Path.home() / ".config/containers/containers.conf.d"
    return Path("/etc/containers/containers.conf.d")


def install_systemd_units(
    settings: PsiSettings,
    mode: DeployMode,
    image: str | None,
    enable: bool,
) -> None:
    """Generate and install systemd units for psi services."""
    if mode == DeployMode.NATIVE:
        _install_native(settings, enable)
    else:
        assert image is not None
        _install_container(settings, image, enable)


def install_driver_conf(
    settings: PsiSettings,
    mode: DeployMode,
    image: str | None,
) -> None:
    """Generate and install the Podman shell driver config."""
    conf_dir = _containers_conf_dir(settings.scope)
    _ensure_dir(conf_dir)
    conf_path = conf_dir / "psi.conf"

    if mode == DeployMode.NATIVE:
        conf_path.write_text(generate_native_driver_conf())
    else:
        assert image is not None
        conf_path.write_text(generate_container_driver_conf(image, settings))

    _ensure_dir(settings.state_dir)
    console.print(f"[green]Wrote {conf_path}[/green]")


def _install_native(settings: PsiSettings, enable: bool) -> None:
    """Install native systemd units."""
    psi_path = _find_psi_path()
    scope = settings.scope
    unit_dir = _systemd_unit_dir(scope)

    _write_unit(
        unit_dir / "psi-secrets-setup.service",
        generate_native_setup_service(psi_path, scope),
    )

    if settings.tls:
        _write_unit(
            unit_dir / "psi-tls-renew.service",
            generate_native_tls_renew_service(psi_path),
        )
        _write_unit(
            unit_dir / "psi-tls-renew.timer",
            generate_tls_renew_timer(),
        )

    _daemon_reload(scope)

    if enable:
        _enable_units(["psi-secrets-setup.service"], settings.tls, scope)


def _install_container(settings: PsiSettings, image: str, enable: bool) -> None:
    """Install container quadlet units + timer."""
    scope = settings.scope
    quadlet_dir = settings.systemd_dir
    _ensure_dir(quadlet_dir)

    _write_unit(
        quadlet_dir / "psi-secrets-setup.container",
        generate_container_setup_quadlet(image, settings),
    )

    if settings.tls:
        _write_unit(
            quadlet_dir / "psi-tls-renew.container",
            generate_container_tls_renew_quadlet(image, settings),
        )
        _write_unit(
            _systemd_unit_dir(scope) / "psi-tls-renew.timer",
            generate_tls_renew_timer(),
        )

    _daemon_reload(scope)

    if enable:
        _enable_units(["psi-secrets-setup.service"], settings.tls, scope)


def _write_unit(path: Path, content: str) -> None:
    """Write a unit file and log it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    console.print(f"  Wrote {path}")


def _ensure_dir(path: Path) -> None:
    """Create a directory and log if it was newly created."""
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True)
    if not existed:
        console.print(f"[green]Created {path}[/green]")


def _daemon_reload(scope: SystemdScope) -> None:
    """Run systemctl daemon-reload."""
    cmd = ["systemctl"]
    if scope == SystemdScope.USER:
        cmd.append("--user")
    cmd.append("daemon-reload")
    subprocess.run(cmd, check=True)
    console.print("[green]Reloaded systemd.[/green]")


def _enable_units(
    base_units: list[str],
    has_tls: object,
    scope: SystemdScope,
) -> None:
    """Enable and start units."""
    cmd_prefix = ["systemctl"]
    if scope == SystemdScope.USER:
        cmd_prefix.append("--user")

    for unit in base_units:
        subprocess.run([*cmd_prefix, "enable", "--now", unit], check=True)
        console.print(f"  Enabled {unit}")

    if has_tls:
        subprocess.run(
            [*cmd_prefix, "enable", "--now", "psi-tls-renew.timer"],
            check=True,
        )
        console.print("  Enabled psi-tls-renew.timer")


def _find_psi_path() -> str:
    """Find the psi binary path."""
    path = shutil.which("psi")
    if not path:
        msg = "psi not found in PATH. Install with: uv tool install podman-secret-infisical"
        raise RuntimeError(msg)
    return path
