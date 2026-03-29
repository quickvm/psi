"""Orchestrate systemd unit installation."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from psi.models import DeployMode
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

_SYSTEMD_DIR = Path("/etc/systemd/system")
_CONTAINERS_CONF_DIR = Path("/etc/containers/containers.conf.d")


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
    _CONTAINERS_CONF_DIR.mkdir(parents=True, exist_ok=True)
    conf_path = _CONTAINERS_CONF_DIR / "psi.conf"

    if mode == DeployMode.NATIVE:
        conf_path.write_text(generate_native_driver_conf())
    else:
        assert image is not None
        conf_path.write_text(generate_container_driver_conf(image, settings))

    settings.state_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[green]Wrote {conf_path}[/green]")
    console.print(f"[green]Created {settings.state_dir}[/green]")


def _install_native(settings: PsiSettings, enable: bool) -> None:
    """Install native systemd units."""
    psi_path = _find_psi_path()
    units_written: list[str] = []

    _write_unit(
        _SYSTEMD_DIR / "psi-secrets-setup.service",
        generate_native_setup_service(psi_path),
    )
    units_written.append("psi-secrets-setup.service")

    if settings.tls:
        _write_unit(
            _SYSTEMD_DIR / "psi-tls-renew.service",
            generate_native_tls_renew_service(psi_path),
        )
        _write_unit(
            _SYSTEMD_DIR / "psi-tls-renew.timer",
            generate_tls_renew_timer(),
        )
        units_written.extend(
            [
                "psi-tls-renew.service",
                "psi-tls-renew.timer",
            ]
        )

    _daemon_reload()

    if enable:
        _enable_units(["psi-secrets-setup.service"], settings.tls)


def _install_container(settings: PsiSettings, image: str, enable: bool) -> None:
    """Install container quadlet units + timer."""
    quadlet_dir = settings.systemd_dir
    quadlet_dir.mkdir(parents=True, exist_ok=True)

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
            _SYSTEMD_DIR / "psi-tls-renew.timer",
            generate_tls_renew_timer(),
        )

    _daemon_reload()

    if enable:
        _enable_units(["psi-secrets-setup.service"], settings.tls)


def _write_unit(path: Path, content: str) -> None:
    """Write a unit file and log it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    console.print(f"  Wrote {path}")


def _daemon_reload() -> None:
    """Run systemctl daemon-reload."""
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    console.print("[green]Reloaded systemd.[/green]")


def _enable_units(base_units: list[str], has_tls: object) -> None:
    """Enable and start units."""
    for unit in base_units:
        subprocess.run(["systemctl", "enable", "--now", unit], check=True)
        console.print(f"  Enabled {unit}")

    if has_tls:
        subprocess.run(
            ["systemctl", "enable", "--now", "psi-tls-renew.timer"],
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
