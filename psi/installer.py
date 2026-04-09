"""Orchestrate systemd unit installation."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from psi.files import write_text_secure
from psi.models import DeployMode, SystemdScope
from psi.systemd import daemon_reload
from psi.unitgen import (
    generate_container_provider_setup_quadlet,
    generate_container_serve_quadlet,
    generate_container_tls_renew_quadlet,
    generate_driver_conf,
    generate_native_provider_setup_service,
    generate_native_serve_service,
    generate_native_tls_renew_service,
    generate_provider_refresh_service,
    generate_provider_refresh_timer,
    generate_tls_renew_timer,
    provider_supports_refresh,
)

if TYPE_CHECKING:
    from psi.settings import PsiSettings


def _has_tls(settings: PsiSettings) -> bool:
    """Check if TLS is configured in the Infisical provider."""
    inf_raw = settings.providers.get("infisical", {})
    return bool(inf_raw.get("tls"))


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


def install_driver_conf(settings: PsiSettings) -> None:
    """Generate and install the Podman shell driver config."""
    from psi.token import resolve_socket_token

    conf_dir = _containers_conf_dir(settings.scope)
    _ensure_dir(conf_dir)
    conf_path = conf_dir / "psi.conf"
    token = resolve_socket_token(settings)
    mode = 0o600 if token else 0o644
    write_text_secure(
        conf_path,
        generate_driver_conf(settings.scope, token=token),
        mode=mode,
    )
    _ensure_dir(settings.state_dir)
    logger.info("Wrote {}", conf_path)


def render_driver_conf(settings: PsiSettings) -> str:
    """Return the Podman shell driver config as a string.

    Side-effect-free counterpart to :func:`install_driver_conf`. Used by the
    ``psi install --stdout`` path so container-mode deployments can pipe the
    rendered conf to the host's ``containers.conf.d/`` without needing a
    bind mount of the host's container config directory:

        podman exec psi-secrets psi install --stdout \\
          | sudo tee /etc/containers/containers.conf.d/psi.conf > /dev/null
    """
    from psi.token import resolve_socket_token

    token = resolve_socket_token(settings)
    return generate_driver_conf(settings.scope, token=token)


def _install_native(settings: PsiSettings, enable: bool) -> None:
    """Install native systemd units."""
    psi_path = _find_psi_path()
    scope = settings.scope
    unit_dir = _systemd_unit_dir(scope)

    _write_unit(
        unit_dir / "psi-secrets.service",
        generate_native_serve_service(psi_path, scope, settings),
    )

    setup_units = _write_provider_setup_units_native(
        settings,
        psi_path,
        unit_dir,
    )

    refresh_timers = _write_refresh_timers(settings, unit_dir)

    if _has_tls(settings):
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
        _enable_units(
            ["psi-secrets.service", *setup_units],
            _has_tls(settings),
            scope,
            refresh_timers=refresh_timers,
        )


def _install_container(settings: PsiSettings, image: str, enable: bool) -> None:
    """Install container quadlet units + timer."""
    scope = settings.scope
    quadlet_dir = settings.systemd_dir
    _ensure_dir(quadlet_dir)

    _write_unit(
        quadlet_dir / "psi-secrets.container",
        generate_container_serve_quadlet(image, settings),
    )

    setup_units = _write_provider_setup_units_container(
        settings,
        image,
        quadlet_dir,
    )

    # Timers are plain systemd units — they live in the unit_dir regardless of
    # whether the setup unit itself comes from a quadlet or a native service.
    refresh_timers = _write_refresh_timers(settings, _systemd_unit_dir(scope))

    if _has_tls(settings):
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
        _enable_units(
            ["psi-secrets.service", *setup_units],
            _has_tls(settings),
            scope,
            refresh_timers=refresh_timers,
        )


def _write_provider_setup_units_native(
    settings: PsiSettings,
    psi_path: str,
    unit_dir: Path,
) -> list[str]:
    """Write per-provider setup units for native mode. Returns unit names."""
    units: list[str] = []
    for provider_name in settings.providers:
        unit_name = f"psi-{provider_name}-setup.service"
        _write_unit(
            unit_dir / unit_name,
            generate_native_provider_setup_service(
                psi_path,
                provider_name,
                settings.scope,
            ),
        )
        units.append(unit_name)
    return units


def _write_provider_setup_units_container(
    settings: PsiSettings,
    image: str,
    quadlet_dir: Path,
) -> list[str]:
    """Write per-provider setup quadlets for container mode. Returns unit names."""
    units: list[str] = []
    for provider_name in settings.providers:
        filename = f"psi-{provider_name}-setup.container"
        _write_unit(
            quadlet_dir / filename,
            generate_container_provider_setup_quadlet(
                image,
                settings,
                provider_name,
            ),
        )
        units.append(f"psi-{provider_name}-setup.service")
    return units


def _write_refresh_timers(settings: PsiSettings, unit_dir: Path) -> list[str]:
    """Write periodic cache-refresh wrapper services and timers.

    For each provider that supports periodic refresh, writes two units:

    - ``psi-{provider}-refresh.service`` — a native oneshot that calls
      ``systemctl restart psi-{provider}-setup.service``. This exists because
      the setup unit uses ``RemainAfterExit=yes`` so ``ActiveEnterTimestamp``
      stops updating after the first run, which in turn would prevent
      ``OnUnitActiveSec`` on the timer from re-arming.
    - ``psi-{provider}-refresh.timer`` — fires on the configured cadence and
      triggers the wrapper service.

    Returns the list of timer unit names written. Emits nothing and returns
    an empty list when the cache is disabled or no backend is configured —
    there is nothing to refresh if PSI is not caching values.
    """
    if not settings.cache.enabled or settings.cache.backend is None:
        return []

    timers: list[str] = []
    for provider_name in settings.providers:
        if not provider_supports_refresh(provider_name):
            continue
        _write_unit(
            unit_dir / f"psi-{provider_name}-refresh.service",
            generate_provider_refresh_service(provider_name),
        )
        timer_name = f"psi-{provider_name}-refresh.timer"
        _write_unit(
            unit_dir / timer_name,
            generate_provider_refresh_timer(
                provider_name,
                settings.cache.refresh_interval,
                settings.cache.refresh_randomized_delay,
            ),
        )
        timers.append(timer_name)
    return timers


def _write_unit(path: Path, content: str) -> None:
    """Write a unit file and log it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    logger.info("Wrote {}", path)


def _ensure_dir(path: Path) -> None:
    """Create a directory and log if it was newly created."""
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True)
    if not existed:
        logger.info("Created {}", path)


def _daemon_reload(scope: SystemdScope) -> None:
    """Reload systemd via the shared D-Bus-first helper."""
    daemon_reload(scope)


def _enable_units(
    base_units: list[str],
    has_tls: object,
    scope: SystemdScope,
    refresh_timers: list[str] | None = None,
) -> None:
    """Enable and start units."""
    cmd_prefix = ["systemctl"]
    if scope == SystemdScope.USER:
        cmd_prefix.append("--user")

    for unit in base_units:
        subprocess.run([*cmd_prefix, "enable", "--now", unit], check=True)
        logger.info("Enabled {}", unit)

    for timer in refresh_timers or []:
        subprocess.run([*cmd_prefix, "enable", "--now", timer], check=True)
        logger.info("Enabled {}", timer)

    if has_tls:
        subprocess.run(
            [*cmd_prefix, "enable", "--now", "psi-tls-renew.timer"],
            check=True,
        )
        logger.info("Enabled psi-tls-renew.timer")


def _find_psi_path() -> str:
    """Find the psi binary path."""
    path = shutil.which("psi")
    if not path:
        msg = "psi not found in PATH. Install with: uv tool install podman-secret-infrastructure"
        raise RuntimeError(msg)
    return path
