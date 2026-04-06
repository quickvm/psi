"""Boot-time setup: discover secrets, register with Podman, generate drop-ins."""

from __future__ import annotations

import os
import subprocess
import time
from typing import TYPE_CHECKING

import httpx
from loguru import logger

from psi.errors import ProviderError
from psi.models import SystemdScope

if TYPE_CHECKING:
    from psi.settings import PsiSettings

_PODMAN_API_VERSION = "v5.0.0"

_RETRY_DELAYS = (5, 10, 20, 40, 60)


def _podman_socket_url() -> str:
    """Return the Podman API Unix socket path."""
    uid = os.getuid()
    if uid == 0:
        return "/run/podman/podman.sock"
    return f"/run/user/{uid}/podman/podman.sock"


def run_setup(
    settings: PsiSettings,
    provider: str | None = None,
) -> None:
    """Discover secrets for all workloads, register, and generate drop-ins.

    Args:
        settings: PSI configuration.
        provider: If set, only process workloads using this provider.
    """
    settings.state_dir.mkdir(parents=True, exist_ok=True)

    for workload_name, workload in settings.workloads.items():
        if provider and workload.provider != provider:
            continue

        logger.info("Workload: {}", workload_name)

        if workload.provider == "infisical":
            _setup_infisical_workload(settings, workload_name)
        elif workload.provider == "nitrokeyhsm":
            logger.info("Nitrokey HSM workload — secrets created via 'psi nitrokeyhsm store'")
        else:
            logger.warning("Unknown provider '{}', skipping", workload.provider)

    logger.info("Reloading systemd...")
    _systemd_daemon_reload(settings.scope)
    logger.info("Setup complete.")


def _is_retryable(exc: Exception) -> bool:
    """Check if an exception is retryable (transient network/server error)."""
    if isinstance(exc, httpx.ConnectError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (404, 502, 503)
    return False


def _setup_infisical_workload(
    settings: PsiSettings,
    workload_name: str,
) -> None:
    """Run Infisical-specific setup for a workload with retry."""
    last_exc: Exception | None = None
    for attempt in range(len(_RETRY_DELAYS) + 1):
        try:
            _fetch_and_register_infisical(settings, workload_name)
            return
        except (httpx.ConnectError, httpx.HTTPStatusError, ProviderError) as e:
            cause = e.__cause__ if isinstance(e, ProviderError) else e
            check = cause if isinstance(cause, Exception) else e
            if not _is_retryable(check):
                raise
            last_exc = e
            if attempt < len(_RETRY_DELAYS):
                delay = _RETRY_DELAYS[attempt]
                logger.warning(
                    "Infisical unavailable, retrying in {}s (attempt {}/{})",
                    delay,
                    attempt + 1,
                    len(_RETRY_DELAYS),
                )
                time.sleep(delay)
    assert last_exc is not None
    raise last_exc


def _fetch_and_register_infisical(
    settings: PsiSettings,
    workload_name: str,
) -> None:
    """Fetch secrets from Infisical and register with Podman."""
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

            logger.info(
                "Fetching project={} path={}",
                source.project,
                source.path,
            )

            secrets = provider._client.list_secrets(
                token,
                project.id,
                project.environment,
                source.path,
                recursive=source.recursive,
            )

            for secret in secrets:
                key = secret["secretKey"]
                actual_path = secret.get("secretPath", source.path)
                merged[key] = InfisicalProvider.make_mapping(
                    source.project,
                    actual_path,
                    key,
                )

            logger.info("Found {} secrets", len(secrets))

        logger.info("Merged: {} unique secrets", len(merged))
        _register_secrets(settings, workload_name, merged)
        _generate_drop_in(settings, workload_name, merged)
    finally:
        provider.close()


def _systemd_daemon_reload(scope: SystemdScope) -> None:
    """Reload systemd via D-Bus, falling back to systemctl.

    Logs a warning and skips if neither D-Bus nor systemctl is available
    (e.g. minimal test containers without systemd).
    """
    try:
        _dbus_daemon_reload(scope)
        return
    except Exception as e:
        logger.debug("D-Bus daemon-reload failed ({}), falling back to systemctl", e)

    cmd = ["systemctl"]
    if scope == SystemdScope.USER:
        cmd.append("--user")
    cmd.append("daemon-reload")
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        logger.warning("systemctl not available, skipping daemon-reload")


def _dbus_daemon_reload(scope: SystemdScope) -> None:
    """Reload systemd via D-Bus. Raises on any failure."""
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

    logger.info("Registered {} secrets with Podman", len(secrets))


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
    logger.info("Wrote drop-in: {}", drop_in_path)
