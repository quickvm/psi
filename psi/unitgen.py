"""Pure generators for systemd unit file contents.

No file I/O — functions return strings only, making them testable.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from psi.models import SystemdScope

if TYPE_CHECKING:
    from pathlib import Path

    from psi.settings import PsiSettings


def _cache_hsm_container_lines(config_dir: Path, unit_name: str) -> tuple[list[str], list[str]]:
    """Return (container_lines, service_lines) to wire HSM access into a quadlet.

    Adds the pcscd socket volume and the ``hsm-pin`` systemd credential so a
    container running inside the quadlet can open a PKCS#11 session and
    resolve the PIN via ``$CREDENTIALS_DIRECTORY``.

    Args:
        config_dir: Unused today (reserved for future PIN path customization).
        unit_name: Systemd service name (e.g. ``psi-secrets.service``),
            needed because ``LoadCredentialEncrypted`` places the decrypted
            credential under ``/run/credentials/<unit_name>/``.

    Returns:
        Tuple of lines to append to ``[Container]`` and ``[Service]``.
    """
    del config_dir  # currently unused — PIN path is fixed by the PSI convention
    container = [
        "Volume=pcscd-socket:/run/pcscd:rw",
        f"Volume=/run/credentials/{unit_name}:/run/credentials:ro",
        "Environment=CREDENTIALS_DIRECTORY=/run/credentials",
    ]
    service = ["LoadCredentialEncrypted=hsm-pin"]
    return container, service


def _cache_tpm_container_lines(config_dir: Path, unit_name: str) -> tuple[list[str], list[str]]:
    """Return (container_lines, service_lines) to wire a TPM-sealed cache key.

    Same pattern as :func:`_cache_hsm_container_lines`: the sealed key file on
    the host is delivered via ``LoadCredentialEncrypted`` and mounted read-only
    into the container at a path exposed through ``$CREDENTIALS_DIRECTORY``.
    """
    key_path = config_dir / "cache.key"
    container = [
        f"Volume=/run/credentials/{unit_name}:/run/credentials:ro",
        "Environment=CREDENTIALS_DIRECTORY=/run/credentials",
    ]
    service = [f"LoadCredentialEncrypted=psi-cache-key:{key_path}"]
    return container, service


def _cache_quadlet_extras(
    settings: PsiSettings,
    unit_name: str,
) -> tuple[list[str], list[str], bool]:
    """Return ``[Container]``/``[Service]`` extras needed by the configured cache.

    The third element is True when the caller should add
    ``After=pcscd.service`` to the ``[Unit]`` section (HSM backend only).
    """
    if not settings.cache.enabled or settings.cache.backend is None:
        return [], [], False
    if settings.cache.backend == "hsm":
        c, s = _cache_hsm_container_lines(settings.config_dir, unit_name)
        return c, s, True
    if settings.cache.backend == "tpm":
        c, s = _cache_tpm_container_lines(settings.config_dir, unit_name)
        return c, s, False
    return [], [], False


def generate_native_provider_setup_service(
    psi_path: str,
    provider: str,
    scope: SystemdScope = SystemdScope.SYSTEM,
) -> str:
    """Generate psi-{provider}-setup.service for native mode."""
    wanted_by = "default.target" if scope == SystemdScope.USER else "multi-user.target"
    needs_network = provider == "infisical"
    after = "psi-secrets.service"
    wants = ""
    if needs_network:
        after = f"network-online.target {after}"
        wants = "Wants=network-online.target\n"
    return (
        "[Unit]\n"
        f"Description=PSI {provider} secrets setup\n"
        f"After={after}\n"
        f"{wants}"
        "Requires=psi-secrets.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"ExecStart={psi_path} setup --provider {provider}\n"
        "\n"
        "[Install]\n"
        f"WantedBy={wanted_by}\n"
    )


def generate_native_tls_renew_service(psi_path: str) -> str:
    """Generate psi-tls-renew.service for native mode."""
    return (
        "[Unit]\n"
        "Description=PSI TLS certificate renewal\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={psi_path} tls renew\n"
    )


def generate_tls_renew_timer() -> str:
    """Generate psi-tls-renew.timer (shared by both modes)."""
    return (
        "[Unit]\n"
        "Description=Daily PSI TLS certificate renewal\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=daily\n"
        "RandomizedDelaySec=1h\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def generate_container_provider_setup_quadlet(
    image: str,
    settings: PsiSettings,
    provider: str,
) -> str:
    """Generate psi-{provider}-setup.container quadlet.

    When ``settings.cache`` is enabled with an HSM or TPM backend, the setup
    container needs the same unseal wiring as the serve container — the
    setup path fetches secret values and writes them to the encrypted cache,
    which requires provider-side key access at setup time.
    """
    state = settings.state_dir
    systemd = settings.systemd_dir
    config_dir = settings.config_dir
    dbus_socket = _dbus_socket_path(settings.scope)
    podman_socket = _podman_socket_path(settings.scope)
    wanted_by = "default.target" if settings.scope == SystemdScope.USER else "multi-user.target"
    needs_network = provider == "infisical"
    unit_name = f"psi-{provider}-setup.service"

    cache_container, cache_service, needs_pcscd = _cache_quadlet_extras(settings, unit_name)

    after_parts = ["psi-secrets.service"]
    if needs_network:
        after_parts.insert(0, "network-online.target")
    if needs_pcscd:
        after_parts.append("pcscd.service")
    after = " ".join(after_parts)

    lines = [
        "[Unit]",
        f"Description=PSI {provider} secrets setup",
        f"After={after}",
    ]
    if needs_network:
        lines.append("Wants=network-online.target")
    lines.extend(
        [
            "Requires=psi-secrets.service",
            "",
            "[Container]",
            f"Image={image}",
            f"Exec=setup --provider {provider}",
            "Network=host",
            "SecurityLabelType=container_runtime_t",
            f"Volume={config_dir}:{config_dir}:ro",
            f"Volume={state}:{state}:Z",
            f"Volume={systemd}:{systemd}:Z",
            f"Volume={podman_socket}:{podman_socket}:z",
            f"Volume={dbus_socket}:{dbus_socket}",
        ]
    )

    if settings.ca_cert:
        ssl_target = "/etc/ssl/certs/ca-certificates.crt"
        lines.append(f"Volume={settings.ca_cert}:{ssl_target}:ro")
        lines.append(f"Environment=SSL_CERT_FILE={ssl_target}")

    lines.extend(cache_container)

    lines.extend(
        [
            "",
            "[Service]",
            "Type=oneshot",
            "RemainAfterExit=yes",
        ]
    )
    lines.extend(cache_service)
    lines.extend(
        [
            "",
            "[Install]",
            f"WantedBy={wanted_by}",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_container_tls_renew_quadlet(image: str, settings: PsiSettings) -> str:
    """Generate psi-tls-renew.container quadlet."""
    state = settings.state_dir
    config_dir = settings.config_dir
    tls_dirs = collect_tls_volume_dirs(settings)

    lines = [
        "[Unit]",
        "Description=PSI TLS certificate renewal",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Container]",
        f"Image={image}",
        "Exec=tls renew",
        "Network=host",
        f"Volume={config_dir}:{config_dir}:ro",
        f"Volume={state}:{state}:Z",
    ]
    for d in sorted(tls_dirs):
        lines.append(f"Volume={d}:{d}:Z")

    lines.extend(
        [
            "",
            "[Service]",
            "Type=oneshot",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_driver_conf(scope: SystemdScope, token: str | None = None) -> str:
    """Generate containers.conf.d/psi.conf using the PSI serve socket.

    Works for both native and container modes — the driver conf just
    talks to the local socket. The PSI serve process handles the rest.

    Args:
        scope: System or user systemd scope (determines socket path).
        token: Optional socket auth token. When set, curl commands include
            an Authorization header. The token is validated elsewhere, so
            it is safe to embed literally in the generated config.
    """
    from psi.models import socket_path

    sock = socket_path(scope)
    auth = f" -H 'Authorization: Bearer {token}'" if token else ""
    curl = f"curl -sf{auth} --unix-socket {sock}"
    secret_id = "$SECRET_ID"
    return (
        "[secrets]\n"
        'driver = "shell"\n'
        "\n"
        "[secrets.opts]\n"
        f'store = "{curl} -X POST -d @- http://localhost/store/{secret_id}"\n'
        f'lookup = "{curl} http://localhost/lookup/{secret_id}"\n'
        f'delete = "{curl} -X DELETE http://localhost/delete/{secret_id}"\n'
        f'list = "{curl} http://localhost/list"\n'
    )


def generate_native_serve_service(
    psi_path: str,
    scope: SystemdScope = SystemdScope.SYSTEM,
    settings: PsiSettings | None = None,
) -> str:
    """Generate psi-secrets.service for native mode.

    When ``settings.cache.backend == "tpm"``, the unit is emitted with
    ``LoadCredentialEncrypted=psi-cache-key:<cache.key>`` so ``psi serve`` can
    unseal the cache key at startup via ``$CREDENTIALS_DIRECTORY``.
    """
    from psi.models import socket_path

    sock = socket_path(scope)
    runtime_dir = sock.parent
    wanted_by = "default.target" if scope == SystemdScope.USER else "multi-user.target"

    lines = [
        "[Unit]",
        "Description=PSI secret lookup service",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        "Restart=on-failure",
        f"RuntimeDirectory={runtime_dir.name}",
        "StateDirectory=psi",
    ]
    if settings is not None and settings.cache.enabled and settings.cache.backend == "tpm":
        key_path = settings.config_dir / "cache.key"
        lines.append(f"LoadCredentialEncrypted=psi-cache-key:{key_path}")
    lines.extend(
        [
            f"ExecStart={psi_path} serve",
            "",
            "[Install]",
            f"WantedBy={wanted_by}",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_container_serve_quadlet(image: str, settings: PsiSettings) -> str:
    """Generate psi-secrets.container quadlet for the serve process."""
    from psi.models import socket_path

    state = settings.state_dir
    config_dir = settings.config_dir
    sock = socket_path(settings.scope)
    runtime_dir = sock.parent
    wanted_by = "default.target" if settings.scope == SystemdScope.USER else "multi-user.target"
    unit_name = "psi-secrets.service"

    cache_container, cache_service, needs_pcscd = _cache_quadlet_extras(settings, unit_name)

    after_parts = ["network-online.target"]
    if needs_pcscd:
        after_parts.append("pcscd.service")
    after = " ".join(after_parts)

    lines = [
        "[Unit]",
        "Description=PSI secret lookup service",
        f"After={after}",
        "Wants=network-online.target",
        "",
        "[Container]",
        f"Image={image}",
        "Exec=serve",
        "Network=host",
        f"Volume={config_dir}:{config_dir}:ro",
        f"Volume={state}:{state}:Z",
        f"Volume={runtime_dir}:{runtime_dir}:Z",
    ]

    if settings.ca_cert:
        ssl_target = "/etc/ssl/certs/ca-certificates.crt"
        lines.append(f"Volume={settings.ca_cert}:{ssl_target}:ro")
        lines.append(f"Environment=SSL_CERT_FILE={ssl_target}")

    lines.extend(cache_container)

    lines.extend(
        [
            "",
            "[Service]",
            "Type=simple",
            "Restart=on-failure",
            f"RuntimeDirectory={runtime_dir.name}",
        ]
    )
    lines.extend(cache_service)
    lines.extend(
        [
            "",
            "[Install]",
            f"WantedBy={wanted_by}",
        ]
    )
    return "\n".join(lines) + "\n"


def _containers_conf_dir(scope: SystemdScope) -> Path:
    """Return the containers.conf.d directory for the given scope."""
    from pathlib import Path

    if scope == SystemdScope.USER:
        return Path.home() / ".config/containers/containers.conf.d"
    return Path("/etc/containers/containers.conf.d")


def _podman_socket_path(scope: SystemdScope) -> str:
    """Return the Podman socket path for the given scope."""
    if scope == SystemdScope.USER:
        xdg = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        return f"{xdg}/podman/podman.sock"
    return "/run/podman/podman.sock"


def _dbus_socket_path(scope: SystemdScope) -> str:
    """Return the D-Bus socket path for the given scope."""
    if scope == SystemdScope.USER:
        xdg = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        return f"{xdg}/bus"
    return "/run/dbus/system_bus_socket"


def collect_tls_volume_dirs(settings: PsiSettings) -> set[Path]:
    """Collect unique parent directories from TLS cert output paths."""
    from psi.providers.infisical.models import InfisicalConfig

    dirs: set[Path] = set()
    inf_raw = settings.providers.get("infisical", {})
    if not inf_raw:
        return dirs
    inf_config = InfisicalConfig.model_validate(inf_raw)
    if not inf_config.tls:
        return dirs
    for cert in inf_config.tls.certificates.values():
        dirs.add(cert.output.cert.parent)
        dirs.add(cert.output.key.parent)
        dirs.add(cert.output.chain.parent)
        if cert.output.ca:
            dirs.add(cert.output.ca.parent)
    return dirs
