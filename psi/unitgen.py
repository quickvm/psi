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


def generate_native_setup_service(
    psi_path: str,
    scope: SystemdScope = SystemdScope.SYSTEM,
) -> str:
    """Generate psi-secrets-setup.service for native mode."""
    wanted_by = "default.target" if scope == SystemdScope.USER else "multi-user.target"
    return (
        "[Unit]\n"
        "Description=PSI secrets setup\n"
        "After=network-online.target psi-secrets.service\n"
        "Wants=network-online.target\n"
        "Requires=psi-secrets.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"ExecStart={psi_path} setup\n"
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


def generate_container_setup_quadlet(image: str, settings: PsiSettings) -> str:
    """Generate psi-secrets-setup.container quadlet."""
    state = settings.state_dir
    systemd = settings.systemd_dir
    config_dir = settings.config_dir
    dbus_socket = _dbus_socket_path(settings.scope)
    podman_socket = _podman_socket_path(settings.scope)
    wanted_by = "default.target" if settings.scope == SystemdScope.USER else "multi-user.target"

    lines = [
        "[Unit]",
        "Description=PSI secrets setup",
        "After=network-online.target psi-secrets.service",
        "Wants=network-online.target",
        "Requires=psi-secrets.service",
        "",
        "[Container]",
        f"Image={image}",
        "Exec=setup",
        "Network=host",
        "SecurityLabelType=container_runtime_t",
        f"Volume={config_dir}:{config_dir}:ro",
        f"Volume={state}:{state}:Z",
        f"Volume={systemd}:{systemd}:Z",
        f"Volume={podman_socket}:{podman_socket}:z",
        f"Volume={dbus_socket}:{dbus_socket}",
    ]

    if settings.ca_cert:
        ssl_target = "/etc/ssl/certs/ca-certificates.crt"
        lines.append(f"Volume={settings.ca_cert}:{ssl_target}:ro")
        lines.append(f"Environment=SSL_CERT_FILE={ssl_target}")

    lines.extend(
        [
            "",
            "[Service]",
            "Type=oneshot",
            "RemainAfterExit=yes",
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


def generate_driver_conf(scope: SystemdScope) -> str:
    """Generate containers.conf.d/psi.conf using the PSI serve socket.

    Works for both native and container modes — the driver conf just
    talks to the local socket. The PSI serve process handles the rest.
    """
    from psi.models import socket_path

    sock = socket_path(scope)
    curl = f"curl -sf --unix-socket {sock}"
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
) -> str:
    """Generate psi-secrets.service for native mode."""
    from psi.models import socket_path

    sock = socket_path(scope)
    runtime_dir = sock.parent
    wanted_by = "default.target" if scope == SystemdScope.USER else "multi-user.target"
    return (
        "[Unit]\n"
        "Description=PSI secret lookup service\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "Restart=on-failure\n"
        f"RuntimeDirectory={runtime_dir.name}\n"
        f"ExecStart={psi_path} serve\n"
        "\n"
        "[Install]\n"
        f"WantedBy={wanted_by}\n"
    )


def generate_container_serve_quadlet(image: str, settings: PsiSettings) -> str:
    """Generate psi-secrets.container quadlet for the serve process."""
    from psi.models import socket_path

    state = settings.state_dir
    config_dir = settings.config_dir
    sock = socket_path(settings.scope)
    runtime_dir = sock.parent
    wanted_by = "default.target" if settings.scope == SystemdScope.USER else "multi-user.target"

    lines = [
        "[Unit]",
        "Description=PSI secret lookup service",
        "After=network-online.target",
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

    lines.extend(
        [
            "",
            "[Service]",
            "Type=simple",
            "Restart=on-failure",
            f"RuntimeDirectory={runtime_dir.name}",
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
    dirs: set[Path] = set()
    if not settings.tls:
        return dirs
    for cert in settings.tls.certificates.values():
        dirs.add(cert.output.cert.parent)
        dirs.add(cert.output.key.parent)
        dirs.add(cert.output.chain.parent)
        if cert.output.ca:
            dirs.add(cert.output.ca.parent)
    return dirs
