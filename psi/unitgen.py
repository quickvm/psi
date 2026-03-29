"""Pure generators for systemd unit file contents.

No file I/O — functions return strings only, making them testable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from psi.settings import PsiSettings


def generate_native_setup_service(psi_path: str) -> str:
    """Generate psi-secrets-setup.service for native mode."""
    return (
        "[Unit]\n"
        "Description=PSI secrets setup\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"ExecStart={psi_path} setup\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
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
    lines = [
        "[Unit]",
        "Description=PSI secrets setup",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Container]",
        f"Image={image}",
        "Exec=setup",
        "Network=host",
        "Volume=/etc/psi:/etc/psi:ro",
        f"Volume={state}:{state}:Z",
        f"Volume={systemd}:{systemd}:Z",
        "Volume=/etc/containers/containers.conf.d:/etc/containers/containers.conf.d:Z",
        "Volume=/run/dbus/system_bus_socket:/run/dbus/system_bus_socket",
        "",
        "[Service]",
        "Type=oneshot",
        "RemainAfterExit=yes",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
    ]
    return "\n".join(lines) + "\n"


def generate_container_tls_renew_quadlet(image: str, settings: PsiSettings) -> str:
    """Generate psi-tls-renew.container quadlet."""
    state = settings.state_dir
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
        "Volume=/etc/psi:/etc/psi:ro",
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


def generate_native_driver_conf() -> str:
    """Generate containers.conf.d/psi.conf for native mode."""
    return (
        "[secrets]\n"
        'driver = "shell"\n'
        "\n"
        "[secrets.opts]\n"
        'store = "psi secret store"\n'
        'lookup = "psi secret lookup"\n'
        'delete = "psi secret delete"\n'
        'list = "psi secret list"\n'
    )


def generate_container_driver_conf(image: str, settings: PsiSettings) -> str:
    """Generate containers.conf.d/psi.conf for container mode."""
    state = settings.state_dir
    base = f"podman run --rm -v {state}:{state}:Z -v /etc/psi:/etc/psi:ro"
    return (
        "[secrets]\n"
        'driver = "shell"\n'
        "\n"
        "[secrets.opts]\n"
        f'store = "{base} -i {image} secret store"\n'
        f'lookup = "{base} --net=host {image} secret lookup"\n'
        f'delete = "{base} {image} secret delete"\n'
        f'list = "{base} {image} secret list"\n'
    )


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
