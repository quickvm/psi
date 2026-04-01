"""Nitrokey HSM CLI commands — preflight, setup-pcscd, init, store, status, test-pin."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from psi.models import detect_scope
from psi.settings import load_settings

console = Console()

nitrokeyhsm_app = typer.Typer(
    name="nitrokeyhsm",
    help="Nitrokey HSM provider commands.",
    no_args_is_help=True,
)

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", envvar="PSI_CONFIG", help="Config file."),
]


def _get_nitrokeyhsm_config(config: Path | None = None):  # noqa: ANN202
    """Load settings and return NitrokeyHSMConfig."""
    from psi.providers.nitrokeyhsm.models import NitrokeyHSMConfig

    settings = load_settings(config, scope=detect_scope())
    return settings, NitrokeyHSMConfig.model_validate(
        settings.providers.get("nitrokeyhsm", {}),
    )


# --- Preflight ---


@nitrokeyhsm_app.command()
def preflight(config: ConfigOption = None) -> None:
    """Check all prerequisites for the Nitrokey HSM provider."""
    settings, hsm_config = _get_nitrokeyhsm_config(config)
    failed = False

    console.print("[bold]Nitrokey HSM Preflight Check[/bold]\n")

    # 1. PKCS#11 module
    module_path = Path(hsm_config.pkcs11_module)
    if module_path.exists():
        console.print(f"  [green]PASS[/green] PKCS#11 module: {module_path}")
    else:
        console.print(
            f"  [red]FAIL[/red] PKCS#11 module not found: {module_path}\n"
            "        Install opensc or check pkcs11_module config path"
        )
        failed = True

    # 2. pcscd socket
    pcscd_socket = Path("/run/pcscd/pcscd.comm")
    if pcscd_socket.exists():
        console.print(f"  [green]PASS[/green] pcscd socket: {pcscd_socket}")
    else:
        console.print(
            f"  [red]FAIL[/red] pcscd socket not found: {pcscd_socket}\n"
            "        Run 'psi nitrokeyhsm setup-pcscd' or start pcscd manually"
        )
        failed = True

    # 3. PIN resolution
    pin_source = _describe_pin_source(hsm_config)
    if pin_source == "not configured":
        console.print(
            "  [red]FAIL[/red] No HSM PIN source configured\n"
            "        Set pin in config, PSI_NITROKEYHSM_PIN env, or "
            "use systemd LoadCredentialEncrypted=hsm-pin"
        )
        failed = True
    else:
        console.print(f"  [green]PASS[/green] PIN source: {pin_source}")

    # 4. HSM connectivity and login
    if not failed:
        from psi.providers.nitrokeyhsm.pin import resolve_pin
        from psi.providers.nitrokeyhsm.pkcs11 import PKCS11Session

        try:
            pin = resolve_pin(hsm_config)
            session = PKCS11Session(hsm_config)
            session.open(pin)
            console.print(f"  [green]PASS[/green] HSM login: slot {hsm_config.slot}")

            # 5. Key exists
            try:
                session.get_public_key_der()
                console.print(
                    f"  [green]PASS[/green] Key found: "
                    f"label={hsm_config.key_label}, id={hsm_config.key_id}"
                )
            except RuntimeError as e:
                console.print(f"  [red]FAIL[/red] Key not found: {e}")
                failed = True

            session.close()
        except Exception as e:
            console.print(f"  [red]FAIL[/red] HSM connection: {e}")
            failed = True
    else:
        console.print("  [yellow]SKIP[/yellow] HSM connectivity (fix above issues first)")

    # 6. Public key cache
    cache_path = hsm_config.public_key_cache or settings.state_dir / "nitrokeyhsm-pubkey.der"
    if cache_path.exists():
        console.print(f"  [green]PASS[/green] Public key cache: {cache_path}")
    else:
        console.print(
            f"  [yellow]WARN[/yellow] Public key cache not found: "
            f"{cache_path}\n"
            "        Run 'psi nitrokeyhsm init' to extract and cache it"
        )

    # 7. State directory
    if settings.state_dir.exists():
        console.print(f"  [green]PASS[/green] State directory: {settings.state_dir}")
    else:
        console.print(
            f"  [yellow]WARN[/yellow] State directory does not exist: "
            f"{settings.state_dir} (will be created on first store)"
        )

    console.print()
    if failed:
        console.print("[red]Preflight failed. Fix the issues above.[/red]")
        raise typer.Exit(1)
    console.print("[green]All checks passed.[/green]")


# --- pcscd setup ---


_PCSCD_CONTAINERFILE = """\
FROM fedora:latest

RUN dnf install -y \\
    pcsc-lite \\
    pcsc-lite-devel \\
    pcsc-lite-libs \\
    ccid \\
    opensc \\
    libusb \\
    usbutils \\
    && dnf clean all

RUN mkdir -p /run/pcscd && chmod 777 /run/pcscd

CMD ["/usr/sbin/pcscd", "-f", "--disable-polkit"]
"""

_PCSCD_QUADLET = """\
[Unit]
Description=pcscd smartcard daemon for HSM access
Before=psi-secrets.service

[Container]
ContainerName=pcscd
Image=localhost/pcscd:latest
AddDevice=/dev/bus/usb
Volume={volume}:/run/pcscd:rw

[Service]
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""

_PCSCD_VOLUME_QUADLET = """\
[Volume]
VolumeName={volume}

[Install]
WantedBy=default.target
"""


@nitrokeyhsm_app.command(name="setup-pcscd")
def setup_pcscd(
    config: ConfigOption = None,
    build_dir: Annotated[
        Path,
        typer.Option(help="Directory to write the pcscd Containerfile."),
    ] = Path("/opt/psi/pcscd"),
    systemd_dir: Annotated[
        Path | None,
        typer.Option(help="Quadlet directory (default: from config)."),
    ] = None,
    build_only: Annotated[
        bool,
        typer.Option(
            "--build-only",
            help="Write files and build image, but don't install quadlets.",
        ),
    ] = False,
) -> None:
    """Set up the pcscd sidecar container for HSM access.

    Builds a Fedora-based pcscd container image, creates a shared volume
    for the pcscd socket, and installs systemd quadlet units so pcscd
    starts automatically before PSI.

    Requires: SELinux boolean container_use_devices=on for USB access.
    """
    settings, hsm_config = _get_nitrokeyhsm_config(config)
    volume_name = hsm_config.pcscd_volume
    quad_dir = systemd_dir or settings.systemd_dir

    # Check SELinux
    _check_selinux_device_access()

    # Write Containerfile
    build_dir.mkdir(parents=True, exist_ok=True)
    containerfile = build_dir / "Containerfile"
    containerfile.write_text(_PCSCD_CONTAINERFILE)
    console.print(f"  Wrote {containerfile}")

    # Build image
    console.print("  Building pcscd image...")
    result = subprocess.run(
        [
            "podman",
            "build",
            "-t",
            "localhost/pcscd:latest",
            str(build_dir),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        console.print(f"[red]Build failed:[/red]\n{result.stderr}")
        raise typer.Exit(1)
    console.print("  [green]Built localhost/pcscd:latest[/green]")

    if build_only:
        console.print("\n[dim]--build-only: skipping quadlet installation[/dim]")
        return

    # Write quadlet units
    quad_dir.mkdir(parents=True, exist_ok=True)

    volume_unit = quad_dir / f"{volume_name}.volume"
    volume_unit.write_text(
        _PCSCD_VOLUME_QUADLET.format(volume=volume_name),
    )
    console.print(f"  Wrote {volume_unit}")

    pcscd_unit = quad_dir / "pcscd.container"
    pcscd_unit.write_text(
        _PCSCD_QUADLET.format(volume=f"{volume_name}.volume"),
    )
    console.print(f"  Wrote {pcscd_unit}")

    # Reload systemd
    scope_flag = ["--user"] if detect_scope() == "user" else []
    subprocess.run(
        ["systemctl", *scope_flag, "daemon-reload"],
        check=True,
    )
    console.print("  Reloaded systemd")

    console.print(
        f"\n[green]pcscd sidecar ready.[/green]\n"
        f"  Start with: systemctl start pcscd.service\n"
        f"  Socket volume: {volume_name}"
    )


def _check_selinux_device_access() -> None:
    """Check and warn about SELinux container_use_devices boolean."""
    try:
        result = subprocess.run(
            ["getsebool", "container_use_devices"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and "off" in result.stdout:
            console.print(
                "  [yellow]WARN[/yellow] SELinux container_use_devices is off\n"
                "        Run: sudo setsebool -P container_use_devices=true"
            )
        elif result.returncode == 0:
            console.print("  [green]PASS[/green] SELinux container_use_devices is on")
    except FileNotFoundError:
        pass  # no SELinux tooling — skip check


# --- Existing commands ---


@nitrokeyhsm_app.command()
def init(config: ConfigOption = None) -> None:
    """Extract the public key from HSM and cache it locally."""
    from psi.providers.nitrokeyhsm.pin import resolve_pin
    from psi.providers.nitrokeyhsm.pkcs11 import PKCS11Session

    settings, hsm_config = _get_nitrokeyhsm_config(config)
    pin = resolve_pin(hsm_config)

    session = PKCS11Session(hsm_config)
    session.open(pin)
    try:
        der = session.get_public_key_der()
    finally:
        session.close()

    cache_path = hsm_config.public_key_cache
    if not cache_path:
        cache_path = settings.state_dir / "nitrokeyhsm-pubkey.der"

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(der)
    cache_path.chmod(0o644)
    console.print(f"[green]Public key cached: {cache_path} ({len(der)} bytes)[/green]")


@nitrokeyhsm_app.command(name="test-pin")
def test_pin(config: ConfigOption = None) -> None:
    """Verify PIN resolution and HSM login."""
    from psi.providers.nitrokeyhsm.pin import resolve_pin
    from psi.providers.nitrokeyhsm.pkcs11 import PKCS11Session

    _, hsm_config = _get_nitrokeyhsm_config(config)

    try:
        pin = resolve_pin(hsm_config)
    except RuntimeError as e:
        console.print(f"[red]PIN resolution failed:[/red] {e}")
        raise typer.Exit(1) from None

    pin_source = _describe_pin_source(hsm_config)
    console.print(f"  PIN source: {pin_source}")
    console.print(f"  PIN length: {len(pin)} characters")

    session = PKCS11Session(hsm_config)
    try:
        session.open(pin)
        console.print("[green]  HSM login: OK[/green]")
    except Exception as e:
        console.print(f"[red]  HSM login failed:[/red] {e}")
        raise typer.Exit(1) from None
    finally:
        session.close()


@nitrokeyhsm_app.command()
def status(config: ConfigOption = None) -> None:
    """Show HSM connection status and key info."""
    from psi.providers.nitrokeyhsm.pin import resolve_pin
    from psi.providers.nitrokeyhsm.pkcs11 import PKCS11Session

    settings, hsm_config = _get_nitrokeyhsm_config(config)

    console.print("[bold]Nitrokey HSM Provider Status[/bold]\n")
    console.print(f"  PKCS#11 module: {hsm_config.pkcs11_module}")
    console.print(f"  Slot: {hsm_config.slot}")
    console.print(f"  Key label: {hsm_config.key_label}")
    console.print(f"  Key ID: {hsm_config.key_id}")
    console.print(f"  pcscd volume: {hsm_config.pcscd_volume}")

    pin_source = _describe_pin_source(hsm_config)
    console.print(f"  PIN source: {pin_source}")

    cache_path = hsm_config.public_key_cache or settings.state_dir / "nitrokeyhsm-pubkey.der"
    if cache_path.exists():
        size = cache_path.stat().st_size
        console.print(f"  Public key cache: {cache_path} ({size} bytes)")
    else:
        console.print("  Public key cache: [yellow]not found[/yellow] (run 'psi nitrokeyhsm init')")

    try:
        pin = resolve_pin(hsm_config)
        session = PKCS11Session(hsm_config)
        session.open(pin)
        console.print("  HSM connection: [green]OK[/green]")
        session.close()
    except Exception as e:
        console.print(f"  HSM connection: [red]FAILED[/red] ({e})")


@nitrokeyhsm_app.command()
def store(
    name: Annotated[str, typer.Argument(help="Podman secret name.")],
    config: ConfigOption = None,
) -> None:
    """Encrypt a secret value from stdin and store it.

    Usage: echo -n "my-secret" | psi nitrokeyhsm store my-secret-name
    """
    import sys

    from psi.providers.nitrokeyhsm import NitrokeyHSMProvider

    settings = load_settings(config, scope=detect_scope())
    plaintext = sys.stdin.buffer.read()
    if not plaintext:
        console.print("[red]No data on stdin.[/red]")
        raise typer.Exit(1)

    provider = NitrokeyHSMProvider(settings)
    provider.open()
    try:
        provider.store(name, plaintext)
    finally:
        provider.close()

    console.print(f"[green]Encrypted and stored: {name}[/green]")
    console.print(
        f"[dim]Register with podman: "
        f"podman secret create --driver shell {name} "
        f"{settings.state_dir / name}[/dim]"
    )


# --- Helpers ---


def _describe_pin_source(config) -> str:  # noqa: ANN001
    """Describe where the PIN will come from."""
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if creds_dir:
        pin_path = Path(creds_dir) / "hsm-pin"
        if pin_path.exists():
            return f"systemd credential ({pin_path})"
    if config.pin:
        return "config file"
    if os.environ.get("PSI_NITROKEYHSM_PIN"):
        return "PSI_NITROKEYHSM_PIN env var"
    return "not configured"
