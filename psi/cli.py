"""psi CLI — Podman Secret Infrastructure."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from psi.models import detect_scope
from psi.settings import load_settings

app = typer.Typer(
    name="psi",
    help="Podman Secret Infrastructure — pluggable secret backends.",
    no_args_is_help=True,
)
secret_app = typer.Typer(
    name="secret",
    help="Podman shell secret driver commands.",
    no_args_is_help=True,
)
app.add_typer(secret_app)
systemd_app = typer.Typer(
    name="systemd",
    help="Systemd unit management.",
    no_args_is_help=True,
)
app.add_typer(systemd_app)

# Register provider subcommands
from psi.providers.infisical.cli import infisical_app  # noqa: E402

app.add_typer(infisical_app)

from psi.providers.nitrohsm.cli import nitrohsm_app  # noqa: E402

app.add_typer(nitrohsm_app)

console = Console()

ConfigOption = Annotated[
    Path | None,
    typer.Option(
        "--config",
        "-c",
        envvar="PSI_CONFIG",
        help="Path to config file.",
    ),
]
JsonOption = Annotated[
    bool,
    typer.Option("--json", help="Force JSON output."),
]


# --- Top-level commands ---


@app.command()
def setup(config: ConfigOption = None) -> None:
    """Discover secrets, register with Podman, generate systemd drop-ins."""
    from psi.setup import run_setup

    settings = load_settings(config, scope=detect_scope())
    run_setup(settings)


@app.command()
def serve(config: ConfigOption = None) -> None:
    """Run the secret lookup service on a Unix socket."""
    from psi.models import socket_path
    from psi.serve import run_serve

    settings = load_settings(config, scope=detect_scope())
    run_serve(settings, str(socket_path(settings.scope)))


@app.command()
def install(config: ConfigOption = None) -> None:
    """Generate Podman shell driver config and state directory."""
    from psi.installer import install_driver_conf

    settings = load_settings(config, scope=detect_scope())
    install_driver_conf(settings)


# --- Shell driver subcommands ---


@secret_app.command()
def store(config: ConfigOption = None) -> None:
    """Store a secret mapping (called by Podman)."""
    from psi.secret import store as do_store

    do_store(load_settings(config, scope=detect_scope()))


@secret_app.command()
def lookup(config: ConfigOption = None) -> None:
    """Fetch a secret value (called by Podman)."""
    from psi.secret import lookup as do_lookup

    do_lookup(load_settings(config, scope=detect_scope()))


@secret_app.command()
def delete(config: ConfigOption = None) -> None:
    """Remove a secret mapping (called by Podman)."""
    from psi.secret import delete as do_delete

    do_delete(load_settings(config, scope=detect_scope()))


@secret_app.command(name="list")
def list_cmd(config: ConfigOption = None) -> None:
    """List all registered secrets (called by Podman)."""
    from psi.secret import list_secrets

    list_secrets(load_settings(config, scope=detect_scope()))


# --- Systemd management commands ---


@systemd_app.command(name="install")
def systemd_install(
    mode: Annotated[
        str,
        typer.Option("--mode", help="Deployment mode: native or container."),
    ],
    image: Annotated[
        str | None,
        typer.Option("--image", help="Container image (container mode)."),
    ] = None,
    enable: Annotated[
        bool,
        typer.Option("--enable", help="Enable and start units."),
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Generate systemd units for psi services."""
    from psi.installer import install_systemd_units
    from psi.models import DeployMode

    deploy_mode = DeployMode(mode)
    if deploy_mode == DeployMode.CONTAINER and not image:
        console.print("[red]Container mode requires --image.[/red]")
        raise typer.Exit(1)

    settings = load_settings(config, scope=detect_scope())
    install_systemd_units(settings, deploy_mode, image, enable)


def main() -> None:
    """Entry point for the psi CLI."""
    app()
