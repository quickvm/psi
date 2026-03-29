"""psi CLI — Podman Secret Infisical."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console

from psi.settings import load_settings, resolve_auth

if TYPE_CHECKING:
    from psi.models import AuthConfig

app = typer.Typer(
    name="psi",
    help="Podman Secret Infisical — fetch secrets at container start time.",
    no_args_is_help=True,
)
secret_app = typer.Typer(
    name="secret",
    help="Podman shell secret driver commands.",
    no_args_is_help=True,
)
app.add_typer(secret_app)
tls_app = typer.Typer(
    name="tls",
    help="TLS certificate management via Infisical PKI.",
    no_args_is_help=True,
)
app.add_typer(tls_app)
systemd_app = typer.Typer(
    name="systemd",
    help="Systemd unit management.",
    no_args_is_help=True,
)
app.add_typer(systemd_app)

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


# --- Top-level commands ---


@app.command()
def setup(config: ConfigOption = None) -> None:
    """Discover secrets, register with Podman, generate systemd drop-ins."""
    from psi.setup import run_setup

    settings = load_settings(config)
    run_setup(settings)


@app.command()
def login(config: ConfigOption = None) -> None:
    """Test authentication against Infisical."""
    from psi.api import InfisicalClient

    settings = load_settings(config)
    auth_configs: dict[str, AuthConfig] = {}
    if settings.auth:
        auth_configs["global"] = settings.auth
    for name, project in settings.projects.items():
        if project.auth:
            auth_configs[f"project:{name}"] = project.auth

    with InfisicalClient.from_settings(settings) as client:
        for label, auth in auth_configs.items():
            try:
                client.ensure_token(auth)
                console.print(f"  [green]OK[/green] {label}")
            except Exception as e:
                console.print(f"  [red]FAIL[/red] {label}: {e}")
                raise typer.Exit(1) from None

    console.print("[green]All auth methods verified.[/green]")


@app.command()
def install(
    mode: Annotated[
        str, typer.Option("--mode", help="Deployment mode: native or container.")
    ] = "native",
    image: Annotated[
        str | None, typer.Option("--image", help="Container image (required for container mode).")
    ] = None,
    config: ConfigOption = None,
) -> None:
    """Generate Podman shell driver config and state directory."""
    from psi.installer import install_driver_conf
    from psi.models import DeployMode

    deploy_mode = DeployMode(mode)
    if deploy_mode == DeployMode.CONTAINER and not image:
        console.print("[red]Container mode requires --image.[/red]")
        raise typer.Exit(1)

    settings = load_settings(config)
    install_driver_conf(settings, deploy_mode, image)


@app.command(name="env")
def env_cmd(
    project: Annotated[str, typer.Option(help="Project alias from config.")],
    secret_path: Annotated[str, typer.Option("--path", help="Infisical folder path.")] = "/",
    environment: Annotated[
        str | None,
        typer.Option(help="Override project environment."),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", help="Output format: export or env."),
    ] = "export",
    config: ConfigOption = None,
) -> None:
    """Fetch secrets and print as environment variables.

    Use with eval for shell export:
        eval "$(psi env --project myproject --path /mypath)"

    Use --format=env for KEY=VALUE lines (env files, EnvironmentFile=):
        psi env --project myproject --path /mypath --format env > /run/app/env
    """
    from psi.api import InfisicalClient

    settings = load_settings(config)
    proj = settings.projects.get(project)
    if not proj:
        console.print(
            f"[red]Unknown project '{project}'. Available: {', '.join(settings.projects)}[/red]"
        )
        raise typer.Exit(1)

    auth = resolve_auth(proj, settings)
    env = environment or proj.environment

    with InfisicalClient.from_settings(settings) as client:
        token = client.ensure_token(auth)
        secrets = client.list_secrets(token, proj.id, env, secret_path)

    for secret in secrets:
        key = secret["secretKey"]
        value = secret["secretValue"]
        if fmt == "export":
            escaped = value.replace("'", "'\\''")
            print(f"export {key}='{escaped}'")  # noqa: T201
        else:
            print(f"{key}={value}")  # noqa: T201


@app.command(name="write-file")
def write_file(
    secret_name: Annotated[str, typer.Argument(help="Secret name in Infisical.")],
    output: Annotated[Path, typer.Argument(help="Output file path.")],
    project: Annotated[str, typer.Option(help="Project alias from config.")],
    secret_path: Annotated[str, typer.Option(help="Infisical folder path.")] = "/",
    base64_decode: Annotated[
        bool, typer.Option("--base64", help="Base64-decode the value before writing.")
    ] = False,
    mode: Annotated[str, typer.Option(help="File permissions (octal).")] = "0600",
    config: ConfigOption = None,
) -> None:
    """Fetch a secret from Infisical and write it to a file."""
    from psi.api import InfisicalClient

    settings = load_settings(config)
    proj = settings.projects.get(project)
    if not proj:
        console.print(
            f"[red]Unknown project '{project}'. Available: {', '.join(settings.projects)}[/red]"
        )
        raise typer.Exit(1)

    auth = resolve_auth(proj, settings)

    with InfisicalClient.from_settings(settings) as client:
        token = client.ensure_token(auth)
        value = client.get_secret(token, proj.id, proj.environment, secret_path, secret_name)

    output.parent.mkdir(parents=True, exist_ok=True)

    if base64_decode:
        output.write_bytes(base64.b64decode(value))
    else:
        output.write_text(value)

    output.chmod(int(mode, 8))
    console.print(f"[green]Wrote {output}[/green]")


# --- Shell driver subcommands ---


@secret_app.command()
def store(config: ConfigOption = None) -> None:
    """Store a secret mapping (called by Podman)."""
    from psi.secret import store as do_store

    do_store(load_settings(config))


@secret_app.command()
def lookup(config: ConfigOption = None) -> None:
    """Fetch a secret value (called by Podman)."""
    from psi.secret import lookup as do_lookup

    do_lookup(load_settings(config))


@secret_app.command()
def delete(config: ConfigOption = None) -> None:
    """Remove a secret mapping (called by Podman)."""
    from psi.secret import delete as do_delete

    do_delete(load_settings(config))


@secret_app.command(name="list")
def list_cmd(config: ConfigOption = None) -> None:
    """List all registered secrets (called by Podman)."""
    from psi.secret import list_secrets

    list_secrets(load_settings(config))


JsonOption = Annotated[
    bool,
    typer.Option("--json", help="Force JSON output."),
]


@secret_app.command(name="status")
def secret_status(
    config: ConfigOption = None,
    json_output: JsonOption = False,
) -> None:
    """Show status of all workloads and their registered secrets."""
    from rich.table import Table

    from psi.output import render_or_json
    from psi.secret import get_secret_status

    settings = load_settings(config)
    workloads = get_secret_status(settings)

    table = Table(title="Secrets")
    table.add_column("Workload")
    table.add_column("Secret")
    table.add_column("Project")
    table.add_column("Path")
    table.add_column("Registered")

    for wl in workloads:
        if not wl.secrets:
            table.add_row(wl.workload, "—", "—", "—", "[yellow]none[/yellow]")
            continue
        for s in wl.secrets:
            reg = "[green]yes[/green]" if s.registered else "[red]no[/red]"
            table.add_row(wl.workload, s.name, s.project, s.path, reg)

    render_or_json(table, workloads, force_json=json_output)


# --- TLS certificate commands ---


@tls_app.command(name="issue")
def tls_issue(config: ConfigOption = None) -> None:
    """Issue all configured TLS certificates."""
    from psi.tls import issue_all

    issue_all(load_settings(config))


@tls_app.command(name="renew")
def tls_renew(config: ConfigOption = None) -> None:
    """Renew certificates approaching expiry."""
    from psi.tls import renew_due

    renew_due(load_settings(config))


@tls_app.command(name="status")
def tls_status(
    config: ConfigOption = None,
    json_output: JsonOption = False,
    timer: Annotated[
        str,
        typer.Option(help="Systemd timer unit name to check."),
    ] = "psi-tls-renew.timer",
) -> None:
    """Show status of all configured certificates."""
    from psi.output import render_or_json
    from psi.systemd import get_timer_info
    from psi.tls import build_tls_status_table, get_tls_status

    settings = load_settings(config)
    certs = get_tls_status(settings)
    table = build_tls_status_table(certs)

    timer_info = get_timer_info(timer)
    if timer_info and not json_output:
        console.print()
        console.print(f"[bold]Timer:[/bold] {timer}")
        console.print(f"  State: {timer_info.active_state}")
        if timer_info.last_trigger:
            console.print(f"  Last check: {timer_info.last_trigger}")
        if timer_info.next_elapse:
            console.print(f"  Next check: {timer_info.next_elapse}")
        console.print()

    render_or_json(table, certs, force_json=json_output)


# --- Systemd management commands ---


@systemd_app.command(name="install")
def systemd_install(
    mode: Annotated[str, typer.Option("--mode", help="Deployment mode: native or container.")],
    image: Annotated[
        str | None, typer.Option("--image", help="Container image (required for container mode).")
    ] = None,
    enable: Annotated[
        bool, typer.Option("--enable", help="Enable and start units after install.")
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

    settings = load_settings(config)
    install_systemd_units(settings, deploy_mode, image, enable)


def main() -> None:
    """Entry point for the psi CLI."""
    app()
