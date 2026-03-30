"""psi CLI — Podman Secret Infisical."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.console import Console

from psi.models import detect_scope
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
import_app = typer.Typer(
    name="import",
    help="Import secrets into Infisical from external sources.",
    no_args_is_help=True,
)
app.add_typer(import_app)

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

    settings = load_settings(config, scope=detect_scope())
    run_setup(settings)


@app.command()
def login(config: ConfigOption = None) -> None:
    """Test authentication against Infisical."""
    from psi.api import InfisicalClient

    settings = load_settings(config, scope=detect_scope())
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

    settings = load_settings(config, scope=detect_scope())
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

    settings = load_settings(config, scope=detect_scope())
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

    settings = load_settings(config, scope=detect_scope())
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

    settings = load_settings(config, scope=detect_scope())
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

    issue_all(load_settings(config, scope=detect_scope()))


@tls_app.command(name="renew")
def tls_renew(config: ConfigOption = None) -> None:
    """Renew certificates approaching expiry."""
    from psi.tls import renew_due

    renew_due(load_settings(config, scope=detect_scope()))


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

    settings = load_settings(config, scope=detect_scope())
    certs = get_tls_status(settings)
    table = build_tls_status_table(certs)

    from psi.models import SystemdScope

    user_mode = settings.scope == SystemdScope.USER
    timer_info = get_timer_info(timer, user_mode=user_mode)
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

    settings = load_settings(config, scope=detect_scope())
    install_systemd_units(settings, deploy_mode, image, enable)


# --- Import subcommands ---


ConflictOption = Annotated[
    str,
    typer.Option(
        "--conflict",
        help="Conflict policy: skip, overwrite, or fail.",
    ),
]
DryRunOption = Annotated[bool, typer.Option("--dry-run", help="Preview without writing.")]
ProjectOption = Annotated[
    str, typer.Option("--project", help="Project alias from config (required).")
]
ImportPathOption = Annotated[str, typer.Option("--path", help="Infisical folder path.")]
EnvironmentOption = Annotated[
    str | None, typer.Option("--environment", help="Override project environment.")
]


def _run_import_and_display(
    settings: Any,
    project_alias: str,
    secret_path: str,
    environment: str | None,
    secrets: list[Any],
    conflict: str,
    dry_run: bool,
    json_output: bool,
) -> None:
    """Shared logic for import subcommands."""
    from rich.table import Table

    from psi.api import InfisicalClient
    from psi.importer import run_import
    from psi.models import ConflictPolicy
    from psi.output import render_or_json

    proj = settings.projects.get(project_alias)
    if not proj:
        console.print(
            f"[red]Unknown project '{project_alias}'. "
            f"Available: {', '.join(settings.projects)}[/red]"
        )
        raise typer.Exit(1)

    auth = resolve_auth(proj, settings)
    env = environment or proj.environment

    if not secrets:
        console.print("[yellow]No secrets found to import.[/yellow]")
        raise typer.Exit(0)

    with InfisicalClient.from_settings(settings) as client:
        token = client.ensure_token(auth)
        result = run_import(
            client,
            token,
            proj.id,
            env,
            secret_path,
            secrets,
            conflict=ConflictPolicy(conflict),
            dry_run=dry_run,
        )

    table = Table(title="Import Results")
    table.add_column("Key")
    table.add_column("Outcome")
    table.add_column("Detail")

    style_map = {
        "created": "green",
        "skipped": "yellow",
        "overwritten": "cyan",
        "failed": "red",
        "dry_run": "dim",
    }
    for s in result.secrets:
        style = style_map.get(s.outcome, "")
        table.add_row(s.key, f"[{style}]{s.outcome}[/{style}]", s.detail)

    render_or_json(table, result.secrets, force_json=json_output)

    prefix = "Would create" if dry_run else "Created"
    skip_prefix = "Would skip" if dry_run else "Skipped"
    overwrite_prefix = "Would overwrite" if dry_run else "Overwritten"
    fail_prefix = "Would fail" if dry_run else "Failed"
    console.print(
        f"\n[bold]Total: {result.total}[/bold] "
        f"[green]{prefix}: {result.created}[/green] "
        f"[yellow]{skip_prefix}: {result.skipped}[/yellow] "
        f"[cyan]{overwrite_prefix}: {result.overwritten}[/cyan] "
        f"[red]{fail_prefix}: {result.failed}[/red]"
    )

    if not dry_run and result.failed > 0:
        raise typer.Exit(1)


@import_app.command(name="env-file")
def import_env_file(
    file: Annotated[
        Path | None,
        typer.Argument(help="Path to .env file, or omit for stdin."),
    ] = None,
    project: ProjectOption = ...,  # ty: ignore[invalid-parameter-default]  # Typer required option
    secret_path: ImportPathOption = "/",
    environment: EnvironmentOption = None,
    conflict: ConflictOption = "fail",
    dry_run: DryRunOption = False,
    json_output: JsonOption = False,
    config: ConfigOption = None,
) -> None:
    """Import secrets from a KEY=VALUE env file."""
    from psi.importer import read_env_file

    settings = load_settings(config, scope=detect_scope())
    secrets = read_env_file(file)
    _run_import_and_display(
        settings,
        project,
        secret_path,
        environment,
        secrets,
        conflict,
        dry_run,
        json_output,
    )


@import_app.command(name="podman-secret")
def import_podman_secret(
    name: Annotated[
        list[str] | None,
        typer.Option("--name", help="Secret name (repeatable)."),
    ] = None,
    all_secrets: Annotated[bool, typer.Option("--all", help="Import all podman secrets.")] = False,
    project: ProjectOption = ...,  # ty: ignore[invalid-parameter-default]  # Typer required option
    secret_path: ImportPathOption = "/",
    environment: EnvironmentOption = None,
    conflict: ConflictOption = "fail",
    dry_run: DryRunOption = False,
    json_output: JsonOption = False,
    config: ConfigOption = None,
) -> None:
    """Import secrets from Podman's secret store."""
    from psi.importer import read_podman_secrets

    if not name and not all_secrets:
        console.print("[red]Specify --name or --all.[/red]")
        raise typer.Exit(1)

    settings = load_settings(config, scope=detect_scope())
    secrets = read_podman_secrets(None if all_secrets else name)
    _run_import_and_display(
        settings,
        project,
        secret_path,
        environment,
        secrets,
        conflict,
        dry_run,
        json_output,
    )


@import_app.command(name="quadlet")
def import_quadlet(
    files: Annotated[
        list[Path],
        typer.Argument(help="One or more .container file paths."),
    ],
    project: ProjectOption = ...,  # ty: ignore[invalid-parameter-default]  # Typer required option
    secret_path: ImportPathOption = "/",
    environment: EnvironmentOption = None,
    resolve_secrets: Annotated[
        bool,
        typer.Option(
            "--resolve-secrets",
            help="Resolve Secret= refs via podman inspect.",
        ),
    ] = False,
    conflict: ConflictOption = "fail",
    dry_run: DryRunOption = False,
    json_output: JsonOption = False,
    config: ConfigOption = None,
) -> None:
    """Import secrets from quadlet .container files."""
    from psi.importer import read_quadlet

    settings = load_settings(config, scope=detect_scope())
    secrets = read_quadlet(files, resolve_secrets=resolve_secrets)
    _run_import_and_display(
        settings,
        project,
        secret_path,
        environment,
        secrets,
        conflict,
        dry_run,
        json_output,
    )


@import_app.command(name="workload")
def import_workload(
    name: Annotated[str, typer.Argument(help="Workload name from config.")],
    resolve_secrets: Annotated[
        bool,
        typer.Option(
            "--resolve-secrets",
            help="Resolve Secret= refs via podman inspect.",
        ),
    ] = False,
    conflict: ConflictOption = "fail",
    dry_run: DryRunOption = False,
    json_output: JsonOption = False,
    config: ConfigOption = None,
) -> None:
    """Import secrets from a workload's configured quadlet unit file."""
    from psi.importer import read_quadlet

    settings = load_settings(config, scope=detect_scope())
    workload = settings.workloads.get(name)
    if not workload:
        console.print(
            f"[red]Unknown workload '{name}'. Available: {', '.join(settings.workloads)}[/red]"
        )
        raise typer.Exit(1)
    if not workload.unit:
        console.print(f"[red]Workload '{name}' has no 'unit' configured.[/red]")
        raise typer.Exit(1)
    if not workload.secrets:
        console.print(f"[red]Workload '{name}' has no secret sources configured.[/red]")
        raise typer.Exit(1)

    unit_path = settings.systemd_dir / workload.unit
    if not unit_path.exists():
        console.print(f"[red]Unit file not found: {unit_path}[/red]")
        raise typer.Exit(1)

    source = workload.secrets[0]
    secrets = read_quadlet([unit_path], resolve_secrets=resolve_secrets)
    _run_import_and_display(
        settings,
        source.project,
        source.path,
        None,
        secrets,
        conflict,
        dry_run,
        json_output,
    )


def main() -> None:
    """Entry point for the psi CLI."""
    app()
