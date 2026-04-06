"""Infisical-specific CLI commands — env, write-file, import, tls, login."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.console import Console

from psi.files import write_bytes_secure, write_text_secure
from psi.models import detect_scope
from psi.settings import load_settings

if TYPE_CHECKING:
    from psi.providers.infisical.models import AuthConfig

console = Console()

infisical_app = typer.Typer(
    name="infisical",
    help="Infisical provider commands.",
    no_args_is_help=True,
)
tls_app = typer.Typer(
    name="tls",
    help="TLS certificate management via Infisical PKI.",
    no_args_is_help=True,
)
infisical_app.add_typer(tls_app)
import_app = typer.Typer(
    name="import",
    help="Import secrets into Infisical from external sources.",
    no_args_is_help=True,
)
infisical_app.add_typer(import_app)

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", envvar="PSI_CONFIG", help="Config file."),
]


def _get_infisical_config(config: Path | None = None):  # noqa: ANN202
    """Load settings and return InfisicalConfig."""
    from psi.providers.infisical.models import InfisicalConfig

    settings = load_settings(config, scope=detect_scope())
    return settings, InfisicalConfig.model_validate(settings.providers.get("infisical", {}))


@infisical_app.command()
def login(config: ConfigOption = None) -> None:
    """Test authentication against Infisical."""
    from psi.providers.infisical.api import InfisicalClient

    settings, inf_config = _get_infisical_config(config)
    auth_configs: dict[str, AuthConfig] = {}
    if inf_config.auth:
        auth_configs["global"] = inf_config.auth
    for name, project in inf_config.projects.items():
        if project.auth:
            auth_configs[f"project:{name}"] = project.auth

    client = InfisicalClient(
        inf_config.api_url,
        settings.state_dir,
        inf_config.token.ttl,
        inf_config.verify_ssl,
    )
    try:
        for label, auth in auth_configs.items():
            try:
                client.ensure_token(auth)
                console.print(f"  [green]OK[/green] {label}")
            except Exception as e:
                console.print(f"  [red]FAIL[/red] {label}: {e}")
                raise typer.Exit(1) from None
    finally:
        client.close()

    console.print("[green]All auth methods verified.[/green]")


@infisical_app.command(name="env")
def env_cmd(
    project: Annotated[str, typer.Option(help="Project alias.")],
    secret_path: Annotated[
        str,
        typer.Option("--path", help="Infisical folder path."),
    ] = "/",
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
    """Fetch secrets and print as environment variables."""
    from psi.providers.infisical.api import InfisicalClient
    from psi.providers.infisical.models import resolve_auth

    settings, inf_config = _get_infisical_config(config)
    proj = inf_config.projects.get(project)
    if not proj:
        console.print(
            f"[red]Unknown project '{project}'. Available: {', '.join(inf_config.projects)}[/red]"
        )
        raise typer.Exit(1)

    auth = resolve_auth(proj, inf_config)
    env = environment or proj.environment

    client = InfisicalClient(
        inf_config.api_url,
        settings.state_dir,
        inf_config.token.ttl,
        inf_config.verify_ssl,
    )
    try:
        token = client.ensure_token(auth)
        secrets = client.list_secrets(token, proj.id, env, secret_path)
    finally:
        client.close()

    for secret in secrets:
        key = secret["secretKey"]
        value = secret["secretValue"]
        if fmt == "export":
            escaped = value.replace("'", "'\\''")
            print(f"export {key}='{escaped}'")  # noqa: T201
        else:
            print(f"{key}={value}")  # noqa: T201


@infisical_app.command(name="write-file")
def write_file(
    secret_name: Annotated[
        str,
        typer.Argument(help="Secret name in Infisical."),
    ],
    output: Annotated[Path, typer.Argument(help="Output file path.")],
    project: Annotated[str, typer.Option(help="Project alias.")],
    secret_path: Annotated[
        str,
        typer.Option(help="Infisical folder path."),
    ] = "/",
    base64_decode: Annotated[
        bool,
        typer.Option("--base64", help="Base64-decode the value."),
    ] = False,
    mode: Annotated[
        str,
        typer.Option(help="File permissions (octal)."),
    ] = "0600",
    config: ConfigOption = None,
) -> None:
    """Fetch a secret from Infisical and write it to a file."""
    from psi.providers.infisical.api import InfisicalClient
    from psi.providers.infisical.models import resolve_auth

    settings, inf_config = _get_infisical_config(config)
    proj = inf_config.projects.get(project)
    if not proj:
        console.print(
            f"[red]Unknown project '{project}'. Available: {', '.join(inf_config.projects)}[/red]"
        )
        raise typer.Exit(1)

    auth = resolve_auth(proj, inf_config)

    client = InfisicalClient(
        inf_config.api_url,
        settings.state_dir,
        inf_config.token.ttl,
        inf_config.verify_ssl,
    )
    try:
        token = client.ensure_token(auth)
        value = client.get_secret(
            token,
            proj.id,
            proj.environment,
            secret_path,
            secret_name,
        )
    finally:
        client.close()

    output.parent.mkdir(parents=True, exist_ok=True)
    file_mode = int(mode, 8)
    if base64_decode:
        write_bytes_secure(output, base64.b64decode(value), mode=file_mode)
    else:
        write_text_secure(output, value, mode=file_mode)
    console.print(f"[green]Wrote {output}[/green]")


# --- TLS commands ---


@tls_app.command(name="issue")
def tls_issue(config: ConfigOption = None) -> None:
    """Issue all configured TLS certificates."""
    from psi.providers.infisical.tls import issue_all

    settings = load_settings(config, scope=detect_scope())
    issue_all(settings)


@tls_app.command(name="renew")
def tls_renew(config: ConfigOption = None) -> None:
    """Renew certificates approaching expiry."""
    from psi.providers.infisical.tls import renew_due

    settings = load_settings(config, scope=detect_scope())
    renew_due(settings)


@tls_app.command(name="status")
def tls_status(
    config: ConfigOption = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Force JSON output."),
    ] = False,
    timer: Annotated[
        str,
        typer.Option(help="Systemd timer unit name to check."),
    ] = "psi-tls-renew.timer",
) -> None:
    """Show status of all configured certificates."""
    from psi.output import render_or_json
    from psi.providers.infisical.tls import (
        build_tls_status_table,
        get_tls_status,
    )
    from psi.systemd import get_timer_info

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


# --- Import commands ---

ConflictOption = Annotated[
    str,
    typer.Option("--conflict", help="Conflict policy: skip, overwrite, fail."),
]
DryRunOption = Annotated[
    bool,
    typer.Option("--dry-run", help="Preview without writing."),
]
ProjectOption = Annotated[str, typer.Option("--project", help="Project alias.")]
ImportPathOption = Annotated[
    str,
    typer.Option("--path", help="Infisical folder path."),
]
EnvironmentOption = Annotated[
    str | None,
    typer.Option("--environment", help="Override environment."),
]
JsonOption = Annotated[
    bool,
    typer.Option("--json", help="Force JSON output."),
]


def _run_import_and_display(
    settings: Any,
    inf_config: Any,
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

    from psi.output import render_or_json
    from psi.providers.infisical.api import InfisicalClient
    from psi.providers.infisical.importer import run_import
    from psi.providers.infisical.models import ConflictPolicy, resolve_auth

    proj = inf_config.projects.get(project_alias)
    if not proj:
        console.print(
            f"[red]Unknown project '{project_alias}'. "
            f"Available: {', '.join(inf_config.projects)}[/red]"
        )
        raise typer.Exit(1)

    auth = resolve_auth(proj, inf_config)
    env = environment or proj.environment

    if not secrets:
        console.print("[yellow]No secrets found to import.[/yellow]")
        raise typer.Exit(0)

    client = InfisicalClient(
        inf_config.api_url,
        settings.state_dir,
        inf_config.token.ttl,
        inf_config.verify_ssl,
    )
    try:
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
    finally:
        client.close()

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
    console.print(
        f"\n[bold]Total: {result.total}[/bold] "
        f"[green]{prefix}: {result.created}[/green] "
        f"[yellow]Skipped: {result.skipped}[/yellow] "
        f"[cyan]Overwritten: {result.overwritten}[/cyan] "
        f"[red]Failed: {result.failed}[/red]"
    )

    if not dry_run and result.failed > 0:
        raise typer.Exit(1)


@import_app.command(name="env-file")
def import_env_file(
    file: Annotated[
        Path | None,
        typer.Argument(help="Path to .env file, or omit for stdin."),
    ] = None,
    project: ProjectOption = ...,  # ty: ignore[invalid-parameter-default]
    secret_path: ImportPathOption = "/",
    environment: EnvironmentOption = None,
    conflict: ConflictOption = "fail",
    dry_run: DryRunOption = False,
    json_output: JsonOption = False,
    config: ConfigOption = None,
) -> None:
    """Import secrets from a KEY=VALUE env file."""
    from psi.providers.infisical.importer import read_env_file

    settings, inf_config = _get_infisical_config(config)
    secrets = read_env_file(file)
    _run_import_and_display(
        settings,
        inf_config,
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
    all_secrets: Annotated[
        bool,
        typer.Option("--all", help="Import all podman secrets."),
    ] = False,
    project: ProjectOption = ...,  # ty: ignore[invalid-parameter-default]
    secret_path: ImportPathOption = "/",
    environment: EnvironmentOption = None,
    conflict: ConflictOption = "fail",
    dry_run: DryRunOption = False,
    json_output: JsonOption = False,
    config: ConfigOption = None,
) -> None:
    """Import secrets from Podman's secret store."""
    from psi.providers.infisical.importer import read_podman_secrets

    if not name and not all_secrets:
        console.print("[red]Specify --name or --all.[/red]")
        raise typer.Exit(1)

    settings, inf_config = _get_infisical_config(config)
    secrets = read_podman_secrets(None if all_secrets else name)
    _run_import_and_display(
        settings,
        inf_config,
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
        typer.Argument(help="One or more .container files."),
    ],
    project: ProjectOption = ...,  # ty: ignore[invalid-parameter-default]
    secret_path: ImportPathOption = "/",
    environment: EnvironmentOption = None,
    resolve_secrets: Annotated[
        bool,
        typer.Option("--resolve-secrets", help="Resolve Secret= refs."),
    ] = False,
    conflict: ConflictOption = "fail",
    dry_run: DryRunOption = False,
    json_output: JsonOption = False,
    config: ConfigOption = None,
) -> None:
    """Import secrets from quadlet .container files."""
    from psi.providers.infisical.importer import read_quadlet

    settings, inf_config = _get_infisical_config(config)
    secrets = read_quadlet(files, resolve_secrets=resolve_secrets)
    _run_import_and_display(
        settings,
        inf_config,
        project,
        secret_path,
        environment,
        secrets,
        conflict,
        dry_run,
        json_output,
    )
