"""psi CLI — Podman Secret Infrastructure."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import httpx
import typer
from pydantic import ValidationError
from rich.console import Console

from psi.errors import PsiError
from psi.logging import configure_logging
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
cache_app = typer.Typer(
    name="cache",
    help="Encrypted secret cache management.",
    no_args_is_help=True,
)
app.add_typer(cache_app)

# Register provider subcommands
from psi.providers.infisical.cli import infisical_app  # noqa: E402

app.add_typer(infisical_app)

from psi.providers.nitrokeyhsm.cli import nitrokeyhsm_app  # noqa: E402

app.add_typer(nitrokeyhsm_app)

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


@app.callback()
def _configure(
    log_level: Annotated[
        str,
        typer.Option(
            "--log-level",
            envvar="PSI_LOG_LEVEL",
            help="Log level: DEBUG, INFO, WARNING, ERROR.",
        ),
    ] = "INFO",
    log_json: Annotated[
        bool,
        typer.Option(
            "--log-json",
            envvar="PSI_LOG_JSON",
            help="Force JSON log output (default: auto-detect from TTY).",
        ),
    ] = False,
) -> None:
    """Configure logging before any subcommand runs."""
    configure_logging(level=log_level, json_output=log_json or None)


# --- Top-level commands ---


@app.command()
def setup(
    config: ConfigOption = None,
    provider: Annotated[
        str | None,
        typer.Option("--provider", help="Only setup workloads for this provider."),
    ] = None,
) -> None:
    """Discover secrets, register with Podman, generate systemd drop-ins."""
    from psi.setup import run_setup

    settings = load_settings(config, scope=detect_scope())
    run_setup(settings, provider=provider)


@app.command()
def serve(config: ConfigOption = None) -> None:
    """Run the secret lookup service on a Unix socket."""
    from psi.models import socket_path
    from psi.serve import run_serve

    settings = load_settings(config, scope=detect_scope())
    run_serve(settings, str(socket_path(settings.scope)))


@app.command()
def install(
    config: ConfigOption = None,
    stdout: Annotated[
        bool,
        typer.Option(
            "--stdout",
            help=(
                "Print the driver conf to stdout instead of writing it. "
                "Use in container mode: `podman exec psi-secrets psi install "
                "--stdout | sudo tee /etc/containers/containers.conf.d/psi.conf`."
            ),
        ),
    ] = False,
) -> None:
    """Generate Podman shell driver config and state directory."""
    from psi.installer import install_driver_conf, render_driver_conf

    settings = load_settings(config, scope=detect_scope())
    if stdout:
        typer.echo(render_driver_conf(settings), nl=False)
        return
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
    from loguru import logger

    from psi.installer import install_systemd_units
    from psi.models import DeployMode

    deploy_mode = DeployMode(mode)
    if deploy_mode == DeployMode.CONTAINER and not image:
        logger.error("Container mode requires --image.")
        raise typer.Exit(1)

    settings = load_settings(config, scope=detect_scope())
    install_systemd_units(settings, deploy_mode, image, enable)


# --- Cache management commands ---


@cache_app.command(name="init")
def cache_init(
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            help="Cache encryption backend: 'tpm' or 'hsm'. Required.",
        ),
    ] = None,
    key_path: Annotated[
        Path | None,
        typer.Option(
            "--key-path",
            help="Where to write the sealed TPM key (tpm backend only). "
            "Default: <config_dir>/cache.key.",
        ),
    ] = None,
    config: ConfigOption = None,
) -> None:
    """Provision the cache encryption key and write an empty cache file."""
    import os
    import subprocess

    from psi.cache import Cache
    from psi.cache_backends import HsmBackend, TpmBackend
    from psi.errors import ConfigError
    from psi.providers.nitrokeyhsm.models import NitrokeyHSMConfig

    if backend is None:
        console.print("Available backends: [bold]tpm[/bold], [bold]hsm[/bold]", highlight=False)
        console.print("Re-run with --backend tpm or --backend hsm.", highlight=False)
        raise typer.Exit(1)
    if backend not in ("tpm", "hsm"):
        raise ConfigError(f"Unknown cache backend: {backend!r}. Valid: 'tpm', 'hsm'.")

    settings = load_settings(config, scope=detect_scope())
    cache_path = settings.cache.resolve_path(settings.state_dir)
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    if backend == "tpm":
        raw_key = os.urandom(32)
        target_key_path = key_path or (settings.config_dir / "cache.key")
        target_key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(
                [
                    "systemd-creds",
                    "encrypt",
                    "--name=psi-cache-key",
                    "--tpm2-pcrs=7",
                    "-",
                    str(target_key_path),
                ],
                input=raw_key,
                check=True,
            )
        except FileNotFoundError as e:
            msg = (
                "systemd-creds not found. TPM backend requires systemd >= 250 "
                "with TPM2 support. Install systemd-container or choose a different backend."
            )
            raise ConfigError(msg) from e
        except subprocess.CalledProcessError as e:
            msg = (
                f"systemd-creds failed (exit {e.returncode}). "
                "Check that this host has a TPM2 and the current user has access."
            )
            raise ConfigError(msg) from e

        cache = Cache(cache_path, TpmBackend(key=raw_key))
        cache.save()
        console.print(
            f"Sealed TPM key → [bold]{target_key_path}[/bold]\n"
            f"Empty cache    → [bold]{cache_path}[/bold]\n"
            f"Add this to the psi serve unit:\n"
            f"  LoadCredentialEncrypted=psi-cache-key:{target_key_path}",
            highlight=False,
        )
        return

    # HSM backend
    raw = settings.providers.get("nitrokeyhsm")
    if not raw:
        raise ConfigError(
            "HSM cache backend requires providers.nitrokeyhsm to be configured. "
            "Add a nitrokeyhsm provider block to your config and run 'psi nitrokeyhsm init' first.",
        )
    hsm_backend = HsmBackend(NitrokeyHSMConfig.model_validate(raw))
    hsm_backend.open()
    try:
        cache = Cache(cache_path, hsm_backend)
        cache.save()
    finally:
        hsm_backend.close()
    console.print(
        f"Empty cache → [bold]{cache_path}[/bold]\n"
        "Cache will be unsealed via PKCS#11 at 'psi serve' startup.",
        highlight=False,
    )


@cache_app.command(name="refresh")
def cache_refresh(config: ConfigOption = None) -> None:
    """Re-run setup to refresh every cached secret from providers."""
    from psi.setup import run_setup

    settings = load_settings(config, scope=detect_scope())
    run_setup(settings)


@cache_app.command(name="invalidate")
def cache_invalidate(
    secret_id: Annotated[str, typer.Argument(help="Namespaced secret ID to drop.")],
    config: ConfigOption = None,
) -> None:
    """Drop a single entry from the cache and persist the change."""
    from psi.cache import Cache
    from psi.cache_backends import make_backend
    from psi.errors import ConfigError

    settings = load_settings(config, scope=detect_scope())
    if not settings.cache.enabled or settings.cache.backend is None:
        raise ConfigError("Cache is not enabled or has no backend configured.")

    backend = make_backend(settings.cache.backend, settings)
    open_method = getattr(backend, "open", None)
    if callable(open_method):
        open_method()
    try:
        cache = Cache(settings.cache.resolve_path(settings.state_dir), backend)
        cache.load()
        if cache.invalidate(secret_id):
            cache.save()
            console.print(f"Dropped [bold]{secret_id}[/bold] from cache.", highlight=False)
        else:
            console.print(f"No cache entry for [bold]{secret_id}[/bold].", highlight=False)
    finally:
        backend.close()


_BACKEND_TAG_NAMES = {0x01: "tpm", 0x02: "hsm"}


@cache_app.command(name="status")
def cache_status(
    verify: Annotated[
        bool,
        typer.Option(
            "--verify",
            help="Decrypt the cache and report the entry count. Requires HSM/TPM access.",
        ),
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Print cache backend and file metadata.

    The default fast path reads only config + file header — no crypto, no HSM
    session, no TPM unseal. Use ``--verify`` to decrypt the cache and report
    the entry count; this takes as long as a full provider open.
    """
    import datetime as _dt

    from psi.cache import Cache, CacheError, read_header
    from psi.cache_backends import make_backend

    settings = load_settings(config, scope=detect_scope())
    cache_path = settings.cache.resolve_path(settings.state_dir)

    console.print(f"Cache path:    [bold]{cache_path}[/bold]", highlight=False)
    console.print(
        f"Enabled:       [bold]{settings.cache.enabled}[/bold]",
        highlight=False,
    )
    console.print(
        f"Backend:       [bold]{settings.cache.backend or '(none)'}[/bold]",
        highlight=False,
    )

    if not cache_path.exists():
        console.print("File:          [yellow]not provisioned[/yellow]", highlight=False)
        return

    stat = cache_path.stat()
    mtime = _dt.datetime.fromtimestamp(stat.st_mtime, tz=_dt.UTC).isoformat()
    console.print(f"File size:     [bold]{stat.st_size}[/bold] bytes", highlight=False)
    console.print(f"Last written:  [bold]{mtime}[/bold]", highlight=False)

    try:
        version, backend_tag = read_header(cache_path)
    except CacheError as e:
        console.print(f"Header:        [red]{e}[/red]", highlight=False)
        return

    tag_name = _BACKEND_TAG_NAMES.get(backend_tag, f"unknown ({backend_tag:#x})")
    console.print(
        f"On-disk tag:   [bold]{tag_name}[/bold] (version {version})",
        highlight=False,
    )

    if not verify:
        console.print(
            "Entries:       [dim]not counted (pass --verify to decrypt)[/dim]",
            highlight=False,
        )
        return

    if not settings.cache.enabled or settings.cache.backend is None:
        console.print(
            "Entries:       [red]cannot verify — no backend configured[/red]",
            highlight=False,
        )
        return

    backend = make_backend(settings.cache.backend, settings)
    open_method = getattr(backend, "open", None)
    try:
        if callable(open_method):
            open_method()
        cache = Cache(cache_path, backend)
        cache.load()
        console.print(f"Entries:       [bold]{len(cache)}[/bold]", highlight=False)
    except Exception as e:
        console.print(f"Entries:       [red]unreadable — {e}[/red]", highlight=False)
    finally:
        backend.close()


def main() -> None:
    """Entry point for the psi CLI."""
    try:
        app()
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except PsiError as e:
        _print_error(str(e))
        raise SystemExit(1) from e
    except ValidationError as e:
        _print_validation_error(e)
        raise SystemExit(1) from e
    except httpx.HTTPError as e:
        _print_error(f"Network error: {e}")
        raise SystemExit(1) from e
    except Exception as e:
        _print_bug()
        raise SystemExit(2) from e


def _print_error(message: str) -> None:
    console.print(f"[red]Error:[/red] {message}", highlight=False)


def _print_validation_error(exc: ValidationError) -> None:
    lines = ["Configuration error:"]
    for err in exc.errors():
        loc = " → ".join(str(p) for p in err["loc"])
        lines.append(f"  - {loc}: {err['msg']}")
    console.print("\n".join(lines), style="red", highlight=False)


def _print_bug() -> None:
    console.print(
        "[red]Internal error — this is a bug.[/red]\n"
        "Please report it at "
        "https://github.com/quickvm/psi/issues\n",
        highlight=False,
    )
    console.print_exception()
