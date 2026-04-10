"""Boot-time setup: discover secrets, register with Podman, generate drop-ins."""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

import httpx
from loguru import logger

from psi.errors import ProviderError
from psi.systemd import daemon_reload

if TYPE_CHECKING:
    from pathlib import Path

    from psi.cache import Cache
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

    cache = _open_setup_cache(settings)
    cache_updates: dict[str, bytes] = {}

    try:
        for workload_name, workload in settings.workloads.items():
            if provider and workload.provider != provider:
                continue

            logger.info("Workload: {}", workload_name)

            if workload.provider == "infisical":
                _setup_infisical_workload(settings, workload_name, cache_updates)
            elif workload.provider == "nitrokeyhsm":
                logger.info("Nitrokey HSM workload — secrets created via 'psi nitrokeyhsm store'")
            else:
                logger.warning("Unknown provider '{}', skipping", workload.provider)

        if cache is not None and cache_updates:
            logger.info("Writing {} entries to secret cache", len(cache_updates))
            for key, value in cache_updates.items():
                cache.set(key, value)
            cache.save()
    finally:
        if cache is not None:
            cache.close()

    logger.info("Reloading systemd...")
    daemon_reload(settings.scope)
    logger.info("Setup complete.")


def _open_setup_cache(settings: PsiSettings) -> Cache | None:
    """Open the cache for write during setup, or return None on any failure."""
    if not settings.cache.enabled or settings.cache.backend is None:
        return None

    from psi.cache import Cache
    from psi.cache_backends import make_backend

    try:
        backend = make_backend(settings.cache.backend, settings)
        open_method = getattr(backend, "open", None)
        if callable(open_method):
            open_method()
    except Exception as e:
        logger.warning(
            "Secret cache backend {} unavailable during setup: {}. "
            "Skipping cache population — container starts will hit the live provider.",
            settings.cache.backend,
            e,
        )
        return None

    cache = Cache(settings.cache.resolve_path(settings.state_dir), backend)
    try:
        cache.load()
    except Exception as e:
        logger.warning(
            "Secret cache at {} is unreadable ({}); starting fresh.",
            cache.path,
            e,
        )
        cache.clear()
    return cache


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
    cache_updates: dict[str, bytes],
) -> None:
    """Run Infisical-specific setup for a workload with retry."""
    last_exc: Exception | None = None
    for attempt in range(len(_RETRY_DELAYS) + 1):
        try:
            _fetch_and_register_infisical(settings, workload_name, cache_updates)
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
    cache_updates: dict[str, bytes],
) -> None:
    """Fetch secrets from Infisical and register with Podman.

    Populates ``cache_updates`` with ``{namespaced_name: value_bytes}`` so the
    caller can flush the encrypted cache once all workloads are processed.
    """
    from psi.providers.infisical import InfisicalProvider
    from psi.providers.infisical.models import InfisicalConfig, resolve_auth

    infisical_config = InfisicalConfig.model_validate(settings.providers.get("infisical", {}))
    workload = settings.workloads[workload_name]
    provider = InfisicalProvider(settings)
    provider.open()

    try:
        merged: dict[str, str] = {}
        values: dict[str, bytes] = {}
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
                raw_value = secret.get("secretValue")
                if raw_value is not None:
                    values[key] = str(raw_value).encode("utf-8")

            logger.info("Found {} secrets", len(secrets))

        logger.info("Merged: {} unique secrets", len(merged))
        _register_secrets(settings, workload_name, merged)
        _generate_drop_in(settings, workload_name, merged)

        for key, value in values.items():
            cache_updates[f"{workload_name}--{key}"] = value
    finally:
        provider.close()


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


def dry_run_setup(settings: PsiSettings) -> None:
    """Inspect Podman secret state without mutating anything.

    For each shell-driver secret registered with Podman, classify it as one
    of:

    - ``managed`` — a mapping file exists in ``state_dir`` and the stored
      ``Spec.Driver.Options`` match the current ``containers.conf.d/psi.conf``.
    - ``stale-opts`` — a mapping file exists but the stored driver opts
      differ from the current conf (e.g. the socket token was rotated but
      ``psi setup`` has not been re-run). Re-run ``psi setup`` to refresh.
    - ``orphaned`` — no mapping file in ``state_dir``. A lookup would return
      404. Candidate for a future ``psi orphans --prune``.

    Does not fetch from Infisical/HSM or contact anything other than the
    local Podman API and the on-disk ``state_dir``. Safe to run at any time.
    """
    from psi.token import resolve_socket_token
    from psi.unitgen import generate_driver_conf

    current_opts = _parse_driver_opts(
        generate_driver_conf(settings.scope, token=resolve_socket_token(settings))
    )

    try:
        secrets = _list_podman_shell_secrets()
    except httpx.HTTPError as e:
        msg = f"Cannot reach Podman API at {_podman_socket_url()}: {e}"
        raise ProviderError(msg, provider_name="podman") from e

    managed, stale, orphaned = _classify_secrets(secrets, settings.state_dir, current_opts)
    _print_dry_run_report(managed, stale, orphaned)


_SHELL_OPT_KEYS = ("lookup", "store", "delete", "list")


def _parse_driver_opts(conf_text: str) -> dict[str, str]:
    """Extract the shell-driver opts from generated ``psi.conf`` TOML text.

    Avoids a full TOML parser — the generator produces a fixed shape, and
    the comparison only needs ``lookup``/``store``/``delete``/``list``.
    """
    opts: dict[str, str] = {}
    for line in conf_text.splitlines():
        for key in _SHELL_OPT_KEYS:
            prefix = f'{key} = "'
            if line.startswith(prefix) and line.endswith('"'):
                opts[key] = line[len(prefix) : -1]
    return opts


def _list_podman_shell_secrets() -> list[dict]:
    """Return every Podman secret whose driver is ``shell``."""
    transport = httpx.HTTPTransport(uds=_podman_socket_url())
    base = f"http://localhost/{_PODMAN_API_VERSION}"
    with httpx.Client(transport=transport, timeout=30.0) as client:
        resp = client.get(f"{base}/libpod/secrets/json")
        resp.raise_for_status()
        secrets = resp.json()
    return [s for s in secrets if s.get("Spec", {}).get("Driver", {}).get("Name") == "shell"]


def _classify_secrets(
    secrets: list[dict],
    state_dir: Path,
    current_opts: dict[str, str],
) -> tuple[list[str], list[str], list[str]]:
    """Bucket secrets into (managed, stale-opts, orphaned) by name."""
    managed: list[str] = []
    stale: list[str] = []
    orphaned: list[str] = []

    for secret in secrets:
        spec = secret.get("Spec", {})
        name = spec.get("Name", "")
        secret_id = secret.get("ID", "")
        if not name:
            continue
        raw_opts = spec.get("Driver", {}).get("Options", {})
        stored_opts = {k: raw_opts.get(k, "") for k in _SHELL_OPT_KEYS}
        mapping_exists = (state_dir / secret_id).exists()
        if not mapping_exists:
            orphaned.append(name)
        elif stored_opts != current_opts:
            stale.append(name)
        else:
            managed.append(name)

    managed.sort()
    stale.sort()
    orphaned.sort()
    return managed, stale, orphaned


def _print_dry_run_report(managed: list[str], stale: list[str], orphaned: list[str]) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    total = len(managed) + len(stale) + len(orphaned)

    summary = Table(title=f"psi setup --dry-run ({total} shell-driver secrets)")
    summary.add_column("Status")
    summary.add_column("Count", justify="right")
    summary.add_row("[green]managed[/green]", str(len(managed)))
    summary.add_row("[yellow]stale-opts[/yellow]", str(len(stale)))
    summary.add_row("[red]orphaned[/red]", str(len(orphaned)))
    console.print(summary)

    if stale:
        console.print(
            "\n[yellow]Stale-opts[/yellow] — driver opts differ from current "
            "psi.conf; re-run `psi setup` to refresh:"
        )
        for name in stale:
            console.print(f"  {name}")

    if orphaned:
        console.print(
            "\n[red]Orphaned[/red] — no mapping file in state_dir; lookups would return 404:"
        )
        for name in orphaned:
            console.print(f"  {name}")

    if not stale and not orphaned:
        console.print("\n[green]All secrets are managed — nothing to do.[/green]")
