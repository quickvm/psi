"""Boot-time setup: discover secrets, register with Podman, generate drop-ins."""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

import httpx
from loguru import logger

from psi.errors import DriftDetectedError, ProviderError
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

    Raises:
        DriftDetectedError: when one or more Podman secrets under ``<workload>--*``
            are missing from the current fetch. Drop-ins are still written
            and systemd is still reloaded — the error fires at the end so
            the caller (and the setup systemd unit) sees a non-zero exit.
    """
    settings.state_dir.mkdir(parents=True, exist_ok=True)

    cache = _open_setup_cache(settings)
    # Keyed by the canonical mapping bytes so the caller can compute the
    # HMAC cache key once the cache object is available.
    values_by_mapping: dict[bytes, bytes] = {}
    drift: list[str] = []

    try:
        for workload_name, workload in settings.workloads.items():
            if provider and workload.provider != provider:
                continue

            logger.info("Workload: {}", workload_name)

            if workload.provider == "infisical":
                _setup_infisical_workload(settings, workload_name, values_by_mapping, drift)
            elif workload.provider == "nitrokeyhsm":
                logger.info("Nitrokey HSM workload — secrets created via 'psi nitrokeyhsm store'")
            else:
                logger.warning("Unknown provider '{}', skipping", workload.provider)

        if cache is not None and values_by_mapping:
            logger.info("Writing {} entries to secret cache", len(values_by_mapping))
            for mapping_bytes, value in values_by_mapping.items():
                cache.set(cache.cache_key(mapping_bytes), value)
            cache.save()
    finally:
        if cache is not None:
            cache.close()

    logger.info("Reloading systemd...")
    daemon_reload(settings.scope)
    logger.info("Setup complete.")

    if drift:
        msg = (
            f"Drift detected: {len(drift)} Podman secret(s) not present in "
            "this fetch — drop-ins will not reference them, so containers "
            "will boot without those env vars. Add 'recursive: true' to the "
            "source(s) in config.yaml if secrets live in a subfolder, or "
            "remove the stale secrets with 'podman secret rm'. Run "
            "'psi setup --dry-run' for per-workload details."
        )
        raise DriftDetectedError(msg)


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
    values_by_mapping: dict[bytes, bytes],
    drift: list[str],
) -> None:
    """Run Infisical-specific setup for a workload with retry."""
    last_exc: Exception | None = None
    for attempt in range(len(_RETRY_DELAYS) + 1):
        try:
            _fetch_and_register_infisical(settings, workload_name, values_by_mapping, drift)
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
    values_by_mapping: dict[bytes, bytes],
    drift: list[str],
) -> None:
    """Fetch secrets from Infisical and register with Podman.

    Populates ``values_by_mapping`` with ``{canonical_mapping_bytes: value}``.
    The caller computes the HMAC cache key from these bytes once the cache
    is available. Keying by mapping content makes the cache survive Podman's
    delete+create churn — the same mapping always produces the same cache
    key, regardless of the hex ID Podman has assigned to it today.

    Between ``_register_secrets`` and ``_generate_drop_in``, compares the
    ``<workload>--*`` Podman namespace against ``merged`` and appends any
    stale names (present in Podman, absent from this fetch) to ``drift``.
    Logs a warning per item. The drop-in is still generated from ``merged``
    alone — this keeps the fix local to the fetch, and the caller decides
    what to do about the accumulated drift (``run_setup`` raises at the end).
    """
    from psi.provider import mapping_cache_bytes, parse_mapping
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

        orphans = _check_workload_drift(workload_name, merged)
        for orphan in orphans:
            logger.warning(
                "Drift: Podman secret '{}' is not in this fetch — the "
                "drop-in will not reference it. If the key lives in an "
                "Infisical subfolder, add 'recursive: true' to the source "
                "in config.yaml. Otherwise remove the stale secret: "
                "podman secret rm {}",
                orphan,
                orphan,
            )
        drift.extend(orphans)

        _generate_drop_in(settings, workload_name, merged)

        for key, value in values.items():
            mapping_bytes = mapping_cache_bytes(parse_mapping(merged[key]))
            values_by_mapping[mapping_bytes] = value
    finally:
        provider.close()


def _register_secrets(
    settings: PsiSettings,
    workload_name: str,
    secrets: dict[str, str],
) -> None:
    """Create namespaced Podman secrets with mapping data.

    The hex IDs Podman assigns during delete+create are no longer tracked —
    cache keying is by mapping content via HMAC, not by Podman's volatile
    hex IDs.
    """
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

    For each configured workload, also diffs ``<workload>--*`` Podman secrets
    against the ``Secret=`` targets in its drop-in. Drift on either side —
    Podman secrets missing from the drop-in, or drop-in references with no
    backing Podman secret — is reported per-workload.

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
    drift = _workload_dropin_drift(settings, secrets)
    _print_dry_run_report(managed, stale, orphaned, drift)


def _parse_dropin_secret_targets(dropin_path: Path) -> set[str]:
    """Parse ``Secret=<name>,...`` lines from a drop-in file.

    Returns the set of Podman secret names (the first comma-separated field
    of each ``Secret=`` value). Returns an empty set if the file does not
    exist — this matches the "no drop-in yet" state before first setup.
    """
    if not dropin_path.exists():
        return set()
    names: set[str] = set()
    for line in dropin_path.read_text().splitlines():
        stripped = line.strip()
        if not stripped.startswith("Secret="):
            continue
        value = stripped[len("Secret=") :]
        name = value.split(",", 1)[0].strip()
        if name:
            names.add(name)
    return names


def _workload_dropin_drift(
    settings: PsiSettings,
    secrets: list[dict],
) -> dict[str, dict[str, list[str]]]:
    """Per-workload diff between ``<workload>--*`` Podman secrets and drop-in targets.

    Returns a dict keyed by workload name, with each value shaped as::

        {
            "in_podman_not_in_dropin": [...],  # stale Podman secrets
            "in_dropin_not_in_podman": [...],  # dangling drop-in refs
        }

    Only workloads with drift on either side are included. Sorted lists for
    stable output.
    """
    result: dict[str, dict[str, list[str]]] = {}
    for workload_name in settings.workloads:
        podman_names = _workload_podman_names(workload_name, secrets)
        dropin_path = settings.systemd_dir / f"{workload_name}.container.d" / "50-secrets.conf"
        dropin_names = _parse_dropin_secret_targets(dropin_path)
        missing_from_dropin = sorted(podman_names - dropin_names)
        missing_from_podman = sorted(dropin_names - podman_names)
        if missing_from_dropin or missing_from_podman:
            result[workload_name] = {
                "in_podman_not_in_dropin": missing_from_dropin,
                "in_dropin_not_in_podman": missing_from_podman,
            }
    return result


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


def _workload_podman_names(workload_name: str, secrets: list[dict]) -> set[str]:
    """Return Podman shell-secret names matching ``<workload_name>--*``."""
    prefix = f"{workload_name}--"
    return {
        s["Spec"]["Name"] for s in secrets if s.get("Spec", {}).get("Name", "").startswith(prefix)
    }


def _check_workload_drift(
    workload_name: str,
    merged: dict[str, str],
) -> list[str]:
    """Return Podman secrets in ``<workload>--*`` namespace absent from ``merged``.

    These are typically subfolder keys fetched by a previous ``psi setup``
    run with different source paths or with ``recursive: true`` set, and
    never removed — ``_register_secrets`` only deletes-then-recreates the
    names it's given, so anything that falls out of the fetch persists.
    Such secrets still resolve via the shell driver (direct lookup by key
    still hits Infisical) but the drop-in never references them, so
    containers boot without those env vars.

    Returns a sorted list. Returns an empty list if the Podman API is
    unreachable; the primary fetch-and-register path would already have
    failed loudly in that case.
    """
    expected = {f"{workload_name}--{key}" for key in merged}
    try:
        secrets = _list_podman_shell_secrets()
    except httpx.HTTPError as e:
        logger.warning(
            "Cannot list Podman secrets to check drift for '{}': {}",
            workload_name,
            e,
        )
        return []
    existing = _workload_podman_names(workload_name, secrets)
    return sorted(existing - expected)


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


def _print_dry_run_report(
    managed: list[str],
    stale: list[str],
    orphaned: list[str],
    drift: dict[str, dict[str, list[str]]],
) -> None:
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
    summary.add_row("[red]workload drift[/red]", str(len(drift)))
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

    if drift:
        console.print(
            "\n[red]Workload drift[/red] — drop-in and Podman registry diverge. "
            "Containers will miss any env vars listed as "
            "[bold]in Podman, not in drop-in[/bold]:"
        )
        for workload_name, groups in drift.items():
            console.print(f"  [bold]{workload_name}[/bold]")
            if groups["in_podman_not_in_dropin"]:
                console.print(
                    "    in Podman, not in drop-in: " + ", ".join(groups["in_podman_not_in_dropin"])
                )
            if groups["in_dropin_not_in_podman"]:
                console.print(
                    "    in drop-in, not in Podman: " + ", ".join(groups["in_dropin_not_in_podman"])
                )

    if not stale and not orphaned and not drift:
        console.print("\n[green]All secrets are managed — nothing to do.[/green]")
