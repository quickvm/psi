"""Import secrets into Infisical from external sources."""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

import httpx
from rich.console import Console

from psi.models import (
    ConflictPolicy,
    ImportOutcome,
    ImportResult,
    ImportSecret,
    ImportSecretResult,
)

if TYPE_CHECKING:
    from pathlib import Path

    from psi.api import InfisicalClient

console = Console()
err_console = Console(stderr=True)

_BATCH_CHUNK_SIZE = 100
_PODMAN_API_VERSION = "v5.0.0"


def _podman_socket_url() -> str:
    """Return the Podman API Unix socket path as an httpx transport URL."""
    uid = os.getuid()
    if uid == 0:
        return "/run/podman/podman.sock"
    return f"/run/user/{uid}/podman/podman.sock"


def _podman_api_get(path: str, params: dict[str, str] | None = None) -> httpx.Response:
    """Make a GET request to the Podman REST API via Unix socket."""
    transport = httpx.HTTPTransport(uds=_podman_socket_url())
    with httpx.Client(transport=transport, timeout=10.0) as client:
        resp = client.get(
            f"http://localhost/{_PODMAN_API_VERSION}{path}",
            params=params,
        )
        resp.raise_for_status()
        return resp


def read_env_file(path: Path | None) -> list[ImportSecret]:
    """Parse KEY=VALUE lines from a file or stdin.

    Handles comments, blank lines, quoted values, and `export` prefix.
    """
    if path is None:
        lines = sys.stdin.read().splitlines()
        source = "stdin"
    else:
        lines = path.read_text().splitlines()
        source = str(path)

    secrets: list[ImportSecret] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[7:]
        if "=" not in stripped:
            err_console.print(
                f"[yellow]Skipping line without '=': {stripped!r}[/yellow]",
            )
            continue
        key, value = stripped.split("=", 1)
        value = _strip_quotes(value)
        secrets.append(ImportSecret(key=key.strip(), value=value, source=source))
    return secrets


def read_podman_secrets(names: list[str] | None) -> list[ImportSecret]:
    """Read secret values from Podman's secret store via the REST API.

    Args:
        names: Specific secret names, or None to read all.
    """
    if names is None:
        resp = _podman_api_get("/libpod/secrets/json")
        names = [s["Spec"]["Name"] for s in resp.json()]

    secrets: list[ImportSecret] = []
    for name in names:
        resp = _podman_api_get(
            f"/libpod/secrets/{name}/json",
            params={"showsecret": "true"},
        )
        value = resp.json()["SecretData"]
        secrets.append(ImportSecret(key=name, value=value, source="podman-secret"))
    return secrets


def read_quadlet(
    paths: list[Path],
    *,
    resolve_secrets: bool = False,
) -> list[ImportSecret]:
    """Parse Environment= and Secret= from quadlet .container files.

    Args:
        paths: One or more .container file paths.
        resolve_secrets: If True, resolve Secret= refs via podman inspect.
    """
    secrets: list[ImportSecret] = []
    seen: set[tuple[str, str]] = set()
    for path in paths:
        source = str(path)
        for line in path.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("Environment="):
                env_part = stripped[len("Environment=") :]
                for s in _parse_env_directive(env_part, source):
                    dedup_key = (s.key, s.value)
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        secrets.append(s)
            elif stripped.startswith("Secret="):
                secret_ref = stripped[len("Secret=") :]
                result = _parse_secret_directive(secret_ref, source, resolve_secrets)
                if result:
                    dedup_key = (result.key, result.value)
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        secrets.append(result)
    return secrets


def run_import(
    client: InfisicalClient,
    token: str,
    project_id: str,
    environment: str,
    secret_path: str,
    secrets: list[ImportSecret],
    *,
    conflict: ConflictPolicy = ConflictPolicy.FAIL,
    dry_run: bool = False,
) -> ImportResult:
    """Import secrets into Infisical.

    Pre-fetches existing secrets to detect conflicts, then batch-creates
    new secrets and individually handles existing ones per conflict policy.
    """
    existing = _fetch_existing_keys(client, token, project_id, environment, secret_path)

    new_secrets = [s for s in secrets if s.key not in existing]
    conflicting = [s for s in secrets if s.key in existing]

    if dry_run:
        return _dry_run_result(new_secrets, conflicting, conflict)

    client.ensure_folder(token, project_id, environment, secret_path)

    results: list[ImportSecretResult] = []
    results.extend(_batch_create(client, token, project_id, environment, secret_path, new_secrets))
    results.extend(
        _handle_conflicts(
            client, token, project_id, environment, secret_path, conflicting, conflict
        )
    )

    return ImportResult(
        total=len(secrets),
        created=sum(1 for r in results if r.outcome == ImportOutcome.CREATED),
        skipped=sum(1 for r in results if r.outcome == ImportOutcome.SKIPPED),
        overwritten=sum(1 for r in results if r.outcome == ImportOutcome.OVERWRITTEN),
        failed=sum(1 for r in results if r.outcome == ImportOutcome.FAILED),
        secrets=results,
    )


def _strip_quotes(value: str) -> str:
    """Strip matching single or double quotes from a value."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _parse_env_directive(
    env_str: str,
    source: str,
) -> list[ImportSecret]:
    """Parse space-separated KEY=VALUE pairs from an Environment= line."""
    secrets: list[ImportSecret] = []
    for token in _split_env_tokens(env_str):
        token = _strip_quotes(token)
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        value = _strip_quotes(value)
        secrets.append(ImportSecret(key=key, value=value, source=source))
    return secrets


def _split_env_tokens(env_str: str) -> list[str]:
    """Split Environment= value respecting quoted strings."""
    tokens: list[str] = []
    current: list[str] = []
    in_quote: str | None = None

    for char in env_str:
        if in_quote:
            current.append(char)
            if char == in_quote:
                in_quote = None
        elif char in ("'", '"'):
            in_quote = char
            current.append(char)
        elif char == " " and not in_quote:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)

    if current:
        tokens.append("".join(current))
    return tokens


def _parse_secret_directive(
    secret_ref: str,
    source: str,
    resolve: bool,
) -> ImportSecret | None:
    """Parse a Secret= directive and optionally resolve its value."""
    parts = secret_ref.split(",")
    secret_name = parts[0]
    target = secret_name

    for part in parts[1:]:
        if part.startswith("target="):
            target = part[len("target=") :]

    if not resolve:
        err_console.print(
            f"[yellow]Skipping Secret= ref '{secret_name}' "
            f"(use --resolve-secrets to import)[/yellow]",
        )
        return None

    resp = _podman_api_get(
        f"/libpod/secrets/{secret_name}/json",
        params={"showsecret": "true"},
    )
    value = resp.json()["SecretData"]
    return ImportSecret(key=target, value=value, source=source)


def _dry_run_result(
    new_secrets: list[ImportSecret],
    conflicting: list[ImportSecret],
    conflict: ConflictPolicy,
) -> ImportResult:
    """Build a dry-run result showing what would happen."""
    results: list[ImportSecretResult] = []

    for s in new_secrets:
        results.append(
            ImportSecretResult(key=s.key, outcome=ImportOutcome.DRY_RUN, detail="would create")
        )

    for s in conflicting:
        match conflict:
            case ConflictPolicy.SKIP:
                detail = "would skip (already exists)"
            case ConflictPolicy.OVERWRITE:
                detail = "would overwrite (already exists)"
            case ConflictPolicy.FAIL:
                detail = "would fail (already exists)"
        results.append(ImportSecretResult(key=s.key, outcome=ImportOutcome.DRY_RUN, detail=detail))

    would_create = len(new_secrets)
    would_skip = sum(1 for s in conflicting if conflict == ConflictPolicy.SKIP)
    would_overwrite = sum(1 for s in conflicting if conflict == ConflictPolicy.OVERWRITE)
    would_fail = sum(1 for s in conflicting if conflict == ConflictPolicy.FAIL)

    return ImportResult(
        total=len(new_secrets) + len(conflicting),
        created=would_create,
        skipped=would_skip,
        overwritten=would_overwrite,
        failed=would_fail,
        secrets=results,
    )


def _fetch_existing_keys(
    client: InfisicalClient,
    token: str,
    project_id: str,
    environment: str,
    secret_path: str,
) -> set[str]:
    """Fetch existing secret keys at the target path.

    Returns an empty set if the folder does not exist yet (404).
    """
    import httpx

    try:
        existing = client.list_secrets(token, project_id, environment, secret_path)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return set()
        raise
    return {s["secretKey"] for s in existing}


def _batch_create(
    client: InfisicalClient,
    token: str,
    project_id: str,
    environment: str,
    secret_path: str,
    secrets: list[ImportSecret],
) -> list[ImportSecretResult]:
    """Batch-create new secrets in chunks."""
    results: list[ImportSecretResult] = []
    for i in range(0, len(secrets), _BATCH_CHUNK_SIZE):
        chunk = secrets[i : i + _BATCH_CHUNK_SIZE]
        batch = [{"secretKey": s.key, "secretValue": s.value} for s in chunk]
        try:
            client.create_secrets_batch(token, project_id, environment, secret_path, batch)
            results.extend(
                ImportSecretResult(key=s.key, outcome=ImportOutcome.CREATED) for s in chunk
            )
        except Exception as e:
            results.extend(
                ImportSecretResult(
                    key=s.key,
                    outcome=ImportOutcome.FAILED,
                    detail=str(e),
                )
                for s in chunk
            )
    return results


def _handle_conflicts(
    client: InfisicalClient,
    token: str,
    project_id: str,
    environment: str,
    secret_path: str,
    secrets: list[ImportSecret],
    policy: ConflictPolicy,
) -> list[ImportSecretResult]:
    """Handle secrets that already exist per the conflict policy."""
    results: list[ImportSecretResult] = []
    for secret in secrets:
        match policy:
            case ConflictPolicy.SKIP:
                results.append(
                    ImportSecretResult(
                        key=secret.key,
                        outcome=ImportOutcome.SKIPPED,
                        detail="already exists",
                    )
                )
            case ConflictPolicy.FAIL:
                results.append(
                    ImportSecretResult(
                        key=secret.key,
                        outcome=ImportOutcome.FAILED,
                        detail="already exists (use --conflict skip or overwrite)",
                    )
                )
            case ConflictPolicy.OVERWRITE:
                try:
                    client.update_secret(
                        token,
                        project_id,
                        environment,
                        secret_path,
                        secret.key,
                        secret.value,
                    )
                    results.append(
                        ImportSecretResult(
                            key=secret.key,
                            outcome=ImportOutcome.OVERWRITTEN,
                        )
                    )
                except Exception as e:
                    results.append(
                        ImportSecretResult(
                            key=secret.key,
                            outcome=ImportOutcome.FAILED,
                            detail=str(e),
                        )
                    )
    return results
