"""TLS certificate lifecycle — issue, renew, status, file output, hooks."""

from __future__ import annotations

import re
import subprocess
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.table import Table

from psi.api import InfisicalClient
from psi.models import CertState, CertStatusInfo
from psi.settings import resolve_auth

if TYPE_CHECKING:
    from pathlib import Path

    from psi.models import CertificateConfig
    from psi.settings import PsiSettings

console = Console()

_DURATION_PATTERN = re.compile(r"^(\d+)([dhyms])$")
_DURATION_MULTIPLIERS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "y": 365 * 86400,
}


def issue_all(settings: PsiSettings) -> None:
    """Issue all configured TLS certificates."""
    tls = _require_tls(settings)

    with InfisicalClient(settings.api_url, settings.state_dir, settings.token.ttl) as client:
        for cert_name, cert_config in tls.certificates.items():
            console.print(f"\n[bold]Certificate: {cert_name}[/bold]")
            _issue_one(client, settings, cert_name, cert_config)

    console.print("\n[green]All certificates issued.[/green]")


def renew_due(settings: PsiSettings) -> None:
    """Renew certificates approaching expiry."""
    tls = _require_tls(settings)
    state_dir = _tls_state_dir(settings)
    any_renewed = False

    with InfisicalClient(settings.api_url, settings.state_dir, settings.token.ttl) as client:
        for cert_name, cert_config in tls.certificates.items():
            state = _load_state(state_dir, cert_name)
            if not state:
                console.print(
                    f"  [yellow]{cert_name}:[/yellow] no state found, run 'psi tls issue' first"
                )
                continue

            renew_before_s = _parse_duration_seconds(cert_config.renew_before)
            if _needs_renewal(state, renew_before_s):
                console.print(f"\n[bold]Renewing: {cert_name}[/bold]")
                _renew_one(client, settings, cert_name, cert_config, state)
                any_renewed = True
            else:
                remaining = state.expires_at - time.time()
                days = int(remaining / 86400)
                console.print(f"  [green]{cert_name}:[/green] valid, {days} days remaining")

    if not any_renewed:
        console.print("\n[green]No renewals needed.[/green]")


def get_tls_status(settings: PsiSettings) -> list[CertStatusInfo]:
    """Gather status data for all configured certificates."""
    tls = _require_tls(settings)
    state_dir = _tls_state_dir(settings)
    results: list[CertStatusInfo] = []

    for cert_name in tls.certificates:
        state = _load_state(state_dir, cert_name)
        if not state:
            results.append(
                CertStatusInfo(
                    name=cert_name,
                    common_name="—",
                    serial_number="—",
                    issued="—",
                    expires="—",
                    days_left=0,
                    status="not_issued",
                )
            )
            continue

        now = time.time()
        days_left = int((state.expires_at - now) / 86400)
        issued = datetime.fromtimestamp(state.issued_at, tz=UTC).strftime("%Y-%m-%d")
        expires = datetime.fromtimestamp(state.expires_at, tz=UTC).strftime("%Y-%m-%d")

        renew_before_s = _parse_duration_seconds(tls.certificates[cert_name].renew_before)
        if _needs_renewal(state, renew_before_s):
            status = "needs_renewal"
        elif days_left < 0:
            status = "expired"
        else:
            status = "valid"

        results.append(
            CertStatusInfo(
                name=cert_name,
                common_name=state.common_name,
                serial_number=state.serial_number,
                issued=issued,
                expires=expires,
                days_left=days_left,
                status=status,
            )
        )

    return results


def build_tls_status_table(
    certs: list[CertStatusInfo],
) -> Table:
    """Build a Rich table from certificate status data."""
    table = Table(title="TLS Certificates")
    table.add_column("Name")
    table.add_column("Common Name")
    table.add_column("Serial")
    table.add_column("Issued")
    table.add_column("Expires")
    table.add_column("Days Left")
    table.add_column("Status")

    status_styles = {
        "valid": "[green]valid[/green]",
        "needs_renewal": "[red]needs renewal[/red]",
        "expired": "[red]expired[/red]",
        "not_issued": "[yellow]not issued[/yellow]",
    }

    for cert in certs:
        serial = cert.serial_number
        serial_short = serial[:16] + "..." if len(serial) > 16 else serial
        styled_status = status_styles.get(cert.status, cert.status)

        table.add_row(
            cert.name,
            cert.common_name,
            serial_short,
            cert.issued,
            cert.expires,
            str(cert.days_left) if cert.status != "not_issued" else "—",
            styled_status,
        )

    return table


# --- Internal helpers ---


def _require_tls(settings: PsiSettings) -> Any:
    """Return TLS config or exit if not configured."""
    if not settings.tls:
        console.print("[red]No TLS configuration found in config.[/red]")
        raise SystemExit(1)
    return settings.tls


def _tls_state_dir(settings: PsiSettings) -> Path:
    """Return and ensure the TLS state directory exists."""
    path = settings.state_dir / "tls"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _load_state(state_dir: Path, name: str) -> CertState | None:
    """Load certificate state from JSON file."""
    path = state_dir / f"{name}.json"
    if not path.exists():
        return None
    try:
        return CertState.model_validate_json(path.read_text())
    except Exception:
        return None


def _save_state(state_dir: Path, name: str, state: CertState) -> None:
    """Save certificate state to JSON file."""
    path = state_dir / f"{name}.json"
    path.write_text(state.model_dump_json(indent=2))
    path.chmod(0o600)


def _parse_duration_seconds(duration: str) -> int:
    """Parse a duration string like '90d', '1y', '24h' to seconds."""
    match = _DURATION_PATTERN.match(duration.strip())
    if not match:
        msg = (
            f"Invalid duration: {duration!r}. "
            f"Expected format: <number><unit> where unit is "
            f"s/m/h/d/y (e.g., '90d', '1y', '24h')"
        )
        raise ValueError(msg)
    value = int(match.group(1))
    unit = match.group(2)
    return value * _DURATION_MULTIPLIERS[unit]


def _needs_renewal(state: CertState, renew_before_seconds: int) -> bool:
    """Check if a certificate needs renewal."""
    return state.expires_at - time.time() <= renew_before_seconds


def _write_cert_files(cert_config: CertificateConfig, cert_data: dict[str, Any]) -> None:
    """Write PEM certificate components to configured output paths."""
    output = cert_config.output
    mode = int(output.mode, 8)

    files = [
        (output.cert, cert_data["certificate"]),
        (output.key, cert_data["privateKey"]),
        (output.chain, cert_data["certificateChain"]),
    ]
    if output.ca and "issuingCaCertificate" in cert_data:
        files.append((output.ca, cert_data["issuingCaCertificate"]))

    for path, content in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)
        console.print(f"  Wrote {path}")

    # Key file gets stricter permissions
    output.key.chmod(0o600)


def _run_hooks(hooks: list[str], cert_name: str) -> bool:
    """Run post-renewal hook commands. Returns True if all succeeded."""
    all_ok = True
    for hook in hooks:
        try:
            subprocess.run(
                hook,
                shell=True,
                check=True,
                capture_output=True,  # noqa: S602
            )
            console.print(f"  Hook OK: {hook}")
        except subprocess.CalledProcessError as e:
            console.print(
                f"  [red]Hook FAILED:[/red] {hook}\n    stderr: {e.stderr.decode().strip()}"
            )
            all_ok = False
    return all_ok


def _issue_one(
    client: InfisicalClient,
    settings: PsiSettings,
    cert_name: str,
    cert_config: CertificateConfig,
) -> None:
    """Issue a single certificate."""
    project = settings.projects[cert_config.project]
    auth = resolve_auth(project, settings)
    token = client.ensure_token(auth)

    alt_names = (
        [{"type": an.type, "value": an.value} for an in cert_config.alt_names]
        if cert_config.alt_names
        else None
    )

    console.print(f"  Issuing CN={cert_config.common_name} TTL={cert_config.ttl}")

    cert_data = client.issue_certificate(
        token=token,
        profile_id=cert_config.profile_id,
        common_name=cert_config.common_name,
        alt_names=alt_names,
        ttl=cert_config.ttl,
        key_algorithm=(cert_config.key_algorithm.value if cert_config.key_algorithm else None),
    )

    _write_cert_files(cert_config, cert_data)

    state = CertState(
        certificate_id=cert_data["certificateId"],
        serial_number=cert_data["serialNumber"],
        common_name=cert_config.common_name,
        issued_at=time.time(),
        expires_at=time.time() + _parse_duration_seconds(cert_config.ttl),
        profile_id=cert_config.profile_id,
    )
    state_dir = _tls_state_dir(settings)
    _save_state(state_dir, cert_name, state)

    if cert_config.hooks:
        _run_hooks(cert_config.hooks, cert_name)

    console.print(f"  [green]Issued: {cert_name}[/green]")


def _renew_one(
    client: InfisicalClient,
    settings: PsiSettings,
    cert_name: str,
    cert_config: CertificateConfig,
    old_state: CertState,
) -> None:
    """Renew a single certificate."""
    project = settings.projects[cert_config.project]
    auth = resolve_auth(project, settings)
    token = client.ensure_token(auth)

    console.print(f"  Renewing certificate ID {old_state.certificate_id[:12]}...")

    cert_data = client.renew_certificate(
        token=token,
        certificate_id=old_state.certificate_id,
    )

    _write_cert_files(cert_config, cert_data)

    state = CertState(
        certificate_id=cert_data.get("certificateId", old_state.certificate_id),
        serial_number=cert_data.get("serialNumber", old_state.serial_number),
        common_name=cert_config.common_name,
        issued_at=time.time(),
        expires_at=time.time() + _parse_duration_seconds(cert_config.ttl),
        profile_id=cert_config.profile_id,
    )
    state_dir = _tls_state_dir(settings)
    _save_state(state_dir, cert_name, state)

    if cert_config.hooks:
        _run_hooks(cert_config.hooks, cert_name)

    console.print(f"  [green]Renewed: {cert_name}[/green]")
