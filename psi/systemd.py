"""Query systemd unit/timer status via subprocess.

Graceful fallback: returns None if systemctl is unavailable (e.g., inside a
container without D-Bus mounted).
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime

from psi.models import TimerInfo


def get_timer_info(timer_name: str) -> TimerInfo | None:
    """Query a systemd timer's status.

    Args:
        timer_name: Unit name, e.g. "psi-tls-renew.timer".

    Returns:
        TimerInfo or None if systemctl unavailable or unit not found.
    """
    props = _systemctl_show(
        timer_name,
        ["ActiveState", "LastTriggerUSec", "NextElapseUSecRealtime"],
    )
    if not props:
        return None

    active = props.get("ActiveState", "unknown")
    if active == "inactive" and props.get("LastTriggerUSec") == "n/a":
        return None

    return TimerInfo(
        active_state=active,
        last_trigger=_usec_to_iso(props.get("LastTriggerUSec")),
        next_elapse=_usec_to_iso(props.get("NextElapseUSecRealtime")),
    )


def get_unit_state(unit_name: str) -> str | None:
    """Query a systemd unit's ActiveState.

    Returns:
        State string (active, inactive, failed, etc.) or None.
    """
    props = _systemctl_show(unit_name, ["ActiveState"])
    if not props:
        return None
    return props.get("ActiveState")


def _systemctl_show(unit_name: str, properties: list[str]) -> dict[str, str] | None:
    """Run systemctl show and parse key=value output."""
    prop_arg = ",".join(properties)
    try:
        result = subprocess.run(
            ["systemctl", "show", unit_name, f"--property={prop_arg}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):  # fmt: skip
        return None

    if result.returncode != 0:
        return None

    props: dict[str, str] = {}
    for line in result.stdout.strip().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            props[key] = value
    return props


def _usec_to_iso(usec_str: str | None) -> str | None:
    """Convert systemd microsecond timestamp to ISO 8601 string."""
    if not usec_str or usec_str in ("0", "n/a"):
        return None
    try:
        usec = int(usec_str)
        if usec == 0:
            return None
        dt = datetime.fromtimestamp(usec / 1_000_000, tz=UTC)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OSError):  # fmt: skip
        return None
