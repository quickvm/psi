"""Query systemd unit/timer status via subprocess.

Graceful fallback: returns None if systemctl is unavailable (e.g., inside a
container without D-Bus mounted).
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime

from loguru import logger

from psi.models import SystemdScope, TimerInfo


def daemon_reload(scope: SystemdScope) -> None:
    """Reload systemd, preferring D-Bus and falling back to systemctl.

    Works correctly when called from inside a container that has the system
    D-Bus socket mounted, and gracefully no-ops on minimal environments where
    neither D-Bus nor systemctl is available (e.g. build containers).

    Args:
        scope: System or user systemd instance.
    """
    try:
        _dbus_daemon_reload(scope)
        return
    except Exception as e:
        logger.debug("D-Bus daemon-reload failed ({}), falling back to systemctl", e)

    cmd = ["systemctl"]
    if scope == SystemdScope.USER:
        cmd.append("--user")
    cmd.append("daemon-reload")
    try:
        subprocess.run(cmd, check=True)
        logger.info("Reloaded systemd.")
    except FileNotFoundError:
        logger.warning("systemctl not available, skipping daemon-reload")
    except subprocess.CalledProcessError as e:
        logger.warning(
            "systemctl daemon-reload failed ({}); skipping — "
            "run 'systemctl daemon-reload' on the host manually.",
            e,
        )


def _dbus_daemon_reload(scope: SystemdScope) -> None:
    """Reload systemd via D-Bus. Raises on any failure."""
    import dbus

    bus = dbus.SessionBus() if scope == SystemdScope.USER else dbus.SystemBus()
    systemd = bus.get_object(
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
    )
    manager = dbus.Interface(
        systemd,
        "org.freedesktop.systemd1.Manager",
    )
    manager.Reload()


def get_timer_info(
    timer_name: str,
    user_mode: bool = False,
) -> TimerInfo | None:
    """Query a systemd timer's status.

    Args:
        timer_name: Unit name, e.g. "psi-tls-renew.timer".
        user_mode: If True, query the user systemd instance.

    Returns:
        TimerInfo or None if systemctl unavailable or unit not found.
    """
    props = _systemctl_show(
        timer_name,
        ["ActiveState", "LastTriggerUSec", "NextElapseUSecRealtime"],
        user_mode=user_mode,
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


def get_unit_state(unit_name: str, user_mode: bool = False) -> str | None:
    """Query a systemd unit's ActiveState.

    Returns:
        State string (active, inactive, failed, etc.) or None.
    """
    props = _systemctl_show(unit_name, ["ActiveState"], user_mode=user_mode)
    if not props:
        return None
    return props.get("ActiveState")


def _systemctl_show(
    unit_name: str,
    properties: list[str],
    user_mode: bool = False,
) -> dict[str, str] | None:
    """Run systemctl show and parse key=value output."""
    prop_arg = ",".join(properties)
    cmd = ["systemctl"]
    if user_mode:
        cmd.append("--user")
    cmd.extend(["show", unit_name, f"--property={prop_arg}"])
    try:
        result = subprocess.run(
            cmd,
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
